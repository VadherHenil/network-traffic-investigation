"""On-disk frame metadata and stable, ordinal-indexed display-filter results."""

from contextlib import closing, contextmanager
import sqlite3
import tempfile
import weakref
from pathlib import Path
from uuid import uuid4


def _named_row(cursor, values):
    # TShark's public frame dictionaries use strings and omit absent fields.
    row = {column[0]: str(value) for column, value in zip(cursor.description, values) if value is not None}
    row.setdefault("frame.time_epoch", "")
    return row


class FrameView:
    def __init__(self, store, count, matches=None):
        self.store = store
        self.count = count
        self.matches = matches
        if matches is not None:
            self._cleanup = weakref.finalize(self, matches.unlink, missing_ok=True)

    def __len__(self):
        return self.count

    @contextmanager
    def connection(self):
        """Read-only database with a connection-local scoped view of selected frames."""
        uri = self.store.path.as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as db:
            self.store.watch_shutdown(db)
            db.execute("PRAGMA temp_store=FILE")
            if self.matches is None:
                db.execute("CREATE TEMP VIEW scoped AS SELECT * FROM main.frames")
            else:
                db.execute("ATTACH ? AS hits", (self.matches.as_uri() + "?mode=ro",))
                db.execute('CREATE TEMP VIEW scoped AS SELECT f.* FROM hits.matches m '
                           'JOIN main.frames f ON f."frame.number" = m.frame')
            yield db

    def search(self, where="", params=(), limit=None):
        """Yield ordered metadata using a trusted internal SQL predicate."""
        sql = "SELECT * FROM scoped"
        if where:
            sql += " WHERE " + where
        sql += ' ORDER BY "frame.number"'
        if limit is not None:
            sql += " LIMIT ?"
            params = (*params, limit)
        with self.connection() as db:
            db.row_factory = _named_row
            yield from db.execute(sql, params)

    def __iter__(self):
        return self.search()

    def get_frame(self, number):
        try:
            n = int(number)
        except (TypeError, ValueError):
            return None
        if n < 1 or n > self.store.count:
            return None
        return next(self.search('"frame.number" = ?', (n,), 1), None)

    def __getitem__(self, key):
        if isinstance(key, int):
            offset = key if key >= 0 else self.count + key
            if not 0 <= offset < self.count:
                raise IndexError("Frame ordinal is outside the view")
            return self[offset:offset + 1][0]
        start, stop, step = key.indices(self.count)
        if step != 1:
            return [self[i] for i in range(start, stop, step)]
        if stop <= start:
            return []
        # Frame and match ordinals are contiguous. A late page seeks directly to
        # its first record, independent of the number of preceding pages.
        with self.connection() as db:
            db.row_factory = _named_row
            if self.matches is None:
                sql = 'SELECT * FROM frames WHERE "frame.number" BETWEEN ? AND ? ORDER BY "frame.number"'
            else:
                sql = ('SELECT f.* FROM hits.matches m CROSS JOIN main.frames f '
                       'ON f."frame.number" = m.frame WHERE m.pos BETWEEN ? AND ? ORDER BY m.pos')
            return list(db.execute(sql, (start + 1, stop)))

    def __eq__(self, other):
        if isinstance(other, list):
            return len(self) == len(other) and all(a == b for a, b in zip(self, other))
        return self is other


class FrameLookup:
    """Map original frame numbers to their metadata without keeping a Python dict."""
    def __init__(self, view):
        self.view = view

    def __getitem__(self, key):
        row = self.view.get_frame(key)
        if row is None:
            raise KeyError(key)
        return row

    def __contains__(self, key):
        return self.view.get_frame(key) is not None


class PacketIndex:
    def __init__(self, folder, stopping=None):
        self.directory = tempfile.TemporaryDirectory(prefix="frames-", dir=folder)
        self.path = (Path(self.directory.name) / "frames.sqlite").resolve()
        self.count = 0
        self.stopping = stopping

    def watch_shutdown(self, db):
        if self.stopping is not None:
            if self.stopping.is_set():
                raise ValueError("The workspace is closing.")
            db.set_progress_handler(self.stopping.is_set, 10000)

    @contextmanager
    def writer(self, path):
        try:
            with closing(sqlite3.connect(path)) as db:
                self.watch_shutdown(db)
                # Each writer builds a new private file and publishes it after
                # success. Partial files are deleted on failure.
                db.execute("PRAGMA journal_mode=OFF")
                db.execute("PRAGMA synchronous=OFF")
                db.execute("PRAGMA temp_store=FILE")
                db.execute("PRAGMA cache_size=-8192")
                yield db
                db.commit()
        except sqlite3.Error as exc:
            if self.stopping is not None and self.stopping.is_set():
                raise ValueError("The workspace is closing.") from None
            raise OSError(f"Could not build the packet index. Check free disk space and permissions ({exc}).") from exc

    def build(self, fields, values):
        columns = []
        for name in fields:
            kind = "TEXT"
            if name == "frame.number":
                kind = "INTEGER PRIMARY KEY"
            elif name in ("frame.len", "frame.cap_len"):
                kind = "INTEGER"
            columns.append(f'"{name}" {kind}')
        with self.writer(self.path) as db:
            db.execute("CREATE TABLE frames (" + ",".join(columns) + ")")
            db.executemany("INSERT INTO frames VALUES (" + ",".join("?" for _ in fields) + ")", values)
            self.count = db.total_changes
            for i, field in enumerate(("tcp.stream", "dns.response_to", "http.request_in")):
                db.execute(f'CREATE INDEX field_{i} ON frames ("{field}") WHERE "{field}" IS NOT NULL')
        return FrameView(self, self.count)

    def select(self, frame_numbers):
        path = self.path.parent / f"matches-{uuid4().hex}.sqlite"
        try:
            with self.writer(path) as db:
                db.execute("CREATE TABLE matches (pos INTEGER PRIMARY KEY, frame INTEGER NOT NULL UNIQUE)")
                db.executemany("INSERT INTO matches (frame) VALUES (?)", ((n,) for n in frame_numbers))
                count = db.total_changes
            return FrameView(self, count, path)
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def close(self):
        self.directory.cleanup()
