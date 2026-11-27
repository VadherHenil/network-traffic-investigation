"""Bounded caches and cooperative cancellation for long-running capture operations."""

import errno
import shutil
import tempfile
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager


MIN_FREE_BYTES = 64 * 1024**2


def disk_headroom(folder):
    return {"free_bytes": shutil.disk_usage(folder).free,
            "temp_free_bytes": shutil.disk_usage(tempfile.gettempdir()).free}


def storage_usage(folder):
    """Measure the workspace's frame index and filter files, including active writers."""
    totals = dict(index_bytes=0, filter_bytes=0)
    for directory in folder.glob("frames-*"):
        try:
            for path in directory.iterdir():
                if path.name == "frames.sqlite":
                    name = "index_bytes"
                elif path.name.startswith("matches-") and path.suffix == ".sqlite":
                    name = "filter_bytes"
                else:
                    continue
                try:
                    totals[name] += path.stat().st_size
                except FileNotFoundError:
                    pass  # A filter result was released between listing and stat.
        except FileNotFoundError:
            pass  # A capture was just closed.
    return {**disk_headroom(folder), **totals}


class DiskGuard:
    """Sample no more than once per second during a decoder or SQL scan."""
    def __init__(self, folder):
        self.folder = folder
        self.next_check = 0

    def check(self, force=False):
        now = time.monotonic()
        if force or now >= self.next_check:
            headroom = disk_headroom(self.folder)
            if min(headroom.values()) < MIN_FREE_BYTES:
                raise OSError(errno.ENOSPC, "Stopped to preserve 64 MiB on workspace and temporary drives.")
            self.next_check = now + 1


class ByteCache:
    def __init__(self, budget, max_entries):
        self.budget = budget
        self.max_entries = max_entries
        self.entries = OrderedDict()
        self.size = 0

    def get(self, key):
        if key in self.entries:
            self.entries.move_to_end(key)
            return self.entries[key][0]

    def put(self, key, value, size):
        if size > self.budget:
            return
        if key in self.entries:
            self.size -= self.entries.pop(key)[1]
        self.entries[key] = (value, size)
        self.size += size
        while self.size > self.budget or len(self.entries) > self.max_entries:
            self.size -= self.entries.popitem(last=False)[1][1]


class Operations:
    def __init__(self):
        self.events = {}
        self.lock = threading.Lock()

    @contextmanager
    def track(self, token):
        event = threading.Event()
        with self.lock:
            if token in self.events:
                raise ValueError("Operation ID already in use.")
            self.events[token] = event
        try:
            yield event
        finally:
            with self.lock:
                self.events.pop(token, None)

    def cancel(self, token):
        with self.lock:
            event = self.events.get(token)
            if event:
                event.set()
            return event is not None


class StopSignal:
    def __init__(self, workspace, operation):
        self.workspace = workspace
        self.operation = operation

    def is_set(self):
        return self.operation.is_set() or (self.workspace is not None and self.workspace.is_set())


@contextmanager
def capture_operation(capture, registry, token):
    if not token:
        with capture.lock:
            yield
        return
    with registry.track(token) as event:
        while not capture.lock.acquire(timeout=0.2):
            if event.is_set():
                raise ValueError("Operation cancelled.")
        try:
            prior = capture.stopping
            if event.is_set():
                raise ValueError("Operation cancelled.")
            capture.stopping = capture.index.stopping = StopSignal(prior, event)
            try:
                yield
            except Exception:
                if event.is_set():
                    raise ValueError("Operation cancelled.") from None
                raise
            finally:
                capture.stopping = capture.index.stopping = prior
        finally:
            capture.lock.release()
