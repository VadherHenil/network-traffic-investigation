"""HENIX local network investigation workspace. Run python app.py."""

import argparse
import errno
import hashlib
import io
import json
import mimetypes
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import NamedTuple
from urllib.parse import parse_qs, urlsplit

from capture import Capture, MAX_BYTES, ROOT, metrics, packet_row, version
from case_io import MAX_CASE_BYTES, checked_string, open_snapshot, prepare_snapshot, write_snapshot
from findings import investigate
from providers import excerpt, prepare_review, provider_options, review, set_approvals
from reports import build_report, bundle
from operations import MIN_FREE_BYTES, Operations, StopSignal, capture_operation, storage_usage
from analyst import annotations, update_annotations, search_conversations

PAGE_SIZE = 50
COPY_CHUNK = 1024 * 1024
STATIC = {"/": "index.html", "/app.js": "app.js", "/style.css": "style.css",
          "/cases.js": "cases.js", "/analyst.js": "analyst.js"}
API_ROUTES = {"/api/status", "/api/import", "/api/import-status", "/api/close", "/api/frame", "/api/view",
              "/api/packets", "/api/preview", "/api/review", "/api/review-approval", "/api/report",
              "/api/conversations", "/api/annotations", "/api/cancel", "/api/storage",
              "/api/case-save", "/api/case-open"}


class RequestError(ValueError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class CaseDownload(NamedTuple):
    expires: float
    evidence: str
    prefix: bytes
    total: int


def text_field(data, name, limit, default=""):
    value = data.get(name, default)
    if not isinstance(value, str) or len(value) > limit or "\0" in value:
        raise RequestError(400, f"Enter a valid {name} of up to {limit:,} characters.")
    return value


class Workspace:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.captures = {}
        self.reviews = OrderedDict()
        self.lock = threading.RLock()
        self.import_lock = threading.Lock()
        self.imports = OrderedDict()
        self.import_cancellations = {}
        self.indexer = ThreadPoolExecutor(max_workers=1, thread_name_prefix="capture-index")
        self.stopping = threading.Event()
        self.downloads = OrderedDict()
        self.operations = Operations()

    def add(self, data, name, source="", acquired=""):
        return self.import_stream(io.BytesIO(data), len(data), name, source, acquired)

    def import_stream(self, stream, length, name, source="", acquired="", background=False):
        for value, limit in ((name, 255), (source, 2000), (acquired, 32)):
            checked_string(value, limit)
        if not name.lower().endswith((".cap", ".pcap", ".pcapng")):
            raise ValueError("Choose a .cap, .pcap or .pcapng file.")
        if not 0 < length <= MAX_BYTES:
            raise ValueError("Choose a non-empty capture up to 5 GiB.")
        if acquired:
            try:
                date.fromisoformat(acquired)
            except ValueError:
                raise ValueError("Enter the acquisition date in YYYY-MM-DD format.") from None
        if not self.import_lock.acquire(blocking=False):
            raise RequestError(409, "Another capture is being imported. Retry when its index is ready.")
        path = self.folder / (uuid.uuid4().hex + ".cap")
        handed_off = False
        job = None
        try:
            if self.stopping.is_set():
                raise RequestError(503, "The workspace is shutting down.")
            if shutil.disk_usage(self.folder).free < length + MIN_FREE_BYTES:
                raise RequestError(507, "The workspace drive has insufficient free space for this upload. "
                                   "Free space or restart HENIX with --work-dir on a larger drive.")
            digest = hashlib.sha256()
            remaining = length
            with path.open("xb") as out:
                while remaining:
                    if self.stopping.is_set():
                        raise ValueError("The workspace is shutting down.")
                    chunk = stream.read(min(remaining, COPY_CHUNK))
                    if not chunk:
                        raise ValueError("The upload ended early. Retry the import.")
                    out.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
            signature = digest.hexdigest()
            with self.lock:
                for c in self.captures.values():
                    if c.digest == signature:
                        c.record_acquisition(name, source, acquired)
                        return c
                if len(self.captures) >= 8:
                    raise ValueError("Eight captures are open. Close a capture to import another.")
                job = uuid.uuid4().hex
                self.imports[job] = dict(job=job, name=name, state="indexing", frames=0)
                self.import_cancellations[job] = threading.Event()
                while len(self.imports) > 16:
                    self.imports.popitem(last=False)
            if background:
                self.indexer.submit(self._index, job, path, name, signature, source, acquired)
                handed_off = True
                return self.job_status(job)
            handed_off = True
            return self._index(job, path, name, signature, source, acquired)
        finally:
            if not handed_off:
                try:
                    if job is not None:
                        with self.lock:
                            self.imports.pop(job, None)
                            self.import_cancellations.pop(job, None)
                    path.unlink(missing_ok=True)
                finally:
                    self.import_lock.release()

    def job_status(self, job):
        with self.lock:
            if job not in self.imports:
                raise RequestError(404, "This import is no longer in the workspace.")
            state = dict(self.imports[job])
        if state["state"] == "indexing":
            state["storage"] = storage_usage(self.folder)
        return state

    def cancel_import(self, job):
        with self.lock:
            event = self.import_cancellations.get(job)
            if event is None or self.imports[job]["state"] != "indexing":
                return False
            self.imports[job]["cancel_requested"] = True
            event.set()
            return True

    def case_ticket(self, capture, expression):
        with self.lock:
            reviews = {filt: review for (eid, filt), review in self.reviews.items() if eid == capture.id}
        prefix, total = prepare_snapshot(capture, expression, reviews)
        with self.lock:
            self.downloads = OrderedDict((k, item) for k, item in self.downloads.items()
                                         if item.expires > time.monotonic())
            token = uuid.uuid4().hex
            self.downloads[token] = CaseDownload(time.monotonic() + 120, capture.id, prefix, total)
            while len(self.downloads) > 16 or sum(len(item.prefix) for item in self.downloads.values()) > 32 * 1024**2:
                self.downloads.popitem(last=False)
            return {"url": "/case-download/" + token}

    def _index(self, job, path, name, signature, source, acquired):
        cancelled = self.import_cancellations[job]
        signal = StopSignal(self.stopping, cancelled)

        def progress(frames):
            if self.stopping.is_set():
                raise ValueError("Indexing stopped because the workspace is shutting down.")
            with self.lock:
                if cancelled.is_set():
                    raise ValueError("Indexing cancelled.")
                self.imports[job]["frames"] = frames

        capture = None
        try:
            progress(0)
            capture = Capture(path, name, signature, source, acquired, progress=progress, stopping=signal)
            manifest = capture.manifest()
            with self.lock:
                progress(manifest["total"])
                capture.stopping = capture.index.stopping = self.stopping
                self.captures[capture.id] = capture
                self.imports[job].update(state="ready", frames=manifest["total"], capture=manifest)
            return capture
        except Exception as exc:
            if cancelled.is_set():
                message = "Indexing cancelled."
            elif isinstance(exc, ValueError):
                message = str(exc)
            elif isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
                message = "Indexing stopped because the workspace or temporary drive is low on free space."
            elif isinstance(exc, (OSError, sqlite3.Error)):
                message = "Could not write the capture index. Check free space and permissions on the workspace drive."
            else:
                message = "The decoder could not finish indexing the capture."
            if capture is not None:
                capture.close()
            path.unlink(missing_ok=True)
            with self.lock:
                self.imports[job].update(state="failed", error=message)
            if cancelled.is_set():
                raise ValueError(message) from None
            raise
        finally:
            with self.lock:
                self.import_cancellations.pop(job, None)
            self.import_lock.release()

    def shutdown(self):
        self.stopping.set()
        # An upload may still hand off its index build to the executor. Wait for
        # that import or case restoration to release its slot before closing it.
        with self.import_lock:
            self.indexer.shutdown(wait=True)
            with self.lock:
                captures = list(self.captures.values())
            for capture in captures:
                self.forget(capture)

    def forget(self, c):
        with c.lock, self.lock:
            c.close()
            c.path.unlink(missing_ok=True)
            self.captures.pop(c.id, None)
            for job, entry in list(self.imports.items()):
                if entry.get("capture", {}).get("id") == c.id:
                    del self.imports[job]
            for key in list(self.reviews):
                if key[0] == c.id:
                    del self.reviews[key]
            for key, ticket in list(self.downloads.items()):
                if ticket.evidence == c.id:
                    del self.downloads[key]


class Handler(BaseHTTPRequestHandler):
    server_version = "HENIX"

    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(90)

    def send_data(self, data, mime, status=200, download=None):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, value, status=200):
        self.send_data(json.dumps(value, ensure_ascii=False).encode(), "application/json; charset=utf-8", status)

    def permitted(self):
        port = self.server.server_port
        host = self.headers.get("Host", "")
        return host in (f"127.0.0.1:{port}", f"localhost:{port}") and self.headers.get("Origin") in (None, "http://" + host)

    def do_GET(self):
        self.handle_action(self.get_page)

    def do_POST(self):
        self.handle_action(self.post_action)

    def handle_action(self, action):
        try:
            action()
            return
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return
        except RequestError as exc:
            status, message = exc.status, str(exc)
        except ValueError as exc:
            status, message = 400, str(exc)
        except TimeoutError:
            status, message = 408, "The request timed out. Retry the operation."
        except OSError as exc:
            status, message = 500, "Could not access a local file. Check disk space and permissions, then retry."
            if exc.errno == errno.ENOSPC:
                status, message = 507, "Workspace or temporary storage is low. Free disk space or use --work-dir on a larger drive."
        except sqlite3.Error:
            status, message = 500, "Could not access the capture index. Check workspace disk space and reopen the capture."
        except Exception as exc:
            print(f"HENIX request failed ({type(exc).__name__}).", file=sys.stderr)
            status, message = 500, "HENIX could not finish this action. Retry, or reopen the capture."
        try:
            self.send_json({"error": message}, status)
        except OSError:
            self.close_connection = True

    def get_page(self):
        if not self.permitted():
            return self.send_json({"error": "Use the local workspace address."}, 403)
        path = urlsplit(self.path).path
        if path.startswith("/case-download/"):
            return self.download_case(path.removeprefix("/case-download/"))
        if path not in STATIC:
            return self.send_json({"error": "Page not found."}, 404)
        asset = ROOT / "web" / STATIC[path]
        self.send_data(asset.read_bytes(), (mimetypes.guess_type(asset)[0] or "text/plain") + "; charset=utf-8")

    def download_case(self, token):
        ws = self.server.workspace
        with ws.lock:
            ticket = ws.downloads.pop(token, None)
            capture = ws.captures.get(ticket.evidence) if ticket and ticket.expires > time.monotonic() else None
        if capture is None:
            raise RequestError(404, "The download link expired. Save the case again.")
        with capture.lock:
            with ws.lock:
                if ws.captures.get(capture.id) is not capture:
                    raise RequestError(404, "This capture was closed.")
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{capture.id}.henix"')
            self.send_header("Content-Length", str(ticket.total))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            write_snapshot(capture, ticket.prefix, self.wfile)

    def post_action(self):
        if not self.permitted() or self.headers.get("X-HENIX") != "workspace":
            return self.send_json({"error": "Open this action from the local workspace."}, 403)
        url = urlsplit(self.path)
        if url.path not in API_ROUTES:
            raise RequestError(404, "Unknown workspace action.")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise RequestError(411, "Send the request with its content length.") from None
        if length < 0:
            raise RequestError(400, "Request length must be zero or greater.")
        if url.path == "/api/case-open" and length > MAX_CASE_BYTES:
            raise RequestError(413, "Portable case uploads are limited to 128 GiB.")
        if url.path != "/api/case-open" and length > (MAX_BYTES if url.path == "/api/import" else 16384):
            raise RequestError(413, "Capture uploads are limited to 5 GiB (5,368,709,120 bytes)." if url.path == "/api/import"
                               else "The request exceeds the size limit.")
        if self.headers.get("Transfer-Encoding"):
            raise RequestError(400, "Use a fixed length upload.")
        self.dispatch_request(url, length)

    def dispatch_request(self, url, length):
        ws = self.server.workspace
        if url.path == "/api/case-open":
            return self.send_json(open_snapshot(ws, self.rfile, length, parse_qs(url.query).get("rebuild") == ["1"]))
        if url.path == "/api/import":
            params = parse_qs(url.query)
            name = Path(params.get("name", ["capture.cap"])[0].replace("\\", "/")).name[:255]
            result = ws.import_stream(self.rfile, length, name, params.get("source", [""])[0][:2000],
                                      params.get("acquired", [""])[0], params.get("background") == ["1"])
            if isinstance(result, dict):
                return self.send_json(result, 202)
            return self.send_json(result.manifest())
        body = self.rfile.read(length)
        if len(body) != length:
            raise ValueError("Incomplete request. Retry the action.")
        try:
            data = json.loads(body or b"{}")
        except (ValueError, RecursionError):
            raise RequestError(400, "The request contains invalid JSON.") from None
        if not isinstance(data, dict):
            raise ValueError("Expected a request object.")
        if url.path == "/api/import-status":
            return self.send_json(ws.job_status(text_field(data, "job", 64)))
        if url.path == "/api/storage":
            return self.send_json(storage_usage(ws.folder))
        if url.path == "/api/cancel":
            job = text_field(data, "job", 64)
            if job:
                cancelled = ws.cancel_import(job)
            else:
                cancelled = ws.operations.cancel(text_field(data, "operation", 64))
            return self.send_json({"cancelled": cancelled})
        if url.path == "/api/status":
            try:
                engine, error = version(), ""
            except ValueError as exc:
                engine, error = "", str(exc)
            with ws.lock:
                captures = [c.manifest() for c in ws.captures.values()]
                imports = [dict(job) for job in ws.imports.values()]
            return self.send_json(dict(engine=engine, error=error, captures=captures, imports=imports,
                                       providers=provider_options()))
        with ws.lock:
            c = ws.captures.get(text_field(data, "id", 64))
        if c is None:
            return self.send_json({"error": "Choose an open capture."}, 404)
        with capture_operation(c, ws.operations, text_field(data, "operation", 64)):
            with ws.lock:
                if ws.captures.get(c.id) is not c:
                    raise RequestError(404, "This capture has been closed. Choose an open capture.")
            if url.path == "/api/close":
                ws.forget(c)
                return self.send_json({"closed": True})
            if url.path == "/api/case-save":
                return self.send_json(ws.case_ticket(c, text_field(data, "filter", 2048)))
            if url.path == "/api/frame":
                return self.send_json(c.inspect_frame(str(data.get("frame", ""))))
            if url.path == "/api/annotations":
                return self.send_json(update_annotations(c, data))
            expression = text_field(data, "filter", 2048).strip()
            rows = c.select(expression)
            if url.path == "/api/conversations":
                return self.send_json(search_conversations(rows, data))
            key = (c.id, expression)
            with ws.lock:
                ai = ws.reviews.get(key)
            if url.path in ("/api/view", "/api/packets"):
                last = max(0, (len(rows)-1) // PAGE_SIZE)
                page = data.get("page", 0)
                if type(page) is not int or page < 0:
                    raise RequestError(400, "The page number must be a nonnegative integer.")
                page = min(last, page)
                start = page * PAGE_SIZE
                result = dict(packets=[packet_row(r) for r in rows[start:start+PAGE_SIZE]],
                              page=page, pages=last+1, matched=len(rows))
                if url.path == "/api/view":
                    findings, events = investigate(rows)
                    result.update(capture=c.manifest(), stats=metrics(rows), findings=findings, events=events, ai=ai,
                                  annotations=annotations(c))
                return self.send_json(result)
            if url.path in ("/api/preview", "/api/review"):
                _, events = investigate(rows)
                redacted = data.get("redact", False)
                if type(redacted) is not bool:
                    raise RequestError(400, "Choose a valid redaction setting.")
                evidence = excerpt(c, rows, expression, events, redact=redacted)
                if url.path == "/api/preview" and "provider" not in data:
                    return self.send_json(evidence)
                provider = text_field(data, "provider", 32)
                model = text_field(data, "model", 200)
                options = dict(endpoint=text_field(data, "endpoint", 2048),
                               protocol=text_field(data, "protocol", 16, "chat"), auth=text_field(data, "auth", 24, "auto"))
                if url.path == "/api/preview":
                    return self.send_json(prepare_review(provider, model, evidence, **options))
                result = review(provider, text_field(data, "key", 1024), model, evidence,
                                fingerprint=text_field(data, "fingerprint", 64), **options)
                with ws.lock:
                    ws.reviews[key] = result
                    ws.reviews.move_to_end(key)
                    if len(ws.reviews) > 64:
                        ws.reviews.popitem(last=False)
                return self.send_json(result)
            if url.path == "/api/review-approval":
                with ws.lock:
                    return self.send_json(set_approvals(ws.reviews.get(key), text_field(data, "review_id", 32),
                                                        data.get("approved")))
            if url.path == "/api/report":
                report_format = text_field(data, "format", 8, "html")
                if report_format == "zip":
                    return self.send_data(bundle(c, rows, expression, ai), "application/zip", download=c.id + "-casefile.zip")
                if report_format != "html":
                    raise RequestError(400, "Choose HTML or ZIP for the report format.")
                html, _ = build_report(c, rows, expression, ai)
                return self.send_data(html.encode(), "text/html; charset=utf-8", download=c.id + "-report.html")


class WorkspaceServer(ThreadingHTTPServer):
    daemon_threads = False

    def server_close(self):
        workspace = getattr(self, "workspace", None)
        if workspace is not None:
            workspace.stopping.set()
        # Closing the socket joins active handlers, including native downloads.
        # Release the evidence files and their indexes after the last user exits.
        super().server_close()
        if workspace is not None:
            workspace.shutdown()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--work-dir", type=Path, metavar="DIRECTORY",
                        help="Existing directory for temporary captures and their on-disk indexes.")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("Choose a port from 0 to 65535.")
    if args.work_dir and not args.work_dir.is_dir():
        parser.error("Choose an existing directory for --work-dir.")
    with tempfile.TemporaryDirectory(prefix="henix-", dir=args.work_dir) as folder:
        try:
            server = WorkspaceServer(("127.0.0.1", args.port), Handler)
        except OSError as error:
            parser.exit(1, f"Could not open local port {args.port}. Try --port 0 for a free port. {error}\n")
        with server:
            server.workspace = Workspace(folder)
            url = f"http://127.0.0.1:{server.server_port}"
            print(f"HENIX is running at {url}\nPress Ctrl+C to close the workspace.", flush=True)
            if not args.no_browser:
                try:
                    webbrowser.open(url)
                except (OSError, webbrowser.Error):
                    print("Open the address above in your browser.", file=sys.stderr)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass


if __name__ == "__main__":
    try:
        main()
    except OSError as exc:
        sys.exit(f"HENIX could not open or clean up the local workspace: {exc}")
