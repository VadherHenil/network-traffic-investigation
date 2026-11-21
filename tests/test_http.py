"""HTTP checks for a fresh workspace, import errors and recoverable failures."""

import http.client
import io
import json
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from app import COPY_CHUNK, MAX_BYTES, Handler, Workspace
from capture import Capture
from tests.fixtures import training_capture


class WorkspaceHTTPTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.workspace = Workspace(folder.name)
        self.addCleanup(self.server.workspace.shutdown)
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(thread.join)
        self.addCleanup(self.server.shutdown)

    def post(self, path, data=None, **headers):
        body = data if isinstance(data, bytes) else json.dumps(data or {}).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=15)
        try:
            conn.request("POST", "/api/" + path, body, {"X-HENIX": "workspace", **headers})
            response = conn.getresponse()
            return response.status, json.loads(response.read())
        finally:
            conn.close()

    def test_initial_state_and_bad_requests(self):
        status, state = self.post("status")
        self.assertEqual(status, 200)
        self.assertEqual(state["captures"], [])
        for path, body, code in [("sample", {}, 404), ("nonesuch", {}, 404),
                                 ("status", b"{bad", 400), ("status", b"[]", 400),
                                 ("frame", {"id": []}, 400), ("view", {"id": "missing"}, 404),
                                 ("import?name=test.png", b"data", 400),
                                 ("import?name=test.cap&acquired=Monday", b"data", 400)]:
            with self.subTest(path=path, body=body):
                status, result = self.post(path, body)
                self.assertEqual(status, code)
                self.assertTrue(result["error"])
        self.assertEqual(self.post("status", **{"Content-Length": "20000"})[0], 413)
        self.assertEqual(self.post("status", Origin="https://invalid.test")[0], 403)

    def test_streaming_upload_bounds_and_cleanup(self):
        self.assertEqual(MAX_BYTES, 5 * 1024**3)
        self.assertEqual(self.post("import?name=large.cap", b"", **{"Content-Length": str(MAX_BYTES + 1)})[0], 413)
        reads = []

        class Truncated(io.BytesIO):
            def read(self, n=-1):
                reads.append(n)
                return super().read(n)

        ws = self.server.workspace
        with self.assertRaisesRegex(ValueError, "ended early"):
            ws.import_stream(Truncated(b"incomplete"), COPY_CHUNK + 10, "missing.cap")
        self.assertTrue(reads)
        self.assertTrue(all(0 < size <= COPY_CHUNK for size in reads))
        self.assertEqual(list(ws.folder.iterdir()), [])
        with patch("app.shutil.disk_usage") as usage:
            usage.return_value.free = 0
            status, _ = self.post("import?name=case.cap", training_capture())
        self.assertEqual(status, 507)
        self.assertEqual(list(ws.folder.iterdir()), [])

    def test_background_jobs_failure_retry_duplicate_and_close(self):
        def finish(job):
            deadline = time.monotonic() + 15
            while job["state"] == "indexing":
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.02)
                status, job = self.post("import-status", {"job": job["job"]})
                self.assertEqual(status, 200)
            return job

        route = "import?background=1&name=background.cap"
        status, broken = self.post(route, training_capture()[:30])
        self.assertEqual(status, 202)
        self.assertEqual(finish(broken)["state"], "failed")
        self.assertEqual(self.post("status")[1]["captures"], [])
        status, job = self.post(route, training_capture())
        self.assertEqual(status, 202)
        ready = finish(job)
        self.assertEqual(ready["frames"], 12)
        status, duplicate = self.post(route, training_capture())
        self.assertEqual(status, 200)
        self.assertEqual(duplicate["id"], ready["capture"]["id"])
        self.assertEqual(self.post("close", {"id": duplicate["id"]})[0], 200)
        self.assertEqual(self.post("import-status", {"job": ready["job"]})[0], 404)
        self.assertEqual(list(self.server.workspace.folder.iterdir()), [])

    def test_status_and_existing_capture_available_during_index(self):
        original = training_capture()
        _, existing = self.post("import?name=first.cap", original)
        started = threading.Event()
        resume = threading.Event()

        def paused_index(*args, **kwargs):
            started.set()
            if not resume.wait(10):
                raise ValueError("Test index timed out.")
            return Capture(*args, **kwargs)

        with patch("app.Capture", side_effect=paused_index):
            status, job = self.post("import?name=empty.cap&background=1", original[:24])
            self.assertEqual(status, 202)
            try:
                self.assertTrue(started.wait(3))
                self.assertEqual(self.post("import-status", {"job": job["job"]})[1]["state"], "indexing")
                self.assertEqual(self.post("packets", {"id": existing["id"]})[1]["matched"], 12)
                self.assertEqual(self.post("import?name=retry.cap", original)[0], 409)
            finally:
                resume.set()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            _, state = self.post("import-status", {"job": job["job"]})
            if state["state"] != "indexing":
                break
            time.sleep(.02)
        self.assertEqual(state["state"], "ready")

    def test_errors_preserve_open_capture(self):
        status, capture = self.post("import?name=case.cap", training_capture())
        self.assertEqual(status, 200)
        scope = {"id": capture["id"]}
        for route, extra in [("packets", {"page": None}), ("view", {"filter": []}),
                             ("report", {"format": "invalid"}), ("frame", {"frame": "90000"}),
                             ("view", {"filter": "tcp.stream =="})]:
            with self.subTest(route=route):
                self.assertEqual(self.post(route, scope | extra)[0], 400)
        with patch("app.investigate", side_effect=RuntimeError("private failure detail")):
            status, result = self.post("view", scope)
            self.assertEqual(status, 500)
            self.assertNotIn("private failure detail", result["error"])
        self.assertEqual(self.post("view", scope)[1]["matched"], 12)
        self.assertEqual(self.post("close", scope)[0], 200)
        self.assertEqual(self.post("view", scope)[0], 404)
        self.assertEqual(self.post("status")[1]["captures"], [])
