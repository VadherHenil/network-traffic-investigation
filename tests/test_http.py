"""HTTP checks for a fresh workspace, import errors and recoverable failures."""

import http.client
import hashlib
import io
import json
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from app import COPY_CHUNK, MAX_BYTES, Handler, Workspace, WorkspaceServer
from capture import Capture
from case_io import DIGEST_SIZE, write_snapshot
from tests.fixtures import training_capture


class WorkspaceHTTPTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.server = WorkspaceServer(("127.0.0.1", 0), Handler)
        self.server.workspace = Workspace(folder.name)
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

    def test_case_download_and_reopen(self):
        route = "import?name=original.cap&source=Tap+A"
        status, capture = self.post(route, training_capture())
        self.assertEqual(status, 200)
        _, duplicate = self.post("import?name=copy.cap&source=Tap+B", training_capture())
        self.assertEqual([a["source"] for a in duplicate["acquisitions"]], ["Tap A", "Tap B"])
        scope = {"id": capture["id"], "filter": "dns"}
        self.assertEqual(self.post("annotations", scope | {"action": "pin", "frames": [2], "note": "answer"})[0], 200)
        with patch("case_io.HEADER_SIZE", 10):
            self.assertEqual(self.post("case-save", scope)[0], 400)
        status, ticket = self.post("case-save", scope)
        self.assertEqual(status, 200)
        self.assertEqual(self.post("annotations", scope | {"action": "remove", "frames": [2]})[0], 200)
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=15)
        try:
            conn.request("GET", ticket["url"])
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            self.assertIn(".henix", response.headers["Content-Disposition"])
            saved = response.read()
            self.assertEqual(len(saved), int(response.headers["Content-Length"]))
            conn.request("GET", ticket["url"])
            response = conn.getresponse()
            self.assertEqual(response.status, 404)
            response.read()
        finally:
            conn.close()
        self.assertEqual(self.post("close", scope)[0], 200)
        status, result = self.post("case-open", saved)
        self.assertEqual(status, 200)
        self.assertEqual(result["capture"], duplicate)
        self.assertTrue(result["index_reused"])
        self.assertEqual(result["filter"], "dns")
        status, restored = self.post("view", scope)
        self.assertEqual(status, 200)
        self.assertEqual(restored["matched"], 2)
        self.assertEqual(restored["annotations"]["pins"][0]["note"], "answer")
        self.assertEqual(self.post("close", scope)[0], 200)

    def test_shutdown_finishes_active_case_download_before_removing_index(self):
        _, info = self.post("import?name=case.cap", training_capture())
        _, ticket = self.post("case-save", {"id": info["id"]})
        ws = self.server.workspace
        index = ws.captures[info["id"]].index.path
        streaming, resume = threading.Event(), threading.Event()

        def paused_download(*args):
            streaming.set()
            if not resume.wait(8):
                raise RuntimeError("Timed out waiting to finish case download.")
            write_snapshot(*args)

        with patch("app.write_snapshot", side_effect=paused_download):
            conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
            self.addCleanup(conn.close)
            conn.request("GET", ticket["url"])
            reply = conn.getresponse()
            self.assertEqual(reply.status, 200)
            self.assertTrue(streaming.wait(3))
            self.server.shutdown()
            closer = threading.Thread(target=self.server.server_close)
            closer.start()
            try:
                self.assertTrue(ws.stopping.wait(3))
                self.assertTrue(index.is_file())
                self.assertTrue(closer.is_alive())
            finally:
                resume.set()
                closer.join(8)
            saved = reply.read()
        self.assertEqual(hashlib.sha256(saved[:-DIGEST_SIZE]).digest(), saved[-DIGEST_SIZE:])
        self.assertFalse(closer.is_alive())
        self.assertFalse(ws.captures)
        self.assertEqual(list(ws.folder.iterdir()), [])

    def test_ai_preview_approval_and_export(self):
        status, capture = self.post("import?name=review.cap", training_capture())
        self.assertEqual(status, 200)
        scope = {"id": capture["id"], "filter": "dns"}
        config = scope | {"redact": True, "provider": "openai", "model": "test-model"}
        with patch.dict("os.environ", {"HENIX_AI_ALLOWED_ORIGINS": "https://api.openai.com"}):
            status, preview = self.post("preview", config)
            self.assertEqual(status, 200)
            self.assertNotIn("portal.example.test", json.dumps(preview["body"]))
            self.assertEqual(self.post("review",config | {"key":"test"})[0],400)
            observations = [{"text":"Resolver answered a lookup.", "evidence":capture["id"], "frames":[2]},
                            {"text":"Impossible frame in excerpt.", "evidence":capture["id"], "frames":[12]}]
            reply = {"output":[{"content":[{"type":"output_text","text":json.dumps({"observations":observations})}]}]}
            with patch("providers.build_opener") as adapter:
                adapter.return_value.open.return_value = io.BytesIO(json.dumps(reply).encode())
                status, reviewed = self.post("review",config | {"key":"test","fingerprint":preview["fingerprint"]})
                self.assertEqual(status,200)
                self.assertEqual(json.loads(adapter.return_value.open.call_args.args[0].data),preview["body"])
        approval = scope | {"review_id":reviewed["id"]}
        self.assertEqual(self.post("review-approval",approval | {"approved":[1]})[0],400)
        self.assertEqual(self.post("review-approval",approval | {"approved":[0]})[0],200)
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=15)
        try:
            conn.request("POST", "/api/report", json.dumps(scope), {"X-HENIX": "workspace"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            body = resp.read().decode()
            self.assertIn("Resolver answered a lookup.",body)
            self.assertNotIn("Impossible frame in excerpt.",body)
        finally:
            conn.close()

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

    def test_cancel_running_lookup_and_keep_evidence_open(self):
        _, info = self.post("import?name=cancel.cap", training_capture())
        capture = self.server.workspace.captures[info["id"]]
        started = threading.Event()
        result = []

        def expensive_lookup(_):
            started.set()
            until = time.monotonic() + 5
            while time.monotonic() < until:
                capture.check_open()
                time.sleep(0.01)
            self.fail("lookup did not receive cancellation")

        with patch.object(capture, "inspect_frame", side_effect=expensive_lookup):
            worker = threading.Thread(target=lambda: result.append(self.post(
                "frame", dict(id=info["id"], frame="1", operation="cancel-test"))))
            worker.start()
            try:
                self.assertTrue(started.wait(3))
                self.assertTrue(self.post("cancel", {"operation": "cancel-test"})[1]["cancelled"])
            finally:
                worker.join(7)
        self.assertEqual(result, [(400, {"error": "Operation cancelled."})])
        self.assertFalse(self.post("cancel", {"operation": "cancel-test"})[1]["cancelled"])
        self.assertEqual(self.post("packets", {"id": info["id"]})[1]["matched"], 12)

    def test_cancel_index_before_publication_releases_workspace(self):
        started, resume = threading.Event(), threading.Event()

        def paused(*args, **kwargs):
            capture = Capture(*args, **kwargs)
            started.set()
            if not resume.wait(8):
                raise RuntimeError("Timeout in test")
            return capture

        with patch("app.Capture", side_effect=paused):
            _, job = self.post("import?background=1&name=first.cap", training_capture())
            try:
                self.assertTrue(started.wait(5))
                self.assertTrue(self.post("cancel", {"job": job["job"]})[1]["cancelled"])
            finally:
                resume.set()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                _, status = self.post("import-status", {"job": job["job"]})
                if status["state"] != "indexing":
                    break
                time.sleep(0.02)
        self.assertEqual(status["state"], "failed")
        self.assertIn("cancel", status["error"].lower())
        self.assertEqual(self.post("status")[1]["captures"], [])
        self.assertEqual(list(self.server.workspace.folder.iterdir()), [])
        self.assertEqual(self.post("import?name=retry.cap", training_capture())[0], 200)

    def test_disk_exhaustion_after_upload_cleans_up_and_allows_retry(self):
        from types import SimpleNamespace
        calls = 0

        def available(_):
            nonlocal calls
            calls += 1
            return SimpleNamespace(free=1024**3 if calls == 1 else 0)

        with patch("app.shutil.disk_usage", side_effect=available):
            status, error = self.post("import?name=low-space.cap", training_capture())
        self.assertEqual(status, 507)
        self.assertIn("space", error["error"].lower())
        self.assertEqual(list(self.server.workspace.folder.iterdir()), [])
        self.assertEqual(self.post("import?name=retry.cap", training_capture())[0], 200)
