import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock
from urllib.error import HTTPError

from app import Workspace
from capture import metrics
from findings import investigate
from providers import excerpt, review
from reports import build_report, bundle
from tests.fixtures import training_capture


class InvestigationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.ws = Workspace(cls.folder.name)
        cls.data = training_capture()
        cls.c = cls.ws.add(cls.data, "training.cap")

    @classmethod
    def tearDownClass(cls):
        cls.ws.shutdown()
        cls.folder.cleanup()

    def test_training_bytes_and_filters(self):
        for expression, expected in [
            ("dns", [1, 2]), ("dns.flags.response == 1", [2]), ("tcp.stream == 0", list(range(3, 9))),
            ("tcp.stream == 0 && tcp.flags.syn == 1", [3, 4]),
            ("tcp.stream == 0 && (http.request || http.response)", [6, 7]),
            ("tls.handshake.type == 1", [12]), ("frame.number == 12", [12]), ("frame.number == 42", [])]:
            with self.subTest(expression=expression):
                self.assertEqual([int(r["frame.number"]) for r in self.c.select(expression)], expected)
        with self.assertRaises(ValueError):
            self.c.select("tcp.stream ==")
        self.assertEqual(len(self.c.rows), 12)
        self.assertIn("Client Hello", self.c.detail("12"))

    def test_evidence_associations_and_scope(self):
        findings, events = investigate(self.c.rows)
        self.assertEqual([f["frames"] for f in findings], [["1", "2", "3"], ["3", "4", "5"], ["6", "7"], ["12"]])
        self.assertEqual(len({e["frame"] for e in events}), 8)
        dns, _ = investigate(self.c.select("dns.flags.response == 1"))
        self.assertEqual(dns[0]["frames"], ["2"])
        self.assertIn("Only one side", dns[0]["meaning"])
        tcp, _ = investigate(self.c.select("frame.number == 5"))
        self.assertIn("partial", tcp[0]["meaning"])
        self.assertNotIn("initiated", tcp[0]["observation"])
        stats = metrics(self.c.rows)
        self.assertEqual(sum(stats["bins"]), 12)
        self.assertEqual(stats["stream_count"], 2)

    def test_exports_and_empty_capture(self):
        expression = "dns.flags.response == 1"
        rows = self.c.select(expression)
        with zipfile.ZipFile(io.BytesIO(bundle(self.c, rows, expression, None))) as z:
            html = z.read("report/investigation.html").decode()
            self.assertIn(self.c.digest, html)
            self.assertIn(expression, html)
            self.assertIn("1 of 12", html)
            self.assertIn("198.51.100.18", html)
            self.assertIn("evidence/manifest.csv", z.namelist())
            self.assertEqual(len(z.read("evidence/timeline.csv").splitlines()), 2)
            self.assertIn("diagrams/observed-flow.svg", z.namelist())
        empty = self.ws.add(self.data[:24], "empty.cap")
        self.assertEqual(empty.rows, [])
        self.assertIn("No frames matched", build_report(empty, [], "", None)[0])

    def test_corrupt_upload_is_removed(self):
        before = set(Path(self.folder.name).iterdir())
        with self.assertRaises(ValueError):
            self.ws.add(self.data[:30], "truncated.cap")
        self.assertEqual(set(Path(self.folder.name).iterdir()), before)

    def test_pcapng_import(self):
        def block(kind, body):
            size = len(body) + 12
            return struct.pack("<II", kind, size) + body + struct.pack("<I", size)
        section = block(0x0a0d0d0a, struct.pack("<IHHq", 0x1a2b3c4d, 1, 0, -1))
        interface = block(1, struct.pack("<HHI", 1, 0, 65535))
        packet_length = int.from_bytes(self.data[32:36], "little")
        packet = self.data[40:40+packet_length]
        enhanced = block(6, struct.pack("<5I", 0, 0, 1, len(packet), len(packet)) + packet + bytes(-len(packet) % 4))
        c = self.ws.add(section + interface + enhanced, "training.pcapng")
        self.assertEqual(len(c.select("dns")), 1)

    def test_provider_adapters_and_excerpt(self):
        evidence = excerpt(self.c, self.c.rows, "", investigate(self.c.rows)[1])
        self.assertEqual(evidence["included_frames"], 12)
        self.assertNotIn("/status", json.dumps(evidence))
        responses = {
            "openai": {"output": [{"content": [{"type": "output_text", "text": "Review of frame 1"}]}]},
            "gemini": {"candidates": [{"content": {"parts": [{"text": "Review of frame 1"}]}, "finishReason": "STOP"}]}}
        for provider, payload in responses.items():
            opener = Mock()
            opener.open.return_value = io.BytesIO(json.dumps(payload).encode())
            result = review(provider, "test-key", "test-model", evidence, opener)
            self.assertTrue(result["complete"])
            self.assertEqual(result["text"], "Review of frame 1")
            req = opener.open.call_args.args[0]
            self.assertNotIn("test-key", req.full_url)
            self.assertNotIn(b"test-key", req.data)
            self.assertIn("test-key", str(req.header_items()))
            self.assertIn(self.c.id, req.data.decode())
        opener = Mock()
        opener.open.side_effect = HTTPError("https://example.test/", 401, "denied", {}, None)
        with self.assertRaisesRegex(ValueError, "401"):
            review("openai", "test-key", "test-model", evidence, opener)


if __name__ == "__main__":
    unittest.main()
