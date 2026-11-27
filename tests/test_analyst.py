import csv
import io
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from analyst import annotations, search_conversations, update_annotations, validate_annotations
from app import Workspace
from reports import bundle
from tests.fixtures import training_capture


class AnalystWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.workspace = Workspace(cls.folder.name)
        cls.capture = cls.workspace.add(training_capture(), "training.cap")

    @classmethod
    def tearDownClass(cls):
        cls.workspace.shutdown()
        cls.folder.cleanup()

    def setUp(self):
        self.capture.annotations = {"pins": [], "conclusion": ""}

    def test_search_endpoints_and_original_frame_bounds_with_filter(self):
        results = search_conversations(self.capture.rows, {})
        self.assertEqual([stream["stream"] for stream in results["streams"]], ["0", "1"])
        self.assertFalse(results["has_more"])
        tcp = results["streams"][0]
        self.assertEqual((tcp["packets"], tcp["first"], tcp["last"]), (6, "3", "8"))
        self.assertTrue(tcp["b"].endswith(":80"))
        self.assertEqual([s["stream"] for s in search_conversations(self.capture.rows, {"search": "443"})["streams"]], ["1"])
        self.assertEqual(search_conversations(self.capture.rows, {"search": "' OR 1=1"})["streams"], [])
        self.assertEqual(search_conversations(self.capture.rows, {"page": 1})["streams"], [])
        with patch("analyst.PAGE_SIZE", 1):
            self.assertTrue(search_conversations(self.capture.rows, {})["has_more"])
            second = search_conversations(self.capture.rows, {"page": 1})
            self.assertFalse(second["has_more"])
            self.assertEqual([s["stream"] for s in second["streams"]], ["1"])
        scoped = search_conversations(self.capture.select("http"), {"search": "0"})["streams"]
        self.assertEqual([(s["first"], s["last"], s["packets"]) for s in scoped], [("6", "7", 2)])
        with self.assertRaises(ValueError):
            search_conversations(self.capture.rows, {"page": -1})

    def test_pin_updates_use_original_capture_and_are_idempotent(self):
        edit = {"action": "pin", "frames": ["7", 6, "7"], "note": "   Status exchange  "}
        for _ in range(2):
            update_annotations(self.capture, edit)
        self.assertEqual(annotations(self.capture)["pins"], [{"frames": ["6", "7"], "note": "Status exchange"}])
        update_annotations(self.capture, {**edit, "note": "Revised"})
        self.assertEqual(annotations(self.capture)["pins"][0]["note"], "Revised")
        with self.assertRaises(ValueError):
            update_annotations(self.capture, {**edit, "frames": [13]})
        with self.assertRaises(ValueError):
            update_annotations(self.capture, {**edit, "note": "A" * 2001})
        with self.assertRaises(ValueError):
            validate_annotations(self.capture, {"pins": annotations(self.capture)["pins"] * 2})
        self.assertEqual(len(annotations(self.capture)["pins"]), 1)
        for _ in range(2):
            update_annotations(self.capture, {"action": "remove", "frames": [6, 7]})
        self.assertEqual(annotations(self.capture)["pins"], [])

    def test_filtered_exports_preserve_provenance_and_analyst_evidence(self):
        acquisitions = [{"name": "training.cap", "source": "sensor-a", "acquired": "", "imported_at": "2026-01-01T00:00:00Z"},
                        {"name": "copy.cap", "source": "sensor-b", "acquired": "", "imported_at": "2026-01-02T00:00:00Z"}]
        self.capture.acquisitions = acquisitions
        update_annotations(self.capture, {"action": "pin", "frames": [6, 7], "note": "HTTP <status>"})
        update_annotations(self.capture, {"action": "pin", "frames": [1], "note": "Resolver query"})
        update_annotations(self.capture, {"action": "conclusion", "conclusion": "Needs <follow-up>."})
        archive = bundle(self.capture, self.capture.select("dns"), "dns", None)
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            html = z.read("report/investigation.html").decode()
            self.assertIn("Needs &lt;follow-up&gt;.", html)
            self.assertIn("HTTP &lt;status&gt;", html)
            self.assertIn(self.capture.id + " #7", html)
            manifest = list(csv.DictReader(io.StringIO(z.read("evidence/manifest.csv").decode("utf-8-sig"))))
            self.assertEqual([r["Source"] for r in manifest], ["sensor-a", "sensor-b"])
            self.assertEqual({r["SHA-256"] for r in manifest}, {self.capture.digest})
            timeline = {r["Frame"]: r for r in csv.DictReader(io.StringIO(z.read("evidence/timeline.csv").decode("utf-8-sig")))}
            self.assertEqual(timeline["1"]["Origin"], "Decoder and analyst pin")
            self.assertEqual(timeline["6"]["Origin"], "Analyst pin")
            self.assertEqual(timeline["7"]["Observation"], "HTTP <status>")
            self.assertEqual(timeline["7"]["Source port"], "80")


if __name__ == "__main__":
    unittest.main()
