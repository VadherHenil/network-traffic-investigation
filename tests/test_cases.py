"""Portable case integrity, compatibility and preservation of analyst state."""

import hashlib
import io
import json
import sqlite3
import struct
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from app import Workspace
from capture import Capture
from case_io import DIGEST_SIZE, MAGIC, open_snapshot, prepare_snapshot, write_snapshot
from tests.fixtures import training_capture


class CaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as folder:
            ws = Workspace(folder)
            try:
                capture = ws.add(training_capture(), "evidence.cap", "Sensor A", "2026-01-10")
                duplicate = ws.add(training_capture(), "copy.cap", "Sensor B", "2026-01-11")
                assert duplicate is capture
                cls.history = capture.acquisitions
                cls.annotations = dict(pins=[dict(frames=["1", "2"], note="Matched DNS exchange")],
                                       conclusion="Resolver answered the client.")
                capture.annotations = cls.annotations
                observations = [dict(text="Resolver responded.", evidence=capture.id, frames=[2])]
                review = dict(id="a" * 32, provider="openai", provider_label="OpenAI", model="test-model",
                              text=json.dumps({"observations": observations}), complete=True, matched=2,
                              frames=[1, 2], approved=[0])
                prefix, total = prepare_snapshot(capture, "dns", {"dns": review})
                result = io.BytesIO()
                write_snapshot(capture, prefix, result)
                cls.saved = result.getvalue()
                assert len(cls.saved) == total
                ws.forget(capture)
            finally:
                ws.shutdown()

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.ws = Workspace(folder.name)
        self.addCleanup(self.ws.shutdown)

    def restore(self, data, rebuild=False):
        return open_snapshot(self.ws, io.BytesIO(data), len(data), rebuild)

    def repack(self, edit=None, evidence=None, index=None):
        header_start = len(MAGIC) + 4
        header_size, = struct.unpack("!I", self.saved[len(MAGIC):header_start])
        offset = header_start + header_size
        meta = json.loads(self.saved[header_start:offset])
        original = self.saved[offset:offset + meta["size"]]
        original_index = self.saved[offset + meta["size"]:-DIGEST_SIZE]
        evidence = original if evidence is None else evidence
        index = original_index if index is None else index
        meta.update(size=len(evidence), index_size=len(index))
        if edit:
            edit(meta)
        raw = json.dumps(meta).encode()
        body = MAGIC + struct.pack("!I", len(raw)) + raw + evidence + index
        return body + hashlib.sha256(body).digest()

    def test_roundtrip_without_indexing_and_preserve_history(self):
        with patch.object(Capture, "__init__", side_effect=AssertionError("Decoded despite compatible index")):
            restored = self.restore(self.saved)
        self.assertTrue(restored["index_reused"])
        self.assertEqual(restored["filter"], "dns")
        capture = self.ws.captures[restored["capture"]["id"]]
        self.assertEqual(capture.path.read_bytes(), training_capture())
        self.assertEqual(capture.name, "evidence.cap")
        self.assertEqual(capture.source, "Sensor A")
        self.assertEqual(capture.acquisitions, self.history)
        self.assertEqual([entry["source"] for entry in self.history], ["Sensor A", "Sensor B"])
        self.assertEqual(capture.annotations, self.annotations)
        self.assertEqual([row["frame.number"] for row in capture.select("dns")], ["1", "2"])
        review = self.ws.reviews[(capture.id, "dns")]
        self.assertTrue(review["observations"][0]["valid"])
        self.assertEqual(review["approved"], [0])
        with self.assertRaisesRegex(ValueError, "already open"):
            self.restore(self.saved)
        self.ws.forget(capture)
        self.assertEqual(list(self.ws.folder.iterdir()), [])

    def test_incompatible_decoder_and_forced_rebuild(self):
        for data, force in ((self.repack(lambda m: m.update(decoder="Older decoder")), False),
                            (self.repack(index=b"discard this index"), True)):
            with self.subTest(force=force):
                result = self.restore(data, force)
                self.assertFalse(result["index_reused"])
                self.assertEqual(result["capture"]["total"], 12)
                self.ws.forget(self.ws.captures[result["capture"]["id"]])

    def test_reject_damaged_and_inconsistent_cases_atomically(self):
        invalid = [
            self.saved[:-1],
            self.saved[:-1] + bytes([self.saved[-1] ^ 1]),
            self.repack(evidence=b"different evidence"),
            self.repack(lambda m: m.update(frames=500)),
            self.repack(lambda m: m["annotations"]["pins"][0].update(frames=["13"])),
            self.repack(lambda m: m["reviews"]["dns"].update(approved=[17])),
        ]
        with tempfile.TemporaryDirectory() as folder:
            dbpath = Path(folder) / "alternate.sqlite"
            with closing(sqlite3.connect(dbpath)) as db:
                db.execute("CREATE TABLE alternate(value)")
                db.commit()
            invalid.append(self.repack(index=dbpath.read_bytes()))
        for pos, case in enumerate(invalid):
            with self.subTest(pos=pos), self.assertRaises(ValueError):
                self.restore(case)
            self.assertFalse(self.ws.reviews)
            self.assertFalse(self.ws.captures)
            self.assertEqual(list(self.ws.folder.iterdir()), [])
