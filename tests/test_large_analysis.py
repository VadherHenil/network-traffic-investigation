"""Large indexed scopes must find late exchanges without iterating every row in Python."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from capture import Capture, FIELDS
from findings import investigate
from large_metrics import metrics
from packet_index import FrameLookup, FrameView, PacketIndex
from providers import excerpt
from reports import build_report


class LargeAnalysisTests(unittest.TestCase):
    def test_late_exchange_and_full_scope_statistics(self):
        filler = 50001
        def frames():
            common = {"frame.len": 64, "frame.cap_len": 64, "_ws.col.Source": "192.0.2.20",
                      "_ws.col.Destination": "192.0.2.30", "frame.time_epoch": "100.5",
                      "frame.protocols": "eth:ip:udp", "_ws.col.Protocol": "UDP"}
            for n in range(1, filler + 1):
                yield tuple(n if field == "frame.number" else common.get(field) for field in FIELDS)
            for i, http in enumerate([
                {"http.request.method": "GET", "http.request.uri": "/health", "http.response_in": str(filler+2)},
                {"http.request_in": str(filler+1), "http.response.code": "200"}], 1):
                row = {**common, **http, "tcp.stream": "9", "frame.protocols": "eth:ip:tcp:http",
                       "_ws.col.Protocol": "HTTP", "frame.number": filler+i, "frame.time_epoch": "102.25"}
                yield tuple(row.get(field) for field in FIELDS)

        with tempfile.TemporaryDirectory() as folder:
            store = PacketIndex(Path(folder))
            try:
                rows = store.build(FIELDS, frames())
                capture = SimpleNamespace(rows=rows, by_number=FrameLookup(rows), id="EV-TEST", name="late.cap",
                    digest="a"*64, window=Capture.time_window(rows),
                    source="", acquired="", dissection_passes=1, time_window=Capture.time_window)
                # The SQL engine may scan the complete scope, but materializing
                # all Python frame dictionaries would exhaust RAM on dense captures.
                with patch.object(FrameView, "__iter__", side_effect=AssertionError("unbounded row iteration")):
                    stats = metrics(rows)
                    self.assertEqual(sum(stats["bins"]), filler + 2)
                    self.assertEqual(stats["bytes"], 64 * (filler + 2))
                    self.assertEqual(stats["hosts"], 2)
                    self.assertEqual(stats["stream_count"], 1)
                    self.assertEqual(dict(stats["layer_counts"])["http"], 2)
                    findings, events = investigate(rows)
                    self.assertEqual(findings[-1]["frames"], [str(filler+1), str(filler+2)])
                    self.assertIn("status 200", findings[-1]["observation"])
                    sample = excerpt(capture, rows, "", events)
                    self.assertEqual(sample["included_frames"], 40)
                    self.assertEqual(sample["frames"][-1]["frame"], filler+2)
                    html, _ = build_report(capture, rows, "")
                    self.assertIn("50,003 of 50,003", html)
                    self.assertIn("GET /health", html)
                    self.assertIn("Single-pass dissection", html)
                    filtered = store.select([filler+2])
                    result, _ = investigate(filtered)
                    self.assertEqual(result[-1]["frames"], [str(filler+2)])
                    self.assertEqual(metrics(filtered)["bytes"], 64)
            finally:
                store.close()
