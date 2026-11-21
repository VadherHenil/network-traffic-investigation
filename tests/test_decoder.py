import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from capture import Capture, metrics, output_stream, packet_row
from tests.fixtures import training_capture


def pcap_packet(data, wire_size=None):
    return struct.pack("<IIII", 1768222810, 0, len(data), wire_size or len(data)) + data


class FrameInspectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        base = training_capture()
        # Append an ARP request with a capture length shorter than its padded wire length.
        arp = bytes.fromhex("ffffffffffff 020000000001 0806 0001 0800 06 04 0001 "
                            "020000000001 c0000201 000000000000 c0000202")
        # Continue the fixture's last TCP stream with a TLS application-data record.
        # The record bytes are synthetic opaque data; no TLS secrets are required.
        hello_size = 134
        hello = base[-hello_size:]
        data = b"\x17\x03\x03\x00\x10" + bytes(range(16))
        new_frame = bytearray(hello[:54] + data)
        struct.pack_into("!H", new_frame, 16, len(new_frame)-14)
        seq = struct.unpack_from("!I", hello, 38)[0]
        struct.pack_into("!I", new_frame, 38, seq+hello_size-54)
        combined = base + pcap_packet(arp, 60) + pcap_packet(new_frame)
        path = Path(cls.folder.name) / "test.pcap"
        path.write_bytes(combined)
        cls.capture = Capture(path, path.name, hashlib.sha256(combined).hexdigest())

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def test_non_ip_and_truncated_capture(self):
        row = packet_row(self.capture.by_number["13"])
        self.assertIsNone(row["src_port"])
        self.assertIsNone(row["dst_port"])
        self.assertIn("arp", row["layers"])
        info = self.capture.inspect_frame("13")
        self.assertEqual((info["captured"], info["wire"]), (42, 60))
        self.assertIn("ff ff ff ff ff ff", info["hex"])
        self.assertIn("Address Resolution Protocol", info["detail"])
        self.assertEqual(info["payload"], "")
        self.assertIn(("arp", 1), metrics(self.capture.rows)["layer_counts"])

    def test_frame_data_and_encryption_evidence(self):
        reply = self.capture.inspect_frame("7")
        self.assertEqual((reply["src_port"], reply["dst_port"]), ("80", "51001"))
        self.assertEqual(reply["payload_field"], "http.file_data")
        self.assertIn("text/plain", reply["format"])
        self.assertIn("|OK|", reply["payload"])
        hello = self.capture.inspect_frame("12")
        self.assertIn("handshake fields", hello["visibility"])
        record = self.capture.inspect_frame("14")
        self.assertIn("protected records", record["visibility"])
        self.assertEqual(record["payload_field"], "tls.app_data")
        self.assertEqual(record["payload_size"], 16)
        with self.assertRaisesRegex(ValueError, "outside"):
            self.capture.inspect_frame("0")

    def test_no_hierarchy_cutoff(self):
        template = self.capture.rows[0]
        rows = [{**template, "frame.protocols": "eth:outer:encap" + str(i)} for i in range(205)]
        stats = metrics(rows)
        self.assertEqual(len(stats["hierarchy"]), 207)
        self.assertIn(("encap204", 1), stats["layer_counts"])


class DiskIndexTests(unittest.TestCase):
    def test_shutdown_interrupts_decoder_before_first_record(self):
        def shutdown():
            raise ValueError("The workspace is closing.")

        with patch("capture.tshark", return_value=sys.executable):
            with self.assertRaisesRegex(ValueError, "closing"):
                with output_stream(["-c", "import time; time.sleep(10)"], shutdown) as output:
                    self.assertEqual(output.read(), b"")

    def test_large_frame_count_pages_and_failed_filter_rollback(self):
        # Cross the old frame-count limit with a modest file. Exercise single-pass
        # indexing, two-pass filtering, direct late-page seeks and a held view.
        arp = bytes.fromhex("ffffffffffff 020000000001 0806 0001 0800 06 04 0001 "
                            "020000000001 c0000201 000000000000 c0000202")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "dense.cap"
            with path.open("wb") as sink:
                sink.write(training_capture()[:24])
                chunk = pcap_packet(arp) * 1000
                for _ in range(51):
                    sink.write(chunk)
            with patch("capture.TWO_PASS_IMPORT_BYTES", 1):
                capture = Capture(path, path.name, "test")
            try:
                self.assertEqual(capture.manifest()["dissection_passes"], 1)
                self.assertEqual(len(capture.rows), 51000)
                self.assertEqual([r["frame.number"] for r in capture.rows[-2:]], ["50999", "51000"])
                late = capture.select("arp && frame.number > 50996")
                self.assertEqual([r["frame.number"] for r in late[1:3]], ["50998", "50999"])
                with self.assertRaises(ValueError):
                    capture.select("tcp.stream ==")
                self.assertIs(capture.select("arp && frame.number > 50996"), late)
                self.assertEqual(capture.select("frame.number == 51000")[0]["frame.number"], "51000")
                self.assertEqual(late.get_frame(50997)["frame.number"], "50997")
                self.assertIsNone(late.get_frame(1))
            finally:
                capture.close()
            self.assertEqual(list(Path(folder).iterdir()), [path])

    def test_cancelled_build_removes_derivatives(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "small.cap"
            path.write_bytes(training_capture())

            def cancel(_):
                raise RuntimeError("cancelled")

            with self.assertRaisesRegex(RuntimeError, "cancelled"):
                Capture(path, path.name, "test", progress=cancel)
            self.assertEqual(list(Path(folder).iterdir()), [path])
