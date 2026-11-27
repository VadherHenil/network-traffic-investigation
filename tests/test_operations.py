import gc
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from capture import Capture
from operations import ByteCache
from tests.fixtures import training_capture


class CaptureCacheTests(unittest.TestCase):
    def test_cache_recency_entry_and_byte_limits(self):
        cache = ByteCache(10, 2)
        cache.put("original", 1, 4)
        cache.put("other", 2, 4)
        self.assertEqual(cache.get("original"), 1)
        cache.put("new", 3, 4)
        self.assertIsNone(cache.get("other"))
        cache.put("expensive", 4, 9)
        self.assertEqual(cache.size, 9)
        self.assertIsNone(cache.get("original"))
        cache.put("oversize", 5, 11)
        self.assertIsNone(cache.get("oversize"))

    def test_reused_filters_survive_switching_and_evict_files(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.cap"
            raw = training_capture()
            path.write_bytes(raw)
            capture = Capture(path, path.name, hashlib.sha256(raw).hexdigest())
            try:
                capture.filter_cache = ByteCache(1024**2, 2)
                dns = capture.select("dns")
                tcp_path = capture.select("tcp").matches
                with patch("capture.output_stream", side_effect=AssertionError("filter re-decoded")):
                    self.assertIs(capture.select("dns"), dns)
                capture.select("frame.number == 1")
                gc.collect()
                self.assertFalse(tcp_path.exists())
                self.assertTrue(dns.matches.exists())
                first = capture.inspect_frame("1")
                capture.inspect_frame("2")
                with patch("capture.run", side_effect=AssertionError("frame re-decoded")):
                    self.assertEqual(capture.inspect_frame("1"), first)
            finally:
                capture.close()
