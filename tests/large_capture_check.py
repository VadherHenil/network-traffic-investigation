"""Opt-in end-to-end capacity check. Example: python -m tests.large_capture_check --gib 5 --work-dir D:/scratch"""

import argparse
import hashlib
import http.client
import json
import struct
import tempfile
import threading
import time
from pathlib import Path

from app import MAX_BYTES, Handler, Workspace, WorkspaceServer
from capture import version
from tests.fixtures import checksum, training_capture


def udp_record(record_size):
    wire = record_size - 16
    ip = struct.pack("!BBHHHBBH4s4s", 69, 0, wire - 14, 1, 0x4000, 64, 17, 0,
                     bytes([192, 0, 2, 80]), bytes([198, 51, 100, 80]))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    ethernet = bytes.fromhex("0200000000020200000000010800")
    udp = struct.pack("!HHHH", 62345, 62346, wire - 34, 0)
    return struct.pack("<IIII", 1768222810, 0, wire, wire) + ethernet + ip + udp + bytes(wire - 42)


def synthetic_stream(size, record_size):
    """Mix the investigation fixture with full-length UDP frames, keeping generation memory under 2 MiB."""
    prefix = training_capture()
    count, tail = divmod(size - len(prefix), record_size)
    if 0 < tail < 58:
        count -= 1
        tail += record_size
    expected_frames = 12 + count + bool(tail)

    def chunks():
        yield prefix
        record = udp_record(record_size)
        batch = (1024 * 1024) // len(record)
        packet_batch = record * batch
        for _ in range(count // batch):
            yield packet_batch
        if count % batch:
            yield record * (count % batch)
        if tail:
            yield udp_record(tail)
    return chunks(), expected_frames


def verify(port, size, record_size):
    def post(route, data=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3600)
        try:
            body = json.dumps(data or {}).encode() if headers is None else data
            conn.request("POST", "/api/" + route, body, {"X-HENIX": "workspace", **(headers or {})})
            result = conn.getresponse()
            raw = result.read()
            if result.status >= 400:
                raise RuntimeError(f"{route} returned {result.status}: {raw[:500]!r}")
            return json.loads(raw) if result.getheader("Content-Type").startswith("application/json") else raw
        finally:
            conn.close()

    source, expected = synthetic_stream(size, record_size)
    digest = hashlib.sha256()

    def counted():
        for block in source:
            digest.update(block)
            yield block

    start = time.monotonic()
    job = post("import?background=1&name=capacity.cap", counted(), {"Content-Length": str(size)})
    print(f"Uploaded {size:,} bytes in {time.monotonic() - start:.1f}s.", flush=True)
    next_update = 0
    while job["state"] == "indexing":
        if time.monotonic() > next_update:
            print(f"Indexed {job['frames']:,} of {expected:,} frames.", flush=True)
            next_update = time.monotonic() + 20
        time.sleep(0.5)
        job = post("import-status", {"job": job["job"]})
    assert job["state"] == "ready", job
    evidence = job["capture"]
    index_seconds = time.monotonic() - start
    assert (evidence["size"], evidence["total"], evidence["sha256"]) == (size, expected, digest.hexdigest())
    print(f"Verified SHA-256 and {expected:,} indexed frames in {time.monotonic() - start:.1f}s.", flush=True)
    scope = {"id": evidence["id"]}
    last = post("packets", scope | {"page": (expected-1) // 50})
    assert last["packets"][-1]["frame"] == str(expected)
    view = post("view", scope)
    assert view["matched"] == expected and sum(view["stats"]["bins"]) == expected
    assert any(f["title"] == "HTTP activity" for f in view["findings"])
    print("Verified final page, full overview and packet findings.", flush=True)
    selected = post("packets", scope | {"filter": "udp.dstport == 62346", "page": (expected-13) // 50})
    assert selected["matched"] == expected-12 and selected["packets"][-1]["frame"] == str(expected)
    frame_start = time.monotonic()
    decoded = post("frame", scope | {"frame": str(expected)})
    frame_seconds = time.monotonic() - frame_start
    assert decoded["dst_port"] == "62346" and decoded["captured"] == decoded["wire"]
    assert post("preview", scope)["included_frames"] == 40
    assert evidence["sha256"].encode() in post("report", scope | {"format": "html"})
    assert post("report", scope | {"format": "zip"}).startswith(b"PK")
    assert post("close", scope)["closed"]
    print(f"Verified filtering, last-frame dissection, AI preview, HTML/ZIP exports and close in "
          f"{time.monotonic() - start:.1f}s total.", flush=True)
    return dict(capture_bytes=size, frames=expected, record_bytes=record_size,
                upload_and_index_seconds=round(index_seconds, 3), late_frame_seconds=round(frame_seconds, 3),
                elapsed_seconds=round(time.monotonic() - start, 3))


class ResourceSampler:
    """Sample the server process, its decoder children and visible workspace files."""

    def __init__(self, folder):
        import psutil  # Optional benchmark dependency. HENIX itself uses the standard library.
        self.psutil = psutil
        self.process = psutil.Process()
        self.folder = Path(folder)
        self.peaks = dict(python_rss_bytes=0, tshark_rss_bytes=0, combined_rss_bytes=0, workspace_bytes=0)
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.sample)
        self.error = None

    def sample(self):
        try:
            while True:
                python = self.process.memory_info().rss
                decoders = 0
                for child in self.process.children(recursive=True):
                    try:
                        if child.name().lower() in ("tshark", "tshark.exe"):
                            decoders += child.memory_info().rss
                    except self.psutil.NoSuchProcess:
                        continue
                disk = 0
                for path in self.folder.rglob("*"):
                    try:
                        if path.is_file():
                            disk += path.stat().st_size
                    except FileNotFoundError:
                        continue
                sample = dict(python_rss_bytes=python, tshark_rss_bytes=decoders,
                              combined_rss_bytes=python + decoders, workspace_bytes=disk)
                for key, value in sample.items():
                    self.peaks[key] = max(self.peaks[key], value)
                if self.done.wait(0.25):
                    break
        except Exception as error:
            self.error = error


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gib", type=float, required=True)
    parser.add_argument("--record-size", type=int, default=8192, help="PCAP record bytes, including 16-byte record header.")
    parser.add_argument("--work-dir", type=Path, help="Existing drive/directory with room for the working capture and index.")
    parser.add_argument("--metrics", type=Path, help="Write a JSON benchmark result (requires psutil).")
    args = parser.parse_args()
    size = int(args.gib * 1024**3)
    if not 1024**2 <= size <= MAX_BYTES or not 64 <= args.record_size <= 65480:
        parser.error("Use a capture between 1 MiB and 5 GiB and a record size between 64 and 65480.")
    with tempfile.TemporaryDirectory(dir=args.work_dir, prefix="henix-capacity-") as folder:
        with WorkspaceServer(("127.0.0.1", 0), Handler) as server:
            server.workspace = Workspace(folder)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            sampler = None
            try:
                if args.metrics:
                    sampler = ResourceSampler(folder)
                    sampler.thread.start()
                result = verify(server.server_port, size, args.record_size)
                assert not list(Path(folder).iterdir()), "Closing the capture left working files."
            finally:
                if sampler:
                    sampler.done.set()
                    sampler.thread.join()
                server.shutdown()
                thread.join()
            if sampler:
                if sampler.error:
                    raise RuntimeError("Could not collect benchmark measurements") from sampler.error
                result.update(decoder=version(), sample_interval_seconds=0.25, sampled_peaks=sampler.peaks)
                args.metrics.parent.mkdir(parents=True, exist_ok=True)
                args.metrics.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
                print(json.dumps(result, indent=2))
