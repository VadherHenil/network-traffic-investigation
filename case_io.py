"""Portable, streaming HENIX case snapshots. All payload paths are server-generated."""

import errno
import hashlib
import hmac
import json
import re
import shutil
import sqlite3
import struct
import uuid
from datetime import date, datetime

from capture import Capture, FIELDS, MAX_BYTES, TWO_PASS_IMPORT_BYTES, version
from operations import DiskGuard, MIN_FREE_BYTES
from packet_index import PacketIndex

MAGIC = b"HENIXCASE\x01"
HEADER_SIZE = 16 * 1024**2
MAX_CASE_BYTES = 128 * 1024**3
CHUNK = 1024**2
INDEX_VERSION = 1
DIGEST_SIZE = hashlib.sha256().digest_size


def checked_string(value, limit):
    if (not isinstance(value, str) or len(value) > limit or "\0" in value
            or any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)):
        raise ValueError("Invalid text in capture or case metadata.")
    return value


def parse_acquisitions(items):
    if not isinstance(items, list) or not items:
        raise ValueError("Missing acquisition history.")
    result = []
    for entry in items:
        if not isinstance(entry, dict):
            raise ValueError("Invalid acquisition record.")
        record = {key: checked_string(entry.get(key), limit)
                  for key, limit in (("name", 255), ("source", 2000), ("acquired", 32), ("imported_at", 64))}
        if not record["name"].lower().endswith((".cap", ".pcap", ".pcapng")):
            raise ValueError("Invalid evidence filename.")
        if record["acquired"]:
            date.fromisoformat(record["acquired"])
        if datetime.fromisoformat(record["imported_at"]).utcoffset() is None:
            raise ValueError("Acquisition history is missing its time zone.")
        result.append(record)
    return result


def prepare_snapshot(c, expression, reviews):
    from analyst import annotations
    metadata = dict(sha256=c.digest, size=c.size, frames=len(c.rows), decoder=version(),
                    index_version=INDEX_VERSION, passes=c.dissection_passes, index_size=c.index.path.stat().st_size,
                    acquisitions=parse_acquisitions(c.acquisitions), filter=checked_string(expression, 2048),
                    annotations=annotations(c), reviews=reviews)
    header = json.dumps(metadata, ensure_ascii=True, allow_nan=False).encode()
    if len(header) > HEADER_SIZE:
        raise ValueError("Case notes and review metadata exceed 16 MiB.")
    prefix = MAGIC + struct.pack("!I", len(header)) + header
    total = len(prefix) + c.size + metadata["index_size"] + DIGEST_SIZE
    if total > MAX_CASE_BYTES:
        raise ValueError("This portable case exceeds the 128 GiB archive limit.")
    return prefix, total


def write_snapshot(c, prefix, output):
    checksum = hashlib.sha256(prefix)
    output.write(prefix)
    for path in (c.path, c.index.path):
        with path.open("rb") as source:
            while block := source.read(CHUNK):
                output.write(block)
                checksum.update(block)
    output.write(checksum.digest())


def _read(stream, length):
    data = stream.read(length)
    if len(data) != length:
        raise ValueError("Saved case is incomplete. Copy it again from the originating workstation.")
    return data


def open_snapshot(ws, stream, length, rebuild=False):
    from analyst import validate_annotations
    from providers import validate_saved_review
    if not ws.import_lock.acquire(blocking=False):
        raise ValueError("An import is already in progress. Open the case when it finishes.")
    index = capture = path = None
    published = False
    try:
        if ws.stopping.is_set():
            raise ValueError("The workspace is shutting down.")
        if length < len(MAGIC) + 4 + DIGEST_SIZE:
            raise ValueError("The selected file is not a complete HENIX case.")
        prefix = _read(stream, len(MAGIC) + 4)
        if not prefix.startswith(MAGIC):
            raise ValueError("Choose a supported .henix case file.")
        header_size, = struct.unpack("!I", prefix[-4:])
        if header_size > HEADER_SIZE or header_size > length - len(prefix) - DIGEST_SIZE:
            raise ValueError("Invalid case metadata length.")
        raw = _read(stream, header_size)
        try:
            meta = json.loads(raw)
        except (ValueError, RecursionError):
            raise ValueError("The case contains invalid metadata.") from None
        if not isinstance(meta, dict):
            raise ValueError("The case manifest is missing.")
        raw_size, index_size, frames = (meta.get(key) for key in ("size", "index_size", "frames"))
        if (any(type(n) is not int for n in (raw_size, index_size, frames))
                or not 0 < raw_size <= MAX_BYTES or index_size <= 0 or frames < 0
                or length != len(prefix) + header_size + raw_size + index_size + DIGEST_SIZE
                or length > MAX_CASE_BYTES):
            raise ValueError("Invalid case payload size.")
        records = parse_acquisitions(meta.get("acquisitions"))
        expression = checked_string(meta.get("filter"), 2048)
        signature = checked_string(meta.get("sha256"), 64)
        if not re.fullmatch(r"[0-9a-f]{64}", signature):
            raise ValueError("Invalid capture SHA-256.")
        evidence_id = "EV-" + signature[:12].upper()
        with ws.lock:
            if evidence_id in ws.captures:
                raise ValueError("This evidence is already open. Save and close it before opening its case.")
            if len(ws.captures) >= 8:
                raise ValueError("Close an open capture to make room for this case.")
        passes = 1 if raw_size > TWO_PASS_IMPORT_BYTES else 2
        reuse = not rebuild and (meta.get("index_version"), meta.get("decoder"), meta.get("passes")) == (
            INDEX_VERSION, version(), passes)
        if shutil.disk_usage(ws.folder).free < raw_size + (index_size if reuse else 0) + MIN_FREE_BYTES:
            raise OSError(errno.ENOSPC, "The workspace drive needs more free space to open this case.")
        disk = DiskGuard(ws.folder)
        disk.check()
        path = ws.folder / (uuid.uuid4().hex + ".cap")
        index = PacketIndex(ws.folder, ws.stopping) if reuse else None
        total_hash = hashlib.sha256(prefix + raw)
        evidence_hash = hashlib.sha256()
        for count, destination, is_capture in ((raw_size, path, True), (index_size, index.path if index else None, False)):
            out = destination.open("xb") if destination else None
            try:
                while count:
                    if ws.stopping.is_set():
                        raise ValueError("The workspace is shutting down.")
                    disk.check()
                    block = _read(stream, min(CHUNK, count))
                    count -= len(block)
                    total_hash.update(block)
                    if is_capture:
                        evidence_hash.update(block)
                    if out:
                        out.write(block)
            finally:
                if out:
                    out.close()
        if not hmac.compare_digest(_read(stream, DIGEST_SIZE), total_hash.digest()):
            raise ValueError("Case integrity check failed. The file is damaged or has been modified.")
        if not hmac.compare_digest(evidence_hash.hexdigest(), signature):
            raise ValueError("The original capture does not match the SHA-256 in the case manifest.")
        if reuse:
            try:
                index.validate_snapshot(FIELDS, frames)
            except sqlite3.DatabaseError:
                raise ValueError("The saved index is unreadable. Reopen with Rebuild index selected.") from None
            capture = Capture.from_saved_index(path, signature, records, index, ws.stopping)
        else:
            first = records[0]
            capture = Capture(path, first["name"], signature, first["source"], first["acquired"],
                              stopping=ws.stopping)
            capture.acquisitions = records
        capture.annotations = validate_annotations(capture, meta.get("annotations"))
        raw_reviews = meta.get("reviews")
        if not isinstance(raw_reviews, dict) or len(raw_reviews) > 64:
            raise ValueError("Invalid saved review list.")
        restored = {(capture.id, checked_string(filt, 2048)): validate_saved_review(review, capture)
                    for filt, review in raw_reviews.items()}
        with ws.lock:
            ws.reviews.update(restored)
            while len(ws.reviews) > 64:
                ws.reviews.popitem(last=False)
            ws.captures[capture.id] = capture
            published = True
        return dict(capture=capture.manifest(), filter=expression, index_reused=reuse)
    finally:
        try:
            if not published:
                if capture is not None:
                    capture.close()
                elif index is not None:
                    index.close()
                if path is not None:
                    path.unlink(missing_ok=True)
        finally:
            ws.import_lock.release()
