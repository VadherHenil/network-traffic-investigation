"""Read-only capture dissection and display filtering with Wireshark."""

import os
import re
import shutil
import subprocess
from collections import deque
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from threading import Event, RLock, Thread
from time import monotonic

from packet_index import FrameLookup, FrameView, PacketIndex

ROOT = Path(__file__).resolve().parent
MAX_BYTES = 5 * 1024**3
TWO_PASS_IMPORT_BYTES = 32 * 1024**2
MAX_INSPECTION_BYTES = 64 * 1024**2
COLUMNS = ('gui.column.format:"No.","%m","Time","%t","Source","%s","Destination","%d",'
           '"Protocol","%p","Length","%L","Info","%i","Source port","%uS","Destination port","%uD"')
FIELDS = """frame.number frame.time_epoch frame.len frame.cap_len frame.protocols _ws.col.Protocol _ws.col.Info
_ws.col.Source _ws.col.Destination _ws.col.unres_src_port _ws.col.unres_dst_port
ip.src ip.dst ipv6.src ipv6.dst eth.src eth.dst tcp.srcport tcp.dstport udp.srcport udp.dstport
tcp.stream tcp.seq_raw tcp.ack_raw tcp.flags.syn tcp.flags.ack tcp.flags.reset tcp.len
dns.id dns.qry.name dns.qry.type dns.flags.response dns.flags.rcode dns.response_to dns.response_in
dns.a dns.aaaa dns.cname http.request.method http.host http.request.uri http.response.code
http.request_in http.response_in tls.handshake.type tls.handshake.extensions_server_name""".split()

# These potentially large byte fields are requested only for the inspected frame.
PAYLOAD_FIELDS = ("http.file_data", "tls.app_data", "ssh.encrypted_packet", "esp.encrypted_data",
                  "quic.protected_payload", "tcp.payload", "udp.payload", "data.data")
CONTENT_FIELDS = (*PAYLOAD_FIELDS, "http.content_type", "tls.record.opaque_type", "dtls.record.content_type",
                  "wlan.fc.protected", "wg.type")


def tshark():
    candidates = [os.getenv("TSHARK_PATH"), shutil.which("tshark"),
                  ROOT / ".runtime/wireshark/Wireshark/tshark.exe",
                  Path(os.getenv("ProgramFiles", "C:/Program Files")) / "Wireshark/tshark.exe",
                  Path("/Applications/Wireshark.app/Contents/MacOS/tshark")]
    for path in candidates:
        if path and Path(path).is_file():
            return str(path)
    raise ValueError("Install Wireshark with TShark, or set TSHARK_PATH to its executable, then retry.")


@contextmanager
def output_stream(args, heartbeat=None):
    """Drain stderr concurrently, keeping only the tail. Kill workers on any error."""
    env = dict(os.environ, TZ="UTC", LC_ALL="C", SSLKEYLOGFILE="")
    try:
        process = subprocess.Popen([tshark(), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.DEVNULL, env=env,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except OSError as exc:
        raise ValueError(f"TShark could not start. Check its installation ({exc.strerror}).") from None
    diagnostic = deque(maxlen=2)
    stop = Event()
    cancelled = []

    def drain_errors():
        for chunk in iter(lambda: process.stderr.read(4096), b""):
            diagnostic.append(chunk)

    def monitor():
        while not stop.wait(1):
            try:
                heartbeat()
            except Exception as exc:
                cancelled.append(exc)
                if process.poll() is None:
                    process.kill()
                return

    reader = Thread(target=drain_errors, daemon=True)
    reader.start()
    watcher = Thread(target=monitor, daemon=True) if heartbeat is not None else None
    if watcher:
        watcher.start()
    try:
        yield process.stdout
        result = process.wait()
        reader.join()
        if cancelled:
            raise cancelled[0]
        if result:
            message = b"".join(diagnostic).decode("utf-8", "replace").strip()
            raise ValueError(message[-1200:] or f"TShark stopped with exit code {result}. Check available memory and disk space.")
    finally:
        stop.set()
        if process.poll() is None:
            process.kill()
        process.wait()
        if watcher:
            watcher.join()
        reader.join()
        process.stdout.close()
        process.stderr.close()


def run(args, heartbeat=None):
    """Only for the decoder version and one explicitly selected frame."""
    with output_stream(args, heartbeat) as output:
        raw = output.read(MAX_INSPECTION_BYTES + 1)
        if len(raw) > MAX_INSPECTION_BYTES:
            raise ValueError("The decoded packet detail exceeds the 64 MiB inspection limit. Inspect this frame in Wireshark.")
    return raw.decode("utf-8", "replace")


@lru_cache(maxsize=1)
def version():
    deadline = monotonic() + 15
    def check_deadline():
        if monotonic() > deadline:
            raise ValueError("TShark timed out while reporting its version. Check the decoder installation.")

    lines = run(["-v"], check_deadline).splitlines()
    if not lines:
        raise ValueError("TShark returned no version information. Check the decoder installation.")
    return lines[0]


def utc(epoch):
    if epoch is None or epoch == "":
        return "Unavailable"
    try:
        stamp = datetime.fromtimestamp(float(epoch), timezone.utc)
    except (ValueError, OSError, OverflowError):
        return "Unavailable"
    return stamp.isoformat(timespec="microseconds").replace("+00:00", "Z")


def address(row, direction):
    column = "_ws.col.Source" if direction == "src" else "_ws.col.Destination"
    if row.get(column):
        return row[column]
    return next((row[f"{p}.{direction}"].split(",")[0] for p in ("ip", "ipv6", "eth")
                 if f"{p}.{direction}" in row), "—")


def port(row, direction):
    return (row.get(f"_ws.col.unres_{direction}_port")
            or row.get(f"tcp.{direction}port") or row.get(f"udp.{direction}port"))


def protocol_layers(row):
    return [layer for layer in row.get("frame.protocols", "").split(":") if layer]


def endpoint(row, direction):
    addr = address(row, direction)
    number = port(row, direction)
    if not number:
        return addr
    return f"[{addr}]:{number}" if ":" in addr else f"{addr}:{number}"


def payload_visibility(row, fields):
    layers = set(protocol_layers(row))
    protected_tls = "tls.app_data" in fields or "23" in fields.get("tls.record.opaque_type", "").split(",")
    if protected_tls and "http.file_data" in fields:
        return "TLS protected records are present, and the decoder also exposes HTTP body data."
    if "http.file_data" in fields:
        return "The decoder exposes HTTP body data. See the payload and headers for its representation."
    if protected_tls:
        return "TLS protected records are present. The frame bytes retain the on-wire representation."
    if any(k in fields for k in ("ssh.encrypted_packet", "quic.protected_payload")):
        return "The decoder identified protected payload bytes. The protocol tree shows the available fields."
    if fields.get("wlan.fc.protected") in ("True", "1") or fields.get("wg.type") == "4":
        return "The decoder identified a protected transport frame. Inspect the protocol tree for visible fields."
    if "esp" in layers:
        return "An IPsec ESP envelope is visible. The capture alone does not establish its encryption transform."
    if "23" in fields.get("dtls.record.content_type", "").split(","):
        return "DTLS application records are present. The frame bytes show their on-wire representation."
    if row.get("tls.handshake.type"):
        return "TLS handshake fields are visible. Expand the protocol tree to inspect the negotiation."
    if layers & {"tls", "dtls", "quic", "wg", "ssh"}:
        return "Secure-protocol headers are visible. Payload protection for this frame is undetermined."
    if row.get("tcp.len") == "0":
        return "This TCP segment declares zero payload bytes."
    if row.get("http.request.method") or row.get("http.response.code") or "dns.qry.name" in row:
        return "Application fields are decoded and visible in the protocol tree."
    return "Captured bytes are available. Encryption cannot be determined from undecoded bytes alone."


def hex_ascii(data):
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset+16]
        ascii_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:04x}  {chunk.hex(' '):47}   |{ascii_text}|")
    return "\n".join(lines)


FIELD_INDEX = {key: i for i, key in enumerate(FIELDS)}
TRANSPORT_INDEX = [i for i, key in enumerate(FIELDS) if key.startswith(("tcp.", "udp."))]
BOOLEAN_INDEX = [FIELD_INDEX[key] for key in ("dns.flags.response", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset")]


def index_values(output, count):
    for raw in iter(lambda: output.readline(MAX_INSPECTION_BYTES + 1), b""):
        if len(raw) > MAX_INSPECTION_BYTES:
            raise ValueError("One decoded frame's metadata exceeds 64 MiB. Inspect this frame in Wireshark.")
        values = raw.rstrip(b"\r\n").decode("utf-8", "replace").split("\t")
        if len(values) != len(FIELDS) or not all(values[FIELD_INDEX[k]].isdigit() for k in ("frame.number", "frame.len", "frame.cap_len")):
            raise ValueError("The decoder returned incomplete frame metadata. Verify the capture in Wireshark.")
        count[0] += 1
        if int(values[0]) != count[0]:
            raise ValueError("The decoder returned a discontinuous frame index. Verify the capture in Wireshark.")
        if utc(values[FIELD_INDEX["frame.time_epoch"]]) == "Unavailable":
            values[FIELD_INDEX["frame.time_epoch"]] = ""
        for i in TRANSPORT_INDEX:
            if "," in values[i]:
                values[i] = values[i].split(",", 1)[0]
        for i in BOOLEAN_INDEX:
            if values[i] == "True":
                values[i] = "1"
            elif values[i] == "False":
                values[i] = "0"
        yield tuple(value or None for value in values)


class Capture:
    def __init__(self, path, name, digest, source="", acquired="", progress=None, stopping=None):
        self.path, self.name, self.digest = path, name, digest
        self.id = "EV-" + digest[:12].upper()
        self.source, self.acquired = source, acquired
        self.size = path.stat().st_size
        if self.size > MAX_BYTES:
            raise ValueError("Capture files are limited to 5 GiB.")
        self.dissection_passes = 1 if self.size > TWO_PASS_IMPORT_BYTES else 2
        self.args = ["-n", "-o", COLUMNS, "-r", str(path)]
        decode = self.args if self.dissection_passes == 1 else [*self.args, "-2"]
        fields = [item for field in FIELDS for item in ("-e", field)]
        self.stopping = stopping
        self.index = PacketIndex(path.parent, stopping)
        count = [0]

        def heartbeat():
            self.check_open()
            if progress:
                progress(count[0])

        try:
            self.check_open()
            args = [*decode, "-T", "fields", "-E", "escape=y", "-E", "quote=n", *fields]
            with output_stream(args, heartbeat if progress or stopping is not None else None) as output:
                self.rows = self.index.build(FIELDS, index_values(output, count))
            heartbeat()
            self.by_number = FrameLookup(self.rows)
            self.window = self.time_window(self.rows)
        except BaseException:
            self.index.close()
            raise
        self.lock = RLock()
        self.last_filter, self.last_rows = "", self.rows

    @staticmethod
    def time_window(rows):
        if isinstance(rows, FrameView):
            if not hasattr(rows, "_window"):
                with rows.connection() as db:
                    low, high = db.execute('SELECT MIN(CAST("frame.time_epoch" AS REAL)), '
                                           'MAX(CAST("frame.time_epoch" AS REAL)) FROM scoped').fetchone()
                rows._window = [utc(low), utc(high)] if low is not None else []
            return rows._window
        low = high = None
        for row in rows:
            if row.get("frame.time_epoch"):
                t = float(row["frame.time_epoch"])
                low = min(t, low) if low is not None else t
                high = max(t, high) if high is not None else t
        return [utc(low), utc(high)] if low is not None else []

    def manifest(self):
        return dict(id=self.id, name=self.name, sha256=self.digest, size=self.size,
                    total=len(self.rows), window=self.window, source=self.source, acquired=self.acquired,
                    dissection_passes=self.dissection_passes)

    def select(self, expression):
        with self.lock:
            self.check_open()
            if not expression:
                return self.rows
            if len(expression) > 2048 or "\0" in expression:
                raise ValueError("Use a display filter of up to 2,048 characters.")
            if expression != self.last_filter:
                # All arbitrary filters use two passes so forward references resolve.
                exact = re.fullmatch(r"frame\.number\s*==\s*([1-9][0-9]{0,8}|0)", expression.strip())
                if exact:
                    n = int(exact[1])
                    rows = self.index.select([n] if 1 <= n <= self.index.count else [])
                else:
                    args = [*self.args, "-2", "-Y", expression, "-T", "fields", "-e", "frame.number"]
                    def numbers():
                        with output_stream(args, self.check_open if self.stopping is not None else None) as output:
                            for number in output:
                                yield int(number)
                    with closing(numbers()) as matches:
                        rows = self.index.select(matches)
                self.last_filter, self.last_rows = expression, rows
            return self.last_rows

    def close(self):
        """Release the derivative index. The workspace owns the capture file."""
        self.index.close()

    def check_open(self):
        if self.stopping is not None and self.stopping.is_set():
            raise ValueError("The workspace is closing.")

    def frame_args(self, number):
        if self.dissection_passes == 1:
            return [*self.args, "-c", number, "-Y", "frame.number == " + number]
        return [*self.args, "-2", "-Y", "frame.number == " + number]

    def detail(self, number):
        number = str(number)
        if not number.isascii() or not number.isdecimal() or number not in self.by_number:
            raise ValueError("Frame is outside this capture.")
        self.check_open()
        return run([*self.frame_args(number), "-V"], self.check_open if self.stopping is not None else None)

    def inspect_frame(self, number):
        number = str(number)
        if not number.isascii() or not number.isdecimal() or number not in self.by_number:
            raise ValueError("Frame is outside this capture.")
        row = self.by_number[number]
        args = self.frame_args(number)
        self.check_open()
        heartbeat = self.check_open if self.stopping is not None else None
        verbose = run([*args, "-V", "--hexdump", "frames", "--hexdump", "delimit"], heartbeat)
        marker = re.search(r"(?m)^0000  [0-9a-fA-F]{2}(?: |$)", verbose)
        tree = verbose[:marker.start()] if marker else verbose
        dump = verbose[marker.start():].strip() if marker else ""
        encap = re.search(r"(?m)^\s*Encapsulation type: ([^\r\n]+)", tree)
        data_format = encap.group(1) if encap else "Encapsulation unspecified"
        columns = [arg for k in CONTENT_FIELDS for arg in ("-e", k)]
        self.check_open()
        line = run([*args, "-T", "fields", "-E", "escape=y", "-E", "occurrence=f", *columns], heartbeat)
        fields = {k: v for k, v in zip(CONTENT_FIELDS, line.rstrip("\r\n").split("\t")) if v}
        if "http.content_type" in fields:
            data_format += " · HTTP Content-Type " + fields["http.content_type"]
        chosen = next((key for key in PAYLOAD_FIELDS if key in fields), None)
        payload = bytes.fromhex(fields[chosen].replace(":", "")) if chosen else b""
        return dict(detail=tree.rstrip(), hex=dump, layers=protocol_layers(row), src_port=port(row, "src"),
                    dst_port=port(row, "dst"), format=data_format, visibility=payload_visibility(row, fields),
                    captured=int(row["frame.cap_len"]), wire=int(row["frame.len"]), payload_field=chosen,
                    payload=hex_ascii(payload), payload_size=len(payload))


def metrics(rows):
    from large_metrics import metrics as compute_metrics
    return compute_metrics(rows)


def packet_row(row):
    return dict(frame=row["frame.number"], time=utc(row["frame.time_epoch"]),
                src=address(row, "src"), dst=address(row, "dst"), protocol=row.get("_ws.col.Protocol", "Unknown"),
                src_port=port(row, "src"), dst_port=port(row, "dst"), layers=protocol_layers(row),
                size=row["frame.len"], info=row.get("_ws.col.Info", ""), stream=row.get("tcp.stream"))
