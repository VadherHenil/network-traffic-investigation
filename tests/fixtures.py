"""Build a reproducible packet capture in memory for decoder regression tests."""

import ipaddress
import struct


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return ~total & 65535


def training_capture():
    client, resolver, web = "192.0.2.24", "192.0.2.53", "198.51.100.18"
    frames = []

    def packet(ms, src, dst, protocol, segment, checksum_offset):
        a, b = (ipaddress.ip_address(ip).packed for ip in (src, dst))
        pseudo = a + b + struct.pack("!BBH", 0, protocol, len(segment))
        check = checksum(pseudo + segment) or 65535
        segment = segment[:checksum_offset] + struct.pack("!H", check) + segment[checksum_offset + 2:]
        header = struct.pack("!BBHHHBBH4s4s", 69, 0, 20 + len(segment), len(frames) + 1,
                             0x4000, 64, protocol, 0, a, b)
        header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
        ether = b"\x02\0\0\0\0" + b[-1:] + b"\x02\0\0\0\0" + a[-1:] + b"\x08\0"
        raw = ether + header + segment
        frames.append(struct.pack("<IIII", 1768222800 + ms // 1000, ms % 1000 * 1000,
                                  len(raw), len(raw)) + raw)

    name = b"portal.example.test"
    qname = b"".join(bytes([len(label)]) + label for label in name.split(b".")) + b"\0"
    question = qname + struct.pack("!HH", 1, 1)
    for reply in (False, True):
        payload = struct.pack("!6H", 9013, 0x8180 if reply else 0x0100, 1, int(reply), 0, 0) + question
        if reply:
            payload += struct.pack("!HHHIH", 0xc00c, 1, 1, 120, 4) + ipaddress.ip_address(web).packed
        ports = (53, 51000) if reply else (51000, 53)
        segment = struct.pack("!4H", *ports, len(payload) + 8, 0) + payload
        packet(64 if reply else 0, resolver if reply else client, client if reply else resolver, 17, segment, 6)

    def tcp(ms, outgoing, port, seq, ack, flags, body=b""):
        local = 51001 if port == 80 else 51002
        ports = (local, port) if outgoing else (port, local)
        segment = struct.pack("!HHIIHHHH", *ports, seq, ack, (5 << 12) | flags, 32768, 0, 0) + body
        packet(ms, client if outgoing else web, web if outgoing else client, 6, segment, 16)

    request = b"GET /status HTTP/1.1\r\nHost: " + name + b"\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nOK"
    sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    extension = struct.pack("!HH", 0, len(sni)) + sni
    hello = b"\x03\x03" + bytes(range(32)) + b"\x00\x00\x02\xc0\x2f\x01\x00" + struct.pack("!H", len(extension)) + extension
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    tls_record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    for start, port, body in [(250, 80, request), (2400, 443, tls_record)]:
        tcp(start, True, port, 100, 0, 2)
        tcp(start + 40, False, port, 500, 101, 18)
        tcp(start + 55, True, port, 101, 501, 16)
        tcp(start + 115, True, port, 101, 501, 24, body)
        if port == 80:
            tcp(start + 330, False, port, 501, 101 + len(body), 24, response)
            tcp(start + 350, True, port, 101 + len(body), 501 + len(response), 16)
    return struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + b"".join(frames)
