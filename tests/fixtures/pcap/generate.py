#!/usr/bin/env python3
"""Writes the pcap fixtures that tests/pcap_golden.rs replays.

Standard library only, and deterministic: the same script always writes the
same bytes, so a diff in a .pcap file means this script changed. Addresses
are the documentation ranges (RFC 5737, RFC 3849) and names are example.com,
so nothing here comes from a real network.

    python3 tests/fixtures/pcap/generate.py

then regenerate the golden files with

    NETWATCH_BLESS=1 cargo test --test pcap_golden
"""
import pathlib
import re
import struct

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
BROADCAST = b"\xff" * 6
C4, S4, R4 = "192.0.2.10", "198.51.100.20", "192.0.2.1"
C6, S6 = "2001:db8::10", "2001:db8::20"


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ip4(addr):
    return bytes(int(p) for p in addr.split("."))


def ip6(addr):
    head, _, tail = addr.partition("::")
    h = [int(x, 16) for x in head.split(":") if x]
    t = [int(x, 16) for x in tail.split(":") if x]
    return struct.pack("!8H", *(h + [0] * (8 - len(h) - len(t)) + t))


def ether(dst, src, ethertype, payload):
    return dst + src + struct.pack("!H", ethertype) + payload


def ipv4(src, dst, proto, payload, ident=1):
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0,
        ip4(src), ip4(dst),
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def ipv6(src, dst, proto, payload):
    return struct.pack("!IHBB", 0x60000000, len(payload), proto, 64) + ip6(src) + ip6(dst) + payload


def l4_checksum(src, dst, proto, segment, v6):
    if v6:
        pseudo = ip6(src) + ip6(dst) + struct.pack("!IxxxB", len(segment), proto)
    else:
        pseudo = ip4(src) + ip4(dst) + struct.pack("!xBH", proto, len(segment))
    return checksum(pseudo + segment)


def udp(src, dst, sport, dport, payload, v6=False):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    seg = seg[:6] + struct.pack("!H", l4_checksum(src, dst, 17, seg, v6)) + seg[8:]
    return ipv6(src, dst, 17, seg) if v6 else ipv4(src, dst, 17, seg)


SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b"", v6=False):
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload
    seg = seg[:16] + struct.pack("!H", l4_checksum(src, dst, 6, seg, v6)) + seg[18:]
    return ipv6(src, dst, 6, seg) if v6 else ipv4(src, dst, 6, seg)


class Conversation:
    """One TCP connection, client and server keeping their own sequence numbers."""

    def __init__(self, sport, dport, v6=False):
        self.sport, self.dport, self.v6 = sport, dport, v6
        self.c, self.s = (C6, S6) if v6 else (C4, S4)
        self.cseq, self.sseq = 1000, 5000

    def _frame(self, from_client, flags, payload):
        et = 0x86DD if self.v6 else 0x0800
        if from_client:
            ack = 0 if flags == SYN else self.sseq
            pkt = tcp(self.c, self.s, self.sport, self.dport, self.cseq, ack, flags, payload, self.v6)
            self.cseq += len(payload) + (1 if flags & (SYN | FIN) else 0)
            return ether(SERVER_MAC, CLIENT_MAC, et, pkt)
        pkt = tcp(self.s, self.c, self.dport, self.sport, self.sseq, self.cseq, flags, payload, self.v6)
        self.sseq += len(payload) + (1 if flags & (SYN | FIN) else 0)
        return ether(CLIENT_MAC, SERVER_MAC, et, pkt)

    def handshake(self):
        syn = self._frame(True, SYN, b"")
        synack = self._frame(False, SYN | ACK, b"")
        ack = self._frame(True, ACK, b"")
        return [syn, synack, ack]

    def client(self, payload):
        return self._frame(True, PSH | ACK, payload)

    def server(self, payload):
        return self._frame(False, PSH | ACK, payload)


def dns_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dns_query(txid, name, qtype):
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_answer(txid, name, qtype, rdata):
    question = dns_name(name) + struct.pack("!HH", qtype, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 300, len(rdata)) + rdata
    return struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer


def ext(kind, body):
    return struct.pack("!HH", kind, len(body)) + body


def client_hello(sni, alpn):
    names = b"".join(bytes([len(a)]) + a for a in alpn)
    host = sni.encode()
    extensions = b"".join([
        ext(0x0000, struct.pack("!HBH", len(host) + 3, 0, len(host)) + host),
        ext(0x000A, struct.pack("!H3H", 6, 0x001D, 0x0017, 0x0018)),
        ext(0x000B, b"\x01\x00"),
        ext(0x000D, struct.pack("!H4H", 8, 0x0403, 0x0804, 0x0401, 0x0503)),
        ext(0x0010, struct.pack("!H", len(names)) + names),
        ext(0x002B, b"\x04\x03\x04\x03\x03"),
        ext(0x0033, struct.pack("!HHH", 36, 0x001D, 32) + bytes(range(32))),
    ])
    suites = struct.pack("!5H", 0x1301, 0x1302, 0x1303, 0xC02F, 0xC030)
    body = (
        b"\x03\x03" + bytes(range(32, 64)) + b"\x20" + bytes(range(64, 96))
        + struct.pack("!H", len(suites)) + suites + b"\x01\x00"
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def rfc9001_client_initial():
    """The sample client Initial from RFC 9001 Appendix A.2, taken from the
    unit test that already checks netwatch decrypts it."""
    src = (ROOT / "src/collectors/quic.rs").read_text()
    fn = src[src.index("fn rfc9001_appendix_a2_end_to_end_extracts_sni"):]
    literal = fn[fn.index('"') + 1:]
    literal = literal[:literal.index('"')]
    return bytes.fromhex(re.sub(r"[\s\\]", "", literal))


def fixtures():
    out = {}

    # DNS over UDP, v4 and v6.
    out["dns"] = [
        ether(SERVER_MAC, CLIENT_MAC, 0x0800, udp(C4, R4, 53001, 53, dns_query(0x1234, "example.com", 1))),
        ether(CLIENT_MAC, SERVER_MAC, 0x0800, udp(R4, C4, 53, 53001, dns_answer(0x1234, "example.com", 1, ip4("93.184.215.14")))),
        ether(SERVER_MAC, CLIENT_MAC, 0x86DD, udp(C6, S6, 53002, 53, dns_query(0x5678, "example.com", 28), v6=True)),
        ether(CLIENT_MAC, SERVER_MAC, 0x86DD, udp(S6, C6, 53, 53002, dns_answer(0x5678, "example.com", 28, ip6("2001:db8::1")), v6=True)),
    ]

    # TLS 1.3 ClientHello with SNI and ALPN after a full handshake.
    c = Conversation(50443, 443)
    out["tls"] = c.handshake() + [c.client(client_hello("www.example.com", [b"h2", b"http/1.1"]))]

    # Plain HTTP/1.1 request and response.
    c = Conversation(50080, 80)
    out["http"] = c.handshake() + [
        c.client(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: netwatch-fixture\r\n\r\n"),
        c.server(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello"),
    ]

    # SSH version exchange, over IPv6.
    c = Conversation(50022, 22, v6=True)
    out["ssh"] = c.handshake() + [
        c.server(b"SSH-2.0-OpenSSH_9.6\r\n"),
        c.client(b"SSH-2.0-OpenSSH_9.6\r\n"),
    ]

    # QUIC v1 Initial carrying a ClientHello for example.com.
    out["quic"] = [
        ether(SERVER_MAC, CLIENT_MAC, 0x0800, udp(C4, S4, 50443, 443, rfc9001_client_initial())),
    ]

    # Link and network odds and ends, and frames a parser must survive.
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, CLIENT_MAC, ip4(C4), b"\0" * 6, ip4(R4))
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x0042, 1) + b"netwatch"
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    ntp = bytes([0x23]) + bytes(47)
    dhcp = (
        struct.pack("!BBBBIHH", 1, 1, 6, 0, 0x3903F326, 0, 0x8000) + b"\0" * 16 + CLIENT_MAC + b"\0" * 202
        + b"\x63\x82\x53\x63" + b"\x35\x01\x01" + b"\xff"
    )
    tls_frame = out["tls"][3]
    out["misc"] = [
        ether(BROADCAST, CLIENT_MAC, 0x0806, arp),
        ether(SERVER_MAC, CLIENT_MAC, 0x0800, ipv4(C4, R4, 1, icmp)),
        ether(SERVER_MAC, CLIENT_MAC, 0x0800, udp(C4, S4, 50123, 123, ntp)),
        ether(BROADCAST, CLIENT_MAC, 0x0800, udp("0.0.0.0", "255.255.255.255", 68, 67, dhcp)),
        # A ClientHello cut off mid-extension, as a short snaplen leaves it.
        tls_frame[:120],
        # An IPv4 header that claims more bytes than the frame holds.
        ether(SERVER_MAC, CLIENT_MAC, 0x0800, ipv4(C4, S4, 6, b"")[:2] + b"\xff\xff" + ipv4(C4, S4, 6, b"")[4:]),
        # An unknown ethertype.
        ether(BROADCAST, CLIENT_MAC, 0x88B5, b"local experimental"),
    ]
    return out


def write_pcap(path, frames):
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, frame in enumerate(frames):
        data += struct.pack("<IIII", 1_700_000_000, i * 1000, len(frame), len(frame)) + frame
    path.write_bytes(data)


if __name__ == "__main__":
    for name, frames in fixtures().items():
        write_pcap(HERE / f"{name}.pcap", frames)
        print(f"{name}.pcap: {len(frames)} frames")
