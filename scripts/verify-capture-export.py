#!/usr/bin/env python3
"""Check netwatch's PCAP/PCAPNG export fixtures with Wireshark's own reader.

CI does not install Wireshark, so this is run by hand after a change to the
writer in src/collectors/packets/export.rs:

    NETWATCH_EXPORT_FIXTURE_DIR=/tmp/nw-export \\
        cargo test --lib write_interop_fixture -- --ignored
    python3 scripts/verify-capture-export.py /tmp/nw-export

It needs tshark and capinfos on PATH, or --tshark/--capinfos.
"""
import argparse
import json
import subprocess
import unicodedata
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
parser.add_argument("fixtures", type=Path)
parser.add_argument("--tshark", default="tshark")
parser.add_argument("--capinfos", default="capinfos")
args = parser.parse_args()

FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "frame.interface_name",
    "frame.encap_type",
    "frame.comment",
]
FRAME = "000102030405060708090a0b08004500001c00000000401100007f000001c000020104d2003500080000"


def tshark_json(name, *options):
    command = [args.tshark, "-n", "-r", str(args.fixtures / name), *options]
    return json.loads(subprocess.check_output(command, text=True))


def frames(name):
    """Each frame's fields as Wireshark decodes them, and its raw bytes."""
    fields = [option for field in FIELDS for option in ("-e", field)]
    decoded = tshark_json(name, "-T", "json", *fields)
    raw = tshark_json(name, "-T", "jsonraw")
    out = []
    for packet, packet_raw in zip(decoded, raw, strict=True):
        layers = packet["_source"]["layers"]
        row = {f: layers.get(f, [None])[0] for f in FIELDS}
        row["bytes"] = packet_raw["_source"]["layers"]["frame_raw"][0]
        row["comment"] = json.loads(row["frame.comment"]) if row["frame.comment"] else None
        out.append(row)
    return out


def capinfos(name):
    """capinfos' long report as {label: value}."""
    output = subprocess.check_output([args.capinfos, "-M", str(args.fixtures / name)], text=True)
    return {
        label.strip(): value.strip()
        for label, value in (line.split(":", 1) for line in output.splitlines() if ":" in line)
    }


def safe(text):
    """No control, format (bidi, zero-width) or line-breaking characters."""
    return not any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in text)


for name in ("single.pcap", "single.pcapng"):
    rows = frames(name)
    assert len(rows) == 1, (name, rows)
    row = rows[0]
    assert row["frame.time_epoch"] == "1700006399.999123000", row
    assert (row["frame.len"], row["frame.cap_len"]) == ("64", "42"), row
    assert row["bytes"] == FRAME, row
    info = capinfos(name)
    assert info["File timestamp precision"].startswith("microseconds"), info
    if name.endswith("pcapng"):
        assert info["Capture application"].startswith("netwatch "), info
        assert row["frame.interface_name"] == "eth0", row
        comment = row["comment"]
        assert comment["schema"] == "netwatch.annotation.v1", comment
        assert comment["status"] == "bracketed_socket_observation", comment
        assert comment["pid"] == 42 and comment["process_name"] == "lookup", comment
        assert comment["start_token"] == "123" and comment["direction"] == "outbound", comment
        assert comment["app"] == "quic" and comment["sni"] == "example.com", comment
        assert comment["ech_outer"] is False, comment
    else:
        assert row["comment"] is None, row

rows = frames("mixed.pcapng")
assert len(rows) == 2, rows
assert [r["frame.interface_name"] for r in rows] == ["eth0", "tun0"], rows
# Wireshark's encapsulation numbers: 1 Ethernet, 7 raw IP.
assert [r["frame.encap_type"] for r in rows] == ["1", "7"], rows
assert rows[1]["frame.time_epoch"] == "1700006400.001123000", rows
assert (rows[1]["frame.len"], rows[1]["frame.cap_len"]) == ("28", "28"), rows
assert rows[1]["bytes"] == FRAME[28:], rows
assert rows[1]["comment"]["status"] == "unknown_owner", rows
assert "pid" not in rows[1]["comment"], rows

rows = frames("hostile.pcapng")
assert len(rows) == 1, rows
name = rows[0]["frame.interface_name"]
assert safe(name) and len(name) == 160, name
comment = rows[0]["comment"]
for key in ("process_name", "sni", "alpn"):
    assert safe(comment[key]) and len(comment[key]) == 160, (key, comment[key])

print("Wireshark read the PCAP and PCAPNG fixtures as written: bytes, UTC times,")
print("microsecond precision, lengths, interfaces and framing, and JSON comments.")
