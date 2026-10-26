#!/usr/bin/env python3
"""Floods an interface for the flood soak (tests/soak/flood_soak.py), from
the namespace on the far side of the veth netwatch captures on.

  flood.py SCENARIO --iface IFACE --seconds S [--pps N] [--cycle N] [--to ADDR] [--tcpreplay FILE]
  flood.py sink --bind ADDR

Frame scenarios write prebuilt Ethernet frames to an AF_PACKET socket, as
fast as it takes them or paced to --pps:

  udp-churn   60 B UDP, a new 5-tuple on every frame
  syn-churn   54 B TCP SYN, a new 5-tuple on every frame
  dns         DNS queries and their answers over 10,000 flows, a name each
  mtu-tcp     1514 B TCP over 1,000 flows, each one in sequence
  replay      tests/fixtures/pcap with every address changed on each pass,
              as tcpreplay --unique-ip does; with --tcpreplay FILE, tcpreplay
              itself sends FILE that way (apt install tcpreplay)
  mix         udp-churn, syn-churn, dns, mtu-tcp and replay, 256 frames of
              each in turn

--cycle N, 0 to 3, gives udp-churn, syn-churn and replay (in mix as well)
source addresses and address masks that no other cycle uses, so a soak's
second cycle is new flows to netwatch, not the first cycle's again. dns and
mtu-tcp send the same flows in every cycle.

Crafted frames go to a MAC nobody owns, so the receiving stack drops them
without answering: netwatch captures them and the kernel does no more. The
fixtures keep their own MACs, which are not the lab's either.

bulk is a real TCP connection to ADDR port 5001, written with sendall. The
sending kernel's segmentation offload then puts frames of up to 64 KB on the
veth, which no frame scenario can: AF_PACKET writes are limited to the MTU.
sink, run on the capture side, accepts and drains it.

Prints one JSON line when it stops: what it sent, and over how long. A send
that fails for any reason but a full queue (ENOBUFS) ends it with an error.
Standard library only.
"""
import argparse, errno, json, pathlib, re, signal, socket, struct, subprocess, threading, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tests/fixtures/pcap'
BULK_PORT = 5001
# Locally administered and owned by nobody in the lab.
DST_MAC = bytes.fromhex('020000000002')
SRC_MAC = bytes.fromhex('020000000001')
# TEST-NET-2, which nothing in the lab routes: crafted frames go to it.
SERVER = bytes([198, 51, 100, 7])
# Frames built at a time for the churn scenarios: one per source port.
CHURN_PORTS = 4096
DNS_FLOWS = 10_000
MTU_FLOWS = 1_000
MTU_PAYLOAD = 1460
# Frames sent between looks at the clock, and between pacing sleeps.
BATCH = 64
# --cycle N is the top two of the 24 bits churn's source addresses and
# replay's address masks are made of, so no two cycles share one.
CYCLE_SHIFT = 22


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4_head(proto, src, dst, l4_len):
    """Ethernet and IPv4 headers, with the IPv4 checksum filled in."""
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + l4_len, 0, 0x4000, 64, proto, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return DST_MAC + SRC_MAC + b'\x08\x00' + ip


def churn(syn, cycle):
    """Batches of frames whose source no earlier batch used: CHURN_PORTS
    source ports on each of the cycle's 2^22 source addresses, so a run
    never repeats a 5-tuple and no other cycle sends one of its 5-tuples.
    Only the address changes per batch, so only the IPv4 header is built
    once per batch; the ports are spliced in."""
    ports = [struct.pack('!H', 1024 + i) for i in range(CHURN_PORTS)]
    generation = 0
    while True:
        generation = (generation + 1) % (1 << CYCLE_SHIFT)
        src = bytes([10]) + (cycle << CYCLE_SHIFT | generation).to_bytes(3, 'big')
        if syn:
            head = ipv4_head(6, src, SERVER, 20)
            tail = struct.pack('!HIIBBHHH', 443, generation, 0, 5 << 4, 0x02, 64240, 0, 0)
        else:
            head = ipv4_head(17, src, SERVER, 26)
            tail = struct.pack('!HHH', 9999, 26, 0) + b'\0' * 18
        yield [head + port + tail for port in ports]


def dns_name(i):
    return b''.join(bytes([len(p)]) + p for p in (b'h%d' % i, b'flood', b'example')) + b'\0'


def dns():
    """A query and its answer for each of DNS_FLOWS clients, each asking for
    a name of its own, so the detectors see that many flows and names."""
    resolver = bytes([198, 51, 100, 53])
    frames = []
    for i in range(DNS_FLOWS):
        client = bytes([10, 53, i >> 8, i & 255])
        sport = 33000 + i % 1000
        question = dns_name(i) + struct.pack('!HH', 1, 1)
        query = struct.pack('!HHHHHH', i & 0xFFFF, 0x0100, 1, 0, 0, 0) + question
        answer = (struct.pack('!HHHHHH', i & 0xFFFF, 0x8180, 1, 1, 0, 0) + question
                  + struct.pack('!HHHIH', 0xC00C, 1, 1, 60, 4) + bytes([192, 0, 2, 1 + i % 250]))
        for src, dst, sp, dp, msg in ((client, resolver, sport, 53, query),
                                      (resolver, client, 53, sport, answer)):
            udp = struct.pack('!HHHH', sp, dp, 8 + len(msg), 0) + msg
            frames.append(ipv4_head(17, src, dst, len(udp)) + udp)
    while True:
        yield frames


def mtu_tcp():
    """One full-size segment on each of MTU_FLOWS flows per batch, every
    flow's sequence number moving on by a segment each time, so each stream
    reassembles in order until it reaches its byte cap."""
    heads = []
    for f in range(MTU_FLOWS):
        src = bytes([10, 14, f >> 8, f & 255])
        heads.append((ipv4_head(6, src, SERVER, 20 + MTU_PAYLOAD), struct.pack('!HH', 40000, 443)))
    rest = struct.pack('!IBBHHH', 1, 5 << 4, 0x18, 64240, 0, 0) + b'A' * MTU_PAYLOAD
    seq = 0
    while True:
        seq = (seq + MTU_PAYLOAD) & 0xFFFFFFFF
        number = struct.pack('!I', seq)
        yield [head + ports + number + rest for head, ports in heads]


def pcap_frames(path):
    """The frames of a little-endian classic pcap, as the fixtures are written."""
    data = path.read_bytes()
    assert data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'), f'{path}: not a little-endian pcap'
    frames, at = [], 24
    while at < len(data):
        caplen = struct.unpack_from('<I', data, at + 8)[0]
        frames.append(data[at + 16:at + 16 + caplen])
        at += 16 + caplen
    return frames


def readdress(frame, mask):
    """The low three bytes of both addresses XORed with mask, and the IPv4
    checksum redone. Both ends change alike, so a conversation stays one."""
    ethertype = frame[12:14]
    if ethertype == b'\x08\x00':
        ends, ip4 = (30, 34), True
    elif ethertype == b'\x86\xdd':
        ends, ip4 = (38, 54), False
    else:
        return bytes(frame)
    out = bytearray(frame)
    m = mask.to_bytes(3, 'big')
    for end in ends:
        for k in range(3):
            out[end - 3 + k] ^= m[k]
    if ip4:
        ihl = (out[14] & 0x0F) * 4
        out[24:26] = b'\0\0'
        out[24:26] = struct.pack('!H', checksum(bytes(out[14:14 + ihl])))
    return bytes(out)


def replay(cycle):
    """The fixtures, every pass with a mask no earlier pass used, for 2^22
    passes. The cycle is the mask's top two bits. Two cycles could send the
    same address pair only if two fixture addresses with the same first
    byte differed in those bits, and none do."""
    fixture = [f for p in sorted(FIXTURES.glob('*.pcap')) for f in pcap_frames(p)]
    assert fixture, f'no frames in {FIXTURES}'
    passes = 0
    while True:
        passes = passes % ((1 << CYCLE_SHIFT) - 1) + 1
        yield [readdress(f, cycle << CYCLE_SHIFT | passes) for f in fixture]


def mix(cycle):
    """256 frames of each frame scenario in turn."""
    sources = [churn(False, cycle), churn(True, cycle), dns(), mtu_tcp(), replay(cycle)]
    pending = [[] for _ in sources]
    while True:
        out = []
        for i, source in enumerate(sources):
            while len(pending[i]) < 256:
                pending[i].extend(next(source))
            out.extend(pending[i][:256])
            del pending[i][:256]
        yield out


# Each takes the cycle.
SCENARIOS = {
    'udp-churn': lambda cycle: churn(False, cycle),
    'syn-churn': lambda cycle: churn(True, cycle),
    'dns': lambda cycle: dns(),
    'mtu-tcp': lambda cycle: mtu_tcp(),
    'replay': replay,
    'mix': mix,
}


class Stop:
    """Set by SIGTERM or SIGINT, so a stopped generator still reports."""

    def __init__(self):
        self.set = False
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self.stop)

    def stop(self, *_):
        self.set = True


def send_frames(iface, seconds, pps, batches, stop):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((iface, 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
    send = sock.send
    sent = nbytes = errors = 0
    started = time.monotonic()
    end = started + seconds
    frames, at = next(batches), 0
    while not stop.set:
        now = time.monotonic()
        if now >= end:
            break
        if pps:
            ahead = sent / pps - (now - started)
            if ahead > 0:
                time.sleep(min(ahead, end - now))
                continue
        for _ in range(BATCH):
            if at == len(frames):
                frames, at = next(batches), 0
            frame = frames[at]
            at += 1
            try:
                send(frame)
                sent += 1
                nbytes += len(frame)
            except OSError as e:
                # ENOBUFS: the veth's queue is full. The frame is not sent,
                # and is not counted. Anything else, such as a link that is
                # down, would fail every send, so it ends the run.
                if e.errno != errno.ENOBUFS:
                    raise
                errors += 1
    return sent, nbytes, errors, time.monotonic() - started


def send_bulk(to, seconds, stop):
    sock = socket.create_connection((to, BULK_PORT), timeout=10)
    block = b'A' * (1 << 20)
    nbytes = 0
    started = time.monotonic()
    while not stop.set and time.monotonic() - started < seconds:
        sock.sendall(block)
        nbytes += len(block)
    sock.close()
    return nbytes, time.monotonic() - started


def tcpreplay(iface, seconds, pps, path, stop):
    """tcpreplay looping FILE, new addresses each loop, for `seconds`."""
    rate = [f'--pps={pps}'] if pps else ['--topspeed']
    p = subprocess.Popen(['tcpreplay', f'--intf1={iface}', '--unique-ip', '--loop=0', *rate, str(path)],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    started = time.monotonic()
    while p.poll() is None and not stop.set and time.monotonic() - started < seconds:
        time.sleep(0.2)
    elapsed = time.monotonic() - started
    if p.poll() is None:
        # tcpreplay prints its totals when interrupted.
        p.send_signal(signal.SIGINT)
    out = p.communicate(timeout=30)[0]
    sent = re.search(r'Actual: (\d+) packets \((\d+) bytes\)', out)
    if not sent:
        raise SystemExit(f'tcpreplay exited {p.returncode}: {out[-2000:]}')
    return int(sent.group(1)), int(sent.group(2)), 0, elapsed


def sink(bind):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind, BULK_PORT))
    srv.listen(8)

    def drain(conn):
        with conn:
            while conn.recv(1 << 20):
                pass
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=drain, args=(conn,), daemon=True).start()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('scenario', choices=[*SCENARIOS, 'bulk', 'sink'])
    ap.add_argument('--iface', help='the interface frame scenarios write to')
    ap.add_argument('--seconds', type=float, default=10)
    ap.add_argument('--pps', type=int, default=0, help='frames a second; 0 sends as fast as it can')
    ap.add_argument('--cycle', type=int, default=0, choices=range(1 << (24 - CYCLE_SHIFT)),
                    help='churn and replay send flows no other cycle sends (default %(default)s)')
    ap.add_argument('--to', help='bulk: the address sink listens on')
    ap.add_argument('--bind', help='sink: the address to listen on')
    ap.add_argument('--tcpreplay', metavar='FILE', help='replay: send FILE with tcpreplay')
    args = ap.parse_args()
    if args.scenario == 'sink':
        sink(args.bind)
        return
    stop = Stop()
    report = {'scenario': args.scenario, 'pps_asked': args.pps}
    if args.scenario == 'bulk':
        nbytes, elapsed = send_bulk(args.to, args.seconds, stop)
        report.update(bytes=nbytes, seconds=round(elapsed, 3))
    else:
        if args.tcpreplay:
            assert args.scenario == 'replay', '--tcpreplay replaces the replay scenario only'
            sent, nbytes, errors, elapsed = tcpreplay(args.iface, args.seconds, args.pps, args.tcpreplay, stop)
        else:
            sent, nbytes, errors, elapsed = send_frames(args.iface, args.seconds, args.pps,
                                                        SCENARIOS[args.scenario](args.cycle), stop)
            report['cycle'] = args.cycle
        report.update(sent=sent, bytes=nbytes, send_errors=errors, seconds=round(elapsed, 3),
                      pps=round(sent / elapsed) if elapsed else 0)
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    main()
