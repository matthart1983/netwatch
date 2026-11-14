#!/usr/bin/env python3
"""An independent witness for the Diagnose false-alert soak.

Every INTERVAL seconds it pings the default gateway and two public addresses,
times one lookup through the system resolver, and reads the link state, and
appends one JSON line to <dir>/witness.jsonl. It shares no code with netwatch
on purpose: `diagnose_quiet_soak report` uses this log as a second opinion on
whether the network was in trouble when a rule opened.

    python3 tests/soak/witness.py <soak-dir> [--interval 10]
            [--anchor ADDR ...] [--name HOST]

Linux and macOS. Standard library only. Needs `ping`, and `ip` on Linux or
`route` on macOS. Stop it with Ctrl-C; start it again and it appends.
"""
import argparse
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time

LINUX = platform.system() == 'Linux'


def run(cmd, timeout):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None


def default_route():
    """(gateway address, interface) or (None, None)."""
    if LINUX:
        out = run(['ip', '-4', 'route', 'show', 'default'], 3)
        m = out and re.search(r'default via (\S+) dev (\S+)', out.stdout)
        return (m.group(1), m.group(2)) if m else (None, None)
    out = run(['route', '-n', 'get', 'default'], 3)
    if not out:
        return None, None
    gw = re.search(r'gateway: (\S+)', out.stdout)
    dev = re.search(r'interface: (\S+)', out.stdout)
    return (gw and gw.group(1), dev and dev.group(1))


def ping(addr):
    """Round trip in ms, or None when nothing came back within a second."""
    wait = ['-W', '1'] if LINUX else ['-W', '1000']
    out = run(['ping', '-n', '-c', '1', *wait, addr], 3)
    if not out or out.returncode != 0:
        return None
    m = re.search(r'time[=<]([\d.]+) ?ms', out.stdout)
    return float(m.group(1)) if m else None


def link_up(dev):
    if not dev:
        return None
    if LINUX:
        try:
            with open(f'/sys/class/net/{dev}/operstate') as f:
                state = f.read().strip()
        except OSError:
            return None
        return state in ('up', 'unknown')
    out = run(['ifconfig', dev], 3)
    m = out and re.search(r'status: (\w+)', out.stdout)
    return (m.group(1) == 'active') if m else None


def lookup(name):
    """(ok, ms). The system resolver may answer from a cache, and then this
    measures the cache; it still catches a resolver that has stopped."""
    start = time.monotonic()
    try:
        socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)
        ok = True
    except OSError:
        ok = False
    return ok, round((time.monotonic() - start) * 1000, 1)


def sample(anchors, name):
    gw, dev = default_route()
    gw_ms = ping(gw) if gw else None
    answered = [ping(a) for a in anchors]
    dns_ok, dns_ms = lookup(name)
    return {
        'at': round(time.time(), 3),
        'gateway_ok': (gw_ms is not None) if gw else None,
        'gateway_ms': gw_ms,
        'anchors': len(anchors),
        'anchors_ok': sum(1 for ms in answered if ms is not None),
        'dns_ok': dns_ok,
        'dns_ms': dns_ms,
        'link_up': link_up(dev),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('dir')
    ap.add_argument('--interval', type=float, default=10.0)
    ap.add_argument('--anchor', action='append',
                    help='public address to ping; default 1.1.1.1 and 9.9.9.9')
    ap.add_argument('--name', default='example.com')
    ap.add_argument('--once', action='store_true', help='print one sample and exit')
    args = ap.parse_args()
    anchors = args.anchor or ['1.1.1.1', '9.9.9.9']
    if args.once:
        print(json.dumps(sample(anchors, args.name)))
        return
    os.makedirs(args.dir, exist_ok=True)
    path = os.path.join(args.dir, 'witness.jsonl')
    print(f'appending to {path} every {args.interval:g}s; stop with Ctrl-C', file=sys.stderr)
    with open(path, 'a', buffering=1) as log:
        try:
            while True:
                began = time.monotonic()
                log.write(json.dumps(sample(anchors, args.name)) + '\n')
                time.sleep(max(0.0, args.interval - (time.monotonic() - began)))
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
