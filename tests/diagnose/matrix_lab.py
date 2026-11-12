#!/usr/bin/env python3
"""The Diagnose lab matrix: the same fault at many sizes, many times, with the
verdict written down before the run.

  python3 tests/diagnose/matrix_lab.py [--rule RULE ...] [--reps N] [--jobs N]
                                       [--out FILE] [--artifacts DIR] [--gate]
  python3 tests/diagnose/matrix_lab.py --list
  python3 tests/diagnose/matrix_lab.py --summarise matrix-lab.json [--gate]

health_lab.py asks whether each rule opens and closes on one staged fault. This
asks how reliably: for each baseline rule it moves the measured value to 0,
0.5, 0.85, 1.15, 2 and 5 times the distance from the baseline mean to the
rule's open line, over base latencies of 1, 20 and 80 ms, `--reps` times each.

A run is labelled by what was measured, not by what was asked for. During the
fault a plain reference probe (ping, or one DNS query, from this script and not
from netwatch) measures the value the rule judges. Its distance above the
seeded baseline mean, as a share of the open line's distance, is the label:

  ratio >= 1.1   positive: the rule must open, once, and close after the clear
  ratio <= 0.9   negative: the rule must not open
  in between     ambiguous: reported, never counted

netem's delay is only accurate to about half a millisecond and a runner adds
its own jitter, so the two steps beside the line aim at 0.85 and 1.15, inside
the bands, and a run that still lands between 0.9 and 1.1 is ambiguous, not a
false open or a miss.

The counts are what a rule's maturity rests on (docs/DIAGNOSE.md, "Rule
maturity"): zero misses in 60 positives puts detection above 95% at 95%
confidence, and zero opens in 60 negatives bounds false opens the same way.
`--gate` exits 1 on any miss or false open. Without it the run only reports.

It runs each cell in its own unshare --user --map-root-user --net --mount, as
health_lab.py does, `--jobs` at a time, and needs what that needs, plus ping.
The open lines below restate rules.rs and detectors.rs for the lab's seeded
baselines. If a default threshold moves and this file does not, 0.9 runs start
opening or 1.1 runs stop, and the table here is the first place to look.

Not built yet: shapes other than step-and-hold (ramp, intermittent, single
spike, step during warm-up, fingerprint change), dns.failing, and every rule
that has no baseline.
"""
import argparse, json, math, os, pathlib, signal, socket, statistics, struct, subprocess, sys, threading, time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import health_lab as hl

FACTORS = [0.0, 0.5, 0.85, 1.15, 2.0, 5.0]
BASES_MS = [1, 20, 80]
POSITIVE, NEGATIVE = 1.1, 0.9
# Reference probes per measurement, and the pause between them.
REFERENCE_PROBES = 15
REFERENCE_GAP_SECS = 0.2
# netem below this is inside its own error; a smaller step is not staged.
MIN_STEP_MS = 2.0
# Thresholds::default(): sigma_k, the sigma floor, and each rule's own floors.
SIGMA_K = 3.0
SIGMA_FLOOR_MS, SIGMA_FLOOR_PCT = 0.5, 0.05
GATEWAY_DELTA_FLOOR_MS = 10.0
DNS_DELTA_FLOOR_MS, DNS_DELTA_MULTIPLE, DNS_CEILING_MS = 5.0, 2.0, 100.0


def seed_for(base_ms):
    """The seeded baselines for a base latency. At 1 ms they are the health
    lab's own; above it the mean is the base and sigma a tenth of it, which is
    what a link of that length shows."""
    if base_ms == 1:
        return dict(hl.SEED)
    sigma = max(2.0, base_ms * 0.05)
    return {metric: {'mean': float(base_ms), 'sigma': sigma} for metric in hl.SEED}


def sigma_floored(mean, sigma):
    return max(sigma, SIGMA_FLOOR_MS, mean * SIGMA_FLOOR_PCT)


def gateway_line(mean, sigma):
    return max(mean + SIGMA_K * sigma_floored(mean, sigma), mean + GATEWAY_DELTA_FLOOR_MS)


def dns_line(mean, sigma):
    by_baseline = max(mean + SIGMA_K * sigma_floored(mean, sigma), mean + DNS_DELTA_FLOOR_MS,
                      mean * DNS_DELTA_MULTIPLE)
    return min(by_baseline, DNS_CEILING_MS)


def path_line(mean, sigma):
    return mean + SIGMA_K * sigma_floored(mean, sigma)


def ping_ms(addr):
    out = hl.cmd('ping', '-n', '-c', '1', '-W', '2', addr, check=False).stdout
    m = hl.re.search(r'time[=<]([\d.]+) ?ms', out)
    return float(m.group(1)) if m else None


def dns_ms(addr):
    """One `. NS` query over UDP, the question netwatch's own RTT probe asks,
    sent by this script."""
    query = struct.pack('>6H', os.getpid() & 0xffff, 0x0100, 1, 0, 0, 0) + b'\0' + struct.pack('>2H', 2, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        start = time.monotonic()
        try:
            s.sendto(query, (addr, 53))
            s.recvfrom(512)
        except OSError:
            return None
        return (time.monotonic() - start) * 1000


# Per rule: the seeded metric it judges, its open line, the reference probe
# that measures the same quantity, the fault that moves it by `ms`, how long
# the fault holds, and how long after the clear the rule may take to close
# (health_lab.py's windows for the same rule).
RULES = {
    'gateway.rtt_spike': {
        'metric': 'gateway.rtt', 'line': gateway_line,
        'reference': lambda: ping_ms(hl.GATEWAY),
        'fault': lambda ms: ('netem-icmp', 'gw0', f'delay {ms:.1f}ms'),
        'clear': ('netem-icmp', 'gw0', None),
        'fault_secs': 60, 'close_within_s': 250,
    },
    'dns.slow_resolver': {
        'metric': 'dns.rtt_p50', 'line': dns_line,
        'reference': lambda: dns_ms(hl.GATEWAY),
        'fault': lambda ms: ('dns', 'gw', f'delay:{ms:.1f}'),
        'clear': ('dns', 'gw', 'ok'),
        # The p50 is a median over the probe history, so the slow samples
        # have to outnumber the warm-up's before it moves.
        'fault_secs': 90, 'close_within_s': 300,
    },
    'path.rtt_spike': {
        'metric': 'path.rtt', 'line': path_line,
        'reference': lambda: ping_ms(hl.INTERNET),
        'fault': lambda ms: ('netem', 'gw1', f'delay {ms:.1f}ms'),
        'clear': ('netem', 'gw1', None),
        # Three traces, 30 s apart.
        'fault_secs': 150, 'close_within_s': 360,
    },
}


def cells(rules, reps):
    return [{'name': f'{rule}@{base}ms×{factor:g}#{rep}', 'rule': rule, 'base_ms': base,
             'factor': factor, 'rep': rep}
            for rule in rules for base in BASES_MS for factor in FACTORS for rep in range(reps)]


def cell_secs(cell):
    spec = RULES[cell['rule']]
    return hl.WARMUP_SECS + spec['fault_secs'] + spec['close_within_s'] + hl.SETTLE_SECS


def measure(reference):
    """The median of a few reference probes, or None when most were lost."""
    got = []
    for _ in range(REFERENCE_PROBES):
        ms = reference()
        if ms is not None:
            got.append(ms)
        time.sleep(REFERENCE_GAP_SECS)
    return statistics.median(got) if len(got) > REFERENCE_PROBES // 2 else None


def label(ratio):
    if ratio is None:
        return 'unmeasured'
    return 'positive' if ratio >= POSITIVE else 'negative' if ratio <= NEGATIVE else 'ambiguous'


def opens_of(rows, rule):
    """Ticks at which `rule` went from not open to open."""
    out, was = [], False
    for r in rows:
        now = hl.is_open(r, rule)
        if now and not was:
            out.append(r['t'])
        was = now
    return out


def run_cell(cell, artifacts):
    """One cell, inside the namespaces this process was started in."""
    spec = RULES[cell['rule']]
    rule, base = cell['rule'], cell['base_ms']
    seed = seed_for(base)
    mean, sigma = seed[spec['metric']]['mean'], seed[spec['metric']]['sigma']
    distance = spec['line'](mean, sigma) - mean
    at = {'fault': None, 'clear': None, 'closed': None}
    measured, fault = {}, {'step_ms': 0.0, 'staged': False}
    with hl.Lab() as lab:
        lab.seed.write_text(json.dumps(seed))
        if base > 1:
            # Everything this namespace sends waits `base`, so every probe's
            # round trip is the seeded mean.
            lab.stage(('netem', 'nw0', f'delay {base}ms'))
        stop = lab.dir / 'stop'
        probe = {}

        def reference(name):
            measured[name] = measure(spec['reference'])

        def on_line(r):
            t = r['t']
            if at['fault'] is None:
                if 'base' not in probe and t >= 2:
                    probe['base'] = threading.Thread(target=reference, args=('base_ms',))
                    probe['base'].start()
                if t >= hl.WARMUP_SECS and not probe['base'].is_alive():
                    # Aim at the value the rule will read, not at a step: the
                    # seeded mean is not exactly what this link measures.
                    aim = mean + cell['factor'] * distance
                    step = aim - (measured.get('base_ms') or mean)
                    if cell['factor'] > 0 and step >= MIN_STEP_MS:
                        fault.update(step_ms=step, staged=True)
                        lab.stage(spec['fault'](step))
                    at['fault'] = t
                    probe['fault'] = threading.Thread(target=reference, args=('fault_ms',))
                    probe['fault'].start()
                return
            if at['clear'] is None:
                if t - at['fault'] >= spec['fault_secs']:
                    if fault['staged']:
                        lab.stage(spec['clear'])
                    at['clear'] = t
                return
            if hl.is_open(r, rule):
                at['closed'] = None
            elif at['closed'] is None:
                at['closed'] = t
            if at['closed'] is not None and t >= at['closed'] + hl.SETTLE_SECS:
                stop.touch()

        rows, err = lab.run(cell_secs(cell), on_line=on_line, stop=stop)
        for th in probe.values():
            th.join()
        if artifacts:
            keep = pathlib.Path(artifacts) / cell['name']
            keep.mkdir(parents=True, exist_ok=True)
            (keep / 'lab.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
            (keep / 'driver.err').write_text(err)

    assert at['clear'] is not None, f'the run ended before the fault cleared: {err}'
    base_ms, fault_ms = measured.get('base_ms'), measured.get('fault_ms')
    # Against the seeded mean, which is what the rule's line is drawn from.
    ratio = None if fault_ms is None else (fault_ms - mean) / distance
    opens = opens_of(rows, rule)
    in_fault = [t for t in opens if at['fault'] <= t]
    still_open = hl.is_open(rows[-1], rule)
    others = sorted({i['rule'] for r in rows for i in r['issues']
                     if i['state'] in hl.OPEN and i['rule'] != rule})
    kind = label(ratio)
    if kind == 'positive':
        verdict = ('miss' if not in_fault else 'reopened' if len(opens) > 1
                   else 'stuck_open' if still_open else 'hit')
    elif kind == 'negative':
        verdict = 'false_open' if opens else 'quiet'
    else:
        verdict = kind
    return {
        **cell, 'label': kind, 'verdict': verdict, 'ratio': None if ratio is None else round(ratio, 3),
        'seed_mean_ms': mean, 'distance_ms': round(distance, 2), 'asked_step_ms': round(fault['step_ms'], 2),
        'base_ms_measured': base_ms and round(base_ms, 2), 'fault_ms_measured': fault_ms and round(fault_ms, 2),
        'opens': len(opens), 'open_before_fault': bool(opens) and opens[0] < at['fault'],
        'open_after_s': in_fault[0] - at['fault'] if in_fault else None,
        'close_after_s': at['closed'] - at['clear'] if in_fault and at['closed'] and not still_open else None,
        'other_rules_open': others,
    }


def upper_95(events, n):
    """One-sided 95% upper bound on a proportion after `events` in `n`
    (Clopper-Pearson by bisection)."""
    if n == 0:
        return None
    if events >= n:
        return 1.0

    def cdf(p):
        return sum(math.comb(n, k) * p ** k * (1 - p) ** (n - k) for k in range(events + 1))
    lo, hi = events / n, 1.0
    for _ in range(60):
        mid = (lo + hi) / 2
        lo, hi = (mid, hi) if cdf(mid) > 0.05 else (lo, mid)
    return round(hi, 4)


def summarise(runs):
    out = {}
    for rule in sorted({r['rule'] for r in runs}):
        mine = [r for r in runs if r['rule'] == rule]
        pos = [r for r in mine if r.get('label') == 'positive']
        neg = [r for r in mine if r.get('label') == 'negative']
        count = lambda rows, *verdicts: sum(1 for r in rows if r['verdict'] in verdicts)
        opened = sorted(r['open_after_s'] for r in pos if r.get('open_after_s') is not None)
        closed = sorted(r['close_after_s'] for r in pos if r.get('close_after_s') is not None)
        misses, false_opens = count(pos, 'miss'), count(neg, 'false_open')
        out[rule] = {
            'runs': len(mine),
            'positives': len(pos), 'misses': misses,
            'reopened': count(pos, 'reopened'), 'stuck_open': count(pos, 'stuck_open'),
            'miss_rate_upper_95': upper_95(misses, len(pos)),
            'negatives': len(neg), 'false_opens': false_opens,
            'false_open_rate_upper_95': upper_95(false_opens, len(neg)),
            'ambiguous': count(mine, 'ambiguous'), 'unmeasured': count(mine, 'unmeasured'),
            'errors': count(mine, 'error'),
            'open_after_s': {'median': statistics.median(opened), 'max': opened[-1]} if opened else None,
            'close_after_s': {'median': statistics.median(closed), 'max': closed[-1]} if closed else None,
        }
    return out


def gate(summary):
    """What `--gate` fails on: any miss, any false open, any run that died."""
    return [f'{rule}: {s[key]} {key}' for rule, s in summary.items()
            for key in ('misses', 'false_opens', 'reopened', 'stuck_open', 'errors') if s[key]]


def text(summary):
    lines = ['rule                 pos  miss  reopen  stuck   neg  false  ambig  unmeas  err   open s (med/max)  close s (med/max)']
    for rule, s in summary.items():
        span = lambda d: f"{d['median']:.0f}/{d['max']:.0f}" if d else '-'
        lines.append(f"{rule:<20} {s['positives']:>3}  {s['misses']:>4}  {s['reopened']:>6}  {s['stuck_open']:>5}  "
                     f"{s['negatives']:>4}  {s['false_opens']:>5}  {s['ambiguous']:>5}  {s['unmeasured']:>6}  "
                     f"{s['errors']:>3}   {span(s['open_after_s']):>16}  {span(s['close_after_s']):>17}")
    return '\n'.join(lines)


def orchestrate(todo, jobs, out, artifacts):
    assert hl.BIN.exists(), f'{hl.BIN}: cargo build --example diagnose_lab'
    base = ['unshare', '--user', '--map-root-user', '--net', '--mount', sys.executable,
            os.path.abspath(__file__)]
    started = time.monotonic()
    queue, done, lock = list(todo), [], threading.Lock()

    def worker():
        while True:
            with lock:
                if not queue:
                    return
                cell = queue.pop(0)
            argv = base + ['--run', json.dumps(cell)] + (['--artifacts', artifacts] if artifacts else [])
            p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 start_new_session=True)
            limit = cell_secs(cell) + 2 * hl.GRACE_SECS
            try:
                stdout, stderr = p.communicate(timeout=limit)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                stdout, stderr = p.communicate()
                stderr = f'killed after {limit}s\n{stderr}'
            try:
                result = json.loads(stdout.strip().splitlines()[-1])
            except (IndexError, ValueError):
                result = {**cell, 'label': None, 'verdict': 'error', 'error': str(stderr)[-2000:]}
            with lock:
                done.append(result)
                print(json.dumps({k: result.get(k) for k in ('name', 'label', 'verdict', 'ratio',
                                                             'open_after_s', 'close_after_s')}), flush=True)

    threads = [threading.Thread(target=worker) for _ in range(jobs)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    summary = summarise(done)
    report = {'wall_s': round(time.monotonic() - started), 'jobs': jobs, 'summary': summary,
              'runs': sorted(done, key=lambda r: r['name'])}
    pathlib.Path(out).write_text(json.dumps(report, indent=1) + '\n')
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--rule', nargs='+', choices=sorted(RULES), default=sorted(RULES))
    ap.add_argument('--reps', type=int, default=1, help='runs of each cell (default %(default)s)')
    ap.add_argument('--base', type=int, nargs='+', choices=BASES_MS, help='base latencies, ms (default: all)')
    ap.add_argument('--factor', type=float, nargs='+', choices=FACTORS, help='steps (default: all)')
    ap.add_argument('--jobs', type=int, default=max(1, min(8, (os.cpu_count() or 2) // 2)),
                    help='cells run at once (default %(default)s); more makes timing noisier')
    ap.add_argument('--out', default='matrix-lab.json')
    ap.add_argument('--artifacts', metavar='DIR', help="keep each run's JSON lines here")
    ap.add_argument('--gate', action='store_true', help='exit 1 on any miss, false open or error')
    ap.add_argument('--list', action='store_true', help='print the cells and how long they take')
    ap.add_argument('--summarise', metavar='FILE', help='summarise a saved result again')
    ap.add_argument('--run', help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.run:
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
        cell = json.loads(args.run)
        try:
            result = run_cell(cell, args.artifacts and os.path.abspath(args.artifacts))
        except Exception as e:  # reported as an error run, not lost
            result = {**cell, 'label': None, 'verdict': 'error', 'error': f'{type(e).__name__}: {e}'[-2000:]}
        print(json.dumps(result), flush=True)
        return
    if args.summarise:
        summary = summarise(json.loads(pathlib.Path(args.summarise).read_text())['runs'])
    else:
        todo = [c for c in cells(args.rule, args.reps)
                if (not args.base or c['base_ms'] in args.base)
                and (not args.factor or c['factor'] in args.factor)]
        if args.list:
            worst = sum(cell_secs(c) for c in todo)
            print(f'{len(todo)} cells, at most {worst / 3600:.1f} runner-hours, '
                  f'{worst / 3600 / args.jobs:.1f} h at --jobs {args.jobs}')
            for c in todo:
                print(' ', c['name'])
            return
        summary = orchestrate(todo, args.jobs, args.out, args.artifacts and os.path.abspath(args.artifacts))
    print(text(summary))
    failures = gate(summary)
    for f in failures:
        print('FAIL' if args.gate else 'note', f)
    sys.exit(1 if args.gate and failures else 0)


if __name__ == '__main__':
    main()
