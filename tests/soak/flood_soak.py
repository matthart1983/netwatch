#!/usr/bin/env python3
"""Flood soak: netwatch capturing a flood sent from a peer namespace.

The real App captures on one end of a veth while a peer namespace floods the
other end, and the run is gated on memory, the capture caps and frame time.

  python3 tests/soak/flood_soak.py [--minutes 60] [--out flood-soak.json] [--artifacts DIR]
  python3 tests/soak/flood_soak.py --smoke [--out FILE] [--artifacts DIR]
  python3 tests/soak/flood_soak.py --summarise flood-soak.jsonl [--out FILE]
  python3 tests/soak/flood_soak.py --self-test

It re-execs itself in unshare --user --map-root-user --net --mount, so it
needs no root, only a kernel that gives an unprivileged user those
namespaces (Ubuntu 24.04 needs kernel.apparmor_restrict_unprivileged_userns=0).
Inside, sysfs is remounted, a peer network namespace comes from
unshare --net, and a veth joins them:

  this namespace   nw0 203.0.113.1/30, captured by netwatch; the bulk sink
  peer             fl0 203.0.113.2/30, where tests/soak/flood.py sends from

The run, all in one driver process (examples/flood_soak, the real App with
capture on nw0, drawn at 10 fps):

  1. two cycles of every scenario in SCENARIOS at full rate, --minutes over
     both cycles (5 min each in a 60-minute run), the second cycle's churn
     and replay flows new
  2. small UDP paced at each rate in PACED_PPS, --paced-seconds between them
  3. then, with the driver gone, the real `netwatch daemon` for
     --daemon-seconds under each load in DAEMON_LOADS in turn, its memory
     read from /proc/PID

--smoke is the same at 20 s a scenario, 10 s a paced rate and 30 s of the
daemon: about five minutes.

The .jsonl beside --out (flood-soak.jsonl) keeps every line the driver
printed, each phase's span and generator report, and the daemon's samples.
--summarise gates a saved one again. The gates are in gates(); --self-test runs them
against canned lines, passing and failing. Nothing here changes a host
setting: the mounts, links and addresses live in namespaces that end with
the run. Needs ip, nsenter, unshare and mount, and
target/release/examples/flood_soak and target/release/netwatch
(cargo build --release --example flood_soak --bin netwatch).
"""
import argparse, importlib.util, itertools, json, math, os, pathlib, platform, signal, socket, statistics, subprocess, sys, tempfile, threading, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
DRIVER = ROOT / 'target/release/examples/flood_soak'
NETWATCH = ROOT / 'target/release/netwatch'
FLOOD = pathlib.Path(__file__).resolve().parent / 'flood.py'
IFACE, PEER_IFACE = 'nw0', 'fl0'
ADDR, PEER_ADDR = '203.0.113.1', '203.0.113.2'
# flood.py's scenarios, in cycle order. bulk is the only one that puts
# segmentation-offload super-frames on the wire.
SCENARIOS = ['udp-churn', 'syn-churn', 'dns', 'mtu-tcp', 'replay', 'bulk']
CYCLES = 2
PACED_PPS = [50_000, 100_000]
# What the real daemon runs under, one after the other. mix opens flows
# faster than any stream fills, so the stream budget stays nearly empty
# under it; mtu-tcp then fills the budget. bulk adds super-frames to both.
DAEMON_LOADS = [('mix', 'bulk'), ('mtu-tcp', 'bulk')]
# examples/flood_soak's VIEWS, by the names its lines use.
VIEWS = ['dashboard', 'connections', 'packets', 'packets_filtered', 'stats', 'timeline']

# The documented RSS ceiling (docs/PERFORMANCE.md): recorder disarmed, default
# budgets, with or without Country and ASN GeoIP loaded.
CEILING_MIB = 512
# How much higher cycle 2 may peak than cycle 1 before memory reads as growing.
PLATEAU_MIB = 16
# packets/mod.rs RING_BYTE_BUDGET, and MAX_STREAMS + STREAM_EVICT_BATCH.
RING_BYTE_BUDGET = 32 << 20
MAX_STREAMS = 1280
MAX_THREADS = 100
# Seconds the driver must have printed a line for, of those planned.
SAMPLED = 0.95
# A frame larger than this came from segmentation offload: AF_PACKET writes
# stop at the MTU.
SUPER_FRAME = 16 << 10
FRAME_P99_MS = 33
# Decoded pps below this share of the calibrated median is a regression.
PPS_FLOOR = 0.25
# A phase's first lines straddle the generator starting, and the first one
# records the end of the phase before, so a phase's figures leave them out.
# Every gate but `decoded` still reads them.
WARMUP = 2
# Past a step's own length before the lab gives up on it.
GRACE_SECS = 60


def cmd(*args, ns=None, check=True):
    prefix = ['nsenter', '-t', str(ns), '-n'] if ns else []
    return subprocess.run(prefix + list(map(str, args)), check=check, capture_output=True, text=True)


def ip(*args, **kw):
    return cmd('ip', *args, **kw)


class Lab:
    """The namespaces, the bulk sink and a temp home, torn down on exit."""

    def __init__(self, geoip):
        self.children = []
        self.tmp = None
        self.geoip = geoip

    def __enter__(self):
        try:
            self.isolate()
            self.topology()
            self.sink()
            self.make_home()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *exc):
        for p in reversed(self.children):
            if p.poll() is None:
                p.kill()
                p.wait()
        if self.tmp:
            self.tmp.cleanup()

    def isolate(self):
        assert os.geteuid() == 0, 'run inside unshare --user --map-root-user --net --mount'
        # Protect against mistakenly executing as real root in the host namespace.
        assert pathlib.Path('/proc/self/uid_map').read_text().split()[1] != '0', 'isolated user namespace required'
        # Only possible in a mount namespace this user namespace owns, so a
        # sysfs that mounts is also proof the host's /sys is untouched.
        mounted = cmd('mount', '-t', 'sysfs', 'sysfs', '/sys', check=False)
        assert mounted.returncode == 0, f'{mounted.stderr.strip()}: a mount namespace is required (unshare --mount)'
        assert os.listdir('/sys/class/net') == ['lo'], os.listdir('/sys/class/net')
        self.tmp = tempfile.TemporaryDirectory(prefix='nw-flood-')
        self.dir = pathlib.Path(self.tmp.name)

    def topology(self):
        p = subprocess.Popen(['unshare', '--net', 'sleep', 'infinity'])
        self.children.append(p)
        mine = os.readlink('/proc/self/ns/net')
        deadline = time.monotonic() + 5
        while os.readlink(f'/proc/{p.pid}/ns/net') == mine:
            assert time.monotonic() < deadline, 'peer namespace did not start'
            time.sleep(0.01)
        self.peer = p.pid
        for ns in (None, self.peer):
            ip('link', 'set', 'lo', 'up', ns=ns)
        ip('link', 'add', IFACE, 'type', 'veth', 'peer', 'name', PEER_IFACE)
        ip('link', 'set', PEER_IFACE, 'netns', self.peer)
        for dev, addr, ns in [(IFACE, ADDR, None), (PEER_IFACE, PEER_ADDR, self.peer)]:
            ip('addr', 'add', f'{addr}/30', 'dev', dev, ns=ns)
            ip('link', 'set', dev, 'up', ns=ns)
        names = sorted(os.listdir('/sys/class/net'))
        assert names == ['lo', IFACE], f'/sys/class/net lists {names}: sysfs is not this namespace'

    def sink(self):
        self.children.append(subprocess.Popen([sys.executable, '-I', FLOOD, 'sink', '--bind', ADDR]))
        # /proc/net/tcp spells a bound address as host-order hex, port 5001 as
        # 1389, and LISTEN as 0A.
        bound = '%08X:1389' % int.from_bytes(socket.inet_aton(ADDR), sys.byteorder)
        deadline = time.monotonic() + 5
        while not any(line.split()[1] == bound and line.split()[3] == '0A'
                      for line in pathlib.Path('/proc/net/tcp').read_text().splitlines()[1:]):
            assert time.monotonic() < deadline, 'the bulk sink did not start'
            time.sleep(0.05)

    def make_home(self):
        """The temp home the driver insists on: marked, with every XDG
        directory inside it, and a config that captures on the lab's link."""
        self.home = self.dir / 'home'
        self.env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(self.home),
                    'TMPDIR': tempfile.gettempdir()}
        for var, sub in [('XDG_CACHE_HOME', '.cache'), ('XDG_CONFIG_HOME', '.config'),
                         ('XDG_STATE_HOME', '.local/state'), ('XDG_DATA_HOME', '.local/share')]:
            (self.home / sub).mkdir(parents=True)
            self.env[var] = str(self.home / sub)
        (self.home / '.netwatch-lab').write_text('')
        self.config = self.home / '.config/netwatch/config.toml'
        self.config.parent.mkdir()
        self.config.write_text(f'capture_interface = "{IFACE}"\ninsights_enabled = false\n')

    def daemon_config(self):
        """The daemon reads GeoIP from its config; the driver takes flags."""
        lines = [f'{key} = {json.dumps(path)}\n' for key, path in self.geoip.items()]
        with open(self.config, 'a') as f:
            f.writelines(lines)

    def flood(self, scenario, seconds, pps=0, tcpreplay=None, cycle=0):
        """flood.py in the peer namespace."""
        argv = [sys.executable, '-I', FLOOD, scenario, '--seconds', seconds]
        if scenario == 'bulk':
            argv += ['--to', ADDR]
        else:
            argv += ['--iface', PEER_IFACE, '--pps', pps, '--cycle', cycle]
        if tcpreplay and scenario == 'replay':
            argv += ['--tcpreplay', tcpreplay]
        p = subprocess.Popen(['nsenter', '-t', str(self.peer), '-n', *map(str, argv)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.children.append(p)
        return p


def finish(p, seconds):
    """A generator's report, or why there is none."""
    try:
        out, err = p.communicate(timeout=seconds + GRACE_SECS)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        return {'error': f'still running {seconds + GRACE_SECS}s after it started'}
    try:
        report = json.loads(out.strip().splitlines()[-1])
    except (IndexError, ValueError):
        report = {}
    if p.returncode != 0 or not report:
        report['error'] = f'exit {p.returncode}: {err.strip()[-2000:]}'
    return report


class Driver:
    """examples/flood_soak and the lines it has printed, read as they come."""

    def __init__(self, lab, argv, log, err):
        self.rows, self.last_t = [], 0
        self.stop = lab.dir / 'stop'
        self.p = subprocess.Popen([*map(str, argv), '--stop-file', self.stop], env=lab.env,
                                  stdout=subprocess.PIPE, stderr=err, text=True, start_new_session=True)
        lab.children.append(self.p)
        self.first = threading.Event()
        self.reader = threading.Thread(target=self.read, args=(log,), daemon=True)
        self.reader.start()

    def read(self, log):
        for line in self.p.stdout:
            row = json.loads(line)
            self.rows.append(row)
            self.last_t = row['t']
            log({'kind': 'driver', **row})
            self.first.set()
        self.first.set()

    def alive(self):
        return self.p.poll() is None

    def end(self):
        """Stop after the next line; the exit status."""
        self.stop.write_text('')
        try:
            self.p.wait(timeout=GRACE_SECS)
        except subprocess.TimeoutExpired:
            os.killpg(self.p.pid, signal.SIGKILL)
            self.p.wait()
        self.reader.join(timeout=10)
        return self.p.returncode


def proc_sample(pid, hz):
    """VmRSS, VmHWM and Threads from /proc/PID/status and CPU seconds from
    /proc/PID/stat, or None once the process is gone."""
    try:
        status = pathlib.Path(f'/proc/{pid}/status').read_text()
        stat = pathlib.Path(f'/proc/{pid}/stat').read_text()
    except OSError:
        return None
    row = {}
    for line in status.splitlines():
        key, _, value = line.partition(':')
        if key in ('VmRSS', 'VmHWM', 'Threads'):
            row[{'VmRSS': 'rss_kib', 'VmHWM': 'hwm_kib', 'Threads': 'threads'}[key]] = int(value.split()[0])
    if 'rss_kib' not in row:
        # A zombie: exited, not yet reaped, and with no memory to report.
        return None
    fields = stat.rpartition(')')[2].split()
    row['utime_s'], row['stime_s'] = int(fields[11]) / hz, int(fields[12]) / hz
    return row


def packet_sockets(pid):
    """How many AF_PACKET sockets the process holds, from its fds and this
    namespace's /proc/net/packet; None when its fds cannot be read."""
    inodes = {line.split()[-1] for line in pathlib.Path('/proc/net/packet').read_text().splitlines()[1:]}
    try:
        links = [os.readlink(f'/proc/{pid}/fd/{fd}') for fd in os.listdir(f'/proc/{pid}/fd')]
    except OSError:
        return None
    return sum(1 for link in links if link.startswith('socket:[') and link[8:-1] in inodes)


def run(args, log):
    """Every phase, in the namespaces. Writes records through log()."""
    phases = plan(args)
    geoip = {k: os.path.abspath(v) for k, v in [('geoip_db', args.geoip_db), ('geoip_asn_db', args.geoip_asn_db)] if v}
    log({'kind': 'run', 'phases': phases, 'daemon_seconds': args.daemon_seconds, 'ceiling_mib': args.ceiling_mib,
         'geoip_asked': sorted(geoip), 'recorder': 'disarmed', 'commit': commit(), 'host': host()})
    errors = []
    with Lab(geoip) as lab, open(lab.dir / 'driver.err', 'w+') as err:
        total = sum(p['seconds'] for p in phases)
        argv = [DRIVER, '--interface', IFACE, '--seconds', total + GRACE_SECS]
        for key, path in geoip.items():
            argv += [f'--{key.replace("_", "-")}', path]
        driver = Driver(lab, argv, log, err)
        if not driver.first.wait(timeout=GRACE_SECS) or not driver.rows:
            errors.append('the driver printed no line')
        for phase in phases if driver.rows else []:
            if not driver.alive():
                errors.append(f'the driver exited {driver.p.returncode} before {phase["name"]}')
                break
            start = driver.last_t + 1
            report = finish(lab.flood(phase['scenario'], phase['seconds'], phase['pps'], args.tcpreplay,
                                      phase['cycle'] or 0), phase['seconds'])
            log({'kind': 'phase', **phase, 'start_t': start, 'end_t': driver.last_t, 'generator': report})
            print(f'{phase["name"]:<14} t {start}..{driver.last_t}  {json.dumps(report)}', flush=True)
        code = driver.end()
        err.seek(0)
        stderr = err.read()
        if args.artifacts:
            (args.artifacts / 'driver.err').write_text(stderr)
        if code != 0:
            errors.append(f'the driver exited {code}: {stderr.strip()[-2000:]}')
        if args.daemon_seconds:
            errors += daemon(lab, args, log)
    log({'kind': 'end', 'errors': errors})


def daemon(lab, args, log):
    """The real `netwatch daemon` under each of DAEMON_LOADS in turn, its
    generators at once, sampled from /proc once a second. Returns what went
    wrong."""
    lab.daemon_config()
    hz = os.sysconf('SC_CLK_TCK')
    errors, reports = [], []
    seconds = args.daemon_seconds // len(DAEMON_LOADS)
    with open(lab.dir / 'daemon.err', 'w+') as err:
        p = subprocess.Popen([NETWATCH, 'daemon'], env=lab.env, stdout=err, stderr=err, start_new_session=True)
        lab.children.append(p)
        deadline = time.monotonic() + 10
        held = packet_sockets(p.pid)
        while not held and p.poll() is None and time.monotonic() < deadline:
            time.sleep(0.1)
            held = packet_sockets(p.pid)
        for i, load in enumerate(DAEMON_LOADS):
            flood = [lab.flood(scenario, seconds) for scenario in load]
            started = time.monotonic()
            for t in range(1, seconds + 1):
                time.sleep(max(0.0, started + t - time.monotonic()))
                row = proc_sample(p.pid, hz)
                if row is None:
                    break
                log({'kind': 'daemon', 't': i * seconds + t, 'load': '+'.join(load), **row})
            reports += [finish(f, seconds) for f in flood]
            if p.poll() is not None:
                break
        # Capture that stopped during the flood shows here, not at the start.
        held_end = packet_sockets(p.pid)
        alive = p.poll() is None
        if alive:
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
        err.seek(0)
        stderr = err.read()
    if args.artifacts:
        (args.artifacts / 'daemon.err').write_text(stderr)
    # The daemon's panic hook chains to the default one, which writes this to
    # stderr. A panic in a collector thread leaves the daemon running and its
    # exit status 0.
    panicked = 'panicked at' in stderr
    log({'kind': 'daemon_end', 'seconds': seconds * len(DAEMON_LOADS), 'loads': ['+'.join(l) for l in DAEMON_LOADS],
         'packet_sockets': held, 'packet_sockets_end': held_end, 'panicked': panicked, 'alive_at_end': alive,
         'exit': p.returncode, 'generators': reports})
    print(f'daemon         {seconds}s each  {json.dumps(reports)}', flush=True)
    if not alive:
        errors.append(f'the daemon exited {p.returncode} during its phase: {stderr.strip()[-2000:]}')
    return errors


def plan(args):
    phases = [{'name': f'c{c}-{s}', 'cycle': c, 'scenario': s, 'pps': 0, 'seconds': args.phase_seconds}
              for c in range(1, CYCLES + 1) for s in args.scenarios]
    phases += [{'name': f'paced-{pps // 1000}k', 'cycle': None, 'scenario': 'udp-churn', 'pps': pps,
                'seconds': args.paced_seconds // len(PACED_PPS)} for pps in PACED_PPS if args.paced_seconds]
    return phases


def commit():
    out = subprocess.run(['git', '-C', ROOT, 'rev-parse', 'HEAD'], capture_output=True, text=True)
    return out.stdout.strip() or os.environ.get('GITHUB_SHA')


def host():
    cpu = next((line.split(':', 1)[1].strip() for line in open('/proc/cpuinfo') if line.startswith('model name')), None)
    mem = next((int(line.split()[1]) for line in open('/proc/meminfo') if line.startswith('MemTotal')), 0)
    return {'kernel': platform.release(), 'cpu': cpu, 'cpus': os.cpu_count(), 'mem_mib': mem // 1024}


# ── Summary and gates: no namespace needed from here on ──────────────────


def percentile(values, p):
    """The pth percentile of values, by nearest rank."""
    if not values:
        return None
    values = sorted(values)
    rank = math.ceil(round(p * len(values), 9))
    return values[min(max(rank, 1), len(values)) - 1]


def mib(kib):
    return round(kib / 1024, 1)


def frame_stats(rows):
    out = {}
    for view in VIEWS:
        times = [ms for r in rows for ms in r.get('frame_ms', {}).get(view, [])]
        if times:
            out[view] = {'n': len(times), 'p50': percentile(times, 0.5), 'p99': percentile(times, 0.99),
                         'max': max(times)}
    return out


def rates(rows, key):
    """Per-second change in key between consecutive lines."""
    return [(b[key] - a[key]) / (b['t'] - a['t']) for a, b in zip(rows, rows[1:]) if b['t'] > a['t']]


def measured(rows):
    """A phase's lines after WARMUP, or all of them in a phase too short to
    spare those."""
    return rows[WARMUP:] if len(rows) > WARMUP + 1 else rows


def phase_stats(phase, rows):
    out = {k: phase[k] for k in ('name', 'cycle', 'scenario', 'pps', 'seconds', 'start_t', 'end_t')}
    gen = phase.get('generator', {})
    out['offered_pps'] = gen.get('pps')
    if phase['scenario'] == 'bulk' and gen.get('seconds'):
        out['offered_mb_s'] = round(gen.get('bytes', 0) / gen['seconds'] / 1e6, 1)
    out['rows'] = len(rows)
    if not rows:
        return out
    rows = measured(rows)
    for key in ('received', 'decoded', 'dropped'):
        r = rates(rows, key)
        out[f'{key}_pps'] = round(statistics.median(r)) if r else None
    first, last = rows[0], rows[-1]
    received = last['received'] - first['received']
    out['drop_pct'] = round(100 * (last['dropped'] - first['dropped']) / received, 2) if received else 0.0
    span = last['t'] - first['t']
    cpu = (last['utime_s'] + last['stime_s']) - (first['utime_s'] + first['stime_s'])
    out['cpu_pct'] = round(100 * cpu / span) if span else None
    out['rss_max_mib'] = mib(max(r['rss_kib'] for r in rows))
    out['hwm_mib'] = mib(max(r['hwm_kib'] for r in rows))
    for key in ('ring_bytes', 'held_bytes', 'streams', 'threads', 'max_frame'):
        out[f'{key}_max'] = max(r[key] for r in rows)
    ticks = [r['tick_ms'] for r in rows if r.get('tick_ms') is not None]
    out['tick_ms_max'] = max(ticks) if ticks else None
    out['frame_ms'] = frame_stats(rows)
    return out


def daemon_stats(rows):
    """One daemon load's peak VmRSS and VmHWM, and its CPU."""
    if not rows:
        return {}
    out = {'rss_max_mib': mib(max(r['rss_kib'] for r in rows)), 'hwm_mib': mib(max(r['hwm_kib'] for r in rows))}
    first, last = rows[0], rows[-1]
    if last['t'] > first['t']:
        cpu = (last['utime_s'] + last['stime_s']) - (first['utime_s'] + first['stime_s'])
        out['cpu_pct'] = round(100 * cpu / (last['t'] - first['t']))
    return out


def load(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def summarise(records, calibration=None, ceiling_mib=None):
    """The summary flood-soak.json holds, gates included, from the records
    a run wrote."""
    run = next(r for r in records if r['kind'] == 'run')
    ceiling = ceiling_mib or run.get('ceiling_mib') or CEILING_MIB
    rows = [r for r in records if r['kind'] == 'driver']
    phases = [r for r in records if r['kind'] == 'phase']
    by_phase = {p['name']: [r for r in rows if p['start_t'] <= r['t'] <= p['end_t']] for p in phases}
    stats = [phase_stats(p, by_phase[p['name']]) for p in phases]
    in_phases = [r for p in phases for r in by_phase[p['name']]]
    scenarios = {}
    for s in dict.fromkeys(p['scenario'] for p in phases if p['cycle']):
        cycles = [p for p in stats if p['cycle'] and p['scenario'] == s and p.get('decoded_pps') is not None]
        if cycles:
            scenarios[s] = {key: round(statistics.median(p[key] for p in cycles if p.get(key) is not None), 2)
                            for key in ('decoded_pps', 'drop_pct', 'cpu_pct')
                            if any(p.get(key) is not None for p in cycles)}
    daemon_rows = [r for r in records if r['kind'] == 'daemon']
    daemon_end = next((r for r in records if r['kind'] == 'daemon_end'), None)
    daemon = None
    if daemon_end:
        daemon = {**{k: daemon_end[k] for k in ('seconds', 'packet_sockets', 'packet_sockets_end', 'panicked',
                                                'alive_at_end', 'exit')},
                  'samples': len(daemon_rows), 'generators': daemon_end['generators']}
        if daemon_rows:
            daemon['rss_max_mib'] = mib(max(r['rss_kib'] for r in daemon_rows))
            daemon['hwm_mib'] = mib(max(r['hwm_kib'] for r in daemon_rows))
            daemon['threads_max'] = max(r['threads'] for r in daemon_rows)
            daemon['loads'] = {load: daemon_stats([r for r in daemon_rows if r['load'] == load])
                               for load in daemon_end['loads']}
    end = next((r for r in records if r['kind'] == 'end'), {'errors': ['the run did not finish']})
    summary = {'commit': run.get('commit'), 'host': run.get('host'), 'geoip_asked': run.get('geoip_asked'),
               'geoip': rows[0]['geoip'] if rows else None, 'recorder': run.get('recorder'),
               'ceiling_mib': ceiling, 'phases': stats,
               'scenarios': scenarios, 'frame_ms': frame_stats(in_phases), 'daemon': daemon,
               'errors': end['errors']}
    summary['gates'] = gates(run, phases, by_phase, in_phases, rows, daemon_rows, daemon, scenarios,
                             calibration, ceiling, end['errors'])
    summary['passed'] = all(g['passed'] for g in summary['gates'])
    return summary


def gates(run, phases, by_phase, in_phases, rows, daemon_rows, daemon, scenarios, calibration, ceiling,
          errors):
    out = []

    def gate(name, passed, detail):
        out.append({'gate': name, 'passed': bool(passed), 'detail': detail})

    def worst(key, rows):
        return max((r[key] for r in rows), default=0)

    gate('run', not errors, '; '.join(errors) or 'every step finished')
    failed = {p['name']: idle(p['generator']) for p in phases if idle(p['generator'])}
    gate('generator', len(phases) == len(run['phases']) and not failed,
         f'{len(phases)} of {len(run["phases"])} phases ran' + (f', generator failed in {failed}' if failed else ''))
    # Over the measured lines only: in the first, capture can still be
    # draining the phase before.
    lines = {p['name']: measured(by_phase[p['name']]) for p in phases}
    silent = [name for name, ls in lines.items() if not ls or ls[-1]['decoded'] <= ls[0]['decoded']]
    gate('decoded', not silent, f'decoded nothing in {silent}' if silent else 'decoded packets in every phase')
    hwm = worst('hwm_kib', rows)
    gate('hwm', rows and hwm <= ceiling * 1024, f'VmHWM {mib(hwm)} MiB, ceiling {ceiling} MiB')
    peaks = {c: worst('rss_kib', [r for p in phases if p['cycle'] == c for r in by_phase[p['name']]])
             for c in (1, 2)}
    gate('plateau', peaks[1] and peaks[2] and peaks[2] <= peaks[1] + PLATEAU_MIB * 1024,
         f'cycle 2 peaked at {mib(peaks[2])} MiB, cycle 1 at {mib(peaks[1])} MiB, allowed +{PLATEAU_MIB}')
    over = [r['t'] for r in rows if r['held_bytes'] > r['stream_budget']]
    gate('held_bytes', rows and not over,
         f'streams held at most {mib(worst("held_bytes", rows) / 1024)} MiB of '
         f'{mib(worst("stream_budget", rows) / 1024)} MiB' + (f'; over at t={over[:5]}' if over else ''))
    gate('ring_bytes', rows and worst('ring_bytes', rows) <= RING_BYTE_BUDGET,
         f'ring held at most {mib(worst("ring_bytes", rows) / 1024)} MiB of {RING_BYTE_BUDGET >> 20} MiB')
    gate('streams', rows and worst('streams', rows) <= MAX_STREAMS,
         f'at most {worst("streams", rows)} streams, cap {MAX_STREAMS}')
    threads = max(worst('threads', rows), worst('threads', daemon_rows))
    gate('threads', rows and threads < MAX_THREADS, f'at most {threads} threads, limit {MAX_THREADS}')
    broken = [(r['t'], r['capture_error']) for r in rows if not r['capturing'] or r['capture_error']]
    gate('capture', rows and not broken, f'not capturing at {broken[:3]}' if broken else 'capturing throughout')
    panicked = [r['t'] for r in rows if r['panicked']]
    gate('panic', not panicked, f'a thread panicked by t={panicked[0]}' if panicked else 'no panic')
    planned = sum(p['seconds'] for p in run['phases'])
    seen = len({r['t'] for r in in_phases})
    gate('sampled', seen >= SAMPLED * planned, f'{seen} lines in {planned} planned seconds, {SAMPLED:.0%} needed')
    bulk = [r for p in phases if p['scenario'] == 'bulk' for r in by_phase[p['name']]]
    if any(p['scenario'] == 'bulk' for p in run['phases']):
        gate('super_frames', worst('max_frame', bulk) > SUPER_FRAME,
             f'largest bulk-phase frame {worst("max_frame", bulk)} B, needs > {SUPER_FRAME}')
    frames = frame_stats(in_phases)
    slow = {v: s['p99'] for v, s in frames.items() if s['p99'] > FRAME_P99_MS}
    gate('frame_p99', len(frames) == len(VIEWS) and not slow,
         f'worst p99 {max((s["p99"] for s in frames.values()), default=None)} ms, budget {FRAME_P99_MS} ms'
         + (f'; over: {slow}' if slow else '') + ('' if len(frames) == len(VIEWS) else f'; drew only {sorted(frames)}'))
    if daemon is not None:
        dhwm = worst('hwm_kib', daemon_rows)
        gate('daemon_hwm', daemon_rows and dhwm <= ceiling * 1024,
             f'daemon VmHWM {mib(dhwm)} MiB, ceiling {ceiling} MiB')
        failed = [idle(g) for g in daemon['generators'] if idle(g)]
        gate('daemon_load', daemon['generators'] and not failed,
             f'generator failed: {failed}' if failed else f'{len(daemon["generators"])} generators sent traffic')
        held = daemon['packet_sockets'], daemon['packet_sockets_end']
        gate('daemon_capture', all(held), "could not read the daemon's fds" if None in held
             else f'daemon held {held[0]} packet sockets when the flood began and {held[1]} when it ended')
        gate('daemon_panic', not daemon['panicked'],
             'a thread panicked: see daemon.err' if daemon['panicked'] else 'no panic')
        gate('daemon_exit', daemon['alive_at_end'] and daemon['exit'] == 0,
             f'alive at the end: {daemon["alive_at_end"]}, exit {daemon["exit"]} on SIGTERM')
    if calibration:
        low = {s: (v['decoded_pps'], round(PPS_FLOOR * calibration[s]))
               for s, v in scenarios.items() if s in calibration and v['decoded_pps'] < PPS_FLOOR * calibration[s]}
        gate('pps_floor', not low, f'decoded pps under {PPS_FLOOR:.0%} of calibration: {low}' if low
             else f'every scenario at or above {PPS_FLOOR:.0%} of calibration')
    return out


def idle(report):
    """Why a generator's report shows no flood, or None. Every report but an
    error has bytes."""
    if report.get('error'):
        return report['error']
    if not report.get('bytes'):
        return 'sent nothing'
    return None


def calibration_from(path):
    """Decoded pps by scenario from an earlier run's flood-soak.json."""
    scenarios = json.loads(pathlib.Path(path).read_text())['scenarios']
    # A scenario that decoded nothing there would set no floor here.
    zero = [s for s, v in scenarios.items() if not v.get('decoded_pps')]
    assert not zero, f'{path} decoded nothing in {zero}: calibrate from a run that did'
    return {s: v['decoded_pps'] for s, v in scenarios.items()}


def report(summary):
    def num(v, unit=''):
        if v is None:
            return '-'
        if isinstance(v, (int, float)) and abs(v) >= 1e6:
            return f'{v / 1e6:.2f}M{unit}'
        if isinstance(v, (int, float)) and abs(v) >= 1000:
            return f'{v / 1000:.0f}k{unit}'
        return f'{v}{unit}'
    print(f'{"phase":<14} {"offered":>8} {"decoded":>8} {"drop":>6} {"cpu":>5} {"rss":>6} {"hwm":>6} '
          f'{"frame p50/p99 worst view":>26}')
    for p in summary['phases']:
        frames = p.get('frame_ms') or {}
        view = max(frames, key=lambda v: frames[v]['p99'], default=None)
        worst = f'{frames[view]["p50"]}/{frames[view]["p99"]} ms {view}' if view else '-'
        offered = num(p.get('offered_pps'))
        if 'offered_mb_s' in p:
            mb = p['offered_mb_s']
            offered = f'{mb / 1000:.1f}GB/s' if mb >= 1000 else f'{mb:.0f}MB/s'
        print(f'{p["name"]:<14} {offered:>8} {num(p.get("decoded_pps")):>8} {num(p.get("drop_pct"), "%"):>6} '
              f'{num(p.get("cpu_pct"), "%"):>5} {num(p.get("rss_max_mib")):>6} {num(p.get("hwm_mib")):>6} {worst:>26}')
    d = summary['daemon']
    for load, figures in (d or {}).get('loads', {}).items():
        print(f'{"daemon":<14} {load:>17} {"":>6} {num(figures.get("cpu_pct"), "%"):>5} '
              f'{num(figures.get("rss_max_mib")):>6} {num(figures.get("hwm_mib")):>6}')
    for view, s in summary['frame_ms'].items():
        print(f'  {view:<17} {s["n"]:>6} frames  p50 {s["p50"]} ms  p99 {s["p99"]} ms  max {s["max"]} ms')
    for g in summary['gates']:
        print(f'{"PASS" if g["passed"] else "FAIL"} {g["gate"]:<15} {g["detail"]}')
    print(f'passed: {summary["passed"]}', flush=True)


# ── Self-test: the gates against canned lines ─────────────────────────────


def canned(case):
    """The records of a short run that passes every gate, or that fails the
    one gate `case` names."""
    phase_s, paced_s = 10, 10
    args = argparse.Namespace(scenarios=SCENARIOS, phase_seconds=phase_s, paced_seconds=paced_s)
    phases = plan(args)
    records = [{'kind': 'run', 'phases': phases, 'daemon_seconds': 6, 'ceiling_mib': CEILING_MIB,
                'geoip_asked': [], 'recorder': 'disarmed', 'commit': None, 'host': None}]
    t, rss, hwm, totals = 0, 0, 0, [0, 0, 0]
    for p in phases:
        start = t + 1
        for _ in range(p['seconds']):
            t += 1
            if case == 'stall' and t % 8 == 0:
                continue
            rss = (300 << 10) + (t % 5) * 1024 + (32 << 10 if case == 'plateau' and p['cycle'] == 2 else 0)
            spike = case == 'ceiling' and p['name'] == 'c1-mtu-tcp'
            hwm = max(hwm, rss, (600 << 10) if spike else 0)
            # In nothing-decoded, c1-syn-churn decodes only in its first two
            # lines, as capture drains the phase before.
            if not (case == 'nothing-decoded' and p['name'] == 'c1-syn-churn' and t > start + 1):
                totals = [totals[0] + 200_000, totals[1] + 20_000, totals[2] + 180_000]
            super_frame = p['scenario'] == 'bulk' and case != 'no-super-frames'
            records.append({
                'kind': 'driver', 't': t, 'geoip': [], 'capturing': True, 'capture_error': None, 'panicked': False,
                'received': totals[0], 'dropped': totals[1], 'decoded': totals[2], 'ring_len': 5000,
                'ring_bytes': 30 << 20, 'max_frame': 65_226 if super_frame else 1514, 'streams': 1200,
                'held_bytes': (300 << 20) if case == 'held' and t == 50 else 200 << 20,
                'stream_budget': 256 << 20, 'dropped_flows': t * 10, 'scan_states': 1000,
                'beacon_states': 0, 'alerts': 100, 'connections': 3, 'rss_kib': rss, 'hwm_kib': hwm,
                'threads': 40, 'utime_s': t * 0.9, 'stime_s': t * 0.1, 'tick_ms': 12.5,
                'frame_ms': {v: [1.5, 2.5, 40.0 if case == 'slow-frames' and v == 'stats' else 3.0]
                             for v in VIEWS}})
        sent = 0 if case == 'nothing-sent' and p['name'] == 'c1-dns' else 1_000_000
        records.append({'kind': 'phase', **p, 'start_t': start, 'end_t': t,
                        'generator': {'scenario': p['scenario'], 'sent': sent, 'bytes': sent * 60, 'pps': sent}})
    loads = ['+'.join(load) for load in DAEMON_LOADS]
    for s in range(1, 7):
        records.append({'kind': 'daemon', 't': s, 'load': loads[(s - 1) // 3], 'rss_kib': 200 << 10,
                        'hwm_kib': 210 << 10, 'threads': 35, 'utime_s': s * 0.5, 'stime_s': s * 0.1})
    generators = [{'scenario': s, 'sent': 1_000_000, 'bytes': 60_000_000} if s != 'bulk'
                  else {'scenario': s, 'bytes': 1 << 30} for load in DAEMON_LOADS for s in load]
    if case == 'daemon-idle':
        generators[0] = {'error': 'exit 1: OSError: [Errno 100] Network is down'}
    records.append({'kind': 'daemon_end', 'seconds': 6, 'loads': loads, 'packet_sockets': 1,
                    'packet_sockets_end': 0 if case == 'daemon-lost-capture' else 1,
                    'panicked': case == 'daemon-panic', 'alive_at_end': True, 'exit': 0, 'generators': generators})
    records.append({'kind': 'end', 'errors': []})
    return records


def self_test():
    """Each case's records go through a JSONL file and load() as a run's do."""
    cases = {'pass': [], 'plateau': ['plateau'], 'ceiling': ['hwm'], 'no-super-frames': ['super_frames'],
             'held': ['held_bytes'], 'stall': ['sampled'], 'slow-frames': ['frame_p99'],
             'pps-floor': ['pps_floor'], 'nothing-sent': ['generator'], 'nothing-decoded': ['decoded'],
             'daemon-idle': ['daemon_load'], 'daemon-panic': ['daemon_panic'],
             'daemon-lost-capture': ['daemon_capture']}
    with tempfile.TemporaryDirectory(prefix='nw-flood-self-test-') as tmp:
        for case, expect in cases.items():
            path = pathlib.Path(tmp) / f'{case}.jsonl'
            path.write_text(''.join(json.dumps(r) + '\n' for r in canned(case)))
            # 180k decoded pps in the canned lines: 4 x 200k puts it below the floor.
            calibration = {s: 4 * 200_000 for s in SCENARIOS} if case == 'pps-floor' else None
            summary = summarise(load(path), calibration)
            failed = [g['gate'] for g in summary['gates'] if not g['passed']]
            assert failed == expect, f'{case}: expected {expect or "no"} failures, got {failed}: {summary["gates"]}'
            assert summary['passed'] == (not expect), case
            print(f'self-test {case}: fails {failed or "nothing"}, as it should', flush=True)
    # A run that dies before its last phase fails on that alone.
    records = [r for r in canned('pass') if r['kind'] != 'end' and not (r['kind'] == 'phase' and r['cycle'] is None)]
    failed = [g['gate'] for g in summarise(records)['gates'] if not g['passed']]
    assert {'run', 'generator', 'sampled'} <= set(failed), failed
    print('self-test cut-short: fails run, generator and sampled, as it should', flush=True)
    # A phase's first line records the end of the phase before it. The
    # phase's own figures leave it out, and the gates still read it.
    records = canned('pass')
    phase = next(r for r in records if r['kind'] == 'phase' and r['name'] == 'c2-replay')
    first = next(r for r in records if r['kind'] == 'driver' and r['t'] == phase['start_t'])
    first.update(rss_kib=345 << 10, max_frame=65_226, frame_ms={v: [9.6] for v in VIEWS})
    summary = summarise(records)
    stats = next(p for p in summary['phases'] if p['name'] == 'c2-replay')
    figures = stats['rss_max_mib'], stats['max_frame_max'], stats['frame_ms']['stats']['max']
    assert figures == (304.0, 1514, 3.0), f'c2-replay counted the line before it: {figures}'
    assert summary['frame_ms']['stats']['max'] == 9.6, summary['frame_ms']
    print('self-test phase-figures: leave out the line before the phase, as they should', flush=True)
    # --summarise gates on the ceiling the run recorded, unless told another.
    records = canned('pass')
    records[0]['ceiling_mib'] = 600
    for r in records:
        if r['kind'] == 'driver':
            r['hwm_kib'] = 550 << 10
    with tempfile.TemporaryDirectory(prefix='nw-flood-self-test-') as tmp:
        path = pathlib.Path(tmp) / 'ceiling.jsonl'
        path.write_text(''.join(json.dumps(r) + '\n' for r in records))
        for extra, code in [([], 0), (['--ceiling-mib', '512'], 1)]:
            done = subprocess.run([sys.executable, '-I', os.path.abspath(__file__), '--summarise', path,
                                   '--out', pathlib.Path(tmp) / 'ceiling.json', *extra], capture_output=True, text=True)
            assert done.returncode == code, f'--summarise {extra}: exit {done.returncode}\n{done.stdout}{done.stderr}'
    print('self-test summarise-ceiling: gates on the recorded 600 MiB, or on --ceiling-mib, as it should', flush=True)
    # flood.py's churn and replay send each cycle from addresses no other
    # cycle uses, so cycle 2 is new flows to every table. Importing it would
    # otherwise leave a __pycache__ in the tree.
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('flood', FLOOD)
    flood = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(flood)
    for name in ('udp-churn', 'syn-churn', 'replay'):
        pairs = [addresses(f for batch in itertools.islice(flood.SCENARIOS[name](cycle), 64) for f in batch)
                 for cycle in (1, 2)]
        assert pairs[0] and not pairs[0] & pairs[1], f'{name}: cycles 1 and 2 share {len(pairs[0] & pairs[1])} address pairs'
    print('self-test cycles: churn and replay send each cycle from new addresses, as they should', flush=True)
    # A daemon that dies mid-phase stays a zombie until poll() reaps it, and
    # a zombie has no VmRSS to sample.
    p = subprocess.Popen(['true'])
    while pathlib.Path(f'/proc/{p.pid}/stat').read_text().rpartition(')')[2].split()[0] != 'Z':
        time.sleep(0.01)
    sample = proc_sample(p.pid, os.sysconf('SC_CLK_TCK'))
    p.wait()
    assert sample is None, f'a zombie sampled as {sample}'
    print('self-test zombie: samples as gone, as it should', flush=True)


def addresses(frames):
    """The source and destination addresses of each IPv4 or IPv6 frame."""
    spans = {b'\x08\x00': slice(26, 34), b'\x86\xdd': slice(22, 54)}
    return {frame[spans[frame[12:14]]] for frame in frames if frame[12:14] in spans}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument('--smoke', action='store_true', help='20 s a scenario, 10 s a paced rate, 30 s of daemon')
    mode.add_argument('--summarise', metavar='JSONL', help='gate a saved flood-soak.jsonl again')
    mode.add_argument('--self-test', action='store_true', help='run the gates against canned lines')
    ap.add_argument('--minutes', type=int, default=60, help='both cycles together (default %(default)s)')
    ap.add_argument('--paced-seconds', type=int, help='all paced rates together (default 300, smoke 20)')
    ap.add_argument('--daemon-seconds', type=int, help='both daemon loads together; 0 skips the daemon (default 600, smoke 30)')
    ap.add_argument('--scenarios', default=','.join(SCENARIOS), help='comma-separated, from %(default)s')
    ap.add_argument('--ceiling-mib', type=int, help=f'VmHWM gate (default {CEILING_MIB}, or with --summarise '
                    'the ceiling that run recorded)')
    ap.add_argument('--calibration', metavar='JSON', help='an earlier flood-soak.json: each scenario must '
                    f'decode at least {PPS_FLOOR * 100:.0f}%% of the pps it did there')
    ap.add_argument('--geoip-db', metavar='MMDB', help='Country (or City) database to load')
    ap.add_argument('--geoip-asn-db', metavar='MMDB', help='ASN database to load')
    ap.add_argument('--tcpreplay', metavar='PCAP', help='send the replay scenario with tcpreplay')
    ap.add_argument('--out', default='flood-soak.json', help='the summary (default %(default)s); the raw '
                    'lines go beside it as .jsonl')
    ap.add_argument('--artifacts', metavar='DIR', help="keep the driver's and the daemon's stderr here")
    ap.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return
    calibration = calibration_from(args.calibration) if args.calibration else None
    out = pathlib.Path(args.out)
    if args.summarise:
        summary = summarise(load(args.summarise), calibration, args.ceiling_mib)
        out.write_text(json.dumps(summary, indent=1) + '\n')
        report(summary)
        sys.exit(0 if summary['passed'] else 1)
    args.ceiling_mib = args.ceiling_mib or CEILING_MIB
    args.scenarios = [s for s in args.scenarios.split(',') if s]
    assert set(args.scenarios) <= set(SCENARIOS), f'scenarios are {SCENARIOS}'
    args.phase_seconds = 20 if args.smoke else args.minutes * 60 // (CYCLES * len(args.scenarios))
    if args.paced_seconds is None:
        args.paced_seconds = 20 if args.smoke else 300
    if args.daemon_seconds is None:
        args.daemon_seconds = 30 if args.smoke else 600
    if not args.inside:
        for binary in (DRIVER, NETWATCH):
            assert binary.exists(), f'{binary}: cargo build --release --example flood_soak --bin netwatch'
        argv = ['unshare', '--user', '--map-root-user', '--net', '--mount', sys.executable,
                os.path.abspath(__file__), *sys.argv[1:], '--inside']
        os.execvp(argv[0], argv)
    # Unwind through Lab.__exit__ on a plain kill too, so the peer namespace's
    # sleeper, the sink and the generators go with this process.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    if args.artifacts:
        args.artifacts = pathlib.Path(args.artifacts)
        args.artifacts.mkdir(parents=True, exist_ok=True)
    jsonl = out.with_suffix('.jsonl')
    lock = threading.Lock()
    with open(jsonl, 'w') as f:
        def log(record):
            with lock:
                f.write(json.dumps(record) + '\n')
                f.flush()
        run(args, log)
    summary = summarise(load(jsonl), calibration, args.ceiling_mib)
    out.write_text(json.dumps(summary, indent=1) + '\n')
    report(summary)
    sys.exit(0 if summary['passed'] else 1)


if __name__ == '__main__':
    main()
