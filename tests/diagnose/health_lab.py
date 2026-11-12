#!/usr/bin/env python3
"""Drives examples/diagnose_lab, the real App::tick, against a namespace network
with faults staged on purpose, and asserts what the engine opens and closes.

  python3 tests/diagnose/health_lab.py --quick [--out FILE] [--artifacts DIR]
  python3 tests/diagnose/health_lab.py --long | --scenario NAME [NAME ...]

run each scenario (SCENARIOS below) in its own unshare --user --map-root-user
--net --mount, all in parallel, and write every open and close time to FILE
(health-lab.json). --quick is the smoke and every scenario but the long
negatives, which --long runs. --artifacts keeps each run's JSON lines and the
episodes it recorded. The smoke alone runs inside namespaces the caller made:

  unshare --user --map-root-user --net --mount python3 tests/diagnose/health_lab.py --smoke

Each namespace run builds a network whose addresses are the ones the health
prober uses on a real host:

  this namespace   nw0 192.0.2.1/24, default via 192.0.2.2
  gw               192.0.2.2/24 (gateway and resolver), 198.51.100.1/30, forwarding
  inet             198.51.100.2/30, and 1.1.1.1/32 on lo (internet probe, DNS
                   reference, trace target)

The prober's targets are fixed: the internet probe and the DNS reference are
both 1.1.1.1, and the resolver comes from /etc/resolv.conf. So a peer namespace
owns 1.1.1.1, a resolv.conf naming 192.0.2.2 is mounted in place of the real
one, and sysfs is remounted, because inside a user namespace /sys/class/net
otherwise lists the host's interfaces. No host setting changes: the mounts,
addresses, sysctls and qdiscs all live in namespaces that end with the run.
Requires ip, tc (with sch_netem, sch_prio and cls_u32 loadable), nsenter,
unshare and mount.
"""
import argparse, json, os, pathlib, re, shutil, signal, socket, struct, subprocess, sys, tempfile, threading, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / 'target/debug/examples/diagnose_lab'
# Past a run's own length. A tick that hangs would otherwise hold the lab,
# and the CI runner under it, until something outside gives up.
GRACE_SECS = 60
GATEWAY = '192.0.2.2'
INTERNET = '1.1.1.1'
# Wide enough that a busy CI runner's jitter stays under 3σ, narrow enough
# that the faults the scenarios stage (tens of ms and up) clear it.
SEED = {
    'gateway.rtt': {'mean': 1.0, 'sigma': 2.0},
    'dns.rtt_p50': {'mean': 2.0, 'sigma': 3.0},
    'path.rtt': {'mean': 2.0, 'sigma': 3.0},
}
# Samples the driver credits a seeded baseline (lab.rs SEED_SAMPLES).
SEED_SAMPLES = 2400
# lab.rs CORE_RULES: the coverage rows each line carries.
CORE_RULES = ['link.down', 'gateway.unreachable', 'gateway.rtt_spike', 'path.rtt_spike',
              'dns.failing', 'dns.slow_resolver']
# Healthy seconds on seeded baselines before a scenario's fault goes in.
WARMUP_SECS = 15
# Seconds a scenario keeps running after its last expected close, so an issue
# that reopens at once is seen doing it.
SETTLE_SECS = 15
# The health probes' cadence. A row that expects nothing judges its rules'
# inputs from one cycle after the fault goes in.
PROBE_SECS = 5
# lab.rs state_name: the states in which an issue is still open.
OPEN = {'open', 'acked', 'muted'}
# The namespace each device a fault can name lives in, as a Lab attribute.
DEVICES = {'nw0': None, 'gw0': 'gw', 'gw1': 'gw', 'inet0': 'inet'}

# The scenarios, as data: a B-item that moves a rule's timing changes a row,
# not code. Opens count from the fault, closes from the clear, in seconds.
# `*_expect_s` is what today's rules should take, worked out from them and
# checked against runs rather than tuned to pass, and every window is at least
# twice it (check_table):
# - an issue opens after consecutive_n = 3 distinct samples of its probe. The
#   health probes run every 5 s, but a cycle whose probes time out runs long
#   and the next waits for it: about 10 s apart while the resolver drops
#   everything, about 25 s while nothing answers at all (3 ICMP and 9 TCP
#   connect timeouts to the gateway alone). Traces run every 30 s;
# - the DNS p50 is a rolling median over the whole probe history
#   (diagnose/live.rs `dns`), so a slow phase opens only once it outnumbers
#   the healthy samples and closes only once they outnumber it again;
# - a close waits out the rule's verify hold (rules.rs `default_verify`),
#   counted from its first healthy sample.
#
#   fault, clear   what goes in after WARMUP_SECS, and what takes it out
#   fault_secs     how long the fault holds; with clear_on_open, at most that
#                  long, clearing once every expected open has been seen
#   expect_open    rules that must open under the fault, each within the
#                  row's open window or its own. With suppressed_by, the rule
#                  must be listed under that one whenever both are open, and
#                  must be seen so at least once
#   under          {family: root}: whenever root is open, every open issue in
#                  the family ('dns.*', or one rule) must be listed under it
#   expect_close   rules that must close after the clear and stay closed, each
#                  within the row's close window or its own
#   forbid         rules that must never be listed, in any state; '*' is all.
#                  In a row that expects nothing to open, each forbidden core
#                  rule must also have been available on every fault tick
#                  past the first probe cycle
#   quick          in --quick; the rest are the weekly long negatives
#   asserted       False: measured and reported, never failed on
SCENARIOS = [
    {'name': 'L-DNS-SLOW',
     'fault': [('dns', 'gw', 'delay:300')], 'fault_secs': 60, 'clear': [('dns', 'gw', 'ok')],
     # 3 healthy samples, so the 4th slow one moves the median; 3 to confirm.
     'expect_open': [{'rule': 'dns.slow_resolver'}], 'open_within_s': 60, 'open_expect_s': 30,
     # 12 slow samples need 10 healthy ones to lose the median (50 s), then
     # the 60 s hold.
     'expect_close': [{'rule': 'dns.slow_resolver'}], 'close_within_s': 220, 'close_expect_s': 110,
     'forbid': ['dns.failing', 'gateway.unreachable', 'gateway.rtt_spike', 'path.rtt_spike',
                'link.down']},
    {'name': 'L-DNS-DOWN',
     'fault': [('dns', 'gw', 'drop:100')], 'fault_secs': 60, 'clear': [('dns', 'gw', 'ok')],
     # Two silent cycles are 6 unanswered queries of the 15 or so sent, which
     # opens it; cycles run about 10 s apart while nothing answers.
     'expect_open': [{'rule': 'dns.failing'}], 'open_within_s': 40, 'open_expect_s': 20,
     # dns.failing holds its verify for 120 s.
     'expect_close': [{'rule': 'dns.failing'}], 'close_within_s': 250, 'close_expect_s': 125,
     'forbid': ['dns.slow_resolver', 'gateway.unreachable', 'gateway.rtt_spike',
                'path.rtt_spike', 'link.down']},
    # dns.failing judges the last 60 queries: it opens once 5 are unanswered
    # and the share's lower confidence bound is over 5%. At 20% loss and 3
    # queries every 5 s the fifth loss comes about 25 queries in, 40 s or so,
    # but runs have taken 37 s and 79 s; by 120 s fewer than one in 500 has
    # not seen five. The close is the rule's 120 s hold, starting within four
    # clean cycles of the clear.
    {'name': 'L-DNS-LOSSY',
     'fault': [('dns', 'gw', 'drop:20')], 'fault_secs': 180, 'clear': [('dns', 'gw', 'ok')],
     'expect_open': [{'rule': 'dns.failing'}], 'open_within_s': 120, 'open_expect_s': 60,
     'expect_close': [{'rule': 'dns.failing'}], 'close_within_s': 250, 'close_expect_s': 125,
     'forbid': []},
    # Total loss, per decision D2, until gateway.loss exists. Nothing answers,
    # so samples come about 25 s apart and the first lands up to 20 s in.
    # That is close to the 30 s a gateway sample stays fresh (engine.rs
    # `observe_live_at`): on a runner a few seconds slower the observation
    # lapses between samples and the confirmation starts over.
    {'name': 'L-GW-DOWN',
     'fault': [('netem', 'nw0', 'loss 100%')], 'fault_secs': 130, 'clear_on_open': True,
     'clear': [('netem', 'nw0', None)],
     'expect_open': [{'rule': 'gateway.unreachable'},
                     {'rule': 'dns.failing', 'suppressed_by': 'gateway.unreachable'}],
     'open_within_s': 130, 'open_expect_s': 65,
     'under': {'dns.*': 'gateway.unreachable'},
     # The cycle in flight at the clear still times out, then the 60 s hold.
     'expect_close': [{'rule': 'gateway.unreachable'}], 'close_within_s': 140, 'close_expect_s': 70,
     'forbid': ['link.down', 'gateway.rtt_spike', 'path.rtt_spike']},
    # ICMP only, so DNS stays fast and only the gateway's answers slow. The
    # trace's answers are ICMP too, so path.rtt_spike opens as well, after 3
    # traces, and must be listed under the gateway.
    {'name': 'L-GW-RTT',
     'fault': [('netem-icmp', 'gw0', 'delay 40ms')], 'fault_secs': 180, 'clear_on_open': True,
     'clear': [('netem-icmp', 'gw0', None)],
     'expect_open': [{'rule': 'gateway.rtt_spike', 'within_s': 30, 'expect_s': 15},
                     {'rule': 'path.rtt_spike', 'suppressed_by': 'gateway.rtt_spike'}],
     'open_within_s': 180, 'open_expect_s': 90,
     # The gateway's next sample, then its 120 s hold; the path's close, as in
     # L-PATH-SPIKE, waits on traces and outlasts it.
     'expect_close': [{'rule': 'gateway.rtt_spike'},
                      {'rule': 'path.rtt_spike', 'within_s': 360, 'expect_s': 180}],
     'close_within_s': 250, 'close_expect_s': 125,
     'forbid': ['dns.slow_resolver', 'dns.failing', 'gateway.unreachable', 'link.down']},
    # Against the seeded `internet` baseline: the trace target has none of its own.
    {'name': 'L-PATH-SPIKE',
     'fault': [('netem', 'gw1', 'delay 80ms')], 'fault_secs': 180, 'clear_on_open': True,
     'clear': [('netem', 'gw1', None)],
     'expect_open': [{'rule': 'path.rtt_spike'}], 'open_within_s': 180, 'open_expect_s': 90,
     # 2 trace intervals plus the 120 s hold, doubled.
     'expect_close': [{'rule': 'path.rtt_spike'}], 'close_within_s': 360, 'close_expect_s': 180,
     'forbid': ['dns.slow_resolver', 'dns.failing', 'gateway.unreachable', 'gateway.rtt_spike',
                'link.down']},
    {'name': 'L-HEALTHY',
     'fault': [('netem', 'nw0', 'delay 1ms 0.3ms')], 'fault_secs': 300,
     'clear': [('netem', 'nw0', None)],
     'expect_open': [], 'expect_close': [], 'forbid': ['*']},
    {'name': 'L-DNS-QUIET-LOSS', 'quick': False,
     'fault': [('dns', 'gw', 'drop:1')], 'fault_secs': 1200, 'clear': [('dns', 'gw', 'ok')],
     'expect_open': [], 'expect_close': [], 'forbid': ['dns.failing']},
]

# A resolver that answers the two questions the prober asks: `.` NS (the RTT
# probe) and `dns.google` A (the cross-check, with the answer set the real one
# has, so the two resolvers agree). Each query is answered on its own thread,
# so a delayed answer does not hold up the next. The mode file is read per
# query: ok, delay:<ms>, drop:<pct> or servfail.
RESPONDER = r'''
import pathlib, random, socket, struct, sys, threading, time
addr, mode, tcp_ports = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3:]
ANSWERS = {'dns.google': ['8.8.8.8', '8.8.4.4']}
def qname(buf, i):
    labels = []
    while buf[i]:
        labels.append(buf[i + 1:i + 1 + buf[i]].decode('ascii', 'replace'))
        i += 1 + buf[i]
    return '.'.join(labels).lower(), i + 1
def answer(sock, q, src):
    m = mode.read_text().strip()
    if m.startswith('drop:') and random.uniform(0, 100) < float(m[5:]):
        return
    if m.startswith('delay:'):
        time.sleep(float(m[6:]) / 1000)
    qid, _, _, _, _, ar = struct.unpack('>6H', q[:12])
    name, i = qname(q, 12)
    qtype = struct.unpack('>H', q[i:i + 2])[0]
    end = i + 4
    # DO in the OPT record: answer as a validating resolver would, with AD.
    dnssec = ar and q[end:end + 3] == b'\x00\x00\x29' and q[end + 7] & 0x80
    rcode, records = 0, []
    if m == 'servfail':
        rcode = 2
    elif name == '' and qtype == 2:
        ns = b''.join(bytes([len(l)]) + l.encode() for l in 'a.root-servers.net'.split('.')) + b'\0'
        records.append(struct.pack('>HHHIH', 0xc00c, 2, 1, 3600, len(ns)) + ns)
    elif name in ANSWERS:
        if qtype == 1:
            for ip in ANSWERS[name]:
                records.append(struct.pack('>HHHIH', 0xc00c, 1, 1, 300, 4) + socket.inet_aton(ip))
    elif name != '':
        rcode = 3
    flags = 0x8180 | (0x20 if dnssec and rcode == 0 else 0) | rcode
    sock.sendto(struct.pack('>6H', qid, flags, 1, len(records), 0, 0) + q[12:end] + b''.join(records), src)
def dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, 53))
    while True:
        q, src = s.recvfrom(1500)
        if len(q) > 12:
            threading.Thread(target=answer, args=(s, q, src), daemon=True).start()
def tcp(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((addr, int(port)))
    s.listen(64)
    while True:
        s.accept()[0].close()
for port in tcp_ports:
    threading.Thread(target=tcp, args=(port,), daemon=True).start()
dns()
'''


def cmd(*args, ns=None, check=True):
    prefix = ['nsenter', '-t', str(ns), '-n'] if ns else []
    return subprocess.run(prefix + list(map(str, args)), check=check, capture_output=True, text=True)


def ip(*args, **kw):
    return cmd('ip', *args, **kw)


def sysctl(key, value, ns=None):
    cmd('sh', '-c', f'echo "{value}" > /proc/sys/{key.replace(".", "/")}', ns=ns)


class Lab:
    """The namespaces, the resolvers and a temp home, torn down on exit."""

    def __init__(self):
        self.children = []
        self.tmp = None

    def __enter__(self):
        try:
            self.isolate()
            self.topology()
            self.services()
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
        assert os.geteuid() == 0, 'run with unshare --user --map-root-user --net --mount'
        # Protect against mistakenly executing as real root in the host namespace.
        assert pathlib.Path('/proc/self/uid_map').read_text().split()[1] != '0', 'isolated user namespace required'
        # Only possible in a mount namespace this user namespace owns, so a
        # sysfs that mounts is also proof the host's /sys is untouched.
        mounted = cmd('mount', '-t', 'sysfs', 'sysfs', '/sys', check=False)
        assert mounted.returncode == 0, f'{mounted.stderr.strip()}: a mount namespace is required (unshare --mount)'
        assert os.listdir('/sys/class/net') == ['lo'], os.listdir('/sys/class/net')
        self.tmp = tempfile.TemporaryDirectory(prefix='nw-health-')
        self.dir = pathlib.Path(self.tmp.name)
        # The resolver the App reads. realpath: on systemd hosts this is
        # stub-resolv.conf, which systemd-resolved replaces by rename whenever
        # the host's DNS settings change, and a rename over a mount point in
        # another mount namespace unmounts it there. A bind over the file
        # lasted until the host's next rewrite, 13 minutes into one run, and
        # the App then read 127.0.0.53. So the file's directory gets a tmpfs
        # of its own, which also hides resolved's socket from the lab's NSS
        # lookups. Only a resolv.conf directly in /etc is bound as a file:
        # a tmpfs over /etc would hide the rest of it.
        real = pathlib.Path(os.path.realpath('/etc/resolv.conf'))
        text = f'nameserver {GATEWAY}\n'
        if real.parent != pathlib.Path('/etc'):
            cmd('mount', '-t', 'tmpfs', 'tmpfs', real.parent)
            real.write_text(text)
        else:
            conf = self.dir / 'resolv.conf'
            conf.write_text(text)
            cmd('mount', '--bind', conf, real)
        assert pathlib.Path('/etc/resolv.conf').read_text() == text, 'resolv.conf did not take'

    def peer(self):
        p = subprocess.Popen(['unshare', '--net', 'sleep', 'infinity'])
        self.children.append(p)
        mine = os.readlink('/proc/self/ns/net')
        deadline = time.monotonic() + 5
        while os.readlink(f'/proc/{p.pid}/ns/net') == mine:
            assert time.monotonic() < deadline, 'peer namespace did not start'
            time.sleep(0.01)
        return p.pid

    def topology(self):
        self.gw, self.inet = self.peer(), self.peer()
        gw, inet = self.gw, self.inet
        for ns in (None, gw, inet):
            ip('link', 'set', 'lo', 'up', ns=ns)
        ip('link', 'add', 'nw0', 'type', 'veth', 'peer', 'name', 'gw0')
        ip('link', 'set', 'gw0', 'netns', gw)
        ip('link', 'add', 'gw1', 'type', 'veth', 'peer', 'name', 'inet0', ns=gw)
        ip('link', 'set', 'inet0', 'netns', inet, ns=gw)
        for dev, addr, ns in [('nw0', '192.0.2.1/24', None), ('gw0', f'{GATEWAY}/24', gw),
                              ('gw1', '198.51.100.1/30', gw), ('inet0', '198.51.100.2/30', inet)]:
            ip('addr', 'add', addr, 'dev', dev, ns=ns)
            ip('link', 'set', dev, 'up', ns=ns)
        ip('addr', 'add', f'{INTERNET}/32', 'dev', 'lo', ns=inet)
        ip('route', 'add', 'default', 'via', GATEWAY)
        ip('route', 'add', f'{INTERNET}/32', 'via', '198.51.100.2', ns=gw)
        ip('route', 'add', 'default', 'via', '198.51.100.1', ns=inet)
        sysctl('net.ipv4.ip_forward', 1, ns=gw)
        # Every probe and trace hop is an ICMP reply; the default 1/s limit
        # would read as loss.
        for ns in (gw, inet):
            sysctl('net.ipv4.icmp_ratelimit', 0, ns=ns)
        # A fresh namespace refuses unprivileged ICMP sockets, and the kernel
        # rejects a range naming unmapped groups (so not "0 2147483647"
        # here): allow every group this user namespace maps.
        spans = [list(map(int, l.split())) for l in pathlib.Path('/proc/self/gid_map').read_text().splitlines()]
        sysctl('net.ipv4.ping_group_range', f'{min(s[0] for s in spans)} {max(s[0] + s[2] - 1 for s in spans)}')
        names = sorted(os.listdir('/sys/class/net'))
        assert names == ['lo', 'nw0'], f'/sys/class/net lists {names}: sysfs is not this namespace'

    def services(self):
        self.modes = {}
        for name, ns, addr, tcp in [('gw', self.gw, GATEWAY, []), ('inet', self.inet, INTERNET, ['443'])]:
            mode = self.dir / f'dns-{name}.mode'
            mode.write_text('ok')
            self.modes[name] = mode
            self.children.append(subprocess.Popen(
                ['nsenter', '-t', str(ns), '-n', sys.executable, '-c', RESPONDER, addr, str(mode), *tcp]))
        # /proc/net/udp spells a bound address as host-order hex, port 53 as 0035.
        deadline = time.monotonic() + 5
        while not all('%08X:0035' % struct.unpack('=I', socket.inet_aton(addr))[0]
                      in cmd('cat', '/proc/net/udp', ns=ns).stdout
                      for addr, ns in [(GATEWAY, self.gw), (INTERNET, self.inet)]):
            assert time.monotonic() < deadline, 'resolvers did not start'
            time.sleep(0.05)

    def dns_mode(self, name, mode):
        """Set a resolver's behaviour: ok, delay:<ms>, drop:<pct>, servfail."""
        self.modes[name].write_text(mode)

    def stage(self, action):
        """Put one scenario fault in, or take it out.

        ('dns', resolver, mode)        a resolver's mode, as dns_mode
        ('netem', dev, spec)           netem on everything dev sends
        ('netem-icmp', dev, spec)      netem on the ICMP dev sends, the rest untouched
        with spec None to remove the qdisc again."""
        kind, target, spec = action
        if kind == 'dns':
            self.dns_mode(target, spec)
            return
        ns = DEVICES[target] and getattr(self, DEVICES[target])
        if spec is None:
            cmd('tc', 'qdisc', 'del', 'dev', target, 'root', ns=ns)
        elif kind == 'netem':
            cmd('tc', 'qdisc', 'replace', 'dev', target, 'root', 'netem', *spec.split(), ns=ns)
        elif kind == 'netem-icmp':
            # prio's default priomap sends priorities 1, 2, 3 and 5, which a
            # TOS or SO_PRIORITY sets, to band 3 (1:3). This one sends every
            # priority to band 2 (1:2), so only what the filter sends to band
            # 3, ICMP, meets the netem under it.
            cmd('tc', 'qdisc', 'replace', 'dev', target, 'root', 'handle', '1:', 'prio',
                'priomap', *['1'] * 16, ns=ns)
            cmd('tc', 'qdisc', 'add', 'dev', target, 'parent', '1:3', 'handle', '30:', 'netem',
                *spec.split(), ns=ns)
            cmd('tc', 'filter', 'add', 'dev', target, 'parent', '1:', 'protocol', 'ip', 'prio', '1',
                'u32', 'match', 'ip', 'protocol', '1', '0xff', 'flowid', '1:3', ns=ns)
        else:
            raise ValueError(f'unknown fault {action}')

    def make_home(self):
        """The temp home the driver insists on: marked, with every XDG
        directory inside it and a config that records episodes."""
        self.home = self.dir / 'home'
        self.env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(self.home),
                    'TMPDIR': tempfile.gettempdir()}
        for var, sub in [('XDG_CACHE_HOME', '.cache'), ('XDG_CONFIG_HOME', '.config'),
                         ('XDG_STATE_HOME', '.local/state'), ('XDG_DATA_HOME', '.local/share')]:
            (self.home / sub).mkdir(parents=True)
            self.env[var] = str(self.home / sub)
        (self.home / '.netwatch-lab').write_text('')
        config = self.home / '.config/netwatch/config.toml'
        config.parent.mkdir()
        config.write_text('diagnose_record_episodes = true\ninsights_enabled = false\n\n'
                          f'[diagnose_probes]\ntrace_target = "{INTERNET}"\ntrace_refresh_secs = 30\n')
        self.seed = self.dir / 'seed.json'
        self.seed.write_text(json.dumps(SEED))

    def run(self, seconds, env=None, on_line=None, stop=None):
        """Run the driver for `seconds`, returning its JSON lines and stderr.
        `on_line(row)` is called as each tick arrives, which is where a
        scenario changes a fault. Creating `stop` ends the run after the
        tick that sees it, as the end of `seconds` would."""
        extra = ['--stop-file', stop] if stop else []
        with open(self.dir / 'driver.err', 'w+') as stderr:
            # Its own process group, so a kill also reaches any child still
            # holding stdout open, which would otherwise keep the read below
            # waiting after the driver itself is gone.
            p = subprocess.Popen([BIN, '--seconds', str(seconds), '--seed', self.seed, '--jsonl', *extra],
                                 env=env or self.env, stdout=subprocess.PIPE, stderr=stderr, text=True,
                                 start_new_session=True)
            killed = threading.Event()

            def kill():
                killed.set()
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            deadline = threading.Timer(seconds + GRACE_SECS, kill)
            deadline.start()
            try:
                rows = []
                for line in p.stdout:
                    rows.append(json.loads(line))
                    if on_line:
                        on_line(rows[-1])
                p.wait()
            finally:
                deadline.cancel()
                if p.poll() is None:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait()
            stderr.seek(0)
            err = stderr.read()
        assert not killed.is_set(), f'driver still running {seconds + GRACE_SECS}s after it started: {err}'
        assert p.returncode == 0, f'driver exited {p.returncode}: {err}'
        return rows, err


def first(rows, pred):
    return next((r['t'] for r in rows if pred(r)), None)


def smoke(lab, results):
    # The driver itself must refuse a home the lab did not make. The inherited
    # HOME is the real one.
    real = dict(lab.env, HOME=os.environ.get('HOME', '/root'))
    for var in ['XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'XDG_STATE_HOME', 'XDG_DATA_HOME']:
        real.pop(var)
    refused = subprocess.run([BIN, '--seconds', '1', '--jsonl'], env=real, capture_output=True, text=True,
                             timeout=30)
    assert refused.returncode != 0 and not refused.stdout, refused
    results.append({'case': 'driver refuses the real home', 'error': refused.stderr.strip()})
    print(json.dumps(results[-1]), flush=True)

    # A seed it cannot apply is a refusal too: unseeded σ rules only learn, so
    # a scenario that expects nothing to open would pass without judging.
    ip('route', 'del', 'default')
    try:
        unseeded = subprocess.run([BIN, '--seconds', '1', '--seed', lab.seed, '--jsonl'], env=lab.env,
                                  capture_output=True, text=True, timeout=30)
    finally:
        ip('route', 'add', 'default', 'via', GATEWAY)
    assert unseeded.returncode != 0 and not unseeded.stdout, unseeded
    assert 'nothing can be seeded' in unseeded.stderr, unseeded.stderr
    results.append({'case': 'driver refuses a seed it cannot apply', 'error': unseeded.stderr.strip()})
    print(json.dumps(results[-1]), flush=True)

    rows, err = lab.run(60)
    assert len(rows) == 60, len(rows)
    assert f'seeded dns.rtt_p50@{GATEWAY}, gateway.rtt@{GATEWAY}, path.rtt@internet' in err, err
    probes = {
        'gateway': first(rows, lambda r: r['probes']['gateway_target'] == GATEWAY and r['probes']['gateway_rtt_ms'] is not None),
        'dns': first(rows, lambda r: r['probes']['dns_target'] == GATEWAY and r['probes']['dns_rtt_ms'] is not None),
        'internet': first(rows, lambda r: r['probes']['internet_rtt_ms'] is not None),
    }
    for probe, t in probes.items():
        assert t is not None and t <= 10, (probe, t, rows[-1]['probes'])
    for probe in ['gateway_target', 'dns_target']:
        seen = {r['probes'][probe] for r in rows} - {None}
        assert seen == {GATEWAY}, (probe, seen)
    opened = sorted({i['key'] for r in rows for i in r['issues']})
    assert not opened, opened
    # Seeded before the first tick, so no line, the first included, judges
    # against a baseline still learning.
    learning = [(r['t'], c['rule']) for r in rows for c in r['coverage']
                if c['rule'] in ('gateway.rtt_spike', 'path.rtt_spike') and c['status'] == 'learning']
    assert not learning, learning
    # Every core rule has its inputs, and the seeded σ rules are judging.
    last = {c['rule']: c['status'] for c in rows[-1]['coverage']}
    assert list(last) == CORE_RULES, list(last)
    for rule in CORE_RULES:
        assert last[rule] == 'available', (rule, last)
    # Where the run wrote: the seeded baselines, persisted at shutdown, on the
    # network the run ended on. Each seeded entry has learned past its seed,
    # which only happens when the seed's subject is the one the sampler
    # records under; a wrong subject would sit at exactly SEED_SAMPLES.
    saved = json.loads((lab.home / '.cache/netwatch/baselines.json').read_text())
    metrics = saved['networks'][saved['last_network']]['metrics']
    for metric, subject in [('dns.rtt_p50', GATEWAY), ('gateway.rtt', GATEWAY), ('path.rtt', 'internet')]:
        b = metrics.get(f'{subject}\x1f{metric}')
        assert b and b['samples'] > SEED_SAMPLES, (metric, subject, b, sorted(metrics))
    results.append({'case': 'healthy 60s', 'measured_at': probes, 'issues': opened,
                    'coverage': last, 'probes': rows[-1]['probes'], 'verdict': rows[-1]['verdict']})
    print(json.dumps(results[-1]), flush=True)


def is_open(row, rule):
    return any(i['rule'] == rule and i['state'] in OPEN for i in row['issues'])


def catalogue():
    """Every rule id the engine has, from docs/diagnostic-coverage.md: the
    catalogue as rules.rs renders it, which a test keeps in step."""
    text = (ROOT / 'docs/diagnostic-coverage.md').read_text()
    rules = re.findall(r'^(?:### |\| )`([a-z0-9_]+\.[a-z0-9_]+)`', text, re.M)
    count = int(re.search(r'contains \*\*(\d+) rules\*\*', text).group(1))
    assert len(set(rules)) == len(rules) == count, (count, rules)
    return rules


def matches(rule, family):
    """Whether a rule is in a row's family: one rule id, or 'dns.*'."""
    return rule == family or family.endswith('.*') and rule.startswith(family[:-1])


def check_table(scenarios):
    """The table's own rules, checked before anything runs: a window narrower
    than twice what the rule should take is a flake waiting to happen, and a
    misspelt rule would pass by never opening or never being forbidden. Any
    rule in the catalogue can be named, not only the core ones."""
    rules = catalogue()
    assert set(CORE_RULES) <= set(rules), CORE_RULES
    names = [s['name'] for s in scenarios]
    assert len(set(names)) == len(names), names
    for s in scenarios:
        name, opens = s['name'], [e['rule'] for e in s['expect_open']]
        closes = [e['rule'] for e in s['expect_close']]
        for rule in opens + closes + [e['suppressed_by'] for e in s['expect_open']
                                      if 'suppressed_by' in e]:
            assert rule in rules, (name, rule)
        assert all(r == '*' or r in rules for r in s['forbid']), (name, s['forbid'])
        for family, root in s.get('under', {}).items():
            assert any(matches(r, family) for r in rules), (name, family)
            # Otherwise the root might never open, and the check never run.
            assert root in opens, (name, root, 'a root the row does not expect to open')
        assert not set(opens) & set(s['forbid']) and not ('*' in s['forbid'] and opens), name
        assert set(closes) <= set(opens), (name, 'a close needs its open')
        for e in s['expect_open']:
            within, expect = window(s, e, 'open')
            assert within >= 2 * expect, (name, e['rule'], 'open window')
            # The open is judged under the fault, never after it cleared.
            assert s['fault_secs'] >= within, (name, e['rule'], 'fault shorter than its window')
        for e in s['expect_close']:
            within, expect = window(s, e, 'close')
            assert within >= 2 * expect, (name, e['rule'], 'close window')
        assert scenario_secs(s) <= 3600, (name, 'longer than the driver runs')


def window(s, e, kind):
    """An expected open's or close's window and expected time: its own, or
    the row's."""
    return e.get('within_s', s.get(f'{kind}_within_s')), e.get('expect_s', s.get(f'{kind}_expect_s'))


def scenario_secs(s):
    """The longest a scenario can run: the driver's --seconds."""
    close = max((window(s, e, 'close')[0] for e in s['expect_close']), default=0)
    return WARMUP_SECS + s['fault_secs'] + close + SETTLE_SECS


def run_scenario(lab, s):
    """Run one row: warm up, stage the fault, clear it, stop once every close
    has been seen and has held. Returns the JSON lines and the ticks the fault
    went in and came out after."""
    at = {'fault': None, 'clear': None}
    seen = set()
    closed = {}
    stop = lab.dir / 'stop'

    def on_line(r):
        t = r['t']
        if at['fault'] is None:
            if t >= WARMUP_SECS:
                for action in s['fault']:
                    lab.stage(action)
                at['fault'] = t
            return
        if at['clear'] is None:
            for e in s['expect_open']:
                if is_open(r, e['rule']) and ('suppressed_by' not in e or is_open(r, e['suppressed_by'])):
                    seen.add(e['rule'])
            done = s.get('clear_on_open') and len(seen) == len(s['expect_open'])
            if done or t - at['fault'] >= s['fault_secs']:
                for action in s['clear']:
                    lab.stage(action)
                at['clear'] = t
            return
        # A rule that never opened cannot close, and has failed already.
        closes = [e['rule'] for e in s['expect_close']]
        for rule in closes:
            if rule in seen and rule not in closed and not is_open(r, rule):
                closed[rule] = t
        waiting = [rule for rule in closes if rule in seen and rule not in closed]
        if not waiting and t >= max(closed.values(), default=at['clear']) + SETTLE_SECS:
            stop.touch()

    rows, err = lab.run(scenario_secs(s), on_line=on_line, stop=stop)
    assert at['clear'] is not None, f'the run ended before the fault cleared: {err}'
    return rows, err, at['fault'], at['clear']


def evaluate(s, rows, fault_at, clear_at):
    """Every assertion the row makes, as a list of failures, the open and
    close times it measured, and how long a negative row's rules could open."""
    failures = []
    # Anything else is the host's network, and every judgement after it is
    # about the wrong resolver or gateway.
    escaped = first(rows, lambda r: {r['probes']['gateway_target'], r['probes']['dns_target']} - {GATEWAY, None})
    if escaped is not None:
        failures.append(f'the probes left the lab network at {escaped}s')
    listed = {}
    for r in rows:
        for i in r['issues']:
            listed.setdefault(i['key'], r['t'])
    for key, t in sorted(listed.items(), key=lambda kv: kv[1]):
        rule = key.split('|')[0]
        if t <= fault_at:
            failures.append(f'{key} listed at {t}s, before the fault')
        elif '*' in s['forbid'] or rule in s['forbid']:
            failures.append(f'{key} listed at {t}s, {t - fault_at}s into the fault, and is forbidden')
    # A rule whose input is stale or unmeasured cannot open, so a row that
    # expects nothing passes only on ticks where what it forbids was judged.
    judged = {}
    if not s['expect_open']:
        ticks = [r for r in rows if fault_at + PROBE_SECS < r['t'] <= clear_at]
        for rule in [r for r in CORE_RULES if '*' in s['forbid'] or r in s['forbid']]:
            status = [(r['t'], next((c['status'] for c in r['coverage'] if c['rule'] == rule), None))
                      for r in ticks]
            off = [(t, st) for t, st in status if st != 'available']
            judged[rule] = {'available': len(ticks) - len(off), 'ticks': len(ticks)}
            if off:
                failures.append(f'{rule} was {off[0][1]} at {off[0][0]}s, and not available on '
                                f'{len(off)} of {len(ticks)} fault ticks')
    faulted = [r for r in rows if r['t'] > fault_at]
    opened = {}
    for e in s['expect_open']:
        rule = e['rule']
        within, expect = window(s, e, 'open')
        t = first(faulted, lambda r: is_open(r, rule))
        got = opened[rule] = {'after_s': None if t is None else t - fault_at, 'within_s': within,
                              'expect_s': expect}
        if t is None:
            failures.append(f'{rule} never opened')
        elif t - fault_at > within:
            failures.append(f'{rule} opened {t - fault_at}s after the fault, past {within}s')
        root = e.get('suppressed_by')
        if root:
            together = [(r['t'], [i['suppressed_by'] for i in r['issues']
                                  if i['rule'] == rule and i['state'] in OPEN])
                        for r in rows if is_open(r, rule) and is_open(r, root)]
            wrong = [(t, by) for t, by in together if not all(b and b.startswith(root + '|') for b in by)]
            got.update(suppressed_by=root, together_s=len(together))
            if not together:
                failures.append(f'{rule} was never open while {root} was')
            elif wrong:
                failures.append(f'{rule} was not under {root} at {wrong[0][0]}s: {wrong[0][1]}')
    for family, root in s.get('under', {}).items():
        wrong = [(r['t'], i['key'], i['suppressed_by']) for r in rows if is_open(r, root)
                 for i in r['issues'] if i['state'] in OPEN and matches(i['rule'], family)
                 and not (i['suppressed_by'] or '').startswith(root + '|')]
        if wrong:
            failures.append(f'{wrong[0][1]} was not under {root} at {wrong[0][0]}s: {wrong[0][2]}')
    cleared = [r for r in rows if r['t'] > clear_at]
    closed = {}
    for e in s['expect_close']:
        rule = e['rule']
        within, expect = window(s, e, 'close')
        got = closed[rule] = {'after_s': None, 'within_s': within, 'expect_s': expect}
        if opened[rule]['after_s'] is None:
            continue
        if not any(is_open(r, rule) for r in rows if r['t'] == clear_at):
            failures.append(f'{rule} closed while the fault held')
            continue
        t = first(cleared, lambda r: not is_open(r, rule))
        if t is None:
            failures.append(f'{rule} still open {rows[-1]["t"] - clear_at}s after the clear')
            continue
        got['after_s'] = t - clear_at
        if t - clear_at > within:
            failures.append(f'{rule} closed {t - clear_at}s after the clear, past {within}s')
        again = first([r for r in cleared if r['t'] > t], lambda r: is_open(r, rule))
        if again is not None:
            failures.append(f'{rule} reopened {again - clear_at}s after the clear')
    return failures, opened, closed, judged


def timeline(rows):
    """Each issue the run listed: when it opened and closed, and under what."""
    out = {}
    for r in rows:
        for i in r['issues']:
            o = out.setdefault(i['key'], {'opened': None, 'closed': None, 'suppressed_by': []})
            if i['state'] in OPEN:
                if o['opened'] is None:
                    o['opened'] = r['t']
                o['closed'] = None
            elif o['opened'] is not None and o['closed'] is None:
                o['closed'] = r['t']
            if i['suppressed_by'] and i['suppressed_by'] not in o['suppressed_by']:
                o['suppressed_by'].append(i['suppressed_by'])
    return out


def scenario(name, artifacts):
    """One row, inside the namespaces this process was started in."""
    s = next(s for s in SCENARIOS if s['name'] == name)
    with Lab() as lab:
        rows, err, fault_at, clear_at = run_scenario(lab, s)
        failures, opened, closed, judged = evaluate(s, rows, fault_at, clear_at)
        episodes = lab.home / '.local/state/netwatch/episodes'
        recorded = sorted(str(p.relative_to(episodes)) for p in episodes.rglob('*.json.gz')) \
            if episodes.is_dir() else []
        # Anything that opened is an incident the recorder keeps, written at
        # the latest by the driver's shutdown, and only under the lab's home.
        if any(r['issues'] for r in rows) and not recorded:
            failures.append('issues opened but no episode was recorded under the lab home')
        if artifacts:
            keep = pathlib.Path(artifacts) / name
            keep.mkdir(parents=True, exist_ok=True)
            (keep / 'lab.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
            (keep / 'driver.err').write_text(err)
            if recorded:
                shutil.copytree(episodes, keep / 'episodes', dirs_exist_ok=True)
    return {'scenario': name, 'asserted': s.get('asserted', True), 'passed': not failures,
            'failures': failures, 'fault': s['fault'], 'fault_at': fault_at, 'clear_at': clear_at,
            'ended_at': rows[-1]['t'], 'open': opened, 'close': closed, 'judged': judged,
            'issues': timeline(rows), 'episodes': recorded}


def orchestrate(names, smoke, out, artifacts):
    """Each scenario, and the smoke, in its own namespaces and all at once;
    then one file with every result."""
    check_table(SCENARIOS)
    assert BIN.exists(), f'{BIN}: cargo build --example diagnose_lab'
    base = ['unshare', '--user', '--map-root-user', '--net', '--mount', sys.executable,
            os.path.abspath(__file__)]
    jobs = {name: (base + ['--run', name] + (['--artifacts', artifacts] if artifacts else []),
                   scenario_secs(next(s for s in SCENARIOS if s['name'] == name)))
            for name in names}
    if smoke:
        jobs['smoke'] = (base + ['--smoke'], 60)
    if artifacts:
        pathlib.Path(artifacts).mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    done = {}

    def run(name):
        argv, secs = jobs[name]
        # Its own session, so a timeout reaches the peer namespaces and the
        # resolvers too, not only unshare.
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             start_new_session=True)
        try:
            # Past the driver's own deadline, which should always fire first.
            stdout, stderr = p.communicate(timeout=secs + 2 * GRACE_SECS)
            lines, code = stdout.strip().splitlines(), p.returncode
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate()
            lines, code, stderr = [], None, f'killed after {secs + 2 * GRACE_SECS}s'
        try:
            result = json.loads(lines[-1])
        except (IndexError, ValueError):
            result = {'scenario': name, 'asserted': True, 'passed': False,
                      'failures': [f'no result; exit {code}'], 'stderr': str(stderr)[-4000:]}
        if name == 'smoke':
            result = {'scenario': 'smoke', 'asserted': True, 'passed': code == 0,
                      'failures': [] if code == 0 else [str(stderr)[-4000:]], 'results': result.get('results')}
        elif code != 0 and result.get('passed'):
            result.update(passed=False, failures=[f'exit {code}: {str(stderr)[-4000:]}'])
        result['wall_s'] = round(time.monotonic() - started)
        done[name] = result
        verdict = 'reported' if not result['asserted'] else 'pass' if result['passed'] else 'FAIL'
        print(json.dumps({'scenario': name, 'verdict': verdict, 'wall_s': result['wall_s'],
                          'open': result.get('open'), 'close': result.get('close'),
                          'failures': result['failures']}), flush=True)

    threads = [threading.Thread(target=run, args=(name,)) for name in jobs]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    results = [done[name] for name in jobs]
    passed = all(r['passed'] for r in results if r['asserted'])
    report = {'passed': passed, 'wall_s': round(time.monotonic() - started), 'scenarios': results}
    pathlib.Path(out).write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps({'passed': passed, 'wall_s': report['wall_s'], 'out': out}), flush=True)
    return passed


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--smoke', action='store_true',
                      help='inside namespaces: 60 s healthy, probes measured, nothing opens')
    mode.add_argument('--quick', action='store_true', help='the smoke and every quick scenario')
    mode.add_argument('--long', action='store_true', help='the long negatives the weekly job runs')
    mode.add_argument('--scenario', nargs='+', metavar='NAME', choices=[s['name'] for s in SCENARIOS])
    mode.add_argument('--run', metavar='NAME', help=argparse.SUPPRESS)
    ap.add_argument('--out', default='health-lab.json', help='where the results go (default %(default)s)')
    ap.add_argument('--artifacts', metavar='DIR', help="keep each run's JSON lines and episodes here")
    args = ap.parse_args()
    if args.smoke or args.run:
        assert BIN.exists(), f'{BIN}: cargo build --example diagnose_lab'
        # Unwind through Lab.__exit__ on a plain kill too, so the peer
        # namespaces' sleepers and the resolvers go with this process.
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    if args.smoke:
        results = []
        with Lab() as lab:
            smoke(lab, results)
        print(json.dumps({'passed': len(results), 'results': results}), flush=True)
    elif args.run:
        result = scenario(args.run, args.artifacts and os.path.abspath(args.artifacts))
        print(json.dumps(result), flush=True)
        sys.exit(0 if result['passed'] or not result['asserted'] else 1)
    else:
        names = ([s['name'] for s in SCENARIOS if s.get('quick', True)] if args.quick
                 else [s['name'] for s in SCENARIOS if not s.get('quick', True)] if args.long
                 else args.scenario)
        artifacts = args.artifacts and os.path.abspath(args.artifacts)
        sys.exit(0 if orchestrate(names, args.quick, args.out, artifacts) else 1)


if __name__ == '__main__':
    main()
