# NetWatch threat model

This describes the 0.39 implementation so far: the wave-1 capability and WHOIS
fixes, the parser and capture roles, and capture authority. It is a
containment inventory, not a guarantee against arbitrary code execution. Linux non-root capability-based operation is preferred. Running
as root works, but containment is limited; the sandbox is defence in depth.
See [the restricted-group setup](REFERENCE.md#running-without-sudo-linux) and
[reporting policy](../SECURITY.md).

## Run modes and assets

TUI and daemon startup install worker policy, start resources, restrict the main
thread, and then audit every thread's capabilities. Capture opens its device
before entry. Early CLI dispatch can return
before policy installation, so a file-reading subcommand must not be assumed
sandboxed. Strict startup rejects required entry failures; best-effort reports
degradation. Disabled mode installs no restrictions. See
[main](../src/main.rs#L20), [bootstrap](../src/runtime/bootstrap.rs#L1), and
[worker lifecycle](../src/sandbox/worker.rs#L1).

Assets include capture payloads and TLS key material, process identities, DNS and
peer history, diagnostic episodes, local configuration, export files, credentials
for remote publishing, and the host's capture and eBPF privileges. These cross
collector, UI, persistence and optional outbound-service interfaces; see
[packet capture](../src/collectors/packets/mod.rs#L1),
[remote publishing](../src/remote/mod.rs#L1), and
[episode storage](../src/diagnose/episode.rs#L1).

## Adversaries and boundaries

| Adversary | Input or authority |
| --- | --- |
| T1 Network peer | Arbitrary packet bytes, names and protocol fields |
| T2 Local unprivileged user | Process names, local traffic, accessible files |
| T3 File supplier | Episodes, databases, keylogs and configuration |
| T4 Network intermediary | DNS replies and unauthenticated HTTP services |
| T5 Remote service | WHOIS, GeoIP, Insights or ingestion responses |
| T6 Dependency/build compromise | Crates, actions, tool downloads, release credentials |
| T7 Already-root attacker | Outside the host-protection promise |

The boundaries are B1 packet decoding, B2 kernel/FFI collection, B3 input files,
B4 terminal rendering, B5 persistence/export, B6 outbound services, B7 per-thread
sandbox entry, and B8 build/release distribution. These are different interfaces,
not isolated address spaces. The input inventory below names their implementation.

## Linux policy

Every confined thread takes a filesystem layer. Parser and capture threads stack
a second layer on it; main and the network workers do not
([roles](../src/sandbox/roles.rs#L47)). The network workers are reverse DNS,
WHOIS, online GeoIP, health, traceroute, Insights, remote publishing, the three
Diagnose probe workers and the runtime's blocking pool. Every other worker is a
parser, and so is any worker name missing from the table. Main keeps the network
because it starts network workers after its own entry, and a thread keeps every
layer it inherits.

The second layer has no rules, so it denies everything it handles. That is TCP
bind and connect (`parser-net`, Linux 6.7), and connecting to an abstract Unix
socket or signalling a process outside the thread's domain (`parser-scope`, Linux
6.12). Signals are scoped only on a kernel that reports the erratum 2 fix. The
layer also denies connecting to a pathname Unix socket (`parser-fs`, Linux 7.1).
Capture's layer also handles every filesystem right and takes only the read rows
of the grants table, so the capture thread can write nothing. Strict mode requires
the TCP part and refuses to start below ABI 4; best-effort logs one line and runs
without it. The other parts are taken where the kernel has them, so these numbers
alone do not establish what a kernel enforced. There is no seccomp filter. See
[ruleset construction](../src/sandbox/linux.rs#L466) and
[layer entry](../src/sandbox/linux.rs#L682).

```text
<!-- policy:abi -->
filesystem: V4
parser-net: V4
parser-scope: V6
parser-fs: ResolveUnix
<!-- /policy:abi -->
```

Capability removals are verified in the Effective, Permitted, Inheritable and
Ambient sets. The first row is dropped on every confined thread, the second is
additional in strict mode, and the third is additional on parser and capture
threads in every mode. The fourth is additional on main and the network workers
in sessions that never reopen capture: the daemon, `diagnose run`, `diagnose
coverage` and every strict session. A best-effort TUI, the demo included, leaves
it on them so `c`, `i` and `Shift+R` can reopen capture, though network workers
that start before the session is known still drop it. The BPF load worker
temporarily retains the fifth row. Threads that never enter drop capabilities
themselves: the proc broker keeps only what it started with from the sixth row,
and the TUI's shutdown-deadline thread and a capture thread whose device failed
to open keep nothing. This is a deny-list, not a complete root allow-list. See
[capability policy](../src/sandbox/linux.rs#L45),
[capture authority](../src/sandbox/mod.rs#L71) and
[broker entry](../src/sandbox/worker.rs#L1).

After main enters, startup reads every thread's four sets from
`/proc/self/task/*/status`. A thread holding CAP_NET_ADMIN, or CAP_NET_RAW in a
session that drops it, gets a warning naming it and its thread id, and strict
refuses to start ([audit](../src/sandbox/audit.rs#L1)). The audit runs once; a
thread started later from one that holds CAP_NET_RAW inherits it unchecked.

```text
<!-- policy:caps -->
default: CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN, CAP_SYS_RAWIO, CAP_SYS_MODULE, CAP_SYS_BOOT, CAP_SYS_TIME, CAP_SYS_PACCT, CAP_SYS_TTY_CONFIG, CAP_SYSLOG, CAP_WAKE_ALARM, CAP_BLOCK_SUSPEND, CAP_SYS_PTRACE, CAP_KILL, CAP_CHECKPOINT_RESTORE, CAP_IPC_OWNER, CAP_SETUID, CAP_SETGID, CAP_SETPCAP, CAP_SETFCAP, CAP_MKNOD, CAP_SYS_CHROOT, CAP_LINUX_IMMUTABLE, CAP_LEASE, CAP_MAC_ADMIN, CAP_MAC_OVERRIDE, CAP_AUDIT_CONTROL, CAP_AUDIT_WRITE, CAP_AUDIT_READ, CAP_NET_BROADCAST, CAP_NET_ADMIN
strict-extra: CAP_NET_RAW
parser-extra: CAP_NET_RAW
after-open: CAP_NET_RAW
bpf-load: CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN
proc-broker: CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH
<!-- /policy:caps -->
```

The following grants are checked against the rule list the ruleset is built
from, with every optional path supplied. Placeholders are prepared application
directories or exact input files, not literal paths. Missing paths are skipped;
grants are pinned to opened objects. A file replacement requires a new session.
The test also checks that each rule allows what its label says: a read row allows
execute, read-file and read-directory beneath it; the city, ASN and keylog files
allow read-file only; a write row allows every filesystem right the requested ABI
handles, so read access accompanies it. A row that names a file rather than a
directory keeps only the file rights. The worker acceptance test checks the
enforced result: a confined thread cannot open a file beneath the `/proc` read
grant for writing. See [path collection](../src/sandbox/linux.rs#L358),
[access per grant](../src/sandbox/linux.rs#L616) and
[path preparation](../src/sandbox/paths.rs#L1).

```text
<!-- policy:grants -->
read: /proc
read: /sys
read: /bin
read: /sbin
read: /usr
read: /lib
read: /lib64
read: /etc/resolv.conf
read: /etc/hosts
read: /etc/services
read: /etc/nsswitch.conf
read: /etc/host.conf
read: /etc/gai.conf
read: /etc/protocols
read: /etc/passwd
read: /etc/group
read: /etc/os-release
read: /etc/localtime
read: /etc/timezone
read: /etc/ssl
read: /etc/pki
read: /etc/ca-certificates
read: /etc/ld.so.cache
read: /etc/ld.so.conf
read: /etc/ld.so.conf.d
read: /run/systemd/resolve
read: /run/dbus
read: <city-file>
read: <asn-file>
read: <keylog-file>
write: <config>
write: <cache>
write: <state>
write: <exports>
write: <cache>/scratch
write: /dev/null
<!-- /policy:grants -->
```

## What containment does not cover

1. Threads share memory and open descriptors. A per-thread Landlock domain is not
   a process boundary ([worker](../src/sandbox/worker.rs#L1)).
2. ProcBroker stays outside Landlock to scan procfs. Wave 1 limits its capabilities
   to ptrace and DAC read/search; it is still privileged
   ([broker policy](../src/sandbox/linux.rs#L160)).
3. The SDK reader inherits the eBPF worker's layers but keeps its creation-time
   load capabilities; it has no separate entry hook
   ([eBPF startup](../src/ebpf/conn_tracker.rs#L130)).
4. Only connect(2) and bind(2) on TCP sockets are denied, only on parser and
   capture threads, and only from Linux 6.7. UDP, ICMP, SCTP and netlink sockets
   stay open to those threads, and so does MPTCP, which falls back to TCP: on
   Linux 7.1 an MPTCP socket on a parser thread connected to a plain TCP
   listener. Two TCP calls get past the deny. A TCP Fast Open send (`sendto` or
   `sendmsg` with `MSG_FASTOPEN`) opens a connection and delivers its data
   without connect(2), and listen(2) on an unbound socket takes an ephemeral port
   on every address without bind(2). Both work from a parser thread on Linux 7.1,
   and a test fails if that changes
   ([gap tests](../src/sandbox/linux.rs#L1122)). Accepting on a listener bound
   before entry is not mediated either, which is how the metrics threads serve.
   Main, the network workers and the proc broker have no network restriction,
   and a parser running injected code can reach them through shared memory
   (item 1) or use a socket another thread holds. The deny raises the cost of
   exfiltration after code execution; it does not prevent it
   ([layer](../src/sandbox/linux.rs#L501)).
5. Unix sockets and signals are scoped on parser and capture threads only, and
   only where the kernel has the feature: abstract sockets from Linux 6.12,
   signals from 6.12 on a kernel that reports the erratum 2 fix, pathname sockets
   from 7.1. Below 7.1 a parser thread can connect to the D-Bus system bus, and
   as root it could ask systemd to start a command outside the sandbox. Main and
   the network workers are not scoped on any kernel: the resolver, the clipboard
   helpers and D-Bus clients need those sockets
   ([layer](../src/sandbox/linux.rs#L501)).
6. There is no syscall allow-list; filesystem restrictions are not seccomp
   ([backend](../src/sandbox/linux.rs#L1)).
7. Root retains filesystem, scheduling and other capabilities. The new deny-list
   reduces authority but does not promise root containment. Previous wording that
   a compromised parser cannot read SSH keys was too broad: shared descriptors,
   other threads and privileged interfaces must also be considered
   ([retained capabilities](../src/sandbox/linux.rs#L45)).
8. Parser and capture threads drop CAP_NET_RAW in best-effort and strict mode.
   A best-effort TUI keeps it on main and the network workers, because `c`,
   `i` and `Shift+R` reopen capture on a new thread started from main; a parser
   running injected code can still reach main's (item 1). The daemon,
   `diagnose run`, `diagnose coverage` and strict sessions drop it on every
   thread once capture has opened, so capture cannot reopen there, and the
   startup audit checks that no thread holds it. In those sessions the `ping`
   that health falls back to, and the one Diagnose's PMTU probe runs, can hold
   no more than the worker that starts it, so on a host whose `ping_group_range`
   excludes the user both fail and health falls back to TCP. With the sandbox
   on, no thread keeps CAP_NET_ADMIN; disabled mode drops neither capability
   from main or the workers. Dropping CAP_NET_RAW stops a thread opening raw or
   packet sockets and setting `IP_TRANSPARENT` or `SO_MARK`, and its
   subprocesses inheriting it through the Ambient set; it does not revoke the
   capture descriptor (below)
   ([parser list](../src/sandbox/linux.rs#L135),
   [after-open list](../src/sandbox/linux.rs#L143),
   [strict list](../src/sandbox/linux.rs#L124)).
9. Every confined thread but capture can write the configuration, so a
   compromised parser can persist a setting such as `sandbox = "off"` for the
   next start. The capture thread has no write grant
   ([write grants](../src/sandbox/linux.rs#L427),
   [capture layer](../src/sandbox/linux.rs#L487)).
10. Subcommands returning before worker installation are outside this policy,
    including file-oriented operations ([dispatch](../src/main.rs#L20)).
11. GeoIP downloading and parsing need separate review. The planned `netwatch
    geoip update` command and sandboxed parser are future work, not current
    protection (E2 below).
12. macOS, Windows and FreeBSD have no NetWatch filesystem sandbox backend
    ([platform dispatch](../src/sandbox/mod.rs#L1)).
13. Strict means required policy entry succeeds, the parser TCP deny included; it
    does not imply no network for main and the network workers, no privileged
    reader, or a separate parser process
    ([worker startup](../src/sandbox/worker.rs#L1)).
14. File capabilities on a world-executable binary let every local account invoke
    capture. Restrict execution to the intended group as in the setup recipe. The
    capture-error hint and the package install messages still give an in-place
    `setcap` line without that restriction (E3 below).

Capture drops CAP_NET_RAW on entry, and in sessions that never reopen every
other thread drops it too, but that does not revoke the AF_PACKET descriptor
capture opened before. Such a descriptor retains layer-2 capture/injection
authority in its network namespace. With every capability dropped, a libpcap
descriptor opened on one interface still sent a frame out of another and, once
rebound, read another interface's traffic (Linux 7.1, libpcap 1.10.6). Every
thread shares it (item 1), so no capability drop takes capture authority away
from a compromised parser. Capture opens before policy entry; a dumpcap-style
separate capture process is needed for a stronger boundary. The drops and the
audit were measured as root in a user and network namespace with a veth pair;
this document does not claim an independent root capture acceptance test was
performed. See [capture startup](../src/collectors/packets/mod.rs#L1).

## Input inventory

| Input | Boundary and handling site |
| --- | --- |
| I1 Ethernet/IP packets | B1, [capture/decode](../src/collectors/packets/mod.rs#L1) |
| I2 DNS messages and names | B1/B4, [DPI](../src/dpi/mod.rs#L1) |
| I3 TLS/QUIC handshakes | B1, [DPI](../src/dpi/mod.rs#L1) |
| I4 HTTP and other application payloads | B1/B4, [DPI](../src/dpi/mod.rs#L1) |
| I5 Kernel socket/process records | B2, [connections](../src/collectors/connections.rs#L1) |
| I6 eBPF events | B2/B7, [tracker](../src/ebpf/conn_tracker.rs#L1) |
| I7 Interface/OS API data | B2, [platform](../src/platform/mod.rs#L1) |
| I8 TLS keylog | B3/B5, exact configured file grant above |
| I9 GeoIP databases | B3, exact city/ASN file grants above |
| I10 Configuration | B3/B5, [config](../src/config.rs#L1) |
| I11 Episode JSON/gzip | B3/B4, [episodes](../src/diagnose/episode.rs#L1); A1 hardening pending |
| I12 Uptime history | B3/B4, [uptime](../src/uptime.rs#L1); A1 hardening pending |
| I13 Peer/process strings on screen | B4, [sanitizer](../src/ui/sanitize.rs#L1) |
| I14 Capture export requests | B5, [export](../src/collectors/packets/export.rs#L1) |
| I15 RDAP responses | B6, [WHOIS](../src/collectors/whois.rs#L1) |
| I16 Insights responses | B6, [Insights](../src/collectors/insights.rs#L1) |
| I17 Remote ingestion errors | B6, [remote](../src/remote/mod.rs#L1); A1 URL redaction pending |
| I18 Probe responses | B1/B6, [active probes](../src/diagnose/active.rs#L1) |

These rows identify review surfaces; they do not claim every parser has the same
bounds or that terminal sanitization protects other output formats.

## Outbound inventory

The marked inventory is checked row by row against default health, startup-trace,
active-probe, load-test and WHOIS endpoints. User-configured endpoints can differ.
DNS resolution itself can contact the system resolver. Health checks and one
startup trace run automatically; explicit experiments and WHOIS require their
respective user actions. See
[health](../src/collectors/health.rs#L177),
[startup trace](../src/collectors/traceroute.rs#L37),
[active defaults](../src/diagnose/active.rs#L35),
[load test](../src/diagnose/next_test.rs#L378), and
[WHOIS](../src/collectors/whois.rs#L11).

<!-- egress -->
| Service | Destination and disclosure |
| --- | --- |
| Reference DNS | 1.1.1.1, querying dns.google |
| Internet reachability | 1.1.1.1, TCP fallback on port 443 |
| Startup trace | 1.1.1.1; TTL-limited trace (UDP, ICMP echo on Windows) on every TUI start, demo included; ignores trace_target |
| STUN | stun.l.google.com:19302 and stun.cloudflare.com:3478; public mapping |
| Dual-stack experiments | 1.1.1.1:443, [2606:4700:4700::1111]:443, 8.8.8.8:443, [2001:4860:4860::8888]:443 |
| Captive portal | http://connectivitycheck.gstatic.com/generate_204 and http://cp.cloudflare.com/generate_204 |
| Explicit upload test | https://speed.cloudflare.com/__up; up to 25 MB |
| WHOIS on W | https://rdap.org/ip/ and the registry it redirects to; on Connections the selected remote address; on Packets the selected packet's source and destination, your own public address included; private ranges are not sent |
| Online GeoIP fallback | http://ip-api.com; peer address, cleartext; E2 will remove it |
| Insights, opt-in | Configured Ollama-compatible /api/chat endpoint; network and packet summaries |
| Remote, opt-in | Configured ingestion endpoint; metrics; HTTPS unless explicitly allowed insecure |
| Other probes | Configured resolver, gateway, trace/PMTU targets; targets and traffic depend on configuration |
<!-- /egress -->

## Platforms, release trust and remaining work

Linux alone has the filesystem backend. Windows uses Npcap and OS APIs; macOS and
FreeBSD use libpcap/BPF and platform collectors. See
[capability matrix](CAPABILITIES.md). Memory safety in Rust does not eliminate
unsafe FFI, native dependencies or resource-exhaustion failures.

Actions are SHA-pinned, Cargo.lock records dependency versions, and releases
include checksums, attestations, an SBOM and auditable binaries. These provide
traceability, not proof that a maintainer, dependency or runner is uncompromised.
Registry publishing uses a token; some cargo-installed build tools remain
unversioned. Fuzz dependencies have a separate lockfile. See
[release workflow](../.github/workflows/release.yml#L1),
[fuzz workflow](../.github/workflows/fuzz.yml#L1), and [Cargo.lock](../Cargo.lock).

| Work | Status / target |
| --- | --- |
| A1 hostile files and log redaction | Separate wave-1 PR; not included here |
| A2 selection leaking addresses to RDAP | Fixed: only W queues WHOIS |
| A4 root capability deny-list and broker restriction | Included; full root allow-list deferred |
| B1 parser TCP deny, scopes, ResolveUnix, no-write capture policy, CAP_NET_RAW off parser threads | Included |
| C1 capture authority and NET_ADMIN audit | Included |
| D1 seccomp no-socket policy | Later 0.39 work |
| E2 local GeoIP/update command | Later 0.39 work |
| E3 capture-error hint and package messages still setcap a world-executable binary | Later 0.39 work |
| E4 probe opt-out, covering the startup trace, and cleartext Insights warning | Later 0.39 work |
| F1 doctor reports actual containment | Later 0.39 work |
| Remaining unsafe-block audit | Later hardening; contributor safety policy applies now |
| Full-path LoadLibraryExW for Npcap | Deferred |
| Trusted publishing, signed tags, pinned cargo tools, fuzz lock maintenance | Deferred |
| Separate privileged capture process | After 1.0 |

Preventing an already-root attacker, containing arbitrary native code in a shared
process, and protecting deliberately public metrics endpoints are non-goals.
Report hostile-input bugs and non-root sandbox escapes through
[SECURITY.md](../SECURITY.md). Every hardening PR must update the affected rows;
`cargo test threat_model` checks the marked policy and endpoint inventories.
