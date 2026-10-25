# NetWatch threat model

This describes the 0.39 wave-1 implementation, including the capability and
WHOIS fixes. It is a containment inventory, not a guarantee against arbitrary
code execution. Linux non-root capability-based operation is preferred. Running
as root works, but containment is limited; the sandbox is defence in depth.
See [the restricted-group setup](REFERENCE.md#running-without-sudo-linux) and
[reporting policy](../SECURITY.md).

## Run modes and assets

TUI and daemon startup install worker policy, start resources, and restrict the
main thread. Capture opens its device before entry. Early CLI dispatch can return
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

Landlock handles filesystem access only. The requested ABI is below; compatibility
is best-effort, so this number alone does not establish the enforced kernel ABI.
There are no Landlock TCP rules, Unix-socket resolution restrictions, signal or
abstract-socket scopes, or seccomp filter in this implementation. See
[ruleset construction](../src/sandbox/linux.rs#L391).

```text
<!-- policy:abi -->
V4
<!-- /policy:abi -->
```

Capability removals are verified. The first row is dropped on ordinary confined
threads, the second is additional in strict mode. The BPF load worker temporarily
retains the third row; the unconfined proc broker retains only capabilities it
started with from the fourth row. This is a deny-list, not a complete root
allow-list. See [capability policy](../src/sandbox/linux.rs#L25) and
[broker entry](../src/sandbox/worker.rs#L1).

```text
<!-- policy:caps -->
default: CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN, CAP_SYS_RAWIO, CAP_SYS_MODULE, CAP_SYS_BOOT, CAP_SYS_TIME, CAP_SYS_PACCT, CAP_SYS_TTY_CONFIG, CAP_SYSLOG, CAP_WAKE_ALARM, CAP_BLOCK_SUSPEND, CAP_SYS_PTRACE, CAP_KILL, CAP_CHECKPOINT_RESTORE, CAP_IPC_OWNER, CAP_SETUID, CAP_SETGID, CAP_SETPCAP, CAP_SETFCAP, CAP_MKNOD, CAP_SYS_CHROOT, CAP_LINUX_IMMUTABLE, CAP_LEASE, CAP_MAC_ADMIN, CAP_MAC_OVERRIDE, CAP_AUDIT_CONTROL, CAP_AUDIT_WRITE, CAP_AUDIT_READ, CAP_NET_BROADCAST
strict-extra: CAP_NET_RAW
bpf-load: CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN
proc-broker: CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH
<!-- /policy:caps -->
```

The following grants are checked against the path collectors with every optional
path supplied. Placeholders are prepared application directories or exact input
files, not literal paths. Missing paths are skipped; grants are pinned to opened
objects. A file replacement requires a new session. The test also checks what each
label grants: a read row allows execute, read-file and read-directory beneath it;
the city, ASN and keylog files allow read-file only; a write row allows every
filesystem right the requested ABI handles, so read access accompanies it. A row
that names a file rather than a directory keeps only the file rights. See
[path collection](../src/sandbox/linux.rs#L283),
[access per grant](../src/sandbox/linux.rs#L455) and
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
   ([broker policy](../src/sandbox/linux.rs#L103)).
3. The SDK reader inherits filesystem policy but keeps its creation-time load
   capabilities; it has no separate entry hook
   ([eBPF startup](../src/ebpf/conn_tracker.rs#L130)).
4. Outbound networking remains unrestricted. The policy does not stop data
   exfiltration after code execution ([ruleset](../src/sandbox/linux.rs#L391)).
5. Unix sockets and cross-process signalling have no Landlock scope restrictions
   here ([ruleset](../src/sandbox/linux.rs#L391)).
6. There is no syscall allow-list; filesystem restrictions are not seccomp
   ([backend](../src/sandbox/linux.rs#L1)).
7. Root retains filesystem, scheduling and other capabilities. The new deny-list
   reduces authority but does not promise root containment. Previous wording that
   a compromised parser cannot read SSH keys was too broad: shared descriptors,
   other threads and privileged interfaces must also be considered
   ([retained capabilities](../src/sandbox/linux.rs#L25)).
8. Best-effort keeps CAP_NET_RAW so capture can reopen. Strict drops it, which can
   make capture restart fail ([strict list](../src/sandbox/linux.rs#L82)).
9. Configuration remains writable, so confinement does not make future startup
   configuration immutable ([write grants](../src/sandbox/linux.rs#L349)).
10. Subcommands returning before worker installation are outside this policy,
    including file-oriented operations ([dispatch](../src/main.rs#L20)).
11. GeoIP downloading and parsing need separate review. The planned `netwatch
    geoip update` command and sandboxed parser are future work, not current
    protection (E2 below).
12. macOS, Windows and FreeBSD have no NetWatch filesystem sandbox backend
    ([platform dispatch](../src/sandbox/mod.rs#L1)).
13. Strict means required policy entry succeeds; it does not imply no network,
    no privileged reader, or a separate parser process
    ([worker startup](../src/sandbox/worker.rs#L1)).
14. File capabilities on a world-executable binary let every local account invoke
    capture. Restrict execution to the intended group as in the setup recipe.

Dropping CAP_NET_RAW does not revoke an already-open AF_PACKET descriptor. Such
a descriptor retains layer-2 capture/injection authority in its network namespace.
Capture opens before policy entry; a dumpcap-style separate capture process is
needed for a stronger boundary. This document does not claim an independent root
capture acceptance test was performed. See
[capture startup](../src/collectors/packets/mod.rs#L1).

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
| B1 parser TCP deny, scopes, ResolveUnix, no-write capture policy | Later 0.39 work |
| C1 capture authority and NET_ADMIN audit | Later 0.39 work |
| D1 seccomp no-socket policy | Later 0.39 work |
| E2 local GeoIP/update command | Later 0.39 work |
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
