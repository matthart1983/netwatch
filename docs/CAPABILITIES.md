# Current capabilities and limits

The [doctor command](doctor.md) reports setup capabilities as text or versioned
JSON without starting collectors. Its optional bounded capture check reports only
the isolated check's results. Live Settings and startup use the same capability
model with runtime observations; static configuration is never a health verdict.

This matrix describes the v0.39.0 capability baseline. Later development changes
must be labeled with their release status. Windows switched from `netstat -ano`
and `tasklist` polling to IP Helper in 0.38. This is not a claim
that every backend was exercised on every supported OS. Linux unit tests do not
establish macOS or Windows runtime parity.

| Capability | Linux | macOS | Windows | FreeBSD |
| --- | --- | --- | --- | --- |
| Interface/configuration collection | Linux system counters and network tools | macOS network tools | IP Helper API (adapters, DNS servers, counters, routes), with `ipconfig`/PowerShell/`route print` fallbacks | `getifaddrs` up-state, `netstat`/`ifconfig` |
| Packet capture | libpcap; capture permission required | libpcap/BPF; access permission required | Npcap installation and capture access required | Base-system libpcap/BPF; `/dev/bpf` access required |
| Capture authority | File capabilities on a binary restricted to a group, the systemd unit, or root. With the sandbox on, the daemon and Diagnose CLI drop `CAP_NET_RAW` from every thread once capture opens, and so does strict mode; the open descriptor keeps its access | No capability model; `/dev/bpf` access is checked at `open()`, and an open descriptor keeps its access | Npcap's install options decide who can capture; no capability model | No capability model; `/dev/bpf` access is checked at `open()`, and an open descriptor keeps its access |
| Process attribution | Verified procfs socket ownership; eBPF hints require corroboration; the SDK reader inherits filesystem policy but retains load capabilities | Unverified `lsof` observations; PKTAP hints cannot overwrite owners | Unverified polling of the kernel socket tables through IP Helper; names from a process snapshot | Unverified `sockstat` observations; executable via `KERN_PROC_PATHNAME` |
| Process in PCAPNG packet comments | When two verified owner checks bracket the packet | Always `unknown_owner`: identity unverified | Always `unknown_owner`: identity unverified | Always `unknown_owner`: identity unverified |
| Kernel TCP metrics | `NETLINK_INET_DIAG` | `net.inet.tcp.pcblist64` sysctl | Not implemented; collector returns no flows | Not implemented; collector returns no flows |
| Diagnose | Shared detectors; available inputs determine coverage | Shared detectors; available inputs determine coverage | Shared detectors; absent TCP metrics limit socket rules | Shared detectors; absent TCP metrics limit socket rules |
| Netwatch sandbox | Worker entry policy with prepared filesystem grants; privileged capture acceptance pending | No backend | No backend | No backend (no Capsicum) |
| Network policy per thread | Parser and capture threads denied TCP bind and connect from Linux 6.7; capture, keylog and metrics threads also lose socket(2) on x86_64, aarch64 and armv5te; main and network workers unrestricted | None | None | None |
| Strict sandbox startup | Rejects preflight/required entry failures; raw capture reopening may fail | Rejected: no backend | Rejected: no backend | Rejected: no backend |
| Resolver changes | Explicit root CLI for confirmed unmanaged regular file; TUI automatic edits disabled | Unavailable | Unavailable | Unavailable |
| AI commentary | Optional Ollama-compatible endpoint | Optional Ollama-compatible endpoint | Optional Ollama-compatible endpoint | Optional Ollama-compatible endpoint |

See [attribution evidence and controlled results](attribution.md) for exact
coverage denominators and pending platform acceptance. Attribution may be unknown or stale. Polling can miss short-lived connections;
backend identity and visibility are constrained by permissions and the observed
network scope. An `ebpf` build or granted capability alone does not prove that the
kernel accepted a program or that every flow was attributed.

## Platform tiers (draft for 1.0)

What 1.0 is expected to promise per platform. Until 1.0 this is a draft, and
every tier is best-effort.

| Tier | Platforms | Meaning |
| --- | --- | --- |
| 1 | Linux x86_64 and aarch64 | Every feature; CI runs the test matrix and the Diagnose fault and health labs; a regression blocks a release. |
| 2 | macOS x86_64 and aarch64, Windows x86_64 | Built and tested in CI on every change; features limited as the matrix above says; a regression blocks a release. |
| 3 | FreeBSD x86_64 (13+), Linux armv5te | Built in CI (FreeBSD tested in a VM, armv5te checked only) by `tier3.yml`, which the release guard does not wait on; fixed when reported. |

## Diagnose and remediation

The [rule coverage document](diagnostic-coverage.md), generated from the
catalogue, lists 30 active rules, eight of which carry a reviewed contract
stating their evidence, lookalikes, recovery and platform limits. An active
rule can still be learning, unmeasured or stale on a given host. Local bufferbloat lacks a live loaded/idle test;
interface saturation lacks link capacity in the live adapter. Empty findings do
not establish host health. Baseline readiness is sample-based, not a guaranteed
30-minute elapsed window.

The [Linux resolver authority command](resolver-adapter.md) supports temporary
changes to an explicitly confirmed unmanaged regular file. Managed resolvers and
other platforms remain unsupported; automatic TUI/daemon edits stay disabled.
Manual guidance and simulated demo remediation remain. TUI and daemon
startup read the legacy journal that 0.30 wrote and report unresolved entries without
opening its target or backup paths. Startup and shutdown leave legacy operations
unchanged: their ownership cannot be verified, even when running as root or with
`--no-sandbox`. Journal/backup locations are reported as unverified evidence for
manual review. Demo startup/shutdown performs no recovery and does not save
simulated baselines. Startup also inspects the per-user [v2 recovery store](recovery-store.md)
in durable state, which no release has written. Its Unix writer provides synced atomic replacement and a
per-store OS lock; it does not grant resolver authority or a host-wide lease.
The Linux resolver CLI uses a separate root-owned shared authority store/lease at
`/var/lib/netwatch/resolver-v2`; normal startup as root reports its unresolved evidence but
does not perform privileged rollback. Startup as anyone else cannot read that store, so it
logs one line saying to run `sudo netwatch resolver status`, and `doctor` reports the same.
`netwatch resolver recover` restores from that
store and from nothing else. Windows v2 writes remain unavailable. Nothing has written
the legacy journal since 0.31.0 and nothing restores from it, so an entry left open there
is [restored by hand](recovery-store.md#legacy-journal); on Linux `resolver status` and
`recover` print its notice.

## Security boundary

The [sandbox reference](REFERENCE.md#landlock-sandbox-linux) documents current
worker entry enforcement and exact file/dedicated-directory grants. eBPF loads
inside the policy; the SDK reader inherits it but keeps the load capabilities
until it has an entry hook of its own.
On Linux, network policy is per thread: the table above says which, `netwatch doctor
--json` says what a parser thread gets on this kernel, and a session's log what each
of its threads got. Linux tests cover actual lookup,
Insights and keylog entries, keylog restart, export access, symlink replacement and
strict entry rejection. Privileged capture/restart and cross-platform acceptance remain pending.
Managed workers have a shared shutdown deadline; an in-flight blocking operation
may still outlive it and is reported rather than forcibly interrupted.

## Navigation and AI

The full view has ten tabs: Dashboard (`1`), Connections (`2`), Interfaces (`3`),
Packets (`4`), Stats (`5`), Topology (`6`), Timeline (`7`), Processes (`8`), Diagnose
(`9`) and Egress (`0`). Insights is commentary within Diagnose, not another tab.
The config value `default_tab = "insights"` is a legacy alias for Diagnose.

AI is off by default. Enabling it sends packet-derived summaries and network
metadata to the configured endpoint. Commentary is not validated against findings;
a localhost endpoint does not guarantee local-only inference. See
[AI Insights](INSIGHTS.md) for the data sent, timing and shutdown limitations.

## Source of truth and verification

This audit checked [tab/config mapping](../src/config.rs),
[application startup and dispatch](../src/app.rs),
[platform collectors](../src/platform/mod.rs),
[attribution](../src/collectors/connections.rs),
[TCP metrics](../src/collectors/tcp_info.rs),
[sandbox dispatch](../src/sandbox/mod.rs),
[Linux policy](../src/sandbox/linux.rs), and
[Insights snapshot/worker](../src/collectors/insights.rs).

Worker entry policy, live Settings reporting and the [doctor capability snapshot](doctor.md)
are implemented. Static doctor results, optional capture checks and session observations
have different scopes; see [where each value can be read](doctor.md#where-each-value-can-be-read).
Pending privileged and cross-platform acceptance above remains pending; availability
of the command does not establish those results.

The [threat model](THREAT-MODEL.md) details containment and privilege limits.
