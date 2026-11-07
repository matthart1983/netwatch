# Runtime lifecycle inventory

PR04 audit, 11 September 2026. This inventory describes the current local code,
including the prepare/start refactor. It does not certify confinement or readiness.

## PR08 resolver command boundary

`netwatch resolver ...` dispatches before application runtime/policy preparation
and before Npcap loading. `status` is read-only; Linux `set`/`recover` require root
and explicit unmanaged confirmation. The bounded foreground `set` command creates
only a current-thread signal/timer runtime, registers SIGINT/SIGTERM before mutation,
and holds the fixed root-owned authority store lock until restoration or exit.
No packet, attribution, remote or model workers start in this command.

The shared live bootstrap also reports unresolved authority records without performing
rollback. A session that is not root cannot read them. When the kernel refuses it the
store, it logs one line saying so instead. See [resolver adapter scope and validation](resolver-adapter.md).

## PR06 implementation update

TUI and daemon use `runtime::bootstrap::start` for recovery inspection, worker
startup/readiness and calling-thread policy, followed by common initial polls.
Static CLI dispatch (`--help`, `--version`, `--generate-config`) returns before
runtime bootstrap; config generation intentionally writes only its config file.

Live recovery authority is explicitly `InspectOnly`. Legacy PID/path metadata
cannot authorize a rollback: inspection does not open journal-supplied target or
backup paths, and nothing writes that journal any more.
TUI displays the persistent reason and exports it in Diagnose reports; daemon logs
the same reason. Shutdown cancels pending applies and preserves legacy entries,
including those whose PID happens to match the current process. Demo sessions skip
recovery and skip saving their simulated baselines at shutdown.

There are no eligible automatic rollback operations in the legacy format, and 0.40
removed the rollback code, which nothing had called since 0.31.1. No privileged
helper or wider parser filesystem grant is introduced.
Optional remote/logging/metrics services still start in shared CLI setup under the
worker policy; recovery inspection precedes application collector startup.

## PR05 implementation update

The inventory below records the PR04 baseline. PR05 changes the executable startup
boundary to synchronous CLI dispatch → directory/ruleset preparation → policy
preflight → current-thread Tokio runtime → explicit workers → main-thread policy.
No executor pool exists before policy setup. Future Tokio blocking workers enter
policy through the runtime callback. Logging's initializer enters policy before
creating the dependency writer, whose thread inherits it.

All listed ordinary worker starts now use a bounded entry handshake. Actual
threads apply the prepared ruleset before their processing closure is released.
Capture prepares pcap first, then enters policy before its first packet read; its
ready flag is separate from the cancellation/start-request flag. Every generation
owns its cancellation flag, so restarting cannot revive a detached old generation.
Strict failures withhold processing and abort startup with a nonzero CLI result.
Component entry outcomes and selected retained capabilities are recorded; Settings
shows verified-entry counts and up to three failure/degradation reasons. Earlier
unverified entries remain visible rather than being overwritten by later success.

Since 0.32.2 eBPF loads inside the sandbox policy: its worker enters holding the
load capabilities, loads, then drops them. The SDK-owned reader thread inherits that
filesystem policy but keeps the load capabilities, because it has no entry hook;
the residual is recorded against the `ebpf-reader` component. No SDK patch or helper
is claimed. PKTAP now uses the entry wrapper; macOS best-effort continues with an
explicit unavailable-backend report, and strict preflight rejects unsupported OSes.

Linux filesystem rules are built once against opened objects and cloned for worker
entry. Later pathname/symlink replacement cannot widen a grant. Existing configured
keylog/GeoIP files receive exact read grants. Missing files and replacement inodes
need a new session; parent directories are not granted for rotation. Writable paths
are private owned config/cache/state directories, dedicated exports/scratch and
`/dev/null`. The startup directory, shared `/tmp` and `/run/user` are no longer
writable grants. Exports now go to the platform cache directory's
`netwatch/exports` subtree (normally `~/.cache/netwatch/exports` on Linux).

Validation includes an isolated-process test at the real WHOIS, reverse-DNS,
Insights and keylog worker entries, keylog restart/read access, allowed exports,
forbidden sentinel reads, post-preparation symlink replacement and injected strict
entry failure. These are Linux filesystem boundary tests, not a hostile-parser
exploit demonstration. Privileged capture/restart and cross-platform runtime
acceptance are still pending; this environment has no CAP_NET_RAW. Managed worker handles now share a shutdown registry. Session exit signals stop,
queue workers check cancellation, metrics accepts are nonblocking, and joins share
a two-second deadline. In-flight blocking calls can exceed that deadline and are
reported as still unwinding. Capture retains its separate bounded stop/join path;
strict raw-authority loss prevents unsandboxed capture reopen retries.

## PR04 startup boundary (historical)


```text
#[tokio::main] creates runtime
  -> main: logging, optional remote sender / metrics listener
  -> App::prepare(): configuration, local snapshots, database handles, channels
  -> App::start_workers(): explicit persistent-worker starts
  -> TUI: legacy remediation reconciliation (daemon parity still pending)
  -> sandbox::apply(): calling-thread policy only
  -> terminal events (TUI), initial polls, tick loop
```

`App::prepare()` launches no application background workers. It still performs
synchronous platform discovery, reads configuration/state/journals, takes the Linux
process-attribution snapshot and opens the GeoIP databases. Synchronous
platform discovery can invoke system commands; prepare is not a no-I/O API.

`start_workers()` is idempotent at the application level. It starts reverse DNS,
optional Insights, configured keylog polling, ambient capture, platform attribution
and WHOIS. It attaches attribution caches to the existing connection collector
so the prepared Linux process snapshot is retained. Its `workers_started` flag
records that startup was requested, not that resources or confinement are ready.
Both TUI and daemon still start these workers before applying the sandbox.

`WhoisCache::new`, `DnsCache::new` and `InsightsCollector::new` now prepare channels
and state only. Call `start()` before expecting queued requests to be processed. Cache
clones share one start gate. `GeoCache` has no worker: it answers from the databases
opened in prepare, on the calling thread.
Settings changes construct and explicitly start a replacement Insights collector.
Terminal worker creation is named `EventHandler::start`; eBPF activation is named
`ConnTracker::start` because its SDK cannot currently prepare without starting.
These API changes also apply to library consumers; eBPF smoke examples are updated.

## Worker inventory

“Authority” below describes resource requirements or inherited authority, not proof
of its successful removal. Existing-thread confinement remains incomplete. Network
policy is the role in [`sandbox/roles.rs`](../src/sandbox/roles.rs), and a session's
log says what each thread got
([where each value can be read](doctor.md#where-each-value-can-be-read)). A TCP deny
needs Linux 6.7 and is not a
wall: [the threat model](THREAT-MODEL.md#what-containment-does-not-cover) lists what
gets past it.

| Component / creator | Resources, authority and input | Filesystem needs | Start/restart | Network policy (Linux) | Shutdown owner and current gaps |
| --- | --- | --- | --- | --- | --- |
| Tokio runtime / `#[tokio::main]` | Runtime threads exist before main body; tasks and I/O | Inherited; no per-task policy | Before CLI dispatch | Open: the blocking pool takes any blocking job, a name lookup among them | Runtime teardown; synchronous confined bootstrap pending |
| Logging / `logging::init` → tracing-appender | Log writer thread; receives application log text | Cache/log directory; opens daily appender | Main startup | TCP denied | Main retains `WorkerGuard` for flush; dependency worker policy unverified |
| Remote sender / `RemotePublisher::start` | HTTP sender, API key, host snapshots and remote responses | Host metadata/config discovery, resolver/TLS files | Main when remote enabled | Open | Explicit bounded `shutdown`; no new lifecycle split needed here; repeated starts lack a gate |
| Metrics listener / `MetricsExporter::start` | TCP listener and untrusted HTTP requests | No export files required | Main in metrics-enabled daemon | no socket(2), TCP denied | Detached accept loop; no stop/join owner |
| Metrics connection handler / listener | One thread per accepted connection; untrusted request line | None beyond runtime dependencies | Per accepted connection | no socket(2), TCP denied | Detached; socket timeout; concurrency bound pending |
| Reverse DNS / `DnsCache::start` | Channel of observed addresses, `host` subprocess responses | Executable, resolver/NSS paths | Explicit app start; also ensured by capture start; clones share gate | Open | All sender clones dropped → channel disconnect; queued work may drain; no join |
| Packet capture/decoder / `PacketCollector::start_capture` | Resolves device, opens pcap, installs BPF; parses hostile packet bytes | Device/system configuration, decoder state; Windows device lookup reads adapter GUIDs from IP Helper, PowerShell only if that fails | Ambient start; capture toggle, interface/filter changes, recorder paths use same method | no socket(2), TCP denied; no write grant | Collector stop flag; join waits up to 750 ms then detaches; old-worker/restart overlap remains a PR05 concern |
| TLS keylog / `configure_tls_keylog` → `spawn_keylog_watcher` | Poller parses externally written session secrets | Configured keylog and rotation/truncation handling | Explicit configured startup or replacement | no socket(2), TCP denied | Watcher handle stops and joins; no verified worker policy |
| PKTAP / `platform::pktap::spawn` (macOS) | Capture resource and kernel attribution metadata; requires capture authority | Platform capture facilities | Explicit app startup | No backend | `PktapHandle` stop/join; startup errors reported separately; no macOS sandbox backend |
| eBPF SDK reader / `EventSource::new` (inside `ConnTracker::start`) | Loads/attaches programs, opens ring buffers and starts dependency reader; BPF authority needed | Embedded object/system BPF resources | Explicit app start; dependency constructor is internally active | Inherits the eBPF worker's: TCP denied | SDK signals shutdown and detaches reader on drop; no preparation/enforcement hook |
| eBPF attribution drain / `ConnTracker::start` | Receives SDK events and updates bounded cache | No application files needed after startup | After SDK reader has already started | TCP denied | Tracker stop flag and join; spawn errors currently converted to absent join rather than readiness failure |
| WHOIS / `WhoisCache::start` | Lookup requests and external command/remote text | Lookup executable and resolver paths | Explicit app start, shared gate | Open | Sender disconnect; queued requests may drain; detached, no cancellation/join |
| Insights / `InsightsCollector::start` | Network-summary prompt and model HTTP response | Resolver/TLS runtime paths | Explicit app start and settings replacement | Open | Sender disconnect; in-flight/queued work may finish; request timeout 30s, no join |
| Terminal events / `EventHandler::start` | Crossterm terminal input and ticks | Terminal descriptors | TUI after sandbox call | TCP denied | Receiver drop eventually makes send fail; detached; no explicit stop/join |
| Interface traffic / `TrafficCollector::update` | OS counter snapshots | `/proc`, `/sys` or platform tools | Tick-driven, busy flag | TCP denied; `ip` and `iw` need netlink | Short-lived detached worker; completion clears busy flag |
| Connections / `ConnectionCollector::update` | Socket/process tables, attribution cache | `/proc` and platform socket/process tools | Initial poll and periodic ticks, busy flag | TCP denied; `ss` needs netlink | Short-lived detached worker; no unified cancellation |
| Health / `HealthProber::probe` | Gateway/internet ICMP, DNS and STUN replies | Resolver/system networking dependencies | Initial probe and periodic ticks | Open | Detached probe cycle with busy flag; individual probe limits, no unified cancellation |
| Kernel TCP / `TcpInfoCollector::update` | Netlink (Linux), sysctl (macOS); Windows unsupported | Kernel interfaces | Tick-driven, busy flag | TCP denied; reads netlink | Detached short-lived worker; timed snapshot published |
| Process CPU / `ProcessBandwidthCollector::refresh_cpu` | Process CPU sampling | `ps`/platform process data | Slow tick, busy flag | TCP denied | Detached short-lived worker |
| Traceroute / `TracerouteRunner::run` | External traceroute/tracert output, hostile network replies | Executable/resolver paths | User-requested target | Open | Detached worker/subprocess; no shared cancellation/join; completion timestamp published |

Source inventory: [app](../src/app.rs), [main](../src/main.rs),
[collectors](../src/collectors/mod.rs), [capture](../src/collectors/packets/mod.rs),
[keylog](../src/dpi/tls_decrypt.rs), [eBPF wrapper](../src/ebpf/conn_tracker.rs),
[PKTAP](../src/platform/pktap.rs), [events](../src/event.rs),
[logging](../src/logging.rs), [remote](../src/remote/mod.rs),
[metrics](../src/metrics.rs).

The dependency audit used the locked `netwatch-sdk` 0.4.1
`src/ebpf/source.rs`: `EventSource::new()` loads resources and spawns its reader;
`Inner::drop()` sets a shutdown flag and intentionally does not join. No separate
prepare/start or pre-read policy callback is exposed in that inspected code.
Do not treat the wrapper's attribution drain as the entire source. PR05 must use
an SDK lifecycle hook or a suitable process boundary before claiming source
confinement. No dependency source was modified in this slice.

## Capture resource boundary

`prepare_capture(interface, filter)` resolves the device, tries promiscuous then
non-promiscuous open, sets nonblocking mode, and installs an optional BPF filter.
It returns an active pcap handle without calling `next_packet()` or decoding.
It executes inside the capture worker, preserving asynchronous device lookup on
Windows and UI responsiveness. Every capture start/restart uses this path.

The enforcement/readiness insertion point is after resource preparation and before
the processing loop. There is no enforcement barrier there yet. The existing
`capturing` flag is set before preparation; it must not be presented as resource
readiness or a verified confinement result. PR05 must also handle startup failure,
stop during preparation and bounded-join restart races.

## Validation and next work

Regression tests cover preparing an app with capture/keylog/Insights configured
without activating those workers, retaining queued cache/analysis requests until
explicit start, and starting each clone-shared lookup worker only once. These tests
consume their synthetic requests before starting workers so they do not send DNS,
WHOIS or model requests. Capture failure/restart checks use a nonexistent
Linux interface and never acquire a live capture handle.

PR05 still owns policy application before processing, readiness/failure messages,
verified capability drops, narrow prepared paths, cancellation, joins, and actual
worker denied-access tests. Current tests do not demonstrate isolation. The outer
Tokio/logging/remote/metrics startup also needs integration into that boundary;
this inventory makes those remaining workers explicit.
