# Changelog

All notable changes to NetWatch will be documented in this file.

## [0.18.0] - 2026-05-23

### Changed
- **Health probing now uses native DGRAM ICMP instead of `Command::new("ping")`.** The v0.17.x sandbox sets `PR_SET_NO_NEW_PRIVS=1` before applying Landlock (required by the kernel for unprivileged use), and `NO_NEW_PRIVS` causes the kernel to ignore the setcap on `/usr/bin/ping` on execve — so the subprocess fallback returned EPERM and both gateway and DNS RTTs sat at "0.0 ms / 100% loss" while the sandbox was active. The new path opens a `SOCK_DGRAM` `IPPROTO_ICMP` (and `IPPROTO_ICMPV6`) socket directly via `nix`, which gates on `net.ipv4.ping_group_range` (default `0 2147483647` on most distros — i.e. any user) instead of `CAP_NET_RAW`, so it works under sandbox without any capability requirement.
- The subprocess `ping` path is preserved as a fallback for systems where DGRAM ICMP isn't permitted (`ping_group_range` set to a restrictive range) and for Windows.
- Verified end-to-end on Linux under best-effort sandbox: `cargo run --example ping_under_sandbox -- 192.168.0.54` returns a clean RTT (3.25 ms in a representative LAN measurement) with Landlock ABI V7 active and `NO_NEW_PRIVS=1` set.

### Fixed
- **Gateway ping + DNS RTT no longer blank under the sandbox** (the regression flagged on v0.17.1). Net effect: with v0.17.1 you had to choose `--no-sandbox` to see health metrics; in v0.18.0 the default-on sandbox and health probing both work together.

### Notes
- The `Topology` tab's `traceroute` hops are still subprocess-based and will hit the same `NO_NEW_PRIVS` issue. That's a separate rewrite (UDP+TTL probes in-process) tracked for a later release. Workaround until then: traceroute renders correctly with `--no-sandbox`, and the rest of the Topology tab (gateway dot, ISP detection, color-coded edges) works under sandbox.

## [0.17.1] - 2026-05-23

### Fixed
- **Sandbox no longer breaks the Dashboard / Interfaces tabs on Linux.** The v0.17.0 Landlock allow-list omitted `/sys`, `/bin`, `/sbin`, `/usr` (the executable + library roots), and `/etc/{passwd,group,os-release,ld.so.*}` — so any reads from `/sys/class/net/*/{statistics,operstate,carrier,mtu,address,wireless}` returned EACCES, every subprocess (`ss`, `lsof`, `ip`, `traceroute`, `whois`) failed to execve under the policy, and `getaddrinfo` couldn't load NSS modules. The interface-info reader in `src/platform/linux.rs` swallows those errors via `unwrap_or_default()`, so the symptom was "everything blank" rather than a visible error in the log.
- The allow-list now covers `/proc`, `/sys`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, plus a narrow set of `/etc/*` files for NSS / TLS / time (deliberately narrow so a sudo'd netwatch still can't read `/etc/shadow` or `/etc/sudoers` through the sandbox), plus `/run/systemd/resolve` and `/run/dbus`. RW restriction (cache dir, CWD, `/tmp`, `/run/user/<uid>`) is unchanged.

If you hit the v0.17.0 regression, `netwatch --no-sandbox` was a working workaround; v0.17.1 makes that unnecessary.

## [0.17.0] - 2026-05-23

### Added
- **Security sandbox (Linux).** After pcap, PKTAP, and the eBPF kprobe finish setup, netwatch now restricts its own authority so a memory-safety bug in DPI parsing (the largest unsafe surface) cannot read SSH keys, exfiltrate arbitrary files, or pivot via new raw sockets. Two layers, applied in order:
  - **Capability drop** via the `caps` crate: `CAP_NET_RAW`, `CAP_BPF`, `CAP_PERFMON`, and the legacy `CAP_SYS_ADMIN` BPF fallback are removed from the Effective, Permitted, and Inheritable sets. The kprobe is already attached and the pcap fd is already open; the process never needs those capabilities again. Running without elevation (no `setcap`, no `sudo`) is a clean no-op.
  - **Landlock filesystem restriction** via the `landlock` crate, targeting ABI V4 with graceful BestEffort degrade to V3 / V2 / V1 on older kernels. The ruleset allows reads from `/proc`, the system resolver files (`/etc/resolv.conf`, `/etc/hosts`, `/etc/services`, `/etc/nsswitch.conf`, …), zoneinfo, CA bundles, NSS-module dirs, the user's `~/.config/netwatch/` and any configured GeoIP DB parent dirs; allows writes only to `~/.cache/netwatch/` (logs + Flight Recorder bundles), the startup CWD (PCAP exports), `/tmp`, and `/run/user/<uid>`. Everything else fails with `EACCES` at the kernel — independent of DAC.
- **Three enforcement modes**, selectable via CLI:
  - **default (best-effort)**: apply what the kernel supports; log a single warning if Landlock isn't enforced (e.g., kernel <5.13 or LSM not enabled). Don't refuse to start.
  - **`--no-sandbox`**: escape hatch for debugging; skips both cap drop and Landlock.
  - **`--sandbox-strict`**: refuse to start if any platform-supported restriction can't be applied. Intended for production deployments where the operator wants a hard guarantee.
- **Settings overlay sandbox row** — read-only info line showing the live enforcement state, e.g. `best-effort: Landlock ABI V4, 3 caps dropped`. Users can confirm the sandbox actually applied at runtime rather than trusting the README claim.
- **`examples/sandbox_smoke.rs`** — a runnable Linux smoke test that applies the sandbox in BestEffort mode and then exercises four real accesses: read `/proc/self/status` (allowed), read `/etc/shadow` (expected EACCES), open a raw socket (expected EPERM), print the enforcement report. Exits non-zero on any unexpected outcome. Used in dev to verify Landlock is actually enforcing.

### Notes

The sandbox is **Linux-only by design**, not Linux-first. macOS Seatbelt and Windows restricted-token are intentionally not on the roadmap. The threat the sandbox defends against — exploitable DPI parsing of hostile traffic — is a production-capture-host concern, not a dev-workstation one. Spending the budget on per-platform sandboxes for feature-matrix parity with neighbouring tools would dilute focus without buying users meaningful security. Landlock network blocking (TCP bind/connect denial on ABI V4) is also deferred: a blanket TCP-block would silently break the ip-api.com GeoIP fallback, `--remote` metric streaming, and inline WHOIS lookups. A future revision can add per-port allow-listing once those endpoints are reachable behind a stable list.

## [0.16.2] - 2026-05-20

### Fixed
- **USB-Ethernet adapters no longer mislabeled as Wi-Fi on the Interfaces tab** (#30). macOS hands out `en*` names to both the built-in Wi-Fi adapter and to USB / Thunderbolt Ethernet dongles, so the old name-prefix classifier flagged everything starting with `en` as `"wifi"` — the Dashboard at least hedged with `"ethernet/wifi"`, which made the two tabs visibly disagree. We now ask the OS what the adapter actually is and propagate that through a new `is_wireless` field on `InterfaceInfo`:
  - **macOS**: parses `networksetup -listallhardwareports` and matches BSD device → `Hardware Port: Wi-Fi` (or legacy `AirPort`).
  - **Linux**: presence of `/sys/class/net/<name>/wireless` (kernel-authoritative).
  - **Windows**: adapter-header type from `ipconfig /all` (`Wireless LAN adapter` vs `Ethernet adapter`).
  Wired adapters now render as `ethernet` everywhere; the `"ethernet/wifi"` hedge survives only as the fallback when detection is unavailable. The two duplicate `role_for()` helpers in `ui/interfaces.rs` and `ui/dashboard.rs` have been collapsed into one — the divergence between them was what produced the inconsistent labels in the first place.

## [0.16.1] - 2026-05-18

### Fixed
- **Shift+W now actually shows whois on the Connections tab** (#29). The keybinding was wired up and the help overlay advertised it, but the Connections UI never rendered the resolved cache entry — only the Packets tab did. The lookup fired silently into the background; nothing appeared in the UI. The detail strip below the connection table now shows `WHOIS  netname │ org │ range │ country` plus an optional description line, mirroring the existing Packets-tab format.

## [0.16.0] - 2026-05-17

### Added
- **Deep packet inspection (DPI) — see what each flow is actually doing, not just where it's going.** New `dpi` module classifies the application-layer protocol of every captured stream from its first non-trivial payload. Surfaces results across the entire UI:
  - **Connections tab** gets a new `APP` column showing `HTTPS api.anthropic.com` / `QUIC youtube.com` / `DNS example.com` / `SSH-2.0-OpenSSH_9.0` per row.
  - **Packets tab** `INFO` column shows the same DPI summary per packet (with subsequent packets on a flow inheriting the cached classification), and rows are color-coded by L7 protocol (cyan HTTPS/QUIC, green HTTP, brand DNS, yellow SSH) so the eye can group flows at a glance.
  - **Dashboard TOP CONNECTIONS** panel substitutes the DPI hostname for the raw remote IP — `172.217.x.x` becomes `youtube.com`, grouping collapses by service rather than per remote address.
  - **Packets tab detail pane** now decodes QUIC v1/v2 Initial packets: derives Initial keys via HKDF, strips header protection, AEAD-decrypts, and surfaces the inner frame structure (`CRYPTO offset=0 len=600`, `PADDING bytes=584`, etc.). This is the differentiator vs. peers — most network TUIs can't decrypt QUIC, so they can't show what's inside a QUIC Initial at all.
  - **Filter prefixes** in the Packets and Connections tabs: `app:tls`, `app:quic`, `app:dns`, `sni:reddit.com`, `host:api.example.com`. Same syntax across both tabs.
- **TLS classifier** — parses ClientHello via `tls-parser`, extracts SNI hostname + ALPN protocol. TLS 1.0–1.3.
- **QUIC classifier** — implements full RFC 9001 (QUIC v1) and RFC 9369 (QUIC v2) Initial-packet decryption: HKDF-Expand-Label key derivation, AES-128-ECB-derived header-protection mask, AES-128-GCM AEAD with `nonce = iv XOR pn`, CRYPTO-frame walk. Reuses the TLS classifier on the reassembled ClientHello to extract SNI.
- **Cross-packet QUIC reassembly** — Chrome's modern ClientHellos commonly span multiple Initial packets; the SNI extension can land in fragment 2+. We buffer CRYPTO frames per-stream and retry SNI extraction across packets, capped at 16 KB of accumulated buffer.
- **DNS classifier** — hand-rolled wire-format parser for the first question's qname + qtype. Handles plain DNS-over-UDP, mDNS (5353), LLMNR (5355). Refuses compression pointers in the question section to keep parsing linear-time.
- **HTTP classifier** — `httparse`-backed request-line + Host-header extraction.
- **SSH classifier** — server/client banner-line capture (`SSH-2.0-OpenSSH_9.0`).
- **`extract_udp_app_payload`** public helper on the packets collector — the UI uses it to feed a captured packet's bytes back through the QUIC decrypt pipeline for the detail-pane frame breakdown.

### Changed
- **Connections tab refresh cadence** moved from 2 s to 1 s. The `busy` flag still coalesces under load, so the effective cadence becomes `max(tick, lsof_duration)`. New flows now appear within a second of opening on the wire.
- **Local-only join fallback for wildcard-remote UDP connections.** `lsof` on macOS commonly reports Chrome's QUIC UDP sockets with remote `*:*` even when the kernel has a specific peer. The strict 5-tuple stream join used to drop those — now we fall back to matching by local endpoint, attaching the DPI tag from whichever Stream owns the same local port. For QUIC this is unambiguous (one flow per ephemeral local port) and is the path that lets the APP column light up at all for browser traffic.
- **307 tests pass** (up from 296), 33.8% line coverage / 44.4% function coverage. New DPI classifiers shipped with their own unit tests (dns 94%, tls 82%, quic 63% incl. the RFC 9001 Appendix A.2 end-to-end test vector that exercises every layer of the decryption stack).

### Fixed
- **macOS no longer falsely shows "eBPF active"** (this is the v0.15.12 hotfix already released earlier today; preserved here for completeness). The dashboard footer now reads live attribution state via `attribution_status()` and shows `pktap active` on macOS instead of the placeholder.
- **Demo GIF re-recorded** with the agg/asciinema pipeline so the README capture reflects the v0.15.x UI layout cleanly.

## [0.15.12] - 2026-05-17

### Fixed
- **Dashboard footer now reports the real attribution path** — The `eBPF active` / `eBPF off` indicator was reading a boot-time placeholder field that was always set to `Active` whenever the `ebpf` feature compiled in. Since the feature is `default = ["ebpf"]` and the field was never updated from the placeholder, every macOS build falsely advertised "eBPF active" even though eBPF is Linux-only. The footer now reads live state via `App::attribution_status()`, which already knows per-OS what's actually doing kernel attribution. macOS shows `pktap active` (the actual mechanism), Linux shows `eBPF active` only when the BPF object loaded successfully, and unprivileged Linux fallbacks show `eBPF off` or `lsof attr` correctly.

## [0.15.11] - 2026-05-17

### Added
- **Two new themes: `sky` and `paper`** — both paint panel backgrounds rather than letting the terminal show through. `sky` is a calm cool-blue dark theme; `paper` is a light theme with AAA-contrast data colors tuned against off-white. Cycle themes from settings or pass `--theme paper`.
- **Graceful recovery from poisoned mutexes** — A panic inside a critical section used to leave shared state in a `PoisonError` state and ripple downstream panics across the whole UI thread. We now `unwrap_or_else` on poisoned guards by clearing the inner state and continuing, so a single panic in a collector doesn't take the TUI with it.
- **Structured file-only logging** — Diagnostic logging now writes to a configurable file rather than stderr (which fights the TUI for the terminal). Levels and target file controllable via env vars. Off by default so the binary still has zero non-UI output.

### Changed
- **Refactored hot-path state into snapshot pattern** — `AppCaches` and `AppUiState` extracted out of the monolithic `App` struct, with hot reads on the UI thread going through cheap snapshots instead of holding the collector lock. Eliminates the occasional input-lag stutter under bursty traffic.

### Fixed
- **Help dialog now respects the active theme** — Previously rendered with hard-coded colors that clashed on `paper` and `sky`. Now derives all colors from the theme palette like every other panel.
- **`paper` popup backgrounds inherit the painted bg** — Settings, help, and confirmation popups were transparent on `paper`, exposing whatever sat behind them. They now paint their own background to match the theme.
- **`paper` data colors meet AAA contrast against off-white** — Several greens and blues failed contrast checks; darkened to compliant variants.
- **Packets tab block titles match the rest of the UI** — They were dim regular weight; now brand-color bold like every other tab's titles. Consistency fix.
- **Default fg set alongside bg** so unstyled spans inherit the theme's text color rather than the terminal's default (which broke `paper` and looked wrong on `sky`).
- **`minimal` theme** (previously `light`) renamed to reflect its constraint — it defers to the terminal's palette for body text, which is the right call for terminals with custom palettes but isn't truly "light." Subsequently deleted entirely after testing showed it duplicated `dark` on the only terminal where it rendered correctly.
- **`process_bandwidth` test de-flaked** for CI — byte-accumulation test was timing-sensitive and intermittently failed under loaded runners.

## [0.15.10] - 2026-05-13

### Added
- **Per-process bandwidth uses real per-connection rates** — Previously the Stats "TOP PROCESSES by RX" panel and the Processes tab split total interface bytes proportionally to each process's *connection count*. With most processes holding a single connection this gave every process an identical fictional slice. The collector now aggregates each connection's measured `rx_rate`/`tx_rate` per `(process, pid)` and accumulates cumulative bytes by integrating rate × elapsed across ticks, with stale entries pruned after 5 minutes. The panel only shows real data; processes with no measured traffic report 0 instead of an equal fake share.
- **`setcap` Linux install path documented** — README now explains the `sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip'` recipe so users can run netwatch without sudo and still get packet capture + eBPF process attribution. Capability table in the README clarifies what each cap unlocks.
- **mimalloc as the global allocator** — Replaces glibc's `ptmalloc` on Linux (and the system allocator everywhere else). Long-running TUI daemons that spawn short per-tick threads pay a noticeable RSS tax to ptmalloc's per-thread arena retention; mimalloc returns memory to the OS more aggressively and meaningfully reduces the steady-state baseline. Functionally transparent.
- **Memory-cap diagnostic overlay** — Press `M` to surface every bounded in-memory collection alongside its current fill ratio, so long-running sessions can verify the caps actually hold under load. Diagnostic tool, documented in the help dialog only.

### Fixed
- **UI no longer flickers between traffic bursts** — Dashboard "ACTIVE INTERFACE" `N live N idle` badge, the Interfaces tab's filter and per-row dot, and the Stats top-processes panel all judged "is this active?" by comparing the current-tick rate to 0. Rates are genuinely 0 most ticks even on busy interfaces, so badges, dots, and counts flapped every refresh. New shared `widgets::interface_recently_active` helper checks the last few history samples instead. Top-processes accumulates bytes across ticks (above) so the panel stays populated through idle moments instead of flashing then emptying.
- **Stats "TOP PROCESSES by RX" no longer shows 0-byte entries** — Panel was reading `process_bandwidth.ranked()` directly, which is sorted by combined RX+TX rate. A TX-heavy process with no RX traffic could land in the top 5 and render as `<name> — 0 KB`. Re-sorted locally by `rx_bytes` and zero-RX entries filtered out before taking the top 5.
- **Connections tab: clicking a row now selects that row (#28)** — Mouse hit-test had two bugs: the content-top arithmetic missed the 2-row chip strip and 10-row detail strip, and the new selection was computed as `connection_scroll + visible_row` (relative to the previously-selected row) instead of `window_top + visible_row` (relative to the visible window). Result: clicking the top visible row at scroll>0 didn't change the selection, and clicking deeper rows landed on rows further down than intended, often scrolling the view as the new selection re-centered. Renderer and handler now share `table_inner_area` and `compute_window_top` helpers from `ui::connections`. Reported by @sliddjur.
- **Clearer error when `traceroute` isn't installed** — Topology's auto-traceroute returned a bare "No such file or directory" on Linux distros that don't include `traceroute` (e.g. Ubuntu default). Now surfaces a distro-aware install hint instead.

## [0.15.9] - 2026-05-12

### Changed
- **`cargo install netwatch-tui` now ships eBPF too** — bumped the `netwatch-sdk` dep to 0.1.2, which carries a pre-built `netwatch_sdk_ebpf.o` (2424-byte eBPF ELF) directly in the published crate. The SDK's `build.rs` embeds it via `include_bytes!` automatically, so any Linux build picks it up without needing nightly Rust + bpf-linker + LLVM 18 on the consumer side. Closes the remaining gap from v0.15.8 where only `brew install` and direct tarball downloads got eBPF.
- **Release workflow simplified** — dropped the now-redundant "Build netwatch-sdk eBPF object" + `[patch.crates-io]` step. The Linux release tarballs still get the same BPF object, but via the published SDK instead of an in-workflow clone-and-build.

## [0.15.8] - 2026-05-10

### Fixed
- **Linux release tarballs now ship with the eBPF BPF object embedded** — the v0.15.6 attempt failed because netwatch-sdk's `crates/ebpf-programs/rust-toolchain.toml` listed `bpfel-unknown-none` as a target, making rustup try to download `rust-std` for a tier-3 target that has no precompiled artifact. SDK fix landed at netwatch-sdk@48f8960; netwatch's release workflow re-enables the BPF build step (clone SDK, install bpf-linker, run `scripts/build-ebpf.sh`, then `[patch.crates-io]`-override the SDK so cargo build picks up the local copy with the BPF object embedded). Linux users downloading the tarball or installing via Homebrew now get kernel-attributed PIDs out of the box; `cargo install netwatch-tui` users still fall back to lsof until the SDK starts shipping the pre-built `.o` on crates.io directly.

## [0.15.7] - 2026-05-10

### Fixed
- **v0.15.6 release was broken** — the new "Build netwatch-sdk eBPF object" step in the release workflow tried to install the SDK's pinned nightly (`nightly-2026-01-15`) but rustup couldn't fetch `rust-std` for `bpfel-unknown-none` on that date (intermittent nightly-channel coverage gap). The first Linux build job failed and `fail-fast` cancelled everything else, so no v0.15.6 binaries shipped. v0.15.7 reverts the workflow's BPF build step; Linux release tarballs ship with the `ebpf` feature compiled in but the BPF object missing, so `EventSource::new` returns `BpfObjectMissing` at runtime and netwatch falls back to lsof/ss attribution. macOS PKTAP is unaffected. The actual BPF-shipping fix is now blocked on bumping the SDK's pinned nightly (and ideally the SDK starts shipping the pre-built `.o` on crates.io directly).

## [0.15.6] - 2026-05-10

### Added
- **Kernel-level Linux process attribution via netwatch-sdk eBPF** — On Linux, netwatch now loads a `tcp_v4_connect` kprobe (via [`netwatch-sdk`](https://crates.io/crates/netwatch-sdk) Phase 1) that captures `(pid, comm, src/dst, dst_port)` for every outbound TCP connect at kernel time. The Connections collector overlays those attributions onto rows from `ss`/`lsof` polling — same shape as the macOS PKTAP integration — which catches sub-2-second flows that polling misses and reports the actual *thread* `comm` rather than the parent binary's name. The Connections header now shows `attribution: ebpf` (green) when the kprobe is loaded or `attribution: lsof — ebpf unavailable: …` (warn) with the specific reason when it fell back; the per-row bullet glyph swaps to `◉` for kernel-attributed rows. Requires `CAP_BPF` + `CAP_PERFMON` (or root) and kernel ≥ 5.10. The Linux release tarballs ship with the BPF object pre-embedded (the release workflow runs the SDK's `scripts/build-ebpf.sh` and builds netwatch against a `[patch.crates-io]` override that picks up the artifact). For `cargo install netwatch-tui` users on Linux, eBPF currently falls back to `BpfObjectMissing` until the SDK starts shipping the BPF object on crates.io directly — a separate piece of work.

### Changed
- The `ebpf` feature is now on by default. Builds gracefully fall back to lsof/ss attribution when the platform can't load eBPF — non-Linux hosts (returns `UnsupportedPlatform`), missing capabilities, kernel < 5.10, or the BPF object isn't embedded. macOS continues to use PKTAP for its kernel-attribution path; both sources flip `Connection.attribution` so the renderer can flag them uniformly.

## [0.15.5] - 2026-05-10

### Added
- **Reliable QUIC SNI extraction (RFC 9001 + RFC 9369)** — The Packets tab now decrypts QUIC v1 and v2 Initial packets per the spec and surfaces the embedded TLS ClientHello's `server_name` extension on the row. Previously netwatch had a heuristic that scanned the Initial payload for a cleartext ClientHello pattern, which doesn't work because real Initials are AEAD-protected with keys derived from the Destination Connection ID; that heuristic always returned `—` on real-world traffic. The new implementation does the full HKDF-Expand-Label key derivation, AES-128 header protection removal (via `ring::aead::quic`), AES-128-GCM payload decryption, and CRYPTO frame reassembly. Verified against RFC 9001 Appendix A.1 (key derivation byte-match) and Appendix A.2 (full sample packet → `example.com` SNI). Lives in the new `src/collectors/quic.rs` module; `ring 0.17` promoted from transitive to direct dep.

## [0.15.4] - 2026-05-10

### Fixed
- **Second memory-leak source for non-sudo Linux runs** — `TrafficCollector::interfaces()` was deep-cloning the full per-interface state (including each interface's two 600-sample history `VecDeque`s) on every call, ~96 KB per call on a 10-interface host. The Dashboard alone hit it 4 times per render and `App::tick()` another 6, totalling ~10 calls/sec ≈ 1 MB/sec of allocation churn. On Linux, glibc's per-thread arena retention turns that churn into climbing RSS even though no logical leak exists in the data structures. The accessor now returns `Arc<Vec<InterfaceTraffic>>` and `update()` swaps in a fresh `Arc` each tick — reads are a single atomic refcount bump regardless of interface count or history depth. `har5ha` reported continued RSS climb on v0.15.3 (~115 MB after 90 min on Dashboard-only); this addresses the source the v0.15.1 packet-pipeline fix couldn't reach because pcap is dormant without root. Reported in #27.

## [0.15.3] - 2026-05-09

### Added
- **Kernel-level process attribution on macOS via PKTAP** — netwatch now opens xnu's `pktap` pseudo-device alongside the regular packet capture (when running with sudo) and harvests `(pid, comm, direction)` straight from the kernel for every captured frame. The Connections, Dashboard, Topology, Timeline, and Insights tabs all consume this attribution, so short-lived flows that close inside one lsof poll window — `curl` to a CDN, a DNS query, an mDNS announcement — now show the real owning process instead of `—`. Threaded processes whose `comm` differs from the parent get the actual thread name rather than the parent binary's. Falls back to the existing lsof/ss/netstat polling path when PKTAP can't be opened (no root, non-Apple libpcap, kernel feature missing); attribution source is tracked per-row via a new `AttributionSource` enum (`Lsof` default, `Pktap` after kernel overlay).
- **`pktap_probe` example** — `sudo cargo run --example pktap_probe` prints attributed events as they arrive, useful for confirming PKTAP works on a given macOS build before turning on the full TUI.

### Fixed
- **PKTAP attribution on macOS 15+** — Apple renamed the libpcap symbol used to enable per-packet metadata: macOS 14 and earlier exported `pcap_set_want_pktap_pktmetadata`, macOS 15 dropped that and exports the shorter `pcap_set_want_pktap` instead. The dlsym lookup now probes both names so the same build picks up attribution across older and newer macOS without a recompile. Surfaced when the probe failed with `pcap_set_want_pktap_pktmetadata not found` on macOS 15.4.1.

## [0.15.2] - 2026-05-07

### Fixed
- **Refresh-rate setting now hot-reloads** — Changing `Refresh Rate (ms)` in the Settings popup used to require a restart because `EventHandler` captured `tick_rate` once at construction. The polling thread now re-reads an `Arc<AtomicU64>` each iteration and a saved change takes effect on the next poll cycle.
- **Filter-aware connection selection (#26)** — Under an active connection filter, `PgDn`-to-bottom left `connection_scroll` clamped against the *unfiltered* list while the table rendered the filtered list, so subsequent `UpArrow` looked stuck and mouse clicks on visible rows did nothing. All five clamp/select sites (PgDn, mouse click, `W`/`T`/`Enter` action handlers) now route through `connections::filtered_sorted_conns(app)` so the rendered view drives selection bounds.

### Changed
- **Dots graph style narrower per-sample** — One filled sub-column per sample window instead of both, with the area-fill below each sample's peak preserved. Gives the classic btop "comb" look with visible gaps between samples.

## [0.15.1] - 2026-05-05

### Fixed
- **Memory leak under sustained packet capture** — `StreamTracker` retained every unique flow for the lifetime of the process, and the per-IP `rtt_history` map plus the `rtt_sampled_streams` set grew without bound alongside it. On a busy host this drove RSS into the 1 GB+ range after roughly an hour. Stream storage is now an LRU map capped at 1024 flows (with a 256-entry watermark), `rtt_history` keys are bounded to 256 remote IPs (FIFO eviction), and the sampled-streams set self-prunes against the live tracker on every visit. The per-tick deep-clone of all streams in the RTT sampler is also gone, replaced with an in-place visitor. Reported in #27.
- **`g` toggle on the Connections tab now actually shows GeoIP** — `app.show_geo` was wired to the keybinding but only the Packets tab read it. Connections now renders a `GEO` column (country code plus city when available) between REMOTE and STATE while the toggle is on. Reported in #27.

## [0.15.0] - 2026-05-04

### Added
- **Selectable graph styles** — A new `Graph Style` setting (Settings → ←/→) cycles between `bars` (the existing solid-color stacked-block sparkline) and `dots` (a btop-style braille pixel-fill that gives 4× vertical resolution per cell). Persists to `~/.config/netwatch/config.toml` alongside the theme. Applies to every chart in the app — dashboard throughput, interface detail chart, top-connections row sparklines, RTT history, processes RX, stats throughput, and the timeline activity strip.

### Changed
- **All sparklines route through a single `graph::render` helper** — Per-call-site `Sparkline::default().data().style()` is replaced with `crate::graph::render(...)`. The timeline's three-color severity overlay shares a y-axis via `graph::render_with_max(...)` so layers stay aligned regardless of style. `dots` skips zero samples so flat-zero spans render nothing instead of a baseline floor — keeps stacked overlays clean.

## [0.14.1] - 2026-04-29

Re-spin of v0.14.0 to correct version metadata. The v0.14.0 commit on
the tag was missing the Cargo.toml/Cargo.lock bump and CHANGELOG entry
(staging mistake), so the binaries shipped under v0.14.0 reported
themselves as `0.14.0-rc.3` internally and `cargo publish` rejected the
duplicate. v0.14.1 ships the same feature set with consistent version
metadata across all release channels.

No code changes vs. the intended v0.14.0 — the whole "what's new"
section below applied to that release and applies here.

## [0.14.0] - 2026-04-29

### Added
- **Topology view, redesigned** — Local addresses (this host + LAN peers) anchor the left side of the graph, public Internet peers on the right, with ROUTER → ISP as the spine in the middle. Each spine box has a colored health dot pinned to its trunk so router/ISP status is visible at a glance. PR #24.
- **Auto-traceroute on launch** — A one-shot traceroute to `1.1.1.1` is kicked at startup so the ISP gateway hop populates the topology view without requiring the user to press T. Manual `T` against the selected remote still works.
- **Real RTT and CPU on Processes tab** — Per-process kernel RTT (min across the process's TCP connections) and CPU% are now wired through to the Processes tab, with rolling history sparklines.
- **Timeline detectors** — Timeline flags RTT spikes and interface flap events as discrete activity entries.

### Changed
- **Whole-app design pass** — Dashboard, Connections, Interfaces, Packets, Stats, Topology, Processes, and Insights tabs reworked around the v0.14 design pack. Visual hierarchy, typography, and color usage are now consistent across tabs.
- **Throughput sparkline fills wide terminals** — Sparkline history was capped at 60 samples (60s @ 1Hz) but the chart could render ~94 cells on a 1200-px terminal, leaving ~36% empty space on the left. History is now capped at 600 samples (10 min). The throughput chart title reflects what's actually drawn (`last 60s` on narrow terminals, `last Nm` on wider ones).
- **Throughput KPI trend window stays short** — Even with the history extension, the KPI tile's trend arrow continues to compare only the most recent ~minute, so the arrow stays responsive instead of smoothing across the full 10 min.

### Notes
First non-RC tag in the 0.14 line. Stable `cargo install netwatch-tui` and `brew upgrade` will both pick this up; `0.14.0-rc.1`/`-rc.2`/`-rc.3` remain on crates.io for anyone pinning to a specific RC.

## [0.13.0] - 2026-04-23

### Added
- **Per-tab sort picker** — Press `s` on Dashboard, Connections, Interfaces, or Processes to open a sort picker overlay. Navigate with `↑↓` or `j/k`, `Enter` to apply, `S` to toggle ascending/descending, `/` to filter columns by name, `Esc` or `s` to close. Each tab remembers its own sort state. Dashboard and Interfaces sort once at render so the sparkline and the table stay index-aligned. #20, #21
- **Comprehensive sort test coverage** — ~38 new tests covering per-tab sort integration, `cmp_ip_addr` (IPv4/IPv6/brackets/wildcards/port tiebreakers), `cmp_f64` (NaN-safe via `total_cmp`), case-insensitive comparators, picker cursor/filter edge cases, and meta-tests that fail CI if a new column is added without a matching comparator arm. #22
- **Vim-style navigation keys** — `j`/`k` alias `↓`/`↑` for list/stream/help/settings scrolling; `h`/`l` alias `←`/`→` for settings theme and default-tab selectors. Arrow keys continue to work unchanged. Stream view's existing `h` (toggle hex/text mode) is preserved. Fixes #18.

## [0.12.5] - 2026-04-21

### Changed
- **Case-insensitive process-name sort in Connections** — The Connections tab's Process column now sorts case-insensitively, so `Finder`, `facetime`, and `kernel_task` interleave in dictionary order instead of splitting into two alphabetical runs. Case-only differences use byte-wise order as a deterministic tiebreaker. Fixes #16.

### Removed
- **Misleading `s:Sort` hint on Processes tab** — The hint was never wired up (the Processes tab is always sorted by total bandwidth descending via the bandwidth ranker) and is gone from the footer.

## [0.12.4] - 2026-04-21

### Changed
- **Default Tab setting is now a cycler** — The "Default Tab" row in the Settings popup (`,`) now cycles through valid tabs with `←` / `→`, mirroring the Theme row. Previously it was a free-text field that required knowing (or guessing) the tab names, and the error hint listing valid values could get truncated at narrow terminal widths. Fixes #17.

## [0.12.3] - 2026-04-19

### Changed
- **Ocean theme — readable group-box borders** — In addition to muted text, group-box borders and separators now use the lighter `#B5B6B7` neutral so panel outlines stay legible on the `#224FBC` background.

### Reverted
- **Dashboard single-interface collapse** — The v0.12.2 behaviour that hid the Interfaces table on single-interface systems is reverted. In practice almost every machine has `lo0` and other virtual interfaces alongside the physical one, which are useful for diagnostics, so hiding the table was rarely correct.

## [0.12.2] - 2026-04-18

### Changed
- **Ocean theme — readable muted text** — `text_muted` in the Ocean theme is now a lighter neutral (#B5B6B7) so secondary labels (group headers, units, etc.) are legible against the `#224FBC` background. The previous value (Apple's bright-black slot, #818383) failed WCAG AA contrast.
- **Dashboard hides Interfaces panel when only one interface exists** — On single-interface systems, the Interfaces table collapses and Top Connections expands to fill the reclaimed space, showing more rows.

## [0.12.1] - 2026-04-18

### Added
- **Ocean theme** — New color theme tuned for Terminal.app's "Ocean" profile (bg #224FBC). Uses Apple's default Terminal ANSI palette values for legibility on the deep blue background. Set `theme = "ocean"` in `~/.config/netwatch/config.toml` or switch via Settings (`,`).

### Changed
- **Integer byte/rate formatting** — Byte totals and transfer rates now display as integers (e.g. `42 MB/s` instead of `42.3 MB/s`). Decimals rarely contained significant signal and added visual noise.
- **Zero values render as `-`** — Empty rates and zero totals show a dash instead of `0 B` / `0 B/s`, reducing noise in tables where many rows are idle.
- **Right-aligned numeric columns** — Rate and byte columns in Dashboard, Interfaces, Processes, and Stats tabs are now right-aligned to fixed widths, so unit suffixes stay put across rows instead of jumping as values change.

## [0.12.0] - 2026-04-18

### Added
- **Per-connection Down/Up column** — The Connections tab now shows live RX/TX rates per flow, sourced from the ambient packet capture. Sort by throughput with `s` to find the busy connection, then `Enter` to drill into its packets.
- **Ambient packet capture at launch** — NetWatch now starts capture automatically on startup (using the configured interface and BPF filter, if any). Connection rates are populated as packets arrive. If capture fails for lack of privileges, the app continues running with the Down/Up column blank.

### Changed
- **BPF filter is now config-only** — The `b` keybinding for live-editing the BPF capture filter on the Packets tab has been removed. Set a BPF filter in Settings (`,`) → BPF Filter if you need one; it applies at launch. The display filter (`/`) is unaffected.
- **Disk metrics exclude macOS internal mounts** — Remote disk metrics now skip `/Volumes/`, `/System/Volumes/`, and `/private/` mounts so APFS firmlinks no longer appear as duplicate rows.

## [0.11.3] - 2026-04-17

### Fixed
- **Processes tab empty on Linux** — Linux `ss` outputs `ESTAB` instead of `ESTABLISHED`, causing the processes and top connections tabs to show zero entries. The parser now normalizes the state at parse time.
- **Windows UI responsiveness** — Moved interface stat collection to a background thread so key bindings no longer block for 5–30 seconds on Windows.
- **Atomic ordering** — Relaxed traffic collector busy-flag from `SeqCst` to `Acquire`/`Release`.

## [0.10.0] - 2026-04-11

### Added
- **AI Insights tab** — Restored as an opt-in feature (off by default). Enable in Settings (`,`) → AI Insights: on. Analyzes live packet data and network state every 15 seconds and surfaces security concerns, performance issues, and anomalies as bullet-point summaries.
- **Configurable AI endpoint** — Supports local Ollama (`local`, default) and any remote endpoint (Ollama Cloud or custom proxy) via the AI Endpoint setting. Point it at a cloud URL to skip local model setup entirely.
- **AI settings in the Settings overlay** — Three new settings: AI Insights (on/off), AI Model (default: `llama3.2`), AI Endpoint (`local` or a full base URL). Changes apply live without restart.

### Changed
- **Tab count** — Tab [9] Insights appears in the header only when AI Insights is enabled. The zero-config experience for users who don't enable it is unchanged.

## [0.9.0] - 2026-04-03

### Added
- **Flight Recorder** — Rolling 5-minute incident capture that records packets, connections, health snapshots, DNS analytics, bandwidth context, and network-intel alerts.
- **Incident bundle export** — `Shift+E` exports a bundle containing `summary.md`, `packets.pcap`, `connections.json`, `health.json`, `bandwidth.json`, `dns.json`, `alerts.json`, and `manifest.json`.
- **Manual and automatic freeze** — `Shift+F` freezes the current incident window, and critical network-intel alerts now auto-freeze an armed recorder so transient failures are preserved.

### Changed
- **Global recorder status in header** — NetWatch now shows `REC 5m` while armed and `FROZEN` after a capture window is locked.

## [0.8.1] - 2026-03-30

### Removed
- **AI Insights tab** — Removed the Ollama-dependent Insights tab. NetWatch is a sharp network tool, not an AI wrapper. The tab required external setup (Ollama + model download) that broke the zero-config promise for 95% of users.

### Changed
- **Tab count reduced from 9 to 8** — Cleaner navigation: Dashboard (1), Connections (2), Interfaces (3), Packets (4), Stats (5), Topology (6), Timeline (7), Processes (8).
- **README rewritten** — Shorter, sharper, sells the product. Install instructions above the fold. Detailed keybindings collapsed. Platform badge is honest (macOS + Linux only).
- **Hardened error handling** — Fixed `unwrap()` calls in production code paths to prevent panics on unexpected input.

## [0.8.0] - 2026-03-14

### Added
- **Processes tab** — Per-process bandwidth ranking with RX/TX rates, connection counts, and totals
- **JSON/CSV export** — Export connection data from the Connections tab
- **CI/CD pipeline** — GitHub Actions with cross-compilation for Linux (x86_64/aarch64), macOS (x86_64/aarch64), and Windows
- **Homebrew formula** — `brew install matthart1983/tap/netwatch`
- **Clippy + fmt enforcement** in CI

## [0.7.0] - 2026-02-28

### Added
- **AI Network Insights** — Ollama integration with auto-analysis every 15s
- **Connection Timeline** — Gantt-style connection lifetime visualization
- **Network Topology** — ASCII network map with health indicators
- **Traceroute** — Built-in hop-by-hop traceroute from Topology or Connections
- **Network Intelligence** — Port scan detection, beaconing detection, DNS tunnel detection
- **TCP handshake timing** — SYN→SYN-ACK→ACK latency measurement
- **Handshake histogram** — Latency distribution in Stats tab
- **Display filters** — Wireshark-style filter syntax with combinators
- **BPF capture filters** — Applied at capture time for efficient filtering
- **Stream reassembly** — TCP/UDP conversation view with text and hex modes
- **Expert info & coloring** — Automatic severity classification
- **Packet bookmarks** — Mark and jump between packets of interest
- **PCAP export** — Save captures to standard .pcap files
- **Protocol statistics** — Protocol hierarchy table
- **5 color themes** — Dark, Light, Solarized, Dracula, Nord with instant switching
- **Settings menu** — Live configuration editing with TOML persistence
- **Mouse support** — Clickable tabs, scroll wheel, row selection
- **GeoIP** — Online + offline MaxMind .mmdb support
- **Whois/RDAP** — On-demand IP lookup
- **Latency sparklines** — Per-connection RTT trend visualization

## [0.1.0] - 2025-11-05

### Added
- Initial release
- Dashboard with live interface stats and bandwidth sparklines
- Connections table with process attribution
- Interface detail view
- Network health probes (gateway + DNS)
- Packet capture with protocol decoding (DNS, TLS, HTTP, ICMP, ARP, DHCP, NTP)
- Cross-platform support (macOS, Linux)
