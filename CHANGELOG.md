# Changelog

All notable changes to NetWatch will be documented in this file.

## [Unreleased]

### Added
- **Drift adjudication — the Egress tab now says what a drifting destination
  appears to *be*, not just that it drifted.** The linter already decided, in
  code, that a destination sits outside a process's allowlist. What it couldn't
  say was whether that destination is a CDN the vendor uses, routine telemetry,
  or a paste site — a judgment you previously made by eye, one row at a time,
  which is why a long drift table got skimmed rather than worked.

  Two tiers answer it. A shipped catalog of 66 well-known destinations —
  package registries, CDNs, certificate infrastructure, NTP, OS vendors,
  telemetry, inference APIs — resolves the boring majority with no network and
  no model, and `netwatch --egress-catalog` prints the whole table, because a
  label you can't inspect is a label you can't trust. Hostname matching is
  label-boundary aware: `evil-github.com` and `github.com.evil.io` do not match
  `github.com`, so a benign label can't be bought for the price of a domain
  registration.

  For the tail the catalog can't resolve, an optional local model over Ollama.
  Off unless you turn it on with `[adjudication] model = true` in
  `egress-policy.toml`, and **loopback only** — a non-local endpoint spawns no
  client and no thread. The analysis never leaves the box; that is the point,
  not a default to override.

  The model never detects. Drift is decided in code, as before, and a label may
  only ever make a row *louder* — a classifier that tries to talk a row down is
  ignored. Its input is treated as hostile, because it is: hostnames are chosen
  by whoever registered the domain, so values are stripped of control and fence
  characters, delimited, and declared untrusted, and text inside them that reads
  like an instruction counts as evidence *for* the `suspicious` label. Responses
  are parsed against a strict schema and discarded on any deviation — a parse
  failure leaves the row unclassified rather than defaulting it to benign.
  Inference runs on its own thread with a bounded queue, one call in flight, a
  hard timeout, a per-session ceiling and a backoff after failure, so a slow or
  absent model costs a blank column and never a dropped frame.

  Verdicts are cached to `egress-verdicts.json` and invalidated by a model or
  prompt change. Catalog verdicts are deliberately *not* persisted — they are
  free to recompute, and a stale file shouldn't outlive the table entry that
  justified it.

### Changed
- Egress NDJSON export is now schema `netwatch.egress.v1.2`, adding `label` and
  `label_source`. Additive and optional; both are omitted when nothing has
  judged a destination. `verdict` says whether a destination was *declared*;
  `label` says what it appears to *be*. Consumers need both — "undeclared" and
  "suspicious" are very different findings.

## [0.29.2] - 2026-08-16

### Fixed
- **Windows: a default Npcap install failed with "wpcap.dll was not found"**
  ([#47](https://github.com/matthart1983/netwatch/issues/47)). Npcap 1.x puts
  its DLLs in `%SystemRoot%\System32\Npcap\` rather than `System32`, so they sit
  beside a WinPcap install instead of replacing it — and that subdirectory is
  not on the loader's search path. NetWatch imported `wpcap.dll` at load time,
  so the process died before `main()` against a Windows message box, and the
  only cure was reinstalling Npcap with *Install Npcap in WinPcap API-compatible
  Mode* ticked, which is off by default. The documented procedure — install
  Npcap, run NetWatch — therefore didn't work.

  `wpcap.dll` is now delay-loaded, and at startup NetWatch adds Npcap's own
  directory to the DLL search path and loads the library itself, the way
  Wireshark and nmap handle the same layout. A stock Npcap install works with no
  checkbox; a machine with no Npcap gets a message naming what to install and
  where to get it, instead of a modal from the loader. `--version` and `--help`
  now answer on a machine without Npcap too — they resolve before the check,
  and previously died with everything else.

## [0.29.1] - 2026-08-15

### Fixed
- **The Dense connection table reordered under the cursor.** Rows sorted on the
  instantaneous rate, and a single sample at the default tick is noise, so two
  flows of similar speed traded places constantly — measured at three swaps in
  five ticks with two active downloads. Because the selection is positional,
  every swap silently retargeted the detail block above to a different
  connection, so the panel changed what it was describing while you read it.
  The table now sorts on each flow's recent average instead. That is also the
  more honest answer to "which flow is busiest", and it matches the column the
  header claims to sort by. A genuinely faster flow still sorts above a slower
  one; only the noise is filtered.

## [0.29.0] - 2026-08-11

### Added
- **Dense view** (`--view dense`, or `V` to cycle, or Settings → View). A
  third answer to "how much terminal do you have": Lite spends 80×24 on one
  question, the tabbed TUI spends ten tabs on ten, and Dense spends a large
  terminal on showing everything at once — four boxes, no header bar, no menu
  bar, no status bar. Identity, sort state, page range and every keybind live
  inside the box borders, so every row carries data. It needs 130×44 as a
  floor and grows into whatever it is given: wider means more history in the
  plots and room for full hostnames, taller means more interfaces and more
  connections. Below the floor it falls back to the same 80×24 grid Lite
  targets, and it never scrolls sideways. The full TUI remains the default at
  every terminal size.
- **The mirrored dual graph.** Download grows up from a centre time axis,
  upload grows down from the same axis. Traffic symmetry becomes a shape you
  recognise without reading a number — a download burst is a cliff above the
  line, a backup job is a cliff below it. Both halves are braille at two
  samples per character cell, and every cell is coloured by its height in the
  plot rather than by which series it belongs to, so a spike's severity is
  pre-attentive. The plot carries one sample per sub-column and shifts by
  exactly one per tick, so it scrolls rather than re-bucketing in place, and
  its ceiling snaps to 1/2/5 × a power of ten — the scale moves when the
  traffic does, not every time the peak drifts a few percent.
- **A split colour vocabulary.** Throughput ramps cool→bright because high
  bandwidth is *busy*, not *bad* — a saturated link during a backup is
  working. Only bounded values where high genuinely is bad (link saturation,
  per-hop latency budget) get green→amber→red, and their meters colour by
  position along the bar, so the red zone is visible before you reach it. Red
  on a bandwidth graph would cry wolf every time you downloaded something.
  Palette-deferring themes collapse every ramp to a flat token by design,
  rather than synthesising 24-bit colour the theme exists to avoid.
- **Kernel TCP state per connection** — `cwnd`, `ssthresh`, `mss`, `rwnd` —
  in the Dense detail row, from `inet_diag` over netlink on Linux and the
  `net.inet.tcp.pcblist64` sysctl on macOS. Throughput tells you what
  happened; `cwnd` against `ssthresh` tells you whether you are in slow start
  or congestion avoidance, and a `cwnd` pinned small next to a healthy `rwnd`
  distinguishes "the network is congested" from "the peer isn't reading".
  The two kernels disagree about units — Linux counts segments, BSD counts
  bytes — so macOS values are normalised against the MSS and the column means
  one thing on both. They also spell "threshold not set" differently
  (`i32::MAX` against BSD's `0x3FFF_C000`); both render `∞`. Windows reads
  `--` until `GetPerTcpConnectionEStats` is wired up.
- **Link speed detection**, from `/sys/class/net/*/speed` on Linux and
  `ifi_baudrate` via `getifaddrs` on macOS, giving the saturation meter a real
  ceiling to measure against. The ceiling is never allowed below throughput
  actually measured on the link: a driver claiming the link is slower than
  traffic it has already carried is wrong, and macOS reports `ifi_baudrate`
  for Wi-Fi as the idle MCS — one machine advertised 304 Mb while sustaining
  456 Mb/s over it. The label names which ceiling is in play, because
  "of 1 Gb link" and "of 472 Mb seen" are different claims.
- `V` cycles full → lite → dense from any view; `--view <name>` selects one
  for a single run; **Settings → View** sets the default, live. `L` and
  `--lite` are unchanged.
- **A recorded demo** (`docs/media/demo-dense.gif`, now leading the README)
  with its tape and traffic generator checked in, so it can be re-recorded
  rather than only replaced. The generator uploads as well as downloads — a
  download-only workload leaves the mirrored graph's lower half flat, which
  would record the headline feature as half a graph.

### Fixed
- **`apply_edit` matched settings rows by bare integer** rather than by the
  `cursor::` constants that exist to name them, so inserting any row silently
  re-pointed every editor below it at the wrong setting. Latent until this
  release added one; now keyed by the constants, with a test that walks each
  named cursor to its own field.

## [0.28.2] - 2026-08-10

### Added
- **CIDR blocks in `allow_ip`.** The rule language could only name an exact
  address. `allow_ip` exists for destinations that carried no name — no
  ClientHello SNI, no resolved ASN — and those are disproportionately the ones
  behind cloud ranges that renumber, so declaring them meant enumerating
  addresses that change underneath the policy. `10.0.0.0/8` and
  `2001:db8::/32` now work alongside exact addresses. A malformed pattern
  matches nothing rather than everything: an allowlist that fails open on a
  typo silently admits what it could not parse.
- **A tour that includes the Egress tab** (`demo-tour.gif`, re-recorded) and a
  dedicated **`demo-egress.gif`** showing the whole observe → promote → warn
  loop against live traffic. Both now have tapes checked in, so they can be
  re-recorded rather than only replaced. The tour dropped from 9.2 MB to
  2.8 MB.

### Fixed
- **The Egress summary said "all precise" while a drift row was on screen.**
  The tally counted undeclared, unchecked and ASN-wide destinations but never
  drift, so a screen whose only finding was drift rendered a green
  "all precise" directly above a red `✗ drift` row — in both the header and
  the panel title. A reassuring summary contradicting the alarming detail is
  the one failure mode a policy linter cannot afford.
- **`S` did nothing on the Egress tab.** It reverses the sort on every other
  sortable tab; Egress had no entry in the sort state, so the key was silently
  inert. It now reverses, and the tab's natural order is documented as
  descending — every one of its modes is "most interesting first".
- **Exports resolved `$HOME` directly** instead of `dirs::home_dir()`, which
  the rest of the codebase uses. `HOME` is normally unset on Windows, where
  the old fallback quietly wrote incident bundles, PCAPs and egress exports
  into the working directory.
- Duplicate `space` entry in the Egress section of the help panel.

### Changed
- **`s` on the Egress tab opens the sort picker**, like the four other
  sortable tabs, instead of silently cycling through modes. One key meaning
  two different things was a trap for anyone with muscle memory from the rest
  of the app. The picker's columns are declared in sort-mode order with a test
  asserting the two cannot drift — a mismatch would sort by the wrong mode
  with no error and no panic.
- **The egress policy model moved to its own module** (`collectors/egress/
  policy.rs`). It has no dependency on the profiler and is the one part of
  netwatch that is a security control rather than an observation: a bug there
  does not produce a wrong number, it silently admits traffic that should have
  been reported. 520 lines that can be reviewed without the other 3,200.
  Re-exported, so no caller changed.
- Property tests for the SNI matcher — reflexivity, case, wildcard depth, and
  the neighbours a wildcard must never admit — plus mask monotonicity for the
  new CIDR matcher. Both were scoped in the egress plan and had not landed.

## [0.28.1] - 2026-07-29

### Added
- **Grouped trees on Connections and Egress.** `group: process` and
  `group: remote` were sort orders wearing the word "group" — rows clustered,
  but the key was restated on every one, so the widest column repeated the
  string above it and the process name was truncated to `Google Chrome…` for
  want of space. Both tabs now render one parent row per group carrying a
  rollup, with foldable children. 63 connections read as 13 processes.
- **Groups start folded**, so a tab opens on the overview rather than the
  detail. `z` folds or expands everything; `space` folds the group under the
  cursor, from a child row as well as its header. Configurable via
  `groups_start_collapsed` (default true) or the settings screen's
  "Groups Start Folded".
- **Byte accounting on Egress.** Destinations accumulate `bytes_out` /
  `bytes_in` plus a per-tick series for an inline sparkline, from rates the
  connection table already computed and discarded. An egress-forensics tab
  could not previously answer *how much data left this machine*.
- **A verdict vocabulary that distinguishes precision from breadth** —
  `✓ sni` / `✓ ip` (an endpoint), `~ asn` (an entire autonomous system),
  `? ech`, `✗ drift`, `— no rule`, `✗ undeclared`. Plus `s` sort (including
  **risk**), `/` filter, `d` detail pane and mouse support.
- **`strict = true` in `egress-policy.toml`.** Treats the policy as complete,
  so a process with no rule becomes a finding rather than a blind spot.
  Off by default. Without it the linter cannot see the one thing a compromise
  actually introduces — a binary nobody declared.
- **Remove a process from the policy** (`x` / `Del`, confirmed with `y`).
  Promotion could only ever grow an allowlist; withdrawing coverage meant
  editing the file by hand. Deletion preserves comments, unrelated rules, the
  `strict` flag and `0600` permissions, and refuses an unparseable file.

### Changed
- **Promotion no longer widens a rule to an autonomous system.** It wrote an
  `allow_asn` entry for any destination without an SNI, and a rule admits on
  *any* dimension — so one nameless hyperscaler flow at promote time admitted
  every host that AS operates, for that process, permanently, rendering
  `✓ ok`. Identity now comes from the SNI or the address. On a real
  25-process baseline this took rules with an ASN-wide entry from **12 of 25
  to 0**, and admitted (destination, port) pairs from 282 to 245.
  Hand-written `allow_asn` rules still match; nothing generates one.
- `Unassigned` — the geo database's *failure* label — is never promoted as an
  identity. Allowlisting it admitted every destination whose ASN lookup failed.
- The NDJSON export gains `undeclared` as a distinct verdict rather than
  folding it into `drift`; nothing was compared, so `drift` would overstate
  what the linter knows.

### Fixed
- **Egress `Seen` was a duration wearing a counter's clothes.** `observe` runs
  once per tick and incremented per tick a flow was present, so `31427` meant
  *open for 8.7 hours*, not 31k requests. Now rendered as a duration and
  labelled `Active`.
- Connections' UDP rows carry an empty state, so a group's dominant-state cell
  counted `""` as the winner and rendered a bare `11/13` — a fraction of
  nothing. Only named states compete.
- Removing the only rule from a policy file emptied it completely, taking the
  header that documents `strict` and promotion with it.
- `✗ undeclared` truncated to `✗ undeclare` in the Egress verdict column.
- Policy-edit status messages were invisible on the Egress tab: they render in
  the shared header slot, which the tab bar consumes at any ordinary width.

## [0.28.0] - 2026-07-28

### Added
- **Lite view (`--lite`, or `L` to toggle).** A single 80×24 screen for the
  one-machine case — throughput charts, gateway/DNS/internet reachability, and
  top talkers by process and host, with six keys. It shares the full TUI's
  collectors, so toggling between the two keeps all history. Also gives the
  small-terminal case a coherent rendering: the full TUI has no global minimum
  size and degrades silently below ~130×36.
- **Internet reachability probe.** `HealthStatus` gains `internet_rtt_ms` /
  `internet_loss_pct`, probing 1.1.1.1 with the same ICMP→TCP fallback the
  gateway probe uses. Distinguishes "the router is fine but the line is down"
  from "the router is down" — gateway and DNS alone can't tell those apart.

### Fixed
- **The `dots` graph style now renders a filled area instead of a sparse dot
  matrix.** `render_dots` lit only the left sub-column of each braille cell —
  the right-hand constant was declared but never used — so the "btop-style
  braille area plot" looked half-empty everywhere it was drawn. Affects every
  chart when `graph_style = "dots"`.
- Lite honours the app-wide `graph_style` / `graph_fade` settings. Its charts
  and sparklines previously hardcoded block glyphs and ignored both.

## [0.27.0] - 2026-07-26

Process identity becomes stable enough to key a policy on, and the egress linter
stops reporting drift it invented. Plus a theme for people who already have a
system-wide color scheme. (#44)

### Added
- **`terminal` theme — defers entirely to your terminal's palette.** For anyone
  running pywal, matugen, or a tuned terminal profile who wants NetWatch to follow
  along rather than impose its own colors. `dark` was already close (ANSI named
  colors, `bg: Reset`); this goes further where theme-matching actually breaks:
  `text_primary` is `Reset` (your exact configured foreground, not the white slot)
  and both selection backgrounds drop fixed RGB for `Indexed(8)`. Nothing in the
  theme pins an RGB value — a test enforces that. Accepts `system` and `ansi` as
  aliases. `dark` remains the default.
- **Security policy** (`SECURITY.md`): private reporting channel and threat-model
  scope.

### Fixed
- **Process identity now derives from the executable, not `comm`.** Two separate
  instabilities made names unusable as a policy key: the kernel truncates `comm`
  (16 bytes on macOS, 15 on Linux), so `Google Chrome Helper` and
  `Google Chrome Helper (GPU)` both arrived as `Google Chrome He`; and `lsof`
  reports the executable's filename, which for version-installed tools *is the
  version* — Claude Code appeared under six different names on one machine, with
  every upgrade minting another and orphaning any policy promoted for it. Identity
  now comes from the executable path (`proc_pidpath` / `/proc/<pid>/exe`), falling
  back to the nearest meaningful parent directory when the file itself is named
  like a bare version. Not `argv[0]` — any process can set that, which would let a
  program inherit another's rules by renaming itself. Measured on live
  connections: 19 distinct names → 15.
- **Blank destinations no longer warn as drift.** Processes appeared as `✗ drift`
  with no destination and no IP, and a violation message reading literally
  " not in allowlist". Four compounding defects: `parse_addr_parts(":443")`
  returned `Some("")` instead of `None`; `is_private_ip("")` is false so `observe()`
  let it through both guards; `upsert` overwrote a known `last_ip` with an empty
  one; and `violation()` built its subject as `sni.or(asn).unwrap_or(ip)`, yielding
  an empty string. Existing baselines repair without a migration.
- **The same program is no longer profiled twice under truncated and full names.**
  PKTAP carries a kernel-truncated `comm` while `lsof` reports the full name, so
  whichever attribution source won a tick decided the profile key — on one machine
  `Google Chrome He` and `Google Chrome Helper` held 16 and 12 destinations with
  only 7 in common, so promoting one ratified a baseline the other immediately
  drifted against. Names now fold onto one key, with hit counts and violation
  tallies carrying across the merge. VS Code's genuine `Code Helper` correctly
  stays separate from the truncated `Code Helper (Plu`.
- The per-process destination cap silently dropped entries at load, resurfacing
  later as drift for traffic that was still happening. It now warns once per load
  with the counts.

### Changed
- Install docs point at homebrew-core, Nix, AUR and Scoop.

## [0.26.1] - 2026-07-04

### Fixed
- **Packet capture now defaults to the NIC carrying the default route.** (#43)
  On multi-NIC machines (e.g. motherboards with two Ethernet ports) the capture
  tab picked the first UP interface with an IPv4 in enumeration order, which
  could be the idle port. The interface with the default route is now preferred,
  with the old heuristic as fallback.
- **`i` (cycle capture interface) now works while capturing** — it restarts the
  capture on the new interface, keeping the packet buffer and active BPF filter.
  Previously it silently did nothing until you stopped capture with `c`. The
  Packets footer now advertises the key (`i:Iface`).
- Loopback is no longer offered when cycling capture interfaces (still
  selectable via the `capture_interface` config key).

## [0.26.0] - 2026-07-04

The **egress policy linter** (Horizon 3): NetWatch learns what each process on your
machine normally talks to, lets you ratify that baseline into a policy, and warns when
traffic drifts from it — observe → promote → warn. It warns, it never blocks. SNI is read
from the cleartext ClientHello, so meaningful policy works without decryption or a keylog.

### Fixed
- **Promoted processes now all read `✓ ok` — a rule admits its own baseline.**
  A process with a mix of named and nameless (raw-IP) destinations got a
  *name-restricted* rule from the named ones, and its raw-IP destinations then
  drifted against that very rule — so after promote some rows stayed `✗ drift`
  instead of flipping to `✓ ok`. Rules now carry an `allow_ip` dimension: a flow
  is allowed if **any** declared dimension (SNI, ASN, or IP) matches, so a
  nameless destination is admitted by its IP. Promotion captures those IPs.
- **Egress promote is now additive — it accumulates the full allowlist.**
  Promotion replaced a process's rule with only what was observed in the
  current session, so re-promoting (or promote-all after some destinations had
  aged out of the live baseline) could *shrink* the list. Promotion now unions
  the observed entries with those already in the file — prior promotes and
  hand-added entries both survive; ratification only ever grows the allowlist.
- **Egress promote now reliably takes effect.** A freshly-promoted
  `egress-policy.toml` written under a loose umask could be group/world-writable,
  which the policy loader then refused — so the promote appeared to do nothing
  (verdicts stayed `—`). Policy writes are now owner-only (`0o600`) and tighten a
  loose pre-existing file, and a failed reload is reported instead of claimed as
  success. The promote confirmation also persists its full display duration.

### Changed
- **Egress tab shows the real destination IP** in its own column — nameless
  destinations no longer collapse to a `(ip)` placeholder, and the IP is carried
  in the NDJSON export. Active drift warnings now render in a panel **on the
  Egress tab itself**, newest first, instead of only in the Timeline alert feed.

### Added
- **Egress policy linter (Horizon 3 foundation)** — observe → promote → warn:
  - **Egress tab** (`0`): per-process destination profiles (SNI / ASN org / port),
    learned live from the cleartext TLS/QUIC ClientHello — no decryption required.
    Scrollable, with a policy verdict column (`✓ ok` / `✗ drift`) once a policy is loaded.
  - **`Shift+P` promote**: ratifies the observed baseline into
    `<config_dir>/netwatch/egress-policy.toml` (`process → allow_sni / allow_asn /
    allow_ports`, exact or `*.wildcard` SNI patterns). Review-before-trust — human
    ratification defeats baseline poisoning.
  - **`PolicyViolation` alerts**: flows outside a declared allowlist raise a
    Warning-severity alert naming the broken rule, with a per-flow cooldown. Only
    processes with a rule are checked; the linter warns, it never blocks.
  - **Persistent baseline**: learned profiles survive restarts
    (`<state_dir>/netwatch/egress-profiles.json`, saved once a minute and at quit;
    Landlock allow-listed). Destinations not seen for 30 days age out at load.
    `First`/`Last` columns show how long each destination has been known.
  - **Selective promotion**: `Enter` promotes just the selected process, with a
    diff on the status line (`+2 SNI, +1 ports`). Promotion now **merges** into
    `egress-policy.toml` via `toml_edit` — hand edits, comments, and rules for
    other processes survive; an unparseable policy file is refused, never
    clobbered.
  - **Headless linting**: `netwatch daemon` evaluates the same policy, and
    violations surface as `netwatch_policy_violations_total{process}` on the
    Prometheus `/metrics` endpoint (bounded cardinality — only declared
    processes can appear).
  - **ECH-aware verdicts**: flows with Encrypted ClientHello show `? ech`
    instead of `✗ drift` when the miss may be "name unreadable, by design",
    and the alert text says so.
  - **Wildcard suggestions**: when ≥3 subdomains of one apex accumulate,
    promotion writes a `# suggestion: *.apex.tld would cover N entries` comment
    above the rule — suggested, never silently collapsed.
  - **Config**: `egress_violation_cooldown_secs` (default 300) controls the
    per-flow re-warn interval.
  - **Hardening**: a group/world-writable `egress-policy.toml` is refused with
    a loud warning — the policy file is a trust anchor.
  - **Structured export** (`e` on the Egress tab): writes attributed egress
    records as versioned NDJSON (`netwatch.egress.v1`) — one metadata-only JSON
    object per line (process, SNI, ASN, IP, port, proto, ECH, first/last-seen,
    count, policy verdict), preceded by a `_meta` schema line. No payload ever.

## [0.25.9] - 2026-06-27

Deeper protocol decoding, broader threat-detection coverage, and a round of reliability and
documentation improvements.

### Added
- **HTTP request path and response status** in the Packets view and connection labels.
- **DNS response codes** (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, …) in DNS decode output, e.g.
  `example.com (type=1, NXDOMAIN)`.
- **Per-connection TCP handshake RTT** (SYN→SYN-ACK), measured per flow.
- **Persistent-connection C2 detection** — beaconing analysis now also covers long-lived
  single-connection heartbeats, in addition to new-connection patterns.
- **Fuzz coverage** across the L7 protocol parsers.

### Improved
- More reliable DNS analytics — query/response latency, NXDOMAIN counts, and per-domain metrics.
- Greater packet-capture resilience under worker-thread failure.
- Quieter beaconing and DNS-tunnel alerting, with de-duplication and cooldowns; C2 beaconing now
  raises a Critical alert, which triggers the Flight Recorder auto-freeze.
- Memory-bounded detection caches.
- Sandbox support for a custom `tls_keylog_path`.
- More accurate multi-label domain grouping (e.g. `*.co.uk`, `*.com.au`).

### Documentation
- Expanded and clarified the protocol-decoding, eBPF attribution, sandbox, and TLS decryption
  references — including TLS 1.2 decryption support.

## [0.25.8] - 2026-06-20

### Added
- **eBPF Phase 2: IPv6 + connected-UDP process attribution.** Kernel-side connect attribution, previously IPv4 TCP only (`tcp_v4_connect`), now also covers IPv6 TCP (`tcp_v6_connect`) and **connected UDP — including QUIC** (`ip{4,6}_datagram_connect` and their `__`-prefixed inner workers). This closes the loop on "decrypt the QUIC flow **and** name the process that owns it": QUIC/UDP flows where the client `connect()`s its socket (browsers, quiche) are now attributed via eBPF instead of falling back to `/proc` polling that misses short flows. The attribution cache is keyed on `(protocol, daddr, dport)` so a TCP and a UDP flow to the same destination (e.g. both to `:443`) never cross-attribute. Both the datagram-connect wrapper and its inner are attached best-effort because kernel builds disagree on which is on the connect path (the other is inlined or absent); a double-fire is idempotent. **Unconnected UDP** (`sendto`/`sendmsg` without a prior `connect()`) is not yet attributed. Linux-only; degrades to lsof/ss attribution where the kernel won't load the probes.

## [0.25.7] - 2026-06-11

### Added
- **Passive TLS 1.2 application-data decryption.** Extends the SSLKEYLOGFILE-driven decryptor (previously TLS 1.3 + QUIC) to TLS 1.2 AEAD flows. The 48-byte master secret from a `CLIENT_RANDOM` keylog line, plus the `server_random` read off the ServerHello, feed the TLS 1.2 PRF (RFC 5246 §5) to derive the key block; records are then decrypted for AES-128/256-GCM (RFC 5288 — 8-byte explicit nonce + 4-byte fixed IV) and ChaCha20-Poly1305 (RFC 7905). It reuses the shared keylog store, background watcher, `decrypted:` display filter, and stream/detail rendering, so 1.2 flows surface through the same UI as 1.3. A flow's version is inferred from which keylog secret is present (`CLIENT_RANDOM` ⇒ 1.2, `*_TRAFFIC_SECRET_0` ⇒ 1.3), and per-direction sequence resync recovers when the keylog secret is ingested after the first records flow. Legacy CBC mac-then-encrypt suites remain out of scope. A live verification harness ships as `examples/tls12_decrypt_live.rs` (with `scripts/verify-tls12-decrypt.sh`).

## [0.25.6] - 2026-06-08

### Added
- **Headless agent / fleet mode (`netwatch daemon`).** Runs the same collectors as the TUI with no rendering and streams to a backend — the fleet-agent entry point. Flushes its buffered telemetry on SIGTERM/Ctrl-C before exiting; reports collector liveness (a thread-panic flag) so a stalled agent surfaces as degraded instead of going silently quiet. Ships `systemd` and `launchd` service units under `packaging/`. The interactive TUI is unchanged. Enable streaming with `--remote`/`--api-key` (or `NETWATCH_REMOTE_URL`/`NETWATCH_API_KEY` so the key stays out of `ps`).
- **Durable remote ingest.** The remote publisher is now at-least-once instead of fire-and-forget: a bounded, drop-oldest queue (≈8h buffer) that only drops a batch after the backend ACKs it, with exponential backoff + jitter and batched drains, so a network blip no longer silently gaps telemetry. Envelopes are versioned (`schema_version`) and carry `agent_health` (collector status, dropped count, queue depth).
- **Prometheus `/metrics` + `/healthz` exporter (daemon).** `netwatch daemon --metrics` (default `127.0.0.1:9464`, the OpenTelemetry Prometheus port; loopback-only) exposes aggregate signals — per-interface throughput, gateway/DNS RTT + loss, connection/TCP-state counts, and `netwatch_up`/`netwatch_collectors_ok`/`build_info` — in Prometheus exposition format. Aggregate-only by design (per-flow forensics is kept out of metrics to avoid cardinality blow-ups). See `docs/observability-export.md`.
- **TLS 1.3 KeyUpdate / post-handshake re-keying (decryption Phase 2).** Long-lived TLS 1.3 sessions that issue a post-handshake KeyUpdate (RFC 8446 §4.6.3) now keep decrypting instead of going dark after the re-key. On an observed KeyUpdate, netwatch derives the next-generation traffic secret (`HKDF-Expand-Label(secret_N, "traffic upd", …)`), re-derives the AEAD key/IV, and resets the per-direction record sequence (§5.3). Recovery from a *missed* KeyUpdate packet (via keylog `*_TRAFFIC_SECRET_<N>` generations) is not yet implemented.

### Fixed
- **Logging no longer crashes the process when the log file can't be opened.** A root-owned `netwatch.log` left by a prior `sudo netwatch` run (or a read-only filesystem) used to panic at startup — fatal for the long-running daemon. File logging now degrades to disabled (with a one-line notice) instead.
- **Processes "TOP REMOTES" used a proportional byte split instead of real per-remote rates.**

## [0.25.5] - 2026-06-08

### Added
- **Cross-packet HTTP/3 stream reassembly (QUIC decryption Phase 3b).** HTTP/3 response bodies that span more than one QUIC 1-RTT packet now reassemble and decompress instead of truncating. A new `H3StreamReassembler` accumulates decrypted STREAM-frame bytes per HTTP/3 stream id, indexed by offset, across packets, and decodes the contiguous prefix from byte 0 (gzip/deflate/brotli) — so a body is recovered once its head and a contiguous run are present, even when packets arrive out of order. The reassembled body shows in the Protocol Detail and Payload Content panes and in the `y` clipboard yank. Per-stream (2 MiB) and per-flow (64 streams) caps bound memory; zstd and identity bodies remain out of scope.

### Changed
- **Decrypt layer surfaces only `application_data`** (TLS content-type 23): post-handshake NewSessionTicket (22) and alert (21) records no longer appear as "decrypted" plaintext, keeping the detail pane and stream view clean.

### Fixed
- **Stream view follows the selected packet.** Opening the stream view (`s`) now highlights the selected packet's bytes and scrolls to them, instead of always starting at the top of the stream.

## [0.25.4] - 2026-06-06

### Added
- **Follow decrypted stream.** The stream view (`s` on the Packets tab) now renders the **decrypted** application-data conversation for flows decrypted via `SSLKEYLOGFILE`, instead of the raw encrypted wire bytes. Each segment's recovered plaintext is mirrored from the packet onto its stream segment, so opening a decrypted flow shows the full plaintext HTTP request/response exchange in order — both directions, in Text and Hex modes. The encrypted handshake is omitted from the decrypted view so the request/response flow reads cleanly (its timing still shows in the header), and a "🔓 decrypted" indicator appears in the stream header. (Previously the stream view followed only the encrypted bytes, which rendered as gibberish for any TLS/QUIC flow.)

## [0.25.3] - 2026-06-03

### Fixed
- **Quit / tab-switch could hang on idle interfaces.** Capture now runs non-blocking, so quitting or switching tabs can't stall waiting on a silent link (fully resolves #41).

## [0.25.2] - 2026-06-03

### Fixed
- **Quit could hang on idle interfaces.** Enabled libpcap `immediate_mode` so a quit isn't blocked waiting for the next packet on a quiet interface (#41). Superseded by the non-blocking capture in 0.25.3.

## [0.25.1] - 2026-06-02

### Added
- **Process attribution for pre-existing connections.** A pre-sandbox `/proc` snapshot captures processes for connections that predate startup, plus native `/proc` attribution so processes show without `ss -p` (#38/#40).

### Fixed
- **eBPF attribution keying** on `(daddr, dport)` to match the netwatch-sdk `uaddr` fix.
- **Windows UTF-8 output** — embed a UTF-8 active-code-page manifest so text renders correctly in non-UTF-8 locales (#39).

## [0.25.0] - 2026-05-31

### Added
- **Passive QUIC 1-RTT application-data decryption via `SSLKEYLOGFILE`.** Extends the v0.24.0 TLS 1.3 decryption from TLS-over-TCP to QUIC's encrypted short-header (1-RTT) packets — the same opt-in, read-only `tls_keylog_path` mechanism. netwatch derives the 1-RTT keys from the keylog `*_TRAFFIC_SECRET_0` (RFC 9001 §5), removes header protection, reconstructs the truncated packet number (RFC 9000 §A.3), and AEAD-opens the payload. The cipher suite and per-direction connection-ID length aren't on the wire for short headers, so the first packet brute-forces them with AEAD authentication as the oracle, then caches the result per flow. Supports the three QUIC v1 suites (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305). Verified against the RFC 9001 §A.5 known-answer vectors and against live Chrome HTTP/3 traffic. QUIC v2 1-RTT, key updates (key-phase), and coalesced packets are out of scope for this phase.
- **HTTP/3 response-body decompression.** When a decrypted 1-RTT packet carries an offset-0 HTTP/3 DATA body, netwatch parses the HTTP/3 framing layer (RFC 9114), concatenates the DATA frames, and decompresses the body — gzip/deflate detected by magic bytes, brotli (`br`) by trial decompression (the `Content-Encoding` lives in the QPACK-compressed HEADERS frame, which is deliberately not decoded). The decoded body renders in the Payload Content pane. Scope is single-packet, offset-0 bodies; larger responses that span multiple packets need cross-packet stream reassembly (a later phase). zstd is out of scope.

### Changed
- **Decrypted QUIC packets are now labelled "QUIC 1-RTT decrypted"** (rather than "TLS decrypted") across the Protocol Detail pane, Payload Content title, and clipboard yank. The decrypted payload is shown once in the Payload Content pane instead of being duplicated in both panes.

## [0.24.0] - 2026-05-30

### Added
- **Passive TLS 1.3 application-data decryption via `SSLKEYLOGFILE`.** When a cooperating client process is launched with `SSLKEYLOGFILE` pointing at the path in the new `tls_keylog_path` config key, netwatch tails that NSS keylog, derives per-record AEAD keys, and decrypts TLS 1.3 Application Data on the Packets tab — the same trick Wireshark uses. Read-only and opt-in: only connections whose client cooperatively exported its secrets are decryptable (production / third-party / malware traffic is not). Supports `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and `TLS_CHACHA20_POLY1305_SHA256`. Verified against the RFC 8448 §3 known-answer vector (full key-schedule → AEAD-open → inner-plaintext pipeline) and against live traffic. TLS 1.2, QUIC application data, and 0-RTT are out of scope for this phase.
- **Decrypted-payload inspection.** Decrypted packets render bold-green in the list; the new `decrypted:true|false` filter selects them, and `contains "…"` now searches decrypted plaintext too. The Protocol Detail and Payload Content panes show the recovered plaintext (the latter titled "Payload Content (TLS decrypted)"), and `y` copies the full payload to the clipboard.
- **HTTP/1.x classifier** — extracts the method and `Host` header from requests and labels server responses (was a placeholder).
- **SSH classifier** — identifies the RFC 4253 version banner, e.g. `SSH-2.0-OpenSSH_9.0` (was a placeholder).

### Fixed
- **Keylog watcher race.** A flow's first application-data records routinely arrive before the keylog secret has been ingested; previously that permanently disabled decryption for the stream. A keylog miss is now retryable (only a missed ClientHello or an unsupported cipher disables a stream), `decrypt_record_resync` recovers the correct record sequence after late-arriving secrets, and the watcher poll was tightened from 500ms to 100ms.
- **Packet filter ignored by the detail pane, scroll, and click.** With a filter applied, scrolling (mouse/arrows), clicking, and the detail pane indexed the full capture instead of the filtered view, so a stale selection or a scroll past the filtered rows rendered details for packets not shown in the list (even when the filter matched nothing). The list, detail pane, scroll, and click now share one filtered view.

## [0.21.7] - 2026-05-26

### Fixed
- **Capture toggle (`c` on the Packets tab) no longer fails with `Capture failed: libpcap error: socket: Operation not permitted` on Linux under the default sandbox.** The Linux sandbox was dropping `CAP_NET_RAW` after startup on the assumption that "pcap is already open, we don't need raw sockets anymore." That assumption was wrong: multiple UI actions re-open a pcap handle mid-run — toggling capture from the Packets tab (`c`), cycling the capture interface (`i`), and arming the Flight Recorder (`Shift+R`) when capture is paused. Each one calls `socket(AF_PACKET, SOCK_RAW, …)` which needs `CAP_NET_RAW`. Split the drop list: `CAPS_TO_DROP_DEFAULT` keeps the BPF caps (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`) which aren't needed at runtime once the kprobe is attached; `CAPS_TO_DROP_STRICT` additionally drops `CAP_NET_RAW` for users who explicitly opted into "fail closed" with `--sandbox-strict` or `sandbox = "strict"`. Two new regression tests pin the policy.

## [0.21.6] - 2026-05-26

### Fixed
- **Saving settings under the Linux sandbox no longer fails with "Permission denied (os error 13)".** The Landlock allow-list put the config dir (`~/.config/netwatch/`) in the *read-only* bucket, but `NetwatchConfig::save()` writes `config.toml` here whenever a user changes a setting in the overlay (`S` → edit → `S` to save). On kernels new enough to enforce Landlock (≥5.13) the write was rejected and the user saw EACCES — worst of all, this blocked them from flipping the Sandbox setting itself to escape the restriction. Moved the config dir to the read-write list. Found on a Linux NUC trying to disable the sandbox via the Settings overlay.
- **Gateway probe no longer reports a fake 100% loss on systems with restrictive `ping_group_range`.** Even after v0.21.5 fixed the DNS probe, Gateway stayed on ICMP — which is unreachable on kernels with `net.ipv4.ping_group_range = 1 0` once the sandbox has dropped `CAP_NET_RAW` and Landlock has set `NO_NEW_PRIVS` (causing the kernel to ignore the file-cap on `/usr/bin/ping`). Added a TCP-connect fallback that runs *only* when ICMP returns 100% loss: tries port 80, 443, 53 in order (stopping at the first one to respond), counts `ConnectionRefused` as success because a RST proves the host is up. Steady-state cost is one port × 3 probes (cheap); only the genuinely-down-or-firewalled case pays the worst-case 9 connect attempts. ICMP-rich environments (default kernels, no sandbox) keep the old behavior — the TCP path doesn't run at all when ICMP succeeds even partially.

## [0.21.5] - 2026-05-26

### Fixed
- **DNS Health probe now sends a real DNS query instead of ICMP-pinging the server.** ICMP echo was a misleading health signal anyway (plenty of resolvers — cloud LBs, hardened routers, internal CoreDNS — drop ICMP while answering DNS just fine), but it also broke entirely on Linux hosts where `net.ipv4.ping_group_range = 1 0` and the sandbox has dropped `CAP_NET_RAW`. Even with `ping_group_range` permissive, Landlock sets `NO_NEW_PRIVS` which makes the kernel ignore the file capability on `/usr/bin/ping`, so the subprocess fallback dies too — leaving every DNS probe at 100% loss on affected systems. New `run_dns_query()` sends a 17-byte standard query for the root NS record over UDP/53 and times the response; unprivileged, no sandbox interaction, and a more honest "DNS health" signal because it tests what actually matters. Three new unit tests cover header layout + transaction-ID round-trip.

### Added
- **Sandbox enforcement mode is now a Settings entry.** New "Sandbox" row in the Settings overlay (`S`) cycles through `on` / `strict` / `off` with `←` / `→`. Persists to `~/.config/netwatch/config.toml` as the new `sandbox = "..."` key; the CLI flags `--no-sandbox` and `--sandbox-strict` still override per-invocation. Changes apply on next netwatch start — Landlock and dropped capabilities can't be undone at runtime, so the live process keeps whatever mode it launched with. The Settings row surfaces "Applies on next netwatch start." when selected so the restart requirement is visible inline. Existing configs without a `sandbox` field continue to load cleanly and pick up the default (`"on"`).

## [0.21.4] - 2026-05-26

### Fixed
- **Health widget no longer reports a fake 100% loss when the system advertises an IPv6 link-local DNS server.** `dns_servers.first()` picked whichever nameserver appeared first in `/etc/resolv.conf` — on macOS with IPv6 RA-discovered DNS, that's the link-local entry (e.g. `fe80::96ea:eaff:fe05:f074`) listed ahead of the routable IPv4 server. The native ICMP probe can't reach link-local targets because `IpAddr::parse` rejects the `%en0` zone identifier they require, so every probe failed and the Dashboard's DNS card showed "100% loss" even though the host's *other* DNS server was healthy. Added `NetworkConfig::primary_dns()` which skips `fe80::/10` and falls through to the next entry, so we now probe (and label) the routable IPv4 fallback. Globally-routable IPv6 nameservers (e.g. `2001:4860:4860::8888`) are still preferred over IPv4 when they come first — only link-local is skipped. ([#31](https://github.com/matthart1983/netwatch/issues/31))
- **scutil `--dns` parser no longer mangles IPv6 nameservers.** The previous parser split each `nameserver[N] : <addr>` line on every `:` and took index 1, which truncated any IPv6 address to its first hextet (`fe80::1` became `fe80`). Switched to `split_once(':')` so the address survives the parse. (Not what triggered #31 — macOS reads `/etc/resolv.conf` first and never reaches the scutil branch when that file is non-empty — but it was waiting to bite anyone whose resolv.conf was empty or unavailable.)

## [0.21.3] - 2026-05-24

### Fixed
- **`package.nix` version bumped to track Cargo.toml.** The Nix derivation was stuck at `version = "0.3.5"` even though the published crate is currently at v0.21.x — Nix users doing `nix build github:matthart1983/netwatch` got a derivation labeled v0.3.5 with the actual current source contents. Bumped to match Cargo.toml + added an inline comment reminding future maintainers to keep the two in sync per release. (Reminder surfaced while wiring up the syswatch sibling's `package.nix` in [syswatch#3](https://github.com/matthart1983/syswatch/issues/3).)

## [0.21.2] - 2026-05-23

### Fixed
- **Processes tab now includes UDP and non-ESTABLISHED TCP flows.** `ProcessBandwidthCollector::update` was filtering connections with `state != "ESTABLISHED"`, which silently excluded the bulk of normal traffic on macOS: every QUIC flow from a browser, every DNS resolver socket, mDNS responders, the whole UDP world (lsof and procfs report UDP with an empty state, not "ESTABLISHED"). The Processes tab was usable mostly for SSH and TCP-only services, missing everything modern web apps actually do. New filter is the inverse — only `LISTEN` and `CLOSED` sockets are skipped (they have no peer traffic by definition). Everything else, including UDP, `TIME_WAIT`, `CLOSE_WAIT`, `FIN_WAIT_*`, etc., now counts toward the process aggregate. Two new unit tests cover both directions of the regression (LISTEN/CLOSED still excluded, UDP/TIME_WAIT now included).

## [0.21.1] - 2026-05-23

### Fixed
- **TOP CONNECTIONS panel on the Dashboard now respects the fade setting.** v0.21.0 wired the fade through every chart and every table renderer except the dashboard's TOP CONNECTIONS rows — they're rendered through their own per-row path that bypassed the table-fade hook. Rows 1..N now fade top-bright / bottom-dim like every other table; row 0 (the visually-highlighted "rank 1" row that already carries `selection_bg`) stays at full intensity.
- **Processes tab no longer cuts the main list to 5 rows on typical terminals.** The layout reserved a fixed 11 rows for the drill-in panel below the table, which left the table with `Min(8)` — yielding only ~5 visible rows after borders + header on a 27-row terminal. The drill-in only shows 5 host rows + header + "others" + borders (≈ 8 rows needed), so the reservation was 3 rows wasted. Dropped to `Length(8)`; the main process table now gets 3 more rows on the same terminal.

## [0.21.0] - 2026-05-23

### Fixed
- **macOS health prober no longer reports a fake 100% loss.** The v0.18.0 native DGRAM ICMP path checked the reply type at offset 0 of the recvfrom buffer, which is correct on Linux (the kernel strips the IPv4 header for `SOCK_DGRAM IPPROTO_ICMP`) but wrong on macOS (the IPv4 header is delivered intact, so offset 0 is `0x45` — IP version/IHL nibble — not the ICMP type). Every reply was rejected, the prober reported 0 successful probes, and the Dashboard's Gateway / DNS RTT cards showed "100% loss" despite the network being fine. The reply check now sniffs `buf[0] >> 4 == 4` to detect a leading IPv4 header and skips past it via the IHL field. IPv6 leaves the header outside the recvfrom buffer on both kernels, so offset 0 stays correct there.
- Verified end-to-end on both platforms with `cargo run --example ping_smoke` against 1.1.1.1: macOS reports ~12 ms RTT / 0% loss (was 100% on v0.18.0–v0.20.0), Linux still ~12 ms RTT / 0% loss (no regression — the IHL skip only triggers when the first byte has the IPv4 version nibble, which doesn't appear on Linux's stripped-header path).

### Added
- **btop-style fade + faint grid as a Settings option.** New `Graph Fade (btop)` row in the Settings overlay (`S`); toggle with `←`/`→`/`Space`/`h`/`l`. The single switch governs three places at once when on:
  - **Charts** — every chart in the app (hero RX/TX panels, in-row connection / process sparklines, RTT history, timeline severity layers) renders columns with a right-bright / left-dim color gradient (newest data at full intensity, oldest at ~30%), with a faint `·` dot grid behind charts at least 16×4 cells (narrower in-row sparklines skip the grid to avoid visual noise).
  - **Tables** — Connections, Packets, Processes, and Stats tables fade row-by-row top-bright → bottom-dim (top row at full intensity, bottom row at ~55%) so visual hierarchy mirrors btop's process list. Selected row stays at full intensity regardless of position.
  - **Persistence** — setting saves to `~/.config/netwatch/config.toml` via the existing save flow.

  Default is off; the original solid-color look is unchanged for users who don't want the effect.

### Changed
- `graph::render` / `graph::render_with_max` now take a `GraphOpts` parameter (carries `fade: bool` and the theme `bg` color used as the fade anchor). `App::graph_opts()` builds it once and every call site passes it, so the toggle drives the whole UI from a single config switch.
- `render_bars` reimplemented to render manually instead of delegating to ratatui's `Sparkline` — necessary because `Sparkline` only supports a single color per chart and fade requires per-column color computation. Visual output is identical to the previous Sparkline-based path (same 8-glyph bar set, same right-aligned sample window) when fade is off.

### Implementation
- `fade_color(base, bg, alpha)` linearly interpolates RGB channels between base and background at the given alpha. Named/indexed colors fall back to sensible defaults (white → black) so non-RGB themes still get *some* gradient. Five unit tests cover endpoints, midpoint, alpha clamping, and the non-RGB fallback.
- Grid uses `·` (middle dot) at quartile-spaced rows and columns, colored 20% from `bg` toward a neutral gray so it sits well below the data on every theme.

## [0.20.0] - 2026-05-23

### Added — DPI protocol breadth

Nine new application-layer classifiers complete the long-tail of common
LAN / IoT / ops protocols that previously rendered as generic "TCP" /
"UDP" with port-number labels:

- **MQTT** (TCP/1883, /8883) — IoT pub/sub. Decodes the variable-length
  fixed header, recognizes CONNECT packets, extracts the MQTT 3.1 /
  3.1.1 / 5.0 client-id when present.
- **STUN** (RFC 5389, any UDP) — NAT-traversal / WebRTC. Magic-cookie
  (0x2112A442) check at offset 4 makes detection unambiguous; surfaces
  the message method + class (e.g. `BindingRequest`,
  `BindingSuccessResponse`, `AllocateErrorResponse`).
- **BitTorrent** (TCP, any port) — BEP 3 peer-wire handshake. Detects
  the 19-byte protocol-string magic + 8 reserved bytes; extracts the
  20-byte info-hash and renders as 40-char hex.
- **NetBIOS** — three flavours: name service (UDP/137), datagram
  service (UDP/138), session service (TCP/139). Surfaces the message
  type per flavour (e.g. `Session Request`, `Name Query`,
  `Datagram Direct Unique`).
- **SNMP** (UDP/161, /162) — ASN.1 BER decoder for the SEQUENCE +
  INTEGER (version) + OCTET STRING (community) prefix. Surfaces
  version `v1` / `v2c` / `v3` and the community string for v1/v2c —
  useful both for "what monitoring traffic is on this network" and as
  a security tell when default communities like `public` / `private`
  appear in plaintext.
- **SSDP** (UDP/1900) — UPnP service discovery. HTTP-like text parser
  recognizes `M-SEARCH`, `NOTIFY`, and 200 OK responses; extracts the
  search target (`ST:` / `NT:` header value).
- **FTP** (TCP/21, control channel) — recognizes 3-digit server reply
  codes (`220`, `230`, `530`, …) and a curated allowlist of client
  command verbs (USER, PASS, RETR, STOR, LIST, …) so HTTP/SMTP banners
  starting with "220 …" don't get misclassified.
- **LLMNR** (UDP/5355) — Link-Local Multicast Name Resolution.
  Wire-format-identical to DNS so the existing DNS parser is reused,
  rebadged as `Llmnr` when port 5355 is on the flow.
- **IGMP** (IP protocol 2) — multicast group management. Doesn't create
  a stream (no TCP/UDP), but the Packets-tab INFO column now decodes
  the message type (`Membership Query`, `v2 Membership Report`, `Leave
  Group`, etc.) and the group address.

### Changed
- `AppProtocol` enum gained 8 new variants (everything except IGMP,
  which lives at the IP layer). Variants serialize via existing
  `#[serde]` derives so Flight Recorder bundles remain
  forward-compatible.
- `classify_once` now takes `src_port` and `dst_port` so port-locked
  classifiers (LLMNR vs. DNS, SNMP, MQTT, NetBIOS, SSDP, FTP) can
  dispatch correctly without expanding the per-classifier signature.
- Connections-tab `APP` column, filter prefixes (`app:mqtt`,
  `app:snmp`, `app:ssdp`, …), Packets-tab `INFO` column + L7
  color-coding, all updated to render the new protocols.

### Notes

This substantially broadens DPI protocol breadth. After v0.20.0 netwatch
has 13 shipped classifiers (TLS / QUIC with Initial decrypt / DNS / HTTP /
SSH / MQTT / STUN / BitTorrent / NetBIOS / SNMP / SSDP / FTP / LLMNR) +
IGMP at the IP layer + 25 port labels — covering the operationally common
protocols, plus QUIC Initial-decryption depth that most terminal tools
don't attempt.

37 new unit tests across the 8 classifier files cover the success
case, the rejection of look-alike traffic (HTTP on FTP port, garbage
bytes on STUN port, etc.), and protocol-side variation (CONNECT vs
non-CONNECT MQTT, v1 vs v2c SNMP, M-SEARCH vs NOTIFY SSDP).

## [0.19.0] - 2026-05-23

### Added
- **TCP retransmit + out-of-order analytics per stream.** Every TCP segment now updates a per-direction high-water sequence number on its flow. Segments whose `seq + payload_len` lands behind that mark are classified by how far behind:
  - **Retransmit** when the gap exceeds `OOO_WINDOW_BYTES` (64 KB) — the sender is resending bytes the other side has effectively already received.
  - **Out-of-order** when the gap is smaller — network reorder, not retransmission.
  Pure ACKs (zero payload) are excluded so duplicate keep-alives don't inflate the count. 32-bit wraparound is handled with signed-diff arithmetic so long sessions (>2 GB per direction) still classify correctly.
- **Visible per row on the Connections tab.** When a flow has retransmits, the STATE cell renders `ESTAB… ↻N` in the error color; OOO-only flows render `ESTAB… ↹N` in warn color. Operators can scan a busy table and immediately see which flows are unhealthy without drilling into Stream View.
- **Per-direction breakdown in Stream View** (Enter on a connection → status bar). Shows `RETX:N (↑A ↓B)` and `OOO:N (↑A ↓B)` so the split between sender-side and receiver-side anomalies is visible.
- Six unit tests in `src/collectors/packets.rs` cover the classification: retransmit-far-behind, OOO-small-jump, pure-ACK-not-counted, forward-progress, per-direction tracking, and 32-bit wraparound.

### Changed
- `CapturedPacket` gained a `tcp_seq: Option<u32>` field; the transport-result tuple gained the seq element. `StreamTracker::track_packet` takes a `tcp_seq` parameter. The data flows from `parse_tcp` through `parse_transport` → `parse_ipv4_packet` / `parse_ipv6_packet` → `track_packet`.
- `Connection` struct gained `retransmits: u32` and `out_of_order: u32` fields, sourced from a new `StreamTracker::snapshot_anomalies()` snapshot during the connection collector's update tick. Both default to 0 via `#[serde(default)]` so on-disk Flight Recorder bundles and stored configs remain forward-compatible.

### Notes
This adds per-stream TCP retransmit / out-of-order analytics — health signals that previously meant dropping to a full packet analyzer. Combined with the v0.18.x sandbox arc, it strengthens netwatch's live-forensics edge; remaining areas to grow are DPI long-tail breadth (MQTT/BitTorrent/SNMP/…), smart staleness coloring, Windows/FreeBSD native process attribution, and distribution breadth.

## [0.18.1] - 2026-05-23

### Changed
- **Traceroute now uses a native UDP+TTL implementation on Linux** instead of shelling out to `/usr/bin/traceroute`. Same root cause as the ping rewrite in v0.18.0: Landlock sets `PR_SET_NO_NEW_PRIVS=1`, which makes the kernel ignore the setcap on the system `traceroute` binary, so the subprocess returned EPERM under sandbox and the Topology view's hop list stayed empty. The new path opens a plain UDP socket, enables `IP_RECVERR`, and reads ICMP Time Exceeded / Port Unreachable replies from the kernel's error queue via `recvmsg(MSG_ERRQUEUE)` — no capabilities required.
- Implementation note: `SO_RCVTIMEO` does not apply to error-queue reads, so the inner loop uses `poll(POLLERR)` with a 1 s deadline per probe to wait for the kernel to queue the ICMP error. Each probe targets a unique destination port (`33434 + ttl*3 + probe`) so the kernel can correlate the response back, matching the wire-level behaviour of the classic Van Jacobson traceroute.
- Subprocess `traceroute` / `tracert` paths are preserved for IPv6 targets (the native path is IPv4-only today; IPv6 follows similar logic with `Ipv6RecvErr` and `IPV6_UNICAST_HOPS` and is tracked for later), for macOS (which lacks `IP_RECVERR` / `MSG_ERRQUEUE` in its BSD-derived stack), and for Windows.

### Fixed
- **Topology view hops now populate under the sandbox.** Verified end-to-end on Linux against `1.1.1.1` (4 hops: orb-gateway → home-router → ISP next-hop → target, RTTs matching system `traceroute` exactly) and `192.168.0.54` (2 hops, target reached at hop 2). `examples/traceroute_under_sandbox.rs` reproduces the test.

### Notes
- Together with v0.18.0's native ICMP ping, the v0.17.x sandbox feature now has no known UX regressions versus v0.16.x. Both `health probes` and `topology` work with `Landlock ABI Vx, 4 caps dropped` active. The `--no-sandbox` workaround for either feature is no longer required.

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
