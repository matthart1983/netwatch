# NetWatch — Feature Reference

The complete reference for NetWatch: every keybinding, the display-filter language, the
protocol decoders, TLS decryption, JA4 hunting, the sandbox, the Flight Recorder, themes,
and configuration. For a quick start, see the [README](../README.md); for architecture and
maintenance notes, see [WIKI.md](WIKI.md).

- [Deep Packet Inspection](#deep-packet-inspection)
  - [Protocol decoders](#protocol-decoders)
  - [TLS 1.3 / 1.2 decryption](#tls-13--12-decryption)
  - [Threat hunting with JA4](#threat-hunting-with-ja4)
- [Display filters](#display-filters)
- [Security & Forensics](#security--forensics)
  - [Network intelligence](#network-intelligence)
  - [Flight Recorder](#flight-recorder)
  - [Landlock sandbox (Linux)](#landlock-sandbox-linux)
- [Command line](#command-line)
- [Keyboard controls](#keyboard-controls)
- [Permissions](#permissions)
  - [Running without sudo (Linux)](#running-without-sudo-linux)
- [Themes](#themes)
- [Configuration](#configuration)
- [AI Insights](#ai-insights)
- [How it works](#how-it-works)

---

## Deep Packet Inspection

Live capture with real L7 decoding — not just port-based labels. Press `c` in the Packets
tab to start capturing.

### Protocol decoders

| Layer | Decoded |
|-------|---------|
| **TLS** | Version, SNI, ALPN, **ECH** flag, **JA4** fingerprint |
| **QUIC** | Initial detection, SNI from reassembled CRYPTO frames, ECH, **JA4Q**, HTTP/3 |
| **HTTP** | Method, host, path, status code |
| **DNS / mDNS / LLMNR** | Query name, record type, response code, reverse-DNS cache (UDP only — DNS-over-TCP isn't classified; DoT/DoH surface at the TLS layer) |
| **SSH** | Client/server banner + version |
| **Others** | MQTT, SNMP, BitTorrent, FTP, NetBIOS, SSDP, STUN, NTP, DHCP, ICMP, ARP |

Cleartext L7 classifiers (in `src/dpi/`): TLS, QUIC, HTTP, DNS, SSH, MQTT, SNMP, BitTorrent,
FTP, NetBIOS, SSDP, STUN, NTP, DHCP, LLMNR — 15 in total. HTTP/3 decoding over decrypted QUIC is
a reassembly/decode utility, not a separate classifier; ICMP/ARP are handled at the parse layer.
Classifiers run over **per-flow stream tracking** (byte accumulation + TCP sequence-anomaly
detection — not full out-of-order resequencing; cross-segment TLS records aren't reassembled),
with handshake timing, a hex/text payload viewer, packet bookmarks, BPF capture filters, and
PCAP export.

### TLS 1.3 / 1.2 decryption

NetWatch can decrypt TLS 1.3 **and TLS 1.2** application data (plus QUIC 1-RTT) when a
**cooperating client** exports its session secrets — the same `SSLKEYLOGFILE` mechanism
Wireshark uses. It is read-only and debugging-oriented: it decrypts traffic *you* control,
never third-party or malware traffic.

```bash
# 1. Point netwatch at a keylog file: set `tls_keylog_path` in your config
#    (see Configuration). Empty by default — nothing is decrypted until you set it.

# 2. Launch the client with the SAME path:
SSLKEYLOGFILE=/tmp/sslkeylog.txt curl https://example.com
SSLKEYLOGFILE=/tmp/sslkeylog.txt google-chrome     # Chrome, Firefox, Node, etc.

# 3. In the Packets tab, decrypted records render inline. Filter with:
#    decrypted:true
```

Supported cipher suites — **TLS 1.3:** `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
`TLS_CHACHA20_POLY1305_SHA256`. **TLS 1.2** (AEAD only, via `CLIENT_RANDOM` keylog lines):
the AES-128/256-GCM and ChaCha20-Poly1305 ECDHE suites; legacy CBC (mac-then-encrypt) suites
are out of scope. NetWatch decrypts application data after the handshake completes, and handles
TLS 1.3 KeyUpdate / post-handshake re-keying. A keylog miss never breaks capture — the record
just stays opaque.

> The ClientHello must be captured **live** — a connection whose handshake predates capture
> is permanently undecryptable. Start capture first, then make the request.

### Threat hunting with JA4

Every TLS ClientHello (and QUIC Initial) is fingerprinted with the
[Foxio JA4](https://github.com/FoxIO-LLC/ja4) spec, with RFC 8701 GREASE filtering. A JA4
fingerprint is stable across connections from the same client software, so you can pivot on
one to find every flow from the same stack — a browser, a CLI tool, or a piece of malware:

```
ja4:t13d1516h2_8daaf6152771_b186095e22b6
```

NetWatch ships the FoxIO BSD-3 lookup database and lets you overlay your own entries via JSON.

---

## Display filters

Wireshark-style filter syntax in the Packets tab (`/`):

```
tcp                        # Protocol
192.168.1.42               # IP address (src or dst)
ip.src == 10.0.0.1         # Directional
port 443                   # Port
stream 7                   # Stream index
contains "hello"           # Text search
app:tls                    # L7 protocol
sni:example.com            # TLS/QUIC server name
host:api.github.com        # HTTP host / resolved name
ja4:t13d1516h2_...         # JA4 fingerprint
ech:true                   # Encrypted ClientHello present
decrypted:true             # Only TLS-decrypted records
tcp and port 443           # Combinators (and / or)
!dns                       # Negation
google                     # Bare word → contains "google"
```

---

## Security & Forensics

### Network intelligence

NetWatch watches your traffic for trouble and raises color-coded alerts (visible in the
Timeline tab) without any setup:

- **Port-scan detection** — many distinct destination ports from one source in a short window (default: 20 ports / 30s).
- **Beaconing detection** — regular-interval outbound connections with low jitter, C2-style (default: ≥5 samples, jitter < 15%).
- **DNS-tunnel detection** — high-volume unique subdomains or abnormally long query names.
- **Bandwidth alerts** — configurable per-interface thresholds.

A **critical** alert automatically freezes an armed Flight Recorder, so the evidence is
captured before you even look.

### Flight Recorder

Catch transient failures that vanish before you can inspect them:

```text
Shift+R   Arm a rolling 5-minute recorder
Shift+F   Freeze the current incident window
Shift+E   Export an incident bundle to ~/netwatch_incident_YYYYMMDD_HHMMSS/
```

Each bundle is self-contained — packet evidence *plus* the operational context that explains it:

```text
netwatch_incident_20260403_103501/
  summary.md       # human-readable incident summary
  manifest.json
  connections.json # who was talking to whom
  health.json      # gateway/DNS RTT + loss samples
  bandwidth.json   # per-interface rates + top processes
  dns.json         # query analytics
  alerts.json      # network-intelligence alert history
  packets.pcap     # present when packets were captured
```

### Egress policy linter

A linter for your machine's outbound traffic: declare what each process is *meant* to
talk to, and NetWatch warns when reality drifts. It warns, it never blocks — the
read-only invariant holds.

The loop is **observe → promote → warn**:

1. **Observe** — the Egress tab (`0`) learns per-process destination profiles:
   SNI (read from the cleartext TLS/QUIC ClientHello — no decryption needed),
   ASN organization, and port. The learned baseline **persists across
   restarts** (`<state_dir>/netwatch/egress-profiles.json`; saved once a
   minute and at quit) and ages out destinations not seen for 30 days. The
   `First`/`Last` columns show how long each destination has been known —
   the evidence you review before promoting.
2. **Promote** — `Enter` ratifies just the selected process (the status line
   reports what the promotion adds, e.g. `+2 SNI, +1 ports`); `Shift+P`
   ratifies everything observed. Both **merge** into
   `<config_dir>/netwatch/egress-policy.toml` (e.g. `~/.config/netwatch/` on
   Linux) — hand edits, comments, and rules for other processes survive.
   Review before trusting: human ratification is what keeps a compromised
   baseline from being blessed as "normal".
3. **Warn** — flows that fall outside a process's declared allowlist raise a
   `PolicyViolation` alert naming the broken rule. Only processes with a rule are
   checked, so an unlisted process never warns. The re-warn cooldown per flow is
   `egress_violation_cooldown_secs` in config.toml (default 300; 0 = every refresh).
   In `netwatch daemon` the same evaluation runs headless, and violations surface
   as `netwatch_policy_violations_total{process}` on the Prometheus endpoint.

Sharp edges handled for you:

- **ECH**: a flow with Encrypted ClientHello has no readable inner SNI, so a policy
  miss may be "name unreadable" rather than real drift — those rows show `? ech`
  (and the alert says so) instead of a red `✗ drift`.
- **Wildcard suggestions**: when ≥3 subdomains of one apex accumulate in a rule,
  promotion writes a `# suggestion: *.apex.tld would cover N entries` comment above
  the rule. It never collapses silently — widening the allowlist is your call.
- **Policy file trust**: a group- or world-writable `egress-policy.toml` is refused
  with a loud log warning. If anyone but the owner can edit the policy, "warn on
  drift" could be silenced by the very thing drifting. `chmod 644` or stricter.

**Structured export.** Press `e` on the Egress tab to write the attributed
records as **NDJSON** (`netwatch.egress.v1`) — one JSON object per line, preceded
by a `_meta` line naming the schema. Each record is metadata only (process, SNI,
ASN org, IP, port, coarse proto, ECH flag, first/last-seen, count, policy
verdict) — never any payload. This is the ingest contract the managed layer consumes; the
same `policy.toml` the TUI lints with is the file a managed layer would
distribute.

```json
{"_meta":{"schema":"netwatch.egress.v1","records":2}}
{"process":"chrome","sni":"mail.google.com","asn_org":"Google LLC","ip":"142.250.66.101","port":443,"proto":"tls","ech":false,"first_seen":1751600000,"last_seen":1751603600,"count":42,"verdict":"ok"}
```

```toml
# egress-policy.toml
[process.chrome]
allow_sni   = ["*.google.com", "*.gstatic.com"]   # exact or *.wildcard (incl. apex)
allow_ports = [443]

[process.node]
allow_asn = ["CLOUDFLARENET"]                     # fallback when a flow has no SNI
allow_ip  = ["203.0.113.9"]                        # for a raw-IP dest with no name at all
```

Rules are expressed in terms a firewall can't write — `process → {SNI, ASN, IP, port}` —
because the flow already carries the owning process (eBPF/proc attribution) and the
destination name (DPI). A flow is allowed if **any** declared dimension matches, so a
promoted baseline admits all of its own destinations: named ones match by SNI/ASN, and a
nameless raw-IP destination matches by IP (without `allow_ip` it would drift against the
very rule it was promoted into, once a sibling destination made the rule name-restricted).
Edit the file by hand freely; it reloads on startup.

### Landlock sandbox (Linux)

Linux worker entry points apply a prepared Landlock filesystem policy before
processing input. Capture opens/configures its device first and marks itself ready
after policy entry. Main applies policy after resource startup. Rules pin opened
filesystem objects, so later pathname replacement cannot widen an existing grant.

```bash
netwatch                     # best-effort; reports unavailable protection
netwatch --sandbox-strict     # reject unverified required startup entries
netwatch --no-sandbox         # explicitly disable Netwatch policy
```

- **Capabilities:** selected BPF/admin capability removals are verified in effective,
  permitted and inheritable sets. Strict also drops `CAP_NET_RAW`; best-effort
  retains it for capture reopening. Effective retained capabilities are recorded.
  This is not a claim that every elevated capability is removed.
- **Writable paths:** owned private config/cache/state directories, dedicated
  `netwatch/exports` and `netwatch/scratch` cache subdirectories, and `/dev/null`.
  There is no whole-CWD, shared `/tmp` or `/run/user` write grant. Directories are
  prepared before restrictions; broad roots and symlink directory targets fail
  preparation. Exports normally land in `~/.cache/netwatch/exports` on Linux.
- **Inputs:** configured GeoIP and keylog files receive exact read grants; system
  executable/library and resolver paths remain readable. Missing or replaced
  keylog/database files require restarting Netwatch. Rotation does not expand the
  policy to a parent directory.
- **SDK source:** eBPF attribution is disabled under enabled sandbox policy until
  its SDK reader has an enforcement hook. Socket polling remains available.
- **Strict mode:** preflight/required worker entry failures stop startup with a
  nonzero exit. After the main thread drops raw-socket authority, capture restart
  may fail; it never retries unsandboxed. macOS/Windows have no backend and reject
  strict startup. Best-effort reports degradation on those platforms.
- **Network:** no network restrictions are installed. Settings reports policy-entry
  results, not an independent proof that the entire process is exploit-proof.

Linux denial tests exercise actual lookup/Insights/keylog workers and keylog restart.
Privileged capture/restart and macOS/Windows runtime validation remain release checks.
Some detached workers still lack bounded shutdown; see the
[runtime inventory](runtime-lifecycle.md) and [capability matrix](CAPABILITIES.md).

---

## Command line

`netwatch --help` prints the flags; `netwatch diagnose` with no subcommand prints its usage.
The [man page](netwatch.1) carries the same list.

| Command | What it does |
|---------|--------------|
| `netwatch` | The TUI. Flags below. |
| `netwatch daemon` (also `--daemon`, `--headless`) | The collectors with no screen. With `--metrics` or `--metrics-addr`, serves [Prometheus metrics](observability-export.md). |
| `netwatch doctor [--json] [--check-capture] [--interface NAME]` | Read-only setup report: what this host lets netwatch see. `--check-capture` tries a real capture. See [doctor.md](doctor.md). |
| `netwatch diagnose run [--budget 30s] [--target NAME] [--format text\|json]` | One bounded diagnosis. Exit 0: completed, no issue. 1: at least one open issue. 2: no usable observation in the budget. 3: bad arguments or no session. |
| `netwatch diagnose coverage [--json] [--seconds N] [--test ID]` | Which checks have their inputs on this host, and why the others do not. |
| `netwatch diagnose episodes [DIR]` | List recorded incident episodes. |
| `netwatch diagnose replay [--json] FILE\|DIR...` | Replay episodes through the engine and report any divergence. |
| `netwatch diagnose features [--out FILE] [--schema FILE] FILE\|DIR...` | Write the feature table of recorded episodes. |
| `netwatch diagnose export [--since DAYS] [--out FILE] [--dry-run] [DIR]` | A pseudonymised bundle of recent incidents. Nothing is uploaded. |
| `netwatch resolver status\|set\|recover` | Inspect, temporarily change (Linux, root, `--unmanaged` files only) or restore the DNS resolver. |
| `netwatch --generate-config` | Write `config.toml` with every key at its default, then exit. |
| `netwatch --version`, `--help` | |

TUI flags:

| Flag | Effect |
|------|--------|
| `--view full\|lite\|dense`, `--lite` | Start in that view. |
| `--demo` | Replay a recorded Diagnose incident instead of watching this host. |
| `--no-sandbox`, `--sandbox-strict` | Turn the Linux sandbox off, or refuse to start unless it is enforced. |
| `--remote URL` | Stream snapshots to a backend. Needs `NETWATCH_API_KEY`. Experimental. |
| `--insecure-remote` | Allow an `http://` remote URL. |
| `--api-key KEY` | Discouraged: the key shows in the process list. Use `NETWATCH_API_KEY`. |
| `--metrics`, `--metrics-addr ADDR` | With `daemon`: serve metrics on `127.0.0.1:9464`, or on `ADDR`. |

---

## Keyboard controls

| Key | Action |
|-----|--------|
| `1`–`9`, `0` | Switch tabs (`9` Diagnose, `0` Egress) |
| `P` | Promote observed egress baseline → `egress-policy.toml` |
| `↑` `↓` | Navigate |
| `p` | Pause / resume |
| `r` | Force refresh |
| `R` | Arm / reset flight recorder |
| `F` | Freeze current incident window |
| `E` | Export incident bundle |
| `/` | Filter (Packets) |
| `c` | Start/stop capture (Packets) |
| `s` | Sort / stream view |
| `w` | Export to .pcap |
| `T` | Traceroute |
| `W` | Whois lookup |
| `t` | Cycle theme |
| `V` | Cycle view: full → lite → dense (dense needs 130×44, then grows to fit) |
| `L` | Switch to the Lite view |
| `,` | Settings |
| `?` | Help |
| `q` | Quit |

<details>
<summary><strong>Full keybinding reference (per tab)</strong></summary>

### Connections
| Key | Action |
|-----|--------|
| `s` | Cycle sort column |
| `Enter` | Jump to Packets with connection filter |
| `T` | Traceroute to remote IP |
| `W` | Whois lookup |
| `e` | Export connections to JSON + CSV |
| `g` | Toggle GeoIP column |

### Packets
| Key | Action |
|-----|--------|
| `c` | Start/stop capture |
| `R` | Arm / disarm flight recorder |
| `F` | Freeze incident window |
| `E` | Export incident bundle |
| `i` | Cycle capture interface |
| `b` | Set BPF capture filter |
| `/` | Display filter |
| `s` | Stream view |
| `w` | Export .pcap |
| `x` | Clear packets |
| `m` | Bookmark packet |
| `n`/`N` | Next/prev bookmark |
| `f` | Auto-follow |
| `W` | Whois lookup for selected packet IPs |

### Stream View
| Key | Action |
|-----|--------|
| `→` `←` | Filter A→B / B→A |
| `a` | Both directions |
| `h` | Toggle hex/text |
| `Esc` | Close |

### Topology
| Key | Action |
|-----|--------|
| `T` | Traceroute to selected host |
| `Enter` | Jump to Connections for host |
| `Esc` | Close traceroute overlay |

### Timeline
| Key | Action |
|-----|--------|
| `t` | Cycle time window (1m–1h) |
| `Enter` | Jump to Connections |

### Processes
| Key | Action |
|-----|--------|
| `↑` `↓` | Navigate |
| `e` | Export connections to JSON + CSV |

### Egress
| Key | Action |
|-----|--------|
| `↑` `↓` | Select / scroll profiles |
| `Enter` | Promote selected process (merges; status line shows the diff) |
| `P` | Promote all → `egress-policy.toml` |
| `e` | Export attributed egress records → `~/netwatch_egress_<ts>.ndjson` |

### Dense view
| Key | Action |
|-----|--------|
| `↑` `↓` / `k` `j` | Select connection (the detail panel follows the selection) |
| `Home` / `End` | First / last connection |
| `p` / `Space` | Pause / resume |
| `V` | Cycle view |
| `Esc` | Back to the full view |
| `,` | Settings |
| `?` | Help |
| `q` | Quit |

### Settings
| Key | Action |
|-----|--------|
| `↑` `↓` | Navigate settings |
| `Enter` | Edit selected setting |
| `←` `→` | Cycle the selected setting (theme, view, graph style, sandbox…) |
| `S` | Save config |
| `Esc` | Close |

</details>

---

## Distro packages

From v0.32.1 every release carries `.deb` and `.rpm` packages for x86_64 and
aarch64, built from the same musl-static binary as the tarball:

```sh
sudo apt install ./netwatch_0.32.1-1_amd64.deb     # Debian, Ubuntu
sudo dnf install ./netwatch-0.32.1-1.x86_64.rpm    # Fedora, RHEL
```

They install the binary, all three shell completions, the man page, the
fleet-agent systemd unit (not enabled) and the docs. They have **no**
dependencies — libpcap is linked into the binary.

Where each package comes from, and what to do at release time, is in
[PACKAGING.md](PACKAGING.md).

Neither package grants capabilities. `netwatch` still needs elevated access to
capture, so either run it with `sudo` or grant them yourself once (see
[Permissions](#permissions)); the package prints that command on install. A
package that silently gives a binary raw-socket access is the administrator's
decision to make, not the packager's.

## Verifying a download

Every release ships `SHA256SUMS` alongside the binaries, and each artifact
carries signed build provenance tying it to the workflow run and commit that
produced it.

```sh
# Checksums
curl -LO https://github.com/matthart1983/netwatch/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS

# Provenance (needs the GitHub CLI)
gh attestation verify netwatch-linux-x86_64.tar.gz -R matthart1983/netwatch
```

Checksums and attestations are produced from v0.32.1 onward; earlier releases
have neither.

## Shell completions and the man page

The repository ships completions for bash, zsh and fish in `completions/`, and
a man page at `docs/netwatch.1`. Package installs put them in place for you;
for a manual install:

```sh
sudo install -m0644 completions/netwatch.bash /etc/bash_completion.d/netwatch
sudo install -m0644 completions/_netwatch /usr/share/zsh/site-functions/_netwatch
install -m0644 completions/netwatch.fish ~/.config/fish/completions/netwatch.fish
sudo install -m0644 docs/netwatch.1 /usr/share/man/man1/netwatch.1
```

A test in `src/cli.rs` fails if an option is added to the parser without being
added to all three completions and the man page.

## Permissions

| Feature | `netwatch` | `sudo netwatch` |
|---------|:---:|:---:|
| Interface stats & rates | ✅ | ✅ |
| Active connections | ✅ | ✅ |
| Network configuration | ✅ | ✅ |
| Health probes (ICMP) | ❌ | ✅ |
| Packet capture | ❌ | ✅ |

Degrades gracefully — features that need root show a clear message, never crash. On Linux,
`setcap` (below) unlocks capture and eBPF without running as root.

### Running without sudo (Linux)

Packet capture and eBPF process attribution need elevated capabilities, but you don't have to
run the whole TUI as root. Grant them once to the binary:

```bash
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' "$(which netwatch)"
netwatch
```

> **Re-run after every install.** `setcap` attaches to a specific binary on disk; `cargo
> install netwatch-tui` and the Release tarballs overwrite that file, so the capabilities
> don't carry over. If you see `pcap open failed: socket: Operation not permitted` or `BPF
> load failed: PermissionDenied` in `~/.cache/netwatch/netwatch.log.*` after an upgrade, the
> new binary just needs `setcap` re-applied.

| Capability | What it unlocks |
|------------|-----------------|
| `cap_net_raw` | Opening packet capture on a live interface (libpcap) |
| `cap_bpf` | Loading the kernel-level process-attribution kprobe (kernel ≥ 5.10) |
| `cap_perfmon` | Reading the BPF ring buffer the kprobe writes to |

Without them netwatch still runs — it falls back to `ss`/`lsof`-style polling for process
attribution and skips packet capture. The Connections header surfaces the active source
(`attribution: ebpf`, `attribution: pktap`, or `attribution: lsof — ebpf unavailable: …`) so
you can tell at a glance which path is live.

---

## Themes

8 built-in themes with instant switching via `t`:
**Dark** (default) · **Terminal** · **Ocean** · **Solarized** · **Dracula** · **Nord** · **Sky** · **Paper**

Theme changes apply immediately. Persist them from the Settings overlay with `S`.

**Terminal** pins no colors of its own — every slot resolves to an ANSI palette entry, and
foreground and background use your terminal's own defaults. If you theme your whole desktop
with pywal, matugen, or a terminal profile, this is the one that follows along. It's also
accepted under the names `system` and `ansi` in a config file.

Chart rendering is a separate axis from the theme. The braille area plot and its magnitude
gradient are both on by default; `graph_style = "bars"` swaps the plot for solid blocks if
your font has no braille coverage, and `graph_fade = false` drops the gradient. Both live in
[Configuration](#configuration).

`NO_COLOR` set to any non-empty value turns colour off in every view, whatever the theme.
The selection, highlighted rows and filled bars show in reverse video instead.

---

## Environment variables

| Variable | Effect |
|----------|--------|
| `NO_COLOR` | Any non-empty value: draw the TUI without colour ([no-color.org](https://no-color.org)). |
| `NETWATCH_API_KEY` | API key for `--remote`. Preferred over `--api-key`, which leaves the key in the process list and shell history. |
| `NETWATCH_REMOTE_URL` | Remote backend URL, when `--remote` is not given. |
| `NETWATCH_METRICS_ADDR` | Address for the daemon's metrics endpoint, when `--metrics-addr` is not given. |
| `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` (and lowercase) | Diagnose records whether a proxy applies to each configured target, and weighs it as evidence: an untrusted certificate behind a proxy points at interception. |

Variables named `NETWATCH_*` that are not listed here are test hooks and may change in any release.

---

## Configuration

NetWatch runs with zero setup — every key below has a working default, and the file doesn't
exist until you write one.

| Platform | Config file |
|----------|-------------|
| Linux | `~/.config/netwatch/config.toml` |
| macOS | `~/Library/Application Support/netwatch/config.toml` |
| Windows | `%APPDATA%\netwatch\config.toml` |

Two ways to write it. From the shell:

```bash
netwatch --generate-config    # writes every key at its default value, then exits
```

Or live in the TUI: `,` opens Settings, `↑`/`↓` moves, `←`/`→` cycles the enum-valued rows
(theme, view, default tab, graph style, graph fade, sandbox, group folding), `Enter` edits
the free-text ones, `S` saves. Most changes apply the moment you make them — `sandbox` is the
exception, because Landlock and dropped capabilities can't be undone inside a running
process, so it takes effect on the next launch.

Both leave out the `[diagnose_thresholds]` table while it holds its defaults, so a later
release can retune them; [DIAGNOSE.md](DIAGNOSE.md#thresholds) lists its keys.

A hand-edited file can't cost you the tool: missing keys fall back to their defaults,
out-of-range numbers are clamped, and an unrecognised value falls back rather than refusing
to start.

### Appearance

| Key | Default | Values | What it does |
|-----|---------|--------|--------------|
| `theme` | `"dark"` | `dark` `terminal` `ocean` `solarized` `dracula` `nord` `sky` `paper` | Color theme. `terminal` is also accepted as `system` or `ansi`. See [Themes](#themes). |
| `view` | `"full"` | `full` `lite` `dense` | Which view starts. `--view` overrides it for one run; an unknown name falls back to `full`. |
| `default_tab` | `"dashboard"` | `dashboard` `connections` `interfaces` `packets` `stats` `topology` `timeline` `processes` `diagnose` `egress` `insights` | `insights` is a legacy alias for Diagnose. Tab shown on launch in the full view. |
| `graph_style` | `"dots"` | `dots` `bars` | Chart rendering for every sparkline in the app. `dots` is the braille area plot: two samples per cell column and four times the vertical resolution, so a sparkline carries twice the history in the same width. `bars` is solid blocks, for terminals whose font has no braille coverage — there the area plot renders as empty boxes. |
| `graph_fade` | `true` | `true` `false` | The magnitude gradient: every cell is coloured by how high it sits — dim at the baseline, the series colour in the middle, lightened at the peak. It is what makes a filled area read as depth rather than as a block. Under the `terminal` theme it steps from each series colour to its bright palette variant instead of blending, so no colour is invented. |
| `groups_start_collapsed` | `true` | `true` `false` | Whether the grouped tables (Connections, Egress) open folded. Folded answers "what is on this machine" in one glance; `false` is closer to the old flat tables. |

**The plain look**, if braille or colour interpolation is a problem in your terminal:

```toml
graph_style = "bars"
graph_fade  = false
```

`graph_style` governs *every* chart routed through the graph module — the Dashboard's hero
tiles and throughput plot, per-interface sparklines, in-row connection lines, RTT history,
timeline tracks, and Lite's charts. There is one braille renderer behind it, shared with the
Dense view's mirrored plot, so no two graphs in the tool can drift apart in texture or in
colour. The Dense view is the one place that stays braille regardless of the setting: it has
no fallback layout that would fit in blocks.

One asymmetry worth knowing under `bars`. The mirrored half of a shared-axis graph — the
upload series hanging below the Dashboard's zero line — draws at three fill levels rather
than eight. The bottom-anchored eighths (`▁`–`▇`) are all in Unicode's Block Elements range;
their top-anchored counterparts past `▔` and `▀` are in Symbols for Legacy Computing, whose
font coverage is the thing `bars` exists to avoid depending on. The upward half keeps its
full resolution.

### Refresh and capture

| Key | Default | Values | What it does |
|-----|---------|--------|--------------|
| `refresh_rate_ms` | `1000` | 100–5000 | Tick rate in milliseconds. Values outside the range are clamped, not rejected. |
| `capture_interface` | `""` | interface name | Interface to capture on, e.g. `"en0"`. Empty auto-detects. |
| `bpf_filter` | `""` | BPF expression | Capture filter applied at the kernel, e.g. `"tcp port 443"`. Empty captures everything. |
| `packet_follow` | `true` | `true` `false` | Auto-scroll the Packets tab to newest. |
| `timeline_window` | `"5m"` | `1m` `5m` `15m` `30m` `1h` | Timeline tab's default window. |
| `tls_keylog_path` | `""` | file path | NSS keylog file to read session secrets from, for [TLS decryption](#tls-13--12-decryption). Config-file only — there is no Settings row for it. |

### GeoIP

| Key | Default | Values | What it does |
|-----|---------|--------|--------------|
| `show_geo` | `true` | `true` `false` | Show the GeoIP column in Connections. |
| `geoip_db` | `""` | file path | MaxMind GeoLite2-City or GeoLite2-Country `.mmdb`. Empty means no offline lookups; see `geoip_online` for the fallback. |
| `geoip_asn_db` | `""` | file path | MaxMind GeoLite2-ASN `.mmdb`, for AS numbers. Optional. |
| `geoip_online` | `false` | `true` `false` | Fall back to `http://ip-api.com` when `geoip_db` is empty or fails to open. Off by default: enabling it sends every public peer IP to a third party over cleartext HTTP, with no per-host opt-out, and anyone on the path can read the lookups and change the answers. ip-api.com offers HTTPS only on its paid tier, so there is no encrypted option. With this on, Settings shows the GeoIP DB Path as `ip-api.com (cleartext)`, or as `ip-api.com (cleartext) if unreadable:` and the path when `geoip_db` is set. |

### Security

| Key | Default | Values | What it does |
|-----|---------|--------|--------------|
| `sandbox` | `"on"` | `on` `strict` `off` | Sandbox enforcement. `on` is best-effort, `strict` refuses to start if the platform backend can't apply it, `off` skips it. `--no-sandbox` and `--sandbox-strict` override for one run. Applies at next launch. See [the Landlock sandbox](#landlock-sandbox-linux). |
| `egress_violation_cooldown_secs` | `300` | seconds | How long before the same violating flow — one (process, destination, port) — warns again on egress policy drift. `0` warns on every refresh. Config-file only. |

### Alerts

Under a `[alerts]` table:

```toml
[alerts]
bandwidth_threshold   = 100000000   # bytes/sec; 0 disables
port_scan_threshold   = 20          # distinct ports within the window
port_scan_window_secs = 30          # detection window
```

`port_scan_window_secs` is config-file only; the other two have Settings rows.

### AI Insights

| Key | Default | Values | What it does |
|-----|---------|--------|--------------|
| `insights_enabled` | `false` | `true` `false` | Adds an AI narrative block to the Diagnose tab. Opt-in — see [AI Insights](#ai-insights). |
| `insights_model` | `"llama3.2"` | model name | Model for the Ollama or cloud endpoint. |
| `insights_endpoint` | `"local"` | `local` or base URL | `local` means `http://localhost:11434`; anything else is used as a base URL. |

---

## AI Insights

Insights is opt-in commentary inside **Diagnose (`9`)**, below the findings.
It sends a network snapshot to the configured Ollama-compatible `/api/chat`
endpoint. Requests are rate-limited with a 15-second interval and a 30-second
request timeout; analysis requires a nonempty retained packet snapshot, not
necessarily new traffic during that interval.

Detection, cause ranking and remediation run without a model. Commentary can be
wrong and is not mechanically checked against the deterministic findings. The
snapshot contains packet-derived summaries, addresses, names and health metrics;
it is not a serialized list of Diagnose issues.

Enable via Settings (`,`) → AI Insights. `local` resolves to
`http://localhost:11434`; a configured remote URL sends data to that host. A local
endpoint alone does not guarantee local inference if its server forwards requests.
See [INSIGHTS.md](INSIGHTS.md) for setup, data disclosure and troubleshooting.

---

## How it works

The intervals below assume the default one-second tick. Platform support is not
feature parity; see the [capability matrix](CAPABILITIES.md), including Windows,
and the [Diagnose rule coverage](diagnostic-coverage.md).

| Collector | Interval | macOS | Linux |
|-----------|:--------:|-------|-------|
| Interface stats | 1s | `netstat -ib` | `/sys/class/net/*/statistics` |
| Connections | 2s | `lsof` + PKTAP | `/proc/net/tcp` + eBPF kprobe |
| Health probes | Every 5 ticks | Gateway/internet ICMP, DNS queries | Gateway/internet ICMP, DNS queries |
| Packets | Real-time | libpcap (BPF) | libpcap |
| GeoIP | On-demand | MaxMind .mmdb / ip-api.com | MaxMind .mmdb / ip-api.com |

```
Raw bytes → Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP → L7 decoders
                                            ↓
                          Per-flow stream tracking · Handshake timing
                          TLS 1.3 decryption · JA4 · Expert info
```

For the module-level source map and runtime architecture, see [WIKI.md](WIKI.md).
