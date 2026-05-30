<p align="center">
  <h1 align="center">NetWatch</h1>
  <p align="center">
    <strong>Network forensics that fits in your terminal.</strong><br>
    <em>Deep packet inspection at real-time speed. Built in Rust. Zero config.</em>
  </p>
  <p align="center">
    <a href="https://crates.io/crates/netwatch-tui"><img src="https://img.shields.io/crates/v/netwatch-tui.svg" alt="crates.io"></a>
    <a href="https://github.com/matthart1983/netwatch/releases"><img src="https://img.shields.io/github/v/release/matthart1983/netwatch" alt="Release"></a>
    <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-blue" alt="Platform">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
    <a href="https://github.com/matthart1983/netwatch/wiki"><img src="https://img.shields.io/badge/docs-Wiki-blue?logo=github" alt="Wiki"></a>
  </p>
  <p align="center">
    <a title="Tool of The Week on Terminal Trove" href="https://terminaltrove.com/netwatch/"><img src="terminal_trove_totw_badge.svg" alt="Terminal Trove Tool of The Week" height="54" /></a>
  </p>
</p>

<p align="center">
  <img src="demo.gif" alt="NetWatch — Dashboard, Connections, Topology, Processes, Timeline" width="800">
</p>

<p align="center">
  <em>Go from a 10,000-ft dashboard to <strong>decrypted TLS 1.3 bytes</strong> without leaving your terminal.</em>
</p>

---

NetWatch is a real-time network **forensics** TUI. It **decrypts TLS 1.3**, fingerprints clients with **JA4**, and hunts **C2 beaconing, port scans, and DNS tunneling** — live, in one zero-config binary. It's a great live dashboard too, but that's the part everything else already does.

**Who it's for:** blue-teamers, incident responders, and homelabbers who need live triage and evidence capture — not just a bandwidth meter.

<samp>500+ tests · Landlock-sandboxed · safely parses hostile capture traffic</samp>

## What makes it different

Most terminal network tools stop at *"which process is using bandwidth."* NetWatch keeps going:

- 🔓 **TLS 1.3 decryption** — point a cooperating client's `SSLKEYLOGFILE` at NetWatch and read decrypted application data, live, in the Packets tab. AES-128/256-GCM and ChaCha20-Poly1305.
- 🧬 **JA4 / JA4Q fingerprinting** — Foxio-spec client fingerprints for TLS *and* QUIC. Hunt with `ja4:<fingerprint>` as a display filter.
- 📡 **17 L7 protocol decoders** — TLS, QUIC (SNI from reassembled CRYPTO frames), HTTP, DNS, SSH, MQTT, SNMP, BitTorrent, FTP, NetBIOS, SSDP, STUN, LLMNR, NTP, DHCP, mDNS — with TCP stream reassembly and handshake timing.
- ⚙️ **Kernel-level process attribution** — an eBPF kprobe tells you which process opened a connection. Not lsof polling. Graceful fallback when eBPF isn't available; PKTAP on macOS.
- 🚨 **Built-in network intelligence** — port-scan, beaconing, and DNS-tunnel detection running in the background. Critical alerts auto-freeze the Flight Recorder.
- 🎥 **Flight Recorder** — arm a rolling capture, then freeze any incident into a portable evidence bundle (`.pcap` + connection/health/DNS/alert context) for bug reports and post-mortems.
- 🛡️ **Landlock sandbox** — after setup, NetWatch drops its capabilities and locks itself into a filesystem allow-list. A forensics tool that parses hostile traffic can never read your SSH keys, browser profiles, or `/etc/shadow`.

**No config files. No setup. No flags required.**

## Live forensics, not just monitoring

Most terminal network tools answer one question — *"which process is using bandwidth?"* — and stop. Full packet analyzers answer *"what happened?"*, but offline, after the fact, in a heavyweight GUI.

NetWatch lives in the gap: **live triage**. Decode L7 protocols, fingerprint clients with JA4, detect beaconing / port scans / DNS tunneling, and freeze an evidence bundle the moment an incident happens — in real time, in one terminal. A bandwidth meter tells you *what's on* the wire; NetWatch tells you *what's wrong with it*.

---

## Install

```bash
# Homebrew (macOS / Linux)
brew install matthart1983/tap/netwatch

# Cargo
cargo install netwatch-tui

# Pre-built binaries — see Releases
```

<details>
<summary><strong>All platforms & options</strong></summary>

| Platform | Download |
|----------|----------|
| Linux (x86_64, Debian/Ubuntu) | [`netwatch-linux-x86_64.tar.gz`](https://github.com/matthart1983/netwatch/releases/latest) |
| Linux (aarch64, Debian/Ubuntu) | [`netwatch-linux-aarch64.tar.gz`](https://github.com/matthart1983/netwatch/releases/latest) |
| Linux (x86_64, static — Arch/Fedora/Alpine/any distro) | [`netwatch-linux-x86_64-static.tar.gz`](https://github.com/matthart1983/netwatch/releases/latest) |
| Linux (aarch64, static — Arch/Fedora/Alpine/any distro) | [`netwatch-linux-aarch64-static.tar.gz`](https://github.com/matthart1983/netwatch/releases/latest) |
| macOS (Intel) | [`netwatch-macos-x86_64.tar.gz`](https://github.com/matthart1983/netwatch/releases/latest) |
| macOS (Apple Silicon) | [`netwatch-macos-aarch64.tar.gz`](https://github.com/matthart1983/netwatch/releases/latest) |

The `-static` Linux builds bundle libpcap and have no runtime dependencies — use these on Arch, Fedora, Alpine, or any distro where the default builds report `libpcap.so.0.8: cannot open shared object file`.

**From source:**

```bash
git clone https://github.com/matthart1983/netwatch.git && cd netwatch
cargo build --release
```

**Prerequisites:** Rust 1.70+, libpcap (`sudo apt install libpcap-dev` on Linux, included on macOS)

</details>

## Quick Start

```bash
netwatch            # Interface stats, connections, config
sudo netwatch       # Full mode — adds health probes + packet capture
netwatch --generate-config
```

### See it decrypt TLS in 60 seconds

The fastest way to understand what NetWatch is — watch it read the plaintext of a TLS 1.3 session *you* control, the same `SSLKEYLOGFILE` way Wireshark does (no MITM, no proxy):

```bash
sudo netwatch                                              # 1. launch; in the Packets tab press 'c' to capture
SSLKEYLOGFILE=/tmp/sslkeylog.txt curl https://example.com  # 2. any cooperating client, the default keylog path
#                                                            3. filter with:  decrypted:true  →  open the record
```

The decrypted application data renders inline. A keylog miss never breaks capture — the record just stays opaque.

### Running without sudo (Linux)

Packet capture and eBPF process attribution need elevated capabilities, but
you don't have to run the whole TUI as root. Grant them once to the binary
and `netwatch` works for your normal user thereafter:

```bash
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' "$(which netwatch)"
netwatch
```

> **Re-run after every install.** `setcap` attaches to a specific binary on
> disk; `cargo install netwatch-tui` and the Release tarballs overwrite that
> file, so the capabilities don't carry over. If you see
> `pcap open failed: socket: Operation not permitted` or
> `BPF load failed: PermissionDenied` in `~/.cache/netwatch/netwatch.log.*`
> after an upgrade, the new binary just needs `setcap` re-applied.

| Capability       | What it unlocks                                                                |
|------------------|--------------------------------------------------------------------------------|
| `cap_net_raw`    | Opening packet capture on a live interface (libpcap)                           |
| `cap_bpf`        | Loading the kernel-level process-attribution kprobe (kernel ≥ 5.10)            |
| `cap_perfmon`    | Reading the BPF ring buffer the kprobe writes to                               |

Without them netwatch still runs — it falls back to `ss`/`lsof`-style polling
for process attribution and skips packet capture. The Connections header
surfaces the active source (`attribution: ebpf`, `attribution: pktap`, or
`attribution: lsof — ebpf unavailable: …`) so you can tell at a glance which
path is live.

---

## Deep Packet Inspection

Live capture with real L7 decoding — not just port-based labels. Press `c` in the
Packets tab to start capturing.

### Protocol decoders

| Layer | Decoded |
|-------|---------|
| **TLS** | Version, SNI, ALPN, **ECH** flag, **JA4** fingerprint |
| **QUIC** | Initial detection, SNI from reassembled CRYPTO frames, ECH, **JA4Q** |
| **HTTP** | Method, host, path, status code |
| **DNS / mDNS / LLMNR** | Query name, record type, response code, reverse-DNS cache |
| **SSH** | Client/server banner + version |
| **Others** | MQTT, SNMP, BitTorrent, FTP, NetBIOS, SSDP, STUN, NTP, DHCP, ICMP, ARP |

Plus TCP stream reassembly, handshake timing, hex/text payload viewer, packet
bookmarks, BPF capture filters, and PCAP export.

### TLS 1.3 decryption

NetWatch can decrypt TLS 1.3 application data when a **cooperating client** exports
its session secrets — the same `SSLKEYLOGFILE` mechanism Wireshark uses. Read-only,
debugging-oriented: it decrypts traffic *you* control, never third-party or malware
traffic.

```bash
# 1. Set the keylog path in Settings (,) → "TLS keylog", or in your config.
#    Default starter path is /tmp/sslkeylog.txt.

# 2. Launch the client with the SAME path:
SSLKEYLOGFILE=/tmp/sslkeylog.txt curl https://example.com
SSLKEYLOGFILE=/tmp/sslkeylog.txt google-chrome     # Chrome, Firefox, Node, etc.

# 3. In the Packets tab, decrypted records render inline. Filter with:
#    decrypted:true
```

Supported cipher suites: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
`TLS_CHACHA20_POLY1305_SHA256`. Decrypts application data after the handshake
completes. A keylog miss never breaks capture — the record just stays opaque.

### Threat hunting with JA4

Every TLS ClientHello (and QUIC Initial) is fingerprinted with the
[Foxio JA4](https://github.com/FoxIO-LLC/ja4) spec. Pivot on a fingerprint to find
every flow from the same client stack:

```
ja4:t13d1516h2_8daaf6152771_b186095e22b6
```

---

## Security & Forensics

### Network Intelligence

NetWatch watches your traffic for trouble and raises color-coded alerts (visible in
the Timeline tab) without any setup:

- **Port-scan detection** — many distinct destination ports from one source in a short window
- **Beaconing detection** — regular-interval outbound connections with low jitter (C2-style)
- **DNS-tunnel detection** — high-volume unique subdomains or abnormally long query names
- **Bandwidth alerts** — configurable per-interface thresholds

A **critical** alert automatically freezes an armed Flight Recorder, so the evidence
is captured before you even look.

### Flight Recorder

Catch transient failures that vanish before you can inspect them:

```text
Shift+R   Arm a rolling 5-minute recorder
Shift+F   Freeze the current incident window
Shift+E   Export an incident bundle to ~/netwatch_incident_YYYYMMDD_HHMMSS/
```

Each bundle is self-contained — packet evidence *plus* the operational context that
explains it:

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

### Landlock sandbox (Linux)

Once pcap, PKTAP, and the eBPF kprobe finish setup, NetWatch hands back its elevated
capabilities and locks itself into a Landlock-enforced filesystem allow-list — so a
memory-safety bug in DPI parsing of hostile capture traffic **can't read SSH keys,
exfiltrate browser profiles, or open a new raw socket.**

```bash
netwatch                     # best-effort sandbox (default)
netwatch --sandbox-strict    # refuse to start if Landlock can't enforce
netwatch --no-sandbox        # escape hatch for debugging
```

- **Capabilities dropped post-init:** `CAP_NET_RAW`, `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`. The existing pcap fd and kprobe stay live; the process just can't acquire *new* ones.
- **Filesystem read allow-list** (kernel-enforced): system dirs plus a deliberately *enumerated* set of `/etc/*` files for NSS/TLS/time — so even a sudo'd NetWatch can't read `/etc/shadow` or `/etc/sudoers`. Everything else returns `EACCES`, including other users' homes and SSH keys.
- **Write allow-list:** `~/.cache/netwatch/`, the startup working dir (PCAP exports), `/tmp`, `/run/user/<uid>`, `/dev/null`.
- **Verify at runtime:** the Settings overlay (`,`) shows the live enforcement state, e.g. `best-effort: Landlock ABI Vx, 3 caps dropped`.

Network restriction is intentionally not enabled (it would break GeoIP fallback,
`--remote` streaming, and WHOIS). macOS/Windows sandboxing is not on the roadmap —
the threat model is production-capture-specific, and that audience is overwhelmingly
Linux.

---

## The Tabs

Switch with `1`–`9`.

| # | Tab | What you get |
|---|-----|--------------|
| 1 | **Dashboard** | Interfaces, aggregate bandwidth graph, top connections, gateway/DNS health, latency heatmap. Useful in 5 seconds. |
| 2 | **Connections** | Every socket with process name + PID, protocol, state, GeoIP, and per-connection latency sparklines. Sort any column; jump to filtered packets. |
| 3 | **Interfaces** | Per-interface IPv4/IPv6, MAC, MTU, RX/TX sparklines, errors, drops. |
| 4 | **Packets** | Live capture + deep decode (see above), stream reassembly, display/BPF filters, bookmarks, PCAP export. |
| 5 | **Stats** | Protocol hierarchy with byte totals + distribution bars; TCP handshake histogram (min/avg/median/p95/max). |
| 6 | **Topology** | ASCII map of machine → gateway → DNS → top hosts, health-colored, with built-in traceroute. |
| 7 | **Timeline** | Gantt-style connection timeline color-coded by TCP state; network-intel alerts land here. Windows 1m–1h. |
| 8 | **Processes** | Per-process bandwidth ranking with live RX/TX, totals, and connection counts. |
| 9 | **Insights** | *(opt-in)* Feeds a live network snapshot to a local/cloud LLM and renders bullet-point analysis. |

### AI Insights (opt-in, off by default)

Feed a snapshot — protocol mix, top talkers, DNS queries, connection states, health,
expert warnings — to an LLM every 15 seconds and get analysis rendered in the TUI:
anomalies, beaconing patterns, suspicious DNS, health regressions.

Enable via Settings (`,`) → AI Insights. Supports local [Ollama](https://ollama.com)
(default), a remote Ollama host, or Ollama **cloud models** — no API keys in NetWatch.
See [INSIGHTS.md](INSIGHTS.md) for setup.

---

## Display Filters

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

## Keyboard Controls

| Key | Action |
|-----|--------|
| `1`–`9` | Switch tabs (tab `9` Insights appears when AI Insights is enabled) |
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
| `,` | Settings |
| `?` | Help |
| `q` | Quit |

<details>
<summary><strong>Full keybinding reference</strong></summary>

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

### Settings
| Key | Action |
|-----|--------|
| `↑` `↓` | Navigate settings |
| `Enter` | Edit selected setting |
| `←` `→` | Cycle theme |
| `S` | Save config |
| `Esc` | Close |

</details>

---

## Permissions

| Feature | `netwatch` | `sudo netwatch` |
|---------|:---:|:---:|
| Interface stats & rates | ✅ | ✅ |
| Active connections | ✅ | ✅ |
| Network configuration | ✅ | ✅ |
| Health probes (ICMP) | ❌ | ✅ |
| Packet capture | ❌ | ✅ |

Degrades gracefully — features that need root show a clear message, never crash.
On Linux, `setcap` (above) unlocks capture and eBPF without running as root.

---

## Themes

7 built-in themes with instant switching via `t`:
**Dark** (default) · **Ocean** · **Solarized** · **Dracula** · **Nord** · **Sky** · **Paper**

Theme changes apply immediately. Persist them from the Settings overlay with `S`.

---

## Configuration

NetWatch runs well with zero setup, but you can persist preferences for theme,
default tab, refresh rate, capture interface, GeoIP database paths, TLS keylog
path, packet-follow behavior, BPF filter, and alert thresholds.

```bash
netwatch --generate-config
```

That writes a starter config to your platform config directory. You can also edit
settings live with `,` and save with `S`.

---

## How It Works

| Collector | Interval | macOS | Linux |
|-----------|:--------:|-------|-------|
| Interface stats | 1s | `netstat -ib` | `/sys/class/net/*/statistics` |
| Connections | 2s | `lsof` + PKTAP | `/proc/net/tcp` + eBPF kprobe |
| Health probes | 5s | native ICMP | native ICMP |
| Packets | Real-time | libpcap (BPF) | libpcap |
| GeoIP | On-demand | MaxMind .mmdb / ip-api.com | MaxMind .mmdb / ip-api.com |

```
Raw bytes → Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP → 17 L7 decoders
                                            ↓
                          Stream reassembly · Handshake timing
                          TLS 1.3 decryption · JA4 · Expert info
```

---

## Related

**Siblings:** [SysWatch](https://github.com/matthart1983/syswatch) (system) and [DiskWatch](https://github.com/matthart1983/diskwatch) (disk) — same chrome, different surface.

**[ESSH](https://github.com/matthart1983/essh)** — If you manage the hosts you monitor, ESSH is built for the same workflow. Same TUI aesthetic, pure-Rust SSH client with concurrent sessions, live remote host diagnostics (CPU, memory, disk, processes — no agent install), fleet management, file transfer, and port forwarding. Connects where NetWatch observes.

**[NetWatch Cloud](https://www.netwatchlabs.com)** — Hosted fleet monitoring for the servers you run NetWatch against. Tiny Rust agent on each Linux host, real-time dashboard, email + Slack alerts on latency, packet loss, or hosts going offline. **Free while we grow.**

NetWatch Cloud is a separate codebase with its own open-source ecosystem (this TUI is intentionally independent — same author, different philosophy):

- [`netwatch-sdk`](https://github.com/matthart1983/netwatch-sdk) — shared Rust wire format + headless collectors ([crates.io](https://crates.io/crates/netwatch-sdk))
- [`netwatch-agent`](https://github.com/matthart1983/netwatch-agent) — audit-able Rust binary that runs on your hosts and reports to NetWatch Cloud
- [`netwatch-dashboard`](https://github.com/matthart1983/netwatch-dashboard) — Next.js web UI for the hosted backend

The hosted backend is proprietary; the agent, SDK, and dashboard that talk to it are MIT.

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for coding conventions and [WIKI.md](WIKI.md) for a current architecture guide.

## License

MIT
