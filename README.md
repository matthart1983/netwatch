<p align="center">
  <h1 align="center">NetWatch</h1>
  <p align="center">
    <strong>Real-time network diagnostics in your terminal. One command, zero config, instant visibility.</strong>
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
  <em>Launch → see every interface, connection, and health probe instantly. Arm the flight recorder before an incident disappears.</em>
</p>

<p align="center">
  <em>Siblings: <a href="https://github.com/matthart1983/syswatch">SysWatch</a> (system) and <a href="https://github.com/matthart1983/diskwatch">DiskWatch</a> (disk). Same chrome. Different surface.</em>
</p>

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

### Running without sudo (Linux)

Packet capture and eBPF process attribution need elevated capabilities, but
you don't have to run the whole TUI as root. Grant them once to the binary
and `netwatch` works for your normal user thereafter:

```bash
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' "$(which netwatch)"
netwatch
```

> **Re-run after every install.** `setcap` attaches to a specific binary on
> disk; `cargo install netwatch-tui` (and the GitHub Release tarballs)
> overwrite that file, so the capabilities don't carry over. If you see
> `pcap open failed: socket: Operation not permitted` or
> `BPF load failed: PermissionDenied` in `~/.cache/netwatch/netwatch.log.*`
> after an upgrade, the new binary just needs `setcap` re-applied.

| Capability       | What it unlocks                                                                |
|------------------|--------------------------------------------------------------------------------|
| `cap_net_raw`    | Opening packet capture on a live interface (libpcap)                           |
| `cap_bpf`        | Loading the kernel-level process-attribution kprobe (kernel ≥ 5.10)            |
| `cap_perfmon`    | Reading the BPF ring buffer the kprobe writes to                               |

Without them netwatch still runs — it falls back to `ss`/`lsof`-style polling
for process attribution and skips packet capture. The Connections tab's
header surfaces the active source (`attribution: ebpf`, `attribution: pktap`,
or `attribution: lsof — ebpf unavailable: …`) so you can tell at a glance
which path is live.

### Security sandbox (Linux)

Available on **v0.18.0+** (v0.17.0 had a path-coverage regression; v0.17.1 fixed that but the sandbox's `NO_NEW_PRIVS` requirement broke the subprocess-based ping path, blanking gateway / DNS RTTs). v0.18.0 routes health probing through a native DGRAM ICMP socket, so the sandbox + health probes finally coexist. Once
pcap, PKTAP, and the eBPF kprobe finish setup, netwatch hands the elevated
capabilities back and locks itself into a Landlock-enforced filesystem
allow-list — so a memory-safety bug in DPI parsing can't read SSH keys,
exfiltrate browser profiles, or pivot via a new raw socket. Default is
best-effort; production deployments that want a hard guarantee should use
strict mode.

```bash
netwatch                     # best-effort sandbox (default)
netwatch --sandbox-strict    # refuse to start if Landlock can't enforce
netwatch --no-sandbox        # escape hatch for debugging
```

What gets restricted:

- **Capabilities dropped post-init**: `CAP_NET_RAW`, `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`. The existing pcap fd stays open and the eBPF kprobe stays attached; the process just can't acquire any *new* raw sockets or load any *new* BPF programs.
- **Filesystem read allow-list** (kernel-enforced, independent of DAC): `/proc`, `/sys`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, plus a narrow enumerated set of `/etc/*` files for NSS / TLS / time (`resolv.conf`, `hosts`, `services`, `nsswitch.conf`, `passwd`, `group`, `os-release`, `ssl`, `pki`, `ca-certificates`, `ld.so.*`, etc.), plus `~/.config/netwatch/` and configured GeoIP DB parent dirs. The `/etc/*` list is deliberately enumerated rather than allow-all so a sudo'd netwatch still can't read `/etc/shadow` or `/etc/sudoers` through the sandbox. Everything outside the allow-list returns `EACCES` — including `/home/<other-user>/`, `/root/`, browser profiles, SSH keys.
- **Filesystem write allow-list**: `~/.cache/netwatch/` (logs + Flight Recorder bundles), the startup working directory (PCAP exports), `/tmp`, `/run/user/<uid>`, and `/dev/null`. Note that the export directory is captured at startup — change it via Settings without restarting and exports will fail.
- **Live verification**: the Settings overlay (press `S`) shows the enforcement state — `best-effort: Landlock ABI Vx, 3 caps dropped` — so you can confirm at runtime that the sandbox actually applied, not just that the binary advertises it.

Network restriction (TCP bind/connect block) is intentionally not enabled — it would silently break the ip-api.com GeoIP fallback, `--remote` streaming, and inline WHOIS. The threat model the sandbox defends against (exploitable DPI parsing of hostile capture traffic on a production host) is well served by filesystem and capability restrictions alone.

macOS and Windows are not on the sandbox roadmap. The threat the sandbox defends against is production-capture-specific, and that audience is overwhelmingly Linux; building Seatbelt or Windows-token wrappers would buy feature-matrix parity with neighbouring tools without buying users meaningful security.

> **v0.17.0 regression — upgrade to v0.17.1.** The v0.17.0 allow-list was
> missing `/sys`, `/bin`/`/sbin`/`/usr`, and several `/etc/*` files, so on
> Linux with the default sandbox enabled the Dashboard and Interfaces tabs
> rendered blank (the interface-info reader at `src/platform/linux.rs`
> swallows fs errors via `unwrap_or_default()`, hiding the EACCES). The
> workaround on v0.17.0 was `netwatch --no-sandbox`; v0.17.1 expands the
> allow-list and is the correct version to install.

### Flight Recorder

Catch transient failures that vanish before you can inspect them:

```text
Shift+R   Arm a rolling 5-minute recorder
Shift+F   Freeze the current incident window
Shift+E   Export an incident bundle to ~/netwatch_incident_YYYYMMDD_HHMMSS/
```

Each bundle includes `summary.md`, `connections.json`, `health.json`, `bandwidth.json`, `dns.json`, `alerts.json`, `manifest.json`, and `packets.pcap` when capture data is available.

---

## Why NetWatch?

Most network tools make you choose: **see what's happening** (iftop, bandwhich) or **inspect packets** (Wireshark, tshark). NetWatch does both in a single terminal — from a 10,000-foot dashboard view down to individual packet bytes.

| What you get | How fast |
|---|---|
| Every interface with live RX/TX sparklines | **Instant** |
| Every connection with process name + PID | **Instant** |
| Gateway & DNS health with latency heatmap | **Instant** |
| Wireshark-style packet capture + decode | One keypress |
| Rolling incident capture + frozen export bundle | One keypress |
| Network topology map with traceroute | One keypress |
| PCAP export for offline analysis | One keypress |
| AI-analyzed network insights (opt-in, local or cloud LLM) | One setting |

**No config files. No setup. No flags required.**

---

## Features

### 🖥️ Dashboard
Everything at a glance — interfaces, aggregate bandwidth graph, top connections, gateway/DNS health probes, and a color-coded latency heatmap. Useful in 5 seconds.

### 🔌 Connections
Every open socket with **process name**, PID, protocol, state, remote address, GeoIP location, and per-connection **latency sparklines**. Sort by any column, jump to filtered packet view.

### 📡 Interfaces
Per-interface detail: IPv4/IPv6 addresses, MAC, MTU, total RX/TX with individual sparkline history, errors, and drops.

### 📦 Packet Capture
Live capture with deep protocol decoding — **DNS** (queries, types, response codes), **TLS** (version, SNI), **HTTP** (method, path, status), **ICMP**, **ARP**, **DHCP**, **NTP**, **mDNS**, and 25+ service labels. TCP stream reassembly, handshake timing, display filters, BPF capture filters, bookmarks, and PCAP export.

### 📈 Processes
Per-process bandwidth ranking with live RX/TX rates, totals, and connection counts. Useful for spotting the process behind a noisy host or bandwidth spike.

### 🎥 Flight Recorder
Arm a rolling 5-minute capture window, then freeze it manually or when a critical network-intel alert fires. Export a self-contained incident bundle with a human-readable summary, `.pcap`, connection/process context, health samples, DNS analytics, and alert history.

### 🗺️ Topology
ASCII network map showing your machine, gateway, DNS servers, and top remote hosts with connection counts and color-coded health indicators. Built-in **traceroute** from any host.

### 📊 Stats
Protocol hierarchy table with packet counts, byte totals, and distribution bars. TCP handshake histogram with min/avg/median/p95/max.

### ⏱️ Timeline
Gantt-style connection timeline — when each connection was active, color-coded by TCP state. Adjustable windows from 1 minute to 1 hour.

### 🤖 AI Insights (opt-in)
Feed a live snapshot of your network — protocol mix, top talkers, DNS queries, connection states, health probes, expert warnings — to an LLM every 15 seconds and get bullet-point analysis rendered in the TUI. Surfaces anomalies, beaconing patterns, suspicious DNS, and health regressions you might miss scrolling through raw data.

**Off by default.** Enable via Settings (`,`) → AI Insights: on. Supports local [Ollama](https://ollama.com) (default), a remote Ollama host on your network, or Ollama **cloud models** — point the AI Endpoint setting at the cloud URL and skip local setup entirely. No API keys in netwatch. See [INSIGHTS.md](INSIGHTS.md) for full setup.

### ⚙️ Settings
Built-in settings overlay for theme, default tab, refresh rate, capture interface, packet-follow mode, GeoIP paths, BPF filter, AI Insights, and alert thresholds. Use `,` to open it and `S` to persist changes.

---

## Display Filters

Wireshark-style filter syntax in the Packets tab:

```
tcp                        # Protocol
192.168.1.42               # IP address (src or dst)
ip.src == 10.0.0.1         # Directional
port 443                   # Port
stream 7                   # Stream index
contains "hello"           # Text search
tcp and port 443           # Combinators
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

## Incident Bundle

When the Flight Recorder is armed, NetWatch keeps a bounded rolling window of evidence. On freeze or export, it writes:

```text
netwatch_incident_20260403_103501/
  summary.md
  manifest.json
  connections.json
  health.json
  bandwidth.json
  dns.json
  alerts.json
  packets.pcap   # present when packets were captured
```

This makes bug reports, incident reviews, and demos much easier: you keep the packet evidence and the operational context that explains it.

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

---

## Themes

5 built-in themes with instant switching via `t`:

**Dark** (default) · **Light** · **Solarized** · **Dracula** · **Nord**

Theme changes apply immediately. Persist them from the Settings overlay with `S`.

---

## Configuration

NetWatch runs well with zero setup, but you can persist preferences for theme, default tab, refresh rate, capture interface, GeoIP database paths, packet-follow behavior, BPF filter, and alert thresholds.

```bash
netwatch --generate-config
```

That writes a starter config file to your platform config directory. You can also edit settings live in the app with `,` and save with `S`.

---

## How It Works

| Collector | Interval | macOS | Linux |
|-----------|:--------:|-------|-------|
| Interface stats | 1s | `netstat -ib` | `/sys/class/net/*/statistics` |
| Connections | 2s | `lsof -i -n -P` | `/proc/net/tcp` + `/proc/*/fd` |
| Health probes | 5s | `ping` | `ping` |
| Packets | Real-time | libpcap (BPF) | libpcap |
| GeoIP | On-demand | MaxMind .mmdb / ip-api.com | MaxMind .mmdb / ip-api.com |

```
Raw bytes → Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP → DNS/TLS/HTTP/DHCP/NTP
                                             ↓
                               Stream tracking · Handshake timing
                               Expert info · Payload extraction
```

---

## Related

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
