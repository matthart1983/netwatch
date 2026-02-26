# NetWatch

**Real-time network diagnostics in your terminal — like htop for your network.**

NetWatch is a lightweight, keyboard-driven TUI application that gives you instant visibility into network traffic, active connections, interface health, and live packet capture with deep protocol inspection. Built with Rust for speed and low overhead.

![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

- **Live interface monitoring** — RX/TX rates, totals, and 60-second sparkline history for every network interface
- **Active connections** — See every open socket with process name, PID, protocol, state, and addresses (sortable)
- **Network health** — ICMP ping probes to your gateway and DNS servers with RTT and packet loss
- **Packet capture** — Wireshark-style live capture with deep protocol decoding:
  - **DNS** — Query names, types (A, AAAA, CNAME…), response codes
  - **TLS** — Handshake type, version, SNI hostname extraction
  - **HTTP** — Method, path, and response status lines
  - **ICMP** — Human-readable type/code (Echo Request, Dest Unreachable, TTL Exceeded…)
  - **ARP, DHCP, NTP, mDNS** — Decoded with meaningful summaries
  - **TCP payload** — Readable text content extracted and displayed
  - **25+ service labels** — Ports mapped to names (SSH, HTTPS, PostgreSQL, Redis…)
- **Network config** — Default gateway, DNS servers, hostname at a glance
- **Cross-platform** — macOS and Linux with platform-specific collectors

---

## Quick Start

### Prerequisites

- **Rust** toolchain (1.70+): https://rustup.rs
- **libpcap** (for packet capture):
  - macOS: included with Xcode Command Line Tools
  - Linux: `sudo apt install libpcap-dev` (Debian/Ubuntu) or `sudo dnf install libpcap-devel` (Fedora)

### Build

```bash
git clone https://github.com/matthart1983/netwatch.git
cd netwatch
cargo build --release
```

### Run

```bash
# Basic mode — interface stats, connections, config
./target/release/netwatch

# Full mode — adds health probes + packet capture (requires root for BPF/ICMP)
sudo ./target/release/netwatch
```

---

## Tabs

NetWatch has four tabs, switched with number keys:

### `1` Dashboard

The default view. Everything at a glance:

```
┌─ NetWatch ────────────────────────────────── 15:04:32 ─┐
│ [1] Dashboard  [2] Connections  [3] Interfaces  [4] Packets │
├────────────────────────────────────────────────────────┤
│ Interfaces                                              │
│ en0   192.168.1.42   ▆▆▆ 12.4 MB/s  ▃▃ 1.2 MB/s  UP   │
│ lo0   127.0.0.1      ▁▁▁  0.1 KB/s  ▁▁ 0.1 KB/s  UP   │
├────────────────────────────────────────────────────────┤
│ Bandwidth (en0) ─ RX ▁▂▃▅▆█▇▅  TX ▁▁▂▂▃▃▂▂           │
├────────────────────────────────────────────────────────┤
│ Top Connections                                         │
│ curl       TCP  ESTABLISHED  52.12.0.8:443              │
│ firefox    TCP  ESTABLISHED  142.250.1.1:443            │
├────────────────────────────────────────────────────────┤
│ Health                                                  │
│ GW 192.168.1.1: 1.2ms (0% loss)  │  DNS: 12ms (0%)    │
└────────────────────────────────────────────────────────┘
```

- **Interfaces** — All network interfaces with live RX/TX rates and UP/DOWN status
- **Sparklines** — Rolling 60-second bandwidth graph for the selected interface
- **Top Connections** — The 5 most active established connections
- **Health** — Gateway and DNS latency with packet loss percentage

### `2` Connections

Full scrollable list of every active network socket:

| Process | PID | Protocol | State | Local Address | Remote Address |
|---------|-----|----------|-------|---------------|----------------|
| firefox | 1234 | TCP | ESTABLISHED | 192.168.1.42:54321 | 142.250.1.1:443 |
| ssh | 5678 | TCP | ESTABLISHED | 192.168.1.42:22 | 10.0.0.5:49200 |

Press `s` to cycle the sort column.

### `3` Interfaces

Detailed per-interface view with:
- IPv4 and IPv6 addresses, MAC address, MTU
- Total RX/TX bytes, packets, errors, and drops
- Individual sparkline history per interface

### `4` Packets

Live packet capture with Wireshark-style protocol inspection:

```
┌─ Packets (247) ───────────────────────────────────────┐
│ #    Time         Source              Dest        Proto│
│ 42   15:04:32.123 192.168.1.42:54321  52.12.0.8:443 (HTTPS) TLS │
│ 43   15:04:32.456 192.168.1.42:51234  8.8.8.8:53 (DNS)  DNS │
├─ Protocol Detail ─────────────────────────────────────┤
│  Frame: 74 bytes on wire                               │
│  Ethernet: aa:bb:cc:dd:ee:ff → 11:22:33:44:55:66      │
│  IPv4: 192.168.1.42 → 8.8.8.8, TTL: 64, Proto: UDP   │
│  UDP: 51234 (—) → 53 (DNS), Len: 40                   │
│  DNS: Query, Name: www.google.com, Type: A             │
├─ Payload Content ─────────────────────────────────────┤
│  GET /api/users HTTP/1.1                                │
│  Host: example.com                                      │
├─ Hex Dump ────────────────┬─ ASCII ───────────────────┤
│ 0000  aa bb cc dd ee ff … │ 0000  ......               │
└───────────────────────────┴───────────────────────────┘
```

**Decoded protocols:**

| Protocol | What's shown |
|----------|-------------|
| DNS | Query/Response, domain name, record type (A, AAAA, MX…), response code |
| TLS | Client Hello / Server Hello, TLS version, SNI hostname |
| HTTP | Full request line (method, path, version) or response status |
| ICMP | Echo Request/Reply, Dest Unreachable (with reason), TTL Exceeded |
| ARP | "Who has 192.168.1.1? Tell 192.168.1.42" |
| DHCP | Discover/Offer/Request/ACK |
| NTP | Version and mode (Client/Server/Broadcast) |

---

## Keyboard Controls

### Global

| Key | Action |
|-----|--------|
| `1` `2` `3` `4` | Switch tab: Dashboard / Connections / Interfaces / Packets |
| `↑` `↓` | Scroll / select interface |
| `p` | Pause / resume all data collection |
| `r` | Force refresh all data |
| `q` | Quit |
| `Ctrl+C` | Quit |

### Connections tab

| Key | Action |
|-----|--------|
| `s` | Cycle sort column |
| `↑` `↓` | Scroll through connections |

### Packets tab

| Key | Action |
|-----|--------|
| `c` | Start / stop packet capture |
| `i` | Cycle capture interface (while stopped) |
| `f` | Toggle auto-follow (scroll to newest packets) |
| `x` | Clear all captured packets |
| `↑` `↓` | Scroll and select packets for inspection |

---

## Permissions

NetWatch works in two modes:

| Feature | Without `sudo` | With `sudo` |
|---------|---------------|-------------|
| Interface stats & rates | ✅ | ✅ |
| Active connections | ✅ | ✅ |
| Network configuration | ✅ | ✅ |
| Health probes (ICMP ping) | ❌ Shows N/A | ✅ |
| Packet capture | ❌ Permission denied | ✅ |

The app degrades gracefully — features that require elevated privileges show a clear message rather than crashing.

### macOS BPF permissions

Packet capture on macOS requires access to `/dev/bpf*` devices, which are root-only by default. You have two options:

1. **Run with sudo** (recommended for occasional use):
   ```bash
   sudo ./target/release/netwatch
   ```

2. **Open BPF devices** (persistent, for frequent use):
   ```bash
   sudo chmod 644 /dev/bpf*
   ```
   > ⚠️ This allows any user to capture packets. Resets on reboot.

---

## Project Structure

```
netwatch/
├── Cargo.toml
├── src/
│   ├── main.rs                  # Entry point, terminal setup
│   ├── app.rs                   # App state, event loop, tab management
│   ├── event.rs                 # Keyboard & tick event handling
│   ├── ui/
│   │   ├── dashboard.rs         # Dashboard composite view
│   │   ├── connections.rs       # Connections table view
│   │   ├── interfaces.rs        # Interface detail view
│   │   ├── packets.rs           # Packet capture & inspection view
│   │   └── widgets.rs           # Formatting helpers
│   ├── collectors/
│   │   ├── traffic.rs           # Interface RX/TX byte polling & rate calc
│   │   ├── connections.rs       # Socket enumeration + PID mapping
│   │   ├── config.rs            # Gateway, DNS, hostname discovery
│   │   ├── health.rs            # ICMP ping probes
│   │   └── packets.rs           # libpcap capture + protocol decoding
│   └── platform/
│       ├── linux.rs             # Linux /proc, /sys collectors
│       └── macos.rs             # macOS ifconfig, netstat collectors
├── SPEC.md                      # Design specification
└── README.md
```

---

## How It Works

### Data Collection

| Collector | Interval | Source (macOS) | Source (Linux) |
|-----------|----------|----------------|----------------|
| Interface stats | 1s | `netstat -ib` | `/sys/class/net/*/statistics` |
| Interface info | 10s | `ifconfig` | `/sys/class/net/*` + `ip addr` |
| Connections | 2s | `lsof -i -n -P` | `/proc/net/tcp` + `/proc/*/fd` |
| Config | 10s | `netstat -rn`, `scutil --dns` | `ip route`, `/etc/resolv.conf` |
| Health | 5s | `ping -c 3 -t 1` | `ping -c 3 -W 1` |
| Packets | Real-time | libpcap (BPF) | libpcap |

### Packet Decoding Pipeline

```
Raw bytes → Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP → DNS/TLS/HTTP/DHCP/NTP
                                           ↓
                                    Payload text extraction
                                    (if >70% printable ASCII)
```

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| [ratatui](https://crates.io/crates/ratatui) | Terminal UI framework |
| [crossterm](https://crates.io/crates/crossterm) | Cross-platform terminal manipulation |
| [tokio](https://crates.io/crates/tokio) | Async runtime |
| [pcap](https://crates.io/crates/pcap) | libpcap bindings for packet capture |
| [nix](https://crates.io/crates/nix) | Unix system call wrappers |
| [chrono](https://crates.io/crates/chrono) | Timestamps |
| [anyhow](https://crates.io/crates/anyhow) | Error handling |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Permission denied` on packet capture | Run with `sudo` |
| `BIOCPROMISC: operation not supported` | Interface doesn't support promiscuous mode — NetWatch falls back automatically |
| Health shows `N/A` | ICMP ping requires root — run with `sudo` |
| No connections listed | `lsof` (macOS) or `/proc` (Linux) access may be restricted |
| Binary not found after build | Check `./target/release/netwatch` exists |
| Blank screen | Ensure terminal supports 256 colors and is at least 80×24 |

---

## Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and test with `cargo build --release`
4. Submit a pull request

---

## License

MIT
