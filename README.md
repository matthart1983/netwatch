# NetWatch

**Real-time network diagnostics in your terminal — like htop for your network.**

NetWatch is a lightweight, keyboard-driven TUI application that gives you instant visibility into network traffic, active connections, interface health, and live packet capture with deep protocol inspection. Built with Rust for speed and low overhead.

![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Demo

<p align="center">
  <img src="demo.gif" alt="NetWatch demo — Dashboard, Connections, Interfaces, and Help overlay" width="800">
</p>

> Dashboard with live interface stats, bandwidth graphs, top connections, health probes, and latency heatmap. Packet capture with deep protocol inspection available when run with `sudo`.

---

## Features

- **Live interface monitoring** — RX/TX rates, totals, and 60-second sparkline history for every network interface
- **Aggregate bandwidth graph** — Full-width RX/TX sparklines across all active interfaces on the Dashboard
- **Active connections** — Every open socket with process name, PID, protocol, state, and addresses (sortable)
- **Network health** — ICMP ping probes to gateway and DNS with RTT and packet loss
- **Latency heatmap** — Color-coded RTT history for gateway and DNS on the Dashboard
- **Packet capture** — Wireshark-style live capture with deep protocol decoding:
  - **DNS** — Query names, types (A, AAAA, CNAME…), response codes
  - **TLS** — Handshake type, version, SNI hostname extraction
  - **HTTP** — Method, path, and response status lines
  - **ICMP** — Human-readable type/code (Echo Request, Dest Unreachable, TTL Exceeded…)
  - **ARP, DHCP, NTP, mDNS** — Decoded with meaningful summaries
  - **TCP payload** — Readable text content extracted and displayed
  - **25+ service labels** — Ports mapped to names (SSH, HTTPS, PostgreSQL, Redis…)
- **TCP stream reassembly** — Follow TCP/UDP conversations with text and hex views
- **TCP handshake timing** — Automatic SYN→SYN-ACK→ACK latency measurement per connection
- **Display filters** — Wireshark-style filter bar with protocol, IP, port, stream, text search, and/or/not combinators
- **BPF capture filters** — Set Berkeley Packet Filter expressions applied at capture time
- **Expert info & coloring** — Automatic severity classification (Error/Warn/Note/Chat) with color-coded rows
- **Packet bookmarks** — Mark packets of interest, jump between bookmarks
- **PCAP export** — Save captured packets (or filtered subset) to standard .pcap files
- **Protocol statistics** — Protocol hierarchy table with packet counts, byte totals, and distribution bars
- **Handshake histogram** — Latency distribution chart with min/avg/median/p95/max stats
- **GeoIP location** — Background IP geolocation with country, city, and org display
- **Whois lookup** — On-demand RDAP whois for any IP address
- **Connection → packet linking** — Jump from a connection to filtered packet view
- **Help overlay** — Full scrollable keybinding reference with filter syntax and expert legend
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

NetWatch has five tabs, switched with number keys `1`–`5`:

### `1` Dashboard

The default view. Everything at a glance:

- **Interfaces** — All network interfaces with live RX/TX rates and UP/DOWN status
- **Bandwidth graph** — Full-width aggregate RX/TX sparklines across all active interfaces (last 60s)
- **Top connections** — The 5 most active established connections
- **Health** — Gateway and DNS latency with packet loss percentage
- **Latency heatmap** — Color-coded RTT history bars for gateway and DNS (green→yellow→orange→red)

### `2` Connections

Full scrollable list of every active network socket:

| Process | PID | Proto | State | Local Address | Remote Address | Location |
|---------|-----|-------|-------|---------------|----------------|----------|
| firefox | 1234 | TCP | ESTABLISHED | 192.168.1.42:54321 | 142.250.1.1:443 | US Mountain View, Google |

- Press `s` to cycle the sort column
- Press `Enter` to jump to Packets tab with a filter matching the selected connection
- Press `W` for whois lookup on the remote IP
- Press `g` to toggle GeoIP location column

### `3` Interfaces

Detailed per-interface view with:
- IPv4 and IPv6 addresses, MAC address, MTU
- Total RX/TX bytes, packets, errors, and drops
- Individual sparkline history per interface

### `4` Packets

Live packet capture with Wireshark-style protocol inspection:

- **Packet list** — Scrollable table with expert severity indicator, stream index, protocol coloring
- **Protocol detail** — Layer-by-layer decode (Ethernet → IP → TCP/UDP → Application)
- **GeoIP & Whois** — Location and network ownership in the detail pane
- **Handshake timing** — `⏱ SYN→SYN-ACK: 5.2ms │ SYN-ACK→ACK: 3.1ms │ Total: 8.3ms`
- **Payload content** — Readable text extracted from application data
- **Hex/ASCII dump** — Raw packet bytes with side-by-side hex and ASCII
- **Stream view** — Press `s` to follow the TCP/UDP conversation with direction arrows
- **Bookmarks** — Press `m` to mark packets, `n`/`N` to jump between them

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

### `5` Stats

Protocol statistics and performance analysis:

- **Protocol hierarchy** — Table of all seen protocols with packet counts, byte totals, percentages, and distribution bars
- **Handshake histogram** — TCP handshake latency distribution across 7 buckets (<1ms to >500ms) with min/avg/median/p95/max summary

---

## Keyboard Controls

### Global

| Key | Action |
|-----|--------|
| `1` `2` `3` `4` `5` | Switch tab: Dashboard / Connections / Interfaces / Packets / Stats |
| `↑` `↓` | Scroll / select |
| `p` | Pause / resume all data collection |
| `r` | Force refresh all data |
| `g` | Toggle GeoIP location display |
| `?` | Show help overlay |
| `q` / `Ctrl+C` | Quit |

### Connections tab

| Key | Action |
|-----|--------|
| `s` | Cycle sort column |
| `Enter` | Jump to Packets tab with auto-filter for selected connection |
| `W` | Whois lookup for selected connection's remote IP |

### Packets tab

| Key | Action |
|-----|--------|
| `c` | Start / stop packet capture |
| `i` | Cycle capture interface (while stopped) |
| `b` | Set BPF capture filter (while stopped) |
| `/` | Open display filter bar |
| `Esc` | Clear display filter |
| `Enter` | Select packet at cursor |
| `s` | Open stream view for selected packet |
| `w` | Export packets to .pcap file |
| `f` | Toggle auto-follow (scroll to newest) |
| `x` | Clear all captured packets |
| `m` | Toggle bookmark on selected packet |
| `n` / `N` | Jump to next / previous bookmark |
| `W` | Whois lookup for selected packet's IPs |

### Stream view (within Packets tab)

| Key | Action |
|-----|--------|
| `Esc` | Close stream view |
| `↑` `↓` | Scroll stream content |
| `→` `←` | Filter to A→B / B→A direction |
| `a` | Show both directions |
| `h` | Toggle hex / text mode |

### Display filter syntax

| Filter | Example | Matches |
|--------|---------|---------|
| Protocol | `tcp`, `udp`, `dns`, `icmp`, `arp` | Protocol field match |
| IP address | `192.168.1.42` | Source or destination IP |
| Directional IP | `ip.src == 10.0.0.1` | Source IP only |
| Port | `port 443` | Source or destination port |
| Stream | `stream 7` | Stream index match |
| Text search | `contains "hello"` | Search info, payload, IPs |
| Negation | `!dns`, `not arp` | Invert match |
| Combinators | `tcp and port 443`, `dns or icmp` | Logical AND / OR |
| Bare word | `google` | Shorthand for `contains "google"` |

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
│   │   ├── stats.rs             # Protocol statistics & handshake histogram
│   │   ├── help.rs              # Scrollable help overlay
│   │   └── widgets.rs           # Formatting helpers
│   ├── collectors/
│   │   ├── traffic.rs           # Interface RX/TX byte polling & rate calc
│   │   ├── connections.rs       # Socket enumeration + PID mapping
│   │   ├── config.rs            # Gateway, DNS, hostname discovery
│   │   ├── health.rs            # ICMP ping probes + RTT history
│   │   ├── packets.rs           # libpcap capture + protocol decoding + stream tracking
│   │   ├── geo.rs               # Background GeoIP lookup (ip-api.com)
│   │   └── whois.rs             # Background RDAP whois lookup
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
| GeoIP | On-demand | ip-api.com (HTTP) | ip-api.com (HTTP) |
| Whois | On-demand | rdap.org (HTTPS) | rdap.org (HTTPS) |

### Packet Decoding Pipeline

```
Raw bytes → Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP → DNS/TLS/HTTP/DHCP/NTP
                                            ↓
                              Stream tracking (per 4-tuple)
                              TCP handshake timing (SYN/SYN-ACK/ACK)
                              Expert info classification
                              Payload text extraction
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
| [ureq](https://crates.io/crates/ureq) | HTTP client (GeoIP, Whois) |
| [serde_json](https://crates.io/crates/serde_json) | JSON parsing (API responses) |

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
| GeoIP/Whois not loading | Requires internet access; results appear after a short delay |

---

## Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and test with `cargo build --release`
4. Submit a pull request

---

## License

MIT
