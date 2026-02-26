# NetWatch — Real-Time Network Diagnostics TUI

## Overview

NetWatch is a terminal-based (TUI) application for real-time network diagnostics and monitoring, inspired by `htop`. It provides a single-pane-of-glass view of network traffic, utilisation, configuration, and health on a local machine.

---

## Goals

- Real-time visibility into network traffic and bandwidth utilisation per interface
- Display active connections with process attribution (which process owns which socket)
- Surface key network configuration (IPs, DNS, routes, interfaces)
- Provide at-a-glance health indicators (packet loss, errors, latency to gateway)
- Keyboard-driven, responsive, and lightweight
- Cross-platform: Linux and macOS

## Non-Goals

- Remote host monitoring or agent-based collection
- Historical data storage or alerting
- Full protocol dissector plugin system (use Wireshark for custom/niche protocols)

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│                   TUI Renderer                   │
│              (ratatui / crossterm)                │
├──────────────────────────────────────────────────┤
│                  App State Layer                  │
│         (aggregation, sorting, filtering)         │
├────────────┬────────────┬────────────┬───────────┤
│  Traffic   │ Connection │  Config    │  Health   │
│  Collector │  Collector │  Collector │  Prober   │
└────────────┴────────────┴────────────┴───────────┘
         ▲            ▲           ▲           ▲
     /proc/net    netstat/ss   ifconfig    ICMP/ARP
     /sys/class   /proc/net    /etc/resolv  ping
```

### Language & Libraries

| Component       | Choice                        |
|-----------------|-------------------------------|
| Language        | Rust                          |
| TUI framework   | `ratatui` + `crossterm`       |
| Async runtime   | `tokio`                       |
| Network stats   | `sysinfo`, `/proc` (Linux), `nix` crate, `ioctl` (macOS) |
| Packet counting | `pnet` or raw sockets (optional, elevated privileges) |
| DNS resolution  | `trust-dns-resolver`          |

---

## UI Layout

```
┌─ NetWatch ──────────────────────────────── 15:04:32 ─┐
│ [1] Dashboard  [2] Connections  [3] Interfaces  [?]  │
├──────────────────────────────────────────────────────┤
│ INTERFACES            RX rate    TX rate    Status    │
│ ─────────────────────────────────────────────────     │
│ en0  192.168.1.42     ▆▆▆ 12.4 MB/s  ▃▃ 1.2 MB/s UP │
│ lo0  127.0.0.1        ▁▁▁  0.1 KB/s  ▁▁ 0.1 KB/s UP │
│ utun3 10.8.0.2        ▂▂▂  0.8 MB/s  ▂▂ 0.3 MB/s UP │
├──────────────────────────────────────────────────────┤
│ BANDWIDTH (en0)            last 60s                   │
│ RX ▁▂▃▅▆█▇▅▃▂▁▂▃▅▇█▇▅▃▂▁▁▂▃▅▆█▇▅▃▂▁▂▃▅▇█▇▅▃▂▁     │
│ TX ▁▁▂▂▃▃▂▂▁▁▁▂▂▃▃▂▂▁▁▁▁▁▂▂▃▃▂▂▁▁▁▂▂▃▃▂▂▁▁▁▁▁     │
├──────────────────────────────────────────────────────┤
│ TOP CONNECTIONS         Proto  Local        Remote    │
│  1  curl          TCP   :443   52.12.0.8    12 KB/s  │
│  2  firefox       TCP   :443   142.250.1.1   8 KB/s  │
│  3  ssh           TCP   :22    10.0.0.5      2 KB/s  │
├──────────────────────────────────────────────────────┤
│ HEALTH                                                │
│  Gateway 192.168.1.1   RTT 1.2ms   Loss 0.0%         │
│  DNS 8.8.8.8           RTT 12ms    Loss 0.0%         │
│  Errors: RX 0  TX 0   Drops: 0   Collisions: 0      │
├──────────────────────────────────────────────────────┤
│ q:Quit  /:Filter  s:Sort  p:Pause  Tab:Next Panel    │
└──────────────────────────────────────────────────────┘
```

### Tabs / Views

| Tab            | Content                                                        |
|----------------|----------------------------------------------------------------|
| **Dashboard**  | Summary of all panels (default view shown above)               |
| **Connections**| Full scrollable table of all active sockets with PID, process name, protocol, state, local/remote addr, throughput |
| **Interfaces** | Per-interface detail: IP (v4/v6), MAC, MTU, speed, RX/TX bytes/packets/errors/drops, sparkline history |
| **Packets**    | Live packet capture with protocol decoding, hex/ASCII dump, and payload inspection |

---

## Feature: Follow TCP/UDP Stream

### Overview

When a packet is selected in the Packets tab, the user can press `S` to open a **stream view** that reassembles all packets belonging to the same TCP connection or UDP conversation and displays the combined payload as a continuous, readable transcript — similar to Wireshark's "Follow TCP Stream" feature.

### Stream Identification

A stream is identified by the 4-tuple `(src_ip, src_port, dst_ip, dst_port)` plus the protocol (TCP or UDP). Both directions of the conversation are included — the tuple is matched bidirectionally:

```
Stream matches if packet's (src, dst) matches either:
  (A:portA → B:portB)  OR  (B:portB → A:portA)
```

Each unique 4-tuple is assigned a **stream index** (u32, incrementing from 0) when first seen during capture. The stream index is stored on each `CapturedPacket`.

### Data Model

```rust
/// Identifies a bidirectional stream
#[derive(Hash, Eq, PartialEq, Clone)]
pub struct StreamKey {
    pub protocol: StreamProtocol,
    pub addr_a: (IpAddr, u16),  // lower of the two endpoints (canonical order)
    pub addr_b: (IpAddr, u16),
}

pub enum StreamProtocol { Tcp, Udp }

pub struct StreamSegment {
    pub packet_id: u64,
    pub timestamp: String,
    pub direction: StreamDirection,  // AtoB or BtoA
    pub payload: Vec<u8>,
}

pub enum StreamDirection { AtoB, BtoA }

pub struct Stream {
    pub index: u32,
    pub key: StreamKey,
    pub segments: Vec<StreamSegment>,
    pub total_bytes_a_to_b: u64,
    pub total_bytes_b_to_a: u64,
    pub packet_count: u32,
}
```

### Stream Tracker

A `StreamTracker` is added to `PacketCollector`. It maintains:

- `HashMap<StreamKey, u32>` — maps 4-tuples to stream indices
- `Vec<Stream>` — all tracked streams, indexed by stream index
- A `next_index: u32` counter

On each captured packet that has both src and dst ports:
1. Canonicalise the key (lower endpoint first, by IP then port)
2. Look up or create the stream index
3. Store the stream index on `CapturedPacket.stream_index`
4. Append payload bytes (if any) as a `StreamSegment` to the stream

Memory is bounded: streams track at most `MAX_STREAM_SEGMENTS` (default 10,000) segments and `MAX_STREAM_BYTES` (default 2 MB) of payload per stream. Oldest segments are dropped when exceeded.

### UI: Stream View

Pressing `S` on a selected packet in the Packets tab opens a **stream overlay** that replaces the detail pane. The overlay shows:

```
┌─ TCP Stream #7 ── 192.168.1.42:54321 ↔ 52.12.0.8:443 ──────────┐
│ [a] Show All  [→] A→B only  [←] B→A only  [h] Hex  [t] Text    │
├──────────────────────────────────────────────────────────────────┤
│ → GET /api/users HTTP/1.1                                        │
│ → Host: api.example.com                                          │
│ → Accept: application/json                                       │
│ →                                                                │
│ ← HTTP/1.1 200 OK                                                │
│ ← Content-Type: application/json                                 │
│ ← Content-Length: 128                                            │
│ ←                                                                │
│ ← {"users": [{"id": 1, "name": "Alice"}, ...]}                  │
├──────────────────────────────────────────────────────────────────┤
│ 12 packets, 3 segments │ A→B: 245 bytes │ B→A: 892 bytes        │
│ Esc:Close  ↑↓:Scroll  →←:Direction  h:Hex/Text  s:Save          │
└──────────────────────────────────────────────────────────────────┘
```

#### Display Modes

| Mode     | Description                                                  |
|----------|--------------------------------------------------------------|
| **Text** | Default. Payload rendered as UTF-8 text (non-printable bytes shown as `·`). Direction arrows (`→` / `←`) prefix each segment. |
| **Hex**  | Side-by-side hex dump + ASCII, like the existing packet detail view, but for the entire reassembled stream. |

#### Direction Filter

| Key | Filter                           |
|-----|----------------------------------|
| `a` | Show both directions (default)   |
| `→` | Show only A→B (client→server)    |
| `←` | Show only B→A (server→client)    |

A→B is determined by which endpoint initiated the conversation (sent the first packet seen). For TCP, the SYN sender is always "A".

#### Stream View Controls

| Key   | Action                                                |
|-------|-------------------------------------------------------|
| `S`   | Open stream view for selected packet (from packet list) |
| `Esc` | Close stream view, return to packet list              |
| `↑↓`  | Scroll within the stream content                      |
| `h`   | Toggle between text and hex display mode              |
| `a`   | Show both directions                                  |
| `→`   | Filter to A→B only                                    |
| `←`   | Filter to B→A only                                    |

### Changes to CapturedPacket

Add a `stream_index: Option<u32>` field. Packets without ports (e.g., ICMP, ARP) have `stream_index: None`.

### Changes to Packets Tab

- The packet list table gains a `Stream` column showing the stream index (e.g., `#7`) when present
- The footer adds `S:Stream` to the key hints
- When stream view is open, it replaces the detail/hex panes (bottom half of the tab)

### Implementation Files

| File | Change |
|------|--------|
| `src/collectors/packets.rs` | Add `StreamKey`, `Stream`, `StreamTracker`, `stream_index` on `CapturedPacket`. Integrate tracker into capture loop. |
| `src/ui/packets.rs` | Add stream overlay rendering, stream view state, `S` key handling, direction/hex toggles. |
| `src/app.rs` | Add `stream_view_open: bool`, `stream_scroll: usize`, `stream_direction_filter`, `stream_hex_mode` to `App`. Wire `S`/`Esc`/scroll keys. |

---

## Feature: Display Filters

### Overview

The Packets tab gains a **filter bar** activated by pressing `/`. The user types a filter expression and only matching packets are displayed in the packet list. This mirrors Wireshark's display filter concept — packets are still captured in full, but the view is narrowed to matching packets.

### Filter Syntax

Filters are simple, composable expressions. No full Wireshark BPF grammar — just the most useful subset:

| Filter | Example | Matches |
|--------|---------|---------|
| Protocol name | `tcp`, `udp`, `dns`, `tls`, `http`, `arp`, `icmp` | Packets where `protocol` field matches (case-insensitive) |
| IP address | `192.168.1.42` | `src_ip` or `dst_ip` contains the value |
| `ip.src ==` | `ip.src == 192.168.1.42` | Source IP exact match |
| `ip.dst ==` | `ip.dst == 8.8.8.8` | Destination IP exact match |
| Port number | `port 443` | `src_port` or `dst_port` equals the value |
| `port ==` | `port == 53` | Same as `port 53` |
| Stream index | `stream 7` | `stream_index` equals the value |
| Text search | `contains "hello"` | Matches if `info`, `payload_text`, `src_ip`, or `dst_ip` contains the string |
| Negation | `!dns`, `not arp` | Invert the match |
| AND | `tcp and port 443` | Both conditions must match |
| OR | `dns or icmp` | Either condition matches |
| Bare word | `google` | Shorthand for `contains "google"` — searches info and IP fields |

Operator precedence: `not` > `and` > `or`. Parentheses are not supported in v1.

### Data Model

```rust
pub enum FilterExpr {
    Protocol(String),                    // e.g. "tcp"
    SrcIp(String),                       // ip.src == x
    DstIp(String),                       // ip.dst == x
    Ip(String),                          // bare IP — matches src or dst
    Port(u16),                           // port x
    Stream(u32),                         // stream x
    Contains(String),                    // contains "x"
    Not(Box<FilterExpr>),                // !expr
    And(Box<FilterExpr>, Box<FilterExpr>),
    Or(Box<FilterExpr>, Box<FilterExpr>),
}
```

A `parse_filter(input: &str) -> Option<FilterExpr>` function tokenises the input and builds the expression tree. A `matches_packet(expr: &FilterExpr, pkt: &CapturedPacket) -> bool` function evaluates it.

### UI Behaviour

```
┌─ Packets (247 / 1203) ─── Filter: tcp and port 443 ──────────┐
│ #    Time         Source              Dest        Proto  ...   │
│ ...only matching packets shown...                              │
├──────────────────────────────────────────────────────────────┤
│ / tcp and port 443█                                           │
└──────────────────────────────────────────────────────────────┘
```

1. Press `/` — a text input bar appears at the bottom of the Packets tab, replacing the footer
2. Type the filter expression. The filter is applied **live** as the user types (each keystroke re-evaluates)
3. Press `Enter` — confirm the filter, close the input bar, filter remains active
4. Press `Esc` while typing — cancel, restore previous filter (or clear if none)
5. Press `/` again when a filter is active — edit the existing filter text
6. Press `Esc` when not in input mode and a filter is active — clear the filter entirely

The packet list header shows the filtered count vs total: `Packets (42 / 1203)`.

### App State

| Field | Type | Purpose |
|-------|------|---------|
| `packet_filter_input` | `bool` | Whether the filter input bar is visible |
| `packet_filter_text` | `String` | Current text in the filter input |
| `packet_filter_active` | `Option<String>` | The confirmed filter string (applied to display) |

### Changes to Packets Tab Rendering

- `render_packet_list`: Before building rows, filter `packets` through `matches_packet()` if `packet_filter_active` is set. Show `(matched / total)` in the block title.
- `render_footer`: When `packet_filter_input` is true, replace the footer with an editable text input showing the filter string with a cursor.

### Implementation Files

| File | Change |
|------|--------|
| `src/collectors/packets.rs` | Add `FilterExpr` enum, `parse_filter()`, and `matches_packet()` |
| `src/ui/packets.rs` | Filter packet list, render filter input bar, show matched/total count |
| `src/app.rs` | Add filter state fields, wire `/`, `Enter`, `Esc`, and character input keys |

---

## Feature: PCAP Export

### Overview

Press `w` on the Packets tab to save all captured packets (or only filtered packets if a filter is active) to a `.pcap` file. The file is written to `~/netwatch_capture_<timestamp>.pcap` in standard pcap format, readable by Wireshark, tshark, and tcpdump.

### Data Requirements

Each `CapturedPacket` stores the raw Ethernet frame bytes (`raw_bytes: Vec<u8>`) captured from libpcap. These are written verbatim as pcap packet records.

### PCAP File Format

The file is written directly (no pcap crate dependency for writing):

1. **Global header** (24 bytes): magic `0xa1b2c3d4`, version 2.4, link type Ethernet (1)
2. **Per-packet record**: 16-byte header (timestamp seconds, microseconds, captured length, original length) + raw bytes

### UI Behaviour

- Press `w` → file written immediately, a status message `"Saved 247 packets to ~/netwatch_capture_20260218_150432.pcap"` is shown briefly in the header area
- If a display filter is active, only matching packets are exported
- The export is synchronous (fast for ≤5000 packets)

### Implementation Files

| File | Change |
|------|--------|
| `src/collectors/packets.rs` | Add `raw_bytes: Vec<u8>` to `CapturedPacket`. Add `export_pcap(packets, path)` function. |
| `src/app.rs` | Add `export_status: Option<String>` field. Wire `w` key to call export and set status. |
| `src/ui/packets.rs` | Show export status in header. Add `w:Save` to footer hints. |

---

## Data Collection

### 1. Interface Traffic (polled every 1s)

| Metric              | Source (Linux)                    | Source (macOS)                |
|----------------------|-----------------------------------|-------------------------------|
| RX/TX bytes          | `/sys/class/net/<iface>/statistics` | `ioctl` / `netstat -ib`     |
| RX/TX packets        | same                              | same                          |
| RX/TX errors/drops   | same                              | same                          |
| Interface state      | `/sys/class/net/<iface>/operstate` | `ifconfig` flags             |
| IP addresses         | `getifaddrs`                      | `getifaddrs`                 |
| MAC address          | `/sys/class/net/<iface>/address`  | `getifaddrs`                 |
| MTU                  | `/sys/class/net/<iface>/mtu`      | `ioctl`                     |

Rates are derived by diffing consecutive samples.

### 2. Active Connections (polled every 2s)

- **Linux**: Parse `/proc/net/tcp`, `/proc/net/udp`, `/proc/net/tcp6`, `/proc/net/udp6`. Map inodes to PIDs via `/proc/<pid>/fd`.
- **macOS**: Shell out to `lsof -i -n -P` or use `libproc`.
- Fields: protocol, state, local address:port, remote address:port, PID, process name, UID.

### 3. Network Configuration (polled every 10s)

| Item              | Source                            |
|-------------------|-----------------------------------|
| Default gateway   | `ip route` / `netstat -rn`        |
| DNS servers       | `/etc/resolv.conf` or `scutil --dns` (macOS) |
| Routing table     | `ip route` / `netstat -rn`        |
| Hostname          | `gethostname()`                   |

### 4. Health Probes (every 5s)

| Probe                  | Method                                         |
|------------------------|-------------------------------------------------|
| Gateway latency/loss   | ICMP echo (3 pings, report avg RTT & loss %)    |
| DNS latency/loss       | ICMP echo to configured DNS servers              |
| DNS resolution check   | Resolve a known domain, report success/time      |

---

## Keyboard Controls

| Key         | Action                                      |
|-------------|---------------------------------------------|
| `1` `2` `3` | Switch to Dashboard / Connections / Interfaces |
| `Tab`       | Cycle focus between panels                   |
| `↑` `↓`    | Scroll selected panel                        |
| `s`         | Cycle sort column in active table            |
| `/`         | Open filter input (filter by process, IP, port) |
| `Esc`       | Clear filter / cancel input                  |
| `p`         | Pause/resume data collection                 |
| `r`         | Force refresh all data                       |
| `q`         | Quit                                         |
| `?`         | Show help overlay                            |

---

## Privileges

- **Unprivileged mode** (default): Interface stats, connection listing (via `/proc` or `lsof`), configuration. No per-connection throughput.
- **Elevated mode** (`sudo`): ICMP health probes, per-connection byte counters (via raw sockets or eBPF on Linux).
- The app should degrade gracefully: if ICMP fails without privileges, show "N/A" in the health panel rather than crashing.

---

## Build & Run

```bash
cargo build --release
./target/release/netwatch           # unprivileged mode
sudo ./target/release/netwatch      # full features (ICMP probes)
```

### CLI Flags

| Flag                 | Default | Description                          |
|----------------------|---------|--------------------------------------|
| `--refresh <ms>`     | 1000    | Polling interval for traffic stats   |
| `--interface <name>` | all     | Monitor only a specific interface    |
| `--no-dns`           | false   | Disable reverse DNS lookups          |
| `--no-probe`         | false   | Disable ICMP health probes           |

---

## Project Structure

```
netwatch/
├── Cargo.toml
├── src/
│   ├── main.rs              # Entry point, arg parsing, tokio setup
│   ├── app.rs               # App state, event loop, tab management
│   ├── ui/
│   │   ├── mod.rs
│   │   ├── dashboard.rs     # Dashboard composite view
│   │   ├── connections.rs   # Connections table view
│   │   ├── interfaces.rs    # Interface detail view
│   │   └── widgets.rs       # Sparklines, gauges, help overlay
│   ├── collectors/
│   │   ├── mod.rs
│   │   ├── traffic.rs       # Interface RX/TX byte polling
│   │   ├── connections.rs   # Socket enumeration + PID mapping
│   │   ├── config.rs        # Gateway, DNS, routes
│   │   └── health.rs        # ICMP ping, DNS resolution probes
│   ├── platform/
│   │   ├── mod.rs
│   │   ├── linux.rs         # Linux-specific /proc, /sys access
│   │   └── macos.rs         # macOS-specific ioctl, libproc
│   └── event.rs             # Keyboard/tick event handling
├── README.md
└── SPEC.md
```

---

## Milestones

| #  | Milestone                          | Scope                                              |
|----|------------------------------------|-----------------------------------------------------|
| M1 | Skeleton + Interface stats         | TUI shell, interface list with live RX/TX rates      |
| M2 | Bandwidth sparklines               | Rolling 60s sparkline per interface                  |
| M3 | Connection listing                 | Active sockets with PID/process, sortable table      |
| M4 | Network config panel               | Gateway, DNS, routing info                           |
| M5 | Health probes                      | ICMP gateway/DNS ping, error/drop counters           |
| M6 | macOS support                      | Platform-specific collectors for macOS               |
| M7 | Polish                             | Filtering, help overlay, colour themes, man page     |
| M8 | Follow TCP/UDP Stream              | Stream tracking, reassembly, stream overlay UI with text/hex modes and direction filtering |
| M9 | Display Filters                    | `/` filter bar with protocol, IP, port, stream, text search, and/or/not combinators |
| M10 | PCAP Export                       | `w` key saves captured packets to a .pcap file for Wireshark analysis |
| M11 | Protocol Statistics               | `[5] Stats` tab with protocol hierarchy table showing packet counts, byte totals, percentages, and distribution bars |
| M12 | Coloring Rules / Expert Info      | Expert severity per packet (Error/Warn/Note/Chat) with condition-based row coloring and indicator column (● ▲ ·). RST→red, DNS NXDOMAIN→red, FIN→cyan, zero window→yellow, ICMP unreachable→yellow, HTTP 4xx/5xx→yellow |
| M13 | Connection → Packet Linking       | Press `Enter` on a connection in tab 2 to jump to Packets tab with a display filter auto-set matching that connection's protocol, remote IP, and port |
| M14 | Capture Filters (BPF)             | Press `b` to set a BPF expression (e.g. `port 443`, `host 10.0.0.1`) applied via `pcap::set_filter()` before capture starts. Shown in header, editable when stopped |
| M15 | Help Overlay                      | Press `?` for full-screen scrollable help popup with all keybindings by context, display filter syntax reference, expert info legend. Esc/?:close, ↑↓:scroll |
| M16 | GeoIP Location                    | Background GeoIP lookup via ip-api.com for public IPs. Location column in Connections tab, Geo lines in packet detail. `g` key toggles on/off. Rate-limited, cached, skips private IPs |
