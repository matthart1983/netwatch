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
│ [1] Dash [2] Conn [3] Iface [4] Pkt [5] Stats       │
│ [6] Topo [7] Time [8] Insights                  [?]  │
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
| **Stats**      | Protocol hierarchy table with packet counts, byte totals, and distribution bars. Handshake histogram |
| **Topology**   | ASCII box diagram showing local machine, gateway, DNS servers, and top remote hosts with connection counts and health indicators |
| **Timeline**   | Gantt-style bar chart of connection lifetimes, color-coded by state with adjustable time windows |
| **Insights**   | AI-powered network analysis via Ollama with auto and on-demand analysis |

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
| M17 | Whois Lookup                      | On-demand RDAP whois via rdap.org. `W` key triggers lookup for selected IPs (Packets + Connections tabs). Results shown in packet detail pane. Background thread with rate limiting and caching |
| M18 | Packet Bookmarks                  | `m` toggles bookmark (★) on selected packet. `n`/`N` jump to next/previous bookmark. Bookmark count in title. Cleared on `x` |
| M19 | Interface Bandwidth Graph         | Full-width aggregate RX/TX sparklines on Dashboard replacing histogram. Shows current rate in title, aggregates across all active non-loopback interfaces |
| M20 | Latency Heatmap                   | Color-coded RTT history (▁▂▃▄▅▆▇█) for gateway and DNS on Dashboard. Green→yellow→orange→red scaling, 60-sample history |
| M21 | Consistent UI & Footer Polish     | All tabs show full tab bar [1-8] and all global keys (q, p, r, g, a, ?) in footers |
| M22 | TCP Handshake Timing              | Automatic SYN→SYN-ACK→ACK measurement per stream. Shown in stream view header/status bar and packet detail pane. Nanosecond precision timestamps |
| M23 | Handshake Histogram               | Latency distribution chart in Stats tab. 7 buckets (<1ms to >500ms) with color-coded bars and min/avg/median/p95/max summary |
| M24 | Connection Timeline               | `[7] Timeline` tab showing a Gantt-style horizontal bar chart of connection lifetimes. Each row is a connection (process + remote), bar spans first-seen→last-seen, color-coded by state. Scrollable, with `Enter` to jump to Connections tab filtered to that entry |
| M25 | Network Topology Map              | `[6] Topology` tab showing an ASCII box diagram of local machine, gateway, DNS, and top remote hosts with connection counts on edges. Auto-laid-out, color-coded by health, scrollable |
| M26 | AI Network Insights               | `[8] Insights` tab with real-time AI analysis of captured traffic via Ollama. Auto-analyzes every 15s, on-demand with `a` key. Detects security concerns, performance issues, anomalies. Graceful degradation when Ollama unavailable |

---

## Feature: Connection Timeline

### Overview

The Timeline tab (`[7] Timeline`) provides a Gantt-style horizontal bar chart showing when connections were first observed and when they disappeared (or are still active). This gives at-a-glance visibility into connection storms, long-lived connections, and churn patterns over time.

### Connection Tracking

The existing `ConnectionCollector` polls every 2 seconds and replaces its entire `connections` vec each cycle. To support a timeline, a new `ConnectionTimeline` tracker wraps the collector and maintains historical state:

```rust
use std::time::Instant;

/// Unique identity for a tracked connection
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct ConnectionKey {
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub pid: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct TrackedConnection {
    pub key: ConnectionKey,
    pub process_name: Option<String>,
    pub state: String,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub is_active: bool,
}

pub struct ConnectionTimeline {
    pub tracked: Vec<TrackedConnection>,
    known_keys: HashSet<ConnectionKey>,
}
```

On each `ConnectionCollector::update()` cycle:
1. Build a `HashSet<ConnectionKey>` from the current snapshot
2. For each current connection:
   - If the key exists in `tracked`, update `last_seen` to `Instant::now()`, update `state`, mark `is_active = true`
   - If new, insert a `TrackedConnection` with `first_seen = last_seen = Instant::now()`, `is_active = true`
3. For any previously-tracked key not in the current snapshot, set `is_active = false` (keep `last_seen` as-is — that was the last time it was observed)

Memory is bounded: drop the oldest inactive connections when `tracked.len()` exceeds `MAX_TRACKED_CONNECTIONS` (default 2000).

### UI: Timeline Tab

```
┌─ NetWatch ──────────────────────────────── 15:04:32 ─┐
│ [1] Dashboard  [2] Connections  [3] Interfaces       │
│ [4] Packets  [5] Stats  [6] Timeline        [?]      │
├──────────────────────────────────────────────────────┤
│ TIMELINE (last 5m)          ← 5m ago        now →    │
│ ─────────────────────────────────────────────────     │
│ ssh        10.0.0.5    ████████████████████████████▓  │
│ firefox    142.250.1.1      ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  │
│ curl       52.12.0.8             ██░░                 │
│ node       127.0.0.1   ████████████████████████████▓  │
│ DNS        8.8.8.8        █░ █░ █░  █░ █░ █░  █░     │
│ chrome     172.217.0.4        ▓▓▓▓▓▓▓▓▓▓░░           │
│ postgres   127.0.0.1   ████████████████████████████▓  │
│                                                       │
├──────────────────────────────────────────────────────┤
│ Active: 5  │  Closed: 2  │  Total seen: 7            │
├──────────────────────────────────────────────────────┤
│ q:Quit  ↑↓:Scroll  Enter:→Connections  t:Timespan    │
│ p:Pause  r:Refresh  1-6:Tab  g:Geo  ?:Help           │
└──────────────────────────────────────────────────────┘
```

#### Bar Rendering

The timeline area maps a time window onto the available terminal width. Each row is one `TrackedConnection`:

| Symbol | Meaning |
|--------|---------|
| `█` (solid) | Connection was active during this time slice and in ESTABLISHED state |
| `▓` (dense) | Connection is currently active (rightmost edge) |
| `░` (light) | Connection was in a transient state (SYN_SENT, TIME_WAIT, CLOSE_WAIT, etc.) |
| ` ` (blank) | Connection did not exist during this time slice |

#### Color Coding

| State | Color |
|-------|-------|
| ESTABLISHED | Green |
| LISTEN | Yellow |
| SYN_SENT / SYN_RECV | Cyan |
| CLOSE_WAIT / TIME_WAIT / FIN_WAIT | Red |
| Inactive (closed) | DarkGray |

#### Time Window

The default window is 5 minutes. Press `t` to cycle through:
- 1 minute
- 5 minutes (default)
- 15 minutes
- 30 minutes
- 1 hour

The window always ends at "now" and scrolls forward with each tick.

#### Sorting

Rows are sorted by `first_seen` (oldest at top). Active connections sort before inactive ones at the same start time.

#### Controls

| Key | Action |
|-----|--------|
| `↑↓` | Scroll through connections |
| `Enter` | Jump to Connections tab filtered to the selected connection's remote IP |
| `t` | Cycle time window (1m → 5m → 15m → 30m → 1h) |
| `1`–`8` | Switch tabs |

### App State

| Field | Type | Purpose |
|-------|------|---------|
| `connection_timeline` | `ConnectionTimeline` | Tracks connection first/last seen times |
| `timeline_scroll` | `usize` | Scroll offset in the timeline view |
| `timeline_window` | `TimelineWindow` | Current time window (enum: Min1, Min5, Min15, Min30, Hour1) |

### Changes to Tab Enum

Add `Timeline` variant to the `Tab` enum. Update tab switching to accept `7`.

### Implementation Files

| File | Change |
|------|--------|
| `src/collectors/connections.rs` | Add `ConnectionKey`, `TrackedConnection`, `ConnectionTimeline` structs. Add `update_timeline()` method. |
| `src/ui/timeline.rs` | New file. Render timeline header, Gantt chart, summary bar, footer. |
| `src/ui/mod.rs` | Add `pub mod timeline;`, wire `Tab::Timeline` in render dispatch. |
| `src/app.rs` | Add `Tab::Timeline`, `timeline_scroll`, `timeline_window`, `connection_timeline` fields. Wire `6`, `t`, `Enter`, `↑↓` keys. Call `connection_timeline.update()` alongside connection collector. |

---

## Feature: Network Topology Map

### Overview

The Topology tab (`[6] Topology`) renders an ASCII box-and-line diagram showing the local machine at the centre, connected to the gateway, DNS servers, and the top remote hosts grouped by process. This provides an at-a-glance view of the network neighbourhood — who the machine is talking to, how many connections exist per remote, and the health of each link.

### Data Sources

The topology is built from data already collected by existing collectors — no new system calls are needed:

| Node type | Source |
|-----------|--------|
| **Local machine** | `ConfigCollector.config.hostname`, active interface IPs from `interface_info` |
| **Gateway** | `ConfigCollector.config.gateway` |
| **DNS servers** | `ConfigCollector.config.dns_servers` |
| **Remote hosts** | Deduplicated remote IPs from `ConnectionCollector.connections` |
| **Edge metadata** | Connection count per remote IP, process names, protocol |
| **Health indicators** | `HealthProber.status` RTT/loss for gateway and DNS |
| **GeoIP labels** | `GeoCache` lookups (when `show_geo` is enabled) |

### Data Model

```rust
pub struct TopologyNode {
    pub kind: NodeKind,
    pub label: String,          // e.g. "192.168.1.1" or "myhost"
    pub sublabel: Option<String>, // e.g. "GW 1.2ms" or "US, Cloudflare"
    pub health: NodeHealth,
}

pub enum NodeKind {
    LocalMachine,
    Gateway,
    DnsServer,
    RemoteHost,
}

pub enum NodeHealth {
    Good,       // green — reachable, low latency
    Degraded,   // yellow — high latency or partial loss
    Down,       // red — unreachable or 100% loss
    Unknown,    // gray — no probe data available
}

pub struct TopologyEdge {
    pub conn_count: usize,
    pub processes: Vec<String>,   // deduplicated process names on this edge
    pub protocols: Vec<String>,   // deduplicated protocols (TCP, UDP)
}
```

The topology is recomputed on each render from existing collector state — no persistent data structure is needed.

### Layout Algorithm

The map uses a fixed 3-column layout that adapts to terminal width:

```
Column 1 (left)       Column 2 (centre)       Column 3 (right)
─────────────────     ──────────────────       ─────────────────
┌─────────────┐       ┌──────────────────┐
│ DNS 8.8.8.8 │       │                  │     ┌───────────────┐
│  12ms  0%   │───────│   myhost         │─────│ 52.12.0.8     │
└─────────────┘       │   192.168.1.42   │     │ 3×TCP (curl)  │
                      │   en0            │     └───────────────┘
┌─────────────┐       │                  │     ┌───────────────┐
│ GW          │───────│                  │─────│ 142.250.1.1   │
│ 192.168.1.1 │       │                  │     │ 5×TCP (chrome)│
│  1.2ms  0%  │       └──────────────────┘     └───────────────┘
└─────────────┘              │                 ┌───────────────┐
                             │─────────────────│ 10.0.0.5      │
                                               │ 1×TCP (ssh)   │
                                               └───────────────┘
```

**Column placement:**
- **Centre**: Local machine (always one node)
- **Left**: Infrastructure nodes — gateway and DNS servers (max 3 DNS)
- **Right**: Remote hosts, sorted by connection count descending, limited to top N that fit the terminal height

**Edge rendering:**
- Horizontal lines using `─` connecting node boxes
- Edge labels show connection count, e.g. `── 3×TCP ──`

### UI: Topology Tab

```
┌─ NetWatch ──────────────────────────────────── 15:04:32 ─┐
│ [1] Dashboard  [2] Connections  [3] Interfaces           │
│ [4] Packets  [5] Stats  [6] Timeline  [7] Topology  [?]  │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  ┌──────────┐         ┌──────────────┐     ┌────────────┐ │
│  │ DNS      │─── 0× ──│              │─ 3× │ 52.12.0.8  │ │
│  │ 8.8.8.8  │         │   myhost     │     │ curl (TCP) │ │
│  │ ●12ms 0% │         │ 192.168.1.42 │     │ US, AWS    │ │
│  └──────────┘         │ en0 / utun3  │     └────────────┘ │
│                       │              │     ┌────────────┐ │
│  ┌──────────┐         │  ↑12.4 MB/s  │─ 5× │142.250.1.1 │ │
│  │ Gateway  │── 0× ───│  ↓ 1.2 MB/s  │     │chrome (TCP)│ │
│  │192.168.1 │         │              │     │ US, Google │ │
│  │ ● 1.2ms  │         └──────────────┘     └────────────┘ │
│  └──────────┘               │              ┌────────────┐ │
│                             └────────── 1× │ 10.0.0.5   │ │
│                                            │ ssh (TCP)  │ │
│                                            └────────────┘ │
│                                                           │
├──────────────────────────────────────────────────────────┤
│ Nodes: 6  │  Connections: 9  │  Remotes: 3               │
├──────────────────────────────────────────────────────────┤
│ q:Quit  ↑↓:Scroll  Enter:→Connections  1-7:Tab           │
│ p:Pause  r:Refresh  g:Geo  ?:Help                        │
└──────────────────────────────────────────────────────────┘
```

### Node Rendering

Each node is a bordered box built from `Paragraph` + `Block`:

**Local machine node (centre):**
```
┌──────────────┐
│   myhost     │  ← hostname
│ 192.168.1.42 │  ← primary interface IP
│ en0 / utun3  │  ← active interface names
│  ↑12.4 MB/s  │  ← aggregate TX rate
│  ↓ 1.2 MB/s  │  ← aggregate RX rate
└──────────────┘
```

**Infrastructure node (gateway/DNS):**
```
┌──────────┐
│ Gateway  │  ← role label
│192.168.1 │  ← IP address
│ ● 1.2ms  │  ← health dot + RTT (green/yellow/red)
└──────────┘
```

**Remote host node:**
```
┌────────────┐
│ 52.12.0.8  │  ← IP address
│ curl (TCP) │  ← top process + protocol
│ US, AWS    │  ← GeoIP location (if enabled)
└────────────┘
```

### Health Dot Color

The `●` dot on infrastructure nodes reflects probe health:

| Condition | Color | Symbol |
|-----------|-------|--------|
| RTT < 10ms and loss = 0% | Green | `●` |
| RTT < 100ms or loss < 50% | Yellow | `●` |
| RTT ≥ 100ms or loss ≥ 50% | Red | `●` |
| No probe data | DarkGray | `○` |

Remote host nodes use the border color instead (Green for ESTABLISHED connections, DarkGray otherwise).

### Scrolling

When there are more remote hosts than fit the terminal height, only the top N by connection count are shown. `↑↓` scrolls through the remote host list, highlighting the selected node. The selected node's border turns Yellow.

### Controls

| Key | Action |
|-----|--------|
| `↑↓` | Scroll through remote hosts |
| `Enter` | Jump to Connections tab filtered to selected remote host's IP |
| `1`–`8` | Switch tabs |

### App State

| Field | Type | Purpose |
|-------|------|---------|
| `topology_scroll` | `usize` | Scroll offset for remote host list |

### Changes to Tab Enum

Add `Topology` variant to the `Tab` enum. Update tab switching to accept `6`.

### Implementation Files

| File | Change |
|------|--------|
| `src/ui/topology.rs` | New file. Build topology from app state, compute layout, render node boxes, edges, summary bar, footer. |
| `src/ui/mod.rs` | Add `pub mod topology;`, wire `Tab::Topology` in render dispatch. |
| `src/app.rs` | Add `Tab::Topology`, `topology_scroll` field. Wire `7`, `Enter`, `↑↓` keys for topology tab. |

---

## Feature: AI Network Insights

### Overview

The Insights tab (`[8] Insights`) provides real-time AI-powered analysis of captured network traffic using a local Ollama instance. Every 15 seconds, a background thread builds a structured snapshot of current network activity and sends it to the configured LLM (default: `llama3.2`) for analysis. Users can also press `a` from any tab for on-demand analysis.

### Data Flow

```
PacketCollector + ConnectionCollector + HealthProber
                    ↓
            NetworkSnapshot::build()
                    ↓
         InsightsCollector.submit_snapshot()
                    ↓
     Background thread → call_ollama() → Insight
                    ↓
            InsightsCollector.insights (Arc<Mutex<Vec<Insight>>>)
                    ↓
              UI renders scrollable insight list
```

### NetworkSnapshot

A `NetworkSnapshot` is built from existing collector data every analysis cycle:

| Field | Source |
|-------|--------|
| `total_packets` | `PacketCollector.packets.len()` |
| `protocol_counts` | Protocol distribution from last 500 packets |
| `top_talkers` | Top 10 destination IPs by packet count |
| `dns_queries` | Up to 20 unique DNS query domains |
| `expert_errors` | Up to 10 error-severity expert info messages |
| `expert_warnings` | Up to 10 warning-severity expert info messages |
| `connections_established` | Count of ESTABLISHED connections |
| `connections_other` | Count of non-ESTABLISHED connections |
| `gateway_rtt_ms` | Gateway RTT from HealthProber |
| `gateway_loss_pct` | Gateway packet loss percentage |
| `dns_rtt_ms` | DNS RTT from HealthProber |
| `dns_loss_pct` | DNS packet loss percentage |
| `bandwidth_rx` | Current aggregate RX rate string |
| `bandwidth_tx` | Current aggregate TX rate string |

### Ollama Integration

The collector calls `POST http://localhost:11434/api/chat` with:
- Model: `llama3.2` (configurable)
- System prompt: Network security and performance analyst persona
- User prompt: Structured text from `NetworkSnapshot::to_prompt()`
- Settings: `temperature: 0.3`, `num_predict: 512`, `stream: false`
- Timeout: 30 seconds

Uses `ureq` with `.send_string()` (ureq v2 API — no `send_json`).

### Insight Format

The AI is instructed to return 3-6 bullet points with emoji severity indicators:
- 🔴 Critical
- 🟡 Warning
- 🟢 Healthy
- 🔵 Info

### Status States

| Status | Meaning |
|--------|---------|
| `Idle` | No analysis performed yet |
| `Analyzing` | Request in progress to Ollama |
| `Available` | Insights ready to display |
| `Error(msg)` | Ollama returned an error |
| `OllamaUnavailable` | Cannot connect to Ollama (shows setup instructions) |

### Controls

| Key | Action |
|-----|--------|
| `a` | Trigger on-demand analysis (works from any tab) |
| `↑↓` | Scroll through insights |
| `1`–`8` | Switch tabs |

### App State

| Field | Type | Purpose |
|-------|------|---------|
| `insights_collector` | `InsightsCollector` | Manages background analysis thread and insight storage |
| `insights_scroll` | `usize` | Scroll offset in insights view |
| `last_insight_time` | `Option<Instant>` | Tracks when last auto-snapshot was sent |

### Implementation Files

| File | Change |
|------|--------|
| `src/collectors/insights.rs` | New file. `NetworkSnapshot`, `InsightsCollector`, `Insight`, `InsightsStatus`, `call_ollama()`, `analysis_loop()`. |
| `src/ui/insights.rs` | New file. Render insights header, status bar, scrollable insight list, Ollama unavailable message, footer. |
| `src/ui/mod.rs` | Add `pub mod insights;`, wire `Tab::Insights` in render dispatch. |
| `src/app.rs` | Add `Tab::Insights`, `insights_collector`, `insights_scroll`, `last_insight_time` fields. Wire `8` key, `a` key (global), snapshot submission in tick handler. |
