# NetWatch Wiki

> **Real-time network diagnostics in your terminal — like htop for your network.**

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Module Reference](#3-module-reference)
   - [Entry Point & App Core](#31-entry-point--app-core)
   - [Collectors (Data Layer)](#32-collectors-data-layer)
   - [UI (Presentation Layer)](#33-ui-presentation-layer)
   - [Platform Abstraction](#34-platform-abstraction)
4. [Data Flow](#4-data-flow)
5. [Tab System](#5-tab-system)
6. [Packet Capture Engine](#6-packet-capture-engine)
7. [Stream Reassembly](#7-stream-reassembly)
8. [Display Filter System](#8-display-filter-system)
9. [Expert Info & Coloring](#9-expert-info--coloring)
10. [Network Intelligence](#10-network-intelligence)
11. [Traceroute System](#11-traceroute-system)
12. [AI Insights (Ollama Integration)](#12-ai-insights-ollama-integration)
13. [Platform Support](#13-platform-support)
14. [Build System](#14-build-system)
15. [Configuration & Dependencies](#15-configuration--dependencies)
16. [Keyboard Controls Reference](#16-keyboard-controls-reference)
17. [Permissions Model](#17-permissions-model)
18. [Testing](#18-testing)
19. [Codebase Statistics](#19-codebase-statistics)
20. [Troubleshooting](#20-troubleshooting)

---

## 1. Project Overview

**NetWatch** is a cross-platform terminal UI (TUI) application for real-time network monitoring and diagnostics. It is published to crates.io as `netwatch-tui` (v0.3.6) and built entirely in Rust using `ratatui` + `crossterm` for rendering, `tokio` for async, and `libpcap` for packet capture.

### Goals

- Real-time visibility into network traffic and bandwidth per interface
- Active connection enumeration with process attribution (PID + name)
- Network configuration discovery (gateway, DNS, hostname)
- Health probing (ICMP ping to gateway/DNS)
- Wireshark-style packet capture with deep protocol inspection
- AI-powered network analysis via local Ollama
- Lightweight, keyboard-driven, cross-platform (Linux, macOS, Windows)

### Non-Goals

- Remote host monitoring or agent-based collection
- Historical data storage or alerting
- Full protocol dissector plugin system

### Repository

- **GitHub:** `https://github.com/matthart1983/netwatch`
- **Crate:** `https://crates.io/crates/netwatch-tui`
- **License:** MIT
- **Author:** Matt Hartley

---

## 2. Architecture

NetWatch follows a clean three-layer architecture:

```
┌──────────────────────────────────────────────────┐
│                   TUI Renderer                   │
│              (ratatui / crossterm)                │
│   dashboard │ connections │ interfaces │ packets  │
│   stats │ topology │ timeline │ insights │ help   │
├──────────────────────────────────────────────────┤
│                  App State Layer                  │
│         (aggregation, sorting, filtering)         │
│              app.rs — central hub                 │
├────────┬────────┬────────┬────────┬──────────────┤
│Traffic │Connect │Config  │Health  │ Packets      │
│Collect │Collect │Collect │Prober  │ Collector    │
├────────┴────────┴────────┴────────┤              │
│  GeoIP │ Whois │ Insights │ Trace │              │
└────────┴────────┴──────────┴──────┴──────────────┘
    ▲         ▲         ▲         ▲         ▲
/sys/class  ss/lsof   ip route   ICMP    libpcap
/proc/net   netstat   resolv.conf ping    BPF
```

### Key Design Decisions

- **Polling model:** Collectors poll at different intervals (1s for traffic, 2s for connections, 5s for health, 10s for config/interface info) via tick counting in the main event loop
- **Thread-per-collector:** CPU-intensive or blocking operations (connections, health, geo, whois, traceroute, insights) spawn dedicated OS threads using `std::thread`
- **Arc<Mutex> sharing:** Cross-thread state is shared via `Arc<Mutex<T>>` or `Arc<RwLock<T>>`
- **Event-driven:** A dedicated OS thread polls `crossterm::event` and sends `AppEvent::Key` or `AppEvent::Tick` through a `tokio::mpsc` channel
- **No persistent state:** All data is ephemeral — nothing is written to disk except optional PCAP exports

---

## 3. Module Reference

### 3.1 Entry Point & App Core

#### `src/main.rs` (34 lines)

The binary entry point. Sets up the terminal (raw mode, alternate screen, mouse capture), creates a `CrosstermBackend`, runs `app::run()`, then restores the terminal on exit.

#### `src/lib.rs` (5 lines)

Library crate root. Exports all public modules: `app`, `collectors`, `event`, `platform`, `ui`.

#### `src/app.rs` (867 lines)

The central nervous system of NetWatch. Contains:

- **`Tab` enum** — 8 variants: `Dashboard`, `Connections`, `Interfaces`, `Packets`, `Stats`, `Topology`, `Timeline`, `Insights`
- **`TimelineWindow` enum** — 5 time window sizes: 1m, 5m, 15m, 30m, 1h (with `seconds()`, `label()`, `next()`)
- **`StreamDirectionFilter` enum** — `Both`, `AtoB`, `BtoA`
- **`App` struct** — Holds all application state:
  - All 9 collectors (traffic, connections, config, health, packets, geo, whois, insights, traceroute)
  - UI state (current tab, scroll positions, selected items, filter state, overlay toggles)
  - Tick counters for polling intervals
- **`App::new()`** — Initializes all collectors, picks the best default capture interface
- **`App::pick_capture_interface()`** — Selects the first UP, non-loopback interface with an IPv4 address
- **`App::tick()`** — Called every ~1s; updates traffic, connections (every 2s), health (every 5s), config/interface info (every 10s), connection timeline, and AI insights (every 15s)
- **`run()`** — The main event loop. Creates `App` and `EventHandler`, then loops on events:
  - `AppEvent::Key` — Dispatches keyboard input to the appropriate handler based on current tab and overlay state
  - `AppEvent::Tick` — Calls `app.tick()`
- **`build_connection_filter()`** — Constructs a display filter string from a `Connection` for cross-tab navigation
- **`parse_addr_parts()`** — Splits `host:port` strings into components

#### `src/event.rs` (46 lines)

Event handling infrastructure:

- **`AppEvent`** — `Key(KeyEvent)` or `Tick`
- **`EventHandler`** — Spawns a dedicated OS thread (not a tokio task, since `crossterm::event::poll()` is blocking) that polls terminal events at 1000ms intervals, sending them through an unbounded mpsc channel

### 3.2 Collectors (Data Layer)

#### `src/collectors/traffic.rs` (104 lines)

**Purpose:** Polls interface RX/TX byte counters and computes rates.

- **`InterfaceTraffic`** — Per-interface data: name, rates, totals, packet counts, errors/drops, and 60-sample sparkline history (`VecDeque<u64>`)
- **`TrafficCollector`** — Stores previous stats + timestamp, computes per-second rates on each `update()` by diffing current vs. previous counters
- **Sparkline history:** 60 samples (one per second), stored as `VecDeque` with `make_contiguous()` called for efficient sparkline rendering
- **Update interval:** Every tick (1s)

#### `src/collectors/connections.rs` (521 lines)

**Purpose:** Enumerates active network sockets with process attribution.

- **`Connection`** — protocol, local/remote addr, state, PID, process name
- **`ConnectionCollector`** — Wraps `Arc<Mutex<Vec<Connection>>>`, spawns a thread on each `update()` to avoid blocking the UI
- **Platform-specific parsing:**
  - **macOS:** Parses `lsof -i -n -P` output (COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME)
  - **Linux:** Parses `ss -tunap` output
  - **Windows:** Parses `netstat -ano` + `tasklist /FO CSV` for PID→name resolution
- **`ConnectionTimeline`** — Tracks connection lifetimes for the Timeline tab:
  - `TrackedConnection` — key, process name, state, first_seen/last_seen `Instant`, is_active flag
  - `ConnectionKey` — (protocol, local_addr, remote_addr, pid) for deduplication
  - Evicts oldest inactive connections when over `MAX_TRACKED_CONNECTIONS` (2000)
- **Update interval:** Every 2 ticks (2s)

#### `src/collectors/config.rs` (142 lines)

**Purpose:** Discovers network configuration (gateway, DNS servers, hostname).

- **`NetworkConfig`** — gateway IP, DNS server list, hostname
- **`ConfigCollector`** — Calls platform-specific functions:
  - **Gateway:** `netstat -rn` (macOS), `ip route` (Linux), `route print` (Windows)
  - **DNS:** `/etc/resolv.conf` (Unix), fallback to `scutil --dns` (macOS) or `ipconfig /all` (Windows)
  - **Hostname:** `nix::unistd::gethostname()` (Unix), `COMPUTERNAME` env var (Windows)
- **Update interval:** Every 10 ticks (10s)

#### `src/collectors/health.rs` (268 lines)

**Purpose:** ICMP ping probes to gateway and DNS servers.

- **`HealthStatus`** — RTT (ms), loss (%), and 60-sample RTT history for both gateway and DNS
- **`HealthProber`** — Spawns a thread that runs `ping -c 3` to gateway and DNS targets
- **Ping parsing:**
  - `parse_loss()` — Extracts packet loss percentage from ping output (handles Linux, macOS, and Windows formats)
  - `parse_avg_rtt()` — Extracts average RTT from `min/avg/max` line or Windows `Average =` line
- **RTT history:** 60 samples stored in `VecDeque<Option<f64>>` for the latency heatmap
- **Update interval:** Every 5 ticks (5s)
- **Requires:** Root/sudo for ICMP raw sockets

#### `src/collectors/packets.rs` (2133 lines) — *Largest file*

**Purpose:** Live packet capture with deep protocol decoding, stream tracking, and expert classification.

**Core types:**
- **`CapturedPacket`** — Complete decoded packet: ID, timestamp, IPs, ports, protocol, length, info string, detail lines, payload text, raw hex/ASCII/bytes, stream index, TCP flags, expert severity, nanosecond timestamp
- **`ExpertSeverity`** — `Chat`, `Note`, `Warn`, `Error`

**Packet collector:**
- **`PacketCollector`** — Manages capture lifecycle:
  - `start_capture(interface, bpf_filter)` — Opens pcap device in promiscuous mode (1MB buffer, 1ms timeout), applies optional BPF filter, spawns capture thread
  - `stop_capture()` — Signals capture thread to stop via `AtomicBool`
  - `get_packets()` — Returns cloned packet buffer (max 5000 packets)
  - `export_pcap(path, filter)` — Writes packets to standard .pcap file format
- **Capture thread:** Reads raw frames, decodes through the protocol stack, enriches with DNS resolution, stream tracking, and expert classification

**Protocol decoding pipeline:**
```
Raw frame → Ethernet (or raw IP) →
  ├─ ARP → parse_arp()
  ├─ IPv4 → parse_ipv4_header()
  │   ├─ TCP → parse_tcp(), tcp_flags()
  │   │   ├─ DNS (port 53) → parse_dns()
  │   │   ├─ TLS (port 443) → parse_tls()
  │   │   ├─ HTTP (port 80) → parse_http()
  │   │   └─ Payload text extraction
  │   ├─ UDP → parse_udp()
  │   │   ├─ DNS (port 53) → parse_dns()
  │   │   ├─ DHCP (port 67/68) → parse_dhcp()
  │   │   ├─ NTP (port 123) → parse_ntp()
  │   │   ├─ mDNS (port 5353) → parse_dns()
  │   │   └─ Other
  │   └─ ICMP → icmp_type_name()
  └─ IPv6 → parse_ipv6_header()
      ├─ TCP/UDP → (same as IPv4)
      └─ ICMPv6 → icmpv6_type_name()
```

**Decoded protocols:**
- **DNS** — Transaction ID, flags, query/response, domain name, record type (A/AAAA/CNAME/MX/NS/SOA/SRV/TXT/PTR), response code (NOERROR/NXDOMAIN/SERVFAIL/REFUSED)
- **TLS** — Content type, handshake type (Client Hello/Server Hello), TLS version, SNI hostname extraction
- **HTTP** — Request line (method + path) and response status line detection
- **ICMP** — 15+ type/code combinations with human-readable names and sub-codes
- **ICMPv6** — Echo, Neighbor Solicitation/Advertisement, Router Solicitation/Advertisement
- **ARP** — Request ("Who has X? Tell Y") and Reply ("X is at MAC") with MAC formatting
- **DHCP** — Message type (Discover/Offer/Request/ACK/NAK/Release/Inform) from options
- **NTP** — Version and mode (Client/Server/Broadcast/Symmetric)

**Supporting systems:**
- **`DnsCache`** — Async reverse DNS resolver with background thread, `HashMap` cache (max 4096), dedup via Pending state
- **`StreamTracker`** — See [Stream Reassembly](#7-stream-reassembly)
- **`TcpHandshake`** — SYN→SYN-ACK→ACK timing measurement
- **Port labels** — 25+ well-known port→name mappings (SSH, DNS, HTTP, HTTPS, PostgreSQL, Redis, etc.)
- **PCAP export** — Standard pcap file format (24-byte global header + per-packet headers with timestamps)

#### `src/collectors/geo.rs` (209 lines)

**Purpose:** Background GeoIP lookups via ip-api.com.

- **`GeoInfo`** — country_code, country, city, org
- **`GeoCache`** — Channel-based async resolver with:
  - Rate limiting: 1 request per 1.4s (ip-api.com allows 45/minute)
  - Cache: `HashMap<String, GeoEntry>` with max 4096 entries, evicts 25% when full
  - Private IP filtering: Skips RFC1918, loopback, link-local, multicast, ULA addresses
  - Entry states: `Resolved`, `Failed`, `Pending` (dedup in-flight requests)
- **API:** `http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,org,as`

#### `src/collectors/whois.rs` (209 lines)

**Purpose:** On-demand RDAP WHOIS lookups.

- **`WhoisInfo`** — net_name, net_range, org, country, description
- **`WhoisCache`** — Same pattern as GeoCache:
  - Rate limiting: 1 request per 2s
  - Cache: max 2048 entries
  - Private IP filtering (same as geo)
  - `request()` method for explicit user-triggered lookups
- **API:** `https://rdap.org/ip/{ip}` — Parses RDAP JSON for entities, vCard names, address ranges

#### `src/collectors/insights.rs` (533 lines)

**Purpose:** AI-powered network analysis via local Ollama. See [AI Insights](#12-ai-insights-ollama-integration).

#### `src/collectors/traceroute.rs` (229 lines)

**Purpose:** Built-in hop-by-hop traceroute. See [Traceroute System](#11-traceroute-system).

### 3.3 UI (Presentation Layer)

All UI modules follow the same pattern: a `render(f: &mut Frame, app: &App, area: Rect)` function that takes the ratatui frame, app state reference, and layout area.

#### `src/ui/dashboard.rs` (481 lines)

Composite view with 7 vertically-stacked sections:
1. **Header** — Tab bar with active tab highlighted, clock
2. **Interface table** — All interfaces with IP, RX/TX rates, totals, UP/DOWN status
3. **Bandwidth graph** — Aggregate RX/TX sparklines across all active (non-loopback) interfaces, or per-interface sparklines when one is selected
4. **Top connections** — 5 most recent ESTABLISHED connections
5. **Health status** — Gateway/DNS RTT and loss with color coding
6. **Latency heatmap** — Unicode block characters (▁▂▃▄▅▆▇█) color-coded by RTT ratio (green < 30% → yellow < 60% → orange < 85% → red)
7. **Footer** — Keyboard shortcut hints

#### `src/ui/connections.rs` (356 lines)

Sortable, scrollable connection table with:
- 6 columns: Process, PID, Proto, State, Local Address, Remote Address (+ optional Location)
- Sort indicator (▼) on the active sort column
- State-based color coding: Green (ESTABLISHED), Yellow (LISTEN), Red (CLOSE_WAIT/TIME_WAIT)
- Selected row highlight (DarkGray background)
- GeoIP location column (toggleable with `g`)
- Traceroute overlay (same as topology — centered modal with hop table)

#### `src/ui/interfaces.rs` (216 lines)

Per-interface detail view showing:
- IPv4/IPv6 addresses, MAC address, MTU
- Total RX/TX bytes, packets, errors, drops
- Individual interface sparklines

#### `src/ui/packets.rs` (755 lines)

The most complex UI tab. Multi-pane layout:
- **Packet list** — Scrollable table with columns: ID, Time, Stream#, Source, Destination, Protocol, Length, Info
  - Expert severity indicator (colored dot: 🔴🟡🔵⚪)
  - Protocol-based row coloring
  - Bookmark indicators
- **Detail pane** — Layer-by-layer protocol decode, GeoIP/Whois, handshake timing
- **Hex/ASCII dump** — Side-by-side raw bytes view
- **Stream view overlay** — TCP/UDP conversation reassembly with direction arrows
- **Filter bar** — Text input mode for display filters
- **BPF filter bar** — Text input for capture-time BPF expressions
- **Status bar** — Capture state, interface, packet count, filter status

#### `src/ui/stats.rs` (323 lines)

Two-section statistics view:
1. **Protocol hierarchy table** — Protocol name, packet count, byte total, percentage, distribution bar (using `━` characters)
2. **Handshake histogram** — 7 latency buckets (<1ms, <5ms, <10ms, <50ms, <100ms, <500ms, ≥500ms) with bar chart and min/avg/median/p95/max statistics

#### `src/ui/topology.rs` (611 lines)

ASCII network topology map with three columns:
- **Left:** Infrastructure nodes (Gateway, DNS) with health dots (●/○)
- **Center:** Local machine (hostname, IP, interfaces, bandwidth)
- **Right:** Remote hosts sorted by connection count with process/protocol/geo labels
- Edge lines with connection counts (`── 3× ──`)
- Selected node highlighting (Yellow border)
- Traceroute overlay support

#### `src/ui/timeline.rs` (295 lines)

Gantt-style connection timeline:
- Horizontal bars spanning first_seen to last_seen
- Color-coded by state: Green (ESTABLISHED), Yellow (LISTEN/SYN_SENT), Cyan (SYN_RECV), Red (closing states)
- Adjustable time windows (1m/5m/15m/30m/1h)
- Active connections shown first, sorted by first_seen

#### `src/ui/insights.rs` (197 lines)

AI insights display:
- Status-dependent rendering (Idle/Analyzing/Available/Error/Unavailable)
- Scrollable list of timestamped insights
- Ollama setup instructions when unavailable
- Analysis trigger hint

#### `src/ui/help.rs` (189 lines)

Scrollable help overlay rendered on top of any tab:
- Complete keyboard shortcut reference organized by context (Global, Connections, Packets, Stream, Topology, Timeline, Insights)
- Display filter syntax reference table
- Expert info legend

#### `src/ui/widgets.rs` (23 lines)

Shared formatting utilities:
- `format_bytes_rate(f64)` — Human-readable bytes/sec (B/s → KB/s → MB/s → GB/s)
- `format_bytes_total(u64)` — Human-readable total bytes

### 3.4 Platform Abstraction

#### `src/platform/mod.rs` (61 lines)

Defines shared types and dispatches to platform-specific implementations:
- **`InterfaceStats`** — rx/tx bytes, packets, errors, drops per interface
- **`InterfaceInfo`** — name, IPv4/IPv6, MAC, MTU, is_up
- **`collect_interface_stats()`** — Returns `HashMap<String, InterfaceStats>`
- **`collect_interface_info()`** — Returns `Vec<InterfaceInfo>`

#### `src/platform/linux.rs` (113 lines)

- **Stats:** Reads `/sys/class/net/*/statistics/{rx_bytes,tx_bytes,...}` directly
- **Info:** Reads `/sys/class/net/*/{operstate,mtu,address}` + parses `ip addr show`

#### `src/platform/macos.rs` (105 lines)

- **Stats:** Parses `netstat -ib` output (deduplicates multi-address rows)
- **Info:** Parses `ifconfig` output (inet, inet6, ether, mtu, UP flag)

#### `src/platform/windows.rs` (262 lines)

- **Stats:** Primary: `PowerShell Get-NetAdapterStatistics | ConvertTo-Json`. Fallback: `netstat -e` aggregate stats
- **Info:** Parses `ipconfig /all` output with `Key.....: Value` format, `netsh interface ipv4 show subinterfaces` for MTU
- **Device name resolution:** Maps friendly names (e.g., "Ethernet") to `\Device\NPF_{GUID}` paths for pcap

---

## 4. Data Flow

### Main Event Loop

```
┌────────────┐     AppEvent::Tick (1s)      ┌──────────┐
│ EventHandler│ ──────────────────────────── │ app.tick()│
│  (OS thread)│                              └──────┬───┘
│             │     AppEvent::Key            ┌──────▼───────────┐
│  polls      │ ──────────────────────────── │ Key handler       │
│  crossterm  │                              │ (match on tab +   │
│  every 1s   │                              │  key combination) │
└────────────┘                              └──────┬───────────┘
                                                    │
                                             ┌──────▼───────┐
                                             │ terminal.draw │
                                             │ (ratatui)     │
                                             └──────────────┘
```

### Tick Cascade

| Tick Count | Action | Collector |
|-----------|--------|-----------|
| Every 1 | `traffic.update()` | TrafficCollector |
| Every 2 | `connection_collector.update()` | ConnectionCollector |
| Every 2 | `connection_timeline.update()` | ConnectionTimeline |
| Every 5 | `health_prober.probe()` | HealthProber |
| Every 10 | `platform::collect_interface_info()` | Platform |
| Every 10 | `config_collector.update()` | ConfigCollector |
| Every 15 | Submit NetworkSnapshot to InsightsCollector | InsightsCollector |

### Cross-Tab Navigation

Several tabs support jumping to related views:
- **Connections → Packets:** `Enter` builds a display filter matching the selected connection and switches to Packets tab
- **Topology → Connections:** `Enter` filters connections by the selected remote host's IP
- **Timeline → Connections:** `Enter` filters by the selected entry's remote IP
- **Connections → Traceroute:** `T` opens traceroute overlay for selected connection's remote IP
- **Topology → Traceroute:** `T` opens traceroute overlay for selected remote host

---

## 5. Tab System

NetWatch has 8 tabs, switched with number keys `1`–`8`:

| # | Tab | File | Description |
|---|-----|------|-------------|
| 1 | Dashboard | `ui/dashboard.rs` | At-a-glance summary: interfaces, bandwidth, top connections, health, heatmap |
| 2 | Connections | `ui/connections.rs` | Full sortable table of all active sockets with process attribution |
| 3 | Interfaces | `ui/interfaces.rs` | Per-interface detail: IPs, MAC, MTU, stats, sparklines |
| 4 | Packets | `ui/packets.rs` | Wireshark-style live capture with protocol inspection |
| 5 | Stats | `ui/stats.rs` | Protocol hierarchy + handshake latency histogram |
| 6 | Topology | `ui/topology.rs` | ASCII network map with health indicators |
| 7 | Timeline | `ui/timeline.rs` | Gantt-chart of connection lifetimes |
| 8 | Insights | `ui/insights.rs` | AI-powered network analysis via Ollama |

The `Tab` enum is defined in `app.rs`. The main render dispatch in `app::run()` calls the appropriate `ui::*::render()` function based on `app.current_tab`.

---

## 6. Packet Capture Engine

### Lifecycle

1. User presses `c` on the Packets tab → `PacketCollector::start_capture(interface, bpf_filter)`
2. Opens pcap device: promiscuous mode, 1MB buffer, 1ms read timeout
3. Optionally applies BPF filter string
4. Spawns capture thread that loops on `cap.next_packet()`
5. Each packet is decoded through the full protocol stack
6. Decoded `CapturedPacket` is sent via `mpsc::Sender` to the collector
7. Collector stores in `Arc<RwLock<Vec<CapturedPacket>>>` (max 5000)
8. User presses `c` again → sets `AtomicBool` stop flag, capture thread exits

### Protocol Decode Functions

| Function | Protocol | Key Outputs |
|----------|----------|-------------|
| `parse_arp(data, details)` | ARP | "Who has X? Tell Y" / "X is at MAC" |
| `parse_dns(data, protocol)` | DNS | Query/Response, domain, record type, response code |
| `parse_tls(data, details)` | TLS | Handshake type, version, SNI hostname |
| `parse_http(data, protocol)` | HTTP | Request line or response status |
| `parse_dhcp(data, details)` | DHCP | Message type from options |
| `parse_ntp(data, details)` | NTP | Version and mode |
| `icmp_type_name(type, code)` | ICMP | Human-readable type/code string |
| `icmpv6_type_name(type)` | ICMPv6 | Human-readable type string |
| `parse_ipv4_header(data)` | IPv4 | src/dst IP, protocol, header length |
| `parse_ipv6_header(data)` | IPv6 | src/dst IP, next header, payload length |
| `parse_tcp(data)` | TCP | src/dst port, flags, seq/ack, window |
| `parse_udp(data)` | UDP | src/dst port, length |
| `tcp_flags(flags)` | TCP | Comma-separated flag names (SYN,ACK,FIN,RST,PSH,URG) |
| `port_label(port)` | — | Well-known service name (SSH, HTTPS, etc.) |
| `format_mac(bytes)` | Ethernet | Colon-separated MAC address |

### PCAP Export

`export_pcap()` writes a standard pcap file:
- **Global header:** Magic number `0xa1b2c3d4`, version 2.4, max packet length 65535, link type Ethernet
- **Per-packet:** Timestamp (sec + usec), captured length, original length, raw bytes
- Respects optional display filter — only matching packets are exported

---

## 7. Stream Reassembly

TCP/UDP stream tracking enables "Follow TCP Stream" functionality similar to Wireshark.

### Stream Identification

A stream is identified by a canonical 4-tuple: `(protocol, addr_a, addr_b)` where `addr_a ≤ addr_b` (lexicographic ordering ensures bidirectional matching).

### Data Model

```rust
StreamKey { protocol: Tcp|Udp, addr_a: (ip, port), addr_b: (ip, port) }
StreamSegment { packet_id, timestamp, direction: AtoB|BtoA, payload: Vec<u8> }
Stream { index, key, segments, total_bytes_a_to_b, total_bytes_b_to_a,
         packet_count, initiator, total_payload_bytes, handshake }
```

### StreamTracker

- `HashMap<StreamKey, u32>` — Maps 4-tuples to stream indices
- `Vec<Stream>` — All tracked streams, indexed by stream index
- `next_index: u32` — Auto-incrementing counter

**Memory bounds:**
- Max `MAX_STREAM_SEGMENTS` (10,000) segments per stream
- Max `MAX_STREAM_BYTES` (2 MB) payload per stream
- Oldest segments dropped when exceeded

### TCP Handshake Timing

The `TcpHandshake` struct records nanosecond timestamps for SYN, SYN-ACK, and ACK packets:
- `syn_to_syn_ack_ms()` — Network latency
- `syn_ack_to_ack_ms()` — Client processing time
- `total_ms()` — Total handshake duration

### Stream View UI

Press `s` on a selected packet to open the stream view overlay:
- **Text mode:** UTF-8 payload with direction arrows (`→` / `←`), non-printable bytes shown as `·`
- **Hex mode:** Side-by-side hex dump + ASCII
- **Direction filter:** Show both / A→B only / B→A only
- **Navigation:** Scroll with ↑↓, toggle hex with `h`, close with Esc

---

## 8. Display Filter System

### Syntax

Display filters are applied to the in-memory packet list (capture continues unfiltered).

| Filter Type | Syntax | Example |
|------------|--------|---------|
| Protocol | bare word | `tcp`, `dns`, `icmp`, `arp`, `tls` |
| IP address | dotted quad | `192.168.1.42` |
| Directional IP | `ip.src ==` / `ip.dst ==` | `ip.src == 10.0.0.1` |
| Port | `port N` | `port 443` |
| Stream index | `stream N` | `stream 7` |
| Text search | `contains "text"` | `contains "hello"` |
| Negation | `!` or `not` | `!dns`, `not arp` |
| Logical AND | `and` | `tcp and port 443` |
| Logical OR | `or` | `dns or icmp` |
| Bare word search | any other word | `google` (shorthand for `contains "google"`) |

### BPF Capture Filters

Separate from display filters. BPF expressions are applied at the libpcap level before packets reach NetWatch:
- Set while capture is stopped (`b` key)
- Applied via `pcap::Capture::filter()`
- Use standard BPF syntax (`tcp port 80`, `host 10.0.0.1`, etc.)

---

## 9. Expert Info & Coloring

### Severity Classification

`classify_expert()` in `packets.rs` assigns severity based on protocol and flags:

| Condition | Severity | Color |
|-----------|----------|-------|
| TCP RST flag | Error | Red |
| DNS NXDOMAIN / SERVFAIL / Refused | Error | Red |
| ICMP Unreachable / Time Exceeded | Warn | Yellow |
| DNS Format Error | Warn | Yellow |
| TCP Zero Window | Warn | Yellow |
| HTTP 4xx/5xx responses | Warn | Yellow |
| TCP FIN flag | Note | Blue |
| DNS Response | Note | Blue |
| TLS Server Hello | Note | Blue |
| TCP SYN (initiating) | Chat | Gray |
| DNS Query | Chat | Gray |
| TLS Client Hello | Chat | Gray |
| ARP | Chat | Gray |

### Visual Indicators

- Packet list rows are color-coded by severity
- Expert dot prefix in the Info column
- Protocol name is colored by type (DNS=yellow, TLS=magenta, HTTP=green, etc.)

---

## 10. Network Intelligence

### GeoIP Lookup

- **Source:** `ip-api.com` (free, no API key)
- **Rate limit:** 1 request per 1.4 seconds
- **Data:** Country code, country name, city, organization/AS
- **Cache:** Up to 4096 entries, evicts 25% oldest when full
- **Private IP filter:** Automatically skips RFC1918, loopback, link-local, ULA, multicast
- **Toggle:** `g` key to show/hide geo column

### WHOIS / RDAP Lookup

- **Source:** `rdap.org` (free RDAP endpoint)
- **Rate limit:** 1 request per 2 seconds
- **Data:** Network name, IP range, organization (from vCard), country, description
- **Cache:** Up to 2048 entries
- **Trigger:** `W` key on selected connection or packet

### Reverse DNS

- **Built into PacketCollector** via `DnsCache`
- **Runs in background thread** using `ToSocketAddrs` for reverse resolution
- **Cache:** Up to 4096 entries with Pending dedup

---

## 11. Traceroute System

### Architecture

```
TracerouteRunner
  ├── result: Arc<Mutex<TracerouteResult>>
  │     ├── target: String
  │     ├── status: Idle | Running | Done | Error(String)
  │     └── hops: Vec<TracerouteHop>
  └── run(target) → spawns thread → run_traceroute()
```

### Platform Commands

| Platform | Command | Flags |
|----------|---------|-------|
| Linux/macOS | `traceroute` | `-n -q 3 -w 1 -m 30` |
| Windows | `tracert` | `-d -w 1000 -h 30` |

### Hop Data

```rust
TracerouteHop {
    hop_number: u8,
    host: Option<String>,
    ip: Option<String>,
    rtt_ms: Vec<Option<f64>>,  // 3 probes
}
```

### Output Parsing

`parse_traceroute_output()` handles:
- Header line skipping (non-numeric first token)
- All-star hops (no response)
- Mixed star/RTT hops
- IP addresses (with/without parentheses)
- Optional hostname resolution

### UI Integration

- **Connections tab:** Press `T` on selected connection to traceroute remote IP
- **Topology tab:** Press `T` on selected remote host to traceroute
- **Overlay:** Centered modal (70% screen) with hop table, color-coded RTTs (green <10ms, yellow <50ms, orange <100ms, red ≥100ms)
- **Scrollable:** ↑↓ to navigate hops, Esc to close

---

## 12. AI Insights (Ollama Integration)

### Architecture

```
Collectors ──→ NetworkSnapshot::build() ──→ InsightsCollector.submit_snapshot()
                                                       │
                                          background thread (analysis_loop)
                                                       │
                                              ┌────────▼────────┐
                                              │ POST /api/chat  │
                                              │ localhost:11434  │
                                              └────────┬────────┘
                                                       │
                                              Insight { timestamp, text }
                                                       │
                                              Arc<Mutex<Vec<Insight>>>
                                                       │
                                              UI renders scrollable list
```

### NetworkSnapshot

Built from the last 500 packets + current connection/health data:
- Protocol distribution
- Top 10 destination IPs by packet count
- Up to 20 unique DNS query domains
- Up to 50 DNS resolution mappings (IP → hostname)
- Up to 10 error/warning-severity expert info messages
- Connection counts (established vs. other)
- Gateway/DNS RTT and loss
- Current bandwidth rates

### Ollama API

- **Endpoint:** `POST http://localhost:11434/api/chat`
- **Model:** `llama3.2` (configurable)
- **System prompt:** Network security and performance analyst persona
- **Settings:** temperature 0.3, max tokens 512, streaming disabled
- **Timeout:** 30 seconds
- **HTTP client:** `ureq` v2

### Analysis Schedule

- **Auto:** Every 15 seconds (only when packets are available)
- **On-demand:** `a` key from any tab
- **Throttle:** Won't re-analyze if last analysis was < 15 seconds ago

### Output Format

Emoji-prefixed bullet points:
- 🔴 Critical
- 🟡 Warning
- 🟢 Healthy
- 🔵 Info

### Status States

| Status | UI Display |
|--------|------------|
| `Idle` | "Waiting for data..." |
| `Analyzing` | Spinner animation |
| `Available` | Scrollable insight list |
| `Error(msg)` | Error message display |
| `OllamaUnavailable` | Setup instructions (install Ollama, pull model) |

---

## 13. Platform Support

### Feature Matrix

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Interface stats | `/sys/class/net` | `netstat -ib` | PowerShell / `netstat -e` |
| Interface info | `/sys/class/net` + `ip addr` | `ifconfig` | `ipconfig /all` + `netsh` |
| Connections | `ss -tunap` | `lsof -i -n -P` | `netstat -ano` + `tasklist` |
| Gateway discovery | `ip route` | `netstat -rn` | `route print` |
| DNS discovery | `/etc/resolv.conf` | `/etc/resolv.conf` + `scutil --dns` | `ipconfig /all` |
| Hostname | `gethostname()` | `gethostname()` | `COMPUTERNAME` env |
| Health probes | `ping -c 3 -W 1` | `ping -c 3 -t 1` | `ping -n 3 -w 1000` |
| Packet capture | libpcap | libpcap (BPF) | Npcap |
| Traceroute | `traceroute -n` | `traceroute -n` | `tracert -d` |
| MTU | `/sys/class/net/*/mtu` | `ifconfig` | `netsh interface ipv4 show subinterfaces` |

### Windows-Specific Handling

- **Npcap SDK:** `build.rs` auto-downloads from npcap.com if not found
- **Device name mapping:** `resolve_device_name()` maps friendly names (e.g., "Ethernet") to `\Device\NPF_{GUID}` paths using `pcap::Device::list()`
- **MTU:** Parsed from `netsh interface ipv4 show subinterfaces` into a HashMap

---

## 14. Build System

### Cargo.toml

```toml
[package]
name = "netwatch-tui"
version = "0.3.6"
edition = "2021"
```

Dual target: library (`src/lib.rs`) + binary (`src/main.rs`).

### build.rs

Windows-only build script that:
1. Checks `LIBPCAP_LIBDIR` env var
2. Checks `NPCAP_SDK` env var
3. Searches common install paths (`C:\Npcap SDK\Lib\x64`, etc.)
4. Auto-downloads Npcap SDK from `npcap.com` via PowerShell
5. Extracts zip and sets `rustc-link-search`

### Nix Flake

`flake.nix` provides a reproducible development environment:
- Inputs: nixpkgs-unstable, flake-utils
- Package: `callPackage ./package.nix {}` (uses `rustPlatform.buildRustPackage`)
- Dev shell: cargo, rustc, rust-analyzer, clippy, rustfmt
- Build inputs: pkg-config, libpcap

---

## 15. Configuration & Dependencies

### Runtime Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `ratatui` | 0.27 | Terminal UI framework |
| `crossterm` | 0.27 | Cross-platform terminal backend |
| `tokio` | 1 (full) | Async runtime (main loop, channels) |
| `pcap` | 2 | libpcap bindings for packet capture |
| `anyhow` | 1 | Error handling |
| `chrono` | 0.4 | Timestamps |
| `ureq` | 2 | HTTP client (GeoIP, WHOIS, Ollama) |
| `serde_json` | 1 | JSON parsing |
| `nix` | 0.29 (Unix only) | Unix syscalls (hostname, net, ioctl) |

### System Dependencies

- **Rust** 1.70+ toolchain
- **libpcap-dev** (Linux) / Xcode CLI tools (macOS) / Npcap (Windows)
- **Ollama** (optional, for AI insights): `ollama serve` + `ollama pull llama3.2`

---

## 16. Keyboard Controls Reference

### Global (All Tabs)

| Key | Action |
|-----|--------|
| `1`–`8` | Switch tabs |
| `a` | Request AI analysis |
| `↑` `↓` | Scroll / select |
| `p` | Pause / resume all data collection |
| `r` | Force refresh all data |
| `g` | Toggle GeoIP location display |
| `?` | Show/hide help overlay |
| `q` / `Ctrl+C` | Quit |

### Connections Tab (2)

| Key | Action |
|-----|--------|
| `s` | Cycle sort column (Process → PID → Proto → State → Local → Remote) |
| `Enter` | Jump to Packets tab with auto-filter for selected connection |
| `T` | Traceroute to selected connection's remote IP |
| `W` | WHOIS lookup for selected connection's remote IP |
| `Esc` | Close traceroute overlay |

### Packets Tab (4)

| Key | Action |
|-----|--------|
| `c` | Start / stop packet capture |
| `i` | Cycle capture interface (while stopped) |
| `b` | Set BPF capture filter (while stopped) |
| `/` | Open display filter bar |
| `Esc` | Clear display filter / close stream view |
| `Enter` | Select packet at cursor |
| `s` | Open stream view for selected packet |
| `w` | Export packets to .pcap file |
| `f` | Toggle auto-follow (scroll to newest) |
| `x` | Clear all captured packets |
| `m` | Toggle bookmark on selected packet |
| `n` / `N` | Jump to next / previous bookmark |
| `W` | WHOIS lookup for selected packet's IPs |

### Stream View

| Key | Action |
|-----|--------|
| `Esc` | Close stream view |
| `↑` `↓` | Scroll |
| `→` `←` | Filter to A→B / B→A direction |
| `a` | Show both directions |
| `h` | Toggle hex / text mode |

### Topology Tab (6)

| Key | Action |
|-----|--------|
| `↑` `↓` | Scroll through remote hosts |
| `T` | Traceroute to selected remote host |
| `Enter` | Jump to Connections tab for selected host |
| `Esc` | Close traceroute overlay |

### Timeline Tab (7)

| Key | Action |
|-----|--------|
| `↑` `↓` | Scroll through connections |
| `t` | Cycle time window (1m → 5m → 15m → 30m → 1h) |
| `Enter` | Jump to Connections tab for selected entry |

### Insights Tab (8)

| Key | Action |
|-----|--------|
| `a` | Trigger on-demand AI analysis |
| `↑` `↓` | Scroll insights |

---

## 17. Permissions Model

NetWatch operates in two privilege levels:

| Feature | Without `sudo` | With `sudo` |
|---------|---------------|-------------|
| Interface stats & rates | ✅ | ✅ |
| Active connections | ✅ | ✅ |
| Network configuration | ✅ | ✅ |
| GeoIP & WHOIS | ✅ | ✅ |
| AI insights | ✅ (if Ollama running) | ✅ |
| Health probes (ICMP) | ❌ Shows "N/A" | ✅ |
| Packet capture | ❌ "Permission denied" | ✅ |
| Traceroute | ❌ May fail | ✅ |

The application degrades gracefully — restricted features display clear messages rather than crashing.

### macOS BPF Access

Packet capture requires `/dev/bpf*` access:
1. `sudo netwatch` (recommended)
2. `sudo chmod 644 /dev/bpf*` (persistent until reboot, allows any user to capture)

---

## 18. Testing

### Test Coverage

The codebase includes **127+ unit tests** across collector modules:

| Module | Test Count | Key Tests |
|--------|-----------|-----------|
| `collectors/packets.rs` | 30+ | MAC formatting, IPv6 formatting, TCP flags, port labels, ICMP types, expert classification, PCAP timestamps, DNS name parsing, ARP parsing |
| `collectors/connections.rs` | 10 | Timeline tracking, connection state changes, eviction, deduplication |
| `collectors/health.rs` | 12 | Ping output parsing (Linux/macOS/Windows formats), RTT extraction, edge cases |
| `collectors/insights.rs` | 8 | Snapshot building, protocol counting, top talkers, DNS query extraction, expert error/warning collection, prompt generation |
| `collectors/traceroute.rs` | 2 | Traceroute output parsing, partial star handling |
| `collectors/geo.rs` | 14 | Private IP detection (RFC1918, loopback, link-local, ULA, multicast, IPv6) |

### Running Tests

```bash
cargo test
```

Tests do not require network access or elevated privileges — they test parsing and data transformation logic using crafted input data.

---

## 19. Codebase Statistics

| Metric | Value |
|--------|-------|
| **Total Rust LOC** | 9,306 |
| **Source files** | 24 (.rs) |
| **Largest file** | `collectors/packets.rs` (2,133 lines) |
| **Dependencies** | 9 crates |
| **Tabs** | 8 |
| **Decoded protocols** | 10+ (DNS, TLS, HTTP, ICMP, ICMPv6, ARP, DHCP, NTP, mDNS, TCP, UDP) |
| **Port labels** | 25+ |
| **Unit tests** | 127+ |
| **Supported platforms** | 3 (Linux, macOS, Windows) |

### File Size Distribution

| File | Lines | Layer |
|------|-------|-------|
| `collectors/packets.rs` | 2,133 | Data |
| `app.rs` | 867 | Core |
| `ui/packets.rs` | 755 | UI |
| `ui/topology.rs` | 611 | UI |
| `collectors/insights.rs` | 533 | Data |
| `collectors/connections.rs` | 521 | Data |
| `ui/dashboard.rs` | 481 | UI |
| `ui/connections.rs` | 356 | UI |
| `ui/stats.rs` | 323 | UI |
| `ui/timeline.rs` | 295 | UI |
| `platform/windows.rs` | 262 | Platform |
| `collectors/traceroute.rs` | 229 | Data |
| `ui/interfaces.rs` | 216 | UI |
| `collectors/geo.rs` | 209 | Data |
| `collectors/whois.rs` | 209 | Data |
| `ui/insights.rs` | 197 | UI |
| `ui/help.rs` | 189 | UI |
| `collectors/config.rs` | 142 | Data |
| `collectors/health.rs` | 268 | Data |
| `platform/linux.rs` | 113 | Platform |
| `platform/macos.rs` | 105 | Platform |
| `collectors/traffic.rs` | 104 | Data |
| `platform/mod.rs` | 61 | Platform |
| `event.rs` | 46 | Core |
| `main.rs` | 34 | Core |
| `ui/widgets.rs` | 23 | UI |

---

## 20. Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| `Permission denied` on capture | Missing root privileges | Run with `sudo` |
| `BIOCPROMISC: operation not supported` | Interface doesn't support promisc | Automatic fallback — no action needed |
| Health shows `N/A` | ICMP requires root | Run with `sudo` |
| No connections listed | `lsof`/`ss`/`netstat` access restricted | Check permissions |
| Binary not found | Not built | `cargo build --release`, check `./target/release/netwatch` |
| Blank screen | Terminal too small or no 256-color support | Ensure ≥80×24 terminal with color support |
| GeoIP not loading | No internet or rate limited | Results appear after short delay; check connectivity |
| WHOIS not loading | No internet or rate limited | Same as GeoIP |
| AI shows "Ollama unavailable" | Ollama not running | `ollama serve` then `ollama pull llama3.2` |
| AI analysis slow | Local model inference | Depends on hardware; try smaller model |
| Windows: wrong interface | Friendly name not mapped | Set interface manually or check Npcap install |
| Traceroute fails | `traceroute`/`tracert` not found or no privileges | Install traceroute package; run with sudo |

---

*Generated from NetWatch v0.3.6 — commit `03d64c0`*
