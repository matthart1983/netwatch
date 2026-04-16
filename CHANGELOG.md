# Changelog

All notable changes to NetWatch will be documented in this file.

## [Unreleased]
- Move interface stat collection to a background thread so that netwatch is more responsive on Windows.

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
