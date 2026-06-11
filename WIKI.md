# NetWatch Wiki

> Current architecture and maintenance notes for the shipped NetWatch TUI.

---

## Overview

NetWatch is a Rust terminal UI for real-time local network diagnostics. The current shipped surface area is the 9-tab TUI plus a small CLI helper for writing a starter config file with `netwatch --generate-config`.

> User-facing deep dives (DPI, TLS decryption, JA4, eBPF, sandbox) live in the
> [GitHub wiki](https://github.com/matthart1983/netwatch/wiki). This file is the
> contributor-facing architecture/maintenance guide.

The repo docs now intentionally stay focused on what is live in this codebase today:

- `README.md` for install, usage, and user-facing features
- `WIKI.md` for architecture and maintenance notes
- `CONTRIBUTING.md` for coding conventions and verification steps
- `CHANGELOG.md` for released changes

---

## What Ships Today

### Tabs

NetWatch currently exposes these runtime tabs:

1. Dashboard
2. Connections
3. Interfaces
4. Packets
5. Stats
6. Topology
7. Timeline
8. Processes
9. Insights (opt-in AI analysis; tab appears when enabled)

### Primary capabilities

- Interface traffic with rolling sparklines and totals
- Active connections with process attribution (Linux eBPF kprobe / macOS PKTAP / lsof fallback)
- Network config discovery for gateway, DNS, and hostname
- Health probing for gateway and DNS targets
- Packet capture with 15 L7 classifiers (`src/dpi/`), display filters, BPF filters, bookmarks, PCAP export
- TLS 1.3 decryption via `SSLKEYLOGFILE` and JA4/JA4Q fingerprinting
- Threat detection (port scan, beaconing, DNS tunnel) via `network_intel.rs`
- Stream reassembly with text and hex views
- Traceroute and WHOIS/RDAP lookups
- Flight recorder with incident export bundles
- Landlock sandbox (Linux): capability drop + filesystem allow-list post-init
- Optional AI insights via local/cloud Ollama
- Settings overlay with persistent user config

### Supported platforms

The current public docs and release assets target macOS and Linux. There is platform-specific code in the tree for other environments, but the maintained user-facing support promise is macOS plus Linux.

---

## Runtime Architecture

NetWatch is structured around a central `App` state object that coordinates collectors, UI state, and input handling.

```text
main.rs
  -> sets up terminal state
  -> runs app::run()

app.rs
  -> owns App state
  -> receives AppEvent::Key / AppEvent::Tick
  -> updates collectors on a polling cadence
  -> dispatches rendering to ui/*

collectors/*
  -> gather traffic, connections, config, health, packets, traceroute, whois,
     GeoIP, process bandwidth, network-intel, and incident data

ui/*
  -> renders each tab plus help, settings, and shared widgets

platform/*
  -> provides OS-specific interface and network helpers
```

### Main update cadence

The main loop is tick-driven.

- Traffic updates every tick
- Connections update every 2 ticks
- Health probes update every 5 ticks
- Interface/config refresh runs every 10 ticks
- Packet capture runs independently on its own capture thread when enabled

### Concurrency model

- Terminal input is read on a dedicated thread in `event.rs`
- Blocking collectors use background threads so the UI can keep rendering
- Shared state generally uses `Arc<Mutex<T>>`
- Packet capture uses `AtomicBool` flags for start/stop coordination

---

## Source Map

### App and state

- `src/main.rs` initializes the terminal and handles `--generate-config`
- `src/app.rs` owns runtime state, tab switching, key handling, and tick updates
- `src/event.rs` turns crossterm input into `AppEvent`s
- `src/config.rs` defines persistent config serialization and mapping into runtime enums
- `src/theme.rs` defines the built-in themes

### Collectors

- `src/collectors/traffic.rs` tracks per-interface rates and totals
- `src/collectors/connections.rs` resolves sockets, process names, exports, and timeline state
- `src/collectors/config.rs` discovers gateway, DNS servers, and hostname
- `src/collectors/health.rs` performs gateway and DNS probe collection
- `src/collectors/packets/` owns capture, decode orchestration, the filter DSL, dns cache, and PCAP export
- `src/dpi/` holds the 15 L7 classifiers plus `tls_decrypt.rs` (SSLKEYLOGFILE) and `ja4.rs`
- `src/ebpf/` holds the Linux kprobe connection tracker and RTT monitor
- `src/sandbox/` implements the Landlock filesystem + capability sandbox
- `src/collectors/process_bandwidth.rs` ranks processes by RX/TX activity
- `src/collectors/traceroute.rs` runs traceroute jobs for overlays
- `src/collectors/whois.rs` performs WHOIS/RDAP lookups
- `src/collectors/geo.rs` resolves GeoIP data via MaxMind or online fallback
- `src/collectors/network_intel.rs` generates alert events used by the dashboard and recorder
- `src/collectors/incident.rs` manages the rolling flight recorder window and bundle export
- `src/collectors/insights.rs` builds network snapshots for the optional Ollama analysis

### UI

- `src/ui/dashboard.rs`
- `src/ui/connections.rs`
- `src/ui/interfaces.rs`
- `src/ui/packets.rs`
- `src/ui/stats.rs`
- `src/ui/topology.rs`
- `src/ui/timeline.rs`
- `src/ui/processes.rs`
- `src/ui/insights.rs`
- `src/ui/help.rs`
- `src/ui/settings.rs`
- `src/ui/widgets.rs`

---

## Flight Recorder

The flight recorder is one of the major product behaviors worth keeping documented because it crosses several modules.

### Behavior

- `Shift+R` arms or disarms a rolling recorder window
- `Shift+F` freezes the current incident window
- `Shift+E` exports the current bundle to the user's home directory
- Critical network-intel alerts can freeze an armed recorder automatically

### Export contents

An exported incident bundle includes:

- `summary.md`
- `manifest.json`
- `connections.json`
- `health.json`
- `bandwidth.json`
- `dns.json`
- `alerts.json`
- `packets.pcap` when the recorder actually captured packets

The export format is implemented in `src/collectors/incident.rs`.

---

## Configuration and Persistence

NetWatch is zero-config by default, but it supports persistent preferences.

### Ways to create or update config

- Run `netwatch --generate-config` to write a starter config file without entering the TUI
- Press `,` in the app to open the Settings overlay
- Press `S` in Settings to save changes

### Stored preferences

The persisted config currently includes:

- Theme
- Default tab
- Refresh rate
- Capture interface
- GeoIP visibility
- Timeline window
- Packet follow mode
- BPF filter
- GeoIP database paths
- Bandwidth threshold
- Port-scan threshold

The schema lives in `src/config.rs`.

---

## Permissions Model

NetWatch intentionally degrades instead of crashing when a capability needs more privilege.

- Regular user mode still shows interface stats, connections, config, and most UI state
- `sudo netwatch` unlocks packet capture and ICMP-backed health probes on systems that require elevated privileges
- Exported packet data may contain raw payloads; that is expected for a diagnostics tool and should stay clearly documented

---

## Build and Verify

For routine maintenance, use the standard Rust checks:

```bash
cargo fmt --check
cargo clippy --all-targets
cargo test
```

If you are updating docs, also sanity-check that `README.md`, `WIKI.md`, and `CHANGELOG.md` still agree on tabs, platform support, and key shipped features.

---

## Documentation Policy

This repository used to accumulate speculative roadmaps, review notes, and stale design specs. The current rule is simpler:

- Keep durable product and maintenance docs in the repo
- Delete one-off planning and critique documents once they stop being maintained
- Prefer short, accurate docs over exhaustive speculative specs
- Only document features as shipped when they are reachable in the current UI or CLI
