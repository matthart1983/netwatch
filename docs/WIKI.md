# NetWatch Wiki

> Current architecture and maintenance notes for the shipped NetWatch TUI.

---

## Overview

NetWatch is a Rust terminal UI for real-time local network diagnostics. The shipped surface is the 10-tab TUI, with Full, Lite and Dense views, and a CLI: `netwatch daemon` (headless, optional Prometheus metrics), `netwatch doctor` (setup report), `netwatch diagnose` (bounded runs, coverage, episodes) and `netwatch resolver`. [REFERENCE.md](REFERENCE.md#command-line) lists every command and flag.

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

| Key | Tab |
| --- | --- |
| `1` | Dashboard |
| `2` | Connections |
| `3` | Interfaces |
| `4` | Packets |
| `5` | Stats |
| `6` | Topology |
| `7` | Timeline |
| `8` | Processes |
| `9` | Diagnose (optional AI commentary below findings) |
| `0` | Egress (destination baselines and policy drift) |

### Primary capabilities

- Interface traffic with rolling sparklines and totals
- Active connections with process attribution (Linux eBPF kprobe / macOS PKTAP / lsof fallback)
- Network config discovery for gateway, DNS, and hostname
- Health probing for gateway and DNS targets
- Packet capture with 15 L7 classifiers (`src/dpi/`), display filters, BPF filters, bookmarks, PCAPNG and PCAP export
- TLS 1.3 decryption via `SSLKEYLOGFILE` and JA4/JA4Q fingerprinting
- Threat detection (port scan, beaconing, DNS tunnel) via `network_intel.rs`
- Stream reassembly with text and hex views
- Traceroute and WHOIS/RDAP lookups
- Flight recorder with incident export bundles
- Linux worker entry policy with pinned filesystem grants; privileged capture acceptance remains pending (see [scope](REFERENCE.md#landlock-sandbox-linux))
- Optional AI insights via local/cloud Ollama
- Settings overlay with persistent user config

### Supported platforms

Netwatch has Linux, macOS, Windows and FreeBSD backends and release targets. Features differ: Windows capture requires Npcap, kernel TCP metrics are absent on Windows and FreeBSD, and only Linux has a sandbox backend. See the [capability matrix](CAPABILITIES.md) for implementation limits; backend presence is not cross-platform runtime validation.

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

See the [runtime lifecycle inventory](runtime-lifecycle.md) for worker creation,
resource needs, restart/shutdown ownership and the remaining confinement gaps.
Application preparation is separate from explicit worker startup.

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
- `src/ebpf/` holds the Linux kprobe connection tracker (process attribution)
- `src/sandbox/` implements the Landlock filesystem + capability sandbox
- `src/collectors/process_bandwidth.rs` ranks processes by RX/TX activity
- `src/collectors/traceroute.rs` runs traceroute jobs for overlays
- `src/collectors/whois.rs` performs WHOIS/RDAP lookups
- `src/collectors/geo.rs` resolves GeoIP data from local `.mmdb` databases
- `src/geoip_update.rs` downloads those databases when asked
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
- `src/ui/diagnose.rs` (including AI commentary)
- `src/ui/egress.rs`
- `src/ui/help.rs`
- `src/ui/settings.rs`
- `src/ui/widgets.rs`

---

## Flight Recorder

The flight recorder is one of the major product behaviors worth keeping documented because it crosses several modules.

### Behavior

- `Shift+R` arms or disarms a rolling recorder window
- `Shift+F` freezes the current incident window
- `Shift+E` previews the frozen bundle, then writes it to the exports directory in netwatch's cache
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
- `packets.pcapng` when any recorded packet can be exported, and `packets.pcap` as well when they share one link type and are dated before 2106 (see "Capture export" in REFERENCE.md)

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
- Capture and ICMP permissions depend on the platform and configuration; DNS health uses UDP queries and does not inherently require root. File capabilities do not establish that an eBPF program can load.
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
