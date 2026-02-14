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

- Deep packet inspection or protocol decoding (use Wireshark/tcpdump)
- Remote host monitoring or agent-based collection
- Historical data storage or alerting

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
