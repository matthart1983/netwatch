# NetWatch — Feature Reference

The complete reference for NetWatch: every keybinding, the display-filter language, the
protocol decoders, TLS decryption, JA4 hunting, the sandbox, the Flight Recorder, themes,
and configuration. For a quick start, see the [README](../README.md); for architecture and
maintenance notes, see [WIKI.md](../WIKI.md).

- [Deep Packet Inspection](#deep-packet-inspection)
  - [Protocol decoders](#protocol-decoders)
  - [TLS 1.3 decryption](#tls-13-decryption)
  - [Threat hunting with JA4](#threat-hunting-with-ja4)
- [Display filters](#display-filters)
- [Security & Forensics](#security--forensics)
  - [Network intelligence](#network-intelligence)
  - [Flight Recorder](#flight-recorder)
  - [Landlock sandbox (Linux)](#landlock-sandbox-linux)
- [Keyboard controls](#keyboard-controls)
- [Permissions](#permissions)
  - [Running without sudo (Linux)](#running-without-sudo-linux)
- [Themes](#themes)
- [Configuration](#configuration)
- [AI Insights](#ai-insights)
- [How it works](#how-it-works)

---

## Deep Packet Inspection

Live capture with real L7 decoding — not just port-based labels. Press `c` in the Packets
tab to start capturing.

### Protocol decoders

| Layer | Decoded |
|-------|---------|
| **TLS** | Version, SNI, ALPN, **ECH** flag, **JA4** fingerprint |
| **QUIC** | Initial detection, SNI from reassembled CRYPTO frames, ECH, **JA4Q**, HTTP/3 |
| **HTTP** | Method, host, path, status code |
| **DNS / mDNS / LLMNR** | Query name, record type, response code, reverse-DNS cache |
| **SSH** | Client/server banner + version |
| **Others** | MQTT, SNMP, BitTorrent, FTP, NetBIOS, SSDP, STUN, NTP, DHCP, ICMP, ARP |

Cleartext L7 classifiers (in `src/dpi/`): TLS, QUIC, HTTP, DNS, SSH, MQTT, SNMP, BitTorrent,
FTP, NetBIOS, SSDP, STUN, NTP, DHCP, LLMNR — plus HTTP/3 over decrypted QUIC, and ICMP/ARP at
the parse layer. Every classifier runs on reassembled TCP streams with handshake timing, a
hex/text payload viewer, packet bookmarks, BPF capture filters, and PCAP export.

### TLS 1.3 decryption

NetWatch can decrypt TLS 1.3 application data when a **cooperating client** exports its
session secrets — the same `SSLKEYLOGFILE` mechanism Wireshark uses. It is read-only and
debugging-oriented: it decrypts traffic *you* control, never third-party or malware traffic.

```bash
# 1. Set the keylog path in Settings (,) → "TLS keylog", or in your config.
#    Default starter path is /tmp/sslkeylog.txt.

# 2. Launch the client with the SAME path:
SSLKEYLOGFILE=/tmp/sslkeylog.txt curl https://example.com
SSLKEYLOGFILE=/tmp/sslkeylog.txt google-chrome     # Chrome, Firefox, Node, etc.

# 3. In the Packets tab, decrypted records render inline. Filter with:
#    decrypted:true
```

Supported cipher suites: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
`TLS_CHACHA20_POLY1305_SHA256`. NetWatch decrypts application data after the handshake
completes, and handles TLS 1.3 KeyUpdate / post-handshake re-keying. A keylog miss never
breaks capture — the record just stays opaque.

> The ClientHello must be captured **live** — a connection whose handshake predates capture
> is permanently undecryptable. Start capture first, then make the request.

### Threat hunting with JA4

Every TLS ClientHello (and QUIC Initial) is fingerprinted with the
[Foxio JA4](https://github.com/FoxIO-LLC/ja4) spec, with RFC 8701 GREASE filtering. A JA4
fingerprint is stable across connections from the same client software, so you can pivot on
one to find every flow from the same stack — a browser, a CLI tool, or a piece of malware:

```
ja4:t13d1516h2_8daaf6152771_b186095e22b6
```

NetWatch ships the FoxIO BSD-3 lookup database and lets you overlay your own entries via JSON.

---

## Display filters

Wireshark-style filter syntax in the Packets tab (`/`):

```
tcp                        # Protocol
192.168.1.42               # IP address (src or dst)
ip.src == 10.0.0.1         # Directional
port 443                   # Port
stream 7                   # Stream index
contains "hello"           # Text search
app:tls                    # L7 protocol
sni:example.com            # TLS/QUIC server name
host:api.github.com        # HTTP host / resolved name
ja4:t13d1516h2_...         # JA4 fingerprint
ech:true                   # Encrypted ClientHello present
decrypted:true             # Only TLS-decrypted records
tcp and port 443           # Combinators (and / or)
!dns                       # Negation
google                     # Bare word → contains "google"
```

---

## Security & Forensics

### Network intelligence

NetWatch watches your traffic for trouble and raises color-coded alerts (visible in the
Timeline tab) without any setup:

- **Port-scan detection** — many distinct destination ports from one source in a short window (default: 20 ports / 30s).
- **Beaconing detection** — regular-interval outbound connections with low jitter, C2-style (default: ≥5 samples, jitter < 15%).
- **DNS-tunnel detection** — high-volume unique subdomains or abnormally long query names.
- **Bandwidth alerts** — configurable per-interface thresholds.

A **critical** alert automatically freezes an armed Flight Recorder, so the evidence is
captured before you even look.

### Flight Recorder

Catch transient failures that vanish before you can inspect them:

```text
Shift+R   Arm a rolling 5-minute recorder
Shift+F   Freeze the current incident window
Shift+E   Export an incident bundle to ~/netwatch_incident_YYYYMMDD_HHMMSS/
```

Each bundle is self-contained — packet evidence *plus* the operational context that explains it:

```text
netwatch_incident_20260403_103501/
  summary.md       # human-readable incident summary
  manifest.json
  connections.json # who was talking to whom
  health.json      # gateway/DNS RTT + loss samples
  bandwidth.json   # per-interface rates + top processes
  dns.json         # query analytics
  alerts.json      # network-intelligence alert history
  packets.pcap     # present when packets were captured
```

### Landlock sandbox (Linux)

Once pcap, PKTAP, and the eBPF kprobe finish setup, NetWatch hands back its elevated
capabilities and locks itself into a Landlock-enforced filesystem allow-list — so a
memory-safety bug in DPI parsing of hostile capture traffic **can't read SSH keys,
exfiltrate browser profiles, or open a new raw socket.**

```bash
netwatch                     # best-effort sandbox (default)
netwatch --sandbox-strict    # refuse to start if Landlock can't enforce
netwatch --no-sandbox        # escape hatch for debugging
```

- **Capabilities dropped post-init:** `CAP_NET_RAW`, `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`. The existing pcap fd and kprobe stay live; the process just can't acquire *new* ones.
- **Filesystem read allow-list** (kernel-enforced): system dirs plus a deliberately *enumerated* set of `/etc/*` files for NSS/TLS/time — so even a sudo'd NetWatch can't read `/etc/shadow` or `/etc/sudoers`. Everything else returns `EACCES`, including other users' homes and SSH keys.
- **Write allow-list:** `~/.cache/netwatch/`, the startup working dir (PCAP exports), `/tmp`, `/run/user/<uid>`, `/dev/null`.
- **Verify at runtime:** the Settings overlay (`,`) shows the live enforcement state, e.g. `best-effort: Landlock ABI Vx, 3 caps dropped`.

Network restriction is intentionally not enabled (it would break GeoIP fallback, `--remote`
streaming, and WHOIS). macOS/Windows sandboxing is not on the roadmap — the threat model is
production-capture-specific, and that audience is overwhelmingly Linux.

---

## Keyboard controls

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
<summary><strong>Full keybinding reference (per tab)</strong></summary>

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

## Permissions

| Feature | `netwatch` | `sudo netwatch` |
|---------|:---:|:---:|
| Interface stats & rates | ✅ | ✅ |
| Active connections | ✅ | ✅ |
| Network configuration | ✅ | ✅ |
| Health probes (ICMP) | ❌ | ✅ |
| Packet capture | ❌ | ✅ |

Degrades gracefully — features that need root show a clear message, never crash. On Linux,
`setcap` (below) unlocks capture and eBPF without running as root.

### Running without sudo (Linux)

Packet capture and eBPF process attribution need elevated capabilities, but you don't have to
run the whole TUI as root. Grant them once to the binary:

```bash
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' "$(which netwatch)"
netwatch
```

> **Re-run after every install.** `setcap` attaches to a specific binary on disk; `cargo
> install netwatch-tui` and the Release tarballs overwrite that file, so the capabilities
> don't carry over. If you see `pcap open failed: socket: Operation not permitted` or `BPF
> load failed: PermissionDenied` in `~/.cache/netwatch/netwatch.log.*` after an upgrade, the
> new binary just needs `setcap` re-applied.

| Capability | What it unlocks |
|------------|-----------------|
| `cap_net_raw` | Opening packet capture on a live interface (libpcap) |
| `cap_bpf` | Loading the kernel-level process-attribution kprobe (kernel ≥ 5.10) |
| `cap_perfmon` | Reading the BPF ring buffer the kprobe writes to |

Without them netwatch still runs — it falls back to `ss`/`lsof`-style polling for process
attribution and skips packet capture. The Connections header surfaces the active source
(`attribution: ebpf`, `attribution: pktap`, or `attribution: lsof — ebpf unavailable: …`) so
you can tell at a glance which path is live.

---

## Themes

7 built-in themes with instant switching via `t`:
**Dark** (default) · **Ocean** · **Solarized** · **Dracula** · **Nord** · **Sky** · **Paper**

Theme changes apply immediately. Persist them from the Settings overlay with `S`.

---

## Configuration

NetWatch runs well with zero setup, but you can persist preferences for theme, default tab,
refresh rate, capture interface, GeoIP database paths, TLS keylog path, packet-follow
behavior, BPF filter, and alert thresholds.

```bash
netwatch --generate-config
```

That writes a starter config to your platform config directory. You can also edit settings
live with `,` and save with `S`.

---

## AI Insights

*(opt-in, off by default.)* Feed a snapshot — protocol mix, top talkers, DNS queries,
connection states, health, expert warnings — to an LLM every 15 seconds and get analysis
rendered in the TUI: anomalies, beaconing patterns, suspicious DNS, health regressions.

Enable via Settings (`,`) → AI Insights. Supports local [Ollama](https://ollama.com)
(default), a remote Ollama host, or Ollama **cloud models** — no API keys in NetWatch. See
[INSIGHTS.md](../INSIGHTS.md) for setup.

---

## How it works

| Collector | Interval | macOS | Linux |
|-----------|:--------:|-------|-------|
| Interface stats | 1s | `netstat -ib` | `/sys/class/net/*/statistics` |
| Connections | 2s | `lsof` + PKTAP | `/proc/net/tcp` + eBPF kprobe |
| Health probes | 5s | native ICMP | native ICMP |
| Packets | Real-time | libpcap (BPF) | libpcap |
| GeoIP | On-demand | MaxMind .mmdb / ip-api.com | MaxMind .mmdb / ip-api.com |

```
Raw bytes → Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP → L7 decoders
                                            ↓
                          Stream reassembly · Handshake timing
                          TLS 1.3 decryption · JA4 · Expert info
```

For the module-level source map and runtime architecture, see [WIKI.md](../WIKI.md).
