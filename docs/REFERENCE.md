# NetWatch — Feature Reference

The complete reference for NetWatch: every keybinding, the display-filter language, the
protocol decoders, TLS decryption, JA4 hunting, the capture export format, the sandbox, the
Flight Recorder, themes, and configuration. For a quick start, see the [README](../README.md); for architecture and
maintenance notes, see [WIKI.md](WIKI.md).

- [Deep Packet Inspection](#deep-packet-inspection)
  - [Protocol decoders](#protocol-decoders)
  - [TLS 1.3 / 1.2 decryption](#tls-13--12-decryption)
  - [Threat hunting with JA4](#threat-hunting-with-ja4)
  - [Capture export](#capture-export)
- [Display filters](#display-filters)
- [Security & Forensics](#security--forensics)
  - [Network intelligence](#network-intelligence)
  - [Flight Recorder](#flight-recorder)
  - [Landlock sandbox (Linux)](#landlock-sandbox-linux)
- [Command line](#command-line)
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
| **DNS / mDNS / LLMNR** | Query name, record type, response code, reverse-DNS cache (UDP only — DNS-over-TCP isn't classified; DoT/DoH surface at the TLS layer) |
| **SSH** | Client/server banner + version |
| **Others** | MQTT, SNMP, BitTorrent, FTP, NetBIOS, SSDP, STUN, NTP, DHCP, ICMP, ARP |

Cleartext L7 classifiers (in `src/dpi/`): TLS, QUIC, HTTP, DNS, SSH, MQTT, SNMP, BitTorrent,
FTP, NetBIOS, SSDP, STUN, NTP, DHCP, LLMNR — 15 in total. HTTP/3 decoding over decrypted QUIC is
a reassembly/decode utility, not a separate classifier; ICMP/ARP are handled at the parse layer.
Classifiers run over **per-flow stream tracking** (byte accumulation + TCP sequence-anomaly
detection — not full out-of-order resequencing; cross-segment TLS records aren't reassembled),
with handshake timing, a hex/text payload viewer, packet bookmarks, BPF capture filters, and
[PCAPNG and PCAP export](#capture-export).

### TLS 1.3 / 1.2 decryption

NetWatch can decrypt TLS 1.3 **and TLS 1.2** application data (plus QUIC 1-RTT) when a
**cooperating client** exports its session secrets — the same `SSLKEYLOGFILE` mechanism
Wireshark uses. It is read-only and debugging-oriented: it decrypts traffic *you* control,
never third-party or malware traffic.

```bash
# 1. Point netwatch at a keylog file: set `tls_keylog_path` in your config
#    (see Configuration). Empty by default — nothing is decrypted until you set it.

# 2. Launch the client with the SAME path:
SSLKEYLOGFILE=/tmp/sslkeylog.txt curl https://example.com
SSLKEYLOGFILE=/tmp/sslkeylog.txt google-chrome     # Chrome, Firefox, Node, etc.

# 3. In the Packets tab, decrypted records render inline. Filter with:
#    decrypted:true
```

Supported cipher suites — **TLS 1.3:** `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
`TLS_CHACHA20_POLY1305_SHA256`. **TLS 1.2** (AEAD only, via `CLIENT_RANDOM` keylog lines):
the AES-128/256-GCM and ChaCha20-Poly1305 ECDHE suites; legacy CBC (mac-then-encrypt) suites
are out of scope. NetWatch decrypts application data after the handshake completes, and handles
TLS 1.3 KeyUpdate / post-handshake re-keying. A keylog miss never breaks capture — the record
just stays opaque.

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

### Capture export

Press `w` in the Packets tab to export the packets the list shows, after any display filter
and `x` (expert findings only).
`Shift+E` does the same for a frozen [Flight Recorder](#flight-recorder) incident. Either one
opens a preview first. The preview freezes the selection, counts what will be written and
what will be left out, and says what the file will hold. `Enter` writes, `f` switches between
PCAPNG and classic PCAP, `a` turns packet comments on or off, and `Esc` or `q` closes the
preview or cancels a write in progress.

Files go to the `exports` directory in netwatch's cache (`~/.cache/netwatch/exports` on Linux,
`~/Library/Caches/netwatch/exports` on macOS, `%LOCALAPPDATA%\netwatch\exports` on Windows),
named `netwatch_capture_YYYYMMDD_HHMMSS_<8 hex digits>.pcapng` or `.pcap`. The write runs in
the background, so capture carries on. An export never overwrites a file: it is written to a
temporary file beside the destination and hard-linked into place only once complete, so a
failed or cancelled export leaves nothing behind (only a crash can leave a
`.netwatch-export-*.tmp`). The exports directory must be on a filesystem with hard links.
Files are readable only by you: 0600 on Unix; on Windows they take the folder's permissions.

**Times and lengths.** Each packet carries the time libpcap stamped it with, in UTC, to the
microsecond, and both the bytes captured and its length on the wire. Packets netwatch did not
capture from an interface (`--demo` traffic) are left out and counted as omitted, and a
selection of nothing else is refused rather than written with invented times. Frames from an
interface that is not Ethernet (a VPN tunnel's raw IP, BSD loopback) show in Packets as
`Raw`, undecoded, and are exported with their own link type.

**Privacy.** Packet bytes are not redacted: they hold whatever crossed the wire, addresses and
any unencrypted payload included. TLS session keys and plaintext decrypted with them are never
written. Packet comments add process names, PIDs and server names; `a` turns them off. To
share evidence with someone else, `netwatch diagnose export` writes a pseudonymised bundle.

#### Export file format, version 1

Classic PCAP and the PCAPNG blocks below are the standard formats, so any reader of them can open
these files. The JSON in packet comments, `netwatch.annotation.v1`, is experimental and outside
the 1.0 compatibility promise. Its keys can change in any release. A change that removes or
renames one, or changes its meaning, gets a new schema name, so a parser can tell.

**Classic PCAP**: little-endian, magic `0xa1b2c3d4` (microsecond timestamps), version 2.4,
snaplen 65535, and one link type for the whole file. A selection that mixes link types can
only be saved as PCAPNG.

**PCAPNG** ([draft-ietf-opsawg-pcapng](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/)):
one little-endian section, with only these blocks:

| Block | Contents |
|-------|----------|
| Section Header | Byte-order magic `0x1A2B3C4D`, version 1.0, section length -1 (unspecified). Option `shb_userappl`: `netwatch <version>` |
| Interface Description | One per capture session, interface and link type, written before its first packet: LINKTYPE, snaplen 65535. Options `if_name` and `if_tsresol` = 6 (microseconds). A file with no packets has one, Ethernet with no `if_name`, since libpcap cannot open a section without one |
| Enhanced Packet | Interface ID, timestamp in microseconds since the Unix epoch, captured length, original length, packet bytes padded to 32 bits. Option `opt_comment` when comments are on |

A block with options ends them with `opt_endofopt`; a block without has no options list.

**Packet comments.** Experimental. Each comment is one JSON object in UTF-8, schema
`netwatch.annotation.v1`. Wireshark shows it under *Packet comments*, and
`tshark -r FILE -T fields -e frame.comment` prints one per line.

| Key | Type | When present | Meaning |
|-----|------|--------------|---------|
| `schema` | string | always | `netwatch.annotation.v1` |
| `packet_id` | integer | always | The packet's number in the Packets list during that run |
| `capture_session` | string | always | A UUID for one capture start. Restarting capture or switching interface starts a new one, as does using up the stream indexes, which start again from 0 after 2^32 streams |
| `protocol` | string | always | netwatch's protocol label, as in the Packets list: `TCP`, `DNS`, `TLS`, `Raw`… |
| `status` | string | always | `bracketed_socket_observation` when the owner keys below are present, else `unknown_owner` |
| `pid` | integer | owner | Process ID |
| `process_name` | string or null | owner | Process name |
| `process_session` | string | owner | UUID of the netwatch run that observed the process |
| `start_token` | string | owner | The process's start time from `/proc/<pid>/stat`, in clock ticks since boot. With `pid` it rules out PID reuse |
| `executable_identity` | string or null | owner | `device:inode:size:ctime:ctime_nsec` of the process's executable |
| `network_namespace` | string or null | owner | Its network namespace, e.g. `net:[4026531840]` |
| `source` | string | owner | Which socket table named the owner: `procfs`, `ebpf`, `lsof`, `pktap` or `sockstat` |
| `direction` | string | owner | `outbound` when the packet left from the socket's local end, else `inbound` |
| `before_utc_ms`, `after_utc_ms` | integer | owner | Unix time in ms by which the earlier check of the owner had finished, and at which the later one began. The packet falls strictly between them |
| `flow_generation` | integer | owner | netwatch's number for this socket and owner in this run; a socket that passes to another process gets a new one |
| `capture_generation` | integer | owner | The stream index the packet belongs to, as the stream view numbers them. Unique within a `capture_session` |
| `app` | string | flow classified | The DPI classifier that recognised the flow: `tls` `quic` `http` `dns` `ssh` `mqtt` `stun` `bittorrent` `netbios` `snmp` `ssdp` `ftp` `llmnr` `dhcp` `ntp` |
| `sni` | string | TLS or QUIC with a server name | The ClientHello's server name. When `ech_outer` is true it is the outer, public name, not the real destination |
| `ech_outer` | boolean | with `sni` | The ClientHello carried Encrypted Client Hello |
| `alpn` | string | TLS with ALPN | The first ALPN protocol the ClientHello offered |
| `ja4` | string | TLS or QUIC fingerprinted | JA4 for TLS, JA4Q for QUIC |

`app` and the keys after it are the flow's classification when the packet was captured, so the
first packets of a flow, captured before it was recognised, have none. Only the classifier's
name is written: HTTP paths, SNMP communities, FTP commands and decrypted payloads are not.
Text values come from other programs and from the network. They are cut to 160 characters, and
any character that could hide or reorder text (control and format characters, which include
bidi overrides, zero-width marks and tag characters, and the line and paragraph separators)
becomes `·`. Readers should ignore keys they do not know.

**How a packet gets an owner.** netwatch polls the connection table about once a second. A
packet is given the owner keys only when two consecutive polls both name the same process
(same PID, start token, executable and namespace), the same socket and the same capture
stream, and the packet falls strictly between the two checks of that owner: the earlier
check had finished before the packet's time and the later one began after it, at most 5 s
apart in all. A check is not always the poll. Sandboxed on Linux, netwatch reads socket
owners from a separate `/proc` scan that runs every 0.5–5 s (the refresh rate) on its own
schedule, so polls that share one scan bracket nothing, and packets after the latest scan
wait for the next. Anything else stays `unknown_owner`: a single check, a stale one, a socket
that changed hands, both ends of a loopback connection, or a platform where netwatch cannot
verify a process's identity (only Linux can today). The owner is recorded during capture and
kept, so packets from a process that has since exited keep it, and nothing is looked up at
export. It is a correlation of socket observations, not proof that the process sent the
packet: a socket that opens and closes between two checks is never seen.

---

## Display filters

Wireshark-style filter syntax in the Packets tab (`/`):

```
tcp                        # Protocol
192.168.1.42               # IP address (src or dst)
ip.addr == 2001:db8::1     # The same; IPv6 in any spelling
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
Shift+E   Preview and export the frozen incident bundle
```

Each bundle is self-contained — packet evidence *plus* the operational context that explains it:

```text
netwatch_incident_20260403_103501_1a2b3c4d/
  summary.md       # human-readable incident summary
  manifest.json    # what the bundle holds (version 2, below)
  connections.json # who was talking to whom
  health.json      # gateway/DNS RTT + loss samples
  bandwidth.json   # per-interface rates + top processes
  dns.json         # query analytics
  alerts.json      # network-intelligence alert history
  packets.pcapng   # recorded packets, when any can be exported
  packets.pcap     # as well, when classic PCAP can hold them all
```

`Shift+E` opens the same preview as a packet export ([Capture export](#capture-export)); an
armed recorder is frozen first, so the bundle holds the window the preview counted. The
packet files follow the [export file format](#export-file-format-version-1). The bundle is
written into a hidden `.netwatch_incident_<id>.tmp` directory beside it and renamed into
place once every file is complete; the directory is 0700 and its files 0600 on Unix. The
incident JSON names processes and endpoints whether or not packet comments are on.

The recorder holds at most 20,000 packets and 64 MiB of them, counting the captured bytes
and what netwatch decoded from them, down to the SNI or request path that every packet of a
flow carries. Past either limit the oldest go first, so under bulk traffic, where one GSO
frame can be 64 KiB, the packets cover less than the whole window.

The connection snapshots hold at most 50,000 rows and 64 MiB between them. Rows of the usual
size reach 50,000 first, at about 55 MB. Each row also carries its flow's SNI or request
path, which the peer picks and can make kilobytes long, and a table of such rows reaches
64 MiB first, so fewer snapshots fit than the table below says. Past either limit the
recorder leaves out whole older snapshots, each time the one whose loss leaves the shortest
gap. With rows of the usual size, how much history stays depends on the size of the table:

| Connections | Snapshots kept | What they cover |
|-------------|----------------|-----------------|
| Up to 16,666 | 3 or more | The window, at a longer interval, with no gap over 150 seconds. At 10,000 connections, five snapshots and no gap over 81 seconds |
| 16,667 to 25,000 | 2 | The newest, and one older snapshot whose age cycles from a second to five minutes |
| Over 25,000 | 1 | The newest only |

The newest snapshot is always whole, even when it alone is over the budget. The recorder
picks snapshots by time, not size. A burst of connections pushes older snapshots out while
it is the newest, and the recorder usually drops it once it takes the next one. To keep a
burst, freeze during it. A critical alert freezes the recorder on its own.
`connection_rows_dropped` in the manifest and a line in `summary.md` say how many rows were
left out.

`manifest.json` is version **2**. Besides the counts of what was recorded, it has:

| Key | Meaning |
|-----|---------|
| `packet_artifacts` | The packet files actually in the bundle: none, `["packets.pcapng"]`, or both |
| `packet_export` | `packets` written, `omitted` (no capture metadata), and `annotated` (with a socket owner) |
| `packet_annotations` | Whether packet comments were on |
| `last_capture_status` | The capture's `session`, `sampled_at_utc_ms` and `drops` (packets libpcap dropped, null when it had not reported recently), last sampled while recording. `drops` counts from the last capture start, so it also covers any earlier `session` that ended when the stream indexes ran out. Not a loss total for the incident window |
| `connection_rows_dropped` | Connection rows left out for the budget of 50,000 rows and 64 MiB, counting snapshots taken inside the window. Whole snapshots are left out, never single rows. `0` when none were |
| `capture_limitations` | What the packet files cannot show, in prose |

Version 1 bundles, from netwatch 0.37 and earlier, have `packets.pcap` only, with times
rebuilt from the time of day. Read `version` and `packet_artifacts` rather than assuming a
file is present.

### Egress policy linter

A linter for your machine's outbound traffic: declare what each process is *meant* to
talk to, and NetWatch warns when reality drifts. It warns, it never blocks — the
read-only invariant holds.

The loop is **observe → promote → warn**:

1. **Observe** — the Egress tab (`0`) learns per-process destination profiles:
   SNI (read from the cleartext TLS/QUIC ClientHello — no decryption needed),
   ASN organization, and port. The learned baseline **persists across
   restarts** (`<state_dir>/netwatch/egress-profiles.json`; saved once a
   minute and at quit) and ages out destinations not seen for 30 days. The
   `First`/`Last` columns show how long each destination has been known —
   the evidence you review before promoting.
2. **Promote** — `Enter` ratifies just the selected process (the status line
   reports what the promotion adds, e.g. `+2 SNI, +1 ports`); `Shift+P`
   ratifies everything observed. Both **merge** into
   `<config_dir>/netwatch/egress-policy.toml` (e.g. `~/.config/netwatch/` on
   Linux) — hand edits, comments, and rules for other processes survive.
   Review before trusting: human ratification is what keeps a compromised
   baseline from being blessed as "normal".
3. **Warn** — flows that fall outside a process's declared allowlist raise a
   `PolicyViolation` alert naming the broken rule. Only processes with a rule are
   checked, so an unlisted process never warns. The re-warn cooldown per flow is
   `egress_violation_cooldown_secs` in config.toml (default 300; 0 = every refresh).
   In `netwatch daemon` the same evaluation runs headless, and violations surface
   as `netwatch_policy_violations_total{process}` on the Prometheus endpoint.

Sharp edges handled for you:

- **ECH**: a flow with Encrypted ClientHello has no readable inner SNI, so a policy
  miss may be "name unreadable" rather than real drift — those rows show `? ech`
  (and the alert says so) instead of a red `✗ drift`.
- **Wildcard suggestions**: when ≥3 subdomains of one apex accumulate in a rule,
  promotion writes a `# suggestion: *.apex.tld would cover N entries` comment above
  the rule. It never collapses silently — widening the allowlist is your call.
- **Policy file trust**: a group- or world-writable `egress-policy.toml` is refused
  with a loud log warning. If anyone but the owner can edit the policy, "warn on
  drift" could be silenced by the very thing drifting. `chmod 644` or stricter.
- **Unknown keys**: a key the policy does not read is ignored and reported, naming the
  key and the file, on stderr when a session starts, in the log, in Settings, in the
  Egress tab and in `netwatch doctor`, as for [`config.toml`](#configuration). It
  matters more here. An empty list means unrestricted, so `allow_snis` for `allow_sni`
  is a rule that restricts no name. The tab stops calling such a policy `all precise`.
  Promoting a rule keeps such a key, as it keeps the rule's `block` table.

**Structured export.** Press `e` on the Egress tab to write the attributed
records as **NDJSON** (`netwatch.egress.v1`) — one JSON object per line, preceded
by a `_meta` line naming the schema. Each record is metadata only (process, SNI,
ASN org, IP, port, coarse proto, ECH flag, first/last-seen, count, policy
verdict) — never any payload. This is the ingest contract the managed layer consumes; the
same `policy.toml` the TUI lints with is the file a managed layer would
distribute.

```json
{"_meta":{"schema":"netwatch.egress.v1","records":2}}
{"process":"chrome","sni":"mail.google.com","asn_org":"Google LLC","ip":"142.250.66.101","port":443,"proto":"tls","ech":false,"first_seen":1751600000,"last_seen":1751603600,"count":42,"verdict":"ok"}
```

```toml
# egress-policy.toml
[process.chrome]
allow_sni   = ["*.google.com", "*.gstatic.com"]   # exact or *.wildcard (incl. apex)
allow_ports = [443]

[process.node]
allow_asn = ["Cloudflare, Inc."]                  # fallback when a flow has no SNI
allow_ip  = ["203.0.113.9"]                        # for a raw-IP dest with no name at all
```

`allow_asn` matches the organisation name in the ASN database you load, so a name from another
database does not carry over: MaxMind's `CLOUDFLARENET` is DB-IP's `Cloudflare, Inc.`.

Rules are expressed in terms a firewall can't write — `process → {SNI, ASN, IP, port}` —
because the flow already carries the owning process (eBPF/proc attribution) and the
destination name (DPI). A flow is allowed if **any** declared dimension matches, so a
promoted baseline admits all of its own destinations: named ones match by SNI/ASN, and a
nameless raw-IP destination matches by IP (without `allow_ip` it would drift against the
very rule it was promoted into, once a sibling destination made the rule name-restricted).
Edit the file by hand freely; it reloads on startup.

### Landlock sandbox (Linux)

See the [threat model](THREAT-MODEL.md) for boundaries, outbound traffic and
remaining gaps. Root operation works, but containment is limited.

Linux worker entry points apply a prepared Landlock filesystem policy before
processing input. Capture opens/configures its device first and marks itself ready
after policy entry. Main applies policy after resource startup. Rules pin opened
filesystem objects, so later pathname replacement cannot widen an existing grant.

```bash
netwatch                     # best-effort; reports unavailable protection
netwatch --sandbox-strict     # reject unverified required startup entries
netwatch --no-sandbox         # explicitly disable Netwatch policy
```

- **Capabilities:** removals are verified in the effective, permitted, inheritable
  and ambient sets. Parser and capture threads drop `CAP_NET_RAW` in every mode. A
  best-effort TUI keeps it on main and the network workers to reopen capture (`c`,
  `i`, `Shift+R`); the daemon, `diagnose run`, `diagnose coverage` and strict drop it
  on every thread once capture has opened. Effective retained capabilities are
  recorded. This is not a claim that every elevated capability is removed.
- **Writable paths:** owned private config/cache/state directories, dedicated
  `netwatch/exports` and `netwatch/scratch` cache subdirectories, and `/dev/null`.
  There is no whole-CWD, shared `/tmp` or `/run/user` write grant. Directories are
  prepared before restrictions; broad roots and symlink directory targets fail
  preparation. Exports normally land in `~/.cache/netwatch/exports` on Linux.
- **Inputs:** GeoIP files in use and the configured keylog file receive exact read grants; system
  executable/library and resolver paths remain readable. Missing or replaced
  keylog/database files require restarting Netwatch. Rotation does not expand the
  policy to a parent directory.
- **SDK source:** eBPF loads inside the filesystem policy. Its SDK reader
  inherits that policy but retains load capabilities until it has its own entry hook.
- **Strict mode:** preflight/required worker entry failures stop startup with a
  nonzero exit. After the main thread drops raw-socket authority, capture restart
  may fail; it never retries unsandboxed. macOS/Windows have no backend and reject
  strict startup. Best-effort reports degradation on those platforms.
- **Network:** policy is per thread, and only on Linux.

  | Threads | TCP bind and connect | socket(2) |
  | --- | --- | --- |
  | Main and the network workers (reverse DNS, WHOIS, GeoIP, health, traceroute, Insights, remote, Diagnose probes, blocking pool) | Allowed | Allowed |
  | Other parser workers (connections, tcp-info, traffic, process CPU, eBPF, terminal, logging, export) | Denied from Linux 6.7 | Allowed: `ss`, `ip` and `iw` need netlink, and the others have not been audited for the filter |
  | Capture, keylog, metrics listener and client | Denied from Linux 6.7 | EPERM |

  `netwatch doctor --json` reports the kernel's ABI and what a parser thread enforces
  on it. What each thread of a running session got, its `network_policy` included, is
  in that session's log, and Settings has the totals; `doctor` shows `protections`
  empty and `tasks_holding_net_raw` null
  ([where each value can be read](doctor.md#where-each-value-can-be-read)). A kernel
  below Linux 6.7 runs best-effort without
  the deny and refuses `--sandbox-strict`. A denied thread still has other routes:
  UDP, ICMP and netlink on threads with socket(2), any descriptor opened earlier, and
  the rest of the [threat model's list](THREAT-MODEL.md#what-containment-does-not-cover).
  Settings reports policy-entry results, not an independent proof that the entire
  process is exploit-proof.
- **Root:** Settings and `doctor` say `running as root: containment limited`.

Linux denial tests exercise actual lookup/Insights/keylog workers and keylog restart.
Privileged capture/restart and macOS/Windows runtime validation remain release checks.
Some detached workers still lack bounded shutdown; see the
[runtime inventory](runtime-lifecycle.md) and [capability matrix](CAPABILITIES.md).

---

## Command line

`netwatch --help` prints the flags; `netwatch diagnose` with no subcommand prints its usage.
The [man page](netwatch.1) carries the same list.

| Command | What it does |
|---------|--------------|
| `netwatch` | The TUI. Flags below. |
| `netwatch daemon` (also `--daemon`, `--headless`) | The collectors with no screen. With `--metrics` or `--metrics-addr`, serves [Prometheus metrics](observability-export.md). |
| `netwatch doctor [--json] [--check-capture] [--interface NAME]` | Read-only setup report: what this host lets netwatch see. `--check-capture` tries a real capture. See [doctor.md](doctor.md). |
| `netwatch diagnose run [--budget 30s] [--target NAME] [--format text\|json]` | One bounded diagnosis. Exit 0: completed, no issue. 1: at least one open issue. 2: no usable observation in the budget. 3: bad arguments or no session. |
| `netwatch diagnose coverage [--json] [--seconds N] [--test ID]` | Which checks have their inputs on this host, and why the others do not. |
| `netwatch diagnose episodes [DIR]` | List recorded incident episodes. |
| `netwatch diagnose replay --unstable [--json] FILE\|DIR...` | Experimental. Replay episodes through the engine and report any divergence. |
| `netwatch diagnose features --unstable [--out FILE] [--schema FILE] FILE\|DIR...` | Experimental. Write the feature table of recorded episodes. |
| `netwatch diagnose export [--since DAYS] [--out FILE] [--dry-run] [DIR]` | A pseudonymised bundle of recent incidents. Nothing is uploaded. |
| `netwatch diagnose corpus --unstable [--only ID] [DIR]` | Experimental, for netwatch's developers. Regenerate the pinned test corpus. |
| `netwatch uptime [--since 7d] [--json\|--csv] [DIR]` | Outage history: start, end, duration and the hop that failed, with totals. See [Uptime report](#uptime-report). |
| `netwatch geoip update [--city]` | Download DB-IP Lite databases for offline GeoIP. Exit 0 when every file is up to date, 1 otherwise. See [GeoIP databases](#geoip-databases). |
| `netwatch resolver status\|set\|recover` | Inspect, temporarily change (Linux, root, `--unmanaged` files only) or restore the DNS resolver. `set` and `recover` are experimental. |
| `netwatch --generate-config` | Write `config.toml` with every key at its default, then exit. To a file that exists it adds only the keys the file lacks, and keeps what is there; delete the file first for a clean one. Refuses to touch a `config.toml` that does not load. |
| `netwatch --version`, `--help` | |

`diagnose replay`, `features` and `corpus` read and write episode, feature and corpus formats
that can change in any release, so each needs `--unstable`. Without it, the command prints an
error naming the flag and exits 3, the status `diagnose run` documents for bad arguments.

TUI flags:

| Flag | Effect |
|------|--------|
| `--view full\|lite\|dense`, `--lite` | Start in that view. |
| `--demo` | Replay a recorded Diagnose incident instead of watching this host. |
| `--no-sandbox`, `--sandbox-strict` | Turn the Linux sandbox off, or refuse to start unless it is enforced. |
| `--remote URL` | Stream snapshots to a backend. Needs `NETWATCH_API_KEY`. Experimental. |
| `--insecure-remote` | Allow an `http://` remote URL. Experimental, with `--remote`. |
| `--api-key KEY` | Deprecated: the key shows in the process list. Use `NETWATCH_API_KEY`. Keeps working until 2.0, and prints a warning that does not include the key. |
| `--metrics`, `--metrics-addr ADDR` | With `daemon`: serve metrics on `127.0.0.1:9464`, or on `ADDR`. |

### Uptime report

The Topology tab's *connection* box shows the live state: how long the connection has been up
(since netwatch started, or since the last outage it saw, with the hop and how long it lasted),
or how long it has been down and which hop is not answering. It follows the rules below and
works with `record_uptime = false`.

`netwatch uptime` answers "how often did my connection drop this week, and for how long?" from a
log the TUI and `netwatch daemon` keep while they run. For an always-on record, run the daemon
(the [systemd unit](../packaging/systemd/netwatch.service) does).

```
$ netwatch uptime --since 7d
Uptime 2026-10-17 09:00 → 2026-10-24 09:00

START                END                  DURATION  FAILED
2026-10-18 14:02:11  2026-10-18 14:05:40    3m 29s  internet
2026-10-21 02:10:05  2026-10-21 02:10:50       45s  gateway

gateway: your router or LAN · internet: your ISP or beyond · dns: name resolution only

2 outages, 4m 14s down, 99.96% up over 6d 22h monitored; 2h 01m not monitored
```

- **Down** means three probe cycles in a row (about 15 s at the default refresh) with no reply,
  timed from the first of them, until the first reply. No default gateway counts as the gateway
  failing. Latency spikes are not outages.
- **The hop** is the nearest one that failed: the gateway (your router or LAN), the internet
  probe (your ISP or beyond) or DNS alone.
- **Not monitored** is time when no netwatch was running, or a gap of more than three minutes in
  the log. It is never counted as up. Time when the internet probe could not be sent at all
  (ICMP blocked and TCP/443 unanswered) is *unmeasured*, and is neither up nor down. With
  `third_party_probes = false` the probe is never sent, so all of it is unmeasured unless the
  gateway or DNS is down, and the report has no uptime percentage to give.
- **Uptime %** is up time over the time known to be up or down. It needs the internet probe,
  the only hop that can say the connection is up: over a period in which that probe was never
  measured, the text leaves the figure out and `--json` gives `"uptime_pct": null`, outages or
  not.

`--json` and `--csv` carry the same outages for an ISP ticket or a chart. Both are versioned
(`"schema": 1` in JSON) and covered by the 1.0 compatibility promise. Each outage's `ended` is
`recovered`, `monitoring_stopped` (netwatch stopped while it was still down) or `ongoing`.

The log is `~/.local/state/netwatch/uptime/`, one small file per day (about 80 KB), kept 90
days, readable only by you. Nothing is uploaded. `record_uptime = false` turns it off.

### GeoIP databases

`netwatch geoip update` downloads DB-IP's free Country and ASN databases, which fill the GeoIP
column and the organisation names. `--city` adds the City database, and later runs keep it up to
date. That is a 60 MB download, and a session holds its 127 MB in memory, against 8 MB for Country.

```
$ netwatch geoip update
updated /home/you/.cache/netwatch/geoip/dbip-country-lite.mmdb (DBIP-Country-Lite, built 2026-10-01)
updated /home/you/.cache/netwatch/geoip/dbip-asn-lite.mmdb (DBIP-ASN-Lite (compat=GeoLite2-ASN), built 2026-10-01)
IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0
restart netwatch to load it
```

A file the server has nothing newer for is reported as `already current`. The command exits 0 when
every file is up to date and 1 otherwise, and a file it could not replace stays as it was. It runs
only when you run it. Nothing refreshes the files on its own, and `netwatch doctor` reports
`geoip_db` as `degraded` (`db_stale`) once a loaded database is over 60 days old.

An empty `geoip_db` or `geoip_asn_db` uses these files, City ahead of Country, and a path in the
config wins. Run the command as the user who runs netwatch: the files live in that user's cache
directory and only that user can read them. It refuses a cache directory whose path is not valid
UTF-8, because netwatch could not load a database saved there.

The command name, `--city` and the exit codes are stable. The data source and the file location may
change between releases, so a script should ask `netwatch doctor --json` what loaded rather than
look for a file name. On Linux the download is read on a worker thread that cannot open TCP
connections from Linux 6.7 on; see the [threat model](THREAT-MODEL.md).

IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0. Settings and `netwatch doctor` show that
line whenever a loaded database says it is DB-IP's, wherever the file came from.

---

## Keyboard controls

| Key | Action |
|-----|--------|
| `1`–`9`, `0` | Switch tabs (`9` Diagnose, `0` Egress) |
| `P` | Promote observed egress baseline → `egress-policy.toml` |
| `↑` `↓` | Navigate |
| `p` | Pause / resume |
| `r` | Force refresh |
| `R` | Arm / reset flight recorder |
| `F` | Freeze current incident window |
| `E` | Preview and export the incident bundle |
| `/` | Filter (Packets) |
| `c` | Start/stop capture (Packets) |
| `s` | Sort / stream view |
| `w` | Preview and export the shown packets as PCAPNG or PCAP |
| `T` | Traceroute |
| `W` | Whois lookup |
| `t` | Cycle theme |
| `V` | Cycle view: full → lite → dense (dense needs 130×44, then grows to fit) |
| `L` | Switch to the Lite view |
| `,` | Settings |
| `?` | Help |
| `q` | Quit (asks first with `confirm_quit = true`). On an overlay, `q` closes it |
| `Ctrl+C` | Quit at once |

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
| `E` | Preview and export the incident bundle |
| `i` | Cycle capture interface |
| `b` | Set BPF capture filter |
| `/` | Display filter |
| `s` | Stream view |
| `w` | Preview and export the shown packets as PCAPNG or PCAP |
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

### Egress
| Key | Action |
|-----|--------|
| `↑` `↓` | Select / scroll profiles |
| `Enter` | Promote selected process (merges; status line shows the diff) |
| `P` | Promote all → `egress-policy.toml` |
| `e` | Export attributed egress records → `~/netwatch_egress_<ts>.ndjson` |

### Dense view
| Key | Action |
|-----|--------|
| `↑` `↓` / `k` `j` | Select connection (the detail panel follows the selection) |
| `Home` / `End` | First / last connection |
| `p` / `Space` | Pause / resume |
| `V` | Cycle view |
| `Esc` | Back to the full view |
| `,` | Settings |
| `?` | Help |
| `q` | Quit |

### Settings
| Key | Action |
|-----|--------|
| `↑` `↓` | Navigate settings |
| `Enter` | Edit selected setting |
| `←` `→` | Cycle the selected setting (theme, view, graph style, sandbox…) |
| `S` | Save config |
| `Esc` / `q` | Close |

</details>

---

## Distro packages

From v0.32.1 every release carries `.deb` and `.rpm` packages for x86_64 and
aarch64, built from the same musl-static binary as the tarball:

```sh
sudo apt install ./netwatch_0.32.1-1_amd64.deb     # Debian, Ubuntu
sudo dnf install ./netwatch-0.32.1-1.x86_64.rpm    # Fedora, RHEL
```

They install the binary, all three shell completions, the man page, the
fleet-agent systemd unit (not enabled) and the docs. They have **no**
dependencies — libpcap is linked into the binary.

Where each package comes from, and what to do at release time, is in
[PACKAGING.md](PACKAGING.md).

Neither package grants capabilities. `netwatch` still needs elevated access to
capture, so either run it with `sudo` or grant them yourself once (see
[Permissions](#permissions)); the package prints that command on install. A
package that silently gives a binary raw-socket access is the administrator's
decision to make, not the packager's.

## Verifying a download

Every release ships `SHA256SUMS` alongside the binaries, and each artifact
carries signed build provenance tying it to the workflow run and commit that
produced it.

```sh
# Checksums
curl -LO https://github.com/matthart1983/netwatch/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS

# Provenance (needs the GitHub CLI)
gh attestation verify netwatch-linux-x86_64.tar.gz -R matthart1983/netwatch

# The SBOM the artifact was built from (netwatch-X.Y.Z.cdx.json on the release)
gh attestation verify netwatch-linux-x86_64.tar.gz -R matthart1983/netwatch \
  --predicate-type https://cyclonedx.org/bom

# The container image
gh attestation verify oci://ghcr.io/matthart1983/netwatch:vX.Y.Z -R matthart1983/netwatch

# Known advisories in an installed binary's dependencies (needs cargo-audit)
cargo audit bin "$(command -v netwatch)"
```

Checksums and attestations are produced from v0.32.1 onward; earlier releases
have neither. The CycloneDX SBOM and the image attestation start with the
release after 0.35.4. Release binaries carry their dependency list (built
with `cargo auditable`) from 0.37.0, so `cargo audit bin`, Trivy and Syft can
check one without the SBOM. A `cargo install` build doesn't carry it.

## Shell completions and the man page

The repository ships completions for bash, zsh and fish in `completions/`, and
a man page at `docs/netwatch.1`. Package installs put them in place for you;
for a manual install:

```sh
sudo install -m0644 completions/netwatch.bash /etc/bash_completion.d/netwatch
sudo install -m0644 completions/_netwatch /usr/share/zsh/site-functions/_netwatch
install -m0644 completions/netwatch.fish ~/.config/fish/completions/netwatch.fish
sudo install -m0644 docs/netwatch.1 /usr/share/man/man1/netwatch.1
```

A test in `src/cli.rs` fails if an option is added to the parser without being
added to all three completions and the man page.

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
run the whole TUI as root. Prefer a root-owned binary executable only by an
authorized group. Create the group if needed and add your account, then log in
again for membership to take effect. Apply capabilities last, after ownership:

```bash
sudo groupadd -f netwatch
sudo usermod -aG netwatch "$USER"
# The first netwatch on PATH outside /usr/local/bin, where this recipe puts
# its copy, so a re-run after an upgrade finds the new binary. A symlink, such
# as a Nix profile's, is followed to its file.
bin=$(echo "$PATH" | tr : '\n' | grep -vx '/usr/local/bin/*' | while read -r dir; do
  [ -x "$dir/netwatch" ] && echo "$dir/netwatch" && break
done)
bin=$(readlink -f "${bin:-/usr/local/bin/netwatch}")
# A package's /usr/bin/netwatch is changed in place, so an upgrade resets it.
# Anything else is copied to a root-owned path first: a binary you own could
# otherwise be made executable by everyone, and a Nix store file is shared.
case $bin in
  /usr/bin/netwatch | /usr/local/bin/netwatch) ;;
  *)
    sudo install -o root -g netwatch -m 0750 "$bin" /usr/local/bin/netwatch
    bin=/usr/local/bin/netwatch
    ;;
esac
sudo chown root:netwatch "$bin"
sudo chmod 0750 "$bin"
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' "$bin"
echo "After logging in again, run $bin"
```

> **Re-run after every install.** `setcap` attaches to a specific binary on disk. A package
> upgrade replaces `/usr/bin/netwatch` with a root-owned, world-executable file without
> capabilities, so capture fails until the recipe runs again. `cargo install netwatch-tui`,
> the Release tarballs, Homebrew and Nix replace only their own file: the copy in
> `/usr/local/bin` keeps the old version and its capabilities until the recipe copies the
> new binary over it. The recipe skips `/usr/local/bin` when it looks for netwatch, so the
> re-run finds the new binary wherever `/usr/local/bin` sits in `PATH`. If you see `pcap
> open failed: socket: Operation not permitted` or `BPF load failed: PermissionDenied` in
> `~/.cache/netwatch/netwatch.log.*` after an upgrade, the binary needs the root ownership,
> group execution restriction and `setcap` re-applied. Never grant capture capabilities to
> a world-executable copy.

When capture is refused, netwatch prints a shorter form of this for a binary it can change in
place, such as a package's. A binary on a read-only store stops
it at `chown` before anything is granted, and needs the recipe above. `netwatch doctor
--check-capture` prints it with each command on its own row. The Dashboard and Packets headers
draw it whole, or, when the terminal has too few rows or columns, point to doctor and to this
section instead:

```bash
b=$(readlink -f "$(which netwatch)") && sudo groupadd -f netwatch && sudo usermod -aG netwatch "$USER" && sudo chown root:netwatch "$b" && sudo chmod 0750 "$b" && sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' "$b" && echo 'Log in again to join the group: netwatch cannot start until you do'
```

As it says, log in again before the next `netwatch`. `usermod` does not change a session already
running, so until then the group restriction keeps this session out too: `netwatch` gets
permission denied, and pasting the line again stops at `which`, which no longer finds it.

The [systemd unit](../packaging/systemd/netwatch.service) needs none of this: it grants the
capabilities to its own service user.

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

8 built-in themes with instant switching via `t`:
**Dark** (default) · **Terminal** · **Ocean** · **Solarized** · **Dracula** · **Nord** · **Sky** · **Paper**

Theme changes apply immediately. Persist them from the Settings overlay with `S`.

**Terminal** pins no colors of its own — every slot resolves to an ANSI palette entry, and
foreground and background use your terminal's own defaults. If you theme your whole desktop
with pywal, matugen, or a terminal profile, this is the one that follows along. It's also
accepted under the names `system` and `ansi` in a config file.

Chart rendering is a separate axis from the theme. The braille area plot and its magnitude
gradient are both on by default; `graph_style = "bars"` swaps the plot for solid blocks if
your font has no braille coverage, and `graph_fade = false` drops the gradient. Both live in
[Configuration](#configuration).

`NO_COLOR` set to any non-empty value turns colour off in every view, whatever the theme.
The selection, highlighted rows and filled bars show in reverse video instead.

---

## Environment variables

| Variable | Effect |
|----------|--------|
| `NO_COLOR` | Any non-empty value: draw the TUI without colour ([no-color.org](https://no-color.org)). |
| `NETWATCH_API_KEY` | API key for `--remote`. Preferred over `--api-key`, which leaves the key in the process list and shell history. |
| `NETWATCH_REMOTE_URL` | Remote backend URL, when `--remote` is not given. |
| `NETWATCH_METRICS_ADDR` | Address for the daemon's metrics endpoint, when `--metrics-addr` is not given. |
| `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` (and lowercase) | Diagnose records whether a proxy applies to each configured target, and weighs it as evidence: an untrusted certificate behind a proxy points at interception. |

Variables named `NETWATCH_*` that are not listed here are test hooks and may change in any release.

---

## What netwatch sends off this machine

GeoIP lookups read local files, so the GeoIP column sends nothing anywhere. This is what does
leave the host. "Automatically" means in every TUI, `netwatch daemon`, `netwatch diagnose run` and
`netwatch diagnose coverage` session, with nothing to press. The
[threat model](THREAT-MODEL.md#outbound-inventory) lists the same destinations, and a test holds
its default endpoints to the code.

| What | When | Where it goes | What it carries |
|------|------|---------------|-----------------|
| Reference DNS query | Automatically | 1.1.1.1 | A query for `dns.google` |
| Internet reachability | Automatically | 1.1.1.1, with a TCP fallback on port 443 | A probe, no data |
| STUN | Automatically, about once a minute | `stun.l.google.com:19302`, `stun.cloudflare.com:3478` | A binding request, which reveals your public address to them |
| Health probes | Automatically | Your gateway and the configured resolver | ICMP echoes, with TCP connects where those are dropped, and DNS queries |
| Reverse DNS | Automatically, for addresses in this host's own connections | The system resolver | The addresses it looks up |
| Startup trace | Every TUI start, the demo included | 1.1.1.1 | TTL-limited packets |
| Traceroute | Only when you press `T` | The selected peer on Connections or Topology | TTL-limited packets |
| Periodic trace | Only with `diagnose_probes.trace_refresh_secs` set | `diagnose_probes.trace_target` | TTL-limited packets |
| Diagnose targets | With `[[diagnose_targets]]` set: automatically on their schedule (`interval_secs`, default 60 s), and on demand | The hosts you list, and your resolvers for their names | DNS lookups, TCP and TLS handshakes and an HTTP request to the path you set |
| WHOIS | Only when you press `W` | `rdap.org` and the registry it redirects to | On Connections the selected remote address, on Packets the selected packet's two addresses; private ranges are not sent |
| Diagnose experiments | When you start one from Diagnose or with `netwatch diagnose coverage --test`; a test you started can repeat itself | The defaults in the [threat model](THREAT-MODEL.md#outbound-inventory), your resolver and gateway, or what `diagnose_probes` sets | Probes; the upload test sends up to 25 MB of filler |
| GeoIP download | Only when you run `netwatch geoip update` | `download.db-ip.com`, HTTPS only | The file names and dates it asks for, no addresses |
| Insights, opt-in | While `insights_enabled` is on, up to every 15 s | The endpoint you configure, by default Ollama on this machine | Network and packet summaries, with top talkers and DNS names |
| Remote, opt-in | With `--remote` or `NETWATCH_REMOTE_URL` | The URL you give | Interface, health, system and disk metrics, the connection count, and the hostname, OS, kernel, uptime, CPU model and memory size; HTTPS unless you allow otherwise |

## Configuration

NetWatch runs with zero setup — every key below has a working default, and the file doesn't
exist until you write one.

| Platform | Config file |
|----------|-------------|
| Linux | `~/.config/netwatch/config.toml` |
| macOS | `~/Library/Application Support/netwatch/config.toml` |
| Windows | `%APPDATA%\netwatch\config.toml` |

Two ways to write it. From the shell:

```bash
netwatch --generate-config    # writes every key at its default value, then exits. To a
                              # file that exists, adds only the keys it lacks
```

Or live in the TUI: `,` opens Settings, `↑`/`↓` moves, `←`/`→` cycles the enum-valued rows
(theme, view, default tab, graph style, graph fade, sandbox, group folding), `Enter` edits
the free-text ones, `S` saves. Most changes apply the moment you make them — `sandbox` is the
exception, because Landlock and dropped capabilities can't be undone inside a running
process, so it takes effect on the next launch.

Neither writes the `[diagnose_thresholds]` table unless you changed it, so a later release can
retune them; [DIAGNOSE.md](DIAGNOSE.md#thresholds) lists its keys.

A hand-edited file can't cost you the tool: missing keys fall back to their defaults,
out-of-range numbers are clamped, and an unrecognised value falls back rather than refusing
to start.

A key netwatch does not read is ignored and reported, because otherwise a typo such as
`sandbox_mode = "strict"` would do nothing without a word. netwatch still starts. `netwatch`
and `netwatch daemon` print `warning: <file>: unknown key <key> is ignored` on stderr before
they start, at any depth (`alerts.typo`, `diagnose_targets.0.typo`), and write it to the log.
The TUI hides stderr until it quits, so it also shows the warning on its bottom row for its
first 30 seconds, in every view, and Settings keeps the list. `diagnose run`,
`diagnose coverage` and `geoip update` print the same line on stderr. `netwatch doctor` reports
`config` as `degraded`, reason `config_unknown_keys`. None of these prints the key's value.

A key that gets renamed keeps working until 2.0. netwatch reads the old name as the new one and
warns `<old> was renamed <new> in <release>` in the same places. `netwatch doctor` leaves `config`
`ready`, with reason `config_renamed_keys`. If the file sets both names, the new one wins. A save
writes the new name. No key has been renamed so far. `geoip_online` below was removed.

The `[experimental]` table is for settings that can still change, and is outside the 1.0
compatibility promise. A key in it can change meaning or go away in any release. Nothing is in
it yet. A key in it this version does not read is expected rather than a mistake, so it does not
warn as unknown. stderr gets a `note:` line, `netwatch doctor` lists it and leaves `config`
`ready`, Settings lists it, and the TUI's bottom row says nothing. A save keeps the table.

A save writes only what the session changed, compared with what it loaded. Settings' `S` and the
Diagnose tab's `d` change those keys in the file, and a target is found by its `name`, wherever
it now sits. Everything else stays as the file has it: a key you edited by hand while netwatch
ran, a value the session clamped or fell back from, a key netwatch does not read, a table at its
defaults, comments, and any default you never set, which a later release can still change. If you
and the session changed the same key, the session's value wins for that key alone. `d` on a target
the file no longer has fails and leaves the file; press `r` to reload. `--view` is for one run, and
a save does not write it. With nothing to write, the file is not touched.

A save that does write keeps the old file until the new one is complete and synced, so a full
disk leaves the settings you had, and keeps the file's mode and any symlink to it. It drops a
byte-order mark and ends every line in LF. Removing `geoip_online` also removes a comment directly
above it.

`--generate-config` is the one thing that writes defaults. A new file gets every key. A file that
exists gains the keys it lacks, and keeps every value and comment it has. It leaves out
`diagnose_targets` while there are none, so you can append `[[diagnose_targets]]` to the file.

A file netwatch cannot read or parse is different. If the TOML is broken, or a key has a value
of the wrong type (`refresh_rate_ms = "fast"`), `netwatch` and `netwatch daemon` print the
file, line and column and exit 1 without starting. Running on the defaults instead would
drop every other setting in the file, `sandbox = "strict"` and `record_uptime = false`
included. `diagnose run` exits 3 and `diagnose coverage` exits 1 with the same message.
`netwatch doctor` reports it as `config_invalid` or `config_unreadable` without quoting the
file. Neither `--generate-config` nor Settings overwrites the file. With no file at all, the
defaults apply as before.

### Appearance

| Key | Default | Values | What it does |
|-----|---------|--------|--------------|
| `theme` | `"dark"` | `dark` `terminal` `ocean` `solarized` `dracula` `nord` `sky` `paper` | Color theme. `terminal` is also accepted as `system` or `ansi`. See [Themes](#themes). |
| `view` | `"full"` | `full` `lite` `dense` | Which view starts. `--view` overrides it for one run; an unknown name falls back to `full`. |
| `default_tab` | `"dashboard"` | `dashboard` `connections` `interfaces` `packets` `stats` `topology` `timeline` `processes` `diagnose` `egress` `insights` | `insights` is a legacy alias for Diagnose. Tab shown on launch in the full view. |
| `graph_style` | `"dots"` | `dots` `bars` | Chart rendering for every sparkline in the app. `dots` is the braille area plot: two samples per cell column and four times the vertical resolution, so a sparkline carries twice the history in the same width. `bars` is solid blocks, for terminals whose font has no braille coverage — there the area plot renders as empty boxes. |
| `graph_fade` | `true` | `true` `false` | The magnitude gradient: every cell is coloured by how high it sits — dim at the baseline, the series colour in the middle, lightened at the peak. It is what makes a filled area read as depth rather than as a block. Under the `terminal` theme it steps from each series colour to its bright palette variant instead of blending, so no colour is invented. |
| `groups_start_collapsed` | `true` | `true` `false` | Whether the grouped tables (Connections, Egress) open folded. Folded answers "what is on this machine" in one glance; `false` is closer to the old flat tables. |
| `confirm_quit` | `false` | `true` `false` | Ask "Quit netwatch?" before `q` quits; `y`, `q` or `Enter` confirms, any other key stays. `Ctrl+C` always quits at once. |

**The plain look**, if braille or colour interpolation is a problem in your terminal:

```toml
graph_style = "bars"
graph_fade  = false
```

`graph_style` governs *every* chart routed through the graph module — the Dashboard's hero
tiles and throughput plot, per-interface sparklines, in-row connection lines, RTT history,
timeline tracks, and Lite's charts. There is one braille renderer behind it, shared with the
Dense view's mirrored plot, so no two graphs in the tool can drift apart in texture or in
colour. The Dense view is the one place that stays braille regardless of the setting: it has
no fallback layout that would fit in blocks.

One asymmetry worth knowing under `bars`. The mirrored half of a shared-axis graph — the
upload series hanging below the Dashboard's zero line — draws at three fill levels rather
than eight. The bottom-anchored eighths (`▁`–`▇`) are all in Unicode's Block Elements range;
their top-anchored counterparts past `▔` and `▀` are in Symbols for Legacy Computing, whose
font coverage is the thing `bars` exists to avoid depending on. The upward half keeps its
full resolution.

### Refresh and capture

| Key | Default | Values | What it does |
|-----|---------|--------|--------------|
| `refresh_rate_ms` | `1000` | 100–5000 | Tick rate in milliseconds. Values outside the range are clamped, not rejected. |
| `capture_interface` | `""` | interface name | Interface to capture on, e.g. `"en0"`. Empty auto-detects. |
| `bpf_filter` | `""` | BPF expression | Capture filter applied at the kernel, e.g. `"tcp port 443"`. Empty captures everything. |
| `packet_follow` | `true` | `true` `false` | Auto-scroll the Packets tab to newest. |
| `timeline_window` | `"5m"` | `1m` `5m` `15m` `30m` `1h` | Timeline tab's default window. |
| `tls_keylog_path` | `""` | file path | NSS keylog file to read session secrets from, for [TLS decryption](#tls-13--12-decryption). Config-file only — there is no Settings row for it. |

### GeoIP

| Key | Default | Values | What it does |
|-----|---------|--------|--------------|
| `show_geo` | `true` | `true` `false` | Show the GeoIP column in Connections. |
| `geoip_db` | `""` | file path | A City or Country `.mmdb`, DB-IP's or MaxMind's. Empty uses what [`netwatch geoip update`](#geoip-databases) downloaded, if anything. Lookups never leave this machine. A file over 2 GiB, or anything but a regular file, is reported as unreadable. |
| `geoip_asn_db` | `""` | file path | An ASN `.mmdb`, DB-IP's or MaxMind's, for organisation names. Empty uses what `netwatch geoip update` downloaded, if anything. The same limits apply. |
| `geoip_online` | removed | | Removed in 0.39: it sent peer addresses to a third party in cleartext. A config that sets it still loads, the setting is ignored, and the log says so once per start. The next save from Settings drops it. Run [`netwatch geoip update`](#geoip-databases) instead. |

### Security

| Key | Default | Values | What it does |
|-----|---------|--------|--------------|
| `sandbox` | `"on"` | `on` `strict` `off` | Sandbox enforcement. `on` is best-effort, `strict` refuses to start if the platform backend can't apply it, `off` skips it. `--no-sandbox` and `--sandbox-strict` override for one run. Applies at next launch. See [the Landlock sandbox](#landlock-sandbox-linux). |
| `record_uptime` | `true` | `true` `false` | Keep the local log [`netwatch uptime`](#uptime-report) reports from. Config-file only. |
| `egress_violation_cooldown_secs` | `300` | seconds | How long before the same violating flow — one (process, destination, port) — warns again on egress policy drift. `0` warns on every refresh. Config-file only. |
| `third_party_probes` | `true` | `true` `false` | Send the automatic probes that go to public servers. `false` stops them; see below. Config-file only, read at start. |

`third_party_probes = false` stops four things: STUN to `stun.l.google.com` and
`stun.cloudflare.com`, the `dns.google` cross-check against 1.1.1.1, the internet probe (ICMP,
then TCP 443) to 1.1.1.1, and the trace each TUI start runs to 1.1.1.1. What they measured reads
as not measured, never as failed:

- The internet RTT reads `—`, and Dense shows its target as `off`. Topology's ISP box stays
  empty until you press `T`.
- `netwatch uptime` reports the connection as unknown rather than up. A gateway or DNS outage
  still counts.
- Diagnose coverage shows `dns.hijack_suspect`, `nat.symmetric`, `gateway.unreachable` and
  `tcp.bufferbloat_local` as not measured, and the first three cannot open. Without a probe beyond the gateway, a router that drops
  ICMP and has no open TCP port looks the same as a dead one, so a dead gateway shows up as a
  failing resolver or a down link instead of `gateway.unreachable`.
- `dns.alt_resolver`, `path.internet_tracks_gateway` and `load.idle_vs_loaded`, the three tests
  that ask 1.1.1.1, do not run. `t` on an issue picks another test, and `t` on the
  `tcp.bufferbloat_local` coverage row says why it will not start the load test, which also
  uploads to `speed.cloudflare.com`.

Your configured resolver and gateway are still probed. What else you start yourself still runs:
`T`, `W`, `t` on a coverage row for the experiments or a trace of `trace_target`, and periodic
traces if you set `diagnose_probes.trace_refresh_secs`. `trace_target` defaults to 1.1.1.1, so
change it if you use those.

### Alerts

Under a `[alerts]` table:

```toml
[alerts]
bandwidth_threshold   = 100000000   # bytes/sec; 0 disables
port_scan_threshold   = 20          # distinct ports within the window
port_scan_window_secs = 30          # detection window
```

`port_scan_window_secs` is config-file only; the other two have Settings rows.

### AI Insights

Experimental, like the feature. These three can change in any release.

| Key | Default | Values | What it does |
|-----|---------|--------|--------------|
| `insights_enabled` | `false` | `true` `false` | Adds an AI narrative block to the Diagnose tab. Opt-in — see [AI Insights](#ai-insights). |
| `insights_model` | `"llama3.2"` | model name | Model for the Ollama or cloud endpoint. |
| `insights_endpoint` | `"local"` | `local` or base URL | `local` means `http://localhost:11434`; anything else is used as a base URL. An `http://` URL on another host is marked `cleartext, off-host`; see [AI Insights](#ai-insights). |

---

## AI Insights

Experimental. This can change or go away in any release, and is outside the 1.0 compatibility
promise.

Insights is opt-in commentary inside **Diagnose (`9`)**, below the findings.
It sends a network snapshot to the configured Ollama-compatible `/api/chat`
endpoint. Requests are rate-limited with a 15-second interval and a 30-second
request timeout; analysis requires a nonempty retained packet snapshot, not
necessarily new traffic during that interval.

Detection, cause ranking and remediation run without a model. Commentary can be
wrong and is not mechanically checked against the deterministic findings. The
snapshot contains packet-derived summaries, addresses, names and health metrics;
it is not a serialized list of Diagnose issues.

Enable via Settings (`,`) → AI Insights. `local` resolves to
`http://localhost:11434`; a configured remote URL sends data to that host. A local
endpoint alone does not guarantee local inference if its server forwards requests.
With an `http://` URL on another host, the snapshot crosses the network unencrypted.
netwatch still sends it, and says `cleartext, off-host` on the Diagnose page and the AI
Endpoint row in Settings. `netwatch doctor` reports `insights` as degraded with reason
`cleartext_off_host`.
See [INSIGHTS.md](INSIGHTS.md) for setup, data disclosure and troubleshooting.

---

## How it works

The intervals below assume the default one-second tick. Platform support is not
feature parity; see the [capability matrix](CAPABILITIES.md), including Windows,
and the [Diagnose rule coverage](diagnostic-coverage.md).

| Collector | Interval | macOS | Linux |
|-----------|:--------:|-------|-------|
| Interface stats | 1s | `netstat -ib` | `/sys/class/net/*/statistics` |
| Connections | 2s | `lsof` + PKTAP | `/proc/net/tcp` + eBPF kprobe |
| Health probes | Every 5 ticks | Gateway/internet ICMP, DNS queries | Gateway/internet ICMP, DNS queries |
| Packets | Real-time | libpcap (BPF) | libpcap |
| GeoIP | On-demand | Local `.mmdb` files | Local `.mmdb` files |

```
Raw bytes → Ethernet → IPv4/IPv6/ARP → TCP/UDP/ICMP → L7 decoders
                                            ↓
                          Per-flow stream tracking · Handshake timing
                          TLS 1.3 decryption · JA4 · Expert info
```

For the module-level source map and runtime architecture, see [WIKI.md](WIKI.md).
