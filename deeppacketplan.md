# Deep Packet Inspection — netwatch implementation plan

Targets adding L7 protocol classification + metadata extraction (SNI hostname, HTTP host, DNS qname, SSH banner, QUIC tag) on top of netwatch's existing packet-capture pipeline. Single user-visible deliverable: the Connections tab gets a **PROTO** column showing e.g. `HTTPS api.example.com` instead of plain `TCP`.

## Existing pieces this hooks into

- **`src/collectors/packets.rs:1949`** — `extract_app_payload()` already returns clean L7 bytes from each captured packet.
- **`src/collectors/packets.rs:319`** — `StreamTracker.all_streams: HashMap<u32, Stream>` is the per-flow store. `Stream` already accumulates per-flow state (byte counters, handshake, segments).
- **`src/collectors/connections.rs:30`** — `Connection` is the user-facing record. Joins to `Stream` via the same code path that surfaces `rx_rate`/`tx_rate` today.
- **`src/ui/connections.rs`** — Connections tab; where the new column lands.

---

## Phase 0 — Dependencies (10 min)

Add to `Cargo.toml`:

```toml
tls-parser = "0.12"   # Suricata folks. Handles ClientHello / SNI / ALPN / TLS 1.3.
httparse = "1.10"     # Already transitive via hyper; promote to direct.
# DNS hand-rolled (avoid hickory-proto's tree).
# QUIC deferred — see Phase 9.
```

No new C deps. No license complexity (MIT/Apache-2 throughout).

---

## Phase 1 — Module scaffolding (~120 LOC, 2 hrs)

**New files:** `src/dpi/mod.rs`, `src/dpi/{tls,http,dns,ssh}.rs` (stubs).

```rust
// src/dpi/mod.rs
pub mod tls;
pub mod http;
pub mod dns;
pub mod ssh;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppProtocol {
    Tls   { sni: Option<String>, alpn: Option<String> },
    Http  { method: String, host: Option<String> },
    Dns   { qname: String, qtype: u16 },
    Ssh   { version: String },
    Quic  { sni: Option<String> },  // Phase 9
}

pub trait Classifier {
    /// Returns `Some(protocol)` if this classifier recognizes the payload,
    /// `None` to let the next classifier try.
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<AppProtocol>;
}

/// Run classifiers in priority order; first hit wins.
pub fn classify_once(payload: &[u8], is_tcp: bool) -> Option<AppProtocol> {
    if let Some(p) = ssh::SshClassifier.classify(payload, is_tcp) { return Some(p); }
    if let Some(p) = http::HttpClassifier.classify(payload, is_tcp) { return Some(p); }
    if let Some(p) = tls::TlsClassifier.classify(payload, is_tcp) { return Some(p); }
    if !is_tcp {
        if let Some(p) = dns::DnsClassifier.classify(payload, is_tcp) { return Some(p); }
    }
    None
}
```

Each classifier file starts with a stub `impl Classifier for X { fn classify(...) -> None }`.

Add `mod dpi;` to `src/lib.rs` (or wherever modules are declared).

**Acceptance:** `cargo build` clean.

---

## Phase 2 — TLS-SNI classifier (~150 LOC, half-day)

**File:** `src/dpi/tls.rs`

```rust
use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsExtension};

pub struct TlsClassifier;

impl super::Classifier for TlsClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<super::AppProtocol> {
        if !is_tcp || payload.len() < 16 { return None; }
        // Quick reject: TLS record always starts with content_type = 0x16
        // (handshake) + version major 0x03.
        if payload[0] != 0x16 || payload[1] != 0x03 { return None; }

        let (_, record) = parse_tls_plaintext(payload).ok()?;
        for msg in record.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) = msg {
                let mut sni = None;
                let mut alpn = None;
                if let Some(ext_data) = ch.ext {
                    if let Ok((_, exts)) = tls_parser::parse_tls_extensions(ext_data) {
                        for ext in exts {
                            match ext {
                                TlsExtension::SNI(entries) => {
                                    sni = entries.first().and_then(|(_, host)|
                                        std::str::from_utf8(host).ok().map(String::from));
                                }
                                TlsExtension::ALPN(protos) => {
                                    alpn = protos.first()
                                        .and_then(|p| std::str::from_utf8(p).ok())
                                        .map(String::from);
                                }
                                _ => {}
                            }
                        }
                    }
                }
                return Some(super::AppProtocol::Tls { sni, alpn });
            }
        }
        None
    }
}
```

**Unit tests** with two fixtures:
- Canonical ClientHello to `example.com` (200-byte byte array, capture via `openssl s_client -msg -connect example.com:443`)
- A ServerHello (must return `None` — we only classify client-side)

**Acceptance:** classifier returns `Some(Tls { sni: Some("example.com"), .. })` for fixture.

---

## Phase 3 — Wire into StreamTracker (~60 LOC, 2 hrs)

**File:** `src/collectors/packets.rs`

Add fields to `Stream` (around line 303):

```rust
pub struct Stream {
    // ... existing fields ...
    /// Detected L7 protocol — populated on first payload that classifies
    /// successfully; cached for the lifetime of the stream.
    pub app_protocol: Option<crate::dpi::AppProtocol>,
    /// True once classification was attempted (success or not) so we don't
    /// repeatedly re-classify long-running streams.
    app_protocol_attempted: bool,
}
```

In `track_packet` (around line 364), after the existing payload accumulation:

```rust
const MAX_CLASSIFY_BYTES: usize = 4096;

if !stream.app_protocol_attempted && !payload.is_empty() && payload.len() >= 16 {
    let is_tcp = matches!(protocol, StreamProtocol::Tcp);
    let slice = &payload[..payload.len().min(MAX_CLASSIFY_BYTES)];
    stream.app_protocol = crate::dpi::classify_once(slice, is_tcp);
    stream.app_protocol_attempted = true;
}
```

Cost: classifier runs once per stream, not per packet. TLS-SNI fits in the first ~600 bytes of payload — single-segment fixture covers 99%+ of TLS connections. Fragmented ClientHellos are <1% and we accept the miss for now.

**Acceptance:** unit test — feed `StreamTracker::track_packet` a synthetic TLS ClientHello, assert `stream.app_protocol == Some(Tls { sni: Some(...), .. })`.

---

## Phase 4 — Join to Connection (~80 LOC, 2 hrs)

**File:** `src/collectors/connections.rs`

Add field to `Connection` (line 30):

```rust
pub struct Connection {
    // ... existing fields ...
    /// L7 protocol from DPI when packet capture has seen this flow.
    pub app_protocol: Option<crate::dpi::AppProtocol>,
}
```

Find the existing join site that populates `rx_rate`/`tx_rate` from the StreamTracker (grep for `rx_rate`). At the same site, populate `app_protocol` from the matching `Stream`.

The join key is the 5-tuple `(proto, local_ip, local_port, remote_ip, remote_port)`. Both stores carry this — same join logic.

**Edge cases:**

- Direction normalization: `StreamKey` is canonical (a < b sorted); `Connection` records direction explicitly. The join must handle both orientations.
- Connections from lsof/eBPF that haven't been seen on the wire have `app_protocol = None` and render as plain "TCP"/"UDP".

**Acceptance:** integration test — synthetic capture of a TLS connection, assert the corresponding `Connection`'s `app_protocol` is `Some(Tls { .. })`.

---

## Phase 5 — Connections tab UI column + filter (~120 LOC, half-day)

**File:** `src/ui/connections.rs`

Add a "PROTO" column to the connections table.

```rust
fn render_app_protocol(p: &Option<AppProtocol>) -> Cow<'_, str> {
    match p {
        None                                              => "—".into(),
        Some(AppProtocol::Tls { sni: Some(host), .. })    => format!("HTTPS {}", host).into(),
        Some(AppProtocol::Tls { sni: None, .. })          => "HTTPS".into(),
        Some(AppProtocol::Http { method, host: Some(h) }) => format!("HTTP {} {}", method, h).into(),
        Some(AppProtocol::Http { method, .. })            => format!("HTTP {}", method).into(),
        Some(AppProtocol::Dns { qname, .. })              => format!("DNS {}", qname).into(),
        Some(AppProtocol::Ssh { version })                => format!("SSH {}", version).into(),
        Some(AppProtocol::Quic { sni: Some(h) })          => format!("QUIC {}", h).into(),
        Some(AppProtocol::Quic { sni: None })             => "QUIC".into(),
    }
}
```

**Filter syntax** (extend existing chip filter):

| Filter | Matches |
|---|---|
| `proto:tls`, `proto:http`, `proto:dns`, `proto:ssh`, `proto:quic` | Connections classified as that protocol |
| `sni:github.com` | Substring match on TLS/QUIC SNI |
| `host:api.example.com` | Substring match on HTTP Host header |

**Acceptance:** open netwatch on a workstation with active traffic, press `2` (Connections), see HTTPS hostnames on browsing rows.

---

## Phase 6 — DNS classifier (~80 LOC, 2 hrs)

**File:** `src/dpi/dns.rs`

Hand-rolled DNS message parser (header 12 bytes, then qname is length-prefixed labels):

```rust
pub struct DnsClassifier;

impl super::Classifier for DnsClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<super::AppProtocol> {
        if is_tcp { return None; }  // DNS-over-TCP exists; defer.
        if payload.len() < 12 { return None; }
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        if qdcount == 0 { return None; }
        let mut pos = 12;
        let mut name = String::new();
        loop {
            if pos >= payload.len() { return None; }
            let len = payload[pos] as usize;
            if len == 0 { pos += 1; break; }
            if len & 0xC0 != 0 { return None; }  // No compression in queries.
            if pos + 1 + len > payload.len() { return None; }
            if !name.is_empty() { name.push('.'); }
            name.push_str(std::str::from_utf8(&payload[pos+1..pos+1+len]).ok()?);
            pos += 1 + len;
        }
        if pos + 4 > payload.len() { return None; }
        let qtype = u16::from_be_bytes([payload[pos], payload[pos+1]]);
        Some(super::AppProtocol::Dns { qname: name, qtype })
    }
}
```

**Acceptance:** unit test with a known DNS query byte array → `Dns { qname: "example.com", qtype: 1 }`.

---

## Phase 7 — HTTP classifier (~60 LOC, 1 hr)

**File:** `src/dpi/http.rs`

```rust
pub struct HttpClassifier;

impl super::Classifier for HttpClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<super::AppProtocol> {
        if !is_tcp || payload.len() < 16 { return None; }
        if !payload[0].is_ascii_uppercase() { return None; }  // All HTTP methods start uppercase.

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        if req.parse(payload).is_err() { return None; }
        let method = req.method?.to_string();
        let host = req.headers.iter()
            .find(|h| h.name.eq_ignore_ascii_case("host"))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .map(String::from);
        Some(super::AppProtocol::Http { method, host })
    }
}
```

**Acceptance:** `b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"` → `Http { method: "GET", host: Some("example.com") }`.

---

## Phase 8 — SSH classifier (~30 LOC, 30 min)

**File:** `src/dpi/ssh.rs`

```rust
pub struct SshClassifier;

impl super::Classifier for SshClassifier {
    fn classify(&self, payload: &[u8], is_tcp: bool) -> Option<super::AppProtocol> {
        if !is_tcp { return None; }
        if !payload.starts_with(b"SSH-") { return None; }
        let line_end = payload.iter().position(|&b| b == b'\r' || b == b'\n')?;
        let banner = std::str::from_utf8(&payload[..line_end]).ok()?;
        Some(super::AppProtocol::Ssh { version: banner.to_string() })
    }
}
```

**Acceptance:** `b"SSH-2.0-OpenSSH_9.0\r\n"` → `Ssh { version: "SSH-2.0-OpenSSH_9.0" }`.

---

## Phase 9 — QUIC (best-effort; defer if scope blows out)

QUIC Initial packets have header protection — the ClientHello can't be read without removing it first. Two paths:

- **Easy:** detect QUIC Initial packets (UDP, version-1 long header bit pattern) and return `AppProtocol::Quic { sni: None }`. Users see "QUIC" but not the hostname. ~50 LOC.
- **Hard:** implement header-protection removal (HKDF + AES-ECB or ChaCha20) so we can read the ClientHello. ~150–300 LOC + tests. Reference: `quinn-proto`'s decode path.

**Recommendation:** ship easy in this pass; come back for hard later. Hostnames-on-QUIC is increasingly the headline DPI ask, but the easy version still adds the "QUIC" tag which itself is useful for users sorting traffic by protocol.

---

## Phase 10 — Safety / perf pass (~1 hr)

- `MAX_CLASSIFY_BYTES = 4096`: classifier never reads beyond this.
- Skip classification entirely if `payload.len() < 16`.
- Confirm `app_protocol_attempted` flag prevents repeat work.
- Profile under saturating capture (1 Gbps sim) — classification cost should stay <1% CPU. If not, demote less-likely classifiers further down the priority order or gate them on port hints.

---

## Phase 11 — Tests (~half-day)

Per-classifier unit tests use captured fixtures (no live network):

```
tests/fixtures/dpi/
├── tls_clienthello_example.com.bin
├── tls_clienthello_no_sni.bin       # edge case
├── http_get_with_host.bin
├── http_post_no_host.bin            # edge case
├── dns_query_a_example.com.bin
└── ssh_banner_openssh.bin
```

Generate with `openssl s_client -msg -connect example.com:443 < /dev/null` etc.; tcpdump, save payload byte slice with Python or a one-off helper.

**Integration test:** synthetic packet → `StreamTracker` → `Connection`. Validates the full pipeline end-to-end without touching real interfaces.

---

## Phase 12 — Docs + ship (~2 hrs)

- **README:** add "Deep packet inspection" feature line: *"Identifies HTTPS (with SNI hostname), HTTP, DNS, SSH, and QUIC connections from payload bytes — no external dissectors."*
- **README:** document limitations — TLS 1.3 with ECH / Encrypted ClientHello hides SNI; connection still shows as "HTTPS" but hostname can't be extracted.
- **CHANGELOG:** entry for v0.16.0 (this is feature work, minor bump appropriate).
- **Optional CLI flag:** `--mask-sni` to disable SNI display on compliance hosts.

---

## Effort / risk summary

| | |
|---|---|
| **Total LOC** | ~700, mostly classifier code + tests |
| **Time** | 5–7 focused days |
| **New runtime deps** | `tls-parser`, `httparse` (both small, well-maintained) |
| **License risk** | None (MIT/Apache-2 throughout) |
| **C deps** | None |
| **Performance risk** | Low (classification is one-shot per stream) |
| **Privacy concern** | TLS-SNI exposes browsing destinations; mitigate with `--mask-sni` flag |
| **Known coverage gaps** | TLS 1.3 ECH (rare today, growing); QUIC SNI (deferred to Phase 9 hard mode); DNS-over-TCP / DoH / DoT (silent miss) |

---

## Shipping order

Phases 0+1+2+3+4+5 alone are a **complete shippable feature** — "HTTPS hostname extraction in the Connections tab" — that closes most of the perceived DPI gap. Day-1 deliverable.

Phases 6–8 are additive in any order. Phase 9 is its own arc that can come later when QUIC SNI extraction becomes worth the effort.
