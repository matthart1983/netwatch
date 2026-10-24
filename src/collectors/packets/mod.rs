use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

const MAX_PACKETS: usize = 5000; // ring buffer; oldest packets are discarded when full

/// How many packets the ring holds before the oldest are discarded. Public
/// because the capture strip states it: a count read off a bounded ring means
/// something different from a session total, and the screen has to say which
/// it is showing.
pub const RING_CAPACITY: usize = MAX_PACKETS;

/// How often the capture loop asks libpcap how it is doing.
const STATS_POLL: std::time::Duration = std::time::Duration::from_millis(1000);
const MAX_STREAM_SEGMENTS: usize = 10_000; // per-stream segment limit; caps memory per flow
const MAX_STREAM_BYTES: usize = 2 * 1024 * 1024; // 2 MB per reassembled stream
                                                 // StreamTracker eviction: cap unique flows to bound memory under sustained capture.
                                                 // When `all_streams.len()` exceeds MAX_STREAMS + STREAM_EVICT_BATCH we drop the
                                                 // STREAM_EVICT_BATCH least-recently-seen flows in one sweep (amortized O(1) per
                                                 // insert). Stream u32 indices are never reused, so evicted indices stay invalid.
pub(crate) const MAX_STREAMS: usize = 1024;
pub(crate) const STREAM_EVICT_BATCH: usize = 256;
/// Bytes all streams may hold between them: payloads, decrypted plaintext,
/// HTTP/3 buffers and per-segment overhead. The per-stream and stream-count
/// caps alone let a peer that opens enough flows fill 1280 × 2 MB, 2.5 GB.
/// Past the budget the least recently seen streams go, down to 7/8 of it, so
/// one sweep covers many packets.
const MAX_ALL_STREAMS_BYTES: usize = 256 * 1024 * 1024;
// `StreamTracker::charge` never evicts the stream it charges, so one flow's
// HTTP/3 buffers and bodies must fit well inside the budget.
const _: () = assert!(crate::dpi::http3::MAX_H3_FLOW_BYTES <= MAX_ALL_STREAMS_BYTES / 4);
const CAPTURE_SNAPLEN: i32 = 65535; // capture full frames (no truncation)
const CAPTURE_TIMEOUT_MS: i32 = 100; // pcap read timeout; controls batch latency
const CAPTURE_BATCH_SIZE: usize = 64; // packets processed per tick before yielding

// TCP control-bit masks (RFC 793)
pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_URG: u8 = 0x20;

#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub id: u64,
    pub timestamp: String,
    /// Original capture metadata; absent for synthetic or legacy packets.
    pub capture: Option<export::CaptureMetadata>,
    /// Frozen historical socket observation, never an export-time PID lookup.
    /// Boxed: most packets never get one, and the ring holds thousands.
    pub annotation: Option<Box<export::PacketAnnotation>>,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_host: Option<String>,
    pub dst_host: Option<String>,
    pub protocol: String,
    pub length: u32,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub info: String,
    pub details: Vec<String>,
    pub payload_text: String,
    pub raw_hex: String,
    pub raw_ascii: String,
    pub raw_bytes: Vec<u8>,
    pub stream_index: Option<u32>,
    pub tcp_flags: Option<u8>,
    /// Sequence number from the TCP header, if this packet is TCP.
    /// Used for retransmit / out-of-order classification in
    /// `StreamTracker::track_packet`. `None` for non-TCP packets.
    pub tcp_seq: Option<u32>,
    pub expert: ExpertSeverity,
    pub timestamp_ns: u64,
    /// L7 protocol classified by `crate::dpi` for this packet's flow,
    /// snapshotted at capture time. Later packets on the same flow
    /// carry the most recent classification — including the SNI that
    /// only becomes available once the ClientHello has been
    /// reassembled across multiple QUIC Initials.
    pub app_protocol: Option<crate::dpi::AppProtocol>,
    /// Inner plaintext when this packet carried a TLS 1.3 Application
    /// Data record AND the stream's secrets were known at the time
    /// (configured `SSLKEYLOGFILE` + cooperating client). `None`
    /// otherwise — non-TLS, non-decrypted, or pre-handshake records.
    pub decrypted_plaintext: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpertSeverity {
    Chat,  // normal informational (SYN, DNS query)
    Note,  // noteworthy (FIN, DNS response)
    Warn,  // warning (zero window, ICMP unreachable)
    Error, // error (RST, DNS NXDOMAIN/SERVFAIL)
}

/// Offset-prefixed hex, sixteen bytes to the line.
pub fn hex_dump(raw: &[u8]) -> String {
    raw.chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            format!("{:04x}  {}", i * 16, hex.join(" "))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The same bytes as printable characters, aligned with [`hex_dump`].
pub fn ascii_dump(raw: &[u8]) -> String {
    raw.chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let ascii: String = chunk
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("{:04x}  {}", i * 16, ascii)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn classify_expert(protocol: &str, info: &str, tcp_flags: Option<u8>) -> ExpertSeverity {
    // TCP RST → Error
    if let Some(flags) = tcp_flags {
        if flags & TCP_FLAG_RST != 0 {
            return ExpertSeverity::Error;
        }
        // SYN (without ACK) → Chat (connection initiation)
        if flags & TCP_FLAG_SYN != 0 && flags & TCP_FLAG_ACK == 0 {
            return ExpertSeverity::Chat;
        }
        // FIN → Note (connection teardown)
        if flags & TCP_FLAG_FIN != 0 {
            return ExpertSeverity::Note;
        }
    }

    // DNS errors
    if protocol == "DNS" {
        if info.contains("NXDOMAIN") || info.contains("Server Failure") || info.contains("Refused")
        {
            return ExpertSeverity::Error;
        }
        if info.contains("Format Error") {
            return ExpertSeverity::Warn;
        }
        if info.contains("Response") {
            return ExpertSeverity::Note;
        }
        // DNS query
        return ExpertSeverity::Chat;
    }

    // ICMP errors
    if protocol == "ICMP" || protocol == "ICMPv6" {
        if info.contains("Unreachable") || info.contains("Time Exceeded") {
            return ExpertSeverity::Warn;
        }
        if info.contains("Redirect") {
            return ExpertSeverity::Note;
        }
    }

    // ARP
    if protocol == "ARP" {
        return ExpertSeverity::Chat;
    }

    // TCP zero window in info string
    if info.contains("Win=0 ") || info.contains("Win=0,") {
        return ExpertSeverity::Warn;
    }

    // TLS
    if protocol == "TLS" {
        if info.contains("Client Hello") {
            return ExpertSeverity::Chat;
        }
        if info.contains("Server Hello") {
            return ExpertSeverity::Note;
        }
    }

    // HTTP errors
    if protocol == "HTTP"
        && (info.contains("HTTP/1.1 4")
            || info.contains("HTTP/1.1 5")
            || info.contains("HTTP/1.0 4")
            || info.contains("HTTP/1.0 5"))
    {
        return ExpertSeverity::Warn;
    }

    ExpertSeverity::Chat
}

mod dns_cache;
pub use dns_cache::DnsCache;

// ── Stream tracking ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct StreamKey {
    pub protocol: StreamProtocol,
    pub addr_a: (String, u16),
    pub addr_b: (String, u16),
}

impl StreamKey {
    pub fn new(protocol: StreamProtocol, ip1: &str, port1: u16, ip2: &str, port2: u16) -> Self {
        let a = (ip1.to_string(), port1);
        let b = (ip2.to_string(), port2);
        if a <= b {
            Self {
                protocol,
                addr_a: a,
                addr_b: b,
            }
        } else {
            Self {
                protocol,
                addr_a: b,
                addr_b: a,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    AtoB,
    BtoA,
}

impl Stream {
    /// A stream with no packets in it yet.
    ///
    /// This was an inline struct literal in the tracker, which meant the only
    /// way to get a `Stream` was to run a live capture — so nothing that
    /// consumes one could be tested. The private bookkeeping fields are the
    /// reason it has to live here rather than in the caller.
    pub fn new(index: u32, key: StreamKey, first_seen_ns: u64) -> Self {
        Self {
            index,
            key,
            segments: Vec::new(),
            total_bytes_a_to_b: 0,
            total_bytes_b_to_a: 0,
            packet_count: 0,
            initiator: None,
            total_payload_bytes: 0,
            handshake: None,
            last_seen_ns: first_seen_ns,
            initial_syn_seq: None,
            closed: false,
            app_protocol: None,
            app_protocol_attempted: false,
            quic_crypto_buf: Vec::new(),
            quic_client_random: None,
            quic_decrypt: QuicDecryptState::default(),
            held_bytes: 0,
            highest_seq_a_to_b: None,
            highest_seq_b_to_a: None,
            retransmits_a_to_b: 0,
            retransmits_b_to_a: 0,
            out_of_order_a_to_b: 0,
            out_of_order_b_to_a: 0,
            tls_client_random: None,
            tls_cipher_suite: None,
            tls_server_random: None,
            tls_decrypt_disabled: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StreamSegment {
    #[allow(dead_code)]
    pub packet_id: u64,
    #[allow(dead_code)]
    pub timestamp: String,
    pub direction: StreamDirection,
    pub payload: Vec<u8>,
    /// Decrypted inner plaintext for this segment's TLS/QUIC application-data
    /// records, attached after decryption. `None` for raw (handshake, non-TLS,
    /// or undecryptable) segments. Lets the stream view "follow" the decrypted
    /// conversation instead of the encrypted wire bytes.
    pub decrypted: Option<Vec<u8>>,
}

impl StreamSegment {
    /// What this segment costs against [`MAX_ALL_STREAMS_BYTES`]. The fixed
    /// part counts too, or a flood of one-byte segments would look free.
    fn held_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.timestamp.len()
            + self.payload.len()
            + self.decrypted.as_ref().map_or(0, Vec::len)
    }
}

#[derive(Debug, Clone)]
pub struct TcpHandshake {
    pub syn_ns: u64,
    pub syn_ack_ns: Option<u64>,
    pub ack_ns: Option<u64>,
}

impl TcpHandshake {
    pub fn syn_to_syn_ack_ms(&self) -> Option<f64> {
        self.syn_ack_ns
            .map(|sa| (sa.saturating_sub(self.syn_ns)) as f64 / 1_000_000.0)
    }

    pub fn syn_ack_to_ack_ms(&self) -> Option<f64> {
        match (self.syn_ack_ns, self.ack_ns) {
            (Some(sa), Some(a)) => Some((a.saturating_sub(sa)) as f64 / 1_000_000.0),
            _ => None,
        }
    }

    pub fn total_ms(&self) -> Option<f64> {
        self.ack_ns
            .map(|a| (a.saturating_sub(self.syn_ns)) as f64 / 1_000_000.0)
    }
}

/// Per-flow QUIC 1-RTT decryption state. The cipher suite and the
/// Destination-CID length aren't on the wire for short headers, so we
/// brute-force them once (AEAD auth is the oracle) and cache the result;
/// `largest_pn` per direction drives truncated packet-number reconstruction.
#[derive(Debug, Clone, Default)]
pub struct QuicDecryptState {
    /// Negotiated suite, discovered by trial. `None` until first success.
    pub suite: Option<crate::dpi::tls_decrypt::CipherSuite>,
    /// DCID length for client→server / server→client short headers
    /// (can differ per direction). `None` until discovered.
    pub dcid_len_c2s: Option<u8>,
    pub dcid_len_s2c: Option<u8>,
    pub largest_pn_c2s: u64,
    pub largest_pn_s2c: u64,
    /// Set once we've concluded this flow can't be decrypted (no
    /// ClientHello, or a full suite×dcid search failed with the secret
    /// present — e.g. unsupported QUIC v2 1-RTT).
    pub disabled: bool,
}

#[derive(Debug, Clone)]
pub struct Stream {
    #[allow(dead_code)]
    pub index: u32,
    pub key: StreamKey,
    /// Shared, so a clone of the stream (the UI takes one per frame) copies
    /// pointers rather than every payload.
    pub segments: Vec<Arc<StreamSegment>>,
    pub total_bytes_a_to_b: u64,
    pub total_bytes_b_to_a: u64,
    pub packet_count: u32,
    pub initiator: Option<(String, u16)>,
    total_payload_bytes: usize,
    pub handshake: Option<TcpHandshake>,
    /// L7 protocol classified by `crate::dpi` on the first non-trivial
    /// payload. Cached for the lifetime of the stream.
    pub app_protocol: Option<crate::dpi::AppProtocol>,
    /// True once classification has succeeded *or* given up for this
    /// stream. Prevents repeat work after we've settled on an answer.
    pub app_protocol_attempted: bool,
    /// Reassembly buffer for QUIC CRYPTO frames across multiple
    /// Initial packets. Chrome-class ClientHellos commonly fragment;
    /// without buffering across packets we miss the SNI extension
    /// whenever it lands in fragment 2+. Capped at MAX_QUIC_CRYPTO_BUF
    /// bytes; reset to empty once we've extracted the SNI.
    quic_crypto_buf: Vec<u8>,
    /// ClientHello random from this QUIC connection's reassembled CRYPTO
    /// frames — the key into the SSLKEYLOGFILE keystore for the flow's
    /// 1-RTT secrets (QUIC 1-RTT decryption, Phase 2). `None` until the
    /// ClientHello is reassembled, and for non-QUIC flows.
    pub quic_client_random: Option<[u8; 32]>,
    /// QUIC 1-RTT decryption state (cipher suite, per-direction DCID length
    /// and largest packet number) discovered/tracked across the flow.
    pub quic_decrypt: QuicDecryptState,
    /// This stream's share of `StreamTracker::held_bytes`.
    held_bytes: usize,
    /// Monotonic ns timestamp of the last packet seen on this flow. Drives LRU
    /// eviction when the tracker exceeds MAX_STREAMS.
    last_seen_ns: u64,
    initial_syn_seq: Option<u32>,
    closed: bool,
    /// Highest TCP `seq + payload_len` seen in each direction, used to
    /// classify subsequent segments as retransmits / out-of-order.
    /// Updated with proper 32-bit wraparound handling (a segment whose
    /// `seq + len` is "less than" the high-water mark only by a small
    /// negative diff is treated as behind; a "less than" with a huge
    /// negative diff is the wraparound case and is treated as ahead).
    highest_seq_a_to_b: Option<u32>,
    highest_seq_b_to_a: Option<u32>,
    /// Count of TCP segments whose seq+len fell entirely behind the
    /// per-direction high-water mark — bytes the other side has
    /// effectively already received, being resent. Pure ACKs
    /// (payload_len == 0) are excluded so duplicate keep-alives don't
    /// inflate the count.
    pub retransmits_a_to_b: u32,
    pub retransmits_b_to_a: u32,
    /// Count of TCP segments whose seq jumped backwards by a small
    /// amount (within `OOO_WINDOW_BYTES` of the high-water mark) —
    /// network reorder rather than retransmission. Reported separately
    /// so operators can tell "the link is flapping" (high retx) from
    /// "packets arrive out of order but no resends" (high OOO).
    pub out_of_order_a_to_b: u32,
    pub out_of_order_b_to_a: u32,
    /// TLS 1.3 ClientHello random — captured when the first
    /// handshake record on this stream is observed. Used to look
    /// up secrets in the SSLKEYLOGFILE-backed `KeylogStore`.
    pub tls_client_random: Option<[u8; 32]>,
    /// Negotiated TLS cipher suite (raw u16 from ServerHello). The keylog
    /// provides AEAD secrets but not the chosen cipher, so we read it off
    /// the wire. Used by both the TLS 1.3 and TLS 1.2 decrypt paths.
    pub tls_cipher_suite: Option<u16>,
    /// TLS ServerHello random (32 bytes). Needed only by the TLS 1.2
    /// decrypt path, whose PRF seed is `server_random || client_random`;
    /// the TLS 1.3 path keys off the keylog traffic secrets and ignores
    /// it. Plaintext on the wire (sent before the cipher is activated).
    pub tls_server_random: Option<[u8; 32]>,
    /// Set once we've concluded this stream can *never* be decrypted —
    /// the ClientHello was missed (no `client_random`) or the cipher
    /// suite is outside our TLS 1.3 support set. A keylog miss does NOT
    /// set this: the watcher ingests secrets asynchronously, so we keep
    /// retrying derivation per record until the secret appears. Once
    /// keys are derived they live in `StreamTracker.tls_keys` (their
    /// `aead::LessSafeKey` isn't `Clone`, so they can't sit on the
    /// otherwise-Clone `Stream`).
    pub tls_decrypt_disabled: bool,
}

/// Boundary between "out-of-order" (small reorder window) and "retransmit"
/// (segment is far behind the high-water mark — the sender is resending
/// already-received bytes). Wireshark's heuristic is similar; 64 KB is a
/// conservative choice that covers most reorder cases without
/// double-counting bursts of retransmits.
const OOO_WINDOW_BYTES: u32 = 64 * 1024;

pub struct StreamTracker {
    streams: HashMap<StreamKey, u32>,
    /// Keyed by stable u32 index (also stored on `CapturedPacket.stream_index`).
    /// Index space is monotonic; evicted indices are never reused, so dangling
    /// references resolve to None rather than aliasing a different flow.
    pub all_streams: HashMap<u32, Stream>,
    next_index: u32,
    /// The capture session the indices count within, as packets' capture
    /// metadata names it. 2^32 flows use the indices up; the tracker then
    /// forgets every stream, starts again at 0 and takes a new session, so a
    /// session and an index still name one flow. `None` outside live capture.
    session: Option<Arc<str>>,
    /// Per-stream TLS 1.3 decryption state, keyed by stream index. Lives
    /// outside `Stream` because `aead::LessSafeKey` isn't `Clone`, and
    /// `Stream` needs to stay Clone for the public `get_stream` API.
    /// `None` for non-TLS streams or those where SSLKEYLOGFILE didn't
    /// yield matching secrets.
    pub tls_keys: HashMap<u32, TlsStreamKeys>,
    /// Shared keylog index (SSLKEYLOGFILE-backed). Empty / placeholder
    /// when decryption isn't configured. Wrapped in `Arc` so the
    /// background watcher thread and the capture loop share one map.
    pub keylog: std::sync::Arc<crate::dpi::tls_decrypt::KeylogStore>,
    /// Cross-packet HTTP/3 stream reassembly (Phase 3b), keyed by stream
    /// index: accumulates decrypted STREAM-frame data per HTTP/3 stream id so
    /// response bodies larger than one 1-RTT packet decode/decompress instead
    /// of truncating. Held here rather than on `Stream` so `get_stream`'s
    /// clone doesn't copy up to 64 buffered bodies.
    quic_h3: HashMap<u32, crate::dpi::http3::H3StreamReassembler>,
    /// Bytes held across all streams, against `byte_budget`.
    held_bytes: usize,
    /// [`MAX_ALL_STREAMS_BYTES`]; a field so tests can use a small one.
    byte_budget: usize,
}

/// Per-stream AEAD state for TLS application data, tagged by protocol
/// version (the key schedule and record framing differ). Held in
/// `StreamTracker.tls_keys` rather than on `Stream` because the underlying
/// `aead::LessSafeKey` isn't `Clone`.
pub enum TlsStreamKeys {
    V13 {
        client: crate::dpi::tls_decrypt::DirectionKeys,
        server: crate::dpi::tls_decrypt::DirectionKeys,
    },
    V12 {
        client: crate::dpi::tls_decrypt::Tls12DirectionKeys,
        server: crate::dpi::tls_decrypt::Tls12DirectionKeys,
    },
}

/// How many record sequence numbers `try_decrypt_tls_record` will search
/// forward when an expected decrypt fails. Lets a stream recover the
/// correct sequence after secrets arrived late (the keylog watcher race)
/// or after a record we couldn't reassemble, while bounding the wasted
/// AEAD attempts on handshake-secret records (which never authenticate
/// under the application keys).
const TLS_RESYNC_WINDOW: u64 = 16;

/// First 4 bytes of a `client_random` rendered as 8 hex chars.
/// Used to correlate trace-log lines between the keylog watcher
/// (which sees secrets indexed by client_random) and the capture
/// loop (which sees client_randoms on the wire).
fn hex_prefix(cr: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", cr[0], cr[1], cr[2], cr[3])
}

impl Default for StreamTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamTracker {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            all_streams: HashMap::new(),
            next_index: 0,
            session: None,
            tls_keys: HashMap::new(),
            keylog: crate::dpi::tls_decrypt::KeylogStore::new(),
            quic_h3: HashMap::new(),
            held_bytes: 0,
            byte_budget: MAX_ALL_STREAMS_BYTES,
        }
    }

    /// Forget a stream everywhere it is held. Indices stay invalid forever
    /// (never reused).
    fn remove_stream(&mut self, idx: u32) {
        if let Some(s) = self.all_streams.remove(&idx) {
            if self.streams.get(&s.key) == Some(&idx) {
                self.streams.remove(&s.key);
            }
            self.held_bytes = self.held_bytes.saturating_sub(s.held_bytes);
        }
        self.tls_keys.remove(&idx);
        self.quic_h3.remove(&idx);
    }

    /// Count `bytes` more held by stream `idx`, then enforce the budget.
    fn charge(&mut self, idx: u32, bytes: usize) {
        let Some(s) = self.all_streams.get_mut(&idx) else {
            return;
        };
        s.held_bytes += bytes;
        self.held_bytes += bytes;
        if self.held_bytes <= self.byte_budget {
            return;
        }
        // Over budget: drop the least recently seen streams that hold
        // anything, never the one being charged, down to 7/8 of the budget.
        let target = self.byte_budget - self.byte_budget / 8;
        let mut by_age: Vec<(u64, u32)> = self
            .all_streams
            .values()
            .filter(|s| s.index != idx && s.held_bytes > 0)
            .map(|s| (s.last_seen_ns, s.index))
            .collect();
        by_age.sort_unstable();
        for (_, old) in by_age {
            if self.held_bytes <= target {
                break;
            }
            self.remove_stream(old);
        }
    }

    /// The next unused stream index. When none is left, every stream is
    /// dropped and counting restarts at 0 under a new session. At the
    /// measured decode rate that takes about seven hours of new flows.
    fn allocate_index(&mut self) -> u32 {
        if let Some(next) = self.next_index.checked_add(1) {
            return std::mem::replace(&mut self.next_index, next);
        }
        self.clear();
        self.next_index = 1;
        if self.session.is_some() {
            self.session = Some(uuid::Uuid::new_v4().to_string().into());
        }
        tracing::warn!(target: "netwatch::capture", "stream indices exhausted; streams cleared and a new capture session started");
        0
    }

    /// Drop the LRU batch when over the high-water mark. Removes from both
    /// `streams` and `all_streams`. Indices stay invalid forever (never reused).
    fn evict_if_needed(&mut self) {
        if self.all_streams.len() <= MAX_STREAMS + STREAM_EVICT_BATCH {
            return;
        }
        let mut by_age: Vec<(u64, u32)> = self
            .all_streams
            .values()
            .map(|s| (s.last_seen_ns, s.index))
            .collect();
        // Tie-break by index so identical timestamps evict the older flow
        // (lower index) first; tuples sort lexicographically.
        by_age.sort_unstable();
        for &(_, idx) in by_age.iter().take(STREAM_EVICT_BATCH) {
            self.remove_stream(idx);
        }
    }

    pub fn track_packet(
        &mut self,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        protocol: StreamProtocol,
        payload: &[u8],
        packet_id: u64,
        timestamp: &str,
        tcp_flags: Option<u8>,
        tcp_seq: Option<u32>,
        timestamp_ns: u64,
    ) -> u32 {
        let key = StreamKey::new(protocol, src_ip, src_port, dst_ip, dst_port);

        // A new handshake or an idle UDP observation starts a new generation.
        // Same-sequence SYN retransmission stays in the original generation.
        let new_syn = tcp_flags.is_some_and(|f| f & 0x02 != 0 && f & 0x10 == 0);
        let replace = self
            .streams
            .get(&key)
            .and_then(|i| self.all_streams.get(i))
            .is_some_and(|s| {
                (new_syn && (s.closed || (s.packet_count > 0 && s.initial_syn_seq != tcp_seq)))
                    || (protocol == StreamProtocol::Udp
                        && timestamp_ns.saturating_sub(s.last_seen_ns) > 60_000_000_000)
            });
        if replace {
            if let Some(&old) = self.streams.get(&key) {
                self.remove_stream(old);
            }
        }
        let stream_index = if let Some(&idx) = self.streams.get(&key) {
            idx
        } else {
            let idx = self.allocate_index();
            self.streams.insert(key.clone(), idx);
            self.all_streams
                .insert(idx, Stream::new(idx, key.clone(), timestamp_ns));
            self.evict_if_needed();
            idx
        };

        let stream = match self.all_streams.get_mut(&stream_index) {
            Some(s) => s,
            // Race: stream was just evicted. Skip update; the next packet on
            // this flow will allocate a fresh index.
            None => return stream_index,
        };
        if new_syn {
            stream.initial_syn_seq = tcp_seq;
        }
        if tcp_flags.is_some_and(|f| f & 0x05 != 0) {
            stream.closed = true;
        }
        stream.last_seen_ns = timestamp_ns;
        stream.packet_count += 1;

        let is_a_to_b = key.addr_a == (src_ip.to_string(), src_port);
        let direction = if is_a_to_b {
            StreamDirection::AtoB
        } else {
            StreamDirection::BtoA
        };

        if stream.initiator.is_none() {
            if let Some(flags) = tcp_flags {
                if flags & TCP_FLAG_SYN != 0 {
                    stream.initiator = Some((src_ip.to_string(), src_port));
                }
            }
            if stream.initiator.is_none() {
                stream.initiator = Some((src_ip.to_string(), src_port));
            }
        }

        // Track TCP handshake timing
        if protocol == StreamProtocol::Tcp {
            if let Some(flags) = tcp_flags {
                let is_syn = flags & TCP_FLAG_SYN != 0;
                let is_ack = flags & TCP_FLAG_ACK != 0;
                if is_syn && !is_ack {
                    // SYN — start of handshake
                    if stream.handshake.is_none() {
                        stream.handshake = Some(TcpHandshake {
                            syn_ns: timestamp_ns,
                            syn_ack_ns: None,
                            ack_ns: None,
                        });
                    }
                } else if is_syn && is_ack {
                    // SYN-ACK
                    if let Some(ref mut hs) = stream.handshake {
                        if hs.syn_ack_ns.is_none() {
                            hs.syn_ack_ns = Some(timestamp_ns);
                        }
                    }
                } else if is_ack && !is_syn && stream.packet_count <= 3 {
                    // ACK (completing handshake — only if early in connection)
                    if let Some(ref mut hs) = stream.handshake {
                        if hs.syn_ack_ns.is_some() && hs.ack_ns.is_none() {
                            hs.ack_ns = Some(timestamp_ns);
                        }
                    }
                }
            }
        }

        if is_a_to_b {
            stream.total_bytes_a_to_b += payload.len() as u64;
        } else {
            stream.total_bytes_b_to_a += payload.len() as u64;
        }

        // TCP retransmit / out-of-order detection. Skip pure ACKs
        // (payload_len == 0) — those are normal, frequent, and would
        // dominate the count if included. Use 32-bit signed wraparound
        // arithmetic so flows that exceed 2 GB in a direction (~30 s
        // at gigabit) are still classified correctly.
        if protocol == StreamProtocol::Tcp && !payload.is_empty() {
            if let Some(seq) = tcp_seq {
                let payload_len = payload.len() as u32;
                let seq_end = seq.wrapping_add(payload_len);

                let highest = if is_a_to_b {
                    &mut stream.highest_seq_a_to_b
                } else {
                    &mut stream.highest_seq_b_to_a
                };
                let (retx, ooo) = if is_a_to_b {
                    (
                        &mut stream.retransmits_a_to_b,
                        &mut stream.out_of_order_a_to_b,
                    )
                } else {
                    (
                        &mut stream.retransmits_b_to_a,
                        &mut stream.out_of_order_b_to_a,
                    )
                };

                match *highest {
                    None => *highest = Some(seq_end),
                    Some(h) => {
                        // Signed diff is positive iff seq_end is "ahead" of h
                        // in TCP-sequence-space (handles 32-bit wraparound).
                        let diff = seq_end.wrapping_sub(h) as i32;
                        if diff > 0 {
                            *highest = Some(seq_end);
                        } else {
                            // seq_end <= h ⇒ bytes already covered.
                            // Distinguish OOO from retransmit by how far
                            // behind we are: small backwards jump = network
                            // reorder; large = sender resending acked bytes.
                            let behind = h.wrapping_sub(seq_end);
                            if behind <= OOO_WINDOW_BYTES {
                                *ooo = ooo.saturating_add(1);
                            } else {
                                *retx = retx.saturating_add(1);
                            }
                        }
                    }
                }
            }
        }

        // DPI classification.
        //
        // Two paths:
        // - TCP and "first payload on UDP" → stateless `classify_once`.
        //   This covers TLS / HTTP / DNS / SSH and the single-Initial
        //   QUIC case.
        // - UDP + QUIC Initial (any time on the flow) → also merge any
        //   CRYPTO-frame fragments into the per-stream buffer and
        //   retry SNI extraction. Handles Chrome-class ClientHellos
        //   that span multiple Initials.
        const MAX_CLASSIFY_BYTES: usize = 4096;
        const MAX_QUIC_CRYPTO_BUF: usize = 16 * 1024;
        let is_tcp = matches!(protocol, StreamProtocol::Tcp);

        if !stream.app_protocol_attempted && payload.len() >= 16 {
            let slice = &payload[..payload.len().min(MAX_CLASSIFY_BYTES)];
            stream.app_protocol = crate::dpi::classify_once(slice, is_tcp, src_port, dst_port);
            // Settle the flag only on a confident answer. A bare
            // `Quic { sni: None }` means "we know this is QUIC but
            // haven't extracted the hostname yet" — keep trying on
            // subsequent Initial packets.
            stream.app_protocol_attempted = match stream.app_protocol {
                Some(crate::dpi::AppProtocol::Quic { sni: None, .. }) => false,
                Some(_) => true,
                None => true,
            };
        }

        // TLS decryption (1.3 and 1.2): opportunistically capture
        // client_random from any ClientHello we see, and cipher_suite +
        // server_random from any ServerHello. All are plaintext at the
        // record layer (handshakes start unencrypted in both versions).
        // They can land on the same flow but on different packets, so we
        // check on every handshake payload until they're populated.
        if is_tcp && !payload.is_empty() && payload[0] == 0x16 {
            if stream.tls_client_random.is_none() {
                let extracted = crate::dpi::tls::extract_client_random(payload);
                if let Some(cr) = extracted {
                    tracing::trace!(
                        target: "netwatch::dpi::tls_decrypt",
                        stream_index = stream_index,
                        cr_prefix = %format!("{:02x}{:02x}{:02x}{:02x}", cr[0], cr[1], cr[2], cr[3]),
                        "captured client_random from ClientHello"
                    );
                }
                stream.tls_client_random = extracted;
            }
            if stream.tls_cipher_suite.is_none() {
                let extracted = crate::dpi::tls::extract_server_hello_cipher_suite(payload);
                if let Some(cs) = extracted {
                    tracing::trace!(
                        target: "netwatch::dpi::tls_decrypt",
                        stream_index = stream_index,
                        cipher_suite = %format!("0x{:04x}", cs),
                        "captured cipher_suite from ServerHello"
                    );
                }
                stream.tls_cipher_suite = extracted;
            }
            if stream.tls_server_random.is_none() {
                // Only consumed by the TLS 1.2 path; harmless to capture
                // for 1.3 flows (their decrypt path ignores it).
                stream.tls_server_random = crate::dpi::tls::extract_server_hello_random(payload);
            }
        }

        // Cross-packet QUIC CRYPTO reassembly. Runs while we still
        // haven't extracted a hostname for this stream.
        if !is_tcp
            && !matches!(
                stream.app_protocol,
                Some(crate::dpi::AppProtocol::Quic { sni: Some(_), .. })
            )
            && stream.quic_crypto_buf.len() < MAX_QUIC_CRYPTO_BUF
            && payload.len() >= 16
        {
            if let Some(fragments) = crate::dpi::quic::extract_initial_crypto_frames(payload) {
                for (offset, data) in fragments {
                    let end = (offset as usize).saturating_add(data.len());
                    if end > MAX_QUIC_CRYPTO_BUF {
                        continue;
                    }
                    if stream.quic_crypto_buf.len() < end {
                        stream.quic_crypto_buf.resize(end, 0);
                    }
                    stream.quic_crypto_buf[offset as usize..end].copy_from_slice(&data);
                }
                let meta = crate::dpi::tls::extract_handshake_metadata(&stream.quic_crypto_buf);
                // Capture client_random for QUIC 1-RTT decryption (Phase 2)
                // before the buffer is released on SNI success below. The
                // ClientHello random keys this flow into the SSLKEYLOGFILE.
                if stream.quic_client_random.is_none() {
                    if let Some(cr) = meta.client_random {
                        stream.quic_client_random = Some(cr);
                        tracing::trace!(
                            target: "netwatch::dpi::quic",
                            cr_prefix = %hex_prefix(&cr),
                            "captured QUIC client_random from reassembled ClientHello"
                        );
                    }
                }
                if let Some(host) = meta.sni {
                    tracing::trace!(
                        target: "netwatch::dpi::quic",
                        host = %host,
                        ech = meta.ech,
                        ja4 = ?meta.ja4,
                        buf_len = stream.quic_crypto_buf.len(),
                        "SNI extracted after cross-packet reassembly"
                    );
                    stream.app_protocol = Some(crate::dpi::AppProtocol::Quic {
                        sni: Some(host),
                        ech: meta.ech,
                        ja4: meta.ja4,
                    });
                    stream.app_protocol_attempted = true;
                    // Release the buffer; we have what we need.
                    stream.quic_crypto_buf = Vec::new();
                } else {
                    tracing::trace!(
                        target: "netwatch::dpi::quic",
                        buf_len = stream.quic_crypto_buf.len(),
                        "reassembled buf still missing SNI — waiting for more Initials"
                    );
                    if stream.app_protocol.is_none() {
                        // At least tag it as QUIC even before full SNI.
                        stream.app_protocol = Some(crate::dpi::AppProtocol::Quic {
                            sni: None,
                            ech: false,
                            ja4: None,
                        });
                    }
                }
            }
        }

        if !payload.is_empty()
            && stream.segments.len() < MAX_STREAM_SEGMENTS
            && stream.total_payload_bytes < MAX_STREAM_BYTES
        {
            stream.total_payload_bytes += payload.len();
            let segment = StreamSegment {
                packet_id,
                timestamp: timestamp.to_string(),
                direction,
                payload: payload.to_vec(),
                decrypted: None,
            };
            let cost = segment.held_bytes();
            stream.segments.push(Arc::new(segment));
            self.charge(stream_index, cost);
        }

        stream_index
    }

    pub fn get_stream(&self, index: u32) -> Option<&Stream> {
        self.all_streams.get(&index)
    }

    /// Attach decrypted plaintext to the stream segment for `packet_id` so the
    /// stream view can render the decrypted conversation. Called right after a
    /// successful decrypt, while the tracker lock is still held; the matching
    /// segment is normally the most recent, so we search from the end.
    pub fn attach_segment_decrypted(
        &mut self,
        stream_index: u32,
        packet_id: u64,
        plaintext: Vec<u8>,
    ) {
        let mut grown = 0;
        if let Some(stream) = self.all_streams.get_mut(&stream_index) {
            if let Some(seg) = stream
                .segments
                .iter_mut()
                .rev()
                .find(|s| s.packet_id == packet_id)
            {
                let added = plaintext.len();
                let replaced = Arc::make_mut(seg).decrypted.replace(plaintext);
                grown = added.saturating_sub(replaced.map_or(0, |p| p.len()));
            }
        }
        self.charge(stream_index, grown);
    }

    /// Attempt to decrypt a TLS 1.3 Application Data record carried by
    /// `payload` (the raw TCP segment payload). Returns the inner
    /// plaintext if all of:
    /// - `payload` starts with a TLS Application Data record header
    ///   (`type=0x17`, `version=0x03??`, with the full record present)
    /// - The stream's `client_random` and `cipher_suite` have been
    ///   observed (ClientHello + ServerHello already processed)
    /// - The configured SSLKEYLOGFILE has matching application-traffic
    ///   secrets for this `client_random`
    ///
    /// Derives per-direction AEAD keys lazily once the keylog yields
    /// this connection's secrets, then stores them in `tls_keys` for
    /// subsequent records on the same flow. Returns `None` (not an
    /// error) for any non-matching input — non-TLS traffic,
    /// pre-handshake records, missing keys, etc.
    ///
    /// ## Retry vs. give-up
    ///
    /// A keylog *miss* is **retryable**, not fatal: the background
    /// watcher polls the SSLKEYLOGFILE asynchronously, so the first few
    /// application-data records on a flow routinely arrive before the
    /// secret has been ingested. We therefore re-attempt key derivation
    /// on every record until it succeeds, and use
    /// [`DirectionKeys::decrypt_record_resync`] so a stream whose
    /// secrets landed late still locks onto the correct record sequence
    /// and decrypts the remainder. We permanently disable a stream
    /// (`tls_decrypt_disabled`) only for conditions that can never
    /// recover: a missing `client_random` (we joined mid-connection and
    /// never saw the ClientHello) or a cipher suite outside our TLS 1.3
    /// support set.
    pub fn try_decrypt_tls_record(
        &mut self,
        stream_index: u32,
        payload: &[u8],
        client_to_server: bool,
    ) -> Option<Vec<u8>> {
        // Sanity: TLS Application Data record header is 5 bytes.
        if payload.len() < 5 || payload[0] != 0x17 || payload[1] != 0x03 {
            return None;
        }
        let length = u16::from_be_bytes([payload[3], payload[4]]) as usize;
        if payload.len() < 5 + length {
            // Record spans multiple TCP segments — Phase 1 does not
            // handle cross-segment reassembly. `decrypt_record_resync`
            // lets a later record re-sync the sequence after this gap.
            return None;
        }
        let aad = &payload[..5];
        let ciphertext_src = &payload[5..5 + length];

        // Lazy-derive AEAD keys once the keylog has this flow's secrets. The
        // TLS version is inferred from which secret the keylog holds for this
        // client_random: a `*_TRAFFIC_SECRET_0` pair ⇒ 1.3, a `CLIENT_RANDOM`
        // master secret ⇒ 1.2. We can't tell from the wire alone — both carry
        // application data as outer type 0x17 with record version 0x0303.
        if !self.tls_keys.contains_key(&stream_index) {
            // Pull the handshake-derived inputs off the stream. Latch off
            // streams that can never be decrypted; leave retryable ones be.
            let (cr, cs_raw, server_random) = {
                let stream = self.all_streams.get_mut(&stream_index)?;
                if stream.tls_decrypt_disabled {
                    return None;
                }
                let Some(cr) = stream.tls_client_random else {
                    // Application data but no ClientHello was ever seen —
                    // capture started mid-connection. Unrecoverable.
                    stream.tls_decrypt_disabled = true;
                    tracing::trace!(target: "netwatch::dpi::tls_decrypt", stream_index, "disable: no client_random (missed ClientHello)");
                    return None;
                };
                let Some(cs_raw) = stream.tls_cipher_suite else {
                    // ServerHello not parsed yet — retry on a later record.
                    tracing::trace!(target: "netwatch::dpi::tls_decrypt", stream_index, cr_prefix=%hex_prefix(&cr), "retry: cipher_suite not observed yet");
                    return None;
                };
                (cr, cs_raw, stream.tls_server_random)
            };

            // A keylog miss (or a half-written entry) is retryable — the
            // watcher may not have ingested the secret yet. Do NOT latch.
            let secrets = self.keylog.lookup(&cr)?;

            let derived = if let (Some(client_app), Some(server_app)) = (
                secrets.client_application.as_ref(),
                secrets.server_application.as_ref(),
            ) {
                // TLS 1.3 — key off the application traffic secrets.
                let Some(suite) = crate::dpi::tls_decrypt::CipherSuite::from_wire(cs_raw) else {
                    self.disable_tls_stream(stream_index);
                    tracing::trace!(target: "netwatch::dpi::tls_decrypt", stream_index, cs=%format!("0x{:04x}", cs_raw), "disable: cipher_suite not in TLS 1.3 support list");
                    return None;
                };
                let client =
                    crate::dpi::tls_decrypt::DirectionKeys::from_traffic_secret(suite, client_app);
                let server =
                    crate::dpi::tls_decrypt::DirectionKeys::from_traffic_secret(suite, server_app);
                TlsStreamKeys::V13 { client, server }
            } else if let Some(master) = secrets.master_secret.as_ref() {
                // TLS 1.2 — derive the key block from the master secret. Needs
                // the server_random (PRF seed); retry until the ServerHello is
                // parsed.
                let Some(suite) = crate::dpi::tls_decrypt::Tls12Suite::from_wire(cs_raw) else {
                    self.disable_tls_stream(stream_index);
                    tracing::trace!(target: "netwatch::dpi::tls_decrypt", stream_index, cs=%format!("0x{:04x}", cs_raw), "disable: TLS 1.2 cipher suite not an AEAD suite we support");
                    return None;
                };
                let Some(sr) = server_random else {
                    tracing::trace!(target: "netwatch::dpi::tls_decrypt", stream_index, cr_prefix=%hex_prefix(&cr), "retry: server_random not observed yet");
                    return None;
                };
                let (client, server) =
                    crate::dpi::tls_decrypt::Tls12DirectionKeys::derive(suite, master, &cr, &sr);
                TlsStreamKeys::V12 { client, server }
            } else {
                tracing::trace!(target: "netwatch::dpi::tls_decrypt", stream_index, cr_prefix=%hex_prefix(&cr), "retry: keylog hit but secrets incomplete");
                return None;
            };
            tracing::debug!(target: "netwatch::dpi::tls_decrypt", stream_index, cr_prefix=%hex_prefix(&cr), "derived AEAD keys — decryption ready");
            self.tls_keys.insert(stream_index, derived);
        }

        match self.tls_keys.get_mut(&stream_index)? {
            TlsStreamKeys::V13 { client, server } => {
                let dir = if client_to_server { client } else { server };
                match dir.decrypt_record_resync(aad, ciphertext_src, TLS_RESYNC_WINDOW) {
                    Ok(inner) => {
                        tracing::trace!(target: "netwatch::dpi::tls_decrypt", stream_index, client_to_server, plain_len=inner.content.len(), inner_type=inner.content_type, "decrypted record (1.3)");
                        // A TLS 1.3 KeyUpdate (handshake type 24, RFC 8446 §4.6.3)
                        // is the last record under the current key; the sender then
                        // rekeys its sending direction. Derive generation N+1 so the
                        // records that follow keep decrypting (this is where long
                        // sessions otherwise "fell off the rails").
                        if inner.content_type == 22 && inner.content.first() == Some(&24) {
                            dir.advance_generation();
                            tracing::debug!(target: "netwatch::dpi::tls_decrypt", stream_index, client_to_server, "TLS KeyUpdate — advanced to next key generation");
                        }
                        // Only surface application_data (type 23) as decrypted
                        // plaintext. Post-handshake handshake messages
                        // (NewSessionTicket, type 22) and alerts (21) decrypt fine
                        // but are binary control records, not the conversation —
                        // dropping them keeps the detail pane and the "follow
                        // decrypted stream" view clean. The record's sequence was
                        // already advanced inside decrypt_record_resync, so
                        // returning None here does not desync the stream.
                        if inner.content_type == 23 {
                            Some(inner.content)
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        // Expected for handshake-secret records carried with outer
                        // type 0x17 (EncryptedExtensions, Certificate, Finished),
                        // which won't authenticate under the application keys.
                        tracing::trace!(target: "netwatch::dpi::tls_decrypt", stream_index, client_to_server, error=?e, "decrypt miss (handshake record or sequence gap beyond window)");
                        None
                    }
                }
            }
            TlsStreamKeys::V12 { client, server } => {
                let dir = if client_to_server { client } else { server };
                // In TLS 1.2 the outer record content type is the real type, so
                // an application_data (0x17) record decrypts directly to the
                // cleartext — no inner content-type byte to strip, and no
                // KeyUpdate mechanism to track.
                let content_type = payload[0];
                let version = [payload[1], payload[2]];
                match dir.decrypt_record_resync(
                    content_type,
                    version,
                    ciphertext_src,
                    TLS_RESYNC_WINDOW,
                ) {
                    Ok(plaintext) => {
                        tracing::trace!(target: "netwatch::dpi::tls_decrypt", stream_index, client_to_server, plain_len=plaintext.len(), "decrypted record (1.2)");
                        Some(plaintext)
                    }
                    Err(e) => {
                        // Expected for the encrypted Finished / NewSessionTicket
                        // records (outer type 0x16, not reaching here) and for
                        // sequence gaps beyond the resync window.
                        tracing::trace!(target: "netwatch::dpi::tls_decrypt", stream_index, client_to_server, error=?e, "decrypt miss (1.2 — sequence gap beyond window)");
                        None
                    }
                }
            }
        }
    }

    /// Latch a stream as permanently undecryptable. Used when we have the
    /// keylog secret but the negotiated cipher suite is outside our support
    /// set (e.g. a TLS 1.2 CBC suite) — retrying can never succeed.
    fn disable_tls_stream(&mut self, stream_index: u32) {
        if let Some(s) = self.all_streams.get_mut(&stream_index) {
            s.tls_decrypt_disabled = true;
        }
    }

    /// Attempt to decrypt a QUIC 1-RTT (short-header) packet in this UDP
    /// datagram. Succeeds when the flow's ClientHello was seen (so we have a
    /// `client_random`), the keylog holds its `*_TRAFFIC_SECRET_0`, and some
    /// (cipher suite, DCID length) combination authenticates. Suite + DCID
    /// length aren't on the wire for short headers, so the first packet
    /// brute-forces them (AEAD auth is the oracle) and caches the result;
    /// `largest_pn` is tracked per direction for pn reconstruction. Assumes
    /// QUIC v1 (v2 1-RTT and coalesced packets are not yet handled).
    pub fn try_decrypt_quic_1rtt(
        &mut self,
        stream_index: u32,
        payload: &[u8],
        client_to_server: bool,
    ) -> Option<Vec<u8>> {
        // Short header: fixed bit (0x40) set, long-header bit (0x80) clear.
        if payload.first().map(|b| b & 0xc0) != Some(0x40) {
            return None;
        }
        // Pull inputs without holding a borrow across the keylog lookup.
        let (cr, suite_cached, dcid_cached, largest_pn) = {
            let s = self.all_streams.get(&stream_index)?;
            if s.quic_decrypt.disabled {
                return None;
            }
            let cr = s.quic_client_random?;
            let dcid = if client_to_server {
                s.quic_decrypt.dcid_len_c2s
            } else {
                s.quic_decrypt.dcid_len_s2c
            };
            let lpn = if client_to_server {
                s.quic_decrypt.largest_pn_c2s
            } else {
                s.quic_decrypt.largest_pn_s2c
            };
            (cr, s.quic_decrypt.suite, dcid, lpn)
        };
        // Keylog miss is retryable (watcher may not have ingested yet) — do
        // not disable on it.
        let secrets = self.keylog.lookup(&cr)?;
        let secret = if client_to_server {
            secrets.client_application
        } else {
            secrets.server_application
        }?;

        use crate::dpi::tls_decrypt::CipherSuite;
        let suites: Vec<CipherSuite> = match suite_cached {
            Some(su) => vec![su],
            None => vec![
                CipherSuite::Aes128GcmSha256,
                CipherSuite::Aes256GcmSha384,
                CipherSuite::Chacha20Poly1305Sha256,
            ],
        };
        let dcid_lens: Vec<usize> = match dcid_cached {
            Some(d) => vec![d as usize],
            None => (0..=20usize).collect(),
        };

        for &suite in &suites {
            for &dcid_len in &dcid_lens {
                if let Ok((pn, plain)) = crate::dpi::quic::decrypt_1rtt_packet(
                    payload,
                    dcid_len,
                    &secret,
                    suite,
                    crate::dpi::quic::QuicVersion::V1,
                    largest_pn,
                ) {
                    if let Some(s) = self.all_streams.get_mut(&stream_index) {
                        s.quic_decrypt.suite = Some(suite);
                        if client_to_server {
                            s.quic_decrypt.dcid_len_c2s = Some(dcid_len as u8);
                            s.quic_decrypt.largest_pn_c2s = s.quic_decrypt.largest_pn_c2s.max(pn);
                        } else {
                            s.quic_decrypt.dcid_len_s2c = Some(dcid_len as u8);
                            s.quic_decrypt.largest_pn_s2c = s.quic_decrypt.largest_pn_s2c.max(pn);
                        }
                    }
                    self.ingest_h3(stream_index, client_to_server, &plain);
                    tracing::trace!(target: "netwatch::dpi::quic", stream_index, client_to_server, dcid_len, pn, plain_len = plain.len(), "decrypted QUIC 1-RTT packet");
                    return Some(plain);
                }
            }
        }
        // Secret present + ClientHello seen, but nothing authenticated across
        // the full suite×DCID search — likely QUIC v2 1-RTT (unsupported) or a
        // coalesced/odd packet. Give up to bound per-packet cost.
        if let Some(s) = self.all_streams.get_mut(&stream_index) {
            s.quic_decrypt.disabled = true;
        }
        tracing::trace!(target: "netwatch::dpi::quic", stream_index, "QUIC 1-RTT decrypt search failed; disabling flow");
        None
    }

    /// DPI snapshot: classified L7 protocol per stream key. Only flows
    /// where classification succeeded appear in the map. Cheap clone
    /// per tick; the per-connection joiner looks up by `StreamKey`.
    pub fn snapshot_app_protocols(&self) -> HashMap<StreamKey, crate::dpi::AppProtocol> {
        self.all_streams
            .values()
            .filter_map(|s| s.app_protocol.clone().map(|p| (s.key.clone(), p)))
            .collect()
    }

    /// Cumulative payload bytes per stream, keyed by canonical `StreamKey`.
    /// The tuple is `(bytes_a_to_b, bytes_b_to_a)` — direction relative to
    /// the key's canonical ordering, not the local side. Callers orient
    /// against the connection's own local address.
    pub fn snapshot_bytes(&self) -> HashMap<StreamKey, (u64, u64)> {
        self.all_streams
            .values()
            .map(|s| (s.key.clone(), (s.total_bytes_a_to_b, s.total_bytes_b_to_a)))
            .collect()
    }

    pub fn snapshot_generations(&self) -> HashMap<StreamKey, u32> {
        self.all_streams
            .values()
            .map(|s| (s.key.clone(), s.index))
            .collect()
    }

    /// Snapshot per-stream TCP anomaly counters (retransmits, out-of-order),
    /// summed across both directions. Used by the connection collector to
    /// attach a per-row count without holding the tracker lock through the
    /// connection render path. Values are `(retransmits, out_of_order)`.
    pub fn snapshot_anomalies(&self) -> HashMap<StreamKey, (u32, u32)> {
        self.all_streams
            .values()
            .filter_map(|s| {
                let retx = s.retransmits_a_to_b + s.retransmits_b_to_a;
                let ooo = s.out_of_order_a_to_b + s.out_of_order_b_to_a;
                if retx == 0 && ooo == 0 {
                    None
                } else {
                    Some((s.key.clone(), (retx, ooo)))
                }
            })
            .collect()
    }

    /// Per-stream TCP handshake RTT (SYN→SYN-ACK) in microseconds, for streams
    /// with a completed handshake. Keyed by `StreamKey` so the connection
    /// collector attaches a precise per-connection RTT via the same 5-tuple
    /// join it uses for app-protocol and anomaly enrichment.
    pub fn snapshot_handshake_rtts(&self) -> HashMap<StreamKey, f64> {
        self.all_streams
            .values()
            .filter_map(|s| {
                s.handshake
                    .as_ref()
                    .and_then(|hs| hs.syn_to_syn_ack_ms())
                    .map(|ms| (s.key.clone(), ms * 1000.0))
            })
            .collect()
    }

    /// Visit each stream that has a completed SYN→SYN-ACK handshake but has
    /// not yet been recorded in `sampled`, invoking `f(remote_ip, rtt_ms)`.
    /// Replaces the previous deep-clone-and-iterate pattern that allocated
    /// every payload byte on every tick. Also prunes evicted indices from
    /// `sampled` so the set stays bounded by current stream count.
    pub fn for_each_new_handshake_rtt<F: FnMut(&str, f64)>(
        &self,
        sampled: &mut std::collections::HashSet<u32>,
        mut f: F,
    ) {
        for s in self.all_streams.values() {
            if sampled.contains(&s.index) {
                continue;
            }
            if let Some(ref hs) = s.handshake {
                if let Some(rtt_ms) = hs.syn_to_syn_ack_ms() {
                    sampled.insert(s.index);
                    // Key by remote IP (addr_b is canonically the server side)
                    f(&s.key.addr_b.0, rtt_ms);
                }
            }
        }
        sampled.retain(|idx| self.all_streams.contains_key(idx));
    }

    /// Buffer one decrypted 1-RTT packet's frames for cross-packet HTTP/3
    /// reassembly (Phase 3b), charging what the buffers grew by. Decoding
    /// happens lazily in the UI.
    fn ingest_h3(&mut self, index: u32, client_to_server: bool, frames: &[u8]) {
        if !self.all_streams.contains_key(&index) {
            return;
        }
        let h3 = self.quic_h3.entry(index).or_default();
        let before = h3.held_bytes();
        h3.ingest(client_to_server, frames);
        let grown = h3.held_bytes().saturating_sub(before);
        self.charge(index, grown);
    }

    /// Reassembled HTTP/3 bodies for a flow. Decoding can grow what the
    /// stream holds, so it is charged like any other growth.
    pub fn quic_h3_bodies(&mut self, index: u32) -> Vec<crate::dpi::http3::DecodedBody> {
        let Some(h3) = self.quic_h3.get_mut(&index) else {
            return Vec::new();
        };
        let before = h3.held_bytes();
        let bodies = h3.decoded_bodies();
        let grown = h3.held_bytes().saturating_sub(before);
        self.charge(index, grown);
        bodies
    }

    pub fn clear(&mut self) {
        self.streams.clear();
        self.all_streams.clear();
        self.tls_keys.clear();
        self.quic_h3.clear();
        self.held_bytes = 0;
    }
}

/// What libpcap reports about the capture itself, as opposed to what the
/// capture contains.
///
/// A packet list with no drop counter beside it cannot be trusted: a filter
/// that appears to match nothing and a kernel buffer that overflowed look
/// identical on screen. `dropped` is the kernel buffer plus the driver — both
/// mean "packets existed that this screen never saw".
// libpcap's pcap_stats() counters (ps_recv/ps_drop/ps_ifdrop) are `u_int`,
// 32 bits on every platform pcap supports, and wrap after 2^32 packets,
// within the hour at 1.2M packets a second. Each poll adds the change since
// the last one to u64 totals. Those sit behind a Mutex rather than in an
// AtomicU64 because armv5te (old Kirkwood NAS boxes) has no native 64-bit
// atomics.
#[derive(Debug, Default)]
pub struct CaptureStats {
    totals: Mutex<CaptureTotals>,
    /// Packets per second over the last poll interval.
    rate_pps: AtomicU32,
    observed_at: Mutex<Option<std::time::Instant>>,
}

/// Counts since the capture started, as of the last poll.
#[derive(Debug, Default, Clone, Copy)]
struct CaptureTotals {
    received: u64,
    dropped: u64,
    /// Packets that reached the list. Taken at the poll rather than live, so
    /// it describes the same moment as the libpcap counts.
    decoded: u64,
}

impl CaptureStats {
    pub fn received(&self) -> u64 {
        self.totals().received
    }

    /// Kernel-buffer drops plus interface/driver drops.
    pub fn dropped(&self) -> u64 {
        self.totals().dropped
    }

    pub fn observed_drops(&self) -> Option<u64> {
        let at = (*self.observed_at.lock().ok()?)?;
        (at.elapsed() <= crate::collectors::attribution::MAX_MATCH_AGE).then(|| self.dropped())
    }
    pub fn rate_pps(&self) -> u64 {
        self.rate_pps.load(Ordering::Relaxed) as u64
    }

    fn totals(&self) -> CaptureTotals {
        *crate::app::safe_lock(&self.totals, "packets::stats")
    }

    /// Fold one `pcap_stats` reading into the totals. `last` is the previous
    /// reading, all zeroes when the capture starts, and becomes this one.
    /// `decoded` is how many packets the list has taken since the start.
    fn record_poll(&self, last: &mut pcap::Stat, reading: pcap::Stat, decoded: u64, elapsed: f64) {
        *crate::app::safe_lock(&self.observed_at, "packets::stats_poll") =
            Some(std::time::Instant::now());
        let received = counter_delta(last.received, reading.received);
        let dropped = counter_delta(last.dropped, reading.dropped)
            + counter_delta(last.if_dropped, reading.if_dropped);
        *last = reading;
        {
            let mut totals = crate::app::safe_lock(&self.totals, "packets::stats_poll");
            totals.received += received;
            totals.dropped += dropped;
            totals.decoded = decoded;
        }
        self.rate_pps.store(
            if elapsed > 0.0 {
                (received as f64 / elapsed).round() as u32
            } else {
                0
            },
            Ordering::Relaxed,
        );
    }

    /// Zeroed when a capture starts, so the numbers describe this run rather
    /// than accumulating across interface switches.
    fn reset(&self) {
        *crate::app::safe_lock(&self.totals, "packets::stats_reset") = CaptureTotals::default();
        self.rate_pps.store(0, Ordering::Relaxed);
        *crate::app::safe_lock(&self.observed_at, "packets::stats_reset") = None;
    }
}

/// How far one of libpcap's u32 counters moved between two polls, counting
/// across a wrap. pcap's counters are monotonic within a capture, but a
/// re-arm can move one backwards; a reading less than half the range below
/// the last is that, not 2^31 packets inside a poll, and counts nothing.
fn counter_delta(last: u32, now: u32) -> u64 {
    let delta = now.wrapping_sub(last);
    if delta > u32::MAX / 2 {
        0
    } else {
        u64::from(delta)
    }
}

/// Whether libpcap's open failed for want of privilege. Its wording differs
/// by platform: Linux names the missing capability, the BPF platforms report
/// the device's EACCES. The full message is still logged.
fn open_refused(message: &str) -> bool {
    [
        "Permission denied",
        "Operation not permitted",
        "CAP_NET_RAW",
        "don't have permission",
    ]
    .iter()
    .any(|m| message.contains(m))
}

/// Open/configure capture resources without reading or decoding traffic.
/// Called inside the worker for startup and every capture restart.
pub(crate) fn prepare_capture(
    interface: &str,
    bpf: Option<&str>,
) -> Result<pcap::Capture<pcap::Active>, String> {
    let iface = resolve_device_name(interface).map_err(|message| {
        tracing::error!(target: "netwatch::capture", %interface, error = %message, "device resolution failed");
        message
    })?;
    // Some interfaces do not support promiscuous mode; preserve the fallback.
    let cap = pcap::Capture::from_device(iface.as_str())
        .and_then(|c| c.promisc(true).snaplen(CAPTURE_SNAPLEN).timeout(CAPTURE_TIMEOUT_MS).open())
        .or_else(|_| pcap::Capture::from_device(iface.as_str())
            .and_then(|c| c.promisc(false).snaplen(CAPTURE_SNAPLEN).timeout(CAPTURE_TIMEOUT_MS).open()))
        .map_err(|error| {
            tracing::error!(target: "netwatch::capture", interface = %iface, %error, "pcap open failed");
            if open_refused(&error.to_string()) {
                format!("not permitted — {}", crate::platform::capture_fix())
            } else { format!("Capture failed: {error}") }
        })?;
    // Blocking reads can hang forever on idle TPACKET_V3 links (#41).
    // Set nonblocking mode before processing so cancellation stays responsive.
    let mut cap = cap.setnonblock().map_err(|error| {
        tracing::error!(target: "netwatch::capture", interface = %iface, %error, "pcap setnonblock failed");
        format!("Capture failed: {error}")
    })?;
    if let Some(filter) = bpf {
        cap.filter(filter, true).map_err(|error| {
            tracing::error!(target: "netwatch::capture", %filter, %error, "BPF filter compile/install failed");
            format!("BPF filter error: {error}")
        })?;
    }
    Ok(cap)
}

/// Run one frame's parsing and stream tracking, catching a panic in it.
///
/// Every parser here reads bytes a peer chose. A panic in one used to end the
/// capture thread silently: the list stopped growing while the header still
/// said capturing. It now stops this generation and leaves an error that the
/// Packets header and the capability report show. Returns false if `step`
/// panicked.
fn run_capture_step(
    capturing: &AtomicBool,
    error: &Mutex<Option<String>>,
    step: impl FnOnce(),
) -> bool {
    let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(step)) else {
        return true;
    };
    let message = panic
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".into());
    tracing::error!(target: "netwatch::capture", panic = %message, "capture step panicked; capture stopped");
    // A cancelled generation must not overwrite a newer start's error.
    if capturing.load(Ordering::SeqCst) {
        // Panic text can quote the packet bytes that caused it.
        *crate::app::safe_lock(error, "packets::capture_panic") = Some(format!(
            "Capture stopped: internal error: {}",
            crate::ui::sanitize::display(&message)
        ));
        capturing.store(false, Ordering::SeqCst);
    }
    false
}

pub struct PacketCollector {
    pub packets: Arc<RwLock<Vec<CapturedPacket>>>,
    pub capturing: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    /// Live capture health — drops and throughput, straight from `pcap_stats`.
    pub stats: Arc<CaptureStats>,
    pub error: Arc<Mutex<Option<String>>>,
    pub dns_cache: DnsCache,
    pub stream_tracker: Arc<Mutex<StreamTracker>>,
    counter: Arc<Mutex<u64>>,
    annotation_history: export::AnnotationHistory,
    handle: Option<thread::JoinHandle<()>>,
    /// Lives for the lifetime of the collector when a TLS keylog path
    /// is configured. Dropping it signals the background polling
    /// thread to stop and joins it.
    tls_keylog_watcher: Option<crate::dpi::tls_decrypt::WatcherHandle>,
}

impl Default for PacketCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketCollector {
    pub fn new() -> Self {
        Self {
            packets: Arc::new(RwLock::new(Vec::new())),
            capturing: Arc::new(AtomicBool::new(false)),
            ready: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(CaptureStats::default()),
            error: Arc::new(Mutex::new(None)),
            dns_cache: DnsCache::new(),
            stream_tracker: Arc::new(Mutex::new(StreamTracker::new())),
            counter: Arc::new(Mutex::new(0)),
            annotation_history: export::AnnotationHistory::default(),
            handle: None,
            tls_keylog_watcher: None,
        }
    }

    /// Start polling the configured SSLKEYLOGFILE for TLS 1.3 secrets.
    /// Idempotent — calling again with a new path replaces the watcher.
    /// Empty path / None drops any existing watcher (stops decryption).
    pub fn configure_tls_keylog(&mut self, path: Option<std::path::PathBuf>) {
        // Dropping the existing handle signals the prior thread to stop
        // before we spawn a new one.
        self.tls_keylog_watcher = None;
        let Some(p) = path else { return };
        // Share the StreamTracker's KeylogStore with the watcher so the
        // capture loop sees ingested secrets immediately.
        let store = {
            let t = crate::app::safe_lock(&self.stream_tracker, "packets::snapshot");
            std::sync::Arc::clone(&t.keylog)
        };
        tracing::info!(
            target: "netwatch::dpi::tls_decrypt",
            path = %p.display(),
            "starting TLS keylog watcher"
        );
        self.tls_keylog_watcher = Some(crate::dpi::tls_decrypt::spawn_keylog_watcher(p, store));
    }

    pub fn start_capture(&mut self, interface: &str, bpf_filter: Option<&str>) {
        self.dns_cache.start();
        // &mut self serializes starts. Never set an old generation's flag:
        // a detached worker may still hold it and must remain cancelled.
        if self.capturing.load(Ordering::SeqCst) {
            return;
        }
        self.annotation_history.clear();
        let mut session_ref: Arc<str> = uuid::Uuid::new_v4().to_string().into();
        crate::app::safe_lock(&self.stream_tracker, "packets::start_session").session =
            Some(Arc::clone(&session_ref));
        // Every generation owns its cancellation flag, including detached old workers.
        self.capturing = Arc::new(AtomicBool::new(true));
        self.ready = Arc::new(AtomicBool::new(false));
        let ready = Arc::clone(&self.ready);
        crate::sandbox::worker::begin("capture");
        *crate::app::safe_lock(&self.error, "packets::clear_error") = None;

        let packets = Arc::clone(&self.packets);
        let capturing = Arc::clone(&self.capturing);
        let error = Arc::clone(&self.error);
        let counter = Arc::clone(&self.counter);
        let tracker = Arc::clone(&self.stream_tracker);
        let dns = self.dns_cache.clone();
        let stats = Arc::clone(&self.stats);
        stats.reset();
        let interface = interface.to_string();
        let bpf = bpf_filter.map(|s| s.to_string());
        let interface_ref: Arc<str> = interface.as_str().into();

        self.handle = Some(thread::spawn(move || {
            // Resource preparation stays off the UI thread (device resolution
            // may invoke PowerShell). No packet is read during preparation.
            let mut cap = match prepare_capture(&interface, bpf.as_deref()) {
                Ok(cap) => cap,
                Err(message) => {
                    // A cancelled generation must not overwrite a newer start's error.
                    if !capturing.load(Ordering::SeqCst) {
                        return;
                    }
                    crate::sandbox::worker::fail("capture", message.clone());
                    *crate::app::safe_lock(&error, "packets::capture_prepare_error") =
                        Some(message);
                    capturing.store(false, Ordering::SeqCst);
                    return;
                }
            };
            if !capturing.load(Ordering::SeqCst) {
                return;
            }
            if !crate::sandbox::worker::enter("capture") {
                *crate::app::safe_lock(&error, "packets::confinement") =
                    Some("Capture stopped: worker confinement failed; see Settings".into());
                capturing.store(false, Ordering::SeqCst);
                return;
            }
            let datalink = cap.get_datalink();
            let ethernet = datalink.0 == DLT_EN10MB;
            let file_link_type = export::file_link_type(datalink);
            ready.store(true, Ordering::SeqCst);

            let mut batch: Vec<CapturedPacket> = Vec::with_capacity(CAPTURE_BATCH_SIZE);

            // Capture health, polled rather than derived from what we stored:
            // libpcap is the only thing that knows about the packets it had to
            // throw away, and those are exactly the ones the list cannot show.
            let mut last_poll = std::time::Instant::now();
            let mut last_reading = pcap::Stat {
                received: 0,
                dropped: 0,
                if_dropped: 0,
            };
            let first_id = *crate::app::safe_lock(&counter, "packets::stats_poll");

            while capturing.load(Ordering::Relaxed) {
                if last_poll.elapsed() >= STATS_POLL {
                    if let Ok(s) = cap.stats() {
                        let decoded = crate::app::safe_lock(&counter, "packets::stats_poll")
                            .saturating_sub(first_id);
                        let elapsed = last_poll.elapsed().as_secs_f64();
                        stats.record_poll(&mut last_reading, s, decoded, elapsed);
                    }
                    last_poll = std::time::Instant::now();
                }
                match cap.next_packet() {
                    Ok(packet) => {
                        // `packet.data` is built by the `pcap` crate as
                        // `slice::from_raw_parts(ptr, header.caplen)` before we
                        // ever see it (see `Packet::new`), so a bad `caplen`
                        // is UB the moment that slice exists. Skip the packet
                        // without touching `packet.data` if `caplen` exceeds
                        // what we asked libpcap to capture.
                        //
                        // A correct build never takes this branch. It is a
                        // last line of defence against an ABI mismatch: on
                        // armv5te, a libpcap compiled with _TIME_BITS=64 has a
                        // 24-byte `pcap_pkthdr`, Rust expects 16, and `caplen`
                        // is read from tv_usec. That was the Iomega ix2-dl
                        // segfault. The release build asserts the 16-byte
                        // layout, so fix the build if this ever fires.
                        if packet.header.caplen > CAPTURE_SNAPLEN as u32 {
                            continue;
                        }
                        let survived = run_capture_step(&capturing, &error, || {
                            let capture = file_link_type.and_then(|link_type| {
                                export::CaptureMetadata::from_pcap(
                                    &session_ref,
                                    &interface_ref,
                                    link_type,
                                    packet.header,
                                )
                            });
                            let frame = Frame {
                                data: packet.data,
                                ethernet,
                                capture,
                            };
                            if let Some(parsed) = decode_and_track(frame, &counter, &dns, &tracker)
                            {
                                // A packet that used up the stream indices
                                // comes back under the tracker's new session,
                                // and every packet after it takes that one.
                                if let Some(meta) = &parsed.capture {
                                    if !Arc::ptr_eq(&meta.session, &session_ref) {
                                        session_ref = Arc::clone(&meta.session);
                                    }
                                }
                                batch.push(parsed);
                                if batch.len() >= CAPTURE_BATCH_SIZE {
                                    let mut pkts =
                                        crate::app::safe_write(&packets, "packets::flush");
                                    pkts.extend(batch.drain(..));
                                    if pkts.len() > MAX_PACKETS {
                                        let excess = pkts.len() - MAX_PACKETS;
                                        pkts.drain(0..excess);
                                    }
                                }
                            }
                        });
                        if !survived {
                            // run_capture_step has logged the panic. Clear any poison
                            // it left, or after a restart each of these locks would
                            // log it again for every packet.
                            tracker.clear_poison();
                            packets.clear_poison();
                            counter.clear_poison();
                            break;
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Non-blocking mode returns this immediately when no
                        // packet is ready. Flush any pending batch, then sleep
                        // briefly so we don't busy-spin — while still re-checking
                        // `capturing` ~50x/sec so quit and interface switches
                        // stay responsive (issue #41).
                        if !batch.is_empty() {
                            let mut pkts = crate::app::safe_write(&packets, "packets::flush");
                            pkts.extend(batch.drain(..));
                            if pkts.len() > MAX_PACKETS {
                                let excess = pkts.len() - MAX_PACKETS;
                                pkts.drain(0..excess);
                            }
                        }
                        thread::sleep(std::time::Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }

            ready.store(false, Ordering::SeqCst);
            capturing.store(false, Ordering::SeqCst);

            // Flush remaining batch on shutdown
            if !batch.is_empty() {
                let mut pkts = crate::app::safe_write(&packets, "packets::flush");
                pkts.extend(batch.drain(..));
                if pkts.len() > MAX_PACKETS {
                    let excess = pkts.len() - MAX_PACKETS;
                    pkts.drain(0..excess);
                }
            }
        }));
    }

    pub fn stop_capture(&mut self) {
        self.ready.store(false, Ordering::SeqCst);
        self.capturing.store(false, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            // Bounded join: the capture loop observes `capturing` at least
            // every CAPTURE_TIMEOUT_MS, so it unwinds promptly under normal
            // operation. Cap the wait anyway so a wedged pcap read can never
            // freeze shutdown or an interface switch the way it did in
            // issue #41 — if the thread hasn't finished by the deadline we
            // detach it (the OS reaps it on process exit) rather than block.
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(750);
            while !h.is_finished() && std::time::Instant::now() < deadline {
                thread::sleep(std::time::Duration::from_millis(10));
            }
            if h.is_finished() {
                let _ = h.join();
            }
        }
    }

    pub fn clear(&self) {
        crate::app::safe_write(&self.packets, "packets::clear").clear();
        crate::app::safe_lock(&self.stream_tracker, "packets::reset").clear();
    }

    /// Includes preparation, for toggle/cancellation ownership decisions.
    pub fn capture_requested(&self) -> bool {
        self.capturing.load(Ordering::SeqCst)
    }

    pub fn is_capturing(&self) -> bool {
        self.ready.load(Ordering::SeqCst) && self.capturing.load(Ordering::SeqCst)
    }

    pub fn get_error(&self) -> Option<String> {
        crate::app::safe_lock(&self.error, "packets::get_error").clone()
    }

    /// Identifies the latest capture session, as each packet's capture
    /// metadata does; the incident recorder samples it with the drop count.
    pub fn capture_session(&self) -> Option<String> {
        crate::app::safe_lock(&self.stream_tracker, "packets::capture_session")
            .session
            .as_deref()
            .map(str::to_string)
    }

    /// Packets libpcap received and dropped since the capture started, and
    /// how many of them reached the list, as of the last poll (once a
    /// second). Monotonic within a capture; libpcap's own counters wrap.
    pub fn capture_totals(&self) -> (u64, u64, u64) {
        let totals = self.stats.totals();
        (totals.received, totals.dropped, totals.decoded)
    }

    /// Cheap read of the packet ring's current length — for the `M`
    /// debug overlay. Uses try_read so a contended lock doesn't stall
    /// the redraw; returns 0 if the lock can't be acquired this frame.
    pub fn packet_count_hint(&self) -> usize {
        match self.packets.try_read() {
            Ok(g) => g.len(),
            Err(_) => 0,
        }
    }

    /// Record one poll of the connection table for PCAPNG annotations. A
    /// packet is annotated only when this poll and the previous one agree on
    /// its socket's owner; see [`export::AnnotationHistory`].
    pub fn observe_attribution(&mut self, connections: &[super::connections::Connection]) {
        self.annotation_history.observe(
            connections,
            &mut crate::app::safe_write(&self.packets, "packets::annotate"),
        );
    }

    pub fn get_packets(&self) -> std::sync::RwLockReadGuard<'_, Vec<CapturedPacket>> {
        crate::app::safe_read(&self.packets, "packets::get_packets")
    }

    /// Decode an Ethernet frame into this collector's packet list and stream
    /// tracker through the capture thread's own path, for render tests.
    /// Returns the packet's id.
    #[cfg(test)]
    pub(crate) fn ingest_frame_for_test(&self, data: &[u8]) -> Option<u64> {
        let frame = Frame {
            data,
            ethernet: true,
            capture: None,
        };
        let pkt = decode_and_track(frame, &self.counter, &self.dns_cache, &self.stream_tracker)?;
        let id = pkt.id;
        crate::app::safe_write(&self.packets, "packets::ingest_for_test").push(pkt);
        Some(id)
    }

    /// Bytes for a seeded packet: something that reads like the protocol in
    /// the hex and ascii panes rather than a block of zeroes.
    fn demo_payload(proto: &str, info: &str, len: usize) -> Vec<u8> {
        if len == 0 {
            return Vec::new();
        }
        let seed: Vec<u8> = match proto {
            "DNS" => {
                let mut v = vec![0x8f, 0x21, 0x01, 0x00, 0x00, 0x01];
                v.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
                v
            }
            "TLS" => {
                let mut v = vec![0x16, 0x03, 0x01];
                v.extend_from_slice(info.as_bytes());
                v
            }
            _ => b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n".to_vec(),
        };
        seed.iter().copied().cycle().take(len).collect()
    }

    /// Seed a recorded conversation so `--demo` has something to show.
    ///
    /// Live capture needs `CAP_NET_RAW`. Without it this tab is an empty list
    /// and an empty decode on every machine where netwatch runs as an
    /// ordinary user — which includes every machine someone is likely to
    /// review it on. The screen was unreachable, and so was untested.
    ///
    /// The packets go in through `track_packet`, the same path a live capture
    /// uses, so the streams, handshake timings and retransmit counters are
    /// built by the real code rather than hand-assembled to look right.
    ///
    /// The story matches the diagnose demo: a slow resolver at 169.254.1.1,
    /// then a TLS connection that opens cleanly, resends a segment, and is
    /// reset by the far end.
    pub fn seed_demo_capture(&self) {
        const MS: u64 = 1_000_000;
        let client = "10.88.0.2";
        let resolver = "169.254.1.1";
        let server = "93.184.216.34";

        // (offset_ms, src, sport, dst, dport, proto, flags, seq, len, info, payload_len)
        type Row = (
            u64,
            &'static str,
            u16,
            &'static str,
            u16,
            &'static str,
            Option<u8>,
            Option<u32>,
            u32,
            &'static str,
            usize,
        );
        let rows: Vec<Row> = vec![
            (
                0,
                client,
                51820,
                resolver,
                53,
                "DNS",
                None,
                None,
                74,
                "Standard query A example.com",
                32,
            ),
            (
                40,
                resolver,
                53,
                client,
                51820,
                "DNS",
                None,
                None,
                90,
                "Response A 93.184.216.34",
                48,
            ),
            (
                42,
                client,
                52344,
                server,
                443,
                "TCP",
                Some(TCP_FLAG_SYN),
                Some(1000),
                74,
                "",
                0,
            ),
            (
                54,
                server,
                443,
                client,
                52344,
                "TCP",
                Some(TCP_FLAG_SYN | TCP_FLAG_ACK),
                Some(5000),
                74,
                "",
                0,
            ),
            (
                66,
                client,
                52344,
                server,
                443,
                "TCP",
                Some(TCP_FLAG_ACK),
                Some(1001),
                66,
                "",
                0,
            ),
            (
                68,
                client,
                52344,
                server,
                443,
                "TLS",
                Some(TCP_FLAG_PSH | TCP_FLAG_ACK),
                Some(1001),
                583,
                "Client Hello (SNI example.com)",
                517,
            ),
            (
                91,
                server,
                443,
                client,
                52344,
                "TLS",
                Some(TCP_FLAG_PSH | TCP_FLAG_ACK),
                Some(5001),
                1478,
                "Server Hello",
                1412,
            ),
            (
                93,
                server,
                443,
                client,
                52344,
                "TLS",
                Some(TCP_FLAG_PSH | TCP_FLAG_ACK),
                Some(6413),
                1478,
                "Certificate",
                1412,
            ),
            (
                140,
                client,
                52344,
                server,
                443,
                "TCP",
                Some(TCP_FLAG_PSH | TCP_FLAG_ACK),
                Some(1518),
                512,
                "Application Data",
                446,
            ),
            // The far end never acknowledged it, so the client sends it again.
            (
                390,
                client,
                52344,
                server,
                443,
                "TCP",
                Some(TCP_FLAG_PSH | TCP_FLAG_ACK),
                Some(1518),
                512,
                "Application Data",
                446,
            ),
            (
                612,
                server,
                443,
                client,
                52344,
                "TCP",
                Some(TCP_FLAG_RST),
                Some(7825),
                66,
                "",
                0,
            ),
        ];

        let mut out = Vec::with_capacity(rows.len());
        let mut tracker = match self.stream_tracker.lock() {
            Ok(t) => t,
            Err(_) => return,
        };
        for (i, row) in rows.iter().enumerate() {
            let (off, src, sport, dst, dport, proto, flags, seq, len, info, plen) = *row;
            let id = i as u64 + 1;
            let ns = off * MS;
            let payload = Self::demo_payload(proto, info, plen);
            let stream_proto = if proto == "DNS" {
                StreamProtocol::Udp
            } else {
                StreamProtocol::Tcp
            };
            let stamp = format!("00:00:{:02}.{:03}", off / 1000, off % 1000);
            let idx = tracker.track_packet(
                src,
                sport,
                dst,
                dport,
                stream_proto,
                &payload,
                id,
                &stamp,
                flags,
                seq,
                ns,
            );
            let hex = hex_dump(&payload);
            let ascii = ascii_dump(&payload);
            out.push(CapturedPacket {
                capture: None,
                annotation: None,
                id,
                timestamp: stamp,
                src_ip: src.into(),
                dst_ip: dst.into(),
                src_host: None,
                dst_host: None,
                protocol: proto.into(),
                length: len,
                src_port: Some(sport),
                dst_port: Some(dport),
                info: info.into(),
                details: vec![
                    format!("{proto}: {src}:{sport} -> {dst}:{dport}"),
                    format!("Frame: {len} bytes on the wire"),
                ],
                payload_text: if plen > 0 {
                    format!("[{plen} bytes]")
                } else {
                    String::new()
                },
                raw_hex: hex,
                raw_ascii: ascii,
                raw_bytes: payload,
                stream_index: Some(idx),
                tcp_flags: flags,
                tcp_seq: seq,
                expert: classify_expert(proto, info, flags),
                timestamp_ns: ns,
                app_protocol: None,
                decrypted_plaintext: None,
            });
        }
        drop(tracker);
        if let Ok(mut p) = self.packets.write() {
            *p = out;
        }
        if let Ok(mut c) = self.counter.lock() {
            *c = rows.len() as u64;
        }
    }

    /// A copy of one stream for the UI, which takes one per frame. Segments
    /// are shared `Arc`s and HTTP/3 buffers stay in the tracker, so the copy
    /// is the bookkeeping plus one pointer per segment, not the payloads.
    pub fn get_stream(&self, index: u32) -> Option<Stream> {
        crate::app::safe_lock(&self.stream_tracker, "packets::get_stream")
            .get_stream(index)
            .cloned()
    }

    /// Reassembled HTTP/3 bodies for a flow (Phase 3b). Decodes lazily (cached
    /// per stream) and clones only the decoded bodies, not the whole `Stream`,
    /// so the UI can call it per render frame.
    pub fn quic_h3_bodies(&self, index: u32) -> Vec<crate::dpi::http3::DecodedBody> {
        crate::app::safe_lock(&self.stream_tracker, "packets::quic_h3_bodies").quic_h3_bodies(index)
    }
}

impl Drop for PacketCollector {
    fn drop(&mut self) {
        self.stop_capture();
    }
}

// ── Packet parsing ──────────────────────────────────────────

/// Decodes a saved capture frame by frame through the capture thread's own
/// path, stream tracking and flow classification included, for the pcap
/// golden tests in `tests/`. No reverse DNS, as for `fuzz_parse_frame`.
#[doc(hidden)]
pub struct Replay {
    counter: Arc<Mutex<u64>>,
    dns: DnsCache,
    tracker: Mutex<StreamTracker>,
}

impl Replay {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            counter: Arc::new(Mutex::new(0)),
            dns: DnsCache::new(),
            tracker: Mutex::new(StreamTracker::new()),
        }
    }

    /// An Ethernet frame. A saved capture's header is not passed in, so the
    /// packet has no capture metadata, and the golden output does not depend
    /// on when the fixture was recorded.
    pub fn frame(&self, data: &[u8]) -> Option<CapturedPacket> {
        let frame = Frame {
            data,
            ethernet: true,
            capture: None,
        };
        decode_and_track(frame, &self.counter, &self.dns, &self.tracker)
    }
}

/// Decode one Ethernet frame exactly as the capture thread does, for the
/// fuzz targets in `fuzz/`. No reverse DNS: the cache has no peers and is
/// never started.
#[doc(hidden)]
pub fn fuzz_parse_frame(data: &[u8]) {
    let counter = Arc::new(Mutex::new(0));
    let _ = parse_packet(data, &counter, &DnsCache::new());
}

/// libpcap's data link number for Ethernet, the only framing the dissectors
/// read. It is 1 on every platform.
const DLT_EN10MB: i32 = 1;

/// One frame as the capture thread received it.
struct Frame<'a> {
    data: &'a [u8],
    /// Whether `data` is Ethernet-framed. Anything else (raw IP from a VPN
    /// tunnel, BSD loopback, Linux cooked capture) is kept undecoded.
    ethernet: bool,
    /// libpcap's timestamp and wire length for the frame, for exports.
    /// `None` when replaying, or when the header or link type cannot be
    /// written to a file.
    capture: Option<export::CaptureMetadata>,
}

/// Decode one frame and fold it into the stream tracker: the per-packet
/// work of the capture thread, apart from batching. Also the entry point
/// for replaying a saved capture ([`Replay`]).
fn decode_and_track(
    frame: Frame<'_>,
    counter: &Arc<Mutex<u64>>,
    dns: &DnsCache,
    tracker: &Mutex<StreamTracker>,
) -> Option<CapturedPacket> {
    let data = frame.data;
    let mut parsed = if frame.ethernet {
        parse_packet(data, counter, dns)?
    } else {
        undecoded_frame(data, counter, dns)
    };
    if let Some(meta) = frame.capture {
        apply_capture_metadata(&mut parsed, meta);
    }
    if let (Some(sp), Some(dp)) = (parsed.src_port, parsed.dst_port) {
        let proto = if parsed.tcp_flags.is_some() {
            StreamProtocol::Tcp
        } else {
            StreamProtocol::Udp
        };
        let payload = extract_app_payload(data, proto);
        let (idx, app_proto, decrypted) = {
            let mut t = crate::app::safe_lock(tracker, "packets::capture_loop");
            let i = t.track_packet(
                &parsed.src_ip,
                sp,
                &parsed.dst_ip,
                dp,
                proto,
                &payload,
                parsed.id,
                &parsed.timestamp,
                parsed.tcp_flags,
                parsed.tcp_seq,
                parsed.timestamp_ns,
            );
            // The index belongs to the tracker's session, which is not the
            // one the frame was stamped with if this packet used them up.
            if let (Some(meta), Some(session)) = (parsed.capture.as_mut(), &t.session) {
                if !Arc::ptr_eq(&meta.session, session) {
                    meta.session = Arc::clone(session);
                }
            }
            let ap = t.get_stream(i).and_then(|s| s.app_protocol.clone());
            // TLS-decrypt the application-data record carried by
            // *this* TCP segment, if we have keys for the flow.
            // Determines direction from initiator info on the stream.
            let client_to_server = t
                .get_stream(i)
                .and_then(|s| s.initiator.as_ref())
                .map(|(ip, port)| ip.as_str() == parsed.src_ip.as_str() && *port == sp)
                .unwrap_or(true);
            let dec = t
                .try_decrypt_tls_record(i, &payload, client_to_server)
                .or_else(|| {
                    // QUIC 1-RTT short-header packets ride UDP; the
                    // TLS path above no-ops on them.
                    if proto == StreamProtocol::Udp {
                        t.try_decrypt_quic_1rtt(i, &payload, client_to_server)
                    } else {
                        None
                    }
                });
            // Mirror the decrypted plaintext onto this
            // packet's stream segment so the stream view
            // can follow the decrypted conversation.
            if let Some(ref pt) = dec {
                t.attach_segment_decrypted(i, parsed.id, pt.clone());
            }
            (i, ap, dec)
        };
        parsed.stream_index = Some(idx);
        parsed.app_protocol = app_proto;
        parsed.decrypted_plaintext = decrypted;
    }
    Some(parsed)
}

/// A frame in a framing the dissectors do not read. It is listed and kept
/// for export with its bytes as captured, rather than fed to the Ethernet
/// parser, which would invent addresses from whatever sits at its offsets.
fn undecoded_frame(data: &[u8], counter: &Arc<Mutex<u64>>, dns: &DnsCache) -> CapturedPacket {
    build_packet(
        counter,
        "Raw",
        data.len() as u32,
        "—",
        "—",
        None,
        None,
        "Undecoded capture framing",
        vec![
            format!("Frame: {} bytes", data.len()),
            "Link: not Ethernet; not decoded".into(),
        ],
        &[],
        data,
        dns,
        None,
        None,
    )
}

/// Use libpcap's timestamp and wire length for the packet in place of the
/// decode-time clock and captured length, so the list, the stream tracker
/// and exports agree on when the frame arrived and how long it was.
fn apply_capture_metadata(parsed: &mut CapturedPacket, meta: export::CaptureMetadata) {
    parsed.length = meta.original_len;
    if let Some(frame) = parsed.details.first_mut() {
        *frame = format!(
            "Frame: {} bytes captured, {} on the wire",
            parsed.raw_bytes.len(),
            meta.original_len
        );
    }
    parsed.timestamp_ns = meta.timestamp_ns;
    if let Some(at) = chrono::DateTime::from_timestamp(
        (meta.timestamp_ns / 1_000_000_000) as i64,
        (meta.timestamp_ns % 1_000_000_000) as u32,
    ) {
        parsed.timestamp = at
            .with_timezone(&chrono::Local)
            .format("%H:%M:%S%.3f")
            .to_string();
    }
    parsed.capture = Some(meta);
}

fn parse_packet(data: &[u8], counter: &Arc<Mutex<u64>>, dns: &DnsCache) -> Option<CapturedPacket> {
    if data.len() < 14 {
        return None;
    }

    let mut details = vec![format!("Frame: {} bytes on wire", data.len())];

    let src_mac = format_mac(&data[6..12]);
    let dst_mac = format_mac(&data[0..6]);
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let ether_name = match ethertype {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86DD => "IPv6",
        _ => "Unknown",
    };
    details.push(format!(
        "Ethernet: {} → {}, Type: {} (0x{:04x})",
        src_mac, dst_mac, ether_name, ethertype
    ));

    match ethertype {
        0x0800 => parse_ipv4_packet(data, &data[14..], &mut details, counter, dns),
        0x0806 => {
            let info = parse_arp(&data[14..], &mut details);
            Some(build_packet(
                counter,
                "ARP",
                data.len() as u32,
                "—",
                "—",
                None,
                None,
                &info,
                details,
                &[],
                data,
                dns,
                None,
                None,
            ))
        }
        0x86DD => parse_ipv6_packet(data, &data[14..], &mut details, counter, dns),
        _ => None,
    }
}

// Transport parse result:
// (protocol, src_port, dst_port, info, app_payload_offset, tcp_flags, tcp_seq)
// app_payload_offset is relative to the transport data start. tcp_seq is
// the TCP sequence number, used for retransmit / OOO classification.
type TransportResult = (
    String,
    Option<u16>,
    Option<u16>,
    String,
    usize,
    Option<u8>,
    Option<u32>,
);

fn parse_ipv4_packet(
    raw: &[u8],
    data: &[u8],
    details: &mut Vec<String>,
    counter: &Arc<Mutex<u64>>,
    dns: &DnsCache,
) -> Option<CapturedPacket> {
    if data.len() < 20 {
        return None;
    }
    let ihl = ((data[0] & 0x0F) as usize) * 4;
    let total_len = u16::from_be_bytes([data[2], data[3]]);
    let ttl = data[8];
    let protocol_num = data[9];
    let src = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
    let dst = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);

    details.push(format!(
        "IPv4: {} → {}, TTL: {}, Proto: {} ({}), Len: {}",
        src,
        dst,
        ttl,
        ip_protocol_name(protocol_num),
        protocol_num,
        total_len
    ));

    let transport_data = if data.len() > ihl { &data[ihl..] } else { &[] };
    let (protocol, src_port, dst_port, info, payload_off, flags, seq) =
        parse_transport(protocol_num, transport_data, &src, &dst, details);

    let app_payload = if transport_data.len() > payload_off {
        &transport_data[payload_off..]
    } else {
        &[]
    };

    Some(build_packet(
        counter,
        &protocol,
        raw.len() as u32,
        &src,
        &dst,
        src_port,
        dst_port,
        &info,
        details.clone(),
        app_payload,
        raw,
        dns,
        flags,
        seq,
    ))
}

fn parse_ipv6_packet(
    raw: &[u8],
    data: &[u8],
    details: &mut Vec<String>,
    counter: &Arc<Mutex<u64>>,
    dns: &DnsCache,
) -> Option<CapturedPacket> {
    if data.len() < 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([data[4], data[5]]);
    let next_header = data[6];
    let hop_limit = data[7];
    let src = format_ipv6(data[8..24].try_into().ok()?);
    let dst = format_ipv6(data[24..40].try_into().ok()?);

    details.push(format!(
        "IPv6: {} → {}, Hop Limit: {}, Next: {} ({}), Payload: {}",
        src,
        dst,
        hop_limit,
        ip_protocol_name(next_header),
        next_header,
        payload_len
    ));

    let transport_data = if data.len() > 40 { &data[40..] } else { &[] };
    let (protocol, src_port, dst_port, info, payload_off, flags, seq) =
        parse_transport(next_header, transport_data, &src, &dst, details);

    let app_payload = if transport_data.len() > payload_off {
        &transport_data[payload_off..]
    } else {
        &[]
    };

    Some(build_packet(
        counter,
        &protocol,
        raw.len() as u32,
        &src,
        &dst,
        src_port,
        dst_port,
        &info,
        details.clone(),
        app_payload,
        raw,
        dns,
        flags,
        seq,
    ))
}

fn parse_transport(
    proto: u8,
    data: &[u8],
    src_ip: &str,
    dst_ip: &str,
    details: &mut Vec<String>,
) -> TransportResult {
    match proto {
        6 if data.len() >= 20 => parse_tcp(data, src_ip, dst_ip, details),
        17 if data.len() >= 8 => parse_udp(data, src_ip, dst_ip, details),
        1 => {
            let r = parse_icmp(data, src_ip, dst_ip, details);
            (r.0, r.1, r.2, r.3, data.len(), None, None)
        }
        2 => {
            // IGMP — IP protocol 2. Not a TCP/UDP flow; no stream is
            // created and DPI classification doesn't run. We decode
            // the message type here so the Packets-tab INFO column
            // shows something more useful than just "IGMP".
            let r = parse_igmp(data, src_ip, dst_ip, details);
            (r.0, r.1, r.2, r.3, data.len(), None, None)
        }
        58 => {
            let r = parse_icmpv6(data, src_ip, dst_ip, details);
            (r.0, r.1, r.2, r.3, data.len(), None, None)
        }
        _ => {
            let name = ip_protocol_name(proto);
            details.push(format!("{}: {} → {}", name, src_ip, dst_ip));
            (
                name.clone(),
                None,
                None,
                format!("{} → {} {}", src_ip, dst_ip, name),
                data.len(),
                None,
                None,
            )
        }
    }
}

/// Render a classified `AppProtocol` into the `(protocol-label, summary)` the
/// Info column shows. The label is preserved from the retired legacy parsers
/// so filters / colors / stats keyed on `pkt.protocol` keep working; the
/// summary is the human-readable middle of the Info string. `crate::dpi` is
/// now the single DPI source — this is the only spot the capture path crosses
/// back from `AppProtocol` to display strings.
fn describe_app_protocol(p: &crate::dpi::AppProtocol) -> (&'static str, String) {
    use crate::dpi::AppProtocol::*;
    match p {
        Tls { sni, alpn, ech, .. } => {
            let mut s = sni.clone().unwrap_or_else(|| "(no SNI)".into());
            if *ech {
                s.push_str(" [ECH]");
            }
            if let Some(a) = alpn {
                s.push_str(&format!(" alpn={a}"));
            }
            ("TLS", s)
        }
        Quic { sni, ech, .. } => {
            let mut s = sni.clone().unwrap_or_else(|| "(no SNI)".into());
            if *ech {
                s.push_str(" [ECH]");
            }
            ("QUIC", s)
        }
        Http {
            method,
            host,
            path,
            status,
        } => (
            "HTTP",
            match (status, host) {
                (Some(code), _) => format!("{code}"),
                (None, Some(h)) => format!("{method} {h}{}", path.as_deref().unwrap_or("")),
                (None, None) => match path {
                    Some(p) => format!("{method} {p}"),
                    None => method.clone(),
                },
            },
        ),
        Dns {
            qname,
            qtype,
            rcode,
        } => (
            "DNS",
            match rcode {
                Some(rc) => {
                    format!(
                        "{qname} (type={qtype}, {})",
                        crate::dpi::dns::rcode_label(*rc)
                    )
                }
                None => format!("{qname} (type={qtype})"),
            },
        ),
        Llmnr { qname, qtype } => ("LLMNR", format!("{qname} (type={qtype})")),
        Ssh { version } => ("SSH", version.clone()),
        Mqtt { client_id } => ("MQTT", client_id.clone().unwrap_or_default()),
        Stun { message_type } => ("STUN", message_type.clone()),
        BitTorrent { info_hash } => ("BitTorrent", info_hash.clone().unwrap_or_default()),
        NetBios { service } => ("NetBIOS", service.clone()),
        Snmp { version, community } => (
            "SNMP",
            match community {
                Some(c) => format!("{version} {c}"),
                None => version.clone(),
            },
        ),
        Ssdp { method, target } => (
            "SSDP",
            match target {
                Some(t) => format!("{method} {t}"),
                None => method.clone(),
            },
        ),
        Ftp { command } => ("FTP", command.clone()),
        Dhcp { op } => (
            "DHCP",
            match op {
                1 => "Discover/Request".into(),
                2 => "Offer/ACK".into(),
                n => format!("op={n}"),
            },
        ),
        Ntp { version, mode } => {
            let m = match mode {
                1 => "Symmetric Active",
                2 => "Symmetric Passive",
                3 => "Client",
                4 => "Server",
                5 => "Broadcast",
                6 => "Control",
                _ => "Unknown",
            };
            ("NTP", format!("v{version} {m}"))
        }
    }
}

fn parse_tcp(
    data: &[u8],
    src_ip: &str,
    dst_ip: &str,
    details: &mut Vec<String>,
) -> TransportResult {
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = ((data[12] >> 4) as usize) * 4;
    let flags = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);
    let flag_str = tcp_flags(flags);

    let src_svc = port_label(src_port);
    let dst_svc = port_label(dst_port);

    let mut detail = format!(
        "TCP: {} ({}) → {} ({}), Seq: {}, Flags: [{}], Win: {}",
        src_port, src_svc, dst_port, dst_svc, seq, flag_str, window
    );
    if flags & TCP_FLAG_ACK != 0 {
        detail.push_str(&format!(", Ack: {}", ack));
    }
    details.push(detail);

    // Check for application-layer protocols in TCP payload
    let payload = if data.len() > data_offset {
        &data[data_offset..]
    } else {
        &[]
    };

    // Single DPI path: classify via `crate::dpi` and render the Info string
    // from the result. Replaces the old per-packet TCP parser registry.
    if let Some(ap) = crate::dpi::classify_once(payload, true, src_port, dst_port) {
        let (label, summary) = describe_app_protocol(&ap);
        details.push(format!("{label}: {summary}"));
        let info = format!(
            "{} → {} {} [{}]",
            format_endpoint(src_ip, src_port),
            format_endpoint(dst_ip, dst_port),
            summary,
            flag_str
        );
        return (
            label.to_string(),
            Some(src_port),
            Some(dst_port),
            info,
            data_offset,
            Some(flags),
            Some(seq),
        );
    }

    let payload_len = payload.len();
    let info = format!(
        "{} → {} [{}] Seq={} Win={}{} Payload={}",
        format_endpoint(src_ip, src_port),
        format_endpoint(dst_ip, dst_port),
        flag_str,
        seq,
        window,
        if flags & TCP_FLAG_ACK != 0 {
            format!(" Ack={}", ack)
        } else {
            String::new()
        },
        payload_len
    );

    let proto = if dst_svc != "—" {
        dst_svc.to_string()
    } else if src_svc != "—" {
        src_svc.to_string()
    } else {
        "TCP".into()
    };

    (
        proto,
        Some(src_port),
        Some(dst_port),
        info,
        data_offset,
        Some(flags),
        Some(seq),
    )
}

fn parse_udp(
    data: &[u8],
    src_ip: &str,
    dst_ip: &str,
    details: &mut Vec<String>,
) -> TransportResult {
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let udp_len = u16::from_be_bytes([data[4], data[5]]);

    let src_svc = port_label(src_port);
    let dst_svc = port_label(dst_port);

    details.push(format!(
        "UDP: {} ({}) → {} ({}), Len: {}",
        src_port, src_svc, dst_port, dst_svc, udp_len
    ));

    let payload = if data.len() > 8 { &data[8..] } else { &[] };

    // Single DPI path (see parse_tcp). UDP Info omits TCP flags.
    if let Some(ap) = crate::dpi::classify_once(payload, false, src_port, dst_port) {
        let (label, summary) = describe_app_protocol(&ap);
        details.push(format!("{label}: {summary}"));
        let info = format!(
            "{} → {} {}",
            format_endpoint(src_ip, src_port),
            format_endpoint(dst_ip, dst_port),
            summary
        );
        return (
            label.to_string(),
            Some(src_port),
            Some(dst_port),
            info,
            8,
            None,
            None,
        );
    }

    let svc = if dst_svc != "—" { dst_svc } else { src_svc };
    let info = format!(
        "{} → {} Len={}{}",
        format_endpoint(src_ip, src_port),
        format_endpoint(dst_ip, dst_port),
        udp_len,
        if svc != "—" {
            format!(" ({})", svc)
        } else {
            String::new()
        }
    );

    let proto = if svc != "—" {
        svc.to_string()
    } else {
        "UDP".into()
    };
    (proto, Some(src_port), Some(dst_port), info, 8, None, None)
}

fn parse_igmp(
    data: &[u8],
    src_ip: &str,
    dst_ip: &str,
    details: &mut Vec<String>,
) -> (String, Option<u16>, Option<u16>, String) {
    if data.is_empty() {
        return (
            "IGMP".into(),
            None,
            None,
            format!("{} → {} IGMP (truncated)", src_ip, dst_ip),
        );
    }
    let msg = match data[0] {
        0x11 => "Membership Query",
        0x12 => "v1 Membership Report",
        0x16 => "v2 Membership Report",
        0x17 => "Leave Group",
        0x22 => "v3 Membership Report",
        _ => "Unknown",
    };
    // For non-v3 IGMP the group address sits at bytes 4..8.
    let group = if data.len() >= 8 && data[0] != 0x22 {
        Some(format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]))
    } else {
        None
    };
    details.push(format!(
        "IGMP: {}{}",
        msg,
        group
            .as_deref()
            .map(|g| format!(" group={}", g))
            .unwrap_or_default()
    ));
    let info = match &group {
        Some(g) => format!("{} → {} IGMP {} {}", src_ip, dst_ip, msg, g),
        None => format!("{} → {} IGMP {}", src_ip, dst_ip, msg),
    };
    ("IGMP".into(), None, None, info)
}

fn parse_icmp(
    data: &[u8],
    src_ip: &str,
    dst_ip: &str,
    details: &mut Vec<String>,
) -> (String, Option<u16>, Option<u16>, String) {
    if data.len() < 4 {
        details.push("ICMP: (truncated)".into());
        return (
            "ICMP".into(),
            None,
            None,
            format!("{} → {} ICMP", src_ip, dst_ip),
        );
    }
    let icmp_type = data[0];
    let icmp_code = data[1];
    let type_name = icmp_type_name(icmp_type, icmp_code);

    let extra = if (icmp_type == 0 || icmp_type == 8) && data.len() >= 8 {
        let id = u16::from_be_bytes([data[4], data[5]]);
        let seq = u16::from_be_bytes([data[6], data[7]]);
        format!(", Id={}, Seq={}", id, seq)
    } else {
        String::new()
    };

    details.push(format!("ICMP: {}{}", type_name, extra));
    let info = format!("{} → {} {}{}", src_ip, dst_ip, type_name, extra);
    ("ICMP".into(), None, None, info)
}

fn parse_icmpv6(
    data: &[u8],
    src_ip: &str,
    dst_ip: &str,
    details: &mut Vec<String>,
) -> (String, Option<u16>, Option<u16>, String) {
    if data.len() < 4 {
        details.push("ICMPv6: (truncated)".into());
        return (
            "ICMPv6".into(),
            None,
            None,
            format!("{} → {} ICMPv6", src_ip, dst_ip),
        );
    }
    let icmp_type = data[0];
    let type_name = icmpv6_type_name(icmp_type);
    details.push(format!("ICMPv6: {}", type_name));
    let info = format!("{} → {} {}", src_ip, dst_ip, type_name);
    ("ICMPv6".into(), None, None, info)
}

/// Wrapper for use from `crate::collectors::quic`. Re-exposes the existing
/// TLS ClientHello SNI extractor so QUIC can reuse the parser unchanged
/// rather than duplicating the extension walk.
pub(crate) fn extract_sni_for_quic(handshake: &[u8]) -> Option<String> {
    extract_sni(handshake)
}

fn extract_sni(handshake: &[u8]) -> Option<String> {
    // ClientHello structure:
    // handshake_type(1) + length(3) + client_version(2) + random(32) = 38 bytes
    // then session_id_length(1) + session_id(var)
    if handshake.len() < 39 {
        return None;
    }
    let mut pos = 38;
    // Session ID
    if pos >= handshake.len() {
        return None;
    }
    let sid_len = handshake[pos] as usize;
    pos += 1 + sid_len;
    // Cipher suites
    if pos + 2 > handshake.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cs_len;
    // Compression methods
    if pos >= handshake.len() {
        return None;
    }
    let cm_len = handshake[pos] as usize;
    pos += 1 + cm_len;
    // Extensions length
    if pos + 2 > handshake.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;

    while pos + 4 <= ext_end && pos + 4 <= handshake.len() {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;
        if ext_type == 0 {
            // SNI extension
            if pos + 5 <= handshake.len() && ext_data_len >= 5 {
                let name_len =
                    u16::from_be_bytes([handshake[pos + 3], handshake[pos + 4]]) as usize;
                let name_start = pos + 5;
                if name_start + name_len <= handshake.len() {
                    let name =
                        String::from_utf8_lossy(&handshake[name_start..name_start + name_len]);
                    return Some(crate::ui::sanitize::display(&name).into_owned());
                }
            }
            return None;
        }
        pos += ext_data_len;
    }
    None
}

// ── Build packet ────────────────────────────────────────────

fn build_packet(
    counter: &Arc<Mutex<u64>>,
    protocol: &str,
    length: u32,
    src_ip: &str,
    dst_ip: &str,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    info: &str,
    details: Vec<String>,
    payload: &[u8],
    raw: &[u8],
    dns: &DnsCache,
    tcp_flags: Option<u8>,
    tcp_seq: Option<u32>,
) -> CapturedPacket {
    let mut cnt = crate::app::safe_lock(counter, "packets::counter");
    *cnt += 1;
    let id = *cnt;
    let now = chrono::Local::now();
    let timestamp = now.format("%H:%M:%S%.3f").to_string();
    let timestamp_ns = now.timestamp_nanos_opt().unwrap_or(0) as u64;

    // Queue reverse DNS lookups (non-blocking — results appear on next render)
    let src_host = dns.lookup(src_ip);
    let dst_host = dns.lookup(dst_ip);

    let hex_lines = hex_dump(raw);

    let ascii_lines = ascii_dump(raw);

    // Extract readable text from the application payload
    let payload_text = extract_readable_payload(payload);

    // Add resolved hostnames to the details
    let mut details = details;
    if src_host.is_some() || dst_host.is_some() {
        let src_label = src_host.as_deref().unwrap_or(src_ip);
        let dst_label = dst_host.as_deref().unwrap_or(dst_ip);
        details.push(format!("DNS: {} → {}", src_label, dst_label));
    }

    let expert = classify_expert(protocol, info, tcp_flags);

    CapturedPacket {
        capture: None,
        annotation: None,
        id,
        timestamp,
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        src_host,
        dst_host,
        protocol: protocol.to_string(),
        length,
        src_port,
        dst_port,
        info: info.to_string(),
        details,
        payload_text,
        raw_hex: hex_lines,
        raw_ascii: ascii_lines,
        raw_bytes: raw.to_vec(),
        stream_index: None,
        tcp_flags,
        tcp_seq,
        expert,
        timestamp_ns,
        app_protocol: None,
        decrypted_plaintext: None,
    }
}

/// UDP-specific shortcut for the Packets-tab detail pane. Avoids
/// requiring callers to construct a `StreamProtocol` value.
pub fn extract_udp_app_payload(raw: &[u8]) -> Vec<u8> {
    extract_app_payload(raw, StreamProtocol::Udp)
}

fn extract_app_payload(raw: &[u8], proto: StreamProtocol) -> Vec<u8> {
    if raw.len() < 14 {
        return Vec::new();
    }
    let ethertype = u16::from_be_bytes([raw[12], raw[13]]);
    let ip_start = 14;
    let transport_start = match ethertype {
        0x0800 => {
            if raw.len() < ip_start + 20 {
                return Vec::new();
            }
            let ihl = ((raw[ip_start] & 0x0F) as usize) * 4;
            ip_start + ihl
        }
        0x86DD => ip_start + 40,
        _ => return Vec::new(),
    };
    if raw.len() <= transport_start {
        return Vec::new();
    }
    match proto {
        StreamProtocol::Tcp => {
            if raw.len() < transport_start + 20 {
                return Vec::new();
            }
            let data_offset = ((raw[transport_start + 12] >> 4) as usize) * 4;
            let payload_start = transport_start + data_offset;
            if raw.len() > payload_start {
                raw[payload_start..].to_vec()
            } else {
                Vec::new()
            }
        }
        StreamProtocol::Udp => {
            let payload_start = transport_start + 8;
            if raw.len() > payload_start {
                raw[payload_start..].to_vec()
            } else {
                Vec::new()
            }
        }
    }
}

fn extract_readable_payload(payload: &[u8]) -> String {
    if payload.is_empty() {
        return String::new();
    }

    // Check how much of the payload is printable text
    let printable = payload
        .iter()
        .take(2048)
        .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' || b == b'\t')
        .count();

    let sample_len = payload.len().min(2048);
    let ratio = printable as f64 / sample_len as f64;

    if ratio > 0.7 {
        // Mostly text — show it cleaned up
        let text: String = payload
            .iter()
            .take(2048)
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
                    b as char
                } else if b == b'\n' || b == b'\r' {
                    '\n'
                } else {
                    '·'
                }
            })
            .collect();
        // Collapse multiple newlines and trim
        let mut result = String::new();
        let mut prev_newline = false;
        for ch in text.chars() {
            if ch == '\n' {
                if !prev_newline {
                    result.push('\n');
                }
                prev_newline = true;
            } else {
                prev_newline = false;
                result.push(ch);
            }
        }
        // Tabs become `·` like every other control byte, after the trim so
        // tabs at either end still go. ratatui drops control characters from
        // the text it lays out, so a raw tab would vanish from the Payload
        // Content pane and `id\tname` would read as `idname`.
        let trimmed: String = result
            .trim()
            .chars()
            .map(|c| {
                if c == '\t' {
                    crate::ui::sanitize::REPLACEMENT
                } else {
                    c
                }
            })
            .collect();
        if payload.len() > 2048 {
            format!("{}\n… ({} bytes total)", trimmed, payload.len())
        } else {
            trimmed
        }
    } else if !payload.is_empty() {
        // Binary data — show a summary
        format!("[{} bytes binary data]", payload.len())
    } else {
        String::new()
    }
}

// ── Helpers (formatting extracted to format.rs) ──
mod format;
pub use format::port_label;
pub(crate) use format::{canonical_ip, format_endpoint};
use format::{
    format_ipv6, format_mac, icmp_type_name, icmpv6_type_name, ip_protocol_name, parse_arp,
    tcp_flags,
};

// ── PCAP export (extracted to pcap_export.rs) ──
mod pcap_export;
pub use pcap_export::export_pcap;
pub mod export;

// ── Display filters (extracted to filter.rs) ──
mod filter;
pub use filter::{matches_packet, parse_filter, FilterExpr};

/// The device name pcap opens for a user-facing interface name.
///
/// On Windows pcap needs `\Device\NPF_{GUID}`, not the friendly name ipconfig
/// reports ("Ethernet", "vEthernet (WSL)"). The matching lives in
/// `platform::npcap_device` — by the adapter's GUID from `GetAdaptersAddresses`,
/// then by its IPv4 address, never by description substring (issue #51).
/// Elsewhere the name is already the device name.
fn resolve_device_name(friendly: &str) -> Result<String, String> {
    #[cfg(not(target_os = "windows"))]
    {
        Ok(friendly.to_string())
    }

    #[cfg(target_os = "windows")]
    {
        use crate::platform::npcap_device::{guid_for, match_npcap_device, PcapDevice};

        if friendly.starts_with("\\Device\\") || friendly.starts_with("\\\\") {
            return Ok(friendly.to_string());
        }

        let devices: Vec<PcapDevice> = pcap::Device::list()
            .map_err(|e| format!("Npcap adapter list failed: {e}"))?
            .into_iter()
            .map(|d| PcapDevice {
                name: d.name,
                desc: d.desc,
                addrs: d.addresses.into_iter().map(|a| a.addr).collect(),
            })
            .collect();

        let guid = guid_for(&crate::platform::windows::adapter_guids(), friendly);
        if let Some(name) = match_npcap_device(friendly, guid.as_deref(), None, &devices) {
            return Ok(name);
        }

        // No GUID, or it matched no Npcap device: try the address the
        // interface list reports for this adapter.
        let ipv4 = crate::platform::collect_interface_info()
            .ok()
            .and_then(|info| {
                info.into_iter()
                    .find(|i| i.name.eq_ignore_ascii_case(friendly))
                    .and_then(|i| i.ipv4)
            });
        match_npcap_device(friendly, None, ipv4.as_deref(), &devices).ok_or_else(|| {
            format!(
                "No Npcap adapter matches '{friendly}' ({} listed) — is Npcap bound to it?",
                devices.len()
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packet(
        proto: &str,
        src: &str,
        dst: &str,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        info: &str,
    ) -> CapturedPacket {
        CapturedPacket {
            capture: None,
            annotation: None,
            id: 1,
            timestamp: "00:00:00.000".into(),
            src_ip: src.into(),
            dst_ip: dst.into(),
            src_host: None,
            dst_host: None,
            protocol: proto.into(),
            length: 100,
            src_port,
            dst_port,
            info: info.into(),
            details: vec![],
            payload_text: String::new(),
            raw_hex: String::new(),
            raw_ascii: String::new(),
            raw_bytes: vec![],
            stream_index: None,
            tcp_flags: None,
            tcp_seq: None,
            expert: ExpertSeverity::Chat,
            timestamp_ns: 0,
            app_protocol: None,
            decrypted_plaintext: None,
        }
    }

    // ── capture metadata ────────────────────────────────────

    /// Ethernet + IPv4 + UDP 127.0.0.1:1234 -> 192.0.2.1:53, 42 bytes.
    const UDP_FRAME: [u8; 42] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0, 0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 127,
        0, 0, 1, 192, 0, 2, 1, 4, 210, 0, 53, 0, 8, 0, 0,
    ];

    fn metadata(link_type: u16) -> export::CaptureMetadata {
        export::CaptureMetadata {
            session: "s".into(),
            interface: "eth0".into(),
            link_type,
            timestamp_ns: 1_700_000_000_123_456_000,
            original_len: 1500,
        }
    }

    fn decode(frame: Frame<'_>) -> Option<CapturedPacket> {
        decode_and_track(
            frame,
            &Arc::new(Mutex::new(0)),
            &DnsCache::new(),
            &Mutex::new(StreamTracker::new()),
        )
    }

    #[test]
    fn capture_metadata_sets_time_and_wire_length_before_tracking() {
        let p = decode(Frame {
            data: &UDP_FRAME,
            ethernet: true,
            capture: Some(metadata(1)),
        })
        .unwrap();
        assert_eq!(p.capture, Some(metadata(1)));
        assert_eq!(p.timestamp_ns, 1_700_000_000_123_456_000);
        assert_eq!(p.length, 1500);
        assert_eq!(p.details[0], "Frame: 42 bytes captured, 1500 on the wire");
        assert!(p.timestamp.ends_with(".123"), "{}", p.timestamp);
        assert_eq!(p.raw_bytes, UDP_FRAME);
        // The stream tracker saw the frame under libpcap's time too.
        assert!(p.stream_index.is_some());

        // Replay passes no header: decode time and captured length, as before.
        let replayed = Replay::new().frame(&UDP_FRAME).unwrap();
        assert!(replayed.capture.is_none());
        assert_eq!(replayed.length, 42);
        assert_eq!(replayed.details[0], "Frame: 42 bytes on wire");
    }

    #[test]
    fn a_frame_in_another_framing_is_kept_undecoded() {
        // Raw IP from a tunnel: the Ethernet parser would read addresses
        // out of the IP header's own fields.
        let raw_ip = &UDP_FRAME[14..];
        let p = decode(Frame {
            data: raw_ip,
            ethernet: false,
            capture: Some(metadata(101)),
        })
        .unwrap();
        assert_eq!(p.protocol, "Raw");
        assert_eq!((p.src_ip.as_str(), p.dst_ip.as_str()), ("—", "—"));
        assert_eq!((p.src_port, p.dst_port, p.stream_index), (None, None, None));
        assert_eq!(p.raw_bytes, raw_ip);
        assert_eq!(p.capture.unwrap().link_type, 101);
        // Even an empty frame is listed; export omits it for having no bytes.
        let empty = decode(Frame {
            data: &[],
            ethernet: false,
            capture: None,
        })
        .unwrap();
        assert!(empty.raw_bytes.is_empty());
    }

    // ── format_mac ──────────────────────────────────────────
    /// What libpcap prints when the open is refused, per platform.
    #[test]
    fn a_refused_open_is_recognised_on_every_platform() {
        for message in [
            "libpcap error: Attempt to create packet socket failed - CAP_NET_RAW may be required",
            "libpcap error: socket: Operation not permitted",
            "libpcap error: (cannot open BPF device) /dev/bpf0: Permission denied",
            "libpcap error: You don't have permission to capture on that device",
        ] {
            assert!(open_refused(message), "{message}");
        }
        assert!(!open_refused("libpcap error: No such device exists"));
    }

    #[test]
    fn test_format_mac_normal() {
        assert_eq!(
            format_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            "aa:bb:cc:dd:ee:ff"
        );
    }
    #[test]
    fn test_format_mac_zeros() {
        assert_eq!(format_mac(&[0, 0, 0, 0, 0, 0]), "00:00:00:00:00:00");
    }
    #[test]
    fn test_format_mac_broadcast() {
        assert_eq!(format_mac(&[0xff; 6]), "ff:ff:ff:ff:ff:ff");
    }

    // ── format_ipv6 ─────────────────────────────────────────
    #[test]
    fn test_format_ipv6_loopback() {
        let mut bytes = [0u8; 16];
        bytes[15] = 1;
        assert_eq!(format_ipv6(&bytes), "::1");
    }
    #[test]
    fn test_format_ipv6_all_zeros() {
        assert_eq!(format_ipv6(&[0u8; 16]), "::");
    }
    /// RFC 5952: lower case, no leading zeros, the longest run of zero groups
    /// (the first of equals) as `::`, and never `::` for a single group.
    #[test]
    fn test_format_ipv6_is_rfc_5952() {
        for (text, want) in [
            ("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
            ("2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"),
            ("2001:0:0:1:0:0:0:1", "2001:0:0:1::1"),
            ("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"),
            (
                "fe80:0:0:0:aede:48ff:fe00:1122",
                "fe80::aede:48ff:fe00:1122",
            ),
            ("0:0:0:0:0:ffff:c000:201", "::ffff:192.0.2.1"),
        ] {
            let octets = text.parse::<std::net::Ipv6Addr>().unwrap().octets();
            assert_eq!(format_ipv6(&octets), want, "{text}");
        }
    }

    /// An endpoint reads back as the address and port it names. Compressed
    /// IPv6 with `:port` appended does not: `2001:db8::20:53` is itself the
    /// address 2001:db8::20:53, so the port goes outside brackets.
    #[test]
    fn an_endpoint_reads_back_as_its_address_and_port() {
        for (ip, port, want) in [
            ("2001:db8::20", 53, "[2001:db8::20]:53"),
            ("::1", 8080, "[::1]:8080"),
            ("::ffff:192.0.2.1", 443, "[::ffff:192.0.2.1]:443"),
            ("192.0.2.1", 443, "192.0.2.1:443"),
        ] {
            let text = format_endpoint(ip, port);
            assert_eq!(text, want);
            let back: std::net::SocketAddr = text.parse().unwrap();
            assert_eq!((back.ip(), back.port()), (ip.parse().unwrap(), port));
        }
        // A resolved name has no colon to confuse.
        assert_eq!(format_endpoint("dns.google", 53), "dns.google:53");
    }

    // ── parse_ip / canonical_ip ─────────────────────────────
    /// Every spelling a platform tool, a capture or a user produces for one
    /// address comes out as the one packet decoding uses.
    #[test]
    fn canonical_ip_agrees_across_spellings() {
        for (text, want) in [
            ("2001:db8::1", "2001:db8::1"),
            ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
            ("2001:0db8:0000::0001", "2001:db8::1"),
            ("[2001:db8::1]", "2001:db8::1"),
            // ss on a device-bound socket; ipconfig's zone index.
            ("fe80::1%eth0", "fe80::1"),
            ("[fe80::1%12]", "fe80::1"),
            // macOS lsof: no opening bracket, scope embedded in group two.
            ("fe80:16::145f:b7c7:8a9e:7fb7]", "fe80::145f:b7c7:8a9e:7fb7"),
            // A dual-stack socket's IPv4 peer, whichever way it is spelled.
            ("::ffff:192.0.2.10", "192.0.2.10"),
            ("::FFFF:c000:20a", "192.0.2.10"),
            ("192.0.2.10", "192.0.2.10"),
            ("::1", "::1"),
            ("::", "::"),
        ] {
            assert_eq!(canonical_ip(text).as_deref(), Some(want), "{text}");
        }
    }
    #[test]
    fn canonical_ip_leaves_non_addresses_alone() {
        for text in [
            "",
            "*",
            "192.168.",
            "fe80:",
            "example.com",
            "1.2.3.4:443",
            "::1::2",
        ] {
            assert_eq!(canonical_ip(text), None, "{text}");
        }
    }
    /// Only a link-local address has bits a platform may borrow for scope;
    /// the same groups elsewhere are part of the address.
    #[test]
    fn only_link_local_scope_is_cleared() {
        assert_eq!(canonical_ip("2001:16::1").as_deref(), Some("2001:16::1"));
        assert_eq!(canonical_ip("ff02:4::fb").as_deref(), Some("ff02:4::fb"));
    }

    // ── tcp_flags ───────────────────────────────────────────
    #[test]
    fn test_tcp_flags_none() {
        assert_eq!(tcp_flags(0), "NONE");
    }
    #[test]
    fn test_tcp_flags_syn() {
        assert_eq!(tcp_flags(0x02), "SYN");
    }
    #[test]
    fn test_tcp_flags_syn_ack() {
        assert_eq!(tcp_flags(0x12), "SYN,ACK");
    }
    #[test]
    fn test_tcp_flags_fin_ack() {
        assert_eq!(tcp_flags(0x11), "FIN,ACK");
    }
    #[test]
    fn test_tcp_flags_rst() {
        assert_eq!(tcp_flags(0x04), "RST");
    }
    #[test]
    fn test_tcp_flags_all() {
        assert_eq!(tcp_flags(0x3F), "FIN,SYN,RST,PSH,ACK,URG");
    }

    // ── ip_protocol_name ────────────────────────────────────
    #[test]
    fn test_ip_proto_tcp() {
        assert_eq!(ip_protocol_name(6), "TCP");
    }
    #[test]
    fn test_ip_proto_udp() {
        assert_eq!(ip_protocol_name(17), "UDP");
    }
    #[test]
    fn test_ip_proto_icmp() {
        assert_eq!(ip_protocol_name(1), "ICMP");
    }
    #[test]
    fn test_ip_proto_icmpv6() {
        assert_eq!(ip_protocol_name(58), "ICMPv6");
    }
    #[test]
    fn test_ip_proto_unknown() {
        assert_eq!(ip_protocol_name(255), "Proto(255)");
    }

    // ── port_label ──────────────────────────────────────────
    #[test]
    fn test_port_label_known() {
        assert_eq!(port_label(22), "SSH");
        assert_eq!(port_label(53), "DNS");
        assert_eq!(port_label(80), "HTTP");
        assert_eq!(port_label(443), "HTTPS");
    }
    #[test]
    fn test_port_label_unknown() {
        assert_eq!(port_label(12345), "—");
    }

    // ── icmp_type_name ──────────────────────────────────────
    #[test]
    fn test_icmp_echo_request() {
        assert_eq!(icmp_type_name(8, 0), "Echo Request");
    }
    #[test]
    fn test_icmp_echo_reply() {
        assert_eq!(icmp_type_name(0, 0), "Echo Reply");
    }
    #[test]
    fn test_icmp_dest_unreachable_port() {
        assert!(icmp_type_name(3, 3).contains("Port Unreachable"));
    }
    #[test]
    fn test_icmp_ttl_exceeded() {
        assert!(icmp_type_name(11, 0).contains("TTL Exceeded"));
    }

    // ── icmpv6_type_name ────────────────────────────────────
    #[test]
    fn test_icmpv6_echo() {
        assert_eq!(icmpv6_type_name(128), "Echo Request");
        assert_eq!(icmpv6_type_name(129), "Echo Reply");
    }
    #[test]
    fn test_icmpv6_neighbor() {
        assert_eq!(icmpv6_type_name(135), "Neighbor Solicitation");
        assert_eq!(icmpv6_type_name(136), "Neighbor Advertisement");
    }

    // ── classify_expert ─────────────────────────────────────
    #[test]
    fn test_expert_rst_is_error() {
        assert_eq!(
            classify_expert("TCP", "", Some(0x04)),
            ExpertSeverity::Error
        );
    }
    #[test]
    fn test_expert_syn_is_chat() {
        assert_eq!(classify_expert("TCP", "", Some(0x02)), ExpertSeverity::Chat);
    }
    #[test]
    fn test_expert_fin_is_note() {
        assert_eq!(classify_expert("TCP", "", Some(0x01)), ExpertSeverity::Note);
    }
    #[test]
    fn test_expert_dns_nxdomain() {
        assert_eq!(
            classify_expert("DNS", "NXDOMAIN", None),
            ExpertSeverity::Error
        );
    }
    #[test]
    fn test_expert_icmp_unreachable() {
        assert_eq!(
            classify_expert("ICMP", "Dest Unreachable", None),
            ExpertSeverity::Warn
        );
    }
    #[test]
    fn test_expert_http_error() {
        assert_eq!(
            classify_expert("HTTP", "HTTP/1.1 404 Not Found", None),
            ExpertSeverity::Warn
        );
    }
    #[test]
    fn test_expert_zero_window() {
        assert_eq!(
            classify_expert("TCP", "Win=0 Len=0", Some(0x10)),
            ExpertSeverity::Warn
        );
    }

    // ── parse_arp ───────────────────────────────────────────
    #[test]
    fn test_arp_request() {
        let mut data = [0u8; 28];
        data[6] = 0;
        data[7] = 1; // op = request
        data[8..14].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        data[14..18].copy_from_slice(&[192, 168, 1, 1]);
        data[24..28].copy_from_slice(&[192, 168, 1, 2]);
        let mut details = vec![];
        let info = parse_arp(&data, &mut details);
        assert!(info.contains("Who has 192.168.1.2"));
        assert!(info.contains("Tell 192.168.1.1"));
    }
    #[test]
    fn test_arp_reply() {
        let mut data = [0u8; 28];
        data[6] = 0;
        data[7] = 2; // op = reply
        data[8..14].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        data[14..18].copy_from_slice(&[192, 168, 1, 1]);
        let mut details = vec![];
        let info = parse_arp(&data, &mut details);
        assert!(info.contains("192.168.1.1 is at"));
    }
    #[test]
    fn test_arp_truncated() {
        let mut details = vec![];
        let info = parse_arp(&[0; 10], &mut details);
        assert!(info.contains("truncated"));
    }

    // ── extract_readable_payload ────────────────────────────
    #[test]
    fn test_readable_text_payload() {
        let payload = b"Hello, World! This is readable text.";
        let result = extract_readable_payload(payload);
        assert!(result.contains("Hello, World!"));
    }
    #[test]
    fn test_readable_binary_payload() {
        let payload: Vec<u8> = vec![0u8; 100];
        let result = extract_readable_payload(&payload);
        assert!(result.contains("binary data"));
    }
    #[test]
    fn test_readable_empty_payload() {
        assert_eq!(extract_readable_payload(&[]), String::new());
    }
    /// A tab inside the text is a visible `·` (ratatui would drop a raw one);
    /// tabs at either end are trimmed with the rest of the whitespace.
    #[test]
    fn test_readable_payload_shows_tabs() {
        assert_eq!(
            extract_readable_payload(b"\tid\tname\n\t\tindented\t\n"),
            "id·name\n··indented"
        );
    }

    // ── parse_filter / matches_packet ───────────────────────
    #[test]
    fn test_filter_protocol() {
        let f = parse_filter("tcp").unwrap();
        assert!(matches!(f, FilterExpr::Protocol(ref p) if p == "TCP"));
    }
    #[test]
    fn test_filter_src_ip() {
        let f = parse_filter("ip.src == 1.2.3.4").unwrap();
        assert!(matches!(f, FilterExpr::SrcIp(ref ip) if ip == "1.2.3.4"));
    }
    #[test]
    fn test_filter_dst_ip() {
        let f = parse_filter("ip.dst == 10.0.0.1").unwrap();
        assert!(matches!(f, FilterExpr::DstIp(ref ip) if ip == "10.0.0.1"));
    }
    #[test]
    fn test_filter_port() {
        let f = parse_filter("port 80").unwrap();
        assert!(matches!(f, FilterExpr::Port(80)));
    }
    #[test]
    fn test_filter_port_eq() {
        let f = parse_filter("port == 443").unwrap();
        assert!(matches!(f, FilterExpr::Port(443)));
    }
    #[test]
    fn test_filter_stream() {
        let f = parse_filter("stream 5").unwrap();
        assert!(matches!(f, FilterExpr::Stream(5)));
    }
    #[test]
    fn test_filter_bare_ip() {
        let f = parse_filter("192.168.1.1").unwrap();
        assert!(matches!(f, FilterExpr::Ip(ref ip) if ip == "192.168.1.1"));
    }
    #[test]
    fn test_filter_and() {
        let f = parse_filter("tcp and port 80").unwrap();
        assert!(matches!(f, FilterExpr::And(_, _)));
    }
    #[test]
    fn test_filter_or() {
        let f = parse_filter("dns or http").unwrap();
        assert!(matches!(f, FilterExpr::Or(_, _)));
    }
    #[test]
    fn test_filter_not() {
        let f = parse_filter("! tcp").unwrap();
        assert!(matches!(f, FilterExpr::Not(_)));
    }
    #[test]
    fn test_filter_empty() {
        assert!(parse_filter("").is_none());
    }
    #[test]
    fn test_filter_ech_true() {
        let f = parse_filter("ech:true").unwrap();
        assert!(matches!(f, FilterExpr::Ech(true)));
    }
    #[test]
    fn test_filter_ech_false() {
        let f = parse_filter("ech:false").unwrap();
        assert!(matches!(f, FilterExpr::Ech(false)));
    }
    #[test]
    fn test_filter_ech_invalid_rejected() {
        // Bad value fails the whole parse; saves the user from a typo
        // (`ech:tru`) silently matching nothing.
        assert!(parse_filter("ech:maybe").is_none());
    }

    #[test]
    fn test_matches_ech_true_on_tls() {
        let mut pkt = make_packet("TCP", "1.1.1.1", "2.2.2.2", Some(1234), Some(443), "");
        pkt.app_protocol = Some(crate::dpi::AppProtocol::Tls {
            sni: Some("cloudflare-ech.com".into()),
            alpn: None,
            ech: true,
            ja4: None,
        });
        assert!(matches_packet(&parse_filter("ech:true").unwrap(), &pkt));
        assert!(!matches_packet(&parse_filter("ech:false").unwrap(), &pkt));
    }
    #[test]
    fn test_matches_ech_true_on_quic() {
        let mut pkt = make_packet("UDP", "1.1.1.1", "2.2.2.2", Some(1234), Some(443), "");
        pkt.app_protocol = Some(crate::dpi::AppProtocol::Quic {
            sni: Some("cloudflare-ech.com".into()),
            ech: true,
            ja4: None,
        });
        assert!(matches_packet(&parse_filter("ech:true").unwrap(), &pkt));
    }
    #[test]
    fn test_matches_ech_false_on_vanilla_tls() {
        let mut pkt = make_packet("TCP", "1.1.1.1", "2.2.2.2", Some(1234), Some(443), "");
        pkt.app_protocol = Some(crate::dpi::AppProtocol::Tls {
            sni: Some("example.com".into()),
            alpn: None,
            ech: false,
            ja4: None,
        });
        assert!(matches_packet(&parse_filter("ech:false").unwrap(), &pkt));
        assert!(!matches_packet(&parse_filter("ech:true").unwrap(), &pkt));
    }
    #[test]
    fn test_matches_ech_never_matches_non_tls_quic() {
        // Non-TLS/QUIC packets must not be selected by `ech:false` —
        // "show me everything without ECH" should not include HTTP, DNS,
        // ICMP, etc. The flag is only meaningful for TLS/QUIC.
        let pkt = make_packet("TCP", "1.1.1.1", "2.2.2.2", Some(1234), Some(80), "");
        assert!(!matches_packet(&parse_filter("ech:false").unwrap(), &pkt));
        assert!(!matches_packet(&parse_filter("ech:true").unwrap(), &pkt));
    }
    #[test]
    fn test_filter_ech_composable() {
        // `ech:true and sni:cloudflare` should select ECH-using flows
        // whose outer SNI mentions cloudflare. Tests parser glue.
        let f = parse_filter("ech:true and sni:cloudflare").unwrap();
        assert!(matches!(f, FilterExpr::And(_, _)));
    }

    #[test]
    fn test_filter_decrypted_parses() {
        assert!(matches!(
            parse_filter("decrypted:true").unwrap(),
            FilterExpr::Decrypted(true)
        ));
        assert!(matches!(
            parse_filter("decrypted:false").unwrap(),
            FilterExpr::Decrypted(false)
        ));
        // Typos must fail the parse, not silently match nothing.
        assert!(parse_filter("decrypted:yes").is_none());
    }

    #[test]
    fn test_matches_decrypted_true_only_on_decrypted_packets() {
        let mut pkt = make_packet("TCP", "1.1.1.1", "2.2.2.2", Some(1234), Some(443), "");
        // No plaintext yet → only decrypted:false matches.
        assert!(!matches_packet(
            &parse_filter("decrypted:true").unwrap(),
            &pkt
        ));
        assert!(matches_packet(
            &parse_filter("decrypted:false").unwrap(),
            &pkt
        ));

        pkt.decrypted_plaintext = Some(b"GET / HTTP/1.1\r\n".to_vec());
        assert!(matches_packet(
            &parse_filter("decrypted:true").unwrap(),
            &pkt
        ));
        assert!(!matches_packet(
            &parse_filter("decrypted:false").unwrap(),
            &pkt
        ));
    }

    #[test]
    fn test_contains_searches_decrypted_plaintext() {
        let mut pkt = make_packet("TCP", "1.1.1.1", "2.2.2.2", Some(1234), Some(443), "");
        pkt.decrypted_plaintext = Some(b"GET /secret HTTP/1.1\r\nHost: x\r\n".to_vec());
        // The needle exists only in the decrypted body, not info/payload_text.
        assert!(matches_packet(
            &parse_filter("contains \"/secret\"").unwrap(),
            &pkt
        ));
    }

    #[test]
    fn test_filter_ja4_substring_match() {
        let f = parse_filter("ja4:t13d").unwrap();
        assert!(matches!(f, FilterExpr::Ja4(ref s) if s == "t13d"));
    }
    #[test]
    fn test_matches_ja4_substring() {
        let mut pkt = make_packet("TCP", "1.1.1.1", "2.2.2.2", Some(1234), Some(443), "");
        pkt.app_protocol = Some(crate::dpi::AppProtocol::Tls {
            sni: Some("example.com".into()),
            alpn: None,
            ech: false,
            ja4: Some("t13d1517h2_8daaf6152771_b1ff8ab2d16f".into()),
        });
        // Substring match — pivot from one observed JA4 to all similar.
        assert!(matches_packet(
            &parse_filter("ja4:t13d1517h2").unwrap(),
            &pkt
        ));
        assert!(matches_packet(
            &parse_filter("ja4:8daaf6152771").unwrap(),
            &pkt
        ));
        // Case-insensitive (we lowercase both sides).
        assert!(matches_packet(
            &parse_filter("ja4:T13D1517H2").unwrap(),
            &pkt
        ));
        // Non-matching JA4.
        assert!(!matches_packet(
            &parse_filter("ja4:t12d0301").unwrap(),
            &pkt
        ));
    }
    #[test]
    fn test_matches_ja4_misses_when_ja4_is_none() {
        // A QUIC packet whose ja4 field is None (reassembly hadn't
        // produced a parseable ClientHello yet) must not match the
        // ja4: filter regardless of needle.
        let mut pkt = make_packet("UDP", "1.1.1.1", "2.2.2.2", Some(1234), Some(443), "");
        pkt.app_protocol = Some(crate::dpi::AppProtocol::Quic {
            sni: Some("example.com".into()),
            ech: false,
            ja4: None,
        });
        assert!(!matches_packet(
            &parse_filter("ja4:anything").unwrap(),
            &pkt
        ));
    }
    #[test]
    fn test_matches_ja4_on_quic_when_ja4_populated() {
        // JA4Q populated on a QUIC stream should match the same way as TLS-TCP JA4.
        let mut pkt = make_packet("UDP", "1.1.1.1", "2.2.2.2", Some(1234), Some(443), "");
        pkt.app_protocol = Some(crate::dpi::AppProtocol::Quic {
            sni: Some("crypto.cloudflare.com".into()),
            ech: false,
            ja4: Some("q13d0312h3_55b375c5d22e_06cda9e17597".into()),
        });
        assert!(matches_packet(
            &parse_filter("ja4:q13d0312h3").unwrap(),
            &pkt
        ));
        assert!(matches_packet(&parse_filter("ja4:q13d").unwrap(), &pkt));
    }

    #[test]
    fn test_matches_protocol() {
        let pkt = make_packet("TCP", "1.1.1.1", "2.2.2.2", Some(1234), Some(80), "");
        let f = parse_filter("tcp").unwrap();
        assert!(matches_packet(&f, &pkt));
        let f2 = parse_filter("udp").unwrap();
        assert!(!matches_packet(&f2, &pkt));
    }
    #[test]
    fn test_matches_port() {
        let pkt = make_packet("TCP", "1.1.1.1", "2.2.2.2", Some(1234), Some(443), "");
        assert!(matches_packet(&parse_filter("port 443").unwrap(), &pkt));
        assert!(matches_packet(&parse_filter("port 1234").unwrap(), &pkt));
        assert!(!matches_packet(&parse_filter("port 80").unwrap(), &pkt));
    }
    #[test]
    fn test_matches_ip() {
        let pkt = make_packet("TCP", "10.0.0.1", "8.8.8.8", None, None, "");
        assert!(matches_packet(&parse_filter("10.0.0.1").unwrap(), &pkt));
        assert!(matches_packet(&parse_filter("8.8.8.8").unwrap(), &pkt));
        assert!(!matches_packet(&parse_filter("1.2.3.4").unwrap(), &pkt));
    }
    #[test]
    fn test_matches_and() {
        let pkt = make_packet("TCP", "1.1.1.1", "2.2.2.2", Some(1234), Some(80), "");
        assert!(matches_packet(
            &parse_filter("tcp and port 80").unwrap(),
            &pkt
        ));
        assert!(!matches_packet(
            &parse_filter("udp and port 80").unwrap(),
            &pkt
        ));
    }
    #[test]
    fn test_matches_not() {
        let pkt = make_packet("TCP", "1.1.1.1", "2.2.2.2", None, None, "");
        assert!(matches_packet(&parse_filter("! udp").unwrap(), &pkt));
        assert!(!matches_packet(&parse_filter("! tcp").unwrap(), &pkt));
    }

    // ── StreamKey ───────────────────────────────────────────
    #[test]
    fn test_stream_key_normalization() {
        let k1 = StreamKey::new(StreamProtocol::Tcp, "1.1.1.1", 80, "2.2.2.2", 1234);
        let k2 = StreamKey::new(StreamProtocol::Tcp, "2.2.2.2", 1234, "1.1.1.1", 80);
        assert_eq!(k1, k2);
    }
    #[test]
    fn test_stream_key_different_proto() {
        let k1 = StreamKey::new(StreamProtocol::Tcp, "1.1.1.1", 80, "2.2.2.2", 1234);
        let k2 = StreamKey::new(StreamProtocol::Udp, "1.1.1.1", 80, "2.2.2.2", 1234);
        assert_ne!(k1, k2);
    }

    // ── TcpHandshake ────────────────────────────────────────
    #[test]
    fn test_handshake_timing() {
        let hs = TcpHandshake {
            syn_ns: 1_000_000,
            syn_ack_ns: Some(2_000_000),
            ack_ns: Some(3_000_000),
        };
        assert!((hs.syn_to_syn_ack_ms().unwrap() - 1.0).abs() < 0.001);
        assert!((hs.syn_ack_to_ack_ms().unwrap() - 1.0).abs() < 0.001);
        assert!((hs.total_ms().unwrap() - 2.0).abs() < 0.001);
    }
    #[test]
    fn test_handshake_incomplete() {
        let hs = TcpHandshake {
            syn_ns: 1_000_000,
            syn_ack_ns: None,
            ack_ns: None,
        };
        assert!(hs.syn_to_syn_ack_ms().is_none());
        assert!(hs.total_ms().is_none());
    }

    // ── StreamTracker ───────────────────────────────────────
    #[test]
    fn test_stream_tracker_basic() {
        let mut tracker = StreamTracker::new();
        let idx = tracker.track_packet(
            "1.1.1.1",
            1234,
            "2.2.2.2",
            80,
            StreamProtocol::Tcp,
            b"hello",
            1,
            "00:00:00",
            Some(0x02),
            None,
            1_000_000,
        );
        assert_eq!(idx, 0);
        let stream = tracker.get_stream(0).unwrap();
        assert_eq!(stream.packet_count, 1);
        assert!(stream.handshake.is_some());
    }
    #[test]
    fn test_stream_tracker_same_stream() {
        let mut tracker = StreamTracker::new();
        let i1 = tracker.track_packet(
            "1.1.1.1",
            1234,
            "2.2.2.2",
            80,
            StreamProtocol::Tcp,
            b"",
            1,
            "t",
            None,
            None,
            0,
        );
        let i2 = tracker.track_packet(
            "2.2.2.2",
            80,
            "1.1.1.1",
            1234,
            StreamProtocol::Tcp,
            b"",
            2,
            "t",
            None,
            None,
            0,
        );
        assert_eq!(i1, i2);
        assert_eq!(tracker.get_stream(i1).unwrap().packet_count, 2);
    }
    #[test]
    fn test_stream_tracker_handshake() {
        let mut tracker = StreamTracker::new();
        tracker.track_packet(
            "1.1.1.1",
            1234,
            "2.2.2.2",
            80,
            StreamProtocol::Tcp,
            b"",
            1,
            "t",
            Some(0x02),
            None,
            1_000_000,
        );
        tracker.track_packet(
            "2.2.2.2",
            80,
            "1.1.1.1",
            1234,
            StreamProtocol::Tcp,
            b"",
            2,
            "t",
            Some(0x12),
            None,
            2_000_000,
        );
        tracker.track_packet(
            "1.1.1.1",
            1234,
            "2.2.2.2",
            80,
            StreamProtocol::Tcp,
            b"",
            3,
            "t",
            Some(0x10),
            None,
            3_000_000,
        );
        let hs = tracker.get_stream(0).unwrap().handshake.as_ref().unwrap();
        assert_eq!(hs.syn_ns, 1_000_000);
        assert_eq!(hs.syn_ack_ns, Some(2_000_000));
        assert_eq!(hs.ack_ns, Some(3_000_000));
    }
    #[test]
    fn reused_tuple_and_capture_clear_get_new_generations() {
        let mut tracker = StreamTracker::new();
        let mut packet = |flags, seq, ns| {
            tracker.track_packet(
                "127.0.0.1",
                42000,
                "127.0.0.1",
                80,
                StreamProtocol::Tcp,
                b"",
                1,
                "t",
                Some(flags),
                Some(seq),
                ns,
            )
        };
        let initial = packet(2, 10, 1);
        assert_eq!(initial, packet(2, 10, 2), "SYN retransmission");
        let reused = packet(2, 99, 3);
        assert_ne!(initial, reused);
        assert_ne!(reused, packet(2, 100, 4));
        tracker.clear();
        let after_clear = tracker.track_packet(
            "127.0.0.1",
            42000,
            "127.0.0.1",
            80,
            StreamProtocol::Tcp,
            b"",
            1,
            "t",
            Some(2),
            Some(100),
            5,
        );
        assert!(after_clear > reused);
    }
    #[test]
    fn idle_udp_tuple_gets_new_generation() {
        let mut tracker = StreamTracker::new();
        let a = tracker.track_packet(
            "127.0.0.1",
            42000,
            "127.0.0.1",
            53,
            StreamProtocol::Udp,
            b"hello",
            1,
            "t",
            None,
            None,
            1,
        );
        let b = tracker.track_packet(
            "127.0.0.1",
            42000,
            "127.0.0.1",
            53,
            StreamProtocol::Udp,
            b"hello",
            2,
            "t",
            None,
            None,
            61_000_000_001,
        );
        assert_ne!(a, b);
        assert_eq!(tracker.snapshot_bytes().values().next(), Some(&(0, 5)));
    }
    #[test]
    fn stream_index_exhaustion_resets_without_aliasing() {
        let first: Arc<str> = "capture-a".into();
        let tracker = Mutex::new(StreamTracker::new());
        {
            let mut t = tracker.lock().unwrap();
            t.session = Some(Arc::clone(&first));
            t.next_index = u32::MAX - 1;
        }
        let counter = Arc::new(Mutex::new(0));
        let dns = DnsCache::new();
        let udp_from = |port: u16| {
            let mut frame = UDP_FRAME;
            frame[34..36].copy_from_slice(&port.to_be_bytes());
            let mut meta = metadata(1);
            meta.session = Arc::clone(&first);
            let frame = Frame {
                data: &frame,
                ethernet: true,
                capture: Some(meta),
            };
            decode_and_track(frame, &counter, &dns, &tracker).unwrap()
        };
        let session = |p: &CapturedPacket| Arc::clone(&p.capture.as_ref().unwrap().session);

        let last = udp_from(1000);
        assert_eq!(last.stream_index, Some(u32::MAX - 1));
        assert!(Arc::ptr_eq(&session(&last), &first));
        // The next new flow finds no index left, since u32::MAX is never
        // handed out, and numbering restarts under a new session.
        let restart = udp_from(2000);
        assert_eq!(restart.stream_index, Some(0));
        let second = session(&restart);
        assert_ne!(second, first);
        // The flow from before is forgotten rather than found under its old
        // index, and numbered afresh in the new session.
        let again = udp_from(1000);
        assert_eq!(again.stream_index, Some(1));
        assert!(Arc::ptr_eq(&session(&again), &second));
        let t = tracker.lock().unwrap();
        assert!(t.get_stream(u32::MAX - 1).is_none());
        assert_eq!(t.all_streams.len(), 2);
        drop(t);

        // The session the incident recorder samples moves on with it.
        let collector = PacketCollector::new();
        {
            let mut t = collector.stream_tracker.lock().unwrap();
            t.session = Some(Arc::clone(&first));
            t.next_index = u32::MAX;
        }
        collector.ingest_frame_for_test(&UDP_FRAME).unwrap();
        let now = collector.capture_session().unwrap();
        assert_ne!(now, *first);
        // Replay and --demo have no session and get none.
        let mut tracker = StreamTracker::new();
        tracker.next_index = u32::MAX;
        let idx = tracker.track_packet(
            "127.0.0.1",
            1,
            "127.0.0.1",
            2,
            StreamProtocol::Udp,
            b"",
            1,
            "t",
            None,
            None,
            1,
        );
        assert_eq!((idx, tracker.session.is_none()), (0, true));
    }
    #[test]
    fn pcap_counter_wrap_keeps_totals_monotonic() {
        let collector = PacketCollector::new();
        let stats = &collector.stats;
        let reading = |received, dropped, if_dropped| pcap::Stat {
            received,
            dropped,
            if_dropped,
        };
        let mut last = reading(0, 0, 0);
        // Climb near the top of the range in two polls. One poll that moved
        // 2^31 or more would read as the counter going back.
        stats.record_poll(&mut last, reading(u32::MAX / 2, u32::MAX / 2, 7), 1, 1.0);
        stats.record_poll(&mut last, reading(u32::MAX - 999, u32::MAX - 9, 7), 5, 1.0);
        let (received, dropped, decoded) = collector.capture_totals();
        assert_eq!(received, u64::from(u32::MAX - 999));
        assert_eq!(dropped, u64::from(u32::MAX - 9) + 7);
        assert_eq!(decoded, 5);

        // libpcap's u32 counters wrap between two polls.
        stats.record_poll(&mut last, reading(1000, 10, 7), 9, 1.0);
        assert_eq!(
            collector.capture_totals(),
            (received + 2000, dropped + 20, 9)
        );
        assert!(stats.received() > u64::from(u32::MAX));
        assert_eq!(stats.rate_pps(), 2000, "the wrap reads as a rate, not 0");
        assert_eq!(stats.observed_drops(), Some(dropped + 20));

        // A counter moving back is a re-arm, not four billion packets.
        stats.record_poll(&mut last, reading(400, 10, 7), 9, 1.0);
        assert_eq!(stats.received(), received + 2000);
        assert_eq!(stats.rate_pps(), 0);
        stats.record_poll(&mut last, reading(700, 10, 7), 9, 1.0);
        assert_eq!(stats.received(), received + 2300);

        stats.reset();
        assert_eq!(collector.capture_totals(), (0, 0, 0));
        assert_eq!(stats.observed_drops(), None);
    }

    #[test]
    fn test_stream_tracker_clear() {
        let mut tracker = StreamTracker::new();
        tracker.track_packet(
            "1.1.1.1",
            1234,
            "2.2.2.2",
            80,
            StreamProtocol::Tcp,
            b"",
            1,
            "t",
            None,
            None,
            0,
        );
        tracker.clear();
        assert!(tracker.all_streams.is_empty());
        assert!(tracker.get_stream(0).is_none());
    }

    #[test]
    fn test_stream_tracker_caps_unique_streams() {
        // Push far more unique flows than the cap allows. Memory must stay
        // bounded by MAX_STREAMS + STREAM_EVICT_BATCH (the high-water mark);
        // both the position map and the secondary key→idx map must shrink.
        let mut tracker = StreamTracker::new();
        let total = (MAX_STREAMS + STREAM_EVICT_BATCH) * 4;
        for i in 0..total {
            let src = format!("10.0.{}.{}", (i / 256) & 0xFF, i & 0xFF);
            tracker.track_packet(
                &src,
                12345,
                "1.2.3.4",
                80,
                StreamProtocol::Tcp,
                b"",
                i as u64,
                "t",
                Some(TCP_FLAG_SYN),
                None,
                i as u64, // monotonic timestamp_ns: later i => more recent
            );
        }
        let high_water = MAX_STREAMS + STREAM_EVICT_BATCH;
        assert!(
            tracker.all_streams.len() <= high_water,
            "all_streams grew past high-water mark: {}",
            tracker.all_streams.len()
        );
        assert_eq!(
            tracker.streams.len(),
            tracker.all_streams.len(),
            "streams key map drifted from all_streams"
        );
        // Surviving streams must be the most-recent ones; the very first
        // packet's flow was inserted long ago and should have been evicted.
        let first_flow_key = StreamKey::new(StreamProtocol::Tcp, "10.0.0.0", 12345, "1.2.3.4", 80);
        assert!(
            !tracker.streams.contains_key(&first_flow_key),
            "oldest flow was not evicted"
        );
    }

    /// One packet carrying `payload` on flow `port`, seen at `ns`.
    fn track_on(tracker: &mut StreamTracker, port: u16, payload: &[u8], ns: u64) -> u32 {
        tracker.track_packet(
            "10.0.0.1",
            port,
            "10.0.0.2",
            80,
            StreamProtocol::Tcp,
            payload,
            ns,
            "t",
            Some(TCP_FLAG_ACK),
            Some(1),
            ns,
        )
    }

    #[test]
    fn byte_budget_evicts_the_least_recently_seen_streams() {
        // Well under the per-stream and stream-count caps: only the global
        // budget can stop this.
        let mut tracker = StreamTracker::new();
        tracker.byte_budget = 64 * 1024;
        let payload = [0x41u8; 1000];
        for i in 0..100u16 {
            track_on(&mut tracker, 40_000 + i, &payload, u64::from(i));
            assert!(tracker.held_bytes <= tracker.byte_budget);
        }
        assert_eq!(
            tracker.held_bytes,
            tracker
                .all_streams
                .values()
                .map(|s| s.held_bytes)
                .sum::<usize>(),
            "the running total drifted from the streams'"
        );
        assert_eq!(tracker.streams.len(), tracker.all_streams.len());
        // The oldest flows went; the newest, and every flow after the oldest
        // survivor, stayed.
        assert!(tracker.get_stream(0).is_none());
        let oldest = *tracker.all_streams.keys().min().unwrap();
        assert!((oldest..100).all(|i| tracker.get_stream(i).is_some()));
    }

    #[test]
    fn byte_budget_counts_overhead_and_decrypted_text() {
        let mut tracker = StreamTracker::new();
        let idx = track_on(&mut tracker, 40_000, b"x", 1);
        // A one-byte payload still costs its segment's fixed size.
        assert!(tracker.held_bytes > std::mem::size_of::<StreamSegment>());
        let before = tracker.held_bytes;
        tracker.attach_segment_decrypted(idx, 1, vec![0; 5000]);
        assert_eq!(tracker.held_bytes, before + 5000);
        tracker.clear();
        assert_eq!(tracker.held_bytes, 0);
    }

    #[test]
    fn get_stream_shares_segments_instead_of_copying_them() {
        let collector = PacketCollector::new();
        let idx = track_on(
            &mut collector.stream_tracker.lock().unwrap(),
            40_000,
            b"payload",
            1,
        );
        let (a, b) = (
            collector.get_stream(idx).unwrap(),
            collector.get_stream(idx).unwrap(),
        );
        assert!(Arc::ptr_eq(&a.segments[0], &b.segments[0]));
        // Attaching plaintext afterwards copies that one segment, leaving the
        // UI's copy as it was.
        collector
            .stream_tracker
            .lock()
            .unwrap()
            .attach_segment_decrypted(idx, 1, b"plain".to_vec());
        assert!(a.segments[0].decrypted.is_none());
        let c = collector.get_stream(idx).unwrap();
        assert_eq!(c.segments[0].decrypted.as_deref(), Some(&b"plain"[..]));
    }

    /// Decrypted 1-RTT frames: one STREAM frame on HTTP/3 request stream 0
    /// carrying a DATA frame with `body` gzipped. Lengths use the two-byte
    /// QUIC varint, so keep the compressed body under 16 KiB.
    fn h3_gzip_response(body: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let varint = |n: usize| (0x4000 | n as u16).to_be_bytes();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(body).unwrap();
        let gz = gz.finish().unwrap();
        let mut data = vec![0x00]; // DATA
        data.extend(varint(gz.len()));
        data.extend(gz);
        let mut frames = vec![0x0e, 0x00, 0x00]; // STREAM with OFF and LEN, id 0, offset 0
        frames.extend(varint(data.len()));
        frames.extend(data);
        frames
    }

    #[test]
    fn http3_buffers_and_decoded_bodies_are_charged() {
        let mut tracker = StreamTracker::new();
        let idx = track_on(&mut tracker, 40_000, b"x", 1);
        let before = tracker.held_bytes;
        let body = b"a decrypted HTTP/3 response body ".repeat(100);
        tracker.ingest_h3(idx, false, &h3_gzip_response(&body));
        let buffered = tracker.quic_h3[&idx].held_bytes();
        assert!(buffered > 0);
        assert_eq!(tracker.held_bytes, before + buffered);

        // Decoding for the UI adds the body, once.
        for _ in 0..2 {
            assert_eq!(tracker.quic_h3_bodies(idx)[0].bytes, body);
            assert_eq!(tracker.held_bytes, before + buffered + body.len());
        }
        assert_eq!(tracker.all_streams[&idx].held_bytes, tracker.held_bytes);

        // Nothing is buffered for a stream the tracker doesn't hold.
        tracker.ingest_h3(idx + 1, false, &h3_gzip_response(&body));
        assert!(!tracker.quic_h3.contains_key(&(idx + 1)));
    }

    /// Give stream `idx` what the tracker holds beside it: TLS keys and an
    /// HTTP/3 reassembler.
    fn hold_keys_and_h3(tracker: &mut StreamTracker, idx: u32) {
        use crate::dpi::tls_decrypt::{CipherSuite, DirectionKeys};
        let keys = || DirectionKeys::from_traffic_secret(CipherSuite::Aes128GcmSha256, &[0; 32]);
        let v13 = TlsStreamKeys::V13 {
            client: keys(),
            server: keys(),
        };
        tracker.tls_keys.insert(idx, v13);
        tracker.ingest_h3(idx, false, &h3_gzip_response(b"body"));
        assert!(tracker.quic_h3.contains_key(&idx));
    }

    #[test]
    fn eviction_frees_a_streams_tls_keys_and_http3_buffers() {
        // By the byte budget: 99 newer flows of 1000 bytes each.
        let mut tracker = StreamTracker::new();
        tracker.byte_budget = 64 * 1024;
        let idx = track_on(&mut tracker, 40_000, b"x", 0);
        hold_keys_and_h3(&mut tracker, idx);
        for i in 1..100u16 {
            track_on(&mut tracker, 40_000 + i, &[0x41; 1000], u64::from(i));
        }
        assert!(tracker.get_stream(idx).is_none());
        assert!(!tracker.tls_keys.contains_key(&idx));
        assert!(!tracker.quic_h3.contains_key(&idx));

        // By the stream count.
        let mut tracker = StreamTracker::new();
        let idx = track_on(&mut tracker, 1, b"x", 0);
        hold_keys_and_h3(&mut tracker, idx);
        for i in 1..=(MAX_STREAMS + STREAM_EVICT_BATCH) as u16 {
            track_on(&mut tracker, 1 + i, b"x", u64::from(i));
        }
        assert!(tracker.get_stream(idx).is_none());
        assert!(!tracker.tls_keys.contains_key(&idx));
        assert!(!tracker.quic_h3.contains_key(&idx));
    }

    // ── Capture-thread panics ───────────────────────────────

    /// Poison `lock` the way a panicking capture step does: by unwinding
    /// while holding it.
    fn poison<T>(lock: &Mutex<T>) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = lock.lock().unwrap();
            panic!("parser bug");
        }));
        assert!(lock.is_poisoned());
    }

    #[test]
    fn stream_accessors_read_through_a_poisoned_tracker() {
        let collector = PacketCollector::new();
        let idx = collector.stream_tracker.lock().unwrap().track_packet(
            "1.1.1.1",
            1234,
            "2.2.2.2",
            443,
            StreamProtocol::Udp,
            b"hello",
            1,
            "t",
            None,
            None,
            0,
        );
        poison(&collector.stream_tracker);
        assert_eq!(collector.get_stream(idx).map(|s| s.packet_count), Some(1));
        assert!(collector.quic_h3_bodies(idx).is_empty());
    }

    #[test]
    fn packet_list_reads_through_a_poisoned_lock() {
        let collector = PacketCollector::new();
        collector.packets.write().unwrap().push(make_packet(
            "TCP",
            "1.1.1.1",
            "2.2.2.2",
            Some(1234),
            Some(80),
            "x",
        ));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = collector.packets.write().unwrap();
            panic!("parser bug");
        }));
        assert!(collector.packets.is_poisoned());
        assert_eq!(collector.get_packets().len(), 1);
        collector.clear();
        assert!(collector.get_packets().is_empty());

        *collector.stats.observed_at.lock().unwrap() = Some(std::time::Instant::now());
        poison(&collector.stats.observed_at);
        collector.stats.reset();
        assert!(collector
            .stats
            .observed_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none());
    }

    #[test]
    fn a_panicking_parser_stops_capture_and_says_why() {
        let capturing = AtomicBool::new(true);
        let error = Mutex::new(None);
        let tracker = Mutex::new(StreamTracker::new());
        let survived = run_capture_step(&capturing, &error, || {
            let _held = tracker.lock().unwrap();
            // A parser bug: cutting a peer's name inside a character.
            let sni = String::from("host.é");
            let _ = &sni[..sni.len() - 1];
        });
        assert!(!survived);
        assert!(!capturing.load(Ordering::SeqCst));
        let message = error.lock().unwrap().clone().unwrap();
        assert!(
            message.starts_with("Capture stopped: internal error: "),
            "{message}"
        );
        assert!(message.contains("not a char boundary"), "{message}");
        // The step unwound through the tracker's guard.
        assert!(tracker.is_poisoned());
    }

    #[test]
    fn a_capture_panic_that_quotes_the_packet_is_made_safe_to_draw() {
        let capturing = AtomicBool::new(true);
        let error = Mutex::new(None);
        let sni = "\u{1b}]52;c;AAAA\u{7}";
        run_capture_step(&capturing, &error, || panic!("unexpected SNI {sni}"));
        assert_eq!(
            error.lock().unwrap().as_deref(),
            Some("Capture stopped: internal error: unexpected SNI ·]52;c;AAAA·")
        );

        // A payload that is not text still says something.
        let capturing = AtomicBool::new(true);
        run_capture_step(&capturing, &error, || std::panic::panic_any(7u8));
        assert_eq!(
            error.lock().unwrap().as_deref(),
            Some("Capture stopped: internal error: unknown panic")
        );
    }

    #[test]
    fn a_capture_step_that_returns_keeps_capturing() {
        let capturing = AtomicBool::new(true);
        let error = Mutex::new(None);
        let mut ran = false;
        assert!(run_capture_step(&capturing, &error, || ran = true));
        assert!(ran);
        assert!(capturing.load(Ordering::SeqCst));
        assert!(error.lock().unwrap().is_none());
    }

    #[test]
    fn a_cancelled_capture_leaves_the_newer_error_alone() {
        let capturing = AtomicBool::new(false);
        let error = Mutex::new(Some("BPF filter error: newer start".to_string()));
        assert!(!run_capture_step(&capturing, &error, || panic!(
            "old worker"
        )));
        assert_eq!(
            error.lock().unwrap().as_deref(),
            Some("BPF filter error: newer start")
        );
    }

    #[test]
    fn snapshot_handshake_rtts_returns_us_for_completed_handshakes() {
        let mut tracker = StreamTracker::new();
        // Completed SYN→SYN-ACK 1ms apart → 1000µs.
        tracker.track_packet(
            "1.1.1.1",
            1234,
            "2.2.2.2",
            80,
            StreamProtocol::Tcp,
            b"",
            0,
            "t",
            Some(TCP_FLAG_SYN),
            None,
            1_000_000,
        );
        tracker.track_packet(
            "2.2.2.2",
            80,
            "1.1.1.1",
            1234,
            StreamProtocol::Tcp,
            b"",
            1,
            "t",
            Some(TCP_FLAG_SYN | TCP_FLAG_ACK),
            None,
            2_000_000,
        );
        // A second flow with only a SYN — no completed handshake, no entry.
        tracker.track_packet(
            "3.3.3.3",
            5555,
            "4.4.4.4",
            80,
            StreamProtocol::Tcp,
            b"",
            2,
            "t",
            Some(TCP_FLAG_SYN),
            None,
            3_000_000,
        );

        let rtts = tracker.snapshot_handshake_rtts();
        assert_eq!(rtts.len(), 1, "only the completed handshake should appear");
        let key = StreamKey::new(StreamProtocol::Tcp, "1.1.1.1", 1234, "2.2.2.2", 80);
        let rtt = rtts.get(&key).copied().expect("handshake rtt present");
        assert!((rtt - 1000.0).abs() < 1.0, "expected ~1000µs, got {rtt}");
    }

    #[test]
    fn test_for_each_new_handshake_rtt_prunes_evicted() {
        // Sample a handshake, then evict that stream by pushing many unseen
        // flows. The next visitor call must drop the stale index from
        // `sampled` so the set doesn't grow unbounded across evictions.
        let mut tracker = StreamTracker::new();
        // Stream 0: full SYN/SYN-ACK so it has a measurable RTT.
        tracker.track_packet(
            "1.1.1.1",
            1234,
            "2.2.2.2",
            80,
            StreamProtocol::Tcp,
            b"",
            0,
            "t",
            Some(TCP_FLAG_SYN),
            None,
            1_000_000,
        );
        tracker.track_packet(
            "2.2.2.2",
            80,
            "1.1.1.1",
            1234,
            StreamProtocol::Tcp,
            b"",
            1,
            "t",
            Some(TCP_FLAG_SYN | TCP_FLAG_ACK),
            None,
            2_000_000,
        );
        let mut sampled = std::collections::HashSet::new();
        let mut hits: Vec<(String, f64)> = Vec::new();
        tracker.for_each_new_handshake_rtt(&mut sampled, |ip, rtt| {
            hits.push((ip.to_string(), rtt));
        });
        assert_eq!(hits.len(), 1);
        assert!(sampled.contains(&0));

        // Now flood with enough new flows to evict index 0. Flood timestamps
        // must exceed stream 0's last_seen_ns (2_000_000) so the LRU sort puts
        // stream 0 in the evict batch.
        let total = MAX_STREAMS + STREAM_EVICT_BATCH * 2;
        let base_ns: u64 = 10_000_000;
        for i in 0..total {
            let src = format!("10.1.{}.{}", (i / 256) & 0xFF, i & 0xFF);
            let ts = base_ns + i as u64;
            tracker.track_packet(
                &src,
                5000,
                "9.9.9.9",
                443,
                StreamProtocol::Tcp,
                b"",
                (10 + i) as u64,
                "t",
                Some(TCP_FLAG_SYN),
                None,
                ts,
            );
        }
        assert!(
            tracker.get_stream(0).is_none(),
            "test setup: stream 0 should be evicted"
        );

        // Visitor must scrub the evicted index from `sampled`.
        tracker.for_each_new_handshake_rtt(&mut sampled, |_, _| {});
        assert!(!sampled.contains(&0), "evicted index leaked in sampled set");
    }

    fn track_tcp_payload(
        tracker: &mut StreamTracker,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        seq: u32,
        payload_len: usize,
        ts_ns: u64,
        id: u64,
    ) -> u32 {
        let payload = vec![0u8; payload_len];
        tracker.track_packet(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            StreamProtocol::Tcp,
            &payload,
            id,
            "t",
            Some(TCP_FLAG_ACK),
            Some(seq),
            ts_ns,
        )
    }

    #[test]
    fn retransmit_counted_for_segment_well_behind_high_water() {
        // High-water at seq+len = 1_000_000 + 200 = 1_000_200. A retransmit
        // of bytes near seq=1000 (well over OOO_WINDOW_BYTES behind) should
        // be classified as retransmit, not OOO.
        let mut tracker = StreamTracker::new();
        let idx = track_tcp_payload(
            &mut tracker,
            "10.0.0.1",
            5000,
            "10.0.0.2",
            80,
            1_000_000,
            200,
            1,
            1,
        );
        // 1_000_200 - 1200 = 999_000 → far beyond OOO_WINDOW_BYTES (65 536).
        track_tcp_payload(
            &mut tracker,
            "10.0.0.1",
            5000,
            "10.0.0.2",
            80,
            1000,
            200,
            2,
            2,
        );

        let stream = tracker.get_stream(idx).unwrap();
        assert_eq!(stream.retransmits_a_to_b, 1);
        assert_eq!(stream.out_of_order_a_to_b, 0);
    }

    #[test]
    fn out_of_order_counted_for_small_backwards_jump() {
        // High-water at seq+len = 1500. A segment with seq+len = 500 is
        // 1000 bytes behind — well within OOO_WINDOW_BYTES (65 536), so
        // it's a network reorder, not a retransmit.
        let mut tracker = StreamTracker::new();
        let idx = track_tcp_payload(
            &mut tracker,
            "10.0.0.1",
            5000,
            "10.0.0.2",
            80,
            1000,
            500,
            1,
            1,
        );
        track_tcp_payload(
            &mut tracker,
            "10.0.0.1",
            5000,
            "10.0.0.2",
            80,
            200,
            300,
            2,
            2,
        );

        let stream = tracker.get_stream(idx).unwrap();
        assert_eq!(stream.out_of_order_a_to_b, 1);
        assert_eq!(stream.retransmits_a_to_b, 0);
    }

    #[test]
    fn pure_acks_do_not_count_as_retransmits() {
        // Three packets with payload_len == 0 (pure ACKs). The high-water
        // mark should never advance, and no retransmits should be counted
        // even when seqs are equal.
        let mut tracker = StreamTracker::new();
        let idx = track_tcp_payload(
            &mut tracker,
            "10.0.0.1",
            5000,
            "10.0.0.2",
            80,
            1000,
            0,
            1,
            1,
        );
        track_tcp_payload(
            &mut tracker,
            "10.0.0.1",
            5000,
            "10.0.0.2",
            80,
            1000,
            0,
            2,
            2,
        );
        track_tcp_payload(
            &mut tracker,
            "10.0.0.1",
            5000,
            "10.0.0.2",
            80,
            1000,
            0,
            3,
            3,
        );

        let stream = tracker.get_stream(idx).unwrap();
        assert_eq!(stream.retransmits_a_to_b, 0);
        assert_eq!(stream.out_of_order_a_to_b, 0);
    }

    #[test]
    fn forward_progress_advances_high_water_without_counting_anomalies() {
        let mut tracker = StreamTracker::new();
        let idx = track_tcp_payload(
            &mut tracker,
            "10.0.0.1",
            5000,
            "10.0.0.2",
            80,
            1000,
            200,
            1,
            1,
        );
        track_tcp_payload(
            &mut tracker,
            "10.0.0.1",
            5000,
            "10.0.0.2",
            80,
            1200,
            200,
            2,
            2,
        );
        track_tcp_payload(
            &mut tracker,
            "10.0.0.1",
            5000,
            "10.0.0.2",
            80,
            1400,
            200,
            3,
            3,
        );

        let stream = tracker.get_stream(idx).unwrap();
        assert_eq!(stream.retransmits_a_to_b, 0);
        assert_eq!(stream.out_of_order_a_to_b, 0);
    }

    #[test]
    fn retransmits_tracked_per_direction() {
        let mut tracker = StreamTracker::new();
        // A→B forward, then A→B retransmit (far behind) → retransmits_a_to_b = 1.
        let idx = track_tcp_payload(
            &mut tracker,
            "10.0.0.1",
            5000,
            "10.0.0.2",
            80,
            1_000_000,
            200,
            1,
            1,
        );
        track_tcp_payload(
            &mut tracker,
            "10.0.0.1",
            5000,
            "10.0.0.2",
            80,
            1000,
            200,
            2,
            2,
        );
        // B→A forward (independent direction).
        track_tcp_payload(
            &mut tracker,
            "10.0.0.2",
            80,
            "10.0.0.1",
            5000,
            5_000_000,
            200,
            3,
            3,
        );
        // B→A retransmit far behind.
        track_tcp_payload(
            &mut tracker,
            "10.0.0.2",
            80,
            "10.0.0.1",
            5000,
            1000,
            200,
            4,
            4,
        );

        let stream = tracker.get_stream(idx).unwrap();
        assert_eq!(stream.retransmits_a_to_b, 1);
        assert_eq!(stream.retransmits_b_to_a, 1);
    }

    #[test]
    fn seq_wraparound_treated_as_forward_progress() {
        // High-water near 32-bit max (0xFFFFFE00 + 0x100 = 0xFFFFFF00).
        // Next segment at seq=0x100, len=0x100 → new high-water 0x200.
        // The signed diff seq_end - h = 0x200 - 0xFFFFFF00 = +0x300 (mod 2^32),
        // i.e. ahead in wraparound space. Should NOT count as retransmit/OOO.
        let mut tracker = StreamTracker::new();
        let idx = track_tcp_payload(
            &mut tracker,
            "10.0.0.1",
            5000,
            "10.0.0.2",
            80,
            0xFFFFFE00,
            0x100,
            1,
            1,
        );
        track_tcp_payload(
            &mut tracker,
            "10.0.0.1",
            5000,
            "10.0.0.2",
            80,
            0x100,
            0x100,
            2,
            2,
        );

        let stream = tracker.get_stream(idx).unwrap();
        assert_eq!(stream.retransmits_a_to_b, 0);
        assert_eq!(stream.out_of_order_a_to_b, 0);
    }

    /// The QUIC Initial fallback reads the SNI with its own walker, so it
    /// needs the same treatment as `dpi::tls`.
    #[test]
    fn quic_fallback_sni_control_characters_are_replaced() {
        let name = b"\x1b]52;c;AAAA\x07.example";
        let mut hello = vec![0x01, 0, 0, 0, 0x03, 0x03];
        hello.extend_from_slice(&[0; 32]); // random
        hello.push(0); // session id
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
        let n = name.len() as u16;
        let mut ext = vec![0x00, 0x00];
        ext.extend_from_slice(&(n + 5).to_be_bytes());
        ext.extend_from_slice(&(n + 3).to_be_bytes());
        ext.push(0); // host_name
        ext.extend_from_slice(&n.to_be_bytes());
        ext.extend_from_slice(name);
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext);
        assert_eq!(
            extract_sni_for_quic(&hello).as_deref(),
            Some("·]52;c;AAAA·.example")
        );
    }

    // ── connection rows join their streams ──────────────────

    /// Ethernet, then IPv4 or IPv6 to match the addresses, then TCP carrying
    /// `payload`: everything the decoder, the stream tracker and DPI read.
    /// Checksums stay zero, as nothing here checks them.
    pub(super) fn tcp_frame(
        src: std::net::SocketAddr,
        dst: std::net::SocketAddr,
        flags: u8,
        (seq, ack): (u32, u32),
        payload: &[u8],
    ) -> Vec<u8> {
        use std::net::IpAddr;
        let mut tcp = Vec::with_capacity(20 + payload.len());
        tcp.extend_from_slice(&src.port().to_be_bytes());
        tcp.extend_from_slice(&dst.port().to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&ack.to_be_bytes());
        tcp.extend_from_slice(&[5 << 4, flags]); // 20-byte header
        tcp.extend_from_slice(&64240u16.to_be_bytes());
        tcp.extend_from_slice(&[0; 4]); // checksum, urgent pointer
        tcp.extend_from_slice(payload);
        let mut frame = vec![0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01];
        match (src.ip(), dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                frame.extend_from_slice(&[0x08, 0x00, 0x45, 0]);
                frame.extend_from_slice(&(20 + tcp.len() as u16).to_be_bytes());
                frame.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
                frame.extend_from_slice(&s.octets());
                frame.extend_from_slice(&d.octets());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                frame.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
                frame.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
                frame.extend_from_slice(&[6, 64]);
                frame.extend_from_slice(&s.octets());
                frame.extend_from_slice(&d.octets());
            }
            _ => panic!("one family per frame"),
        }
        frame.extend_from_slice(&tcp);
        frame
    }

    /// An SSH session's handshake and server banner, replayed through the
    /// capture path. The replay's tracker holds the stream and its DPI label.
    fn replay_ssh(client: &str, server: &str) -> (Replay, Vec<CapturedPacket>) {
        let (c, s) = (client.parse().unwrap(), server.parse().unwrap());
        let replay = Replay::new();
        let packets = [
            tcp_frame(c, s, TCP_FLAG_SYN, (1000, 0), b""),
            tcp_frame(s, c, TCP_FLAG_SYN | TCP_FLAG_ACK, (5000, 1001), b""),
            tcp_frame(c, s, TCP_FLAG_ACK, (1001, 5001), b""),
            tcp_frame(
                s,
                c,
                TCP_FLAG_PSH | TCP_FLAG_ACK,
                (5001, 1001),
                b"SSH-2.0-OpenSSH_9.6\r\n",
            ),
        ]
        .iter()
        .map(|f| replay.frame(f).expect("decodes"))
        .collect();
        (replay, packets)
    }

    /// A connection table row, as the collectors build one.
    fn row(local: &str, remote: &str) -> crate::collectors::connections::Connection {
        crate::collectors::connections::Connection {
            protocol: "TCP".into(),
            local_addr: local.into(),
            remote_addr: remote.into(),
            state: "ESTABLISHED".into(),
            pid: None,
            process_name: None,
            handshake_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
            attribution: Default::default(),
            evidence: Default::default(),
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        }
    }

    /// Every row in `rows` keys to the stream the replayed packets made, with
    /// `local` on its own side, and so finds the stream's bytes and DPI label.
    fn assert_rows_join(
        replay: &Replay,
        packets: &[CapturedPacket],
        local: &str,
        rows: &[(&str, &str)],
    ) {
        use crate::collectors::connections::{connection_stream_key, LocalSide};
        let tracker = replay.tracker.lock().unwrap();
        let (labels, bytes) = (tracker.snapshot_app_protocols(), tracker.snapshot_bytes());
        let local: std::net::SocketAddr = local.parse().unwrap();
        for &(l, r) in rows {
            let (key, side) = connection_stream_key(&row(l, r)).expect("row keys");
            for p in packets {
                let (sp, dp) = (p.src_port.unwrap(), p.dst_port.unwrap());
                let packet_key = StreamKey::new(StreamProtocol::Tcp, &p.src_ip, sp, &p.dst_ip, dp);
                assert_eq!(packet_key, key, "{l} -> {r}");
            }
            let own = match side {
                LocalSide::A => &key.addr_a,
                LocalSide::B => &key.addr_b,
            };
            assert_eq!(own, &(local.ip().to_string(), local.port()), "{l}");
            assert!(bytes.contains_key(&key), "{l}");
            assert!(
                matches!(labels.get(&key), Some(crate::dpi::AppProtocol::Ssh { .. })),
                "{l}"
            );
        }
    }

    /// The regression: capture wrote every IPv6 group out while the
    /// connection table compresses them, so an IPv6 row never found its
    /// stream, packets, DPI label or JA4.
    #[test]
    fn an_ipv6_row_joins_its_packets_stream_and_label() {
        let (replay, packets) = replay_ssh("[2001:db8::10]:50022", "[2001:db8::20]:22");
        assert_eq!(
            (packets[0].src_ip.as_str(), packets[0].dst_ip.as_str()),
            ("2001:db8::10", "2001:db8::20")
        );
        assert_rows_join(
            &replay,
            &packets,
            "[2001:db8::10]:50022",
            &[
                // ss, lsof, IP Helper and the /proc/net fallback.
                ("[2001:db8::10]:50022", "[2001:db8::20]:22"),
                // ss on a socket bound to a device.
                ("[2001:db8::10%eth0]:50022", "[2001:db8::20]:22"),
                // ss -n's occasional unbracketed form.
                ("2001:db8::10:50022", "2001:db8::20:22"),
                // No collector writes this, but it is the same address.
                ("[2001:DB8:0:0:0:0:0:10]:50022", "[2001:0db8::0020]:22"),
            ],
        );
    }

    /// macOS `lsof` drops the opening bracket of a link-local endpoint and
    /// embeds the interface in its second group; neither is on the wire.
    /// Each end of an IPv6 packet's Info line names its peer and port. With
    /// the port appended bare, `2001:db8::20:22` read as another host, and
    /// pasting it into the filter matched nothing.
    #[test]
    fn ipv6_info_names_each_end_with_its_port() {
        let (_, packets) = replay_ssh("[2001:db8::10]:50022", "[2001:db8::20]:22");
        for p in &packets {
            let (src, rest) = p.info.split_once(" → ").expect("two ends");
            let dst = rest.split_whitespace().next().unwrap();
            for (end, ip, port) in [(src, &p.src_ip, p.src_port), (dst, &p.dst_ip, p.dst_port)] {
                let addr: std::net::SocketAddr = end
                    .parse()
                    .unwrap_or_else(|e| panic!("{end}: {e} in {}", p.info));
                assert_eq!(
                    (addr.ip().to_string(), Some(addr.port())),
                    (ip.clone(), port),
                    "{}",
                    p.info
                );
            }
        }
        assert!(packets[3]
            .info
            .starts_with("[2001:db8::20]:22 → [2001:db8::10]:50022 "));
    }

    #[test]
    fn a_macos_link_local_row_joins_its_stream() {
        let (replay, packets) = replay_ssh(
            "[fe80::145f:b7c7:8a9e:7fb7]:50022",
            "[fe80::aede:48ff:fe00:1122]:22",
        );
        assert_rows_join(
            &replay,
            &packets,
            "[fe80::145f:b7c7:8a9e:7fb7]:50022",
            &[
                (
                    "fe80:16::145f:b7c7:8a9e:7fb7]:50022",
                    "fe80:16::aede:48ff:fe00:1122]:22",
                ),
                (
                    "[fe80::145f:b7c7:8a9e:7fb7%en0]:50022",
                    "[fe80::aede:48ff:fe00:1122%en0]:22",
                ),
            ],
        );
    }

    /// A dual-stack socket talking to an IPv4 peer: `ss` prints both ends
    /// v4-mapped, and the packets travel as IPv4.
    #[test]
    fn a_v4_mapped_row_joins_its_ipv4_stream() {
        let (replay, packets) = replay_ssh("192.0.2.10:51234", "198.51.100.7:22");
        assert_eq!(packets[0].src_ip, "192.0.2.10");
        assert_rows_join(
            &replay,
            &packets,
            "192.0.2.10:51234",
            &[
                ("[::ffff:192.0.2.10]:51234", "[::ffff:198.51.100.7]:22"),
                ("192.0.2.10:51234", "198.51.100.7:22"),
            ],
        );
    }

    /// Typed any way, an address finds its packets, and only its own: as
    /// text, `2001:db8::1` is inside `2001:db8::10`.
    #[test]
    fn address_filters_match_ipv6_however_it_is_typed() {
        let (_, packets) = replay_ssh("[2001:db8::10]:50022", "[2001:db8::20]:22");
        let syn = &packets[0];
        let matches = |filter: &str| matches_packet(&parse_filter(filter).unwrap(), syn);
        for filter in [
            "ip.addr == 2001:db8::10",
            "ip.addr == 2001:DB8:0:0:0:0:0:10",
            "ip.addr == 2001:0db8:0000:0000:0000:0000:0000:0010",
            "ip.addr==\"2001:db8::20\"",
            "ip.src == [2001:db8::10]",
            "ip.src == 2001:db8:0:0:0:0:0:10",
            "ip.dst == 2001:db8::20",
            "2001:db8:0:0:0:0:0:20",
            "2001:db8::20 and port 22",
            // A fragment still matches as text.
            "ip.addr == 2001:db8:",
        ] {
            assert!(matches(filter), "{filter}");
        }
        for filter in [
            "ip.addr == 2001:db8::1",
            "ip.addr == 2001:db8:0:0:0:0:0:1",
            "ip.addr == ::10",
            "ip.src == 2001:db8::20",
            "ip.dst == 2001:db8::10",
            "2001:db8::2",
        ] {
            assert!(!matches(filter), "{filter}");
        }
    }

    /// The v4-mapped spelling a dual-stack row shows finds the IPv4 packets,
    /// and a whole IPv4 address no longer matches every address it prefixes.
    #[test]
    fn address_filters_match_ipv4_as_an_address() {
        let (_, packets) = replay_ssh("192.0.2.10:51234", "198.51.100.7:22");
        let syn = &packets[0];
        let matches = |filter: &str| matches_packet(&parse_filter(filter).unwrap(), syn);
        for filter in [
            "ip.addr == ::ffff:192.0.2.10",
            "::ffff:198.51.100.7",
            "192.0.2.10",
            "ip.src == 192.0.2.10",
            "192.0.2.",
        ] {
            assert!(matches(filter), "{filter}");
        }
        for filter in [
            "192.0.2.1",
            "ip.addr == 198.51.100.70",
            "ip.dst == 192.0.2.10",
        ] {
            assert!(!matches(filter), "{filter}");
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn failed_capture_preparation_can_be_stopped_and_retried() {
        let mut collector = PacketCollector::new();
        for _ in 0..2 {
            let previous_generation = Arc::clone(&collector.capturing);
            collector.start_capture("netwatch-pr04-nonexistent-interface", None);
            assert!(
                !previous_generation.load(Ordering::SeqCst),
                "restart revived the cancelled generation"
            );
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while collector.capturing.load(Ordering::SeqCst) && std::time::Instant::now() < deadline
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert!(
                !collector.is_capturing(),
                "failed preparation must clear capture state"
            );
            assert!(collector.get_error().is_some());
            assert!(collector.packets.read().unwrap().is_empty());
            collector.stop_capture();
        }
    }
}
