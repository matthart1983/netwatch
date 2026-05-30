use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

const MAX_PACKETS: usize = 5000; // ring buffer; oldest packets are discarded when full
const MAX_STREAM_SEGMENTS: usize = 10_000; // per-stream segment limit; caps memory per flow
const MAX_STREAM_BYTES: usize = 2 * 1024 * 1024; // 2 MB per reassembled stream
                                                 // StreamTracker eviction: cap unique flows to bound memory under sustained capture.
                                                 // When `all_streams.len()` exceeds MAX_STREAMS + STREAM_EVICT_BATCH we drop the
                                                 // STREAM_EVICT_BATCH least-recently-seen flows in one sweep (amortized O(1) per
                                                 // insert). Stream u32 indices are never reused, so evicted indices stay invalid.
pub(crate) const MAX_STREAMS: usize = 1024;
pub(crate) const STREAM_EVICT_BATCH: usize = 256;
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

#[derive(Debug, Clone)]
pub struct StreamSegment {
    #[allow(dead_code)]
    pub packet_id: u64,
    #[allow(dead_code)]
    pub timestamp: String,
    pub direction: StreamDirection,
    pub payload: Vec<u8>,
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

#[derive(Debug, Clone)]
pub struct Stream {
    #[allow(dead_code)]
    pub index: u32,
    pub key: StreamKey,
    pub segments: Vec<StreamSegment>,
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
    /// Monotonic ns timestamp of the last packet seen on this flow. Drives LRU
    /// eviction when the tracker exceeds MAX_STREAMS.
    last_seen_ns: u64,
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
    /// Negotiated TLS 1.3 cipher suite (raw u16 from ServerHello).
    /// The keylog provides AEAD secrets but not the chosen cipher,
    /// so we read it off the wire.
    pub tls_cipher_suite: Option<u16>,
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
}

/// Per-stream AEAD state for TLS 1.3 application data. Held in
/// `StreamTracker.tls_keys` rather than on `Stream` because the
/// underlying `aead::LessSafeKey` isn't `Clone`.
pub struct TlsStreamKeys {
    pub client: crate::dpi::tls_decrypt::DirectionKeys,
    pub server: crate::dpi::tls_decrypt::DirectionKeys,
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
            tls_keys: HashMap::new(),
            keylog: crate::dpi::tls_decrypt::KeylogStore::new(),
        }
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
            if let Some(s) = self.all_streams.remove(&idx) {
                self.streams.remove(&s.key);
            }
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

        let stream_index = if let Some(&idx) = self.streams.get(&key) {
            idx
        } else {
            let idx = self.next_index;
            self.next_index += 1;
            self.streams.insert(key.clone(), idx);
            self.all_streams.insert(
                idx,
                Stream {
                    index: idx,
                    key: key.clone(),
                    segments: Vec::new(),
                    total_bytes_a_to_b: 0,
                    total_bytes_b_to_a: 0,
                    packet_count: 0,
                    initiator: None,
                    total_payload_bytes: 0,
                    handshake: None,
                    last_seen_ns: timestamp_ns,
                    app_protocol: None,
                    app_protocol_attempted: false,
                    quic_crypto_buf: Vec::new(),
                    highest_seq_a_to_b: None,
                    highest_seq_b_to_a: None,
                    retransmits_a_to_b: 0,
                    retransmits_b_to_a: 0,
                    out_of_order_a_to_b: 0,
                    out_of_order_b_to_a: 0,
                    tls_client_random: None,
                    tls_cipher_suite: None,
                    tls_decrypt_disabled: false,
                },
            );
            self.evict_if_needed();
            idx
        };

        let stream = match self.all_streams.get_mut(&stream_index) {
            Some(s) => s,
            // Race: stream was just evicted. Skip update; the next packet on
            // this flow will allocate a fresh index.
            None => return stream_index,
        };
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

        // TLS 1.3 decryption: opportunistically capture client_random
        // from any ClientHello we see, and cipher_suite from any
        // ServerHello. Both are plaintext on TLS 1.3 (handshakes start
        // unencrypted). Both can land on the same flow but on
        // different packets, so we check on every payload until both
        // are populated.
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
            stream.segments.push(StreamSegment {
                packet_id,
                timestamp: timestamp.to_string(),
                direction,
                payload: payload.to_vec(),
            });
        }

        stream_index
    }

    pub fn get_stream(&self, index: u32) -> Option<&Stream> {
        self.all_streams.get(&index)
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

        // Lazy-derive AEAD keys once the keylog has this flow's secrets.
        if !self.tls_keys.contains_key(&stream_index) {
            // First, pull the handshake-derived inputs off the stream and
            // latch off streams that can never be decrypted.
            let (cr, suite) = {
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
                let Some(suite) = crate::dpi::tls_decrypt::CipherSuite::from_wire(cs_raw) else {
                    stream.tls_decrypt_disabled = true;
                    tracing::trace!(target: "netwatch::dpi::tls_decrypt", stream_index, cs=%format!("0x{:04x}", cs_raw), "disable: cipher_suite not in TLS 1.3 support list");
                    return None;
                };
                (cr, suite)
            };

            // A keylog miss (or a half-written entry) is retryable — the
            // watcher may not have ingested the secret yet. Do NOT latch.
            let secrets = self.keylog.lookup(&cr)?;
            let (Some(client_app), Some(server_app)) =
                (secrets.client_application, secrets.server_application)
            else {
                tracing::trace!(target: "netwatch::dpi::tls_decrypt", stream_index, cr_prefix=%hex_prefix(&cr), "retry: keylog hit but app-traffic secrets incomplete");
                return None;
            };
            let client =
                crate::dpi::tls_decrypt::DirectionKeys::from_traffic_secret(suite, &client_app);
            let server =
                crate::dpi::tls_decrypt::DirectionKeys::from_traffic_secret(suite, &server_app);
            tracing::debug!(target: "netwatch::dpi::tls_decrypt", stream_index, cr_prefix=%hex_prefix(&cr), "derived AEAD keys — decryption ready");
            self.tls_keys
                .insert(stream_index, TlsStreamKeys { client, server });
        }

        let keys = self.tls_keys.get_mut(&stream_index)?;
        let dir = if client_to_server {
            &mut keys.client
        } else {
            &mut keys.server
        };
        match dir.decrypt_record_resync(aad, ciphertext_src, TLS_RESYNC_WINDOW) {
            Ok(inner) => {
                tracing::trace!(target: "netwatch::dpi::tls_decrypt", stream_index, client_to_server, plain_len=inner.content.len(), inner_type=inner.content_type, "decrypted record");
                Some(inner.content)
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

    pub fn clear(&mut self) {
        self.streams.clear();
        self.all_streams.clear();
        self.next_index = 0;
    }
}

pub struct PacketCollector {
    pub packets: Arc<RwLock<Vec<CapturedPacket>>>,
    pub capturing: Arc<AtomicBool>,
    pub error: Arc<Mutex<Option<String>>>,
    pub dns_cache: DnsCache,
    pub stream_tracker: Arc<Mutex<StreamTracker>>,
    counter: Arc<Mutex<u64>>,
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
            error: Arc::new(Mutex::new(None)),
            dns_cache: DnsCache::new(),
            stream_tracker: Arc::new(Mutex::new(StreamTracker::new())),
            counter: Arc::new(Mutex::new(0)),
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
            let t = self.stream_tracker.lock().unwrap();
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
        if self
            .capturing
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        *self.error.lock().unwrap() = None;

        let packets = Arc::clone(&self.packets);
        let capturing = Arc::clone(&self.capturing);
        let error = Arc::clone(&self.error);
        let counter = Arc::clone(&self.counter);
        let tracker = Arc::clone(&self.stream_tracker);
        let dns = self.dns_cache.clone();
        let iface = resolve_device_name(interface);
        let bpf = bpf_filter.map(|s| s.to_string());

        self.handle = Some(thread::spawn(move || {
            // Try with promiscuous mode first, fall back to non-promiscuous
            // (some interfaces like loopback don't support promisc on macOS)
            let cap = pcap::Capture::from_device(iface.as_str())
                .and_then(|c| {
                    c.promisc(true)
                        .snaplen(CAPTURE_SNAPLEN)
                        .timeout(CAPTURE_TIMEOUT_MS)
                        .open()
                })
                .or_else(|_| {
                    pcap::Capture::from_device(iface.as_str()).and_then(|c| {
                        c.promisc(false)
                            .snaplen(CAPTURE_SNAPLEN)
                            .timeout(CAPTURE_TIMEOUT_MS)
                            .open()
                    })
                });

            let mut cap = match cap {
                Ok(c) => c,
                Err(e) => {
                    let msg = if e.to_string().contains("Permission denied") {
                        "Permission denied — run with sudo".to_string()
                    } else {
                        format!("Capture failed: {e}")
                    };
                    tracing::error!(target: "netwatch::capture", interface = %iface, error = %e, "pcap open failed");
                    *error.lock().unwrap() = Some(msg);
                    capturing.store(false, Ordering::SeqCst);
                    return;
                }
            };

            // Apply BPF capture filter if specified
            if let Some(filter) = bpf.as_deref() {
                if let Err(e) = cap.filter(filter, true) {
                    tracing::error!(target: "netwatch::capture", filter = %filter, error = %e, "BPF filter compile/install failed");
                    *error.lock().unwrap() = Some(format!("BPF filter error: {e}"));
                    capturing.store(false, Ordering::SeqCst);
                    return;
                }
            }

            let mut batch: Vec<CapturedPacket> = Vec::with_capacity(CAPTURE_BATCH_SIZE);

            while capturing.load(Ordering::Relaxed) {
                match cap.next_packet() {
                    Ok(packet) => {
                        if let Some(mut parsed) = parse_packet(packet.data, &counter, &dns) {
                            if let (Some(sp), Some(dp)) = (parsed.src_port, parsed.dst_port) {
                                let proto = if parsed.tcp_flags.is_some() {
                                    StreamProtocol::Tcp
                                } else {
                                    StreamProtocol::Udp
                                };
                                let payload = extract_app_payload(packet.data, proto);
                                let (idx, app_proto, decrypted) = {
                                    let mut t = tracker.lock().unwrap();
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
                                    let ap = t.get_stream(i).and_then(|s| s.app_protocol.clone());
                                    // TLS-decrypt the application-data record carried by
                                    // *this* TCP segment, if we have keys for the flow.
                                    // Determines direction from initiator info on the stream.
                                    let client_to_server = t
                                        .get_stream(i)
                                        .and_then(|s| s.initiator.as_ref())
                                        .map(|(ip, port)| {
                                            ip.as_str() == parsed.src_ip.as_str() && *port == sp
                                        })
                                        .unwrap_or(true);
                                    let dec =
                                        t.try_decrypt_tls_record(i, &payload, client_to_server);
                                    (i, ap, dec)
                                };
                                parsed.stream_index = Some(idx);
                                parsed.app_protocol = app_proto;
                                parsed.decrypted_plaintext = decrypted;
                            }
                            batch.push(parsed);
                            if batch.len() >= CAPTURE_BATCH_SIZE {
                                let mut pkts = packets.write().unwrap();
                                pkts.extend(batch.drain(..));
                                if pkts.len() > MAX_PACKETS {
                                    let excess = pkts.len() - MAX_PACKETS;
                                    pkts.drain(0..excess);
                                }
                            }
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Flush any pending batch on timeout
                        if !batch.is_empty() {
                            let mut pkts = packets.write().unwrap();
                            pkts.extend(batch.drain(..));
                            if pkts.len() > MAX_PACKETS {
                                let excess = pkts.len() - MAX_PACKETS;
                                pkts.drain(0..excess);
                            }
                        }
                        continue;
                    }
                    Err(_) => break,
                }
            }

            // Flush remaining batch on shutdown
            if !batch.is_empty() {
                let mut pkts = packets.write().unwrap();
                pkts.extend(batch.drain(..));
                if pkts.len() > MAX_PACKETS {
                    let excess = pkts.len() - MAX_PACKETS;
                    pkts.drain(0..excess);
                }
            }
        }));
    }

    pub fn stop_capture(&mut self) {
        self.capturing.store(false, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    pub fn clear(&self) {
        self.packets.write().unwrap().clear();
        self.stream_tracker.lock().unwrap().clear();
    }

    pub fn is_capturing(&self) -> bool {
        self.capturing.load(Ordering::SeqCst)
    }

    pub fn get_error(&self) -> Option<String> {
        self.error.lock().unwrap().clone()
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

    pub fn get_packets(&self) -> std::sync::RwLockReadGuard<'_, Vec<CapturedPacket>> {
        self.packets.read().unwrap()
    }

    pub fn get_stream(&self, index: u32) -> Option<Stream> {
        self.stream_tracker
            .lock()
            .unwrap()
            .get_stream(index)
            .cloned()
    }
}

impl Drop for PacketCollector {
    fn drop(&mut self) {
        self.stop_capture();
    }
}

// ── Packet parsing ──────────────────────────────────────────

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
    let src = format_ipv6(&data[8..24]);
    let dst = format_ipv6(&data[24..40]);

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

    let ctx = ParseCtx {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    };
    for parser in TCP_PARSERS.iter() {
        if parser.matches(src_port, dst_port, payload) {
            if let Some(result) = parser.parse(payload, &ctx, &flag_str) {
                details.push(result.detail);
                return (
                    result.proto,
                    Some(src_port),
                    Some(dst_port),
                    result.info,
                    data_offset,
                    Some(flags),
                    Some(seq),
                );
            }
        }
    }

    let payload_len = payload.len();
    let info = format!(
        "{}:{} → {}:{} [{}] Seq={} Win={}{} Payload={}",
        src_ip,
        src_port,
        dst_ip,
        dst_port,
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

    let ctx = ParseCtx {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    };
    for parser in UDP_PARSERS.iter() {
        if parser.matches(src_port, dst_port, payload) {
            if let Some(result) = parser.parse(payload, &ctx) {
                details.push(result.detail);
                return (
                    result.proto,
                    Some(src_port),
                    Some(dst_port),
                    result.info,
                    8,
                    None,
                    None,
                );
            }
        }
    }

    let svc = if dst_svc != "—" { dst_svc } else { src_svc };
    let info = format!(
        "{}:{} → {}:{} Len={}{}",
        src_ip,
        src_port,
        dst_ip,
        dst_port,
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

// ── Protocol parser traits ─────────────────────────────────────────────────────

/// Shared address/port context passed to every protocol parser.
struct ParseCtx<'a> {
    src_ip: &'a str,
    dst_ip: &'a str,
    src_port: u16,
    dst_port: u16,
}

/// Successful result from a protocol parser: protocol name, one-line summary,
/// and a detail line suitable for `details.push(...)`.
struct ParsedProto {
    proto: String,
    info: String,
    detail: String,
}

/// Pluggable UDP application-layer parser. Implement this trait and add an
/// instance to `UDP_PARSERS` to support a new protocol without modifying
/// `parse_udp` itself.
trait UdpProtocolParser: Send + Sync {
    /// Returns `true` if this parser should attempt to parse the datagram.
    fn matches(&self, src_port: u16, dst_port: u16, payload: &[u8]) -> bool;
    /// Attempt to parse `payload`. Returns `None` to pass to the next parser.
    fn parse(&self, payload: &[u8], ctx: &ParseCtx) -> Option<ParsedProto>;
}

/// Pluggable TCP application-layer parser.
trait TcpProtocolParser: Send + Sync {
    fn matches(&self, src_port: u16, dst_port: u16, payload: &[u8]) -> bool;
    /// Parse `payload` and produce a result. `flag_str` is the TCP flags label.
    fn parse(&self, payload: &[u8], ctx: &ParseCtx, flag_str: &str) -> Option<ParsedProto>;
}

// ── UDP parser implementations ─────────────────────────────────────────────

struct UdpDnsParser;
impl UdpProtocolParser for UdpDnsParser {
    fn matches(&self, src_port: u16, dst_port: u16, payload: &[u8]) -> bool {
        (src_port == 53 || dst_port == 53 || src_port == 5353 || dst_port == 5353)
            && !payload.is_empty()
    }
    fn parse(&self, payload: &[u8], ctx: &ParseCtx) -> Option<ParsedProto> {
        let proto_name = if ctx.src_port == 5353 || ctx.dst_port == 5353 {
            "mDNS"
        } else {
            "DNS"
        };
        let (dns_info, detail) = parse_dns(payload)?;
        let info = format!("{} → {} {}", ctx.src_ip, ctx.dst_ip, dns_info);
        Some(ParsedProto {
            proto: proto_name.into(),
            info,
            detail,
        })
    }
}

struct DhcpParser;
impl UdpProtocolParser for DhcpParser {
    fn matches(&self, src_port: u16, dst_port: u16, _payload: &[u8]) -> bool {
        (src_port == 67 || src_port == 68) && (dst_port == 67 || dst_port == 68)
    }
    fn parse(&self, payload: &[u8], ctx: &ParseCtx) -> Option<ParsedProto> {
        let dhcp_info = parse_dhcp(payload);
        Some(ParsedProto {
            proto: "DHCP".into(),
            info: format!("{} → {} {}", ctx.src_ip, ctx.dst_ip, dhcp_info),
            detail: format!("DHCP: {}", dhcp_info),
        })
    }
}

struct SsdpParser;
impl UdpProtocolParser for SsdpParser {
    fn matches(&self, src_port: u16, dst_port: u16, _payload: &[u8]) -> bool {
        src_port == 1900 || dst_port == 1900
    }
    fn parse(&self, payload: &[u8], ctx: &ParseCtx) -> Option<ParsedProto> {
        let (ssdp_info, detail) = parse_ssdp(payload)?;
        let info = format!("{} → {} {}", ctx.src_ip, ctx.dst_ip, ssdp_info);
        Some(ParsedProto {
            proto: "SSDP".into(),
            info,
            detail,
        })
    }
}

struct NtpParser;
impl UdpProtocolParser for NtpParser {
    fn matches(&self, src_port: u16, dst_port: u16, _payload: &[u8]) -> bool {
        src_port == 123 || dst_port == 123
    }
    fn parse(&self, payload: &[u8], ctx: &ParseCtx) -> Option<ParsedProto> {
        let ntp_info = parse_ntp(payload);
        Some(ParsedProto {
            proto: "NTP".into(),
            info: format!("{} → {} {}", ctx.src_ip, ctx.dst_ip, ntp_info),
            detail: format!("NTP: {}", ntp_info),
        })
    }
}

struct QuicParser;
impl UdpProtocolParser for QuicParser {
    fn matches(&self, src_port: u16, dst_port: u16, payload: &[u8]) -> bool {
        (dst_port == 443 || src_port == 443) && !payload.is_empty()
    }
    fn parse(&self, payload: &[u8], ctx: &ParseCtx) -> Option<ParsedProto> {
        let (quic_info, detail) = parse_quic(payload)?;
        let info = format!(
            "{}:{} → {}:{} {}",
            ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port, quic_info
        );
        Some(ParsedProto {
            proto: "QUIC".into(),
            info,
            detail,
        })
    }
}

static UDP_PARSERS: std::sync::LazyLock<Vec<Box<dyn UdpProtocolParser>>> =
    std::sync::LazyLock::new(|| {
        vec![
            Box::new(UdpDnsParser),
            Box::new(DhcpParser),
            Box::new(SsdpParser),
            Box::new(NtpParser),
            Box::new(QuicParser),
        ]
    });

// ── TCP application-layer parser implementations ───────────────────────────

struct TcpDnsParser;
impl TcpProtocolParser for TcpDnsParser {
    fn matches(&self, src_port: u16, dst_port: u16, payload: &[u8]) -> bool {
        (src_port == 53 || dst_port == 53) && payload.len() > 2
    }
    fn parse(&self, payload: &[u8], ctx: &ParseCtx, _flag_str: &str) -> Option<ParsedProto> {
        let dns_data = &payload[2..];
        let (dns_info, detail) = parse_dns(dns_data)?;
        let info = format!("{} → {} {}", ctx.src_ip, ctx.dst_ip, dns_info);
        Some(ParsedProto {
            proto: "DNS".into(),
            info,
            detail,
        })
    }
}

struct TlsParser;
impl TcpProtocolParser for TlsParser {
    fn matches(&self, _src_port: u16, _dst_port: u16, payload: &[u8]) -> bool {
        !payload.is_empty()
    }
    fn parse(&self, payload: &[u8], ctx: &ParseCtx, flag_str: &str) -> Option<ParsedProto> {
        let (tls_info, detail) = parse_tls(payload)?;
        let info = format!(
            "{}:{} → {}:{} {} [{}]",
            ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port, tls_info, flag_str
        );
        Some(ParsedProto {
            proto: "TLS".into(),
            info,
            detail,
        })
    }
}

struct HttpParser;
impl TcpProtocolParser for HttpParser {
    fn matches(&self, _src_port: u16, _dst_port: u16, payload: &[u8]) -> bool {
        !payload.is_empty()
    }
    fn parse(&self, payload: &[u8], ctx: &ParseCtx, _flag_str: &str) -> Option<ParsedProto> {
        let (http_info, detail) = parse_http(payload)?;
        let info = format!(
            "{}:{} → {}:{} {}",
            ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port, http_info
        );
        Some(ParsedProto {
            proto: "HTTP".into(),
            info,
            detail,
        })
    }
}

static TCP_PARSERS: std::sync::LazyLock<Vec<Box<dyn TcpProtocolParser>>> =
    std::sync::LazyLock::new(|| {
        vec![
            Box::new(TcpDnsParser),
            Box::new(TlsParser),
            Box::new(HttpParser),
        ]
    });

// ── Application-layer parsers ───────────────────────────────

fn parse_dns(data: &[u8]) -> Option<(String, String)> {
    if data.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let is_response = flags & 0x8000 != 0;
    let qd_count = u16::from_be_bytes([data[4], data[5]]);
    let an_count = u16::from_be_bytes([data[6], data[7]]);

    if is_response {
        let rcode = flags & 0x000F;
        let rcode_str = match rcode {
            0 => "No Error",
            1 => "Format Error",
            2 => "Server Failure",
            3 => "Name Error (NXDOMAIN)",
            4 => "Not Implemented",
            5 => "Refused",
            _ => "Unknown",
        };
        let info = format!("DNS Response, {} answers, {}", an_count, rcode_str);
        let detail = format!("DNS: Response, Answers: {}, Rcode: {}", an_count, rcode_str);
        Some((info, detail))
    } else {
        // Parse query name
        let name = parse_dns_name(data, 12).unwrap_or_else(|| "?".into());
        let qtype = dns_query_type(data, 12, &name);
        let info = format!("DNS Query {} {}", qtype, name);
        let detail = format!(
            "DNS: Query, Questions: {}, Name: {}, Type: {}",
            qd_count, name, qtype
        );
        Some((info, detail))
    }
}

fn parse_dns_name(data: &[u8], offset: usize) -> Option<String> {
    let mut name = String::new();
    let mut pos = offset;
    let mut first = true;
    for _ in 0..128 {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }
        if len >= 0xC0 {
            break;
        }
        if !first {
            name.push('.');
        }
        first = false;
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        name.push_str(&String::from_utf8_lossy(&data[pos..pos + len]));
        pos += len;
    }
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn dns_query_type(data: &[u8], start: usize, _name: &str) -> &'static str {
    // Skip past the name to find the QTYPE
    let mut pos = start;
    for _ in 0..128 {
        if pos >= data.len() {
            return "?";
        }
        let len = data[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len >= 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + len;
    }
    if pos + 2 > data.len() {
        return "?";
    }
    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        65 => "HTTPS",
        _ => "?",
    }
}

fn parse_tls(data: &[u8]) -> Option<(String, String)> {
    if data.len() < 6 {
        return None;
    }
    let content_type = data[0];
    if content_type != 0x16 {
        return None; // Not a TLS handshake
    }
    let tls_major = data[1];
    let tls_minor = data[2];
    if tls_major < 3 {
        return None;
    }
    let version = match (tls_major, tls_minor) {
        (3, 0) => "SSL 3.0",
        (3, 1) => "TLS 1.0",
        (3, 2) => "TLS 1.1",
        (3, 3) => "TLS 1.2",
        (3, 4) => "TLS 1.3",
        _ => "TLS",
    };

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + 1 || record_len < 1 {
        return None;
    }
    let handshake_type = data[5];
    match handshake_type {
        1 => {
            // ClientHello — try to extract SNI
            let sni = extract_sni(&data[5..]);
            let sni_str = sni.as_deref().unwrap_or("—");
            let info = format!("Client Hello ({}), SNI: {}", version, sni_str);
            let detail = format!("TLS: Client Hello, Version: {}, SNI: {}", version, sni_str);
            Some((info, detail))
        }
        2 => {
            let cipher = extract_cipher_suite(&data[5..]);
            let cipher_str = cipher.as_deref().unwrap_or("—");
            let info = format!("Server Hello ({}), Cipher: {}", version, cipher_str);
            let detail = format!(
                "TLS: Server Hello, Version: {}, Cipher Suite: {}",
                version, cipher_str
            );
            Some((info, detail))
        }
        11 => Some((
            "Certificate".into(),
            format!("TLS: Certificate, Version: {}", version),
        )),
        14 => Some((
            "Server Hello Done".into(),
            "TLS: Server Hello Done".to_string(),
        )),
        16 => Some((
            "Client Key Exchange".into(),
            "TLS: Client Key Exchange".to_string(),
        )),
        _ => {
            let info = format!("Handshake type {}", handshake_type);
            let detail = format!(
                "TLS: Handshake type {}, Version: {}",
                handshake_type, version
            );
            Some((info, detail))
        }
    }
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
                    return Some(
                        String::from_utf8_lossy(&handshake[name_start..name_start + name_len])
                            .to_string(),
                    );
                }
            }
            return None;
        }
        pos += ext_data_len;
    }
    None
}

fn extract_cipher_suite(handshake: &[u8]) -> Option<String> {
    // ServerHello: type(1) + length(3) + version(2) + random(32) = 38 bytes
    // then session_id_length(1) + session_id(var) + cipher_suite(2)
    if handshake.len() < 39 {
        return None;
    }
    let mut pos = 38;
    if pos >= handshake.len() {
        return None;
    }
    let sid_len = handshake[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 > handshake.len() {
        return None;
    }
    let suite = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
    Some(cipher_suite_name(suite))
}

fn cipher_suite_name(suite: u16) -> String {
    match suite {
        0x1301 => "TLS_AES_128_GCM_SHA256".into(),
        0x1302 => "TLS_AES_256_GCM_SHA384".into(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".into(),
        0xc02b => "ECDHE_ECDSA_AES_128_GCM_SHA256".into(),
        0xc02c => "ECDHE_ECDSA_AES_256_GCM_SHA384".into(),
        0xc02f => "ECDHE_RSA_AES_128_GCM_SHA256".into(),
        0xc030 => "ECDHE_RSA_AES_256_GCM_SHA384".into(),
        0xcca8 => "ECDHE_RSA_CHACHA20_POLY1305".into(),
        0xcca9 => "ECDHE_ECDSA_CHACHA20_POLY1305".into(),
        0x009c => "RSA_AES_128_GCM_SHA256".into(),
        0x009d => "RSA_AES_256_GCM_SHA384".into(),
        0x002f => "RSA_AES_128_CBC_SHA".into(),
        0x0035 => "RSA_AES_256_CBC_SHA".into(),
        0x00ff => "EMPTY_RENEGOTIATION_INFO".into(),
        _ => format!("0x{:04x}", suite),
    }
}

fn parse_http(data: &[u8]) -> Option<(String, String)> {
    let methods = [
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH ", "OPTIONS ", "HTTP/",
    ];
    let text = String::from_utf8_lossy(&data[..data.len().min(512)]);
    let first_line = text.lines().next().unwrap_or("");

    for method in &methods {
        if first_line.starts_with(method) {
            let truncated = if first_line.len() > 80 {
                let t: String = first_line.chars().take(80).collect();
                format!("{}…", t)
            } else {
                first_line.to_string()
            };

            let host = extract_header(&text, "Host");
            let content_type = extract_header(&text, "Content-Type");

            let mut detail = format!("HTTP: {}", truncated);
            if let Some(ref h) = host {
                detail.push_str(&format!(", Host: {}", h));
            }
            if let Some(ref ct) = content_type {
                detail.push_str(&format!(", Content-Type: {}", ct));
            }

            let info = if first_line.starts_with("HTTP/") {
                truncated.to_string()
            } else if let Some(ref h) = host {
                format!("{} ({})", truncated, h)
            } else {
                truncated.to_string()
            };

            return Some((info, detail));
        }
    }
    None
}

fn parse_ssdp(data: &[u8]) -> Option<(String, String)> {
    let text = String::from_utf8_lossy(&data[..data.len().min(512)]);
    let first_line = text.lines().next()?;

    if first_line.starts_with("M-SEARCH") {
        let st = extract_header(&text, "ST");
        let info = format!("M-SEARCH {}", st.as_deref().unwrap_or("*"));
        let detail = format!("SSDP: M-SEARCH, ST: {}", st.as_deref().unwrap_or("—"));
        Some((info, detail))
    } else if first_line.starts_with("NOTIFY") {
        let nt = extract_header(&text, "NT");
        let nts = extract_header(&text, "NTS");
        let info = format!(
            "NOTIFY {} {}",
            nt.as_deref().unwrap_or(""),
            nts.as_deref().unwrap_or("")
        );
        let detail = format!(
            "SSDP: NOTIFY, NT: {}, NTS: {}",
            nt.as_deref().unwrap_or("—"),
            nts.as_deref().unwrap_or("—")
        );
        Some((info, detail))
    } else if first_line.starts_with("HTTP/") {
        let server = extract_header(&text, "SERVER");
        let st = extract_header(&text, "ST");
        let label = server.as_deref().or(st.as_deref()).unwrap_or("");
        let info = format!("Response {}", label);
        let detail = format!(
            "SSDP: Response, Server: {}",
            server.as_deref().unwrap_or("—")
        );
        Some((info, detail))
    } else {
        None
    }
}

fn extract_header(text: &str, name: &str) -> Option<String> {
    let prefix_lower = format!("{}:", name.to_lowercase());
    for line in text.lines() {
        if line.to_lowercase().starts_with(&prefix_lower) {
            return Some(line[name.len() + 1..].trim().to_string());
        }
    }
    None
}

fn parse_dhcp(data: &[u8]) -> String {
    if data.is_empty() {
        return "DHCP".into();
    }
    let op = data[0];
    match op {
        1 => "DHCP Discover/Request".into(),
        2 => "DHCP Offer/ACK".into(),
        _ => format!("DHCP op={}", op),
    }
}

fn parse_ntp(data: &[u8]) -> String {
    if data.is_empty() {
        return "NTP".into();
    }
    let li_vn_mode = data[0];
    let mode = li_vn_mode & 0x07;
    let version = (li_vn_mode >> 3) & 0x07;
    let mode_str = match mode {
        1 => "Symmetric Active",
        2 => "Symmetric Passive",
        3 => "Client",
        4 => "Server",
        5 => "Broadcast",
        6 => "Control",
        _ => "Unknown",
    };
    format!("NTPv{} {}", version, mode_str)
}

fn parse_quic(data: &[u8]) -> Option<(String, String)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];

    // QUIC long header: bit 7 (form) = 1
    if first & 0x80 == 0 {
        // Short header (1-RTT) — encrypted, can't decode much
        return Some((
            "Protected Payload (1-RTT)".into(),
            "QUIC: Short Header, Protected Payload".into(),
        ));
    }

    // Long header
    if data.len() < 5 {
        return None;
    }

    let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    let pkt_type = (first & 0x30) >> 4;

    let version_str = match version {
        0x00000001 => "v1",
        0x6b3343cf => "v2",
        0x00000000 => "Version Negotiation",
        v if v & 0x0f0f0f0f == 0x0a0a0a0a => "Greased",
        _ => "Unknown",
    };

    let type_str = match pkt_type {
        0 => "Initial",
        1 => "0-RTT",
        2 => "Handshake",
        3 => "Retry",
        _ => "Unknown",
    };

    // For Initial packets, derive the well-known Initial keys from the DCID
    // and decrypt the embedded TLS ClientHello to extract the SNI. Falls
    // back to "—" when decryption fails (server-side Initials, non-v1/v2
    // versions, truncated captures, or AEAD failures from packet damage).
    // See `crate::collectors::quic` for the RFC 9001 implementation.
    let is_initial = match version {
        0x00000001 => pkt_type == 0,
        0x6b3343cf => pkt_type == 1, // QUIC v2 reorders type bits (RFC 9369 §3.2)
        _ => false,
    };
    if is_initial && data.len() > 7 {
        let sni = crate::collectors::quic::try_extract_initial_sni(data);
        let sni_str = sni.as_deref().unwrap_or("—");
        let info = format!("QUIC {} {} SNI: {}", version_str, type_str, sni_str);
        let detail = format!(
            "QUIC: {} {}, Version: {} (0x{:08x}), SNI: {}",
            type_str, version_str, version_str, version, sni_str
        );
        return Some((info, detail));
    }

    let info = format!("QUIC {} {}", version_str, type_str);
    let detail = format!(
        "QUIC: {} {}, Version: {} (0x{:08x})",
        type_str, version_str, version_str, version
    );
    Some((info, detail))
}

// QUIC SNI extraction now lives in `crate::collectors::quic` (RFC 9001
// HKDF + AEAD path). The previous heuristic that scanned the encrypted
// payload for a cleartext ClientHello pattern has been removed — it
// effectively never fired on real-world QUIC traffic.

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
    let mut cnt = counter.lock().unwrap();
    *cnt += 1;
    let id = *cnt;
    let now = chrono::Local::now();
    let timestamp = now.format("%H:%M:%S%.3f").to_string();
    let timestamp_ns = now.timestamp_nanos_opt().unwrap_or(0) as u64;

    // Queue reverse DNS lookups (non-blocking — results appear on next render)
    let src_host = dns.lookup(src_ip);
    let dst_host = dns.lookup(dst_ip);

    let hex_lines = raw
        .chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            format!("{:04x}  {}", i * 16, hex.join(" "))
        })
        .collect::<Vec<_>>()
        .join("\n");

    let ascii_lines = raw
        .chunks(16)
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
        .join("\n");

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
        let trimmed = result.trim().to_string();
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
use format::{
    format_ipv6, format_mac, icmp_type_name, icmpv6_type_name, ip_protocol_name, parse_arp,
    tcp_flags,
};

// ── PCAP export (extracted to pcap_export.rs) ──
mod pcap_export;
pub use pcap_export::export_pcap;

// ── Display filters (extracted to filter.rs) ──
mod filter;
pub use filter::{matches_packet, parse_filter, FilterExpr};

/// On Windows, pcap needs the `\Device\NPF_{GUID}` name rather than the
/// friendly name (e.g. "Ethernet" or "Wi-Fi") that ipconfig reports.
/// This maps friendly names to the pcap device name by matching descriptions.
/// On non-Windows platforms this is a no-op.
fn resolve_device_name(friendly: &str) -> String {
    #[cfg(not(target_os = "windows"))]
    {
        friendly.to_string()
    }

    #[cfg(target_os = "windows")]
    {
        // If it already looks like an NPF path, use as-is.
        if friendly.starts_with("\\Device\\") || friendly.starts_with("\\\\") {
            return friendly.to_string();
        }

        let devices = match pcap::Device::list() {
            Ok(d) => d,
            Err(_) => return friendly.to_string(),
        };

        let friendly_lower = friendly.to_lowercase();

        // Match against the device description (which contains the friendly name).
        for dev in &devices {
            if let Some(ref desc) = dev.desc {
                if desc.to_lowercase().contains(&friendly_lower) {
                    return dev.name.clone();
                }
            }
        }

        // Fallback: return original and let pcap produce its own error.
        friendly.to_string()
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

    // ── format_mac ──────────────────────────────────────────
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
        assert_eq!(format_ipv6(&bytes), "0:0:0:0:0:0:0:1");
    }
    #[test]
    fn test_format_ipv6_all_zeros() {
        assert_eq!(format_ipv6(&[0u8; 16]), "0:0:0:0:0:0:0:0");
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

    // ── parse_timestamp_for_pcap ────────────────────────────

    // ── parse_dns_name ──────────────────────────────────────
    #[test]
    fn test_dns_name_simple() {
        // "\x07example\x03com\x00"
        let data = b"\x07example\x03com\x00";
        assert_eq!(parse_dns_name(data, 0), Some("example.com".into()));
    }
    #[test]
    fn test_dns_name_subdomain() {
        let data = b"\x03www\x07example\x03com\x00";
        assert_eq!(parse_dns_name(data, 0), Some("www.example.com".into()));
    }
    #[test]
    fn test_dns_name_empty() {
        let data = b"\x00";
        assert_eq!(parse_dns_name(data, 0), None);
    }
    #[test]
    fn test_dns_name_truncated() {
        let data = b"\x07exam";
        assert_eq!(parse_dns_name(data, 0), None);
    }

    // ── dns_query_type ──────────────────────────────────────
    #[test]
    fn test_dns_qtype_a() {
        // name: "\x07example\x03com\x00" + qtype 1 (A)
        let mut data = b"\x07example\x03com\x00".to_vec();
        data.extend_from_slice(&[0x00, 0x01]); // A record
        assert_eq!(dns_query_type(&data, 0, "example.com"), "A");
    }
    #[test]
    fn test_dns_qtype_aaaa() {
        let mut data = b"\x07example\x03com\x00".to_vec();
        data.extend_from_slice(&[0x00, 28]); // AAAA
        assert_eq!(dns_query_type(&data, 0, "example.com"), "AAAA");
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

    // ── parse_dhcp / parse_ntp ──────────────────────────────
    #[test]
    fn test_dhcp_discover() {
        assert!(parse_dhcp(&[1]).contains("Discover"));
    }
    #[test]
    fn test_dhcp_offer() {
        assert!(parse_dhcp(&[2]).contains("Offer"));
    }
    #[test]
    fn test_dhcp_empty() {
        assert_eq!(parse_dhcp(&[]), "DHCP");
    }

    #[test]
    fn test_ntp_client() {
        let data = [0x23]; // version 4, mode 3 (client)
        assert!(parse_ntp(&data).contains("Client"));
    }
    #[test]
    fn test_ntp_server() {
        let data = [0x24]; // version 4, mode 4 (server)
        assert!(parse_ntp(&data).contains("Server"));
    }
    #[test]
    fn test_ntp_empty() {
        assert_eq!(parse_ntp(&[]), "NTP");
    }

    // ── parse_http ──────────────────────────────────────────
    #[test]
    fn test_http_get() {
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n";
        let (info, _detail) = parse_http(data).unwrap();
        assert!(info.contains("GET /index.html"));
    }
    #[test]
    fn test_http_response() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n";
        let (info, _) = parse_http(data).unwrap();
        assert!(info.contains("200 OK"));
    }
    #[test]
    fn test_http_not_http() {
        assert!(parse_http(b"\x16\x03\x01binary stuff").is_none());
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
}
