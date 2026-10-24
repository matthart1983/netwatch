//! What a packet's conversation is doing, and where the packet sits in it.
//!
//! The stream panel used to say `42 packets · 184 KB · 24ms handshake` and
//! stop. That is a fact about the flow, not context for the packet you have
//! selected: it does not say whether you are looking at the handshake or the
//! teardown, which end spoke, what this particular packet is *for*, or what
//! happened either side of it. An operator selecting a packet mid-capture is
//! asking "what is going on here", and the honest answer is a sequence.
//!
//! Everything here is a pure function of the stream, the capture and the
//! selected id — no `App`, no `Frame`. That is deliberate: `ui::packets`
//! cannot be rendered in a test because it takes `&App`, so the substance
//! lives here where it can be.

use crate::collectors::packets::{
    CapturedPacket, Stream, StreamProtocol, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST,
    TCP_FLAG_SYN,
};

/// What one packet is doing in its conversation.
///
/// This is the *nature* of the traffic at packet granularity — the thing a
/// bare `TCP  1412 bytes` row cannot tell you. Ordering matters only for
/// display styling; the classifier below picks exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Opening a connection.
    Syn,
    /// The other end agreeing to open it.
    SynAck,
    /// Pure acknowledgement, no payload.
    Ack,
    /// Orderly shutdown.
    Fin,
    /// Abrupt shutdown — someone refused or gave up.
    Rst,
    /// Carrying application bytes.
    Data,
    /// A request went out.
    Query,
    /// An answer came back.
    Reply,
    /// Anything the classifier will not guess at.
    Other,
}

impl Role {
    /// Whether this role is a problem in its own right, so the renderer can
    /// colour it without re-deriving the judgement.
    pub fn is_alarming(self) -> bool {
        matches!(self, Role::Rst)
    }
}

/// What the conversation as a whole is doing right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Still shaking hands — no application bytes yet.
    Opening,
    /// Application bytes flowing.
    Active,
    /// One side has sent a FIN.
    Closing,
    /// Someone sent a RST. This outranks every other phase: a reset
    /// conversation is the finding, whatever else it did first.
    Reset,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Phase::Opening => "opening",
            Phase::Active => "active",
            Phase::Closing => "closing",
            Phase::Reset => "reset",
        }
    }
}

/// Something worth flagging about an individual packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// This sequence number was already sent in this direction.
    Retransmit,
    /// This sequence number is behind the furthest one seen, but is new —
    /// the network reordered it rather than the sender resending it.
    OutOfOrder,
}

impl Note {
    /// One-character stand-in for a panel too narrow to spell the note out.
    pub fn glyph(self) -> &'static str {
        match self {
            Note::Retransmit => "⟲",
            Note::OutOfOrder => "⤨",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Note::Retransmit => "retransmit",
            Note::OutOfOrder => "out of order",
        }
    }
}

/// One rung of the sequence ladder.
#[derive(Debug, Clone)]
pub struct Rung {
    pub packet_id: u64,
    /// Milliseconds since the conversation's first packet, so the reader sees
    /// the shape of the exchange rather than wall-clock timestamps they have
    /// to subtract in their head.
    pub offset_ms: f64,
    /// True when this packet travelled from the end that opened the
    /// conversation. Direction is only meaningful relative to the initiator —
    /// "source" and "destination" swap every other packet.
    pub from_initiator: bool,
    pub role: Role,
    /// Short human label: `syn·ack`, `tls client hello`, `data`, `query A`.
    pub label: String,
    pub bytes: u32,
    pub note: Option<Note>,
    /// The packet the operator has selected in the list above.
    pub selected: bool,
}

/// A packet's conversation, ready to render.
#[derive(Debug, Clone)]
pub struct Conversation {
    /// The ladder, windowed around the selection — see [`conversation`].
    pub rungs: Vec<Rung>,
    /// 1-based position of the selected packet among all packets in the
    /// stream, and the total. `None` when the selection is not in this stream.
    pub position: Option<usize>,
    pub total: usize,
    /// True when the window omits packets before the first rung shown.
    pub truncated_above: bool,
    /// True when the window omits packets after the last rung shown.
    pub truncated_below: bool,
    pub phase: Phase,
    /// `ip:port` of the end that opened the conversation, when known.
    pub initiator: Option<String>,
    pub peer: Option<String>,
    /// Bytes sent by the initiator, and by the other end.
    pub bytes_out: u64,
    pub bytes_in: u64,
    /// Wall time from the conversation's first packet to its last.
    pub duration_ms: f64,
    pub retransmits: u32,
    pub out_of_order: u32,
}

/// Name the address pair, initiator first.
fn endpoints(stream: &Stream) -> (Option<String>, Option<String>) {
    use crate::collectors::packets::format_endpoint;
    let (a, b) = (&stream.key.addr_a, &stream.key.addr_b);
    let show = |(ip, port): &(String, u16)| Some(format_endpoint(ip, port));
    match &stream.initiator {
        Some(init) => {
            if init == a {
                (show(a), show(b))
            } else {
                (show(b), show(a))
            }
        }
        // Without a recorded initiator the key's canonical ordering is the
        // best we have, and it is arbitrary — so say nothing rather than
        // assert that the wrong end opened the conversation.
        None => (None, None),
    }
}

/// Classify one packet within its conversation.
///
/// TCP flags are authoritative when present — they are the protocol saying
/// what the packet is for. Otherwise fall back to the decoded `info` line,
/// which is where the DNS and TLS decoders put their summary.
fn classify(pkt: &CapturedPacket) -> (Role, String) {
    if let Some(flags) = pkt.tcp_flags {
        if flags & TCP_FLAG_RST != 0 {
            return (Role::Rst, "rst".into());
        }
        let syn = flags & TCP_FLAG_SYN != 0;
        let ack = flags & TCP_FLAG_ACK != 0;
        if syn && ack {
            return (Role::SynAck, "syn·ack".into());
        }
        if syn {
            return (Role::Syn, "syn".into());
        }
        if flags & TCP_FLAG_FIN != 0 {
            return (Role::Fin, if ack { "fin·ack".into() } else { "fin".into() });
        }
        // A pure ACK carries no application bytes. PSH means the sender is
        // pushing data up to the application, which makes it data whatever
        // else it is flagged with.
        if flags & TCP_FLAG_PSH == 0 && pkt.payload_text.is_empty() {
            return (Role::Ack, "ack".into());
        }
    }

    // TLS and DNS decoders write a summary into `info`; it is more useful
    // than "data" and it is already in the operator's vocabulary.
    let info = pkt.info.to_lowercase();
    for (needle, label) in [
        ("client hello", "tls client hello"),
        ("server hello", "tls server hello"),
        ("certificate", "tls certificate"),
    ] {
        if info.contains(needle) {
            return (Role::Data, label.into());
        }
    }

    if pkt.protocol == "DNS" {
        // A reply comes *from* port 53; a query goes to it.
        if pkt.src_port == Some(53) {
            return (Role::Reply, short_info(&pkt.info, "reply"));
        }
        return (Role::Query, short_info(&pkt.info, "query"));
    }

    if pkt.payload_text.is_empty() {
        // A TCP segment with no payload is an acknowledgement; anything else
        // with nothing in it we decline to name rather than calling it data.
        return if pkt.tcp_flags.is_some() {
            (Role::Ack, "ack".into())
        } else {
            (Role::Other, pkt.protocol.to_lowercase())
        };
    }
    (Role::Data, "data".into())
}

/// Use the decoded info line when it is short enough to read at a glance,
/// otherwise the generic word. A ladder rung is not the place for a
/// 90-character DNS summary; the decode pane beside it has the full text.
fn short_info(info: &str, fallback: &str) -> String {
    let trimmed = info.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 28 {
        fallback.to_string()
    } else {
        trimmed.to_lowercase()
    }
}

/// Build the conversation around `selected_id`.
///
/// `max_rungs` is how many ladder rows the panel has room for. The window is
/// centred on the selected packet so there is context on both sides: the
/// question "what happened just before this" is most of why anyone opens this
/// panel, and a ladder anchored to the top of the conversation answers it only
/// for the first few packets.
pub fn conversation(
    stream: &Stream,
    packets: &[CapturedPacket],
    stream_index: u32,
    selected_id: Option<u64>,
    max_rungs: usize,
) -> Conversation {
    let (initiator, peer) = endpoints(stream);
    let initiator_is_a = stream
        .initiator
        .as_ref()
        .is_none_or(|init| *init == stream.key.addr_a);
    let mut mine: Vec<&CapturedPacket> = packets
        .iter()
        .filter(|p| p.stream_index == Some(stream_index))
        .collect();
    mine.sort_by_key(|p| p.timestamp_ns);

    let first_ns = mine.first().map(|p| p.timestamp_ns).unwrap_or(0);
    let last_ns = mine.last().map(|p| p.timestamp_ns).unwrap_or(0);

    // Retransmit / out-of-order detection, per direction.
    //
    // We key on the TCP sequence number rather than recomputing `seq + len`:
    // the frame length in a `CapturedPacket` is the whole frame, not the
    // payload, so a seq+len comparison here would be wrong in a way that is
    // hard to see. A sequence number sent twice in one direction is a
    // retransmit; one that is behind the furthest sent but has not been seen
    // before is the network reordering. Both are the same judgement the
    // collector makes over the live capture, made again over what is on
    // screen so the ladder and the counters cannot disagree.
    let mut seen: [std::collections::HashSet<u32>; 2] = Default::default();
    let mut high: [Option<u32>; 2] = [None, None];
    let mut retransmits = 0u32;
    let mut out_of_order = 0u32;
    let mut phase = Phase::Opening;

    let init_addr = stream.initiator.clone();
    let mut all: Vec<Rung> = Vec::with_capacity(mine.len());
    for pkt in &mine {
        let from_initiator = match &init_addr {
            Some((ip, port)) => pkt.src_ip == *ip && pkt.src_port == Some(*port),
            None => pkt.src_ip == stream.key.addr_a.0 && pkt.src_port == Some(stream.key.addr_a.1),
        };
        let dir = usize::from(!from_initiator);

        let (role, label) = classify(pkt);

        // Sequence bookkeeping applies only to segments that carry payload.
        // A pure ACK consumes no sequence space, so the next data segment in
        // that direction starts at the *same* number — the commonest pattern
        // in TCP, and one that read as a retransmit until this check existed.
        // The live collector excludes zero-payload segments for the same
        // reason; the two must agree or the ladder contradicts the counter
        // printed directly above it.
        let mut note = None;
        if let (Some(seq), true) = (pkt.tcp_seq, carries_payload(role)) {
            if !seen[dir].insert(seq) {
                note = Some(Note::Retransmit);
                retransmits += 1;
            } else if high[dir].is_some_and(|h| seq < h) {
                note = Some(Note::OutOfOrder);
                out_of_order += 1;
            }
            high[dir] = Some(high[dir].map_or(seq, |h| h.max(seq)));
        }

        phase = advance(phase, role);

        all.push(Rung {
            packet_id: pkt.id,
            offset_ms: (pkt.timestamp_ns.saturating_sub(first_ns)) as f64 / 1_000_000.0,
            from_initiator,
            role,
            label,
            bytes: pkt.length,
            note,
            selected: Some(pkt.id) == selected_id,
        });
    }

    let total = all.len();
    let position = all.iter().position(|r| r.selected).map(|i| i + 1);

    // Centre the window on the selection, clamped to both ends.
    let (start, end) = window(total, position.map(|p| p - 1), max_rungs);
    let rungs = all[start..end].to_vec();

    Conversation {
        rungs,
        position,
        total,
        truncated_above: start > 0,
        truncated_below: end < total,
        phase,
        initiator,
        peer,
        // `total_bytes_a_to_b` follows the key's canonical ordering, which
        // sorts the two addresses lexically — it is not "from the initiator".
        // Labelling them ↑ and ↓ without this swap silently reverses the
        // direction of every flow whose opener happens to sort second.
        bytes_out: if initiator_is_a {
            stream.total_bytes_a_to_b
        } else {
            stream.total_bytes_b_to_a
        },
        bytes_in: if initiator_is_a {
            stream.total_bytes_b_to_a
        } else {
            stream.total_bytes_a_to_b
        },
        duration_ms: (last_ns.saturating_sub(first_ns)) as f64 / 1_000_000.0,
        retransmits,
        out_of_order,
    }
}

/// Whether a segment with this role occupies sequence space.
fn carries_payload(role: Role) -> bool {
    matches!(role, Role::Data | Role::Query | Role::Reply)
}

/// Advance the conversation phase. Reset is terminal — a flow that was reset
/// is reported as reset however many bytes it moved first.
fn advance(phase: Phase, role: Role) -> Phase {
    if phase == Phase::Reset || role == Role::Rst {
        return Phase::Reset;
    }
    match (phase, role) {
        // Once one side has said it is done, later data does not reopen the
        // conversation — it is the tail of a close.
        (Phase::Closing, _) => Phase::Closing,
        (_, Role::Fin) => Phase::Closing,
        (_, Role::Data | Role::Query | Role::Reply) => Phase::Active,
        (p, _) => p,
    }
}

/// The slice of the ladder to show: `max` rungs centred on `focus`, clamped.
fn window(total: usize, focus: Option<usize>, max: usize) -> (usize, usize) {
    if max == 0 || total == 0 {
        return (0, 0);
    }
    if total <= max {
        return (0, total);
    }
    let Some(focus) = focus else {
        // No selection in this stream: the end of a conversation is the part
        // that is still changing, so show the most recent packets.
        return (total - max, total);
    };
    let half = max / 2;
    let start = focus.saturating_sub(half).min(total - max);
    (start, start + max)
}

/// A one-line characterisation of the traffic, for the panel's metadata.
pub fn nature(stream: &Stream, phase: Phase, app_label: Option<&str>) -> String {
    let base = match stream.key.protocol {
        StreamProtocol::Tcp => "tcp",
        StreamProtocol::Udp => "udp",
    };
    match app_label {
        Some(app) if !app.is_empty() => format!("{base} · {app} · {}", phase.label()),
        _ => format!("{base} · {}", phase.label()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::packets::{ExpertSeverity, StreamKey};

    fn pkt(id: u64, ns: u64, src: &str, sport: u16, dst: &str, dport: u16) -> CapturedPacket {
        CapturedPacket {
            capture: None,
            annotation: None,
            id,
            timestamp: format!("00:00:{id:02}.000"),
            src_ip: src.into(),
            dst_ip: dst.into(),
            src_host: None,
            dst_host: None,
            protocol: "TCP".into(),
            length: 100,
            src_port: Some(sport),
            dst_port: Some(dport),
            info: String::new(),
            details: vec![],
            payload_text: String::new(),
            raw_hex: String::new(),
            raw_ascii: String::new(),
            raw_bytes: vec![],
            stream_index: Some(0),
            tcp_flags: None,
            tcp_seq: None,
            expert: ExpertSeverity::Chat,
            timestamp_ns: ns,
            app_protocol: None,
            decrypted_plaintext: None,
        }
    }

    fn stream() -> Stream {
        let mut s = Stream::new(
            0,
            StreamKey::new(StreamProtocol::Tcp, "10.0.0.1", 5000, "10.0.0.2", 443),
            0,
        );
        s.initiator = Some(("10.0.0.1".into(), 5000));
        s
    }

    /// A three-way handshake reads as one, in order, from the right end.
    #[test]
    fn the_handshake_is_named_packet_by_packet() {
        let mut syn = pkt(1, 0, "10.0.0.1", 5000, "10.0.0.2", 443);
        syn.tcp_flags = Some(TCP_FLAG_SYN);
        let mut synack = pkt(2, 12_000_000, "10.0.0.2", 443, "10.0.0.1", 5000);
        synack.tcp_flags = Some(TCP_FLAG_SYN | TCP_FLAG_ACK);
        let mut ack = pkt(3, 24_000_000, "10.0.0.1", 5000, "10.0.0.2", 443);
        ack.tcp_flags = Some(TCP_FLAG_ACK);

        let c = conversation(&stream(), &[syn, synack, ack], 0, Some(2), 10);
        let labels: Vec<&str> = c.rungs.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, ["syn", "syn·ack", "ack"]);
        assert_eq!(
            c.rungs.iter().map(|r| r.from_initiator).collect::<Vec<_>>(),
            [true, false, true],
            "direction is relative to whoever opened the conversation"
        );
        assert_eq!(c.position, Some(2), "1-based position of the selection");
        assert_eq!(c.total, 3);
        assert_eq!(c.phase, Phase::Opening, "no application bytes yet");
        // Offsets are relative to the first packet, not wall clock.
        assert_eq!(c.rungs[0].offset_ms, 0.0);
        assert!((c.rungs[2].offset_ms - 24.0).abs() < 0.001);
    }

    /// A reset outranks everything the flow did beforehand.
    #[test]
    fn a_reset_is_the_headline_however_it_started() {
        let mut syn = pkt(1, 0, "10.0.0.1", 5000, "10.0.0.2", 443);
        syn.tcp_flags = Some(TCP_FLAG_SYN);
        let mut data = pkt(2, 1_000_000, "10.0.0.1", 5000, "10.0.0.2", 443);
        data.tcp_flags = Some(TCP_FLAG_PSH | TCP_FLAG_ACK);
        data.payload_text = "hello".into();
        let mut rst = pkt(3, 2_000_000, "10.0.0.2", 443, "10.0.0.1", 5000);
        rst.tcp_flags = Some(TCP_FLAG_RST);

        let c = conversation(&stream(), &[syn, data, rst], 0, None, 10);
        assert_eq!(c.phase, Phase::Reset);
        assert_eq!(c.rungs[2].role, Role::Rst);
        assert!(c.rungs[2].role.is_alarming());
        assert_eq!(c.rungs[1].label, "data");
    }

    /// A sequence number sent twice in one direction is a retransmit; one
    /// that arrives behind the high-water mark without having been sent
    /// before is the network reordering. They are different findings.
    #[test]
    fn retransmits_and_reordering_are_told_apart() {
        let mk = |id, ns, seq| {
            let mut p = pkt(id, ns, "10.0.0.1", 5000, "10.0.0.2", 443);
            p.tcp_flags = Some(TCP_FLAG_PSH | TCP_FLAG_ACK);
            p.payload_text = "x".into();
            p.tcp_seq = Some(seq);
            p
        };
        // 100, 200, then 100 again (a resend), then 150 (never sent, behind).
        let c = conversation(
            &stream(),
            &[mk(1, 0, 100), mk(2, 1, 200), mk(3, 2, 100), mk(4, 3, 150)],
            0,
            None,
            10,
        );
        assert_eq!(c.rungs[0].note, None);
        assert_eq!(c.rungs[1].note, None);
        assert_eq!(c.rungs[2].note, Some(Note::Retransmit));
        assert_eq!(c.rungs[3].note, Some(Note::OutOfOrder));
        assert_eq!(c.retransmits, 1);
        assert_eq!(c.out_of_order, 1);
    }

    /// A pure ACK consumes no sequence space, so the data segment that
    /// follows it reuses the number. That is the commonest pattern in TCP and
    /// it is not a resend.
    #[test]
    fn an_ack_followed_by_data_on_the_same_seq_is_not_a_retransmit() {
        let mut ack = pkt(1, 0, "10.0.0.1", 5000, "10.0.0.2", 443);
        ack.tcp_flags = Some(TCP_FLAG_ACK);
        ack.tcp_seq = Some(1001);
        let mut data = pkt(2, 1_000_000, "10.0.0.1", 5000, "10.0.0.2", 443);
        data.tcp_flags = Some(TCP_FLAG_PSH | TCP_FLAG_ACK);
        data.tcp_seq = Some(1001);
        data.payload_text = "hello".into();

        let c = conversation(&stream(), &[ack, data], 0, None, 10);
        assert_eq!(c.retransmits, 0, "{:?}", c.rungs);
        assert!(c.rungs.iter().all(|r| r.note.is_none()), "{:?}", c.rungs);

        // The same number a third time, now with payload both times, is one.
        let mut again = pkt(3, 2_000_000, "10.0.0.1", 5000, "10.0.0.2", 443);
        again.tcp_flags = Some(TCP_FLAG_PSH | TCP_FLAG_ACK);
        again.tcp_seq = Some(1001);
        again.payload_text = "hello".into();
        let c = conversation(&stream(), &[ack_clone(), data_clone(), again], 0, None, 10);
        assert_eq!(c.retransmits, 1);
        assert_eq!(c.rungs[2].note, Some(Note::Retransmit));
    }

    fn ack_clone() -> CapturedPacket {
        let mut p = pkt(1, 0, "10.0.0.1", 5000, "10.0.0.2", 443);
        p.tcp_flags = Some(TCP_FLAG_ACK);
        p.tcp_seq = Some(1001);
        p
    }
    fn data_clone() -> CapturedPacket {
        let mut p = pkt(2, 1_000_000, "10.0.0.1", 5000, "10.0.0.2", 443);
        p.tcp_flags = Some(TCP_FLAG_PSH | TCP_FLAG_ACK);
        p.tcp_seq = Some(1001);
        p.payload_text = "hello".into();
        p
    }

    /// `↑` means "sent by whoever opened this", not "sent by whichever
    /// address sorts first". The stream key's ordering is lexical.
    #[test]
    fn the_byte_counters_follow_the_initiator_not_the_key_order() {
        // Key sorting puts "10.0.0.1" first, so a_to_b is client→server.
        let mut s = stream();
        s.total_bytes_a_to_b = 100;
        s.total_bytes_b_to_a = 900;

        let c = conversation(&s, &[], 0, None, 4);
        assert_eq!((c.bytes_out, c.bytes_in), (100, 900), "initiator is addr_a");

        // Now the server opened the connection, so the same raw counters mean
        // the opposite thing.
        s.initiator = Some(("10.0.0.2".into(), 443));
        let c = conversation(&s, &[], 0, None, 4);
        assert_eq!(
            (c.bytes_out, c.bytes_in),
            (900, 100),
            "the counters must follow whoever opened the flow"
        );
    }

    /// The panel names IPv6 ends `[addr]:port`, initiator first, so the
    /// port is not read as one more group of the address.
    #[test]
    fn ipv6_ends_are_bracketed_initiator_first() {
        let mut s = Stream::new(
            0,
            StreamKey::new(
                StreamProtocol::Tcp,
                "2001:db8::10",
                50022,
                "2001:db8::20",
                22,
            ),
            0,
        );
        for (init, want) in [
            (
                ("2001:db8::10", 50022),
                ("[2001:db8::10]:50022", "[2001:db8::20]:22"),
            ),
            (
                ("2001:db8::20", 22),
                ("[2001:db8::20]:22", "[2001:db8::10]:50022"),
            ),
        ] {
            s.initiator = Some((init.0.into(), init.1));
            let c = conversation(&s, &[], 0, None, 4);
            assert_eq!(
                (c.initiator.as_deref(), c.peer.as_deref()),
                (Some(want.0), Some(want.1))
            );
        }
    }

    /// The same sequence number in each direction is two different byte
    /// streams, not a retransmit.
    #[test]
    fn the_two_directions_have_separate_sequence_spaces() {
        let mut a = pkt(1, 0, "10.0.0.1", 5000, "10.0.0.2", 443);
        a.tcp_seq = Some(1);
        let mut b = pkt(2, 1, "10.0.0.2", 443, "10.0.0.1", 5000);
        b.tcp_seq = Some(1);
        let c = conversation(&stream(), &[a, b], 0, None, 10);
        assert_eq!(c.retransmits, 0, "{:?}", c.rungs);
    }

    /// The window keeps the selected packet on screen with context either
    /// side of it — "what happened just before this" is most of the reason
    /// the panel is open.
    #[test]
    fn the_ladder_is_centred_on_the_selection() {
        let all: Vec<CapturedPacket> = (1..=40)
            .map(|i| pkt(i, i * 1_000_000, "10.0.0.1", 5000, "10.0.0.2", 443))
            .collect();
        let c = conversation(&stream(), &all, 0, Some(20), 7);
        assert_eq!(c.rungs.len(), 7);
        assert!(
            c.rungs.iter().any(|r| r.selected),
            "selection must be shown"
        );
        let ids: Vec<u64> = c.rungs.iter().map(|r| r.packet_id).collect();
        assert_eq!(ids, [17, 18, 19, 20, 21, 22, 23]);
        assert!(c.truncated_above && c.truncated_below);
        assert_eq!(c.position, Some(20));
        assert_eq!(c.total, 40);

        // Clamped at the start rather than running off the front.
        let c = conversation(&stream(), &all, 0, Some(1), 7);
        assert_eq!(c.rungs[0].packet_id, 1);
        assert!(!c.truncated_above && c.truncated_below);

        // And at the end.
        let c = conversation(&stream(), &all, 0, Some(40), 7);
        assert_eq!(c.rungs.last().unwrap().packet_id, 40);
        assert!(c.truncated_above && !c.truncated_below);
    }

    /// With nothing selected, show the live end of the conversation — that is
    /// the part still changing.
    #[test]
    fn an_unselected_stream_shows_its_most_recent_packets() {
        let all: Vec<CapturedPacket> = (1..=20)
            .map(|i| pkt(i, i * 1_000_000, "10.0.0.1", 5000, "10.0.0.2", 443))
            .collect();
        let c = conversation(&stream(), &all, 0, None, 5);
        assert_eq!(
            c.rungs.iter().map(|r| r.packet_id).collect::<Vec<_>>(),
            [16, 17, 18, 19, 20]
        );
        assert_eq!(c.position, None);
        assert!(!c.truncated_below);
    }

    /// Packets belonging to other conversations stay out of this one.
    #[test]
    fn only_this_streams_packets_are_laddered() {
        let mut mine = pkt(1, 0, "10.0.0.1", 5000, "10.0.0.2", 443);
        mine.stream_index = Some(0);
        let mut theirs = pkt(2, 1, "10.0.0.9", 6000, "10.0.0.8", 443);
        theirs.stream_index = Some(7);
        let c = conversation(&stream(), &[mine, theirs], 0, None, 10);
        assert_eq!(c.total, 1);
        assert_eq!(c.rungs[0].packet_id, 1);
    }

    /// Out-of-order arrival in the capture buffer must not scramble the
    /// ladder: the sequence is what the operator is reading.
    #[test]
    fn the_ladder_is_ordered_by_time_not_by_capture_order() {
        let a = pkt(1, 30_000_000, "10.0.0.1", 5000, "10.0.0.2", 443);
        let b = pkt(2, 10_000_000, "10.0.0.1", 5000, "10.0.0.2", 443);
        let c = conversation(&stream(), &[a, b], 0, None, 10);
        assert_eq!(
            c.rungs.iter().map(|r| r.packet_id).collect::<Vec<_>>(),
            [2, 1]
        );
        assert_eq!(c.rungs[0].offset_ms, 0.0);
        assert!((c.rungs[1].offset_ms - 20.0).abs() < 0.001);
    }

    /// DNS queries and replies are told apart by which end port 53 is on.
    #[test]
    fn dns_queries_and_replies_are_distinguished() {
        let mut q = pkt(1, 0, "10.0.0.1", 5000, "10.0.0.2", 53);
        q.protocol = "DNS".into();
        q.info = "Standard query A example.com".into();
        let mut r = pkt(2, 5_000_000, "10.0.0.2", 53, "10.0.0.1", 5000);
        r.protocol = "DNS".into();
        r.info = "Response A 93.184.216.34".into();

        let c = conversation(&stream(), &[q, r], 0, None, 10);
        assert_eq!(c.rungs[0].role, Role::Query);
        assert_eq!(c.rungs[1].role, Role::Reply);
        assert_eq!(c.phase, Phase::Active);
        // A long info line falls back to the generic word rather than
        // overflowing the rung.
        assert_eq!(c.rungs[0].label, "standard query a example.com");
        let mut long = pkt(3, 6_000_000, "10.0.0.1", 5000, "10.0.0.2", 53);
        long.protocol = "DNS".into();
        long.info = "Standard query A a-very-long-name.example.invalid".into();
        let c = conversation(&stream(), &[long], 0, None, 10);
        assert_eq!(c.rungs[0].label, "query");
    }

    /// Without a recorded initiator the panel must not assert which end
    /// opened the conversation — the key's ordering is canonical, not causal.
    #[test]
    fn an_unknown_initiator_is_left_unnamed() {
        let mut s = stream();
        s.initiator = None;
        let c = conversation(
            &s,
            &[pkt(1, 0, "10.0.0.1", 5000, "10.0.0.2", 443)],
            0,
            None,
            10,
        );
        assert!(c.initiator.is_none());
        assert!(c.peer.is_none());
    }

    /// An empty stream renders as an empty ladder rather than panicking on
    /// the arithmetic.
    #[test]
    fn an_empty_conversation_is_not_a_panic() {
        let c = conversation(&stream(), &[], 0, Some(1), 8);
        assert!(c.rungs.is_empty());
        assert_eq!(c.total, 0);
        assert_eq!(c.position, None);
        assert_eq!(c.duration_ms, 0.0);
        assert!(!c.truncated_above && !c.truncated_below);
        // And a zero-height panel asks for zero rungs.
        let c = conversation(
            &stream(),
            &[pkt(1, 0, "10.0.0.1", 5000, "10.0.0.2", 443)],
            0,
            None,
            0,
        );
        assert!(c.rungs.is_empty());
    }
}
