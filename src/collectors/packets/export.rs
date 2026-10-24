//! Packet export: classic PCAP and annotated PCAPNG, written from the capture
//! metadata the capture thread records with each packet, plus the historical
//! socket observations that annotate PCAPNG packets.
//!
//! What this writes is a stable file format. docs/REFERENCE.md ("Capture
//! export format") is its specification, so a change to the blocks, options
//! or comment keys written here is a change to that document, and the
//! annotation schema name changes with any change a reader could notice.
//!
//! Timestamps and lengths come from libpcap's own header for the frame, never
//! from the time-of-day text the packet list shows. A packet without capture
//! metadata (a demo packet, say) is left out and counted, because giving it a
//! made-up timestamp would put false evidence in the file.

use super::{CapturedPacket, StreamKey, StreamProtocol};
use crate::collectors::attribution::ProcessIdentity;
use crate::collectors::connections::{
    connection_stream_key, AttributionSource, Connection, LocalSide,
};
use serde::Serialize;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// The `schema` key of every PCAPNG packet comment. Bumped to `v2` for any
/// change a reader could notice: a key renamed or removed, or a meaning
/// changed. New optional keys do not bump it.
pub const ANNOTATION_SCHEMA: &str = "netwatch.annotation.v1";

/// Longest text netwatch puts in a comment value or an interface name, in
/// characters. Process names, SNIs and interface names come from other
/// programs and peers; this keeps one comment far below the 64 KiB a PCAPNG
/// option can hold, whatever they contain.
const MAX_TEXT_CHARS: usize = 160;

/// Longest bracket between two socket observations that may annotate the
/// packets inside it, from the start of the first owner check to the end of
/// the second. Owners are checked about once a second, so anything wider
/// means checks were missed and the socket could have changed hands in
/// between.
const MAX_BRACKET_MS: u64 = 5000;

/// Timestamps are written in microseconds, which is what live libpcap capture
/// delivers. PCAPNG says so with `if_tsresol`, classic PCAP with its magic.
const MICROS_PER_SECOND: u64 = 1_000_000;

/// The PCAPNG link type for a live capture's data link, or `None` when it has
/// no portable equivalent, in which case its packets carry no capture
/// metadata and are omitted from exports.
///
/// libpcap's DLT numbers are the file LINKTYPE numbers except for a few
/// historical ones that differ between operating systems (DLT_RAW is 12 on
/// Linux and 14 on OpenBSD; LINKTYPE_RAW is 101), so those are resolved by
/// name, once per capture start.
pub fn file_link_type(dlt: pcap::Linktype) -> Option<u16> {
    link_type_for(dlt.get_name().ok().as_deref(), dlt.0)
}

fn link_type_for(name: Option<&str>, dlt: i32) -> Option<u16> {
    let by_name = match name? {
        "NULL" => Some(0),
        "EN10MB" => Some(1),
        "PPP_SERIAL" => Some(50),
        "PPP_ETHER" => Some(51),
        "SYMANTEC_FIREWALL" => Some(99),
        "ATM_RFC1483" => Some(100),
        "RAW" => Some(101),
        "SLIP_BSDOS" => Some(102),
        "PPP_BSDOS" => Some(103),
        "ATM_CLIP" => Some(106),
        "LOOP" => Some(108),
        "ENC" => Some(109),
        "PFSYNC" => Some(246),
        "PKTAP" => Some(258),
        _ => None,
    };
    // Below 104 only 2-10 are shared between DLT and LINKTYPE numbering.
    by_name.or_else(|| {
        u16::try_from(dlt)
            .ok()
            .filter(|d| *d >= 104 || (2..=10).contains(d))
    })
}

/// What libpcap reported about a captured frame, beyond its bytes. The
/// session and interface are shared by every packet of a capture, so each
/// packet holds a reference rather than its own copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureMetadata {
    /// Identifies one capture start; a restart on the same interface is a
    /// new session and gets its own PCAPNG interface block.
    pub session: Arc<str>,
    pub interface: Arc<str>,
    /// PCAPNG / pcap-savefile LINKTYPE of the bytes in `raw_bytes`.
    pub link_type: u16,
    /// UTC epoch time libpcap stamped the frame with, in nanoseconds. Live
    /// capture stamps in microseconds, so the last three digits are zero.
    pub timestamp_ns: u64,
    /// Length of the frame on the wire, which can exceed the bytes captured.
    pub original_len: u32,
}

impl CaptureMetadata {
    /// `None` for a header libpcap should never produce: a time before the
    /// epoch or with 10^6 microseconds or more, or fewer bytes on the wire
    /// than were captured.
    pub fn from_pcap(
        session: &Arc<str>,
        interface: &Arc<str>,
        link_type: u16,
        h: &pcap::PacketHeader,
    ) -> Option<Self> {
        Self::from_parts(
            session,
            interface,
            link_type,
            h.ts.tv_sec,
            h.ts.tv_usec,
            h.caplen,
            h.len,
        )
    }

    /// `timeval`'s field types differ by platform (32-bit on Windows), so
    /// they are taken as they come.
    fn from_parts(
        session: &Arc<str>,
        interface: &Arc<str>,
        link_type: u16,
        seconds: impl TryInto<u64>,
        micros: impl TryInto<u64>,
        caplen: u32,
        len: u32,
    ) -> Option<Self> {
        let seconds: u64 = seconds.try_into().ok()?;
        let micros: u64 = micros.try_into().ok()?;
        if micros >= MICROS_PER_SECOND || len < caplen {
            return None;
        }
        Some(Self {
            session: Arc::clone(session),
            interface: Arc::clone(interface),
            link_type,
            timestamp_ns: seconds
                .checked_mul(1_000_000_000)?
                .checked_add(micros * 1000)?,
            original_len: len,
        })
    }
}

/// Which way a packet went relative to the observed socket's local end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Outbound,
    Inbound,
}

/// The socket owner recorded for a packet while it was captured. Frozen once
/// set, so the export never consults the live process table: a PID looked up
/// at export time could belong to a different process by then.
#[derive(Debug, Clone)]
pub struct PacketAnnotation {
    pub process: ProcessIdentity,
    pub process_name: Option<String>,
    pub source: AttributionSource,
    /// UTC ms by which the earlier check of the owner had finished.
    pub before_utc_ms: u64,
    /// UTC ms at which the later check of the owner began.
    pub after_utc_ms: u64,
    pub flow_generation: u64,
    pub capture_generation: u32,
    pub direction: Direction,
}

/// One connection-table row reduced to what an annotation needs, kept until
/// the next poll so a packet can be checked against the polls either side.
#[derive(Debug, Clone)]
struct Observation {
    process: ProcessIdentity,
    process_name: Option<String>,
    source: AttributionSource,
    /// The owner was seen holding the socket at some point from
    /// `checked_from` to `checked_until`, UTC ms. Not the poll's time: see
    /// `MatchEvidence::owner_checked_utc_ms`.
    checked_from: u64,
    checked_until: u64,
    flow_session: String,
    flow_generation: u64,
    capture_generation: Option<u32>,
    local: (String, u16),
    remote: String,
}

impl Observation {
    /// `None` for a row whose owner is not verified now: unknown, stale, or
    /// without a process identity, flow or time of check.
    fn from_connection(c: &Connection, local: (String, u16)) -> Option<Self> {
        if !c.evidence.verified() {
            return None;
        }
        let flow = c.evidence.flow.as_ref()?;
        let (checked_from, checked_until) = c
            .evidence
            .owner_checked_utc_ms
            .filter(|(from, until)| from <= until)?;
        Some(Self {
            process: c.evidence.process.clone()?,
            process_name: c.process_name.clone(),
            source: c.attribution,
            checked_from,
            checked_until,
            flow_session: flow.session.clone(),
            flow_generation: flow.generation,
            capture_generation: flow.capture_generation,
            local,
            remote: flow.remote.clone(),
        })
    }

    /// Whether `self`, the earlier poll, and `later` describe one socket
    /// owned by one process, for a packet of capture stream `generation`,
    /// from two separate checks of the owner: polls that carry one broker
    /// scan have overlapping check times and never qualify.
    fn same_socket(&self, later: &Self, generation: u32) -> bool {
        self.process == later.process
            && self.flow_session == later.flow_session
            && self.flow_generation == later.flow_generation
            && self.capture_generation == Some(generation)
            && later.capture_generation == Some(generation)
            && self.local == later.local
            && self.remote == later.remote
            && self.checked_until < later.checked_from
            && later.checked_until - self.checked_from <= MAX_BRACKET_MS
    }
}

/// Annotates packets with the socket owner only when two consecutive polls of
/// the connection table agree on it and the packet was captured between the
/// checks of the owner they carry: the earlier check finished before the
/// packet and the later one began after it. One check is not enough: the
/// socket may have changed hands just before or after it. A check is not the
/// poll itself, since on Linux a sandboxed poll takes owners from the
/// broker's latest `/proc` scan, which can predate the poll and be shared by
/// several. `None` entries mark flows with no single verified owner, such as
/// loopback, where both ends are local and may be different processes.
#[derive(Default)]
pub struct AnnotationHistory {
    previous: HashMap<StreamKey, Option<Observation>>,
    session: Option<Arc<str>>,
}

impl AnnotationHistory {
    pub fn clear(&mut self) {
        self.previous.clear();
        self.session = None;
    }

    /// Record one poll of the connection table and annotate the packets it
    /// and the previous poll bracket.
    pub fn observe(&mut self, connections: &[Connection], packets: &mut [CapturedPacket]) {
        let session = packets
            .iter()
            .rev()
            .find_map(|p| p.capture.as_ref().map(|m| m.session.clone()));
        if self.session != session {
            // A new capture has new stream indexes; the old poll cannot
            // vouch for them.
            self.previous.clear();
            self.session = session;
        }
        let mut current: HashMap<StreamKey, Option<Observation>> = HashMap::new();
        for c in connections {
            let Some((key, side)) = connection_stream_key(c) else {
                continue;
            };
            let local = match side {
                LocalSide::A => key.addr_a.clone(),
                LocalSide::B => key.addr_b.clone(),
            };
            let observation = Observation::from_connection(c, local);
            current
                .entry(key)
                .and_modify(|seen| *seen = None)
                .or_insert(observation);
        }
        // Only a packet newer than the oldest earlier check can sit inside a
        // bracket, so the rest of the ring is skipped without building keys.
        let floor = self
            .previous
            .values()
            .flatten()
            .map(|o| o.checked_until)
            .min();
        if let (Some(floor), Some(session)) = (floor, self.session.as_deref()) {
            for packet in packets.iter_mut() {
                annotate(packet, session, floor, &self.previous, &current);
            }
        }
        self.previous = current;
    }
}

fn annotate(
    packet: &mut CapturedPacket,
    session: &str,
    floor: u64,
    previous: &HashMap<StreamKey, Option<Observation>>,
    current: &HashMap<StreamKey, Option<Observation>>,
) {
    if packet.annotation.is_some() {
        return;
    }
    let Some(meta) = packet.capture.as_ref().filter(|m| &*m.session == session) else {
        return;
    };
    // Millisecond resolution on both sides. Both boundary milliseconds are
    // excluded, since the order within one millisecond is unknown, and a
    // clock step leaves packets outside every bracket, so they stay unknown.
    let ms = meta.timestamp_ns / 1_000_000;
    if ms <= floor {
        return;
    }
    let (Some(sp), Some(dp), Some(generation)) =
        (packet.src_port, packet.dst_port, packet.stream_index)
    else {
        return;
    };
    let protocol = if packet.tcp_flags.is_some() {
        StreamProtocol::Tcp
    } else {
        StreamProtocol::Udp
    };
    let key = StreamKey::new(protocol, &packet.src_ip, sp, &packet.dst_ip, dp);
    let (Some(Some(before)), Some(Some(after))) = (previous.get(&key), current.get(&key)) else {
        return;
    };
    if !before.same_socket(after, generation)
        || ms <= before.checked_until
        || ms >= after.checked_from
    {
        return;
    }
    let outbound = after.local.0 == packet.src_ip && after.local.1 == sp;
    packet.annotation = Some(Box::new(PacketAnnotation {
        process: after.process.clone(),
        process_name: after.process_name.clone(),
        source: after.source,
        before_utc_ms: before.checked_until,
        after_utc_ms: after.checked_from,
        flow_generation: after.flow_generation,
        capture_generation: generation,
        direction: if outbound {
            Direction::Outbound
        } else {
            Direction::Inbound
        },
    }));
}

/// Text from another program or a peer, made safe to read in Wireshark or a
/// terminal and bounded: characters that could reorder or hide text become
/// the same mark the packet list uses, so tampering stays visible.
fn clean(value: &str) -> String {
    use crate::ui::sanitize::{display, REPLACEMENT};
    display(value)
        .chars()
        .map(|c| if invisible(c) { REPLACEMENT } else { c })
        .take(MAX_TEXT_CHARS)
        .collect()
}

/// Every format character (General_Category Cf, as of Unicode 16) and the
/// line and paragraph separators. The terminal sanitizer passes most of
/// them, since a terminal draws them harmlessly, but a comment reader shows
/// a tag character or a soft hyphen as nothing and U+2028 as a line break,
/// so an SNI could read as another name.
fn invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Pcap,
    PcapNg,
}

impl Format {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Pcap => "pcap",
            Self::PcapNg => "pcapng",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ExportSummary {
    /// Packets written.
    pub packets: usize,
    /// Packets left out because they have no usable capture metadata.
    pub omitted: usize,
    /// Written packets whose comment names a socket owner.
    pub annotated: usize,
}

pub fn preview<P: Borrow<CapturedPacket>>(packets: &[P]) -> ExportSummary {
    preview_iter(packets.iter().map(Borrow::borrow))
}

pub fn preview_iter<'a>(packets: impl IntoIterator<Item = &'a CapturedPacket>) -> ExportSummary {
    let mut summary = ExportSummary::default();
    for p in packets {
        if exportable(p).is_some() {
            summary.packets += 1;
            summary.annotated += usize::from(p.annotation.is_some());
        } else {
            summary.omitted += 1;
        }
    }
    summary
}

/// Whether classic PCAP can hold every exportable packet: one link type, and
/// times before 2106, when its 32-bit seconds run out. True for an empty
/// selection.
pub fn fits_pcap<P: Borrow<CapturedPacket>>(packets: &[P]) -> bool {
    single_link_type(packets)
        && packets
            .iter()
            .filter_map(|p| exportable(p.borrow()))
            .all(|m| m.timestamp_ns / 1_000_000_000 <= u64::from(u32::MAX))
}

/// Whether every exportable packet shares one link type, which classic PCAP
/// needs. True for an empty selection.
pub fn single_link_type<P: Borrow<CapturedPacket>>(packets: &[P]) -> bool {
    let mut types = packets
        .iter()
        .filter_map(|p| exportable(p.borrow()))
        .map(|m| m.link_type);
    let first = types.next();
    types.all(|t| Some(t) == first)
}

/// The packet's capture metadata, when its bytes can be written as captured:
/// some bytes, no more than were on the wire, and no more than the snaplen
/// both formats declare.
fn exportable(p: &CapturedPacket) -> Option<&CaptureMetadata> {
    p.capture.as_ref().filter(|m| {
        !p.raw_bytes.is_empty()
            && p.raw_bytes.len() <= m.original_len as usize
            && p.raw_bytes.len() <= super::CAPTURE_SNAPLEN as usize
    })
}

fn cancelled(cancel: &AtomicBool) -> io::Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "Export cancelled",
        ))
    } else {
        Ok(())
    }
}

/// Write `path` without ever overwriting it or leaving a partial file there.
///
/// The bytes go to an owner-only temporary file beside `path`, which is then
/// hard-linked to `path`: the link fails if `path` exists, and appears only
/// once the file is complete. The temporary name is removed on every outcome,
/// so a failed or cancelled write leaves nothing behind (only a crash can
/// leave a `.netwatch-export-*.tmp`). A filesystem without hard links fails
/// the export rather than falling back to writing `path` in place.
pub fn atomic_write(
    path: &Path,
    write: impl FnOnce(&mut std::fs::File) -> io::Result<()>,
) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = parent.join(format!(
        ".netwatch-export-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let result = (|| {
        let mut file = crate::owner_only::file_options()
            .create_new(true)
            .open(&temporary)?;
        write(&mut file)?;
        file.sync_all()?;
        drop(file);
        std::fs::hard_link(&temporary, path)
    })();
    let _ = std::fs::remove_file(&temporary);
    result
}

/// Write the exportable `packets` to a new file at `path`.
///
/// `annotations` adds a JSON comment to every PCAPNG packet; classic PCAP has
/// nowhere to put one. A selection that has packets but none with capture
/// metadata is an error, since the file would claim a capture that never
/// happened. An empty selection writes an empty capture.
pub fn export_capture<P: Borrow<CapturedPacket>>(
    packets: &[P],
    path: &Path,
    format: Format,
    annotations: bool,
    cancel: &AtomicBool,
) -> Result<ExportSummary, String> {
    let mut summary = preview(packets);
    if !annotations || format == Format::Pcap {
        summary.annotated = 0;
    }
    if summary.packets == 0 && !packets.is_empty() {
        return Err(
            "No packets have exportable capture metadata (synthetic/legacy packets are omitted)"
                .into(),
        );
    }
    cancelled(cancel).map_err(|e| e.to_string())?;
    atomic_write(path, |file| {
        let mut writer = io::BufWriter::new(file);
        match format {
            Format::Pcap => write_pcap(&mut writer, packets, cancel)?,
            Format::PcapNg => write_pcapng(&mut writer, packets, annotations, cancel)?,
        }
        cancelled(cancel)?;
        writer.flush()
    })
    .map_err(|e| e.to_string())?;
    Ok(summary)
}

/// Classic little-endian, microsecond PCAP: the most widely readable form,
/// one link type per file.
fn write_pcap<P: Borrow<CapturedPacket>>(
    w: &mut impl Write,
    packets: &[P],
    cancel: &AtomicBool,
) -> io::Result<()> {
    if !single_link_type(packets) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Mixed framing requires PCAPNG",
        ));
    }
    let eligible = packets
        .iter()
        .map(Borrow::borrow)
        .filter_map(|p| Some((p, exportable(p)?)));
    let link = eligible.clone().next().map_or(1, |(_, m)| m.link_type);
    for value in [
        0xa1b2c3d4u32, // magic: microsecond timestamps
        0x0004_0002,   // version 2.4, as major 2 then minor 4 in little-endian u16s
        0,             // thiszone
        0,             // sigfigs
        super::CAPTURE_SNAPLEN as u32,
        u32::from(link),
    ] {
        w.write_all(&value.to_le_bytes())?;
    }
    for (p, m) in eligible {
        cancelled(cancel)?;
        let micros = m.timestamp_ns / 1000;
        let seconds = u32::try_from(micros / MICROS_PER_SECOND).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Timestamp requires PCAPNG")
        })?;
        for value in [
            seconds,
            (micros % MICROS_PER_SECOND) as u32,
            p.raw_bytes.len() as u32,
            m.original_len,
        ] {
            w.write_all(&value.to_le_bytes())?;
        }
        w.write_all(&p.raw_bytes)?;
    }
    Ok(())
}

// PCAPNG block types and option codes (draft-ietf-opsawg-pcapng).
const SHB: u32 = 0x0A0D_0D0A;
const IDB: u32 = 0x0000_0001;
const EPB: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;
const OPT_ENDOFOPT: u16 = 0;
const OPT_COMMENT: u16 = 1;
const SHB_USERAPPL: u16 = 4;
const IF_NAME: u16 = 2;
const IF_TSRESOL: u16 = 9;
/// `if_tsresol` value: 10^-6 seconds, matching the timestamps written.
const TSRESOL_MICROS: u8 = 6;

/// A block's options: each is code, length, value padded to 32 bits, and the
/// list ends with `opt_endofopt`, which is left out when there are none.
#[derive(Default)]
struct Options(Vec<u8>);

impl Options {
    fn add(&mut self, code: u16, value: &[u8]) -> io::Result<()> {
        let len = u16::try_from(value.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "PCAPNG option too long"))?;
        self.0.extend(code.to_le_bytes());
        self.0.extend(len.to_le_bytes());
        self.0.extend(value);
        pad(&mut self.0);
        Ok(())
    }

    fn finish(mut self, body: &mut Vec<u8>) {
        if !self.0.is_empty() {
            self.0.extend(OPT_ENDOFOPT.to_le_bytes());
            self.0.extend(0u16.to_le_bytes());
            body.extend(self.0);
        }
    }
}

fn pad(bytes: &mut Vec<u8>) {
    while !bytes.len().is_multiple_of(4) {
        bytes.push(0);
    }
}

/// Type, total length, body, total length again. Every body here is already
/// padded to 32 bits, so the total is a multiple of 4.
fn block(kind: u32, body: &[u8]) -> io::Result<Vec<u8>> {
    debug_assert!(body.len().is_multiple_of(4));
    let len = u32::try_from(body.len() + 12).map_err(io::Error::other)?;
    let mut out = Vec::with_capacity(body.len() + 12);
    out.extend(kind.to_le_bytes());
    out.extend(len.to_le_bytes());
    out.extend(body);
    out.extend(len.to_le_bytes());
    Ok(out)
}

/// Section header: little-endian byte-order magic, version 1.0, section
/// length unknown (-1), and which program wrote it.
fn section_header() -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend(BYTE_ORDER_MAGIC.to_le_bytes());
    body.extend(1u16.to_le_bytes());
    body.extend(0u16.to_le_bytes());
    body.extend((-1i64).to_le_bytes());
    let mut options = Options::default();
    options.add(
        SHB_USERAPPL,
        concat!("netwatch ", env!("CARGO_PKG_VERSION")).as_bytes(),
    )?;
    options.finish(&mut body);
    block(SHB, &body)
}

/// One interface description per capture session, interface and link type,
/// in the order their first packets appear.
fn interface_description(link_type: u16, name: &str) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    body.extend(link_type.to_le_bytes());
    body.extend(0u16.to_le_bytes());
    body.extend((super::CAPTURE_SNAPLEN as u32).to_le_bytes());
    let mut options = Options::default();
    let name = clean(name);
    if !name.is_empty() {
        options.add(IF_NAME, name.as_bytes())?;
    }
    options.add(IF_TSRESOL, &[TSRESOL_MICROS])?;
    options.finish(&mut body);
    block(IDB, &body)
}

fn enhanced_packet(
    interface_id: u32,
    meta: &CaptureMetadata,
    data: &[u8],
    comment: Option<&str>,
) -> io::Result<Vec<u8>> {
    let micros = meta.timestamp_ns / 1000;
    let mut body = Vec::with_capacity(20 + data.len() + 3);
    for value in [
        interface_id,
        (micros >> 32) as u32,
        micros as u32,
        data.len() as u32,
        meta.original_len,
    ] {
        body.extend(value.to_le_bytes());
    }
    body.extend(data);
    pad(&mut body);
    let mut options = Options::default();
    if let Some(comment) = comment {
        options.add(OPT_COMMENT, comment.as_bytes())?;
    }
    options.finish(&mut body);
    block(EPB, &body)
}

fn write_pcapng<P: Borrow<CapturedPacket>>(
    w: &mut impl Write,
    packets: &[P],
    annotations: bool,
    cancel: &AtomicBool,
) -> io::Result<()> {
    w.write_all(&section_header()?)?;
    let mut interfaces: HashMap<(&str, &str, u16), u32> = HashMap::new();
    for p in packets.iter().map(Borrow::borrow) {
        let Some(m) = exportable(p) else {
            continue;
        };
        cancelled(cancel)?;
        let key = (&*m.session, &*m.interface, m.link_type);
        let id = match interfaces.get(&key) {
            Some(id) => *id,
            None => {
                let id = u32::try_from(interfaces.len()).map_err(io::Error::other)?;
                w.write_all(&interface_description(m.link_type, &m.interface)?)?;
                interfaces.insert(key, id);
                id
            }
        };
        let comment = if annotations {
            Some(serde_json::to_string(&Comment::new(p, m)).map_err(io::Error::other)?)
        } else {
            None
        };
        w.write_all(&enhanced_packet(id, m, &p.raw_bytes, comment.as_deref())?)?;
    }
    // libpcap refuses a section with no interface, so a file without packets
    // still describes one: Ethernet, as classic PCAP's header does then.
    if interfaces.is_empty() {
        w.write_all(&interface_description(1, "")?)?;
    }
    Ok(())
}

/// The JSON in a PCAPNG packet's `opt_comment`, schema [`ANNOTATION_SCHEMA`].
/// Every key is listed in docs/REFERENCE.md. Free text from the packet (HTTP
/// paths, the info column, decrypted payloads) never goes in.
#[derive(Serialize)]
struct Comment {
    schema: &'static str,
    packet_id: u64,
    capture_session: String,
    protocol: String,
    status: &'static str,
    #[serde(flatten)]
    owner: Option<Owner>,
    #[serde(skip_serializing_if = "Option::is_none")]
    app: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ech_outer: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ja4: Option<String>,
}

/// Present when `status` is `bracketed_socket_observation`.
#[derive(Serialize)]
struct Owner {
    pid: u32,
    process_name: Option<String>,
    process_session: String,
    start_token: String,
    executable_identity: Option<String>,
    network_namespace: Option<String>,
    source: AttributionSource,
    direction: Direction,
    before_utc_ms: u64,
    after_utc_ms: u64,
    flow_generation: u64,
    capture_generation: u32,
}

impl Comment {
    fn new(p: &CapturedPacket, m: &CaptureMetadata) -> Self {
        use crate::dpi::AppProtocol;
        let owner = p.annotation.as_ref().map(|a| Owner {
            pid: a.process.pid,
            process_name: a.process_name.as_deref().map(clean),
            process_session: clean(&a.process.session),
            start_token: clean(&a.process.start_token),
            executable_identity: a.process.executable.as_deref().map(clean),
            network_namespace: a.process.network_namespace.as_deref().map(clean),
            source: a.source,
            direction: a.direction,
            before_utc_ms: a.before_utc_ms,
            after_utc_ms: a.after_utc_ms,
            flow_generation: a.flow_generation,
            capture_generation: a.capture_generation,
        });
        let mut comment = Self {
            schema: ANNOTATION_SCHEMA,
            packet_id: p.id,
            capture_session: clean(&m.session),
            protocol: clean(&p.protocol),
            status: if owner.is_some() {
                "bracketed_socket_observation"
            } else {
                "unknown_owner"
            },
            owner,
            app: p.app_protocol.as_ref().map(app_token),
            sni: None,
            ech_outer: None,
            alpn: None,
            ja4: None,
        };
        match &p.app_protocol {
            Some(AppProtocol::Tls {
                sni,
                alpn,
                ech,
                ja4,
            }) => {
                comment.sni = sni.as_deref().map(clean);
                comment.ech_outer = sni.as_ref().map(|_| *ech);
                comment.alpn = alpn.as_deref().map(clean);
                comment.ja4 = ja4.as_deref().map(clean);
            }
            Some(AppProtocol::Quic { sni, ech, ja4 }) => {
                comment.sni = sni.as_deref().map(clean);
                comment.ech_outer = sni.as_ref().map(|_| *ech);
                comment.ja4 = ja4.as_deref().map(clean);
            }
            _ => {}
        }
        comment
    }
}

/// The comment's `app` value: which DPI classifier recognised the flow. Only
/// the name; fields such as an SNMP community or an FTP command are not
/// copied, since they can be credentials.
fn app_token(app: &crate::dpi::AppProtocol) -> &'static str {
    use crate::dpi::AppProtocol::*;
    match app {
        Tls { .. } => "tls",
        Http { .. } => "http",
        Dns { .. } => "dns",
        Ssh { .. } => "ssh",
        Quic { .. } => "quic",
        Mqtt { .. } => "mqtt",
        Stun { .. } => "stun",
        BitTorrent { .. } => "bittorrent",
        NetBios { .. } => "netbios",
        Snmp { .. } => "snmp",
        Ssdp { .. } => "ssdp",
        Ftp { .. } => "ftp",
        Llmnr { .. } => "llmnr",
        Dhcp { .. } => "dhcp",
        Ntp { .. } => "ntp",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::attribution::{FlowIdentity, MatchEvidence};
    use std::time::Instant;

    fn packet() -> CapturedPacket {
        let mut p = super::super::build_packet(
            &std::sync::Arc::new(std::sync::Mutex::new(0)),
            "UDP",
            64,
            "127.0.0.1",
            "192.0.2.1",
            Some(1234),
            Some(53),
            "",
            vec![],
            &[],
            &[0; 42],
            &super::super::DnsCache::new(),
            None,
            None,
        );
        p.capture = Some(CaptureMetadata {
            session: "capture-a".into(),
            interface: "eth0".into(),
            link_type: 1,
            // 23:59:59.999123 UTC, so a second packet 2 ms later crosses midnight.
            timestamp_ns: 1_700_006_399_999_123_000,
            original_len: 64,
        });
        p.stream_index = Some(4);
        p
    }

    fn path(extension: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "netwatch-export-{}.{}",
            uuid::Uuid::new_v4(),
            extension
        ))
    }

    fn conn(ms: u64) -> Connection {
        Connection {
            protocol: "UDP".into(),
            local_addr: "127.0.0.1:1234".into(),
            remote_addr: "192.0.2.1:53".into(),
            state: "".into(),
            pid: Some(42),
            process_name: Some("lookup".into()),
            handshake_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
            attribution: AttributionSource::Procfs,
            evidence: MatchEvidence {
                observed_at: Some(Instant::now()),
                observed_at_utc_ms: Some(ms),
                owner_checked_utc_ms: Some((ms, ms)),
                process: Some(ProcessIdentity {
                    session: "run".into(),
                    pid: 42,
                    start_token: "123".into(),
                    executable: None,
                    network_namespace: Some("ns1".into()),
                }),
                flow: Some(FlowIdentity {
                    session: "run".into(),
                    generation: 8,
                    capture_generation: Some(4),
                    protocol: "UDP".into(),
                    local: "127.0.0.1:1234".into(),
                    remote: "192.0.2.1:53".into(),
                    network_namespace: Some("ns1".into()),
                }),
                unknown_reason: None,
                corroborated_by: None,
                event_age_at_match_ms: None,
            },
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        }
    }

    /// A packet annotated the way the capture path would, from polls 100 ms
    /// either side of it.
    fn annotated(mut p: CapturedPacket) -> CapturedPacket {
        let ms = p.capture.as_ref().unwrap().timestamp_ns / 1_000_000;
        let mut packets = vec![p.clone()];
        let mut history = AnnotationHistory::default();
        history.observe(&[conn(ms - 100)], &mut packets);
        history.observe(&[conn(ms + 100)], &mut packets);
        p.annotation = packets.pop().unwrap().annotation;
        assert!(p.annotation.is_some());
        p
    }

    fn u16_at(data: &[u8], at: usize) -> u16 {
        u16::from_le_bytes(data[at..at + 2].try_into().unwrap())
    }
    fn u32_at(data: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
    }

    /// One block, read back with every length and padding rule checked.
    #[derive(Debug)]
    struct Block {
        kind: u32,
        body: Vec<u8>,
    }

    /// A strict reader for the subset of PCAPNG netwatch writes: it fails
    /// the test on anything the specification forbids, rather than skipping.
    fn blocks(data: &[u8]) -> Vec<Block> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < data.len() {
            assert!(data.len() - at >= 12, "truncated block at {at}");
            let kind = u32_at(data, at);
            let len = u32_at(data, at + 4) as usize;
            assert!(len >= 12 && len.is_multiple_of(4), "block length {len}");
            assert!(at + len <= data.len(), "block overruns the file");
            assert_eq!(u32_at(data, at + len - 4) as usize, len, "trailing length");
            out.push(Block {
                kind,
                body: data[at + 8..at + len - 4].to_vec(),
            });
            at += len;
        }
        assert_eq!(at, data.len());
        out
    }

    /// Options from `at` to the end of `body`, checking padding and that
    /// `opt_endofopt` ends a non-empty list and appears nowhere else.
    fn options(body: &[u8], mut at: usize) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        if at == body.len() {
            return out;
        }
        loop {
            assert!(body.len() - at >= 4, "truncated option");
            let code = u16_at(body, at);
            let len = u16_at(body, at + 2) as usize;
            at += 4;
            if code == OPT_ENDOFOPT {
                assert_eq!(len, 0);
                assert_eq!(at, body.len(), "data after opt_endofopt");
                assert!(!out.is_empty(), "opt_endofopt alone");
                return out;
            }
            let padded = len.div_ceil(4) * 4;
            assert!(at + padded <= body.len(), "option overruns its block");
            assert!(body[at + len..at + padded].iter().all(|b| *b == 0));
            out.push((code, body[at..at + len].to_vec()));
            at += padded;
        }
    }

    struct Packet {
        interface: u32,
        ts: u64,
        data: Vec<u8>,
        original_len: u32,
        comment: Option<serde_json::Value>,
    }

    struct Interface {
        link_type: u16,
        name: Option<String>,
        tsresol: u8,
    }

    fn read_pcapng(data: &[u8]) -> (Vec<Interface>, Vec<Packet>) {
        let blocks = blocks(data);
        assert_eq!(blocks[0].kind, SHB, "file starts with a section header");
        let shb = &blocks[0].body;
        assert_eq!(&shb[..4], &[0x4D, 0x3C, 0x2B, 0x1A], "little-endian BOM");
        assert_eq!((u16_at(shb, 4), u16_at(shb, 6)), (1, 0), "version 1.0");
        assert_eq!(&shb[8..16], &[0xFF; 8], "section length unspecified");
        let shb_options = options(shb, 16);
        let appl = shb_options
            .iter()
            .find(|(c, _)| *c == SHB_USERAPPL)
            .unwrap();
        assert!(String::from_utf8(appl.1.clone())
            .unwrap()
            .starts_with("netwatch "));
        let (mut interfaces, mut packets) = (Vec::new(), Vec::new());
        for b in &blocks[1..] {
            match b.kind {
                IDB => {
                    assert_eq!(u16_at(&b.body, 2), 0, "IDB reserved field");
                    assert_eq!(u32_at(&b.body, 4), 65535, "snaplen");
                    let opts = options(&b.body, 8);
                    let get = |code| opts.iter().find(|(c, _)| *c == code).map(|o| &o.1);
                    let tsresol = get(IF_TSRESOL).expect("if_tsresol is explicit");
                    assert_eq!(tsresol.len(), 1);
                    interfaces.push(Interface {
                        link_type: u16_at(&b.body, 0),
                        name: get(IF_NAME).map(|v| String::from_utf8(v.clone()).unwrap()),
                        tsresol: tsresol[0],
                    });
                }
                EPB => {
                    let interface = u32_at(&b.body, 0);
                    assert!((interface as usize) < interfaces.len(), "IDB precedes use");
                    let ts = (u64::from(u32_at(&b.body, 4)) << 32) | u64::from(u32_at(&b.body, 8));
                    let caplen = u32_at(&b.body, 12) as usize;
                    let original_len = u32_at(&b.body, 16);
                    assert!(caplen as u32 <= original_len);
                    let end = 20 + caplen.div_ceil(4) * 4;
                    assert!(b.body[20 + caplen..end].iter().all(|b| *b == 0), "padding");
                    let opts = options(&b.body, end);
                    assert!(opts.iter().all(|(c, _)| *c == OPT_COMMENT));
                    let comment = opts.first().map(|(_, v)| {
                        serde_json::from_slice::<serde_json::Value>(v).expect("comment is JSON")
                    });
                    packets.push(Packet {
                        interface,
                        ts,
                        data: b.body[20..20 + caplen].to_vec(),
                        original_len,
                        comment,
                    });
                }
                other => panic!("unexpected block type {other:#x}"),
            }
        }
        (interfaces, packets)
    }

    #[test]
    fn link_types_resolve_by_name_then_shared_numbers() {
        assert_eq!(link_type_for(Some("EN10MB"), 1), Some(1));
        assert_eq!(link_type_for(Some("NULL"), 0), Some(0));
        // DLT_RAW is 12 on Linux and 14 on OpenBSD; both are LINKTYPE_RAW.
        assert_eq!(link_type_for(Some("RAW"), 12), Some(101));
        assert_eq!(link_type_for(Some("RAW"), 14), Some(101));
        // macOS numbers DLT_PKTAP 149; the file type is 258.
        assert_eq!(link_type_for(Some("PKTAP"), 149), Some(258));
        assert_eq!(link_type_for(Some("LINUX_SLL"), 113), Some(113));
        assert_eq!(link_type_for(Some("IEEE802"), 6), Some(6));
        // Unshared numbers below 104 with an unknown name have no file type.
        assert_eq!(link_type_for(Some("UNKNOWN"), 30), None);
        assert_eq!(link_type_for(None, 1), None);
        assert_eq!(link_type_for(Some("USER0"), -1), None);
    }

    #[test]
    fn capture_metadata_rejects_impossible_headers() {
        let ok = CaptureMetadata::from_parts(
            &"s".into(),
            &"i".into(),
            1,
            1_700_000_000,
            999_999,
            60,
            64,
        )
        .unwrap();
        assert_eq!(ok.timestamp_ns, 1_700_000_000_999_999_000);
        assert_eq!(ok.original_len, 64);
        for (seconds, micros, caplen, len) in [
            (1i64, 1_000_000i64, 60, 64), // a whole second of microseconds
            (-1, 0, 60, 64),              // before the epoch
            (1, -1, 60, 64),
            (1, 0, 64, 60), // more captured than was on the wire
            (i64::MAX, 0, 60, 64),
        ] {
            assert!(
                CaptureMetadata::from_parts(
                    &"s".into(),
                    &"i".into(),
                    1,
                    seconds,
                    micros,
                    caplen,
                    len
                )
                .is_none(),
                "{seconds} {micros} {caplen} {len}"
            );
        }
    }

    /// libpcap as an independent reader of both formats. Not on Windows,
    /// where CI has no Npcap and so no wpcap.dll to load.
    #[cfg(not(windows))]
    #[test]
    fn libpcap_reads_back_times_lengths_and_bytes() {
        for format in [Format::Pcap, Format::PcapNg] {
            let mut second = packet();
            second.capture.as_mut().unwrap().timestamp_ns += 2_000_000;
            let packets = vec![packet(), second];
            let file = path(format.extension());
            export_capture(&packets, &file, format, true, &AtomicBool::new(false)).unwrap();
            let mut reader = pcap::Capture::from_file(&file).unwrap();
            for expected in &packets {
                let got = reader.next_packet().unwrap();
                assert_eq!(got.data, &expected.raw_bytes);
                assert_eq!(got.header.len, 64);
                assert_eq!(got.header.caplen, 42);
                let ns = expected.capture.as_ref().unwrap().timestamp_ns;
                assert_eq!(got.header.ts.tv_sec as u64, ns / 1_000_000_000);
                assert_eq!(got.header.ts.tv_usec as u64, ns % 1_000_000_000 / 1000);
            }
            assert!(reader.next_packet().is_err());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            std::fs::remove_file(file).unwrap();
        }
    }

    #[test]
    fn classic_pcap_is_little_endian_microseconds() {
        let file = path("pcap");
        export_capture(
            &[packet()],
            &file,
            Format::Pcap,
            true,
            &AtomicBool::new(false),
        )
        .unwrap();
        let data = std::fs::read(&file).unwrap();
        std::fs::remove_file(file).unwrap();
        assert_eq!(&data[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!((u16_at(&data, 4), u16_at(&data, 6)), (2, 4));
        assert_eq!(u32_at(&data, 16), 65535);
        assert_eq!(u32_at(&data, 20), 1, "LINKTYPE_ETHERNET");
        assert_eq!(u32_at(&data, 24), 1_700_006_399);
        assert_eq!(u32_at(&data, 28), 999_123);
        assert_eq!((u32_at(&data, 32), u32_at(&data, 36)), (42, 64));
        assert_eq!(data.len(), 24 + 16 + 42);
    }

    /// Every frame size from 1 to 70 bytes, so each padding remainder and
    /// both comment and no-comment layouts are read back block by block.
    #[test]
    fn pcapng_blocks_are_well_formed_at_every_padding() {
        for comments in [false, true] {
            let packets: Vec<CapturedPacket> = (1..=70u32)
                .map(|n| {
                    let mut p = if n % 3 == 0 {
                        annotated(packet())
                    } else {
                        packet()
                    };
                    p.id = u64::from(n);
                    p.raw_bytes = (0..n).map(|b| b as u8 ^ 0xA5).collect();
                    let m = p.capture.as_mut().unwrap();
                    m.original_len = n + n % 7;
                    m.timestamp_ns += u64::from(n) * 1_000;
                    p
                })
                .collect();
            let file = path("pcapng");
            let summary = export_capture(
                &packets,
                &file,
                Format::PcapNg,
                comments,
                &AtomicBool::new(false),
            )
            .unwrap();
            let data = std::fs::read(&file).unwrap();
            std::fs::remove_file(file).unwrap();
            assert_eq!(summary.packets, 70);
            assert_eq!(summary.annotated, if comments { 23 } else { 0 });

            let (interfaces, read) = read_pcapng(&data);
            assert_eq!(interfaces.len(), 1);
            assert_eq!(interfaces[0].link_type, 1);
            assert_eq!(interfaces[0].name.as_deref(), Some("eth0"));
            assert_eq!(interfaces[0].tsresol, TSRESOL_MICROS);
            assert_eq!(read.len(), packets.len());
            for (got, want) in read.iter().zip(&packets) {
                let m = want.capture.as_ref().unwrap();
                assert_eq!(got.interface, 0);
                // if_tsresol 6: the 64-bit timestamp counts microseconds.
                assert_eq!(got.ts, m.timestamp_ns / 1000);
                assert_eq!(got.data, want.raw_bytes);
                assert_eq!(got.original_len, m.original_len);
                let Some(comment) = &got.comment else {
                    assert!(!comments);
                    continue;
                };
                assert!(comments);
                assert_eq!(comment["schema"], ANNOTATION_SCHEMA);
                assert_eq!(comment["packet_id"], want.id);
                assert_eq!(comment["capture_session"], "capture-a");
                assert_eq!(comment["protocol"], "UDP");
                if want.annotation.is_some() {
                    assert_eq!(comment["status"], "bracketed_socket_observation");
                    assert_eq!(comment["pid"], 42);
                    assert_eq!(comment["process_name"], "lookup");
                    assert_eq!(comment["start_token"], "123");
                    assert_eq!(comment["process_session"], "run");
                    assert!(comment["executable_identity"].is_null());
                    assert_eq!(comment["network_namespace"], "ns1");
                    assert_eq!(comment["source"], "procfs");
                    assert_eq!(comment["direction"], "outbound");
                    assert_eq!(comment["flow_generation"], 8);
                    assert_eq!(comment["capture_generation"], 4);
                    let (before, after) = (
                        comment["before_utc_ms"].as_u64().unwrap(),
                        comment["after_utc_ms"].as_u64().unwrap(),
                    );
                    assert!(before < m.timestamp_ns / 1_000_000);
                    assert!(after > m.timestamp_ns / 1_000_000);
                } else {
                    assert_eq!(comment["status"], "unknown_owner");
                    assert!(comment.get("pid").is_none());
                }
            }
        }
    }

    #[test]
    fn missing_metadata_and_mixed_framing_are_explicit() {
        let mut unknown = packet();
        unknown.capture = None;
        let mut raw = packet();
        raw.capture.as_mut().unwrap().link_type = 101;
        raw.capture.as_mut().unwrap().interface = "tun0".into();
        let mut restarted = packet();
        restarted.capture.as_mut().unwrap().session = "capture-b".into();
        let packets = vec![packet(), raw, unknown, restarted, packet()];
        assert!(!single_link_type(&packets));
        let file = path("pcapng");
        let result = export_capture(
            &packets,
            &file,
            Format::PcapNg,
            true,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!((result.packets, result.omitted), (4, 1));
        let (interfaces, read) = read_pcapng(&std::fs::read(&file).unwrap());
        std::fs::remove_file(file).unwrap();
        // eth0 per capture session, and tun0's raw IP framing.
        let kinds: Vec<_> = interfaces
            .iter()
            .map(|i| (i.link_type, i.name.clone().unwrap()))
            .collect();
        assert_eq!(
            kinds,
            [(1, "eth0".into()), (101, "tun0".into()), (1, "eth0".into())]
        );
        let ids: Vec<_> = read.iter().map(|p| p.interface).collect();
        assert_eq!(ids, [0, 1, 2, 0]);

        let file = path("pcap");
        assert!(export_capture(
            &packets,
            &file,
            Format::Pcap,
            false,
            &AtomicBool::new(false)
        )
        .unwrap_err()
        .contains("Mixed framing"));
        assert!(!file.exists());
    }

    #[test]
    fn an_entirely_synthetic_selection_is_refused() {
        let mut synthetic = packet();
        synthetic.capture = None;
        let file = path("pcapng");
        let error = export_capture(
            &[synthetic],
            &file,
            Format::PcapNg,
            true,
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert!(error.contains("No packets have exportable capture metadata"));
        assert!(!file.exists());
    }

    #[test]
    fn oversized_or_inconsistent_frames_are_omitted() {
        let mut empty = packet();
        empty.raw_bytes.clear();
        let mut longer_than_wire = packet();
        longer_than_wire.capture.as_mut().unwrap().original_len = 10;
        let mut over_snaplen = packet();
        over_snaplen.raw_bytes = vec![0; 65_536];
        over_snaplen.capture.as_mut().unwrap().original_len = 70_000;
        let summary = preview(&[packet(), empty, longer_than_wire, over_snaplen]);
        assert_eq!((summary.packets, summary.omitted), (1, 3));
    }

    #[test]
    fn timestamps_past_2106_need_pcapng() {
        let mut late = packet();
        late.capture.as_mut().unwrap().timestamp_ns = (u64::from(u32::MAX) + 1) * 1_000_000_000;
        let file = path("pcap");
        let error = export_capture(
            &[late.clone()],
            &file,
            Format::Pcap,
            false,
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert!(error.contains("requires PCAPNG"));
        assert!(!file.exists());
        let file = path("pcapng");
        export_capture(
            &[late],
            &file,
            Format::PcapNg,
            false,
            &AtomicBool::new(false),
        )
        .unwrap();
        let (_, read) = read_pcapng(&std::fs::read(&file).unwrap());
        std::fs::remove_file(file).unwrap();
        assert_eq!(read[0].ts, (u64::from(u32::MAX) + 1) * MICROS_PER_SECOND);
    }

    #[test]
    fn publication_never_clobbers_and_failure_cleans_up() {
        let dir = path("dir");
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("capture.pcapng");
        std::fs::write(&file, b"keep").unwrap();
        assert!(export_capture(
            &[packet()],
            &file,
            Format::PcapNg,
            true,
            &AtomicBool::new(false)
        )
        .is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"keep");
        let failed = dir.join("failed");
        assert!(atomic_write(&failed, |w| {
            w.write_all(b"partial")?;
            Err(io::Error::other("disk full"))
        })
        .is_err());
        assert!(!failed.exists());
        let cancelled_file = dir.join("cancelled");
        assert!(export_capture(
            &[packet()],
            &cancelled_file,
            Format::PcapNg,
            true,
            &AtomicBool::new(true)
        )
        .is_err());
        // Only the file that was there before: no temporary files left.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bracketed_observations_freeze_and_reject_unsafe_joins() {
        let mut p = packet();
        p.capture.as_mut().unwrap().timestamp_ns = 1_500_000_000;
        let a = conn(1000);
        let b = conn(2000);
        let mut history = AnnotationHistory::default();
        let mut packets = vec![p.clone()];
        history.observe(std::slice::from_ref(&a), &mut packets);
        assert!(packets[0].annotation.is_none());
        history.observe(std::slice::from_ref(&b), &mut packets);
        let annotation = packets[0].annotation.clone().unwrap();
        assert_eq!(annotation.process.pid, 42);
        assert_eq!(annotation.direction, Direction::Outbound);
        assert_eq!(
            (annotation.before_utc_ms, annotation.after_utc_ms),
            (1000, 2000)
        );
        history.observe(&[], &mut packets); // exit cannot rewrite frozen evidence
        assert!(packets[0].annotation.is_some());
        for case in 0..14 {
            let mut changed = b.clone();
            let mut before = a.clone();
            let mut h = AnnotationHistory::default();
            let mut ps = vec![p.clone()];
            match case {
                0 => changed.evidence.process.as_mut().unwrap().start_token = "reused".into(),
                1 => changed.evidence.flow.as_mut().unwrap().capture_generation = Some(5),
                2 => changed.evidence.flow.as_mut().unwrap().generation += 1,
                3 => {
                    changed.evidence.observed_at =
                        Some(Instant::now() - std::time::Duration::from_secs(6))
                }
                4 => changed.evidence.process = None,
                5 => changed.evidence.owner_checked_utc_ms = Some((1000, 1000)),
                6 => before.evidence.owner_checked_utc_ms = Some((1600, 1600)),
                7 => {
                    changed.evidence.process.as_mut().unwrap().network_namespace =
                        Some("different".into())
                }
                8 => {
                    changed.evidence.owner_checked_utc_ms =
                        Some((1000 + MAX_BRACKET_MS + 1, 1000 + MAX_BRACKET_MS + 1))
                }
                9 => {
                    changed.evidence.unknown_reason =
                        Some(crate::collectors::attribution::UnknownReason::IdentityUnavailable)
                }
                // The later check of the owner began before the packet, or
                // the earlier one ended after it, whenever the polls ran.
                10 => changed.evidence.owner_checked_utc_ms = Some((1400, 1600)),
                11 => before.evidence.owner_checked_utc_ms = Some((900, 1500)),
                // No time of check at all.
                12 => changed.evidence.owner_checked_utc_ms = None,
                _ => changed.evidence.flow.as_mut().unwrap().session = "other-run".into(),
            }
            h.observe(&[before], &mut ps);
            h.observe(&[changed], &mut ps);
            assert!(ps[0].annotation.is_none(), "case {case}");
        }
        // The packet in a boundary millisecond is not inside the bracket.
        for ms in [1000, 2000] {
            let mut edge = p.clone();
            edge.capture.as_mut().unwrap().timestamp_ns = ms * 1_000_000 + 500_000;
            let mut h = AnnotationHistory::default();
            let mut ps = vec![edge];
            h.observe(std::slice::from_ref(&a), &mut ps);
            h.observe(std::slice::from_ref(&b), &mut ps);
            assert!(ps[0].annotation.is_none(), "{ms}");
        }
        let mut restart = AnnotationHistory::default();
        let mut restarted = vec![p.clone()];
        restart.observe(std::slice::from_ref(&a), &mut restarted);
        restarted[0].capture.as_mut().unwrap().session = "new-capture".into();
        restart.observe(std::slice::from_ref(&b), &mut restarted);
        assert!(restarted[0].annotation.is_none());
        // Two rows for one flow (both ends of a loopback socket) is no owner.
        let mut h = AnnotationHistory::default();
        let mut ps = vec![p];
        h.observe(&[a.clone(), a], &mut ps);
        h.observe(&[b.clone(), b], &mut ps);
        assert!(ps[0].annotation.is_none());
    }

    /// On Linux a sandboxed poll takes owners from the broker's latest
    /// `/proc` scan, so when the poll ran says nothing about when the owner
    /// was seen, and consecutive polls can carry the same scan.
    #[test]
    fn the_bracket_is_when_the_owner_was_checked_not_when_polled() {
        let mut p = packet();
        p.capture.as_mut().unwrap().timestamp_ns = 1_500_000_000;
        let scanned = |from, until, poll| {
            let mut c = conn(poll);
            c.evidence.owner_checked_utc_ms = Some((from, until));
            c
        };
        let mut h = AnnotationHistory::default();
        let mut ps = vec![p];
        // Polls either side of the packet, both carrying one scan from
        // before it: the owner was seen once, before the packet.
        h.observe(&[scanned(900, 950, 1000)], &mut ps);
        h.observe(&[scanned(900, 950, 2000)], &mut ps);
        assert!(ps[0].annotation.is_none());
        // The next poll carries a scan begun after the packet.
        h.observe(&[scanned(1600, 1700, 2200)], &mut ps);
        let annotation = ps[0].annotation.as_ref().unwrap();
        assert_eq!(
            (annotation.before_utc_ms, annotation.after_utc_ms),
            (950, 1600)
        );
    }

    #[test]
    fn a_reply_is_inbound() {
        let mut reply = packet();
        reply.src_ip = "192.0.2.1".into();
        reply.src_port = Some(53);
        reply.dst_ip = "127.0.0.1".into();
        reply.dst_port = Some(1234);
        let reply = annotated(reply);
        assert_eq!(reply.annotation.unwrap().direction, Direction::Inbound);
    }

    /// An IPv6 packet as capture decodes it takes its owner from the row `ss`
    /// prints for its socket. The two spelled IPv6 differently, so no IPv6
    /// packet was ever annotated.
    #[test]
    fn an_ipv6_packet_is_annotated_from_its_row() {
        let (client, server) = (
            "[2001:db8::10]:50022".parse().unwrap(),
            "[2001:db8::20]:22".parse().unwrap(),
        );
        let frame = super::super::tests::tcp_frame(
            client,
            server,
            super::super::TCP_FLAG_SYN,
            (1000, 0),
            b"",
        );
        let mut p = super::super::Replay::new().frame(&frame).unwrap();
        p.capture = packet().capture;
        p.capture.as_mut().unwrap().timestamp_ns = 1_500_000_000;
        let row = |ms| {
            let mut c = conn(ms);
            c.protocol = "TCP".into();
            c.local_addr = "[2001:db8::10]:50022".into();
            c.remote_addr = "[2001:db8::20]:22".into();
            c.evidence.flow.as_mut().unwrap().capture_generation = p.stream_index;
            c
        };
        let mut history = AnnotationHistory::default();
        let mut packets = vec![p.clone()];
        history.observe(&[row(1000)], &mut packets);
        history.observe(&[row(2000)], &mut packets);
        let annotation = packets[0].annotation.as_ref().expect("annotated");
        assert_eq!(annotation.process.pid, 42);
        assert_eq!(annotation.direction, Direction::Outbound);
    }

    #[test]
    fn comments_are_optional_bounded_and_exclude_plaintext() {
        let mut p = packet();
        p.decrypted_plaintext = Some(b"secret-session-material".to_vec());
        p.info = "secret-session-material".into();
        p.protocol = "X\n\0".repeat(10000);
        for comments in [false, true] {
            let file = path("pcapng");
            export_capture(
                &[p.clone()],
                &file,
                Format::PcapNg,
                comments,
                &AtomicBool::new(false),
            )
            .unwrap();
            let bytes = std::fs::read(&file).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("secret-session-material"));
            assert_eq!(text.contains("unknown_owner"), comments);
            assert!(bytes.len() < 2000);
            std::fs::remove_file(file).unwrap();
        }
    }

    /// Process names, SNIs and interface names are chosen by other programs
    /// and peers. Whatever they hold, the comment stays valid JSON within the
    /// length bound, with nothing that can reorder text or drive a terminal.
    fn unsafe_or_invisible(c: char) -> bool {
        crate::ui::sanitize::is_unsafe(c) || invisible(c)
    }

    /// Characters a terminal draws harmlessly but a comment reader hides, or
    /// breaks the line at, are marked like the rest.
    #[test]
    fn invisible_text_is_marked() {
        assert_eq!(
            clean("login.bank.example\u{E0065}\u{E0076}"),
            "login.bank.example··"
        );
        assert_eq!(
            clean("a\u{2028}b\u{2029}c\u{AD}d\u{2062}e\u{FFF9}f\u{180E}"),
            "a·b·c·d·e·f·"
        );
        assert_eq!(clean("ünïcödé.example"), "ünïcödé.example");
    }

    #[test]
    fn hostile_text_is_escaped_and_bounded() {
        let hostile =
            "\u{1b}]52;c;AAAA\u{7}\"},\\\u{202e}evil\u{200b}\n\u{2028}\u{ad}\u{e0065}".repeat(500);
        let mut p = annotated(packet());
        p.capture.as_mut().unwrap().interface = hostile.as_str().into();
        p.annotation.as_mut().unwrap().process_name = Some(hostile.clone());
        p.annotation.as_mut().unwrap().process.executable = Some(hostile.clone());
        p.app_protocol = Some(crate::dpi::AppProtocol::Tls {
            sni: Some(hostile.clone()),
            alpn: Some(hostile.clone()),
            ech: true,
            ja4: Some(hostile),
        });
        let file = path("pcapng");
        export_capture(&[p], &file, Format::PcapNg, true, &AtomicBool::new(false)).unwrap();
        let (interfaces, read) = read_pcapng(&std::fs::read(&file).unwrap());
        std::fs::remove_file(file).unwrap();
        let name = interfaces[0].name.clone().unwrap();
        assert_eq!(name.chars().count(), MAX_TEXT_CHARS);
        let comment = read[0].comment.as_ref().unwrap();
        for key in ["process_name", "executable_identity", "sni", "alpn", "ja4"] {
            let value = comment[key].as_str().unwrap();
            assert_eq!(value.chars().count(), MAX_TEXT_CHARS, "{key}");
            assert!(!value.chars().any(unsafe_or_invisible), "{key}");
        }
        assert!(!name.chars().any(unsafe_or_invisible));
        assert_eq!(comment["app"], "tls");
        assert_eq!(comment["ech_outer"], true);
    }

    #[test]
    fn dpi_fields_name_the_classifier_without_credentials() {
        let mut snmp = packet();
        snmp.app_protocol = Some(crate::dpi::AppProtocol::Snmp {
            version: "2c".into(),
            community: Some("private-community".into()),
        });
        let mut quic = packet();
        quic.app_protocol = Some(crate::dpi::AppProtocol::Quic {
            sni: Some("example.com".into()),
            ech: false,
            ja4: Some("q13d0310h3_55b375c5d22e_cd85d2d88918".into()),
        });
        let mut http = packet();
        http.app_protocol = Some(crate::dpi::AppProtocol::Http {
            method: "GET".into(),
            host: Some("example.com".into()),
            path: Some("/private/path".into()),
            status: None,
        });
        let file = path("pcapng");
        export_capture(
            &[snmp, quic, http],
            &file,
            Format::PcapNg,
            true,
            &AtomicBool::new(false),
        )
        .unwrap();
        let bytes = std::fs::read(&file).unwrap();
        std::fs::remove_file(file).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("private-community"));
        assert!(!text.contains("/private/path"));
        let (_, read) = read_pcapng(&bytes);
        let comment = |i: usize| read[i].comment.clone().unwrap();
        assert_eq!(comment(0)["app"], "snmp");
        assert_eq!(comment(1)["app"], "quic");
        assert_eq!(comment(1)["sni"], "example.com");
        assert_eq!(comment(1)["ech_outer"], false);
        assert_eq!(comment(1)["ja4"], "q13d0310h3_55b375c5d22e_cd85d2d88918");
        assert!(comment(1).get("alpn").is_none());
        assert_eq!(comment(2)["app"], "http");
        assert!(comment(2).get("sni").is_none());
    }

    #[test]
    fn an_option_longer_than_its_length_field_is_an_error() {
        let mut options = Options::default();
        assert!(options.add(OPT_COMMENT, &vec![b'x'; 65_536]).is_err());
        assert!(options.add(OPT_COMMENT, &vec![b'x'; 65_535]).is_ok());
    }

    /// Writes the files `scripts/verify-capture-export.py` checks with
    /// Wireshark's own reader, which CI does not install:
    ///
    /// ```sh
    /// NETWATCH_EXPORT_FIXTURE_DIR=/tmp/nw-export cargo test --lib write_interop_fixture -- --ignored
    /// python3 scripts/verify-capture-export.py /tmp/nw-export
    /// ```
    #[test]
    #[ignore = "writes fixtures for an independent reader; set NETWATCH_EXPORT_FIXTURE_DIR"]
    fn write_interop_fixture() {
        let dir = std::path::PathBuf::from(std::env::var("NETWATCH_EXPORT_FIXTURE_DIR").unwrap());
        std::fs::create_dir_all(&dir).unwrap();
        let mut p = packet();
        // Ethernet + IPv4 + UDP, 42 bytes captured of 64 on the wire.
        p.raw_bytes = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0, 0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0,
            127, 0, 0, 1, 192, 0, 2, 1, 4, 210, 0, 53, 0, 8, 0, 0,
        ];
        p.app_protocol = Some(crate::dpi::AppProtocol::Quic {
            sni: Some("example.com".into()),
            ech: false,
            ja4: None,
        });
        let p = annotated(p);
        let never = AtomicBool::new(false);
        for f in [Format::Pcap, Format::PcapNg] {
            let file = dir.join(format!("single.{}", f.extension()));
            let _ = std::fs::remove_file(&file);
            export_capture(std::slice::from_ref(&p), &file, f, true, &never).unwrap();
        }
        // A raw-IP tunnel packet 2 ms later, after midnight UTC.
        let mut raw = packet();
        raw.id = 2;
        raw.capture.as_mut().unwrap().interface = "tun0".into();
        raw.capture.as_mut().unwrap().link_type = 101;
        raw.capture.as_mut().unwrap().original_len = 28;
        raw.capture.as_mut().unwrap().timestamp_ns += 2_000_000;
        raw.raw_bytes = p.raw_bytes[14..].to_vec();
        let file = dir.join("mixed.pcapng");
        let _ = std::fs::remove_file(&file);
        export_capture(&[p.clone(), raw], &file, Format::PcapNg, true, &never).unwrap();
        let hostile = "\u{1b}]52;c;AAAA\u{7}\"},\\\u{202e}evil\n\u{2028}\u{e0065}".repeat(50);
        let mut h = p;
        h.capture.as_mut().unwrap().interface = hostile.as_str().into();
        h.annotation.as_mut().unwrap().process_name = Some(hostile.clone());
        h.app_protocol = Some(crate::dpi::AppProtocol::Tls {
            sni: Some(hostile.clone()),
            alpn: Some(hostile),
            ech: true,
            ja4: None,
        });
        let file = dir.join("hostile.pcapng");
        let _ = std::fs::remove_file(&file);
        export_capture(&[h], &file, Format::PcapNg, true, &never).unwrap();
    }

    #[test]
    fn empty_capture_is_a_valid_file() {
        for format in [Format::Pcap, Format::PcapNg] {
            let file = path(format.extension());
            let summary =
                export_capture::<CapturedPacket>(&[], &file, format, true, &AtomicBool::new(false))
                    .unwrap();
            assert_eq!(summary, ExportSummary::default());
            let data = std::fs::read(&file).unwrap();
            // libpcap opens it: a PCAPNG section needs an interface for that.
            #[cfg(not(windows))]
            assert!(pcap::Capture::from_file(&file)
                .unwrap()
                .next_packet()
                .is_err());
            std::fs::remove_file(file).unwrap();
            match format {
                Format::Pcap => assert_eq!(data.len(), 24),
                Format::PcapNg => {
                    let (interfaces, packets) = read_pcapng(&data);
                    assert!(packets.is_empty());
                    assert_eq!(interfaces.len(), 1);
                    let i = &interfaces[0];
                    assert_eq!((i.link_type, i.name.as_deref(), i.tsresol), (1, None, 6));
                }
            }
        }
    }
}
