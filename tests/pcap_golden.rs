//! Replays the captures in `tests/fixtures/pcap/` through the capture
//! thread's decode path and compares what it reports with the `.golden`
//! file beside each one. A change to any dissector or DPI classifier that
//! alters what the Packets tab shows for these frames fails here.
//!
//! The captures come from `tests/fixtures/pcap/generate.py`. After an
//! intended change, rewrite the golden files with
//! `NETWATCH_BLESS=1 cargo test --test pcap_golden` and review the diff.
use std::{fmt::Write as _, fs, path::Path};

use netwatch::collectors::packets::{
    export::{export_capture, CaptureMetadata, Format},
    CapturedPacket, Replay,
};

/// One frame of a saved capture with the times and lengths its header gave.
#[derive(Debug, PartialEq)]
struct Record<'a> {
    micros: u64,
    original_len: u32,
    data: &'a [u8],
}

/// Frames from a classic little-endian, microsecond pcap file. The fixtures
/// are written in that one format, so this need not read any other, and
/// the test does not depend on libpcap or Npcap being installed.
fn frames(pcap: &[u8]) -> Vec<&[u8]> {
    records(pcap).into_iter().map(|r| r.data).collect()
}

fn records(pcap: &[u8]) -> Vec<Record<'_>> {
    assert!(pcap.len() >= 24, "pcap global header is truncated");
    assert_eq!(
        &pcap[..4],
        &[0xd4, 0xc3, 0xb2, 0xa1],
        "not a LE microsecond pcap"
    );
    let linktype = u32::from_le_bytes(pcap[20..24].try_into().unwrap());
    assert_eq!(linktype, 1, "fixtures are Ethernet captures");
    let field = |at: usize| u32::from_le_bytes(pcap[at..at + 4].try_into().unwrap());
    let mut out = Vec::new();
    let mut at = 24;
    while at < pcap.len() {
        let caplen = field(at + 8) as usize;
        out.push(Record {
            micros: u64::from(field(at)) * 1_000_000 + u64::from(field(at + 4)),
            original_len: field(at + 12),
            data: &pcap[at + 16..at + 16 + caplen],
        });
        at += 16 + caplen;
    }
    out
}

/// The Enhanced Packet Blocks of a little-endian PCAPNG file whose
/// interfaces all use microsecond timestamps, as netwatch writes them.
fn pcapng_records(file: &[u8]) -> Vec<Record<'_>> {
    let field = |at: usize| u32::from_le_bytes(file[at..at + 4].try_into().unwrap());
    assert_eq!(field(0), 0x0A0D_0D0A, "starts with a section header");
    assert_eq!(field(8), 0x1A2B_3C4D, "little-endian section");
    let mut out = Vec::new();
    let mut at = 0;
    while at < file.len() {
        let (kind, len) = (field(at), field(at + 4) as usize);
        assert_eq!(field(at + len - 4) as usize, len, "trailing block length");
        if kind == 6 {
            let caplen = field(at + 20) as usize;
            out.push(Record {
                micros: (u64::from(field(at + 12)) << 32) | u64::from(field(at + 16)),
                original_len: field(at + 24),
                data: &file[at + 28..at + 28 + caplen],
            });
        }
        at += len;
    }
    out
}

/// Everything the Packets tab shows for a frame except the wall-clock
/// timestamp and the hex/ASCII dump, which repeats the frame bytes.
fn describe(out: &mut String, n: usize, p: &CapturedPacket) {
    // As the Packets tab writes an endpoint: IPv6 in brackets, so the port
    // is not read as one more group of a compressed address.
    let end = |ip: &str, port: Option<u16>| match port {
        Some(port) if ip.contains(':') => format!("[{ip}]:{port}"),
        Some(port) => format!("{ip}:{port}"),
        None => ip.to_string(),
    };
    writeln!(
        out,
        "#{n} {} {} -> {} len={} expert={:?}",
        p.protocol,
        end(&p.src_ip, p.src_port),
        end(&p.dst_ip, p.dst_port),
        p.length,
        p.expert,
    )
    .unwrap();
    writeln!(out, "  info: {}", p.info).unwrap();
    if let Some(stream) = p.stream_index {
        writeln!(out, "  stream: {stream}").unwrap();
    }
    if let Some(app) = &p.app_protocol {
        writeln!(out, "  app: {app:?}").unwrap();
    }
    for line in &p.details {
        writeln!(out, "  | {line}").unwrap();
    }
}

fn replay(pcap: &Path) -> String {
    let bytes = fs::read(pcap).unwrap();
    let replay = Replay::new();
    let mut out = String::new();
    for (i, frame) in frames(&bytes).into_iter().enumerate() {
        match replay.frame(frame) {
            Some(p) => describe(&mut out, i + 1, &p),
            None => writeln!(out, "#{} (not decoded)", i + 1).unwrap(),
        }
    }
    out
}

#[test]
fn pcap_fixtures_match_golden() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pcap");
    let bless = std::env::var_os("NETWATCH_BLESS").is_some();
    let mut pcaps: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "pcap"))
        .collect();
    pcaps.sort();
    assert!(!pcaps.is_empty(), "no fixtures in {}", dir.display());

    let mut stale = Vec::new();
    for pcap in &pcaps {
        let actual = replay(pcap);
        let golden = pcap.with_extension("golden");
        if bless {
            fs::write(&golden, &actual).unwrap();
            continue;
        }
        let expected = fs::read_to_string(&golden)
            .unwrap_or_else(|_| {
                panic!("{} is missing; run with NETWATCH_BLESS=1", golden.display())
            })
            .replace("\r\n", "\n");
        if actual != expected {
            eprintln!("--- {}\n{actual}", golden.display());
            stale.push(golden.file_name().unwrap().to_string_lossy().into_owned());
        }
    }
    assert!(
        stale.is_empty(),
        "decode output changed for {stale:?} (actual output above); \
         if intended, rerun with NETWATCH_BLESS=1 and review the diff"
    );
}

/// netwatch's own exports, read back by the reader above and replayed, give
/// the decode the fixtures gave: the writer keeps every byte, time and
/// length of what it was given, in both formats.
#[test]
fn exports_replay_like_the_capture_they_came_from() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pcap");
    let out = std::env::temp_dir().join(format!("netwatch-golden-export-{}", std::process::id()));
    let _ = fs::remove_dir_all(&out);
    fs::create_dir_all(&out).unwrap();
    let mut fixtures: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "pcap"))
        .collect();
    fixtures.sort();
    assert!(!fixtures.is_empty());
    for fixture in &fixtures {
        let name = fixture.file_stem().unwrap().to_string_lossy();
        let bytes = fs::read(fixture).unwrap();
        let input = records(&bytes);
        let replay = Replay::new();
        let mut decoded = Vec::new();
        let mut packets = Vec::new();
        for record in &input {
            let Some(mut p) = replay.frame(record.data) else {
                continue;
            };
            p.capture = Some(CaptureMetadata {
                session: "golden".into(),
                interface: "fixture0".into(),
                link_type: 1,
                timestamp_ns: record.micros * 1000,
                original_len: record.original_len,
            });
            decoded.push(record);
            packets.push(p);
        }
        assert!(!packets.is_empty(), "{name}");
        let expected = describe_all(decoded.iter().map(|r| r.data));
        for format in [Format::Pcap, Format::PcapNg] {
            let file = out.join(format!("{name}.{}", format.extension()));
            let never = std::sync::atomic::AtomicBool::new(false);
            let summary = export_capture(&packets, &file, format, true, &never).unwrap();
            assert_eq!(summary.packets, packets.len(), "{name}");
            let written = fs::read(&file).unwrap();
            let back = match format {
                Format::Pcap => records(&written),
                Format::PcapNg => pcapng_records(&written),
            };
            assert_eq!(back.len(), decoded.len(), "{name} {format:?}");
            for (got, want) in back.iter().zip(&decoded) {
                assert_eq!(got, *want, "{name} {format:?}");
            }
            assert_eq!(
                describe_all(back.iter().map(|r| r.data)),
                expected,
                "{name} {format:?}"
            );
        }
    }
    let _ = fs::remove_dir_all(&out);
}

fn describe_all<'a>(frames: impl Iterator<Item = &'a [u8]>) -> String {
    let replay = Replay::new();
    let mut out = String::new();
    for (i, frame) in frames.enumerate() {
        describe(&mut out, i + 1, &replay.frame(frame).unwrap());
    }
    out
}
