//! Replays the captures in `tests/fixtures/pcap/` through the capture
//! thread's decode path and compares what it reports with the `.golden`
//! file beside each one. A change to any dissector or DPI classifier that
//! alters what the Packets tab shows for these frames fails here.
//!
//! The captures come from `tests/fixtures/pcap/generate.py`. After an
//! intended change, rewrite the golden files with
//! `NETWATCH_BLESS=1 cargo test --test pcap_golden` and review the diff.
use std::{fmt::Write as _, fs, path::Path};

use netwatch::collectors::packets::{CapturedPacket, Replay};

/// Frames from a classic little-endian, microsecond pcap file. The fixtures
/// are written in that one format, so this need not read any other, and
/// the test does not depend on libpcap or Npcap being installed.
fn frames(pcap: &[u8]) -> Vec<&[u8]> {
    assert!(pcap.len() >= 24, "pcap global header is truncated");
    assert_eq!(
        &pcap[..4],
        &[0xd4, 0xc3, 0xb2, 0xa1],
        "not a LE microsecond pcap"
    );
    let linktype = u32::from_le_bytes(pcap[20..24].try_into().unwrap());
    assert_eq!(linktype, 1, "fixtures are Ethernet captures");
    let mut out = Vec::new();
    let mut at = 24;
    while at < pcap.len() {
        let header = &pcap[at..at + 16];
        let caplen = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
        at += 16;
        out.push(&pcap[at..at + caplen]);
        at += caplen;
    }
    out
}

/// Everything the Packets tab shows for a frame except the wall-clock
/// timestamp and the hex/ASCII dump, which repeats the frame bytes.
fn describe(out: &mut String, n: usize, p: &CapturedPacket) {
    let port = |p: Option<u16>| p.map(|p| format!(":{p}")).unwrap_or_default();
    writeln!(
        out,
        "#{n} {} {}{} -> {}{} len={} expert={:?}",
        p.protocol,
        p.src_ip,
        port(p.src_port),
        p.dst_ip,
        port(p.dst_port),
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
