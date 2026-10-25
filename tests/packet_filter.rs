//! The Packets tab's text filter runs over every packet in the ring on every
//! frame, under the ring's read lock. It used to lowercase a copy of each
//! packet's payload, info and addresses to search them, 8 to 21 ms a frame on
//! a full ring. This checks that it now finds the same packets without
//! allocating, on the frames in `tests/fixtures/pcap/`.
//!
//! A test binary of its own, because counting allocations needs a global
//! allocator, and the library's unit tests should not run on a counting one.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fs;

use netwatch::collectors::packets::{
    matches_packet, parse_filter, CapturedPacket, FilterExpr, Replay,
};

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

/// The system allocator, counting what each thread allocates.
struct Counting;

// SAFETY: every call goes straight to `System` with the caller's arguments,
// so `System` upholds the `GlobalAlloc` contract. The counter is a
// const-initialised thread local without a destructor, so touching it
// allocates nothing and is sound at any point in a thread's life.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        // SAFETY: the caller's guarantees for `alloc` are passed on as they are.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `System` through `alloc` above, with `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocations() -> usize {
    ALLOCATIONS.with(Cell::get)
}

/// The frames of a classic little-endian, microsecond pcap file, as the
/// fixtures are written.
fn frames(pcap: &[u8]) -> Vec<&[u8]> {
    let field = |at: usize| u32::from_le_bytes(pcap[at..at + 4].try_into().unwrap()) as usize;
    let mut out = Vec::new();
    let mut at = 24;
    while at < pcap.len() {
        let caplen = field(at + 8);
        out.push(&pcap[at + 16..at + 16 + caplen]);
        at += 16 + caplen;
    }
    out
}

fn fixture_packets() -> Vec<CapturedPacket> {
    let mut packets = Vec::new();
    for name in ["dns", "http", "misc", "quic", "ssh", "tls"] {
        let pcap = fs::read(format!("tests/fixtures/pcap/{name}.pcap")).unwrap();
        let replay = Replay::new();
        packets.extend(frames(&pcap).into_iter().filter_map(|f| replay.frame(f)));
    }
    packets
}

/// The text search as it was: every field lowercased into a new string.
fn old_contains(p: &CapturedPacket, s: &str) -> bool {
    p.info.to_lowercase().contains(s)
        || p.src_ip.to_lowercase().contains(s)
        || p.dst_ip.to_lowercase().contains(s)
        || p.protocol.to_lowercase().contains(s)
        || p.payload_text.to_lowercase().contains(s)
        || p.src_host
            .as_ref()
            .is_some_and(|h| h.to_lowercase().contains(s))
        || p.dst_host
            .as_ref()
            .is_some_and(|h| h.to_lowercase().contains(s))
        || p.decrypted_plaintext
            .as_ref()
            .is_some_and(|pt| String::from_utf8_lossy(pt).to_lowercase().contains(s))
}

#[test]
fn bare_word_filter_matches_without_allocating() {
    let mut packets = fixture_packets();
    assert!(packets.len() >= 20, "{} fixture packets", packets.len());
    // Text whose lowercase is not its ASCII lowercase: É and Σ lowercase
    // outside ASCII, and the Kelvin sign and dotted İ into it.
    let mut odd = packets[0].clone();
    odd.payload_text = "ÉCOLE ΟΔΟΣ \u{212a}ELVIN İSTANBUL · → …".into();
    odd.src_host = Some("Bücher.EXAMPLE".into());
    odd.decrypted_plaintext = Some(b"GET /Index.HTML \xff\xfe".to_vec());
    packets.push(odd);

    let words = [
        "zzz",
        "example",
        "EXAMPLE",
        "Example.COM",
        "get",
        "http/1.1",
        "198.51",
        "2001:db8",
        "→",
        "·",
        "école",
        "ΟΔΟΣ",
        "kelvin",
        "istanbul",
        "i",
        "bücher",
        "index.html",
        "",
    ];
    for word in words {
        // Quoted, a word is a text search even when it reads as an address
        // or a protocol name.
        let expr = parse_filter(&format!("\"{word}\"")).unwrap();
        let needle = word.to_lowercase();
        assert!(
            matches!(&expr, FilterExpr::Contains(s) if *s == needle),
            "{expr:?}"
        );
        for (i, p) in packets.iter().enumerate() {
            assert_eq!(
                matches_packet(&expr, p),
                old_contains(p, &needle),
                "{word:?} on packet {i}: {} / {}",
                p.info,
                p.payload_text
            );
        }

        // An ASCII word searched across the fixtures, whose text has `→` and
        // `·` but nothing that lowercases into ASCII, allocates nothing.
        if word.is_ascii() {
            let fixtures = &packets[..packets.len() - 1];
            let before = allocations();
            for p in fixtures {
                std::hint::black_box(matches_packet(&expr, p));
            }
            assert_eq!(allocations(), before, "{word:?} allocated");
        }
    }
    // The words above find something, or they test nothing.
    let expr = parse_filter("example").unwrap();
    assert!(packets.iter().any(|p| matches_packet(&expr, p)));
}
