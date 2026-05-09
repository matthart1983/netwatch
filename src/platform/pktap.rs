// macOS PKTAP-based per-packet process attribution.
//
// PKTAP is a libpcap-accessible pseudo-device exposed by xnu that delivers
// every captured frame prefixed with a `pktap_header` containing the PID and
// command name of the process that owned the socket. Capturing on the "pktap"
// device gives us kernel-grade attribution that lsof polling can't match —
// short-lived flows (sub-2-second), connections that close before the next
// poll cycle, and threaded processes whose `comm` differs from the parent.
//
// On modern macOS, opening "pktap" via libpcap returns DLT_RAW by default;
// the per-packet metadata is gated behind an Apple-specific libpcap call that
// must be invoked between `pcap_create` and `pcap_activate`. The exported
// symbol changed across macOS versions: older releases shipped
// `pcap_set_want_pktap_pktmetadata`, while macOS 15+ exports the shorter
// `pcap_set_want_pktap` (a separate `pcap_set_pktap_hdr_v2` opts in to the
// v2 header layout, which we don't need — our parser keys off pth_length so
// either header generation works). The Rust `pcap` crate doesn't expose
// either symbol, so we drive libpcap via raw FFI here. We resolve the
// Apple-only symbols with `dlsym`, preferring whichever exists, so older
// macOS keeps working and non-Apple libpcap builds (e.g. Homebrew) fail
// gracefully at runtime instead of failing to link.
//
// Header layout reference: xnu/bsd/net/pktap.h plus the Wireshark
// packet-pktap.c dissector. The kernel writes `pth_length` at offset 0 so
// future header growth is forwards-compatible — we read up to the documented
// fields and skip past pth_length bytes to reach the inner frame.

use crate::collectors::packets::{StreamKey, StreamProtocol};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Linktype reported by libpcap on macOS for live PKTAP capture.
const DLT_PKTAP: i32 = 149;
/// Linktype value used in pcap savefile format (LINKTYPE_PKTAP).
const LINKTYPE_PKTAP: i32 = 258;

const DLT_EN10MB: u32 = 1;
const DLT_NULL: u32 = 0;
const DLT_RAW: u32 = 12;

const PKTAP_FLAG_DIR_IN: u32 = 0x1;
const PKTAP_FLAG_DIR_OUT: u32 = 0x2;

/// Lifetime of a cache entry after we last saw a packet for it. Long enough to
/// span a few lsof poll cycles, short enough that closed connections age out.
const ATTRIBUTION_TTL: Duration = Duration::from_secs(60);

/// Snaplen large enough to capture pktap_header (~156) + ethernet (14) +
/// IPv4 (20) + TCP (60 with options) plus slack. We never read past the
/// transport ports, so a tight snaplen keeps kernel→userspace copies cheap.
const PKTAP_SNAPLEN: i32 = 320;

/// Short timeout so the thread can react to the stop signal promptly.
const PKTAP_TIMEOUT_MS: i32 = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Attribution {
    pub pid: u32,
    pub comm: String,
    pub direction: Direction,
    pub seen_at: Instant,
}

/// Shared cache of `StreamKey → Attribution`. Populated by the background
/// PKTAP thread, consulted by the connection collector.
#[derive(Default)]
pub struct PktapAttributor {
    cache: Mutex<HashMap<StreamKey, Attribution>>,
}

impl PktapAttributor {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn lookup(&self, key: &StreamKey) -> Option<Attribution> {
        let cache = self.cache.lock().ok()?;
        cache.get(key).cloned()
    }

    pub fn record(&self, key: StreamKey, attr: Attribution) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(key, attr);
        }
    }

    pub fn evict_stale(&self, ttl: Duration) {
        if let Ok(mut cache) = self.cache.lock() {
            let now = Instant::now();
            cache.retain(|_, attr| now.duration_since(attr.seen_at) < ttl);
        }
    }

    pub fn len(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot the entire cache. Intended for diagnostics (the `pktap_probe`
    /// example) — production callers should use `lookup` against a single key.
    pub fn snapshot(&self) -> Vec<(StreamKey, Attribution)> {
        self.cache
            .lock()
            .map(|c| c.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    }
}

/// Handle returned by `spawn`. Drop or call `stop()` to terminate the thread.
pub struct PktapHandle {
    pub attributor: Arc<PktapAttributor>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    /// Non-fatal startup error message (e.g. "permission denied"), surfaced
    /// to the UI so we can show users why attribution upgraded or didn't.
    pub startup_error: Arc<Mutex<Option<String>>>,
}

impl PktapHandle {
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }

    pub fn startup_error(&self) -> Option<String> {
        self.startup_error.lock().ok().and_then(|e| e.clone())
    }
}

impl Drop for PktapHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawn the PKTAP capture thread. Returns immediately; capture runs in the
/// background and the cache is populated incrementally. If the kernel refuses
/// to open the pktap device (no root, kernel feature missing), the thread
/// records the error in `startup_error` and exits cleanly — callers can keep
/// using the attributor and lookups will simply return None.
pub fn spawn() -> PktapHandle {
    let attributor = PktapAttributor::new();
    let stop = Arc::new(AtomicBool::new(false));
    let startup_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    let thread_attr = Arc::clone(&attributor);
    let thread_stop = Arc::clone(&stop);
    let thread_err = Arc::clone(&startup_error);

    let join = thread::Builder::new()
        .name("pktap-attributor".into())
        .spawn(move || run(thread_attr, thread_stop, thread_err))
        .ok();

    PktapHandle {
        attributor,
        stop,
        join,
        startup_error,
    }
}

fn set_error(slot: &Arc<Mutex<Option<String>>>, msg: String) {
    if let Ok(mut s) = slot.lock() {
        *s = Some(msg);
    }
}

fn pcap_geterr_string(p: *mut ffi::pcap_t) -> String {
    unsafe { CStr::from_ptr(ffi::pcap_geterr(p)) }
        .to_string_lossy()
        .into_owned()
}

/// Resolve and call Apple's per-packet metadata flag. Probes both the
/// legacy (`pcap_set_want_pktap_pktmetadata`) and current
/// (`pcap_set_want_pktap`) symbol names so the same build works across
/// pre- and post-macOS-15 libpcap. Returns Err if neither symbol is present
/// (non-Apple libpcap, or a stripped-down build) or the call itself fails.
fn enable_pktap_metadata(p: *mut ffi::pcap_t) -> Result<(), String> {
    // Both Apple symbols share the signature `int (*)(pcap_t*, int)`.
    type SetFlagFn = unsafe extern "C" fn(*mut ffi::pcap_t, c_int) -> c_int;

    // Legacy symbol first — present on macOS 14 and earlier. macOS 15
    // dropped it in favor of the shorter name.
    const CANDIDATES: &[&[u8]] = &[
        b"pcap_set_want_pktap_pktmetadata\0",
        b"pcap_set_want_pktap\0",
    ];

    let mut resolved: Option<(&[u8], SetFlagFn)> = None;
    for symbol in CANDIDATES {
        // SAFETY: dlsym with a NUL-terminated symbol name is safe; null
        // return means "not found", handled by the loop.
        let raw = unsafe { nix::libc::dlsym(nix::libc::RTLD_DEFAULT, symbol.as_ptr() as *const _) };
        if !raw.is_null() {
            // SAFETY: Apple's ABI for both symbols is documented as
            // `int func(pcap_t*, int)`.
            let func: SetFlagFn = unsafe { std::mem::transmute(raw) };
            resolved = Some((symbol, func));
            break;
        }
    }

    let (symbol, func) = match resolved {
        Some(r) => r,
        None => {
            return Err(
                "neither pcap_set_want_pktap_pktmetadata nor pcap_set_want_pktap \
                 was found — Apple's libpcap is required for kernel-level \
                 attribution (Homebrew's libpcap does not export these)"
                    .to_string(),
            );
        }
    };

    let rc = unsafe { func(p, 1) };
    if rc != 0 {
        let name = std::str::from_utf8(&symbol[..symbol.len() - 1]).unwrap_or("?");
        return Err(format!(
            "{name} failed (rc={rc}): {}",
            pcap_geterr_string(p)
        ));
    }
    Ok(())
}

fn run(
    attributor: Arc<PktapAttributor>,
    stop: Arc<AtomicBool>,
    startup_error: Arc<Mutex<Option<String>>>,
) {
    let device = match CString::new("pktap") {
        Ok(s) => s,
        Err(_) => {
            set_error(&startup_error, "internal: invalid device name".into());
            return;
        }
    };
    let mut errbuf = [0i8; ffi::PCAP_ERRBUF_SIZE];

    // SAFETY: pcap_create takes a NUL-terminated source string and a buffer
    // of at least PCAP_ERRBUF_SIZE bytes; both invariants are satisfied.
    let p = unsafe { ffi::pcap_create(device.as_ptr(), errbuf.as_mut_ptr()) };
    if p.is_null() {
        let msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        set_error(&startup_error, format!("pcap_create(pktap): {msg}"));
        return;
    }

    // Apple's metadata flag must be set BEFORE activate so the kernel
    // attaches the pktap_header to every frame.
    if let Err(e) = enable_pktap_metadata(p) {
        unsafe { ffi::pcap_close(p) };
        set_error(&startup_error, e);
        return;
    }

    // Configure capture parameters. Errors here are non-fatal — libpcap
    // returns negative on failure but the activate path will surface
    // anything important.
    unsafe {
        ffi::pcap_set_snaplen(p, PKTAP_SNAPLEN);
        ffi::pcap_set_timeout(p, PKTAP_TIMEOUT_MS);
        ffi::pcap_set_immediate_mode(p, 1);
    }

    let rc = unsafe { ffi::pcap_activate(p) };
    if rc < 0 {
        let err = pcap_geterr_string(p);
        unsafe { ffi::pcap_close(p) };
        set_error(&startup_error, format!("pcap_activate(pktap): {err}"));
        return;
    }

    let link = unsafe { ffi::pcap_datalink(p) };
    if link != DLT_PKTAP && link != LINKTYPE_PKTAP {
        unsafe { ffi::pcap_close(p) };
        set_error(
            &startup_error,
            format!("pktap returned linktype {link} after enabling metadata flag"),
        );
        return;
    }

    let mut last_evict = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let mut header_ptr: *mut ffi::pcap_pkthdr = std::ptr::null_mut();
        let mut data_ptr: *const u8 = std::ptr::null();
        // SAFETY: pcap_next_ex writes to both out-params on rc==1, leaves
        // them untouched on rc==0 (timeout). We check both before reading.
        let rc = unsafe { ffi::pcap_next_ex(p, &mut header_ptr, &mut data_ptr) };
        match rc {
            1 => {
                if !header_ptr.is_null() && !data_ptr.is_null() {
                    let caplen = unsafe { (*header_ptr).caplen } as usize;
                    let slice = unsafe { std::slice::from_raw_parts(data_ptr, caplen) };
                    if let Some((key, attr)) = parse_frame(slice) {
                        attributor.record(key, attr);
                    }
                }
            }
            0 => {} // timeout — loop and check stop signal
            _ => break,
        }

        if last_evict.elapsed() >= Duration::from_secs(10) {
            attributor.evict_stale(ATTRIBUTION_TTL);
            last_evict = Instant::now();
        }
    }

    unsafe { ffi::pcap_close(p) };
}

mod ffi {
    use std::os::raw::{c_char, c_int, c_uint};

    /// Opaque handle. We never construct one; libpcap hands them back as
    /// pointers and we pass them through.
    #[allow(non_camel_case_types)]
    pub enum pcap_t {}

    #[repr(C)]
    pub struct timeval {
        pub tv_sec: i64,
        pub tv_usec: i32,
    }

    #[repr(C)]
    pub struct pcap_pkthdr {
        pub ts: timeval,
        pub caplen: c_uint,
        pub len: c_uint,
        // Apple's pcap_pkthdr appends `char comment[256]` after `len`;
        // we never read that field so the size mismatch is harmless when we
        // only access fields by name through a pointer libpcap gave us.
    }

    pub const PCAP_ERRBUF_SIZE: usize = 256;

    extern "C" {
        pub fn pcap_create(source: *const c_char, errbuf: *mut c_char) -> *mut pcap_t;
        pub fn pcap_set_snaplen(p: *mut pcap_t, snaplen: c_int) -> c_int;
        pub fn pcap_set_timeout(p: *mut pcap_t, to_ms: c_int) -> c_int;
        pub fn pcap_set_immediate_mode(p: *mut pcap_t, immediate_mode: c_int) -> c_int;
        pub fn pcap_activate(p: *mut pcap_t) -> c_int;
        pub fn pcap_datalink(p: *mut pcap_t) -> c_int;
        pub fn pcap_next_ex(
            p: *mut pcap_t,
            pkt_header: *mut *mut pcap_pkthdr,
            pkt_data: *mut *const u8,
        ) -> c_int;
        pub fn pcap_close(p: *mut pcap_t);
        pub fn pcap_geterr(p: *mut pcap_t) -> *const c_char;
    }
}

// ── pktap_header layout (xnu/bsd/net/pktap.h + Wireshark dissector) ─────────
//
//    offset  size  field
//      0      4    pth_length            (header length in bytes)
//      4      4    pth_type_next
//      8      4    pth_dlt               (DLT of inner frame)
//     12     24    pth_ifname            (PKTAP_IFXNAMESIZE)
//     36      4    pth_flags             (PKTAP_FLAG_DIR_IN/OUT)
//     40      4    pth_protocol_family
//     44      4    pth_frame_pre_length
//     48      4    pth_frame_post_length
//     52      4    pth_pid
//     56     20    pth_comm              (MAXCOMLEN+1, NUL-padded to 20)
//     76      4    pth_svc
//     ...
// Newer macOS releases append additional fields; pth_length tells us where
// the inner frame begins, so we never assume the layout reaches the end.

const PTH_LENGTH_OFFSET: usize = 0;
const PTH_DLT_OFFSET: usize = 8;
const PTH_FLAGS_OFFSET: usize = 36;
const PTH_PID_OFFSET: usize = 52;
const PTH_COMM_OFFSET: usize = 56;
const PTH_COMM_SIZE: usize = 20;
const PKTAP_HEADER_MIN_LEN: usize = PTH_COMM_OFFSET + PTH_COMM_SIZE;

#[derive(Debug, Clone)]
struct PktapMeta {
    header_len: usize,
    inner_dlt: u32,
    pid: u32,
    comm: String,
    direction: Direction,
}

fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        buf.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_i32_le(buf: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_le_bytes(
        buf.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn parse_pktap_header(buf: &[u8]) -> Option<PktapMeta> {
    if buf.len() < PKTAP_HEADER_MIN_LEN {
        return None;
    }

    let pth_length = read_u32_le(buf, PTH_LENGTH_OFFSET)? as usize;
    if pth_length < PKTAP_HEADER_MIN_LEN || pth_length > buf.len() {
        return None;
    }

    let inner_dlt = read_u32_le(buf, PTH_DLT_OFFSET)?;
    let flags = read_u32_le(buf, PTH_FLAGS_OFFSET)?;
    let pid = read_i32_le(buf, PTH_PID_OFFSET)?;
    if pid <= 0 {
        // Kernel-internal traffic (-1) or unattributed (0) — skip.
        return None;
    }

    let comm_bytes = buf.get(PTH_COMM_OFFSET..PTH_COMM_OFFSET + PTH_COMM_SIZE)?;
    let nul = comm_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(PTH_COMM_SIZE);
    let comm = String::from_utf8_lossy(&comm_bytes[..nul]).into_owned();

    let direction = if flags & PKTAP_FLAG_DIR_IN != 0 {
        Direction::Inbound
    } else if flags & PKTAP_FLAG_DIR_OUT != 0 {
        Direction::Outbound
    } else {
        Direction::Unknown
    };

    Some(PktapMeta {
        header_len: pth_length,
        inner_dlt,
        pid: pid as u32,
        comm,
        direction,
    })
}

fn parse_frame(buf: &[u8]) -> Option<(StreamKey, Attribution)> {
    let meta = parse_pktap_header(buf)?;
    let inner = buf.get(meta.header_len..)?;
    let key = parse_inner_5tuple(meta.inner_dlt, inner)?;
    let attr = Attribution {
        pid: meta.pid,
        comm: meta.comm,
        direction: meta.direction,
        seen_at: Instant::now(),
    };
    Some((key, attr))
}

fn parse_inner_5tuple(dlt: u32, buf: &[u8]) -> Option<StreamKey> {
    match dlt {
        DLT_EN10MB => parse_ethernet(buf),
        DLT_RAW => parse_ip(buf),
        DLT_NULL => parse_null(buf),
        _ => None,
    }
}

fn parse_ethernet(buf: &[u8]) -> Option<StreamKey> {
    if buf.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
    let payload = &buf[14..];
    match ethertype {
        0x0800 => parse_ipv4(payload),
        0x86DD => parse_ipv6(payload),
        _ => None,
    }
}

fn parse_null(buf: &[u8]) -> Option<StreamKey> {
    if buf.len() < 4 {
        return None;
    }
    // BSD loopback header is a 4-byte address family. The byte order varies
    // between platforms and capture sources; try LE first then BE.
    let af_le = u32::from_le_bytes(buf[0..4].try_into().ok()?);
    let af = if matches!(af_le, 2 | 28 | 30) {
        af_le
    } else {
        u32::from_be_bytes(buf[0..4].try_into().ok()?)
    };
    let payload = &buf[4..];
    match af {
        2 => parse_ipv4(payload),
        28 | 30 => parse_ipv6(payload),
        _ => None,
    }
}

fn parse_ip(buf: &[u8]) -> Option<StreamKey> {
    if buf.is_empty() {
        return None;
    }
    let version = buf[0] >> 4;
    match version {
        4 => parse_ipv4(buf),
        6 => parse_ipv6(buf),
        _ => None,
    }
}

fn parse_ipv4(buf: &[u8]) -> Option<StreamKey> {
    if buf.len() < 20 {
        return None;
    }
    let ihl = ((buf[0] & 0x0F) as usize) * 4;
    if buf.len() < ihl + 4 {
        return None;
    }
    let proto = buf[9];
    let src = format!("{}.{}.{}.{}", buf[12], buf[13], buf[14], buf[15]);
    let dst = format!("{}.{}.{}.{}", buf[16], buf[17], buf[18], buf[19]);
    let transport = &buf[ihl..];
    parse_l4(proto, transport, &src, &dst)
}

fn parse_ipv6(buf: &[u8]) -> Option<StreamKey> {
    if buf.len() < 40 {
        return None;
    }
    // We treat the Next Header byte as the L4 protocol. Extension headers
    // would shift the offset, but they're rare enough on attribution paths
    // that we accept the minor blind spot for parser simplicity.
    let proto = buf[6];
    let src = format_ipv6(&buf[8..24]);
    let dst = format_ipv6(&buf[24..40]);
    let transport = &buf[40..];
    parse_l4(proto, transport, &src, &dst)
}

fn format_ipv6(bytes: &[u8]) -> String {
    use std::net::Ipv6Addr;
    let mut a = [0u8; 16];
    a.copy_from_slice(&bytes[..16]);
    Ipv6Addr::from(a).to_string()
}

fn parse_l4(proto: u8, buf: &[u8], src_ip: &str, dst_ip: &str) -> Option<StreamKey> {
    if buf.len() < 4 {
        return None;
    }
    let src_port = u16::from_be_bytes([buf[0], buf[1]]);
    let dst_port = u16::from_be_bytes([buf[2], buf[3]]);
    let stream_proto = match proto {
        6 => StreamProtocol::Tcp,
        17 => StreamProtocol::Udp,
        _ => return None,
    };
    Some(StreamKey::new(
        stream_proto,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic PKTAP-decorated ethernet/IPv4/TCP frame.
    fn build_test_frame(pid: i32, comm: &[u8], dir_flag: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 156];
        buf[0..4].copy_from_slice(&156u32.to_le_bytes()); // pth_length
        buf[4..8].copy_from_slice(&1u32.to_le_bytes()); // pth_type_next
        buf[8..12].copy_from_slice(&1u32.to_le_bytes()); // pth_dlt = ETHERNET
        buf[12..16].copy_from_slice(b"en0\0"); // pth_ifname
        buf[36..40].copy_from_slice(&dir_flag.to_le_bytes()); // pth_flags
        buf[52..56].copy_from_slice(&pid.to_le_bytes()); // pth_pid
        let n = comm.len().min(PTH_COMM_SIZE - 1);
        buf[PTH_COMM_OFFSET..PTH_COMM_OFFSET + n].copy_from_slice(&comm[..n]);

        // Ethernet (14)
        let mut eth = vec![0u8; 14];
        eth[12] = 0x08;
        eth[13] = 0x00;
        buf.extend_from_slice(&eth);

        // IPv4 (20) — TCP
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[1, 1, 1, 1]);
        buf.extend_from_slice(&ip);

        // TCP (20) — only ports matter
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&54321u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        buf.extend_from_slice(&tcp);

        buf
    }

    #[test]
    fn parse_header_extracts_pid_and_comm() {
        let frame = build_test_frame(4242, b"curl\0", PKTAP_FLAG_DIR_OUT);
        let meta = parse_pktap_header(&frame).expect("header parse");
        assert_eq!(meta.pid, 4242);
        assert_eq!(meta.comm, "curl");
        assert_eq!(meta.direction, Direction::Outbound);
        assert_eq!(meta.inner_dlt, 1);
    }

    #[test]
    fn parse_header_rejects_truncated_buffer() {
        let frame = build_test_frame(1, b"x", 0);
        assert!(parse_pktap_header(&frame[..30]).is_none());
    }

    #[test]
    fn parse_header_rejects_zero_pid() {
        let frame = build_test_frame(0, b"", 0);
        assert!(parse_pktap_header(&frame).is_none());
    }

    #[test]
    fn parse_frame_extracts_5tuple_and_attribution() {
        let frame = build_test_frame(99, b"ssh\0", PKTAP_FLAG_DIR_IN);
        let (key, attr) = parse_frame(&frame).expect("parse");
        assert_eq!(attr.pid, 99);
        assert_eq!(attr.comm, "ssh");
        assert_eq!(attr.direction, Direction::Inbound);
        assert_eq!(key.protocol, StreamProtocol::Tcp);
    }

    #[test]
    fn parse_ipv4_handles_minimum_header() {
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[192, 168, 1, 1]);
        ip[16..20].copy_from_slice(&[8, 8, 8, 8]);
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        ip.extend_from_slice(&udp);

        let key = parse_ipv4(&ip).expect("parse ipv4");
        assert_eq!(key.protocol, StreamProtocol::Udp);
    }

    #[test]
    fn cache_lookup_round_trip() {
        let attr = PktapAttributor::new();
        let key = StreamKey::new(StreamProtocol::Tcp, "10.0.0.1", 8000, "1.1.1.1", 443);
        attr.record(
            key.clone(),
            Attribution {
                pid: 1234,
                comm: "myapp".to_string(),
                direction: Direction::Outbound,
                seen_at: Instant::now(),
            },
        );
        let got = attr.lookup(&key).expect("present");
        assert_eq!(got.pid, 1234);
        assert_eq!(got.comm, "myapp");
    }

    #[test]
    fn cache_evicts_old_entries() {
        let attr = PktapAttributor::new();
        let key = StreamKey::new(StreamProtocol::Tcp, "10.0.0.1", 1, "1.1.1.1", 2);
        attr.record(
            key.clone(),
            Attribution {
                pid: 1,
                comm: "x".to_string(),
                direction: Direction::Unknown,
                seen_at: Instant::now() - Duration::from_secs(3600),
            },
        );
        attr.evict_stale(Duration::from_secs(60));
        assert!(attr.lookup(&key).is_none());
    }
}
