//! Kernel TCP state per connection — congestion window, slow-start threshold,
//! MSS and the peer's advertised receive window.
//!
//! These are the four numbers that explain *why* a transfer is the speed it
//! is. Throughput tells you what happened; `cwnd` against `ssthresh` tells you
//! whether you're in slow start or congestion avoidance, and a `cwnd` pinned
//! small next to a healthy `rwnd` is the difference between "the network is
//! congested" and "the peer isn't reading". Nothing else netwatch collects
//! answers that.
//!
//! **Availability is per-platform and the UI must degrade, not lie:**
//!
//! | platform | source | status |
//! |---|---|---|
//! | Linux | `NETLINK_INET_DIAG` / `SOCK_DIAG_BY_FAMILY` with `INET_DIAG_INFO` | implemented |
//! | macOS | `sysctl net.inet.tcp.pcblist64` (`struct xtcpcb64`) | implemented |
//! | Windows | `GetPerTcpConnectionEStats` (needs per-connection enablement) | not yet — returns nothing |
//! | FreeBSD | would be `sysctl net.inet.tcp.pcblist` (a different struct from macOS's exported ABI) | not yet — returns nothing |
//!
//! Callers get `None` for an unknown flow on every platform, so a missing
//! collector and a not-yet-observed connection take the same path: render `--`.
//!
//! The wire parsing is deliberately split from the syscalls ([`parse_diag_dump`]
//! and [`parse_pcblist64`] are pure and compiled everywhere) so the byte layout
//! — the part that is easy to get wrong and impossible to eyeball — is unit
//! tested on any host, not only on the platform it belongs to.
//!
//! **The two kernels disagree about units**, and normalising is the whole
//! reason this module exists rather than two ad-hoc readers:
//!
//! * Linux reports `cwnd` / `ssthresh` in **segments**; BSD reports them in
//!   **bytes**. macOS values are divided by the MSS here so the column means
//!   one thing, and `ss`-shaped numbers are what you get on both.
//! * "ssthresh not set yet" is `i32::MAX` on Linux and `0x3FFF_C000`
//!   (`TCP_MAXWIN << TCP_MAX_WINSHIFT`) on BSD. [`TcpInfo::ssthresh_unset`]
//!   knows both.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

/// Per-connection kernel TCP state. Every field is optional: kernels differ in
/// what they report, and a field we cannot read must never be confused with a
/// measured zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpInfo {
    /// Congestion window, in segments (the kernel's own unit).
    pub cwnd: Option<u32>,
    /// Slow-start threshold, in segments. The kernel writes `i32::MAX`
    /// (2147483647) when it hasn't been set yet — a connection that has never
    /// left slow start — which is why [`TcpInfo::ssthresh_unset`] exists rather
    /// than a `u32::MAX` check. `ss` simply omits the field in that state; we
    /// render `∞`, which says the same thing in a fixed-width column.
    pub ssthresh: Option<u32>,
    /// Sender MSS in bytes.
    pub mss: Option<u32>,
    /// The peer's advertised receive window in bytes. Only exposed by kernels
    /// new enough to carry `tcpi_snd_wnd` (Linux 5.4+).
    pub rwnd: Option<u32>,
    /// Smoothed RTT in microseconds — the kernel's own estimate, which is a
    /// different measurement from netwatch's handshake RTT and worth having
    /// beside it.
    pub rtt_us: Option<u32>,
    /// Total retransmits over the life of the connection.
    pub total_retrans: Option<u32>,
}

/// BSD's "no slow-start threshold yet" sentinel: `TCP_MAXWIN << TCP_MAX_WINSHIFT`.
const BSD_SSTHRESH_UNSET: u32 = 65535 << 14;

impl TcpInfo {
    /// True when the kernel is reporting "slow-start threshold not yet set" —
    /// in either of the two spellings the platforms use for it.
    pub fn ssthresh_unset(&self) -> bool {
        matches!(self.ssthresh, Some(v) if v >= i32::MAX as u32 || v >= BSD_SSTHRESH_UNSET)
    }
}

/// Flow identity as the connection table renders it: `(local, remote)` with
/// `addr:port` on both sides, so a lookup is a plain map hit with no parsing
/// at render time.
pub type FlowKey = (String, String);

pub type FlowMap = HashMap<FlowKey, TcpInfo>;

/// Canonical `addr:port` for one endpoint.
///
/// Both sides of a lookup go through this. The kernel and the connection table
/// spell addresses differently — `lsof` on macOS emits `fe80::1]:1024` with no
/// opening bracket, IPv4-mapped IPv6 shows up either way round — and an
/// unnormalised key match is a silent miss that renders `--` forever while both
/// halves look healthy in isolation.
pub fn endpoint(ip: std::net::IpAddr, port: u16) -> String {
    format!("{}:{}", ip.to_canonical(), port)
}

/// Canonicalise an endpoint the UI already rendered as a string.
///
/// Unparseable input is passed through trimmed rather than dropped: a key that
/// can't be canonicalised still matches itself.
pub fn normalize_endpoint(s: &str) -> String {
    fn trim(h: &str) -> &str {
        h.trim_start_matches('[').trim_end_matches(']')
    }
    let (host, port) = if let Some(i) = s.rfind("]:") {
        (trim(&s[..i]), &s[i + 2..])
    } else if let Some(i) = s.rfind(':') {
        let (h, p) = (&s[..i], &s[i + 1..]);
        if h.contains(':') || p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return trim(s).to_string();
        }
        (trim(h), p)
    } else {
        return trim(s).to_string();
    };
    match (host.parse::<std::net::IpAddr>(), port.parse::<u16>()) {
        (Ok(ip), Ok(p)) => endpoint(ip, p),
        _ => format!("{host}:{port}"),
    }
}

/// Collects kernel TCP state off-thread and publishes an immutable snapshot.
///
/// Same `Arc<RwLock<Arc<…>>>` shape as [`crate::collectors::traffic`]: readers
/// clone the inner `Arc` in O(1) and never block on an in-flight dump.
pub struct TcpInfoCollector {
    snapshot: Arc<RwLock<(Arc<FlowMap>, Option<std::time::Instant>)>>,
    busy: Arc<AtomicBool>,
    outcome: Arc<RwLock<Option<Result<(), String>>>>,
}

impl Default for TcpInfoCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpInfoCollector {
    pub fn new() -> Self {
        Self {
            snapshot: Arc::new(RwLock::new((Arc::new(HashMap::new()), None))),
            busy: Arc::new(AtomicBool::new(false)),
            outcome: Arc::new(RwLock::new(None)),
        }
    }

    /// Kick off a refresh. Returns immediately; a dump already in flight is
    /// left alone rather than queued behind itself.
    pub fn update(&self) {
        if !platform_supported() {
            return;
        }
        if self.busy.swap(true, Ordering::SeqCst) {
            return;
        }
        let snapshot = Arc::clone(&self.snapshot);
        let busy = Arc::clone(&self.busy);
        let outcome = Arc::clone(&self.outcome);
        crate::sandbox::worker::spawn("tcp-info", move || {
            let collected = collect();
            *outcome.write().unwrap() = Some(
                collected
                    .as_ref()
                    .map(|_| ())
                    .map_err(|e| format!("{:?}: {e}", e.kind())),
            );
            let completed = collected.as_ref().ok().map(|_| std::time::Instant::now());
            if let Ok(mut w) = snapshot.write() {
                *w = (Arc::new(collected.unwrap_or_default()), completed);
            }
            busy.store(false, Ordering::SeqCst);
        });
    }

    /// Latest dump outcome; a successful empty dump is not a collector failure.
    pub fn outcome(&self) -> Option<Result<(), String>> {
        self.outcome.read().unwrap().clone()
    }

    pub fn snapshot(&self) -> Arc<FlowMap> {
        Arc::clone(&self.snapshot.read().unwrap().0)
    }

    pub fn timed_snapshot(&self) -> (Arc<FlowMap>, Option<std::time::Instant>) {
        self.snapshot.read().unwrap().clone()
    }

    /// Publish `flows` as if a dump had just completed, for tests.
    #[cfg(test)]
    pub(crate) fn publish_for_test(&self, flows: FlowMap) {
        *self.snapshot.write().unwrap() = (Arc::new(flows), Some(std::time::Instant::now()));
    }

    pub fn get(&self, local: &str, remote: &str) -> Option<TcpInfo> {
        self.snapshot()
            .get(&(normalize_endpoint(local), normalize_endpoint(remote)))
            .copied()
    }
}

/// True where a dump is actually implemented — see the table in the module
/// docs. Keeps the collector from spawning a thread per tick to do nothing.
pub const fn platform_supported() -> bool {
    cfg!(target_os = "linux") || cfg!(target_os = "macos")
}

// ── the wire format ─────────────────────────────────────────────────────────
//
// Offsets into `struct tcp_info` (linux/tcp.h). The struct only ever grows at
// the end, so reading by offset with a length guard is stable across kernels —
// and is why every accessor below checks `len` first.

const TCPI_SND_MSS: usize = 16;
const TCPI_RTT: usize = 68;
const TCPI_SND_SSTHRESH: usize = 76;
const TCPI_SND_CWND: usize = 80;
const TCPI_TOTAL_RETRANS: usize = 100;
/// Added in Linux 5.4, well past the original struct's tail.
const TCPI_SND_WND: usize = 228;

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_ne_bytes([s[0], s[1], s[2], s[3]]))
}

/// Parse a `struct tcp_info` payload.
///
/// Short buffers are normal, not an error: an older kernel simply stops the
/// struct earlier, and every field past that point reads as `None`.
pub fn parse_tcp_info(b: &[u8]) -> TcpInfo {
    TcpInfo {
        cwnd: u32_at(b, TCPI_SND_CWND),
        ssthresh: u32_at(b, TCPI_SND_SSTHRESH),
        mss: u32_at(b, TCPI_SND_MSS),
        rwnd: u32_at(b, TCPI_SND_WND),
        rtt_us: u32_at(b, TCPI_RTT),
        total_retrans: u32_at(b, TCPI_TOTAL_RETRANS),
    }
}

// netlink / inet_diag constants
const NLMSG_HDR_LEN: usize = 16;
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const INET_DIAG_INFO: u16 = 2;
/// `struct inet_diag_msg` up to the start of its rtattrs.
const INET_DIAG_MSG_LEN: usize = 72;
/// Offset of `inet_diag_sockid` inside `inet_diag_msg`.
const SOCKID_OFF: usize = 4;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Render an address from an `inet_diag_sockid` — 4 bytes for v4, 16 for v6,
/// which is the only thing that distinguishes them on the wire here.
fn addr_str(raw: &[u8], family: u8) -> String {
    if family == 2 {
        // AF_INET
        format!("{}.{}.{}.{}", raw[0], raw[1], raw[2], raw[3])
    } else {
        let mut segs = [0u16; 8];
        for (i, s) in segs.iter_mut().enumerate() {
            *s = u16::from_be_bytes([raw[i * 2], raw[i * 2 + 1]]);
        }
        std::net::Ipv6Addr::from(segs).to_string()
    }
}

/// Parse a full `SOCK_DIAG_BY_FAMILY` dump into flow → [`TcpInfo`].
///
/// Pure and platform-independent on purpose: this is the half that is easy to
/// get wrong, so it is the half that gets tested everywhere.
pub fn parse_diag_dump(buf: &[u8]) -> FlowMap {
    let mut out = HashMap::new();
    let mut off = 0usize;

    while off + NLMSG_HDR_LEN <= buf.len() {
        let len = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
        let kind = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
        if len < NLMSG_HDR_LEN || off + len > buf.len() {
            break;
        }
        if kind == NLMSG_DONE || kind == NLMSG_ERROR {
            break;
        }
        let body = &buf[off + NLMSG_HDR_LEN..off + len];

        if kind == SOCK_DIAG_BY_FAMILY && body.len() >= INET_DIAG_MSG_LEN {
            let family = body[0];
            let sid = &body[SOCKID_OFF..];
            let sport = u16::from_be_bytes([sid[0], sid[1]]);
            let dport = u16::from_be_bytes([sid[2], sid[3]]);
            let src = addr_str(&sid[4..20], family);
            let dst = addr_str(&sid[20..36], family);

            // rtattrs follow the fixed struct.
            let mut a = INET_DIAG_MSG_LEN;
            let mut info = None;
            while a + 4 <= body.len() {
                let alen = u16::from_ne_bytes([body[a], body[a + 1]]) as usize;
                let atype = u16::from_ne_bytes([body[a + 2], body[a + 3]]);
                if alen < 4 || a + alen > body.len() {
                    break;
                }
                if atype == INET_DIAG_INFO {
                    info = Some(parse_tcp_info(&body[a + 4..a + alen]));
                }
                a += align4(alen);
            }

            if let Some(info) = info {
                out.insert(
                    (
                        normalize_endpoint(&format!("{src}:{sport}")),
                        normalize_endpoint(&format!("{dst}:{dport}")),
                    ),
                    info,
                );
            }
        }
        off += align4(len);
    }
    out
}

// ── platform ────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn collect() -> std::io::Result<FlowMap> {
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;

    /// `NETLINK_INET_DIAG`
    const NETLINK_INET_DIAG: i32 = 4;
    const NLM_F_REQUEST: u16 = 0x001;
    const NLM_F_DUMP: u16 = 0x300;
    const IPPROTO_TCP: u8 = 6;
    /// Established sockets only. Listening and time-wait sockets have no
    /// congestion state worth showing, and dumping them triples the response
    /// on a busy host for nothing.
    const TCPF_ESTABLISHED: u32 = 1 << 1;

    let mut map = FlowMap::new();
    for family in [2u8, 10u8] {
        // AF_INET, AF_INET6
        // SAFETY: socket takes three integers and reads no memory of ours;
        // the descriptor it returns is checked below.
        let fd = unsafe {
            nix::libc::socket(
                nix::libc::AF_NETLINK,
                nix::libc::SOCK_DGRAM | nix::libc::SOCK_CLOEXEC,
                NETLINK_INET_DIAG,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is the socket just created, checked non-negative above
        // and owned by nothing else, so `sock` takes sole ownership and
        // closes it once.
        let mut sock = unsafe { std::fs::File::from_raw_fd(fd) };

        // nlmsghdr + inet_diag_req_v2
        let mut req = Vec::with_capacity(72);
        req.extend_from_slice(&72u32.to_ne_bytes()); // nlmsg_len
        req.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        req.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        req.extend_from_slice(&1u32.to_ne_bytes()); // seq
        req.extend_from_slice(&0u32.to_ne_bytes()); // pid
        req.push(family);
        req.push(IPPROTO_TCP);
        // sdiag_ext: request INET_DIAG_INFO. The bitmask is 1 << (attr - 1).
        req.push(1 << (INET_DIAG_INFO - 1));
        req.push(0); // pad
        req.extend_from_slice(&TCPF_ESTABLISHED.to_ne_bytes());
        req.extend_from_slice(&[0u8; 48]); // inet_diag_sockid: match all
        sock.write_all(&req)?;

        // Dumps arrive in multiple datagrams; read until DONE or EOF.
        let mut acc = Vec::new();
        let mut chunk = vec![0u8; 32 * 1024];
        loop {
            let n = sock.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            acc.extend_from_slice(&chunk[..n]);
            // A DONE message ends the dump; parse_diag_dump stops there too.
            let kind = u16::from_ne_bytes([chunk[4], chunk[5]]);
            if kind == NLMSG_DONE || kind == NLMSG_ERROR || n < NLMSG_HDR_LEN {
                break;
            }
        }
        map.extend(parse_diag_dump(&acc));
    }
    Ok(map)
}

// ── macOS: net.inet.tcp.pcblist64 ──────────────────────────────────────────
//
// Offsets into `struct xtcpcb64` (netinet/tcp_var.h, under `#pragma pack(4)`),
// taken from `offsetof` against the SDK headers rather than counted by hand,
// and then checked against a live dump. Both steps mattered: the struct packs
// at 4, so hand-counting drifts, and a wrong offset reads a plausible number
// from the wrong field instead of failing.
//
// This is the sysctl-exported ABI, not an internal struct — it is stable, and
// `xt_len` is used to walk records so a longer one on a future OS is skipped
// rather than misread.

/// `struct xinpgen`, the header and the trailer of the dump.
const XIG_SIZE: usize = 24;
const XT_LEN: usize = 0;
const INP_FPORT: usize = 20;
const INP_LPORT: usize = 22;
const INP_VFLAG: usize = 96;
const INP_FADDR: usize = 100;
const INP_LADDR: usize = 116;
/// IPv4 sits in the last 4 bytes of the 16-byte `in_addr_4in6` union.
const V4_IN_V6: usize = 12;
const XT_STATE: usize = 292;
const XT_RCV_WND: usize = 344;
const XT_SND_WND: usize = 352;
const XT_SND_CWND: usize = 356;
const XT_SND_SSTHRESH: usize = 360;
const XT_MAXSEG: usize = 388;
const XT_SRTT: usize = 392;
/// Shortest record we can read every field from.
const XT_MIN_LEN: usize = XT_SRTT + 4;

const INP_IPV4: u8 = 1;
const TCPS_ESTABLISHED: i32 = 4;

/// BSD stores `t_srtt` as milliseconds shifted left by `TCP_RTT_SHIFT` (5).
/// Neither constant is in the public SDK, so the conversion is spelled out and
/// pinned by a test against a value cross-checked with a live connection.
const TCP_RTT_SHIFT: u32 = 5;

fn u32_at_ne(b: &[u8], off: usize) -> Option<u32> {
    u32_at(b, off)
}

/// Parse a `net.inet.tcp.pcblist64` dump into flow → [`TcpInfo`].
///
/// Pure and compiled on every platform so the layout is unit-tested off macOS
/// too. Only established connections are kept: a listening or time-wait socket
/// has no congestion state worth showing.
pub fn parse_pcblist64(buf: &[u8]) -> FlowMap {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let mut out = HashMap::new();
    if buf.len() < XIG_SIZE {
        return out;
    }
    // The leading xinpgen states its own length; records follow it.
    let mut off = u32_at(buf, 0).unwrap_or(XIG_SIZE as u32) as usize;

    while off + 8 <= buf.len() {
        let Some(rec_len) = u32_at(buf, off + XT_LEN).map(|v| v as usize) else {
            break;
        };
        // A trailing xinpgen closes the dump, and any nonsense length stops it.
        if rec_len < 8 || off + rec_len > buf.len() || rec_len == XIG_SIZE {
            break;
        }
        let rec = &buf[off..off + rec_len];
        off += rec_len;

        if rec_len < XT_MIN_LEN {
            continue;
        }
        if u32_at_ne(rec, XT_STATE).map(|v| v as i32) != Some(TCPS_ESTABLISHED) {
            continue;
        }

        let vflag = rec[INP_VFLAG];
        let addr = |base: usize| -> Option<IpAddr> {
            let raw = rec.get(base..base + 16)?;
            if vflag & INP_IPV4 != 0 {
                let o = &raw[V4_IN_V6..];
                Some(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])))
            } else {
                let mut b = [0u8; 16];
                b.copy_from_slice(raw);
                Some(IpAddr::V6(Ipv6Addr::from(b)))
            }
        };
        let (Some(local), Some(remote)) = (addr(INP_LADDR), addr(INP_FADDR)) else {
            continue;
        };
        // Ports are network byte order inside a host-endian struct.
        let lport = u16::from_be_bytes([rec[INP_LPORT], rec[INP_LPORT + 1]]);
        let fport = u16::from_be_bytes([rec[INP_FPORT], rec[INP_FPORT + 1]]);

        let mss = u32_at_ne(rec, XT_MAXSEG).filter(|v| *v > 0);
        // BSD counts the windows in bytes; Linux counts them in segments.
        // Normalise here so the UI column means one thing on both.
        let to_segments = |bytes: Option<u32>| match (bytes, mss) {
            (Some(b), Some(m)) if b < BSD_SSTHRESH_UNSET => Some(b / m),
            (Some(b), _) => Some(b),
            _ => None,
        };
        let srtt = u32_at_ne(rec, XT_SRTT);

        out.insert(
            (endpoint(local, lport), endpoint(remote, fport)),
            TcpInfo {
                cwnd: to_segments(u32_at_ne(rec, XT_SND_CWND)),
                ssthresh: to_segments(u32_at_ne(rec, XT_SND_SSTHRESH)),
                mss,
                rwnd: u32_at_ne(rec, XT_SND_WND),
                // Scale before shifting: `(v >> 5) * 1000` throws away every
                // sub-millisecond RTT, so a LAN peer reported a flat 0.
                rtt_us: srtt.map(|v| ((v as u64 * 1000) >> TCP_RTT_SHIFT) as u32),
                // BSD's exported tcpcb has no lifetime retransmit counter;
                // netwatch's own stream tracker already carries per-flow
                // retransmits, and the detail row shows those.
                total_retrans: None,
            },
        );
        let _ = u32_at_ne(rec, XT_RCV_WND);
    }
    out
}

#[cfg(target_os = "macos")]
fn collect() -> std::io::Result<FlowMap> {
    use std::ffi::CString;

    let name = CString::new("net.inet.tcp.pcblist64").expect("literal has no NUL");
    let mut len: usize = 0;
    // Sized first, then fetched — the table changes between the two calls, so
    // the buffer is over-allocated a little and the walk is length-driven.
    // SAFETY: `name` is a CString that outlives the call. A null `oldp` with
    // a live `oldlenp` asks only for the size, which is written to `len`, and
    // a null `newp` with length 0 sets nothing.
    let rc = unsafe {
        nix::libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len == 0 {
        return Err(std::io::Error::last_os_error());
    }
    len += len / 8;
    let mut buf = vec![0u8; len];
    // SAFETY: `buf` holds `len` writable bytes, since it was allocated from
    // `len` on the line above. sysctlbyname writes at most `len` bytes into
    // it and stores the count written back in `len`. `name` is as above.
    let rc = unsafe {
        nix::libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr() as *mut nix::libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(len);
    Ok(parse_pcblist64(&buf))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn collect() -> std::io::Result<FlowMap> {
    // Windows would come from `GetPerTcpConnectionEStats`, which needs
    // per-connection enablement. Until then the UI shows `--`, which is the
    // honest answer.
    Ok(FlowMap::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `tcp_info` payload with the fields we read set to known values.
    fn tcp_info_bytes(len: usize) -> Vec<u8> {
        let mut b = vec![0u8; len];
        let put = |b: &mut Vec<u8>, off: usize, v: u32| {
            if off + 4 <= b.len() {
                b[off..off + 4].copy_from_slice(&v.to_ne_bytes());
            }
        };
        put(&mut b, TCPI_SND_MSS, 1448);
        put(&mut b, TCPI_RTT, 18_000);
        put(&mut b, TCPI_SND_SSTHRESH, 128);
        put(&mut b, TCPI_SND_CWND, 42);
        put(&mut b, TCPI_TOTAL_RETRANS, 3);
        put(&mut b, TCPI_SND_WND, 3_100_000);
        b
    }

    #[test]
    fn parses_every_field_from_a_modern_kernel_struct() {
        let info = parse_tcp_info(&tcp_info_bytes(232));
        assert_eq!(info.cwnd, Some(42));
        assert_eq!(info.ssthresh, Some(128));
        assert_eq!(info.mss, Some(1448));
        assert_eq!(info.rwnd, Some(3_100_000));
        assert_eq!(info.rtt_us, Some(18_000));
        assert_eq!(info.total_retrans, Some(3));
    }

    /// An older kernel's struct simply stops early. Fields past the end must
    /// read as unavailable, never as a zero we'd render as a real measurement.
    #[test]
    fn short_structs_degrade_field_by_field() {
        let info = parse_tcp_info(&tcp_info_bytes(104));
        assert_eq!(info.cwnd, Some(42), "cwnd is inside even the oldest struct");
        assert_eq!(info.total_retrans, Some(3));
        assert_eq!(info.rwnd, None, "snd_wnd is past this kernel's struct");

        let truncated = parse_tcp_info(&tcp_info_bytes(20));
        assert_eq!(truncated.mss, Some(1448));
        assert_eq!(truncated.cwnd, None);
        assert_eq!(truncated.rtt_us, None);
    }

    /// Observed on Linux 7.0: an SSH session that has never left slow start
    /// reports `ssthresh: 2147483647`. Rendering that as a segment count would
    /// be gibberish in a column two characters wide.
    #[test]
    fn unset_ssthresh_is_recognised_at_the_kernel_sentinel() {
        let mut b = tcp_info_bytes(232);
        b[TCPI_SND_SSTHRESH..TCPI_SND_SSTHRESH + 4]
            .copy_from_slice(&(i32::MAX as u32).to_ne_bytes());
        let info = parse_tcp_info(&b);
        assert!(info.ssthresh_unset(), "i32::MAX must read as unset");

        let normal = parse_tcp_info(&tcp_info_bytes(232));
        assert!(!normal.ssthresh_unset(), "128 is a real threshold");
    }

    #[test]
    fn empty_payload_yields_nothing_rather_than_panicking() {
        assert_eq!(parse_tcp_info(&[]), TcpInfo::default());
    }

    /// One `inet_diag_msg` carrying one `INET_DIAG_INFO` attribute, built the
    /// way the kernel lays it out.
    fn diag_msg(family: u8, src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Vec<u8> {
        let info = tcp_info_bytes(232);
        let attr_len = 4 + info.len();
        let body_len = INET_DIAG_MSG_LEN + align4(attr_len);
        let total = NLMSG_HDR_LEN + body_len;

        let mut m = Vec::new();
        m.extend_from_slice(&(total as u32).to_ne_bytes());
        m.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        m.extend_from_slice(&0u16.to_ne_bytes()); // flags
        m.extend_from_slice(&1u32.to_ne_bytes()); // seq
        m.extend_from_slice(&0u32.to_ne_bytes()); // pid

        let mut body = vec![0u8; INET_DIAG_MSG_LEN];
        body[0] = family;
        body[SOCKID_OFF..SOCKID_OFF + 2].copy_from_slice(&sport.to_be_bytes());
        body[SOCKID_OFF + 2..SOCKID_OFF + 4].copy_from_slice(&dport.to_be_bytes());
        body[SOCKID_OFF + 4..SOCKID_OFF + 8].copy_from_slice(&src);
        body[SOCKID_OFF + 20..SOCKID_OFF + 24].copy_from_slice(&dst);
        body.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        body.extend_from_slice(&INET_DIAG_INFO.to_ne_bytes());
        body.extend_from_slice(&info);
        body.resize(body_len, 0);

        m.extend_from_slice(&body);
        m
    }

    #[test]
    fn parses_a_dump_into_flow_keys_the_ui_can_look_up() {
        let mut buf = diag_msg(2, [192, 168, 0, 213], 52814, [151, 101, 1, 229], 443);
        buf.extend_from_slice(&diag_msg(2, [10, 0, 0, 5], 22, [10, 0, 0, 9], 51000));

        let map = parse_diag_dump(&buf);
        assert_eq!(map.len(), 2);
        let info = map
            .get(&(
                "192.168.0.213:52814".to_string(),
                "151.101.1.229:443".to_string(),
            ))
            .expect("flow key must match how the connection table renders addresses");
        assert_eq!(info.cwnd, Some(42));
        assert_eq!(info.mss, Some(1448));
    }

    #[test]
    fn parses_v6_addresses() {
        let mut m = diag_msg(10, [0, 0, 0, 0], 443, [0, 0, 0, 0], 443);
        // Overwrite the v6 source with ::1 and the destination with 2606:4700::1111.
        let src = std::net::Ipv6Addr::LOCALHOST.octets();
        let dst: [u8; 16] = "2606:4700::1111"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets();
        let base = NLMSG_HDR_LEN + SOCKID_OFF;
        m[base + 4..base + 20].copy_from_slice(&src);
        m[base + 20..base + 36].copy_from_slice(&dst);

        let map = parse_diag_dump(&m);
        assert!(
            map.contains_key(&("::1:443".to_string(), "2606:4700::1111:443".to_string())),
            "got {:?}",
            map.keys().collect::<Vec<_>>()
        );
    }

    /// A dump that ends in DONE, and a truncated one, must both terminate.
    #[test]
    fn malformed_and_terminated_dumps_do_not_loop() {
        let mut done = Vec::new();
        done.extend_from_slice(&(NLMSG_HDR_LEN as u32).to_ne_bytes());
        done.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        done.extend_from_slice(&[0u8; 8]);
        assert!(parse_diag_dump(&done).is_empty());

        // Length field claims more than the buffer holds.
        let mut lying = diag_msg(2, [1, 2, 3, 4], 1, [5, 6, 7, 8], 2);
        lying[0] = 255;
        assert!(parse_diag_dump(&lying).is_empty());

        assert!(parse_diag_dump(&[]).is_empty());
        assert!(parse_diag_dump(&[0, 0, 0]).is_empty());
    }

    /// Talks to the running kernel, so it is environment-dependent and
    /// `#[ignore]`d by default. Run it on a Linux box that has at least one
    /// established TCP connection (an SSH session will do):
    ///
    /// ```text
    /// cargo test --lib tcp_info -- --ignored --nocapture
    /// ```
    ///
    /// Compiling the netlink path is not the same as proving the kernel
    /// answers it, and the offsets are exactly the kind of thing that compiles
    /// perfectly while reading the wrong four bytes.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn live_dump_returns_plausible_kernel_state() {
        let map = collect().expect("netlink dump failed");
        assert!(
            !map.is_empty(),
            "no established TCP flows found — run this with an SSH session open"
        );
        for ((local, remote), info) in map.iter().take(5) {
            println!("{local} → {remote}: {info:?}");
        }
        // Every established flow must have a sane MSS and a non-zero window.
        let (_, info) = map.iter().next().unwrap();
        let mss = info
            .mss
            .expect("mss must be present on an established flow");
        assert!(
            (88..=65535).contains(&mss),
            "mss {mss} is outside any plausible range — offsets are probably wrong"
        );
        let cwnd = info.cwnd.expect("cwnd must be present");
        assert!(
            (1..=100_000).contains(&cwnd),
            "cwnd {cwnd} is not a plausible segment count"
        );
    }

    /// The seam that would fail silently: netlink renders its own addresses,
    /// and the connection table renders addresses from `/proc` or `ss`. If the
    /// two spellings disagree — brackets on IPv6, a canonicalised v4-mapped
    /// address — every lookup misses and the detail row shows `--` forever
    /// while both halves look perfectly healthy in isolation.
    ///
    /// Environment-dependent, so `#[ignore]`d:
    /// `cargo test --lib tcp_info -- --ignored --nocapture`
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn flow_keys_match_the_connection_table() {
        use crate::collectors::connections::ConnectionCollector;
        use std::sync::{Arc, Mutex};

        let diag = collect().expect("netlink dump failed");
        assert!(!diag.is_empty(), "no established flows to compare against");

        let tracker = Arc::new(Mutex::new(Default::default()));
        let conns = ConnectionCollector::new(tracker);
        conns.update();
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let table = conns.connections();
        let established: Vec<_> = table
            .iter()
            .filter(|c| c.state == "ESTABLISHED" && c.protocol.eq_ignore_ascii_case("tcp"))
            .collect();
        assert!(
            !established.is_empty(),
            "connection table produced no established TCP rows"
        );

        let hits = established
            .iter()
            .filter(|c| diag.contains_key(&(c.local_addr.clone(), c.remote_addr.clone())))
            .count();
        for c in established.iter().take(3) {
            println!(
                "table: {} → {}  netlink hit: {}",
                c.local_addr,
                c.remote_addr,
                diag.contains_key(&(c.local_addr.clone(), c.remote_addr.clone()))
            );
        }
        assert!(
            hits > 0,
            "not one of {} established rows matched a netlink flow key — the two \
             sides are spelling addresses differently",
            established.len()
        );
    }

    /// One `xtcpcb64` laid out the way the kernel exports it.
    fn xtcpcb64(state: i32, v4: bool, lport: u16, fport: u16) -> Vec<u8> {
        let mut r = vec![0u8; 472];
        let put = |r: &mut Vec<u8>, off: usize, v: u32| {
            r[off..off + 4].copy_from_slice(&v.to_ne_bytes());
        };
        put(&mut r, XT_LEN, 472);
        put(&mut r, XT_STATE, state as u32);
        r[INP_VFLAG] = if v4 { INP_IPV4 } else { 2 };
        r[INP_LPORT..INP_LPORT + 2].copy_from_slice(&lport.to_be_bytes());
        r[INP_FPORT..INP_FPORT + 2].copy_from_slice(&fport.to_be_bytes());
        if v4 {
            r[INP_LADDR + V4_IN_V6..INP_LADDR + 16].copy_from_slice(&[192, 168, 0, 202]);
            r[INP_FADDR + V4_IN_V6..INP_FADDR + 16].copy_from_slice(&[160, 79, 104, 10]);
        } else {
            let l = std::net::Ipv6Addr::LOCALHOST.octets();
            let f: [u8; 16] = "2606:4700::1111"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets();
            r[INP_LADDR..INP_LADDR + 16].copy_from_slice(&l);
            r[INP_FADDR..INP_FADDR + 16].copy_from_slice(&f);
        }
        put(&mut r, XT_SND_CWND, 16412);
        put(&mut r, XT_SND_SSTHRESH, BSD_SSTHRESH_UNSET);
        put(&mut r, XT_MAXSEG, 1388);
        put(&mut r, XT_SND_WND, 131072);
        put(&mut r, XT_RCV_WND, 131072);
        put(&mut r, XT_SRTT, 455);
        r
    }

    fn pcblist(records: &[Vec<u8>]) -> Vec<u8> {
        let mut b = vec![0u8; XIG_SIZE];
        b[0..4].copy_from_slice(&(XIG_SIZE as u32).to_ne_bytes());
        for r in records {
            b.extend_from_slice(r);
        }
        // The dump is closed by a trailing xinpgen.
        let mut tail = vec![0u8; XIG_SIZE];
        tail[0..4].copy_from_slice(&(XIG_SIZE as u32).to_ne_bytes());
        b.extend_from_slice(&tail);
        b
    }

    /// Values here are the ones a live dump actually produced on macOS 15
    /// (cwnd 16412 bytes over a 1388-byte MSS, srtt 455). The conversions are
    /// the point: Linux reports segments, BSD reports bytes, and the column
    /// has to mean the same thing on both.
    #[test]
    fn macos_dump_parses_and_normalises_units() {
        let buf = pcblist(&[xtcpcb64(TCPS_ESTABLISHED, true, 65100, 443)]);
        let map = parse_pcblist64(&buf);
        assert_eq!(map.len(), 1);
        let info = map
            .get(&(
                "192.168.0.202:65100".to_string(),
                "160.79.104.10:443".to_string(),
            ))
            .expect("flow key must be canonical addr:port");

        assert_eq!(
            info.cwnd,
            Some(16412 / 1388),
            "cwnd must convert to segments"
        );
        assert_eq!(info.mss, Some(1388));
        assert_eq!(info.rwnd, Some(131072), "the send window is already bytes");
        // 455 × 1000 / 32 = 14.2 ms, which is what the live connection measured.
        assert_eq!(info.rtt_us, Some(14_218));
        assert!(info.ssthresh_unset(), "BSD's sentinel must read as unset");
    }

    /// A sub-millisecond LAN RTT must survive the conversion. Shifting first
    /// and scaling after reported a flat zero for every local peer.
    #[test]
    fn macos_sub_millisecond_rtt_is_not_truncated_to_zero() {
        let mut r = xtcpcb64(TCPS_ESTABLISHED, true, 1, 2);
        r[XT_SRTT..XT_SRTT + 4].copy_from_slice(&10u32.to_ne_bytes());
        let map = parse_pcblist64(&pcblist(&[r]));
        let (_, info) = map.iter().next().unwrap();
        assert_eq!(info.rtt_us, Some(312), "10/32 ms is 312 µs, not 0");
    }

    #[test]
    fn macos_dump_keeps_only_established_flows() {
        let buf = pcblist(&[
            xtcpcb64(TCPS_ESTABLISHED, true, 1, 2),
            xtcpcb64(10, true, 3, 4), // TCPS_TIME_WAIT
            xtcpcb64(1, true, 5, 6),  // TCPS_LISTEN
        ]);
        assert_eq!(parse_pcblist64(&buf).len(), 1);
    }

    #[test]
    fn macos_dump_parses_v6_and_stops_at_the_trailer() {
        let buf = pcblist(&[xtcpcb64(TCPS_ESTABLISHED, false, 443, 443)]);
        let map = parse_pcblist64(&buf);
        assert!(
            map.contains_key(&("::1:443".to_string(), "2606:4700::1111:443".to_string())),
            "got {:?}",
            map.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn macos_malformed_dumps_do_not_loop_or_panic() {
        assert!(parse_pcblist64(&[]).is_empty());
        assert!(parse_pcblist64(&[0; 8]).is_empty());
        // A record claiming more bytes than the buffer holds.
        let mut lying = pcblist(&[xtcpcb64(TCPS_ESTABLISHED, true, 1, 2)]);
        lying[XIG_SIZE..XIG_SIZE + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(parse_pcblist64(&lying).is_empty());
        // A short record is skipped, not read past.
        let short = pcblist(&[vec![0u8; 16]]);
        assert!(parse_pcblist64(&short).is_empty());
    }

    /// The lookup key must survive every spelling the UI might hand it.
    #[test]
    fn endpoints_normalise_to_one_spelling() {
        assert_eq!(normalize_endpoint("1.2.3.4:443"), "1.2.3.4:443");
        assert_eq!(normalize_endpoint("[::1]:443"), "::1:443");
        // macOS lsof: closing bracket, no opening one.
        assert_eq!(normalize_endpoint("fe80::1]:1024"), "fe80::1:1024");
        // IPv4-mapped IPv6 must land on the same key as its IPv4 spelling.
        assert_eq!(
            normalize_endpoint("[::ffff:1.2.3.4]:443"),
            normalize_endpoint("1.2.3.4:443")
        );
        // Unparseable input still matches itself rather than vanishing.
        assert_eq!(normalize_endpoint("weird"), "weird");
    }

    /// Talks to the running kernel; `#[ignore]`d like its Linux twin.
    /// `cargo test --lib tcp_info -- --ignored --nocapture`
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore]
    fn live_dump_returns_plausible_kernel_state() {
        let map = collect().expect("pcblist64 sysctl failed");
        assert!(!map.is_empty(), "no established TCP flows found");
        for ((local, remote), info) in map.iter().take(5) {
            println!("{local} → {remote}: {info:?}");
        }
        let (_, info) = map.iter().next().unwrap();
        let mss = info.mss.expect("mss must be present");
        assert!(
            (88..=65535).contains(&mss),
            "mss {mss} is outside any plausible range — offsets are probably wrong"
        );
        let cwnd = info.cwnd.expect("cwnd must be present");
        assert!(
            (1..=100_000).contains(&cwnd),
            "cwnd {cwnd} is not a plausible segment count — is it still in bytes?"
        );
    }

    #[test]
    fn collector_returns_none_for_unknown_flows_on_every_platform() {
        let c = TcpInfoCollector::new();
        assert_eq!(c.get("1.2.3.4:1", "5.6.7.8:2"), None);
    }
}
