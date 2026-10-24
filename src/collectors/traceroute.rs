use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct TracerouteHop {
    pub hop_number: u8,
    pub host: Option<String>,
    pub ip: Option<String>,
    pub rtt_ms: Vec<Option<f64>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TracerouteStatus {
    Idle,
    Running,
    Done,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct TracerouteResult {
    pub completed: Option<std::time::Instant>,
    pub completed_at: String,
    pub target: String,
    pub status: TracerouteStatus,
    pub hops: Vec<TracerouteHop>,
    /// Whether the destination itself answered — a port-unreachable from the
    /// target on the Linux native path, an echo reply or the target's own
    /// unreachable on the Windows one, or a final hop matching the target
    /// address on the subprocess path. `None` when the trace cannot tell,
    /// which is the usual case for a firewalled tail.
    ///
    /// Diagnose needs this to decide whether silence after a lossy hop means
    /// "the loss propagates" or "we simply cannot see past it".
    pub reached: Option<bool>,
}

pub struct TracerouteRunner {
    cancel: Mutex<crate::diagnose::probe_io::Cancel>,
    pub result: Arc<Mutex<TracerouteResult>>,
}

impl Drop for TracerouteRunner {
    fn drop(&mut self) {
        self.cancel.lock().unwrap().cancel();
    }
}

impl Default for TracerouteRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl TracerouteRunner {
    pub fn new() -> Self {
        Self {
            cancel: Mutex::new(Default::default()),
            result: Arc::new(Mutex::new(TracerouteResult {
                reached: None,
                completed: None,
                completed_at: String::new(),
                target: String::new(),
                status: TracerouteStatus::Idle,
                hops: Vec::new(),
            })),
        }
    }

    pub fn run(&self, target: &str) {
        {
            let mut r = self.result.lock().unwrap();
            // Don't start if already running
            if r.status == TracerouteStatus::Running {
                return;
            }
            r.target = target.to_string();
            r.status = TracerouteStatus::Running;
            r.completed = None;
            r.hops.clear();
        }

        let cancel = crate::diagnose::probe_io::Cancel::default();
        *self.cancel.lock().unwrap() = cancel.clone();
        let result = Arc::clone(&self.result);
        let target = target.to_string();
        crate::sandbox::worker::spawn("traceroute", move || {
            let outcome = run_traceroute(&target, &cancel);
            let mut r = result.lock().unwrap();
            if cancel.cancelled() {
                return;
            }
            match outcome {
                Ok((hops, reached)) => {
                    r.hops = hops;
                    r.reached = reached;
                    r.status = TracerouteStatus::Done;
                    r.completed = Some(std::time::Instant::now());
                    r.completed_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                }
                Err(e) => {
                    r.status = TracerouteStatus::Error(e);
                }
            }
        });
    }

    pub fn clear(&self) {
        self.cancel.lock().unwrap().cancel();
        let mut r = self.result.lock().unwrap();
        r.target.clear();
        r.status = TracerouteStatus::Idle;
        r.completed = None;
        r.hops.clear();
        r.reached = None;
    }
}

type Trace = (Vec<TracerouteHop>, Option<bool>);

fn run_traceroute(
    target: &str,
    cancel: &crate::diagnose::probe_io::Cancel,
) -> Result<Trace, String> {
    // Prefer native UDP+TTL traceroute on Linux — works under the
    // sandbox because Landlock sets NO_NEW_PRIVS, which makes the
    // kernel ignore the setcap on /usr/bin/traceroute. The native
    // path uses IP_RECVERR (Linux-only) to receive ICMP Time Exceeded
    // / Port Unreachable from intermediate hops and the destination
    // respectively, with no capability requirement.
    //
    // macOS lacks IP_RECVERR / MSG_ERRQUEUE in its BSD sockets API,
    // so the subprocess path is preserved there (and macOS has no
    // sandbox today, so the setcap issue doesn't bite).
    #[cfg(target_os = "linux")]
    if let Some(trace) = run_traceroute_native(target, cancel) {
        return Ok(trace);
    }

    // Windows traces natively too, through the ICMP API, for both families.
    // tracert stays only for a target that is not an address or a host where
    // no ICMP handle can be opened.
    #[cfg(windows)]
    if let Some(trace) = run_traceroute_icmp(target, cancel) {
        return trace;
    }

    if cancel.cancelled() {
        return Err("traceroute cancelled".into());
    }
    run_traceroute_subprocess(target, cancel)
}

// Probes per hop, the hop limit and each probe's wait, the same on every
// path: `traceroute -q 3 -m 30 -w 1`, `tracert -h 30 -w 1000`.
const PROBES: usize = 3;
#[cfg(windows)]
const MAX_HOPS: u8 = 30;
#[cfg(windows)]
const PROBE_TIMEOUT_MS: u32 = 1000;

/// Echo requests with a rising TTL through `IcmpSendEcho2` and
/// `Icmp6SendEcho2`: each router where the TTL runs out answers with its
/// address, and an echo reply means the destination itself answered.
///
/// `None` sends the caller to the tracert fallback when the target is not an
/// address or no ICMP handle could be opened. It also means the trace was
/// cancelled, which the caller checks before falling back. `Some(Err)` is a
/// trace the stack refused to send at all.
#[cfg(windows)]
fn run_traceroute_icmp(
    target: &str,
    cancel: &crate::diagnose::probe_io::Cancel,
) -> Option<Result<Trace, String>> {
    use crate::platform::windows::icmp::IcmpHandle;

    let dst: std::net::IpAddr = target.parse().ok()?;
    let icmp = IcmpHandle::open(dst)?;
    let mut hops = Vec::new();
    for ttl in 1..=MAX_HOPS {
        let mut echoes = Vec::with_capacity(PROBES);
        for _ in 0..PROBES {
            if cancel.cancelled() {
                return None;
            }
            echoes.push(icmp.echo(ttl, PROBE_TIMEOUT_MS));
        }
        match icmp_hop(dst, ttl, &echoes) {
            IcmpHop::Unsendable(code) if hops.is_empty() => {
                return Some(Err(format!(
                    "could not send an echo request to {target} (status {code})"
                )));
            }
            // A stack that stops sending mid-trace will refuse every later
            // TTL too: keep what was traced, and say nothing about the
            // destination.
            IcmpHop::Unsendable(_) => return Some(Ok((hops, None))),
            IcmpHop::Hop(hop, end) => {
                hops.push(hop);
                if let Some(reached) = end {
                    return Some(Ok((hops, Some(reached))));
                }
            }
        }
    }
    // Out of hops without an echo reply, as on the Linux native path.
    Some(Ok((hops, Some(false))))
}

/// What one TTL's probes say on the native ICMP trace.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug)]
enum IcmpHop {
    /// A hop to record. `Some(reached)` ends the trace there: `true` when the
    /// destination answered, with an echo reply or an error of its own;
    /// `false` when a router on the path said it cannot be reached, after
    /// which every higher TTL hears the same.
    Hop(TracerouteHop, Option<bool>),
    /// Not one probe at this TTL left the host; carries the status.
    Unsendable(u32),
}

/// Decode one TTL's echoes to `dst` into the hop the UI and Diagnose read:
/// the first address that answered, and one RTT or `None` per probe.
///
/// An unreachable sent by `dst` itself still means the destination answered:
/// a host that rejects echo requests (iptables' default REJECT is a
/// port-unreachable, firewalld's icmp-block an admin-prohibited) is up, as a
/// port-unreachable from the target is on the Linux native path.
#[cfg_attr(not(windows), allow(dead_code))]
fn icmp_hop(dst: std::net::IpAddr, ttl: u8, echoes: &[crate::platform::icmp::Echo]) -> IcmpHop {
    use crate::platform::icmp::Echo;
    if let Some(Echo::Failed(code)) = echoes.first() {
        if echoes.iter().all(|e| !e.was_sent()) {
            return IcmpHop::Unsendable(*code);
        }
    }
    let from_dst = |from: Option<std::net::IpAddr>| {
        from.is_some_and(|ip| ip.to_canonical() == dst.to_canonical())
    };
    let end = if echoes.iter().any(|e| match *e {
        Echo::Reply { .. } => true,
        Echo::Unreachable { from, .. } => from_dst(from),
        _ => false,
    }) {
        Some(true)
    } else if echoes.iter().any(|e| matches!(e, Echo::Unreachable { .. })) {
        Some(false)
    } else {
        None
    };
    let hop = TracerouteHop {
        hop_number: ttl,
        host: None,
        ip: echoes
            .iter()
            .find_map(Echo::answered_by)
            .map(|ip| ip.to_string()),
        rtt_ms: echoes.iter().map(Echo::rtt_ms).collect(),
    };
    IcmpHop::Hop(hop, end)
}

#[cfg(target_os = "linux")]
fn run_traceroute_native(
    target: &str,
    cancel: &crate::diagnose::probe_io::Cancel,
) -> Option<Trace> {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use nix::sys::socket::{
        recvmsg, sendto, setsockopt, socket,
        sockopt::{Ipv4RecvErr, Ipv4Ttl},
        AddressFamily, ControlMessageOwned, MsgFlags, SockFlag, SockType, SockaddrIn,
    };
    use std::io::IoSliceMut;
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
    use std::os::fd::{AsFd, AsRawFd};
    use std::time::Instant;

    let dst_v4: Ipv4Addr = match target.parse::<IpAddr>().ok()? {
        IpAddr::V4(v) => v,
        // IPv6 path needs Ipv6RecvErr + a separate sockopt for hoplimit;
        // not implemented here. Falls back to the subprocess.
        IpAddr::V6(_) => return None,
    };

    // SOCK_DGRAM UDP needs no capabilities. We never bind — the kernel
    // assigns an ephemeral source port automatically.
    let sock = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .ok()?;

    // Kernel queues ICMP errors (Time Exceeded, Dest Unreach) with
    // the originating router's address in a SOCK_EXTENDED_ERR cmsg.
    // Critical: SO_RCVTIMEO does NOT apply to MSG_ERRQUEUE reads —
    // recvmsg returns EAGAIN immediately if the queue is empty. We
    // use poll(POLLERR) below to wait for the queue to become readable.
    setsockopt(&sock, Ipv4RecvErr, &true).ok()?;

    let fd = sock.as_raw_fd();

    const PROBES: usize = 3;
    const MAX_HOPS: u8 = 30;
    // Classic Van Jacobson traceroute base port: 33434. We bump by
    // hop_number * PROBES + probe so each datagram has a unique
    // destination port, matching the wire-level behaviour of `traceroute`.
    const BASE_PORT: u16 = 33434;

    let mut hops: Vec<TracerouteHop> = Vec::new();
    let mut target_reached = false;

    for ttl in 1..=MAX_HOPS {
        setsockopt(&sock, Ipv4Ttl, &(ttl as i32)).ok()?;

        let mut rtts: Vec<Option<f64>> = Vec::with_capacity(PROBES);
        let mut hop_ip: Option<String> = None;

        for probe in 0..PROBES {
            if cancel.cancelled() {
                return None;
            }
            let port = BASE_PORT
                .wrapping_add((ttl as u16).wrapping_mul(PROBES as u16))
                .wrapping_add(probe as u16);
            let dst: SockaddrIn = SocketAddrV4::new(dst_v4, port).into();
            let payload = [0u8; 32];

            let send_t = Instant::now();
            if sendto(fd, &payload, &dst, MsgFlags::empty()).is_err() {
                rtts.push(None);
                continue;
            }

            // Wait up to 1 s for the kernel to queue an ICMP error
            // on this socket. `MSG_ERRQUEUE` reads are not affected
            // by SO_RCVTIMEO and would return EAGAIN immediately if
            // we called recvmsg directly, so we gate the read on
            // poll(POLLERR) instead.
            let pfd = PollFd::new(sock.as_fd(), PollFlags::POLLERR);
            let mut fds = [pfd];
            let ready = match poll(
                &mut fds,
                PollTimeout::try_from(1000i32).unwrap_or(PollTimeout::NONE),
            ) {
                Ok(n) => n > 0,
                Err(_) => false,
            };
            if !ready {
                rtts.push(None);
                continue;
            }

            // Read the error queue. The cmsg carries
            // (sock_extended_err, sockaddr_in) where sockaddr_in is the
            // address of the router that sent the ICMP error.
            let mut cmsg_buf =
                nix::cmsg_space!(nix::libc::sock_extended_err, nix::libc::sockaddr_in);
            let mut data = [0u8; 128];
            let mut iov = [IoSliceMut::new(&mut data)];

            match recvmsg::<SockaddrIn>(
                fd,
                &mut iov,
                Some(&mut cmsg_buf),
                MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(msg) => {
                    let rtt_ms = send_t.elapsed().as_secs_f64() * 1000.0;
                    let mut got_useful = false;
                    for cmsg in msg.cmsgs().ok()? {
                        if let ControlMessageOwned::Ipv4RecvErr(err, src) = cmsg {
                            // Only count ICMP-origin errors. SO_EE_ORIGIN_ICMP = 2.
                            if err.ee_origin != 2 {
                                continue;
                            }
                            if let Some(addr) = src {
                                let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                                hop_ip.get_or_insert_with(|| ip.to_string());
                            }
                            // ee_type 11 = ICMP_TIME_EXCEEDED (intermediate hop).
                            // ee_type 3  = ICMP_DEST_UNREACH; code 3 = port unreachable
                            //   (we reached the target — its UDP port is closed).
                            if err.ee_type == 11 || (err.ee_type == 3 && err.ee_code == 3) {
                                got_useful = true;
                            }
                            if err.ee_type == 3 && err.ee_code == 3 {
                                target_reached = true;
                            }
                        }
                    }
                    rtts.push(if got_useful { Some(rtt_ms) } else { None });
                }
                Err(_) => {
                    // EAGAIN / EWOULDBLOCK: hop timed out → `*`.
                    rtts.push(None);
                }
            }
        }

        hops.push(TracerouteHop {
            hop_number: ttl,
            host: None,
            ip: hop_ip,
            rtt_ms: rtts,
        });

        if target_reached {
            break;
        }
    }

    // The native path knows this for certain: a port-unreachable can only have
    // come from the destination. Without one we ran out of hops instead, which
    // is not the same as the destination being down.
    Some((hops, Some(target_reached)))
}

/// Subprocess fallback for macOS and FreeBSD, for IPv6 targets on Linux
/// (the Linux native path is IPv4-only today), and on Windows only for a
/// target that is not an address or a host with no ICMP handle. Under the
/// v0.17.x+ Linux sandbox this path is broken because Landlock sets
/// NO_NEW_PRIVS and the setcap on /usr/bin/traceroute is ignored on exec —
/// the native path above is what makes traceroute work under sandbox.
fn run_traceroute_subprocess(
    target: &str,
    cancel: &crate::diagnose::probe_io::Cancel,
) -> Result<Trace, String> {
    #[cfg(target_os = "windows")]
    let (binary, args) = ("tracert", vec!["-d", "-w", "1000", "-h", "30", target]);
    #[cfg(not(target_os = "windows"))]
    let (binary, args) = (
        "traceroute",
        vec!["-n", "-q", "3", "-w", "1", "-m", "30", target],
    );
    let (ok, text) = run_subprocess(binary, &args, cancel).map_err(|e| spawn_error(binary, e))?;
    if !ok {
        return Err(text.trim().to_string());
    }
    let hops = parse_traceroute_output(&text);
    let reached = destination_answered(target, &hops);
    Ok((hops, reached))
}

/// Run the trace binary: bounded and cancellable through probe_io on Unix.
#[cfg(unix)]
fn run_subprocess(
    binary: &str,
    args: &[&str],
    cancel: &crate::diagnose::probe_io::Cancel,
) -> std::io::Result<(bool, String)> {
    crate::diagnose::probe_io::command(binary, args, std::time::Duration::from_secs(95), cancel)
}

/// probe_io's bounded runner is Unix-only and refuses to start anything
/// elsewhere, which left Windows with no trace at all. tracert bounds itself
/// (`-h 30 -w 1000` is about 90 seconds at worst), and the runner discards
/// a cancelled trace's result, so waiting on it is enough here.
#[cfg(not(unix))]
fn run_subprocess(
    binary: &str,
    args: &[&str],
    _cancel: &crate::diagnose::probe_io::Cancel,
) -> std::io::Result<(bool, String)> {
    let out = std::process::Command::new(binary).args(args).output()?;
    // tracert writes in the console's OEM code page, so Cyrillic or umlauts
    // arrive as replacement characters. The parser reads only digits,
    // addresses and `*`, which every code page writes as ASCII.
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text))
}

/// Did the destination itself answer the subprocess trace?
///
/// `traceroute -n` prints the target's own address as the last hop when it
/// replies. Anything else — a silent tail, a different final address, a target
/// we cannot parse as an address — is unknown rather than a "no": the
/// destination may simply be filtering the probes traceroute uses.
fn destination_answered(target: &str, hops: &[TracerouteHop]) -> Option<bool> {
    let target_ip: std::net::IpAddr = target.parse().ok()?;
    let last = hops.last()?;
    let ip = last.ip.as_deref()?;
    let ip: std::net::IpAddr = ip.parse().ok()?;
    if ip.to_canonical() == target_ip.to_canonical() {
        Some(true)
    } else {
        None
    }
}

/// Format a `Command::output()` failure with an install hint when the
/// binary isn't on PATH. The generic `std::io::Error` Display for
/// `NotFound` is `"No such file or directory"` which doesn't help users
/// figure out what to install — substitute the package name explicitly.
fn spawn_error(binary: &str, err: std::io::Error) -> String {
    if err.kind() == std::io::ErrorKind::NotFound {
        let hint = match binary {
            "traceroute" => "install with `sudo apt install traceroute` (Debian/Ubuntu), `sudo dnf install traceroute` (Fedora), or `brew install traceroute` (macOS)",
            "tracert" => "tracert ships with Windows; PATH or %SystemRoot%\\System32 may be misconfigured",
            _ => "binary not found on PATH",
        };
        format!("`{binary}` not installed — {hint}")
    } else {
        format!("Failed to run {binary}: {err}")
    }
}

/// Parse `traceroute -n` or `tracert -d` output into hops.
///
/// The two print the same facts in a different order. traceroute puts the
/// address first and an RTT per probe after it (" 1  192.0.2.1  1.234 ms  *
/// 1.789 ms"); tracert prints three probe columns, then the address, then
/// nothing but text ("  3     *        *        *     Request timed out.",
/// or the same in German or Russian). So the parser reads tokens, not
/// positions: `*` is a probe with no answer, a number (or tracert's `<1`) is
/// an RTT, and the hop's address is the first token that parses as an IP
/// address. Every other word is a unit, an annotation or commentary, in
/// whatever language, and is skipped.
fn parse_traceroute_output(output: &str) -> Vec<TracerouteHop> {
    let mut hops = Vec::new();

    for line in output.lines() {
        let mut tokens = line.split_whitespace();
        // Header and footer lines ("traceroute to ...", "Tracing route to
        // ...", "Trace complete.") do not start with a hop number. tracert's
        // send failures do ("  1  Transmit error: code 1231."), and leave no
        // hop because parse_rtt does not take the code for an RTT.
        let Some(hop_number) = tokens.next().and_then(|t| t.parse::<u8>().ok()) else {
            continue;
        };

        let mut ip: Option<String> = None;
        let mut host: Option<String> = None;
        let mut rtts: Vec<Option<f64>> = Vec::new();
        // The last word that was neither a probe nor an address: the name
        // in "name (addr)" or tracert's "name [addr]".
        let mut word: Option<&str> = None;

        for tok in tokens {
            if tok == "*" {
                rtts.push(None);
            } else if let Some(ms) = parse_rtt(tok) {
                rtts.push(Some(ms));
            } else if let Some(addr) = parse_hop_addr(tok) {
                if ip.is_none() {
                    ip = Some(addr.to_string());
                    if tok.starts_with(['(', '[']) {
                        host = word.map(str::to_string);
                    }
                }
                // tracert's address follows all three probe columns and only
                // text follows it, which must not be read as an RTT.
                if rtts.len() >= PROBES {
                    break;
                }
            } else {
                word = Some(tok);
                continue;
            }
            word = None;
        }

        if rtts.is_empty() && ip.is_none() {
            continue;
        }
        hops.push(TracerouteHop {
            hop_number,
            host,
            ip,
            rtt_ms: rtts,
        });
    }

    hops
}

/// One probe column in milliseconds: `1.234` from traceroute, whose unit is
/// the next token, `12` or `<1` from tracert, or either with a unit attached
/// (`12ms`).
///
/// tracert's `<N` means under N ms. It stands as half of N, so a
/// sub-millisecond hop reads as sub-millisecond, as it does on the native
/// paths, rather than as 0 or as a full millisecond.
///
/// A number that ends a sentence is not a probe column: tracert's "Transmit
/// error: code 1231." would otherwise read as a 1231 ms answer.
fn parse_rtt(tok: &str) -> Option<f64> {
    let (under, num) = match tok.strip_prefix('<') {
        Some(rest) => (true, rest),
        None => (false, tok),
    };
    let num = num.trim_end_matches(char::is_alphabetic);
    if !num.starts_with(|c: char| c.is_ascii_digit()) || num.ends_with('.') {
        return None;
    }
    let ms: f64 = num.parse().ok()?;
    if !ms.is_finite() {
        return None;
    }
    Some(if under { ms / 2.0 } else { ms })
}

/// A hop address, bare or in the brackets traceroute and tracert put round
/// it after a name. A link-local IPv6 hop may carry a zone (`fe80::1%12`),
/// which is dropped.
fn parse_hop_addr(tok: &str) -> Option<std::net::IpAddr> {
    let bare = tok
        .trim_start_matches(['(', '['])
        .trim_end_matches([')', ']', ',']);
    let bare = bare.split('%').next().unwrap_or(bare);
    bare.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_traceroute_basic() {
        let output = "\
traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  192.168.1.1  1.234 ms  1.456 ms  1.789 ms
 2  10.0.0.1  5.123 ms  5.456 ms  5.789 ms
 3  * * *
 4  8.8.8.8  12.345 ms  12.456 ms  12.789 ms
";
        let hops = parse_traceroute_output(output);
        assert_eq!(hops.len(), 4);
        assert_eq!(hops[0].hop_number, 1);
        assert_eq!(hops[0].ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(hops[2].ip, None);
        assert!(hops[2].rtt_ms.iter().all(|r| r.is_none()));
        assert_eq!(hops[3].ip.as_deref(), Some("8.8.8.8"));
    }

    #[test]
    fn test_parse_traceroute_partial_stars() {
        let output = "\
traceroute to 1.1.1.1 (1.1.1.1), 30 hops max
 1  192.168.1.1  1.0 ms  *  1.5 ms
";
        let hops = parse_traceroute_output(output);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].rtt_ms.len(), 3);
        assert!(hops[0].rtt_ms[0].is_some());
        assert!(hops[0].rtt_ms[1].is_none());
        assert!(hops[0].rtt_ms[2].is_some());
    }

    // ── tracert ────────────────────────────────────────────────────────

    type HopSummary = (u8, Option<String>, Vec<Option<f64>>);

    fn summary(hops: &[TracerouteHop]) -> Vec<HopSummary> {
        hops.iter()
            .map(|h| (h.hop_number, h.ip.clone(), h.rtt_ms.clone()))
            .collect()
    }

    /// The trace every tracert fixture below prints, in its own language.
    fn expected_tracert() -> Vec<HopSummary> {
        let ip = |s: &str| Some(s.to_string());
        vec![
            (1, ip("192.168.1.1"), vec![Some(0.5); 3]),
            (2, ip("10.0.0.1"), vec![Some(8.0), Some(7.0), Some(9.0)]),
            (3, None, vec![None; 3]),
            (4, ip("100.64.0.1"), vec![None, Some(14.0), Some(13.0)]),
            (5, ip("8.8.8.8"), vec![Some(12.0), Some(11.0), Some(12.0)]),
        ]
    }

    /// `tracert -d -w 1000 -h 30 8.8.8.8` on an English install, with the
    /// CRLF line ends Windows writes.
    const TRACERT_EN: &str = "\r\n\
Tracing route to 8.8.8.8 over a maximum of 30 hops\r\n\
\r\n\
  1    <1 ms    <1 ms    <1 ms  192.168.1.1\r\n\
  2     8 ms     7 ms     9 ms  10.0.0.1\r\n\
  3     *        *        *     Request timed out.\r\n\
  4     *       14 ms    13 ms  100.64.0.1\r\n\
  5    12 ms    11 ms    12 ms  8.8.8.8\r\n\
\r\n\
Trace complete.\r\n";

    const TRACERT_DE: &str = "
Routenverfolgung zu 8.8.8.8 über maximal 30 Abschnitte

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     8 ms     7 ms     9 ms  10.0.0.1
  3     *        *        *     Zeitüberschreitung der Anforderung.
  4     *       14 ms    13 ms  100.64.0.1
  5    12 ms    11 ms    12 ms  8.8.8.8

Ablaufverfolgung beendet.
";

    /// Russian tracert also translates the unit: `мс`, not `ms`.
    const TRACERT_RU: &str = "
Трассировка маршрута к 8.8.8.8 с максимальным числом прыжков 30

  1    <1 мс    <1 мс    <1 мс  192.168.1.1
  2     8 мс     7 мс     9 мс  10.0.0.1
  3     *        *        *     Превышен интервал ожидания для запроса.
  4     *       14 мс    13 мс  100.64.0.1
  5    12 мс    11 мс    12 мс  8.8.8.8

Трассировка завершена.
";

    #[test]
    fn tracert_reads_the_same_in_every_language() {
        for (lang, text) in [("en", TRACERT_EN), ("de", TRACERT_DE), ("ru", TRACERT_RU)] {
            let hops = parse_traceroute_output(text);
            assert_eq!(summary(&hops), expected_tracert(), "{lang}");
            assert!(
                hops.iter().all(|h| h.host.is_none()),
                "{lang}: no names with -d"
            );
            assert_eq!(destination_answered("8.8.8.8", &hops), Some(true), "{lang}");
        }
    }

    #[test]
    fn tracert_in_the_console_code_page_still_parses() {
        // tracert writes CP866 on a Russian console; decoded as UTF-8 every
        // Cyrillic letter, the unit included, is a replacement character.
        let mangled: String = TRACERT_RU
            .chars()
            .map(|c| if c.is_ascii() { c } else { '\u{FFFD}' })
            .collect();
        assert_eq!(
            summary(&parse_traceroute_output(&mangled)),
            expected_tracert()
        );
    }

    #[test]
    fn a_timed_out_hop_has_no_address() {
        // The old parser stored "out." from "Request timed out." as the IP.
        let hops = parse_traceroute_output("  3     *        *        *     Request timed out.");
        assert_eq!(hops[0].ip, None);
        assert_eq!(hops[0].rtt_ms, vec![None; 3]);
    }

    #[test]
    fn a_send_failure_is_not_a_hop() {
        // tracert numbers the hop it could not send, then prints the error.
        for line in [
            "  1  Transmit error: code 1231.",
            "  1  Übertragungsfehler: Code 1231.",
            "  1     General failure.",
        ] {
            assert!(parse_traceroute_output(line).is_empty(), "{line}");
        }
    }

    #[test]
    fn a_reporting_hop_keeps_its_address_and_ignores_the_report() {
        let hops = parse_traceroute_output(
            "  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2  192.168.1.1  reports: Destination net unreachable.
  3    10 ms     9 ms    10 ms  198.51.100.1  reports 3 hops of trouble",
        );
        assert_eq!(hops[1].ip.as_deref(), Some("192.168.1.1"));
        assert!(hops[1].rtt_ms.is_empty());
        // Commentary after tracert's address is never an RTT, numbers or not.
        assert_eq!(hops[2].rtt_ms, vec![Some(10.0), Some(9.0), Some(10.0)]);
    }

    #[test]
    fn tracert_over_ipv6_and_with_names() {
        let hops = parse_traceroute_output(
            "  1    <1 ms    <1 ms    <1 ms  fe80::1%12
  2     9 ms     8 ms     9 ms  2001:db8:1::a
  3    <1 ms    <1 ms    <1 ms  fritz.box [192.168.178.1]",
        );
        assert_eq!(hops[0].ip.as_deref(), Some("fe80::1"));
        assert_eq!(hops[1].ip.as_deref(), Some("2001:db8:1::a"));
        assert_eq!(hops[1].rtt_ms, vec![Some(9.0), Some(8.0), Some(9.0)]);
        assert_eq!(hops[2].ip.as_deref(), Some("192.168.178.1"));
        assert_eq!(hops[2].host.as_deref(), Some("fritz.box"));
    }

    #[test]
    fn traceroute_names_and_late_first_replies() {
        let hops = parse_traceroute_output(
            " 1  router.lan (192.168.1.1)  1.234 ms  1.456 ms  1.789 ms
 2  * 10.0.0.1  5.1 ms  5.3 ms
 3  10.0.0.9  7.0 ms !H  10.0.0.10  7.5 ms  7.9 ms",
        );
        assert_eq!(hops[0].host.as_deref(), Some("router.lan"));
        assert_eq!(hops[0].ip.as_deref(), Some("192.168.1.1"));
        // traceroute prints the address when the first answer arrives, so
        // RTTs can come both before and after it.
        assert_eq!(hops[1].rtt_ms, vec![None, Some(5.1), Some(5.3)]);
        assert_eq!(hops[1].ip.as_deref(), Some("10.0.0.1"));
        // A second responder on the same hop keeps the first address.
        assert_eq!(hops[2].ip.as_deref(), Some("10.0.0.9"));
        assert_eq!(hops[2].rtt_ms, vec![Some(7.0), Some(7.5), Some(7.9)]);
    }

    #[test]
    fn rtt_tokens() {
        assert_eq!(parse_rtt("1.234"), Some(1.234));
        assert_eq!(parse_rtt("12"), Some(12.0));
        assert_eq!(
            parse_rtt("<1"),
            Some(0.5),
            "under 1 ms stands as half of it"
        );
        assert_eq!(parse_rtt("12ms"), Some(12.0));
        assert_eq!(parse_rtt("<1мс"), Some(0.5));
        for not_rtt in [
            "ms",
            "мс",
            "*",
            "out.",
            "1231.",
            "inf",
            "NaN",
            "!H",
            "192.0.2.1",
            "<",
            "",
        ] {
            assert_eq!(parse_rtt(not_rtt), None, "{not_rtt:?}");
        }
    }

    #[test]
    fn hop_addresses_only_from_tokens_that_are_addresses() {
        for (tok, want) in [
            ("192.0.2.1", Some("192.0.2.1")),
            ("(192.0.2.1)", Some("192.0.2.1")),
            ("[192.0.2.1]", Some("192.0.2.1")),
            ("[2001:db8::1]", Some("2001:db8::1")),
            ("fe80::1%12", Some("fe80::1")),
            ("out.", None),
            ("router.lan", None),
            ("reports:", None),
            ("1.234", None),
        ] {
            assert_eq!(
                parse_hop_addr(tok).map(|ip| ip.to_string()).as_deref(),
                want,
                "{tok}"
            );
        }
    }

    // ── native ICMP trace (decoded everywhere) ─────────────────────────

    mod icmp {
        use super::super::*;
        use crate::platform::icmp::Echo;
        use std::net::IpAddr;

        const ROUTER: &str = "198.51.100.7";
        const TARGET: &str = "192.0.2.1";

        fn ip(s: &str) -> IpAddr {
            s.parse().unwrap()
        }

        fn hop(echoes: &[Echo]) -> (TracerouteHop, Option<bool>) {
            match icmp_hop(ip(TARGET), 4, echoes) {
                IcmpHop::Hop(hop, end) => (hop, end),
                other => panic!("expected a hop, got {other:?}"),
            }
        }

        #[test]
        fn a_router_hop_carries_its_address_and_goes_on() {
            let exceeded = |rtt_ms| Echo::TimeExceeded {
                from: Some(ip(ROUTER)),
                rtt_ms,
            };
            let (h, end) = hop(&[exceeded(3.0), Echo::TimedOut, exceeded(0.4)]);
            assert_eq!(h.hop_number, 4);
            assert_eq!(h.ip.as_deref(), Some(ROUTER));
            assert_eq!(h.host, None);
            assert_eq!(h.rtt_ms, vec![Some(3.0), None, Some(0.4)]);
            assert_eq!(end, None);
        }

        #[test]
        fn a_silent_hop_is_three_stars() {
            let (h, end) = hop(&[Echo::TimedOut; 3]);
            assert_eq!(h.ip, None);
            assert_eq!(h.rtt_ms, vec![None; 3]);
            assert_eq!(end, None);
        }

        #[test]
        fn an_echo_reply_reaches_the_destination() {
            let reply = Echo::Reply {
                from: ip(TARGET),
                rtt_ms: 12.0,
            };
            let (h, end) = hop(&[Echo::TimedOut, reply, reply]);
            assert_eq!(h.ip.as_deref(), Some(TARGET));
            assert_eq!(h.rtt_ms, vec![None, Some(12.0), Some(12.0)]);
            assert_eq!(end, Some(true));
        }

        #[test]
        fn an_unreachable_ends_the_trace_short_of_the_destination() {
            let unreachable = Echo::Unreachable {
                from: Some(ip(ROUTER)),
                rtt_ms: 9.0,
            };
            let (h, end) = hop(&[unreachable; 3]);
            assert_eq!(h.ip.as_deref(), Some(ROUTER));
            assert_eq!(h.rtt_ms, vec![Some(9.0); 3], "it answered");
            assert_eq!(end, Some(false));
        }

        /// A target that rejects echo requests (iptables REJECT, a firewalld
        /// icmp-block) answers them with an unreachable of its own: it was
        /// reached, as a port-unreachable from the target is on Linux.
        #[test]
        fn an_unreachable_from_the_destination_reaches_it() {
            let rejected = Echo::Unreachable {
                from: Some(ip(TARGET)),
                rtt_ms: 14.0,
            };
            let (h, end) = hop(&[Echo::TimedOut, rejected, rejected]);
            assert_eq!(h.ip.as_deref(), Some(TARGET));
            assert_eq!(h.rtt_ms, vec![None, Some(14.0), Some(14.0)]);
            assert_eq!(end, Some(true));
            // The same target written as a v4-mapped IPv6 address.
            let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
            assert!(matches!(
                icmp_hop(mapped, 4, &[rejected; 3]),
                IcmpHop::Hop(_, Some(true))
            ));
        }

        #[test]
        fn a_hop_the_stack_would_not_send_is_not_silence() {
            assert!(matches!(
                icmp_hop(ip(TARGET), 1, &[Echo::Failed(11050); 3]),
                IcmpHop::Unsendable(11050)
            ));
            // One probe out of three left: that is a hop, with stars.
            let (h, _) = hop(&[Echo::Failed(11050), Echo::TimedOut, Echo::Failed(11050)]);
            assert_eq!(h.rtt_ms, vec![None; 3]);
        }

        /// The whole native trace on Windows. CI's runners reach loopback,
        /// which answers the first TTL with an echo reply.
        #[cfg(windows)]
        #[test]
        fn windows_traces_loopback_natively() {
            for target in ["127.0.0.1", "::1"] {
                let (hops, reached) = run_traceroute_icmp(target, &Default::default())
                    .expect("an ICMP handle opens")
                    .expect("the trace runs");
                assert_eq!(reached, Some(true), "{target}");
                assert_eq!(hops.len(), 1, "{target}: {hops:?}");
                assert_eq!(hops[0].ip.as_deref(), Some(target));
                assert_eq!(hops[0].rtt_ms.len(), PROBES);
                assert!(hops[0].rtt_ms.iter().all(|r| r.is_some_and(|ms| ms > 0.0)));
            }
            // Not an address: the tracert fallback's to resolve.
            assert!(run_traceroute_icmp("localhost", &Default::default()).is_none());
            // A cancelled trace sends nothing more.
            let cancel = crate::diagnose::probe_io::Cancel::default();
            cancel.cancel();
            assert!(run_traceroute_icmp("127.0.0.1", &cancel).is_none());
        }
    }
}
