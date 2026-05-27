use crate::app::{safe_read, safe_write};
use std::collections::VecDeque;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;

const RTT_HISTORY_MAX: usize = 60;

#[derive(Clone)]
pub struct HealthStatus {
    pub gateway_rtt_ms: Option<f64>,
    pub gateway_loss_pct: f64,
    pub dns_rtt_ms: Option<f64>,
    pub dns_loss_pct: f64,
    pub gateway_rtt_history: VecDeque<Option<f64>>,
    pub dns_rtt_history: VecDeque<Option<f64>>,
}

pub struct HealthProber {
    /// Latest probe results, shared via the `Arc<RwLock<Arc<…>>>` snapshot
    /// pattern (see [`crate::collectors::traffic::TrafficCollector`] for the
    /// canonical example). Readers clone the inner `Arc` in O(1); the probe
    /// thread builds a new `HealthStatus` and swaps it in via a brief write
    /// lock so renders never block on an in-flight ping.
    snapshot: Arc<RwLock<Arc<HealthStatus>>>,
    busy: Arc<AtomicBool>,
}

impl Default for HealthProber {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthProber {
    pub fn new() -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(Arc::new(HealthStatus {
                gateway_rtt_ms: None,
                gateway_loss_pct: 100.0,
                dns_rtt_ms: None,
                dns_loss_pct: 100.0,
                gateway_rtt_history: VecDeque::new(),
                dns_rtt_history: VecDeque::new(),
            }))),
            busy: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Cheap snapshot of the most recent probe results. Single atomic
    /// refcount bump regardless of history depth.
    pub fn status(&self) -> Arc<HealthStatus> {
        Arc::clone(&safe_read(&self.snapshot, "health::status"))
    }

    pub fn probe(&self, gateway: Option<&str>, dns_server: Option<&str>) {
        if self.busy.load(Ordering::SeqCst) {
            return;
        }
        self.busy.store(true, Ordering::SeqCst);
        let busy = Arc::clone(&self.busy);
        let snapshot = Arc::clone(&self.snapshot);
        let gw = gateway.map(|s| s.to_string());
        let dns = dns_server.map(|s| s.to_string());
        thread::spawn(move || {
            // Each probe block builds a new HealthStatus off the latest
            // published snapshot, then swaps it in. The deep-clone is cheap:
            // `HealthStatus` contains at most ~60 history entries per series.
            if let Some(gw) = gw.as_deref() {
                let (rtt, loss) = run_gateway_probe(gw);
                let mut next = (**safe_read(&snapshot, "health::probe::read_gw")).clone();
                next.gateway_rtt_ms = rtt;
                next.gateway_loss_pct = loss;
                next.gateway_rtt_history.push_back(rtt);
                if next.gateway_rtt_history.len() > RTT_HISTORY_MAX {
                    next.gateway_rtt_history.pop_front();
                }
                next.gateway_rtt_history.make_contiguous();
                *safe_write(&snapshot, "health::probe::publish_gw") = Arc::new(next);
            }
            if let Some(dns) = dns.as_deref() {
                // Send a real DNS query rather than ICMP. ICMP-pinging the
                // DNS server is a misleading health signal — plenty of
                // resolvers (cloud LBs, internal CoreDNS, hardened routers)
                // drop ICMP echo while happily answering DNS. It also fails
                // on Linux hosts where `net.ipv4.ping_group_range = 1 0`
                // and the sandbox has dropped CAP_NET_RAW, even though UDP
                // queries to port 53 work fine.
                let (rtt, loss) = run_dns_query(dns);
                let mut next = (**safe_read(&snapshot, "health::probe::read_dns")).clone();
                next.dns_rtt_ms = rtt;
                next.dns_loss_pct = loss;
                next.dns_rtt_history.push_back(rtt);
                if next.dns_rtt_history.len() > RTT_HISTORY_MAX {
                    next.dns_rtt_history.pop_front();
                }
                next.dns_rtt_history.make_contiguous();
                *safe_write(&snapshot, "health::probe::publish_dns") = Arc::new(next);
            }
            busy.store(false, Ordering::SeqCst);
        });
    }
}

/// Gateway probe: try ICMP first (works in the normal case), fall back to
/// TCP-connect if ICMP comes back at 100% loss.
///
/// Why the fallback: on Linux hosts with `net.ipv4.ping_group_range = 1 0`
/// the kernel refuses unprivileged SOCK_DGRAM ICMP outright. Combined with
/// the sandbox dropping CAP_NET_RAW and Landlock setting NO_NEW_PRIVS
/// (which makes `/usr/bin/ping`'s file-cap get ignored on exec), every
/// ICMP path is blocked and the Gateway card sits at 100% loss even when
/// the router is up. A 1-RTT TCP connect to a port the router is almost
/// certain to be listening on (admin UI on 80/443, DNS forwarder on 53)
/// answers the same question — is the gateway responsive? — without any
/// privileges. `ConnectionRefused` counts as success because the host
/// returned a RST, which proves it's up.
///
/// We only fall back when ICMP returns 100% loss; partial ICMP success
/// (e.g. 1/3 probes) is a real signal we should preserve. This also means
/// the extra TCP work only runs on hosts that actually need it.
fn run_gateway_probe(target: &str) -> (Option<f64>, f64) {
    let (rtt, loss) = run_ping(target);
    if loss < 100.0 {
        return (rtt, loss);
    }
    // ICMP completely failed — could be sandbox/kernel restrictions,
    // could be a genuinely-firewalled host. Try TCP.
    run_tcp_probe(target)
}

/// TCP-connect probe used as the gateway-ICMP fallback. Walks a small list
/// of ports that home/SOHO routers almost always have something listening
/// on, returning the first port that gets *any* response (3WHS success or
/// RST). The "probes per port" loop matches the ICMP path's 3-probe
/// averaging so the RTT history widget gets comparable numbers.
fn run_tcp_probe(target: &str) -> (Option<f64>, f64) {
    use std::net::IpAddr;

    let addr: IpAddr = match target.parse() {
        Ok(a) => a,
        Err(_) => return (None, 100.0),
    };

    // 80 / 443 / 53 covers ≥95% of home + SOHO gateways. Ordered by how
    // commonly each is exposed on the gateway interface itself: most
    // routers serve the admin UI on 80 (or redirect to 443) and many
    // forward DNS on 53. We stop on the first port that yields a non-
    // 100%-loss result so the steady-state cost is one port × 3 probes.
    const PORTS: &[u16] = &[80, 443, 53];
    for &port in PORTS {
        let (rtt, loss) = run_tcp_probe_port(addr, port);
        if loss < 100.0 {
            return (rtt, loss);
        }
    }
    (None, 100.0)
}

fn run_tcp_probe_port(addr: std::net::IpAddr, port: u16) -> (Option<f64>, f64) {
    use std::net::{SocketAddr, TcpStream};
    use std::time::{Duration, Instant};

    const PROBES: usize = 3;
    let dest = SocketAddr::new(addr, port);
    let mut rtts = Vec::with_capacity(PROBES);

    for _ in 0..PROBES {
        let send_t = Instant::now();
        match TcpStream::connect_timeout(&dest, Duration::from_secs(1)) {
            Ok(_) => {
                // 3-way handshake completed — host is alive and the port
                // is open. Drop the stream immediately; we don't want to
                // hold connections to the gateway.
                rtts.push(send_t.elapsed().as_secs_f64() * 1000.0);
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                // RST received — host is alive but the port is closed.
                // For "is the gateway up?" this is just as good as a
                // successful connect.
                rtts.push(send_t.elapsed().as_secs_f64() * 1000.0);
            }
            // TimedOut / NetworkUnreachable / HostUnreachable / etc. all
            // count as loss — silent or routing-level rejection.
            Err(_) => {}
        }
    }

    let avg = if rtts.is_empty() {
        None
    } else {
        Some(rtts.iter().sum::<f64>() / rtts.len() as f64)
    };
    let loss = (PROBES - rtts.len()) as f64 / PROBES as f64 * 100.0;
    (avg, loss)
}

/// Probe a DNS server by sending a real DNS query over UDP/53 and timing
/// the response. Returns the same `(avg_rtt_ms, loss_pct)` shape as
/// [`run_ping`] so the Health widget consumes both the same way.
///
/// Why a DNS query instead of ICMP:
/// - Many resolvers don't respond to ICMP echo (cloud LBs, hardened
///   routers) but happily answer DNS — ICMP loss has no correlation with
///   DNS health for those targets.
/// - Linux with `net.ipv4.ping_group_range = 1 0` blocks unprivileged
///   SOCK_DGRAM ICMP. Combined with netwatch's sandbox dropping
///   CAP_NET_RAW and Landlock setting NO_NEW_PRIVS (which makes the
///   kernel ignore the file-cap on `/usr/bin/ping`), ICMP probes are
///   silently impossible for some users. UDP/53 is unprivileged.
/// - It tests the thing that actually matters — DNS resolution — rather
///   than a proxy for it.
fn run_dns_query(server: &str) -> (Option<f64>, f64) {
    use std::net::{IpAddr, SocketAddr, UdpSocket};
    use std::time::{Duration, Instant};

    // `IpAddr::parse` rejects IPv6 zone identifiers (e.g. `fe80::1%en0`),
    // which means `primary_dns()` should already have skipped link-local
    // entries upstream. If it didn't (only link-local servers configured),
    // we report 100% loss rather than panic — same as the old ICMP path.
    let addr: IpAddr = match server.parse() {
        Ok(a) => a,
        Err(_) => return (None, 100.0),
    };

    let bind_addr = match addr {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let sock = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(_) => return (None, 100.0),
    };
    if sock.set_read_timeout(Some(Duration::from_secs(1))).is_err() {
        return (None, 100.0);
    }
    let dest = SocketAddr::new(addr, 53);

    const PROBES: usize = 3;
    let mut rtts = Vec::with_capacity(PROBES);

    for seq in 0..PROBES as u16 {
        // Per-probe IDs let us reject stale replies from earlier probes
        // landing late inside the same socket's recv buffer.
        let id = 0xa6b4u16.wrapping_add(seq);
        let query = build_dns_query(id);

        let send_t = Instant::now();
        if sock.send_to(&query, dest).is_err() {
            continue;
        }

        let mut buf = [0u8; 512];
        if let Ok((n, _src)) = sock.recv_from(&mut buf) {
            // Header is 12 bytes; first 2 are the transaction ID.
            if n >= 12 {
                let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
                // We don't validate RCODE — even a SERVFAIL means the
                // resolver is reachable and responsive, which is what
                // the Health widget measures.
                if resp_id == id {
                    rtts.push(send_t.elapsed().as_secs_f64() * 1000.0);
                }
            }
        }
    }

    let avg = if rtts.is_empty() {
        None
    } else {
        Some(rtts.iter().sum::<f64>() / rtts.len() as f64)
    };
    let loss = (PROBES - rtts.len()) as f64 / PROBES as f64 * 100.0;
    (avg, loss)
}

/// Minimal DNS query: standard query (RD=1) for the root zone's NS
/// record. Total payload is 17 bytes — smallest valid query we can send
/// without depending on any name being resolvable.
fn build_dns_query(id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(17);
    q.extend_from_slice(&id.to_be_bytes()); // transaction id
    q.extend_from_slice(&[0x01, 0x00]); // flags: standard query, RD=1
    q.extend_from_slice(&[0x00, 0x01]); // qdcount = 1
    q.extend_from_slice(&[0x00, 0x00]); // ancount = 0
    q.extend_from_slice(&[0x00, 0x00]); // nscount = 0
    q.extend_from_slice(&[0x00, 0x00]); // arcount = 0
    q.push(0x00); // qname: root (single null label)
    q.extend_from_slice(&[0x00, 0x02]); // qtype = NS
    q.extend_from_slice(&[0x00, 0x01]); // qclass = IN
    q
}

fn run_ping(target: &str) -> (Option<f64>, f64) {
    // Prefer native DGRAM ICMP on Unix — works under the sandbox
    // because Landlock sets NO_NEW_PRIVS, which makes the kernel
    // ignore the setcap on /usr/bin/ping and break the subprocess
    // fallback. DGRAM ICMP gates on `net.ipv4.ping_group_range`
    // (default `0 2147483647` on most distros) instead of CAP_NET_RAW.
    #[cfg(unix)]
    if let Some(result) = run_ping_native(target) {
        return result;
    }

    run_ping_subprocess(target)
}

#[cfg(unix)]
fn run_ping_native(target: &str) -> Option<(Option<f64>, f64)> {
    use nix::sys::socket::{
        recvfrom, sendto, setsockopt, socket, sockopt::ReceiveTimeout, AddressFamily, MsgFlags,
        SockFlag, SockType, SockaddrIn, SockaddrIn6,
    };
    use nix::sys::time::TimeVal;
    use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};
    use std::os::fd::AsRawFd;
    use std::time::Instant;

    let addr: IpAddr = target.parse().ok()?;

    let (af, proto, icmp_echo_type, icmp_echo_reply_type) = match addr {
        IpAddr::V4(_) => (
            AddressFamily::Inet,
            nix::sys::socket::SockProtocol::Icmp,
            8u8,
            0u8,
        ),
        IpAddr::V6(_) => (
            AddressFamily::Inet6,
            nix::sys::socket::SockProtocol::IcmpV6,
            128u8,
            129u8,
        ),
    };

    // SOCK_DGRAM ICMP: kernel rewrites the Identifier per-socket and
    // delivers only matching Echo Replies. No CAP_NET_RAW required.
    let sock = socket(af, SockType::Datagram, SockFlag::empty(), proto).ok()?;

    // 1-second receive timeout per probe so a dead gateway doesn't
    // hang the prober thread.
    setsockopt(&sock, ReceiveTimeout, &TimeVal::new(1, 0)).ok()?;

    let fd = sock.as_raw_fd();

    const PROBES: usize = 3;
    let mut rtts = Vec::with_capacity(PROBES);

    for seq in 0..PROBES as u16 {
        let mut pkt = vec![0u8; 16];
        pkt[0] = icmp_echo_type;
        pkt[1] = 0; // code
        pkt[2] = 0; // checksum hi (we'll compute below for IPv4)
        pkt[3] = 0; // checksum lo
        pkt[4] = 0; // id hi (kernel rewrites for SOCK_DGRAM)
        pkt[5] = 0; // id lo
        pkt[6] = (seq >> 8) as u8;
        pkt[7] = seq as u8;
        // Payload: 8 arbitrary bytes so the reply is large enough to
        // identify and so we match `ping`'s 8-byte data block default.
        pkt[8..16].copy_from_slice(b"netwatch");

        // For IPv4 SOCK_DGRAM ICMP the kernel does NOT compute the
        // checksum for us — userspace must. (IPv6 the kernel does.)
        if matches!(addr, IpAddr::V4(_)) {
            let cksum = icmp_checksum(&pkt);
            pkt[2] = (cksum >> 8) as u8;
            pkt[3] = cksum as u8;
        }

        let send_t = Instant::now();

        let send_ok = match addr {
            IpAddr::V4(v4) => {
                let dst: SockaddrIn = SocketAddrV4::new(v4, 0).into();
                sendto(fd, &pkt, &dst, MsgFlags::empty()).is_ok()
            }
            IpAddr::V6(v6) => {
                let dst: SockaddrIn6 = SocketAddrV6::new(v6, 0, 0, 0).into();
                sendto(fd, &pkt, &dst, MsgFlags::empty()).is_ok()
            }
        };
        if !send_ok {
            // EPERM here probably means the kernel rejected SOCK_DGRAM
            // ICMP entirely (no ping_group_range entry). Caller falls
            // back to the subprocess path.
            return None;
        }

        let mut buf = [0u8; 256];
        let recv_ok = match addr {
            IpAddr::V4(_) => recvfrom::<SockaddrIn>(fd, &mut buf).map(|_| ()).is_ok(),
            IpAddr::V6(_) => recvfrom::<SockaddrIn6>(fd, &mut buf).map(|_| ()).is_ok(),
        };

        if recv_ok {
            // ICMP type sits at different offsets depending on OS:
            //   Linux SOCK_DGRAM ICMP: kernel strips the IPv4 header, so
            //     buf[0] is the ICMP type.
            //   macOS SOCK_DGRAM ICMP: IPv4 header is delivered intact,
            //     so the ICMP type sits at offset `IHL * 4`. Without
            //     this, every reply got rejected and the prober reported
            //     a fake "100% loss" on macOS.
            // IPv6 leaves the header outside the recvfrom buffer on
            // both kernels, so offset 0 is always correct there.
            let reply_offset = match addr {
                IpAddr::V4(_) if buf.first().map(|b| b >> 4) == Some(4) => {
                    let ihl_words = (buf[0] & 0x0F) as usize;
                    ihl_words * 4
                }
                _ => 0,
            };
            let reply_type_ok = buf.get(reply_offset) == Some(&icmp_echo_reply_type);
            if reply_type_ok {
                let elapsed_ms = send_t.elapsed().as_secs_f64() * 1000.0;
                rtts.push(elapsed_ms);
            }
        }
    }

    let avg = if rtts.is_empty() {
        None
    } else {
        Some(rtts.iter().sum::<f64>() / rtts.len() as f64)
    };
    let loss = (PROBES - rtts.len()) as f64 / PROBES as f64 * 100.0;
    Some((avg, loss))
}

#[cfg(unix)]
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Subprocess fallback for Windows + Unix systems where SOCK_DGRAM ICMP
/// isn't available (no `net.ipv4.ping_group_range` entry, exotic
/// kernels). Under the v0.17.x Linux sandbox this path is broken
/// because Landlock sets NO_NEW_PRIVS and the setcap on `/usr/bin/ping`
/// is ignored on exec — the native path above is what makes pings
/// work under sandbox.
fn run_ping_subprocess(target: &str) -> (Option<f64>, f64) {
    #[cfg(target_os = "macos")]
    let args = ["-c", "3", "-t", "1", target];

    #[cfg(target_os = "linux")]
    let args = ["-c", "3", "-W", "1", target];

    #[cfg(target_os = "windows")]
    let args = ["-n", "3", "-w", "1000", target];

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let args = ["-c", "3", "-W", "1", target];

    let output = match Command::new("ping").args(args).output() {
        Ok(o) => o,
        Err(_) => return (None, 100.0),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let loss = parse_loss(&text);
    let rtt = parse_avg_rtt(&text);

    (rtt, loss)
}

fn parse_loss(output: &str) -> f64 {
    // "3 packets transmitted, 3 packets received, 0.0% packet loss"
    for line in output.lines() {
        if line.contains("packet loss") || line.contains("% loss") {
            for part in line.split_whitespace() {
                if part.ends_with('%') {
                    if let Ok(val) = part.trim_end_matches('%').parse::<f64>() {
                        return val;
                    }
                }
            }
            // Try comma-separated format
            for segment in line.split(',') {
                let trimmed = segment.trim();
                if trimmed.contains("% packet loss") || trimmed.contains("% loss") {
                    if let Some(pct_str) = trimmed.split('%').next() {
                        let pct_str = pct_str.trim();
                        if let Ok(val) = pct_str.parse::<f64>() {
                            return val;
                        }
                        // Handle "0.0% packet loss" - get last word before %
                        if let Some(last_word) = pct_str.split_whitespace().last() {
                            let cleaned = last_word.trim_start_matches('(');
                            if let Ok(val) = cleaned.parse::<f64>() {
                                return val;
                            }
                        }
                    }
                }
            }
        }
    }
    100.0
}

fn parse_avg_rtt(output: &str) -> Option<f64> {
    // "round-trip min/avg/max/stddev = 1.234/2.345/3.456/0.567 ms"
    for line in output.lines() {
        if line.contains("min/avg/max") || line.contains("rtt min/avg/max") {
            if let Some(stats) = line.split('=').nth(1) {
                let stats = stats.trim();
                let parts: Vec<&str> = stats.split('/').collect();
                if parts.len() >= 2 {
                    return parts[1].trim().parse().ok();
                }
            }
        }
    }
    // Windows format: "Minimum = 1ms, Maximum = 3ms, Average = 2ms"
    for line in output.lines() {
        if line.contains("Average =") {
            if let Some(avg_part) = line.split("Average =").nth(1) {
                let avg_str = avg_part.trim().trim_end_matches("ms").trim();
                return avg_str.parse().ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_loss tests ──────────────────────────────────────────────

    #[test]
    fn parse_loss_linux_zero() {
        let output = "\
PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.23 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=1.10 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=1.05 ms

--- 192.168.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 1.050/1.126/1.230/0.075 ms";
        assert_eq!(parse_loss(output), 0.0);
    }

    #[test]
    fn parse_loss_linux_partial() {
        let output = "3 packets transmitted, 1 received, 66.7% packet loss, time 2003ms";
        assert_eq!(parse_loss(output), 66.7);
    }

    #[test]
    fn parse_loss_macos_format() {
        let output = "\
PING 192.168.1.1 (192.168.1.1): 56 data bytes
64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=2.345 ms

--- 192.168.1.1 ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 1.234/2.345/3.456/0.567 ms";
        assert_eq!(parse_loss(output), 0.0);
    }

    #[test]
    fn parse_loss_windows_format() {
        let output = "\
Ping statistics for 192.168.1.1:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 3ms, Average = 2ms";
        assert_eq!(parse_loss(output), 0.0);
    }

    #[test]
    fn parse_loss_full_loss() {
        let output = "3 packets transmitted, 0 received, 100% packet loss, time 2003ms";
        assert_eq!(parse_loss(output), 100.0);
    }

    #[test]
    fn parse_loss_empty_input() {
        assert_eq!(parse_loss(""), 100.0);
    }

    #[test]
    fn parse_loss_gibberish() {
        assert_eq!(parse_loss("not a ping output at all"), 100.0);
    }

    // ── parse_avg_rtt tests ───────────────────────────────────────────

    #[test]
    fn parse_avg_rtt_linux() {
        let output = "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.111 ms";
        assert_eq!(parse_avg_rtt(output), Some(0.456));
    }

    #[test]
    fn parse_avg_rtt_macos() {
        let output = "round-trip min/avg/max/stddev = 1.234/2.345/3.456/0.567 ms";
        assert_eq!(parse_avg_rtt(output), Some(2.345));
    }

    #[test]
    fn parse_avg_rtt_full_linux_output() {
        let output = "\
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=12.3 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=11.8 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=117 time=12.1 ms

--- 8.8.8.8 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 11.800/12.066/12.300/0.205 ms";
        assert_eq!(parse_avg_rtt(output), Some(12.066));
    }

    #[test]
    fn parse_avg_rtt_windows() {
        let output = "\
Ping statistics for 192.168.1.1:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 3ms, Average = 2ms";
        assert_eq!(parse_avg_rtt(output), Some(2.0));
    }

    #[test]
    fn parse_avg_rtt_windows_large() {
        let output = "    Minimum = 10ms, Maximum = 50ms, Average = 25ms";
        assert_eq!(parse_avg_rtt(output), Some(25.0));
    }

    #[test]
    fn parse_avg_rtt_empty_input() {
        assert_eq!(parse_avg_rtt(""), None);
    }

    #[test]
    fn parse_avg_rtt_gibberish() {
        assert_eq!(parse_avg_rtt("this is not ping output"), None);
    }

    // ── build_dns_query tests ─────────────────────────────────────────

    #[test]
    fn dns_query_has_correct_header_and_question() {
        let q = build_dns_query(0xa6b4);
        // 12-byte header + 1 byte qname + 2 qtype + 2 qclass = 17
        assert_eq!(q.len(), 17);

        // Transaction ID
        assert_eq!(&q[0..2], &[0xa6, 0xb4]);
        // Flags: standard query, RD=1
        assert_eq!(&q[2..4], &[0x01, 0x00]);
        // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        assert_eq!(&q[4..12], &[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Root qname
        assert_eq!(q[12], 0x00);
        // QTYPE=NS(2), QCLASS=IN(1)
        assert_eq!(&q[13..17], &[0x00, 0x02, 0x00, 0x01]);
    }

    #[test]
    fn dns_query_id_round_trips() {
        for id in [0u16, 1, 0x1234, 0xfffe, 0xffff] {
            let q = build_dns_query(id);
            let parsed = u16::from_be_bytes([q[0], q[1]]);
            assert_eq!(parsed, id, "id round-trip failed for {id:#x}");
        }
    }

    // ── TCP gateway-probe tests ───────────────────────────────────────

    #[test]
    fn tcp_probe_port_succeeds_against_local_listener() {
        // Bind an ephemeral TCP port, leave it accept-able, then probe it.
        // We expect 0% loss + a small but non-None RTT because all three
        // probes complete the 3WHS.
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();

        // Drain accept() in a background thread so connect() doesn't
        // block on listen backlog quirks.
        let _t = std::thread::spawn(move || {
            for _ in 0..3 {
                if let Ok((stream, _)) = listener.accept() {
                    drop(stream);
                }
            }
        });

        let (rtt, loss) = run_tcp_probe_port("127.0.0.1".parse().unwrap(), port);
        assert_eq!(loss, 0.0, "expected 0% loss against a live local listener");
        assert!(rtt.is_some(), "expected an RTT measurement");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn tcp_probe_port_treats_connection_refused_as_success() {
        // Find a port nothing is listening on by binding then dropping.
        // The follow-up `connect()` should get ECONNREFUSED, which the
        // probe treats as "host alive" (RST proves the host responded).
        //
        // Skipped on Windows: the bind-then-drop-then-connect pattern
        // doesn't reliably surface as `ConnectionRefused` on Win32.
        // Windows' TCP stack puts the socket into TIME_WAIT after the
        // listener drops and a subsequent connect attempt to that local
        // ephemeral port can return `ConnectionAborted` or
        // `HostUnreachable` instead of `ConnectionRefused`. The
        // production code (which counts ConnectionRefused as success) is
        // still correct for real-network probes — a remote host with a
        // closed port returns a clean RST → ConnectionRefused on Windows
        // too. This test just covers the local-loopback edge case where
        // OS-level timing makes the behavior platform-dependent.
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let (rtt, loss) = run_tcp_probe_port("127.0.0.1".parse().unwrap(), port);
        assert_eq!(
            loss, 0.0,
            "ECONNREFUSED should count as success (host responded with RST)"
        );
        assert!(rtt.is_some());
    }

    #[test]
    fn tcp_probe_port_times_out_to_unrouted_address() {
        // 192.0.2.0/24 is reserved for documentation (RFC 5737) and
        // should be unrouted — connect_timeout will hit the 1s timer.
        // Mark as #[ignore] in CI if your environment proxies / blocks
        // outbound to TEST-NET addresses with custom routing; locally
        // this hits ETIMEDOUT.
        let (rtt, loss) = run_tcp_probe_port("192.0.2.1".parse().unwrap(), 80);
        // Either 100% loss (timeout) or some flavor of NetworkUnreachable
        // — both are acceptable. The test guards against the probe
        // *succeeding* against an unrouted host, which would mean the
        // success detection is too permissive.
        assert!(
            loss > 0.0,
            "probe must report loss for unrouted host (got rtt={rtt:?}, loss={loss})"
        );
    }
}
