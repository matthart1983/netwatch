use crate::app::{safe_read, safe_write};
use std::collections::VecDeque;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

// One sample per probe — i.e. one per `HEALTH_PROBE_TICKS` refresh ticks —
// retained for `HISTORY_WINDOW_SECS`. This was a bare 60, which at a 5-tick
// probe cadence covered five minutes against the traffic series' ten, so any
// plot stacking the two had one track that stopped half-way and stayed there.
const RTT_HISTORY_MAX: usize = crate::app::probe_history_len(1000);

#[derive(Clone)]
pub struct HealthStatus {
    pub completed: ProbeTimes,
    pub gateway_rtt_ms: Option<f64>,
    pub gateway_loss: Loss,
    pub dns_rtt_ms: Option<f64>,
    pub dns_loss: Loss,
    /// Reachability of a fixed public host beyond the local network.
    ///
    /// Distinguishes "my router is fine but the line is down" from "my router
    /// is down" — gateway and DNS alone can't tell those apart, since a
    /// working LAN with a dead uplink looks perfectly healthy on both.
    pub internet_rtt_ms: Option<f64>,
    pub internet_loss: Loss,
    pub gateway_rtt_history: VecDeque<Option<f64>>,
    pub dns_rtt_history: VecDeque<Option<f64>>,
    pub internet_rtt_history: VecDeque<Option<f64>>,
    /// Per-cycle reply flags from the DNS probe, one entry per probe cycle.
    /// The RTT series says whether the resolver answered; this says *what*
    /// it answered — a truncated reply or a SERVFAIL is a reply.
    pub dns_probe_history: VecDeque<DnsProbe>,
    /// The latest answer cross-check, and whether each past cycle's local
    /// answer disagreed with the validating reference.
    pub dns_cross: Option<DnsCrossCheck>,
    pub dns_cross_history: VecDeque<bool>,
    /// The latest STUN mapping probe. Runs every [`STUN_EVERY`] cycles.
    pub nat: Option<NatProbe>,
}

/// What a probe's loss figure means.
///
/// The prober used to start every series at 100% and to report 100% when a
/// probe could not be sent at all, so a fresh start and a blocked ICMP socket
/// both read as a dead network — on the dashboard tile, in Lite's verdict
/// line, and in every export. Loss is a measurement; when there is none, the
/// value says so and carries the reason.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Loss {
    /// No probe has completed yet.
    Pending,
    /// The probe could not be sent, so loss is unknown — not 100%.
    Unmeasured(&'static str),
    /// Measured over the probe's samples, 0.0–100.0.
    Measured(f64),
}

impl Loss {
    pub fn pct(self) -> Option<f64> {
        match self {
            Self::Measured(p) => Some(p),
            _ => None,
        }
    }

    pub fn is_measured(self) -> bool {
        matches!(self, Self::Measured(_))
    }

    /// Measured, and above zero.
    pub fn is_lossy(self) -> bool {
        matches!(self, Self::Measured(p) if p > 0.0)
    }

    /// The probe ran and the target did not answer cleanly: measured loss, or
    /// a measured probe with no rtt. Pending and unmeasured never degrade —
    /// "we could not ask" is not "it did not answer".
    pub fn degrades(self, rtt: Option<f64>) -> bool {
        matches!(self, Self::Measured(p) if p > 0.0 || rtt.is_none())
    }

    /// Why there is no figure, when the probe could not be sent.
    pub fn note(self) -> Option<&'static str> {
        match self {
            Self::Unmeasured(why) => Some(why),
            _ => None,
        }
    }

    /// The figure for display, or `—` when there is none.
    pub fn label(self, decimals: usize) -> String {
        match self {
            Self::Measured(p) => format!("{p:.decimals$}%"),
            _ => "—".into(),
        }
    }
}

/// Completion times belong to measurements, not the UI refresh cadence.
#[derive(Clone, Debug, Default)]
pub struct ProbeTimes {
    /// Completion timestamps aligned with each RTT history, oldest first.
    pub gateway_history: VecDeque<std::time::Instant>,
    pub dns_history: VecDeque<std::time::Instant>,
    pub internet_history: VecDeque<std::time::Instant>,
    pub gateway: Option<std::time::Instant>,
    pub dns: Option<std::time::Instant>,
    pub internet: Option<std::time::Instant>,
    pub nat: Option<std::time::Instant>,
    pub gateway_target: Option<String>,
    pub dns_target: Option<String>,
}

impl ProbeTimes {
    pub fn fresh(at: Option<std::time::Instant>, max_secs: u64) -> bool {
        Self::fresh_at(at, max_secs, std::time::Instant::now())
    }

    /// [`Self::fresh`] against an explicit `now`, so a replayed episode judges
    /// freshness at the recorded moment rather than at replay time.
    pub fn fresh_at(
        at: Option<std::time::Instant>,
        max_secs: u64,
        now: std::time::Instant,
    ) -> bool {
        at.is_some_and(|at| {
            now.saturating_duration_since(at) <= std::time::Duration::from_secs(max_secs)
        })
    }
}

/// Reply flags for one DNS probe cycle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DnsProbe {
    pub replies: u8,
    pub truncated: u8,
    pub servfail: u8,
}

/// One name asked of the configured resolver and of a validating reference.
///
/// The name is chosen for a stable answer set (`dns.google` → 8.8.8.8 and
/// 8.8.4.4 everywhere), so a disagreement is not a CDN handing out the
/// nearest POP; it is the local resolver saying something the reference
/// does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsCrossCheck {
    pub name: String,
    pub local: Vec<std::net::Ipv4Addr>,
    pub reference_resolver: String,
    pub reference: Vec<std::net::Ipv4Addr>,
    /// The reference set the AD bit: its answer was DNSSEC-validated.
    pub validated: bool,
    /// The local resolver answered a public name with a private, loopback,
    /// link-local or CGNAT address — the signature of a portal or an
    /// interceptor, whatever the reference says.
    pub private_answer: bool,
    /// Local and reference answer sets share no address.
    pub mismatch: bool,
}

/// What two STUN servers said our address was, asked from one socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NatProbe {
    /// `(server, mapped address)` for each server that answered.
    pub mappings: Vec<(String, String)>,
    /// The mapping depended on the destination: a different public port for
    /// each server, from the same local socket. That is a symmetric NAT, and
    /// it is why hole-punching fails behind it.
    pub symmetric: bool,
}

/// Reference resolver for the answer cross-check. Asked with the DO bit so a
/// validated answer comes back with AD set.
pub const REFERENCE_RESOLVER: &str = "1.1.1.1";
/// A public name whose answer set is the same from every vantage point.
pub const CROSS_CHECK_NAME: &str = "dns.google";
/// Two STUN servers on different addresses, so a destination-dependent
/// mapping has something to depend on.
pub const STUN_SERVERS: [&str; 2] = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"];
/// STUN runs once in this many probe cycles — about a minute at defaults.
/// NAT mappings do not change from second to second, and two UDP packets a
/// minute to public servers is the whole cost.
pub const STUN_EVERY: u32 = 12;

/// Fixed target for the internet reachability probe.
///
/// 1.1.1.1 over 443: anycast (so the RTT reflects the nearest POP rather than
/// a transcontinental hop), and the same ICMP→TCP fallback as the gateway
/// probe applies — plenty of networks drop echo but pass TCP.
pub const INTERNET_TARGET: &str = "1.1.1.1";

pub struct HealthProber {
    cancel: crate::diagnose::probe_io::Cancel,
    /// Latest probe results, shared via the `Arc<RwLock<Arc<…>>>` snapshot
    /// pattern (see [`crate::collectors::traffic::TrafficCollector`] for the
    /// canonical example). Readers clone the inner `Arc` in O(1); the probe
    /// thread builds a new `HealthStatus` and swaps it in via a brief write
    /// lock so renders never block on an in-flight ping.
    snapshot: Arc<RwLock<Arc<HealthStatus>>>,
    busy: Arc<AtomicBool>,
    /// Probe cycles so far, for the checks that run less often than every
    /// cycle.
    cycles: Arc<AtomicU32>,
    nat_outcome: Arc<RwLock<Option<Result<(), String>>>>,
}

impl Drop for HealthProber {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl Default for HealthProber {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthProber {
    pub fn new() -> Self {
        Self {
            cancel: Default::default(),
            snapshot: Arc::new(RwLock::new(Arc::new(HealthStatus {
                completed: Default::default(),
                gateway_rtt_ms: None,
                gateway_loss: Loss::Pending,
                dns_rtt_ms: None,
                dns_loss: Loss::Pending,
                internet_rtt_ms: None,
                internet_loss: Loss::Pending,
                gateway_rtt_history: VecDeque::new(),
                dns_rtt_history: VecDeque::new(),
                internet_rtt_history: VecDeque::new(),
                dns_probe_history: VecDeque::new(),
                dns_cross: None,
                dns_cross_history: VecDeque::new(),
                nat: None,
            }))),
            busy: Arc::new(AtomicBool::new(false)),
            cycles: Arc::new(AtomicU32::new(0)),
            nat_outcome: Arc::new(RwLock::new(None)),
        }
    }

    /// Cheap snapshot of the most recent probe results. Single atomic
    /// refcount bump regardless of history depth.
    pub fn status(&self) -> Arc<HealthStatus> {
        Arc::clone(&safe_read(&self.snapshot, "health::status"))
    }

    pub fn nat_outcome(&self) -> Option<Result<(), String>> {
        self.nat_outcome.read().unwrap().clone()
    }

    /// Request STUN on the next health cycle, without starting another worker.
    pub fn request_nat(&self) {
        self.cycles.store(0, Ordering::SeqCst);
    }

    pub fn probe(&self, gateway: Option<&str>, dns_server: Option<&str>) {
        if self.busy.load(Ordering::SeqCst) {
            return;
        }
        self.busy.store(true, Ordering::SeqCst);
        let cancel = self.cancel.clone();
        let busy = Arc::clone(&self.busy);
        let nat_outcome = Arc::clone(&self.nat_outcome);
        let snapshot = Arc::clone(&self.snapshot);
        let gw = gateway.map(|s| s.to_string());
        let dns = dns_server.map(|s| s.to_string());
        let cycle = self.cycles.fetch_add(1, Ordering::SeqCst);
        crate::sandbox::worker::spawn("health", move || {
            // Each probe block builds a new HealthStatus off the latest
            // published snapshot, then swaps it in. The deep-clone is cheap:
            // `HealthStatus` contains at most ~60 history entries per series.
            if cancel.cancelled() {
                busy.store(false, Ordering::SeqCst);
                return;
            }
            if let Some(gw) = gw.as_deref() {
                let (rtt, loss) = run_gateway_probe(gw);
                let mut next = (**safe_read(&snapshot, "health::probe::read_gw")).clone();
                if next.completed.gateway_target.as_deref() != Some(gw) {
                    next.gateway_rtt_history.clear();
                    next.completed.gateway_history.clear();
                }
                next.gateway_rtt_ms = rtt;
                next.gateway_loss = loss;
                let completed = std::time::Instant::now();
                // The history is a series of measurements. A probe that could
                // not be sent is recorded as such on `gateway_loss`, not as
                // a lost sample the sparkline and the rules would then read.
                if loss.is_measured() {
                    next.completed.gateway_history.push_back(completed);
                    next.gateway_rtt_history.push_back(rtt);
                    if next.gateway_rtt_history.len() > RTT_HISTORY_MAX {
                        next.gateway_rtt_history.pop_front();
                        next.completed.gateway_history.pop_front();
                    }
                    next.gateway_rtt_history.make_contiguous();
                }
                next.completed.gateway = Some(completed);
                next.completed.gateway_target = Some(gw.to_string());
                *safe_write(&snapshot, "health::probe::publish_gw") = Arc::new(next);
            }
            if cancel.cancelled() {
                busy.store(false, Ordering::SeqCst);
                return;
            }
            if let Some(dns) = dns.as_deref() {
                // Send a real DNS query rather than ICMP. ICMP-pinging the
                // DNS server is a misleading health signal — plenty of
                // resolvers (cloud LBs, internal CoreDNS, hardened routers)
                // drop ICMP echo while happily answering DNS. It also fails
                // on Linux hosts where `net.ipv4.ping_group_range = 1 0`
                // and the sandbox has dropped CAP_NET_RAW, even though UDP
                // queries to port 53 work fine.
                let (rtt, loss, flags) = run_dns_query(dns);
                let completed = std::time::Instant::now();
                // Same cycle, same resolver: what does it say a public name
                // resolves to, against a reference that validates?
                let cross = run_dns_cross_check(dns);
                let mut next = (**safe_read(&snapshot, "health::probe::read_dns")).clone();
                if next.completed.dns_target.as_deref() != Some(dns) {
                    next.dns_rtt_history.clear();
                    next.completed.dns_history.clear();
                    next.dns_probe_history.clear();
                    next.dns_cross_history.clear();
                }
                next.dns_rtt_ms = rtt;
                next.dns_loss = loss;
                if loss.is_measured() {
                    next.completed.dns_history.push_back(completed);
                    next.dns_rtt_history.push_back(rtt);
                    if next.dns_rtt_history.len() > RTT_HISTORY_MAX {
                        next.dns_rtt_history.pop_front();
                        next.completed.dns_history.pop_front();
                    }
                    next.dns_rtt_history.make_contiguous();
                    next.dns_probe_history.push_back(flags);
                    if next.dns_probe_history.len() > RTT_HISTORY_MAX {
                        next.dns_probe_history.pop_front();
                    }
                }
                if let Some(c) = &cross {
                    next.dns_cross_history
                        .push_back(c.mismatch || c.private_answer);
                    if next.dns_cross_history.len() > RTT_HISTORY_MAX {
                        next.dns_cross_history.pop_front();
                    }
                }
                next.dns_cross = cross;
                next.completed.dns = Some(completed);
                next.completed.dns_target = Some(dns.to_string());
                *safe_write(&snapshot, "health::probe::publish_dns") = Arc::new(next);
            }
            if cancel.cancelled() {
                busy.store(false, Ordering::SeqCst);
                return;
            }
            if cycle.is_multiple_of(STUN_EVERY) {
                let result = run_stun_probe(&cancel);
                *nat_outcome.write().unwrap() =
                    Some(result.as_ref().map(|_| ()).map_err(Clone::clone));
                let nat = result.ok();
                let mut next = (**safe_read(&snapshot, "health::probe::read_nat")).clone();
                next.nat = nat;
                next.completed.nat = Some(std::time::Instant::now());
                *safe_write(&snapshot, "health::probe::publish_nat") = Arc::new(next);
            }
            {
                // Same ICMP-then-TCP shape as the gateway probe: on hosts
                // where unprivileged ICMP is unavailable, a 1-RTT TCP connect
                // to 443 answers the same question without any privileges.
                let (rtt, loss) = run_internet_probe(INTERNET_TARGET);
                let mut next = (**safe_read(&snapshot, "health::probe::read_inet")).clone();
                next.internet_rtt_ms = rtt;
                next.internet_loss = loss;
                let completed = std::time::Instant::now();
                if loss.is_measured() {
                    next.completed.internet_history.push_back(completed);
                    next.internet_rtt_history.push_back(rtt);
                    if next.internet_rtt_history.len() > RTT_HISTORY_MAX {
                        next.internet_rtt_history.pop_front();
                        next.completed.internet_history.pop_front();
                    }
                    next.internet_rtt_history.make_contiguous();
                }
                next.completed.internet = Some(completed);
                *safe_write(&snapshot, "health::probe::publish_inet") = Arc::new(next);
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
///
/// When ICMP could not be *sent* (`run_ping` returns `None`) and no TCP port
/// answers either, nothing has been measured: the result says so rather than
/// reporting 100% loss against a router that may be perfectly healthy. Only
/// when ICMP was actually sent and both paths went unanswered is 100% a
/// measurement.
fn run_gateway_probe(target: &str) -> (Option<f64>, Loss) {
    let icmp = run_ping(target);
    if let Some((rtt, loss)) = icmp {
        if loss < 100.0 {
            return (rtt, Loss::Measured(loss));
        }
    }
    // ICMP blocked, or answered by nothing. Try TCP.
    let (rtt, loss) = run_tcp_probe(target);
    if loss < 100.0 || icmp.is_some() {
        return (rtt, Loss::Measured(loss));
    }
    (
        None,
        Loss::Unmeasured("icmp is blocked here and the gateway answers no tcp port"),
    )
}

/// Internet reachability probe: ICMP first, TCP/443 when ICMP is unavailable.
///
/// Mirrors [`run_gateway_probe`]'s structure but targets a single well-known
/// port — unlike a router, a public anycast resolver has a predictable
/// listener, so there's no port list to walk.
fn run_internet_probe(target: &str) -> (Option<f64>, Loss) {
    let icmp = run_ping(target);
    if let Some((rtt, loss)) = icmp {
        if loss < 100.0 {
            return (rtt, Loss::Measured(loss));
        }
    }
    let Ok(addr) = target.parse::<std::net::IpAddr>() else {
        return (
            None,
            Loss::Unmeasured("the internet probe target is not an address"),
        );
    };
    let (rtt, loss) = run_tcp_probe_port(addr, 443);
    if loss < 100.0 || icmp.is_some() {
        return (rtt, Loss::Measured(loss));
    }
    (
        None,
        Loss::Unmeasured("icmp is blocked here and tcp/443 to the probe target did not answer"),
    )
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

pub(crate) fn run_tcp_probe_port(addr: std::net::IpAddr, port: u16) -> (Option<f64>, f64) {
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

/// One decoded DNS reply: the header bits the rules read, plus any A records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DnsReply {
    pub(crate) id: u16,
    pub(crate) truncated: bool,
    /// Authentic Data — the resolver validated the answer with DNSSEC.
    pub(crate) authentic: bool,
    pub(crate) rcode: u8,
    pub(crate) answers: Vec<std::net::Ipv4Addr>,
}

const RCODE_SERVFAIL: u8 = 2;

/// Parse the header and walk the sections for A records.
///
/// Names are skipped, not decoded — a compression pointer is two bytes and
/// ends the name, a label is its length plus one. Anything malformed returns
/// `None` and counts as no reply, which is the safe way to be wrong here.
pub(crate) fn parse_dns_reply(buf: &[u8]) -> Option<DnsReply> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut reply = DnsReply {
        id,
        truncated: flags & 0x0200 != 0,
        authentic: flags & 0x0020 != 0,
        rcode: (flags & 0x000f) as u8,
        answers: Vec::new(),
    };
    let skip_name = |mut i: usize| -> Option<usize> {
        loop {
            let len = *buf.get(i)?;
            if len == 0 {
                return Some(i + 1);
            }
            if len & 0xc0 == 0xc0 {
                return Some(i + 2);
            }
            i += 1 + len as usize;
        }
    };
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(i)? + 4;
    }
    for _ in 0..an {
        i = skip_name(i)?;
        let rtype = u16::from_be_bytes([*buf.get(i)?, *buf.get(i + 1)?]);
        let rdlen = u16::from_be_bytes([*buf.get(i + 8)?, *buf.get(i + 9)?]) as usize;
        let rdata = buf.get(i + 10..i + 10 + rdlen)?;
        if rtype == 1 && rdlen == 4 {
            reply.answers.push(std::net::Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ));
        }
        i += 10 + rdlen;
    }
    Some(reply)
}

/// Send one query and wait up to a second for the reply that matches its id.
pub(crate) fn dns_exchange(
    sock: &std::net::UdpSocket,
    dest: std::net::SocketAddr,
    query: &[u8],
    id: u16,
) -> Option<(DnsReply, f64)> {
    let send_t = std::time::Instant::now();
    sock.send_to(query, dest).ok()?;
    let mut buf = [0u8; 1232];
    // Stale replies from an earlier probe can land in the same socket; keep
    // reading until the id matches or the timeout does its job.
    loop {
        let (n, _src) = sock.recv_from(&mut buf).ok()?;
        if let Some(reply) = parse_dns_reply(&buf[..n]) {
            if reply.id == id {
                return Some((reply, send_t.elapsed().as_secs_f64() * 1000.0));
            }
        }
    }
}

pub(crate) fn dns_socket(addr: std::net::IpAddr) -> Option<std::net::UdpSocket> {
    let bind_addr = match addr {
        std::net::IpAddr::V4(_) => "0.0.0.0:0",
        std::net::IpAddr::V6(_) => "[::]:0",
    };
    let sock = std::net::UdpSocket::bind(bind_addr).ok()?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .ok()?;
    Some(sock)
}

/// The reachability probe: three root-NS queries, timed.
///
/// Returns the mean rtt, the loss, and the reply flags — a SERVFAIL or a
/// truncated reply is still a reply for reachability, but the diagnostic
/// rules want to know it happened.
fn run_dns_query(server: &str) -> (Option<f64>, Loss, DnsProbe) {
    use std::net::{IpAddr, SocketAddr};

    const PROBES: usize = 3;
    let lost = |n: usize| (PROBES - n) as f64 / PROBES as f64 * 100.0;

    // `IpAddr::parse` rejects IPv6 zone identifiers (e.g. `fe80::1%en0`),
    // which means `primary_dns()` should already have skipped link-local
    // entries upstream. If it didn't (only link-local servers configured),
    // no query was sent: that is not 100% loss, it is a resolver address the
    // probe cannot use, and the Health widget says which (issue #31).
    let Ok(addr) = server.parse::<IpAddr>() else {
        return (
            None,
            Loss::Unmeasured("the resolver address is not usable by the probe"),
            DnsProbe::default(),
        );
    };
    let Some(sock) = dns_socket(addr) else {
        return (
            None,
            Loss::Unmeasured("could not open a udp socket for the dns probe"),
            DnsProbe::default(),
        );
    };
    let dest = SocketAddr::new(addr, 53);

    let mut rtts = Vec::with_capacity(PROBES);
    let mut flags = DnsProbe::default();
    for seq in 0..PROBES as u16 {
        // Per-probe IDs let us reject stale replies from earlier probes
        // landing late inside the same socket's recv buffer.
        let id = 0xa6b4u16.wrapping_add(seq);
        let query = build_dns_query(id, ".", 2, false);
        if let Some((reply, rtt)) = dns_exchange(&sock, dest, &query, id) {
            // RCODE is not a failure here — even a SERVFAIL means the
            // resolver is reachable and responsive, which is what the
            // Health widget measures. It is recorded for the rules.
            rtts.push(rtt);
            flags.replies += 1;
            flags.truncated += u8::from(reply.truncated);
            flags.servfail += u8::from(reply.rcode == RCODE_SERVFAIL);
        }
    }

    let avg = if rtts.is_empty() {
        None
    } else {
        Some(rtts.iter().sum::<f64>() / rtts.len() as f64)
    };
    (avg, Loss::Measured(lost(rtts.len())), flags)
}

/// Not a routable public address: RFC 1918, loopback, link-local, CGNAT,
/// or unspecified. A public name answering with one of these is the mark of
/// a captive portal or an interceptor.
pub fn is_private_v4(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || (o[0] == 100 && (64..=127).contains(&o[1]))
}

/// Ask the configured resolver and a validating reference the same public
/// name, and compare.
fn run_dns_cross_check(server: &str) -> Option<DnsCrossCheck> {
    use std::net::{IpAddr, SocketAddr};

    let local_addr: IpAddr = server.parse().ok()?;
    let sock = dns_socket(local_addr)?;
    let local_q = build_dns_query(0x5a11, CROSS_CHECK_NAME, 1, false);
    let (local_reply, _) = dns_exchange(&sock, SocketAddr::new(local_addr, 53), &local_q, 0x5a11)?;

    let reference_addr: IpAddr = REFERENCE_RESOLVER.parse().ok()?;
    let ref_sock = dns_socket(reference_addr)?;
    let ref_q = build_dns_query(0x5a12, CROSS_CHECK_NAME, 1, true);
    let reference = dns_exchange(
        &ref_sock,
        SocketAddr::new(reference_addr, 53),
        &ref_q,
        0x5a12,
    )
    .map(|(r, _)| r);

    let private_answer = local_reply.answers.iter().any(|ip| is_private_v4(*ip));
    let (reference_answers, validated) = match &reference {
        Some(r) => (r.answers.clone(), r.authentic),
        None => (Vec::new(), false),
    };
    // Disagreement needs both sides to have said something. An empty local
    // answer is a failing resolver (its own rule); an empty reference is a
    // reference we could not reach, which says nothing about the resolver.
    let mismatch = !local_reply.answers.is_empty()
        && !reference_answers.is_empty()
        && !local_reply
            .answers
            .iter()
            .any(|ip| reference_answers.contains(ip));

    Some(DnsCrossCheck {
        name: CROSS_CHECK_NAME.to_string(),
        local: local_reply.answers,
        reference_resolver: REFERENCE_RESOLVER.to_string(),
        reference: reference_answers,
        validated,
        private_answer,
        mismatch,
    })
}

/// A standard recursive query for `name`/`qtype`. With `dnssec`, an EDNS OPT
/// record with the DO bit asks the resolver to validate and say so via AD.
pub(crate) fn build_dns_query(id: u16, name: &str, qtype: u16, dnssec: bool) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes()); // transaction id
    q.extend_from_slice(&[0x01, 0x00]); // flags: standard query, RD=1
    q.extend_from_slice(&[0x00, 0x01]); // qdcount = 1
    q.extend_from_slice(&[0x00, 0x00]); // ancount = 0
    q.extend_from_slice(&[0x00, 0x00]); // nscount = 0
    q.extend_from_slice(&[0x00, u8::from(dnssec)]); // arcount: the OPT record
    for label in name.split('.').filter(|l| !l.is_empty()) {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00); // root
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0x00, 0x01]); // qclass = IN
    if dnssec {
        q.push(0x00); // OPT owner: root
        q.extend_from_slice(&[0x00, 0x29]); // type OPT
        q.extend_from_slice(&1232u16.to_be_bytes()); // udp payload size
        q.extend_from_slice(&[0x00, 0x00, 0x80, 0x00]); // ext rcode/version, DO
        q.extend_from_slice(&[0x00, 0x00]); // rdlen
    }
    q
}

// ── STUN ────────────────────────────────────────────────────────────────────

const STUN_MAGIC: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

/// A Binding Request, RFC 5389 §6: type, zero length, cookie, transaction id.
fn build_stun_binding(txid: [u8; 12]) -> [u8; 20] {
    let mut m = [0u8; 20];
    m[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    m[4..8].copy_from_slice(&STUN_MAGIC);
    m[8..20].copy_from_slice(&txid);
    m
}

/// The mapped address in a Binding Success, from XOR-MAPPED-ADDRESS or the
/// older MAPPED-ADDRESS. IPv4 only, which is what a NAT is.
fn parse_stun_mapped(buf: &[u8], txid: [u8; 12]) -> Option<std::net::SocketAddrV4> {
    if buf.len() < 20 || buf[0..2] != [0x01, 0x01] || buf[4..8] != STUN_MAGIC || buf[8..20] != txid
    {
        return None;
    }
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let body = buf.get(20..20 + len)?;
    let mut i = 0;
    let mut plain = None;
    while i + 4 <= body.len() {
        let atype = u16::from_be_bytes([body[i], body[i + 1]]);
        let alen = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        let v = body.get(i + 4..i + 4 + alen)?;
        if alen == 8 && v[1] == 0x01 {
            let port = u16::from_be_bytes([v[2], v[3]]);
            let ip = [v[4], v[5], v[6], v[7]];
            match atype {
                0x0020 => {
                    let port = port ^ 0x2112;
                    let ip = std::net::Ipv4Addr::new(
                        ip[0] ^ STUN_MAGIC[0],
                        ip[1] ^ STUN_MAGIC[1],
                        ip[2] ^ STUN_MAGIC[2],
                        ip[3] ^ STUN_MAGIC[3],
                    );
                    return Some(std::net::SocketAddrV4::new(ip, port));
                }
                0x0001 => plain = Some(std::net::SocketAddrV4::new(ip.into(), port)),
                _ => {}
            }
        }
        // Attributes are padded to four bytes.
        i += 4 + alen.div_ceil(4) * 4;
    }
    plain
}

/// Ask two STUN servers what our address is, from one socket.
///
/// A NAT that hands the same public port to both is endpoint-independent
/// and hole-punching works through it. One that hands each a different port
/// is address-dependent — symmetric — and only a relay gets through.
fn run_stun_probe(cancel: &crate::diagnose::probe_io::Cancel) -> Result<NatProbe, String> {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("STUN socket: {e}"))?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    let mut mappings = Vec::new();
    let mut errors = Vec::new();
    for server in STUN_SERVERS {
        if cancel.cancelled() {
            return Err("STUN cancelled".into());
        }
        let (host, port) = server.rsplit_once(':').expect("authored STUN endpoint");
        let dest = match crate::diagnose::probe_io::resolve(host, port.parse().unwrap(), cancel) {
            Ok(addrs) => match addrs.into_iter().find(|a| a.is_ipv4()) {
                Some(a) => a,
                None => {
                    errors.push(format!("{server}: no IPv4 address"));
                    continue;
                }
            },
            Err(e) => {
                errors.push(format!("{server}: resolution: {e}"));
                continue;
            }
        };
        let uuid = uuid::Uuid::new_v4();
        let mut txid = [0; 12];
        txid.copy_from_slice(&uuid.as_bytes()[..12]);
        if let Err(e) = sock.send_to(&build_stun_binding(txid), dest) {
            errors.push(format!("{server}: send: {e}"));
            continue;
        }
        let mut buf = [0; 256];
        match sock.recv_from(&mut buf) {
            Ok((len, source)) if source == dest => match parse_stun_mapped(&buf[..len], txid) {
                Some(mapped) => mappings.push((server.to_string(), mapped.to_string())),
                None => errors.push(format!("{server}: invalid mapping response")),
            },
            Ok(_) => errors.push(format!("{server}: reply source did not match")),
            Err(e) => errors.push(format!("{server}: receive: {e}")),
        }
    }
    if mappings.len() != 2 {
        return Err(format!(
            "STUN obtained {}/2 mappings: {}",
            mappings.len(),
            errors.join("; ")
        ));
    }
    let symmetric = mappings[0].1 != mappings[1].1;
    Ok(NatProbe {
        mappings,
        symmetric,
    })
}

/// `None` means no echo request was sent by either path — the kernel refused
/// the socket and `ping` could not run or could not open one. `Some` is a
/// measurement, including `Some((None, 100.0))` for three unanswered echoes.
fn run_ping(target: &str) -> Option<(Option<f64>, f64)> {
    // Prefer native DGRAM ICMP on Unix — works under the sandbox
    // because Landlock sets NO_NEW_PRIVS, which makes the kernel
    // ignore the setcap on /usr/bin/ping and break the subprocess
    // fallback. DGRAM ICMP gates on `net.ipv4.ping_group_range`
    // (default `0 2147483647` on most distros) instead of CAP_NET_RAW.
    #[cfg(unix)]
    if let Some(result) = run_ping_native(target) {
        return Some(result);
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
fn run_ping_subprocess(target: &str) -> Option<(Option<f64>, f64)> {
    #[cfg(target_os = "macos")]
    let args = ["-c", "3", "-t", "1", target];

    #[cfg(target_os = "linux")]
    let args = ["-c", "3", "-W", "1", target];

    #[cfg(target_os = "windows")]
    let args = ["-n", "3", "-w", "1000", target];

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let args = ["-c", "3", "-W", "1", target];

    let output = Command::new("ping").args(args).output().ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    // `ping` that could not open its socket ("socket: Operation not
    // permitted" under NO_NEW_PRIVS) prints nothing to stdout and exits
    // non-zero. No summary line means no echo was sent, which is not loss.
    if !ping_ran(&text) {
        return None;
    }
    let loss = parse_loss(&text);
    let rtt = parse_avg_rtt(&text);

    Some((rtt, loss))
}

/// Whether `ping`'s output carries a transmit summary at all: "3 packets
/// transmitted" on Linux and macOS, "Packets: Sent = 3" on Windows.
fn ping_ran(output: &str) -> bool {
    output.contains("transmitted") || output.contains("Sent =")
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

    // ── loss model ─────────────────────────────────────────────────────
    #[test]
    fn a_fresh_prober_has_measured_nothing() {
        // The dashboard used to open on "100% loss" because this started at
        // 100.0. Pending is the whole fix for the fresh-start case.
        let s = HealthProber::new().status();
        assert_eq!(s.gateway_loss, Loss::Pending);
        assert_eq!(s.dns_loss, Loss::Pending);
        assert_eq!(s.internet_loss, Loss::Pending);
        assert!(s.gateway_rtt_history.is_empty());
    }

    #[test]
    fn a_pending_or_unmeasured_probe_never_degrades() {
        assert!(!Loss::Pending.degrades(None));
        assert!(!Loss::Unmeasured("icmp blocked").degrades(None));
        assert!(
            Loss::Measured(0.0).degrades(None),
            "a measured probe with no rtt is a target that did not answer"
        );
        assert!(Loss::Measured(33.3).degrades(Some(1.0)));
        assert!(!Loss::Measured(0.0).degrades(Some(1.0)));
    }

    #[test]
    fn only_a_measurement_has_a_figure() {
        assert_eq!(Loss::Pending.pct(), None);
        assert_eq!(Loss::Unmeasured("x").pct(), None);
        assert_eq!(Loss::Measured(12.5).pct(), Some(12.5));
        assert_eq!(Loss::Pending.label(0), "—");
        assert_eq!(Loss::Unmeasured("x").label(1), "—");
        assert_eq!(Loss::Measured(12.5).label(1), "12.5%");
        assert_eq!(Loss::Measured(0.0).label(0), "0%");
        assert_eq!(
            Loss::Unmeasured("icmp blocked").note(),
            Some("icmp blocked")
        );
        assert_eq!(Loss::Pending.note(), None);
        assert!(!Loss::Unmeasured("x").is_lossy());
        assert!(Loss::Measured(0.1).is_lossy());
    }

    #[test]
    fn ping_that_could_not_open_a_socket_did_not_run() {
        assert!(!ping_ran(""));
        assert!(!ping_ran("ping: socket: Operation not permitted"));
        assert!(ping_ran(
            "3 packets transmitted, 0 received, 100% packet loss, time 2003ms"
        ));
        assert!(ping_ran(
            "    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),"
        ));
    }

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
        let q = build_dns_query(0xa6b4, ".", 2, false);
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
            let q = build_dns_query(id, ".", 2, false);
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

#[cfg(test)]
mod probe_format_tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// A reply as a resolver would send it: header with TC and AD set, the
    /// question echoed, and two A records using a compression pointer.
    fn reply(flags: u16, answers: &[[u8; 4]]) -> Vec<u8> {
        let mut r = vec![0x5a, 0x11];
        r.extend_from_slice(&flags.to_be_bytes());
        r.extend_from_slice(&[0, 1, 0, answers.len() as u8, 0, 0, 0, 0]);
        r.extend_from_slice(&[
            3, b'd', b'n', b's', 6, b'g', b'o', b'o', b'g', b'l', b'e', 0,
        ]);
        r.extend_from_slice(&[0, 1, 0, 1]);
        for a in answers {
            r.extend_from_slice(&[0xc0, 0x0c]); // pointer to the question name
            r.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            r.extend_from_slice(a);
        }
        r
    }

    #[test]
    fn a_reply_decodes_its_flags_and_a_records() {
        let r = parse_dns_reply(&reply(
            0x8000 | 0x0200 | 0x0020 | 0x0002,
            &[[8, 8, 8, 8], [8, 8, 4, 4]],
        ))
        .expect("well-formed");
        assert_eq!(r.id, 0x5a11);
        assert!(r.truncated, "TC");
        assert!(r.authentic, "AD");
        assert_eq!(r.rcode, RCODE_SERVFAIL);
        assert_eq!(
            r.answers,
            vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)]
        );
    }

    #[test]
    fn a_truncated_packet_is_no_reply_rather_than_a_panic() {
        let full = reply(0x8180, &[[8, 8, 8, 8]]);
        for cut in [0, 5, 11, 20, full.len() - 3] {
            assert!(
                parse_dns_reply(&full[..cut])
                    .map(|r| r.answers.len())
                    .unwrap_or(0)
                    <= 1,
                "cut at {cut}"
            );
        }
        assert!(parse_dns_reply(&full[..11]).is_none());
    }

    /// The reference query asks for validation: an OPT record with DO set
    /// in the additional section, and arcount says so.
    #[test]
    fn a_dnssec_query_carries_an_opt_record_with_do() {
        let q = build_dns_query(7, "dns.google", 1, true);
        assert_eq!(&q[10..12], &[0, 1], "arcount");
        assert_eq!(q[12], 3, "first label length");
        let opt = &q[q.len() - 11..];
        assert_eq!(&opt[0..3], &[0, 0, 0x29], "root owner, type OPT");
        assert_eq!(
            opt[7] & 0x80,
            0x80,
            "DO bit: ttl bytes follow the 2-byte udp size"
        );
        let plain = build_dns_query(7, ".", 2, false);
        assert_eq!(&plain[10..12], &[0, 0]);
        assert_eq!(plain[12], 0, "root name is one null label");
    }

    #[test]
    fn private_answers_for_public_names_are_the_portal_signature() {
        for ip in [
            "10.1.1.1",
            "192.168.1.1",
            "172.16.0.5",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
        ] {
            assert!(is_private_v4(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "100.128.0.1", "172.32.0.1"] {
            assert!(!is_private_v4(ip.parse().unwrap()), "{ip}");
        }
    }

    /// XOR-MAPPED-ADDRESS decodes back to the address the server saw; a
    /// response for another transaction is ignored.
    #[test]
    fn stun_mapped_address_unxors() {
        let txid = [7u8; 12];
        let mut m = vec![0x01, 0x01, 0x00, 0x0c];
        m.extend_from_slice(&STUN_MAGIC);
        m.extend_from_slice(&txid);
        m.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
        m.extend_from_slice(&(51234u16 ^ 0x2112).to_be_bytes());
        let ip = [203u8, 0, 113, 9];
        for (i, b) in ip.iter().enumerate() {
            m.push(b ^ STUN_MAGIC[i]);
        }
        let got = parse_stun_mapped(&m, txid).expect("mapped");
        assert_eq!(got.to_string(), "203.0.113.9:51234");
        assert!(
            parse_stun_mapped(&m, [8u8; 12]).is_none(),
            "wrong transaction"
        );
        assert_eq!(build_stun_binding(txid)[4..8], STUN_MAGIC);
    }
}
