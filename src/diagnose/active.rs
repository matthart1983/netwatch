//! Explicit, bounded network experiments. Results describe selected endpoints,
//! not all Internet traffic. No redirects, credentials, or host MTU changes.
use super::{
    coverage::Availability,
    detectors::Detection,
    issue::{Cause, CheckResult, Evidence, Subject},
    probe_io::{self, Cancel},
};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pair {
    pub v4: SocketAddr,
    pub v6: SocketAddr,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpEndpoint {
    pub url: String,
    pub expect_status: u16,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub ipv6_pairs: Vec<Pair>,
    pub portal_endpoints: Vec<HttpEndpoint>,
    /// Plain HTTP resource that returns at least 4096 body bytes. A controlled
    /// endpoint is recommended. The probe downloads at most 64 KiB per request.
    pub pmtu_url: Option<String>,
    pub trace_target: String,
    /// Disabled by default. Automatic trace interval, 30–3600 seconds.
    pub trace_refresh_secs: Option<u64>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            ipv6_pairs: vec![
                Pair {
                    v4: "1.1.1.1:443".parse().unwrap(),
                    v6: "[2606:4700:4700::1111]:443".parse().unwrap(),
                },
                Pair {
                    v4: "8.8.8.8:443".parse().unwrap(),
                    v6: "[2001:4860:4860::8888]:443".parse().unwrap(),
                },
            ],
            portal_endpoints: vec![
                HttpEndpoint {
                    url: "http://connectivitycheck.gstatic.com/generate_204".into(),
                    expect_status: 204,
                },
                HttpEndpoint {
                    url: "http://cp.cloudflare.com/generate_204".into(),
                    expect_status: 204,
                },
            ],
            pmtu_url: None,
            trace_target: "1.1.1.1".into(),
            trace_refresh_secs: None,
        }
    }
}
fn endpoint(raw: &str) -> Result<url::Url, String> {
    let u = url::Url::parse(raw).map_err(|_| "invalid probe URL")?;
    if raw.len() > 2048
        || u.scheme() != "http"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
        || u.query().is_some()
    {
        return Err(
            "probe URL must be HTTP, at most 2048 bytes, without credentials, query or fragment"
                .into(),
        );
    }
    Ok(u)
}
impl Config {
    /// Seconds between automatic traces, or `None` when they do not run:
    /// no interval, one outside 30–3600, or a trace target that is not an
    /// IP address.
    pub fn periodic_trace_secs(&self) -> Option<u64> {
        self.trace_refresh_secs
            .filter(|s| (30..=3600).contains(s))
            .filter(|_| self.trace_target.parse::<std::net::IpAddr>().is_ok())
    }

    pub fn validate(&self, rule: &str) -> Result<(), String> {
        match rule {
            "ipv6.broken" => {
                let mut v4 = std::collections::BTreeSet::new();
                let mut v6 = std::collections::BTreeSet::new();
                if !(2..=4).contains(&self.ipv6_pairs.len()) {
                    return Err("configure 2–4 independent IPv4/IPv6 endpoint pairs".into());
                }
                for p in &self.ipv6_pairs {
                    if !p.v4.is_ipv4()
                        || !p.v6.is_ipv6()
                        || p.v4.port() == 0
                        || p.v6.port() == 0
                        || !v4.insert(p.v4.ip())
                        || !v6.insert(p.v6.ip())
                    {
                        return Err("comparison requires distinct IPs of the stated families and nonzero ports".into());
                    }
                }
            }
            "captive.portal" => {
                if !(2..=4).contains(&self.portal_endpoints.len()) {
                    return Err("configure 2–4 independent HTTP expected-response endpoints".into());
                }
                let mut hosts = std::collections::BTreeSet::new();
                for e in &self.portal_endpoints {
                    let u = endpoint(&e.url)?;
                    if !hosts.insert(u.host_str().unwrap().to_string())
                        || !(200..300).contains(&e.expect_status)
                    {
                        return Err(
                            "portal endpoints require distinct hosts and expected 2xx statuses"
                                .into(),
                        );
                    }
                }
            }
            "pmtu.blackhole" => {
                endpoint(self.pmtu_url.as_deref().ok_or(
                    "set diagnose_probes.pmtu_url to a plain HTTP resource of at least 4096 bytes",
                )?)?;
            }
            _ => return Err("unknown active check".into()),
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Healthy,
    Fault,
    Inconclusive,
    NotApplicable,
    PermissionDenied,
    Failed,
    /// This platform cannot run the experiment at all.
    Unsupported,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultObs {
    pub outcome: Outcome,
    /// Selected PMTU IP only; URLs and redirect locations are never retained.
    pub target: Option<String>,
    pub successes: u32,
    pub failures: u32,
    pub detail: String,
}
impl ResultObs {
    fn new(outcome: Outcome, detail: &str) -> Self {
        Self {
            outcome,
            target: None,
            successes: 0,
            failures: 0,
            detail: detail.into(),
        }
    }
    pub fn coverage(&self) -> (Availability, &'static str) {
        match self.outcome {
            Outcome::Healthy | Outcome::Fault => (Availability::Available,"completed experiment for selected endpoints; direct connections, no proxy or fallback"),
            Outcome::NotApplicable => (Availability::NotApplicable,"no usable IPv6 default-route/address context"),
            Outcome::PermissionDenied => (Availability::PermissionDenied,"probe capability denied; inspect experiment detail"),
            Outcome::Failed => (Availability::CollectorFailed,"experiment could not complete; inspect detail and retry"),
            Outcome::Unsupported if self.detail == PMTU_UNSUPPORTED => {
                (Availability::Unsupported, PMTU_UNSUPPORTED)
            }
            Outcome::Unsupported => (Availability::Unsupported, IPV6_UNSUPPORTED),
            Outcome::Inconclusive => (Availability::NotMeasured,"experiment inconclusive; endpoint, filtering, or multiple faults prevent attribution"),
        }
    }
}
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub ipv6: Option<ResultObs>,
    pub portal: Option<ResultObs>,
    pub pmtu: Option<ResultObs>,
}
impl Observation {
    pub fn get(&self, rule: &str) -> Option<&ResultObs> {
        match rule {
            "ipv6.broken" => self.ipv6.as_ref(),
            "captive.portal" => self.portal.as_ref(),
            "pmtu.blackhole" => self.pmtu.as_ref(),
            _ => None,
        }
    }
}
#[derive(Default)]
struct State {
    obs: Observation,
    times: super::engine::ObservationTimes,
    running: bool,
    cancel: Cancel,
    context: String,
    progress: String,
}
#[derive(Default)]
pub struct Runner {
    state: Arc<Mutex<State>>,
}
impl Drop for Runner {
    fn drop(&mut self) {
        self.cancel();
    }
}
impl Runner {
    pub fn context(&self, context: String) {
        let mut s = self.state.lock().unwrap();
        if s.context != context {
            s.cancel.cancel();
            s.obs = Observation::default();
            s.times = Default::default();
            s.context = context;
            s.progress = "network or configuration changed; rerun experiments".into();
        }
    }
    pub fn cancel(&self) {
        let mut s = self.state.lock().unwrap();
        s.cancel.cancel();
        s.obs = Observation::default();
        s.times = Default::default();
        s.progress = "active test cancelled; partial results discarded".into();
    }
    pub fn snapshot(&self) -> (Observation, super::engine::ObservationTimes, String) {
        let s = self.state.lock().unwrap();
        (s.obs.clone(), s.times.clone(), s.progress.clone())
    }
    pub fn start(&self, rule: &str, cfg: &Config) -> Result<(), String> {
        if let Some(why) = unsupported(rule) {
            return Err(why.into());
        }
        cfg.validate(rule)?;
        let mut s = self.state.lock().unwrap();
        if s.running {
            return Err("an active network test is already running; cancel it or wait".into());
        }
        s.running = true;
        s.cancel = Cancel::default();
        s.progress = format!("{rule}: round 1/3; bounded direct probes");
        let cancel = s.cancel.clone();
        let context = s.context.clone();
        drop(s);
        let state = self.state.clone();
        let cfg = cfg.clone();
        let rule = rule.to_string();
        crate::sandbox::worker::spawn("diagnose-active", move || {
            for round in 1..=3 {
                if cancel.cancelled() {
                    break;
                }
                let obs = run(&rule, &cfg, &cancel);
                if cancel.cancelled() {
                    break;
                }
                let mut s = state.lock().unwrap();
                if cancel.cancelled() || s.context != context {
                    break;
                }
                let at = Some(Instant::now());
                match rule.as_str() {
                    "ipv6.broken" => {
                        s.obs.ipv6 = Some(obs);
                        s.times.ipv6 = at;
                    }
                    "captive.portal" => {
                        s.obs.portal = Some(obs);
                        s.times.portal = at;
                    }
                    _ => {
                        s.obs.pmtu = Some(obs);
                        s.times.pmtu = at;
                    }
                }
                s.progress = format!("{rule}: round {round}/3 completed");
                drop(s);
                if round < 3 {
                    for _ in 0..150 {
                        if cancel.cancelled() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            state.lock().unwrap().running = false;
        });
        Ok(())
    }
}
fn connected(addr: SocketAddr, cancel: &Cancel) -> bool {
    !cancel.cancelled() && TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok()
}
/// Linux route and non-link-local address context. An absent default route is
/// not evidence of broken IPv6 on an IPv4-only network.
/// Why `ipv6.broken` cannot run off Linux: its route and address context
/// comes from `/proc`.
pub const IPV6_UNSUPPORTED: &str = "IPv6 route context is read only on Linux";

/// Whether `pmtu.blackhole` can run here. Its verdict rests on a transfer
/// that fails at the normal segment size and then succeeds at MSS 536 on the
/// same endpoint, and only Unix lets a program lower the MSS of one socket:
/// socket2's `set_tcp_mss` exists only there, and Windows' `TCP_MAXSEG` only
/// reports the MSS. DF pings through `IcmpSendEcho2` would run on Windows,
/// but without that corroboration the experiment could only come out healthy
/// or inconclusive, so a real black hole would read as "inconclusive" instead
/// of as a check this platform cannot make.
pub const PMTU_SUPPORTED: bool = cfg!(unix);
/// Why `pmtu.blackhole` cannot run on Windows.
pub const PMTU_UNSUPPORTED: &str =
    "the PMTU check confirms a black hole with a reduced TCP MSS, which Windows cannot set per socket";

/// Why `rule` cannot run on this platform, whatever the configuration says.
/// Checked before the configuration, so no setting is asked for that would
/// not make it runnable.
pub fn unsupported(rule: &str) -> Option<&'static str> {
    match rule {
        "ipv6.broken" if !cfg!(target_os = "linux") => Some(IPV6_UNSUPPORTED),
        "pmtu.blackhole" if !PMTU_SUPPORTED => Some(PMTU_UNSUPPORTED),
        _ => None,
    }
}

/// Whether this host has an IPv6 default route and a global address, so the
/// experiment means something. Off Linux, Unsupported.
fn ipv6_context() -> Result<bool, (Outcome, &'static str)> {
    if !cfg!(target_os = "linux") {
        return Err((Outcome::Unsupported, IPV6_UNSUPPORTED));
    }
    context_from(
        std::fs::read_to_string("/proc/net/ipv6_route"),
        std::fs::read_to_string("/proc/net/if_inet6"),
    )
}

/// [`ipv6_context`] from the two `/proc` files. A missing `if_inet6` means
/// the kernel has IPv6 off, which makes the experiment not applicable rather
/// than failed; any other read error is a failure.
fn context_from(
    routes: std::io::Result<String>,
    addrs: std::io::Result<String>,
) -> Result<bool, (Outcome, &'static str)> {
    let addrs = match addrs {
        Ok(addrs) => addrs,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err((Outcome::NotApplicable, "IPv6 is disabled in the kernel"))
        }
        Err(_) => return Err((Outcome::Failed, "IPv6 route context unavailable")),
    };
    let routes = routes.map_err(|_| (Outcome::Failed, "IPv6 route context unavailable"))?;
    let route = routes.lines().any(|l| {
        let f: Vec<_> = l.split_whitespace().collect();
        f.len() >= 10
            && f[0] == "00000000000000000000000000000000"
            && f[1] == "00"
            && f[9] != "lo"
            && u32::from_str_radix(f[8], 16).is_ok_and(|v| v & 1 != 0 && v & 0x200 == 0)
    });
    let address = addrs.lines().any(|l| {
        let f: Vec<_> = l.split_whitespace().collect();
        f.len() >= 6
            && f[3] == "00"
            && f[5] != "lo"
            && u32::from_str_radix(f[4], 16).is_ok_and(|v| v & 0x48 == 0)
    });
    Ok(route && address)
}
pub fn run(rule: &str, cfg: &Config, cancel: &Cancel) -> ResultObs {
    if rule == "ipv6.broken" && !cfg!(target_os = "linux") {
        return ResultObs::new(Outcome::Unsupported, IPV6_UNSUPPORTED);
    }
    if rule == "pmtu.blackhole" && !PMTU_SUPPORTED {
        return ResultObs::new(Outcome::Unsupported, PMTU_UNSUPPORTED);
    }
    if let Err(e) = cfg.validate(rule) {
        return ResultObs::new(Outcome::Failed, &e);
    }
    match rule {
        "ipv6.broken" => {
            match ipv6_context() {
                Ok(false) => {
                    return ResultObs::new(
                        Outcome::NotApplicable,
                        "IPv6 default route or global address absent",
                    )
                }
                Err((outcome, why)) => return ResultObs::new(outcome, why),
                Ok(true) => {}
            }
            let pairs: Vec<_> = cfg
                .ipv6_pairs
                .iter()
                .map(|p| (connected(p.v4, cancel), connected(p.v6, cancel)))
                .collect();
            ipv6_result(&pairs)
        }
        "captive.portal" => {
            let results: Vec<_> = cfg
                .portal_endpoints
                .iter()
                .map(|e| http(&e.url, None, None, 0, cancel).map(|r| (r.status, r.redirect)))
                .collect();
            portal_result(&results, &cfg.portal_endpoints)
        }
        _ => pmtu(cfg.pmtu_url.as_deref().unwrap(), cancel),
    }
}
fn ipv6_result(pairs: &[(bool, bool)]) -> ResultObs {
    let outcome = if pairs.len() >= 2 && pairs.iter().all(|p| *p == (true, false)) {
        Outcome::Fault
    } else if pairs.len() >= 2 && pairs.iter().all(|p| p.1) {
        Outcome::Healthy
    } else {
        Outcome::Inconclusive
    };
    let mut r=ResultObs::new(outcome,"paired TCP connections without address-family fallback; a single endpoint or both families failing is inconclusive");
    r.successes = pairs.iter().filter(|p| p.1).count() as u32;
    r.failures = pairs.iter().filter(|p| p.0 && !p.1).count() as u32;
    r
}
fn portal_result(results: &[Result<(u16, bool), String>], endpoints: &[HttpEndpoint]) -> ResultObs {
    let healthy = results.len() >= 2
        && results
            .iter()
            .zip(endpoints)
            .all(|(r, e)| matches!(r,Ok((status,_)) if *status==e.expect_status));
    let redirected = results.len() >= 2
        && results
            .iter()
            .all(|r| matches!(r,Ok((status,true)) if (300..400).contains(status)));
    let mut r=ResultObs::new(if healthy{Outcome::Healthy}else if redirected{Outcome::Fault}else{Outcome::Inconclusive},"independent expected-response HTTP endpoints; redirects not followed; status errors and timeouts alone do not prove a portal");
    r.successes = results
        .iter()
        .zip(endpoints)
        .filter(|(r, e)| matches!(r,Ok((s,_)) if *s==e.expect_status))
        .count() as u32;
    r.failures = results
        .iter()
        .filter(|r| matches!(r,Ok((s,true)) if (300..400).contains(s)))
        .count() as u32;
    r
}
struct HttpResult {
    status: u16,
    redirect: bool,
    body: usize,
}
fn http(
    raw: &str,
    pinned: Option<SocketAddr>,
    mss: Option<u32>,
    wanted: usize,
    cancel: &Cancel,
) -> Result<HttpResult, String> {
    let u = endpoint(raw)?;
    let host = u.host_str().unwrap().trim_matches(['[', ']']);
    let addr = match pinned {
        Some(a) => a,
        None => *probe_io::resolve(host, u.port_or_known_default().unwrap(), cancel)
            .map_err(|e| e.to_string())?
            .first()
            .ok_or("no addresses")?,
    };
    cancel
        .check(Instant::now() + Duration::from_secs(1))
        .map_err(|e| e.to_string())?;
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .map_err(|e| e.to_string())?;
    if let Some(mss) = mss {
        #[cfg(unix)]
        socket.set_tcp_mss(mss).map_err(|e| e.to_string())?;
        #[cfg(not(unix))]
        {
            let _ = mss;
            return Err("per-socket MSS experiment unsupported on this platform".into());
        }
    }
    socket
        .connect_timeout(&addr.into(), Duration::from_secs(2))
        .map_err(|e| e.to_string())?;
    let mut stream = probe_io::Stream::new(
        socket.into(),
        Instant::now() + Duration::from_secs(3),
        cancel.clone(),
    )
    .map_err(|e| e.to_string())?;
    let request=format!("GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: netwatch-diagnose\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",u.path(),u.authority());
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let mut chunk = [0; 2048];
    loop {
        let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("response ended before required bytes".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 65536 {
            return Err("HTTP response exceeds 64 KiB limit".into());
        }
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = std::str::from_utf8(&buf[..end]).map_err(|_| "invalid HTTP header")?;
            let status = head
                .lines()
                .next()
                .and_then(|s| s.split_whitespace().nth(1))
                .and_then(|s| s.parse().ok())
                .ok_or("invalid HTTP status")?;
            let redirect = head.lines().any(|l| {
                l.to_ascii_lowercase().starts_with("location:")
                    && l.split_once(':').is_some_and(|(_, v)| !v.trim().is_empty())
            });
            let body = buf.len() - end - 4;
            if body >= wanted {
                return Ok(HttpResult {
                    status,
                    redirect,
                    body,
                });
            }
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq)]
enum Ping {
    Reply,
    Timeout,
    TooBig,
    Unavailable,
    PermissionDenied,
}
/// One DF ping of `size` bytes, with iputils flags. Never reached on Windows,
/// where `pmtu.blackhole` is Unsupported before any probe runs.
fn ping(ip: &str, size: usize, cancel: &Cancel) -> Ping {
    let size = size.to_string();
    match probe_io::command(
        "ping",
        &["-n", "-c", "1", "-W", "1", "-M", "do", "-s", &size, ip],
        Duration::from_secs(2),
        cancel,
    ) {
        Ok((true, _)) => Ping::Reply,
        Ok((false, text))
            if text.contains("Frag needed")
                || text.contains("Packet too big")
                || text.contains("message too long") =>
        {
            Ping::TooBig
        }
        Ok((false, text))
            if text.contains("Operation not permitted") || text.contains("Permission denied") =>
        {
            Ping::PermissionDenied
        }
        Ok((false, _)) => Ping::Timeout,
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ping::Timeout,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ping::PermissionDenied,
        Err(_) => Ping::Unavailable,
    }
}
fn pmtu(raw: &str, cancel: &Cancel) -> ResultObs {
    let u = endpoint(raw).expect("validated URL");
    let addr = match probe_io::resolve(
        u.host_str().unwrap().trim_matches(['[', ']']),
        u.port_or_known_default().unwrap(),
        cancel,
    ) {
        Ok(a) => a[0],
        Err(e) => return ResultObs::new(Outcome::Failed, &e.to_string()),
    };
    let ip = addr.ip().to_string();
    let small = ping(&ip, 64, cancel);
    let large = ping(&ip, 1400, cancel);
    let normal =
        http(raw, Some(addr), None, 4096, cancel).is_ok_and(|r| r.status == 200 && r.body >= 4096);
    let reduced = if normal {
        false
    } else {
        http(raw, Some(addr), Some(536), 4096, cancel)
            .is_ok_and(|r| r.status == 200 && r.body >= 4096)
    };
    let mut r = pmtu_result(small, large, normal, reduced);
    r.detail.push_str(&format!("; small DF: {small:?}, large DF: {large:?}, normal transfer: {normal}, MSS 536 transfer: {reduced}"));
    r.target = Some(ip);
    r
}
fn pmtu_result(small: Ping, large: Ping, normal: bool, reduced: bool) -> ResultObs {
    let (outcome, detail) = if normal {
        (Outcome::Healthy,"normal TCP transfers at least 4096 bytes; tested path works, including any successful PMTU adaptation")
    } else if small == Ping::Reply && large == Ping::Timeout && reduced {
        (Outcome::Fault,"small DF ping succeeds, large DF ping times out, normal HTTP transfer fails, and the same pinned endpoint transfers 4096 bytes with MSS 536")
    } else if small == Ping::PermissionDenied || large == Ping::PermissionDenied {
        (
            Outcome::PermissionDenied,
            "ICMP socket capability denied; no PMTU fault established",
        )
    } else if large == Ping::TooBig {
        (
            Outcome::Inconclusive,
            "explicit packet-too-big response: smaller path MTU, not a silent PMTU blackhole",
        )
    } else {
        (Outcome::Inconclusive,"ICMP filtering, endpoint failure, or missing transport corroboration; no blackhole established")
    };
    ResultObs::new(outcome, detail)
}
pub fn detect(obs: &Observation) -> Vec<Detection> {
    let mut out = vec![];
    if obs
        .ipv6
        .as_ref()
        .is_some_and(|r| r.outcome == Outcome::Fault)
    {
        let mut d = Detection::new("ipv6.broken", Subject::Host);
        d.evidence
            .push(Evidence::new("ipv6.probe_loss", 100.0, "%"));
        d.causes.push(Cause::new(
            "ipv6_path_failure",
            "IPv6 connections fail to independent paired endpoints",
            vec![CheckResult::pass(
                "paired_family_failures",
                "IPv4 works while IPv6 fails",
                "IPv6 default route and address present; no fallback used",
            )],
        ));
        out.push(d);
    }
    if obs
        .portal
        .as_ref()
        .is_some_and(|r| r.outcome == Outcome::Fault)
    {
        let mut d = Detection::new("captive.portal", Subject::Host);
        d.title = "HTTP interception suspected at independent connectivity endpoints".into();
        d.evidence.push(Evidence::new("captive.probe_204", 0.0, ""));
        d.causes.push(Cause::new(
            "http_interception",
            "connectivity endpoints redirect unexpectedly",
            vec![CheckResult::pass(
                "independent_http_redirects",
                "independent endpoints returned redirects",
                "No login attempted or redirect followed; does not suppress unrelated failures",
            )],
        ));
        out.push(d);
    }
    if let Some(r) = obs.pmtu.as_ref().filter(|r| r.outcome == Outcome::Fault) {
        if let Some(target) = &r.target {
            let mut d = Detection::new(
                "pmtu.blackhole",
                Subject::Path {
                    target: target.clone(),
                },
            );
            d.evidence.push(Evidence::new("pmtu.transfer_ok", 0.0, ""));
            d.causes.push(Cause::new("size_dependent_path_failure","small packets work and reduced TCP MSS restores transfer",vec![CheckResult::pass("mss_restores_transfer","same pinned endpoint works with MSS 536","Small/large DF comparison plus transport corroboration; scoped to this endpoint")]));
            out.push(d);
        }
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_and_network_change_discard_inflight_results() {
        let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = Config {
            portal_endpoints: vec![
                HttpEndpoint {
                    url: format!("http://127.0.0.1:{port}/"),
                    expect_status: 204,
                },
                HttpEndpoint {
                    url: format!("http://127.0.0.2:{port}/"),
                    expect_status: 204,
                },
            ],
            ..Default::default()
        };
        let runner = Runner::default();
        runner.context("network one".into());
        runner.start("captive.portal", &cfg).unwrap();
        assert!(runner.start("captive.portal", &cfg).is_err());
        std::thread::sleep(Duration::from_millis(30));
        runner.context("network two".into());
        let start = Instant::now();
        while runner.state.lock().unwrap().running && start.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!runner.state.lock().unwrap().running);
        assert_eq!(runner.snapshot().0, Observation::default());
        runner.start("captive.portal", &cfg).unwrap();
        runner.cancel();
        assert_eq!(runner.snapshot().0, Observation::default());
    }
    #[test]
    fn unsupported_outcome_maps_to_unsupported_coverage() {
        let obs = ResultObs::new(Outcome::Unsupported, IPV6_UNSUPPORTED);
        assert_eq!(
            obs.coverage(),
            (Availability::Unsupported, IPV6_UNSUPPORTED)
        );
    }
    #[test]
    fn each_unsupported_experiment_keeps_its_own_reason() {
        let pmtu = ResultObs::new(Outcome::Unsupported, PMTU_UNSUPPORTED);
        assert_eq!(
            pmtu.coverage(),
            (Availability::Unsupported, PMTU_UNSUPPORTED)
        );
        assert_ne!(PMTU_UNSUPPORTED, IPV6_UNSUPPORTED);
    }
    #[test]
    fn only_the_platform_makes_an_experiment_unsupported() {
        assert_eq!(unsupported("pmtu.blackhole").is_some(), !PMTU_SUPPORTED);
        assert_eq!(
            unsupported("ipv6.broken").is_some(),
            !cfg!(target_os = "linux")
        );
        assert_eq!(unsupported("captive.portal"), None);
    }
    #[cfg(windows)]
    #[test]
    fn pmtu_experiment_refuses_to_start_on_windows() {
        let cfg = Config {
            pmtu_url: Some("http://192.0.2.10:8080/test-data".into()),
            ..Default::default()
        };
        let runner = Runner::default();
        assert_eq!(
            runner.start("pmtu.blackhole", &cfg),
            Err(PMTU_UNSUPPORTED.to_string())
        );
        // Unconfigured, it still says why, not "set pmtu_url".
        assert_eq!(
            runner.start("pmtu.blackhole", &Config::default()),
            Err(PMTU_UNSUPPORTED.to_string())
        );
        // Not even a DNS lookup or a ping: the answer is the platform's.
        let obs = run("pmtu.blackhole", &cfg, &Cancel::default());
        assert_eq!(obs.outcome, Outcome::Unsupported);
        assert_eq!(obs.coverage().1, PMTU_UNSUPPORTED);
    }
    #[test]
    fn missing_ipv6_proc_files_mean_not_applicable() {
        use std::io::{Error, ErrorKind};
        let missing = || Err(Error::from(ErrorKind::NotFound));
        assert_eq!(
            context_from(missing(), missing()).unwrap_err().0,
            Outcome::NotApplicable
        );
        assert_eq!(
            context_from(
                Ok(String::new()),
                Err(Error::from(ErrorKind::PermissionDenied))
            )
            .unwrap_err()
            .0,
            Outcome::Failed
        );
        assert_eq!(
            context_from(Ok(String::new()), Ok(String::new())),
            Ok(false)
        );
        let route = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
                     fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0";
        let addr = "20010db8000000000000000000000001 02 40 00 00 eth0";
        assert_eq!(context_from(Ok(route.into()), Ok(addr.into())), Ok(true));
    }
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn ipv6_experiment_refuses_to_start_off_linux() {
        let runner = Runner::default();
        assert_eq!(
            runner.start("ipv6.broken", &Config::default()),
            Err(IPV6_UNSUPPORTED.to_string())
        );
        let obs = run("ipv6.broken", &Config::default(), &Cancel::default());
        assert_eq!(obs.outcome, Outcome::Unsupported);
    }
    #[test]
    fn missing_icmp_capability_cannot_be_a_blackhole() {
        assert_eq!(
            pmtu_result(Ping::PermissionDenied, Ping::PermissionDenied, false, true).outcome,
            Outcome::PermissionDenied
        );
        assert_eq!(
            pmtu_result(Ping::Unavailable, Ping::Unavailable, false, true).outcome,
            Outcome::Inconclusive
        );
    }
    #[test]
    fn paired_family_outcomes() {
        assert_eq!(
            ipv6_result(&[(true, false), (true, false)]).outcome,
            Outcome::Fault
        );
        for p in [
            vec![(true, false)],
            vec![(false, false), (false, false)],
            vec![(true, false), (true, true)],
        ] {
            assert_eq!(ipv6_result(&p).outcome, Outcome::Inconclusive);
        }
        assert_eq!(
            ipv6_result(&[(true, true), (true, true)]).outcome,
            Outcome::Healthy
        );
    }
    #[test]
    fn portal_errors_are_not_redirects() {
        let e = Config::default().portal_endpoints;
        assert_eq!(
            portal_result(&[Ok((302, true)), Ok((307, true))], &e).outcome,
            Outcome::Fault
        );
        for rs in [
            vec![Ok((500, false)), Ok((500, false))],
            vec![Ok((302, true)), Err("timeout".into())],
            vec![Ok((200, false)), Ok((200, false))],
        ] {
            assert_eq!(portal_result(&rs, &e).outcome, Outcome::Inconclusive);
        }
        assert_eq!(
            portal_result(&[Ok((204, false)), Ok((204, false))], &e).outcome,
            Outcome::Healthy
        );
    }
    #[test]
    fn pmtu_requires_transport_corroboration() {
        assert_eq!(
            pmtu_result(Ping::Reply, Ping::Timeout, false, true).outcome,
            Outcome::Fault
        );
        for (s, l, n, r) in [
            (Ping::Reply, Ping::Timeout, false, false),
            (Ping::Timeout, Ping::Timeout, false, true),
            (Ping::Reply, Ping::TooBig, false, true),
        ] {
            assert_ne!(pmtu_result(s, l, n, r).outcome, Outcome::Fault);
        }
        assert_eq!(
            pmtu_result(Ping::Timeout, Ping::Timeout, true, false).outcome,
            Outcome::Healthy
        );
    }
    #[test]
    fn credentials_queries_duplicates_rejected() {
        for u in [
            "http://user:pass@host/",
            "http://host/?secret=x",
            "https://host/",
        ] {
            assert!(endpoint(u).is_err());
        }
        let mut c = Config::default();
        c.ipv6_pairs[1] = c.ipv6_pairs[0].clone();
        assert!(c.validate("ipv6.broken").is_err());
    }
}
