//! Discriminating tests: when two causes fit the evidence, run the cheapest
//! measurement that tells them apart.
//!
//! ```text
//!   Issue ── suggest ──▶ TestSpec ── run (worker) ──▶ TestRun
//!     ▲                                                  │
//!     └──────── apply: one CheckResult per cause ◀───────┘
//! ```
//!
//! Every test answers one yes/no question ("does the reference resolver
//! answer quickly?"). [`TESTS`] records, per cause, which answer that cause
//! predicts. A run becomes a `test_<id>` check on each cause with a
//! prediction — passed when the answer matched it — so ranking, the report
//! and the feature vector all see test evidence the same way as detector
//! evidence.
//!
//! Selection is authored, not learned: among causes still in contention, a
//! test's value is how many pairs of them it separates, divided by what it
//! costs to run. That table is also the slot a learned policy fills later.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::issue::{Capability, CheckResult, Issue};

thread_local! { static PROBE_CANCEL: std::cell::RefCell<super::probe_io::Cancel> = std::cell::RefCell::new(super::probe_io::Cancel::default()); }
fn cancelled() -> bool {
    PROBE_CANCEL.with(|c| c.borrow().cancelled())
}
fn cancellation() -> super::probe_io::Cancel {
    PROBE_CANCEL.with(|c| c.borrow().clone())
}

/// Test results older than this no longer count as evidence.
pub const VALID_SECS: i64 = 15 * 60;
/// Causes this close to the top score are still in contention.
pub const CONTENTION: f64 = 0.2;
/// Weight of a test check against a detector check's 1.0: a test was run on
/// purpose to decide between causes.
pub const TEST_WEIGHT: f64 = 2.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cost {
    pub secs: u32,
    pub bytes: u64,
    pub privileged: bool,
    /// Uses enough of the link to be felt, or sends traffic to a third party.
    pub disruptive: bool,
}

impl Cost {
    /// Seconds, with privilege and disruption priced as if they took longer.
    pub fn weight(&self) -> f64 {
        f64::from(self.secs.max(1))
            + if self.privileged { 10.0 } else { 0.0 }
            + if self.disruptive { 30.0 } else { 0.0 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expect {
    pub rule: &'static str,
    pub cause: &'static str,
    /// The answer this cause predicts.
    pub positive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TestSpec {
    pub id: &'static str,
    /// The yes/no question, as a check name.
    pub question: &'static str,
    /// What running it does, for the button's tooltip.
    pub does: &'static str,
    pub cost: Cost,
    /// Never suggested automatically; offered only when asked.
    pub manual_only: bool,
    pub expects: &'static [Expect],
}

const fn cheap(secs: u32) -> Cost {
    Cost {
        secs,
        bytes: 2_000,
        privileged: false,
        disruptive: false,
    }
}

const fn e(rule: &'static str, cause: &'static str, positive: bool) -> Expect {
    Expect {
        rule,
        cause,
        positive,
    }
}

pub const TESTS: &[TestSpec] = &[
    TestSpec {
        id: "dns.alt_resolver",
        question: "a reference resolver answers quickly",
        does: "asks the same name of your resolver and of 1.1.1.1, three times each",
        cost: cheap(3),
        manual_only: false,
        expects: &[
            e("dns.slow_resolver", "upstream_slow", true),
            e("dns.slow_resolver", "resolver_overloaded", true),
            e("dns.slow_resolver", "local_udp_path", false),
            e("dns.failing", "resolver_down", true),
            e("dns.failing", "udp53_filtered", false),
        ],
    },
    TestSpec {
        id: "dns.tcp_fallback",
        question: "the resolver answers over tcp",
        does: "sends one query to your resolver over TCP port 53",
        cost: cheap(2),
        manual_only: false,
        expects: &[
            e("dns.failing", "udp53_filtered", true),
            e("dns.failing", "resolver_down", false),
        ],
    },
    TestSpec {
        id: "dns.cached_vs_cold",
        question: "cached names answer far faster than new ones",
        does: "times a name your resolver has cached against one it has to look up",
        cost: cheap(3),
        manual_only: false,
        expects: &[
            e("dns.slow_resolver", "upstream_slow", true),
            e("dns.slow_resolver", "resolver_overloaded", false),
            e("dns.slow_resolver", "local_udp_path", false),
        ],
    },
    TestSpec {
        id: "dns.nxdomain_probe",
        question: "a name that cannot exist gets an address",
        does: "asks your resolver for a random name that does not exist",
        cost: cheap(2),
        manual_only: false,
        expects: &[
            e("dns.hijack_suspect", "interceptor", true),
            e("dns.hijack_suspect", "forged_records", false),
            e("dns.hijack_suspect", "split_horizon", false),
        ],
    },
    TestSpec {
        id: "gateway.tcp_probe",
        question: "the gateway answers on a tcp port",
        does: "opens TCP connections to the gateway on ports 80, 443, 53 and 22",
        cost: cheap(4),
        manual_only: false,
        expects: &[
            e("gateway.unreachable", "icmp_filtered", true),
            e("gateway.unreachable", "wrong_vlan_or_address_conflict", false),
        ],
    },
    TestSpec {
        id: "path.internet_tracks_gateway",
        question: "internet latency rose with gateway latency",
        does: "times TCP connections to 1.1.1.1 and compares the rise with the gateway's",
        cost: cheap(3),
        manual_only: false,
        expects: &[
            e("gateway.rtt_spike", "local_network_congested", true),
            e("gateway.rtt_spike", "gateway_loaded", false),
        ],
    },
    TestSpec {
        id: "path.end_to_end_loss",
        question: "connections to the destination are being lost",
        does: "opens 20 TCP connections to the traced destination and counts the ones that never answer",
        cost: cheap(14),
        manual_only: false,
        expects: &[
            e("path.high_loss", "hop_dropping", true),
            e("path.high_loss", "icmp_rate_limit", false),
        ],
    },
    TestSpec {
        id: "load.idle_vs_loaded",
        question: "our uplink stays responsive under load",
        does: "times connections while idle, then while uploading up to 25 MB to speed.cloudflare.com for 10 seconds",
        cost: Cost {
            secs: 15,
            bytes: 25_000_000,
            privileged: false,
            disruptive: true,
        },
        manual_only: true,
        expects: &[e("tcp.bufferbloat_remote", "receiver_queueing", true)],
    },
];

pub fn lookup(id: &str) -> Option<&'static TestSpec> {
    TESTS.iter().find(|t| t.id == id)
}

/// `dns.alt_resolver` → `test_dns_alt_resolver`, the check id a run becomes.
pub fn check_id(test: &str) -> String {
    format!("test_{}", test.replace('.', "_"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Positive,
    Negative,
    /// Ran, but the answer couldn't be told (no baseline, no reply at all).
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestRun {
    pub test: String,
    /// Local timestamp the run finished.
    pub at: String,
    pub outcome: Outcome,
    /// What was measured, in words, e.g. "1.1.1.1 answered in 14ms".
    pub detail: String,
    #[serde(default)]
    pub measurements: BTreeMap<String, f64>,
    /// Run to verify a fix rather than to choose a cause.
    #[serde(default)]
    pub after_action: bool,
}

/// The latest still-valid, conclusive run of each test on `issue`.
pub fn latest_runs<'a>(issue: &'a Issue, now: &str) -> Vec<&'a TestRun> {
    let now = super::engine::parse_ts(now);
    let mut latest: BTreeMap<&str, &TestRun> = BTreeMap::new();
    for run in &issue.tests {
        let fresh = match (now, super::engine::parse_ts(&run.at)) {
            (Some(now), Some(at)) => (now - at).num_seconds() <= VALID_SECS,
            _ => true,
        };
        if !fresh {
            continue;
        }
        // An inconclusive re-run retracts the earlier answer instead of being
        // ignored. Skipping it left the superseded result ranking causes and
        // stopped the test being offered again, so a test that stopped
        // working kept voting on its own last good day.
        if run.outcome == Outcome::Inconclusive {
            latest.remove(run.test.as_str());
        } else {
            latest.insert(run.test.as_str(), run);
        }
    }
    latest.into_values().collect()
}

/// Add test evidence to the issue's causes and re-rank. Called after every
/// merge, because the detectors rebuild causes from scratch each tick.
pub fn apply(issue: &mut Issue, now: &str) {
    let runs: Vec<TestRun> = latest_runs(issue, now).into_iter().cloned().collect();
    for run in &runs {
        let Some(spec) = lookup(&run.test) else {
            continue;
        };
        let id = check_id(spec.id);
        for cause in &mut issue.causes {
            let Some(expect) = spec
                .expects
                .iter()
                .find(|x| x.rule == issue.rule && x.cause == cause.id)
            else {
                continue;
            };
            let positive = run.outcome == Outcome::Positive;
            let check = if positive == expect.positive {
                CheckResult::pass(&id, spec.question, run.detail.clone())
            } else {
                CheckResult::fail(&id, spec.question, run.detail.clone())
            }
            .weighted(TEST_WEIGHT);
            cause.checks.retain(|c| c.id != id);
            cause.checks.push(check);
        }
    }
    issue.rank_causes();
}

#[derive(Debug, Clone, PartialEq)]
pub struct Suggestion {
    pub test: &'static TestSpec,
    /// Pairs of cause ids the test separates.
    pub separates: Vec<(&'static str, &'static str)>,
    pub score: f64,
}

/// Tests that apply to the issue's rule, runnable with `cap`.
pub fn offered(issue: &Issue, cap: Capability) -> Vec<&'static TestSpec> {
    TESTS
        .iter()
        .filter(|t| t.expects.iter().any(|x| x.rule == issue.rule))
        .filter(|t| !t.cost.privileged || cap != Capability::None)
        .collect()
}

/// The next test worth running, if any separates causes still in contention
/// and hasn't already answered within [`VALID_SECS`].
pub fn suggest(issue: &Issue, cap: Capability, now: &str) -> Option<Suggestion> {
    let top = issue
        .causes
        .iter()
        .filter_map(|c| c.score())
        .fold(None, |m: Option<f64>, s| Some(m.map_or(s, |m| m.max(s))));
    let contending: Vec<&str> = issue
        .causes
        .iter()
        .filter(|c| match (c.score(), top) {
            (Some(s), Some(t)) => s >= t - CONTENTION,
            _ => true,
        })
        .map(|c| c.id.as_str())
        .collect();
    if contending.len() < 2 {
        return None;
    }
    let answered: Vec<&str> = latest_runs(issue, now)
        .iter()
        .map(|r| r.test.as_str())
        .collect();

    let mut best: Option<Suggestion> = None;
    for spec in offered(issue, cap) {
        if spec.manual_only || answered.contains(&spec.id) {
            continue;
        }
        let predictions: Vec<&Expect> = spec
            .expects
            .iter()
            .filter(|x| x.rule == issue.rule && contending.contains(&x.cause))
            .collect();
        let mut separates = Vec::new();
        for (i, a) in predictions.iter().enumerate() {
            for b in &predictions[i + 1..] {
                if a.positive != b.positive {
                    separates.push((a.cause, b.cause));
                }
            }
        }
        if separates.is_empty() {
            continue;
        }
        let score = separates.len() as f64 / spec.cost.weight();
        let better = best.as_ref().is_none_or(|b| {
            score > b.score || (score == b.score && spec.cost.weight() < b.test.cost.weight())
        });
        if better {
            best = Some(Suggestion {
                test: spec,
                separates,
                score,
            });
        }
    }
    best
}

// ------------------------------------------------------------------ running

/// What a test needs to know about the host, captured when it starts.
#[derive(Debug, Clone, PartialEq)]
pub struct Context {
    pub resolver: Option<IpAddr>,
    pub reference: IpAddr,
    pub gateway: Option<IpAddr>,
    /// Destination for path tests: the issue's traced target, else the
    /// internet probe target.
    pub target: IpAddr,
    pub gateway_rtt_ms: Option<f64>,
    pub gateway_baseline_ms: Option<f64>,
    pub path_baseline_ms: Option<f64>,
    pub loaded_rtt_delta_ms: f64,
    pub upload_url: String,
    pub upload_bytes: u64,
}

impl Context {
    pub fn new(reference: IpAddr) -> Self {
        Self {
            resolver: None,
            reference,
            gateway: None,
            target: reference,
            gateway_rtt_ms: None,
            gateway_baseline_ms: None,
            path_baseline_ms: None,
            loaded_rtt_delta_ms: super::detectors::Thresholds::default().loaded_rtt_delta_ms,
            upload_url: "https://speed.cloudflare.com/__up".into(),
            upload_bytes: 25_000_000,
        }
    }
}

/// Run `test` to completion. Blocking; call from a worker thread.
pub fn run(test: &str, ctx: &Context, now: impl Fn() -> String) -> TestRun {
    let (mut outcome, mut detail, mut measurements) = match test {
        "dns.alt_resolver" => alt_resolver(ctx),
        "dns.tcp_fallback" => tcp_fallback(ctx),
        "dns.cached_vs_cold" => cached_vs_cold(ctx),
        "dns.nxdomain_probe" => nxdomain_probe(ctx),
        "gateway.tcp_probe" => gateway_tcp(ctx),
        "path.internet_tracks_gateway" => internet_tracks_gateway(ctx),
        "path.end_to_end_loss" => end_to_end_loss(ctx),
        "load.idle_vs_loaded" => idle_vs_loaded(ctx),
        other => (
            Outcome::Inconclusive,
            format!("no test named {other}"),
            BTreeMap::new(),
        ),
    };
    if cancelled() {
        outcome = Outcome::Inconclusive;
        detail = "test cancelled; partial measurements discarded".into();
        measurements.clear();
    }
    TestRun {
        test: test.to_string(),
        at: now(),
        outcome,
        detail,
        measurements,
        after_action: false,
    }
}

type Result3 = (Outcome, String, BTreeMap<String, f64>);

fn measured(pairs: &[(&str, Option<f64>)]) -> BTreeMap<String, f64> {
    pairs
        .iter()
        .filter_map(|(k, v)| v.map(|v| (k.to_string(), v)))
        .collect()
}

fn median(mut v: Vec<f64>) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    Some(v[v.len() / 2])
}

fn fmt_ms(v: Option<f64>) -> String {
    v.map_or("no reply".into(), |v| format!("{v:.0}ms"))
}

fn random_label() -> String {
    format!("nw{}", &uuid::Uuid::new_v4().simple().to_string()[..16])
}

/// One UDP query; the round trip in ms and the reply.
fn udp_query(server: SocketAddr, name: &str) -> Option<(f64, crate::collectors::health::DnsReply)> {
    use crate::collectors::health::{build_dns_query, dns_exchange, dns_socket};
    if cancelled() {
        return None;
    }
    let sock = dns_socket(server.ip())?;
    let id = (uuid::Uuid::new_v4().as_u128() & 0xffff) as u16;
    let query = build_dns_query(id, name, 1, false);
    dns_exchange(&sock, server, &query, id).map(|(r, ms)| (ms, r))
}

fn udp_times(server: SocketAddr, name: &str, n: usize) -> Vec<f64> {
    (0..n)
        .filter_map(|_| udp_query(server, name).map(|(ms, _)| ms))
        .collect()
}

/// A query over TCP: two-byte length prefix each way.
fn tcp_query(server: SocketAddr, name: &str, timeout: Duration) -> Option<f64> {
    use std::io::{Read, Write};
    let started = Instant::now();
    if cancelled() {
        return None;
    }
    let tcp = std::net::TcpStream::connect_timeout(&server, timeout).ok()?;
    let mut stream = super::probe_io::Stream::new(tcp, started + timeout, cancellation()).ok()?;
    let id = (uuid::Uuid::new_v4().as_u128() & 0xffff) as u16;
    let query = crate::collectors::health::build_dns_query(id, name, 1, false);
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&query);
    stream.write_all(&framed).ok()?;
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).ok()?;
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).ok()?;
    let reply = crate::collectors::health::parse_dns_reply(&body)?;
    (reply.id == id).then(|| started.elapsed().as_secs_f64() * 1000.0)
}

/// Positive when the reference answered within half the resolver's time, or
/// within 25ms. A public reference sits 10–20ms away on most connections, so a
/// ratio alone would call a 13ms reference "slow" next to a 40ms resolver.
pub fn decide_alt(resolver_ms: Option<f64>, reference_ms: Option<f64>) -> Outcome {
    match (resolver_ms, reference_ms) {
        (_, None) => Outcome::Negative,
        (None, Some(_)) => Outcome::Positive,
        (Some(r), Some(a)) => {
            if a <= (r * 0.5).max(25.0) {
                Outcome::Positive
            } else {
                Outcome::Negative
            }
        }
    }
}

fn alt_resolver(ctx: &Context) -> Result3 {
    let Some(resolver) = ctx.resolver else {
        return (
            Outcome::Inconclusive,
            "no resolver to compare".into(),
            BTreeMap::new(),
        );
    };
    let name = crate::collectors::health::CROSS_CHECK_NAME;
    let r = median(udp_times(SocketAddr::new(resolver, 53), name, 3));
    let a = median(udp_times(SocketAddr::new(ctx.reference, 53), name, 3));
    (
        decide_alt(r, a),
        format!(
            "your resolver {}, {} {}",
            fmt_ms(r),
            ctx.reference,
            fmt_ms(a)
        ),
        measured(&[("resolver_ms", r), ("reference_ms", a)]),
    )
}

fn tcp_fallback(ctx: &Context) -> Result3 {
    let Some(resolver) = ctx.resolver else {
        return (
            Outcome::Inconclusive,
            "no resolver to query".into(),
            BTreeMap::new(),
        );
    };
    let ms = tcp_query(
        SocketAddr::new(resolver, 53),
        crate::collectors::health::CROSS_CHECK_NAME,
        Duration::from_secs(2),
    );
    let outcome = if ms.is_some() {
        Outcome::Positive
    } else {
        Outcome::Negative
    };
    (
        outcome,
        match ms {
            Some(ms) => format!("answered over tcp in {ms:.0}ms"),
            None => "no answer over tcp within 2s".into(),
        },
        measured(&[("tcp_ms", ms)]),
    )
}

pub fn decide_cached(warm_ms: Option<f64>, cold_ms: Option<f64>) -> Outcome {
    match (warm_ms, cold_ms) {
        (Some(w), Some(c)) if c >= 20.0 && w <= c / 4.0 => Outcome::Positive,
        (Some(_), Some(c)) if c >= 20.0 => Outcome::Negative,
        // Both fast, or nothing answered: this can't tell the causes apart.
        _ => Outcome::Inconclusive,
    }
}

fn cached_vs_cold(ctx: &Context) -> Result3 {
    let Some(resolver) = ctx.resolver else {
        return (
            Outcome::Inconclusive,
            "no resolver to query".into(),
            BTreeMap::new(),
        );
    };
    let server = SocketAddr::new(resolver, 53);
    let name = crate::collectors::health::CROSS_CHECK_NAME;
    let _ = udp_query(server, name);
    let warm = median(udp_times(server, name, 2));
    let cold = udp_query(server, &format!("{}.google.com", random_label())).map(|(ms, _)| ms);
    (
        decide_cached(warm, cold),
        format!(
            "cached name {}, uncached name {}",
            fmt_ms(warm),
            fmt_ms(cold)
        ),
        measured(&[("warm_ms", warm), ("cold_ms", cold)]),
    )
}

fn nxdomain_probe(ctx: &Context) -> Result3 {
    let Some(resolver) = ctx.resolver else {
        return (
            Outcome::Inconclusive,
            "no resolver to query".into(),
            BTreeMap::new(),
        );
    };
    let name = format!("{}.com", random_label());
    match udp_query(SocketAddr::new(resolver, 53), &name) {
        None => (Outcome::Inconclusive, "no reply".into(), BTreeMap::new()),
        Some((ms, reply)) if !reply.answers.is_empty() => (
            Outcome::Positive,
            format!("a random name got {} address(es)", reply.answers.len()),
            measured(&[
                ("rtt_ms", Some(ms)),
                ("answers", Some(reply.answers.len() as f64)),
            ]),
        ),
        Some((ms, reply)) => (
            Outcome::Negative,
            format!("a random name got rcode {} and no address", reply.rcode),
            measured(&[("rtt_ms", Some(ms)), ("answers", Some(0.0))]),
        ),
    }
}

fn gateway_tcp(ctx: &Context) -> Result3 {
    let Some(gw) = ctx.gateway else {
        return (
            Outcome::Inconclusive,
            "no gateway configured".into(),
            BTreeMap::new(),
        );
    };
    for port in [80u16, 443, 53, 22] {
        if cancelled() {
            break;
        }
        let (rtt, loss) = crate::collectors::health::run_tcp_probe_port(gw, port);
        if loss < 100.0 {
            return (
                Outcome::Positive,
                format!("port {port} answered in {}", fmt_ms(rtt)),
                measured(&[("rtt_ms", rtt), ("port", Some(f64::from(port)))]),
            );
        }
    }
    (
        Outcome::Negative,
        "no answer on ports 80, 443, 53 or 22".into(),
        BTreeMap::new(),
    )
}

fn connect_times(dest: SocketAddr, n: usize, timeout: Duration) -> (Vec<f64>, usize) {
    let mut times = Vec::new();
    let mut lost = 0;
    for _ in 0..n {
        if cancelled() {
            break;
        }
        let t = Instant::now();
        match std::net::TcpStream::connect_timeout(&dest, timeout) {
            Ok(_) => times.push(t.elapsed().as_secs_f64() * 1000.0),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                times.push(t.elapsed().as_secs_f64() * 1000.0)
            }
            Err(_) => lost += 1,
        }
    }
    (times, lost)
}

pub fn decide_tracks(
    gateway_now: f64,
    gateway_base: f64,
    internet_now: f64,
    internet_base: f64,
) -> Outcome {
    let gw_rise = gateway_now - gateway_base;
    if gw_rise <= 1.0 {
        return Outcome::Inconclusive;
    }
    if internet_now - internet_base >= 0.5 * gw_rise {
        Outcome::Positive
    } else {
        Outcome::Negative
    }
}

fn internet_tracks_gateway(ctx: &Context) -> Result3 {
    let (Some(gw_now), Some(gw_base), Some(net_base)) = (
        ctx.gateway_rtt_ms,
        ctx.gateway_baseline_ms,
        ctx.path_baseline_ms,
    ) else {
        return (
            Outcome::Inconclusive,
            "needs gateway and internet baselines".into(),
            BTreeMap::new(),
        );
    };
    let (times, _) = connect_times(
        SocketAddr::new(ctx.reference, 443),
        5,
        Duration::from_secs(2),
    );
    let Some(net_now) = median(times) else {
        return (
            Outcome::Inconclusive,
            "internet target did not answer".into(),
            BTreeMap::new(),
        );
    };
    (
        decide_tracks(gw_now, gw_base, net_now, net_base),
        format!("gateway {gw_base:.0}→{gw_now:.0}ms, internet {net_base:.0}→{net_now:.0}ms"),
        measured(&[("internet_ms", Some(net_now)), ("gateway_ms", Some(gw_now))]),
    )
}

pub fn decide_loss(lost: usize, total: usize) -> Outcome {
    if total == 0 || lost == total {
        return Outcome::Inconclusive;
    }
    if lost * 10 >= total {
        Outcome::Positive
    } else {
        Outcome::Negative
    }
}

fn end_to_end_loss(ctx: &Context) -> Result3 {
    const N: usize = 20;
    let mut port = 443;
    let (mut times, mut lost) = connect_times(
        SocketAddr::new(ctx.target, port),
        3,
        Duration::from_millis(700),
    );
    if times.is_empty() {
        port = 80;
        (times, lost) = (Vec::new(), 0);
    }
    let (t, l) = connect_times(
        SocketAddr::new(ctx.target, port),
        N,
        Duration::from_millis(700),
    );
    times.extend(t);
    lost += l;
    let total = times.len() + lost;
    (
        decide_loss(lost, total),
        format!(
            "{lost} of {total} connections to {}:{port} never answered",
            ctx.target
        ),
        measured(&[
            ("lost", Some(lost as f64)),
            ("total", Some(total as f64)),
            (
                "loss_pct",
                (total > 0).then(|| lost as f64 / total as f64 * 100.0),
            ),
        ]),
    )
}

pub fn decide_load(idle_ms: f64, loaded_ms: f64, delta_ms: f64) -> Outcome {
    if loaded_ms - idle_ms < delta_ms {
        Outcome::Positive
    } else {
        Outcome::Negative
    }
}

fn idle_vs_loaded(ctx: &Context) -> Result3 {
    let dest = SocketAddr::new(ctx.reference, 443);
    let (idle, _) = connect_times(dest, 5, Duration::from_secs(2));
    let Some(idle) = median(idle) else {
        return (
            Outcome::Inconclusive,
            "no idle measurement".into(),
            BTreeMap::new(),
        );
    };

    struct Zeros {
        cancel: super::probe_io::Cancel,
        left: u64,
        until: Instant,
    }
    impl std::io::Read for Zeros {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.cancel.cancelled() {
                return Err(std::io::Error::other("upload cancelled"));
            }
            if self.left == 0 || Instant::now() >= self.until {
                return Ok(0);
            }
            let n = buf.len().min(self.left as usize);
            buf[..n].fill(0);
            self.left -= n as u64;
            Ok(n)
        }
    }
    let url = ctx.upload_url.clone();
    let bytes = ctx.upload_bytes;
    let cancel = cancellation();
    let upload = std::thread::spawn(move || {
        let body = Zeros {
            cancel: cancel.clone(),
            left: bytes,
            until: Instant::now() + Duration::from_secs(10),
        };
        ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(14))
            .redirects(0)
            .resolver(move |netloc: &str| {
                let u =
                    url::Url::parse(&format!("http://{netloc}")).map_err(std::io::Error::other)?;
                super::probe_io::resolve(
                    u.host_str().unwrap_or("").trim_matches(['[', ']']),
                    u.port_or_known_default().unwrap_or(80),
                    &cancel,
                )
            })
            .build()
            .post(&url)
            .set("content-type", "application/octet-stream")
            .send(body)
            .is_ok()
    });
    for _ in 0..20 {
        if cancelled() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let (loaded, _) = connect_times(dest, 5, Duration::from_secs(3));
    let uploaded = upload.join().unwrap_or(false);
    let Some(loaded) = median(loaded) else {
        return (
            Outcome::Inconclusive,
            "no loaded measurement".into(),
            BTreeMap::new(),
        );
    };
    (
        if uploaded {
            decide_load(idle, loaded, ctx.loaded_rtt_delta_ms)
        } else {
            Outcome::Inconclusive
        },
        format!(
            "idle {idle:.0}ms, under upload {loaded:.0}ms{}",
            if uploaded {
                ""
            } else {
                " (upload did not complete)"
            }
        ),
        if uploaded {
            measured(&[("idle_rtt_ms", Some(idle)), ("loaded_rtt_ms", Some(loaded))])
        } else {
            BTreeMap::new()
        },
    )
}

// ------------------------------------------------------------------ runner

/// Tests in flight and follow-up re-runs. Each test runs on its own sandbox
/// worker; finished runs come back through a channel the tick drains.
pub struct Runner {
    tx: std::sync::mpsc::Sender<(String, TestRun)>,
    rx: std::sync::mpsc::Receiver<(String, TestRun)>,
    running: std::collections::HashSet<(String, String)>,
    reruns: Vec<(Instant, String, String)>,
    cancellations: std::collections::HashMap<(String, String), super::probe_io::Cancel>,
}

impl Default for Runner {
    fn default() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        Self {
            tx,
            rx,
            running: Default::default(),
            reruns: Vec::new(),
            cancellations: Default::default(),
        }
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        self.cancel_all();
    }
}

impl Runner {
    pub fn cancel_all(&mut self) {
        for cancel in self.cancellations.values() {
            cancel.cancel();
        }
        self.reruns.clear();
    }
    pub fn is_running(&self, issue: &str, test: &str) -> bool {
        self.running
            .contains(&(issue.to_string(), test.to_string()))
    }

    pub fn running_for(&self, issue: &str) -> Vec<String> {
        let mut v: Vec<String> = self
            .running
            .iter()
            .filter(|(i, _)| i == issue)
            .map(|(_, t)| t.clone())
            .collect();
        v.sort();
        v
    }

    pub fn any_running(&self, issue: &str) -> bool {
        self.running.iter().any(|(i, _)| i == issue)
    }

    /// Start `test` for `issue` unless it is already running.
    pub fn start(
        &mut self,
        issue: &str,
        test: &str,
        ctx: Context,
        after_action: bool,
    ) -> Result<(), String> {
        if lookup(test).is_none() {
            return Err(format!("no test named {test}"));
        }
        if self.running.len() >= 2 || self.running.iter().any(|(_, id)| id == test) {
            return Err(
                "a diagnostic measurement is already running; wait for it to finish".into(),
            );
        }
        if !self.running.insert((issue.to_string(), test.to_string())) {
            return Err(format!("{test} is already running"));
        }
        let cancel = super::probe_io::Cancel::default();
        self.cancellations
            .insert((issue.to_string(), test.to_string()), cancel.clone());
        let (tx, issue, test) = (self.tx.clone(), issue.to_string(), test.to_string());
        crate::sandbox::worker::spawn("diagnose-test", move || {
            PROBE_CANCEL.with(|slot| *slot.borrow_mut() = cancel);
            let mut run = run(&test, &ctx, || {
                super::engine::format_ts(chrono::Local::now())
            });
            run.after_action = after_action;
            let _ = tx.send((issue, run));
        });
        Ok(())
    }

    /// Finished runs since the last call.
    pub fn poll(&mut self) -> Vec<(String, TestRun)> {
        let mut done: Vec<_> = self.rx.try_iter().collect();
        for (issue, run) in &mut done {
            if self
                .cancellations
                .get(&(issue.clone(), run.test.clone()))
                .is_some_and(|c| c.cancelled())
            {
                run.outcome = Outcome::Inconclusive;
                run.detail = "test cancelled; late result discarded".into();
                run.measurements.clear();
            }
            self.running.remove(&(issue.clone(), run.test.clone()));
            self.cancellations
                .remove(&(issue.clone(), run.test.clone()));
        }
        done
    }

    pub fn schedule_rerun(&mut self, due: Instant, issue: &str, test: &str) {
        self.reruns.push((due, issue.to_string(), test.to_string()));
    }

    /// Re-runs whose time has come, removed from the schedule.
    pub fn due_reruns(&mut self, now: Instant) -> Vec<(String, String)> {
        let (due, later): (Vec<_>, Vec<_>) =
            self.reruns.drain(..).partition(|(at, _, _)| *at <= now);
        self.reruns = later;
        due.into_iter().map(|(_, i, t)| (i, t)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::issue::{Availability, Cause, CheckResult};

    fn issue(rule: &str, causes: Vec<Cause>) -> Issue {
        let d = crate::diagnose::detectors::Observations::default();
        let _ = d;
        Issue {
            id: "t-01".into(),
            rule: rule.into(),
            severity: crate::diagnose::issue::Severity::Medium,
            title: "t".into(),
            subject: crate::diagnose::issue::Subject::Host,
            since: "2026-09-15 10:00:00".into(),
            last_seen: "2026-09-15 10:00:00".into(),
            stale_since: None,
            beta: false,
            state: crate::diagnose::issue::IssueState::Open,
            evidence: vec![],
            scope: Default::default(),
            causes,
            remediation: vec![],
            verify: crate::diagnose::issue::Verify::below("x", 1.0, ""),
            artifacts: vec![],
            consequences: vec![],
            suppressed_by: None,
            recurrence: 0,
            tests: vec![],
            verification: None,
        }
    }

    fn slow_resolver() -> Issue {
        issue(
            "dns.slow_resolver",
            vec![
                Cause::new(
                    "upstream_slow",
                    "u",
                    vec![CheckResult::not_run(
                        "a",
                        "a",
                        Availability::NotMeasured,
                        "",
                    )],
                ),
                Cause::new(
                    "resolver_overloaded",
                    "o",
                    vec![CheckResult::not_run(
                        "b",
                        "b",
                        Availability::NotMeasured,
                        "",
                    )],
                ),
                Cause::new(
                    "local_udp_path",
                    "l",
                    vec![CheckResult::not_run(
                        "c",
                        "c",
                        Availability::NotMeasured,
                        "",
                    )],
                ),
            ],
        )
    }

    #[test]
    fn cancellation_discards_a_result_already_queued_for_delivery() {
        let mut runner = Runner::default();
        let token = super::super::probe_io::Cancel::default();
        let key = ("coverage".to_string(), "load.idle_vs_loaded".to_string());
        runner.running.insert(key.clone());
        runner.cancellations.insert(key.clone(), token);
        runner
            .tx
            .send((
                key.0,
                TestRun {
                    test: key.1,
                    at: "test".into(),
                    outcome: Outcome::Positive,
                    detail: "completed just before cancel".into(),
                    measurements: measured(&[
                        ("idle_rtt_ms", Some(2.0)),
                        ("loaded_rtt_ms", Some(100.0)),
                    ]),
                    after_action: false,
                },
            ))
            .unwrap();
        runner.cancel_all();
        let done = runner.poll();
        assert_eq!(done[0].1.outcome, Outcome::Inconclusive);
        assert!(done[0].1.measurements.is_empty());
    }

    #[test]
    fn cancellation_discards_measurements_and_stops_new_io() {
        let token = super::super::probe_io::Cancel::default();
        token.cancel();
        PROBE_CANCEL.with(|slot| *slot.borrow_mut() = token);
        let mut ctx = Context::new("127.0.0.1".parse().unwrap());
        ctx.resolver = Some(ctx.reference);
        let start = Instant::now();
        let result = run("dns.alt_resolver", &ctx, || "test".into());
        assert_eq!(result.outcome, Outcome::Inconclusive);
        assert!(result.measurements.is_empty());
        assert!(result.detail.contains("cancelled"));
        assert!(start.elapsed() < Duration::from_secs(1));
        PROBE_CANCEL.with(|slot| *slot.borrow_mut() = Default::default());
    }

    #[test]
    fn every_expectation_names_a_catalogued_cause() {
        let mut ids = std::collections::HashSet::new();
        for t in TESTS {
            assert!(ids.insert(t.id), "{} twice", t.id);
            assert!(!t.expects.is_empty());
            for x in t.expects {
                assert!(
                    crate::diagnose::causes::lookup(x.rule, x.cause).is_some(),
                    "{}: {}/{} is not a cause",
                    t.id,
                    x.rule,
                    x.cause
                );
            }
            assert!(Cause::valid_id(&check_id(t.id)));
        }
    }

    #[test]
    fn with_everything_untested_the_best_separator_wins() {
        let s = suggest(&slow_resolver(), Capability::None, "2026-09-15 10:00:10").unwrap();
        // alt_resolver separates 2 pairs for 3s; cached_vs_cold separates 2
        // pairs for 3s too — ties go to the cheaper, and both cost the same,
        // so the first listed wins.
        assert_eq!(s.test.id, "dns.alt_resolver");
        assert_eq!(s.separates.len(), 2);
    }

    #[test]
    fn a_run_becomes_evidence_and_is_not_suggested_again() {
        let mut i = slow_resolver();
        i.tests.push(TestRun {
            test: "dns.alt_resolver".into(),
            at: "2026-09-15 10:00:05".into(),
            outcome: Outcome::Positive,
            detail: "1.1.1.1 12ms".into(),
            measurements: BTreeMap::new(),
            after_action: false,
        });
        apply(&mut i, "2026-09-15 10:00:10");
        assert_eq!(
            i.causes.last().unwrap().id,
            "local_udp_path",
            "the fail sinks it"
        );
        let local = i.causes.iter().find(|c| c.id == "local_udp_path").unwrap();
        assert_eq!(local.checks.last().unwrap().passed, Some(false));
        let s = suggest(&i, Capability::None, "2026-09-15 10:00:10").unwrap();
        assert_eq!(
            s.test.id, "dns.cached_vs_cold",
            "the remaining pair needs another test"
        );
        assert_eq!(s.separates, vec![("upstream_slow", "resolver_overloaded")]);

        // Applying twice doesn't duplicate the check.
        apply(&mut i, "2026-09-15 10:00:11");
        let n = |i: &Issue| i.causes.iter().map(|c| c.checks.len()).sum::<usize>();
        let before = n(&i);
        apply(&mut i, "2026-09-15 10:00:12");
        assert_eq!(n(&i), before);
    }

    #[test]
    fn an_inconclusive_rerun_retracts_the_earlier_answer() {
        // A test that stopped working used to keep voting with its last good
        // result: the inconclusive run was skipped rather than retracting the
        // answer, so the superseded verdict went on ranking causes and the
        // test was never offered again.
        let mut i = slow_resolver();
        let run = |at: &str, outcome: Outcome| TestRun {
            test: "dns.alt_resolver".into(),
            at: at.into(),
            outcome,
            detail: String::new(),
            measurements: BTreeMap::new(),
            after_action: false,
        };
        i.tests.push(run("2026-09-15 10:00:00", Outcome::Positive));
        apply(&mut i, "2026-09-15 10:00:05");
        let scored = |i: &Issue| {
            i.causes
                .iter()
                .find(|c| c.id == "upstream_slow")
                .unwrap()
                .score()
        };
        assert_eq!(scored(&i), Some(1.0), "the positive run supports the cause");

        i.tests
            .push(run("2026-09-15 10:01:00", Outcome::Inconclusive));
        assert!(
            latest_runs(&i, "2026-09-15 10:01:05").is_empty(),
            "an inconclusive rerun leaves no valid answer behind"
        );

        // Causes are rebuilt from the detectors each tick, so re-apply on a
        // fresh copy the way the engine does.
        let mut fresh = slow_resolver();
        fresh.tests = i.tests.clone();
        apply(&mut fresh, "2026-09-15 10:01:05");
        assert_eq!(
            scored(&fresh),
            None,
            "a retracted answer cannot keep ranking the cause"
        );
        assert_eq!(
            suggest(&fresh, Capability::None, "2026-09-15 10:01:05")
                .unwrap()
                .test
                .id,
            "dns.alt_resolver",
            "and the test is offered again"
        );
    }

    #[test]
    fn stale_runs_stop_counting() {
        let mut i = slow_resolver();
        i.tests.push(TestRun {
            test: "dns.alt_resolver".into(),
            at: "2026-09-15 10:00:00".into(),
            outcome: Outcome::Positive,
            detail: String::new(),
            measurements: BTreeMap::new(),
            after_action: false,
        });
        assert_eq!(latest_runs(&i, "2026-09-15 10:10:00").len(), 1);
        assert_eq!(latest_runs(&i, "2026-09-15 10:20:00").len(), 0);
        assert_eq!(
            suggest(&i, Capability::None, "2026-09-15 10:20:00")
                .unwrap()
                .test
                .id,
            "dns.alt_resolver"
        );
    }

    #[test]
    fn a_decided_issue_suggests_nothing_and_manual_tests_are_never_suggested() {
        let strong = issue(
            "dns.slow_resolver",
            vec![
                Cause::new("upstream_slow", "u", vec![CheckResult::pass("a", "a", "")]),
                Cause::new(
                    "resolver_overloaded",
                    "o",
                    vec![CheckResult::fail("b", "b", "")],
                ),
            ],
        );
        assert!(suggest(&strong, Capability::None, "2026-09-15 10:00:00").is_none());
        let bloat = issue(
            "tcp.bufferbloat_remote",
            vec![
                Cause::new("receiver_queueing", "r", vec![]),
                Cause::new("path_loss", "p", vec![]),
            ],
        );
        assert!(suggest(&bloat, Capability::None, "2026-09-15 10:00:00").is_none());
        assert_eq!(
            offered(&bloat, Capability::None)[0].id,
            "load.idle_vs_loaded"
        );
    }

    #[test]
    fn decisions_follow_their_thresholds() {
        assert_eq!(decide_alt(Some(80.0), Some(12.0)), Outcome::Positive);
        assert_eq!(
            decide_alt(Some(40.0), Some(13.0)),
            Outcome::Positive,
            "a typical public reference"
        );
        assert_eq!(decide_alt(Some(80.0), Some(60.0)), Outcome::Negative);
        assert_eq!(
            decide_alt(Some(200.0), Some(150.0)),
            Outcome::Negative,
            "both slow"
        );
        assert_eq!(decide_alt(None, Some(12.0)), Outcome::Positive);
        assert_eq!(decide_alt(Some(80.0), None), Outcome::Negative);

        assert_eq!(decide_cached(Some(2.0), Some(90.0)), Outcome::Positive);
        assert_eq!(decide_cached(Some(70.0), Some(90.0)), Outcome::Negative);
        assert_eq!(decide_cached(Some(2.0), Some(8.0)), Outcome::Inconclusive);

        assert_eq!(decide_tracks(40.0, 2.0, 60.0, 20.0), Outcome::Positive);
        assert_eq!(decide_tracks(40.0, 2.0, 22.0, 20.0), Outcome::Negative);
        assert_eq!(decide_tracks(2.5, 2.0, 60.0, 20.0), Outcome::Inconclusive);

        assert_eq!(decide_loss(3, 20), Outcome::Positive);
        assert_eq!(decide_loss(1, 20), Outcome::Negative);
        assert_eq!(decide_loss(20, 20), Outcome::Inconclusive);

        assert_eq!(decide_load(12.0, 18.0, 30.0), Outcome::Positive);
        assert_eq!(decide_load(12.0, 90.0, 30.0), Outcome::Negative);
    }

    #[test]
    fn tcp_dns_framing_round_trips_against_a_local_server() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut len = [0u8; 2];
            s.read_exact(&mut len).unwrap();
            let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut q).unwrap();
            // Echo the query back with QR set and no answers: a valid reply.
            q[2] |= 0x80;
            let mut out = (q.len() as u16).to_be_bytes().to_vec();
            out.extend_from_slice(&q);
            s.write_all(&out).unwrap();
        });
        assert!(tcp_query(addr, "example.com", Duration::from_secs(2)).is_some());
    }

    #[test]
    fn missing_context_is_inconclusive_not_a_guess() {
        let ctx = Context::new("127.0.0.1".parse().unwrap());
        for id in [
            "dns.alt_resolver",
            "dns.tcp_fallback",
            "dns.cached_vs_cold",
            "dns.nxdomain_probe",
            "gateway.tcp_probe",
            "path.internet_tracks_gateway",
        ] {
            let run = run(id, &ctx, || "2026-09-15 10:00:00".into());
            assert_eq!(run.outcome, Outcome::Inconclusive, "{id}: {}", run.detail);
        }
    }
}
