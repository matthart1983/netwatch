//! The demo scenario, and the fixture every test and screenshot is built on.
//!
//! Nothing here is a hand-written report. The observations below are fed to
//! the real [`Engine`] on a [`FixedClock`], and the issues, the verdict line,
//! the screen and the report all fall out of that one run. That is the point:
//! a fixture assembled by hand can contain a number the engine could never
//! produce — which is exactly how the design bundle this implements ended up
//! describing 40ms against a 1.2ms baseline as "100×" in one panel and
//! stating the underlying numbers in another. Generate the demo from the
//! engine and the contradiction is unrepresentable.
//!
//! The scenario, at 06:51:19 on 2026-09-03:
//!
//! * the DHCP-supplied resolver 169.254.1.1 answers in 40ms against a 1.2ms
//!   learned baseline, since 06:48:10 — 33× baseline, so a `high`;
//! * the upstream path to 1.1.1.1 changed at hop 3 inside as7545 at 06:44:02,
//!   adding 40ms — an `info` that escalates to `medium` on the added latency,
//!   and the thing the DNS cause analysis correlates against;
//! * one LAN socket (`ncat` → 10.88.0.3:9000) shows receiver-side bufferbloat
//!   at 184ms with 12 retransmits, since 06:49:31;
//! * gateway, loss and throughput are nominal, and stay that way.
//!
//! The same machinery builds the replay corpus's synthetic episodes: a
//! [`Scenario`] is a frame function and a collector [`Cadence`], and
//! [`record`] runs it through the engine and the episode recorder. The demo
//! incident is [`Scenario::incident`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::baseline::{BaselineStore, NetworkFingerprint};
use super::coverage::Availability;
use super::detectors::{
    DnsObs, GatewayObs, HopObs, IfaceObs, Observations, ObservedConfig, PathObs, SocketObs,
    Thresholds,
};
use super::engine::{format_ts, Clock, Engine, FixedClock, ObservationTimes, Settings};
use super::episode::{EnvProfile, Episode, Recorder, Tick};
use super::report::{Environment, Report, TimelineEvent};

/// When the demo window ends. Every timestamp in the fixture is relative to
/// this, so the whole scenario is reproducible to the second.
pub const NOW: &str = "2026-09-03 06:51:19";
pub const WINDOW_START: &str = "2026-09-03 06:44:00";
/// Length of the scenario, 06:44:00 → 06:51:19.
pub const SCENARIO_SECS: u64 = 439;

pub const RESOLVER: &str = "169.254.1.1";
pub const ALT_RESOLVER: &str = "192.168.8.1";
pub const GATEWAY: &str = "192.168.8.1";
pub const IFACE: &str = "eth0";

/// Learned baselines for the demo network, already past the learning window.
pub fn baselines() -> BaselineStore {
    let mut b = BaselineStore::new(NetworkFingerprint::new(
        IFACE,
        Some(GATEWAY.to_string()),
        vec![RESOLVER.to_string()],
        Some("192.168.8.0/24".to_string()),
    ));
    // 1.2ms mean, σ0.4 — the numbers the whole scenario hangs on.
    b.seed(RESOLVER, "dns.rtt_p50", 1.2, 0.4, 2_400);
    b.seed(GATEWAY, "gateway.rtt", 0.9, 0.2, 2_400);
    b.seed("1.1.1.1", "path.rtt", 12.0, 1.8, 2_400);
    b
}

fn hop(n: u8, ip: &str, asn: &str, rtt: f64) -> HopObs {
    HopObs {
        number: n,
        ip: Some(ip.to_string()),
        asn: Some(asn.to_string()),
        rtt_p50_ms: Some(rtt),
        rtt_p95_ms: Some(rtt * 1.4),
        loss_pct: 0.0,
        silent: false,
    }
}

/// The path as it was before 06:44:02.
pub fn path_before() -> Vec<HopObs> {
    vec![
        hop(1, GATEWAY, "-", 0.9),
        hop(2, "100.64.0.1", "as7545", 8.1),
        hop(3, "203.0.113.9", "as7545", 12.0),
        hop(4, "1.1.1.1", "as13335", 13.4),
    ]
}

/// The path after the reroute: hop 3 moved inside the same ASN and added 40ms.
pub fn path_after() -> Vec<HopObs> {
    vec![
        hop(1, GATEWAY, "-", 0.9),
        hop(2, "100.64.0.1", "as7545", 8.1),
        hop(3, "203.0.113.44", "as7545", 52.0),
        hop(4, "1.1.1.1", "as13335", 53.6),
    ]
}

/// The bufferbloated LAN socket.
pub fn bloated_socket(age_secs: u64) -> SocketObs {
    SocketObs {
        local: "10.88.0.2:52344".into(),
        remote: "10.88.0.3:9000".into(),
        process: Some("ncat".into()),
        rtt_ms: Some(184.0),
        rttvar_ms: Some(41.0),
        retrans: Some(12),
        cwnd: Some(64),
        ssthresh: Some(u32::MAX),
        rwnd: Some(262_144),
        mss: Some(1448),
        tx_bps: Some(2.4e6),
        rx_bps: Some(1.1e4),
        verdict_age_secs: age_secs,
    }
}

fn healthy_iface() -> IfaceObs {
    IfaceObs {
        counter_window_secs: None,
        name: IFACE.into(),
        carrier: Some(true),
        rx_errors: 0,
        tx_errors: 0,
        rx_dropped: 0,
        tx_dropped: 0,
        errors_per_min: 0,
        drops_per_min: Some(0),
        link_rate_bps: Some(1e9),
        wireless: Some(false),
        signal_dbm: None,
        tx_retry_pct: None,
        rx_bps: 3.1e6,
        tx_bps: 2.6e6,
    }
}

fn healthy_gateway() -> GatewayObs {
    GatewayObs {
        addr: Some(GATEWAY.into()),
        rtt_ms: Some(0.9),
        loss_pct: 0.0,
        arp_ok: Some(true),
        icmp_ok: true,
        internet_reachable: Some(true),
    }
}

fn slow_dns() -> DnsObs {
    DnsObs {
        resolver: RESOLVER.into(),
        rtt_p50_ms: Some(40.0),
        rtt_p95_ms: Some(48.0),
        failure_rate_pct: 0.0,
        truncation_rate_pct: 5.3,
        queries: 38,
        failed: 0,
        truncated: 2,
        alt_resolver: Some(ALT_RESOLVER.into()),
        alt_rtt_ms: Some(1.4),
        icmp_rtt_ms: Some(0.1),
        cached_rtt_ms: Some(0.9),
        window_secs: 189,
        cross: None,
    }
}

fn healthy_dns() -> DnsObs {
    DnsObs {
        rtt_p50_ms: Some(1.2),
        rtt_p95_ms: Some(1.9),
        truncation_rate_pct: 0.0,
        truncated: 0,
        ..slow_dns()
    }
}

/// The resolver after the session has been switched to the alternate: the
/// 1.4ms the discriminating check measured during diagnosis is what it
/// actually delivers, which is the point of having measured it.
fn fixed_dns() -> DnsObs {
    DnsObs {
        resolver: ALT_RESOLVER.into(),
        rtt_p50_ms: Some(1.4),
        rtt_p95_ms: Some(2.1),
        truncation_rate_pct: 0.0,
        truncated: 0,
        alt_resolver: Some(RESOLVER.into()),
        alt_rtt_ms: Some(40.0),
        ..slow_dns()
    }
}

/// One observation frame. `secs_from_start` counts from [`WINDOW_START`], so
/// the scenario's onsets land where the story says they do.
pub fn observations_at(secs_from_start: u64) -> Observations {
    observations_with(secs_from_start, false)
}

/// As [`observations_at`], but with the resolver remediation already applied.
///
/// This is what closes the loop in the interactive demo: switching the session
/// resolver is supposed to fix the DNS issue, so the scenario has to be able to
/// show it doing that. The engine is not told anything — it simply sees the
/// resolver answering in 1.4ms, and its own verify condition (`dns.rtt_p50`
/// under 4.96ms, 0.8 of the 6.2ms line it opened on, for 60s) closes the
/// issue on schedule.
pub fn observations_with(secs_from_start: u64, resolver_fixed: bool) -> Observations {
    // 06:44:00 + n. Onsets: path 06:44:02 (2s), dns 06:48:10 (250s),
    // socket 06:49:31 (331s).
    let path_changed = secs_from_start >= 2;
    let dns_slow = secs_from_start >= 250 && !resolver_fixed;
    let socket_bad = secs_from_start >= 331;

    Observations {
        coverage_hints: Default::default(),
        egress: None,
        kernel: None,
        active: Default::default(),
        now: String::new(),
        iface: Some(healthy_iface()),
        gateway: Some(healthy_gateway()),
        dns: Some(match (dns_slow, resolver_fixed) {
            (true, _) => slow_dns(),
            (false, true) => fixed_dns(),
            (false, false) => healthy_dns(),
        }),
        paths: vec![PathObs {
            destination_reached: Some(true),
            target: "1.1.1.1".into(),
            hops: if path_changed {
                path_after()
            } else {
                path_before()
            },
            previous: path_changed.then(path_before),
            traced_at: "2026-09-03 06:44:02".into(),
        }],
        sockets: if socket_bad {
            // The verdict has to have held for 30s before it can open an
            // issue, so the socket's age tracks how long it has been bad.
            vec![bloated_socket(secs_from_start - 331 + 60)]
        } else {
            vec![]
        },
        // The uplink itself is fine — which is what makes the socket's
        // bufferbloat the *receiver's* problem, and the check that proves it.
        idle_rtt_ms: Some(12.0),
        loaded_rtt_ms: Some(18.0),
        captive_portal_url: None,
        nat: None,
        targets: vec![],
        // Unknown, as in every recording made before the snapshot existed.
        config: None,
    }
}

struct ClockRef(std::sync::Arc<FixedClock>);

impl Clock for ClockRef {
    fn now(&self) -> chrono::DateTime<chrono::Local> {
        self.0.now()
    }
}

/// Run the real engine across the whole demo window and hand back the result.
/// Every issue, timestamp and confidence in the demo comes out of this loop.
pub fn run() -> (Engine, BaselineStore) {
    let clock = std::sync::Arc::new(FixedClock::at(WINDOW_START));
    let mut engine = Engine::new(Box::new(ClockRef(clock.clone())));
    let base = baselines();

    // 06:44:00 → 06:51:19 at one observation per second.
    for t in 0..=SCENARIO_SECS {
        engine.observe(&observations_at(t), &base);
        clock.advance_secs(1);
    }
    (engine, base)
}

pub fn environment(base: &BaselineStore) -> Environment {
    Environment {
        host: "nw-demo".into(),
        iface: IFACE.into(),
        driver: Some("e1000e".into()),
        kernel: Some("6.19.10".into()),
        qdisc: Some("fq_codel".into()),
        resolvers: vec![RESOLVER.into(), ALT_RESOLVER.into()],
        gateway: Some(GATEWAY.into()),
        netwatch_version: env!("CARGO_PKG_VERSION").into(),
        ruleset_version: "v1".into(),
        baseline_state: format!(
            "{} on {}",
            base.overall_readiness().label(),
            base.fingerprint().label()
        ),
    }
}

/// The demo report, generated from the demo run.
pub fn report() -> Report {
    let (engine, base) = run();
    let issues = engine.issues().to_vec();

    let mut timeline: Vec<TimelineEvent> = issues
        .iter()
        .map(|i| TimelineEvent {
            at: i.since.clone(),
            kind: "issue".into(),
            text: format!("{} · {}", i.title, i.subject.label()),
        })
        .collect();
    timeline.push(TimelineEvent {
        at: "2026-09-03 06:44:02".into(),
        kind: "path".into(),
        text: "hop 3 to 1.1.1.1 changed inside as7545, adding 40ms".into(),
    });
    timeline.sort_by(|a, b| a.at.cmp(&b.at));

    Report {
        coverage: engine.coverage().clone(),
        generated_at: NOW.into(),
        window_start: WINDOW_START.into(),
        window_end: NOW.into(),
        environment: environment(&base),
        issues,
        timeline,
        artifacts: vec![
            "diagnose.json".into(),
            "baselines.json".into(),
            "trace-1.1.1.1.json".into(),
            "capture.pcap".into(),
            "timeline.json".into(),
        ],
    }
}

// ------------------------------------------------------------------ scenarios

/// Unix seconds of every scenario's first frame. Only differences between
/// frame times are ever read, and a fixed origin keeps a recording
/// independent of the timezone its `start` is read in.
const SCENARIO_UNIX_START: f64 = 1.789e9;

/// How often each collector completes, in seconds. Each frame is stamped
/// with the last completion on that grid, as the live tick is: stamping
/// every frame would count each second as a new sample. A collector left
/// `None` never completes, and the engine drops its input as stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cadence {
    pub interface: Option<u64>,
    pub sockets: Option<u64>,
    /// The DNS, gateway and internet probes, which complete together.
    pub health: Option<u64>,
    pub path: Option<u64>,
    /// Every developer target in the frame, each on this one grid.
    pub targets: Option<u64>,
}

impl Cadence {
    /// The app's: interface and sockets every tick, the health prober every
    /// 5 s, a trace every 30 s, and each target at its default interval of
    /// a minute.
    pub fn live() -> Self {
        Self {
            interface: Some(1),
            sockets: Some(1),
            health: Some(5),
            path: Some(30),
            targets: Some(60),
        }
    }

    /// The last completion on a `period`-second grid, `t` seconds in.
    fn stamp(period: Option<u64>, start: Instant, t: u64) -> Option<Instant> {
        let period = period?.max(1);
        Some(start + Duration::from_secs(t - t % period))
    }
}

/// The stretches of a scenario's story.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Healthy,
    Fault,
    Clear,
}

/// The phase `t` falls in: the last one starting at or before it, so
/// `phase(t, &[(0, Healthy), (120, Fault), (300, Clear)])` is a fault from
/// 120 s to 299 s.
pub fn phase(t: u64, phases: &[(u64, Phase)]) -> Phase {
    phases
        .iter()
        .rev()
        .find(|(from, _)| *from <= t)
        .or(phases.first())
        .map(|(_, p)| *p)
        .expect("a scenario has at least one phase")
}

/// A synthetic episode: observations as a function of time, run through the
/// real engine and the real recorder by [`record`]. Every `synthetic` row of
/// the corpus manifest is one of [`scenarios`].
#[derive(Debug, Clone, Copy)]
pub struct Scenario {
    /// The corpus id, which names its files.
    pub id: &'static str,
    /// Local time of the first frame, `YYYY-MM-DD HH:MM:SS`.
    pub start: &'static str,
    /// Seconds from the first frame to the last; one frame a second.
    pub secs: u64,
    pub baselines: fn() -> BaselineStore,
    /// The observations `t` seconds after `start`.
    pub obs: fn(u64) -> Observations,
    pub cadence: Cadence,
    pub thresholds: Thresholds,
}

impl Scenario {
    /// The demo incident at the top of this file.
    pub fn incident() -> Self {
        Self {
            id: "fixture-scenario",
            start: WINDOW_START,
            secs: SCENARIO_SECS,
            baselines,
            obs: incident_frame,
            // The demo re-traces every second: that is what opens
            // path.changed at 06:44:04, on the third trace after the reroute.
            cadence: Cadence {
                path: Some(1),
                ..Cadence::live()
            },
            thresholds: Thresholds::default(),
        }
    }
}

fn incident_frame(t: u64) -> Observations {
    let mut obs = observations_at(t);
    for s in &mut obs.sockets {
        s.process = Some("firefox".into());
    }
    obs
}

/// The demo network's baselines as the live sampler learns them. It learns
/// a path baseline from the internet probe only, never one per trace target
/// as [`baselines`] seeds for 1.1.1.1, so here a trace is judged against
/// `internet`.
fn live_baselines() -> BaselineStore {
    let mut b = BaselineStore::new(baselines().fingerprint().clone());
    b.seed(RESOLVER, "dns.rtt_p50", 1.2, 0.4, 2_400);
    b.seed(GATEWAY, "gateway.rtt", 0.9, 0.2, 2_400);
    b.seed("internet", "path.rtt", 12.0, 1.8, 2_400);
    b
}

/// The demo network before anything goes wrong, with the configuration a
/// live frame records: its resolver and interfaces, a trace to 1.1.1.1
/// every 30 s, and no targets. Without a configuration nothing can expire.
fn quiet_frame() -> Observations {
    Observations {
        config: Some(ObservedConfig {
            resolvers: Some(vec![RESOLVER.into()]),
            targets: vec![],
            trace_target: "1.1.1.1".into(),
            trace_refresh_secs: Some(30),
            interfaces: Some(vec!["lo".into(), IFACE.into()]),
        }),
        ..observations_at(0)
    }
}

/// Healthy until 120 s, faulty until 300 s, then clear. In a socket
/// episode the socket closes at 300 s; a socket verdict holds 30 s and
/// three samples before it opens, so each opens at 152 s, and expires 60 s
/// after the close.
const STORY: [(u64, Phase); 3] = [
    (0, Phase::Healthy),
    (120, Phase::Fault),
    (300, Phase::Clear),
];

/// A browser connection that stays healthy throughout. With it listed the
/// socket rules stay available after the faulty socket closes, which is
/// what lets the closed socket count as gone.
fn neighbour_socket(t: u64) -> SocketObs {
    SocketObs {
        local: "10.88.0.2:41822".into(),
        remote: "93.184.215.14:443".into(),
        process: Some("firefox".into()),
        rtt_ms: Some(24.0),
        rttvar_ms: Some(3.0),
        retrans: Some(0),
        cwnd: Some(10),
        ssthresh: Some(u32::MAX),
        rwnd: Some(131_072),
        mss: Some(1448),
        tx_bps: Some(1.2e4),
        rx_bps: Some(8.6e5),
        verdict_age_secs: t,
    }
}

/// An upload over a lossy path: 18 retransmits a minute at 38 ms, under
/// the queueing line, so the path is losing segments rather than queueing
/// them. The upload ends at 300 s.
fn retrans_socket_closes(t: u64) -> Observations {
    let mut obs = quiet_frame();
    obs.sockets.push(neighbour_socket(t));
    let scp = SocketObs {
        local: "10.88.0.2:48210".into(),
        remote: "203.0.113.20:22".into(),
        process: Some("scp".into()),
        rtt_ms: Some(31.0),
        rttvar_ms: Some(4.0),
        retrans: Some(0),
        cwnd: Some(42),
        ssthresh: Some(u32::MAX),
        rwnd: Some(1_048_576),
        mss: Some(1448),
        tx_bps: Some(3.8e6),
        rx_bps: Some(4.2e4),
        verdict_age_secs: t,
    };
    match phase(t, &STORY) {
        Phase::Healthy => obs.sockets.push(scp),
        Phase::Fault => obs.sockets.push(SocketObs {
            rtt_ms: Some(38.0),
            retrans: Some(18),
            cwnd: Some(12),
            ssthresh: Some(21),
            tx_bps: Some(6.1e5),
            verdict_age_secs: t - 120,
            ..scp
        }),
        Phase::Clear => {}
    }
    obs
}

/// The demo's bufferbloated LAN socket, fast until 120 s. The loaded-rtt
/// test in the quiet frame places the queue on the receiver.
fn bufferbloat_remote_socket_closes(t: u64) -> Observations {
    let mut obs = quiet_frame();
    obs.sockets.push(neighbour_socket(t));
    match phase(t, &STORY) {
        Phase::Healthy => obs.sockets.push(SocketObs {
            rtt_ms: Some(1.1),
            rttvar_ms: Some(0.3),
            retrans: Some(0),
            ..bloated_socket(t)
        }),
        Phase::Fault => obs.sockets.push(bloated_socket(t - 120)),
        Phase::Clear => {}
    }
    obs
}

/// A backup to a NAS whose daemon stops reading at 120 s; rsync gives up
/// at 300 s. It is the host's only socket, so once it closes the sampler
/// lists none and says so, as it does live.
fn zero_window_socket_closes(t: u64) -> Observations {
    let mut obs = quiet_frame();
    let rsync = SocketObs {
        local: "10.88.0.2:40522".into(),
        remote: "10.88.0.7:873".into(),
        process: Some("rsync".into()),
        rtt_ms: Some(0.8),
        rttvar_ms: Some(0.2),
        retrans: Some(0),
        cwnd: Some(40),
        ssthresh: Some(u32::MAX),
        rwnd: Some(524_288),
        mss: Some(1448),
        tx_bps: Some(9.1e7),
        rx_bps: Some(2.2e5),
        verdict_age_secs: t,
    };
    match phase(t, &STORY) {
        Phase::Healthy => obs.sockets.push(rsync),
        Phase::Fault => obs.sockets.push(SocketObs {
            rwnd: Some(0),
            tx_bps: Some(0.0),
            rx_bps: Some(0.0),
            verdict_age_secs: t - 120,
            ..rsync
        }),
        Phase::Clear => {
            for rule in [
                "tcp.bufferbloat_remote",
                "tcp.retrans_burst",
                "tcp.zero_window",
            ] {
                obs.coverage_hints.insert(
                    rule.into(),
                    (
                        Availability::NoSubjects,
                        "successful TCP dump contained no established sockets in this \
                         network namespace"
                            .into(),
                    ),
                );
            }
        }
    }
    obs
}

/// The local stamp `secs` after [`WINDOW_START`], for the times a collector
/// writes into its own results.
fn wall_clock(secs: u64) -> String {
    let start = chrono::NaiveDateTime::parse_from_str(WINDOW_START, "%Y-%m-%d %H:%M:%S")
        .expect("WINDOW_START is a stamp");
    (start + chrono::Duration::seconds(secs as i64))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

/// The trace to 1.1.1.1, every 30 s, judged against the internet probe's
/// 12 ms baseline (σ 1.8). Hop 3 congests from 120 s and the path reads
/// 80 ms. From 300 s it reads 16.5 ms, 2.5σ: under the 3σ open line and
/// over the 2σ close line, so the issue stays open. From 420 s it is back
/// at 13.4 ms, and the issue closes once that has held 120 s.
fn path_rtt_spike(t: u64) -> Observations {
    // A frame carries the last trace to complete, on the cadence's grid.
    let traced = t - t % 30;
    let (hop3, hop4) = match traced {
        120..=299 => (78.6, 80.0),
        300..=419 => (15.1, 16.5),
        _ => (12.0, 13.4),
    };
    let mut obs = quiet_frame();
    obs.paths = vec![PathObs {
        destination_reached: Some(true),
        target: "1.1.1.1".into(),
        hops: vec![
            hop(1, GATEWAY, "-", 0.9),
            hop(2, "100.64.0.1", "as7545", 8.1),
            hop(3, "203.0.113.9", "as7545", hop3),
            hop(4, "1.1.1.1", "as13335", hop4),
        ],
        // The route never changes; only hop 3's queue does.
        previous: Some(path_before()),
        traced_at: wall_clock(traced),
    }];
    obs
}

/// The `api` target's configuration revision, which keys its baselines.
const API_REVISION: &str = "target-config:synthetic-api";

/// [`live_baselines`] and the `api` target's stage timings, σ a tenth of
/// each mean: a 40 ms first byte opens above 52 ms and closes under 48 ms.
fn target_baselines() -> BaselineStore {
    let mut b = live_baselines();
    for (metric, mean) in [
        ("target.resolve_ms", 2.0),
        ("target.connect_ms", 12.0),
        ("target.tls_ms", 30.0),
        ("target.ttfb_ms", 40.0),
    ] {
        b.seed(API_REVISION, metric, mean, mean / 10.0, 2_400);
    }
    b
}

/// The `api` target, probed once a minute. Its first byte goes from 41 ms
/// to 400 ms at 180 s and reads 50 ms from 360 s, 2.5σ: under the 3σ open
/// line and over the 2σ close line, so the issue stays open. From 480 s it
/// is back at 41 ms, and the issue closes once that has held 180 s. The
/// other stages stay at their baselines.
fn target_slow_stage(t: u64) -> Observations {
    use super::targets::{ConnectAttempt, Lookup, LookupOutcome, Stage, TargetContext, TargetObs};
    // A frame carries the last probe to complete, on the cadence's grid.
    let probed = t - t % 60;
    let first_byte = match probed {
        180..=359 => 400.0,
        360..=479 => 50.0,
        _ => 41.0,
    };
    let took = |ms| Stage {
        ms: Some(ms),
        error: None,
    };
    let mut obs = quiet_frame();
    if let Some(config) = &mut obs.config {
        config.targets = vec![("api".into(), API_REVISION.into())];
    }
    obs.targets = vec![TargetObs {
        baseline_key: Some(API_REVISION.into()),
        name: "api".into(),
        host: "api.example.com".into(),
        port: 443,
        tls: true,
        http: true,
        expect_status: None,
        probed_at: wall_clock(probed),
        resolve: took(2.0),
        addresses: vec!["203.0.113.30".into()],
        lookups: vec![Lookup {
            resolver: RESOLVER.into(),
            link: None,
            outcome: LookupOutcome::Answered,
        }],
        connect: Some(took(12.0)),
        connect_v4: Some(took(12.0)),
        connect_v6: None,
        tls_stage: Some(took(30.0)),
        http_stage: Some(took(first_byte)),
        status: Some(200),
        attempts: vec![ConnectAttempt {
            address: "203.0.113.30:443".into(),
            stage: took(12.0),
        }],
        effective_endpoint: Some("203.0.113.30:443".into()),
        sni: Some("api.example.com".into()),
        http_authority: Some("api.example.com".into()),
        // Three missed probes at the default interval.
        stale_after_secs: Some(180),
        context: TargetContext::default(),
    }];
    obs
}

/// [`live_baselines`] on a network whose router is its resolver too,
/// answering in 10.5 ms (σ 0.3), as the notes measured one.
fn router_baselines() -> BaselineStore {
    let mut b = BaselineStore::new(NetworkFingerprint::new(
        IFACE,
        Some(GATEWAY.to_string()),
        vec![GATEWAY.to_string()],
        Some("192.168.8.0/24".to_string()),
    ));
    b.seed(GATEWAY, "dns.rtt_p50", 10.5, 0.3, 2_400);
    b.seed(GATEWAY, "gateway.rtt", 0.9, 0.2, 2_400);
    b.seed("internet", "path.rtt", 12.0, 1.8, 2_400);
    b
}

/// The router's DNS forwarder. The p50 reads 10 ms, then 150 ms from
/// 120 s, when the router's upstream slows, and 11 ms from 300 s. Live,
/// the p50 is a median over ten minutes of probes, so these are the times
/// the median moves, some minutes after the resolver does. The issue opens
/// on the third slow probe. It closes once 11 ms has held 60 s under
/// 16.8 ms, 0.8 of the 21 ms line it opened on, twice the baseline, though
/// the 100 ms ceiling fired too. The flat 5 ms line this replaced never
/// closed it.
fn dns_slow_router(t: u64) -> Observations {
    let (p50, p95) = match phase(t, &STORY) {
        Phase::Healthy => (10.0, 12.0),
        Phase::Fault => (150.0, 180.0),
        Phase::Clear => (11.0, 13.0),
    };
    let mut obs = quiet_frame();
    if let Some(config) = &mut obs.config {
        config.resolvers = Some(vec![GATEWAY.into()]);
    }
    // As the live sampler fills it: ten minutes of probes to the one
    // resolver, and no alternate, icmp or cached timing, which it never
    // measures.
    obs.dns = Some(DnsObs {
        resolver: GATEWAY.into(),
        rtt_p50_ms: Some(p50),
        rtt_p95_ms: Some(p95),
        failure_rate_pct: 0.0,
        truncation_rate_pct: 0.0,
        queries: 120,
        failed: 0,
        truncated: 0,
        alt_resolver: None,
        alt_rtt_ms: None,
        icmp_rtt_ms: None,
        cached_rtt_ms: None,
        window_secs: 600,
        cross: None,
    });
    obs
}

/// A healthy probe's rtt: `mean`, give or take `spread`, moving from one
/// probe to the next in a fixed order, so a recording stays the same.
fn wobble(probe: u64, mean: f64, spread: f64) -> f64 {
    const STEPS: [f64; 6] = [0.0, 0.7, -0.3, 1.0, -1.0, 0.3];
    mean + spread * STEPS[(probe % 6) as usize]
}

/// [`live_baselines`] with the router answering its own pings in 1.0 ms,
/// σ 0.3.
fn wired_gateway_baselines() -> BaselineStore {
    let mut b = live_baselines();
    b.seed(GATEWAY, "gateway.rtt", 1.0, 0.3, 2_400);
    b
}

/// The router, answering its own pings in 1.0 ms, give or take 0.3. From
/// 120 s its CPU is busy and it answers in 40 ms, though what it forwards
/// is not held up; from 300 s it answers in 1.0 ms again. The issue opens
/// on the third slow probe and closes once the rtt has held under 2σ,
/// 2.0 ms against the 0.5 ms σ floor, for 120 s.
fn gateway_rtt(t: u64) -> Observations {
    let rtt = match phase(t, &STORY) {
        Phase::Fault => 40.0,
        _ => wobble(t / 5, 1.0, 0.3),
    };
    let mut obs = quiet_frame();
    obs.gateway = Some(GatewayObs {
        rtt_ms: Some(rtt),
        // The sampler has no ARP probe.
        arp_ok: None,
        ..healthy_gateway()
    });
    obs
}

/// The laptop's Wi-Fi interface.
const WLAN: &str = "wlan0";

/// The demo network's live baselines over Wi-Fi, where the access point
/// answers its own pings in 4 ms, σ 4.
fn wifi_baselines() -> BaselineStore {
    let mut b = BaselineStore::new(NetworkFingerprint::new(
        WLAN,
        Some(GATEWAY.to_string()),
        vec![RESOLVER.to_string()],
        Some("192.168.8.0/24".to_string()),
    ));
    b.seed(RESOLVER, "dns.rtt_p50", 1.2, 0.4, 2_400);
    b.seed(GATEWAY, "gateway.rtt", 4.0, 4.0, 2_400);
    b.seed("internet", "path.rtt", 12.0, 1.8, 2_400);
    b
}

/// [`quiet_frame`] on a laptop on Wi-Fi: wlan0 at −53 dBm with 7% of
/// frames retried, what `iw station dump` showed on a healthy link, and
/// the access point answering in 4 ms, give or take 3.
fn wifi_frame(t: u64) -> Observations {
    let mut obs = quiet_frame();
    obs.iface = Some(IfaceObs {
        name: WLAN.into(),
        counter_window_secs: Some(60.0),
        wireless: Some(true),
        // The sampler reads no link rate on a radio.
        link_rate_bps: None,
        signal_dbm: Some(-53),
        tx_retry_pct: Some(7.0),
        ..healthy_iface()
    });
    obs.gateway = Some(GatewayObs {
        rtt_ms: Some(wobble(t / 5, 4.0, 3.0)),
        arp_ok: None,
        ..healthy_gateway()
    });
    if let Some(config) = &mut obs.config {
        config.interfaces = Some(vec!["lo".into(), WLAN.into()]);
    }
    obs
}

/// The access point hovering at the open line. Against its 4 ms baseline
/// (σ 4), 3σ is 16 ms, 12 ms over the mean and past the 10 ms delta
/// floor. From 120 s its own replies slow: 30 s at 16.4 ms (3.1σ), then
/// three minutes at 15.6 ms (2.9σ), three times over. Each dip is under
/// the open line and over the 2σ close line, so the issue stays one
/// issue; under a 3σ close line each dip outlasts the 120 s hold, and the
/// issue closes and reopens. From 750 s it answers in 4 ms again, and the
/// issue closes 120 s later.
fn gateway_rtt_edge(t: u64) -> Observations {
    let mut obs = wifi_frame(t);
    if (120..750).contains(&t) {
        let sigma = if (t - 120) % 210 < 30 { 3.1 } else { 2.9 };
        if let Some(gw) = &mut obs.gateway {
            gw.rtt_ms = Some(4.0 + sigma * 4.0);
        }
    }
    obs
}

/// The demo's wired link, unplugged at 120 s and plugged back in at 300 s.
/// NetworkManager takes the connection down with the carrier, and the
/// default route and the DHCP resolver go with it, so the prober has
/// nothing to probe and no trace completes: the frames carry no gateway,
/// DNS or path observation until the link is back. The issue opens on the
/// third sample with no carrier and closes once the carrier has held 30 s.
fn link_down(t: u64) -> Observations {
    let mut obs = quiet_frame();
    if phase(t, &STORY) == Phase::Fault {
        let iface = obs
            .iface
            .as_mut()
            .expect("the quiet frame has an interface");
        iface.carrier = Some(false);
        iface.link_rate_bps = None;
        iface.rx_bps = 0.0;
        iface.tx_bps = 0.0;
        obs.gateway = None;
        obs.dns = None;
        obs.paths.clear();
        if let Some(config) = &mut obs.config {
            config.resolvers = None;
        }
    }
    obs
}

/// The same link, never down: from 120 s to 300 s the platform's
/// interface list comes back empty, as when the read fails, while the
/// link's counters keep moving. The carrier is unknown, which is not
/// down, so nothing opens.
fn link_down_carrier_unknown(t: u64) -> Observations {
    let mut obs = quiet_frame();
    if phase(t, &STORY) == Phase::Fault {
        let iface = obs
            .iface
            .as_mut()
            .expect("the quiet frame has an interface");
        iface.carrier = None;
        iface.wireless = None;
        if let Some(config) = &mut obs.config {
            config.interfaces = None;
        }
    }
    obs
}

/// The laptop carried to the far end of the house at 120 s: −78 dBm, and
/// 14% of frames retried, under the 20% line, so the signal alone opens
/// the issue. From 300 s it sits at −60 dBm, over the −70 dBm line, and
/// the issue closes once that has held 120 s.
fn wifi_weak(t: u64) -> Observations {
    let (signal, retries) = match phase(t, &STORY) {
        Phase::Healthy => (-53, 7.0),
        Phase::Fault => (-78, 14.0),
        Phase::Clear => (-60, 9.0),
    };
    let mut obs = wifi_frame(t);
    let iface = obs
        .iface
        .as_mut()
        .expect("the Wi-Fi frame has an interface");
    iface.signal_dbm = Some(signal);
    iface.tx_retry_pct = Some(retries);
    obs
}

/// The laptop's driver drops about 70 frames a minute it has no use for,
/// multicast for groups nothing here joined, and counts them as interface
/// drops. That is over the 60/min floor, so iface.errors opens on the
/// drops alone two seconds in. From 120 s to 300 s interference costs the
/// link 30 errors a minute as well. The issue never closes: it closes only
/// under 1/min errors and drops combined, which the drops never allow,
/// until B19 retunes the rule. On the errors alone it would close at 659 s.
fn iface_errors_wifi_drops(t: u64) -> Observations {
    // Both rates count the minute before the frame, as the sampler's do,
    // so the errors ramp in and out over a minute. The seconds of
    // `from..to` in that minute:
    let in_last_minute =
        |from: u64, to: u64| t.min(to).saturating_sub(t.saturating_sub(60).max(from));
    let mut obs = wifi_frame(t);
    let iface = obs
        .iface
        .as_mut()
        .expect("the Wi-Fi frame has an interface");
    iface.errors_per_min = 30 * in_last_minute(120, 300) / 60;
    iface.drops_per_min = Some(70);
    // And the lifetime counters behind them.
    iface.rx_errors = 30 * t.min(300).saturating_sub(120) / 60;
    iface.rx_dropped = 18_400 + 70 * t / 60;
    obs
}

impl Scenario {
    /// An episode on the demo network as the app sees it: the live cadence,
    /// the baselines live learns and the default thresholds.
    fn live(id: &'static str, secs: u64, obs: fn(u64) -> Observations) -> Self {
        Self {
            id,
            start: WINDOW_START,
            secs,
            baselines: live_baselines,
            obs,
            cadence: Cadence::live(),
            thresholds: Thresholds::default(),
        }
    }
}

/// Every scenario the corpus can pin, by id.
pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario::incident(),
        // Each runs a minute past its expiry.
        Scenario::live("retrans-socket-closes", 420, retrans_socket_closes),
        Scenario::live(
            "bufferbloat-remote-socket-closes",
            420,
            bufferbloat_remote_socket_closes,
        ),
        Scenario::live("zero-window-socket-closes", 420, zero_window_socket_closes),
        // A minute past the close.
        Scenario::live("path-rtt-spike", 600, path_rtt_spike),
        Scenario {
            baselines: target_baselines,
            ..Scenario::live("target-slow-stage", 720, target_slow_stage)
        },
        Scenario {
            baselines: router_baselines,
            ..Scenario::live("dns-slow-router", 420, dns_slow_router)
        },
        Scenario {
            baselines: wired_gateway_baselines,
            ..Scenario::live("gateway-rtt", 480, gateway_rtt)
        },
        Scenario {
            baselines: wifi_baselines,
            ..Scenario::live("gateway-rtt-edge", 930, gateway_rtt_edge)
        },
        Scenario::live("link-down", 390, link_down),
        Scenario::live("link-down-carrier-unknown", 420, link_down_carrier_unknown),
        Scenario {
            baselines: wifi_baselines,
            ..Scenario::live("wifi-weak", 480, wifi_weak)
        },
        // A minute past where it would close without the drops.
        Scenario {
            baselines: wifi_baselines,
            ..Scenario::live("iface-errors-wifi-drops", 720, iface_errors_wifi_drops)
        },
    ]
}

/// The profile every synthetic episode carries. Detected, it held this
/// host's kernel and netwatch's version, so the same scenario recorded on
/// another machine, or after a release, made a different file.
fn synthetic_env() -> EnvProfile {
    EnvProfile {
        os: "linux".into(),
        arch: "x86_64".into(),
        kernel: None,
        netwatch_version: "synthetic".into(),
        capability: "root".into(),
        refresh_rate_ms: 1000,
    }
}

/// Run `scenario` through the real engine and recorder, one frame a second,
/// and return the episode. Two runs give byte-identical files.
///
/// The recorder starts a quiet sample on the first frame, so a scenario that
/// opens nothing still yields its frames, and one that does keeps up to 10
/// minutes of them as pre-roll, as live. Panics if the recorder ends the
/// episode before `secs`: a quiet sample lasts 15 minutes, and an incident
/// ends 10 minutes after its last issue closes.
pub fn record(scenario: &Scenario) -> Episode {
    let clock = Arc::new(FixedClock::at(scenario.start));
    let mut engine = Engine::new(Box::new(clock.clone())).with_settings(Settings {
        thresholds: scenario.thresholds,
        ..Settings::default()
    });
    let mut base = (scenario.baselines)();
    let mut rec = Recorder::new(synthetic_env(), SCENARIO_UNIX_START);
    rec.schedule_quiet_sample(SCENARIO_UNIX_START);
    let start = Instant::now() + Duration::from_secs(86_400);
    let cadence = scenario.cadence;
    for t in 0..=scenario.secs {
        let obs = (scenario.obs)(t);
        let now = start + Duration::from_secs(t);
        let mut times = ObservationTimes {
            interface: Cadence::stamp(cadence.interface, start, t),
            sockets: Cadence::stamp(cadence.sockets, start, t),
            path: Cadence::stamp(cadence.path, start, t),
            ..Default::default()
        };
        // Without health times the live engine drops the DNS and gateway
        // observations as stale, so the corpus could not see a regression in
        // either.
        let probed = Cadence::stamp(cadence.health, start, t);
        times.health.dns = probed;
        times.health.gateway = probed;
        times.health.internet = probed;
        times.health.dns_target = obs.dns.as_ref().map(|d| d.resolver.clone());
        times.health.gateway_target = obs.gateway.as_ref().and_then(|g| g.addr.clone());
        // Target results are dropped as stale, and cannot open or verify
        // anything, without a completion time under their own name.
        if let Some(probed) = Cadence::stamp(cadence.targets, start, t) {
            times.targets = obs
                .targets
                .iter()
                .map(|x| (x.name.clone(), probed))
                .collect();
        }
        engine.observe_live_at(&obs, &base, &times, now);
        let ended = rec.record(Tick {
            at: SCENARIO_UNIX_START + t as f64,
            ts: format_ts(clock.now()),
            now,
            obs: &obs,
            times: &times,
            readings: &[],
            engine: &engine,
            baselines: &base,
            events: vec![],
        });
        assert!(
            ended.is_none(),
            "{}: the recorder ended the episode {t}s in, before the scenario's {}s",
            scenario.id,
            scenario.secs
        );
        let thresholds = engine.settings().thresholds;
        base.set_gate(thresholds.sigma_k, thresholds.sigma_floor());
        clock.advance_secs(1);
    }
    let mut ep = rec
        .flush(&engine, &format_ts(clock.now()))
        .expect("a quiet sample starts on the first frame");
    ep.id = scenario.id.into();
    ep
}

/// A deterministic recorded episode of the demo incident. The corpus pins
/// it as `fixture-scenario`: same frames, same decisions, every time.
pub fn episode() -> Episode {
    record(&Scenario::incident())
}

/// The synthetic corpus episode `id`, rebuilt. `None` for an id no scenario
/// here builds; `diagnose corpus` refuses a manifest row naming one.
pub fn synthetic(id: &str) -> Option<Episode> {
    scenarios()
        .into_iter()
        .find(|s| s.id == id)
        .map(|s| record(&s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::issue::Severity;

    #[test]
    fn the_demo_run_produces_the_scenario_it_describes() {
        let (engine, _) = run();
        let primary = engine.primary();
        let rules: Vec<&str> = primary.iter().map(|i| i.rule.as_str()).collect();

        assert!(rules.contains(&"dns.slow_resolver"), "{rules:?}");
        assert!(rules.contains(&"tcp.bufferbloat_remote"), "{rules:?}");
        assert!(rules.contains(&"path.changed"), "{rules:?}");
        assert_eq!(primary.len(), 3, "{rules:?}");
    }

    /// The reroute costs 40ms, which the path.rtt_spike rule also detects.
    /// Both are true; only one is a finding. The other is reported under it.
    #[test]
    fn the_latency_the_reroute_cost_is_filed_under_the_reroute() {
        let (engine, _) = run();
        let changed = engine
            .issues()
            .iter()
            .find(|i| i.rule == "path.changed")
            .expect("the path change should be a finding");
        let spike = engine
            .issues()
            .iter()
            .find(|i| i.rule == "path.rtt_spike")
            .expect("the added latency should still be detected");

        assert_eq!(spike.suppressed_by.as_deref(), Some(changed.id.as_str()));
        assert!(changed.consequences.contains(&spike.id));
        // And its evidence survives — suppression hides a finding from the
        // list, it does not throw the measurement away.
        assert!(spike.evidence.iter().any(|e| e.metric == "path.rtt"));
    }

    #[test]
    fn onsets_land_where_the_story_says() {
        let (engine, _) = run();
        let dns = engine
            .issues()
            .iter()
            .find(|i| i.rule == "dns.slow_resolver")
            .unwrap();
        assert_eq!(dns.since, "2026-09-03 06:48:10");

        let sock = engine
            .issues()
            .iter()
            .find(|i| i.rule == "tcp.bufferbloat_remote")
            .unwrap();
        assert_eq!(sock.since, "2026-09-03 06:49:31");
    }

    #[test]
    fn the_dns_issue_is_high_because_of_its_multiple_not_its_absolute_value() {
        let (engine, _) = run();
        let dns = engine
            .issues()
            .iter()
            .find(|i| i.rule == "dns.slow_resolver")
            .unwrap();
        assert_eq!(dns.severity, Severity::High);
        assert_eq!(dns.evidence[0].multiple_label().unwrap(), "33× baseline");
    }

    #[test]
    fn the_uplink_being_healthy_is_what_makes_the_socket_the_receivers_fault() {
        let (engine, _) = run();
        let sock = engine
            .issues()
            .iter()
            .find(|i| i.rule == "tcp.bufferbloat_remote")
            .unwrap();
        let top = sock.top_cause().unwrap();
        assert!(top.label.contains("receiver"), "{}", top.label);
        assert!(top
            .checks
            .iter()
            .any(|c| c.name.contains("link-level") && c.passed == Some(true)));
    }

    /// The gateway and link are healthy throughout, so no finding may be
    /// filed as a consequence of one. (The reroute does suppress its own
    /// latency spike — see the test above; that edge is the point.)
    #[test]
    fn a_healthy_gateway_explains_nothing() {
        let (engine, _) = run();
        for issue in engine.issues() {
            let Some(root_id) = &issue.suppressed_by else {
                continue;
            };
            let root = engine.get(root_id).expect("suppressing issue exists");
            assert!(
                !root.rule.starts_with("gateway.") && !root.rule.starts_with("link."),
                "{} was blamed on {} while the gateway was healthy",
                issue.rule,
                root.rule
            );
        }
    }

    #[test]
    fn applying_the_fix_lets_the_issue_close_itself() {
        use super::super::engine::{Engine, FixedClock};
        let clock = std::sync::Arc::new(FixedClock::at(WINDOW_START));
        let mut engine = Engine::new(Box::new(ClockRef(clock.clone())));
        let base = baselines();

        // Run into the incident.
        for t in 0..=300 {
            engine.observe(&observations_with(t, false), &base);
            clock.advance_secs(1);
        }
        assert!(engine
            .primary()
            .iter()
            .any(|i| i.rule == "dns.slow_resolver"));

        let id = engine
            .primary()
            .iter()
            .find(|i| i.rule == "dns.slow_resolver")
            .unwrap()
            .id
            .clone();
        engine.record_applied(
            &id,
            '1',
            crate::diagnose::issue::Applied::Yes {
                at: NOW.into(),
                before: RESOLVER.into(),
                after: ALT_RESOLVER.into(),
            },
        );

        // The operator switches resolver. dns.slow_resolver verifies on
        // p50 under 4.96ms held for 60s, so it must survive a while and then
        // close.
        for t in 301..=340 {
            engine.observe(&observations_with(t, true), &base);
            clock.advance_secs(1);
        }
        assert!(
            engine
                .primary()
                .iter()
                .any(|i| i.rule == "dns.slow_resolver"),
            "40s of quiet is not the 60s the rule asks for"
        );

        for t in 341..=380 {
            engine.observe(&observations_with(t, true), &base);
            clock.advance_secs(1);
        }
        assert!(
            !engine
                .primary()
                .iter()
                .any(|i| i.rule == "dns.slow_resolver"),
            "once verify has held for its window the issue closes itself"
        );
        let closed = engine
            .issues()
            .iter()
            .find(|i| i.rule == "dns.slow_resolver")
            .unwrap();
        assert!(matches!(
            closed.state,
            crate::diagnose::issue::IssueState::AutoClosed { .. }
        ));
    }

    /// The pinned corpus replays this episode through `observe_live_at`,
    /// which drops DNS and gateway observations with no completion time.
    /// Without health ages the corpus could not see either regress.
    #[test]
    fn fixture_episode_carries_health_ages() {
        let ep = episode();
        assert_eq!(ep.frames.len() as u64, SCENARIO_SECS + 1);
        for (t, f) in ep.frames.iter().enumerate() {
            for (probe, age) in [
                ("dns", f.ages.dns),
                ("gateway", f.ages.gateway),
                ("internet", f.ages.internet),
            ] {
                let age = age.unwrap_or_else(|| panic!("{}: no {probe} age", f.ts));
                assert_eq!(
                    age,
                    (t % 5) as f64,
                    "{}: {probe} age {age}s is off the prober's 5s grid",
                    f.ts
                );
            }
            assert_eq!(f.ages.dns_target.as_deref(), Some(RESOLVER), "{}", f.ts);
            assert_eq!(f.ages.gateway_target.as_deref(), Some(GATEWAY), "{}", f.ts);
        }
    }

    fn gzip(episode: &Episode) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        serde_json::to_writer(&mut gz, episode).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn record_is_deterministic() {
        let scenario = Scenario::incident();
        assert!(
            gzip(&record(&scenario)) == gzip(&record(&scenario)),
            "two recordings of one scenario differ"
        );
    }

    /// `Err` unless the pinned corpus episode `id` is what `rebuilt` holds:
    /// the frames the corpus replays, the settings and the profile. Issue
    /// snapshots are left out; they are the engine's output, which the
    /// pinned decisions already cover.
    fn is_pinned(id: &str, rebuilt: &Episode) -> Result<(), String> {
        use crate::diagnose::episode::{load, CORPUS_DIR};
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(CORPUS_DIR)
            .join(format!("{id}.json.gz"));
        let mut pinned = load(&path).map_err(|e| format!("{id}: {}: {e}", path.display()))?;
        // Through JSON, as the pinned copy went, so floats parse alike.
        let mut rebuilt: Episode =
            serde_json::from_str(&serde_json::to_string(rebuilt).unwrap()).unwrap();
        pinned.issues.clear();
        rebuilt.issues.clear();
        if rebuilt == pinned {
            return Ok(());
        }
        Err(format!(
            "{id}: its scenario no longer records the pinned episode; if that is intended, \
             run `cargo run -- diagnose corpus --unstable --only {id}` and review the diff"
        ))
    }

    /// The pinned `fixture-scenario` is what [`Scenario::incident`] records.
    #[test]
    fn the_incident_episode_is_unchanged_by_the_refactor() {
        is_pinned("fixture-scenario", &episode()).unwrap();
    }

    /// The replay test holds a pinned episode only to itself, so a scenario
    /// renamed, removed or edited without regenerating still passed it, and
    /// the next `diagnose corpus` failed on that row or quietly rewrote it.
    #[test]
    fn every_synthetic_corpus_entry_is_what_its_scenario_records() {
        use crate::diagnose::episode::{CorpusKind, Manifest, CORPUS_DIR};
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS_DIR);
        let manifest = Manifest::load(&dir).expect("corpus manifest");
        let failures: Vec<String> = manifest
            .entries
            .iter()
            .filter(|entry| entry.kind == CorpusKind::Synthetic)
            .filter_map(|entry| match synthetic(&entry.id) {
                Some(rebuilt) => is_pinned(&entry.id, &rebuilt).err(),
                None => Some(format!("{}: no scenario in fixture.rs builds it", entry.id)),
            })
            .collect();
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// The decisions the corpus pins for `id`, which the replay test holds
    /// the engine to.
    fn pinned_spans(id: &str) -> Vec<(String, Option<String>, Option<String>)> {
        use crate::diagnose::episode::{CanonicalDecisions, CORPUS_DIR};
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(CORPUS_DIR)
            .join(format!("{id}.decisions.json"));
        let text = std::fs::read_to_string(&path).expect("pinned decisions");
        let decisions: CanonicalDecisions = serde_json::from_str(&text).unwrap();
        decisions
            .issues
            .into_iter()
            .map(|s| (s.opened, s.closed, s.close_reason))
            .collect()
    }

    fn span(opened: &str, closed: &str, reason: &str) -> (String, Option<String>, Option<String>) {
        (opened.into(), Some(closed.into()), Some(reason.into()))
    }

    /// B25 closes a socket issue when its socket goes: each opens once on
    /// the fault, at 152 s, and ends Expired 60 s after the close at 300 s,
    /// whether a healthy socket is still listed or none is.
    #[test]
    fn a_socket_issue_expires_a_minute_after_its_socket_closes() {
        for id in [
            "retrans-socket-closes",
            "bufferbloat-remote-socket-closes",
            "zero-window-socket-closes",
        ] {
            assert_eq!(
                pinned_spans(id),
                vec![span(
                    "2026-09-03 06:46:32",
                    "2026-09-03 06:50:00",
                    "expired"
                )],
                "{id}"
            );
        }
    }

    /// B11 closes the σ rules at 2σ, under the 3σ open line. Each σ episode
    /// sits at 2.5σ before it recovers, so it closes only after the metric
    /// has held under 2σ; a 3σ close line would have closed it two minutes
    /// sooner.
    #[test]
    fn a_sigma_issue_closes_under_its_two_sigma_line() {
        // Open on the third slow trace (180 s); 16.5 ms from 300 s holds it
        // open; 13.4 ms from 420 s holds for 120 s.
        assert_eq!(
            pinned_spans("path-rtt-spike"),
            vec![span(
                "2026-09-03 06:47:00",
                "2026-09-03 06:53:00",
                "auto-closed"
            )]
        );
        // Open on the third slow probe (300 s); 50 ms from 360 s holds it
        // open; 41 ms from 480 s holds for 180 s.
        assert_eq!(
            pinned_spans("target-slow-stage"),
            vec![span(
                "2026-09-03 06:49:00",
                "2026-09-03 06:55:00",
                "auto-closed"
            )]
        );
    }

    /// B13 closes a slow-resolver issue relative to the line it opened on.
    /// The router's 150 ms p50 opens the issue on the third slow probe, at
    /// 130 s, over the ceiling and over its baseline's 21 ms line, and 11 ms
    /// from 300 s holds under 0.8 of the lower line for 60 s. The flat 5 ms
    /// line B13 replaced never closed it.
    #[test]
    fn a_router_resolver_issue_closes_under_the_line_it_opened_on() {
        assert_eq!(
            pinned_spans("dns-slow-router"),
            vec![span(
                "2026-09-03 06:46:10",
                "2026-09-03 06:50:00",
                "auto-closed"
            )]
        );
        let ep = synthetic("dns-slow-router").unwrap();
        let line = ep.issues[0].issue.verify.threshold;
        assert!((line - 16.8).abs() < 1e-9, "{line}");
    }

    /// A router answering in 40 ms opens gateway.rtt_spike on the third slow
    /// probe, at 130 s, and back at 1.0 ms from 300 s it closes once that
    /// has held under 2σ for 120 s.
    #[test]
    fn a_gateway_rtt_spike_closes_once_the_router_answers_again() {
        assert_eq!(
            pinned_spans("gateway-rtt"),
            vec![span(
                "2026-09-03 06:46:10",
                "2026-09-03 06:51:00",
                "auto-closed"
            )]
        );
    }

    /// B11's deadband, in the corpus. An access point hovering at the open
    /// line is one issue from its first open, at 130 s, until 120 s after
    /// the hover ends at 750 s. With the close line on the open line, the
    /// same frames close it after each dip and reopen it on each rise.
    #[test]
    fn a_gateway_hovering_at_the_open_line_stays_one_issue() {
        assert_eq!(
            pinned_spans("gateway-rtt-edge"),
            vec![span(
                "2026-09-03 06:46:10",
                "2026-09-03 06:58:30",
                "auto-closed"
            )]
        );
        let edge = scenarios()
            .into_iter()
            .find(|s| s.id == "gateway-rtt-edge")
            .unwrap();
        let flapping = record(&Scenario {
            thresholds: Thresholds {
                sigma_close_k: 3.0,
                ..Thresholds::default()
            },
            ..edge
        });
        let (decisions, _) = crate::diagnose::episode::CanonicalDecisions::of(&flapping);
        let closes: Vec<_> = decisions
            .issues
            .iter()
            .map(|s| s.closed.as_deref())
            .collect();
        assert_eq!(
            closes,
            vec![
                Some("2026-09-03 06:48:30"),
                Some("2026-09-03 06:52:00"),
                Some("2026-09-03 06:55:30"),
            ]
        );
    }

    /// A05 judges the link on what the platform reported. link.down opens
    /// on a carrier read as down, at 122 s, and closes 30 s after one read
    /// as up; wifi.weak_signal opens on −78 dBm and closes 120 s into
    /// −60 dBm.
    #[test]
    fn a_link_issue_opens_and_closes_on_what_was_read() {
        assert_eq!(
            pinned_spans("link-down"),
            vec![span(
                "2026-09-03 06:46:02",
                "2026-09-03 06:49:30",
                "auto-closed"
            )]
        );
        assert_eq!(
            pinned_spans("wifi-weak"),
            vec![span(
                "2026-09-03 06:46:02",
                "2026-09-03 06:51:00",
                "auto-closed"
            )]
        );
    }

    /// Three minutes with no interface info open nothing, and link.down is
    /// not measured on each of them rather than passed.
    #[test]
    fn an_unknown_carrier_opens_nothing_and_is_not_measured() {
        assert_eq!(pinned_spans("link-down-carrier-unknown"), vec![]);
        let ep = synthetic("link-down-carrier-unknown").unwrap();
        let mut unknown = 0;
        crate::diagnose::episode::drive(&ep, |step| {
            let carrier = step.frame.obs.iface.as_ref().and_then(|i| i.carrier);
            let link_down = step
                .engine
                .coverage()
                .rules
                .iter()
                .find(|r| r.rule == "link.down")
                .map(|r| r.status.clone());
            match carrier {
                None => {
                    unknown += 1;
                    assert_eq!(
                        link_down,
                        Some(Availability::NotMeasured),
                        "{}",
                        step.frame.ts
                    );
                }
                Some(_) => assert_eq!(
                    link_down,
                    Some(Availability::Available),
                    "{}",
                    step.frame.ts
                ),
            }
        });
        assert_eq!(unknown, 180);
    }

    /// A Wi-Fi driver's background drops open iface.errors two seconds in
    /// and hold it open to the end, because it closes only under 1/min
    /// errors and drops combined; `PENDING_CLOSE` in episode.rs says so.
    /// The drops are all that hold it: without them the errors open it at
    /// 124 s and it closes at 659 s, 300 s after the last error leaves the
    /// minute's count.
    #[test]
    fn background_wifi_drops_hold_iface_errors_open() {
        assert_eq!(
            pinned_spans("iface-errors-wifi-drops"),
            vec![("2026-09-03 06:44:02".to_string(), None, None)]
        );
        let scenario = scenarios()
            .into_iter()
            .find(|s| s.id == "iface-errors-wifi-drops")
            .unwrap();
        let errors_alone = record(&Scenario {
            obs: |t| {
                let mut obs = iface_errors_wifi_drops(t);
                obs.iface.as_mut().unwrap().drops_per_min = Some(0);
                obs
            },
            ..scenario
        });
        let (decisions, _) = crate::diagnose::episode::CanonicalDecisions::of(&errors_alone);
        let spans: Vec<_> = decisions
            .issues
            .into_iter()
            .map(|s| (s.opened, s.closed, s.close_reason))
            .collect();
        assert_eq!(
            spans,
            vec![span(
                "2026-09-03 06:46:04",
                "2026-09-03 06:54:59",
                "auto-closed"
            )]
        );
    }

    /// Without an age under its own name a target's result is dropped as
    /// stale, and the target episode would open nothing.
    #[test]
    fn a_target_scenario_carries_each_probe_age_under_the_targets_name() {
        let ep = synthetic("target-slow-stage").unwrap();
        assert_eq!(ep.frames.len(), 721);
        for (t, f) in ep.frames.iter().enumerate() {
            assert_eq!(
                f.ages.target_ages.get("api"),
                Some(&((t % 60) as f64)),
                "{}: off the target's 60 s grid",
                f.ts
            );
        }
    }

    /// What a new corpus scenario costs: a frame function and a `Scenario`.
    /// The gateway and everything past it stop answering for three minutes.
    fn gateway_outage(t: u64) -> Observations {
        use Phase::*;
        let mut obs = observations_at(0);
        if phase(t, &[(0, Healthy), (120, Fault), (300, Clear)]) == Fault {
            obs.gateway = Some(GatewayObs {
                rtt_ms: None,
                loss_pct: 100.0,
                arp_ok: Some(false),
                icmp_ok: false,
                internet_reachable: Some(false),
                ..healthy_gateway()
            });
        }
        obs
    }

    #[test]
    fn a_new_scenario_records_an_open_and_a_close() {
        let ep = record(&Scenario {
            id: "gateway-outage",
            start: WINDOW_START,
            secs: 600,
            baselines,
            obs: gateway_outage,
            cadence: Cadence::live(),
            thresholds: Thresholds::default(),
        });
        // A quiet sample from the first frame, so the pre-roll is all there.
        assert_eq!(ep.frames.len(), 601);
        let (decisions, report) = crate::diagnose::episode::CanonicalDecisions::of(&ep);
        assert!(report.matches(), "{:#?}", report.divergences.first());
        let spans: Vec<_> = decisions
            .issues
            .iter()
            .map(|s| (s.key.as_str(), s.close_reason.as_deref()))
            .collect();
        assert_eq!(
            spans,
            vec![("gateway.unreachable|host", Some("auto-closed"))],
            "{:#?}",
            decisions.issues
        );
    }

    #[test]
    fn a_scenario_that_opens_nothing_still_records_its_frames() {
        let ep = record(&Scenario {
            id: "quiet",
            // Before the reroute, and with the resolver still fast.
            obs: |_| observations_at(0),
            secs: 60,
            cadence: Cadence::live(),
            ..Scenario::incident()
        });
        assert_eq!(ep.frames.len(), 61);
        assert!(ep.issue_keys().is_empty(), "{:?}", ep.issue_keys());
    }

    #[test]
    fn a_phase_runs_from_its_start_to_the_next() {
        use Phase::*;
        let story = [(0, Healthy), (120, Fault), (300, Clear)];
        assert_eq!(phase(0, &story), Healthy);
        assert_eq!(phase(119, &story), Healthy);
        assert_eq!(phase(120, &story), Fault);
        assert_eq!(phase(299, &story), Fault);
        assert_eq!(phase(300, &story), Clear);
        assert_eq!(phase(10_000, &story), Clear);
    }

    #[test]
    fn live_cadence_stamps_each_collector_on_its_own_grid() {
        let start = Instant::now();
        let c = Cadence::live();
        let at =
            |period, t| Cadence::stamp(period, start, t).map(|i: Instant| (i - start).as_secs());
        assert_eq!(at(c.interface, 37), Some(37));
        assert_eq!(at(c.sockets, 37), Some(37));
        assert_eq!(at(c.health, 37), Some(35));
        assert_eq!(at(c.path, 37), Some(30));
        assert_eq!(at(c.targets, 137), Some(120));
        assert_eq!(at(None, 37), None);
    }

    #[test]
    fn the_run_is_deterministic() {
        let a = report();
        let b = report();
        assert_eq!(a.to_json().unwrap(), b.to_json().unwrap());
    }

    #[test]
    fn the_verdict_line_leads_with_the_worst_issue() {
        let (engine, base) = run();
        let line = engine.verdict(&base).line();
        assert!(line.starts_with("3 issues"), "{line}");
        assert!(line.contains("slow dns resolver"), "{line}");
        assert!(line.contains("33× baseline"), "{line}");
    }
}
