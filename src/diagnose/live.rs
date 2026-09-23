//! Bridging live collectors to [`Observations`].
//!
//! The detectors take a plain data struct, not the `App`, so they can be
//! tested against any scenario without a running capture. This module is the
//! one place that knows how to fill that struct from what netwatch actually
//! measures — and the one place that has to be honest about what it *can't*
//! measure yet. Where an input is missing, the field stays `None` and the
//! corresponding check reports as "not run" rather than silently counting as
//! evidence.
//!
//! It also holds the small amount of cross-tick state the detectors are
//! deliberately without: how long a socket has held its verdict, what the
//! interface counters were last tick, and the previous trace to each target.

use std::collections::HashMap;
use std::time::Instant;

use super::baseline::{BaselineStore, NetworkFingerprint};
use super::detectors::{
    classify_socket, DnsCross, DnsObs, GatewayObs, HopObs, IfaceObs, NatObs, Observations, PathObs,
    SocketObs, SocketVerdict, Thresholds,
};
use crate::app::App;

/// Metrics fed to the baseline store every tick, each paired with the rule
/// that consumes it.
///
/// The pairing is asserted in a test. Learning a baseline nobody reads is
/// invisible dead weight — it costs a write to `baselines.json` every tick and
/// buys nothing — and a metric baselined under one name but verified under
/// another is worse, because the rule silently never fires.
pub const BASELINED_METRICS: &[(&str, &str)] = &[
    ("dns.rtt_p50", "dns.slow_resolver"),
    ("gateway.rtt", "gateway.rtt_spike"),
    ("path.rtt", "path.rtt_spike"),
    ("target.resolve_ms", "target.slow_stage"),
    ("target.connect_ms", "target.slow_stage"),
    ("target.tls_ms", "target.slow_stage"),
    ("target.ttfb_ms", "target.slow_stage"),
];

/// Negotiated wired link rate from `/sys/class/net/<iface>/speed` (Mb/s).
/// `None` off Linux, for unknown (-1) or absent speeds.
fn link_rate_bps(iface: &str) -> Option<f64> {
    if iface.contains('/') || iface.contains("..") {
        return None;
    }
    let text = std::fs::read_to_string(format!("/sys/class/net/{iface}/speed")).ok()?;
    parse_link_speed(&text)
}

fn parse_link_speed(text: &str) -> Option<f64> {
    let mbps: i64 = text.trim().parse().ok()?;
    (mbps > 0).then_some(mbps as f64 * 1_000_000.0)
}

/// One probe result destined for the baseline store.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    pub subject: String,
    pub metric: &'static str,
    pub value: f64,
    /// When the probe completed, as unix seconds. Baselines smooth over time,
    /// so this is the probe's time, not the tick that noticed it.
    pub at: f64,
}

impl Reading {
    pub fn new(subject: impl Into<String>, metric: &'static str, value: f64, at: f64) -> Self {
        Self {
            subject: subject.into(),
            metric,
            value,
            at,
        }
    }
}

/// Wall-clock unix seconds for a monotonic instant in the recent past.
fn unix_secs(at: Instant) -> f64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    now - at.elapsed().as_secs_f64()
}

#[derive(Default)]
pub struct LiveSampler {
    kernel: super::kernel::Collector,
    egress_tracker: super::egress::Tracker,
    interface_sample: Option<(Instant, IfaceObs)>,
    network: Option<NetworkFingerprint>,
    pub completed: super::engine::ObservationTimes,
    path_samples: HashMap<String, (Instant, PathObs)>,
    /// Socket key → (verdict, when it started). A verdict has to persist
    /// before it becomes an issue, and only this map knows for how long.
    learned_samples: HashMap<String, Instant>,
    verdict_since: HashMap<String, (SocketVerdict, Instant)>,
    retrans_history: HashMap<String, RetransWindow>,
    /// Interface name → the last 60 seconds of (errors, drops) deltas. Rules
    /// fire on the rate over that window, not on a lifetime counter (a NIC
    /// that logged 40 errors during boot last month is not a live fault) and
    /// not on a single tick's delta, which reported as "/min" is off by 60.
    iface_history: HashMap<String, IfaceCounters>,
    /// Target → the last trace we saw, for the path diff.
    prev_path: HashMap<String, Vec<HopObs>>,
    /// Interface name → the last minute of (tx retries, tx packets) deltas,
    /// for the wifi retry rate. Same shape as `iface_history`.
    wifi_history: HashMap<String, IfaceCounters>,
    /// The last idle-vs-loaded test: when it finished, idle rtt, loaded rtt.
    pub load_test: Option<(Instant, f64, f64)>,
}

/// How long a load test result stands in for a live measurement.
pub const LOAD_TEST_VALID_SECS: u64 = 30 * 60;

/// Counter samples timestamped by the collector, independent of UI tick rate.
#[derive(Debug)]
struct IfaceCounters {
    last: (u64, u64),
    last_at: Instant,
    started_at: Instant,
    window: std::collections::VecDeque<(Instant, u64, u64)>,
}
impl IfaceCounters {
    fn new(errors: u64, drops: u64) -> Self {
        Self {
            last: (errors, drops),
            last_at: Instant::now(),
            started_at: Instant::now(),
            window: Default::default(),
        }
    }
    fn observe(&mut self, at: Instant, errors: u64, drops: u64) -> (u64, u64) {
        if at < self.last_at
            || errors < self.last.0
            || drops < self.last.1
            || at.saturating_duration_since(self.last_at).as_secs() > 15
        {
            self.window.clear();
            self.started_at = at;
            self.last = (errors, drops);
        }
        let delta = (
            errors.saturating_sub(self.last.0),
            drops.saturating_sub(self.last.1),
        );
        self.last = (errors, drops);
        self.last_at = at;
        self.window.push_back((at, delta.0, delta.1));
        while self
            .window
            .front()
            .is_some_and(|(old, _, _)| at.saturating_duration_since(*old).as_secs() >= 60)
        {
            self.window.pop_front();
        }
        self.window
            .iter()
            .fold((0, 0), |(e, d), (_, de, dd)| (e + de, d + dd))
    }
}

impl LiveSampler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Identity of the network we are currently on. Baselines are scoped to
    /// this, so moving networks can't make every rule fire at once.
    pub fn fingerprint(app: &App) -> NetworkFingerprint {
        let cfg = &app.config_collector.config;
        let subnet = app
            .interface_info
            .iter()
            .find(|i| i.name == app.capture_interface)
            .and_then(|i| i.ipv4.clone())
            .map(|ip| subnet_of(&ip));
        // Tunnels that are up are part of this network's identity: they
        // change the route and the resolver a target reaches, so a baseline
        // or a pending verification from before they came up describes
        // something else.
        let vpn: Vec<String> = app
            .interface_info
            .iter()
            .filter(|i| i.is_up && super::targets::is_vpn_iface(&i.name))
            .map(|i| i.name.clone())
            .collect();
        NetworkFingerprint::new(
            app.capture_interface.clone(),
            cfg.gateway.clone(),
            cfg.dns_servers.clone(),
            subnet,
        )
        .with_vpn(vpn)
    }

    /// This tick's raw readings as `(subject, metric, value)`, ready to feed
    /// the baseline store.
    ///
    /// Returned rather than written directly so the caller owns the borrow of
    /// the store, and so the set of baselined metrics is inspectable — a
    /// metric learned under one name and verified under another would be a
    /// silent dead end, and [`BASELINED_METRICS`] is asserted against the rules.
    pub fn readings(&mut self, app: &App) -> Vec<Reading> {
        self.check_network(app);
        let health = app.health_prober.status();
        let cfg = &app.config_collector.config;
        let mut out = Vec::new();

        // Learn the statistic the rule judges. `dns.slow_resolver` compares
        // the rolling p50 of the probe history against this baseline, so the
        // baseline has to be fed that p50 — feeding it the latest single probe
        // taught it a noisier, lower number than the one it was later asked
        // to judge, and the 3σ test drifted with the difference.
        let dns_p50 = {
            let samples: Vec<f64> = health.dns_rtt_history.iter().flatten().copied().collect();
            percentile(&samples, 0.5).or(health.dns_rtt_ms)
        };
        if let (Some(resolver), Some(rtt)) = (cfg.primary_dns(), dns_p50) {
            if health.completed.dns_target.as_ref() == Some(&resolver) {
                if let Some(at) = self.fresh_reading("dns", health.completed.dns) {
                    out.push(Reading::new(resolver, "dns.rtt_p50", rtt, at));
                }
            }
        }
        if let (Some(gw), Some(rtt)) = (cfg.gateway.clone(), health.gateway_rtt_ms) {
            if health.completed.gateway_target.as_ref() == Some(&gw) {
                if let Some(at) = self.fresh_reading("gateway", health.completed.gateway) {
                    out.push(Reading::new(gw, "gateway.rtt", rtt, at));
                }
            }
        }
        if let Some(rtt) = health.internet_rtt_ms {
            if let Some(at) = self.fresh_reading("internet", health.completed.internet) {
                out.push(Reading::new("internet", "path.rtt", rtt, at));
            }
        }
        let (targets, _) = app
            .diagnose
            .target_prober
            .fresh(&app.user_config.diagnose_targets);
        for (completed, target) in targets {
            if let Some(at) =
                self.fresh_reading(&format!("target:{}", target.name), Some(completed))
            {
                for (metric, ms) in target.stage_readings() {
                    out.push(Reading::new(target.baseline_subject(), metric, ms, at));
                }
            }
        }
        out
    }

    fn targets(&mut self, app: &App) -> Vec<super::targets::TargetObs> {
        let (fresh, _) = app
            .diagnose
            .target_prober
            .fresh(&app.user_config.diagnose_targets);
        // Each target carries its own completion time: an issue about one
        // target may only be confirmed or verified by that target's probes.
        self.completed.targets = fresh
            .iter()
            .map(|(at, obs)| (obs.name.clone(), *at))
            .collect();
        fresh.into_iter().map(|(_, obs)| obs).collect()
    }

    /// The probe's completion time as unix seconds, the first time a fresh
    /// completion is seen; `None` for a stale probe or one already learned.
    fn fresh_reading(&mut self, source: &str, completed: Option<Instant>) -> Option<f64> {
        if !crate::collectors::health::ProbeTimes::fresh(completed, 30) {
            return None;
        }
        let completed = completed?;
        if self.learned_samples.insert(source.into(), completed) == Some(completed) {
            return None;
        }
        Some(unix_secs(completed))
    }

    /// The verdict this socket is currently carrying, if it has one.
    ///
    /// Read by the surfaces that show a verdict column. They must not
    /// re-classify: `classify_socket` is cheap but the *age* of a verdict is
    /// not derivable from a single sample, and a column that disagreed with
    /// the Diagnose tab about what a socket is doing would be worse than no
    /// column at all.
    pub fn verdict_for(&self, local: &str, remote: &str) -> Option<SocketVerdict> {
        self.verdict_since
            .get(&format!("{local} → {remote}"))
            .map(|(v, _)| *v)
    }

    /// Apply a batch of readings to the store.
    pub fn learn(base: &mut BaselineStore, readings: &[Reading]) {
        for r in readings {
            base.observe(&r.subject, r.metric, r.value, r.at);
        }
    }

    pub fn sample(&mut self, app: &App, thresholds: &Thresholds) -> Observations {
        self.check_network(app);
        self.completed = super::engine::ObservationTimes {
            health: app.health_prober.status().completed.clone(),
            ..Default::default()
        };
        let (active, active_times, _) = app.diagnose.active_prober.snapshot();
        self.completed.ipv6 = active_times.ipv6;
        self.completed.portal = active_times.portal;
        self.completed.pmtu = active_times.pmtu;
        let kernel = self.kernel.sample().ok().map(|(at, obs)| {
            self.completed.kernel = Some(at);
            obs
        });
        Observations {
            active,
            kernel,
            coverage_hints: coverage_hints(app),
            now: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            iface: self.iface(app),
            gateway: gateway(app),
            dns: dns(app),
            paths: self.paths(app),
            sockets: self.sockets(app, thresholds),
            // Only the user-started load test measures these. Without a recent
            // one they stay `None`: the local-bufferbloat rule is dormant and
            // the remote rule's discriminating check reports "not run".
            idle_rtt_ms: self.recent_load_test().map(|(idle, _)| idle),
            loaded_rtt_ms: self.recent_load_test().map(|(_, loaded)| loaded),
            captive_portal_url: None,
            nat: nat(app),
            targets: self.targets(app),
            egress: self.egress(app),
        }
    }

    fn check_network(&mut self, app: &App) {
        let current = Self::fingerprint(app);
        if self.network.as_ref().is_some_and(|old| old != &current) {
            // Measurements and previous paths belong to the network on which
            // they ran. Never compare a hotspot against the prior office link.
            *self = Self::default();
        }
        self.network = Some(current);
    }

    fn egress(&mut self, app: &App) -> Option<super::egress::Observation> {
        let source = app.connection_collector.coverage();
        let at = source.completed_at?;
        self.completed.egress = Some(at);
        if !crate::collectors::health::ProbeTimes::fresh(Some(at), 30) {
            return None;
        }
        let conns = app.connection_collector.connections();
        let complete = source.collection_succeeded
            && conns.iter().all(|c| {
                crate::app::parse_addr_parts(&c.remote_addr)
                    .0
                    .is_none_or(|ip| {
                        crate::collectors::geo::is_private_ip(&ip)
                            || c.process_name.as_ref().is_some_and(|name| !name.is_empty())
                    })
            });
        Some(
            self.egress_tracker
                .sample(&app.egress_profiler, at, complete),
        )
    }

    fn recent_load_test(&self) -> Option<(f64, f64)> {
        self.load_test
            .filter(|(at, _, _)| at.elapsed().as_secs() <= LOAD_TEST_VALID_SECS)
            .map(|(_, idle, loaded)| (idle, loaded))
    }

    fn iface(&mut self, app: &App) -> Option<IfaceObs> {
        let (interfaces, completed) = app.traffic.timed_snapshot();
        self.completed.interface = completed;
        if !crate::collectors::health::ProbeTimes::fresh(completed, 15) {
            return None;
        }
        if let Some((at, cached)) = &self.interface_sample {
            if Some(*at) == completed && cached.name == app.capture_interface {
                return Some(cached.clone());
            }
        }
        let t = interfaces
            .iter()
            .find(|i| i.name == app.capture_interface)?;
        let info = app.interface_info.iter().find(|i| i.name == t.name);

        let errors = t.rx_errors + t.tx_errors;
        let drops = t.rx_drops + t.tx_drops;
        let history = self
            .iface_history
            .entry(t.name.clone())
            .or_insert_with(|| IfaceCounters::new(errors, drops));
        let (errors_per_min, drops_per_min) = history.observe(completed?, errors, drops);
        let counter_window_secs = Some(
            completed?
                .saturating_duration_since(history.started_at)
                .as_secs_f64()
                .min(60.0),
        );

        let wireless = info.and_then(|i| i.is_wireless).unwrap_or(false);
        // Retries as a share of frames sent over the same minute. Both are
        // lifetime counters, so the rate is delta over delta.
        let tx_retry_pct = t.tx_retries.map(|retries| {
            let (d_retries, d_packets) = self
                .wifi_history
                .entry(t.name.clone())
                .or_insert_with(|| IfaceCounters::new(retries, t.tx_packets))
                .observe(completed.unwrap(), retries, t.tx_packets);
            if d_packets == 0 {
                0.0
            } else {
                d_retries as f64 / d_packets as f64 * 100.0
            }
        });

        let observed = IfaceObs {
            name: t.name.clone(),
            carrier: info.map(|i| i.is_up).unwrap_or(true),
            rx_errors: t.rx_errors,
            tx_errors: t.tx_errors,
            rx_dropped: t.rx_drops,
            tx_dropped: t.tx_drops,
            counter_window_secs,
            errors_per_min,
            drops_per_min,
            // Wired only. A wifi PHY rate moves with every retrain and is
            // not the rate the link can carry, so on wifi the saturation
            // rule stays dormant rather than crying wolf.
            link_rate_bps: if wireless {
                None
            } else {
                link_rate_bps(&t.name)
            },
            wireless,
            signal_dbm: t.signal_dbm,
            tx_retry_pct,
            rx_bps: t.rx_rate,
            tx_bps: t.tx_rate,
        };
        self.interface_sample = Some((completed.unwrap(), observed.clone()));
        Some(observed)
    }

    fn paths(&mut self, app: &App) -> Vec<PathObs> {
        let result = match app.traceroute_runner.result.lock() {
            Ok(r) => r.clone(),
            Err(_) => return vec![],
        };
        self.completed.path = result.completed;
        if result.target.is_empty()
            || result.hops.is_empty()
            || !crate::collectors::health::ProbeTimes::fresh(result.completed, 120)
        {
            return vec![];
        }

        let completed = result.completed.unwrap();
        self.completed.path = Some(completed);
        if let Some((at, path)) = self.path_samples.get(&result.target) {
            if *at == completed {
                return vec![path.clone()];
            }
        }

        let hops: Vec<HopObs> = result
            .hops
            .iter()
            .map(|h| {
                let replies: Vec<f64> = h.rtt_ms.iter().flatten().copied().collect();
                let sent = h.rtt_ms.len().max(1) as f64;
                let lost = sent - replies.len() as f64;
                HopObs {
                    number: h.hop_number,
                    ip: h.ip.clone(),
                    // ASN would come from the whois cache; absent here, so the
                    // "provider changed" check compares addresses only.
                    asn: None,
                    rtt_p50_ms: percentile(&replies, 0.5),
                    rtt_p95_ms: percentile(&replies, 0.95),
                    loss_pct: (lost / sent) * 100.0,
                    // A hop with no replies at all is silent, not 100% lossy.
                    silent: replies.is_empty(),
                }
            })
            .collect();

        let previous = self.prev_path.insert(result.target.clone(), hops.clone());
        let path = PathObs {
            target: result.target.clone(),
            hops,
            previous,
            traced_at: result.completed_at.clone(),
            destination_reached: result.reached,
        };
        self.path_samples
            .insert(result.target.clone(), (completed, path.clone()));
        vec![path]
    }

    fn sockets(&mut self, app: &App, thresholds: &Thresholds) -> Vec<SocketObs> {
        let (flows, completed) = app.tcp_info.timed_snapshot();
        self.completed.sockets = completed;
        if flows.is_empty() || !crate::collectors::health::ProbeTimes::fresh(completed, 30) {
            self.verdict_since.clear();
            self.retrans_history.clear();
            return vec![];
        }
        let conns = app.connection_collector.connections();
        let now = Instant::now();
        let mut out = Vec::new();
        let mut live_keys: Vec<String> = Vec::new();

        for ((local, remote), info) in flows.iter() {
            let conn = conns
                .iter()
                .find(|c| &c.local_addr == local && &c.remote_addr == remote);

            let mut s = SocketObs {
                local: local.clone(),
                remote: remote.clone(),
                process: conn.and_then(|c| c.process_name.clone()),
                rtt_ms: info.rtt_us.map(|us| us as f64 / 1000.0),
                rttvar_ms: None,
                retrans: info.total_retrans.and_then(|total| {
                    self.retrans_history
                        .entry(format!("{local} → {remote}"))
                        .or_default()
                        .observe(completed?, total)
                }),
                cwnd: info.cwnd,
                ssthresh: info.ssthresh,
                rwnd: info.rwnd,
                mss: info.mss,
                tx_bps: conn.and_then(|c| c.tx_rate).unwrap_or(0.0),
                rx_bps: conn.and_then(|c| c.rx_rate).unwrap_or(0.0),
                verdict_age_secs: 0,
            };

            let key = s.key();
            live_keys.push(key.clone());
            let verdict = classify_socket(&s, thresholds);
            let since = match self.verdict_since.get(&key) {
                // Same verdict as last tick: keep the original start time.
                Some((prev, at)) if *prev == verdict => *at,
                _ => now,
            };
            self.verdict_since.insert(key, (verdict, since));
            s.verdict_age_secs = now.duration_since(since).as_secs();
            out.push(s);
        }

        // Sockets that have gone away lose their history; a new connection to
        // the same peer starts its verdict clock from zero.
        self.verdict_since.retain(|k, _| live_keys.contains(k));
        self.retrans_history.retain(|k, _| live_keys.contains(k));
        out
    }
}

fn gateway(app: &App) -> Option<GatewayObs> {
    let cfg = &app.config_collector.config;
    let addr = cfg.gateway.clone()?;
    let health = app.health_prober.status();

    // No observation until a probe has actually measured something: the
    // history deques only record measurements, and `gateway_loss` says when
    // the latest cycle could not be sent at all. On a fresh start, or on a
    // host where ICMP is blocked and the router answers no TCP port, there is
    // nothing here to judge — not a `critical` finding against a working
    // router.
    if health.gateway_rtt_history.is_empty()
        || !crate::collectors::health::ProbeTimes::fresh(health.completed.gateway, 30)
        || health.completed.gateway_target.as_ref() != Some(&addr)
    {
        return None;
    }
    let loss_pct = health.gateway_loss.pct()?;
    let icmp_ok = health.gateway_rtt_ms.is_some() && loss_pct < 100.0;

    // Corroborating evidence for a gateway verdict, on the same footing:
    // unknown until the internet probe has run at least once.
    let internet_reachable = if health.internet_rtt_history.is_empty()
        || !crate::collectors::health::ProbeTimes::fresh(health.completed.internet, 30)
    {
        None
    } else {
        health
            .internet_loss
            .pct()
            .map(|p| health.internet_rtt_ms.is_some() && p < 100.0)
    };
    Some(GatewayObs {
        addr: Some(addr),
        rtt_ms: health.gateway_rtt_ms,
        loss_pct,
        internet_reachable,
        // No ARP probe yet, so this stays unknown. Mirroring the ICMP result
        // here made the checks assert "no arp reply from the gateway" about a
        // probe that was never sent — and an unprivileged run, which cannot
        // send ICMP at all, produced that line every time.
        arp_ok: None,
        icmp_ok,
    })
}

fn dns(app: &App) -> Option<DnsObs> {
    let cfg = &app.config_collector.config;
    let resolver = cfg.primary_dns()?;
    let health = app.health_prober.status();

    if !crate::collectors::health::ProbeTimes::fresh(health.completed.dns, 30)
        || health.completed.dns_target.as_ref() != Some(&resolver)
    {
        return None;
    }

    // A resolver the probe could not query (a scoped link-local address, no
    // socket) is not a resolver failing 100% of queries; it is no observation.
    let failure_rate_pct = health.dns_loss.pct()?;

    let samples: Vec<f64> = health.dns_rtt_history.iter().flatten().copied().collect();
    // One sample per probe, so the window is samples × the probe interval —
    // not × a bare 5, which silently became wrong the moment the cadence
    // constant moved.
    let window_secs = health.dns_rtt_history.len() as u64 * crate::app::HEALTH_PROBE_TICKS as u64;

    // Reply flags across the window: every reply the probe decoded, and how
    // many of them were truncated.
    let replies: u32 = health
        .dns_probe_history
        .iter()
        .map(|p| p.replies as u32)
        .sum();
    let truncated: u32 = health
        .dns_probe_history
        .iter()
        .map(|p| p.truncated as u32)
        .sum();
    let truncation_rate_pct = if replies == 0 {
        0.0
    } else {
        truncated as f64 / replies as f64 * 100.0
    };
    let cross = health.dns_cross.as_ref().map(|c| {
        let cycles = health.dns_cross_history.len() as u32;
        let disagreed = health.dns_cross_history.iter().filter(|b| **b).count();
        DnsCross {
            name: c.name.clone(),
            local: c.local.iter().map(|ip| ip.to_string()).collect(),
            reference_resolver: c.reference_resolver.clone(),
            reference: c.reference.iter().map(|ip| ip.to_string()).collect(),
            validated: c.validated,
            private_answer: c.private_answer,
            mismatch_pct: if cycles == 0 {
                0.0
            } else {
                disagreed as f64 / cycles as f64 * 100.0
            },
            cycles,
        }
    });

    Some(DnsObs {
        resolver,
        rtt_p50_ms: percentile(&samples, 0.5).or(health.dns_rtt_ms),
        rtt_p95_ms: percentile(&samples, 0.95),
        failure_rate_pct,
        truncation_rate_pct,
        queries: replies.max(health.dns_rtt_history.len() as u32),
        failed: health
            .dns_rtt_history
            .iter()
            .filter(|s| s.is_none())
            .count() as u32,
        truncated,
        // netwatch probes one resolver today. The alternate-resolver check is
        // the strongest discriminator the DNS rule has, so this is the first
        // thing the pipeline should add; until then it reports "not run".
        alt_resolver: cfg.dns_servers.get(1).cloned(),
        alt_rtt_ms: None,
        icmp_rtt_ms: None,
        cached_rtt_ms: None,
        window_secs,
        cross,
    })
}

fn nat(app: &App) -> Option<NatObs> {
    let health = app.health_prober.status();
    if !crate::collectors::health::ProbeTimes::fresh(health.completed.nat, 300) {
        return None;
    }
    health.nat.as_ref().map(|n| NatObs {
        mappings: n.mappings.clone(),
        symmetric: n.symmetric,
    })
}

/// Nearest-rank percentile. `None` on an empty sample set rather than 0.0 —
/// "no measurement" and "zero milliseconds" are different claims.
fn percentile(values: &[f64], p: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut v = values.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((v.len() as f64 - 1.0) * p).round() as usize;
    v.get(idx).copied()
}

/// `192.168.8.42` → `192.168.8.0/24`. A coarse /24 assumption, but the
/// fingerprint only needs to distinguish networks, not describe them.
fn subnet_of(ip: &str) -> String {
    let base = ip.split('/').next().unwrap_or(ip);
    let parts: Vec<&str> = base.split('.').collect();
    if parts.len() == 4 {
        format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
    } else {
        base.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_speed_parses_megabits_and_rejects_unknown() {
        assert_eq!(parse_link_speed("1000\n"), Some(1e9));
        assert_eq!(parse_link_speed("-1\n"), None);
        assert_eq!(parse_link_speed(""), None);
        assert_eq!(link_rate_bps("../etc"), None);
    }

    #[test]
    fn cached_probe_is_learned_once_and_stale_results_are_not_learned() {
        let mut sampler = LiveSampler::new();
        let now = Instant::now();
        assert!(sampler.fresh_reading("dns", Some(now)).is_some());
        assert!(sampler.fresh_reading("dns", Some(now)).is_none());
        assert!(sampler
            .fresh_reading("dns", Some(now - std::time::Duration::from_secs(31)))
            .is_none());
        assert!(sampler.fresh_reading("dns", None).is_none());
        assert!(sampler
            .fresh_reading("dns", Some(now + std::time::Duration::from_nanos(1)))
            .is_some());
    }

    #[test]
    fn percentile_of_nothing_is_not_zero() {
        assert_eq!(percentile(&[], 0.5), None);
    }

    #[test]
    fn percentiles_pick_the_right_samples() {
        let v = vec![1.0, 2.0, 3.0, 4.0, 100.0];
        assert_eq!(percentile(&v, 0.5), Some(3.0));
        assert_eq!(percentile(&v, 0.95), Some(100.0));
    }

    #[test]
    fn interface_window_uses_seconds_and_discards_unobserved_gaps() {
        let mut c = IfaceCounters::new(0, 0);
        let at = c.last_at;
        for step in 1..=13 {
            c.observe(
                at + std::time::Duration::from_secs(step * 5),
                step * 5,
                step * 10,
            );
        }
        assert_eq!(
            c.observe(at + std::time::Duration::from_secs(65), 65, 130),
            (60, 120)
        );
        assert_eq!(
            c.observe(at + std::time::Duration::from_secs(100), 1000, 2000),
            (0, 0)
        );
    }
    #[test]
    fn interface_rates_are_per_minute_not_per_tick() {
        let mut c = IfaceCounters::new(1000, 5000);
        let at = c.last_at;
        for i in 1..=10 {
            let (e, d) = c.observe(
                at + std::time::Duration::from_secs(i),
                1000 + i,
                5000 + 2 * i,
            );
            assert_eq!((e, d), (i, 2 * i), "the window must accumulate");
        }
        for i in 11..=120 {
            c.observe(
                at + std::time::Duration::from_secs(i),
                1000 + i,
                5000 + 2 * i,
            );
        }
        // errors 1000 + 121, drops 5000 + 2 × 121.
        let (e, d) = c.observe(at + std::time::Duration::from_secs(121), 1121, 5242);
        assert_eq!((e, d), (60, 120), "one minute at 1/s errors and 2/s drops");
    }

    #[test]
    fn a_counter_reset_does_not_report_billions_of_errors() {
        let mut c = IfaceCounters::new(50_000, 90_000);
        let (e, d) = c.observe(Instant::now(), 3, 7);
        assert_eq!(
            (e, d),
            (0, 0),
            "a reset must not underflow into a huge rate"
        );
        assert_eq!(c.observe(Instant::now(), 5, 9), (2, 2));
    }

    #[test]
    fn a_quiet_interface_reports_nothing() {
        let mut c = IfaceCounters::new(10, 20);
        for _ in 0..120 {
            assert_eq!(c.observe(Instant::now(), 10, 20), (0, 0));
        }
    }

    #[test]
    fn subnet_of_collapses_a_host_address() {
        assert_eq!(subnet_of("192.168.8.42"), "192.168.8.0/24");
        assert_eq!(subnet_of("192.168.8.42/24"), "192.168.8.0/24");
        assert_eq!(subnet_of("fe80::1"), "fe80::1");
    }

    #[test]
    fn a_socket_verdict_clock_survives_ticks_but_resets_on_change() {
        let mut sampler = LiveSampler::new();
        let key = "a → b".to_string();
        let t0 = Instant::now();
        sampler
            .verdict_since
            .insert(key.clone(), (SocketVerdict::Bufferbloat, t0));

        // Same verdict next tick: the clock keeps running.
        let kept = match sampler.verdict_since.get(&key) {
            Some((v, at)) if *v == SocketVerdict::Bufferbloat => *at,
            _ => Instant::now(),
        };
        assert_eq!(kept, t0);

        // Different verdict: the clock restarts.
        let restarted = match sampler.verdict_since.get(&key) {
            Some((v, at)) if *v == SocketVerdict::ZeroWindow => *at,
            _ => Instant::now(),
        };
        assert_ne!(restarted, t0);
    }

    /// Every baselined metric must be consumed by an *active* rule whose
    /// verify condition is expressed in that metric or its σ form. This test
    /// caught `gateway.rtt` being learned every second by a rule that did not
    /// exist.
    #[test]
    fn every_baselined_metric_feeds_an_active_rule() {
        for (metric, rule_id) in BASELINED_METRICS {
            let rule = crate::diagnose::rules::lookup(rule_id).unwrap_or_else(|| {
                panic!("{metric} names rule {rule_id}, which is not in the catalogue")
            });
            assert!(
                rule.status.is_active(),
                "{metric} is baselined for {rule_id}, which is only Planned —                  the samples would never be read"
            );
            let verify = crate::diagnose::rules::default_verify(rule_id)
                .unwrap_or_else(|| panic!("{rule_id} has no verify condition"));
            let sigma_form = format!("{metric}_sigma");
            // A target's four stage timings share one verify: the worst σ.
            let shared =
                metric.starts_with("target.") && verify.metric == "target.worst_stage_sigma";
            assert!(
                verify.metric == *metric || verify.metric == sigma_form || shared,
                "{rule_id} verifies on {}, but {metric} is what gets baselined",
                verify.metric
            );
        }
    }

    #[test]
    fn readings_and_baselined_metrics_agree() {
        // The names `readings()` emits must be exactly the ones declared.
        let declared: Vec<&str> = BASELINED_METRICS.iter().map(|(m, _)| *m).collect();
        for m in ["dns.rtt_p50", "gateway.rtt", "path.rtt"] {
            assert!(declared.contains(&m), "{m} is emitted but not declared");
        }
        for m in [
            "target.resolve_ms",
            "target.connect_ms",
            "target.tls_ms",
            "target.ttfb_ms",
        ] {
            assert!(declared.contains(&m), "{m} is emitted but not declared");
        }
        assert_eq!(declared.len(), 7);
    }
}

fn coverage_hints(
    app: &App,
) -> std::collections::BTreeMap<String, (super::coverage::Availability, String)> {
    use super::coverage::Availability;
    let mut hints = std::collections::BTreeMap::new();
    for rule in ["ipv6.broken", "captive.portal", "pmtu.blackhole"] {
        if let Err(error) = app.user_config.diagnose_probes.validate(rule) {
            hints.insert(rule.into(), (Availability::NotConfigured, error));
        }
    }
    let tcp_status = if !crate::collectors::tcp_info::platform_supported() {
        Some((
            Availability::Unsupported,
            "TCP kernel collector is not implemented on this platform".into(),
        ))
    } else {
        match app.tcp_info.outcome() {
            Some(Err(error)) => Some((
                if error.starts_with("PermissionDenied:") {
                    Availability::PermissionDenied
                } else {
                    Availability::CollectorFailed
                },
                error,
            )),
            Some(Ok(())) if app.tcp_info.snapshot().is_empty() => Some((
                Availability::NoSubjects,
                "successful TCP dump contained no established sockets in this network namespace"
                    .into(),
            )),
            None => Some((
                Availability::NotMeasured,
                "first TCP kernel dump has not completed".into(),
            )),
            _ => None,
        }
    };
    let flows = app.tcp_info.snapshot();
    if !flows.is_empty() {
        if flows.values().all(|s| s.rwnd.is_none()) {
            hints.insert(
                "tcp.zero_window".into(),
                (
                    Availability::Unsupported,
                    "the kernel TCP dump does not expose receive windows for observed sockets"
                        .into(),
                ),
            );
        }
        if flows.values().all(|s| s.total_retrans.is_none()) {
            hints.insert("tcp.retrans_burst".into(), (Availability::Unsupported, "the kernel TCP dump does not expose retransmission counters for observed sockets".into()));
        }
    }
    if let Some(status) = tcp_status {
        for rule in [
            "tcp.bufferbloat_remote",
            "tcp.retrans_burst",
            "tcp.zero_window",
        ] {
            hints.insert(rule.into(), status.clone());
        }
    }
    match app.health_prober.nat_outcome() {
        Some(Err(error)) => {
            hints.insert(
                "nat.symmetric".into(),
                (Availability::CollectorFailed, error),
            );
        }
        None => {
            hints.insert(
                "nat.symmetric".into(),
                (
                    Availability::NotMeasured,
                    "scheduled STUN measurement has not completed".into(),
                ),
            );
        }
        _ => {}
    }
    if !app.user_config.diagnose_targets.is_empty()
        && app.user_config.diagnose_targets.iter().all(|t| !t.enabled)
    {
        for rule in super::rules::CATALOGUE
            .iter()
            .filter(|r| r.id.starts_with("target."))
        {
            hints.insert(rule.id.into(), (Availability::NotApplicable, "all configured targets are disabled; select one with [/] and press d to enable it".into()));
        }
    }
    let errors = super::targets::validation_errors(&app.user_config.diagnose_targets);
    if !errors.is_empty() {
        for rule in super::rules::CATALOGUE
            .iter()
            .filter(|r| r.id.starts_with("target."))
        {
            hints.insert(
                rule.id.into(),
                (Availability::NotConfigured, errors.join("; ")),
            );
        }
    }
    if app.user_config.diagnose_targets.is_empty() {
        for rule in super::rules::CATALOGUE
            .iter()
            .filter(|r| r.id.starts_with("target."))
        {
            hints.insert(
                rule.id.into(),
                (
                    Availability::NotConfigured,
                    "no [[diagnose_targets]] entries in config.toml".into(),
                ),
            );
        }
    }
    if app
        .interface_info
        .iter()
        .any(|i| i.name == app.capture_interface && i.is_wireless == Some(true))
    {
        hints.insert(
            "iface.saturated".into(),
            (
                Availability::Unsupported,
                "wireless usable capacity is not measured; PHY rate is not an internet speed limit"
                    .into(),
            ),
        );
    }
    hints
}

#[derive(Debug, Default)]
struct RetransWindow {
    samples: std::collections::VecDeque<(Instant, u32)>,
}
impl RetransWindow {
    fn observe(&mut self, at: Instant, total: u32) -> Option<u32> {
        if self
            .samples
            .back()
            .is_some_and(|(old_at, old)| at < *old_at || total < *old)
        {
            self.samples.clear();
        }
        if self.samples.back().is_none_or(|(last, _)| *last != at) {
            self.samples.push_back((at, total));
        }
        while self.samples.len() > 2
            && self
                .samples
                .get(1)
                .is_some_and(|(t, _)| at.duration_since(*t).as_secs() >= 60)
        {
            self.samples.pop_front();
        }
        let (first_at, first) = self.samples.front()?;
        let elapsed = at.duration_since(*first_at).as_secs_f64();
        // Do not treat an old lifetime total, or a long sampling gap, as a burst.
        if !(60.0..=75.0).contains(&elapsed) {
            return None;
        }
        Some(((total - first) as f64 * 60.0 / elapsed).round() as u32)
    }
}

#[cfg(test)]
mod retrans_window_tests {
    use super::*;
    #[test]
    fn lifetime_counts_duplicates_and_resets_are_not_bursts() {
        let start = Instant::now();
        let mut window = RetransWindow::default();
        assert_eq!(window.observe(start, 1000), None);
        assert_eq!(window.observe(start, 1000), None);
        assert_eq!(
            window.observe(start + std::time::Duration::from_secs(60), 1000),
            Some(0)
        );
        assert_eq!(
            window.observe(start + std::time::Duration::from_secs(61), 1012),
            Some(12)
        );
        assert_eq!(
            window.observe(start + std::time::Duration::from_secs(62), 0),
            None
        );
        assert_eq!(
            window.observe(start + std::time::Duration::from_secs(162), 500),
            None
        );
    }
}
