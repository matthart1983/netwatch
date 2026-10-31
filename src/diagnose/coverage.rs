//! Runtime input coverage for the diagnostic catalogue. Counts describe
//! available rule inputs, not proof that all traffic or subjects were observed.
use super::{
    baseline::{BaselineStore, SigmaFloor},
    detectors::Observations,
    rules::{self, RuleStatus},
};
use serde::{Deserialize, Serialize};

/// Defined beside `CheckResult`, which carries it as `why_not`, so `issue.rs`
/// still needs nothing but serde and fmt.
pub use super::issue::Availability;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCoverage {
    pub rule: String,
    pub status: Availability,
    pub reason: String,
}

impl RuleCoverage {
    pub fn source(&self) -> &'static str {
        match self.rule.split('.').next().unwrap_or("") {
            "ipv6" => "paired IPv4/IPv6 TCP experiment",
            "captive" => "independent HTTP expected-response experiment",
            "pmtu" => "DF ping and per-socket TCP MSS experiment",
            "dns" => "resolver probes",
            "gateway" => "gateway and internet probes",
            "link" | "iface" | "wifi" => "selected interface collector",
            "path" => "traceroute",
            "target" => "configured target probes",
            "nat" => "two-server STUN probe",
            "egress" => "egress profiler",
            "tcp" if self.rule == "tcp.bufferbloat_local" => "manual idle-versus-loaded test",
            "tcp" => "TCP sockets in this network namespace",
            _ => "no live observation adapter",
        }
    }

    pub fn next_action(&self) -> &'static str {
        match self.status {
            Availability::Available => "continue monitoring observed subjects",
            Availability::Learning => "keep Netwatch running on this network to learn its baseline",
            Availability::NotImplemented => "collector and detector implementation still required",
            Availability::NotApplicable => "no action needed for this interface or target",
            Availability::PermissionDenied => "inspect the collector error and required capability",
            Availability::CollectorFailed => "inspect the collector error, then retry",
            // Before the experiment rows: an experiment this platform cannot
            // run must not offer t.
            Availability::Unsupported => {
                "nothing to run on this host or interface; the reason says what is missing"
            }
            // Before the rule rows too: `t` will not start STUN with the
            // switch off, so the nat row must not offer it.
            _ if self.reason.starts_with(crate::collectors::health::PROBES_OFF) => {
                "set third_party_probes = true in config.toml to measure this"
            }
            _ if matches!(self.rule.as_str(), "ipv6.broken" | "captive.portal" | "pmtu.blackhole") => { "configure [diagnose_probes]; t runs three rounds, x cancels; direct selected-endpoint traffic only" }
            _ if self.rule.starts_with("egress.") => {
                "review the Egress tab; press t on the policy check to reload egress-policy.toml"
            }
            _ if self.rule.starts_with("target.") => {
                "check [[diagnose_targets]] in config.toml; wait for the next probe"
            }
            _ if self.rule.starts_with("path.") => {
                "press t in Diagnose coverage to trace diagnose_probes.trace_target; run twice to compare paths"
            }
            _ if self.rule == "tcp.bufferbloat_local" => {
                "run load.idle_vs_loaded after reviewing its traffic cost"
            }
            _ if self.rule == "nat.symmetric" => {
                "press t in Diagnose coverage to retry STUN; check UDP reachability if it fails"
            }
            _ if self.rule.starts_with("tcp.") => {
                "observe active TCP connections in this network namespace"
            }
            _ => "wait for a fresh collector sample; inspect netwatch doctor if this persists",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub rules: Vec<RuleCoverage>,
}

impl Coverage {
    /// Keep each area's rules together (catalogue order otherwise), so a list
    /// or table grouped by area names each area once.
    fn group_by_area(&mut self) {
        let mut areas: Vec<String> = Vec::new();
        for row in &self.rules {
            let area = row.rule.split('.').next().unwrap_or("").to_string();
            if !areas.contains(&area) {
                areas.push(area);
            }
        }
        self.rules.sort_by_key(|row| {
            let area = row.rule.split('.').next().unwrap_or("");
            areas.iter().position(|a| a == area)
        });
    }

    pub fn label(&self) -> String {
        if self.rules.is_empty() {
            return "coverage not recorded".into();
        }
        let available = self
            .rules
            .iter()
            .filter(|r| r.status == Availability::Available)
            .count();
        let mut counts = std::collections::BTreeMap::<&str, usize>::new();
        for row in &self.rules {
            if row.status != Availability::Available {
                *counts.entry(row.status.label()).or_default() += 1;
            }
        }
        let details = counts
            .into_iter()
            .map(|(label, n)| format!("{n} {label}"))
            .collect::<Vec<_>>()
            .join(" · ");
        format!(
            "{available}/{} rule inputs available{}",
            self.rules.len(),
            if details.is_empty() {
                String::new()
            } else {
                format!(" · {details}")
            }
        )
    }

    pub fn mark_stale_probes(
        &mut self,
        times: &crate::collectors::health::ProbeTimes,
        now: std::time::Instant,
    ) {
        use crate::collectors::health::ProbeTimes;
        for row in &mut self.rules {
            let sample = if row.rule.starts_with("dns.") {
                Some((times.dns, 30))
            } else if row.rule.starts_with("gateway.") {
                Some((times.gateway, 30))
            } else if row.rule == "nat.symmetric" {
                Some((times.nat, 300))
            } else {
                None
            };
            if let Some((Some(at), limit)) = sample {
                if !ProbeTimes::fresh_at(Some(at), limit, now) {
                    row.status = Availability::Stale;
                    row.reason =
                        format!("probe result is older than {limit}s; excluded from evaluation");
                }
            }
        }
    }

    /// `floor` is the detectors' σ floor: a baseline that has never varied
    /// is judged against it, so it is usable.
    pub fn from_observations(obs: &Observations, base: &BaselineStore, floor: SigmaFloor) -> Self {
        use Availability::*;
        let present = |yes, reason| {
            if yes {
                (Available, "inputs present for observed subjects")
            } else {
                (NotMeasured, reason)
            }
        };
        let baseline = |value: Option<f64>, subject: Option<&str>, metric| {
            if value.is_none() {
                return (NotMeasured, "RTT not measured");
            }
            match subject.and_then(|s| base.get(s, metric)) {
                Some(b) if b.sigma_floored(floor) > f64::EPSILON => {
                    (Available, "RTT and usable baseline present")
                }
                _ => (
                    Learning,
                    "baseline absent, learning, or has no measurable variation",
                ),
            }
        };
        // Behind a local stub the resolver RTT is measured, so the rule stays
        // available, but what it times is the stub answering root NS from its
        // cache. The reason says so rather than implying the upstream is fast.
        let stub = obs
            .dns
            .as_ref()
            .filter(|d| d.rtt_p50_ms.is_some() && d.is_local_stub())
            .map(|d| {
                format!(
                    "limited: measures the local stub at {}, not the upstream",
                    d.resolver
                )
            });
        let mut coverage = Self { rules: rules::CATALOGUE.iter().map(|rule| {
            let (status, reason) = if let RuleStatus::Planned(reason) = rule.status {
                (NotImplemented, reason)
            } else { match rule.id {
                "ipv6.broken" | "captive.portal" | "pmtu.blackhole" => obs.active.get(rule.id).map(|o| o.coverage()).unwrap_or((AwaitingTest,"press t to run three bounded experiment rounds; x cancels")),
                "tcp.connect_failures" | "tcp.timewait_exhaustion" => obs.kernel.as_ref().map(|o| o.coverage(rule.id)).unwrap_or((if cfg!(target_os = "linux") { CollectorFailed } else { Unsupported }, "namespace TCP accounting unavailable")),
                "egress.drift" | "egress.policy_violation" => obs.egress.as_ref().map(|o| o.coverage(rule.id)).unwrap_or((NotMeasured, "no fresh egress observation")),
                "iface.errors" if obs.iface.as_ref().and_then(|i| i.counter_window_secs).is_some_and(|s| s < 60.0) => (Learning, "collecting a full elapsed minute of interface counter changes"),
                "link.down" if obs.iface.as_ref().is_some_and(|i| i.carrier.is_none()) => (NotMeasured, "no interface info, so carrier state is unknown"),
                "iface.errors" if obs.iface.as_ref().is_some_and(|i| i.drops_per_min.is_none()) => (Available, "interface error counters present; drops not counted on macOS"),
                "link.down" | "iface.errors" => present(obs.iface.is_some(), "interface counters not measured"),
                "iface.saturated" => present(obs.iface.as_ref().and_then(|i| i.utilisation_pct()).is_some(), "link rate or interface counters missing"),
                "wifi.weak_signal" if obs.iface.as_ref().is_some_and(|i| i.wireless == Some(false)) => (NotApplicable, "selected interface is not wireless"),
                "wifi.weak_signal" if obs.iface.as_ref().is_some_and(|i| i.wireless.is_none()) => (NotMeasured, "not known whether the selected interface is wireless"),
                "wifi.weak_signal" => present(obs.iface.as_ref().is_some_and(|i| i.wireless == Some(true) && (i.signal_dbm.is_some() || i.tx_retry_pct.is_some())), "wireless signal/retries not measured"),
                "gateway.unreachable" => present(obs.gateway.as_ref().is_some_and(|g| g.addr.is_some() && g.internet_reachable.is_some()), "gateway and corroborating internet probe required"),
                "gateway.rtt_spike" => baseline(obs.gateway.as_ref().and_then(|g| g.rtt_ms), obs.gateway.as_ref().and_then(|g| g.addr.as_deref()), "gateway.rtt"),
                "dns.slow_resolver" if stub.is_some() => (Available, stub.as_deref().unwrap_or_default()),
                "dns.slow_resolver" => present(obs.dns.as_ref().and_then(|d| d.rtt_p50_ms).is_some(), "resolver RTT not measured; absolute threshold remains usable without a baseline"),
                "dns.failing" | "dns.truncation_retry" => present(obs.dns.as_ref().is_some_and(|d| d.queries > 0), "no DNS query outcomes measured"),
                "dns.hijack_suspect" => present(obs.dns.as_ref().and_then(|d| d.cross.as_ref()).is_some(), "resolver cross-check not measured"),
                id if id.starts_with("path.") && obs.paths.is_empty() => (AwaitingTest, "run a traceroute; results remain usable for 120 seconds"),
                "path.changed" => present(obs.paths.iter().any(|p| p.previous.is_some() && !p.hops.is_empty()), "current and previous traces required"),
                "path.high_loss" => present(obs.paths.iter().any(|p| p.hops.iter().any(|h| !h.silent)), "no responding path hops measured"),
                "path.rtt_spike" => {
                    let states: Vec<_> = obs.paths.iter().map(|p| {
                        let subject = if base.get(&p.target, "path.rtt").is_some() { p.target.as_str() } else { "internet" };
                        baseline(p.hops.iter().rev().find(|h| !h.silent).and_then(|h| h.rtt_p50_ms), Some(subject), "path.rtt")
                    }).collect();
                    if states.iter().any(|(s, _)| *s == Available) { (Available, "path RTT and usable baseline present") }
                    else if states.iter().any(|(s, _)| *s == Learning) { (Learning, "path baseline unavailable") }
                    else { (NotMeasured, "path RTT not measured") }
                },
                "tcp.bufferbloat_local" if obs.idle_rtt_ms.is_none() || obs.loaded_rtt_ms.is_none() => (AwaitingTest, "run the idle-versus-loaded RTT test"),
                "tcp.bufferbloat_local" => (Available, "idle and loaded RTT measured"),
                "tcp.bufferbloat_remote" => present(obs.sockets.iter().any(|s| s.rtt_ms.is_some()), "socket RTT not measured"),
                "tcp.retrans_burst" => present(obs.sockets.iter().any(|s| s.rtt_ms.is_some() && s.retrans.is_some()), "socket RTT and a full minute of retransmission counters required"),
                "tcp.zero_window" => present(obs.sockets.iter().any(|s| s.rwnd.is_some()), "socket receive window not measured"),
                "nat.symmetric" => present(obs.nat.is_some(), "STUN mappings not measured"),
                "target.resolve_failed" => present(!obs.targets.is_empty(), "no completed target resolution; check target configuration"),
                "target.connect_failed" => present(obs.targets.iter().any(|t| t.connect.is_some()), "no completed TCP attempt; resolution must finish first"),
                "target.tls_failed" if !obs.targets.is_empty() && obs.targets.iter().all(|t| !t.tls) => (NotApplicable, "observed targets do not use TLS"),
                "target.tls_failed" => present(obs.targets.iter().any(|t| t.tls_stage.is_some()), "no completed TLS attempt; TCP must connect first"),
                "target.http_error" if !obs.targets.is_empty() && obs.targets.iter().all(|t| !t.http) => (NotApplicable, "observed targets do not use HTTP"),
                "target.http_error" => present(obs.targets.iter().any(|t| t.http_stage.is_some()), "no completed HTTP attempt; preceding stages must succeed"),
                "target.slow_stage" => {
                    if obs.targets.is_empty() { (NotMeasured, "no diagnose targets configured, or none probed yet") }
                    else if obs.targets.iter().any(|t| t.stage_readings().iter().any(|(m, _)| base.get(t.baseline_subject(), m).is_some())) { (Available, "target stage timings and usable baselines present") }
                    else { (Learning, "target stage baselines still learning") }
                },
                _ => (Unsupported, "no diagnostic observation adapter"),
            }};
            let (status, reason) = if status != Available && status != NotImplemented {
                obs.coverage_hints.get(rule.id).cloned().unwrap_or((status, reason.into()))
            } else { (status, reason.into()) };
            RuleCoverage { rule: rule.id.into(), status, reason }
        }).collect::<Vec<_>>() };
        coverage.group_by_area();
        coverage
    }
}

/// Read-only, bounded live audit. It uses the same collectors and sampler as
/// the TUI, but never runs App::tick or shutdown_diagnose (both persist state).
pub fn command(args: &[String]) -> anyhow::Result<()> {
    use crate::{app::App, config::NetwatchConfig, diagnose::live::LiveSampler};
    use std::time::{Duration, Instant};
    let mut seconds = 10u64;
    let mut json = false;
    let mut test: Option<String> = None;
    let mut explicit_seconds = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            // Regenerate the committed catalogue document. No host is probed:
            // this describes the ruleset, not what this machine can see.
            "--doc" => {
                let path = args
                    .next()
                    .cloned()
                    .unwrap_or_else(|| "docs/diagnostic-coverage.md".to_string());
                std::fs::write(&path, super::rules::coverage_markdown())?;
                crate::logging::stdout_text(&format!("wrote {path}\n"));
                return Ok(());
            }
            "--json" => json = true,
            "--test" => {
                test = Some(
                    args.next()
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "--test requires ipv6.broken, captive.portal or pmtu.blackhole"
                            )
                        })?
                        .clone(),
                );
            }
            "--seconds" => {
                explicit_seconds = true;
                seconds = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--seconds requires 1..120"))?
                    .parse()?
            }
            _ => anyhow::bail!("unknown coverage option: {arg}"),
        }
    }
    if test.is_some() && !explicit_seconds {
        seconds = 90;
    }
    anyhow::ensure!((1..=120).contains(&seconds), "--seconds must be 1..120");
    let config = NetwatchConfig {
        insights_enabled: false,
        diagnose_record_episodes: false,
        ..NetwatchConfig::load()?
    };
    crate::config::print_warnings(&config.load_warnings);
    crate::config::print_warnings(&crate::collectors::egress::default_policy_warnings());
    super::run::print_threshold_warnings(&config.diagnose_thresholds);
    if let Some(rule) = &test {
        // The platform first, as Runner::start checks it: asking for a
        // pmtu_url Windows could never use would only lead to this refusal.
        if let Some(why) = super::active::unsupported(rule) {
            anyhow::bail!("{rule} cannot run here: {why}");
        }
        config
            .diagnose_probes
            .validate(rule)
            .map_err(anyhow::Error::msg)?;
    }
    let mode = crate::sandbox::Mode::from_config(&config.sandbox);
    let mut app = App::prepare_with_config(config);
    crate::runtime::bootstrap::start(
        &mut app,
        crate::runtime::bootstrap::SessionKind::Daemon,
        mode,
    )?;
    crate::runtime::bootstrap::prime_collectors(&mut app);
    let started_at = chrono::Local::now();
    let started = Instant::now();
    let mut sampler = LiveSampler::new();
    let mut samples = 0usize;
    if let Some(rule) = &test {
        crate::logging::stderr_line(&format!("Running {rule}: three direct endpoint rounds. IPv6: up to 24 TCP connects; portal: up to 12 GETs; PMTU: six DF pings and up to six 64 KiB downloads. No redirects or host configuration changes."));
        app.diagnose
            .active_prober
            .start(rule, &app.user_config.diagnose_probes)
            .map_err(anyhow::Error::msg)?;
    }
    loop {
        app.traffic.update();
        app.connection_collector.update();
        app.tcp_info.update();
        let network = &app.config_collector.config;
        app.health_prober
            .probe(network.gateway.as_deref(), network.primary_dns().as_deref());
        app.diagnose.target_prober.probe_due(
            &app.user_config.diagnose_targets,
            super::targets::ProbeEnv {
                resolvers: network
                    .dns_servers
                    .iter()
                    .filter_map(|d| d.parse().ok())
                    .collect(),
                vpn_ifaces: app
                    .interface_info
                    .iter()
                    .filter(|i| i.is_up && super::targets::is_vpn_iface(&i.name))
                    .map(|i| i.name.clone())
                    .collect(),
            },
        );
        app.egress_profiler
            .observe(&app.connection_collector.connections(), &app.geo_cache);
        let fingerprint = LiveSampler::fingerprint(&app);
        app.diagnose.baselines.set_network(fingerprint);
        let observations = sampler.sample(&app, &app.diagnose.engine.settings().thresholds);
        app.diagnose.engine.observe_live_at(
            &observations,
            &app.diagnose.baselines,
            &sampler.completed,
            Instant::now(),
        );
        samples += 1;
        if started.elapsed() >= Duration::from_secs(seconds) {
            break;
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
    app.packet_collector.stop_capture();
    let coverage = app.diagnose.engine.coverage();
    let age = |at: Option<Instant>| at.map(|at| at.elapsed().as_secs_f64());
    let times = &sampler.completed;
    let report = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"), "binary": std::env::current_exe().ok(),
        "mode": "live", "interface": app.capture_interface,
        "started_at": started_at.to_rfc3339(), "finished_at": chrono::Local::now().to_rfc3339(),
        "window_seconds": started.elapsed().as_secs_f64(), "samples": samples,
        "baseline_policy": "existing network baselines read; no learning or writes",
        "completeness": "bounded snapshot; missing results may still be in flight",
        "source_age_seconds": { "ipv6": age(times.ipv6), "portal": age(times.portal), "pmtu": age(times.pmtu), "kernel": age(times.kernel), "interface": age(times.interface), "sockets": age(times.sockets),
            "dns": age(times.health.dns), "gateway": age(times.health.gateway), "nat": age(times.health.nat),
            "path": age(times.path), "targets": age(times.targets.values().copied().max()), "egress": age(times.egress) },
        "active_experiments": app.diagnose.active_prober.snapshot().0,
        "experiment_progress": app.diagnose.active_prober.snapshot().2,
        "configured_targets": app.user_config.diagnose_targets.len(),
        "coverage": coverage,
        "sources": coverage.rules.iter().map(|r| (&r.rule, r.source())).collect::<std::collections::BTreeMap<_, _>>(),
        "actions": coverage.rules.iter().map(|r| (&r.rule, r.next_action())).collect::<std::collections::BTreeMap<_, _>>()
    });
    if json {
        let json = serde_json::to_string_pretty(&report)?;
        crate::logging::stdout_text(&format!("{json}\n"));
    } else {
        let mut text = format!(
            "Netwatch {} · live · {} · {:.1}s sample window\n{}\n",
            env!("CARGO_PKG_VERSION"),
            app.capture_interface,
            started.elapsed().as_secs_f64(),
            coverage.label()
        );
        for row in &coverage.rules {
            text.push_str(&format!(
                "{} [{}]\n  {}\n  Next: {}\n",
                row.rule,
                row.status.label(),
                row.reason,
                row.next_action()
            ));
        }
        text.push_str("Bounded snapshot; existing baselines were read without learning or writing. Missing probes may still be running.\n");
        crate::logging::stdout_text(&text);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::{baseline::NetworkFingerprint, fixture};

    #[test]
    fn target_resolution_failure_does_not_claim_later_stages_were_measured() {
        let target: super::super::targets::TargetObs = serde_json::from_value(serde_json::json!({
            "name":"test", "host":"missing.invalid", "port":443, "tls":true, "http":true,
            "expect_status":null, "probed_at":"now", "resolve":{"ms":1.0,"error":{"kind":"nx_domain"}},
            "addresses":[],"lookups":[],"connect":null,"connect_v4":null,"connect_v6":null,
            "tls_stage":null,"http_stage":null,"status":null,
            "context":{"proxy_env":false,"vpn_ifaces":[],"link_domains":[],"clock_offset_secs":null}
        })).unwrap();
        let obs = Observations {
            targets: vec![target],
            ..Default::default()
        };
        let coverage = Coverage::from_observations(&obs, &fixture::baselines(), Default::default());
        for row in coverage.rules.iter().filter(|r| {
            [
                "target.connect_failed",
                "target.tls_failed",
                "target.http_error",
            ]
            .contains(&r.rule.as_str())
        }) {
            assert_ne!(row.status, Availability::Available, "{}", row.rule);
        }
        assert_eq!(
            coverage
                .rules
                .iter()
                .find(|r| r.rule == "target.resolve_failed")
                .unwrap()
                .status,
            Availability::Available
        );
    }

    #[test]
    fn coverage_status_roundtrips_and_unknown_future_status_is_honest() {
        assert_eq!(
            serde_json::from_str::<Availability>("\"future_state\"").unwrap(),
            Availability::Unknown
        );
        for status in [
            Availability::NotConfigured,
            Availability::NoSubjects,
            Availability::AwaitingTest,
            Availability::NotImplemented,
        ] {
            assert_eq!(
                serde_json::from_str::<Availability>(&serde_json::to_string(&status).unwrap())
                    .unwrap(),
                status
            );
        }
    }

    #[test]
    fn an_unsupported_experiment_does_not_offer_t() {
        // pmtu.blackhole on Windows, ipv6.broken off Linux.
        for rule in ["ipv6.broken", "pmtu.blackhole"] {
            let row = RuleCoverage {
                rule: rule.into(),
                status: Availability::Unsupported,
                reason: String::new(),
            };
            assert!(!row.next_action().contains("t runs"), "{rule}");
            let awaiting = RuleCoverage {
                status: Availability::AwaitingTest,
                ..row
            };
            assert!(awaiting.next_action().contains("t runs"), "{rule}");
        }
    }

    #[test]
    fn every_catalogued_rule_has_explicit_runtime_coverage() {
        let c = Coverage::from_observations(
            &Observations::default(),
            &fixture::baselines(),
            Default::default(),
        );
        assert_eq!(c.rules.len(), rules::CATALOGUE.len());
        assert!(c.rules.iter().all(|r| r.status != Availability::Available));
        assert_eq!(
            c.rules
                .iter()
                .filter(|r| r.status == Availability::NotImplemented)
                .count(),
            0
        );
        assert!(c
            .rules
            .iter()
            .all(|r| r.reason != "no diagnostic observation adapter"));
        assert!(c
            .label()
            .starts_with(&format!("0/{}", rules::CATALOGUE.len())));
    }

    #[test]
    fn dns_absolute_threshold_remains_available_while_gateway_baseline_learns() {
        let base = BaselineStore::new(NetworkFingerprint::new("test", None, vec![], None));
        let obs = fixture::observations_at(300);
        let c = Coverage::from_observations(&obs, &base, Default::default());
        assert_eq!(
            c.rules
                .iter()
                .find(|r| r.rule == "dns.slow_resolver")
                .unwrap()
                .status,
            Availability::Available
        );
        assert_eq!(
            c.rules
                .iter()
                .find(|r| r.rule == "gateway.rtt_spike")
                .unwrap()
                .status,
            Availability::Learning
        );
    }

    #[test]
    fn a_baseline_that_never_varied_is_usable_against_the_floor() {
        let mut base = BaselineStore::new(NetworkFingerprint::new("test", None, vec![], None));
        base.seed(fixture::GATEWAY, "gateway.rtt", 0.9, 0.0, 2_400);
        let obs = fixture::observations_at(300);
        let gateway = |floor| {
            Coverage::from_observations(&obs, &base, floor)
                .rules
                .into_iter()
                .find(|r| r.rule == "gateway.rtt_spike")
                .unwrap()
                .status
        };
        assert_eq!(gateway(SigmaFloor::default()), Availability::Available);
        // Only with both floors set to zero is there nothing to score by.
        assert_eq!(
            gateway(SigmaFloor { ms: 0.0, pct: 0.0 }),
            Availability::Learning
        );
    }

    #[test]
    fn unknown_wireless_is_not_measured_not_not_applicable() {
        let weak_signal = |wireless| {
            let mut obs = fixture::observations_at(300);
            obs.iface.as_mut().unwrap().wireless = wireless;
            Coverage::from_observations(&obs, &fixture::baselines(), Default::default())
                .rules
                .into_iter()
                .find(|r| r.rule == "wifi.weak_signal")
                .unwrap()
                .status
        };
        assert_eq!(weak_signal(Some(false)), Availability::NotApplicable);
        assert_eq!(weak_signal(None), Availability::NotMeasured);
    }

    #[test]
    fn missing_loaded_test_and_receive_window_are_not_available() {
        let mut obs = fixture::observations_at(300);
        obs.loaded_rtt_ms = None;
        for s in &mut obs.sockets {
            s.rwnd = None;
        }
        let c = Coverage::from_observations(&obs, &fixture::baselines(), Default::default());
        for rule in ["tcp.bufferbloat_local", "tcp.zero_window"] {
            assert_eq!(
                c.rules.iter().find(|r| r.rule == rule).unwrap().status,
                if rule == "tcp.bufferbloat_local" {
                    Availability::AwaitingTest
                } else {
                    Availability::NotMeasured
                }
            );
        }
    }
}
