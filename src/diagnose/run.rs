//! `netwatch diagnose run` — one bounded diagnosis, for a script or a ticket.
//!
//! The TUI answers "what is wrong with my network right now" interactively.
//! This answers it once, within a budget, and says so in an exit status a
//! shell can branch on. The distinction that matters is between *no finding*
//! and *not enough evidence*: a run that could not gather what it needed must
//! never be read as a healthy host, which is why those are different exits.

use crate::diagnose::coverage::Coverage;
use crate::diagnose::detectors::Observations;
use crate::diagnose::issue::{Availability, CheckResult, Issue, Kind, Subject};
use crate::diagnose::rules;
use serde::Serialize;
use std::time::{Duration, Instant};

/// What a run concluded, and the exit status it reports.
///
/// Documented and stable: scripts branch on these, so the numbers are part of
/// the interface, not an implementation detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The run completed and found no Issue. Not a claim that the host is
    /// healthy — only that the rules that could be evaluated did not fire.
    /// Observations may still be listed.
    NoFinding = 0,
    /// The run completed and found at least one open Issue. An Observation,
    /// such as a symmetric NAT, never sets this.
    Finding = 1,
    /// The budget ran out before enough evidence existed to decide. The
    /// caller should retry with a longer budget rather than read this as
    /// health.
    Incomplete = 2,
    /// Bad arguments, or the session could not start.
    Error = 3,
}

impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Outcome::NoFinding => "no_finding",
            Outcome::Finding => "finding",
            Outcome::Incomplete => "incomplete",
            Outcome::Error => "error",
        }
    }
}

/// Decide the outcome of a finished run, from the findings [`select`] chose.
///
/// Only an Issue is a finding. An Observation says something worth knowing,
/// not something wrong, so a host whose only finding is a symmetric NAT
/// exits 0. `evidence` is whether the run ever saw a usable observation for
/// what it was asked about. Without one there is nothing to conclude,
/// however quiet the issue list looks.
///
/// An Issue from a beta rule counts only with `include_beta`: it is shown
/// either way, but a script's exit status should not rest on a rule whose
/// contract nobody has reviewed.
pub fn outcome(findings: &[Issue], evidence: bool, include_beta: bool) -> Outcome {
    if findings
        .iter()
        .any(|f| f.kind() == Kind::Issue && (include_beta || !f.beta))
    {
        Outcome::Finding
    } else if evidence {
        Outcome::NoFinding
    } else {
        Outcome::Incomplete
    }
}

/// Whether one sample gave the run something to conclude from.
///
/// Asked about one target, only that target's own probe counts: another
/// target completing says nothing about this one. Otherwise a gateway or
/// resolver observation counts, or any completed target probe. The sampler
/// gives no gateway observation until a probe cycle measured loss, so a
/// gateway that answers neither ICMP nor any TCP port is no evidence. The
/// prober's completion stamp, which it sets after that cycle too, used to
/// count, and such a host exited 0.
fn evidence(observations: &Observations, target: Option<&str>) -> bool {
    match target {
        Some(name) => observations.targets.iter().any(|t| t.name == name),
        None => {
            observations.gateway.is_some()
                || observations.dns.is_some()
                || !observations.targets.is_empty()
        }
    }
}

struct Options {
    target: Option<String>,
    budget: Duration,
    json: bool,
    include_beta: bool,
}

fn parse(args: &[String]) -> anyhow::Result<Options> {
    let mut opts = Options {
        target: None,
        budget: Duration::from_secs(30),
        json: false,
        include_beta: false,
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--target" => {
                opts.target = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--target requires a configured name"))?
                        .clone(),
                )
            }
            "--budget" => {
                let raw = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--budget requires a duration, e.g. 30s"))?;
                opts.budget = parse_budget(raw)?;
            }
            "--format" => {
                let fmt = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--format requires json or text"))?;
                match fmt.as_str() {
                    "json" => opts.json = true,
                    "text" => opts.json = false,
                    other => anyhow::bail!("unknown format: {other} (json or text)"),
                }
            }
            "--json" => opts.json = true,
            "--include-beta" => opts.include_beta = true,
            other => anyhow::bail!("unknown run option: {other}"),
        }
    }
    Ok(opts)
}

/// `30s`, `2m`, or a bare number of seconds. Bounded at both ends: a run
/// shorter than a probe interval cannot gather evidence, and one longer than
/// ten minutes is a session, not a one-shot.
pub fn parse_budget(raw: &str) -> anyhow::Result<Duration> {
    let (value, scale) = match raw.strip_suffix('s') {
        Some(v) => (v, 1),
        None => match raw.strip_suffix('m') {
            Some(v) => (v, 60),
            None => (raw, 1),
        },
    };
    const OUT_OF_RANGE: &str = "budget must be between 5s and 10m";
    let secs = match value.parse::<u64>() {
        Ok(n) => n,
        Err(e) if *e.kind() == std::num::IntErrorKind::PosOverflow => anyhow::bail!(OUT_OF_RANGE),
        Err(_) => anyhow::bail!("budget must be a duration like 30s or 2m"),
    };
    // Checked: a minute count near u64::MAX overflows the multiply, which
    // panics in a debug build and wraps into the valid range in a release one.
    let secs = secs
        .checked_mul(scale)
        .filter(|s| (5..=600).contains(s))
        .ok_or_else(|| anyhow::anyhow!(OUT_OF_RANGE))?;
    Ok(Duration::from_secs(secs))
}

/// Print to stderr what the engine will log about invalid
/// `[diagnose_thresholds]`. It replaces them with defaults and logs each one,
/// but the `diagnose` subcommands run before the log file opens, so the log
/// line goes nowhere and stderr is where their caller looks.
pub(crate) fn print_threshold_warnings(thresholds: &crate::diagnose::detectors::Thresholds) {
    for warning in thresholds.validated().1 {
        eprintln!("warning: {warning}");
    }
}

pub fn command(args: &[String]) -> anyhow::Result<()> {
    // Exit codes are the interface here, so the error path owns its own
    // status rather than inheriting whatever main does with an `Err`.
    let outcome = match parse(args).and_then(run) {
        Ok(outcome) => outcome,
        Err(e) => {
            eprintln!("error: {e}");
            Outcome::Error
        }
    };
    std::process::exit(outcome as i32);
}

/// The user's configuration as a run uses it. A run never traces on a
/// timer: only the TUI's controller does. Each sample records the interval
/// it ran with, so the run's copy has none.
fn run_config(loaded: crate::config::NetwatchConfig) -> crate::config::NetwatchConfig {
    let mut config = crate::config::NetwatchConfig {
        insights_enabled: false,
        diagnose_record_episodes: false,
        ..loaded
    };
    config.diagnose_probes.trace_refresh_secs = None;
    config
}

fn run(opts: Options) -> anyhow::Result<Outcome> {
    use crate::{app::App, config::NetwatchConfig, diagnose::live::LiveSampler};

    let config = run_config(NetwatchConfig::load()?);
    print_threshold_warnings(&config.diagnose_thresholds);
    let mut asked = opts
        .target
        .as_deref()
        .map(|name| {
            config
                .diagnose_targets
                .iter()
                .find(|t| t.name == name)
                .map(Asked::new)
                .ok_or_else(|| anyhow::anyhow!("no configured target named {name}"))
        })
        .transpose()?;
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
    let mut saw_evidence = false;

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
        let fingerprint = LiveSampler::fingerprint(&app);
        app.diagnose.baselines.set_network(fingerprint);
        let observations = sampler.sample(&app, &app.diagnose.engine.settings().thresholds);
        saw_evidence |= evidence(&observations, opts.target.as_deref());
        if let Some(asked) = &mut asked {
            asked.saw(&observations);
        }
        app.diagnose.engine.observe_live_at(
            &observations,
            &app.diagnose.baselines,
            &sampler.completed,
            Instant::now(),
        );
        samples += 1;
        if started.elapsed() >= opts.budget {
            break;
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
    app.packet_collector.stop_capture();

    let findings = select(app.diagnose.engine.issues(), asked.as_ref());
    let outcome = outcome(&findings, saw_evidence, opts.include_beta);
    let sampling = Sampling {
        target: opts.target,
        started_at: started_at.to_rfc3339(),
        seconds: started.elapsed().as_secs_f64(),
        samples,
        evidence: saw_evidence,
    };

    if opts.json {
        let report = json_report(
            outcome,
            &sampling,
            app.diagnose.engine.coverage(),
            &findings,
            opts.include_beta,
        );
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!(
            "{}",
            text_report(outcome, &sampling, &findings, opts.include_beta)
        );
    }
    Ok(outcome)
}

/// The target a run was asked about, and the interface and resolver its
/// latest probe's lookup went through, as a finding about it would record
/// them in its scope. Either is `None` when not known.
#[derive(Debug, Clone)]
struct Asked {
    name: String,
    /// A sample has held a probe of the target. Until one has, the run knows
    /// no route for it, not an empty one.
    observed: bool,
    via_iface: Option<String>,
    via_resolver: Option<String>,
    /// The target is a name. One given as an address has no resolver on its
    /// route.
    resolves: bool,
    /// The target is this host: it is a loopback address, or every address
    /// its latest probe resolved is. Nothing host-wide lies on its route.
    local: bool,
}

impl Asked {
    fn new(target: &super::targets::TargetConfig) -> Self {
        let address = target.host.parse::<std::net::IpAddr>().ok();
        Self {
            name: target.name.clone(),
            observed: false,
            via_iface: None,
            via_resolver: None,
            resolves: address.is_none(),
            local: address.is_some_and(|a| a.is_loopback()),
        }
    }

    /// Take the route from this sample's probe of the target, if it has one.
    fn saw(&mut self, observations: &Observations) {
        let Some(probe) = observations.targets.iter().find(|t| t.name == self.name) else {
            return;
        };
        self.observed = true;
        let lookup = probe.route_lookup();
        self.via_resolver = lookup.map(|l| l.resolver.clone());
        self.via_iface = lookup.and_then(|l| l.link.clone());
        if !probe.addresses.is_empty() {
            self.local = probe
                .addresses
                .iter()
                .all(|a| a.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback()));
        }
    }

    fn is_about(&self, finding: &Issue) -> bool {
        matches!(&finding.subject, Subject::Target { name } if *name == self.name)
    }

    /// Whether a host, interface or resolver finding can lie on this
    /// target's route. It can unless it names an interface or resolver the
    /// target is known not to use, the edge suppression draws, or it is
    /// about a resolver and the target is an address, or the target is this
    /// host. Nothing can before the target was probed: a target that is
    /// disabled, invalid or slower than the budget would otherwise take on
    /// every host-wide Issue and exit 1 with no evidence about it.
    fn routes_through(&self, finding: &Issue) -> bool {
        if !self.observed || self.local {
            return false;
        }
        let (iface, resolver) = match &finding.subject {
            Subject::Host => (
                finding.scope.via_iface.as_deref(),
                finding.scope.via_resolver.as_deref(),
            ),
            Subject::Iface { name } => (Some(name.as_str()), None),
            Subject::Resolver { addr } => (finding.scope.via_iface.as_deref(), Some(addr.as_str())),
            _ => return false,
        };
        let differs = |theirs: Option<&str>, ours: Option<&str>| {
            theirs
                .zip(ours)
                .is_some_and(|(theirs, ours)| theirs != ours)
        };
        !differs(iface, self.via_iface.as_deref())
            && (resolver.is_none() || self.resolves)
            && !differs(resolver, self.via_resolver.as_deref())
    }

    /// A finding about this target, as the run counts it. The detector makes
    /// a failure of the service itself an Observation, "service, not
    /// network", because the Diagnose tab asks whether the network is at
    /// fault. A run asked about one target asks whether it works, and a 503
    /// says it does not, so the finding keeps its rule's severity.
    fn counted(&self, finding: &Issue) -> Issue {
        let mut finding = finding.clone();
        if let Some(rule) = rules::lookup(&finding.rule) {
            finding.severity = finding.severity.max(rule.severity);
        }
        finding
    }
}

/// The findings a run reports, as it counts them.
///
/// Without a target, every primary finding. With one: the findings about
/// that target, which count as Issues; the findings whose consequences
/// include one, so a gateway failure that hides the target's own finding
/// still decides the run; and the host, interface and resolver Issues on the
/// target's route. Matching on the subject's label alone used to drop the
/// gateway failure, and the run exited 0 with the target down.
fn select(all: &[Issue], asked: Option<&Asked>) -> Vec<Issue> {
    let primary = rules::primary_findings(all);
    let Some(asked) = asked else {
        return primary.into_iter().cloned().collect();
    };
    let about: Vec<&str> = all
        .iter()
        .filter(|i| asked.is_about(i))
        .map(|i| i.id.as_str())
        .collect();
    primary
        .into_iter()
        .filter_map(|f| {
            if asked.is_about(f) {
                Some(asked.counted(f))
            } else if f.consequences.iter().any(|id| about.contains(&id.as_str()))
                || (f.kind() == Kind::Issue && asked.routes_through(f))
            {
                Some(f.clone())
            } else {
                None
            }
        })
        .collect()
}

/// What a run sampled, apart from what it found.
struct Sampling {
    target: Option<String>,
    started_at: String,
    seconds: f64,
    samples: usize,
    evidence: bool,
}

/// One finding as schema 2 writes it: the issue, with its kind beside it.
#[derive(Serialize)]
struct Finding<'a> {
    kind: Kind,
    #[serde(flatten)]
    issue: &'a Issue,
}

/// The JSON report, schema 2. Issues and Observations are separate arrays,
/// each entry says which it is, and checks carry `state` without `passed`.
/// Schema 1 listed both kinds under `issues`.
fn json_report(
    outcome: Outcome,
    sampling: &Sampling,
    coverage: &Coverage,
    findings: &[Issue],
    include_beta: bool,
) -> serde_json::Value {
    let of = |kind: Kind| -> Vec<Finding> {
        findings
            .iter()
            .filter(|f| f.kind() == kind)
            .map(|issue| Finding { kind, issue })
            .collect()
    };
    serde_json::json!({
        "metadata": crate::schemas::DIAGNOSE_RUN.metadata(),
        "schema": 2,
        "version": env!("CARGO_PKG_VERSION"),
        "ruleset": super::rules::CATALOGUE.len(),
        "outcome": outcome.label(),
        "exit": outcome as i32,
        "include_beta": include_beta,
        "target": sampling.target,
        "started_at": sampling.started_at,
        "window_seconds": sampling.seconds,
        "samples": sampling.samples,
        "evidence": sampling.evidence,
        "completeness": if sampling.evidence {
            "the rules that could be evaluated were; an empty list is not a health claim"
        } else {
            "no usable observation arrived inside the budget; nothing was concluded"
        },
        "coverage": coverage,
        "issues": of(Kind::Issue),
        "observations": of(Kind::Observation),
    })
}

/// The text report: the outcome, the Issues under it, then the Observations
/// under their own heading, since they do not set the exit status.
fn text_report(
    outcome: Outcome,
    sampling: &Sampling,
    findings: &[Issue],
    include_beta: bool,
) -> String {
    let mut out = format!(
        "{} · {} samples in {:.0}s\n",
        outcome.label(),
        sampling.samples,
        sampling.seconds
    );
    let (issues, observations): (Vec<&Issue>, Vec<&Issue>) =
        findings.iter().partition(|f| f.kind() == Kind::Issue);
    let uncounted_beta = !include_beta && issues.iter().any(|i| i.beta);
    for issue in issues {
        out.push_str(&finding_lines(issue));
    }
    if uncounted_beta {
        out.push_str(
            "  beta issues are not counted in the exit status; --include-beta counts them\n",
        );
    }
    if outcome == Outcome::Incomplete {
        out.push_str("  no usable observation arrived inside the budget\n");
    }
    if !observations.is_empty() {
        out.push_str("observations · not counted in the exit status\n");
        for observation in observations {
            out.push_str(&finding_lines(observation));
        }
    }
    out
}

/// A finding's summary line and the note that qualifies it, such as
/// "service, not network", then its top cause and the check that cause is
/// still missing.
fn finding_lines(finding: &Issue) -> String {
    let beta = if finding.beta { "beta · " } else { "" };
    let mut out = format!("  {beta}{}\n", finding.summary_line());
    if let Some(note) = &finding.scope.note {
        out.push_str(&format!("    {note}\n"));
    }
    if let Some(cause) = finding.top_cause() {
        out.push_str(&format!(
            "    {} ({}, {})\n",
            cause.label,
            cause.confidence().label(),
            cause.checks_label()
        ));
        if let Some(missing) = cause.missing_discriminator() {
            out.push_str(&format!("    {}\n", missing_line(missing)));
        }
    }
    out
}

/// The check a qualified cause is still missing, led by why it did not run
/// in the words the Diagnose tab uses, so the text agrees with the JSON's
/// `why_not`.
fn missing_line(missing: &CheckResult) -> String {
    let why = missing
        .why_not
        .as_ref()
        .map_or("not measured", Availability::label);
    format!("{why}: {} — {}", missing.name, missing.detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::issue::Severity;
    use crate::diagnose::targets::TargetObs;

    #[test]
    fn budgets_parse_and_are_bounded() {
        assert_eq!(parse_budget("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_budget("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_budget("45").unwrap(), Duration::from_secs(45));
        assert!(parse_budget("1s").is_err(), "shorter than a probe interval");
        assert!(parse_budget("30m").is_err(), "that is a session, not a run");
        assert!(parse_budget("soon").is_err());
    }

    #[test]
    fn budget_bounds_are_inclusive() {
        assert_eq!(parse_budget("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_budget("600").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_budget("10m").unwrap(), Duration::from_secs(600));
        assert!(parse_budget("4s").is_err());
        assert!(parse_budget("601s").is_err());
        assert!(parse_budget("0m").is_err());
    }

    /// Review R6: `18446744073709551615m` overflowed the minutes multiply,
    /// a panic in a debug build. Each of these is out of range, and says so.
    #[test]
    fn huge_budgets_are_out_of_range_not_a_panic() {
        for raw in [
            "18446744073709551615m",
            "307445734561825861m",  // just past u64::MAX / 60
            "2152120141932781022m", // wraps to 8 s where the multiply wraps
            "18446744073709551615s",
            "18446744073709551615",
            "99999999999999999999999m", // too big for u64 at all
        ] {
            let err = parse_budget(raw).expect_err(raw);
            assert_eq!(
                err.to_string(),
                "budget must be between 5s and 10m",
                "{raw}"
            );
        }
        for raw in ["", "m", "s", "-5s", "1.5m", "5 s", "5ms"] {
            let err = parse_budget(raw).expect_err(raw);
            assert_eq!(
                err.to_string(),
                "budget must be a duration like 30s or 2m",
                "{raw:?}"
            );
        }
    }

    /// D33-B04 review: a run never traces on a timer, so its samples must
    /// not record periodic tracing as on. B30 and the expiry guard read that
    /// field.
    #[test]
    fn a_run_records_periodic_tracing_as_off() {
        let loaded: crate::config::NetwatchConfig = toml::from_str(
            r#"
            [diagnose_probes]
            trace_target = "9.9.9.9"
            trace_refresh_secs = 120
            "#,
        )
        .unwrap();
        assert_eq!(loaded.diagnose_probes.periodic_trace_secs(), Some(120));
        let app = crate::app::App::prepare_with_config(run_config(loaded));
        let observed = crate::diagnose::live::LiveSampler::new()
            .sample(&app, &app.diagnose.engine.settings().thresholds)
            .config
            .expect("a live sample records its configuration");
        assert_eq!(observed.trace_refresh_secs, None);
        assert_eq!(
            observed.trace_target, "9.9.9.9",
            "the target is still known"
        );
    }

    #[test]
    fn an_empty_list_without_evidence_is_incomplete_not_healthy() {
        // The distinction the exit statuses exist for. A run that gathered
        // nothing has not established that anything is well.
        assert_eq!(outcome(&[], false, false), Outcome::Incomplete);
        assert_eq!(outcome(&[], true, false), Outcome::NoFinding);
        assert_eq!(Outcome::Incomplete as i32, 2);
        assert_eq!(Outcome::NoFinding as i32, 0);
    }

    const GATEWAY: &str = "192.0.2.1";

    /// The prober's status after `cycles` gateway probes, each an (rtt, loss)
    /// pair recorded the way the probe thread records it: every cycle stamps
    /// `completed.gateway`, and only a measured one joins the history.
    fn after_gateway_cycles(
        cycles: &[(Option<f64>, crate::collectors::health::Loss)],
    ) -> crate::collectors::health::HealthStatus {
        let mut status = (*crate::collectors::health::HealthProber::new().status()).clone();
        for &(rtt, loss) in cycles {
            let completed = Instant::now();
            status.gateway_rtt_ms = rtt;
            status.gateway_loss = loss;
            if loss.is_measured() {
                status.completed.gateway_history.push_back(completed);
                status.gateway_rtt_history.push_back(rtt);
            }
            status.completed.gateway = Some(completed);
            status.completed.gateway_target = Some(GATEWAY.into());
        }
        status
    }

    /// One live sample on a host whose gateway is [`GATEWAY`] and which lists
    /// no resolver, with `status` as the prober's latest.
    fn sample_with(
        status: crate::collectors::health::HealthStatus,
    ) -> (crate::diagnose::live::LiveSampler, Observations) {
        let mut app =
            crate::app::App::prepare_with_config(crate::config::NetwatchConfig::default());
        app.config_collector.config.gateway = Some(GATEWAY.into());
        app.config_collector.config.dns_servers.clear();
        app.health_prober.publish_for_test(status);
        let mut sampler = crate::diagnose::live::LiveSampler::new();
        let observations = sampler.sample(&app, &app.diagnose.engine.settings().thresholds);
        (sampler, observations)
    }

    /// REVIEW §2.1: count gateway evidence only when loss is measured. A
    /// gateway cycle that could send nothing ("icmp is blocked here and the
    /// gateway answers no tcp port") still stamps the prober's completion
    /// time, which the run used to count; it yields no gateway observation,
    /// and with no resolver either the run has nothing to conclude from.
    #[test]
    fn an_unmeasured_gateway_is_not_evidence() {
        use crate::collectors::health::Loss;
        let unmeasured = (
            None,
            Loss::Unmeasured("icmp is blocked here and the gateway answers no tcp port"),
        );
        let measured = |rtt| (Some(rtt), Loss::Measured(0.0));
        for (case, cycles) in [
            ("never measured", vec![unmeasured]),
            (
                "measured before, not now",
                vec![measured(0.9), measured(1.1), unmeasured],
            ),
        ] {
            let (sampler, observations) = sample_with(after_gateway_cycles(&cycles));
            assert!(
                sampler.completed.health.gateway.is_some(),
                "{case}: the old check would have counted this cycle"
            );
            assert_eq!(
                sampler.completed.health.gateway_target.as_deref(),
                Some(GATEWAY),
                "{case}"
            );
            assert!(observations.gateway.is_none(), "{case}");
            assert!(observations.dns.is_none(), "{case}");
            assert!(!evidence(&observations, None), "{case}");
            assert_eq!(
                outcome(&[], evidence(&observations, None), false),
                Outcome::Incomplete,
                "{case}"
            );
        }
    }

    #[test]
    fn a_measured_gateway_is_evidence() {
        use crate::collectors::health::Loss;
        use crate::diagnose::detectors::{DnsObs, GatewayObs};
        // Through the sampler, on the same seam the unmeasured test uses: a
        // measured cycle, including one that lost everything, is observed.
        for (rtt, loss) in [
            (Some(0.9), Loss::Measured(0.0)),
            (None, Loss::Measured(100.0)),
        ] {
            let (_, observations) = sample_with(after_gateway_cycles(&[(rtt, loss)]));
            let observed = observations.gateway.as_ref().expect("a measured gateway");
            assert_eq!(observed.addr.as_deref(), Some(GATEWAY));
            assert_eq!(Some(observed.loss_pct), loss.pct());
            assert!(evidence(&observations, None));
        }

        let gateway = Observations {
            gateway: Some(GatewayObs {
                addr: Some("192.0.2.2".into()),
                rtt_ms: Some(0.9),
                loss_pct: 0.0,
                arp_ok: None,
                icmp_ok: true,
                internet_reachable: Some(true),
            }),
            ..Default::default()
        };
        assert!(evidence(&gateway, None));
        assert_eq!(
            outcome(&[], evidence(&gateway, None), false),
            Outcome::NoFinding
        );
        // Total loss is measured too: that is gateway.unreachable's input.
        let dead = Observations {
            gateway: gateway.gateway.clone().map(|g| GatewayObs {
                rtt_ms: None,
                loss_pct: 100.0,
                icmp_ok: false,
                ..g
            }),
            ..Default::default()
        };
        assert!(evidence(&dead, None));
        // A measured resolver alone is evidence as well.
        let resolver = Observations {
            dns: Some(DnsObs {
                resolver: "192.0.2.2".into(),
                rtt_p50_ms: Some(2.0),
                rtt_p95_ms: Some(3.0),
                failure_rate_pct: 0.0,
                truncation_rate_pct: 0.0,
                queries: 6,
                failed: 0,
                truncated: 0,
                alt_resolver: None,
                alt_rtt_ms: None,
                icmp_rtt_ms: None,
                cached_rtt_ms: None,
                window_secs: 30,
                cross: None,
            }),
            ..Default::default()
        };
        assert!(evidence(&resolver, None));
        // Asked about one target, the gateway says nothing about it.
        assert!(!evidence(&gateway, Some("api")));
    }

    /// Decision B-10, revised: the rules without a reviewed contract are
    /// beta. Their issues are shown and tagged, and set the exit status only
    /// with `--include-beta`.
    #[test]
    fn beta_issue_does_not_set_exit_code() {
        let mut issue = crate::diagnose::fixture::report().issues.remove(0);
        issue.beta = true;
        let findings = std::slice::from_ref(&issue);
        assert_eq!(outcome(findings, true, false), Outcome::NoFinding);
        assert_eq!(outcome(findings, false, false), Outcome::Incomplete);

        let text = text_report(Outcome::NoFinding, &sampling(true), findings, false);
        assert!(
            text.contains(&format!("beta · {}", issue.summary_line())),
            "{text}"
        );
        assert!(text.contains("--include-beta counts them"), "{text}");
        let json = json_report(
            Outcome::NoFinding,
            &sampling(true),
            &Coverage::default(),
            findings,
            false,
        );
        assert_eq!(json["issues"][0]["beta"], true);
        assert_eq!(json["include_beta"], false);
    }

    #[test]
    fn include_beta_counts_it() {
        let mut issue = crate::diagnose::fixture::report().issues.remove(0);
        issue.beta = true;
        let findings = std::slice::from_ref(&issue);
        assert_eq!(outcome(findings, true, true), Outcome::Finding);
        let text = text_report(Outcome::Finding, &sampling(true), findings, true);
        assert!(!text.contains("--include-beta"), "{text}");
        issue.beta = false;
        assert_eq!(
            outcome(std::slice::from_ref(&issue), true, false),
            Outcome::Finding,
            "a contracted rule's issue counts without the flag"
        );
    }

    #[test]
    fn a_finding_outranks_the_evidence_question() {
        let issue = crate::diagnose::fixture::report().issues.remove(0);
        let issue = std::slice::from_ref(&issue);
        // The fixture's issues come from beta rules; counting them is what
        // this test is about, not the beta gate (below).
        assert_eq!(outcome(issue, true, true), Outcome::Finding);
        assert_eq!(outcome(issue, false, true), Outcome::Finding);
        assert_eq!(Outcome::Finding as i32, 1);
    }

    /// An engine that opens an issue on its first sample, after one sample
    /// of `obs`.
    fn engine_after(obs: &Observations) -> crate::diagnose::engine::Engine {
        use crate::diagnose::engine::{Engine, FixedClock};
        let engine = Engine::new(Box::new(FixedClock::at("2026-09-15 10:00:00")));
        let mut settings = *engine.settings();
        settings.thresholds.consecutive_n = 1;
        let mut engine = engine.with_settings(settings);
        engine.observe(obs, &crate::diagnose::fixture::baselines());
        engine
    }

    /// A host whose only finding is a symmetric NAT: an Observation.
    fn symmetric_nat() -> Issue {
        use crate::diagnose::detectors::NatObs;
        let engine = engine_after(&Observations {
            nat: Some(NatObs {
                mappings: vec![
                    ("stun1".into(), "198.51.100.7:40001".into()),
                    ("stun2".into(), "198.51.100.7:40517".into()),
                ],
                symmetric: true,
            }),
            ..Default::default()
        });
        let found = engine.primary();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].rule, "nat.symmetric");
        assert_eq!(found[0].kind(), Kind::Observation);
        found[0].clone()
    }

    fn sampling(evidence: bool) -> Sampling {
        Sampling {
            target: None,
            started_at: "2026-09-15T10:00:00+00:00".into(),
            seconds: 30.0,
            samples: 30,
            evidence,
        }
    }

    /// D33-B06: the exit code counts Issues only. Schema 1 exited 1 on any
    /// finding, Info included.
    #[test]
    fn observations_alone_exit_zero() {
        let findings = [symmetric_nat()];
        let nat = &findings[0];
        let outcome = outcome(&findings, true, false);
        assert_eq!(outcome, Outcome::NoFinding);
        assert_eq!(outcome as i32, 0);
        // An Observation is no evidence either way: with nothing measured
        // the run is still incomplete, not healthy.
        assert_eq!(super::outcome(&findings, false, false), Outcome::Incomplete);

        let json = json_report(
            outcome,
            &sampling(true),
            &Coverage::default(),
            &findings,
            false,
        );
        assert_eq!(json["exit"], 0);
        assert_eq!(json["issues"], serde_json::json!([]));
        assert_eq!(json["observations"][0]["rule"], "nat.symmetric");
        let text = text_report(outcome, &sampling(true), &findings, false);
        let (above, below) = text
            .split_once("observations · not counted in the exit status\n")
            .expect("observations have their own heading");
        assert!(!above.contains("symmetric"), "{text}");
        assert!(below.contains(&nat.summary_line()), "{text}");
    }

    #[test]
    fn one_issue_exits_one() {
        let nat = symmetric_nat();
        let (engine, _) = crate::diagnose::fixture::run();
        let issue = engine.primary_issues()[0].clone();
        let findings = [nat.clone(), issue.clone()];
        assert_eq!(outcome(&findings, true, true), Outcome::Finding);
        assert_eq!(outcome(&findings, false, true), Outcome::Finding);

        let text = text_report(Outcome::Finding, &sampling(true), &findings, false);
        let (above, below) = text
            .split_once("observations · not counted in the exit status\n")
            .expect("observations have their own heading");
        assert!(above.starts_with("finding · 30 samples in 30s\n"), "{text}");
        assert!(above.contains(&issue.summary_line()), "{text}");
        assert!(below.contains(&nat.summary_line()), "{text}");
    }

    #[test]
    fn json_separates_issues_from_observations() {
        let (engine, _) = crate::diagnose::fixture::run();
        let mut findings = select(engine.issues(), None);
        let issues = findings.len();
        findings.push(symmetric_nat());
        let json = json_report(
            outcome(&findings, true, false),
            &sampling(true),
            engine.coverage(),
            &findings,
            false,
        );
        assert_eq!(json["schema"], 2);
        assert_eq!(json["outcome"], "finding");
        assert_eq!(json["exit"], 1);
        let listed = |key: &str| json[key].as_array().unwrap().clone();
        assert_eq!(listed("issues").len(), issues);
        for entry in listed("issues") {
            assert_eq!(entry["kind"], "issue", "{entry}");
            assert_ne!(entry["severity"], "info", "{entry}");
        }
        let observations = listed("observations");
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0]["kind"], "observation");
        assert_eq!(observations[0]["rule"], "nat.symmetric");
        // The finding's own `kind` sits beside the subject's, not over it.
        assert_eq!(observations[0]["subject"]["kind"], "host");
    }

    /// What the fixture's faults write, against
    /// schemas/diagnose-run.v2.schema.json. The binary reaches only the target
    /// rules on a test machine (tests/schemas.rs), and this reaches the
    /// fixture's other findings, every check state and an Observation. The
    /// second report is one no run writes today, a finding with everything a
    /// session can put on one, so the fields a run leaves empty are described
    /// by what they hold and not only by a null.
    #[test]
    fn the_fixture_s_findings_match_the_schema() {
        use crate::diagnose::issue::{Action, Applied, Capability, IssueState, Step, Verification};
        use crate::diagnose::next_test::{Outcome as TestOutcome, TestRun};
        use crate::schemas::{test_support as schema, DIAGNOSE_RUN};

        let (engine, _) = crate::diagnose::fixture::run();
        let mut findings = select(engine.issues(), None);
        findings.push(symmetric_nat());
        let json = json_report(
            outcome(&findings, true, false),
            &sampling(true),
            engine.coverage(),
            &findings,
            false,
        );
        schema::check(DIAGNOSE_RUN.file, &json);
        assert_eq!(json["metadata"]["schema"], DIAGNOSE_RUN.schema);
        assert_eq!(
            json["metadata"]["schema_version"],
            json["schema"].to_string()
        );

        let subjects = [
            Subject::Host,
            Subject::Egress {
                process: "curl".into(),
                destination: "example.com".into(),
                port: 443,
            },
            Subject::Resolver {
                addr: "192.0.2.53".into(),
            },
            Subject::Path {
                target: "192.0.2.1".into(),
            },
            Subject::Socket {
                local: "192.0.2.2:5000".into(),
                remote: "192.0.2.1:443".into(),
            },
            Subject::Iface {
                name: "eth0".into(),
            },
            Subject::Process {
                name: "curl".into(),
                pid: None,
            },
            Subject::Process {
                name: "curl".into(),
                pid: Some(7),
            },
            Subject::Target { name: "api".into() },
        ];
        let rich: Vec<Issue> = subjects
            .into_iter()
            .enumerate()
            .map(|(n, subject)| {
                let mut f = finding(&n.to_string(), "gateway.unreachable", subject);
                f.stale_since = Some("2026-09-15 10:00:01".into());
                f.beta = true;
                f.state = IssueState::Acked;
                f.scope.configuration = Some("target-config:abc".into());
                f.scope.via_iface = Some("eth0".into());
                f.scope.via_resolver = Some("192.0.2.53".into());
                f.scope.processes_measured = true;
                f.scope.processes = vec!["curl".into()];
                f.scope.note = Some("a note".into());
                f.evidence =
                    vec![
                        crate::diagnose::issue::Evidence::new("gateway.loss", 100.0, "%")
                            .with_baseline(0.5, 0.25)
                            .with_window(30, 30),
                    ];
                let mut apply = Step::apply(
                    '1',
                    "switch",
                    "detail",
                    Action::SetResolver {
                        addr: "192.0.2.53".into(),
                    },
                    Capability::Root,
                );
                apply.applied = Some(Applied::No {
                    reason: "needs root".into(),
                });
                f.remediation = vec![
                    Step::instruct("do", "this"),
                    Step::escalate("ask", "them"),
                    apply,
                ];
                f.artifacts = vec!["capture.pcapng".into()];
                f.consequences = vec!["9".into()];
                f.suppressed_by = Some("8".into());
                f.recurrence = 2;
                f.tests = vec![TestRun {
                    test: "load.idle_vs_loaded".into(),
                    at: "2026-09-15 10:00:00".into(),
                    outcome: TestOutcome::Inconclusive,
                    detail: "no reply".into(),
                    measurements: [("rtt".to_string(), 1.5)].into_iter().collect(),
                    after_action: false,
                }];
                f.verification = Some(Verification {
                    step: 0,
                    action_at: "2026-09-15 10:00:00".into(),
                    holding_at_action: false,
                    top_cause: None,
                    supporting: vec![],
                    outcome: None,
                    decided_at: None,
                });
                f
            })
            .collect();
        let json = json_report(
            outcome(&rich, true, true),
            &sampling(false),
            &Coverage::default(),
            &rich,
            true,
        );
        schema::check(DIAGNOSE_RUN.file, &json);
        assert_eq!(json["issues"].as_array().unwrap().len(), rich.len());
    }

    #[test]
    fn schema_2_checks_have_state_not_passed() {
        let (engine, _) = crate::diagnose::fixture::run();
        let findings = select(engine.issues(), None);
        let json = json_report(
            outcome(&findings, true, false),
            &sampling(true),
            engine.coverage(),
            &findings,
            false,
        );
        let mut states = std::collections::BTreeSet::new();
        for entry in json["issues"].as_array().unwrap() {
            for cause in entry["causes"].as_array().unwrap() {
                for check in cause["checks"].as_array().unwrap() {
                    assert!(check.get("passed").is_none(), "{check}");
                    let state = check["state"].as_str().expect("every check has a state");
                    assert_eq!(
                        state == "not_run",
                        check.get("why_not").is_some(),
                        "{check}"
                    );
                    states.insert(state.to_string());
                }
            }
        }
        // The fixture exercises all three, so none is vacuous.
        assert_eq!(
            states.into_iter().collect::<Vec<_>>(),
            ["failed", "not_run", "passed"]
        );
    }

    fn asked(toml: &str) -> Asked {
        Asked::new(&toml::from_str(toml).expect("a target entry"))
    }

    /// A probe of `name` that resolved through 192.168.8.1 and connected,
    /// with `http` as its first-byte stage.
    fn probe(name: &str, http: crate::diagnose::targets::Stage) -> TargetObs {
        use crate::diagnose::targets::{Lookup, LookupOutcome, Stage, TargetContext};
        let ok = |ms| {
            Some(Stage {
                ms: Some(ms),
                error: None,
            })
        };
        TargetObs {
            baseline_key: None,
            name: name.into(),
            host: format!("{name}.corp.internal"),
            port: 443,
            tls: true,
            http: true,
            expect_status: None,
            probed_at: "2026-09-15 10:00:00".into(),
            resolve: Stage {
                ms: Some(2.0),
                error: None,
            },
            addresses: vec!["10.1.2.3".into()],
            lookups: vec![Lookup {
                resolver: "192.168.8.1".into(),
                link: None,
                outcome: LookupOutcome::Answered,
            }],
            connect: ok(12.0),
            connect_v4: ok(12.0),
            connect_v6: None,
            tls_stage: ok(30.0),
            status: None,
            http_stage: Some(http),
            attempts: vec![],
            effective_endpoint: None,
            sni: None,
            http_authority: None,
            stale_after_secs: None,
            context: TargetContext::default(),
        }
    }

    /// D33-B07: `--target api` exited 0 on a 503, because the detector
    /// demotes a failing service to an Observation. Asked about the target,
    /// the run counts it as an Issue; asked about the network, it does not.
    #[test]
    fn a_named_target_answering_503_exits_one() {
        use crate::diagnose::targets::{Stage, StageError};
        let mut target = probe(
            "api",
            Stage {
                ms: Some(40.0),
                error: Some(StageError::HttpStatus { status: 503 }),
            },
        );
        target.status = Some(503);
        let observations = Observations {
            targets: vec![target],
            ..Default::default()
        };
        let engine = engine_after(&observations);
        let tab = engine.primary();
        assert_eq!(tab.len(), 1, "{tab:?}");
        assert_eq!(tab[0].rule, "target.http_error");
        assert_eq!(tab[0].kind(), Kind::Observation, "the Diagnose tab's kind");
        assert!(evidence(&observations, Some("api")));

        let mut api = asked("name = \"api\"\nhost = \"api.corp.internal\"");
        api.saw(&observations);
        let findings = select(engine.issues(), Some(&api));
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].kind(), Kind::Issue);
        assert_eq!(findings[0].severity, Severity::Medium);
        let outcome = outcome(&findings, true, false);
        assert_eq!(outcome as i32, 1);
        let json = json_report(
            outcome,
            &sampling(true),
            engine.coverage(),
            &findings,
            false,
        );
        assert_eq!(json["issues"][0]["kind"], "issue");
        assert_eq!(json["issues"][0]["scope"]["note"], "service, not network");
        let text = text_report(outcome, &sampling(true), &findings, false);
        assert!(
            text.contains(&format!(
                "  {}\n    service, not network\n",
                findings[0].summary_line()
            )),
            "{text}"
        );
        assert!(!text.contains("observations"), "{text}");
        assert_eq!(
            engine.primary()[0].severity,
            Severity::Info,
            "the engine's finding is left alone"
        );

        // The same run without --target asks whether the network is at
        // fault, and a failing service is not.
        let findings = select(engine.issues(), None);
        assert_eq!(findings[0].kind(), Kind::Observation);
        assert_eq!(super::outcome(&findings, true, false) as i32, 0);
    }

    /// One sample in which `api` times out on connect and the fixture's
    /// gateway loses every probe. `edit` adjusts the target's probe first.
    fn gateway_down(edit: impl FnOnce(&mut TargetObs)) -> Observations {
        use crate::diagnose::detectors::GatewayObs;
        use crate::diagnose::targets::{Stage, StageError};
        let mut target = probe(
            "api",
            Stage {
                ms: None,
                error: None,
            },
        );
        target.connect = Some(Stage {
            ms: Some(3000.0),
            error: Some(StageError::Timeout),
        });
        target.connect_v4 = target.connect.clone();
        target.tls_stage = None;
        target.http_stage = None;
        edit(&mut target);
        Observations {
            iface: crate::diagnose::fixture::observations_at(0).iface,
            gateway: Some(GatewayObs {
                addr: Some("192.168.8.1".into()),
                rtt_ms: None,
                loss_pct: 100.0,
                arp_ok: None,
                icmp_ok: false,
                internet_reachable: Some(false),
            }),
            targets: vec![target],
            ..Default::default()
        }
    }

    /// REVIEW §2.1: the filter matched on the subject's label, so a gateway
    /// failure that suppressed the target's own finding was dropped and the
    /// run exited 0 with the target down.
    #[test]
    fn a_gateway_root_cause_survives_the_target_filter() {
        let observations = gateway_down(|_| {});
        let engine = engine_after(&observations);
        let tab = engine.primary();
        assert_eq!(tab.len(), 1, "{tab:?}");
        let gateway = tab[0];
        assert_eq!(gateway.rule, "gateway.unreachable");
        let hidden = engine
            .issues()
            .iter()
            .find(|i| i.subject.label() == "api")
            .expect("the target's own finding");
        assert_eq!(hidden.suppressed_by.as_ref(), Some(&gateway.id));
        assert!(
            tab.iter().all(|f| f.subject.label() != "api"),
            "the old label filter kept nothing"
        );

        let mut api = asked("name = \"api\"\nhost = \"api.corp.internal\"");
        api.saw(&observations);
        let findings = select(engine.issues(), Some(&api));
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, "gateway.unreachable");
        assert_eq!(findings[0].consequences, vec![hidden.id.clone()]);
        assert_eq!(outcome(&findings, true, false), Outcome::Finding);
    }

    /// P13 review: the gateway above lies on the target's route as well, so
    /// that test passes without the consequence edge. A loopback target
    /// takes no host-wide Issue, and only the edge keeps the gateway failure
    /// the engine hid its finding under. Without it the run exited 0 with
    /// the target down.
    #[test]
    fn a_root_that_hides_the_target_is_kept_off_its_route() {
        let observations = gateway_down(|target| {
            target.host = "127.0.0.1".into();
            target.addresses = vec!["127.0.0.1".into()];
            target.lookups.clear();
        });
        let engine = engine_after(&observations);
        let tab = engine.primary();
        assert_eq!(tab.len(), 1, "{tab:?}");
        let gateway = tab[0];
        assert_eq!(gateway.rule, "gateway.unreachable");
        let hidden = engine
            .issues()
            .iter()
            .find(|i| i.subject.label() == "api")
            .expect("the target's own finding");
        assert_eq!(hidden.suppressed_by.as_ref(), Some(&gateway.id));

        let mut api = asked("name = \"api\"\nhost = \"127.0.0.1\"");
        api.saw(&observations);
        assert!(
            !api.routes_through(gateway),
            "nothing host-wide is on its route"
        );
        let findings = select(engine.issues(), Some(&api));
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, "gateway.unreachable");
        assert_eq!(outcome(&findings, true, false), Outcome::Finding);
    }

    fn finding(id: &str, rule: &str, subject: Subject) -> Issue {
        let r = rules::lookup(rule).expect("a catalogued rule");
        Issue {
            id: id.into(),
            rule: rule.into(),
            severity: r.severity,
            title: r.title.into(),
            subject,
            since: "2026-09-15 10:00:00".into(),
            last_seen: "2026-09-15 10:00:00".into(),
            stale_since: None,
            beta: false,
            state: crate::diagnose::issue::IssueState::Open,
            evidence: vec![],
            scope: Default::default(),
            causes: vec![],
            remediation: vec![],
            verify: rules::default_verify(rule).unwrap(),
            artifacts: vec![],
            consequences: vec![],
            suppressed_by: None,
            recurrence: 0,
            tests: vec![],
            verification: None,
        }
    }

    /// A host-wide Issue stays with the named target unless it names an
    /// interface or resolver the target is known not to use. Findings about
    /// paths, sockets or other targets, and Observations, leave.
    #[test]
    fn the_target_keeps_host_wide_issues_on_its_route() {
        let resolver = |addr: &str| Subject::Resolver { addr: addr.into() };
        let iface = |name: &str| Subject::Iface { name: name.into() };
        let mut gateway = finding("1", "gateway.unreachable", Subject::Host);
        gateway.scope.via_iface = Some("eth0".into());
        let issues = vec![
            gateway,
            finding("2", "dns.failing", resolver("192.168.8.1")),
            finding("3", "link.down", iface("wlan0")),
            finding("4", "gateway.rtt_spike", Subject::Host),
            finding("5", "nat.symmetric", Subject::Host),
            finding(
                "6",
                "path.high_loss",
                Subject::Path {
                    target: "1.1.1.1".into(),
                },
            ),
            finding(
                "7",
                "target.connect_failed",
                Subject::Target {
                    name: "other".into(),
                },
            ),
        ];
        let kept = |asked: &Asked| -> Vec<String> {
            select(&issues, Some(asked))
                .into_iter()
                .map(|f| f.id)
                .collect()
        };
        let named = "name = \"api\"\nhost = \"api.corp.internal\"";

        // Probed, but its lookup recorded no route: every host-wide Issue
        // could lie on it.
        assert_eq!(kept(&probed(named, &["10.1.2.3"])), ["1", "2", "3", "4"]);

        let mut known = probed(named, &["10.1.2.3"]);
        known.via_iface = Some("eth0".into());
        known.via_resolver = Some("192.168.8.1".into());
        assert_eq!(kept(&known), ["1", "2", "4"], "wlan0 is not its link");

        let mut tunnelled = probed(named, &["10.1.2.3"]);
        tunnelled.via_iface = Some("wg0".into());
        tunnelled.via_resolver = Some("10.8.0.1".into());
        assert_eq!(kept(&tunnelled), ["4"]);

        // An address needs no resolver.
        let literal = probed("name = \"api\"\nhost = \"10.1.2.3\"", &["10.1.2.3"]);
        assert_eq!(kept(&literal), ["1", "3", "4"]);

        // A service on this host goes through no gateway, link or resolver.
        let loopback = probed("name = \"api\"\nhost = \"127.0.0.1\"", &["127.0.0.1"]);
        assert!(kept(&loopback).is_empty());
        let mut localhost = probed("name = \"api\"\nhost = \"localhost\"", &[]);
        assert_eq!(kept(&localhost), ["1", "2", "3", "4"], "not yet resolved");
        localhost.saw(&Observations {
            targets: vec![unrouted(&["::1", "127.0.0.1"])],
            ..Default::default()
        });
        assert!(kept(&localhost).is_empty());
    }

    /// A probe of `api` whose lookup recorded no route, and which resolved
    /// `addresses`.
    fn unrouted(addresses: &[&str]) -> TargetObs {
        let mut target = probe(
            "api",
            crate::diagnose::targets::Stage {
                ms: Some(40.0),
                error: None,
            },
        );
        target.lookups.clear();
        target.addresses = addresses.iter().map(|a| a.to_string()).collect();
        target
    }

    /// The target in `toml`, after one sample held [`unrouted`]`(addresses)`.
    fn probed(toml: &str, addresses: &[&str]) -> Asked {
        let mut target = asked(toml);
        target.saw(&Observations {
            targets: vec![unrouted(addresses)],
            ..Default::default()
        });
        target
    }

    /// P13 review: a target no sample held a probe of, because it is
    /// disabled, failed validation or did not finish inside the budget, has
    /// no route to put a host-wide Issue on. Reading its unknown route as
    /// any route kept every one, and the run exited 1 with `"evidence":
    /// false`, where the label filter before it exited 2.
    #[test]
    fn a_target_never_probed_is_incomplete_whatever_the_host_shows() {
        let (engine, _) = crate::diagnose::fixture::run();
        let observations = crate::diagnose::fixture::observations_at(0);
        let named = "name = \"api\"\nhost = \"api.corp.internal\"";
        let mut api = asked(named);
        api.saw(&observations);
        assert!(!evidence(&observations, Some("api")));
        let findings = select(engine.issues(), Some(&api));
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(outcome(&findings, false, false), Outcome::Incomplete);

        // Not vacuous: the host has Issues a probed target would keep.
        let findings = select(engine.issues(), Some(&probed(named, &["10.1.2.3"])));
        assert!(
            findings.iter().any(|f| f.kind() == Kind::Issue),
            "{findings:?}"
        );
        assert_eq!(outcome(&findings, true, true), Outcome::Finding);
    }

    #[test]
    fn the_missing_check_line_gives_the_reason_the_json_gives() {
        let awaiting = CheckResult::not_run(
            "link_level_bufferbloat_test_passed",
            "link-level bufferbloat test passed",
            Availability::AwaitingTest,
            "no loaded-rtt test has run",
        );
        assert_eq!(
            missing_line(&awaiting),
            "awaiting test: link-level bufferbloat test passed — no loaded-rtt test has run"
        );
        let never_built = CheckResult::not_run(
            "icmp_rtt_raised",
            "icmp rtt raised",
            Availability::NotImplemented,
            "no icmp probe",
        );
        assert_eq!(
            missing_line(&never_built),
            "not implemented: icmp rtt raised — no icmp probe"
        );
    }

    #[test]
    fn unknown_options_are_refused_rather_than_ignored() {
        assert!(parse(&["--target".into(), "api".into()]).is_ok());
        assert!(parse(&["--nope".into()]).is_err());
        assert!(parse(&["--target".into()]).is_err());
        assert!(parse(&["--format".into(), "yaml".into()]).is_err());
    }
}
