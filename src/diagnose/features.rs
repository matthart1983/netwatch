//! Feature vectors for learned models, computed once, in Rust.
//!
//! Training code reads what this module writes and never computes a feature
//! itself, so a model trained offline sees exactly the numbers the app will
//! hand it at inference time. [`schema`] is derived by running [`extract`]
//! over empty inputs, so the names and the values can't drift apart, and
//! [`schema_hash`] lets a model refuse a vector built from a different schema.
//!
//! Missing values are `NaN`, never zero: "the alternate resolver answered in
//! 0ms" and "no alternate resolver was probed" must stay different numbers.
//! Check features use +1 passed, −1 failed, 0 not run, and `NaN` when the
//! check belongs to a different rule than the issue being described.
//!
//! By construction no feature carries an address, hostname, process name or
//! network identity: those would let a model memorise one user's network
//! instead of learning what a fault looks like.

use std::sync::OnceLock;

use serde::Serialize;

use super::baseline::BaselineStore;
use super::coverage::{Availability, Coverage};
use super::detectors::{
    classify_socket, first_hop_change, Observations, SocketVerdict, Thresholds,
};
use super::issue::{Issue, Severity};
use super::{causes, rules};
use crate::ui::sanitize::{display, display_owned};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    /// Raw measurements from the observations.
    Observation,
    /// Measurements against their learned baseline.
    Baseline,
    /// The issue's own cause checks.
    Check,
    /// Discriminating tests run against the issue.
    Test,
    /// The developer target the issue is about.
    Target,
    /// Which rule inputs were available.
    Coverage,
    /// The issue and the host it was raised on.
    Context,
    /// Other rules open at the same time.
    CoOpen,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FeatureSpec {
    pub name: String,
    pub group: Group,
}

/// Everything a decision point is described by.
pub struct Input<'a> {
    pub issue: Option<&'a Issue>,
    pub obs: &'a Observations,
    pub baselines: Option<&'a BaselineStore>,
    pub coverage: &'a Coverage,
    /// Issues open at the decision point, the described one included.
    pub open: &'a [&'a Issue],
    pub thresholds: &'a Thresholds,
    pub capability_root: bool,
    /// Local `YYYY-MM-DD HH:MM:SS` of the decision point.
    pub ts: &'a str,
}

struct Builder {
    group: Group,
    names: Vec<FeatureSpec>,
    values: Vec<f32>,
}

impl Builder {
    fn group(&mut self, g: Group) {
        self.group = g;
    }

    fn put(&mut self, name: impl Into<String>, value: Option<f64>) {
        self.names.push(FeatureSpec {
            name: name.into(),
            group: self.group,
        });
        self.values.push(value.map_or(f32::NAN, |v| v as f32));
    }

    fn flag(&mut self, name: impl Into<String>, value: Option<bool>) {
        self.put(name, value.map(|b| if b { 1.0 } else { 0.0 }));
    }
}

/// The feature vector for one decision point, in [`schema`] order.
pub fn extract(input: &Input<'_>) -> Vec<f32> {
    build(input).values
}

/// Names and groups, in vector order.
pub fn schema() -> &'static [FeatureSpec] {
    static SCHEMA: OnceLock<Vec<FeatureSpec>> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let obs = Observations::default();
        let coverage = Coverage::default();
        let thresholds = Thresholds::default();
        build(&Input {
            issue: None,
            obs: &obs,
            baselines: None,
            coverage: &coverage,
            open: &[],
            thresholds: &thresholds,
            capability_root: false,
            ts: "",
        })
        .names
    })
}

/// FNV-1a over every `group:name`, as 16 hex digits. Stable across builds and
/// platforms, which `std`'s hasher is not.
pub fn schema_hash() -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for spec in schema() {
        let group = serde_json::to_string(&spec.group).unwrap_or_default();
        for b in group
            .bytes()
            .chain(b":".iter().copied())
            .chain(spec.name.bytes())
            .chain(b"\n".iter().copied())
        {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("{h:016x}")
}

fn build(input: &Input<'_>) -> Builder {
    let mut b = Builder {
        group: Group::Observation,
        names: Vec::new(),
        values: Vec::new(),
    };
    let obs = input.obs;

    // ------------------------------------------------------ observations
    b.group(Group::Observation);
    let gw = obs.gateway.as_ref();
    b.put("gateway.rtt_ms", gw.and_then(|g| g.rtt_ms));
    b.put("gateway.loss_pct", gw.map(|g| g.loss_pct));
    b.flag("gateway.arp_ok", gw.and_then(|g| g.arp_ok));
    b.flag("gateway.icmp_ok", gw.map(|g| g.icmp_ok));
    b.flag(
        "gateway.internet_reachable",
        gw.and_then(|g| g.internet_reachable),
    );

    let dns = obs.dns.as_ref();
    b.put("dns.rtt_p50_ms", dns.and_then(|d| d.rtt_p50_ms));
    b.put("dns.rtt_p95_ms", dns.and_then(|d| d.rtt_p95_ms));
    b.put("dns.failure_rate_pct", dns.map(|d| d.failure_rate_pct));
    b.put(
        "dns.truncation_rate_pct",
        dns.map(|d| d.truncation_rate_pct),
    );
    b.put("dns.queries", dns.map(|d| f64::from(d.queries)));
    b.put("dns.alt_rtt_ms", dns.and_then(|d| d.alt_rtt_ms));
    b.put("dns.icmp_rtt_ms", dns.and_then(|d| d.icmp_rtt_ms));
    b.put("dns.cached_rtt_ms", dns.and_then(|d| d.cached_rtt_ms));
    b.put(
        "dns.alt_over_p50",
        dns.and_then(|d| Some(d.alt_rtt_ms? / d.rtt_p50_ms.filter(|p| *p > 0.0)?)),
    );
    b.put(
        "dns.cached_over_p50",
        dns.and_then(|d| Some(d.cached_rtt_ms? / d.rtt_p50_ms.filter(|p| *p > 0.0)?)),
    );
    let cross = dns.and_then(|d| d.cross.as_ref());
    b.put("dns.cross_mismatch_pct", cross.map(|c| c.mismatch_pct));
    b.flag("dns.cross_private_answer", cross.map(|c| c.private_answer));
    b.flag("dns.cross_validated", cross.map(|c| c.validated));

    let iface = obs.iface.as_ref();
    b.flag("iface.carrier", iface.and_then(|i| i.carrier));
    b.flag("iface.wireless", iface.and_then(|i| i.wireless));
    b.put(
        "iface.errors_per_min",
        iface.map(|i| i.errors_per_min as f64),
    );
    b.put(
        "iface.drops_per_min",
        iface.and_then(|i| i.drops_per_min).map(|d| d as f64),
    );
    b.put(
        "iface.signal_dbm",
        iface.and_then(|i| i.signal_dbm.map(f64::from)),
    );
    b.put("iface.tx_retry_pct", iface.and_then(|i| i.tx_retry_pct));
    b.put(
        "iface.utilisation_pct",
        iface.and_then(|i| i.utilisation_pct()),
    );
    b.put("iface.rx_bps", iface.map(|i| i.rx_bps));
    b.put("iface.tx_bps", iface.map(|i| i.tx_bps));

    let path = obs.paths.first();
    let last_hop = path.and_then(|p| p.hops.iter().rev().find(|h| !h.silent));
    b.put("path.last_rtt_ms", last_hop.and_then(|h| h.rtt_p50_ms));
    b.put("path.last_loss_pct", last_hop.map(|h| h.loss_pct));
    b.put(
        "path.max_hop_loss_pct",
        path.and_then(|p| {
            p.hops
                .iter()
                .filter(|h| !h.silent)
                .map(|h| h.loss_pct)
                .reduce(f64::max)
        }),
    );
    b.put("path.hops", path.map(|p| p.hops.len() as f64));
    b.put(
        "path.first_changed_hop",
        path.map(|p| {
            p.previous
                .as_deref()
                .and_then(|prev| first_hop_change(prev, &p.hops))
                .map_or(0.0, f64::from)
        }),
    );

    let verdicts: Vec<SocketVerdict> = obs
        .sockets
        .iter()
        .map(|s| classify_socket(s, input.thresholds))
        .collect();
    let count = |v: SocketVerdict| Some(verdicts.iter().filter(|x| **x == v).count() as f64);
    b.put("sockets.count", Some(obs.sockets.len() as f64));
    b.put("sockets.bufferbloat", count(SocketVerdict::Bufferbloat));
    b.put("sockets.retrans_burst", count(SocketVerdict::RetransBurst));
    b.put("sockets.zero_window", count(SocketVerdict::ZeroWindow));
    b.put(
        "sockets.receiver_limited",
        count(SocketVerdict::ReceiverLimited),
    );
    b.put("sockets.congestion", count(SocketVerdict::Congestion));
    b.put(
        "sockets.max_rtt_ms",
        obs.sockets.iter().filter_map(|s| s.rtt_ms).reduce(f64::max),
    );

    b.put("load.idle_rtt_ms", obs.idle_rtt_ms);
    b.put("load.loaded_rtt_ms", obs.loaded_rtt_ms);
    b.flag("nat.symmetric", obs.nat.as_ref().map(|n| n.symmetric));
    b.flag("captive.portal", Some(obs.captive_portal_url.is_some()));

    // ------------------------------------------------------ baselines
    b.group(Group::Baseline);
    let against = |subject: Option<&str>, metric: &str, value: Option<f64>| {
        let base = input.baselines?.get(subject?, metric)?;
        let value = value?;
        Some((
            base.sigma_above(value, input.thresholds.sigma_floor()),
            (base.mean > 0.0).then(|| value / base.mean),
        ))
    };
    for (name, subject, metric, value) in [
        (
            "dns.rtt_p50",
            dns.map(|d| d.resolver.as_str()),
            "dns.rtt_p50",
            dns.and_then(|d| d.rtt_p50_ms),
        ),
        (
            "gateway.rtt",
            gw.and_then(|g| g.addr.as_deref()),
            "gateway.rtt",
            gw.and_then(|g| g.rtt_ms),
        ),
        (
            "path.rtt",
            path.map(|_| "internet"),
            "path.rtt",
            last_hop.and_then(|h| h.rtt_p50_ms),
        ),
    ] {
        let r = against(subject, metric, value);
        b.put(format!("{name}.sigma"), r.and_then(|r| r.0));
        b.put(format!("{name}.multiple"), r.and_then(|r| r.1));
    }

    // ------------------------------------------------------ checks
    b.group(Group::Check);
    for spec in causes::CAUSES {
        let cause = input
            .issue
            .filter(|i| i.rule == spec.rule)
            .map(|i| i.causes.iter().find(|c| c.id == spec.cause));
        for check in spec.checks {
            let value = match cause {
                None => None,
                Some(None) => Some(0.0),
                Some(Some(c)) => Some(match c.checks.iter().find(|k| k.id == *check) {
                    Some(k) => match k.passed {
                        Some(true) => 1.0,
                        Some(false) => -1.0,
                        None => 0.0,
                    },
                    None => 0.0,
                }),
            };
            b.put(
                format!("check.{}.{}.{}", spec.rule, spec.cause, check),
                value,
            );
        }
    }

    // ------------------------------------------------------ tests
    b.group(Group::Test);
    let runs = input
        .issue
        .map(|i| super::next_test::latest_runs(i, input.ts))
        .unwrap_or_default();
    for spec in super::next_test::TESTS {
        let value = runs
            .iter()
            .find(|r| r.test == spec.id)
            .map(|r| match r.outcome {
                super::next_test::Outcome::Positive => 1.0,
                super::next_test::Outcome::Negative => -1.0,
                super::next_test::Outcome::Inconclusive => 0.0,
            });
        b.put(format!("test.{}", spec.id), value);
    }

    // ------------------------------------------------------ target
    b.group(Group::Target);
    // The probe of the entry the issue was found under: after an edit, the
    // name's new entry is another target.
    let target = match input.issue {
        Some(Issue {
            subject: super::issue::Subject::Target { name },
            scope,
            ..
        }) => obs.targets.iter().find(|t| {
            &t.name == name
                && (scope.configuration.is_none() || scope.configuration == t.baseline_key)
        }),
        _ => None,
    };
    let stage_ok = |s: Option<&super::targets::Stage>| s.map(|s| s.is_ok());
    let stage_ms = |s: Option<&super::targets::Stage>| s.and_then(|s| s.ms);
    b.flag("target.resolve_ok", target.map(|t| t.resolve.is_ok()));
    b.flag(
        "target.connect_ok",
        target.and_then(|t| stage_ok(t.connect.as_ref())),
    );
    b.flag(
        "target.tls_ok",
        target.and_then(|t| stage_ok(t.tls_stage.as_ref())),
    );
    b.flag(
        "target.http_ok",
        target.and_then(|t| stage_ok(t.http_stage.as_ref())),
    );
    b.put("target.resolve_ms", target.and_then(|t| t.resolve.ms));
    b.put(
        "target.connect_ms",
        target.and_then(|t| stage_ms(t.connect.as_ref())),
    );
    b.put(
        "target.tls_ms",
        target.and_then(|t| stage_ms(t.tls_stage.as_ref())),
    );
    b.put(
        "target.ttfb_ms",
        target.and_then(|t| stage_ms(t.http_stage.as_ref())),
    );
    b.put(
        "target.status",
        target.and_then(|t| t.status.map(f64::from)),
    );
    b.flag(
        "target.v6_fails_v4_ok",
        target.and_then(|t| match (&t.connect_v4, &t.connect_v6) {
            (Some(v4), Some(v6)) => Some(v4.is_ok() && !v6.is_ok()),
            _ => None,
        }),
    );
    use super::targets::{LookupOutcome, StageError};
    let lookups = |o: LookupOutcome| {
        target.map(|t| t.lookups.iter().filter(|l| l.outcome == o).count() as f64)
    };
    b.put("target.lookups_answered", lookups(LookupOutcome::Answered));
    b.put("target.lookups_nxdomain", lookups(LookupOutcome::NxDomain));
    b.put(
        "target.lookups_failed",
        target.map(|t| {
            t.lookups
                .iter()
                .filter(|l| matches!(l.outcome, LookupOutcome::ServFail | LookupOutcome::NoReply))
                .count() as f64
        }),
    );
    b.flag("target.proxy_env", target.map(|t| t.context.proxy_env));
    b.flag(
        "target.vpn_up",
        target.map(|t| !t.context.vpn_ifaces.is_empty()),
    );
    b.put(
        "target.clock_offset_secs",
        target.and_then(|t| t.context.clock_offset_secs),
    );
    let first_error = target.and_then(|t| {
        [
            Some(&t.resolve),
            t.connect.as_ref(),
            t.tls_stage.as_ref(),
            t.http_stage.as_ref(),
        ]
        .into_iter()
        .flatten()
        .find_map(|s| s.error.clone())
    });
    for (label, matches) in [
        (
            "nxdomain",
            (|e: &StageError| *e == StageError::NxDomain) as fn(&StageError) -> bool,
        ),
        ("resolver_failed", |e| *e == StageError::ResolverFailed),
        ("timeout", |e| {
            matches!(e, StageError::Timeout | StageError::Unreachable)
        }),
        ("refused", |e| *e == StageError::Refused),
        ("cert_untrusted", |e| *e == StageError::CertUntrusted),
        ("cert_validity", |e| {
            matches!(e, StageError::CertExpired | StageError::CertNotYetValid)
        }),
        ("cert_name", |e| *e == StageError::CertNameMismatch),
        ("http_status", |e| {
            matches!(e, StageError::HttpStatus { .. })
        }),
    ] {
        b.flag(
            format!("target.error.{label}"),
            target.map(|_| first_error.as_ref().is_some_and(matches)),
        );
    }

    // ------------------------------------------------------ coverage
    b.group(Group::Coverage);
    for rule in rules::CATALOGUE.iter().filter(|r| r.status.is_active()) {
        let status = input
            .coverage
            .rules
            .iter()
            .find(|r| r.rule == rule.id)
            .map(|r| &r.status);
        for (label, state) in [
            ("available", Availability::Available),
            ("learning", Availability::Learning),
            ("not_measured", Availability::NotMeasured),
            ("stale", Availability::Stale),
        ] {
            b.flag(
                format!("coverage.{}.{label}", rule.id),
                status.map(|s| *s == state),
            );
        }
    }

    // ------------------------------------------------------ context
    b.group(Group::Context);
    let issue = input.issue;
    b.flag("context.capability_root", Some(input.capability_root));
    b.flag(
        "context.switched_network",
        input.baselines.map(|s| s.switched_network()),
    );
    b.flag(
        "context.baselines_ready",
        input.baselines.map(|s| s.overall_readiness().is_ready()),
    );
    b.put(
        "context.severity",
        issue.map(|i| match i.severity {
            Severity::Info => 0.0,
            Severity::Medium => 1.0,
            Severity::High => 2.0,
            Severity::Critical => 3.0,
        }),
    );
    b.put("context.recurrence", issue.map(|i| f64::from(i.recurrence)));
    b.put(
        "context.consequences",
        issue.map(|i| i.consequences.len() as f64),
    );
    b.put(
        "context.secs_since_onset",
        issue.and_then(|i| {
            let since = super::engine::parse_ts(&i.since)?;
            let now = super::engine::parse_ts(input.ts)?;
            Some((now - since).num_seconds().max(0) as f64)
        }),
    );
    b.put(
        "context.rule_top_score",
        issue.and_then(|i| i.top_cause()?.score()),
    );

    // ------------------------------------------------------ co-open
    b.group(Group::CoOpen);
    for rule in rules::CATALOGUE.iter().filter(|r| r.status.is_active()) {
        let others = input
            .open
            .iter()
            .filter(|o| o.rule == rule.id && issue.is_none_or(|i| i.id != o.id))
            .count();
        b.flag(format!("open.{}", rule.id), issue.map(|_| others > 0));
    }

    b
}

// ------------------------------------------------------------ decisions

/// Columns written before the features in every CSV row.
pub const META_COLUMNS: &[&str] = &[
    "episode",
    "source",
    "os",
    "trigger",
    "ts",
    "issue",
    "rule",
    "rule_top_cause",
    "label",
    "label_source",
];

#[derive(Debug, Clone, PartialEq)]
pub struct DecisionRow {
    pub episode: String,
    pub source: String,
    pub os: String,
    /// `opened`, `tested` (after a test result), `closed`, or `final` for an
    /// issue still open at the end.
    pub trigger: &'static str,
    pub ts: String,
    /// `rule#n`: the n-th distinct issue in the episode. Not the subject,
    /// which would put an address in the training data.
    pub issue: String,
    pub rule: String,
    pub rule_top_cause: Option<String>,
    pub label: Option<String>,
    pub label_source: Option<String>,
    pub values: Vec<f32>,
}

/// Replay an episode and describe every decision point: each issue when it
/// opened, when it closed, and, if still open, at the last frame. Computed by
/// replay rather than stored, so older recordings gain new features when the
/// schema changes.
pub fn decisions(episode: &super::episode::Episode) -> Vec<DecisionRow> {
    use super::episode::{issue_key, EpisodeSource, LabelSource};
    use std::collections::{BTreeMap, HashMap};

    let source = match &episode.source {
        EpisodeSource::Live => "live".to_string(),
        EpisodeSource::QuietSample => "quiet".to_string(),
        EpisodeSource::Lab { scenario, .. } => format!("lab:{scenario}"),
    };
    let capability_root = episode.env.capability == "root";
    let last = episode.frames.len().saturating_sub(1);
    let label_for = |key: &str| {
        let rank = |s: &LabelSource| match s {
            LabelSource::Lab => 3,
            LabelSource::Expert { .. } => 2,
            LabelSource::User => 1,
            LabelSource::Rule => 0,
        };
        episode
            .labels
            .iter()
            .filter(|l| l.issue == key)
            .max_by_key(|l| rank(&l.source))
            .map(|l| {
                let source = match &l.source {
                    LabelSource::Lab => "lab",
                    LabelSource::Expert { .. } => "expert",
                    LabelSource::User => "user",
                    LabelSource::Rule => "rule",
                };
                (l.cause.clone(), source.to_string())
            })
    };

    let mut rows = Vec::new();
    let mut ordinals: HashMap<String, usize> = HashMap::new();
    // Ordered, so rows come out in the same order on every run.
    let mut open_before: BTreeMap<String, String> = BTreeMap::new();

    super::episode::drive(episode, |step| {
        let engine = step.engine;
        let primary = engine.primary();
        let now_open: BTreeMap<String, String> = primary
            .iter()
            .map(|i| (issue_key(i), i.id.clone()))
            .collect();

        let mut emit = |issue: &Issue, trigger: &'static str| {
            let key = issue_key(issue);
            let next = ordinals.len() + 1;
            let n = *ordinals.entry(key.clone()).or_insert(next);
            let label = label_for(&key);
            rows.push(DecisionRow {
                episode: episode.id.clone(),
                source: source.clone(),
                os: episode.env.os.clone(),
                trigger,
                ts: step.frame.ts.clone(),
                issue: format!("{}#{n}", issue.rule),
                rule: issue.rule.clone(),
                rule_top_cause: issue.top_cause().map(|c| c.key(&issue.rule)),
                label: label.as_ref().map(|l| l.0.clone()),
                label_source: label.map(|l| l.1),
                values: extract(&Input {
                    issue: Some(issue),
                    obs: &step.frame.obs,
                    baselines: Some(step.baselines),
                    coverage: engine.coverage(),
                    open: &primary,
                    thresholds: &engine.settings().thresholds,
                    capability_root,
                    ts: &step.frame.ts,
                }),
            });
        };

        for (key, id) in &now_open {
            if !open_before.contains_key(key) {
                if let Some(issue) = engine.get(id) {
                    emit(issue, "opened");
                }
            }
        }
        for event in &step.frame.events {
            if let super::engine::EngineEvent::TestCompleted { issue, .. } = event {
                if let Some(issue) = now_open.get(issue).and_then(|id| engine.get(id)) {
                    emit(issue, "tested");
                }
            }
        }
        for (key, id) in &open_before {
            if !now_open.contains_key(key) {
                if let Some(issue) = engine.get(id) {
                    emit(issue, "closed");
                }
            }
        }
        if step.index == last {
            for id in now_open.values() {
                if let Some(issue) = engine.get(id) {
                    emit(issue, "final");
                }
            }
        }
        open_before = now_open;
    });
    rows
}

/// One CSV field. The strings in a row come from the episode file, which
/// can be someone else's, and with no `--out` the CSV goes to the terminal,
/// so each goes through [`display`] first.
fn csv_field(s: &str) -> String {
    let s = display(s);
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.into_owned()
    }
}

pub fn csv_header() -> String {
    META_COLUMNS
        .iter()
        .map(|c| c.to_string())
        .chain(schema().iter().map(|s| s.name.clone()))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn csv_row(row: &DecisionRow) -> String {
    let opt = |o: &Option<String>| o.as_deref().map(csv_field).unwrap_or_default();
    let mut fields = vec![
        csv_field(&row.episode),
        csv_field(&row.source),
        csv_field(&row.os),
        row.trigger.to_string(),
        csv_field(&row.ts),
        csv_field(&row.issue),
        csv_field(&row.rule),
        opt(&row.rule_top_cause),
        opt(&row.label),
        opt(&row.label_source),
    ];
    // Shortest round-trip form; NaN is an empty field.
    fields.extend(row.values.iter().map(|v| {
        if v.is_nan() {
            String::new()
        } else {
            format!("{v}")
        }
    }));
    fields.join(",")
}

/// `schema.json`: what a training run checks its CSV against.
pub fn schema_json() -> serde_json::Value {
    serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "hash": schema_hash(),
        "meta_columns": META_COLUMNS,
        "missing": "empty field (NaN)",
        "check_encoding": { "passed": 1, "failed": -1, "not_run": 0, "other_rule": "empty" },
        "features": schema(),
    })
}

/// `netwatch diagnose features --unstable [--out FILE] [--schema FILE] <FILE|DIR>...`,
/// with `--unstable` checked and removed by [`super::episode::command`].
pub fn command(args: &[String]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::path::{Path, PathBuf};

    let (mut out, mut schema_out, mut targets) = (None, None, Vec::new());
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--out" => {
                out = Some(PathBuf::from(
                    rest.next()
                        .ok_or_else(|| anyhow::anyhow!("--out needs a file"))?,
                ))
            }
            "--schema" => {
                schema_out = Some(PathBuf::from(
                    rest.next()
                        .ok_or_else(|| anyhow::anyhow!("--schema needs a file"))?,
                ))
            }
            other if other.starts_with("--") => anyhow::bail!("unknown option {other}"),
            other => targets.push(PathBuf::from(other)),
        }
    }
    if let Some(path) = &schema_out {
        std::fs::write(path, serde_json::to_string_pretty(&schema_json())? + "\n")?;
    }
    if targets.is_empty() {
        if schema_out.is_some() {
            return Ok(());
        }
        anyhow::bail!("features needs at least one episode file or directory");
    }
    let mut sink: Box<dyn Write> = match &out {
        Some(path) => Box::new(std::io::BufWriter::new(std::fs::File::create(path)?)),
        None => Box::new(std::io::stdout().lock()),
    };
    writeln!(sink, "{}", csv_header())?;
    let (mut episodes, mut rows) = (0, 0);
    for target in &targets {
        let files = if target.is_dir() {
            super::episode::list(target)
        } else {
            vec![target.clone()]
        };
        for file in files {
            let ep = super::episode::load(Path::new(&file)).map_err(|e| {
                anyhow::anyhow!("{}: {e}", display_owned(file.display().to_string()))
            })?;
            episodes += 1;
            for row in decisions(&ep) {
                writeln!(sink, "{}", csv_row(&row))?;
                rows += 1;
            }
        }
    }
    sink.flush()?;
    if out.is_some() {
        eprintln!(
            "{rows} decision points from {episodes} episodes · schema {}",
            schema_hash()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::fixture;

    fn rich() -> (Vec<Issue>, Observations, BaselineStore) {
        let (engine, base) = fixture::run();
        (
            engine.issues().to_vec(),
            fixture::observations_at(fixture::SCENARIO_SECS),
            base,
        )
    }

    #[test]
    fn names_do_not_depend_on_the_data() {
        let (issues, obs, base) = rich();
        let coverage = Coverage::from_observations(&obs, &base, Default::default());
        let open: Vec<&Issue> = issues.iter().collect();
        let t = Thresholds::default();
        for issue in &issues {
            let built = build(&Input {
                issue: Some(issue),
                obs: &obs,
                baselines: Some(&base),
                coverage: &coverage,
                open: &open,
                thresholds: &t,
                capability_root: true,
                ts: "2026-09-03 06:51:19",
            });
            assert_eq!(built.names, schema(), "{} changed the schema", issue.rule);
            assert_eq!(built.values.len(), schema().len());
        }
    }

    #[test]
    fn a_dns_issue_fills_its_own_checks_and_leaves_other_rules_nan() {
        let (issues, obs, base) = rich();
        let dns = issues
            .iter()
            .find(|i| i.rule == "dns.slow_resolver")
            .unwrap();
        let coverage = Coverage::from_observations(&obs, &base, Default::default());
        let t = Thresholds::default();
        let v = extract(&Input {
            issue: Some(dns),
            obs: &obs,
            baselines: Some(&base),
            coverage: &coverage,
            open: &[dns],
            thresholds: &t,
            capability_root: false,
            ts: "2026-09-03 06:51:19",
        });
        let at = |name: &str| {
            let i = schema()
                .iter()
                .position(|s| s.name == name)
                .unwrap_or_else(|| panic!("{name}"));
            v[i]
        };
        assert_eq!(
            at("check.dns.slow_resolver.upstream_slow.alt_resolver_is_fast"),
            1.0
        );
        assert!(
            at("check.gateway.rtt_spike.local_network_congested.gateway_rtt_above_baseline")
                .is_nan()
        );
        // 40ms against 1.2ms, scored against the 0.5ms floor rather than the
        // fixture's σ 0.4, as the detector scored it.
        assert!((at("dns.rtt_p50.sigma") - 77.6).abs() < 1e-3);
        assert!(at("dns.rtt_p50_ms") > 30.0);
        assert!(at("context.secs_since_onset") > 0.0);
        assert!(at("nat.symmetric").is_nan(), "missing stays NaN, not 0");
        assert_eq!(at("load.idle_rtt_ms"), 12.0);
    }

    #[test]
    fn a_target_issue_reads_the_probe_of_the_entry_it_was_found_under() {
        let ep = fixture::synthetic("target-slow-stage").unwrap();
        let issue = &ep.issues.first().unwrap().issue;
        assert!(issue.scope.configuration.is_some());
        let coverage = Coverage::default();
        let t = Thresholds::default();
        let connect_ms = |obs: &Observations| {
            let v = extract(&Input {
                issue: Some(issue),
                obs,
                baselines: None,
                coverage: &coverage,
                open: &[issue],
                thresholds: &t,
                capability_root: false,
                ts: "2026-09-03 06:55:00",
            });
            v[schema()
                .iter()
                .position(|s| s.name == "target.connect_ms")
                .unwrap()]
        };
        let mut obs = ep.frames.last().unwrap().obs.clone();
        assert_eq!(connect_ms(&obs), 12.0);
        // Edited: the name's probe is now of another entry.
        obs.targets[0].baseline_key = Some("target-config:edited".into());
        assert!(connect_ms(&obs).is_nan());
    }

    #[test]
    fn no_feature_name_carries_an_identity() {
        for spec in schema() {
            assert!(
                spec.name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._".contains(c)),
                "{}",
                spec.name
            );
            let digits_dot_digits = spec
                .name
                .split('.')
                .collect::<Vec<_>>()
                .windows(2)
                .any(|w| {
                    w.iter()
                        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
                });
            assert!(!digits_dot_digits, "{} looks like an address", spec.name);
        }
        let unique: std::collections::HashSet<_> = schema().iter().map(|s| &s.name).collect();
        assert_eq!(unique.len(), schema().len(), "duplicate feature names");
    }

    /// Training reads `ml/schema.json`. A schema change without regenerating
    /// it would train on one column layout and infer on another.
    #[test]
    fn the_committed_schema_is_current() {
        let committed: serde_json::Value =
            serde_json::from_str(include_str!("../../ml/schema.json")).unwrap();
        assert_eq!(
            committed,
            schema_json(),
            "run: cargo run -- diagnose features --unstable --schema ml/schema.json"
        );
    }

    #[test]
    fn the_hash_is_stable_and_tracks_the_names() {
        assert_eq!(schema_hash(), schema_hash());
        assert_eq!(schema_hash().len(), 16);
    }
}

#[cfg(test)]
mod decision_tests {
    use super::*;
    use crate::diagnose::episode::{self, Episode, Label, LabelSource};

    /// An episode recorded from the fixture scenario through the real recorder.
    fn recorded() -> Episode {
        use crate::diagnose::engine::{Engine, FixedClock, ObservationTimes};
        let clock = std::sync::Arc::new(FixedClock::at(fixture_start()));
        let mut engine = Engine::new(Box::new(clock.clone()));
        let base = crate::diagnose::fixture::baselines();
        let mut recorder =
            episode::Recorder::new(episode::EnvProfile::detect("root", 1000), 1_789_000_000.0);
        recorder.schedule_quiet_sample(f64::MAX);
        let start = std::time::Instant::now() + std::time::Duration::from_secs(86_400);
        for t in 0..=crate::diagnose::fixture::SCENARIO_SECS {
            let obs = crate::diagnose::fixture::observations_at(t);
            let now = start + std::time::Duration::from_secs(t);
            // Every collector completes each second in the fixture's story.
            let mut times = ObservationTimes {
                interface: Some(now),
                sockets: Some(now),
                path: Some(now),
                ..Default::default()
            };
            times.health.dns = Some(now);
            times.health.gateway = Some(now);
            times.health.internet = Some(now);
            times.health.nat = Some(now);
            engine.observe_live_at(&obs, &base, &times, now);
            use crate::diagnose::engine::Clock;
            let ts = crate::diagnose::engine::format_ts(clock.now());
            let _ = recorder.record(episode::Tick {
                at: 1_789_000_000.0 + t as f64,
                ts,
                now,
                obs: &obs,
                times: &times,
                readings: &[],
                engine: &engine,
                baselines: &base,
                events: vec![],
            });
            clock.advance_secs(1);
        }
        use crate::diagnose::engine::Clock;
        recorder
            .flush(&engine, &crate::diagnose::engine::format_ts(clock.now()))
            .expect("the fixture opens issues")
    }

    fn fixture_start() -> &'static str {
        "2026-09-03 06:44:00"
    }

    #[test]
    fn every_opened_issue_is_a_decision_point_with_a_label_when_one_exists() {
        let mut ep = recorded();
        let dns_key = ep
            .issue_keys()
            .into_iter()
            .find(|k| k.starts_with("dns.slow_resolver"))
            .unwrap();
        ep.labels.push(Label {
            issue: dns_key,
            cause: "dns.slow_resolver/upstream_slow".into(),
            source: LabelSource::Lab,
            ts: ep.ended.clone(),
            note: None,
        });
        let rows = decisions(&ep);
        let opened: Vec<_> = rows.iter().filter(|r| r.trigger == "opened").collect();
        assert_eq!(opened.len(), ep.issue_keys().len());
        let dns = opened
            .iter()
            .find(|r| r.rule == "dns.slow_resolver")
            .unwrap();
        assert_eq!(
            dns.label.as_deref(),
            Some("dns.slow_resolver/upstream_slow")
        );
        assert_eq!(dns.label_source.as_deref(), Some("lab"));
        assert!(dns.issue.starts_with("dns.slow_resolver#"));
        assert!(rows.iter().all(|r| r.values.len() == schema().len()));

        let csv = csv_row(dns);
        assert_eq!(csv.split(',').count(), META_COLUMNS.len() + schema().len());
        assert!(
            !csv.contains("169.254"),
            "no addresses in training rows: {csv}"
        );
        assert_eq!(csv_header().split(',').count(), csv.split(',').count());
    }

    /// With no `--out` the CSV goes to the terminal, and the strings in a row
    /// come from the episode file.
    #[test]
    fn a_row_prints_a_shared_episode_as_text() {
        use crate::ui::sanitize::is_unsafe;
        const OSC52: &str = "\x1b]52;c;aGk=\x07";
        let mut ep = recorded();
        ep.id = format!("id{OSC52}");
        ep.env.os = format!("os\u{202e}{OSC52}");
        ep.source = episode::EpisodeSource::Lab {
            scenario: OSC52.into(),
            seed: 1,
        };
        let key = ep.issue_keys().remove(0);
        ep.labels.push(Label {
            issue: key,
            cause: OSC52.into(),
            source: LabelSource::Lab,
            ts: ep.ended.clone(),
            note: None,
        });
        let rows = decisions(&ep);
        assert!(!rows.is_empty());
        for row in &rows {
            let csv = csv_row(row);
            assert!(csv.starts_with("id·]52;c;aGk=·,lab:·]52"), "{csv:?}");
            assert!(!csv.chars().any(is_unsafe), "{csv:?}");
        }
    }

    #[test]
    fn features_round_trip_through_a_saved_episode() {
        let ep = recorded();
        let dir = std::env::temp_dir().join(format!("nw-features-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = episode::save(&dir, &ep).unwrap();
        let back = episode::load(&path).unwrap();
        let a: Vec<String> = decisions(&ep).iter().map(csv_row).collect();
        let b: Vec<String> = decisions(&back).iter().map(csv_row).collect();
        assert_eq!(a, b);
        let out = dir.join("features.csv");
        let schema = dir.join("schema.json");
        command(&[
            "--out".into(),
            out.to_string_lossy().into(),
            "--schema".into(),
            schema.to_string_lossy().into(),
            dir.to_string_lossy().into(),
        ])
        .unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert_eq!(text.lines().count(), 1 + a.len());
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&schema).unwrap()).unwrap();
        assert_eq!(json["hash"], schema_hash());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
