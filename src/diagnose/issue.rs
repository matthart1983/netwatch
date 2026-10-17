//! The `Issue` object: one source of truth for the Diagnose tab, the verdict
//! line on every other tab, the timeline event, and the exported report.
//!
//! The rule the whole module is built around: **if the screen and the report
//! are generated from the same object they cannot disagree.** Nothing here
//! stores a pre-rendered sentence containing a number. Every ratio, delta and
//! multiple shown to a user is computed from [`Evidence`] at render time by
//! the helpers on these types, so a report can never claim "100×" while the
//! evidence says 33×.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable identifier, `YYYY-MMDD-NN`. Assigned by the engine in the order
/// issues first opened within a session.
pub type IssueId = String;

/// Which rule in the catalogue fired, e.g. `dns.slow_resolver`. Rule ids are
/// stable strings because they appear in user rulesets and exported reports.
pub type RuleId = &'static str;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Medium => "med",
            Severity::High => "high",
            Severity::Critical => "crit",
        }
    }

    /// Long form for the report, where column width isn't a constraint.
    pub fn long_label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Info is an Observation; Medium and up are Issues.
    pub fn kind(self) -> Kind {
        match self {
            Severity::Info => Kind::Observation,
            Severity::Medium | Severity::High | Severity::Critical => Kind::Issue,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.long_label())
    }
}

/// Whether a finding says something is wrong or only something worth knowing.
///
/// An Issue is a fault: the verdict line counts it, and it can hide the
/// findings it explains. An Observation, such as a symmetric NAT or a route
/// change that added 20 ms or less, or whose added latency was not measured,
/// is listed with the findings, but the verdict line does not count it and it
/// never hides an Issue.
///
/// Derived from [`Severity`], never stored, so the two cannot disagree and a
/// recording that says "info" loads as an Observation. `diagnose run` writes
/// it beside each finding it reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Observation,
    Issue,
}

/// What the issue is about. Drives drill-through (`t` trace, `p` packets) and
/// the scope line, and is what the suppression graph matches on when deciding
/// whether one issue is a consequence of another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Subject {
    /// The host itself — no narrower subject applies.
    Host,
    /// One attributed public destination; process identity is name-scoped.
    Egress {
        process: String,
        destination: String,
        port: u16,
    },
    Resolver {
        addr: String,
    },
    Path {
        target: String,
    },
    Socket {
        local: String,
        remote: String,
    },
    Iface {
        name: String,
    },
    Process {
        name: String,
        pid: Option<u32>,
    },
    /// A developer target from `[[diagnose_targets]]`, by its configured name.
    Target {
        name: String,
    },
}

impl Subject {
    /// One-line rendering used in issue titles and the report.
    pub fn label(&self) -> String {
        match self {
            Subject::Host => "host".to_string(),
            Subject::Egress {
                process,
                destination,
                port,
            } => format!("{process} → {destination}:{port}"),
            Subject::Resolver { addr } => addr.clone(),
            Subject::Path { target } => target.clone(),
            Subject::Socket { local, remote } => format!("{local} → {remote}"),
            Subject::Iface { name } => name.clone(),
            Subject::Process { name, pid } => match pid {
                Some(p) => format!("{name}[{p}]"),
                None => name.clone(),
            },
            Subject::Target { name } => name.clone(),
        }
    }

    /// Traceable subjects get a `t` key; the rest don't.
    pub fn trace_target(&self) -> Option<&str> {
        match self {
            Subject::Resolver { addr } => Some(addr),
            Subject::Path { target } => Some(target),
            Subject::Socket { remote, .. } => Some(remote),
            _ => None,
        }
    }
}

/// A measurement that justifies the issue. Carries the *numbers*, never a
/// sentence — sentences are rendered from these so screen and report agree.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Metric name as the rest of netwatch knows it, e.g. `dns.rtt_p50`.
    pub metric: String,
    pub value: f64,
    /// Unit suffix for display: "ms", "%", "/min", "" …
    pub unit: String,
    /// Learned baseline for this metric on this subject, when one exists.
    pub baseline: Option<f64>,
    /// Standard deviation of the baseline. Present iff `baseline` is.
    pub sigma: Option<f64>,
    /// Seconds of data the value summarises.
    pub window_secs: u64,
    /// How many samples went into `value`.
    pub samples: u32,
}

impl Evidence {
    pub fn new(metric: impl Into<String>, value: f64, unit: impl Into<String>) -> Self {
        Self {
            metric: metric.into(),
            value,
            unit: unit.into(),
            baseline: None,
            sigma: None,
            window_secs: 0,
            samples: 0,
        }
    }

    pub fn with_baseline(mut self, baseline: f64, sigma: f64) -> Self {
        self.baseline = Some(baseline);
        self.sigma = Some(sigma);
        self
    }

    pub fn with_window(mut self, window_secs: u64, samples: u32) -> Self {
        self.window_secs = window_secs;
        self.samples = samples;
        self
    }

    /// How many σ above baseline the value sits. `None` without a baseline, or
    /// when σ is zero (a metric that has never varied can't be scored in σ).
    pub fn sigma_above(&self) -> Option<f64> {
        match (self.baseline, self.sigma) {
            (Some(b), Some(s)) if s > f64::EPSILON => Some((self.value - b) / s),
            _ => None,
        }
    }

    /// Multiple of baseline, e.g. 33.3 for 40ms against a 1.2ms baseline.
    /// This is the *only* place a "N×" figure is produced. Screen and report
    /// both call it, so they cannot print different multiples for one issue.
    pub fn multiple_of_baseline(&self) -> Option<f64> {
        match self.baseline {
            Some(b) if b.abs() > f64::EPSILON => Some(self.value / b),
            _ => None,
        }
    }

    /// `"33× baseline"` — rounded the way the UI shows it, with a shared
    /// rounding rule so 33.3 never renders as "33×" here and "33.3×" there.
    pub fn multiple_label(&self) -> Option<String> {
        self.multiple_of_baseline().map(|m| {
            if m >= 10.0 {
                format!("{}× baseline", m.round() as i64)
            } else {
                format!("{m:.1}× baseline")
            }
        })
    }

    /// `"40ms"` — value with its unit, at the precision the magnitude warrants.
    pub fn value_label(&self) -> String {
        format!("{}{}", round_for_display(self.value), self.unit)
    }

    /// `"baseline 1.2ms σ0.4"`, or `None` when the metric has no baseline yet.
    pub fn baseline_label(&self) -> Option<String> {
        let b = self.baseline?;
        match self.sigma {
            Some(s) => Some(format!(
                "baseline {}{} σ{}",
                round_for_display(b),
                self.unit,
                round_for_display(s)
            )),
            None => Some(format!("baseline {}{}", round_for_display(b), self.unit)),
        }
    }
}

/// Display rounding shared by every renderer: three significant-ish figures,
/// no trailing `.0`. Centralised so the same number never appears with two
/// different precisions on one screen.
pub fn round_for_display(v: f64) -> String {
    let a = v.abs();
    // Three-ish significant figures: whole numbers past 100 (184ms), one
    // decimal in the middle (1.2ms), two below one (0.42ms).
    let s = if a >= 100.0 {
        format!("{v:.0}")
    } else if a >= 1.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.2}")
    };
    // 40.0 → 40, 1.20 → 1.2
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

/// Why a rule input, or a single check, has nothing to say. Coverage uses it
/// per rule; a check that did not run carries one as its `why_not`, so the
/// reason is one of these words rather than whatever a call site wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    Learning,
    NotMeasured,
    Unsupported,
    Stale,
    NotConfigured,
    NoSubjects,
    NotApplicable,
    AwaitingTest,
    PermissionDenied,
    CollectorFailed,
    NotImplemented,
    #[serde(other)]
    Unknown,
}

impl Availability {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Available => "ready",
            Self::Learning => "learning",
            Self::NotMeasured => "not measured",
            Self::Unsupported => "unsupported",
            Self::Stale => "stale",
            Self::NotConfigured => "not configured",
            Self::NoSubjects => "no subjects",
            Self::NotApplicable => "not applicable",
            Self::AwaitingTest => "awaiting test",
            Self::PermissionDenied => "permission denied",
            Self::CollectorFailed => "collector failed",
            Self::NotImplemented => "not implemented",
            Self::Unknown => "unknown",
        }
    }
}

/// What became of one check: `passed` as a word, which the JSON carries as
/// `state` in its place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    Passed,
    Failed,
    NotRun,
}

impl CheckState {
    fn passed(self) -> Option<bool> {
        match self {
            CheckState::Passed => Some(true),
            CheckState::Failed => Some(false),
            CheckState::NotRun => None,
        }
    }
}

/// One discriminating test that ranks a cause. `passed: None` means the check
/// could not be run (no data, no capability) — which is different from failing
/// and must not count against the cause — and `why_not` then says which.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(into = "CheckWire", from = "CheckWire")]
pub struct CheckResult {
    /// Stable snake_case identity, unique within its cause. Labels, features
    /// and recorded episodes key on this, never on `name`, so rewording a
    /// check for the screen doesn't orphan the data collected under it.
    pub id: String,
    pub name: String,
    pub passed: Option<bool>,
    /// Set exactly when `passed` is `None`. [`CheckResult::not_run`] is the
    /// one constructor for such a check, so a call site cannot leave it out,
    /// and `detect` asserts it in debug builds.
    pub why_not: Option<Availability>,
    /// Short factual detail, e.g. "alt resolver 1.1.1.1 answered in 1.4ms".
    pub detail: String,
    /// Relative importance within the cause. Defaults to 1.0.
    pub weight: f64,
}

/// A check as it is written and read. It is written with `state` and no
/// `passed`, as `diagnose run`'s schema 2 has it; reading takes either, so
/// records made before `state` and `why_not` existed still load.
#[derive(Serialize, Deserialize)]
struct CheckWire {
    #[serde(default)]
    id: String,
    name: String,
    #[serde(default, skip_serializing)]
    passed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<CheckState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    why_not: Option<Availability>,
    detail: String,
    #[serde(default = "one")]
    weight: f64,
}

impl From<CheckResult> for CheckWire {
    fn from(c: CheckResult) -> Self {
        Self {
            state: Some(c.state()),
            id: c.id,
            name: c.name,
            passed: c.passed,
            why_not: c.why_not,
            detail: c.detail,
            weight: c.weight,
        }
    }
}

impl From<CheckWire> for CheckResult {
    fn from(w: CheckWire) -> Self {
        let passed = w.state.map_or(w.passed, CheckState::passed);
        Self {
            id: w.id,
            name: w.name,
            passed,
            // A check recorded before `why_not` existed kept its reason in
            // `detail` only, so the word for it is Unknown.
            why_not: passed
                .is_none()
                .then(|| w.why_not.unwrap_or(Availability::Unknown)),
            detail: w.detail,
            weight: w.weight,
        }
    }
}

fn one() -> f64 {
    1.0
}

impl CheckResult {
    pub fn pass(id: &str, name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            id: id.to_string(),
            name: name.into(),
            passed: Some(true),
            why_not: None,
            detail: detail.into(),
            weight: 1.0,
        }
    }

    pub fn fail(id: &str, name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            id: id.to_string(),
            name: name.into(),
            passed: Some(false),
            why_not: None,
            detail: detail.into(),
            weight: 1.0,
        }
    }

    /// Check couldn't run. Neither evidence for nor against, and `why_not`
    /// says whether that is a missing probe, a missing sample, a test the
    /// user has not run, or a check that does not apply here.
    pub fn not_run(
        id: &str,
        name: impl Into<String>,
        why_not: Availability,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: id.to_string(),
            name: name.into(),
            passed: None,
            why_not: Some(why_not),
            detail: detail.into(),
            weight: 1.0,
        }
    }

    pub fn state(&self) -> CheckState {
        match self.passed {
            Some(true) => CheckState::Passed,
            Some(false) => CheckState::Failed,
            None => CheckState::NotRun,
        }
    }

    pub fn weighted(mut self, weight: f64) -> Self {
        self.weight = weight;
        self
    }

    /// Whether this check is the one that tells the cause apart from its
    /// lookalikes, rather than a symptom several causes share.
    ///
    /// Weight carries that meaning already: a detector gives a check extra
    /// weight precisely when it discriminates — the loaded/idle comparison
    /// that places a queue, the corroborating internet probe behind a
    /// gateway verdict, whether the destination answered a trace. Deriving it
    /// from weight keeps one source of truth instead of a second flag that
    /// can disagree with the first.
    pub fn is_discriminating(&self) -> bool {
        self.weight >= DISCRIMINATING_WEIGHT
    }

    pub fn glyph(&self) -> &'static str {
        match self.passed {
            Some(true) => "✓",
            Some(false) => "✗",
            None => "·",
        }
    }
}

/// The weight at which a check counts as the cause's discriminator rather
/// than a shared symptom. Detectors already use 2.0 and 3.0 for exactly that.
pub const DISCRIMINATING_WEIGHT: f64 = 2.0;

/// How well a cause's checks held up. Deliberately four buckets and not a
/// percentage: the underlying number is a weighted check-pass fraction, not a
/// calibrated probability, and printing "92%" invites people to read it as
/// one. Ranking still uses the continuous score; only the *display* is coarse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// No check for this cause could be run.
    Untested,
    Weak,
    Possible,
    Likely,
    Strong,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Untested => "untested",
            Confidence::Weak => "weak",
            Confidence::Possible => "possible",
            Confidence::Likely => "likely",
            Confidence::Strong => "strong",
        }
    }
}

/// A ranked explanation for an issue, with the checks that put it there.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cause {
    /// Stable snake_case identity, unique within its rule. The full key is
    /// [`Cause::key`]; labels can be built at runtime ("hop 3 is dropping
    /// traffic") and are for display only.
    #[serde(default)]
    pub id: String,
    pub label: String,
    pub checks: Vec<CheckResult>,
}

impl Cause {
    pub fn new(id: &str, label: impl Into<String>, checks: Vec<CheckResult>) -> Self {
        Self {
            id: id.to_string(),
            label: label.into(),
            checks,
        }
    }

    /// `"dns.slow_resolver/upstream_slow"` — what labels and model classes use.
    pub fn key(&self, rule: &str) -> String {
        format!("{rule}/{}", self.id)
    }

    /// True when `id` is non-empty snake_case: lowercase ascii, digits and
    /// single underscores, starting with a letter.
    pub fn valid_id(id: &str) -> bool {
        id.starts_with(|c: char| c.is_ascii_lowercase())
            && !id.ends_with('_')
            && !id.contains("__")
            && id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    }

    /// Weighted fraction of *runnable* checks that passed, 0..=1.
    /// `None` when no check could be run.
    pub fn score(&self) -> Option<f64> {
        let mut total = 0.0;
        let mut passed = 0.0;
        for c in &self.checks {
            match c.passed {
                Some(true) => {
                    total += c.weight;
                    passed += c.weight;
                }
                Some(false) => total += c.weight,
                None => {}
            }
        }
        if total <= f64::EPSILON {
            None
        } else {
            Some(passed / total)
        }
    }

    /// A discriminating check that could not be run. The cause may still be
    /// the right answer; what is missing is the measurement that would tell
    /// it apart from its lookalikes.
    pub fn missing_discriminator(&self) -> Option<&CheckResult> {
        self.checks
            .iter()
            .find(|c| c.passed.is_none() && c.is_discriminating())
    }

    /// What makes this cause's support sufficient: the discriminating checks
    /// that actually passed. Empty when nothing discriminating ran, which is
    /// why such a cause cannot be Strong.
    pub fn sufficient_evidence(&self) -> Vec<&str> {
        self.checks
            .iter()
            .filter(|c| c.passed == Some(true) && c.is_discriminating())
            .map(|c| c.name.as_str())
            .collect()
    }

    pub fn confidence(&self) -> Confidence {
        let Some(s) = self.score() else {
            return Confidence::Untested;
        };
        let level = if s >= 0.85 {
            Confidence::Strong
        } else if s >= 0.6 {
            Confidence::Likely
        } else if s >= 0.3 {
            Confidence::Possible
        } else {
            Confidence::Weak
        };
        // A pass fraction says how the runnable checks went; it says nothing
        // about the check that did not run. One shared symptom passing while
        // the discriminator is skipped scored 1.0 and printed "strong",
        // which is the claim this cap exists to prevent.
        //
        // Strong therefore needs one of two things: every check ran, so
        // nothing is outstanding, or a discriminating check passed and can be
        // named as the reason. Either way the claim can say what supports it.
        let complete = self.checks.iter().all(|c| c.passed.is_some());
        if level == Confidence::Strong
            && (self.missing_discriminator().is_some()
                || (!complete && self.sufficient_evidence().is_empty()))
        {
            return Confidence::Likely;
        }
        level
    }

    /// `"3 of 4 checks"` — the honest denominator, excluding skipped checks.
    pub fn checks_label(&self) -> String {
        let run = self.checks.iter().filter(|c| c.passed.is_some()).count();
        let passed = self
            .checks
            .iter()
            .filter(|c| c.passed == Some(true))
            .count();
        let skipped = self.checks.len() - run;
        if skipped > 0 {
            format!("{passed} of {run} checks ({skipped} not run)")
        } else {
            format!("{passed} of {run} checks")
        }
    }
}

/// Privilege a remediation step needs before netwatch will offer to apply it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    None,
    Root,
    CapNetAdmin,
}

impl Capability {
    pub fn label(self) -> &'static str {
        match self {
            Capability::None => "no privileges",
            Capability::Root => "root",
            Capability::CapNetAdmin => "CAP_NET_ADMIN",
        }
    }
}

/// What netwatch would actually do for an `Apply` step. Anything that mutates
/// host state names the file it touches so the journal can back it up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// Request a resolver change. TUI apply remains disabled; the explicit Linux
    /// authority command supports only confirmed unmanaged regular files.
    SetResolver { addr: String },
    /// Persist the resolver through the system's resolver manager.
    /// Not reversible by netwatch — it's an instruct step for that reason.
    PersistResolver { addr: String },
    /// Re-run the diagnose pipeline (or one stage of it).
    RunTest { stage: String },
    /// Drop a socket. Reversible only in the sense that it's not persistent.
    KillSocket { local: String, remote: String },
    /// Keep the issue open and re-evaluate after `secs`.
    Watch { secs: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    /// netwatch performs it, key-bound.
    Apply,
    /// Exact command or setting for the operator to run.
    Instruct,
    /// What to send to whom, with artifacts attached.
    Escalate,
}

/// Outcome of an apply, recorded on the step so the report can state it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Applied {
    /// Applied at this local timestamp, with before/after for the report.
    Yes {
        at: String,
        before: String,
        after: String,
    },
    /// Deliberately not applied. Carries the reason, e.g. "needs root".
    No { reason: String },
    /// Applied and then reverted (by the user, on quit, or by reconciliation).
    Reverted { at: String, reason: String },
    /// A write was attempted but its completion or recording failed.
    RecoveryRequired {
        operation_id: String,
        reason: String,
        backup: String,
    },
}

impl Applied {
    /// Shared wording for persistent UI details, status, and reports.
    pub fn recovery_summary(&self) -> Option<String> {
        match self {
            Self::RecoveryRequired {
                operation_id,
                reason,
                backup,
            } => Some(format!(
                "recovery required · {operation_id}: {reason}; backup: {backup}"
            )),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    /// Hotkey when netwatch can apply it. `None` for instruct/escalate steps.
    pub key: Option<char>,
    pub text: String,
    /// Second line: exactly what netwatch would do, or the literal command.
    pub detail: String,
    pub kind: StepKind,
    pub action: Option<Action>,
    /// netwatch keeps a backup and can put it back.
    pub reversible: bool,
    pub requires: Capability,
    #[serde(default)]
    pub applied: Option<Applied>,
}

impl Step {
    pub fn instruct(text: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            key: None,
            text: text.into(),
            detail: detail.into(),
            kind: StepKind::Instruct,
            action: None,
            reversible: false,
            requires: Capability::None,
            applied: None,
        }
    }

    pub fn escalate(text: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind: StepKind::Escalate,
            ..Self::instruct(text, detail)
        }
    }

    pub fn apply(
        key: char,
        text: impl Into<String>,
        detail: impl Into<String>,
        action: Action,
        requires: Capability,
    ) -> Self {
        Self {
            key: Some(key),
            text: text.into(),
            detail: detail.into(),
            kind: StepKind::Apply,
            action: Some(action),
            reversible: true,
            requires,
            applied: None,
        }
    }

    /// Apply steps are hidden — not greyed — when the capability is missing.
    /// The reason still reaches the report, so a reader can tell the
    /// difference between "we didn't try" and "there was nothing to try".
    pub fn available(&self, have: Capability) -> bool {
        match self.requires {
            Capability::None => true,
            Capability::Root => have == Capability::Root,
            Capability::CapNetAdmin => matches!(have, Capability::Root | Capability::CapNetAdmin),
        }
    }
}

/// The testable condition that closes an issue. Mandatory: §4's rule is that a
/// remediation without a verify condition is an instruct step, not an apply
/// step, and [`crate::diagnose::rules`] enforces it in a test.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verify {
    /// Metric to re-check — matches an [`Evidence::metric`].
    pub metric: String,
    pub predicate: Predicate,
    pub threshold: f64,
    pub unit: String,
    /// Condition must hold for this long before the issue auto-closes.
    pub hold_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    Below,
    Above,
}

impl Verify {
    pub fn below(metric: impl Into<String>, threshold: f64, unit: impl Into<String>) -> Self {
        Self {
            metric: metric.into(),
            predicate: Predicate::Below,
            threshold,
            unit: unit.into(),
            hold_secs: 60,
        }
    }

    pub fn above(metric: impl Into<String>, threshold: f64, unit: impl Into<String>) -> Self {
        Self {
            predicate: Predicate::Above,
            ..Self::below(metric, threshold, unit)
        }
    }

    pub fn holding_for(mut self, secs: u64) -> Self {
        self.hold_secs = secs;
        self
    }

    pub fn holds(&self, value: f64) -> bool {
        match self.predicate {
            Predicate::Below => value < self.threshold,
            Predicate::Above => value > self.threshold,
        }
    }

    /// `"dns.rtt_p50 < 5ms for 60s"`.
    pub fn label(&self) -> String {
        let op = match self.predicate {
            Predicate::Below => "<",
            Predicate::Above => ">",
        };
        format!(
            "{} {} {}{} for {}s",
            self.metric,
            op,
            round_for_display(self.threshold),
            self.unit,
            self.hold_secs
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum IssueState {
    Open,
    Acked,
    /// Muted until this local timestamp.
    Muted {
        until: String,
    },
    Resolved {
        at: String,
    },
    /// The verify condition held for its window: netwatch watched it clear.
    AutoClosed {
        at: String,
    },
    /// Closed because what the issue is about went away, such as a socket
    /// that closed, not because anything measured it recover. An expiry is
    /// never a recovery and never credits a step.
    ///
    /// `reason` is an authored phrase ("socket closed"), never a host,
    /// address or target name: redacted exports keep a state verbatim.
    Expired {
        at: String,
        reason: String,
    },
}

impl IssueState {
    pub fn is_open(&self) -> bool {
        matches!(self, IssueState::Open | IssueState::Acked)
    }

    /// Open, acknowledged or muted: the engine still watches it. A muted
    /// issue is only quiet. Its condition merges into it, its verify can close
    /// it and its subject can expire it, so it is not closed, and nothing may
    /// file the same condition as a second issue while it lasts.
    pub fn is_tracked(&self) -> bool {
        self.is_open() || matches!(self, IssueState::Muted { .. })
    }

    /// When a mute ends, for a muted issue.
    pub fn muted_until(&self) -> Option<&str> {
        match self {
            IssueState::Muted { until } => Some(until),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            IssueState::Open => "open",
            IssueState::Acked => "acked",
            IssueState::Muted { .. } => "muted",
            IssueState::Resolved { .. } => "resolved",
            IssueState::AutoClosed { .. } => "auto-closed",
            IssueState::Expired { .. } => "expired",
        }
    }
}

/// What the issue touches. Rendered as the `scope` line.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Scope {
    /// Opaque configured-target revision; changing endpoints is not recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<String>,
    pub processes: Vec<String>,
    pub destinations: u32,
    pub flows: u32,
    /// The interface this finding's traffic actually used, when it is known.
    ///
    /// Suppression reads it: a link or gateway failure on eth0 explains
    /// nothing about a target reached over wg0, and demoting that target to a
    /// consequence hides a second, unrelated fault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_iface: Option<String>,
    /// The resolver this finding's lookups actually used, when it is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_resolver: Option<String>,
    /// Whether process attribution was attempted for this finding.
    ///
    /// An empty `processes` means two different things: a host-wide fault
    /// that really does affect everything, or an attribution that failed. It
    /// used to render as "all processes" either way, which turns a missing
    /// measurement into a claim about the whole machine.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub processes_measured: bool,
    /// Free-text qualifier, e.g. "not affecting established flows".
    pub note: Option<String>,
}

impl Scope {
    /// `"all processes · 6 destinations · not affecting established flows"`.
    pub fn label(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.processes.is_empty() {
            parts.push(if self.processes_measured {
                "process not identified".to_string()
            } else {
                "all processes".to_string()
            });
        } else if self.processes.len() <= 3 {
            parts.push(self.processes.join(", "));
        } else {
            parts.push(format!("{} processes", self.processes.len()));
        }
        if self.destinations > 0 {
            parts.push(format!(
                "{} destination{}",
                self.destinations,
                if self.destinations == 1 { "" } else { "s" }
            ));
        }
        if self.flows > 0 {
            parts.push(format!(
                "{} flow{}",
                self.flows,
                if self.flows == 1 { "" } else { "s" }
            ));
        }
        if let Some(n) = &self.note {
            parts.push(n.clone());
        }
        parts.join(" · ")
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Issue {
    pub id: IssueId,
    pub rule: String,
    pub severity: Severity,
    pub title: String,
    pub subject: Subject,
    /// Local timestamp of the first sample that violated the rule.
    pub since: String,
    pub last_seen: String,
    /// Local timestamp from which this open issue's evidence stopped arriving:
    /// its rule's input went unavailable or its verify metric went missing.
    /// Set once, and cleared when the condition is detected again or the
    /// metric returns. An issue nothing can measure stays open rather than
    /// expiring, and this says since when. It is also set while a subject
    /// that has gone waits out `expire_after_secs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_since: Option<String>,
    /// Opened by a beta rule ([`super::rules::Rule::beta`]). Copied when the
    /// issue opens, so a later contract review does not rewrite history.
    #[serde(default)]
    pub beta: bool,
    pub state: IssueState,
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub scope: Scope,
    pub causes: Vec<Cause>,
    pub remediation: Vec<Step>,
    /// Fixed when the issue opens or reopens; later detections of the same
    /// condition do not move it.
    pub verify: Verify,
    #[serde(default)]
    pub artifacts: Vec<String>,
    /// Issues suppressed by this one — consequences of the same root cause.
    /// They are reported *under* this issue, never as separate findings.
    #[serde(default)]
    pub consequences: Vec<IssueId>,
    /// Set when this issue is itself suppressed by another.
    #[serde(default)]
    pub suppressed_by: Option<IssueId>,
    /// Times this issue has reopened within the recurrence window. A flapping
    /// condition is one issue with a count, not N issues.
    #[serde(default)]
    pub recurrence: u32,
    /// Discriminating tests run against this issue, oldest first.
    #[serde(default)]
    pub tests: Vec<super::next_test::TestRun>,
    /// Set when the user says they carried out a step; tracks whether it
    /// worked.
    #[serde(default)]
    pub verification: Option<Verification>,
}

/// What became of an issue after the user acted on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyOutcome {
    /// Closed, and no re-run test still points at the cause.
    Recovered,
    /// The headline recovered but a re-run test still points at the cause,
    /// or it was still settling when time ran out.
    Partial,
    NotRecovered,
    /// It was already recovering before the step; the step gets no credit.
    RecoveredBeforeAction,
    /// An operator closed the issue by hand. Nothing was measured, so this is
    /// not evidence that the step worked — or that the fault is gone.
    ClosedByOperator,
    /// The issue expired: what it was about went away before its verify
    /// condition held, so nothing measured whether the step worked.
    NotMeasured,
}

impl VerifyOutcome {
    pub fn label(self) -> &'static str {
        match self {
            VerifyOutcome::Recovered => "recovered",
            VerifyOutcome::Partial => "partly recovered",
            VerifyOutcome::NotRecovered => "not recovered",
            VerifyOutcome::RecoveredBeforeAction => "was already recovering",
            VerifyOutcome::ClosedByOperator => "closed by hand, not measured",
            VerifyOutcome::NotMeasured => "closed without a measurement",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verification {
    /// Index of the remediation step the user carried out.
    pub step: usize,
    pub action_at: String,
    /// The verify condition was already holding when they acted.
    pub holding_at_action: bool,
    /// `rule/cause` that was on top when they acted.
    pub top_cause: Option<String>,
    /// Tests whose last answer supported that cause; re-run to confirm.
    pub supporting: Vec<String>,
    pub outcome: Option<VerifyOutcome>,
    pub decided_at: Option<String>,
}

/// The identity a finding is merged, confirmed, reopened and named under:
/// `rule|subject`, and for a configured target `rule|name|revision`.
///
/// A target's revision digests every field of its `[[diagnose_targets]]`
/// entry, so an edited entry probes a different endpoint, or the same one a
/// different way. Keyed by name alone, its detections merged into the old
/// entry's issue, which then never expired and lent the edited target its
/// mute, applied steps and close condition. A target finding with no
/// revision, as in recordings made before targets had one, keeps
/// `rule|name`. Live probes always carry one.
pub fn finding_key(rule: &str, subject: &Subject, configuration: Option<&str>) -> String {
    match (subject, configuration) {
        (Subject::Target { name }, Some(revision)) => format!("{rule}|{name}|{revision}"),
        _ => format!("{rule}|{}", subject.label()),
    }
}

impl Issue {
    /// See [`finding_key`].
    pub fn key(&self) -> String {
        finding_key(
            &self.rule,
            &self.subject,
            self.scope.configuration.as_deref(),
        )
    }

    /// Issue or Observation, from the severity the detector settled on. A
    /// detector that demotes a finding to Info at runtime makes it an
    /// Observation with no further code.
    pub fn kind(&self) -> Kind {
        self.severity.kind()
    }

    /// The evidence entry a rule considers primary — by convention the first.
    /// Titles and one-line summaries quote this one.
    pub fn headline(&self) -> Option<&Evidence> {
        self.evidence.first()
    }

    /// Highest-ranked cause. Causes are stored pre-sorted by the engine.
    pub fn top_cause(&self) -> Option<&Cause> {
        self.causes.first()
    }

    /// Sort causes best-first. Untestable causes sink below tested ones so a
    /// cause nothing could rule out never outranks one with passing checks.
    /// Order causes by how well the evidence supports them: confidence
    /// first, so a cause whose discriminator never ran cannot outrank one
    /// that was actually measured, then the pass fraction within a level.
    pub fn rank_causes(&mut self) {
        self.causes.sort_by(|a, b| {
            let sa = a.score().unwrap_or(-1.0);
            let sb = b.score().unwrap_or(-1.0);
            b.confidence()
                .cmp(&a.confidence())
                .then(sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal))
        });
    }

    /// One-line summary: severity, title, subject, and the headline number
    /// with its multiple of baseline. This is the string the toast shows, `y`
    /// copies, the verdict line renders and the report's summary quotes —
    /// one function, so all four agree by construction.
    pub fn summary_line(&self) -> String {
        let mut s = format!("{} {}", self.severity.long_label(), self.title);
        let subject = self.subject.label();
        if !subject.is_empty() && subject != "host" {
            s.push_str(&format!(" · {subject}"));
        }
        if let Some(e) = self.headline() {
            s.push_str(&format!(" · {}", e.value_label()));
            if let Some(m) = e.multiple_label() {
                s.push_str(&format!(" ({m})"));
            }
        }
        s.push_str(&format!(" · since {}", short_time(&self.since)));
        s
    }

    /// Steps netwatch can actually offer given the privileges it holds.
    pub fn offered_steps(&self, have: Capability) -> Vec<&Step> {
        self.remediation
            .iter()
            .filter(|s| s.kind != StepKind::Apply || s.available(have))
            .collect()
    }
}

/// `189` → `"3m 9s"`. One renderer, used by the tab and the report, because
/// the same evidence field showing as `189s` on screen and `3m` in the export
/// is exactly the sort of small disagreement this module exists to prevent.
pub fn format_duration(secs: u64) -> String {
    match (secs / 3600, (secs % 3600) / 60, secs % 60) {
        (0, 0, s) => format!("{s}s"),
        (0, m, 0) => format!("{m}m"),
        (0, m, s) => format!("{m}m {s}s"),
        (h, 0, _) => format!("{h}h"),
        (h, m, _) => format!("{h}h {m}m"),
    }
}

/// `"2026-09-03 06:48:10"` → `"06:48:10"`. Reports keep the full stamp; the
/// TUI has 80 columns and shows the time only.
pub fn short_time(ts: &str) -> &str {
    ts.split(' ').next_back().unwrap_or(ts)
}

/// `"2026-09-03 06:48:10"` → `"06:48"`, for a column or a status line with no
/// room for seconds.
pub fn hh_mm(ts: &str) -> String {
    short_time(ts).chars().take(5).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_evidence() -> Evidence {
        // The exact numbers from the handover fixture: 40ms observed against a
        // 1.2ms baseline. The bundle's mockup called this "100×".
        Evidence::new("dns.rtt_p50", 40.0, "ms")
            .with_baseline(1.2, 0.4)
            .with_window(180, 38)
    }

    #[test]
    fn multiple_of_baseline_is_computed_not_asserted() {
        let e = dns_evidence();
        let m = e.multiple_of_baseline().unwrap();
        assert!(
            (m - 33.333).abs() < 0.01,
            "40/1.2 is 33.3×, not 100× — got {m}"
        );
        assert_eq!(e.multiple_label().unwrap(), "33× baseline");
    }

    #[test]
    fn sigma_above_matches_the_rule_threshold() {
        let e = dns_evidence();
        // (40 - 1.2) / 0.4 = 97σ. Far past the k=3 trigger.
        assert!(e.sigma_above().unwrap() > 3.0);
    }

    #[test]
    fn sigma_is_none_when_baseline_never_varied() {
        let e = Evidence::new("x", 5.0, "ms").with_baseline(1.0, 0.0);
        assert_eq!(e.sigma_above(), None, "zero σ must not divide by zero");
        // A multiple is still meaningful without variance.
        assert_eq!(e.multiple_of_baseline(), Some(5.0));
    }

    #[test]
    fn durations_render_the_same_everywhere() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(189), "3m 9s");
        assert_eq!(format_duration(180), "3m");
        assert_eq!(format_duration(3600), "1h");
        assert_eq!(format_duration(3900), "1h 5m");
    }

    #[test]
    fn display_rounding_is_stable() {
        assert_eq!(round_for_display(40.0), "40");
        assert_eq!(round_for_display(1.2), "1.2");
        assert_eq!(round_for_display(0.42), "0.42");
        assert_eq!(round_for_display(184.0), "184");
    }

    #[test]
    fn a_check_writes_its_state_not_passed() {
        let json = |c: &CheckResult| serde_json::to_value(c).unwrap();
        let not_run = json(&CheckResult::not_run(
            "alt_resolver_is_fast",
            "alt resolver is fast",
            Availability::NotMeasured,
            "no alternate resolver probed",
        ));
        assert!(not_run.get("passed").is_none(), "{not_run}");
        assert_eq!(not_run["state"], "not_run");
        assert_eq!(not_run["why_not"], "not_measured");
        // A check that ran carries no `why_not`.
        let passed = json(&CheckResult::pass("a", "a", "fine"));
        assert!(passed.get("passed").is_none(), "{passed}");
        assert_eq!(passed["state"], "passed");
        assert!(passed.get("why_not").is_none(), "{passed}");
        assert_eq!(json(&CheckResult::fail("a", "a", ""))["state"], "failed");

        let c = CheckResult::not_run("a", "a", Availability::AwaitingTest, "press t").weighted(2.0);
        let back: CheckResult = serde_json::from_value(json(&c)).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn a_check_recorded_before_why_not_still_loads() {
        let load = |s: &str| serde_json::from_str::<CheckResult>(s).unwrap();
        let old =
            load(r#"{"id":"a","name":"a","passed":null,"detail":"no icmp probe","weight":1.0}"#);
        assert_eq!(old.state(), CheckState::NotRun);
        assert_eq!(old.detail, "no icmp probe");
        // The reason was free text then; the word for it is Unknown, so
        // every check that did not run still says why.
        assert_eq!(old.why_not, Some(Availability::Unknown));
        let ran = load(r#"{"name":"a","passed":false,"detail":""}"#);
        assert_eq!(ran.state(), CheckState::Failed);
        assert_eq!(ran.why_not, None);
        assert_eq!(ran.weight, 1.0);
        // A record that carries `state` alone, as schema 2 writes it, loads too.
        let new = load(r#"{"id":"a","name":"a","state":"passed","detail":""}"#);
        assert_eq!(new.passed, Some(true));
        let new = load(
            r#"{"id":"a","name":"a","state":"not_run","why_not":"awaiting_test","detail":""}"#,
        );
        assert_eq!(new.passed, None);
        assert_eq!(new.why_not, Some(Availability::AwaitingTest));
    }

    #[test]
    fn a_skipped_shared_symptom_does_not_count_against_a_cause() {
        // Skipping a check that several causes share is not evidence against
        // this one, so the pass fraction still reads 1.0 — but with a check
        // outstanding and nothing discriminating to point at, the cause is
        // not strong either.
        let all_pass = Cause::new(
            "all_pass",
            "c",
            vec![
                CheckResult::pass("a", "a", ""),
                CheckResult::pass("b", "b", ""),
                CheckResult::not_run("c", "c", Availability::NotMeasured, "no data"),
            ],
        );
        assert_eq!(all_pass.score(), Some(1.0));
        assert_eq!(all_pass.confidence(), Confidence::Likely);
        assert_eq!(all_pass.checks_label(), "2 of 2 checks (1 not run)");
        assert_eq!(all_pass.sufficient_evidence(), Vec::<&str>::new());
    }

    #[test]
    fn a_missing_discriminator_keeps_a_cause_short_of_strong() {
        // The defect this cap exists for: one shared symptom passes, the
        // check that would separate this cause from its lookalikes never
        // ran, and the ratio alone called that strong.
        let c = Cause::new(
            "receiver_queueing",
            "c",
            vec![
                CheckResult::pass("symptom", "symptom", ""),
                CheckResult::not_run(
                    "discriminator",
                    "discriminator",
                    Availability::AwaitingTest,
                    "no test has run",
                )
                .weighted(2.0),
            ],
        );
        assert_eq!(c.score(), Some(1.0), "a skipped check is not a failure");
        assert_eq!(c.confidence(), Confidence::Likely);
        assert_eq!(
            c.missing_discriminator().map(|k| k.id.as_str()),
            Some("discriminator")
        );
        assert!(c.sufficient_evidence().is_empty());

        // Run it, and the cause can be strong on evidence that names itself.
        let measured = Cause::new(
            "receiver_queueing",
            "c",
            vec![
                CheckResult::pass("symptom", "symptom", ""),
                CheckResult::pass("discriminator", "discriminator", "").weighted(2.0),
            ],
        );
        assert_eq!(measured.confidence(), Confidence::Strong);
        assert_eq!(measured.sufficient_evidence(), vec!["discriminator"]);
    }

    #[test]
    fn strong_needs_either_a_complete_set_of_checks_or_a_named_discriminator() {
        // Everything ran and passed: nothing is outstanding to qualify it.
        let complete = Cause::new(
            "c",
            "c",
            vec![
                CheckResult::pass("a", "a", ""),
                CheckResult::pass("b", "b", ""),
            ],
        );
        assert_eq!(complete.confidence(), Confidence::Strong);

        // A symptom passed, an ordinary check did not, and nothing
        // discriminating spoke for the cause: not strong.
        let partial = Cause::new(
            "c",
            "c",
            vec![
                CheckResult::pass("a", "a", ""),
                CheckResult::not_run("b", "b", Availability::NotMeasured, "no data"),
            ],
        );
        assert_eq!(partial.confidence(), Confidence::Likely);
        assert!(partial.sufficient_evidence().is_empty());
    }

    #[test]
    fn a_measured_cause_outranks_one_whose_discriminator_never_ran() {
        let mut issue = test_issue();
        issue.causes = vec![
            Cause::new(
                "unmeasured",
                "unmeasured",
                vec![
                    CheckResult::pass("symptom", "symptom", ""),
                    CheckResult::not_run("d", "d", Availability::NotMeasured, "").weighted(2.0),
                ],
            ),
            Cause::new(
                "measured",
                "measured",
                vec![
                    CheckResult::pass("symptom", "symptom", ""),
                    CheckResult::pass("d", "d", "").weighted(2.0),
                ],
            ),
        ];
        issue.rank_causes();
        assert_eq!(issue.causes[0].id, "measured");
    }

    #[test]
    fn a_failed_attribution_does_not_read_as_every_process() {
        let host_wide = Scope::default();
        assert!(host_wide.label().contains("all processes"));

        let attempted = Scope {
            processes_measured: true,
            ..Default::default()
        };
        assert!(
            attempted.label().contains("process not identified"),
            "{}",
            attempted.label()
        );
        assert!(!attempted.label().contains("all processes"));
    }

    #[test]
    fn a_cause_with_no_runnable_checks_is_untested_not_certain() {
        let c = Cause::new(
            "c",
            "c",
            vec![CheckResult::not_run(
                "a",
                "a",
                Availability::NotMeasured,
                "no data",
            )],
        );
        assert_eq!(c.score(), None);
        assert_eq!(c.confidence(), Confidence::Untested);
    }

    #[test]
    fn untested_causes_rank_below_tested_ones() {
        let mut issue = test_issue();
        issue.causes = vec![
            Cause::new(
                "untested",
                "untested",
                vec![CheckResult::not_run(
                    "a",
                    "a",
                    Availability::NotMeasured,
                    "",
                )],
            ),
            Cause::new(
                "half",
                "half",
                vec![
                    CheckResult::pass("a", "a", ""),
                    CheckResult::fail("b", "b", ""),
                ],
            ),
        ];
        issue.rank_causes();
        assert_eq!(issue.causes[0].label, "half");
    }

    #[test]
    fn verify_predicates() {
        let v = Verify::below("dns.rtt_p50", 5.0, "ms").holding_for(60);
        assert!(v.holds(1.4));
        assert!(!v.holds(40.0));
        assert_eq!(v.label(), "dns.rtt_p50 < 5ms for 60s");
    }

    #[test]
    fn capability_gating_hides_root_steps_for_unprivileged_runs() {
        let s = Step::apply(
            '1',
            "switch resolver",
            "",
            Action::SetResolver {
                addr: "1.1.1.1".into(),
            },
            Capability::Root,
        );
        assert!(!s.available(Capability::None));
        assert!(s.available(Capability::Root));
        // CAP_NET_ADMIN is satisfied by root but not the other way round.
        let n = Step::apply(
            '1',
            "x",
            "",
            Action::Watch { secs: 1 },
            Capability::CapNetAdmin,
        );
        assert!(n.available(Capability::Root));
        assert!(!n.available(Capability::None));
    }

    #[test]
    fn summary_line_quotes_the_computed_multiple() {
        let issue = test_issue();
        let s = issue.summary_line();
        assert!(s.contains("33× baseline"), "{s}");
        assert!(!s.contains("100×"), "{s}");
        assert!(s.contains("06:48:10"), "{s}");
    }

    fn test_issue() -> Issue {
        Issue {
            id: "2026-0903-01".into(),
            rule: "dns.slow_resolver".into(),
            severity: Severity::High,
            title: "slow dns resolver".into(),
            subject: Subject::Resolver {
                addr: "169.254.1.1".into(),
            },
            since: "2026-09-03 06:48:10".into(),
            last_seen: "2026-09-03 06:51:19".into(),
            stale_since: None,
            beta: false,
            state: IssueState::Open,
            evidence: vec![dns_evidence()],
            scope: Scope::default(),
            causes: vec![],
            remediation: vec![],
            verify: Verify::below("dns.rtt_p50", 5.0, "ms"),
            artifacts: vec![],
            consequences: vec![],
            suppressed_by: None,
            recurrence: 0,
            tests: vec![],
            verification: None,
        }
    }

    #[test]
    fn issue_json_round_trips() {
        let issue = test_issue();
        let json = serde_json::to_string(&issue).unwrap();
        let back: Issue = serde_json::from_str(&json).unwrap();
        assert_eq!(issue, back, "report.json must reload into the same object");
    }

    #[test]
    fn info_is_an_observation_and_everything_else_an_issue() {
        assert_eq!(Severity::Info.kind(), Kind::Observation);
        for sev in [Severity::Medium, Severity::High, Severity::Critical] {
            assert_eq!(sev.kind(), Kind::Issue, "{sev}");
        }

        // The kind is not stored: a finding recorded as "info" loads as an
        // Observation, and one that says "high" as an Issue.
        let issue = test_issue();
        assert_eq!(issue.kind(), Kind::Issue);
        let json = serde_json::to_string(&issue).unwrap();
        assert!(!json.contains("\"kind\":\"issue\""), "{json}");
        let info = json.replace("\"severity\":\"high\"", "\"severity\":\"info\"");
        let back: Issue = serde_json::from_str(&info).unwrap();
        assert_eq!(back.kind(), Kind::Observation);
    }
}
