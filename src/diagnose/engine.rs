//! The evaluator: detections in, a stable `Vec<Issue>` out.
//!
//! Everything a user sees about what is wrong reads from [`Engine::issues`] —
//! the Diagnose tab, the verdict line under the tab bar on every other tab,
//! the timeline events, the toast, and the exported report. There is exactly
//! one list, so those six surfaces cannot disagree with each other.
//!
//! The engine's real job is *continuity*. A resolver that has been slow for an
//! hour is one issue with a growing window, not 3,600 findings; a resolver
//! that flaps every few minutes is one issue with a recurrence count, not
//! twenty. Detectors are stateless and fire every tick — turning that into a
//! stable, human-sized list of findings happens here.

use chrono::{DateTime, Duration, Local, TimeZone};
use std::collections::{HashMap, HashSet};

use super::baseline::{BaselineStore, SigmaFloor};
use super::detectors::{self, Detection, Observations, Thresholds};
use super::issue::{Issue, IssueId, IssueState, Kind, Severity};
use super::rules;

/// Time source. A trait so the fixture and the tests can pin the clock and
/// produce byte-identical reports.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Local>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Local> {
        Local::now()
    }
}

/// A clock frozen at one instant, then advanced by hand.
pub struct FixedClock {
    at: std::sync::Mutex<DateTime<Local>>,
}

impl FixedClock {
    pub fn at(s: &str) -> Self {
        let naive = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
            .expect("fixed clock needs YYYY-MM-DD HH:MM:SS");
        let at = Local
            .from_local_datetime(&naive)
            .single()
            .expect("unambiguous local time");
        Self {
            at: std::sync::Mutex::new(at),
        }
    }

    pub fn advance_secs(&self, secs: i64) {
        let mut g = self.at.lock().unwrap();
        *g += Duration::seconds(secs);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Local> {
        *self.at.lock().unwrap()
    }
}

impl FixedClock {
    /// Move the clock to a recorded timestamp. `false` if it doesn't parse.
    pub fn set(&self, s: &str) -> bool {
        let Some(at) = parse_ts(s) else {
            return false;
        };
        *self.at.lock().unwrap() = at;
        true
    }
}

/// A shared handle, so a caller can keep setting the clock an engine owns.
impl Clock for std::sync::Arc<FixedClock> {
    fn now(&self) -> DateTime<Local> {
        self.as_ref().now()
    }
}

/// The completion time of the collector a rule's evidence comes from.
/// `None` for rules with no single sampling collector; `Some(None)` when the
/// collector exists but hasn't completed.
///
/// `subject` matters for the per-target rules: evidence about one target is
/// not evidence about another, however recently the other was probed.
fn sample_time(
    rule: &str,
    subject: &super::issue::Subject,
    times: &ObservationTimes,
) -> Option<Option<std::time::Instant>> {
    if rule == "ipv6.broken" {
        Some(times.ipv6)
    } else if rule == "captive.portal" {
        Some(times.portal)
    } else if rule == "pmtu.blackhole" {
        Some(times.pmtu)
    } else if matches!(rule, "tcp.connect_failures" | "tcp.timewait_exhaustion") {
        Some(times.kernel)
    } else if rule.starts_with("egress.") {
        Some(times.egress)
    } else if rule.starts_with("dns.") {
        Some(times.health.dns)
    } else if rule.starts_with("gateway.") {
        Some(times.health.gateway)
    } else if rule.starts_with("nat.") {
        Some(times.health.nat)
    } else if rule.starts_with("link.") || rule.starts_with("iface.") || rule.starts_with("wifi.") {
        Some(times.interface)
    } else if rule.starts_with("path.") {
        Some(times.path)
    } else if rule.starts_with("tcp.") && rule != "tcp.bufferbloat_local" {
        Some(times.sockets)
    } else if rule.starts_with("target.") {
        match subject {
            super::issue::Subject::Target { name } => Some(times.targets.get(name).copied()),
            // A target rule filed against something else has no per-target
            // clock to read; treat it as unsampled rather than borrowing
            // another target's.
            _ => Some(None),
        }
    } else {
        None
    }
}

/// Why an open issue's subject has gone away, or `None` while it may still be
/// there. Gone is a positive finding about the subject, never an absence of
/// readings about it: an unmeasured gateway, a stale probe or a collector
/// that did not run leaves the issue open, however long it lasts.
///
/// | Subject | Gone when |
/// |---|---|
/// | Socket | the sockets collector is fresh (≤ 30 s), the rule's coverage is available or has no subjects, and no socket matches |
/// | Target | its name has left the config, or no entry under its name has the revision the issue was found under |
/// | Resolver | it has left the system resolvers, and so has any resolver an applied step switched to |
/// | Path (`path.*`) | it was the periodic trace target while open, periodic tracing is still on, and the trace target is now another |
/// | Iface | the interface collector is fresh (≤ 15 s) and does not read it, and the platform no longer lists it |
/// | Host, anything else, or no recorded config | never |
///
/// The returned reason is authored text, never the subject's name, because
/// redacted exports keep a state verbatim.
fn subject_gone(
    issue: &Issue,
    obs: &Observations,
    coverage: &super::coverage::Coverage,
    live: Option<(&ObservationTimes, std::time::Instant)>,
    periodic_path: bool,
) -> Option<&'static str> {
    use super::coverage::Availability;
    use super::issue::Subject;
    // A recording from before the configuration was recorded, or a frame
    // built without one: unknown, which never expires anything.
    let config = obs.config.as_ref()?;
    let fresh = |at: fn(&ObservationTimes) -> Option<std::time::Instant>, max_secs| {
        live.is_some_and(|(times, now)| {
            crate::collectors::health::ProbeTimes::fresh_at(at(times), max_secs, now)
        })
    };
    match &issue.subject {
        Subject::Socket { local, remote } => {
            // The collector listed every socket it could see, just now.
            let listed = coverage.rules.iter().any(|r| {
                r.rule == issue.rule
                    && matches!(r.status, Availability::Available | Availability::NoSubjects)
            });
            let open = obs
                .sockets
                .iter()
                .any(|s| &s.local == local && &s.remote == remote);
            (fresh(|t| t.sockets, 30) && listed && !open).then_some("socket closed")
        }
        Subject::Target { name } => {
            let mut revisions = config
                .targets
                .iter()
                .filter(|(n, _)| n == name)
                .map(|(_, r)| r)
                .peekable();
            if revisions.peek().is_none() {
                Some("target removed from the config")
            } else if let Some(found) = &issue.scope.configuration {
                // A duplicated name is a config error netwatch reports, and
                // one entry still carrying this revision keeps the subject.
                (!revisions.any(|r| r == found)).then_some("target configuration changed")
            } else {
                None
            }
        }
        Subject::Resolver { addr } => {
            let resolvers = config.resolvers.as_ref()?;
            let listed = |a: &str| resolvers.iter().any(|r| r == a);
            (!listed(addr) && !replacement_resolvers(issue).any(listed))
                .then_some("resolver left the config")
        }
        Subject::Path { target } if issue.rule.starts_with("path.") => {
            (periodic_path && config.trace_refresh_secs.is_some() && &config.trace_target != target)
                .then_some("trace target changed")
        }
        Subject::Iface { name } => {
            // The list lags the collector, and on Windows may name adapters
            // differently, so a fresh reading of the interface keeps it.
            let listed = config.interfaces.as_ref()?.contains(name)
                || obs.iface.as_ref().is_some_and(|i| &i.name == name);
            (!listed && fresh(|t| t.interface, 15)).then_some("interface removed")
        }
        _ => None,
    }
}

/// Resolvers an applied step switched this issue's lookups to. Their results
/// stand in for the original resolver's, so they can verify its issue and
/// keep its subject from counting as gone.
fn replacement_resolvers(issue: &Issue) -> impl Iterator<Item = &str> {
    use super::issue::{Action, Applied};
    issue
        .remediation
        .iter()
        .filter_map(|step| match (&step.action, &step.applied) {
            (Some(Action::SetResolver { addr }), Some(Applied::Yes { .. })) => Some(addr.as_str()),
            _ => None,
        })
}

pub fn format_ts(dt: DateTime<Local>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Parse a `%Y-%m-%d %H:%M:%S` local stamp of the kind every issue carries.
///
/// Public so surfaces that place an event on a time axis measure it against
/// the same clock the engine wrote it with, instead of re-deriving an offset
/// and drifting by a tick.
pub fn parse_ts(s: &str) -> Option<DateTime<Local>> {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .ok()
        .and_then(|n| Local.from_local_datetime(&n).single())
}

/// Whether a mute that ends at `until`, a stamp like [`parse_ts`] reads, is
/// over at `now`. The stamp carries no offset, so in the hour a clock goes
/// back it names two instants, and [`parse_ts`] returns neither. This takes
/// the later: at worst the mute lasts an hour longer, where returning neither
/// ended it on the next tick. A stamp that does not parse has ended: a mute
/// that never ends would hide the issue for good.
fn mute_over<Tz: TimeZone>(until: &str, now: &DateTime<Tz>) -> bool {
    chrono::NaiveDateTime::parse_from_str(until, "%Y-%m-%d %H:%M:%S")
        .ok()
        .and_then(|n| now.timezone().from_local_datetime(&n).latest())
        .is_none_or(|u| u <= *now)
}

/// How long after closing a recurrence reopens the same issue instead of
/// filing a new one. Flapping should read as one problem with a count.
const RECURRENCE_WINDOW_MINS: i64 = 30;

/// Engine settings, all user-tunable.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    pub thresholds: Thresholds,
    /// How long an issue's subject must stay gone before the issue closes as
    /// [`IssueState::Expired`]. Recovery is the verify condition's business
    /// (`Verify::hold_secs`); this is only about absence.
    ///
    /// Episodes recorded before 0.34 call it `auto_close_secs`; nothing read
    /// it then.
    #[serde(alias = "auto_close_secs")]
    pub expire_after_secs: u64,
    /// Closed issues kept for the report and the timeline.
    pub history_limit: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            thresholds: Thresholds::default(),
            expire_after_secs: 60,
            history_limit: 50,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ObservationTimes {
    pub ipv6: Option<std::time::Instant>,
    pub portal: Option<std::time::Instant>,
    pub pmtu: Option<std::time::Instant>,
    pub kernel: Option<std::time::Instant>,
    pub egress: Option<std::time::Instant>,
    pub interface: Option<std::time::Instant>,
    pub health: crate::collectors::health::ProbeTimes,
    pub sockets: Option<std::time::Instant>,
    pub path: Option<std::time::Instant>,
    /// When each developer target last published a result, by configured
    /// name.
    ///
    /// This used to be one `Option<Instant>` holding the newest completion
    /// across all targets, which every `target.*` rule then read. A target
    /// probed every 10s therefore supplied samples for an issue about a
    /// target probed every 5 minutes: it confirmed findings and ran down
    /// recovery holds against a cached result nobody had re-measured.
    pub targets: std::collections::BTreeMap<String, std::time::Instant>,
}

/// Something done to an issue from outside the detection loop: a user action,
/// or (later) a diagnostic test result. Logged so an episode can replay it.
///
/// Events name issues by key ([`super::issue::finding_key`]) rather than
/// id, because a replayed engine numbers its issues independently.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum EngineEvent {
    Acked {
        issue: String,
    },
    Muted {
        issue: String,
        until: String,
    },
    Resolved {
        issue: String,
        at: String,
    },
    Applied {
        issue: String,
        step: char,
        applied: super::issue::Applied,
    },
    TestCompleted {
        issue: String,
        run: super::next_test::TestRun,
    },
    StepDone {
        issue: String,
        /// Index into the issue's remediation steps.
        step: usize,
        at: String,
    },
}

impl EngineEvent {
    /// The key of the issue this event is about.
    pub fn issue_mut(&mut self) -> &mut String {
        match self {
            EngineEvent::Acked { issue }
            | EngineEvent::Muted { issue, .. }
            | EngineEvent::Resolved { issue, .. }
            | EngineEvent::Applied { issue, .. }
            | EngineEvent::TestCompleted { issue, .. }
            | EngineEvent::StepDone { issue, .. } => issue,
        }
    }
}

/// No target result newer than this means target rules have no input.
const TARGET_STALE_SECS: u64 = 900;

/// Test runs kept per issue.
const MAX_TEST_RUNS: usize = 20;
/// Seconds past an issue's verify hold before an unrecovered step is judged
/// not to have worked.
const VERIFY_GRACE_SECS: i64 = 600;

/// Events kept when nothing drains them (demo mode, recording off).
const EVENT_LOG_CAP: usize = 256;

/// A condition on its way to becoming an issue.
#[derive(Debug, Clone)]
struct Pending {
    /// Consecutive samples that have shown it.
    samples: u32,
    /// The last sample counted, when live timing is known.
    last: Option<std::time::Instant>,
    /// When it was first seen, which becomes the issue's `since`.
    first_seen: DateTime<Local>,
}

pub struct Engine {
    issues: Vec<Issue>,
    /// `Detection::key()` → issue id, so a condition maps to the same issue
    /// across ticks.
    by_key: HashMap<String, IssueId>,
    /// When the verify condition started holding for an issue. Cleared the
    /// moment it stops.
    verifying_since: HashMap<IssueId, DateTime<Local>>,
    clock: Box<dyn Clock>,
    settings: Settings,
    seq: u32,
    coverage: super::coverage::Coverage,
    verification_samples: HashMap<IssueId, (std::time::Instant, std::time::Instant)>,
    /// When an open issue's subject was first seen gone; see
    /// [`subject_gone`]. Cleared the moment it is not.
    gone_since: HashMap<IssueId, DateTime<Local>>,
    /// Path issues whose target was the periodic trace target on some tick
    /// while they were open. Only these can expire when the trace target
    /// changes: a path traced by hand was never going to be traced again.
    periodic_paths: HashSet<IssueId>,
    /// Conditions detected but not yet open, by `Detection::key()`.
    pending: HashMap<String, Pending>,
    /// Events since the last [`Engine::take_events`].
    events: Vec<EngineEvent>,
}

impl Engine {
    pub fn new(clock: Box<dyn Clock>) -> Self {
        Self {
            issues: Vec::new(),
            by_key: HashMap::new(),
            verifying_since: HashMap::new(),
            clock,
            settings: Settings::default(),
            seq: 0,
            coverage: Default::default(),
            verification_samples: HashMap::new(),
            gone_since: HashMap::new(),
            periodic_paths: HashSet::new(),
            pending: HashMap::new(),
            events: Vec::new(),
        }
    }

    pub fn with_settings(mut self, settings: Settings) -> Self {
        self.settings = settings;
        self
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn coverage(&self) -> &super::coverage::Coverage {
        &self.coverage
    }

    pub fn issues(&self) -> &[Issue] {
        &self.issues
    }

    /// Findings to show: open, and not a consequence of another open issue.
    /// Both kinds, in the order the Diagnose tab lists them; replay records
    /// this list, so it is not narrowed to either kind.
    pub fn primary(&self) -> Vec<&Issue> {
        rules::primary_findings(&self.issues)
    }

    /// The primary findings that are Issues: what the verdict line counts.
    pub fn primary_issues(&self) -> Vec<&Issue> {
        self.primary_of(Kind::Issue)
    }

    /// The primary findings that are Observations.
    pub fn primary_observations(&self) -> Vec<&Issue> {
        self.primary_of(Kind::Observation)
    }

    fn primary_of(&self, kind: Kind) -> Vec<&Issue> {
        self.primary()
            .into_iter()
            .filter(|i| i.kind() == kind)
            .collect()
    }

    /// The Observations the verdict line leaves out, counted the way it counts
    /// Issues. Nothing draws it yet; it lives here so the surface that does
    /// cannot count differently from the verdict.
    pub fn observation_count(&self) -> usize {
        self.primary_observations()
            .into_iter()
            .filter(|i| !matches!(i.state, IssueState::Muted { .. }))
            .count()
    }

    /// The Issues the verdict line leaves out because they are muted, so the
    /// line that stops counting them can say how many it left out.
    pub fn muted_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| i.state.muted_until().is_some() && i.kind() == Kind::Issue)
            .count()
    }

    pub fn open_count(&self) -> usize {
        self.primary().len()
    }

    pub fn worst_severity(&self) -> Option<Severity> {
        self.primary().iter().map(|i| i.severity).max()
    }

    pub fn get(&self, id: &str) -> Option<&Issue> {
        self.issues.iter().find(|i| i.id == id)
    }

    /// The issue filed under a key ([`super::issue::finding_key`]): the open
    /// one, or the last to close. `None` once history pruning has dropped it.
    pub fn get_by_key(&self, key: &str) -> Option<&Issue> {
        self.by_key.get(key).and_then(|id| self.get(id))
    }

    /// One tick. Detections are merged into the existing list, issues whose
    /// condition has cleared are moved toward auto-close, and the suppression
    /// graph is recomputed.
    pub fn observe(&mut self, obs: &Observations, base: &BaselineStore) {
        self.observe_inner(obs, base, None);
    }

    pub fn observe_live(
        &mut self,
        obs: &Observations,
        base: &BaselineStore,
        times: &ObservationTimes,
    ) {
        self.observe_live_at(obs, base, times, std::time::Instant::now());
    }

    /// [`Self::observe_live`] with freshness judged at `now`. Replay drives
    /// this with synthetic instants so a recorded tick sees exactly the probe
    /// ages it saw live.
    pub fn observe_live_at(
        &mut self,
        obs: &Observations,
        base: &BaselineStore,
        times: &ObservationTimes,
        now: std::time::Instant,
    ) {
        use crate::collectors::health::ProbeTimes;
        let fresh = |at, max| ProbeTimes::fresh_at(at, max, now);
        let mut observed = obs.clone();
        if !fresh(times.interface, 15) {
            observed.iface = None;
        }
        if !fresh(times.health.dns, 30) {
            observed.dns = None;
        }
        if !fresh(times.health.gateway, 30) {
            observed.gateway = None;
        }
        if !fresh(times.health.internet, 30) {
            if let Some(gateway) = &mut observed.gateway {
                gateway.internet_reachable = None;
            }
        }
        if !fresh(times.health.nat, 300) {
            observed.nat = None;
        }
        if !fresh(times.sockets, 30) {
            observed.sockets.clear();
        }
        if !fresh(times.path, 120) {
            observed.paths.clear();
        }
        // Per target, not in bulk: one target going stale says nothing about
        // the others, and the newest completion standing in for all of them
        // is what let a fast target keep a slow one's result looking live.
        observed.targets.retain(|t| {
            fresh(
                times.targets.get(&t.name).copied(),
                t.stale_after_secs.unwrap_or(TARGET_STALE_SECS),
            )
        });
        if !fresh(times.ipv6, 120) {
            observed.active.ipv6 = None;
        }
        if !fresh(times.portal, 120) {
            observed.active.portal = None;
        }
        if !fresh(times.pmtu, 120) {
            observed.active.pmtu = None;
        }
        if !fresh(times.kernel, 15) {
            observed.kernel = None;
        }
        if !fresh(times.egress, 30) {
            observed.egress = None;
        }
        self.observe_inner(&observed, base, Some((times, now)));
        self.coverage.mark_stale_probes(&times.health, now);
        for row in &mut self.coverage.rules {
            if matches!(
                row.status,
                super::coverage::Availability::Unsupported
                    | super::coverage::Availability::NotImplemented
            ) {
                continue;
            }
            let sample = if row.rule == "ipv6.broken" {
                Some((times.ipv6, 120))
            } else if row.rule == "captive.portal" {
                Some((times.portal, 120))
            } else if row.rule == "pmtu.blackhole" {
                Some((times.pmtu, 120))
            } else if matches!(
                row.rule.as_str(),
                "tcp.connect_failures" | "tcp.timewait_exhaustion"
            ) {
                Some((times.kernel, 15))
            } else if row.rule.starts_with("egress.") {
                Some((times.egress, 30))
            } else if row.rule.starts_with("path.") {
                Some((times.path, 120))
            } else if row.rule.starts_with("tcp.") && row.rule != "tcp.bufferbloat_local" {
                Some((times.sockets, 30))
            } else if row.rule.starts_with("link.")
                || row.rule.starts_with("iface.")
                || row.rule.starts_with("wifi.")
            {
                Some((times.interface, 15))
            } else if row.rule.starts_with("target.") {
                // Coverage is per rule, not per target, so the rule counts as
                // sampled while any target is still fresh; the freshest is
                // the one that decides.
                Some((times.targets.values().copied().max(), TARGET_STALE_SECS))
            } else {
                None
            };
            if let Some((Some(at), max_age)) = sample {
                if !fresh(Some(at), max_age) {
                    row.status = super::coverage::Availability::Stale;
                    row.reason = format!(
                        "collector snapshot older than {max_age}s; excluded from evaluation"
                    );
                }
            }
        }
    }

    /// `live` is the collectors' completion times and the instant they are
    /// judged at, when the caller has them.
    fn observe_inner(
        &mut self,
        obs: &Observations,
        base: &BaselineStore,
        live: Option<(&ObservationTimes, std::time::Instant)>,
    ) {
        self.coverage = super::coverage::Coverage::from_observations(
            obs,
            base,
            self.settings.thresholds.sigma_floor(),
        );
        let now = self.clock.now();
        self.end_mutes(now);
        let detections: Vec<_> = detectors::detect(obs, base, &self.settings.thresholds)
            .into_iter()
            .filter(|d| {
                self.coverage.rules.iter().any(|r| {
                    r.rule == d.rule && r.status == super::coverage::Availability::Available
                })
            })
            .collect();
        let seen: Vec<String> = detections.iter().map(|d| d.key()).collect();
        self.pending.retain(|key, _| seen.contains(key));

        for d in detections {
            if self.is_tracked_key(&d.key()) {
                self.merge(d, now, now);
            } else if let Some(since) = self.confirmed(&d, live.map(|(t, _)| t), now) {
                self.pending.remove(&d.key());
                self.merge(d, now, since);
            }
        }

        self.age_unseen(&seen, obs, base, now, live);
        self.decide_verifications(now);

        rules::apply_suppression(&mut self.issues);
        self.sort();
        self.prune();
    }

    /// Whether `key` already has an issue the engine is watching. A muted
    /// issue counts: its condition coming back each tick is the same issue,
    /// not a new one to confirm and file beside it.
    fn is_tracked_key(&self, key: &str) -> bool {
        self.get_by_key(key).is_some_and(|i| i.state.is_tracked())
    }

    /// Return every issue whose mute has run out to Open. Read from the clock,
    /// not a timer, so a replayed episode ends each mute on the frame the live
    /// engine did.
    fn end_mutes(&mut self, now: DateTime<Local>) {
        for issue in &mut self.issues {
            let ended = issue
                .state
                .muted_until()
                .is_some_and(|until| mute_over(until, &now));
            if ended {
                issue.state = IssueState::Open;
            }
        }
    }

    /// Hysteresis for a condition that isn't open yet: it has to hold for
    /// `consecutive_n` samples before it becomes an issue, so one slow probe
    /// on a noisy wifi link is not a finding.
    ///
    /// Counted in *samples*, not ticks. A probe result stays in the
    /// observations until the next probe completes, several ticks later; one
    /// spike seen on five ticks is still one sample. Without live timing (the
    /// fixture, the demo, unit tests) each call counts as a sample.
    ///
    /// Returns when the condition was first seen once it is confirmed.
    fn confirmed(
        &mut self,
        d: &Detection,
        times: Option<&ObservationTimes>,
        now: DateTime<Local>,
    ) -> Option<DateTime<Local>> {
        let need = self.settings.thresholds.consecutive_n.max(1);
        let sample = times
            .and_then(|t| sample_time(d.rule, &d.subject, t))
            .flatten();
        let entry = self.pending.entry(d.key()).or_insert(Pending {
            samples: 0,
            last: None,
            first_seen: now,
        });
        let new_sample = match (sample, entry.last) {
            (Some(at), Some(last)) => at > last,
            _ => true,
        };
        if new_sample {
            entry.samples += 1;
            entry.last = sample;
        }
        (entry.samples >= need).then_some(entry.first_seen)
    }

    /// `since` is when the condition was first seen: `now` for an issue that
    /// is already open, earlier for one that just passed hysteresis.
    ///
    /// The verify condition is the one the detection carried when the issue
    /// opened or reopened. A close line derived from the metric and taken
    /// afresh every tick would move with the value it judges, and the issue
    /// could chase it forever. A merge that changes the severity keeps it
    /// too, so an issue that escalates from Info keeps the verify it opened
    /// with.
    fn merge(&mut self, d: Detection, now: DateTime<Local>, since: DateTime<Local>) {
        let key = d.key();
        let ts = format_ts(now);

        if let Some(id) = self.by_key.get(&key).cloned() {
            if let Some(idx) = self.issues.iter().position(|i| i.id == id) {
                // A muted issue is not reopening: its mute has not ended, or
                // `end_mutes` would have made it Open already.
                let reopening = !self.issues[idx].state.is_tracked();
                let issue = &mut self.issues[idx];

                if reopening {
                    // Within the recurrence window this is the same problem
                    // coming back, so it keeps its id and gains a count.
                    // Outside it, the old issue stays closed and we file new.
                    // An expired issue counts too: a resolver that left the
                    // config and came back still slow is the same problem.
                    // A target's key carries its revision, so this never
                    // crosses an edit. An entry put back to the revision
                    // the issue was found under probes the same endpoint the
                    // same way, and is this problem coming back.
                    let closed_at = match &issue.state {
                        IssueState::Resolved { at }
                        | IssueState::AutoClosed { at }
                        | IssueState::Expired { at, .. } => parse_ts(at),
                        _ => None,
                    };
                    let within = closed_at
                        .map(|c| now - c <= Duration::minutes(RECURRENCE_WINDOW_MINS))
                        .unwrap_or(false);
                    if within {
                        issue.state = IssueState::Open;
                        issue.recurrence += 1;
                        issue.since = format_ts(since);
                    } else {
                        self.by_key.remove(&key);
                        self.open_new(d, now, since);
                        return;
                    }
                }

                // A muted issue keeps accruing evidence silently and stays
                // muted; it just doesn't reach the verdict line.
                issue.last_seen = ts.clone();
                issue.stale_since = None;
                issue.severity = d.severity;
                issue.title = d.title;
                issue.evidence = d.evidence;
                issue.causes = d.causes;
                issue.scope = d.scope;
                if reopening {
                    issue.verify = d.verify;
                }
                // Preserve applied outcomes across ticks: a step the user
                // already ran must keep saying so.
                merge_remediation(&mut issue.remediation, d.remediation);
                // Detectors rebuild causes every tick; test evidence has to
                // be laid back on top before ranking.
                super::next_test::apply(issue, &ts);
                self.verifying_since.remove(&id);
                self.verification_samples.remove(&id);
                self.gone_since.remove(&id);
                return;
            }
            self.by_key.remove(&key);
        }
        self.open_new(d, now, since);
    }

    fn open_new(&mut self, d: Detection, now: DateTime<Local>, since: DateTime<Local>) {
        self.seq += 1;
        let id = format!("{}-{:02}", now.format("%Y-%m%d"), self.seq);
        let ts = format_ts(now);
        // Take the key before the detection is consumed field by field.
        let key = d.key();
        let mut issue = Issue {
            id: id.clone(),
            rule: d.rule.to_string(),
            severity: d.severity,
            title: d.title,
            subject: d.subject,
            since: format_ts(since),
            last_seen: ts,
            stale_since: None,
            beta: super::rules::lookup(d.rule).is_some_and(|r| r.beta()),
            state: IssueState::Open,
            evidence: d.evidence,
            scope: d.scope,
            causes: d.causes,
            remediation: d.remediation,
            verify: d.verify,
            artifacts: vec![],
            consequences: vec![],
            suppressed_by: None,
            recurrence: 0,
            tests: vec![],
            verification: None,
        };
        issue.rank_causes();
        self.by_key.insert(key, id);
        self.issues.push(issue);
    }

    /// Issues that no detector produced this pass. Their verify condition is
    /// checked against live metrics; once it has held for `hold_secs` the
    /// issue auto-closes. Until then it stays open — a metric dipping under
    /// the threshold for one sample is not a fix.
    ///
    /// An issue whose subject has gone, per [`subject_gone`], for
    /// `expire_after_secs` closes as Expired instead. One whose evidence has
    /// only stopped arriving stays open and records `stale_since`: a probe
    /// that cannot run looks just like a fault that has not cleared.
    ///
    /// Muted issues age like open ones. A mute quiets an issue; it does not
    /// stop netwatch watching it clear.
    fn age_unseen(
        &mut self,
        seen: &[String],
        obs: &Observations,
        base: &BaselineStore,
        now: DateTime<Local>,
        live: Option<(&ObservationTimes, std::time::Instant)>,
    ) {
        let mut closed: Vec<IssueId> = Vec::new();
        let floor = self.settings.thresholds.sigma_floor();
        // A replayed episode's settings come from its file unchecked, and
        // one too long for a Duration means never.
        let expire_after = i64::try_from(self.settings.expire_after_secs)
            .ok()
            .and_then(Duration::try_seconds)
            .unwrap_or(Duration::MAX);
        for issue in self.issues.iter_mut() {
            if !issue.state.is_tracked() {
                continue;
            }
            if let (super::issue::Subject::Path { target }, Some(config)) =
                (&issue.subject, &obs.config)
            {
                if config.trace_refresh_secs.is_some() && &config.trace_target == target {
                    self.periodic_paths.insert(issue.id.clone());
                }
            }
            if seen.contains(&issue.key()) {
                continue;
            }

            let periodic = self.periodic_paths.contains(&issue.id);
            match subject_gone(issue, obs, &self.coverage, live, periodic) {
                Some(reason) => {
                    let since = *self.gone_since.entry(issue.id.clone()).or_insert(now);
                    if now - since >= expire_after {
                        issue.state = IssueState::Expired {
                            at: format_ts(now),
                            reason: reason.into(),
                        };
                        closed.push(issue.id.clone());
                        continue;
                    }
                }
                None => {
                    self.gone_since.remove(&issue.id);
                }
            }

            let mut scoped = obs.clone();
            match &issue.subject {
                super::issue::Subject::Resolver { addr } => {
                    scoped.dns = scoped.dns.filter(|d| {
                        &d.resolver == addr || replacement_resolvers(issue).any(|r| r == d.resolver)
                    })
                }
                super::issue::Subject::Path { target } => {
                    scoped.paths.retain(|p| &p.target == target);
                    scoped.active.pmtu = scoped
                        .active
                        .pmtu
                        .filter(|p| p.target.as_ref() == Some(target))
                }
                super::issue::Subject::Socket { local, remote } => scoped
                    .sockets
                    .retain(|s| &s.local == local && &s.remote == remote),
                super::issue::Subject::Iface { name } => {
                    scoped.iface = scoped.iface.filter(|i| &i.name == name)
                }
                super::issue::Subject::Target { name } => scoped.targets.retain(|t| {
                    &t.name == name
                        && (issue.scope.configuration.is_none()
                            || issue.scope.configuration == t.baseline_key)
                }),
                _ => {}
            }
            let mut values = metric_values(&scoped);
            add_sigma_metrics(&mut values, &scoped, base, floor);
            let available = self.coverage.rules.iter().any(|r| {
                r.rule == issue.rule && r.status == super::coverage::Availability::Available
            });
            let (measured, holding) = if issue.rule.starts_with("egress.") {
                let recovered = obs
                    .egress
                    .as_ref()
                    .and_then(|o| o.recovered(&issue.subject, &issue.rule));
                (recovered.is_some(), recovered == Some(true))
            } else {
                match values.get(&issue.verify.metric) {
                    Some(v) => (true, available && issue.verify.holds(*v)),
                    // Missing evidence is not recovery; reset the hold timer.
                    None => (false, false),
                }
            };
            if available && measured {
                issue.stale_since = None;
            } else if issue.stale_since.is_none() {
                issue.stale_since = Some(format_ts(now));
            }

            if !holding {
                self.verifying_since.remove(&issue.id);
                self.verification_samples.remove(&issue.id);
                continue;
            }

            let mut live_held = None;
            if let Some((times, _)) = live {
                if let Some(sample) = sample_time(&issue.rule, &issue.subject, times) {
                    let Some(sample) = sample else {
                        self.verifying_since.remove(&issue.id);
                        self.verification_samples.remove(&issue.id);
                        continue;
                    };
                    let max_gap = if issue.rule.starts_with("nat.") {
                        300
                    } else if issue.rule.starts_with("target.") {
                        // Targets are probed once a minute by default.
                        TARGET_STALE_SECS / 3
                    } else if issue.rule.starts_with("path.") {
                        120
                    } else if issue.rule.starts_with("link.")
                        || issue.rule.starts_with("iface.")
                        || issue.rule.starts_with("wifi.")
                    {
                        15
                    } else {
                        30
                    };
                    match self.verification_samples.get_mut(&issue.id) {
                        Some((start, last)) => {
                            if sample <= *last {
                                continue;
                            }
                            if sample.duration_since(*last).as_secs() > max_gap {
                                *start = sample;
                            }
                            *last = sample;
                            live_held = Some(sample.duration_since(*start).as_secs());
                        }
                        None => {
                            self.verification_samples
                                .insert(issue.id.clone(), (sample, sample));
                            live_held = Some(0);
                        }
                    }
                }
            }
            let started = *self.verifying_since.entry(issue.id.clone()).or_insert(now);
            let held = live_held.unwrap_or_else(|| (now - started).num_seconds().max(0) as u64);
            if held >= issue.verify.hold_secs {
                issue.state = IssueState::AutoClosed { at: format_ts(now) };
                closed.push(issue.id.clone());
            }
        }
        for id in closed {
            self.verifying_since.remove(&id);
            self.verification_samples.remove(&id);
            self.gone_since.remove(&id);
            self.periodic_paths.remove(&id);
        }
    }

    fn sort(&mut self) {
        // Open before closed, then severity, then oldest first — a problem
        // that has been running for an hour outranks one from ten seconds ago.
        self.issues.sort_by(|a, b| {
            b.state
                .is_open()
                .cmp(&a.state.is_open())
                .then(b.severity.cmp(&a.severity))
                .then(a.since.cmp(&b.since))
        });
    }

    /// Drops the oldest closed issues past `history_limit`. A muted issue is
    /// not history: pruning it would drop its key, and the next detection of
    /// its condition would file a second issue.
    fn prune(&mut self) {
        let closed: Vec<usize> = self
            .issues
            .iter()
            .enumerate()
            .filter(|(_, i)| !i.state.is_tracked())
            .map(|(n, _)| n)
            .collect();
        if closed.len() <= self.settings.history_limit {
            return;
        }
        let drop_count = closed.len() - self.settings.history_limit;
        let doomed: Vec<IssueId> = closed
            .iter()
            .rev()
            .take(drop_count)
            .map(|&n| self.issues[n].id.clone())
            .collect();
        self.issues.retain(|i| !doomed.contains(&i.id));
        self.by_key.retain(|_, id| !doomed.contains(id));
        self.verifying_since.retain(|id, _| !doomed.contains(id));
        self.verification_samples
            .retain(|id, _| !doomed.contains(id));
        self.gone_since.retain(|id, _| !doomed.contains(id));
        self.periodic_paths.retain(|id| !doomed.contains(id));
    }

    // ------------------------------------------------------ user actions

    pub fn ack(&mut self, id: &str) -> bool {
        let done = self.set_state(id, |s| {
            if matches!(s, IssueState::Open) {
                Some(IssueState::Acked)
            } else {
                None
            }
        });
        self.log(id, done, |issue| EngineEvent::Acked { issue });
        done
    }

    pub fn mute(&mut self, id: &str, mins: i64) -> bool {
        let until = format_ts(self.clock.now() + Duration::minutes(mins));
        self.mute_until(id, &until)
    }

    fn mute_until(&mut self, id: &str, until: &str) -> bool {
        let until = until.to_string();
        let state_until = until.clone();
        let done = self.set_state(id, move |s| {
            s.is_open().then(|| IssueState::Muted {
                until: state_until.clone(),
            })
        });
        self.log(id, done, |issue| EngineEvent::Muted { issue, until });
        done
    }

    /// Mark an issue fixed by hand. Distinct from auto-close: the report says
    /// which, because "netwatch watched it clear" and "a human said it was
    /// fine" are different claims.
    pub fn resolve(&mut self, id: &str) -> bool {
        let at = format_ts(self.clock.now());
        self.resolve_at(id, &at)
    }

    fn resolve_at(&mut self, id: &str, at: &str) -> bool {
        let at = at.to_string();
        let state_at = at.clone();
        let done = self.set_state(id, move |_| {
            Some(IssueState::Resolved {
                at: state_at.clone(),
            })
        });
        self.log(id, done, |issue| EngineEvent::Resolved { issue, at });
        done
    }

    /// Events since the last call, oldest first.
    pub fn take_events(&mut self) -> Vec<EngineEvent> {
        std::mem::take(&mut self.events)
    }

    /// Re-apply a recorded event. Returns false when no issue has its key.
    pub fn apply_event(&mut self, event: &EngineEvent) -> bool {
        let key = match event {
            EngineEvent::Acked { issue }
            | EngineEvent::Muted { issue, .. }
            | EngineEvent::Resolved { issue, .. }
            | EngineEvent::Applied { issue, .. }
            | EngineEvent::TestCompleted { issue, .. }
            | EngineEvent::StepDone { issue, .. } => issue,
        };
        let Some(id) = self.by_key.get(key).cloned() else {
            return false;
        };
        match event {
            EngineEvent::Acked { .. } => self.ack(&id),
            EngineEvent::Muted { until, .. } => self.mute_until(&id, until),
            EngineEvent::Resolved { at, .. } => self.resolve_at(&id, at),
            EngineEvent::Applied { step, applied, .. } => {
                self.record_applied(&id, *step, applied.clone())
            }
            EngineEvent::TestCompleted { run, .. } => self.record_test(&id, run.clone()),
            EngineEvent::StepDone { step, at, .. } => self.mark_step_done_at(&id, *step, at),
        }
    }

    /// Attach a finished test run to an issue and re-rank its causes.
    pub fn record_test(&mut self, id: &str, run: super::next_test::TestRun) -> bool {
        let now = format_ts(self.clock.now());
        let Some(issue) = self.issues.iter_mut().find(|i| i.id == id) else {
            return false;
        };
        issue.tests.push(run.clone());
        if issue.tests.len() > MAX_TEST_RUNS {
            issue.tests.remove(0);
        }
        super::next_test::apply(issue, &now);
        self.log(id, true, |issue| EngineEvent::TestCompleted { issue, run });
        true
    }

    /// The user says they carried out remediation step `step` (its index).
    /// From here the engine decides whether it worked; see
    /// [`super::issue::VerifyOutcome`].
    pub fn mark_step_done(&mut self, id: &str, step: usize) -> bool {
        let at = format_ts(self.clock.now());
        self.mark_step_done_at(id, step, &at)
    }

    fn mark_step_done_at(&mut self, id: &str, step: usize, at: &str) -> bool {
        use super::issue::{Verification, VerifyOutcome};
        let holding = self.verifying_since.contains_key(id);
        let Some(issue) = self.issues.iter_mut().find(|i| i.id == id) else {
            return false;
        };
        if !issue.state.is_open() || step >= issue.remediation.len() {
            return false;
        }
        let top = issue.top_cause().cloned();
        let supporting = super::next_test::latest_runs(issue, at)
            .into_iter()
            .filter(|run| {
                top.as_ref().is_some_and(|c| {
                    c.checks.iter().any(|k| {
                        k.id == super::next_test::check_id(&run.test) && k.passed == Some(true)
                    })
                })
            })
            .map(|run| run.test.clone())
            .collect();
        issue.verification = Some(Verification {
            step,
            action_at: at.to_string(),
            holding_at_action: holding,
            top_cause: top.map(|c| c.key(&issue.rule)),
            supporting,
            outcome: holding.then_some(VerifyOutcome::RecoveredBeforeAction),
            decided_at: holding.then(|| at.to_string()),
        });
        let at = at.to_string();
        self.log(id, true, |issue| EngineEvent::StepDone { issue, step, at });
        true
    }

    /// Decide pending verifications: closed issues recovered (fully, unless a
    /// re-run test still points at the cause), except hand-resolved and
    /// expired ones, which nothing measured; open and muted ones past their
    /// deadline did not.
    fn decide_verifications(&mut self, now: DateTime<Local>) {
        use super::issue::VerifyOutcome;
        let ts = format_ts(now);
        for issue in &mut self.issues {
            let rule = issue.rule.clone();
            let Some(v) = issue.verification.as_mut() else {
                continue;
            };
            if v.outcome.is_some() {
                continue;
            }
            let still_supported = v.supporting.iter().any(|test| {
                let Some(spec) = super::next_test::lookup(test) else {
                    return false;
                };
                let Some(cause) = v
                    .top_cause
                    .as_deref()
                    .and_then(|k| k.split_once('/'))
                    .map(|x| x.1)
                else {
                    return false;
                };
                let Some(expect) = spec
                    .expects
                    .iter()
                    .find(|x| x.rule == rule && x.cause == cause)
                else {
                    return false;
                };
                issue
                    .tests
                    .iter()
                    .rev()
                    .find(|r| r.after_action && &r.test == test)
                    .is_some_and(|r| {
                        r.outcome != super::next_test::Outcome::Inconclusive
                            && (r.outcome == super::next_test::Outcome::Positive) == expect.positive
                    })
            });
            // Only an auto-close is measured: netwatch watched the verify
            // condition hold. A hand-resolved issue closed because someone
            // said so, and an expired one because its subject went away;
            // neither is evidence that the step worked. A muted issue has
            // not closed at all, so it waits for its deadline as an open one
            // does.
            let outcome = if matches!(issue.state, IssueState::Resolved { .. }) {
                Some(VerifyOutcome::ClosedByOperator)
            } else if matches!(issue.state, IssueState::Expired { .. }) {
                Some(VerifyOutcome::NotMeasured)
            } else if !issue.state.is_tracked() {
                Some(if still_supported {
                    VerifyOutcome::Partial
                } else {
                    VerifyOutcome::Recovered
                })
            } else {
                let deadline = parse_ts(&v.action_at).map(|a| {
                    a + Duration::seconds(issue.verify.hold_secs as i64 + VERIFY_GRACE_SECS)
                });
                match deadline {
                    Some(d) if now >= d => Some(if self.verifying_since.contains_key(&issue.id) {
                        VerifyOutcome::Partial
                    } else {
                        VerifyOutcome::NotRecovered
                    }),
                    _ => None,
                }
            };
            if outcome.is_some() {
                v.outcome = outcome;
                v.decided_at = Some(ts.clone());
            }
        }
    }

    fn log(&mut self, id: &str, done: bool, event: impl FnOnce(String) -> EngineEvent) {
        if !done {
            return;
        }
        let Some(issue) = self.issues.iter().find(|i| i.id == id) else {
            return;
        };
        let key = issue.key();
        if self.events.len() >= EVENT_LOG_CAP {
            self.events.remove(0);
        }
        self.events.push(event(key));
    }

    fn set_state(&mut self, id: &str, f: impl Fn(&IssueState) -> Option<IssueState>) -> bool {
        let Some(issue) = self.issues.iter_mut().find(|i| i.id == id) else {
            return false;
        };
        match f(&issue.state) {
            Some(next) => {
                issue.state = next;
                rules::apply_suppression(&mut self.issues);
                true
            }
            None => false,
        }
    }

    /// Record the outcome of a remediation step on its issue, so the screen
    /// and the report both show what was actually done.
    pub fn record_applied(&mut self, id: &str, key: char, applied: super::issue::Applied) -> bool {
        let Some(issue) = self.issues.iter_mut().find(|i| i.id == id) else {
            return false;
        };
        let Some(step) = issue.remediation.iter_mut().find(|s| s.key == Some(key)) else {
            return false;
        };
        step.applied = Some(applied.clone());
        self.log(id, true, |issue| EngineEvent::Applied {
            issue,
            step: key,
            applied,
        });
        true
    }

    /// The line under the tab bar. Collapses to one dim sentence when nothing
    /// is wrong, and never claims health it hasn't verified — a host still
    /// learning its baselines says so rather than saying "all nominal".
    ///
    /// Only Issues make it say so. A host whose only findings are
    /// Observations reads as learning or incomplete, as an empty one does,
    /// and the Diagnose tab still lists them.
    pub fn verdict(&self, base: &BaselineStore) -> Verdict {
        let visible: Vec<&Issue> = self
            .primary_issues()
            .into_iter()
            .filter(|i| !matches!(i.state, IssueState::Muted { .. }))
            .collect();

        if visible.is_empty() {
            let readiness = base.overall_readiness();
            if base.switched_network() && !readiness.is_ready() {
                return Verdict::Learning {
                    detail: format!(
                        "new network ({}) — {} · {}",
                        base.fingerprint().label(),
                        readiness.label(),
                        self.coverage.label()
                    ),
                };
            }
            if !readiness.is_ready() {
                return Verdict::Learning {
                    detail: format!(
                        "baselines {} · {}",
                        readiness.label(),
                        self.coverage.label()
                    ),
                };
            }
            return Verdict::Incomplete {
                detail: self.coverage.label(),
            };
        }

        let worst = visible
            .iter()
            .map(|i| i.severity)
            .max()
            .unwrap_or(Severity::Info);
        Verdict::Issues {
            severity: worst,
            count: visible.len(),
            headline: visible[0].summary_line(),
            id: visible[0].id.clone(),
        }
    }
}

/// Preserve `applied` outcomes when a detector re-emits a step list.
fn merge_remediation(existing: &mut Vec<super::issue::Step>, fresh: Vec<super::issue::Step>) {
    let applied: HashMap<String, super::issue::Applied> = existing
        .iter()
        .filter_map(|s| s.applied.clone().map(|a| (s.text.clone(), a)))
        .collect();
    *existing = fresh
        .into_iter()
        .map(|mut s| {
            if let Some(a) = applied.get(&s.text) {
                s.applied = Some(a.clone());
            }
            s
        })
        .collect();
}

/// What the verdict line says.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Baselines are ready and no Issue is open.
    Clear,
    /// No Issue is open, but netwatch doesn't yet have the baselines to say so
    /// with confidence.
    Learning {
        detail: String,
    },
    Incomplete {
        detail: String,
    },
    /// At least one Issue is open. `count` leaves Observations out, so
    /// `severity` is never Info.
    Issues {
        severity: Severity,
        count: usize,
        headline: String,
        id: IssueId,
    },
}

impl Verdict {
    /// The exact text of the line, so the TUI, the toast and `y` copy agree.
    pub fn line(&self) -> String {
        match self {
            Verdict::Clear => "no issues · baselines ready".to_string(),
            Verdict::Learning { detail } | Verdict::Incomplete { detail } => {
                format!("no visible issues · {detail}")
            }
            Verdict::Issues {
                count, headline, ..
            } => {
                let n = if *count == 1 {
                    "1 issue".to_string()
                } else {
                    format!("{count} issues")
                };
                format!("{n} · {headline} · press 9 to diagnose")
            }
        }
    }

    pub fn is_clear(&self) -> bool {
        !matches!(self, Verdict::Issues { .. })
    }

    /// Short form for tight chrome — a box title, a Lite status cell, a Dense
    /// subtitle.
    ///
    /// Note what this deliberately cannot say: "nominal" is reserved for a
    /// host whose baselines are ready and whose issue list is empty. A host
    /// that has been up for ninety seconds reports `learning`, because it has
    /// not yet earned the right to call anything nominal — which is the
    /// specific claim the design review objected to.
    pub fn chip(&self) -> &'static str {
        match self {
            Verdict::Clear => "nominal",
            Verdict::Learning { .. } => "learning",
            Verdict::Incomplete { .. } => "limited",
            Verdict::Issues { count, .. } => {
                if *count == 1 {
                    "1 issue"
                } else {
                    "issues"
                }
            }
        }
    }

    /// Count for the chip when it needs a number alongside the word.
    pub fn count(&self) -> usize {
        match self {
            Verdict::Issues { count, .. } => *count,
            _ => 0,
        }
    }

    pub fn severity(&self) -> Option<Severity> {
        match self {
            Verdict::Issues { severity, .. } => Some(*severity),
            _ => None,
        }
    }

    /// Colour for the chip, resolved against a theme.
    pub fn color(&self, t: &crate::theme::Theme) -> ratatui::style::Color {
        match self.severity() {
            Some(Severity::Critical) | Some(Severity::High) => t.status_error,
            Some(Severity::Medium) => t.status_warn,
            Some(Severity::Info) => t.status_info,
            // A clear verdict is green; a learning one is not — it is an
            // absence of information, and green would misreport it as health.
            None => match self {
                Verdict::Clear => t.status_good,
                _ => t.text_muted,
            },
        }
    }
}

/// Derive the σ-denominated metrics from the raw readings and the baselines,
/// scored against the same floored σ the detectors open on.
///
/// A rule that opened because a value was 3σ above baseline closes when it is
/// back under 2σ (`sigma_close_k`) — not when it drops below some absolute
/// number, which would be a different claim on every network. The gap between
/// the two lines keeps a value hovering at 3σ from opening and closing in turn.
fn add_sigma_metrics(
    values: &mut HashMap<String, f64>,
    obs: &Observations,
    base: &BaselineStore,
    floor: SigmaFloor,
) {
    if let Some(t) = obs.targets.first() {
        let readings = t.stage_readings();
        let worst = readings
            .iter()
            .filter_map(|(metric, ms)| {
                base.get(t.baseline_subject(), metric)
                    .and_then(|b| b.sigma_above(*ms, floor))
            })
            .reduce(f64::max);
        // Every stage within its baseline, or none has one yet: nothing slow.
        values.insert("target.worst_stage_sigma".into(), worst.unwrap_or(0.0));
    }
    if let Some(gw) = &obs.gateway {
        if let (Some(addr), Some(rtt)) = (&gw.addr, gw.rtt_ms) {
            if let Some(sigma) = base
                .get(addr, "gateway.rtt")
                .and_then(|b| b.sigma_above(rtt, floor))
            {
                values.insert("gateway.rtt_sigma".to_string(), sigma);
            }
        }
    }
    for path in &obs.paths {
        let Some(last) = path.hops.iter().rev().find(|h| !h.silent) else {
            continue;
        };
        let Some(rtt) = last.rtt_p50_ms else { continue };
        let sigma = base
            .get(&path.target, "path.rtt")
            .or_else(|| base.get("internet", "path.rtt"))
            .and_then(|b| b.sigma_above(rtt, floor));
        if let Some(sigma) = sigma {
            values.insert("path.rtt_sigma".to_string(), sigma);
            values.insert("path.rtt".to_string(), rtt);
        }
    }
}

/// Flatten observations into the metric namespace the verify conditions use.
/// Every key here matches an `Evidence::metric` a detector emits — that shared
/// vocabulary is what lets a rule declare its own success condition.
fn metric_values(obs: &Observations) -> HashMap<String, f64> {
    let mut m = HashMap::new();
    for (r, metric) in [
        ("ipv6.broken", "ipv6.probe_loss"),
        ("captive.portal", "captive.probe_204"),
        ("pmtu.blackhole", "pmtu.transfer_ok"),
    ] {
        if let Some(o) = obs.active.get(r) {
            if matches!(
                o.outcome,
                super::active::Outcome::Healthy | super::active::Outcome::Fault
            ) {
                let healthy = o.outcome == super::active::Outcome::Healthy;
                m.insert(
                    metric.into(),
                    if r == "ipv6.broken" {
                        if healthy {
                            0.0
                        } else {
                            100.0
                        }
                    } else if healthy {
                        1.0
                    } else {
                        0.0
                    },
                );
            }
        }
    }
    if let Some(k) = &obs.kernel {
        if let Some(v) = k.failures_per_minute {
            m.insert("tcp.connect_failure_rate".into(), v);
        }
        if let Some(v) = k.timewait_port_pct {
            m.insert("tcp.timewait_pct".into(), v);
        }
    }
    if let Some(dns) = &obs.dns {
        if let Some(p50) = dns.rtt_p50_ms {
            m.insert("dns.rtt_p50".to_string(), p50);
        }
        if let Some(p95) = dns.rtt_p95_ms {
            m.insert("dns.rtt_p95".to_string(), p95);
        }
        m.insert("dns.failure_rate".to_string(), dns.failure_rate_pct);
        m.insert("dns.tc_rate".to_string(), dns.truncation_rate_pct);
        if let Some(c) = &dns.cross {
            // A private answer is a total mismatch, whatever the history
            // says — the verify condition must not clear while it persists.
            let v = if c.private_answer {
                100.0
            } else {
                c.mismatch_pct
            };
            m.insert("dns.answer_mismatch".to_string(), v);
        }
    }
    if let Some(gw) = &obs.gateway {
        m.insert("gateway.loss".to_string(), gw.loss_pct);
        if let Some(rtt) = gw.rtt_ms {
            m.insert("gateway.rtt".to_string(), rtt);
        }
    }
    if let Some(iface) = &obs.iface {
        // Unknown carrier stays out, so link.down's verify cannot pass on it.
        if let Some(up) = iface.carrier {
            m.insert("iface.carrier".to_string(), if up { 1.0 } else { 0.0 });
        }
        m.insert("iface.error_rate".to_string(), iface.error_rate() as f64);
        if let Some(u) = iface.utilisation_pct() {
            m.insert("iface.utilisation".to_string(), u);
        }
        if let Some(s) = iface.signal_dbm {
            m.insert("wifi.rssi".to_string(), s as f64);
        }
        if let Some(r) = iface.tx_retry_pct {
            m.insert("wifi.tx_retry_pct".to_string(), r);
        }
    }
    if let Some(nat) = &obs.nat {
        m.insert(
            "nat.symmetric".to_string(),
            if nat.symmetric { 1.0 } else { 0.0 },
        );
    }
    if let (Some(idle), Some(loaded)) = (obs.idle_rtt_ms, obs.loaded_rtt_ms) {
        m.insert("tcp.loaded_rtt_delta".to_string(), loaded - idle);
    }
    // Scoped to one target by the caller; outside that, the first target.
    if let Some(t) = obs.targets.first() {
        let flag = |ok: bool| if ok { 1.0 } else { 0.0 };
        m.insert("target.resolve_ok".into(), flag(t.resolve.is_ok()));
        if let Some(c) = &t.connect {
            m.insert("target.connect_ok".into(), flag(c.is_ok()));
        }
        if let Some(s) = &t.tls_stage {
            m.insert("target.tls_ok".into(), flag(s.is_ok()));
        }
        if let Some(h) = &t.http_stage {
            m.insert("target.http_ok".into(), flag(h.is_ok()));
        }
    }
    for path in &obs.paths {
        if let Some(previous) = &path.previous {
            if !previous.is_empty()
                && previous.len() == path.hops.len()
                && previous
                    .iter()
                    .chain(&path.hops)
                    .all(|h| !h.silent && h.ip.is_some())
            {
                m.insert(
                    "path.hop_changes".into(),
                    if detectors::first_hop_change(previous, &path.hops).is_some() {
                        1.0
                    } else {
                        0.0
                    },
                );
            }
        }
        // Conservative: all responding hops must meet the recovery condition.
        if let Some(loss) = path
            .hops
            .iter()
            .filter(|h| !h.silent)
            .map(|h| h.loss_pct)
            .max_by(|a, b| a.total_cmp(b))
        {
            m.insert("path.hop_loss".into(), loss);
        }
    }
    // Socket metrics are per-subject; the worst socket stands for the metric,
    // so an issue can't close while any socket still shows the condition.
    if let Some(worst) = obs
        .sockets
        .iter()
        .filter_map(|s| s.rtt_ms)
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    {
        m.insert("tcp.socket_rtt".to_string(), worst);
    }
    if let Some(worst) = obs.sockets.iter().filter_map(|s| s.retrans).max() {
        m.insert("tcp.retrans_rate".to_string(), worst as f64);
    }
    if let Some(min_rwnd) = obs.sockets.iter().filter_map(|s| s.rwnd).min() {
        m.insert("tcp.rwnd".to_string(), min_rwnd as f64);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::baseline::NetworkFingerprint;
    use crate::diagnose::detectors::{DnsObs, GatewayObs, IfaceObs, ObservedConfig, SocketObs};

    fn base() -> BaselineStore {
        let mut b = BaselineStore::new(NetworkFingerprint::new(
            "eth0",
            Some("192.168.8.1".into()),
            vec!["169.254.1.1".into()],
            None,
        ))
        .with_min_samples(3);
        b.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        b
    }

    fn dns(p50: f64) -> DnsObs {
        DnsObs {
            resolver: "169.254.1.1".into(),
            rtt_p50_ms: Some(p50),
            rtt_p95_ms: Some(p50 * 1.2),
            failure_rate_pct: 0.0,
            truncation_rate_pct: 0.0,
            queries: 38,
            failed: 0,
            truncated: 0,
            alt_resolver: Some("192.168.8.1".into()),
            alt_rtt_ms: Some(1.4),
            icmp_rtt_ms: Some(0.1),
            cached_rtt_ms: Some(0.9),
            window_secs: 180,
            cross: None,
        }
    }

    fn obs(p50: f64) -> Observations {
        Observations {
            now: "2026-09-03 06:48:10".into(),
            dns: Some(dns(p50)),
            ..Default::default()
        }
    }

    /// An engine that opens an issue on its first sample. Most tests here are
    /// about what happens *after* an issue opens; hysteresis has its own.
    fn engine_at(ts: &str) -> (Engine, std::sync::Arc<FixedClock>) {
        let (engine, clock) = hysteresis_engine_at(ts);
        let mut settings = *engine.settings();
        settings.thresholds.consecutive_n = 1;
        (engine.with_settings(settings), clock)
    }

    /// An engine with the default `consecutive_n`.
    fn hysteresis_engine_at(ts: &str) -> (Engine, std::sync::Arc<FixedClock>) {
        let clock = std::sync::Arc::new(FixedClock::at(ts));
        let engine = Engine::new(Box::new(ClockRef(clock.clone())));
        (engine, clock)
    }

    #[test]
    fn one_slow_sample_does_not_open_an_issue() {
        let (mut e, clock) = hysteresis_engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        clock.advance_secs(1);
        e.observe(&obs(1.0), &b);
        clock.advance_secs(1);
        e.observe(&obs(40.0), &b);
        clock.advance_secs(1);
        e.observe(&obs(40.0), &b);
        assert_eq!(e.open_count(), 0, "the streak was broken by a good sample");
        clock.advance_secs(1);
        e.observe(&obs(40.0), &b);
        assert_eq!(e.open_count(), 1);
        assert_eq!(
            e.issues()[0].since,
            "2026-09-03 06:48:12",
            "since is the first sample of the streak, not the one that confirmed it"
        );
    }

    #[test]
    fn a_cached_probe_result_counts_once_however_many_ticks_show_it() {
        let (mut e, _clock) = hysteresis_engine_at("2026-09-03 06:48:10");
        let b = base();
        let start = std::time::Instant::now();
        let mut times = ObservationTimes::default();
        times.health.dns = Some(start);
        // One slow probe result, visible for ten ticks until the next probe.
        for tick in 0..10 {
            e.observe_live_at(
                &obs(40.0),
                &b,
                &times,
                start + std::time::Duration::from_millis(tick * 500),
            );
        }
        assert_eq!(e.open_count(), 0, "one probe result is one sample");
        for probe in 1..=2u64 {
            times.health.dns = Some(start + std::time::Duration::from_secs(5 * probe));
            e.observe_live_at(
                &obs(40.0),
                &b,
                &times,
                start + std::time::Duration::from_secs(5 * probe),
            );
        }
        assert_eq!(e.open_count(), 1, "three distinct probes confirm it");
    }

    struct ClockRef(std::sync::Arc<FixedClock>);
    impl Clock for ClockRef {
        fn now(&self) -> DateTime<Local> {
            self.0.now()
        }
    }

    #[test]
    fn a_persistent_condition_stays_one_issue() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        for _ in 0..120 {
            e.observe(&obs(40.0), &b);
            clock.advance_secs(1);
        }
        assert_eq!(e.open_count(), 1, "120 ticks must not make 120 issues");
        let issue = &e.primary()[0];
        assert_eq!(
            issue.since, "2026-09-03 06:48:10",
            "since must be the first violation"
        );
        assert_eq!(issue.last_seen, "2026-09-03 06:50:09");
        assert_eq!(issue.recurrence, 0);
    }

    #[test]
    fn ids_are_stable_across_ticks() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let first = e.primary()[0].id.clone();
        clock.advance_secs(5);
        e.observe(&obs(41.0), &b);
        assert_eq!(e.primary()[0].id, first);
    }

    #[test]
    fn an_issue_does_not_close_on_one_good_sample() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        assert_eq!(e.open_count(), 1);

        clock.advance_secs(1);
        e.observe(&obs(1.3), &b);
        assert_eq!(
            e.open_count(),
            1,
            "one good sample is not a fix — the verify window has to elapse"
        );
    }

    fn run(
        test: &str,
        at: &str,
        outcome: crate::diagnose::next_test::Outcome,
        after: bool,
    ) -> crate::diagnose::next_test::TestRun {
        crate::diagnose::next_test::TestRun {
            test: test.into(),
            at: at.into(),
            outcome,
            detail: "t".into(),
            measurements: Default::default(),
            after_action: after,
        }
    }

    #[test]
    fn a_test_run_survives_the_next_detector_pass() {
        use crate::diagnose::next_test::Outcome;
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        let _ = e.take_events();
        assert!(e.record_test(
            &id,
            run(
                "dns.alt_resolver",
                "2026-09-03 06:48:10",
                Outcome::Positive,
                false
            )
        ));
        clock.advance_secs(1);
        e.observe(&obs(40.0), &b);
        let issue = e.get(&id).unwrap();
        let check = crate::diagnose::next_test::check_id("dns.alt_resolver");
        let local = issue
            .causes
            .iter()
            .find(|c| c.id == "local_udp_path")
            .unwrap();
        assert_eq!(
            local.checks.iter().find(|k| k.id == check).unwrap().passed,
            Some(false),
            "a fast reference resolver rules out the local path"
        );
        assert_eq!(issue.causes.last().unwrap().id, "local_udp_path");
        assert!(matches!(
            e.take_events().as_slice(),
            [EngineEvent::TestCompleted { .. }]
        ));
    }

    #[test]
    fn a_step_that_works_is_recovered_and_one_that_does_not_is_not() {
        use crate::diagnose::issue::VerifyOutcome;
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        assert!(e.mark_step_done(&id, 0));
        assert_eq!(
            e.get(&id).unwrap().verification.as_ref().unwrap().outcome,
            None
        );
        for _ in 0..61 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }
        assert_eq!(
            e.get(&id).unwrap().verification.as_ref().unwrap().outcome,
            Some(VerifyOutcome::Recovered)
        );

        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        assert!(e.mark_step_done(&id, 0));
        for _ in 0..(60 + VERIFY_GRACE_SECS) {
            clock.advance_secs(1);
            e.observe(&obs(40.0), &b);
        }
        assert_eq!(
            e.get(&id).unwrap().verification.as_ref().unwrap().outcome,
            Some(VerifyOutcome::NotRecovered)
        );
    }

    #[test]
    fn a_step_taken_while_already_recovering_gets_no_credit() {
        use crate::diagnose::issue::VerifyOutcome;
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        for _ in 0..10 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }
        assert!(e.mark_step_done(&id, 0));
        assert_eq!(
            e.get(&id).unwrap().verification.as_ref().unwrap().outcome,
            Some(VerifyOutcome::RecoveredBeforeAction)
        );
    }

    #[test]
    fn recovery_with_a_rerun_still_pointing_at_the_cause_is_partial() {
        use crate::diagnose::issue::VerifyOutcome;
        use crate::diagnose::next_test::Outcome;
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        // A fast reference resolver supports upstream_slow, the top cause.
        e.record_test(
            &id,
            run(
                "dns.alt_resolver",
                "2026-09-03 06:48:10",
                Outcome::Positive,
                false,
            ),
        );
        assert!(e.mark_step_done(&id, 0));
        assert_eq!(
            e.get(&id)
                .unwrap()
                .verification
                .as_ref()
                .unwrap()
                .supporting,
            vec!["dns.alt_resolver".to_string()]
        );
        clock.advance_secs(1);
        e.record_test(
            &id,
            run(
                "dns.alt_resolver",
                "2026-09-03 06:48:11",
                Outcome::Positive,
                true,
            ),
        );
        for _ in 0..61 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }
        assert_eq!(
            e.get(&id).unwrap().verification.as_ref().unwrap().outcome,
            Some(VerifyOutcome::Partial)
        );
    }

    #[test]
    fn a_target_issue_needs_three_probes_and_closes_when_the_target_recovers() {
        use crate::diagnose::targets::{Stage, StageError, TargetContext, TargetObs};
        let (mut e, _clock) = hysteresis_engine_at("2026-09-15 10:00:00");
        let b = base();
        let target = |refused: bool| TargetObs {
            baseline_key: None,
            attempts: vec![],
            effective_endpoint: None,
            sni: None,
            http_authority: None,
            name: "api".into(),
            host: "127.0.0.1".into(),
            port: 8443,
            tls: false,
            http: false,
            expect_status: None,
            probed_at: String::new(),
            resolve: Stage {
                ms: Some(0.0),
                error: None,
            },
            addresses: vec!["127.0.0.1".into()],
            lookups: vec![],
            connect: Some(Stage {
                ms: Some(1.0),
                error: refused.then_some(StageError::Refused),
            }),
            connect_v4: None,
            connect_v6: None,
            tls_stage: None,
            http_stage: None,
            status: None,
            stale_after_secs: None,
            context: TargetContext::default(),
        };
        let obs = |refused| Observations {
            targets: vec![target(refused)],
            ..Default::default()
        };
        let start = std::time::Instant::now();
        let mut times = ObservationTimes::default();
        let mut tick = |e: &mut Engine, refused: bool, probe: u64, secs: u64| {
            times.targets = [(
                "api".to_string(),
                start + std::time::Duration::from_secs(probe * 60),
            )]
            .into_iter()
            .collect();
            e.observe_live_at(
                &obs(refused),
                &b,
                &times,
                start + std::time::Duration::from_secs(secs),
            );
        };
        // One probe result seen on many ticks is one sample.
        for s in 0..30 {
            tick(&mut e, true, 0, s);
        }
        assert_eq!(e.open_count(), 0);
        tick(&mut e, true, 1, 60);
        tick(&mut e, true, 2, 120);
        assert_eq!(e.open_count(), 1);
        let issue = e.primary()[0].clone();
        assert_eq!(issue.rule, "target.connect_failed");
        assert_eq!(issue.subject.label(), "api");

        for p in 3..6 {
            tick(&mut e, false, p, p * 60);
        }
        assert!(
            !e.get(&issue.id).unwrap().state.is_open(),
            "{:?}",
            e.get(&issue.id).unwrap().state
        );
    }

    #[test]
    fn an_issue_auto_closes_once_verify_holds_for_its_window() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);

        // Against this baseline dns.slow_resolver closes once p50 has held
        // under 4.96ms, 0.8 of its 6.2ms open line, for 60s.
        for _ in 0..61 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }
        assert_eq!(e.open_count(), 0);
        let issue = &e.issues()[0];
        assert!(
            matches!(issue.state, IssueState::AutoClosed { .. }),
            "{:?}",
            issue.state
        );
    }

    #[test]
    fn closing_an_issue_by_hand_is_not_a_measured_recovery() {
        // Pressing resolve after carrying out a step used to record
        // `Recovered` against that step, crediting an action with a repair
        // nothing measured. Only an auto-close follows an observed hold.
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();

        assert!(e.mark_step_done(&id, 0));
        clock.advance_secs(5);
        assert!(e.resolve(&id));

        // The rule stops firing afterwards, so nothing reopens it. The engine
        // still never watched a verify window: a human ended this, not a
        // measurement.
        clock.advance_secs(120);
        e.observe(&obs(1.3), &b);

        let issue = e.get(&id).unwrap();
        assert!(matches!(issue.state, IssueState::Resolved { .. }));
        let v = issue.verification.as_ref().expect("a step was carried out");
        assert_eq!(
            v.outcome,
            Some(super::super::issue::VerifyOutcome::ClosedByOperator),
            "a hand-closed issue cannot report a measured recovery"
        );
    }

    #[test]
    fn an_auto_close_after_a_step_still_reports_a_measured_recovery() {
        // The counterpart: the engine watched p50 hold under its close line
        // for the rule's window, so the step keeps its credit.
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        assert!(e.mark_step_done(&id, 0));

        for _ in 0..61 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }

        let issue = e.get(&id).unwrap();
        assert!(matches!(issue.state, IssueState::AutoClosed { .. }));
        assert_eq!(
            issue.verification.as_ref().unwrap().outcome,
            Some(super::super::issue::VerifyOutcome::Recovered)
        );
    }

    /// Close `id` as Expired at the clock's time, as the expiry guard does,
    /// so these tests are about what follows an expiry rather than what
    /// causes one. The guard's own tests drive [`subject_gone`].
    fn expire(e: &mut Engine, id: &str, reason: &str) {
        let at = format_ts(e.clock.now());
        let issue = e.issues.iter_mut().find(|i| i.id == id).unwrap();
        issue.state = IssueState::Expired {
            at,
            reason: reason.into(),
        };
        e.verifying_since.remove(id);
        e.verification_samples.remove(id);
        e.gone_since.remove(id);
    }

    #[test]
    fn expired_is_closed_and_not_a_recovery() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        expire(&mut e, &id, "resolver left the config");

        // The resolver is fast again afterwards. That is not the issue's
        // verify holding, because nothing watches a closed issue: it stays
        // Expired and never turns into a close netwatch saw clear.
        for _ in 0..61 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }
        let issue = e.get(&id).unwrap();
        assert!(!issue.state.is_open());
        assert_eq!(e.open_count(), 0);
        assert!(
            matches!(&issue.state, IssueState::Expired { reason, .. } if reason == "resolver left the config"),
            "{:?}",
            issue.state
        );
        assert_eq!(issue.state.label(), "expired");
    }

    #[test]
    fn a_step_before_expiry_is_not_credited() {
        use crate::diagnose::issue::VerifyOutcome;
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        assert!(e.mark_step_done(&id, 0));

        // The verify condition holds for half its window, then the subject
        // goes. Counting that close as a recovery would credit the step
        // with a fix nothing finished measuring.
        for _ in 0..30 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }
        assert_eq!(
            e.get(&id).unwrap().verification.as_ref().unwrap().outcome,
            None
        );
        expire(&mut e, &id, "resolver left the config");
        clock.advance_secs(1);
        e.observe(&obs(1.3), &b);

        let v = e.get(&id).unwrap().verification.clone().unwrap();
        assert_eq!(v.outcome, Some(VerifyOutcome::NotMeasured));
        assert_eq!(v.decided_at.as_deref(), Some("2026-09-03 06:48:41"));
        assert_eq!(
            VerifyOutcome::NotMeasured.label(),
            "closed without a measurement"
        );
    }

    #[test]
    fn an_expired_condition_that_returns_within_the_window_reopens() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        expire(&mut e, &id, "resolver left the config");

        // Back five minutes later and still slow: the same problem, once
        // more, not a second finding.
        clock.advance_secs(5 * 60);
        e.observe(&obs(40.0), &b);
        assert_eq!(e.issues().len(), 1, "{:#?}", e.issues());
        let issue = e.get(&id).unwrap();
        assert_eq!(issue.state, IssueState::Open);
        assert_eq!(issue.recurrence, 1);
        assert_eq!(issue.since, "2026-09-03 06:53:10");

        // Past the recurrence window it is a new incident.
        expire(&mut e, &id, "resolver left the config");
        clock.advance_secs((RECURRENCE_WINDOW_MINS + 1) * 60);
        e.observe(&obs(40.0), &b);
        assert_eq!(e.issues().len(), 2);
        assert_eq!(e.primary()[0].recurrence, 0);
        assert_ne!(e.primary()[0].id, id);
    }

    #[test]
    fn settings_with_auto_close_secs_still_load() {
        // The settings block of an episode recorded before the rename, as
        // the pinned corpus held it.
        let old = r#"{"thresholds":{"sigma_k":3.0,"consecutive_n":3,"verdict_hold_secs":30,
            "dns_ceiling_ms":100.0,"socket_rtt_ms":100.0,"loaded_rtt_delta_ms":100.0,
            "saturation_pct":90.0,"iface_error_floor":1.0,"iface_drop_floor":60.0,
            "dns_tc_pct":10.0,"dns_mismatch_pct":50.0,"wifi_rssi_dbm":-70.0,
            "wifi_retry_pct":20.0},"auto_close_secs":300,"history_limit":50}"#;
        let loaded: Settings = serde_json::from_str(old).unwrap();
        assert_eq!(loaded.expire_after_secs, 300);
        assert_eq!(loaded.history_limit, 50);

        // It writes back under the new name only.
        let json = serde_json::to_string(&loaded).unwrap();
        assert!(json.contains(r#""expire_after_secs":300"#), "{json}");
        assert!(!json.contains("auto_close_secs"), "{json}");
        assert_eq!(Settings::default().expire_after_secs, 60);
    }

    // ------------------------------------------------------ the expiry guard

    fn find(e: &Engine, rule: &str) -> Issue {
        e.issues()
            .iter()
            .find(|i| i.rule == rule)
            .unwrap_or_else(|| panic!("no {rule} issue: {:#?}", e.issues()))
            .clone()
    }

    fn expired(reason: &str, at: &str) -> IssueState {
        IssueState::Expired {
            at: at.into(),
            reason: reason.into(),
        }
    }

    /// A socket retransmitting 12 segments a minute at 20 ms: tcp.retrans_burst.
    fn retransmitting() -> SocketObs {
        SocketObs {
            local: "10.88.0.2:52344".into(),
            remote: "10.88.0.3:9000".into(),
            process: Some("ncat".into()),
            rtt_ms: Some(20.0),
            rttvar_ms: Some(2.0),
            retrans: Some(12),
            cwnd: Some(10),
            ssthresh: Some(u32::MAX),
            rwnd: Some(64_000),
            mss: Some(1448),
            tx_bps: Some(2.4e6),
            rx_bps: Some(0.0),
            verdict_age_secs: 90,
        }
    }

    /// What the sampler reports once a successful dump lists no sockets.
    fn no_sockets(config: Option<ObservedConfig>) -> Observations {
        let mut o = Observations {
            config,
            ..Default::default()
        };
        for rule in [
            "tcp.bufferbloat_remote",
            "tcp.retrans_burst",
            "tcp.zero_window",
        ] {
            o.coverage_hints.insert(
                rule.into(),
                (
                    super::super::coverage::Availability::NoSubjects,
                    "successful TCP dump contained no established sockets".into(),
                ),
            );
        }
        o
    }

    /// Collector completion times `t` seconds after `start`, as a live tick
    /// sees them when every listed collector has just run.
    fn ran_at(start: std::time::Instant, t: u64) -> ObservationTimes {
        let at = start + std::time::Duration::from_secs(t);
        let mut times = ObservationTimes {
            interface: Some(at),
            sockets: Some(at),
            ..Default::default()
        };
        times.health.gateway = Some(at);
        times.health.internet = Some(at);
        times.health.gateway_target = Some("192.168.8.1".into());
        times
    }

    #[test]
    fn a_closed_socket_expires_its_retrans_issue() {
        let mut other = retransmitting();
        other.local = "10.88.0.2:52390".into();
        other.retrans = Some(0);
        // The socket closes, and the collector's next dumps say so: either
        // they list nothing at all, or they list the sockets still open.
        let empty = no_sockets(Some(ObservedConfig::default()));
        let others = Observations {
            sockets: vec![other],
            config: Some(ObservedConfig::default()),
            ..Default::default()
        };
        for closed in [empty, others] {
            let (mut e, clock) = engine_at("2026-09-03 06:48:10");
            let b = base();
            let start = std::time::Instant::now();
            let at = |t| start + std::time::Duration::from_secs(t);
            let open = Observations {
                sockets: vec![retransmitting()],
                config: Some(ObservedConfig::default()),
                ..Default::default()
            };
            e.observe_live_at(&open, &b, &ran_at(start, 0), at(0));
            let id = find(&e, "tcp.retrans_burst").id;

            for t in 1..=60 {
                clock.advance_secs(1);
                e.observe_live_at(&closed, &b, &ran_at(start, t), at(t));
            }
            let issue = e.get(&id).unwrap();
            assert_eq!(issue.state, IssueState::Open, "gone for 59 s");
            assert_eq!(issue.stale_since.as_deref(), Some("2026-09-03 06:48:11"));

            clock.advance_secs(1);
            e.observe_live_at(&closed, &b, &ran_at(start, 61), at(61));
            assert_eq!(
                e.get(&id).unwrap().state,
                expired("socket closed", "2026-09-03 06:49:11")
            );
        }
    }

    /// Outside the Dense view nothing refreshes the socket collector, so its
    /// last dump ages out. An empty list from a collector that has stopped,
    /// or one whose input the rule cannot use, is not a socket closing.
    #[test]
    fn a_socket_issue_goes_stale_when_its_collector_stops() {
        let mut unusable = no_sockets(Some(ObservedConfig::default()));
        unusable.coverage_hints.insert(
            "tcp.retrans_burst".into(),
            (
                super::super::coverage::Availability::CollectorFailed,
                "netlink dump failed".into(),
            ),
        );
        let cases = [
            (no_sockets(Some(ObservedConfig::default())), false),
            (unusable, true),
        ];
        for (closed, collector_runs) in cases {
            let (mut e, clock) = engine_at("2026-09-03 06:48:10");
            let b = base();
            let start = std::time::Instant::now();
            let at = |t| start + std::time::Duration::from_secs(t);
            let open = Observations {
                sockets: vec![retransmitting()],
                config: Some(ObservedConfig::default()),
                ..Default::default()
            };
            e.observe_live_at(&open, &b, &ran_at(start, 0), at(0));
            let id = find(&e, "tcp.retrans_burst").id;

            for t in 1..=600 {
                clock.advance_secs(1);
                let ran = if collector_runs { t } else { 0 };
                e.observe_live_at(&closed, &b, &ran_at(start, ran), at(t));
            }
            let issue = e.get(&id).unwrap();
            assert_eq!(issue.state, IssueState::Open);
            assert_eq!(issue.stale_since.as_deref(), Some("2026-09-03 06:48:11"));
        }
    }

    /// The gateway probe measures nothing when ICMP cannot be sent and no
    /// TCP port answers, and the sampler then reports no gateway at all. That
    /// is what a gateway outage looks like from a host that cannot ping, so
    /// it must never close the outage.
    #[test]
    fn an_unmeasured_gateway_never_expires_the_outage() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        let start = std::time::Instant::now();
        let at = |t| start + std::time::Duration::from_secs(t);
        let config = Some(ObservedConfig {
            resolvers: Some(vec!["169.254.1.1".into()]),
            interfaces: Some(vec!["lo".into(), "eth0".into()]),
            ..Default::default()
        });
        let down = Observations {
            gateway: Some(GatewayObs {
                addr: Some("192.168.8.1".into()),
                rtt_ms: None,
                loss_pct: 100.0,
                arp_ok: None,
                icmp_ok: false,
                internet_reachable: Some(false),
            }),
            config: config.clone(),
            ..Default::default()
        };
        e.observe_live_at(&down, &b, &ran_at(start, 0), at(0));
        let id = find(&e, "gateway.unreachable").id;

        let unmeasured = Observations {
            config,
            ..Default::default()
        };
        for t in (5..=1800).step_by(5) {
            clock.advance_secs(5);
            e.observe_live_at(&unmeasured, &b, &ran_at(start, t), at(t));
        }
        let issue = e.get(&id).unwrap();
        assert_eq!(issue.state, IssueState::Open, "half an hour unmeasured");
        assert_eq!(issue.stale_since.as_deref(), Some("2026-09-03 06:48:15"));
    }

    fn target_obs(revision: &str, refused: bool) -> crate::diagnose::targets::TargetObs {
        use crate::diagnose::targets::{Stage, StageError, TargetContext, TargetObs};
        TargetObs {
            baseline_key: Some(revision.into()),
            attempts: vec![],
            effective_endpoint: None,
            sni: None,
            http_authority: None,
            name: "api".into(),
            host: "127.0.0.1".into(),
            port: 8443,
            tls: false,
            http: false,
            expect_status: None,
            probed_at: String::new(),
            resolve: Stage {
                ms: Some(0.0),
                error: None,
            },
            addresses: vec!["127.0.0.1".into()],
            lookups: vec![],
            connect: Some(Stage {
                ms: Some(1.0),
                error: refused.then_some(StageError::Refused),
            }),
            connect_v4: None,
            connect_v6: None,
            tls_stage: None,
            http_stage: None,
            status: None,
            stale_after_secs: None,
            context: TargetContext::default(),
        }
    }

    fn targets_config(revisions: &[&str]) -> Option<ObservedConfig> {
        Some(ObservedConfig {
            targets: revisions
                .iter()
                .map(|r| ("api".to_string(), r.to_string()))
                .collect(),
            ..Default::default()
        })
    }

    #[test]
    fn a_removed_target_expires() {
        // Taken out of the config, the target is no longer probed. Edited,
        // it is probed afresh under its new revision, and that result,
        // healthy or not, says nothing about the endpoint the issue is about.
        let removed = Observations {
            config: targets_config(&[]),
            ..Default::default()
        };
        let edited = Observations {
            targets: vec![target_obs("target-config:bbbb", false)],
            config: targets_config(&["target-config:bbbb"]),
            ..Default::default()
        };
        for (after, reason) in [
            (removed, "target removed from the config"),
            (edited, "target configuration changed"),
        ] {
            let (mut e, clock) = engine_at("2026-09-03 06:48:10");
            let b = base();
            e.observe(
                &Observations {
                    targets: vec![target_obs("target-config:aaaa", true)],
                    config: targets_config(&["target-config:aaaa"]),
                    ..Default::default()
                },
                &b,
            );
            let id = find(&e, "target.connect_failed").id;
            for _ in 0..60 {
                clock.advance_secs(1);
                e.observe(&after, &b);
            }
            assert_eq!(e.get(&id).unwrap().state, IssueState::Open, "{reason}");
            clock.advance_secs(1);
            e.observe(&after, &b);
            assert_eq!(
                e.get(&id).unwrap().state,
                expired(reason, "2026-09-03 06:49:11")
            );
        }

        // Still there: a duplicated name, one of whose entries keeps the
        // revision, and an issue found with no revision to compare against.
        let mut unrevised = target_obs("", true);
        unrevised.baseline_key = None;
        for (found, after, case) in [
            (
                target_obs("target-config:aaaa", true),
                targets_config(&["target-config:bbbb", "target-config:aaaa"]),
                "duplicated name",
            ),
            (
                unrevised,
                targets_config(&["target-config:bbbb"]),
                "no revision",
            ),
        ] {
            let (mut e, clock) = engine_at("2026-09-03 06:48:10");
            let b = base();
            e.observe(
                &Observations {
                    targets: vec![found],
                    config: targets_config(&["target-config:aaaa"]),
                    ..Default::default()
                },
                &b,
            );
            let id = find(&e, "target.connect_failed").id;
            let after = Observations {
                config: after,
                ..Default::default()
            };
            for _ in 0..120 {
                clock.advance_secs(1);
                e.observe(&after, &b);
            }
            assert_eq!(e.get(&id).unwrap().state, IssueState::Open, "{case}");
        }
    }

    /// `api` refused under `revision`, the only entry the config lists.
    fn refused_under(revision: &str) -> Observations {
        Observations {
            targets: vec![target_obs(revision, true)],
            config: targets_config(&[revision]),
            ..Default::default()
        }
    }

    /// The issue that is not `old`, once there is one.
    fn other_than(e: &Engine, old: &str) -> Option<Issue> {
        e.issues().iter().find(|i| i.id != old).cloned()
    }

    /// Edited while it still fails the same way, a target's issue used to
    /// take the new detection in: same rule, same name, same key. The merge
    /// overwrote the revision it was found under, so the expiry check found
    /// that revision in the config and the issue never expired, carrying its
    /// history onto an endpoint nobody had diagnosed.
    #[test]
    fn an_edited_target_still_failing_expires_and_files_a_new_issue() {
        let (mut e, clock) = hysteresis_engine_at("2026-09-03 06:48:10");
        let b = base();
        let before = refused_under("target-config:aaaa");
        e.observe(&before, &b);
        for _ in 0..2 {
            clock.advance_secs(1);
            e.observe(&before, &b);
        }
        let old = find(&e, "target.connect_failed").id;
        // It flaps once, so it has a count. Target steps have no hotkey for
        // record_applied, so one is marked applied here as it would.
        assert!(e.resolve(&old));
        for _ in 0..3 {
            clock.advance_secs(1);
            e.observe(&before, &b);
        }
        assert_eq!(e.get(&old).unwrap().recurrence, 1);
        let issue = e.issues.iter_mut().find(|i| i.id == old).unwrap();
        issue.remediation[0].applied = Some(crate::diagnose::issue::Applied::Yes {
            at: "2026-09-03 06:48:15".into(),
            before: String::new(),
            after: String::new(),
        });

        // Edited at 06:48:16. The new revision confirms on its own samples.
        let after = refused_under("target-config:bbbb");
        for _ in 0..2 {
            clock.advance_secs(1);
            e.observe(&after, &b);
            assert!(other_than(&e, &old).is_none(), "needs three samples");
        }
        clock.advance_secs(1);
        e.observe(&after, &b);
        let new = other_than(&e, &old).expect("the edited target files its own issue");
        assert_eq!(new.state, IssueState::Open);
        assert_eq!(new.since, "2026-09-03 06:48:16");
        assert_eq!(new.recurrence, 0);
        assert!(new.remediation.iter().all(|s| s.applied.is_none()));
        assert_eq!(
            new.scope.configuration.as_deref(),
            Some("target-config:bbbb")
        );

        // The old revision is no longer probed: gone from 06:48:16.
        let old_issue = e.get(&old).unwrap();
        assert_eq!(
            old_issue.scope.configuration.as_deref(),
            Some("target-config:aaaa")
        );
        assert!(old_issue.remediation[0].applied.is_some());
        while clock.now() < parse_ts("2026-09-03 06:49:15").unwrap() {
            clock.advance_secs(1);
            e.observe(&after, &b);
        }
        assert_eq!(e.get(&old).unwrap().state, IssueState::Open);
        clock.advance_secs(1);
        e.observe(&after, &b);
        assert_eq!(
            e.get(&old).unwrap().state,
            expired("target configuration changed", "2026-09-03 06:49:16")
        );
        assert_eq!(e.get(&new.id).unwrap().state, IssueState::Open);
        let primary: Vec<_> = e.primary().into_iter().map(|i| i.id.clone()).collect();
        assert_eq!(primary, vec![new.id]);
    }

    /// Edited before its issue opens, a target starts counting again. Two
    /// samples of the old entry and one of the new are not three of either,
    /// and the issue the new entry opens starts at its own first sample.
    #[test]
    fn an_edited_target_confirms_on_its_own_samples() {
        let (mut e, clock) = hysteresis_engine_at("2026-09-03 06:48:10");
        let b = base();
        let before = refused_under("target-config:aaaa");
        e.observe(&before, &b);
        clock.advance_secs(1);
        e.observe(&before, &b);

        // Edited at 06:48:12.
        let after = refused_under("target-config:bbbb");
        clock.advance_secs(1);
        e.observe(&after, &b);
        assert!(e.issues().is_empty(), "{:#?}", e.issues());
        for _ in 0..2 {
            clock.advance_secs(1);
            e.observe(&after, &b);
        }
        let issue = find(&e, "target.connect_failed");
        assert_eq!(e.issues().len(), 1);
        assert_eq!(issue.since, "2026-09-03 06:48:12");
        assert_eq!(
            issue.scope.configuration.as_deref(),
            Some("target-config:bbbb")
        );
    }

    #[test]
    fn a_muted_target_edited_while_failing_expires_and_leaves_its_mute_behind() {
        let (mut e, clock) = hysteresis_engine_at("2026-09-03 06:48:10");
        let b = base();
        let before = refused_under("target-config:aaaa");
        e.observe(&before, &b);
        for _ in 0..2 {
            clock.advance_secs(1);
            e.observe(&before, &b);
        }
        let old = find(&e, "target.connect_failed").id;
        assert!(e.mute(&old, 60));
        let muted = e.get(&old).unwrap().state.clone();

        // Edited at 06:48:13; the new revision opens on its third sample.
        let after = refused_under("target-config:bbbb");
        for _ in 0..3 {
            clock.advance_secs(1);
            e.observe(&after, &b);
        }
        let new = other_than(&e, &old).expect("the edited target files its own issue");
        assert_eq!(
            new.state,
            IssueState::Open,
            "the mute stays with the old issue"
        );
        assert_eq!(e.get(&old).unwrap().state, muted);

        while clock.now() < parse_ts("2026-09-03 06:49:13").unwrap() {
            clock.advance_secs(1);
            e.observe(&after, &b);
        }
        assert_eq!(
            e.get(&old).unwrap().state,
            expired("target configuration changed", "2026-09-03 06:49:13")
        );
        assert_eq!(e.get(&new.id).unwrap().state, IssueState::Open);
        assert_eq!(e.primary().len(), 1);
    }

    #[test]
    fn an_edited_target_does_not_inherit_the_old_verification() {
        let (mut e, clock) = hysteresis_engine_at("2026-09-03 06:48:10");
        let b = base();
        let start = std::time::Instant::now();
        let at = |t| start + std::time::Duration::from_secs(t);
        // Probed every 10 s; each tick reads the result just published.
        let tick = |e: &mut Engine, o: &Observations, t: u64| {
            let times = ObservationTimes {
                targets: [("api".to_string(), at(t))].into_iter().collect(),
                ..Default::default()
            };
            e.observe_live_at(o, &b, &times, at(t));
        };
        let failing = refused_under("target-config:aaaa");
        let mut healthy = failing.clone();
        healthy.targets[0] = target_obs("target-config:aaaa", false);
        tick(&mut e, &failing, 0);
        for t in [10, 20] {
            clock.advance_secs(10);
            tick(&mut e, &failing, t);
        }
        let old = find(&e, "target.connect_failed").id;
        assert!(e.mark_step_done(&old, 0));

        // It recovers for two probes, so its hold is running.
        for t in [30, 40] {
            clock.advance_secs(10);
            tick(&mut e, &healthy, t);
        }
        assert!(e.verifying_since.contains_key(&old));
        assert!(e.verification_samples.contains_key(&old));

        // Edited at 06:49:00 to an entry that fails.
        let after = refused_under("target-config:bbbb");
        for t in [50, 60, 70] {
            clock.advance_secs(10);
            tick(&mut e, &after, t);
        }
        let new = other_than(&e, &old).expect("the edited target files its own issue");
        assert_eq!(new.verification, None, "the step was done on the old entry");
        assert!(!e.verifying_since.contains_key(&new.id));
        assert!(!e.verification_samples.contains_key(&new.id));
        // The old entry is not measured any more, so its hold stops.
        assert!(!e.verifying_since.contains_key(&old));
        assert!(!e.verification_samples.contains_key(&old));

        // The new entry recovers: its hold starts on its own first sample.
        let mut recovered = after.clone();
        recovered.targets[0] = target_obs("target-config:bbbb", false);
        clock.advance_secs(10);
        tick(&mut e, &recovered, 80);
        assert_eq!(
            e.verifying_since.get(&new.id).copied(),
            parse_ts("2026-09-03 06:49:30")
        );
        assert_eq!(e.verification_samples.get(&new.id), Some(&(at(80), at(80))));

        // Gone since 06:49:00, the old issue expires a minute later, and the
        // step done on it was never measured.
        for t in [90, 100, 110] {
            clock.advance_secs(10);
            tick(&mut e, &recovered, t);
        }
        let old = e.get(&old).unwrap();
        assert_eq!(
            old.state,
            expired("target configuration changed", "2026-09-03 06:50:00")
        );
        assert_eq!(
            old.verification.as_ref().and_then(|v| v.outcome),
            Some(crate::diagnose::issue::VerifyOutcome::NotMeasured)
        );
        assert!(e.get(&new.id).unwrap().state.is_open(), "held 30 s of 120");
    }

    /// Put back to the revision it was found under within the recurrence
    /// window, a target reopens its old issue. The revision is a digest of
    /// every field of the entry, so the same revision probes the same
    /// endpoint the same way: by merge()'s rule, the same problem coming back
    /// after an expiry, like a resolver that left the config and returned
    /// still slow. The revision in between is a different problem, and
    /// expires in its turn.
    #[test]
    fn a_target_edited_back_within_the_window_reopens_its_old_issue() {
        let (mut e, clock) = hysteresis_engine_at("2026-09-03 06:48:10");
        let b = base();
        let first = refused_under("target-config:aaaa");
        let second = refused_under("target-config:bbbb");
        e.observe(&first, &b);
        for _ in 0..2 {
            clock.advance_secs(1);
            e.observe(&first, &b);
        }
        let old = find(&e, "target.connect_failed").id;

        // Edited at 06:48:13: the first issue expires at 06:49:13.
        while clock.now() < parse_ts("2026-09-03 06:50:00").unwrap() {
            clock.advance_secs(1);
            e.observe(&second, &b);
        }
        assert_eq!(
            e.get(&old).unwrap().state,
            expired("target configuration changed", "2026-09-03 06:49:13")
        );
        let between = other_than(&e, &old)
            .expect("the second revision's issue")
            .id;

        // Put back at 06:50:01, it confirms again and reopens the first.
        for _ in 0..3 {
            clock.advance_secs(1);
            e.observe(&first, &b);
        }
        let reopened = e.get(&old).unwrap();
        assert_eq!(reopened.state, IssueState::Open);
        assert_eq!(reopened.recurrence, 1);
        assert_eq!(reopened.since, "2026-09-03 06:50:01");
        assert_eq!(e.issues().len(), 2, "no third issue");
        while clock.now() < parse_ts("2026-09-03 06:51:01").unwrap() {
            clock.advance_secs(1);
            e.observe(&first, &b);
        }
        assert_eq!(
            e.get(&between).unwrap().state,
            expired("target configuration changed", "2026-09-03 06:51:01")
        );
        assert!(e.get(&old).unwrap().state.is_open());
    }

    #[test]
    fn an_expiry_window_too_long_for_a_duration_never_expires() {
        // A replayed episode's settings are whatever its file says. Cast
        // straight to i64, u64::MAX was -1 s and expired on the first tick
        // gone; 1e17 s panicked out of TimeDelta::seconds.
        for secs in [u64::MAX, 100_000_000_000_000_000] {
            let (e, clock) = engine_at("2026-09-03 06:48:10");
            let settings = Settings {
                expire_after_secs: secs,
                ..*e.settings()
            };
            let mut e = e.with_settings(settings);
            let b = base();
            e.observe(
                &Observations {
                    targets: vec![target_obs("target-config:aaaa", true)],
                    config: targets_config(&["target-config:aaaa"]),
                    ..Default::default()
                },
                &b,
            );
            let id = find(&e, "target.connect_failed").id;
            let removed = Observations {
                config: targets_config(&[]),
                ..Default::default()
            };
            for _ in 0..60 {
                clock.advance_secs(60);
                e.observe(&removed, &b);
            }
            assert_eq!(e.get(&id).unwrap().state, IssueState::Open, "{secs}");
        }
    }

    #[test]
    fn a_stale_target_probe_is_stale_not_expired() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        let start = std::time::Instant::now();
        let at = |t| start + std::time::Duration::from_secs(t);
        let refused = Observations {
            targets: vec![target_obs("target-config:aaaa", true)],
            config: targets_config(&["target-config:aaaa"]),
            ..Default::default()
        };
        // The target stays configured, but its prober publishes once and
        // then stops, so its one result ages past the stale limit.
        let times = ObservationTimes {
            targets: [("api".to_string(), at(0))].into_iter().collect(),
            ..Default::default()
        };
        e.observe_live_at(&refused, &b, &times, at(0));
        let id = find(&e, "target.connect_failed").id;
        for t in (60..=3600).step_by(60) {
            clock.advance_secs(60);
            e.observe_live_at(&refused, &b, &times, at(t));
        }
        let issue = e.get(&id).unwrap();
        assert_eq!(issue.state, IssueState::Open);
        // Fresh up to 900 s, so first missing on the tick at 960 s.
        assert_eq!(issue.stale_since.as_deref(), Some("2026-09-03 07:04:10"));
    }

    #[test]
    fn stale_since_is_set_once_and_cleared_on_fresh_evidence() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        let stale = |e: &Engine| e.issues()[0].stale_since.clone();
        e.observe(&obs(40.0), &b);
        assert_eq!(stale(&e), None);

        let unmeasured = Observations::default();
        clock.advance_secs(5);
        e.observe(&unmeasured, &b);
        clock.advance_secs(5);
        e.observe(&unmeasured, &b);
        assert_eq!(stale(&e).as_deref(), Some("2026-09-03 06:48:15"));

        // The metric returns, under the verify line: measured again, so no
        // longer stale, though not yet closed.
        clock.advance_secs(5);
        e.observe(&obs(1.3), &b);
        assert_eq!(stale(&e), None);
        assert!(e.issues()[0].state.is_open());

        // Missing again, then the condition itself comes back.
        clock.advance_secs(5);
        e.observe(&unmeasured, &b);
        assert_eq!(stale(&e).as_deref(), Some("2026-09-03 06:48:30"));
        clock.advance_secs(5);
        e.observe(&obs(40.0), &b);
        assert_eq!(stale(&e), None);
        assert_eq!(e.open_count(), 1);
    }

    /// An episode recorded before the configuration was recorded replays
    /// with `config: None`. Its socket closing is the same evidence as in
    /// the tests above, but the guard reads unknown as "never expire", so
    /// the replay keeps the issue open as the recording did. The same frames
    /// with a configuration expire it.
    #[test]
    fn an_episode_without_config_never_expires() {
        use crate::diagnose::{episode, fixture};
        // The socket retransmits for 30 s, then a fresh dump lists nothing.
        fn frame(t: u64) -> Observations {
            if t < 30 {
                Observations {
                    sockets: vec![retransmitting()],
                    ..Default::default()
                }
            } else {
                no_sockets(None)
            }
        }
        let old = fixture::record(&fixture::Scenario {
            id: "socket-closes-before-0.34",
            start: "2026-09-03 06:48:10",
            secs: 240,
            baselines: base,
            obs: frame,
            cadence: fixture::Cadence::live(),
            thresholds: Thresholds::default(),
        });
        assert!(old.frames.iter().all(|f| f.obs.config.is_none()));
        let span = |replay: &episode::ReplayReport| {
            let spans: Vec<_> = replay
                .issues
                .iter()
                .filter(|s| s.key.starts_with("tcp.retrans_burst|"))
                .cloned()
                .collect();
            assert_eq!(spans.len(), 1, "{spans:?}");
            spans[0].clone()
        };

        let replayed = episode::replay(&old);
        assert!(replayed.matches(), "{:?}", replayed.divergences);
        assert_eq!(span(&replayed).closed, None);

        let mut new = old.clone();
        for f in &mut new.frames {
            f.obs.config = Some(ObservedConfig::default());
        }
        let span = span(&episode::replay(&new));
        // Gone from the frame at 30 s, expired 60 s later.
        assert_eq!(span.closed.as_deref(), Some("2026-09-03 06:49:40"));
        assert_eq!(span.close_reason.as_deref(), Some("expired"));
    }

    fn on_resolver(p50: f64, resolver: &str, listed: Option<&[&str]>) -> Observations {
        let mut o = obs(p50);
        o.dns.as_mut().unwrap().resolver = resolver.into();
        o.config = Some(ObservedConfig {
            resolvers: listed.map(|l| l.iter().map(|r| r.to_string()).collect()),
            ..Default::default()
        });
        o
    }

    #[test]
    fn a_resolver_that_left_the_config_expires() {
        let b = base();
        let old = "169.254.1.1";
        let new = "192.168.8.1";
        // The network now hands out another resolver, which answers fast.
        // Its results cannot verify the old resolver's issue.
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        e.observe(&on_resolver(40.0, old, Some(&[old])), &b);
        let id = find(&e, "dns.slow_resolver").id;
        for _ in 0..61 {
            clock.advance_secs(1);
            e.observe(&on_resolver(1.3, new, Some(&[new])), &b);
        }
        assert_eq!(
            e.get(&id).unwrap().state,
            expired("resolver left the config", "2026-09-03 06:49:11")
        );

        // A resolver list that could not be read says nothing about it.
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        e.observe(&on_resolver(40.0, old, Some(&[old])), &b);
        let id = find(&e, "dns.slow_resolver").id;
        for _ in 0..600 {
            clock.advance_secs(1);
            e.observe(&on_resolver(1.3, new, None), &b);
        }
        assert_eq!(e.get(&id).unwrap().state, IssueState::Open);
    }

    /// A resolver switched to by an applied step stands in for the old one:
    /// its answers verify the issue, so the old one leaving is the fix
    /// working, not the subject going away.
    #[test]
    fn a_resolver_switched_to_by_an_applied_step_is_a_recovery_not_an_expiry() {
        use crate::diagnose::issue::Applied;
        let b = base();
        let old = "169.254.1.1";
        let new = "192.168.8.1";
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        e.observe(&on_resolver(40.0, old, Some(&[old])), &b);
        let id = find(&e, "dns.slow_resolver").id;
        assert!(e.record_applied(
            &id,
            '1',
            Applied::Yes {
                at: "2026-09-03 06:48:10".into(),
                before: old.into(),
                after: new.into(),
            }
        ));
        for _ in 0..61 {
            clock.advance_secs(1);
            e.observe(&on_resolver(1.3, new, Some(&[new])), &b);
        }
        assert_eq!(
            e.get(&id).unwrap().state,
            IssueState::AutoClosed {
                at: "2026-09-03 06:49:11".into()
            }
        );
    }

    #[test]
    fn a_path_expires_only_when_its_periodic_trace_target_changes() {
        use crate::diagnose::detectors::{HopObs, PathObs};
        let b = base();
        let hop = |number, loss_pct| HopObs {
            number,
            ip: Some(format!("10.0.0.{number}")),
            asn: None,
            rtt_p50_ms: Some(5.0),
            rtt_p95_ms: None,
            loss_pct,
            silent: false,
        };
        let lossy = |trace: &str, every| Observations {
            paths: vec![PathObs {
                target: "1.1.1.1".into(),
                hops: vec![hop(1, 0.0), hop(2, 20.0)],
                previous: None,
                traced_at: "2026-09-03 06:48:05".into(),
                destination_reached: Some(false),
            }],
            config: Some(ObservedConfig {
                trace_target: trace.into(),
                trace_refresh_secs: every,
                ..Default::default()
            }),
            ..Default::default()
        };
        let untraced = |trace: &str, every| Observations {
            paths: vec![],
            ..lossy(trace, every)
        };
        let cases = [
            // Traced every 5 minutes, then the trace target is changed.
            (
                lossy("1.1.1.1", Some(300)),
                untraced("9.9.9.9", Some(300)),
                true,
            ),
            // Traced by hand while the periodic trace follows another
            // target: nothing will trace it again, but it has not gone.
            (
                lossy("9.9.9.9", Some(300)),
                untraced("9.9.9.9", Some(300)),
                false,
            ),
            // The target changed, but tracing is by hand from now on.
            (
                lossy("1.1.1.1", Some(300)),
                untraced("9.9.9.9", None),
                false,
            ),
        ];
        for (before, after, expires) in cases {
            let (mut e, clock) = engine_at("2026-09-03 06:48:10");
            e.observe(&before, &b);
            let id = find(&e, "path.high_loss").id;
            for _ in 0..61 {
                clock.advance_secs(1);
                e.observe(&after, &b);
            }
            let state = e.get(&id).unwrap().state.clone();
            if expires {
                assert_eq!(
                    state,
                    expired("trace target changed", "2026-09-03 06:49:11")
                );
            } else {
                assert_eq!(state, IssueState::Open, "{after:?}");
            }
        }
    }

    #[test]
    fn a_removed_interface_expires_only_on_a_fresh_collector() {
        let b = base();
        let listing = |names: &[&str]| {
            Some(ObservedConfig {
                interfaces: Some(names.iter().map(|n| n.to_string()).collect()),
                ..Default::default()
            })
        };
        let down = Observations {
            iface: Some(IfaceObs {
                carrier: Some(false),
                ..crate::diagnose::fixture::observations_at(0).iface.unwrap()
            }),
            config: listing(&["lo", "eth0"]),
            ..Default::default()
        };
        // The USB adapter is pulled: the platform stops listing it.
        let pulled = Observations {
            config: listing(&["lo"]),
            ..Default::default()
        };
        // Replugged, or brought up after `diagnose run` read the list: the
        // collector reads it while the list does not name it yet.
        let unlisted = Observations {
            iface: Some(IfaceObs {
                carrier: None,
                ..down.iface.clone().unwrap()
            }),
            config: listing(&["lo"]),
            ..Default::default()
        };
        for (after, collector_runs, gone) in [
            (&pulled, true, true),
            (&pulled, false, false),
            (&unlisted, true, false),
        ] {
            let (mut e, clock) = engine_at("2026-09-03 06:48:10");
            let start = std::time::Instant::now();
            let at = |t| start + std::time::Duration::from_secs(t);
            e.observe_live_at(&down, &b, &ran_at(start, 0), at(0));
            let id = find(&e, "link.down").id;
            for t in 1..=61 {
                clock.advance_secs(1);
                let ran = if collector_runs { t } else { 0 };
                e.observe_live_at(after, &b, &ran_at(start, ran), at(t));
            }
            let state = e.get(&id).unwrap().state.clone();
            if gone {
                assert_eq!(state, expired("interface removed", "2026-09-03 06:49:11"));
            } else {
                assert_eq!(state, IssueState::Open);
            }
        }
    }

    #[test]
    fn a_relapse_inside_the_window_resets_the_verify_clock() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        for _ in 0..50 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }
        // 50s of good, then one bad sample: the clock must restart.
        clock.advance_secs(1);
        e.observe(&obs(40.0), &b);
        for _ in 0..30 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }
        assert_eq!(
            e.open_count(),
            1,
            "30s of quiet is not the 60s the rule asks for"
        );
    }

    #[test]
    fn flapping_reads_as_one_issue_with_a_recurrence_count() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        for round in 0..3 {
            e.observe(&obs(40.0), &b);
            for _ in 0..61 {
                clock.advance_secs(1);
                e.observe(&obs(1.3), &b);
            }
            assert_eq!(e.open_count(), 0, "round {round} should have closed");
        }
        e.observe(&obs(40.0), &b);

        assert_eq!(e.issues().len(), 1, "flapping must not file four findings");
        assert_eq!(e.primary()[0].recurrence, 3);
    }

    #[test]
    fn a_return_after_the_recurrence_window_is_a_new_issue() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        for _ in 0..61 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }
        clock.advance_secs(60 * 60); // an hour later
        e.observe(&obs(40.0), &b);

        assert_eq!(e.issues().len(), 2, "an hour later is a new incident");
        assert_eq!(e.primary()[0].recurrence, 0);
    }

    /// A detector that derives its close line from the metric sends a new
    /// line with every detection. Taken every tick, the line would follow
    /// the metric and never judge it against where the issue opened.
    #[test]
    fn the_verify_condition_is_the_one_set_at_open() {
        use crate::diagnose::issue::{Subject, Verify};
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        let slow = |line: f64| {
            let mut d = Detection::new(
                "dns.slow_resolver",
                Subject::Resolver {
                    addr: "169.254.1.1".into(),
                },
            );
            d.verify = Verify::below("dns.rtt_p50", line, "ms").holding_for(60);
            d
        };
        let line = |e: &Engine| e.issues()[0].verify.threshold;
        let now = clock.now();
        e.merge(slow(10.0), now, now);
        assert_eq!(line(&e), 10.0);

        // Neither a later detection with another line nor the detector's
        // own pass, with the line it derives from the baseline, moves it.
        clock.advance_secs(5);
        let now = clock.now();
        e.merge(slow(30.0), now, now);
        clock.advance_secs(5);
        e.observe(&obs(40.0), &b);
        assert_eq!(e.issues().len(), 1, "{:#?}", e.issues());
        assert_eq!(line(&e), 10.0, "a merge keeps the line set at open");

        // Closed, and back inside the recurrence window: a reopen sets the
        // line again, as an open does.
        for _ in 0..61 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }
        assert_eq!(e.open_count(), 0);
        clock.advance_secs(60);
        let now = clock.now();
        e.merge(slow(20.0), now, now);
        assert_eq!(e.issues()[0].state, IssueState::Open);
        assert_eq!(e.issues()[0].recurrence, 1);
        assert_eq!(line(&e), 20.0);
    }

    /// The verify used to be a flat 5 ms, which a router answering in 10 to
    /// 11 ms never meets, so an issue opened on one stayed open until
    /// netwatch restarted.
    #[test]
    fn a_router_resolver_issue_can_close() {
        let mut b = base();
        b.seed("169.254.1.1", "dns.rtt_p50", 10.5, 0.3, 2000);
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        e.observe(&obs(60.0), &b);
        let id = find(&e, "dns.slow_resolver").id;
        // It opened at twice the mean, 21ms, and closes under 0.8 of that.
        let line = e.get(&id).unwrap().verify.threshold;
        assert!((line - 16.8).abs() < 1e-9, "{line}");

        // Five minutes at 18ms: under the open line, over the close line.
        for _ in 0..300 {
            clock.advance_secs(1);
            e.observe(&obs(18.0), &b);
        }
        assert_eq!(e.get(&id).unwrap().state, IssueState::Open);

        // Back to 11ms: open through the hold, closed once 60s have held.
        for _ in 0..60 {
            clock.advance_secs(1);
            e.observe(&obs(11.0), &b);
        }
        assert_eq!(e.get(&id).unwrap().state, IssueState::Open);
        clock.advance_secs(1);
        e.observe(&obs(11.0), &b);
        assert_eq!(
            e.get(&id).unwrap().state,
            IssueState::AutoClosed {
                at: "2026-09-03 06:54:11".into()
            }
        );
    }

    /// A resolver at 90 ms, give or take 10, closes under 110 ms, over the
    /// 100 ms ceiling it opened on. A p50 over the ceiling fires again and
    /// keeps the issue open, so it closes only under the ceiling.
    #[test]
    fn a_resolver_near_the_ceiling_closes_under_it() {
        let mut b = base();
        b.seed("169.254.1.1", "dns.rtt_p50", 90.0, 10.0, 2000);
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        e.observe(&obs(120.0), &b);
        let id = find(&e, "dns.slow_resolver").id;
        let line = e.get(&id).unwrap().verify.threshold;
        assert!((line - 110.0).abs() < 1e-9, "{line}");

        // Five minutes at 105ms: under the close line, over the ceiling.
        for _ in 0..300 {
            clock.advance_secs(1);
            e.observe(&obs(105.0), &b);
        }
        assert_eq!(e.get(&id).unwrap().state, IssueState::Open);

        // Just under the ceiling: closed once 60s have held.
        for _ in 0..60 {
            clock.advance_secs(1);
            e.observe(&obs(99.0), &b);
        }
        assert_eq!(e.get(&id).unwrap().state, IssueState::Open);
        clock.advance_secs(1);
        e.observe(&obs(99.0), &b);
        assert_eq!(
            e.get(&id).unwrap().state,
            IssueState::AutoClosed {
                at: "2026-09-03 06:54:11".into()
            }
        );
    }

    #[test]
    fn suppression_reaches_the_verdict_line() {
        let (mut e, _clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        let mut o = obs(40.0);
        o.gateway = Some(GatewayObs {
            addr: Some("192.168.8.1".into()),
            rtt_ms: None,
            loss_pct: 100.0,
            arp_ok: Some(true),
            icmp_ok: false,
            internet_reachable: Some(false),
        });
        e.observe(&o, &b);

        assert_eq!(
            e.open_count(),
            1,
            "dns is a consequence of the dead gateway"
        );
        let v = e.verdict(&b);
        assert!(v.line().contains("gateway unreachable"), "{}", v.line());
        assert!(v.line().contains("1 issue"), "{}", v.line());
    }

    /// A trace to 1.1.1.1 whose hop 3 moved, adding `added_ms`. Up to 20 ms
    /// that is an Info `path.changed`: an Observation.
    fn rerouted(added_ms: f64) -> Observations {
        let before = crate::diagnose::fixture::path_before();
        let mut after = before.clone();
        after[2].ip = Some("203.0.113.44".into());
        after[2].rtt_p50_ms = after[2].rtt_p50_ms.map(|r| r + added_ms);
        Observations {
            now: "2026-09-03 06:48:10".into(),
            paths: vec![crate::diagnose::detectors::PathObs {
                target: "1.1.1.1".into(),
                hops: after,
                previous: Some(before),
                traced_at: "2026-09-03 06:48:10".into(),
                destination_reached: Some(true),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn observations_alone_do_not_make_the_verdict_say_issues() {
        let (mut e, _clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&rerouted(2.0), &b);

        let listed: Vec<&str> = e.primary().iter().map(|i| i.rule.as_str()).collect();
        assert_eq!(listed, ["path.changed"], "the tab still lists it");
        assert_eq!(e.primary_observations().len(), 1);
        assert!(e.primary_issues().is_empty());
        assert_eq!(e.observation_count(), 1);
        let v = e.verdict(&b);
        assert!(!matches!(v, Verdict::Issues { .. }), "{v:?}");
        assert_eq!(v.count(), 0);
        // The line must not deny the finding the tab lists beside it.
        assert!(v.line().starts_with("no visible issues"), "{}", v.line());

        // An Issue beside it is what the verdict counts and leads with.
        let mut both = rerouted(2.0);
        both.dns = Some(dns(40.0));
        e.observe(&both, &b);
        assert_eq!(e.primary().len(), 2);
        let v = e.verdict(&b);
        assert_eq!(v.count(), 1, "{}", v.line());
        assert!(v.line().contains("slow dns resolver"), "{}", v.line());
        assert_ne!(v.severity(), Some(Severity::Info));
        assert_eq!(e.observation_count(), 1);
    }

    #[test]
    fn the_verdict_admits_when_it_has_no_baselines() {
        let (e, _clock) = engine_at("2026-09-03 06:48:10");
        let empty = BaselineStore::new(NetworkFingerprint::new("eth0", None, vec![], None));
        let v = e.verdict(&empty);
        assert!(matches!(v, Verdict::Learning { .. }));
        assert!(
            !v.line().contains("nominal"),
            "an unlearned host must not claim health: {}",
            v.line()
        );
        assert!(v.line().contains("no baseline"), "{}", v.line());
    }

    #[test]
    fn the_verdict_says_so_after_a_network_change() {
        let (e, _clock) = engine_at("2026-09-03 06:48:10");
        let mut b = base();
        b.set_network(NetworkFingerprint::new(
            "wlan0",
            Some("172.20.10.1".into()),
            vec!["172.20.10.1".into()],
            None,
        ));
        let line = e.verdict(&b).line();
        assert!(line.contains("new network"), "{line}");
        assert!(line.contains("wlan0"), "{line}");
    }

    #[test]
    fn the_chip_never_calls_an_unlearned_host_nominal() {
        let (e, _clock) = engine_at("2026-09-03 06:48:10");
        let empty = BaselineStore::new(NetworkFingerprint::new("eth0", None, vec![], None));
        assert_eq!(e.verdict(&empty).chip(), "learning");
        assert_eq!(e.verdict(&base()).chip(), "limited");

        let theme = crate::theme::by_name("default");
        assert_ne!(
            e.verdict(&empty).color(&theme),
            theme.status_good,
            "learning must not render as health"
        );
        assert_ne!(e.verdict(&base()).color(&theme), theme.status_good);
    }

    #[test]
    fn disappearing_measurement_does_not_close_issue_and_resets_recovery() {
        let (mut engine, clock) = engine_at("2026-09-03 06:48:10");
        let base = base();
        engine.observe(&obs(40.0), &base);
        let id = engine.primary()[0].id.clone();
        engine.observe(&obs(1.0), &base);
        clock.advance_secs(40);
        engine.observe(&Observations::default(), &base);
        clock.advance_secs(600);
        engine.observe(&Observations::default(), &base);
        assert!(engine.get(&id).unwrap().state.is_open());
        engine.observe(&obs(1.0), &base);
        clock.advance_secs(40);
        engine.observe(&obs(1.0), &base);
        assert!(engine.get(&id).unwrap().state.is_open());
        clock.advance_secs(21);
        engine.observe(&obs(1.0), &base);
        assert!(!engine.get(&id).unwrap().state.is_open());
    }

    /// Interface info that goes missing, as it does when a USB adapter is
    /// pulled, is not the link coming back. link.down verifies only on a
    /// carrier that was read.
    #[test]
    fn an_unknown_carrier_does_not_close_link_down() {
        let (mut engine, clock) = engine_at("2026-09-03 06:48:10");
        let base = base();
        let link = |carrier| Observations {
            iface: Some(IfaceObs {
                carrier,
                ..crate::diagnose::fixture::observations_at(0).iface.unwrap()
            }),
            ..Default::default()
        };
        assert!(!metric_values(&link(None)).contains_key("iface.carrier"));
        engine.observe(&link(Some(false)), &base);
        let id = engine.primary()[0].id.clone();
        for _ in 0..10 {
            clock.advance_secs(10);
            engine.observe(&link(None), &base);
        }
        assert!(engine.get(&id).unwrap().state.is_open());
        engine.observe(&link(Some(true)), &base);
        clock.advance_secs(31);
        engine.observe(&link(Some(true)), &base);
        assert!(!engine.get(&id).unwrap().state.is_open());
    }

    #[test]
    fn another_resolvers_results_cannot_verify_original_issue() {
        let (mut engine, clock) = engine_at("2026-09-03 06:48:10");
        let base = base();
        engine.observe(&obs(40.0), &base);
        let id = engine.primary()[0].id.clone();
        let mut replacement = obs(1.0);
        replacement.dns.as_mut().unwrap().resolver = "203.0.113.1".into();
        engine.observe(&replacement, &base);
        clock.advance_secs(600);
        engine.observe(&replacement, &base);
        assert!(engine.get(&id).unwrap().state.is_open());
    }

    #[test]
    fn stale_probe_cannot_open_or_close_an_issue() {
        let (mut engine, clock) = engine_at("2026-09-03 06:48:10");
        let base = base();
        let times = ObservationTimes {
            health: crate::collectors::health::ProbeTimes {
                dns: Some(std::time::Instant::now() - std::time::Duration::from_secs(31)),
                ..Default::default()
            },
            ..Default::default()
        };
        engine.observe_live(&obs(40.0), &base, &times);
        assert_eq!(engine.open_count(), 0);
        assert_eq!(
            engine
                .coverage()
                .rules
                .iter()
                .find(|r| r.rule == "dns.slow_resolver")
                .unwrap()
                .status,
            super::super::coverage::Availability::Stale
        );
        engine.observe(&obs(40.0), &base);
        let id = engine.primary()[0].id.clone();
        engine.observe_live(&obs(1.0), &base, &times);
        clock.advance_secs(600);
        engine.observe_live(&obs(1.0), &base, &times);
        assert!(engine.get(&id).unwrap().state.is_open());
    }

    #[test]
    fn one_targets_probes_cannot_confirm_or_recover_another_targets_issue() {
        // Every `target.*` rule used to read one shared "newest completion"
        // across all targets. A target on a 10s interval therefore supplied
        // samples for an issue about a target on a 5-minute one: it confirmed
        // the finding, and then ran down its recovery hold, against a cached
        // result nobody had re-measured.
        use crate::diagnose::targets::{Stage, StageError, TargetContext, TargetObs};
        let (mut e, _clock) = hysteresis_engine_at("2026-09-15 10:00:00");
        let b = base();
        let target = |name: &str, refused: bool| TargetObs {
            baseline_key: None,
            attempts: vec![],
            effective_endpoint: None,
            sni: None,
            http_authority: None,
            stale_after_secs: Some(600),
            name: name.into(),
            host: "127.0.0.1".into(),
            port: 8443,
            tls: false,
            http: false,
            expect_status: None,
            probed_at: String::new(),
            resolve: Stage {
                ms: Some(0.0),
                error: None,
            },
            addresses: vec!["127.0.0.1".into()],
            lookups: vec![],
            connect: Some(Stage {
                ms: Some(1.0),
                error: refused.then_some(StageError::Refused),
            }),
            connect_v4: None,
            connect_v6: None,
            tls_stage: None,
            http_stage: None,
            status: None,
            context: TargetContext::default(),
        };
        let start = std::time::Instant::now();
        let at = |secs: u64| start + std::time::Duration::from_secs(secs);
        // "slow" is refused throughout and probed once; "fast" is healthy and
        // probed every 10 seconds.
        let tick = |e: &mut Engine, slow_probe: u64, fast_probe: u64, secs: u64| {
            let times = ObservationTimes {
                targets: [
                    ("slow".to_string(), at(slow_probe)),
                    ("fast".to_string(), at(fast_probe)),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            };
            e.observe_live_at(
                &Observations {
                    targets: vec![target("slow", true), target("fast", false)],
                    ..Default::default()
                },
                &b,
                &times,
                at(secs),
            );
        };

        // Three probes of "fast" while "slow" has published once: not enough
        // to confirm an issue about "slow".
        tick(&mut e, 0, 0, 0);
        tick(&mut e, 0, 10, 10);
        tick(&mut e, 0, 20, 20);
        assert_eq!(
            e.open_count(),
            0,
            "another target's probes cannot confirm this one"
        );

        // "slow" publishes twice more and the issue opens on its own samples.
        tick(&mut e, 60, 60, 60);
        tick(&mut e, 120, 120, 120);
        assert_eq!(e.open_count(), 1);
        let id = e.primary()[0].id.clone();
        assert_eq!(e.get(&id).unwrap().subject.label(), "slow");

        // "slow" now looks healthy, but only "fast" keeps probing. The
        // recovery hold must not run down on another target's cadence.
        let healthy_tick = |e: &mut Engine, slow_probe: u64, fast_probe: u64, secs: u64| {
            let times = ObservationTimes {
                targets: [
                    ("slow".to_string(), at(slow_probe)),
                    ("fast".to_string(), at(fast_probe)),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            };
            e.observe_live_at(
                &Observations {
                    targets: vec![target("slow", false), target("fast", false)],
                    ..Default::default()
                },
                &b,
                &times,
                at(secs),
            );
        };
        healthy_tick(&mut e, 180, 180, 180);
        for secs in [240, 300, 360, 420, 480] {
            healthy_tick(&mut e, 180, secs, secs);
        }
        assert!(
            e.get(&id).unwrap().state.is_open(),
            "only one probe of this target has shown recovery, whatever the other target did"
        );

        // Its own probes then hold the condition and it closes.
        for secs in [540, 600, 660, 720] {
            healthy_tick(&mut e, secs, secs, secs);
        }
        assert!(!e.get(&id).unwrap().state.is_open());
    }

    #[test]
    fn cached_probe_does_not_complete_verification_without_a_new_result() {
        let (mut engine, clock) = engine_at("2026-09-03 06:48:10");
        let base = base();
        engine.observe(&obs(40.0), &base);
        let id = engine.primary()[0].id.clone();
        let mut times = ObservationTimes {
            health: crate::collectors::health::ProbeTimes {
                dns: Some(std::time::Instant::now()),
                ..Default::default()
            },
            ..Default::default()
        };
        engine.observe_live(&obs(1.0), &base, &times);
        clock.advance_secs(90);
        engine.observe_live(&obs(1.0), &base, &times);
        assert!(engine.get(&id).unwrap().state.is_open());
        times.health.dns = Some(times.health.dns.unwrap() + std::time::Duration::from_nanos(1));
        engine.observe_live(&obs(1.0), &base, &times);
        assert!(
            engine.get(&id).unwrap().state.is_open(),
            "wall clock jumps cannot satisfy a hold"
        );
        for _ in 0..3 {
            times.health.dns = Some(times.health.dns.unwrap() + std::time::Duration::from_secs(20));
            engine.observe_live(&obs(1.0), &base, &times);
        }
        assert!(!engine.get(&id).unwrap().state.is_open());
    }

    #[test]
    fn missing_gateway_corroboration_does_not_open_a_finding() {
        let (mut engine, _) = engine_at("2026-09-03 06:48:10");
        let mut observations = Observations {
            gateway: Some(super::super::detectors::GatewayObs {
                addr: Some("192.0.2.1".into()),
                rtt_ms: None,
                loss_pct: 100.0,
                internet_reachable: None,
                arp_ok: Some(false),
                icmp_ok: false,
            }),
            ..Default::default()
        };
        engine.observe(&observations, &base());
        assert_eq!(engine.open_count(), 0);
        observations.gateway.as_mut().unwrap().internet_reachable = Some(false);
        engine.observe(&observations, &base());
        assert!(engine
            .issues()
            .iter()
            .any(|i| i.rule == "gateway.unreachable"));
    }

    #[test]
    fn a_gap_between_probe_completions_restarts_recovery() {
        let (mut engine, _) = engine_at("2026-09-03 06:48:10");
        let base = base();
        engine.observe(&obs(40.0), &base);
        let id = engine.primary()[0].id.clone();
        let mut times = ObservationTimes::default();
        let start = std::time::Instant::now();
        for seconds in [0, 20, 80, 100, 120] {
            times.health.dns = Some(start + std::time::Duration::from_secs(seconds));
            engine.observe_live(&obs(1.0), &base, &times);
            assert!(engine.get(&id).unwrap().state.is_open());
        }
        times.health.dns = Some(start + std::time::Duration::from_secs(140));
        engine.observe_live(&obs(1.0), &base, &times);
        assert!(!engine.get(&id).unwrap().state.is_open());
    }

    #[test]
    fn a_clear_verdict_is_one_quiet_line() {
        let (e, _clock) = engine_at("2026-09-03 06:48:10");
        assert_eq!(
            e.verdict(&base()).line(),
            "no visible issues · coverage not recorded"
        );
    }

    #[test]
    fn muted_issues_leave_the_verdict_line_but_stay_in_the_list() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        assert!(e.mute(&id, 60));
        clock.advance_secs(5);
        e.observe(&obs(40.0), &b);

        assert!(e.verdict(&b).is_clear(), "a muted issue must not shout");
        assert_eq!(e.muted_count(), 1, "the verdict says what it left out");
        assert_eq!(e.issues().len(), 1, "but it is still on the Diagnose tab");
        assert_eq!(
            e.get(&id).unwrap().state.muted_until(),
            Some("2026-09-03 07:48:10")
        );
    }

    /// Muting used to make an issue look closed to the engine. Its condition,
    /// still firing, went back through hysteresis and filed a second issue
    /// beside it after `consecutive_n` samples, while the first read "muted
    /// until" long after its mute had ended.
    #[test]
    fn a_muted_condition_stays_one_issue() {
        let (mut e, clock) = hysteresis_engine_at("2026-09-03 06:48:10");
        let b = base();
        for _ in 0..3 {
            e.observe(&obs(40.0), &b);
            clock.advance_secs(5);
        }
        let id = e.primary()[0].id.clone();
        assert!(e.mute(&id, 60));

        // Ten minutes more of the same fault.
        for _ in 0..120 {
            e.observe(&obs(38.0), &b);
            clock.advance_secs(5);
        }
        assert_eq!(e.issues().len(), 1, "{:#?}", e.issues());
        let issue = e.get(&id).unwrap();
        assert!(matches!(issue.state, IssueState::Muted { .. }));
        assert_eq!(e.open_count(), 0);
        assert!(e.verdict(&b).is_clear());
        // The evidence keeps arriving, quietly.
        assert_eq!(issue.last_seen, "2026-09-03 06:58:20");
        assert_eq!(issue.headline().unwrap().value, 38.0);
    }

    #[test]
    fn a_mute_ends_at_its_time() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        assert!(e.mute(&id, 60));

        for _ in 0..59 {
            clock.advance_secs(60);
            e.observe(&obs(40.0), &b);
        }
        assert!(matches!(
            e.get(&id).unwrap().state,
            IssueState::Muted { .. }
        ));

        // 07:48:10: the hour is up and the resolver is still slow.
        clock.advance_secs(60);
        e.observe(&obs(40.0), &b);
        assert_eq!(e.issues().len(), 1);
        let issue = e.get(&id).unwrap();
        assert_eq!(issue.state, IssueState::Open);
        assert_eq!(issue.recurrence, 0, "the same incident, not a return");
        assert_eq!(issue.since, "2026-09-03 06:48:10");
        assert!(!e.verdict(&b).is_clear());
        assert_eq!(e.muted_count(), 0);

        // It ends on the clock, not on a detection: a mute that runs out
        // while nothing fires is over too.
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        assert!(e.mute(&id, 1));
        clock.advance_secs(60);
        e.observe(&Observations::default(), &b);
        assert_eq!(e.get(&id).unwrap().state, IssueState::Open);
    }

    /// A zone whose clocks go back at 01:00 UTC on 25 October 2026, as
    /// London's do, so wall time 01:00 to 02:00 happens twice that night.
    #[derive(Clone, Copy, Debug)]
    struct ClocksGoBack;

    impl ClocksGoBack {
        const SUMMER: i32 = 3_600;
        fn change() -> chrono::NaiveDateTime {
            chrono::NaiveDate::from_ymd_opt(2026, 10, 25)
                .and_then(|d| d.and_hms_opt(1, 0, 0))
                .unwrap()
        }
        fn offset(secs: i32) -> chrono::FixedOffset {
            chrono::FixedOffset::east_opt(secs).unwrap()
        }
    }

    impl TimeZone for ClocksGoBack {
        type Offset = chrono::FixedOffset;
        fn from_offset(_: &chrono::FixedOffset) -> Self {
            ClocksGoBack
        }
        fn offset_from_local_date(
            &self,
            _: &chrono::NaiveDate,
        ) -> chrono::LocalResult<chrono::FixedOffset> {
            unreachable!("mute_over reads date-times")
        }
        fn offset_from_local_datetime(
            &self,
            local: &chrono::NaiveDateTime,
        ) -> chrono::LocalResult<chrono::FixedOffset> {
            let (summer, winter) = (Self::offset(Self::SUMMER), Self::offset(0));
            if *local < Self::change() {
                chrono::LocalResult::Single(summer)
            } else if *local < Self::change() + Duration::hours(1) {
                chrono::LocalResult::Ambiguous(summer, winter)
            } else {
                chrono::LocalResult::Single(winter)
            }
        }
        fn offset_from_utc_date(&self, _: &chrono::NaiveDate) -> chrono::FixedOffset {
            unreachable!("mute_over reads date-times")
        }
        fn offset_from_utc_datetime(&self, utc: &chrono::NaiveDateTime) -> chrono::FixedOffset {
            Self::offset(if *utc < Self::change() {
                Self::SUMMER
            } else {
                0
            })
        }
    }

    /// A mute set at 01:10 summer time ends at 01:10 winter time, a stamp
    /// that names two instants. Read as neither, it ended on the next tick.
    #[test]
    fn a_mute_into_the_hour_the_clocks_go_back_lasts_its_hour() {
        let muted_at = ClocksGoBack
            .from_local_datetime(&ClocksGoBack::change())
            .earliest()
            .unwrap()
            + Duration::minutes(10);
        let until = (muted_at + Duration::hours(1))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        assert_eq!(until, "2026-10-25 01:10:00");

        assert!(!mute_over(&until, &muted_at));
        assert!(!mute_over(&until, &(muted_at + Duration::minutes(59))));
        assert!(mute_over(&until, &(muted_at + Duration::hours(1))));
        // A stamp that does not parse still ends the mute.
        assert!(mute_over("07:48", &muted_at));
    }

    #[test]
    fn a_muted_issue_still_closes_when_verify_holds() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        assert!(e.mute(&id, 60));

        // Against this baseline dns.slow_resolver closes once p50 has held
        // under 4.96ms, 0.8 of its 6.2ms open line, for 60s.
        for _ in 0..61 {
            clock.advance_secs(1);
            e.observe(&obs(1.3), &b);
        }
        assert!(
            matches!(e.get(&id).unwrap().state, IssueState::AutoClosed { .. }),
            "{:?}",
            e.get(&id).unwrap().state
        );
        assert_eq!(e.muted_count(), 0);
    }

    #[test]
    fn a_muted_socket_issue_still_expires() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        let start = std::time::Instant::now();
        let at = |t| start + std::time::Duration::from_secs(t);
        let open = Observations {
            sockets: vec![retransmitting()],
            config: Some(ObservedConfig::default()),
            ..Default::default()
        };
        e.observe_live_at(&open, &b, &ran_at(start, 0), at(0));
        let id = find(&e, "tcp.retrans_burst").id;
        assert!(e.mute(&id, 60));

        let closed = no_sockets(Some(ObservedConfig::default()));
        for t in 1..=61 {
            clock.advance_secs(1);
            e.observe_live_at(&closed, &b, &ran_at(start, t), at(t));
        }
        assert_eq!(
            e.get(&id).unwrap().state,
            expired("socket closed", "2026-09-03 06:49:11")
        );
    }

    /// A mute is the user asking for quiet, not a fix. It used to count as
    /// a close, so a step marked done before it was credited with a recovery
    /// on the next tick.
    #[test]
    fn a_mute_after_a_step_is_not_a_recovery() {
        use crate::diagnose::issue::VerifyOutcome;
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        assert!(e.mark_step_done(&id, 0));
        assert!(e.mute(&id, 60));
        clock.advance_secs(1);
        e.observe(&obs(40.0), &b);
        let v = e.get(&id).unwrap().verification.clone().unwrap();
        assert_eq!(v.outcome, None);

        // Past the verify hold and its grace, still slow: it did not work.
        clock.advance_secs(60 + VERIFY_GRACE_SECS);
        e.observe(&obs(40.0), &b);
        let v = e.get(&id).unwrap().verification.clone().unwrap();
        assert_eq!(v.outcome, Some(VerifyOutcome::NotRecovered));
    }

    #[test]
    fn a_muted_issue_is_not_pruned_as_history() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        e.settings.history_limit = 0;
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        assert!(e.mute(&id, 60));
        clock.advance_secs(5);
        e.observe(&obs(40.0), &b);
        assert_eq!(e.issues().len(), 1, "a muted issue is still tracked");
        assert!(e.get(&id).is_some());
    }

    /// The root is what the verdict names, so it is what gets muted. Muting
    /// it released its consequences, and for the hour a symptom led the
    /// verdict while its cause was hidden.
    #[test]
    fn muting_a_root_keeps_its_consequences_suppressed() {
        let (mut e, clock) = hysteresis_engine_at("2026-09-03 06:48:10");
        let b = base();
        let mut o = obs(40.0);
        o.gateway = Some(GatewayObs {
            addr: Some("192.168.8.1".into()),
            rtt_ms: None,
            loss_pct: 100.0,
            arp_ok: Some(true),
            icmp_ok: false,
            internet_reachable: Some(false),
        });
        for _ in 0..3 {
            e.observe(&o, &b);
            clock.advance_secs(5);
        }
        let root = find(&e, "gateway.unreachable").id;
        assert_eq!(e.open_count(), 1);
        assert!(e.mute(&root, 60));

        // Ten minutes more of the same fault.
        for _ in 0..120 {
            e.observe(&o, &b);
            clock.advance_secs(5);
        }
        assert_eq!(e.issues().len(), 2, "{:#?}", e.issues());
        let dns = find(&e, "dns.slow_resolver");
        assert_eq!(dns.suppressed_by.as_deref(), Some(root.as_str()));
        assert_eq!(e.get(&root).unwrap().consequences, vec![dns.id.clone()]);
        assert_eq!(e.open_count(), 0, "{:?}", e.primary());
        assert!(e.verdict(&b).is_clear(), "{}", e.verdict(&b).line());
        assert_eq!(e.muted_count(), 1);
    }

    #[test]
    fn acking_keeps_an_issue_open() {
        let (mut e, _clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        assert!(e.ack(&id));
        assert_eq!(e.open_count(), 1);
        assert_eq!(e.get(&id).unwrap().state.label(), "acked");
    }

    #[test]
    fn an_applied_step_survives_the_next_tick() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        e.observe(&obs(40.0), &b);
        let id = e.primary()[0].id.clone();
        assert!(e.record_applied(
            &id,
            '1',
            super::super::issue::Applied::Yes {
                at: "2026-09-03 06:52:00".into(),
                before: "169.254.1.1".into(),
                after: "192.168.8.1".into(),
            }
        ));

        clock.advance_secs(1);
        e.observe(&obs(40.0), &b);
        let step = e
            .get(&id)
            .unwrap()
            .remediation
            .iter()
            .find(|s| s.key == Some('1'))
            .unwrap();
        assert!(
            step.applied.is_some(),
            "a detector re-emitting its steps must not erase what the user did"
        );
    }

    #[test]
    fn worst_socket_rtt_keeps_an_issue_open_until_every_socket_clears() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        let b = base();
        let socket = |rtt: f64, age: u64| SocketObs {
            local: "10.88.0.2:52344".into(),
            remote: "10.88.0.3:9000".into(),
            process: Some("ncat".into()),
            rtt_ms: Some(rtt),
            rttvar_ms: Some(10.0),
            retrans: Some(12),
            cwnd: Some(10),
            ssthresh: Some(u32::MAX),
            rwnd: Some(64_000),
            mss: Some(1448),
            tx_bps: Some(2.4e6),
            rx_bps: Some(0.0),
            verdict_age_secs: age,
        };
        let mut o = Observations {
            sockets: vec![socket(184.0, 90)],
            idle_rtt_ms: Some(12.0),
            loaded_rtt_ms: Some(18.0),
            ..Default::default()
        };
        e.observe(&o, &b);
        assert_eq!(e.open_count(), 1);

        // Socket recovers but is still above the verify threshold.
        o.sockets = vec![socket(120.0, 90)];
        for _ in 0..70 {
            clock.advance_secs(1);
            e.observe(&o, &b);
        }
        assert_eq!(e.open_count(), 1, "120ms still fails verify (< 100ms)");
    }

    #[test]
    fn closed_issue_history_is_bounded() {
        let (mut e, clock) = engine_at("2026-09-03 06:48:10");
        e.settings.history_limit = 3;
        let b = base();
        for _ in 0..8 {
            e.observe(&obs(40.0), &b);
            for _ in 0..61 {
                clock.advance_secs(1);
                e.observe(&obs(1.3), &b);
            }
            // Push past the recurrence window so each round is a new issue.
            clock.advance_secs(31 * 60);
        }
        let closed = e.issues().iter().filter(|i| !i.state.is_open()).count();
        assert!(
            closed <= 3,
            "history limit not enforced: {closed} closed issues"
        );
    }

    /// The verify reads `gateway.rtt_sigma`, scored against the same floored
    /// σ as the open. Scored raw, a 0.9ms gateway with σ 0.05 that settles
    /// at 1.3ms would sit at 8σ and its issue would never close.
    #[test]
    fn a_gateway_back_inside_the_floor_closes() {
        let gw = "192.168.8.1";
        let mut b = base();
        b.seed(gw, "gateway.rtt", 0.9, 0.05, 2000);
        let (mut e, clock) = engine_at("2026-09-03 06:00:00");
        let gateway = |rtt: f64| Observations {
            gateway: Some(GatewayObs {
                addr: Some(gw.into()),
                rtt_ms: Some(rtt),
                loss_pct: 0.0,
                arp_ok: Some(true),
                icmp_ok: true,
                internet_reachable: Some(true),
            }),
            ..Default::default()
        };
        let state = |e: &Engine| {
            e.issues()
                .iter()
                .find(|i| i.rule == "gateway.rtt_spike")
                .map(|i| i.state.clone())
        };
        e.observe(&gateway(12.0), &b);
        assert_eq!(
            state(&e),
            Some(IssueState::Open),
            "22.2σ over the floor, and 11.1ms slower"
        );

        for _ in 0..=24 {
            clock.advance_secs(5);
            e.observe(&gateway(1.3), &b);
        }
        assert!(
            matches!(state(&e), Some(IssueState::AutoClosed { .. })),
            "0.8σ held for 120s: {:?}",
            state(&e)
        );
    }

    /// A wireless gateway at 4ms, give or take 4: 3σ is 16ms, which is 12ms
    /// slower and clears the delta floor, and 2σ is 12ms.
    fn wireless_gateway() -> BaselineStore {
        let mut b = base();
        b.seed("192.168.8.1", "gateway.rtt", 4.0, 4.0, 2000);
        b
    }

    /// That gateway answering `sigma` σ above its mean.
    fn gateway_at_sigma(sigma: f64) -> Observations {
        Observations {
            gateway: Some(GatewayObs {
                addr: Some("192.168.8.1".into()),
                rtt_ms: Some(4.0 + sigma * 4.0),
                loss_pct: 0.0,
                arp_ok: Some(true),
                icmp_ok: true,
                internet_reachable: Some(true),
            }),
            ..Default::default()
        }
    }

    fn gateway_rtt_issues(e: &Engine) -> Vec<Issue> {
        e.issues()
            .iter()
            .filter(|i| i.rule == "gateway.rtt_spike")
            .cloned()
            .collect()
    }

    /// The open and close lines used to be the same 3σ. A gateway hovering at
    /// the line closed each time it sat just under it for the 120 s hold,
    /// and reopened each time it rose back, so one condition read as a run of
    /// recoveries. The dips here outlast the hold: alternating sample by
    /// sample never closed even at 3σ/3σ, because each detection restarts
    /// the hold.
    #[test]
    fn a_gateway_rtt_hovering_at_three_sigma_does_not_flap() {
        let b = wireless_gateway();
        let hover = |close_k: f64| {
            let (e, clock) = hysteresis_engine_at("2026-09-03 06:00:00");
            let mut settings = *e.settings();
            settings.thresholds.sigma_close_k = close_k;
            let mut e = e.with_settings(settings);
            for _ in 0..3 {
                // 30 s at 3.1σ, then 3 minutes at 2.9σ.
                for sigma in [3.1; 6].into_iter().chain([2.9; 36]) {
                    e.observe(&gateway_at_sigma(sigma), &b);
                    clock.advance_secs(5);
                }
            }
            gateway_rtt_issues(&e)
        };

        let issues = hover(2.0);
        assert_eq!(issues.len(), 1, "{issues:#?}");
        assert_eq!(issues[0].state, IssueState::Open);
        assert_eq!(issues[0].recurrence, 0);

        // With the close line on the open line, the same gateway closes after
        // every dip and reopens after every rise.
        let flapping = hover(3.0);
        assert_eq!(flapping.len(), 1, "{flapping:#?}");
        assert_eq!(flapping[0].recurrence, 2);
        assert!(matches!(flapping[0].state, IssueState::AutoClosed { .. }));
    }

    #[test]
    fn gateway_rtt_spike_closes_below_two_sigma() {
        let b = wireless_gateway();
        let (mut e, clock) = engine_at("2026-09-03 06:00:00");
        e.observe(&gateway_at_sigma(4.0), &b);
        let issues = gateway_rtt_issues(&e);
        assert_eq!(issues[0].state, IssueState::Open, "20ms is 4σ, 16ms slower");
        assert_eq!(issues[0].verify.threshold, 2.0);

        // Five minutes at 2.1σ: under the open line, over the close line.
        for _ in 0..60 {
            clock.advance_secs(5);
            e.observe(&gateway_at_sigma(2.1), &b);
        }
        assert_eq!(gateway_rtt_issues(&e)[0].state, IssueState::Open);

        // 1.9σ held for the 120 s verify.
        for _ in 0..=24 {
            clock.advance_secs(5);
            e.observe(&gateway_at_sigma(1.9), &b);
        }
        let issues = gateway_rtt_issues(&e);
        assert_eq!(issues.len(), 1);
        assert!(
            matches!(issues[0].state, IssueState::AutoClosed { .. }),
            "{:?}",
            issues[0].state
        );
    }

    /// A gateway that stays slow for 25 minutes must stay one open issue for
    /// all 25 minutes, whatever the probe cadence. Before learning was gated
    /// and ordered after evaluation, the EWMA absorbed the slowdown within a
    /// few minutes and the issue auto-closed while the user still had it.
    #[test]
    fn a_sustained_slowdown_is_not_learned_away() {
        for step in [2.0_f64, 25.0] {
            let gw = "192.168.8.1";
            let mut b = BaselineStore::new(NetworkFingerprint::new(
                "eth0",
                Some(gw.into()),
                vec!["169.254.1.1".into()],
                None,
            ));
            let (mut e, clock) = engine_at("2026-09-03 06:00:00");
            let gateway = |rtt: f64| Observations {
                now: "2026-09-03 06:48:10".into(),
                gateway: Some(GatewayObs {
                    addr: Some(gw.into()),
                    rtt_ms: Some(rtt),
                    loss_pct: 0.0,
                    arp_ok: Some(true),
                    icmp_ok: true,
                    internet_reachable: Some(true),
                }),
                ..Default::default()
            };

            // An hour of a healthy ~2ms gateway, in the same order as the
            // live tick: evaluate, then learn.
            let mut t = 0.0;
            let mut i = 0u32;
            while t < 3_600.0 {
                let rtt = if i.is_multiple_of(2) { 1.7 } else { 2.3 };
                e.observe(&gateway(rtt), &b);
                b.observe(gw, "gateway.rtt", rtt, t);
                clock.advance_secs(step as i64);
                t += step;
                i += 1;
            }
            assert!(
                b.get(gw, "gateway.rtt").is_some(),
                "baseline ready at step {step}"
            );

            let mut open_since = None;
            while t < 3_600.0 + 25.0 * 60.0 {
                e.observe(&gateway(82.0), &b);
                b.observe(gw, "gateway.rtt", 82.0, t);
                let open = e
                    .issues()
                    .iter()
                    .any(|i| i.rule == "gateway.rtt_spike" && i.state.is_open());
                match (open, open_since) {
                    (true, None) => open_since = Some(t),
                    (false, Some(since)) => panic!(
                        "step {step}s: issue closed {:.0}s into the slowdown",
                        t - since
                    ),
                    _ => {}
                }
                clock.advance_secs(step as i64);
                t += step;
            }
            assert!(
                open_since.is_some(),
                "step {step}s: the slowdown never opened an issue"
            );
        }
    }
}
