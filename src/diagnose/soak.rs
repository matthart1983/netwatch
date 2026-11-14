//! False-alert accounting over a soak's recordings.
//!
//! A soak is netwatch left running on an ordinary network with the recorder
//! in [`super::episode::Recorder::continuous`] mode, so every monitored
//! second is on disk. This module turns those recordings into the two
//! numbers a rule's maturity rests on: how long each host was watched, and
//! how many times each rule opened while it was.
//!
//! It counts opens twice. *Recorded* opens are what the engine did on the
//! day. *Replayed* opens are what today's engine does with the same frames,
//! which is the number that matters after a rule changes: quiet weeks are
//! earned once and re-checked in seconds.
//!
//! ## What it cannot say
//!
//! Whether an open was *false*. Nothing in a recording knows the truth. The
//! optional witness log is a second, independent opinion (plain pings and
//! lookups, see `tests/soak/witness.py`), and an open is sorted by whether
//! the witness saw trouble near it:
//!
//! - `corroborated`: the witness saw trouble too. Probably a real fault.
//! - `unexplained`: the witness was watching and saw nothing. A candidate
//!   false open, to be looked at by a person.
//! - `unwitnessed`: no witness sample near it.
//!
//! The witness cannot see everything a rule can (a socket's rtt, a route
//! change), so `unexplained` is an upper bound on false opens, not a count.

use super::episode::{self, Episode, EpisodeSource};
use super::rules;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Two frames further apart than this were not continuous monitoring: the
/// host slept, or the recorder was stopped. The gap is not counted.
pub const MAX_FRAME_GAP_SECS: f64 = 10.0;
/// How long before an open the witness may have seen trouble and still
/// corroborate it. Rules wait for three probe completions before opening.
pub const WITNESS_BEFORE_SECS: f64 = 180.0;
/// And how long after.
pub const WITNESS_AFTER_SECS: f64 = 60.0;
/// A witness lookup slower than this is trouble.
pub const WITNESS_DNS_SLOW_MS: f64 = 400.0;
/// A witness gateway ping this far above the log's own median is trouble.
pub const WITNESS_GATEWAY_DELTA_MS: f64 = 10.0;
pub const SECS_PER_WEEK: f64 = 7.0 * 86_400.0;

/// One line of the witness log.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct WitnessSample {
    /// Unix seconds.
    pub at: f64,
    /// Whether the default gateway answered a ping. `None` when the witness
    /// found no gateway to ask.
    #[serde(default)]
    pub gateway_ok: Option<bool>,
    #[serde(default)]
    pub gateway_ms: Option<f64>,
    /// Public addresses pinged, and how many answered.
    #[serde(default)]
    pub anchors: u32,
    #[serde(default)]
    pub anchors_ok: u32,
    #[serde(default)]
    pub dns_ok: Option<bool>,
    #[serde(default)]
    pub dns_ms: Option<f64>,
    #[serde(default)]
    pub link_up: Option<bool>,
}

/// The witness log, with the median it judges gateway latency against.
#[derive(Debug, Clone, Default)]
pub struct Witness {
    samples: Vec<WitnessSample>,
    gateway_median_ms: Option<f64>,
}

impl Witness {
    pub fn new(mut samples: Vec<WitnessSample>) -> Self {
        samples.sort_by(|a, b| a.at.total_cmp(&b.at));
        let mut rtts: Vec<f64> = samples.iter().filter_map(|s| s.gateway_ms).collect();
        rtts.sort_by(f64::total_cmp);
        let gateway_median_ms = (!rtts.is_empty()).then(|| rtts[rtts.len() / 2]);
        Self {
            samples,
            gateway_median_ms,
        }
    }

    /// Read a JSONL log. A line that does not parse is skipped: the witness
    /// is killed and restarted with the host, and a torn last line is normal.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::new(
            text.lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect(),
        ))
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    fn trouble(&self, s: &WitnessSample) -> bool {
        let gateway_slow = match (s.gateway_ms, self.gateway_median_ms) {
            (Some(ms), Some(median)) => ms > (median * 3.0).max(median + WITNESS_GATEWAY_DELTA_MS),
            _ => false,
        };
        s.gateway_ok == Some(false)
            || gateway_slow
            || (s.anchors > 0 && s.anchors_ok == 0)
            || s.dns_ok == Some(false)
            || s.dns_ms.is_some_and(|ms| ms > WITNESS_DNS_SLOW_MS)
            || s.link_up == Some(false)
    }

    /// What the witness has to say about an open at `at`.
    pub fn judge(&self, at: f64) -> Witnessed {
        let from = at - WITNESS_BEFORE_SECS;
        let to = at + WITNESS_AFTER_SECS;
        let start = self.samples.partition_point(|s| s.at < from);
        let near: Vec<&WitnessSample> = self.samples[start..]
            .iter()
            .take_while(|s| s.at <= to)
            .collect();
        if near.is_empty() {
            Witnessed::Unwitnessed
        } else if near.iter().any(|s| self.trouble(s)) {
            Witnessed::Corroborated
        } else {
            Witnessed::Unexplained
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Witnessed {
    Corroborated,
    Unexplained,
    Unwitnessed,
}

/// One open, by today's engine, of one rule on one host.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Open {
    pub host: String,
    pub rule: String,
    /// `rule|subject`.
    pub key: String,
    /// Unix seconds.
    pub at: f64,
    pub ts: String,
    pub episode: String,
    pub witnessed: Witnessed,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct HostSummary {
    pub host: String,
    pub episodes: usize,
    pub frames: usize,
    pub monitored_secs: f64,
    /// Episodes whose replay opened or closed something the recording did
    /// not, or the other way round. Expected to be non-zero once a rule's
    /// logic has changed since the soak ran.
    pub divergent_episodes: usize,
    pub witness_samples: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuleSummary {
    pub rule: String,
    pub maturity: &'static str,
    /// Host-weeks the rule had its inputs and could have opened, by today's
    /// engine. Less than the soak's length for a rule that spent time
    /// learning, and zero for one whose input never arrived.
    pub evaluated_host_weeks: f64,
    /// Opens the engine made while recording.
    pub recorded_opens: usize,
    /// Opens today's engine makes from the same frames.
    pub replayed_opens: usize,
    pub corroborated: usize,
    pub unexplained: usize,
    pub unwitnessed: usize,
    /// Approximate 95% upper bound on unexplained opens per evaluated
    /// host-week: the rule of three (3 / n) when there were none, otherwise
    /// a Poisson bound. `None` when the rule was never evaluated.
    pub unexplained_per_host_week_upper: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SoakReport {
    pub netwatch_version: &'static str,
    /// Whether replay judged with today's default thresholds or with the
    /// ones each recording was made under.
    pub current_defaults: bool,
    pub host_weeks: f64,
    pub hosts: Vec<HostSummary>,
    pub rules: Vec<RuleSummary>,
    /// Unexplained and unwitnessed opens, for a person to go through.
    pub to_review: Vec<Open>,
    /// Unexplained opens across the stable rules, the number the catalogue
    /// budget is set against.
    pub stable_unexplained: usize,
}

/// One host's recordings and its witness log, if it kept one.
pub struct HostInput {
    pub host: String,
    pub episodes: Vec<Episode>,
    pub witness: Option<Witness>,
}

impl HostInput {
    /// Load `<dir>/state/netwatch/episodes` and `<dir>/witness.jsonl`, the
    /// layout `examples/diagnose_quiet_soak.rs record` writes. Recordings
    /// that fail to load are reported in the second value and left out.
    pub fn load(dir: &Path, host: &str) -> (Self, Vec<String>) {
        let mut errors = Vec::new();
        let mut episodes = Vec::new();
        for path in episode::list(&dir.join("state").join("netwatch").join("episodes")) {
            match episode::load(&path) {
                Ok(ep) => episodes.push(ep),
                Err(e) => errors.push(format!("{}: {e}", path.display())),
            }
        }
        let witness = Witness::load(&dir.join("witness.jsonl")).ok();
        (
            Self {
                host: host.to_string(),
                episodes,
                witness,
            },
            errors,
        )
    }
}

fn rule_of(key: &str) -> &str {
    key.split('|').next().unwrap_or(key)
}

/// Seconds covered by `frames`' timestamps, counting each instant once and
/// leaving out gaps longer than [`MAX_FRAME_GAP_SECS`].
fn monitored_secs(mut at: Vec<f64>) -> f64 {
    at.sort_by(f64::total_cmp);
    at.dedup();
    at.windows(2)
        .map(|w| w[1] - w[0])
        .filter(|gap| *gap <= MAX_FRAME_GAP_SECS)
        .sum()
}

/// Keys that appear in `open` on a frame and were not there on the frame
/// before. An episode that continues another starts with its issues already
/// open, and those are not new.
fn recorded_opens(ep: &Episode) -> Vec<String> {
    let mut was: BTreeSet<&str> = BTreeSet::new();
    let mut out = Vec::new();
    for (i, frame) in ep.frames.iter().enumerate() {
        let now: BTreeSet<&str> = frame.open.iter().map(|o| o.key.as_str()).collect();
        if !(i == 0 && ep.continues.is_some()) {
            out.extend(now.difference(&was).map(|k| k.to_string()));
        }
        was = now;
    }
    out
}

/// What today's engine makes of one recording.
#[derive(Default)]
struct Replayed {
    /// Each open: key, unix seconds, local timestamp.
    opens: Vec<(String, f64, String)>,
    /// Whether any frame's open issues differ from the recording's.
    diverged: bool,
    /// Seconds each rule had its inputs and could have opened. A rule that
    /// is still learning, or waiting on a trace nobody asked for, was not
    /// being tested, and its silence earns nothing.
    evaluated_secs: BTreeMap<String, f64>,
}

fn replayed(ep: &Episode) -> Replayed {
    let mut was: BTreeSet<String> = BTreeSet::new();
    let mut out = Replayed::default();
    let mut last_at: Option<f64> = None;
    episode::drive(ep, |step| {
        let gap = last_at.map_or(0.0, |at| step.frame.at - at);
        last_at = Some(step.frame.at);
        if gap > 0.0 && gap <= MAX_FRAME_GAP_SECS {
            for row in &step.engine.coverage().rules {
                if row.status == super::coverage::Availability::Available {
                    *out.evaluated_secs.entry(row.rule.clone()).or_default() += gap;
                }
            }
        }
        let now: BTreeSet<String> = step
            .engine
            .primary()
            .into_iter()
            .map(episode::issue_key)
            .collect();
        let recorded: BTreeSet<String> = step.frame.open.iter().map(|o| o.key.clone()).collect();
        out.diverged |= now != recorded;
        if !(step.index == 0 && ep.continues.is_some()) {
            for key in now.difference(&was) {
                out.opens
                    .push((key.clone(), step.frame.at, step.frame.ts.clone()));
            }
        }
        was = now;
    });
    out
}

/// Approximate one-sided 95% upper bound on a Poisson rate, per unit of
/// exposure, after `events` in `exposure`. Exact at zero (the rule of
/// three); above it, the Wilson–Hilferty approximation to the chi-square
/// quantile, which is within a few percent for the small counts seen here.
pub fn poisson_upper_95(events: usize, exposure: f64) -> Option<f64> {
    if exposure <= 0.0 {
        return None;
    }
    if events == 0 {
        return Some(3.0 / exposure);
    }
    let k = events as f64 + 1.0;
    let z = 1.644_853_6;
    let upper = k * (1.0 - 1.0 / (9.0 * k) + z / (3.0 * k.sqrt())).powi(3);
    Some(upper / exposure)
}

/// Account for every host's recordings.
///
/// With `current_defaults`, replay judges with today's default thresholds
/// instead of the ones each recording was made under, which is the question
/// after a default is retuned.
pub fn summarise(hosts: &[HostInput], current_defaults: bool) -> SoakReport {
    let mut host_rows = Vec::new();
    let mut recorded: BTreeMap<String, usize> = BTreeMap::new();
    let mut opens: Vec<Open> = Vec::new();
    let mut evaluated: BTreeMap<String, f64> = BTreeMap::new();

    for input in hosts {
        let mut row = HostSummary {
            host: input.host.clone(),
            episodes: input.episodes.len(),
            witness_samples: input.witness.as_ref().map_or(0, Witness::len),
            ..Default::default()
        };
        let mut at = Vec::new();
        for ep in &input.episodes {
            // Lab recordings are injected faults, not quiet time.
            if matches!(ep.source, EpisodeSource::Lab { .. }) {
                continue;
            }
            row.frames += ep.frames.len();
            at.extend(ep.frames.iter().map(|f| f.at));
            for key in recorded_opens(ep) {
                *recorded.entry(rule_of(&key).to_string()).or_default() += 1;
            }
            let mut judged = ep.clone();
            if current_defaults {
                judged.settings.thresholds = Default::default();
            }
            let replay = replayed(&judged);
            row.divergent_episodes += replay.diverged as usize;
            for (rule, secs) in replay.evaluated_secs {
                *evaluated.entry(rule).or_default() += secs;
            }
            for (key, when, ts) in replay.opens {
                opens.push(Open {
                    host: input.host.clone(),
                    rule: rule_of(&key).to_string(),
                    key,
                    at: when,
                    ts,
                    episode: ep.id.clone(),
                    witnessed: input
                        .witness
                        .as_ref()
                        .map_or(Witnessed::Unwitnessed, |w| w.judge(when)),
                });
            }
        }
        row.monitored_secs = monitored_secs(at);
        host_rows.push(row);
    }

    let host_weeks = host_rows.iter().map(|h| h.monitored_secs).sum::<f64>() / SECS_PER_WEEK;
    let count = |rule: &str, w: Witnessed| {
        opens
            .iter()
            .filter(|o| o.rule == rule && o.witnessed == w)
            .count()
    };
    let rules: Vec<RuleSummary> = rules::CATALOGUE
        .iter()
        .map(|r| {
            let unexplained = count(r.id, Witnessed::Unexplained);
            let evaluated_host_weeks = evaluated.get(r.id).copied().unwrap_or(0.0) / SECS_PER_WEEK;
            RuleSummary {
                evaluated_host_weeks,
                rule: r.id.to_string(),
                maturity: r.maturity.label(),
                recorded_opens: recorded.get(r.id).copied().unwrap_or(0),
                replayed_opens: opens.iter().filter(|o| o.rule == r.id).count(),
                corroborated: count(r.id, Witnessed::Corroborated),
                unexplained,
                unwitnessed: count(r.id, Witnessed::Unwitnessed),
                unexplained_per_host_week_upper: poisson_upper_95(
                    unexplained,
                    evaluated_host_weeks,
                ),
            }
        })
        .collect();
    let stable_unexplained = rules
        .iter()
        .filter(|r| r.maturity == rules::Maturity::Stable.label())
        .map(|r| r.unexplained)
        .sum();
    let mut to_review: Vec<Open> = opens
        .into_iter()
        .filter(|o| o.witnessed != Witnessed::Corroborated)
        .collect();
    to_review.sort_by(|a, b| a.at.total_cmp(&b.at));

    SoakReport {
        netwatch_version: env!("CARGO_PKG_VERSION"),
        current_defaults,
        host_weeks,
        hosts: host_rows,
        rules,
        to_review,
        stable_unexplained,
    }
}

impl SoakReport {
    /// The report as text: hosts, then every rule that opened, then the
    /// opens a person should look at.
    pub fn text(&self) -> String {
        let mut out = format!(
            "soak · netwatch {} · {:.2} host-weeks over {} host(s) · {}\n",
            self.netwatch_version,
            self.host_weeks,
            self.hosts.len(),
            if self.current_defaults {
                "judged with today's default thresholds"
            } else {
                "judged with each recording's own thresholds"
            }
        );
        for h in &self.hosts {
            out.push_str(&format!(
                "  {:<16} {:>7.1} h monitored · {} recordings · {} divergent · {} witness samples\n",
                h.host,
                h.monitored_secs / 3_600.0,
                h.episodes,
                h.divergent_episodes,
                h.witness_samples
            ));
        }
        out.push_str(
            "\nrule                      maturity  eval. wk  recorded  replayed  corrob.  unexpl.  unwitn.  unexpl./host-week (95% upper)\n",
        );
        for r in &self.rules {
            out.push_str(&format!(
                "{:<25} {:<8}  {:>8.2}  {:>8}  {:>8}  {:>7}  {:>7}  {:>7}  {}\n",
                r.rule,
                r.maturity,
                r.evaluated_host_weeks,
                r.recorded_opens,
                r.replayed_opens,
                r.corroborated,
                r.unexplained,
                r.unwitnessed,
                r.unexplained_per_host_week_upper
                    .map_or_else(|| "never evaluated".to_string(), |u| format!("{u:.2}")),
            ));
        }
        out.push_str(&format!(
            "\nstable rules: {} unexplained open(s)\n",
            self.stable_unexplained
        ));
        if !self.to_review.is_empty() {
            out.push_str("\nto review (the witness did not corroborate these):\n");
            for o in &self.to_review {
                out.push_str(&format!(
                    "  {} · {} · {} · {:?} · recording {}\n",
                    o.ts, o.host, o.key, o.witnessed, o.episode
                ));
            }
        }
        out.push_str(
            "\nA zero here bounds a rate; it does not prove a rule correct. The witness cannot see\n\
             everything a rule can, so unexplained is an upper bound on false opens.\n",
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(at: f64) -> WitnessSample {
        WitnessSample {
            at,
            gateway_ok: Some(true),
            gateway_ms: Some(2.0),
            anchors: 2,
            anchors_ok: 2,
            dns_ok: Some(true),
            dns_ms: Some(20.0),
            link_up: Some(true),
        }
    }

    /// The first corpus scenario that opens at least three issues.
    fn incident() -> Episode {
        crate::diagnose::fixture::scenarios()
            .iter()
            .map(crate::diagnose::fixture::record)
            .find(|ep| recorded_opens(ep).len() >= 3)
            .expect("a corpus scenario with three opens")
    }

    #[test]
    fn monitored_time_skips_gaps_and_counts_an_instant_once() {
        // Two recordings sharing a pre-roll, then a suspend.
        let at = vec![0.0, 1.0, 2.0, 1.0, 2.0, 3.0, 5_000.0, 5_001.0];
        assert_eq!(monitored_secs(at), 4.0);
        assert_eq!(monitored_secs(vec![]), 0.0);
    }

    #[test]
    fn the_witness_sorts_an_open_three_ways() {
        let mut samples: Vec<WitnessSample> = (0..100).map(|i| sample(i as f64 * 10.0)).collect();
        samples[50].dns_ok = Some(false);
        let w = Witness::new(samples);
        // Trouble at 500 s: an open shortly after it is corroborated.
        assert_eq!(w.judge(560.0), Witnessed::Corroborated);
        // Watching, and nothing seen.
        assert_eq!(w.judge(100.0), Witnessed::Unexplained);
        // Long after the log ends.
        assert_eq!(w.judge(9_000.0), Witnessed::Unwitnessed);
    }

    #[test]
    fn a_slow_gateway_is_judged_against_the_logs_own_median() {
        let mut samples: Vec<WitnessSample> = (0..100).map(|i| sample(i as f64 * 10.0)).collect();
        samples[10].gateway_ms = Some(11.0);
        samples[60].gateway_ms = Some(13.0);
        let w = Witness::new(samples);
        // 11 ms is under median + 10.
        assert_eq!(w.judge(100.0), Witnessed::Unexplained);
        assert_eq!(w.judge(600.0), Witnessed::Corroborated);
    }

    #[test]
    fn no_anchors_configured_is_not_an_outage() {
        let mut s = sample(0.0);
        s.anchors = 0;
        s.anchors_ok = 0;
        assert_eq!(Witness::new(vec![s]).judge(0.0), Witnessed::Unexplained);
    }

    #[test]
    fn the_bound_is_the_rule_of_three_at_zero_and_grows_with_events() {
        assert_eq!(poisson_upper_95(0, 13.0), Some(3.0 / 13.0));
        assert_eq!(poisson_upper_95(0, 0.0), None);
        // Exact one-sided 95% bounds are 4.74 for one event and 6.30 for two.
        let one = poisson_upper_95(1, 1.0).unwrap();
        let two = poisson_upper_95(2, 1.0).unwrap();
        assert!((one - 4.74).abs() < 0.1, "{one}");
        assert!((two - 6.30).abs() < 0.1, "{two}");
    }

    /// The demo episode is an incident, so every rule it opens is counted,
    /// replay agrees with the recording, and with no witness each open is
    /// left for review.
    #[test]
    fn a_recorded_incident_is_counted_once_per_rule_it_opened() {
        let ep = incident();
        let expected = recorded_opens(&ep).len();
        assert!(expected >= 3, "the fixture opens at least three issues");
        let report = summarise(
            &[HostInput {
                host: "fixture".into(),
                episodes: vec![ep.clone()],
                witness: None,
            }],
            false,
        );
        let replayed: usize = report.rules.iter().map(|r| r.replayed_opens).sum();
        let recorded: usize = report.rules.iter().map(|r| r.recorded_opens).sum();
        assert_eq!(recorded, expected);
        assert_eq!(replayed, expected);
        assert_eq!(report.hosts[0].divergent_episodes, 0);
        assert_eq!(report.to_review.len(), expected);
        assert!(report.hosts[0].monitored_secs > 0.0);
        // A rule that opened was evaluated; no rule was for longer than the
        // recording ran.
        let monitored_weeks = report.hosts[0].monitored_secs / SECS_PER_WEEK;
        for r in &report.rules {
            assert!(
                r.evaluated_host_weeks <= monitored_weeks + 1e-9,
                "{}",
                r.rule
            );
            if r.replayed_opens > 0 {
                assert!(r.evaluated_host_weeks > 0.0, "{}", r.rule);
            }
        }
        assert!(report.text().contains("to review"));
    }

    #[test]
    fn a_lab_recording_is_not_quiet_time() {
        let mut ep = incident();
        ep.source = EpisodeSource::Lab {
            scenario: "x".into(),
            seed: 1,
        };
        let report = summarise(
            &[HostInput {
                host: "lab".into(),
                episodes: vec![ep],
                witness: None,
            }],
            false,
        );
        assert_eq!(report.host_weeks, 0.0);
        assert!(report.to_review.is_empty());
    }
}
