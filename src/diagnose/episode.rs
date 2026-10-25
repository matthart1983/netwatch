//! Incident episodes: what the engine saw around an issue, recorded so it can
//! be reviewed, exported, labelled and replayed.
//!
//! ```text
//!   tick ──▶ Frame ──▶ pre-roll ring (10 min) ──┐
//!                                              │ a primary issue opens
//!                                              ▼
//!                                        Episode (Live) ── last issue closes
//!                                              │           + 10 min post-roll
//!                                              ▼
//!                           <state>/netwatch/episodes/YYYY-MM/<id>.json.gz
//! ```
//!
//! A frame holds the *inputs* to one diagnose tick — observations, probe ages,
//! the readings learned afterwards — plus the open issues the live engine
//! produced from them. [`replay`] feeds the inputs to a fresh engine and
//! compares its open issues frame by frame, so a recording doubles as a
//! regression test of the engine that made it.
//!
//! Recording is local. Nothing here uploads or redacts; exports do that.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::baseline::{BaselineSnapshot, BaselineStore};
use super::detectors::{classify_socket, Observations, SocketVerdict};
use super::engine::{Engine, FixedClock, ObservationTimes, Settings};
use super::issue::{Issue, Subject};
use super::live::Reading;
use crate::ui::sanitize::{display, display_owned, is_unsafe};

pub const SCHEMA_VERSION: u16 = 1;

/// Seconds of frames kept before an issue opens.
pub const PRE_ROLL_SECS: f64 = 600.0;
/// Seconds recorded after the last attached issue closes.
pub const POST_ROLL_SECS: f64 = 600.0;
/// Longest single episode; a longer incident continues in a new file.
pub const MAX_EPISODE_SECS: f64 = 2.0 * 3_600.0;
/// Length of the daily sample of a quiet network.
pub const QUIET_SAMPLE_SECS: f64 = 900.0;
/// Sockets kept per frame beyond those with a verdict or an open issue.
pub const TOP_SOCKETS: usize = 20;

pub const RETAIN_SECS: u64 = 90 * 24 * 3_600;
pub const RETAIN_BYTES: u64 = 300 * 1024 * 1024;
/// Most frames [`load`] accepts from one recording. netwatch ticks at most
/// every 100 ms, its fastest refresh, and starts a new episode once one
/// spans [`MAX_EPISODE_SECS`], so a recording holds at most 72,000 frames;
/// the two rolls on top are headroom. A frame with every field empty is
/// 35 bytes of JSON and 1.7 KB in memory, so a 100 KB gzip of a million of
/// them took 2.6 GB.
pub const MAX_LOAD_FRAMES: usize =
    ((MAX_EPISODE_SECS + PRE_ROLL_SECS + POST_ROLL_SECS) * 10.0) as usize;
/// Most [`load`] inflates from one recording: [`MAX_LOAD_FRAMES`] frames of
/// 10 KiB. A busy host's frames average 9 KB, so two hours of them at the
/// fastest refresh inflate to 650 MB. This bounds the input, not the memory
/// parsing it takes: a list of empty strings takes eight times its JSON, so
/// a crafted file under both limits can still need gigabytes.
pub const MAX_LOAD_BYTES: u64 = MAX_LOAD_FRAMES as u64 * 10 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EpisodeSource {
    /// Recorded around an issue on this host.
    Live,
    /// A stretch with no open issues, recorded once a day so false-alert
    /// rates have a denominator.
    QuietSample,
    /// Produced by the fault lab.
    Lab { scenario: String, seed: u64 },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvProfile {
    pub os: String,
    pub arch: String,
    pub kernel: Option<String>,
    pub netwatch_version: String,
    /// Privileges the process held, as [`super::issue::Capability::label`].
    pub capability: String,
    pub refresh_rate_ms: u64,
}

impl EnvProfile {
    pub fn detect(capability: &str, refresh_rate_ms: u64) -> Self {
        Self {
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            kernel: std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .ok()
                .map(|s| s.trim().to_string()),
            netwatch_version: env!("CARGO_PKG_VERSION").into(),
            capability: capability.into(),
            refresh_rate_ms,
        }
    }
}

/// Seconds before the frame each collector's last result completed. Instants
/// can't be stored; ages can, and replay turns them back into instants.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProbeAges {
    #[serde(default)]
    pub ipv6: Option<f64>,
    #[serde(default)]
    pub portal: Option<f64>,
    #[serde(default)]
    pub pmtu: Option<f64>,
    #[serde(default)]
    pub kernel: Option<f64>,
    #[serde(default)]
    pub egress: Option<f64>,
    pub interface: Option<f64>,
    pub sockets: Option<f64>,
    pub path: Option<f64>,
    pub gateway: Option<f64>,
    pub dns: Option<f64>,
    pub internet: Option<f64>,
    pub nat: Option<f64>,
    /// Newest target completion, kept for recordings written before probe
    /// ages were split per target. Replay reads `target_ages` instead: one
    /// age shared by every target is what let a fast target verify a slow
    /// one, and it cannot be attributed back to a name after the fact.
    #[serde(default)]
    pub targets: Option<f64>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub target_ages: std::collections::BTreeMap<String, f64>,
    pub gateway_target: Option<String>,
    pub dns_target: Option<String>,
}

impl ProbeAges {
    fn from_times(times: &ObservationTimes, now: Instant) -> Self {
        let age =
            |at: Option<Instant>| at.map(|at| now.saturating_duration_since(at).as_secs_f64());
        Self {
            ipv6: age(times.ipv6),
            portal: age(times.portal),
            pmtu: age(times.pmtu),
            kernel: age(times.kernel),
            egress: age(times.egress),
            interface: age(times.interface),
            sockets: age(times.sockets),
            path: age(times.path),
            gateway: age(times.health.gateway),
            dns: age(times.health.dns),
            internet: age(times.health.internet),
            nat: age(times.health.nat),
            targets: times
                .targets
                .values()
                .copied()
                .max()
                .map(|at| now.saturating_duration_since(at).as_secs_f64()),
            target_ages: times
                .targets
                .iter()
                .map(|(name, at)| {
                    (
                        name.clone(),
                        now.saturating_duration_since(*at).as_secs_f64(),
                    )
                })
                .collect(),
            gateway_target: times.health.gateway_target.clone(),
            dns_target: times.health.dns_target.clone(),
        }
    }

    /// Rebuild completion instants for a frame `frame_secs` after `origin`.
    ///
    /// Completion times are snapped to a 100ms grid. An age is wall time
    /// minus a monotonic elapsed, so the same probe result recorded on ten
    /// ticks gives ten slightly different "frame − age" values; unsnapped,
    /// replay would count each as a new sample and open issues early.
    fn to_times(&self, origin: Instant, frame_secs: f64) -> ObservationTimes {
        let at = |age: Option<f64>| {
            let secs = ((frame_secs - age?) * 10.0).round() / 10.0;
            // An age no `Duration` holds reads as no completion, as one
            // past what an `Instant` reaches already does.
            if secs >= 0.0 {
                origin.checked_add(Duration::try_from_secs_f64(secs).ok()?)
            } else {
                origin.checked_sub(Duration::try_from_secs_f64(-secs).ok()?)
            }
        };
        let mut times = ObservationTimes {
            ipv6: at(self.ipv6),
            portal: at(self.portal),
            pmtu: at(self.pmtu),
            kernel: at(self.kernel),
            egress: at(self.egress),
            interface: at(self.interface),
            sockets: at(self.sockets),
            path: at(self.path),
            // A recording from before per-target ages has only the newest
            // completion, which cannot be attributed to a target; it decodes
            // as no per-target sampling rather than as evidence for whichever
            // target is on screen.
            targets: self
                .target_ages
                .iter()
                .filter_map(|(name, age)| Some((name.clone(), at(Some(*age))?)))
                .collect(),
            ..Default::default()
        };
        times.health.gateway = at(self.gateway);
        times.health.dns = at(self.dns);
        times.health.internet = at(self.internet);
        times.health.nat = at(self.nat);
        times.health.gateway_target = self.gateway_target.clone();
        times.health.dns_target = self.dns_target.clone();
        times
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordedReading {
    pub subject: String,
    pub metric: String,
    pub value: f64,
    pub at: f64,
}

/// An open, primary issue as the engine left it after a tick.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpenIssue {
    /// `rule|subject`, the engine's own identity for a condition; see
    /// [`super::issue::finding_key`].
    pub key: String,
    pub top_cause: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Frame {
    /// Unix seconds.
    pub at: f64,
    /// Local `YYYY-MM-DD HH:MM:SS`, what the engine's clock read.
    pub ts: String,
    pub obs: Observations,
    pub ages: ProbeAges,
    /// Learned after evaluation, as on the live tick.
    #[serde(default)]
    pub readings: Vec<RecordedReading>,
    /// Present on the first frame and wherever the network changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baselines: Option<BaselineSnapshot>,
    /// What the live engine had open after this tick.
    #[serde(default)]
    pub open: Vec<OpenIssue>,
    /// User actions (and test results) since the previous frame. Replay
    /// applies them before evaluating this frame, as they happened live.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<super::engine::EngineEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotReason {
    Opened,
    Closed,
    /// Still open when the episode ended.
    Final,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IssueSnapshot {
    pub ts: String,
    pub reason: SnapshotReason,
    pub issue: Issue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LabelSource {
    /// The rule engine's own top cause. Provisional only.
    Rule,
    /// The person at the keyboard, after the issue resolved.
    User,
    /// A reviewer working from the recording.
    Expert { reviewer: String },
    /// The fault the lab injected.
    Lab,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Label {
    /// Issue key (`rule|subject`, see [`super::issue::finding_key`]) the
    /// label is about.
    pub issue: String,
    /// `rule/cause_id`, or `not_network`, `unknown`.
    pub cause: String,
    pub source: LabelSource,
    pub ts: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Episode {
    pub schema_version: u16,
    pub id: String,
    pub source: EpisodeSource,
    pub env: EnvProfile,
    pub settings: Settings,
    pub started: String,
    pub ended: String,
    /// Id of the episode this one continues, when an incident outlasted
    /// [`MAX_EPISODE_SECS`].
    #[serde(default)]
    pub continues: Option<String>,
    #[serde(deserialize_with = "at_most_max_frames")]
    pub frames: Vec<Frame>,
    #[serde(default)]
    pub issues: Vec<IssueSnapshot>,
    #[serde(default)]
    pub labels: Vec<Label>,
}

/// `frames`, failing at the first past [`MAX_LOAD_FRAMES`] instead of
/// growing until memory runs out.
fn at_most_max_frames<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Vec<Frame>, D::Error> {
    struct Frames;
    impl<'de> serde::de::Visitor<'de> for Frames {
        type Value = Vec<Frame>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a list of frames")
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Vec<Frame>, A::Error> {
            let mut frames = Vec::new();
            while let Some(frame) = seq.next_element()? {
                if frames.len() == MAX_LOAD_FRAMES {
                    return Err(serde::de::Error::custom(format_args!(
                        "more than {MAX_LOAD_FRAMES} frames, more than any recording"
                    )));
                }
                frames.push(frame);
            }
            Ok(frames)
        }
    }
    de.deserialize_seq(Frames)
}

impl Episode {
    pub fn duration_secs(&self) -> f64 {
        match (self.frames.first(), self.frames.last()) {
            (Some(a), Some(b)) => b.at - a.at,
            _ => 0.0,
        }
    }

    /// Distinct issue keys that were open at any frame.
    pub fn issue_keys(&self) -> Vec<String> {
        let mut seen = Vec::new();
        for o in self.frames.iter().flat_map(|f| &f.open) {
            if !seen.contains(&o.key) {
                seen.push(o.key.clone());
            }
        }
        seen
    }
}

// ------------------------------------------------------------------ recorder

/// One tick's worth of what the recorder needs, borrowed from the app.
pub struct Tick<'a> {
    /// Unix seconds.
    pub at: f64,
    pub ts: String,
    pub now: Instant,
    pub obs: &'a Observations,
    pub times: &'a ObservationTimes,
    pub readings: &'a [Reading],
    pub engine: &'a Engine,
    /// The store as the engine judged against it, before this tick's learning.
    pub baselines: &'a BaselineStore,
    /// [`Engine::take_events`], drained before this tick's evaluation.
    pub events: Vec<super::engine::EngineEvent>,
}

struct Active {
    episode: Episode,
    /// Network of the last snapshot kept, so later frames only carry one
    /// when it changes.
    network: Option<super::baseline::NetworkFingerprint>,
    /// By key, so issues that open or close on the same tick, and the final
    /// snapshots, are written in one order. A hashed map wrote them in a
    /// different order each run, and the pinned corpus with them.
    open: BTreeMap<String, Issue>,
    started_at: f64,
    all_closed_since: Option<f64>,
}

pub struct Recorder {
    env: EnvProfile,
    ring: VecDeque<Frame>,
    active: Option<Active>,
    next_quiet_at: f64,
}

impl Recorder {
    pub fn new(env: EnvProfile, now_unix: f64) -> Self {
        Self {
            env,
            ring: VecDeque::new(),
            active: None,
            next_quiet_at: now_unix + random_offset(86_400.0),
        }
    }

    /// Move the next quiet sample to `at` (unix seconds).
    pub fn schedule_quiet_sample(&mut self, at: f64) {
        self.next_quiet_at = at;
    }

    pub fn is_recording(&self) -> bool {
        self.active.is_some()
    }

    /// Record one tick. Returns an episode when one finished on this tick.
    pub fn record(&mut self, tick: Tick<'_>) -> Option<Episode> {
        let frame = self.frame(&tick);
        let open: BTreeMap<String, &Issue> = tick
            .engine
            .primary()
            .into_iter()
            .map(|i| (issue_key(i), i))
            .collect();

        self.ring.push_back(frame.clone());
        while self
            .ring
            .front()
            .is_some_and(|f| tick.at - f.at > PRE_ROLL_SECS)
        {
            self.ring.pop_front();
        }

        let Some(active) = self.active.as_mut() else {
            if !open.is_empty() {
                self.start(EpisodeSource::Live, &tick, true, None);
                self.track(&tick, &open);
            } else if tick.at >= self.next_quiet_at {
                self.next_quiet_at = tick.at + 86_400.0 + random_offset(3_600.0) - 1_800.0;
                self.start(EpisodeSource::QuietSample, &tick, false, None);
            }
            return None;
        };

        let mut frame = frame;
        strip_repeat_snapshot(&mut active.network, &mut frame);
        active.episode.frames.push(frame);

        if active.episode.source == EpisodeSource::QuietSample && !open.is_empty() {
            // Something broke during the quiet sample. Its last ten minutes
            // become the incident's pre-roll, taken from the ring because the
            // ring's frames still carry their own baseline snapshots.
            active.episode.source = EpisodeSource::Live;
            active.network = None;
            active.episode.frames = self.ring.iter().cloned().collect();
            for f in &mut active.episode.frames {
                strip_repeat_snapshot(&mut active.network, f);
            }
            active.started_at = active.episode.frames.first().map_or(tick.at, |f| f.at);
            active.episode.started = active
                .episode
                .frames
                .first()
                .map_or_else(|| tick.ts.clone(), |f| f.ts.clone());
        }
        self.track(&tick, &open);

        let active = self.active.as_mut().expect("still recording");
        let elapsed = tick.at - active.started_at;
        let done = match active.episode.source {
            EpisodeSource::QuietSample => elapsed >= QUIET_SAMPLE_SECS,
            _ => {
                // Over when nothing is tracked, not when `primary` is empty. A
                // muted issue has left `primary` but the engine still watches
                // it, and a replay needs every frame up to its close or the
                // end of its mute.
                let tracked = tick.engine.issues().iter().any(|i| i.state.is_tracked());
                if !tracked {
                    let since = *active.all_closed_since.get_or_insert(tick.at);
                    tick.at - since >= POST_ROLL_SECS
                } else {
                    active.all_closed_since = None;
                    false
                }
            }
        };
        if done {
            return self.finish(&tick);
        }
        if elapsed >= MAX_EPISODE_SECS {
            let finished = self.finish(&tick);
            let prev = finished.as_ref().map(|e| e.id.clone());
            self.start(EpisodeSource::Live, &tick, false, prev);
            self.track(&tick, &open);
            return finished;
        }
        None
    }

    /// Attach a label to the episode being recorded, if it covers `label.issue`.
    pub fn label(&mut self, label: &Label) -> bool {
        let Some(active) = self.active.as_mut() else {
            return false;
        };
        let covers = active.open.contains_key(&label.issue)
            || active
                .episode
                .issues
                .iter()
                .any(|s| issue_key(&s.issue) == label.issue);
        if covers {
            active.episode.labels.push(label.clone());
        }
        covers
    }

    /// End the active episode now, e.g. on quit.
    pub fn flush(&mut self, engine: &Engine, ts: &str) -> Option<Episode> {
        let mut active = self.active.take()?;
        final_snapshots(&mut active, engine, ts);
        active.episode.ended = ts.to_string();
        Some(active.episode)
    }

    fn frame(&self, tick: &Tick<'_>) -> Frame {
        let thresholds = tick.engine.settings().thresholds;
        let open: Vec<OpenIssue> = tick.engine.primary().into_iter().map(open_issue).collect();
        let mut obs = tick.obs.clone();
        trim_sockets(&mut obs, &thresholds, tick.engine);
        Frame {
            at: tick.at,
            ts: tick.ts.clone(),
            obs,
            ages: ProbeAges::from_times(tick.times, tick.now),
            readings: tick
                .readings
                .iter()
                .map(|r| RecordedReading {
                    subject: r.subject.clone(),
                    metric: r.metric.to_string(),
                    value: r.value,
                    at: r.at,
                })
                .collect(),
            baselines: Some(tick.baselines.snapshot()),
            open,
            events: tick.events.clone(),
        }
    }

    fn start(
        &mut self,
        source: EpisodeSource,
        tick: &Tick<'_>,
        with_pre_roll: bool,
        continues: Option<String>,
    ) {
        let mut frames: Vec<Frame> = if with_pre_roll {
            self.ring.iter().cloned().collect()
        } else {
            self.ring.back().cloned().into_iter().collect()
        };
        let mut network = None;
        for f in &mut frames {
            strip_repeat_snapshot(&mut network, f);
        }
        let started = frames
            .first()
            .map(|f| f.ts.clone())
            .unwrap_or_else(|| tick.ts.clone());
        let started_at = frames.first().map(|f| f.at).unwrap_or(tick.at);
        self.active = Some(Active {
            episode: Episode {
                schema_version: SCHEMA_VERSION,
                id: uuid::Uuid::new_v4().to_string(),
                source,
                env: self.env.clone(),
                settings: *tick.engine.settings(),
                started,
                ended: String::new(),
                continues,
                frames,
                issues: vec![],
                labels: vec![],
            },
            network,
            open: BTreeMap::new(),
            started_at,
            all_closed_since: None,
        });
    }

    /// Snapshot issues as they open and close.
    fn track(&mut self, tick: &Tick<'_>, open: &BTreeMap<String, &Issue>) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        for (key, issue) in open {
            if !active.open.contains_key(key) {
                active.episode.issues.push(IssueSnapshot {
                    ts: tick.ts.clone(),
                    reason: SnapshotReason::Opened,
                    issue: (*issue).clone(),
                });
            }
            active.open.insert(key.clone(), (*issue).clone());
        }
        let closed: Vec<String> = active
            .open
            .keys()
            .filter(|k| !open.contains_key(*k))
            .cloned()
            .collect();
        for key in closed {
            let last = active.open.remove(&key).expect("key came from the map");
            let issue = tick
                .engine
                .issues()
                .iter()
                .find(|i| i.id == last.id)
                .cloned()
                .unwrap_or(last);
            active.episode.issues.push(IssueSnapshot {
                ts: tick.ts.clone(),
                reason: SnapshotReason::Closed,
                issue,
            });
        }
    }

    fn finish(&mut self, tick: &Tick<'_>) -> Option<Episode> {
        let mut active = self.active.take()?;
        final_snapshots(&mut active, tick.engine, &tick.ts);
        active.episode.ended = tick.ts.clone();
        Some(active.episode)
    }
}

/// Drop a frame's baseline snapshot when its network matches the last one
/// kept. Replay learns forward from a snapshot, so only the first frame and
/// network changes need one.
fn strip_repeat_snapshot(
    last: &mut Option<super::baseline::NetworkFingerprint>,
    frame: &mut Frame,
) {
    let Some(snap) = &frame.baselines else {
        return;
    };
    if last.as_ref() == Some(&snap.network) {
        frame.baselines = None;
    } else {
        *last = Some(snap.network.clone());
    }
}

fn final_snapshots(active: &mut Active, engine: &Engine, ts: &str) {
    for last in active.open.values() {
        let issue = engine
            .issues()
            .iter()
            .find(|i| i.id == last.id)
            .cloned()
            .unwrap_or_else(|| last.clone());
        active.episode.issues.push(IssueSnapshot {
            ts: ts.to_string(),
            reason: SnapshotReason::Final,
            issue,
        });
    }
}

pub fn issue_key(issue: &Issue) -> String {
    issue.key()
}

fn open_issue(issue: &Issue) -> OpenIssue {
    OpenIssue {
        key: issue_key(issue),
        top_cause: issue.top_cause().map(|c| c.key(&issue.rule)),
    }
}

/// Keep every socket whose verdict can raise an issue or that a tracked issue
/// is about, plus the busiest few by retransmits. Nothing dropped here could
/// have produced or held an issue, and the kept set still carries rtt and rwnd
/// whenever any socket did, so replay reaches the same coverage and result.
/// Muted issues count: the engine still closes or expires them on what their
/// socket does.
fn trim_sockets(obs: &mut Observations, t: &super::detectors::Thresholds, engine: &Engine) {
    if obs.sockets.len() <= TOP_SOCKETS {
        return;
    }
    let subjects: HashSet<(String, String)> = engine
        .issues()
        .iter()
        .filter(|i| i.state.is_tracked())
        .filter_map(|i| match &i.subject {
            Subject::Socket { local, remote } => Some((local.clone(), remote.clone())),
            _ => None,
        })
        .collect();
    let mut rest = Vec::new();
    let mut keep = Vec::new();
    for s in obs.sockets.drain(..) {
        let raises = !matches!(
            classify_socket(&s, t),
            SocketVerdict::Ok | SocketVerdict::AppLimited | SocketVerdict::Congestion
        );
        if raises || subjects.contains(&(s.local.clone(), s.remote.clone())) {
            keep.push(s);
        } else {
            rest.push(s);
        }
    }
    rest.sort_by(|a, b| {
        let measured = |s: &super::detectors::SocketObs| s.rtt_ms.is_some() && s.rwnd.is_some();
        measured(b)
            .cmp(&measured(a))
            .then(b.retrans.cmp(&a.retrans))
    });
    keep.extend(rest.into_iter().take(TOP_SOCKETS));
    obs.sockets = keep;
}

fn random_offset(range_secs: f64) -> f64 {
    (uuid::Uuid::new_v4().as_u128() % 1_000_000) as f64 / 1_000_000.0 * range_secs
}

// ------------------------------------------------------------------ storage

/// `<state>/netwatch/episodes`, beside the egress baseline so the sandbox
/// rule that permits one permits the other.
pub fn default_dir() -> Option<PathBuf> {
    crate::collectors::egress::default_profiles_path()
        .and_then(|p| p.parent().map(|d| d.join("episodes")))
}

pub fn path_for(dir: &Path, episode: &Episode) -> PathBuf {
    let month = episode.started.get(..7).unwrap_or("unknown");
    dir.join(month).join(format!("{}.json.gz", episode.id))
}

/// Gzipped JSON, written to a temp file and renamed so a crash can't leave a
/// half-written episode. Private to the user: it holds addresses and names.
pub fn save(dir: &Path, episode: &Episode) -> std::io::Result<PathBuf> {
    let path = path_for(dir, episode);
    let parent = path.parent().expect("episode path has a month dir");
    std::fs::create_dir_all(parent)?;
    let tmp = path.with_extension("gz.tmp");
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&tmp)?;
        let mut gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        serde_json::to_writer(&mut gz, episode).map_err(std::io::Error::other)?;
        gz.finish()?.flush()?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

pub fn load(path: &Path) -> std::io::Result<Episode> {
    let file = std::fs::File::open(path)?;
    let bytes = if path.extension().is_some_and(|e| e == "gz") {
        read_capped(flate2::read::GzDecoder::new(file), MAX_LOAD_BYTES)?
    } else {
        read_capped(std::io::BufReader::new(file), MAX_LOAD_BYTES)?
    };
    // A parse error can quote the file, such as the name of a variant it
    // does not know, and the CLI prints it.
    let mut episode: Episode = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::other(display_owned(e.to_string())))?;
    if episode.schema_version > SCHEMA_VERSION {
        return Err(std::io::Error::other(format!(
            "episode schema {} is newer than this netwatch ({SCHEMA_VERSION})",
            episode.schema_version
        )));
    }
    add_target_revisions(&mut episode);
    Ok(episode)
}

/// All of `reader`, or an error naming `cap` once it passes that many bytes.
/// Nothing past the cap is read.
fn read_capped(reader: impl Read, cap: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(std::io::Error::other(format!(
            "more than {} MiB uncompressed, larger than any recording",
            cap >> 20
        )));
    }
    Ok(bytes)
}

/// Rename target issues recorded as `rule|name` to `rule|name|revision`.
///
/// Before 0.34 a target's issue key had no revision. The engine now files
/// that issue under its revision, so an older recording's labels, test
/// results, actions and open keys would match nothing it replays to: the
/// labels and "tested" rows would drop out of `diagnose features` and the
/// history, and replay would skip the actions. A key is renamed only when
/// every snapshot of that rule and name carries the same revision. One seen
/// under two revisions is the edit the new key fixes, and the recording does
/// not say which revision each event meant. A recording made since has no
/// `rule|name` key with a revision to add, so this changes nothing in it.
fn add_target_revisions(episode: &mut Episode) {
    let mut revisions: HashMap<String, HashSet<Option<String>>> = HashMap::new();
    let mut renamed: HashMap<String, String> = HashMap::new();
    for snap in &episode.issues {
        let issue = &snap.issue;
        if matches!(issue.subject, Subject::Target { .. }) {
            let old = super::issue::finding_key(&issue.rule, &issue.subject, None);
            revisions
                .entry(old.clone())
                .or_default()
                .insert(issue.scope.configuration.clone());
            renamed.insert(old, issue.key());
        }
    }
    renamed.retain(|old, new| revisions[old].len() == 1 && new != old);
    if renamed.is_empty() {
        return;
    }
    let rename = |key: &mut String| {
        if let Some(new) = renamed.get(key.as_str()) {
            key.clone_from(new);
        }
    };
    for label in &mut episode.labels {
        rename(&mut label.issue);
    }
    for frame in &mut episode.frames {
        for open in &mut frame.open {
            rename(&mut open.key);
        }
        for event in &mut frame.events {
            rename(event.issue_mut());
        }
    }
}

/// One incident in the history list: enough to render a row and open the
/// recording, without holding every frame in memory.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HistoryEntry {
    pub path: PathBuf,
    pub id: String,
    pub source: EpisodeSource,
    pub started: String,
    pub ended: String,
    pub duration_secs: f64,
    pub issues: Vec<HistoryIssue>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HistoryIssue {
    pub key: String,
    pub rule: String,
    pub title: String,
    pub opened: String,
    /// `None` when still open at the end of the recording.
    pub closed: Option<String>,
    pub rule_top_cause: Option<String>,
    /// The most trusted label, if any: lab, then expert, then user.
    pub label: Option<Label>,
}

pub fn summarise(ep: &Episode, path: &Path) -> HistoryEntry {
    let rank = |s: &LabelSource| match s {
        LabelSource::Lab => 3,
        LabelSource::Expert { .. } => 2,
        LabelSource::User => 1,
        LabelSource::Rule => 0,
    };
    let mut issues: Vec<HistoryIssue> = Vec::new();
    for snap in &ep.issues {
        let key = issue_key(&snap.issue);
        let entry = match issues
            .iter_mut()
            .rev()
            .find(|i| i.key == key && i.closed.is_none())
        {
            Some(e) => e,
            None => {
                issues.push(HistoryIssue {
                    key: key.clone(),
                    rule: snap.issue.rule.clone(),
                    title: snap.issue.title.clone(),
                    opened: snap.issue.since.clone(),
                    closed: None,
                    rule_top_cause: None,
                    label: ep
                        .labels
                        .iter()
                        .filter(|l| l.issue == key)
                        .max_by_key(|l| rank(&l.source))
                        .cloned(),
                });
                issues.last_mut().expect("just pushed")
            }
        };
        entry.rule_top_cause = snap.issue.top_cause().map(|c| c.key(&snap.issue.rule));
        if snap.reason == SnapshotReason::Closed {
            entry.closed = Some(snap.ts.clone());
        }
    }
    HistoryEntry {
        path: path.to_path_buf(),
        id: ep.id.clone(),
        source: ep.source.clone(),
        started: ep.started.clone(),
        ended: ep.ended.clone(),
        duration_secs: ep.duration_secs(),
        issues,
    }
}

/// The newest `limit` incident episodes under `root`, newest first. Quiet
/// samples are not incidents and are left out.
pub fn history(root: &Path, limit: usize) -> Vec<HistoryEntry> {
    list(root)
        .into_iter()
        .rev()
        .filter_map(|p| load(&p).ok().map(|ep| summarise(&ep, &p)))
        .filter(|h| h.source != EpisodeSource::QuietSample)
        .take(limit)
        .collect()
}

/// Answers offered when asking what caused an issue, as `(label, wording)`.
/// Candidate causes first, then the three ways of not naming one.
pub fn label_choices(issue: &Issue) -> Vec<(String, String)> {
    let mut choices: Vec<(String, String)> = issue
        .causes
        .iter()
        .map(|c| (c.key(&issue.rule), c.label.clone()))
        .collect();
    choices.push(("other".into(), "something else".into()));
    choices.push(("not_a_problem".into(), "not a real problem".into()));
    choices.push(("unknown".into(), "don't know".into()));
    choices
}

/// Add `label` to the newest saved episode under `root` that covers its issue.
/// Looks at the most recent `search` files only; an answer about a problem
/// from last month is not what this prompt is for.
pub fn label_saved(root: &Path, label: &Label, search: usize) -> std::io::Result<Option<PathBuf>> {
    for path in list(root).into_iter().rev().take(search) {
        let Ok(mut ep) = load(&path) else {
            continue;
        };
        let covers = ep.issue_keys().contains(&label.issue)
            || ep.issues.iter().any(|s| issue_key(&s.issue) == label.issue);
        if covers {
            ep.labels.push(label.clone());
            let dir = root;
            let written = save(dir, &ep)?;
            if written != path {
                std::fs::remove_file(&path)?;
            }
            return Ok(Some(written));
        }
    }
    Ok(None)
}

/// Every saved episode (`*.json.gz`) under `root`, oldest first by
/// modification time.
pub fn list(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.to_string_lossy().ends_with(".json.gz") {
                // Only what `save` writes. `prune` deletes from this list, so
                // a schema.json or notes file beside the episodes must never
                // appear in it.
                out.push(path);
            }
        }
    }
    out.sort_by_key(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok());
    out
}

/// Delete episodes older than `max_age`, then the oldest until the total fits
/// `max_bytes`. Returns how many files were removed.
pub fn prune(root: &Path, max_age: Duration, max_bytes: u64) -> usize {
    let now = std::time::SystemTime::now();
    let mut files: Vec<(PathBuf, u64, std::time::SystemTime)> = list(root)
        .into_iter()
        .filter_map(|p| {
            let m = std::fs::metadata(&p).ok()?;
            Some((p, m.len(), m.modified().ok()?))
        })
        .collect();
    let mut removed = 0;
    files.retain(|(p, _, modified)| {
        let old = now.duration_since(*modified).is_ok_and(|age| age > max_age);
        if old && std::fs::remove_file(p).is_ok() {
            removed += 1;
            return false;
        }
        true
    });
    let mut total: u64 = files.iter().map(|f| f.1).sum();
    for (p, len, _) in &files {
        if total <= max_bytes {
            break;
        }
        if std::fs::remove_file(p).is_ok() {
            total -= len;
            removed += 1;
        }
    }
    removed
}

// ------------------------------------------------------------------ replay

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Divergence {
    pub frame: usize,
    pub ts: String,
    pub recorded: Vec<OpenIssue>,
    pub replayed: Vec<OpenIssue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IssueSpan {
    pub key: String,
    pub opened: String,
    pub closed: Option<String>,
    pub top_cause: Option<String>,
    /// Why the issue left the primary list: `"suppressed"` when it is still
    /// open under another issue, otherwise its state label (`"auto-closed"`,
    /// `"expired"`, `"resolved"`, `"muted"`), or `"pruned"` when the engine's
    /// history limit dropped it on the same tick. Without it an expiry, a
    /// suppression and a verified fix pin the same way. `None` while open,
    /// and in decisions pinned before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_reason: Option<String>,
}

/// Why `key`, primary on the previous frame, is not primary now.
fn close_reason(engine: &Engine, key: &str) -> String {
    match engine.get_by_key(key) {
        Some(issue) if issue.state.is_open() && issue.suppressed_by.is_some() => {
            "suppressed".into()
        }
        Some(issue) => issue.state.label().into(),
        None => "pruned".into(),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReplayReport {
    pub episode: String,
    pub frames: usize,
    pub issues: Vec<IssueSpan>,
    /// Frames where replay's open issues differ from the recording. Issues
    /// open before recording began, and user actions (ack, mute, apply)
    /// during it, are not replayed and can show up here.
    pub divergences: Vec<Divergence>,
    pub first_frame_open: Vec<OpenIssue>,
}

impl ReplayReport {
    pub fn matches(&self) -> bool {
        self.divergences.is_empty()
    }
}

/// Run an episode's frames through a fresh engine, exactly as the live tick
/// did: evaluate at the recorded clock and probe ages, then learn.
pub fn replay(episode: &Episode) -> ReplayReport {
    let mut report = ReplayReport {
        episode: episode.id.clone(),
        frames: episode.frames.len(),
        issues: vec![],
        divergences: vec![],
        first_frame_open: episode
            .frames
            .first()
            .map(|f| f.open.clone())
            .unwrap_or_default(),
    };
    let mut spans: Vec<IssueSpan> = Vec::new();
    let mut was_open: HashSet<String> = HashSet::new();

    drive(episode, |step| {
        let (n, frame) = (step.index, step.frame);
        let open: Vec<OpenIssue> = step.engine.primary().into_iter().map(open_issue).collect();
        if sorted(&open) != sorted(&frame.open) {
            report.divergences.push(Divergence {
                frame: n,
                ts: frame.ts.clone(),
                recorded: frame.open.clone(),
                replayed: open.clone(),
            });
        }
        let now_open: HashSet<String> = open.iter().map(|o| o.key.clone()).collect();
        for o in &open {
            if !was_open.contains(&o.key) {
                spans.push(IssueSpan {
                    key: o.key.clone(),
                    opened: frame.ts.clone(),
                    closed: None,
                    top_cause: o.top_cause.clone(),
                    close_reason: None,
                });
            }
            if let Some(span) = spans
                .iter_mut()
                .rev()
                .find(|s| s.key == o.key && s.closed.is_none())
            {
                span.top_cause = o.top_cause.clone();
            }
        }
        for key in was_open.difference(&now_open) {
            if let Some(span) = spans
                .iter_mut()
                .rev()
                .find(|s| &s.key == key && s.closed.is_none())
            {
                span.closed = Some(frame.ts.clone());
                span.close_reason = Some(close_reason(step.engine, key));
            }
        }
        was_open = now_open;
    });
    report.issues = spans;
    report
}

/// The engine's state right after evaluating one recorded frame, before that
/// frame's readings are learned.
pub struct Step<'a> {
    pub index: usize,
    pub frame: &'a Frame,
    pub engine: &'a Engine,
    pub baselines: &'a BaselineStore,
}

/// Run an episode's frames through a fresh engine exactly as the live tick
/// did — evaluate at the recorded clock and probe ages, then learn — calling
/// `on_step` between the two.
pub fn drive(episode: &Episode, mut on_step: impl FnMut(Step<'_>)) {
    // Each frame sets the clock below. `FixedClock::at` panics on a time
    // that does not parse, or that names two instants because a clock went
    // back in that hour, and a recording can hold either.
    let clock = std::sync::Arc::new(FixedClock::at("1970-01-01 00:00:00"));
    let mut engine = Engine::new(Box::new(clock.clone())).with_settings(episode.settings);
    let mut store: Option<BaselineStore> = None;
    // Real instants, offset by recorded time. Nothing here sleeps, so these
    // are only ever compared with each other.
    let base = Instant::now() + Duration::from_secs(86_400);
    let t0 = episode.frames.first().map(|f| f.at).unwrap_or(0.0);

    for (index, frame) in episode.frames.iter().enumerate() {
        clock.set(&frame.ts);
        if let Some(snap) = &frame.baselines {
            match store.as_mut() {
                Some(s) => s.restore(snap),
                None => store = Some(BaselineStore::from_snapshot(snap)),
            }
        }
        let Some(store) = store.as_mut() else {
            continue;
        };
        // A frame further on than an `Instant` reaches is not one netwatch
        // recorded, and there is no time to evaluate it at.
        let Some(now) = Duration::try_from_secs_f64((frame.at - t0).max(0.0))
            .ok()
            .and_then(|d| base.checked_add(d))
        else {
            continue;
        };
        let times = frame.ages.to_times(base, frame.at - t0);
        for event in &frame.events {
            engine.apply_event(event);
        }
        engine.observe_live_at(&frame.obs, store, &times, now);

        on_step(Step {
            index,
            frame,
            engine: &engine,
            baselines: store,
        });

        let t = engine.settings().thresholds;
        store.set_gate(t.sigma_k, t.sigma_floor());
        for r in &frame.readings {
            store.observe(&r.subject, &r.metric, r.value, r.at);
        }
    }
}

fn sorted(open: &[OpenIssue]) -> Vec<OpenIssue> {
    let mut v = open.to_vec();
    v.sort_by(|a, b| a.key.cmp(&b.key));
    v
}

// ------------------------------------------------------------------ cli

/// The decisions a pinned episode must keep producing: which issues opened,
/// when, what each one was blamed on, and why each left the list.
///
/// This is what the corpus compares, rather than the whole engine state: an
/// issue opening a frame later, or landing on a different cause, is a change
/// worth reviewing, while a reworded detail string is not.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CanonicalDecisions {
    pub episode: String,
    pub frames: usize,
    pub issues: Vec<IssueSpan>,
}

impl CanonicalDecisions {
    pub fn of(episode: &Episode) -> (Self, ReplayReport) {
        let report = replay(episode);
        (
            Self {
                episode: episode.id.clone(),
                frames: report.frames,
                issues: report.issues.clone(),
            },
            report,
        )
    }
}

/// The pinned corpus, relative to the crate root.
pub const CORPUS_DIR: &str = "tests/diagnose/corpus";
/// The file in the corpus directory that lists its episodes.
pub const MANIFEST: &str = "manifest.toml";

/// Where a corpus episode's frames come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusKind {
    /// Built by a scenario in [`super::fixture`]. `diagnose corpus` rebuilds
    /// its frames, so they must replay to themselves.
    Synthetic,
    /// Recorded by the health lab through the real `App::tick`. Its frames
    /// are kept as recorded and only its decisions are derived again. It is
    /// not held to replaying its recording frame for frame: an issue already
    /// open when a live recording began shows as a divergence.
    Lab,
}

/// One row of the corpus manifest.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusEntry {
    /// Names `<id>.json.gz` and `<id>.decisions.json` beside the manifest.
    pub id: String,
    pub kind: CorpusKind,
    /// Rule ids the episode is there to pin.
    pub rules: Vec<String>,
    pub note: String,
}

impl CorpusEntry {
    pub fn episode_path(&self, dir: &Path) -> PathBuf {
        dir.join(format!("{}.json.gz", self.id))
    }

    pub fn decisions_path(&self, dir: &Path) -> PathBuf {
        dir.join(format!("{}.decisions.json", self.id))
    }
}

/// `tests/diagnose/corpus/manifest.toml`: every pinned episode, one
/// `[[episode]]` table each. The replay test iterates it, so an episode
/// is tested because it is listed, not because a test names its file.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default, rename = "episode")]
    pub entries: Vec<CorpusEntry>,
}

impl Manifest {
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let path = dir.join(MANIFEST);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        let manifest: Self =
            toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        let mut seen = HashSet::new();
        for entry in &manifest.entries {
            anyhow::ensure!(
                seen.insert(entry.id.as_str()),
                "{}: {} is listed twice",
                path.display(),
                entry.id
            );
            for rule in &entry.rules {
                anyhow::ensure!(
                    super::rules::lookup(rule).is_some(),
                    "{}: {} names {rule}, which is not in the catalogue",
                    path.display(),
                    entry.id
                );
            }
        }
        Ok(manifest)
    }
}

/// Write the pinned corpus from its manifest, or only the entry `only`.
///
/// A synthetic entry is rebuilt from its scenario and written with its
/// decisions. A lab entry keeps the frames it was recorded with, and only its
/// decisions are derived again by the engine as it is now.
pub fn write_corpus(dir: &Path, only: Option<&str>) -> anyhow::Result<Vec<PathBuf>> {
    let manifest = Manifest::load(dir)?;
    if let Some(id) = only {
        anyhow::ensure!(
            manifest.entries.iter().any(|e| e.id == id),
            "{id} is not in {}",
            dir.join(MANIFEST).display()
        );
    }
    let mut written = vec![];
    for entry in &manifest.entries {
        if only.is_some_and(|id| id != entry.id) {
            continue;
        }
        let episode = match entry.kind {
            CorpusKind::Synthetic => super::fixture::synthetic(&entry.id).ok_or_else(|| {
                anyhow::anyhow!("{}: no scenario in fixture.rs builds it", entry.id)
            })?,
            CorpusKind::Lab => load(&entry.episode_path(dir))
                .map_err(|e| anyhow::anyhow!("{}: {e}", entry.episode_path(dir).display()))?,
        };
        let (decisions, report) = CanonicalDecisions::of(&episode);
        if entry.kind == CorpusKind::Synthetic {
            anyhow::ensure!(
                report.matches(),
                "{}: the episode does not replay to its own recording; \
                 fix that before pinning it",
                entry.id
            );
            // Gzipped, like a real recording: the fixture scenario is 440
            // frames and 2MB of pretty JSON, which is not something to put
            // in a diff.
            let ep_path = entry.episode_path(dir);
            {
                let file = std::fs::File::create(&ep_path)?;
                let mut gz = flate2::write::GzEncoder::new(file, flate2::Compression::best());
                serde_json::to_writer(&mut gz, &episode)?;
                gz.finish()?.flush()?;
            }
            written.push(ep_path);
        }
        let dec_path = entry.decisions_path(dir);
        std::fs::write(&dec_path, serde_json::to_string_pretty(&decisions)?)?;
        written.push(dec_path);
    }
    Ok(written)
}

/// Every `netwatch diagnose` subcommand `command` routes. The shell
/// completions and the man page are tested against this list.
pub const SUBCOMMANDS: &[&str] = &[
    "run", "coverage", "episodes", "replay", "features", "export", "corpus",
];

/// `netwatch diagnose <SUBCOMMAND>`, one of [`SUBCOMMANDS`].
pub fn command(args: &[String]) -> anyhow::Result<()> {
    match args.first().map(String::as_str) {
        Some("coverage") => super::coverage::command(&args[1..]),
        Some("run") => super::run::command(&args[1..]),
        Some("corpus") => {
            let mut only = None;
            let mut dir = None;
            let mut rest = args[1..].iter();
            while let Some(arg) = rest.next() {
                match arg.as_str() {
                    "--only" => {
                        only = Some(
                            rest.next()
                                .ok_or_else(|| anyhow::anyhow!("--only needs an entry id"))?,
                        )
                    }
                    flag if flag.starts_with("--") => anyhow::bail!("unknown option {flag}"),
                    _ if dir.is_none() => dir = Some(PathBuf::from(arg)),
                    _ => anyhow::bail!("usage: netwatch diagnose corpus [--only ID] [DIR]"),
                }
            }
            let dir = dir.unwrap_or_else(|| PathBuf::from(CORPUS_DIR));
            for path in write_corpus(&dir, only.map(String::as_str))? {
                println!("wrote {}", path.display());
            }
            Ok(())
        }
        Some("episodes") => {
            let dir = match args.get(1) {
                Some(d) => PathBuf::from(d),
                None => default_dir().ok_or_else(|| anyhow::anyhow!("no state directory"))?,
            };
            let files = list(&dir);
            if files.is_empty() {
                println!("no episodes under {}", dir.display());
            }
            for path in files {
                match load(&path) {
                    Ok(ep) => println!("{}", summary_line(&ep, &path)),
                    Err(e) => println!("{}  unreadable: {e}", shown(&path)),
                }
            }
            Ok(())
        }
        Some("replay") => {
            let json = args.iter().any(|a| a == "--json");
            let targets: Vec<&String> = args[1..].iter().filter(|a| *a != "--json").collect();
            if targets.is_empty() {
                anyhow::bail!("replay needs at least one episode file or directory");
            }
            let mut all_match = true;
            let mut reports = Vec::new();
            for target in targets {
                let path = Path::new(target);
                let files = if path.is_dir() {
                    list(path)
                } else {
                    vec![path.to_path_buf()]
                };
                for file in files {
                    let ep =
                        load(&file).map_err(|e| anyhow::anyhow!("{}: {e}", shown(&file)))?;
                    let report = replay(&ep);
                    all_match &= report.matches();
                    if json {
                        reports.push(report);
                    } else {
                        print!("{}", render_report(&report, &file));
                    }
                }
            }
            if json {
                println!("{}", replay_json(&reports)?);
            }
            if !all_match {
                anyhow::bail!("replay diverged from the recording");
            }
            Ok(())
        }
        Some("features") => super::features::command(&args[1..]),
        Some("export") => super::export::command(&args[1..]),
        _ => anyhow::bail!(
            "usage: netwatch diagnose run [--target NAME] [--budget 30s] [--format json|text]\n       netwatch diagnose coverage [--json] [--seconds N] [--test ID]\n       netwatch diagnose episodes [DIR]\n       netwatch diagnose replay [--json] <FILE|DIR>...\n       netwatch diagnose features [--out FILE] [--schema FILE] <FILE|DIR>...\n       netwatch diagnose export [--since DAYS] [--out FILE] [--dry-run] [DIR]\n       netwatch diagnose corpus [--only ID] [DIR]"
        ),
    }
}

/// `replay --json`, with every unsafe character in its strings written as a
/// `\u` escape. serde_json escapes C0 controls only, so DEL, C1 (the 8-bit
/// CSI among them) and bidi overrides from the file would reach the terminal
/// as they are. Outside its strings, pretty JSON holds only spaces and
/// newlines, so every other unsafe character is inside one and the escape
/// decodes to the same value. Each is in the BMP, so one `\u` covers it.
fn replay_json(reports: &[ReplayReport]) -> serde_json::Result<String> {
    use std::fmt::Write as _;
    let json = serde_json::to_string_pretty(reports)?;
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if c != '\n' && is_unsafe(c) {
            let _ = write!(out, "\\u{:04x}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// A path for the terminal. Episodes are files people pass around, so a
/// name in a directory listing is someone else's text too.
fn shown(path: &Path) -> String {
    display_owned(path.display().to_string())
}

/// One line of `diagnose episodes`. Its strings come from the file, so each
/// goes through [`display`] on its way to the terminal, as in
/// [`render_report`].
fn summary_line(ep: &Episode, path: &Path) -> String {
    let source = match &ep.source {
        EpisodeSource::Live => "live".to_string(),
        EpisodeSource::QuietSample => "quiet".to_string(),
        EpisodeSource::Lab { scenario, seed } => format!("lab:{}#{seed}", display(scenario)),
    };
    let keys = ep.issue_keys();
    format!(
        "{}  {:<6} {}  {:>4}m  {:>5} frames  {}  {}",
        display(&ep.id.chars().take(8).collect::<String>()),
        source,
        display(&ep.started),
        (ep.duration_secs() / 60.0).round() as u64,
        ep.frames.len(),
        if keys.is_empty() {
            "no issues".to_string()
        } else {
            display_owned(keys.join(", "))
        },
        shown(path)
    )
}

fn render_report(report: &ReplayReport, path: &Path) -> String {
    let mut out = format!(
        "{}  {} frames  {}\n",
        shown(path),
        report.frames,
        if report.matches() {
            "matches recording".to_string()
        } else {
            format!("{} divergent frames", report.divergences.len())
        }
    );
    for span in &report.issues {
        out.push_str(&format!(
            "  {}  opened {}  {}  cause {}\n",
            display(&span.key),
            display(&span.opened),
            match (&span.closed, &span.close_reason) {
                (Some(c), Some(reason)) => {
                    format!("closed {} ({})", display(c), display(reason))
                }
                (Some(c), None) => format!("closed {}", display(c)),
                (None, _) => "still open".to_string(),
            },
            display(span.top_cause.as_deref().unwrap_or("none"))
        ));
    }
    if !report.first_frame_open.is_empty() {
        out.push_str("  note: issues were already open when recording began\n");
    }
    if let Some(d) = report.divergences.first() {
        let keys = |v: &[OpenIssue]| {
            v.iter()
                .map(|o| {
                    format!(
                        "{} ({})",
                        display(&o.key),
                        display(o.top_cause.as_deref().unwrap_or("-"))
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push_str(&format!(
            "  first divergence at frame {} ({}):\n    recorded: {}\n    replayed: {}\n",
            d.frame,
            display(&d.ts),
            keys(&d.recorded),
            keys(&d.replayed)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::baseline::NetworkFingerprint;
    use crate::diagnose::detectors::GatewayObs;
    use crate::diagnose::engine::Clock;

    const GW: &str = "192.168.8.1";
    const T0: f64 = 1_789_000_000.0;

    /// A live session driven exactly like `App::tick_diagnose`: evaluate at
    /// `now`, record, then learn.
    struct Session {
        clock: std::sync::Arc<FixedClock>,
        engine: Engine,
        store: BaselineStore,
        recorder: Recorder,
        base: Instant,
        at: f64,
        finished: Vec<Episode>,
    }

    impl Session {
        fn new() -> Self {
            let clock = std::sync::Arc::new(FixedClock::at("2026-09-14 09:00:00"));
            let engine = Engine::new(Box::new(clock.clone()));
            let mut store = BaselineStore::new(NetworkFingerprint::new(
                "eth0",
                Some(GW.into()),
                vec!["192.168.8.1".into()],
                None,
            ));
            store.seed(GW, "gateway.rtt", 2.0, 0.3, 2_400);
            let mut recorder = Recorder::new(EnvProfile::detect("no privileges", 1000), T0);
            recorder.schedule_quiet_sample(f64::MAX);
            Self {
                clock,
                engine,
                store,
                recorder,
                base: Instant::now() + Duration::from_secs(86_400),
                at: T0,
                finished: vec![],
            }
        }

        fn tick(&mut self, rtt: f64, step: f64) {
            self.tick_with(
                GatewayObs {
                    addr: Some(GW.into()),
                    rtt_ms: Some(rtt),
                    loss_pct: 0.0,
                    arp_ok: Some(true),
                    icmp_ok: true,
                    internet_reachable: Some(true),
                },
                step,
            );
        }

        fn tick_with(&mut self, gateway: GatewayObs, step: f64) {
            let now = self.base + Duration::from_secs_f64(self.at - T0);
            let mut times = ObservationTimes::default();
            times.health.gateway = now.checked_sub(Duration::from_secs(1));
            // The internet probe completes with the gateway's; without it
            // gateway.unreachable has no corroboration and cannot open.
            times.health.internet = times.health.gateway;
            times.health.gateway_target = Some(GW.into());
            let readings: Vec<Reading> = gateway
                .rtt_ms
                .map(|rtt| Reading::new(GW, "gateway.rtt", rtt, self.at - 1.0))
                .into_iter()
                .collect();
            let obs = Observations {
                now: super::super::engine::format_ts(self.clock.now()),
                gateway: Some(gateway),
                ..Default::default()
            };
            let events = self.engine.take_events();
            self.engine.observe_live_at(&obs, &self.store, &times, now);
            let ts = super::super::engine::format_ts(self.clock.now());
            if let Some(ep) = self.recorder.record(Tick {
                at: self.at,
                ts,
                now,
                obs: &obs,
                times: &times,
                readings: &readings,
                engine: &self.engine,
                baselines: &self.store,
                events,
            }) {
                self.finished.push(ep);
            }
            let t = self.engine.settings().thresholds;
            self.store.set_gate(t.sigma_k, t.sigma_floor());
            for r in &readings {
                self.store.observe(&r.subject, r.metric, r.value, r.at);
            }
            self.at += step;
            self.clock.advance_secs(step as i64);
        }

        fn run(&mut self, rtt: impl Fn(u32) -> f64, secs: f64, step: f64) {
            let ticks = (secs / step) as u32;
            for i in 0..ticks {
                self.tick(rtt(i), step);
            }
        }
    }

    fn healthy(i: u32) -> f64 {
        if i.is_multiple_of(2) {
            1.7
        } else {
            2.3
        }
    }

    fn incident() -> Session {
        let mut s = Session::new();
        s.run(healthy, 900.0, 5.0);
        s.run(|_| 80.0, 600.0, 5.0);
        s.run(healthy, 1_800.0, 5.0);
        s
    }

    /// The usage error is the only listing of `diagnose` subcommands a user
    /// sees without the man page, so it names every one `command` routes.
    #[test]
    fn usage_names_every_subcommand() {
        let err = command(&["no-such-subcommand".to_string()])
            .unwrap_err()
            .to_string();
        for sub in SUBCOMMANDS {
            assert!(
                err.contains(&format!("netwatch diagnose {sub} ")),
                "usage is missing {sub}: {err}"
            );
        }
    }

    #[test]
    fn an_incident_becomes_one_episode_with_pre_and_post_roll() {
        let s = incident();
        assert!(!s.recorder.is_recording());
        assert_eq!(s.finished.len(), 1, "one incident, one episode");
        let ep = &s.finished[0];
        assert_eq!(ep.source, EpisodeSource::Live);
        assert_eq!(ep.issue_keys(), vec!["gateway.rtt_spike|host".to_string()]);

        let first_open = ep.frames.iter().position(|f| !f.open.is_empty()).unwrap();
        let pre_roll = ep.frames[first_open].at - ep.frames[0].at;
        assert!(
            (PRE_ROLL_SECS - 10.0..=PRE_ROLL_SECS).contains(&pre_roll),
            "pre-roll {pre_roll}s"
        );
        let last_open = ep.frames.iter().rposition(|f| !f.open.is_empty()).unwrap();
        let post_roll = ep.frames.last().unwrap().at - ep.frames[last_open].at;
        assert!(post_roll >= POST_ROLL_SECS, "post-roll {post_roll}s");

        assert!(ep.frames[0].baselines.is_some());
        assert_eq!(
            ep.frames.iter().filter(|f| f.baselines.is_some()).count(),
            1
        );
        let reasons: Vec<_> = ep.issues.iter().map(|i| i.reason).collect();
        assert_eq!(
            reasons,
            vec![SnapshotReason::Opened, SnapshotReason::Closed]
        );
    }

    /// One manifest entry against the engine as it is now. `Err` names the
    /// entry, so a failure says which episode moved.
    fn check_entry(dir: &Path, entry: &CorpusEntry) -> Result<(), String> {
        let fail = |what: String| format!("{}: {what}", entry.id);
        let ep_path = entry.episode_path(dir);
        let episode = load(&ep_path).map_err(|e| fail(format!("{}: {e}", ep_path.display())))?;
        let dec_path = entry.decisions_path(dir);
        let pinned: CanonicalDecisions = std::fs::read_to_string(&dec_path)
            .map_err(|e| e.to_string())
            .and_then(|text| serde_json::from_str(&text).map_err(|e| e.to_string()))
            .map_err(|e| fail(format!("{}: {e}", dec_path.display())))?;
        let (decisions, report) = CanonicalDecisions::of(&episode);
        if entry.kind == CorpusKind::Synthetic {
            if let Some(d) = report.divergences.first() {
                return Err(fail(format!(
                    "replay diverged from the recording at frame {} ({})",
                    d.frame, d.ts
                )));
            }
        }
        if decisions != pinned {
            return Err(fail(format!(
                "the engine now reaches different decisions; if that is intended, \
                 run `cargo run -- diagnose corpus --only {}` and review the diff\n  \
                 pinned:   {:?}\n  replayed: {:?}",
                entry.id, pinned.issues, decisions.issues
            )));
        }
        Ok(())
    }

    #[test]
    fn every_corpus_entry_replays_to_its_pinned_decisions() {
        // A replay compared against a recording made in the same test cannot
        // catch a change that alters both sides. These are committed
        // episodes and the decisions each must keep producing: which issues
        // open, when, what each is blamed on and why it ended.
        //
        // A semantic fix that changes them is expected to change these
        // files, reviewed in the same diff. Regenerate with:
        //   cargo run -- diagnose corpus [--only ID]
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS_DIR);
        let manifest = Manifest::load(&dir).expect("corpus manifest");
        assert!(!manifest.entries.is_empty());
        let failures: Vec<String> = manifest
            .entries
            .iter()
            .filter_map(|entry| check_entry(&dir, entry).err())
            .collect();
        assert!(
            failures.is_empty(),
            "{} of {} corpus entries failed:\n{}",
            failures.len(),
            manifest.entries.len(),
            failures.join("\n")
        );
        // An episode no row lists would never be checked.
        let unlisted: Vec<PathBuf> = list(&dir)
            .into_iter()
            .filter(|p| !manifest.entries.iter().any(|e| &e.episode_path(&dir) == p))
            .collect();
        assert!(unlisted.is_empty(), "not in {MANIFEST}: {unlisted:?}");
    }

    /// Every rule whose open condition or verify a 0.33 or 0.34 PR changed,
    /// and the socket rules B25 made closable, each with the closes that
    /// count for it. REVIEW §2's exit clause 2 asks each for a pinned
    /// episode in which it opens and closes. A PR that changes another
    /// rule's open condition or verify adds its row here and its episode to
    /// the corpus. B25's expiry of a removed target, resolver or interface
    /// holds for every rule with that subject and is pinned by its engine
    /// tests, not by an episode per rule, so only the socket rules count it
    /// as a close.
    const TOUCHED_SINCE_0_32: &[(&str, &[&str])] = &[
        // B09's σ floor, B10's delta floors, B13's close line.
        ("dns.slow_resolver", VERIFY),
        // B09, B10, and B11's 2σ close line.
        ("gateway.rtt_spike", VERIFY),
        // A05: opens only on a carrier read as down, closes only on one
        // read as up.
        ("link.down", VERIFY),
        // A04's idle radio and A05's unknown one.
        ("wifi.weak_signal", VERIFY),
        // A06: errors alone where drops are not counted.
        ("iface.errors", VERIFY),
        // B09 and B11.
        ("path.rtt_spike", VERIFY),
        ("target.slow_stage", VERIFY),
        // A03's socket with no rtt, and B25's expiry once the socket closes.
        ("tcp.bufferbloat_remote", VERIFY_OR_EXPIRY),
        ("tcp.retrans_burst", VERIFY_OR_EXPIRY),
        // B25.
        ("tcp.zero_window", VERIFY_OR_EXPIRY),
    ];

    /// A verify that held. A suppression, a mute or a user's resolve ends a
    /// span without the rule closing.
    const VERIFY: &[&str] = &["auto-closed"];
    /// A verify that held, or the socket going away (B25).
    const VERIFY_OR_EXPIRY: &[&str] = &["auto-closed", "expired"];

    /// Touched rules that no episode can close yet, each with the reason.
    /// The owner accepts each row in the PR that adds it, and
    /// `pending_close_entries_are_still_needed` fails once the rule closes
    /// in an episode, so the row goes with the fix.
    const PENDING_CLOSE: &[(&str, &str)] = &[(
        "iface.errors",
        "it closes only under 1/min errors and drops combined, which a Wi-Fi \
         driver's background drops never allow, until B19 retunes it",
    )];

    /// Each corpus entry that lists `rule` among the rules it pins, with its
    /// pinned spans of that rule.
    fn pinned_spans_of(rule: &str) -> Vec<(String, Vec<IssueSpan>)> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS_DIR);
        let manifest = Manifest::load(&dir).expect("corpus manifest");
        manifest
            .entries
            .iter()
            .filter(|entry| entry.rules.iter().any(|r| r == rule))
            .map(|entry| {
                let path = entry.decisions_path(&dir);
                let decisions: CanonicalDecisions = std::fs::read_to_string(&path)
                    .map_err(|e| e.to_string())
                    .and_then(|text| serde_json::from_str(&text).map_err(|e| e.to_string()))
                    .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                let spans = decisions
                    .issues
                    .into_iter()
                    .filter(|span| span.key.split('|').next() == Some(rule))
                    .collect();
                (entry.id.clone(), spans)
            })
            .collect()
    }

    /// Whether `span` ended in one of `closes`.
    fn closed_by(span: &IssueSpan, closes: &[&str]) -> bool {
        span.close_reason
            .as_deref()
            .is_some_and(|reason| closes.contains(&reason))
    }

    /// REVIEW §2's exit clause 2, as a test: each touched rule opens in an
    /// episode that lists it, and closes there too, or has a PENDING_CLOSE
    /// row saying why it cannot yet.
    #[test]
    fn every_touched_rule_has_an_open_close_episode() {
        let failures: Vec<String> = TOUCHED_SINCE_0_32
            .iter()
            .filter_map(|&(rule, counted)| {
                if crate::diagnose::rules::lookup(rule).is_none() {
                    return Some(format!("{rule}: not in the catalogue"));
                }
                let episodes = pinned_spans_of(rule);
                let opening: Vec<&str> = episodes
                    .iter()
                    .filter(|(_, spans)| !spans.is_empty())
                    .map(|(id, _)| id.as_str())
                    .collect();
                let closes = episodes
                    .iter()
                    .any(|(_, spans)| spans.iter().any(|span| closed_by(span, counted)));
                let pending = PENDING_CLOSE.iter().any(|(r, _)| *r == rule);
                if opening.is_empty() {
                    Some(format!(
                        "{rule}: no corpus entry that lists it opens it; pin an episode \
                         in {MANIFEST} that does"
                    ))
                } else if !closes && !pending {
                    Some(format!(
                        "{rule}: opens in {opening:?} but never closes by {counted:?}; \
                         pin an episode that closes it, or add a PENDING_CLOSE row saying \
                         why it cannot"
                    ))
                } else {
                    None
                }
            })
            .collect();
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn pending_close_entries_are_still_needed() {
        for (rule, why) in PENDING_CLOSE {
            let (_, counted) = TOUCHED_SINCE_0_32
                .iter()
                .find(|(r, _)| r == rule)
                .unwrap_or_else(|| {
                    panic!("{rule} is pending a close but is not in TOUCHED_SINCE_0_32")
                });
            let closing: Vec<String> = pinned_spans_of(rule)
                .into_iter()
                .filter(|(_, spans)| spans.iter().any(|span| closed_by(span, counted)))
                .map(|(id, _)| id)
                .collect();
            assert!(
                closing.is_empty(),
                "{rule} now closes in {closing:?}, so its PENDING_CLOSE row (\"{why}\") must go"
            );
        }
    }

    fn scratch_corpus(name: &str, manifest: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nw-corpus-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(MANIFEST), manifest).unwrap();
        dir
    }

    #[test]
    fn a_manifest_entry_without_files_fails() {
        let dir = scratch_corpus(
            "missing",
            "[[episode]]\nid = \"nowhere\"\nkind = \"synthetic\"\nrules = []\nnote = \"\"\n",
        );
        let manifest = Manifest::load(&dir).unwrap();
        let err = check_entry(&dir, &manifest.entries[0]).unwrap_err();
        assert!(err.starts_with("nowhere: "), "{err}");
        // Nor can one be pinned: no scenario builds it.
        let err = write_corpus(&dir, None).unwrap_err().to_string();
        assert!(err.starts_with("nowhere: "), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_manifest_row_naming_an_unknown_rule_is_refused() {
        let dir = scratch_corpus(
            "typo",
            "[[episode]]\nid = \"a\"\nkind = \"lab\"\nrules = [\"gateway.unreachabel\"]\nnote = \"\"\n",
        );
        let err = Manifest::load(&dir).unwrap_err().to_string();
        assert!(err.contains("gateway.unreachabel"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_lab_entry_keeps_its_frames_and_rederives_decisions() {
        let dir = scratch_corpus(
            "lab",
            "[[episode]]\nid = \"lab-gateway\"\nkind = \"lab\"\n\
             rules = [\"gateway.rtt_spike\"]\nnote = \"\"\n",
        );
        let mut episode = incident().finished.remove(0);
        // A live recording can disagree with its replay on a frame, e.g. an
        // issue already open when recording began. Only the decisions, which
        // replay derives, are pinned for a lab row.
        let open_at = episode
            .frames
            .iter()
            .position(|f| !f.open.is_empty())
            .unwrap();
        episode.frames[open_at].open.clear();
        let ep_path = dir.join("lab-gateway.json.gz");
        {
            let file = std::fs::File::create(&ep_path).unwrap();
            let mut gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            serde_json::to_writer(&mut gz, &episode).unwrap();
            gz.finish().unwrap();
        }
        let recorded = std::fs::read(&ep_path).unwrap();

        assert!(write_corpus(&dir, Some("elsewhere")).is_err());
        let written = write_corpus(&dir, Some("lab-gateway")).unwrap();
        assert_eq!(written, vec![dir.join("lab-gateway.decisions.json")]);
        assert_eq!(std::fs::read(&ep_path).unwrap(), recorded);
        let mut entry = Manifest::load(&dir).unwrap().entries.remove(0);
        check_entry(&dir, &entry).unwrap();
        // The same files as a synthetic row fail: those must replay exactly.
        entry.kind = CorpusKind::Synthetic;
        let err = check_entry(&dir, &entry).unwrap_err();
        assert!(err.contains(&format!("frame {open_at}")), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn close_reason_distinguishes_suppression_from_close() {
        let mut s = Session::new();
        s.run(healthy, 900.0, 5.0);
        s.run(|_| 80.0, 120.0, 5.0);
        // Then the gateway stops answering at all, which explains the slow
        // replies: the rtt spike stays open, but under the outage.
        for _ in 0..24 {
            s.tick_with(
                GatewayObs {
                    addr: Some(GW.into()),
                    rtt_ms: None,
                    loss_pct: 100.0,
                    arp_ok: Some(false),
                    icmp_ok: false,
                    internet_reachable: Some(false),
                },
                5.0,
            );
        }
        s.run(healthy, 1_800.0, 5.0);

        let report = replay(&s.finished[0]);
        assert!(report.matches(), "{:#?}", report.divergences.first());
        let reasons = |key: &str| -> Vec<Option<&str>> {
            report
                .issues
                .iter()
                .filter(|span| span.key == key)
                .map(|span| span.close_reason.as_deref())
                .collect()
        };
        // Under the outage the spike leaves the list without closing, comes
        // back when the outage verifies closed, then verifies closed itself.
        assert_eq!(
            reasons("gateway.rtt_spike|host"),
            vec![Some("suppressed"), Some("auto-closed")],
            "{:#?}",
            report.issues
        );
        assert_eq!(
            reasons("gateway.unreachable|host"),
            vec![Some("auto-closed")],
            "{:#?}",
            report.issues
        );
        let (decisions, _) = CanonicalDecisions::of(&s.finished[0]);
        let json = serde_json::to_string(&decisions).unwrap();
        assert!(json.contains("\"close_reason\":\"suppressed\""), "{json}");
    }

    #[test]
    fn a_span_pinned_before_close_reason_still_parses() {
        let span: IssueSpan = serde_json::from_str(
            r#"{"key": "gateway.rtt_spike|host", "opened": "2026-09-14 09:15:00",
                "closed": "2026-09-14 09:27:00", "top_cause": null}"#,
        )
        .unwrap();
        assert_eq!(span.closed.as_deref(), Some("2026-09-14 09:27:00"));
        assert_eq!(span.close_reason, None);
        // And an open span still writes no close_reason at all.
        let open = IssueSpan {
            closed: None,
            ..span
        };
        assert!(!serde_json::to_string(&open)
            .unwrap()
            .contains("close_reason"));
    }

    #[test]
    fn an_episode_recorded_before_new_threshold_fields_still_loads() {
        // Every episode embeds the thresholds it ran with. One recorded
        // before a threshold existed has no key for it, and has to load with
        // the default: failing would orphan the corpus and every episode on
        // disk each time a threshold is added.
        let s = incident();
        let ep = &s.finished[0];
        let mut json = serde_json::to_value(ep).unwrap();
        let thresholds = json["settings"]["thresholds"].as_object_mut().unwrap();
        assert!(thresholds.remove("wifi_retry_pct").is_some());
        assert!(thresholds.remove("dns_tc_pct").is_some());
        // The σ floor arrived in 0.34, in the thresholds and in the
        // baseline snapshot on each frame.
        assert!(thresholds.remove("sigma_floor_ms").is_some());
        assert!(thresholds.remove("sigma_floor_pct").is_some());
        // So did the delta floors and the close line.
        assert!(thresholds.remove("sigma_close_k").is_some());
        assert!(thresholds.remove("gateway_delta_floor_ms").is_some());
        assert!(thresholds.remove("dns_delta_floor_ms").is_some());
        assert!(thresholds.remove("dns_delta_multiple").is_some());
        for frame in json["frames"].as_array_mut().unwrap() {
            if let Some(snap) = frame["baselines"].as_object_mut() {
                assert!(snap.remove("sigma_floor").is_some());
            }
        }
        let back: Episode = serde_json::from_value(json).unwrap();
        assert_eq!(back.settings, ep.settings);
        assert!(replay(&back).matches());
    }

    #[test]
    fn snapshots_taken_on_one_tick_are_in_key_order() {
        // Three issues are still open when the fixture episode ends. A hashed
        // map wrote their final snapshots in a new order each run, so the
        // pinned corpus changed on every regeneration.
        let ep = crate::diagnose::fixture::episode();
        let finals: Vec<String> = ep
            .issues
            .iter()
            .filter(|s| s.reason == SnapshotReason::Final)
            .map(|s| issue_key(&s.issue))
            .collect();
        assert_eq!(finals.len(), 3, "{finals:?}");
        assert!(finals.is_sorted(), "{finals:?}");
    }

    #[test]
    fn replay_reproduces_the_recording_frame_by_frame() {
        let s = incident();
        let report = replay(&s.finished[0]);
        assert!(report.matches(), "{:#?}", report.divergences.first());
        assert_eq!(report.issues.len(), 1);
        let span = &report.issues[0];
        assert!(span.closed.is_some());
        assert_eq!(
            span.top_cause.as_deref(),
            Some("gateway.rtt_spike/local_network_congested")
        );
    }

    #[test]
    fn user_actions_during_an_incident_replay_too() {
        let mut s = Session::new();
        s.run(healthy, 900.0, 5.0);
        s.run(|_| 80.0, 120.0, 5.0);
        let id = s.engine.primary()[0].id.clone();
        assert!(s.engine.mute(&id, 5));
        s.run(|_| 80.0, 480.0, 5.0);
        s.run(healthy, 1_800.0, 5.0);
        let ep = &s.finished[0];
        let events: Vec<_> = ep.frames.iter().flat_map(|f| &f.events).collect();
        assert!(matches!(
            events.as_slice(),
            [crate::diagnose::engine::EngineEvent::Muted { .. }]
        ));
        let report = replay(ep);
        assert!(report.matches(), "{:#?}", report.divergences.first());
        // Muting really changed what was open, so replay had to apply it.
        let muted_frames = ep.frames.iter().filter(|f| f.open.is_empty()).count();
        assert!(muted_frames > 0);
        // And the span the mute ended says so, rather than looking fixed.
        assert_eq!(report.issues[0].close_reason.as_deref(), Some("muted"));
    }

    /// A muted issue is not in `primary`, so the recorder took the incident
    /// for over and ended it ten minutes into the mute. When the mute ran out
    /// a second episode began, with a pre-roll recorded while the issue was
    /// muted; a fresh engine replaying it opened the issue there, and live
    /// showed nothing open.
    #[test]
    fn a_mute_that_ends_mid_fault_replays_as_one_episode() {
        let mut s = Session::new();
        s.run(healthy, 900.0, 5.0);
        s.run(|_| 80.0, 120.0, 5.0);
        let id = s.engine.primary()[0].id.clone();
        assert!(s.engine.mute(&id, 60));
        // The fault outlasts the hour's mute by eight minutes.
        s.run(|_| 80.0, 4_080.0, 5.0);
        s.run(healthy, 1_800.0, 5.0);
        assert_eq!(s.finished.len(), 1, "{:?}", s.finished.len());
        let report = replay(&s.finished[0]);
        assert!(report.matches(), "{:#?}", report.divergences.first());
        // Quiet for the hour, then back on the frame the mute ended.
        let spans: Vec<_> = report
            .issues
            .iter()
            .map(|s| (s.opened.as_str(), s.close_reason.as_deref()))
            .collect();
        assert_eq!(spans.len(), 2, "{:#?}", report.issues);
        assert_eq!(spans[0].1, Some("muted"));
        assert_eq!(spans[1].0, "2026-09-14 10:17:00");
    }

    #[test]
    fn a_label_lands_on_the_recording_or_the_saved_episode() {
        let key = "gateway.rtt_spike|host".to_string();
        let label = |cause: &str| Label {
            issue: key.clone(),
            cause: cause.into(),
            source: LabelSource::User,
            ts: "2026-09-14 10:00:00".into(),
            note: None,
        };
        let mut s = Session::new();
        s.run(healthy, 900.0, 5.0);
        s.run(|_| 80.0, 600.0, 5.0);
        assert!(s
            .recorder
            .label(&label("gateway.rtt_spike/local_network_congested")));
        s.run(healthy, 1_800.0, 5.0);
        assert_eq!(s.finished[0].labels.len(), 1);
        assert!(
            !s.recorder.label(&label("unknown")),
            "nothing is recording now"
        );

        let dir = std::env::temp_dir().join(format!("nw-label-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = save(&dir, &s.finished[0]).unwrap();
        let written = label_saved(&dir, &label("not_a_problem"), 10).unwrap();
        assert_eq!(written.as_deref(), Some(path.as_path()));
        let back = load(&path).unwrap();
        assert_eq!(back.labels.len(), 2);
        assert!(replay(&back).matches(), "labels don't change replay");
        let mut other = label("unknown");
        other.issue = "dns.failing|1.1.1.1".into();
        assert_eq!(label_saved(&dir, &other, 10).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);

        let history_dir = std::env::temp_dir().join(format!("nw-history-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&history_dir);
        let mut labelled = s.finished[0].clone();
        labelled
            .labels
            .push(label("gateway.rtt_spike/local_network_congested"));
        save(&history_dir, &labelled).unwrap();
        let h = history(&history_dir, 10);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].issues.len(), 1);
        assert!(h[0].issues[0].closed.is_some());
        assert_eq!(
            h[0].issues[0].label.as_ref().map(|l| l.cause.as_str()),
            Some("gateway.rtt_spike/local_network_congested")
        );
        let _ = std::fs::remove_dir_all(&history_dir);

        let issue = &s.finished[0].issues[0].issue;
        let choices = label_choices(issue);
        assert_eq!(choices[0].0, "gateway.rtt_spike/local_network_congested");
        assert_eq!(choices.last().unwrap().0, "unknown");
    }

    /// Recorded before a target's key carried its revision, an episode names
    /// its target issue `rule|name`. The engine files that issue under
    /// `rule|name|revision` now, so unless loading renames them, its labels
    /// and test results match nothing and drop out of the training rows and
    /// the history.
    #[test]
    fn a_recording_from_before_target_revisions_keeps_its_labels_and_tests() {
        use crate::diagnose::engine::EngineEvent;
        use crate::diagnose::next_test::{Outcome, TestRun};
        let key = "target.slow_stage|api|target-config:synthetic-api";
        let old = "target.slow_stage|api";
        let mut older = crate::diagnose::fixture::synthetic("target-slow-stage").unwrap();
        assert_eq!(older.issue_keys(), vec![key.to_string()]);
        for open in older.frames.iter_mut().flat_map(|f| &mut f.open) {
            open.key = old.into();
        }
        older.labels.push(Label {
            issue: old.into(),
            cause: "target.slow_stage/server_stage_slow".into(),
            source: LabelSource::User,
            ts: "2026-09-03 06:56:00".into(),
            note: None,
        });
        let tested = older
            .frames
            .iter()
            .position(|f| !f.open.is_empty())
            .unwrap()
            + 1;
        let at = older.frames[tested].ts.clone();
        older.frames[tested]
            .events
            .push(EngineEvent::TestCompleted {
                issue: old.into(),
                run: TestRun {
                    test: "load.idle_vs_loaded".into(),
                    at,
                    outcome: Outcome::Negative,
                    detail: String::new(),
                    measurements: Default::default(),
                    after_action: false,
                },
            });
        assert!(!replay(&older).matches());

        let dir = std::env::temp_dir().join(format!("nw-old-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = save(&dir, &older).unwrap();
        let back = load(&path).unwrap();
        assert_eq!(back.issue_keys(), vec![key.to_string()]);
        assert_eq!(back.labels[0].issue, key);
        assert!(matches!(
            back.frames[tested].events.as_slice(),
            [EngineEvent::TestCompleted { issue, .. }] if issue == key
        ));
        let report = replay(&back);
        assert!(report.matches(), "{:#?}", report.divergences.first());
        let rows = crate::diagnose::features::decisions(&back);
        let triggers: Vec<_> = rows.iter().map(|r| r.trigger).collect();
        assert_eq!(triggers, ["opened", "tested", "closed"]);
        assert!(rows
            .iter()
            .all(|r| r.label.as_deref() == Some("target.slow_stage/server_stage_slow")));
        let summary = summarise(&back, &path);
        assert!(summary.issues[0].label.is_some());
        let _ = std::fs::remove_dir_all(&dir);

        // Seen under two revisions, the issue is the one the new key splits,
        // and which revision each label or event meant is not recorded.
        let mut edited = older.clone();
        edited.issues.last_mut().unwrap().issue.scope.configuration =
            Some("target-config:edited".into());
        add_target_revisions(&mut edited);
        assert_eq!(edited.labels[0].issue, old);
        assert_eq!(edited.issue_keys(), vec![old.to_string()]);
    }

    #[test]
    fn a_test_result_during_an_incident_replays_and_becomes_a_decision_point() {
        use crate::diagnose::next_test::{Outcome, TestRun};
        let mut s = Session::new();
        s.run(healthy, 900.0, 5.0);
        s.run(|_| 80.0, 120.0, 5.0);
        let id = s.engine.primary()[0].id.clone();
        let at = super::super::engine::format_ts(s.clock.now());
        assert!(s.engine.record_test(
            &id,
            TestRun {
                test: "path.internet_tracks_gateway".into(),
                at,
                outcome: Outcome::Negative,
                detail: "internet flat while gateway rose".into(),
                measurements: Default::default(),
                after_action: false,
            },
        ));
        s.run(|_| 80.0, 480.0, 5.0);
        s.run(healthy, 1_800.0, 5.0);
        let ep = &s.finished[0];
        let report = replay(ep);
        assert!(report.matches(), "{:#?}", report.divergences.first());
        assert_eq!(
            report.issues[0].top_cause.as_deref(),
            Some("gateway.rtt_spike/gateway_loaded"),
            "the test moved the ranking, and replay kept it"
        );
        let rows = crate::diagnose::features::decisions(ep);
        let tested: Vec<_> = rows.iter().filter(|r| r.trigger == "tested").collect();
        assert_eq!(tested.len(), 1);
        let i = crate::diagnose::features::schema()
            .iter()
            .position(|f| f.name == "test.path.internet_tracks_gateway")
            .unwrap();
        assert_eq!(tested[0].values[i], -1.0);
    }

    #[test]
    fn one_probe_seen_on_many_frames_replays_as_one_sample() {
        let origin = Instant::now() + Duration::from_secs(3_600);
        // The same completion at t=4.0, recorded on frames with sub-ms jitter.
        let instants: Vec<_> = [(5.0, 1.0003), (6.0, 1.9998), (7.0005, 3.0004)]
            .iter()
            .map(|(frame, age)| {
                ProbeAges {
                    dns: Some(*age),
                    ..Default::default()
                }
                .to_times(origin, *frame)
                .health
                .dns
                .unwrap()
            })
            .collect();
        assert!(instants.windows(2).all(|w| w[0] == w[1]), "{instants:?}");
    }

    #[test]
    fn replay_reports_where_a_recording_disagrees() {
        let s = incident();
        let mut ep = s.finished[0].clone();
        let n = ep.frames.iter().position(|f| !f.open.is_empty()).unwrap();
        ep.frames[n].open.clear();
        let report = replay(&ep);
        assert_eq!(report.divergences.len(), 1);
        assert_eq!(report.divergences[0].frame, n);
    }

    #[test]
    fn episodes_round_trip_through_gzip_and_stay_small() {
        let s = incident();
        let ep = &s.finished[0];
        let dir = std::env::temp_dir().join(format!("nw-episodes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = save(&dir, ep).unwrap();
        assert!(path.starts_with(dir.join("2026-09")));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o077,
                0,
                "episodes hold addresses; keep them private"
            );
        }
        let back = load(&path).unwrap();
        assert_eq!(&back, ep);
        assert!(replay(&back).matches());
        let bytes = std::fs::metadata(&path).unwrap().len();
        assert!(
            bytes < 64 * 1024,
            "{} frames took {bytes} bytes",
            ep.frames.len()
        );
        assert_eq!(list(&dir), vec![path.clone()]);
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        command(&args(&["replay", path.to_str().unwrap()])).unwrap();
        command(&args(&["episodes", dir.to_str().unwrap()])).unwrap();
        assert!(render_report(&replay(&back), &path).contains("matches recording"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Byte 8 of this id falls inside the euro sign.
    #[test]
    fn summary_line_handles_multibyte_ids() {
        let mut ep = incident().finished.remove(0);
        ep.id = "aaaaaaa€".into();
        let line = summary_line(&ep, Path::new("ep.json.gz"));
        assert!(line.starts_with("aaaaaaa€  live "), "{line}");
    }

    /// An episode is a file someone can hand over, so whatever `episodes` and
    /// `replay` print from it reaches the terminal as text, never escapes.
    #[test]
    fn replay_report_escapes_control_characters() {
        use crate::ui::sanitize::is_unsafe;
        const OSC52: &str = "\x1b]52;c;aGk=\x07";
        let mut ep = incident().finished.remove(0);
        ep.id = format!("{OSC52}0123456789");
        ep.started = format!("{}{OSC52}", ep.started);
        ep.source = EpisodeSource::Lab {
            scenario: OSC52.into(),
            seed: 1,
        };
        for open in ep.frames.iter_mut().flat_map(|f| &mut f.open) {
            open.key = format!("{}{OSC52}", open.key);
            open.top_cause = Some(OSC52.into());
        }
        let mut report = replay(&ep);
        assert!(!report.matches(), "the recorded keys no longer match");
        // Spans copy their times from the frames. A frame time that does not
        // parse holds the replay's clock still and changes what replays, so
        // the times are set on the report instead.
        assert!(!report.issues.is_empty());
        for span in &mut report.issues {
            span.key = format!("{}{OSC52}", span.key);
            span.opened = format!("{}{OSC52}", span.opened);
            span.closed = Some(OSC52.into());
            span.close_reason = Some(OSC52.into());
        }
        report.divergences[0].ts = OSC52.into();
        let path = Path::new("episodes").join(format!("{OSC52}.json.gz"));
        let printed = format!(
            "{}\n{}",
            summary_line(&ep, &path),
            render_report(&report, &path)
        );
        assert!(printed.contains("first divergence"), "{printed:?}");
        for line in printed.lines() {
            assert!(!line.chars().any(is_unsafe), "{line:?}");
        }
    }

    /// serde_json escapes C0 controls only. DEL, C1 (the 8-bit CSI among
    /// them) and bidi overrides from the file reached the terminal as they
    /// were.
    #[test]
    fn replay_json_escapes_what_serde_json_leaves() {
        use crate::ui::sanitize::is_unsafe;
        let mut report = replay(&incident().finished.remove(0));
        let key = "k\u{9d}52;c;aGk=\u{9c}\u{202e}evil\u{7f}\x1b";
        report.issues[0].key = key.into();
        let reports = vec![report];
        let json = replay_json(&reports).unwrap();
        assert!(!json.chars().any(|c| c != '\n' && is_unsafe(c)), "{json}");
        assert!(json.contains(r#""k\u009d52;c;aGk=\u009c\u202eevil\u007f\u001b""#));
        let back: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(back, serde_json::to_value(&reports).unwrap());
        assert_eq!(back[0]["issues"][0]["key"], key);
    }

    /// The engine's clock starts at the first frame's time, and a file can
    /// carry anything there.
    #[test]
    fn replay_survives_an_unparsable_first_timestamp() {
        let mut ep = incident().finished.remove(0);
        ep.frames[0].ts = "\x1b]52;c;aGk=\x07".into();
        let report = replay(&ep);
        assert_eq!(report.frames, ep.frames.len());
    }

    /// Replay turns a frame's time and its probe ages into instants, and a
    /// file can carry any number in either. Seconds past what a `Duration`
    /// holds, or past what an `Instant` can add, panicked.
    #[test]
    fn replay_survives_times_no_instant_can_hold() {
        let mut ep = incident().finished.remove(0);
        // Past `Duration`, then past `Instant` but not `Duration`.
        ep.frames[1].at = 1e20;
        ep.frames[2].at = 1e19;
        ep.frames[0].ages.interface = Some(1e20);
        ep.frames[3].ages.egress = Some(-1e20);
        let report = replay(&ep);
        assert_eq!(report.frames, ep.frames.len());
        let times = ep.frames[0].ages.to_times(Instant::now(), 0.0);
        assert_eq!(times.interface, None);
    }

    /// Just over a megabyte of gzip that inflates to 1 GiB of zeros, close to
    /// the most deflate can pack.
    fn gzip_bomb() -> Vec<u8> {
        const SEGMENT: usize = 1 << 20;
        let zeros = vec![0u8; SEGMENT];
        // A full flush ends the deflate block on a byte boundary, so the
        // same bytes can follow themselves; every distance back still lands
        // on a zero.
        let mut deflate = flate2::Compress::new(flate2::Compression::best(), false);
        let mut block = Vec::with_capacity(SEGMENT);
        deflate
            .compress_vec(&zeros, &mut block, flate2::FlushCompress::Full)
            .unwrap();
        assert_eq!(deflate.total_in(), SEGMENT as u64);
        let mut segment = flate2::Crc::new();
        segment.update(&zeros);
        let mut whole = flate2::Crc::new();
        let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
        for _ in 0..1024 {
            gz.extend_from_slice(&block);
            whole.combine(&segment);
        }
        // An empty final block, then the trailer a whole file would have.
        gz.extend_from_slice(&[0x03, 0x00]);
        gz.extend_from_slice(&whole.sum().to_le_bytes());
        gz.extend_from_slice(&whole.amount().to_le_bytes());
        gz
    }

    /// Before the cap, this held the whole gigabyte in memory and then
    /// failed to parse it.
    #[test]
    fn load_rejects_oversized_gzip() {
        let bomb = gzip_bomb();
        assert!(bomb.len() * 1000 < 1 << 30, "{} bytes", bomb.len());
        let dir = std::env::temp_dir().join(format!("nw-bomb-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bomb.json.gz");
        std::fs::write(&path, bomb).unwrap();
        let err = load(&path).unwrap_err().to_string();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            err.contains(&format!("more than {} MiB", MAX_LOAD_BYTES >> 20)),
            "{err}"
        );
    }

    /// serde quotes a variant it does not know as written, escapes and all,
    /// and `diagnose episodes` prints the error.
    #[test]
    fn a_load_error_does_not_quote_escapes() {
        let dir = std::env::temp_dir().join(format!("nw-bad-ep-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.json");
        std::fs::write(
            &path,
            r#"{"schema_version":1,"id":"x","source":{"kind":"\u001b]52;c;aGk=\u0007"}}"#,
        )
        .unwrap();
        let err = load(&path).unwrap_err().to_string();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(err.contains("unknown variant"), "{err}");
        assert!(!err.chars().any(crate::ui::sanitize::is_unsafe), "{err:?}");
    }

    /// A gzip of `frames` frames with every field empty, in an episode that
    /// is otherwise real.
    fn empty_frames(frames: usize) -> Vec<u8> {
        let mut ep = incident().finished.remove(0);
        ep.frames.clear();
        let empty = r#"{"at":0,"ts":"","obs":{},"ages":{}}"#;
        let json = serde_json::to_string(&ep).unwrap().replacen(
            r#""frames":[]"#,
            &format!(r#""frames":[{}]"#, vec![empty; frames].join(",")),
            1,
        );
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        gz.write_all(json.as_bytes()).unwrap();
        gz.finish().unwrap()
    }

    /// A few kilobytes of gzip, nowhere near the byte limit. Before the frame
    /// limit, a million of these frames took 2.6 GB.
    #[test]
    fn load_rejects_more_frames_than_a_recording_holds() {
        let dir = std::env::temp_dir().join(format!("nw-frames-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("frames.json.gz");
        std::fs::write(&path, empty_frames(MAX_LOAD_FRAMES)).unwrap();
        let most = load(&path).map(|ep| ep.frames.len());
        let gz = empty_frames(MAX_LOAD_FRAMES + 1);
        assert!(gz.len() < 64 << 10, "{} bytes", gz.len());
        std::fs::write(&path, gz).unwrap();
        let over = load(&path).map(|ep| ep.frames.len());
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(most.unwrap(), MAX_LOAD_FRAMES);
        let err = over.unwrap_err().to_string();
        assert!(
            err.contains(&format!("more than {MAX_LOAD_FRAMES} frames")),
            "{err}"
        );
    }

    #[test]
    fn read_capped_takes_up_to_the_cap_and_no_more() {
        let text = b"0123456789";
        assert_eq!(read_capped(&text[..], 10).unwrap(), text);
        assert!(read_capped(&text[..], 9).is_err());
    }

    #[test]
    fn a_simulated_day_of_quiet_time_and_incidents_stays_under_five_megabytes() {
        let mut session = Session::new();
        session.recorder.schedule_quiet_sample(T0 + 60.0);
        session.run(healthy, 6.0 * 3600.0, 5.0);
        for _ in 0..3 {
            session.run(|_| 80.0, 600.0, 5.0);
            session.run(healthy, 5.0 * 3600.0 + 600.0, 5.0);
        }
        session.run(healthy, 2.0 * 3600.0, 5.0);
        assert_eq!(session.at - T0, 86400.0);
        let dir = std::env::temp_dir().join(format!("nw-day-{}", uuid::Uuid::new_v4()));
        let mut bytes = 0;
        assert!(session.finished.len() >= 4);
        for ep in &session.finished {
            let path = save(&dir, ep).unwrap();
            bytes += std::fs::metadata(path).unwrap().len();
            assert!(replay(ep).matches());
        }
        std::fs::remove_dir_all(dir).unwrap();
        assert!(
            bytes < 5 * 1024 * 1024,
            "day of recordings used {bytes} bytes"
        );
    }

    #[test]
    fn a_quiet_sample_is_recorded_when_due() {
        let mut s = Session::new();
        s.recorder.schedule_quiet_sample(T0 + 60.0);
        s.run(healthy, QUIET_SAMPLE_SECS + 120.0, 5.0);
        assert_eq!(s.finished.len(), 1);
        let ep = &s.finished[0];
        assert_eq!(ep.source, EpisodeSource::QuietSample);
        assert!(ep.issue_keys().is_empty());
        assert!(ep.duration_secs() >= QUIET_SAMPLE_SECS - 5.0);
        assert!(replay(ep).matches());
    }

    #[test]
    fn an_incident_during_a_quiet_sample_becomes_a_live_episode() {
        let mut s = Session::new();
        s.run(healthy, 900.0, 5.0);
        s.recorder.schedule_quiet_sample(s.at);
        s.run(healthy, 300.0, 5.0);
        s.run(|_| 80.0, 300.0, 5.0);
        s.run(healthy, 1_800.0, 5.0);
        assert_eq!(s.finished.len(), 1);
        let ep = &s.finished[0];
        assert_eq!(ep.source, EpisodeSource::Live);
        assert!(ep.frames[0].baselines.is_some());
        assert!(
            replay(ep).matches(),
            "{:#?}",
            replay(ep).divergences.first()
        );
    }

    #[test]
    fn a_long_incident_is_split_and_linked() {
        let mut s = Session::new();
        s.run(healthy, 900.0, 30.0);
        s.run(|_| 80.0, MAX_EPISODE_SECS + 600.0, 30.0);
        s.run(healthy, 1_800.0, 30.0);
        assert_eq!(s.finished.len(), 2);
        assert_eq!(
            s.finished[1].continues.as_deref(),
            Some(s.finished[0].id.as_str())
        );
        assert!(s.finished[1].frames[0].baselines.is_some());
    }

    #[test]
    fn many_sockets_are_trimmed_to_the_interesting_ones() {
        let t = crate::diagnose::detectors::Thresholds::default();
        let engine = Engine::new(Box::new(crate::diagnose::engine::SystemClock));
        let mut obs = Observations::default();
        for i in 0..100u32 {
            obs.sockets.push(crate::diagnose::detectors::SocketObs {
                local: format!("10.0.0.2:{}", 40_000 + i),
                remote: "1.1.1.1:443".into(),
                process: None,
                rtt_ms: Some(20.0),
                rttvar_ms: Some(1.0),
                retrans: Some(i % 4),
                cwnd: Some(10),
                ssthresh: None,
                rwnd: Some(65_535),
                mss: Some(1460),
                tx_bps: 0.0,
                rx_bps: 0.0,
                verdict_age_secs: 0,
            });
        }
        obs.sockets[50].retrans = Some(3);
        obs.sockets[50].tx_bps = 1_000.0;
        obs.sockets[3].rwnd = Some(0);
        let zero_window = obs.sockets[3].clone();
        assert_ne!(classify_socket(&zero_window, &t), SocketVerdict::Ok);
        trim_sockets(&mut obs, &t, &engine);
        assert!(obs.sockets.len() <= TOP_SOCKETS + 1);
        assert!(obs.sockets.contains(&zero_window));
        assert!(obs
            .sockets
            .iter()
            .all(|s| s.retrans == Some(3) || s.rwnd == Some(0)));
    }

    /// The engine still closes or expires a muted issue on what its socket
    /// does, so replay needs that socket even once it has gone quiet.
    #[test]
    fn a_muted_socket_issue_keeps_its_socket_in_the_recording() {
        let t = crate::diagnose::detectors::Thresholds::default();
        let socket = |port: u32, retrans: u32| crate::diagnose::detectors::SocketObs {
            local: format!("10.0.0.2:{port}"),
            remote: "10.0.0.3:9000".into(),
            process: None,
            rtt_ms: Some(20.0),
            rttvar_ms: Some(2.0),
            retrans: Some(retrans),
            cwnd: Some(10),
            ssthresh: Some(u32::MAX),
            rwnd: Some(64_000),
            mss: Some(1448),
            tx_bps: 2.4e6,
            rx_bps: 0.0,
            verdict_age_secs: 90,
        };
        let mut settings = crate::diagnose::engine::Settings::default();
        settings.thresholds.consecutive_n = 1;
        let mut engine =
            Engine::new(Box::new(crate::diagnose::engine::SystemClock)).with_settings(settings);
        let base = BaselineStore::new(NetworkFingerprint::new("eth0", None, vec![], None));
        let open = Observations {
            sockets: vec![socket(40_000, 12)],
            ..Default::default()
        };
        engine.observe(&open, &base);
        let id = engine
            .issues()
            .iter()
            .find(|i| i.rule == "tcp.retrans_burst")
            .expect("the socket opens an issue")
            .id
            .clone();
        assert!(engine.mute(&id, 60));

        // It has stopped retransmitting, among a hundred busier sockets.
        let quiet = socket(40_000, 0);
        let mut obs = Observations::default();
        obs.sockets.push(quiet.clone());
        for i in 1..100u32 {
            obs.sockets.push(socket(40_000 + i, 1 + i % 3));
        }
        assert_eq!(classify_socket(&quiet, &t), SocketVerdict::Ok);
        trim_sockets(&mut obs, &t, &engine);
        assert!(obs.sockets.contains(&quiet));
    }

    #[test]
    fn pruning_removes_the_oldest_beyond_the_size_cap() {
        let dir = std::env::temp_dir().join(format!("nw-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("2026-09")).unwrap();
        for n in 0..3 {
            std::fs::write(
                dir.join("2026-09").join(format!("{n}.json.gz")),
                vec![0u8; 1000],
            )
            .unwrap();
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(prune(&dir, Duration::from_secs(3_600), 2_500), 1);
        let left: Vec<String> = list(&dir)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec!["1.json.gz", "2.json.gz"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
