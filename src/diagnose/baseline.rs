//! Per-metric, per-subject baselines: EWMA mean and standard deviation,
//! learned over a minimum window and persisted across runs.
//!
//! ## Why baselines are scoped to a network
//!
//! A baseline is only meaningful on the network it was learned on. Carry a
//! laptop from a 1.2ms office resolver to a hotel hotspot and every
//! baseline-derived rule fires at once — dns, gateway rtt, path, throughput —
//! producing a screen full of red that describes nothing but the fact that the
//! user moved. A persisted `baselines.json` makes that worse, because the
//! wrong baselines survive the reboot too.
//!
//! So every sample is recorded under a [`NetworkFingerprint`] (interface,
//! gateway, resolver set, local subnet). Changing networks doesn't discard
//! anything — the old fingerprint's baselines stay on disk and come back when
//! the user returns to that network — but rules only ever see baselines
//! learned on the network that is currently up, and a freshly-seen network
//! starts in `Learning` where no baseline rule can fire.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

/// EWMA time constant. Smoothing is defined in seconds, not samples: probes
/// arrive once per `HEALTH_PROBE_TICKS` refresh ticks and the refresh rate is
/// user-configurable (100ms–5s), so a per-sample factor gave a half-life
/// anywhere from ~90s to ~15min. Thirty minutes (half-life ≈ 21min) tracks a
/// congested evening without absorbing an incident while it is happening.
pub const DEFAULT_TAU_SECS: f64 = 1_800.0;

/// Observed time required before a metric's baseline may be used by a rule.
pub const DEFAULT_MIN_OBSERVED_SECS: f64 = 1_800.0;

/// Samples also required, so thirty minutes of one sample every 60s (a
/// sleeping laptop, a stalled prober) can't produce a "ready" baseline.
pub const DEFAULT_MIN_SAMPLES: u32 = 60;

/// Longest gap credited to one update. A laptop waking after a night asleep
/// must not let its first sample replace the baseline, nor count the night
/// as observation time.
pub const MAX_STEP_SECS: f64 = 60.0;

/// Far over what baselines reach: a host's is a few KiB per network.
const MAX_PERSISTED_BYTES: u64 = 16 * 1024 * 1024;

/// Step assumed when a baseline has no previous timestamp (first update after
/// migrating a v1 file). Matches the default probe cadence.
pub const NOMINAL_STEP_SECS: f64 = 5.0;

/// A reading this many σ above a ready baseline is not learned. Matches the
/// detectors' default `sigma_k`, so any sample that can open an issue is one
/// the baseline refuses to normalise. A σ issue stays open down to
/// `sigma_close_k`, and a reading between the two is learned: an issue that
/// settles there is slowly absorbed and then closes.
pub const DEFAULT_GATE_SIGMA: f64 = 3.0;

/// How long a baseline may refuse readings before it concedes the network has
/// changed underneath it (a new ISP with the same gateway) and resumes
/// learning, clamped to the gate so the move is gradual.
pub const MAX_HOLD_SECS: f64 = 6.0 * 3_600.0;

/// Smallest σ, in ms, a baseline is scored against. Every baselined metric is
/// a latency in ms.
pub const DEFAULT_SIGMA_FLOOR_MS: f64 = 0.5;

/// Smallest σ as a percentage of the baseline's mean.
pub const DEFAULT_SIGMA_FLOOR_PCT: f64 = 5.0;

/// Seconds credited per sample when migrating a v1 file, which counted
/// samples only. One probe every 5 ticks at the default 1s refresh.
const V1_SECS_PER_SAMPLE: f64 = 5.0;

const PERSISTED_VERSION: u32 = 2;

/// Identity of the network a baseline was learned on. Two runs on the same
/// network produce the same fingerprint; changing any component produces a
/// different one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkFingerprint {
    pub iface: String,
    pub gateway: Option<String>,
    /// Sorted so resolver order can't change the fingerprint.
    pub resolvers: Vec<String>,
    /// Local network in CIDR-ish form, e.g. "192.168.8.0/24".
    pub subnet: Option<String>,
    /// VPN or tunnel interfaces that were up, sorted. Bringing a tunnel up
    /// changes which routes and resolvers apply, so a baseline learned
    /// without it describes a different network — and an issue opened before
    /// it cannot be verified after it.
    ///
    /// Absent in baselines written before this field existed, which keeps
    /// their keys stable for hosts that have never had a tunnel up.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vpn: Vec<String>,
}

impl NetworkFingerprint {
    pub fn new(
        iface: impl Into<String>,
        gateway: Option<String>,
        mut resolvers: Vec<String>,
        subnet: Option<String>,
    ) -> Self {
        resolvers.sort();
        resolvers.dedup();
        Self {
            iface: iface.into(),
            gateway,
            resolvers,
            subnet,
            vpn: vec![],
        }
    }

    /// Record the tunnels that were up when this network was seen.
    pub fn with_vpn(mut self, mut vpn: Vec<String>) -> Self {
        vpn.sort();
        vpn.dedup();
        self.vpn = vpn;
        self
    }

    /// Stable key for the on-disk map. Human-readable on purpose: someone
    /// opening `baselines.json` should be able to tell which network is which.
    pub fn key(&self) -> String {
        let base = format!(
            "{}|{}|{}|{}",
            self.iface,
            self.gateway.as_deref().unwrap_or("-"),
            if self.resolvers.is_empty() {
                "-".to_string()
            } else {
                self.resolvers.join(",")
            },
            self.subnet.as_deref().unwrap_or("-")
        );
        // Appended only when a tunnel is up, so keys already on disk for
        // ordinary networks keep matching and their baselines survive.
        if self.vpn.is_empty() {
            base
        } else {
            format!("{base}|vpn:{}", self.vpn.join(","))
        }
    }

    /// Short label for the UI, e.g. `eth0 via 192.168.8.1`.
    pub fn label(&self) -> String {
        let mut s = match &self.gateway {
            Some(gw) => format!("{} via {}", self.iface, gw),
            None => self.iface.clone(),
        };
        if !self.vpn.is_empty() {
            s.push_str(&format!(" + {}", self.vpn.join(", ")));
        }
        s
    }
}

/// The smallest σ a baseline is judged against: the larger of `ms` and `pct`
/// percent of the mean.
///
/// ## Why σ has a floor
///
/// A resolver that answers from cache in 1.2ms, give or take 0.05ms, learns
/// a σ of 0.05ms, and a 1.35ms answer then scores 3σ. Nobody can feel that
/// difference, but the rule fires, and the learning gate refuses the reading
/// as an outlier. The floor makes a σ score mean a move a person could
/// notice: that baseline is judged against 0.5ms, so 3σ is 2.7ms.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SigmaFloor {
    pub ms: f64,
    pub pct: f64,
}

impl Default for SigmaFloor {
    fn default() -> Self {
        Self {
            ms: DEFAULT_SIGMA_FLOOR_MS,
            pct: DEFAULT_SIGMA_FLOOR_PCT,
        }
    }
}

/// One metric's learned distribution on one subject.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    pub mean: f64,
    /// EWMA of squared deviation. `sigma()` is its square root.
    pub variance: f64,
    pub samples: u32,
    /// Highest value ever accepted into the baseline, for context in reports.
    pub max_seen: f64,
    /// Observation time credited so far, gaps capped at [`MAX_STEP_SECS`].
    #[serde(default)]
    pub observed_secs: f64,
    /// Unix time of the last reading, learned or gated.
    #[serde(default)]
    pub last_at: Option<f64>,
    /// Consecutive time readings have been gated out. Reset by any reading
    /// the gate accepts.
    #[serde(default)]
    pub held_secs: f64,
}

/// What [`BaselineStore::observe`] did with a reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Learned {
    Accepted,
    /// Above the gate on a ready baseline; not learned.
    Gated,
    /// Gated for longer than [`MAX_HOLD_SECS`]; learned, clamped to the gate.
    Clamped,
    /// NaN or infinite.
    Rejected,
}

impl Baseline {
    fn new(first: f64, at: f64) -> Self {
        Self {
            mean: first,
            variance: 0.0,
            samples: 1,
            max_seen: first,
            observed_secs: 0.0,
            last_at: Some(at),
            held_secs: 0.0,
        }
    }

    /// The σ this baseline learned, with no floor. Only the Packets overlay
    /// shows it; every judgement uses [`Self::sigma_floored`].
    pub fn sigma(&self) -> f64 {
        self.variance.max(0.0).sqrt()
    }

    /// σ raised to `floor`: `max(σ, floor.ms, floor.pct% of |mean|)`.
    pub fn sigma_floored(&self, floor: SigmaFloor) -> f64 {
        self.sigma()
            .max(floor.ms)
            .max(floor.pct / 100.0 * self.mean.abs())
    }

    /// How many floored σ above the mean `value` sits. `None` only when the
    /// floored σ is zero, which takes a floor configured to zero — a metric
    /// that has never varied cannot be scored in σ, and dividing by zero
    /// would make every sample infinitely anomalous.
    pub fn sigma_above(&self, value: f64, floor: SigmaFloor) -> Option<f64> {
        let s = self.sigma_floored(floor);
        if s <= f64::EPSILON {
            None
        } else {
            Some((value - self.mean) / s)
        }
    }

    /// Seconds since the previous reading, capped, and advance the clock.
    fn step(&mut self, at: f64) -> f64 {
        let dt = match self.last_at {
            Some(last) => (at - last).clamp(0.0, MAX_STEP_SECS),
            None => NOMINAL_STEP_SECS,
        };
        if self.last_at.is_none_or(|last| at > last) {
            self.last_at = Some(at);
        }
        dt
    }

    fn update(&mut self, value: f64, dt: f64, tau_secs: f64) {
        let alpha = 1.0 - (-dt / tau_secs).exp();
        self.observed_secs += dt;
        let delta = value - self.mean;
        self.mean += alpha * delta;
        // EWMA variance (West's incremental form): tracks the same window as
        // the mean, so σ widens during genuinely noisy periods instead of
        // staying pinned to whatever the first minute looked like.
        self.variance = (1.0 - alpha) * (self.variance + alpha * delta * delta);
        self.samples = self.samples.saturating_add(1);
        if value > self.max_seen {
            self.max_seen = value;
        }
    }
}

/// Whether a metric's baseline is usable yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Never seen on this network.
    Unknown,
    /// Seen, but not for long enough. Rules must not fire.
    Learning {
        observed_secs: u64,
        need_secs: u64,
    },
    Ready,
}

impl Readiness {
    pub fn is_ready(self) -> bool {
        matches!(self, Readiness::Ready)
    }

    /// `"learning 7m/30m"` — what the Diagnose header shows so a user is
    /// never left wondering why nothing has fired yet.
    pub fn label(self) -> String {
        match self {
            Readiness::Unknown => "no baseline".to_string(),
            Readiness::Learning {
                observed_secs,
                need_secs,
            } => format!(
                "learning {}/{}",
                minutes_label(observed_secs),
                minutes_label(need_secs)
            ),
            Readiness::Ready => "ready".to_string(),
        }
    }
}

fn minutes_label(secs: u64) -> String {
    format!("{}m", secs / 60)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct NetworkBaselines {
    /// Serialised as `"subject\u{1f}metric"` because JSON object keys are
    /// strings; the unit separator can't occur in an address or metric name.
    #[serde(default)]
    metrics: HashMap<String, Baseline>,
    /// Human-readable record of which network this block belongs to.
    #[serde(default)]
    label: String,
}

fn encode(subject: &str, metric: &str) -> String {
    format!("{subject}\u{1f}{metric}")
}

/// The baseline store. Holds every network the host has learned, but only
/// serves reads for the one that is currently up.
#[derive(Debug, Clone)]
pub struct BaselineStore {
    networks: HashMap<String, NetworkBaselines>,
    current: NetworkFingerprint,
    tau_secs: f64,
    min_observed_secs: f64,
    min_samples: u32,
    gate_sigma: f64,
    /// The floor under σ for the gate and its clamp, kept in step with the
    /// detectors' by [`Self::set_gate`].
    sigma_floor: SigmaFloor,
    /// Set when `current` changed since load — the UI says so, and rules stay
    /// quiet until the new network's baselines are ready.
    switched: bool,
    dirty: bool,
}

impl BaselineStore {
    pub fn new(current: NetworkFingerprint) -> Self {
        Self {
            networks: HashMap::new(),
            current,
            tau_secs: DEFAULT_TAU_SECS,
            min_observed_secs: DEFAULT_MIN_OBSERVED_SECS,
            min_samples: DEFAULT_MIN_SAMPLES,
            gate_sigma: DEFAULT_GATE_SIGMA,
            sigma_floor: SigmaFloor::default(),
            switched: false,
            dirty: false,
        }
    }

    pub fn with_min_samples(mut self, min_samples: u32) -> Self {
        self.min_samples = min_samples;
        self
    }

    pub fn with_min_observed_secs(mut self, secs: f64) -> Self {
        self.min_observed_secs = secs;
        self
    }

    pub fn with_tau_secs(mut self, tau_secs: f64) -> Self {
        self.tau_secs = tau_secs;
        self
    }

    /// Keep the learning gate in step with the detectors' `sigma_k` and σ
    /// floor, which a user can change in settings.
    pub fn set_gate(&mut self, sigma: f64, floor: SigmaFloor) {
        self.gate_sigma = sigma;
        self.sigma_floor = floor;
    }

    pub fn fingerprint(&self) -> &NetworkFingerprint {
        &self.current
    }

    /// True when the live network differs from the one the last samples were
    /// recorded on. The Diagnose header shows this; it's the difference
    /// between "nothing is wrong" and "I have nothing to compare against".
    pub fn switched_network(&self) -> bool {
        self.switched
    }

    /// Point the store at a different network. Existing baselines are kept —
    /// walking back to the office restores the office baselines — but reads
    /// now resolve against the new fingerprint, so no rule can compare a
    /// hotspot's latency to an office baseline.
    pub fn set_network(&mut self, fp: NetworkFingerprint) {
        if fp == self.current {
            return;
        }
        self.current = fp;
        self.switched = true;
        self.dirty = true;
    }

    fn is_ready(&self, b: &Baseline) -> bool {
        b.samples >= self.min_samples && b.observed_secs >= self.min_observed_secs
    }

    /// Record a reading taken at `at` (unix seconds) for the current network.
    ///
    /// ## Why a ready baseline refuses outliers
    ///
    /// An incident is exactly the period a baseline must not learn from. With
    /// plain EWMA a sustained slowdown pulls the mean up until the detector
    /// stops firing, and the issue auto-closes while the user is still
    /// suffering it. So once a baseline is ready, a reading at or above
    /// `gate_sigma` floored σ is not learned. If that lasts longer than
    /// [`MAX_HOLD_SECS`] the network has most likely changed for good, and
    /// readings are learned again but clamped to the gate, so the baseline
    /// walks toward the new level instead of jumping to it.
    pub fn observe(&mut self, subject: &str, metric: &str, value: f64, at: f64) -> Learned {
        if !value.is_finite() || !at.is_finite() {
            return Learned::Rejected;
        }
        let key = self.current.key();
        let label = self.current.label();
        let net = self
            .networks
            .entry(key)
            .or_insert_with(|| NetworkBaselines {
                metrics: HashMap::new(),
                label,
            });
        self.dirty = true;
        let (tau, gate, floor, min_samples, min_secs) = (
            self.tau_secs,
            self.gate_sigma,
            self.sigma_floor,
            self.min_samples,
            self.min_observed_secs,
        );
        let Some(b) = net.metrics.get_mut(&encode(subject, metric)) else {
            net.metrics
                .insert(encode(subject, metric), Baseline::new(value, at));
            return Learned::Accepted;
        };

        let dt = b.step(at);
        let ready = b.samples >= min_samples && b.observed_secs >= min_secs;
        let over_gate = ready && b.sigma_above(value, floor).is_some_and(|s| s >= gate);
        if !over_gate {
            b.held_secs = 0.0;
            b.update(value, dt, tau);
            return Learned::Accepted;
        }
        b.held_secs += dt;
        if b.held_secs <= MAX_HOLD_SECS {
            return Learned::Gated;
        }
        let ceiling = b.mean + gate * b.sigma_floored(floor);
        b.update(value.min(ceiling), dt, tau);
        Learned::Clamped
    }

    /// Baseline for a metric, **only if it is usable**. Returns `None` while
    /// learning, so a caller cannot accidentally compare against a two-sample
    /// mean. Use [`Self::readiness`] to tell "not ready" from "no such metric".
    pub fn get(&self, subject: &str, metric: &str) -> Option<&Baseline> {
        let b = self
            .networks
            .get(&self.current.key())?
            .metrics
            .get(&encode(subject, metric))?;
        self.is_ready(b).then_some(b)
    }

    pub fn readiness(&self, subject: &str, metric: &str) -> Readiness {
        match self
            .networks
            .get(&self.current.key())
            .and_then(|n| n.metrics.get(&encode(subject, metric)))
        {
            None => Readiness::Unknown,
            Some(b) if self.is_ready(b) => Readiness::Ready,
            Some(b) => self.learning(b.observed_secs),
        }
    }

    fn learning(&self, observed_secs: f64) -> Readiness {
        Readiness::Learning {
            observed_secs: observed_secs.min(self.min_observed_secs) as u64,
            need_secs: self.min_observed_secs as u64,
        }
    }

    /// Least-ready metric across everything learned on this network — what the
    /// Diagnose header reports as overall baseline state.
    pub fn overall_readiness(&self) -> Readiness {
        let Some(net) = self.networks.get(&self.current.key()) else {
            return Readiness::Unknown;
        };
        let Some(least) = net
            .metrics
            .values()
            .filter(|b| !self.is_ready(b))
            .map(|b| b.observed_secs)
            .reduce(f64::min)
        else {
            return if net.metrics.is_empty() {
                Readiness::Unknown
            } else {
                Readiness::Ready
            };
        };
        self.learning(least)
    }

    /// Seed a ready-made baseline. Used by the fixture and by tests, and on a
    /// live `App` only by the lab driver (`diagnose::lab`), which refuses to
    /// run outside a temp home. `samples` is credited as observation time at
    /// the v1 cadence so seeded fixtures stay ready.
    pub fn seed(&mut self, subject: &str, metric: &str, mean: f64, sigma: f64, samples: u32) {
        let key = self.current.key();
        let label = self.current.label();
        let net = self
            .networks
            .entry(key)
            .or_insert_with(|| NetworkBaselines {
                metrics: HashMap::new(),
                label,
            });
        net.metrics.insert(
            encode(subject, metric),
            Baseline {
                mean,
                variance: sigma * sigma,
                samples,
                max_seen: mean + 3.0 * sigma,
                observed_secs: samples as f64 * V1_SECS_PER_SAMPLE,
                last_at: None,
                held_secs: 0.0,
            },
        );
        self.dirty = true;
    }

    pub fn load(path: &Path, current: NetworkFingerprint) -> Self {
        let mut store = Self::new(current);
        // No ownership check: a sudo that keeps HOME leaves this file root's, and
        // the same user's next session should not lose what was learned.
        let Ok(text) = crate::owner_only::read_saved(path, MAX_PERSISTED_BYTES) else {
            return store;
        };
        match serde_json::from_str::<Persisted>(&text) {
            Ok(mut p) => {
                if p.version < 2 {
                    // v1 counted samples, not time. Credit each at the
                    // default probe cadence so a baseline that was ready
                    // stays ready, and let its first update use a nominal step.
                    for b in p.networks.values_mut().flat_map(|n| n.metrics.values_mut()) {
                        b.observed_secs = b.samples as f64 * V1_SECS_PER_SAMPLE;
                        b.last_at = None;
                    }
                    store.dirty = true;
                }
                store.networks = p.networks;
                // A run that comes up on a different network than the one last
                // written is exactly the case this whole module exists for.
                store.switched = p
                    .last_network
                    .map(|last| last != store.current.key())
                    .unwrap_or(false);
                store
            }
            Err(_) => store,
        }
    }

    /// Atomic write: temp file then rename, so a kill mid-write can't leave a
    /// truncated `baselines.json` that reads as "no baselines" forever.
    pub fn save(&mut self, path: &Path) -> std::io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let payload = Persisted {
            version: PERSISTED_VERSION,
            last_network: Some(self.current.key()),
            networks: self.networks.clone(),
        };
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&payload)?)?;
        std::fs::rename(&tmp, path)?;
        self.dirty = false;
        Ok(())
    }

    /// Default location: alongside the rest of netwatch's cache.
    pub fn default_path() -> PathBuf {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("netwatch")
            .join("baselines.json")
    }
}

/// The current network's baselines and the store's tuning, as one value.
///
/// An episode stores one at its first frame and at every network change, so
/// replay starts from exactly the baselines the live engine judged against.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    pub network: NetworkFingerprint,
    pub switched: bool,
    pub tau_secs: f64,
    pub min_observed_secs: f64,
    pub min_samples: u32,
    pub gate_sigma: f64,
    /// Absent from episodes recorded before the floor existed, which replay
    /// with today's default.
    #[serde(default)]
    pub sigma_floor: SigmaFloor,
    /// Keyed as in `baselines.json`: `"subject\u{1f}metric"`. Ordered, so a
    /// recorded episode serializes the same way on every run.
    pub metrics: BTreeMap<String, Baseline>,
}

impl BaselineStore {
    pub fn snapshot(&self) -> BaselineSnapshot {
        BaselineSnapshot {
            network: self.current.clone(),
            switched: self.switched,
            tau_secs: self.tau_secs,
            min_observed_secs: self.min_observed_secs,
            min_samples: self.min_samples,
            gate_sigma: self.gate_sigma,
            sigma_floor: self.sigma_floor,
            metrics: self
                .networks
                .get(&self.current.key())
                .map(|n| n.metrics.clone().into_iter().collect())
                .unwrap_or_default(),
        }
    }

    /// Switch to the snapshot's network and tuning, replacing that network's
    /// baselines with the snapshot's. Other networks are untouched.
    pub fn restore(&mut self, snap: &BaselineSnapshot) {
        self.current = snap.network.clone();
        self.switched = snap.switched;
        self.tau_secs = snap.tau_secs;
        self.min_observed_secs = snap.min_observed_secs;
        self.min_samples = snap.min_samples;
        self.gate_sigma = snap.gate_sigma;
        self.sigma_floor = snap.sigma_floor;
        self.networks.insert(
            snap.network.key(),
            NetworkBaselines {
                metrics: snap.metrics.clone().into_iter().collect(),
                label: snap.network.label(),
            },
        );
    }

    pub fn from_snapshot(snap: &BaselineSnapshot) -> Self {
        let mut store = Self::new(snap.network.clone());
        store.restore(snap);
        store
    }
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    version: u32,
    #[serde(default)]
    last_network: Option<String>,
    #[serde(default)]
    networks: HashMap<String, NetworkBaselines>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn office() -> NetworkFingerprint {
        NetworkFingerprint::new(
            "eth0",
            Some("192.168.8.1".into()),
            vec!["169.254.1.1".into()],
            Some("192.168.8.0/24".into()),
        )
    }

    fn hotspot() -> NetworkFingerprint {
        NetworkFingerprint::new(
            "wlan0",
            Some("172.20.10.1".into()),
            vec!["172.20.10.1".into()],
            Some("172.20.10.0/28".into()),
        )
    }

    /// Feed `value` every `step` seconds for `secs`, starting at `from`.
    /// Returns the time after the last reading.
    fn feed(s: &mut BaselineStore, value: f64, from: f64, step: f64, secs: f64) -> f64 {
        let mut t = from;
        while t < from + secs {
            s.observe("r", "m", value, t);
            t += step;
        }
        t
    }

    /// A baseline with some natural variation around `mean`, ready to judge.
    fn ready_noisy(s: &mut BaselineStore, mean: f64, from: f64, step: f64, secs: f64) -> f64 {
        let mut t = from;
        let mut i = 0u64;
        while t < from + secs {
            let jitter = if i.is_multiple_of(2) { -0.5 } else { 0.5 };
            s.observe("r", "m", mean + jitter, t);
            t += step;
            i += 1;
        }
        t
    }

    #[test]
    fn a_tunnel_coming_up_is_a_different_network() {
        // Routes and resolvers change when a tunnel comes up, so a baseline
        // learned without it describes somewhere else.
        let plain = NetworkFingerprint::new(
            "eth0",
            Some("192.168.8.1".into()),
            vec!["192.168.8.1".into()],
            Some("192.168.8.0/24".into()),
        );
        let tunnelled = plain.clone().with_vpn(vec!["wg0".into()]);
        assert_ne!(plain.key(), tunnelled.key());
        assert!(tunnelled.label().contains("wg0"));

        // Keys for networks with no tunnel keep their old spelling, so
        // baselines already on disk still match.
        assert_eq!(plain.key(), "eth0|192.168.8.1|192.168.8.1|192.168.8.0/24");

        // Tunnel order cannot change identity.
        assert_eq!(
            plain
                .clone()
                .with_vpn(vec!["wg0".into(), "tun0".into()])
                .key(),
            plain.with_vpn(vec!["tun0".into(), "wg0".into()]).key()
        );
    }

    #[test]
    fn fingerprint_ignores_resolver_order() {
        let a =
            NetworkFingerprint::new("eth0", None, vec!["1.1.1.1".into(), "8.8.8.8".into()], None);
        let b =
            NetworkFingerprint::new("eth0", None, vec!["8.8.8.8".into(), "1.1.1.1".into()], None);
        assert_eq!(a.key(), b.key());
    }

    #[test]
    fn baseline_is_withheld_until_it_has_observed_long_enough() {
        let mut s = BaselineStore::new(office())
            .with_min_samples(10)
            .with_min_observed_secs(100.0);
        let t = feed(&mut s, 1.2, 0.0, 5.0, 50.0);
        assert!(s.get("r", "m").is_none());
        assert_eq!(
            s.readiness("r", "m"),
            Readiness::Learning {
                observed_secs: 45,
                need_secs: 100
            }
        );
        feed(&mut s, 1.2, t, 5.0, 60.0);
        assert!(s.get("r", "m").is_some());
    }

    #[test]
    fn few_samples_over_a_long_time_are_not_ready() {
        let mut s = BaselineStore::new(office())
            .with_min_samples(60)
            .with_min_observed_secs(1_800.0);
        // One reading a minute for an hour: plenty of time, too few samples.
        feed(&mut s, 1.2, 0.0, 60.0, 3_000.0);
        assert!(s.get("r", "m").is_none());
    }

    #[test]
    fn a_long_gap_is_neither_observation_time_nor_a_big_step() {
        let mut s = BaselineStore::new(office())
            .with_min_samples(5)
            .with_min_observed_secs(1_000.0);
        feed(&mut s, 10.0, 0.0, 5.0, 100.0);
        // Laptop asleep overnight, wakes on a slow network.
        s.observe("r", "m", 500.0, 100.0 + 8.0 * 3_600.0);
        let b = &s.networks[&office().key()].metrics[&encode("r", "m")];
        assert!(b.observed_secs <= 95.0 + MAX_STEP_SECS + 0.01);
        assert!(
            b.mean < 30.0,
            "one sample after a gap moved the mean to {}",
            b.mean
        );
    }

    #[test]
    fn half_life_does_not_depend_on_sample_rate() {
        // Same 20 minutes of a +10 step, sampled every 1s and every 25s.
        let mean_after = |step: f64| {
            let mut s = BaselineStore::new(office())
                .with_min_samples(u32::MAX) // never ready: no gating
                .with_tau_secs(DEFAULT_TAU_SECS);
            let t = feed(&mut s, 0.0, 0.0, step, 600.0);
            feed(&mut s, 10.0, t, step, 1_200.0);
            s.networks[&office().key()].metrics[&encode("r", "m")].mean
        };
        let fast = mean_after(1.0);
        let slow = mean_after(25.0);
        let expected = 10.0 * (1.0 - (-1_200.0 / DEFAULT_TAU_SECS).exp());
        assert!(
            (fast - expected).abs() / expected < 0.05,
            "1s: {fast} vs {expected}"
        );
        assert!(
            (fast - slow).abs() / fast < 0.10,
            "1s gave {fast}, 25s gave {slow}"
        );
    }

    #[test]
    fn a_sustained_incident_is_not_learned() {
        let mut s = BaselineStore::new(office())
            .with_min_samples(60)
            .with_min_observed_secs(1_800.0);
        let t = ready_noisy(&mut s, 10.0, 0.0, 5.0, 3_600.0);
        let before = s.get("r", "m").unwrap().clone();

        // +80ms for 25 minutes, far above 3σ of a ±0.5 metric.
        let mut at = t;
        while at < t + 1_500.0 {
            assert_eq!(s.observe("r", "m", 90.0, at), Learned::Gated);
            at += 5.0;
        }
        let after = s.get("r", "m").unwrap();
        assert_eq!(after.mean, before.mean);
        assert!(after.sigma_above(90.0, SigmaFloor::default()).unwrap() >= DEFAULT_GATE_SIGMA);
    }

    #[test]
    fn a_permanent_shift_is_eventually_learned_gradually() {
        let mut s = BaselineStore::new(office())
            .with_min_samples(60)
            .with_min_observed_secs(1_800.0);
        let t = ready_noisy(&mut s, 10.0, 0.0, 5.0, 3_600.0);
        let before = s.get("r", "m").unwrap().clone();
        let t = feed(&mut s, 40.0, t, 5.0, MAX_HOLD_SECS);
        assert_eq!(
            s.get("r", "m").unwrap().mean,
            before.mean,
            "held for six hours"
        );

        assert_eq!(s.observe("r", "m", 40.0, t), Learned::Clamped);
        let b = s.get("r", "m").unwrap();
        let ceiling =
            before.mean + DEFAULT_GATE_SIGMA * before.sigma_floored(SigmaFloor::default());
        assert!(
            b.mean > before.mean,
            "a clamped reading still moves the mean"
        );
        assert!(b.mean < ceiling, "clamped step moved mean to {}", b.mean);
    }

    #[test]
    fn improvement_is_always_learned() {
        let mut s = BaselineStore::new(office())
            .with_min_samples(60)
            .with_min_observed_secs(1_800.0);
        let t = ready_noisy(&mut s, 10.0, 0.0, 5.0, 3_600.0);
        assert_eq!(s.observe("r", "m", 1.0, t), Learned::Accepted);
    }

    #[test]
    fn moving_networks_does_not_leak_the_old_baseline() {
        let mut s = BaselineStore::new(office())
            .with_min_samples(3)
            .with_min_observed_secs(10.0);
        for i in 0..10 {
            s.observe("resolver", "dns.rtt_p50", 1.2, i as f64 * 5.0);
        }
        assert!(s.get("resolver", "dns.rtt_p50").is_some());

        s.set_network(hotspot());
        assert!(
            s.get("resolver", "dns.rtt_p50").is_none(),
            "a hotspot must not be judged against the office baseline"
        );
        assert!(s.switched_network());
        assert_eq!(s.readiness("resolver", "dns.rtt_p50"), Readiness::Unknown);
    }

    #[test]
    fn returning_to_a_known_network_restores_its_baseline() {
        let mut s = BaselineStore::new(office())
            .with_min_samples(3)
            .with_min_observed_secs(10.0);
        for i in 0..10 {
            s.observe("resolver", "dns.rtt_p50", 1.2, i as f64 * 5.0);
        }
        s.set_network(hotspot());
        for i in 10..20 {
            s.observe("resolver", "dns.rtt_p50", 45.0, i as f64 * 5.0);
        }
        s.set_network(office());
        let b = s
            .get("resolver", "dns.rtt_p50")
            .expect("office baseline back");
        assert!(
            (b.mean - 1.2).abs() < 0.01,
            "office baseline was polluted by the hotspot: {}",
            b.mean
        );
    }

    #[test]
    fn a_flat_baseline_scores_against_the_floor_not_zero() {
        // A LAN resolver answering from cache: 1.2ms, σ 0.05ms. Raw, 2.7ms
        // would be 30σ; against the 0.5ms floor it is 3σ.
        let mut s = BaselineStore::new(office());
        s.seed("r", "m", 1.2, 0.05, 2_400);
        let b = s.get("r", "m").unwrap();
        let floor = SigmaFloor::default();
        assert!((b.sigma() - 0.05).abs() < 1e-9, "raw σ is kept");
        assert_eq!(b.sigma_floored(floor), 0.5);
        assert!((b.sigma_above(2.7, floor).unwrap() - 3.0).abs() < 1e-9);

        // A metric that never varied is scored against the floor too,
        // rather than not at all.
        let mut s = BaselineStore::new(office())
            .with_min_samples(2)
            .with_min_observed_secs(10.0);
        feed(&mut s, 5.0, 0.0, 5.0, 50.0);
        let b = s.get("r", "m").unwrap();
        assert_eq!(b.sigma(), 0.0);
        assert!((b.sigma_above(6.5, floor).unwrap() - 3.0).abs() < 1e-9);
        // With both floors set to zero there is nothing to divide by.
        let none = SigmaFloor { ms: 0.0, pct: 0.0 };
        assert_eq!(b.sigma_above(500.0, none), None);
    }

    #[test]
    fn the_floor_is_five_percent_of_a_large_mean() {
        // A 40ms mobile resolver with σ 0.4ms: 5% of the mean, 2ms, is the
        // largest of the three, so 3σ is 46ms, not 41.2ms.
        let mut s = BaselineStore::new(office());
        s.seed("r", "m", 40.0, 0.4, 2_400);
        let b = s.get("r", "m").unwrap();
        let floor = SigmaFloor::default();
        assert!((b.sigma_floored(floor) - 2.0).abs() < 1e-9);
        assert!((b.sigma_above(46.0, floor).unwrap() - 3.0).abs() < 1e-9);
        // A baseline noisier than either floor keeps its own σ.
        s.seed("r", "m", 40.0, 3.0, 2_400);
        assert_eq!(s.get("r", "m").unwrap().sigma_floored(floor), 3.0);
    }

    #[test]
    fn the_gate_uses_the_floored_sigma() {
        let flat = || {
            let mut s = BaselineStore::new(office());
            s.seed("r", "m", 1.2, 0.05, 2_400);
            s
        };
        // 2.0ms is 16σ raw but 1.6σ floored: an ordinary reading, learned.
        let mut s = flat();
        assert_eq!(s.observe("r", "m", 2.0, 0.0), Learned::Accepted);
        let mut unfloored = flat();
        unfloored.set_gate(DEFAULT_GATE_SIGMA, SigmaFloor { ms: 0.0, pct: 0.0 });
        assert_eq!(unfloored.observe("r", "m", 2.0, 0.0), Learned::Gated);

        // 3.0ms is 3.6σ floored, so it is held out, and after the hold the
        // clamp is 3 floored σ, 2.7ms, not 3 raw σ, 1.35ms.
        assert_eq!(flat().observe("r", "m", 3.0, 0.0), Learned::Gated);
        let mut s = flat();
        let t = feed(&mut s, 3.0, 0.0, 5.0, MAX_HOLD_SECS);
        assert_eq!(s.get("r", "m").unwrap().mean, 1.2, "held for six hours");
        assert_eq!(s.observe("r", "m", 3.0, t), Learned::Clamped);
        let alpha = 1.0 - (-5.0 / DEFAULT_TAU_SECS).exp();
        let mean = s.get("r", "m").unwrap().mean;
        assert!(
            (mean - (1.2 + alpha * (2.7 - 1.2))).abs() < 1e-9,
            "clamped to {mean}"
        );
    }

    #[test]
    fn variance_tracks_a_noisy_metric() {
        let mut s = BaselineStore::new(office())
            .with_min_samples(u32::MAX)
            .with_tau_secs(50.0);
        for i in 0..200 {
            s.observe(
                "r",
                "m",
                if i % 2 == 0 { 8.0 } else { 12.0 },
                i as f64 * 5.0,
            );
        }
        let b = &s.networks[&office().key()].metrics[&encode("r", "m")];
        assert!((b.mean - 10.0).abs() < 1.0, "mean {}", b.mean);
        assert!(
            b.sigma() > 0.5,
            "σ should reflect the ±2 swing, got {}",
            b.sigma()
        );
        // A 12ms sample on a ±2 metric is not a 3σ event.
        assert!(b.sigma_above(12.0, SigmaFloor::default()).unwrap() < 3.0);
    }

    #[test]
    fn persists_and_reloads_per_network() {
        let dir = std::env::temp_dir().join(format!("nw-baseline-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("baselines.json");

        let mut s = BaselineStore::new(office())
            .with_min_samples(3)
            .with_min_observed_secs(10.0);
        feed(&mut s, 1.2, 0.0, 5.0, 50.0);
        s.save(&path).unwrap();

        let back = BaselineStore::load(&path, office())
            .with_min_samples(3)
            .with_min_observed_secs(10.0);
        assert!(back.get("r", "m").is_some());
        assert!(!back.switched_network());

        // Same file, different network: baselines invisible, switch flagged.
        let moved = BaselineStore::load(&path, hotspot()).with_min_samples(3);
        assert!(moved.get("r", "m").is_none());
        assert!(moved.switched_network());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_v1_file_keeps_its_readiness() {
        let dir = std::env::temp_dir().join(format!("nw-baseline-v1-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("baselines.json");
        let key = office().key();
        let mut metrics = serde_json::Map::new();
        metrics.insert(
            encode("r", "m"),
            serde_json::json!({ "mean": 1.2, "variance": 0.04, "samples": 1800, "max_seen": 3.0 }),
        );
        let mut networks = serde_json::Map::new();
        networks.insert(
            key.clone(),
            serde_json::json!({ "label": "eth0 via 192.168.8.1", "metrics": metrics }),
        );
        let v1 = serde_json::json!({ "version": 1, "last_network": key, "networks": networks });
        std::fs::write(&path, v1.to_string()).unwrap();

        let s = BaselineStore::load(&path, office());
        let b = s.get("r", "m").expect("a ready v1 baseline stays ready");
        assert_eq!(b.samples, 1_800);
        assert_eq!(b.observed_secs, 9_000.0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_snapshot_restores_the_same_judgements() {
        let mut s = BaselineStore::new(office())
            .with_min_samples(10)
            .with_min_observed_secs(100.0);
        let t = ready_noisy(&mut s, 10.0, 0.0, 5.0, 300.0);
        // A floor of 5ms makes 12ms 0.4σ, where the default makes it 4σ, so
        // a snapshot that dropped the floor would gate what this one learns.
        s.set_gate(DEFAULT_GATE_SIGMA, SigmaFloor { ms: 5.0, pct: 0.0 });
        let snap = s.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let mut back = BaselineStore::from_snapshot(&serde_json::from_str(&json).unwrap());
        assert_eq!(back.get("r", "m"), s.get("r", "m"));
        assert_eq!(s.observe("r", "m", 12.0, t), Learned::Accepted);
        assert_eq!(back.observe("r", "m", 12.0, t), Learned::Accepted);
        assert_eq!(
            back.observe("r", "m", 90.0, t),
            s.observe("r", "m", 90.0, t)
        );
    }

    #[test]
    fn a_truncated_file_degrades_to_empty_not_panic() {
        let dir = std::env::temp_dir().join(format!("nw-baseline-bad-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("baselines.json");
        std::fs::write(&path, "{\"version\": 1, \"netw").unwrap();
        let s = BaselineStore::load(&path, office());
        assert_eq!(s.overall_readiness(), Readiness::Unknown);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_snapshot_round_trips_bit_for_bit() {
        // serde_json's fast float parser reads this mean back one unit in
        // the last place low, so a replay started from a baseline the live
        // engine never had.
        let mut s = BaselineStore::new(office());
        s.seed("r", "m", 9.576_865_747_399_413, 0.27, 2_400);
        let json = serde_json::to_string(&s.snapshot()).unwrap();
        let back = BaselineStore::from_snapshot(&serde_json::from_str(&json).unwrap());
        assert!(s.get("r", "m").is_some());
        assert_eq!(back.get("r", "m"), s.get("r", "m"));
    }

    /// A confined thread can write the cache, and this read comes before the
    /// session can do anything else. Whatever is at the path, it starts afresh.
    #[cfg(unix)]
    #[test]
    fn a_fifo_or_oversize_file_of_baselines_is_not_read() {
        let dir = std::env::temp_dir().join(format!("netwatch-baselines-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let fifo = dir.join("fifo.json");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || sent.send(BaselineStore::load(&fifo, office()).networks.len()));
        assert_eq!(
            received
                .recv_timeout(std::time::Duration::from_secs(20))
                .expect("reading the baselines blocked"),
            0
        );

        // A valid store that only a read with no limit would get to the end of.
        let mut store = BaselineStore::new(office());
        store.seed("r", "m", 5.0, 1.0, 500);
        let saved = dir.join("saved.json");
        store.save(&saved).unwrap();
        let text = std::fs::read_to_string(&saved).unwrap();
        assert_eq!(BaselineStore::load(&saved, office()).networks.len(), 1);
        let padded = " ".repeat(MAX_PERSISTED_BYTES as usize) + &text;
        std::fs::write(&saved, padded).unwrap();
        assert_eq!(BaselineStore::load(&saved, office()).networks.len(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
