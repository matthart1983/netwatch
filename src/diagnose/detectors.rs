//! Detectors: live observations in, candidate issues out.
//!
//! Four sources feed one evaluator — baselines, socket verdicts, diffs, and
//! the on-demand pipeline. Each produces a [`Detection`], which is an issue
//! without the parts only the engine can know (its id, when it first opened,
//! how many times it has recurred). The engine merges detections into the
//! issue list, so a condition that persists for an hour stays *one* issue with
//! a growing window rather than 3,600 findings.
//!
//! Every threshold that isn't a physical constant comes from [`Thresholds`],
//! so a user ruleset can retune the engine without touching this file.

use serde::{Deserialize, Serialize};

use super::baseline::{
    Baseline, BaselineStore, SigmaFloor, DEFAULT_SIGMA_FLOOR_MS, DEFAULT_SIGMA_FLOOR_PCT,
};
use super::issue::{
    Action, Availability, Capability, Cause, CheckResult, Evidence, Scope, Severity, Step, Subject,
    Verify,
};
use super::rules;

/// Tunables. Defaults are the spec's: k=3σ, N=3 consecutive samples.
///
/// Read from `[diagnose_thresholds]` in config.toml, and embedded in every
/// recorded episode. A field missing from either takes its default, so a
/// field added later neither breaks a config written before it nor stops
/// an older episode from loading.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    /// σ multiple that counts as a deviation.
    pub sigma_k: f64,
    /// σ multiple an issue opened on σ must fall below before it closes.
    /// Below `sigma_k`, so a metric hovering at the open line does not open
    /// and close in turn. `dns.slow_resolver` never closes on a line lower
    /// than this many σ above the resolver's mean.
    pub sigma_close_k: f64,
    /// Smallest σ, in ms, a baseline is judged against, so a baseline that
    /// has barely varied does not score an unnoticeable move as many σ.
    pub sigma_floor_ms: f64,
    /// Smallest σ as a percentage of the baseline's mean.
    pub sigma_floor_pct: f64,
    /// How far, in ms, the gateway's rtt must rise above its baseline mean
    /// before `gateway.rtt_spike` opens, however many σ that is. The σ
    /// floor makes a σ a move someone could notice; this makes it one worth
    /// reporting: 2 to 9 ms on a wired gateway is 14σ and harms nothing.
    pub gateway_delta_floor_ms: f64,
    /// How far, in ms, a resolver's p50 must rise above its baseline mean
    /// before `dns.slow_resolver` opens on the baseline. A LAN resolver
    /// moving from 1.2 to 2.7 ms clears 3σ over the floor, and nobody waits
    /// on it.
    pub dns_delta_floor_ms: f64,
    /// And the multiple of its baseline mean the p50 must reach, so a
    /// resolver that normally takes 30 ms opens at 60, not at 35.
    pub dns_delta_multiple: f64,
    /// Consecutive violating samples before an issue opens (hysteresis).
    pub consecutive_n: u32,
    /// A socket verdict must persist this long before it becomes an issue.
    pub verdict_hold_secs: u64,
    /// Absolute DNS ceiling — a resolver this slow is a problem whatever its
    /// baseline says, which is what makes the rule work on a first run. It
    /// has to sit above what ordinary resolvers do: the previous 20 ms was
    /// inside the normal range of ISP and mobile resolvers, so every first
    /// run on such a network opened a finding with no baseline behind it.
    /// Anything the baseline can catch, the 3σ test catches once it is ready.
    /// With no baseline, an issue it opened closes under 0.8 of it.
    pub dns_ceiling_ms: f64,
    /// Socket rtt above this, with retransmits, reads as receiver-side queue.
    pub socket_rtt_ms: f64,
    /// Loaded-vs-idle rtt delta that means the uplink is bloated.
    pub loaded_rtt_delta_ms: f64,
    /// Interface utilisation counted as saturation.
    pub saturation_pct: f64,
    /// Interface *errors* per minute before the rule fires. Errors are rare
    /// and always mean something, so the floor is low.
    pub iface_error_floor: f64,
    /// Interface *drops* per minute before the rule fires. Much higher than
    /// the error floor: a wireless NIC drops multicast and management frames
    /// as a matter of course, and reporting one drop a minute as a fault
    /// trains people to ignore the tab.
    pub iface_drop_floor: f64,
    /// Share of DNS replies carrying the TC bit before truncation is a
    /// finding. Some truncation is normal for large answers over UDP.
    pub dns_tc_pct: f64,
    /// Share of cross-check cycles whose local answer disagreed with the
    /// validating reference before the resolver is suspected.
    pub dns_mismatch_pct: f64,
    /// Signal level at or below which wifi is weak.
    pub wifi_rssi_dbm: f64,
    /// 802.11 transmit retries as a share of transmitted frames.
    pub wifi_retry_pct: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            sigma_k: 3.0,
            sigma_close_k: 2.0,
            sigma_floor_ms: DEFAULT_SIGMA_FLOOR_MS,
            sigma_floor_pct: DEFAULT_SIGMA_FLOOR_PCT,
            gateway_delta_floor_ms: 10.0,
            dns_delta_floor_ms: 5.0,
            dns_delta_multiple: 2.0,
            consecutive_n: 3,
            verdict_hold_secs: 30,
            dns_ceiling_ms: 100.0,
            socket_rtt_ms: 100.0,
            loaded_rtt_delta_ms: 100.0,
            saturation_pct: 90.0,
            iface_error_floor: 1.0,
            iface_drop_floor: 60.0,
            dns_tc_pct: 10.0,
            dns_mismatch_pct: 50.0,
            wifi_rssi_dbm: -70.0,
            wifi_retry_pct: 20.0,
        }
    }
}

impl Thresholds {
    /// The floor under every baseline's σ, for scoring and for learning.
    pub fn sigma_floor(&self) -> SigmaFloor {
        SigmaFloor {
            ms: self.sigma_floor_ms,
            pct: self.sigma_floor_pct,
        }
    }

    /// These thresholds with every value that cannot mean anything put back
    /// to its default, and one warning per value put back.
    ///
    /// They come from a hand-edited file, and a typo there should cost one
    /// setting, not the tab: a σ multiple of 0 calls every sample a
    /// deviation, and a share above 100% can never be reached. NaN and
    /// infinity are refused everywhere: every comparison with NaN is false,
    /// so the rule it feeds would never fire, and every episode embeds these
    /// values, where JSON writes either as `null` and the episode no longer
    /// loads.
    pub fn validated(self) -> (Self, Vec<String>) {
        type Rule = (fn(f64) -> bool, &'static str);
        let above_zero: Rule = (
            |v| v > 0.0 && v.is_finite(),
            "must be a finite number above 0",
        );
        let at_least_zero: Rule = (
            |v| v >= 0.0 && v.is_finite(),
            "must be a finite number of 0 or more",
        );
        let share: Rule = (|v| (0.0..=100.0).contains(&v), "must be within 0..=100");
        let number: Rule = (|v| v.is_finite(), "must be a finite number");

        let mut t = self;
        let mut warnings = Vec::new();
        let mut check = |name: &str, field: fn(&mut Self) -> &mut f64, (ok, needs): Rule| {
            let value = field(&mut t);
            if !ok(*value) {
                let default = *field(&mut Self::default());
                warnings.push(format!(
                    "diagnose_thresholds.{name} = {value} {needs}, so the default {default} is used"
                ));
                *value = default;
            }
        };
        check("sigma_k", |t| &mut t.sigma_k, above_zero);
        check("sigma_close_k", |t| &mut t.sigma_close_k, above_zero);
        check("sigma_floor_ms", |t| &mut t.sigma_floor_ms, at_least_zero);
        check("sigma_floor_pct", |t| &mut t.sigma_floor_pct, share);
        check(
            "gateway_delta_floor_ms",
            |t| &mut t.gateway_delta_floor_ms,
            at_least_zero,
        );
        check(
            "dns_delta_floor_ms",
            |t| &mut t.dns_delta_floor_ms,
            at_least_zero,
        );
        check(
            "dns_delta_multiple",
            |t| &mut t.dns_delta_multiple,
            at_least_zero,
        );
        check("dns_ceiling_ms", |t| &mut t.dns_ceiling_ms, number);
        check("socket_rtt_ms", |t| &mut t.socket_rtt_ms, number);
        check(
            "loaded_rtt_delta_ms",
            |t| &mut t.loaded_rtt_delta_ms,
            number,
        );
        check("saturation_pct", |t| &mut t.saturation_pct, share);
        check("iface_error_floor", |t| &mut t.iface_error_floor, number);
        check("iface_drop_floor", |t| &mut t.iface_drop_floor, number);
        check("dns_tc_pct", |t| &mut t.dns_tc_pct, share);
        check("dns_mismatch_pct", |t| &mut t.dns_mismatch_pct, share);
        check("wifi_rssi_dbm", |t| &mut t.wifi_rssi_dbm, number);
        check("wifi_retry_pct", |t| &mut t.wifi_retry_pct, share);
        // A close line at or above the open line is no deadband. When the
        // default is not below a lowered `sigma_k` either, the fallback keeps
        // the defaults' proportion. The warning rounds it: a `sigma_k` of 2
        // leaves 1.3333333333333333.
        if t.sigma_close_k >= t.sigma_k {
            let default = Self::default();
            let (fallback, used) = if default.sigma_close_k < t.sigma_k {
                let v = default.sigma_close_k;
                (v, format!("the default {v}"))
            } else {
                let v = t.sigma_k * default.sigma_close_k / default.sigma_k;
                let shown = (v * 100.0).round() / 100.0;
                (v, format!("{shown}, two thirds of it,"))
            };
            warnings.push(format!(
                "diagnose_thresholds.sigma_close_k = {} must be below sigma_k = {}, so {used} is used",
                t.sigma_close_k, t.sigma_k
            ));
            t.sigma_close_k = fallback;
        }
        if t.consecutive_n == 0 {
            t.consecutive_n = Self::default().consecutive_n;
            warnings.push(format!(
                "diagnose_thresholds.consecutive_n = 0 must be at least 1, so the default {} is used",
                t.consecutive_n
            ));
        }
        (t, warnings)
    }
}

/// One socket's kernel state, as `tcp_info` reports it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SocketObs {
    pub local: String,
    pub remote: String,
    pub process: Option<String>,
    pub rtt_ms: Option<f64>,
    pub rttvar_ms: Option<f64>,
    /// Retransmissions observed during the preceding minute; missing is not zero.
    pub retrans: Option<u32>,
    pub cwnd: Option<u32>,
    pub ssthresh: Option<u32>,
    pub rwnd: Option<u32>,
    pub mss: Option<u32>,
    /// This socket's rates, from its connection-table row. None when no row
    /// matched it or the row has no rate yet: missing is not zero, which
    /// would read as an idle socket.
    pub tx_bps: Option<f64>,
    pub rx_bps: Option<f64>,
    /// Seconds this socket has been in its current verdict.
    pub verdict_age_secs: u64,
}

impl SocketObs {
    pub fn key(&self) -> String {
        format!("{} → {}", self.local, self.remote)
    }
}

/// Per-socket classification from `tcp_info`. Deliberately explicit about the
/// "nothing is wrong" case so a socket is never left unexplained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketVerdict {
    Ok,
    /// rtt far above the path's, with the socket's own tx driving it.
    Bufferbloat,
    /// cwnd is large but rwnd caps it — the peer isn't reading fast enough.
    ReceiverLimited,
    /// Neither window is the limit; the application isn't writing.
    AppLimited,
    /// cwnd collapsed to ssthresh territory — congestion control is working.
    Congestion,
    RetransBurst,
    ZeroWindow,
}

impl SocketVerdict {
    pub fn label(self) -> &'static str {
        match self {
            SocketVerdict::Ok => "ok",
            SocketVerdict::Bufferbloat => "bufferbloat",
            SocketVerdict::ReceiverLimited => "receiver-limited",
            SocketVerdict::AppLimited => "app-limited",
            SocketVerdict::Congestion => "congestion",
            SocketVerdict::RetransBurst => "retrans-burst",
            SocketVerdict::ZeroWindow => "zero-window",
        }
    }

    pub fn is_ok(self) -> bool {
        matches!(self, SocketVerdict::Ok)
    }
}

/// Classify a socket from its kernel state.
///
/// Order matters — a zero window explains everything downstream of it, so it
/// is tested before the queue-depth verdicts that it would otherwise mimic.
pub fn classify_socket(s: &SocketObs, t: &Thresholds) -> SocketVerdict {
    if s.rwnd == Some(0) {
        return SocketVerdict::ZeroWindow;
    }
    // Retransmits dominate: a socket losing segments is describing the path,
    // not its own queueing, and the retrans rule carries the better causes.
    // The count is measured; with no rtt only the queueing exclusion is
    // unknown, and the finding says so rather than reading the rtt as 0.
    if s.retrans.is_some_and(|n| n >= 5) && s.rtt_ms.is_none_or(|r| r < t.socket_rtt_ms) {
        return SocketVerdict::RetransBurst;
    }

    // Bufferbloat: high rtt while *this* socket is the one sending. A high rtt
    // on an idle socket is just a distant peer, and a socket with no rtt, or
    // no known rate, is not a bloated one.
    if s.rtt_ms.is_some_and(|r| r >= t.socket_rtt_ms) && s.tx_bps.is_some_and(|tx| tx > 0.0) {
        return SocketVerdict::Bufferbloat;
    }

    if let (Some(cwnd), Some(rwnd), Some(mss)) = (s.cwnd, s.rwnd, s.mss) {
        // cwnd is in segments, rwnd in bytes; compare like with like.
        let cwnd_bytes = cwnd as u64 * mss as u64;
        if rwnd > 0 && cwnd_bytes > 2 * rwnd as u64 {
            return SocketVerdict::ReceiverLimited;
        }
    }

    if let (Some(cwnd), Some(ssthresh)) = (s.cwnd, s.ssthresh) {
        if ssthresh != u32::MAX && cwnd <= ssthresh && s.retrans.is_some_and(|n| n > 0) {
            return SocketVerdict::Congestion;
        }
    }

    // Idle only when both rates were measured at zero: a socket whose rates
    // are unknown has not been seen to wait on its application.
    if s.tx_bps == Some(0.0) && s.rx_bps == Some(0.0) {
        return SocketVerdict::AppLimited;
    }

    SocketVerdict::Ok
}

/// One hop of a traced path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HopObs {
    pub number: u8,
    pub ip: Option<String>,
    pub asn: Option<String>,
    pub rtt_p50_ms: Option<f64>,
    pub rtt_p95_ms: Option<f64>,
    pub loss_pct: f64,
    /// No ICMP reply at all. A silent hop is not a 100%-loss hop — routers
    /// that decline to answer are normal, and calling that loss is the single
    /// most common way traceroute output gets misread.
    pub silent: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathObs {
    pub target: String,
    pub hops: Vec<HopObs>,
    /// The previous trace to the same target, for diffing.
    pub previous: Option<Vec<HopObs>>,
    pub traced_at: String,
    /// Whether the destination itself answered this trace. `None` when the
    /// trace cannot tell, which is the usual case for a firewalled tail and
    /// the default for recordings made before this field existed.
    ///
    /// Without it, "every hop after the lossy one is silent" cannot be told
    /// apart from "the loss reaches the destination", and blaming a hop on
    /// that basis names a router for its own ICMP policy.
    #[serde(default)]
    pub destination_reached: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IfaceObs {
    /// None in older recordings whose collector assumed a one-second cadence.
    #[serde(default)]
    pub counter_window_secs: Option<f64>,
    pub name: String,
    /// Link up. `None` when the platform gave no info for this interface,
    /// which is not the same as up. Older recordings' booleans read as
    /// `Some`.
    pub carrier: Option<bool>,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    /// Errors and drops over the last minute — a *rate*, not a lifetime
    /// counter. A NIC that logged 40 errors during boot last month is not a
    /// live fault, and a per-tick delta reported as "/min" is off by 60.
    pub errors_per_min: u64,
    /// `None` where the platform does not count drops (macOS), which is not
    /// the same as none dropped.
    pub drops_per_min: Option<u64>,
    pub link_rate_bps: Option<f64>,
    pub rx_bps: f64,
    pub tx_bps: f64,
    /// The kernel registered this as an 802.11 device. `None` when the
    /// platform did not say, which is not the same as wired.
    pub wireless: Option<bool>,
    /// Signal level, where the platform reports one.
    pub signal_dbm: Option<i32>,
    /// Transmit retries over the last minute as a share of frames sent.
    /// `None` when the radio sent too few frames for a share to mean
    /// anything, so an idle link does not read as 0%.
    pub tx_retry_pct: Option<f64>,
}

impl IfaceObs {
    /// Errors plus drops a minute, where drops are counted, and errors alone
    /// where they are not. `iface.errors` opens and verifies on this one
    /// statistic.
    pub fn error_rate(&self) -> u64 {
        self.drops_per_min
            .map_or(self.errors_per_min, |d| self.errors_per_min + d)
    }

    pub fn utilisation_pct(&self) -> Option<f64> {
        let rate = self.link_rate_bps?;
        if rate <= 0.0 {
            return None;
        }
        Some((self.rx_bps.max(self.tx_bps) / rate) * 100.0)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsObs {
    pub resolver: String,
    pub rtt_p50_ms: Option<f64>,
    pub rtt_p95_ms: Option<f64>,
    pub failure_rate_pct: f64,
    pub truncation_rate_pct: f64,
    pub queries: u32,
    pub failed: u32,
    pub truncated: u32,
    /// A second resolver probed over the same path, for discrimination.
    pub alt_resolver: Option<String>,
    pub alt_rtt_ms: Option<f64>,
    /// ICMP rtt to the resolver itself — separates "slow to answer" from
    /// "slow to reach".
    pub icmp_rtt_ms: Option<f64>,
    /// Cached names still answering fast points at the upstream forwarder.
    pub cached_rtt_ms: Option<f64>,
    pub window_secs: u64,
    /// The latest answer cross-check against a validating reference.
    pub cross: Option<DnsCross>,
}

impl DnsObs {
    /// The configured resolver is a stub on this host, such as
    /// systemd-resolved's 127.0.0.53. The probe asks root NS, which the stub
    /// answers from its cache, so what it times is the stub's round trip,
    /// not the upstream the stub forwards to.
    pub fn is_local_stub(&self) -> bool {
        self.resolver
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    }
}

/// A public name asked of the configured resolver and of a validating
/// reference, and whether they agreed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsCross {
    pub name: String,
    pub local: Vec<String>,
    pub reference_resolver: String,
    pub reference: Vec<String>,
    pub validated: bool,
    pub private_answer: bool,
    /// Share of recent cycles where the two disagreed.
    pub mismatch_pct: f64,
    pub cycles: u32,
}

/// What STUN said about the NAT in front of us.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NatObs {
    pub mappings: Vec<(String, String)>,
    pub symmetric: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayObs {
    pub addr: Option<String>,
    pub rtt_ms: Option<f64>,
    pub loss_pct: f64,
    /// Whether the gateway answered ARP. `None` when no ARP probe has run,
    /// which is currently always: netwatch sends no ARP of its own. An
    /// unmeasured probe must not be rendered as a failed one, so the checks
    /// below report it as unknown rather than asserting either way.
    #[serde(default)]
    pub arp_ok: Option<bool>,
    pub icmp_ok: bool,
    /// Whether a host beyond the gateway answered. This is the corroborating
    /// check that makes "gateway unreachable" safe to say.
    ///
    /// A failed gateway probe on its own means very little: plenty of routers
    /// drop ICMP echo and have no open TCP port, and an unprivileged netwatch
    /// cannot always send ICMP at all. But if something on the internet
    /// answered, packets are demonstrably transiting the gateway, and calling
    /// it unreachable would be flatly wrong — a `critical` that suppresses
    /// every other finding on the screen, raised against a working router.
    /// `None` when no internet probe has completed yet.
    pub internet_reachable: Option<bool>,
}

/// The configuration a sample ran with. Whether an issue's subject went
/// away or only stopped being measured depends on it: a socket that closed,
/// a target the user removed, a resolver that left the system config. It is
/// recorded with the readings so a replay decides the same way.
///
/// The resolver and interface lists are the app's last read of each, taken
/// every tenth tick in the TUI and only at start under `diagnose run`, and
/// neither carries a time of its own.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ObservedConfig {
    /// The system resolvers, in the order the platform lists them. `None`
    /// when it listed none: the collector returns the same empty list when
    /// it cannot read the resolver config, so an empty list never says a
    /// resolver left.
    pub resolvers: Option<Vec<String>>,
    /// Enabled `[[diagnose_targets]]` as (name, revision). The revision is
    /// the target's baseline key, which changes when any field of its entry
    /// does.
    pub targets: Vec<(String, String)>,
    /// `diagnose_probes.trace_target`.
    pub trace_target: String,
    /// Seconds between periodic traces; `None` while periodic tracing is
    /// off, as it always is under `diagnose run`.
    pub trace_refresh_secs: Option<u64>,
    /// Every interface the platform lists, up or down. `None` when it
    /// listed none, as after a read that failed at start.
    pub interfaces: Option<Vec<String>>,
}

/// Everything a detector pass gets to look at.
/// Serialisable so an episode can store exactly what the detectors saw and
/// replay it. `default` keeps older recordings loadable as fields are added.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Observations {
    pub active: super::active::Observation,
    pub kernel: Option<super::kernel::Observation>,
    pub egress: Option<super::egress::Observation>,
    /// Collector/configuration provenance, recorded so coverage replays faithfully.
    pub coverage_hints: std::collections::BTreeMap<String, (super::coverage::Availability, String)>,
    pub now: String,
    pub iface: Option<IfaceObs>,
    pub gateway: Option<GatewayObs>,
    pub dns: Option<DnsObs>,
    pub paths: Vec<PathObs>,
    pub sockets: Vec<SocketObs>,
    /// Loaded-vs-idle rtt from the bufferbloat test, when one has run.
    pub idle_rtt_ms: Option<f64>,
    pub loaded_rtt_ms: Option<f64>,
    /// Set when the http 204 probe came back redirected.
    pub captive_portal_url: Option<String>,
    /// The STUN mapping probe, when one has run.
    pub nat: Option<NatObs>,
    /// Configured developer targets with a fresh probe result.
    pub targets: Vec<super::targets::TargetObs>,
    /// The configuration the sample ran with. `None` means unknown: a
    /// recording made before it was recorded, or a synthetic episode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<ObservedConfig>,
}

/// A candidate issue. The engine supplies identity and history.
#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    pub rule: &'static str,
    pub severity: Severity,
    pub title: String,
    pub subject: Subject,
    pub evidence: Vec<Evidence>,
    pub scope: Scope,
    pub causes: Vec<Cause>,
    pub remediation: Vec<Step>,
    pub verify: Verify,
}

impl Detection {
    pub(super) fn new(rule: &'static str, subject: Subject) -> Self {
        let r = rules::lookup(rule).expect("detector references a catalogued rule");
        Self {
            rule,
            severity: r.severity,
            title: r.title.to_string(),
            subject,
            evidence: Vec::new(),
            scope: Scope::default(),
            causes: Vec::new(),
            remediation: Vec::new(),
            verify: rules::default_verify(rule).expect("catalogued rule has a verify"),
        }
    }

    /// Stable identity for merging across ticks: one issue per (rule,
    /// subject), and per revision for a configured target. See
    /// [`super::issue::finding_key`].
    pub fn key(&self) -> String {
        super::issue::finding_key(
            self.rule,
            &self.subject,
            self.scope.configuration.as_deref(),
        )
    }
}

/// Run every detector over one set of observations.
pub fn detect(obs: &Observations, base: &BaselineStore, t: &Thresholds) -> Vec<Detection> {
    let mut out = Vec::new();
    out.extend(super::active::detect(&obs.active));
    out.extend(super::kernel::detect(obs.kernel.as_ref()));
    out.extend(detect_link(obs, t));
    out.extend(detect_gateway(obs, base, t));
    out.extend(detect_dns(obs, base, t));
    out.extend(detect_paths(obs, base, t));
    out.extend(detect_sockets(obs, t));
    out.extend(detect_bufferbloat_local(obs, t));
    out.extend(detect_nat(obs));
    out.extend(super::egress::detect(obs.egress.as_ref()));
    out.extend(detect_targets(obs, base, t));
    let valid = |d: &Detection| ids_are_valid(d).and_then(|()| not_run_checks_say_why(d));
    debug_assert!(
        out.iter().all(|d| valid(d).is_ok()),
        "{:?}",
        out.iter()
            .filter_map(|d| valid(d).err())
            .collect::<Vec<_>>()
    );
    out
}

// ---------------------------------------------------------------- targets

fn detect_targets(obs: &Observations, base: &BaselineStore, t: &Thresholds) -> Vec<Detection> {
    obs.targets
        .iter()
        .filter_map(|target| {
            target_detection(target, obs, base, t).map(|mut d| {
                d.scope.configuration = target.baseline_key.clone();
                // Which resolver answered for this target, and the link that
                // resolver belongs to. Suppression uses both: a resolver
                // failure elsewhere, or a link failure on another interface,
                // does not explain this finding.
                if let Some(answered) = target.route_lookup() {
                    d.scope.via_resolver = Some(answered.resolver.clone());
                    d.scope.via_iface = answered.link.clone();
                }
                d
            })
        })
        .collect()
}

fn target_detection(
    target: &super::targets::TargetObs,
    obs: &Observations,
    base: &BaselineStore,
    t: &Thresholds,
) -> Option<Detection> {
    use super::targets::{LookupOutcome, StageError};
    let subject = Subject::Target {
        name: target.name.clone(),
    };
    let ctx = &target.context;
    let proxy = || {
        if ctx.proxy_env {
            CheckResult::pass(
                "proxy_configured",
                "proxy configured",
                "HTTP(S)_PROXY applies to this host",
            )
        } else {
            CheckResult::fail(
                "proxy_configured",
                "proxy configured",
                "no proxy in netwatch's environment",
            )
        }
    };
    let vpn_up = || {
        if ctx.vpn_ifaces.is_empty() {
            CheckResult::fail(
                "vpn_interface_up",
                "a vpn interface is up",
                "no tun/wg/tailscale interface",
            )
        } else {
            CheckResult::pass(
                "vpn_interface_up",
                "a vpn interface is up",
                ctx.vpn_ifaces.join(", "),
            )
        }
    };
    let stage_err = |s: Option<&super::targets::Stage>| s.and_then(|s| s.error.clone());

    let mut d;
    if let Some(error) = target.resolve.error.clone() {
        d = Detection::new("target.resolve_failed", subject);
        d.evidence
            .push(Evidence::new("target.resolve_ok", 0.0, "").with_window(0, 1));
        let answered = target
            .lookups
            .iter()
            .filter(|l| l.outcome == LookupOutcome::Answered)
            .count();
        let nx = target
            .lookups
            .iter()
            .filter(|l| l.outcome == LookupOutcome::NxDomain)
            .count();
        let failed = target
            .lookups
            .iter()
            .filter(|l| matches!(l.outcome, LookupOutcome::ServFail | LookupOutcome::NoReply))
            .count();
        let asked = target.lookups.len();
        let other_answers = if asked == 0 {
            CheckResult::not_run(
                "another_resolver_answers",
                "another resolver knows the name",
                Availability::NotMeasured,
                "no resolvers to ask directly",
            )
        } else if answered > 0 {
            CheckResult::pass(
                "another_resolver_answers",
                "another resolver knows the name",
                format!("{answered} of {asked} resolvers answered"),
            )
        } else {
            CheckResult::fail(
                "another_resolver_answers",
                "another resolver knows the name",
                format!("none of {asked} resolvers answered"),
            )
        };
        d.causes = vec![
            Cause::new(
                "vpn_split_dns_missing",
                "the name belongs to a vpn whose dns isn't being used",
                vec![vpn_up(), other_answers.clone().weighted(2.0)],
            ),
            Cause::new(
                "resolver_failing",
                "the resolver couldn't answer",
                vec![
                    if error == StageError::ResolverFailed || failed > 0 {
                        CheckResult::pass(
                            "lookup_failed_not_nxdomain",
                            "the lookup failed rather than saying no",
                            error.label(),
                        )
                    } else {
                        CheckResult::fail(
                            "lookup_failed_not_nxdomain",
                            "the lookup failed rather than saying no",
                            error.label(),
                        )
                    },
                    match obs.dns.as_ref() {
                        Some(dns) if dns.failure_rate_pct >= 5.0 => CheckResult::pass(
                            "public_names_failing_too",
                            "public names are failing too",
                            format!("{:.0}% of probe queries failed", dns.failure_rate_pct),
                        ),
                        Some(_) => CheckResult::fail(
                            "public_names_failing_too",
                            "public names are failing too",
                            "the resolver answers other names",
                        ),
                        None => CheckResult::not_run(
                            "public_names_failing_too",
                            "public names are failing too",
                            Availability::NotMeasured,
                            "no resolver probe",
                        ),
                    },
                ],
            ),
            Cause::new(
                "name_does_not_exist",
                "the name does not exist — not a network fault",
                vec![
                    if asked > 0 && nx == asked {
                        CheckResult::pass(
                            "every_resolver_says_nxdomain",
                            "every resolver says it doesn't exist",
                            format!("{nx} of {asked} said NXDOMAIN"),
                        )
                        .weighted(2.0)
                    } else if asked == 0 {
                        CheckResult::not_run(
                            "every_resolver_says_nxdomain",
                            "every resolver says it doesn't exist",
                            Availability::NotMeasured,
                            "no resolvers to ask directly",
                        )
                    } else {
                        CheckResult::fail(
                            "every_resolver_says_nxdomain",
                            "every resolver says it doesn't exist",
                            format!("{nx} of {asked} said NXDOMAIN"),
                        )
                        .weighted(2.0)
                    },
                    if ctx.vpn_ifaces.is_empty() {
                        CheckResult::pass(
                            "no_vpn_interface",
                            "no vpn that might know it",
                            "no vpn interface is up",
                        )
                    } else {
                        CheckResult::fail(
                            "no_vpn_interface",
                            "no vpn that might know it",
                            ctx.vpn_ifaces.join(", "),
                        )
                    },
                ],
            ),
        ];
        d.remediation = vec![
            Step::instruct(
                "check the name",
                "a typo or a retired hostname resolves nowhere; compare with what the service advertises",
            ),
            Step::instruct(
                "if it's a vpn name, route its domain to the vpn's resolver",
                "e.g. `resolvectl domain <vpn-iface> ~corp.internal`, or reconnect so the client sets it",
            ),
        ];
    } else if let Some(error) = stage_err(target.connect.as_ref()) {
        d = Detection::new("target.connect_failed", subject);
        d.evidence
            .push(Evidence::new("target.connect_ok", 0.0, "").with_window(0, 1));
        let timed_out = matches!(error, StageError::Timeout | StageError::Unreachable);
        let v6_only_broken = match (&target.connect_v4, &target.connect_v6) {
            (Some(v4), Some(v6)) => Some(v4.is_ok() && !v6.is_ok()),
            _ => None,
        };
        d.causes = vec![
            Cause::new(
                "service_down",
                "the service isn't listening — not a network fault",
                vec![if error == StageError::Refused {
                    CheckResult::pass(
                        "connection_refused",
                        "the host refused the port",
                        "connection refused: the host is up",
                    )
                    .weighted(2.0)
                } else {
                    CheckResult::fail(
                        "connection_refused",
                        "the host refused the port",
                        error.label(),
                    )
                    .weighted(2.0)
                }],
            ),
            Cause::new(
                "firewall_or_route",
                "a firewall or route is dropping the connection",
                vec![
                    if ctx.proxy_env {
                        CheckResult::fail(
                            "no_proxy_configured",
                            "no proxy configured",
                            "a configured proxy may be required for this destination",
                        )
                    } else {
                        CheckResult::pass(
                            "no_proxy_configured",
                            "no proxy configured",
                            "no proxy applies to this destination",
                        )
                    },
                    if timed_out {
                        CheckResult::pass(
                            "connection_timed_out",
                            "the connection timed out",
                            error.label(),
                        )
                    } else {
                        CheckResult::fail(
                            "connection_timed_out",
                            "the connection timed out",
                            error.label(),
                        )
                    },
                    match obs.gateway.as_ref().and_then(|g| g.internet_reachable) {
                        Some(true) => CheckResult::pass(
                            "internet_reachable",
                            "the internet is reachable",
                            "the internet probe answered",
                        ),
                        Some(false) => CheckResult::fail(
                            "internet_reachable",
                            "the internet is reachable",
                            "nothing beyond the gateway answers",
                        ),
                        None => CheckResult::not_run(
                            "internet_reachable",
                            "the internet is reachable",
                            Availability::NotMeasured,
                            "no internet probe",
                        ),
                    },
                    match v6_only_broken {
                        Some(true) => CheckResult::fail(
                            "other_address_family_also_fails",
                            "the other address family fails too",
                            "ipv4 connects, so the host is reachable",
                        ),
                        Some(false) => CheckResult::pass(
                            "other_address_family_also_fails",
                            "the other address family fails too",
                            "ipv4 and ipv6 both fail",
                        ),
                        None => CheckResult::not_run(
                            "other_address_family_also_fails",
                            "the other address family fails too",
                            Availability::NotApplicable,
                            "the name has only one address family",
                        ),
                    },
                ],
            ),
            Cause::new(
                "ipv6_path_broken",
                "ipv6 to this host is broken while ipv4 works",
                vec![match v6_only_broken {
                    Some(true) => CheckResult::pass(
                        "ipv6_fails_ipv4_works",
                        "ipv6 fails but ipv4 works",
                        "the v4 address connected",
                    )
                    .weighted(2.0),
                    Some(false) => CheckResult::fail(
                        "ipv6_fails_ipv4_works",
                        "ipv6 fails but ipv4 works",
                        "both families behave the same",
                    )
                    .weighted(2.0),
                    None => CheckResult::not_run(
                        "ipv6_fails_ipv4_works",
                        "ipv6 fails but ipv4 works",
                        Availability::NotApplicable,
                        "the name has only one address family",
                    ),
                }],
            ),
            Cause::new(
                "proxy_required",
                "direct connections are blocked; a proxy is required",
                vec![
                    proxy(),
                    if timed_out {
                        CheckResult::pass(
                            "connection_timed_out",
                            "the connection timed out",
                            error.label(),
                        )
                    } else {
                        CheckResult::fail(
                            "connection_timed_out",
                            "the connection timed out",
                            error.label(),
                        )
                    },
                ],
            ),
        ];
        d.remediation = vec![
            Step::instruct(
                "check the service is running",
                "a refused connection means the host answered and nothing listens on that port",
            ),
            Step::instruct(
                "try the path from outside this network",
                "a timeout that only happens here points at a firewall, VPN route or required proxy",
            ),
        ];
    } else if let Some(error) = stage_err(target.tls_stage.as_ref()) {
        d = Detection::new("target.tls_failed", subject);
        d.evidence
            .push(Evidence::new("target.tls_ok", 0.0, "").with_window(0, 1));
        let issuer_unknown = || {
            if error == StageError::CertUntrusted {
                CheckResult::pass(
                    "issuer_unknown",
                    "the certificate's issuer isn't trusted",
                    error.label(),
                )
            } else {
                CheckResult::fail(
                    "issuer_unknown",
                    "the certificate's issuer isn't trusted",
                    error.label(),
                )
            }
        };
        d.causes = vec![
            Cause::new(
                "cert_untrusted",
                "the server's certificate isn't from a trusted issuer",
                vec![
                    issuer_unknown(),
                    match ctx.proxy_env {
                        false => CheckResult::pass(
                            "no_proxy_configured",
                            "no proxy in the way",
                            "no proxy configured",
                        ),
                        true => CheckResult::fail(
                            "no_proxy_configured",
                            "no proxy in the way",
                            "a proxy is configured",
                        ),
                    },
                ],
            ),
            Cause::new(
                "clock_skew",
                "this machine's clock is wrong",
                vec![
                    if matches!(error, StageError::CertExpired | StageError::CertNotYetValid) {
                        CheckResult::pass(
                            "certificate_outside_validity",
                            "the certificate looks expired or not yet valid",
                            error.label(),
                        )
                    } else {
                        CheckResult::fail(
                            "certificate_outside_validity",
                            "the certificate looks expired or not yet valid",
                            error.label(),
                        )
                    },
                    match ctx.clock_offset_secs {
                        Some(o) if o.abs() > 300.0 => CheckResult::pass(
                            "clock_offset_large",
                            "our clock is more than 5 minutes off",
                            format!("{o:+.0}s against the local NTP service"),
                        ),
                        Some(o) => CheckResult::fail(
                            "clock_offset_large",
                            "our clock is more than 5 minutes off",
                            format!("{o:+.0}s"),
                        ),
                        // Only Linux reads the local NTP status; elsewhere
                        // the offset is a platform gap, not a missed sample.
                        None if cfg!(target_os = "linux") => CheckResult::not_run(
                            "clock_offset_large",
                            "our clock is more than 5 minutes off",
                            Availability::NotMeasured,
                            "no synchronised local NTP status available",
                        ),
                        None => CheckResult::not_run(
                            "clock_offset_large",
                            "our clock is more than 5 minutes off",
                            Availability::Unsupported,
                            "the local NTP status is read only on Linux",
                        ),
                    },
                ],
            ),
            Cause::new(
                "tls_intercepting_proxy",
                "a proxy or security product is intercepting tls",
                vec![issuer_unknown(), proxy()],
            ),
        ];
        d.remediation = vec![Step::instruct(
            "check the certificate chain and this machine's clock",
            "`openssl s_client -connect host:port -servername host` shows the issuer; `timedatectl` shows sync",
        )];
    } else if let Some(StageError::HttpStatus { status }) = stage_err(target.http_stage.as_ref()) {
        d = Detection::new("target.http_error", subject);
        d.evidence
            .push(Evidence::new("target.http_status", f64::from(status), "").with_window(0, 1));
        d.evidence
            .push(Evidence::new("target.http_ok", 0.0, "").with_window(0, 1));
        d.causes = vec![
            Cause::new(
                "service_error",
                "the service itself is failing — not a network fault",
                vec![if (500..600).contains(&status) {
                    CheckResult::pass(
                        "status_5xx",
                        "the server reports its own error",
                        format!("http {status}"),
                    )
                    .weighted(2.0)
                } else {
                    CheckResult::fail(
                        "status_5xx",
                        "the server reports its own error",
                        format!("http {status}"),
                    )
                    .weighted(2.0)
                }],
            ),
            Cause::new(
                "proxy_rejected",
                "a proxy rejected the request",
                vec![
                    if status == 407 || status == 403 {
                        CheckResult::pass(
                            "status_407_or_403",
                            "an access-denied status",
                            format!("http {status}"),
                        )
                    } else {
                        CheckResult::fail(
                            "status_407_or_403",
                            "an access-denied status",
                            format!("http {status}"),
                        )
                    },
                    proxy(),
                ],
            ),
        ];
        d.remediation = vec![Step::escalate(
            "tell whoever runs the service",
            "the network delivered the request; the answer was an error",
        )];
    } else {
        // Everything worked. Slower than usual? A plain-TCP target has no tls
        // or first-byte stage, and a plain-HTTP one no tls stage.
        let stages = [
            (
                "dns_stage_slow",
                "target.resolve_ms",
                Some(&target.resolve),
                "resolve",
                true,
            ),
            (
                "connect_stage_slow",
                "target.connect_ms",
                target.connect.as_ref(),
                "connect",
                true,
            ),
            (
                "tls_stage_slow",
                "target.tls_ms",
                target.tls_stage.as_ref(),
                "tls",
                target.tls,
            ),
            (
                "server_stage_slow",
                "target.ttfb_ms",
                target.http_stage.as_ref(),
                "first byte",
                target.http,
            ),
        ];
        let sigmas: Vec<_> = stages
            .iter()
            .map(|(cause, metric, stage, word, applies)| {
                let ms = stage.and_then(|s| s.ms);
                let b = base.get(target.baseline_subject(), metric);
                (
                    *cause,
                    *word,
                    ms,
                    b.and_then(|b| ms.and_then(|v| b.sigma_above(v, t.sigma_floor()))),
                    b.map(|b| (b.mean, b.sigma_floored(t.sigma_floor()))),
                    *applies,
                )
            })
            .collect();
        let worst = sigmas
            .iter()
            .filter_map(|s| s.3.map(|sig| (s, sig)))
            .max_by(|a, b| a.1.total_cmp(&b.1))?;
        if worst.1 < t.sigma_k {
            return None;
        }
        d = Detection::new("target.slow_stage", subject);
        // Closes below the open line, as gateway.rtt_spike does.
        d.verify.threshold = t.sigma_close_k;
        let (_, word, ms, _, baseline, _) = worst.0;
        let mut ev = Evidence::new(
            format!("target.{}_ms", word.replace(' ', "_")),
            ms.unwrap_or_default(),
            "ms",
        );
        if let Some((mean, sigma)) = baseline {
            ev = ev.with_baseline(*mean, *sigma);
        }
        d.evidence.push(ev);
        d.evidence
            .push(Evidence::new("target.worst_stage_sigma", worst.1, "σ"));
        let stage_check = |id: &'static str, cause: &str| {
            let (_, word, ms, sigma, _, applies) = sigmas
                .iter()
                .find(|s| s.0 == cause)
                .expect("every stage is listed");
            stage_result(id, word, *applies, *ms, *sigma, t.sigma_k)
        };
        d.causes = vec![
            Cause::new(
                "dns_stage_slow",
                "name resolution got slower",
                vec![stage_check("dns_stage_above_baseline", "dns_stage_slow")],
            ),
            Cause::new(
                "connect_stage_slow",
                "connecting got slower",
                vec![stage_check(
                    "connect_stage_above_baseline",
                    "connect_stage_slow",
                )],
            ),
            Cause::new(
                "tls_stage_slow",
                "the tls handshake got slower",
                vec![stage_check("tls_stage_above_baseline", "tls_stage_slow")],
            ),
            Cause::new(
                "server_stage_slow",
                "the server is slower to answer",
                vec![stage_check(
                    "server_stage_above_baseline",
                    "server_stage_slow",
                )],
            ),
        ];
        d.remediation = vec![Step::instruct(
            "compare with the service's own latency",
            "a slow first byte with fast connect and tls is the server, not the network",
        )];
    }

    // What isn't a network fault shouldn't read like one. It stays an
    // Observation here; `diagnose run --target` asks whether this target
    // works, and counts it as an Issue.
    let top = d
        .causes
        .iter()
        .filter_map(|c| c.score().map(|s| (c.id.as_str(), s)))
        .max_by(|a, b| a.1.total_cmp(&b.1));
    if let Some((id, score)) = top {
        if score >= 0.6 && ["service_down", "name_does_not_exist", "service_error"].contains(&id) {
            d.severity = Severity::Info;
            d.scope.note = Some("service, not network".into());
        }
    }
    Some(d)
}

/// One stage of a target against its baseline. Ids are literals at the call
/// site, which the catalogue scan reads. `applies` is false for a stage this
/// kind of target never has, such as tls on a plain-HTTP target.
fn stage_result(
    id: &'static str,
    word: &str,
    applies: bool,
    ms: Option<f64>,
    sigma: Option<f64>,
    k: f64,
) -> CheckResult {
    let name = format!("{word} is slower than usual");
    match sigma {
        Some(s) if s >= k => CheckResult {
            id: id.into(),
            name,
            passed: Some(true),
            why_not: None,
            detail: format!("{:.0}ms, {s:.1}σ above baseline", ms.unwrap_or_default()),
            weight: 1.0,
        },
        Some(s) => CheckResult {
            id: id.into(),
            name,
            passed: Some(false),
            why_not: None,
            detail: format!("{s:.1}σ"),
            weight: 1.0,
        },
        None => {
            let (why_not, detail) = if ms.is_some() {
                (
                    Availability::Learning,
                    "no baseline for this stage yet".to_string(),
                )
            } else if !applies {
                (
                    Availability::NotApplicable,
                    format!("this target has no {word} stage"),
                )
            } else {
                (
                    Availability::NotMeasured,
                    format!("no {word} time in this probe"),
                )
            };
            CheckResult::not_run(id, name, why_not, detail)
        }
    }
}

/// Every cause id valid, unique within its detection and catalogued under its
/// rule; every check id valid, unique within its cause and catalogued. Checked on every `detect` in debug builds, so
/// any test that reaches a detector branch also checks the ids it emits.
fn ids_are_valid(d: &Detection) -> Result<(), String> {
    let mut causes = std::collections::HashSet::new();
    for c in &d.causes {
        if !Cause::valid_id(&c.id) || !causes.insert(c.id.as_str()) {
            return Err(format!("{}: bad or duplicate cause id {:?}", d.rule, c.id));
        }
        if !super::causes::is_catalogued(d.rule, c) {
            return Err(format!(
                "{} or one of its checks is missing from causes::CAUSES",
                c.key(d.rule)
            ));
        }
        let mut checks = std::collections::HashSet::new();
        for k in &c.checks {
            if !Cause::valid_id(&k.id) || !checks.insert(k.id.as_str()) {
                return Err(format!(
                    "{}: bad or duplicate check id {:?}",
                    c.key(d.rule),
                    k.id
                ));
            }
        }
    }
    Ok(())
}

/// A check that did not run names an [`Availability`] and one that ran does
/// not. Checked beside the ids on every `detect` in debug builds, so every
/// detector test also checks the reasons its branches give. `Available` would
/// print "ready" on a check that did not run, and `Unknown` is only for
/// records made before `why_not`, so a detector may give neither.
fn not_run_checks_say_why(d: &Detection) -> Result<(), String> {
    for c in &d.causes {
        for k in &c.checks {
            if k.passed.is_none() != k.why_not.is_some()
                || matches!(
                    k.why_not,
                    Some(Availability::Available | Availability::Unknown)
                )
            {
                return Err(format!(
                    "{}/{}: passed {:?} with why_not {:?}",
                    c.key(d.rule),
                    k.id,
                    k.passed,
                    k.why_not
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- link

fn detect_link(obs: &Observations, t: &Thresholds) -> Vec<Detection> {
    let Some(iface) = &obs.iface else {
        return vec![];
    };
    let mut out = Vec::new();

    // Only a reported down. With no interface info the carrier is unknown,
    // and unknown is not down.
    if iface.carrier == Some(false) {
        let mut d = Detection::new(
            "link.down",
            Subject::Iface {
                name: iface.name.clone(),
            },
        );
        d.evidence
            .push(Evidence::new("iface.carrier", 0.0, "").with_window(1, 1));
        d.causes = vec![
            Cause::new(
                "unplugged_or_port_down",
                "cable unplugged or the port is down",
                vec![CheckResult::fail(
                    "carrier",
                    "carrier",
                    "no carrier on the interface",
                )],
            ),
            Cause::new(
                "wifi_disassociated",
                "wifi disassociated",
                vec![CheckResult::not_run(
                    "wireless",
                    "wireless",
                    Availability::NotImplemented,
                    "no wireless statistics for this interface",
                )],
            ),
        ];
        d.remediation = vec![
            Step::instruct(
                "check the cable or reassociate",
                format!("ip link show {}", iface.name),
            ),
            Step::instruct(
                "bring the interface up",
                format!("ip link set {} up", iface.name),
            ),
        ];
        out.push(d);
        // Nothing else on this interface means anything while it is down.
        return out;
    }

    // Where drops are not counted the rule stands on errors alone, and
    // neither cause can weigh one against the other.
    let errors = iface.errors_per_min;
    let drops_over_floor = iface
        .drops_per_min
        .is_some_and(|d| d as f64 >= t.iface_drop_floor);
    if errors as f64 >= t.iface_error_floor || drops_over_floor {
        let mut d = Detection::new(
            "iface.errors",
            Subject::Iface {
                name: iface.name.clone(),
            },
        );
        d.evidence.push(
            Evidence::new("iface.error_rate", iface.error_rate() as f64, "/min").with_window(60, 1),
        );
        d.causes = vec![
            Cause::new(
                "ring_buffer_small",
                "ring buffer too small for the offered rate",
                vec![match iface.drops_per_min {
                    Some(drops) if drops > errors => CheckResult::pass(
                        "drops_dominate",
                        "drops dominate",
                        format!("{drops} drops vs {errors} errors"),
                    ),
                    Some(drops) => CheckResult::fail(
                        "drops_dominate",
                        "drops dominate",
                        format!("{drops} drops vs {errors} errors"),
                    ),
                    None => CheckResult::not_run(
                        "drops_dominate",
                        "drops dominate",
                        Availability::Unsupported,
                        "interface drops are not counted on macOS",
                    ),
                }],
            ),
            Cause::new(
                "bad_cable_or_duplex",
                "bad cable or duplex mismatch",
                vec![match iface.drops_per_min {
                    Some(drops) if errors > drops => CheckResult::pass(
                        "errors_dominate",
                        "errors dominate",
                        format!("{errors} errors this window"),
                    ),
                    Some(_) => CheckResult::fail(
                        "errors_dominate",
                        "errors dominate",
                        format!("only {errors} errors this window"),
                    ),
                    None => CheckResult::not_run(
                        "errors_dominate",
                        "errors dominate",
                        Availability::Unsupported,
                        "interface drops are not counted on macOS, so errors have nothing to outweigh",
                    ),
                }],
            ),
        ];
        // Neither cause can be tested here, so they rank in the order
        // written. A ring that is too small overflows as drops, and this
        // link shows only errors, so the wire goes first.
        if iface.drops_per_min.is_none() {
            d.causes.reverse();
        }
        d.remediation = vec![
            Step::instruct(
                "grow the rx ring",
                format!("ethtool -G {} rx 4096", iface.name),
            ),
            Step::instruct("check for softirq drops", "cat /proc/net/softnet_stat"),
        ];
        out.push(d);
    }

    if iface.wireless == Some(true) {
        let weak = matches!(iface.signal_dbm, Some(s) if (s as f64) <= t.wifi_rssi_dbm);
        let retrying = matches!(iface.tx_retry_pct, Some(r) if r > t.wifi_retry_pct);
        if weak || retrying {
            let mut d = Detection::new(
                "wifi.weak_signal",
                Subject::Iface {
                    name: iface.name.clone(),
                },
            );
            if let Some(rssi) = iface.signal_dbm {
                d.evidence
                    .push(Evidence::new("wifi.rssi", rssi as f64, "dBm").with_window(1, 1));
            }
            if let Some(r) = iface.tx_retry_pct {
                d.evidence
                    .push(Evidence::new("wifi.tx_retry_pct", r, "%").with_window(60, 60));
            }
            d.causes = vec![
                Cause::new(
                    "weak_signal",
                    "too far from the access point, or something in the way",
                    vec![match iface.signal_dbm {
                        Some(s) if weak => CheckResult::pass(
                            "signal_weak",
                            "signal weak",
                            format!("{s} dBm, at or below {:.0}", t.wifi_rssi_dbm),
                        ),
                        Some(s) => CheckResult::fail(
                            "signal_weak",
                            "signal weak",
                            format!("{s} dBm is fine"),
                        ),
                        None => CheckResult::not_run(
                            "signal_weak",
                            "signal weak",
                            Availability::NotMeasured,
                            "no signal level reported",
                        ),
                    }],
                ),
                Cause::new(
                    "congested_channel",
                    "a congested channel — retries with a healthy signal",
                    vec![
                        match iface.tx_retry_pct {
                            Some(r) if retrying => CheckResult::pass(
                                "retries_high",
                                "retries high",
                                format!("{r:.0}% of frames retried"),
                            ),
                            Some(r) => CheckResult::fail(
                                "retries_high",
                                "retries high",
                                format!("{r:.0}% of frames retried"),
                            ),
                            // The sampler gives no share for a radio
                            // that sent too little to judge, as well as
                            // for one with no counter.
                            None => CheckResult::not_run(
                                "retries_high",
                                "retries high",
                                Availability::NotMeasured,
                                format!(
                                    "no retry counter, or under {} frames sent in the last minute",
                                    super::live::WIFI_MIN_FRAMES
                                ),
                            ),
                        },
                        match iface.signal_dbm {
                            Some(s) if !weak => {
                                CheckResult::pass("signal_fine", "signal fine", format!("{s} dBm"))
                            }
                            Some(s) => {
                                CheckResult::fail("signal_fine", "signal fine", format!("{s} dBm"))
                            }
                            None => CheckResult::not_run(
                                "signal_fine",
                                "signal fine",
                                Availability::NotMeasured,
                                "no signal level",
                            ),
                        },
                    ],
                ),
            ];
            d.remediation = vec![
                Step::instruct(
                    "see the link as the driver does",
                    format!("iw dev {} link", iface.name),
                ),
                Step::instruct(
                    "move nearer the access point, or onto 5 GHz",
                    "a wall or a floor costs 10–20 dB; 2.4 GHz shares three usable channels with every neighbour",
                ),
                Step::instruct(
                    "look for a quieter channel",
                    format!("iw dev {} scan | grep -E 'freq|signal'", iface.name),
                ),
            ];
            out.push(d);
        }
    }

    if let Some(util) = iface.utilisation_pct() {
        if util >= t.saturation_pct {
            let mut d = Detection::new(
                "iface.saturated",
                Subject::Iface {
                    name: iface.name.clone(),
                },
            );
            d.evidence
                .push(Evidence::new("iface.utilisation", util, "%").with_window(30, 30));
            d.causes = vec![Cause::new(
                "link_at_capacity",
                "the link is carrying as much as it can",
                vec![CheckResult::pass(
                    "utilisation",
                    "utilisation",
                    format!("{util:.0}% of link rate"),
                )],
            )];
            d.remediation = vec![Step::instruct(
                "throttle or reschedule the top talker",
                "see the Processes tab for the flows holding the link",
            )];
            out.push(d);
        }
    }

    out
}

// ------------------------------------------------------------- gateway

fn detect_gateway(obs: &Observations, base: &BaselineStore, t: &Thresholds) -> Vec<Detection> {
    let Some(gw) = &obs.gateway else {
        return vec![];
    };
    if gw.arp_ok != Some(false) && gw.icmp_ok {
        return detect_gateway_rtt(gw, base, t);
    }
    // The probe failed, but the internet answered — so the gateway is
    // forwarding and simply doesn't reply to us. Not a finding.
    if gw.internet_reachable == Some(true) {
        return vec![];
    }
    let mut d = Detection::new("gateway.unreachable", Subject::Host);
    d.evidence
        .push(Evidence::new("gateway.loss", gw.loss_pct, "%").with_window(30, 30));
    let corroboration = match gw.internet_reachable {
        Some(false) => CheckResult::pass(
            "nothing_beyond_the_gateway_answers_either",
            "nothing beyond the gateway answers either",
            "the internet probe also failed, so this is not just a quiet router",
        )
        .weighted(3.0),
        Some(true) => CheckResult::fail(
            "nothing_beyond_the_gateway_answers_either",
            "nothing beyond the gateway answers either",
            "the internet is reachable through this gateway",
        )
        .weighted(3.0),
        None => CheckResult::not_run(
            "nothing_beyond_the_gateway_answers_either",
            "nothing beyond the gateway answers either",
            Availability::NotMeasured,
            "no internet probe has completed yet",
        )
        .weighted(3.0),
    };

    d.causes = vec![
        Cause::new(
            "icmp_filtered",
            "gateway is up but not answering icmp",
            vec![
                match gw.arp_ok {
                    Some(true) => CheckResult::pass(
                        "arp_resolves",
                        "arp resolves",
                        "the gateway answered arp",
                    ),
                    Some(false) => CheckResult::fail(
                        "arp_resolves",
                        "arp resolves",
                        "no arp reply from the gateway",
                    ),
                    None => CheckResult::not_run(
                        "arp_resolves",
                        "arp resolves",
                        Availability::NotImplemented,
                        "no arp probe has run",
                    ),
                },
                CheckResult::fail(
                    "icmp_reaches_the_gateway",
                    "icmp reaches the gateway",
                    "no icmp echo reply",
                ),
                corroboration.clone(),
            ],
        ),
        Cause::new(
            "wrong_vlan_or_address_conflict",
            "wrong vlan or an address conflict",
            vec![
                match gw.arp_ok {
                    Some(false) => CheckResult::pass(
                        "arp_fails",
                        "arp fails",
                        "no arp reply — we may not be on its segment",
                    ),
                    Some(true) => {
                        CheckResult::fail("arp_fails", "arp fails", "arp resolved normally")
                    }
                    None => CheckResult::not_run(
                        "arp_fails",
                        "arp fails",
                        Availability::NotImplemented,
                        "no arp probe has run",
                    ),
                }
                .weighted(2.0),
                corroboration,
            ],
        ),
    ];
    d.remediation = vec![
        Step::instruct("renew the dhcp lease", "dhclient -r && dhclient"),
        Step::instruct("confirm the default route", "ip route show default"),
    ];
    d.scope.note = Some("everything downstream is affected".into());
    // The gateway is reached over the primary interface; naming it lets
    // suppression leave alone whatever runs over a different one.
    d.scope.via_iface = obs.iface.as_ref().map(|i| i.name.clone());
    vec![d]
}

/// A reachable gateway that has become slow to answer. Separates "the AP is
/// congested" from "the internet is slow", which is otherwise the hardest
/// distinction to make from a laptop.
fn detect_gateway_rtt(gw: &GatewayObs, base: &BaselineStore, t: &Thresholds) -> Vec<Detection> {
    let (Some(addr), Some(rtt)) = (gw.addr.clone(), gw.rtt_ms) else {
        return vec![];
    };
    let Some(b) = base.get(&addr, "gateway.rtt") else {
        // No usable baseline: there is no absolute rtt that means "slow
        // gateway" — 20ms is fine over wifi and terrible over ethernet — so
        // without a baseline this rule stays quiet rather than guessing.
        return vec![];
    };
    let Some(sigma) = b.sigma_above(rtt, t.sigma_floor()) else {
        return vec![];
    };
    // Both: many σ on a quiet wired gateway can still be a few ms nobody
    // feels, and 10 ms on a noisy wireless one can still be ordinary.
    if sigma < t.sigma_k || rtt - b.mean < t.gateway_delta_floor_ms {
        return vec![];
    }

    let mut d = Detection::new("gateway.rtt_spike", Subject::Iface { name: addr.clone() });
    d.subject = Subject::Host;
    // Closing below the open line keeps an rtt hovering at 3σ one issue.
    // The catalogue's line is the default one; this is the configured one.
    d.verify.threshold = t.sigma_close_k;
    d.evidence.push(
        Evidence::new("gateway.rtt", rtt, "ms")
            .with_baseline(b.mean, b.sigma_floored(t.sigma_floor()))
            .with_window(30, 30),
    );
    d.evidence
        .push(Evidence::new("gateway.rtt_sigma", sigma, "σ").with_window(30, 30));
    d.causes = vec![
        Cause::new(
            "local_network_congested",
            "the local network or access point is congested",
            vec![CheckResult::pass(
                "gateway_rtt_above_baseline",
                "gateway rtt above baseline",
                format!(
                    "{rtt:.1}ms against a {:.1}ms baseline ({sigma:.1}σ)",
                    b.mean
                ),
            )],
        ),
        Cause::new(
            "gateway_loaded",
            "the gateway itself is loaded",
            vec![CheckResult::not_run(
                "gateway_cpu",
                "gateway cpu",
                Availability::Unsupported,
                "netwatch cannot see inside the gateway",
            )],
        ),
    ];
    d.remediation = vec![
        Step::instruct(
            "check what is using the local link",
            "the Processes tab ranks flows by throughput",
        ),
        Step::instruct(
            "if wireless, check signal and channel",
            "a weak or contended channel shows up here first",
        ),
    ];
    vec![d]
}

// ----------------------------------------------------------------- dns

/// Why a check about the resolver's upstream did not run behind a local stub.
const UPSTREAM_UNKNOWN: &str = "the upstream behind the stub is not identified";

fn detect_dns(obs: &Observations, base: &BaselineStore, t: &Thresholds) -> Vec<Detection> {
    let Some(dns) = &obs.dns else {
        return vec![];
    };
    let mut out = Vec::new();

    if dns.failure_rate_pct > 5.0 {
        let mut d = Detection::new(
            "dns.failing",
            Subject::Resolver {
                addr: dns.resolver.clone(),
            },
        );
        d.evidence.push(
            Evidence::new("dns.failure_rate", dns.failure_rate_pct, "%")
                .with_window(dns.window_secs, dns.queries),
        );
        d.causes = vec![
            Cause::new(
                "resolver_down",
                "resolver is down",
                // `icmp_rtt_ms` is `None` when the probe has not run, which
                // on the live path is always. Reading that as "no reply" made
                // every failing resolver rank as down; a check that was never
                // made is skipped, and the next-test suggester can offer it.
                vec![match dns.icmp_rtt_ms {
                    None => CheckResult::not_run(
                        "resolver_unreachable",
                        "resolver unreachable",
                        Availability::NotImplemented,
                        "no icmp probe of the resolver has run",
                    ),
                    Some(rtt) => CheckResult::fail(
                        "resolver_unreachable",
                        "resolver unreachable",
                        format!("resolver answers icmp in {rtt:.1}ms"),
                    ),
                }],
            ),
            Cause::new(
                "udp53_filtered",
                "resolver reachable but not answering queries",
                vec![match dns.icmp_rtt_ms {
                    Some(rtt) => CheckResult::pass(
                        "resolver_reachable",
                        "resolver reachable",
                        format!("icmp {rtt:.1}ms but queries fail — udp/53 may be filtered"),
                    ),
                    None => CheckResult::not_run(
                        "resolver_reachable",
                        "resolver reachable",
                        Availability::NotImplemented,
                        "no icmp probe of the resolver has run",
                    ),
                }],
            ),
        ];
        d.remediation = dns_remediation(dns, None);
        out.push(d);
        // A resolver that is failing outright makes its latency uninteresting.
        return out;
    }

    // Truncation: the resolver keeps answering with TC set, which makes
    // every such lookup a second round trip over TCP — visible as a slow
    // resolver that the rtt probe, asking a small question, never sees.
    if dns.queries >= 10 && dns.truncation_rate_pct > t.dns_tc_pct {
        let mut d = Detection::new(
            "dns.truncation_retry",
            Subject::Resolver {
                addr: dns.resolver.clone(),
            },
        );
        d.evidence.push(
            Evidence::new("dns.tc_rate", dns.truncation_rate_pct, "%")
                .with_window(dns.window_secs, dns.queries),
        );
        d.causes = vec![
            Cause::new(
                "no_edns",
                "the resolver is not offering EDNS, so anything over 512 bytes truncates",
                vec![CheckResult::pass(
                    "truncated_replies",
                    "truncated replies",
                    format!("{} of {} replies carried TC", dns.truncated, dns.queries),
                )],
            ),
            Cause::new(
                "middlebox_clamps_udp",
                "a middlebox strips EDNS or clamps UDP replies",
                vec![CheckResult::not_run(
                    "edns_through_the_path",
                    "edns through the path",
                    Availability::NotImplemented,
                    "not probed — compare a direct query against the resolver's",
                )],
            ),
        ];
        d.remediation = vec![
            Step::instruct(
                "see the truncation from the client's side",
                format!("dig @{} . NS +noedns | grep -i flags", dns.resolver),
            ),
            Step::instruct(
                "check whether EDNS gets through",
                format!("dig @{} . NS +bufsize=1232 | grep -i flags", dns.resolver),
            ),
            Step::instruct(
                "use a resolver that speaks EDNS, or forward over TCP",
                "most stub resolvers retry over TCP on TC; the cost is one extra round trip per lookup",
            ),
        ];
        out.push(d);
    }

    if let Some(cross) = &dns.cross {
        let forged = cross.cycles >= 3 && cross.mismatch_pct > t.dns_mismatch_pct;
        if cross.private_answer || forged {
            let mut d = Detection::new(
                "dns.hijack_suspect",
                Subject::Resolver {
                    addr: dns.resolver.clone(),
                },
            );
            d.evidence.push(
                Evidence::new("dns.answer_mismatch", cross.mismatch_pct, "%")
                    .with_window(dns.window_secs, cross.cycles),
            );
            let local = if cross.local.is_empty() {
                "nothing".to_string()
            } else {
                cross.local.join(", ")
            };
            let reference = if cross.reference.is_empty() {
                "no answer".to_string()
            } else {
                cross.reference.join(", ")
            };
            d.causes = vec![
                Cause::new(
                    "interceptor",
                    "a captive portal or interceptor answering for every name",
                    vec![if cross.private_answer {
                        CheckResult::pass(
                            "private_answer_for_a_public_name",
                            "private answer for a public name",
                            format!("{} → {local}", cross.name),
                        )
                        .weighted(2.0)
                    } else {
                        CheckResult::fail(
                            "private_answer_for_a_public_name",
                            "private answer for a public name",
                            format!("{} → {local}", cross.name),
                        )
                        .weighted(2.0)
                    }],
                ),
                Cause::new(
                    "forged_records",
                    "the resolver returns records the validating reference does not",
                    vec![
                        if forged {
                            CheckResult::pass(
                                "disagrees_with_reference",
                                "disagrees with reference",
                                format!(
                                    "{local} here, {reference} from {}",
                                    cross.reference_resolver
                                ),
                            )
                            .weighted(2.0)
                        } else {
                            CheckResult::fail(
                                "disagrees_with_reference",
                                "disagrees with reference",
                                format!("{local} agrees with {}", cross.reference_resolver),
                            )
                            .weighted(2.0)
                        },
                        if cross.validated {
                            CheckResult::pass(
                                "reference_validated",
                                "reference validated",
                                format!("{} set AD on its answer", cross.reference_resolver),
                            )
                        } else {
                            // The reference did answer, just without AD
                            // (most often an unsigned zone), so this is a
                            // fresh result with nothing to validate, not a
                            // missing one.
                            CheckResult::not_run(
                                "reference_validated",
                                "reference validated",
                                Availability::NotApplicable,
                                format!("{} answered without AD", cross.reference_resolver),
                            )
                        },
                    ],
                ),
                // A private answer for a public name is the signature of an
                // internal zone as much as of an interceptor, so it supports
                // this cause on the same evidence and at the same weight as
                // `interceptor` above. Nothing netwatch measures separates a
                // deliberate override from a hostile one; ranking them equally
                // is the honest outcome until a discriminating check exists.
                Cause::new(
                    "split_horizon",
                    "split-horizon dns on this network, by design",
                    vec![if cross.private_answer {
                        CheckResult::pass(
                            "private_answer_for_a_public_name",
                            "private answer for a public name",
                            format!(
                                "{} → {local}, which an internal zone also explains",
                                cross.name
                            ),
                        )
                        .weighted(2.0)
                    } else {
                        CheckResult::not_run(
                            "private_answer_for_a_public_name",
                            "private answer for a public name",
                            Availability::NotApplicable,
                            "the answer is public, so an internal zone does not explain it",
                        )
                        .weighted(2.0)
                    }],
                ),
            ];
            d.remediation = vec![
                Step::instruct(
                    "compare the two answers yourself",
                    format!(
                        "dig @{} {} A +short; dig @{} {} A +short +dnssec",
                        dns.resolver, cross.name, cross.reference_resolver, cross.name
                    ),
                ),
                Step::instruct(
                    "if this is a portal, open a browser and sign in",
                    "portals answer every name with their own address until you do",
                ),
                Step::escalate(
                    "use a validating resolver you trust",
                    format!(
                        "resolvectl dns <iface> {} — or DNS over HTTPS in the browser",
                        cross.reference_resolver
                    ),
                ),
            ];
            out.push(d);
        }
    }

    let Some(p50) = dns.rtt_p50_ms else {
        return out;
    };

    let baseline = base.get(&dns.resolver, "dns.rtt_p50");
    // The ceiling applies with a baseline too: 160 ms is slow whatever the
    // resolver usually does.
    let over_ceiling = p50 > t.dns_ceiling_ms;
    let over_baseline = baseline
        .and_then(|b| dns_open_line(b, t))
        .is_some_and(|line| p50 >= line);

    if !over_ceiling && !over_baseline {
        return out;
    }

    let mut ev = Evidence::new("dns.rtt_p50", p50, "ms").with_window(dns.window_secs, dns.queries);
    if let Some(b) = baseline {
        ev = ev.with_baseline(b.mean, b.sigma_floored(t.sigma_floor()));
    }

    let mut d = Detection::new(
        "dns.slow_resolver",
        Subject::Resolver {
            addr: dns.resolver.clone(),
        },
    );
    // Severity escalates with the multiple of baseline, not with the raw
    // number — 40ms is catastrophic against a 1.2ms LAN resolver and
    // unremarkable against a 35ms mobile one.
    d.severity = match ev.multiple_of_baseline() {
        Some(m) if m >= 20.0 => Severity::High,
        _ => Severity::Medium,
    };
    d.evidence.push(ev);
    if let Some(p95) = dns.rtt_p95_ms {
        d.evidence.push(
            Evidence::new("dns.rtt_p95", p95, "ms").with_window(dns.window_secs, dns.queries),
        );
    }

    let alt_fast = matches!(dns.alt_rtt_ms, Some(a) if a < p50 / 4.0);
    // Behind a local stub, ICMP to the resolver and its cached answers say
    // nothing about the upstream these checks are about: loopback always
    // answers, and the probe's own root-NS answer is a cache hit.
    let stub = dns.is_local_stub();
    let (icmp_rtt_ms, cached_rtt_ms) = if stub {
        (None, None)
    } else {
        (dns.icmp_rtt_ms, dns.cached_rtt_ms)
    };
    let icmp_normal = icmp_rtt_ms.map(|r| r < 10.0);
    let cached_fast = matches!(cached_rtt_ms, Some(c) if c < p50 / 4.0);

    d.causes = vec![
        Cause::new(
            "upstream_slow",
            "the resolver's upstream forwarder is slow",
            vec![
                match (dns.alt_resolver.as_deref(), dns.alt_rtt_ms) {
                    (Some(alt), Some(rtt)) if alt_fast => CheckResult::pass(
                        "alt_resolver_is_fast",
                        "alt resolver is fast",
                        format!("{alt} answered in {rtt:.1}ms"),
                    )
                    .weighted(2.0),
                    (Some(alt), Some(rtt)) => CheckResult::fail(
                        "alt_resolver_is_fast",
                        "alt resolver is fast",
                        format!("{alt} is also slow at {rtt:.1}ms"),
                    )
                    .weighted(2.0),
                    _ => CheckResult::not_run(
                        "alt_resolver_is_fast",
                        "alt resolver is fast",
                        Availability::NotMeasured,
                        "no alternate resolver probed",
                    )
                    .weighted(2.0),
                },
                match (icmp_normal, icmp_rtt_ms) {
                    (Some(true), Some(rtt)) => CheckResult::pass(
                        "resolver_itself_is_reachable",
                        "resolver itself is reachable",
                        format!("icmp {rtt:.1}ms — the box is fine, its answers are not"),
                    ),
                    (Some(false), Some(rtt)) => CheckResult::fail(
                        "resolver_itself_is_reachable",
                        "resolver itself is reachable",
                        format!("icmp {rtt:.1}ms is slow too"),
                    ),
                    _ if stub => CheckResult::not_run(
                        "resolver_itself_is_reachable",
                        "resolver itself is reachable",
                        Availability::NotMeasured,
                        UPSTREAM_UNKNOWN,
                    ),
                    _ => CheckResult::not_run(
                        "resolver_itself_is_reachable",
                        "resolver itself is reachable",
                        Availability::NotImplemented,
                        "no icmp probe",
                    ),
                },
                match (cached_fast, cached_rtt_ms) {
                    (true, Some(c)) => CheckResult::pass(
                        "cached_names_still_fast",
                        "cached names still fast",
                        format!("cache hits answer in {c:.1}ms — only recursion is slow"),
                    ),
                    (false, Some(c)) => CheckResult::fail(
                        "cached_names_still_fast",
                        "cached names still fast",
                        format!("even cache hits take {c:.1}ms"),
                    ),
                    _ if stub => CheckResult::not_run(
                        "cached_names_still_fast",
                        "cached names still fast",
                        Availability::NotMeasured,
                        UPSTREAM_UNKNOWN,
                    ),
                    _ => CheckResult::not_run(
                        "cached_names_still_fast",
                        "cached names still fast",
                        Availability::NotImplemented,
                        "no cache probe",
                    ),
                },
            ],
        ),
        Cause::new(
            "resolver_overloaded",
            "the resolver is overloaded",
            vec![
                match (icmp_normal, icmp_rtt_ms) {
                    (Some(false), Some(rtt)) => CheckResult::pass(
                        "icmp_rtt_raised",
                        "icmp rtt raised",
                        format!("icmp to the resolver is {rtt:.1}ms"),
                    ),
                    (Some(true), Some(rtt)) => CheckResult::fail(
                        "icmp_rtt_raised",
                        "icmp rtt raised",
                        format!("icmp is normal at {rtt:.1}ms"),
                    ),
                    _ if stub => CheckResult::not_run(
                        "icmp_rtt_raised",
                        "icmp rtt raised",
                        Availability::NotMeasured,
                        UPSTREAM_UNKNOWN,
                    ),
                    _ => CheckResult::not_run(
                        "icmp_rtt_raised",
                        "icmp rtt raised",
                        Availability::NotImplemented,
                        "no icmp probe",
                    ),
                },
                if dns.failed > 0 || dns.truncated > 0 {
                    CheckResult::pass(
                        "timeouts_or_servfail_present",
                        "timeouts or servfail present",
                        format!("{} failed, {} truncated", dns.failed, dns.truncated),
                    )
                } else {
                    CheckResult::fail(
                        "timeouts_or_servfail_present",
                        "timeouts or servfail present",
                        "no failures, only latency",
                    )
                },
            ],
        ),
        Cause::new(
            "local_udp_path",
            "local: conntrack, udp buffers or nftables",
            // Neither shared check tells this cause apart from a slow or
            // lossy uplink, which slows the alternate too. They used to pass
            // with no alternate probed and on a single drop, so a Wi-Fi
            // laptop shedding one multicast frame a minute got a strong local
            // fault from two checks that measured nothing local.
            vec![
                // "Also slow" is half this resolver's median or more. The
                // half is a judgement, not a validated line; below it the
                // alternate is at least twice as fast over the same path.
                match dns.alt_rtt_ms {
                    Some(alt) if alt >= p50 / 2.0 => CheckResult::pass(
                        "alt_resolver_over_the_same_path_is_also_slow",
                        "alt resolver over the same path is also slow",
                        format!(
                            "the alternate took {alt:.1}ms against {p50:.1}ms — the problem may be local"
                        ),
                    ),
                    Some(alt) => CheckResult::fail(
                        "alt_resolver_over_the_same_path_is_also_slow",
                        "alt resolver over the same path is also slow",
                        format!("the alternate answered in {alt:.1}ms over the same path"),
                    ),
                    None => CheckResult::not_run(
                        "alt_resolver_over_the_same_path_is_also_slow",
                        "alt resolver over the same path is also slow",
                        Availability::NotMeasured,
                        "no alternate resolver probed",
                    ),
                },
                // The same floor iface.errors uses: a wireless NIC drops
                // multicast and management frames as a matter of course.
                match obs.iface.as_ref().map(|i| i.drops_per_min) {
                    Some(Some(d)) if d as f64 >= t.iface_drop_floor => CheckResult::pass(
                        "interface_drops",
                        "interface drops",
                        format!("{d} drops a minute"),
                    ),
                    Some(Some(d)) => CheckResult::fail(
                        "interface_drops",
                        "interface drops",
                        format!(
                            "{d} drops a minute, under the {:.0}/min floor",
                            t.iface_drop_floor
                        ),
                    ),
                    Some(None) => CheckResult::not_run(
                        "interface_drops",
                        "interface drops",
                        Availability::Unsupported,
                        "interface drops are not counted on macOS",
                    ),
                    None => CheckResult::not_run(
                        "interface_drops",
                        "interface drops",
                        Availability::NotMeasured,
                        "no interface counters",
                    ),
                },
                // The discriminator: the kernel counting UDP datagrams it
                // threw away on this host. Until it is read the cause stops
                // at Likely, however the shared checks come out.
                CheckResult::not_run(
                    "local_drop_counters",
                    "local drop counters",
                    Availability::NotImplemented,
                    "UDP receive-buffer and conntrack drop counters are not read yet",
                )
                .weighted(2.0),
            ],
        ),
    ];

    d.remediation = dns_remediation(dns, Some(p50));
    d.verify.threshold = dns_close_line(baseline, t);
    d.scope = Scope {
        configuration: None,
        processes: vec![],
        destinations: 0,
        flows: 0,
        via_iface: None,
        processes_measured: false,
        via_resolver: Some(dns.resolver.clone()),
        note: Some(if stub {
            format!(
                "every new connection pays this before it can start · the probe asks root NS; \
                 the local stub at {} answers from cache, so this is the stub's round trip",
                dns.resolver
            )
        } else {
            "every new connection pays this before it can start".into()
        }),
    };
    out.push(d);
    out
}

/// The p50 at which a resolver with this baseline is slow: `sigma_k` floored
/// σ above the mean, but at least `dns_delta_floor_ms` above it and
/// `dns_delta_multiple` times it. The σ floor alone opens on a LAN resolver
/// moving from 1.2 to 2.7 ms, and 5 ms over a 30 ms resolver is noise. `None`
/// when the floored σ is zero and the baseline cannot be scored.
///
/// With the ceiling, one of the two lines an issue opens on; the close line
/// is derived from the lower of them ([`dns_close_line`]).
fn dns_open_line(b: &Baseline, t: &Thresholds) -> Option<f64> {
    let sigma = b.sigma_floored(t.sigma_floor());
    (sigma > f64::EPSILON).then(|| {
        (b.mean + t.sigma_k * sigma)
            .max(b.mean + t.dns_delta_floor_ms)
            .max(t.dns_delta_multiple * b.mean)
    })
}

/// The share of its open line a slow resolver's p50 must fall under before
/// the issue closes.
const DNS_CLOSE_SHARE: f64 = 0.8;

/// The p50 a `dns.slow_resolver` issue must stay under for its 60 s hold:
/// `sigma_close_k` floored σ above the baseline mean, or 0.8 of the line the
/// issue opened on, whichever is higher. With no baseline it is 0.8 of the
/// ceiling. The engine keeps the line set at open.
///
/// The open line is the lower of the ceiling and the baseline's line,
/// because crossing either opens the issue. A router answering in 10.5 ms
/// opens at 21 ms and closes under 16.8 ms, whether a 60 ms or a 150 ms spike
/// opened it. The σ term keeps the line above the resolver's normal range:
/// 0.8 of the open line alone can fall inside it, and the issue would never
/// close, as the flat 5 ms this replaces never did for a 10 ms router.
///
/// On a resolver whose normal range reaches the ceiling, the σ term can put
/// the close line above it. The issue then closes once the p50 has stayed
/// under the ceiling for the hold, because a p50 over it keeps the issue open.
fn dns_close_line(baseline: Option<&Baseline>, t: &Thresholds) -> f64 {
    let open = baseline
        .and_then(|b| dns_open_line(b, t))
        .map_or(t.dns_ceiling_ms, |line| line.min(t.dns_ceiling_ms));
    let under_open = DNS_CLOSE_SHARE * open;
    baseline.map_or(under_open, |b| {
        under_open.max(b.mean + t.sigma_close_k * b.sigma_floored(t.sigma_floor()))
    })
}

/// Steps for a failing or slow resolver. A switch is proposed only to an
/// alternate that was measured: for a slow resolver, one that answered in
/// under a quarter of `slow_p50`, the line `alt_resolver_is_fast` passes on;
/// for a failing one (`None`), answering at all is the case for it. Live, no
/// alternate is timed until A11 keeps the reference resolver's RTT, so today
/// the step appears only in the demo, which simulates it.
fn dns_remediation(dns: &DnsObs, slow_p50: Option<f64>) -> Vec<Step> {
    let mut steps = Vec::new();
    let measured = match (&dns.alt_resolver, dns.alt_rtt_ms) {
        (Some(alt), Some(rtt)) if slow_p50.is_none_or(|p50| rtt < p50 / 4.0) => Some((alt, rtt)),
        _ => None,
    };
    if let Some((alt, rtt)) = measured {
        // The live `↵` writes nothing, so the text says what to run instead
        // of promising an edit netwatch will not make.
        steps.push(Step::apply(
            '1',
            format!("switch this session's resolver to {alt}"),
            format!(
                "{alt} answered in {rtt:.1}ms during the check; netwatch does not change \
                 resolvers from this screen; run: sudo netwatch resolver set {alt} --unmanaged \
                 (unmanaged resolv.conf only), or resolvectl dns <iface> {alt}"
            ),
            Action::SetResolver { addr: alt.clone() },
            Capability::Root,
        ));
        steps.push(Step::instruct(
            "make it permanent",
            format!("resolvectl dns <iface> {alt}, or set it in the dhcp client"),
        ));
    }
    steps.push(Step::instruct(
        "keep watching",
        "netwatch re-evaluates every tick and closes the issue when it clears",
    ));
    steps.push(Step::escalate(
        "if you run the resolver",
        "check its upstream forwarder and consider a second one",
    ));
    steps
}

// ---------------------------------------------------------------- paths

fn detect_paths(obs: &Observations, base: &BaselineStore, t: &Thresholds) -> Vec<Detection> {
    let mut out = Vec::new();
    for path in &obs.paths {
        if let Some(d) = detect_path_change(path) {
            out.push(d);
        }
        if let Some(d) = detect_path_loss(path) {
            out.push(d);
        }
        if let Some(d) = detect_path_rtt(path, base, t) {
            out.push(d);
        }
    }
    out
}

/// End-to-end rtt drifting above what this path normally does. The last hop's
/// rtt is the whole path's rtt; earlier hops are only interesting for
/// attributing *where* the time went, which the cause list does.
fn detect_path_rtt(path: &PathObs, base: &BaselineStore, t: &Thresholds) -> Option<Detection> {
    let last = path.hops.iter().rev().find(|h| !h.silent)?;
    let rtt = last.rtt_p50_ms?;
    let b = base
        .get(&path.target, "path.rtt")
        .or_else(|| base.get("internet", "path.rtt"))?;
    let sigma = b.sigma_above(rtt, t.sigma_floor())?;
    if sigma < t.sigma_k {
        return None;
    }

    // Where the extra latency entered the path: the hop with the largest
    // jump over its predecessor.
    let worst_jump = path
        .hops
        .windows(2)
        .filter_map(|w| match (w[0].rtt_p50_ms, w[1].rtt_p50_ms) {
            (Some(a), Some(c)) if !w[1].silent => Some((w[1].number, c - a)),
            _ => None,
        })
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut d = Detection::new(
        "path.rtt_spike",
        Subject::Path {
            target: path.target.clone(),
        },
    );
    // Closes below the open line, as gateway.rtt_spike does.
    d.verify.threshold = t.sigma_close_k;
    d.evidence.push(
        Evidence::new("path.rtt", rtt, "ms")
            .with_baseline(b.mean, b.sigma_floored(t.sigma_floor()))
            .with_window(60, 60),
    );
    d.evidence
        .push(Evidence::new("path.rtt_sigma", sigma, "σ").with_window(60, 60));
    d.causes = vec![
        Cause::new(
            "hop_adds_latency",
            match worst_jump {
                Some((hop, _)) => format!("latency enters the path at hop {hop}"),
                None => "latency is spread across the path".to_string(),
            },
            vec![match worst_jump {
                Some((hop, delta)) => CheckResult::pass(
                    "one_hop_dominates",
                    "one hop dominates",
                    format!("hop {hop} adds {delta:.0}ms over its predecessor"),
                ),
                None => CheckResult::not_run(
                    "one_hop_dominates",
                    "one hop dominates",
                    Availability::NotMeasured,
                    "not enough per-hop timing to attribute the increase",
                ),
            }],
        ),
        Cause::new(
            "route_change",
            "a route change moved the traffic",
            vec![match &path.previous {
                Some(prev) => match first_hop_change(prev, &path.hops) {
                    Some(hop) => CheckResult::pass(
                        "the_path_changed",
                        "the path changed",
                        format!("hop {hop} differs from the previous trace"),
                    ),
                    None => CheckResult::fail(
                        "the_path_changed",
                        "the path changed",
                        "the route is unchanged",
                    ),
                },
                None => CheckResult::not_run(
                    "the_path_changed",
                    "the path changed",
                    Availability::AwaitingTest,
                    "no previous trace to compare",
                ),
            }],
        ),
    ];
    d.remediation = vec![Step::instruct(
        "trace the target",
        "the hop table shows p50/p95 per hop and the diff against the last trace",
    )];
    Some(d)
}

/// Diff two traces. Returns the first hop number whose IP or ASN changed.
pub fn first_hop_change(previous: &[HopObs], current: &[HopObs]) -> Option<u8> {
    for cur in current {
        let Some(prev) = previous.iter().find(|h| h.number == cur.number) else {
            continue;
        };
        // A hop that has gone silent, or come back, is not a route change —
        // routers rate-limit ICMP and drop in and out of traces constantly.
        if prev.silent || cur.silent {
            continue;
        }
        if prev.ip != cur.ip || (prev.asn.is_some() && cur.asn.is_some() && prev.asn != cur.asn) {
            return Some(cur.number);
        }
    }
    None
}

fn detect_path_change(path: &PathObs) -> Option<Detection> {
    let previous = path.previous.as_ref()?;
    let hop_no = first_hop_change(previous, &path.hops)?;
    let cur = path.hops.iter().find(|h| h.number == hop_no)?;
    let prev = previous.iter().find(|h| h.number == hop_no)?;

    let mut d = Detection::new(
        "path.changed",
        Subject::Path {
            target: path.target.clone(),
        },
    );

    // Latency the new hop added is what turns a route change from a note into
    // a finding — and it leads the evidence, because "hop 3 changed" is the
    // headline nobody can act on while "+40ms" is the one they can. The
    // change count still rides along; it is what `verify` closes against.
    let added_latency = match (cur.rtt_p50_ms, prev.rtt_p50_ms) {
        (Some(c), Some(p)) => Some(c - p),
        _ => None,
    };
    if let Some(j) = added_latency {
        // No baseline on a delta: "+40ms" against a 12ms previous hop would
        // render as "3.3× baseline", which is a true division and a
        // meaningless statement.
        d.evidence
            .push(Evidence::new("path.hop_rtt_delta", j, "ms added").with_window(60, 1));
        if j > 20.0 {
            d.severity = Severity::Medium;
        }
    }
    d.evidence
        .push(Evidence::new("path.hop_changes", 1.0, " hop").with_window(60, 1));

    let asn_changed = prev.asn != cur.asn;
    d.causes = vec![
        Cause::new(
            "provider_reroute",
            if asn_changed {
                "the traffic moved to a different provider"
            } else {
                "the provider rerouted inside its own network"
            },
            vec![
                if asn_changed {
                    CheckResult::pass(
                        "asn_changed",
                        "asn changed",
                        format!(
                            "hop {hop_no}: {} → {}",
                            prev.asn.as_deref().unwrap_or("unknown"),
                            cur.asn.as_deref().unwrap_or("unknown")
                        ),
                    )
                } else {
                    CheckResult::pass(
                        "asn_unchanged",
                        "asn unchanged",
                        format!(
                            "hop {hop_no} stayed in {}",
                            cur.asn.as_deref().unwrap_or("the same asn")
                        ),
                    )
                },
                CheckResult::pass(
                    "hop_address_changed",
                    "hop address changed",
                    format!(
                        "{} → {}",
                        prev.ip.as_deref().unwrap_or("—"),
                        cur.ip.as_deref().unwrap_or("—")
                    ),
                ),
            ],
        ),
        Cause::new(
            "local_route_change",
            "a local route or interface changed",
            vec![if hop_no <= 2 {
                CheckResult::pass(
                    "change_is_at_hop_1_or_2",
                    "change is at hop 1 or 2",
                    "the change is on our side",
                )
            } else {
                CheckResult::fail(
                    "change_is_at_hop_1_or_2",
                    "change is at hop 1 or 2",
                    format!("the change is at hop {hop_no}, upstream of us"),
                )
            }],
        ),
    ];
    d.remediation = vec![
        Step::instruct(
            "nothing to do",
            "a route change is context, not a fault — netwatch keeps it on the \
             timeline so a later issue can be correlated with it",
        ),
        Step::escalate(
            "if problems started with it",
            "send the before/after trace to the provider",
        ),
    ];
    Some(d)
}

fn detect_path_loss(path: &PathObs) -> Option<Detection> {
    // Loss only counts when it propagates. A hop that drops probes while
    // later hops are clean is rate-limiting ICMP, not losing traffic.
    //
    // A silent tail is a third case, and the one that produced false blame:
    // nothing after the lossy hop answered, so propagation was never observed
    // either way. That is reported as unattributed loss, because the
    // alternative — naming the last hop that happened to answer — accuses a
    // router of dropping traffic on the strength of its own ICMP policy.
    let mut attributed: Option<&HopObs> = None;
    let mut blind: Option<&HopObs> = None;
    for (i, hop) in path.hops.iter().enumerate() {
        if hop.silent || hop.loss_pct < 5.0 {
            continue;
        }
        let later: Vec<&HopObs> = path.hops[i + 1..].iter().filter(|h| !h.silent).collect();
        if later.iter().any(|h| h.loss_pct >= 5.0) {
            attributed = Some(hop);
            break;
        }
        if later.is_empty() {
            blind.get_or_insert(hop);
        }
        // Otherwise later hops answered and are clean: ICMP rate limiting,
        // not a finding. Keep scanning for a hop whose loss does propagate.
    }

    let hop = attributed.or(blind)?;
    let propagates = attributed.is_some();

    let mut d = Detection::new(
        "path.high_loss",
        Subject::Path {
            target: path.target.clone(),
        },
    );
    d.evidence
        .push(Evidence::new("path.hop_loss", hop.loss_pct, "%").with_window(60, 1));

    // Each check states what this trace showed. The strings used to be fixed,
    // so "loss propagates to later hops" and "later hops lose packets too"
    // were printed in the branch where nothing after the hop answered.
    let propagation = if propagates {
        CheckResult::pass(
            "loss_propagates_to_later_hops",
            "loss propagates to later hops",
            format!("{:.0}% at hop {} and beyond", hop.loss_pct, hop.number),
        )
    } else {
        CheckResult::not_run(
            "loss_propagates_to_later_hops",
            "loss propagates to later hops",
            Availability::NotMeasured,
            "every hop after this one is silent, so propagation was not observed",
        )
    };
    let later_clean = if propagates {
        CheckResult::fail(
            "later_hops_are_clean",
            "later hops are clean",
            "later hops lose packets too, so this is real loss",
        )
    } else {
        CheckResult::not_run(
            "later_hops_are_clean",
            "later hops are clean",
            Availability::NotMeasured,
            "no hop after this one answered, so there is nothing to compare",
        )
    };
    let destination = match path.destination_reached {
        Some(true) => CheckResult::pass(
            "destination_answered_the_trace",
            "destination answered the trace",
            format!("{} replied, so the path completes", path.target),
        )
        .weighted(2.0),
        Some(false) => CheckResult::fail(
            "destination_answered_the_trace",
            "destination answered the trace",
            format!("{} never replied to the trace", path.target),
        )
        .weighted(2.0),
        None => CheckResult::not_run(
            "destination_answered_the_trace",
            "destination answered the trace",
            Availability::NotMeasured,
            "this trace cannot tell whether the destination answered",
        )
        .weighted(2.0),
    };

    let hop_label = format!(
        "hop {} ({})",
        hop.number,
        hop.ip.as_deref().unwrap_or("unknown")
    );
    d.causes = vec![
        Cause::new(
            "hop_dropping",
            format!("{hop_label} is dropping traffic"),
            vec![propagation, destination.clone()],
        ),
        Cause::new(
            "icmp_rate_limit",
            "the hop is rate-limiting icmp rather than losing traffic",
            vec![later_clean, destination],
        ),
    ];
    if !propagates {
        d.scope.note = Some(format!(
            "every hop after {hop_label} is silent — the trace lost packets, \
             but no hop can be blamed for it"
        ));
    }
    d.remediation = vec![
        Step::instruct(
            "try a different path",
            "a vpn or alternate route avoids the hop",
        ),
        Step::escalate(
            "send the trace to the provider",
            "the exported bundle contains the full trace with per-hop loss",
        ),
    ];
    Some(d)
}

// -------------------------------------------------------------- sockets

fn detect_sockets(obs: &Observations, t: &Thresholds) -> Vec<Detection> {
    let mut out = Vec::new();
    for s in &obs.sockets {
        let verdict = classify_socket(s, t);
        if verdict.is_ok() {
            continue;
        }
        // Hysteresis: a verdict has to stick before it becomes a finding.
        // Without this, every slow-start ramp opens and closes an issue.
        if s.verdict_age_secs < t.verdict_hold_secs {
            continue;
        }
        if let Some(d) = socket_detection(s, verdict, obs, t) {
            out.push(d);
        }
    }
    out
}

fn socket_detection(
    s: &SocketObs,
    verdict: SocketVerdict,
    obs: &Observations,
    t: &Thresholds,
) -> Option<Detection> {
    let subject = Subject::Socket {
        local: s.local.clone(),
        remote: s.remote.clone(),
    };
    let link_test_passed = match (obs.idle_rtt_ms, obs.loaded_rtt_ms) {
        (Some(idle), Some(loaded)) => Some(loaded - idle < t.loaded_rtt_delta_ms),
        _ => None,
    };

    let mut d = match verdict {
        SocketVerdict::Bufferbloat => {
            // The verdict needs a measured rtt; with none there is no finding,
            // and never one quoting an rtt of 0.
            let rtt = s.rtt_ms?;
            let mut d = Detection::new("tcp.bufferbloat_remote", subject);
            d.evidence
                .push(Evidence::new("tcp.socket_rtt", rtt, "ms").with_window(30, 30));
            if let Some(retrans) = s.retrans {
                d.evidence
                    .push(Evidence::new("tcp.retrans", retrans as f64, "").with_window(60, 60));
            }
            // Localisation needs the loaded/idle comparison. Without it the
            // only measurement in hand is "rtt is high while this socket
            // sends", which a queue at either end explains equally well — and
            // an intercontinental peer explains without any queue at all. The
            // cause named below changes with the evidence, so the finding
            // never claims a side it has not measured.
            let localised = link_test_passed.is_some();
            let queue_checks = vec![
                match link_test_passed {
                    Some(true) => CheckResult::pass(
                        "link_level_bufferbloat_test_passed",
                        "link-level bufferbloat test passed",
                        "our uplink stays responsive under load",
                    )
                    .weighted(2.0),
                    Some(false) => CheckResult::fail(
                        "link_level_bufferbloat_test_passed",
                        "link-level bufferbloat test passed",
                        "our own uplink bloats under load too",
                    )
                    .weighted(2.0),
                    None => CheckResult::not_run(
                        "link_level_bufferbloat_test_passed",
                        "link-level bufferbloat test passed",
                        Availability::AwaitingTest,
                        "no loaded-rtt test has run, so the queue cannot be placed",
                    )
                    .weighted(2.0),
                },
                match s.tx_bps {
                    Some(tx) if tx > 0.0 => CheckResult::pass(
                        "rtt_tracks_this_socket_s_own_tx",
                        "rtt tracks this socket's own tx",
                        format!("{} in flight while rtt is {rtt:.0}ms", rate(tx)),
                    ),
                    Some(_) => CheckResult::fail(
                        "rtt_tracks_this_socket_s_own_tx",
                        "rtt tracks this socket's own tx",
                        "socket is idle",
                    ),
                    None => CheckResult::not_run(
                        "rtt_tracks_this_socket_s_own_tx",
                        "rtt tracks this socket's own tx",
                        Availability::NotMeasured,
                        "no connection row gave this socket's rate",
                    ),
                },
            ];
            let queue = if localised {
                Cause::new(
                    "receiver_queueing",
                    "the receiver is queueing — its buffer, not ours",
                    queue_checks,
                )
            } else {
                Cause::new(
                    "unlocalised_queueing",
                    "something is queueing; which end is unmeasured",
                    queue_checks,
                )
            };
            d.causes = vec![
                queue,
                Cause::new(
                    "path_loss",
                    "loss on the path",
                    // Retransmit count is *not* the discriminator here: a
                    // bufferbloated socket retransmits because the queue
                    // delays its ACKs past the RTO, so "12 retransmits"
                    // supports both causes equally and ranking on it is a
                    // coin toss dressed up as analysis. What separates them
                    // is whether the path is actually losing packets — which
                    // takes a trace, and says so when it hasn't got one.
                    vec![path_loss_check(&s.remote, obs)],
                ),
            ];
            d.remediation = if localised {
                vec![
                    Step::instruct(
                        "nothing to fix locally",
                        "the queue is on the receiver; the report names the peer",
                    ),
                    Step::escalate(
                        "tell whoever runs the peer",
                        "ask for fq_codel or cake on its egress",
                    ),
                ]
            } else {
                vec![Step::instruct(
                    "run the loaded-rtt test to place the queue",
                    "it compares idle and loaded rtt on your own uplink; until it \
                     runs, neither end can be blamed",
                )]
            };
            if !localised {
                // The rule's catalogue title says "receiver-side
                // bufferbloat". Leaving it on a finding that could not place
                // the queue puts the claim back in the headline, which is the
                // line most people read and the only one a copied summary
                // carries.
                d.title = "socket queueing, side unmeasured".into();
                // And it is not a Medium finding either: until the loaded-rtt
                // test places the queue, "rtt is high while sending" is an
                // observation to act on by running that test, not a fault.
                d.severity = Severity::Info;
                d.scope.note = Some(
                    "rtt is high while this socket sends, but no loaded-rtt test has \
                     run — a distant peer looks the same as a queue"
                        .into(),
                );
            }
            d
        }
        SocketVerdict::RetransBurst => {
            let mut d = Detection::new("tcp.retrans_burst", subject);
            d.evidence.push(
                Evidence::new("tcp.retrans_rate", s.retrans? as f64, "/min").with_window(60, 60),
            );
            d.causes = vec![Cause::new(
                "packet_loss",
                "packet loss between here and the peer",
                vec![
                    CheckResult::pass(
                        "retransmits_observed",
                        "retransmits observed",
                        format!(
                            "{} retransmits in the last minute on this socket",
                            s.retrans?
                        ),
                    ),
                    // What keeps a queue out of it: a bloated socket
                    // retransmits too, once its ACKs queue past the RTO.
                    match s.rtt_ms {
                        Some(rtt) if rtt < t.socket_rtt_ms => CheckResult::pass(
                            "socket_rtt_below_queueing_line",
                            "socket rtt below queueing line",
                            format!(
                                "rtt {rtt:.0}ms, under the {:.0}ms queueing line",
                                t.socket_rtt_ms
                            ),
                        ),
                        Some(rtt) => CheckResult::fail(
                            "socket_rtt_below_queueing_line",
                            "socket rtt below queueing line",
                            format!(
                                "rtt {rtt:.0}ms, over the {:.0}ms queueing line",
                                t.socket_rtt_ms
                            ),
                        ),
                        None => CheckResult::not_run(
                            "socket_rtt_below_queueing_line",
                            "socket rtt below queueing line",
                            Availability::NotMeasured,
                            "no rtt for this socket, so a queue is not ruled out",
                        ),
                    },
                ],
            )];
            d.remediation = vec![Step::instruct(
                "trace the peer",
                "press t to trace and see which hop loses",
            )];
            d
        }
        SocketVerdict::ZeroWindow => {
            let mut d = Detection::new("tcp.zero_window", subject);
            d.evidence
                .push(Evidence::new("tcp.rwnd", 0.0, "B").with_window(30, 30));
            d.causes = vec![Cause::new(
                "peer_not_reading",
                "the peer application is not reading its socket",
                vec![CheckResult::pass(
                    "rwnd_is_zero",
                    "rwnd is zero",
                    "the receive window has closed",
                )],
            )];
            d.remediation = vec![Step::instruct(
                "nothing to fix on this side",
                "the report names the peer and the local process",
            )];
            d
        }
        SocketVerdict::ReceiverLimited => {
            let mut d = Detection::new("tcp.zero_window", subject);
            d.severity = Severity::Info;
            d.title = "receiver-limited socket".into();
            d.evidence.push(
                Evidence::new("tcp.rwnd", s.rwnd.unwrap_or(0) as f64, "B").with_window(30, 30),
            );
            d.causes = vec![Cause::new(
                "peer_reading_slowly",
                "the peer is reading slower than we can send",
                vec![CheckResult::pass(
                    "cwnd_exceeds_rwnd",
                    "cwnd exceeds rwnd",
                    format!(
                        "cwnd {} × mss {} is more than twice rwnd {}",
                        s.cwnd.unwrap_or(0),
                        s.mss.unwrap_or(0),
                        s.rwnd.unwrap_or(0)
                    ),
                )],
            )];
            d.remediation = vec![Step::instruct(
                "nothing to fix on this side",
                "the sending side is healthy; the peer sets the pace",
            )];
            d
        }
        // Congestion and app-limited are normal states, not faults. They show
        // as verdicts in the Connections column and never open an issue.
        SocketVerdict::Congestion | SocketVerdict::AppLimited | SocketVerdict::Ok => return None,
    };

    d.scope = Scope {
        configuration: None,
        processes: s.process.iter().cloned().collect(),
        destinations: 1,
        flows: 1,
        via_iface: None,
        via_resolver: None,
        // A socket finding is about one flow, so attribution was attempted.
        // Whether it produced a name is what the label now distinguishes.
        processes_measured: true,
        note: None,
    };
    Some(d)
}

// ----------------------------------------------------------------- nat

/// Symmetric NAT: the mapping STUN reports depends on who asked.
fn detect_nat(obs: &Observations) -> Vec<Detection> {
    let Some(nat) = &obs.nat else {
        return vec![];
    };
    if !nat.symmetric {
        return vec![];
    }
    let mut d = Detection::new("nat.symmetric", Subject::Host);
    d.evidence
        .push(Evidence::new("nat.symmetric", 1.0, "").with_window(60, nat.mappings.len() as u32));
    let seen = nat
        .mappings
        .iter()
        .map(|(server, mapped)| format!("{mapped} via {server}"))
        .collect::<Vec<_>>()
        .join(", ");
    d.causes = vec![
        Cause::new(
            "address_dependent_nat",
            "a carrier-grade or enterprise nat with address-dependent mapping",
            vec![CheckResult::pass(
                "mapping_depends_on_destination",
                "mapping depends on destination",
                seen,
            )],
        ),
        Cause::new(
            "router_symmetric_nat",
            "the router's nat set to symmetric or 'strict'",
            vec![CheckResult::not_run(
                "single_nat_layer",
                "single nat layer",
                Availability::NotImplemented,
                "cannot tell the router from a carrier nat behind it",
            )],
        ),
    ];
    d.remediation = vec![
        Step::instruct(
            "expect peer-to-peer to fall back to relays",
            "webrtc, voip and games hole-punch through cone nats; a symmetric one needs turn",
        ),
        Step::instruct(
            "check the router for a full-cone or upnp setting",
            "consumer routers often call it 'nat type' or 'open nat'",
        ),
    ];
    vec![d]
}

/// Whether a traced path to this peer is losing packets. Tri-state on
/// purpose: without a trace there is no evidence either way, and reporting
/// that as a failed check would let an untested cause be "ruled out".
fn path_loss_check(remote: &str, obs: &Observations) -> CheckResult {
    let host = remote.rsplit_once(':').map(|(h, _)| h).unwrap_or(remote);
    let Some(path) = obs.paths.iter().find(|p| p.target == host) else {
        return CheckResult::not_run(
            "the_path_to_this_peer_is_losing_packets",
            "the path to this peer is losing packets",
            Availability::AwaitingTest,
            format!("no trace to {host} — press t to run one"),
        );
    };
    match path.hops.iter().find(|h| !h.silent && h.loss_pct >= 5.0) {
        Some(hop) => CheckResult::pass(
            "the_path_to_this_peer_is_losing_packets",
            "the path to this peer is losing packets",
            format!("hop {} loses {:.0}%", hop.number, hop.loss_pct),
        ),
        None => CheckResult::fail(
            "the_path_to_this_peer_is_losing_packets",
            "the path to this peer is losing packets",
            "every hop on the traced path is clean",
        ),
    }
}

fn rate(bps: f64) -> String {
    if bps >= 1e6 {
        format!("{:.1} MB/s", bps / 1e6)
    } else if bps >= 1e3 {
        format!("{:.0} KB/s", bps / 1e3)
    } else {
        format!("{bps:.0} B/s")
    }
}

fn detect_bufferbloat_local(obs: &Observations, t: &Thresholds) -> Vec<Detection> {
    let (Some(idle), Some(loaded)) = (obs.idle_rtt_ms, obs.loaded_rtt_ms) else {
        return vec![];
    };
    let delta = loaded - idle;
    if delta < t.loaded_rtt_delta_ms {
        return vec![];
    }
    let mut d = Detection::new("tcp.bufferbloat_local", Subject::Host);
    d.evidence
        .push(Evidence::new("tcp.loaded_rtt_delta", delta, "ms").with_window(30, 30));
    d.causes = vec![Cause::new(
        "no_aqm_upstream",
        "no queue management on the upstream device",
        vec![CheckResult::pass(
            "rtt_rises_under_our_own_load",
            "rtt rises under our own load",
            format!("idle {idle:.0}ms → loaded {loaded:.0}ms"),
        )],
    )];
    d.remediation = vec![
        Step::instruct(
            "enable fq_codel or cake on the router",
            "on Linux: tc qdisc replace dev <wan> root cake bandwidth <uplink>",
        ),
        Step::instruct(
            "or rate-limit uploads to ~95% of the uplink",
            "leaves the queue empty enough to stay responsive",
        ),
    ];
    vec![d]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::baseline::NetworkFingerprint;

    fn store() -> BaselineStore {
        BaselineStore::new(NetworkFingerprint::new(
            "eth0",
            Some("192.168.8.1".into()),
            vec!["169.254.1.1".into()],
            None,
        ))
        .with_min_samples(3)
    }

    fn slow_dns() -> DnsObs {
        DnsObs {
            resolver: "169.254.1.1".into(),
            rtt_p50_ms: Some(40.0),
            rtt_p95_ms: Some(48.0),
            failure_rate_pct: 0.0,
            truncation_rate_pct: 5.2,
            queries: 38,
            failed: 0,
            truncated: 2,
            alt_resolver: Some("192.168.8.1".into()),
            alt_rtt_ms: Some(1.4),
            icmp_rtt_ms: Some(0.1),
            cached_rtt_ms: Some(0.9),
            window_secs: 180,
            cross: None,
        }
    }

    fn obs_with_dns(dns: DnsObs) -> Observations {
        Observations {
            now: "2026-09-03 06:51:19".into(),
            dns: Some(dns),
            ..Default::default()
        }
    }

    fn rules_of(found: &[Detection]) -> Vec<&str> {
        found.iter().map(|d| d.rule).collect()
    }

    #[test]
    fn truncation_fires_on_a_tc_rate_over_the_floor_and_needs_a_sample_size() {
        let mut dns = slow_dns();
        dns.rtt_p50_ms = Some(1.0);
        dns.truncation_rate_pct = 25.0;
        dns.queries = 40;
        dns.truncated = 10;
        let found = detect(&obs_with_dns(dns.clone()), &store(), &Thresholds::default());
        assert!(
            rules_of(&found).contains(&"dns.truncation_retry"),
            "{:?}",
            rules_of(&found)
        );

        dns.queries = 4;
        let found = detect(&obs_with_dns(dns), &store(), &Thresholds::default());
        assert!(
            !rules_of(&found).contains(&"dns.truncation_retry"),
            "four replies is not a rate"
        );
    }

    #[test]
    fn hijack_fires_on_a_private_answer_at_once_and_on_disagreement_only_with_history() {
        let mut dns = slow_dns();
        dns.rtt_p50_ms = Some(1.0);
        let cross = |private: bool, mismatch_pct: f64, cycles: u32| DnsCross {
            name: "dns.google".into(),
            local: vec!["10.0.0.1".into()],
            reference_resolver: "1.1.1.1".into(),
            reference: vec!["8.8.8.8".into()],
            validated: true,
            private_answer: private,
            mismatch_pct,
            cycles,
        };
        dns.cross = Some(cross(true, 100.0, 1));
        let found = detect(&obs_with_dns(dns.clone()), &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "dns.hijack_suspect")
            .expect("portal answer");
        assert_eq!(
            d.causes[0].label,
            "a captive portal or interceptor answering for every name"
        );

        dns.cross = Some(cross(false, 100.0, 1));
        let found = detect(&obs_with_dns(dns.clone()), &store(), &Thresholds::default());
        assert!(
            !rules_of(&found).contains(&"dns.hijack_suspect"),
            "one cycle is not a pattern"
        );

        dns.cross = Some(cross(false, 100.0, 5));
        let found = detect(&obs_with_dns(dns.clone()), &store(), &Thresholds::default());
        assert!(rules_of(&found).contains(&"dns.hijack_suspect"));

        dns.cross = Some(cross(false, 0.0, 50));
        let found = detect(&obs_with_dns(dns), &store(), &Thresholds::default());
        assert!(
            !rules_of(&found).contains(&"dns.hijack_suspect"),
            "agreement is not a finding"
        );
    }

    #[test]
    fn weak_wifi_fires_on_signal_or_retries_and_only_on_wireless() {
        let iface = |wireless: bool, signal: Option<i32>, retry: Option<f64>| IfaceObs {
            counter_window_secs: None,
            name: "wlan0".into(),
            carrier: Some(true),
            rx_errors: 0,
            tx_errors: 0,
            rx_dropped: 0,
            tx_dropped: 0,
            errors_per_min: 0,
            drops_per_min: Some(0),
            link_rate_bps: None,
            wireless: Some(wireless),
            signal_dbm: signal,
            tx_retry_pct: retry,
            rx_bps: 0.0,
            tx_bps: 0.0,
        };
        let obs = |i: IfaceObs| Observations {
            now: "2026-09-03 06:51:19".into(),
            iface: Some(i),
            ..Default::default()
        };
        let t = Thresholds::default();
        let fires =
            |i: IfaceObs| rules_of(&detect(&obs(i), &store(), &t)).contains(&"wifi.weak_signal");
        assert!(fires(iface(true, Some(-75), Some(2.0))), "weak signal");
        assert!(
            fires(iface(true, Some(-50), Some(35.0))),
            "retries with a fine signal"
        );
        assert!(!fires(iface(true, Some(-50), Some(2.0))), "healthy");
        assert!(!fires(iface(true, None, None)), "no wireless statistics");
        assert!(!fires(iface(false, Some(-90), Some(90.0))), "not wireless");
    }

    /// A weak signal on a radio that sent too little for a retry share. The
    /// retry counter exists, so the not-run reason must not deny it.
    #[test]
    fn an_idle_radio_is_not_read_as_having_no_retry_counter() {
        let obs = Observations {
            iface: Some(IfaceObs {
                name: "wlan0".into(),
                link_rate_bps: None,
                wireless: Some(true),
                signal_dbm: Some(-80),
                tx_retry_pct: None,
                ..eth0()
            }),
            ..Default::default()
        };
        let d = detect(&obs, &store(), &Thresholds::default())
            .into_iter()
            .find(|d| d.rule == "wifi.weak_signal")
            .expect("a weak signal fires");
        let retries = d
            .causes
            .iter()
            .flat_map(|c| &c.checks)
            .find(|c| c.id == "retries_high")
            .unwrap();
        assert_eq!(retries.why_not, Some(Availability::NotMeasured));
        assert!(retries.detail.contains("frames sent"), "{}", retries.detail);
    }

    #[test]
    fn symmetric_nat_fires_only_when_the_mapping_differs() {
        let obs = |symmetric: bool| Observations {
            now: "2026-09-03 06:51:19".into(),
            nat: Some(NatObs {
                mappings: vec![
                    ("stun.a".into(), "203.0.113.9:51234".into()),
                    (
                        "stun.b".into(),
                        if symmetric {
                            "203.0.113.9:51240"
                        } else {
                            "203.0.113.9:51234"
                        }
                        .into(),
                    ),
                ],
                symmetric,
            }),
            ..Default::default()
        };
        let t = Thresholds::default();
        assert!(rules_of(&detect(&obs(true), &store(), &t)).contains(&"nat.symmetric"));
        assert!(!rules_of(&detect(&obs(false), &store(), &t)).contains(&"nat.symmetric"));
    }

    #[test]
    fn slow_resolver_fires_and_ranks_the_forwarder_first() {
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let obs = obs_with_dns(slow_dns());

        let found = detect(&obs, &base, &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "dns.slow_resolver")
            .expect("dns.slow_resolver should fire");

        assert_eq!(
            d.severity,
            Severity::High,
            "33× baseline is a high, not a medium"
        );
        let ev = &d.evidence[0];
        assert_eq!(ev.multiple_label().unwrap(), "33× baseline");

        let mut causes = d.causes.clone();
        causes.sort_by(|a, b| b.score().partial_cmp(&a.score()).unwrap());
        assert!(
            causes[0].label.contains("upstream forwarder"),
            "expected the forwarder cause on top, got {:?}",
            causes[0].label
        );
        assert_eq!(
            causes[0].confidence(),
            super::super::issue::Confidence::Strong
        );
    }

    #[test]
    fn a_slow_alt_resolver_moves_the_blame_local() {
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let mut dns = slow_dns();
        dns.alt_rtt_ms = Some(38.0); // the alternate is slow too
        dns.cached_rtt_ms = Some(37.0);
        let obs = obs_with_dns(dns);

        let found = detect(&obs, &base, &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "dns.slow_resolver")
            .unwrap();
        let mut causes = d.causes.clone();
        causes.sort_by(|a, b| b.score().partial_cmp(&a.score()).unwrap());
        assert!(
            causes[0].label.contains("local"),
            "both resolvers slow should point local, got {:?}",
            causes[0].label
        );
        // Pointing local is as far as it goes: no local drop counter is read.
        assert_eq!(
            causes[0].confidence(),
            super::super::issue::Confidence::Likely
        );
    }

    /// A Wi-Fi laptop behind a resolver at 33× its baseline. The report's
    /// scenario is one drop a minute and no alternate probed, which live is
    /// always.
    fn laptop_with_a_slow_resolver(alt_rtt_ms: Option<f64>, drops_per_min: u64) -> Observations {
        Observations {
            iface: Some(IfaceObs {
                name: "wlan0".into(),
                wireless: Some(true),
                link_rate_bps: None,
                drops_per_min: Some(drops_per_min),
                ..eth0()
            }),
            ..obs_with_dns(DnsObs {
                alt_rtt_ms,
                ..slow_dns()
            })
        }
    }

    fn local_udp_path(obs: &Observations) -> (Cause, Vec<Cause>) {
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let found = detect(obs, &base, &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "dns.slow_resolver")
            .expect("dns.slow_resolver should fire");
        let (mut local, others): (Vec<Cause>, _) = d
            .causes
            .iter()
            .cloned()
            .partition(|c| c.id == "local_udp_path");
        (local.remove(0), others)
    }

    #[test]
    fn one_dropped_multicast_frame_a_minute_is_not_a_local_udp_fault() {
        use super::super::issue::Confidence;
        let (local, others) = local_udp_path(&laptop_with_a_slow_resolver(None, 1));
        assert!(
            local.confidence() <= Confidence::Weak,
            "{} on {}",
            local.confidence().label(),
            local.checks_label()
        );
        // The engine ranks by confidence first, so a cause above it on
        // confidence keeps it off the top.
        assert!(
            others.iter().any(|c| c.confidence() > local.confidence()),
            "local_udp_path ranks top: {:?}",
            others
                .iter()
                .map(|c| (c.id.clone(), c.confidence()))
                .collect::<Vec<_>>()
        );
        let check = |id| local.checks.iter().find(|c| c.id == id).unwrap();
        assert_eq!(
            check("alt_resolver_over_the_same_path_is_also_slow").why_not,
            Some(Availability::NotMeasured)
        );
        assert_eq!(check("interface_drops").passed, Some(false));
    }

    #[test]
    fn local_udp_path_is_never_strong_without_a_local_counter() {
        // Everything the rule can see points local: the alternate is as slow
        // over the same path, and the interface drops twice the floor.
        let (local, _) = local_udp_path(&laptop_with_a_slow_resolver(Some(38.0), 120));
        assert_eq!(local.score(), Some(1.0), "{}", local.checks_label());
        assert_eq!(local.confidence(), super::super::issue::Confidence::Likely);
        assert_eq!(
            local.missing_discriminator().map(|c| c.id.as_str()),
            Some("local_drop_counters")
        );
    }

    fn local_udp_check(alt_rtt_ms: Option<f64>, drops_per_min: u64, id: &str) -> CheckResult {
        let (local, _) = local_udp_path(&laptop_with_a_slow_resolver(alt_rtt_ms, drops_per_min));
        local.checks.into_iter().find(|c| c.id == id).unwrap()
    }

    #[test]
    fn interface_drops_is_unsupported_without_drop_counters() {
        let mut obs = laptop_with_a_slow_resolver(None, 0);
        obs.iface.as_mut().unwrap().drops_per_min = None;
        let (local, _) = local_udp_path(&obs);
        let c = local
            .checks
            .iter()
            .find(|c| c.id == "interface_drops")
            .unwrap();
        assert_eq!(c.why_not, Some(Availability::Unsupported));
    }

    #[test]
    fn the_alternate_is_also_slow_at_half_the_median() {
        // The median is 40ms, so the line is 20ms.
        let c = local_udp_check(
            Some(20.0),
            120,
            "alt_resolver_over_the_same_path_is_also_slow",
        );
        assert_eq!(c.passed, Some(true), "{}", c.detail);
    }

    #[test]
    fn the_alternate_is_not_also_slow_below_half_the_median() {
        let c = local_udp_check(
            Some(19.9),
            120,
            "alt_resolver_over_the_same_path_is_also_slow",
        );
        assert_eq!(c.passed, Some(false), "{}", c.detail);
        // An alternate far under the line says the path is fine.
        let c = local_udp_check(
            Some(1.4),
            120,
            "alt_resolver_over_the_same_path_is_also_slow",
        );
        assert_eq!(c.passed, Some(false));
        assert_eq!(
            c.detail,
            "the alternate answered in 1.4ms over the same path"
        );
    }

    #[test]
    fn local_udp_interface_drops_pass_at_the_drop_floor() {
        let c = local_udp_check(Some(38.0), 60, "interface_drops");
        assert_eq!(c.passed, Some(true), "{}", c.detail);
    }

    #[test]
    fn local_udp_interface_drops_fail_below_the_drop_floor() {
        let c = local_udp_check(Some(38.0), 59, "interface_drops");
        assert_eq!(c.passed, Some(false));
        assert_eq!(c.detail, "59 drops a minute, under the 60/min floor");
    }

    #[test]
    fn dns_does_not_fire_on_a_normal_resolver() {
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let mut dns = slow_dns();
        dns.rtt_p50_ms = Some(1.3);
        let obs = obs_with_dns(dns);
        assert!(detect(&obs, &base, &Thresholds::default()).is_empty());
    }

    #[test]
    fn an_ordinary_resolver_does_not_trip_the_ceiling_on_a_first_run() {
        // No baseline and a 40ms median: an ISP or mobile resolver on day
        // one. The old 20ms ceiling opened a finding here on every such
        // network; the rule now waits for a baseline to say what slow is.
        let base = store();
        let obs = obs_with_dns(slow_dns());
        let found = detect(&obs, &base, &Thresholds::default());
        assert!(
            !found.iter().any(|d| d.rule == "dns.slow_resolver"),
            "40ms with no baseline is not a finding"
        );
    }

    #[test]
    fn a_failing_resolver_with_no_icmp_probe_does_not_claim_it_is_down() {
        let mut dns = slow_dns();
        dns.failure_rate_pct = 40.0;
        dns.failed = 15;
        dns.icmp_rtt_ms = None; // the live path never runs this probe
        let found = detect(&obs_with_dns(dns), &store(), &Thresholds::default());
        let d = found.iter().find(|d| d.rule == "dns.failing").unwrap();
        assert!(
            d.causes
                .iter()
                .all(|c| c.confidence() != super::super::issue::Confidence::Strong),
            "an unrun icmp probe was read as evidence: {:?}",
            d.causes
                .iter()
                .map(|c| (c.label.clone(), c.confidence()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_absolute_ceiling_fires_without_any_baseline() {
        // First run on a new network: no baseline at all, but a 160ms median
        // is worth saying out loud anywhere. 40ms is not — that is an
        // ordinary ISP or mobile resolver — which is why the ceiling sits at
        // 100ms and the baseline test carries everything below it.
        let base = store();
        let mut dns = slow_dns();
        dns.rtt_p50_ms = Some(160.0);
        dns.rtt_p95_ms = Some(190.0);
        let obs = obs_with_dns(dns);
        let found = detect(&obs, &base, &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "dns.slow_resolver")
            .unwrap();
        assert_eq!(
            d.severity,
            Severity::Medium,
            "no baseline means no multiple, so no escalation"
        );
        assert!(d.evidence[0].baseline.is_none());
        assert!(d.evidence[0].multiple_label().is_none());
    }

    /// `dns.slow_resolver` for a LAN resolver that answers in 1.2ms, give or
    /// take 0.05, once its p50 moves to `p50`.
    fn lan_resolver_at(p50: f64, t: &Thresholds) -> Option<Detection> {
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.05, 2_000);
        let mut dns = slow_dns();
        dns.rtt_p50_ms = Some(p50);
        detect(&obs_with_dns(dns), &base, t)
            .into_iter()
            .find(|d| d.rule == "dns.slow_resolver")
    }

    #[test]
    fn a_flat_resolver_baseline_is_judged_against_the_floor() {
        // 1.2ms with σ 0.05: raw, 1.5ms is 6σ; against the 0.5ms floor it is
        // 0.6σ, and 3ms is 3.6σ. The delta floors are off: they keep all of
        // these quiet, and this is about the σ.
        let slow = lan_resolver_at;
        let t = Thresholds {
            dns_delta_floor_ms: 0.0,
            dns_delta_multiple: 0.0,
            ..Thresholds::default()
        };
        assert!(slow(1.5, &t).is_none());
        let unfloored = Thresholds {
            sigma_floor_ms: 0.0,
            sigma_floor_pct: 0.0,
            ..t
        };
        assert!(slow(1.5, &unfloored).is_some());

        let d = slow(3.0, &t).expect("3.6σ against the floor");
        // The evidence carries the σ the resolver was judged against.
        assert_eq!(d.evidence[0].sigma, Some(0.5));
        assert!((d.evidence[0].sigma_above().unwrap() - 3.6).abs() < 1e-9);
    }

    #[test]
    fn a_lan_resolver_moving_from_1_2_to_2_7ms_does_not_fire() {
        // 2.7ms is 3σ over the 0.5ms floor and 2.25 times the mean, and
        // the σ floor alone reported it. It is 1.5ms slower.
        let t = Thresholds::default();
        assert!(lan_resolver_at(2.7, &t).is_none());
        let no_delta = Thresholds {
            dns_delta_floor_ms: 0.0,
            ..t
        };
        assert!(
            lan_resolver_at(2.7, &no_delta).is_some(),
            "only the 5ms floor holds it back"
        );
    }

    #[test]
    fn a_lan_resolver_moving_from_1_2_to_7ms_fires() {
        let t = Thresholds::default();
        let d = lan_resolver_at(7.0, &t).expect("5.8ms slower, 5.8 times the mean, 11.6σ");
        assert_eq!(d.evidence[0].value, 7.0);
        assert_eq!(d.evidence[0].baseline, Some(1.2));
        // 4.9ms slower is still under the floor.
        assert!(lan_resolver_at(6.1, &t).is_none());
    }

    #[test]
    fn a_resolver_with_a_high_baseline_opens_at_twice_its_mean() {
        // 30ms, give or take 1: the floor is 5% of the mean, so 3σ is
        // 34.5ms, and 5ms slower is 35ms. A resolver that normally takes 30ms
        // is not slow at 40.
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 30.0, 1.0, 2_000);
        let slow = |p50: f64| {
            let mut dns = slow_dns();
            dns.rtt_p50_ms = Some(p50);
            rules_of(&detect(&obs_with_dns(dns), &base, &Thresholds::default()))
                .contains(&"dns.slow_resolver")
        };
        assert!(!slow(40.0));
        assert!(!slow(59.0));
        assert!(slow(60.0));
    }

    #[test]
    fn the_ceiling_fires_on_a_resolver_whose_baseline_would_not() {
        // 80ms, give or take 5: the baseline opens at twice the mean, 160ms,
        // so from a mean of 50ms up the 100ms ceiling is the only way this
        // rule opens. It must not wait for the baseline to agree.
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 80.0, 5.0, 2_000);
        let t = Thresholds::default();
        let b = base.get("169.254.1.1", "dns.rtt_p50").unwrap();
        assert_eq!(dns_open_line(b, &t), Some(160.0));
        let slow = |p50: f64| {
            let mut dns = slow_dns();
            dns.rtt_p50_ms = Some(p50);
            detect(&obs_with_dns(dns), &base, &t)
                .into_iter()
                .find(|d| d.rule == "dns.slow_resolver")
        };
        assert!(slow(100.0).is_none(), "the ceiling is exclusive");
        let d = slow(120.0).expect("120ms is over the 100ms ceiling");
        assert_eq!(d.evidence[0].value, 120.0);
        assert_eq!(d.evidence[0].baseline, Some(80.0));
        assert_eq!(d.severity, Severity::Medium, "1.5 times the mean");
    }

    #[test]
    fn the_dns_open_line_is_the_highest_of_its_three_tests() {
        let t = Thresholds::default();
        let line = |mean: f64, sigma: f64| {
            let mut base = store();
            base.seed("169.254.1.1", "dns.rtt_p50", mean, sigma, 2_000);
            dns_open_line(base.get("169.254.1.1", "dns.rtt_p50").unwrap(), &t)
        };
        // Each of the three can be the one that sets it.
        assert_eq!(line(1.2, 0.05), Some(6.2), "5ms above the mean");
        assert_eq!(line(30.0, 1.0), Some(60.0), "twice the mean");
        assert_eq!(line(10.0, 4.0), Some(22.0), "3σ above the mean");
        // With both σ floors at 0 a baseline that never varied cannot be
        // scored, as `sigma_above` cannot score it.
        let unfloored = Thresholds {
            sigma_floor_ms: 0.0,
            sigma_floor_pct: 0.0,
            ..t
        };
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.0, 2_000);
        let flat = base.get("169.254.1.1", "dns.rtt_p50").unwrap();
        assert_eq!(dns_open_line(flat, &unfloored), None);
    }

    #[test]
    fn the_verify_line_sits_below_the_open_line() {
        // The line `dns.slow_resolver` closes on, for a p50 that opens it
        // against a baseline of (mean, σ), or none.
        let close_line = |baseline: Option<(f64, f64)>, p50: f64, t: &Thresholds| {
            let mut base = store();
            if let Some((mean, sigma)) = baseline {
                base.seed("169.254.1.1", "dns.rtt_p50", mean, sigma, 2_000);
            }
            let mut dns = slow_dns();
            dns.rtt_p50_ms = Some(p50);
            let d = detect(&obs_with_dns(dns), &base, t)
                .into_iter()
                .find(|d| d.rule == "dns.slow_resolver")
                .unwrap_or_else(|| panic!("{p50}ms against {baseline:?} should open"));
            assert_eq!(d.verify.metric, "dns.rtt_p50");
            assert_eq!(d.verify.hold_secs, 60);
            d.verify.threshold
        };
        let t = Thresholds::default();
        // (baseline, the p50 that opens, the line it opened on, the close line)
        for (baseline, p50, open, close) in [
            // A router at 10.5ms opens at twice its mean. The flat 5ms this
            // replaces was under anything it ever answers in.
            (Some((10.5, 0.3)), 60.0, 21.0, 16.8),
            // Over the ceiling too, but the baseline's line is the lower of
            // the two it crossed: the issue opened there, not at 100ms.
            (Some((10.5, 0.3)), 150.0, 21.0, 16.8),
            // A LAN resolver opens 5ms above its mean.
            (Some((1.2, 0.05)), 7.0, 6.2, 4.96),
            // A noisy one: 2σ above its mean is over 0.8 of its line, 17.6ms,
            // and a close line inside its normal range would never hold.
            (Some((10.0, 4.0)), 25.0, 22.0, 18.0),
            // Twice an 80ms mean is 160ms, so the ceiling opens it.
            (Some((80.0, 5.0)), 120.0, 100.0, 90.0),
            // No baseline: 0.8 of the ceiling.
            (None, 160.0, 100.0, 80.0),
        ] {
            let line = close_line(baseline, p50, &t);
            assert!(
                (line - close).abs() < 1e-9,
                "{baseline:?} at {p50}ms closes under {line}, not {close}"
            );
            assert!(line < open, "{baseline:?}: {line} is not below {open}");
        }
        // The exception: a resolver whose normal range reaches the ceiling.
        // Its mean plus 2σ, 110ms, is over the 100ms it opened on, so it
        // closes once its p50 has stayed under the ceiling for the hold.
        let line = close_line(Some((90.0, 10.0)), 120.0, &t);
        assert!((line - 110.0).abs() < 1e-9, "{line}");
        assert!(line > t.dns_ceiling_ms);

        // The catalogue's line is the one with no baseline.
        let catalogued = rules::default_verify("dns.slow_resolver").unwrap();
        assert_eq!(catalogued.threshold, close_line(None, 160.0, &t));
        // A configured ceiling moves it.
        let low = Thresholds {
            dns_ceiling_ms: 30.0,
            ..t
        };
        assert!((close_line(None, 40.0, &low) - 24.0).abs() < 1e-9);
    }

    #[test]
    fn a_gateway_moving_2_to_9ms_does_not_fire_but_2_to_15ms_does() {
        // A wired gateway at 2ms, give or take 0.3: 9ms is 14σ over the
        // floor but 7ms slower; 15ms is 13ms slower.
        let mut base = store();
        base.seed("192.168.8.1", "gateway.rtt", 2.0, 0.3, 2_000);
        let spike = |rtt: f64, t: &Thresholds| {
            let obs = Observations {
                gateway: Some(GatewayObs {
                    addr: Some("192.168.8.1".into()),
                    rtt_ms: Some(rtt),
                    loss_pct: 0.0,
                    arp_ok: Some(true),
                    icmp_ok: true,
                    internet_reachable: Some(true),
                }),
                ..Default::default()
            };
            rules_of(&detect(&obs, &base, t)).contains(&"gateway.rtt_spike")
        };
        let t = Thresholds::default();
        assert!(!spike(9.0, &t));
        assert!(spike(15.0, &t));
        let no_delta = Thresholds {
            gateway_delta_floor_ms: 0.0,
            ..t
        };
        assert!(spike(9.0, &no_delta), "only the 10ms floor holds it back");
    }

    #[test]
    fn a_lowered_dns_ceiling_fires_where_the_default_does_not() {
        // A 40ms resolver on a first run, with no baseline: under the 100ms
        // default it is ordinary, under a configured 30ms ceiling it is slow.
        let obs = obs_with_dns(slow_dns());
        let found = detect(&obs, &store(), &Thresholds::default());
        assert!(!rules_of(&found).contains(&"dns.slow_resolver"));

        let t = Thresholds {
            dns_ceiling_ms: 30.0,
            ..Thresholds::default()
        };
        let found = detect(&obs, &store(), &t);
        let d = found
            .iter()
            .find(|d| d.rule == "dns.slow_resolver")
            .expect("40ms is over a 30ms ceiling");
        assert_eq!(d.evidence[0].value, 40.0);
        assert!(d.evidence[0].baseline.is_none());
    }

    #[test]
    fn an_invalid_threshold_falls_back_to_its_default() {
        let default = Thresholds::default();
        assert_eq!(default.validated(), (default, vec![]));

        let (t, warnings) = Thresholds {
            sigma_k: 0.0,
            sigma_close_k: f64::NAN,
            sigma_floor_ms: -0.5,
            gateway_delta_floor_ms: -10.0,
            consecutive_n: 0,
            saturation_pct: 150.0,
            dns_tc_pct: -1.0,
            dns_ceiling_ms: f64::NAN,
            // TOML reads `inf`, a natural way to switch a rule off, but an
            // episode that embeds it would not load again.
            loaded_rtt_delta_ms: f64::INFINITY,
            iface_drop_floor: f64::NEG_INFINITY,
            // Valid values that are not the defaults are kept, the edges
            // of a share included.
            sigma_floor_pct: 0.0,
            dns_delta_floor_ms: 0.0,
            dns_delta_multiple: 0.0,
            dns_mismatch_pct: 100.0,
            wifi_retry_pct: 0.0,
            wifi_rssi_dbm: -80.0,
            socket_rtt_ms: 0.0,
            ..default
        }
        .validated();
        assert_eq!(
            t,
            Thresholds {
                sigma_floor_pct: 0.0,
                dns_delta_floor_ms: 0.0,
                dns_delta_multiple: 0.0,
                dns_mismatch_pct: 100.0,
                wifi_retry_pct: 0.0,
                wifi_rssi_dbm: -80.0,
                socket_rtt_ms: 0.0,
                ..default
            }
        );
        assert_eq!(
            warnings,
            [
                "diagnose_thresholds.sigma_k = 0 must be a finite number above 0, so the default 3 is used",
                "diagnose_thresholds.sigma_close_k = NaN must be a finite number above 0, so the default 2 is used",
                "diagnose_thresholds.sigma_floor_ms = -0.5 must be a finite number of 0 or more, so the default 0.5 is used",
                "diagnose_thresholds.gateway_delta_floor_ms = -10 must be a finite number of 0 or more, so the default 10 is used",
                "diagnose_thresholds.dns_ceiling_ms = NaN must be a finite number, so the default 100 is used",
                "diagnose_thresholds.loaded_rtt_delta_ms = inf must be a finite number, so the default 100 is used",
                "diagnose_thresholds.saturation_pct = 150 must be within 0..=100, so the default 90 is used",
                "diagnose_thresholds.iface_drop_floor = -inf must be a finite number, so the default 60 is used",
                "diagnose_thresholds.dns_tc_pct = -1 must be within 0..=100, so the default 10 is used",
                "diagnose_thresholds.consecutive_n = 0 must be at least 1, so the default 3 is used",
            ]
        );

        let (t, warnings) = Thresholds {
            sigma_k: f64::INFINITY,
            ..default
        }
        .validated();
        assert_eq!(t, default);
        assert_eq!(
            warnings,
            ["diagnose_thresholds.sigma_k = inf must be a finite number above 0, so the default 3 is used"]
        );
    }

    #[test]
    fn a_close_line_at_or_above_the_open_line_is_refused() {
        let default = Thresholds::default();
        let (t, warnings) = Thresholds {
            sigma_close_k: 3.0,
            ..default
        }
        .validated();
        assert_eq!(t, default);
        assert_eq!(
            warnings,
            ["diagnose_thresholds.sigma_close_k = 3 must be below sigma_k = 3, so the default 2 is used"]
        );

        // A sigma_k lowered below the default close line takes the close
        // line down with it, in the defaults' proportion.
        let (t, warnings) = Thresholds {
            sigma_k: 1.5,
            ..default
        }
        .validated();
        assert_eq!((t.sigma_k, t.sigma_close_k), (1.5, 1.0));
        assert_eq!(
            warnings,
            ["diagnose_thresholds.sigma_close_k = 2 must be below sigma_k = 1.5, so 1, two thirds of it, is used"]
        );

        // The warning rounds what it reports; the value is not rounded.
        let (t, warnings) = Thresholds {
            sigma_k: 2.0,
            ..default
        }
        .validated();
        assert_eq!(t.sigma_close_k, 2.0 * 2.0 / 3.0);
        assert_eq!(
            warnings,
            ["diagnose_thresholds.sigma_close_k = 2 must be below sigma_k = 2, so 1.33, two thirds of it, is used"]
        );

        // Any line below the open one stands.
        let (t, warnings) = Thresholds {
            sigma_k: 4.0,
            sigma_close_k: 3.5,
            ..default
        }
        .validated();
        assert_eq!((t.sigma_k, t.sigma_close_k), (4.0, 3.5));
        assert!(warnings.is_empty());
    }

    #[test]
    fn failing_dns_replaces_slow_dns_rather_than_joining_it() {
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let mut dns = slow_dns();
        dns.failure_rate_pct = 40.0;
        dns.failed = 15;
        let found = detect(&obs_with_dns(dns), &base, &Thresholds::default());
        assert!(found.iter().any(|d| d.rule == "dns.failing"));
        assert!(
            !found.iter().any(|d| d.rule == "dns.slow_resolver"),
            "a resolver that isn't answering shouldn't also be reported as slow"
        );
    }

    // ------------------------------------------------------------ sockets

    fn bloated_socket() -> SocketObs {
        SocketObs {
            local: "10.88.0.2:52344".into(),
            remote: "10.88.0.3:9000".into(),
            process: Some("ncat".into()),
            rtt_ms: Some(184.0),
            rttvar_ms: Some(40.0),
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

    #[test]
    fn classifies_a_bloated_socket() {
        assert_eq!(
            classify_socket(&bloated_socket(), &Thresholds::default()),
            SocketVerdict::Bufferbloat
        );
    }

    #[test]
    fn a_zero_window_beats_every_other_verdict() {
        let mut s = bloated_socket();
        s.rwnd = Some(0);
        assert_eq!(
            classify_socket(&s, &Thresholds::default()),
            SocketVerdict::ZeroWindow
        );
    }

    #[test]
    fn an_idle_socket_with_a_distant_peer_is_not_bloated() {
        let mut s = bloated_socket();
        s.tx_bps = Some(0.0);
        s.rx_bps = Some(0.0);
        s.retrans = Some(0);
        assert_eq!(
            classify_socket(&s, &Thresholds::default()),
            SocketVerdict::AppLimited,
            "high rtt with nothing in flight is just distance"
        );
    }

    /// Review R4: a socket that no connection row matched has unknown rates.
    /// That is neither the traffic a bloated queue needs nor the silence of
    /// an idle socket.
    #[test]
    fn unknown_rates_are_neither_sending_nor_idle() {
        let mut s = bloated_socket();
        s.tx_bps = None;
        s.rx_bps = None;
        s.retrans = Some(0);
        assert_eq!(
            classify_socket(&s, &Thresholds::default()),
            SocketVerdict::Ok
        );
        s.rx_bps = Some(0.0);
        assert_eq!(
            classify_socket(&s, &Thresholds::default()),
            SocketVerdict::Ok,
            "one rate measured at zero is not an idle socket"
        );
    }

    #[test]
    fn a_receiver_that_stops_reading_is_receiver_limited() {
        let mut s = bloated_socket();
        s.rtt_ms = Some(12.0);
        s.retrans = Some(0);
        s.cwnd = Some(100); // 100 × 1448 = 144KB against a 32KB window
        s.rwnd = Some(32_000);
        assert_eq!(
            classify_socket(&s, &Thresholds::default()),
            SocketVerdict::ReceiverLimited
        );
    }

    #[test]
    fn an_unplaced_socket_queue_is_information_not_a_finding() {
        // Only the loaded-rtt test can say which end is queueing. Until it
        // runs, "rtt is high while this socket sends" is something to test,
        // not a fault to report at Medium — a distant peer looks identical.
        let obs = Observations {
            sockets: vec![bloated_socket()],
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "tcp.bufferbloat_remote")
            .expect("the socket rule still fires");
        assert_eq!(d.severity, Severity::Info);
        assert_eq!(d.title, "socket queueing, side unmeasured");
    }

    #[test]
    fn a_verdict_must_persist_before_it_becomes_an_issue() {
        let mut s = bloated_socket();
        s.verdict_age_secs = 5;
        let obs = Observations {
            sockets: vec![s.clone()],
            ..Default::default()
        };
        assert!(
            detect(&obs, &store(), &Thresholds::default()).is_empty(),
            "a 5-second-old verdict is a transient, not a finding"
        );

        s.verdict_age_secs = 45;
        let obs = Observations {
            sockets: vec![s],
            ..Default::default()
        };
        assert_eq!(detect(&obs, &store(), &Thresholds::default()).len(), 1);
    }

    /// A socket losing segments on an ordinary path: rtt well under the
    /// queueing line, so only the retransmit count can classify it.
    fn retransmitting_socket(retrans: u32) -> SocketObs {
        SocketObs {
            rtt_ms: Some(20.0),
            rttvar_ms: Some(4.0),
            retrans: Some(retrans),
            ..bloated_socket()
        }
    }

    #[test]
    fn retrans_burst_fires_at_five_a_minute() {
        let obs = Observations {
            sockets: vec![retransmitting_socket(5)],
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        assert_eq!(rules_of(&found), ["tcp.retrans_burst"]);
        let d = &found[0];
        assert_eq!(d.evidence[0].metric, "tcp.retrans_rate");
        assert_eq!(d.evidence[0].value, 5.0);
    }

    #[test]
    fn retrans_burst_is_quiet_below_five() {
        let obs = Observations {
            sockets: vec![retransmitting_socket(4)],
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        assert!(
            !rules_of(&found).contains(&"tcp.retrans_burst"),
            "4 retransmits a minute is under the burst line: {:?}",
            rules_of(&found)
        );
    }

    #[test]
    fn a_socket_without_rtt_is_never_bufferbloat() {
        // Sending hard with nothing retransmitted, so only the rtt the
        // verdict turns on is missing.
        let s = SocketObs {
            rtt_ms: None,
            rttvar_ms: None,
            retrans: Some(0),
            ..bloated_socket()
        };
        let t = Thresholds::default();
        assert_ne!(classify_socket(&s, &t), SocketVerdict::Bufferbloat);
        let obs = Observations {
            sockets: vec![s.clone()],
            ..Default::default()
        };
        let found = detect(&obs, &store(), &t);
        assert!(
            !rules_of(&found).contains(&"tcp.bufferbloat_remote"),
            "{:?}",
            rules_of(&found)
        );
        // Handed the verdict anyway, the detection refuses rather than
        // quoting an rtt of 0.
        assert!(socket_detection(&s, SocketVerdict::Bufferbloat, &obs, &t).is_none());
    }

    #[test]
    fn a_missing_rtt_is_not_read_as_0_under_a_0_ms_line() {
        // Under the default 100ms line an rtt read as 0 lands on the right
        // side of both tests by luck. A 0ms line takes the luck away: 0 >= 0
        // made the sender bloated and kept the retransmitter out of its burst.
        let t = Thresholds {
            socket_rtt_ms: 0.0,
            ..Thresholds::default()
        };
        let no_rtt = |retrans| SocketObs {
            rtt_ms: None,
            rttvar_ms: None,
            retrans: Some(retrans),
            ..bloated_socket()
        };
        assert_ne!(classify_socket(&no_rtt(0), &t), SocketVerdict::Bufferbloat);
        assert_eq!(
            classify_socket(&no_rtt(12), &t),
            SocketVerdict::RetransBurst
        );
    }

    #[test]
    fn retransmits_without_rtt_say_the_rtt_was_not_measured() {
        use super::super::issue::Confidence;
        let finding = |rtt_ms| {
            let obs = Observations {
                sockets: vec![SocketObs {
                    rtt_ms,
                    rttvar_ms: None,
                    ..retransmitting_socket(12)
                }],
                ..Default::default()
            };
            let mut found = detect(&obs, &store(), &Thresholds::default());
            assert_eq!(rules_of(&found), ["tcp.retrans_burst"]);
            found.remove(0)
        };
        let check = |d: &Detection| {
            d.causes[0]
                .checks
                .iter()
                .find(|c| c.id == "socket_rtt_below_queueing_line")
                .cloned()
                .unwrap()
        };

        // The retransmit count is measured, so the rule still fires; only
        // the check that rules a queue out is missing.
        let d = finding(None);
        let k = check(&d);
        assert_eq!(k.passed, None);
        assert_eq!(k.why_not, Some(Availability::NotMeasured));
        assert_eq!(d.causes[0].confidence(), Confidence::Likely);
        assert!(!d.evidence.iter().any(|e| e.metric == "tcp.socket_rtt"));

        let d = finding(Some(20.0));
        assert_eq!(check(&d).passed, Some(true));
        assert_eq!(d.causes[0].confidence(), Confidence::Strong);
    }

    #[test]
    fn retransmits_do_not_let_path_loss_tie_with_the_queue() {
        // 12 retransmits are consistent with both causes, so they must not
        // decide between them. Without a trace, path loss is untested and
        // ranks below the cause whose checks actually passed.
        let obs = Observations {
            sockets: vec![bloated_socket()],
            idle_rtt_ms: Some(12.0),
            loaded_rtt_ms: Some(18.0),
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "tcp.bufferbloat_remote")
            .unwrap();

        let queue = &d.causes[0];
        let loss = &d.causes[1];
        assert!(queue.label.contains("receiver is queueing"));
        assert_eq!(queue.confidence(), super::super::issue::Confidence::Strong);
        assert_eq!(
            loss.confidence(),
            super::super::issue::Confidence::Untested,
            "no trace means no verdict on path loss, not a strong one"
        );
        assert!(loss.checks[0].detail.contains("press t to run one"));
    }

    #[test]
    fn a_lossy_traced_path_does_support_the_loss_cause() {
        let mut hops = vec![
            hop(1, "192.168.8.1", "-", 1.0),
            hop(2, "100.64.0.1", "as7545", 8.0),
        ];
        hops[1].loss_pct = 30.0;
        let obs = Observations {
            sockets: vec![bloated_socket()],
            paths: vec![PathObs {
                destination_reached: Some(true),
                target: "10.88.0.3".into(),
                hops,
                previous: None,
                traced_at: "now".into(),
            }],
            idle_rtt_ms: Some(12.0),
            loaded_rtt_ms: Some(18.0),
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "tcp.bufferbloat_remote")
            .unwrap();
        let loss = d
            .causes
            .iter()
            .find(|c| c.label.contains("loss on the path"))
            .unwrap();
        assert_eq!(loss.confidence(), super::super::issue::Confidence::Strong);
    }

    #[test]
    fn remote_bufferbloat_needs_the_local_test_to_have_passed() {
        let obs = Observations {
            sockets: vec![bloated_socket()],
            idle_rtt_ms: Some(12.0),
            loaded_rtt_ms: Some(18.0), // our uplink is fine
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "tcp.bufferbloat_remote")
            .unwrap();
        assert_eq!(
            d.causes[0].confidence(),
            super::super::issue::Confidence::Strong
        );
        assert!(!found.iter().any(|d| d.rule == "tcp.bufferbloat_local"));
    }

    #[test]
    fn without_a_loaded_rtt_test_the_queue_is_not_placed_on_the_receiver() {
        // A stable distant peer looks exactly like this: high rtt while the
        // socket sends. Calling it receiver-side bufferbloat, and telling the
        // operator to go and ask the peer's owner for fq_codel, needs the
        // loaded/idle comparison that has not run here.
        let obs = Observations {
            sockets: vec![bloated_socket()],
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "tcp.bufferbloat_remote")
            .expect("the socket is still worth surfacing");
        assert!(
            d.causes.iter().all(|c| c.id != "receiver_queueing"),
            "no measurement placed the queue at the receiver"
        );
        let queue = d
            .causes
            .iter()
            .find(|c| c.id == "unlocalised_queueing")
            .expect("the unlocalised cause takes its place");
        assert_ne!(queue.confidence(), super::super::issue::Confidence::Strong);
        assert!(queue.sufficient_evidence().is_empty());
        assert!(
            d.remediation
                .iter()
                .any(|s| s.text.contains("loaded-rtt test")),
            "the useful next move is the test that would localise it"
        );
        assert!(d.remediation.iter().all(|s| !s.text.contains("peer")));
        assert_eq!(
            d.title, "socket queueing, side unmeasured",
            "the headline is the line a copied summary carries, so it cannot \
             name a side either"
        );
    }

    #[test]
    fn a_bloated_uplink_opens_the_local_issue_too() {
        let obs = Observations {
            sockets: vec![bloated_socket()],
            idle_rtt_ms: Some(12.0),
            loaded_rtt_ms: Some(320.0),
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        assert!(found.iter().any(|d| d.rule == "tcp.bufferbloat_local"));
        // And the remote cause's discriminating check now fails.
        let remote = found
            .iter()
            .find(|d| d.rule == "tcp.bufferbloat_remote")
            .unwrap();
        assert_ne!(
            remote.causes[0].confidence(),
            super::super::issue::Confidence::Strong
        );
    }

    // ------------------------------------------------------------ gateway

    fn dead_gateway() -> GatewayObs {
        GatewayObs {
            addr: Some("192.168.8.1".into()),
            rtt_ms: None,
            loss_pct: 100.0,
            arp_ok: Some(false),
            icmp_ok: false,
            internet_reachable: Some(false),
        }
    }

    #[test]
    fn a_gateway_that_ignores_icmp_is_not_reported_as_unreachable() {
        // The single most damaging false positive available: a `critical`
        // that suppresses every other finding, raised because an
        // unprivileged netwatch could not ping a router that is working.
        let obs = Observations {
            gateway: Some(GatewayObs {
                internet_reachable: Some(true),
                ..dead_gateway()
            }),
            ..Default::default()
        };
        assert!(
            detect(&obs, &store(), &Thresholds::default()).is_empty(),
            "the internet answered through this gateway — it is plainly up"
        );
    }

    #[test]
    fn an_unprobed_arp_is_never_rendered_as_a_failed_arp() {
        // netwatch sends no ARP of its own, so `arp_ok` is `None` on every
        // live host. It used to mirror the ICMP result, which made both
        // checks assert a probe that never ran — worst on an unprivileged
        // run, where ICMP cannot be sent either.
        let obs = Observations {
            gateway: Some(GatewayObs {
                arp_ok: None,
                ..dead_gateway()
            }),
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "gateway.unreachable")
            .expect("nothing answers anywhere — still a real outage");
        for cause in &d.causes {
            for check in &cause.checks {
                if check.id == "arp_resolves" || check.id == "arp_fails" {
                    assert!(
                        check.passed.is_none(),
                        "{} claimed {:?} about an arp probe that never ran",
                        check.id,
                        check.passed
                    );
                }
            }
        }
        // And an unmeasured probe cannot carry the cause it would have
        // discriminated: its corroborating check is skipped, so the cause
        // stays short of strong.
        let vlan = d
            .causes
            .iter()
            .find(|c| c.id == "wrong_vlan_or_address_conflict")
            .expect("cause present");
        assert!(vlan.checks.iter().any(|k| k.passed.is_none()));
        assert_ne!(vlan.confidence(), super::super::issue::Confidence::Strong);
    }

    #[test]
    fn a_reference_answer_without_ad_is_not_applicable_not_unmeasured() {
        let mut dns = slow_dns();
        dns.rtt_p50_ms = Some(1.0);
        dns.cross = Some(DnsCross {
            name: "dns.google".into(),
            local: vec!["10.0.0.1".into()],
            reference_resolver: "1.1.1.1".into(),
            reference: vec!["8.8.8.8".into()],
            validated: false,
            private_answer: false,
            mismatch_pct: 100.0,
            cycles: 5,
        });
        let found = detect(&obs_with_dns(dns), &store(), &Thresholds::default());
        let check = found
            .iter()
            .find(|d| d.rule == "dns.hijack_suspect")
            .expect("disagreement with history fires the rule")
            .causes
            .iter()
            .flat_map(|c| &c.checks)
            .find(|k| k.id == "reference_validated")
            .expect("forged_records carries the check");
        assert_eq!(check.passed, None);
        assert_eq!(check.why_not, Some(Availability::NotApplicable));
        assert_eq!(check.detail, "1.1.1.1 answered without AD");
    }

    #[test]
    fn a_private_answer_keeps_split_horizon_on_the_table() {
        // A private answer for a public name is the signature of an internal
        // zone as much as of an interceptor. The check used to be inverted,
        // so the benign explanation scored 0.0 in exactly the case where it
        // applies.
        let mut dns = slow_dns();
        dns.rtt_p50_ms = Some(1.0);
        dns.cross = Some(DnsCross {
            name: "dns.google".into(),
            local: vec!["10.0.0.1".into()],
            reference_resolver: "1.1.1.1".into(),
            reference: vec!["8.8.8.8".into()],
            validated: true,
            private_answer: true,
            mismatch_pct: 100.0,
            cycles: 1,
        });
        let found = detect(&obs_with_dns(dns), &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "dns.hijack_suspect")
            .expect("private answer fires the rule");
        let split = d
            .causes
            .iter()
            .find(|c| c.id == "split_horizon")
            .expect("cause present");
        assert_eq!(
            split.score(),
            Some(1.0),
            "the private answer supports an intentional internal zone too"
        );
        let interceptor = d
            .causes
            .iter()
            .find(|c| c.id == "interceptor")
            .expect("cause present");
        assert_eq!(
            split.score(),
            interceptor.score(),
            "nothing measured separates the two, so neither may outrank the other"
        );
    }

    #[test]
    fn a_genuinely_dead_gateway_still_fires() {
        let obs = Observations {
            gateway: Some(dead_gateway()),
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "gateway.unreachable")
            .expect("nothing answers anywhere — this is a real outage");
        assert_eq!(d.severity, Severity::Critical);
    }

    #[test]
    fn an_unprobed_internet_weakens_the_finding_rather_than_hiding_it() {
        let obs = Observations {
            gateway: Some(GatewayObs {
                internet_reachable: None,
                ..dead_gateway()
            }),
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "gateway.unreachable")
            .expect("still worth raising");
        // The corroborating check is weighted 3× and reports "not run", so it
        // neither props the cause up nor counts against it.
        let top = d.causes.iter().max_by(|a, b| {
            a.score()
                .unwrap_or(0.0)
                .partial_cmp(&b.score().unwrap_or(0.0))
                .unwrap()
        });
        assert!(top.is_some());
        assert!(d
            .causes
            .iter()
            .all(|c| c.checks.iter().any(|k| k.passed.is_none())));
    }

    // -------------------------------------------------------------- paths

    fn hop(n: u8, ip: &str, asn: &str, rtt: f64) -> HopObs {
        HopObs {
            number: n,
            ip: Some(ip.into()),
            asn: Some(asn.into()),
            rtt_p50_ms: Some(rtt),
            rtt_p95_ms: Some(rtt * 1.5),
            loss_pct: 0.0,
            silent: false,
        }
    }

    #[test]
    fn a_changed_hop_is_detected_and_attributed_to_the_provider() {
        let previous = vec![
            hop(1, "192.168.8.1", "-", 1.0),
            hop(2, "100.64.0.1", "as7545", 8.0),
            hop(3, "203.0.113.9", "as7545", 12.0),
        ];
        let current = vec![
            hop(1, "192.168.8.1", "-", 1.0),
            hop(2, "100.64.0.1", "as7545", 8.0),
            hop(3, "203.0.113.44", "as7545", 52.0),
        ];
        assert_eq!(first_hop_change(&previous, &current), Some(3));

        let path = PathObs {
            target: "1.1.1.1".into(),
            hops: current,
            previous: Some(previous),
            traced_at: "2026-09-03 06:44:02".into(),
            destination_reached: Some(true),
        };
        let d = detect_path_change(&path).unwrap();
        assert_eq!(
            d.severity,
            Severity::Medium,
            "40ms of added rtt is not just a note"
        );
        assert!(d.causes[0]
            .label
            .contains("rerouted inside its own network"));
    }

    #[test]
    fn a_silent_hop_is_not_a_route_change() {
        let previous = vec![
            hop(1, "192.168.8.1", "-", 1.0),
            hop(2, "100.64.0.1", "as7545", 8.0),
        ];
        let mut current = previous.clone();
        current[1].silent = true;
        current[1].ip = None;
        assert_eq!(
            first_hop_change(&previous, &current),
            None,
            "a router that stopped answering icmp has not moved"
        );
    }

    #[test]
    fn a_silent_hop_is_not_reported_as_loss() {
        let mut hops = vec![
            hop(1, "192.168.8.1", "-", 1.0),
            hop(2, "100.64.0.1", "as7545", 8.0),
            hop(3, "203.0.113.9", "as7545", 12.0),
        ];
        hops[1].silent = true;
        hops[1].loss_pct = 100.0;
        hops[1].ip = None;
        let path = PathObs {
            target: "1.1.1.1".into(),
            hops,
            previous: None,
            traced_at: "now".into(),
            destination_reached: Some(true),
        };
        assert!(
            detect_path_loss(&path).is_none(),
            "a silent middle hop with clean hops after it is icmp rate-limiting"
        );
    }

    #[test]
    fn a_silent_tail_after_a_lossy_hop_blames_nobody() {
        // The hop that answers last used to be named the culprit whenever
        // every hop behind it was silent — the normal shape of a firewalled
        // tail. Rate-limiting its own ICMP became "hop 2 is dropping
        // traffic", with evidence text asserting a propagation nobody saw.
        let mut hops = vec![
            hop(1, "192.168.8.1", "-", 1.0),
            hop(2, "100.64.0.1", "as7545", 8.0),
            hop(3, "203.0.113.9", "as7545", 12.0),
        ];
        hops[1].loss_pct = 30.0;
        hops[2].silent = true;
        hops[2].loss_pct = 100.0;
        hops[2].ip = None;
        let path = PathObs {
            target: "1.1.1.1".into(),
            hops,
            previous: None,
            traced_at: "now".into(),
            destination_reached: None,
        };
        let d = detect_path_loss(&path).expect("the trace did lose packets");
        let propagation = d
            .causes
            .iter()
            .flat_map(|c| &c.checks)
            .find(|k| k.id == "loss_propagates_to_later_hops")
            .unwrap();
        assert!(
            propagation.passed.is_none(),
            "propagation was never observed, so it cannot be claimed either way"
        );
        for check in d.causes.iter().flat_map(|c| &c.checks) {
            assert!(
                !check.detail.contains("and beyond"),
                "{}: {} — asserts a propagation this branch did not see",
                check.id,
                check.detail
            );
        }
        assert!(d
            .scope
            .note
            .as_deref()
            .unwrap_or_default()
            .contains("no hop can be blamed"));
        for cause in &d.causes {
            assert_ne!(
                cause.confidence(),
                super::super::issue::Confidence::Strong,
                "{} outran the evidence",
                cause.id
            );
        }
    }

    #[test]
    fn a_reached_destination_is_recorded_on_both_causes() {
        let mut hops = vec![
            hop(1, "192.168.8.1", "-", 1.0),
            hop(2, "100.64.0.1", "as7545", 8.0),
            hop(3, "203.0.113.9", "as7545", 12.0),
        ];
        hops[1].loss_pct = 22.0;
        hops[2].loss_pct = 24.0;
        let path = PathObs {
            target: "1.1.1.1".into(),
            hops,
            previous: None,
            traced_at: "now".into(),
            destination_reached: Some(true),
        };
        let d = detect_path_loss(&path).unwrap();
        for cause in &d.causes {
            let dest = cause
                .checks
                .iter()
                .find(|k| k.id == "destination_answered_the_trace")
                .expect("both causes carry the destination check");
            assert_eq!(dest.passed, Some(true));
        }
    }

    #[test]
    fn loss_that_propagates_is_reported() {
        let mut hops = vec![
            hop(1, "192.168.8.1", "-", 1.0),
            hop(2, "100.64.0.1", "as7545", 8.0),
            hop(3, "203.0.113.9", "as7545", 12.0),
        ];
        hops[1].loss_pct = 22.0;
        hops[2].loss_pct = 24.0;
        let path = PathObs {
            target: "1.1.1.1".into(),
            hops,
            previous: None,
            traced_at: "now".into(),
            destination_reached: Some(true),
        };
        let d = detect_path_loss(&path).unwrap();
        assert_eq!(d.rule, "path.high_loss");
        assert!(d.causes[0].label.contains("hop 2"));
    }

    // --------------------------------------------------------------- link

    #[test]
    fn a_down_link_reports_nothing_else_about_that_interface() {
        let obs = Observations {
            iface: Some(IfaceObs {
                counter_window_secs: None,
                name: "eth0".into(),
                carrier: Some(false),
                rx_errors: 0,
                tx_errors: 0,
                rx_dropped: 0,
                tx_dropped: 0,
                errors_per_min: 40,
                drops_per_min: Some(12),
                link_rate_bps: Some(1e9),
                wireless: Some(false),
                signal_dbm: None,
                tx_retry_pct: None,
                rx_bps: 0.0,
                tx_bps: 0.0,
            }),
            ..Default::default()
        };
        let found = detect(&obs, &store(), &Thresholds::default());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, "link.down");
    }

    /// No interface info used to read as "carrier up, wired". It is neither:
    /// no link.down, and coverage says the carrier was not measured rather
    /// than that the rule had its input.
    #[test]
    fn missing_interface_info_opens_no_link_issue() {
        use crate::diagnose::{coverage::Coverage, fixture};
        let mut obs = fixture::observations_at(300);
        let iface = obs.iface.as_mut().unwrap();
        iface.carrier = None;
        iface.wireless = None;
        let base = fixture::baselines();
        let found = detect(&obs, &base, &Thresholds::default());
        assert!(!rules_of(&found).contains(&"link.down"));
        let coverage = Coverage::from_observations(&obs, &base, Default::default());
        let link_down = coverage
            .rules
            .iter()
            .find(|r| r.rule == "link.down")
            .unwrap();
        assert_eq!(link_down.status, Availability::NotMeasured);
    }

    /// A healthy wired gigabit interface with nothing on its counters.
    fn eth0() -> IfaceObs {
        IfaceObs {
            counter_window_secs: Some(60.0),
            name: "eth0".into(),
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

    fn link_rules(iface: IfaceObs) -> Vec<&'static str> {
        let obs = Observations {
            iface: Some(iface),
            ..Default::default()
        };
        detect(&obs, &store(), &Thresholds::default())
            .iter()
            .map(|d| d.rule)
            .collect()
    }

    #[test]
    fn iface_errors_fires_at_the_error_floor() {
        // One error a minute: errors are rare and always mean something.
        let found = link_rules(IfaceObs {
            errors_per_min: 1,
            ..eth0()
        });
        assert_eq!(found, ["iface.errors"]);
    }

    #[test]
    fn iface_errors_fires_at_the_drop_floor() {
        let found = link_rules(IfaceObs {
            drops_per_min: Some(60),
            ..eth0()
        });
        assert_eq!(found, ["iface.errors"]);
    }

    #[test]
    fn iface_errors_is_quiet_below_both_floors() {
        // No errors, and 59 drops a minute: a wireless NIC drops multicast
        // and management frames as a matter of course.
        let found = link_rules(IfaceObs {
            errors_per_min: 0,
            drops_per_min: Some(59),
            ..eth0()
        });
        assert!(!found.contains(&"iface.errors"), "{found:?}");
    }

    /// A link on a platform that counts no drops (macOS), with this many
    /// errors a minute.
    fn uncounted_drops(errors_per_min: u64) -> IfaceObs {
        IfaceObs {
            errors_per_min,
            drops_per_min: None,
            ..eth0()
        }
    }

    fn iface_errors(iface: IfaceObs) -> Detection {
        let obs = Observations {
            iface: Some(iface),
            ..Default::default()
        };
        detect(&obs, &store(), &Thresholds::default())
            .into_iter()
            .find(|d| d.rule == "iface.errors")
            .expect("iface.errors fires")
    }

    /// Without drop counters iface.errors fires on errors alone, and the
    /// rate it opens on is the one its verify reads: errors plus drops where
    /// drops are counted, errors alone where they are not.
    #[test]
    fn without_drop_counters_iface_errors_judges_errors_only() {
        assert!(link_rules(uncounted_drops(0)).is_empty());
        let d = iface_errors(uncounted_drops(3));
        assert_eq!(d.evidence[0].metric, "iface.error_rate");
        assert_eq!(d.evidence[0].value, 3.0);
        assert_eq!(uncounted_drops(3).error_rate(), 3);
        let counted = IfaceObs {
            drops_per_min: Some(5),
            ..uncounted_drops(3)
        };
        assert_eq!(counted.error_rate(), 8);

        let obs = Observations {
            iface: Some(uncounted_drops(3)),
            ..Default::default()
        };
        let coverage = crate::diagnose::coverage::Coverage::from_observations(
            &obs,
            &store(),
            Default::default(),
        );
        let row = coverage
            .rules
            .iter()
            .find(|r| r.rule == "iface.errors")
            .unwrap();
        assert_eq!(row.status, Availability::Available);
        // A coverage row says what was measured, not what was found.
        assert_eq!(
            row.reason,
            "interface error counters present; drops not counted on macOS"
        );
    }

    /// Both causes weigh drops against errors, so neither can be judged
    /// without drops. The ring buffer cause has no other check, and with
    /// only errors to go on it must not be the probable cause.
    #[test]
    fn ring_buffer_cause_is_not_run_without_drop_counters() {
        use crate::diagnose::engine::{Engine, FixedClock};
        let d = iface_errors(uncounted_drops(3));
        let cause = |id| d.causes.iter().find(|c| c.id == id).unwrap();
        let ring = cause("ring_buffer_small");
        assert_eq!(ring.confidence(), super::super::issue::Confidence::Untested);
        for c in ring
            .checks
            .iter()
            .chain(&cause("bad_cable_or_duplex").checks)
        {
            assert_eq!(c.why_not, Some(Availability::Unsupported), "{}", c.id);
        }

        let clock = std::sync::Arc::new(FixedClock::at("2026-09-03 06:48:10"));
        let mut engine = Engine::new(Box::new(clock.clone()));
        let obs = Observations {
            iface: Some(uncounted_drops(40)),
            ..Default::default()
        };
        for _ in 0..5 {
            engine.observe(&obs, &store());
            clock.advance_secs(10);
        }
        let issue = engine
            .primary()
            .into_iter()
            .find(|i| i.rule == "iface.errors")
            .expect("iface.errors opens");
        assert_eq!(issue.top_cause().unwrap().id, "bad_cable_or_duplex");
    }

    #[test]
    fn iface_saturated_fires_at_ninety_percent() {
        let found = link_rules(IfaceObs {
            rx_bps: 9e8,
            ..eth0()
        });
        assert_eq!(found, ["iface.saturated"]);
    }

    #[test]
    fn iface_saturated_is_quiet_at_eighty_nine() {
        let found = link_rules(IfaceObs {
            rx_bps: 8.9e8,
            ..eth0()
        });
        assert!(!found.contains(&"iface.saturated"), "{found:?}");
    }

    #[test]
    fn every_detection_carries_a_verify_condition() {
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let obs = Observations {
            dns: Some(slow_dns()),
            sockets: vec![bloated_socket()],
            idle_rtt_ms: Some(12.0),
            loaded_rtt_ms: Some(320.0),
            ..Default::default()
        };
        let found = detect(&obs, &base, &Thresholds::default());
        assert!(!found.is_empty());
        for d in &found {
            assert!(
                !d.verify.metric.is_empty(),
                "{} has no verify metric",
                d.rule
            );
            assert!(d.verify.hold_secs > 0, "{} closes instantly", d.rule);
        }
    }

    #[test]
    fn every_apply_step_is_reversible_and_declares_its_privilege() {
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let found = detect(&obs_with_dns(slow_dns()), &base, &Thresholds::default());
        let mut applies = 0;
        for d in &found {
            for s in &d.remediation {
                if s.kind == super::super::issue::StepKind::Apply {
                    applies += 1;
                    assert!(s.reversible, "{}: apply step must be reversible", d.rule);
                    assert!(s.key.is_some(), "{}: apply step needs a hotkey", d.rule);
                    assert_ne!(
                        s.requires,
                        Capability::None,
                        "{}: writing resolv.conf needs a declared privilege",
                        d.rule
                    );
                }
            }
        }
        assert!(applies > 0, "the dns rule should offer something to apply");
    }

    /// The string literals in `src`, skipping comments and char literals, so
    /// a word in a comment is not mistaken for text a user reads.
    fn string_literals(src: &str) -> Vec<&str> {
        let b = src.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'/' if b.get(i + 1) == Some(&b'/') => {
                    while i < b.len() && b[i] != b'\n' {
                        i += 1;
                    }
                }
                b'\'' if b.get(i + 2) == Some(&b'\'') => i += 3,
                b'"' => {
                    let start = i + 1;
                    i += 1;
                    while i < b.len() && b[i] != b'"' {
                        i += if b[i] == b'\\' { 2 } else { 1 };
                    }
                    out.push(&src[start..i.min(b.len())]);
                    i += 1;
                }
                _ => i += 1,
            }
        }
        out
    }

    /// The live `↵` writes nothing, so no step may say netwatch writes, backs
    /// up or restores anything. Read from the source, so a step on a branch
    /// no test reaches is held to it as well, and from what the DNS rule
    /// emits with and without a measured alternate.
    #[test]
    fn no_step_text_promises_a_write() {
        const PROMISES: [&str; 3] = ["writes", "backup", "puts it back"];
        let src = include_str!("detectors.rs");
        let body = &src[..src.find("#[cfg(test)]").unwrap()];
        let literals = string_literals(body);
        assert!(
            literals.len() > 300,
            "found only {} literals; did the scan break?",
            literals.len()
        );
        for lit in &literals {
            let lower = lit.to_lowercase();
            for promise in PROMISES {
                assert!(!lower.contains(promise), "{lit:?} promises a write");
            }
        }

        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        for alt_rtt_ms in [Some(1.4), Some(38.0), None] {
            let dns = DnsObs {
                alt_rtt_ms,
                ..slow_dns()
            };
            for d in detect(&obs_with_dns(dns), &base, &Thresholds::default()) {
                for s in &d.remediation {
                    let text = format!("{} {}", s.text, s.detail).to_lowercase();
                    for promise in PROMISES {
                        assert!(!text.contains(promise), "{}: {text}", d.rule);
                    }
                }
            }
        }
    }

    /// On a systemd-resolved host the probe asks 127.0.0.53 for root NS, which
    /// the stub answers from its cache in 0 ms. Coverage keeps the rule
    /// available, since the stub's RTT is measured, and says what it times;
    /// a finding says so in its scope; the checks about the upstream abstain
    /// instead of reading loopback ICMP and the stub's cache as the upstream.
    #[test]
    fn a_loopback_resolver_says_it_measures_the_stub() {
        use crate::diagnose::coverage::{Availability as A, Coverage};
        for (addr, stub) in [
            ("127.0.0.53", true),
            ("127.0.0.54", true),
            ("::1", true),
            ("169.254.1.1", false),
            ("192.168.8.1", false),
            ("fe80::1%eth0", false),
        ] {
            let dns = DnsObs {
                resolver: addr.into(),
                ..slow_dns()
            };
            assert_eq!(dns.is_local_stub(), stub, "{addr}");
        }

        let coverage_of = |dns: DnsObs| {
            Coverage::from_observations(&obs_with_dns(dns), &store(), Default::default())
                .rules
                .into_iter()
                .find(|r| r.rule == "dns.slow_resolver")
                .unwrap()
        };
        // The Fedora host: healthy, 0 ms, nothing opens.
        let quiet = DnsObs {
            resolver: "127.0.0.53".into(),
            rtt_p50_ms: Some(0.0),
            rtt_p95_ms: Some(0.1),
            ..slow_dns()
        };
        let row = coverage_of(quiet.clone());
        assert_eq!(row.status, A::Available);
        assert_eq!(
            row.reason,
            "limited: measures the local stub at 127.0.0.53, not the upstream"
        );
        let found = detect(&obs_with_dns(quiet), &store(), &Thresholds::default());
        assert!(!rules_of(&found).contains(&"dns.slow_resolver"));
        assert_ne!(
            coverage_of(slow_dns()).reason,
            row.reason,
            "a resolver off the host is not a stub"
        );

        // A stub slow enough to cross the ceiling, with loopback ICMP and a
        // cache probe that would otherwise read as the upstream's.
        let slow_stub = DnsObs {
            resolver: "127.0.0.53".into(),
            rtt_p50_ms: Some(150.0),
            rtt_p95_ms: Some(180.0),
            icmp_rtt_ms: Some(0.05),
            cached_rtt_ms: Some(0.9),
            ..slow_dns()
        };
        let found = detect(&obs_with_dns(slow_stub), &store(), &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "dns.slow_resolver")
            .expect("150ms is over the 100ms ceiling");
        let note = d.scope.note.as_deref().unwrap_or_default();
        assert!(
            note.contains(
                "the probe asks root NS; the local stub at 127.0.0.53 answers from cache, \
                 so this is the stub's round trip"
            ),
            "{note}"
        );
        for id in [
            "resolver_itself_is_reachable",
            "cached_names_still_fast",
            "icmp_rtt_raised",
        ] {
            let check = d
                .causes
                .iter()
                .flat_map(|c| &c.checks)
                .find(|k| k.id == id)
                .unwrap();
            assert_eq!(check.passed, None, "{id}: {check:?}");
            assert_eq!(check.why_not, Some(A::NotMeasured), "{id}");
            assert_eq!(check.detail, UPSTREAM_UNKNOWN, "{id}");
        }

        // Off the host, the same readings are the resolver's own.
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let found = detect(&obs_with_dns(slow_dns()), &base, &Thresholds::default());
        let d = found
            .iter()
            .find(|d| d.rule == "dns.slow_resolver")
            .unwrap();
        assert!(!d.scope.note.as_deref().unwrap_or_default().contains("stub"));
        let icmp = d
            .causes
            .iter()
            .flat_map(|c| &c.checks)
            .find(|k| k.id == "resolver_itself_is_reachable")
            .unwrap();
        assert_eq!(icmp.passed, Some(true));
    }

    /// REVIEW §2.4: propose a resolver only after measuring it. Live, the
    /// second configured resolver is never timed, so the switch used to be
    /// offered on nothing but its presence in resolv.conf.
    #[test]
    fn no_switch_step_without_a_measured_alternate() {
        use super::super::issue::StepKind;
        let mut base = store();
        base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let steps = |dns: DnsObs| -> Vec<Step> {
            detect(&obs_with_dns(dns), &base, &Thresholds::default())
                .into_iter()
                .find(|d| d.rule == "dns.slow_resolver")
                .expect("a 40ms resolver against a 1.2ms baseline is slow")
                .remediation
        };
        let offers_switch = |steps: &[Step]| {
            steps
                .iter()
                .any(|s| s.kind == StepKind::Apply || s.text == "make it permanent")
        };

        // Live today: configured, never timed.
        let unmeasured = steps(DnsObs {
            alt_rtt_ms: None,
            ..slow_dns()
        });
        assert!(!offers_switch(&unmeasured), "{unmeasured:?}");
        // Timed, but no faster than a quarter of the 40ms median.
        let slow = steps(DnsObs {
            alt_rtt_ms: Some(10.0),
            ..slow_dns()
        });
        assert!(!offers_switch(&slow), "{slow:?}");
        let none = steps(DnsObs {
            alt_resolver: None,
            ..slow_dns()
        });
        assert!(!offers_switch(&none), "{none:?}");

        // The demo's alternate: 1.4ms against 40ms. Offered, with the command
        // to run and the number that justified it.
        let fast = steps(slow_dns());
        let switch = fast
            .iter()
            .find(|s| s.kind == StepKind::Apply)
            .expect("a measured fast alternate is proposed");
        for want in [
            "192.168.8.1 answered in 1.4ms",
            "netwatch does not change resolvers from this screen",
            "sudo netwatch resolver set 192.168.8.1 --unmanaged",
            "resolvectl dns <iface> 192.168.8.1",
        ] {
            assert!(switch.detail.contains(want), "{want}: {}", switch.detail);
        }

        // A failing resolver has no speed to beat: an alternate that answered
        // at all is the case for it, and one never asked is none.
        let failing = |alt_rtt_ms| {
            detect(
                &obs_with_dns(DnsObs {
                    failure_rate_pct: 40.0,
                    alt_rtt_ms,
                    ..slow_dns()
                }),
                &base,
                &Thresholds::default(),
            )
            .into_iter()
            .find(|d| d.rule == "dns.failing")
            .expect("40% of queries failing")
            .remediation
        };
        assert!(!offers_switch(&failing(None)));
        assert!(offers_switch(&failing(Some(30.0))));
    }

    #[test]
    fn id_validation_rejects_bad_and_duplicate_ids() {
        assert!(Cause::valid_id("upstream_slow"));
        assert!(Cause::valid_id("udp53_filtered"));
        for bad in [
            "",
            "Upstream",
            "has space",
            "_lead",
            "trail_",
            "double__underscore",
            "9lives",
        ] {
            assert!(!Cause::valid_id(bad), "{bad:?} should be rejected");
        }
        let mut d = Detection::new("dns.slow_resolver", Subject::Host);
        d.causes = vec![
            Cause::new("same", "a", vec![]),
            Cause::new("same", "b", vec![]),
        ];
        assert!(ids_are_valid(&d).is_err());
        d.causes = vec![Cause::new(
            "one",
            "a",
            vec![
                CheckResult::pass("x", "x", ""),
                CheckResult::fail("x", "x again", ""),
            ],
        )];
        assert!(ids_are_valid(&d).is_err());
    }

    /// The debug assertion in `detect` only sees branches some test reaches.
    /// This reads the source so a cause or check on an untested branch still
    /// has to carry a literal, valid id.
    #[test]
    fn every_id_in_the_detector_source_is_a_valid_literal() {
        let src = include_str!("detectors.rs");
        let body = &src[..src.find("#[cfg(test)]").unwrap()];
        let mut causes = 0;
        let mut forwarded = 0;
        for (needle, is_cause) in [
            ("Cause::new(", true),
            ("CheckResult::pass(", false),
            ("CheckResult::fail(", false),
            ("CheckResult::not_run(", false),
            ("stage_check(", false),
        ] {
            for (at, _) in body.match_indices(needle) {
                let rest = body[at + needle.len()..].trim_start();
                // `stage_result` passes on the literal its `stage_check(`
                // caller gave it, which this scan has already read.
                if rest.starts_with("id,") {
                    forwarded += 1;
                    continue;
                }
                let lit = rest
                    .strip_prefix('"')
                    .and_then(|r| r.split_once('"'))
                    .map(|(id, _)| id)
                    .unwrap_or_else(|| {
                        panic!(
                            "{needle} without a literal id: {}",
                            &rest[..rest.len().min(60)]
                        )
                    });
                assert!(Cause::valid_id(lit), "{needle} has invalid id {lit:?}");
                causes += usize::from(is_cause);
            }
        }
        assert!(
            causes >= 35,
            "found only {causes} causes; did the scan break?"
        );
        assert_eq!(forwarded, 1, "only stage_result may forward an id");
    }

    /// `detect` checks this on every call in debug builds, so each detector
    /// test above already holds its own branches to it. This one adds the
    /// fixture's whole timeline and a host where every optional probe is
    /// missing, and ties `state()` to the reason as well.
    #[test]
    fn a_not_run_check_always_says_why() {
        use crate::diagnose::{fixture, issue::CheckState};
        let mut scenarios: Vec<Observations> = (0..=fixture::SCENARIO_SECS)
            .step_by(10)
            .map(fixture::observations_at)
            .collect();
        scenarios.push(Observations {
            now: "2026-09-03 06:51:19".into(),
            dns: Some(DnsObs {
                alt_rtt_ms: None,
                icmp_rtt_ms: None,
                cached_rtt_ms: None,
                ..slow_dns()
            }),
            gateway: Some(GatewayObs {
                arp_ok: None,
                internet_reachable: None,
                ..dead_gateway()
            }),
            iface: Some(IfaceObs {
                counter_window_secs: Some(60.0),
                name: "wlan0".into(),
                carrier: Some(true),
                rx_errors: 0,
                tx_errors: 0,
                rx_dropped: 0,
                tx_dropped: 0,
                errors_per_min: 0,
                drops_per_min: Some(0),
                link_rate_bps: None,
                rx_bps: 0.0,
                tx_bps: 0.0,
                wireless: Some(true),
                signal_dbm: None,
                tx_retry_pct: Some(40.0),
            }),
            sockets: vec![bloated_socket()],
            ..Default::default()
        });
        let base = fixture::baselines();
        let mut not_run = 0;
        for obs in &scenarios {
            for d in detect(obs, &base, &Thresholds::default()) {
                for c in &d.causes {
                    for k in &c.checks {
                        let key = format!("{}/{}", c.key(d.rule), k.id);
                        assert_eq!(k.passed.is_none(), k.why_not.is_some(), "{key}");
                        assert!(
                            !matches!(
                                k.why_not,
                                Some(Availability::Available | Availability::Unknown)
                            ),
                            "{key}: {:?} is not a reason a check did not run",
                            k.why_not
                        );
                        assert_eq!(
                            k.state() == CheckState::NotRun,
                            k.why_not.is_some(),
                            "{key}"
                        );
                        not_run += usize::from(k.passed.is_none());
                    }
                }
            }
        }
        assert!(not_run >= 10, "only {not_run} checks did not run");
    }

    #[test]
    fn a_not_run_check_cannot_claim_to_be_ready_or_unknown() {
        let with = |why_not| {
            let mut d = Detection::new(
                "dns.slow_resolver",
                Subject::Resolver {
                    addr: "127.0.0.53".into(),
                },
            );
            d.causes = vec![Cause::new(
                "resolver_overloaded",
                "the resolver is overloaded",
                vec![CheckResult::not_run(
                    "icmp_rtt_raised",
                    "icmp rtt raised",
                    why_not,
                    "no icmp probe",
                )],
            )];
            not_run_checks_say_why(&d)
        };
        assert!(with(Availability::NotImplemented).is_ok());
        assert!(with(Availability::Available).is_err());
        assert!(with(Availability::Unknown).is_err());
    }

    // ------------------------------------------------------------ absence

    /// Rows whose detectors still read the missing input as evidence. Each
    /// is removed by the 0.33 abstain item that fixes its site, and a row
    /// listed here that starts abstaining fails the test, so the list cannot
    /// outlive the fix.
    const EXPECTED_UNTIL_0_33_A: &[&str] = &[];

    /// What one absence row demands of the detectors.
    enum Expect {
        /// The check is present, and neither passed nor failed.
        NotRun(&'static str),
        /// The rule does not fire.
        NoRule(&'static str),
        /// No evidence on this metric carries this value.
        NoEvidence(&'static str, f64),
        /// The rule fires, so the row reached the code that reads the input.
        Fires(&'static str),
    }

    struct AbsenceRow {
        /// The input left unmeasured.
        input: &'static str,
        obs: Observations,
        base: BaselineStore,
        expect: Vec<Expect>,
    }

    /// One row per input the live path can leave unmeasured. Everything else
    /// in the row is set so the rules that read the input fire.
    fn absence_rows() -> Vec<AbsenceRow> {
        let mut dns_base = store();
        dns_base.seed("169.254.1.1", "dns.rtt_p50", 1.2, 0.4, 2000);
        let dns_row = |input, dns: DnsObs, expect| AbsenceRow {
            input,
            obs: obs_with_dns(dns),
            base: dns_base.clone(),
            expect,
        };
        let row = |input, obs, expect| AbsenceRow {
            input,
            obs,
            base: store(),
            expect,
        };
        let wlan0 = |signal_dbm, tx_retry_pct| Observations {
            iface: Some(IfaceObs {
                name: "wlan0".into(),
                wireless: Some(true),
                link_rate_bps: None,
                signal_dbm,
                tx_retry_pct,
                ..eth0()
            }),
            ..Default::default()
        };
        // A target whose connect timed out: its firewall_or_route cause asks
        // whether the internet answers.
        let mut timed_out = super::target_tests::healthy();
        timed_out.connect = Some(crate::diagnose::targets::Stage {
            ms: Some(3000.0),
            error: Some(crate::diagnose::targets::StageError::Timeout),
        });
        timed_out.connect_v4 = timed_out.connect.clone();
        let no_rtt = |local: &str, retrans| SocketObs {
            local: local.into(),
            rtt_ms: None,
            rttvar_ms: None,
            retrans: Some(retrans),
            ..bloated_socket()
        };

        vec![
            dns_row(
                "DnsObs.alt_rtt_ms",
                DnsObs {
                    alt_rtt_ms: None,
                    ..slow_dns()
                },
                vec![
                    Expect::NotRun("alt_resolver_is_fast"),
                    Expect::NotRun("alt_resolver_over_the_same_path_is_also_slow"),
                ],
            ),
            dns_row(
                "DnsObs.icmp_rtt_ms",
                DnsObs {
                    icmp_rtt_ms: None,
                    ..slow_dns()
                },
                vec![
                    Expect::NotRun("icmp_rtt_raised"),
                    Expect::NotRun("resolver_itself_is_reachable"),
                ],
            ),
            // The same probe, read by the failing-resolver causes.
            dns_row(
                "DnsObs.icmp_rtt_ms, failing resolver",
                DnsObs {
                    icmp_rtt_ms: None,
                    failure_rate_pct: 40.0,
                    failed: 15,
                    ..slow_dns()
                },
                vec![
                    Expect::NotRun("resolver_unreachable"),
                    Expect::NotRun("resolver_reachable"),
                ],
            ),
            dns_row(
                "DnsObs.cached_rtt_ms",
                DnsObs {
                    cached_rtt_ms: None,
                    ..slow_dns()
                },
                vec![Expect::NotRun("cached_names_still_fast")],
            ),
            // Both sockets send. One retransmits, so it is classified; the
            // other reaches the bufferbloat test with no rtt to judge.
            row(
                "SocketObs.rtt_ms",
                Observations {
                    sockets: vec![no_rtt("10.88.0.2:52344", 12), no_rtt("10.88.0.2:52346", 0)],
                    ..Default::default()
                },
                vec![
                    Expect::Fires("tcp.retrans_burst"),
                    Expect::NotRun("socket_rtt_below_queueing_line"),
                    Expect::NoRule("tcp.bufferbloat_remote"),
                    Expect::NoEvidence("tcp.socket_rtt", 0.0),
                ],
            ),
            row(
                "IfaceObs.signal_dbm",
                wlan0(None, Some(35.0)),
                vec![Expect::NotRun("signal_weak"), Expect::NotRun("signal_fine")],
            ),
            row(
                "IfaceObs.tx_retry_pct",
                wlan0(Some(-80), None),
                vec![Expect::NotRun("retries_high")],
            ),
            // Errors on the same interface fire, so the row gets past the
            // carrier test, which returns early on a link that is down.
            row(
                "IfaceObs.carrier",
                Observations {
                    iface: Some(IfaceObs {
                        carrier: None,
                        errors_per_min: 40,
                        ..eth0()
                    }),
                    ..Default::default()
                },
                vec![Expect::NoRule("link.down"), Expect::Fires("iface.errors")],
            ),
            // Errors fire iface.errors and the slow resolver brings in
            // local_udp_path: every reader of the drop count.
            AbsenceRow {
                input: "IfaceObs.drops_per_min",
                obs: Observations {
                    iface: Some(IfaceObs {
                        drops_per_min: None,
                        errors_per_min: 40,
                        ..eth0()
                    }),
                    ..obs_with_dns(slow_dns())
                },
                base: dns_base.clone(),
                expect: vec![
                    Expect::NotRun("interface_drops"),
                    Expect::NotRun("drops_dominate"),
                    Expect::NotRun("errors_dominate"),
                ],
            },
            row(
                "GatewayObs.arp_ok",
                Observations {
                    gateway: Some(GatewayObs {
                        arp_ok: None,
                        ..dead_gateway()
                    }),
                    ..Default::default()
                },
                vec![Expect::NotRun("arp_resolves"), Expect::NotRun("arp_fails")],
            ),
            row(
                "GatewayObs.internet_reachable",
                Observations {
                    gateway: Some(GatewayObs {
                        internet_reachable: None,
                        ..dead_gateway()
                    }),
                    targets: vec![timed_out],
                    ..Default::default()
                },
                vec![
                    Expect::NotRun("nothing_beyond_the_gateway_answers_either"),
                    Expect::NotRun("internet_reachable"),
                ],
            ),
        ]
    }

    /// What the row got wrong: absent input read as evidence, and anything
    /// that makes the row prove nothing (a check or rule that never came up).
    fn judge(row: &AbsenceRow) -> (Vec<String>, Vec<String>) {
        let found = detect(&row.obs, &row.base, &Thresholds::default());
        let (mut read, mut vacuous) = (vec![], vec![]);
        for expect in &row.expect {
            match *expect {
                Expect::NotRun(id) => {
                    let checks: Vec<&CheckResult> = found
                        .iter()
                        .flat_map(|d| &d.causes)
                        .flat_map(|c| &c.checks)
                        .filter(|c| c.id == id)
                        .collect();
                    if checks.is_empty() {
                        vacuous.push(format!("no detection carries {id}"));
                    }
                    for c in checks {
                        if let Some(passed) = c.passed {
                            let verb = if passed { "passed" } else { "failed" };
                            read.push(format!("{id} {verb}: {}", c.detail));
                        }
                    }
                }
                Expect::NoRule(rule) => {
                    if found.iter().any(|d| d.rule == rule) {
                        read.push(format!("{rule} fired"));
                    }
                }
                Expect::NoEvidence(metric, value) => {
                    if found
                        .iter()
                        .flat_map(|d| &d.evidence)
                        .any(|e| e.metric == metric && e.value == value)
                    {
                        read.push(format!("{metric} evidence of {value}"));
                    }
                }
                Expect::Fires(rule) => {
                    if !found.iter().any(|d| d.rule == rule) {
                        vacuous.push(format!("{rule} did not fire"));
                    }
                }
            }
        }
        (read, vacuous)
    }

    /// REVIEW §2 exit clause 3: no detector reads a hard-coded `None` as
    /// evidence. A source scan cannot see the sites that invent a value
    /// rather than unwrap one, and flags dozens of lines that are fine, so
    /// this is a behaviour table: each row leaves one input unmeasured and
    /// names what must then be not run, or must not happen.
    ///
    /// Two rows are about the sampler rather than a detector, so they live
    /// in `live.rs`: the idle radio
    /// (`the_sampler_gives_an_idle_radio_no_retry_share`) and missing
    /// interface info (`the_sampler_reads_missing_interface_info_as_unknown`).
    #[test]
    fn no_detector_reads_an_absent_input_as_evidence() {
        let rows = absence_rows();
        let mut problems = vec![];
        for input in EXPECTED_UNTIL_0_33_A {
            if !rows.iter().any(|r| r.input == *input) {
                problems.push(format!("{input} is expected to fail but has no row"));
            }
        }
        for row in &rows {
            let (read, vacuous) = judge(row);
            if !vacuous.is_empty() {
                problems.push(format!(
                    "{} proves nothing: {}",
                    row.input,
                    vacuous.join("; ")
                ));
            }
            match (read.is_empty(), EXPECTED_UNTIL_0_33_A.contains(&row.input)) {
                (false, false) => problems.push(format!(
                    "{} read as evidence: {}",
                    row.input,
                    read.join("; ")
                )),
                (true, true) => problems.push(format!(
                    "{} now abstains; remove it from EXPECTED_UNTIL_0_33_A",
                    row.input
                )),
                _ => {}
            }
        }
        assert!(problems.is_empty(), "\n{}", problems.join("\n"));
    }

    #[test]
    fn observations_round_trip_through_json() {
        let obs = Observations {
            now: "2026-09-14 10:00:00".into(),
            gateway: Some(GatewayObs {
                addr: Some("192.168.8.1".into()),
                rtt_ms: Some(1.4),
                loss_pct: 0.0,
                arp_ok: Some(true),
                icmp_ok: true,
                internet_reachable: Some(true),
            }),
            paths: vec![PathObs {
                destination_reached: Some(true),
                target: "1.1.1.1".into(),
                hops: vec![HopObs {
                    number: 1,
                    ip: Some("192.168.8.1".into()),
                    asn: None,
                    rtt_p50_ms: Some(1.1),
                    rtt_p95_ms: None,
                    loss_pct: 0.0,
                    silent: false,
                }],
                previous: None,
                traced_at: "2026-09-14 09:59:30".into(),
            }],
            idle_rtt_ms: Some(18.0),
            config: Some(ObservedConfig {
                resolvers: Some(vec!["192.168.8.1".into(), "fe80::1%wlan0".into()]),
                targets: vec![("api".into(), "target-config:0123abcd".into())],
                trace_target: "1.1.1.1".into(),
                trace_refresh_secs: Some(120),
                interfaces: Some(vec!["lo".into(), "wlan0".into()]),
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&obs).unwrap();
        assert_eq!(serde_json::from_str::<Observations>(&json).unwrap(), obs);
        // A recording from before a field existed still loads.
        let old: Observations = serde_json::from_str(r#"{"now":"2026-09-14 10:00:00"}"#).unwrap();
        assert_eq!(old.now, "2026-09-14 10:00:00");
        // Without a configuration it is unknown, not empty, and a sample
        // that has none writes nothing for it.
        assert_eq!(old.config, None);
        let unknown = serde_json::to_value(&old).unwrap();
        assert!(unknown.get("config").is_none(), "{unknown}");
    }

    #[test]
    fn iface_obs_from_older_recordings_still_loads() {
        // As 0.32 wrote it, with carrier and wireless as plain booleans.
        let old: IfaceObs = serde_json::from_str(
            r#"{"counter_window_secs":60.0,"name":"eth0","carrier":true,"rx_errors":0,
                "tx_errors":0,"rx_dropped":0,"tx_dropped":0,"errors_per_min":0,
                "drops_per_min":0,"link_rate_bps":1000000000.0,"rx_bps":3100000.0,
                "tx_bps":2600000.0,"wireless":false,"signal_dbm":null,"tx_retry_pct":null}"#,
        )
        .unwrap();
        assert_eq!(old, eth0());
        // Unknown is written as null and read back as unknown.
        let unknown = IfaceObs {
            carrier: None,
            wireless: None,
            ..eth0()
        };
        let json = serde_json::to_value(&unknown).unwrap();
        assert!(json["carrier"].is_null() && json["wireless"].is_null());
        assert_eq!(serde_json::from_value::<IfaceObs>(json).unwrap(), unknown);
    }
}

#[cfg(test)]
mod target_tests {
    use super::*;
    use crate::diagnose::targets::{
        Lookup, LookupOutcome, Stage, StageError, TargetContext, TargetObs,
    };

    fn ok(ms: f64) -> Option<Stage> {
        Some(Stage {
            ms: Some(ms),
            error: None,
        })
    }
    fn err(e: StageError) -> Option<Stage> {
        Some(Stage {
            ms: Some(3000.0),
            error: Some(e),
        })
    }

    pub(super) fn healthy() -> TargetObs {
        TargetObs {
            stale_after_secs: None,
            attempts: vec![],
            effective_endpoint: None,
            sni: None,
            http_authority: None,
            baseline_key: None,
            name: "api".into(),
            host: "api.corp.internal".into(),
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
            lookups: vec![],
            connect: ok(12.0),
            connect_v4: ok(12.0),
            connect_v6: None,
            tls_stage: ok(30.0),
            http_stage: ok(40.0),
            status: Some(200),
            context: TargetContext::default(),
        }
    }

    fn detect_one(t: TargetObs) -> Detection {
        let obs = Observations {
            targets: vec![t],
            ..Default::default()
        };
        let base = crate::diagnose::fixture::baselines();
        let mut found = detect(&obs, &base, &Thresholds::default());
        assert_eq!(found.len(), 1, "{found:?}");
        let mut d = found.remove(0);
        d.causes.sort_by(|a, b| {
            b.score()
                .unwrap_or(-1.0)
                .total_cmp(&a.score().unwrap_or(-1.0))
        });
        d
    }

    #[test]
    fn a_healthy_target_raises_nothing() {
        let obs = Observations {
            targets: vec![healthy()],
            ..Default::default()
        };
        assert!(detect(
            &obs,
            &crate::diagnose::fixture::baselines(),
            &Thresholds::default()
        )
        .is_empty());
    }

    #[test]
    fn a_vpn_name_the_system_resolver_misses_points_at_split_dns() {
        let mut t = healthy();
        t.resolve = Stage {
            ms: Some(4.0),
            error: Some(StageError::NxDomain),
        };
        t.connect = None;
        t.tls_stage = None;
        t.http_stage = None;
        t.context.vpn_ifaces = vec!["wg0".into()];
        t.lookups = vec![
            Lookup {
                resolver: "127.0.0.53".into(),
                link: None,
                outcome: LookupOutcome::NxDomain,
            },
            Lookup {
                resolver: "10.8.0.1".into(),
                link: Some("wg0".into()),
                outcome: LookupOutcome::Answered,
            },
        ];
        let d = detect_one(t);
        assert_eq!(d.rule, "target.resolve_failed");
        assert_eq!(d.causes[0].id, "vpn_split_dns_missing");
        assert_ne!(d.severity, Severity::Info);
    }

    #[test]
    fn a_name_nobody_knows_is_information_not_a_network_fault() {
        let mut t = healthy();
        t.resolve = Stage {
            ms: Some(4.0),
            error: Some(StageError::NxDomain),
        };
        t.connect = None;
        t.lookups = vec![
            Lookup {
                resolver: "192.168.0.1".into(),
                link: None,
                outcome: LookupOutcome::NxDomain,
            },
            Lookup {
                resolver: "1.1.1.1".into(),
                link: None,
                outcome: LookupOutcome::NxDomain,
            },
        ];
        let d = detect_one(t);
        assert_eq!(d.causes[0].id, "name_does_not_exist");
        assert_eq!(d.severity, Severity::Info);
        assert_eq!(d.scope.note.as_deref(), Some("service, not network"));
    }

    #[test]
    fn a_refused_port_is_a_stopped_service_not_the_network() {
        let mut t = healthy();
        t.connect = err(StageError::Refused);
        t.connect_v4 = err(StageError::Refused);
        let d = detect_one(t);
        assert_eq!(d.rule, "target.connect_failed");
        assert_eq!(d.causes[0].id, "service_down");
        assert_eq!(d.severity, Severity::Info);
    }

    #[test]
    fn ipv6_timing_out_while_ipv4_connects_is_named() {
        let mut t = healthy();
        t.addresses = vec!["2001:db8::5".into(), "10.1.2.3".into()];
        t.connect = err(StageError::Timeout);
        t.connect_v6 = err(StageError::Timeout);
        t.connect_v4 = ok(12.0);
        let d = detect_one(t);
        assert_eq!(d.causes[0].id, "ipv6_path_broken");
        assert_ne!(d.severity, Severity::Info);
    }

    #[test]
    fn a_certificate_not_yet_valid_with_a_skewed_clock_is_the_clock() {
        let mut t = healthy();
        t.tls_stage = err(StageError::CertNotYetValid);
        t.http_stage = None;
        t.context.clock_offset_secs = Some(-3_600.0);
        let d = detect_one(t);
        assert_eq!(d.rule, "target.tls_failed");
        assert_eq!(d.causes[0].id, "clock_skew");
    }

    #[test]
    fn an_unread_clock_offset_is_unsupported_off_linux() {
        let mut t = healthy();
        t.tls_stage = err(StageError::CertExpired);
        t.http_stage = None;
        t.context.clock_offset_secs = None;
        let d = detect_one(t);
        let check = d
            .causes
            .iter()
            .flat_map(|c| &c.checks)
            .find(|k| k.id == "clock_offset_large")
            .expect("the clock cause is listed");
        // Linux reads chrony and only misses a sample; the other platforms
        // never read the local NTP status at all.
        let expected = if cfg!(target_os = "linux") {
            Availability::NotMeasured
        } else {
            Availability::Unsupported
        };
        assert_eq!(check.why_not, Some(expected));
    }

    #[test]
    fn an_untrusted_issuer_behind_a_proxy_reads_as_interception() {
        let mut t = healthy();
        t.tls_stage = err(StageError::CertUntrusted);
        t.http_stage = None;
        t.context.proxy_env = true;
        let d = detect_one(t);
        assert_eq!(d.causes[0].id, "tls_intercepting_proxy");
    }

    /// An Observation on the Diagnose tab. `diagnose run --target api`
    /// counts it as an Issue (D33-B07).
    #[test]
    fn a_503_is_the_service_not_the_network() {
        let mut t = healthy();
        t.http_stage = err(StageError::HttpStatus { status: 503 });
        t.status = Some(503);
        let d = detect_one(t);
        assert_eq!(d.rule, "target.http_error");
        assert_eq!(d.causes[0].id, "service_error");
        assert_eq!(d.severity, Severity::Info);
        assert_eq!(d.scope.note.as_deref(), Some("service, not network"));
    }

    #[test]
    fn remaining_target_causes_have_distinguishing_observation_scenarios() {
        let mut resolver = healthy();
        resolver.resolve = err(StageError::ResolverFailed).unwrap();
        resolver.lookups = vec![Lookup {
            resolver: "192.168.0.1".into(),
            link: None,
            outcome: LookupOutcome::ServFail,
        }];
        let mut route = healthy();
        route.connect = err(StageError::Unreachable);
        route.connect_v4 = err(StageError::Unreachable);
        let mut proxy = route.clone();
        proxy.context.proxy_env = true;
        let mut trust = healthy();
        trust.tls_stage = err(StageError::CertUntrusted);
        let mut rejected = healthy();
        rejected.http_stage = err(StageError::HttpStatus { status: 407 });
        rejected.status = Some(407);
        rejected.context.proxy_env = true;
        for (target, expected) in [
            (resolver, "resolver_failing"),
            (route, "firewall_or_route"),
            (proxy, "proxy_required"),
            (trust, "cert_untrusted"),
            (rejected, "proxy_rejected"),
        ] {
            let detection = detect_one(target);
            assert_eq!(detection.causes[0].id, expected, "{:#?}", detection.causes);
        }
    }

    #[test]
    fn a_slow_first_byte_against_its_baseline_points_at_the_server() {
        let mut base = crate::diagnose::fixture::baselines();
        for (metric, mean) in [
            ("target.resolve_ms", 2.0),
            ("target.connect_ms", 12.0),
            ("target.tls_ms", 30.0),
            ("target.ttfb_ms", 40.0),
        ] {
            base.seed("api", metric, mean, mean / 10.0, 2_400);
        }
        let mut t = healthy();
        t.http_stage = ok(900.0);
        let obs = Observations {
            targets: vec![t],
            ..Default::default()
        };
        let d = detect(&obs, &base, &Thresholds::default()).remove(0);
        assert_eq!(d.rule, "target.slow_stage");
        let top = d
            .causes
            .iter()
            .max_by(|a, b| {
                a.score()
                    .unwrap_or(-1.0)
                    .total_cmp(&b.score().unwrap_or(-1.0))
            })
            .unwrap();
        assert_eq!(top.id, "server_stage_slow");

        // The evidence carries the σ the stage was judged against. It used to
        // carry 0, and the report printed "σ0".
        let ev = &d.evidence[0];
        assert_eq!(ev.metric, "target.first_byte_ms");
        assert_eq!((ev.baseline, ev.sigma), (Some(40.0), Some(4.0)));
        // A first byte that never varied is judged, and reported, against the
        // floor.
        base.seed("api", "target.ttfb_ms", 5.0, 0.1, 2_400);
        let d = detect(&obs, &base, &Thresholds::default()).remove(0);
        assert_eq!(d.evidence[0].sigma, Some(0.5));
    }

    /// `default_verify` cannot read `Thresholds`, so each σ rule's detector
    /// sets its own close line. 1.5 is not the default, so a line of 1.5
    /// came from the configuration.
    #[test]
    fn the_sigma_rules_close_on_the_configured_close_line() {
        let mut base = crate::diagnose::fixture::baselines();
        base.seed("192.168.8.1", "gateway.rtt", 2.0, 0.3, 2_400);
        base.seed("internet", "path.rtt", 10.0, 1.0, 2_400);
        base.seed("api", "target.ttfb_ms", 40.0, 4.0, 2_400);
        let mut target = healthy();
        target.http_stage = ok(900.0);
        let obs = Observations {
            gateway: Some(GatewayObs {
                addr: Some("192.168.8.1".into()),
                rtt_ms: Some(40.0),
                loss_pct: 0.0,
                arp_ok: Some(true),
                icmp_ok: true,
                internet_reachable: Some(true),
            }),
            paths: vec![PathObs {
                target: "1.1.1.1".into(),
                hops: vec![HopObs {
                    number: 1,
                    ip: Some("1.1.1.1".into()),
                    asn: None,
                    rtt_p50_ms: Some(90.0),
                    rtt_p95_ms: Some(95.0),
                    loss_pct: 0.0,
                    silent: false,
                }],
                previous: None,
                traced_at: "2026-09-14 09:59:30".into(),
                destination_reached: Some(true),
            }],
            targets: vec![target],
            ..Default::default()
        };
        let t = Thresholds {
            sigma_close_k: 1.5,
            ..Thresholds::default()
        };
        let found = detect(&obs, &base, &t);
        for rule in ["gateway.rtt_spike", "path.rtt_spike", "target.slow_stage"] {
            let d = found
                .iter()
                .find(|d| d.rule == rule)
                .unwrap_or_else(|| panic!("{rule} should fire: {found:#?}"));
            let catalogued = rules::default_verify(rule).unwrap();
            assert_eq!(catalogued.threshold, Thresholds::default().sigma_close_k);
            assert_eq!(
                d.verify,
                Verify {
                    threshold: 1.5,
                    ..catalogued
                },
                "{rule}"
            );
        }
    }

    #[test]
    fn a_slow_connect_on_a_plain_http_target_says_it_has_no_tls_stage() {
        let mut base = crate::diagnose::fixture::baselines();
        for (metric, mean) in [("target.resolve_ms", 2.0), ("target.connect_ms", 12.0)] {
            base.seed("api", metric, mean, mean / 10.0, 2_400);
        }
        let mut t = healthy();
        t.port = 80;
        t.tls = false;
        t.tls_stage = None;
        t.connect = ok(900.0);
        let why = |t: TargetObs| {
            let obs = Observations {
                targets: vec![t],
                ..Default::default()
            };
            let d = detect(&obs, &base, &Thresholds::default()).remove(0);
            assert_eq!(d.rule, "target.slow_stage");
            d.causes
                .iter()
                .flat_map(|c| &c.checks)
                .map(|k| (k.id.clone(), (k.why_not.clone(), k.detail.clone())))
                .collect::<std::collections::HashMap<_, _>>()
        };
        let checks = why(t.clone());
        assert_eq!(
            checks["tls_stage_above_baseline"],
            (
                Some(Availability::NotApplicable),
                "this target has no tls stage".to_string()
            )
        );
        // A stage the target has, timed but with no baseline yet, is still
        // learning.
        assert_eq!(
            checks["server_stage_above_baseline"].0,
            Some(Availability::Learning)
        );
        // A tls target whose probe returned no tls time was not measured.
        t.tls = true;
        assert_eq!(
            why(t)["tls_stage_above_baseline"].0,
            Some(Availability::NotMeasured)
        );
    }
}
