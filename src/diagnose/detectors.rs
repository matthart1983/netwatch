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

use super::baseline::BaselineStore;
use super::issue::{
    Action, Capability, Cause, CheckResult, Evidence, Scope, Severity, Step, Subject, Verify,
};
use super::rules;

/// Tunables. Defaults are the spec's: k=3σ, N=3 consecutive samples.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Thresholds {
    /// σ multiple that counts as a deviation.
    pub sigma_k: f64,
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
    pub tx_bps: f64,
    pub rx_bps: f64,
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
    let rtt = s.rtt_ms.unwrap_or(0.0);

    // Retransmits dominate: a socket losing segments is describing the path,
    // not its own queueing, and the retrans rule carries the better causes.
    if s.retrans.is_some_and(|n| n >= 5) && rtt < t.socket_rtt_ms {
        return SocketVerdict::RetransBurst;
    }

    // Bufferbloat: high rtt while *this* socket is the one sending. A high rtt
    // on an idle socket is just a distant peer.
    if rtt >= t.socket_rtt_ms && s.tx_bps > 0.0 {
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

    if s.tx_bps == 0.0 && s.rx_bps == 0.0 {
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
    pub carrier: bool,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    /// Errors and drops over the last minute — a *rate*, not a lifetime
    /// counter. A NIC that logged 40 errors during boot last month is not a
    /// live fault, and a per-tick delta reported as "/min" is off by 60.
    pub errors_per_min: u64,
    pub drops_per_min: u64,
    pub link_rate_bps: Option<f64>,
    pub rx_bps: f64,
    pub tx_bps: f64,
    /// The kernel registered this as an 802.11 device.
    pub wireless: bool,
    /// Signal level, where the platform reports one.
    pub signal_dbm: Option<i32>,
    /// Transmit retries over the last minute as a share of frames sent.
    pub tx_retry_pct: Option<f64>,
}

impl IfaceObs {
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

    /// Stable identity for merging across ticks: one issue per (rule, subject).
    pub fn key(&self) -> String {
        format!("{}|{}", self.rule, self.subject.label())
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
    debug_assert!(
        out.iter().all(|d| ids_are_valid(d).is_ok()),
        "{:?}",
        out.iter()
            .filter_map(|d| ids_are_valid(d).err())
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
                if let Some(answered) = target
                    .lookups
                    .iter()
                    .find(|l| l.outcome == super::targets::LookupOutcome::Answered)
                    .or_else(|| target.lookups.first())
                {
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
            CheckResult::skipped(
                "another_resolver_answers",
                "another resolver knows the name",
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
                        None => CheckResult::skipped(
                            "public_names_failing_too",
                            "public names are failing too",
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
                        CheckResult::skipped(
                            "every_resolver_says_nxdomain",
                            "every resolver says it doesn't exist",
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
                        None => CheckResult::skipped(
                            "internet_reachable",
                            "the internet is reachable",
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
                        None => CheckResult::skipped(
                            "other_address_family_also_fails",
                            "the other address family fails too",
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
                    None => CheckResult::skipped(
                        "ipv6_fails_ipv4_works",
                        "ipv6 fails but ipv4 works",
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
                        None => CheckResult::skipped(
                            "clock_offset_large",
                            "our clock is more than 5 minutes off",
                            "no synchronised local NTP status available",
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
        // Everything worked. Slower than usual?
        let stages = [
            (
                "dns_stage_slow",
                "target.resolve_ms",
                Some(&target.resolve),
                "resolve",
            ),
            (
                "connect_stage_slow",
                "target.connect_ms",
                target.connect.as_ref(),
                "connect",
            ),
            (
                "tls_stage_slow",
                "target.tls_ms",
                target.tls_stage.as_ref(),
                "tls",
            ),
            (
                "server_stage_slow",
                "target.ttfb_ms",
                target.http_stage.as_ref(),
                "first byte",
            ),
        ];
        let sigmas: Vec<_> = stages
            .iter()
            .map(|(cause, metric, stage, word)| {
                let ms = stage.and_then(|s| s.ms);
                let b = base.get(target.baseline_subject(), metric);
                (
                    *cause,
                    *word,
                    ms,
                    b.and_then(|b| ms.and_then(|v| b.sigma_above(v))),
                    b.map(|b| b.mean),
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
        let (_, word, ms, _, mean) = worst.0;
        let mut ev = Evidence::new(
            format!("target.{}_ms", word.replace(' ', "_")),
            ms.unwrap_or_default(),
            "ms",
        );
        if let Some(mean) = mean {
            ev = ev.with_baseline(*mean, 0.0);
        }
        d.evidence.push(ev);
        d.evidence
            .push(Evidence::new("target.worst_stage_sigma", worst.1, "σ"));
        let stage_check = |id: &'static str, cause: &str| {
            let (_, word, ms, sigma, _) = sigmas
                .iter()
                .find(|s| s.0 == cause)
                .expect("every stage is listed");
            stage_result(id, word, *ms, *sigma, t.sigma_k)
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

    // What isn't a network fault shouldn't read like one.
    let top = d
        .causes
        .iter()
        .filter_map(|c| c.score().map(|s| (c.id.as_str(), s)))
        .max_by(|a, b| a.1.total_cmp(&b.1));
    if let Some((id, score)) = top {
        if score >= 0.6 && ["service_down", "name_does_not_exist", "service_error"].contains(&id) {
            d.severity = Severity::Info;
            d.scope.note = Some("not a network fault".into());
        }
    }
    Some(d)
}

/// One stage of a target against its baseline. Ids are literals at the call
/// site, which the catalogue scan reads.
fn stage_result(
    id: &'static str,
    word: &str,
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
            detail: format!("{:.0}ms, {s:.1}σ above baseline", ms.unwrap_or_default()),
            weight: 1.0,
        },
        Some(s) => CheckResult {
            id: id.into(),
            name,
            passed: Some(false),
            detail: format!("{s:.1}σ"),
            weight: 1.0,
        },
        None => CheckResult {
            id: id.into(),
            name,
            passed: None,
            detail: "no baseline for this stage yet".into(),
            weight: 1.0,
        },
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

// ---------------------------------------------------------------- link

fn detect_link(obs: &Observations, t: &Thresholds) -> Vec<Detection> {
    let Some(iface) = &obs.iface else {
        return vec![];
    };
    let mut out = Vec::new();

    if !iface.carrier {
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
                vec![CheckResult::skipped(
                    "wireless",
                    "wireless",
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

    if iface.errors_per_min as f64 >= t.iface_error_floor
        || iface.drops_per_min as f64 >= t.iface_drop_floor
    {
        let mut d = Detection::new(
            "iface.errors",
            Subject::Iface {
                name: iface.name.clone(),
            },
        );
        d.evidence.push(
            Evidence::new(
                "iface.error_rate",
                (iface.errors_per_min + iface.drops_per_min) as f64,
                "/min",
            )
            .with_window(60, 1),
        );
        d.causes = vec![
            Cause::new(
                "ring_buffer_small",
                "ring buffer too small for the offered rate",
                vec![if iface.drops_per_min > iface.errors_per_min {
                    CheckResult::pass(
                        "drops_dominate",
                        "drops dominate",
                        format!(
                            "{} drops vs {} errors",
                            iface.drops_per_min, iface.errors_per_min
                        ),
                    )
                } else {
                    CheckResult::fail(
                        "drops_dominate",
                        "drops dominate",
                        format!(
                            "{} drops vs {} errors",
                            iface.drops_per_min, iface.errors_per_min
                        ),
                    )
                }],
            ),
            Cause::new(
                "bad_cable_or_duplex",
                "bad cable or duplex mismatch",
                vec![if iface.errors_per_min > iface.drops_per_min {
                    CheckResult::pass(
                        "errors_dominate",
                        "errors dominate",
                        format!("{} errors this window", iface.errors_per_min),
                    )
                } else {
                    CheckResult::fail(
                        "errors_dominate",
                        "errors dominate",
                        format!("only {} errors this window", iface.errors_per_min),
                    )
                }],
            ),
        ];
        d.remediation = vec![
            Step::instruct(
                "grow the rx ring",
                format!("ethtool -G {} rx 4096", iface.name),
            ),
            Step::instruct("check for softirq drops", "cat /proc/net/softnet_stat"),
        ];
        out.push(d);
    }

    if iface.wireless {
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
                        None => CheckResult::skipped(
                            "signal_weak",
                            "signal weak",
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
                            None => CheckResult::skipped(
                                "retries_high",
                                "retries high",
                                "no retry counter",
                            ),
                        },
                        match iface.signal_dbm {
                            Some(s) if !weak => {
                                CheckResult::pass("signal_fine", "signal fine", format!("{s} dBm"))
                            }
                            Some(s) => {
                                CheckResult::fail("signal_fine", "signal fine", format!("{s} dBm"))
                            }
                            None => CheckResult::skipped(
                                "signal_fine",
                                "signal fine",
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
        None => CheckResult::skipped(
            "nothing_beyond_the_gateway_answers_either",
            "nothing beyond the gateway answers either",
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
                    None => {
                        CheckResult::skipped("arp_resolves", "arp resolves", "no arp probe has run")
                    }
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
                    None => CheckResult::skipped("arp_fails", "arp fails", "no arp probe has run"),
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
    let Some(sigma) = b.sigma_above(rtt) else {
        return vec![];
    };
    if sigma < t.sigma_k {
        return vec![];
    }

    let mut d = Detection::new("gateway.rtt_spike", Subject::Iface { name: addr.clone() });
    d.subject = Subject::Host;
    d.evidence.push(
        Evidence::new("gateway.rtt", rtt, "ms")
            .with_baseline(b.mean, b.sigma())
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
            vec![CheckResult::skipped(
                "gateway_cpu",
                "gateway cpu",
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
                    None => CheckResult::skipped(
                        "resolver_unreachable",
                        "resolver unreachable",
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
                    None => CheckResult::skipped(
                        "resolver_reachable",
                        "resolver reachable",
                        "no icmp probe of the resolver has run",
                    ),
                }],
            ),
        ];
        d.remediation = dns_remediation(dns);
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
                vec![CheckResult::skipped(
                    "edns_through_the_path",
                    "edns through the path",
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
                            CheckResult::skipped(
                                "reference_validated",
                                "reference validated",
                                "reference did not validate the answer",
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
                        CheckResult::skipped(
                            "private_answer_for_a_public_name",
                            "private answer for a public name",
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
    let over_ceiling = p50 > t.dns_ceiling_ms;
    let over_sigma = baseline
        .and_then(|b| b.sigma_above(p50))
        .map(|s| s >= t.sigma_k)
        .unwrap_or(false);

    if !over_ceiling && !over_sigma {
        return out;
    }

    let mut ev = Evidence::new("dns.rtt_p50", p50, "ms").with_window(dns.window_secs, dns.queries);
    if let Some(b) = baseline {
        ev = ev.with_baseline(b.mean, b.sigma());
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
    let icmp_normal = dns.icmp_rtt_ms.map(|r| r < 10.0);
    let cached_fast = matches!(dns.cached_rtt_ms, Some(c) if c < p50 / 4.0);

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
                    _ => CheckResult::skipped(
                        "alt_resolver_is_fast",
                        "alt resolver is fast",
                        "no alternate resolver probed",
                    )
                    .weighted(2.0),
                },
                match (icmp_normal, dns.icmp_rtt_ms) {
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
                    _ => CheckResult::skipped(
                        "resolver_itself_is_reachable",
                        "resolver itself is reachable",
                        "no icmp probe",
                    ),
                },
                match (cached_fast, dns.cached_rtt_ms) {
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
                    _ => CheckResult::skipped(
                        "cached_names_still_fast",
                        "cached names still fast",
                        "no cache probe",
                    ),
                },
            ],
        ),
        Cause::new(
            "resolver_overloaded",
            "the resolver is overloaded",
            vec![
                match (icmp_normal, dns.icmp_rtt_ms) {
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
                    _ => {
                        CheckResult::skipped("icmp_rtt_raised", "icmp rtt raised", "no icmp probe")
                    }
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
            vec![
                if alt_fast {
                    CheckResult::fail(
                        "alt_resolver_over_the_same_path_is_also_slow",
                        "alt resolver over the same path is also slow",
                        "the alternate resolver is fast over the same path",
                    )
                } else {
                    CheckResult::pass(
                        "alt_resolver_over_the_same_path_is_also_slow",
                        "alt resolver over the same path is also slow",
                        "both resolvers are slow — the problem may be local",
                    )
                },
                match obs.iface.as_ref().map(|i| i.drops_per_min) {
                    Some(d) if d > 0 => CheckResult::pass(
                        "interface_drops",
                        "interface drops",
                        format!("{d} drops this window"),
                    ),
                    Some(_) => CheckResult::fail(
                        "interface_drops",
                        "interface drops",
                        "no drops on the interface",
                    ),
                    None => CheckResult::skipped(
                        "interface_drops",
                        "interface drops",
                        "no interface counters",
                    ),
                },
            ],
        ),
    ];

    d.remediation = dns_remediation(dns);
    d.verify = Verify::below("dns.rtt_p50", 5.0, "ms").holding_for(60);
    d.scope = Scope {
        configuration: None,
        processes: vec![],
        destinations: 0,
        flows: 0,
        via_iface: None,
        processes_measured: false,
        via_resolver: Some(dns.resolver.clone()),
        note: Some("every new connection pays this before it can start".into()),
    };
    out.push(d);
    out
}

fn dns_remediation(dns: &DnsObs) -> Vec<Step> {
    let mut steps = Vec::new();
    if let Some(alt) = &dns.alt_resolver {
        let detail = match dns.alt_rtt_ms {
            Some(rtt) => format!(
                "writes resolv.conf, keeps a backup, and puts it back on quit \
                 (measured {rtt:.1}ms during the check)"
            ),
            None => "writes resolv.conf, keeps a backup, and puts it back on quit".to_string(),
        };
        steps.push(Step::apply(
            '1',
            format!("switch this session's resolver to {alt}"),
            detail,
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
    let sigma = b.sigma_above(rtt)?;
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
    d.evidence.push(
        Evidence::new("path.rtt", rtt, "ms")
            .with_baseline(b.mean, b.sigma())
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
                None => CheckResult::skipped(
                    "one_hop_dominates",
                    "one hop dominates",
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
                None => CheckResult::skipped(
                    "the_path_changed",
                    "the path changed",
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
        CheckResult::skipped(
            "loss_propagates_to_later_hops",
            "loss propagates to later hops",
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
        CheckResult::skipped(
            "later_hops_are_clean",
            "later hops are clean",
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
        None => CheckResult::skipped(
            "destination_answered_the_trace",
            "destination answered the trace",
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
    let rtt = s.rtt_ms.unwrap_or(0.0);
    let link_test_passed = match (obs.idle_rtt_ms, obs.loaded_rtt_ms) {
        (Some(idle), Some(loaded)) => Some(loaded - idle < t.loaded_rtt_delta_ms),
        _ => None,
    };

    let mut d = match verdict {
        SocketVerdict::Bufferbloat => {
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
                    None => CheckResult::skipped(
                        "link_level_bufferbloat_test_passed",
                        "link-level bufferbloat test passed",
                        "no loaded-rtt test has run, so the queue cannot be placed",
                    )
                    .weighted(2.0),
                },
                if s.tx_bps > 0.0 {
                    CheckResult::pass(
                        "rtt_tracks_this_socket_s_own_tx",
                        "rtt tracks this socket's own tx",
                        format!("{} in flight while rtt is {rtt:.0}ms", rate(s.tx_bps)),
                    )
                } else {
                    CheckResult::fail(
                        "rtt_tracks_this_socket_s_own_tx",
                        "rtt tracks this socket's own tx",
                        "socket is idle",
                    )
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
                vec![CheckResult::pass(
                    "retransmits_observed",
                    "retransmits observed",
                    format!(
                        "{} retransmits in the last minute on this socket",
                        s.retrans?
                    ),
                )],
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
            vec![CheckResult::skipped(
                "single_nat_layer",
                "single nat layer",
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
        return CheckResult::skipped(
            "the_path_to_this_peer_is_losing_packets",
            "the path to this peer is losing packets",
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
            carrier: true,
            rx_errors: 0,
            tx_errors: 0,
            rx_dropped: 0,
            tx_dropped: 0,
            errors_per_min: 0,
            drops_per_min: 0,
            link_rate_bps: None,
            wireless,
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
            tx_bps: 2.4e6,
            rx_bps: 0.0,
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
        s.tx_bps = 0.0;
        s.rx_bps = 0.0;
        s.retrans = Some(0);
        assert_eq!(
            classify_socket(&s, &Thresholds::default()),
            SocketVerdict::AppLimited,
            "high rtt with nothing in flight is just distance"
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
                carrier: false,
                rx_errors: 0,
                tx_errors: 0,
                rx_dropped: 0,
                tx_dropped: 0,
                errors_per_min: 40,
                drops_per_min: 12,
                link_rate_bps: Some(1e9),
                wireless: false,
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
        for (needle, is_cause) in [
            ("Cause::new(", true),
            ("CheckResult::pass(", false),
            ("CheckResult::fail(", false),
            ("CheckResult::skipped(", false),
            ("stage_check(", false),
        ] {
            for (at, _) in body.match_indices(needle) {
                let rest = body[at + needle.len()..].trim_start();
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
            ..Default::default()
        };
        let json = serde_json::to_string(&obs).unwrap();
        assert_eq!(serde_json::from_str::<Observations>(&json).unwrap(), obs);
        // A recording from before a field existed still loads.
        let old: Observations = serde_json::from_str(r#"{"now":"2026-09-14 10:00:00"}"#).unwrap();
        assert_eq!(old.now, "2026-09-14 10:00:00");
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

    fn healthy() -> TargetObs {
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
        assert_eq!(d.scope.note.as_deref(), Some("not a network fault"));
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
    fn an_untrusted_issuer_behind_a_proxy_reads_as_interception() {
        let mut t = healthy();
        t.tls_stage = err(StageError::CertUntrusted);
        t.http_stage = None;
        t.context.proxy_env = true;
        let d = detect_one(t);
        assert_eq!(d.causes[0].id, "tls_intercepting_proxy");
    }

    #[test]
    fn a_503_is_the_service_not_the_network() {
        let mut t = healthy();
        t.http_stage = err(StageError::HttpStatus { status: 503 });
        t.status = Some(503);
        let d = detect_one(t);
        assert_eq!(d.rule, "target.http_error");
        assert_eq!(d.causes[0].id, "service_error");
        assert_eq!(d.severity, Severity::Info);
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
    }
}
