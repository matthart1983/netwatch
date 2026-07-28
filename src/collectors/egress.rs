//! Observe-mode egress profiling (Horizon 3, phase 0).
//!
//! Builds per-process profiles of *what each program talks to* by joining
//! three signals that otherwise live apart:
//!   - the process name + remote endpoint (from the connection table),
//!   - the destination hostname (TLS/QUIC SNI from the ClientHello, or the
//!     cleartext HTTP `Host`), and
//!   - the destination's autonomous-system org (from the geo/ASN database).
//!
//! This is the learned baseline the egress policy linter is authored from
//! ("observe → promote → warn on drift"). It is **observe only** — it
//! records what egress looks like, it never blocks. SNI is cleartext in the
//! ClientHello, so meaningful profiles form on the vast majority of traffic
//! with no decryption and no keylog.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::connections::Connection;
use super::geo::{is_private_ip, GeoCache};
use crate::dpi::AppProtocol;

/// Cap on distinct processes profiled. A fork-storm of short-lived
/// process names can't grow the map without bound.
pub(crate) const MAX_PROCESSES: usize = 256;
/// Length at which the kernel truncates a process's `comm`. PKTAP carries
/// `pth_comm[MAXCOMLEN+1]` on macOS and procfs `comm` is `TASK_COMM_LEN-1`
/// on Linux, while `lsof` reports the untruncated name — so the same program
/// arrives under two spellings depending on which attribution source won the
/// tick, and gets two profiles. A name of exactly this length is therefore
/// *suspected* truncation; see `canonical_process`.
#[cfg(target_os = "macos")]
const COMM_TRUNCATE_LEN: usize = 16;
#[cfg(not(target_os = "macos"))]
const COMM_TRUNCATE_LEN: usize = 15;
/// Samples kept per destination for the inline activity sparkline — one
/// per connection tick, so roughly the last minute at the 1 s default.
pub(crate) const ACTIVITY_SAMPLES: usize = 40;
/// Cap on distinct destinations tracked per process.
const MAX_DESTS_PER_PROCESS: usize = 128;
/// Re-warn at most this often for the same (process, destination, port)
/// policy violation, so a continuously-violating flow doesn't alert-storm.
const VIOLATION_COOLDOWN_SECS: u64 = 300;
/// Persisted destinations not seen for this long are dropped at load time,
/// so the baseline ages out instead of accreting forever.
const STALE_DEST_SECS: u64 = 30 * 24 * 3600;
/// Write the learned baseline to disk at most this often (plus once at quit).
const PERSIST_INTERVAL_SECS: u64 = 60;
/// Under `strict = true`, how many observation ticks (~1 s each) a process
/// must persist before its lack of a rule is reported.
///
/// Set low on purpose. The noise it exists to suppress is a fork storm of
/// short-lived build tooling, each member appearing for a single tick; the
/// thing it must *not* suppress is a burst of exfiltration, which cannot
/// move meaningful volume in under a few seconds. Erring high would trade
/// the feature's whole point for tidiness.
const UNDECLARED_SETTLE_TICKS: u64 = 3;
/// Schema tag stamped on the NDJSON export's `_meta` line. Bump the minor
/// when adding fields (additive/back-compatible), the major on a breaking
/// change — the managed ingest keys off this.
pub const EGRESS_EXPORT_SCHEMA: &str = "netwatch.egress.v1.1";

/// One observed destination for a process.
#[derive(Clone, Debug)]
pub struct EgressDest {
    /// Destination hostname — TLS/QUIC SNI, or cleartext HTTP `Host`. `None`
    /// when the flow carried no name we could read (e.g. raw-IP traffic).
    pub sni: Option<String>,
    /// Autonomous-system organization of the remote IP (e.g. `Google LLC`),
    /// when the ASN database resolved it.
    pub asn_org: Option<String>,
    pub port: u16,
    /// Most recent remote IP observed for this destination. Always populated
    /// (an SNI/CDN destination fronts many IPs; this is the last one seen).
    /// Shown so a nameless row isn't a useless "(ip)" placeholder, and so the
    /// export carries the concrete endpoint.
    pub last_ip: String,
    /// True when this destination was (ever) reached with an Encrypted
    /// ClientHello — the inner SNI is hidden by design, so a policy miss on
    /// this row may be "name unreadable", not real drift. Sticky once seen.
    pub ech: bool,
    /// Wall-clock times, not `Instant`: the evidence a human reviews at
    /// promote time ("known for 3 weeks" vs "showed up 40 seconds ago")
    /// must survive restarts, and the persisted baseline serializes them.
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    /// Number of observations (connection-refresh ticks this dest appeared).
    ///
    /// Because `observe` runs once per ~1 s connection tick, this is really a
    /// *dwell time in ticks*, not an event count — a single long-lived
    /// connection accrues one per second it stays open. The UI renders it as
    /// a duration for exactly that reason; don't relabel it "hits".
    pub count: u64,
    /// Bytes attributed to this destination, accumulated from the per-tick
    /// rates on the connection table (`rate × elapsed`). Approximate by
    /// construction — the rates are themselves per-tick averages — and only
    /// populated when packet capture is running, since that is what produces
    /// the rates. Zero with no capture, which the UI shows as `—` rather
    /// than a misleading 0 B.
    pub bytes_out: u64,
    pub bytes_in: u64,
    /// Recent per-tick outbound bytes, newest last, for the inline
    /// sparkline. Bounded to `ACTIVITY_SAMPLES`. Deliberately not persisted
    /// — it is a live-session signal, and restoring one would be a lie
    /// about what is happening now.
    pub activity: VecDeque<u64>,
}

/// Identity of a destination within a process profile: the most specific
/// name available (SNI → ASN org → raw IP) paired with the port. Mirrors the
/// roadmap's rule granularity — prefer SNI, fall back to ASN, avoid raw IP.
/// `(label, port)`, where `label` is `sni.or(asn_org).unwrap_or(ip)` at the
/// moment the destination was first seen.
///
/// The label is not a redundant copy of the fields below it — when a
/// destination has neither an SNI nor an ASN, it is the *only* surviving
/// record of the address it was learned from, and both `load_profiles` and
/// the Egress table fall back to it to repair rows whose `last_ip` is blank.
/// Don't "simplify" it away.
type DestKey = (String, u16);

/// How a destination stands against the declared policy.
///
/// The distinction that matters is `Sni`/`Ip` versus `Asn`. A hostname or
/// address match is a statement about *one endpoint*; an autonomous-system
/// match admits everything that AS operates, which for a hyperscaler is
/// effectively unbounded. Collapsing both into a single "ok" is what let a
/// promoted rule quietly allow all of Google Cloud, so they are separate
/// states and render differently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Matched a declared hostname — precise.
    Sni,
    /// Matched a declared IP — precise.
    Ip,
    /// Matched only by autonomous system — broad. Carries the org so the UI
    /// can name what was actually admitted.
    Asn(String),
    /// Encrypted ClientHello: the real name is hidden by design, so this is
    /// "cannot judge", not "bad".
    Ech,
    /// Outside the allowlist.
    Drift,
    /// The process has no rule, so nothing was checked. Distinct from
    /// `NoPolicy` — here the operator has a policy and simply never declared
    /// this program.
    NoRule,
    /// The process has no rule and the policy claims to be complete
    /// (`strict = true`), so the absence *is* the finding. Distinct from
    /// `NoRule`, which is the same fact without the claim: unchecked versus
    /// checked-and-unexpected.
    Undeclared,
    /// No policy loaded at all; observe-only.
    NoPolicy,
}

impl Verdict {
    /// Short glyph + label for the table's verdict column.
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Sni => "\u{2713} sni",
            Verdict::Ip => "\u{2713} ip",
            Verdict::Asn(_) => "~ asn",
            Verdict::Ech => "? ech",
            Verdict::Drift => "\u{2717} drift",
            Verdict::NoRule => "\u{2014} no rule",
            Verdict::Undeclared => "\u{2717} undeclared",
            Verdict::NoPolicy => "\u{2014}",
        }
    }
    /// True for states the operator should look at: broad matches and
    /// outright drift. Drives colour and the header tally.
    pub fn is_notable(&self) -> bool {
        matches!(
            self,
            Verdict::Asn(_) | Verdict::Drift | Verdict::NoRule | Verdict::Undeclared
        )
    }
}

/// Per-process egress profile: the set of distinct destinations observed.
#[derive(Clone, Debug)]
pub struct EgressProfile {
    pub process: String,
    pub dests: HashMap<DestKey, EgressDest>,
    pub last_seen: SystemTime,
}

/// One attributed egress flow-summary plus its policy verdict — the unit of
/// the structured export (`netwatch.egress.v1`). Metadata only; no payload.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EgressRecord {
    pub process: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn_org: Option<String>,
    /// Most recent concrete remote IP for this destination.
    pub ip: String,
    pub port: u16,
    /// Coarse L7 class: `tls` when a ClientHello named the destination,
    /// else `other`. Kept coarse on purpose — no payload inspection.
    pub proto: String,
    pub ech: bool,
    /// Unix seconds.
    pub first_seen: u64,
    pub last_seen: u64,
    pub count: u64,
    /// Policy verdict at export time: `ok` | `drift` | `unreadable` (ECH,
    /// name hidden) | `unchecked` (no rule for this process, observe mode) |
    /// `undeclared` (no rule, under a policy declaring itself complete).
    pub verdict: String,
    /// Which dimension admitted an `ok` verdict — `sni` | `ip` | `asn`.
    /// `None` for anything not admitted.
    ///
    /// Additive in schema v1.1. This is the breadth signal: `asn` means the
    /// rule admitted an entire autonomous system, not one endpoint, so a
    /// consumer can distinguish a precise allowlist from a rule that lets
    /// through everything a hyperscaler operates.
    pub matched_by: Option<String>,
    /// Bytes attributed to this destination. Approximate (derived from
    /// per-tick rates) and zero when packet capture isn't running.
    pub bytes_out: u64,
    pub bytes_in: u64,
}

/// A flow that violated a declared egress rule. Surfaced as a warning —
/// the linter never blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub process: String,
    /// The destination identity that violated — SNI, ASN org, or IP.
    pub dest: String,
    pub port: u16,
    pub reason: String,
}

/// A retained violation for on-screen display (the Egress tab shows these,
/// separate from the drained `pending` queue that feeds the alert stream).
#[derive(Clone, Debug)]
pub struct RecentViolation {
    pub process: String,
    pub dest: String,
    pub port: u16,
    pub reason: String,
    pub when: SystemTime,
}

/// How many recent violations to retain for the on-screen warnings panel.
const RECENT_VIOLATIONS_CAP: usize = 100;

/// Accumulates per-process egress profiles across connection refreshes, and
/// (when a policy is loaded) flags flows that drift from the declared rules.
pub struct EgressProfiler {
    profiles: HashMap<String, EgressProfile>,
    /// Declared egress policy, if any. `None` ⇒ pure observe mode.
    policy: Option<EgressPolicy>,
    /// Cooldown per violating (process, dest, port) so a steady violation
    /// warns periodically, not every tick. Configurable via
    /// `egress_violation_cooldown_secs` in config.toml.
    violation_cooldown: HashMap<(String, String, u16), Instant>,
    cooldown: Duration,
    /// Newly-detected violations awaiting drain by the caller.
    pending: Vec<Violation>,
    /// Retained recent violations for the on-screen warnings panel (bounded
    /// ring). Distinct from `pending`, which the caller drains each tick.
    recent: std::collections::VecDeque<RecentViolation>,
    /// When `observe` last ran, so byte deltas can be derived from rates.
    last_observe: Option<Instant>,
    /// Cumulative violation count per process (post-cooldown, so it tracks
    /// the alert stream). Bounded: only processes with a declared rule can
    /// violate. Feeds `netwatch_policy_violations_total` on /metrics.
    violation_totals: HashMap<String, u64>,
    /// Last time the baseline was written to disk (rate-limits `maybe_persist`).
    last_persist: Option<Instant>,
}

impl Default for EgressProfiler {
    fn default() -> Self {
        Self {
            profiles: HashMap::new(),
            policy: None,
            violation_cooldown: HashMap::new(),
            cooldown: Duration::from_secs(VIOLATION_COOLDOWN_SECS),
            pending: Vec::new(),
            recent: std::collections::VecDeque::new(),
            last_observe: None,
            violation_totals: HashMap::new(),
            last_persist: None,
        }
    }
}

impl EgressProfiler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the per-flow re-warn cooldown (config:
    /// `egress_violation_cooldown_secs`; 0 ⇒ warn on every tick).
    pub fn set_violation_cooldown(&mut self, secs: u64) {
        self.cooldown = Duration::from_secs(secs);
    }

    /// Construct and load both the declared policy and the persisted learned
    /// baseline from their default paths, when present. A 20-minute session
    /// isn't a baseline — the profiles carry across restarts.
    pub fn with_default_policy() -> Self {
        let mut profiler = Self::new();
        if let Some(path) = default_policy_path() {
            profiler.set_policy(load_policy_file(&path));
        }
        if let Some(path) = default_profiles_path() {
            profiler.load_profiles(&path);
        }
        profiler
    }

    /// Fold the current connection table into the profiles. Call once per
    /// connection refresh. Only external (non-private) destinations that have
    /// an owning process are recorded — egress to the public internet is the
    /// thing we baseline; LAN/loopback chatter isn't.
    pub fn observe(&mut self, connections: &[Connection], geo: &GeoCache) {
        let now = Instant::now();
        let wall = SystemTime::now();
        // Seconds since the previous observe, used to turn the connection
        // table's per-second rates into a byte delta for this tick. Clamped:
        // a long stall (laptop sleep, a slow lsof) must not credit a
        // destination with minutes of traffic it may not have sent.
        let elapsed = self
            .last_observe
            .map(|t| now.duration_since(t).as_secs_f64().clamp(0.0, 5.0))
            .unwrap_or(0.0);
        self.last_observe = Some(now);
        for conn in connections {
            let Some(process) = conn.process_name.as_deref() else {
                continue;
            };
            if process.is_empty() {
                continue;
            }
            let (Some(ip), Some(port_str)) = crate::app::parse_addr_parts(&conn.remote_addr) else {
                continue;
            };
            // Belt and braces with `parse_addr_parts`, which no longer yields
            // an empty host — but `is_private_ip("")` is false, so an empty IP
            // would otherwise clear every guard here and be recorded as a real
            // destination with no name and no address.
            if ip.is_empty() || is_private_ip(&ip) {
                continue;
            }
            let Ok(port) = port_str.parse::<u16>() else {
                continue;
            };

            let sni = dest_hostname(&conn.app_protocol);
            let ech = flow_ech(&conn.app_protocol);
            let asn_org = geo.lookup(&ip).map(|g| g.org).filter(|o| !o.is_empty());
            // Rates are present only while packet capture is running, so
            // without it these stay zero and the UI shows "—" rather than a
            // confident 0 B.
            let out = (conn.tx_rate.unwrap_or(0.0) * elapsed).max(0.0) as u64;
            let inb = (conn.rx_rate.unwrap_or(0.0) * elapsed).max(0.0) as u64;
            self.record_flow(
                process,
                &ip,
                port,
                sni.clone(),
                asn_org.clone(),
                ech,
                wall,
                out,
                inb,
            );
            self.check_policy(process, &ip, port, &sni, &asn_org, ech, now);
        }
        self.evict_processes_if_needed();
        // Drop expired cooldown entries so the map stays bounded.
        let cooldown = self.cooldown;
        self.violation_cooldown
            .retain(|_, &mut t| now.duration_since(t) < cooldown);
    }

    /// Compare one observed flow against the loaded policy.
    ///
    /// By default only processes that *have* a declared rule are checked — an
    /// unlisted process has no rule to violate, so it never warns
    /// (deterministic, low-noise). Under `strict = true` the policy claims to
    /// be complete, so an undeclared process is itself the finding. A new
    /// violation is queued (subject to the per-flow cooldown).
    #[allow(clippy::too_many_arguments)]
    fn check_policy(
        &mut self,
        process: &str,
        ip: &str,
        port: u16,
        sni: &Option<String>,
        asn_org: &Option<String>,
        ech: bool,
        now: Instant,
    ) {
        // A policy may be authored against either spelling of a truncated
        // name — the user promoted whichever one the baseline held. Try the
        // observed name first, then its canonical form, so a flow attributed
        // under the truncated `comm` still matches a rule declared under the
        // full name (and vice versa). Computed before borrowing the policy.
        let canonical = self.canonical_process(process);
        // Under strict mode, has this process been around long enough to be
        // worth reporting? Computed before the policy borrow.
        let settled = self.process_is_settled(process);
        let Some(policy) = &self.policy else {
            return;
        };
        let rule = policy
            .process
            .get(process)
            .or_else(|| policy.process.get(canonical.as_str()));
        let mut reason = match rule {
            Some(rule) => match rule.violation(sni.as_deref(), asn_org.as_deref(), ip, port) {
                Some(r) => r,
                None => return,
            },
            // No rule. In observe mode that is silence by design; in strict
            // mode it is the whole point of the feature.
            None => {
                if !policy.strict || !settled {
                    return;
                }
                format!("{process} has no rule in the egress policy")
            }
        };
        // An ECH flow's inner SNI is hidden by design — the miss may be
        // "name unreadable", not real drift. Say so in the alert.
        if ech && sni.is_none() {
            reason.push_str(" (ECH — real name encrypted)");
        }
        let dest = sni
            .clone()
            .or_else(|| asn_org.clone())
            .unwrap_or_else(|| ip.to_string());

        let key = (process.to_string(), dest.clone(), port);
        if let Some(&last) = self.violation_cooldown.get(&key) {
            if now.duration_since(last) < self.cooldown {
                return;
            }
        }
        self.violation_cooldown.insert(key, now);
        *self
            .violation_totals
            .entry(process.to_string())
            .or_insert(0) += 1;
        self.pending.push(Violation {
            process: process.to_string(),
            dest: dest.clone(),
            port,
            reason: reason.clone(),
        });
        // Retain for the on-screen warnings panel (bounded ring).
        self.recent.push_front(RecentViolation {
            process: process.to_string(),
            dest,
            port,
            reason,
            when: SystemTime::now(),
        });
        self.recent.truncate(RECENT_VIOLATIONS_CAP);
    }

    /// Whether a process has been observed long enough for strict mode to
    /// report it as undeclared.
    ///
    /// `count` is dwell in observation ticks, so the longest-lived
    /// destination is how long the process has been talking. Because the
    /// baseline persists, a program seen for hours in a previous session is
    /// settled immediately on restart — which is right: it is not new.
    fn process_is_settled(&self, process: &str) -> bool {
        self.profiles
            .get(process)
            .is_some_and(|p| p.dests.values().any(|d| d.count >= UNDECLARED_SETTLE_TICKS))
    }

    /// Recent violations retained for the on-screen warnings panel, newest
    /// first. Independent of `take_violations` (which drains the alert feed).
    pub fn recent_violations(&self) -> impl Iterator<Item = &RecentViolation> {
        self.recent.iter()
    }

    /// Number of retained recent violations.
    pub fn recent_violation_count(&self) -> usize {
        self.recent.len()
    }

    /// Install (or clear) the declared egress policy.
    pub fn set_policy(&mut self, policy: Option<EgressPolicy>) {
        self.policy = policy;
    }

    /// Whether a policy is currently loaded.
    pub fn has_policy(&self) -> bool {
        self.policy.is_some()
    }

    /// Policy verdict for one observed destination, for display: `None` when
    /// no policy is loaded or the process has no rule (nothing to check),
    /// `Some(true)` when allowed, `Some(false)` when it drifts.
    pub fn dest_allowed(&self, process: &str, dest: &EgressDest) -> Option<bool> {
        match self.verdict(process, dest) {
            Verdict::NoPolicy | Verdict::NoRule => None,
            // ECH is a policy *miss* whose cause is an encrypted name. It
            // stays `false` here so the export keeps reporting it as
            // "unreadable"; only the presentation differs from real drift.
            // `Undeclared` is a miss too — under a policy that claims to be
            // complete, "no rule" is a finding rather than a blind spot.
            Verdict::Drift | Verdict::Ech | Verdict::Undeclared => Some(false),
            _ => Some(true),
        }
    }

    /// Full verdict for a destination, naming *why* it passed.
    ///
    /// `dest_allowed` flattens this to a bool for callers that only need
    /// pass/fail; the UI wants the reason, because "matched a hostname" and
    /// "matched an entire autonomous system" are very different assurances.
    pub fn verdict(&self, process: &str, dest: &EgressDest) -> Verdict {
        let Some(policy) = self.policy.as_ref() else {
            return Verdict::NoPolicy;
        };
        // Same both-spellings lookup as `check_policy`, so the table verdict
        // and the warnings panel can never disagree about a truncated name.
        let canonical = self.canonical_process(process);
        let Some(rule) = policy
            .process
            .get(process)
            .or_else(|| policy.process.get(canonical.as_str()))
        else {
            // Same fact, two readings: unchecked when the policy is partial,
            // a finding when it claims to be complete.
            return if policy.strict {
                Verdict::Undeclared
            } else {
                Verdict::NoRule
            };
        };
        if rule
            .violation(
                dest.sni.as_deref(),
                dest.asn_org.as_deref(),
                &dest.last_ip,
                dest.port,
            )
            .is_some()
        {
            // An ECH flow's inner name is encrypted, so a miss is "can't
            // read it", not "shouldn't be there".
            return if dest.ech && dest.sni.is_none() {
                Verdict::Ech
            } else {
                Verdict::Drift
            };
        }
        // Admitted — report the most precise dimension that did it, in the
        // same order `violation` checks them.
        if dest
            .sni
            .as_deref()
            .is_some_and(|h| rule.allow_sni.iter().any(|p| sni_matches(p, h)))
        {
            return Verdict::Sni;
        }
        if rule.allow_ip.iter().any(|x| x == &dest.last_ip) {
            return Verdict::Ip;
        }
        if let Some(org) = dest.asn_org.as_deref() {
            if rule.allow_asn.iter().any(|x| x.eq_ignore_ascii_case(org)) {
                return Verdict::Asn(org.to_string());
            }
        }
        // Admitted because the rule declares no name restriction at all.
        Verdict::Sni
    }

    /// Drain the violations detected since the last call.
    pub fn take_violations(&mut self) -> Vec<Violation> {
        std::mem::take(&mut self.pending)
    }

    /// Ratify the current observed baseline into a declared policy — the
    /// "promote" step. The human reviews/edits the result before trusting
    /// it; that review is what defeats baseline poisoning (a profile learned
    /// on an already-compromised host).
    pub fn promote(&self) -> EgressPolicy {
        let mut policy = EgressPolicy::default();
        for profile in self.profiles.values() {
            policy
                .process
                .insert(profile.process.clone(), rule_from_profile(profile));
        }
        policy
    }

    /// Ratify a single process's observed baseline — selective promotion, so
    /// a reviewed rule can be adopted without blessing every other process's
    /// traffic along with it. `None` if the process has no profile.
    pub fn promote_one(&self, process: &str) -> Option<ProcessRule> {
        self.profiles.get(process).map(rule_from_profile)
    }

    /// The currently-declared rule for a process, if any (for promote diffs).
    pub fn declared_rule(&self, process: &str) -> Option<&ProcessRule> {
        self.policy.as_ref()?.process.get(process)
    }

    /// Record one observed (process, destination) pair. Split out from
    /// `observe` so the join/key/eviction logic is testable without the geo
    /// resolver. The destination identity prefers the most specific name we
    /// have: SNI, then ASN org, then the raw IP.
    /// Test-facing shorthand for `record_flow` with `ech: false`.
    #[cfg(test)]
    fn record(
        &mut self,
        process: &str,
        ip: &str,
        port: u16,
        sni: Option<String>,
        asn_org: Option<String>,
        now: SystemTime,
    ) {
        self.record_flow(process, ip, port, sni, asn_org, false, now, 0, 0);
    }

    #[allow(clippy::too_many_arguments)]
    fn record_flow(
        &mut self,
        process: &str,
        ip: &str,
        port: u16,
        sni: Option<String>,
        asn_org: Option<String>,
        ech: bool,
        now: SystemTime,
        bytes_out: u64,
        bytes_in: u64,
    ) {
        let label = sni
            .clone()
            .or_else(|| asn_org.clone())
            .unwrap_or_else(|| ip.to_string());
        self.upsert(
            process,
            (label, port),
            sni,
            asn_org,
            port,
            ip,
            ech,
            now,
            bytes_out,
            bytes_in,
        );
    }

    /// Resolve the profile key for an observed process name, folding a
    /// kernel-truncated `comm` into the full name when we've already seen it.
    ///
    /// Only a name of exactly `COMM_TRUNCATE_LEN` bytes is a truncation
    /// candidate — that's the one length the kernel could have cut. A shorter
    /// name is complete and must never be merged, which is what keeps VS
    /// Code's `Code Helper` (11 bytes, a real distinct process) separate from
    /// `Code Helper (Plu` (16 bytes, truncated `Code Helper (Plugin)`).
    ///
    /// When several known names share the prefix the truncation is genuinely
    /// ambiguous (`Google Chrome Helper` vs `Google Chrome Helper (GPU)` both
    /// truncate to `Google Chrome He`). Pick the shortest match so the choice
    /// is deterministic across runs rather than HashMap-order dependent.
    fn canonical_process(&self, process: &str) -> String {
        if process.len() != COMM_TRUNCATE_LEN {
            return process.to_string();
        }
        self.profiles
            .keys()
            .filter(|k| k.len() > process.len() && k.starts_with(process))
            .min_by(|a, b| {
                a.len()
                    .cmp(&b.len())
                    .then_with(|| a.as_str().cmp(b.as_str()))
            })
            .cloned()
            .unwrap_or_else(|| process.to_string())
    }

    /// Fold an existing truncated profile into `full` when the untruncated
    /// name shows up later. Called when a longer name arrives and a profile
    /// keyed by its truncated form already exists — without this the merge
    /// only works in one direction and the split survives whichever order the
    /// two spellings happened to appear in.
    fn absorb_truncated(&mut self, full: &str) {
        if full.len() <= COMM_TRUNCATE_LEN {
            return;
        }
        let truncated = match full.get(..COMM_TRUNCATE_LEN) {
            Some(t) => t.to_string(),
            // Not a char boundary — a multi-byte name the kernel would have
            // cut mid-character. Leave it alone rather than guess.
            None => return,
        };
        // Only fold when `full` is the name the truncation most plausibly
        // belongs to. Ambiguity is resolved the same way as
        // `canonical_process`: shortest candidate wins, ties broken
        // alphabetically, so the choice is stable across runs. `full` is a
        // candidate whether or not it already has a profile — it usually
        // doesn't yet, since this runs on the way to creating it.
        let shortest_claimant = self
            .profiles
            .keys()
            .map(String::as_str)
            .filter(|k| k.len() > COMM_TRUNCATE_LEN && k.starts_with(&truncated))
            .chain(std::iter::once(full))
            .min_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
        if shortest_claimant != Some(full) {
            return;
        }
        let Some(old) = self.profiles.remove(&truncated) else {
            return;
        };
        let target = self
            .profiles
            .entry(full.to_string())
            .or_insert_with(|| EgressProfile {
                process: full.to_string(),
                dests: HashMap::new(),
                last_seen: old.last_seen,
            });
        target.last_seen = target.last_seen.max(old.last_seen);
        for (key, dest) in old.dests {
            match target.dests.get_mut(&key) {
                // Same destination under both spellings: keep one row with
                // the summed hit count and the widest time span.
                Some(existing) => {
                    existing.count += dest.count;
                    existing.first_seen = existing.first_seen.min(dest.first_seen);
                    existing.last_seen = existing.last_seen.max(dest.last_seen);
                    existing.ech |= dest.ech;
                    if existing.sni.is_none() {
                        existing.sni = dest.sni;
                    }
                    if existing.asn_org.is_none() {
                        existing.asn_org = dest.asn_org;
                    }
                    if existing.last_ip.is_empty() {
                        existing.last_ip = dest.last_ip;
                    }
                }
                None => {
                    if target.dests.len() < MAX_DESTS_PER_PROCESS {
                        target.dests.insert(key, dest);
                    }
                }
            }
        }
        // Violation tallies follow the profile, or the counter resets to zero
        // the moment the two spellings merge.
        if let Some(n) = self.violation_totals.remove(&truncated) {
            *self.violation_totals.entry(full.to_string()).or_insert(0) += n;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn upsert(
        &mut self,
        process: &str,
        key: DestKey,
        sni: Option<String>,
        asn_org: Option<String>,
        port: u16,
        ip: &str,
        ech: bool,
        now: SystemTime,
        bytes_out: u64,
        bytes_in: u64,
    ) {
        // Fold kernel-truncated and untruncated spellings of the same program
        // onto one key, in whichever order they arrive.
        self.absorb_truncated(process);
        let process = self.canonical_process(process);
        let process = process.as_str();

        let profile = self
            .profiles
            .entry(process.to_string())
            .or_insert_with(|| EgressProfile {
                process: process.to_string(),
                dests: HashMap::new(),
                last_seen: now,
            });
        profile.last_seen = now;

        if let Some(dest) = profile.dests.get_mut(&key) {
            dest.last_seen = now;
            dest.count += 1;
            dest.ech |= ech;
            // Only ever upgrade the endpoint. A flow whose address we couldn't
            // read must not downgrade a destination we already know the IP for
            // — that turned named rows into blank ones on disk.
            if !ip.is_empty() {
                dest.last_ip = ip.to_string();
            }
            dest.bytes_out = dest.bytes_out.saturating_add(bytes_out);
            dest.bytes_in = dest.bytes_in.saturating_add(bytes_in);
            dest.activity.push_back(bytes_out);
            while dest.activity.len() > ACTIVITY_SAMPLES {
                dest.activity.pop_front();
            }
            // Backfill a name/ASN that wasn't resolved on first sight (SNI
            // appears once the ClientHello is parsed; ASN once geo resolves).
            if dest.sni.is_none() {
                dest.sni = sni;
            }
            if dest.asn_org.is_none() {
                dest.asn_org = asn_org;
            }
            return;
        }

        if profile.dests.len() >= MAX_DESTS_PER_PROCESS {
            if let Some(oldest) = profile
                .dests
                .iter()
                .min_by_key(|(_, d)| d.last_seen)
                .map(|(k, _)| k.clone())
            {
                profile.dests.remove(&oldest);
            }
        }
        profile.dests.insert(
            key,
            EgressDest {
                sni,
                asn_org,
                port,
                last_ip: ip.to_string(),
                ech,
                first_seen: now,
                last_seen: now,
                count: 1,
                bytes_out,
                bytes_in,
                activity: VecDeque::from(vec![bytes_out]),
            },
        );
    }

    /// Cumulative post-cooldown violation counts per process, sorted by
    /// process name — the `netwatch_policy_violations_total` series.
    pub fn violation_totals_sorted(&self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = self
            .violation_totals
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    fn evict_processes_if_needed(&mut self) {
        while self.profiles.len() > MAX_PROCESSES {
            if let Some(oldest) = self
                .profiles
                .iter()
                .min_by_key(|(_, p)| p.last_seen)
                .map(|(k, _)| k.clone())
            {
                self.profiles.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// Number of processes with a profile (drives the debug overlay).
    pub fn process_count(&self) -> usize {
        self.profiles.len()
    }

    /// Total distinct destinations across all profiles.
    pub fn dest_count(&self) -> usize {
        self.profiles.values().map(|p| p.dests.len()).sum()
    }

    /// Borrowed view of the profiles, sorted by process name.
    ///
    /// `snapshot` clones every profile, which the Egress tab used to do once
    /// per frame; the tree view borrows instead so rendering allocates
    /// nothing beyond the row list.
    pub fn profiles_ref(&self) -> Vec<&EgressProfile> {
        let mut out: Vec<&EgressProfile> = self.profiles.values().collect();
        out.sort_by(|a, b| a.process.cmp(&b.process));
        out
    }

    /// Snapshot of all profiles, sorted by process name. Each profile's
    /// destinations can be sorted by the caller; the map is returned as-is.
    pub fn snapshot(&self) -> Vec<EgressProfile> {
        let mut out: Vec<EgressProfile> = self.profiles.values().cloned().collect();
        out.sort_by(|a, b| a.process.cmp(&b.process));
        out
    }

    // ── Structured export (the cloud-ingest seam) ───────────────────────

    /// One exported egress record: an attributed flow-summary plus the
    /// current policy verdict. This is the schema the managed layer ingests
    /// — the seam between the OSS linter and the product. Versioned via the
    /// leading `_meta` line the NDJSON writer emits.
    ///
    /// Deliberately the same fields the tab shows; no raw payload, ever —
    /// metadata-only is the whole point of the redaction posture.
    pub fn export_records(&self) -> Vec<EgressRecord> {
        let mut out = Vec::new();
        for profile in self.snapshot() {
            for dest in profile.dests.values() {
                let v = self.verdict(&profile.process, dest);
                let verdict = match &v {
                    Verdict::Ech => "unreadable",
                    Verdict::Drift => "drift",
                    // Its own value, not folded into `drift`: nothing was
                    // compared, so calling it drift would overstate what the
                    // linter knows. A consumer that wants findings takes
                    // `drift | undeclared`.
                    Verdict::Undeclared => "undeclared",
                    Verdict::NoRule | Verdict::NoPolicy => "unchecked",
                    _ => "ok",
                }
                .to_string();
                let matched_by = match &v {
                    Verdict::Sni => Some("sni".to_string()),
                    Verdict::Ip => Some("ip".to_string()),
                    Verdict::Asn(_) => Some("asn".to_string()),
                    _ => None,
                };
                out.push(EgressRecord {
                    process: profile.process.clone(),
                    sni: dest.sni.clone(),
                    asn_org: dest.asn_org.clone(),
                    ip: dest.last_ip.clone(),
                    port: dest.port,
                    proto: if dest.sni.is_some() { "tls" } else { "other" }.to_string(),
                    ech: dest.ech,
                    first_seen: unix_secs(dest.first_seen),
                    last_seen: unix_secs(dest.last_seen),
                    count: dest.count,
                    verdict,
                    matched_by,
                    bytes_out: dest.bytes_out,
                    bytes_in: dest.bytes_in,
                });
            }
        }
        // Stable order (process, then destination label) so a diff of two
        // exports is meaningful.
        out.sort_by(|a, b| {
            a.process
                .cmp(&b.process)
                .then_with(|| a.sni.cmp(&b.sni))
                .then_with(|| a.port.cmp(&b.port))
        });
        out
    }

    /// Write the attributed egress records as NDJSON: one JSON object per
    /// line, preceded by a `_meta` line naming the schema version. NDJSON so
    /// the managed collector can stream-parse it line-by-line. Returns the
    /// number of flow records written (excludes the meta line).
    pub fn export_ndjson(&self, path: &Path) -> std::io::Result<usize> {
        use std::io::Write as _;
        let records = self.export_records();
        let file = std::fs::File::create(path)?;
        let mut w = std::io::BufWriter::new(file);
        let meta = serde_json::json!({
            "_meta": { "schema": EGRESS_EXPORT_SCHEMA, "records": records.len() }
        });
        writeln!(w, "{meta}")?;
        for rec in &records {
            let line = serde_json::to_string(rec)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            writeln!(w, "{line}")?;
        }
        w.flush()?;
        Ok(records.len())
    }

    // ── Baseline persistence ────────────────────────────────────────────

    /// Write the learned baseline to the default path if one is due
    /// (rate-limited). Call from the observe tick; cheap when not due.
    pub fn maybe_persist(&mut self) {
        let due = self
            .last_persist
            .is_none_or(|t| t.elapsed() >= Duration::from_secs(PERSIST_INTERVAL_SECS));
        if due {
            self.persist_now();
        }
    }

    /// Write the learned baseline to the default path immediately (quit path).
    pub fn persist_now(&mut self) {
        let Some(path) = default_profiles_path() else {
            return;
        };
        if let Err(e) = self.save_profiles(&path) {
            tracing::warn!(target: "netwatch::egress", path = %path.display(), error = %e, "egress baseline save failed");
        }
        self.last_persist = Some(Instant::now());
    }

    /// Serialize the learned baseline to `path` as versioned JSON.
    pub fn save_profiles(&self, path: &Path) -> std::io::Result<()> {
        let persisted = PersistedProfiles {
            version: 1,
            profiles: self
                .profiles
                .values()
                .map(|p| PersistedProfile {
                    process: p.process.clone(),
                    dests: p
                        .dests
                        .iter()
                        .map(|((label, port), d)| PersistedDest {
                            label: label.clone(),
                            port: *port,
                            sni: d.sni.clone(),
                            asn_org: d.asn_org.clone(),
                            ip: d.last_ip.clone(),
                            ech: d.ech,
                            first_seen: unix_secs(d.first_seen),
                            last_seen: unix_secs(d.last_seen),
                            count: d.count,
                            bytes_out: d.bytes_out,
                            bytes_in: d.bytes_in,
                        })
                        .collect(),
                })
                .collect(),
        };
        let body = serde_json::to_string(&persisted)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, body)
    }

    /// Merge a persisted baseline from `path` into the profiler, dropping
    /// destinations not seen within `STALE_DEST_SECS` (the baseline ages out
    /// instead of accreting forever). Best-effort: absent or unparseable
    /// files are ignored — the baseline re-learns.
    pub fn load_profiles(&mut self, path: &Path) {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return;
        };
        let persisted: PersistedProfiles = match serde_json::from_str(&contents) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(target: "netwatch::egress", path = %path.display(), error = %e, "egress baseline parse failed; re-learning");
                return;
            }
        };
        let now = SystemTime::now();
        let mut dropped: HashMap<String, usize> = HashMap::new();
        for profile in persisted.profiles {
            for dest in profile.dests {
                let last_seen = from_unix_secs(dest.last_seen);
                let age_ok = now
                    .duration_since(last_seen)
                    .map(|d| d.as_secs() < STALE_DEST_SECS)
                    .unwrap_or(true); // future timestamp (clock skew) → keep
                if !age_ok {
                    continue;
                }
                let entry = self
                    .profiles
                    .entry(profile.process.clone())
                    .or_insert_with(|| EgressProfile {
                        process: profile.process.clone(),
                        dests: HashMap::new(),
                        last_seen,
                    });
                entry.last_seen = entry.last_seen.max(last_seen);
                if entry.dests.len() >= MAX_DESTS_PER_PROCESS {
                    // Silently dropping these is what makes a capped profile
                    // look like drift later: the destination is gone from the
                    // baseline but the traffic keeps happening. Count them and
                    // say so once per load rather than per row.
                    *dropped.entry(profile.process.clone()).or_insert(0usize) += 1;
                    continue;
                }
                // Repair a blank IP from the key label. `label` is
                // `sni.or(asn_org).unwrap_or(ip)`, so when neither name is
                // present the label *is* the address it was learned from.
                // This recovers two cases without a migration: baselines
                // written before the `ip` field existed (it defaults to ""),
                // and rows an unreadable address blanked. Guarded on both
                // names being absent so a hostname never lands in the IP.
                let last_ip = if dest.ip.is_empty() && dest.sni.is_none() && dest.asn_org.is_none()
                {
                    dest.label.clone()
                } else {
                    dest.ip
                };
                entry
                    .dests
                    .entry((dest.label, dest.port))
                    .or_insert(EgressDest {
                        sni: dest.sni,
                        asn_org: dest.asn_org,
                        port: dest.port,
                        last_ip,
                        ech: dest.ech,
                        first_seen: from_unix_secs(dest.first_seen),
                        last_seen,
                        count: dest.count,
                        bytes_out: dest.bytes_out,
                        bytes_in: dest.bytes_in,
                        // Activity is a live signal; a restored spark would
                        // claim traffic that isn't happening.
                        activity: VecDeque::new(),
                    });
            }
        }
        // A baseline saved before truncated names were folded holds both
        // spellings. Merge them once, on load, rather than waiting for new
        // traffic to arrive under the full name.
        let full_names: Vec<String> = self
            .profiles
            .keys()
            .filter(|k| k.len() > COMM_TRUNCATE_LEN)
            .cloned()
            .collect();
        for full in full_names {
            self.absorb_truncated(&full);
        }
        if !dropped.is_empty() {
            let total: usize = dropped.values().sum();
            let mut worst: Vec<_> = dropped.into_iter().collect();
            worst.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
            worst.truncate(3);
            let detail = worst
                .iter()
                .map(|(p, n)| format!("{p} (+{n})"))
                .collect::<Vec<_>>()
                .join(", ");
            tracing::warn!(
                target: "netwatch::egress",
                dropped = total,
                cap = MAX_DESTS_PER_PROCESS,
                "egress baseline truncated at the per-process destination cap: {detail}"
            );
        }
        self.evict_processes_if_needed();
    }
}

/// Whether an ASN org string names an actual organisation.
///
/// The geo database uses `Unassigned` as its *failure* label, and a lookup
/// that finds nothing yields an empty string. Allowlisting either admits
/// every destination whose ASN lookup failed — the opposite of an allowlist.
/// Checked wherever a rule is generated; a hand-written policy is still
/// honoured verbatim, because the file should do what it says.
fn is_identifying_asn(org: &str) -> bool {
    let t = org.trim();
    !t.is_empty() && !t.eq_ignore_ascii_case("unassigned") && !t.eq_ignore_ascii_case("unknown")
}

/// Build the allowlist rule a profile's observations imply.
///
/// Promotion never widens a rule to an autonomous system. An ASN match
/// admits everything that AS operates — for a hyperscaler, effectively the
/// whole internet — so learning one nameless Google flow would have handed
/// the process every host Google runs, permanently and invisibly. Identity
/// is taken from the SNI where there is one and the address otherwise; an
/// ASN entry is only ever reached when a destination has *no* other
/// identity at all, and even then only if the org actually names someone.
/// Widening to an AS remains available, but as a deliberate hand edit.
fn rule_from_profile(profile: &EgressProfile) -> ProcessRule {
    let mut allow_sni = BTreeSet::new();
    let mut allow_asn = BTreeSet::new();
    let mut allow_ip = BTreeSet::new();
    let mut allow_ports = BTreeSet::new();
    for dest in profile.dests.values() {
        match &dest.sni {
            Some(s) => {
                allow_sni.insert(s.clone());
            }
            // No readable name: the address is the precise identity we have,
            // so admit that. This also keeps a promoted baseline admitting
            // its own members — without it a nameless dest would drift
            // against its own rule the moment a sibling contributed an SNI.
            None => {
                if !dest.last_ip.is_empty() {
                    allow_ip.insert(dest.last_ip.clone());
                } else if let Some(a) = dest.asn_org.as_deref().filter(|a| is_identifying_asn(a)) {
                    // Neither name nor address survived. The AS is the last
                    // identity left, and admitting it beats emitting a rule
                    // that flags its own baseline.
                    allow_asn.insert(a.to_string());
                }
            }
        }
        allow_ports.insert(dest.port);
    }
    ProcessRule {
        allow_sni: allow_sni.into_iter().collect(),
        allow_asn: allow_asn.into_iter().collect(),
        allow_ip: allow_ip.into_iter().collect(),
        allow_ports: allow_ports.into_iter().collect(),
    }
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn from_unix_secs(s: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(s)
}

/// On-disk shape of the learned baseline (versioned so later phases can
/// migrate). Timestamps are unix seconds.
#[derive(Serialize, Deserialize)]
struct PersistedProfiles {
    version: u32,
    profiles: Vec<PersistedProfile>,
}

#[derive(Serialize, Deserialize)]
struct PersistedProfile {
    process: String,
    dests: Vec<PersistedDest>,
}

#[derive(Serialize, Deserialize)]
struct PersistedDest {
    label: String,
    port: u16,
    sni: Option<String>,
    asn_org: Option<String>,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    ech: bool,
    first_seen: u64,
    last_seen: u64,
    count: u64,
    #[serde(default)]
    bytes_out: u64,
    #[serde(default)]
    bytes_in: u64,
}

/// Default learned-baseline location: `<state_dir>/netwatch/egress-profiles.json`
/// (`~/.local/state` on Linux; falls back to the local data dir on macOS).
pub fn default_profiles_path() -> Option<PathBuf> {
    dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .map(|d| d.join("netwatch").join("egress-profiles.json"))
}

// ── Declared egress policy ─────────────────────────────────────────────

/// A declarative egress allowlist: `process → {allowed SNIs, ASNs, ports}`.
/// The linter warns when a process with a rule talks to something outside
/// it — a sentence no firewall ruleset can express. It never blocks.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EgressPolicy {
    /// Treat the policy as *complete*: a process with no rule is a finding,
    /// not a blind spot. Off by default, because it is only meaningful once
    /// the operator believes they have declared everything.
    ///
    /// This is the difference between "netwatch tells me when my declared
    /// software misbehaves" and "netwatch tells me when something is
    /// exfiltrating". Without it the linter cannot see the one thing a
    /// compromise actually introduces — a binary nobody declared — because
    /// an undeclared process has no rule to violate and so warns never.
    ///
    /// Lives in the policy file rather than config.toml deliberately: it is
    /// a claim about *this policy*, travels with it, and is meaningless
    /// without one.
    #[serde(default)]
    pub strict: bool,
    #[serde(default)]
    pub process: HashMap<String, ProcessRule>,
}

/// The allowed egress for one process. An empty list means "unrestricted on
/// that dimension" — e.g. empty `allow_ports` permits any port.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ProcessRule {
    /// Allowed destination hostnames. Exact (`api.example.com`) or a leading
    /// wildcard (`*.example.com`, which also matches the apex).
    #[serde(default)]
    pub allow_sni: Vec<String>,
    /// Allowed autonomous-system orgs (matched case-insensitively), used when
    /// a flow has no readable SNI.
    #[serde(default)]
    pub allow_asn: Vec<String>,
    /// Allowed raw destination IPs — the identity for a flow that carried no
    /// name (no ClientHello SNI, no resolved ASN). Without this, a rule that
    /// is name-restricted by *other* destinations would flag its own nameless
    /// members as drift.
    #[serde(default)]
    pub allow_ip: Vec<String>,
    /// Allowed destination ports. Empty ⇒ any port.
    #[serde(default)]
    pub allow_ports: Vec<u16>,
}

impl ProcessRule {
    /// Returns `Some(reason)` if the destination is outside this rule. The
    /// destination is identified by whichever of `sni` / `asn_org` / `ip` the
    /// flow carried; a rule admits a flow if *any* dimension it declares
    /// matches. This is why a promoted baseline admits its own members: a
    /// named dest matches by SNI, a raw-IP dest matches by IP.
    fn violation(
        &self,
        sni: Option<&str>,
        asn_org: Option<&str>,
        ip: &str,
        port: u16,
    ) -> Option<String> {
        if !self.allow_ports.is_empty() && !self.allow_ports.contains(&port) {
            return Some(format!("port {port} not in allowlist"));
        }
        let name_restricted =
            !self.allow_sni.is_empty() || !self.allow_asn.is_empty() || !self.allow_ip.is_empty();
        if name_restricted {
            let sni_ok = sni.is_some_and(|s| self.allow_sni.iter().any(|p| sni_matches(p, s)));
            let asn_ok =
                asn_org.is_some_and(|a| self.allow_asn.iter().any(|x| x.eq_ignore_ascii_case(a)));
            let ip_ok = self.allow_ip.iter().any(|x| x == ip);
            if !sni_ok && !asn_ok && !ip_ok {
                // Never build a message with an empty subject: a destination
                // with no SNI, no ASN and no readable IP used to warn as
                // " not in allowlist", which reads as a bug rather than a
                // finding. Name the gap instead.
                let dest = sni
                    .or(asn_org)
                    .filter(|d| !d.is_empty())
                    .unwrap_or(if ip.is_empty() {
                        "unknown destination"
                    } else {
                        ip
                    });
                return Some(format!("{dest} not in allowlist"));
            }
        }
        None
    }
}

/// Match an `allow_sni` pattern against a host. Supports an exact match or a
/// leading `*.` wildcard (`*.example.com` matches `a.example.com` and the
/// apex `example.com`). Case-insensitive.
fn sni_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.eq_ignore_ascii_case(suffix)
            || host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
    } else {
        host.eq_ignore_ascii_case(pattern)
    }
}

/// Default policy location: `<config_dir>/netwatch/egress-policy.toml`.
pub fn default_policy_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("netwatch").join("egress-policy.toml"))
}

/// Suggest wildcard collapses for a rule: when several `allow_sni` entries
/// are subdomains of one apex (naively the last two labels), a `*.apex`
/// entry would cover them all. Returned as *suggestions* — the promotion
/// writes the exact entries and a comment; the human collapses by hand if
/// they agree. Silent collapse would widen the allowlist unratified.
pub fn wildcard_suggestions(rule: &ProcessRule) -> Vec<String> {
    const MIN_SUBDOMAINS: usize = 3;
    let mut by_apex: HashMap<String, usize> = HashMap::new();
    for host in &rule.allow_sni {
        if host.starts_with("*.") {
            continue; // already a wildcard
        }
        let labels: Vec<&str> = host.split('.').collect();
        // Only proper subdomains suggest a wildcard; apex entries don't.
        // (Two-label apex assumption — good enough for a suggestion; wrong
        // for eTLDs like co.uk, which is why this never auto-applies.)
        if labels.len() > 2 {
            let apex = labels[labels.len() - 2..].join(".");
            *by_apex.entry(apex).or_insert(0) += 1;
        }
    }
    let mut out: Vec<String> = by_apex
        .into_iter()
        .filter(|(_, n)| *n >= MIN_SUBDOMAINS)
        .map(|(apex, n)| format!("*.{apex} would cover {n} entries"))
        .collect();
    out.sort();
    out
}

/// Load a policy from disk. `None` if the file is absent or unparseable.
/// On unix a group- or world-writable policy is **refused** (with a loud
/// warning): the policy is a trust anchor — if anyone but the owner can
/// edit it, "warn on drift" can be silenced by the very thing drifting.
pub fn load_policy_file(path: &Path) -> Option<EgressPolicy> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o022 != 0 {
                tracing::warn!(
                    target: "netwatch::egress",
                    path = %path.display(),
                    mode = format!("{:o}", mode & 0o777),
                    "REFUSING group/world-writable egress policy — chmod 644 (or stricter) to load it"
                );
                return None;
            }
        }
    }
    let contents = std::fs::read_to_string(path).ok()?;
    match toml::from_str(&contents) {
        Ok(policy) => Some(policy),
        Err(e) => {
            tracing::warn!(target: "netwatch::egress", path = %path.display(), error = %e, "egress policy parse failed");
            None
        }
    }
}

/// Serialize a policy to disk (creating parent dirs). Used by "promote".
pub fn save_policy_file(policy: &EgressPolicy, path: &Path) -> std::io::Result<()> {
    let body = toml::to_string_pretty(policy)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_owner_only(path, format!("{POLICY_HEADER}{body}").as_bytes())
}

/// Write a file owner-read/write only (`0o600` on unix). The egress policy is
/// a trust anchor: `load_policy_file` refuses a group/world-writable one, so
/// our OWN writes must be tight or promote-then-reload would refuse the file
/// we just wrote (which looked like "promote didn't take"). No-op perms on
/// non-unix; the byte write still happens.
fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        // Re-assert mode in case the file pre-existed with looser perms
        // (create+mode only applies to newly-created files).
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

const POLICY_HEADER: &str = "# netwatch egress policy (observe → promote → warn).\n\
                             # Generated from the observed baseline; review before trusting.\n\
                             # The linter WARNS on drift — it never blocks.\n\
                             #\n\
                             # strict = true treats this policy as complete: any process\n\
                             # WITHOUT a rule below is then reported as undeclared. Off by\n\
                             # default. Turn it on once you believe the list is complete —\n\
                             # it is what lets the linter see a binary nobody declared.\n\
                             #\n\
                             # Promotion never writes allow_asn from an observation: an AS\n\
                             # entry admits every host that AS operates. Widen by hand if\n\
                             # you mean it.\n\n";

/// Union the string entries already declared under `key` in an existing
/// TOML process table with the newly-promoted ones. Deduped, sorted, stable.
fn union_strings(existing: Option<&toml_edit::Item>, key: &str, add: &[String]) -> Vec<String> {
    let mut set: BTreeSet<String> = add.iter().cloned().collect();
    if let Some(arr) = existing.and_then(|e| e.get(key)).and_then(|v| v.as_array()) {
        for v in arr.iter() {
            if let Some(s) = v.as_str() {
                set.insert(s.to_string());
            }
        }
    }
    set.into_iter().collect()
}

/// Port variant of `union_strings`.
fn union_ports(existing: Option<&toml_edit::Item>, key: &str, add: &[u16]) -> Vec<u16> {
    let mut set: BTreeSet<u16> = add.iter().copied().collect();
    if let Some(arr) = existing.and_then(|e| e.get(key)).and_then(|v| v.as_array()) {
        for v in arr.iter() {
            if let Some(n) = v.as_integer() {
                if let Ok(p) = u16::try_from(n) {
                    set.insert(p);
                }
            }
        }
    }
    set.into_iter().collect()
}

/// Delete the named processes' rules from the policy file, preserving
/// everything else. The counterpart to `merge_rules_into_policy_file`, which
/// only ever grows an allowlist.
///
/// Returns the names actually removed — a name with no rule is not an error,
/// it is simply nothing to do, and the caller says so rather than claiming a
/// removal that didn't happen.
///
/// Removing a rule is the one destructive operation in the linter: it can
/// discard hand-written entries the baseline cannot regenerate. So it refuses
/// an unparseable file for the same reason promotion does, writes owner-only,
/// and the caller is expected to confirm first.
///
/// A comment sitting immediately above a rule goes with it — such a comment
/// documents that rule, and leaving it behind would orphan a note about
/// something no longer in the file. The one exception is the file's own
/// leading comment block, which `toml_edit` happens to store as the first
/// table's prefix: removing the first (or only) rule would otherwise delete
/// the header explaining `strict` and the promotion semantics, leaving a file
/// with no hint of how to get it back. That block is restored explicitly.
pub fn remove_rules_from_policy_file(
    names: &[String],
    path: &Path,
) -> std::io::Result<Vec<String>> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        // Nothing declared anywhere: removing is vacuously done. Creating the
        // file here just to delete from it would be absurd.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut doc: toml_edit::DocumentMut = existing.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("existing policy does not parse (fix it by hand first): {e}"),
        )
    })?;

    let mut removed = Vec::new();
    if let Some(tbl) = doc.get_mut("process").and_then(|p| p.as_table_mut()) {
        for name in names {
            if tbl.remove(name.as_str()).is_some() {
                removed.push(name.clone());
            }
        }
        // Leave `[process]` implicit so an emptied policy renders as the
        // header and nothing else, rather than a stray bare table.
        tbl.set_implicit(true);
    }
    if removed.is_empty() {
        return Ok(removed);
    }
    let mut body = doc.to_string();
    let head = leading_comment_block(&existing);
    if !head.is_empty() && !body.starts_with(&head) {
        body.insert_str(0, &head);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_owner_only(path, body.as_bytes())?;
    Ok(removed)
}

/// The run of comment and blank lines at the very top of a policy file — its
/// header. Returned with the trailing newline so it can be re-prepended
/// verbatim.
fn leading_comment_block(src: &str) -> String {
    let mut out = String::new();
    for line in src.lines() {
        let t = line.trim_start();
        if t.starts_with('#') || t.is_empty() {
            out.push_str(line);
            out.push('\n');
        } else {
            break;
        }
    }
    // A file that is *only* comments has no rules to remove, so preserving
    // "everything" would be a no-op anyway; more usefully, this stops a
    // comment-only file from being duplicated onto itself.
    if out.len() == src.len() {
        return String::new();
    }
    out
}

/// Upsert `rules` into the policy file, preserving everything else — hand
/// edits, comments, and rules for processes not being promoted. Promotion
/// is additive per process: it unions the observed entries with those already
/// declared (it never shrinks or deletes an allowlist). Removal is
/// `remove_rules_from_policy_file`. Refuses (rather than clobbers) a file that
/// no longer parses, so a broken hand edit is never silently thrown away.
pub fn merge_rules_into_policy_file(
    rules: &[(String, ProcessRule)],
    path: &Path,
) -> std::io::Result<()> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => POLICY_HEADER.to_string(),
        Err(e) => return Err(e),
    };
    let mut doc: toml_edit::DocumentMut = existing.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("existing policy does not parse (fix it by hand first): {e}"),
        )
    })?;

    let process_tbl = doc["process"].or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    if let Some(t) = process_tbl.as_table_mut() {
        // Render `[process.<name>]` sections only — no bare `[process]`.
        t.set_implicit(true);
    }
    for (name, rule) in rules {
        // Promote is *additive*: union the newly-observed entries with
        // whatever the file already declares for this process — prior
        // promotes that have since aged out of the live baseline, and any
        // hand-added entries. Replacing would shrink the allowlist to just
        // what's observed this session (the "not updating the full list"
        // bug); ratification only ever grows it. Removal stays a manual edit.
        let existing = doc["process"].get(name.as_str());
        let sni = union_strings(existing, "allow_sni", &rule.allow_sni);
        let asn = union_strings(existing, "allow_asn", &rule.allow_asn);
        let ip = union_strings(existing, "allow_ip", &rule.allow_ip);
        let ports = union_ports(existing, "allow_ports", &rule.allow_ports);

        let mut t = toml_edit::Table::new();
        // Wildcard suggestions land as a comment above the rule — visible
        // exactly where the human reviews, applied only by their hand.
        // Computed on the *unioned* set so the suggestion reflects the file.
        let unioned = ProcessRule {
            allow_sni: sni.clone(),
            allow_asn: asn.clone(),
            allow_ip: ip.clone(),
            allow_ports: ports.clone(),
        };
        let suggestions = wildcard_suggestions(&unioned);
        if !suggestions.is_empty() {
            t.decor_mut()
                .set_prefix(format!("# suggestion: {}\n", suggestions.join("; ")));
        }
        t["allow_sni"] =
            toml_edit::value(toml_edit::Array::from_iter(sni.iter().map(String::as_str)));
        t["allow_asn"] =
            toml_edit::value(toml_edit::Array::from_iter(asn.iter().map(String::as_str)));
        t["allow_ip"] =
            toml_edit::value(toml_edit::Array::from_iter(ip.iter().map(String::as_str)));
        t["allow_ports"] = toml_edit::value(toml_edit::Array::from_iter(
            ports.iter().map(|p| i64::from(*p)),
        ));
        doc["process"][name.as_str()] = toml_edit::Item::Table(t);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_owner_only(path, doc.to_string().as_bytes())
}

/// One-line summary of what promoting `new` changes relative to the declared
/// rule — the pre-promote evidence shown on the status line.
pub fn rule_diff(old: Option<&ProcessRule>, new: &ProcessRule) -> String {
    fn added<T: PartialEq>(old: &[T], new: &[T]) -> usize {
        new.iter().filter(|x| !old.contains(x)).count()
    }
    let Some(old) = old else {
        return format!(
            "new rule: {} SNI, {} ASN, {} IP, {} ports",
            new.allow_sni.len(),
            new.allow_asn.len(),
            new.allow_ip.len(),
            new.allow_ports.len()
        );
    };
    let (sni, asn, ip, ports) = (
        added(&old.allow_sni, &new.allow_sni),
        added(&old.allow_asn, &new.allow_asn),
        added(&old.allow_ip, &new.allow_ip),
        added(&old.allow_ports, &new.allow_ports),
    );
    if sni + asn + ip + ports == 0 {
        "no additions".to_string()
    } else {
        format!("+{sni} SNI, +{asn} ASN, +{ip} IP, +{ports} ports")
    }
}

/// Extract the destination hostname from a flow's app-protocol: TLS/QUIC SNI
/// (cleartext ClientHello) or the cleartext HTTP `Host`.
fn dest_hostname(p: &Option<AppProtocol>) -> Option<String> {
    match p {
        Some(AppProtocol::Tls { sni: Some(s), .. }) => Some(s.clone()),
        Some(AppProtocol::Quic { sni: Some(s), .. }) => Some(s.clone()),
        Some(AppProtocol::Http { host: Some(h), .. }) => Some(h.clone()),
        _ => None,
    }
}

/// Whether the flow's ClientHello carried an `encrypted_client_hello`
/// extension — the outer SNI (if any) is a decoy and the real name is hidden.
fn flow_ech(p: &Option<AppProtocol>) -> bool {
    matches!(
        p,
        Some(AppProtocol::Tls { ech: true, .. }) | Some(AppProtocol::Quic { ech: true, .. })
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sni(host: &str) -> Option<String> {
        Some(host.to_string())
    }

    #[test]
    fn record_builds_per_process_profile_keyed_by_sni() {
        let mut p = EgressProfiler::new();
        let now = SystemTime::now();
        p.record(
            "chrome",
            "142.250.1.1",
            443,
            sni("www.google.com"),
            Some("Google LLC".into()),
            now,
        );
        p.record(
            "chrome",
            "142.250.1.2",
            443,
            sni("mail.google.com"),
            Some("Google LLC".into()),
            now,
        );
        // Same SNI again → same destination, count increments (not a new dest).
        p.record(
            "chrome",
            "142.250.9.9",
            443,
            sni("www.google.com"),
            Some("Google LLC".into()),
            now,
        );

        assert_eq!(p.process_count(), 1);
        let snap = p.snapshot();
        let chrome = &snap[0];
        assert_eq!(chrome.process, "chrome");
        assert_eq!(
            chrome.dests.len(),
            2,
            "two distinct SNIs → two destinations"
        );
        let www = chrome
            .dests
            .get(&("www.google.com".to_string(), 443))
            .unwrap();
        assert_eq!(www.count, 2);
        assert_eq!(www.asn_org.as_deref(), Some("Google LLC"));
    }

    #[test]
    fn falls_back_to_asn_then_ip_when_no_sni() {
        let mut p = EgressProfiler::new();
        let now = SystemTime::now();
        p.record("curl", "9.9.9.9", 443, None, Some("Quad9".into()), now);
        p.record("nc", "203.0.113.7", 4444, None, None, now);

        let snap = p.snapshot();
        // Sorted by process name: curl, nc.
        assert!(snap
            .iter()
            .any(|pr| pr.dests.contains_key(&("Quad9".to_string(), 443))));
        assert!(snap
            .iter()
            .any(|pr| pr.dests.contains_key(&("203.0.113.7".to_string(), 4444))));
    }

    #[test]
    fn backfills_sni_and_asn_discovered_later() {
        let mut p = EgressProfiler::new();
        let now = SystemTime::now();
        // First sight: no name resolved yet → keyed on IP.
        p.record("app", "198.51.100.5", 443, None, None, now);
        // The dest exists under the IP label; a later sighting that DOES
        // carry an SNI lands on a *new* key (the identity is now the SNI).
        p.record(
            "app",
            "198.51.100.5",
            443,
            sni("api.example.com"),
            Some("Example Org".into()),
            now,
        );

        let snap = p.snapshot();
        let app = &snap[0];
        // IP-keyed dest plus SNI-keyed dest.
        let by_ip = app.dests.get(&("198.51.100.5".to_string(), 443)).unwrap();
        assert!(by_ip.sni.is_none());
        let by_sni = app
            .dests
            .get(&("api.example.com".to_string(), 443))
            .unwrap();
        assert_eq!(by_sni.asn_org.as_deref(), Some("Example Org"));
    }

    #[test]
    fn observe_skips_private_and_processless_connections() {
        use crate::collectors::connections::Connection;
        let mk = |proc: Option<&str>, remote: &str| Connection {
            protocol: "TCP".into(),
            local_addr: "192.168.1.10:5000".into(),
            remote_addr: remote.into(),
            state: "ESTABLISHED".into(),
            pid: Some(1),
            process_name: proc.map(|s| s.to_string()),
            handshake_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
            attribution: Default::default(),
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        };
        let mut p = EgressProfiler::new();
        let geo = crate::collectors::geo::GeoCache::new();
        let conns = vec![
            mk(Some("ssh"), "192.168.1.1:22"),  // private dst → skipped
            mk(None, "8.8.8.8:53"),             // no process → skipped
            mk(Some("ssh"), "203.0.113.50:22"), // recorded
        ];
        p.observe(&conns, &geo);
        assert_eq!(p.process_count(), 1);
        assert_eq!(p.dest_count(), 1);
    }

    #[test]
    fn per_process_destinations_are_capped() {
        let mut p = EgressProfiler::new();
        let now = SystemTime::now();
        for i in 0..(MAX_DESTS_PER_PROCESS + 50) {
            p.record(
                "noisy",
                &format!("203.0.113.{}", i % 256),
                1000 + i as u16,
                None,
                None,
                now,
            );
        }
        let snap = p.snapshot();
        assert!(snap[0].dests.len() <= MAX_DESTS_PER_PROCESS);
    }

    // ── Policy ──

    #[test]
    fn sni_wildcard_and_exact_matching() {
        assert!(sni_matches("api.example.com", "api.example.com"));
        assert!(sni_matches("API.example.com", "api.example.com")); // case-insensitive
        assert!(!sni_matches("api.example.com", "other.example.com"));
        assert!(sni_matches("*.example.com", "a.example.com"));
        assert!(sni_matches("*.example.com", "deep.sub.example.com"));
        assert!(sni_matches("*.example.com", "example.com")); // apex
        assert!(!sni_matches("*.example.com", "example.org"));
        assert!(!sni_matches("*.example.com", "notexample.com"));
    }

    #[test]
    fn rule_violation_semantics() {
        let rule = ProcessRule {
            allow_sni: vec!["*.google.com".into()],
            allow_asn: vec!["Cloudflare, Inc.".into()],
            allow_ip: vec!["203.0.113.5".into()],
            allow_ports: vec![443],
        };
        let ip = "198.51.100.1"; // an IP NOT in allow_ip, unless stated
                                 // Allowed: matching SNI on an allowed port.
        assert!(rule
            .violation(Some("www.google.com"), None, ip, 443)
            .is_none());
        // Allowed via ASN fallback when no SNI.
        assert!(rule
            .violation(None, Some("Cloudflare, Inc."), ip, 443)
            .is_none());
        // Allowed via IP when there's no name at all.
        assert!(rule.violation(None, None, "203.0.113.5", 443).is_none());
        // Wrong port.
        assert!(rule
            .violation(Some("www.google.com"), None, ip, 8080)
            .is_some());
        // Unlisted SNI (and IP not listed).
        assert!(rule
            .violation(Some("evil.example.com"), None, ip, 443)
            .is_some());
        // No name AND an unlisted IP on a name-restricted rule → violation.
        assert!(rule.violation(None, None, ip, 443).is_some());

        // A rule with no name restrictions only constrains ports.
        let port_only = ProcessRule {
            allow_ports: vec![443],
            ..Default::default()
        };
        assert!(port_only
            .violation(Some("anything.com"), None, ip, 443)
            .is_none());
        assert!(port_only
            .violation(Some("anything.com"), None, ip, 80)
            .is_some());
    }

    #[test]
    fn promote_then_policy_admits_the_observed_baseline() {
        let mut p = EgressProfiler::new();
        let now = SystemTime::now();
        p.record(
            "chrome",
            "142.250.1.1",
            443,
            sni("www.google.com"),
            Some("Google LLC".into()),
            now,
        );
        p.record("curl", "9.9.9.9", 443, None, Some("Quad9".into()), now);

        let policy = p.promote();
        let chrome = policy.process.get("chrome").unwrap();
        assert!(chrome.allow_sni.contains(&"www.google.com".to_string()));
        assert_eq!(chrome.allow_ports, vec![443]);
        // A nameless destination is promoted by *address*, never by its
        // autonomous system — admitting all of Quad9 is not what observing
        // one Quad9 address means.
        let curl = policy.process.get("curl").unwrap();
        assert!(curl.allow_ip.contains(&"9.9.9.9".to_string()));
        assert!(curl.allow_asn.is_empty());

        // The promoted policy must not flag the very baseline it came from.
        assert!(chrome
            .violation(
                Some("www.google.com"),
                Some("Google LLC"),
                "142.250.1.1",
                443
            )
            .is_none());
        assert!(curl
            .violation(None, Some("Quad9"), "9.9.9.9", 443)
            .is_none());
    }

    #[test]
    fn policy_toml_roundtrips() {
        let mut policy = EgressPolicy::default();
        policy.process.insert(
            "chrome".into(),
            ProcessRule {
                allow_sni: vec!["*.google.com".into()],
                allow_asn: vec![],
                allow_ip: vec![],
                allow_ports: vec![443],
            },
        );
        let s = toml::to_string_pretty(&policy).unwrap();
        let parsed: EgressPolicy = toml::from_str(&s).unwrap();
        let rule = parsed.process.get("chrome").unwrap();
        assert_eq!(rule.allow_sni, vec!["*.google.com".to_string()]);
        assert_eq!(rule.allow_ports, vec![443]);
    }

    #[test]
    fn observe_warns_on_drift_with_cooldown() {
        let mut p = EgressProfiler::new();
        let mut policy = EgressPolicy::default();
        policy.process.insert(
            "app".into(),
            ProcessRule {
                allow_sni: vec!["api.example.com".into()],
                allow_asn: vec![],
                allow_ip: vec![],
                allow_ports: vec![443],
            },
        );
        p.set_policy(Some(policy));
        let now = Instant::now();

        // Drift: app talks to an undeclared host.
        p.check_policy(
            "app",
            "203.0.113.9",
            443,
            &sni("evil.example.com"),
            &None,
            false,
            now,
        );
        // An unlisted process is never flagged (no rule to violate).
        p.check_policy(
            "other",
            "203.0.113.9",
            443,
            &sni("whatever.com"),
            &None,
            false,
            now,
        );

        let v = p.take_violations();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].process, "app");
        assert!(v[0].reason.contains("not in allowlist"));

        // Same violation again immediately → suppressed by cooldown.
        p.check_policy(
            "app",
            "203.0.113.9",
            443,
            &sni("evil.example.com"),
            &None,
            false,
            now,
        );
        assert_eq!(p.take_violations().len(), 0);
    }

    // ── Phase 1: persistence, selective promote, merge, diff ──

    /// Unique scratch path in the OS temp dir (no tempfile dep).
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "netwatch-egress-test-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn baseline_persists_across_profilers() {
        let path = scratch("profiles.json");
        let mut p = EgressProfiler::new();
        p.record(
            "chrome",
            "142.250.1.1",
            443,
            sni("www.google.com"),
            Some("Google LLC".into()),
            SystemTime::now(),
        );
        p.save_profiles(&path).unwrap();

        let mut fresh = EgressProfiler::new();
        fresh.load_profiles(&path);
        assert_eq!(fresh.process_count(), 1);
        let snap = fresh.snapshot();
        let dest = snap[0]
            .dests
            .get(&("www.google.com".to_string(), 443))
            .unwrap();
        assert_eq!(dest.count, 1);
        assert_eq!(dest.asn_org.as_deref(), Some("Google LLC"));
    }

    #[test]
    fn stale_destinations_age_out_at_load() {
        let path = scratch("stale.json");
        let mut p = EgressProfiler::new();
        let stale = SystemTime::now() - Duration::from_secs(STALE_DEST_SECS + 3600);
        p.record(
            "old",
            "203.0.113.1",
            443,
            sni("gone.example.com"),
            None,
            stale,
        );
        p.record(
            "fresh",
            "203.0.113.2",
            443,
            sni("live.example.com"),
            None,
            SystemTime::now(),
        );
        p.save_profiles(&path).unwrap();

        let mut loaded = EgressProfiler::new();
        loaded.load_profiles(&path);
        let snap = loaded.snapshot();
        assert!(
            !snap.iter().any(|pr| pr.process == "old"),
            "stale-only profile must not survive the load"
        );
        assert!(snap.iter().any(|pr| pr.process == "fresh"));
    }

    #[test]
    fn load_merges_persisted_into_live_observations() {
        let path = scratch("merge.json");
        let mut p = EgressProfiler::new();
        p.record(
            "chrome",
            "1.2.3.4",
            443,
            sni("persisted.example.com"),
            None,
            SystemTime::now(),
        );
        p.save_profiles(&path).unwrap();

        let mut live = EgressProfiler::new();
        live.record(
            "chrome",
            "5.6.7.8",
            443,
            sni("live.example.com"),
            None,
            SystemTime::now(),
        );
        live.load_profiles(&path);
        let snap = live.snapshot();
        assert_eq!(
            snap[0].dests.len(),
            2,
            "persisted + live dests both present"
        );
    }

    #[test]
    fn promote_one_only_covers_that_process() {
        let mut p = EgressProfiler::new();
        let now = SystemTime::now();
        p.record("chrome", "1.1.1.1", 443, sni("a.example.com"), None, now);
        p.record("curl", "2.2.2.2", 443, sni("b.example.com"), None, now);

        let rule = p.promote_one("chrome").unwrap();
        assert!(rule.allow_sni.contains(&"a.example.com".to_string()));
        assert!(!rule.allow_sni.contains(&"b.example.com".to_string()));
        assert!(p.promote_one("nonexistent").is_none());
    }

    #[test]
    fn merge_preserves_comments_and_other_rules() {
        let path = scratch("policy.toml");
        std::fs::write(
            &path,
            "# my hand-written note\n\n[process.ssh]\nallow_ports = [22] # keep tight\n",
        )
        .unwrap();

        let rules = vec![(
            "chrome".to_string(),
            ProcessRule {
                allow_sni: vec!["*.google.com".into()],
                allow_asn: vec![],
                allow_ip: vec![],
                allow_ports: vec![443],
            },
        )];
        merge_rules_into_policy_file(&rules, &path).unwrap();

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("# my hand-written note"), "comments survive");
        assert!(body.contains("# keep tight"), "inline comments survive");
        assert!(body.contains("[process.ssh]"), "unrelated rules survive");
        let parsed: EgressPolicy = toml::from_str(&body).unwrap();
        assert_eq!(
            parsed.process.get("chrome").unwrap().allow_sni,
            vec!["*.google.com".to_string()]
        );
        assert_eq!(parsed.process.get("ssh").unwrap().allow_ports, vec![22]);

        // Re-promoting chrome replaces only chrome's rule.
        let rules2 = vec![(
            "chrome".to_string(),
            ProcessRule {
                allow_sni: vec!["*.google.com".into(), "*.gstatic.com".into()],
                allow_asn: vec![],
                allow_ip: vec![],
                allow_ports: vec![443],
            },
        )];
        merge_rules_into_policy_file(&rules2, &path).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("# my hand-written note"));
        assert!(body.contains("gstatic"));
        assert!(body.contains("[process.ssh]"));
    }

    /// Removal is surgical: the named rule goes, everything a human put in
    /// the file stays.
    #[test]
    fn remove_deletes_only_the_named_rule() {
        let path = scratch("remove.toml");
        std::fs::write(
            &path,
            "# my hand-written note\n\n\
             [process.ssh]\nallow_ports = [22] # keep tight\n\n\
             [process.chrome]\nallow_sni = [\"*.google.com\"]\nallow_ports = [443]\n",
        )
        .unwrap();

        let removed = remove_rules_from_policy_file(&["chrome".to_string()], &path).unwrap();
        assert_eq!(removed, vec!["chrome".to_string()]);

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(!body.contains("chrome"), "the rule is gone: {body}");
        assert!(body.contains("# my hand-written note"), "comments survive");
        assert!(body.contains("# keep tight"), "inline comments survive");
        let parsed: EgressPolicy = toml::from_str(&body).unwrap();
        assert!(!parsed.process.contains_key("chrome"));
        assert_eq!(parsed.process.get("ssh").unwrap().allow_ports, vec![22]);
    }

    /// Removing the last (or first) rule must not take the file's header with
    /// it. `toml_edit` stores the leading comment block as the first table's
    /// prefix, so a naive removal emptied the file completely — leaving the
    /// user with no record of what `strict` does or how to promote again.
    #[test]
    fn removing_the_only_rule_keeps_the_file_header() {
        let path = scratch("remove-header.toml");
        let rules = vec![("chrome".to_string(), ProcessRule::default())];
        merge_rules_into_policy_file(&rules, &path).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        assert!(before.contains("observe → promote → warn"));

        remove_rules_from_policy_file(&["chrome".to_string()], &path).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(
            after.contains("observe → promote → warn"),
            "the generated header must survive: {after:?}"
        );
        assert!(
            after.contains("strict = true"),
            "including the part documenting strict mode: {after:?}"
        );
        assert!(!after.contains("[process.chrome]"), "the rule is gone");
        // Still a valid, loadable policy — not a pile of comments plus junk.
        let parsed: EgressPolicy = toml::from_str(&after).unwrap();
        assert!(parsed.process.is_empty());
        // And promoting again reproduces a normal file, not a doubled header.
        merge_rules_into_policy_file(&rules, &path).unwrap();
        let again = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            again.matches("observe → promote → warn").count(),
            1,
            "header must not be duplicated: {again:?}"
        );
    }

    /// Removing something that was never declared is not an error — but the
    /// caller must be able to tell, so it doesn't report a removal that
    /// didn't happen. The file is left untouched.
    #[test]
    fn removing_an_undeclared_process_reports_nothing_removed() {
        let path = scratch("remove-absent.toml");
        let original = "[process.ssh]\nallow_ports = [22]\n";
        std::fs::write(&path, original).unwrap();

        let removed = remove_rules_from_policy_file(&["nothere".to_string()], &path).unwrap();
        assert!(removed.is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);

        // No file at all is likewise vacuously done, and must not create one.
        let missing = path.parent().unwrap().join("does-not-exist.toml");
        assert!(remove_rules_from_policy_file(&["x".to_string()], &missing)
            .unwrap()
            .is_empty());
        assert!(!missing.exists(), "removal must not create a policy file");
    }

    /// Same guard as promotion: a file that no longer parses is refused, not
    /// rewritten. Losing a broken hand edit is worse than failing loudly.
    #[test]
    fn remove_refuses_to_clobber_unparseable_policy() {
        let path = scratch("remove-broken.toml");
        std::fs::write(&path, "[process.ssh\nallow_ports = [22]").unwrap();
        let err = remove_rules_from_policy_file(&["ssh".to_string()], &path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .starts_with("[process.ssh\n"));
    }

    /// Remove-then-re-add is the round trip a user will actually perform, and
    /// the rewritten file must still be loadable — including its permissions,
    /// since `load_policy_file` refuses a group/world-writable policy.
    #[test]
    fn removed_process_stops_being_checked_and_can_be_re_added() {
        let path = scratch("remove-roundtrip.toml");
        let rules = vec![(
            "chrome".to_string(),
            ProcessRule {
                allow_sni: vec!["api.example.com".into()],
                allow_asn: vec![],
                allow_ip: vec![],
                allow_ports: vec![443],
            },
        )];
        merge_rules_into_policy_file(&rules, &path).unwrap();
        assert!(load_policy_file(&path)
            .unwrap()
            .process
            .contains_key("chrome"));

        remove_rules_from_policy_file(&["chrome".to_string()], &path).unwrap();
        let policy = load_policy_file(&path).expect("policy still loads after removal");
        assert!(policy.process.is_empty());

        // The destination that was declared now reads as unchecked rather
        // than allowed — coverage was withdrawn, not granted.
        let mut p = EgressProfiler::new();
        p.set_policy(Some(policy));
        let d = EgressDest {
            sni: Some("api.example.com".into()),
            asn_org: None,
            port: 443,
            last_ip: "1.2.3.4".into(),
            ech: false,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            count: 1,
            bytes_out: 0,
            bytes_in: 0,
            activity: VecDeque::new(),
        };
        assert_eq!(p.verdict("chrome", &d), Verdict::NoRule);

        // And it can be put back.
        merge_rules_into_policy_file(&rules, &path).unwrap();
        p.set_policy(load_policy_file(&path));
        assert_eq!(p.verdict("chrome", &d), Verdict::Sni);
    }

    /// Under a policy declaring itself complete, removing a rule does not make
    /// a process go quiet — it makes it a finding.
    #[test]
    fn removal_under_strict_surfaces_the_process_as_undeclared() {
        let path = scratch("remove-strict.toml");
        std::fs::write(
            &path,
            "strict = true\n\n[process.chrome]\nallow_sni = [\"api.example.com\"]\n",
        )
        .unwrap();
        write_owner_only(&path, std::fs::read(&path).unwrap().as_slice()).unwrap();

        remove_rules_from_policy_file(&["chrome".to_string()], &path).unwrap();
        let policy = load_policy_file(&path).expect("loads after removal");
        assert!(policy.strict, "the strict flag is not collateral damage");

        let mut p = EgressProfiler::new();
        p.set_policy(Some(policy));
        let d = EgressDest {
            sni: Some("api.example.com".into()),
            asn_org: None,
            port: 443,
            last_ip: "1.2.3.4".into(),
            ech: false,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            count: 1,
            bytes_out: 0,
            bytes_in: 0,
            activity: VecDeque::new(),
        };
        assert_eq!(p.verdict("chrome", &d), Verdict::Undeclared);
    }

    #[test]
    fn merge_refuses_to_clobber_unparseable_policy() {
        let path = scratch("broken.toml");
        std::fs::write(&path, "[process.ssh\nallow_ports = [22]").unwrap(); // broken
        let rules = vec![("x".to_string(), ProcessRule::default())];
        let err = merge_rules_into_policy_file(&rules, &path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.starts_with("[process.ssh\n"), "file untouched");
    }

    // ── Phase 2: wildcard suggestions, ECH, cooldown, totals, perms ──

    #[test]
    fn wildcard_suggested_at_three_subdomains_never_for_apex_or_existing() {
        let rule = ProcessRule {
            allow_sni: vec![
                "a.example.com".into(),
                "b.example.com".into(),
                "c.example.com".into(),
                "example.com".into(),   // apex — doesn't count toward the 3
                "one.other.org".into(), // below threshold
                "*.already.net".into(), // existing wildcard — ignored
            ],
            ..Default::default()
        };
        let s = wildcard_suggestions(&rule);
        assert_eq!(s.len(), 1);
        assert!(s[0].contains("*.example.com"), "{s:?}");
        assert!(s[0].contains("3 entries"), "{s:?}");
    }

    #[test]
    fn merge_writes_wildcard_suggestion_as_comment_only() {
        let path = scratch("suggest.toml");
        let rules = vec![(
            "chrome".to_string(),
            ProcessRule {
                allow_sni: vec![
                    "a.google.com".into(),
                    "b.google.com".into(),
                    "c.google.com".into(),
                ],
                allow_asn: vec![],
                allow_ip: vec![],
                allow_ports: vec![443],
            },
        )];
        merge_rules_into_policy_file(&rules, &path).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            body.contains("# suggestion:") && body.contains("*.google.com"),
            "suggestion comment present: {body}"
        );
        // The rule itself still lists exact entries — no silent collapse.
        let parsed: EgressPolicy = toml::from_str(&body).unwrap();
        let sni = &parsed.process.get("chrome").unwrap().allow_sni;
        assert_eq!(sni.len(), 3);
        assert!(!sni.iter().any(|s| s.starts_with("*.")));
    }

    #[test]
    fn ech_is_sticky_and_survives_persistence() {
        let path = scratch("ech.json");
        let mut p = EgressProfiler::new();
        let now = SystemTime::now();
        p.record_flow(
            "chrome",
            "1.2.3.4",
            443,
            None,
            Some("Cloudflare".into()),
            true,
            now,
            0,
            0,
        );
        p.record_flow(
            "chrome",
            "1.2.3.4",
            443,
            None,
            Some("Cloudflare".into()),
            false,
            now,
            0,
            0,
        );
        let snap = p.snapshot();
        let dest = snap[0].dests.get(&("Cloudflare".to_string(), 443)).unwrap();
        assert!(dest.ech, "ech is sticky once observed");

        p.save_profiles(&path).unwrap();
        let mut fresh = EgressProfiler::new();
        fresh.load_profiles(&path);
        let snap = fresh.snapshot();
        assert!(
            snap[0]
                .dests
                .get(&("Cloudflare".to_string(), 443))
                .unwrap()
                .ech
        );
    }

    #[test]
    fn ech_violation_reason_names_the_encryption() {
        let mut p = EgressProfiler::new();
        let mut policy = EgressPolicy::default();
        policy.process.insert(
            "app".into(),
            ProcessRule {
                allow_sni: vec!["api.example.com".into()],
                ..Default::default()
            },
        );
        p.set_policy(Some(policy));
        p.check_policy(
            "app",
            "203.0.113.9",
            443,
            &None,
            &None,
            true,
            Instant::now(),
        );
        let v = p.take_violations();
        assert_eq!(v.len(), 1);
        assert!(v[0].reason.contains("ECH"), "{}", v[0].reason);
    }

    #[test]
    fn zero_cooldown_rewarns_every_check_and_totals_accumulate() {
        let mut p = EgressProfiler::new();
        p.set_violation_cooldown(0);
        let mut policy = EgressPolicy::default();
        policy.process.insert(
            "app".into(),
            ProcessRule {
                allow_sni: vec!["api.example.com".into()],
                ..Default::default()
            },
        );
        p.set_policy(Some(policy));
        let now = Instant::now();
        p.check_policy("app", "1.1.1.1", 443, &sni("evil.com"), &None, false, now);
        p.check_policy("app", "1.1.1.1", 443, &sni("evil.com"), &None, false, now);
        assert_eq!(
            p.take_violations().len(),
            2,
            "cooldown 0 ⇒ every check warns"
        );
        assert_eq!(p.violation_totals_sorted(), vec![("app".to_string(), 2)]);
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_policy_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let path = scratch("loose.toml");
        std::fs::write(&path, "[process.ssh]\nallow_ports = [22]\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            load_policy_file(&path).is_none(),
            "world-writable policy must be refused"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_policy_file(&path).is_some(), "0644 loads fine");
    }

    // ── Phase 3: structured export ──

    #[test]
    fn export_records_carry_verdicts_and_sort_stably() {
        let mut p = EgressProfiler::new();
        let now = SystemTime::now();
        p.record("chrome", "1.1.1.1", 443, sni("a.google.com"), None, now);
        p.record("curl", "9.9.9.9", 443, None, Some("Quad9".into()), now);
        let mut policy = EgressPolicy::default();
        policy.process.insert(
            "chrome".into(),
            ProcessRule {
                allow_sni: vec!["a.google.com".into()],
                ..Default::default()
            },
        );
        p.set_policy(Some(policy));

        let recs = p.export_records();
        assert_eq!(recs.len(), 2);
        // Sorted by process: chrome, curl.
        assert_eq!(recs[0].process, "chrome");
        assert_eq!(recs[0].verdict, "ok"); // matches its rule
        assert_eq!(recs[0].proto, "tls");
        assert_eq!(recs[1].process, "curl");
        assert_eq!(recs[1].verdict, "unchecked"); // no rule for curl
        assert_eq!(recs[1].asn_org.as_deref(), Some("Quad9"));
        assert_eq!(recs[1].proto, "other");
    }

    #[test]
    fn ech_flow_exports_as_unreadable_not_drift() {
        let mut p = EgressProfiler::new();
        p.record_flow(
            "app",
            "1.2.3.4",
            443,
            None,
            Some("Cloudflare".into()),
            true,
            SystemTime::now(),
            0,
            0,
        );
        let mut policy = EgressPolicy::default();
        policy.process.insert(
            "app".into(),
            ProcessRule {
                allow_sni: vec!["api.example.com".into()],
                ..Default::default()
            },
        );
        p.set_policy(Some(policy));
        let recs = p.export_records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].verdict, "unreadable");
        assert!(recs[0].ech);
    }

    #[test]
    fn export_ndjson_has_meta_header_then_one_line_per_record() {
        let path = scratch("export.ndjson");
        let mut p = EgressProfiler::new();
        let now = SystemTime::now();
        p.record("chrome", "1.1.1.1", 443, sni("a.google.com"), None, now);
        p.record("chrome", "1.1.1.2", 443, sni("b.google.com"), None, now);

        let n = p.export_ndjson(&path).unwrap();
        assert_eq!(n, 2);
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 3, "meta line + 2 records");

        // Meta line names the schema and count.
        let meta: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(meta["_meta"]["schema"], EGRESS_EXPORT_SCHEMA);
        assert_eq!(meta["_meta"]["records"], 2);

        // Each subsequent line is a standalone EgressRecord.
        let rec: EgressRecord = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(rec.process, "chrome");
        // No payload field ever leaks into the export.
        assert!(!lines[1].contains("payload") && !lines[1].contains("raw"));
    }

    // ── Field-report fixes ──

    #[cfg(unix)]
    #[test]
    fn promote_writes_owner_only_so_reload_is_not_refused() {
        // Regression: the world-writable refusal (Phase 2) rejected our OWN
        // freshly-promoted file under a loose umask, so promote silently
        // didn't take. Our writes must be 0o600 and reload cleanly.
        use std::os::unix::fs::PermissionsExt;
        let path = scratch("promote-perms.toml");
        let rules = vec![(
            "chrome".to_string(),
            ProcessRule {
                allow_sni: vec!["*.google.com".into()],
                allow_ports: vec![443],
                ..Default::default()
            },
        )];
        merge_rules_into_policy_file(&rules, &path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "promoted policy must be owner-only");
        assert!(
            load_policy_file(&path).is_some(),
            "our own promoted file must reload, not be refused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn promote_tightens_a_preexisting_loose_policy_file() {
        use std::os::unix::fs::PermissionsExt;
        let path = scratch("preexisting-loose.toml");
        std::fs::write(&path, "[process.ssh]\nallow_ports=[22]\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let rules = vec![("chrome".to_string(), ProcessRule::default())];
        merge_rules_into_policy_file(&rules, &path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a loose pre-existing file is tightened on write"
        );
        assert!(load_policy_file(&path).is_some());
    }

    #[test]
    fn promoted_rule_marks_all_its_own_destinations_ok() {
        // The field-report symptom: after promote, mixed named + nameless
        // destinations of one process must ALL read "ok" — a raw-IP dest
        // must not drift against the rule it was promoted into just because
        // a sibling dest contributed an SNI (which makes the rule
        // name-restricted).
        let mut p = EgressProfiler::new();
        let now = SystemTime::now();
        // Named dest (has SNI) — makes the rule name-restricted.
        p.record(
            "app",
            "142.250.1.1",
            443,
            sni("api.example.com"),
            Some("Example".into()),
            now,
        );
        // Nameless raw-IP dest for the same process.
        p.record("app", "203.0.113.9", 4444, None, None, now);

        // Promote and load the rule back (as the UI does).
        let policy = p.promote();
        p.set_policy(Some(policy));

        // Every observed destination must now be allowed (verdict = ok).
        for profile in p.snapshot() {
            for dest in profile.dests.values() {
                assert_eq!(
                    p.dest_allowed(&profile.process, dest),
                    Some(true),
                    "dest sni={:?} ip={} must be ok after promote",
                    dest.sni,
                    dest.last_ip
                );
            }
        }
    }

    #[test]
    fn promote_is_additive_and_never_shrinks_the_allowlist() {
        let path = scratch("additive.toml");

        // First promote: chrome observed talking to google.
        merge_rules_into_policy_file(
            &[(
                "chrome".to_string(),
                ProcessRule {
                    allow_sni: vec!["mail.google.com".into()],
                    allow_ports: vec![443],
                    ..Default::default()
                },
            )],
            &path,
        )
        .unwrap();

        // Second promote: a *different* observed set (e.g. a new session where
        // the old destination wasn't seen). Must UNION, not replace.
        merge_rules_into_policy_file(
            &[(
                "chrome".to_string(),
                ProcessRule {
                    allow_sni: vec!["drive.google.com".into()],
                    allow_ports: vec![443],
                    ..Default::default()
                },
            )],
            &path,
        )
        .unwrap();

        let policy = load_policy_file(&path).unwrap();
        let sni = &policy.process.get("chrome").unwrap().allow_sni;
        assert!(
            sni.contains(&"mail.google.com".to_string())
                && sni.contains(&"drive.google.com".to_string()),
            "promote must accumulate both destinations, got {sni:?}"
        );
    }

    #[test]
    fn promote_preserves_hand_added_entries() {
        let path = scratch("handadd.toml");
        // User hand-curated an entry the baseline never observed.
        std::fs::write(
            &path,
            "[process.node]\nallow_sni = [\"internal.corp\"]\nallow_ports = [443]\n",
        )
        .unwrap();
        merge_rules_into_policy_file(
            &[(
                "node".to_string(),
                ProcessRule {
                    allow_sni: vec!["api.stripe.com".into()],
                    allow_ports: vec![443],
                    ..Default::default()
                },
            )],
            &path,
        )
        .unwrap();
        let policy = load_policy_file(&path).unwrap();
        let sni = &policy.process.get("node").unwrap().allow_sni;
        assert!(
            sni.contains(&"internal.corp".to_string()),
            "hand-added entry must survive promote, got {sni:?}"
        );
        assert!(sni.contains(&"api.stripe.com".to_string()));
    }

    #[test]
    fn nameless_destination_keeps_its_real_ip() {
        let mut p = EgressProfiler::new();
        p.record("nc", "203.0.113.7", 4444, None, None, SystemTime::now());
        let snap = p.snapshot();
        let dest = snap[0]
            .dests
            .get(&("203.0.113.7".to_string(), 4444))
            .unwrap();
        assert_eq!(dest.last_ip, "203.0.113.7");
        // And it reaches the export as a concrete endpoint.
        let rec = &p.export_records()[0];
        assert_eq!(rec.ip, "203.0.113.7");
    }

    #[test]
    fn named_destination_still_records_the_backing_ip() {
        let mut p = EgressProfiler::new();
        p.record(
            "chrome",
            "142.250.1.1",
            443,
            sni("www.google.com"),
            Some("Google LLC".into()),
            SystemTime::now(),
        );
        let snap = p.snapshot();
        let dest = snap[0]
            .dests
            .get(&("www.google.com".to_string(), 443))
            .unwrap();
        assert_eq!(
            dest.last_ip, "142.250.1.1",
            "named row still carries the IP"
        );
    }

    #[test]
    fn violations_are_retained_for_the_on_screen_panel() {
        let mut p = EgressProfiler::new();
        let mut policy = EgressPolicy::default();
        policy.process.insert(
            "app".into(),
            ProcessRule {
                allow_sni: vec!["api.example.com".into()],
                ..Default::default()
            },
        );
        p.set_policy(Some(policy));
        assert_eq!(p.recent_violation_count(), 0);

        p.check_policy(
            "app",
            "203.0.113.9",
            443,
            &sni("evil.example.com"),
            &None,
            false,
            Instant::now(),
        );
        // Draining the alert feed does NOT clear the on-screen history.
        let _ = p.take_violations();
        assert_eq!(p.recent_violation_count(), 1);
        let v = p.recent_violations().next().unwrap();
        assert_eq!(v.process, "app");
        assert_eq!(v.dest, "evil.example.com");
        assert!(v.reason.contains("not in allowlist"));
    }

    #[test]
    fn rule_diff_reports_additions() {
        let new = ProcessRule {
            allow_sni: vec!["a.com".into(), "b.com".into()],
            allow_asn: vec![],
            allow_ip: vec![],
            allow_ports: vec![443],
        };
        assert_eq!(
            rule_diff(None, &new),
            "new rule: 2 SNI, 0 ASN, 0 IP, 1 ports"
        );

        let old = ProcessRule {
            allow_sni: vec!["a.com".into()],
            allow_asn: vec![],
            allow_ip: vec![],
            allow_ports: vec![443],
        };
        assert_eq!(
            rule_diff(Some(&old), &new),
            "+1 SNI, +0 ASN, +0 IP, +0 ports"
        );
        assert_eq!(rule_diff(Some(&new), &new), "no additions");
    }
}

/// Regressions for the blank-destination / split-profile defects found in the
/// 2026-07-26 review. Each test names the failure it locks out.
#[cfg(test)]
mod blank_and_split_regressions {
    use super::*;

    fn sni(host: &str) -> Option<String> {
        Some(host.to_string())
    }

    fn dest(sni: Option<&str>, asn: Option<&str>, ip: &str) -> EgressDest {
        EgressDest {
            sni: sni.map(str::to_string),
            asn_org: asn.map(str::to_string),
            port: 443,
            last_ip: ip.to_string(),
            ech: false,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            count: 1,
            bytes_out: 0,
            bytes_in: 0,
            activity: VecDeque::new(),
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nw-egress-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // ── blank destinations (Finding 2) ──────────────────────────────────

    /// An address with an empty host is not an address. Returning `Some("")`
    /// here is what let blank destinations into the baseline at all.
    #[test]
    fn empty_host_parses_as_no_host() {
        assert_eq!(crate::app::parse_addr_parts(":443").0, None);
        assert_eq!(
            crate::app::parse_addr_parts(":443").1.as_deref(),
            Some("443")
        );
        // The wildcard and well-formed cases are unchanged.
        assert_eq!(crate::app::parse_addr_parts("*:443").0, None);
        assert_eq!(
            crate::app::parse_addr_parts("1.2.3.4:443").0.as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(
            crate::app::parse_addr_parts("[2001:db8::1]:443")
                .0
                .as_deref(),
            Some("2001:db8::1")
        );
    }

    /// `is_private_ip("")` is false, so an empty IP clears every guard in
    /// `observe` unless it is rejected explicitly.
    #[test]
    fn empty_ip_is_not_mistaken_for_public() {
        assert!(!is_private_ip(""), "empty IP is not private…");
        // …which is exactly why observe() needs its own emptiness check.
        let mut p = EgressProfiler::new();
        p.record("curl", "", 443, None, None, SystemTime::now());
        // record() bypasses observe()'s guard, so this asserts the *storage*
        // shape the guard is protecting: nothing else should ever see it.
        assert_eq!(p.dest_count(), 1);
    }

    /// A flow whose address couldn't be read must not erase an endpoint we
    /// already resolved — this is what blanked named rows on disk.
    #[test]
    fn unreadable_address_does_not_erase_a_known_ip() {
        let mut p = EgressProfiler::new();
        let t = SystemTime::now();
        p.record("curl", "203.0.113.7", 443, sni("api.example.com"), None, t);
        p.record("curl", "", 443, sni("api.example.com"), None, t);
        let snap = p.snapshot();
        let d = snap[0].dests.values().next().unwrap();
        assert_eq!(d.last_ip, "203.0.113.7", "known IP was downgraded");
        assert_eq!(d.count, 2, "both flows counted");
    }

    /// A destination with nothing readable must not warn with an empty
    /// subject — " not in allowlist" reads as a bug, not a finding.
    #[test]
    fn violation_never_names_an_empty_destination() {
        let rule = ProcessRule {
            allow_sni: vec!["api.example.com".into()],
            allow_asn: vec![],
            allow_ip: vec![],
            allow_ports: vec![],
        };
        let msg = rule.violation(None, None, "", 443).unwrap();
        assert_eq!(msg, "unknown destination not in allowlist");
        assert!(!msg.starts_with(' '), "no empty subject");
    }

    // ── baseline repair (Findings 2c + 3) ───────────────────────────────

    /// A baseline written before the `ip` field existed has the address only
    /// in the key label. Loading must recover it rather than surfacing a
    /// blank row that warns as drift.
    #[test]
    fn legacy_baseline_recovers_the_ip_from_the_label() {
        let dir = tmpdir("legacy");
        let path = dir.join("legacy.json");
        let now = unix_secs(SystemTime::now());
        let legacy = format!(
            r#"{{"version":1,"profiles":[{{"process":"curl","dests":[
               {{"label":"203.0.113.7","port":443,"sni":null,"asn_org":null,
                 "first_seen":{now},"last_seen":{now},"count":5}}]}}]}}"#
        );
        std::fs::write(&path, legacy).unwrap();

        let mut p = EgressProfiler::new();
        p.load_profiles(&path);
        let snap = p.snapshot();
        let d = snap[0].dests.values().next().unwrap();
        assert_eq!(d.last_ip, "203.0.113.7", "IP recovered from label");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The label repair must never put a *hostname* in the IP column — it
    /// only applies when neither name was recorded.
    #[test]
    fn label_repair_does_not_put_a_hostname_in_the_ip_field() {
        let dir = tmpdir("named");
        let path = dir.join("named.json");
        let now = unix_secs(SystemTime::now());
        let body = format!(
            r#"{{"version":1,"profiles":[{{"process":"curl","dests":[
               {{"label":"api.example.com","port":443,"sni":"api.example.com",
                 "asn_org":null,"ip":"","first_seen":{now},"last_seen":{now},"count":1}}]}}]}}"#
        );
        std::fs::write(&path, body).unwrap();

        let mut p = EgressProfiler::new();
        p.load_profiles(&path);
        let snap = p.snapshot();
        let d = snap[0].dests.values().next().unwrap();
        assert_eq!(d.last_ip, "", "hostname must not masquerade as an IP");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── truncated process names (Finding 1a) ────────────────────────────

    /// The core split: PKTAP's 16-byte `comm` and lsof's full name are the
    /// same program and must share one profile, in either arrival order.
    #[test]
    fn truncated_and_full_names_merge_in_both_directions() {
        let full = "Google Chrome Helper";
        let trunc = &full[..COMM_TRUNCATE_LEN];
        let t = SystemTime::now();

        // truncated first, then full
        let mut a = EgressProfiler::new();
        a.record(trunc, "203.0.113.1", 443, sni("a.example.com"), None, t);
        a.record(full, "203.0.113.2", 443, sni("b.example.com"), None, t);
        assert_eq!(a.process_count(), 1, "did not merge (truncated first)");
        assert_eq!(a.snapshot()[0].process, full);
        assert_eq!(a.dest_count(), 2, "both destinations kept");

        // full first, then truncated
        let mut b = EgressProfiler::new();
        b.record(full, "203.0.113.2", 443, sni("b.example.com"), None, t);
        b.record(trunc, "203.0.113.1", 443, sni("a.example.com"), None, t);
        assert_eq!(b.process_count(), 1, "did not merge (full first)");
        assert_eq!(b.snapshot()[0].process, full);
    }

    /// The guard that keeps the merge honest: a name shorter than the
    /// truncation length is complete, so VS Code's real `Code Helper` must
    /// stay separate from the truncated `Code Helper (Plugin)`.
    #[test]
    fn a_complete_short_name_is_never_merged() {
        let t = SystemTime::now();
        let mut p = EgressProfiler::new();
        p.record("Code Helper", "203.0.113.1", 443, None, None, t);
        p.record("Code Helper (Plugin)", "203.0.113.2", 443, None, None, t);
        assert_eq!(
            p.process_count(),
            2,
            "'Code Helper' is 11 bytes — complete, not truncated"
        );
    }

    /// Merging must carry the hit counts, not silently reset them.
    #[test]
    fn merge_sums_counts_for_a_shared_destination() {
        let full = "Google Chrome Helper";
        let trunc = &full[..COMM_TRUNCATE_LEN];
        let t = SystemTime::now();
        let mut p = EgressProfiler::new();
        p.record(trunc, "203.0.113.1", 443, sni("a.example.com"), None, t);
        p.record(trunc, "203.0.113.1", 443, sni("a.example.com"), None, t);
        p.record(full, "203.0.113.1", 443, sni("a.example.com"), None, t);
        assert_eq!(p.process_count(), 1);
        let snap = p.snapshot();
        assert_eq!(snap[0].dests.values().next().unwrap().count, 3);
    }

    /// A policy promoted under the full name must cover a flow attributed
    /// under the truncated one — otherwise promote doesn't cover its own
    /// baseline, which is the whole promise of warn-on-drift.
    #[test]
    fn policy_under_the_full_name_covers_the_truncated_spelling() {
        let full = "Google Chrome Helper";
        let trunc = &full[..COMM_TRUNCATE_LEN];
        let mut p = EgressProfiler::new();
        let mut policy = EgressPolicy::default();
        policy.process.insert(
            full.into(),
            ProcessRule {
                allow_sni: vec!["a.example.com".into()],
                allow_asn: vec![],
                allow_ip: vec![],
                allow_ports: vec![],
            },
        );
        p.set_policy(Some(policy));
        // Seed the full-name profile so the truncated form resolves to it.
        p.record(
            full,
            "203.0.113.1",
            443,
            sni("a.example.com"),
            None,
            SystemTime::now(),
        );

        let allowed = dest(Some("a.example.com"), None, "203.0.113.1");
        assert_eq!(
            p.dest_allowed(trunc, &allowed),
            Some(true),
            "declared destination warned as drift under the truncated name"
        );
    }
}

/// The verdict vocabulary: `✓ sni` and `~ asn` are both "admitted", but only
/// one of them is a statement about a single endpoint. Collapsing them is
/// what let a promoted rule quietly allow an entire hyperscaler.
#[cfg(test)]
mod verdict_tests {
    use super::*;

    fn rule(sni: &[&str], asn: &[&str], ip: &[&str], ports: &[u16]) -> ProcessRule {
        ProcessRule {
            allow_sni: sni.iter().map(|s| s.to_string()).collect(),
            allow_asn: asn.iter().map(|s| s.to_string()).collect(),
            allow_ip: ip.iter().map(|s| s.to_string()).collect(),
            allow_ports: ports.to_vec(),
        }
    }

    fn profiler(r: ProcessRule) -> EgressProfiler {
        let mut p = EgressProfiler::new();
        let mut policy = EgressPolicy::default();
        policy.process.insert("app".into(), r);
        p.set_policy(Some(policy));
        p
    }

    fn dest(sni: Option<&str>, asn: Option<&str>, ip: &str, ech: bool) -> EgressDest {
        EgressDest {
            sni: sni.map(str::to_string),
            asn_org: asn.map(str::to_string),
            port: 443,
            last_ip: ip.to_string(),
            ech,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
            count: 1,
            bytes_out: 0,
            bytes_in: 0,
            activity: VecDeque::new(),
        }
    }

    #[test]
    fn exact_hostname_is_reported_as_precise() {
        let p = profiler(rule(&["api.example.com"], &[], &[], &[]));
        assert_eq!(
            p.verdict(
                "app",
                &dest(Some("api.example.com"), None, "1.2.3.4", false)
            ),
            Verdict::Sni
        );
    }

    /// The finding this whole vocabulary exists for: admitted, but by an
    /// autonomous system rather than a name. Must not read as `Sni`.
    #[test]
    fn asn_match_is_distinguished_from_a_name_match() {
        let p = profiler(rule(&["api.example.com"], &["Google LLC"], &[], &[]));
        let v = p.verdict("app", &dest(None, Some("Google LLC"), "1.2.3.4", false));
        assert_eq!(v, Verdict::Asn("Google LLC".into()));
        assert!(v.is_notable(), "an ASN-wide match must be flagged");
        assert_ne!(v, Verdict::Sni);
    }

    /// A destination with a readable name that isn't declared, admitted only
    /// because its ASN is — the silent over-admission. It must surface as
    /// `Asn`, not a clean tick.
    #[test]
    fn undeclared_hostname_admitted_by_asn_is_flagged_not_clean() {
        let p = profiler(rule(&["api.example.com"], &["Google LLC"], &[], &[]));
        let v = p.verdict(
            "app",
            &dest(
                Some("evil.appspot.com"),
                Some("Google LLC"),
                "1.2.3.4",
                false,
            ),
        );
        assert_eq!(v, Verdict::Asn("Google LLC".into()));
        assert!(v.is_notable());
    }

    #[test]
    fn declared_ip_is_precise() {
        let p = profiler(rule(&[], &[], &["1.2.3.4"], &[]));
        assert_eq!(
            p.verdict("app", &dest(None, None, "1.2.3.4", false)),
            Verdict::Ip
        );
    }

    #[test]
    fn outside_the_allowlist_is_drift() {
        let p = profiler(rule(&["api.example.com"], &[], &[], &[]));
        assert_eq!(
            p.verdict(
                "app",
                &dest(Some("evil.example.net"), None, "9.9.9.9", false)
            ),
            Verdict::Drift
        );
    }

    /// ECH hides the real name, so a miss is "cannot judge" — never drift.
    #[test]
    fn ech_miss_is_unreadable_not_drift() {
        let p = profiler(rule(&["api.example.com"], &[], &[], &[]));
        assert_eq!(
            p.verdict("app", &dest(None, None, "9.9.9.9", true)),
            Verdict::Ech
        );
    }

    /// The critical coverage gap, made explicit: a process with no rule is
    /// never checked, and that must be a distinct visible state rather than
    /// looking like approval.
    #[test]
    fn undeclared_process_is_unchecked_not_approved() {
        let p = profiler(rule(&["api.example.com"], &[], &[], &[]));
        let v = p.verdict("other", &dest(Some("anything.com"), None, "9.9.9.9", false));
        assert_eq!(v, Verdict::NoRule);
        assert!(v.is_notable(), "unchecked must be visible");
        assert_ne!(v, Verdict::Sni);
    }

    #[test]
    fn no_policy_is_its_own_state() {
        let p = EgressProfiler::new();
        assert_eq!(
            p.verdict("app", &dest(Some("x.com"), None, "1.2.3.4", false)),
            Verdict::NoPolicy
        );
    }

    /// A port outside the allowlist is drift regardless of the name.
    #[test]
    fn port_outside_the_allowlist_is_drift() {
        let p = profiler(rule(&["api.example.com"], &[], &[], &[8443]));
        assert_eq!(
            p.verdict(
                "app",
                &dest(Some("api.example.com"), None, "1.2.3.4", false)
            ),
            Verdict::Drift
        );
    }

    /// Under a policy that declares itself complete, the same absence is a
    /// finding rather than a blind spot — and must not be confused with
    /// drift, which is a *declared* process going somewhere new.
    #[test]
    fn strict_mode_reports_an_undeclared_process_as_a_finding() {
        let mut p = profiler(rule(&["api.example.com"], &[], &[], &[]));
        let mut policy = p.policy.clone().unwrap();
        policy.strict = true;
        p.set_policy(Some(policy));

        let v = p.verdict("other", &dest(Some("anything.com"), None, "9.9.9.9", false));
        assert_eq!(v, Verdict::Undeclared);
        assert!(v.is_notable());
        assert_ne!(v, Verdict::Drift, "nothing was compared — don't say drift");
        assert_eq!(
            p.dest_allowed("other", &dest(Some("anything.com"), None, "9.9.9.9", false)),
            Some(false),
            "strict turns 'unchecked' into 'not allowed'"
        );
        // A process that IS declared is unaffected.
        assert_eq!(
            p.verdict(
                "app",
                &dest(Some("api.example.com"), None, "1.2.3.4", false)
            ),
            Verdict::Sni
        );
    }

    /// Strict mode is opt-in: the same profiler without the flag stays silent
    /// about processes it was never told about.
    #[test]
    fn strict_is_off_by_default_and_observe_mode_stays_silent() {
        let mut p = profiler(rule(&["api.example.com"], &[], &[], &[]));
        assert!(!p.policy.as_ref().unwrap().strict);
        let now = Instant::now();
        for _ in 0..10 {
            p.record_flow(
                "unknown",
                "203.0.113.9",
                443,
                sni("evil.example.com"),
                None,
                false,
                SystemTime::now(),
                0,
                0,
            );
            p.check_policy(
                "unknown",
                "203.0.113.9",
                443,
                &sni("evil.example.com"),
                &None,
                false,
                now,
            );
        }
        assert!(
            p.take_violations().is_empty(),
            "observe mode must not warn about an undeclared process"
        );
    }

    /// The warning strict mode exists to produce, plus the settle threshold
    /// that keeps a fork storm of one-tick build tooling from storming.
    #[test]
    fn strict_warns_on_an_undeclared_process_once_it_has_settled() {
        let mut p = profiler(rule(&["api.example.com"], &[], &[], &[]));
        let mut policy = p.policy.clone().unwrap();
        policy.strict = true;
        p.set_policy(Some(policy));
        p.set_violation_cooldown(0);
        let now = Instant::now();

        let step = |p: &mut EgressProfiler| {
            p.record_flow(
                "backdoor",
                "203.0.113.9",
                443,
                sni("evil.example.com"),
                None,
                false,
                SystemTime::now(),
                0,
                0,
            );
            p.check_policy(
                "backdoor",
                "203.0.113.9",
                443,
                &sni("evil.example.com"),
                &None,
                false,
                now,
            );
        };

        // A single-tick appearance is below the settle threshold.
        step(&mut p);
        assert!(
            p.take_violations().is_empty(),
            "a one-tick process must not warn"
        );

        // Sustained presence crosses it.
        for _ in 0..UNDECLARED_SETTLE_TICKS {
            step(&mut p);
        }
        let v = p.take_violations();
        assert!(!v.is_empty(), "a settled undeclared process must warn");
        assert_eq!(v[0].process, "backdoor");
        assert!(
            v[0].reason.contains("no rule"),
            "the reason must name the actual finding, got {:?}",
            v[0].reason
        );
        assert_eq!(
            p.violation_totals_sorted()
                .iter()
                .find(|(n, _)| n == "backdoor")
                .map(|(_, c)| *c),
            Some(v.len() as u64),
            "strict findings feed the same violation counter as drift"
        );
    }

    /// Strict findings export under their own verdict rather than being
    /// folded into `drift` — the consumer should be able to tell "went
    /// somewhere new" from "was never accounted for".
    #[test]
    fn strict_finding_exports_as_undeclared() {
        let mut p = profiler(rule(&["api.example.com"], &[], &[], &[]));
        let mut policy = p.policy.clone().unwrap();
        policy.strict = true;
        p.set_policy(Some(policy));
        p.record_flow(
            "backdoor",
            "203.0.113.9",
            443,
            sni("evil.example.com"),
            None,
            false,
            SystemTime::now(),
            0,
            0,
        );
        let recs = p.export_records();
        let rec = recs.iter().find(|r| r.process == "backdoor").unwrap();
        assert_eq!(rec.verdict, "undeclared");
        assert_eq!(rec.matched_by, None);
    }

    /// Promotion must not widen a rule to an entire autonomous system: one
    /// nameless flow to a hyperscaler would otherwise admit every host that
    /// hyperscaler operates, for that process, permanently and invisibly.
    #[test]
    fn promotion_never_widens_to_an_autonomous_system() {
        let mut p = EgressProfiler::new();
        let now = SystemTime::now();
        p.record(
            "app",
            "35.190.46.17",
            443,
            None,
            Some("Google LLC".into()),
            now,
        );

        let rule = p.promote_one("app").unwrap();
        assert!(
            rule.allow_asn.is_empty(),
            "promoted an ASN: {:?}",
            rule.allow_asn
        );
        assert_eq!(rule.allow_ip, vec!["35.190.46.17".to_string()]);

        // The narrower rule still admits the baseline it came from...
        assert!(rule
            .violation(None, Some("Google LLC"), "35.190.46.17", 443)
            .is_none());
        // ...but a different Google-hosted endpoint is now drift, where the
        // ASN-wide rule would have rendered it a clean tick.
        assert!(rule
            .violation(
                Some("evil.appspot.com"),
                Some("Google LLC"),
                "35.190.46.99",
                443
            )
            .is_some());
    }

    /// `Unassigned` is the geo database's *failure* label, not an
    /// organisation. Allowlisting it would admit every destination whose ASN
    /// lookup failed — an allowlist that grows by not working.
    #[test]
    fn a_failed_asn_lookup_is_never_promoted_as_an_identity() {
        for label in ["Unassigned", "unassigned", "  ", "Unknown"] {
            assert!(!is_identifying_asn(label), "{label:?} is not an identity");
        }
        assert!(is_identifying_asn("Google LLC"));

        // Even on the last-resort path — no name and no address — a failure
        // label must not become a rule.
        let mut p = EgressProfiler::new();
        p.record_flow(
            "app",
            "",
            443,
            None,
            Some("Unassigned".into()),
            false,
            SystemTime::now(),
            0,
            0,
        );
        let rule = p.promote_one("app").unwrap_or_default();
        assert!(rule.allow_asn.is_empty());
    }

    #[test]
    fn bytes_accumulate_and_never_downgrade() {
        let mut p = EgressProfiler::new();
        let t = SystemTime::now();
        p.record_flow("app", "1.2.3.4", 443, sni("a.com"), None, false, t, 100, 10);
        p.record_flow("app", "1.2.3.4", 443, sni("a.com"), None, false, t, 50, 5);
        let snap = p.snapshot();
        let d = snap[0].dests.values().next().unwrap();
        assert_eq!(d.bytes_out, 150);
        assert_eq!(d.bytes_in, 15);
        assert_eq!(d.activity.len(), 2, "one activity sample per observation");
    }

    fn sni(h: &str) -> Option<String> {
        Some(h.to_string())
    }
}
