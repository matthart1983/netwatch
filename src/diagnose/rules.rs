//! The built-in ruleset: what netwatch knows how to recognise, and which
//! findings are consequences of which others.
//!
//! The catalogue is data, not code paths. Each [`Rule`] carries the metadata
//! the UI and the report need — severity, the plain-English trigger, the
//! suppression edges — and declares whether netwatch can currently *evaluate*
//! it ([`RuleStatus`]). A rule netwatch can't yet evaluate is listed as
//! `Planned` and is visible in the ruleset browser, but it can never open an
//! issue. That distinction is the point: a diagnostic tool that lists 24 rules
//! and silently evaluates nine is lying about its coverage.

use super::issue::{Issue, IssueId, Kind, RuleId, Severity, Subject, Verify};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleStatus {
    /// Detector implemented; runtime coverage determines whether inputs exist.
    Active,
    /// In the catalogue, not yet wired to a data source. Cannot open an issue.
    /// The `&'static str` says what input is missing.
    Planned(&'static str),
}

impl RuleStatus {
    pub fn is_active(self) -> bool {
        matches!(self, RuleStatus::Active)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub id: RuleId,
    /// Issue title when this rule fires.
    pub title: &'static str,
    /// Category for grouping in the ruleset browser: dns, link, path, tcp…
    pub category: &'static str,
    pub severity: Severity,
    /// Plain-English trigger, shown in the "how issues are found" panel.
    pub trigger: &'static str,
    /// Rules whose issues become consequences of this one when both are open
    /// and they share a subject scope. Explicit — never inferred. An
    /// Observation of this rule still never hides an Issue.
    pub suppresses: &'static [RuleId],
    pub status: RuleStatus,
    /// What must be measured before this rule may fire. Empty means the rule
    /// has not been through a contract review yet, which the generated
    /// coverage document states rather than hides.
    pub evidence: &'static [&'static str],
    /// Healthy situations that produce the same symptom, and which the rule's
    /// checks have to tell apart.
    pub lookalikes: &'static [&'static str],
    /// What counts as recovery, in words.
    pub recovery: &'static str,
    /// Where the rule can run at all, and what it cannot see.
    pub platforms: &'static str,
}

impl Rule {
    /// Whether this rule has been through the contract review: evidence,
    /// lookalikes, recovery and platform limits all stated.
    pub fn contracted(&self) -> bool {
        !self.evidence.is_empty()
            && !self.lookalikes.is_empty()
            && !self.recovery.is_empty()
            && !self.platforms.is_empty()
    }

    /// Beta until its contract is reviewed. A beta rule's issues are shown,
    /// tagged, and leave `diagnose run`'s exit status alone unless asked
    /// (`--include-beta`): netwatch makes no promise about a rule nobody has
    /// written the evidence and lookalikes down for.
    pub fn beta(&self) -> bool {
        !self.contracted()
    }
}

/// Built-in ruleset v1.
pub const CATALOGUE: &[Rule] = &[
    // ---------------------------------------------------------------- dns
    Rule {
        id: "dns.slow_resolver",
        title: "slow dns resolver",
        category: "dns",
        severity: Severity::Medium,
        trigger: "resolver p50 > 3σ above baseline, at least 5ms above it and at least 2× it, or p50 > 100ms with or without a baseline, for 3 samples",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "dns.failing",
        title: "dns resolution failing",
        category: "dns",
        severity: Severity::High,
        trigger: "servfail/timeout rate > 5%, or the pipeline dns stage fails",
        suppresses: &["dns.slow_resolver", "target.resolve_failed"],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "dns.truncation_retry",
        title: "dns replies truncating",
        category: "dns",
        severity: Severity::Info,
        trigger: "more than 10% of probe replies carry the TC bit",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "dns.hijack_suspect",
        title: "dns answers disagree",
        category: "dns",
        severity: Severity::High,
        trigger: "a private address for a public name, or disagreement with a validating reference on most cycles",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[
            "the same name asked of the configured resolver and of a reference resolver",
            "whether the answer is private, and whether the reference validated it",
        ],
        lookalikes: &[
            "split-horizon dns on a corporate network, which is by design",
            "a cdn answering differently by geography",
        ],
        recovery: "the two resolvers agree again, or the private answer stops",
        platforms: "anywhere a reference resolver is reachable; blocked outbound dns leaves it unmeasured",
    },
    // ------------------------------------------------------- gateway / link
    Rule {
        id: "gateway.unreachable",
        title: "gateway unreachable",
        category: "link",
        severity: Severity::Critical,
        // The root cause of nearly everything else, so it suppresses widely.
        // A quiet router alone is not enough: a failed internet probe has to
        // corroborate it, and no ARP probe exists to consult.
        trigger: "icmp and the tcp fallback to the default gateway both fail, and the internet probe fails too; arp is not probed",
        suppresses: &[
            "dns.slow_resolver",
            "dns.failing",
            "gateway.rtt_spike",
            "path.high_loss",
            "path.rtt_spike",
            "tcp.retrans_burst",
            "tcp.connect_failures",
            "target.resolve_failed",
            "target.connect_failed",
            "target.tls_failed",
            "target.http_error",
            "target.slow_stage",
        ],
        status: RuleStatus::Active,
        evidence: &[
            "arp or icmp probe to the default gateway, with its result",
            "an internet probe beyond the gateway, to tell a quiet router from a broken one",
        ],
        lookalikes: &[
            "a router that does not answer icmp but forwards normally",
            "an unprivileged run that cannot send icmp at all",
        ],
        recovery: "the gateway answers again, or something beyond it does",
        platforms: "linux and macos; no arp probe exists yet, so arp is reported as unmeasured",
    },
    Rule {
        id: "link.down",
        title: "link down",
        category: "link",
        severity: Severity::Critical,
        // Each OS reports "up" differently, and macOS reports the admin flag
        // rather than carrier. A09 moves macOS to the `status:` line and
        // rewrites that clause.
        trigger: "the os reports the interface down: on linux operstate is not up, where unknown with carrier set counts as up; on macos ifconfig lacks the UP flag, which is the admin state, so an unplugged cable is not seen; on windows ipconfig says \"Media disconnected\"",
        suppresses: &["gateway.unreachable"],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "gateway.rtt_spike",
        title: "gateway slow to answer",
        category: "link",
        severity: Severity::Medium,
        trigger: "gateway rtt > 3σ and at least 10ms above baseline for 3 samples",
        suppresses: &["path.rtt_spike"],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "iface.errors",
        title: "interface errors",
        category: "link",
        severity: Severity::Medium,
        trigger: "rx/tx error, drop, overrun or fifo counters increment",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "iface.saturated",
        title: "interface saturated",
        category: "link",
        severity: Severity::Medium,
        trigger: "throughput above 90% of link rate for 30s",
        suppresses: &["tcp.bufferbloat_local", "path.rtt_spike"],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "wifi.weak_signal",
        title: "weak wifi signal",
        category: "link",
        severity: Severity::Medium,
        trigger: "signal at or below −70 dBm, or more than 20% of frames retried over a minute",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    // --------------------------------------------------------------- path
    Rule {
        id: "path.changed",
        title: "upstream path changed",
        category: "path",
        severity: Severity::Info,
        trigger: "a hop differs between consecutive traces to the same target",
        // A reroute that costs latency is one finding, not two. The rtt spike
        // is reported underneath as the consequence it is, which is also what
        // makes the pair readable: "the path changed, and it cost you 40ms".
        suppresses: &["path.rtt_spike"],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "path.high_loss",
        title: "loss on the path",
        category: "path",
        severity: Severity::High,
        trigger: "a hop loses packets and the loss propagates to later hops",
        suppresses: &["tcp.retrans_burst"],
        status: RuleStatus::Active,
        evidence: &[
            "per-hop loss from a trace, with silent hops distinguished from lossy ones",
            "whether the destination itself answered the trace",
        ],
        lookalikes: &[
            "a hop rate-limiting its own icmp while forwarding traffic normally",
            "a firewalled tail that answers nothing, so propagation cannot be seen",
        ],
        recovery: "a later trace to the same target shows no hop losing packets",
        platforms: "native trace on linux ipv4; elsewhere a traceroute subprocess, which cannot always tell whether the destination replied",
    },
    Rule {
        id: "path.rtt_spike",
        title: "path rtt above baseline",
        category: "path",
        severity: Severity::Medium,
        trigger: "end-to-end rtt > 3σ above baseline",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    // ---------------------------------------------------------- tcp/sockets
    Rule {
        id: "tcp.bufferbloat_local",
        title: "bufferbloat on the uplink",
        category: "tcp",
        severity: Severity::High,
        trigger: "rtt under load exceeds idle rtt by more than 100ms",
        suppresses: &["tcp.bufferbloat_remote", "path.rtt_spike"],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "tcp.bufferbloat_remote",
        title: "receiver-side bufferbloat",
        category: "tcp",
        severity: Severity::Medium,
        trigger: "one socket's rtt rises with its own tx while the link-level test passes",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[
            "socket rtt and tx rate from the kernel, held for the verdict window",
            "an idle-versus-loaded rtt comparison on our own uplink, to place the queue",
        ],
        lookalikes: &[
            "a stable distant peer, whose rtt is distance rather than queueing",
            "our own uplink bloating, which is the local rule, not this one",
        ],
        recovery: "socket rtt returns to its baseline while the socket is still sending",
        platforms: "linux and macos; without the loaded-rtt test the finding names an unlocalised queue",
    },
    Rule {
        id: "tcp.retrans_burst",
        title: "retransmission burst",
        category: "tcp",
        severity: Severity::Medium,
        trigger: "5 or more retransmits per minute on a socket whose rtt is under the queueing threshold",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "tcp.zero_window",
        title: "receiver not reading",
        category: "tcp",
        severity: Severity::Info,
        trigger: "rwnd is zero, or cwnd greatly exceeds rwnd",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "tcp.connect_failures",
        title: "connections failing",
        category: "tcp",
        severity: Severity::Medium,
        trigger: "more than 5 failed active or passive TCP handshakes per minute in this namespace",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "tcp.timewait_exhaustion",
        title: "time-wait pressure",
        category: "tcp",
        severity: Severity::Info,
        trigger: "distinct TIME_WAIT local ports exceed 60% of the ephemeral range for one address; not exhaustion proof",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    // ------------------------------------------------- mtu / nat / v6 / cap
    Rule {
        id: "pmtu.blackhole",
        title: "path mtu blackhole",
        category: "mtu",
        severity: Severity::High,
        trigger: "small DF probes work, large probes time out, and reducing TCP MSS restores a transfer to the same endpoint",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "nat.symmetric",
        title: "symmetric nat",
        category: "nat",
        severity: Severity::Info,
        trigger: "two stun servers see different public ports from one socket",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "ipv6.broken",
        title: "ipv6 route present but unusable",
        category: "ipv6",
        severity: Severity::Medium,
        trigger: "a v6 default route exists but v6 probes fail while v4 works",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "captive.portal",
        title: "captive portal intercepting",
        category: "captive",
        severity: Severity::High,
        trigger: "the http 204 probe is redirected",
        // Selected-endpoint HTTP evidence cannot establish global causality.
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    // ------------------------------------------------------------- targets
    Rule {
        id: "target.resolve_failed",
        title: "target name does not resolve",
        category: "target",
        severity: Severity::Medium,
        trigger: "a configured target's name fails to resolve for 3 probes",
        suppresses: &[
            "target.connect_failed",
            "target.tls_failed",
            "target.http_error",
            "target.slow_stage",
        ],
        status: RuleStatus::Active,
        evidence: &[
            "a lookup for the configured target, with the resolver that answered",
            "the outcome per resolver: answered, nxdomain, servfail or no reply",
        ],
        lookalikes: &[
            "a name that genuinely does not exist",
            "split-horizon dns where the name only resolves on another link",
        ],
        recovery: "the same target resolves again on its own probe",
        platforms: "all platforms; resolver identity comes from systemd-resolved where available",
    },
    Rule {
        id: "target.connect_failed",
        title: "target refuses or drops connections",
        category: "target",
        severity: Severity::Medium,
        trigger: "a configured target's first address fails to connect for 3 probes",
        suppresses: &["target.tls_failed", "target.http_error", "target.slow_stage"],
        status: RuleStatus::Active,
        evidence: &[
            "a connect attempt per address and family, with the error each returned",
        ],
        lookalikes: &[
            "a service that is down, which is not a network fault",
            "one address family broken while the other works",
        ],
        recovery: "the same target connects again on its own probe",
        platforms: "all platforms",
    },
    Rule {
        id: "target.tls_failed",
        title: "target tls handshake fails",
        category: "target",
        severity: Severity::Medium,
        trigger: "a configured target's TLS handshake fails for 3 probes",
        suppresses: &["target.http_error", "target.slow_stage"],
        status: RuleStatus::Active,
        evidence: &[
            "the tls handshake result on the connection that succeeded, with the certificate error",
        ],
        lookalikes: &[
            "an enterprise ca that netwatch does not trust",
            "a clock skew that makes a valid certificate look expired",
        ],
        recovery: "the handshake completes again on the same target",
        platforms: "all platforms; system trust stores are read where available",
    },
    Rule {
        id: "target.http_error",
        title: "target returns an error",
        category: "target",
        severity: Severity::Medium,
        trigger: "a configured target answers 5xx, or not the expected status, for 3 probes",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[
            "the response status on the configured target, against the expected status",
        ],
        lookalikes: &[
            "an authentication or redirect response that is expected for this endpoint",
            "a proxy answering instead of the service",
        ],
        recovery: "the target returns its expected status again",
        platforms: "all platforms",
    },
    Rule {
        id: "target.slow_stage",
        title: "target slower than usual",
        category: "target",
        severity: Severity::Medium,
        trigger: "a target's dns, connect, tls or first-byte time > 3σ above its baseline for 3 probes",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    // -------------------------------------------------------------- egress
    Rule {
        id: "egress.drift",
        title: "egress drift",
        category: "egress",
        severity: Severity::Info,
        trigger: "a destination outside the learned egress baseline (only with alert = \"all\")",
        suppresses: &[],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
    Rule {
        id: "egress.policy_violation",
        title: "egress policy violation",
        category: "egress",
        severity: Severity::High,
        trigger: "an observed destination is blocked by the loaded policy, or with alert = \"all\" falls outside it (warning only)",
        suppresses: &["egress.drift"],
        status: RuleStatus::Active,
        evidence: &[],
        lookalikes: &[],
        recovery: "",
        platforms: "",
    },
];

/// The catalogue rendered as `docs/diagnostic-coverage.md`.
///
/// Generated rather than written by hand: the committed copy claimed 25 rules
/// when there were 30, omitted every `target.*` entry, and marked five active
/// rules as unintegrated. A test asserts the file matches this output, so the
/// document cannot drift from the catalogue again.
pub fn coverage_markdown() -> String {
    let total = CATALOGUE.len();
    let active = CATALOGUE.iter().filter(|r| r.status.is_active()).count();
    let contracted: Vec<&Rule> = CATALOGUE.iter().filter(|r| r.contracted()).collect();
    let mut m = String::new();
    m.push_str("# Diagnose rule coverage\n\n");
    m.push_str(
        "Generated from `rules::CATALOGUE` by `netwatch diagnose coverage --doc`. \
Do not edit by hand: `rules.rs` holds the source of truth, and a test fails when this \
file and the catalogue disagree.\n\n",
    );
    m.push_str(&format!(
        "The catalogue contains **{total} rules**, of which **{active}** are active. \
**{}** have been through a contract review: evidence, lookalikes, recovery and platform \
limits all stated. The rest are listed as not yet contracted, which is a statement about \
this document, not about whether the detector runs.\n\n",
        contracted.len()
    ));
    m.push_str(
        "Runtime availability is a separate question, answered per host by \
`netwatch diagnose coverage`: a rule with a detector may still have no inputs on the \
machine in front of you. An empty issue list says \"no findings\", never \"this host is \
healthy\".\n\n",
    );

    m.push_str("## Contracted rules\n\n");
    for rule in &contracted {
        m.push_str(&format!("### `{}`\n\n", rule.id));
        m.push_str(&format!(
            "{} · severity {:?}\n\n",
            rule.title, rule.severity
        ));
        m.push_str(&format!("**Fires when:** {}\n\n", rule.trigger));
        m.push_str("**Evidence required:**\n\n");
        for e in rule.evidence {
            m.push_str(&format!("- {e}\n"));
        }
        m.push_str("\n**Healthy lookalikes:**\n\n");
        for l in rule.lookalikes {
            m.push_str(&format!("- {l}\n"));
        }
        m.push_str(&format!("\n**Recovery:** {}\n\n", rule.recovery));
        m.push_str(&format!("**Platforms:** {}\n\n", rule.platforms));
        if !rule.suppresses.is_empty() {
            m.push_str(&format!(
                "**Suppresses:** {}\n\n",
                rule.suppresses
                    .iter()
                    .map(|r| format!("`{r}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    m.push_str("## Not yet contracted\n\n");
    m.push_str(
        "These rules have detectors and can open issues. What they have not had is a \
written statement of the evidence they need and the healthy situations they must not \
mistake for a fault. Until they do they are **beta**: their issues are shown and tagged \
beta, and set `netwatch diagnose run`'s exit status only with `--include-beta`.\n\n",
    );
    m.push_str("| Rule | Category | Fires when | Status |\n|---|---|---|---|\n");
    for rule in CATALOGUE.iter().filter(|r| !r.contracted()) {
        let status = match rule.status {
            RuleStatus::Active => "active".to_string(),
            RuleStatus::Planned(missing) => format!("planned — {missing}"),
        };
        m.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            rule.id, rule.category, rule.trigger, status
        ));
    }
    m
}

pub fn lookup(id: &str) -> Option<&'static Rule> {
    CATALOGUE.iter().find(|r| r.id == id)
}

pub fn active_count() -> usize {
    CATALOGUE.iter().filter(|r| r.status.is_active()).count()
}

/// `"24 rules · 20 active · 4 planned"` for the Diagnose footer. Being
/// explicit about the split is the difference between a ruleset and a wishlist.
pub fn catalogue_label() -> String {
    let total = CATALOGUE.len();
    let active = active_count();
    let planned = total - active;
    if planned == 0 {
        format!("{total} rules · all active")
    } else {
        format!("{total} rules · {active} active · {planned} planned")
    }
}

/// Whether a root finding can explain a child one.
///
/// Subject alone is too coarse: `gateway.unreachable` is filed against the
/// host and used to cover every target on the machine, including targets
/// reached over a tunnel that never touches that gateway. Where the two
/// findings record which interface or resolver they actually went through,
/// a demonstrated difference breaks the edge.
fn depends_on(root: &Issue, child: &Issue) -> bool {
    // Measured on different interfaces: neither explains the other, whatever
    // their subjects say.
    if let (Some(a), Some(b)) = (&root.scope.via_iface, &child.scope.via_iface) {
        if a != b {
            return false;
        }
    }
    // One target's name across an edit: the old entry's finding waits out
    // its expiry about an endpoint no longer probed, and explains nothing
    // the new entry finds.
    if let (Subject::Target { .. }, Subject::Target { .. }, Some(a), Some(b)) = (
        &root.subject,
        &child.subject,
        &root.scope.configuration,
        &child.scope.configuration,
    ) {
        if a != b {
            return false;
        }
    }
    match (&root.subject, &child.subject) {
        (Subject::Host, _) => true,
        (Subject::Iface { name }, Subject::Iface { name: other }) => name == other,
        // A link or gateway problem on an interface covers what runs over it —
        // unless the child recorded a different interface, handled above.
        (Subject::Iface { name }, _) => child
            .scope
            .via_iface
            .as_ref()
            .is_none_or(|used| used == name),
        // A failing resolver covers the names looked up through it. A target
        // that resolved through a different resolver is not its consequence.
        (Subject::Resolver { addr }, Subject::Target { .. }) => child
            .scope
            .via_resolver
            .as_ref()
            .is_none_or(|used| used == addr),
        (a, b) => a == b,
    }
}

/// Apply the suppression graph to a set of open issues.
///
/// Consequences are not deleted — they keep their evidence and are listed
/// under their root cause, which is what the report needs in order to explain
/// why three symptoms were one fault. Suppression is transitive: if link.down
/// suppresses gateway.unreachable, and gateway.unreachable suppresses
/// dns.failing, then dns.failing lands under link.down.
pub fn apply_suppression(issues: &mut [Issue]) {
    // Reset — suppression is recomputed from scratch each pass so an issue
    // that closes releases whatever it was suppressing.
    for i in issues.iter_mut() {
        i.suppressed_by = None;
        i.consequences.clear();
    }

    // Direct edges: root index → child index.
    let mut parent: HashMap<usize, usize> = HashMap::new();
    for (ci, child) in issues.iter().enumerate() {
        if !child.state.is_open() {
            continue;
        }
        let mut best: Option<(usize, Severity)> = None;
        for (ri, root) in issues.iter().enumerate() {
            // A muted root still explains its symptoms. Releasing them would
            // put a consequence at the head of the verdict for the hour the
            // user asked the cause to be quiet.
            if ri == ci || !root.state.is_tracked() {
                continue;
            }
            let Some(rule) = lookup(&root.rule) else {
                continue;
            };
            if !rule.suppresses.contains(&child.rule.as_str()) {
                continue;
            }
            if !depends_on(root, child) {
                continue;
            }
            // An Observation never hides an Issue. The edge stays in the
            // catalogue because a detector can raise the same rule to an
            // Issue: path.changed is Medium once the new hop adds more than
            // 20 ms, and then it does explain the path's rtt spike. At Info
            // it is a route that changed, which explains nothing a user
            // would fix.
            if root.kind() == Kind::Observation && child.kind() == Kind::Issue {
                continue;
            }
            // Most severe root wins, so a link failure beats a gateway failure.
            if best.map(|(_, s)| root.severity > s).unwrap_or(true) {
                best = Some((ri, root.severity));
            }
        }
        if let Some((ri, _)) = best {
            parent.insert(ci, ri);
        }
    }

    // Walk to the ultimate root, guarding against a cycle in a user ruleset.
    let ids: Vec<IssueId> = issues.iter().map(|i| i.id.clone()).collect();
    let mut assignments: Vec<(usize, usize)> = Vec::new();
    for (&child, &direct) in parent.iter() {
        let mut root = direct;
        let mut seen: HashSet<usize> = HashSet::from([child, direct]);
        while let Some(&next) = parent.get(&root) {
            if !seen.insert(next) {
                break; // cycle — stop at the deepest node reached
            }
            root = next;
        }
        if root != child {
            assignments.push((child, root));
        }
    }

    for (child, root) in assignments {
        issues[child].suppressed_by = Some(ids[root].clone());
        let child_id = ids[child].clone();
        issues[root].consequences.push(child_id);
    }

    for i in issues.iter_mut() {
        i.consequences.sort();
    }
}

/// The findings a user should be shown: open, and not a consequence of
/// another open finding. Issues and Observations alike; [`Kind`] tells them
/// apart.
pub fn primary_findings(issues: &[Issue]) -> Vec<&Issue> {
    issues
        .iter()
        .filter(|i| i.state.is_open() && i.suppressed_by.is_none())
        .collect()
}

/// Default verify condition for a rule, used when a detector doesn't supply a
/// more specific one. Every active rule must have one — enforced by a test,
/// because §4's rule is that a remediation without a testable success
/// condition is an instruction, not something netwatch can claim to have fixed.
///
/// The three σ rules close at the default `sigma_close_k`, 2σ. This cannot
/// read `Thresholds`, so their detectors put the configured value in its place.
/// `dns.slow_resolver` closes at 0.8 of the default 100 ms ceiling, its line
/// with no baseline; its detector derives the line from the baseline and the
/// configured ceiling.
pub fn default_verify(id: &str) -> Option<Verify> {
    Some(match id {
        "dns.slow_resolver" => Verify::below("dns.rtt_p50", 80.0, "ms").holding_for(60),
        "dns.failing" => Verify::below("dns.failure_rate", 1.0, "%").holding_for(120),
        "dns.truncation_retry" => Verify::below("dns.tc_rate", 1.0, "%").holding_for(120),
        "dns.hijack_suspect" => Verify::below("dns.answer_mismatch", 1.0, "%").holding_for(300),
        "gateway.unreachable" => Verify::below("gateway.loss", 1.0, "%").holding_for(60),
        "gateway.rtt_spike" => Verify::below("gateway.rtt_sigma", 2.0, "σ").holding_for(120),
        "link.down" => Verify::above("iface.carrier", 0.0, "").holding_for(30),
        "iface.errors" => Verify::below("iface.error_rate", 1.0, "/min").holding_for(300),
        "iface.saturated" => Verify::below("iface.utilisation", 90.0, "%").holding_for(60),
        "wifi.weak_signal" => Verify::above("wifi.rssi", -70.0, "dBm").holding_for(120),
        "path.changed" => Verify::below("path.hop_changes", 1.0, "").holding_for(300),
        "path.high_loss" => Verify::below("path.hop_loss", 1.0, "%").holding_for(120),
        "path.rtt_spike" => Verify::below("path.rtt_sigma", 2.0, "σ").holding_for(120),
        "tcp.bufferbloat_local" => {
            Verify::below("tcp.loaded_rtt_delta", 100.0, "ms").holding_for(60)
        }
        "tcp.bufferbloat_remote" => Verify::below("tcp.socket_rtt", 100.0, "ms").holding_for(60),
        "tcp.retrans_burst" => Verify::below("tcp.retrans_rate", 1.0, "/min").holding_for(120),
        "tcp.zero_window" => Verify::above("tcp.rwnd", 0.0, "B").holding_for(60),
        "tcp.connect_failures" => {
            Verify::below("tcp.connect_failure_rate", 1.0, "/min").holding_for(120)
        }
        "tcp.timewait_exhaustion" => Verify::below("tcp.timewait_pct", 40.0, "%").holding_for(120),
        "pmtu.blackhole" => Verify::above("pmtu.transfer_ok", 0.0, "").holding_for(30),
        "nat.symmetric" => Verify::below("nat.symmetric", 1.0, "").holding_for(300),
        "ipv6.broken" => Verify::below("ipv6.probe_loss", 1.0, "%").holding_for(30),
        "captive.portal" => Verify::above("captive.probe_204", 0.0, "").holding_for(30),
        "target.resolve_failed" => Verify::above("target.resolve_ok", 0.5, "").holding_for(120),
        "target.connect_failed" => Verify::above("target.connect_ok", 0.5, "").holding_for(120),
        "target.tls_failed" => Verify::above("target.tls_ok", 0.5, "").holding_for(120),
        "target.http_error" => Verify::above("target.http_ok", 0.5, "").holding_for(120),
        "target.slow_stage" => Verify::below("target.worst_stage_sigma", 2.0, "σ").holding_for(180),
        "egress.drift" => Verify::below("egress.new_destinations", 1.0, "").holding_for(300),
        "egress.policy_violation" => {
            Verify::below("egress.denied_flows", 1.0, "observed destinations").holding_for(300)
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnose::issue::{IssueState, Scope};

    fn issue(id: &str, rule: &str, subject: Subject) -> Issue {
        let r = lookup(rule).expect("rule in catalogue");
        Issue {
            id: id.into(),
            rule: rule.into(),
            severity: r.severity,
            title: r.title.into(),
            subject,
            since: "2026-09-03 06:48:10".into(),
            last_seen: "2026-09-03 06:51:19".into(),
            stale_since: None,
            beta: false,
            state: IssueState::Open,
            evidence: vec![],
            scope: Scope::default(),
            causes: vec![],
            remediation: vec![],
            verify: default_verify(rule).unwrap(),
            artifacts: vec![],
            consequences: vec![],
            suppressed_by: None,
            recurrence: 0,
            tests: vec![],
            verification: None,
        }
    }

    #[test]
    fn the_committed_coverage_document_matches_the_catalogue() {
        // The hand-written version claimed 25 rules when there were 30, left
        // out every `target.*` entry, and described five active rules as
        // unintegrated. Generating it is what stops that happening again.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/diagnostic-coverage.md");
        let committed = std::fs::read_to_string(path).expect("coverage doc is committed");
        // Compared line by line: a Windows checkout rewrites the committed
        // file to CRLF, and the generator emits LF, so comparing the raw
        // strings failed there over line endings rather than content.
        let normalise = |s: &str| s.replace("\r\n", "\n");
        assert_eq!(
            normalise(&committed),
            normalise(&coverage_markdown()),
            "run: cargo run -- diagnose coverage --doc"
        );
    }

    /// Triggers that still misdescribe their detector, each waiting on the
    /// plan item that changes that detector: the rule, its text as it
    /// stands, and the item with what the text gets wrong. The guard below
    /// skips them. The item rewrites the text and removes its row; a row
    /// whose text has already changed fails, so none outlives its reason.
    const PENDING_TRIGGER_TEXTS: &[(&str, &str, &str)] = &[
        (
            "dns.failing",
            "servfail/timeout rate > 5%, or the pipeline dns stage fails",
            "B15, then A14: servfail counts as a reply, and no pipeline branch exists",
        ),
        (
            "iface.errors",
            "rx/tx error, drop, overrun or fifo counters increment",
            "B19: fires on the per-minute error and drop floors, not on any increment",
        ),
        (
            "iface.saturated",
            "throughput above 90% of link rate for 30s",
            "B33: held for consecutive_n interface samples, not for 30 s",
        ),
        (
            "path.high_loss",
            "a hop loses packets and the loss propagates to later hops",
            "B33: loss before a silent tail also opens, unattributed",
        ),
        (
            "path.rtt_spike",
            "end-to-end rtt > 3σ above baseline",
            "B31: the baseline falls back to the internet probe's",
        ),
        (
            "tcp.bufferbloat_remote",
            "one socket's rtt rises with its own tx while the link-level test passes",
            "B23: opens with no link test, and after a failed one",
        ),
    ];

    /// The quantities a trigger quotes. Digits glued to a word name
    /// something (p50, v6, 5xx) and are not quantities; a unit glued to a
    /// number (100ms, 30s, 3σ) is part of one. Any other suffix panics
    /// rather than being skipped, so a new one (2x, 10min) must be listed
    /// here as a unit or a name before the guard can pass.
    fn quoted_numbers(text: &str) -> Vec<f64> {
        let chars: Vec<char> = text.chars().collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < chars.len() {
            if !chars[i].is_ascii_digit() || (i > 0 && chars[i - 1].is_alphanumeric()) {
                i += 1;
                continue;
            }
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            let digits: String = chars[start..i].iter().collect();
            let unit: String = chars[i..]
                .iter()
                .take_while(|c| c.is_alphabetic())
                .collect();
            match unit.as_str() {
                "" | "ms" | "s" | "σ" => {}
                "xx" => continue,
                _ => panic!("{text:?}: is {digits}{unit} a quantity or a name? list {unit:?} in quoted_numbers"),
            }
            let value: f64 = digits
                .trim_end_matches('.')
                .parse()
                .unwrap_or_else(|_| panic!("{text:?}: {digits:?} is not a number"));
            let negative = start > 0
                && matches!(chars[start - 1], '-' | '−')
                && (start < 2 || !chars[start - 2].is_alphanumeric());
            out.push(if negative { -value } else { value });
        }
        out
    }

    #[test]
    fn quoted_numbers_reads_quantities_not_names() {
        assert_eq!(
            quoted_numbers("p50 > 3σ for 3 samples, or > 100ms"),
            [3.0, 3.0, 100.0]
        );
        assert_eq!(
            quoted_numbers("at or below −70 dBm, or 20% for 30s."),
            [-70.0, 20.0, 30.0]
        );
        assert!(quoted_numbers("a v6 route while v4 works answers 5xx").is_empty());
    }

    #[test]
    #[should_panic(expected = "\"p50 ≥ 2x mean\": is 2x a quantity or a name?")]
    fn quoted_numbers_refuses_a_suffix_it_does_not_know() {
        // Skipping it would let "2x" or "10min" leave the guard unchecked.
        quoted_numbers("p50 ≥ 2x mean");
    }

    #[test]
    #[should_panic(expected = "\"answers 1.1.1.1\": \"1.1.1.1\" is not a number")]
    fn quoted_numbers_names_the_text_it_cannot_read() {
        quoted_numbers("answers 1.1.1.1");
    }

    /// The drift test above only proves the document matches the catalogue.
    /// This one ties the numbers a trigger quotes to the values the detector
    /// judges with, so a retuned default cannot leave the text behind.
    #[test]
    fn catalogue_triggers_quote_the_default_thresholds() {
        use crate::diagnose::detectors::Thresholds;

        // The `Thresholds` fields each trigger quotes. A rule listed in
        // neither table quotes no number. Every field needs its own quote,
        // so two fields that share a value (sigma_k and consecutive_n are
        // both 3) need the number twice.
        const QUOTED_THRESHOLDS: &[(&str, &[&str])] = &[
            ("dns.truncation_retry", &["dns_tc_pct"]),
            (
                "dns.slow_resolver",
                &[
                    "sigma_k",
                    "dns_delta_floor_ms",
                    "dns_delta_multiple",
                    "dns_ceiling_ms",
                    "consecutive_n",
                ],
            ),
            (
                "gateway.rtt_spike",
                &["sigma_k", "gateway_delta_floor_ms", "consecutive_n"],
            ),
            ("wifi.weak_signal", &["wifi_rssi_dbm", "wifi_retry_pct"]),
            ("tcp.bufferbloat_local", &["loaded_rtt_delta_ms"]),
            ("target.resolve_failed", &["consecutive_n"]),
            ("target.connect_failed", &["consecutive_n"]),
            ("target.tls_failed", &["consecutive_n"]),
            ("target.http_error", &["consecutive_n"]),
            ("target.slow_stage", &["sigma_k", "consecutive_n"]),
        ];
        // Numbers `Thresholds` does not carry: three literals in the
        // detectors, pinned by their own firing tests, and a protocol
        // constant.
        const QUOTED_LITERALS: &[(&str, f64)] = &[
            // retrans_burst_fires_at_five_a_minute
            ("tcp.retrans_burst", 5.0),
            // kernel::tests::matched_positive_negative_and_unknown
            ("tcp.connect_failures", 5.0),
            ("tcp.timewait_exhaustion", 60.0),
            // The status the portal probe expects.
            ("captive.portal", 204.0),
        ];

        let defaults = serde_json::to_value(Thresholds::default()).expect("thresholds serialise");
        let default_of = |field: &str| {
            defaults
                .get(field)
                .and_then(|v| v.as_f64())
                .unwrap_or_else(|| panic!("Thresholds has no numeric field {field}"))
        };
        let sorted = |mut v: Vec<f64>| {
            v.sort_by(f64::total_cmp);
            v
        };

        for (id, text, why) in PENDING_TRIGGER_TEXTS {
            let rule = lookup(id).unwrap_or_else(|| panic!("{id} is not in the catalogue"));
            assert_eq!(
                rule.trigger, *text,
                "{id}'s trigger changed; if its item has landed ({why}), remove its row"
            );
        }
        for (id, _) in QUOTED_THRESHOLDS {
            assert!(lookup(id).is_some(), "{id} is not in the catalogue");
        }
        for (id, _) in QUOTED_LITERALS {
            assert!(lookup(id).is_some(), "{id} is not in the catalogue");
        }

        for rule in CATALOGUE {
            if PENDING_TRIGGER_TEXTS.iter().any(|(id, ..)| *id == rule.id) {
                continue;
            }
            let expected = QUOTED_THRESHOLDS
                .iter()
                .filter(|(id, _)| *id == rule.id)
                .flat_map(|(_, fields)| fields.iter().map(|f| default_of(f)))
                .chain(
                    QUOTED_LITERALS
                        .iter()
                        .filter(|(id, _)| *id == rule.id)
                        .map(|(_, value)| *value),
                )
                .collect();
            assert_eq!(
                sorted(quoted_numbers(rule.trigger)),
                sorted(expected),
                "{}: \"{}\" does not quote the defaults its detector judges with",
                rule.id,
                rule.trigger
            );
        }
    }

    #[test]
    fn a_contracted_rule_states_all_four_parts() {
        for rule in CATALOGUE.iter().filter(|r| r.contracted()) {
            assert!(!rule.evidence.is_empty(), "{}", rule.id);
            assert!(!rule.lookalikes.is_empty(), "{}", rule.id);
            assert!(!rule.recovery.is_empty(), "{}", rule.id);
            assert!(!rule.platforms.is_empty(), "{}", rule.id);
        }
        // Tier one: the rules implicated by the review's findings. The
        // release gate is these eight; the remaining rules follow.
        for id in [
            "gateway.unreachable",
            "dns.hijack_suspect",
            "path.high_loss",
            "tcp.bufferbloat_remote",
            "target.resolve_failed",
            "target.connect_failed",
            "target.tls_failed",
            "target.http_error",
        ] {
            assert!(
                lookup(id).expect("rule exists").contracted(),
                "{id} is tier one and must carry a contract"
            );
        }
    }

    #[test]
    fn a_gateway_failure_does_not_hide_a_target_reached_over_a_tunnel() {
        // `gateway.unreachable` is filed against the host and suppresses
        // every target rule. Subject overlap alone therefore demoted a
        // target reached over wg0 — which never touches that gateway — to a
        // consequence of it, hiding a second, unrelated fault.
        let mut gateway = issue("1", "gateway.unreachable", Subject::Host);
        gateway.scope.via_iface = Some("eth0".into());

        let mut tunnelled = issue(
            "2",
            "target.connect_failed",
            Subject::Target {
                name: "corp-api".into(),
            },
        );
        tunnelled.scope.via_iface = Some("wg0".into());

        let mut same_link = issue(
            "3",
            "target.connect_failed",
            Subject::Target {
                name: "public-api".into(),
            },
        );
        same_link.scope.via_iface = Some("eth0".into());

        let mut issues = vec![gateway, tunnelled, same_link];
        apply_suppression(&mut issues);
        assert_eq!(issues[1].suppressed_by, None, "different interface");
        assert_eq!(issues[2].suppressed_by.as_deref(), Some("1"));
        assert_eq!(issues[0].consequences, vec!["3".to_string()]);
    }

    #[test]
    fn a_failing_resolver_only_explains_targets_that_used_it() {
        let resolver = issue(
            "1",
            "dns.failing",
            Subject::Resolver {
                addr: "192.168.8.1".into(),
            },
        );
        let mut through_it = issue(
            "2",
            "target.resolve_failed",
            Subject::Target { name: "api".into() },
        );
        through_it.scope.via_resolver = Some("192.168.8.1".into());
        let mut elsewhere = issue(
            "3",
            "target.resolve_failed",
            Subject::Target {
                name: "corp".into(),
            },
        );
        elsewhere.scope.via_resolver = Some("10.0.0.53".into());

        let mut issues = vec![resolver, through_it, elsewhere];
        apply_suppression(&mut issues);
        assert_eq!(issues[1].suppressed_by.as_deref(), Some("1"));
        assert_eq!(
            issues[2].suppressed_by, None,
            "this target resolved through a different resolver"
        );
    }

    #[test]
    fn a_targets_old_revision_does_not_explain_its_new_one() {
        // Edited, a target's old finding stays tracked until it expires.
        // It is about an entry that no longer exists, so it cannot hide
        // what the entry that replaced it finds.
        let target = || Subject::Target { name: "api".into() };
        let mut old = issue("1", "target.connect_failed", target());
        old.scope.configuration = Some("target-config:aaaa".into());
        let mut edited = issue("2", "target.slow_stage", target());
        edited.scope.configuration = Some("target-config:bbbb".into());
        let mut same = issue("3", "target.http_error", target());
        same.scope.configuration = Some("target-config:aaaa".into());
        let unrevised = issue("4", "target.slow_stage", target());

        let mut issues = vec![old, edited, same, unrevised];
        apply_suppression(&mut issues);
        assert_eq!(issues[1].suppressed_by, None, "another revision");
        assert_eq!(issues[2].suppressed_by.as_deref(), Some("1"));
        assert_eq!(issues[3].suppressed_by.as_deref(), Some("1"), "no revision");
    }

    #[test]
    fn catalogue_ids_are_unique() {
        let mut seen = HashSet::new();
        for r in CATALOGUE {
            assert!(seen.insert(r.id), "duplicate rule id {}", r.id);
        }
    }

    #[test]
    fn suppression_edges_reference_real_rules() {
        for r in CATALOGUE {
            for s in r.suppresses {
                assert!(lookup(s).is_some(), "{} suppresses unknown rule {s}", r.id);
            }
            assert!(!r.suppresses.contains(&r.id), "{} suppresses itself", r.id);
        }
    }

    #[test]
    fn every_rule_has_a_verify_condition() {
        for r in CATALOGUE {
            assert!(
                default_verify(r.id).is_some(),
                "{} has no verify condition — it could never be closed",
                r.id
            );
        }
    }

    /// Every rule now has an input. The label must say so rather than keep
    /// a split that no longer exists; if a rule is ever added as `Planned`
    /// again, the label goes back to stating the count and this changes.
    #[test]
    fn catalogue_label_reports_the_active_split_honestly() {
        let label = catalogue_label();
        assert!(
            label.starts_with(&format!("{} rules", CATALOGUE.len())),
            "{label}"
        );
        assert_eq!(active_count(), 30, "{label}");
        assert!(!label.contains("planned"), "{label}");
    }

    #[test]
    fn gateway_failure_swallows_the_dns_symptom() {
        let mut issues = vec![
            issue(
                "A",
                "dns.slow_resolver",
                Subject::Resolver {
                    addr: "169.254.1.1".into(),
                },
            ),
            issue("B", "gateway.unreachable", Subject::Host),
        ];
        apply_suppression(&mut issues);

        assert_eq!(issues[0].suppressed_by.as_deref(), Some("B"));
        assert_eq!(issues[1].consequences, vec!["A".to_string()]);
        let primary = primary_findings(&issues);
        assert_eq!(primary.len(), 1);
        assert_eq!(primary[0].id, "B");
    }

    #[test]
    fn suppression_is_transitive_to_the_deepest_root() {
        let mut issues = vec![
            issue(
                "A",
                "dns.failing",
                Subject::Resolver {
                    addr: "10.0.0.1".into(),
                },
            ),
            issue("B", "gateway.unreachable", Subject::Host),
            issue(
                "C",
                "link.down",
                Subject::Iface {
                    name: "eth0".into(),
                },
            ),
        ];
        apply_suppression(&mut issues);

        assert_eq!(
            issues[0].suppressed_by.as_deref(),
            Some("C"),
            "dns → link.down"
        );
        assert_eq!(issues[1].suppressed_by.as_deref(), Some("C"));
        assert_eq!(
            issues[2].consequences,
            vec!["A".to_string(), "B".to_string()]
        );
        assert_eq!(primary_findings(&issues).len(), 1);
    }

    #[test]
    fn suppression_does_not_cross_unrelated_interfaces() {
        let mut issues = vec![
            issue(
                "A",
                "iface.errors",
                Subject::Iface {
                    name: "eth0".into(),
                },
            ),
            issue(
                "B",
                "link.down",
                Subject::Iface {
                    name: "wlan0".into(),
                },
            ),
        ];
        apply_suppression(&mut issues);
        // link.down doesn't suppress iface.errors anyway, but the scope guard
        // is what keeps a wlan0 fault from explaining an eth0 counter.
        assert!(issues[0].suppressed_by.is_none());
    }

    #[test]
    fn a_closed_root_releases_its_consequences() {
        let mut issues = vec![
            issue(
                "A",
                "dns.slow_resolver",
                Subject::Resolver {
                    addr: "1.1.1.1".into(),
                },
            ),
            issue("B", "gateway.unreachable", Subject::Host),
        ];
        apply_suppression(&mut issues);
        assert!(issues[0].suppressed_by.is_some());

        issues[1].state = IssueState::Resolved {
            at: "2026-09-03 07:00:00".into(),
        };
        apply_suppression(&mut issues);
        assert!(
            issues[0].suppressed_by.is_none(),
            "dns must resurface as a finding once the gateway recovers"
        );
        assert_eq!(primary_findings(&issues).len(), 1);
    }

    #[test]
    fn independent_issues_are_both_primary() {
        let mut issues = vec![
            issue(
                "A",
                "dns.slow_resolver",
                Subject::Resolver {
                    addr: "169.254.1.1".into(),
                },
            ),
            issue(
                "B",
                "tcp.bufferbloat_remote",
                Subject::Socket {
                    local: "10.88.0.2:52344".into(),
                    remote: "10.88.0.3:9000".into(),
                },
            ),
            issue(
                "C",
                "path.changed",
                Subject::Path {
                    target: "1.1.1.1".into(),
                },
            ),
        ];
        apply_suppression(&mut issues);
        assert_eq!(primary_findings(&issues).len(), 3);
    }

    /// An Info `path.changed` used to hide a Medium `path.rtt_spike` on the
    /// same path: a note that the route moved took the fault off the screen.
    #[test]
    fn an_observation_never_hides_an_issue() {
        let path = || Subject::Path {
            target: "1.1.1.1".into(),
        };
        let mut issues = vec![
            issue("A", "path.changed", path()),
            issue("B", "path.rtt_spike", path()),
        ];
        assert_eq!(issues[0].kind(), Kind::Observation);
        apply_suppression(&mut issues);
        assert!(issues[1].suppressed_by.is_none());
        assert!(issues[0].consequences.is_empty());
        let primary: Vec<&str> = primary_findings(&issues)
            .iter()
            .map(|i| i.id.as_str())
            .collect();
        assert_eq!(primary, ["A", "B"]);

        // Once the new hop adds enough latency to make the route change an
        // Issue, it explains the spike again.
        issues[0].severity = Severity::Medium;
        apply_suppression(&mut issues);
        assert_eq!(issues[1].suppressed_by.as_deref(), Some("A"));

        // An Issue still hides an Observation it explains.
        let flow = || Subject::Egress {
            process: "curl".into(),
            destination: "203.0.113.7".into(),
            port: 443,
        };
        let mut issues = vec![
            issue("C", "egress.drift", flow()),
            issue("D", "egress.policy_violation", flow()),
        ];
        apply_suppression(&mut issues);
        assert_eq!(issues[0].suppressed_by.as_deref(), Some("D"));
    }

    #[test]
    fn the_six_info_rules_are_observations() {
        let observations: Vec<&str> = CATALOGUE
            .iter()
            .filter(|r| r.severity.kind() == Kind::Observation)
            .map(|r| r.id)
            .collect();
        assert_eq!(
            observations,
            [
                "dns.truncation_retry",
                "path.changed",
                "tcp.zero_window",
                "tcp.timewait_exhaustion",
                "nat.symmetric",
                "egress.drift",
            ]
        );
        for id in observations {
            let found = issue("A", id, Subject::Host);
            assert_eq!(found.kind(), Kind::Observation, "{id}");
        }
    }
}
