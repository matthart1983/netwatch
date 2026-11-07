# Netwatch gap assessment and roadmap

> Design/review record: this document can include proposals and revision-specific results.
> For current user behavior, use the [documentation index](../index.md).

Netwatch’s strongest opportunity is to become the terminal tool that turns a network symptom into an attributable, explainable incident, then produces evidence another engineer can use. The current product already contains much of that workflow. Its next investment should concentrate on measurement credibility, safe recovery, and incident handoff before adding more screens or protocol breadth.

The immediate priorities are worker sandbox coverage, remediation correctness, and honest diagnostic availability. The next product milestone should combine guided diagnosis, a shared incident timeline, and reproducible reports. Egress change review is the strongest adjacent experiment; fleet incident collaboration is a conditional commercial extension.

## Scope and confidence

The assessment covers the local Netwatch TUI repository at commit `9b4597e`, version **0.30.4**, inspected on 10 September 2026. It considers the supplied local design handover for 0.29.2 as historical context, current source and documentation as implementation evidence, and public primary sources as competitive context. The recommended audience is developers, Linux operators, and homelab users, with small engineering teams as a possible commercial expansion. Staffing, adoption, retention, and revenue data were unavailable; proposed dates and commercial demand are planning hypotheses.[^1][^2]

Library validation completed with **958 passing tests, zero failures, and three ignored tests** using `cargo test --offline --lib --quiet`. Three local-socket tests initially failed under the execution sandbox and passed when rerun outside it. This validates the existing Linux library suite, not privileged capture behaviour, macOS/Windows runtime parity, performance under load, or production security. Findings below distinguish directly observed code paths from risks requiring reproduction.

The cloud service, separate agent, SDK, and dashboard were not audited. Public cloud statements are treated as vendor claims. Public issue-page retrieval did not expose a usable complete issue inventory; no demand ranking or issue-frequency estimate is inferred from it. Older web copies of Netwatch’s README lag the local checkout, so local code governs capability conclusions.

## Current strengths and strategic focus

Netwatch has a substantial base: ten terminal tabs, Lite and Dense views, packet inspection, process attribution, diagnostic baselines and issue lifecycles, TLS/QUIC work, egress profiling, incident capture, a headless mode, remote publishing, and aggregate Prometheus export. The roadmap should build on these assets. In particular, “add a daemon,” “add alerts,” “add egress baselines,” and “add incident export” would duplicate existing work.[^1][^3]

The strongest design choice is the deterministic Diagnose engine. Findings have evidence, candidate causes, suppression, remediation steps, and verification conditions. The older handover explicitly proposed this structure, and the current repository implements it. That makes a new design overhaul less valuable than closing the distance between a rule’s advertised availability, its actual measurements, and its incident report.[^2][^4]

Three user jobs should define the product:

| User job | Existing foundation | Next useful outcome |
|---|---|---|
| “Why is this application slow?” | Process attribution, socket metrics, health probes, Diagnose | Explain the likely failing layer, show missing checks, and link the finding to relevant flows |
| “What changed when the problem started?” | Timeline, baselines, topology, egress history | Align route, resolver, interface, application, and policy changes on one incident timeline |
| “Can someone else verify this?” | Flight recorder, PCAP, Markdown/JSON reports | Export a privacy-conscious, versioned evidence package and reopen it offline |

Recommended positioning: **“Diagnose network problems from the terminal, with process-level evidence and a shareable incident report.”** This is a product direction, not a claim that competitors cannot do parts of it. The opportunity lies in reducing the work between observation and explanation.

## Competitive landscape

The relevant competitive set spans several jobs rather than one category. Official product documentation supports the capabilities below; the implications are analytical judgments. No performance or price comparisons are asserted without comparable measurements.

| Tool | Documented strength | Roadmap implication for Netwatch |
|---|---|---|
| bandwhich | Terminal bandwidth attribution using packet observation and OS process information | Process names and throughput are necessary foundations; they are insufficient differentiation alone.[^5] |
| Trippy | Ping/traceroute analysis; TCP/UDP/ICMP, IPv4/IPv6, ECMP strategies, MPLS information, ASN lookup | Provide useful path-change evidence and export to deeper tracing workflows; avoid rebuilding every tracing feature.[^6] |
| Sniffnet | Cross-platform graphical traffic monitoring, program identification, PCAP import/export, notifications, filtering | Ease of installation and clear first-run output matter. Offline review is an established user expectation.[^7] |
| Wireshark/TShark | Detailed captured-packet analysis and extensive filtering; separate privileged capture through dumpcap | Make PCAP handoff excellent. Use privilege separation as an architectural reference, and expand decoders when a supported incident needs them.[^8][^9] |
| Cilium Hubble | Cluster flow inspection, service maps, flow export, TLS configuration | Container identity is useful; entering full Kubernetes network observability creates a much larger scope.[^10] |
| OpenSnitch | Linux interactive application firewall | Preserve Netwatch’s observe-and-review use case. Enforcement requires a separate product and safety decision.[^11] |
| NetWatch Cloud | Publicly describes an agent/ingest/dashboard fleet workflow, JSON export, and free access while growing | Explore shared incidents and historical evidence within the existing ecosystem. Do not assume public fleet claims establish code parity or commercial demand.[^12] |

The competitive evidence supports focus on incident workflow, but does not establish market size or willingness to pay. A terminal-first product can serve operators well without competing feature-for-feature with packet laboratories, application firewalls, and cluster platforms simultaneously.

## Prioritised gaps

### 1. Worker sandbox coverage needs immediate verification and correction

**Observed:** `App::new()` starts packet capture; `PacketCollector::start_capture()` spawns the worker. The TUI and daemon apply Landlock after constructing the application. The inspected ruleset calls `restrict_self()` without requesting thread synchronisation. The kernel documents that, without synchronisation, restrictions apply to the calling thread and its future children, not existing sibling threads. Thus the startup worker is outside the confinement established later by this call.[^13][^14]

This is a high-confidence architectural finding, not a demonstrated exploit. It matters because capture workers process untrusted traffic, and the README makes a broad filesystem-isolation claim. Existing-thread coverage cannot be inferred from a successful sandbox report on the application thread. Capture restart may also create workers under a different inherited restriction set.

**Recommendation:** establish an explicit worker startup barrier: acquire necessary resources, enforce the intended restrictions inside each worker or before its creation, then begin parsing. Evaluate a small privileged capture helper as the longer-term boundary. Modern thread synchronisation may help on supporting kernels, but older supported kernels still need a working design. Wireshark’s dumpcap separation offers a relevant precedent.[^9]

**Release gate:** integration checks must exercise denied file access from the actual capture/parser worker, keylog worker, and relevant runtime workers, including initial launch and restart. Use temporary test files representing disallowed resources; do not use real secrets. Report the effective protection by component. Review capability retention separately: best-effort mode deliberately retains `CAP_NET_RAW`, and the Linux backend does not impose network restrictions.[^13]

### 2. Remediation guarantees exceed the implementation

**Observed:** the host implementation uses `std::fs::write` for the journal and edited files. Applying a change writes pending intent, writes the backup, writes the target, then flushes the applied journal state. A failure in the final flush returns an error after the target changed; the UI then reports “host unchanged.” Journal loading treats unreadable or invalid JSON as an empty journal. The daemon entry point does not invoke the reconciliation call used by the TUI.[^15]

These are concrete failure paths. They do not demonstrate that a resolver change has been lost in normal operation. They do show that the current success/error vocabulary and recovery promise need tightening. Ordering writes alone is not proof of power-loss durability, and a partially completed operation needs a distinct outcome.

The live action dispatcher implements resolver-file editing; other actions return an unsupported outcome. The cross-Unix process-liveness implementation checks `/proc/<pid>`, which does not provide a portable macOS liveness check. PID-only ownership also merits review for reuse. Resolver ownership and symlinks need explicit handling before treating direct file editing as generally applicable.[^15]

**Recommendation:** prioritise trustworthy reporting and recovery over adding more automatic fixes. Introduce explicit unchanged/applied/partially-applied/recovery-required outcomes; durable journal replacement with appropriate synchronisation; corruption detection; operation ownership and locking; and reconciliation shared by every entry point. Use resolver-manager-specific adapters where supported and instructions elsewhere. Avoid naïvely replacing manager-owned symlinks.

**Release gate:** inject failures at every persistence boundary; test truncated journals, concurrent instances, PID reuse handling, external resolver edits, and restart through both TUI and daemon. Every state must preserve a recoverable backup or provide a precise recovery instruction. The interface must never claim the host is unchanged when an edit may have landed.

### 3. Rule availability must reflect live evidence

**Observed:** the README says all 25 rules are active. The live observation constructor always sets `idle_rtt_ms` and `loaded_rtt_ms` to `None`. The local-bufferbloat detector returns without a finding unless both are present. Fixtures populate these values, so detector tests can pass without proving live availability.[^4][^16]

**Recommendation:** generate availability from actual runtime prerequisites. Distinguish “available,” “learning,” “missing permission,” “unsupported,” and “measurement not run.” Catalogue membership is not the same as live evaluation capability. Show these states in Diagnose and reports. Add an opt-in bounded loaded-latency test if users need local-bufferbloat diagnosis; document its traffic and duration before it runs.

**Release gate:** each advertised rule maps to a real collector, platform/privilege requirements, an end-to-end triggering scenario, and a recovery scenario. Missing input must produce “unknown/not measured,” never an implication of good health. Use evidence-support scores with their checks visible; do not present a weighted score as a calibrated probability.

### 4. Attribution needs measurable coverage across deployment conditions

The 0.29.2 handover reported severe unknown-process attribution. The current code includes a pre-sandbox process snapshot and eBPF fallback handling, so that historical failure must not be asserted as an unresolved current reproduction. However, attribution remains foundational to Processes, Connections, Egress, and any diagnosis naming an application.[^2][^17]

**Recommendation:** expose attribution method, age, known/unknown flow share, and reason for degradation. Test short-lived TCP/UDP over IPv4/IPv6, existing connections at startup, restart, missing eBPF capability, PID churn, and network namespaces. Start container work with cgroup/container identity on Linux; add orchestration metadata only if pilot users need it. A search of the inspected attribution and policy paths did not establish container-aware identity; this is a bounded gap assessment, not a claim about the separate SDK or agent.

Windows kernel TCP metrics currently return no data in the inspected collector, and macOS/Windows sandbox backends report unavailable. Platform support should therefore be presented as a capability matrix rather than equivalent depth. A narrow, dependable Windows experience is preferable to unsupported fields that resemble missing traffic.[^17]

### 5. Incident capture needs a safe sharing and replay contract

The flight recorder already has bounded retention, a manifest, snapshots, a Markdown summary, and PCAP export. Diagnose separately exports Markdown and JSON. The inspected incident export writes captured packets and descriptive snapshots directly; it does not expose a redaction policy in that path. This is an improvement to existing export, not a proposal to invent incident bundles.[^18]

**Recommendation:** define a shared incident identifier, event timestamps, schema version, collector provenance, capture-loss/coverage information, and a manifest linking diagnosis to packet evidence. Offer a summary-only sharing profile by default for handoff, with explicit selection of sensitive raw evidence. Preserve the original capture separately when fidelity matters. Payload redaction is more complex than removing visible hostnames, so do not label a PCAP safe after superficial field masking.

Add reopening of an incident package before general-purpose PCAP replay. Diagnosis often depends on kernel/process/probe observations that a PCAP cannot reconstruct. A reopened package should reproduce saved findings; recomputation under a newer engine should be a separate, version-labelled operation. General PCAP import can then provide the subset of diagnosis supported by packets alone.

**Release gate:** exported evidence is understandable on another machine; redacted output contains no seeded sensitive test values; file permissions are deliberate; truncation is visible; the package opens without network access; and schema compatibility is tested.

### 6. Egress can become a development change-review workflow

Existing policy supports process rules, hostname/IP/ASN destinations, ports, and strict handling of undeclared processes. Destination matching accepts a hostname, ASN, or IP match after the port condition. Broad ASN allowance can therefore authorise more than the named service alone. The product already exposes matching granularity; retain this honesty.[^19]

The opportunity is to answer “what new destinations did this build or task introduce?” This can help developers reviewing dependency changes, installation scripts, or automated workloads. It remains a hypothesis until used in real reviews. A process name alone may conflate distinct executables or multiple tasks sharing a runtime, so stronger executable/workload identity is a prerequisite.

**Recommendation:** add bounded sessions, before/after policy diff, destination evidence, approved exceptions with expiry, and a machine-readable result for CI. Separate “no observed change” from “complete observation”; short runs and encrypted naming can limit coverage. Retain observation semantics. Do not claim this prevents exfiltration or proves a program safe.

**Release gate:** five pilot projects use it in actual change reviews, can explain flagged destinations, and can distinguish expected updates from actionable drift. Stronger identity and stable exports precede any fail-on-drift CI mode.

### 7. Release assurance should cover behaviour beyond library correctness

The repository already has three-OS CI with formatting, Clippy, release builds, and tests. That is a meaningful strength. The inspected workflow inventory does not include dedicated fuzzing, sustained capture benchmarks, or dependency-audit jobs. Large coordinating modules—about 5,000 lines in `app.rs` and 3,900 in the packet collector—also raise the cost of changing startup, collection, and UI behaviour together.[^20]

**Recommendation:** add representative malformed-packet fuzzing, bounded-memory/soak checks, and live capture/attribution scenarios on a small supported platform matrix. Publish CPU, RSS, packet loss, and UI responsiveness for named hardware and traffic profiles. Capture statistics already exist; surface their effect on diagnostic confidence instead of adding another competing counter.[^18][^20]

Extract runtime lifecycle and incident assembly from UI orchestration as enabling work for headless diagnosis and replay. Preserve existing collector logic initially. A rewrite would consume the same capacity needed to validate real behaviour.

### 8. Documentation and onboarding need one capability model

The current README places optional AI commentary in Diagnose, while `docs/INSIGHTS.md` still instructs users to open an Insights tab numbered 8. The rule-coverage discrepancy is another example of documentation describing a broader experience than the live path guarantees.[^1][^16][^21]

**Recommendation:** create a capability summary at first run and in a proposed `doctor` command: selected interface, capture status, attribution backend, probe availability, effective sandbox, and relevant external lookups. Derive help and capability documentation from shared definitions where practical. Keep Dense and Lite; improve task navigation and error explanations before another broad visual redesign.

AI should remain optional commentary, visibly separate from measured evidence and authorised actions. Network-derived text is untrusted input; any future AI expansion needs tests for misleading instructions in observed data and explicit disclosure of what is sent to the configured service. No automatic execution based on model narrative is recommended.

## Roadmap and delivery gates

The schedule assumes approximately one experienced full-time maintainer, with access to platform testers and intermittent security review. Estimates include meaningful validation but are not commitments. Phases are sequential; later scope should move if the trust work reveals broader changes. Priority is ordinal: **P0** protects existing promises, **P1** completes the primary workflow, and **P2** tests expansion.

| Phase | Indicative window | Deliverables | Exit gate |
|---|---|---|---|
| A: Trust and recovery | Weeks 1–4 | Worker confinement; truthful remediation outcomes; shared startup reconciliation; rule availability; capability documentation | Worker-level isolation checks pass; persistence-failure cases report truthfully; every rule declares real prerequisites |
| B: Complete diagnosis | Weeks 5–9 | Guided diagnostic session; observation provenance; attribution coverage; bounded headless diagnosis; targeted active tests | Representative failures produce supported explanations, known missing checks, and verified recovery |
| C: Evidence handoff | Weeks 10–13 | Shared incident schema; correlated timeline; sharing profiles; offline package reopening; focused runtime extraction | A second engineer can understand and reopen an incident without the original host |
| D: Egress pilot | Weeks 14–18 | Workload identity; bounded sessions; policy diff; stable JSON; reviewed exceptions | Five real projects complete change reviews and justify continued use |
| E: Fleet discovery | After phase C; build after demand gate | Customer interviews and prototype of shared incidents, history, ownership, and annotations | Repeated multi-host incidents plus at least three explicit paid-pilot commitments before substantial service expansion |

### First backlog

Effort bands are approximate engineer effort: S = 1–3 days, M = 4–8 days, L = 2–4 weeks. They overlap with phase work and should not be added as a promised delivery total.

| ID | Priority | Work | Effort | Dependency / acceptance |
|---|---|---|---|---|
| NW-R01 | P0 | Map worker startup and enforce confinement at the real boundary | L | Isolated worker tests cover launch and restart; effective status is accurate |
| NW-R02 | P0 | Correct partial-apply and journal-corruption outcomes | M | No false “unchanged”; recoverable failure state exposed |
| NW-R03 | P0 | Durable journal, concurrent ownership, common reconciliation | L | R02; injected failures and TUI/daemon restarts behave consistently |
| NW-R04 | P0 | Runtime diagnostic availability and README correction | S–M | All 25 catalogue entries trace to prerequisites; dormant bufferbloat shown correctly |
| NW-R05 | P1 | Capability/doctor output and platform matrix | M | R01/R04; unsupported states distinguishable from healthy readings |
| NW-R06 | P1 | Attribution coverage and lifecycle integration corpus | L | R01; short-lived and startup flows measured against known generators |
| NW-R07 | P1 | Incident schema and common report assembly | M | Versioning, provenance, capture completeness, deterministic saved output |
| NW-R08 | P1 | Bounded headless diagnostic session and JSON output | M | R04/R07; finite duration, documented exit statuses, missing-input semantics |
| NW-R09 | P1 | Sharing profiles and offline package reopening | L | R07; sensitive-value fixtures and cross-machine round trip |
| NW-R10 | P1 | Guided symptom flow and correlated incident timeline | L | R07; measurable reduction in time to supported explanation |
| NW-R11 | P1 | Parser fuzzing and published performance profiles | M–L | Resource budgets, malformed traffic, and capture loss visible |
| NW-R12 | P2 | Workload egress diff pilot | L | R06/R08; real review usage, explicit unknown coverage, useful exceptions |

Proposed CLI concepts such as `netwatch doctor`, `netwatch diagnose --duration 60s --json`, and `netwatch incident open <bundle>` are **future interface sketches**, not existing commands. Settle exact syntax after the shared runtime and schema are designed.

## Validation programme and success measures

Build a compact labelled scenario corpus around slow/unreachable DNS, gateway failure, external service refusal, packet loss, path changes, IPv6 failure, missing privileges, and short-lived connections. Add local bufferbloat only with a real live measurement path. Pair each fault with recovery and a benign lookalike. Examples include ICMP silence with successful application connectivity and a changed CDN destination that is expected.

Use independent observations to establish ground truth. A fixture proving the engine emits the expected rule is useful, but an integration scenario must establish that the real collector supplies the needed measurement. Distinguish probable cause from proven cause; on incomplete evidence, success may be an explicit next check.

Proposed initial targets are management gates, not current measured results:

| Measure | Initial target | Interpretation |
|---|---|---|
| Capability disclosure | 100% of supported collector states represented | No silent substitution of missing data with health |
| Diagnostic corpus | At least 20 fault/recovery/benign scenarios | Coverage quality matters more than raw count |
| Supported explanation | At least 90% of labelled supported scenarios | Include uncertain/unsupported cases separately; do not hide them in denominator |
| Attribution | At least 95% of eligible flows in controlled supported scenarios | Publish by backend, protocol, lifetime, and privilege; report byte coverage separately |
| Handoff usability | Four of five pilot engineers understand a seeded incident within five minutes | A small usability gate, not population-level evidence |
| Resource behaviour | Establish baseline, then investigate regressions above 10% on fixed profiles | Declare machine, rates, duration, capture settings, and noise |
| Recovery safety | All injected persistence failures give accurate, recoverable states | A release gate, not a probability claim |

Start with eight to twelve interviews across developers, Linux operators, and homelab users. Ask for the last actual network incident, the tools used, time spent gathering evidence, and what had to be shared. Have participants perform a task with Netwatch, not rank a feature wishlist. Record whether they return for a second incident before treating first-run enthusiasm as retention.

## Commercial opportunities and explicit deferrals

The closest commercial extension is shared incident history: teams pay for retaining evidence, comparing hosts, coordinating ownership, and producing reports across incidents. This follows naturally from a capable free local tool. It should be validated against actual repeated incidents before adding substantial backend scope. Cloud pricing and unit economics require separate evidence: storage per incident, ingest rate, retention, support burden, and willingness to pay.

The public cloud site currently describes free access while growing and advertises fleet monitoring. Those statements do not validate sustainable pricing or production scale. Avoid copying its comparison table into sales material as independent benchmarking. The local TUI remote publisher samples snapshots every 15 seconds; the cloud page describes one-second resolution. These may be different product paths, so document boundaries rather than asserting a contradiction across repositories.[^3][^12]

Defer full Kubernetes observability, automatic firewall enforcement, an autonomous AI remediation agent, broad new protocol coverage, and decorative terminal graphics. Container identity, useful PCAP handoff, and explainable egress review can deliver value without those commitments. Revisit protocol depth when repeated incidents cannot be explained with existing evidence; revisit fleet expansion when users need cross-host correlation that local reports cannot provide.

The near-term investment decision is to fund phases A–C as a coherent product improvement, run the egress pilot after identity and exports are dependable, and make fleet expansion contingent on demonstrated demand. This preserves Netwatch’s existing strengths while making its central promise reviewable and trustworthy.

## Sources

Local citations refer to the inspected checkout, version 0.30.4 at `9b4597e`; public code links use that commit for reproducibility. Web sources were accessed 10 September 2026. Undated documentation is identified as such; vendor capabilities are not independently benchmarked.

[^1]: Netwatch, [README](https://github.com/matthart1983/netwatch/blob/9b4597e/README.md) and [Cargo manifest](https://github.com/matthart1983/netwatch/blob/9b4597e/Cargo.toml). Local checkout, 0.30.4. Product scope, version, tabs, claims.
[^2]: Netwatch next handover, `HANDOVER.md` and `review/REVIEW.md`, 3 September 2026, version 0.29.2. Local files in `/home/matt/Downloads/netwatch-next-handover/netwatch-next/`; no public URL supplied. Historical design and observations, not current bug reproduction.
[^3]: Netwatch, [observability export](https://github.com/matthart1983/netwatch/blob/9b4597e/docs/observability-export.md), [remote publisher](https://github.com/matthart1983/netwatch/blob/9b4597e/src/remote/mod.rs), and [main entry point](https://github.com/matthart1983/netwatch/blob/9b4597e/src/main.rs). Local checkout. Existing daemon, metrics, queue and publication cadence.
[^4]: Netwatch, [diagnostic engine](https://github.com/matthart1983/netwatch/blob/9b4597e/src/diagnose/engine.rs), [rules](https://github.com/matthart1983/netwatch/blob/9b4597e/src/diagnose/rules.rs), and [issue model](https://github.com/matthart1983/netwatch/blob/9b4597e/src/diagnose/issue.rs). Local checkout. Existing deterministic issue workflow.
[^5]: imsnif/bandwhich, [official repository README](https://github.com/imsnif/bandwhich). Undated living documentation. Attribution and bandwidth-monitoring scope.
[^6]: Trippy, [official product documentation](https://trippy.rs/). Undated living documentation. Tracing protocols, ECMP, MPLS, ASN, NAT.
[^7]: GyulyVGC/Sniffnet, [official repository README](https://github.com/GyulyVGC/sniffnet). Undated living documentation. Program identification, notifications, capture import/export.
[^8]: Wireshark, [Working With Captured Packets](https://www.wireshark.org/docs/wsug_html_chunked/ChapterWork.html). Undated current User’s Guide. Packet-analysis workflow and display filters.
[^9]: Wireshark, [Capturing packets](https://www.wireshark.org/docs/wsdg_html_chunked/ChWorksCapturePackets.html) and [Capture Privileges](https://wiki.wireshark.org/CaptureSetup/CapturePrivileges). Living official documentation. Privileged capture isolation through dumpcap.
[^10]: Cilium, [Network Observability with Hubble](https://docs.cilium.io/en/stable/observability/hubble/). Retrieved documentation labelled 1.20.1. Cluster inspection, service map, exporter, TLS topics.
[^11]: evilsocket/OpenSnitch, [official repository](https://github.com/evilsocket/opensnitch). Undated living documentation. Linux interactive application firewall scope.
[^12]: NetWatch Labs, [Cloud](https://www.netwatchlabs.com/cloud). Undated vendor page. Public fleet workflow, free-while-growing statement, export and resolution claims; service not audited.
[^13]: Netwatch, [application startup](https://github.com/matthart1983/netwatch/blob/9b4597e/src/app.rs#L710), [capture worker](https://github.com/matthart1983/netwatch/blob/9b4597e/src/collectors/packets/mod.rs#L1320), and [Linux sandbox](https://github.com/matthart1983/netwatch/blob/9b4597e/src/sandbox/linux.rs). Local checkout. Startup order, worker creation, restriction API and retained capabilities.
[^14]: Mickaël Salaün / Linux kernel project, [Landlock: unprivileged access control](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html), retrieved page dated August 2026. Thread inheritance and explicit TSYNC requirements. Local `landlock-0.4.7` crate source also inspected for default restriction flags.
[^15]: Netwatch, [remediation journal](https://github.com/matthart1983/netwatch/blob/9b4597e/src/diagnose/remediation.rs#L128), [action dispatcher](https://github.com/matthart1983/netwatch/blob/9b4597e/src/app.rs#L4908), [TUI startup](https://github.com/matthart1983/netwatch/blob/9b4597e/src/app.rs#L1703), and [daemon startup](https://github.com/matthart1983/netwatch/blob/9b4597e/src/app.rs#L1943). Local checkout. Write ordering, error reporting, liveness and reconciliation differences.
[^16]: Netwatch, [live observations](https://github.com/matthart1983/netwatch/blob/9b4597e/src/diagnose/live.rs#L160) and [bufferbloat detector](https://github.com/matthart1983/netwatch/blob/9b4597e/src/diagnose/detectors.rs#L1619). Local checkout. Missing loaded/idle RTT inputs and early return.
[^17]: Netwatch, [attribution initialisation](https://github.com/matthart1983/netwatch/blob/9b4597e/src/app.rs#L750), [TCP information collector](https://github.com/matthart1983/netwatch/blob/9b4597e/src/collectors/tcp_info.rs), and [sandbox platform dispatch](https://github.com/matthart1983/netwatch/blob/9b4597e/src/sandbox/mod.rs). Local checkout. Current mitigations and platform boundaries.
[^18]: Netwatch, [incident recorder](https://github.com/matthart1983/netwatch/blob/9b4597e/src/collectors/incident.rs#L240), [diagnostic report export](https://github.com/matthart1983/netwatch/blob/9b4597e/src/app.rs#L4951), and [capture statistics](https://github.com/matthart1983/netwatch/blob/9b4597e/src/collectors/packets/mod.rs#L1428). Local checkout. Existing evidence retention, export paths and capture health.
[^19]: Netwatch, [egress policy implementation](https://github.com/matthart1983/netwatch/blob/9b4597e/src/collectors/egress/policy.rs). Local checkout. Identity model, matching semantics, strict mode.
[^20]: Netwatch, [CI workflow](https://github.com/matthart1983/netwatch/blob/9b4597e/.github/workflows/ci.yml), [release workflow](https://github.com/matthart1983/netwatch/blob/9b4597e/.github/workflows/release.yml), and local source inventory. Validation command and result recorded in this report’s scope; no performance measurements collected.
[^21]: Netwatch, [AI Insights documentation](https://github.com/matthart1983/netwatch/blob/9b4597e/docs/INSIGHTS.md). Local checkout. Stale tab instructions and opt-in external commentary.
