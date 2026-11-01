**Netwatch Diagnose — implementation plan**

> Design/review record: this document can include proposals and revision-specific results.
> For current user behavior, use the [documentation index](../index.md).

Created 20 September 2026. Revised 20 September 2026 after verifying every finding against source. Status: DG00–DG09 implemented locally on 20 September 2026. What remains is listed under Remaining work.

Base revision: `3fff5d9`, version 0.32.0. The originating review examined v0.32.0 at `36832dd`. Every defect below was re-checked against `3fff5d9` and carries a file:line reference; revalidate before editing, since line numbers move.

Scope: diagnostic reliability and operator workflow. The 30-rule catalogue, deterministic engine, baselines, episode recorder, active tests and remediation journal stay. This plan corrects what they conclude, not how they are structured.

**Outcome**

An operator can select an affected service, identify the failed stage, inspect the supporting measurements, distinguish plausible causes, run a useful next test, verify recovery on that same service, and export a report another engineer can check.

Acceptance runs on Linux. macOS and Windows builds and behaviour are preserved, but this plan makes no reliability claim for them; see the platform gate.

**Relationship to the existing plan**

`netwatch-implementation-plan.md` defines PR01–PR16 and `implementation-progress.md` records PR01–PR10 as shipped in 0.31.0–0.31.2. To avoid two live meanings for "PR03", packages here are numbered **DG00–DG09**.

Overlap with that plan's unfinished packages, which must be reconciled before the corresponding DG package starts:

| Existing package | Status | Overlap | Resolution |
|---|---|---|---|
| PR11 shared incident schema | Not started | DG03 observation identity, DG09 export | DG03 defines the schema; PR11 is closed as superseded |
| PR12 finite diagnostic sessions | Not started | DG09 `diagnose run` | DG09 delivers it; PR12 closed as superseded |
| PR13 sharing profiles | Not started | DG09 redaction | DG09 covers support export only; PR13 keeps pseudonymised sharing |
| PR14 guided diagnosis | Not started | Parked work below | Remains the owner of guided UI; not duplicated here |
| PR15 loaded-latency measurement | Not started | DG01 needs it | DG01 depends on PR15 or ships the rule dormant |

**Verified defects**

Each was reproduced by source inspection at `3fff5d9`. The engine's 308 library tests pass today, so these behaviours are what the suite currently protects.

| # | Defect | Location |
|---|---|---|
| D1 | `arp_ok` is assigned the ICMP result; no ARP probe is ever sent, and the field is a `bool` with no unknown state | `live.rs:574`, `detectors.rs:294` |
| D2 | Split-horizon DNS is disproved by its own signature: a private answer for a public name scores the benign cause 0.0 | `detectors.rs:1641-1656` |
| D3 | Any non-open issue verifies as `Recovered`, so a manual close credits the preceding action | `engine.rs:926-932` |
| D4 | An inconclusive re-run is skipped rather than retracting the previous answer, which keeps ranking causes | `next_test.rs:233-244` |
| D5 | Hop blame fires when all later hops are silent, and the emitted evidence text asserts propagation that was never observed | `detectors.rs:2146-2156`, `2175-2187` |
| D6 | Receiver bufferbloat is an absolute-RTT test (`rtt >= 100ms && tx_bps > 0`) with the comparative check optional | `detectors.rs:158`, `2234-2268` |
| D7 | Skipped checks leave both numerator and denominator, so one trivial pass scores 1.0 and renders Strong | `issue.rs:380-407` |
| D8 | All target rules share one `newest` completion time, so a fast target confirms and recovers a stale one | `targets.rs:1004-1020`, `engine.rs:108-109` |
| D9 | Suppression overlap is `(Host, _) => true`, `(Iface, _) => true`, `(Resolver, Target) => true` | `rules.rs:374-386` |

Also found: baselines fingerprint only iface/gateway/resolvers/subnet (`baseline.rs:67-105`), with no VPN, namespace or route awareness; `docs/diagnostic-coverage.md` claims 25 rules, omits all five `target.*` rules, and marks five Active rules as unintegrated.

**Tests that assert current behaviour**

These pass today and must be inverted or deleted by the package that fixes the defect. A package is not done while its casualty still passes unchanged.

| Test | Asserts | Fixed by |
|---|---|---|
| `issue.rs:932` `skipped_checks_do_not_count_against_a_cause` | Strong with a skipped check | DG02 |
| `engine.rs:1968` `cached_probe_does_not_complete_verification_without_a_new_result` | Single-target case only; extend to two targets | DG03 |
| Any `detectors.rs` case asserting `arp_resolves`/`arp_fails` text | Fabricated ARP result | DG00 |

**Work packages**

Estimates are engineering days for one experienced Rust developer with review, expressed as ranges. They are not calendar commitments.

---

**DG00 — Four corrections that need no new architecture** · implemented 20 September 2026 · no dependencies · release blocker

Files: `live.rs`, `detectors.rs`, `engine.rs`, `next_test.rs`, `issue.rs`, `features.rs`.

- Make `GatewayObs.arp_ok` an `Option<bool>` and leave it `None` until an ARP probe exists. Render unknown as unknown in both the `arp_resolves` and `arp_fails` checks, and in the `gateway.arp_ok` feature (`features.rs:155`).
- Invert the split-horizon condition: a private answer for a public name supports split DNS rather than refuting it. Keep `interceptor` as a competing cause.
- Add a verification outcome for operator closure, distinct from `Recovered`. Only an observed recovery hold may produce `Recovered`.
- Make an inconclusive re-run retract the prior answer for that test instead of being skipped, so a superseded result stops ranking causes.

Acceptance: an unprivileged run with no ARP probe never prints "no arp reply from the gateway"; a private answer for a public name leaves split DNS among the ranked causes; closing an issue by hand cannot produce `Recovered`; an inconclusive re-run removes the earlier answer from cause ranking and the test is offered again.

Ship this before anything else. These are wrong answers in released builds.

Result: `arp_ok` is now `Option<bool>` and `None` on every live host; the split-horizon check supports the cause it names, at the same weight as `interceptor`; `VerifyOutcome::ClosedByOperator` separates a hand-closed issue from a measured one, and only an auto-close still reports `Recovered`; an inconclusive re-run retracts the earlier answer and the test is offered again. Four regression tests added, three of which fail against the previous code (the ARP one could not be expressed before, since the field had no unknown state). Full suite 1171 passed, 3 ignored; Clippy and fmt clean. `ml/schema.json` regenerated for the renamed check.

Not covered, by design: `wrong_vlan_or_address_conflict` still reads Strong on a skipped ARP check, because skipped checks leave the denominator. That is DG02.

---

**DG01 — Two claims the evidence cannot support** · implemented 20 September 2026 · after DG00 · release blocker

Files: `detectors.rs`, `rules.rs`, `docs/diagnostic-coverage.md`.

- Add `destination_reached` to `PathObs` and require it before naming a hop. Where every later hop is silent, report unattributed path loss rather than a culprit.
- Emit evidence text from the branch that fired. The current strings assert propagation in a branch where nothing propagated.
- Require the loaded/idle comparison before `tcp.bufferbloat_remote` claims receiver queueing. Absent it, report elevated RTT without localisation.

Decision this package must record: both rules go dormant on hosts where the corroboration is unavailable. That is the intended outcome. `tcp.bufferbloat_remote` becomes dependent on the loaded-latency work in the existing PR15; until that lands, the rule fires only when an operator has run the test manually. State the dormancy in the coverage document rather than leaving users to infer it.

Acceptance: steady 150 ms traffic with no comparative evidence produces no bufferbloat claim; two lossy intermediate hops followed by a silent tail produce unattributed loss, not hop blame; every check string in a fired detection is true of the branch that produced it.

---

**DG02 — Evidence support replaces the confidence ratio** · implemented 20 September 2026 · after DG01

Files: `issue.rs`, `causes.rs`, `detectors.rs`, `next_test.rs`.

- Declare per cause which evidence is required, which is supporting, and which contradicts.
- A missing required check caps the cause below Strong. Skipped checks stop being free.
- Keep a directly observed fact confirmable by a single appropriate measurement; the cap applies to explanations, not observations.
- Prevent checks derived from one measurement from counting as independent corroboration.

Acceptance: one supporting symptom plus a missing required test cannot reach Strong; every Strong cause names the condition that made it sufficient; `issue.rs:932` is inverted; the healthy-lookalike corpus produces no Strong cause.

---

**DG03 — Per-target observation identity** · implemented 20 September 2026 · after DG02 · release blocker

Files: `targets.rs`, `engine.rs`, `issue.rs`, `episode.rs`, `export.rs`.

- Replace the single `newest` completion with per-target completion identity carried through adapter, engine and recorder.
- Key confirmation and recovery holds on observations of the issue's own subject.
- Derive freshness from each target's configured interval; a cached result is not a new sample.
- Separate UTC event time from monotonic in-process duration.
- Define the serialised shape once here, since DG09 exports it and the SDK consumes it. Old recordings decode missing identity as unknown.

Acceptance: a fast target B cannot confirm, hold or resolve an issue about cached target A; the existing single-target test is extended to two targets and fails before the fix; suspend/resume and wall-clock jumps cannot manufacture observed duration; recordings from 0.32.0 load without inventing measurements.

---

**DG04 — Suppression that follows dependency** · implemented 20 September 2026 · after DG03

Files: `rules.rs`, `engine.rs`, `report.rs`.

- Replace blanket subject overlap with demonstrated shared dependency: same route or interface, same resolver, same address family.
- Where the relationship is uncertain, group without hiding either finding.
- Keep suppression reasons in reports; keep the graph deterministic and cycle-safe.

Acceptance: an Ethernet failure cannot demote a target reached over Wi-Fi or a tunnel; a resolver failure suppresses only targets that used that resolver; two unrelated simultaneous faults both stay visible.

---

**DG05 — Network context on baselines and issues** · implemented 20 September 2026 · after DG03

Files: `baseline.rs`, `live.rs`, `engine.rs`, `coverage.rs`, `src/app.rs`.

- Extend the fingerprint beyond iface/gateway/resolvers/subnet to address family, effective route and VPN generation.
- Scope issue identity and pending confirmations the same way, not just baselines.
- Separate last evaluation from last measurement, and show stale or unobservable findings as such.
- Replace unknown process attribution rendered as "all processes" with explicit measured or unknown scope.

Acceptance: changing network or VPN route does not verify the previous incident; stale evidence does not become fresh on redraw; returning to a known network states what history it reused; missing attribution never claims universal impact.

---

**DG06 — Rule contracts, implicated families first** · tier one implemented 20 September 2026 · after DG02

Files: `detectors.rs`, `rules.rs`, `causes.rs`, `kernel.rs`, `active.rs`, `egress.rs`, `docs/diagnostic-coverage.md`.

For each rule record: observed condition, scope, sufficient evidence, lookalikes, contradictions, severity, confirmation, recovery, next test, platform limits.

Order: the eight rules implicated above (`gateway.unreachable`, `dns.hijack_suspect`, `path.high_loss`, `tcp.bufferbloat_remote`, and the four `target.*` rules that share completion identity), then DNS and socket families, then the rest. Partial completion is expected and acceptable; the release gate distinguishes the two tiers.

Regenerate `docs/diagnostic-coverage.md` from `CATALOGUE` so it cannot drift again. It currently says 25 rules, omits all five `target.*` entries, and marks five Active rules as unintegrated.

Acceptance: every contracted rule has a positive case, a healthy lookalike, an absent-evidence case, a scoped recovery case and an unrelated-subject case; the coverage document is generated, not hand-maintained.

---

**DG07 — Target address selection and stage semantics** · implemented 20 September 2026 · after DG03

Files: `targets.rs`, `probe_io.rs`, target collector tests.

- Bounded, paced address fallback that preserves per-address and per-family results.
- Run TLS and HTTP on the connection that actually succeeded.
- Record effective endpoint, SNI and HTTP authority; correct non-default ports and IPv6 literals.
- Enforce a total deadline and cancellation budget; one hanging target must not starve the others.

Acceptance: first-address failure with a working alternative yields a successful service result plus a recorded family degradation; AAAA-only targets work; cancelled work cannot publish success; a hanging target does not block healthy results.

---

**DG08 — Replay corpus and fault lab in CI** · implemented 20 September 2026

Files: `episode.rs`, new fixture corpus, `tests/diagnose/fault_lab.py`, `.github/workflows/ci.yml`.

Today's replay tests record and replay in memory, comparing a recording against itself; there is no checked-in corpus. `fault_lab.py` exists with 14 cases and CI references it nowhere.

- Add a reviewed corpus of recorded episodes with expected canonical decisions: issues, lifecycle, cause support, evidence references, coverage, suppression, action outcomes.
- Record engine and ruleset identity separately from schema version.
- Add a privileged Linux CI job running `fault_lab.py` with retained artefacts.
- Semantic fixes require a reviewed change to expected output. Never preserve an old wrong answer to keep a diff clean.

Acceptance: replay of the pinned corpus is deterministic under a pinned engine; each DG package that changes a conclusion lands with its corpus diff reviewed; the fault lab runs on every push to main.

---

**DG09 — One-shot diagnosis and support export** · implemented 20 September 2026 · after DG03, DG07

Files: `src/cli.rs`, `episode.rs`, `report.rs`, `export.rs`.

`netwatch diagnose` already has `coverage`, `episodes`, `replay`, `features` and `export`, and `coverage`/`replay` already emit `--json`. This adds the missing single-shot entry point:

`netwatch diagnose run --target NAME --budget 30s --format json`

- Versioned output with documented exit classes: finding, no finding, incomplete, error.
- A bounded run that cannot gather enough evidence returns incomplete, never "healthy".
- Export build and ruleset identity, scope, endpoint attempts, evidence ages, tests, actions and verification outcome.
- Exercise redaction against hostnames, URLs, tokens, labels and certificate fields.

Acceptance: a shell consumer can distinguish a failure from insufficient evidence; an empty finding list never implies health; exported numbers match the UI; seeded sensitive fixtures do not survive redaction.

---

**Parked**

Not scheduled here, and not because they lack value:

- Explicit connection, proxy and trust profiles. Large, and the confidence and identity work must settle first.
- Guided TUI investigation. Owned by the existing PR14; revisit once DG02–DG05 have landed and the underlying conclusions are trustworthy.
- Learned ranking, new detector families, generated narratives, fleet orchestration.

**Effort**

| Tier | Packages | Days |
|---|---|---|
| Credibility core | DG00–DG04 | 29–45 |
| Context and contracts | DG05, DG06 | 15–23 |
| Surface and assurance | DG07–DG09 | 19–30 |
| Total | | 63–98 |

That is 13–20 engineer-weeks, against the 8–12 implied by the previous draft. The predecessor plan estimated 18–31 engineer-weeks for comparable scope and remains unfinished, which is the better reference point. If the budget is smaller, ship DG00–DG04 and stop: that tier removes every fabricated conclusion found by the review. The rest improves coverage and handoff.

**Release gates**

| Gate | Requirement | Achievable now |
|---|---|---|
| False verified repair | Zero across the deterministic missing, stale, manual-close and context-change matrix | Yes |
| Unsupported strong cause | Zero in the reviewed healthy-lookalike corpus | Yes |
| Fabricated evidence text | No check string may assert an observation the firing branch did not make | Yes |
| Rule contracts, tier 1 | The eight implicated rules have full contracts and all five scenario classes | Yes |
| Rule contracts, tier 2 | All 30 rules contracted. Required before any "professional diagnostic tool" claim | Later |
| Replay | Exact canonical decisions on the pinned corpus; semantic changes reviewed | Yes |
| Downstream consumers | `netwatch-sdk`, the dashboard and stored reports round-trip the DG03 schema; a migration note ships with it | Yes |
| Resource use | Declared CPU, memory, disk, traffic and cancellation budgets verified on representative hardware | Yes |
| Platform | Linux live-adapter acceptance. macOS and Windows publish a capability table and claim nothing beyond it | Yes |
| Operator usefulness | Five operators, three scripted faults each, correct scope named within ten minutes, four of five pass | Yes |
| Detection and precision | Measure and publish per-family rates with denominators and confidence intervals. No threshold | Yes |
| Quiet alert burden | Publish false actionable alerts per quiet host-hour with the host-hour count | Yes |

The previous draft set 95% detection, 95% strong-cause precision and fewer than one false alert per 100 quiet host-hours over 1,000 pooled host-hours. At 100 reviewed decisions a 95% rate carries roughly ±4 points of uncertainty, and 1,000 quiet host-hours is about 42 machine-days that the four-week pilot also has to spend exercising faults. Publish the measurements with their denominators; set thresholds in a later release, once there is a fleet to measure against.

**Tracking**

Per package record: status, source revision, defects addressed, contracts changed, tests added and casualties inverted, schema and consumer impact, remaining limitations, acceptance result. Compiling and passing unit tests is not completion.

Run focused regressions during development, then formatting, Clippy, test and build checks for the affected targets. Validate shared-engine consumers whenever public types or serialised contracts change.

**Remaining work**

Every package landed, but three things in this plan were deliberately not finished, and one was cut:

- **Tier-two rule contracts.** Eight rules carry a reviewed contract; the other 22 are listed in the generated document as not yet contracted. The release gate distinguishes the two tiers, and the "professional diagnostic tool" claim still needs all 30.
- **Measurement provenance on checks.** Two checks derived from one measurement can still both count as support, because checks carry no source identity. The annotation belongs with the per-rule contracts.
- **Field measurements.** Detection rate, strong-cause precision and quiet alert burden are published, not thresholded, and nothing has yet measured them over the host-hours the gates describe.
- **Cut: support export.** DG09 shipped the one-shot run and its exit classes. The redaction and ticket-summary half stays with the existing PR13, which already owns sharing profiles.

The parked work below — connection and trust profiles, guided TUI investigation — is unchanged.
