# Diagnose implementation plan — 0.33, 0.34, Q1 2027

> Design/review record: this document can include proposals and revision-specific results.
> For current user behavior, use the [documentation index](index.md).

Date: 2026-09-26. Written against `diagnose-enhancements` at `df1dfba`.

Sources:
- `/home/matt/reports/Netwatch Diagnose rules and refinements.md` (the report). It decides what to build. Where it and REVIEW disagree, the report wins: the `dns.failing` window, the `path.rtt_spike` fallback and the exit-code floor.
- `docs/REVIEW-2026-09-24.md` §2 and §3 (REVIEW). It sets the release scopes and the order of work.
- `/home/matt/reports/Portfolio two-year plan 2026-09.md` (the plan): §4.3 Finding model, §6.1 human hours and session rules, §6.9 beta bar, §7 release dates and split rule, §12 first 30 days.
- The research notes in `/home/matt/research_notes/Netwatch Diagnose rules and refinements/`, mainly `verification_new_rules.md` (VNR) and `verification_refinements.md` (VR).

Summary:
1. Owner review time sets the pace, not agent time. This plan books the plan's 1.5 h a week of PR review for Diagnose, 16.9 h from 5 Oct to 18 Dec against 16.5 h of review line, and leaves most of the 0.75 h weekly buffer for other repos and overruns.
2. 0.33 (Tue 20 Oct) is 7 PRs and about 4.7 h of review. It meets two of REVIEW's three exit clauses: no check reads absent input as evidence, and the fault lab drives the real engine.
3. 0.34 (Tue 24 Nov) is 15 PRs and about 6.7 h. It adds the Observation kind, an exit code that counts issues only, expiry, the σ floor, a DNS verify that can close, the mute fix, the controller split and open→close corpus episodes. That meets the third exit clause.
4. 0.35 (Tue 15 Dec) is 8 PRs and about 4.25 h. It ships First Look beta with three complete facts, a partial path MTU fact, and IPv6 and CGNAT rows that say why they are not measured yet. This is not the plan §7 split: Windows and the rest of REVIEW §3 move to 2027 (decision M3).
5. Q1 2027 carries PCAPNG and about 12 h of remaining REVIEW §2, §3 and First Look work. The DNS probe fix, `gateway.loss` and `wifi.high_retry` land in Q2 2027, and the Q1 rule slice (host batch, WAN and VPN rules) in Q3 2027.
6. Three things are due before any 0.33 session: clear the working tree (overdue), put 0.33 PRs where CI runs, and decide M1 (extra review hours) by Mon 5 Oct.

Conventions:
- File:line citations are at `df1dfba` and use paths under `src/` unless they start with `docs/`, `tests/`, `examples/`, `ml/` or `.github/`. I re-read each one on 26 Sep.
- 0.32.4 is being built in `/home/matt/netwatch-wt/hotfix-0.32.4` and edits `app.rs`, `collectors/config.rs`, `collectors/insights.rs`, `collectors/network_intel.rs`, `collectors/connections.rs`, `collectors/packets/mod.rs` and `platform/mod.rs`, among others. After the forward merge (D33-X07), lines in those files move. Agents find anchors by function name.
- Work-item IDs are stable across this plan and the slice plans it merges. PR numbers are new and run in merge order.
- Review hours are owner hours. PRs marked "agent review first" get an agent `/code-review` pass before the owner looks, and their hours assume that (decision OD-12c).

---

## 1. Owner decisions needed

Due dates are the latest day the default can still change without moving a PR.

| ID | Decision | Default if undecided | Due |
|---|---|---|---|
| A00 | Clear the working tree: PCAPNG to its branch, the separate README edit to its own branch or dropped, REVIEW and this plan committed, `BACKLOG.md` created (D33-A00) | Must happen; there is no default | Overdue. The 48 h window in plan §6.1 closed about 26 Sep 07:00. Do it by Mon 28 Sep |
| X07 | Where 0.33 PRs merge. `.github/workflows/ci.yml:3-8` runs only for `main`, so PRs into `diagnose-enhancements` get no CI and the 0.32.4 release guard would refuse the tag | Merge `release/0.32.4` into `main`, then `df1dfba` into `main`; `main` is the base and tag branch for every lane | Fri 2 Oct |
| WRITER | Which owner-only file writer survives: 0.32.4 §1.4's or PCAPNG's `builder.mode(0o700)` code | 0.32.4's, because it ships first. PCAPNG adopts it when rebased (D33-X08) | Fri 2 Oct |
| M1 | Add review hours: about 1.5 h a week from 5 Oct to 11 Dec, taken from essays and the second experiment per the plan §6.1 drop order | No. The schedule in §7 applies. §7 shows what each extra hour buys | Mon 5 Oct |
| M2 | Ship 0.33 with exit clause 2 (open→close episodes) unmet, listed as a known gap and made a 0.34 gate | Yes, if M1 is no | Mon 5 Oct |
| M6 | Move the watch-finding 0.1 extraction from 6-9 Oct (plan §12) to the week of 14 Dec, after the 0.34 types settle. `IssueState` and the close states stay in netwatch | Move it, and leave lifecycle types in netwatch | Mon 5 Oct |
| D2 | What "gateway loss" means in REVIEW's exit clause 1 | Total loss (`gateway.unreachable`) until `gateway.loss` exists | Mon 5 Oct |
| OD-12c | Agent `/code-review` before owner review for tests-only, mechanical-move and parser PRs | Yes | Mon 5 Oct |
| D6 | Lab CI scope | `--quick` on PRs touching `src/diagnose/`, `src/collectors/health.rs` or `tests/diagnose/`; long negatives on a weekly schedule | Wed 7 Oct |
| X02 | REVIEW §2.4's temp-file-then-rename for the resolver CLI | Drop it. The adapter's design writes through the opened fd and preserves the inode (`docs/resolver-adapter.md:72-75`), and the journal already blocks after an interrupted write. Delete the two unused helpers only | Mon 12 Oct |
| S2 | `diagnose run --json` schema 2: `issues` and `observations` split, `kind` on findings, `state` replaces `passed` on checks | Accept, with a CHANGELOG breaking-change note | Mon 26 Oct |
| D7 | Mute length | Keep 1 h | Mon 2 Nov |
| M3 | What 0.35 carries. The plan §7 split ships Windows and first run first and First Look second. At 1.5 h a week only one fits in December | First Look beta in 0.35; REVIEW §3 (Windows, first-run banner, help from the key table) in 2027 | Sat 24 Oct |
| M4 | Rebook the six First Look sessions, and re-date the label-uptake test (23 Jan) and the Show HN (9 Feb) | Sessions 16 Dec to 29 Jan; label test and Show HN re-dated at the 25 Jan review | Sat 24 Oct |
| CAP | The `setcap` line First Look and the banner print. REVIEW §3.3 says `cap_net_raw,cap_net_admin+eip`; the shipped docs say `cap_net_raw,cap_bpf,cap_perfmon+eip` (`README.md:70`, `docs/REFERENCE.md:465`), and eBPF needs CAP_BPF and CAP_PERFMON (`sandbox/mod.rs:165`) | The shipped line, as one constant; edit REVIEW §3.3 to match | Mon 23 Nov |
| M5 | On a loopback stub resolver, does `dns.slow_resolver` count as a core rule for earned green (C14)? | No. On a loopback resolver it leaves the core set and the Clear sentence says "DNS speed not judged: the local stub answers from cache" | Mon 7 Dec |
| OD-1 | The DNS probe zone for the uncached probe (A13) | **Decided 2026-09-26: a random 8-character label under `metric.gstatic.com`, as ChromeOS does.** Listed in the 0.34 network-calls table. The DNS bundle is unblocked | Done |
| B-4 | `dns.failing` close rule (B15) | The simulated close: `dns.cycle_failure_rate` < 1% for 120 s | Before B15 is drafted, Mon 18 Jan |
| B-10 | Do retuned existing rules carry the beta mark? | No. Only new rule and Observation ids do | Mon 23 Nov |
| BETA-EXIT | Are beta findings on by default, and do they count toward `diagnose run`'s exit code? | On and tagged; counted only with `--include-beta` | Mon 23 Nov |
| OD-2 | May Diagnose name 1.1.1.1 as the resolver to switch to? | Instruct only, with the measured RTT, no Apply step | With A11 (Q2 2027) |
| OD-3 | Run First Look experiments on every network change by default | On, and listed in the network-calls table first | With D34-12 (Q1 2027) |

Decisions for Q1 2027 and later (release numbers, second WAN target, host rules on laptops, the `lab` cargo feature, calibration cut-offs) are listed in §6.

---

## 2. Principles

1. **Abstain before judging.** A check whose input was never gathered is `not_run` with a `why_not` from `Availability`, never `passed`. Plan §4.3 builds this into the schema, and the `alt_rtt_ms` defect is the case it was written for.
2. **Inputs before thresholds.** Fix what a probe measures before tuning its numbers. A σ floor tuned on a loopback cache that answers in 0 ms means nothing.
3. **Thresholds before lifecycle.** A verify line is derived from the open line, so the open line settles first.
4. **Lifecycle before screen.** The tab shows only states the engine has. "Recovering", "expired" and "muted until" wait for the engine to track them.
5. **Every new rule or Observation is beta until the §6.9 bar.** That bar is 0 false positives across at least 5 scenarios, one of them from the field. The beta marker (D34-17) lands in 0.35, so no new rule or Observation id ships before it. This is why B08 (`tcp.receiver_limited`) waits.

Working rules that follow from these:
- A PR that changes any recorded decision re-records the corpus in the same PR, and its description lists each changed span with the item that explains it. An unexplained change blocks the merge.
- A PR that adds or renames a check or cause regenerates `ml/schema.json` with `cargo run -- diagnose features --schema ml/schema.json`. `the_committed_schema_is_current` (`diagnose/features.rs:892`) fails otherwise, because the feature columns come from `causes::CAUSES` (`diagnose/features.rs:294-303`).
- Each PR should take under an hour to review. Three reach the hour (P04, P29, P30) and say why.
- At most 2 unreviewed PRs per lane. The two lanes are the two sessions plan §6.1 allows per repo.
- Feature freeze is the Friday before a release. Every PR an exit clause or gate depends on is merged by then. The Monday before a Tuesday tag takes only the release PR and at most one low-risk PR that can slip without touching a gate.

---

## 3. Dependency graph

`A ← B, C` means A needs B and C merged first. Items in brackets are soft: A can land first and use today's behaviour.

**Before 0.33**
- D33-X07 ← 0.32.4 tagged. D33-A00 ← nothing.
- Every 0.33 item ← D33-A00, D33-X07.

**0.33**
- A01 ← nothing. A02, A03 ← A01. A06 ← A01, A02. A04, A05 ← nothing.
- C01, C03 ← nothing. C04 ← nothing; each of A02 to A06 empties its rows of C04's `EXPECTED_UNTIL_0_33_A` list.
- C05 ← nothing. C06 ← C05. C07 ← C05, C06.
- B16, X02, X03, X04, X05, X06, C19a ← nothing.

**0.34**
- X01 ← 0.33 tag. B01 ← X01, because X01 moves `DiagnoseState::new`.
- B05 ← B01 (merge order only). B06 ← B05. B07 ← B05, B06.
- B03, B04 ← B01. B24 ← nothing. B25 ← B04, B24. C16 ← B25, because both edit `merge` and `age_unseen`.
- B09 ← B01. B10 ← B09. B11 ← B01, B03. B13 ← B03, B10, [B12].
- C02 ← C01. C08 ← C01, C02. C09 ← C08, B11, B13, A05. C10 ← C08, B11, B25. C11 ← C09, C10.
- B33a ← nothing.

**0.35**
- D34-17 ← B05. D34-01 ← nothing. D34-02 ← D34-01, C01.
- D34-04 ← nothing. D34-21 ← nothing; it uses today's gateway address, and D34-03 later adds the tunnel class. A10 ← A01.
- D34-22 ← D34-02, D34-04, D34-21, D34-17, B05, A01, A10. D34-23 ← D34-22.
- D34-24 ← D34-22, D34-17. I dropped its dependency on C13: the band replaces "Nothing to report" and needs no readiness summary.

**2027** (forecast order, §6)
- D34-03 ← nothing. A07 ← D34-03; the watched interface comes from `route_to`.
- B02 ← B01. B12 ← B02, B09. B15 ← B02, B05.
- C13 ← A01. C14 ← C13, A05, M5, [A07].
- D34-13 ← D34-03, D34-04, B05. It supersedes A10 on Linux.
- D34-29a ← nothing. D34-11 ← nothing. D34-12 ← D34-11, D34-13, X01, D34-29a. D34-14 ← D34-12.
- B08 ← B05, D34-17. D34-28 ← X01, D34-24. It no longer waits for C23 or the key-map PR: labels are stored locally first and `u` is registered directly.
- D34-08 + B21 (one PR) ← A03. D34-09 ← B21, A03, X01.
- B27 ← nothing. D34-16 ← C05 to C07. D34-15 ← D34-03, D34-04, D34-12, D34-16, B27.
- A11 ← nothing. A12 ← A01, A11. B14 ← B05, B10, B13. A13 ← A11, B14, OD-1, all in one PR. A14 ← A12, A13, B15.
- D34-18 ← D34-01, D34-02, D34-16, D34-17, B24, B25. I dropped its B26 dependency: without superseded closes, a `gateway.loss` issue from the old network closes as "recovered" on the new one once its verify holds. The close reason is wrong but the issue does not stick.
- D34-07 ← A04. D34-20 ← D34-07, D34-17.
- C22 ← 0.32.4 §1.4's writer. C23 ← C22.
- D34-06 ← D34-05, C23, B24 to B26. It absorbs A08.
- The Q1 rule slice: D36-01 ← B24 to B26. D36-06 ← B26, C05 to C07. D36-07 to D36-09 ← D34-03, D34-04, D34-21, D36-06. D37-01 ← D34-01, which owns `impl Default for HealthStatus`.

**Cycles.** One existed and is resolved. D34-12's traffic test checks D34-29's table, and D34-29 depended on D34-12. D34-29 is now D34-29a only: the in-code table, the off switches and a generator with a test that fails when the README section differs. Each PR that adds default traffic adds its own row and regenerates the README section, so there is no separate README item. The other mutual references are merge-order conventions, not cycles: A14 after B15, C04 and the A sites, C11 and the rule PRs.

**Handle map.** The slice plans used handles. They resolve to these items:

| Handle | Items |
|---|---|
| X-AVAIL | A01 |
| X-ABSTAIN | A02 to A06, C04 |
| X-FIX | C01 |
| X-LAB | C05, C06, C07 |
| X-OBS | B05 |
| X-SIGMA | B09, B10, then B12 |
| X-EXPIRE, D33:CLOSE | B24, B25, then B26 |
| X-GREEN | C13, C14 |
| X-CTRL | X01 |
| X-RETRANS | B21 (with D34-08), then B08 |
| X-FLOWID | B27 |
| X-REPORT | C22, C23 |
| X-ZONE | OD-1 |
| D33:UPLINK | A07 |
| D33:DNSREF | A11 |
| D34:HIST | D34-01, D34-02 |
| D34:ROUTE | D34-03, W1 |
| D34:ADDR | D34-04, W2 |
| D34:BETA | D34-17 |
| D34:LBL | D34-28 |
| D34:NETCALLS | D34-29a |
| D34:FLAB | D34-16 |
| D34:KEYS, R-KEYS | REVIEW §3.4 key-map PR |
| D34:CARD | folded into D37-07 |
| R-BANNER | the `setcap` constant in D34-23; the banner itself is REVIEW §3.3 |

---

## 4. 0.33, Tue 20 Oct

Scope: REVIEW exit clauses 1 and 3, plus the cheap honesty fixes. No new rule ids (plan §10 stop list). Seven PRs, about 12.3 agent-days and 4.7 owner hours including the release PR.

| PR | Branch | Items | Lane | Review h | Owner reviews |
|---|---|---|---|---|---|
| P01 | `diagnose/033-why-not` | A01 | A | 0.75 | Wed 7 Oct |
| P02 | `diagnose/033-corpus-and-guards` | C01, C03, C04 | W | 0.45 | Wed 7 Oct |
| P03 | `diagnose/033-abstain-dns-tcp` | A02, A03 | A | 0.5 | Fri 9 Oct |
| P04 | `diagnose/033-lab-driver` | C05, C06 | W | 1.0 | Mon 12 Oct |
| P05 | `diagnose/033-abstain-iface` | A04, A05, A06 | A | 0.4 | Tue 13 Oct |
| P06 | `diagnose/033-lab-scenarios` | C07 | W | 0.75 | Thu 15 Oct |
| P07 | `diagnose/033-honesty` | B16, X03, X04, X05, C19a, X02, X06 | A | 0.6 | Mon 19 Oct |

P04 is one of three PRs that reach an hour; it is the lab driver and topology, which cannot be split without a PR that does nothing on its own. P07 is the one PR allowed on the Monday before the tag. No exit clause depends on it; if it is not approved by Mon 19 noon, it moves to 0.34 and its gate lines drop.

### Before any 0.33 session

#### D33-A00 · Clear the working tree
- **Why.** Plan §6.1: no session starts in a repo whose uncommitted changes are older than 48 hours. The PCAPNG files were last written 24 Sep 06:44 to 07:01, so the window closed about 26 Sep 07:00. Plan §7 merges PCAPNG after 0.33, so its work must not ride on 0.33 branches.
- **Files.** The PCAPNG set: `CHANGELOG.md` (its diff is PCAPNG only), `docs/REFERENCE.md`, `app.rs`, `collectors/incident.rs`, `collectors/insights.rs`, `collectors/packets/mod.rs`, `collectors/packets/pcap_export.rs`, `ui/help.rs`, `ui/mod.rs`, `ui/packets.rs`, `ui/stream_context.rs`, and untracked `collectors/packets/export.rs`, `ui/capture_export.rs`, `docs/capture-export.md`, `scripts/verify-capture-export.py`. Separately, `README.md` carries an unrelated docs edit dated 20 Sep (new tagline, keybinding paragraph, Diagnose and Packets rows), with no PCAPNG lines. Also untracked: `docs/REVIEW-2026-09-24.md`, `docs/research/*`, and this plan.
- **Change.** Commit the PCAPNG set to `feat/pcapng-export`. Commit the README edit to its own branch, or drop it. Commit REVIEW and this plan on the 0.33 base. Move `docs/research/*` to the archive folder plan §12 names. Create `BACKLOG.md` with one line per PR in this plan, since plan §6.1 gives each session one backlog item.
- **Tests.** None.
- **Acceptance.** `git status --short` is empty in `/home/matt/netwatch`.
- **Depends on.** Nothing.
- **Size.** S (owner). **Owner review.** 0.25 h. **Risk.** Low. Losing the PCAPNG work is the only risk, so commit rather than stash.

#### D33-X07 · Put 0.33 work where CI runs
- **Why.** `.github/workflows/ci.yml:3-8` runs on pushes and PRs to `main` only. The 0.32.4 release guard (`release/0.32.4` at `c8ac289`, job `guard` calling `scripts/release-guard.sh`) refuses a tag unless every `ci.yml` run on the tagged commit passed. `origin/main` and `diagnose-enhancements` each hold one commit the other lacks (`6e28232` and `df1dfba`). A lane that forks from `diagnose-enhancements` would get no CI, no clippy and no lab job, and its tag would be refused. REVIEW §1 says to cherry-pick 0.32.4 forward, and no item did.
- **Files.** `.github/workflows/ci.yml:3-8` (unchanged under the default); branches `main`, `release/0.32.4`, `diagnose-enhancements`.
- **Change.** After 0.32.4 is tagged: merge `release/0.32.4` into `main`, then open a PR that merges `df1dfba` into `main`. Every lane forks from `main`, every PR targets `main`, and 0.33 is tagged on `main`. `diagnose-enhancements` is retired. The alternative is adding `diagnose-enhancements` to the CI triggers and tagging there; the default avoids a second long-lived branch.
- **Tests.** CI on the merge PR.
- **Acceptance.** `git log main` contains `df1dfba` and the 0.32.4 tag commit; a test PR from a lane shows the CI, clippy and fault-lab checks.
- **Depends on.** 0.32.4 tagged, decision X07.
- **Size.** S. **Owner review.** 0.25 h. **Risk.** Low. The merge conflicts are in `CHANGELOG.md` only if 0.32.4 and `df1dfba` both edited `[Unreleased]`.

#### D33-X08 · Rebase PCAPNG onto the 0.32.4 writer
- **Why.** 0.32.4 §1.4 makes pcaps and incident bundles owner-only at `collectors/packets/pcap_export.rs:10` and `collectors/incident.rs:670`. PCAPNG deletes most of `pcap_export.rs` and brings its own writer (`builder.mode(0o700)`), and its CHANGELOG entry already claims "Export writes are private on Unix". 0.32.4 §1.2 and §1.3 edit `collectors/packets/mod.rs`, where PCAPNG adds 78 lines. Nobody planned these conflicts.
- **Files.** `feat/pcapng-export`: `collectors/packets/pcap_export.rs`, `collectors/packets/export.rs`, `collectors/incident.rs`, `collectors/packets/mod.rs`, `CHANGELOG.md`.
- **Change.** Lane W rebases the branch onto `main` at `v0.33.0` in the week of 19 Oct, replaces PCAPNG's own permission code with the 0.32.4 helper (decision WRITER), and drops the duplicate CHANGELOG claim. It rebases again in the week of 4 Jan before review. It is not merged in 2026.
- **Tests.** The branch's own tests plus `cargo test` on the rebased head.
- **Acceptance.** The branch rebases cleanly, CI passes, and one owner-only writer exists in the tree.
- **Depends on.** 0.32.4, X07, decision WRITER.
- **Size.** M (1 agent-day per rebase). **Owner review.** None until the January merge (§6). **Risk.** Medium. Two rebases of another author's work; keep the author in the loop.

### P01 · `diagnose/033-why-not`

#### D33-A01 · Every check that did not run says why, as an `Availability`
- **Why.** Report §"Abstain first, then probe the right thing", step one. Plan §4.3 specifies `checks[{id, state: passed|failed|not_run, why_not?: Availability}]`. Today a check that did not run is `passed: None` with free text in `detail` (`diagnose/issue.rs:290-298`), so `why_not` has no value and a new call site can invent any reason. One production site bypasses the constructor: the literal at `diagnose/detectors.rs:1046-1052`.
- **Files.**
  - `diagnose/issue.rs:249-298`: `CheckResult`, with `skipped` at 290.
  - `diagnose/coverage.rs:10-47`: `Availability` and `label()`.
  - `diagnose/detectors.rs`: 33 `CheckResult::skipped` sites at 507, 559, 579, 688, 705, 729, 834, 1115, 1239, 1261, 1274, 1361, 1386, 1410, 1473, 1521, 1542, 1583, 1679, 1707, 1802, 1820, 1837, 1861, 1907, 2035, 2058, 2247, 2260, 2279, 2390, 2597, 2623, and the literal at 1046-1052.
  - Test sites: `diagnose/detectors.rs:3718`, `diagnose/issue.rs:1032, 1051, 1096, 1112, 1147, 1159`, `diagnose/next_test.rs:1035, 1040, 1045`, `diagnose/report.rs:788`.
  - `diagnose/causes.rs:413-418`: the source-scan needle list.
  - `diagnose/export.rs:268-278`: the key allowlist the pseudonymiser skips.
  - `ui/diagnose.rs:1362-1369`: the check line.
- **Change.**
  - Move `Availability` into `issue.rs`, which still imports only serde and fmt, and `pub use` it from `coverage.rs`. This keeps `issue.rs` extractable for watch-finding.
  - Add `why_not: Option<Availability>` (`serde(default, skip_serializing_if = "Option::is_none")`), `enum CheckState { Passed, Failed, NotRun }` and `CheckResult::state()`.
  - Serialise through a wire struct (`serde(into, from)`) that writes `state` next to `passed` and reads records carrying either. Schema 1 output only gains fields; schema 2 (D33-B06) drops `passed`.
  - Add `CheckResult::not_run(id, name, why_not, detail)` and delete `skipped`, so the compiler forces a choice at every site. The literal at 1046 becomes `not_run(.., Learning, "no baseline for this stage yet")`.
  - Map each site by one rule. A probe never built (ICMP to the resolver, cached-name probe, ARP) is `NotImplemented`. A probe that exists but has no fresh result is `NotMeasured`. A user-run test (loaded RTT, trace) is `AwaitingTest`. A check irrelevant by construction is `NotApplicable`. A counter the platform lacks is `Unsupported`. The PR description carries the whole site-to-`Availability` table, so review is one table.
  - The TUI check line prints the availability label before the detail, for example `· not measured · no alternate resolver probe`.
  - Add `why_not` to the `export.rs` allowlist.
- **Tests.**
  - Unit `a_not_run_check_always_says_why`: run `detect()` over every detector-test scenario and over `fixture::observations_at(t)` for `t` in `0..=SCENARIO_SECS` step 10, and assert `passed.is_none() == why_not.is_some()` and `state()` agrees.
  - Unit `a_check_recorded_before_why_not_still_loads`: JSON without `why_not` or `state` deserialises.
  - Export `why_not_survives_redaction`.
  - The `causes.rs` needle becomes `CheckResult::not_run(`.
- **Acceptance.**
  - `git grep -c 'CheckResult::skipped' src` and `git grep -n 'passed: None' src/diagnose/detectors.rs` both print nothing.
  - `netwatch diagnose run --format json` shows `"state": "not_run"` and a `why_not` on every check whose `passed` is null. Checks leave through `"issues": issues` at `diagnose/run.rs:240`.
  - `the_pinned_corpus_replays_to_its_recorded_decisions` (`diagnose/episode.rs:1431`) passes with unchanged decisions.
- **Depends on.** A00, X07.
- **Size.** M. **Owner review.** 0.75 h, agent review first; the owner reads the mapping table. **Risk.** Low. It touches every detector, so it merges first in lane A and nothing else edits `detectors.rs` until it lands.

### P02 · `diagnose/033-corpus-and-guards`

#### D33-C01 · The fixture episode stamps health-probe times
- **Why.** Report §"Tests that make the 0.33 exit reachable". `fixture::episode()` never stamps health times (`diagnose/fixture.rs:343-348`), and `observe_live_at` drops DNS and gateway observations without them (`diagnose/engine.rs:351-356`). The corpus therefore cannot see a DNS or gateway regression. Today it pins two spans, `path.changed` and `tcp.bufferbloat_remote`, both with `closed: null`.
- **Files.** `diagnose/fixture.rs:328-368` (`episode()`); `tests/diagnose/corpus/fixture-scenario.json.gz` and `.decisions.json`.
- **Change.** Set `times.health.{dns, gateway, internet}` on the prober's 5 s grid, `start + (t − t % 5)`. Set `times.health.dns_target` from `obs.dns.resolver` and `gateway_target` from `obs.gateway.addr`. Regenerate with `netwatch diagnose corpus`.
- **Tests.** New `fixture_episode_carries_health_ages`: every frame has DNS and gateway ages and a DNS target. Existing: `the_pinned_corpus_replays_to_its_recorded_decisions`.
- **Acceptance.** The decisions file gains `dns.slow_resolver|169.254.1.1`, opened `2026-09-03 06:48:20` with top cause `upstream_slow`, and replay still matches. Slice C measured both values in a scratch build.
- **Depends on.** Nothing.
- **Size.** S. **Owner review.** 0.15 h. **Risk.** Low. It makes one intended corpus change.

#### D33-C03 · Firing tests for `iface.errors`, `iface.saturated` and `tcp.retrans_burst`
- **Why.** Report §"Today's rules misread the network": these three rules have no test that fires their detector. None is named in `diagnose/detectors.rs` `mod tests` (starts at 2687).
- **Files.** Triggers: `iface.errors` at `diagnose/detectors.rs:1137-1139`, `iface.saturated` at 1301-1326, `tcp.retrans_burst` via `classify_socket` at 148-158. Thresholds at 64-79.
- **Change.** Tests only, at today's thresholds: one that fires and one just below that does not, per rule. The tests encoding the 0.33-B thresholds belong to B19, B20 and B21 when those land.
- **Tests.** `iface_errors_fires_at_the_error_floor`, `iface_errors_fires_at_the_drop_floor`, `iface_errors_is_quiet_below_both_floors`, `iface_saturated_fires_at_ninety_percent`, `iface_saturated_is_quiet_at_eighty_nine`, `retrans_burst_fires_at_five_a_minute`, `retrans_burst_is_quiet_below_five`.
- **Acceptance.** Each rule id appears in a passing detector test that asserts `d.rule`.
- **Depends on.** Nothing.
- **Size.** S. **Owner review.** 0.1 h, agent review first. **Risk.** Low.

#### D33-C04 · One test names every absence site
- **Why.** REVIEW §2 exit clause 3: "No detector reads a hard-coded `None` as evidence". The report lists five sites plus `local_udp_path`. A source-pattern scan cannot see two of them, `if d_packets == 0 { 0.0 }` at `diagnose/live.rs:417-419` and `rx_drops: 0` at `platform/macos.rs:46-47`, and flags about 48 unrelated lines. So the gate is a behaviour table, not a scan.
- **Files.** `diagnose/detectors.rs` `mod tests`, next to `every_id_in_the_detector_source_is_a_valid_literal` (3710); `diagnose/live.rs` tests for the two sampler rows.
- **Change.** A table-driven test. Each row sets one input to `None` (or, for the sampler rows, to the idle or missing state) and names the checks that must be `not_run` or the verdict that must not occur:

  | Input absent | Must be `not_run`, or must not happen |
  |---|---|
  | `DnsObs.alt_rtt_ms` | `alt_resolver_is_fast`, `alt_resolver_over_the_same_path_is_also_slow` |
  | `DnsObs.icmp_rtt_ms` | `icmp_rtt_raised`, `resolver_itself_is_reachable` |
  | `DnsObs.cached_rtt_ms` | `cached_names_still_fast` |
  | `SocketObs.rtt_ms` | no `tcp.bufferbloat_remote`; no `tcp.socket_rtt` evidence of 0 |
  | `IfaceObs.signal_dbm` and `tx_retry_pct` | `signal_weak`, `signal_fine`, `retries_high` |
  | idle radio, 0 frames (sampler) | `tx_retry_pct` is `None`, not 0 |
  | `IfaceObs.carrier` | no `link.down` |
  | interface info missing (sampler) | `carrier` and `wireless` are `None` |
  | `IfaceObs.drops_per_min` | `interface_drops`, `drops_dominate`, `ring_buffer_small` |
  | `GatewayObs.arp_ok`, `internet_reachable` | `arp_resolves`, `arp_fails`, `internet_reachable` |

  Rows that fail at `df1dfba` start in `EXPECTED_UNTIL_0_33_A`, so the test is green when it lands. Rows that need a type or helper that does not exist yet are added by the item that creates it: the idle-radio row by A04 (`retry_share`), the `carrier` and missing-info rows by A05, the `drops_per_min` row by A06.
- **Tests.** `no_detector_reads_an_absent_input_as_evidence`.
- **Acceptance.** Green at `df1dfba`. Exit clause 3 is met when all ten rows exist and `EXPECTED_UNTIL_0_33_A` is empty.
- **Depends on.** Nothing. A02 to A06 each remove their rows from the expected list.
- **Size.** S. **Owner review.** 0.2 h. **Risk.** Low. It absorbs A16 from the slice plans.

### P03 · `diagnose/033-abstain-dns-tcp`

#### D33-A02 · `local_udp_path` stops passing on absent or trivial input
- **Why.** Report §"Today's rules misread the network": a Wi-Fi laptop dropping one multicast frame a minute gets "local: conntrack, udp buffers or nftables · strong · 2 of 2 checks". The alternate-resolver check passes when `alt_rtt_ms` is `None` (`diagnose/detectors.rs:1883-1895`), which it always is live (`diagnose/live.rs:688`). The interface-drops check passes on any drop (1896-1912). Neither is a discriminator, so the Strong cap at `diagnose/issue.rs:458-464` never applies.
- **Files.** `diagnose/detectors.rs:1879-1914` (`detect_dns`, cause `local_udp_path`); `diagnose/causes.rs:164-171`; the test `a_slow_alt_resolver_moves_the_blame_local` (`diagnose/detectors.rs:2895`); `ml/schema.json`.
- **Change.**
  1. `alt_resolver_over_the_same_path_is_also_slow` is `not_run(NotMeasured)` when `alt_rtt_ms` is `None`, passes when the alternate took at least 0.5 × p50, and fails otherwise.
  2. `interface_drops` passes only at `drops_per_min >= t.iface_drop_floor` (60/min, `diagnose/detectors.rs:74`), fails below, and is `not_run(NotMeasured)` when `obs.iface` is `None`.
  3. Add `local_drop_counters` at weight 2.0 (`DISCRIMINATING_WEIGHT`, `diagnose/issue.rs:329`) as `not_run(NotImplemented, "UDP receive-buffer and conntrack drop counters are not read yet")`. The missing discriminator caps the cause at Likely until D36-04 reads `RcvbufErrors`.
  4. Add the check to `causes.rs` and regenerate `ml/schema.json`.
- **Tests.** Detector `one_dropped_multicast_frame_a_minute_is_not_a_local_udp_fault` (1 drop/min, alt `None`: `local_udp_path` at or below Weak and not the top cause) and `local_udp_path_is_never_strong_without_a_local_counter` (alt slow, 120 drops/min: Likely). The test at 2895 now expects Likely. C04's `alt_rtt_ms` row leaves the expected list.
- **Acceptance.** On the report's laptop scenario `diagnose run --format json` never shows `local_udp_path` at `strong`. `the_committed_schema_is_current` passes.
- **Depends on.** A01.
- **Size.** S. **Owner review.** 0.3 h. **Risk.** Low. The 0.5 × p50 line is a judgement, not a validated threshold.

#### D33-A03 · A socket with no RTT is not a 0 ms socket
- **Why.** Report §"Today's rules misread the network", five sites. `rtt_ms.unwrap_or(0.0)` at `diagnose/detectors.rs:152` and 2354.
- **Files.** `classify_socket` (`diagnose/detectors.rs:148-185`); `socket_detection` (2344-2563), in particular 2354, 2364 and 2401; `diagnose/causes.rs` (the retrans cause); `ml/schema.json`.
- **Change.**
  - `Bufferbloat` needs `Some(rtt)` with `rtt >= t.socket_rtt_ms`.
  - `RetransBurst` keeps `retrans >= 5` and requires `rtt.is_none_or(|r| r < t.socket_rtt_ms)`. The retransmit count is measured; only the exclusion input is unknown.
  - The retrans cause gains `socket_rtt_below_queueing_line`, `not_run(NotMeasured)` when RTT is `None`.
  - The Bufferbloat arm reads `s.rtt_ms?`, so no invented 0 reaches evidence or detail.
  - Regenerate `ml/schema.json`. The ratio rule and dropping the 100 ms exclusion are B21.
- **Tests.** Detector `a_socket_without_rtt_is_never_bufferbloat` and `retransmits_without_rtt_say_the_rtt_was_not_measured`. C04's socket row leaves the expected list.
- **Acceptance.** A `SocketObs` with `rtt_ms: None` never yields `tcp.bufferbloat_remote` and never carries `tcp.socket_rtt` evidence of 0.
- **Depends on.** A01.
- **Size.** S. **Owner review.** 0.2 h. **Risk.** Low.

### P04 · `diagnose/033-lab-driver`

#### D33-C05 · A headless lab driver runs the real `App::tick`
- **Why.** Report §"Tests that make the 0.33 exit reachable". The fault lab runs `examples/diagnose_probe.rs` (`tests/diagnose/fault_lab.py:8`), which calls only `active::run` and `kernel::Collector`. `diagnose run` cannot stand in: its loop (`diagnose/run.rs:166-209`) does not learn baselines or start periodic traces, and it prints only open issues (`diagnose/run.rs:212`), so it cannot show a close.
- **Files.** New `examples/diagnose_lab.rs` and `diagnose/lab.rs` (`snapshot`). It uses `App::prepare_with_config` (`app.rs:710`), `runtime::bootstrap::{start, prime_collectors}` (`runtime/bootstrap.rs:21, 57`), `App::tick` (`app.rs:1840`), `App::shutdown_diagnose` (`app.rs:1028`) and `BaselineStore::seed` (`diagnose/baseline.rs:482`).
- **Change.** `diagnose_lab --seconds N [--seed FILE] [--jsonl]`.
  - It refuses to start unless `HOME`, `XDG_CACHE_HOME` and `XDG_CONFIG_HOME` point inside a temp directory the lab created. Otherwise seeded baselines would land in the real `dirs::cache_dir()/netwatch/baselines.json` (`diagnose/baseline.rs:559-563`).
  - It builds the App from that config with a Daemon session and calls `app.tick()` once a second.
  - After the first tick that knows the gateway and resolver, it seeds `gateway.rtt`@gateway, `dns.rtt_p50`@resolver and `path.rtt`@`internet`.
  - Each tick prints one JSON line: time, verdict chip and line, every tracked issue as `{key, rule, state, severity, suppressed_by, top_cause, confidence}`, and the coverage rows of the core rules.
  - On exit it calls `shutdown_diagnose()` so the recorder writes the episode.
- **Tests.** Unit `lab_snapshot_lists_closed_issues_with_their_state`; `lab_refuses_the_real_home`; `cargo build --examples` in CI.
- **Acceptance.** Inside C06's lab the JSONL shows gateway and DNS results within 10 s, and a run that opened an issue leaves an episode file under the temp directory only.
- **Depends on.** Nothing.
- **Size.** M (1 day). **Owner review.** 0.4 h. **Risk.** `App::tick` also runs capture, egress and incident collectors. If one fails in a user namespace, turn it off in the lab config rather than giving the driver its own code path.

#### D33-C06 · Lab topology with a peer namespace owning 1.1.1.1
- **Why.** Report §"Tests that make the 0.33 exit reachable": a peer netns owning 1.1.1.1, a bind-mounted `resolv.conf`, an unshared mount namespace and remounted sysfs. Measured on Fedora 44, `/sys/class/net` inside a user namespace otherwise lists the host's interfaces. The prober's targets are fixed: the internet probe and the DNS reference are both 1.1.1.1 (`collectors/health.rs:176, 192`), and the resolver comes from `/etc/resolv.conf` (`collectors/config.rs:116-129`).
- **Files.** New `tests/diagnose/health_lab.py` (`fault_lab.py` unchanged); `.github/workflows/ci.yml:101-125`.
- **Change.** Run as `unshare --user --map-root-user --net --mount python3 tests/diagnose/health_lab.py`.
  - First commit: a CI step that only checks `unshare --user --map-root-user --net --mount` plus `mount -t sysfs sysfs /sys` on `ubuntu-latest`. If the runner refuses, the fallback is `sudo unshare` in CI only.
  - Isolation: the user-namespace guard from `tests/diagnose/fault_lab.py:9-11`, then remount sysfs and assert `/sys/class/net` holds only `lo` and `nw0`. Create the temp home C05 requires.
  - Resolver: bind a temp `resolv.conf` (`nameserver 192.0.2.2`) over `realpath(/etc/resolv.conf)` and read it back.
  - Topology: host `nw0` 192.0.2.1/24 with a default route via 192.0.2.2; namespace `gw` with 192.0.2.2/24 and 198.51.100.1/30 and forwarding on; namespace `inet` with 198.51.100.2/30 and 1.1.1.1/32 on `lo`.
  - Sysctls: `icmp_ratelimit=0` in `gw` and `inet`; host `ping_group_range="0 2147483647"` so the unprivileged ICMP path runs.
  - Services: Python DNS responders at 192.0.2.2:53 and 1.1.1.1:53 answering `.` NS and `dns.google` A, with a mode file (`ok`, `delay:<ms>`, `drop:<pct>`, `servfail`); a TCP 443 listener on 1.1.1.1.
  - Config: `diagnose_record_episodes = true`, `insights_enabled = false`, `[diagnose_probes] trace_target = "1.1.1.1"`, `trace_refresh_secs = 30`.
- **Tests.** `health_lab.py --smoke`: 60 s healthy, gateway and DNS RTT measured, no issue opened.
- **Acceptance.** The smoke run passes on the Fedora host and on `ubuntu-latest`, and the JSONL shows `gateway_target` and `dns_target` 192.0.2.2.
- **Depends on.** C05.
- **Size.** M (2 days). **Owner review.** 0.6 h. **Risk.** Medium. The mount plus sysfs remount in a user namespace was measured only on Fedora 44; the first commit answers that for CI before anything else is built on it.

### P05 · `diagnose/033-abstain-iface`

#### D33-A04 · An idle radio reports no retry share, not 0%
- **Why.** Report §"Today's rules misread the network": "an idle Wi-Fi link read as 0% retries". `diagnose/live.rs:417-419` returns 0.0 when no frames were sent.
- **Files.** `LiveSampler::iface` (`diagnose/live.rs:378-450`, retry share at 411-422); `diagnose/detectors.rs:1206-1298`; `diagnose/coverage.rs:220`.
- **Change.** Add `const WIFI_MIN_FRAMES: u64 = 1_000` over the existing 60 s window and a pure `retry_share(d_retries, d_packets) -> Option<f64>` that returns `None` below it. `observe()` still runs every tick so the window keeps filling. The metric stays named as it is; relabelling it `tx_failed` belongs to D34-07.
- **Tests.** Unit `an_idle_radio_has_no_retry_share`, `a_busy_radio_reports_its_share`. C04's idle-radio row leaves the expected list.
- **Acceptance.** Under 1,000 frames a minute no `wifi.tx_retry_pct` evidence appears. With signal also absent, `wifi.weak_signal` coverage reads "wireless signal/retries not measured".
- **Depends on.** Nothing.
- **Size.** S. **Owner review.** 0.1 h. **Risk.** Low. D34-07 reuses `retry_share`.

#### D33-A05 · Missing interface info is unknown, not "carrier up, wired"
- **Why.** Report five sites: `info.map(|i| i.is_up).unwrap_or(true)` at `diagnose/live.rs:426`. A sixth site has the same pattern: `diagnose/live.rs:408` reads missing info as `wireless = false`, so `diagnose/coverage.rs:219` says "not wireless" (NotApplicable) about an interface it knows nothing about.
- **Files.** `IfaceObs` (`diagnose/detectors.rs:221-245`); `diagnose/live.rs:408, 426, 437`; `detect_link` (`diagnose/detectors.rs:1093, 1206`); `metric_values` (`diagnose/engine.rs:1312-1316`); `diagnose/coverage.rs:217, 219-220`; `diagnose/features.rs:188-189`; literals at `diagnose/fixture.rs:110, 118`, `diagnose/detectors.rs:2800-2815` and `3606-3616`.
- **Change.** `carrier` and `wireless` become `Option<bool>`; serde reads old recordings' booleans as `Some`. `link.down` fires only on `Some(false)`. The Wi-Fi block runs only on `Some(true)`. `iface.carrier` enters `metric_values` only when known. Coverage: `link.down` is present only when carrier is known; `wifi.weak_signal` is NotApplicable only for `Some(false)` and NotMeasured for `None`. `link_rate_bps` is skipped only when `wireless == Some(true)`.
- **Tests.** Detector `missing_interface_info_opens_no_link_issue`; coverage `unknown_wireless_is_not_measured_not_not_applicable`; serde `iface_obs_from_older_recordings_still_loads`. C04 gains the `carrier` and missing-info rows.
- **Acceptance.** With `interface_info` empty in a fixture, no `link.down` opens and its coverage reads NotMeasured. The corpus replays unchanged.
- **Depends on.** Nothing.
- **Size.** S. **Owner review.** 0.15 h. **Risk.** Low. It changes the feature flags `iface.carrier` and `iface.wireless` from false to absent when unknown; the schema hash does not change because names do not.

#### D33-A06 · macOS interface drops are "not counted", not 0
- **Why.** Report five sites: `rx_drops: 0, tx_drops: 0` at `platform/macos.rs:46-47`. `netstat -ibn` has no drop column, so "no drops" reads as a measurement.
- **Files.** `platform/mod.rs` (new const); `IfaceObs.drops_per_min` (`diagnose/detectors.rs:235`); `diagnose/live.rs:400, 433`; the `iface.errors` block (`diagnose/detectors.rs:1137-1204`); `diagnose/engine.rs:1317-1320`; `diagnose/features.rs:194`; `diagnose/coverage.rs:217`.
- **Change.** Add `pub const IFACE_DROPS_COUNTED: bool = !cfg!(target_os = "macos")`, which avoids touching `InterfaceTraffic` literals in files PCAPNG edits. `drops_per_min` becomes `Option<u64>`, `None` when the const is false. `iface.errors` judges the drop leg only when `Some`. `ring_buffer_small` and `drops_dominate` become `not_run(Unsupported)` without drops. `iface.error_rate` sums errors plus drops where drops are counted, at open and at verify, so both judge one statistic. The coverage reason adds "drops not counted on macOS". `netstat -ibnd` output drops are noted as future work.
- **Tests.** Detector `without_drop_counters_iface_errors_judges_errors_only`, `ring_buffer_cause_is_not_run_without_drop_counters`. C04 gains the `drops_per_min` row.
- **Acceptance.** A macOS recording carries `"drops_per_min": null`, and `local_udp_path`'s `interface_drops` check reads `why_not: unsupported` there.
- **Depends on.** A01, A02.
- **Size.** S. **Owner review.** 0.15 h. **Risk.** The dashboard, Dense view and `--metrics` still show 0 drops on macOS; this item fixes Diagnose only.

### P06 · `diagnose/033-lab-scenarios`

#### D33-C07 · Lab scenarios drive the engine end to end, in CI
- **Why.** REVIEW §2 exit clause 1: the fault lab drives the engine for at least DNS slow and failing, gateway loss and path spike. Decision D2 reads "gateway loss" as total loss until `gateway.loss` exists.
- **Files.** The scenario table in `tests/diagnose/health_lab.py`; `.github/workflows/health-lab.yml` (build `--example diagnose_lab`, run `--quick` or `--long`, upload `health-lab.json` and the recorded episodes), which a `.github/workflows/ci.yml` job calls for `--quick` on every push to `main` and on PRs touching the D6 paths, so the release guard's wait on `ci.yml` covers it; `health-lab.yml` runs the long negatives weekly by itself.
- **Change.** Rows hold `{name, fault, clear, expect_open, open_within_s, expect_close, close_within_s, forbid}`. Each scenario runs in its own `unshare` process; scenarios run in parallel. Every window is at least twice the expected time. The expected times below come from today's rules: the DNS p50 is a rolling median over the whole probe history (`diagnose/live.rs:629, 673`), so a slow phase must outnumber the healthy samples before it opens, and the close waits for healthy samples to outnumber the slow ones again.

  | Scenario | Fault | Asserted |
  |---|---|---|
  | L-DNS-SLOW | seeded baselines, 15 s healthy, then gateway DNS `delay:300` for exactly 60 s, then `ok` | `dns.slow_resolver` opens within 60 s of the fault (expected about 30 s); closes within 220 s of `ok` (expected about 110 s: 50 s for the median to return, 60 s hold) |
  | L-DNS-DOWN | `drop:100` for 60 s | `dns.failing` opens within 30 s; closes within 180 s |
  | L-DNS-LOSSY | `drop:20` for 180 s | Reported, not asserted, until B15. After B15: opens within 120 s. A 60 s bound would fail about 40% of runs, because B15 needs 7 failures of 60 and 36 faulted queries give that only about 60% of the time |
  | L-GW-DOWN | netem loss 100% on `nw0` | `gateway.unreachable` opens within 30 s with the `dns.*` findings as `suppressed_by`; closes within 120 s |
  | L-GW-RTT | netem 40 ms on ICMP only, `gw` to host | `gateway.rtt_spike` opens and `path.rtt_spike` is suppressed; closes |
  | L-PATH-SPIKE | netem 80 ms on `gw`'s WAN side | `path.rtt_spike` opens against the seeded `internet` baseline; closes within 2 trace intervals plus the hold, doubled |
  | L-HEALTHY | 5 min at netem 1 ± 0.3 ms | nothing opens |
  | L-DNS-QUIET-LOSS | scheduled only: 20 min at `drop:1` | `dns.failing` never opens |

- **Tests.** The rows are the tests.
- **Acceptance.** CI runs `--quick` (every row but L-DNS-QUIET-LOSS) in 8 min or less and fails on any assertion. `health-lab.json` lists open and close times per scenario.
- **Depends on.** C05, C06.
- **Size.** M (1.5 days). **Owner review.** 0.75 h. **Risk.** Timing flake from the 5 s cadence and 3-sample confirmation. Expectations live as data, so B-items change a row, not code.

### P07 · `diagnose/033-honesty`

#### D33-B16 · The remediation text stops promising a write
- **Why.** Report §"Today's rules misread the network": the live `↵` writes nothing and records "not applied" (`app.rs:5465-5474`), while the step text promises "writes resolv.conf, keeps a backup, and puts it back on quit" (`diagnose/detectors.rs:1936-1941`). REVIEW §2.4: propose a resolver only after measuring it.
- **Files.** `dns_remediation` (`diagnose/detectors.rs:1933-1964`).
- **Change.** Offer the switch step only when `alt_rtt_ms` is measured and under p50/4. Live, that never happens until A11 keeps the reference RTT. The step stays `Apply` because the demo simulates it (`diagnose/demo.rs:117-130`; the fixture's alternate answers in 1.4 ms, `diagnose/fixture.rs:148`). New detail: "netwatch does not change resolvers from this screen; run: sudo netwatch resolver set <alt> --unmanaged (unmanaged resolv.conf only), or resolvectl dns <iface> <alt>", plus the measured RTT.
- **Tests.** `no_step_text_promises_a_write` (scans detector step text for "writes", "backup" and "puts it back"); `no_switch_step_without_a_measured_alternate`. `every_apply_step_is_reversible_and_declares_its_privilege` (`diagnose/detectors.rs:3651`) still passes.
- **Acceptance.** No live step claims a write; the demo still offers and simulates the switch.
- **Depends on.** Nothing.
- **Size.** S. **Owner review.** 0.15 h. **Risk.** Low.

#### D33-C19a · Live mode never offers `↵`
- **Why.** Report tab table, "Honest apply". Outside the demo, `stage_remediation` skips the prompt and applies at once (`app.rs:5403-5406`), and the live branch always records `Applied::No` (`app.rs:5465-5474`). The footer still offers "↵ apply fix".
- **Files.** `has_applicable_step` (`ui/diagnose.rs:589-600`); `footer_hints` (`ui/diagnose.rs:535-573`); `stage_remediation` (`app.rs:5385-5425`).
- **Change.** `has_applicable_step` also requires demo mode. In live mode Enter shows "netwatch won't change this from here; run the command shown" and records nothing. The full version (per-action `cli_equivalent`, `ApplyMode`, always prompting) is C19b in 2027.
- **Tests.** `live_mode_offers_no_enter`, `enter_in_live_mode_records_nothing` (`step.applied` stays `None`). Update `a_privileged_run_offers_the_key_bound_fix` (`ui/diagnose.rs:1846`) to run in demo mode.
- **Acceptance.** Running as root with `dns.slow_resolver` open, the footer has no `↵` and Enter writes nothing.
- **Depends on.** Nothing.
- **Size.** S. **Owner review.** 0.1 h. **Risk.** Low.

#### D33-X03 · Incomplete never draws green
- **Why.** Report §"The tab should earn its green". `Engine::verdict()` never returns `Clear` (`diagnose/engine.rs:1037-1081`), yet `Incomplete` draws a green ● on the tab (`ui/diagnose.rs:670-674`) and in the header on every tab (`ui/widgets.rs:580-585`), against the module's own rule (`ui/diagnose.rs:8-10`). `y` copies `Verdict::line()` (`app.rs:5375-5378`), which says something different from the screen. C14 is the full fix; this removes the false green now.
- **Files.** `ui/diagnose.rs:670-674`; `ui/widgets.rs:580-585`; `diagnose_summary` (`app.rs:5375-5378`).
- **Change.** Incomplete renders `◌ no issues found · …` in `text_muted`; the header shows a muted `◌ no issues`. `y` copies the words on screen. The Clear arm is unchanged, since the engine never returns it.
- **Tests.** `incomplete_never_draws_status_good_in_the_verdict_row`, `the_header_never_draws_incomplete_green` (TestBackend cell colours), `y_copies_the_words_on_screen`.
- **Acceptance.** No green cell in the verdict row or header on the Fedora host.
- **Depends on.** Nothing.
- **Size.** S. **Owner review.** 0.1 h. **Risk.** Nothing is green until C14, which matches `ui/diagnose.rs:8-10`.

#### D33-X04 · Say that the DNS probe measures the local stub
- **Why.** Report §"Abstain first": if the zone is not decided by early October, keep root NS and the 100 ms ceiling and say what the probe measures. On a systemd-resolved host it probes 127.0.0.53 (`collectors/config.rs:19-25, 116-129`), which answers root NS in 0 ms.
- **Files.** The evidence at `diagnose/detectors.rs:1755`; the scope note at `diagnose/detectors.rs:1919-1928`; `diagnose/coverage.rs:223`.
- **Change.** For a loopback resolver, the evidence detail and the scope note say "the probe asks root NS; the local stub at <addr> answers from cache, so this is the stub's round trip". Coverage stays Available, because the stub RTT is measured, and its reason reads "limited: measures the local stub, not the upstream". The checks that need the upstream stay `not_run(NotMeasured, "the upstream behind the stub is not identified")`. Earned green (C14) takes this rule out of the core set on a loopback resolver (decision M5). No threshold changes.
- **Tests.** `a_loopback_resolver_says_it_measures_the_stub`.
- **Acceptance.** `diagnose run --format json` on the Fedora host names 127.0.0.53 as a stub in the DNS evidence and coverage reason.
- **Depends on.** Nothing.
- **Size.** S. **Owner review.** 0.05 h. **Risk.** Low.

#### D33-X05 · `diagnose run` counts a gateway probe as evidence only when it measured
- **Why.** REVIEW §2.1: "count gateway evidence only when loss is measured". `collectors/health.rs:304` sets `completed.gateway` after every cycle, including one whose loss is `Unmeasured` ("icmp is blocked here and the gateway answers no tcp port", `collectors/health.rs:436`). `diagnose/run.rs:196` treats `completed.health.gateway.is_some()` as evidence, so such a host gets `NoFinding`, exit 0 and "the rules that could be evaluated were".
- **Files.** `diagnose/run.rs:192-197`; `gateway()` (`diagnose/live.rs:568-612`), unchanged.
- **Change.** Evidence is `observations.gateway.is_some() || observations.dns.is_some() || !observations.targets.is_empty()` without `--target`. `gateway()` already returns `None` until a measured cycle exists and when the latest loss is unmeasured (`diagnose/live.rs:579-585`).
- **Tests.** `an_unmeasured_gateway_is_not_evidence` (run outcome is `Incomplete`); `a_measured_gateway_is_evidence`.
- **Acceptance.** In the lab, with the gateway answering neither ICMP nor TCP and an empty bind-mounted `resolv.conf`, `diagnose run` exits 2 (incomplete) and says nothing was concluded. At `df1dfba` the same run exits 0.
- **Depends on.** Nothing.
- **Size.** S. **Owner review.** 0.1 h. **Risk.** Low.

#### D33-X02 · Delete the unused remediation helpers
- **Why.** REVIEW §2.4 third bullet. `apply_file_edit` (`diagnose/remediation.rs:317`) and `make_permanent` (`diagnose/remediation.rs:392`) have no callers outside the tests module, which starts at 582. The bullet's other half, write-temp-then-rename for the resolver CLI, contradicts the adapter's design: writes go through the opened fd and preserve the inode (`docs/resolver-adapter.md:72-75`), `verify` compares `(dev, ino)` (`diagnose/remediation/resolver/linux.rs:220`), recovery refuses an identity change (`diagnose/remediation/resolver/linux.rs:313-318`), and `replacement_inode_and_changed_backup_block_rollback` (592) and `partial_write_is_recovery_required_and_never_speculatively_reverted` (613) pin that behaviour. A killed write already leaves a recovery-required journal entry that blocks new operations (259).
- **Files.** `apply_file_edit` (`diagnose/remediation.rs:317`) and `make_permanent` (`diagnose/remediation.rs:392`), and the tests in the module at 582 that call them.
- **Change.** Delete both helpers and their tests. Keep the resolver CLI's in-place write. Record decision X02 in `docs/resolver-adapter.md`.
- **Tests.** `cargo test` count falls by the deleted tests only.
- **Acceptance.** `git grep -n 'apply_file_edit\|make_permanent' src` prints nothing.
- **Depends on.** Decision X02.
- **Size.** S. **Owner review.** 0.05 h. **Risk.** Low.

#### D33-X06 · An issue link in the README
- **Why.** Plan §7 adds "An issue link in the README" to 0.33.
- **Files.** `README.md` (after A00 has committed or dropped the 20 Sep edit).
- **Change.** One line under the docs table: how to report a misread, linking the new-issue page and asking for `netwatch diagnose run --format json` output.
- **Tests.** None.
- **Acceptance.** The link resolves.
- **Depends on.** A00.
- **Size.** S. **Owner review.** 0.05 h. **Risk.** Low.

---

## 5. 0.34, Tue 24 Nov, and its split-off 0.35, Tue 15 Dec

### 5.1 0.34

Scope: the rest of REVIEW §2 that the review line can hold. That is the Observation kind and the exit code, expiry, the σ and delta floors, a DNS verify that can close, the mute fix, the controller split, and open→close episodes for every rule touched (exit clause 2). Fifteen PRs, about 14 agent-days, 6.7 owner hours. Still no new rule ids, because the beta marker lands in 0.35.

| PR | Branch | Items | Lane | Review h | Owner reviews |
|---|---|---|---|---|---|
| P08 | `diagnose/034-controller` | X01 | A | 0.25 | Fri 23 Oct |
| P09 | `diagnose/034-thresholds-config` | B01 | A | 0.25 | Mon 26 Oct |
| P10 | `diagnose/034-observation-kind` | B05 | A | 0.5 | Wed 28 Oct |
| P11 | `diagnose/034-corpus-manifest` | C02, C08 | W | 0.5 | Thu 29 Oct |
| P12 | `diagnose/034-catalogue-texts` | B33a | W | 0.2 | Fri 30 Oct |
| P13 | `diagnose/034-exit-code` | B06, B07 | A | 0.5 | Mon 2 Nov |
| P14 | `diagnose/034-verify-and-config` | B03, B04 | A | 0.35 | Wed 4 Nov |
| P15 | `diagnose/034-sigma-floor` | B09 | W | 0.55 | Thu 5 Nov |
| P16 | `diagnose/034-expired` | B24 | A | 0.3 | Mon 9 Nov |
| P17 | `diagnose/034-delta-floor-deadband` | B10, B11 | W | 0.45 | Tue 10 Nov |
| P18 | `diagnose/034-expiry-guard` | B25 | A | 0.95 | Thu 12 Nov |
| P19 | `diagnose/034-dns-verify` | B13 | W | 0.4 | Mon 16 Nov |
| P20 | `diagnose/034-mute` | C16 | A | 0.5 | Tue 17 Nov |
| P21 | `diagnose/034-episodes-net` | C09 (subset), C11 | W | 0.5 | Wed 18 Nov |
| P22 | `diagnose/034-episodes-transport` | C10 (subset) | W | 0.5 | Thu 19 Nov |

Freeze is Fri 20 Nov. P21 and P22 carry exit clause 2 and are reviewed before it. P18 is the other PR near the hour: the expiry guard is the riskiest logic in the release, and the owner reviews its predicate table rather than the diff.

#### P08 · `diagnose/034-controller`

##### D33-X01 · Move the Diagnose controller out of `app.rs`
- **Why.** REVIEW §2.5 and plan §7 put this in 0.33. It lands the day after the 0.33 tag instead, because before the tag it would force rebases of P07 and B01. D34-09, D34-12 and D34-28 depend on it.
- **Files.** New `diagnose/controller.rs`. The code that moves, at `df1dfba` (0.32.4 shifts these; find them by name):
  - `DiagnoseState`: struct `app.rs:466-505`, impl `app.rs:507-573`, helpers `detect_capability` (`app.rs:578`) and `effective_uid` (`app.rs:592-602`).
  - The Diagnose methods of `impl App`, from `tick_diagnose` (`app.rs:874`) through `record_episode_tick` (`app.rs:1309`), ending before the `pktap_status` doc comment at `app.rs:1365`.
  - The free functions from `// ── Diagnose actions` (`app.rs:5363`) to the end of the file (5578): `selected_issue_id` 5365, `diagnose_summary` 5375, `stage_remediation` 5385, `apply_pending_remediation` 5428, `export_diagnose_report` 5482, `build_diagnose_report` 5518.
- **Change.** App keeps one field, `diagnose: DiagnoseController`. Bodies move verbatim; the call sites in `tick()` and `handle_main_key` stay where they are.
- **Tests.** No new tests. The `cargo test` count is unchanged.
- **Acceptance.** `app.rs` shrinks by at least 600 lines, and `git diff --color-moved=zebra` shows only moved blocks and call sites. None of PCAPNG's `app.rs` hunks (HEAD 614, 781, 1780-1890, 2245-2259, 3073, 3588, 3979-3996) falls inside a moved range, so X08's second rebase has offset-only conflicts there.
- **Depends on.** The 0.33 tag.
- **Size.** M. **Owner review.** 0.25 h, agent review first. **Risk.** Low.

#### P09 · `diagnose/034-thresholds-config`

##### D33-B01 · Load `Thresholds` from config
- **Why.** Report §"Close on evidence" last paragraph; REVIEW §2.3. The engine starts with defaults (`app.rs:512`), so no test exercises the threshold plumbing, and every later item adds fields to `Thresholds`.
- **Files.** `Thresholds` (`diagnose/detectors.rs:21-81`); `NetwatchConfig` (`config.rs:10-147`, next to `diagnose_probes` at 144-145); `DiagnoseState::new` (`app.rs:507-512`, in the controller after X01) and its caller (`app.rs:817`); `set_gate_sigma` (`app.rs:978`); `diagnose/run.rs:140-158`; `Episode.settings` (`diagnose/episode.rs:291`).
- **Change.** `#[serde(default)]` on `Thresholds`. Without it any new field breaks loading every recorded episode, because `Episode.settings` embeds `Thresholds`. Add a `[diagnose_thresholds]` section defaulting to `Thresholds::default()`. Add `Thresholds::validated() -> (Thresholds, Vec<String>)`, which resets invalid fields to defaults (σ k ≤ 0, `consecutive_n` = 0, percentages outside 0..=100, and later `sigma_close_k >= sigma_k`) and logs a warning. `DiagnoseState::new(&Thresholds)` builds the engine with `with_settings`.
- **Tests.** Config `diagnose_thresholds_parse_from_toml_and_default_when_absent`; detector `a_lowered_dns_ceiling_fires_where_the_default_does_not` (40 ms, no baseline, ceiling 30); episode `an_episode_recorded_before_new_threshold_fields_still_loads`; controller `the_engine_starts_with_configured_thresholds`.
- **Acceptance.** `dns_ceiling_ms = 30` in `config.toml` makes `diagnose run` report a 40 ms resolver; without the section, behaviour is unchanged; an invalid value logs a warning and uses the default; the corpus is unchanged.
- **Depends on.** X01.
- **Size.** S. **Owner review.** 0.25 h. **Risk.** Low.

#### P10 · `diagnose/034-observation-kind`

##### D33-B05 · The Observation kind
- **Why.** Report §"0.33 retunes": "Info becomes the Observation kind, issues keep Medium, High and Critical". Plan §4.3 `kind: observation | issue`. `Severity` has no Low (`diagnose/issue.rs:24-29`), so REVIEW's "floor default Low" cannot be built.
- **Files.** `diagnose/issue.rs:22-29`, `808-944`; `diagnose/engine.rs:302-313`, `1037-1081` (`verdict`, `visible` filter at 1039-1042); `apply_suppression` and `primary_issues` (`diagnose/rules.rs:682-755`); `diagnose/report.rs:81-93`.
- **Change.**
  - `enum Kind { Observation, Issue }`, derived through `Severity::kind()` and `Issue::kind()`, with Info as Observation. It is not stored, so kind and severity cannot disagree and recordings that say "info" still load.
  - `Engine::primary_issues()` and `primary_observations()`. `primary()` stays as it is because replay compares it (`diagnose/episode.rs:980`).
  - `verdict()` builds `Verdict::Issues` from issues only, excludes Observations from `visible`, and exposes `observation_count()`. This absorbs the engine half of C15.
  - An Observation never suppresses an Issue. Today an Info `path.changed` can hide a Medium `path.rtt_spike`.
  - The six Info-by-catalogue rules (`dns.truncation_retry`, `path.changed`, `tcp.zero_window`, `tcp.timewait_exhaustion`, `nat.symmetric`, `egress.drift`) and the three runtime demotions (`diagnose/detectors.rs:1014, 2467, 2520`) become Observations with no further code.
- **Tests.** Issue `info_is_an_observation_and_everything_else_an_issue`; rules `an_observation_never_hides_an_issue`, `the_six_info_rules_are_observations`; engine `observations_alone_do_not_make_the_verdict_say_issues`.
- **Acceptance.** With only a `path.changed` Observation open the verdict is not Issues; a Medium `path.rtt_spike` under an Info `path.changed` is primary; corpus decisions are unchanged (the fixture's `path.changed` is Medium).
- **Depends on.** B01 (merge order).
- **Size.** M. **Owner review.** 0.5 h. **Risk.** Until C14 and the First Look band render Observations, a host with only Observations shows the Incomplete line.

#### P11 · `diagnose/034-corpus-manifest`

##### D33-C02 · The corpus holds many episodes and pins why each span ended
- **Why.** Report §"Tests that make the 0.33 exit reachable"; REVIEW §2.2 wants open→close episodes per touched rule. The replay test loads one hard-coded file (`diagnose/episode.rs:1431`), `write_corpus` writes only the fixture (`diagnose/episode.rs:1118-1142`), and `IssueSpan` records when an issue left the primary list but not why (`diagnose/episode.rs:936-941`, set at 1007-1015), so an expiry, a suppression and a verified fix look the same.
- **Files.** `diagnose/episode.rs:936-941`, `963-1019` (`replay`), `1118-1142`, the `corpus` arm at 1150-1159, the test at 1431; new `tests/diagnose/corpus/manifest.toml`.
- **Change.** `IssueSpan.close_reason: Option<String>` (serde default, skipped when `None`): `"suppressed"` when the issue is still open with `suppressed_by` set, otherwise the state label. Manifest rows are `{id, kind = "synthetic" | "lab", rules, note}`. `write_corpus` rebuilds synthetic episodes; lab episodes keep their frames and re-derive decisions. The test iterates the manifest: synthetic entries must replay to their recording and match decisions; lab entries must match decisions. Add `netwatch diagnose corpus --only ID`.
- **Tests.** `every_corpus_entry_replays_to_its_pinned_decisions` (names the failing entry), `a_manifest_entry_without_files_fails`, `close_reason_distinguishes_suppression_from_close`.
- **Acceptance.** `cargo test` asserts once per manifest entry; decision files without `close_reason` still parse.
- **Depends on.** C01.
- **Size.** M. **Owner review.** 0.3 h. **Risk.** Low.

##### D33-C08 · A scenario builder for synthetic episodes
- **Why.** C02 needs many small episodes, and the only builder, `fixture::episode()` (`diagnose/fixture.rs:328-368`), is tied to one story.
- **Files.** `diagnose/fixture.rs`: a `Scenario` struct and `record(&Scenario) -> Episode`.
- **Change.** `Scenario { id, start, secs, baselines, obs: fn(u64) -> Observations, cadence, thresholds }`. `Cadence::live()` stamps interface and sockets every 1 s, health every 5 s and path every 30 s. A `phase(t, &[(0, Healthy), (120, Fault), (300, Clear)])` helper. `episode()` becomes `record(&Scenario::incident())`.
- **Tests.** `record_is_deterministic` (byte-identical gzip twice); `the_incident_episode_is_unchanged_by_the_refactor`.
- **Acceptance.** `fixture-scenario` decisions unchanged; a new scenario takes 40 lines or fewer.
- **Depends on.** C01, C02.
- **Size.** M. **Owner review.** 0.2 h. **Risk.** Low.

#### P12 · `diagnose/034-catalogue-texts`

##### D33-B33a · Two trigger texts and a guard
- **Why.** Report: 9 of 30 catalogue triggers misdescribe their detectors, and the drift test (`diagnose/rules.rs:834-849`) only compares the generated doc with the catalogue. Seven of the nine are rewritten by the items that change those detectors. Two have no such item.
- **Files.** `diagnose/rules.rs:136` (`gateway.unreachable`, "arp or icmp to the default gateway fails", while no ARP probe exists, `diagnose/rules.rs:161`) and `diagnose/rules.rs:168` (`link.down`); `docs/diagnostic-coverage.md`.
- **Change.** `gateway.unreachable`: "icmp and the tcp fallback to the default gateway both fail, and the internet probe fails too; arp is not probed". `link.down`: name the per-OS carrier source (Linux operstate and carrier, macOS `status:` line after A09, Windows "Media disconnected"). Add `catalogue_triggers_quote_the_default_thresholds`, which checks each number in a trigger against `Thresholds::default()` and allowlists the seven texts whose items have not landed; each of those items removes its row. Regenerate the coverage doc.
- **Tests.** The guard and the existing drift test.
- **Acceptance.** Both texts match the code; the allowlist names exactly the seven pending texts.
- **Depends on.** Nothing.
- **Size.** S. **Owner review.** 0.2 h. **Risk.** Low.

#### P13 · `diagnose/034-exit-code`

##### D33-B06 · Exit code on issues only; JSON schema 2
- **Why.** Report: "the exit-code floor becomes 'any issue'". `outcome()` exits 1 on any finding, Info included (`diagnose/run.rs:47-55`). Plan §4.3 shapes checks as `{state, why_not}`; shipping schema 2 without `state` would force a schema 3 when watch-finding lands.
- **Files.** `diagnose/run.rs:47-55`, `222-266`; `docs/DIAGNOSE.md:100-110`.
- **Change.** `Outcome::Finding` only when a selected finding has kind Issue. JSON `schema: 2`: `issues` holds issues only, a new `observations` array holds the rest, every entry carries `kind`, and checks carry `state` and `why_not` without `passed` (A01's wire struct stops writing it; loading still accepts it). Text output lists observations under their own heading. CHANGELOG carries a breaking-change note (decision S2).
- **Tests.** `observations_alone_exit_zero`, `one_issue_exits_one`, `json_separates_issues_from_observations`, `schema_2_checks_have_state_not_passed`.
- **Acceptance.** A host whose only finding is `nat.symmetric` exits 0 and lists it under observations.
- **Depends on.** B05, A01.
- **Size.** S. **Owner review.** 0.25 h. **Risk.** Scripts reading schema 1 lose Info findings from `issues`.

##### D33-B07 · `--target` keeps service-down as an Issue and keeps host-wide root causes
- **Why.** Report C12 exception: `diagnose run --target api` exits 0 on a 503, because `diagnose/detectors.rs:1006-1017` demotes the finding. REVIEW §2.1: `diagnose/run.rs:213-219` filters by subject label, so a `gateway.unreachable` that suppresses the target's finding is dropped and the run exits 0.
- **Files.** `diagnose/detectors.rs:1006-1017`; `diagnose/run.rs:212-220` and the `outcome` signature; the test `a_503_is_the_service_not_the_network` (`diagnose/detectors.rs:3963`).
- **Change.** The demotion note becomes "service, not network"; the finding stays an Observation in the TUI. In `run`, a `target.*` Observation about the named target counts as an Issue for the exit code. The selection keeps findings about the target, findings whose `consequences` include one, and Host, Iface or Resolver Issues whose scope matches the target's `via_iface` or `via_resolver`, or has none.
- **Tests.** `a_named_target_answering_503_exits_one`, `a_gateway_root_cause_survives_the_target_filter`; update the test at 3963.
- **Acceptance.** A 503 target makes `--target api` exit 1 with "service, not network"; the same run without `--target` exits 0.
- **Depends on.** B05, B06.
- **Size.** S. **Owner review.** 0.25 h. **Risk.** Low.

#### P14 · `diagnose/034-verify-and-config`

##### D33-B03 · The verify condition is the one set at open
- **Why.** Report row "`dns.slow_resolver` verify: one number fixed at open". `merge` overwrites `issue.verify` every tick (`diagnose/engine.rs:566`).
- **Files.** `merge` (`diagnose/engine.rs:527-580`).
- **Change.** On a merge into an open issue, keep `issue.verify`; take `d.verify` only when opening or reopening (536-556). Only `diagnose/detectors.rs:1918` sets a detector verify today, and it is constant, so nothing changes until B11 and B13.
- **Tests.** Engine `the_verify_condition_is_the_one_set_at_open`.
- **Acceptance.** Corpus unchanged.
- **Depends on.** B01.
- **Size.** S. **Owner review.** 0.1 h. **Risk.** An issue that moves from Observation to Issue keeps the verify it opened with; the doc comment says so.

##### D33-B04 · A configuration snapshot in `Observations`
- **Why.** The expiry guard (B25) must know that a socket closed, a target was removed or a resolver left the config, and replay must see the same.
- **Files.** `Observations` (`diagnose/detectors.rs:332-353`); `LiveSampler::sample` (`diagnose/live.rs:303-337`).
- **Change.** `config: Option<ObservedConfig>` (serde default) with `resolvers`, `targets: Vec<(name, revision)>`, `trace_target`, `trace_refresh_secs` and `interfaces`. `None` in an old recording means unknown, and B25 reads unknown as "never expire".
- **Tests.** Extend `observations_round_trip_through_json` (`diagnose/detectors.rs:3744`); live `the_sampler_records_the_configuration_it_ran_with`.
- **Acceptance.** New recordings carry the field; old ones load with `None`.
- **Depends on.** B01.
- **Size.** S. **Owner review.** 0.25 h. **Risk.** Episodes grow by a few hundred bytes a frame.

#### P15 · `diagnose/034-sigma-floor`

##### D33-B09 · σ floor, with the corpus re-recorded
- **Why.** Report threshold row "Baseline": σ floor `max(0.5 ms, 5% of mean)`. `sigma_above` returns `None` only when σ ≤ ε (`diagnose/baseline.rs:200-207`), so a near-flat baseline scores tiny moves as many σ. The report requires a corpus re-record after this lands, because it changes the learning gate (`diagnose/baseline.rs:411`), `Evidence::sigma_above` (`diagnose/issue.rs:174`) and the features (`diagnose/features.rs:263`).
- **Files.** `diagnose/baseline.rs:193-207`, `409-423` (gate at 411, clamp at 421); `diagnose/detectors.rs:940, 1441, 1452, 1747, 1757, 1993, 2017`; `diagnose/coverage.rs:200`; `add_sigma_metrics` (`diagnose/engine.rs:1206-1243`); `diagnose/features.rs:259-266`; `tests/diagnose/corpus/*`.
- **Change.** `Baseline::sigma_floored() = max(σ, sigma_floor_ms, sigma_floor_pct × |mean|)`, with both floors in `Thresholds`. Every baselined metric is in ms. `sigma_above`, the learning gate and clamp, the σ in evidence, coverage and features use the floored σ. `sigma()` stays raw for `ui/dashboard.rs` and `ui/packets.rs`. Re-record the corpus in this PR and list every changed span; this absorbs the σ half of the slice plans' C25.
- **Tests.** Baseline `a_flat_baseline_scores_against_the_floor_not_zero`, `the_floor_is_five_percent_of_a_large_mean`, `the_gate_uses_the_floored_sigma`; `a_sustained_slowdown_is_not_learned_away` (`diagnose/engine.rs:2386`) stays green.
- **Acceptance.** A 1.2 ms baseline with raw σ 0.05 scores 2.7 ms at 3σ, not 30σ. The PR lists each changed span with its cause.
- **Depends on.** B01.
- **Size.** S. **Owner review.** 0.55 h, including the decision diff. **Risk.** The Packets overlay shows raw σ while Diagnose evidence shows the floored σ until someone edits `ui/packets.rs`, which PCAPNG also edits.

#### P16 · `diagnose/034-expired`

##### D33-B24 · The Expired close state
- **Why.** Report §"Close on evidence, expire on absence": `auto_close_secs` (`diagnose/engine.rs:154`) is never read, and `AutoClosed` already means the verify held (`diagnose/engine.rs:728`), so "evidence gone" needs its own state.
- **Files.** `IssueState` (`diagnose/issue.rs:707-738`); `VerifyOutcome` (`diagnose/issue.rs:846-873`); `Settings` (`diagnose/engine.rs:150-167`); reopen logic (536-556); `decide_verifications` (917-986); `diagnose/report.rs:426-438`.
- **Change.** `IssueState::Expired { at, reason }`, a closed state. Rename `auto_close_secs` to `expire_after_secs` (serde alias), default 60: how long the subject must stay gone. An Expired condition that returns within the recurrence window reopens with `recurrence + 1`. A verification in progress resolves to a new `VerifyOutcome::NotMeasured` ("closed without a measurement"). The report prints "expired, evidence gone: <reason>".
- **Tests.** `expired_is_closed_and_not_a_recovery`, `a_step_before_expiry_is_not_credited`, `settings_with_auto_close_secs_still_load`.
- **Acceptance.** A done step followed by an expiry never shows "recovered".
- **Depends on.** Nothing.
- **Size.** S. **Owner review.** 0.3 h. **Risk.** Low.

#### P17 · `diagnose/034-delta-floor-deadband`

##### D33-B10 · Absolute delta floors for σ opens
- **Why.** Report: "The σ floor alone still fires on a 1.2 to 2.7 ms LAN resolver." DNS needs p50 at least 2× the baseline mean and 5 ms above it; the gateway needs 10 ms above.
- **Files.** `detect_gateway_rtt` (`diagnose/detectors.rs:1431-1446`); the DNS σ test (`diagnose/detectors.rs:1744-1753`).
- **Change.** `gateway.rtt_spike` needs floored σ ≥ k and `rtt − mean ≥ 10 ms`. The DNS σ path needs floored σ ≥ k, `p50 − mean ≥ 5 ms` and `p50 ≥ 2 × mean`. New fields `gateway_delta_floor_ms`, `dns_delta_floor_ms`, `dns_delta_multiple`. Record the effective open line for B13.
- **Tests.** `a_lan_resolver_moving_from_1_2_to_2_7ms_does_not_fire`, `a_lan_resolver_moving_from_1_2_to_7ms_fires`, `a_gateway_moving_2_to_9ms_does_not_fire_but_2_to_15ms_does`.
- **Acceptance.** The fixture's 40 ms against 1.2 ms still fires.
- **Depends on.** B09.
- **Size.** S. **Owner review.** 0.25 h. **Risk.** A LAN resolver slowing from 1 to 4 ms is never reported, on purpose.

##### D33-B11 · A deadband on σ closes
- **Why.** Report: open and close lines are equal, 3σ/3σ, on `gateway.rtt_spike` (`diagnose/rules.rs:768`), and the same holds for `path.rtt_spike` (775) and `target.slow_stage` (794), so a metric hovering at the line flaps.
- **Files.** `diagnose/rules.rs:768, 775, 794`; `diagnose/detectors.rs:1448-1490`, `2009-2070`, `952-1003`.
- **Change.** `Thresholds.sigma_close_k = 2.0`. The three detectors set their own verify below it, because `default_verify` cannot read `Thresholds`; B03 keeps it from open. The `default_verify` rows change to 2.0 so the generated doc matches the defaults. Validation rejects `sigma_close_k >= sigma_k`.
- **Tests.** Engine `a_gateway_rtt_hovering_at_three_sigma_does_not_flap` (alternating 2.9σ and 3.1σ: one issue, no close), `gateway_rtt_spike_closes_below_two_sigma`.
- **Acceptance.** Both pass; the PR re-records any changed spans.
- **Depends on.** B01, B03, B09.
- **Size.** S. **Owner review.** 0.2 h. **Risk.** Noisy links close more slowly.

#### P18 · `diagnose/034-expiry-guard`

##### D33-B25 · The expiry guard and "stale since"
- **Why.** Report: expire only when the collector is healthy and the subject is gone. The gateway probe returns Unmeasured when ICMP cannot be sent and no TCP port answers (`collectors/health.rs:431-437`); an expiry there would close a real outage.
- **Files.** `age_unseen` (`diagnose/engine.rs:618-736`); `Issue` (`diagnose/issue.rs:807-844`).
- **Change.** In `age_unseen`, `subject_gone(issue, obs, coverage, times)` decides per subject:

  | Subject | Gone when |
  |---|---|
  | Socket | the sockets collector is fresh (≤ 30 s), its coverage is Available or NoSubjects, and no socket matches |
  | Target | the name has left `obs.config`, or its revision changed |
  | Resolver | it has left `config.resolvers` |
  | Path | `trace_target` changed while periodic tracing is on |
  | Iface | it is missing from `config.interfaces` and the collector is fresh |
  | Host, anything else, or `config: None` | never |

  After `expire_after_secs` of gone, the issue is Expired. Otherwise, when coverage is not Available or the verify metric is missing, set `Issue.stale_since` once; clear it on a merge or when the metric returns.
- **Tests.** `a_closed_socket_expires_its_retrans_issue`, `an_unmeasured_gateway_never_expires_the_outage`, `a_removed_target_expires`, `a_stale_target_probe_is_stale_not_expired`, `stale_since_is_set_once_and_cleared_on_fresh_evidence`, `an_episode_without_config_never_expires`.
- **Acceptance.** Under `diagnose run`, and in the TUI's Dense view, a socket issue expires within 60 s of the socket closing. In the Full and Lite views the socket collector refreshes only in Dense (`app.rs:1956-1958`) and the sampler returns no sockets when stale (`diagnose/live.rs:511-515`), so there the issue shows "stale since" instead of expiring until D34-09 lands. A gateway outage with ICMP blocked stays open and shows "stale since".
- **Depends on.** B04, B24.
- **Size.** M. **Owner review.** 0.95 h; review the predicate table. **Risk.** High for its size. A predicate that calls a collector healthy when it is not closes a real fault; the unmeasured-gateway test pins the known case.

#### P19 · `diagnose/034-dns-verify`

##### D33-B13 · A relative DNS verify, fixed at open
- **Why.** Report row: verify below `max(mean + 2σ_floored, 0.8 × open line)` held 60 s. Today `p50 < 5 ms` (`diagnose/rules.rs:763`, `diagnose/detectors.rs:1918`), which a router answering in 10 to 11 ms never meets, so an issue opened there stays open until restart.
- **Files.** `diagnose/detectors.rs:1740-1772`, `1918`; `diagnose/rules.rs:763`.
- **Change.** The open line is the ceiling when the ceiling fired, else `max(mean + kσ_f, mean + 5, 2 × mean)`. The verify is `max(mean + 2σ_f, 0.8 × open line)`, kept from open by B03. The catalogue default becomes `0.8 × dns_ceiling_ms`, the no-baseline case. It judges today's rolling p50; B12 later changes the statistic and re-records.
- **Tests.** Detector `the_verify_line_sits_below_the_open_line`; engine `a_router_resolver_issue_can_close` (baseline 10.5 ms, 60 ms spike, back to 11 ms, closes after 60 s); `applying_the_fix_closes_the_issue_through_the_normal_verify_path` (`diagnose/demo.rs:185`) stays green.
- **Acceptance.** A slow-resolver issue against a 10 ms router closes.
- **Depends on.** B03, B10.
- **Size.** S. **Owner review.** 0.4 h. **Risk.** Low.

#### P20 · `diagnose/034-mute`

##### D33-C16 · Mute holds, expires, and is never drawn as fixed
- **Why.** Report tab table, "Muted is not fixed". Slice C measured a worse engine defect in a scratch build: a muted condition that continues files a second, identical open issue after `consecutive_n` samples, and the original reads "muted until 07:48:30" two hours later. `is_open_key` treats Muted as closed (`diagnose/engine.rs:482-487`), so `merge` reopens and files anew (536-555); nothing reads `until`; `age_unseen` skips Muted issues (627-630), so a muted issue can never verify-close.
- **Files.** `diagnose/issue.rs:709-737`; `diagnose/engine.rs:482-487`, `527-580`, `627-630`, `789-804`; `ui/diagnose.rs:980-1057` and `649-722`; the `m` handler (`app.rs:3622-3630`).
- **Change.** `IssueState::is_tracked()` (Open, Acked or Muted), used by `is_open_key` and `age_unseen`. `merge` keeps Muted while `until > now` and updates evidence silently, as the comment at `diagnose/engine.rs:558-559` intends. `observe_inner` returns an issue whose mute has ended to Open, derived from the clock so replay agrees. The UI draws a muted row as `◌` in the muted colour with "muted until 07:48"; the verdict gains "· 1 muted"; the status after `m` names the time.
- **Tests.** `a_muted_condition_stays_one_issue` (fails today), `a_mute_ends_at_its_time`, `a_muted_issue_still_closes_when_verify_holds`, `muted_is_never_drawn_green`; update `muted_issues_leave_the_verdict_line_but_stay_in_the_list` (`diagnose/engine.rs:2270`).
- **Acceptance.** The scratch reproduction yields one issue, and no muted row has a green cell.
- **Depends on.** B25 (both edit `age_unseen`).
- **Size.** S. **Owner review.** 0.5 h. **Risk.** Old recordings with `EngineEvent::Muted` (`diagnose/engine.rs:846`) may replay differently; lab corpus entries compare decisions only.

#### P21 · `diagnose/034-episodes-net`

##### D33-C09 (subset) · Open→close episodes for the network rules touched
- **Why.** REVIEW §2 exit clause 2. These rules have open, verify or close logic changed by 0.33 or 0.34.
- **Files.** Scenarios in `diagnose/fixture.rs`; `tests/diagnose/corpus/*` and manifest rows.
- **Change.** Episodes, each healthy → fault → clear:
  - `dns-slow-router`: 10 ms → 150 ms → 11 ms; closes under B13.
  - `gateway-rtt`: 1.0 ± 0.3 ms → 40 ms → 1.0 ms; closes under B11.
  - `gateway-rtt-edge`: holds at 3σ; one issue, no flapping.
  - `link-down`: carrier lost and restored; also the `carrier: None` variant that opens nothing.
  - `wifi-weak`: −78 dBm → −60 dBm.
  - `iface-errors-wifi-drops`: 70 drops/min background; pinned as never closing, with a `PENDING_CLOSE` entry, because it closes only below 1/min combined (`diagnose/rules.rs:770`) until B19.
- **Tests.** Manifest entries under `every_corpus_entry_replays_to_its_pinned_decisions`.
- **Acceptance.** Every episode has `opened` set, and `closed` set or a `PENDING_CLOSE` entry.
- **Depends on.** C08, B13, B11, A05.
- **Size.** M. **Owner review.** Shared with C11 below. **Risk.** Synthetic inputs encode assumptions; they use the notes' measured values (router 10 to 11 ms, healthy Wi-Fi −53 dBm).

##### D33-C11 · A gate: every touched rule has an open→close episode
- **Why.** Makes REVIEW §2 exit clause 2 a CI check.
- **Files.** `diagnose/episode.rs` `mod tests`.
- **Change.** `TOUCHED_SINCE_0_32: &[&str]`, one row per rule whose open condition or verify a PR in this plan changed, plus the three socket rules that B25 makes closable; each rule PR adds its row. B25's expiry on a removed target, resolver or interface applies to every rule with that subject and is covered by B25's engine tests, not by one episode per rule. `PENDING_CLOSE: &[(&str, &str)]`, a rule and the reason it cannot close yet. At the 0.34 tag it holds `iface.errors` (until B19).
- **Tests.** `every_touched_rule_has_an_open_close_episode`; `pending_close_entries_are_still_needed`, which fails once a pending rule starts closing so its row must go.
- **Acceptance.** Exit clause 2 is met when every touched rule has an episode and each `PENDING_CLOSE` row was accepted by the owner in its PR.
- **Depends on.** C09, C10.
- **Size.** S. **Owner review.** 0.5 h for C09 and C11 together. **Risk.** Low.

#### P22 · `diagnose/034-episodes-transport`

##### D33-C10 (subset) · Open→close episodes for the transport, path and target rules touched
- **Why.** B25 changes when every socket rule closes, and B11 changes the `path.rtt_spike` and `target.slow_stage` verifies (`diagnose/rules.rs:775, 794`). Without these episodes, the C11 gate cannot pass in 0.34.
- **Files.** As C09.
- **Change.** Episodes:
  - `retrans-socket-closes`, `bufferbloat-remote-socket-closes`, `zero-window-socket-closes`: the socket goes away and the issue ends Expired within 60 s.
  - `path-rtt-spike`: synthetic 30 s traces, 80 ms spike against the `internet` baseline, closes under the 2σ verify.
  - `target-slow-stage`: σ open on first byte, closes under the 2σ verify.
- **Tests.** Manifest entries.
- **Acceptance.** As C09.
- **Depends on.** C08, B25, B11.
- **Size.** M. **Owner review.** 0.5 h. **Risk.** As C09. The rest of C10 (`retrans-high-rtt`, `receiver-limited-flips`, `path-reroute-persistent` and others) comes with the items that change those rules.

### 5.2 0.35: First Look beta

M3's default gives the December release to First Look rather than to REVIEW §3. Linux is the reference platform; macOS gets the same facts where its readers exist, and Windows waits for IP Helper. It adds no default network traffic: every fact reuses a probe or a local read that already exists.

What the facts show on 15 Dec:

| Fact | Linux | macOS | Windows |
|---|---|---|---|
| Gateway RTT and jitter | value, per-probe jitter | value, per-probe jitter | value; jitter reads "variation between 5 s samples" until `IcmpSendEcho2` |
| Resolver identity | stub plus upstream from `resolvectl` | from `scutil --dns` | configured resolver only, "upstream not identified on Windows yet" |
| Top talkers | top 3 with capture, else the exact `setcap` line | with capture, else the fix | with Npcap, else the fix |
| Path MTU | interface MTU of the default-route interface, labelled "interface MTU, not a measured path MTU" | same | "not measured on Windows yet": `default_route_interface` spawns PowerShell (`platform/windows.rs:295`) |
| IPv6 | "no IPv6 address" or "OS has IPv6; press t to test reachability", from D34-04's address flags | Unsupported, with the reason (A10) | Unsupported (A10) |
| CGNAT | "not measured: needs a 3-hop trace, which is not built yet" (D34-15, Q2 2027) | same | same |

That is three complete facts, path MTU from the interface only, IPv6 awaiting a test, and CGNAT not measured. Plan §7.1's 60-second promise holds for the first four rows. IPv6 meets it only after D34-12 runs the experiment on network change (§6).

| PR | Branch | Items | Lane | Review h | Owner reviews |
|---|---|---|---|---|---|
| P23 | `diagnose/035-beta-marker` | D34-17 | A | 0.5 | Wed 25 Nov |
| P24 | `diagnose/035-address-list` | D34-04 | W | 0.25 | Wed 25 Nov |
| P25 | `diagnose/035-probe-cycles` | D34-01 | A | 0.75 | Fri 27 Nov |
| P26 | `diagnose/035-resolver-identity` | D34-21 | W | 0.25 | Mon 30 Nov |
| P27 | `diagnose/035-probe-windows` | D34-02 | A | 0.25 | Tue 1 Dec |
| P28 | `diagnose/035-ipv6-unsupported` | A10 | W | 0.25 | Tue 1 Dec |
| P29 | `diagnose/035-first-look-model` | D34-22, D34-23 | A | 1.0 | Thu 3 Dec |
| P30 | `diagnose/035-first-look-band` | D34-24 | A | 1.0 | Tue 8 Dec |

Freeze is Fri 11 Dec. P29 and P30 each take an hour: the model is where every First Look input meets, and the band is the screen the sessions test. The watch-finding 0.1 extraction (decision M6) follows the tag in the week of 14 Dec.

#### P23 · `diagnose/035-beta-marker`

##### D34-17 · Beta marker
- **Why.** Plan §6.9: a rule stays marked beta on screen until it shows 0 false positives across at least 5 scenarios, one from the field. Plan §4.3 has `beta: bool`. No such field exists (`diagnose/rules.rs:31-55`), so no new rule or Observation id can ship before this.
- **Files.** `Rule` (`diagnose/rules.rs:31-55`); `Issue` (`diagnose/issue.rs:808-844`); `render_issue_list` (`ui/diagnose.rs:1064`) and `render_detail` (`ui/diagnose.rs:1229`); `diagnose/run.rs:47-55`, `222-242`; `docs/diagnostic-coverage.md`.
- **Change.** `Rule.beta`, copied to `Issue.beta` (serde default) at open. A dim "beta" tag in the issue list, the detail pane and First Look rows. JSON carries `beta: true`. Beta issues set the exit code only with `--include-beta` (decision BETA-EXIT). The coverage doc gains a beta column that counts each beta rule's scenarios by source (lab, fixture, field) against §6.9's bar of 5 with 1 from the field; this is the ledger later rule PRs add to. No existing rule is marked (decision B-10).
- **Tests.** TestBackend `beta_issue_is_tagged`; run `beta_issue_does_not_set_exit_code`, `include_beta_counts_it`; regenerate the coverage doc.
- **Acceptance.** A test rule marked beta shows "beta" in the TUI and JSON.
- **Depends on.** B05.
- **Size.** S. **Owner review.** 0.5 h. **Risk.** Low.

#### P24 · `diagnose/035-address-list`

##### D34-04 · Full address list with flags (Linux, macOS)
- **Why.** Report §"Twenty-eight candidates wait": `InterfaceInfo` holds one IPv4 and one IPv6 address (`platform/mod.rs:44-55`); Linux keeps the last `inet` and the first `inet6` (`get_ip_addresses`, `platform/linux.rs:224-253`), which may be link-local.
- **Files.** `platform/mod.rs:44-55`; `platform/linux.rs:140-196`, `224-253`; `parse_ifconfig_output` (`platform/macos.rs:74-121`).
- **Change.** `InterfaceInfo.addrs: Vec<AddrInfo { ip, prefix, scope, flags }>` with flags tentative, dadfailed, deprecated, temporary, dynamic, secondary, optimistic. Linux runs one `ip -o addr show` per refresh instead of one `ip addr show <iface>` per interface. macOS reads every `inet`/`inet6` line with prefix, `scopeid` and its flags. `ipv4` and `ipv6` keep today's selection exactly, because the fingerprint subnet (`diagnose/live.rs:172-196`) keys the baselines. Helpers `has_global_v6`, `is_local_addr`, `clat_v4`.
- **Tests.** Fixtures `ip_o_addr_multi_inet_dadfailed_tentative`, `ifconfig_duplicated_scopeid`, `legacy_primary_address_unchanged`.
- **Acceptance.** `baselines.json` keys are byte-identical before and after on the Fedora host.
- **Depends on.** Nothing.
- **Size.** M. **Owner review.** 0.25 h, agent review first (parser). **Risk.** Low; the key-stability test pins the fingerprint.

#### P25 · `diagnose/035-probe-cycles`

##### D34-01 · Per-probe RTT and per-cycle loss history
- **Why.** Report §"Twenty-eight candidates wait": gateway and internet history keep one averaged RTT per 5 s cycle and only the latest cycle's loss (`collectors/health.rs:297, 384`); ping RTTs are averaged away (`collectors/health.rs:1018-1022`). This blocks real jitter now and `gateway.loss` later.
- **Files.** `HealthStatus` (`collectors/health.rs:14-40`); `probe()` (`collectors/health.rs:262-396`), gateway block 282-307 and internet block 373-393; `run_gateway_probe` (422-438); `run_internet_probe` (445-467); `run_tcp_probe_port` (496-531); `run_ping_native` (906-1024); `run_ping_subprocess` (1050-1076); test helpers `make_health` at `collectors/insights.rs:552` and `collectors/incident.rs:727`.
- **Change.** `enum ProbeMethod { Icmp, Tcp { port } }` and `struct ProbeCycle { at, method, sent, received, rtts_ms: [Option<f32>; 3], icmp_before_fallback }`. `HealthStatus.gateway_cycles` and `internet_cycles: VecDeque<ProbeCycle>`, capped at `RTT_HISTORY_MAX` and cleared on target change like the RTT history. The averaged histories stay; the dashboard, Dense and Timeline read them. The ping paths return per-probe RTTs; the subprocess parser reads each reply's `time=`, including Windows `time<1ms`. A TCP fallback after 3/3 ICMP loss records method Tcp and keeps the ICMP counts. An unmeasured probe records no cycle. Add `impl Default for HealthStatus` and change both test helpers to `..HealthStatus::default()`, the only hunk in files PCAPNG edits.
- **Tests.** `ping_native_keeps_each_probe_rtt`; `ping_subprocess_per_reply_linux`, `_macos`, `_windows_lt1ms`; `tcp_fallback_cycle_keeps_icmp_counts`; `cycles_cap_and_clear_on_target_change`; `unmeasured_probe_records_no_cycle`.
- **Acceptance.** `cargo test` passes with dashboard, Dense and Timeline snapshots unchanged; a debug dump on the Fedora host shows three RTTs per gateway cycle.
- **Depends on.** Nothing. Windows per-probe RTT needs `IcmpSendEcho2` (REVIEW §3.1); until then Windows records counts only.
- **Size.** M. **Owner review.** 0.75 h. **Risk.** Medium. It is the hot path behind every health tile, which is why the averaged histories stay untouched.

#### P26 · `diagnose/035-resolver-identity`

##### D34-21 · Resolver identity
- **Why.** Report §"Thirteen new candidates are ready", `dns.resolver_identity` narrowed to identity. `primary_dns()` takes `resolv.conf` verbatim (`collectors/config.rs:19-25, 116-129`). `parse_resolvectl` (`diagnose/targets.rs:988-1039`) starts at the first `Link` line, so it misses the global section and the "Current DNS Server" line.
- **Files.** `diagnose/targets.rs:943-970` (`context_command`), `988-1039`; `collectors/config.rs:116-190` (`scutil` is read only when `resolv.conf` is empty).
- **Change.** `ResolverIdentity { configured, stub, current_upstream, upstreams, class, scope_id }` with class Lan, Isp, Public, Overlay or Stub. Linux parses Global and each link's current and listed servers; macOS reads `scutil --dns` for identity. Classes: RFC 1918, ULA or link-local is Lan, and "your router" when it equals the gateway; a fixed anycast list (1.1.1.1, 8.8.8.8, 9.9.9.9, 208.67.222.222 and their v6 forms) is Public; 100.100.100.100 or a name on the VPN prefix list is Overlay; anything else is Isp. Link-local resolvers keep their scope ID (#31). The DNS probe target does not change.
- **Tests.** Fixtures `resolvectl_fedora_stub_global_and_link`, `resolvectl_tailscale_magicdns`, `resolvectl_split_vpn`, `scutil_dns_scoped`, `link_local_resolver_keeps_scope`; a class-table test.
- **Acceptance.** The Fedora host shows "stub 127.0.0.53 → upstream 192.168.0.1 (your router, LAN)".
- **Depends on.** Nothing. D34-03 later refines Overlay by route.
- **Size.** M. **Owner review.** 0.25 h, agent review first (parser). **Risk.** Low.

#### P27 · `diagnose/035-probe-windows`

##### D34-02 · Windowed gateway and internet statistics in `GatewayObs`
- **Why.** Detectors see only `Observations`, so the loss window and the 60 s p50 are computed in `live.rs` and serialised for replay.
- **Files.** `gateway()` (`diagnose/live.rs:568-612`); `GatewayObs` (`diagnose/detectors.rs:303-325`); the fixture builder.
- **Change.** `window` and `internet_window: Option<ProbeWindow>` (serde default), where `ProbeWindow { method, probes, lost, secs, rtt_p50_60s_ms, jitter_ms, jitter_kind }`. Loss counts the last 300 s of same-method cycles; a window that mixes methods is `None`. Jitter is the mean absolute difference between consecutive per-probe RTTs; the fallback over cycle means is labelled "variation between 5 s samples".
- **Tests.** `loss_window_300s_same_method`, `mixed_methods_give_no_window`, `jitter_per_probe_vs_cycle_means`, `old_recording_without_window_replays`.
- **Acceptance.** Replaying the corpus gives identical decisions; the windows appear in `diagnose run --format json`.
- **Depends on.** D34-01, C01.
- **Size.** S. **Owner review.** 0.25 h. **Risk.** Low.

#### P28 · `diagnose/035-ipv6-unsupported`

##### D33-A10 · The IPv6 experiment is Unsupported off Linux
- **Why.** Report §"Abstain first": on macOS and Windows `ipv6_context()` returns `None` because it reads `/proc` (`diagnose/active.rs:292-311`); `run` maps that to `Outcome::Failed` (`diagnose/active.rs:325`), which shows as a red CollectorFailed row (`diagnose/active.rs:167`). The First Look IPv6 row would inherit it.
- **Files.** `Outcome` (`diagnose/active.rs:135-142`); `ResultObs::coverage` (162-170); `ipv6_context` (292-311); `run` (312-327); `Runner::start` (228); `coverage_hints` (`diagnose/live.rs:912-921`).
- **Change.** `Outcome::Unsupported`, mapped to Unsupported with "IPv6 route context is read only on Linux". Off Linux `run` returns it and `start("ipv6.broken")` refuses with the same text; `coverage_hints` sets it, so the row never says "press t". On Linux, a missing `/proc/net/if_inet6` (IPv6 off in the kernel) means NotApplicable and other read errors stay Failed, through a pure `context_from(io::Result<String>, io::Result<String>)`.
- **Tests.** `unsupported_outcome_maps_to_unsupported_coverage`; `#[cfg(not(target_os = "linux"))] ipv6_experiment_refuses_to_start_off_linux`; `missing_ipv6_proc_files_mean_not_applicable`; the four existing IPv6 fault-lab cases stay green.
- **Acceptance.** `diagnose coverage --json` on the macOS and Windows CI runners shows `ipv6.broken: unsupported`.
- **Depends on.** A01.
- **Size.** S. **Owner review.** 0.25 h. **Risk.** Low. D34-13 replaces it with a three-state fact on every OS.

#### P29 · `diagnose/035-first-look-model`

##### D34-22 · The First Look model and JSON
- **Why.** Plan §7.1; report §"Repairs in 0.33, First Look in 0.34". Each row reads "value · provenance · age" or "not measured because X · fix".
- **Files.** New `diagnose/first_look.rs`; `Observations` (`diagnose/detectors.rs:332-353`, adds `first_look: FirstLookInputs`, serde default); `LiveSampler::sample` (`diagnose/live.rs:303-337`); `diagnose/run.rs:222-242`; `BaselineStore::readiness` (`diagnose/baseline.rs:438`).
- **Change.** A pure `facts(obs, base, now) -> Vec<Fact>` with `Fact { id, label, value, provenance: GeneralReference | Learning { done, need } | NormalHere, age_secs, availability, why_not, fix, beta: true, how }`. The six rows are as in the table above. Path MTU is the MTU of the interface `platform::default_route_interface()` names (`platform/linux.rs:199`, `platform/macos.rs:174`), read on the 10 s interface-info cadence and labelled as the interface MTU. Gateway RTT has no reference band; ChromeOS's 1,500 ms appears only as a labelled outer reference. A fact is stale after twice its refresh interval. `diagnose run --format json` gains `first_look` entries with `kind: "observation"` and `beta: true`.
- **Tests.** A unit test per fact in each of its forms (value, learning, not measured) plus stale; `path_mtu_is_labelled_interface_mtu`; `first_look_replays_from_episode`; a run JSON schema test.
- **Acceptance.** `netwatch diagnose run --budget 60s --format json` on the Fedora host returns all six facts, each with a value or a `why_not`. The health lab asserts the same within 60 s.
- **Depends on.** D34-02, D34-04, D34-21, D34-17, B05, A01, A10.
- **Size.** M. **Owner review.** 0.7 h. **Risk.** Medium; all the inputs meet here.

##### D34-23 · The top talkers fact and one `setcap` line
- **Why.** Report §"Thirteen new candidates"; plan §7.1 on privileges; issues #11, #38 and #40 failed silently. The fix line must be exact, and today two versions exist (decision CAP).
- **Files.** `ProcessBandwidthCollector::ranked` (`collectors/process_bandwidth.rs:233`); `runtime/capabilities.rs:285-330`; `diagnose/first_look.rs`; `README.md:70`; `docs/REFERENCE.md:465`.
- **Change.** With capture running, show the top 3 processes by rx+tx rate; other users' sockets count as "unattributed". Without capture, show `why_not` and the per-OS fix from one constant, `capture_fix_line()`: Linux `sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' "$(which netwatch)"`, the line the docs already ship; macOS run with sudo or grant `/dev/bpf` access; Windows install Npcap. REVIEW §3.3's banner later uses the same constant.
- **Tests.** `capture_off_gives_setcap_line`, `top3_by_rate`, `unattributed_bucket`, `the_fix_line_matches_the_readme`.
- **Acceptance.** An unprivileged Linux run prints the exact line from `README.md`.
- **Depends on.** D34-22, decision CAP.
- **Size.** S. **Owner review.** 0.3 h. **Risk.** Low.

#### P30 · `diagnose/035-first-look-band`

##### D34-24 · The First Look band and strip
- **Why.** Report tab table, First Look band. Today the quiet page is one sentence (`render_nothing_open`, `ui/diagnose.rs:856-953`, text at 867).
- **Files.** `View` (`ui/diagnose.rs:25-58`); `ui/diagnose.rs:603-639`, `649-724`, `856-953`.
- **Change.** With no issues open, the band replaces "Nothing to report": one row per fact, a dim beta tag, no status colour on any row. With issues open, a one-line strip under the verdict, for example "gw 2.1 ms ±0.4 · dns 192.168.0.1 via stub · v6 press t · mtu 1500 (iface) · CGNAT not measured · top: firefox 3.1 MB/s"; facts the selected issue cites are bold.
- **Tests.** TestBackend snapshots `first_run_learning`, `healthy_values`, `unprivileged_setcap`, `issue_open_strip_dns_bold`, `narrow_80_cols`; an assertion that no fact row uses a status colour. Update `ui/diagnose.rs:1969`, which asserts "Nothing to report".
- **Acceptance.** Snapshots committed; a cold start fills the band within 60 s on the Fedora host.
- **Depends on.** D34-22, D34-17. C13 is no longer a dependency.
- **Size.** M. **Owner review.** 1.0 h. **Risk.** Medium. This is the screen the First Look sessions test.

### 5.3 Slip plan

The cut order protects exit clauses and gates first, then First Look's inputs. Each checkpoint is a Monday review.

**0.34**
- Mon 9 Nov: if P08 to P15 are not all merged, move P12 (B33a) and P20 (C16) to 0.35. C16 is a real defect but touches no gate.
- Mon 16 Nov: if P18 (B25) is not merged, move P18 and P22 (the socket episodes) to 0.35 and narrow exit clause 2 to the rules whose close path changed in what ships: `dns.slow_resolver`, `gateway.rtt_spike`, `link.down`, `wifi.weak_signal`, `path.rtt_spike` and `target.slow_stage`.
- Never cut B01, B05 to B07, B09 to B11 or B13. They are REVIEW §2.1 and §2.2, and everything in 0.35 builds on the kind and the thresholds.

**0.35**
- Mon 30 Nov: if P23 to P26 are not merged, move P28 (A10) to 2027 and keep the IPv6 row as "press t" on every OS.
- Mon 7 Dec: if P29 is not merged, slip the 0.35 tag one week to Tue 22 Dec rather than ship First Look without its band, because the sessions test the band. Sessions then start in January (M4).

**Plan §7's split rule.** Plan §7 says: if 0.34 slips, ship the Windows and first-run half alone and First Look as 0.35 by 15 Dec. This plan departs from it on purpose. At 1.5 h a week, REVIEW §2's carry-over fills 0.34, and December holds either First Look or REVIEW §3, not both. M3 picks First Look, because the plan's Q4 bet and the First Look sessions depend on it. If the owner picks REVIEW §3 instead, P23 to P30 move to 0.36 and 0.35 takes the §3 items from §6.1 and §6.2: the traceroute parser and Windows smoke test, the docs and completions PR, the key-map PR, the capture banner, and IP Helper.

---

## 6. Q1 2027 and later

Items here are coarser: ID, what, review hours and what they wait on. Each gets the full work-item format when it is scheduled into a release, from its slice plan. The forecast assumes netwatch Diagnose gets about 1.0 h a week of review in Q1, because plan §8 makes Q1's bet watch-cli and the MCP pilot, which need the rest of the line. That is about 12 h for the quarter.

### 6.1 Q1 2027 queue

| Release | Item | What | Review h | Waits on |
|---|---|---|---|---|
| 0.36, Tue 19 Jan | PCAPNG | Merge `feat/pcapng-export` after X08's second rebase, in two review sittings (plan §7 moves it to January under the split) | 2.0 | X08 |
| | D34-03 + A07 | Policy-aware `route_to()` on Linux and macOS with tunnel classification; link rules watch the interface that holds the route to 1.1.1.1, and coverage JSON names it | 1.0 | Nothing |
| | B02 + B12 | Per-rule confirmation counts; DNS p50 judged and learned on fixed 30 s windows, confirmed over 2; the PR re-records the corpus | 0.95 | B09 |
| | B08 | `tcp.receiver_limited` gets its own rule id, beta. It splits an existing Info detection (`diagnose/detectors.rs:2518-2544`), so it is the first id to use the beta marker | 0.4 | B05, D34-17 |
| 0.37, Tue 16 Feb | B15 | `dns.failing` as a window rule: ≥ 5 failures in 60 queries with Wilson lower bound > 5%, 15 s all-lost fast path, Medium below 50% and High at 50% or more. L-DNS-LOSSY then asserts an open within 120 s | 0.8 | B02, B05, decision B-4 |
| | REVIEW §3.1a | `tracert` parser fix with English and German fixtures; `--version` and `doctor --json` on windows-latest | 0.5 | Nothing |
| | REVIEW §3.4a | Docs, completions and man page for `diagnose run` and `corpus`; `completions_and_man_cover_every_option` covers subcommands | 0.3 | Nothing |
| | C13 + C14 | One readiness vocabulary (`Coverage::summary()`); earned green: Clear needs the core rules Available and core baselines ready, with the M5 exception for loopback stubs | 1.25 | A01, A05, M5 |
| | D34-29a | The default-network-calls table in code, off switches for the internet probe, the DNS cross-check and STUN, and a generated README section with a test | 0.5 | Nothing |
| | D34-28 | `u` then y/n usefulness labels, written to `labels.jsonl` (0600) and the active episode. It registers `u` in `handle_main_key` and `ui/help.rs` directly, and the key-map PR absorbs it later. It no longer waits for `netwatch report`, so plan §11's label test can start in February | 0.75 | X01, D34-24 |
| 0.38, Tue 30 Mar | D34-13 | IPv6 three-state fact on every OS; `ipv6.broken` judged over 2 of 3 rounds; `ipv6.partial` Observation (beta) | 0.75 | D34-03, D34-04, D34-17 |
| | D34-11 | Captive portal: `Content-Length`, 511 and 200-with-body on ≥ 2 endpoints | 0.5 | Nothing |
| | D34-12 | Portal and IPv6 experiments run on network change, so the IPv6 fact meets the 60-second promise | 0.75 | D34-11, D34-13, X01, D34-29a, OD-3 |
| | B30 | Path rules read "needs periodic traces" while tracing is off; freshness and the verify gap follow the trace interval | 0.3 | B04 |
| | C19b | Honest apply in full: `Action::cli_equivalent()`, `ApplyMode`, a prompt before any real apply | 0.4 | C19a |
| | A09 | macOS `link.down` reads `status: inactive`, not the admin UP flag (`platform/macos.rs:84`) | 0.25 | Nothing |
| | REVIEW §3.4b | Key-map table replacing `handle_main_key` (`app.rs:3525-4288`, 105 `KeyCode::` matches), with help built from it. It lands after PCAPNG (hunks at HEAD 3588 and 3979-3996) and after C16's `m` handler change, and is split from §3.4a because it rewrites 765 lines | 0.6 | PCAPNG merged, C16 |

About 12 h across the three releases. Plan §11's label-uptake test (23 Jan) and the Show HN (9 Feb, "if First Look has left beta") cannot happen on those dates at this rate; decision M4 re-dates them.

### 6.2 Q2 2027, in queue order

1. REVIEW §3.1b IP Helper with the `platform::` trait (connections, interfaces, `IcmpSendEcho2`), §3.3 capture banner (using D34-23's constant), §3.2 `/proc/net` fallback and macOS libproc, §3.5 FreeBSD CI, winget. About 3 h.
2. W1 to W3: Windows route lookup, address list with DAD state, gateway neighbour entry. 0.75 h.
3. D34-08 + B21 in one PR: `tcpi_pmtu`, `min_rtt`, `rttvar`, `segs_out` and `lost` parsed by offset, and `tcp.retrans_burst` judged as a ratio (Observation 2 to 5%, Medium ≥ 5% over floors, High on the stall pattern). Then D34-09, `tcp_info` refreshed outside the Dense view. About 1.55 h. D34-09 also lifts B25's Dense-only limit.
4. B27 constant flow ID on the native traceroute; D34-16 First Look lab helpers; D34-15 CGNAT from a 3-hop trace; D34-14 the NAT64 Observation (one AAAA query for `ipv4only.arpa` per network change, added to D34-29a's table). First Look then has all six facts. About 1.85 h.
5. The DNS bundle, once OD-1 names a zone: A11 (keep the reference RTT, always query the reference), A12 (the 2×2 table as causes), B14 + A13 (uncached wildcard probe and the 400/500 ms ceiling in one PR, so uncached names never meet the 100 ms ceiling), A14 (SERVFAIL and REFUSED as failures, after B15), A15a (truncation abstains). About 3.3 h plus 0.5 h for OD-1.
6. D34-18 + D34-19 `gateway.loss` and `gateway.rtt_high` (beta); D34-07 + D34-20 nl80211 station stats and `wifi.high_retry` (beta). About 2 h.
7. C22 owner-only local report, C23 `netwatch report --share`, D34-30 the six-fact privilege matrix in CI. About 2.25 h.
8. The rest of the 0.33 slices: B18, B19, B20, B22, B23, B26, B28, B29, B31, B32 and the remaining B33 texts; C10's other episodes, C12, C15's UI panel, C17, C18, C20, C21, C24; A15b. B26 must land before the rule slice's lane B.
9. First Look's cut-first list in the report's order: D34-10, D34-M1, D34-26 and D34-27, D34-25, D34-06 (absorbs A08), D34-05, W02, W03.

### 6.3 Q3 2027: the rule slice

From the Q1 slice plan, now starting Q3 at the earliest. Every rule ships beta (D34-17), adds a catalogue entry with its contract, a `default_verify` arm, `CauseSpec` rows, regenerates `docs/diagnostic-coverage.md` and `ml/schema.json`, and adds any new destination to D34-29a's table.

| ID | What | Needs |
|---|---|---|
| D36-01 | One `Rule.source` table instead of five hand-written routing lists (`diagnose/engine.rs:90-127, 338-430`, `diagnose/coverage.rs:57-73`, `ui/diagnose.rs:211-235`); a reusable counter window in `kernel.rs` | B24 to B26 |
| D36-02 | `host.conntrack_full` (drops rising: Medium; fill ≥ 90%: Observation) | D36-01 |
| D36-03 | `tcp.listen_overflow` from TcpExt `ListenDrops`, `ListenOverflows`, `TCPReqQFullDrop` | D36-01 |
| D36-04 | Replaces A02's `local_drop_counters` placeholder with two host-wide checks at weight 1: `RcvbufErrors` above 10/s and conntrack insert failures | D36-02, A02 |
| D36-05 | `host.softnet_drops` Observation on the dropped column only | D36-01 |
| D36-06 | Interface kind, carrier-up clock, and connectivity memory that survives a fingerprint change | B26, C05 to C07, D34-03 |
| D36-07 | `addr.dad_failed` | D34-04, D36-06 |
| D36-08 | `addr.self_assigned` (covers `dhcp.no_lease`), Critical; a test-only `lab` cargo feature | D34-03, D34-04, D36-06 |
| D36-09 | `local.no_route` and `dns.no_resolver`, Issue only after this network had a route | D34-03, D34-21, D36-06 |
| D37-01 | Internet probe outcomes (RST is Rejected, not reachable), second operator target 8.8.8.8:443 | D34-01 |
| D37-02 | NetworkManager `Connectivity` via `busctl` | D36-01 |
| D37-03 | `wan.unreachable`, naming the tunnel when the route leaves through one | D37-01, D37-02, D34-03, D36-06, D34-11 |
| D37-04 | `vpn.ipv6_bypass` | D34-03, D34-04, D36-06 |
| D37-05 | `link.speed_degraded` (half duplex Issue; below both ends' best mode Observation) | A07, D36-06 |
| D37-06 | `host.clock_unsynced` Observation and chrony offset tiers | D36-01 |
| D37-07 | Explain cards behind `?` through watch-explain, including the first cards the 0.34 slice planned | watch-explain 0.1, REVIEW §3.4b |
| D38-01 | `route.overlap`, an Issue only with a SYN-SENT pile-up into the shadowed prefix | D34-03, D34-05, D36-06 |
| D38-02 | `connectivity.partial` (HTTPS leg after the portal check) | D34-11, D37-06, the `lab` feature |
| D38-03 | Structured STUN outcomes and `udp.blocked` | D37-01 |
| D38-04 | `dns.encrypted_blocked` Observation (DoH canary, DoT) | B05, A11 |
| D38-05 | `path.call_quality` grade as an Observation | D34-01, D34-24 |
| D38-06 | Calibration disclosure after ≥ 10 labelled closures per rule | D34-28, D34-17 |
| D38-07 | Bufferbloat demotion from TCP chrono stats (optional) | B08, D34-08 |

Decisions for that slice, due before it starts: release numbers; the second WAN target (default 8.8.8.8:443, probed only when the first fails and once every 5 minutes); whether `wan.unreachable` with no prior reachability stays an Observation (default yes); the proposed severities (`addr.self_assigned` Critical; `wan.unreachable`, `local.no_route`, `dns.no_resolver`, `vpn.ipv6_bypass`, `connectivity.partial` High; half duplex Medium); a `lab` cargo feature that never ships in release builds; `?` on a selected evidence row opens its card; the new default destinations; HTTP-Date clock skew stays rejected (`diagnose/targets.rs:791`); calibration's N ≥ 10 and 0.70 cut; whether `host.*` rules run on laptops by default; `busctl` over zbus; softnet stays an Observation; whether D38-07 is in scope.

### 6.4 Blocked candidates

Each lacks one signal. Revisit when that signal exists.

| Candidate | Missing signal | Revisit when |
|---|---|---|
| `dns.servfail` | An uncached probe name. It then becomes a failure class of `dns.failing` (A14), not a rule | OD-1 is decided |
| `wifi.segment_bottleneck` | A way to tell a slow radio from power save at idle; the idle PHY rate is the last rate used | netwatch samples PHY rate under load |
| `wifi.idle_spikes` | A 10 to 20 Hz burst prober to the gateway, and evidence beyond two anecdotes | Such a prober exists |
| `wifi.beacon_loss` | A sourced threshold; the counter is already in `iw station dump` | A published threshold or field data |
| `wifi.insecure` | The network's security type: NetworkManager D-Bus on Linux, Location consent on Windows | A D-Bus reader in the D37-02 style |
| `lan.ipv4_conflict` | ARP replies for our own address, from capture or `CAP_NET_RAW` | Diagnose can read capture |
| `lan.rogue_dhcp` | DHCP option 54 server ids, from capture | Same |
| `vpn.dns_leak` | Which interface DNS packets leave on, from capture | Same |
| `lan.gateway_mac_changed` | BSSID on macOS and Windows, to rule out mesh roaming | After D34-05, as a Linux-only flapping Observation |
| `nat.double_nat` | The router's WAN address, from UPnP IGD or PCP | A UPnP or PCP client |
| `proxy.mismatch` | A system-proxy reader that works in the sandbox; `gsettings` runs without dconf access (`diagnose/targets.rs:869-880`) | A sandbox grant plus KDE, `scutil` and WinHTTP readers |
| `path.profile` | Per-context baselines | watch-baseline, Q2 2027 or later |
| `dhcp.lease_renewal` | Lease timers; lease files are permission-denied to uid 1000, so NetworkManager `DHCP4Config` is needed, plus prevalence data | A D-Bus reader and field data |

Deferred halves, not blocked: the `ipv6.nat64` Issue half needs a CLAT address and a NAT64 translator in the lab; a passive PMTU black-hole suspect cannot work while `tcp_mtu_probing = 0`; `dns.tcp_fallback_broken` must test the upstream, not the stub; `tls.interception` and `target.cert_expiry` need chain capture and an X.509 parser.

---

## 7. Schedule and capacity

### 7.1 Week by week

Lane A and lane W are the two sessions plan §6.1 allows in the repo. Review hours are the owner's, on the day in the PR tables above. Agent time left over goes to agent cross-review and to drafting the next PR, capped at 2 unreviewed PRs per lane; drafts touch only files the other lane is not editing.

| Week | Lane A | Lane W | Owner review booked | Decisions due |
|---|---|---|---|---|
| W0, 28 Sep to 2 Oct | 0.32.4 (REVIEW §1) | 0.32.4 test depth | A00 0.25, plus the 0.32.4 approval | A00 (overdue); X07 and WRITER by Fri 2 Oct |
| W1, 5 to 9 Oct | P01 (Mon-Tue), P03 (Wed-Thu), P05 drafted Fri | X07 merge PR (Mon), P02 (Mon-Tue), P04 (Wed-Fri) | X07 0.25, P01 0.75, P02 0.45, P03 0.5: **1.95** | M1, M2, M6, D2, OD-12c on Mon 5; D6 on Wed 7 |
| W2, 12 to 16 Oct, freeze Fri | P05, P07 | P06 | P04 1.0, P05 0.4, P06 0.75: **2.15** | X02 on Mon 12 |
| W3, 19 to 23 Oct | Mon release PR; **Tue 20 tag 0.33**; P08 (Wed-Thu), P09 (Fri) | X08 rebase onto `v0.33.0`; P11 | P07 0.6, release 0.25, P08 0.25: **1.1** | M3, M4 at the Sat 24 Oct check |
| W4, 26 to 30 Oct | P10, P13 | P11, P12, P15 | P09 0.25, P10 0.5, P11 0.5, P12 0.2: **1.45** | S2 on Mon 26 |
| W5, 2 to 6 Nov | P14, P16 | P15, P17 | P13 0.5, P14 0.35, P15 0.55: **1.4** | D7 on Mon 2 |
| W6, 9 to 13 Nov | P18 | P17, P19 | P16 0.3, P17 0.45, P18 0.95: **1.7** | Slip checkpoint Mon 9 |
| W7, 16 to 20 Nov, freeze Fri | P20 | P19, P21, P22 | P19 0.4, P20 0.5, P21 0.5, P22 0.5: **1.9** | Slip checkpoint Mon 16 |
| W8, 23 to 27 Nov | Mon release PR; **Tue 24 tag 0.34**; P23, P25 | P24, P26 | release 0.25, P23 0.5, P24 0.25, P25 0.75: **1.75** | CAP, B-10 on Mon 23 |
| W9, 30 Nov to 4 Dec | P27, P29 | P28, then drafts of 0.36 items | P26 0.25, P27 0.25, P28 0.25, P29 1.0: **1.75** | Slip checkpoint Mon 30 |
| W10, 7 to 11 Dec, freeze Fri | P30 | Drafts of 0.36 items | P30 1.0: **1.0** | M5, OD-1 on Mon 7; slip checkpoint Mon 7 |
| W11, 14 to 18 Dec | Mon release PR; **Tue 15 tag 0.35** | watch-finding 0.1 extraction (M6) | release 0.25, watch-finding 0.5: **0.75** | |

Weeks W1, W2, W6, W7, W8 and W9 go over the 1.5 h line by 0.2 to 0.65 h and draw on the buffer. Across W1 to W11 the schedule books 16.9 h against 16.5 h of review line. Plan §12 also needs owner review in October for other repos: the diskwatch release, the reusable workflows in four repos, the essh fix and publish, `syswatch insights --json`, AGENTS.md, CONTRIBUTING and SECURITY.md in five repos, archiving nine repos and the last netwatch-agent release. Those come out of the buffer, 8.25 h over the eleven weeks less the 2.2 h the heavy weeks draw, and out of line left unused in W3, W10 and W11. If a Monday note shows a week overran, that week's last PR moves to the next week, and the slip checkpoints in §5.3 decide what leaves the release.

### 7.2 Capacity by release

| Release | Review window | Review line in window | Booked | Buffer drawn | Agent-days booked / available |
|---|---|---|---|---|---|
| 0.33, Tue 20 Oct | 5 to 19 Oct | 4.5 h | 4.95 h (X07, P01 to P07, release PR) | 0.45 h | 12.6 / 22 |
| 0.34, Tue 24 Nov | 23 Oct to 23 Nov | 6.65 h | 6.95 h (P08 to P22, release PR) | 0.3 h | 15 / 46 (with X08) |
| 0.35, Tue 15 Dec | 23 Nov to 14 Dec | 4.25 h | 4.5 h (P23 to P30, release PR) | 0.25 h | 10.5 / 30 |
| Q1 2027 | 4 Jan to 26 Mar | about 12 h for Diagnose (1.0 h a week) | about 12 h (§6.1) | none planned | about 25 / 120 |

Agent time is not the limit. Two sessions have about three times the agent-days these releases need; the spare goes to other repos within plan §6.1's portfolio cap of 4 sessions.

What the three slice plans asked for, before any cut, was about 58 agent-days and 32 owner hours for 0.33 alone, and about 20 more owner hours for First Look and 4 for REVIEW §3. The cut list is §5.3 and §6.

### 7.3 What extra review hours buy (decision M1)

| Extra review | When | What moves up |
|---|---|---|
| +1.5 h a week, about 3 h | 5 to 16 Oct | 0.33 also ships B01, B05, B06 and B07 (the Observation kind, issue-only exit code, schema 2) and C19b. The exit-code gate moves into 0.33. X01 then rebases over B01, which is mechanical |
| +1.5 h a week, about 6 h | 26 Oct to 20 Nov | 0.34 also ships B02 + B12, B15, B30, A09, REVIEW §3.1a and §3.4a, and C13 + C14 earned green. REVIEW §2 is complete in 0.34 apart from the DNS bundle, which waits for OD-1 |
| +1.5 h a week, about 4.5 h | 23 Nov to 11 Dec | 0.35 also ships D34-03 + A07, D34-13, D34-29a, D34-11 and D34-12. First Look then shows five of six facts, with IPv6 inside 60 s, on Linux and macOS. PCAPNG stays in January |

The plan's drop order (§6.1) is essays first, then incubator work, then new crate extraction. Taking the first row costs about two essay slots in October.

---

## 8. Release gates

### 8.1 0.33, Tue 20 Oct

1. CI is green on Linux, macOS and Windows for the tag commit on `main`, with clippy `-D warnings`, and the 0.32.4 release guard passes.
2. **Exit clause 3.** `git grep -c 'CheckResult::skipped' src` and `git grep -n 'passed: None' src/diagnose/detectors.rs` print nothing. `no_detector_reads_an_absent_input_as_evidence` passes with all ten rows and `EXPECTED_UNTIL_0_33_A` empty. `a_not_run_check_always_says_why` passes.
3. **Exit clause 1.** The `health-lab --quick` CI job passes. `health-lab.json` shows L-DNS-SLOW, L-DNS-DOWN, L-GW-DOWN (total loss, per D2) and L-PATH-SPIKE opening and closing inside their windows, and L-HEALTHY opening nothing. No lab run wrote outside its temp home.
4. **Corpus.** The pinned corpus replays. Against v0.32.4 the only decision change is C01's `dns.slow_resolver|169.254.1.1` span.
5. **Feature schema.** `ml/schema.json` was regenerated in P03 and `the_committed_schema_is_current` passes. The CHANGELOG says the feature schema hash changed.
6. **No new rule ids.** The catalogue still has 30 rules; `docs/diagnostic-coverage.md` is regenerated and its drift test passes.
7. **Exit clause 2 is recorded as a known gap** in the CHANGELOG and becomes a 0.34 gate, unless M1 changed that.
8. **If P07 merged:** live mode offers no `↵`; no verdict-row or header cell is green; `an_unmeasured_gateway_is_not_evidence` and `no_step_text_promises_a_write` pass.
9. **CHANGELOG** covers `why_not` and `state` on checks; `local_udp_path` no longer reads Strong without a local counter; sockets without RTT, idle radios, missing interface info and macOS drops read as not measured; and, with P07, the stub disclosure, the remediation text, the muted Incomplete verdict and the Incomplete exit when the gateway was never measured.
10. **No PCAPNG content.** `git diff v0.32.4..v0.33.0 --name-only` lists none of `src/collectors/packets/export.rs`, `src/ui/capture_export.rs`, `docs/capture-export.md`.
11. **Owner check on the Fedora host.** Every check with `"state": "not_run"` in `diagnose run --format json` has a `why_not`; the DNS evidence names 127.0.0.53 as a stub; `--demo` runs to its end and still offers the simulated switch.

### 8.2 0.34, Tue 24 Nov

1. Every 0.33 gate still passes.
2. **Exit clause 2.** `every_touched_rule_has_an_open_close_episode` and `every_corpus_entry_replays_to_its_pinned_decisions` pass. Each `PENDING_CLOSE` row (only `iface.errors` expected) was accepted by the owner in the PR that added it.
3. **Corpus changes explained.** Every PR that changed a decision lists its changed spans with the item that caused them. `a_sustained_slowdown_is_not_learned_away` still passes.
4. **Lifecycle.** These pass: `an_unmeasured_gateway_never_expires_the_outage`, `a_closed_socket_expires_its_retrans_issue`, `a_router_resolver_issue_can_close`, `a_muted_condition_stays_one_issue`, `a_gateway_rtt_hovering_at_three_sigma_does_not_flap`, `an_episode_recorded_before_new_threshold_fields_still_loads`, `settings_with_auto_close_secs_still_load`.
5. **Exit code and schema.** `observations_alone_exit_zero`, `one_issue_exits_one`, `a_named_target_answering_503_exits_one` and `a_gateway_root_cause_survives_the_target_filter` pass. `diagnose run --format json` reports `schema: 2`, with `kind` on findings and `state` without `passed` on checks.
6. **Controller move.** X01 changed no test count and its diff is moved blocks and call sites only.
7. **Lab.** `--quick` still passes, with L-DNS-SLOW's close window rechecked under B13.
8. **Still no new rule ids.** Any new id blocks the release until D34-17 exists.
9. `ml/schema.json` and `docs/diagnostic-coverage.md` are current.
10. **CHANGELOG** covers schema 2 with a breaking-change note; the Observation kind and the exit code; the σ and delta floors, which make DNS and gateway findings open later; `auto_close_secs` renamed `expire_after_secs` with an alias; "expired, evidence gone" and "stale since", including that socket issues expire only in the Dense view or `diagnose run` until D34-09; the mute fix; `[diagnose_thresholds]` in config.
11. **Owner check on the Fedora host.** `dns_ceiling_ms = 30` makes a 40 ms resolver report; muting a live condition leaves one issue.

### 8.3 0.35, Tue 15 Dec

1. Every First Look fact carries `beta: true` on screen and in JSON.
2. No new default traffic: a 5-minute capture on the Fedora host shows the same destinations as v0.34.0.
3. `diagnose run --budget 60s --format json` on the Fedora host returns all six facts, each with a value or a `why_not`, matching the table in §5.2; the health lab asserts the same within 60 s.
4. `baselines.json` keys are byte-identical before and after D34-04.
5. macOS and Windows CI no longer report `ipv6.broken` as `collector_failed`.
6. The `setcap` line First Look prints equals the one in `README.md`.

---

## 9. Changes to REVIEW-2026-09-24 §2 that this plan supersedes

Line numbers are in `docs/REVIEW-2026-09-24.md` as committed by A00. Each entry says what to change the text to.

1. **§2.1 first bullet (lines 111-116).** "Mark that check NotRun when alt is None" stands, as `not_run(NotMeasured)` with a `why_not` (A01, A02), and `interface_drops` gains the 60/min floor and a `not_run` weight-2 discriminator. Replace "Then add the passive alternate-resolver probe, timing one query to the second configured resolver or 1.1.1.1 per cycle" with: keep the RTT of the cross-check query to 1.1.1.1 that already runs every cycle, and send it even when the local query fails (A11, Q2 2027). No new probe.
2. **§2.1 second bullet (lines 117-120).** Delete "or a random `*.example` query that gets an NXDOMAIN": 9.9.9.9 answered such names at cache speed. The probe asks a random label under a wildcard zone the owner chooses (OD-1, A13). Until then it keeps root NS, and the evidence says it measures the local stub (X04, 0.33).
3. **§2.1 third bullet (lines 121-125).** "Count gateway evidence only when loss is measured" is X05 in 0.33, at `diagnose/run.rs:196` rather than 199. Replace "Exit 1 only when an issue is at or above a severity floor (default Low); report Info issues but don't let them decide the exit code" with: Info becomes the Observation kind, and the exit code counts Issues only (B05, B06, 0.34), because `Severity` has no Low. "Stop `--target` from filtering out host-wide root causes" is B07 (0.34), which also keeps a named target's service failure an Issue.
4. **§2.2 first bullet (lines 128-131).** Replace "Implement `auto_close_secs` … when the rule's evidence has been absent that long" with: a new `Expired` state; `auto_close_secs` renamed `expire_after_secs`; expire only when the collector is healthy and the subject is gone, otherwise show "stale since" (B24, B25, 0.34). `AutoClosed` keeps meaning "verify held".
5. **§2.2 second bullet (lines 132-134).** Replace the relative verify wording with: one number fixed at open, `max(mean + 2σ_floored, 0.8 × open line)`, held 60 s (B03, B13, 0.34).
6. **§2.2 third bullet (line 135).** Stands, as C02, C08, C09, C10 and the C11 gate in 0.34, scoped to rules whose open, verify or close logic changed.
7. **§2.3 `path.rtt_spike` (lines 138-140).** Replace "Never fall back … No baseline means NotRun" with: fall back to the `internet` baseline only when the trace target is `INTERNET_TARGET` in the same address family, otherwise NotRun (B31, Q2 2027). Never falling back would leave the default setup permanently Learning.
8. **§2.3 `dns.failing` (lines 141-144).** Replace "Require at least N=10 queries across cycles before judging, or a ≥2-of-3 streak over 3 cycles" with: at least 5 failures in the last 60 queries with a Wilson lower bound above 5%, `consecutive_n = 1`, and a 15 s all-lost fast path (B15, Q1 2027). "N ≥ 10 at > 5%" gave about 230 false opens a day in simulation. The "pipeline dns stage fails" branch is removed, not implemented (B15).
9. **§2.3 σ floor (lines 145-147).** Stands, and gains absolute delta floors: ≥ 10 ms above the mean for gateway RTT, and ≥ 5 ms and 2× for DNS (B09, B10, 0.34). Non-overlapping p50 windows are B12 (Q1 2027).
10. **§2.3 `tcp.bufferbloat_remote` (lines 148-151).** Stands in substance, with the uplink counting as clean only at ≤ 30 ms added (B23, Q2 2027). The 10-minute expiry of the test result is B22.
11. **§2.3 `tcp.retrans_burst` (lines 152-156).** Replace "retransmits per segments sent ≥ 1%" with: Observation at 2 to 5%, Medium at ≥ 5% with ≥ 20 retransmitted and ≥ 400 sent segments over 2 windows, High on the stall pattern (B21 with D34-08, Q2 2027). Normal rates run 1 to 2.5%, so 1% would fire on healthy long-haul flows. "A missing rtt is unknown, not 0" is A03 (0.33). Receiver-limited gets its own id after the beta marker (B08, Q1 2027).
12. **§2.3 link rules (lines 157-159).** Link rules watch the interface that holds the route to 1.1.1.1, from `route_to()` (D34-03 with A07, Q1 2027). Delete "`link.down` on a non-uplink interface is at most Info": no link rule watches a non-uplink interface.
13. **§2.3 thresholds (lines 160-163).** `Thresholds` from config is B01 (0.34). The `dns.rtt_p50` baseline test is B12's `the_judged_and_learned_dns_statistic_are_the_same` (Q1 2027).
14. **§2.4 first two bullets (lines 166-171).** The step text stops promising a write and shows the command (B16, 0.33); live mode offers no `↵` (C19a, 0.33); the full apply handoff is C19b. A resolver is proposed only after it was measured and found fast (B16).
15. **§2.4 third bullet (lines 172-174).** Keep "Delete `apply_file_edit`/`make_permanent`" (X02, 0.33). Delete "switch it to write-temp-then-rename": it contradicts `docs/resolver-adapter.md:72-75` and two tests, and the journal already refuses new operations after an interrupted write.
16. **§2.5 (lines 177-180).** Lands in 0.34, the day after the 0.33 tag (X01). The ranges are `app.rs:466-602` and `874-1363` and `5363-5578` at `df1dfba`.
17. **Exit (lines 182-185).** Clause 1 is met in 0.33, with "gateway loss" meaning total loss until `gateway.loss` exists (D2). Clause 3 is met in 0.33 through a behaviour table, not a source scan. Clause 2 moves to 0.34.

Related edits outside §2:
- **§1 (lines 26-27).** "Then cherry-pick it forward" becomes: merge `release/0.32.4` into `main`, then `df1dfba` into `main`; 0.33 is built and tagged on `main` (X07).
- **§3.3 (lines 213-214).** The fix line becomes `sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' "$(which netwatch)"`, the line the docs ship, held in one constant (D34-23, decision CAP).
- **§3.4 (lines 220-223).** Split into a docs and completions PR (§3.4a) and a key-map PR (§3.4b) that lands after PCAPNG.
- **Order of work (lines 282-284).** 0.33 carries §2.1 to §2.4 in part as listed above, §2.5 moves to 0.34, and §3 moves to 2027 under decision M3.

