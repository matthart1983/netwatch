# Plan: Horizon 3 — egress policy linter (observe → promote → warn)

**Drafted:** 2026-07-04
**Status (2026-07-28):** shipped through v0.27.0. Since then, on
`feat/egress-tree-ux`: byte accounting, the grouped tree and the verdict
vocabulary; on `feat/egress-policy-criticals`: the two policy-model criticals —
strict mode for undeclared processes, and promotion no longer widening to an
autonomous system (see the amended invariants below). Still open from the
2026-07-28 analysis: `--egress-lint` breadth report, exec-path rule keys, CGNAT
+ IPv4-mapped private ranges, destination-scoped ports, metrics expansion.

**Status (2026-07-04):** Phases 0–2 ✅ and **Phase 3 step 1 (OSS export) ✅**
implemented on `feat/h3-egress-linter` (commits `bedd447` foundation, `777cb22`
tab, `38a83bb` Phase 1, `1ea0d75` Phase 2, + NDJSON export), all unreleased —
ships together as **v0.26.0** once the live check passes. Deferred within
Phase 2: violations pane / alert→flow jump / per-rule snooze (ergonomics beyond
the configurable cooldown). Phase 3 steps 2–3 (agent parity, cloud ingest)
remain **gated on the launch decision** — the export contract should be pulled
by a launchable product, not pushed ahead of one.
**Context:** ROADMAP.md Horizon 3. Foundation already exists on `feat/h3-egress-linter`
(commit `bedd447`, unreleased): `collectors/egress.rs` EgressProfiler joins
process + SNI + ASN + port into per-process profiles; `Shift+P` promotes the
baseline to `<config>/netwatch/egress-policy.toml`; `AlertCategory::PolicyViolation`
warns on drift with a 300s per-flow cooldown. 10 unit tests. Working tree has an
uncommitted Egress tab (`src/ui/egress.rs` + wiring in app.rs/ui/mod.rs/widgets.rs).

**Invariants (hold in every phase):**
- Warn, never block. No inline data path, no new capabilities held after init.
- Deterministic and low-noise: by default only processes with a declared rule
  are checked, and a violation names the rule it broke. **Amended 2026-07-28:**
  `strict = true` in the policy file opts into reporting *undeclared* processes
  too. The default is unchanged; the opt-in exists because the thing a
  compromise introduces is a new binary, which the default can never see.
- The baseline is how you author the config (AppArmor-style profile generation,
  applied to egress). Resist iptables-in-TOML; let real use pull complexity.
- SNI-first matching (cleartext ClientHello — no keylog required), then the
  address. **Amended 2026-07-28:** promotion no longer falls back to the ASN.
  An AS entry admits every host that AS operates, so learning one nameless
  hyperscaler flow silently handed the process the whole hyperscaler — measured
  at 12 of 25 rules on a real baseline. Rules match on ASN when a human writes
  one; nothing generates one. The original "never raw IP" line was reversed
  earlier (a nameless dest has no other identity, and would otherwise drift
  against its own promoted rule); IP is the narrow choice, not the loose one.

---

## Phase 0 — Ship the foundation — **v0.26.0** (target: ~1 week)

Goal: what's on the branch becomes a released, documented, demo-able feature.

1. **Finish the Egress tab** (in flight, uncommitted). Table of per-process
   profiles (process, dest SNI/ASN, ports, first/last seen), policy status column
   when a policy is loaded (`in-policy` / `drift` / `unlisted`), footer with
   `Shift+P` hint. Sort + existing filter-language integration (`process:`,
   `sni:` prefixes already exist elsewhere — reuse).
2. **Violations surface**: PolicyViolation alerts appear in the existing alerts
   flow — verify they render with rule name and are reachable from the tab.
3. **Docs**: REFERENCE.md (tab, keybinding, policy.toml format with a commented
   example), README one-liner in the feature table, CHANGELOG.
4. **Demo GIF**: observe a browser session → promote → `curl https://unexpected.example`
   → warning fires naming the rule. This is the marketing asset; the loop is the
   story.
5. **Verification (release gate)**:
   - Unit suite green (523+); clippy clean.
   - Live on the NUC (eBPF attribution path): stage a violation with a scripted
     client; confirm alert text names process + rule + destination.
   - macOS path (lsof attribution): confirm profiles still form (degraded pid
     coverage is acceptable and documented).
   - Policy file round-trip: promote → edit by hand → reload → hand edits survive.

Release as **v0.26.0** — headline: "NetWatch learns what your machine normally
talks to, and warns when it drifts."

## Phase 1 — Make the baseline trustworthy — v0.27.x (~2–3 weeks)

The v0 baseline lives and dies with the process; a 20-minute TUI session is not
a baseline. This phase makes "observe" mean something.

1. **Profile persistence.** Serialize observed profiles to the state dir
   (`$XDG_STATE_HOME/netwatch/egress-profiles.json`), load + merge on start,
   age out destinations not seen for N days (default 30). Keep the LRU caps
   (256 procs / 128 dests); cap file size. Sandbox: add the state path to the
   Landlock allow-list (`sandbox/paths.rs`).
2. **Evidence for ratification.** Per destination: first-seen, last-seen,
   flow count. Shown in the tab; this is what a human reviews before promoting.
3. **Selective promotion.** `Shift+P` currently ratifies everything. Add
   per-process promote (promote the selected row's process only) and a
   pre-promote diff ("this will add 3 SNIs to `chrome`, create rule for `node`").
   Review-before-trust is the anti-poisoning story — make the review real.
4. **Preserve hand edits**: switch policy writes to `toml_edit` so comments and
   ordering survive re-promotion.

## Phase 2 — Signal quality + headless — v0.28.x (~3–4 weeks)

Drift warnings are only valuable if people leave them on.

1. **Wildcard suggestion.** When a process accumulates ≥K subdomains of one
   apex, suggest `*.apex.tld` at promote time instead of K exact entries.
   Suggestion, not silent collapse — the human ratifies.
2. **ECH-aware state.** A flow with ECH has no readable inner SNI (`tls.rs`
   already flags it): match falls to ASN and the tab shows `ech` on the row, so
   an unmatched-because-encrypted flow is distinguishable from real drift.
3. **Violation ergonomics.** Violations pane (or filter `violation:true`) in the
   Egress tab; jump from alert → offending flow; per-rule snooze; configurable
   cooldown in config.rs.
4. **Headless mode.** `netwatch daemon` (v0.25.6) evaluates policy too:
   PolicyViolation events go out the existing remote-ingest path and a
   `netwatch_policy_violations_total{process,rule}` counter lands on the
   Prometheus endpoint. The linter now works on servers with no TUI attached —
   this is the fleet story's on-ramp.
5. **Hardening.** Property tests for the SNI matcher (wildcards, apex, case);
   fuzz the policy-file parser (same harness as the L7 parser fuzzing); refuse
   (with a loud warning) a group/world-writable policy file — the policy is a
   trust anchor and a tamper target.

## Phase 3 — The seam to cloud — v0.29–v0.30 (~a month, crosses repos)

Where OSS linting becomes the product's ingest contract.

1. **Structured egress export.** ✅ **Done (OSS side)** on
   `feat/h3-egress-linter`: `EgressProfiler::export_ndjson` writes versioned
   NDJSON (`netwatch.egress.v1`) — a `_meta` schema line then one metadata-only
   `EgressRecord` per line (process, SNI, ASN, port, proto, ECH, first/last-seen,
   count, policy verdict). Bound to `e` on the Egress tab. No payload, ever.
   This is the contract the managed layer ingests.
2. **Agent parity.** ⛔ **Gated on launch decision.** Lift `EgressProfiler`
   into netwatch-sdk (or netwatch-dpi) so `netwatch-agent` runs the same observe
   loop and ships records to the cloud. One implementation, two consumers.
   Don't build ahead of a launchable product.
3. **policy.toml as the second seam.** ⛔ **Gated.** Same file the TUI lints
   with, the cloud can distribute and (later, managed layer) enforce. Cloud work
   itself — fleet drift view, central promote — lives in the netwatch-cloud repo
   and is gated on the launch decision, not on this plan.

## Phase 4 — Fleet/product layer — v0.31+ / cloud repo

Central policy distribution, fleet-wide drift dashboard, promote-from-cloud,
org-level baselines. Deliberately unspecified here: shape it from real usage of
Phases 0–3, and don't start it before netwatch-cloud can take signups.

---

## Explicitly out (unchanged from ROADMAP.md)

- Blocking/enforcement in the OSS TUI — enforcement is a managed-layer concern.
- Raw-IP rules; iptables-in-TOML rule complexity nobody asked for.
- Windows/FreeBSD kernel attribution work for this feature.

## The write-up (not optional)

Each phase that ships gets told. Minimum: one deep-dive at v0.26.0 —
"A linter for your network egress" (why warn-not-block, why process+SNI is a rule
shape firewalls can't express, the baseline-poisoning problem and human
ratification). This is the field-positioning artifact; the feature without the
essay repeats the v0.24/v0.25 silence.

## Sequencing note

Phase 0 ships now (it's nearly done). Phases 1–2 are TUI-local and safe to run
on the point-release cadence. Phase 3 starts only after the ASIC/launch decision
is made — the export contract should be pulled by a launchable product, not
pushed ahead of one.
