# Netwatch code review remediation plan

Date: 27 October 2026. Status on 31 October: every item is merged to main, not yet released. See [Progress](#progress-31-october-2026).

Reviewed commit: `a268f30d24c9139b000c88bff46168526d3587e3` on `origin/main`, after 0.38.0. The checkout where this plan is saved is the older `feat/uptime` branch. Implement against current main after checking whether the findings have already been fixed.

The review scored the codebase **7/10**. Its diagnostic evidence model, attribution checks, recovery storage and testing infrastructure are strong. Incorrect packet interpretation, silent configuration fallback and incomplete privilege handling are the highest-priority gaps. This plan closes those gaps before expanding the feature set.

## Review baseline

| Area | Judgement score |
| --- | --- |
| Correctness and data integrity | 6.5/10 |
| Security and privacy | 6.5/10 |
| Architecture and maintainability | 6.5/10 |
| Tests and engineering discipline | 8/10 |
| Release readiness | 7/10 |

Scores are engineering judgements, not coverage measurements. The review covered capture and decoding, attribution, diagnostics, configuration, worker lifecycle, sandboxing, persistence, remote publishing and release checks. It was not an exhaustive line-by-line audit.

Validation on the reviewed commit:

- Linux `cargo nextest run --profile ci`: 1,820 passed, 10 skipped.
- `cargo clippy --all-targets -- -D warnings`: passed.
- Five additional probes failed on the expected assertions: two packet-decoding cases, configuration fallback, retry backoff and CLI duration overflow.
- Native macOS/Windows acceptance and the full flood soak were not rerun.

## Implementation order

| Order | Work item | Priority | Status at review |
| --- | --- | --- | --- |
| 1 | R1 Packet boundaries and fragments | High | Two failures reproduced |
| 2 | R2 Explicit configuration failures | High | Failure reproduced |
| 3 | R3 Complete thread privilege handling | High | Code-confirmed; existing PR #144 |
| 4 | R4 Canonical socket identity and indexed joins | Medium | Code-confirmed; existing PR #142 |
| 5 | R5 Effective remote retry backoff | Medium | Failure reproduced |
| 6 | R6 Checked CLI duration conversion | Low | Debug-build panic reproduced |

Keep changes narrowly scoped. Review and integrate existing PRs for R3 and R4 instead of creating duplicate implementations. Their open status is a snapshot from this review, not a live tracker.

## Progress, 31 October 2026

Every item is merged to main. `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo nextest run --profile ci` pass on the merged tree (2,076 tests, 11 skipped), and CI passes on Linux, macOS, Windows, FreeBSD and armv5te. Host: Fedora 44, Linux 7.1.13, AMD Ryzen AI 9 HX 370, 24 threads, 62 GB.

| Item | Where | Evidence | Left |
| --- | --- | --- | --- |
| R1 | #147 | Both packet probes pass as unit tests. Eleven new tests, one of which cuts sample frames at every length and tries every IHL and TCP data offset. One golden line changed: `misc` frame 6, a TCP header that was never captured, now reads `TCP (truncated)`. A 180-second random-mutation loop decoded 3.7 million frames without a panic. | `fuzz.yml` passed on the merged tree (all six targets). IPv6 extension headers are not walked, and fragments are not reassembled. No new `.pcap` semantic fixtures. `src/platform/pktap.rs` has its own IPv4 parser with the same fragment and IHL blind spots. |
| R2 | #146 | Probe adapted to `NetwatchConfig::load() -> Result`. Unit tests for each load outcome. CLI tests run the binary: the TUI and daemon exit 1 naming the file, line and column; `diagnose run` exits 3; `doctor` reports a failed `config` check and does not run `--check-capture` on defaults. A file that does not load is never overwritten. | CLI tests not run on FreeBSD, macOS or Windows. Diagnose's `r` reload already refused a broken file, but its message does not name the path. |
| R3 | #127, #138, #144 | `shutdown_deadline_thread_holds_no_capability` and the other 83 sandbox, capability and doctor tests ran on the host above, none skipped: unprivileged user namespaces work there and Landlock is on. The stack's full suite passes. | Not run as real root. CI's runners refuse user namespaces, so CI skips the runtime checks. |
| R4 | #142 | IPv4, bracketed IPv6 and IPv4-mapped rows join to their connections. A socket with no row has unknown rates, not zero, so it is neither idle nor sending. At 10,000 rows the join's p50, as the median of five interleaved runs, was 1.11 ms, against 0.93 ms for #142 alone and a 2 ms budget. | Two of those five runs were over 2 ms; the host was not idle, and #142 alone also varied. |
| R5 | #149 | Deterministic ceiling, cap and reset tests. A test of the production entropy. The real sender against a backend that answers every POST with 503 after 700 ms waits each ceiling from the end of the answer; that test fails on either old behaviour alone. | — |
| R6 | #145 | Unit tests, including `2152120141932781022m`, which the 0.38.0 release binary ran as an 8-second diagnosis. A CLI test exits 3 in debug and release builds. | — |

#148 puts a `SAFETY:` comment on every unsafe site, and #155 makes clippy fail a new site without one. Three are documented but not proven: the signature `src/platform/pktap.rs` assumes for `pcap_set_want_pktap_pktmetadata`, which Apple's headers do not declare, and two safe functions that pass raw pointers to FFI, `pcap_geterr_string` and `enable_pktap_metadata` in `pktap.rs` and `sockaddr_inet_ip` in `src/platform/windows/iphlpapi.rs`. Their callers are sound today.

The one-hour flood soak passed every gate on the reference machine and on a GitHub runner, and the strict scale benchmarks met every budget. [PERFORMANCE.md](PERFORMANCE.md) has the numbers.

Online GeoIP is removed, per the owner's decision on 25 October, and `netwatch geoip update` replaces it (#152).

## R1 Respect packet boundaries and fragment semantics

**Problem.** `parse_ipv4_packet` reads `total_len` but slices transport input to the end of the captured frame. It does not check the fragment offset. `parse_udp` and `extract_app_payload` also consume bytes beyond declared protocol lengths. A non-initial IPv4 fragment acquires invented UDP ports and a stream; padding outside an IP datagram can become a DNS query.

**Code anchors.** `src/collectors/packets/mod.rs`: `parse_ipv4_packet`, `parse_ipv6_packet`, `parse_tcp`, `parse_udp`, `extract_app_payload`, `decode_and_track`.

**Change.** Validate minimum header lengths and offsets, bound each protocol slice by its declared length and the captured bytes, and represent incomplete or fragmented traffic explicitly. Never feed non-initial fragments to transport/DPI parsing as if they contain a transport header. Share validated payload boundaries between display parsing and stream tracking. Full fragment reassembly is not required for this fix.

**Acceptance.**

- Both saved packet regression probes pass.
- Non-initial fragments create no invented ports, application classifications or transport streams.
- IP padding and bytes beyond UDP length never reach DPI or stream payloads.
- Invalid IHL/TCP offsets and truncated IPv4/IPv6/UDP/TCP inputs fail safely or render as incomplete.
- First fragments with more fragments pending do not claim a fully reassembled application message.
- Existing pcap goldens remain correct; add semantic fixtures for these cases and exercise the affected fuzz targets.

## R2 Make invalid configuration visible

**Problem.** `NetwatchConfig::load` uses `toml::from_str(...).unwrap_or_default()`. One invalid value discards the whole file silently. The reproduced case changed `sandbox = 'strict'` to best-effort and `record_uptime = false` to true because `refresh_rate_ms` had the wrong type.

**Code anchors.** `src/config.rs`: `NetwatchConfig::load`; all callers in startup and CLI paths.

**Change.** Distinguish an absent file from an unreadable or invalid existing file. Return an actionable error for the latter and handle it consistently before starting collectors or writing state. Preserve documented defaults for omitted fields in valid configurations. Do not silently replace an explicitly configured security/privacy policy.

**Acceptance.**

- A missing file starts with defaults; a valid partial file retains omitted-field defaults.
- Invalid TOML, wrong field types and unreadable existing files produce a visible error naming the path and cause.
- The reproduced invalid-refresh configuration does not start a session with weakened sandboxing or recording enabled.
- TUI, daemon, doctor and Diagnose callers handle configuration errors deliberately; script commands preserve their documented error exit statuses.
- Update the saved probe to assert the chosen error API and add an actual CLI startup regression test.

## R3 Enforce privilege handling for every live thread

**Problem.** `shutdown_deadline` spawns a raw thread before `bootstrap::start` confines main. It neither enters worker policy nor relinquishes inherited capabilities. Privileged launches therefore leave authority on a thread outside the managed boundary.

**Code anchors.** `src/app.rs`: `run`, `shutdown_deadline`; `src/sandbox/worker.rs`; `src/runtime/bootstrap.rs`.

**Existing work.** [PR #144](https://github.com/matthart1983/netwatch/pull/144), built on [PR #138](https://github.com/matthart1983/netwatch/pull/138).

**Change.** Integrate the existing capability-authority and thread-audit work after reviewing its current diff. Apply the intended least-privilege treatment to the shutdown thread and failed capture startup paths without breaking terminal recovery.

**Acceptance.**

- A per-thread audit demonstrates that the shutdown thread retains no unnecessary capability.
- Daemon, Diagnose and strict-session capability results match their documented policies.
- Best-effort TUI capture reopen paths still work; existing capture continues after intended capability drops.
- Signal, panic and stalled-terminal regression tests pass.
- Record which privileged tests ran, which skipped, and the host/kernel used. Unit policy-table checks alone do not establish runtime enforcement.

## R4 Use one socket identity representation

**Problem.** `tcp_info::endpoint` creates unbracketed IPv6 endpoint strings, while connection rows use bracketed endpoints. `LiveSampler::sockets` joins them by direct string equality. Misses lose process/rate association and missing rates become zero. The join and history cleanup also perform repeated linear searches.

**Code anchors.** `src/collectors/tcp_info.rs`: `endpoint`, `normalize_endpoint`; `src/diagnose/live.rs`: `LiveSampler::sockets`.

**Existing work.** [PR #142](https://github.com/matthart1983/netwatch/pull/142).

**Change.** Review and integrate canonical endpoint keys and indexed joins from the existing PR. Prefer typed address/port keys where practical. Keep missing association distinct from measured zero throughput when it affects a diagnostic decision.

**Acceptance.**

- IPv4, IPv6 and IPv4-mapped IPv6 join to the correct connection, process and rates.
- Unmatched sockets do not acquire another connection's data.
- Validate join and cleanup behaviour at 2k, 10k and 50k rows.
- Report join-only and whole socket-pass timings separately; do not claim that a join-only budget covers the whole pass.
- Run the relevant strict performance checks; the relaxed CI configuration is not release acceptance evidence.

## R5 Repair remote retry pacing

**Problem.** `jitter_entropy` supplies only `subsec_nanos()`, always less than one billion. `Backoff::fail` takes that number modulo a nanosecond ceiling. Once the ceiling exceeds one second, delays remain below one second instead of growing towards the configured 60-second cap.

**Code anchors.** `src/remote/mod.rs`: `jitter_entropy`, sender loop; `src/remote/queue.rs`: `Backoff::fail`.

**Change.** Generate jitter across the full current backoff interval using an appropriate entropy source or bounded generator. Keep deterministic injection for tests. Check that scheduling uses the intended reference time when an HTTP request itself takes a long time.

**Acceptance.**

- Deterministic tests cover early attempts, increasing ceilings, the cap and reset after success.
- Test the production entropy-to-delay path, not only the backoff helper with arbitrary inputs.
- A controlled fast-failing endpoint demonstrates effective pacing after repeated failures.
- Transient failures retain queued snapshots, and shutdown remains bounded.

## R6 Reject overflowing CLI durations

**Problem.** `parse_budget` multiplies the parsed integer by 60 before validating the resulting range. `18446744073709551615m` panics with overflow checks enabled. Release-build wrapping also needs explicit rejection.

**Code anchor.** `src/diagnose/run.rs`: `parse_budget`.

**Change.** Use checked conversion or validate the input before multiplying. Return the documented argument error for every out-of-range input.

**Acceptance.**

- Maximum integers, overflow-producing minute values, malformed input and values outside 5–600 seconds return errors without panics.
- Valid boundary values still work.
- Exercise the CLI error exit status in both debug and release builds.

## Release acceptance and follow-up

- Complete R1–R6, or explicitly record any accepted deferral and narrow the associated product claim.
- Run the full existing suite and meaningful regressions on one candidate commit; require Tier 1/2 CI and Clippy to pass.
- Run the planned strict reference-host performance checks and full soak. Preserve the commit, command, host, results and any skipped checks.
- Reconcile capability/security documentation with the merged implementation.
- Freeze CLI/config/JSON promises only after the above behaviour is settled.

Follow-up architecture work should extract packet decoding and consolidate endpoint identity first. Avoid a wholesale rewrite or making large-file cleanup a release gate. Additional GeoIP convenience features, diagnostic expansion and broader sandbox mechanisms remain outside this defect-fix plan unless required by an agreed release promise.

## Reproduction evidence

The review-only [probe source](review-evidence-2026-10-27/review_regressions.rs) and [failure log](review-evidence-2026-10-27/regressions.log) are preserved beside this plan. The source is intentionally outside Cargo's test discovery because its assertions fail on the reviewed commit.

To reproduce, use a disposable checkout of the reviewed commit, copy the source to `tests/review_regressions.rs`, then run:

```sh
cargo test --test review_regressions review_ -- --nocapture --test-threads=1
```

The single-thread setting isolates the configuration probe's temporary environment change. The queue probe imports production `src/remote/queue.rs` through a relative path that expects the source to be under `tests/`. Tests asserting corrected behaviour are expected to fail before fixes. Move/adapt the useful cases into normal regression tests with their respective fixes; do not introduce the entire failing review harness into CI.

Maintain this plan while the work is active. Once completed, move durable decisions into the product documentation and retire the temporary review plan/evidence in accordance with the repository documentation policy.
