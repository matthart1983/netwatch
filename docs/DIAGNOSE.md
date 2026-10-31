# Diagnose: implementation and verification

The rules engine, incident recorder, next-test loop and developer target probes
are available in the TUI and desktop. Model training and inference are not part
of this implementation.

## Developer targets

Add targets to netwatch's `config.toml`; reload with **r** in TUI coverage or restart:

```toml
diagnose_record_episodes = true

[[diagnose_targets]]
name = "staging api"
host = "api.staging.example.internal"
port = 443
path = "/healthz"
expect_status = 200
interval_secs = 60
```

`tls` defaults to true on port 443. For a plain TCP service, set `http = false`
and set `tls = false` if appropriate. Without `expect_status`, HTTP 4xx and 5xx
responses are errors; an explicit expected status takes precedence.

The desktop's **targets** control shows DNS, TCP, TLS and HTTP stages, timings,
and context. A missing or stale result says it is waiting for a fresh probe.
Probes use the host's network and direct connections. Process proxy environment,
GNOME proxy mode, VPN interfaces and container bridges are context; the probe
is not run inside another application's environment or a container. GNOME PAC
mode does not establish that a particular target needs a proxy.

TLS uses bundled public WebPKI trust roots, not an application's private trust
store. Local NTP clock error comes from synchronised `chronyc -n tracking` when
available; absent context stays unmeasured. An HTTP Date header does not provide
clock-skew evidence. See the [chrony tracking documentation](https://chrony-project.org/doc/4.8/chronyc.html#tracking).

## Diagnose an incident

1. Select an issue and inspect its evidence and possible causes.
2. In **Tests and recovery**, run the suggested test or another offered test.
   Each test shows its expected time, traffic cost and any disruption. Results
   are recorded with the incident and update its cause ranking.
3. Carry out a manual remediation, then click **I've done this** beside that
   step. Netwatch watches for recovery and repeats supporting tests. This
   records a manual action; it does not execute the instruction.
4. When the issue closes, the optional cause prompt records what actually
   happened. You can skip it or change the answer from the issue/history.

An issue closes on its own in one of two ways. It auto-closes when its verify
condition holds for its window, which means netwatch watched it recover. It
expires when what it is about has been gone for 60 seconds: the socket closed,
the target was removed from the config or its entry changed, the resolver left
the system config, the periodic trace moved to another target, or the platform
no longer lists the interface. The report then says "expired, evidence gone",
and an expiry never counts as a recovery.

An issue whose evidence has only stopped arriving stays open and shows
"stale since" and the time it stopped. A gateway that cannot be probed because
ICMP is blocked is the usual case. From this host it looks the same as a
gateway that is down. The socket collector refreshes only in the Dense view
and under `netwatch diagnose run`, so in the Full and Lite views a socket issue
goes stale instead of expiring.

Muting an issue (`m`) quiets it for an hour and does not close it. It leaves
the issue list and the verdict, which says how many it left out ("1 muted"),
and the chronology shows it as `◌ muted until` and the time. The report lists
it under Muted findings, not as closed. Netwatch keeps watching it: the same
condition does not open a second issue, and the muted issue still auto-closes
or expires as above. A muted root cause keeps its consequences under it, so a
symptom does not take its place in the verdict. When the hour is up, an issue
that has not closed is open again.

## History and sharing

**Incident history** lists the latest 100 saved incidents, including their
issue timelines, evidence, tests, actions, verification and labels. An active
incident appears after the recorder finishes it, including its post-roll.
Reopen history to refresh the list. Saved incidents can be labelled after the
original engine session has ended.

**Export incidents…** previews the last seven days of saved recordings. It
shows included episodes, replaced/removed field counts and skipped files before
**Save pseudonymised bundle** writes the file. No upload occurs. The existing
report export is a separate local report containing local detail.

Episode exports replace addresses and target identities with keyed tokens,
hash routing domains and remove free-text notes, diagnostic details, remediation
text, process names and artifact paths. Local recordings retain their original
detail. Bundles are written atomically with owner-only file permissions on Unix.
The per-install key stays on the device; exports are pseudonymised, not anonymous.

CLI equivalents:

```sh
netwatch diagnose episodes
netwatch diagnose replay /path/to/episode.json.gz
netwatch diagnose export --since 7d --dry-run
netwatch diagnose export --since 7d --out /path/to/bundle.json.gz
```

## Validation boundary

Automated coverage includes each P3 cause, local HTTP probes, HTTP 407 handling,
NTP parsing, live/replay parity, redacted target replay, private export files and
a simulated 24-hour storage/replay check. The simulation is not a live
24-hour workstation soak.

The privileged namespace fault lab (M1), actual workstation soak and pilot
release gates remain. Before ML evaluation, add independent monitored-time and
alert accounting, historical baseline inputs, and an explicit DNS/target family
mapping. Current QuietSample recordings alone do not establish false alerts per
device-week or supply a week of baseline history.


## One bounded diagnosis

```sh
netwatch diagnose run --budget 30s
netwatch diagnose run --target api --budget 2m --format json
```

Runs for the budget, then reports what it found and exits. Exit statuses are
part of the interface:

| Exit | Meaning |
| --- | --- |
| 0 | completed, no issue — the rules that could be evaluated did not fire |
| 1 | completed, at least one open issue |
| 2 | incomplete — no usable observation arrived inside the budget |
| 3 | bad arguments, or the session could not start |

An issue from a beta rule (one whose contract is not yet reviewed; see
[diagnostic-coverage.md](diagnostic-coverage.md#not-yet-contracted)) is reported, tagged
`beta`, but sets exit 1 only with `--include-beta`.

Exit 0 and exit 2 are deliberately different. A run that gathered nothing has
established nothing, and a script that treats silence as health will report a
dead link as a healthy one. Without `--target`, a measured gateway, a measured
resolver or a completed target probe counts as evidence. A gateway probe that
could send nothing, because ICMP is blocked and the gateway answers no TCP port,
does not. With `--target`, only that target's own probes count: another target
completing says nothing about this one.

Only an issue sets exit 1. An observation, such as a symmetric NAT or a route
change that added 20 ms or less, is reported but says nothing is wrong, so a
host whose only finding is an observation exits 0. Text output lists
observations under their own heading, after the issues.

With `--target`, the run reports the findings about that target, the findings
that explain one of them, such as a gateway failure that hides the target's
own, and the host, interface and resolver issues that could lie on the
target's route. An issue that names an interface or resolver the target's
lookup did not use is left out, and so is a resolver issue when the target is
an address. A target on a loopback address keeps only an issue that hides one
of its own findings. Nothing lies on a target's route until a probe of it
arrives, so a target that is disabled, or not probed inside the budget, exits
with status 2 whatever else is open. A failure of the service itself, such as
a refused port, an HTTP 503 or a name that does not exist, is reported as a
medium issue and exits 1. The Diagnose tab lists it as an info observation
marked "service, not network", because the network is not at fault; the run
was asked whether the target works.

Budgets accept `30s`, `2m` or a bare number of seconds, between 5s and 10m.
JSON output carries the ruleset size, the sampling window, the coverage object
and the findings, so a support engineer can see what was evaluated rather than
inferring it from an empty list. It is `"schema": 2`: `issues` holds issues
only, `observations` holds the rest, and each finding carries a `kind` of
`issue` or `observation`. Each check carries a `state` of `passed`, `failed`
or `not_run`, and a `why_not` when it did not run. Schema 1 listed
observations under `issues` and wrote `passed` (`true`, `false` or `null`) on
each check; recordings that carry `passed` still load.
[`schemas/diagnose-run.v2.schema.json`](../schemas/diagnose-run.v2.schema.json)
describes the output, and [JSON schemas](REFERENCE.md#json-schemas) has the
rules it follows. `diagnose export` has
[its own](../schemas/diagnose-export.v1.schema.json), which covers the bundle
and not the recordings in it.

## Thresholds

The engine's thresholds live in a `config.toml` table. These are the defaults,
and a key left out keeps its default:

```toml
[diagnose_thresholds]
sigma_k = 3.0              # σ multiple of the baseline that counts as a deviation
sigma_close_k = 2.0        # σ multiple an issue must fall below to close
sigma_floor_ms = 0.5       # smallest σ a baseline is judged against
sigma_floor_pct = 5.0      # or this percentage of the baseline's mean, if larger
gateway_delta_floor_ms = 10.0  # ms the gateway must be slower than its mean, too
dns_delta_floor_ms = 5.0   # ms a resolver must be slower than its mean, too
dns_delta_multiple = 2.0   # and the multiple of its mean it must reach
consecutive_n = 3          # samples a condition must show before an issue opens
verdict_hold_secs = 30     # how long a socket verdict must persist
dns_ceiling_ms = 100.0     # a resolver median above this is slow, baseline or not
socket_rtt_ms = 100.0
loaded_rtt_delta_ms = 100.0
saturation_pct = 90.0
iface_error_floor = 1.0    # interface errors per minute
iface_drop_floor = 60.0    # interface drops per minute
dns_tc_pct = 10.0
dns_mismatch_pct = 50.0
wifi_rssi_dbm = -70.0
wifi_retry_pct = 20.0
```

A value that cannot mean anything (a σ multiple of 0 or less, a negative σ
or delta floor, `consecutive_n = 0`, a percentage outside 0–100, `nan` or
`inf`) is replaced by its default and logged; `diagnose run` and `diagnose
coverage` also print it to stderr. So is a `sigma_close_k` at or above
`sigma_k`: it becomes 2, or two thirds of a `sigma_k` of 2 or less. The
table is read at startup, and coverage's **r** reload leaves it alone: each
recorded episode keeps the thresholds it ran with, so a replay judges it by the
same numbers. An episode recorded before a threshold existed replays with that
threshold's default: one from before 0.34 is judged against the σ and delta
floors and the 2σ close line it ran without.
`--generate-config` and the Settings editor's save write the table only once it
differs from the defaults. Then they write every key, and a key in the file
keeps its value when a later release retunes that default.

Every σ is floored before it is used. A resolver that answers from cache in
1.2 ms, give or take 0.05 ms, is judged as if σ were 0.5 ms, so 3σ is 2.7 ms
rather than 1.35 ms, and a 40 ms resolver is judged against at least 2 ms. The
Dashboard's latency tiles show the floored σ too. Setting both floors to 0
judges the raw σ.

Many σ can still be a move nobody feels, so two rules also need an absolute
rise. `gateway.rtt_spike` needs the gateway 10 ms slower than its mean: a wired
gateway moving from 2 to 9 ms is 14σ over the floor. `dns.slow_resolver` needs
the resolver's median 5 ms slower than its mean and at least twice it before
its baseline opens an issue: a LAN resolver moving from 1.2 to 2.7 ms is 3σ,
and a 30 ms resolver at 35 ms is more than 3σ. So a LAN resolver slowing from
1 to 4 ms is never reported, on purpose. The 100 ms ceiling does not wait for
a baseline. Setting these three to 0 judges by σ alone. The Dashboard's tiles
do not apply them, so a move under these floors can turn one red with no issue
raised.

`gateway.rtt_spike`, `path.rtt_spike` and `target.slow_stage` open at 3σ and
close only once the metric has stayed under 2σ for the verify hold. With one
line for both, a gateway hovering at 3σ closed each time it dipped under for
two minutes and reopened each time it rose. A noisy link now takes longer to
close.

`dns.slow_resolver` closes once the resolver's median has stayed under one
line for 60 s, set when the issue opens: 0.8 of the line it opened on, or 2σ
above the resolver's mean if that is higher. The line it opened on is the
lower of the ceiling and the baseline's line. A router answering in 10.5 ms
opens at 21 ms and closes under 16.8 ms; with no baseline the line is 80 ms,
0.8 of the ceiling. The close line used to be a flat 5 ms, which a router
answering in 10 ms never meets, so an issue opened on one stayed open until
netwatch restarted. The line is in ms and does not follow the baseline, so an
issue whose median settles between the two lines stays open until netwatch
restarts or the resolver leaves the config, even after the baseline has
learned the new median.

`sigma_k` also sets what the baselines learn: a reading that many σ or more
above normal is left out, so an incident does not become the new normal. A
reading between `sigma_close_k` and `sigma_k` is learned, so a
`gateway.rtt_spike`, `path.rtt_spike` or `target.slow_stage` issue that
settles there closes once its baseline has caught up with it. A low value
leaves out ordinary peaks too, so the saved baselines settle lower and flag
more, and they take time to relearn after the value is raised again.

## Diagnose coverage in terminal Netwatch

Press **9**, then **c** to inspect every check. Use **↑/↓** to select a row.
The detail shows its input source, source completion age, reason and next action.
Press **t** on a path, target, NAT or local-bufferbloat row to request a measurement.
Paths trace `1.1.1.1`; run twice for a comparison. Target rows use
`[[diagnose_targets]]` from config.toml. STUN uses Google and Cloudflare.
The manual load test uploads up to 25 MB to `speed.cloudflare.com` and can slow
other traffic. It requires no open incident. Its result expires after 30 minutes.

For a bounded live audit:

```sh
cargo run --release -- diagnose coverage
cargo run --release -- diagnose coverage --json --seconds 30 > coverage.json
```

The command samples for 10 seconds by default (1–30 seconds allowed), reads
existing network baselines without updating them, and reports incomplete or
still-running inputs honestly. It does not reproduce a previous TUI session.
The JSON is a local audit containing interface and configuration/error details;
use the incident redaction/export workflow when sharing incident recordings.

Ready, learning, not configured, no subjects, not applicable, awaiting test,
permission denied, collector failed, stale and not implemented are separate
states. A successful TCP dump with no established connections is **no subjects**.
TCP scope is this network namespace. Retransmission checks need a full minute
of counter observations; lifetime totals and absent fields are not a rate.

Linux Wi-Fi signal collection falls back to `iw dev <interface> link` when the
legacy `/proc/net/wireless` reading is absent. The fallback has a 500 ms deadline.
Wireless saturation remains unsupported: PHY bitrate does not measure usable
capacity. Invalid or duplicate target configurations are explained in coverage;
changed target configurations cannot reuse old probe results.

All 30 catalogued rules now have implementations. Ready inputs still depend on
capabilities, configuration and completed measurements; implemented does not mean
every check applies to this network.


## Egress checks

`egress.drift` reports a newly observed public destination after learning a
process name's destinations for 10 minutes of observed activity. It can use
persisted destinations with at least 600 observations spanning 10 minutes.
The session comparison set then stays fixed, so a new destination does not
immediately become normal just because the program contacts it again.
This informational finding does not mean the traffic is malicious. Process
names are not verified executable identities; local/private destinations and
unattributed connections are outside this check's scope.

`egress.policy_violation` compares observed destinations with the loaded policy
in `~/.config/netwatch/egress-policy.toml` (or the XDG config location). It warns;
it does not block connections. No policy is **not configured**; unreadable,
invalid or unsafe-permission policy files report **collector failed**. Traffic
without an applicable rule, or with an encrypted destination name, is not
silently counted as allowed. In strict policy mode, an undeclared process must
first appear in three profiler observations before it can become a finding.

In Diagnose coverage (**9 → c**), select `egress.policy_violation` and press
**t** to reload the policy after editing/reviewing it. Reloading an unchanged
policy preserves the existing notification cooldown. Diagnose never promotes
learned traffic into permissions or rewrites the policy. The existing Egress
review workflow remains the place to make deliberate policy changes.

Both rules require distinct completed connection snapshots before opening.
They retain one incident per process/destination/port, suppress matching drift
under a policy violation, and require five minutes without the condition before
closing. Closure can mean the connection disappeared; it does not prove a
program was repaired. Missing attribution, truncated observations, stale
samples, failed connection-table commands, lost hostname visibility and
invalid/missing policy cannot verify a policy fix.

Recordings include the policy digest and contemporaneous verdicts, so replay
keeps historical policy decisions intact. Export pseudonymizes process and
destination identities while preserving replay. Observations are bounded to
128 destinations per frame; a truncated snapshot cannot prove disappearance.
The shared cause/feature schema was refreshed for compatibility; no ML model
was added or trained.

## TCP namespace measurements

`tcp.connect_failures` reads Linux `Tcp: AttemptFails`, using a full elapsed
minute and rejecting counter resets and collection gaps. This counts failed
**active and passive TCP handshakes in the current network namespace**. It does
not identify a process or distinguish refusal, timeout and resource exhaustion.
More than five failures/minute, confirmed by distinct snapshots, opens a finding.

`tcp.timewait_exhaustion` retains its compatibility ID but reports informational
**TIME_WAIT pressure**. It counts distinct local ports within the configured
ephemeral range for each local address, and reports the highest occupancy.
Multiple destinations using the same local port count once. Above 60% opens a
finding; this does not prove exhaustion because TCP allocation depends on tuples
and reuse rules. Both checks require measured recovery rather than missing data.
Linux TCP tables are limited to 4 MiB each; incomplete tables cannot establish
port occupancy. Interface error counters also require a full elapsed minute,
independent of the configured screen refresh rate.

Counter semantics: [RFC 1213, tcpAttemptFails](https://www.rfc-editor.org/rfc/rfc1213).

## IPv6, captive portal and PMTU experiments

Open **9 → c**, select a check and press **t**. Each experiment takes three
separate rounds, with 15 seconds between rounds. Cached screen updates do not
count as new measurements. **x** cancels active measurements; partial cancelled
results are discarded. Results expire after two minutes without a new round.
No active experiment runs automatically by default.

| Check | What establishes a finding | What remains inconclusive |
|---|---|---|
| `ipv6.broken` | IPv6 default route and global address exist; IPv4 connects but IPv6 fails for at least two independent configured endpoint pairs | One endpoint fails, or both families fail. An IPv4-only network is not applicable. |
| `captive.portal` | Independent expected-response HTTP endpoints return redirects in three rounds | Timeouts, server errors, unexpected non-redirect content, or disagreement between endpoints. The finding says interception is suspected. |
| `pmtu.blackhole` | Small DF ping works, large DF ping times out, a normal HTTP transfer fails, and the same pinned endpoint transfers at least 4096 bytes with MSS 536 | ICMP filtering alone, a dead endpoint, a packet-too-big response, or transfer failure without successful smaller-segment corroboration. |

Portal probes never follow redirects or attempt login. They retain counts and
outcomes, not redirect locations. HTTP probes use direct connections without a
proxy and bound response reads to 64 KiB. Probe URLs must be plain HTTP without
credentials, query strings or fragments. The PMTU experiment changes TCP segment
size on its own socket only; it does not change the host/interface MTU. Recovery
requires a working transfer on the same tested path, not a fixed 1400-byte cutoff.
Windows has no way to set one socket's segment size, so there the PMTU check is
listed as unsupported, and **t** and `netwatch diagnose coverage --test
pmtu.blackhole` refuse it.
These selected-endpoint experiments do not suppress unrelated DNS/TCP findings.

Default IPv6 pairs are Cloudflare and Google DNS addresses on TCP 443. Default
portal endpoints are `connectivitycheck.gstatic.com/generate_204` and
`cp.cloudflare.com/generate_204`. Configurations permit 2–4 independent pairs or
HTTP hosts. Per three-round run, the bounds are 24 TCP connections for IPv6,
12 HTTP requests for portal checks, or six DF pings and six bounded HTTP requests
for PMTU. On Linux, DNS subprocesses are killed/reaped after three seconds; connections
and stream operations have separate deadlines. Other platforms keep native name
resolution behind a three-second caller deadline and a single shared worker; an
OS lookup already running may continue after cancellation. One active experiment runs at a
time. Failed experiments do not retry indefinitely.

Add this table to `~/.config/netwatch/config.toml` (or its XDG location):

```toml
[diagnose_probes]
trace_target = "1.1.1.1"
# Optional automatic traces, 30–3600 seconds; omitted means manual only:
# trace_refresh_secs = 120

# Replace with a controlled HTTP resource returning status 200 and >=4096 bytes:
# pmtu_url = "http://192.0.2.10:8080/test-data"

# Optional replacements for the built-in IPv6 pairs and portal endpoints:
# ipv6_pairs = [
#   { v4 = "1.1.1.1:443", v6 = "[2606:4700:4700::1111]:443" },
#   { v4 = "8.8.8.8:443", v6 = "[2001:4860:4860::8888]:443" },
# ]
# portal_endpoints = [
#   { url = "http://connectivitycheck.gstatic.com/generate_204", expect_status = 204 },
#   { url = "http://cp.cloudflare.com/generate_204", expect_status = 204 },
# ]
```

Press **r** in coverage to reload Diagnose configuration. A passive CLI audit can
wait long enough to collect the one-minute TCP window:

```sh
./target/release/netwatch diagnose coverage --json --seconds 65
./target/release/netwatch diagnose coverage --json --test ipv6.broken
./target/release/netwatch diagnose coverage --json --test captive.portal
```

`--test` runs the requested experiment; without it, the audit does not start these
experiments. A test audit defaults to 90 seconds; `--seconds` accepts 1–120.
The JSON includes experiment outcomes and progress. A shorter audit can end
before three rounds finish; incomplete evidence does not confirm an issue.

## Target setup, baselines and cancellation

```toml
[[diagnose_targets]]
name = "development API"
host = "127.0.0.1"
port = 8080
http = true
tls = false
path = "/health"
expect_status = 200
interval_secs = 60
enabled = true
```

On a target coverage row, **[ / ]** selects a configured target. Its DNS, TCP,
TLS and HTTP stages show timings or failure reasons. **d** enables/disables the
selected target and saves the setting; **r** reloads edited configuration;
**t** probes enabled targets now. Disabled targets do not send probe traffic.
Configuration changes select a separate baseline identity and invalidate cached
results. A healthy replacement endpoint cannot verify an old endpoint's issue.
Old recordings without configuration identities remain readable.

Changes to the observed interface/gateway/resolver/subnet fingerprint invalidate
target, trace, health and active-test results and
reset the sampler's histories. Cancellation stops new requests and discards
late results; an operation already in progress may take its bounded timeout to
return. STUN now reports resolution, send, receive and malformed-response errors,
and only a complete two-server mapping comparison is usable.

## Rule coverage document

`docs/diagnostic-coverage.md` is generated from the catalogue:

```sh
netwatch diagnose coverage --doc
```

A test fails when the committed copy and the catalogue disagree, so the
document cannot drift from the rules again.

## Pinned replay corpus

`tests/diagnose/corpus/` holds recorded episodes and the decisions each must
keep producing: which issues open, when, what each is blamed on, and why each
left the list (`close_reason`: auto-closed, expired, resolved, muted,
suppressed, or pruned when the history limit dropped it on the tick it
closed).
The replay test compares against those files rather than against a recording
it just made, so a change that moves both sides still shows up.

`manifest.toml` lists every episode, and the test checks each row by name. A
`synthetic` row is built by a scenario in `src/diagnose/fixture.rs`; it must
still be what that scenario records, and must also replay to its own
recording. A `lab` row keeps the frames the health lab recorded, and only its
decisions are derived again.

```sh
netwatch diagnose corpus              # regenerate after an intended semantic change
netwatch diagnose corpus --only ID    # one manifest row
```

A diff there is a change in what netwatch concludes, and belongs in the same
review as the code that caused it.

Every rule whose open condition or close line changed since 0.32 is listed in
`TOUCHED_SINCE_0_32` in `src/diagnose/episode.rs`, and a test fails unless a
corpus entry that lists the rule both opens it and closes it by its verify. For
the socket rules an expiry once the socket closes counts too. A rule that cannot
close yet has a `PENDING_CLOSE` row there saying why: `iface.errors`, whose
close line a Wi-Fi driver's background drops never let it reach. Another test
fails once such a rule closes, so its row goes in the same change.

## Reproducible verification

```sh
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo build --examples
unshare --user --map-root-user --net python3 tests/diagnose/fault_lab.py
python3 tests/diagnose/health_lab.py --quick
cargo run --example diagnose_live_check -- /tmp/netwatch-live-new
cargo run --example diagnose_active_live -- /tmp/netwatch-active-new
cargo run --example diagnose_soak -- /tmp/netwatch-soak-new 600
```

Use new scratch directories for live examples. The fault lab requires Linux,
unprivileged user/network namespaces, `ip`, `nsenter`, `tc`, `ethtool` and `ping`.
It changes routes, packet-drop filters and the ephemeral range **only inside its
throwaway namespace**. It also exercises a socket-denying seccomp policy in the isolated probe process.
It exercises working and broken IPv6, expected responses,
redirects, HTTP errors/timeouts, actual dropped-large packets, lower working MTU,
ICMP filtering, endpoint failure, real TCP handshake counters and port pressure.
Integration tests verify distinct samples, missing-data safety, recovery,
recurrence, endpoint scope, old recordings, and full/redacted replay.

The health lab needs `cargo build --example diagnose_lab` first, and a mount
namespace as well: it remounts sysfs, mounts a `resolv.conf` naming 192.0.2.2
in place of the host's, and gives a peer namespace 1.1.1.1, **only inside its throwaway
namespaces**. It then runs `diagnose_lab`, the real `App::tick` once a second,
which refuses to start unless its home, cache, config and state directories are
inside the temp home the lab created. `--smoke` runs 60 seconds healthy and
asserts that the gateway, DNS and internet probes measured the lab's addresses
and that nothing opened.

`--quick` runs the smoke and each scenario in its own namespaces, all at once,
in about six minutes, and writes every open and close time to
`health-lab.json`; `--artifacts DIR` keeps each run's JSON lines and the
episodes it recorded. A scenario stages one fault — a slow, dead or lossy
resolver, total loss or ICMP delay toward the gateway, delay beyond it, or a
healthy 1 ms link — and asserts which rules open within how long, which are
listed under which, which close once it clears, and which must never appear.
A scenario that expects nothing to open also fails if a rule it forbids lost
its input during the fault, since a rule without input cannot open.
The scenarios are rows of data in `health_lab.py`, each window at least twice
what today's rules should take, so a change to a rule's timing changes a row.
`--long` runs the negatives too slow for every change, such as 20 minutes of
1% resolver loss that must never open `dns.failing`. CI runs `--quick` on every
push to `main` and on pull requests that touch Diagnose, the health prober or
the lab, as a `ci.yml` job, so the release guard holds a tag until it passes;
`--long` runs once a week. The faults are netem qdiscs, so `tc` needs
`sch_netem`, `sch_prio` and `cls_u32` available.

The workstation soak records actual observed seconds, stalls, worker count,
resident memory and state size. Its duration is a bounded stability check, not a
long-term false-alert-rate estimate. No ML model is trained by these changes.
