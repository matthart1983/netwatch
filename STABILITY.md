# Stability

From 1.0.0, the interfaces marked stable below won't break without a 2.0. Scripts, dashboards and config files that use them keep working across every 1.x release. There is no 2.0 planned.

This takes effect at 1.0.0. Until then 0.40 and its release candidates hold to it as closely as they can, but a bug found in them can still change a contract.

## What is covered

| Interface | Status | The rule |
| --- | --- | --- |
| Subcommands and long flags | Stable | Names and meaning stay. See [the CLI](#the-cli). |
| Environment variables `NETWATCH_REMOTE_URL`, `NETWATCH_API_KEY`, `NETWATCH_METRICS_ADDR` | Stable names | As with `--remote` and `--api-key` below. |
| `config.toml` keys and `egress-policy.toml` keys | Stable | Names and meaning stay. See [Configuration](#configuration). |
| `diagnose run --format json` (schema 2) | Stable | See [JSON outputs](#json-outputs). |
| `doctor --json` (`schema_version` 1) | Stable | |
| Egress NDJSON (`netwatch.egress.v1.1`) | Stable | |
| `diagnose export` envelope (version 1) | Stable | The `episodes[]` inside are experimental, apart from each one's `schema_version`. |
| `netwatch uptime --json` (schema 1) | Stable | |
| `netwatch uptime --csv` | Stable | By header name: columns aren't renamed or removed, and new ones go at the end. |
| `diagnose run` exit codes 0, 1, 2, 3 | Stable | Exit 3 prints no JSON. |
| `netwatch geoip update [--city]` | Stable | The name, the flag and exit codes 0 and 1. The data provider and file paths are not covered. |
| Prometheus metric names and labels | Stable | New metrics and new labels' values can appear. Existing names don't change. |

## What is not covered

**Unstable.** Rules marked beta, and what `--include-beta` returns. A beta finding keeps the shape of any other finding, but its thresholds can change and the rule can go away.

**Experimental**, which can change or go in any release:

- AI Insights
- `--remote`, its snapshot format and what the backend receives
- `netwatch resolver set` and `recover`
- The JSON in PCAPNG packet comments. Saved files stay valid PCAP and PCAPNG, but the comment keys can change.
- Episode, features, corpus and replay formats
- `diagnose corpus`, `replay` and `features`, which need `--unstable`
- Anything under `[experimental]` in `config.toml`

**Not covered at all.** The TUI's layout and keybindings, all human-readable text including warnings and `report.md`, log messages, and file locations. Keybinding changes are noted in the CHANGELOG.

**The library.** The crate exposes a library so that its examples and tests can reach it. It is internal, and its API can change in any release, whatever its version number suggests.

## The CLI

A subcommand or long flag keeps its name and meaning. Removing one takes a deprecation warning for at least one minor, and the removal itself happens only in 2.0.

`--unstable` is a stable flag. What it unlocks isn't.

`--remote`, `--insecure-remote`, `--api-key` and their environment variables will keep being accepted through 1.x, so a unit file that sets them keeps starting. What they do is experimental. `--api-key` is deprecated, because a key on a command line is visible to other users on the host. It warns, and goes in 2.0.

Only `diagnose run` and `geoip update` promise their exit codes. Other commands exit 0 on success and nonzero otherwise, and the specific values aren't covered.

## Configuration

A key keeps its name and meaning. An unknown key warns and netwatch still starts, so a file written for a newer netwatch runs on an older one. A renamed key keeps working and warns.

Defaults aren't promised. A default can change in a minor, with a CHANGELOG entry, and the `[diagnose_thresholds]` defaults in particular exist to be retuned. Set a key if you depend on its value. Values that work today, including aliases such as `default_tab = "insights"`, keep working.

`insights_enabled`, `insights_model` and `insights_endpoint` keep being accepted, but what they do is experimental along with Insights.

`geoip_online` was removed in 0.39. It still parses, does nothing and warns.

## JSON outputs

Each has a schema under [`schemas/`](schemas), which the tests check real output against, and a `metadata` block saying which schema and netwatch version produced it. [REFERENCE](docs/REFERENCE.md#json-schemas) lists them.

**Consumers must ignore fields they don't know.** New fields can appear in any minor, and this is the one thing a consumer has to do to be safe. A field added after 1.0 is never `required` in an existing schema file.

**A breaking change gets a new schema version, and that needs 2.0.** Schema files are never renamed or removed, and only additive edits reach them. An added field doesn't change a version marker, and that includes the egress export's `netwatch.egress.v1.1`.

**Value sets are either closed or open, and each schema says which.** A new value in a closed set, such as `diagnose run`'s `outcome` or `severity`, or doctor's `state`, needs 2.0. An open set, such as rule ids, capability ids, reason codes, `verdict` and `proto`, can grow in a minor, so handle an unknown value.

**Free-text fields aren't covered**, such as `detail`, `next` and titles. Parse the codes beside them. `reason` is a stable code in doctor and free text in `coverage`.

**Fields marked `deprecated` in a schema** stay until 2.0, but they carry nothing useful, so don't rely on them.

**Timestamps come in three formats**, listed in [REFERENCE](docs/REFERENCE.md#json-schemas). Some are local time with no offset, so don't read those as UTC.

Some names are odder than they'd be if chosen today, such as egress `sni` also holding an HTTP `Host`, and they stay as they are.

## Rust version

`rust-version` in `Cargo.toml` is checked in CI. It can rise in a minor, with a CHANGELOG entry.

## Platforms

[CAPABILITIES](docs/CAPABILITIES.md#platform-tiers) sets out three tiers and what each means. Tier 1 is Linux on x86_64 and aarch64, tier 2 is macOS and Windows, and tier 3 is FreeBSD and armv5te. A feature can exist on one platform and not another, and that isn't a break.

## Enforcement

`tests/stability.rs` holds a config file that sets every stable key, plus the stable flags and metric names, so removing or renaming one fails CI. `tests/schemas.rs` checks real output against the schemas. Together they catch an accident, not a decision, and changing one of those lists means breaking this promise.
