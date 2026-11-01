# Contributing to NetWatch

Thanks for your interest. This guide covers everything you need to make a clean contribution.

---

## Table of Contents

1. [Getting started](#getting-started)
2. [Architecture overview](#architecture-overview)
3. [Adding a new tab](#adding-a-new-tab)
4. [Adding a new collector](#adding-a-new-collector)
5. [Adding a setting](#adding-a-setting)
6. [Error handling conventions](#error-handling-conventions)
7. [Code style](#code-style)
8. [Testing](#testing)
9. [Security](#security)
10. [Opening a PR](#opening-a-pr)

---

## Getting started

```bash
git clone https://github.com/matthart1983/netwatch
cd netwatch

# Build as your normal user; do not run Cargo as root.
cargo build --release
./target/release/netwatch doctor
./target/release/netwatch

# Run tests and checks before every PR
cargo test
cargo fmt --check
cargo clippy --all-targets
```

Use the minimum Rust version declared in `Cargo.toml` or newer.

**Linux:** install your distribution's libpcap development package (for example,
`libpcap-dev` on Debian/Ubuntu) before building. Live capture requires separate
[permission setup](docs/REFERENCE.md#permissions); ordinary builds do not.

**Windows:** download the [Npcap SDK](https://npcap.com) and set `LIB` to the SDK's `Lib\x64` directory.

---

## Architecture overview

Start with the [current architecture](docs/ARCHITECTURE.md),
[attribution evidence](docs/attribution.md) and [threat model](docs/THREAT-MODEL.md).
The [Architecture Tour](docs/architecture-tour.html) and
[eBPF Deep Dive](docs/ebpf-deep-dive.html) are historical teaching illustrations,
not current API, ownership or security contracts.

The [source map](docs/ARCHITECTURE.md#source-map) owns the module inventory.
Terminal events, UI ticks and independently running collectors have different
lifecycles; see [worker creation and shutdown](docs/runtime-lifecycle.md).

## Adding a new tab

1. Update `Tab` in `src/app.rs` and the labels/order in `src/ui/widgets.rs`.
2. Add the renderer and dispatch in `src/ui/mod.rs`, and state where the existing
   application groups the relevant UI state.
3. Update input routing and scrolling in `src/app.rs`. The digits `1`–`9` and `0`
   are already assigned; choose and document navigation without replacing an
   existing tab's shortcut. Check full, lite and dense behavior separately.
4. Update persisted tab names/aliases in `src/config.rs`, help, reference and wiki
   orientation. Preserve existing configuration aliases where appropriate.
5. Exercise navigation and relevant routing tests; assert reachable behavior,
   rather than only incrementing a tab-count assertion.

## Adding a new collector

Collectors live in `src/collectors/`. Separate preparation from starting work,
use the runtime's managed worker/policy entry mechanism, and register resource
ownership and shutdown behavior. Do not copy an unmanaged infinite thread into
`new()`; static commands such as doctor must not accidentally start collectors.

Use an existing collector with matching I/O and lifecycle needs as a template.
Define cancellation, deadlines, bounded buffers, error reporting and permitted
filesystem/network access before integrating it. Update the
[runtime inventory](docs/runtime-lifecycle.md), [threat model](docs/THREAT-MODEL.md)
and [outbound inventory](docs/THREAT-MODEL.md#outbound-inventory) when applicable.

## Adding a setting

Settings are defined in `src/ui/settings.rs`. They are indexed by integer cursor position.

1. Increment `SETTINGS_COUNT`.
2. Add a `SettingRow` entry to `build_rows()`.
3. Add the current value to `get_edit_value()`.
4. Add the mutation to `apply_edit()`.
5. Add the field to `NetwatchConfig` in `config.rs` with a `Default` value.
6. Update `full_roundtrip` test in `config.rs`.

The cursor index you use in `apply_edit()` must match the position in `build_rows()` — they are positional, not named. Count from 0.

---

## Error handling conventions

### Mutex locks

`Mutex::lock().unwrap()` is acceptable throughout. A poisoned lock means unrecoverable state — panicking is correct here.

### System calls and external commands

Functions that shell out must handle failures gracefully:

- Return `Vec::new()` or a sensible default on error.
- Store error messages in shared state for display (e.g., `PacketCollector.error`).
- Never `unwrap()` on `Command::new(...).output()` — use `match` or `?`.
- Never use shell expansion or `sh -c` — always `Command::new("binary").args([...])`.

### User input

Never `unwrap()` on data derived from user input (filter expressions, addresses, hostnames). The filter parser returns `Option<FilterExpr>` — invalid filters are silently ignored.

### Packet parsing

Validate buffer lengths before indexing. All parsers check minimum sizes (e.g., `data.len() < 14` for Ethernet) and return `None` for malformed packets. Never index into packet data without a bounds check.

### Thread spawning

Background threads that run external commands use an `AtomicBool` busy guard to prevent unbounded thread accumulation. Always check the guard before spawning a new thread.

---

## Code style

- `cargo fmt` — enforced in CI, no exceptions.
- Named constants for magic numbers. The pattern `0x02` for TCP SYN is confusing — use `TCP_FLAG_SYN`.
- `#[cfg(target_os = "...")]` for platform-specific code, not runtime checks.
- eBPF code is gated behind `#[cfg(all(target_os = "linux", feature = "ebpf"))]`.
- Prefer `Arc<Mutex<T>>` for shared mutable state between threads.
- Prefer `Arc<AtomicBool>` for simple flags.
- No `eprintln!` in library code — errors surface through the UI or collector state.

---

## Testing

Unit tests live inline (`#[cfg(test)] mod tests`); integration and acceptance tests
live under `tests/`. Some suites require namespaces, privileges or live endpoints.
Use the relevant workflow to reproduce those conditions rather than assuming
every test is offline. Before opening a PR:

```bash
cargo test                   # all tests
cargo fmt --check            # formatting
cargo clippy --all-targets   # lints
```

If you add a new tab, add it to the `tab_at_column` tests in `ui/widgets.rs` (update the count assertion and add a reachability test).

If you add a setting, update the `build_rows_count` and `full_roundtrip` tests.

---

## Security

- Never log or display secrets, API keys, or credentials.
- Packet capture data may contain sensitive payloads — the PCAP export writes raw data by design.
- eBPF programs require `CAP_BPF` / root — fail gracefully with a status bar warning, never escalate privileges programmatically.

---

## Opening a PR

- Keep PRs focused: one feature or fix per PR.
- Update `CHANGELOG.md` under `[Unreleased]` with a one-line description.
- Run `cargo test && cargo fmt --check && cargo clippy --all-targets` before pushing.
- If your change adds a new tab or setting, include a screenshot or description of the UI in the PR body.

## Unsafe code policy

Prefer safe standard-library or existing crate APIs to new unsafe code. Keep
necessary unsafe at the platform or FFI boundary. Each unsafe block needs a
`SAFETY:` comment explaining the concrete lifetime, alignment, initialization,
size and ownership assumptions that make that operation valid. Unsafe functions
need a `# Safety` contract; a safe wrapper must check every condition its caller
can violate. Null checks alone do not establish pointer validity.

Changes to an unsafe boundary require tests for malformed or short inputs where
those can be supplied safely, and checks on every affected platform. State any
platform that was only type-checked or reviewed by inspection.

The `[lints]` tables in `Cargo.toml` enforce what a compiler can see:

- `unsafe_code` flags unsafe outside a module or item that has
  `allow(unsafe_code)`. Put the allow on the smallest item that needs it, or at
  the top of a module that exists to wrap an FFI. Parsers under `src/dpi` do not
  get one, because packet bytes reach them directly.
- `clippy::undocumented_unsafe_blocks` flags a block or `unsafe impl` with no
  `SAFETY:` comment directly above it or above the statement holding it, and
  `clippy::unnecessary_safety_comment` and `unnecessary_safety_doc` flag one on
  code with nothing unsafe.
- `unsafe_op_in_unsafe_fn` requires a block, with its comment, inside an unsafe
  function.
- `missing_unsafe_on_extern` requires `unsafe extern`. Give that block a plain
  comment on how its declarations were checked. Clippy rejects `SAFETY:` there.

They are `warn`, so a `cargo install` on a newer toolchain never fails on them.
`cargo clippy --all-targets -- -D warnings` turns them into failures. `ci.yml`
runs it on Linux, macOS and Windows, and `tier3.yml` on FreeBSD. Clippy only reads
what is compiled for its target, so unsafe in a macOS branch passes on Linux and
fails the macOS job.

The lints check that a comment exists. Whether it is true is for review, as is
the `# Safety` section on an unsafe function that is not `pub`, which clippy
does not ask for.

## Documentation changes

Update the affected current reference and wiki sources together; see
[documentation ownership and release checks](docs/wiki-maintenance.md).
Run `python3 scripts/wiki.py --check` and
`python3 -m unittest discover -s tests/docs -v` for documentation tooling changes.
Changes limited to prose do not require rebuilding unrelated Rust targets.
Keep released behavior, unreleased changes and historical design intent distinct.
