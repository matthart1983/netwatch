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

# macOS / Linux
sudo cargo run --release

# Run tests and checks before every PR
cargo test
cargo fmt --check
cargo clippy --all-targets
```

**Linux only:** install `libpcap-dev` before building.

**Windows:** download the [Npcap SDK](https://npcap.com) and set `LIB` to the SDK's `Lib\x64` directory.

---

## Architecture overview

> **New here?** Take the interactive [Architecture Tour](docs/architecture-tour.html) — an 18-slide,
> kernel-up walkthrough of the runtime, the DPI/decryption pipeline, eBPF attribution, and the
> sandbox. Open it in a browser, or read on for the text map.
>
> **Working on the eBPF subsystem?** The [eBPF Deep Dive](docs/ebpf-deep-dive.html) is a 23-slide
> interactive deck that builds eBPF from first principles up to NetWatch's real aya kprobe — with
> drive-able simulations of the verifier, the issue-#38 timing bug, and the full
> `connect()` → process-name trace.

```
src/
├── main.rs                  — Entry point, CLI arg parsing, root error handling
├── app.rs                   — App struct (all state), event loop, tick logic
├── config.rs                — NetwatchConfig: TOML load/save, defaults
├── theme.rs                 — Color palettes
├── platform.rs              — OS-specific helpers (interface info, etc.)
├── collectors/
│   ├── packets.rs           — libpcap capture, packet parsing, stream reassembly
│   ├── connections.rs       — Active connections via lsof/netstat, timeline
│   ├── health.rs            — Gateway + DNS RTT probes
│   ├── traffic.rs           — Per-interface bandwidth accounting
│   ├── processes.rs         — Per-process bandwidth via packets + connections
│   ├── network_intel.rs     — Port scan / beaconing / DNS tunnel detection
│   ├── incident.rs          — Flight recorder (rolling 5-minute capture window)
│   ├── geo.rs               — Offline GeoIP lookups from .mmdb files
│   └── insights.rs          — Ollama AI analysis (opt-in)
└── ui/
    ├── mod.rs               — Tab dispatch: routes current_tab to the right renderer
    ├── widgets.rs           — Shared: header, footer, tab bar, format helpers
    ├── dashboard.rs         — Tab 1
    ├── connections.rs       — Tab 2
    ├── interfaces.rs        — Tab 3
    ├── packets.rs           — Tab 4
    ├── stats.rs             — Tab 5
    ├── topology.rs          — Tab 6
    ├── timeline.rs          — Tab 7
    ├── processes.rs         — Tab 8
    ├── insights.rs          — Tab 9 (opt-in)
    └── settings.rs          — Settings overlay (`,` key)
```

### Event loop lifecycle

Every iteration of the main loop in `app.rs`:

1. **Tick** (`app.tick()`) — fires on a timer (default 1s). Updates all collectors: refreshes connections, submits snapshots to insights, checks bandwidth.
2. **Event** — a terminal event (key, mouse, resize) arrives. Key events update `app` state directly. No async — everything is synchronous.
3. **Render** — `ui::render()` dispatches to the active tab's renderer based on `app.current_tab`.

State shared between threads (collectors running in background threads) is always `Arc<Mutex<T>>` or `Arc<RwLock<T>>`. The main thread only reads these during render and writes to them indirectly through the collector's public API.

---

## Adding a new tab

**Step 1** — Add the variant to `Tab` in `app.rs`:

```rust
pub enum Tab {
    // existing...
    MyNewTab,
}
```

**Step 2** — Add it to `BASE_TABS` in `ui/widgets.rs`:

```rust
const BASE_TABS: &[Tab] = &[
    // existing...
    Tab::MyNewTab,
];
```

**Step 3** — Add a label entry in `tab_label()` in `ui/widgets.rs`:

```rust
Tab::MyNewTab => ("9", "MyTab"),
```

Update the number prefix to be one higher than the last tab, and increment the `all_base_tabs_reachable` test assertion.

**Step 4** — Add scroll state fields to `App` if needed (e.g., `my_new_tab_scroll: usize`).

**Step 5** — Create `src/ui/my_new_tab.rs` with a `pub fn render(f: &mut Frame, app: &App, area: Rect)`. Use any existing tab as a template. The standard layout is:

```rust
let chunks = Layout::default()
    .direction(Direction::Vertical)
    .constraints([
        Constraint::Length(3), // header
        Constraint::Min(0),    // content
        Constraint::Length(3), // footer
    ])
    .split(area);

widgets::render_header(f, app, chunks[0]);
// render content into chunks[1]
widgets::render_footer(f, app, chunks[2], hints);
```

**Step 6** — Register the module and dispatch in `ui/mod.rs`:

```rust
pub mod my_new_tab;

// inside render():
Tab::MyNewTab => my_new_tab::render(f, &app, area),
```

**Step 7** — Add the keybinding in `app.rs` (in the global key handler):

```rust
KeyCode::Char('9') => { app.current_tab = Tab::MyNewTab; }
```

**Step 8** — Handle scroll keys for the new tab in `app.rs`. Search for `Tab::Insights` scroll handling to see the pattern.

---

## Adding a new collector

Collectors live in `src/collectors/`. A collector is typically a struct that:

- Holds shared state behind `Arc<Mutex<T>>` or `Arc<RwLock<T>>`
- Spawns a background thread in `new()` or `start()`
- Exposes a read method (e.g., `get_connections()`) that locks and clones

Minimal template:

```rust
pub struct MyCollector {
    data: Arc<Mutex<Vec<MyData>>>,
}

impl MyCollector {
    pub fn new() -> Self {
        let data: Arc<Mutex<Vec<MyData>>> = Arc::new(Mutex::new(Vec::new()));
        let data_clone = Arc::clone(&data);

        thread::spawn(move || {
            loop {
                // collect and update data_clone
                thread::sleep(Duration::from_secs(5));
            }
        });

        Self { data }
    }

    pub fn get_data(&self) -> Vec<MyData> {
        self.data.lock().unwrap().clone()
    }
}
```

Add the collector as a field on `App` and call `MyCollector::new()` in `App::new()`.

---

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

Unit tests live inline (`#[cfg(test)] mod tests`). There are no integration tests yet. Before opening a PR:

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
