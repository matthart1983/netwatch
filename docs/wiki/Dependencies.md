# Dependencies

Read [Cargo.toml](@repo@/Cargo.toml) for declared dependencies/features and minimum Rust version, and [Cargo.lock](@repo@/Cargo.lock) for resolved versions. This page deliberately does not copy version numbers.

libpcap/BPF and Npcap provide native capture; ratatui/crossterm provide the terminal UI. Protocol parsing, decryption and optional kernel integration have their own dependencies and target constraints.

See [build.rs](@repo@/build.rs), [[Build System]] and the [security policy](@repo@/SECURITY.md). Rust memory safety does not remove native-library or unsafe-FFI risk.

## Which dependency matters for which task?

| Component | Role | Operational consequence |
| --- | --- | --- |
| Rust toolchain | Builds the application and dependencies. | Use `rust-version` from Cargo.toml or newer; do not infer it from an old wiki version. |
| libpcap/BPF | Native capture on Unix platforms. | Source builds may need development headers/libraries; runtime access is a separate permission issue. |
| Npcap | Windows capture driver/library. | The SDK enables linking; installing the SDK alone does not install working runtime capture. |
| ratatui/crossterm | Terminal rendering and input. | Terminal size, capabilities and view selection affect presentation. |
| Optional Linux eBPF integration | Kernel connection evidence. | Feature compilation does not prove successful kernel loading or verified ownership. |
| Local GeoIP databases | Country/ASN/city enrichment. | Database installation/update is separate from address lookup. |
| Ollama-compatible endpoint | Optional AI narrative. | Deterministic diagnostics work without it; enabling it discloses summaries to that endpoint. |

## Inspect a checkout reproducibly

```sh
rustc --version
cargo metadata --locked --no-deps --format-version 1
cargo tree --locked -e features
```

Record the checkout commit and target when comparing dependencies. Cargo commands
can fetch registry metadata/packages if they are not cached; use `--offline` only
when your local cache is complete. The lockfile records resolved dependencies,
while target-specific features determine which code is actually built.
