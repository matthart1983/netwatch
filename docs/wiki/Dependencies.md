# Dependencies

Read [Cargo.toml](@repo@/Cargo.toml) for declared dependencies/features and minimum Rust version, and [Cargo.lock](@repo@/Cargo.lock) for resolved versions. This page deliberately does not copy version numbers.

libpcap/BPF and Npcap provide native capture; ratatui/crossterm provide the terminal UI. Protocol parsing, decryption and optional kernel integration have their own dependencies and target constraints.

See [build.rs](@repo@/build.rs), [[Build System]] and the [security policy](@repo@/SECURITY.md). Rust memory safety does not remove native-library or unsafe-FFI risk.
