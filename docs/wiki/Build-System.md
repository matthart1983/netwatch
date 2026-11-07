# Build system

Use [CONTRIBUTING](@repo@/CONTRIBUTING.md) for build commands and [PACKAGING](@repo@/docs/PACKAGING.md) for release channels. Build as your normal user; configure runtime capture access separately.

[Cargo.toml](@repo@/Cargo.toml) owns the Rust minimum version and features, [Cargo.lock](@repo@/Cargo.lock) pins dependencies, and [build.rs](@repo@/build.rs) owns native build setup. Linux needs libpcap development files. Windows builds need the Npcap SDK; runtime capture separately needs Npcap installed. Windows-host SDK discovery/download and target-specific linker/manifest behavior are distinct.

See [[Dependencies]], [[Permissions]] and [[Testing]].

<!-- include: CONTRIBUTING.md#getting-started -->

<!-- include: docs/PACKAGING.md#the-channels -->

<!-- include: docs/PACKAGING.md#per-release-checklist -->
