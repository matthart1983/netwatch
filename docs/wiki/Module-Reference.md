# Module reference

Use the [source tree](@repo@/src) and [architecture guide](@repo@/docs/ARCHITECTURE.md) for current modules.

- `src/app.rs`: application state and input dispatch.
- `src/collectors/`: measurements, capture and enrichment.
- `src/dpi/`: protocol parsing and decryption.
- `src/diagnose/`: diagnostic evidence, rules and experiments.
- `src/platform/`, `src/sandbox/`, `src/ebpf/`: platform interfaces and policy boundaries.
- `src/ui/`: rendering; `src/config.rs`: configuration.

See [[Build System]] and [[Testing]]. Copied struct definitions and line counts are not maintained here.

<!-- include: docs/ARCHITECTURE.md#source-map -->

<!-- include: CONTRIBUTING.md#adding-a-new-collector -->
