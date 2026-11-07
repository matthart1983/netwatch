# Architecture

The TUI coordinates collectors and UI state; daemon mode runs collectors without rendering. Capture and other workers can continue independently of UI-driven updates.

Read the [architecture guide](@repo@/docs/ARCHITECTURE.md), [runtime lifecycle](@repo@/docs/runtime-lifecycle.md) and [recovery store](@repo@/docs/recovery-store.md). Sessions can persist baselines, uptime and recovery evidence as well as preferences and exports. They are not wholly ephemeral.

[[Sandbox]] describes the security boundary; [[Configuration and Privacy]] covers outbound behavior.

<!-- include: docs/ARCHITECTURE.md#runtime-architecture -->

<!-- include: docs/ARCHITECTURE.md#configuration-and-persistence -->
