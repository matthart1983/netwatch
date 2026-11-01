# Sandbox and security limits

Linux applies per-thread filesystem, capability and selected network policies. Available enforcement depends on kernel, architecture, mode and worker role. macOS, Windows and FreeBSD have no NetWatch sandbox backend.

Threads share memory and open descriptors. An already-open capture descriptor retains capture/injection authority; dropping capabilities does not revoke it. Main/network workers have different authority from parser/capture workers, and the SDK reader retains load capabilities. Running as root has limited containment.

This is defense in depth, not isolation against arbitrary native code or a guarantee that a compromised process cannot reach secrets. Strict mode requires its specified policy entries; it does not mean no network access for the process.

Read the [threat model](@repo@/docs/THREAT-MODEL.md), [capability matrix](@repo@/docs/CAPABILITIES.md) and [[Doctor]] for exact limits and observed enforcement. The threat model owns the policy inventory; this page does not duplicate it.
