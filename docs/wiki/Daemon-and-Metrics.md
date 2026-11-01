# Daemon and metrics

`netwatch daemon` runs collectors without the TUI. Remote ingestion is optional; see the [service setup](@repo@/packaging/README.md) and [command reference](@repo@/docs/REFERENCE.md#command-line).

Prefer the documented environment-variable API key to a command-line argument visible in process listings. HTTPS is required unless explicitly bypassed; bypassing it sends the key and snapshots in cleartext.

Use the [Prometheus guide](@repo@/docs/observability-export.md) for listener configuration, exposed metrics and scrape setup. Restrict listener exposure to the intended monitoring environment. See [runtime lifecycle](@repo@/docs/runtime-lifecycle.md) for shutdown/durable queue behavior and [[Configuration and Privacy]] for disclosure.
