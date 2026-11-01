# Testing

Follow [CONTRIBUTING](@repo@/CONTRIBUTING.md) for formatting, Clippy and ordinary Rust tests. CI configuration is the authority for the platform matrix and required jobs.

[Workflows](@repo@/.github/workflows) separate normal CI, platform checks, fault/health labs, sandbox acceptance, external GeoIP checks, fuzzing and flood/soak runs. Some tests use namespaces, privileges, sockets or live services; do not assume every test is offline or unprivileged.

Test counts are not a coverage guarantee. [Capabilities](@repo@/docs/CAPABILITIES.md), [attribution](@repo@/docs/attribution.md) and [performance](@repo@/docs/PERFORMANCE.md) distinguish measured results from pending acceptance.

Run `python3 scripts/wiki.py --check` for maintained documentation links and wiki sources. See [wiki maintenance](@repo@/docs/wiki-maintenance.md).
