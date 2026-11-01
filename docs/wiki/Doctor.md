# Doctor

`netwatch doctor` reports setup without starting normal collectors. `netwatch doctor --json` provides versioned structured output. Static configuration and library availability are not live health verdicts.

`netwatch doctor --check-capture` opts into a bounded capture-open check; `--interface NAME` selects the interface for that check. Its result describes the isolated check, not every future session or complete packet visibility.

See the [doctor guide](@repo@/docs/doctor.md) for reason codes, platform behavior and the distinction between static, checked and session-observed capabilities. Continue with [[Troubleshooting]] or [[Permissions]].

<!-- include: docs/doctor.md -->
