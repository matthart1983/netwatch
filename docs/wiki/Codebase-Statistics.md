# Codebase measurements

The old v0.24.0 counts are retired. Counts vary by revision, generated code and test discovery method and do not establish quality or supported behavior.

For a checkout, `git ls-files '*.rs'` lists tracked Rust files. Use Cargo's test discovery for the relevant package, features and target rather than counting `#[test]` strings.

See [[Testing]], [[Module Reference]] and [[Platform Support]] for maintained guidance.

## Record the revision first

```sh
git rev-parse HEAD
git status --short
git ls-files '*.rs'
```

A dirty checkout can differ from the recorded commit. Include the package, target
and feature selection with test/build measurements. For discovered tests:

```sh
cargo test --locked -- --list
```

This builds test targets and may download dependencies; it is not a lightweight
source-text count. It lists tests for the selected build configuration and does
not prove that ignored, privileged or live-service tests were executed.

## Measure the property you need

| Question | Useful evidence | Misleading substitute |
| --- | --- | --- |
| Is this platform usable? | Platform CI and explicit runtime acceptance. | Number of conditional-compilation branches. |
| Does capture keep up? | Offered/decoded rates, drops, hardware and workload. | Source-file count. |
| Is a parser covered? | Supported and malformed-input fixtures, fuzzing results and known gaps. | Total test count. |
| How much memory is retained? | Buffer budgets and measured RSS under a stated workload. | Lines of Rust. |

The performance page contains reproducible workload commands and measured scope.
Source size is useful for navigation and maintenance planning; it is not an
adoption, correctness or security metric.

<!-- include: docs/PERFORMANCE.md#memory-ceiling -->
