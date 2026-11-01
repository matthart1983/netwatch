# Codebase measurements

The old v0.24.0 counts are retired. Counts vary by revision, generated code and test discovery method and do not establish quality or supported behavior.

For a checkout, `git ls-files '*.rs'` lists tracked Rust files. Use Cargo's test discovery for the relevant package, features and target rather than counting `#[test]` strings.

See [[Testing]], [[Module Reference]] and [[Platform Support]] for maintained guidance.
