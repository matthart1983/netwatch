# netwatch-ml

Offline training and evaluation for Diagnose. Nothing here ships to users.

Features come from netwatch, never from this package:

```sh
cargo run -- diagnose features --unstable --out ml/data/features.csv --schema ml/schema.json <episodes-dir>
python3 -m unittest discover -s ml/tests
```

`netwatch_ml.load` refuses a CSV whose header doesn't match `schema.json`, or a
`schema.json` whose hash doesn't match its names. Split by `Dataset.groups_of()`
(episode id) so no episode lands on both sides of a split. `labelled()` keeps
lab and expert labels only; user labels stay out until their agreement with
reviewers is measured.

`schema.json` is committed. `cargo test` fails when it is stale.
