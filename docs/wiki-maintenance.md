# Documentation and wiki maintenance

Edit documentation in this repository. README owns orientation; REFERENCE owns
commands, settings, keys and protocol behavior. Specialist documents own their
contracts: CAPABILITIES, THREAT-MODEL, attribution, doctor, DIAGNOSE/coverage,
INSIGHTS, PERFORMANCE, runtime lifecycle and recovery. Link to these contracts
instead of copying their tables into a second guide.

## Wiki sources and rendering

`docs/wiki/*.md` contains the public wiki's concise guides. The JSON manifest
records the release baseline, peeled release commit, review date and complete
page inventory. Existing slugs are retained for inbound links. `@repo@` links
resolve to an immutable documentation commit, not a moving branch. Wiki links
use `[[Page Name]]`; spaces resolve to hyphens. Repository readers can follow the
rendered wiki links after publication.

```sh
python3 scripts/wiki.py --check
python3 scripts/wiki.py --output /tmp/netwatch-wiki-rendered --ref HEAD
```

The output path must not exist. Rendering is deterministic: it uses the manifest
review date rather than wall-clock time. The command resolves `--ref` to a commit,
requires the maintained documentation at that commit to match the working tree,
and validates source links before writing. It emits Markdown only; it never
publishes or modifies an existing wiki checkout. Before committing sources,
`--check` validates the working tree without requiring a matching commit.

The release baseline is distinct from the documentation commit: corrections may
postdate a release. Any descriptions of later product changes must say unreleased.
Do not infer a release from Cargo.toml's version. On a release, verify the manifest
commit against the tag, update its baseline/date and review the development-only
notes before publishing.

## Publication

1. Run the documentation checks and review the rendered pages, including Home,
   Sidebar, Permissions, Sandbox, Troubleshooting and TLS Decryption.
2. Commit and push the source change so immutable documentation links resolve.
3. Clone/fetch `https://github.com/matthart1983/netwatch.wiki.git`. Record its current
   commit as a rollback point. Compare its full page inventory with the output;
   investigate unexpected remote edits rather than overwriting them.
4. Copy the reviewed generated Markdown into that checkout, review `git diff`,
   commit and push without force. A concurrent remote change requires fetching
   and reconciliation before retrying.
5. Verify public Home, Sidebar and representative deep links. Record source and
   wiki commit IDs in the PR/release evidence. Restore a prior tree with a new
   reviewed commit if rollback is needed; preserve wiki history.

Pull-request CI is read-only. It validates sources and links and never publishes.
No additional publication token or workflow is needed for this manual process.

## Change and release checklist

- Feature authors update affected reference, capability/privacy contracts, manual,
  completions and wiki summaries together. CLI option coverage already has a Rust
  test; do not maintain a second handwritten option inventory.
- Keep platform build success, smoke tests, privileged runtime acceptance and
  feature parity separate. Record untested platforms explicitly.
- Run `python3 scripts/wiki.py --check`. For CLI changes, run the existing CLI
  documentation/completion tests; for security changes, run the threat-model
  inventory tests and relevant acceptance tests.
- Review the six user journeys: unprivileged Linux setup, macOS/Windows capture,
  Diagnose coverage, process/Egress investigation, controlled TLS keylogging,
  and privacy/headless operation. Record which were actually exercised.
- Do not execute all fenced shell blocks: permission changes, probes and keylog
  examples require a disposable environment or explicitly chosen test target.
- Release maintainers verify rendered wiki baseline, installed manual and any
  remaining unreleased notes. A repository merge alone does not publish the wiki.

The checker covers the maintained documentation paths listed in its source, local
Markdown file/heading links, wiki targets and source inventory. It does not prove
semantic correctness or external URL availability. Historical plans/changelogs
are outside its blocking link scope; links *to* them still resolve. External
network checks belong in a separate, nonblocking review to avoid flaky releases.
