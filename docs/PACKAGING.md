# Packaging

Where netwatch is distributed, what produces each package, and what to do by
hand when a release goes out.

## The channels

| Channel | Built by | Updated by | Source |
|---|---|---|---|
| homebrew-core (`brew install netwatch`) | Homebrew | Homebrew autobump, within hours of a tag | the tag's source archive |
| crates.io (`netwatch-tui`) | `publish` job in `release.yml` | every tag | this repository |
| `cargo binstall netwatch-tui` | nothing — reads `[package.metadata.binstall]` | every tag | the release tarballs |
| GitHub release binaries | `build` job | every tag | musl-static (Linux), native (macOS/Windows) |
| GitHub release FreeBSD binary | `build-freebsd` job, FreeBSD 13.5 VM | every tag, best-effort | dynamic against base libc/libpcap; runs on 13+ |
| GitHub release `.deb` / `.rpm` | `build` job, `cargo-deb` + `cargo-generate-rpm` | every tag | the same static binary |
| Fedora COPR | COPR builders from `packaging/rpm/netwatch.spec` | the `copr` job on each tag | built from source against system libpcap |
| apt repo on GitHub Pages | the `apt` job, from the release `.deb` files | every tag | the same static binary |
| Scoop (Windows) | ScoopInstaller/Main | the bucket's autoupdate bot | GitHub release |
| AUR `netwatch-tui`, `netwatch-tui-bin` | community maintainers | community | — |
| nixpkgs | community maintainer | community | — |
| conda-forge (`conda install -c conda-forge netwatch`) | community maintainer | community | the tag's source archive |
| `matthart1983/homebrew-tap` | — | **deprecated**, no longer updated | superseded by homebrew-core |

Only the first five are ours. The others are maintained by other people; if
they lag, the fix is a polite issue, not a commit here.

## The two RPMs

They are different on purpose.

- **`netwatch-<version>-1.<arch>.rpm` on the release page** repackages the
  musl-static binary. `auto-req = "no"`, no dependencies, installs on anything
  with rpm. Produced by `cargo generate-rpm` from the `[package.metadata.generate-rpm]`
  table in `Cargo.toml`.
- **The COPR package** is built from source against the system libpcap by
  `packaging/rpm/netwatch.spec`, so it has a normal `Requires: libpcap` and
  behaves like any other Fedora package.

`.deb` follows the first model only; `[package.metadata.deb]` in `Cargo.toml`
drives it, with maintainer scripts in `packaging/debian/`.

## Capabilities

No package grants capabilities. Capture needs `CAP_NET_RAW` (and `CAP_BPF` /
`CAP_PERFMON` for eBPF attribution), and a package that hands those to a binary
without asking takes a decision that belongs to the administrator. Every
post-install prints the `setcap` line instead, and CI fails the release if an
installed package ever comes with capabilities already applied.

## Per-release checklist

Most of it is automatic. By hand:

1. Write the release notes under `## [Unreleased]` in `CHANGELOG.md`, and
   commit them.
2. On `main`, or on a `release/X.Y.Z` branch for a hotfix, run
   `scripts/release.sh X.Y.Z "summary"`. It bumps the version in `Cargo.toml`,
   `Cargo.lock` and `packaging/rpm/netwatch.spec`, and adds the spec's
   `%changelog` entry. It turns `[Unreleased]` into the version's section,
   runs `cargo test`, then commits and tags `vX.Y.Z`. It pushes nothing.
3. Run the push commands it prints.

The release workflow's first job runs `scripts/release-guard.sh`, which
refuses a tag that is not Cargo.toml's version or has no CHANGELOG section.
It then waits for `ci.yml` to pass on the tagged commit, and the workflow
builds nothing unless it does. CI runs by itself only on the head of a push to
`main` and on pull requests into it. For a tag anywhere else, such as on a
release branch or on a commit pushed together with a later one, ask for CI on
the tag with `gh workflow run ci.yml --ref vX.Y.Z`. For a release branch,
`release.sh` prints that command. If CI failed, fix it and release the fix. If the failure
was flaky, re-run the failed run with the `gh run rerun <id> --failed` the
guard prints, and then the release workflow.

Once the guard passes, the workflow builds every target, produces the
packages, generates `SHA256SUMS`, attests provenance, publishes to crates.io,
and attaches everything to the GitHub release. Homebrew and Scoop follow on
their own. COPR builds when its webhook fires.

## Container image

`ghcr.io/matthart1983/netwatch`, multi-arch (amd64 + arm64), built from the
musl-static release binary on an Alpine base — about 26 MB.

```sh
docker run --rm -it --net=host --pid=host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  ghcr.io/matthart1983/netwatch
```

Each flag earns its place:

| Flag | Without it |
|---|---|
| `--net=host` | netwatch sees the container's veth, not the host's traffic |
| `--pid=host` | no process attribution: `/proc/<pid>/fd` is the container's |
| `--cap-add=NET_RAW` | packet capture fails with `socket: Operation not permitted` |
| `--cap-add=NET_ADMIN` | interface state and some probes degrade |

The image is not `scratch`. netwatch shells out to `ss` and `ip` (iproute2)
for the connection table and routes, `ping` (iputils) for gateway and internet
RTT, and `iw` for wireless signal; without `ss` in particular the Connections,
Processes and Egress tabs are simply empty. Traceroute is native on Linux and
needs no binary. `chronyc` is left out, so Diagnose reports NTP clock offset as
unmeasured rather than guessing.

Verified in the image (15-second live sample, rootless podman, host network):
DNS, gateway, link, wifi, TCP socket metrics and STUN checks all report their
inputs as available — the same profile as a host run. **Packet capture needs a
rootful container**: rootless Docker or podman cannot grant `CAP_NET_RAW`, and
capture fails even with `--cap-add`. Use `sudo docker run …`, or run netwatch
outside a container if you mainly want the Packets tab.

## The apt repository

`https://matthart1983.github.io/netwatch/apt`, served from the `gh-pages`
branch, amd64 and arm64. The `apt` job in `release.yml` copies each release's
`.deb` files into `pool/main`, rebuilds the indices with `apt-ftparchive`,
signs `Release` (both `InRelease` and the detached `Release.gpg`, for old and
new clients) and force-pushes the branch. Older packages are kept, so a user
holding a version back does not break.

Self-hosted rather than a Launchpad PPA on purpose: the `.deb` carries a
musl-static binary, so it installs on any current Debian or Ubuntu. A PPA
builds from source against the distro's Rust — 24.04 LTS is on 1.75 — and
forbids network access during builds, so every crate would have to be vendored.

**Signing key.** A dedicated 4096-bit RSA key, "netwatch apt repository",
expiring 2029-09-19. The public half is `packaging/apt/netwatch-archive-keyring.gpg`
(published to the site as `apt/netwatch.gpg`); the private half is the
`APT_GPG_PRIVATE_KEY` repository secret, with its id in `APT_GPG_KEY_ID`. It
signs nothing but this repository. To rotate: generate a new key, replace both
secrets and the file, and tell users to re-download the key — there is no
revocation path that reaches them automatically.

## Repology

Repology tracks which distributions carry netwatch and which are behind:
<https://repology.org/project/netwatch-tui/versions>.

Two unrelated programs are called netwatch — the other is a C tool from the
1990s, last released as 1.3.1 — so entries land in two projects. The AUR and
nixpkgs packages are under `netwatch-tui`; the homebrew formula was grouped
with the C tool, where 0.32.x reads as "outdated" against 1.3.1.
[repology-rules#1241](https://github.com/repology/repology-rules/pull/1241)
moves it across. Check there first if a version looks wrong on Repology.

## Channels waiting on an account

Prepared here, but each needs a login CI cannot have:

- **winget** — `packaging/winget/`, generated per release by
  `scripts/winget-manifest.sh <tag>`. Needs a fork of `microsoft/winget-pkgs`.
  Neither netwatch nor its closest competitor is on winget today.
- **AUR** — no action needed. `netwatch-tui` (source) tracks releases closely;
  `netwatch-tui-bin` lags by a release and ships no completions or man page.
  Both are other people's packages, so the most that is warranted is a comment
  on the -bin package when it falls behind.
- **nixpkgs** — no action needed. `r-ryantm`, the nixpkgs update bot, opens the
  bump PRs (it did 0.30.0), so the package catches up on its own cadence
  rather than ours. Only step in if it stalls for several releases.

## Setting up COPR (one-off)

One browser step, then a script.

1. **Get an API token.** Log in at <https://copr.fedorainfracloud.org> with a
   Fedora account, open <https://copr.fedorainfracloud.org/api/> and save the
   config block it shows to `~/.config/copr`. It looks like:

   ```ini
   [copr-cli]
   login = ...
   username = ...
   token = ...
   copr_url = https://copr.fedorainfracloud.org
   ```

2. **Run the setup.** `scripts/copr-setup.sh` creates the project, registers
   `packaging/rpm/netwatch.spec` as an SCM package against `main`, and starts
   the first build. It uses the COPR API directly, so it needs nothing
   installed beyond curl, and is safe to re-run.

3. **Wire up releases.** Add `COPR_LOGIN`, `COPR_TOKEN` and `COPR_USERNAME` as
   repository secrets; the `copr` job in `release.yml` then asks COPR to
   rebuild on every tag. Without them that job skips, so nothing breaks. This
   replaces the webhook the COPR UI offers.

4. Once a build succeeds, add to the README:
   `sudo dnf copr enable <user>/netwatch && sudo dnf install netwatch`.

The spec has not been built yet — the first COPR build is also its first real
test. Expect to iterate on `BuildRequires` once.
