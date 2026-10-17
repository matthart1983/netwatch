//! The release guard: what `.github/workflows/release.yml` checks, through
//! `scripts/release-guard.sh`, before it builds anything, and
//! `scripts/release.sh`, which makes a commit and tag that pass those checks.
//!
//! 0.32.2 and 0.32.3 were published from commits whose CI was red, and a
//! hand edit produced a stray v0.33.0 release commit. The workflow now
//! refuses a tag on a red commit or one that disagrees with Cargo.toml, and
//! the script replaces the hand edit. These tests keep both honest.

const RELEASE_WORKFLOW: &str = include_str!("../.github/workflows/release.yml");
const CHANGELOG: &str = include_str!("../CHANGELOG.md");

/// The jobs in a workflow, each with its lines. Reads this repository's
/// layout (job names at two spaces, their keys at four); not a YAML parser.
fn jobs(workflow: &str) -> Vec<(&str, Vec<&str>)> {
    let mut jobs: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut in_jobs = false;
    for line in workflow.lines() {
        if !line.is_empty() && !line.starts_with([' ', '#']) {
            in_jobs = line == "jobs:";
            continue;
        }
        if !in_jobs {
            continue;
        }
        match line.strip_prefix("  ").and_then(|l| l.strip_suffix(':')) {
            Some(name) if !name.starts_with([' ', '#']) => jobs.push((name, Vec::new())),
            _ => {
                if let Some((_, body)) = jobs.last_mut() {
                    body.push(line);
                }
            }
        }
    }
    jobs
}

/// The jobs a job's `needs:` names, in either the scalar or the `[a, b]` form.
fn needs<'a>(body: &[&'a str]) -> Vec<&'a str> {
    body.iter()
        .filter_map(|l| l.strip_prefix("    needs:"))
        .flat_map(|n| {
            n.trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .split(',')
        })
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect()
}

#[test]
fn every_release_job_waits_for_the_guard() {
    let jobs = jobs(RELEASE_WORKFLOW);
    let needs_of = |job: &str| {
        jobs.iter()
            .find(|(name, _)| *name == job)
            .map(|(_, body)| needs(body))
            .unwrap_or_default()
    };
    assert!(
        jobs.iter().any(|(name, _)| *name == "guard"),
        "release.yml has no guard job"
    );
    assert!(jobs.len() > 1, "found no jobs besides the guard: {jobs:?}");
    for (job, _) in jobs.iter().filter(|(name, _)| *name != "guard") {
        let mut seen = vec![*job];
        let mut pending = needs_of(job);
        let mut guarded = false;
        while let Some(next) = pending.pop() {
            if next == "guard" {
                guarded = true;
                break;
            }
            if !seen.contains(&next) {
                seen.push(next);
                pending.extend(needs_of(next));
            }
        }
        assert!(
            guarded,
            "release.yml's `{job}` job does not need `guard`, directly or through another \
             job, so it would run on a tag whose commit CI never passed"
        );
    }
}

/// The workflow's top-level permissions leave `actions` at none, which would
/// make `gh run list` fail rather than report CI's runs.
#[test]
fn the_guard_can_read_ci_runs() {
    let jobs = jobs(RELEASE_WORKFLOW);
    let (_, guard) = jobs
        .iter()
        .find(|(name, _)| *name == "guard")
        .expect("release.yml has a guard job");
    assert!(
        guard.iter().any(|l| l.trim() == "actions: read"),
        "the guard job needs `actions: read` to list CI's runs"
    );
    assert!(
        guard
            .iter()
            .any(|l| l.trim() == r#"run: scripts/release-guard.sh "${RELEASE_TAG}""#),
        "the guard job does not run scripts/release-guard.sh, whose checks the tests below cover"
    );
    assert!(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".github/workflows/ci.yml")
            .exists(),
        "the guard waits on ci.yml, which is not in the repository"
    );
}

/// The guard's second check, made here so a version bump without its
/// CHANGELOG section fails before anything is tagged.
#[test]
fn changelog_has_a_section_for_the_crate_version() {
    let heading = format!("## [{}]", env!("CARGO_PKG_VERSION"));
    assert!(
        CHANGELOG.lines().any(|l| l.starts_with(&heading)),
        "CHANGELOG.md has no `{heading}` section; the release workflow refuses a tag without one"
    );
}

/// scripts/release.sh and scripts/release-guard.sh, run in a throwaway
/// repository. Unix only, like the scripts: Windows has no bash to rely on.
#[cfg(unix)]
mod script {
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

    fn has(tool: &str) -> bool {
        let found = Command::new(tool).arg("--version").output().is_ok();
        if !found {
            eprintln!("skipping: no {tool} to run the release scripts with");
        }
        found
    }

    /// A throwaway repository shaped like this one, as far as the release
    /// scripts can tell: a crate named netwatch-tui at 0.32.3 with no
    /// dependencies, so release.sh's own `cargo test` takes a second and needs
    /// no network.
    struct Fixture(PathBuf);

    /// What a run of scripts/release-guard.sh did: whether it passed, its
    /// output, and the arguments of each call it made to `gh`.
    struct Guarded {
        passed: bool,
        log: String,
        gh: Vec<String>,
    }

    impl Fixture {
        /// None without git or bash, as in a distribution's build sandbox.
        fn new() -> Option<Self> {
            if !["git", "bash"].into_iter().all(has) {
                return None;
            }
            let root =
                std::env::temp_dir().join(format!("netwatch-release-{}", uuid::Uuid::new_v4()));
            let repo = root.join("repo");
            fs::create_dir_all(repo.join("src")).unwrap();
            fs::create_dir_all(repo.join("scripts")).unwrap();
            fs::create_dir_all(repo.join("packaging/rpm")).unwrap();
            fs::write(
                repo.join("Cargo.toml"),
                "[package]\nname = \"netwatch-tui\"\nversion = \"0.32.3\"\nedition = \"2021\"\n\n\
                 [dependencies]\n",
            )
            .unwrap();
            fs::write(repo.join("src/lib.rs"), "").unwrap();
            fs::write(repo.join(".gitignore"), "/target\n").unwrap();
            fs::write(
                repo.join("CHANGELOG.md"),
                "# Changelog\n\n## [Unreleased]\n\n### Fixed\n- Something.\n\n\
                 ## [0.32.3] - 2026-09-20\n\n### Fixed\n- Something earlier.\n",
            )
            .unwrap();
            fs::write(
                repo.join("packaging/rpm/netwatch.spec"),
                "Name:           netwatch\nVersion:        0.32.3\nRelease:        1%{?dist}\n\n\
                 %changelog\n* Sun Sep 20 2026 Someone <someone@example.com> - 0.32.3-1\n- Earlier\n",
            )
            .unwrap();
            for script in [
                "scripts/release.sh",
                "scripts/release-guard.sh",
                "scripts/tags-on-main.sh",
            ] {
                fs::copy(
                    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(script),
                    repo.join(script),
                )
                .unwrap();
            }
            let fixture = Self(root);
            let lock = fixture.cargo().arg("generate-lockfile").output().unwrap();
            assert!(
                lock.status.success(),
                "{}",
                String::from_utf8_lossy(&lock.stderr)
            );
            fixture.git(&["init", "-q", "-b", "main"]);
            fixture.git(&["config", "user.name", "Release Test"]);
            fixture.git(&["config", "user.email", "release-test@example.com"]);
            fixture.git(&["add", "-A"]);
            fixture.git(&["commit", "-q", "-m", "initial"]);
            Some(fixture)
        }

        /// As `new`, for release-guard.sh, which also needs jq.
        fn for_guard() -> Option<Self> {
            if !has("jq") {
                return None;
            }
            Self::new()
        }

        fn repo(&self) -> PathBuf {
            self.0.join("repo")
        }

        /// Isolated from the user's git configuration, which may sign commits
        /// and tags or install hooks, and from `GIT_DIR` and the rest: under a
        /// git hook, `cargo test` inherits them, and they would point these
        /// commands at the real repository.
        fn command(&self, program: &str) -> Command {
            let mut cmd = Command::new(program);
            for (key, _) in std::env::vars_os() {
                if key.to_string_lossy().starts_with("GIT_") {
                    cmd.env_remove(key);
                }
            }
            cmd.current_dir(self.repo())
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("CARGO_TARGET_DIR", self.0.join("target"));
            cmd
        }

        fn cargo(&self) -> Command {
            self.command("cargo")
        }

        fn git(&self, args: &[&str]) -> String {
            let out = self.command("git").args(args).output().unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        }

        fn release(&self, args: &[&str]) -> std::process::Output {
            self.command("bash")
                .arg("scripts/release.sh")
                .args(args)
                .output()
                .unwrap()
        }

        /// Runs release-guard.sh for `tag`, with a fake `gh` that answers each
        /// `gh run list` with the next of `answers`, repeating the last. It
        /// polls without sleeping, and gives CI 30 seconds to start and to
        /// finish unless `env` says otherwise.
        fn guard(&self, tag: &str, answers: &[String], env: &[(&str, &str)]) -> Guarded {
            let bin = self.0.join("bin");
            let _ = fs::remove_dir_all(&bin);
            fs::create_dir_all(&bin).unwrap();
            fs::write(
                bin.join("gh"),
                "#!/bin/sh\n\
                 dir=$(dirname \"$0\")\n\
                 echo \"$*\" >> \"$dir/calls\"\n\
                 n=$(( $(wc -l < \"$dir/calls\") ))\n\
                 [ -f \"$dir/runs.$n.json\" ] || n=last\n\
                 cat \"$dir/runs.$n.json\"\n",
            )
            .unwrap();
            fs::set_permissions(bin.join("gh"), fs::Permissions::from_mode(0o755)).unwrap();
            for (n, answer) in answers.iter().enumerate() {
                fs::write(bin.join(format!("runs.{}.json", n + 1)), answer).unwrap();
            }
            fs::write(bin.join("runs.last.json"), answers.last().unwrap()).unwrap();

            let path = std::env::var_os("PATH").unwrap_or_default();
            let mut paths = vec![bin.clone()];
            paths.extend(std::env::split_paths(&path));
            let out = self
                .command("bash")
                .arg("scripts/release-guard.sh")
                .arg(tag)
                .env("PATH", std::env::join_paths(paths).unwrap())
                .env("GITHUB_REPOSITORY", "owner/netwatch")
                .env("GUARD_POLL", "0")
                .env("GUARD_FIRST_RUN", "30")
                .env("GUARD_TIMEOUT", "30")
                .envs(env.iter().copied())
                .output()
                .unwrap();
            Guarded {
                passed: out.status.success(),
                log: format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                ),
                gh: fs::read_to_string(bin.join("calls"))
                    .unwrap_or_default()
                    .lines()
                    .map(String::from)
                    .collect(),
            }
        }

        /// Gives the repository an `origin` one commit ahead of local `main`,
        /// with `main` tracking it.
        fn behind_origin(&self) {
            self.git(&["clone", "-q", "--bare", ".", "../origin.git"]);
            self.git(&["remote", "add", "origin", "../origin.git"]);
            self.git(&["commit", "-q", "--allow-empty", "-m", "on the remote"]);
            self.git(&["push", "-q", "-u", "origin", "main"]);
            self.git(&["reset", "-q", "--hard", "HEAD~1"]);
        }

        /// Runs tags-on-main.sh in the repository: whether it passed, and its
        /// output.
        fn tags_on_main(&self) -> (bool, String) {
            let out = self
                .command("bash")
                .arg("scripts/tags-on-main.sh")
                .output()
                .unwrap();
            (
                out.status.success(),
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                ),
            )
        }

        fn read(&self, path: &str) -> String {
            fs::read_to_string(self.repo().join(path)).unwrap()
        }

        /// Runs the script, expects a refusal naming `reason`, and checks that it
        /// left no commit, no tag and no edit behind.
        fn refuses(&self, args: &[&str], reason: &str) {
            let head = self.git(&["rev-parse", "HEAD"]);
            let status = self.git(&["status", "--porcelain"]);
            let out = self.release(args);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                !out.status.success(),
                "release.sh {args:?} should have refused"
            );
            assert!(
                stderr.contains(reason),
                "release.sh {args:?}: expected {reason:?} in {stderr}"
            );
            assert_eq!(self.git(&["rev-parse", "HEAD"]), head);
            assert_eq!(self.git(&["tag", "--list"]), "");
            assert_eq!(self.git(&["status", "--porcelain"]), status);
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// `gh run list --json` output for runs given as (status, conclusion,
    /// event), numbered from 101.
    fn runs(list: &[(&str, &str, &str)]) -> String {
        let runs: Vec<String> = list
            .iter()
            .zip(101..)
            .map(|(&(status, conclusion, event), id)| {
                format!(
                    "{{\"conclusion\":\"{conclusion}\",\"databaseId\":{id},\"event\":\"{event}\",\
                     \"status\":\"{status}\",\
                     \"url\":\"https://github.com/owner/netwatch/actions/runs/{id}\"}}"
                )
            })
            .collect();
        format!("[{}]", runs.join(","))
    }

    #[test]
    fn release_script_bumps_every_version_commits_and_tags() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let out = fixture.release(&["0.32.4", "the security hotfix"]);
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        assert!(fixture
            .read("Cargo.toml")
            .contains("\nversion = \"0.32.4\"\n"));
        assert!(fixture
            .read("Cargo.lock")
            .contains("name = \"netwatch-tui\"\nversion = \"0.32.4\"\n"));

        let spec = fixture.read("packaging/rpm/netwatch.spec");
        assert!(spec.contains("\nVersion:        0.32.4\n"), "{spec}");
        let entry = spec.split("%changelog\n").nth(1).unwrap();
        let mut entry = entry.lines();
        let header = entry.next().unwrap();
        assert!(
            header.starts_with("* ")
                && header.ends_with("Release Test <release-test@example.com> - 0.32.4-1"),
            "{header}"
        );
        assert_eq!(entry.next(), Some("- the security hotfix"));
        assert_eq!(entry.next(), Some(""));
        assert!(spec.contains("- 0.32.3-1\n- Earlier\n"), "{spec}");

        let changelog = fixture.read("CHANGELOG.md");
        assert!(!changelog.contains("[Unreleased]"), "{changelog}");
        let date = changelog
            .lines()
            .find_map(|l| l.strip_prefix("## [0.32.4] - "))
            .expect("the Unreleased section became 0.32.4's");
        assert_eq!(date.len(), "YYYY-MM-DD".len(), "{date}");
        assert!(
            changelog.contains("\n## [0.32.3] - 2026-09-20\n"),
            "{changelog}"
        );

        assert_eq!(
            fixture.git(&["log", "-1", "--format=%s"]).trim(),
            "release: netwatch v0.32.4 — the security hotfix"
        );
        assert_eq!(
            fixture.git(&["rev-parse", "v0.32.4^{commit}"]),
            fixture.git(&["rev-parse", "HEAD"])
        );
        assert_eq!(fixture.git(&["cat-file", "-t", "v0.32.4"]).trim(), "tag");
        assert_eq!(fixture.git(&["status", "--porcelain"]), "");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("git push --atomic origin main v0.32.4"),
            "{stdout}"
        );
    }

    #[test]
    fn release_script_refuses_a_dirty_tree() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fs::write(fixture.repo().join("src/lib.rs"), "// unfinished\n").unwrap();
        fixture.refuses(&["0.32.4", "summary"], "not clean");
        fs::write(fixture.repo().join("src/lib.rs"), "").unwrap();
        fs::write(fixture.repo().join("stray.txt"), "").unwrap();
        fixture.refuses(&["0.32.4", "summary"], "not clean");
    }

    #[test]
    fn release_script_refuses_a_branch_that_does_not_match() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fixture.git(&["checkout", "-q", "-b", "diagnose-enhancements"]);
        fixture.refuses(&["0.32.4", "summary"], "on diagnose-enhancements");
        fixture.git(&["checkout", "-q", "-b", "release/0.32.5"]);
        fixture.refuses(&["0.32.4", "summary"], "on release/0.32.5");
        fixture.git(&["checkout", "-q", "--detach"]);
        fixture.refuses(&["0.32.4", "summary"], "detached");
    }

    #[test]
    fn release_script_refuses_a_version_that_does_not_follow() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fixture.refuses(&["v0.32.4", "summary"], "is not X.Y.Z");
        fixture.refuses(&["0.33", "summary"], "is not X.Y.Z");
        fixture.refuses(&["0.32.3", "summary"], "is not above the current version");
        fixture.refuses(&["0.31.9", "summary"], "is not above the current version");
        fixture.refuses(&["0.32.4"], "usage");
    }

    #[test]
    fn release_script_refuses_an_existing_tag_or_missing_notes() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fixture.git(&["tag", "v0.32.4"]);
        let head = fixture.git(&["rev-parse", "HEAD"]);
        let out = fixture.release(&["0.32.4", "summary"]);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("v0.32.4 already exists"));
        assert_eq!(fixture.git(&["rev-parse", "HEAD"]), head);
        fixture.git(&["tag", "-d", "v0.32.4"]);

        let released = fixture.read("CHANGELOG.md").replace(
            "## [0.32.3]",
            "## [0.32.4] - 2026-09-25\n\n### Fixed\n- Already out.\n\n## [0.32.3]",
        );
        fs::write(fixture.repo().join("CHANGELOG.md"), released).unwrap();
        fixture.git(&["commit", "-q", "-am", "0.32.4 notes"]);
        fixture.refuses(&["0.32.4", "summary"], "already has a 0.32.4 section");
        fixture.git(&["reset", "-q", "--hard", "HEAD~1"]);

        // A heading is not a note.
        let heading_only = fixture
            .read("CHANGELOG.md")
            .replace("- Something.\n\n## [0.32.3]", "\n## [0.32.3]");
        fs::write(fixture.repo().join("CHANGELOG.md"), heading_only).unwrap();
        fixture.git(&["commit", "-q", "-am", "a heading and no notes"]);
        fixture.refuses(&["0.32.4", "summary"], "[Unreleased]");

        let empty = fixture
            .read("CHANGELOG.md")
            .replace("### Fixed\n\n## [0.32.3]", "## [0.32.3]");
        fs::write(fixture.repo().join("CHANGELOG.md"), empty).unwrap();
        fixture.git(&["commit", "-q", "-am", "empty notes"]);
        fixture.refuses(&["0.32.4", "summary"], "[Unreleased]");

        let none = fixture
            .read("CHANGELOG.md")
            .replace("## [Unreleased]\n\n", "");
        fs::write(fixture.repo().join("CHANGELOG.md"), none).unwrap();
        fixture.git(&["commit", "-q", "-am", "no notes"]);
        fixture.refuses(&["0.32.4", "summary"], "[Unreleased]");
    }

    #[test]
    fn release_script_refuses_a_branch_behind_its_remote() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fixture.behind_origin();
        fixture.refuses(&["0.32.4", "summary"], "1 commit(s) behind origin/main");
        // Whatever main tracks, or if it tracks nothing.
        fixture.git(&["branch", "-q", "--unset-upstream"]);
        fixture.refuses(&["0.32.4", "summary"], "1 commit(s) behind origin/main");
    }

    /// A release branch made from origin/main tracks origin/main, so its
    /// upstream says nothing about origin/release/X.Y.Z, which someone else
    /// may have pushed to.
    #[test]
    fn release_script_refuses_a_release_branch_behind_its_own_remote() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fixture.behind_origin();
        fixture.git(&["checkout", "-q", "-b", "release/0.32.4", "origin/main"]);
        fixture.git(&["branch", "-q", "-u", "origin/main"]);
        fixture.git(&[
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "on the remote branch",
        ]);
        fixture.git(&["push", "-q", "origin", "release/0.32.4"]);
        fixture.git(&["reset", "-q", "--hard", "HEAD~1"]);
        // As in a clone that has not fetched it: the script has to.
        fixture.git(&["update-ref", "-d", "refs/remotes/origin/release/0.32.4"]);
        fixture.refuses(
            &["0.32.4", "summary"],
            "release/0.32.4 is 1 commit(s) behind origin/release/0.32.4",
        );
    }

    /// The release is tested before it is committed or tagged.
    #[test]
    fn release_script_makes_no_commit_or_tag_when_the_tests_fail() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fs::write(
            fixture.repo().join("src/lib.rs"),
            "#[test]\nfn red() {\n    panic!(\"red\");\n}\n",
        )
        .unwrap();
        fixture.git(&["commit", "-q", "-am", "a failing test"]);
        let head = fixture.git(&["rev-parse", "HEAD"]);
        let out = fixture.release(&["0.32.4", "summary"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "release.sh released a red commit");
        assert!(stderr.contains("cargo test failed"), "{stderr}");
        assert_eq!(fixture.git(&["rev-parse", "HEAD"]), head);
        assert_eq!(fixture.git(&["tag", "--list"]), "");
        // Left for a look, as the refusal says.
        assert!(fixture
            .git(&["status", "--porcelain"])
            .contains(" M Cargo.toml"));
    }

    /// A pre-release may be followed by its own X.Y.Z, and by nothing lower.
    #[test]
    fn release_script_follows_a_pre_release_with_its_release() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let rc = fixture
            .read("Cargo.toml")
            .replace("version = \"0.32.3\"", "version = \"0.32.4-rc.1\"");
        fs::write(fixture.repo().join("Cargo.toml"), rc).unwrap();
        fixture.git(&["commit", "-q", "-am", "0.32.4-rc.1"]);
        fixture.refuses(
            &["0.32.3", "summary"],
            "0.32.3 is not above the current version, 0.32.4-rc.1",
        );
        let out = fixture.release(&["0.32.4", "summary"]);
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(fixture
            .read("Cargo.toml")
            .contains("\nversion = \"0.32.4\"\n"));
        assert_eq!(
            fixture.git(&["rev-parse", "v0.32.4^{commit}"]),
            fixture.git(&["rev-parse", "HEAD"])
        );
    }

    /// The RPM %changelog entry is signed with git's identity; without one the
    /// script used to stop with no message.
    #[test]
    fn release_script_refuses_without_a_git_identity() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fixture.git(&["config", "--unset", "user.email"]);
        fixture.refuses(&["0.32.4", "summary"], "no user.name or user.email");
    }

    /// This hotfix's own layout: release/0.32.4 tracks origin/main, which is
    /// allowed to be ahead of it. CI does not run on the branch by itself, so
    /// the printed commands ask for it, on the tag so that it tests the tagged
    /// commit.
    #[test]
    fn release_script_on_a_release_branch_asks_for_ci() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fixture.behind_origin();
        fixture.git(&["checkout", "-q", "-b", "release/0.32.4"]);
        fixture.git(&["branch", "-q", "-u", "origin/main"]);
        let out = fixture.release(&["0.32.4", "the security hotfix"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains("git push --atomic origin release/0.32.4 v0.32.4"),
            "{stdout}"
        );
        assert!(
            stdout.contains("gh workflow run ci.yml --ref v0.32.4"),
            "{stdout}"
        );
    }

    #[test]
    fn guard_passes_a_tag_whose_ci_passed() {
        let Some(fixture) = Fixture::for_guard() else {
            return;
        };
        let passed = runs(&[
            ("completed", "success", "workflow_dispatch"),
            ("completed", "success", "push"),
        ]);
        let run = fixture.guard("v0.32.3", &[passed], &[]);
        assert!(run.passed, "{}", run.log);
        let sha = fixture.git(&["rev-parse", "HEAD"]);
        assert_eq!(run.gh.len(), 1, "{:?}", run.gh);
        assert!(
            run.gh[0].starts_with("run list -R owner/netwatch "),
            "{:?}",
            run.gh
        );
        assert!(
            run.gh[0].contains(&format!("--workflow ci.yml --commit {}", sha.trim())),
            "asked about some other commit than the tag's: {:?}",
            run.gh
        );
    }

    /// Every finished run on the commit has to have passed: a later run that
    /// passed does not clear one that failed, and the guard does not wait on
    /// the rest once one has failed.
    #[test]
    fn guard_refuses_a_tag_whose_ci_did_not_pass() {
        let Some(fixture) = Fixture::for_guard() else {
            return;
        };
        for conclusion in ["failure", "cancelled", "timed_out", "startup_failure"] {
            let run = fixture.guard(
                "v0.32.3",
                &[runs(&[("completed", conclusion, "push")])],
                &[],
            );
            assert!(!run.passed, "{conclusion}: {}", run.log);
            assert!(
                run.log.contains("::error::CI did not pass"),
                "{conclusion}: {}",
                run.log
            );
            assert!(run.log.contains("gh run rerun 101 --failed"), "{}", run.log);
        }

        let failed_then_passed = runs(&[
            ("completed", "failure", "push"),
            ("completed", "success", "workflow_dispatch"),
        ]);
        let run = fixture.guard("v0.32.3", &[failed_then_passed], &[]);
        assert!(!run.passed, "{}", run.log);
        assert!(run.log.contains("gh run rerun 101 --failed"), "{}", run.log);
        assert!(!run.log.contains("gh run rerun 102"), "{}", run.log);

        let failed_and_running = runs(&[
            ("completed", "failure", "push"),
            ("in_progress", "", "workflow_dispatch"),
        ]);
        let run = fixture.guard("v0.32.3", &[failed_and_running], &[]);
        assert!(!run.passed, "{}", run.log);
        assert_eq!(run.gh.len(), 1, "{}", run.log);
    }

    /// The tag and its commit are pushed together, so CI may not have started
    /// when the guard first looks, and then may not have finished.
    #[test]
    fn guard_waits_for_ci_to_start_and_finish() {
        let Some(fixture) = Fixture::for_guard() else {
            return;
        };
        let answers = [
            runs(&[]),
            runs(&[("queued", "", "push")]),
            runs(&[
                ("in_progress", "", "push"),
                ("completed", "success", "workflow_dispatch"),
            ]),
            runs(&[
                ("completed", "success", "push"),
                ("completed", "success", "workflow_dispatch"),
            ]),
        ];
        let run = fixture.guard("v0.32.3", &answers, &[]);
        assert!(run.passed, "{}", run.log);
        assert_eq!(run.gh.len(), 4, "{}", run.log);
        assert!(run.log.contains("Waiting on CI"), "{}", run.log);
    }

    #[test]
    fn guard_gives_up_on_ci_that_never_starts_or_never_finishes() {
        let Some(fixture) = Fixture::for_guard() else {
            return;
        };
        let run = fixture.guard("v0.32.3", &[runs(&[])], &[("GUARD_FIRST_RUN", "0")]);
        assert!(!run.passed, "{}", run.log);
        assert!(run.log.contains("::error::No CI run"), "{}", run.log);
        // On the tag: the branch's head may be another commit.
        assert!(
            run.log.contains("gh workflow run ci.yml --ref v0.32.3"),
            "{}",
            run.log
        );

        let running = runs(&[("in_progress", "", "push")]);
        let run = fixture.guard("v0.32.3", &[running], &[("GUARD_TIMEOUT", "0")]);
        assert!(!run.passed, "{}", run.log);
        assert!(run.log.contains("still running after"), "{}", run.log);
    }

    /// The tag has to be the crate's version, with a CHANGELOG section, before
    /// CI is asked about at all.
    #[test]
    fn guard_refuses_a_tag_that_is_not_the_release() {
        let Some(fixture) = Fixture::for_guard() else {
            return;
        };
        let passed = [runs(&[("completed", "success", "push")])];
        let run = fixture.guard("v0.32.4", &passed, &[]);
        assert!(!run.passed, "{}", run.log);
        assert!(
            run.log
                .contains("v0.32.4 is not the crate's version: Cargo.toml says 0.32.3"),
            "{}",
            run.log
        );
        assert!(run.gh.is_empty(), "{:?}", run.gh);

        let changelog = fixture
            .read("CHANGELOG.md")
            .replace("## [0.32.3] - 2026-09-20", "## 0.32.3");
        fs::write(fixture.repo().join("CHANGELOG.md"), changelog).unwrap();
        let run = fixture.guard("v0.32.3", &passed, &[]);
        assert!(!run.passed, "{}", run.log);
        assert!(
            run.log
                .contains("CHANGELOG.md has no '## [0.32.3]' heading"),
            "{}",
            run.log
        );
        assert!(run.gh.is_empty(), "{:?}", run.gh);
    }

    #[test]
    fn tags_on_main_passes_when_every_tag_is_in_history() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fixture.git(&["tag", "v0.32.3"]);
        fixture.git(&["commit", "-q", "--allow-empty", "-m", "later work"]);
        let (passed, log) = fixture.tags_on_main();
        assert!(passed, "{log}");
        assert!(log.contains("all 1 release tags"), "{log}");
    }

    /// The v0.35.3 layout: a hotfix tagged on a release branch that main has
    /// not merged. It fails until the branch is merged back.
    #[test]
    fn tags_on_main_refuses_a_hotfix_tag_left_off_main() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        fixture.git(&["tag", "v0.32.3"]);
        fixture.git(&["checkout", "-q", "-b", "release/0.32.4"]);
        fixture.git(&["commit", "-q", "--allow-empty", "-m", "the hotfix"]);
        fixture.git(&["tag", "v0.32.4"]);
        fixture.git(&["checkout", "-q", "main"]);
        fixture.git(&["commit", "-q", "--allow-empty", "-m", "unreleased work"]);

        let (passed, log) = fixture.tags_on_main();
        assert!(!passed, "{log}");
        assert!(log.contains("::error::v0.32.4 is not on main"), "{log}");
        assert!(!log.contains("v0.32.3 is not on main"), "{log}");

        fixture.git(&["merge", "-q", "--no-edit", "release/0.32.4"]);
        let (passed, log) = fixture.tags_on_main();
        assert!(passed, "{log}");
    }

    /// Without tags, or in a shallow clone, the check would pass for want of
    /// anything to look at.
    #[test]
    fn tags_on_main_refuses_a_clone_without_tags() {
        let Some(fixture) = Fixture::new() else {
            return;
        };
        let (passed, log) = fixture.tags_on_main();
        assert!(!passed, "{log}");
        assert!(log.contains("no v* tags in this clone"), "{log}");
    }
}
