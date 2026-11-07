//! `netwatch diagnose run` argument errors, through the real binary: the exit
//! status is the interface, so a test of `parse_budget` alone does not cover it.
use std::process::Command;

fn diagnose_run(args: &[&str]) -> std::process::Output {
    let home = std::env::temp_dir().join(format!("netwatch-diagnose-cli-{}", uuid::Uuid::new_v4()));
    let output = Command::new(env!("CARGO_BIN_EXE_netwatch"))
        .args(["diagnose", "run"])
        .args(args)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("XDG_STATE_HOME", home.join("state"))
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&home);
    output
}

fn diagnose(args: &[&str], cwd: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_netwatch"))
        .arg("diagnose")
        .args(args)
        .current_dir(cwd)
        .env("HOME", cwd)
        .env("XDG_CONFIG_HOME", cwd.join("config"))
        .env("XDG_CACHE_HOME", cwd.join("cache"))
        .env("XDG_STATE_HOME", cwd.join("state"))
        .output()
        .unwrap()
}

/// The three subcommands whose formats are experimental refuse to run without
/// the flag: the argument-error status `diagnose run` documents, a message
/// naming the flag, and nothing written.
#[test]
fn the_experimental_subcommands_need_unstable() {
    let dir = std::env::temp_dir().join(format!("netwatch-unstable-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    for args in [
        &["replay", "episode.json.gz"][..],
        &["replay", "--json", "episode.json.gz"][..],
        &["features", "--schema", "schema.json"][..],
        &["corpus", "out"][..],
        &["corpus", "--only", "x", "out"][..],
        &["replay"][..],
    ] {
        let output = diagnose(args, &dir);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(3), "{args:?}: {stderr}");
        assert!(stderr.contains("--unstable"), "{args:?}: {stderr}");
        assert!(
            stderr.contains(&format!("netwatch diagnose {}", args[0])),
            "{args:?}: {stderr}"
        );
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "wrote something"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// With it they run as before, wherever it sits, and it is not taken for an
/// episode, a directory or an unknown option.
#[test]
fn unstable_is_taken_off_before_they_run() {
    let dir = std::env::temp_dir().join(format!("netwatch-unstable-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();

    let output = diagnose(&["features", "--unstable", "--schema", "schema.json"], &dir);
    assert!(output.status.success(), "{output:?}");
    assert!(dir.join("schema.json").is_file());
    let output = diagnose(&["features", "--schema", "again.json", "--unstable"], &dir);
    assert!(output.status.success(), "{output:?}");
    assert!(dir.join("again.json").is_file());

    // Past the gate: each fails for its own reason, with its usual status.
    for (args, expect) in [
        (&["replay", "--unstable"][..], "at least one episode"),
        (
            &["replay", "--unstable", "--json", "none.json.gz"][..],
            "none.json.gz",
        ),
        (&["corpus", "--unstable", "none"][..], "manifest.toml"),
        (
            &["corpus", "--unstable", "--bogus"][..],
            "unknown option --bogus",
        ),
    ] {
        let output = diagnose(args, &dir);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(stderr.contains(expect), "{args:?}: {stderr}");
        assert!(!stderr.contains("--unstable"), "{args:?}: {stderr}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// It gates only those three. `diagnose run`, whose flags are its interface,
/// does not take it, and the subcommands that need no flag run without it.
#[test]
fn unstable_gates_nothing_else() {
    let dir = std::env::temp_dir().join(format!("netwatch-unstable-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let output = diagnose(&["run", "--unstable"], &dir);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let output = diagnose(&["episodes", "none"], &dir);
    assert!(output.status.success(), "{output:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Review R6: these budgets overflowed a multiply, which panicked (exit 101)
/// in a debug build and wrapped in a release one, where the second became an
/// 8-second run. Each is a bad argument, exit 3, in every build.
#[test]
fn overflowing_budget_exits_3_without_panicking() {
    for budget in [
        "18446744073709551615m",
        "2152120141932781022m",
        "99999999999999999999999m",
        "601s",
    ] {
        let output = diagnose_run(&["--budget", budget]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(3), "{budget}: {stderr}");
        assert!(
            stderr.contains("budget must be between 5s and 10m"),
            "{budget}: {stderr}"
        );
        assert!(!stderr.contains("panicked"), "{budget}: {stderr}");
    }
}
