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
