//! Command routing and validation, before any application side effects.
use crate::{app::ViewMode, sandbox::Mode};
#[derive(Debug)]
pub enum Command {
    Help,
    Version,
    GenerateConfig,
    Doctor {
        json: bool,
        check_capture: bool,
        interface: Option<String>,
    },
    Resolver(Vec<String>),
    Diagnose(Vec<String>),
    Uptime(Vec<String>),
    GeoipUpdate {
        city: bool,
    },
    CaptureChild {
        interface: String,
        mode: Mode,
    },
    Run(Run),
}
#[derive(Debug, Default)]
pub struct Run {
    pub daemon: bool,
    pub demo: bool,
    pub view: Option<ViewMode>,
    pub sandbox: Option<Mode>,
    pub remote: Option<String>,
    pub api_key: Option<String>,
    pub insecure_remote: bool,
    pub metrics: bool,
    pub metrics_addr: Option<String>,
}
// One option catalogue supplies both accepted spellings and help text.
const OPTIONS: &[(&str, bool, &str)] = &[
    ("--remote", true, "Remote https:// URL (requires API key)"),
    ("--api-key", true, "Discouraged: use NETWATCH_API_KEY"),
    ("--insecure-remote", false, "Allow an http:// remote URL"),
    ("--view", true, "full, lite, or dense"),
    ("--lite", false, "Start in Lite view"),
    ("--demo", false, "Replay the Diagnose demo"),
    ("--no-sandbox", false, "Disable sandbox"),
    ("--sandbox-strict", false, "Require sandbox enforcement"),
    ("--metrics", false, "Daemon metrics on 127.0.0.1:9464"),
    ("--metrics-addr", true, "Daemon metrics address"),
    ("--daemon", false, "Headless mode (alias: --headless)"),
];
pub fn help() -> String {
    let mut text = format!("netwatch {}\n\nUsage: netwatch [OPTIONS] | daemon [OPTIONS]\n       netwatch doctor [--json] [--check-capture] [--interface NAME]\n       netwatch diagnose run [--target NAME] [--budget 30s] [--format json]\n       netwatch diagnose coverage [--json] [--seconds 1..120] [--test CHECK] [--doc [PATH]]\n       netwatch diagnose episodes [DIR]\n       netwatch diagnose corpus [--only ID] [DIR]\n       netwatch diagnose replay [--json] <FILE|DIR>...\n       netwatch diagnose features [--out FILE] [--schema FILE] <FILE|DIR>...\n       netwatch diagnose export [--since DAYS] [--out FILE] [--dry-run] [DIR]\n       netwatch uptime [--since 7d] [--json | --csv] [DIR]\n       netwatch geoip update [--city]\n       netwatch resolver status\n       netwatch resolver set <IP> --unmanaged [--seconds 1..3600]\n       netwatch resolver recover --unmanaged\n\nOptions:\n", env!("CARGO_PKG_VERSION"));
    for (name, value, description) in OPTIONS {
        text.push_str(&format!(
            "  {name:<19} {}{description}\n",
            if *value { "<value> " } else { "" }
        ));
    }
    text.push_str("  --generate-config    Write default config and exit\n  --help, -h           Show help\n  --version, -V        Show version\n\nKeys: 1–9,0 tabs; V view; L Lite; q quit; Shift+R/F/E recorder\n");
    text
}
pub fn parse(args: &[String]) -> anyhow::Result<Command> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(Command::Help);
    }
    if args == ["--version"] || args == ["-V"] {
        return Ok(Command::Version);
    }
    if args == ["--generate-config"] {
        return Ok(Command::GenerateConfig);
    }
    if args.first().map(String::as_str) == Some("resolver") {
        return Ok(Command::Resolver(args[1..].to_vec()));
    }
    if args.first().map(String::as_str) == Some("diagnose") {
        return Ok(Command::Diagnose(args[1..].to_vec()));
    }
    if args.first().map(String::as_str) == Some("uptime") {
        return Ok(Command::Uptime(args[1..].to_vec()));
    }
    if args.first().map(String::as_str) == Some("geoip") {
        let rest: Vec<_> = args[1..].iter().map(String::as_str).collect();
        return match rest[..] {
            ["update"] => Ok(Command::GeoipUpdate { city: false }),
            ["update", "--city"] => Ok(Command::GeoipUpdate { city: true }),
            _ => anyhow::bail!("usage: netwatch geoip update [--city]"),
        };
    }
    if args.first().map(String::as_str) == Some("__capture-check") {
        if args.len() != 3 || !["off", "strict", "best-effort"].contains(&args[2].as_str()) {
            anyhow::bail!("invalid capture check arguments");
        }
        return Ok(Command::CaptureChild {
            interface: args[1].clone(),
            mode: Mode::from_config(&args[2]),
        });
    }
    if args.first().map(String::as_str) == Some("doctor") {
        let (mut json, mut check_capture, mut interface) = (false, false, None);
        let mut rest = args[1..].iter();
        while let Some(arg) = rest.next() {
            match arg.as_str() {
                "--json" if !json => json = true,
                "--check-capture" if !check_capture => check_capture = true,
                "--interface" if interface.is_none() => interface = Some(value(&mut rest, arg)?),
                _ => anyhow::bail!("unknown or repeated doctor option: {arg}"),
            }
        }
        return Ok(Command::Doctor {
            json,
            check_capture,
            interface,
        });
    }
    let mut run = Run::default();
    let mut seen = std::collections::HashSet::new();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let key = match arg.as_str() {
            "daemon" | "--headless" => "--daemon",
            s => s,
        };
        if !OPTIONS.iter().any(|o| o.0 == key) {
            anyhow::bail!("unknown option: {arg}; see --help");
        }
        if !seen.insert(key) {
            anyhow::bail!("repeated option: {arg}");
        }
        match key {
            "--daemon" => run.daemon = true,
            "--demo" => run.demo = true,
            "--remote" => run.remote = Some(value(&mut rest, arg)?),
            "--api-key" => run.api_key = Some(value(&mut rest, arg)?),
            "--insecure-remote" => run.insecure_remote = true,
            "--view" | "--lite" => {
                if run.view.is_some() {
                    anyhow::bail!("choose only one view option");
                }
                let name = if key == "--lite" {
                    "lite".to_owned()
                } else {
                    value(&mut rest, arg)?
                };
                if !["full", "lite", "dense"].contains(&name.as_str()) {
                    anyhow::bail!("--view expects full, lite, or dense");
                }
                run.view = Some(ViewMode::by_name(&name));
            }
            "--no-sandbox" | "--sandbox-strict" => {
                if run.sandbox.is_some() {
                    anyhow::bail!("sandbox flags conflict");
                }
                run.sandbox = Some(if key == "--no-sandbox" {
                    Mode::Disabled
                } else {
                    Mode::Strict
                });
            }
            "--metrics" => run.metrics = true,
            "--metrics-addr" => run.metrics_addr = Some(value(&mut rest, arg)?),
            _ => unreachable!(),
        }
    }
    if run.daemon && (run.demo || run.view.is_some()) {
        anyhow::bail!("daemon cannot use demo or view options");
    }
    if !run.daemon && (run.metrics || run.metrics_addr.is_some()) {
        anyhow::bail!("metrics options require daemon mode");
    }
    if run.metrics && run.metrics_addr.is_some() {
        anyhow::bail!("choose --metrics or --metrics-addr");
    }
    Ok(Command::Run(run))
}
fn value<'a>(rest: &mut impl Iterator<Item = &'a String>, flag: &str) -> anyhow::Result<String> {
    rest.next()
        .filter(|s| !s.is_empty() && !s.starts_with('-'))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn command(s: &str) -> anyhow::Result<Command> {
        parse(&s.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
    }
    #[test]
    fn aliases_and_existing_views_are_preserved() {
        for s in ["daemon", "--daemon", "--headless"] {
            assert!(matches!(
                command(s).unwrap(),
                Command::Run(Run { daemon: true, .. })
            ));
        }
        assert!(matches!(
            command("--view dense").unwrap(),
            Command::Run(Run {
                view: Some(ViewMode::Dense),
                ..
            })
        ));
        assert!(matches!(
            command("--lite").unwrap(),
            Command::Run(Run {
                view: Some(ViewMode::Lite),
                ..
            })
        ));
    }
    #[test]
    fn ambiguous_or_missing_values_fail_before_startup() {
        for s in [
            "--remote",
            "--api-key --demo",
            "--view typo",
            "--lite --view full",
            "--no-sandbox --sandbox-strict",
            "daemon --demo",
            "--metrics",
            "--typo",
            "doctor --remote secret",
            "doctor --interface",
        ] {
            assert!(command(s).is_err(), "{s}");
        }
        assert!(matches!(
            command("doctor --json --check-capture --interface eth0").unwrap(),
            Command::Doctor {
                json: true,
                check_capture: true,
                ..
            }
        ));
    }

    #[test]
    fn insecure_remote_is_off_unless_given() {
        assert!(matches!(
            command("--remote http://10.0.0.1 --api-key k --insecure-remote").unwrap(),
            Command::Run(Run {
                insecure_remote: true,
                ..
            })
        ));
        assert!(matches!(
            command("--remote https://cloud.example.com --api-key k").unwrap(),
            Command::Run(Run {
                insecure_remote: false,
                ..
            })
        ));
        assert!(command("--insecure-remote --insecure-remote").is_err());
    }

    #[test]
    fn help_steers_the_api_key_to_the_environment() {
        let help = help();
        let line = help
            .lines()
            .find(|l| l.trim_start().starts_with("--api-key"))
            .unwrap();
        assert!(line.contains("NETWATCH_API_KEY"), "{line}");
        // Discouraged, not removed: existing units keep working.
        assert!(matches!(
            command("--remote https://cloud.example.com --api-key k").unwrap(),
            Command::Run(Run {
                api_key: Some(_),
                ..
            })
        ));
    }

    #[test]
    fn geoip_routes() {
        assert!(matches!(
            command("geoip update").unwrap(),
            Command::GeoipUpdate { city: false }
        ));
        assert!(matches!(
            command("geoip update --city").unwrap(),
            Command::GeoipUpdate { city: true }
        ));
        for s in [
            "geoip",
            "geoip download",
            "geoip update --typo",
            "geoip update --city --city",
            "geoip --city update",
        ] {
            assert!(command(s).is_err(), "{s}");
        }
        assert!(help().contains("netwatch geoip update [--city]"));
    }

    /// Shipped completions and the man page must cover every option the
    /// parser accepts. A flag that exists but cannot be completed, or is
    /// undocumented in the man page a distro installs, is the packaging
    /// equivalent of a missing help line — and nobody notices until a user
    /// reports it. Adding to OPTIONS fails this test until both are updated.
    #[test]
    fn completions_and_man_cover_every_option() {
        const BASH: &str = include_str!("../completions/netwatch.bash");
        const ZSH: &str = include_str!("../completions/_netwatch");
        const FISH: &str = include_str!("../completions/netwatch.fish");
        const MAN: &str = include_str!("../docs/netwatch.1");

        for (name, _, _) in OPTIONS {
            for (what, text) in [("bash", BASH), ("zsh", ZSH), ("fish", FISH)] {
                assert!(
                    text.contains(name) || text.contains(name.trim_start_matches("--")),
                    "{what} completion is missing {name}"
                );
            }
            // roff escapes every hyphen: `--api-key` is written `\-\-api\-key`.
            let roff = name.replace('-', "\\-");
            assert!(
                MAN.contains(&roff) || MAN.contains(name),
                "man page is missing {name}"
            );
        }

        // The subcommands the parser routes on, which are not in OPTIONS.
        for sub in [
            "daemon", "doctor", "diagnose", "uptime", "geoip", "resolver",
        ] {
            for (what, text) in [("bash", BASH), ("zsh", ZSH), ("fish", FISH), ("man", MAN)] {
                assert!(text.contains(sub), "{what} is missing the {sub} subcommand");
            }
        }

        // Its one subcommand and flag, which are not in OPTIONS either.
        for (what, text) in [("bash", BASH), ("zsh", ZSH), ("fish", FISH)] {
            for word in ["update", "city"] {
                assert!(
                    text.split(|c: char| !c.is_ascii_alphanumeric())
                        .any(|w| w == word),
                    "{what} completion is missing geoip's {word}"
                );
            }
        }
        assert!(
            MAN.lines().any(|l| l.trim_end() == ".B geoip update"),
            "man page is missing geoip update"
        );
        assert!(
            MAN.contains("\\-\\-city"),
            "man page is missing geoip update --city"
        );

        for sub in crate::diagnose::episode::SUBCOMMANDS {
            for (what, text) in [("bash", BASH), ("zsh", ZSH), ("fish", FISH)] {
                assert!(
                    text.split(|c: char| !c.is_ascii_alphanumeric())
                        .any(|w| w == *sub),
                    "{what} completion is missing diagnose {sub}"
                );
            }
            // By line: a Windows checkout has CRLF endings.
            let heading = format!(".B diagnose {sub}");
            assert!(
                MAN.lines().any(|l| l.trim_end() == heading),
                "man page is missing diagnose {sub}"
            );
        }
    }
}
