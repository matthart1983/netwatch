//! Each stable JSON output against its file under `schemas/`, through the real
//! binary where a test can drive it. The Egress tab's export takes a keypress
//! in the TUI, and some `diagnose run` findings need faults only the fixture
//! has, so those two have unit tests in `collectors::egress` and `diagnose::run`.

#[path = "support/schema.rs"]
mod support;

use netwatch::schemas;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Command, Output};
use support::{assert_rejected, check, compile, load};

/// A home of its own, so a test reads no real config and writes no real state.
/// Windows ignores these and finds its folders by asking the system, so a test
/// there sees the runner's own, which hold nothing.
struct Home(PathBuf);

impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("netwatch-schemas-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn netwatch(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_netwatch"));
        cmd.args(args)
            .env("HOME", &self.0)
            .env("XDG_CONFIG_HOME", self.0.join("config"))
            .env("XDG_CACHE_HOME", self.0.join("cache"))
            .env("XDG_STATE_HOME", self.0.join("state"))
            .env_remove("NETWATCH_REMOTE_URL")
            .env_remove("NETWATCH_METRICS_ADDR");
        cmd
    }

    #[cfg(target_os = "linux")]
    fn with_config(self, toml: &str) -> Self {
        let dir = self.0.join("config/netwatch");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.toml"), toml).unwrap();
        self
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Every node under `value`.
fn walk<'a>(value: &'a Value, visit: &mut dyn FnMut(&'a Value)) {
    visit(value);
    match value {
        Value::Object(map) => map.values().for_each(|v| walk(v, visit)),
        Value::Array(items) => items.iter().for_each(|v| walk(v, visit)),
        _ => {}
    }
}

fn file_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(support::dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// ------------------------------------------------------------- the files

/// The table in `netwatch::schemas`, the files, and what each file says it is
/// all agree, and each file is a valid 2020-12 schema.
#[test]
fn every_output_has_a_file_that_names_it_and_no_file_is_spare() {
    let mut expected: Vec<String> = schemas::ALL.iter().map(|o| o.file.to_string()).collect();
    expected.sort();
    assert_eq!(file_names(), expected);

    for output in schemas::ALL {
        let schema = load(output.file);
        compile(&schema);
        assert_eq!(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema",
            "{}",
            output.file
        );
        assert_eq!(schema["$id"], output.url(), "{}", output.file);
        let metadata = schema
            .pointer("/properties/metadata/properties")
            .or_else(|| schema.pointer("/$defs/header/properties/metadata/properties"))
            .unwrap_or_else(|| panic!("{} has no metadata block", output.file));
        assert_eq!(metadata["schema"]["const"], output.schema);
        assert_eq!(metadata["schema_version"]["const"], output.version);
        assert_eq!(metadata["schema_url"]["const"], output.url());
    }
}

/// The promise is that a minor may add fields and consumers ignore them. A file
/// that closed an object would fail a consumer's validator on the first one.
#[test]
fn no_schema_closes_an_object() {
    for output in schemas::ALL {
        let schema = load(output.file);
        walk(&schema, &mut |node| {
            let Value::Object(map) = node else { return };
            if let Some(extra) = map.get("additionalProperties") {
                assert_eq!(extra, &json!(true), "{}: {node}", output.file);
            }
            for keyword in ["unevaluatedProperties", "propertyNames", "maxProperties"] {
                assert!(!map.contains_key(keyword), "{}: {node}", output.file);
            }
        });
    }
}

/// A consumer writing a `match` needs to know whether it can be exhaustive, so
/// every listed value set says. `enum` is for a closed set, because a validator
/// enforces it. `examples` is for an open one, because a validator does not.
#[test]
fn every_listed_value_set_says_whether_a_minor_can_add_to_it() {
    for output in schemas::ALL {
        let schema = load(output.file);
        walk(&schema, &mut |node| {
            let Value::Object(map) = node else { return };
            let description = map
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if map.contains_key("examples") {
                assert!(description.contains("Open set"), "{}: {node}", output.file);
                // Any of these would refuse a value a minor is allowed to add.
                for keyword in ["enum", "const", "pattern", "format"] {
                    assert!(!map.contains_key(keyword), "{}: {node}", output.file);
                }
            }
            if map.contains_key("enum") {
                assert!(
                    description.contains("Closed set"),
                    "{}: {node}",
                    output.file
                );
            }
        });
    }
}

/// A deprecated field keeps being written until a major version, so a file says
/// that wherever it marks one, and never requires one.
#[test]
fn a_deprecated_field_is_optional_and_goes_only_in_a_major_version() {
    let mut marked = 0;
    for output in schemas::ALL {
        let schema = load(output.file);
        walk(&schema, &mut |node| {
            let Value::Object(map) = node else { return };
            if map.get("deprecated") == Some(&json!(true)) {
                marked += 1;
                let description = map["description"].as_str().unwrap_or_default();
                assert!(
                    description.contains("only in a major version"),
                    "{}: {node}",
                    output.file
                );
            }
            let (Some(Value::Array(required)), Some(Value::Object(properties))) =
                (map.get("required"), map.get("properties"))
            else {
                return;
            };
            for name in required {
                let property = name.as_str().and_then(|name| properties.get(name));
                assert!(
                    property.is_none_or(|p| p.get("deprecated").is_none()),
                    "{}: {name} is required and deprecated",
                    output.file
                );
            }
        });
    }
    assert_eq!(marked, 10, "one in doctor, nine in diagnose run");
}

/// `strict` turns `examples` into the whole set, so a value a test reaches
/// cannot go unlisted. Most rules take a fault a test cannot cause, so the
/// catalogue is checked directly.
#[test]
fn the_rule_ids_the_schema_lists_are_the_catalogue() {
    let schema = load(schemas::DIAGNOSE_RUN.file);
    let mut listed: Vec<&str> = schema["$defs"]["rule_id"]["examples"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    listed.sort_unstable();
    let mut catalogue: Vec<&str> = netwatch::diagnose::rules::CATALOGUE
        .iter()
        .map(|r| r.id)
        .collect();
    catalogue.sort_unstable();
    assert_eq!(listed, catalogue);
}

/// `cargo package` is what decides, so ask it rather than read Cargo.toml.
#[test]
fn the_schemas_ship_in_the_crate() {
    let output = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["package", "--list", "--allow-dirty", "--offline"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    let listed = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for name in file_names() {
        // cargo prints `\` on Windows, so compare past the directory.
        assert!(
            listed
                .lines()
                .any(|l| l.starts_with("schemas") && l.ends_with(&name)),
            "{name} is not in the package:\n{listed}"
        );
    }
}

// ---------------------------------------------------------------- doctor

const DOCTOR: &str = schemas::DOCTOR.file;

/// One capability's state and reason.
fn capability<'a>(doc: &'a Value, id: &str) -> (&'a str, &'a str) {
    let found = doc["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("no {id} in {doc}"));
    (
        found["state"].as_str().unwrap(),
        found["reason"].as_str().unwrap(),
    )
}

#[test]
fn doctor_matches_its_schema() {
    let home = Home::new();
    let output = home.netwatch(&["doctor", "--json"]).output().unwrap();
    assert!(output.status.success());
    let doc = stdout_json(&output);
    check(DOCTOR, &doc);
    assert_eq!(doc["scope"], "static");
    assert_eq!(doc["metadata"]["schema"], schemas::DOCTOR.schema);
    assert_eq!(
        doc["metadata"]["netwatch_version"],
        env!("CARGO_PKG_VERSION")
    );

    let mut bad = doc.clone();
    bad["capabilities"][0]["state"] = json!("fine");
    assert_rejected(DOCTOR, &bad, "a state outside the closed set");
    let mut bad = doc.clone();
    bad["capabilities"][0].as_object_mut().unwrap().remove("id");
    assert_rejected(DOCTOR, &bad, "a capability with no id");
    let mut bad = doc.clone();
    bad["capabilities"][0]["detail"] = Value::Null;
    assert_rejected(DOCTOR, &bad, "a null detail");
    let mut bad = doc.clone();
    bad["interface"] = json!("");
    assert_rejected(DOCTOR, &bad, "an empty interface, which is null instead");
    let mut bad = doc.clone();
    bad["metadata"]["schema"] = json!("netwatch.doctor.v2");
    assert_rejected(DOCTOR, &bad, "another version's name");
    let mut bad = doc;
    bad["schema_version"] = json!(2);
    assert_rejected(DOCTOR, &bad, "another schema_version");
}

/// A capture check that cannot open: `capture` goes unavailable, and on Linux
/// `interface` does too.
#[test]
fn a_failed_capture_check_matches_the_schema() {
    let home = Home::new();
    let output = home
        .netwatch(&[
            "doctor",
            "--json",
            "--check-capture",
            "--interface",
            "netwatch-no-such-interface",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let doc = stdout_json(&output);
    check(DOCTOR, &doc);
    assert_eq!(doc["scope"], "capture_check");
    assert_eq!(capability(&doc, "capture").0, "unavailable");

    // With none named, it selects one if it can. A Windows runner has no Npcap
    // to check with, and that used to write an empty interface.
    let output = home
        .netwatch(&["doctor", "--json", "--check-capture"])
        .output()
        .unwrap();
    assert!(output.status.success());
    check(DOCTOR, &stdout_json(&output));
}

/// None named and none up, so selection fails. The namespace needs a sysfs of its
/// own, because /sys/class/net otherwise still lists the host's interfaces. This
/// skips where it cannot make one, as tests/doctor.rs does.
#[cfg(target_os = "linux")]
#[test]
fn a_capture_check_that_selects_nothing_has_a_null_interface() {
    let home = Home::new();
    let mut command = Command::new("unshare");
    command
        .args(["--user", "--map-root-user", "--net", "--mount", "sh", "-c"])
        .arg(r#"mount -t sysfs sys /sys && exec "$0" doctor --json --check-capture"#)
        .arg(env!("CARGO_BIN_EXE_netwatch"));
    for (key, value) in home.netwatch(&[]).get_envs() {
        match value {
            Some(value) => command.env(key, value),
            None => command.env_remove(key),
        };
    }
    let output = match command.output() {
        Ok(output) if output.status.success() => output,
        other => {
            eprintln!("skipped: no namespace with its own sysfs: {other:?}");
            return;
        }
    };
    let doc = stdout_json(&output);
    check(DOCTOR, &doc);
    assert!(doc["interface"].is_null(), "{doc}");
    assert_eq!(
        capability(&doc, "interface"),
        ("unavailable", "selection_failed")
    );
}

/// A config that does not load: `config` is unavailable and the capture check
/// does not run. Exit 0 still, since a report is not a verdict.
#[cfg(target_os = "linux")]
#[test]
fn doctor_on_a_broken_config_matches_the_schema() {
    let home = Home::new().with_config("not toml at all = = =");
    let output = home
        .netwatch(&["doctor", "--json", "--check-capture"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let doc = stdout_json(&output);
    check(DOCTOR, &doc);
    assert_eq!(
        capability(&doc, "config"),
        ("unavailable", "config_invalid")
    );
    assert_eq!(
        capability(&doc, "capture"),
        ("not_checked", "config_not_loaded")
    );
}

/// The states and nulls a default config never shows: degraded insights, an
/// unreadable GeoIP database, the sandbox turned off, and a configured
/// interface in place of a null one.
#[cfg(target_os = "linux")]
#[test]
fn a_degraded_doctor_matches_the_schema() {
    let home = Home::new().with_config(
        r#"
        insights_enabled = true
        insights_endpoint = "http://203.0.113.9:11434"
        geoip_db = "/nonexistent/netwatch-test.mmdb"
        sandbox = "off"
        capture_interface = "netwatch-no-such-interface"
        "#,
    );
    let output = home
        .netwatch(&["doctor", "--json"])
        .env("NETWATCH_REMOTE_URL", "https://203.0.113.9")
        .env("NETWATCH_METRICS_ADDR", "127.0.0.1:1")
        .output()
        .unwrap();
    assert!(output.status.success());
    let doc = stdout_json(&output);
    check(DOCTOR, &doc);
    assert_eq!(doc["interface"], "netwatch-no-such-interface");
    for (id, state, reason) in [
        ("insights", "degraded", "cleartext_off_host"),
        ("geoip_db", "unavailable", "db_unreadable"),
        ("landlock", "disabled", "sandbox_disabled"),
        ("interface", "unavailable", "interface_missing"),
        ("remote", "not_checked", "environment_only"),
    ] {
        assert_eq!(capability(&doc, id), (state, reason), "{id}");
    }
}

/// No command prints a live session's snapshot, but it is the same document,
/// and it is the only one that fills `protections`, `attribution_coverage` and
/// `tasks_holding_net_raw`.
#[test]
fn a_live_snapshot_matches_the_doctor_schema() {
    use netwatch::runtime::capabilities::CapabilitySnapshot;
    let app = netwatch::app::App::prepare_with_config(netwatch::config::NetwatchConfig::default());
    let snapshot = CapabilitySnapshot::live(&app);
    let doc = serde_json::to_value(&snapshot).unwrap();
    check(DOCTOR, &doc);
    assert_eq!(doc["scope"], "runtime");
    assert!(
        !doc["protections"].as_array().unwrap().is_empty(),
        "main's own, at least"
    );
    assert!(doc["attribution_coverage"].is_object(), "{doc}");
}

// ---------------------------------------------------------------- uptime

const UPTIME: &str = schemas::UPTIME.file;

/// A log under `home` with one outage ended each way: a reply, netwatch stopping,
/// and still down now.
fn uptime_log_with_outages(home: &Home) -> PathBuf {
    use netwatch::uptime::{Hop, HopState, Log, Record};
    let dir = home.0.join("uptime");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let log = Log::new(dir.clone());
    let hop = |ago: u64, hop, state| Record::Hop {
        t: now - ago,
        hop,
        state,
    };
    let beats = |from: u64, to: u64| {
        (to..=from)
            .rev()
            .step_by(60)
            .map(|ago| Record::Beat { t: now - ago })
            .collect::<Vec<_>>()
    };
    let mut records = vec![
        Record::Start {
            t: now - 3000,
            version: "test".into(),
        },
        hop(3000, Hop::Internet, HopState::Up),
    ];
    records.extend(beats(2940, 2040));
    records.push(hop(2000, Hop::Internet, HopState::Down));
    records.extend(beats(1980, 1860));
    records.push(hop(1800, Hop::Internet, HopState::Up));
    records.extend(beats(1800, 660));
    records.push(hop(600, Hop::Gateway, HopState::Down));
    records.extend(beats(600, 360));
    records.push(Record::Stop { t: now - 300 });
    records.push(Record::Start {
        t: now - 120,
        version: "test".into(),
    });
    records.push(hop(120, Hop::Gateway, HopState::Up));
    records.push(hop(120, Hop::Internet, HopState::Up));
    records.push(hop(60, Hop::Dns, HopState::Down));
    records.push(Record::Beat { t: now - 30 });
    for record in &records {
        log.append(record).unwrap();
    }
    dir
}

#[test]
fn uptime_with_outages_matches_its_schema() {
    let home = Home::new();
    let dir = uptime_log_with_outages(&home);
    let output = home
        .netwatch(&["uptime", "--json", dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let doc = stdout_json(&output);
    check(UPTIME, &doc);
    assert_eq!(doc["metadata"]["schema"], schemas::UPTIME.schema);
    let ended: Vec<&str> = doc["outages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["ended"].as_str().unwrap())
        .collect();
    assert_eq!(
        ended,
        ["recovered", "monitoring_stopped", "ongoing"],
        "{doc}"
    );
    assert!(doc["summary"]["uptime_pct"].is_number(), "{doc}");

    let mut bad = doc.clone();
    bad["outages"][0]["ended"] = json!("fixed");
    assert_rejected(UPTIME, &bad, "an ended outside the closed set");
    let mut bad = doc.clone();
    bad["outages"][0]["hop"] = Value::Null;
    assert_rejected(UPTIME, &bad, "a null hop");
    let mut bad = doc.clone();
    bad["since"] = json!("yesterday");
    assert_rejected(UPTIME, &bad, "a since that is not a date-time");
    let mut bad = doc;
    bad["summary"].as_object_mut().unwrap().remove("up_secs");
    assert_rejected(UPTIME, &bad, "a summary with no up_secs");
}

/// `uptime --csv` has no version marker, so this row is its contract. A column
/// is never renamed or removed. A new one goes at the end, and this constant
/// gains it there.
#[test]
fn the_uptime_csv_header_row_is_pinned() {
    const HEADER: &str = "start,end,duration_secs,hop,ended";
    let home = Home::new();
    let dir = uptime_log_with_outages(&home);
    let csv = |dir: &std::path::Path| -> String {
        let output = home
            .netwatch(&["uptime", "--csv", dir.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    };
    let text = csv(&dir);
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some(HEADER));

    // Read by header name, as the documentation tells a consumer to.
    let columns: Vec<&str> = HEADER.split(',').collect();
    let cell = |row: &str, name: &str| -> String {
        let at = columns.iter().position(|c| *c == name).unwrap();
        row.split(',').nth(at).unwrap().to_string()
    };
    let rows: Vec<(String, String)> = lines.map(|r| (cell(r, "hop"), cell(r, "ended"))).collect();
    let expected = [
        ("internet", "recovered"),
        ("gateway", "monitoring_stopped"),
        ("dns", "ongoing"),
    ]
    .map(|(hop, ended)| (hop.to_string(), ended.to_string()));
    assert_eq!(rows, expected);

    // With no outages it is the header row alone.
    let empty = home.0.join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    assert_eq!(csv(&empty), format!("{HEADER}\n"));
}

/// Nothing in the log: no outages and no percentage to give.
#[test]
fn uptime_with_nothing_monitored_matches_its_schema() {
    let home = Home::new();
    let dir = home.0.join("empty");
    std::fs::create_dir_all(&dir).unwrap();
    let output = home
        .netwatch(&["uptime", "--json", dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let doc = stdout_json(&output);
    check(UPTIME, &doc);
    assert_eq!(doc["outages"], json!([]));
    assert!(doc["summary"]["uptime_pct"].is_null(), "{doc}");
}

// --------------------------------------------------------- diagnose export

#[cfg(unix)]
const EXPORT: &str = schemas::DIAGNOSE_EXPORT.file;

/// A real recording from the replay corpus, through the real redaction. Unix,
/// because the install key goes to a state directory only there under `home`.
#[cfg(unix)]
#[test]
fn a_diagnose_export_matches_its_schema() {
    use std::io::Read;
    let home = Home::new();
    let bundle = home.0.join("bundle.json.gz");
    let episodes = home.0.join("episodes");
    std::fs::create_dir_all(&episodes).unwrap();
    let recording = "fixture-scenario.json.gz";
    std::fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/diagnose/corpus")
            .join(recording),
        episodes.join(recording),
    )
    .unwrap();
    let output = home
        .netwatch(&[
            "diagnose",
            "export",
            "--since",
            "36500",
            "--out",
            bundle.to_str().unwrap(),
            episodes.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut text = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(&bundle).unwrap())
        .read_to_string(&mut text)
        .unwrap();
    let doc: Value = serde_json::from_str(&text).unwrap();
    check(EXPORT, &doc);
    assert_eq!(doc["metadata"]["schema"], schemas::DIAGNOSE_EXPORT.schema);
    assert_eq!(doc["episodes"].as_array().unwrap().len(), 1);

    let mut bad = doc.clone();
    bad["version"] = json!(2);
    assert_rejected(EXPORT, &bad, "another version");
    let mut bad = doc.clone();
    bad["created"] = json!("2026-11-01T08:00:00+11:00");
    assert_rejected(EXPORT, &bad, "a created in another format");
    let mut bad = doc;
    bad["episodes"][0]
        .as_object_mut()
        .unwrap()
        .remove("schema_version");
    assert_rejected(EXPORT, &bad, "an episode with no schema_version");
}

// ------------------------------------------------------------ diagnose run

/// The smallest budget a run takes. Each of these runs lasts this long.
#[cfg(target_os = "linux")]
const BUDGET: &str = "5s";

#[cfg(target_os = "linux")]
const RUN: &str = schemas::DIAGNOSE_RUN.file;

/// A target at `port` on loopback, reached with plain TCP, whose first failed
/// probe opens an issue. A loopback target takes no host-wide finding, so what
/// the run reports does not depend on the machine's own network.
#[cfg(target_os = "linux")]
fn target_config(port: u16) -> String {
    format!(
        r#"
        [diagnose_thresholds]
        consecutive_n = 1

        [[diagnose_targets]]
        name = "api"
        host = "127.0.0.1"
        port = {port}
        tls = false
        http = false
        "#
    )
}

/// Refused on loopback: an Issue, exit 1, and a finding with checks in every
/// state a real probe gives. Port 1 is tcpmux, which nothing runs.
#[cfg(target_os = "linux")]
#[test]
fn a_diagnose_run_with_a_finding_matches_its_schema() {
    let home = Home::new().with_config(&target_config(1));
    let output = home
        .netwatch(&[
            "diagnose", "run", "--budget", BUDGET, "--target", "api", "--format", "json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let doc = stdout_json(&output);
    check(RUN, &doc);
    assert_eq!(doc["outcome"], "finding");
    assert_eq!(doc["target"], "api");
    assert_eq!(doc["metadata"]["schema"], schemas::DIAGNOSE_RUN.schema);
    let issue = &doc["issues"][0];
    assert_eq!(issue["rule"], "target.connect_failed", "{doc}");
    assert_eq!(issue["subject"]["kind"], "target");
    assert_eq!(issue["state"]["state"], "open");

    let mut bad = doc.clone();
    bad["exit"] = json!(0);
    assert_rejected(RUN, &bad, "exit 0 on a finding");
    let mut bad = doc.clone();
    bad["exit"] = json!(3);
    bad["outcome"] = json!("error");
    assert_rejected(RUN, &bad, "the error outcome, which prints no JSON");
    let mut bad = doc.clone();
    bad["issues"][0]["kind"] = json!("observation");
    assert_rejected(RUN, &bad, "an observation under issues");
    let mut bad = doc.clone();
    bad["issues"][0]["severity"] = json!("low");
    assert_rejected(RUN, &bad, "a severity outside the closed set");
    let mut bad = doc.clone();
    bad["issues"][0]["subject"]
        .as_object_mut()
        .unwrap()
        .remove("name");
    assert_rejected(RUN, &bad, "a target subject with no name");
    let mut bad = doc.clone();
    bad["issues"][0]["since"] = json!("2026-11-01T08:00:00+11:00");
    assert_rejected(RUN, &bad, "a since in another format");
    let mut bad = doc;
    let check_not_run = bad["issues"][0]["causes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .flat_map(|c| c["checks"].as_array_mut().unwrap())
        .find(|c| c["state"] == "not_run")
        .expect("the probe leaves a check not run");
    check_not_run.as_object_mut().unwrap().remove("why_not");
    assert_rejected(RUN, &bad, "a check not run that does not say why");
}

/// A target that answers: exit 0, empty lists.
#[cfg(target_os = "linux")]
#[test]
fn a_diagnose_run_with_no_finding_matches_its_schema() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let home = Home::new().with_config(&target_config(port));
    let output = home
        .netwatch(&[
            "diagnose", "run", "--budget", BUDGET, "--target", "api", "--format", "json",
        ])
        .output()
        .unwrap();
    drop(listener);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let doc = stdout_json(&output);
    check(RUN, &doc);
    assert_eq!(doc["outcome"], "no_finding");
    assert_eq!(doc["issues"], json!([]));
    assert_eq!(doc["evidence"], true);
}

/// A disabled target is never probed: exit 2, and `evidence` false.
#[cfg(target_os = "linux")]
#[test]
fn an_incomplete_diagnose_run_matches_its_schema() {
    let config = format!("{}\nenabled = false\n", target_config(1));
    let home = Home::new().with_config(&config);
    let output = home
        .netwatch(&[
            "diagnose", "run", "--budget", BUDGET, "--target", "api", "--format", "json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let doc = stdout_json(&output);
    check(RUN, &doc);
    assert_eq!(doc["outcome"], "incomplete");
    assert_eq!(doc["evidence"], false);
    assert_eq!(doc["target"], "api");
}

/// A run about this host, whatever it finds here, with beta rules counted: the
/// exit status varies by machine and the document's shape must not.
#[cfg(target_os = "linux")]
#[test]
fn a_diagnose_run_about_the_host_matches_its_schema() {
    let home = Home::new();
    let output = home
        .netwatch(&[
            "diagnose",
            "run",
            "--budget",
            BUDGET,
            "--include-beta",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(matches!(output.status.code(), Some(0..=2)), "{output:?}");
    let doc = stdout_json(&output);
    check(RUN, &doc);
    assert!(doc["target"].is_null());
    assert_eq!(doc["include_beta"], true);
    assert!(!doc["coverage"]["rules"].as_array().unwrap().is_empty());
}

/// Exit 3 has no document to validate, and the schema says so.
#[test]
fn a_diagnose_run_that_cannot_start_prints_no_json() {
    let home = Home::new();
    let output = home
        .netwatch(&[
            "diagnose",
            "run",
            "--target",
            "nothing-configured",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
}
