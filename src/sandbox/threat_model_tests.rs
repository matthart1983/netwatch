//! Keep the operator-facing policy inventory tied to executable policy.
const DOC: &str = include_str!("../../docs/THREAT-MODEL.md");
fn block(name: &str) -> &str {
    DOC.split_once(&format!("<!-- {name} -->"))
        .unwrap()
        .1
        .split_once(&format!("<!-- /{name} -->"))
        .unwrap()
        .0
        .trim()
}

#[test]
#[cfg(target_os = "linux")]
fn threat_model_policy_tables_match_code() {
    use super::{linux, SandboxPaths};
    let caps = |xs: &[caps::Capability]| {
        xs.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    assert_eq!(
        block("policy:caps"),
        format!(
            "default: {}\nstrict-extra: {}\nparser-extra: {}\nafter-open: {}\nbpf-load: {}\nproc-broker: {}",
            caps(linux::CAPS_TO_DROP_DEFAULT),
            caps(linux::CAPS_TO_DROP_STRICT),
            caps(linux::CAPS_TO_DROP_PARSER),
            caps(linux::CAPS_TO_DROP_AFTER_OPEN),
            caps(linux::CAPS_FOR_BPF_LOAD),
            caps(linux::CAPS_FOR_PROC_BROKER)
        )
    );
    assert_eq!(
        block("policy:abi"),
        format!(
            "filesystem: {:?}\nparser-net: {:?}\nparser-scope: {:?}\nparser-fs: {:?}",
            linux::TARGET_ABI,
            linux::PARSER_NET_ABI,
            linux::PARSER_SCOPE_ABI,
            linux::PARSER_FS
        )
    );
    let paths = SandboxPaths {
        config_dir: Some("<config>".into()),
        cache_dir: Some("<cache>".into()),
        state_dir: Some("<state>".into()),
        cwd: Some("<exports>".into()),
        geoip_db_dir: Some("<city-file>".into()),
        geoip_asn_db_dir: Some("<asn-file>".into()),
        keylog_dir: Some("<keylog-file>".into()),
    };
    // The rules the ruleset is built from, so each row's label is the one
    // the ruleset gives its path.
    let grants = linux::grants(&paths);
    let rows: Vec<_> = grants
        .iter()
        .map(|g| {
            let label = if g.write { "write" } else { "read" };
            format!("{label}: {}", g.path.display())
        })
        .collect();
    assert_eq!(block("policy:grants"), rows.join("\n"));
    // And each rule allows what the document says its label grants.
    use landlock::{Access, AccessFs, BitFlags};
    let abi = linux::TARGET_ABI;
    let file_rights =
        AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Execute | AccessFs::Truncate;
    let files = ["<city-file>", "<asn-file>", "<keylog-file>"].map(std::path::Path::new);
    for grant in &grants {
        let (dir, file) = if files.contains(&grant.path.as_path()) {
            (None, BitFlags::from(AccessFs::ReadFile))
        } else if grant.write {
            let all = AccessFs::from_all(abi);
            (Some(all), all & file_rights)
        } else {
            let read = AccessFs::from_read(abi);
            (Some(read), read & file_rights)
        };
        if let Some(dir) = dir {
            assert_eq!(grant.access(true), dir, "{}", grant.path.display());
        }
        assert_eq!(grant.access(false), file, "{}", grant.path.display());
    }
}

#[test]
fn threat_model_lists_every_outbound_endpoint() {
    use crate::{
        collectors::{health, traceroute, whois},
        diagnose::{active, next_test},
    };
    // Each row's destinations as whole words, so a changed endpoint cannot
    // pass on another row's address or a prefix of the documented URL.
    let rows: std::collections::HashMap<&str, Vec<&str>> = block("egress")
        .lines()
        .filter_map(|line| {
            let mut cells = line.split('|').skip(1).map(str::trim);
            let service = cells.next()?;
            let words = cells.next()?.split([' ', ',', ';']);
            Some((service, words.filter(|w| !w.is_empty()).collect()))
        })
        .collect();
    let mut endpoints = vec![
        ("Reference DNS", health::REFERENCE_RESOLVER.to_owned()),
        ("Reference DNS", health::CROSS_CHECK_NAME.to_owned()),
        ("Internet reachability", health::INTERNET_TARGET.to_owned()),
        ("Startup trace", traceroute::STARTUP_TARGET.to_owned()),
        ("WHOIS on W", whois::RDAP_URL.to_owned()),
    ];
    endpoints.extend(
        health::STUN_SERVERS
            .iter()
            .map(|s| ("STUN", (*s).to_owned())),
    );
    let config = active::Config::default();
    endpoints.extend(
        config
            .portal_endpoints
            .into_iter()
            .map(|e| ("Captive portal", e.url)),
    );
    for pair in config.ipv6_pairs {
        endpoints.push(("Dual-stack experiments", pair.v4.to_string()));
        endpoints.push(("Dual-stack experiments", pair.v6.to_string()));
    }
    endpoints.push((
        "Explicit upload test",
        next_test::Context::new("1.1.1.1".parse().unwrap()).upload_url,
    ));
    for (service, endpoint) in endpoints {
        let row = rows
            .get(service)
            .unwrap_or_else(|| panic!("no {service} row"));
        assert!(
            row.contains(&endpoint.as_str()),
            "{service}: missing {endpoint}"
        );
    }
}

/// Whether a sentence names eBPF (or its SDK source) as switched off by the
/// sandbox, in either order. Untrue since 0.32.2, when the load moved
/// inside the policy (`ebpf/conn_tracker.rs`).
fn says_sandbox_turns_off_ebpf(sentence: &str) -> bool {
    let s = sentence.to_lowercase();
    // Greedy: the earliest match of each step leaves the most text for the next.
    let then = |from: usize, words: &[&str]| {
        words
            .iter()
            .filter_map(|w| s[from..].find(w).map(|i| from + i + w.len()))
            .min()
    };
    let ordered = |first: &[&str], last: &[&str]| {
        then(0, first)
            .and_then(|i| then(i, &["disabl"]))
            .and_then(|i| then(i, last))
            .is_some()
    };
    let ebpf = ["ebpf", "sdk"];
    let sandbox = ["sandbox", "policy"];
    ordered(&ebpf, &sandbox) || ordered(&sandbox, &ebpf)
}

#[test]
fn docs_have_no_stale_sandbox_claims() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // A dated log: its header says each entry keeps the status it had when
    // written, and the PR05 entry predates 0.32.2.
    let historical = root
        .join("docs")
        .join("research")
        .join("implementation-progress.md");
    let mut pending = vec![root.join("docs"), root.join("src"), root.join("README.md")];
    let mut stale = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(std::fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
            continue;
        }
        if path == historical {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // Prose only: in Rust sources, the comments. Code is held to the
        // same claim by the tests of what it reports, such as doctor's.
        let rust = path.extension().is_some_and(|e| e == "rs");
        let prose = text
            .lines()
            .map(str::trim)
            .map(|line| match line.strip_prefix("//") {
                Some(comment) => comment.trim_start_matches(['/', '!']),
                None if rust => ".",
                None => line,
            })
            .collect::<Vec<_>>()
            .join(" ");
        stale.extend(
            prose
                .split(['.', ';'])
                .filter(|s| says_sandbox_turns_off_ebpf(s))
                .map(|s| format!("{}: {}", path.display(), s.trim())),
        );
    }
    assert!(stale.is_empty(), "{}", stale.join("\n"));
}
