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
            "default: {}\nstrict-extra: {}\nbpf-load: {}\nproc-broker: {}",
            caps(linux::CAPS_TO_DROP_DEFAULT),
            caps(linux::CAPS_TO_DROP_STRICT),
            caps(linux::CAPS_FOR_BPF_LOAD),
            caps(linux::CAPS_FOR_PROC_BROKER)
        )
    );
    assert_eq!(block("policy:abi"), format!("{:?}", linux::TARGET_ABI));
    let paths = SandboxPaths {
        config_dir: Some("<config>".into()),
        cache_dir: Some("<cache>".into()),
        state_dir: Some("<state>".into()),
        cwd: Some("<exports>".into()),
        geoip_db_dir: Some("<city-file>".into()),
        geoip_asn_db_dir: Some("<asn-file>".into()),
        keylog_dir: Some("<keylog-file>".into()),
    };
    let mut rows = Vec::new();
    for (kind, entries) in [
        ("read", linux::collect_read_only(&paths)),
        ("write", linux::collect_read_write(&paths)),
    ] {
        rows.extend(entries.iter().map(|p| format!("{kind}: {}", p.display())));
    }
    assert_eq!(block("policy:grants"), rows.join("\n"));
}

#[test]
fn threat_model_lists_every_outbound_endpoint() {
    use crate::{
        collectors::{health, whois},
        diagnose::{active, next_test},
    };
    let egress = block("egress");
    let mut endpoints = vec![
        health::REFERENCE_RESOLVER.to_owned(),
        health::CROSS_CHECK_NAME.to_owned(),
        health::INTERNET_TARGET.to_owned(),
        whois::RDAP_URL.to_owned(),
    ];
    endpoints.extend(health::STUN_SERVERS.iter().map(|s| (*s).to_owned()));
    let config = active::Config::default();
    endpoints.extend(config.portal_endpoints.into_iter().map(|e| e.url));
    for pair in config.ipv6_pairs {
        endpoints.push(pair.v4.to_string());
        endpoints.push(pair.v6.to_string());
    }
    endpoints.push(next_test::Context::new("1.1.1.1".parse().unwrap()).upload_url);
    for endpoint in endpoints {
        assert!(egress.contains(&endpoint), "missing {endpoint}");
    }
}

#[test]
fn docs_have_no_stale_sandbox_claims() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs");
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            for stale in [
                "disabled in sandboxed runs",
                "disabled under enabled sandbox",
            ] {
                assert!(!text.contains(stale), "{}: {stale}", path.display());
            }
        }
    }
}
