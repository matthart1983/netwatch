//! Mapping a Windows adapter's friendly name to the Npcap device that captures
//! it. Platform-neutral so the matching is unit-tested on every host; only the
//! lookups feeding it (`platform::windows`) are Windows-only.
//!
//! Npcap names devices `\Device\NPF_{GUID}`, and the description it attaches
//! is the driver's — "Hyper-V Virtual Ethernet Adapter", "Intel(R) Ethernet
//! Connection I219-LM", or just "Microsoft" for a Wi-Fi card — never the
//! friendly name ipconfig shows ("Ethernet", "vEthernet (WSL)"). The old
//! resolver matched the friendly name as a *substring of the description*, so
//! "Ethernet" landed on whichever Hyper-V virtual adapter Npcap listed first,
//! and "vEthernet (WSL)" matched nothing and was handed to Npcap verbatim,
//! which fails with "The system cannot find the file specified" (issue #51).
//!
//! The GUID is the adapter's identity, so that is matched first. The IPv4
//! address is the fallback for when the GUID lookup fails, and an exact
//! description match the last resort. There is no substring matching.

use std::collections::HashMap;
use std::net::IpAddr;

/// What the matcher needs from a `pcap::Device`, without depending on pcap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapDevice {
    pub name: String,
    pub desc: Option<String>,
    pub addrs: Vec<IpAddr>,
}

/// Pick the Npcap device for `friendly`, given what is known about it.
///
/// `guid` is the adapter's interface GUID with or without braces; `ipv4` its
/// address as ipconfig prints it. Both are optional because each comes from a
/// separate lookup that can fail independently.
pub fn match_npcap_device(
    friendly: &str,
    guid: Option<&str>,
    ipv4: Option<&str>,
    devices: &[PcapDevice],
) -> Option<String> {
    // Already a device path: `\Device\NPF_{...}` or `\\.\...`.
    if friendly.starts_with("\\Device\\") || friendly.starts_with("\\\\") {
        return Some(friendly.to_string());
    }

    if let Some(guid) = guid {
        let want = format!("npf_{{{}}}", normalise_guid(guid));
        if let Some(dev) = devices
            .iter()
            .find(|d| d.name.to_ascii_lowercase().ends_with(&want))
        {
            return Some(dev.name.clone());
        }
    }

    if let Some(addr) = ipv4.and_then(|s| s.trim().parse::<IpAddr>().ok()) {
        // Require a unique owner: two adapters can share an address
        // transiently (APIPA, a bridge and its member), and guessing between
        // them is the bug this replaces.
        let mut owners = devices.iter().filter(|d| d.addrs.contains(&addr));
        if let (Some(dev), None) = (owners.next(), owners.next()) {
            return Some(dev.name.clone());
        }
    }

    devices
        .iter()
        .find(|d| {
            d.desc
                .as_deref()
                .is_some_and(|desc| desc.eq_ignore_ascii_case(friendly))
        })
        .map(|d| d.name.clone())
}

fn normalise_guid(guid: &str) -> String {
    guid.trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .to_ascii_lowercase()
}

/// Parse `Get-NetAdapter | Select-Object Name,InterfaceGuid | ConvertTo-Json`
/// into friendly name -> GUID. PowerShell emits a bare object for one adapter
/// and an array for several.
pub fn parse_adapter_guids(json: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return map;
    };
    let items = match value {
        serde_json::Value::Array(items) => items,
        obj @ serde_json::Value::Object(_) => vec![obj],
        _ => return map,
    };
    for item in items {
        let (Some(name), Some(guid)) = (item["Name"].as_str(), item["InterfaceGuid"].as_str())
        else {
            continue;
        };
        if !name.is_empty() && !guid.is_empty() {
            map.insert(name.to_string(), normalise_guid(guid));
        }
    }
    map
}

/// Case-insensitive lookup: ipconfig and Get-NetAdapter agree on the name,
/// but not always on its case.
pub fn guid_for(guids: &HashMap<String, String>, friendly: &str) -> Option<String> {
    guids.get(friendly).cloned().or_else(|| {
        guids
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(friendly))
            .map(|(_, v)| v.clone())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(name: &str, desc: &str, addrs: &[&str]) -> PcapDevice {
        PcapDevice {
            name: name.into(),
            desc: Some(desc.into()),
            addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
        }
    }

    // The reporter's machine, as Npcap lists it: two Hyper-V virtual
    // adapters, then the physical NIC. Descriptions carry no friendly name.
    fn hyperv_host() -> Vec<PcapDevice> {
        vec![
            dev(
                "\\Device\\NPF_{AAAA1111-0000-0000-0000-000000000001}",
                "Hyper-V Virtual Ethernet Adapter",
                &["172.29.16.1"],
            ),
            dev(
                "\\Device\\NPF_{AAAA1111-0000-0000-0000-000000000002}",
                "Hyper-V Virtual Ethernet Adapter #2",
                &["172.17.0.1"],
            ),
            dev(
                "\\Device\\NPF_{BBBB2222-0000-0000-0000-000000000003}",
                "Intel(R) Ethernet Connection (17) I219-LM",
                &["192.168.1.50"],
            ),
        ]
    }

    #[test]
    fn guid_picks_the_physical_nic_not_the_first_ethernet_description() {
        let got = match_npcap_device(
            "Ethernet",
            Some("{BBBB2222-0000-0000-0000-000000000003}"),
            None,
            &hyperv_host(),
        );
        assert_eq!(
            got.as_deref(),
            Some("\\Device\\NPF_{BBBB2222-0000-0000-0000-000000000003}")
        );
    }

    #[test]
    fn guid_match_is_case_insensitive_and_brace_tolerant() {
        let got = match_npcap_device(
            "vEthernet (WSL)",
            Some("aaaa1111-0000-0000-0000-000000000001"),
            None,
            &hyperv_host(),
        );
        assert_eq!(
            got.as_deref(),
            Some("\\Device\\NPF_{AAAA1111-0000-0000-0000-000000000001}")
        );
    }

    #[test]
    fn vethernet_resolves_by_address_without_powershell() {
        let got = match_npcap_device("vEthernet (WSL)", None, Some("172.29.16.1"), &hyperv_host());
        assert_eq!(
            got.as_deref(),
            Some("\\Device\\NPF_{AAAA1111-0000-0000-0000-000000000001}")
        );
    }

    #[test]
    fn shared_address_is_not_guessed() {
        let mut devs = hyperv_host();
        devs[1].addrs = vec!["192.168.1.50".parse().unwrap()];
        assert_eq!(
            match_npcap_device("Ethernet", None, Some("192.168.1.50"), &devs),
            None
        );
    }

    #[test]
    fn no_substring_match_on_description() {
        // This is the #51 failure: "Ethernet" is inside every description here.
        assert_eq!(
            match_npcap_device("Ethernet", None, None, &hyperv_host()),
            None
        );
    }

    #[test]
    fn exact_description_is_the_last_resort() {
        let got = match_npcap_device(
            "hyper-v virtual ethernet adapter #2",
            None,
            None,
            &hyperv_host(),
        );
        assert_eq!(
            got.as_deref(),
            Some("\\Device\\NPF_{AAAA1111-0000-0000-0000-000000000002}")
        );
    }

    #[test]
    fn device_paths_pass_through() {
        let path = "\\Device\\NPF_{CCCC3333-0000-0000-0000-000000000009}";
        assert_eq!(
            match_npcap_device(path, None, None, &[]).as_deref(),
            Some(path)
        );
        assert_eq!(
            match_npcap_device("\\\\.\\pipe\\x", None, None, &[]).as_deref(),
            Some("\\\\.\\pipe\\x")
        );
    }

    #[test]
    fn parses_get_netadapter_array_and_single_object() {
        let many = r#"[{"Name":"Ethernet","InterfaceGuid":"{BBBB2222-0000-0000-0000-000000000003}"},
                       {"Name":"vEthernet (WSL)","InterfaceGuid":"{AAAA1111-0000-0000-0000-000000000001}"},
                       {"Name":"","InterfaceGuid":"{DEAD}"}]"#;
        let map = parse_adapter_guids(many);
        assert_eq!(map.len(), 2);
        assert_eq!(
            map["vEthernet (WSL)"],
            "aaaa1111-0000-0000-0000-000000000001"
        );

        let one = r#"{"Name":"Wi-Fi","InterfaceGuid":"{1234ABCD-0000-0000-0000-000000000000}"}"#;
        let map = parse_adapter_guids(one);
        assert_eq!(map["Wi-Fi"], "1234abcd-0000-0000-0000-000000000000");

        assert!(parse_adapter_guids("not json").is_empty());
        assert!(parse_adapter_guids("42").is_empty());
    }

    #[test]
    fn guid_lookup_ignores_case() {
        let map = parse_adapter_guids(
            r#"{"Name":"Wi-Fi","InterfaceGuid":"{1234ABCD-0000-0000-0000-000000000000}"}"#,
        );
        assert_eq!(
            guid_for(&map, "wi-fi").as_deref(),
            Some("1234abcd-0000-0000-0000-000000000000")
        );
        assert_eq!(guid_for(&map, "Ethernet"), None);
    }
}
