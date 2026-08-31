//! The declared egress policy: the allowlist the linter checks flows against.
//!
//! Split out of the profiler deliberately. This is the one part of netwatch
//! that is a *security control* rather than an observation — a bug here does
//! not produce a wrong number on a dashboard, it silently admits traffic that
//! should have been reported. It has no dependency on the profiler, so it can
//! be read, reviewed and tested entirely on its own, which is the point.
//!
//! The shape is `process → {allowed SNIs, ASNs, IPs, ports}`, loaded from
//! `egress-policy.toml`. A rule admits a flow if *any* dimension it declares
//! matches; an empty dimension means "unrestricted on that axis".

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ── Declared egress policy ─────────────────────────────────────────────

/// A declarative egress allowlist: `process → {allowed SNIs, ASNs, ports}`.
/// The linter warns when a process with a rule talks to something outside
/// it — a sentence no firewall ruleset can express. It never blocks.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EgressPolicy {
    /// Treat the policy as *complete*: a process with no rule is a finding,
    /// not a blind spot. Off by default, because it is only meaningful once
    /// the operator believes they have declared everything.
    ///
    /// This is the difference between "netwatch tells me when my declared
    /// software misbehaves" and "netwatch tells me when something is
    /// exfiltrating". Without it the linter cannot see the one thing a
    /// compromise actually introduces — a binary nobody declared — because
    /// an undeclared process has no rule to violate and so warns never.
    ///
    /// Lives in the policy file rather than config.toml deliberately: it is
    /// a claim about *this policy*, travels with it, and is meaningless
    /// without one.
    #[serde(default)]
    pub strict: bool,
    /// Drift adjudication. The catalog tier is always on; this block only
    /// governs the local-model tier, which is off unless asked for.
    ///
    /// Lives here rather than in `config.toml` for the same reason `strict`
    /// does — it describes how *this policy's* findings should be read.
    #[serde(default)]
    pub adjudication: super::adjudicate::AdjudicationConfig,
    #[serde(default)]
    pub process: HashMap<String, ProcessRule>,
}

/// The allowed egress for one process. An empty list means "unrestricted on
/// that dimension" — e.g. empty `allow_ports` permits any port.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ProcessRule {
    /// Allowed destination hostnames. Exact (`api.example.com`) or a leading
    /// wildcard (`*.example.com`, which also matches the apex).
    #[serde(default)]
    pub allow_sni: Vec<String>,
    /// Allowed autonomous-system orgs (matched case-insensitively), used when
    /// a flow has no readable SNI.
    #[serde(default)]
    pub allow_asn: Vec<String>,
    /// Allowed raw destination IPs — the identity for a flow that carried no
    /// name (no ClientHello SNI, no resolved ASN). Without this, a rule that
    /// is name-restricted by *other* destinations would flag its own nameless
    /// members as drift.
    #[serde(default)]
    pub allow_ip: Vec<String>,
    /// Allowed destination ports. Empty ⇒ any port.
    #[serde(default)]
    pub allow_ports: Vec<u16>,
}

impl ProcessRule {
    /// Returns `Some(reason)` if the destination is outside this rule. The
    /// destination is identified by whichever of `sni` / `asn_org` / `ip` the
    /// flow carried; a rule admits a flow if *any* dimension it declares
    /// matches. This is why a promoted baseline admits its own members: a
    /// named dest matches by SNI, a raw-IP dest matches by IP.
    pub(super) fn violation(
        &self,
        sni: Option<&str>,
        asn_org: Option<&str>,
        ip: &str,
        port: u16,
    ) -> Option<String> {
        if !self.allow_ports.is_empty() && !self.allow_ports.contains(&port) {
            return Some(format!("port {port} not in allowlist"));
        }
        let name_restricted =
            !self.allow_sni.is_empty() || !self.allow_asn.is_empty() || !self.allow_ip.is_empty();
        if name_restricted {
            let sni_ok = sni.is_some_and(|s| self.allow_sni.iter().any(|p| sni_matches(p, s)));
            let asn_ok =
                asn_org.is_some_and(|a| self.allow_asn.iter().any(|x| x.eq_ignore_ascii_case(a)));
            let ip_ok = self.allow_ip.iter().any(|x| ip_matches(x, ip));
            if !sni_ok && !asn_ok && !ip_ok {
                // Never build a message with an empty subject: a destination
                // with no SNI, no ASN and no readable IP used to warn as
                // " not in allowlist", which reads as a bug rather than a
                // finding. Name the gap instead.
                let dest = sni
                    .or(asn_org)
                    .filter(|d| !d.is_empty())
                    .unwrap_or(if ip.is_empty() {
                        "unknown destination"
                    } else {
                        ip
                    });
                return Some(format!("{dest} not in allowlist"));
            }
        }
        None
    }
}

/// Match an `allow_sni` pattern against a host. Supports an exact match or a
/// leading `*.` wildcard (`*.example.com` matches `a.example.com` and the
/// apex `example.com`). Case-insensitive.
pub(super) fn sni_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.eq_ignore_ascii_case(suffix)
            || host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", suffix.to_ascii_lowercase()))
    } else {
        host.eq_ignore_ascii_case(pattern)
    }
}

/// Match an `allow_ip` entry against a destination address. Accepts an exact
/// address or a CIDR block (`10.0.0.0/8`, `2001:db8::/32`).
///
/// CIDR matters because `allow_ip` exists for destinations that carried no
/// name — no ClientHello SNI, no resolved ASN — and those are disproportionately
/// the ones behind cloud address ranges that rotate. Without it the only way to
/// declare such a destination is to enumerate addresses that change underneath
/// the policy, so the rule goes stale and starts reporting drift that is really
/// a renumbering.
///
/// Hand-rolled rather than pulled from a crate: this is ~30 lines of masking,
/// and every dependency added here is one more package a distro maintainer has
/// to package before netwatch can ship in their archive.
///
/// A malformed pattern matches nothing rather than everything. Failing closed
/// on an allowlist means an unreadable rule produces drift warnings — noisy,
/// and noticed. Failing open would silently admit the traffic it could not
/// parse, which is the one outcome an allowlist must never have.
pub(super) fn ip_matches(pattern: &str, ip: &str) -> bool {
    if pattern == ip {
        return true;
    }
    let Some((net, len)) = pattern.split_once('/') else {
        return false;
    };
    let Ok(bits) = len.trim().parse::<u32>() else {
        return false;
    };
    let (Ok(net), Ok(addr)) = (
        net.trim().parse::<std::net::IpAddr>(),
        ip.trim().parse::<std::net::IpAddr>(),
    ) else {
        return false;
    };
    match (net, addr) {
        (std::net::IpAddr::V4(n), std::net::IpAddr::V4(a)) => {
            if bits > 32 {
                return false;
            }
            if bits == 0 {
                return true;
            }
            // Guarded above: `bits` is 1..=32, so the shift is 0..=31 and
            // cannot overflow.
            let mask = u32::MAX << (32 - bits);
            u32::from(n) & mask == u32::from(a) & mask
        }
        (std::net::IpAddr::V6(n), std::net::IpAddr::V6(a)) => {
            if bits > 128 {
                return false;
            }
            if bits == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - bits);
            u128::from(n) & mask == u128::from(a) & mask
        }
        // A v4 rule never admits a v6 destination, or the reverse.
        _ => false,
    }
}

/// Default policy location: `<config_dir>/netwatch/egress-policy.toml`.
pub fn default_policy_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("netwatch").join("egress-policy.toml"))
}

/// Suggest wildcard collapses for a rule: when several `allow_sni` entries
/// are subdomains of one apex (naively the last two labels), a `*.apex`
/// entry would cover them all. Returned as *suggestions* — the promotion
/// writes the exact entries and a comment; the human collapses by hand if
/// they agree. Silent collapse would widen the allowlist unratified.
pub fn wildcard_suggestions(rule: &ProcessRule) -> Vec<String> {
    const MIN_SUBDOMAINS: usize = 3;
    let mut by_apex: HashMap<String, usize> = HashMap::new();
    for host in &rule.allow_sni {
        if host.starts_with("*.") {
            continue; // already a wildcard
        }
        let labels: Vec<&str> = host.split('.').collect();
        // Only proper subdomains suggest a wildcard; apex entries don't.
        // (Two-label apex assumption — good enough for a suggestion; wrong
        // for eTLDs like co.uk, which is why this never auto-applies.)
        if labels.len() > 2 {
            let apex = labels[labels.len() - 2..].join(".");
            *by_apex.entry(apex).or_insert(0) += 1;
        }
    }
    let mut out: Vec<String> = by_apex
        .into_iter()
        .filter(|(_, n)| *n >= MIN_SUBDOMAINS)
        .map(|(apex, n)| format!("*.{apex} would cover {n} entries"))
        .collect();
    out.sort();
    out
}

/// Load a policy from disk. `None` if the file is absent or unparseable.
/// On unix a group- or world-writable policy is **refused** (with a loud
/// warning): the policy is a trust anchor — if anyone but the owner can
/// edit it, "warn on drift" can be silenced by the very thing drifting.
pub fn load_policy_file(path: &Path) -> Option<EgressPolicy> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o022 != 0 {
                tracing::warn!(
                    target: "netwatch::egress",
                    path = %path.display(),
                    mode = format!("{:o}", mode & 0o777),
                    "REFUSING group/world-writable egress policy — chmod 644 (or stricter) to load it"
                );
                return None;
            }
        }
    }
    let contents = std::fs::read_to_string(path).ok()?;
    match toml::from_str(&contents) {
        Ok(policy) => Some(policy),
        Err(e) => {
            tracing::warn!(target: "netwatch::egress", path = %path.display(), error = %e, "egress policy parse failed");
            None
        }
    }
}

/// Serialize a policy to disk (creating parent dirs). Used by "promote".
pub fn save_policy_file(policy: &EgressPolicy, path: &Path) -> std::io::Result<()> {
    let body = toml::to_string_pretty(policy)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_owner_only(path, format!("{POLICY_HEADER}{body}").as_bytes())
}

/// Write a file owner-read/write only (`0o600` on unix). The egress policy is
/// a trust anchor: `load_policy_file` refuses a group/world-writable one, so
/// our OWN writes must be tight or promote-then-reload would refuse the file
/// we just wrote (which looked like "promote didn't take"). No-op perms on
/// non-unix; the byte write still happens.
pub(super) fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        // Re-assert mode in case the file pre-existed with looser perms
        // (create+mode only applies to newly-created files).
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

const POLICY_HEADER: &str = "# netwatch egress policy (observe → promote → warn).\n\
                             # Generated from the observed baseline; review before trusting.\n\
                             # The linter WARNS on drift — it never blocks.\n\
                             #\n\
                             # strict = true treats this policy as complete: any process\n\
                             # WITHOUT a rule below is then reported as undeclared. Off by\n\
                             # default. Turn it on once you believe the list is complete —\n\
                             # it is what lets the linter see a binary nobody declared.\n\
                             #\n\
                             # Promotion never writes allow_asn from an observation: an AS\n\
                             # entry admits every host that AS operates. Widen by hand if\n\
                             # you mean it.\n\n";

/// Union the string entries already declared under `key` in an existing
/// TOML process table with the newly-promoted ones. Deduped, sorted, stable.
fn union_strings(existing: Option<&toml_edit::Item>, key: &str, add: &[String]) -> Vec<String> {
    let mut set: BTreeSet<String> = add.iter().cloned().collect();
    if let Some(arr) = existing.and_then(|e| e.get(key)).and_then(|v| v.as_array()) {
        for v in arr.iter() {
            if let Some(s) = v.as_str() {
                set.insert(s.to_string());
            }
        }
    }
    set.into_iter().collect()
}

/// Port variant of `union_strings`.
fn union_ports(existing: Option<&toml_edit::Item>, key: &str, add: &[u16]) -> Vec<u16> {
    let mut set: BTreeSet<u16> = add.iter().copied().collect();
    if let Some(arr) = existing.and_then(|e| e.get(key)).and_then(|v| v.as_array()) {
        for v in arr.iter() {
            if let Some(n) = v.as_integer() {
                if let Ok(p) = u16::try_from(n) {
                    set.insert(p);
                }
            }
        }
    }
    set.into_iter().collect()
}

/// Delete the named processes' rules from the policy file, preserving
/// everything else. The counterpart to `merge_rules_into_policy_file`, which
/// only ever grows an allowlist.
///
/// Returns the names actually removed — a name with no rule is not an error,
/// it is simply nothing to do, and the caller says so rather than claiming a
/// removal that didn't happen.
///
/// Removing a rule is the one destructive operation in the linter: it can
/// discard hand-written entries the baseline cannot regenerate. So it refuses
/// an unparseable file for the same reason promotion does, writes owner-only,
/// and the caller is expected to confirm first.
///
/// A comment sitting immediately above a rule goes with it — such a comment
/// documents that rule, and leaving it behind would orphan a note about
/// something no longer in the file. The one exception is the file's own
/// leading comment block, which `toml_edit` happens to store as the first
/// table's prefix: removing the first (or only) rule would otherwise delete
/// the header explaining `strict` and the promotion semantics, leaving a file
/// with no hint of how to get it back. That block is restored explicitly.
pub fn remove_rules_from_policy_file(
    names: &[String],
    path: &Path,
) -> std::io::Result<Vec<String>> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        // Nothing declared anywhere: removing is vacuously done. Creating the
        // file here just to delete from it would be absurd.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut doc: toml_edit::DocumentMut = existing.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("existing policy does not parse (fix it by hand first): {e}"),
        )
    })?;

    let mut removed = Vec::new();
    if let Some(tbl) = doc.get_mut("process").and_then(|p| p.as_table_mut()) {
        for name in names {
            if tbl.remove(name.as_str()).is_some() {
                removed.push(name.clone());
            }
        }
        // Leave `[process]` implicit so an emptied policy renders as the
        // header and nothing else, rather than a stray bare table.
        tbl.set_implicit(true);
    }
    if removed.is_empty() {
        return Ok(removed);
    }
    let mut body = doc.to_string();
    let head = leading_comment_block(&existing);
    if !head.is_empty() && !body.starts_with(&head) {
        body.insert_str(0, &head);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_owner_only(path, body.as_bytes())?;
    Ok(removed)
}

/// The run of comment and blank lines at the very top of a policy file — its
/// header. Returned with the trailing newline so it can be re-prepended
/// verbatim.
fn leading_comment_block(src: &str) -> String {
    let mut out = String::new();
    for line in src.lines() {
        let t = line.trim_start();
        if t.starts_with('#') || t.is_empty() {
            out.push_str(line);
            out.push('\n');
        } else {
            break;
        }
    }
    // A file that is *only* comments has no rules to remove, so preserving
    // "everything" would be a no-op anyway; more usefully, this stops a
    // comment-only file from being duplicated onto itself.
    if out.len() == src.len() {
        return String::new();
    }
    out
}

/// Upsert `rules` into the policy file, preserving everything else — hand
/// edits, comments, and rules for processes not being promoted. Promotion
/// is additive per process: it unions the observed entries with those already
/// declared (it never shrinks or deletes an allowlist). Removal is
/// `remove_rules_from_policy_file`. Refuses (rather than clobbers) a file that
/// no longer parses, so a broken hand edit is never silently thrown away.
pub fn merge_rules_into_policy_file(
    rules: &[(String, ProcessRule)],
    path: &Path,
) -> std::io::Result<()> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => POLICY_HEADER.to_string(),
        Err(e) => return Err(e),
    };
    let mut doc: toml_edit::DocumentMut = existing.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("existing policy does not parse (fix it by hand first): {e}"),
        )
    })?;

    let process_tbl = doc["process"].or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    if let Some(t) = process_tbl.as_table_mut() {
        // Render `[process.<name>]` sections only — no bare `[process]`.
        t.set_implicit(true);
    }
    for (name, rule) in rules {
        // Promote is *additive*: union the newly-observed entries with
        // whatever the file already declares for this process — prior
        // promotes that have since aged out of the live baseline, and any
        // hand-added entries. Replacing would shrink the allowlist to just
        // what's observed this session (the "not updating the full list"
        // bug); ratification only ever grows it. Removal stays a manual edit.
        let existing = doc["process"].get(name.as_str());
        let sni = union_strings(existing, "allow_sni", &rule.allow_sni);
        let asn = union_strings(existing, "allow_asn", &rule.allow_asn);
        let ip = union_strings(existing, "allow_ip", &rule.allow_ip);
        let ports = union_ports(existing, "allow_ports", &rule.allow_ports);

        let mut t = toml_edit::Table::new();
        // Wildcard suggestions land as a comment above the rule — visible
        // exactly where the human reviews, applied only by their hand.
        // Computed on the *unioned* set so the suggestion reflects the file.
        let unioned = ProcessRule {
            allow_sni: sni.clone(),
            allow_asn: asn.clone(),
            allow_ip: ip.clone(),
            allow_ports: ports.clone(),
        };
        let suggestions = wildcard_suggestions(&unioned);
        if !suggestions.is_empty() {
            t.decor_mut()
                .set_prefix(format!("# suggestion: {}\n", suggestions.join("; ")));
        }
        t["allow_sni"] =
            toml_edit::value(toml_edit::Array::from_iter(sni.iter().map(String::as_str)));
        t["allow_asn"] =
            toml_edit::value(toml_edit::Array::from_iter(asn.iter().map(String::as_str)));
        t["allow_ip"] =
            toml_edit::value(toml_edit::Array::from_iter(ip.iter().map(String::as_str)));
        t["allow_ports"] = toml_edit::value(toml_edit::Array::from_iter(
            ports.iter().map(|p| i64::from(*p)),
        ));
        doc["process"][name.as_str()] = toml_edit::Item::Table(t);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_owner_only(path, doc.to_string().as_bytes())
}

/// One-line summary of what promoting `new` changes relative to the declared
/// rule — the pre-promote evidence shown on the status line.
pub fn rule_diff(old: Option<&ProcessRule>, new: &ProcessRule) -> String {
    fn added<T: PartialEq>(old: &[T], new: &[T]) -> usize {
        new.iter().filter(|x| !old.contains(x)).count()
    }
    let Some(old) = old else {
        return format!(
            "new rule: {} SNI, {} ASN, {} IP, {} ports",
            new.allow_sni.len(),
            new.allow_asn.len(),
            new.allow_ip.len(),
            new.allow_ports.len()
        );
    };
    let (sni, asn, ip, ports) = (
        added(&old.allow_sni, &new.allow_sni),
        added(&old.allow_asn, &new.allow_asn),
        added(&old.allow_ip, &new.allow_ip),
        added(&old.allow_ports, &new.allow_ports),
    );
    if sni + asn + ip + ports == 0 {
        "no additions".to_string()
    } else {
        format!("+{sni} SNI, +{asn} ASN, +{ip} IP, +{ports} ports")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── sni_matches: the function where a wrong answer silently widens an
    // allowlist. Property-style rather than example-style: the invariants are
    // asserted over generated inputs, because the failure mode is an input
    // nobody thought to write an example for.

    /// Every pattern matches itself, whatever its shape or case.
    #[test]
    fn prop_sni_exact_is_reflexive() {
        for host in [
            "example.com",
            "a.example.com",
            "deep.a.example.com",
            "EXAMPLE.com",
            "xn--80ak6aa92e.com",
            "a-b.example.co.uk",
            "1.2.3.4",
        ] {
            assert!(sni_matches(host, host), "{host} did not match itself");
            assert!(
                sni_matches(&host.to_ascii_uppercase(), &host.to_ascii_lowercase()),
                "{host} was case-sensitive"
            );
        }
    }

    /// `*.apex` admits the apex and every depth of subdomain beneath it, and
    /// nothing outside it. The generated depth is what makes this a property
    /// rather than three examples.
    #[test]
    fn prop_sni_wildcard_admits_apex_and_all_depths() {
        let apex = "example.com";
        let pattern = format!("*.{apex}");
        assert!(sni_matches(&pattern, apex), "wildcard rejected the apex");
        let mut host = apex.to_string();
        for depth in 1..=8 {
            host = format!("s{depth}.{host}");
            assert!(
                sni_matches(&pattern, &host),
                "wildcard rejected depth {depth}: {host}"
            );
        }
    }

    /// The neighbours a wildcard must never admit. `notexample.com` is the one
    /// that catches a naive `ends_with` without the dot.
    #[test]
    fn prop_sni_wildcard_rejects_neighbours() {
        let pattern = "*.example.com";
        for host in [
            "notexample.com",
            "example.com.evil.net",
            "example.co",
            "fexample.com",
            "com",
            "",
        ] {
            assert!(
                !sni_matches(pattern, host),
                "wildcard wrongly admitted {host:?}"
            );
        }
    }

    /// A wildcard is never narrower than the exact rule it generalises: if an
    /// exact pattern matches a host, `*.apex` covering that pattern must too.
    #[test]
    fn prop_sni_wildcard_is_a_superset_of_exact() {
        let apex = "example.com";
        let wild = format!("*.{apex}");
        for exact in ["example.com", "a.example.com", "b.a.example.com"] {
            if sni_matches(exact, exact) {
                assert!(
                    sni_matches(&wild, exact),
                    "*.{apex} was narrower than the exact rule {exact}"
                );
            }
        }
    }

    // ── ip_matches: CIDR and exact.

    #[test]
    fn ip_exact_and_cidr_v4() {
        assert!(ip_matches("203.0.113.5", "203.0.113.5"));
        assert!(!ip_matches("203.0.113.5", "203.0.113.6"));
        assert!(ip_matches("10.0.0.0/8", "10.1.2.3"));
        assert!(ip_matches("10.0.0.0/8", "10.255.255.255"));
        assert!(!ip_matches("10.0.0.0/8", "11.0.0.1"));
        assert!(ip_matches("192.168.1.0/24", "192.168.1.7"));
        assert!(!ip_matches("192.168.1.0/24", "192.168.2.7"));
        // /32 is an exact address, /0 is everything.
        assert!(ip_matches("203.0.113.5/32", "203.0.113.5"));
        assert!(!ip_matches("203.0.113.5/32", "203.0.113.6"));
        assert!(ip_matches("0.0.0.0/0", "8.8.8.8"));
    }

    #[test]
    fn ip_cidr_v6_and_family_mismatch() {
        assert!(ip_matches("2001:db8::/32", "2001:db8:1234::1"));
        assert!(!ip_matches("2001:db8::/32", "2001:db9::1"));
        assert!(ip_matches("::/0", "2001:db8::1"));
        // A v4 rule must not admit a v6 destination, or the reverse.
        assert!(!ip_matches("10.0.0.0/8", "2001:db8::1"));
        assert!(!ip_matches("2001:db8::/32", "10.1.2.3"));
    }

    /// Anything unparseable matches nothing. An allowlist that fails open on a
    /// typo is worse than one that fails loudly.
    #[test]
    fn ip_malformed_patterns_match_nothing() {
        for pattern in [
            "10.0.0.0/",
            "10.0.0.0/abc",
            "10.0.0.0/33",
            "2001:db8::/129",
            "not-an-ip/8",
            "/8",
            "10.0.0.0/-1",
        ] {
            assert!(
                !ip_matches(pattern, "10.1.2.3"),
                "malformed pattern {pattern:?} admitted traffic"
            );
        }
    }

    /// Every mask width behaves monotonically: widening the prefix can only
    /// admit more, never less.
    #[test]
    fn prop_ip_wider_prefix_admits_more() {
        let ip = "10.1.2.3";
        let mut admitted_at = Vec::new();
        for bits in 0..=32 {
            if ip_matches(&format!("10.0.0.0/{bits}"), ip) {
                admitted_at.push(bits);
            }
        }
        // 10.0.0.0/n admits 10.1.2.3 for every n up to the point the third
        // octet starts to matter; once it stops matching it must never resume.
        let first_reject = (0..=32).find(|b| !admitted_at.contains(b));
        if let Some(r) = first_reject {
            for b in r..=32 {
                assert!(
                    !admitted_at.contains(&b),
                    "/{b} admitted after /{r} rejected — mask is not monotonic"
                );
            }
        }
    }
}
