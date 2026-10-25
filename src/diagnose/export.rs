//! Redacted episode exports: what a pilot user sends, and nothing else.
//!
//! Local episodes keep real addresses and names because the local history is
//! only useful with them. An export replaces every IP address and every
//! hostname netwatch knows about with a keyed hash, drops process names and
//! artifact paths, and writes one gzipped bundle the user sends themselves.
//!
//! The key is per install and stays on the machine, so the same resolver maps
//! to the same token in every weekly bundle — a reviewer can follow it across
//! incidents — but nobody holding the bundle can reverse or confirm a guess.
//! That is pseudonymisation, not anonymity, and the preview says so.
//!
//! Tokens keep the address class (`ip4-private:…`, `ip4-loopback:…`) because
//! "the resolver is on the LAN" is diagnostic and identifies no one.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::episode::{self, Episode};
use crate::ui::sanitize::{display, display_owned};

pub const FORMAT: &str = "netwatch-episode-export";
pub const VERSION: u32 = 1;

pub struct Redactor {
    key: ring::hmac::Key,
    /// Hostnames seen in structured fields, longest first when replacing.
    names: Vec<String>,
    tokens: HashMap<String, String>,
    target_names: HashMap<String, String>,
    pub counts: BTreeMap<&'static str, usize>,
}

impl Redactor {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret),
            names: Vec::new(),
            tokens: HashMap::new(),
            target_names: HashMap::new(),
            counts: BTreeMap::new(),
        }
    }

    fn token(&mut self, class: &'static str, value: &str) -> String {
        if let Some(t) = self.tokens.get(value) {
            return t.clone();
        }
        let tag = ring::hmac::sign(&self.key, value.as_bytes());
        let hex: String = tag.as_ref()[..5]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let token = format!("{class}:{hex}");
        *self.counts.entry(class).or_default() += 1;
        self.tokens.insert(value.to_string(), token.clone());
        token
    }

    /// A redacted copy of `episode`.
    pub fn episode(&mut self, episode: &Episode) -> Episode {
        let mut ep = episode.clone();
        // Display names can be single-label hosts or arbitrary user text.
        // Map their identity references explicitly, never schema field names.
        for frame in &ep.frames {
            if let Some(egress) = &frame.obs.egress {
                for flow in &egress.flows {
                    let mut safe = flow.clone();
                    safe.process = self.token("process", &flow.process);
                    safe.destination = if flow.destination.parse::<IpAddr>().is_ok() {
                        self.addresses(&flow.destination)
                    } else {
                        self.token("host", &flow.destination)
                    };
                    self.target_names
                        .insert(flow.subject().label(), safe.subject().label());
                }
            }
            for target in &frame.obs.targets {
                self.learn_target(&target.name, target.baseline_key.as_deref());
            }
            // A configured target can have no probe result in any frame,
            // and its name is still the user's own text.
            for (name, revision) in frame.obs.config.iter().flat_map(|c| &c.targets) {
                self.learn_target(name, Some(revision));
            }
        }
        // An issue can outlive its revision in the frames. An episode split
        // during the expiry grace after an edit starts on one frame of the
        // new revision, while the old one's issue is still open under a key
        // and a snapshot that name the old revision.
        for snap in &ep.issues {
            if let super::issue::Subject::Target { name } = &snap.issue.subject {
                self.learn_target(name, snap.issue.scope.configuration.as_deref());
            }
        }
        for label in &mut ep.labels {
            if label.note.take().is_some() {
                *self.counts.entry("free-text").or_default() += 1;
            }
        }
        for frame in &mut ep.frames {
            for s in &mut frame.obs.sockets {
                if s.process.take().is_some() {
                    *self.counts.entry("process").or_default() += 1;
                }
            }
            for (_, reason) in frame.obs.coverage_hints.values_mut() {
                *reason = "[collector/configuration detail removed]".into();
            }
            if let Some(egress) = &mut frame.obs.egress {
                for flow in &mut egress.flows {
                    flow.process = self.token("process", &flow.process);
                    flow.destination = if flow.destination.parse::<IpAddr>().is_ok() {
                        self.addresses(&flow.destination)
                    } else {
                        self.token("host", &flow.destination)
                    };
                }
            }
            self.learn_names(&frame.obs);
            // URL paths and query strings can contain names or credentials
            // that appear nowhere else in an episode. Presence is the evidence.
            if frame.obs.captive_portal_url.is_some() {
                frame.obs.captive_portal_url = Some("[redacted portal URL]".into());
            }
            if let Some(cross) = frame.obs.dns.as_mut().and_then(|dns| dns.cross.as_mut()) {
                cross.name = self.token("host", &cross.name);
            }
            for target in &mut frame.obs.targets {
                target.baseline_key = target
                    .baseline_key
                    .as_ref()
                    .map(|k| self.target_identity(k));
                target.host = if target.host.parse::<IpAddr>().is_ok() {
                    self.addresses(&target.host)
                } else {
                    self.token("host", &target.host)
                };
                for (_, domains) in &mut target.context.link_domains {
                    for domain in domains {
                        if domain != "~." && domain != "." {
                            *domain = self.token("domain", domain);
                        }
                    }
                }
            }
            if let Some(config) = &mut frame.obs.config {
                for (name, revision) in &mut config.targets {
                    *name = self.target_identity(name);
                    *revision = self.target_identity(revision);
                }
                // An address is redacted by the walk below. Anything else
                // here is a name the user typed.
                if config.trace_target.parse::<IpAddr>().is_err() {
                    config.trace_target = self.token("host", &config.trace_target);
                }
            }
        }
        for snap in &mut ep.issues {
            if let super::issue::Subject::Process { name, pid } = &mut snap.issue.subject {
                let old = pid.map_or_else(|| name.clone(), |p| format!("{name}[{p}]"));
                let token = self.token("process", name);
                self.target_names.insert(old, token.clone());
                *name = token;
                *pid = None;
            }
            snap.issue.scope.processes.clear();
            snap.issue.artifacts.clear();
        }
        let mut value = serde_json::to_value(&ep).expect("episodes serialise");
        self.walk(&mut value);
        serde_json::from_value(value).expect("redaction keeps the shape")
    }

    /// Tokens for a target's name and configuration revision, so each maps
    /// the same way wherever it appears.
    fn learn_target(&mut self, name: &str, revision: Option<&str>) {
        let token = self.token("target", name);
        self.target_names.insert(name.to_string(), token);
        if let Some(key) = revision {
            let safe = self.token("target-config", key);
            self.target_names.insert(key.to_string(), safe);
        }
    }

    fn learn_names(&mut self, obs: &super::detectors::Observations) {
        let mut add = |name: &str| {
            let name = name.trim().trim_end_matches('.');
            if name.contains('.')
                && name.parse::<IpAddr>().is_err()
                && !self.names.iter().any(|n| n == name)
            {
                self.names.push(name.to_string());
            }
        };
        for target in &obs.targets {
            add(&target.host);
            add(&target.name);
            for (_, domains) in &target.context.link_domains {
                for domain in domains {
                    add(domain.trim_start_matches('~'));
                }
            }
        }
        if let Some(cross) = obs.dns.as_ref().and_then(|d| d.cross.as_ref()) {
            add(&cross.name);
        }
        for (name, _) in obs.config.iter().flat_map(|c| &c.targets) {
            add(name);
        }
        for path in &obs.paths {
            add(&path.target);
        }
        if let Some(url) = &obs.captive_portal_url {
            let host = url
                .split("://")
                .nth(1)
                .unwrap_or(url)
                .split(['/', ':', '?'])
                .next()
                .unwrap_or_default();
            add(host);
        }
        self.names.sort_by_key(|n| std::cmp::Reverse(n.len()));
    }

    fn walk(&mut self, value: &mut serde_json::Value) {
        use serde_json::Value;
        match value {
            Value::String(s) => *s = self.text(s),
            Value::Array(items) => items.iter_mut().for_each(|v| self.walk(v)),
            Value::Object(map) => {
                if map.get("kind").and_then(Value::as_str) == Some("egress") {
                    if let Some(Value::String(process)) = map.get_mut("process") {
                        *process = self.token("process", process);
                    }
                    if let Some(Value::String(destination)) = map.get_mut("destination") {
                        *destination = if destination.parse::<IpAddr>().is_ok() {
                            self.addresses(destination)
                        } else {
                            self.token("host", destination)
                        };
                    }
                }
                let entries: Vec<(String, Value)> = std::mem::take(map).into_iter().collect();
                for (k, mut v) in entries {
                    // These fields are prose, not evidence. Unknown names in
                    // notes/errors cannot be discovered from structured fields.
                    if matches!(
                        k.as_str(),
                        "detail"
                            | "note"
                            | "message"
                            | "text"
                            | "title"
                            | "why"
                            | "before"
                            | "after"
                    ) {
                        if let Value::String(s) = &mut v {
                            if !s.is_empty() {
                                *self.counts.entry("free-text").or_default() += 1;
                                s.clear();
                            }
                        }
                    }
                    if k == "reason" && !matches!(v.as_str(), Some("opened" | "closed" | "final")) {
                        if let Value::String(s) = &mut v {
                            s.clear();
                        }
                    }
                    // Per-target probe ages are keyed by target name, and a
                    // map key is not a string value the walk would reach. Left
                    // alone, the recording would carry real names and replay
                    // would look for them under their redacted spelling.
                    if k == "target_ages" {
                        if let Value::Object(ages) = &mut v {
                            let renamed: Vec<(String, Value)> = std::mem::take(ages)
                                .into_iter()
                                .map(|(name, age)| (self.target_identity(&name), age))
                                .collect();
                            *ages = renamed.into_iter().collect();
                        }
                    }
                    if k == "reviewer" {
                        if let Value::String(s) = &mut v {
                            *s = self.token("reviewer", s);
                        }
                    }
                    if matches!(k.as_str(), "name" | "subject" | "issue" | "configuration")
                        || (k == "key" && v.as_str().is_some_and(|s| s.contains('|')))
                    {
                        if let Value::String(s) = &mut v {
                            *s = self.target_identity(s);
                        }
                    }
                    // Stable identifiers are authored catalogue values, not hostnames.
                    // A target named like a rule must not rewrite that rule's identity.
                    if !matches!(
                        k.as_str(),
                        "id" | "rule"
                            | "metric"
                            | "test"
                            | "cause"
                            | "top_cause"
                            | "kind"
                            | "state"
                            | "why_not"
                            | "reason"
                    ) {
                        self.walk(&mut v);
                    }
                    let key = if k.contains('\u{1f}') {
                        self.target_identity(&k)
                    } else {
                        k.clone()
                    };
                    let key = if key.contains('\u{1f}') {
                        self.text(&key)
                    } else {
                        key
                    };
                    map.insert(key, v);
                }
            }
            _ => {}
        }
    }

    fn target_identity(&self, s: &str) -> String {
        if let Some(token) = self.target_names.get(s) {
            return token.clone();
        }
        // An issue key: `rule|subject`, or `rule|name|revision` for a
        // configured target. Rule ids never contain `|`.
        if let Some((rule, subject)) = s.split_once('|') {
            if let Some(token) = self.target_names.get(subject) {
                return format!("{rule}|{token}");
            }
            // A revision nothing in the episode names, as in an event about
            // an issue the recording holds no snapshot of, still must not
            // let the name through.
            if let Some((name, revision)) = subject.rsplit_once('|') {
                if let Some(name) = self.target_names.get(name) {
                    let revision = self
                        .target_names
                        .get(revision)
                        .map_or("target-config:[redacted]", String::as_str);
                    return format!("{rule}|{name}|{revision}");
                }
            }
        }
        if let Some((name, metric)) = s.split_once('\u{1f}') {
            if let Some(token) = self.target_names.get(name) {
                return format!("{token}\u{1f}{metric}");
            }
        }
        s.to_string()
    }

    /// Replace every known hostname and every IP address in `s`.
    pub fn text(&mut self, s: &str) -> String {
        let mut out = s.to_string();
        for name in self.names.clone() {
            if out.contains(&name) {
                let token = self.token("host", &name);
                out = out.replace(&name, &token);
            }
        }
        self.addresses(&out)
    }

    fn addresses(&mut self, s: &str) -> String {
        let is_addr_char = |c: char| c.is_ascii_hexdigit() || c == '.' || c == ':';
        let mut out = String::with_capacity(s.len());
        let mut run = String::new();
        let flush = |run: &mut String, out: &mut String, this: &mut Self| {
            if !run.is_empty() {
                out.push_str(&this.address_run(run));
                run.clear();
            }
        };
        for c in s.chars() {
            if is_addr_char(c) {
                run.push(c);
            } else {
                flush(&mut run, &mut out, self);
                out.push(c);
            }
        }
        flush(&mut run, &mut out, self);
        out
    }

    /// One run of address-ish characters: an address, `v4:port`, or not an
    /// address at all (a time, a version number, a hex word).
    fn address_run(&mut self, run: &str) -> String {
        let trimmed = run.trim_end_matches(['.', ':']);
        let tail = &run[trimmed.len()..];
        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            if trimmed.contains(['.', ':']) && !is_unspecified_text(trimmed) {
                return format!("{}{tail}", self.token(class(&ip), trimmed));
            }
        }
        if let Some((host, port)) = trimmed.rsplit_once(':') {
            if let (Ok(ip @ IpAddr::V4(_)), true) = (
                host.parse::<IpAddr>(),
                port.chars().all(|c| c.is_ascii_digit()),
            ) {
                return format!("{}:{port}{tail}", self.token(class(&ip), host));
            }
        }
        run.to_string()
    }
}

/// `::` on its own parses as an address but is far more often punctuation.
fn is_unspecified_text(s: &str) -> bool {
    s == "::"
}

fn class(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(v4) if v4.is_loopback() => "ip4-loopback",
        IpAddr::V4(v4) if v4.is_private() => "ip4-private",
        IpAddr::V4(v4) if v4.is_link_local() => "ip4-linklocal",
        IpAddr::V4(v4) if v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]) => {
            "ip4-cgnat"
        }
        IpAddr::V4(_) => "ip4-public",
        IpAddr::V6(v6) if v6.is_loopback() => "ip6-loopback",
        IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80 => "ip6-linklocal",
        IpAddr::V6(v6) if (v6.segments()[0] & 0xfe00) == 0xfc00 => "ip6-ula",
        IpAddr::V6(_) => "ip6-public",
    }
}

// ------------------------------------------------------------------ bundle

#[derive(Debug, Serialize)]
pub struct Bundle {
    pub format: &'static str,
    pub version: u32,
    pub created: String,
    /// Stable per install, unlinkable to anything else about the machine.
    pub install: String,
    pub redaction: &'static str,
    pub episodes: Vec<Episode>,
}

pub const REDACTION_NOTE: &str =
    "IP addresses and hostnames replaced with per-install keyed hashes \
(pseudonymised, not anonymous); process names, artifact paths and free-text notes/details removed; target names and routing domains hashed; interface names, \
timings, counts, rule and cause ids kept.";

/// The per-install export key: 32 random bytes, created on first use,
/// readable only by the user.
pub fn install_key(dir: &Path) -> std::io::Result<Vec<u8>> {
    let path = dir.join("export-key");
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            return Ok(bytes);
        }
    }
    let mut key = vec![0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut key)
        .map_err(|_| std::io::Error::other("no system randomness"))?;
    std::fs::create_dir_all(dir)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options.open(&path)?.write_all(&key)?;
    Ok(key)
}

pub struct Preview {
    pub bundle: Bundle,
    pub skipped: Vec<(PathBuf, String)>,
    pub counts: BTreeMap<&'static str, usize>,
}

/// Build a redacted bundle of the episodes under `dir` started within
/// `since_days`.
pub fn build(
    dir: &Path,
    key: &[u8],
    since_days: u64,
    now: chrono::DateTime<chrono::Local>,
) -> Preview {
    let cutoff = super::engine::format_ts(now - chrono::Duration::days(since_days as i64));
    let mut redactor = Redactor::new(key);
    let mut episodes = Vec::new();
    let mut skipped = Vec::new();
    for path in episode::list(dir) {
        match episode::load(&path) {
            Ok(ep) if ep.started >= cutoff => episodes.push(redactor.episode(&ep)),
            Ok(_) => {}
            Err(e) => skipped.push((path, e.to_string())),
        }
    }
    let install = {
        let tag = ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key),
            b"install",
        );
        tag.as_ref()[..6]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    Preview {
        bundle: Bundle {
            format: FORMAT,
            version: VERSION,
            created: super::engine::format_ts(now),
            install,
            redaction: REDACTION_NOTE,
            episodes,
        },
        skipped,
        counts: redactor.counts,
    }
}

pub fn write(bundle: &Bundle, path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&temp)?;
        let mut gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        serde_json::to_writer(&mut gz, bundle).map_err(std::io::Error::other)?;
        gz.finish()?.flush()?;
        std::fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// One line per episode in the bundle, then one per file left out. Ids,
/// times and keys come from the file, which can be someone else's, so each
/// goes through [`display`] on its way to the terminal.
fn preview_lines(preview: &Preview) -> Vec<String> {
    let mut lines: Vec<String> = preview
        .bundle
        .episodes
        .iter()
        .map(|ep| {
            format!(
                "  {}  {}  {:>4}m  {}",
                display(&ep.id.chars().take(8).collect::<String>()),
                display(&ep.started),
                (ep.duration_secs() / 60.0).round() as u64,
                display_owned(ep.issue_keys().join(", "))
            )
        })
        .collect();
    for (path, why) in &preview.skipped {
        lines.push(format!(
            "  skipped {}: {}",
            display_owned(path.display().to_string()),
            display(why)
        ));
    }
    lines
}

/// `netwatch diagnose export [--since DAYS] [--out FILE] [--dry-run] [DIR]`
pub fn command(args: &[String]) -> anyhow::Result<()> {
    let (mut since, mut out, mut dry_run, mut dir) = (7u64, None, false, None);
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--since" => {
                let v = rest
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--since needs days"))?;
                since = v.trim_end_matches('d').parse()?;
            }
            "--out" => {
                out = Some(PathBuf::from(
                    rest.next()
                        .ok_or_else(|| anyhow::anyhow!("--out needs a file"))?,
                ))
            }
            "--dry-run" => dry_run = true,
            other if other.starts_with("--") => anyhow::bail!("unknown option {other}"),
            other => dir = Some(PathBuf::from(other)),
        }
    }
    let state = episode::default_dir()
        .and_then(|d| d.parent().map(Path::to_path_buf))
        .ok_or_else(|| anyhow::anyhow!("no state directory"))?;
    let dir = dir.unwrap_or_else(|| state.join("episodes"));
    let key = install_key(&state)?;
    let now = chrono::Local::now();
    let preview = build(&dir, &key, since, now);

    println!(
        "episodes from the last {since} days under {}:",
        dir.display()
    );
    for line in preview_lines(&preview) {
        println!("{line}");
    }
    let redacted: Vec<String> = preview
        .counts
        .iter()
        .map(|(k, n)| format!("{n} {k}"))
        .collect();
    println!(
        "redacted: {}",
        if redacted.is_empty() {
            "nothing".into()
        } else {
            redacted.join(", ")
        }
    );
    println!("{REDACTION_NOTE}");

    if dry_run {
        println!("dry run: nothing written");
        return Ok(());
    }
    if preview.bundle.episodes.is_empty() {
        println!("nothing to export");
        return Ok(());
    }
    let path = out.unwrap_or_else(|| {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("netwatch")
            .join("exports")
            .join(format!(
                "netwatch-episodes-{}.json.gz",
                now.format("%Y%m%d-%H%M%S")
            ))
    });
    write(&preview.bundle, &path)?;
    println!(
        "wrote {} — review it, then send it yourself",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The preview prints episodes before anything is written, and the
    /// redactor keeps ids, times and issue keys as the file had them.
    #[test]
    fn the_preview_prints_a_shared_episode_as_text() {
        use crate::ui::sanitize::is_unsafe;
        const OSC52: &str = "\x1b]52;c;aGk=\x07";
        let mut ep = fixture_episode();
        // Byte 8 falls inside the euro sign.
        ep.id = "aaaaaaa€".into();
        ep.started = format!("{}{OSC52}", ep.started);
        ep.frames[0].open.push(episode::OpenIssue {
            key: format!("rule|{OSC52}"),
            top_cause: None,
        });
        let preview = Preview {
            bundle: Bundle {
                format: FORMAT,
                version: VERSION,
                created: String::new(),
                install: String::new(),
                redaction: REDACTION_NOTE,
                episodes: vec![ep],
            },
            skipped: vec![(PathBuf::from(format!("{OSC52}.json.gz")), OSC52.into())],
            counts: BTreeMap::new(),
        };
        let lines = preview_lines(&preview);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("  aaaaaaa€  "), "{lines:?}");
        assert!(lines[0].contains("rule|·]52"), "{lines:?}");
        assert!(lines[1].starts_with("  skipped ·]52"), "{lines:?}");
        for line in &lines {
            assert!(!line.chars().any(is_unsafe), "{line:?}");
        }
    }

    #[test]
    fn addresses_become_stable_classed_tokens() {
        let mut r = Redactor::new(b"test key");
        let a = r.text("resolver 192.168.8.1 answered; 192.168.8.1 again");
        let parts: Vec<&str> = a.split(' ').collect();
        assert!(parts[1].starts_with("ip4-private:"));
        assert_eq!(parts[1], parts[3]);
        assert!(!a.contains("192.168"));

        let s = r.text("10.88.0.2:52344 → 1.1.1.1:443 via fe80::1%wlan0 and [2001:db8::5]:53");
        assert!(
            !s.contains("10.88") && !s.contains("1.1.1.1") && !s.contains("2001:db8"),
            "{s}"
        );
        assert!(
            s.contains(":52344") && s.contains(":443"),
            "ports survive: {s}"
        );
        assert!(s.contains("ip6-linklocal:") && s.contains("%wlan0"));
    }

    #[test]
    fn times_versions_and_words_are_left_alone() {
        let mut r = Redactor::new(b"k");
        let text = "2026-09-14 20:56:46 · v0.31.2 · 12.5ms · cafe · aa:bb:cc:dd:ee:ff · a :: b";
        assert_eq!(r.text(text), text);
    }

    #[test]
    fn a_different_install_key_gives_different_tokens() {
        let a = Redactor::new(b"one").text("1.1.1.1");
        let b = Redactor::new(b"two").text("1.1.1.1");
        assert_ne!(a, b);
    }

    fn fixture_episode() -> Episode {
        fixture_episode_with_target(None)
    }

    fn fixture_episode_with_target(target: Option<super::super::targets::TargetObs>) -> Episode {
        use crate::diagnose::engine::{Clock, Engine, FixedClock, ObservationTimes};
        use crate::diagnose::fixture;
        let clock = std::sync::Arc::new(FixedClock::at("2026-09-03 06:44:00"));
        let mut engine = Engine::new(Box::new(clock.clone()));
        let base = fixture::baselines();
        let mut rec = episode::Recorder::new(episode::EnvProfile::detect("root", 1000), 1.789e9);
        rec.schedule_quiet_sample(f64::MAX);
        let start = std::time::Instant::now() + std::time::Duration::from_secs(86_400);
        for t in 0..=fixture::SCENARIO_SECS {
            let mut obs = fixture::observations_at(t);
            for s in &mut obs.sockets {
                s.process = Some("firefox".into());
            }
            if let Some(target) = &target {
                let mut target = target.clone();
                target.probed_at = crate::diagnose::engine::format_ts(clock.now());
                obs.targets.push(target);
            }
            let now = start + std::time::Duration::from_secs(t);
            let mut times = ObservationTimes {
                interface: Some(now),
                sockets: Some(now),
                path: Some(now),
                ..Default::default()
            };
            times.targets = target
                .as_ref()
                .map(|t| (t.name.clone(), now))
                .into_iter()
                .collect();
            times.health.dns = Some(now);
            times.health.gateway = Some(now);
            times.health.internet = Some(now);
            engine.observe_live_at(&obs, &base, &times, now);
            let _ = rec.record(episode::Tick {
                at: 1.789e9 + t as f64,
                ts: crate::diagnose::engine::format_ts(clock.now()),
                now,
                obs: &obs,
                times: &times,
                readings: &[],
                engine: &engine,
                baselines: &base,
                events: vec![],
            });
            clock.advance_secs(1);
        }
        rec.flush(&engine, &crate::diagnose::engine::format_ts(clock.now()))
            .unwrap()
    }

    #[test]
    fn a_redacted_episode_holds_no_address_or_process_and_still_replays() {
        let ep = fixture_episode();
        let raw = serde_json::to_string(&ep).unwrap();
        let mut r = Redactor::new(b"install");
        let redacted = r.episode(&ep);
        let text = serde_json::to_string(&redacted).unwrap();

        let mut probe = Redactor::new(b"probe");
        let originals: Vec<String> = probe.tokens_in(&raw);
        assert!(
            originals.len() >= 4,
            "the fixture should carry addresses: {originals:?}"
        );
        for addr in &originals {
            assert!(!text.contains(addr.as_str()), "{addr} survived redaction");
        }
        assert!(!text.contains("firefox"));
        assert!(raw.contains("firefox"));

        // One consistent mapping means the engine sees the same structure,
        // so replay reaches the same issues under their redacted names.
        let report = episode::replay(&redacted);
        assert!(report.matches(), "{:#?}", report.divergences.first());
        assert_eq!(report.issues.len(), episode::replay(&ep).issues.len());
    }

    #[test]
    fn why_not_survives_redaction() {
        use crate::diagnose::coverage::Availability;
        // Redaction clears a check's detail as free text, which leaves
        // `why_not` as the only reason an exported check gives for not
        // running. It is a catalogue word, not a name, so it passes untouched.
        let not_run = |ep: &Episode| -> Vec<(String, Option<Availability>, String)> {
            ep.issues
                .iter()
                .flat_map(|s| s.issue.causes.iter())
                .flat_map(|c| c.checks.iter())
                .filter(|k| k.passed.is_none())
                .map(|k| (k.id.clone(), k.why_not.clone(), k.detail.clone()))
                .collect()
        };
        let ep = fixture_episode();
        let before = not_run(&ep);
        assert!(
            before.iter().any(|(_, why, detail)| {
                *why == Some(Availability::AwaitingTest) && !detail.is_empty()
            }),
            "the fixture should hold a check awaiting a test: {before:?}"
        );
        let safe = Redactor::new(b"install").episode(&ep);
        let after = not_run(&safe);
        assert_eq!(after.len(), before.len());
        for ((id, why, _), (safe_id, safe_why, safe_detail)) in before.iter().zip(&after) {
            assert_eq!((id, why), (safe_id, safe_why));
            assert!(safe_detail.is_empty(), "{safe_detail}");
        }
        let text = serde_json::to_string(&safe).unwrap();
        assert!(text.contains(r#""state":"not_run""#), "{text}");
    }

    /// A target whose resolve fails, named and configured with things only
    /// this user would know.
    fn private_target() -> super::super::targets::TargetObs {
        use crate::diagnose::targets::{Stage, StageError, TargetContext, TargetObs};
        TargetObs {
            stale_after_secs: None,
            attempts: vec![],
            effective_endpoint: None,
            sni: None,
            http_authority: None,
            baseline_key: Some("target-config:private-test-revision".into()),
            name: "dns".into(),     // deliberately collides with a schema field
            host: "payroll".into(), // single-label internal hostname
            port: 443,
            tls: true,
            http: true,
            expect_status: None,
            // Each frame stamps its own.
            probed_at: String::new(),
            resolve: Stage {
                ms: Some(3.0),
                error: Some(StageError::Other {
                    message: "unknown-secret.internal from secret-process".into(),
                }),
            },
            addresses: vec![],
            lookups: vec![],
            connect: None,
            connect_v4: None,
            connect_v6: None,
            tls_stage: None,
            http_stage: None,
            status: None,
            context: TargetContext {
                link_domains: vec![("wg0".into(), vec!["~finance.internal".into()])],
                ..Default::default()
            },
        }
    }

    #[test]
    fn target_identities_and_unknown_free_text_are_redacted_without_changing_schema() {
        let mut ep = fixture_episode_with_target(Some(private_target()));
        for frame in &mut ep.frames {
            frame.obs.coverage_hints.insert(
                "target.connect_failed".into(),
                (
                    crate::diagnose::coverage::Availability::NotConfigured,
                    "duplicate target secret-config-name".into(),
                ),
            );
            // The probed target, one configured target no frame has a
            // result for, and a trace target that is not an address.
            frame.obs.config = Some(crate::diagnose::detectors::ObservedConfig {
                resolvers: Some(vec!["192.168.8.53".into()]),
                targets: vec![
                    ("dns".into(), "target-config:private-test-revision".into()),
                    ("ledger".into(), "target-config:unprobed-revision".into()),
                ],
                trace_target: "tracehost".into(),
                trace_refresh_secs: Some(120),
                interfaces: Some(vec!["wlan0".into()]),
            });
        }
        ep.labels.push(episode::Label {
            issue: "target.resolve_failed|dns".into(),
            cause: "unknown".into(),
            source: episode::LabelSource::User,
            ts: ep.started.clone(),
            note: Some("another-secret.internal from secret-process".into()),
        });
        let mut r = Redactor::new(b"install");
        let safe = r.episode(&ep);
        let text = serde_json::to_string(&safe).unwrap();
        for secret in [
            "payroll",
            "finance.internal",
            "unknown-secret.internal",
            "another-secret.internal",
            "secret-process",
            "secret-config-name",
            "target-config:private-test-revision",
            "ledger",
            "target-config:unprobed-revision",
            "tracehost",
            "192.168.8.53",
        ] {
            assert!(!text.contains(secret), "{secret} escaped redaction");
        }
        // A configured target maps to the tokens its probe results carry,
        // so a replay of the export matches one to the other.
        let probed = &safe.frames[0].obs.targets[0];
        let config = safe.frames[0].obs.config.as_ref().unwrap();
        assert_eq!(
            config.targets[0],
            (probed.name.clone(), probed.baseline_key.clone().unwrap())
        );
        assert!(config.targets[1].0.starts_with("target:"));
        assert!(config.targets[1].1.starts_with("target-config:"));
        assert_eq!(config.interfaces, Some(vec!["wlan0".to_string()]));
        assert!(safe.frames[0].obs.targets[0].name.starts_with("target:"));
        assert!(safe.labels[0]
            .issue
            .starts_with("target.resolve_failed|target:"));
        // A target's issue key carries its name and its revision; both map.
        assert!(!text.contains("target.resolve_failed|dns"), "{text}");
        let key = format!(
            "target.resolve_failed|{}|{}",
            probed.name,
            probed.baseline_key.as_deref().unwrap()
        );
        assert!(text.contains(&key), "{key}");
        assert!(
            safe.frames[0].obs.dns.is_some(),
            "field name must survive target-name collision"
        );
        assert_eq!(
            ep.frames[0].obs.targets[0].host, "payroll",
            "local recording stays intact"
        );
        assert!(safe
            .issues
            .iter()
            .any(|s| s.issue.rule.starts_with("target.")));
        let replay = episode::replay(&safe);
        assert!(replay.matches(), "{:#?}", replay.divergences.first());
    }

    /// An episode split at MAX_EPISODE_SECS in the minute after an edit
    /// starts on one frame, which probes the new revision. The old revision's
    /// issue is still open, so only its key and its snapshot name the old
    /// revision.
    #[test]
    fn a_revision_only_an_issue_names_is_redacted_with_its_target() {
        use crate::diagnose::engine::EngineEvent;
        use crate::diagnose::issue::Subject;
        let mut target = private_target();
        target.name = "payroll-api".into();
        let mut ep = fixture_episode_with_target(Some(target));
        let old = "target.resolve_failed|payroll-api|target-config:private-test-revision";
        assert!(ep.issue_keys().contains(&old.to_string()));
        for t in ep.frames.iter_mut().flat_map(|f| &mut f.obs.targets) {
            t.baseline_key = Some("target-config:edited-revision".into());
        }
        // And an event about a revision nothing else in the episode names.
        ep.frames[1].events.push(EngineEvent::Acked {
            issue: "target.resolve_failed|payroll-api|target-config:unrecorded".into(),
        });

        let safe = Redactor::new(b"install").episode(&ep);
        let text = serde_json::to_string(&safe).unwrap();
        for secret in ["payroll-api", "private-test-revision", "unrecorded"] {
            assert!(!text.contains(secret), "{secret} escaped redaction");
        }
        // The key maps the way the snapshot's name and revision do.
        let snap = safe
            .issues
            .iter()
            .find(|s| s.issue.rule == "target.resolve_failed")
            .unwrap();
        assert!(safe.issue_keys().contains(&snap.issue.key()));
        let Subject::Target { name } = &snap.issue.subject else {
            panic!("{:?}", snap.issue.subject);
        };
        assert!(matches!(
            safe.frames[1].events.as_slice(),
            [EngineEvent::Acked { issue }]
                if *issue == format!("target.resolve_failed|{name}|target-config:[redacted]")
        ));
    }

    #[test]
    fn bundles_include_recent_episodes_and_write_privately_keyed() {
        let root = std::env::temp_dir().join(format!("nw-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("episodes");
        episode::save(&dir, &fixture_episode()).unwrap();
        let key = install_key(&root).unwrap();
        assert_eq!(install_key(&root).unwrap(), key, "the key is created once");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(root.join("export-key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
        let now = crate::diagnose::engine::parse_ts("2026-09-05 12:00:00").unwrap();
        assert_eq!(build(&dir, &key, 7, now).bundle.episodes.len(), 1);
        assert_eq!(build(&dir, &key, 1, now).bundle.episodes.len(), 0);

        let preview = build(&dir, &key, 7, now);
        assert!(preview.counts.get("process").copied().unwrap_or(0) > 0);
        let out = root.join("bundle.json.gz");
        write(&preview.bundle, &out).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&out).unwrap().permissions().mode() & 0o077,
                0
            );
        }
        let mut text = String::new();
        use std::io::Read;
        flate2::read::GzDecoder::new(std::fs::File::open(&out).unwrap())
            .read_to_string(&mut text)
            .unwrap();
        assert!(text.contains(FORMAT) && !text.contains("169.254.1.1"));
        let _ = std::fs::remove_dir_all(&root);
    }

    impl Redactor {
        /// Every original address or known hostname `text` would replace.
        fn tokens_in(&mut self, text: &str) -> Vec<String> {
            self.text(text);
            let mut v: Vec<String> = self.tokens.keys().cloned().collect();
            v.sort();
            v
        }
    }
}
