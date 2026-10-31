use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use toml_edit::{DocumentMut, InlineTable, Item, Table, TableLike, Value};

/// User-facing persistent configuration, stored as `netwatch/config.toml`
/// under the platform config directory (`dirs::config_dir()`): `~/.config` on
/// Linux, `~/Library/Application Support` on macOS, `%APPDATA%` on Windows.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetwatchConfig {
    /// Which tab to show on launch (dashboard, connections, interfaces,
    /// packets, stats, topology, timeline, insights)
    pub default_tab: String,

    /// Tick / refresh rate in milliseconds (100–5000)
    pub refresh_rate_ms: u64,

    /// Preferred capture interface (e.g. "en0"). Empty = auto-detect.
    pub capture_interface: String,

    /// Show GeoIP column in Connections tab
    pub show_geo: bool,

    /// Default timeline window (1m, 5m, 15m, 30m, 1h)
    pub timeline_window: String,

    /// Auto-follow new packets in the Packets tab
    pub packet_follow: bool,

    /// Default BPF capture filter (e.g. "tcp port 443")
    pub bpf_filter: String,

    /// Path to a City or Country .mmdb file, DB-IP's or MaxMind's. Empty uses
    /// what `netwatch geoip update` downloaded, if anything; see
    /// [`geoip_paths`](Self::geoip_paths).
    pub geoip_db: String,

    /// Path to an ASN .mmdb file, DB-IP's or MaxMind's, for organisation
    /// names. Empty uses what `netwatch geoip update` downloaded, if anything.
    pub geoip_asn_db: String,

    /// Removed in 0.39, when it sent every public peer address to a third party
    /// in cleartext. Still read, so a config that sets it loads, and
    /// [`warn_removed_keys`](Self::warn_removed_keys) can say so, but nothing
    /// acts on it and a save drops it from the file.
    #[serde(default, skip_serializing)]
    pub geoip_online: bool,

    /// Network intelligence alert settings
    pub alerts: AlertConfig,

    /// Enable the AI Insights tab (opt-in — off by default)
    pub insights_enabled: bool,

    /// AI insights model name (for Ollama / local LLM or cloud)
    pub insights_model: String,

    /// AI insights endpoint: "local" → http://localhost:11434, or a full base URL
    pub insights_endpoint: String,

    /// Color theme (dark, light, ocean, solarized, dracula, nord)
    pub theme: String,

    /// Which view starts: `full` (the tabbed TUI), `lite` (one 80×24 screen),
    /// or `dense` (the four-box 130×44 screen). `full` stays the default —
    /// the other two are opt-in, and `--view` overrides this for one run.
    #[serde(default = "default_view")]
    pub view: String,

    /// Chart style for every sparkline in the app (`dots` or `bars`) —
    /// hero tiles, in-row connection lines, RTT history, timeline layers and
    /// Lite's charts all route through `graph::render`.
    ///
    /// `dots` is the default and is the braille area plot the Dense view and
    /// the Dashboard's throughput graph draw: two samples per cell column, so
    /// a sparkline carries twice the history in the same width. `bars` is the
    /// pre-v0.21 block look, kept for terminals whose font has no braille
    /// coverage — there the area plot renders as empty boxes.
    pub graph_style: String,

    /// The magnitude gradient. When `true`, every chart colours each cell by
    /// how high it sits — dim at the baseline, the series colour in the
    /// middle, lightened at the peak.
    ///
    /// On by default: it is what makes a filled area read as depth rather
    /// than as a block. Under the `terminal` theme it steps from each series
    /// colour to its bright palette variant instead of blending, so no colour
    /// is invented.
    #[serde(default = "default_graph_fade")]
    pub graph_fade: bool,

    /// Sandbox enforcement mode — `"on"` (best-effort, default),
    /// `"strict"` (refuse to start if the platform backend can't apply),
    /// or `"off"` (skip sandboxing entirely). CLI flags `--no-sandbox`
    /// and `--sandbox-strict` still override. Changes apply on next
    /// netwatch start — Landlock and dropped capabilities can't be undone
    /// at runtime, so the live process keeps whatever mode it launched
    /// with.
    #[serde(default = "default_sandbox")]
    pub sandbox: String,

    /// Path to an NSS `SSLKEYLOGFILE` containing per-connection TLS
    /// secrets exported by a cooperating client (Chrome, Firefox, Node,
    /// curl with `--ssl-no-revoke` etc.). When non-empty, netwatch
    /// reads this file and uses the secrets to decrypt observed TLS
    /// 1.3 Application Data records — same trick Wireshark uses.
    ///
    /// Empty (default) = no decryption. Decryption only works when:
    ///   - You control the client process (it must export its secrets).
    ///   - The client sets `SSLKEYLOGFILE=<this-path>` before launch.
    ///   - The connection is TLS 1.3 (TLS 1.2 / QUIC application data /
    ///     0-RTT not in scope for the initial implementation).
    #[serde(default)]
    pub tls_keylog_path: String,

    /// How long (seconds) before the same violating flow — one
    /// (process, destination, port) — re-warns on egress policy drift.
    /// 0 warns on every connection refresh. Default 300 (5 minutes).
    #[serde(default = "default_egress_cooldown")]
    pub egress_violation_cooldown_secs: u64,

    /// Whether the grouped tables (Connections, Egress) open with every group
    /// folded. Default true: a folded screen answers "what is on this machine"
    /// in one glance, and expanding is one keystroke. Set false to open with
    /// everything visible, which is closer to the old flat tables.
    #[serde(default = "default_groups_collapsed")]
    pub groups_start_collapsed: bool,

    /// Ask before `q` quits. Off by default. Ctrl+C always quits at once.
    #[serde(default)]
    pub confirm_quit: bool,

    /// Record Diagnose episodes: the ten minutes before an issue opens through
    /// ten minutes after it closes, plus one quiet 15-minute sample a day.
    /// Stored locally under `~/.local/state/netwatch/episodes`, kept 90 days
    /// or 300 MB. Nothing is uploaded. Default true.
    #[serde(default = "default_record_episodes")]
    pub diagnose_record_episodes: bool,

    /// Keep the uptime log `netwatch uptime` reports from: a heartbeat a
    /// minute and a line when the gateway, internet or DNS hop goes down or
    /// comes back. Stored locally under `~/.local/state/netwatch/uptime`,
    /// kept 90 days, about 80 KB a day. Nothing is uploaded. Default true.
    #[serde(default = "default_record_uptime")]
    pub record_uptime: bool,

    /// Send the automatic probes that go to public servers: STUN to Google
    /// and Cloudflare, the `dns.google` cross-check against 1.1.1.1, the
    /// internet probe to 1.1.1.1 and the trace a TUI start runs to 1.1.1.1.
    /// With false none of them is sent, and what they would have measured
    /// reads as not measured, never as failed. Your resolver and gateway are
    /// still probed, and what you start yourself still runs. Read at start.
    /// Default true.
    #[serde(default = "default_third_party_probes")]
    pub third_party_probes: bool,

    /// Hosts Diagnose probes stage by stage (DNS, TCP, TLS, HTTP), e.g.
    ///
    /// ```toml
    /// [[diagnose_targets]]
    /// name = "staging api"
    /// host = "api.staging.example.internal"
    /// port = 443
    /// path = "/healthz"
    /// expect_status = 200
    /// ```
    #[serde(default)]
    pub diagnose_probes: crate::diagnose::active::Config,
    /// Left out of a file while empty: `diagnose_targets = []` is a key, and the
    /// `[[diagnose_targets]]` someone appends after it is then a TOML error.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diagnose_targets: Vec<crate::diagnose::targets::TargetConfig>,

    /// The Diagnose engine's thresholds, e.g.
    ///
    /// ```toml
    /// [diagnose_thresholds]
    /// dns_ceiling_ms = 30
    /// ```
    ///
    /// A missing key keeps its default. A value that cannot mean anything
    /// (σ multiple ≤ 0, a negative σ or delta floor, `consecutive_n` = 0, a
    /// share outside 0–100, NaN, a close σ multiple not below the open one)
    /// is logged and replaced by its default. Read at startup: an episode
    /// records the thresholds it ran with, so they do not change mid-run.
    ///
    /// `--generate-config` leaves it out while it holds the defaults. Every other
    /// key it writes, and a table of today's defaults in the file would hold them
    /// there when a release retunes one.
    #[serde(default, skip_serializing_if = "is_default_thresholds")]
    pub diagnose_thresholds: crate::diagnose::detectors::Thresholds,

    /// Settings that can still change: `[experimental]`. See
    /// [`ExperimentalConfig`].
    #[serde(default, skip_serializing_if = "is_default_experimental")]
    pub experimental: ExperimentalConfig,

    /// What the file this came from should have its owner told. Never read
    /// from or written to a file; see [`ConfigWarning`].
    #[serde(skip)]
    pub load_warnings: Vec<ConfigWarning>,

    /// The values this session started from, set by loading and by each save. A
    /// save writes only what differs from these. `None` for a config built in
    /// code, which started from the defaults. Never read from or written to a
    /// file. Public because the rest of the crate and the examples build this
    /// struct with `..Default::default()`, which needs every field visible.
    #[serde(skip)]
    pub loaded: Option<toml::Table>,
}

/// `[experimental]` in config.toml: where a setting goes while it can still
/// change. A top-level key is covered by the 1.0 compatibility promise from the
/// day it ships, so a setting that might not last starts here, as a field, and
/// can change or go away in any release.
///
/// Nothing belongs in it yet, so it has no fields. It exists now so that the
/// table parses, and has the meaning documented, before anything uses it. A key
/// in it this version does not read is expected, from another version, rather
/// than a mistake, so it is [`ConfigWarningKind::UnreadExperimentalKey`], and a
/// save keeps it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExperimentalConfig {}

/// Saved only once it holds something, so `--generate-config` writes no empty
/// table.
fn is_default_experimental(experimental: &ExperimentalConfig) -> bool {
    *experimental == ExperimentalConfig::default()
}

fn is_default_thresholds(t: &crate::diagnose::detectors::Thresholds) -> bool {
    *t == crate::diagnose::detectors::Thresholds::default()
}

fn default_record_episodes() -> bool {
    true
}

fn default_record_uptime() -> bool {
    true
}

fn default_third_party_probes() -> bool {
    true
}

fn default_groups_collapsed() -> bool {
    true
}

fn default_view() -> String {
    "full".into()
}

/// The braille area plot. `bars` remains selectable for terminals whose font
/// has no braille coverage.
fn default_graph_style() -> String {
    "dots".into()
}

/// On: the gradient is what makes a filled area read as depth.
fn default_graph_fade() -> bool {
    true
}

fn default_sandbox() -> String {
    "on".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertConfig {
    /// Bandwidth alert threshold in bytes/sec (0 = disabled)
    pub bandwidth_threshold: u64,

    /// Minimum distinct ports within window to flag a port scan
    pub port_scan_threshold: usize,

    /// Port-scan detection window in seconds
    pub port_scan_window_secs: u64,
}

// ── Defaults ───────────────────────────────────────────────

impl Default for NetwatchConfig {
    fn default() -> Self {
        Self {
            default_tab: "dashboard".into(),
            refresh_rate_ms: 1000,
            capture_interface: String::new(),
            show_geo: true,
            timeline_window: "5m".into(),
            packet_follow: true,
            bpf_filter: String::new(),
            geoip_db: String::new(),
            geoip_asn_db: String::new(),
            geoip_online: false,
            alerts: AlertConfig::default(),
            insights_enabled: false,
            insights_model: "llama3.2".into(),
            insights_endpoint: "local".into(),
            theme: "dark".into(),
            view: default_view(),
            graph_style: default_graph_style(),
            graph_fade: default_graph_fade(),
            diagnose_record_episodes: default_record_episodes(),
            record_uptime: default_record_uptime(),
            third_party_probes: default_third_party_probes(),
            diagnose_probes: Default::default(),
            diagnose_targets: Vec::new(),
            diagnose_thresholds: Default::default(),
            sandbox: default_sandbox(),
            tls_keylog_path: String::new(),
            egress_violation_cooldown_secs: default_egress_cooldown(),
            groups_start_collapsed: default_groups_collapsed(),
            confirm_quit: false,
            experimental: ExperimentalConfig::default(),
            load_warnings: Vec::new(),
            loaded: None,
        }
    }
}

fn default_egress_cooldown() -> u64 {
    300
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            bandwidth_threshold: 100_000_000, // 100 MB/s
            port_scan_threshold: 20,
            port_scan_window_secs: 30,
        }
    }
}

// ── Persistence ────────────────────────────────────────────

/// Why a config.toml that exists was not loaded. A missing file is not an
/// error: it means the defaults.
#[derive(Debug)]
pub enum ConfigError {
    /// The file is there but could not be read: no permission, a directory,
    /// a symlink to nothing, or bytes that are not UTF-8.
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Not valid TOML, or a value of the wrong type. `source` names the line,
    /// column and key and quotes the line. `position` is the 1-based line and
    /// column alone, for a report that must not echo the file. Boxed, as
    /// toml's error would make every `Result` holding this one large.
    Parse {
        path: PathBuf,
        position: Option<(usize, usize)>,
        source: Box<toml::de::Error>,
    },
}

impl ConfigError {
    pub fn path(&self) -> &Path {
        match self {
            ConfigError::Read { path, .. } | ConfigError::Parse { path, .. } => path,
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Read { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            // toml's message ends in a newline.
            ConfigError::Parse { path, source, .. } => write!(
                f,
                "invalid config {}: {}",
                path.display(),
                source.to_string().trim_end()
            ),
        }
    }
}

// The message already carries the cause, so `source()` stays `None`: anyhow
// would otherwise print it twice.
impl std::error::Error for ConfigError {}

/// Something about a file that loaded that its owner should be told: serde
/// ignores a key it does not know, so `sandbox_mode = "strict"` would otherwise
/// do nothing without a word.
///
/// Loading only records these. A session loads the file again after `main` has
/// and on every save, so each entry point reports them once, where its user
/// looks: stderr, which the TUI hides, then the log, Settings and doctor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    pub file: PathBuf,
    pub kind: ConfigWarningKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigWarningKind {
    /// A key netwatch does not read, so setting it changes nothing.
    UnknownKey(String),
    /// A key under `[experimental]` that this version does not read. Quieter
    /// than [`Self::UnknownKey`]: these come and go between releases by design.
    UnreadExperimentalKey(String),
    /// A key under a name it used to have. Its value is in force under `new`,
    /// unless the file sets `new` as well, which then wins.
    RenamedKey {
        old: &'static str,
        new: &'static str,
        since: &'static str,
        both_set: bool,
    },
}

impl ConfigWarningKind {
    /// Keys come from the file and can hold anything a quoted key can, so they
    /// are made safe for a terminal here. A value is never part of this.
    pub fn message(&self) -> String {
        match self {
            Self::UnknownKey(key) => {
                format!(
                    "unknown key {} is ignored",
                    crate::ui::sanitize::display(key)
                )
            }
            Self::UnreadExperimentalKey(key) => format!(
                "{} is not used by this version; experimental settings can change or go away in any release",
                crate::ui::sanitize::display(key)
            ),
            Self::RenamedKey {
                old,
                new,
                since,
                both_set: false,
            } => format!("{old} was renamed {new} in {since}; it still works until 2.0"),
            Self::RenamedKey {
                old,
                new,
                since,
                both_set: true,
            } => format!("{old} was renamed {new} in {since}; both are set, so {old} is ignored"),
        }
    }
}

impl ConfigWarning {
    /// The file by name alone, for the TUI's narrow rows.
    pub fn short(&self) -> String {
        let name = self.file.file_name().map(|name| name.to_string_lossy());
        format!(
            "{}: {}",
            crate::ui::sanitize::display(name.as_deref().unwrap_or("config")),
            self.kind.message()
        )
    }

    /// Whether this is worth interrupting someone for, or only worth having
    /// where they would look.
    pub fn is_quiet(&self) -> bool {
        matches!(self.kind, ConfigWarningKind::UnreadExperimentalKey(_))
    }

    /// For the log, once it exists.
    pub fn log(&self) {
        if self.is_quiet() {
            tracing::info!(target: "netwatch::config", "{self}");
        } else {
            tracing::warn!(target: "netwatch::config", "{self}");
        }
    }
}

impl std::fmt::Display for ConfigWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.file.display(), self.kind.message())
    }
}

/// `warnings` on stderr, for a command with no log, and for the moment before a
/// session takes the terminal: the lines are there when the TUI quits, and in
/// the journal under a service manager.
pub fn print_warnings(warnings: &[ConfigWarning]) {
    for warning in warnings {
        let level = if warning.is_quiet() {
            "note"
        } else {
            "warning"
        };
        eprintln!("{level}: {warning}");
    }
}

/// A key `T` did not read, one element per level: `["alerts", "typo"]`, or
/// `["diagnose_targets", "0", "typo"]` under an array of tables. A table `T`
/// has no field for at all is reported once, not key by key.
pub(crate) type KeyPath = Vec<String>;

fn key_path(path: &serde_ignored::Path<'_>, out: &mut KeyPath) {
    use serde_ignored::Path;
    match path {
        Path::Root => {}
        Path::Seq { parent, index } => {
            key_path(parent, out);
            out.push(index.to_string());
        }
        Path::Map { parent, key } => {
            key_path(parent, out);
            out.push(key.clone());
        }
        Path::Some { parent }
        | Path::NewtypeStruct { parent }
        | Path::NewtypeVariant { parent } => key_path(parent, out),
    }
}

/// [`toml::from_str`], and every key in `text` that `T` did not read.
pub(crate) fn from_toml_reporting_unread<T: serde::de::DeserializeOwned>(
    text: &str,
) -> Result<(T, Vec<KeyPath>), toml::de::Error> {
    let mut unread = Vec::new();
    let value = serde_ignored::deserialize(toml::de::Deserializer::parse(text)?, |path| {
        let mut key = KeyPath::new();
        key_path(&path, &mut key);
        unread.push(key);
    })?;
    Ok((value, unread))
}

const EXPERIMENTAL_TABLE: &str = "experimental";

/// A config file as read: its text, with any renamed keys moved, and the config
/// it holds.
struct ParsedConfig {
    text: String,
    config: NetwatchConfig,
}

/// A list of keys that changed: where each is, and its value now, or `None` for
/// an optional key that no longer has one.
type KeyChanges = Vec<(KeyPath, Option<toml::Value>)>;

/// One change to `diagnose_targets`. A target is known by its `name`, and by `nth`
/// among any that share it, because its place in the file can change while a
/// session runs: entries reordered by hand must not take each other's keys.
#[derive(Debug, Clone, PartialEq)]
enum TargetChange {
    Added {
        name: String,
        nth: usize,
        entry: toml::Table,
    },
    Removed {
        name: String,
        nth: usize,
    },
    Fields {
        name: String,
        nth: usize,
        fields: KeyChanges,
    },
}

/// What a session changed: the values it holds now against the ones it started
/// from. This, and not the session's whole config, is what a save writes, so a
/// hand edit made while it ran stays, and so does a value `validate` corrected
/// for the session but nobody asked to rewrite. If the file changed the same key,
/// the session's change wins for that key alone.
#[derive(Debug, Clone, Default, PartialEq)]
struct Changes {
    keys: KeyChanges,
    targets: Vec<TargetChange>,
}

impl Changes {
    fn between(now: &toml::Table, was: &toml::Table) -> Self {
        let (mut plain_now, mut plain_was) = (now.clone(), was.clone());
        plain_now.remove(TARGETS_KEY);
        plain_was.remove(TARGETS_KEY);
        let mut keys = KeyChanges::new();
        diff_tables(&plain_now, &plain_was, &mut KeyPath::new(), &mut keys);

        let (targets_now, targets_was) = (target_entries(now), target_entries(was));
        let mut targets = Vec::new();
        for (name, nth, entry) in &targets_now {
            let (name, nth) = (name.clone(), *nth);
            match targets_was.iter().find(|t| t.0 == name && t.1 == nth) {
                None => targets.push(TargetChange::Added {
                    name,
                    nth,
                    entry: (*entry).clone(),
                }),
                Some((_, _, old)) => {
                    let mut fields = KeyChanges::new();
                    diff_tables(entry, old, &mut KeyPath::new(), &mut fields);
                    if !fields.is_empty() {
                        targets.push(TargetChange::Fields { name, nth, fields });
                    }
                }
            }
        }
        for (name, nth, _) in &targets_was {
            if !targets_now.iter().any(|t| t.0 == *name && t.1 == *nth) {
                targets.push(TargetChange::Removed {
                    name: name.clone(),
                    nth: *nth,
                });
            }
        }
        Self { keys, targets }
    }

    fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.targets.is_empty()
    }

    /// Make these changes in `doc`, or in `appended` for what has to go after
    /// everything already in the file.
    fn write_into(
        &self,
        doc: &mut DocumentMut,
        appended: &mut DocumentMut,
        file: &Path,
    ) -> anyhow::Result<()> {
        for (path, value) in &self.keys {
            match value {
                Some(value) => {
                    let item = item_of(value)?;
                    write_key(doc.as_table_mut(), false, path, path, &item, appended);
                }
                None => remove_key(doc.as_table_mut(), path),
            }
        }
        for change in &self.targets {
            match change {
                TargetChange::Fields { name, nth, fields } => {
                    // Writing `enabled` alone would make an entry with no host.
                    let entry = target_in_file(doc, name, *nth).ok_or_else(|| {
                        anyhow::anyhow!(
                            "target {name} is no longer in {}; press r in Diagnose coverage to reload",
                            file.display()
                        )
                    })?;
                    write_target_fields(entry, fields)?;
                }
                TargetChange::Added { name, nth, entry } => {
                    if let Some(found) = target_in_file(doc, name, *nth) {
                        let fields: KeyChanges = entry
                            .iter()
                            .map(|(key, value)| (vec![key.clone()], Some(value.clone())))
                            .collect();
                        write_target_fields(found, &fields)?;
                    } else {
                        append_target(doc, appended, entry)?;
                    }
                }
                TargetChange::Removed { name, nth } => remove_target(doc, name, *nth),
            }
        }
        Ok(())
    }

    /// `values` as they should read once these changes are made. A second, plain
    /// statement of what [`Self::write_into`] does, for the check after a save.
    fn applied_to(&self, mut values: toml::Table) -> toml::Table {
        for (path, value) in &self.keys {
            set_plain(&mut values, path, value.as_ref());
        }
        if self.targets.is_empty() {
            return values;
        }
        let mut list = match values.remove(TARGETS_KEY) {
            Some(toml::Value::Array(list)) => list,
            _ => Vec::new(),
        };
        let find = |list: &[toml::Value], name: &str, nth: usize| {
            list.iter()
                .enumerate()
                .filter(|(_, entry)| entry.get("name").and_then(toml::Value::as_str) == Some(name))
                .map(|(index, _)| index)
                .nth(nth)
        };
        for change in &self.targets {
            match change {
                TargetChange::Fields { name, nth, fields } => {
                    if let Some(index) = find(&list, name, *nth) {
                        if let Some(entry) = list[index].as_table_mut() {
                            for (path, value) in fields {
                                set_plain(entry, path, value.as_ref());
                            }
                        }
                    }
                }
                TargetChange::Added { name, nth, entry } => match find(&list, name, *nth) {
                    Some(index) => list[index] = toml::Value::Table(entry.clone()),
                    None => list.push(toml::Value::Table(entry.clone())),
                },
                TargetChange::Removed { name, nth } => {
                    if let Some(index) = find(&list, name, *nth) {
                        list.remove(index);
                    }
                }
            }
        }
        if !list.is_empty() {
            values.insert(TARGETS_KEY.to_owned(), toml::Value::Array(list));
        }
        values
    }
}

const TARGETS_KEY: &str = "diagnose_targets";
const THRESHOLDS_KEY: &str = "diagnose_thresholds";

/// Keys netwatch no longer reads, which a save takes out of the file. A comment
/// on the line above one goes with it.
const REMOVED_KEYS: &[&str] = &["geoip_online"];

fn diff_tables(now: &toml::Table, was: &toml::Table, at: &mut KeyPath, out: &mut KeyChanges) {
    for (key, value) in now {
        at.push(key.clone());
        match (value, was.get(key)) {
            (toml::Value::Table(value), Some(toml::Value::Table(old))) => {
                diff_tables(value, old, at, out);
            }
            (toml::Value::Table(value), None) => {
                diff_tables(value, &toml::Table::new(), at, out);
            }
            (value, Some(old)) if values_match(value, old) => {}
            (value, _) => out.push((at.clone(), Some(value.clone()))),
        }
        at.pop();
    }
    for (key, old) in was {
        if !now.contains_key(key) {
            at.push(key.clone());
            match old {
                toml::Value::Table(old) => diff_tables(&toml::Table::new(), old, at, out),
                _ => out.push((at.clone(), None)),
            }
            at.pop();
        }
    }
}

/// `==`, except that a NaN is the same as itself. A hand-written `nan` must not
/// count as a change on every save.
fn values_match(a: &toml::Value, b: &toml::Value) -> bool {
    match (a, b) {
        (toml::Value::Float(a), toml::Value::Float(b)) => a == b || (a.is_nan() && b.is_nan()),
        (toml::Value::Table(a), toml::Value::Table(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, a)| b.get(key).is_some_and(|b| values_match(a, b)))
        }
        (toml::Value::Array(a), toml::Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| values_match(a, b))
        }
        _ => a == b,
    }
}

/// Each target with its name and its place among any sharing the name.
fn target_entries(values: &toml::Table) -> Vec<(String, usize, &toml::Table)> {
    let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    values
        .get(TARGETS_KEY)
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_table)
        .map(|entry| {
            let name = entry
                .get("name")
                .and_then(toml::Value::as_str)
                .unwrap_or("");
            let nth = seen.entry(name).or_insert(0);
            let at = *nth;
            *nth += 1;
            (name.to_owned(), at, entry)
        })
        .collect()
}

fn set_plain(table: &mut toml::Table, path: &[String], value: Option<&toml::Value>) {
    match path {
        [] => {}
        [leaf] => match value {
            Some(value) => {
                table.insert(leaf.clone(), value.clone());
            }
            None => {
                table.remove(leaf);
            }
        },
        [head, rest @ ..] => {
            let child = table
                .entry(head.clone())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            if let Some(child) = child.as_table_mut() {
                set_plain(child, rest, value);
            }
        }
    }
}

/// `value` as the item a file would hold, laid out as a generated file lays it out.
fn item_of(value: &toml::Value) -> anyhow::Result<Item> {
    const KEY: &str = "key";
    let mut one = toml::Table::new();
    one.insert(KEY.to_owned(), value.clone());
    let doc: DocumentMut = toml::to_string_pretty(&one)?.parse()?;
    doc.as_table()
        .get(KEY)
        .map(without_positions)
        .ok_or_else(|| anyhow::anyhow!("no value for a changed key"))
}

/// Put `item` at `path` under `table`, the rest of `full`. A value already there
/// keeps its line's comment, and stays exactly as written if it means the same. A
/// new table goes in `appended`, after everything the file has, so that comments
/// at the end of the file stay after what they followed. `inline` says `table` is
/// an inline table, which nothing can be appended to.
fn write_key(
    table: &mut dyn TableLike,
    inline: bool,
    path: &[String],
    full: &[String],
    item: &Item,
    appended: &mut DocumentMut,
) {
    let [head, rest @ ..] = path else {
        return;
    };
    if rest.is_empty() {
        if let (Some(Item::Value(current)), Item::Value(new)) = (table.get_mut(head), item) {
            if !same_value(current, new) {
                let decor = current.decor().clone();
                *current = new.clone();
                *current.decor_mut() = decor;
            }
            return;
        }
        table.remove(head);
        if inline || item.is_value() {
            table.insert(head, without_positions(item));
        } else {
            append_at(appended.as_table_mut(), full, item);
        }
        return;
    }
    match table.get_mut(head) {
        Some(child) if child.is_table_like() => {
            let child_inline = child.is_value();
            if let Some(child) = child.as_table_like_mut() {
                write_key(child, child_inline, rest, full, item, appended);
            }
        }
        _ if inline => {
            table.insert(head, Item::Value(Value::InlineTable(InlineTable::new())));
            if let Some(child) = table.get_mut(head).and_then(Item::as_table_like_mut) {
                write_key(child, true, rest, full, item, appended);
            }
        }
        _ => append_at(appended.as_table_mut(), full, item),
    }
}

fn remove_key(table: &mut dyn TableLike, path: &[String]) {
    match path {
        [] => {}
        [leaf] => {
            table.remove(leaf);
        }
        [head, rest @ ..] => {
            if let Some(child) = table.get_mut(head).and_then(Item::as_table_like_mut) {
                remove_key(child, rest);
            }
        }
    }
}

/// Add `item` at `path` to what goes after the file. The tables on the way write
/// no header of their own unless they get a value, as the file may have one.
fn append_at(table: &mut Table, path: &[String], item: &Item) {
    match path {
        [] => {}
        [leaf] => {
            table.insert(leaf, without_positions(item));
        }
        [head, rest @ ..] => {
            let child = table.entry(head).or_insert_with(|| {
                let mut child = Table::new();
                child.set_implicit(true);
                Item::Table(child)
            });
            if let Some(child) = child.as_table_mut() {
                append_at(child, rest, item);
            }
        }
    }
}

/// The entry in the file for this target, by name.
fn target_in_file<'a>(
    doc: &'a mut DocumentMut,
    name: &str,
    nth: usize,
) -> Option<&'a mut dyn TableLike> {
    tables_in(doc.get_mut(TARGETS_KEY)?)?
        .into_iter()
        .filter(|entry| entry.get("name").and_then(Item::as_str) == Some(name))
        .nth(nth)
}

/// A target's own keys are all plain values, so nothing goes in `appended`.
fn write_target_fields(entry: &mut dyn TableLike, fields: &KeyChanges) -> anyhow::Result<()> {
    let mut unused = DocumentMut::new();
    for (path, value) in fields {
        match value {
            Some(value) => {
                let item = item_of(value)?;
                write_key(&mut *entry, false, path, path, &item, &mut unused);
            }
            None => remove_key(&mut *entry, path),
        }
    }
    Ok(())
}

/// A target the file does not have. After the file's other entries, or in place
/// of an empty `diagnose_targets = []`, or in an array of inline tables if that is
/// how the file writes them.
fn append_target(
    doc: &mut DocumentMut,
    appended: &mut DocumentMut,
    entry: &toml::Table,
) -> anyhow::Result<()> {
    let list = item_of(&toml::Value::Array(vec![toml::Value::Table(entry.clone())]))?;
    let Some(table) = list.as_array_of_tables().and_then(|list| list.get(0)) else {
        anyhow::bail!("a target did not serialize as a table");
    };
    if let Some(Item::Value(Value::Array(values))) = doc.get_mut(TARGETS_KEY) {
        if !values.is_empty() {
            values.push_formatted(Value::InlineTable(table.clone().into_inline_table()));
            return Ok(());
        }
        doc.remove(TARGETS_KEY);
    }
    let slot = appended
        .as_table_mut()
        .entry(TARGETS_KEY)
        .or_insert(Item::ArrayOfTables(toml_edit::ArrayOfTables::new()));
    if let Some(entries) = slot.as_array_of_tables_mut() {
        entries.push(table.clone());
    }
    Ok(())
}

fn remove_target(doc: &mut DocumentMut, name: &str, nth: usize) {
    let named = |entry: &dyn TableLike| entry.get("name").and_then(Item::as_str) == Some(name);
    match doc.get_mut(TARGETS_KEY) {
        Some(Item::ArrayOfTables(entries)) => {
            let index = entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| named(*entry))
                .map(|(index, _)| index)
                .nth(nth);
            if let Some(index) = index {
                entries.remove(index);
            }
        }
        Some(Item::Value(Value::Array(values))) => {
            let index = values
                .iter()
                .enumerate()
                .filter(|(_, value)| {
                    value.as_inline_table().is_some_and(|entry| {
                        entry.get("name").and_then(Value::as_str) == Some(name)
                    })
                })
                .map(|(index, _)| index)
                .nth(nth);
            if let Some(index) = index {
                values.remove(index);
            }
        }
        _ => {}
    }
}

/// The defaults `file` has no key for, at any depth, in the order a generated file
/// has them. A list the file has at all counts as set.
fn missing_defaults(
    file: &dyn TableLike,
    defaults: &Table,
    at: &mut KeyPath,
    out: &mut Vec<(KeyPath, Item)>,
) {
    for (key, item) in defaults.iter() {
        at.push(key.to_owned());
        match (file.get(key), item) {
            (None, _) => out.push((at.clone(), item.clone())),
            (Some(current), Item::Table(defaults)) => {
                if let Some(table) = current.as_table_like() {
                    missing_defaults(table, defaults, at, out);
                }
            }
            _ => {}
        }
        at.pop();
    }
}

/// The file as `parsed` holds it, or nothing yet, with renamed keys under their new
/// names, removed keys gone, `changes` made, and with `add_defaults` every missing
/// key added. `None` if that leaves the file as it is, so that it is not written.
fn edited_file(
    parsed: Option<&ParsedConfig>,
    changes: &Changes,
    add_defaults: bool,
    file: &Path,
) -> anyhow::Result<Option<String>> {
    let text = parsed.map_or("", |parsed| parsed.text.as_str());
    let mut doc: DocumentMut = text.parse()?;
    let mut appended = DocumentMut::new();
    let mut tidied = parsed.is_some_and(|parsed| {
        parsed
            .config
            .load_warnings
            .iter()
            .any(|warning| matches!(warning.kind, ConfigWarningKind::RenamedKey { .. }))
    });
    for key in REMOVED_KEYS {
        tidied |= doc.remove(key).is_some();
    }
    changes.write_into(&mut doc, &mut appended, file)?;
    let mut missing = Vec::new();
    if add_defaults {
        let defaults: DocumentMut = toml::to_string_pretty(&NetwatchConfig::default())?.parse()?;
        missing_defaults(
            doc.as_table(),
            defaults.as_table(),
            &mut KeyPath::new(),
            &mut missing,
        );
        for (path, item) in &missing {
            write_key(doc.as_table_mut(), false, path, path, item, &mut appended);
        }
    }
    if changes.is_empty() && missing.is_empty() && !tidied {
        return Ok(None);
    }
    let mut edited = doc.to_string();
    let tail = appended.to_string();
    let tail = tail.trim_start_matches(['\r', '\n']);
    if !tail.is_empty() {
        if !edited.is_empty() {
            if !edited.ends_with('\n') {
                edited.push('\n');
            }
            edited.push('\n');
        }
        edited.push_str(tail);
    }
    check_reads_back(text, &edited, changes)?;
    Ok(Some(edited))
}

/// Refuse an edit that does not mean what it should: the file as it was, plus
/// `changes`, and nothing else. The file it would replace does load, so a bug in
/// the editing must not cost anyone that file.
fn check_reads_back(before: &str, after: &str, changes: &Changes) -> anyhow::Result<()> {
    let before: NetwatchConfig = toml::from_str(before)?;
    let after: NetwatchConfig = toml::from_str(after)?;
    let wanted = changes.applied_to(before.values()?);
    anyhow::ensure!(
        values_match(
            &toml::Value::Table(after.values()?),
            &toml::Value::Table(wanted)
        ),
        "cannot update it in place; not overwriting it"
    );
    Ok(())
}

/// The tables of an array of tables, or of an array of inline tables.
fn tables_in(item: &mut Item) -> Option<Vec<&mut dyn TableLike>> {
    match item {
        Item::ArrayOfTables(tables) => {
            Some(tables.iter_mut().map(|t| t as &mut dyn TableLike).collect())
        }
        Item::Value(Value::Array(values)) => values
            .iter_mut()
            .map(|v| v.as_inline_table_mut().map(|t| t as &mut dyn TableLike))
            .collect(),
        _ => None,
    }
}

/// Whether two values mean the same, however each is written: `'a'` and `"a"`,
/// `1_000` and `1000`, and `30` and `30.0`, as a float key reads either.
pub(crate) fn same_value(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(a), Value::String(b)) => a.value() == b.value(),
        (Value::Integer(a), Value::Integer(b)) => a.value() == b.value(),
        (Value::Float(a), Value::Float(b)) => {
            a.value() == b.value() || (a.value().is_nan() && b.value().is_nan())
        }
        (Value::Integer(a), Value::Float(b)) | (Value::Float(b), Value::Integer(a)) => {
            *a.value() as f64 == *b.value()
        }
        (Value::Boolean(a), Value::Boolean(b)) => a.value() == b.value(),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(a, b)| same_value(a, b))
        }
        _ => false,
    }
}

/// A copy of `item` from another document, whose positions mean nothing in this
/// one. Without them a table is written after the one before it.
fn without_positions(item: &Item) -> Item {
    fn clear(table: &mut Table) {
        table.set_position(None);
        for (_, item) in table.iter_mut() {
            clear_item(&mut *item);
        }
    }
    fn clear_item(item: &mut Item) {
        match item {
            Item::Table(table) => clear(table),
            Item::ArrayOfTables(tables) => tables.iter_mut().for_each(clear),
            Item::None | Item::Value(_) => {}
        }
    }
    let mut item = item.clone();
    clear_item(&mut item);
    item
}

/// The 1-based line and column of byte `at`, counting characters as toml does.
fn line_column(text: &str, at: usize) -> (usize, usize) {
    let before = text.get(..at).unwrap_or(text);
    let line = before.matches('\n').count() + 1;
    let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
    (line, column)
}

impl NetwatchConfig {
    /// Path to `netwatch/config.toml` under the platform config dir
    /// (`~/.config` on Linux, `~/Library/Application Support` on macOS,
    /// `%APPDATA%` on Windows).
    pub fn path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("netwatch").join("config.toml"))
    }

    /// Load from disk. No file means the defaults, and a key the file leaves
    /// out keeps its default. A file that is there but cannot be read or
    /// parsed is an error rather than the defaults: falling back would drop
    /// every setting in it, `sandbox = "strict"` and `record_uptime = false`
    /// included, over one bad value.
    pub fn load() -> Result<Self, ConfigError> {
        match Self::path() {
            Some(path) => Self::load_from(&path),
            None => Ok(Self::default()),
        }
    }

    /// [`load`](Self::load) from `path` rather than the platform location.
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        match Self::read_file(path)? {
            Some(parsed) => Ok(parsed.config),
            None => Ok(Self::default()),
        }
    }

    /// What is at `path`, or `None` if there is nothing.
    fn read_file(path: &Path) -> Result<Option<ParsedConfig>, ConfigError> {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            // Nothing at the path at all. A symlink to a missing file is
            // something, and an error.
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound
                    && fs::symlink_metadata(path).is_err() =>
            {
                return Ok(None);
            }
            Err(source) => {
                return Err(ConfigError::Read {
                    path: path.into(),
                    source,
                })
            }
        };
        // With a renamed key in the file the position is in the text as moved,
        // which can be a line out. The message still names the key.
        let mut parsed =
            Self::parse(&contents, path, RENAMED_KEYS).map_err(|source| ConfigError::Parse {
                path: path.into(),
                position: source.span().map(|span| line_column(&contents, span.start)),
                source: Box::new(source),
            })?;
        // After `validate`, so that a value it corrected is not a change this
        // session made. The file keeps what it says until someone edits that key.
        parsed.config.validate();
        parsed.config.loaded = parsed.config.values().ok();
        Ok(Some(parsed))
    }

    /// `text`, the contents of `file`, with [`load_warnings`](Self::load_warnings)
    /// filled in. Not validated: that is for what a session will run on.
    pub fn from_toml(text: &str, file: &Path) -> Result<Self, toml::de::Error> {
        Self::parse(text, file, RENAMED_KEYS).map(|mut parsed| {
            parsed.config.loaded = parsed.config.values().ok();
            parsed.config
        })
    }

    /// Every value as TOML, with the thresholds there even at their defaults, so
    /// that changing one is a change to that one key.
    fn values(&self) -> Result<toml::Table, toml::ser::Error> {
        let mut values = toml::Table::try_from(self)?;
        if !values.contains_key(THRESHOLDS_KEY) {
            values.insert(
                THRESHOLDS_KEY.to_owned(),
                toml::Value::try_from(self.diagnose_thresholds)?,
            );
        }
        Ok(values)
    }

    /// What a save compares against.
    fn baseline(&self) -> Result<toml::Table, toml::ser::Error> {
        match &self.loaded {
            Some(values) => Ok(values.clone()),
            None => Self::default().values(),
        }
    }

    /// `--view` is a decision about this run, not a change to the saved default,
    /// so a save leaves the file's `view` alone unless someone also changes it in
    /// Settings. The Settings row still shows what is on screen.
    pub fn set_view_for_this_run(&mut self, view: &str) {
        self.view = view.to_owned();
        if let Ok(mut baseline) = self.baseline() {
            baseline.insert("view".to_owned(), toml::Value::String(view.to_owned()));
            self.loaded = Some(baseline);
        }
    }

    /// Take the Diagnose settings from `fresh`, the file read again, for the
    /// Diagnose tab's `r`. What they now hold is what the file says, so a later
    /// save has nothing to write for them. Other unsaved changes stay unsaved.
    pub fn reload_diagnose_settings(&mut self, fresh: Self) {
        let (Ok(mut baseline), Ok(values)) = (self.baseline(), fresh.values()) else {
            return;
        };
        for key in [TARGETS_KEY, "diagnose_probes"] {
            match values.get(key) {
                Some(value) => baseline.insert(key.to_owned(), value.clone()),
                None => baseline.remove(key),
            };
        }
        self.loaded = Some(baseline);
        self.diagnose_targets = fresh.diagnose_targets;
        self.diagnose_probes = fresh.diagnose_probes;
        self.load_warnings = fresh.load_warnings;
    }

    fn parse(
        text: &str,
        file: &Path,
        renames: &[RenamedKey],
    ) -> Result<ParsedConfig, toml::de::Error> {
        let (text, moved) = apply_renames(text, renames);
        let (mut config, unread): (Self, Vec<KeyPath>) = from_toml_reporting_unread(&text)?;
        config.load_warnings = moved
            .into_iter()
            .chain(unread.iter().map(|key| {
                let key_name = key.join(".");
                if key.first().map(String::as_str) == Some(EXPERIMENTAL_TABLE) {
                    ConfigWarningKind::UnreadExperimentalKey(key_name)
                } else {
                    ConfigWarningKind::UnknownKey(key_name)
                }
            }))
            .map(|kind| ConfigWarning {
                file: file.into(),
                kind,
            })
            .collect();
        Ok(ParsedConfig {
            text: text.into_owned(),
            config,
        })
    }

    /// Clamp and normalise fields that may arrive out of range from a hand-edited
    /// config file. Called automatically by `load()`; also useful in tests.
    pub fn validate(&mut self) {
        self.refresh_rate_ms = self.refresh_rate_ms.clamp(100, 5000);
        if self.theme.is_empty() {
            self.theme = "dark".into();
        }
        if self.graph_style.is_empty() {
            self.graph_style = default_graph_style();
        }
        // An unknown view name falls back to `full` rather than refusing to
        // start: a typo in a config file must not cost you the tool.
        if !crate::app::VIEW_MODE_NAMES.contains(&self.view.as_str()) {
            self.view = default_view();
        }
        if self.default_tab.is_empty() {
            self.default_tab = "dashboard".into();
        }
        if self.timeline_window.is_empty() {
            self.timeline_window = "5m".into();
        }
        if self.insights_model.is_empty() {
            self.insights_model = "llama3.2".into();
        }
        if self.insights_endpoint.is_empty() {
            self.insights_endpoint = "local".into();
        }
    }

    /// Write what this session changed to the platform location, creating parent
    /// directories as needed. See [`save_to`](Self::save_to).
    pub fn save(&mut self) -> anyhow::Result<()> {
        let path =
            Self::path().ok_or_else(|| anyhow::anyhow!("cannot determine config directory"))?;
        self.save_to(&path)?;
        // A save writes a renamed key under its new name, which ends its warning.
        if let Ok(saved) = Self::load_from(&path) {
            self.load_warnings = saved.load_warnings;
        }
        Ok(())
    }

    /// [`save`](Self::save) to `path`. A file already there that does not load
    /// is left alone: it holds settings nothing has read, such as a hand edit
    /// made while netwatch ran.
    ///
    /// One that does load has only the keys this session changed written to it,
    /// by name for a target. Everything else stays as the file has it: another
    /// key edited by hand since this session started, a value `validate` corrected
    /// for the session, a key this version does not read, a table at its defaults,
    /// comments, and any default the file does not set, which a later release can
    /// still change. If the file changed a key the session also changed, the
    /// session's value wins for that key. A renamed key moves to its new name, and
    /// a removed one goes. With nothing to write the file is not touched.
    pub fn save_to(&mut self, path: &Path) -> anyhow::Result<()> {
        let now = self.values()?;
        let changes = Changes::between(&now, &self.baseline()?);
        let existing = Self::read_existing(path)?;
        if let Some(contents) = edited_file(existing.as_ref(), &changes, false, path)? {
            write_config(path, &contents)?;
        }
        self.loaded = Some(now);
        Ok(())
    }

    /// `--generate-config` at the platform location. See
    /// [`generate_at`](Self::generate_at).
    pub fn generate() -> anyhow::Result<()> {
        let path =
            Self::path().ok_or_else(|| anyhow::anyhow!("cannot determine config directory"))?;
        Self::generate_at(&path)
    }

    /// Write every key at its default: a whole new file, or to a file that loads,
    /// the keys it does not have, keeping everything it does. The one thing that
    /// writes defaults, because someone asked for them. A file that does not load
    /// is left alone, as in [`save_to`](Self::save_to).
    pub fn generate_at(path: &Path) -> anyhow::Result<()> {
        match Self::read_existing(path)? {
            None => write_config(path, &toml::to_string_pretty(&Self::default())?),
            Some(parsed) => match edited_file(Some(&parsed), &Changes::default(), true, path)? {
                Some(contents) => write_config(path, &contents),
                None => Ok(()),
            },
        }
    }

    fn read_existing(path: &Path) -> anyhow::Result<Option<ParsedConfig>> {
        Self::read_file(path).map_err(|e| {
            let context = format!("{} does not load; not overwriting it", path.display());
            anyhow::Error::new(e).context(context)
        })
    }
}

fn write_config(path: &Path, contents: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)?;
    Ok(())
}

// ── Keys with a new name ───────────────────────────────────

/// A key that has been renamed: the old spelling keeps working, with a warning,
/// until 2.0.
pub(crate) struct RenamedKey {
    /// Dotted, as the warnings print it. `*` is every entry of an array of
    /// tables or of a table of named entries, and needs a `*` in `new` at the
    /// same place. A table that went too can be renamed itself.
    pub(crate) old: &'static str,
    pub(crate) new: &'static str,
    /// The release that renamed it.
    pub(crate) since: &'static str,
}

/// Every config.toml key that has been renamed. A rename after 1.0 is the field's
/// new name and one line here:
///
/// ```text
/// RenamedKey { old: "alerts.bandwidth_limit", new: "alerts.bandwidth_threshold", since: "1.2" },
/// ```
///
/// Empty so far. `geoip_online` was removed, not renamed, as
/// [`warn_removed_keys`](NetwatchConfig::warn_removed_keys) says, and 0.34's
/// `auto_close_secs` to `expire_after_secs` is a field of recorded episodes,
/// with its own alias on `diagnose::engine::Settings`, and was never a key here.
const RENAMED_KEYS: &[RenamedKey] = &[];

/// `text` with every key in `renames` under its new name, keeping its comment and
/// value, and what to tell the owner of the file. Moved before the file is read,
/// not after, so a rename can be of a key that must be there. `text` itself when
/// none of them is set, which is every file until a key is renamed, or when it is
/// not TOML, which is for the parser to say.
pub(crate) fn apply_renames<'a>(
    text: &'a str,
    renames: &[RenamedKey],
) -> (std::borrow::Cow<'a, str>, Vec<ConfigWarningKind>) {
    use std::borrow::Cow;
    let mut moved = Vec::new();
    if renames.is_empty() {
        return (Cow::Borrowed(text), moved);
    }
    let Ok(mut doc) = text.parse::<DocumentMut>() else {
        return (Cow::Borrowed(text), moved);
    };
    for rename in renames {
        let (old, new): (Vec<_>, Vec<_>) = (
            rename.old.split('.').collect(),
            rename.new.split('.').collect(),
        );
        let (mut found, mut both_set) = (false, false);
        rename_in(doc.as_table_mut(), &old, &new, &mut |placed| {
            found = true;
            both_set |= !placed;
        });
        if found {
            moved.push(ConfigWarningKind::RenamedKey {
                old: rename.old,
                new: rename.new,
                since: rename.since,
                both_set,
            });
        }
    }
    if moved.is_empty() {
        return (Cow::Borrowed(text), moved);
    }
    (Cow::Owned(doc.to_string()), moved)
}

/// Down the path `old` and `new` share, then across. `moved` hears each key found,
/// and whether it could go to its new name, which it cannot if that is set too.
fn rename_in(table: &mut dyn TableLike, old: &[&str], new: &[&str], moved: &mut dyn FnMut(bool)) {
    match (old, new) {
        ([head, old_rest @ ..], [new_head, new_rest @ ..])
            if head == new_head && !old_rest.is_empty() && !new_rest.is_empty() =>
        {
            if *head == "*" {
                for (_, item) in table.iter_mut() {
                    if let Some(entry) = item.as_table_like_mut() {
                        rename_in(entry, old_rest, new_rest, moved);
                    }
                }
                return;
            }
            let Some(item) = table.get_mut(head) else {
                return;
            };
            if let Some(child) = item.as_table_like_mut() {
                rename_in(child, old_rest, new_rest, moved);
            } else if let (["*", old_rest @ ..], ["*", new_rest @ ..]) = (old_rest, new_rest) {
                for entry in tables_in(item).into_iter().flatten() {
                    rename_in(entry, old_rest, new_rest, moved);
                }
            }
        }
        _ => {
            if let Some((key, item)) = take_key(table, old) {
                moved(put_key(table, new, &key, item));
            }
        }
    }
}

/// Remove the key at `path`, and a table that leaves empty, which would otherwise
/// be reported as unknown once its name has gone.
fn take_key(table: &mut dyn TableLike, path: &[&str]) -> Option<(toml_edit::Key, Item)> {
    match path {
        [] => None,
        [leaf] => {
            let key = table.key(leaf)?.clone();
            Some((key, table.remove(leaf)?))
        }
        [head, rest @ ..] => {
            let child = table.get_mut(head)?.as_table_like_mut()?;
            let taken = take_key(child, rest)?;
            if child.is_empty() {
                table.remove(head);
            }
            Some(taken)
        }
    }
}

/// Put `item` at `path` with the comment `old` carried, making any table on the
/// way. False if something is already there.
fn put_key(table: &mut dyn TableLike, path: &[&str], old: &toml_edit::Key, item: Item) -> bool {
    match path {
        [] => false,
        [leaf] => {
            if table.contains_key(leaf) {
                return false;
            }
            let key = toml_edit::Key::new(*leaf)
                .with_leaf_decor(old.leaf_decor().clone())
                .with_dotted_decor(old.dotted_decor().clone());
            table.entry_format(&key).or_insert(item);
            true
        }
        [head, rest @ ..] => {
            let child = table.entry(head).or_insert(Item::Table(Table::new()));
            child
                .as_table_like_mut()
                .is_some_and(|child| put_key(child, rest, old, item))
        }
    }
}

// ── GeoIP database locations ───────────────────────────────

impl NetwatchConfig {
    /// Log a warning for each key a config still sets that no longer does
    /// anything. For the session's start, once the log exists: `main` loads
    /// the config before it installs the logger, and a session loads it again
    /// after that and on every save, so this cannot live in [`Self::load_from`].
    /// [`load_warnings`](Self::load_warnings) go to the log the same way.
    pub fn warn_removed_keys(&self) {
        if self.geoip_online {
            tracing::warn!(
                target: "netwatch::config",
                "geoip_online was removed in 0.39: it sent peer addresses to a third party in cleartext. Run `netwatch geoip update` for offline lookups."
            );
        }
    }

    /// The City or Country database and the ASN database a session opens, each
    /// empty when there is none. A path in the config wins; an empty one means
    /// what `netwatch geoip update` downloaded, City ahead of Country.
    pub fn geoip_paths(&self) -> (String, String) {
        // What a test finds must not depend on who runs it, or on whether they
        // have run the command.
        #[cfg(test)]
        let downloaded: Option<PathBuf> = None;
        #[cfg(not(test))]
        let downloaded = crate::geoip_update::downloaded_dir();
        self.geoip_paths_in(downloaded.as_deref())
    }

    pub(crate) fn geoip_paths_in(&self, downloaded: Option<&Path>) -> (String, String) {
        use crate::geoip_update::Database;
        // A session takes paths as text. One that is not UTF-8 cannot be passed
        // on, and a lossy copy names a different file, so it is not found.
        // `netwatch geoip update` refuses to write there and says why.
        let found = |db: Database| {
            downloaded
                .map(|dir| dir.join(db.file_name()))
                .filter(|path| path.is_file())
                .and_then(|path| path.to_str().map(str::to_owned))
        };
        let or_downloaded = |set: &str, downloaded: Option<String>| {
            if set.trim().is_empty() {
                downloaded.unwrap_or_default()
            } else {
                set.to_owned()
            }
        };
        (
            or_downloaded(
                &self.geoip_db,
                found(Database::City).or_else(|| found(Database::Country)),
            ),
            or_downloaded(&self.geoip_asn_db, found(Database::Asn)),
        )
    }
}

// ── Helpers to map string ↔ app types ──────────────────────

use crate::app::{Tab, TimelineWindow};

impl NetwatchConfig {
    pub fn tab(&self) -> Tab {
        match self.default_tab.to_lowercase().as_str() {
            "connections" => Tab::Connections,
            "interfaces" => Tab::Interfaces,
            "packets" => Tab::Packets,
            "stats" => Tab::Stats,
            "topology" => Tab::Topology,
            "timeline" => Tab::Timeline,
            "processes" => Tab::Processes,
            // Kept as an alias: the Insights tab folded into Diagnose,
            // and a config naming it should land somewhere sensible.
            "diagnose" | "insights" => Tab::Diagnose,
            "egress" => Tab::Egress,
            _ => Tab::Dashboard,
        }
    }

    pub fn timeline_window_enum(&self) -> TimelineWindow {
        match self.timeline_window.as_str() {
            "1m" => TimelineWindow::Min1,
            "15m" => TimelineWindow::Min15,
            "30m" => TimelineWindow::Min30,
            "1h" => TimelineWindow::Hour1,
            _ => TimelineWindow::Min5,
        }
    }
}

// ── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let cfg = NetwatchConfig::default();
        assert_eq!(cfg.default_tab, "dashboard");
        assert_eq!(cfg.refresh_rate_ms, 1000);
        assert!(cfg.show_geo);
        assert!(cfg.packet_follow);
        assert!(!cfg.confirm_quit);
        assert!(cfg.record_uptime);
        assert_eq!(cfg.timeline_window, "5m");
        assert_eq!(cfg.alerts.bandwidth_threshold, 100_000_000);
    }

    #[test]
    fn partial_toml_fills_defaults() {
        let toml_str = r#"
default_tab = "packets"
show_geo = false
"#;
        let cfg: NetwatchConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.default_tab, "packets");
        assert!(!cfg.show_geo);
        // un-specified fields get defaults
        assert_eq!(cfg.refresh_rate_ms, 1000);
        assert!(cfg.packet_follow);
        assert!(!cfg.confirm_quit);
        assert_eq!(cfg.alerts.port_scan_threshold, 20);
    }

    /// A config from before 0.39 still loads and is told about the key, once,
    /// and the key does not survive a save.
    #[test]
    fn geoip_online_true_parses_and_is_ignored() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tracing_subscriber::layer::{Context, SubscriberExt};

        struct Count(Arc<AtomicUsize>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Count {
            fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
                assert_eq!(*event.metadata().level(), tracing::Level::WARN);
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let dir = std::env::temp_dir().join(format!("nw-geoip-online-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        fs::write(&path, "geoip_online = true\ntheme = \"nord\"\n").unwrap();

        let events = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry().with(Count(Arc::clone(&events)));
        tracing::subscriber::with_default(subscriber, || {
            // Loading and saving say nothing. A session does both repeatedly.
            let mut cfg = NetwatchConfig::load_from(&path).unwrap();
            assert!(cfg.geoip_online);
            assert_eq!(cfg.theme, "nord");
            cfg.save_to(&path).unwrap();
            assert_eq!(events.load(Ordering::Relaxed), 0);

            cfg.warn_removed_keys();
            assert_eq!(events.load(Ordering::Relaxed), 1);

            // The save dropped it, so the next start has nothing to say.
            let saved = fs::read_to_string(&path).unwrap();
            assert!(!saved.contains("geoip_online"), "{saved}");
            let cfg = NetwatchConfig::load_from(&path).unwrap();
            assert!(!cfg.geoip_online);
            assert_eq!(cfg.theme, "nord");
            cfg.warn_removed_keys();
            assert_eq!(events.load(Ordering::Relaxed), 1);
        });
        let _ = fs::remove_dir_all(&dir);
    }

    fn unknown_keys(cfg: &NetwatchConfig) -> Vec<String> {
        cfg.load_warnings
            .iter()
            .filter_map(|warning| match &warning.kind {
                ConfigWarningKind::UnknownKey(key) => Some(key.clone()),
                _ => None,
            })
            .collect()
    }

    /// Renames as they will be written, on keys that exist today. The table
    /// the code reads is empty, so each case passes its own.
    fn parse_renamed(text: &str, renames: &[RenamedKey]) -> ParsedConfig {
        NetwatchConfig::parse(text, Path::new("/etc/config.toml"), renames).unwrap()
    }

    const RENAMES: &[RenamedKey] = &[
        RenamedKey {
            old: "colour_theme",
            new: "theme",
            since: "1.1",
        },
        RenamedKey {
            old: "alerts.bandwidth_limit",
            new: "alerts.bandwidth_threshold",
            since: "1.2",
        },
        RenamedKey {
            old: "scan_threshold",
            new: "alerts.port_scan_threshold",
            since: "1.3",
        },
        // A key that must be there, so it has to move before the file is read.
        RenamedKey {
            old: "diagnose_targets.*.hostname",
            new: "diagnose_targets.*.host",
            since: "1.4",
        },
        RenamedKey {
            old: "old_probes.trace_to",
            new: "diagnose_probes.trace_target",
            since: "1.5",
        },
    ];

    /// The mechanism on every shape of rename, with the comment on the old line
    /// carried over and a warning that says what to do.
    #[test]
    fn a_renamed_key_keeps_working_and_warns() {
        let parsed = parse_renamed(
            r#"
# my colours
colour_theme = "nord"
scan_threshold = 7
[alerts]
bandwidth_limit = 5
[old_probes]
trace_to = "9.9.9.9"
[[diagnose_targets]]
name = "a"
hostname = "a.example"
[[diagnose_targets]]
name = "b"
hostname = "b.example"
"#,
            RENAMES,
        );
        let cfg = &parsed.config;
        assert_eq!(cfg.theme, "nord");
        assert_eq!(cfg.alerts.bandwidth_threshold, 5);
        assert_eq!(cfg.alerts.port_scan_threshold, 7);
        assert_eq!(cfg.diagnose_probes.trace_target, "9.9.9.9");
        assert_eq!(cfg.diagnose_targets[0].host, "a.example");
        assert_eq!(cfg.diagnose_targets[1].host, "b.example");
        // Nothing moved is called unknown, nor is the table it left behind.
        assert_eq!(unknown_keys(cfg), Vec::<String>::new());
        assert_eq!(cfg.load_warnings.len(), RENAMES.len());
        assert_eq!(
            cfg.load_warnings[0].to_string(),
            "/etc/config.toml: colour_theme was renamed theme in 1.1; it still works until 2.0"
        );
        assert!(
            parsed.text.contains("# my colours\ntheme = \"nord\""),
            "{}",
            parsed.text
        );
    }

    /// With both, the new name wins and the old one is what the warning calls
    /// ignored. In a file with neither nothing is rewritten at all.
    #[test]
    fn a_new_name_beats_the_old_and_a_file_with_neither_is_untouched() {
        let cfg = parse_renamed("colour_theme = 'nord'\ntheme = 'ocean'\n", RENAMES).config;
        assert_eq!(cfg.theme, "ocean");
        assert_eq!(
            cfg.load_warnings[0].short(),
            "config.toml: colour_theme was renamed theme in 1.1; both are set, so colour_theme is ignored"
        );

        let text = "# as written\ntheme   =   'ocean'\n";
        let parsed = parse_renamed(text, RENAMES);
        assert_eq!(parsed.text, text);
        assert_eq!(parsed.config.load_warnings, []);

        // A value of the wrong type is the same error under either name.
        let err = NetwatchConfig::parse("colour_theme = 1\n", Path::new("c"), RENAMES)
            .err()
            .expect("a number is not a theme");
        assert!(err.to_string().contains("invalid type"), "{err}");
    }

    /// A save writes the new name once and the old one not at all, so the next
    /// load has nothing to say. Saving again changes nothing.
    #[test]
    fn a_save_moves_a_renamed_key_to_its_new_name() {
        let file = Path::new("config.toml");
        let parsed = parse_renamed(
            "# mine\ncolour_theme = 'nord' # why\n[alerts]\nbandwidth_limit = 5\ntypo = 1\n",
            RENAMES,
        );
        let saved = edited_file(Some(&parsed), &Changes::default(), false, file)
            .unwrap()
            .expect("a rename is worth a write");
        for gone in ["colour_theme", "bandwidth_limit"] {
            assert!(!saved.contains(gone), "{gone} in\n{saved}");
        }
        assert_eq!(saved.matches("theme = ").count(), 1, "{saved}");
        assert!(saved.contains("# mine\ntheme = 'nord' # why\n"), "{saved}");
        assert_eq!(
            saved.matches("bandwidth_threshold = 5\n").count(),
            1,
            "{saved}"
        );
        assert!(saved.contains("typo = 1\n"), "{saved}");

        let again = parse_renamed(&saved, RENAMES);
        assert_eq!(unknown_keys(&again.config), ["alerts.typo"]);
        assert_eq!(again.config.load_warnings.len(), 1, "{saved}");
        assert_eq!(
            edited_file(Some(&again), &Changes::default(), false, file).unwrap(),
            None
        );
    }

    /// `[experimental]` parses, what is in it is not called unknown, a save keeps
    /// it, comment and all, and a file that never mentioned it does not gain it.
    #[test]
    fn the_experimental_table_parses_and_is_quieter_than_an_unknown_key() {
        let dir = scratch("experimental");
        let path = dir.join("config.toml");
        fs::write(
            &path,
            "typo = 1\n# trying this out\n[experimental]\nfuture_thing = 1\n[experimental.nested]\na = 2\n",
        )
        .unwrap();
        let mut cfg = NetwatchConfig::load_from(&path).unwrap();
        assert_eq!(unknown_keys(&cfg), ["typo"]);
        let quiet: Vec<_> = cfg.load_warnings.iter().filter(|w| w.is_quiet()).collect();
        assert_eq!(quiet.len(), 2, "{:?}", cfg.load_warnings);
        assert!(quiet[0]
            .to_string()
            .contains("experimental.future_thing is not used"));

        cfg.confirm_quit = true;
        cfg.save_to(&path).unwrap();
        let saved = fs::read_to_string(&path).unwrap();
        for kept in [
            "# trying this out\n[experimental]\nfuture_thing = 1\n",
            "[experimental.nested]\na = 2\n",
        ] {
            assert!(saved.contains(kept), "{kept:?} not in\n{saved}");
        }
        assert_eq!(
            NetwatchConfig::load_from(&path).unwrap().load_warnings,
            cfg.load_warnings
        );

        // Empty, it has nothing to say and still stays.
        fs::write(&path, "# later\n[experimental]\n").unwrap();
        let mut cfg = NetwatchConfig::load_from(&path).unwrap();
        assert_eq!(cfg.load_warnings, []);
        cfg.confirm_quit = true;
        cfg.save_to(&path).unwrap();
        let saved = fs::read_to_string(&path).unwrap();
        assert!(saved.contains("# later\n[experimental]\n"), "{saved}");

        let fresh = toml::to_string_pretty(&NetwatchConfig::default()).unwrap();
        assert!(!fresh.contains("experimental"), "{fresh}");

        // Not a table is a value of the wrong type, like any other key.
        fs::write(&path, "experimental = 5\n").unwrap();
        assert!(matches!(
            NetwatchConfig::load_from(&path),
            Err(ConfigError::Parse { .. })
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    /// `*` is a named entry as well as an array's, for the policy's
    /// `[process.<name>]`.
    #[test]
    fn a_rename_reaches_every_named_entry() {
        let (text, moved) = apply_renames(
            "[process.curl]\nallow_snis = ['a']\n[process.ssh]\nallow_ports = [22]\n",
            &[RenamedKey {
                old: "process.*.allow_snis",
                new: "process.*.allow_sni",
                since: "1.1",
            }],
        );
        assert_eq!(moved.len(), 1);
        let policy: crate::collectors::egress::EgressPolicy = toml::from_str(&text).unwrap();
        assert_eq!(policy.process["curl"].allow_sni, ["a"]);
        assert_eq!(policy.process["ssh"].allow_ports, [22]);
    }

    /// The typo the warning exists for, at every depth a config has, and the
    /// value is not what it reads as. Loading any number of times says nothing
    /// and finds the same keys, because a session does load more than once.
    #[test]
    fn unknown_keys_are_recorded_at_every_depth_and_loading_says_nothing() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tracing_subscriber::layer::{Context, SubscriberExt};

        struct Count(Arc<AtomicUsize>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Count {
            fn on_event(&self, _: &tracing::Event<'_>, _: Context<'_, S>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let dir = scratch("unknown");
        let path = dir.join("config.toml");
        fs::write(
            &path,
            r#"
sandbox_mode = "strict"
[alerts]
bandwidth_thresold = 5
[diagnose_thresholds]
dns_ceiling = 30
[diagnose_probes]
trace_targt = "9.9.9.9"
[[diagnose_probes.portal_endpoints]]
url = "http://a.example/"
expect_status = 204
expected = 1
[[diagnose_targets]]
name = "api"
host = "a.example"
[[diagnose_targets]]
name = "web"
host = "b.example"
intervl = 5
[stray]
anything = "goes"
"#,
        )
        .unwrap();

        let events = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry().with(Count(Arc::clone(&events)));
        tracing::subscriber::with_default(subscriber, || {
            for _ in 0..3 {
                let cfg = NetwatchConfig::load_from(&path).unwrap();
                let mut keys = unknown_keys(&cfg);
                keys.sort();
                assert_eq!(
                    keys,
                    [
                        "alerts.bandwidth_thresold",
                        "diagnose_probes.portal_endpoints.0.expected",
                        "diagnose_probes.trace_targt",
                        "diagnose_targets.1.intervl",
                        "diagnose_thresholds.dns_ceiling",
                        "sandbox_mode",
                        "stray",
                    ]
                );
                assert_eq!(cfg.sandbox, "on", "the typo is not the setting");
                assert!(cfg.load_warnings.iter().all(|w| w.file == path));
            }
            assert_eq!(events.load(Ordering::Relaxed), 0);
        });
        let _ = fs::remove_dir_all(&dir);
    }

    /// A warning that fires on a key netwatch does read teaches people to
    /// ignore the warning. Every key at once, with every optional one set.
    #[test]
    fn no_key_netwatch_reads_is_called_unknown() {
        let cfg: NetwatchConfig = toml::from_str(
            r#"
[diagnose_probes]
pmtu_url = "http://a.example/big"
trace_refresh_secs = 60
[[diagnose_targets]]
name = "api"
host = "a.example"
tls = true
expect_status = 200
"#,
        )
        .unwrap();
        let cfg = NetwatchConfig {
            diagnose_thresholds: crate::diagnose::detectors::Thresholds {
                sigma_k: 4.0,
                ..Default::default()
            },
            ..cfg
        };
        let text = format!(
            "geoip_online = true\n{}",
            toml::to_string_pretty(&cfg).unwrap()
        );
        for key in [
            "pmtu_url",
            "trace_refresh_secs",
            "tls",
            "expect_status",
            "sigma_k",
        ] {
            assert!(text.contains(key), "{key} is not in\n{text}");
        }
        let back = NetwatchConfig::from_toml(&text, Path::new("config.toml")).unwrap();
        assert_eq!(back.load_warnings, []);
        // Nor is the field that holds them a key a file can set.
        let set = NetwatchConfig::from_toml("load_warnings = []", Path::new("c")).unwrap();
        assert_eq!(unknown_keys(&set), ["load_warnings"]);
    }

    /// A quoted key can hold an escape sequence, and this text goes to a
    /// terminal. The message names the file, and never carries the value.
    #[test]
    fn a_warning_names_the_key_and_file_safely_and_not_the_value() {
        let cfg = NetwatchConfig::from_toml(
            "\"a\\u001b[2Jb\" = \"secret-value\"\n",
            Path::new("/etc/netwatch/config.toml"),
        )
        .unwrap();
        let warning = &cfg.load_warnings[0];
        assert_eq!(
            warning.to_string(),
            "/etc/netwatch/config.toml: unknown key a·[2Jb is ignored"
        );
        assert_eq!(
            warning.short(),
            "config.toml: unknown key a·[2Jb is ignored"
        );
    }

    /// A session's save, from a file read at the start of it and possibly edited
    /// since: load, `change`, optionally `edit` the file by hand, save.
    fn saved_after(
        original: &str,
        change: impl FnOnce(&mut NetwatchConfig),
        edited: Option<&str>,
    ) -> String {
        let dir = scratch("session");
        let path = dir.join("config.toml");
        fs::write(&path, original).unwrap();
        let mut cfg = NetwatchConfig::load_from(&path).unwrap();
        change(&mut cfg);
        if let Some(edited) = edited {
            fs::write(&path, edited).unwrap();
        }
        cfg.save_to(&path).unwrap();
        let saved = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_dir_all(&dir);
        saved
    }

    /// What a save did to these until 0.40: rewrote the file from the struct,
    /// so a key netwatch does not read was gone with no word, and with it the
    /// warning about it. A key from a newer version went the same way.
    #[test]
    fn a_save_keeps_unknown_keys_and_comments_and_changes_only_what_changed() {
        let original = r#"# my settings
sandbox_mode = "strict"  # typo, fix me
theme = 'nord' # the good one
refresh_rate_ms = 1_000

# watch the uplink
[alerts]
bandwidth_threshold = 1_000
bandwidth_thresold = 5

[[diagnose_targets]]
# the api
name = "api"
host = "a.example"
from_a_newer_version = { a = 1 }

[stray]
anything = "goes"
"#;
        let saved = saved_after(
            original,
            |cfg| {
                cfg.theme = "ocean".into();
                cfg.diagnose_targets[0].enabled = false;
            },
            None,
        );
        let wanted = original
            .replace(
                "theme = 'nord' # the good one",
                "theme = \"ocean\" # the good one",
            )
            .replace(
                "from_a_newer_version = { a = 1 }\n",
                "from_a_newer_version = { a = 1 }\nenabled = false\n",
            );
        assert_eq!(saved, wanted);
    }

    /// The bad one: a strict sandbox set by hand while a session ran went back to
    /// `on` when that session saved a theme.
    #[test]
    fn a_save_leaves_a_hand_edit_made_while_the_session_ran() {
        let saved = saved_after(
            "theme = 'nord'\nsandbox = 'on'\n",
            |cfg| cfg.theme = "ocean".into(),
            Some("theme = 'nord'\nsandbox = 'strict'\n# added by hand\nnew_key = 1\n"),
        );
        assert_eq!(
            saved,
            "theme = \"ocean\"\nsandbox = 'strict'\n# added by hand\nnew_key = 1\n"
        );
    }

    /// If both changed the same key the session's explicit change wins, for that
    /// key alone.
    #[test]
    fn a_session_change_beats_a_hand_edit_of_that_key_only() {
        let saved = saved_after(
            "theme = 'nord'\nview = 'lite'\n",
            |cfg| cfg.theme = "ocean".into(),
            Some("theme = 'dracula'\nview = 'dense'\n"),
        );
        assert_eq!(saved, "theme = \"ocean\"\nview = 'dense'\n");
    }

    /// `validate` corrects these for the session. That is not a change anyone
    /// asked to write: a later release may accept `future_view`, and an unrelated
    /// save used to turn it into `full`.
    #[test]
    fn a_save_does_not_write_what_validate_corrected() {
        let original = "refresh_rate_ms = 50\nview = \"future_view\"\ntheme = \"\"\n";
        let saved = saved_after(original, |cfg| cfg.confirm_quit = true, None);
        assert_eq!(saved, format!("{original}confirm_quit = true\n"));

        // Until someone sets one of them.
        let saved = saved_after(original, |cfg| cfg.refresh_rate_ms = 200, None);
        assert!(saved.contains("refresh_rate_ms = 200\n"), "{saved}");
        assert!(saved.contains("view = \"future_view\"\n"), "{saved}");
    }

    /// Every save used to write every default, which grew this to 49 lines, and
    /// held today's defaults there when a release changed one.
    #[test]
    fn a_save_writes_no_defaults_and_a_target_can_be_appended_afterwards() {
        let saved = saved_after("theme = 'nord'\n", |cfg| cfg.theme = "ocean".into(), None);
        assert_eq!(saved, "theme = \"ocean\"\n");

        // Nothing to start from, too: `diagnose_targets = []` from a save made the
        // `[[diagnose_targets]]` DIAGNOSE.md says to append a TOML error.
        let dir = scratch("no_file");
        let path = dir.join("netwatch/config.toml");
        let mut cfg = NetwatchConfig {
            confirm_quit: true,
            ..Default::default()
        };
        cfg.save_to(&path).unwrap();
        let mut text = fs::read_to_string(&path).unwrap();
        assert_eq!(text, "confirm_quit = true\n");
        text.push_str("[[diagnose_targets]]\nname = \"api\"\nhost = \"a.example\"\n");
        fs::write(&path, text).unwrap();
        assert_eq!(
            NetwatchConfig::load_from(&path).unwrap().diagnose_targets[0].name,
            "api"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Nothing changed, nothing written, down to the bytes: a table at its
    /// defaults, Windows line endings, a byte-order mark. A second save with
    /// nothing new leaves what the first one wrote.
    #[test]
    fn a_save_with_nothing_to_write_does_not_touch_the_file() {
        let dir = scratch("untouched");
        let path = dir.join("config.toml");
        let original = "\u{feff}# mine\r\n[diagnose_thresholds]\r\nsigma_k = 3.0\r\n# the end\r\n";
        fs::write(&path, original).unwrap();
        let mut cfg = NetwatchConfig::load_from(&path).unwrap();
        cfg.save_to(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), original);

        let dir2 = scratch("no_file_no_change");
        let missing = dir2.join("config.toml");
        NetwatchConfig::default().save_to(&missing).unwrap();
        assert!(!missing.exists(), "nothing changed, so nothing to write");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&dir2);
    }

    /// A first save of a key in a table the file lacks goes after everything,
    /// comments at the end of the file included, which used to end up below it.
    #[test]
    fn a_new_table_goes_after_the_comments_at_the_end_of_the_file() {
        let original = "theme = 'nord'\n\n[stray]\na = 1\n# about stray\n\n# the end\n";
        let saved = saved_after(original, |cfg| cfg.alerts.bandwidth_threshold = 5, None);
        assert_eq!(
            saved,
            format!("{original}\n[alerts]\nbandwidth_threshold = 5\n")
        );
    }

    /// Changing one threshold writes that one, in a table of its own if need be.
    #[test]
    fn changing_a_threshold_writes_only_that_threshold() {
        let saved = saved_after(
            "theme = 'nord'\n",
            |cfg| cfg.diagnose_thresholds.sigma_k = 4.0,
            None,
        );
        assert_eq!(
            saved,
            "theme = 'nord'\n\n[diagnose_thresholds]\nsigma_k = 4.0\n"
        );
        let saved = saved_after(
            "[diagnose_thresholds]\n# keep\ndns_ceiling_ms = 30\n",
            |cfg| cfg.diagnose_thresholds.sigma_k = 4.0,
            None,
        );
        assert_eq!(
            saved,
            "[diagnose_thresholds]\n# keep\ndns_ceiling_ms = 30\nsigma_k = 4.0\n"
        );
    }

    /// `30` and `30.0` are the same to a float key, so writing 30.0 over a file
    /// that says `30` leaves it. A different number still goes in.
    #[test]
    fn a_numerically_equal_value_is_left_as_written() {
        let saved = saved_after(
            "[diagnose_thresholds]\ndns_ceiling_ms = 25\n",
            |cfg| cfg.diagnose_thresholds.dns_ceiling_ms = 30.0,
            Some("[diagnose_thresholds]\ndns_ceiling_ms = 30 # by hand\n"),
        );
        assert_eq!(
            saved,
            "[diagnose_thresholds]\ndns_ceiling_ms = 30 # by hand\n"
        );
        let saved = saved_after(
            "[diagnose_thresholds]\ndns_ceiling_ms = 25\n",
            |cfg| cfg.diagnose_thresholds.dns_ceiling_ms = 31.0,
            None,
        );
        assert_eq!(saved, "[diagnose_thresholds]\ndns_ceiling_ms = 31.0\n");
    }

    const TWO_TARGETS: &str = r#"[[diagnose_targets]]
# the api
name = "api"
host = "a.example"
api_only = 1

[[diagnose_targets]]
# the web
name = "web"
host = "b.example"
enabled = true
web_only = 2
"#;

    fn toggled(name: &str) -> impl FnOnce(&mut NetwatchConfig) + '_ {
        move |cfg| {
            let target = cfg
                .diagnose_targets
                .iter_mut()
                .find(|t| t.name == name)
                .unwrap();
            target.enabled = !target.enabled;
        }
    }

    /// `d` in Diagnose changes that target's `enabled` and no other line.
    #[test]
    fn toggling_a_target_changes_only_its_enabled() {
        assert_eq!(
            saved_after(TWO_TARGETS, toggled("web"), None),
            TWO_TARGETS.replace("enabled = true", "enabled = false")
        );
        assert_eq!(
            saved_after(TWO_TARGETS, toggled("api"), None),
            TWO_TARGETS.replace("api_only = 1\n", "api_only = 1\nenabled = false\n")
        );
    }

    /// Entries reordered by hand while a session ran. By position, the first
    /// entry's comment and unknown keys would have gone to the wrong target, as
    /// a whole entry was rewritten from the session's list by index.
    #[test]
    fn a_target_is_found_by_name_after_the_file_reorders_them() {
        let reordered = r#"[[diagnose_targets]]
# the web
name = "web"
host = "b.example"
enabled = true
web_only = 2

[[diagnose_targets]]
# the api
name = "api"
host = "a.example"
api_only = 1
"#;
        assert_eq!(
            saved_after(TWO_TARGETS, toggled("web"), Some(reordered)),
            reordered.replace("enabled = true", "enabled = false")
        );
    }

    /// A target added or edited by hand survives a save of anything else, or of
    /// a toggle of another target. The file's host stays, as the session changed
    /// only `enabled`.
    #[test]
    fn a_target_added_or_edited_by_hand_survives_a_save() {
        let edited = format!(
            "{}\n[[diagnose_targets]]\nname = \"new\"\nhost = \"c.example\"\n",
            TWO_TARGETS.replace("host = \"b.example\"", "host = \"moved.example\"")
        );
        assert_eq!(
            saved_after(TWO_TARGETS, |cfg| cfg.confirm_quit = true, Some(&edited)),
            format!("confirm_quit = true\n{edited}")
        );
        assert_eq!(
            saved_after(TWO_TARGETS, toggled("api"), Some(&edited)),
            edited.replace("api_only = 1\n", "api_only = 1\nenabled = false\n")
        );
    }

    /// A target deleted by hand cannot take a toggle: `enabled` alone would be an
    /// entry with no host, and a file that no longer loads. The save says so.
    #[test]
    fn toggling_a_target_the_file_lost_fails_and_leaves_the_file() {
        let dir = scratch("target_gone");
        let path = dir.join("config.toml");
        fs::write(&path, TWO_TARGETS).unwrap();
        let mut cfg = NetwatchConfig::load_from(&path).unwrap();
        cfg.diagnose_targets[1].enabled = false;
        let kept = "[[diagnose_targets]]\nname = \"api\"\nhost = \"a.example\"\n";
        fs::write(&path, kept).unwrap();
        let err = cfg.save_to(&path).unwrap_err().to_string();
        assert!(err.contains("target web is no longer in"), "{err}");
        assert_eq!(fs::read_to_string(&path).unwrap(), kept);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Targets the session adds or removes, which only a caller in code does, and
    /// the forms a file can hold them in.
    #[test]
    fn a_session_can_add_and_remove_targets() {
        let target: crate::diagnose::targets::TargetConfig =
            toml::from_str("name = \"new\"\nhost = \"c.example\"").unwrap();

        let saved = saved_after(
            TWO_TARGETS,
            |cfg| {
                cfg.diagnose_targets.remove(0);
                cfg.diagnose_targets.push(target.clone());
            },
            None,
        );
        let back: NetwatchConfig = toml::from_str(&saved).unwrap();
        let names: Vec<_> = back
            .diagnose_targets
            .iter()
            .map(|t| t.name.as_str())
            .collect();
        assert_eq!(names, ["web", "new"], "{saved}");
        assert!(saved.contains("web_only = 2"), "{saved}");
        assert!(!saved.contains("api_only"), "{saved}");

        // In place of the `diagnose_targets = []` older releases generated.
        let saved = saved_after(
            "diagnose_targets = []\ntheme = 'nord'\n",
            |cfg| cfg.diagnose_targets.push(target.clone()),
            None,
        );
        assert!(!saved.contains("diagnose_targets = []"), "{saved}");
        let back: NetwatchConfig = toml::from_str(&saved).unwrap();
        assert_eq!(back.diagnose_targets[0].name, "new", "{saved}");

        // Inside an array of inline tables, where a `[[...]]` could not follow.
        let saved = saved_after(
            "diagnose_targets = [{ name = \"api\", host = \"a.example\", typo = 1 }]\n",
            |cfg| cfg.diagnose_targets.push(target.clone()),
            None,
        );
        let back = NetwatchConfig::from_toml(&saved, Path::new("c")).unwrap();
        assert_eq!(back.diagnose_targets.len(), 2, "{saved}");
        assert_eq!(unknown_keys(&back), ["diagnose_targets.0.typo"], "{saved}");
    }

    /// The other ways TOML writes a table. An unknown key in each stays, and a
    /// changed value goes where the file has its table.
    #[test]
    fn a_save_writes_into_inline_and_dotted_tables() {
        let original = "alerts = { bandwidth_threshold = 5, typo = 1 }\n\
             diagnose_probes.trace_target = \"9.9.9.9\"\n\
             diagnose_probes.typo = 2\n\
             diagnose_targets = [{ name = \"api\", host = \"a.example\", typo = 3 }]\n";
        let saved = saved_after(
            original,
            |cfg| {
                cfg.alerts.bandwidth_threshold = 6;
                cfg.alerts.port_scan_threshold = 7;
                cfg.diagnose_probes.trace_target = "8.8.8.8".into();
                cfg.diagnose_probes.trace_refresh_secs = Some(60);
                cfg.diagnose_targets[0].port = 8443;
            },
            None,
        );
        let back = NetwatchConfig::from_toml(&saved, Path::new("c")).unwrap();
        assert_eq!(back.load_warnings.len(), 3, "{saved}");
        assert_eq!(back.alerts.bandwidth_threshold, 6, "{saved}");
        assert_eq!(back.alerts.port_scan_threshold, 7, "{saved}");
        assert_eq!(back.diagnose_probes.trace_target, "8.8.8.8", "{saved}");
        assert_eq!(back.diagnose_probes.trace_refresh_secs, Some(60), "{saved}");
        assert_eq!(back.diagnose_targets[0].port, 8443, "{saved}");
        assert!(!saved.contains("[alerts]"), "{saved}");
    }

    /// A list the session changed goes in whole, in place of the old one, and a
    /// table new to the file comes after its parent.
    #[test]
    fn a_changed_list_replaces_the_old_one() {
        let pair: crate::diagnose::active::Pair =
            toml::from_str("v4 = \"192.0.2.1:443\"\nv6 = \"[2001:db8::1]:443\"\n").unwrap();
        let saved = saved_after(
            "[diagnose_probes]\ntrace_target = \"9.9.9.9\"\n\n[stray]\na = 1\n",
            |cfg| cfg.diagnose_probes.ipv6_pairs = vec![pair.clone()],
            None,
        );
        assert_eq!(
            saved,
            "[diagnose_probes]\ntrace_target = \"9.9.9.9\"\n\n[stray]\na = 1\n\n\
             [[diagnose_probes.ipv6_pairs]]\nv4 = \"192.0.2.1:443\"\nv6 = \"[2001:db8::1]:443\"\n"
        );
    }

    /// An optional key the session no longer has goes, and nothing else.
    #[test]
    fn clearing_an_optional_key_removes_it() {
        let saved = saved_after(
            "[diagnose_probes]\n# why\npmtu_url = \"http://a.example/big\"\ntypo = 1\n",
            |cfg| cfg.diagnose_probes.pmtu_url = None,
            None,
        );
        assert!(!saved.contains("pmtu_url"), "{saved}");
        assert!(saved.contains("typo = 1\n"), "{saved}");
    }

    /// The check at the end of a save. Nothing a user does should reach it, so it
    /// gets an edit that went wrong each way it could: a value not written, and a
    /// value written that nobody changed.
    #[test]
    fn an_edit_that_does_not_read_back_is_refused() {
        let changes = Changes {
            keys: vec![(
                vec!["theme".to_owned()],
                Some(toml::Value::String("ocean".into())),
            )],
            targets: vec![],
        };
        let before = "theme = 'nord'\nview = 'lite'\n";
        check_reads_back(before, "theme = 'ocean'\nview = 'lite'\n", &changes).unwrap();
        for wrong in [
            "theme = 'nord'\nview = 'lite'\n",
            "theme = 'ocean'\nview = 'dense'\n",
            "theme = 'ocean'\ntheme = 'ocean'\n",
        ] {
            assert!(
                check_reads_back(before, wrong, &changes).is_err(),
                "{wrong}"
            );
        }
    }

    /// `--generate-config` is the one thing that writes defaults. On a new file it
    /// writes them all, and on an old one it adds what is missing and keeps the
    /// rest, values and all.
    #[test]
    fn generate_writes_every_default_and_keeps_what_the_file_has() {
        let dir = scratch("generate");
        let path = dir.join("netwatch/config.toml");
        NetwatchConfig::generate_at(&path).unwrap();
        let fresh = fs::read_to_string(&path).unwrap();
        assert_eq!(
            fresh,
            toml::to_string_pretty(&NetwatchConfig::default()).unwrap()
        );
        assert!(!fresh.contains("diagnose_targets"), "{fresh}");

        // Run again, and over an empty file: the same.
        NetwatchConfig::generate_at(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), fresh);
        fs::write(&path, "").unwrap();
        NetwatchConfig::generate_at(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), fresh);

        // A target can be appended to what it wrote.
        let mut text = fresh.clone();
        text.push_str("[[diagnose_targets]]\nname = \"api\"\nhost = \"a.example\"\n");
        fs::write(&path, text).unwrap();
        assert_eq!(
            NetwatchConfig::load_from(&path)
                .unwrap()
                .diagnose_targets
                .len(),
            1
        );

        fs::write(
            &path,
            "# mine\nsandbox = \"strict\"\nrefresh_rate_ms = 50\ntypo = 1\n\n[alerts]\n\
             port_scan_threshold = 7 # low\n\n[[diagnose_targets]]\nname = \"api\"\n\
             host = \"a.example\"\n\n[diagnose_thresholds]\nsigma_k = 9.0\n# the end\n",
        )
        .unwrap();
        NetwatchConfig::generate_at(&path).unwrap();
        let saved = fs::read_to_string(&path).unwrap();
        for kept in [
            "# mine\nsandbox = \"strict\"\nrefresh_rate_ms = 50\ntypo = 1\n",
            "port_scan_threshold = 7 # low\n",
            "[[diagnose_targets]]\nname = \"api\"\nhost = \"a.example\"\n",
            "sigma_k = 9.0\n# the end\n",
            // Filled in where the file's table is.
            "port_scan_window_secs = 30\n",
            // New tables after the comments at the end.
            "# the end\n\n[diagnose_probes]\n",
            // A key the file left out, at the end of the keys it has.
            "show_geo = true\n",
        ] {
            assert!(saved.contains(kept), "{kept:?} not in\n{saved}");
        }
        let back = NetwatchConfig::load_from(&path).unwrap();
        assert_eq!(back.sandbox, "strict");
        assert_eq!(back.alerts.port_scan_threshold, 7);
        assert_eq!(back.diagnose_thresholds.sigma_k, 9.0);
        assert_eq!(unknown_keys(&back), ["typo"]);

        // With nothing missing it does not write, and it still refuses a bad file.
        NetwatchConfig::generate_at(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), saved);
        fs::write(&path, "refresh_rate_ms = 'oops'\n").unwrap();
        assert!(NetwatchConfig::generate_at(&path).is_err());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "refresh_rate_ms = 'oops'\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `--view dense` is about this run. A save does not make it the default, and
    /// changing the View row in Settings does.
    #[test]
    fn view_for_this_run_is_not_saved() {
        let saved = saved_after(
            "view = 'lite'\n",
            |cfg| {
                cfg.set_view_for_this_run("dense");
                cfg.confirm_quit = true;
            },
            None,
        );
        assert_eq!(saved, "view = 'lite'\nconfirm_quit = true\n");
        let saved = saved_after(
            "view = 'lite'\n",
            |cfg| {
                cfg.set_view_for_this_run("dense");
                cfg.view = "full".into();
            },
            None,
        );
        assert_eq!(saved, "view = \"full\"\n");
    }

    /// What `r` read in the Diagnose tab is what the file says, so a later save has
    /// nothing to do for it, and unsaved Settings changes are still unsaved.
    #[test]
    fn reloading_diagnose_settings_moves_the_baseline() {
        let dir = scratch("reload");
        let path = dir.join("config.toml");
        fs::write(&path, TWO_TARGETS).unwrap();
        let mut cfg = NetwatchConfig::load_from(&path).unwrap();
        cfg.theme = "ocean".into();

        let edited = "[[diagnose_targets]]\nname = \"only\"\nhost = \"c.example\"\n# new\n";
        fs::write(&path, edited).unwrap();
        cfg.reload_diagnose_settings(NetwatchConfig::from_toml(edited, &path).unwrap());
        assert_eq!(cfg.diagnose_targets[0].name, "only");

        cfg.save_to(&path).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("theme = \"ocean\"\n{edited}")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A second save starts from what the first wrote, so a hand edit of a key the
    /// first one wrote survives the next, and a failed save stays pending.
    #[test]
    fn each_save_moves_the_baseline_and_a_failed_one_does_not() {
        let dir = scratch("twice");
        let path = dir.join("config.toml");
        fs::write(&path, "theme = 'nord'\n").unwrap();
        let mut cfg = NetwatchConfig::load_from(&path).unwrap();
        cfg.theme = "ocean".into();
        cfg.save_to(&path).unwrap();
        fs::write(&path, "theme = 'dracula'\n").unwrap();
        cfg.confirm_quit = true;
        cfg.save_to(&path).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "theme = 'dracula'\nconfirm_quit = true\n"
        );

        cfg.view = "dense".into();
        fs::write(&path, "refresh_rate_ms = 'oops'\n").unwrap();
        assert!(cfg.save_to(&path).is_err());
        fs::write(&path, "theme = 'dracula'\n").unwrap();
        cfg.save_to(&path).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "theme = 'dracula'\nview = \"dense\"\n"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `geoip_online` goes on a save with a comment directly above it, because
    /// that comment is about it. Nothing else moves.
    #[test]
    fn a_save_drops_a_removed_key_with_the_comment_above_it() {
        let saved = saved_after(
            "# keep\ntheme = 'nord'\n# why online\ngeoip_online = true\n# also keep\nview = 'lite'\n",
            |_| {},
            None,
        );
        assert_eq!(
            saved,
            "# keep\ntheme = 'nord'\n# also keep\nview = 'lite'\n"
        );
    }

    /// Enough of a random number generator to make these files. The seed is in
    /// every failure message.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        fn chance(&mut self, percent: u64) -> bool {
            self.below(100) < percent
        }
        fn pick<'a>(&mut self, from: &[&'a str]) -> &'a str {
            from[self.below(from.len() as u64) as usize]
        }
    }

    /// A config.toml a person might have: known keys in odd spellings, values out
    /// of range, comments everywhere, keys netwatch does not read at every depth.
    fn generated_file(rng: &mut Rng) -> String {
        const ROOT: &[&str] = &[
            "theme = 'nord'",
            "theme = \"ocean\" # mine",
            "refresh_rate_ms = 1_000",
            "refresh_rate_ms = 50",
            "refresh_rate_ms = 0x3e8",
            "view = \"future_view\"",
            "view = 'lite'",
            "sandbox = 'strict'",
            "sandbox = \"on\"  # for now",
            "show_geo = false",
            "packet_follow = true",
            "confirm_quit = false",
            "insights_model = \"\"",
            "bpf_filter = 'tcp port 443'",
            "geoip_online = false",
            "unknown_root = 1",
            "sandbox_mode = \"strict\"",
            "# a comment about nothing",
            "",
        ];
        let mut text = String::new();
        let mut used = std::collections::HashSet::new();
        for _ in 0..rng.below(10) {
            let line = rng.pick(ROOT);
            // A key once, as TOML wants.
            let key = line.split(['=', ' ']).next().unwrap_or("");
            if line.starts_with('#') || line.is_empty() || used.insert(key) {
                text.push_str(line);
                text.push('\n');
            }
        }
        if rng.chance(60) {
            text.push_str("\n# the alerts\n[alerts]\n");
            if rng.chance(70) {
                text.push_str("bandwidth_threshold = 1_000 # low\n");
            }
            if rng.chance(30) {
                text.push_str("bandwidth_thresold = 2\n");
            }
            if rng.chance(30) {
                text.push_str("# scans\nport_scan_threshold = 99\n");
            }
        }
        if rng.chance(30) {
            text.push_str(
                "\n[diagnose_thresholds]\nsigma_k = 3.0\ndns_ceiling_ms = 30\ntypo = 1\n",
            );
        }
        if rng.chance(30) {
            text.push_str("\n[stray]\nanything = 'goes'\n[stray.deeper]\nb = 2\n");
        }
        if rng.chance(20) {
            text.push_str("\n[experimental]\nsomething = 1\n");
        }
        for (name, comment) in [("api", "# the api\n"), ("web", ""), ("db", "# the db\n")] {
            if rng.chance(40) {
                text.push_str(&format!(
                    "\n[[diagnose_targets]]\n{comment}name = \"{name}\"\nhost = \"{name}.example\"\n"
                ));
                if rng.chance(40) {
                    text.push_str(&format!("{name}_unknown = 1\n"));
                }
                if rng.chance(30) {
                    text.push_str("enabled = true\n");
                }
            }
        }
        if rng.chance(50) {
            text.push_str("\n# the end of the file\n");
        }
        text
    }

    /// A hand edit made while the session ran: one more line in the root table,
    /// and sometimes the targets in another order. They are the last tables a
    /// generated file has, so each block runs to the next one, and the comment at
    /// the end of the file moves with the last, as it would in an editor.
    fn hand_edited(text: &str, rng: &mut Rng) -> String {
        let text = format!("hand_edit = {}\n{text}", rng.below(1000));
        if rng.chance(50) {
            let mut blocks: Vec<&str> = text.split("\n[[diagnose_targets]]").collect();
            if blocks.len() > 2 {
                let head = blocks.remove(0);
                blocks.reverse();
                let mut edited = head.to_owned();
                for block in blocks {
                    edited.push_str("\n[[diagnose_targets]]");
                    edited.push_str(block.trim_end_matches('\n'));
                    edited.push('\n');
                }
                return edited;
            }
        }
        text
    }

    /// `text` without `geoip_online`, the one other key a save takes out, and the
    /// comments and blank lines directly above it, which go with it.
    fn without_removed_key(text: &str) -> String {
        let mut kept: Vec<&str> = Vec::new();
        for line in text.lines() {
            if line.starts_with("geoip_online") {
                while kept
                    .last()
                    .is_some_and(|l| l.is_empty() || l.starts_with('#'))
                {
                    kept.pop();
                }
            } else {
                kept.push(line);
            }
        }
        kept.iter().map(|line| format!("{line}\n")).collect()
    }

    /// The lines of `before` not in `changed` still appear in `after`, in order.
    fn missing_lines<'a>(before: &'a str, after: &str, changed: &str) -> Vec<&'a str> {
        let mut rest = after.lines();
        before
            .lines()
            .filter(|line| !line.trim_start().starts_with(changed))
            .filter(|line| !rest.any(|l| l == *line))
            .collect()
    }

    /// Generated files, one change by a session, with or without a hand edit. The
    /// file then means what it meant plus that change, and every other line is
    /// still there in its order. A second save writes nothing.
    #[test]
    fn a_save_changes_one_key_and_nothing_else_in_generated_files() {
        let iterations = std::env::var("NETWATCH_SAVE_FUZZ_ITERATIONS")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(400u64);
        let dir = scratch("fuzz");
        let path = dir.join("config.toml");
        for seed in 1..=iterations {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let original = generated_file(&mut rng);
            fs::write(&path, &original).unwrap();
            let Ok(mut cfg) = NetwatchConfig::load_from(&path) else {
                panic!("seed {seed}: a generated file did not load\n{original}");
            };

            let target_names: Vec<String> = cfg
                .diagnose_targets
                .iter()
                .map(|t| t.name.clone())
                .collect();
            let key = match rng.below(if target_names.is_empty() { 6 } else { 8 }) {
                0 => {
                    cfg.theme = "dracula".into();
                    "theme"
                }
                1 => {
                    cfg.refresh_rate_ms = 777;
                    "refresh_rate_ms"
                }
                2 => {
                    cfg.confirm_quit = !cfg.confirm_quit;
                    "confirm_quit"
                }
                3 => {
                    cfg.alerts.bandwidth_threshold = 12345;
                    "bandwidth_threshold"
                }
                4 => {
                    cfg.alerts.port_scan_threshold = 321;
                    "port_scan_threshold"
                }
                5 => {
                    cfg.insights_endpoint = "http://a.example".into();
                    "insights_endpoint"
                }
                _ => {
                    let at = rng.below(target_names.len() as u64) as usize;
                    cfg.diagnose_targets[at].enabled = !cfg.diagnose_targets[at].enabled;
                    "enabled"
                }
            };
            let toggled = cfg
                .diagnose_targets
                .iter()
                .find(|t| !t.enabled)
                .map(|t| t.name.clone());

            let before = if rng.chance(50) {
                let edited = hand_edited(&original, &mut rng);
                fs::write(&path, &edited).unwrap();
                edited
            } else {
                original.clone()
            };
            let context = || format!("seed {seed}, changed {key}\n--- before\n{before}");
            cfg.save_to(&path)
                .unwrap_or_else(|e| panic!("{e:#}: {}", context()));
            let after = fs::read_to_string(&path).unwrap();
            let context = || format!("{}--- after\n{after}", context());

            let kept = without_removed_key(&before);
            let lost = missing_lines(&kept, &after, key);
            assert_eq!(lost, Vec::<&str>::new(), "{}", context());

            // Nothing written but that key, and the table it may need.
            let added: Vec<_> = {
                let mut old = kept.lines().peekable();
                after
                    .lines()
                    .filter(|line| {
                        if old.peek() == Some(line) {
                            old.next();
                            return false;
                        }
                        old.clone().all(|l| l != *line)
                    })
                    .filter(|line| !line.is_empty())
                    .collect()
            };
            assert!(
                added
                    .iter()
                    .all(|line| line.starts_with(key) || *line == "[alerts]"),
                "{added:?}: {}",
                context()
            );

            // It means what it meant, with that one change.
            let read = |text: &str| -> toml::Table {
                toml::from_str::<NetwatchConfig>(text)
                    .unwrap()
                    .values()
                    .unwrap()
            };
            let changes = Changes::between(&read(&after), &read(&before));
            let one = if key == "enabled" {
                assert!(changes.keys.is_empty(), "{changes:?}: {}", context());
                changes.targets.len() <= 1
                    && changes.targets.iter().all(|change| match change {
                        TargetChange::Fields { name, fields, .. } => {
                            fields.len() == 1
                                && fields[0].0 == ["enabled"]
                                && (fields[0].1 == Some(toml::Value::Boolean(false))
                                    && Some(name) == toggled.as_ref()
                                    || fields[0].1 == Some(toml::Value::Boolean(true)))
                        }
                        _ => false,
                    })
            } else {
                changes.targets.is_empty()
                    && changes.keys.len() <= 1
                    && changes
                        .keys
                        .iter()
                        .all(|(path, _)| path.last().is_some_and(|k| k == key))
            };
            assert!(one, "{changes:?}: {}", context());

            // The same keys it could not read, and nothing left to write.
            let unread = |text: &str| -> Vec<KeyPath> {
                let (_, mut keys): (NetwatchConfig, Vec<KeyPath>) =
                    from_toml_reporting_unread(text).unwrap();
                keys.sort();
                keys
            };
            assert_eq!(unread(&after), unread(&before), "{}", context());
            cfg.save_to(&path).unwrap();
            assert_eq!(fs::read_to_string(&path).unwrap(), after, "{}", context());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// An empty key means the downloaded file where there is one, a path in
    /// the config always wins, and each key is decided on its own.
    #[test]
    fn empty_geoip_paths_use_the_downloaded_files() {
        let dir = std::env::temp_dir().join(format!("nw-geoip-paths-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let text = |name: &str| dir.join(name).to_str().unwrap().to_owned();
        let empty = NetwatchConfig::default();
        let paths = |cfg: &NetwatchConfig| cfg.geoip_paths_in(Some(&dir));

        assert_eq!(paths(&empty), (String::new(), String::new()));
        assert_eq!(
            empty.geoip_paths_in(None),
            (String::new(), String::new()),
            "no cache directory"
        );

        fs::write(dir.join("dbip-country-lite.mmdb"), "x").unwrap();
        fs::write(dir.join("dbip-asn-lite.mmdb"), "x").unwrap();
        assert_eq!(
            paths(&empty),
            (text("dbip-country-lite.mmdb"), text("dbip-asn-lite.mmdb"))
        );

        // City ahead of Country.
        fs::write(dir.join("dbip-city-lite.mmdb"), "x").unwrap();
        assert_eq!(paths(&empty).0, text("dbip-city-lite.mmdb"));

        let own_db = NetwatchConfig {
            geoip_db: "/geo/own.mmdb".into(),
            ..Default::default()
        };
        assert_eq!(
            paths(&own_db),
            ("/geo/own.mmdb".to_owned(), text("dbip-asn-lite.mmdb"))
        );
        let own_asn = NetwatchConfig {
            geoip_asn_db: "/geo/asn.mmdb".into(),
            ..Default::default()
        };
        assert_eq!(
            paths(&own_asn),
            (text("dbip-city-lite.mmdb"), "/geo/asn.mmdb".to_owned())
        );
        // A set path that is not there is reported, not quietly replaced.
        let missing = NetwatchConfig {
            geoip_db: "/nonexistent.mmdb".into(),
            ..Default::default()
        };
        assert_eq!(paths(&missing).0, "/nonexistent.mmdb");

        // Only a file counts.
        let empty_dir = dir.join("empty");
        fs::create_dir(&empty_dir).unwrap();
        fs::create_dir(empty_dir.join("dbip-country-lite.mmdb")).unwrap();
        assert_eq!(empty.geoip_paths_in(Some(&empty_dir)).0, "");
        let _ = fs::remove_dir_all(&dir);
    }

    /// `is_file` accepted the real path and a lossy copy of it went on, so
    /// doctor looked for a file with a different name and called it unreadable.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_downloaded_file_under_a_non_utf8_path_is_not_found() {
        use std::os::unix::ffi::OsStrExt;
        let root = std::env::temp_dir().join(format!("nw-geoip-paths-{}", uuid::Uuid::new_v4()));
        let dir = root.join(std::ffi::OsStr::from_bytes(b"cache-\xff"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("dbip-country-lite.mmdb"), "x").unwrap();
        assert_eq!(
            NetwatchConfig::default().geoip_paths_in(Some(&dir)),
            (String::new(), String::new())
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn full_roundtrip() {
        let cfg = NetwatchConfig {
            default_tab: "topology".into(),
            refresh_rate_ms: 500,
            capture_interface: "en1".into(),
            show_geo: false,
            timeline_window: "15m".into(),
            packet_follow: false,
            bpf_filter: "tcp port 443".into(),
            geoip_db: "/path/to/GeoLite2-City.mmdb".into(),
            geoip_asn_db: "/path/to/GeoLite2-ASN.mmdb".into(),
            geoip_online: true,
            alerts: AlertConfig {
                bandwidth_threshold: 50_000_000,
                port_scan_threshold: 10,
                port_scan_window_secs: 60,
            },
            insights_enabled: true,
            insights_model: "llama3:8b".into(),
            insights_endpoint: "local".into(),
            theme: "dark".into(),
            view: "dense".into(),
            graph_style: "bars".into(),
            graph_fade: false,
            sandbox: "strict".into(),
            tls_keylog_path: "/tmp/sslkeylog.txt".into(),
            egress_violation_cooldown_secs: 120,
            groups_start_collapsed: false,
            confirm_quit: true,
            third_party_probes: false,
            diagnose_record_episodes: false,
            record_uptime: false,
            diagnose_probes: Default::default(),
            diagnose_targets: vec![],
            diagnose_thresholds: Default::default(),
            experimental: Default::default(),
            load_warnings: vec![],
            loaded: None,
        };
        let serialized = toml::to_string_pretty(&cfg).unwrap();
        let deserialized: NetwatchConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.default_tab, "topology");
        assert_eq!(deserialized.refresh_rate_ms, 500);
        assert_eq!(deserialized.capture_interface, "en1");
        assert!(!deserialized.show_geo);
        assert_eq!(deserialized.timeline_window, "15m");
        assert!(!deserialized.packet_follow);
        assert!(deserialized.confirm_quit);
        assert!(!deserialized.record_uptime);
        assert!(!deserialized.third_party_probes);
        assert_eq!(deserialized.bpf_filter, "tcp port 443");
        assert_eq!(deserialized.alerts.bandwidth_threshold, 50_000_000);
        assert_eq!(deserialized.alerts.port_scan_threshold, 10);
        assert_eq!(deserialized.alerts.port_scan_window_secs, 60);
        assert_eq!(deserialized.insights_model, "llama3:8b");
        assert_eq!(deserialized.sandbox, "strict");
    }

    /// config.toml is a file people edit by hand and keep in their dotfiles,
    /// and `--generate-config` writes the one they start from. A toml release
    /// that laid it out differently (tables inlined, strings quoted another
    /// way, a float losing its `.0`) would show up in those files, and in the
    /// lines a save adds. This pins what toml decides about the layout rather
    /// than the list of keys, so adding a key does not fail it.
    #[test]
    fn saved_config_layout_is_stable() {
        let text = toml::to_string_pretty(&NetwatchConfig::default()).unwrap();
        let first_table = text.find("\n[").expect("a table");
        // Top-level keys first, one `key = value` line each.
        for line in [
            "default_tab = \"dashboard\"\n",
            "refresh_rate_ms = 1000\n",
            "capture_interface = \"\"\n",
            "show_geo = true\n",
        ] {
            let at = text
                .find(line)
                .unwrap_or_else(|| panic!("{line:?} in\n{text}"));
            assert!(at < first_table, "{line:?} after a table in\n{text}");
        }
        // Then each nested struct as its own table and each list of them as
        // an array of tables, never inline.
        for block in [
            "\n\n[alerts]\nbandwidth_threshold = 100000000\n",
            "\n\n[diagnose_probes]\ntrace_target = \"1.1.1.1\"\n",
            "\n\n[[diagnose_probes.ipv6_pairs]]\nv4 = \"1.1.1.1:443\"\nv6 = \"[2606:4700:4700::1111]:443\"\n",
            "\n\n[[diagnose_probes.portal_endpoints]]\nurl = \"http://cp.cloudflare.com/generate_204\"\nexpect_status = 204\n",
        ] {
            assert!(text.contains(block), "{block:?} in\n{text}");
        }
        assert!(!text.contains('{'), "an inline table in\n{text}");
        assert!(!text.contains("diagnose_targets"), "{text}");

        let text = toml::to_string_pretty(&NetwatchConfig {
            bpf_filter: "host \"a\"".into(),
            geoip_db: r"C:\GeoIP\City.mmdb".into(),
            tls_keylog_path: "/tmp/a\nb".into(),
            diagnose_targets: vec![toml::from_str("name = \"api\"\nhost = \"a.example\"").unwrap()],
            diagnose_thresholds: crate::diagnose::detectors::Thresholds {
                sigma_k: 3.5,
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        for line in [
            // A string a basic string would need escapes for is written as a
            // literal string, and one with a newline as a multi-line string.
            "\nbpf_filter = 'host \"a\"'\n",
            "\ngeoip_db = 'C:\\GeoIP\\City.mmdb'\n",
            "\ntls_keylog_path = \"\"\"\n/tmp/a\nb\"\"\"\n",
            "\n\n[[diagnose_targets]]\nenabled = true\nname = \"api\"\nhost = \"a.example\"\nport = 443\n",
            // Floats keep their decimal point, whole or not.
            "\n\n[diagnose_thresholds]\nsigma_k = 3.5\nsigma_close_k = 2.0\n",
        ] {
            assert!(text.contains(line), "{line:?} in\n{text}");
        }
    }

    /// toml 1.x reads TOML 1.1: an inline table may span lines and end in a
    /// comma, and strings take `\e` and `\xHH` escapes. A file written that
    /// way loads rather than falling back to the defaults.
    #[test]
    fn toml_1_1_syntax_loads() {
        let cfg: NetwatchConfig = toml::from_str(
            "bpf_filter = \"\\x74cp\"\nalerts = {\n    bandwidth_threshold = 5,\n    port_scan_threshold = 6,\n}\n",
        )
        .unwrap();
        assert_eq!(cfg.bpf_filter, "tcp");
        assert_eq!(cfg.alerts.bandwidth_threshold, 5);
        assert_eq!(cfg.alerts.port_scan_threshold, 6);
    }

    #[test]
    fn third_party_probes_defaults_true() {
        assert!(NetwatchConfig::default().third_party_probes);
        // An older file, which never heard of the key, changes nothing.
        let cfg: NetwatchConfig = toml::from_str("default_tab = \"packets\"\n").unwrap();
        assert!(cfg.third_party_probes);
    }

    #[test]
    fn third_party_probes_false_parses() {
        let cfg: NetwatchConfig = toml::from_str("third_party_probes = false\n").unwrap();
        assert!(!cfg.third_party_probes);
        // And a Settings save writes it back rather than turning them on again.
        let saved = toml::to_string_pretty(&cfg).unwrap();
        let again: NetwatchConfig = toml::from_str(&saved).unwrap();
        assert!(!again.third_party_probes);
    }

    #[test]
    fn sandbox_field_defaults_when_missing() {
        // Pre-v0.21.5 configs don't have a `sandbox` key — they must
        // continue to load cleanly and pick up the default ("on").
        let toml_str = r#"
default_tab = "dashboard"
"#;
        let cfg: NetwatchConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.sandbox, "on");
    }

    #[test]
    fn tab_parsing() {
        let mut cfg = NetwatchConfig::default();
        assert_eq!(cfg.tab(), Tab::Dashboard);

        cfg.default_tab = "Connections".into();
        assert_eq!(cfg.tab(), Tab::Connections);

        cfg.default_tab = "PACKETS".into();
        assert_eq!(cfg.tab(), Tab::Packets);

        cfg.default_tab = "nonsense".into();
        assert_eq!(cfg.tab(), Tab::Dashboard);
    }

    #[test]
    fn timeline_window_parsing() {
        let mut cfg = NetwatchConfig::default();
        assert_eq!(cfg.timeline_window_enum(), TimelineWindow::Min5);

        cfg.timeline_window = "1m".into();
        assert_eq!(cfg.timeline_window_enum(), TimelineWindow::Min1);

        cfg.timeline_window = "1h".into();
        assert_eq!(cfg.timeline_window_enum(), TimelineWindow::Hour1);

        cfg.timeline_window = "bad".into();
        assert_eq!(cfg.timeline_window_enum(), TimelineWindow::Min5);
    }

    #[test]
    fn empty_toml_gives_defaults() {
        let cfg: NetwatchConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.default_tab, "dashboard");
        assert_eq!(cfg.refresh_rate_ms, 1000);
        assert!(cfg.show_geo);
    }

    #[test]
    fn alerts_section_partial() {
        let toml_str = r#"
[alerts]
bandwidth_threshold = 50000000
"#;
        let cfg: NetwatchConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.alerts.bandwidth_threshold, 50_000_000);
        assert_eq!(cfg.alerts.port_scan_threshold, 20); // default
        assert_eq!(cfg.alerts.port_scan_window_secs, 30); // default
    }

    #[test]
    fn diagnose_thresholds_parse_from_toml_and_default_when_absent() {
        use crate::diagnose::detectors::Thresholds;
        let cfg: NetwatchConfig = toml::from_str(
            r#"
[diagnose_thresholds]
dns_ceiling_ms = 30
consecutive_n = 5
"#,
        )
        .unwrap();
        // A whole number is read as a float, and the keys left out keep
        // their defaults.
        assert_eq!(
            cfg.diagnose_thresholds,
            Thresholds {
                dns_ceiling_ms: 30.0,
                consecutive_n: 5,
                ..Thresholds::default()
            }
        );

        let cfg: NetwatchConfig = toml::from_str("default_tab = \"diagnose\"").unwrap();
        assert_eq!(cfg.diagnose_thresholds, Thresholds::default());

        // A save leaves the table out while it holds the defaults, so a
        // later retune still reaches this file, and keeps it once changed.
        let saved = toml::to_string_pretty(&NetwatchConfig::default()).unwrap();
        assert!(!saved.contains("diagnose_thresholds"), "{saved}");
        let saved = toml::to_string_pretty(&NetwatchConfig {
            diagnose_thresholds: Thresholds {
                sigma_k: 4.0,
                ..Thresholds::default()
            },
            ..Default::default()
        })
        .unwrap();
        let back: NetwatchConfig = toml::from_str(&saved).unwrap();
        assert_eq!(back.diagnose_thresholds.sigma_k, 4.0);
    }

    /// DIAGNOSE.md lists the table with every default, so a threshold added
    /// or retuned without the doc fails here.
    #[test]
    fn the_documented_thresholds_are_the_defaults() {
        // A Windows checkout rewrites the doc to CRLF, and the search below
        // spans a line break.
        let doc = include_str!("../docs/DIAGNOSE.md").replace("\r\n", "\n");
        let start = doc
            .find("```toml\n[diagnose_thresholds]\n")
            .expect("DIAGNOSE.md shows the thresholds table")
            + "```toml\n".len();
        let block = &doc[start..][..doc[start..].find("```").unwrap()];
        let documented: toml::Table = toml::from_str(block).unwrap();
        assert_eq!(
            documented["diagnose_thresholds"],
            toml::Value::try_from(crate::diagnose::detectors::Thresholds::default()).unwrap()
        );
    }

    #[test]
    fn config_path_exists() {
        // Just verify it returns Some on normal systems
        let path = NetwatchConfig::path();
        assert!(path.is_some());
        let p = path.unwrap();
        assert!(p.to_string_lossy().contains("netwatch"));
        assert!(p.to_string_lossy().ends_with("config.toml"));
    }

    #[test]
    fn save_and_load_tempdir() {
        // Test save/load with a temp file
        let dir = std::env::temp_dir().join("netwatch_test_config");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");

        let cfg = NetwatchConfig {
            default_tab: "stats".into(),
            refresh_rate_ms: 750,
            ..Default::default()
        };
        let contents = toml::to_string_pretty(&cfg).unwrap();
        fs::write(&path, &contents).unwrap();

        let loaded: NetwatchConfig = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.default_tab, "stats");
        assert_eq!(loaded.refresh_rate_ms, 750);
        assert!(loaded.show_geo); // default

        let _ = fs::remove_dir_all(&dir);
    }

    /// A directory of its own for one test, so tests running in parallel
    /// never share a config file and none of them sets an env var.
    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "netwatch_config_{name}_{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn load_from_a_missing_file_gives_the_defaults() {
        let dir = scratch("missing");
        let cfg = NetwatchConfig::load_from(&dir.join("config.toml")).unwrap();
        assert_eq!(cfg.sandbox, "on");
        assert!(cfg.record_uptime);
        // Nor does a missing parent directory make it an error.
        NetwatchConfig::load_from(&dir.join("absent/config.toml")).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_a_partial_file_keeps_the_other_defaults() {
        let dir = scratch("partial");
        let path = dir.join("config.toml");
        fs::write(&path, "sandbox = 'strict'\nrefresh_rate_ms = 50\n").unwrap();
        let cfg = NetwatchConfig::load_from(&path).unwrap();
        assert_eq!(cfg.sandbox, "strict");
        // Clamped by `validate`, as before.
        assert_eq!(cfg.refresh_rate_ms, 100);
        assert!(cfg.record_uptime);
        assert_eq!(cfg.default_tab, "dashboard");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_invalid_toml_names_the_path_line_and_column() {
        let dir = scratch("syntax");
        let path = dir.join("config.toml");
        fs::write(&path, "sandbox = 'strict'\nshow_geo = tru\n").unwrap();
        let err = NetwatchConfig::load_from(&path).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Parse {
                    position: Some((2, 12)),
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(err.path(), path);
        let message = err.to_string();
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(message.contains("line 2, column 12"), "{message}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// The case the review reproduced: one value of the wrong type used to
    /// discard the whole file, so a strict sandbox came up best-effort and
    /// uptime recording came back on.
    #[test]
    fn load_from_a_wrong_type_is_an_error_not_the_defaults() {
        let dir = scratch("wrong_type");
        let path = dir.join("config.toml");
        fs::write(
            &path,
            "sandbox = 'strict'\nrecord_uptime = false\nrefresh_rate_ms = 'oops'\n",
        )
        .unwrap();
        let err = NetwatchConfig::load_from(&path).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Parse {
                    position: Some((3, 19)),
                    ..
                }
            ),
            "{err:?}"
        );
        let message = err.to_string();
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(message.contains("refresh_rate_ms"), "{message}");
        assert!(message.contains("expected u64"), "{message}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_from_an_unreadable_file_is_an_error() {
        let dir = scratch("unreadable");
        // A directory where the file should be is unreadable on every
        // platform, root included, where a mode of 000 is not.
        let path = dir.join("config.toml");
        fs::create_dir(&path).unwrap();
        let err = NetwatchConfig::load_from(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }), "{err:?}");
        assert!(
            err.to_string()
                .starts_with(&format!("cannot read {}: ", path.display())),
            "{err}"
        );

        let path = dir.join("latin1.toml");
        fs::write(&path, b"theme = \"caf\xe9\"\n").unwrap();
        let err = NetwatchConfig::load_from(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }), "{err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A dotfiles manager's link to a file that has gone is a config the user
    /// meant to have, not a missing one.
    #[cfg(unix)]
    #[test]
    fn load_from_a_dangling_symlink_is_an_error() {
        let dir = scratch("dangling");
        let path = dir.join("config.toml");
        std::os::unix::fs::symlink(dir.join("gone.toml"), &path).unwrap();
        let err = NetwatchConfig::load_from(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }), "{err:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_to_leaves_a_file_that_does_not_load_alone() {
        let dir = scratch("save");
        let path = dir.join("netwatch/config.toml");
        let mut cfg = NetwatchConfig {
            theme: "nord".into(),
            ..Default::default()
        };

        // No file yet: written, parent directory included.
        cfg.save_to(&path).unwrap();
        assert_eq!(NetwatchConfig::load_from(&path).unwrap().theme, "nord");

        // A valid file takes the change.
        fs::write(&path, "theme = 'ocean'\n").unwrap();
        cfg.theme = "dracula".into();
        cfg.save_to(&path).unwrap();
        assert_eq!(NetwatchConfig::load_from(&path).unwrap().theme, "dracula");

        // One that does not load is not touched.
        let broken = "sandbox = 'strict'\nrefresh_rate_ms = 'oops'\n";
        fs::write(&path, broken).unwrap();
        let err = NetwatchConfig::default().save_to(&path).unwrap_err();
        assert!(err.to_string().contains("not overwriting"), "{err:#}");
        assert!(format!("{err:#}").contains("refresh_rate_ms"), "{err:#}");
        assert_eq!(fs::read_to_string(&path).unwrap(), broken);
        let _ = fs::remove_dir_all(&dir);
    }
}
