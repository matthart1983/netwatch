use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use toml_edit::{DocumentMut, Item, Table, TableLike, Value};

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
    /// Saved only once it differs from the defaults. `--generate-config` and
    /// the Settings editor write the whole config, and a table of today's
    /// defaults in the file would hold them there when a release retunes one.
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

/// A config file as read: its text, with any renamed keys moved, the config it
/// holds, and the keys that were not read.
struct ParsedConfig {
    text: String,
    config: NetwatchConfig,
    unread: Vec<KeyPath>,
}

/// Bring `old`, a table as the file has it, up to `new`, what the config would
/// write. Comments and layout stay, and so does a value that has not changed,
/// however it is spelled. What netwatch read but does not write back goes: a
/// removed key such as `geoip_online`, a table back at its defaults. A key it
/// did not read stays, because it may belong to another version or be a typo
/// the user has yet to fix. `keep` lists those, and `at` is where `old` is.
fn merge_table(old: &mut dyn TableLike, new: &Table, at: &mut KeyPath, keep: &[KeyPath]) {
    let gone: Vec<String> = old
        .iter()
        .map(|(key, _)| key.to_owned())
        .filter(|key| !new.contains_key(key))
        .collect();
    for key in gone {
        at.push(key.clone());
        // A key not read, or inside a table not read, is left exactly as it is.
        if !keep.iter().any(|kept| at.starts_with(kept)) {
            if keep.iter().any(|kept| kept.starts_with(at)) {
                if let Some(table) = old.get_mut(&key).and_then(Item::as_table_like_mut) {
                    merge_table(table, &Table::new(), at, keep);
                }
            } else {
                old.remove(&key);
            }
        }
        at.pop();
    }
    for (key, item) in new.iter() {
        at.push(key.to_owned());
        let merged = old
            .get_mut(key)
            .is_some_and(|current| merge_item(current, item, at, keep));
        if !merged {
            // New to the file, or now a different kind of thing, such as the
            // `diagnose_targets = []` of a reset. The key goes too, as a table's
            // has none of the spacing a value's needs.
            old.remove(key);
            old.insert(key, without_positions(item));
        }
        at.pop();
    }
}

/// Whether `new` could be written into `current` where it is.
fn merge_item(current: &mut Item, new: &Item, at: &mut KeyPath, keep: &[KeyPath]) -> bool {
    match new {
        Item::Table(new) => match current.as_table_like_mut() {
            Some(table) => merge_table(table, new, at, keep),
            None => return false,
        },
        // An entry at a time while there are as many as the file has. Only a
        // reset or a hand edit changes the number.
        Item::ArrayOfTables(new) => {
            let Some(tables) = tables_in(current).filter(|tables| tables.len() == new.len()) else {
                return false;
            };
            for (index, (table, new)) in tables.into_iter().zip(new.iter()).enumerate() {
                at.push(index.to_string());
                merge_table(table, new, at, keep);
                at.pop();
            }
        }
        Item::Value(new) => {
            let Item::Value(value) = current else {
                return false;
            };
            if !same_value(value, new) {
                let decor = value.decor().clone();
                *value = new.clone();
                *value.decor_mut() = decor;
            }
        }
        Item::None => return false,
    }
    true
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

fn same_value(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(a), Value::String(b)) => a.value() == b.value(),
        (Value::Integer(a), Value::Integer(b)) => a.value() == b.value(),
        (Value::Float(a), Value::Float(b)) => a.value() == b.value(),
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
        parsed.config.validate();
        Ok(Some(parsed))
    }

    /// `text`, the contents of `file`, with [`load_warnings`](Self::load_warnings)
    /// filled in. Not validated: that is for what a session will run on.
    pub fn from_toml(text: &str, file: &Path) -> Result<Self, toml::de::Error> {
        Self::parse(text, file, RENAMED_KEYS).map(|parsed| parsed.config)
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
            unread,
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

    /// Write current config to disk, creating parent directories as needed.
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

    /// [`save`](Self::save) to `path`. A file already there that does not
    /// load is left alone, by Settings and `--generate-config` alike: it holds
    /// settings nothing has read, such as a hand edit made while netwatch ran.
    ///
    /// One that does load is edited in place, not replaced, so a key this
    /// version does not read, from a newer one or misspelled, is still there
    /// and still warned about afterwards. So are the file's comments. A renamed
    /// key moves to its new name, and is not written under both.
    pub fn save_to(&self, path: &Path) -> anyhow::Result<()> {
        let existing = Self::read_file(path).map_err(|e| {
            let context = format!("{} does not load; not overwriting it", path.display());
            anyhow::Error::new(e).context(context)
        })?;
        let contents = match existing {
            Some(parsed) => self.merged_into(&parsed.text, &parsed.unread)?,
            None => toml::to_string_pretty(self)?,
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)?;
        Ok(())
    }

    /// `text` with this config's values in it and the keys in `unread` left
    /// alone. Refuses a result that does not read back as this config, because
    /// the file it would replace does.
    fn merged_into(&self, text: &str, unread: &[KeyPath]) -> anyhow::Result<String> {
        let wanted = toml::to_string_pretty(self)?;
        let new: DocumentMut = wanted.parse()?;
        let mut doc: DocumentMut = text.parse()?;
        // The table stays even with nothing in it this version reads, or nothing
        // in it at all: the comment above a setting someone switched off.
        let mut keep = unread.to_vec();
        keep.push(vec![EXPERIMENTAL_TABLE.to_owned()]);
        merge_table(
            doc.as_table_mut(),
            new.as_table(),
            &mut KeyPath::new(),
            &keep,
        );
        let merged = doc.to_string();
        let back: Self = toml::from_str(&merged)?;
        anyhow::ensure!(
            toml::to_string_pretty(&back)? == wanted,
            "cannot update it in place; not overwriting it"
        );
        Ok(merged)
    }
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
            let cfg = NetwatchConfig::load_from(&path).unwrap();
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
        let parsed = parse_renamed(
            "# mine\ncolour_theme = 'nord' # why\n[alerts]\nbandwidth_limit = 5\ntypo = 1\n",
            RENAMES,
        );
        let saved = parsed
            .config
            .merged_into(&parsed.text, &parsed.unread)
            .unwrap();
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
            again
                .config
                .merged_into(&again.text, &again.unread)
                .unwrap(),
            saved
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
        let cfg = NetwatchConfig::load_from(&path).unwrap();
        assert_eq!(unknown_keys(&cfg), ["typo"]);
        let quiet: Vec<_> = cfg.load_warnings.iter().filter(|w| w.is_quiet()).collect();
        assert_eq!(quiet.len(), 2, "{:?}", cfg.load_warnings);
        assert!(quiet[0]
            .to_string()
            .contains("experimental.future_thing is not used"));

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
        let cfg = NetwatchConfig::load_from(&path).unwrap();
        assert_eq!(cfg.load_warnings, []);
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

    /// What a save did to these until 0.40: rewrote the file from the struct,
    /// so a key netwatch does not read was gone with no word, and with it the
    /// warning about it. A key from a newer version went the same way.
    #[test]
    fn a_save_keeps_unknown_keys_and_comments_and_changes_what_changed() {
        let dir = scratch("save_unknown");
        let path = dir.join("config.toml");
        fs::write(
            &path,
            r#"# my settings
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
"#,
        )
        .unwrap();

        let mut cfg = NetwatchConfig::load_from(&path).unwrap();
        cfg.theme = "ocean".into();
        cfg.diagnose_targets[0].enabled = false;
        cfg.save_to(&path).unwrap();
        let saved = fs::read_to_string(&path).unwrap();
        for kept in [
            "# my settings\n",
            "sandbox_mode = \"strict\"  # typo, fix me\n",
            "refresh_rate_ms = 1_000\n",
            "# watch the uplink\n",
            "bandwidth_threshold = 1_000\n",
            "bandwidth_thresold = 5\n",
            "# the api\n",
            "from_a_newer_version = { a = 1 }\n",
            "[stray]\nanything = \"goes\"\n",
            // A changed value keeps its line's comment.
            "theme = \"ocean\" # the good one\n",
        ] {
            assert!(saved.contains(kept), "{kept:?} not in\n{saved}");
        }

        let back = NetwatchConfig::load_from(&path).unwrap();
        assert_eq!(back.theme, "ocean");
        assert!(!back.diagnose_targets[0].enabled);
        assert_eq!(cfg.load_warnings, back.load_warnings, "\n{saved}");

        // Again, unchanged: nothing is written twice or moves.
        back.save_to(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), saved);
        let _ = fs::remove_dir_all(&dir);
    }

    /// The other ways TOML writes a table. An unknown key in each stays.
    #[test]
    fn a_save_keeps_unknown_keys_in_inline_and_dotted_tables() {
        let dir = scratch("save_forms");
        let path = dir.join("config.toml");
        fs::write(
            &path,
            "alerts = { bandwidth_threshold = 5, typo = 1 }\n\
             diagnose_probes.trace_target = \"9.9.9.9\"\n\
             diagnose_probes.typo = 2\n\
             diagnose_targets = [{ name = \"api\", host = \"a.example\", typo = 3 }]\n",
        )
        .unwrap();
        let mut cfg = NetwatchConfig::load_from(&path).unwrap();
        let unknown = cfg.load_warnings.clone();
        assert_eq!(unknown.len(), 3);
        cfg.alerts.bandwidth_threshold = 6;
        cfg.diagnose_probes.trace_target = "8.8.8.8".into();
        cfg.diagnose_targets[0].port = 8443;
        cfg.save_to(&path).unwrap();

        let saved = fs::read_to_string(&path).unwrap();
        let back = NetwatchConfig::load_from(&path).unwrap();
        assert_eq!(back.load_warnings, unknown, "\n{saved}");
        assert_eq!(back.alerts.bandwidth_threshold, 6, "\n{saved}");
        assert_eq!(back.alerts.port_scan_threshold, 20, "\n{saved}");
        assert_eq!(back.diagnose_probes.trace_target, "8.8.8.8", "\n{saved}");
        assert_eq!(back.diagnose_targets[0].port, 8443, "\n{saved}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Tables new to the file go after what is there, a table's own entries after
    /// it, and the user's stay in their order, wherever the new ones came from.
    #[test]
    fn a_save_adds_tables_after_the_ones_the_file_has() {
        let dir = scratch("save_tables");
        let path = dir.join("config.toml");
        fs::write(
            &path,
            "[stray_1]\na = 1\n[stray_2]\na = 1\n[stray_3]\na = 1\n[stray_4]\na = 1\n\
             [stray_5]\na = 1\n[diagnose_probes]\ntrace_target = \"9.9.9.9\"\n",
        )
        .unwrap();
        let cfg = NetwatchConfig::load_from(&path).unwrap();
        cfg.save_to(&path).unwrap();
        let saved = fs::read_to_string(&path).unwrap();
        let at = |needle: &str| {
            saved
                .find(needle)
                .unwrap_or_else(|| panic!("{needle} not in\n{saved}"))
        };
        assert!(at("[stray_1]") < at("[stray_5]"), "{saved}");
        assert!(at("[stray_5]") < at("[diagnose_probes]"), "{saved}");
        assert!(
            at("[diagnose_probes]") < at("[[diagnose_probes.ipv6_pairs]]"),
            "{saved}"
        );
        assert!(at("[stray_5]") < at("[alerts]"), "{saved}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// The check at the end of a save: a merge that would change what the file
    /// means is refused, and the file stays. Nothing a user can do should reach
    /// this, so it takes a list of keys to keep that names a key netwatch reads:
    /// the table should go, as it holds what a default config does not.
    #[test]
    fn a_merge_that_does_not_read_back_is_refused() {
        let text = "[diagnose_thresholds]\nsigma_k = 9.0\n";
        let keep = [vec!["diagnose_thresholds".to_owned()]];
        let err = NetwatchConfig::default()
            .merged_into(text, &keep)
            .unwrap_err();
        assert!(
            err.to_string().contains("cannot update it in place"),
            "{err}"
        );
        assert!(NetwatchConfig::default().merged_into(text, &[]).is_ok());
    }

    /// `--generate-config` resets what netwatch reads. It cannot reset what it
    /// does not, and a list it empties takes the entries' own keys with it.
    #[test]
    fn a_reset_sets_known_keys_to_their_defaults_and_keeps_the_rest() {
        let dir = scratch("save_reset");
        let path = dir.join("config.toml");
        fs::write(
            &path,
            r#"# mine
sandbox = "strict"
typo = 1
[[diagnose_targets]]
name = "api"
host = "a.example"
intervl = 5
[diagnose_thresholds]
sigma_k = 9.0
sigmak = 9.0
"#,
        )
        .unwrap();
        NetwatchConfig::default().save_to(&path).unwrap();
        let saved = fs::read_to_string(&path).unwrap();
        assert!(saved.contains("# mine\n"), "{saved}");
        assert!(saved.contains("sandbox = \"on\"\n"), "{saved}");
        assert!(saved.contains("diagnose_targets = []\n"), "{saved}");
        // The table holds its defaults again, so only what was not read is left.
        assert!(
            saved.contains("[diagnose_thresholds]\nsigmak = 9.0\n"),
            "{saved}"
        );
        let back = NetwatchConfig::load_from(&path).unwrap();
        assert_eq!(back.sandbox, "on");
        assert_eq!(back.diagnose_targets, []);
        assert_eq!(back.diagnose_thresholds, Default::default());
        let mut keys = unknown_keys(&back);
        keys.sort();
        assert_eq!(keys, ["diagnose_thresholds.sigmak", "typo"]);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A first save has nothing to keep, and an empty file should end up the
    /// same as no file. A file with Windows line endings stays loadable.
    #[test]
    fn a_save_over_nothing_lays_the_file_out_as_generated() {
        let dir = scratch("save_layout");
        let path = dir.join("config.toml");
        let cfg = NetwatchConfig::default();
        cfg.save_to(&path).unwrap();
        let fresh = fs::read_to_string(&path).unwrap();
        assert_eq!(fresh, toml::to_string_pretty(&cfg).unwrap());
        cfg.save_to(&path).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            fresh,
            "a save of itself"
        );
        fs::write(&path, "").unwrap();
        cfg.save_to(&path).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            fresh,
            "over an empty file"
        );

        fs::write(&path, "# mine\r\ntypo = 1\r\ntheme = \"nord\"\r\n").unwrap();
        cfg.save_to(&path).unwrap();
        let back = NetwatchConfig::load_from(&path).unwrap();
        assert_eq!(back.theme, "dark");
        assert_eq!(unknown_keys(&back), ["typo"]);
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
    /// way, a float losing its `.0`) would show up as a rewrite of that file
    /// on the next Settings save. This pins what toml decides about the
    /// layout rather than the list of keys, so adding a key does not fail it.
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
            "diagnose_targets = []\n",
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
        let cfg = NetwatchConfig {
            theme: "nord".into(),
            ..Default::default()
        };

        // No file yet: written, parent directory included.
        cfg.save_to(&path).unwrap();
        assert_eq!(NetwatchConfig::load_from(&path).unwrap().theme, "nord");

        // A valid file is replaced, as Settings has always done.
        fs::write(&path, "theme = 'ocean'\n").unwrap();
        cfg.save_to(&path).unwrap();
        assert_eq!(NetwatchConfig::load_from(&path).unwrap().theme, "nord");

        // One that does not load is not.
        let broken = "sandbox = 'strict'\nrefresh_rate_ms = 'oops'\n";
        fs::write(&path, broken).unwrap();
        let err = NetwatchConfig::default().save_to(&path).unwrap_err();
        assert!(err.to_string().contains("not overwriting"), "{err:#}");
        assert!(format!("{err:#}").contains("refresh_rate_ms"), "{err:#}");
        assert_eq!(fs::read_to_string(&path).unwrap(), broken);
        let _ = fs::remove_dir_all(&dir);
    }
}
