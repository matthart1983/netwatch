use crate::app::App;
use crate::collectors::geo::DbFile;
use crate::config::NetwatchConfig;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Clear, Paragraph},
};

pub const SETTINGS_COUNT: usize = ROWS.len();

/// The startup tabs Settings offers, one per tab, in tab-bar order. The
/// config also accepts `insights`, the old name for Diagnose.
pub const TAB_NAMES: &[&str] = &[
    "dashboard",
    "connections",
    "interfaces",
    "packets",
    "stats",
    "topology",
    "timeline",
    "processes",
    "diagnose",
    "egress",
];

/// Named cursor positions for each settings row.
/// Use these instead of magic integers when navigating or jumping to a setting.
/// Each one is a row's index in `ROWS`, and the build fails if one names
/// the wrong row.
pub mod cursor {
    pub const THEME: usize = 0;
    pub const VIEW: usize = 1;
    pub const DEFAULT_TAB: usize = 2;
    pub const REFRESH_RATE: usize = 3;
    pub const CAPTURE_INTERFACE: usize = 4;
    pub const SHOW_GEO: usize = 5;
    pub const TIMELINE_WINDOW: usize = 6;
    pub const PACKET_FOLLOW: usize = 7;
    pub const BPF_FILTER: usize = 8;
    pub const GEOIP_DB: usize = 9;
    pub const GEOIP_ASN_DB: usize = 10;
    pub const BANDWIDTH_THRESHOLD: usize = 11;
    pub const PORT_SCAN_THRESHOLD: usize = 12;
    pub const AI_INSIGHTS: usize = 13;
    pub const AI_MODEL: usize = 14;
    pub const AI_ENDPOINT: usize = 15;
    pub const GRAPH_STYLE: usize = 16;
    pub const GRAPH_FADE: usize = 17;
    pub const SANDBOX: usize = 18;
    pub const GROUPS_COLLAPSED: usize = 19;
    pub const CONFIRM_QUIT: usize = 20;
}

/// One row of the settings overlay.
struct Setting {
    /// The `cursor::*` constant that names this row. It must equal the row's
    /// index in [`ROWS`]; the check after the table fails the build if not.
    at: usize,
    label: &'static str,
    /// The raw value: what Enter puts in the edit box, and what `apply`
    /// takes back unchanged.
    raw: fn(&NetwatchConfig) -> String,
    /// What the row shows, where that differs from `raw`.
    show: Option<fn(&NetwatchConfig) -> String>,
    apply: fn(&mut NetwatchConfig, &str) -> Result<(), String>,
    /// Cycles through a small enum on `←` / `→` rather than being edited as
    /// free text. Rendered with `◀ value ▶` chevrons, and the footer hint
    /// reads "Cycle" instead of "Edit".
    cycles: bool,
}

impl Setting {
    fn shown(&self, cfg: &NetwatchConfig) -> String {
        self.show.unwrap_or(self.raw)(cfg)
    }
}

/// Every settings row, in the order the overlay draws them.
///
/// This is the only place the order is written down. The overlay draws these
/// rows, and Enter loads and applies an edit through them, all by the same
/// index. `get_edit_value` used to keep its own numbering, which the View row
/// shifted by one: Enter on GeoIP DB Path loaded the ASN path, and accepting
/// it saved that path as `geoip_db`.
const ROWS: &[Setting] = &[
    Setting {
        at: cursor::THEME,
        label: "Theme",
        raw: |c| c.theme.clone(),
        show: None,
        apply: |c, v| {
            let valid = crate::theme::THEME_NAMES;
            let v = v.to_lowercase();
            if !valid.contains(&v.as_str()) {
                return Err(format!("Invalid theme. Use: {}", valid.join(", ")));
            }
            c.theme = v;
            Ok(())
        },
        cycles: true,
    },
    Setting {
        at: cursor::VIEW,
        label: "View",
        raw: |c| c.view.clone(),
        show: None,
        apply: |c, v| {
            let valid = crate::app::VIEW_MODE_NAMES;
            let v = v.to_lowercase();
            if !valid.contains(&v.as_str()) {
                return Err(format!("Invalid view. Use: {}", valid.join(", ")));
            }
            c.view = v;
            Ok(())
        },
        cycles: true,
    },
    Setting {
        at: cursor::DEFAULT_TAB,
        label: "Default Tab",
        raw: |c| c.default_tab.clone(),
        show: None,
        apply: |c, v| {
            let v = v.to_lowercase();
            if !TAB_NAMES.contains(&v.as_str()) {
                return Err(format!("Invalid tab. Use: {}", TAB_NAMES.join(", ")));
            }
            c.default_tab = v;
            Ok(())
        },
        cycles: true,
    },
    Setting {
        at: cursor::REFRESH_RATE,
        label: "Refresh Rate (ms)",
        raw: |c| c.refresh_rate_ms.to_string(),
        show: None,
        apply: |c, v| {
            let ms: u64 = v.parse().map_err(|_| "Must be a number")?;
            if !(100..=5000).contains(&ms) {
                return Err("Must be 100–5000".into());
            }
            c.refresh_rate_ms = ms;
            Ok(())
        },
        cycles: false,
    },
    Setting {
        at: cursor::CAPTURE_INTERFACE,
        label: "Capture Interface",
        raw: |c| c.capture_interface.clone(),
        show: Some(|c| or_placeholder(&c.capture_interface, "(auto)")),
        apply: |c, v| {
            c.capture_interface = v.to_string();
            Ok(())
        },
        cycles: false,
    },
    Setting {
        at: cursor::SHOW_GEO,
        label: "Show GeoIP",
        raw: |c| on_off(c.show_geo),
        show: None,
        apply: |c, v| {
            c.show_geo = parse_on_off(v).ok_or("Use on/off")?;
            Ok(())
        },
        cycles: false,
    },
    Setting {
        at: cursor::TIMELINE_WINDOW,
        label: "Timeline Window",
        raw: |c| c.timeline_window.clone(),
        show: None,
        apply: |c, v| {
            let valid = ["1m", "5m", "15m", "30m", "1h"];
            if !valid.contains(&v) {
                return Err(format!("Use: {}", valid.join(", ")));
            }
            c.timeline_window = v.to_string();
            Ok(())
        },
        cycles: false,
    },
    Setting {
        at: cursor::PACKET_FOLLOW,
        label: "Packet Follow",
        raw: |c| on_off(c.packet_follow),
        show: None,
        apply: |c, v| {
            c.packet_follow = parse_on_off(v).ok_or("Use on/off")?;
            Ok(())
        },
        cycles: false,
    },
    Setting {
        at: cursor::BPF_FILTER,
        label: "BPF Filter",
        raw: |c| c.bpf_filter.clone(),
        show: Some(|c| or_placeholder(&c.bpf_filter, "(none)")),
        apply: |c, v| {
            c.bpf_filter = v.to_string();
            Ok(())
        },
        cycles: false,
    },
    Setting {
        at: cursor::GEOIP_DB,
        label: "GeoIP DB Path",
        raw: |c| c.geoip_db.clone(),
        // `draw` shows what the session opened, through `geoip_row`.
        show: None,
        apply: |c, v| {
            c.geoip_db = v.to_string();
            Ok(())
        },
        cycles: false,
    },
    Setting {
        at: cursor::GEOIP_ASN_DB,
        label: "GeoIP ASN DB Path",
        raw: |c| c.geoip_asn_db.clone(),
        // `draw` shows what the session opened, through `geoip_row`.
        show: None,
        apply: |c, v| {
            c.geoip_asn_db = v.to_string();
            Ok(())
        },
        cycles: false,
    },
    Setting {
        at: cursor::BANDWIDTH_THRESHOLD,
        label: "Bandwidth Threshold",
        raw: |c| c.alerts.bandwidth_threshold.to_string(),
        show: Some(|c| format_bandwidth(c.alerts.bandwidth_threshold)),
        apply: |c, v| {
            c.alerts.bandwidth_threshold = v.parse().map_err(|_| "Must be a number (bytes/sec)")?;
            Ok(())
        },
        cycles: false,
    },
    Setting {
        at: cursor::PORT_SCAN_THRESHOLD,
        label: "Port Scan Threshold",
        raw: |c| c.alerts.port_scan_threshold.to_string(),
        show: None,
        apply: |c, v| {
            c.alerts.port_scan_threshold = v.parse().map_err(|_| "Must be a number")?;
            Ok(())
        },
        cycles: false,
    },
    Setting {
        at: cursor::AI_INSIGHTS,
        label: "AI Insights",
        raw: |c| on_off(c.insights_enabled),
        show: None,
        apply: |c, v| {
            c.insights_enabled = parse_on_off(v).ok_or("Use on/off")?;
            Ok(())
        },
        cycles: false,
    },
    Setting {
        at: cursor::AI_MODEL,
        label: "AI Model",
        raw: |c| c.insights_model.clone(),
        show: None,
        apply: |c, v| {
            if v.is_empty() {
                return Err("Model name cannot be empty".into());
            }
            c.insights_model = v.to_string();
            Ok(())
        },
        cycles: false,
    },
    Setting {
        at: cursor::AI_ENDPOINT,
        label: "AI Endpoint",
        raw: |c| c.insights_endpoint.clone(),
        // Before the URL, like the GeoIP row, so a long one cannot push it
        // out of view.
        show: Some(|c| {
            use crate::collectors::insights::{cleartext_off_host, CLEARTEXT_OFF_HOST};
            if cleartext_off_host(&c.insights_endpoint) {
                format!("{CLEARTEXT_OFF_HOST}: {}", c.insights_endpoint)
            } else {
                c.insights_endpoint.clone()
            }
        }),
        apply: |c, v| {
            c.insights_endpoint = v.to_string();
            Ok(())
        },
        cycles: false,
    },
    Setting {
        at: cursor::GRAPH_STYLE,
        label: "Graph Style",
        raw: |c| c.graph_style.clone(),
        show: None,
        apply: |c, v| {
            let valid = crate::graph::GRAPH_STYLE_NAMES;
            let v = v.to_lowercase();
            if !valid.contains(&v.as_str()) {
                return Err(format!("Invalid graph style. Use: {}", valid.join(", ")));
            }
            c.graph_style = v;
            Ok(())
        },
        cycles: true,
    },
    Setting {
        at: cursor::GRAPH_FADE,
        label: "Graph Fade (btop)",
        raw: |c| on_off(c.graph_fade),
        show: None,
        apply: |c, v| {
            c.graph_fade = parse_on_off(v).ok_or("Use on / off")?;
            Ok(())
        },
        cycles: true,
    },
    Setting {
        at: cursor::SANDBOX,
        label: "Sandbox",
        raw: |c| c.sandbox.clone(),
        show: None,
        apply: |c, v| {
            let v = v.trim().to_ascii_lowercase();
            if !matches!(v.as_str(), "on" | "strict" | "off") {
                return Err("Use on / strict / off".into());
            }
            c.sandbox = v;
            Ok(())
        },
        cycles: true,
    },
    Setting {
        at: cursor::GROUPS_COLLAPSED,
        label: "Groups Start Folded",
        raw: |c| on_off(c.groups_start_collapsed),
        show: None,
        apply: |c, v| {
            c.groups_start_collapsed = parse_on_off(v).ok_or("Use on / off")?;
            Ok(())
        },
        cycles: true,
    },
    Setting {
        at: cursor::CONFIRM_QUIT,
        label: "Confirm Quit",
        raw: |c| on_off(c.confirm_quit),
        show: None,
        apply: |c, v| {
            c.confirm_quit = parse_on_off(v).ok_or("Use on / off")?;
            Ok(())
        },
        cycles: true,
    },
];

// The key handler names rows by `cursor::*` while the overlay draws them by
// position, so a constant that disagrees with its row fails the build.
const _: () = {
    let mut i = 0;
    while i < ROWS.len() {
        assert!(ROWS[i].at == i, "a cursor:: constant names the wrong row");
        i += 1;
    }
};

fn on_off(on: bool) -> String {
    if on { "on" } else { "off" }.into()
}

fn parse_on_off(value: &str) -> Option<bool> {
    match value.to_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Some(true),
        "off" | "false" | "no" | "0" => Some(false),
        _ => None,
    }
}

fn or_placeholder(value: &str, placeholder: &str) -> String {
    if value.is_empty() {
        placeholder.into()
    } else {
        value.to_string()
    }
}

/// Rows whose value cycles through a small enum on `←` / `→` rather than
/// being edited as free text.
fn is_cycle_through(cursor: usize) -> bool {
    ROWS.get(cursor).is_some_and(|row| row.cycles)
}

fn format_bandwidth(bytes: u64) -> String {
    if bytes == 0 {
        "disabled".into()
    } else if bytes >= 1_000_000_000 {
        format!("{} GB/s", bytes / 1_000_000_000)
    } else if bytes >= 1_000_000 {
        format!("{} MB/s", bytes / 1_000_000)
    } else if bytes >= 1_000 {
        format!("{} KB/s", bytes / 1_000)
    } else {
        format!("{} B/s", bytes)
    }
}

/// One row of the sandbox detail in the popup.
struct SandboxRow {
    indent: usize,
    text: String,
    /// From the clause saying a root session's containment is limited.
    root: bool,
}

/// The sandbox capability's detail as rows no wider than `inner`, because the popup
/// does not wrap. The first clause stays in the settings' value column, `value`
/// from the left, and the others take the whole width, because what a worker got
/// or a root session lacks has to show in a narrow terminal too.
fn sandbox_rows(detail: &str, inner: usize, value: usize) -> Vec<SandboxRow> {
    let mut rows = Vec::new();
    for (at, clause) in detail.split(" · ").enumerate() {
        let (first, rest) = if at == 0 { (value, value) } else { (2, 4) };
        let wrapped = wrap_words(
            clause,
            inner.saturating_sub(first),
            inner.saturating_sub(rest),
        );
        for (line, text) in wrapped.into_iter().enumerate() {
            rows.push(SandboxRow {
                indent: if line == 0 { first } else { rest },
                text,
                root: clause.starts_with("running as root"),
            });
        }
    }
    rows
}

/// `text` broken at spaces into rows, the first `first` columns wide and the rest
/// `rest`. A word too long for a row is cut between graphemes. The widths have a
/// floor, so that a terminal narrower than the popup's own minimum still makes
/// progress, though the popup cuts those rows off.
fn wrap_words(text: &str, first: usize, rest: usize) -> Vec<String> {
    use crate::ui::text;
    const FLOOR: usize = 8;
    let rest = rest.max(FLOOR);
    let mut limit = first.max(FLOOR);
    let mut rows = Vec::new();
    let mut row = String::new();
    for mut word in text.split_whitespace() {
        loop {
            let gap = usize::from(!row.is_empty());
            if text::width(&row) + gap + text::width(word) <= limit {
                if gap == 1 {
                    row.push(' ');
                }
                row.push_str(word);
                break;
            }
            if !row.is_empty() {
                rows.push(std::mem::take(&mut row));
            } else {
                // Alone on a row and still too long. A wide grapheme can leave
                // nothing that fits, and it has to go somewhere.
                let head = match text::prefix(word, limit) {
                    "" => word.chars().next().map_or("", |c| &word[..c.len_utf8()]),
                    head => head,
                };
                rows.push(head.to_string());
                word = &word[head.len()..];
                if word.is_empty() {
                    limit = rest;
                    break;
                }
            }
            limit = rest;
        }
    }
    if !row.is_empty() || rows.is_empty() {
        rows.push(row);
    }
    rows
}

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let attribution = app.geo_cache.db_status().attribution();
    // Wide enough for the attribution on one row, with its indent and borders.
    let popup_width = (area.width * 60 / 100)
        .max(attribution.map_or(50, |line| line.len() as u16 + 4))
        .min(area.width.saturating_sub(4));
    let label_width = 22;
    // Sandbox enforcement state — read-only info rows. Surfaces whether
    // Landlock / cap-drop / Seatbelt actually applied so users can
    // confirm enforcement at runtime rather than trusting the README.
    let capabilities = crate::runtime::capabilities::CapabilitySnapshot::live(app);
    let inner_width = popup_width.saturating_sub(2) as usize;
    let sandbox_detail = sandbox_rows(
        &capabilities.get("sandbox").detail,
        inner_width,
        label_width + 4,
    );
    // Up to three workers that warned, the capability line, the connection table
    // when it is not read from `ss`, and what the config files got wrong.
    let mut notes: Vec<String> = crate::sandbox::worker::snapshot()
        .iter()
        .filter(|(_, s)| {
            s.error.is_some()
                || s.report
                    .as_ref()
                    .is_some_and(|r| !r.mode.warnings.is_empty())
        })
        .take(3)
        .map(|(name, state)| {
            let reason = state
                .error
                .clone()
                .unwrap_or_else(|| state.report.as_ref().unwrap().mode.warnings.join("; "));
            format!("{name}: {reason}")
        })
        .collect();
    notes.push(capabilities.compact());
    notes.extend(capabilities.connection_table_line());
    notes.extend(app.config_warnings().map(|warning| warning.short()));
    let note_rows: Vec<(usize, String)> = notes
        .iter()
        .flat_map(|note| {
            wrap_words(
                note,
                inner_width.saturating_sub(2),
                inner_width.saturating_sub(4),
            )
            .into_iter()
            .enumerate()
            .map(|(line, text)| (if line == 0 { 2 } else { 4 }, text))
        })
        .collect();
    // +9 holds the rest beside the settings, with one to spare: the attribution,
    // a blank, the doctor hint, a blank, the status row, the footer and two borders.
    let popup_height = (SETTINGS_COUNT + 9 + sandbox_detail.len() + note_rows.len()) as u16;
    let popup_height = popup_height.min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(popup_width)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_height)) / 2;
    let popup = Rect::new(x, y, popup_width, popup_height);

    f.render_widget(Clear, popup);
    crate::ui::widgets::paint_overlay_bg(f, &app.theme, popup);

    let title = if let Some(ref path) = NetwatchConfig::path() {
        format!(" Settings — {} ", path.display())
    } else {
        " Settings ".to_string()
    };

    let block = widgets::panel_block(&app.theme)
        .title(title)
        .border_style(Style::default().fg(app.theme.brand));
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    let cfg = &app.user_config;

    let mut lines: Vec<Line> = Vec::new();

    for (i, row) in ROWS.iter().enumerate() {
        let is_selected = i == app.ui.settings_cursor;
        let is_editing = is_selected && app.ui.settings_editing;

        let indicator = if is_selected { "▸ " } else { "  " };
        let label_style = if is_selected {
            Style::default().fg(app.theme.active_tab).bold()
        } else {
            Style::default().fg(app.theme.brand)
        };

        let value_display = if is_editing {
            format!("{}▏", app.ui.settings_edit_buf)
        } else if is_selected && row.cycles {
            format!("◀ {} ▶", row.shown(cfg))
        } else if i == cursor::GEOIP_DB {
            let (wanted, _) = cfg.geoip_paths();
            geoip_row(&wanted, &app.geo_cache.db_status().city)
        } else if i == cursor::GEOIP_ASN_DB {
            let (_, wanted) = cfg.geoip_paths();
            geoip_row(&wanted, &app.geo_cache.db_status().asn)
        } else {
            row.shown(cfg)
        };

        let value_style = if is_editing {
            Style::default()
                .fg(app.theme.text_primary)
                .bg(app.theme.selection_bg)
        } else if is_selected {
            Style::default().fg(app.theme.text_primary)
        } else {
            Style::default().fg(app.theme.text_muted)
        };

        lines.push(Line::from(vec![
            Span::styled(indicator.to_string(), label_style),
            Span::styled(
                format!("{:<width$}", row.label, width = label_width),
                label_style,
            ),
            Span::styled(value_display, value_style),
        ]));

        // Under the GeoIP rows, so a short terminal cuts it off last. A terminal
        // too narrow for the popup to hold it gets it on two rows.
        if let (cursor::GEOIP_ASN_DB, Some(line)) = (i, attribution) {
            let parts: Vec<&str> = if line.len() + 2 <= inner.width as usize {
                vec![line]
            } else {
                line.split_inclusive(", ").collect()
            };
            for part in parts {
                lines.push(Line::from(Span::styled(
                    format!("  {}", part.trim_end()),
                    Style::default().fg(app.theme.text_muted),
                )));
            }
        }
    }

    lines.push(Line::raw(""));
    let sandbox_color =
        if capabilities.get("sandbox").state == crate::runtime::capabilities::State::Ready {
            app.theme.status_good
        } else {
            app.theme.text_muted
        };
    for (at, row) in sandbox_detail.into_iter().enumerate() {
        let lead = if at == 0 {
            Span::styled(
                format!("  {:<width$}", "Sandbox", width = label_width + 2),
                Style::default().fg(app.theme.brand),
            )
        } else {
            Span::raw(" ".repeat(row.indent))
        };
        let color = if row.root {
            app.theme.status_warn
        } else {
            sandbox_color
        };
        lines.push(Line::from(vec![
            lead,
            Span::styled(row.text, Style::default().fg(color)),
        ]));
    }

    for (indent, text) in note_rows {
        lines.push(Line::raw(format!("{}{text}", " ".repeat(indent))));
    }
    lines.push(Line::raw("  Setup details: netwatch doctor --json"));

    // Status message
    lines.push(Line::raw(""));
    if let Some(ref status) = app.ui.settings_status {
        lines.push(Line::from(Span::styled(
            format!("  {}", status),
            Style::default().fg(app.theme.status_good),
        )));
    } else if app.ui.settings_cursor == cursor::SANDBOX {
        // Sandbox changes don't reapply at runtime — Landlock can't be
        // undone and dropped caps can't be regained. Surface that to the
        // user inline so they don't expect the live process to react.
        lines.push(Line::from(Span::styled(
            "  Applies on next netwatch start.",
            Style::default().fg(app.theme.text_muted),
        )));
    } else if matches!(
        app.ui.settings_cursor,
        cursor::AI_INSIGHTS | cursor::AI_MODEL | cursor::AI_ENDPOINT
    ) {
        lines.push(Line::from(Span::styled(
            "  Experimental: can change in any release.",
            Style::default().fg(app.theme.text_muted),
        )));
    } else {
        lines.push(Line::raw(""));
    }

    let content_height = inner.height.saturating_sub(1);
    let content = Paragraph::new(lines);
    f.render_widget(
        content,
        Rect::new(inner.x, inner.y, inner.width, content_height),
    );

    // Footer
    let footer_spans = if app.ui.settings_editing {
        vec![
            Span::styled("Enter", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Apply  "),
            Span::styled("Esc", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Cancel"),
        ]
    } else if is_cycle_through(app.ui.settings_cursor) {
        vec![
            Span::styled("←→", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Cycle  "),
            Span::styled("↑↓", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Navigate  "),
            Span::styled("S", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Save  "),
            Span::styled("Esc", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Close"),
        ]
    } else {
        vec![
            Span::styled("↑↓", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Navigate  "),
            Span::styled("Enter", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Edit  "),
            Span::styled("S", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Save  "),
            Span::styled("Esc", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Close"),
        ]
    };
    let footer = Paragraph::new(Line::from(footer_spans)).alignment(Alignment::Center);
    let footer_area = Rect::new(
        inner.x,
        inner.y + inner.height.saturating_sub(1),
        inner.width,
        1,
    );
    f.render_widget(footer, footer_area);
}

/// A GeoIP row's text: the database this session opened, type first so a long
/// path cannot push it out of view. Databases open once, so a path changed
/// since, or a download made since, is named as waiting for the next start.
fn geoip_row(wanted: &str, opened: &DbFile) -> String {
    let held = match opened {
        DbFile::NotConfigured => "",
        DbFile::Loaded { path, .. } | DbFile::Unreadable { path, .. } => path,
    };
    if wanted != held {
        return format!("{} on next start", or_placeholder(wanted, "(none)"));
    }
    match opened {
        DbFile::NotConfigured => "(none): run netwatch geoip update".into(),
        DbFile::Unreadable { path, .. } => format!("unreadable: {path}"),
        DbFile::Loaded {
            path,
            database_type,
            ..
        } => format!("{database_type}: {path}"),
    }
}

/// Returns the raw config value for the setting at `cursor` position,
/// suitable for pre-filling the edit buffer.
pub fn get_edit_value(cfg: &NetwatchConfig, cursor: usize) -> String {
    ROWS.get(cursor)
        .map(|row| (row.raw)(cfg))
        .unwrap_or_default()
}

/// Apply an edited value to the setting at `cursor`. Returns an error
/// message if the value is invalid.
pub fn apply_edit(cfg: &mut NetwatchConfig, cursor: usize, value: &str) -> Result<(), String> {
    let row = ROWS.get(cursor).ok_or("Unknown setting")?;
    (row.apply)(cfg, value)
}

/// A config for testing that Enter reaches the right field, shared with the
/// key-handler test in `app.rs`.
#[cfg(test)]
pub(crate) mod fixture {
    use super::cursor;
    use crate::config::{AlertConfig, NetwatchConfig};

    /// A config in which no settings row holds the value of the row either
    /// side of it, so a row that reads or writes its neighbour's field shows.
    /// Every row but AI Insights is off its default. That one stays off,
    /// because turning it on through the key handler starts the insights
    /// worker.
    pub(crate) fn config() -> NetwatchConfig {
        NetwatchConfig {
            theme: "nord".into(),
            view: "dense".into(),
            default_tab: "packets".into(),
            refresh_rate_ms: 250,
            capture_interface: "wlan7".into(),
            show_geo: false,
            timeline_window: "15m".into(),
            packet_follow: false,
            bpf_filter: "udp port 53".into(),
            geoip_db: "/geo/city.mmdb".into(),
            geoip_asn_db: "/geo/asn.mmdb".into(),
            alerts: AlertConfig {
                bandwidth_threshold: 42_000_000,
                port_scan_threshold: 37,
                ..Default::default()
            },
            insights_enabled: false,
            insights_model: "qwen-test".into(),
            insights_endpoint: "http://127.0.0.1:1".into(),
            graph_style: "bars".into(),
            graph_fade: false,
            sandbox: "strict".into(),
            groups_start_collapsed: false,
            confirm_quit: true,
            ..Default::default()
        }
    }

    /// What Enter must load on each row of [`config`], in row order. Written
    /// out by hand rather than read from `ROWS`, so a wrong table cannot
    /// agree with itself.
    pub(crate) const EDIT_VALUES: &[(usize, &str)] = &[
        (cursor::THEME, "nord"),
        (cursor::VIEW, "dense"),
        (cursor::DEFAULT_TAB, "packets"),
        (cursor::REFRESH_RATE, "250"),
        (cursor::CAPTURE_INTERFACE, "wlan7"),
        (cursor::SHOW_GEO, "off"),
        (cursor::TIMELINE_WINDOW, "15m"),
        (cursor::PACKET_FOLLOW, "off"),
        (cursor::BPF_FILTER, "udp port 53"),
        (cursor::GEOIP_DB, "/geo/city.mmdb"),
        (cursor::GEOIP_ASN_DB, "/geo/asn.mmdb"),
        (cursor::BANDWIDTH_THRESHOLD, "42000000"),
        (cursor::PORT_SCAN_THRESHOLD, "37"),
        (cursor::AI_INSIGHTS, "off"),
        (cursor::AI_MODEL, "qwen-test"),
        (cursor::AI_ENDPOINT, "http://127.0.0.1:1"),
        (cursor::GRAPH_STYLE, "bars"),
        (cursor::GRAPH_FADE, "off"),
        (cursor::SANDBOX, "strict"),
        (cursor::GROUPS_COLLAPSED, "off"),
        (cursor::CONFIRM_QUIT, "on"),
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loaded(path: &str) -> DbFile {
        DbFile::Loaded {
            path: path.into(),
            database_type: "DBIP-Country-Lite".into(),
            build_epoch: 1_790_000_000,
        }
    }

    #[test]
    fn geoip_row_says_which_database_is_loaded() {
        assert_eq!(
            geoip_row("", &DbFile::NotConfigured),
            "(none): run netwatch geoip update"
        );
        assert_eq!(
            geoip_row("/geo/db.mmdb", &loaded("/geo/db.mmdb")),
            "DBIP-Country-Lite: /geo/db.mmdb"
        );
        let unreadable = DbFile::Unreadable {
            path: "/geo/db.mmdb".into(),
            error: "bad".into(),
        };
        assert_eq!(
            geoip_row("/geo/db.mmdb", &unreadable),
            "unreadable: /geo/db.mmdb"
        );
    }

    /// Databases open once. A path edited in the overlay, or a file downloaded
    /// while this session runs, is not what lookups are using yet.
    #[test]
    fn geoip_row_names_a_change_that_waits_for_a_restart() {
        assert_eq!(
            geoip_row("/geo/new.mmdb", &loaded("/geo/old.mmdb")),
            "/geo/new.mmdb on next start"
        );
        assert_eq!(
            geoip_row("/cache/dbip-country-lite.mmdb", &DbFile::NotConfigured),
            "/cache/dbip-country-lite.mmdb on next start"
        );
        assert_eq!(
            geoip_row("", &loaded("/geo/old.mmdb")),
            "(none) on next start"
        );
    }

    /// The rows of a drawn Settings overlay, in a session that opened a file
    /// with this name and `database_type`.
    fn drawn_with_database(name: &str, database_type: &str, width: u16) -> Vec<String> {
        use crate::collectors::geo::test_db;
        use ratatui::{backend::TestBackend, Terminal};
        let dir = std::env::temp_dir().join(format!("nw-settings-geo-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, test_db::city(database_type, 1_790_000_000)).unwrap();
        let app = App::prepare_with_config(NetwatchConfig {
            geoip_db: path.to_str().unwrap().to_owned(),
            ..Default::default()
        });
        let _ = std::fs::remove_dir_all(&dir);
        let mut terminal = Terminal::new(TestBackend::new(width, 40)).unwrap();
        terminal.draw(|f| render(f, &app, f.area())).unwrap();
        let buf = terminal.backend().buffer();
        buf.content
            .chunks(width as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect())
            .collect()
    }

    /// AI Insights says what it is on its own rows, and nowhere else: this is
    /// the slot under the list that a selected row can use, and the running UI
    /// is not where everything experimental needs a label.
    #[test]
    fn settings_label_ai_insights_experimental_on_its_rows_only() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app = App::prepare_with_config(NetwatchConfig::default());
        let mut drawn = |cursor: usize| {
            app.ui.settings_cursor = cursor;
            let mut terminal = Terminal::new(TestBackend::new(120, 60)).unwrap();
            terminal.draw(|f| render(f, &app, f.area())).unwrap();
            let text: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect();
            text.contains("Experimental")
        };
        for row in [cursor::AI_INSIGHTS, cursor::AI_MODEL, cursor::AI_ENDPOINT] {
            assert!(drawn(row), "row {row}");
        }
        for row in [cursor::THEME, cursor::SANDBOX, cursor::CONFIRM_QUIT] {
            assert!(!drawn(row), "row {row}");
        }
    }

    /// Where the keys a config got wrong stay listed after the session's first
    /// moments, however narrow the popup.
    #[test]
    fn settings_list_the_keys_the_config_ignored() {
        use ratatui::{backend::TestBackend, Terminal};
        let config = NetwatchConfig::from_toml(
            "sandbox_mode = 'strict'\n[alerts]\na_rather_long_key_of_some_kind = 1\n",
            std::path::Path::new("/etc/netwatch/config.toml"),
        )
        .unwrap();
        let app = App::prepare_with_config(config);
        for width in [80, 120] {
            let mut terminal = Terminal::new(TestBackend::new(width, 60)).unwrap();
            terminal.draw(|f| render(f, &app, f.area())).unwrap();
            let text: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect();
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            for needle in ["unknown key sandbox_mode", "a_rather_long_key_of_some_kind"] {
                assert!(text.contains(needle), "{width}: {needle} in {text}");
            }
        }
    }

    /// Settings redraws the live capability snapshot, which is how a date chrono
    /// cannot represent took the TUI down. The session reports the file instead.
    #[test]
    fn an_out_of_range_build_epoch_draws_as_unreadable() {
        use crate::collectors::geo::test_db;
        use ratatui::{backend::TestBackend, Terminal};
        let dir = std::env::temp_dir().join(format!("nw-settings-geo-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("far.mmdb");
        std::fs::write(&path, test_db::city("DBIP-Country-Lite", 9_000_000_000_000)).unwrap();
        let app = App::prepare_with_config(NetwatchConfig {
            geoip_db: path.to_str().unwrap().to_owned(),
            ..Default::default()
        });
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!app.geo_cache.has_offline_db());
        let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
        terminal.draw(|f| render(f, &app, f.area())).unwrap();
        let buf = terminal.backend().buffer();
        let drawn: String = buf.content.iter().map(|c| c.symbol()).collect();
        assert!(drawn.contains("unreadable: "), "{drawn}");
    }

    /// DB-IP's data carries its attribution where the session shows what it
    /// opened, wherever the file came from: here a name the download never
    /// uses, in the narrowest popup and a wide one.
    #[test]
    fn settings_attributes_a_dbip_database() {
        for width in [80, 120] {
            let rows = drawn_with_database("own.mmdb", "DBIP-Country-Lite", width);
            let at = |text: &str| rows.iter().position(|row| row.contains(text));
            assert!(
                at(crate::collectors::geo::DBIP_ATTRIBUTION).is_some(),
                "{width} columns:\n{}",
                rows.join("\n")
            );
            // Right under the rows it belongs to.
            assert_eq!(
                at(crate::collectors::geo::DBIP_ATTRIBUTION),
                at("GeoIP ASN DB Path").map(|row| row + 1)
            );
        }
    }

    /// Too narrow for the popup to hold it on one row, none of it is cut off.
    #[test]
    fn settings_attribution_stays_whole_in_a_very_narrow_terminal() {
        let rows = drawn_with_database("own.mmdb", "DBIP-Country-Lite", 60);
        for part in ["IP geolocation by DB-IP (https://db-ip.com),", "CC BY 4.0"] {
            assert!(
                rows.iter().any(|row| row.contains(part)),
                "{part}:\n{}",
                rows.join("\n")
            );
        }
    }

    /// A MaxMind file named as the download names its files is still MaxMind's.
    #[test]
    fn settings_does_not_attribute_another_database() {
        for width in [80, 120] {
            let rows = drawn_with_database("dbip-country-lite.mmdb", "GeoLite2-City", width);
            let drawn = rows.join("\n");
            assert!(drawn.contains("GeoLite2-City"), "{drawn}");
            assert!(!drawn.contains("IP geolocation"), "{drawn}");
            assert!(!drawn.contains("db-ip.com"), "{drawn}");
        }
    }

    #[test]
    fn ai_endpoint_row_says_when_requests_go_out_in_cleartext() {
        let row = &ROWS[cursor::AI_ENDPOINT];
        let mut cfg = NetwatchConfig::default();
        assert_eq!(row.shown(&cfg), "local");
        cfg.insights_endpoint = "http://10.0.0.5:11434".into();
        assert_eq!(
            row.shown(&cfg),
            "cleartext, off-host: http://10.0.0.5:11434"
        );
        // The edit box still gets the URL alone, or accepting it would save
        // the label as the endpoint.
        assert_eq!(
            get_edit_value(&cfg, cursor::AI_ENDPOINT),
            "http://10.0.0.5:11434"
        );
        for fine in ["http://127.0.0.1:11434", "https://ollama.example.com"] {
            cfg.insights_endpoint = fine.into();
            assert_eq!(row.shown(&cfg), fine);
        }
    }

    /// `get_edit_value` numbered rows without the View row, so Enter on
    /// GeoIP DB Path loaded the ASN database path, and so on down the list.
    #[test]
    fn enter_loads_each_rows_own_value() {
        let rows: Vec<usize> = fixture::EDIT_VALUES.iter().map(|&(at, _)| at).collect();
        assert_eq!(rows, (0..SETTINGS_COUNT).collect::<Vec<_>>());
        let cfg = fixture::config();
        for &(at, want) in fixture::EDIT_VALUES {
            assert_eq!(get_edit_value(&cfg, at), want, "{}", ROWS[at].label);
        }
    }

    /// Every on/off row reads "off" in the fixture, so the test above passes
    /// even if one of them reads another's flag. Turn each on alone: only its
    /// own row may read "on", and accepting "on" there must set that flag and
    /// nothing else.
    #[test]
    fn each_on_off_row_owns_its_flag() {
        let turn_on = |c: &mut NetwatchConfig, at: usize| match at {
            cursor::SHOW_GEO => c.show_geo = true,
            cursor::PACKET_FOLLOW => c.packet_follow = true,
            cursor::AI_INSIGHTS => c.insights_enabled = true,
            cursor::GRAPH_FADE => c.graph_fade = true,
            cursor::GROUPS_COLLAPSED => c.groups_start_collapsed = true,
            cursor::CONFIRM_QUIT => c.confirm_quit = true,
            _ => panic!("no flag to turn on for {}", ROWS[at].label),
        };
        let flags: Vec<usize> = fixture::EDIT_VALUES
            .iter()
            .filter(|&&(_, v)| v == "off")
            .map(|&(at, _)| at)
            .collect();

        for &on in &flags {
            let mut want = fixture::config();
            turn_on(&mut want, on);
            for &at in &flags {
                let reads = if at == on { "on" } else { "off" };
                assert_eq!(
                    get_edit_value(&want, at),
                    reads,
                    "{} with {} on",
                    ROWS[at].label,
                    ROWS[on].label
                );
            }
            let mut got = fixture::config();
            assert_eq!(apply_edit(&mut got, on, "on"), Ok(()));
            assert_eq!(
                format!("{got:?}"),
                format!("{want:?}"),
                "{}",
                ROWS[on].label
            );
        }
    }

    /// Accepting what Enter loaded, unchanged, must leave the config as it
    /// was. With the old numbering, accepting GeoIP DB Path saved the ASN
    /// path into `geoip_db`.
    #[test]
    fn accepting_the_loaded_value_changes_nothing() {
        let on = NetwatchConfig {
            insights_enabled: true,
            ..fixture::config()
        };
        for cfg in [NetwatchConfig::default(), fixture::config(), on] {
            for (at, row) in ROWS.iter().enumerate() {
                let loaded = get_edit_value(&cfg, at);
                let mut after = cfg.clone();
                assert_eq!(
                    apply_edit(&mut after, at, &loaded),
                    Ok(()),
                    "{} refused {loaded:?}",
                    row.label
                );
                assert_eq!(format!("{after:?}"), format!("{cfg:?}"), "{}", row.label);
            }
        }
    }

    #[test]
    fn apply_valid_tab() {
        let mut cfg = NetwatchConfig::default();
        assert!(apply_edit(&mut cfg, cursor::DEFAULT_TAB, "packets").is_ok());
        assert_eq!(cfg.default_tab, "packets");
    }

    #[test]
    fn apply_invalid_tab() {
        let mut cfg = NetwatchConfig::default();
        assert!(apply_edit(&mut cfg, cursor::DEFAULT_TAB, "nonsense").is_err());
    }

    #[test]
    fn tab_names_covers_all_tabs() {
        // Every TAB_NAMES entry must be accepted by apply_edit, and the
        // default must be in the list.
        let mut cfg = NetwatchConfig::default();
        assert!(TAB_NAMES.contains(&cfg.default_tab.as_str()));
        for name in TAB_NAMES {
            assert!(
                apply_edit(&mut cfg, cursor::DEFAULT_TAB, name).is_ok(),
                "rejected {}",
                name
            );
            assert_eq!(cfg.default_tab, *name);
        }
    }

    /// Each name opens a different tab, so all ten are reachable: `egress`
    /// used to fall through to Dashboard, and Settings offered neither
    /// Processes, Diagnose nor Egress.
    #[test]
    fn tab_names_open_every_tab() {
        let tabs: std::collections::HashSet<_> = TAB_NAMES
            .iter()
            .map(|name| {
                NetwatchConfig {
                    default_tab: name.to_string(),
                    ..NetwatchConfig::default()
                }
                .tab()
            })
            .collect();
        assert_eq!(tabs.len(), 10, "{TAB_NAMES:?} open only {tabs:?}");
    }

    #[test]
    fn apply_refresh_rate_bounds() {
        let mut cfg = NetwatchConfig::default();
        assert!(apply_edit(&mut cfg, cursor::REFRESH_RATE, "500").is_ok());
        assert_eq!(cfg.refresh_rate_ms, 500);
        assert!(apply_edit(&mut cfg, cursor::REFRESH_RATE, "50").is_err());
        assert!(apply_edit(&mut cfg, cursor::REFRESH_RATE, "10000").is_err());
        assert!(apply_edit(&mut cfg, cursor::REFRESH_RATE, "abc").is_err());
    }

    #[test]
    fn apply_bool_toggle() {
        let mut cfg = NetwatchConfig::default();
        assert!(apply_edit(&mut cfg, cursor::SHOW_GEO, "off").is_ok());
        assert!(!cfg.show_geo);
        assert!(apply_edit(&mut cfg, cursor::SHOW_GEO, "on").is_ok());
        assert!(cfg.show_geo);
        assert!(apply_edit(&mut cfg, cursor::SHOW_GEO, "maybe").is_err());
    }

    #[test]
    fn apply_timeline_window() {
        let mut cfg = NetwatchConfig::default();
        assert!(apply_edit(&mut cfg, cursor::TIMELINE_WINDOW, "1h").is_ok());
        assert_eq!(cfg.timeline_window, "1h");
        assert!(apply_edit(&mut cfg, cursor::TIMELINE_WINDOW, "2h").is_err());
    }

    #[test]
    fn apply_bandwidth_threshold() {
        let mut cfg = NetwatchConfig::default();
        assert!(apply_edit(&mut cfg, cursor::BANDWIDTH_THRESHOLD, "50000000").is_ok());
        assert_eq!(cfg.alerts.bandwidth_threshold, 50_000_000);
        assert!(apply_edit(&mut cfg, cursor::BANDWIDTH_THRESHOLD, "not_a_number").is_err());
    }

    #[test]
    fn apply_string_fields() {
        let mut cfg = NetwatchConfig::default();
        assert!(apply_edit(&mut cfg, cursor::CAPTURE_INTERFACE, "en1").is_ok());
        assert_eq!(cfg.capture_interface, "en1");
        assert!(apply_edit(&mut cfg, cursor::BPF_FILTER, "tcp port 80").is_ok());
        assert_eq!(cfg.bpf_filter, "tcp port 80");
        assert!(apply_edit(&mut cfg, cursor::BANDWIDTH_THRESHOLD, "50000000").is_ok());
        assert_eq!(cfg.alerts.bandwidth_threshold, 50_000_000);
    }

    #[test]
    fn apply_theme() {
        let mut cfg = NetwatchConfig::default();
        assert!(apply_edit(&mut cfg, cursor::THEME, "dracula").is_ok());
        assert_eq!(cfg.theme, "dracula");
        assert!(apply_edit(&mut cfg, cursor::THEME, "invalid").is_err());
    }

    #[test]
    fn format_bandwidth_values() {
        assert_eq!(format_bandwidth(0), "disabled");
        assert_eq!(format_bandwidth(500), "500 B/s");
        assert_eq!(format_bandwidth(50_000), "50 KB/s");
        assert_eq!(format_bandwidth(100_000_000), "100 MB/s");
        assert_eq!(format_bandwidth(2_000_000_000), "2 GB/s");
    }

    #[test]
    fn apply_sandbox_accepts_valid_modes() {
        let mut cfg = NetwatchConfig::default();
        for v in ["on", "strict", "off", "ON", "Strict"] {
            assert!(
                apply_edit(&mut cfg, cursor::SANDBOX, v).is_ok(),
                "rejected {v}"
            );
            assert_eq!(cfg.sandbox, v.to_lowercase());
        }
    }

    #[test]
    fn apply_sandbox_rejects_unknown() {
        let mut cfg = NetwatchConfig::default();
        assert!(apply_edit(&mut cfg, cursor::SANDBOX, "loose").is_err());
        assert!(apply_edit(&mut cfg, cursor::SANDBOX, "").is_err());
    }

    /// `apply_edit` is keyed by row position, so every named cursor must
    /// still reach its own setting. This is the test that would have caught
    /// the View row shifting every editor below it by one.
    #[test]
    fn each_cursor_edits_its_own_setting() {
        let mut cfg = NetwatchConfig::default();
        assert!(apply_edit(&mut cfg, cursor::VIEW, "dense").is_ok());
        assert_eq!(cfg.view, "dense");
        assert!(apply_edit(&mut cfg, cursor::VIEW, "nope").is_err());

        assert!(apply_edit(&mut cfg, cursor::THEME, "nord").is_ok());
        assert_eq!(cfg.theme, "nord");
        assert!(apply_edit(&mut cfg, cursor::DEFAULT_TAB, "packets").is_ok());
        assert_eq!(cfg.default_tab, "packets");
        assert!(apply_edit(&mut cfg, cursor::REFRESH_RATE, "250").is_ok());
        assert_eq!(cfg.refresh_rate_ms, 250);
        assert!(apply_edit(&mut cfg, cursor::GRAPH_STYLE, "dots").is_ok());
        assert_eq!(cfg.graph_style, "dots");
        assert!(apply_edit(&mut cfg, cursor::SANDBOX, "strict").is_ok());
        assert_eq!(cfg.sandbox, "strict");
        assert_eq!(SETTINGS_COUNT, cursor::CONFIRM_QUIT + 1);
    }

    #[test]
    fn cycle_through_includes_sandbox() {
        assert!(is_cycle_through(cursor::SANDBOX));
        assert!(is_cycle_through(cursor::THEME));
        assert!(!is_cycle_through(cursor::REFRESH_RATE));
    }

    fn rows_at(app: &App, width: u16) -> Vec<String> {
        use ratatui::{backend::TestBackend, Terminal};
        let mut terminal = Terminal::new(TestBackend::new(width, 50)).unwrap();
        terminal.draw(|f| render(f, app, f.area())).unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .chunks(width as usize)
            .map(|row| row.iter().map(|c| c.symbol()).collect())
            .collect()
    }

    /// A session as root says containment is limited, on a row of its own that
    /// fits the narrowest popup.
    #[cfg(target_os = "linux")]
    #[test]
    fn settings_say_when_running_as_root() {
        let test = "ui::settings::tests::settings_say_when_running_as_root";
        if !crate::sandbox::audit::as_root_in_user_namespace(test) {
            return;
        }
        let mut app = App::prepare_with_config(NetwatchConfig::default());
        app.sandbox_report.mode.effective = Some("best-effort");
        for width in [80, 100, 120] {
            let rows = rows_at(&app, width);
            assert!(
                rows.iter()
                    .any(|row| row.contains("running as root: containment limited")),
                "{width} columns:\n{}",
                rows.join("\n")
            );
        }
    }

    #[test]
    fn wrap_words_breaks_at_spaces_and_keeps_every_word() {
        let rows = |text, first, rest| wrap_words(text, first, rest);
        assert_eq!(rows("one two three", 40, 40), ["one two three"]);
        assert_eq!(rows("one two three", 7, 40), ["one two", "three"]);
        assert_eq!(rows("one two three", 8, 5), ["one two", "three"]);
        assert_eq!(rows("", 10, 10), [""]);
        // A word longer than a row is cut, and nothing is lost.
        assert_eq!(rows("abcdefghijkl mn", 8, 8), ["abcdefgh", "ijkl mn"]);
        // Wide graphemes count as two columns.
        assert_eq!(rows("界界界界界", 8, 8), ["界界界界", "界"]);
        // The floor, for a terminal narrower than the popup's minimum.
        assert_eq!(rows("one two", 0, 0), ["one two"]);
    }

    #[test]
    fn sandbox_rows_fit_the_popup_at_each_width() {
        let detail = "best-effort: Landlock fs ABI 3 (kernel 9), 31 caps dropped \
                      · TCP denied on 13/13 parser workers \
                      · CAP_NET_RAW kept on main to reopen capture (c, i, Shift+R) \
                      · no-socket filter skipped: no syscall table for powerpc64 \
                      · 25/25 worker entries verified \
                      · running as root: containment limited";
        // Inside the borders of the popup at 80, 100 and 120 columns.
        for inner in [48, 58, 70] {
            let rows = sandbox_rows(detail, inner, 26);
            for row in &rows {
                let used = row.indent + crate::ui::text::width(&row.text);
                assert!(used <= inner, "{used} of {inner}: {}", row.text);
            }
            assert_eq!(rows[0].indent, 26);
            let words: Vec<&str> = rows.iter().flat_map(|r| r.text.split(' ')).collect();
            assert_eq!(
                words.join(" "),
                detail.replace(" · ", " "),
                "{inner} columns lost a word"
            );
            let root: Vec<_> = rows.iter().filter(|r| r.root).collect();
            assert_eq!(root.len(), 1, "{inner}");
            assert_eq!(root[0].text, "running as root: containment limited");
        }
    }

    /// `rows` as one line of words, with the popup's borders gone, so a clause
    /// reads whole however it wrapped and is missing if a row cut it off.
    #[cfg(target_os = "linux")]
    fn popup_text(rows: &[String]) -> String {
        let text: String = rows
            .iter()
            .flat_map(|row| row.chars().chain([' ']))
            .map(|c| {
                if ('\u{2500}'..='\u{257f}').contains(&c) {
                    ' '
                } else {
                    c
                }
            })
            .collect();
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// A best-effort TUI session's real clauses, the long ones included, from
    /// workers that really entered. Every word has to show at each width.
    #[cfg(target_os = "linux")]
    #[test]
    fn settings_show_the_whole_sandbox_detail_at_80_100_and_120_columns() {
        use crate::runtime::capabilities::CapabilitySnapshot;
        use crate::sandbox::{worker, Mode, NetRaw, SandboxPaths};
        const CHILD: &str = "NETWATCH_SETTINGS_DETAIL_TEST";
        // Worker policy is process-wide, so install it in a child.
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "ui::settings::tests::settings_show_the_whole_sandbox_detail_at_80_100_and_120_columns",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            return;
        }
        worker::install(Mode::BestEffort, SandboxPaths::default()).unwrap();
        worker::spawn("connections", || {}).join().unwrap();
        worker::spawn("keylog", || {}).join().unwrap();
        worker::spawn("traffic", || {}).join().unwrap();
        let reader = "confined by inheritance: the SDK reader thread takes this worker's \
                      Landlock layers, TCP deny included, but has no entry hook of its own";
        worker::note("ebpf-reader", reader);
        let mut app = App::prepare_with_config(NetwatchConfig::default());
        app.sandbox_report.mode.effective = Some("best-effort");
        let platform = &mut app.sandbox_report.platform;
        platform.landlock_abi = 3;
        platform.landlock_kernel_abi = 9;
        platform.caps_dropped = vec!["CAP_NET_ADMIN".into(); 31];
        platform.capture_authority = NetRaw::RetainedForReopen;
        let snapshot = CapabilitySnapshot::live(&app);
        let detail = snapshot.get("sandbox").detail.clone();
        for long in [
            "best-effort: Landlock fs ABI 3 (kernel 9), 31 caps dropped",
            "TCP denied on ",
            "CAP_NET_RAW kept on main to reopen capture (c, i, Shift+R)",
        ] {
            assert!(detail.contains(long), "{long} is not in {detail}");
        }
        for width in [80, 100, 120] {
            let rows = rows_at(&app, width);
            let text = popup_text(&rows);
            for clause in detail.split(" · ") {
                assert!(
                    text.contains(clause),
                    "{width} columns cut off {clause:?}:\n{}",
                    rows.join("\n")
                );
            }
            // The rows below it wrap too and are still inside the popup.
            for row in [
                format!("ebpf-reader: {reader}"),
                snapshot.compact(),
                "Setup details: netwatch doctor --json".to_string(),
            ] {
                assert!(
                    text.contains(&row),
                    "{width} columns cut off {row:?}:\n{}",
                    rows.join("\n")
                );
            }
        }
    }

    /// The sandbox detail is split across rows, so the parts after the first
    /// are not lost off the end of one.
    #[test]
    fn settings_put_each_sandbox_clause_on_a_row() {
        let mut app = App::prepare_with_config(NetwatchConfig::default());
        app.sandbox_report.mode.effective = Some("best-effort");
        app.sandbox_report.platform.landlock_abi = 3;
        app.sandbox_report.platform.landlock_kernel_abi = 9;
        let rows = rows_at(&app, 120);
        let sandbox = rows
            .iter()
            .find(|row| row.contains("Sandbox") && row.contains("best-effort:"))
            .unwrap_or_else(|| panic!("{}", rows.join("\n")));
        assert!(!sandbox.contains("worker"), "{sandbox}");
        assert!(
            rows.iter()
                .any(|row| row.contains("worker coverage not recorded")),
            "{}",
            rows.join("\n")
        );
    }

    /// The popup does not wrap, so a state at the end of the capability line
    /// was cut off below about 140 columns. The connection-table state must
    /// show in an 80-column terminal, where the popup is at its narrowest.
    #[cfg(target_os = "linux")]
    #[test]
    fn connection_fallback_shows_in_a_narrow_terminal() {
        use crate::collectors::attribution::{Coverage, TableSource};
        use ratatui::{backend::TestBackend, Terminal};
        let app = App::prepare_with_config(NetwatchConfig::default());
        app.connection_collector.set_coverage_for_test(Coverage {
            completed_at: Some(std::time::Instant::now()),
            collection_succeeded: true,
            table_source: Some(TableSource::ProcNet),
            table_note: Some("ss could not start: Permission denied (os error 13)".into()),
            ..Default::default()
        });
        for width in [80, 120] {
            let mut terminal = Terminal::new(TestBackend::new(width, 40)).unwrap();
            terminal.draw(|f| render(f, &app, f.area())).unwrap();
            let buf = terminal.backend().buffer();
            let rows: Vec<String> = buf
                .content
                .chunks(width as usize)
                .map(|row| row.iter().map(|c| c.symbol()).collect())
                .collect();
            assert!(
                rows.iter()
                    .any(|row| row.contains("connections: degraded · ss could")),
                "{width} columns:\n{}",
                rows.join("\n")
            );
        }
    }
}
