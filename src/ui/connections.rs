use crate::app::{App, AttributionStatus, ConnectionGroup, ConnectionStateFilter};
use crate::collectors::connections::AttributionSource;
use crate::collectors::connections::{has_stream_key, Connection};
use crate::collectors::traceroute::TracerouteStatus;
use crate::sort::{case_insensitive_key, ip_sort_key, SortColumn, TabSortState, TotalF64};
use crate::ui::text::truncate_end as truncate;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
};
use std::cmp::Reverse;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Width of the state column. `state_label` guarantees every state name fits,
/// so nothing in this column is ever truncated.
const STATE_COL: usize = 12;

pub const COLUMNS: &[SortColumn] = &[
    SortColumn { name: "Process" },
    SortColumn { name: "PID" },
    SortColumn { name: "Proto" },
    SortColumn { name: "State" },
    SortColumn {
        name: "Local Address",
    },
    SortColumn {
        name: "Remote Address",
    },
    SortColumn { name: "Down/Up" }, // RATE_COL — conditionally shown, see render
];

pub const DEFAULT_SORT: TabSortState = TabSortState {
    column: 0,
    ascending: true,
};

// COLUMNS is retained for the existing sort_picker integration; the new
// chip+group toolbar replaces the visible header but `s:Sort` still opens
// the picker for fine-grained ordering when group is None.

/// Order `order`, indices into `conns`, by a column of [`COLUMNS`]. A cached
/// key per row, not a comparator: lowering strings and parsing addresses twice
/// per comparison was most of a 10,000-row frame. The sort is stable, so rows
/// that tie keep their order in either direction.
fn sort_by_column(order: &mut [usize], conns: &[Connection], column: usize, ascending: bool) {
    fn by<K: Ord>(order: &mut [usize], ascending: bool, key: impl Fn(usize) -> K) {
        if ascending {
            order.sort_by_cached_key(|&i| key(i));
        } else {
            order.sort_by_cached_key(|&i| Reverse(key(i)));
        }
    }
    let col_name = COLUMNS.get(column).map(|c| c.name).unwrap_or("");
    match col_name {
        "Process" => by(order, ascending, |i| {
            case_insensitive_key(conns[i].process_name.as_deref().unwrap_or(""))
        }),
        "PID" => by(order, ascending, |i| conns[i].pid),
        "Proto" => by(order, ascending, |i| {
            case_insensitive_key(&conns[i].protocol)
        }),
        "State" => by(order, ascending, |i| case_insensitive_key(&conns[i].state)),
        "Local Address" => by(order, ascending, |i| ip_sort_key(&conns[i].local_addr)),
        "Remote Address" => by(order, ascending, |i| ip_sort_key(&conns[i].remote_addr)),
        "Down/Up" => by(order, ascending, |i| {
            TotalF64(conns[i].rx_rate.unwrap_or(0.0) + conns[i].tx_rate.unwrap_or(0.0))
        }),
        _ => {}
    }
}

/// [`sort_by_column`] on the rows themselves.
#[cfg(test)]
pub fn sort(conns: &mut [Connection], column: usize, ascending: bool) {
    let mut order: Vec<usize> = (0..conns.len()).collect();
    sort_by_column(&mut order, conns, column, ascending);
    let sorted: Vec<Connection> = order.iter().map(|&i| conns[i].clone()).collect();
    conns.clone_from_slice(&sorted);
}

/// Layout constraints for the Connections tab. Kept as a function so the
/// renderer and the mouse hit-tester share a single source of truth — when
/// the chip row or detail strip's height changes, both sides update together.
fn layout_chunks(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // header and attribution coverage
            Constraint::Length(2),  // chip row
            Constraint::Min(8),     // table
            Constraint::Length(10), // detail strip
            Constraint::Length(3),  // footer
        ])
        .split(area)
}

/// Inner table area (inside the bordered block) where data rows are drawn.
/// Used by `handle_mouse` to map a screen y-coordinate back to a connection
/// index without duplicating the layout chunk arithmetic.
pub(crate) fn table_inner_area(area: Rect) -> Rect {
    let chunks = layout_chunks(area);
    let outer = chunks[2];
    // Same four-sided inset as the panel the rows are drawn in. Corner style
    // doesn't affect `inner`, but deriving it from the shared chrome means a
    // future change to the box can't silently move the click targets.
    widgets::panel_block(&crate::theme::by_name("default")).inner(outer)
}

/// Centered-on-selected window top, matching the renderer's auto-scroll
/// behaviour. Pure function so both sides can compute the same value.
pub(crate) fn compute_window_top(selected: usize, total: usize, visible_rows: usize) -> usize {
    crate::ui::tree::window_top(selected, total, visible_rows)
}

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = layout_chunks(area);
    // One view and one row list for the whole frame. A poll can publish
    // between two reads, and the table and the detail strip would then
    // describe different rows.
    let view = current_view(app);
    let rows = view.rows(&app.ui.connection_collapsed);

    render_header(f, app, &view, chunks[0]);
    render_chip_row(f, app, &view, chunks[1]);
    render_connection_table(f, app, &view, &rows, chunks[2]);
    render_detail_strip(f, app, &rows, chunks[3]);
    render_footer(f, app, chunks[4]);

    if app.ui.traceroute_view_open {
        render_traceroute_overlay(f, app, area);
    }
}

struct StateCounts {
    all: usize,
    established: usize,
    listen: usize,
    time_wait: usize,
}

fn count_states(conns: &[Connection]) -> StateCounts {
    let mut c = StateCounts {
        all: conns.len(),
        established: 0,
        listen: 0,
        time_wait: 0,
    };
    for conn in conns {
        match conn.state.as_str() {
            "ESTABLISHED" => c.established += 1,
            "LISTEN" => c.listen += 1,
            "TIME_WAIT" | "TIME-WAIT" => c.time_wait += 1,
            _ => {}
        }
    }
    c
}

fn render_chip_row(f: &mut Frame, app: &App, view: &ConnView, area: Rect) {
    let t = &app.theme;
    let counts = &view.counts;

    let chips: [(ConnectionStateFilter, usize); 4] = [
        (ConnectionStateFilter::All, counts.all),
        (ConnectionStateFilter::Established, counts.established),
        (ConnectionStateFilter::Listen, counts.listen),
        (ConnectionStateFilter::TimeWait, counts.time_wait),
    ];

    let mut spans: Vec<Span> = vec![Span::styled(" show  ", Style::default().fg(t.text_muted))];
    for (filter, count) in chips.iter() {
        let label = format!("{} {}", filter.label(), count);
        let active = *filter == app.ui.connection_state_filter;
        if active {
            spans.push(Span::styled(
                format!(" {} ", label),
                Style::default()
                    .fg(t.text_primary)
                    .bg(t.selection_bg)
                    .bold(),
            ));
        } else {
            spans.push(Span::styled(
                format!(" {} ", label),
                Style::default().fg(t.text_secondary),
            ));
        }
        spans.push(Span::raw(" "));
    }

    // Right-aligned group toggle: " group: process / remote / none"
    let group_label = format!(
        "group: {}    f cycles  G groups",
        app.ui.connection_group.label(),
    );
    let used_w: usize = spans.iter().map(|s| s.content.chars().count()).sum();
    let total_w = area.width as usize;
    let group_w = group_label.chars().count();
    if total_w > used_w + group_w + 2 {
        let pad = total_w - used_w - group_w - 2;
        spans.push(Span::raw(" ".repeat(pad)));
        spans.push(Span::styled(group_label, Style::default().fg(t.text_muted)));
    }

    let row1 = Line::from(spans);
    f.render_widget(Paragraph::new(vec![row1, Line::from("")]), area);
}

fn render_header(f: &mut Frame, app: &App, view: &ConnView, area: Rect) {
    let total = view.conns.len();
    let filter = view.text_filter.as_deref();
    let shown = view.text_matches;

    let mut extra = vec![Span::raw("  ")];
    if filter.is_some() {
        extra.push(Span::styled(
            format!("{shown}/{total} connections"),
            Style::default().fg(app.theme.status_warn),
        ));
        extra.push(Span::raw("  "));
        extra.push(Span::styled(
            format!("filter: {}", filter.unwrap_or("")),
            Style::default().fg(app.theme.key_hint),
        ));
    } else {
        extra.push(Span::styled(
            format!("{total} connections"),
            Style::default().fg(app.theme.status_good),
        ));
    }

    // Kernel-attribution status. Picks PKTAP on macOS and eBPF on
    // Linux+ebpf-feature builds; on platforms with neither the row stays
    // uncluttered. The source name in the message ("pktap" / "ebpf") is
    // carried by AttributionStatus so the renderer doesn't have to know
    // which path won.
    match app.attribution_status() {
        AttributionStatus::Lsof => {}
        AttributionStatus::Active(source) => {
            extra.push(Span::raw("  "));
            extra.push(Span::styled(
                format!("attribution: {source}"),
                Style::default().fg(app.theme.status_good),
            ));
        }
        AttributionStatus::Failed(source, err) => {
            extra.push(Span::raw("  "));
            // Truncate the error so it doesn't blow out narrow terminals.
            let short = err.chars().take(60).collect::<String>();
            extra.push(Span::styled(
                format!("attribution: lsof — {source} unavailable: {short}"),
                Style::default().fg(app.theme.status_warn),
            ));
        }
    }

    crate::ui::widgets::render_attribution_header(f, app, area, extra);
}

fn active_connection_filter(app: &App) -> Option<&str> {
    if let Some(ref f) = app.ui.connection_filter_active {
        return Some(f);
    }
    if app.ui.connection_filter_input && !app.ui.connection_filter_text.is_empty() {
        return Some(&app.ui.connection_filter_text);
    }
    None
}

fn matches_filter(conn: &crate::collectors::connections::Connection, filter: &str) -> bool {
    let needle = filter.to_lowercase();

    // Prefix-typed filters: `proto:tls`, `sni:host`, `host:hostname`.
    // Fall through to free-text matching when no prefix matches.
    if let Some(stripped) = needle.strip_prefix("proto:") {
        return app_protocol_tag(&conn.app_protocol)
            .map(|tag| tag.contains(stripped))
            .unwrap_or(false);
    }
    if let Some(stripped) = needle.strip_prefix("sni:") {
        return app_protocol_sni(&conn.app_protocol)
            .map(|s| s.to_lowercase().contains(stripped))
            .unwrap_or(false);
    }
    if let Some(stripped) = needle.strip_prefix("host:") {
        return app_protocol_host(&conn.app_protocol)
            .map(|s| s.to_lowercase().contains(stripped))
            .unwrap_or(false);
    }
    if let Some(stripped) = needle.strip_prefix("ech:") {
        let want = match stripped {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        };
        return match (want, app_protocol_ech(&conn.app_protocol)) {
            (Some(w), Some(have)) => w == have,
            // Bad value or non-TLS/QUIC connection: no match. Mirrors the
            // Packets-tab semantics where `ech:` is meaningless outside
            // TLS/QUIC.
            _ => false,
        };
    }
    if let Some(stripped) = needle.strip_prefix("ja4:") {
        return app_protocol_ja4(&conn.app_protocol)
            .map(|j| j.to_lowercase().contains(stripped))
            .unwrap_or(false);
    }

    let process = conn.process_name.as_deref().unwrap_or("").to_lowercase();
    let state = conn.state.to_lowercase();
    let remote = conn.remote_addr.to_lowercase();
    let app_summary = render_app_protocol(&conn.app_protocol).to_lowercase();
    process.contains(&needle)
        || state.contains(&needle)
        || remote.contains(&needle)
        || app_summary.contains(&needle)
}

/// Short cell text for the APP column. Empty when no DPI result.
pub(crate) fn render_app_protocol(p: &Option<crate::dpi::AppProtocol>) -> String {
    use crate::dpi::AppProtocol::*;
    let base = render_app_protocol_base(p);
    // Append the decoded JA4 client name when the bundled DB knows
    // the fingerprint, so the APP column shows "HTTPS host (Chromium
    // Browser)" without requiring the user to drill into a per-packet
    // details view. Covers both TLS-over-TCP and QUIC (JA4Q). Unknown
    // JA4s stay quiet — the column already gets crowded on narrow
    // terminals.
    let ja4 = match p {
        Some(Tls { ja4: Some(j), .. }) => Some(j.as_str()),
        Some(Quic { ja4: Some(j), .. }) => Some(j.as_str()),
        _ => None,
    };
    if let Some(j) = ja4 {
        if let Some(label) = crate::dpi::ja4_db::lookup(j) {
            return format!("{base} ({label})");
        }
    }
    base
}

fn render_app_protocol_base(p: &Option<crate::dpi::AppProtocol>) -> String {
    use crate::dpi::AppProtocol::*;
    match p {
        None => "—".into(),
        // ECH-flagged variants get a distinct prefix so the user can
        // tell at a glance that the displayed SNI is the *outer* SNI
        // and the real destination is hidden from the network.
        Some(Tls {
            sni: Some(host),
            ech: true,
            ..
        }) => format!("HTTPS-ECH {}", host),
        Some(Tls {
            sni: None,
            ech: true,
            ..
        }) => "HTTPS-ECH".into(),
        Some(Tls {
            sni: Some(host), ..
        }) => format!("HTTPS {}", host),
        Some(Tls { sni: None, .. }) => "HTTPS".into(),
        Some(Http {
            method,
            host: Some(h),
            path,
            ..
        }) => format!("HTTP {} {}{}", method, h, path.as_deref().unwrap_or("")),
        Some(Http {
            status: Some(code), ..
        }) => format!("HTTP {}", code),
        Some(Http {
            method,
            host: None,
            path: Some(p),
            ..
        }) => format!("HTTP {} {}", method, p),
        Some(Http { method, .. }) => format!("HTTP {}", method),
        Some(Dns { qname, .. }) => format!("DNS {}", qname),
        Some(Ssh { version }) => format!("SSH {}", version),
        Some(Quic {
            sni: Some(h),
            ech: true,
            ..
        }) => format!("QUIC-ECH {}", h),
        Some(Quic {
            sni: None,
            ech: true,
            ..
        }) => "QUIC-ECH".into(),
        Some(Quic { sni: Some(h), .. }) => format!("QUIC {}", h),
        Some(Quic { sni: None, .. }) => "QUIC".into(),
        Some(Mqtt { client_id: Some(c) }) => format!("MQTT {}", c),
        Some(Mqtt { client_id: None }) => "MQTT".into(),
        Some(Stun { message_type }) => format!("STUN {}", message_type),
        Some(BitTorrent { .. }) => "BitTorrent".into(),
        Some(NetBios { service }) => format!("NetBIOS {}", service),
        Some(Snmp {
            version,
            community: Some(c),
        }) => format!("SNMP {} {}", version, c),
        Some(Snmp {
            version,
            community: None,
        }) => format!("SNMP {}", version),
        Some(Ssdp {
            method,
            target: Some(t),
        }) => format!("SSDP {} {}", method, t),
        Some(Ssdp {
            method,
            target: None,
        }) => format!("SSDP {}", method),
        Some(Ftp { command }) => format!("FTP {}", command),
        Some(Llmnr { qname, .. }) => format!("LLMNR {}", qname),
        Some(Dhcp { op }) => match op {
            1 => "DHCP Discover/Request".into(),
            2 => "DHCP Offer/ACK".into(),
            n => format!("DHCP op={}", n),
        },
        Some(Ntp { version, .. }) => format!("NTPv{}", version),
    }
}

fn app_protocol_tag(p: &Option<crate::dpi::AppProtocol>) -> Option<&'static str> {
    use crate::dpi::AppProtocol::*;
    match p {
        None => None,
        Some(Tls { .. }) => Some("tls"),
        Some(Http { .. }) => Some("http"),
        Some(Dns { .. }) => Some("dns"),
        Some(Ssh { .. }) => Some("ssh"),
        Some(Quic { .. }) => Some("quic"),
        Some(Mqtt { .. }) => Some("mqtt"),
        Some(Stun { .. }) => Some("stun"),
        Some(BitTorrent { .. }) => Some("bittorrent"),
        Some(NetBios { .. }) => Some("netbios"),
        Some(Snmp { .. }) => Some("snmp"),
        Some(Ssdp { .. }) => Some("ssdp"),
        Some(Ftp { .. }) => Some("ftp"),
        Some(Llmnr { .. }) => Some("llmnr"),
        Some(Dhcp { .. }) => Some("dhcp"),
        Some(Ntp { .. }) => Some("ntp"),
    }
}

fn app_protocol_sni(p: &Option<crate::dpi::AppProtocol>) -> Option<&str> {
    use crate::dpi::AppProtocol::*;
    match p {
        Some(Tls { sni: Some(s), .. }) => Some(s.as_str()),
        Some(Quic { sni: Some(s), .. }) => Some(s.as_str()),
        _ => None,
    }
}

fn app_protocol_ech(p: &Option<crate::dpi::AppProtocol>) -> Option<bool> {
    use crate::dpi::AppProtocol::*;
    match p {
        Some(Tls { ech, .. }) => Some(*ech),
        Some(Quic { ech, .. }) => Some(*ech),
        _ => None,
    }
}

fn app_protocol_ja4(p: &Option<crate::dpi::AppProtocol>) -> Option<&str> {
    use crate::dpi::AppProtocol::*;
    match p {
        Some(Tls { ja4: Some(j), .. }) => Some(j.as_str()),
        _ => None,
    }
}

fn app_protocol_host(p: &Option<crate::dpi::AppProtocol>) -> Option<&str> {
    use crate::dpi::AppProtocol::*;
    match p {
        Some(Http { host: Some(h), .. }) => Some(h.as_str()),
        _ => None,
    }
}

fn app_protocol_color(
    p: &Option<crate::dpi::AppProtocol>,
    t: &crate::theme::Theme,
) -> ratatui::style::Color {
    use crate::dpi::AppProtocol::*;
    match p {
        None => t.text_muted,
        Some(Tls { .. }) | Some(Quic { .. }) | Some(Mqtt { .. }) => t.status_info, // cyan-ish
        Some(Http { .. }) | Some(Ftp { .. }) => t.status_good,                     // green
        Some(Dns { .. }) | Some(Llmnr { .. }) | Some(Snmp { .. }) => t.brand,      // brand accent
        Some(Ssh { .. }) | Some(Ssdp { .. }) | Some(NetBios { .. }) => t.status_warn, // yellow
        Some(Stun { .. }) | Some(BitTorrent { .. }) => t.text_muted, // muted (transport-level)
        Some(Dhcp { .. }) | Some(Ntp { .. }) => t.status_warn,       // infra services
    }
}

// ── Grouped tree ────────────────────────────────────────────────────────
//
// `group: process` and `group: remote` used to be sort orders wearing the
// word "group": rows clustered, but the key was still restated on every one.
// On a real machine that meant `claude` down eleven consecutive rows and the
// process column so starved of width it rendered `Google Chrome…`. These are
// now actual trees — one parent row carrying the rollup, children foldable
// beneath — built on `ui::tree`, the same machinery as the Egress tab.
//
// `group: none` stays a flat list. It is the mode you pick precisely when you
// want every connection as a peer, and a tree with one child per parent would
// be strictly worse.

/// Summary shown on a group's parent row.
pub struct ConnRollup {
    pub conns: usize,
    /// Distinct PIDs (process grouping) or distinct processes (remote
    /// grouping) — the count that says "this row is more than one thing".
    pub facets: usize,
    pub rx_rate: f64,
    pub tx_rate: f64,
    /// Best (lowest) handshake RTT across the group, if any was measured.
    pub rtt_us: Option<f64>,
    /// Dominant connection state, and how many of the group share it.
    pub state: String,
    pub state_count: usize,
    /// True when any member carries retransmits — a rollup must not hide a
    /// problem that would be visible on an expanded child row.
    pub degraded: bool,
    /// True when every member was attributed by the kernel (PKTAP / eBPF),
    /// so the parent can carry the same `◉` the children would.
    pub kernel_attributed: bool,
}

/// A group's children are indices into the view's table.
pub type ConnGroup = crate::ui::tree::Group<ConnRollup, usize>;

/// One line of the Connections table.
pub enum ConnRow<'a> {
    Parent {
        group: &'a ConnGroup,
        collapsed: bool,
    },
    Conn {
        conn: &'a Connection,
    },
}

/// The connection list in whatever shape the current group mode implies, for
/// one table under one set of filters.
///
/// Owns its data so the borrowed row list can be derived from it repeatedly —
/// the renderer, the mouse handler and the key handlers all need the same
/// numbering, and recomputing it independently is how they drift apart. It
/// holds the table and indices into it, with no copy of a row, and
/// [`current_view`] builds it once per table.
pub struct ConnView {
    generation: u64,
    state_filter: ConnectionStateFilter,
    text_filter: Option<String>,
    group: ConnectionGroup,
    sort: Option<TabSortState>,
    capturing: bool,
    conns: Arc<Vec<Connection>>,
    pub groups: Vec<ConnGroup>,
    /// Row indices in display order, under `group: none`.
    pub flat: Vec<usize>,
    /// The chip row's counts: the whole table, whichever chip is active.
    counts: StateCounts,
    /// Rows the text filter matches, whichever chip is active.
    text_matches: usize,
    /// See [`rate_coverage`].
    rate_coverage: Option<(usize, usize)>,
}

/// The most common *named* state in a group, and how many share it.
///
/// Connectionless rows (UDP) carry an empty state, so counting them would
/// make "" the winner and the cell would render as a bare `11/13` — a
/// fraction of nothing. Only named states compete; a group with none at all
/// says so with an em-dash.
fn dominant_state(conns: &[&Connection]) -> (String, usize) {
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for c in conns.iter().filter(|c| !c.state.is_empty()) {
        *counts.entry(c.state.as_str()).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(s, n)| (s.to_string(), n))
        .unwrap_or_else(|| ("—".to_string(), conns.len()))
}

fn rollup(key_is_process: bool, conns: &[&Connection]) -> ConnRollup {
    let facets = if key_is_process {
        let pids: BTreeSet<u32> = conns.iter().filter_map(|c| c.pid).collect();
        pids.len()
    } else {
        let names: BTreeSet<&str> = conns
            .iter()
            .map(|c| c.process_name.as_deref().unwrap_or("—"))
            .collect();
        names.len()
    };
    let (state, state_count) = dominant_state(conns);
    ConnRollup {
        conns: conns.len(),
        facets,
        rx_rate: conns.iter().filter_map(|c| c.rx_rate).sum(),
        tx_rate: conns.iter().filter_map(|c| c.tx_rate).sum(),
        rtt_us: conns
            .iter()
            .filter_map(|c| c.handshake_rtt_us)
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)),
        state,
        state_count,
        degraded: conns.iter().any(|c| c.retransmits > 0),
        kernel_attributed: !conns.is_empty()
            && conns.iter().all(|c| {
                matches!(
                    c.attribution,
                    AttributionSource::Pktap | AttributionSource::Ebpf
                )
            }),
    }
}

/// The view of the current table under the current filters: the one every
/// reader of the tab goes through. It is built when the table or a filter, the
/// group mode or the sort has changed since the last call, and otherwise the
/// last one comes back. Fold state is not part of it: a fold changes which
/// rows [`ConnView::rows`] lists, not the view they come from.
pub fn current_view(app: &App) -> Arc<ConnView> {
    let (generation, conns) = app.connection_collector.connections_with_generation();
    let mut cached = crate::app::safe_lock(&app.caches.conn_view, "connections::current_view");
    if let Some(view) = cached.as_ref().filter(|v| v.is_current(generation, app)) {
        return Arc::clone(view);
    }
    let view = Arc::new(ConnView::build(app, generation, conns));
    *cached = Some(Arc::clone(&view));
    view
}

impl ConnView {
    fn is_current(&self, generation: u64, app: &App) -> bool {
        self.generation == generation
            && self.state_filter == app.ui.connection_state_filter
            && self.group == app.ui.connection_group
            && self.sort == connections_sort(app)
            && self.capturing == app.packet_collector.is_capturing()
            && self.text_filter.as_deref() == active_connection_filter(app)
    }

    /// The table grouped into a tree, or flat under `group: none`.
    fn build(app: &App, generation: u64, conns: Arc<Vec<Connection>>) -> Self {
        let state_filter = app.ui.connection_state_filter;
        let text_filter = active_connection_filter(app);
        let group = app.ui.connection_group;
        let sort = connections_sort(app);

        let mut text_matches = 0;
        let mut order: Vec<usize> = Vec::with_capacity(conns.len());
        for (i, c) in conns.iter().enumerate() {
            if text_filter.is_none_or(|f| matches_filter(c, f)) {
                text_matches += 1;
                if state_filter.matches(&c.state) {
                    order.push(i);
                }
            }
        }

        // Process keeps process-grouped, remote groups by host, none follows
        // the sort picker.
        match group {
            ConnectionGroup::Process => order.sort_by_cached_key(|&i| {
                let c = &conns[i];
                (
                    case_insensitive_key(c.process_name.as_deref().unwrap_or("~")),
                    Reverse(TotalF64(c.rx_rate.unwrap_or(0.0))),
                    c.remote_addr.as_str(),
                )
            }),
            ConnectionGroup::Remote => order.sort_by_cached_key(|&i| {
                let c = &conns[i];
                (
                    case_insensitive_key(host_only(&c.remote_addr)),
                    c.remote_addr.as_str(),
                    case_insensitive_key(c.process_name.as_deref().unwrap_or("~")),
                )
            }),
            ConnectionGroup::None => {
                let column = sort.map(|s| s.column).unwrap_or(0);
                let ascending = sort.map(|s| s.ascending).unwrap_or(true);
                sort_by_column(&mut order, &conns, column, ascending);
            }
        }

        let (groups, flat) = if matches!(group, ConnectionGroup::None) {
            (Vec::new(), order)
        } else {
            (group_rows(&conns, order, group), Vec::new())
        };

        let capturing = app.packet_collector.is_capturing();
        let rate_coverage = capturing.then(|| rate_coverage(app, &conns)).flatten();

        Self {
            generation,
            state_filter,
            text_filter: text_filter.map(str::to_string),
            group,
            sort,
            capturing,
            counts: count_states(&conns),
            text_matches,
            rate_coverage,
            groups,
            flat,
            conns,
        }
    }

    /// The visible rows, honouring fold state. Single source of truth for
    /// "what is row N" — renderer and input handlers both go through it.
    pub fn rows(&self, fold: &crate::ui::tree::FoldState) -> Vec<ConnRow<'_>> {
        if self.groups.is_empty() {
            return self
                .flat
                .iter()
                .map(|&i| ConnRow::Conn {
                    conn: &self.conns[i],
                })
                .collect();
        }
        crate::ui::tree::flatten(&self.groups, fold)
            .into_iter()
            .map(|row| match row {
                crate::ui::tree::Row::Parent { group, collapsed } => {
                    ConnRow::Parent { group, collapsed }
                }
                crate::ui::tree::Row::Child { item, .. } => ConnRow::Conn {
                    conn: &self.conns[*item],
                },
            })
            .collect()
    }
}

/// A view built from scratch, to check [`current_view`] against.
#[cfg(test)]
pub(crate) fn fresh_view_for_test(app: &App) -> ConnView {
    let (generation, conns) = app.connection_collector.connections_with_generation();
    ConnView::build(app, generation, conns)
}

/// How many of the table's flows have a rate, and how many could, when the
/// running capture has dropped flows for want of room and some have none.
///
/// A dropped flow's byte counts go with it, whether a count or a byte limit
/// dropped it, so its row has no rate, which looks the same as a flow with no
/// traffic. With no drop there is nothing to tell apart, and an empty tracker
/// costs a lock and no walk of the table.
fn rate_coverage(app: &App, conns: &[Connection]) -> Option<(usize, usize)> {
    let dropped = crate::app::safe_lock(
        &app.packet_collector.stream_tracker,
        "connections::rate_coverage",
    )
    .session_dropped_flows();
    if dropped == 0 {
        return None;
    }
    let (mut rated, mut flows) = (0, 0);
    for c in conns.iter().filter(|c| has_stream_key(c)) {
        flows += 1;
        rated += usize::from(c.rx_rate.is_some() || c.tx_rate.is_some());
    }
    (rated < flows).then_some((rated, flows))
}

fn connections_sort(app: &App) -> Option<TabSortState> {
    app.ui
        .sort_states
        .get(&crate::app::Tab::Connections)
        .copied()
}

/// `order`'s rows bucketed by process or remote host. `order` is sorted by
/// the group key then by rate, so first-seen bucket order is the order the user
/// asked for; only the rollup-level ranking is left, and busiest-first is what
/// a rate column is for.
fn group_rows(conns: &[Connection], order: Vec<usize>, mode: ConnectionGroup) -> Vec<ConnGroup> {
    let key_is_process = matches!(mode, ConnectionGroup::Process);
    let buckets = crate::ui::tree::group_by_str(order, |&i| {
        let c = &conns[i];
        if key_is_process {
            c.process_name.as_deref().unwrap_or("—")
        } else {
            host_only(&c.remote_addr)
        }
    });
    let mut members: Vec<&Connection> = Vec::new();
    let mut groups: Vec<ConnGroup> = buckets
        .into_iter()
        .map(|(key, children)| {
            members.clear();
            members.extend(children.iter().map(|&i| &conns[i]));
            ConnGroup {
                key: key.to_string(),
                rollup: rollup(key_is_process, &members),
                children,
            }
        })
        .collect();
    groups.sort_by_cached_key(|g| {
        let (lowered, key) = case_insensitive_key(&g.key);
        (
            Reverse(TotalF64(g.rollup.rx_rate + g.rollup.tx_rate)),
            lowered,
            key.to_string(),
        )
    });
    groups
}

/// The row under the cursor, in `rows`: the same one the table highlights.
fn selected_row<'r, 'a>(app: &App, rows: &'r [ConnRow<'a>]) -> Option<&'r ConnRow<'a>> {
    rows.get(
        app.ui
            .scroll
            .connection_scroll
            .min(rows.len().saturating_sub(1)),
    )
}

/// The connection under the cursor, or `None` when a group header is selected.
///
/// Every action that operates on "the selected connection" — traceroute,
/// whois, drill to packets, the detail strip — resolves through here, so a
/// parent row can never be mistaken for the first connection beneath it.
pub fn selected_connection(app: &App) -> Option<Connection> {
    let view = current_view(app);
    let rows = view.rows(&app.ui.connection_collapsed);
    match selected_row(app, &rows)? {
        ConnRow::Conn { conn } => Some((*conn).clone()),
        ConnRow::Parent { .. } => None,
    }
}

/// The group key under the cursor, from a parent row or any of its children.
pub fn selected_group_key(app: &App) -> Option<String> {
    let view = current_view(app);
    if view.groups.is_empty() {
        return None;
    }
    let rows = view.rows(&app.ui.connection_collapsed);
    let idx = app
        .ui
        .scroll
        .connection_scroll
        .min(rows.len().saturating_sub(1));
    // Walk back to the nearest header so folding works from a child row —
    // navigating up to the parent first would be busywork.
    rows.get(..=idx)?.iter().rev().find_map(|r| match r {
        ConnRow::Parent { group, .. } => Some(group.key.clone()),
        ConnRow::Conn { .. } => None,
    })
}

/// Number of visible rows, for clamping scroll against what is on screen.
pub fn visible_row_count(app: &App) -> usize {
    current_view(app).rows(&app.ui.connection_collapsed).len()
}

/// Compact geo string for the Connections GEO column. Prefers
/// `country_code-city` (e.g. "US-Ashburn"), falls back to country code, and
/// returns an em-dash for private/unresolved IPs so the column always has a
/// glyph to align against. Truncated to fit a 12-char cell at the call site.
fn format_geo_cell(app: &App, host: &str) -> String {
    match app.geo_cache.lookup(host) {
        Some(geo) => {
            if !geo.country_code.is_empty() && !geo.city.is_empty() {
                format!("{}-{}", geo.country_code, geo.city)
            } else if !geo.country_code.is_empty() {
                geo.country_code
            } else if !geo.country.is_empty() {
                geo.country
            } else {
                "—".into()
            }
        }
        None => "—".into(),
    }
}

fn host_only(addr: &str) -> &str {
    if let Some(stripped) = addr.strip_prefix('[') {
        if let Some(end) = stripped.find("]:") {
            // Through the closing bracket: the `[` and the `]` are one byte each.
            return &addr[..end + 2];
        }
    }
    if let Some(colon) = addr.rfind(':') {
        &addr[..colon]
    } else {
        addr
    }
}

fn render_connection_table(
    f: &mut Frame,
    app: &App,
    view: &ConnView,
    rows: &[ConnRow],
    area: Rect,
) {
    let t = &app.theme;
    let conn_count = if view.groups.is_empty() {
        view.flat.len()
    } else {
        view.groups.iter().map(|g| g.rollup.conns).sum()
    };

    // Attribution warning, in the border row rather than the header line.
    // The header's `extra` spans are appended after the tab bar, which fills
    // the row on its own past ~120 columns — so the one message that explains
    // why half the PROCESS column is empty was being clipped off-screen on
    // every terminal wide enough to run this tab. Only worth saying when
    // Landlock is enforced: unsandboxed, the ss/`/proc` fallback still
    // attributes new connections, and the message would be a lie.
    let attribution_warning = match app.attribution_status() {
        AttributionStatus::Failed(source, _) if app.sandbox_report.platform.landlock_abi > 0 => {
            Some(format!(
                " ⚠ {source} unavailable · new connections unattributed "
            ))
        }
        _ => None,
    };

    // In the border row for the same reason: past ~120 columns the header line
    // has no room left for it.
    let rates = view.rate_coverage.map(|(rated, flows)| {
        format!(
            " rates: {} of {} flows ",
            widgets::format_count(rated),
            widgets::format_count(flows)
        )
    });

    let title_right = if view.groups.is_empty() {
        format!(" {conn_count} shown  group: none ")
    } else {
        let noun = match app.ui.connection_group {
            ConnectionGroup::Remote => "hosts",
            _ => "processes",
        };
        format!(
            " {} {noun} · {conn_count} conns  group: {} ",
            view.groups.len(),
            app.ui.connection_group.label()
        )
    };
    let block = table_block(t, area.width, attribution_warning, rates, title_right);
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 {
        return;
    }

    // Column header. Mirrors the layout in `render_conn_row`. The GEO column
    // is only shown when the user has toggled `g`; it sits between REMOTE and
    // STATE so it qualifies the destination it describes.
    let header_text: &str = if app.ui.show_geo {
        "  process              proto  remote                          app                    geo           state         rx/s         tx/s     rtt    age"
    } else {
        "  process              proto  remote                          app                    state         rx/s         tx/s     rtt    age"
    };
    let header_area = Rect {
        x: inner.x + 1,
        y: inner.y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            header_text,
            Style::default().fg(t.text_muted),
        ))),
        header_area,
    );

    let visible_rows = inner.height.saturating_sub(1) as usize;
    let max_idx = rows.len().saturating_sub(1);
    let selected = app.ui.scroll.connection_scroll.min(max_idx);
    let window_top = compute_window_top(selected, rows.len(), visible_rows);

    let rendered = rows.iter().skip(window_top).take(visible_rows).count();
    for (i, row) in rows.iter().skip(window_top).take(visible_rows).enumerate() {
        let abs_idx = window_top + i;
        let is_selected = abs_idx == selected;
        let row_y = inner.y + 1 + i as u16;
        // Selected row stays at full intensity regardless of position;
        // unselected rows fade top-bright / bottom-dim when fade is on.
        let row_alpha = if app.user_config.graph_fade && !is_selected {
            crate::graph::row_fade_alpha(i, rendered)
        } else {
            1.0
        };
        match row {
            ConnRow::Conn { conn } => {
                render_conn_row(f, app, inner, row_y, conn, is_selected, row_alpha)
            }
            ConnRow::Parent { group, collapsed } => render_group_row(
                f,
                app,
                inner,
                row_y,
                group,
                *collapsed,
                is_selected,
                row_alpha,
            ),
        }
    }

    if rows.is_empty() {
        let empty_area = Rect {
            x: inner.x + 2,
            y: inner.y + 1,
            width: inner.width.saturating_sub(2),
            height: 1,
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "No connections match this filter (press f to cycle)",
                Style::default().fg(t.text_muted),
            ))),
            empty_area,
        );
    }
}

/// The table's panel, and in its border row the title, the attribution warning,
/// the counts, and the rates note if there is room left. The note is the least
/// of them, so it goes first: a right-aligned title wider than the row draws
/// over whatever is to its left, and the row reads as if the note were not
/// there.
fn table_block(
    t: &crate::theme::Theme,
    width: u16,
    warning: Option<String>,
    rates: Option<String>,
    counts: String,
) -> Block<'static> {
    const TITLE: &str = " connections ";
    let width_of = crate::ui::text::width;
    // Inside the two corners.
    let room = (width as usize).saturating_sub(2);
    let taken = width_of(TITLE) + warning.as_deref().map_or(0, width_of) + width_of(&counts);
    let rates = rates.filter(|r| taken + width_of(r) <= room);
    widgets::panel_block(t)
        .title(Line::from(Span::styled(
            TITLE,
            Style::default().fg(t.brand).bold(),
        )))
        .title(
            Line::from(
                warning
                    .map(|w| Span::styled(w, Style::default().fg(t.status_warn).bold()))
                    .into_iter()
                    .chain(rates.map(|r| Span::styled(r, Style::default().fg(t.status_warn))))
                    .chain([Span::styled(counts, Style::default().fg(t.brand).bold())])
                    .collect::<Vec<_>>(),
            )
            .alignment(Alignment::Right),
        )
}

/// A group header: the key named once, with the rollup of everything folded
/// beneath it.
///
/// Laid out on the same column grid as `render_conn_row` so an expanded tree
/// still reads as one table — a header with its own private alignment would
/// make the children look like a different screen. Each cell answers the
/// question its column asks, at group scale: PROTO becomes the child count,
/// REMOTE becomes how many distinct things are inside, STATE becomes the
/// dominant state, and the rates are sums.
#[allow(clippy::too_many_arguments)]
fn render_group_row(
    f: &mut Frame,
    app: &App,
    inner: Rect,
    row_y: u16,
    group: &ConnGroup,
    collapsed: bool,
    is_selected: bool,
    row_alpha: f32,
) {
    let t = &app.theme;
    let r = &group.rollup;
    let chevron = if collapsed { "▶ " } else { "▼ " };
    // The group name gets the full 20-char cell the child rows split between
    // process and PID — the point of the tree is that the name is legible.
    let name = truncate(&group.key, 20);

    let facet_label = match app.ui.connection_group {
        ConnectionGroup::Remote => {
            if r.facets == 1 {
                "1 proc".to_string()
            } else {
                format!("{} procs", r.facets)
            }
        }
        _ => {
            if r.facets == 1 {
                "1 pid".to_string()
            } else {
                format!("{} pids", r.facets)
            }
        }
    };

    let state_cell = if r.state_count == r.conns {
        crate::ui::widgets::state_label(&r.state)
    } else {
        // Mixed states: say which dominates and how many, rather than picking
        // one and implying the group is uniform. The longer state names leave
        // no room for the denominator, and a clipped `time-wait 1…` is worse
        // than no denominator — the row already says how many connections the
        // group holds.
        let label = crate::ui::widgets::state_label(&r.state);
        let full = format!("{label} {}/{}", r.state_count, r.conns);
        if full.chars().count() <= STATE_COL {
            full
        } else {
            format!("{label} {}", r.state_count)
        }
    };
    let state_color = match r.state.as_str() {
        "ESTABLISHED" => t.status_good,
        "LISTEN" => t.status_info,
        "TIME_WAIT" | "TIME-WAIT" => t.status_warn,
        _ => t.text_muted,
    };

    let rx_str = if r.rx_rate > 0.0 {
        crate::ui::widgets::format_bytes_rate(r.rx_rate)
    } else {
        "—".into()
    };
    let tx_str = if r.tx_rate > 0.0 {
        crate::ui::widgets::format_bytes_rate(r.tx_rate)
    } else {
        "—".into()
    };
    let rtt_str = r
        .rtt_us
        .map(|us| {
            let ms = us / 1000.0;
            if ms < 1.0 {
                format!("{ms:.1}ms")
            } else {
                format!("{ms:.0}ms")
            }
        })
        .unwrap_or_else(|| "—".into());

    let mut spans: Vec<Span> = vec![
        // The chevron stays on the selected row: fold state is information
        // the selection highlight already conveys separately, and swapping it
        // for a cursor glyph would hide whether the group is open.
        Span::styled(chevron, Style::default().fg(t.brand)),
        // The group name carries the row's weight; the children sit at
        // normal intensity beneath it.
        Span::styled(
            format!("{name:<20}"),
            Style::default().fg(t.text_primary).bold(),
        ),
        // PROTO belongs to an individual flow, so a rollup leaves it empty
        // rather than putting a count under a header that promises a
        // protocol. The summary goes in the REMOTE cell, which is where the
        // eye already is and which has the width to spell it out.
        Span::raw(" "),
        Span::styled("     ".to_string(), Style::default().fg(t.text_muted)),
        Span::raw(" "),
        Span::styled(
            format!(
                "{:<32}",
                truncate(
                    &format!(
                        "{} conn{} · {facet_label}",
                        r.conns,
                        if r.conns == 1 { "" } else { "s" }
                    ),
                    32
                )
            ),
            Style::default().fg(t.text_secondary),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{:<22}", if r.degraded { "retransmits" } else { "" }),
            Style::default().fg(if r.degraded {
                t.status_error
            } else {
                t.text_muted
            }),
        ),
    ];

    if app.ui.show_geo {
        // Geo is a property of one endpoint, so a rollup has nothing honest
        // to put here. Hold the column so the children stay aligned.
        spans.push(Span::styled(
            format!(" {:<width$}", "", width = STATE_COL),
            Style::default().fg(t.text_muted),
        ));
    }

    spans.extend([
        Span::styled(
            format!(" {:<width$}", state_cell, width = STATE_COL),
            Style::default().fg(state_color),
        ),
        Span::styled(format!(" {rx_str:>10}"), Style::default().fg(t.rx_rate)),
        Span::raw(" "),
        Span::styled(format!(" {tx_str:>9}"), Style::default().fg(t.tx_rate)),
        Span::raw(" "),
        Span::styled(
            format!(" {rtt_str:>5}"),
            Style::default().fg(t.text_primary),
        ),
        Span::raw(" "),
        Span::styled(format!(" {:>4}", ""), Style::default().fg(t.text_muted)),
    ]);

    let faded_spans = if (row_alpha - 1.0).abs() < f32::EPSILON {
        spans
    } else {
        crate::graph::fade_spans_fg(spans, t.bg, row_alpha, t.defers_to_terminal())
    };
    let row_area = Rect {
        x: inner.x + 1,
        y: row_y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };
    let para = if is_selected {
        Paragraph::new(Line::from(faded_spans)).style(Style::default().bg(t.selection_bg))
    } else {
        Paragraph::new(Line::from(faded_spans))
    };
    f.render_widget(para, row_area);
}

fn render_conn_row(
    f: &mut Frame,
    app: &App,
    inner: Rect,
    row_y: u16,
    conn: &Connection,
    is_selected: bool,
    row_alpha: f32,
) {
    let t = &app.theme;
    let state_color = conn_state_color(&conn.state, t);
    let active = matches!(
        (conn.rx_rate, conn.tx_rate),
        (Some(r), _) if r > 0.0
    ) || matches!(conn.tx_rate, Some(r) if r > 0.0);
    let dot_color = if active { t.status_good } else { t.status_info };

    let pid_str = conn
        .pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "—".into());
    let process = conn.process_name.as_deref().unwrap_or("—");
    // Under a tree, the parent row already names the group. Restating it on
    // every child is what made the flat table unreadable — `claude` eleven
    // times down a column too narrow to spell `Google Chrome Helper`. Indent
    // instead, and spend the width on what actually differs.
    let proc_label = match app.ui.connection_group {
        ConnectionGroup::Process => format!("    {:>5}{:<10}", pid_str, ""),
        _ => format!("{:<14} {:>5}", truncate(process, 14), pid_str),
    };

    let proto_color = if conn.protocol.eq_ignore_ascii_case("UDP") {
        t.proto_udp()
    } else {
        t.status_info
    };

    let rx_str = conn
        .rx_rate
        .map(crate::ui::widgets::format_bytes_rate)
        .unwrap_or_else(|| "—".into());
    let tx_str = conn
        .tx_rate
        .map(crate::ui::widgets::format_bytes_rate)
        .unwrap_or_else(|| "—".into());

    let rtt_str = conn
        .handshake_rtt_us
        .map(|us| {
            let ms = us / 1000.0;
            if ms < 1.0 {
                format!("{:.1}ms", ms)
            } else {
                format!("{:.0}ms", ms)
            }
        })
        .unwrap_or_else(|| "—".into());

    let age_str = connection_age(app, conn);

    // Bullet glyph encodes attribution source: `◉` (filled+ring) for
    // kernel-attributed rows (PKTAP on macOS, eBPF on Linux), plain `●`
    // for lsof-polled rows. The header labels which path is active so
    // users can decode this; see `render_header`. Selected row uses the
    // same arrow regardless.
    let bullet = if is_selected {
        "▸ "
    } else if matches!(
        conn.attribution,
        AttributionSource::Pktap | AttributionSource::Ebpf
    ) {
        "◉ "
    } else {
        "● "
    };
    let mut spans: Vec<Span> = vec![
        Span::styled(
            bullet,
            Style::default().fg(if is_selected { t.brand } else { dot_color }),
        ),
        Span::styled(
            format!("{:<20}", proc_label),
            Style::default().fg(t.text_primary),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{:<5}", conn.protocol),
            Style::default().fg(proto_color),
        ),
        Span::raw(" "),
        Span::styled(
            // Same reasoning under `group: remote`: the host is the parent's
            // name, so the child shows the port that distinguishes it.
            match app.ui.connection_group {
                ConnectionGroup::Remote => {
                    let host = host_only(&conn.remote_addr);
                    let port = conn
                        .remote_addr
                        .rsplit_once(':')
                        .map(|(_, p)| p.to_string())
                        .unwrap_or_default();
                    if port.is_empty() {
                        format!("    {:<28}", truncate(host, 28))
                    } else {
                        format!("    :{port:<27}")
                    }
                }
                _ => format!("{:<32}", truncate(&conn.remote_addr, 32)),
            },
            Style::default().fg(t.text_primary),
        ),
        Span::raw(" "),
        Span::styled(
            format!(
                "{:<22}",
                truncate(&render_app_protocol(&conn.app_protocol), 22)
            ),
            Style::default().fg(app_protocol_color(&conn.app_protocol, t)),
        ),
    ];

    if app.ui.show_geo {
        let host = host_only(&conn.remote_addr);
        let geo_str = format_geo_cell(app, host);
        spans.push(Span::styled(
            format!(" {:<12}", truncate(&geo_str, 12)),
            Style::default().fg(t.status_info),
        ));
    }

    // Build the STATE cell so we can append a retransmit badge inside
    // its fixed 12-char width when one is present. "↻N" tells operators
    // at a glance that the flow has TCP retransmits without widening
    // the row layout. OOO without retransmits gets "↹N" in muted color.
    let state_cell = if conn.retransmits > 0 {
        format!(
            "{} ↻{}",
            crate::ui::widgets::state_label(&conn.state),
            conn.retransmits
        )
    } else if conn.out_of_order > 0 {
        format!(
            "{} ↹{}",
            crate::ui::widgets::state_label(&conn.state),
            conn.out_of_order
        )
    } else {
        truncate(&conn.state, 12).to_string()
    };
    let state_span_color = if conn.retransmits > 0 {
        t.status_error
    } else if conn.out_of_order > 0 {
        t.status_warn
    } else {
        state_color
    };

    spans.extend([
        Span::styled(
            format!(" {:<width$}", state_cell, width = STATE_COL),
            Style::default().fg(state_span_color),
        ),
        Span::styled(format!(" {:>10}", rx_str), Style::default().fg(t.rx_rate)),
        Span::raw(" "),
        Span::styled(format!(" {:>9}", tx_str), Style::default().fg(t.tx_rate)),
        Span::raw(" "),
        Span::styled(
            format!(" {:>5}", rtt_str),
            Style::default().fg(t.text_primary),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" {:>4}", age_str),
            Style::default().fg(t.text_muted),
        ),
    ]);
    let faded_spans = if (row_alpha - 1.0).abs() < f32::EPSILON {
        spans
    } else {
        crate::graph::fade_spans_fg(spans, t.bg, row_alpha, t.defers_to_terminal())
    };
    let line = Line::from(faded_spans);

    let row_area = Rect {
        x: inner.x + 1,
        y: row_y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };
    let para = if is_selected {
        Paragraph::new(line).style(Style::default().bg(t.selection_bg))
    } else {
        Paragraph::new(line)
    };
    f.render_widget(para, row_area);
}

fn connection_age(app: &App, conn: &Connection) -> String {
    use crate::collectors::connections::ConnectionKey;
    let key = ConnectionKey {
        protocol: conn.protocol.clone(),
        local_addr: conn.local_addr.clone(),
        remote_addr: conn.remote_addr.clone(),
        pid: conn.pid,
    };
    match app.connection_timeline.first_seen(&key) {
        Some(first_seen) => format_duration_short(first_seen.elapsed()),
        None => "—".to_string(),
    }
}

fn format_duration_short(d: std::time::Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{}s", s)
    } else if s < 3600 {
        format!("{}m", s / 60)
    } else if s < 86_400 {
        format!("{}h", s / 3600)
    } else {
        format!("{}d", s / 86_400)
    }
}

fn render_detail_strip(f: &mut Frame, app: &App, rows: &[ConnRow], area: Rect) {
    let t = &app.theme;
    let selected = selected_row(app, rows);

    let title_left = match selected {
        Some(ConnRow::Conn { conn: c }) => {
            let proc = c.process_name.as_deref().unwrap_or("—");
            let host = host_only(&c.remote_addr);
            format!(
                " detail  {}  pid {}  → {} ",
                proc,
                c.pid.map(|p| p.to_string()).unwrap_or_else(|| "—".into()),
                host,
            )
        }
        // A group header has no single flow to detail, so the title carries
        // the rollup rather than pretending one child stands for all of them.
        Some(ConnRow::Parent { group, .. }) => format!(
            " detail  {}  {} connections ",
            group.key, group.rollup.conns
        ),
        None => " detail ".to_string(),
    };

    let block = widgets::panel_block(t)
        .title(Line::from(Span::styled(
            title_left,
            Style::default().fg(t.status_warn).bold(),
        )))
        .title(
            Line::from(Span::styled(
                " ↑↓ to switch ",
                Style::default().fg(t.text_muted),
            ))
            .alignment(Alignment::Right),
        );
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 4 {
        return;
    }

    let hint = |f: &mut Frame, msg: &str| {
        let hint_area = Rect {
            x: inner.x + 2,
            y: inner.y + 1,
            width: inner.width.saturating_sub(2),
            height: 1,
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                msg.to_string(),
                Style::default().fg(t.text_muted),
            ))),
            hint_area,
        );
    };
    let conn = match selected {
        Some(ConnRow::Conn { conn }) => conn,
        Some(ConnRow::Parent { group, collapsed }) => {
            let r = &group.rollup;
            hint(
                f,
                &format!(
                    "{} · {} connections · {} in, {} out{}   —   space to {}",
                    group.key,
                    r.conns,
                    crate::ui::widgets::format_bytes_rate(r.rx_rate),
                    crate::ui::widgets::format_bytes_rate(r.tx_rate),
                    if r.degraded { " · retransmits" } else { "" },
                    if *collapsed { "expand" } else { "fold" },
                ),
            );
            return;
        }
        None => {
            hint(f, "No connection selected");
            return;
        }
    };

    // Two-column body: left FLOW + STATS, right RX 30s sparkline placeholder
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(70), Constraint::Min(0)])
        .split(inner);

    render_detail_left(f, app, cols[0], conn);
    render_detail_right(f, app, cols[1], conn);

    // Action keys at bottom
    let action_y = inner.y + inner.height.saturating_sub(1);
    let action_area = Rect {
        x: inner.x + 1,
        y: action_y,
        width: inner.width.saturating_sub(2),
        height: 1,
    };
    let key_style = Style::default().fg(t.key_hint).bold();
    let dim = Style::default().fg(t.text_muted);
    let action_line = Line::from(vec![
        Span::styled("Enter", key_style),
        Span::styled(" → Packets   ", dim),
        Span::styled("T", key_style),
        Span::styled(" Traceroute   ", dim),
        Span::styled("/", key_style),
        Span::styled(" Filter   ", dim),
        Span::styled("f", key_style),
        Span::styled(" Cycle state   ", dim),
        Span::styled("G", key_style),
        Span::styled(" Cycle group", dim),
    ]);
    f.render_widget(Paragraph::new(action_line), action_area);
}

fn render_detail_left(f: &mut Frame, app: &App, area: Rect, conn: &Connection) {
    let t = &app.theme;
    if area.height < 2 {
        return;
    }

    let age = connection_age(app, conn);
    let rx = conn
        .rx_rate
        .map(crate::ui::widgets::format_bytes_rate)
        .unwrap_or_else(|| "—".into());
    let tx = conn
        .tx_rate
        .map(crate::ui::widgets::format_bytes_rate)
        .unwrap_or_else(|| "—".into());
    let rtt = conn
        .handshake_rtt_us
        .map(|us| format!("{:.1}ms", us / 1000.0))
        .unwrap_or_else(|| "—".into());

    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled("FLOW", Style::default().fg(t.text_muted))),
        Line::from(vec![
            Span::styled(
                conn.local_addr.to_string(),
                Style::default().fg(t.text_primary),
            ),
            Span::styled("  →  ", Style::default().fg(t.text_muted)),
            Span::styled(
                conn.remote_addr.to_string(),
                Style::default().fg(t.text_primary),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{}  ", conn.protocol),
                Style::default().fg(t.status_info),
            ),
            Span::styled(
                format!("{}  ", crate::ui::widgets::state_label(&conn.state)),
                Style::default().fg(t.text_primary),
            ),
            Span::styled(format!("age {}", age), Style::default().fg(t.text_muted)),
        ]),
        Line::from(format!(
            "Match: {:?} · {}",
            conn.attribution,
            conn.evidence
                .unknown_reason
                .map(|r| format!("{r:?}"))
                .unwrap_or_else(|| format!(
                    "verified · {}ms old",
                    conn.evidence
                        .observed_at
                        .map(|t| t.elapsed().as_millis())
                        .unwrap_or(0)
                ))
        )),
        Line::from(vec![
            Span::styled("STATS  ", Style::default().fg(t.text_muted)),
            Span::styled(format!("RX {}", rx), Style::default().fg(t.rx_rate)),
            Span::styled("    ", Style::default()),
            Span::styled(format!("TX {}", tx), Style::default().fg(t.tx_rate)),
            Span::styled("    ", Style::default()),
            Span::styled(format!("RTT {}", rtt), Style::default().fg(t.text_primary)),
        ]),
    ];

    // Inline whois output once Shift+W has populated the cache. Mirrors
    // the rendering in ui/packets.rs so users see something appear after
    // the lookup — without this the keybinding looks like a no-op.
    let (remote_ip, _) = crate::app::parse_addr_parts(&conn.remote_addr);
    if let Some(ip) = remote_ip {
        if let Some(whois) = app.whois_cache.lookup(&ip) {
            let mut parts = Vec::new();
            if !whois.net_name.is_empty() {
                parts.push(whois.net_name.clone());
            }
            if !whois.org.is_empty() {
                parts.push(whois.org.clone());
            }
            if !whois.net_range.is_empty() {
                parts.push(whois.net_range.clone());
            }
            if !whois.country.is_empty() {
                parts.push(whois.country.clone());
            }
            lines.push(Line::from(vec![
                Span::styled("WHOIS  ", Style::default().fg(t.text_muted)),
                Span::styled(parts.join(" │ "), Style::default().fg(t.text_primary)),
            ]));
            if !whois.description.is_empty() {
                lines.push(Line::from(Span::styled(
                    format!("       {}", whois.description),
                    Style::default().fg(t.text_muted),
                )));
            }
        }
    }

    let body_area = Rect {
        x: area.x + 1,
        y: area.y,
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(1),
    };
    f.render_widget(Paragraph::new(lines), body_area);
}

fn render_detail_right(f: &mut Frame, app: &App, area: Rect, conn: &Connection) {
    let t = &app.theme;
    if area.height < 3 || area.width < 12 {
        return;
    }

    // RX history: try app.caches.top_conn_history keyed by (process, host) — same key the dashboard uses
    let proc = conn.process_name.clone().unwrap_or_else(|| "—".into());
    let host = host_only(&conn.remote_addr).to_string();
    let key = (proc, host);

    let hdr_area = Rect {
        x: area.x,
        y: area.y,
        width: area.width,
        height: 1,
    };
    let window = crate::ui::lite::window_label(
        crate::app::TOP_CONN_HISTORY_LEN,
        app.user_config.refresh_rate_ms,
    );
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!("RX {window}"),
            Style::default().fg(t.text_muted),
        ))),
        hdr_area,
    );

    if let Some(hist) = app.caches.top_conn_history.get(&key) {
        let data: Vec<u64> = hist.iter().copied().collect();
        if !data.is_empty() {
            let spark_area = Rect {
                x: area.x,
                y: area.y + 1,
                width: area.width,
                height: area.height.saturating_sub(2),
            };
            // The cache's whole window across the pane. One sample per column
            // left everything left of the newest 30 columns empty.
            let fitted = crate::ui::dense::fit_window(
                &data,
                crate::app::TOP_CONN_HISTORY_LEN,
                spark_area.width as usize * crate::graph::samples_per_column(app.graph_style),
            );
            crate::graph::render(
                f,
                spark_area,
                &fitted,
                app.graph_style,
                t.rx_rate,
                t.status_warn,
                app.graph_opts(),
            );
        }
    }
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    if app.ui.connection_filter_input {
        let filter_line = Line::from(vec![
            Span::styled(" / ", Style::default().fg(app.theme.brand).bold()),
            Span::raw(&app.ui.connection_filter_text),
            Span::styled("█", Style::default().fg(app.theme.text_primary)),
        ]);
        let bar = Paragraph::new(filter_line).block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(app.theme.key_hint)),
        );
        f.render_widget(bar, area);
        return;
    }

    use crate::ui::widgets::hint;
    let hints = if app.ui.traceroute_view_open {
        vec![hint("esc", "close")]
    } else {
        let mut v = vec![hint("s", "sort"), hint("/", "filter")];
        // Only advertise folding when there is something to fold — under
        // `group: none` the key does nothing and the hint would be a lie.
        if !matches!(app.ui.connection_group, ConnectionGroup::None) {
            v.push(hint("space", "fold"));
            v.push(hint(
                "z",
                if app.ui.connection_collapsed.all_collapsed() {
                    "expand all"
                } else {
                    "fold all"
                },
            ));
        }
        v.push(hint("T", "trace"));
        v.push(hint("↵", "packets"));
        v
    };
    crate::ui::widgets::render_footer(f, app, area, hints);
}

fn render_traceroute_overlay(f: &mut Frame, app: &App, area: Rect) {
    let result = crate::app::safe_lock(
        &app.traceroute_runner.result,
        "connections::render_traceroute_overlay",
    );

    let overlay_width = (area.width * 70 / 100)
        .max(50)
        .min(area.width.saturating_sub(4));
    let overlay_height = (area.height * 70 / 100)
        .max(10)
        .min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(overlay_width)) / 2;
    let y = area.y + (area.height.saturating_sub(overlay_height)) / 2;
    let overlay = Rect::new(x, y, overlay_width, overlay_height);

    f.render_widget(Clear, overlay);
    crate::ui::widgets::paint_overlay_bg(f, &app.theme, overlay);

    let title = format!(" Traceroute → {} ", result.target);
    let border_color = match result.status {
        TracerouteStatus::Running => app.theme.status_warn,
        TracerouteStatus::Done => app.theme.brand,
        TracerouteStatus::Error(_) => app.theme.status_error,
        TracerouteStatus::Idle => app.theme.text_muted,
    };
    let block = widgets::panel_block(&app.theme)
        .title(title)
        .border_style(Style::default().fg(border_color));
    let inner = block.inner(overlay);
    f.render_widget(block, overlay);

    let mut lines: Vec<Line> = Vec::new();

    match &result.status {
        TracerouteStatus::Running => {
            lines.push(Line::from(Span::styled(
                " ⏳ Running traceroute...",
                Style::default().fg(app.theme.status_warn),
            )));
        }
        TracerouteStatus::Error(msg) => {
            lines.push(Line::from(Span::styled(
                format!(" ✗ Error: {}", msg),
                Style::default().fg(app.theme.status_error),
            )));
        }
        TracerouteStatus::Done => {
            lines.push(Line::from(vec![
                Span::styled(" Hop", Style::default().fg(app.theme.brand).bold()),
                Span::raw("  "),
                Span::styled(
                    format!("{:<40}", "Host / IP"),
                    Style::default().fg(app.theme.brand).bold(),
                ),
                Span::styled("RTT 1     ", Style::default().fg(app.theme.brand).bold()),
                Span::styled("RTT 2     ", Style::default().fg(app.theme.brand).bold()),
                Span::styled("RTT 3", Style::default().fg(app.theme.brand).bold()),
            ]));
            lines.push(Line::from(Span::styled(
                " ───────────────────────────────────────────────────────────────────",
                Style::default().fg(app.theme.text_muted),
            )));
            for hop in &result.hops {
                lines.push(format_hop_line(hop, &app.theme));
            }
            if result.hops.is_empty() {
                lines.push(Line::from(Span::styled(
                    " No hops received",
                    Style::default().fg(app.theme.text_muted),
                )));
            }
        }
        TracerouteStatus::Idle => {
            lines.push(Line::from(Span::styled(
                " No traceroute data",
                Style::default().fg(app.theme.text_muted),
            )));
        }
    }

    let visible_height = inner.height as usize;
    let max_scroll = lines.len().saturating_sub(visible_height);
    let scroll = app.ui.scroll.traceroute_scroll.min(max_scroll);
    let visible_lines: Vec<Line> = lines
        .into_iter()
        .skip(scroll)
        .take(visible_height)
        .collect();

    let content = Paragraph::new(visible_lines);
    f.render_widget(content, inner);
}

fn format_hop_line(
    hop: &crate::collectors::traceroute::TracerouteHop,
    theme: &crate::theme::Theme,
) -> Line<'static> {
    let hop_num = format!(" {:>2} ", hop.hop_number);
    let host_ip = match (&hop.host, &hop.ip) {
        (Some(h), Some(ip)) => format!("{} ({})", h, ip),
        (None, Some(ip)) => ip.clone(),
        (Some(h), None) => h.clone(),
        (None, None) => "*".to_string(),
    };

    let rtt_spans: Vec<String> = if hop.rtt_ms.is_empty() && hop.ip.is_none() {
        vec!["*".to_string(); 3]
    } else {
        (0..3)
            .map(|i| match hop.rtt_ms.get(i) {
                Some(Some(ms)) => format!("{:>7.2}ms", ms),
                _ => "      *  ".to_string(),
            })
            .collect()
    };

    let rtt_color = hop
        .rtt_ms
        .iter()
        .filter_map(|r| r.as_ref())
        .next()
        .map(|ms| {
            if *ms < 10.0 {
                theme.status_good
            } else if *ms < 50.0 {
                theme.status_warn
            } else if *ms < 100.0 {
                theme.accent_amber()
            } else {
                theme.status_error
            }
        })
        .unwrap_or(theme.text_muted);

    Line::from(vec![
        Span::styled(hop_num, Style::default().fg(theme.brand)),
        Span::raw("  "),
        Span::styled(
            format!("{:<40}", host_ip),
            Style::default().fg(if hop.ip.is_some() {
                theme.text_primary
            } else {
                theme.text_muted
            }),
        ),
        Span::styled(rtt_spans[0].clone(), Style::default().fg(rtt_color)),
        Span::raw(" "),
        Span::styled(rtt_spans[1].clone(), Style::default().fg(rtt_color)),
        Span::raw(" "),
        Span::styled(rtt_spans[2].clone(), Style::default().fg(rtt_color)),
    ])
}

#[allow(dead_code)]
const SPARKLINE_BLOCKS: &[char] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

#[allow(dead_code)]
fn rtt_sparkline(history: &std::collections::VecDeque<f64>) -> String {
    if history.is_empty() {
        return String::new();
    }
    let min = history.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = history.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = max - min;

    history
        .iter()
        .map(|&v| {
            let idx = if range < 0.001 {
                3 // middle block for flat line
            } else {
                let normalized = (v - min) / range;
                (normalized * 7.0).round() as usize
            };
            SPARKLINE_BLOCKS[idx.min(7)]
        })
        .collect()
}

/// A connection row's state colour. Linux and Windows spell states as `ss`
/// does (`CLOSE-WAIT`), macOS as lsof does (`CLOSE_WAIT`), so each takes both:
/// a CLOSE-WAIT socket an application never closed is what the error colour
/// is there to flag.
fn conn_state_color(state: &str, t: &crate::theme::Theme) -> Color {
    match state {
        "ESTABLISHED" => t.status_good,
        "LISTEN" => t.status_info,
        "TIME_WAIT" | "TIME-WAIT" => t.status_warn,
        "CLOSE_WAIT" | "CLOSE-WAIT" | "FIN_WAIT1" | "FIN_WAIT_1" | "FIN-WAIT-1" | "FIN_WAIT2"
        | "FIN_WAIT_2" | "FIN-WAIT-2" => t.status_error,
        _ => t.text_muted,
    }
}

#[allow(dead_code)]
fn rtt_sparkline_color(
    history: &std::collections::VecDeque<f64>,
    theme: &crate::theme::Theme,
) -> Color {
    match history.back() {
        Some(&rtt) if rtt > 100.0 => theme.status_error,
        Some(&rtt) if rtt > 50.0 => theme.status_warn,
        _ => theme.status_good,
    }
}

#[allow(dead_code)]
fn extract_ip(addr: &str) -> Option<&str> {
    if addr == "*:*" || addr.is_empty() {
        return None;
    }
    if let Some(bracket_end) = addr.rfind("]:") {
        Some(&addr[1..bracket_end])
    } else if let Some(colon) = addr.rfind(':') {
        let ip = &addr[..colon];
        if ip == "*" {
            None
        } else {
            Some(ip)
        }
    } else {
        Some(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collectors::connections::Connection;
    use std::collections::VecDeque;

    /// Regression for issue #28 — mouse clicks were using the wrong
    /// window-top, so `compute_window_top` is the seam we want to lock
    /// down. The same value drives both the renderer's auto-scroll and
    /// the mouse hit-tester; if they ever disagree, clicks land on the
    /// wrong row again.
    #[test]
    fn window_top_centers_selection_when_scrolled() {
        // Selection within the first visible window: don't scroll.
        assert_eq!(compute_window_top(0, 100, 20), 0);
        assert_eq!(compute_window_top(5, 100, 20), 0);
        assert_eq!(compute_window_top(19, 100, 20), 0);

        // Selection past the first window: center it. With visible=20,
        // selected=30 → window_top = 30 - 10 = 20. The selected row sits
        // at visible_row=10 (middle of the table).
        assert_eq!(compute_window_top(30, 100, 20), 20);
        assert_eq!(compute_window_top(50, 100, 20), 40);

        // Selection near the end: clamp so the last visible row is the
        // last row of the list (don't scroll past it).
        assert_eq!(compute_window_top(99, 100, 20), 80);
        assert_eq!(compute_window_top(95, 100, 20), 80);
    }

    #[test]
    fn window_top_handles_short_lists() {
        // Total shorter than visible window → no scroll.
        assert_eq!(compute_window_top(0, 5, 20), 0);
        assert_eq!(compute_window_top(4, 5, 20), 0);
    }

    fn conn(proc: &str, state: &str, remote: &str) -> Connection {
        Connection {
            protocol: "TCP".into(),
            local_addr: "127.0.0.1:1234".into(),
            remote_addr: remote.into(),
            state: state.into(),
            pid: Some(1),
            process_name: Some(proc.into()),
            handshake_rtt_us: None,
            rx_rate: None,
            tx_rate: None,
            attribution: Default::default(),
            evidence: Default::default(),
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        }
    }

    // ── Grouped tree ────────────────────────────────────────────────────

    /// A view of `flat` under `group: none`, or of `groups` as given.
    fn view_of(flat: Vec<Connection>, groups: Vec<(&str, Vec<Connection>)>) -> ConnView {
        let mut conns = flat;
        let flat: Vec<usize> = (0..conns.len()).collect();
        let groups = groups
            .into_iter()
            .map(|(key, children)| {
                let refs: Vec<&Connection> = children.iter().collect();
                let rollup = rollup(true, &refs);
                let start = conns.len();
                conns.extend(children);
                ConnGroup {
                    key: key.into(),
                    rollup,
                    children: (start..conns.len()).collect(),
                }
            })
            .collect();
        ConnView {
            generation: 0,
            state_filter: ConnectionStateFilter::All,
            text_filter: None,
            group: ConnectionGroup::Process,
            sort: None,
            capturing: false,
            counts: count_states(&conns),
            text_matches: conns.len(),
            rate_coverage: None,
            conns: Arc::new(conns),
            groups,
            flat,
        }
    }

    /// The parent row must summarise its children accurately — a rollup that
    /// undercounts is worse than no rollup, because the user stops expanding.
    #[test]
    fn rollup_summarises_its_children() {
        let mut a = conn("claude", "ESTABLISHED", "1.2.3.4:443");
        a.pid = Some(10);
        a.rx_rate = Some(100.0);
        a.tx_rate = Some(10.0);
        a.handshake_rtt_us = Some(5000.0);
        let mut b = conn("claude", "ESTABLISHED", "5.6.7.8:443");
        b.pid = Some(11);
        b.rx_rate = Some(50.0);
        b.handshake_rtt_us = Some(2000.0);
        let r = rollup(true, &[&a, &b]);
        assert_eq!(r.conns, 2);
        assert_eq!(r.facets, 2, "two distinct pids");
        assert_eq!(r.rx_rate, 150.0);
        assert_eq!(r.tx_rate, 10.0);
        assert_eq!(r.rtt_us, Some(2000.0), "best RTT, not the first one");
        assert_eq!(r.state, "ESTABLISHED");
        assert_eq!(r.state_count, 2);
        assert!(!r.degraded);
    }

    /// A rollup must never hide a problem that an expanded child would show.
    #[test]
    fn rollup_surfaces_retransmits_from_any_child() {
        let a = conn("curl", "ESTABLISHED", "1.2.3.4:443");
        let mut b = conn("curl", "ESTABLISHED", "5.6.7.8:443");
        b.retransmits = 3;
        assert!(rollup(true, &[&a, &b]).degraded);
    }

    /// UDP rows carry an empty state. Counting them would make "" the winner
    /// and render the cell as a bare fraction of nothing.
    #[test]
    fn dominant_state_ignores_stateless_rows() {
        let udp = conn("chrome", "", "*:*");
        let tcp = conn("chrome", "ESTABLISHED", "1.2.3.4:443");
        let (state, n) = dominant_state(&[&udp, &udp, &udp, &tcp]);
        assert_eq!(state, "ESTABLISHED");
        assert_eq!(n, 1, "1 of 4 has a named state");

        // All stateless: say so rather than emitting an empty cell.
        let (state, n) = dominant_state(&[&udp, &udp]);
        assert_eq!(state, "—");
        assert_eq!(n, 2);
    }

    #[test]
    fn rows_emit_a_header_then_its_children_and_fold_hides_only_children() {
        let view = view_of(
            Vec::new(),
            vec![
                (
                    "claude",
                    vec![
                        conn("claude", "ESTABLISHED", "1.2.3.4:443"),
                        conn("claude", "ESTABLISHED", "5.6.7.8:443"),
                    ],
                ),
                ("gh", vec![conn("gh", "ESTABLISHED", "9.9.9.9:443")]),
            ],
        );

        let rows = view.rows(&crate::ui::tree::FoldState::new(false));
        assert_eq!(rows.len(), 5);
        assert!(matches!(rows[0], ConnRow::Parent { .. }));
        assert!(matches!(rows[1], ConnRow::Conn { .. }));
        assert!(matches!(rows[3], ConnRow::Parent { .. }));

        let mut fold = crate::ui::tree::FoldState::new(false);
        fold.toggle("claude");
        let rows = view.rows(&fold);
        assert_eq!(rows.len(), 3, "claude's two children are hidden");
        assert!(
            matches!(&rows[0], ConnRow::Parent { group, collapsed } if group.key == "claude" && *collapsed),
            "the header itself must survive folding"
        );
    }

    /// `group: none` is a flat peer list — a tree with one child per parent
    /// would be strictly worse, so it must not grow headers.
    #[test]
    fn ungrouped_view_has_no_header_rows() {
        let view = view_of(
            vec![
                conn("a", "ESTABLISHED", "1.1.1.1:443"),
                conn("b", "ESTABLISHED", "2.2.2.2:443"),
            ],
            Vec::new(),
        );
        let rows = view.rows(&crate::ui::tree::FoldState::new(false));
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| matches!(r, ConnRow::Conn { .. })));
    }

    /// Row indices now include headers, so anything that resolves "the
    /// selected connection" by indexing the *connection* list would silently
    /// act on the wrong flow. A header must resolve to no connection at all.
    #[test]
    fn a_header_row_is_not_a_connection() {
        let view = view_of(
            Vec::new(),
            vec![("claude", vec![conn("claude", "ESTABLISHED", "1.2.3.4:443")])],
        );
        let rows = view.rows(&crate::ui::tree::FoldState::new(false));
        assert!(
            !matches!(rows[0], ConnRow::Conn { .. }),
            "row 0 is the header, not the connection beneath it"
        );
        match &rows[1] {
            ConnRow::Conn { conn } => assert_eq!(conn.remote_addr, "1.2.3.4:443"),
            ConnRow::Parent { .. } => panic!("row 1 should be the connection"),
        }
    }

    /// A table with what sorting has to get right: names that differ only in
    /// case, rows with no owner beside owners named as the placeholders are,
    /// rates that tie, addresses of each family and none.
    fn awkward_table() -> Vec<Connection> {
        let mut rows = crate::testutil::connections::synthetic_connections(1_500, 5);
        for (i, row) in rows.iter_mut().enumerate() {
            match i % 9 {
                0 => row.process_name = row.process_name.take().map(|n| n.to_uppercase()),
                1 => row.process_name = None,
                2 => row.process_name = Some("~".into()),
                3 => row.process_name = Some("—".into()),
                4 => row.process_name = Some("Σας".into()),
                _ => {}
            }
            row.rx_rate = (i % 3 != 0).then_some((i % 4) as f64 * 100.0);
            row.tx_rate = (i % 5 != 0).then_some((i % 2) as f64 * 100.0);
            match i % 31 {
                0 => row.remote_addr = "*:*".into(),
                1 => row.remote_addr = String::new(),
                2 => row.remote_addr = "example.com:443".into(),
                _ => {}
            }
        }
        rows
    }

    fn column_cmp(column: &str, a: &Connection, b: &Connection) -> std::cmp::Ordering {
        use crate::sort::{cmp_case_insensitive, cmp_f64, cmp_ip_addr};
        let total = |c: &Connection| c.rx_rate.unwrap_or(0.0) + c.tx_rate.unwrap_or(0.0);
        match column {
            "Process" => cmp_case_insensitive(
                a.process_name.as_deref().unwrap_or(""),
                b.process_name.as_deref().unwrap_or(""),
            ),
            "PID" => a.pid.cmp(&b.pid),
            "Proto" => cmp_case_insensitive(&a.protocol, &b.protocol),
            "State" => cmp_case_insensitive(&a.state, &b.state),
            "Local Address" => cmp_ip_addr(&a.local_addr, &b.local_addr),
            "Remote Address" => cmp_ip_addr(&a.remote_addr, &b.remote_addr),
            "Down/Up" => cmp_f64(total(a), total(b)),
            _ => unreachable!("{column} has no comparator here"),
        }
    }

    /// The cached keys stand in for these comparators, so each column has to
    /// come out in the order they give it, ties included, in both directions.
    #[test]
    fn each_column_sorts_as_its_comparator_does() {
        let table = awkward_table();
        for (i, column) in COLUMNS.iter().enumerate() {
            for ascending in [true, false] {
                let mut got = table.clone();
                sort(&mut got, i, ascending);
                let mut want = table.clone();
                want.sort_by(|a, b| {
                    crate::sort::apply_direction(column_cmp(column.name, a, b), ascending)
                });
                let locals = |rows: &[Connection]| -> Vec<String> {
                    rows.iter().map(|c| c.local_addr.clone()).collect()
                };
                assert_eq!(locals(&got), locals(&want), "{} {ascending}", column.name);
            }
        }
    }

    /// What grouping came to when the rows were sorted by comparators and
    /// grouped by owned keys: each group's key and its children, in order.
    fn grouped_by_comparators(
        conns: &[Connection],
        by_process: bool,
    ) -> Vec<(String, Vec<String>)> {
        use crate::sort::{cmp_case_insensitive, cmp_f64};
        let mut sorted: Vec<&Connection> = conns.iter().collect();
        sorted.sort_by(|a, b| {
            if by_process {
                cmp_case_insensitive(
                    a.process_name.as_deref().unwrap_or("~"),
                    b.process_name.as_deref().unwrap_or("~"),
                )
                .then_with(|| cmp_f64(a.rx_rate.unwrap_or(0.0), b.rx_rate.unwrap_or(0.0)).reverse())
                .then_with(|| a.remote_addr.cmp(&b.remote_addr))
            } else {
                cmp_case_insensitive(host_only(&a.remote_addr), host_only(&b.remote_addr))
                    .then_with(|| a.remote_addr.cmp(&b.remote_addr))
                    .then_with(|| {
                        cmp_case_insensitive(
                            a.process_name.as_deref().unwrap_or("~"),
                            b.process_name.as_deref().unwrap_or("~"),
                        )
                    })
            }
        });
        let mut groups = crate::ui::tree::group_by(sorted, |c: &&Connection| {
            if by_process {
                c.process_name.clone().unwrap_or_else(|| "—".into())
            } else {
                host_only(&c.remote_addr).to_string()
            }
        });
        let rate = |g: &(String, Vec<&Connection>)| -> f64 {
            let rx: f64 = g.1.iter().filter_map(|c| c.rx_rate).sum();
            let tx: f64 = g.1.iter().filter_map(|c| c.tx_rate).sum();
            rx + tx
        };
        groups.sort_by(|a, b| {
            cmp_f64(rate(a), rate(b))
                .reverse()
                .then_with(|| cmp_case_insensitive(&a.0, &b.0))
        });
        groups
            .into_iter()
            .map(|(key, children)| {
                let locals = children.iter().map(|c| c.local_addr.clone()).collect();
                (key, locals)
            })
            .collect()
    }

    #[test]
    fn groups_come_out_as_the_comparators_ordered_them() {
        let table = awkward_table();
        for (mode, by_process) in [
            (ConnectionGroup::Process, true),
            (ConnectionGroup::Remote, false),
        ] {
            let mut app =
                crate::app::App::prepare_with_config(crate::config::NetwatchConfig::default());
            app.ui.connection_group = mode;
            app.connection_collector.publish_for_test(table.clone());
            let view = fresh_view_for_test(&app);
            let got: Vec<(String, Vec<String>)> = view
                .groups
                .iter()
                .map(|g| {
                    let locals = g
                        .children
                        .iter()
                        .map(|&i| view.conns[i].local_addr.clone())
                        .collect();
                    (g.key.clone(), locals)
                })
                .collect();
            assert_eq!(got, grouped_by_comparators(&view.conns, by_process));
        }
    }

    #[test]
    fn host_only_keeps_the_brackets_and_drops_the_port() {
        assert_eq!(host_only("1.2.3.4:443"), "1.2.3.4");
        assert_eq!(host_only("[2001:db8::1]:443"), "[2001:db8::1]");
        assert_eq!(host_only("[::1]"), "[:");
        assert_eq!(host_only("example.com"), "example.com");
        assert_eq!(host_only(""), "");
    }

    fn table_title(app: &crate::app::App) -> String {
        table_title_at(app, 200)
    }

    fn table_title_at(app: &crate::app::App, width: u16) -> String {
        use ratatui::{backend::TestBackend, Terminal};
        let mut terminal = Terminal::new(TestBackend::new(width, 50)).unwrap();
        terminal.draw(|f| render(f, app, f.area())).unwrap();
        let buffer = terminal.backend().buffer();
        let table = layout_chunks(buffer.area)[2];
        (0..buffer.area.width)
            .map(|x| buffer[(x, table.y)].symbol())
            .collect()
    }

    /// Flows numbered `flows` in the capture's stream tracker.
    fn track_flows(app: &crate::app::App, flows: std::ops::Range<usize>) {
        use crate::collectors::packets::StreamProtocol;
        let mut tracker = app.packet_collector.stream_tracker.lock().unwrap();
        for i in flows {
            let src = format!("10.0.{}.{}", i / 256, i % 256);
            tracker.track_packet(
                &src,
                12345,
                "1.2.3.4",
                80,
                StreamProtocol::Tcp,
                b"",
                i as u64,
                "t",
                None,
                None,
                i as u64,
            );
        }
    }

    /// Enough new flows past the tracker's limits to make it sweep.
    fn sweep_the_tracker(app: &crate::app::App, numbered_from: usize) {
        use crate::collectors::packets::{MAX_STREAMS, STREAM_EVICT_BATCH};
        track_flows(
            app,
            numbered_from..numbered_from + MAX_STREAMS + STREAM_EVICT_BATCH + 1,
        );
        let tracker = app.packet_collector.stream_tracker.lock().unwrap();
        assert!(tracker.session_dropped_flows() > 0);
    }

    /// A table whose flows have no rate, but for the first `rated`.
    fn table_with_rates(rated: usize) -> (Vec<Connection>, usize) {
        let mut rows = crate::testutil::connections::synthetic_connections(2_000, 5);
        let mut flows = 0;
        for row in &mut rows {
            let rate = has_stream_key(row) && flows < rated;
            row.rx_rate = rate.then_some(1.0);
            row.tx_rate = rate.then_some(1.0);
            flows += usize::from(has_stream_key(row));
        }
        (rows, flows)
    }

    /// The note counts the rows that have a rate. The tracker's own count says
    /// nothing about them: it may hold flows the table no longer lists.
    #[test]
    fn the_note_counts_the_table_flows_that_have_a_rate() {
        let (rows, flows) = table_with_rates(431);
        let note = format!("rates: 431 of {} flows", widgets::format_count(flows));

        let mut app =
            crate::app::App::prepare_with_config(crate::config::NetwatchConfig::default());
        app.packet_collector.mark_capturing_for_test();
        app.connection_collector.publish_for_test(rows.clone());
        assert!(!table_title(&app).contains("rates:"), "nothing dropped");

        // A full tracker that has dropped nothing has nothing to report.
        track_flows(&app, 0..1_280);
        app.connection_collector.publish_for_test(rows.clone());
        assert!(!table_title(&app).contains("rates:"), "full, none dropped");

        sweep_the_tracker(&app, 2_000);
        // Read once per table: the next poll brings it.
        assert!(!table_title(&app).contains("rates:"), "the same table");
        app.connection_collector.publish_for_test(rows.clone());
        let title = table_title(&app);
        assert!(title.contains(&note), "{title}");

        // Whichever filters narrow the rows on screen: the note is about the
        // table.
        app.ui.connection_group = ConnectionGroup::None;
        app.ui.connection_filter_active = Some("proc-01".into());
        let title = table_title(&app);
        assert!(title.contains(&note), "{title}");

        // Every flow with a rate, there is nothing to say.
        let (rows, flows) = table_with_rates(usize::MAX);
        assert!(flows > 0);
        app.connection_collector.publish_for_test(rows);
        assert!(!table_title(&app).contains("rates:"), "all rated");
    }

    /// The byte budget can drop flows long before the flow count is reached,
    /// and a row's rate goes with its flow either way.
    #[test]
    fn the_note_shows_when_the_byte_budget_drops_flows() {
        use crate::collectors::connections::connection_stream_key;
        let app = crate::app::App::prepare_with_config(crate::config::NetwatchConfig::default());
        app.packet_collector.mark_capturing_for_test();
        let mut rows = crate::testutil::connections::synthetic_connections(2_000, 5);

        let snapshot = {
            let mut tracker = app.packet_collector.stream_tracker.lock().unwrap();
            tracker.set_byte_budget_for_test(1 << 20);
            let payload = [0u8; 16 * 1024];
            for (i, row) in rows.iter().enumerate() {
                if let Some((key, _)) = connection_stream_key(row) {
                    tracker.track_packet(
                        &key.addr_a.0,
                        key.addr_a.1,
                        &key.addr_b.0,
                        key.addr_b.1,
                        key.protocol,
                        &payload,
                        i as u64,
                        "t",
                        None,
                        None,
                        i as u64,
                    );
                }
            }
            assert!(tracker.session_dropped_flows() > 0);
            tracker.snapshot_bytes()
        };
        assert!(snapshot.len() < 1_024, "{} flows held", snapshot.len());

        // As the poll leaves them: a rate for each flow the tracker still has.
        let (mut rated, mut flows) = (0, 0);
        for row in &mut rows {
            let tracked = connection_stream_key(row).map(|(key, _)| snapshot.contains_key(&key));
            flows += usize::from(tracked.is_some());
            let tracked = tracked == Some(true);
            rated += usize::from(tracked);
            row.rx_rate = tracked.then_some(1.0);
            row.tx_rate = tracked.then_some(1.0);
        }
        assert!(rated > 0 && rated < flows);
        app.connection_collector.publish_for_test(rows);
        let title = table_title(&app);
        let note = format!(
            "rates: {} of {} flows",
            widgets::format_count(rated),
            widgets::format_count(flows)
        );
        assert!(title.contains(&note), "{title}");
    }

    /// Streams outlive a stopped capture. They say nothing about a capture
    /// that is not running, or one that has only just started.
    #[test]
    fn the_note_is_about_the_running_capture() {
        let (rows, _) = table_with_rates(431);
        let mut app =
            crate::app::App::prepare_with_config(crate::config::NetwatchConfig::default());
        app.packet_collector.mark_capturing_for_test();
        sweep_the_tracker(&app, 0);
        app.connection_collector.publish_for_test(rows.clone());
        assert!(table_title(&app).contains("rates: 431 of"), "running");

        // Stopping is seen at once, with no new table.
        app.packet_collector.stop_capture();
        assert!(!table_title(&app).contains("rates:"), "stopped");
        app.connection_collector.publish_for_test(rows.clone());
        assert!(!table_title(&app).contains("rates:"), "stopped, new table");

        // A restart keeps the streams and has followed nothing yet.
        app.packet_collector.start_session_for_test();
        app.packet_collector.mark_capturing_for_test();
        app.connection_collector.publish_for_test(rows.clone());
        assert!(!table_title(&app).contains("rates:"), "restarted");

        sweep_the_tracker(&app, 5_000);
        app.connection_collector.publish_for_test(rows.clone());
        assert!(
            table_title(&app).contains("rates: 431 of"),
            "dropping again"
        );

        // `X` empties the tracker.
        app.packet_collector.clear();
        app.connection_collector.publish_for_test(rows);
        assert!(!table_title(&app).contains("rates:"), "cleared");
    }

    /// The note goes first when the border row is short. Where it does not
    /// fit, the row is exactly what it would be without one, and that includes
    /// a warning already too long to leave the title whole.
    #[test]
    fn the_rates_note_gives_way_to_the_rest_of_its_row() {
        use ratatui::{buffer::Buffer, layout::Rect, widgets::Widget};
        const NOTE: &str = " rates: 1,431 of 10,800 flows ";
        const WARNING: &str = " ⚠ ebpf unavailable · new connections unattributed ";
        const COUNTS: &str = " 150 processes · 12000 conns  group: process ";
        let theme = crate::theme::dark();
        let row = |width: u16, warning: Option<&str>, note: Option<&str>| -> String {
            let area = Rect::new(0, 0, width, 3);
            let mut buffer = Buffer::empty(area);
            table_block(
                &theme,
                width,
                warning.map(str::to_string),
                note.map(str::to_string),
                COUNTS.to_string(),
            )
            .render(area, &mut buffer);
            (0..width).map(|x| buffer[(x, 0)].symbol()).collect()
        };

        for (width, warning, fits) in [
            (60, None, false),
            (80, None, false),
            (100, None, true),
            (120, None, true),
            (60, Some(WARNING), false),
            (80, Some(WARNING), false),
            (100, Some(WARNING), false),
            (120, Some(WARNING), false),
            (160, Some(WARNING), true),
        ] {
            let with_note = row(width, warning, Some(NOTE));
            let without = row(width, warning, None);
            if fits {
                assert!(with_note.contains(NOTE), "{width}: {with_note}");
                assert!(with_note.contains(" connections "), "{width}: {with_note}");
                assert!(with_note.contains(COUNTS), "{width}: {with_note}");
                assert!(
                    with_note.contains(warning.unwrap_or("")),
                    "{width}: {with_note}"
                );
            } else {
                assert_eq!(with_note, without, "at {width}");
            }
        }
        // The warning keeps the place the note would have taken.
        let row_at_120 = row(120, Some(WARNING), Some(NOTE));
        assert!(row_at_120.contains(WARNING), "{row_at_120}");
        assert!(row_at_120.contains(" connections "), "{row_at_120}");
    }

    /// The same through the real table, where the note is live.
    #[test]
    fn the_table_shows_the_note_only_where_it_fits() {
        let (rows, _) = table_with_rates(431);
        let app = crate::app::App::prepare_with_config(crate::config::NetwatchConfig::default());
        app.packet_collector.mark_capturing_for_test();
        sweep_the_tracker(&app, 0);
        app.connection_collector.publish_for_test(rows);
        for (width, fits) in [(60, false), (80, false), (100, true), (120, true)] {
            let title = table_title_at(&app, width);
            assert_eq!(title.contains("rates:"), fits, "{title}");
            assert!(title.contains(" connections "), "{title}");
            assert!(title.contains("group: process"), "{title}");
        }
    }

    #[test]
    fn filter_matches_process_name() {
        let c = conn("apache2", "ESTABLISHED", "1.2.3.4:443");
        assert!(matches_filter(&c, "apache"));
        assert!(matches_filter(&c, "APACHE")); // case insensitive
    }

    #[test]
    fn filter_matches_state() {
        let c = conn("firefox", "CLOSE_WAIT", "1.2.3.4:443");
        assert!(matches_filter(&c, "close_wait"));
        assert!(matches_filter(&c, "CLOSE"));
    }

    #[test]
    fn filter_matches_remote_address() {
        let c = conn("firefox", "ESTABLISHED", "192.168.1.50:443");
        assert!(matches_filter(&c, "192.168"));
        assert!(matches_filter(&c, ":443"));
    }

    #[test]
    fn filter_rejects_non_matching() {
        let c = conn("firefox", "ESTABLISHED", "10.0.0.1:80");
        assert!(!matches_filter(&c, "apache"));
        assert!(!matches_filter(&c, "close_wait"));
        assert!(!matches_filter(&c, "192.168"));
    }

    #[test]
    fn filter_handles_missing_process_name() {
        let mut c = conn("", "LISTEN", "0.0.0.0:22");
        c.process_name = None;
        assert!(!matches_filter(&c, "sshd"));
        assert!(matches_filter(&c, "listen"));
    }

    #[test]
    fn sparkline_empty() {
        let h = VecDeque::new();
        assert_eq!(rtt_sparkline(&h), "");
    }

    #[test]
    fn sparkline_single_sample() {
        let h = VecDeque::from(vec![10.0]);
        let s = rtt_sparkline(&h);
        assert_eq!(s.chars().count(), 1);
        // Single sample → flat line → middle block
        assert_eq!(s, "▄");
    }

    #[test]
    fn sparkline_flat_line() {
        let h = VecDeque::from(vec![5.0, 5.0, 5.0, 5.0]);
        let s = rtt_sparkline(&h);
        assert_eq!(s.chars().count(), 4);
        // All same → all middle blocks
        assert!(s.chars().all(|c| c == '▄'));
    }

    #[test]
    fn sparkline_ascending() {
        let h = VecDeque::from(vec![0.0, 50.0, 100.0]);
        let s = rtt_sparkline(&h);
        let chars: Vec<char> = s.chars().collect();
        assert_eq!(chars.len(), 3);
        assert_eq!(chars[0], '▁'); // min
        assert_eq!(chars[2], '█'); // max
    }

    #[test]
    fn sparkline_descending() {
        let h = VecDeque::from(vec![100.0, 50.0, 0.0]);
        let s = rtt_sparkline(&h);
        let chars: Vec<char> = s.chars().collect();
        assert_eq!(chars[0], '█'); // max
        assert_eq!(chars[2], '▁'); // min
    }

    #[test]
    fn closing_states_take_the_error_colour_in_either_spelling() {
        let theme = crate::theme::dark();
        for s in [
            "CLOSE_WAIT",
            "CLOSE-WAIT",
            "FIN_WAIT_1",
            "FIN-WAIT-1",
            "FIN_WAIT_2",
            "FIN-WAIT-2",
        ] {
            assert_eq!(conn_state_color(s, &theme), theme.status_error, "{s}");
        }
        assert_eq!(conn_state_color("TIME-WAIT", &theme), theme.status_warn);
        assert_eq!(conn_state_color("SYN-SENT", &theme), theme.text_muted);
    }

    #[test]
    fn sparkline_color_green_low() {
        let h = VecDeque::from(vec![10.0, 15.0, 12.0]);
        let theme = crate::theme::dark();
        assert_eq!(rtt_sparkline_color(&h, &theme), theme.status_good);
    }

    #[test]
    fn sparkline_color_yellow_medium() {
        let h = VecDeque::from(vec![10.0, 60.0]);
        let theme = crate::theme::dark();
        assert_eq!(rtt_sparkline_color(&h, &theme), theme.status_warn);
    }

    #[test]
    fn sparkline_color_red_high() {
        let h = VecDeque::from(vec![10.0, 150.0]);
        let theme = crate::theme::dark();
        assert_eq!(rtt_sparkline_color(&h, &theme), theme.status_error);
    }

    #[test]
    fn sparkline_twenty_samples() {
        let h: VecDeque<f64> = (0..20).map(|i| i as f64 * 5.0).collect();
        let s = rtt_sparkline(&h);
        assert_eq!(s.chars().count(), 20);
    }

    /// The detail strip shows WHOIS for the selected row only after W. It
    /// used to queue the lookup itself, so moving the cursor down the table
    /// sent each remote address to rdap.org. So did a parked cursor: the
    /// selection is a row index, and the live table changes under it.
    #[test]
    fn drawing_the_selected_connection_queues_no_whois_lookup() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut app =
            crate::app::App::prepare_with_config(crate::config::NetwatchConfig::default());
        app.connection_collector
            .publish_for_test(vec![conn("curl", "ESTABLISHED", "8.8.8.8:443")]);
        app.ui.connection_group = ConnectionGroup::None;

        let mut terminal = Terminal::new(TestBackend::new(200, 50)).unwrap();
        terminal.draw(|f| render(f, &app, f.area())).unwrap();
        let screen: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(
            screen.contains("127.0.0.1:1234  →  8.8.8.8:443"),
            "detail not drawn"
        );
        assert_eq!(app.whois_cache.queued_for_test(), Vec::<String>::new());

        // A new connection takes row 0 with no key pressed.
        app.connection_collector
            .publish_for_test(vec![conn("curl", "ESTABLISHED", "9.9.9.9:443")]);
        terminal.draw(|f| render(f, &app, f.area())).unwrap();
        assert_eq!(app.ui.scroll.connection_scroll, 0);
        assert_eq!(app.whois_cache.queued_for_test(), Vec::<String>::new());
    }

    /// The detail graph spreads the cache's whole window across the pane, in
    /// either graph style, and its header names that window. It padded the
    /// 30 samples to one per column, so a pane wider than 30 columns drew
    /// only its right edge (15 columns in the dots style), under a header
    /// that said `RX 30s` at every refresh rate.
    #[test]
    fn the_detail_graph_fills_the_pane_with_the_window_it_names() {
        use crate::graph::GraphStyle;
        use ratatui::{backend::TestBackend, Terminal};
        let mut app =
            crate::app::App::prepare_with_config(crate::config::NetwatchConfig::default());
        let c = conn("curl", "ESTABLISHED", "8.8.8.8:443");
        app.caches.top_conn_history.insert(
            ("curl".into(), "8.8.8.8".into()),
            vec![1000; crate::app::TOP_CONN_HISTORY_LEN].into(),
        );
        let area = Rect::new(0, 0, 80, 6);
        for style in [GraphStyle::Bars, GraphStyle::Dots] {
            app.graph_style = style;
            // 30 samples at each rate. 150 seconds is not `3m`.
            for (refresh_rate_ms, label) in [
                (1000, "RX 30s"),
                (500, "RX 15s"),
                (4000, "RX 2m"),
                (4500, "RX 135s"),
                (5000, "RX 150s"),
            ] {
                app.user_config.refresh_rate_ms = refresh_rate_ms;
                let mut terminal =
                    Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
                terminal
                    .draw(|f| render_detail_right(f, &app, area, &c))
                    .unwrap();
                let buf = terminal.backend().buffer();
                let header: String = (0..area.width).map(|x| buf[(x, 0)].symbol()).collect();
                assert_eq!(header.trim_end(), label);
                // A full-scale sample reaches the plot's top row.
                for x in 0..area.width {
                    assert_ne!(
                        buf[(x, 1)].symbol(),
                        " ",
                        "column {x} empty, {style:?} at {refresh_rate_ms} ms"
                    );
                }
            }
        }
    }
}
