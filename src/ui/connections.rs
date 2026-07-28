use crate::app::{App, AttributionStatus, ConnectionGroup, ConnectionStateFilter};
use crate::collectors::connections::AttributionSource;
use crate::collectors::connections::Connection;
use crate::collectors::traceroute::TracerouteStatus;
use crate::sort::{
    apply_direction, cmp_case_insensitive, cmp_f64, cmp_ip_addr, SortColumn, TabSortState,
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
};

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

pub fn sort(
    conns: &mut [crate::collectors::connections::Connection],
    column: usize,
    ascending: bool,
) {
    let col_name = COLUMNS.get(column).map(|c| c.name).unwrap_or("");
    conns.sort_by(|a, b| {
        let ord = match col_name {
            "Process" => cmp_case_insensitive(
                a.process_name.as_deref().unwrap_or(""),
                b.process_name.as_deref().unwrap_or(""),
            ),
            "PID" => a.pid.cmp(&b.pid),
            "Proto" => cmp_case_insensitive(&a.protocol, &b.protocol),
            "State" => cmp_case_insensitive(&a.state, &b.state),
            "Local Address" => cmp_ip_addr(&a.local_addr, &b.local_addr),
            "Remote Address" => cmp_ip_addr(&a.remote_addr, &b.remote_addr),
            "Down/Up" => {
                let total = |c: &crate::collectors::connections::Connection| {
                    c.rx_rate.unwrap_or(0.0) + c.tx_rate.unwrap_or(0.0)
                };
                cmp_f64(total(a), total(b))
            }
            _ => std::cmp::Ordering::Equal,
        };
        apply_direction(ord, ascending)
    });
}

/// Layout constraints for the Connections tab. Kept as a function so the
/// renderer and the mouse hit-tester share a single source of truth — when
/// the chip row or detail strip's height changes, both sides update together.
fn layout_chunks(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
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
    let block = Block::default().borders(Borders::ALL);
    block.inner(outer)
}

/// Centered-on-selected window top, matching the renderer's auto-scroll
/// behaviour. Pure function so both sides can compute the same value.
pub(crate) fn compute_window_top(selected: usize, total: usize, visible_rows: usize) -> usize {
    crate::ui::tree::window_top(selected, total, visible_rows)
}

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = layout_chunks(area);

    render_header(f, app, chunks[0]);
    render_chip_row(f, app, chunks[1]);
    render_connection_table(f, app, chunks[2]);
    render_detail_strip(f, app, chunks[3]);
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

fn render_chip_row(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let conns = app.connection_collector.connections();
    let counts = count_states(&conns);
    drop(conns);

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

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    let conns = app.connection_collector.connections();
    let total = conns.len();
    let filter = active_connection_filter(app);
    let shown = if let Some(f) = filter.as_deref() {
        conns.iter().filter(|c| matches_filter(c, f)).count()
    } else {
        total
    };
    drop(conns);

    let mut extra = vec![Span::raw("  ")];
    if filter.is_some() {
        extra.push(Span::styled(
            format!("{shown}/{total} connections"),
            Style::default().fg(app.theme.status_warn),
        ));
        extra.push(Span::raw("  "));
        extra.push(Span::styled(
            format!("filter: {}", filter.as_deref().unwrap_or("")),
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

    crate::ui::widgets::render_header_with_extra(f, app, area, extra);
}

fn active_connection_filter(app: &App) -> Option<String> {
    if let Some(ref f) = app.ui.connection_filter_active {
        return Some(f.clone());
    }
    if app.ui.connection_filter_input && !app.ui.connection_filter_text.is_empty() {
        return Some(app.ui.connection_filter_text.clone());
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

pub(crate) fn filtered_sorted_conns(app: &App) -> Vec<Connection> {
    let mut conns: Vec<Connection> = (*app.connection_collector.connections()).clone();

    // Chip-based state filter
    conns.retain(|c| app.ui.connection_state_filter.matches(&c.state));

    // Free-text filter (slash mode)
    if let Some(ref f) = active_connection_filter(app) {
        conns.retain(|c| matches_filter(c, f));
    }

    // Group/sort: process keeps process-grouped, remote groups by host, none sorts by RX desc
    match app.ui.connection_group {
        ConnectionGroup::Process => {
            conns.sort_by(|a, b| {
                cmp_case_insensitive(
                    a.process_name.as_deref().unwrap_or("~"),
                    b.process_name.as_deref().unwrap_or("~"),
                )
                .then_with(|| {
                    let ar = a.rx_rate.unwrap_or(0.0);
                    let br = b.rx_rate.unwrap_or(0.0);
                    cmp_f64(ar, br).reverse()
                })
                .then_with(|| a.remote_addr.cmp(&b.remote_addr))
            });
        }
        ConnectionGroup::Remote => {
            conns.sort_by(|a, b| {
                let ah = host_only(&a.remote_addr);
                let bh = host_only(&b.remote_addr);
                cmp_case_insensitive(&ah, &bh)
                    .then_with(|| a.remote_addr.cmp(&b.remote_addr))
                    .then_with(|| {
                        cmp_case_insensitive(
                            a.process_name.as_deref().unwrap_or("~"),
                            b.process_name.as_deref().unwrap_or("~"),
                        )
                    })
            });
        }
        ConnectionGroup::None => {
            // Apply sort_states-driven sort or default RX desc
            let sort_state = app.ui.sort_states.get(&crate::app::Tab::Connections);
            let col = sort_state.map(|s| s.column).unwrap_or(0);
            let asc = sort_state.map(|s| s.ascending).unwrap_or(true);
            sort(&mut conns, col, asc);
        }
    }

    conns
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

pub type ConnGroup = crate::ui::tree::Group<ConnRollup, Connection>;

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

/// The connection list in whatever shape the current group mode implies.
///
/// Owns its data so the borrowed row list can be derived from it repeatedly —
/// the renderer, the mouse handler and the key handlers all need the same
/// numbering, and recomputing it independently is how they drift apart.
pub struct ConnView {
    pub groups: Vec<ConnGroup>,
    pub flat: Vec<Connection>,
}

/// The most common *named* state in a group, and how many share it.
///
/// Connectionless rows (UDP) carry an empty state, so counting them would
/// make "" the winner and the cell would render as a bare `11/13` — a
/// fraction of nothing. Only named states compete; a group with none at all
/// says so with an em-dash.
fn dominant_state(conns: &[Connection]) -> (String, usize) {
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

fn rollup(key_is_process: bool, conns: &[Connection]) -> ConnRollup {
    let facets: std::collections::BTreeSet<String> = if key_is_process {
        conns
            .iter()
            .filter_map(|c| c.pid.map(|p| p.to_string()))
            .collect()
    } else {
        conns
            .iter()
            .map(|c| c.process_name.clone().unwrap_or_else(|| "—".into()))
            .collect()
    };
    let (state, state_count) = dominant_state(conns);
    ConnRollup {
        conns: conns.len(),
        facets: facets.len(),
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

/// Build the current view: grouped into a tree, or flat under `group: none`.
pub fn build_view(app: &App) -> ConnView {
    let conns = filtered_sorted_conns(app);
    let group_mode = app.ui.connection_group;
    if matches!(group_mode, ConnectionGroup::None) {
        return ConnView {
            groups: Vec::new(),
            flat: conns,
        };
    }
    let key_is_process = matches!(group_mode, ConnectionGroup::Process);
    let buckets = crate::ui::tree::group_by(conns, |c: &Connection| {
        if key_is_process {
            c.process_name.clone().unwrap_or_else(|| "—".into())
        } else {
            host_only(&c.remote_addr)
        }
    });
    // `filtered_sorted_conns` already ordered by the group key then by rate,
    // so first-seen bucket order is the order the user asked for; only the
    // rollup-level ranking is left, and busiest-first is what a rate column
    // is for.
    let mut groups: Vec<ConnGroup> = buckets
        .into_iter()
        .map(|(key, children)| ConnGroup {
            key,
            rollup: rollup(key_is_process, &children),
            children,
        })
        .collect();
    groups.sort_by(|a, b| {
        cmp_f64(
            a.rollup.rx_rate + a.rollup.tx_rate,
            b.rollup.rx_rate + b.rollup.tx_rate,
        )
        .reverse()
        .then_with(|| cmp_case_insensitive(&a.key, &b.key))
    });
    ConnView {
        groups,
        flat: Vec::new(),
    }
}

impl ConnView {
    /// The visible rows, honouring fold state. Single source of truth for
    /// "what is row N" — renderer and input handlers both go through it.
    pub fn rows(&self, fold: &crate::ui::tree::FoldState) -> Vec<ConnRow<'_>> {
        if self.groups.is_empty() {
            return self
                .flat
                .iter()
                .map(|conn| ConnRow::Conn { conn })
                .collect();
        }
        crate::ui::tree::flatten(&self.groups, fold)
            .into_iter()
            .map(|row| match row {
                crate::ui::tree::Row::Parent { group, collapsed } => {
                    ConnRow::Parent { group, collapsed }
                }
                crate::ui::tree::Row::Child { item, .. } => ConnRow::Conn { conn: item },
            })
            .collect()
    }
}

/// The connection under the cursor, or `None` when a group header is selected.
///
/// Every action that operates on "the selected connection" — traceroute,
/// whois, drill to packets, the detail strip — resolves through here, so a
/// parent row can never be mistaken for the first connection beneath it.
pub fn selected_connection(app: &App) -> Option<Connection> {
    let view = build_view(app);
    let rows = view.rows(&app.ui.connection_collapsed);
    let idx = app
        .ui
        .scroll
        .connection_scroll
        .min(rows.len().saturating_sub(1));
    match rows.get(idx)? {
        ConnRow::Conn { conn } => Some((*conn).clone()),
        ConnRow::Parent { .. } => None,
    }
}

/// The group key under the cursor, from a parent row or any of its children.
pub fn selected_group_key(app: &App) -> Option<String> {
    let view = build_view(app);
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
    build_view(app).rows(&app.ui.connection_collapsed).len()
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

fn host_only(addr: &str) -> String {
    if let Some(stripped) = addr.strip_prefix('[') {
        if let Some(end) = stripped.find("]:") {
            return format!("[{}]", &stripped[..end]);
        }
    }
    if let Some(colon) = addr.rfind(':') {
        addr[..colon].to_string()
    } else {
        addr.to_string()
    }
}

fn render_connection_table(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let view = build_view(app);
    let rows = view.rows(&app.ui.connection_collapsed);
    let conn_count = if view.groups.is_empty() {
        view.flat.len()
    } else {
        view.groups.iter().map(|g| g.rollup.conns).sum()
    };

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
    let block = Block::default()
        .title(Line::from(Span::styled(
            " CONNECTIONS ",
            Style::default().fg(t.brand).bold(),
        )))
        .title(
            Line::from(Span::styled(title_right, Style::default().fg(t.text_muted)))
                .alignment(Alignment::Right),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 {
        return;
    }

    // Column header. Mirrors the layout in `render_conn_row`. The GEO column
    // is only shown when the user has toggled `g`; it sits between REMOTE and
    // STATE so it qualifies the destination it describes.
    let header_text: &str = if app.ui.show_geo {
        "  PROCESS              PROTO  REMOTE                          APP                    GEO           STATE         RX/s         TX/s     RTT    AGE"
    } else {
        "  PROCESS              PROTO  REMOTE                          APP                    STATE         RX/s         TX/s     RTT    AGE"
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
        truncate(&r.state, 12).to_string()
    } else {
        // Mixed states: say which dominates and how many, rather than
        // picking one and implying the group is uniform.
        format!("{} {}/{}", truncate(&r.state, 6), r.state_count, r.conns)
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
            format!(" {:<12}", ""),
            Style::default().fg(t.text_muted),
        ));
    }

    spans.extend([
        Span::styled(
            format!(" {:<12}", truncate(&state_cell, 12)),
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
    let state_color = match conn.state.as_str() {
        "ESTABLISHED" => t.status_good,
        "LISTEN" => t.status_info,
        "TIME_WAIT" | "TIME-WAIT" => t.status_warn,
        "CLOSE_WAIT" | "FIN_WAIT_1" | "FIN_WAIT_2" => t.status_error,
        _ => t.text_muted,
    };
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
                        format!("    {:<28}", truncate(&host, 28))
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
        let geo_str = format_geo_cell(app, &host);
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
        format!("{} ↻{}", truncate(&conn.state, 8), conn.retransmits)
    } else if conn.out_of_order > 0 {
        format!("{} ↹{}", truncate(&conn.state, 8), conn.out_of_order)
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
            format!(" {:<12}", truncate(&state_cell, 12)),
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
    let tracked = app
        .connection_timeline
        .tracked
        .iter()
        .find(|t| t.key == key);
    match tracked {
        Some(t) => format_duration_short(t.first_seen.elapsed()),
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

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

fn render_detail_strip(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let view = build_view(app);
    let rows = view.rows(&app.ui.connection_collapsed);
    let selected_idx = app
        .ui
        .scroll
        .connection_scroll
        .min(rows.len().saturating_sub(1));
    let selected = if rows.is_empty() {
        None
    } else {
        rows.get(selected_idx)
    };

    let title_left = match selected {
        Some(ConnRow::Conn { conn: c }) => {
            let proc = c.process_name.as_deref().unwrap_or("—");
            let host = host_only(&c.remote_addr);
            format!(
                " DETAIL  {}  pid {}  → {} ",
                proc,
                c.pid.map(|p| p.to_string()).unwrap_or_else(|| "—".into()),
                host,
            )
        }
        // A group header has no single flow to detail, so the title carries
        // the rollup rather than pretending one child stands for all of them.
        Some(ConnRow::Parent { group, .. }) => format!(
            " DETAIL  {}  {} connections ",
            group.key, group.rollup.conns
        ),
        None => " DETAIL ".to_string(),
    };

    let block = Block::default()
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
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.border));
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
                format!("{}", conn.local_addr),
                Style::default().fg(t.text_primary),
            ),
            Span::styled("  →  ", Style::default().fg(t.text_muted)),
            Span::styled(
                format!("{}", conn.remote_addr),
                Style::default().fg(t.text_primary),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{}  ", conn.protocol),
                Style::default().fg(t.status_info),
            ),
            Span::styled(
                format!("{}  ", conn.state),
                Style::default().fg(t.text_primary),
            ),
            Span::styled(format!("age {}", age), Style::default().fg(t.text_muted)),
        ]),
        Line::from(""),
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
    let host = host_only(&conn.remote_addr);
    let key = (proc, host);

    let hdr_area = Rect {
        x: area.x,
        y: area.y,
        width: area.width,
        height: 1,
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "RX 30s",
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
            let padded = pad_hist(&data, spark_area.width as usize);
            crate::graph::render(
                f,
                spark_area,
                &padded,
                app.graph_style,
                t.rx_rate,
                t.status_warn,
                app.graph_opts(),
            );
        }
    }
}

fn pad_hist(data: &[u64], target_width: usize) -> Vec<u64> {
    if target_width == 0 {
        return Vec::new();
    }
    if data.len() >= target_width {
        return data[data.len() - target_width..].to_vec();
    }
    let mut padded = vec![0u64; target_width - data.len()];
    padded.extend_from_slice(data);
    padded
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

    let hints = if app.ui.traceroute_view_open {
        vec![
            Span::styled("Esc", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Close  "),
            Span::styled("q", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Quit"),
        ]
    } else {
        let mut v = vec![
            Span::styled("s", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Sort  "),
            Span::styled("/", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Filter  "),
        ];
        // Only advertise folding when there is something to fold — under
        // `group: none` the key does nothing and the hint would be a lie.
        if !matches!(app.ui.connection_group, ConnectionGroup::None) {
            v.push(Span::styled(
                "space",
                Style::default().fg(app.theme.key_hint).bold(),
            ));
            v.push(Span::raw(":Fold  "));
            v.push(Span::styled(
                "z",
                Style::default().fg(app.theme.key_hint).bold(),
            ));
            v.push(Span::raw(if app.ui.connection_collapsed.all_collapsed() {
                ":Expand all  "
            } else {
                ":Fold all  "
            }));
        }
        v.extend([
            Span::styled("T", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":Traceroute  "),
            Span::styled("Enter", Style::default().fg(app.theme.key_hint).bold()),
            Span::raw(":→Packets"),
        ]);
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
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
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
            app_protocol: None,
            retransmits: 0,
            out_of_order: 0,
        }
    }

    // ── Grouped tree ────────────────────────────────────────────────────

    fn group_of(key: &str, conns: Vec<Connection>, by_process: bool) -> ConnGroup {
        ConnGroup {
            key: key.into(),
            rollup: rollup(by_process, &conns),
            children: conns,
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
        let r = rollup(true, &[a, b]);
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
        assert!(rollup(true, &[a, b]).degraded);
    }

    /// UDP rows carry an empty state. Counting them would make "" the winner
    /// and render the cell as a bare fraction of nothing.
    #[test]
    fn dominant_state_ignores_stateless_rows() {
        let udp = conn("chrome", "", "*:*");
        let tcp = conn("chrome", "ESTABLISHED", "1.2.3.4:443");
        let (state, n) = dominant_state(&[udp.clone(), udp.clone(), udp.clone(), tcp]);
        assert_eq!(state, "ESTABLISHED");
        assert_eq!(n, 1, "1 of 4 has a named state");

        // All stateless: say so rather than emitting an empty cell.
        let (state, n) = dominant_state(&[udp.clone(), udp]);
        assert_eq!(state, "—");
        assert_eq!(n, 2);
    }

    #[test]
    fn rows_emit_a_header_then_its_children_and_fold_hides_only_children() {
        let groups = vec![
            group_of(
                "claude",
                vec![
                    conn("claude", "ESTABLISHED", "1.2.3.4:443"),
                    conn("claude", "ESTABLISHED", "5.6.7.8:443"),
                ],
                true,
            ),
            group_of("gh", vec![conn("gh", "ESTABLISHED", "9.9.9.9:443")], true),
        ];
        let view = ConnView {
            groups,
            flat: Vec::new(),
        };

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
        let view = ConnView {
            groups: Vec::new(),
            flat: vec![
                conn("a", "ESTABLISHED", "1.1.1.1:443"),
                conn("b", "ESTABLISHED", "2.2.2.2:443"),
            ],
        };
        let rows = view.rows(&crate::ui::tree::FoldState::new(false));
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| matches!(r, ConnRow::Conn { .. })));
    }

    /// Row indices now include headers, so anything that resolves "the
    /// selected connection" by indexing the *connection* list would silently
    /// act on the wrong flow. A header must resolve to no connection at all.
    #[test]
    fn a_header_row_is_not_a_connection() {
        let view = ConnView {
            groups: vec![group_of(
                "claude",
                vec![conn("claude", "ESTABLISHED", "1.2.3.4:443")],
                true,
            )],
            flat: Vec::new(),
        };
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
}
