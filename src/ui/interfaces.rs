use crate::app::{sort_columns_for_tab, App, Tab};
use crate::sort::{
    apply_direction, cmp_case_insensitive, cmp_f64, cmp_ip, SortColumn, TabSortState,
};
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table},
};

pub const COLUMNS: &[SortColumn] = &[
    SortColumn { name: "Name" },
    SortColumn { name: "IPv4" },
    SortColumn { name: "IPv6" },
    SortColumn { name: "MAC" },
    SortColumn { name: "MTU" },
    SortColumn { name: "RX B/s" },
    SortColumn { name: "TX B/s" },
    SortColumn { name: "RX Pkts" },
    SortColumn { name: "TX Pkts" },
    SortColumn { name: "Err/Drop" },
    SortColumn { name: "Status" },
];

pub const DEFAULT_SORT: TabSortState = TabSortState {
    column: 0,
    ascending: true,
};

// serves both Dashboard and Interfaces tabs — column name aliases
// like "Interface"/"Name" and "IP Address"/"IPv4" handle the overlap
pub fn sort_interfaces(
    interfaces: &mut [crate::collectors::traffic::InterfaceTraffic],
    tab: Tab,
    column: usize,
    ascending: bool,
    interface_info: &[crate::platform::InterfaceInfo],
) {
    let cols = sort_columns_for_tab(tab);
    let col_name = cols.get(column).map(|c| c.name).unwrap_or("");

    interfaces.sort_by(|a, b| {
        let info_a = interface_info.iter().find(|i| i.name == a.name);
        let info_b = interface_info.iter().find(|i| i.name == b.name);
        let ord = match col_name {
            "Interface" | "Name" => cmp_case_insensitive(&a.name, &b.name),
            "IP Address" | "IPv4" => {
                let ip_a = info_a.and_then(|i| i.ipv4.as_deref()).unwrap_or("");
                let ip_b = info_b.and_then(|i| i.ipv4.as_deref()).unwrap_or("");
                cmp_ip(ip_a, ip_b)
            }
            "IPv6" => {
                let ip_a = info_a.and_then(|i| i.ipv6.as_deref()).unwrap_or("");
                let ip_b = info_b.and_then(|i| i.ipv6.as_deref()).unwrap_or("");
                cmp_ip(ip_a, ip_b)
            }
            "MAC" => {
                let mac_a = info_a.and_then(|i| i.mac.as_deref()).unwrap_or("");
                let mac_b = info_b.and_then(|i| i.mac.as_deref()).unwrap_or("");
                cmp_case_insensitive(mac_a, mac_b)
            }
            "MTU" => {
                let mtu_a = info_a.and_then(|i| i.mtu).unwrap_or(0);
                let mtu_b = info_b.and_then(|i| i.mtu).unwrap_or(0);
                mtu_a.cmp(&mtu_b)
            }
            "RX B/s" | "Rx Rate" => cmp_f64(a.rx_rate, b.rx_rate),
            "TX B/s" | "Tx Rate" => cmp_f64(a.tx_rate, b.tx_rate),
            "Rx Total" => a.rx_bytes_total.cmp(&b.rx_bytes_total),
            "Tx Total" => a.tx_bytes_total.cmp(&b.tx_bytes_total),
            "RX Pkts" | "Rx Packets" => a.rx_packets.cmp(&b.rx_packets),
            "TX Pkts" | "Tx Packets" => a.tx_packets.cmp(&b.tx_packets),
            "Err/Drop" | "Errors/Drop" => {
                let err_a = a.rx_errors + a.tx_errors + a.rx_drops + a.tx_drops;
                let err_b = b.rx_errors + b.tx_errors + b.rx_drops + b.tx_drops;
                err_a.cmp(&err_b)
            }
            "Status" => {
                let up_a = info_a.map(|i| i.is_up).unwrap_or(false);
                let up_b = info_b.map(|i| i.is_up).unwrap_or(false);
                up_a.cmp(&up_b)
            }
            _ => std::cmp::Ordering::Equal,
        };
        apply_direction(ord, ascending)
    });
}

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(8),    // interface detail table
            Constraint::Length(5), // sparkline
            Constraint::Length(3), // footer
        ])
        .split(area);

    // sort interfaces once, share between table and sparkline so
    // selected_interface index refers to the same sorted order
    let mut sorted_interfaces = app.traffic.interfaces();
    let sort_state = app.sort_states.get(&crate::app::Tab::Interfaces);
    if let Some(state) = sort_state {
        sort_interfaces(
            &mut sorted_interfaces,
            crate::app::Tab::Interfaces,
            state.column,
            state.ascending,
            &app.interface_info,
        );
    }

    render_header(f, app, chunks[0]);
    render_detail_table(f, app, &sorted_interfaces, chunks[1]);
    render_sparkline(f, app, &sorted_interfaces, chunks[2]);
    render_footer(f, app, chunks[3]);
}

fn render_header(f: &mut Frame, app: &App, area: Rect) {
    widgets::render_header(f, app, area);
}

fn render_detail_table(
    f: &mut Frame,
    app: &App,
    interfaces: &[crate::collectors::traffic::InterfaceTraffic],
    area: Rect,
) {
    let tab = crate::app::Tab::Interfaces;

    let header = widgets::sort_header_row(app, tab, COLUMNS);

    let rows: Vec<Row> = interfaces
        .iter()
        .enumerate()
        .map(|(i, iface)| {
            let info = app
                .interface_info
                .iter()
                .find(|info| info.name == iface.name);

            let ipv4 = info
                .and_then(|i| i.ipv4.clone())
                .unwrap_or_else(|| "—".to_string());
            let ipv6 = info
                .and_then(|i| i.ipv6.clone())
                .unwrap_or_else(|| "—".to_string());
            let mac = info
                .and_then(|i| i.mac.clone())
                .unwrap_or_else(|| "—".to_string());
            let mtu = info
                .and_then(|i| i.mtu)
                .map(|m| m.to_string())
                .unwrap_or_else(|| "—".to_string());
            let is_up = info.map(|i| i.is_up).unwrap_or(false);

            let errors_drops = format!(
                "{}/{}",
                iface.rx_errors + iface.tx_errors,
                iface.rx_drops + iface.tx_drops
            );

            let status_style = if is_up {
                Style::default().fg(app.theme.status_good)
            } else {
                Style::default().fg(app.theme.status_error)
            };

            let row_style = if app.selected_interface == Some(i) {
                Style::default().bg(app.theme.selection_bg)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(iface.name.clone()),
                Cell::from(ipv4),
                Cell::from(ipv6),
                Cell::from(mac),
                Cell::from(mtu),
                Cell::from(widgets::format_bytes_rate_padded(iface.rx_rate))
                    .style(Style::default().fg(app.theme.rx_rate)),
                Cell::from(widgets::format_bytes_rate_padded(iface.tx_rate))
                    .style(Style::default().fg(app.theme.tx_rate)),
                Cell::from(iface.rx_packets.to_string()),
                Cell::from(iface.tx_packets.to_string()),
                Cell::from(errors_drops),
                Cell::from(if is_up { "UP" } else { "DOWN" }).style(status_style),
            ])
            .style(row_style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(16),
            Constraint::Length(20),
            Constraint::Length(18),
            Constraint::Length(6),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(6),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" Interface Details ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border)),
    );

    f.render_widget(table, area);
}

fn render_sparkline(
    f: &mut Frame,
    app: &App,
    sorted_interfaces: &[crate::collectors::traffic::InterfaceTraffic],
    area: Rect,
) {
    // look up from the sorted list so the sparkline matches the highlighted row
    let selected = app
        .selected_interface
        .and_then(|i| sorted_interfaces.get(i));

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    if let Some(iface) = selected {
        let rx_spark = Sparkline::default()
            .block(
                Block::default()
                    .title(format!(" RX {} ", iface.name))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(app.theme.border)),
            )
            .data(iface.rx_history.as_slices().0)
            .style(Style::default().fg(app.theme.rx_rate));

        let tx_spark = Sparkline::default()
            .block(
                Block::default()
                    .title(format!(" TX {} ", iface.name))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(app.theme.border)),
            )
            .data(iface.tx_history.as_slices().0)
            .style(Style::default().fg(app.theme.tx_rate));

        f.render_widget(rx_spark, chunks[0]);
        f.render_widget(tx_spark, chunks[1]);
    } else {
        let empty = Paragraph::new("No interface selected").block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(app.theme.border)),
        );
        f.render_widget(empty, area);
    }
}

fn render_footer(f: &mut Frame, app: &App, area: Rect) {
    let hints = vec![
        Span::styled("s", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Sort  "),
        Span::styled("a", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Analyze  "),
        Span::styled("p", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Pause  "),
        Span::styled("r", Style::default().fg(app.theme.key_hint).bold()),
        Span::raw(":Refresh"),
    ];
    widgets::render_footer(f, app, area, hints);
}
