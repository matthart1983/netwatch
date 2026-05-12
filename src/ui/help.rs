use crate::app::App;
use crate::theme::Theme;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let popup_width = (area.width * 80 / 100).max(60).min(area.width);
    let popup_height = (area.height * 80 / 100).max(20).min(area.height);

    let x = area.x + (area.width.saturating_sub(popup_width)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_height)) / 2;
    let popup = Rect::new(x, y, popup_width, popup_height);

    f.render_widget(Clear, popup);
    crate::ui::widgets::paint_overlay_bg(f, &app.theme, popup);

    let block = Block::default()
        .title(" Help ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(app.theme.brand));
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    let lines = build_help_lines(&app.theme);

    // Reserve 1 line for the footer hint
    let visible_height = inner.height.saturating_sub(1) as usize;
    let max_scroll = lines.len().saturating_sub(visible_height);
    let offset = app.scroll.help_scroll.min(max_scroll);

    let visible: Vec<Line> = lines
        .into_iter()
        .skip(offset)
        .take(visible_height)
        .collect();

    let content = Paragraph::new(visible);
    f.render_widget(
        content,
        Rect::new(
            inner.x,
            inner.y,
            inner.width,
            inner.height.saturating_sub(1),
        ),
    );

    // Footer hint
    let key = app.theme.key_hint;
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("↑↓", Style::default().fg(key).bold()),
        Span::styled(":Scroll  ", Style::default().fg(app.theme.text_primary)),
        Span::styled("?", Style::default().fg(key).bold()),
        Span::styled("/", Style::default().fg(app.theme.text_primary)),
        Span::styled("Esc", Style::default().fg(key).bold()),
        Span::styled(":Close", Style::default().fg(app.theme.text_primary)),
    ]))
    .alignment(Alignment::Center);
    let footer_area = Rect::new(
        inner.x,
        inner.y + inner.height.saturating_sub(1),
        inner.width,
        1,
    );
    f.render_widget(footer, footer_area);
}

fn section_header(theme: &Theme, title: &str) -> Line<'static> {
    Line::from(Span::styled(
        title.to_string(),
        Style::default().fg(theme.brand).bold(),
    ))
}

fn key_line(theme: &Theme, key: &str, desc: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled(
            format!("{:<16}", key),
            Style::default().fg(theme.key_hint).bold(),
        ),
        Span::styled(desc.to_string(), Style::default().fg(theme.text_primary)),
    ])
}

fn build_help_lines(theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // GLOBAL KEYS
    lines.push(section_header(theme, "GLOBAL KEYS"));
    lines.push(key_line(theme, "q", "Quit"));
    lines.push(key_line(theme, "Ctrl+C", "Quit"));
    lines.push(key_line(
        theme,
        "1-8",
        "Switch tab (Dash/Conn/Iface/Pkt/Stats/Topo/Time/Proc)",
    ));
    lines.push(key_line(theme, "p", "Pause/resume data collection"));
    lines.push(key_line(theme, "r", "Force refresh all data"));
    lines.push(key_line(theme, "R (shift)", "Arm/disarm flight recorder"));
    lines.push(key_line(
        theme,
        "F (shift)",
        "Freeze the current incident window",
    ));
    lines.push(key_line(
        theme,
        "E (shift)",
        "Export the current incident bundle",
    ));
    lines.push(key_line(theme, "?", "Toggle this help overlay"));
    lines.push(key_line(theme, "g", "Toggle GeoIP location display"));
    lines.push(key_line(
        theme,
        "t",
        "Cycle theme (dark/minimal/ocean/solarized/dracula/nord/sky/paper)",
    ));
    lines.push(key_line(
        theme,
        ",",
        "Open settings menu (←→ / h/l to cycle theme)",
    ));
    lines.push(key_line(theme, "PgUp/PgDn", "Scroll lists by a page"));
    lines.push(Line::raw(""));

    // DASHBOARD
    lines.push(section_header(theme, "DASHBOARD (Tab 1)"));
    lines.push(key_line(theme, "↑↓ / j/k", "Select interface"));
    lines.push(key_line(theme, "s", "Open sort picker"));
    lines.push(Line::raw(""));

    // SORT PICKER
    lines.push(section_header(theme, "SORT PICKER (any table tab)"));
    lines.push(key_line(theme, "↑↓ / j/k", "Move selection"));
    lines.push(key_line(theme, "Enter", "Apply selected sort column"));
    lines.push(key_line(theme, "S (shift)", "Toggle ascending/descending"));
    lines.push(key_line(theme, "/", "Filter columns by name"));
    lines.push(key_line(theme, "Esc / s / q", "Close picker"));
    lines.push(Line::raw(""));

    // CONNECTIONS
    lines.push(section_header(theme, "CONNECTIONS (Tab 2)"));
    lines.push(key_line(theme, "↑↓ / j/k", "Scroll connection list"));
    lines.push(key_line(theme, "s", "Open sort picker"));
    lines.push(key_line(
        theme,
        "/",
        "Filter connections (process, state, remote address)",
    ));
    lines.push(key_line(theme, "Esc", "Clear active filter"));
    lines.push(key_line(
        theme,
        "Enter",
        "Jump to Packets tab with filter for selected connection",
    ));
    lines.push(key_line(
        theme,
        "W (shift)",
        "Whois lookup for selected connection's remote IP",
    ));
    lines.push(key_line(
        theme,
        "T",
        "Traceroute to selected connection's remote IP",
    ));
    lines.push(key_line(theme, "Esc", "Close traceroute overlay"));
    lines.push(Line::raw(""));

    // INTERFACES
    lines.push(section_header(theme, "INTERFACES (Tab 3)"));
    lines.push(key_line(theme, "↑↓ / j/k", "Select interface"));
    lines.push(key_line(theme, "s", "Open sort picker"));
    lines.push(Line::raw(""));

    // PACKETS
    lines.push(section_header(theme, "PACKETS (Tab 4)"));
    lines.push(key_line(theme, "↑↓ / j/k", "Scroll packet list"));
    lines.push(key_line(theme, "Enter", "Select packet at cursor"));
    lines.push(key_line(theme, "c", "Start/stop capture"));
    lines.push(key_line(
        theme,
        "R/F/E",
        "Recorder arm, freeze, export incident bundle",
    ));
    lines.push(key_line(
        theme,
        "i",
        "Cycle capture interface (when stopped)",
    ));
    lines.push(key_line(theme, "/", "Open display filter bar"));
    lines.push(key_line(theme, "Esc", "Clear display filter"));
    lines.push(key_line(theme, "s", "Open stream view for selected packet"));
    lines.push(key_line(theme, "w", "Export packets to .pcap file"));
    lines.push(key_line(theme, "f", "Toggle auto-follow"));
    lines.push(key_line(theme, "x", "Clear all captured packets"));
    lines.push(key_line(theme, "m", "Toggle bookmark on selected packet"));
    lines.push(key_line(theme, "n", "Jump to next bookmarked packet"));
    lines.push(key_line(
        theme,
        "N (shift)",
        "Jump to previous bookmarked packet",
    ));
    lines.push(key_line(
        theme,
        "W (shift)",
        "Whois lookup for selected packet IPs",
    ));
    lines.push(Line::raw(""));

    // STREAM VIEW
    lines.push(section_header(theme, "STREAM VIEW (in Packets tab)"));
    lines.push(key_line(theme, "Esc", "Close stream view"));
    lines.push(key_line(theme, "↑↓ / j/k", "Scroll stream content"));
    lines.push(key_line(theme, "→←", "Filter direction (A→B / B→A)"));
    lines.push(key_line(theme, "a", "Show both directions"));
    lines.push(key_line(theme, "h", "Toggle hex/text mode"));
    lines.push(Line::raw(""));

    // STATS
    lines.push(section_header(theme, "STATS (Tab 5)"));
    lines.push(key_line(theme, "↑↓ / j/k", "Scroll protocol list"));
    lines.push(Line::raw(""));

    // TOPOLOGY
    lines.push(section_header(theme, "TOPOLOGY (Tab 6)"));
    lines.push(key_line(theme, "↑↓ / j/k", "Scroll topology view"));
    lines.push(key_line(theme, "Enter", "Jump to Connections tab"));
    lines.push(key_line(theme, "T", "Traceroute to selected remote host"));
    lines.push(key_line(theme, "Esc", "Close traceroute overlay"));
    lines.push(Line::raw(""));

    // TIMELINE
    lines.push(section_header(theme, "TIMELINE (Tab 7)"));
    lines.push(key_line(theme, "↑↓ / j/k", "Scroll connection list"));
    lines.push(key_line(theme, "t", "Cycle time window (1m/5m/15m/30m/1h)"));
    lines.push(key_line(theme, "Enter", "Jump to Connections tab"));
    lines.push(Line::raw(""));

    // PROCESSES
    lines.push(section_header(theme, "PROCESSES (Tab 8)"));
    lines.push(key_line(theme, "↑↓ / j/k", "Scroll process list"));
    lines.push(key_line(theme, "s", "Open sort picker"));
    lines.push(key_line(theme, "e", "Export connections to JSON + CSV"));
    lines.push(Line::raw(""));

    // DISPLAY FILTER SYNTAX
    lines.push(section_header(theme, "DISPLAY FILTER SYNTAX"));
    lines.push(key_line(
        theme,
        "tcp, udp, dns, icmp, arp",
        "Filter by protocol",
    ));
    lines.push(key_line(
        theme,
        "192.168.1.1",
        "Match source or destination IP",
    ));
    lines.push(key_line(
        theme,
        "ip.src == X / ip.dst == X",
        "Match specific direction",
    ));
    lines.push(key_line(
        theme,
        "port 443",
        "Match source or destination port",
    ));
    lines.push(key_line(theme, "stream 7", "Match stream index"));
    lines.push(key_line(
        theme,
        "contains \"text\"",
        "Search in info/payload",
    ));
    lines.push(key_line(theme, "and, or, not / !", "Combine filters"));
    lines.push(key_line(theme, "bare word", "Shorthand for contains"));
    lines.push(Line::raw(""));

    // TCP HANDSHAKE TIMING
    lines.push(section_header(theme, "TCP HANDSHAKE TIMING"));
    lines.push(key_line(
        theme,
        "⏱ in stream header",
        "Total 3-way handshake time (SYN→ACK)",
    ));
    lines.push(key_line(
        theme,
        "SYN→SA",
        "Client→Server network RTT (SYN to SYN-ACK)",
    ));
    lines.push(key_line(
        theme,
        "SA→ACK",
        "Server→Client network RTT (SYN-ACK to ACK)",
    ));
    lines.push(key_line(
        theme,
        "Shown in:",
        "Stream view header, status bar, packet detail",
    ));
    lines.push(Line::raw(""));

    // EXPERT INFO INDICATORS
    lines.push(section_header(theme, "EXPERT INFO INDICATORS"));
    lines.push(key_line(
        theme,
        "● (red)",
        "Error: TCP RST, DNS NXDOMAIN/SERVFAIL",
    ));
    lines.push(key_line(
        theme,
        "▲ (yellow)",
        "Warning: Zero window, ICMP unreachable, HTTP 4xx/5xx",
    ));
    lines.push(key_line(
        theme,
        "· (cyan)",
        "Note: TCP FIN, DNS response, TLS Server Hello",
    ));
    lines.push(key_line(
        theme,
        "(space)",
        "Chat: SYN, DNS query, ARP, normal traffic",
    ));

    lines
}
