use crate::app::App;
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

    let block = Block::default()
        .title(" Help ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    let lines = build_help_lines();

    // Reserve 1 line for the footer hint
    let visible_height = inner.height.saturating_sub(1) as usize;
    let max_scroll = lines.len().saturating_sub(visible_height);
    let offset = app.help_scroll.min(max_scroll);

    let visible: Vec<Line> = lines
        .into_iter()
        .skip(offset)
        .take(visible_height)
        .collect();

    let content = Paragraph::new(visible);
    f.render_widget(content, Rect::new(inner.x, inner.y, inner.width, inner.height.saturating_sub(1)));

    // Footer hint
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("↑↓", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Scroll  "),
        Span::styled("?", Style::default().fg(Color::Yellow).bold()),
        Span::raw("/"),
        Span::styled("Esc", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Close"),
    ]))
    .alignment(Alignment::Center);
    let footer_area = Rect::new(inner.x, inner.y + inner.height.saturating_sub(1), inner.width, 1);
    f.render_widget(footer, footer_area);
}

fn section_header(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        title.to_string(),
        Style::default().fg(Color::Cyan).bold(),
    ))
}

fn key_line(key: &str, desc: &str) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled(
            format!("{:<16}", key),
            Style::default().fg(Color::Yellow).bold(),
        ),
        Span::styled(desc.to_string(), Style::default().fg(Color::White)),
    ])
}

fn build_help_lines() -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    // GLOBAL KEYS
    lines.push(section_header("GLOBAL KEYS"));
    lines.push(key_line("q", "Quit"));
    lines.push(key_line("Ctrl+C", "Quit"));
    lines.push(key_line("1-8", "Switch tab (Dash/Conn/Iface/Pkt/Stats/Topo/Time/Insights)"));
    lines.push(key_line("p", "Pause/resume data collection"));
    lines.push(key_line("r", "Force refresh all data"));
    lines.push(key_line("a", "Request AI analysis (from any tab)"));
    lines.push(key_line("?", "Toggle this help overlay"));
    lines.push(key_line("g", "Toggle GeoIP location display"));
    lines.push(Line::raw(""));

    // DASHBOARD
    lines.push(section_header("DASHBOARD (Tab 1)"));
    lines.push(key_line("↑↓", "Select interface"));
    lines.push(Line::raw(""));

    // CONNECTIONS
    lines.push(section_header("CONNECTIONS (Tab 2)"));
    lines.push(key_line("↑↓", "Scroll connection list"));
    lines.push(key_line("s", "Cycle sort column"));
    lines.push(key_line("Enter", "Jump to Packets tab with filter for selected connection"));
    lines.push(key_line("W (shift)", "Whois lookup for selected connection's remote IP"));
    lines.push(Line::raw(""));

    // INTERFACES
    lines.push(section_header("INTERFACES (Tab 3)"));
    lines.push(key_line("↑↓", "Select interface"));
    lines.push(Line::raw(""));

    // PACKETS
    lines.push(section_header("PACKETS (Tab 4)"));
    lines.push(key_line("↑↓", "Scroll packet list"));
    lines.push(key_line("Enter", "Select packet at cursor"));
    lines.push(key_line("c", "Start/stop capture"));
    lines.push(key_line("i", "Cycle capture interface (when stopped)"));
    lines.push(key_line("b", "Set BPF capture filter (when stopped)"));
    lines.push(key_line("/", "Open display filter bar"));
    lines.push(key_line("Esc", "Clear display filter"));
    lines.push(key_line("s", "Open stream view for selected packet"));
    lines.push(key_line("w", "Export packets to .pcap file"));
    lines.push(key_line("f", "Toggle auto-follow"));
    lines.push(key_line("x", "Clear all captured packets"));
    lines.push(key_line("m", "Toggle bookmark on selected packet"));
    lines.push(key_line("n", "Jump to next bookmarked packet"));
    lines.push(key_line("N (shift)", "Jump to previous bookmarked packet"));
    lines.push(key_line("W (shift)", "Whois lookup for selected packet IPs"));
    lines.push(Line::raw(""));

    // STREAM VIEW
    lines.push(section_header("STREAM VIEW (in Packets tab)"));
    lines.push(key_line("Esc", "Close stream view"));
    lines.push(key_line("↑↓", "Scroll stream content"));
    lines.push(key_line("→←", "Filter direction (A→B / B→A)"));
    lines.push(key_line("a", "Show both directions"));
    lines.push(key_line("h", "Toggle hex/text mode"));
    lines.push(Line::raw(""));

    // STATS
    lines.push(section_header("STATS (Tab 5)"));
    lines.push(key_line("↑↓", "Scroll protocol list"));
    lines.push(Line::raw(""));

    // TOPOLOGY
    lines.push(section_header("TOPOLOGY (Tab 6)"));
    lines.push(key_line("↑↓", "Scroll topology view"));
    lines.push(key_line("Enter", "Jump to Connections tab"));
    lines.push(Line::raw(""));

    // TIMELINE
    lines.push(section_header("TIMELINE (Tab 7)"));
    lines.push(key_line("↑↓", "Scroll connection list"));
    lines.push(key_line("t", "Cycle time window (30s/1m/5m/15m/1h)"));
    lines.push(key_line("Enter", "Jump to Connections tab"));
    lines.push(Line::raw(""));

    // INSIGHTS
    lines.push(section_header("INSIGHTS (Tab 8)"));
    lines.push(key_line("a", "Trigger on-demand AI analysis"));
    lines.push(key_line("↑↓", "Scroll insights"));
    lines.push(Line::raw(""));

    // DISPLAY FILTER SYNTAX
    lines.push(section_header("DISPLAY FILTER SYNTAX"));
    lines.push(key_line("tcp, udp, dns, icmp, arp", "Filter by protocol"));
    lines.push(key_line("192.168.1.1", "Match source or destination IP"));
    lines.push(key_line("ip.src == X / ip.dst == X", "Match specific direction"));
    lines.push(key_line("port 443", "Match source or destination port"));
    lines.push(key_line("stream 7", "Match stream index"));
    lines.push(key_line("contains \"text\"", "Search in info/payload"));
    lines.push(key_line("and, or, not / !", "Combine filters"));
    lines.push(key_line("bare word", "Shorthand for contains"));
    lines.push(Line::raw(""));

    // TCP HANDSHAKE TIMING
    lines.push(section_header("TCP HANDSHAKE TIMING"));
    lines.push(key_line("⏱ in stream header", "Total 3-way handshake time (SYN→ACK)"));
    lines.push(key_line("SYN→SA", "Client→Server network RTT (SYN to SYN-ACK)"));
    lines.push(key_line("SA→ACK", "Server→Client network RTT (SYN-ACK to ACK)"));
    lines.push(key_line("Shown in:", "Stream view header, status bar, packet detail"));
    lines.push(Line::raw(""));

    // EXPERT INFO INDICATORS
    lines.push(section_header("EXPERT INFO INDICATORS"));
    lines.push(key_line("● (red)", "Error: TCP RST, DNS NXDOMAIN/SERVFAIL"));
    lines.push(key_line("▲ (yellow)", "Warning: Zero window, ICMP unreachable, HTTP 4xx/5xx"));
    lines.push(key_line("· (cyan)", "Note: TCP FIN, DNS response, TLS Server Hello"));
    lines.push(key_line("(space)", "Chat: SYN, DNS query, ARP, normal traffic"));

    lines
}
