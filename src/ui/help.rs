use crate::app::{App, Tab};
use crate::theme::Theme;
use crate::ui::widgets;
use ratatui::{
    prelude::*,
    widgets::{Clear, Paragraph},
};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let popup_width = (area.width * 80 / 100).max(60).min(area.width);
    let popup_height = (area.height * 80 / 100).max(20).min(area.height);

    let x = area.x + (area.width.saturating_sub(popup_width)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_height)) / 2;
    let popup = Rect::new(x, y, popup_width, popup_height);

    f.render_widget(Clear, popup);
    crate::ui::widgets::paint_overlay_bg(f, &app.theme, popup);

    let block = widgets::panel_block(&app.theme)
        .title(" Help ")
        .border_style(Style::default().fg(app.theme.brand));
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    // Lite gets its own compact key list — dumping the full TUI's ~40
    // bindings into a view built around six keys would undercut the point.
    let lines = match app.ui.view_mode {
        crate::app::ViewMode::Lite => build_lite_help_lines(&app.theme),
        crate::app::ViewMode::Dense => build_dense_help_lines(&app.theme),
        crate::app::ViewMode::Full => build_help_lines(&app.theme),
    };

    // Reserve 1 line for the footer hint
    let visible_height = inner.height.saturating_sub(1) as usize;
    let max_scroll = lines.len().saturating_sub(visible_height);
    let offset = app.ui.scroll.help_scroll.min(max_scroll);

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

    // Footer hint, in the one key-hint rendering the rest of the tool uses.
    let footer = Paragraph::new(Line::from(crate::ui::widgets::hint_spans(
        &app.theme,
        &[
            crate::ui::widgets::hint("↑↓", "scroll"),
            crate::ui::widgets::hint("? esc", "close"),
        ],
    )))
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

/// Lite's complete key surface — including the keys the footer deliberately
/// doesn't advertise (navigation and `Esc`, which are `less`/`vim`/`top`
/// conventions). This overlay is the one place the full set is written down.
/// Dense advertises its bindings in the box borders, so this overlay exists to
/// explain what the screen *means* — the keys are only half of it.
fn build_dense_help_lines(theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    lines.push(section_header(theme, "NETWATCH DENSE"));
    lines.push(key_line(theme, "q / Ctrl+C", "Quit"));
    lines.push(key_line(theme, "V", "Cycle view: full → lite → dense"));
    lines.push(key_line(
        theme,
        "1-4",
        "Zoom that box to the whole screen; again to restore",
    ));
    lines.push(key_line(
        theme,
        "Esc",
        "Restore the grid, then back to the full view",
    ));
    lines.push(key_line(theme, "p", "Pause/resume"));
    lines.push(key_line(theme, ",", "Settings"));
    lines.push(key_line(theme, "?", "Toggle this overlay"));
    lines.push(Line::from(""));

    lines.push(section_header(theme, "NAVIGATION"));
    lines.push(key_line(theme, "↑ / k", "Select the previous connection"));
    lines.push(key_line(theme, "↓ / j", "Select the next connection"));
    lines.push(key_line(theme, "Home / End", "First / last connection"));
    lines.push(key_line(
        theme,
        "space / Enter",
        "Fold/expand the process under the cursor",
    ));
    lines.push(key_line(theme, "z", "Fold/expand every process"));
    lines.push(Line::from(""));

    lines.push(section_header(theme, "READING THE SCREEN"));
    lines.push(key_line(
        theme,
        "graph",
        "Download grows up, upload grows down",
    ));
    lines.push(key_line(
        theme,
        "colour",
        "Height in the graph, not the series",
    ));
    lines.push(key_line(
        theme,
        "meters",
        "Red zone is fixed, so you see it coming",
    ));
    lines.push(key_line(theme, "--", "Not measured — not the same as zero"));
    lines.push(Line::from(""));

    lines.push(section_header(theme, "NOTES"));
    lines.push(key_line(theme, "RTT", "From captured TCP handshakes only"));
    lines.push(key_line(theme, "cwnd", "Kernel TCP state; Linux + macOS"));
    lines.push(key_line(theme, "size", "Needs 130×44, then grows to fit"));

    lines
}

fn build_lite_help_lines(theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    lines.push(section_header(theme, "NETWATCH LITE"));
    lines.push(key_line(theme, "q / Ctrl+C", "Quit"));
    lines.push(key_line(theme, "p", "Pause/resume"));
    lines.push(key_line(theme, "/", "Filter by process or host"));
    lines.push(key_line(theme, "↵", "Expand/collapse the selected talker"));
    lines.push(key_line(theme, "L", "Switch to the full view"));
    lines.push(key_line(theme, "V", "Cycle view: full → lite → dense"));
    lines.push(key_line(theme, "?", "Toggle this overlay"));
    lines.push(Line::from(""));

    lines.push(section_header(theme, "NAVIGATION"));
    lines.push(key_line(theme, "↑ / k", "Move selection up"));
    lines.push(key_line(theme, "↓ / j", "Move selection down"));
    lines.push(key_line(
        theme,
        "Esc",
        "Close detail, then clear the filter",
    ));
    lines.push(Line::from(""));

    lines.push(section_header(theme, "NOTES"));
    // The overlay is ~64 columns wide; keep these inside it.
    lines.push(key_line(theme, "RTT", "From captured TCP handshakes only"));
    lines.push(key_line(theme, "HOST", "SNI when captured, else remote IP"));

    lines
}

/// Where a section's keys work. The test below reads `handle_main_key` and
/// requires every key it handles to appear in a section of the matching
/// scope, so a binding added without a help line fails the build.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Scope {
    Global,
    Tab(Tab),
    StreamView,
    DiagnoseCoverage,
    /// Syntax and legends: not keys, and not checked.
    Reference,
}

struct Section {
    title: &'static str,
    // Read only by the tests, which check it against the key handler.
    #[cfg_attr(not(test), allow(dead_code))]
    scope: Scope,
    keys: &'static [(&'static str, &'static str)],
}

/// The full view's help, in display order.
const FULL_HELP: &[Section] = &[
    Section {
        title: "GLOBAL KEYS",
        scope: Scope::Global,
        keys: &[
            ("q / Ctrl+C", "Quit"),
            (
                "1-9, 0",
                "Switch tab (Dash/Conn/Iface/Pkt/Stats/Topo/Time/Proc/Diagnose/Egress)",
            ),
            ("↑↓ / j/k", "Move the cursor or scroll"),
            ("PgUp/PgDn", "Scroll lists by a page"),
            ("p", "Pause/resume data collection"),
            ("r", "Force refresh all data"),
            ("s / S", "Sort picker on tabs with a table · S reverses the order"),
            ("V / v", "Cycle view: full → lite → dense (dense needs 130×44)"),
            ("L (shift)", "Switch to the Lite view"),
            ("R (shift)", "Arm/disarm flight recorder"),
            ("F (shift)", "Freeze the current incident window"),
            ("E (shift)", "Preview and export the frozen incident bundle"),
            ("?", "Toggle this help overlay"),
            ("g", "Toggle GeoIP location display"),
            (
                "P (shift)",
                "Promote observed egress baseline → egress-policy.toml (warn on drift)",
            ),
            (
                "t",
                "Cycle theme — except on Dashboard, Stats, Timeline and Diagnose, where t is the tab's own",
            ),
            (",", "Open settings menu (←→ / h/l to cycle theme)"),
            ("M (shift)", "Memory overlay: sizes of the bounded collections"),
        ],
    },
    Section {
        title: "SORT PICKER (any table tab)",
        scope: Scope::Reference,
        keys: &[
            ("↑↓ / j/k", "Move selection"),
            ("Enter", "Apply selected sort column"),
            ("S (shift)", "Toggle ascending/descending"),
            ("/", "Filter columns by name"),
            ("Esc / s / q", "Close picker"),
        ],
    },
    Section {
        title: "DASHBOARD (Tab 1)",
        scope: Scope::Tab(Tab::Dashboard),
        keys: &[
            (
                "↑↓ / j/k",
                "Move the cursor in the connections panel (↑ off the top hides it)",
            ),
            ("space / Enter", "Fold/expand the process under the cursor"),
            ("z", "Fold/expand every process"),
            ("t", "Throughput graph: linear or log scale"),
        ],
    },
    Section {
        title: "CONNECTIONS (Tab 2)",
        scope: Scope::Tab(Tab::Connections),
        keys: &[
            ("↑↓ / j/k", "Scroll connection list"),
            ("/", "Filter connections (process, state, remote address)"),
            ("f", "Cycle state: all / established / listen / time-wait"),
            ("G (shift)", "Group by process / remote / none"),
            (
                "space",
                "Fold/expand the group under the cursor (grouped modes)",
            ),
            ("z", "Fold/expand every group"),
            (
                "Enter",
                "Jump to Packets tab with filter for selected connection; on a group row, fold it",
            ),
            ("e", "Export connections to JSON + CSV"),
            ("W (shift)", "Whois lookup for selected connection's remote IP"),
            ("T (shift)", "Traceroute to selected connection's remote IP"),
            ("Esc", "Close the traceroute overlay, else clear the filter"),
        ],
    },
    Section {
        title: "INTERFACES (Tab 3)",
        scope: Scope::Tab(Tab::Interfaces),
        keys: &[
            ("↑↓ / j/k", "Select interface"),
            ("f", "Cycle the list: active / all / wifi / vpn / idle"),
        ],
    },
    Section {
        title: "PACKETS (Tab 4)",
        scope: Scope::Tab(Tab::Packets),
        keys: &[
            ("↑↓ / j/k", "Scroll packet list"),
            ("Enter", "Select packet at cursor"),
            ("c", "Start/stop capture"),
            ("i", "Cycle capture interface (restarts capture if running)"),
            ("/", "Open display filter bar"),
            ("Esc", "Clear display filter"),
            ("s", "Open stream view for selected packet"),
            ("d", "Expand/shrink the packet detail pane"),
            ("y", "Copy the selected packet's details"),
            ("w", "Preview and export the shown packets (PCAPNG or PCAP)"),
            ("f", "Toggle auto-follow"),
            ("x", "Show only expert findings (warnings and errors)"),
            ("n", "Jump to next expert finding"),
            ("N (shift)", "Jump to previous expert finding"),
            ("m", "Toggle bookmark on selected packet"),
            ("] / [", "Jump to next/previous bookmark"),
            ("X (shift)", "Clear all captured packets and bookmarks"),
            ("W (shift)", "Whois lookup for selected packet IPs"),
        ],
    },
    Section {
        title: "EXPORT PREVIEW (w in Packets, E anywhere)",
        scope: Scope::Reference,
        keys: &[
            ("Enter", "Write the export in the background"),
            ("f", "PCAPNG or classic PCAP (packet export only)"),
            ("a", "Packet comments on/off (PCAPNG)"),
            ("↑↓ / j/k", "Scroll the preview"),
            ("Esc / q", "Close, or cancel a write in progress"),
        ],
    },
    Section {
        title: "STREAM VIEW (in Packets tab)",
        scope: Scope::StreamView,
        keys: &[
            ("Esc", "Close stream view"),
            ("↑↓ / j/k", "Scroll stream content"),
            ("→←", "Filter direction (A→B / B→A)"),
            ("a", "Show both directions"),
            ("h", "Toggle hex/text mode"),
        ],
    },
    Section {
        title: "STATS (Tab 5)",
        scope: Scope::Tab(Tab::Stats),
        keys: &[
            ("↑↓ / j/k", "Scroll protocol list"),
            ("t", "Cycle range: 1m / 5m / 15m / 1h / 24h / session"),
        ],
    },
    Section {
        title: "TOPOLOGY (Tab 6)",
        scope: Scope::Tab(Tab::Topology),
        keys: &[
            ("↑↓ / j/k", "Scroll topology view"),
            ("Enter", "Jump to Connections tab"),
            ("T (shift)", "Traceroute to selected remote host"),
            ("Esc", "Close traceroute overlay"),
        ],
    },
    Section {
        title: "TIMELINE (Tab 7)",
        scope: Scope::Tab(Tab::Timeline),
        keys: &[
            ("↑↓ / j/k", "Scroll connection list"),
            ("t", "Cycle time window (1m/5m/15m/30m/1h)"),
            ("f", "Cycle events: all / crit / warn / conn / dns / rtt / iface"),
            ("Enter", "Jump to Connections tab"),
        ],
    },
    Section {
        title: "PROCESSES (Tab 8)",
        scope: Scope::Tab(Tab::Processes),
        keys: &[
            ("↑↓ / j/k", "Scroll process list"),
            ("e", "Export connections to JSON + CSV"),
        ],
    },
    Section {
        title: "DIAGNOSE (Tab 9)",
        scope: Scope::Tab(Tab::Diagnose),
        keys: &[
            ("↑↓ / j/k", "Select issue"),
            (
                "↵",
                "--demo: simulate the first remediation (asks first); live, run the command shown",
            ),
            ("a", "Acknowledge — stays open, leaves the verdict line"),
            ("m", "Mute for one hour"),
            ("t", "Run the test that best separates the remaining causes"),
            ("d", "Mark the issue's next manual step done"),
            ("c", "Toggle the coverage view"),
            ("o", "Toggle the report preview"),
            ("e", "Export report.md + report.json"),
            ("y", "Copy the one-line summary"),
            ("i", "Regenerate the AI narrative (when enabled)"),
        ],
    },
    Section {
        title: "DIAGNOSE COVERAGE (c in Tab 9)",
        scope: Scope::DiagnoseCoverage,
        keys: &[
            ("↑↓ / j/k", "Select a check"),
            ("t", "Run the selected check's test"),
            ("] / [", "Select the next/previous configured target"),
            ("d", "Enable/disable the selected target (on a target.* check)"),
            ("r", "Reload targets and probes from config.toml"),
            ("x", "Cancel running active and target probes"),
        ],
    },
    Section {
        title: "EGRESS (Tab 0)",
        scope: Scope::Tab(Tab::Egress),
        keys: &[
            ("↑↓ / j/k", "Move cursor (click also selects)"),
            ("space", "Fold / unfold a process (or click its ▼)"),
            (
                "s / S",
                "Sort picker (volume / active / process / last seen / risk) · S reverses",
            ),
            ("/", "Filter by process or destination"),
            ("d", "Toggle destination detail pane"),
            ("H (shift)", "Include processes seen in earlier sessions"),
            (
                "Enter",
                "Add selected process to policy (from its observed baseline)",
            ),
            ("P (shift)", "Add every observed process"),
            (
                "x / Del",
                "Remove selected process from policy (confirm with y)",
            ),
            ("z", "Fold/expand every process"),
            ("e", "Export baseline to NDJSON"),
            ("", ""),
            ("✓ sni / ✓ ip", "Matched a declared name or address"),
            (
                "~ asn",
                "Admitted by autonomous system — broad, not one endpoint",
            ),
            ("? ech", "Name encrypted (ECH) — cannot judge"),
            ("✗ drift", "Outside the allowlist"),
            ("— no rule", "Process undeclared — nothing was checked"),
            (
                "✗ undeclared",
                "No rule, under strict = true — the absence is the finding",
            ),
            ("", ""),
            (
                "strict = true",
                "Set in egress-policy.toml to warn on any undeclared process",
            ),
        ],
    },
    Section {
        title: "DISPLAY FILTER SYNTAX",
        scope: Scope::Reference,
        keys: &[
            ("tcp, udp, dns, icmp, arp", "Filter by protocol"),
            ("192.168.1.1", "Match source or destination IP"),
            ("ip.src == X / ip.dst == X", "Match specific direction"),
            ("port 443", "Match source or destination port"),
            ("stream 7", "Match stream index"),
            ("contains \"text\"", "Search in info/payload"),
            ("and, or, not / !", "Combine filters"),
            ("bare word", "Shorthand for contains"),
        ],
    },
    Section {
        title: "TCP HANDSHAKE TIMING",
        scope: Scope::Reference,
        keys: &[
            ("⏱ in stream header", "Total 3-way handshake time (SYN→ACK)"),
            ("SYN→SA", "Client→Server network RTT (SYN to SYN-ACK)"),
            ("SA→ACK", "Server→Client network RTT (SYN-ACK to ACK)"),
            ("Shown in:", "Stream view header, status bar, packet detail"),
        ],
    },
    Section {
        title: "EXPERT INFO INDICATORS",
        scope: Scope::Reference,
        keys: &[
            ("● (red)", "Error: TCP RST, DNS NXDOMAIN/SERVFAIL"),
            (
                "▲ (yellow)",
                "Warning: Zero window, ICMP unreachable, HTTP 4xx/5xx",
            ),
            ("· (cyan)", "Note: TCP FIN, DNS response, TLS Server Hello"),
            ("(space)", "Chat: SYN, DNS query, ARP, normal traffic"),
        ],
    },
];

fn build_help_lines(theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (n, section) in FULL_HELP.iter().enumerate() {
        if n > 0 {
            lines.push(Line::raw(""));
        }
        lines.push(section_header(theme, section.title));
        for (key, desc) in section.keys {
            if key.is_empty() {
                lines.push(Line::raw(""));
            } else {
                lines.push(key_line(theme, key, desc));
            }
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The keys a help label names: "q / Ctrl+C" is q and Ctrl+C, "R/F/E"
    /// is three keys, "1-9, 0" is ten.
    fn label_keys(label: &str) -> BTreeSet<String> {
        if label == "/" || label == "," {
            return BTreeSet::from([label.to_string()]);
        }
        let mut keys = BTreeSet::new();
        let label = label.replace("(shift)", "").replace('↵', "Enter");
        for word in label.split([' ', ',']).filter(|w| !w.is_empty()) {
            let parts: Vec<&str> = if word.len() > 1 && word.contains('/') {
                word.split('/').collect()
            } else {
                vec![word]
            };
            for part in parts.into_iter().filter(|p| !p.is_empty() && *p != "/") {
                if let Some((a, b)) = part.split_once('-').filter(|_| part.len() == 3) {
                    let (a, b) = (a.as_bytes()[0], b.as_bytes()[0]);
                    keys.extend((a..=b).map(|c| (c as char).to_string()));
                } else if ["↑↓", "→←"].contains(&part) {
                    keys.extend(part.chars().map(String::from));
                } else {
                    keys.insert(part.to_string());
                }
            }
        }
        keys
    }

    /// The name help uses for a `KeyCode::…` pattern.
    fn key_name(code: &str) -> String {
        if let Some(c) = code
            .strip_prefix("Char('")
            .and_then(|c| c.strip_suffix("')"))
        {
            return if c == " " { "space".into() } else { c.into() };
        }
        match code {
            "Up" => "↑",
            "Down" => "↓",
            "Left" => "←",
            "Right" => "→",
            "PageUp" => "PgUp",
            "PageDown" => "PgDn",
            "Delete" => "Del",
            other => other,
        }
        .into()
    }

    /// Every (scope, key) `handle_main_key` acts on, read from its source.
    /// An arm whose guard compares the tab with `==` belongs to those tabs;
    /// one guarded on the stream view or the coverage view belongs to that
    /// view; anything else is global. The y/n remediation prompt is skipped:
    /// it prints its own keys.
    fn handled_keys() -> Vec<(Scope, String, String)> {
        const SRC: &str = include_str!("../app.rs");
        let start = SRC.find("\nfn handle_main_key(").expect("handle_main_key");
        let body = &SRC[start + 1..];
        let body = &body[..body[1..].find("\nfn ").map_or(body.len(), |n| n + 1)];

        let mut handled = Vec::new();
        let mut lines = body.lines().peekable();
        while let Some(line) = lines.next() {
            if !line.starts_with("        KeyCode::") {
                continue;
            }
            let mut arm = line.trim().to_string();
            while !arm.contains("=>") {
                let Some(next) = lines.next() else { break };
                arm.push(' ');
                arm.push_str(next.trim());
            }
            let head = &arm[..arm.find("=>").unwrap()];
            let (patterns, guard) = head.split_once(" if ").unwrap_or((head, ""));
            if guard.contains("pending_apply.is_some()") {
                continue;
            }
            let scopes: Vec<Scope> = if guard.contains("&& app.ui.stream_view_open") {
                vec![Scope::StreamView]
            } else if guard.contains("&& app.diagnose.show_coverage") {
                vec![Scope::DiagnoseCoverage]
            } else if guard.contains("!= Tab::") || !guard.contains("Tab::") {
                vec![Scope::Global]
            } else {
                Tab::ALL
                    .iter()
                    .filter(|t| guard.contains(&format!("== Tab::{t:?}")))
                    .map(|t| Scope::Tab(*t))
                    .collect()
            };
            assert!(!scopes.is_empty(), "no scope read from: {arm}");
            for pattern in patterns.split('|').map(str::trim) {
                let code = pattern.strip_prefix("KeyCode::").expect(pattern);
                let mut name = key_name(code);
                if guard.contains("KeyModifiers::CONTROL") {
                    name = format!("Ctrl+{}", name.to_uppercase());
                }
                for scope in &scopes {
                    handled.push((*scope, name.clone(), arm.clone()));
                }
            }
        }
        assert!(handled.len() > 50, "read only {} keys", handled.len());
        handled
    }

    #[test]
    fn every_handled_key_has_a_help_line() {
        let documented = |scope: Scope, key: &str| {
            FULL_HELP
                .iter()
                .filter(|s| s.scope == scope)
                .flat_map(|s| s.keys.iter())
                .any(|(label, _)| label_keys(label).contains(key))
        };
        let missing: Vec<String> = handled_keys()
            .into_iter()
            .filter(|(scope, key, _)| !documented(*scope, key))
            .map(|(scope, key, arm)| format!("{scope:?} `{key}`: {arm}"))
            .collect();
        assert!(
            missing.is_empty(),
            "keys with no help line:\n{}",
            missing.join("\n")
        );
    }

    #[test]
    fn help_sections_are_unique() {
        let mut seen = BTreeSet::new();
        for section in FULL_HELP {
            assert!(
                seen.insert(section.title),
                "{} appears twice",
                section.title
            );
        }
        for tab in Tab::ALL {
            let count = FULL_HELP
                .iter()
                .filter(|s| s.scope == Scope::Tab(*tab))
                .count();
            assert_eq!(count, 1, "{tab:?} has {count} help sections");
        }
    }

    #[test]
    fn label_keys_reads_the_notations_help_uses() {
        let keys = |l: &str| label_keys(l).into_iter().collect::<Vec<_>>();
        assert_eq!(keys("q / Ctrl+C"), ["Ctrl+C", "q"]);
        assert_eq!(keys("R/F/E"), ["E", "F", "R"]);
        assert_eq!(keys("] / ["), ["[", "]"]);
        assert_eq!(keys("/"), ["/"]);
        assert_eq!(keys(","), [","]);
        assert_eq!(keys("↑↓ / j/k"), ["j", "k", "↑", "↓"]);
        assert_eq!(keys("1-9, 0").len(), 10);
        assert_eq!(keys("N (shift)"), ["N"]);
    }
}
