//! The `:` command palette: every action in the full view, by name.
//!
//! The tool has about seventy key bindings across ten tabs, and the footer can
//! show nine of them. The palette is the rest: type a few letters of what you
//! want, press `↵`, and it happens. Each row also shows the key that does the
//! same thing, so the palette teaches the bindings rather than replacing them.
//!
//! A command is a name and the key it stands for. Running one closes the
//! palette and sends that key through the ordinary key handler, so a command
//! cannot do something its key does not, and cannot drift from it: there is
//! one implementation of every action, and the palette is a second way to
//! reach it.

use crate::app::{App, Tab};
use crate::ui::widgets;
use crossterm::event::KeyCode;
use ratatui::{
    prelude::*,
    widgets::{Clear, Paragraph},
};

/// Open or closed, what has been typed, and which match the cursor is on.
#[derive(Default)]
pub struct PaletteState {
    pub open: bool,
    pub query: String,
    pub selected: usize,
}

impl PaletteState {
    pub fn open(&mut self) {
        self.open = true;
        self.query.clear();
        self.selected = 0;
    }

    pub fn close(&mut self) {
        self.open = false;
    }
}

/// One action: what it is called, the key that does it, and the tab it
/// belongs to (`None` for the keys that work everywhere).
pub struct Command {
    pub name: &'static str,
    pub key: KeyCode,
    pub tab: Option<Tab>,
}

const fn global(name: &'static str, key: char) -> Command {
    Command {
        name,
        key: KeyCode::Char(key),
        tab: None,
    }
}

const fn on(tab: Tab, name: &'static str, key: char) -> Command {
    Command {
        name,
        key: KeyCode::Char(key),
        tab: Some(tab),
    }
}

/// Every command, in the order an empty query lists them: the current tab's
/// own first (see [`matches`]), then these.
pub const COMMANDS: &[Command] = &[
    global("go to dashboard", '1'),
    global("go to connections", '2'),
    global("go to interfaces", '3'),
    global("go to packets", '4'),
    global("go to stats", '5'),
    global("go to topology", '6'),
    global("go to timeline", '7'),
    global("go to processes", '8'),
    global("go to diagnose", '9'),
    global("go to egress", '0'),
    global("view: lite", 'L'),
    global("view: next (full, lite, dense)", 'V'),
    global("pause or resume collection", 'p'),
    global("refresh all data now", 'r'),
    global("settings: theme, refresh rate, interface", ','),
    global("help: every key", '?'),
    global("recorder: arm or disarm", 'R'),
    global("recorder: freeze the incident window", 'F'),
    global("recorder: export the incident bundle", 'E'),
    global("geo: show or hide locations", 'g'),
    global("memory: sizes of the bounded collections", 'M'),
    global("quit", 'q'),
    on(Tab::Dashboard, "scale: linear or log", 't'),
    on(Tab::Dashboard, "fold or unfold every group", 'z'),
    on(Tab::Connections, "sort by column", 's'),
    on(Tab::Connections, "filter by text", '/'),
    on(Tab::Connections, "show: next state filter", 'f'),
    on(Tab::Connections, "group: next grouping", 'G'),
    on(Tab::Connections, "fold or unfold every group", 'z'),
    on(Tab::Connections, "traceroute to the selected remote", 'T'),
    on(Tab::Interfaces, "sort by column", 's'),
    on(Tab::Interfaces, "show: next interface filter", 'f'),
    on(Tab::Packets, "filter packets", '/'),
    on(Tab::Packets, "capture: start or stop", 'c'),
    on(Tab::Packets, "capture: next interface", 'i'),
    on(Tab::Packets, "follow the selected stream", 'f'),
    on(
        Tab::Packets,
        "export the shown packets (pcapng or pcap)",
        'w',
    ),
    on(Tab::Packets, "next expert finding", 'n'),
    on(Tab::Packets, "clear the capture", 'X'),
    on(Tab::Stats, "range: next time range", 't'),
    on(Tab::Topology, "traceroute to the selected remote", 'T'),
    on(Tab::Timeline, "filter: next event filter", 'f'),
    on(Tab::Timeline, "range: next time window", 't'),
    on(Tab::Processes, "sort by column", 's'),
    on(Tab::Processes, "export the table as csv", 'e'),
    on(Tab::Diagnose, "coverage: which checks are running", 'c'),
    on(Tab::Diagnose, "report: open the incident report", 'o'),
    on(Tab::Diagnose, "report: export", 'e'),
    on(Tab::Diagnose, "copy the summary", 'y'),
    on(Tab::Diagnose, "acknowledge the selected issue", 'a'),
    on(Tab::Diagnose, "mute the selected issue", 'm'),
    on(Tab::Egress, "sort", 's'),
    on(Tab::Egress, "filter by text", '/'),
    on(Tab::Egress, "detail pane: show or hide", 'd'),
    on(Tab::Egress, "history: show or hide past destinations", 'H'),
    on(Tab::Egress, "policy: add every observed destination", 'P'),
    on(Tab::Egress, "export", 'e'),
];

/// The commands `query` selects on `tab`, best first.
///
/// Every word of the query has to appear in the name, in any order, so
/// `rep exp` finds `report: export`. The current tab's commands come before
/// the global ones, and a name that starts with the query before one that
/// only contains it. Commands for other tabs are left out: their keys would
/// do something else here.
pub fn matches(query: &str, tab: Tab) -> Vec<&'static Command> {
    let query = query.to_lowercase();
    let words: Vec<&str> = query.split_whitespace().collect();
    let mut found: Vec<(u8, usize, &'static Command)> = COMMANDS
        .iter()
        .enumerate()
        .filter(|(_, c)| c.tab.is_none_or(|t| t == tab))
        .filter(|(_, c)| words.iter().all(|w| c.name.contains(w)))
        .map(|(i, c)| {
            let prefix = !query.is_empty() && c.name.starts_with(query.trim());
            let rank = match (prefix, c.tab.is_some()) {
                (true, _) => 0,
                (false, true) => 1,
                (false, false) => 2,
            };
            (rank, i, c)
        })
        .collect();
    found.sort_by_key(|&(rank, i, _)| (rank, i));
    found.into_iter().map(|(_, _, c)| c).collect()
}

/// What a key does while the palette is open.
pub enum Outcome {
    /// Still open.
    Stay,
    /// Closed without running anything.
    Closed,
    /// Closed; send this key through the ordinary handler.
    Run(KeyCode),
}

pub fn handle_key(state: &mut PaletteState, tab: Tab, code: KeyCode) -> Outcome {
    let count = matches(&state.query, tab).len();
    match code {
        KeyCode::Esc => {
            state.close();
            Outcome::Closed
        }
        KeyCode::Enter => {
            let chosen = matches(&state.query, tab)
                .get(state.selected.min(count.saturating_sub(1)))
                .map(|c| c.key);
            state.close();
            chosen.map_or(Outcome::Closed, Outcome::Run)
        }
        KeyCode::Up => {
            state.selected = state.selected.saturating_sub(1);
            Outcome::Stay
        }
        KeyCode::Down | KeyCode::Tab => {
            state.selected = (state.selected + 1).min(count.saturating_sub(1));
            Outcome::Stay
        }
        KeyCode::Backspace => {
            // Backspace on an empty line closes, as it does in a shell
            // history search: there is nothing left to take back.
            if state.query.pop().is_none() {
                state.close();
                return Outcome::Closed;
            }
            state.selected = 0;
            Outcome::Stay
        }
        KeyCode::Char(c) if !c.is_control() && state.query.chars().count() < 40 => {
            state.query.push(c);
            state.selected = 0;
            Outcome::Stay
        }
        _ => Outcome::Stay,
    }
}

fn key_label(code: KeyCode) -> String {
    match code {
        KeyCode::Char(c) => c.to_string(),
        other => format!("{other:?}").to_lowercase(),
    }
}

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let state = &app.ui.palette;
    let found = matches(&state.query, app.ui.current_tab);

    let width = 64.min(area.width.saturating_sub(4)).max(20).min(area.width);
    let list_rows = (found.len().max(1) as u16).min(12);
    // border, prompt, rule, rows, hint, border
    let height = (list_rows + 5).min(area.height);
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        // A third of the way down: under the tab bar, above the middle, where
        // the eye already is after pressing `:`.
        y: area.y + (area.height.saturating_sub(height)) / 4,
        width,
        height,
    };
    f.render_widget(Clear, popup);
    widgets::paint_overlay_bg(f, t, popup);
    let block = widgets::panel_block(t)
        .title(Line::from(Span::styled(
            " command ",
            Style::default().fg(t.brand).bold(),
        )))
        .border_style(Style::default().fg(t.brand));
    let inner = block.inner(popup);
    f.render_widget(block, popup);
    if inner.height < 3 || inner.width < 10 {
        return;
    }

    let name_w = usize::from(inner.width).saturating_sub(2 + 6);
    let mut lines = vec![
        Line::from(vec![
            Span::styled(" : ", Style::default().fg(t.brand).bold()),
            Span::styled(state.query.clone(), Style::default().fg(t.text_primary)),
            Span::styled("▏", Style::default().fg(t.brand)),
        ]),
        Line::from(Span::styled(
            "─".repeat(usize::from(inner.width)),
            Style::default().fg(t.border),
        )),
    ];

    let visible = usize::from(inner.height.saturating_sub(3));
    let selected = state.selected.min(found.len().saturating_sub(1));
    let top = crate::ui::tree::window_top(selected, found.len(), visible.max(1));
    if found.is_empty() {
        lines.push(Line::from(Span::styled(
            "  no command matches",
            Style::default().fg(t.text_muted),
        )));
    }
    for (i, c) in found.iter().enumerate().skip(top).take(visible) {
        let is_selected = i == selected;
        let row_style = if is_selected {
            Style::default().bg(t.selection_bg)
        } else {
            Style::default()
        };
        let name = crate::ui::text::truncate_end(c.name, name_w);
        let pad = name_w.saturating_sub(crate::ui::text::width(&name));
        lines.push(
            Line::from(vec![
                Span::styled(
                    if is_selected { " ▸ " } else { "   " },
                    Style::default().fg(t.brand),
                ),
                Span::styled(
                    name,
                    Style::default().fg(if c.tab.is_some() {
                        t.text_primary
                    } else {
                        t.text_secondary
                    }),
                ),
                Span::raw(" ".repeat(pad)),
                Span::styled(
                    format!("{:>4} ", key_label(c.key)),
                    Style::default().fg(t.key_hint).bold(),
                ),
            ])
            .style(row_style),
        );
    }
    f.render_widget(
        Paragraph::new(lines),
        Rect {
            height: inner.height.saturating_sub(1),
            ..inner
        },
    );
    f.render_widget(
        Paragraph::new(Line::from(widgets::hint_spans(
            t,
            &[
                widgets::hint("↑↓", "select"),
                widgets::hint("↵", "run"),
                widgets::hint("esc", "close"),
            ],
        )))
        .alignment(Alignment::Center),
        Rect {
            y: inner.y + inner.height - 1,
            height: 1,
            ..inner
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_word_of_the_query_must_match_in_any_order() {
        let found = matches("exp rep", Tab::Diagnose);
        assert_eq!(found[0].name, "report: export");
        assert!(matches("zzz", Tab::Dashboard).is_empty());
    }

    #[test]
    fn an_empty_query_lists_the_current_tabs_commands_first() {
        let found = matches("", Tab::Packets);
        assert_eq!(found[0].tab, Some(Tab::Packets));
        assert!(found
            .iter()
            .all(|c| c.tab.is_none_or(|t| t == Tab::Packets)));
        assert!(found.iter().any(|c| c.name == "quit"));
    }

    #[test]
    fn another_tabs_commands_are_not_offered() {
        // `e` exports on Processes and does nothing on Topology.
        assert!(matches("csv", Tab::Topology).is_empty());
        assert_eq!(matches("csv", Tab::Processes).len(), 1);
    }

    #[test]
    fn enter_runs_the_selected_command_and_escape_runs_nothing() {
        let mut state = PaletteState::default();
        state.open();
        for c in "go to stats".chars() {
            assert!(matches!(
                handle_key(&mut state, Tab::Dashboard, KeyCode::Char(c)),
                Outcome::Stay
            ));
        }
        assert!(matches!(
            handle_key(&mut state, Tab::Dashboard, KeyCode::Enter),
            Outcome::Run(KeyCode::Char('5'))
        ));
        assert!(!state.open);

        state.open();
        assert!(matches!(
            handle_key(&mut state, Tab::Dashboard, KeyCode::Esc),
            Outcome::Closed
        ));
    }

    #[test]
    fn no_two_commands_on_one_tab_share_a_name() {
        for &tab in Tab::ALL {
            let found = matches("", tab);
            let mut names: Vec<&str> = found.iter().map(|c| c.name).collect();
            names.sort_unstable();
            let before = names.len();
            names.dedup();
            assert_eq!(names.len(), before, "{tab:?} lists a name twice");
        }
    }
}
