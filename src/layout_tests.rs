//! Every screen at every size people run, checked for the ways a layout
//! breaks quietly.
//!
//! A table that runs past the right edge does not fail a unit test: the cells
//! past the edge are just not drawn. The 2026-11 review found the tab bar
//! missing four tabs at 80 columns, the Connections tab's rate columns off
//! screen at 120, and the dashboard's largest panel blank at 80 — all on
//! `main`, all with a green suite. These tests draw the whole frame into a
//! `TestBackend` and assert what a reader would notice:
//!
//! - every tab's digit is in the bar, so every tab is reachable and clickable;
//! - the footer still offers `? help`, the hint that leads to all the others;
//! - each table's header is on screen whole, last column included;
//! - no bordered panel is left with nothing in it but blanks;
//! - nothing panics at sizes smaller than any layout was designed for.
//!
//! They assert properties, not golden text, so restyling a panel does not
//! mean re-recording forty screens.

use crate::app::{draw_frame, App, Tab, ViewMode};
use crate::config::NetwatchConfig;
use crate::testutil::connections::synthetic_connections;
use ratatui::{backend::TestBackend, Terminal};

/// Terminal sizes the layouts are designed for: the classic 80×24, a laptop
/// split, a laptop full screen, and a desktop.
const SIZES: [(u16, u16); 5] = [(80, 24), (100, 30), (120, 40), (160, 50), (200, 55)];

fn app_with(rows: usize) -> App {
    let mut app = App::prepare_with_config(NetwatchConfig::default());
    // Not the user's learned baseline, which would make the screens depend on
    // whose machine this is.
    app.egress_profiler = crate::collectors::egress::EgressProfiler::new();
    app.ui.view_mode = ViewMode::Full;
    let mut conns = synthetic_connections(rows, 1);
    for c in &mut conns {
        c.evidence.observe();
    }
    app.connection_collector.publish_for_test(conns);
    app.observe_connections();
    app
}

fn screen(app: &mut App, width: u16, height: u16) -> Vec<String> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|f| draw_frame(f, app)).unwrap();
    let buffer = terminal.backend().buffer();
    buffer
        .content
        .chunks(buffer.area.width as usize)
        .map(|row| row.iter().map(|c| c.symbol()).collect())
        .collect()
}

fn dump(lines: &[String]) -> String {
    lines.join("\n")
}

#[test]
fn every_tab_digit_is_in_the_bar_at_every_size() {
    let mut app = app_with(40);
    for (w, h) in SIZES {
        for &tab in Tab::ALL {
            app.ui.current_tab = tab;
            let lines = screen(&mut app, w, h);
            let bar = &lines[0];
            for digit in ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"] {
                assert!(
                    bar.contains(&format!(" {digit} ")),
                    "{w}x{h} {tab:?}: no tab {digit} in {bar:?}"
                );
            }
        }
    }
}

#[test]
fn the_footer_always_offers_help() {
    let mut app = app_with(40);
    for (w, h) in SIZES {
        for &tab in Tab::ALL {
            app.ui.current_tab = tab;
            let lines = screen(&mut app, w, h);
            assert!(
                lines.iter().rev().take(3).any(|l| l.contains("? help")),
                "{w}x{h} {tab:?}: no `? help` in the footer\n{}",
                dump(&lines)
            );
        }
    }
}

/// The last column of each tab's main table. If it is on screen, the columns
/// before it are.
fn last_header(tab: Tab) -> Option<(&'static str, &'static [&'static str])> {
    match tab {
        // `age` goes in the compact layout; `rtt` never does.
        Tab::Connections => Some(("process", &["remote", "state", "rx/s", "tx/s", "rtt"])),
        Tab::Processes => Some(("process", &["pid", "conns", "cpu"])),
        Tab::Egress => Some(("process / destination", &["policy"])),
        _ => None,
    }
}

#[test]
fn table_headers_are_on_screen_whole() {
    let mut app = app_with(40);
    for (w, h) in SIZES {
        for &tab in Tab::ALL {
            let Some((first, rest)) = last_header(tab) else {
                continue;
            };
            app.ui.current_tab = tab;
            let lines = screen(&mut app, w, h);
            let header = lines
                .iter()
                .find(|l| l.starts_with('│') && l.contains(first))
                .unwrap_or_else(|| panic!("{w}x{h} {tab:?}: no table header\n{}", dump(&lines)));
            for name in rest {
                // A whole word: `rtt` followed by a blank or the border, not
                // `rt` cut off by it.
                let whole = header.match_indices(name).any(|(i, _)| {
                    header[i + name.len()..]
                        .chars()
                        .next()
                        .is_none_or(|c| c == ' ' || c == '│')
                });
                assert!(whole, "{w}x{h} {tab:?}: `{name}` is not in {header:?}");
            }
        }
    }
}

/// A bordered panel with a title and nothing inside it. The dashboard's
/// connections panel was one at 80 columns, with 181 connections to show.
#[test]
fn no_titled_panel_is_drawn_empty_on_the_dashboard() {
    let mut app = app_with(40);
    app.ui.current_tab = Tab::Dashboard;
    for (w, h) in SIZES {
        let lines = screen(&mut app, w, h);
        let top = lines
            .iter()
            .position(|l| l.contains("connections ─"))
            .unwrap_or_else(|| panic!("{w}x{h}: no connections panel\n{}", dump(&lines)));
        let body: Vec<&String> = lines[top + 1..]
            .iter()
            .take_while(|l| l.starts_with('│'))
            .collect();
        assert!(
            body.iter().any(|l| l.contains("process")),
            "{w}x{h}: the connections panel has no header\n{}",
            dump(&lines)
        );
        assert!(
            body.len() >= 2,
            "{w}x{h}: the connections panel has no rows\n{}",
            dump(&lines)
        );
    }
}

/// Smaller than anything is designed for. The screens may be useless; they
/// may not panic on a subtraction.
#[test]
fn no_view_panics_at_any_size() {
    let mut app = app_with(40);
    for view in [ViewMode::Full, ViewMode::Lite, ViewMode::Dense] {
        app.ui.view_mode = view;
        for (w, h) in [
            (1, 1),
            (10, 3),
            (20, 5),
            (40, 10),
            (60, 15),
            (80, 24),
            (120, 40),
            (300, 100),
        ] {
            for &tab in Tab::ALL {
                app.ui.current_tab = tab;
                screen(&mut app, w, h);
            }
            for overlay in 0..2 {
                app.ui.show_help = overlay == 0;
                screen(&mut app, w, h);
            }
            app.ui.show_help = false;
        }
    }
}

/// `t` is a tab's own control where the tab has one, and nothing elsewhere.
/// It used to repaint the whole tool in the next theme on six of the ten tabs.
#[test]
fn t_never_changes_the_theme() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let mut app = app_with(10);
    let theme = app.theme.name;
    for &tab in Tab::ALL {
        app.ui.current_tab = tab;
        crate::app::handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE),
        );
        assert_eq!(app.theme.name, theme, "{tab:?}: t changed the theme");
    }
}

/// `↵` drills in, `esc` comes back the way it went, and a tab chosen by its
/// digit is not a level to come back from.
#[test]
fn enter_drills_in_and_escape_steps_back() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    let press = |app: &mut App, code| {
        crate::app::handle_key(app, KeyEvent::new(code, KeyModifiers::NONE));
    };
    let mut app = app_with(40);
    app.ui.current_tab = Tab::Connections;
    // Unfold the first group and step onto a connection.
    press(&mut app, KeyCode::Char('z'));
    press(&mut app, KeyCode::Down);
    if crate::ui::connections::selected_connection(&app).is_none() {
        press(&mut app, KeyCode::Down);
    }
    assert!(crate::ui::connections::selected_connection(&app).is_some());
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.ui.current_tab, Tab::Packets);
    assert_eq!(app.ui.drill_path, [Tab::Connections]);

    let lines = screen(&mut app, 160, 50);
    assert!(
        lines[1].contains("connections › packets") && lines[1].contains("esc back"),
        "no breadcrumb in {:?}",
        lines[1]
    );

    press(&mut app, KeyCode::Esc);
    assert_eq!(app.ui.current_tab, Tab::Connections);
    assert!(app.ui.drill_path.is_empty());
    assert!(
        app.ui.packet_filter_active.is_none(),
        "the drill's filter stayed"
    );

    // By digit: nowhere to go back to.
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('5'));
    assert!(app.ui.drill_path.is_empty());
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.ui.current_tab, Tab::Stats);
}

/// No cell is drawn in its own background colour. In the `terminal` theme the
/// selection ground and muted text are both ANSI 8, and the selected row of an
/// idle table was invisible.
#[test]
fn no_text_is_the_colour_of_its_ground() {
    use ratatui::style::Color;
    fn slot(c: Color) -> Color {
        match c {
            Color::DarkGray => Color::Indexed(8),
            c => c,
        }
    }
    let mut app = app_with(40);
    for theme in crate::theme::THEME_NAMES {
        app.theme = crate::theme::by_name(theme);
        for &tab in Tab::ALL {
            app.ui.current_tab = tab;
            let mut terminal = Terminal::new(TestBackend::new(140, 45)).unwrap();
            terminal.draw(|f| draw_frame(f, &mut app)).unwrap();
            let buffer = terminal.backend().buffer();
            for (i, cell) in buffer.content.iter().enumerate() {
                if cell.symbol().trim().is_empty() || cell.bg == Color::Reset {
                    continue;
                }
                assert_ne!(
                    slot(cell.fg),
                    slot(cell.bg),
                    "{theme} {tab:?}: {:?} at column {}, row {} is drawn in its ground colour",
                    cell.symbol(),
                    i % 140,
                    i / 140
                );
            }
        }
    }
}

/// One key-hint rendering: `↵ apply`, never `Enter:Apply`. The tabs moved to
/// it in 0.30 and the overlays were missed — the sort picker, Settings and the
/// memory overlay each kept a `Key:Label` row of their own.
#[test]
fn no_screen_or_overlay_uses_the_old_key_colon_label_hints() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    fn old_style(line: &str) -> Option<String> {
        let chars: Vec<char> = line.chars().collect();
        for i in 1..chars.len().saturating_sub(2) {
            if chars[i] == ':'
                && (chars[i - 1].is_alphabetic() || "↑↓←→/".contains(chars[i - 1]))
                && chars[i + 1].is_uppercase()
                && chars[i + 2].is_lowercase()
            {
                let from = i.saturating_sub(8);
                let to = (i + 10).min(chars.len());
                return Some(chars[from..to].iter().collect());
            }
        }
        None
    }
    let check = |app: &mut App, what: &str| {
        for line in screen(app, 140, 45) {
            if let Some(found) = old_style(&line) {
                panic!("{what}: old-style hint {found:?} in {line:?}");
            }
        }
    };
    let press = |app: &mut App, c: char| {
        crate::app::handle_key(app, KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
    };
    let mut app = app_with(40);
    for &tab in Tab::ALL {
        app.ui.current_tab = tab;
        check(&mut app, &format!("{tab:?}"));
    }
    app.ui.current_tab = Tab::Connections;
    for (key, name) in [
        ('s', "sort picker"),
        (',', "settings"),
        ('M', "memory"),
        (':', "palette"),
    ] {
        press(&mut app, key);
        check(&mut app, name);
        crate::app::handle_key(&mut app, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    }
    app.ui.current_tab = Tab::Diagnose;
    press(&mut app, 'c');
    check(&mut app, "diagnose coverage");
}
