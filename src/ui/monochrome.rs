//! `NO_COLOR` (https://no-color.org): with the variable set and not empty,
//! the TUI draws no colour.
//!
//! Applied to the finished frame rather than through a theme, so it covers
//! every view and widget, including colours a widget picks without asking the
//! theme. A cell with a background of its own (the selection, a highlighted
//! row, a filled bar) becomes reverse video, so what was marked stays marked.
//! The theme's panel fill, which `sky` and `paper` paint behind everything,
//! is not a mark and is dropped.

use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use std::sync::OnceLock;

/// Whether `NO_COLOR` is set to something other than the empty string. Read
/// once: the frame loop asks every frame.
pub fn requested() -> bool {
    static REQUESTED: OnceLock<bool> = OnceLock::new();
    *REQUESTED.get_or_init(|| from_env(std::env::var_os("NO_COLOR")))
}

fn from_env(value: Option<std::ffi::OsString>) -> bool {
    value.is_some_and(|v| !v.is_empty())
}

/// Remove every colour from a drawn frame. `panel_bg` is the theme's fill.
pub fn strip(buf: &mut Buffer, panel_bg: Color) {
    for cell in &mut buf.content {
        let marked = cell.bg != Color::Reset && cell.bg != panel_bg;
        if marked {
            // Already reversed and marked: its visible background was its
            // foreground, which is about to go, so keep the reversal. Either
            // way the cell ends up reversed.
            cell.modifier.insert(Modifier::REVERSED);
        }
        cell.fg = Color::Reset;
        cell.bg = Color::Reset;
        cell.underline_color = Color::Reset;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::layout::Rect;
    use ratatui::style::Style;

    #[test]
    fn set_and_not_empty_means_no_colour() {
        assert!(!from_env(None));
        assert!(!from_env(Some("".into())));
        assert!(from_env(Some("1".into())));
        assert!(from_env(Some("0".into())), "any value counts, even 0");
    }

    #[test]
    fn strips_colour_and_keeps_marked_cells_visible() {
        let panel = Color::Rgb(250, 248, 240);
        let mut buf = Buffer::empty(Rect::new(0, 0, 4, 1));
        buf.set_string(0, 0, "a", Style::default().fg(Color::Red));
        buf.set_string(1, 0, "b", Style::default().fg(Color::White).bg(Color::Blue));
        buf.set_string(2, 0, "c", Style::default().fg(Color::Black).bg(panel));
        buf.set_string(3, 0, "d", Style::default().add_modifier(Modifier::BOLD));

        strip(&mut buf, panel);

        for cell in &buf.content {
            assert_eq!((cell.fg, cell.bg), (Color::Reset, Color::Reset));
            assert_eq!(cell.underline_color, Color::Reset);
        }
        let reversed: Vec<bool> = buf
            .content
            .iter()
            .map(|c| c.modifier.contains(Modifier::REVERSED))
            .collect();
        assert_eq!(reversed, [false, true, false, false]);
        assert!(buf.content[3].modifier.contains(Modifier::BOLD));
    }
}
