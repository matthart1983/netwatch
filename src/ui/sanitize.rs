//! Terminal safety for strings that someone else wrote.
//!
//! An SNI, a DNS name, an HTTP Host, an SSH banner, a PTR record, a whois
//! reply and another user's process name all reach the screen as text we did
//! not choose, and crossterm writes cell symbols to the terminal verbatim.
//! ratatui 0.27 gave a control character a cell of its own, so a ClientHello
//! whose SNI is `\x1b]52;c;…\x07` wrote the viewer's clipboard (OSC 52), and
//! the same trick reaches the window title, screen clears and cursor moves.
//! ratatui 0.30 leaves control characters out of the text it lays out, with no
//! mark where they were, but a symbol set on a cell directly still goes out as
//! it is. Bidi overrides and zero-width characters execute nothing, but they
//! let one hostname read as another; `Line`, `Table` and `List` keep them
//! appended to the neighbouring cell.
//!
//! Two layers:
//! - [`display`] at ingest, where a string is built from packet bytes, a
//!   peer's reply or another process's name. Each unsafe character becomes
//!   [`REPLACEMENT`], so the text keeps its width and the tampering stays
//!   visible. Exports, the clipboard and the log get the clean string too.
//! - [`scrub_buffer`] on every frame, after every widget has drawn, for
//!   anything an ingest path missed.

use std::borrow::Cow;

use ratatui::buffer::Buffer;

/// Stands in for a character that must never reach the terminal. The packet
/// ASCII pane already uses it for non-printable bytes.
pub const REPLACEMENT: char = '·';

/// True for a character that can start an escape sequence, move the cursor,
/// or change how the rest of the line reads.
pub fn is_unsafe(c: char) -> bool {
    // C0 (ESC, BEL, TAB, CR, LF, ...), DEL, and C1, which includes the 8-bit
    // CSI U+009B that xterm-family terminals honour like ESC [.
    c.is_control()
        || matches!(
            c,
            // Arabic letter mark, which reorders text like RLM.
            '\u{061C}'
                // Zero-width space, non-joiner, joiner, and the LRM/RLM marks.
                | '\u{200B}'..='\u{200F}'
                // Bidi embeddings and overrides ("trojan source").
                | '\u{202A}'..='\u{202E}'
                // Word joiner.
                | '\u{2060}'
                // Bidi isolates.
                | '\u{2066}'..='\u{2069}'
                // Zero-width no-break space / BOM.
                | '\u{FEFF}'
        )
}

fn replace_where(s: &str, bad: impl Fn(char) -> bool) -> Cow<'_, str> {
    if !s.chars().any(&bad) {
        return Cow::Borrowed(s);
    }
    Cow::Owned(
        s.chars()
            .map(|c| if bad(c) { REPLACEMENT } else { c })
            .collect(),
    )
}

/// `s` with every unsafe character replaced by [`REPLACEMENT`]. Borrows when
/// `s` is already clean, which is nearly always.
pub fn display(s: &str) -> Cow<'_, str> {
    replace_where(s, is_unsafe)
}

/// [`display`] for a `String` the caller already owns: a clean string is
/// returned as is, without a copy.
pub fn display_owned(s: String) -> String {
    if s.chars().any(is_unsafe) {
        display(&s).into_owned()
    } else {
        s
    }
}

/// [`display`] that keeps `\n`, for text the caller splits into lines itself.
pub fn display_multiline(s: &str) -> Cow<'_, str> {
    replace_where(s, |c| c != '\n' && is_unsafe(c))
}

/// Remove unsafe characters from every cell of a drawn frame.
///
/// The backstop behind [`display`]. A control character set on a cell
/// directly arrives in a cell of its own and becomes [`REPLACEMENT`]; a
/// zero-width one arrives appended to its neighbour's symbol and is dropped,
/// which leaves the neighbour and the cell's width as they were.
pub fn scrub_buffer(buf: &mut Buffer) {
    for cell in &mut buf.content {
        if !cell.symbol().chars().any(is_unsafe) {
            continue;
        }
        let kept: String = cell.symbol().chars().filter(|&c| !is_unsafe(c)).collect();
        if kept.is_empty() {
            cell.set_symbol(REPLACEMENT.encode_utf8(&mut [0; 4]));
        } else {
            cell.set_symbol(&kept);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Rect;
    use ratatui::text::Line;
    use ratatui::widgets::{Paragraph, Widget};
    use ratatui::Terminal;

    /// The payload from the review: OSC 52 writes the clipboard, BEL ends it.
    const OSC52: &str = "\x1b]52;c;AAAA\x07";

    fn has_unsafe(buf: &Buffer) -> bool {
        buf.content
            .iter()
            .any(|c| c.symbol().chars().any(is_unsafe))
    }

    #[test]
    fn replaces_an_osc52_clipboard_write() {
        assert_eq!(display(OSC52), "·]52;c;AAAA·");
    }

    #[test]
    fn replaces_c0_del_and_c1() {
        for c in [
            '\x1b', '\x07', '\t', '\n', '\r', '\0', '\x7f', '\u{85}', '\u{9b}',
        ] {
            assert_eq!(
                display(&format!("a{c}b")),
                "a·b",
                "U+{:04X} survived",
                c as u32
            );
        }
    }

    #[test]
    fn replaces_bidi_controls_and_zero_width_characters() {
        // "gnp.exe" reads as "exe.png" under a right-to-left override.
        assert_eq!(display("gnp\u{202E}.exe"), "gnp·.exe");
        for c in [
            '\u{061C}', '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{202A}',
            '\u{202B}', '\u{202C}', '\u{202D}', '\u{2060}', '\u{2066}', '\u{2067}', '\u{2068}',
            '\u{2069}', '\u{FEFF}',
        ] {
            assert_eq!(
                display(&format!("a{c}b")),
                "a·b",
                "U+{:04X} survived",
                c as u32
            );
        }
    }

    #[test]
    fn borrows_clean_text_unchanged() {
        for s in [
            "example.com",
            "xn--bcher-kva.example",
            "日本語",
            "café",
            "e\u{301}",
            "🦀",
            "",
        ] {
            assert!(matches!(display(s), Cow::Borrowed(b) if b == s), "{s:?}");
        }
        let owned = String::from("example.com");
        let ptr = owned.as_ptr();
        let kept = display_owned(owned);
        assert_eq!(kept.as_ptr(), ptr, "clean string was copied");
        assert_eq!(display_owned(OSC52.to_string()), "·]52;c;AAAA·");
    }

    #[test]
    fn multiline_keeps_newlines_and_nothing_else() {
        assert_eq!(
            display_multiline("GET /\r\nHost: a\x1bb\n"),
            "GET /·\nHost: a·b\n"
        );
        assert!(matches!(display_multiline("a\nb"), Cow::Borrowed(_)));
    }

    /// Why the backstop exists. ratatui 0.30 leaves the ESC and BEL out of
    /// text it lays out, but a symbol set on a cell keeps them, and cell
    /// symbols are what crossterm writes to the terminal.
    #[test]
    fn ratatui_keeps_control_characters_set_on_a_cell() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 30, 1));
        Paragraph::new(format!("HTTPS {OSC52}")).render(buf.area, &mut buf);
        assert!(!has_unsafe(&buf), "ratatui laid out a control character");
        buf[(0, 0)].set_symbol(OSC52);
        assert!(has_unsafe(&buf));
    }

    #[test]
    fn scrub_buffer_replaces_control_cells_and_drops_zero_width_ones() {
        let mut terminal = Terminal::new(TestBackend::new(40, 1)).unwrap();
        terminal
            .draw(|f| {
                // `Line` rather than `Paragraph`: Paragraph skips zero-width
                // graphemes, Line appends them to the previous cell. Both
                // drop the ESC and BEL, so one is set on a cell directly, the
                // only way a control character reaches a cell now.
                f.render_widget(Line::from(format!("{OSC52} x\u{202E}y")), f.area());
                f.buffer_mut()[(16, 0)].set_symbol("\x1b");
                assert_eq!(f.buffer_mut()[(11, 0)].symbol(), "x\u{202E}");
                scrub_buffer(f.buffer_mut());
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        assert!(!has_unsafe(buf));
        let row: String = buf.content.iter().map(|c| c.symbol()).collect();
        assert_eq!(row.trim_end(), "]52;c;AAAA xy   ·");
    }
}
