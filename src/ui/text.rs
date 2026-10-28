//! Text measured and cut in the cells ratatui draws.
//!
//! ratatui lays a string out one grapheme at a time, drops any grapheme that
//! holds a control character, and advances by [`CellWidth`]. Two other
//! measures disagree with it. unicode-width's `str` width counts a halfwidth
//! katakana sound mark (ﾞ or ﾟ) as 0, where ratatui gives it a cell, as
//! terminals do. Summing widths one char at a time counts `❤️` and `#️⃣` as 1
//! where they draw 2, and `👍🏽` or a ZWJ family as 4 to 6 where they draw 2.
//! Anything that places the next column from a string's width measures it
//! here.

use ratatui::buffer::CellWidth;
use unicode_segmentation::UnicodeSegmentation;

/// Columns `s` takes when ratatui draws it.
pub fn width(s: &str) -> usize {
    // Each ASCII char but CR LF is a grapheme of its own, and one cell wide
    // unless it is a control character.
    if s.is_ascii() {
        return s.bytes().filter(|b| !b.is_ascii_control()).count();
    }
    s.graphemes(true).map(grapheme_width).sum()
}

/// Cut `s` to `w` columns on a grapheme boundary, appending `…` when it
/// doesn't fit. Below 2 columns the ellipsis is all that is left.
pub fn truncate_end(s: &str, w: usize) -> String {
    if width(s) <= w {
        return s.to_string();
    }
    if w <= 1 {
        return "…".into();
    }
    let mut out = prefix(s, w - 1).to_string();
    out.push('…');
    out
}

/// The longest start of `s` that fits in `w` columns, cut between graphemes.
pub fn prefix(s: &str, w: usize) -> &str {
    let mut used = 0;
    let end = if s.is_ascii() {
        // A grapheme a byte, but for CR LF, whose halves take no cell and so
        // are never cut apart. Segmenting took 5 to 8 times as long on the
        // ASCII names that fill a big table.
        s.bytes()
            .position(|b| {
                used += usize::from(!b.is_ascii_control());
                used > w
            })
            .unwrap_or(s.len())
    } else {
        s.grapheme_indices(true)
            .find(|(_, g)| {
                used += grapheme_width(g);
                used > w
            })
            .map_or(s.len(), |(i, _)| i)
    };
    &s[..end]
}

/// A grapheme holding a control character takes no cell: ratatui drops it.
/// Asking [`CellWidth`] about a lone control byte trips its debug assertion.
fn grapheme_width(g: &str) -> usize {
    if g.contains(char::is_control) {
        0
    } else {
        g.cell_width() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;
    use ratatui::style::Style;

    /// One of each kind of grapheme the char-by-char measures got wrong, and
    /// the plain ones they got right.
    const SAMPLES: &[&str] = &[
        "abcdefghijklmnopqrstuvwxyz",
        "あいうえお",
        // VS16: the heart is 1 column alone and 2 with the selector.
        "❤\u{FE0F}",
        // Keycap: `#`, VS16, then the combining keycap.
        "#\u{FE0F}\u{20E3}",
        // Skin-tone modifier.
        "👍\u{1F3FD}",
        // ZWJ family.
        "👨\u{200D}👩\u{200D}👧",
        // Halfwidth katakana and its sound mark, a cell each.
        "ﾊﾟ",
        // e and a combining acute.
        "e\u{301}",
        // Regional-indicator pair.
        "🇯🇵",
    ];

    /// The column ratatui's `set_stringn` stops at, which is what the next
    /// field has to start after.
    fn drawn(s: &str) -> usize {
        let mut b = Buffer::empty(Rect::new(0, 0, 200, 1));
        b.set_stringn(0, 0, s, usize::MAX, Style::default()).0 as usize
    }

    #[test]
    fn width_is_what_ratatui_draws() {
        for base in SAMPLES {
            for n in [0, 1, 3] {
                let s = base.repeat(n);
                assert_eq!(width(&s), drawn(&s), "{s:?}");
            }
        }
        assert_eq!(width("ﾊﾟﾊﾟ"), 4);
        assert_eq!(width("❤\u{FE0F}"), 2);
        assert_eq!(width("👨\u{200D}👩\u{200D}👧"), 2);
        assert_eq!(width("a\x1b]0;x\x07b\r\n"), drawn("a\x1b]0;x\x07b\r\n"));
        assert_eq!(width("a\u{301}\u{1b}"), 1);
    }

    #[test]
    fn truncate_end_fits_every_width_and_cuts_between_graphemes() {
        for base in SAMPLES {
            let s = base.repeat(24);
            assert!(width(&s) > 20, "{base:?} is not long enough");
            for w in 0..=20usize {
                let out = truncate_end(&s, w);
                assert!(width(&out) <= w.max(1), "{base:?} at {w}: {out:?}");
                let kept = out.strip_suffix('…').unwrap_or(&out);
                assert!(
                    s.grapheme_indices(true).any(|(i, _)| i == kept.len()) && s.starts_with(kept),
                    "{base:?} at {w} split a grapheme: {out:?}"
                );
                // Every whole grapheme that fits is kept.
                if w >= 2 {
                    let next = s[kept.len()..].graphemes(true).next().unwrap();
                    assert!(
                        width(kept) + grapheme_width(next) > w - 1,
                        "{base:?} at {w} cut early: {out:?}"
                    );
                }

                // What the next column would see: a sentinel just past the
                // slot survives the draw.
                let edge = w.max(1) as u16;
                let mut b = Buffer::empty(Rect::new(0, 0, 40, 1));
                b[(edge, 0)].set_symbol("|");
                b.set_stringn(0, 0, &out, usize::MAX, Style::default());
                assert_eq!(b[(edge, 0)].symbol(), "|", "{base:?} at {w}: {out:?}");
            }
        }
    }

    #[test]
    fn truncate_end_keeps_what_fits_and_marks_the_cut() {
        assert_eq!(truncate_end("", 0), "");
        assert_eq!(truncate_end("firefox", 7), "firefox");
        assert_eq!(truncate_end("firefox", 6), "firef…");
        assert_eq!(truncate_end("firefox", 1), "…");
        assert_eq!(truncate_end("ﾊﾟﾊﾟ", 4), "ﾊﾟﾊﾟ");
        assert_eq!(truncate_end("ﾊﾟﾊﾟ", 3), "ﾊﾟ…");
        assert_eq!(truncate_end("あいう", 5), "あい…");
        assert_eq!(truncate_end("あいう", 4), "あ…");
    }

    /// The ASCII path walks bytes rather than graphemes, so CR LF is the one
    /// grapheme it sees as two. Neither half takes a cell, so it never cuts
    /// between them.
    #[test]
    fn prefix_keeps_cr_lf_together() {
        assert_eq!(prefix("ab\r\ncd", 2), "ab\r\n");
        assert_eq!(prefix("ab\r\ncd", 3), "ab\r\nc");
        assert_eq!(prefix("あ\r\nい", 2), "あ\r\n");
        assert_eq!(prefix("ab", 0), "");
    }
}
