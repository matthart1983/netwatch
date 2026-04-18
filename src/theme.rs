use ratatui::prelude::Color;

/// Semantic color roles for the NetWatch TUI.
#[derive(Debug, Clone)]
pub struct Theme {
    pub name: &'static str,

    // ── Brand / chrome ──────────────────────────────────
    pub brand: Color,
    pub active_tab: Color,
    pub inactive_tab: Color,
    pub border: Color,
    pub separator: Color,

    // ── Text ────────────────────────────────────────────
    pub text_primary: Color,
    pub text_secondary: Color,
    pub text_muted: Color,
    pub text_inverse: Color,

    // ── Status / semantic ───────────────────────────────
    pub status_good: Color,
    pub status_warn: Color,
    pub status_error: Color,
    pub status_info: Color,

    // ── Data ────────────────────────────────────────────
    pub rx_rate: Color,
    pub tx_rate: Color,
    pub key_hint: Color,

    // ── Selection ───────────────────────────────────────
    pub selection_bg: Color,
    pub highlight_bg: Color,
}

// ── Built-in themes ────────────────────────────────────────

pub const THEME_NAMES: &[&str] = &["dark", "light", "ocean", "solarized", "dracula", "nord"];

pub fn by_name(name: &str) -> Theme {
    match name.to_lowercase().as_str() {
        "light" => light(),
        "ocean" => ocean(),
        "solarized" => solarized(),
        "dracula" => dracula(),
        "nord" => nord(),
        _ => dark(),
    }
}

pub fn dark() -> Theme {
    Theme {
        name: "dark",
        brand: Color::Cyan,
        active_tab: Color::Yellow,
        inactive_tab: Color::DarkGray,
        border: Color::DarkGray,
        separator: Color::DarkGray,
        text_primary: Color::White,
        text_secondary: Color::Gray,
        text_muted: Color::DarkGray,
        text_inverse: Color::Black,
        status_good: Color::Green,
        status_warn: Color::Yellow,
        status_error: Color::Red,
        status_info: Color::Cyan,
        rx_rate: Color::Green,
        tx_rate: Color::Blue,
        key_hint: Color::Yellow,
        selection_bg: Color::Rgb(40, 40, 60),
        highlight_bg: Color::Rgb(60, 60, 80),
    }
}

pub fn light() -> Theme {
    Theme {
        name: "light",
        brand: Color::Rgb(0, 120, 180),
        active_tab: Color::Rgb(180, 100, 0),
        inactive_tab: Color::Rgb(140, 140, 140),
        border: Color::Rgb(180, 180, 180),
        separator: Color::Rgb(180, 180, 180),
        text_primary: Color::Rgb(30, 30, 30),
        text_secondary: Color::Rgb(80, 80, 80),
        text_muted: Color::Rgb(140, 140, 140),
        text_inverse: Color::White,
        status_good: Color::Rgb(0, 140, 60),
        status_warn: Color::Rgb(200, 140, 0),
        status_error: Color::Rgb(200, 40, 40),
        status_info: Color::Rgb(0, 120, 180),
        rx_rate: Color::Rgb(0, 140, 60),
        tx_rate: Color::Rgb(0, 90, 180),
        key_hint: Color::Rgb(180, 100, 0),
        selection_bg: Color::Rgb(220, 230, 240),
        highlight_bg: Color::Rgb(200, 215, 230),
    }
}

/// For Terminal.app's "Ocean" profile (bg #224FBC).
/// Colors are taken from Apple's Terminal.app default ANSI palette (Ocean
/// inherits it — the profile plist only overrides bg, text, and selection).
/// Bright variants are preferred for legibility on the deep blue bg.
/// Blue/magenta ANSI slots are avoided since they clash with the bg.
pub fn ocean() -> Theme {
    // Apple Terminal.app default ANSI palette
    let bright_black = Color::Rgb(0x81, 0x83, 0x83);
    let white = Color::Rgb(0xCB, 0xCC, 0xCD);
    let bright_white = Color::Rgb(0xFF, 0xFF, 0xFF); // Ocean's TextColor
    let bright_red = Color::Rgb(0xFC, 0x39, 0x1F);
    let bright_green = Color::Rgb(0x31, 0xE7, 0x22);
    let bright_yellow = Color::Rgb(0xEA, 0xEC, 0x23);
    let bright_cyan = Color::Rgb(0x14, 0xF0, 0xF0);
    // bright_black (#818383) on the Ocean bg (#224FBC) is below WCAG AA;
    // use a lighter neutral for muted text. Chrome (borders/separators)
    // keeps bright_black since low contrast is desirable there.
    let muted_readable = Color::Rgb(0xB5, 0xB6, 0xB7);

    Theme {
        name: "ocean",
        brand: bright_cyan,
        active_tab: bright_white,
        inactive_tab: white,
        border: bright_black,
        separator: bright_black,
        text_primary: bright_white,
        text_secondary: white,
        text_muted: muted_readable,
        text_inverse: Color::Rgb(0, 0, 0),
        status_good: bright_green,
        status_warn: bright_yellow,
        status_error: bright_red,
        status_info: bright_cyan,
        rx_rate: bright_green,
        tx_rate: bright_cyan,
        key_hint: bright_yellow,
        selection_bg: Color::Rgb(0x21, 0x6D, 0xFF), // Ocean's SelectionColor
        highlight_bg: Color::Rgb(0x3A, 0x6B, 0xE8),
    }
}

pub fn solarized() -> Theme {
    // Solarized Dark palette
    let base03 = Color::Rgb(0, 43, 54);
    let base01 = Color::Rgb(88, 110, 117);
    let _base00 = Color::Rgb(101, 123, 131);
    let base0 = Color::Rgb(131, 148, 150);
    let base1 = Color::Rgb(147, 161, 161);
    let _base2 = Color::Rgb(238, 232, 213);
    let yellow = Color::Rgb(181, 137, 0);
    let orange = Color::Rgb(203, 75, 22);
    let red = Color::Rgb(220, 50, 47);
    let green = Color::Rgb(133, 153, 0);
    let cyan = Color::Rgb(42, 161, 152);
    let blue = Color::Rgb(38, 139, 210);
    let violet = Color::Rgb(108, 113, 196);

    Theme {
        name: "solarized",
        brand: cyan,
        active_tab: yellow,
        inactive_tab: base01,
        border: base01,
        separator: base01,
        text_primary: base0,
        text_secondary: base1,
        text_muted: base01,
        text_inverse: base03,
        status_good: green,
        status_warn: yellow,
        status_error: red,
        status_info: cyan,
        rx_rate: green,
        tx_rate: blue,
        key_hint: orange,
        selection_bg: Color::Rgb(7, 54, 66),
        highlight_bg: violet,
    }
}

pub fn dracula() -> Theme {
    let bg = Color::Rgb(40, 42, 54);
    let fg = Color::Rgb(248, 248, 242);
    let comment = Color::Rgb(98, 114, 164);
    let cyan = Color::Rgb(139, 233, 253);
    let green = Color::Rgb(80, 250, 123);
    let orange = Color::Rgb(255, 184, 108);
    let pink = Color::Rgb(255, 121, 198);
    let purple = Color::Rgb(189, 147, 249);
    let red = Color::Rgb(255, 85, 85);
    let yellow = Color::Rgb(241, 250, 140);

    Theme {
        name: "dracula",
        brand: purple,
        active_tab: pink,
        inactive_tab: comment,
        border: comment,
        separator: comment,
        text_primary: fg,
        text_secondary: Color::Rgb(200, 200, 210),
        text_muted: comment,
        text_inverse: bg,
        status_good: green,
        status_warn: yellow,
        status_error: red,
        status_info: cyan,
        rx_rate: green,
        tx_rate: cyan,
        key_hint: orange,
        selection_bg: Color::Rgb(68, 71, 90),
        highlight_bg: Color::Rgb(98, 114, 164),
    }
}

pub fn nord() -> Theme {
    // Nord palette
    let polar0 = Color::Rgb(46, 52, 64);
    let snow0 = Color::Rgb(216, 222, 233);
    let snow1 = Color::Rgb(229, 233, 240);
    let frost0 = Color::Rgb(143, 188, 187);
    let frost1 = Color::Rgb(136, 192, 208);
    let frost2 = Color::Rgb(129, 161, 193);
    let frost3 = Color::Rgb(94, 129, 172);
    let aurora_red = Color::Rgb(191, 97, 106);
    let aurora_orange = Color::Rgb(208, 135, 112);
    let aurora_yellow = Color::Rgb(235, 203, 139);
    let aurora_green = Color::Rgb(163, 190, 140);

    Theme {
        name: "nord",
        brand: frost1,
        active_tab: frost0,
        inactive_tab: frost3,
        border: Color::Rgb(67, 76, 94),
        separator: Color::Rgb(67, 76, 94),
        text_primary: snow0,
        text_secondary: snow1,
        text_muted: Color::Rgb(76, 86, 106),
        text_inverse: polar0,
        status_good: aurora_green,
        status_warn: aurora_yellow,
        status_error: aurora_red,
        status_info: frost1,
        rx_rate: aurora_green,
        tx_rate: frost2,
        key_hint: aurora_orange,
        selection_bg: Color::Rgb(59, 66, 82),
        highlight_bg: Color::Rgb(76, 86, 106),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_builtin_themes_load() {
        for name in THEME_NAMES {
            let theme = by_name(name);
            assert_eq!(theme.name, *name);
        }
    }

    #[test]
    fn unknown_theme_falls_back_to_dark() {
        let theme = by_name("nonexistent");
        assert_eq!(theme.name, "dark");
    }

    #[test]
    fn dark_is_default() {
        let theme = dark();
        assert_eq!(theme.name, "dark");
        assert_eq!(theme.brand, Color::Cyan);
    }

    #[test]
    fn theme_names_count() {
        assert_eq!(THEME_NAMES.len(), 6);
    }

    #[test]
    fn by_name_case_insensitive() {
        assert_eq!(by_name("DARK").name, "dark");
        assert_eq!(by_name("Light").name, "light");
        assert_eq!(by_name("DRACULA").name, "dracula");
    }
}
