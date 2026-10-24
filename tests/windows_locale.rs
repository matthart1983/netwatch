//! The 0.38 exit criterion "Windows has no English-only string matches in
//! collectors", kept by a test that fails when one comes back.
//!
//! Windows translates what its networking tools print. A parser that looks
//! for "Average =" in `ping.exe` output, "IPv4 Address" in ipconfig's or
//! `LISTENING` in netstat's finds nothing on a German or Russian install, and
//! that left the Health widget, the interface list and the listen filter
//! empty there until 0.38 moved each collector onto an API that answers in
//! numbers. The text parsing that is left runs only after one of those calls
//! has failed, and this test keeps it that way.
//!
//! It reads netwatch's source as a Windows build sees it: the modules that
//! `src/lib.rs` and `src/main.rs` reach, less everything a `#[cfg]` leaves out
//! of a Windows build (`#[cfg(unix)]`, `#[cfg(target_os = "linux")]`,
//! `#[cfg(test)]` and the rest). There it looks only at string literals that
//! are compared with text: the argument of a `str` search such as `contains`
//! or `starts_with`, a side of `==` or `!=`, a `match` pattern, and the value
//! of a `const` or `static` or an entry in its array. A literal fails the
//! test when it holds a word or phrase from [`ENGLISH_OUTPUT`], the English
//! the Windows tools print. Log messages, UI text and errors are not compared
//! with anything, so the list can hold short words such as "Bytes" without
//! catching a column heading.
//!
//! A fallback that has to read English stays allowed by name. It is listed in
//! [`FALLBACKS`] with the call it stands in for, and carries a
//! `// locale: fallback-only` comment directly above it, among its doc
//! comments and attributes. A listing without the comment, a comment without
//! a listing, and a listing that no longer matches anything all fail, so an
//! exemption takes two edits and goes when it is no longer needed.
//!
//! This reads tokens, not a syntax tree, which is enough for this crate's
//! source and needs no parser dependency. A `#[cfg]` it cannot decide, such
//! as a feature, counts as compiled, so anything it misjudges is read rather
//! than skipped. A literal whose comparison it cannot see, such as an array
//! searched through a closure, goes unchecked.

use std::path::{Path, PathBuf};

/// The comment that marks an exempted fallback.
const MARKER: &str = "locale: fallback-only";

/// A fallback allowed to read English output, and what it stands in for.
struct Fallback {
    file: &'static str,
    item: &'static str,
    instead_of: &'static str,
}

/// Every exemption. Each runs only after the API call it names has failed,
/// and an English install is the only one it helps.
const FALLBACKS: &[Fallback] = &[
    Fallback {
        file: "src/collectors/config.rs",
        item: "parse_ipconfig_dns",
        instead_of: "GetAdaptersAddresses, for DNS servers",
    },
    Fallback {
        file: "src/platform/socket_table.rs",
        item: "NETSTAT_STATES",
        instead_of: "GetExtendedTcpTable, for connection states",
    },
    Fallback {
        file: "src/platform/windows.rs",
        item: "collect_interface_info_ipconfig",
        instead_of: "GetAdaptersAddresses, for the interface list",
    },
    Fallback {
        file: "src/platform/windows.rs",
        item: "collect_mtu_map",
        instead_of: "GetAdaptersAddresses, for MTUs in the ipconfig fallback",
    },
];

/// What the Windows networking tools print in English, by tool. A phrase
/// that begins or ends with a letter matches only as whole words there, so
/// "Errors" does not match "IfErrors". Case matters: these tools capitalise
/// their labels, and Linux's `ip` and `ss` do not. Labels that netwatch's own
/// views use as column names and sort by, such as netstat's "Local Address"
/// and the old ipconfig's "IP Address", are left out.
const ENGLISH_OUTPUT: &[&str] = &[
    // ping.exe
    "Pinging",
    "Reply from",
    "Request timed out",
    "Destination host unreachable",
    "General failure",
    "Ping statistics",
    "Packets: Sent",
    "Sent =",
    "Received =",
    "Lost =",
    "% loss",
    "Approximate round trip times",
    "Minimum =",
    "Maximum =",
    "Average =",
    // tracert
    "Tracing route",
    "over a maximum of",
    "Trace complete",
    "Transmit error",
    // ipconfig
    "Windows IP Configuration",
    "Ethernet adapter",
    "Wireless LAN",
    "Tunnel adapter",
    "PPP adapter",
    "Media State",
    "Media disconnected",
    "Physical Address",
    "IPv4 Address",
    "IPv6 Address",
    "Link-local IPv6",
    "Subnet Mask",
    "Default Gateway",
    "DHCP Enabled",
    "DHCP Server",
    "DNS Server",
    "DNS Servers",
    "DNS Suffix",
    "NetBIOS over Tcpip",
    "Lease Obtained",
    "Lease Expires",
    "(Preferred)",
    // netstat -ano, -e and -r, and route print
    "Active Connections",
    "LISTENING",
    "DELETE_TCB",
    "Interface Statistics",
    "Bytes",
    "Unicast",
    "Non-unicast",
    "Discards",
    "Errors",
    "Unknown protocols",
    "Route Table",
    "Active Routes",
    "Persistent Routes",
    "Network Destination",
    "On-link",
    // netsh
    "MTU",
    "MediaSenseState",
    "Bytes In",
    "Bytes Out",
    "Radio type",
    "Receive rate",
    "Transmit rate",
    // arp, tasklist, nslookup and getmac
    "Internet Address",
    "Image Name",
    "Session Name",
    "Mem Usage",
    "Non-authoritative answer",
    "Default Server",
    "Transport Name",
];

// ── reading source ─────────────────────────────────────────────────────────

#[derive(PartialEq)]
enum Tok {
    /// An identifier, keyword or number.
    Word(String),
    /// A string literal's text as written, escapes and all.
    Str(String),
    Punct(&'static str),
    /// A `// locale: fallback-only` comment.
    Marker,
}

struct Token {
    tok: Tok,
    line: usize,
}

/// The two-character operators the scan looks at. `||` is here so that a
/// closure's `||` is never taken for a pattern's `|`.
const OPERATORS: [&str; 7] = ["=>", "==", "!=", "||", "&&", "::", "->"];
const PUNCTUATION: &str = "#![](){}.,;:=|&<>+-*/%^@?$~\\`";

/// Rust source as tokens, without comments other than the marker.
fn lex(src: &str) -> Vec<Token> {
    let s: Vec<char> = src.chars().collect();
    let at = |i: usize| s.get(i).copied().unwrap_or('\0');
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = Vec::new();
    let (mut i, mut line) = (0, 1);
    while i < s.len() {
        let c = s[i];
        let start = i;
        let tok = if c.is_whitespace() {
            i += 1;
            None
        } else if c == '/' && at(i + 1) == '/' {
            i = s[i..]
                .iter()
                .position(|&c| c == '\n')
                .map_or(s.len(), |n| i + n);
            let text: String = s[start + 2..i].iter().collect();
            // `///` and `//!` are doc comments, never the marker.
            (!text.starts_with(['/', '!']) && text.trim().starts_with(MARKER))
                .then_some(Tok::Marker)
        } else if c == '/' && at(i + 1) == '*' {
            let mut depth = 0;
            loop {
                if at(i) == '/' && at(i + 1) == '*' {
                    depth += 1;
                    i += 2;
                } else if at(i) == '*' && at(i + 1) == '/' {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else if i >= s.len() {
                    break;
                } else {
                    i += 1;
                }
            }
            None
        } else if c == '"' {
            let (text, end) = quoted(&s, i + 1);
            i = end;
            Some(Tok::Str(text))
        } else if c == '\'' {
            if at(i + 1) == '\\' {
                // An escaped char: '\n', '\'', '\u{FFFD}'.
                i += 3;
                while at(i) != '\'' {
                    i += 1;
                }
                i += 1;
            } else if at(i + 2) == '\'' {
                i += 3;
            } else {
                // A lifetime or a loop label.
                i += 1;
                while ident(at(i)) {
                    i += 1;
                }
            }
            None
        } else if ident(c) {
            while ident(at(i)) {
                i += 1;
            }
            let word: String = s[start..i].iter().collect();
            let hashes = s[i..].iter().take_while(|&&c| c == '#').count();
            if matches!(word.as_str(), "r" | "br" | "cr") && at(i + hashes) == '"' {
                let body = i + hashes + 1;
                let close: Vec<char> = std::iter::once('"')
                    .chain(std::iter::repeat_n('#', hashes))
                    .collect();
                let end = (body..s.len())
                    .find(|&k| s[k..].starts_with(&close))
                    .unwrap_or_else(|| panic!("unterminated raw string on line {line}"));
                i = end + close.len();
                Some(Tok::Str(s[body..end].iter().collect()))
            } else if matches!(word.as_str(), "b" | "c") && at(i) == '"' {
                let (text, end) = quoted(&s, i + 1);
                i = end;
                Some(Tok::Str(text))
            } else {
                Some(Tok::Word(word))
            }
        } else if let Some(op) = OPERATORS.iter().find(|op| op.chars().eq([c, at(i + 1)])) {
            i += 2;
            Some(Tok::Punct(op))
        } else {
            let at_punct = PUNCTUATION
                .find(c)
                .unwrap_or_else(|| panic!("unexpected {c:?} on line {line}"));
            i += 1;
            Some(Tok::Punct(&PUNCTUATION[at_punct..at_punct + 1]))
        };
        if let Some(tok) = tok {
            out.push(Token { tok, line });
        }
        line += s[start..i].iter().filter(|&&c| c == '\n').count();
    }
    out
}

/// The text of a `"` string from `from`, and the index after its closing quote.
fn quoted(s: &[char], from: usize) -> (String, usize) {
    let mut k = from;
    while k < s.len() && s[k] != '"' {
        k += if s[k] == '\\' { 2 } else { 1 };
    }
    (s[from..k.min(s.len())].iter().collect(), k + 1)
}

fn punct(t: &[Token], i: usize) -> Option<&'static str> {
    match t.get(i)?.tok {
        Tok::Punct(p) => Some(p),
        _ => None,
    }
}

fn word(t: &[Token], i: usize) -> Option<&str> {
    match &t.get(i)?.tok {
        Tok::Word(w) => Some(w),
        _ => None,
    }
}

/// Each bracket's partner, and the innermost bracket open around each token.
fn brackets(t: &[Token]) -> (Vec<Option<usize>>, Vec<Option<usize>>) {
    let mut partner = vec![None; t.len()];
    let mut enclosing = vec![None; t.len()];
    let mut open = Vec::new();
    for i in 0..t.len() {
        match punct(t, i) {
            Some("(" | "[" | "{") => {
                enclosing[i] = open.last().copied();
                open.push(i);
            }
            Some(")" | "]" | "}") => {
                let o = open
                    .pop()
                    .unwrap_or_else(|| panic!("unbalanced bracket on line {}", t[i].line));
                partner[o] = Some(i);
                partner[i] = Some(o);
                enclosing[i] = open.last().copied();
            }
            _ => enclosing[i] = open.last().copied(),
        }
    }
    assert!(open.is_empty(), "unclosed bracket");
    (partner, enclosing)
}

// ── what a Windows build compiles ──────────────────────────────────────────

/// A `cfg` predicate's value for a Windows build outside tests: `None` for a
/// feature, an architecture or anything else a build can turn either way.
fn cfg_value(t: &[Token], i: &mut usize) -> Option<bool> {
    let name = word(t, *i).expect("a cfg predicate").to_string();
    *i += 1;
    if punct(t, *i) == Some("(") {
        *i += 1;
        let mut args = Vec::new();
        while punct(t, *i) != Some(")") {
            args.push(cfg_value(t, i));
            if punct(t, *i) == Some(",") {
                *i += 1;
            }
        }
        *i += 1;
        return match name.as_str() {
            "not" => args[0].map(|v| !v),
            "any" if args.contains(&Some(true)) => Some(true),
            "any" => args.iter().all(|a| *a == Some(false)).then_some(false),
            "all" if args.contains(&Some(false)) => Some(false),
            "all" => args.iter().all(|a| *a == Some(true)).then_some(true),
            _ => None,
        };
    }
    if punct(t, *i) == Some("=") {
        let Tok::Str(value) = &t[*i + 1].tok else {
            panic!("cfg {name} = without a string on line {}", t[*i].line)
        };
        *i += 2;
        return match name.as_str() {
            "target_os" | "target_family" => Some(value == "windows"),
            _ => None,
        };
    }
    match name.as_str() {
        "windows" => Some(true),
        "unix" | "test" => Some(false),
        _ => None,
    }
}

/// The attribute whose `[` is at `open` leaves its item out of a Windows build.
fn cfg_off(t: &[Token], open: usize) -> bool {
    let mut i = open + 3;
    word(t, open + 1) == Some("cfg")
        && punct(t, open + 2) == Some("(")
        && cfg_value(t, &mut i) == Some(false)
}

/// Where the item, statement, field or match arm that starts at `start` ends.
///
/// `let`, `use`, `const`, `static` and `type` run to their semicolon, and a
/// `fn`, `struct`, `impl` or other item to its semicolon or the end of its
/// first block. Anything else also ends at a comma, as a field or match arm
/// does, and runs on past a block that `else` follows, as an `if` does.
fn construct_end(t: &[Token], start: usize, partner: &[Option<usize>]) -> usize {
    let mut k = start;
    loop {
        if punct(t, k) == Some("#") && punct(t, k + 1) == Some("[") {
            k = partner[k + 1].unwrap() + 1;
            continue;
        }
        match word(t, k) {
            Some("pub") if punct(t, k + 1) == Some("(") => k = partner[k + 1].unwrap() + 1,
            Some("pub" | "unsafe" | "async" | "default") => k += 1,
            Some("extern") => k += 1 + usize::from(matches!(t[k + 1].tok, Tok::Str(_))),
            Some("const") if matches!(word(t, k + 1), Some("fn" | "unsafe" | "async")) => k += 1,
            _ => break,
        }
    }
    let to_semicolon = matches!(
        word(t, k),
        Some("let" | "use" | "const" | "static" | "type")
    );
    // A generic's comma, as in `-> HashMap<String, u32>`, is no end.
    let item = matches!(
        word(t, k),
        Some("fn" | "struct" | "enum" | "union" | "impl" | "trait" | "mod" | "macro_rules")
    );
    let mut i = start;
    while i < t.len() {
        match punct(t, i) {
            Some(open @ ("(" | "[" | "{")) => {
                let close = partner[i].unwrap();
                if open == "{" && !to_semicolon && (item || word(t, close + 1) != Some("else")) {
                    return close + 1;
                }
                i = close + 1;
                continue;
            }
            // The block around the construct closes first.
            Some(")" | "]" | "}") => return i,
            Some(";") => return i + 1,
            Some(",") if !to_semicolon && !item => return i,
            _ => {}
        }
        i += 1;
    }
    t.len()
}

/// A `fn`, `const` or `static` a finding can be inside.
struct Item {
    name: String,
    start: usize,
    end: usize,
    /// For a `const` or `static`, the `=` before its value.
    value: Option<usize>,
    /// The marker comment above it.
    marker: Option<usize>,
}

/// The marker among the doc comments and attributes above the item keyword
/// at `keyword`, skipping its visibility and qualifiers.
fn marker_above(t: &[Token], keyword: usize, partner: &[Option<usize>]) -> Option<usize> {
    let mut j = keyword;
    while j > 0 {
        j -= 1;
        match &t[j].tok {
            Tok::Marker => return Some(j),
            Tok::Punct("]") => {
                j = partner[j].unwrap();
                if j == 0 || punct(t, j - 1) != Some("#") {
                    return None;
                }
                j -= 1;
            }
            Tok::Punct(")") if j > 0 => {
                let open = partner[j].unwrap();
                if open == 0 || word(t, open - 1) != Some("pub") {
                    return None;
                }
                j = open;
            }
            Tok::Word(w)
                if matches!(w.as_str(), "pub" | "unsafe" | "async" | "extern" | "const") => {}
            Tok::Str(_) if word(t, j.saturating_sub(1)) == Some("extern") => {}
            _ => return None,
        }
    }
    None
}

/// `str` methods whose argument is text to look for.
const SEARCHES: &[&str] = &[
    "contains",
    "starts_with",
    "ends_with",
    "strip_prefix",
    "strip_suffix",
    "find",
    "rfind",
    "split",
    "rsplit",
    "splitn",
    "rsplitn",
    "split_once",
    "rsplit_once",
    "split_terminator",
    "matches",
    "match_indices",
    "trim_matches",
    "trim_start_matches",
    "trim_end_matches",
    "replace",
    "replacen",
    "eq",
    "ne",
    "eq_ignore_ascii_case",
];

struct Finding {
    file: String,
    line: usize,
    literal: String,
    phrase: &'static str,
    /// The innermost `fn`, `const` or `static` around it.
    item: Option<String>,
    marked: bool,
}

/// One file as a Windows build compiles it.
#[derive(Default)]
struct Scan {
    findings: Vec<Finding>,
    /// Marked items, by name.
    marked: Vec<String>,
    /// Lines of markers that sit above no `fn`, `const` or `static`.
    stray_markers: Vec<usize>,
    /// The `mod name;` declarations a Windows build compiles.
    modules: Vec<String>,
    /// False when `#![cfg]` leaves the whole file out.
    compiled: bool,
}

fn scan(file: &str, src: &str) -> Scan {
    let t = lex(src);
    let (partner, enclosing) = brackets(&t);

    // Tokens a Windows build compiles, and tokens inside attributes.
    let mut compiled = vec![true; t.len()];
    let mut attribute = vec![false; t.len()];
    let mut i = 0;
    while i < t.len() {
        let inner = punct(&t, i + 1) == Some("!");
        let open = i + 1 + usize::from(inner);
        if punct(&t, i) != Some("#") || punct(&t, open) != Some("[") {
            i += 1;
            continue;
        }
        let close = partner[open].unwrap();
        attribute[i..=close].fill(true);
        if !cfg_off(&t, open) {
            i = close + 1;
        } else if inner {
            return Scan::default();
        } else {
            let end = construct_end(&t, close + 1, &partner);
            compiled[i..end].fill(false);
            i = end;
        }
    }

    let mut items = Vec::new();
    for k in (0..t.len()).filter(|&k| compiled[k]) {
        let Some(keyword @ ("fn" | "const" | "static")) = word(&t, k) else {
            continue;
        };
        // `*const T`, `<const N: usize>`, `const fn` and `const { }` are not
        // items of their own.
        if matches!(punct(&t, k.wrapping_sub(1)), Some("*" | "<" | ","))
            || (keyword == "const" && word(&t, k + 1).is_some_and(|w| w == "fn" || w == "unsafe"))
        {
            continue;
        }
        let at_name = k + 1 + usize::from(keyword == "static" && word(&t, k + 1) == Some("mut"));
        let Some(name) = word(&t, at_name) else {
            continue;
        };
        let end = construct_end(&t, k, &partner);
        let value = (keyword != "fn")
            .then(|| (at_name..end).find(|&j| punct(&t, j) == Some("=")))
            .flatten();
        items.push(Item {
            name: name.to_string(),
            start: k,
            end,
            value,
            marker: marker_above(&t, k, &partner),
        });
    }

    let mut findings = Vec::new();
    for i in 0..t.len() {
        let Tok::Str(text) = &t[i].tok else {
            continue;
        };
        if !compiled[i] || attribute[i] {
            continue;
        }
        let item = items
            .iter()
            .filter(|it| it.start < i && i < it.end)
            .min_by_key(|it| it.end - it.start);
        // A `const` or `static` that is the literal, or an array of them. A
        // literal in a struct or tuple there, such as a rule's description,
        // is not a table entry.
        let tabled = item.and_then(|it| it.value).is_some_and(|v| {
            v < i
                && match enclosing[i] {
                    Some(o) if o > v => punct(&t, o) == Some("["),
                    _ => true,
                }
        });
        let compared = matches!(punct(&t, i.wrapping_sub(1)), Some("==" | "!="))
            || matches!(punct(&t, i + 1), Some("==" | "!=" | "=>" | "|"))
            || word(&t, i + 1) == Some("if")
            || searched(&t, i, &enclosing)
            || tabled;
        if !compared {
            continue;
        }
        if let Some(phrase) = ENGLISH_OUTPUT.iter().find(|p| holds(text, p)) {
            findings.push(Finding {
                file: file.to_string(),
                line: t[i].line,
                literal: text.clone(),
                phrase,
                item: item.map(|it| it.name.clone()),
                marked: item.is_some_and(|it| it.marker.is_some()),
            });
        }
    }

    let used: Vec<usize> = items.iter().filter_map(|it| it.marker).collect();
    let stray_markers = (0..t.len())
        .filter(|&i| t[i].tok == Tok::Marker && !used.contains(&i))
        .map(|i| t[i].line)
        .collect();

    let modules = (0..t.len())
        .filter(|&i| compiled[i] && word(&t, i) == Some("mod") && punct(&t, i + 2) == Some(";"))
        .map(|i| {
            assert!(
                enclosing[i].is_none(),
                "{file}:{}: a file module inside an inline one is not followed",
                t[i].line
            );
            word(&t, i + 1).expect("a module name").to_string()
        })
        .collect();

    Scan {
        findings,
        marked: items
            .iter()
            .filter(|it| it.marker.is_some())
            .map(|it| it.name.clone())
            .collect(),
        stray_markers,
        modules,
        compiled: true,
    }
}

/// The literal at `i` is an argument of a `str` search, directly or in an
/// array of them.
fn searched(t: &[Token], i: usize, enclosing: &[Option<usize>]) -> bool {
    let mut open = enclosing[i];
    if open.is_some_and(|o| punct(t, o) == Some("[")) {
        open = enclosing[open.unwrap()];
    }
    open.is_some_and(|o| {
        o >= 2
            && punct(t, o) == Some("(")
            && word(t, o - 1).is_some_and(|m| SEARCHES.contains(&m))
            && punct(t, o - 2) == Some(".")
    })
}

/// `phrase` appears in `text`, as whole words where it begins or ends with one.
fn holds(text: &str, phrase: &str) -> bool {
    let word_char = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    let starts_word = word_char(phrase.chars().next());
    let ends_word = word_char(phrase.chars().next_back());
    text.match_indices(phrase).any(|(at, _)| {
        !(starts_word && word_char(text[..at].chars().next_back()))
            && !(ends_word && word_char(text[at + phrase.len()..].chars().next()))
    })
}

// ── the tree ───────────────────────────────────────────────────────────────

/// Every file a Windows build of the library and binary compiles, by its
/// path in the repository with `/` separators, as it compiles it.
fn windows_tree() -> Vec<(String, Scan)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut queue: Vec<PathBuf> = vec![root.join("src/lib.rs"), root.join("src/main.rs")];
    let mut tree = Vec::new();
    while let Some(path) = queue.pop() {
        let rel = path
            .strip_prefix(root)
            .unwrap()
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"));
        let scan = scan(&rel, &src);
        if !scan.compiled {
            continue;
        }
        // `a.rs` keeps its modules in `a/`; `lib.rs`, `main.rs` and `mod.rs`
        // keep them beside themselves.
        let stem = path.file_stem().unwrap().to_string_lossy();
        let dir = match stem.as_ref() {
            "lib" | "main" | "mod" => path.parent().unwrap().to_path_buf(),
            _ => path.with_extension(""),
        };
        for module in &scan.modules {
            let file = [
                dir.join(format!("{module}.rs")),
                dir.join(module).join("mod.rs"),
            ]
            .into_iter()
            .find(|p| p.exists())
            .unwrap_or_else(|| panic!("{rel}: no file for `mod {module};`"));
            queue.push(file);
        }
        tree.push((rel, scan));
    }
    tree
}

fn listed(file: &str, item: &str) -> Option<&'static Fallback> {
    FALLBACKS.iter().find(|f| f.file == file && f.item == item)
}

// ── tests ──────────────────────────────────────────────────────────────────

#[test]
fn windows_code_compares_no_english_command_output() {
    let found: Vec<String> = windows_tree()
        .iter()
        .flat_map(|(_, scan)| &scan.findings)
        .filter(|f| {
            !(f.marked
                && f.item
                    .as_deref()
                    .is_some_and(|i| listed(&f.file, i).is_some()))
        })
        .map(|f| {
            format!(
                "  {}:{} in {}: {:?} holds {:?}",
                f.file,
                f.line,
                f.item.as_deref().unwrap_or("(no fn, const or static)"),
                f.literal,
                f.phrase
            )
        })
        .collect();
    assert!(
        found.is_empty(),
        "code a Windows build compiles compares text with English that a Windows \
         tool prints:\n{}\n\nOn a translated install the tool prints something else, and \
         the match fails. Read the value through an API (IP Helper, the ICMP API), or \
         match only what every language prints: digits, addresses, `*`. To exempt a \
         fallback that runs only after its API call has failed, list it in FALLBACKS in \
         tests/windows_locale.rs and put `// {MARKER}` directly above it.",
        found.join("\n")
    );
}

#[test]
fn every_fallback_is_listed_marked_and_still_needed() {
    let tree = windows_tree();
    let mut problems = Vec::new();
    for (file, scan) in &tree {
        for line in &scan.stray_markers {
            problems.push(format!(
                "{file}:{line}: `// {MARKER}` is not directly above a fn, const or static"
            ));
        }
        for item in &scan.marked {
            if listed(file, item).is_none() {
                problems.push(format!(
                    "{file}: {item} is marked `// {MARKER}` but not listed in FALLBACKS"
                ));
            }
        }
    }
    for f in FALLBACKS {
        let Some((_, scan)) = tree.iter().find(|(file, _)| file == f.file) else {
            problems.push(format!("{}: listed in FALLBACKS, but not compiled", f.file));
            continue;
        };
        if !scan.marked.iter().any(|m| m == f.item) {
            problems.push(format!(
                "{}: {} (instead of {}) is listed but has no `// {MARKER}` above it",
                f.file, f.item, f.instead_of
            ));
        }
        if !scan
            .findings
            .iter()
            .any(|x| x.item.as_deref() == Some(f.item))
        {
            problems.push(format!(
                "{}: {} no longer compares English; drop it from FALLBACKS and its marker",
                f.file, f.item
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// A pass means something only if the scan reads the Windows-only modules and
/// leaves out the ones a Windows build never compiles.
#[test]
fn the_scan_reads_what_a_windows_build_compiles() {
    let tree = windows_tree();
    let scanned = |f: &str| tree.iter().any(|(file, _)| file == f);
    for f in [
        "src/lib.rs",
        "src/main.rs",
        "src/collectors/config.rs",
        "src/collectors/connections.rs",
        "src/collectors/health.rs",
        "src/collectors/traceroute.rs",
        "src/platform/socket_table.rs",
        "src/platform/windows.rs",
        "src/platform/windows/iphlpapi.rs",
        "src/platform/windows/tcp_table.rs",
    ] {
        assert!(scanned(f), "{f} was not scanned");
    }
    for f in [
        "src/platform/linux.rs",
        "src/platform/macos.rs",
        "src/platform/freebsd.rs",
        "src/sandbox/linux.rs",
        "src/diagnose/remediation/store/unix.rs",
    ] {
        assert!(
            !scanned(f),
            "{f} was scanned, but Windows does not compile it"
        );
    }
}

/// The scanner on a made-up file: which literals it reports and in which
/// item, which markers count, and which modules it follows.
#[test]
fn only_compared_literals_in_windows_code_are_findings() {
    let src = r##"
#[cfg(windows)]
fn a(line: &str) -> bool { line.trim().starts_with("IPv4 Address") }
#[cfg(target_os = "linux")]
fn b(line: &str) -> bool { line.contains("IPv4 Address") }
#[cfg(any(target_os = "windows", test))]
fn c(state: &str) -> u8 {
    match state { "LISTENING" | "X" => 1, _ if state == "Errors" => 2, _ => 0 }
}
fn d() { tracing::warn!("IPv4 Address missing"); let s = "Bytes"; }
#[cfg(test)]
mod tests { fn e(l: &str) -> bool { l.contains("Sent =") } }
/// Docs.
// locale: fallback-only
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn f(text: &str) -> Vec<&str> {
    text.split(['\n', '\'']).filter(|l| l.contains(r#"Average ="#)).collect()
}
const STATES: [&str; 2] = ["DELETE_TCB", "ESTABLISHED"];
#[cfg(not(unix))]
fn g(x: *const u8, l: &str) -> bool { "IPv6 Address" != l || l.ends_with("IfErrors") }
fn h(l: &str) -> bool {
    #[cfg(unix)]
    let ok = l.contains("Bytes");
    #[cfg(windows)]
    let ok = l.contains("Unicast");
    ok
}
// locale: fallback-only
let stray = 1;
mod kept;
#[cfg(target_os = "macos")]
mod gone;
#[cfg(unix)]
fn m(l: &str) -> HashMap<String, u32> { l.contains("Bytes") }
const RULES: &[(&str, &str)] = &[("link.down", "ipconfig says Media disconnected")];
"##;
    let s = scan("x.rs", src);
    let found: Vec<(usize, &str, Option<&str>, bool)> = s
        .findings
        .iter()
        .map(|f| (f.line, f.phrase, f.item.as_deref(), f.marked))
        .collect();
    assert_eq!(
        found,
        [
            (3, "IPv4 Address", Some("a"), false),
            (8, "LISTENING", Some("c"), false),
            (8, "Errors", Some("c"), false),
            (17, "Average =", Some("f"), true),
            (19, "DELETE_TCB", Some("STATES"), false),
            (21, "IPv6 Address", Some("g"), false),
            (26, "Unicast", Some("h"), false),
        ]
    );
    assert_eq!(s.marked, ["f"]);
    assert_eq!(s.stray_markers, [29]);
    assert_eq!(s.modules, ["kept"]);
    assert!(!scan("y.rs", "#![cfg(unix)]\nfn a() {}").compiled);
}
