//! Renders the Diagnose tab from the demo fixture and writes a shareable
//! bundle: an ANSI dump for the terminal, an HTML page that preserves the
//! real colours, and the `report.md` / `report.json` the `e` key exports.
//!
//! This is not a mockup. It runs the actual detection engine over 440 seconds
//! of observations and draws the result with the same `render_body` the TUI
//! calls, so anything that appears here is something netwatch produced.
//!
//! ```text
//! cargo run --example diagnose_demo -- [output-dir]
//! ```

use netwatch::diagnose::issue::Capability;
use netwatch::diagnose::{fixture, report::Report};
use netwatch::ui::diagnose::{render_body, View};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;

const WIDTH: u16 = 150;
const HEIGHT: u16 = 42;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "netwatch-diagnose-demo".to_string());
    let out = std::path::Path::new(&out_dir);
    std::fs::create_dir_all(out)?;

    // The engine run. Everything below is derived from this.
    let (engine, baselines) = fixture::run();
    let report = fixture::report();

    println!("netwatch diagnose demo");
    println!("  window   {} → {}", fixture::WINDOW_START, fixture::NOW);
    println!("  verdict  {}", engine.verdict(&baselines).line());
    println!(
        "  issues   {} open of {} tracked",
        engine.open_count(),
        engine.issues().len()
    );
    for issue in engine.primary() {
        println!(
            "    [{}] {} — {}",
            issue.severity.label(),
            issue.id,
            issue.summary_line()
        );
        if let Some(c) = issue.top_cause() {
            println!(
                "           cause: {} ({}, {})",
                c.label,
                c.confidence().label(),
                c.checks_label()
            );
        }
        for cid in &issue.consequences {
            if let Some(c) = engine.get(cid) {
                println!("           explains: {} · {}", c.title, c.subject.label());
            }
        }
    }

    // Two screens: the default view, and the same screen with the report
    // preview open, so the demo shows the export matching what is above it.
    let theme = netwatch::theme::by_name("dracula");
    let mut frames = Vec::new();
    for (name, show_report, selected) in [
        ("diagnose", false, 0usize),
        ("diagnose-report", true, 0),
        ("diagnose-path", false, 2),
    ] {
        let view = View {
            engine: &engine,
            baselines: &baselines,
            theme: &theme,
            selected,
            show_report,
            capability: Capability::Root,
            ai: None,
            endpoint: "local".to_string(),
            third_party_probes: true,
            status: None,
            status_is_recovery: false,
            // These stills are for documentation, not a live claim: the
            // caption carries the provenance.
            demo_banner: None,
            running_tests: vec![],
            // The stills render from a recorded engine, which carries no
            // live probe history to chart.
            history: None,
        };
        let mut terminal = Terminal::new(TestBackend::new(WIDTH, HEIGHT))?;
        terminal.draw(|f| render_body(f, &view, f.area()))?;
        let buffer = terminal.backend().buffer().clone();

        std::fs::write(out.join(format!("{name}.txt")), buffer_to_text(&buffer))?;
        std::fs::write(out.join(format!("{name}.ans")), buffer_to_ansi(&buffer))?;
        frames.push((name.to_string(), buffer_to_html(&buffer)));
    }

    std::fs::write(out.join("report.md"), report.to_markdown())?;
    std::fs::write(out.join("report.json"), report.to_json()?)?;
    std::fs::write(out.join("index.html"), page(&frames, &report))?;

    println!();
    println!("wrote {}/", out.display());
    for name in ["index.html", "report.md", "report.json"] {
        println!("  {name}");
    }
    for (name, _) in &frames {
        println!("  {name}.txt, {name}.ans");
    }
    Ok(())
}

// ── buffer export ───────────────────────────────────────────────────

fn buffer_to_text(buf: &Buffer) -> String {
    (0..buf.area.height)
        .map(|y| {
            (0..buf.area.width)
                .map(|x| buf[(x, y)].symbol())
                .collect::<String>()
                .trim_end()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn rgb(c: Color) -> Option<(u8, u8, u8)> {
    Some(match c {
        Color::Rgb(r, g, b) => (r, g, b),
        Color::Black => (0x1a, 0x1b, 0x26),
        Color::Red => (0xf7, 0x76, 0x8e),
        Color::Green => (0x9e, 0xce, 0x6a),
        Color::Yellow => (0xe0, 0xaf, 0x68),
        Color::Blue => (0x7a, 0xa2, 0xf7),
        Color::Magenta => (0xbb, 0x9a, 0xf7),
        Color::Cyan => (0x7d, 0xcf, 0xff),
        Color::Gray => (0xa9, 0xb1, 0xd6),
        Color::DarkGray => (0x56, 0x5f, 0x89),
        Color::LightRed => (0xff, 0x9e, 0x9e),
        Color::LightGreen => (0xb9, 0xf2, 0x7c),
        Color::LightYellow => (0xff, 0xd7, 0x8c),
        Color::LightBlue => (0x9a, 0xbd, 0xff),
        Color::LightMagenta => (0xd6, 0xba, 0xff),
        Color::LightCyan => (0xa4, 0xe4, 0xff),
        Color::White => (0xc0, 0xca, 0xf5),
        Color::Indexed(_) | Color::Reset => return None,
    })
}

fn buffer_to_ansi(buf: &Buffer) -> String {
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            let cell = &buf[(x, y)];
            let mut codes = Vec::new();
            if let Some((r, g, b)) = rgb(cell.fg) {
                codes.push(format!("38;2;{r};{g};{b}"));
            }
            if let Some((r, g, b)) = rgb(cell.bg) {
                codes.push(format!("48;2;{r};{g};{b}"));
            }
            if cell.modifier.contains(Modifier::BOLD) {
                codes.push("1".into());
            }
            if codes.is_empty() {
                out.push_str(cell.symbol());
            } else {
                out.push_str(&format!(
                    "\x1b[{}m{}\x1b[0m",
                    codes.join(";"),
                    cell.symbol()
                ));
            }
        }
        out.push('\n');
    }
    out
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Walk the buffer into HTML, coalescing runs that share a style so the page
/// stays small. Colours come from the cells themselves — this is a picture of
/// what the terminal drew, not a re-creation of it.
fn buffer_to_html(buf: &Buffer) -> String {
    let mut out = String::new();
    for y in 0..buf.area.height {
        let mut run = String::new();
        let mut run_style: Option<(Color, Color, bool)> = None;

        let flush = |out: &mut String, run: &mut String, style: &Option<(Color, Color, bool)>| {
            if run.is_empty() {
                return;
            }
            match style {
                Some((fg, bg, bold)) => {
                    let mut css = String::new();
                    if let Some((r, g, b)) = rgb(*fg) {
                        css.push_str(&format!("color:#{r:02x}{g:02x}{b:02x};"));
                    }
                    if let Some((r, g, b)) = rgb(*bg) {
                        css.push_str(&format!("background:#{r:02x}{g:02x}{b:02x};"));
                    }
                    if *bold {
                        css.push_str("font-weight:700;");
                    }
                    if css.is_empty() {
                        out.push_str(&escape(run));
                    } else {
                        out.push_str(&format!("<span style=\"{css}\">{}</span>", escape(run)));
                    }
                }
                None => out.push_str(&escape(run)),
            }
            run.clear();
        };

        for x in 0..buf.area.width {
            let cell = &buf[(x, y)];
            let style = (cell.fg, cell.bg, cell.modifier.contains(Modifier::BOLD));
            if run_style != Some(style) {
                flush(&mut out, &mut run, &run_style);
                run_style = Some(style);
            }
            run.push_str(cell.symbol());
        }
        flush(&mut out, &mut run, &run_style);
        out.push('\n');
    }
    out
}

fn page(frames: &[(String, String)], report: &Report) -> String {
    let mut screens = String::new();
    for (name, html) in frames {
        let caption = match name.as_str() {
            "diagnose" => "The tab as it opens: three findings, the top one expanded.",
            "diagnose-report" => {
                "`o` opens the report preview — the same numbers, ready to export."
            }
            _ => "The path change, with the latency it cost filed underneath it.",
        };
        screens.push_str(&format!(
            "<figure><pre class=\"term\">{html}</pre><figcaption>{}</figcaption></figure>\n",
            escape(caption)
        ));
    }

    format!(
        r#"<title>netwatch Diagnose</title>
<style>
  :root {{
    --bg:#faf9f7; --fg:#1c1b19; --muted:#6b6862; --rule:#e3e0da;
    --term-bg:#282a36; --card:#ffffff;
  }}
  @media (prefers-color-scheme: dark) {{
    :root:not([data-theme="light"]) {{
      --bg:#16151a; --fg:#e8e6e1; --muted:#9a968e; --rule:#2e2c33; --card:#1e1d23;
    }}
  }}
  :root[data-theme="dark"] {{
    --bg:#16151a; --fg:#e8e6e1; --muted:#9a968e; --rule:#2e2c33; --card:#1e1d23;
  }}
  body {{ background:var(--bg); color:var(--fg); margin:0;
         font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }}
  main {{ max-width:1180px; margin:0 auto; padding:48px 24px 96px; }}
  h1 {{ font-size:28px; margin:0 0 6px; letter-spacing:-0.02em; }}
  .sub {{ color:var(--muted); margin:0 0 40px; font-size:16px; }}
  h2 {{ font-size:19px; margin:44px 0 12px; letter-spacing:-0.01em; }}
  p {{ margin:0 0 14px; max-width:70ch; }}
  figure {{ margin:0 0 28px; }}
  figcaption {{ color:var(--muted); font-size:13.5px; margin-top:8px; }}
  pre.term {{ background:var(--term-bg); color:#f8f8f2; padding:16px 18px;
    border-radius:8px; overflow-x:auto; font:12px/1.32 ui-monospace,
    "SF Mono",Menlo,Consolas,monospace; white-space:pre; }}
  pre.md {{ background:var(--card); border:1px solid var(--rule); border-radius:8px;
    padding:16px 18px; overflow-x:auto; font:12.5px/1.55 ui-monospace,Menlo,monospace;
    white-space:pre-wrap; max-height:520px; overflow-y:auto; }}
  .note {{ border-left:3px solid var(--rule); padding:2px 0 2px 16px; color:var(--muted); }}
</style>
<main>
  <h1>netwatch — Diagnose</h1>
  <p class="sub">Issue → probable cause → remediation → report. Every screen below was
  rendered by the shipping code from a 440-second engine run; nothing is drawn by hand.</p>

  <h2>The screen</h2>
{screens}
  <h2>The report it exports</h2>
  <p>Generated from the same <code>Vec&lt;Issue&gt;</code> the screen renders, so the two
  cannot disagree — a test asserts that every number in the report traces back to an
  evidence field on some issue.</p>
  <pre class="md">{report_md}</pre>

  <h2 class="note">Verdict</h2>
  <p class="note">{verdict}</p>
</main>
"#,
        screens = screens,
        report_md = escape(&report.to_markdown()),
        verdict = escape(&report.summary_line()),
    )
}
