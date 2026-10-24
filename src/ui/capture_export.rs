//! The export preview `w` (packets) and `Shift+E` (incident bundle) open.
//!
//! It freezes the selection when it opens, so what it counts is what gets
//! written however much capture continues, and it says what the file will
//! hold before anything is written: packet bytes are not redacted. The write
//! runs on a worker, so a large export does not stall the screen, and Esc
//! cancels it and removes the partial file.

use crate::collectors::incident::IncidentRecorder;
use crate::collectors::packets::{
    export::{self, Format},
    CapturedPacket,
};
use crate::ui::widgets;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    prelude::*,
    widgets::{Clear, Paragraph, Wrap},
};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
};

pub enum Selection {
    Packets(Vec<CapturedPacket>),
    Incident(Box<IncidentRecorder>),
}

pub struct Dialog {
    selection: Option<Selection>,
    summary: export::ExportSummary,
    incident: bool,
    format: Format,
    annotations: bool,
    cancel: Arc<AtomicBool>,
    receiver: Option<mpsc::Receiver<Result<String, String>>>,
    base: PathBuf,
    scroll: u16,
}

/// Closing the dialog any way at all, quitting included, cancels its write.
impl Drop for Dialog {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

impl Dialog {
    pub fn new(selection: Selection, base: PathBuf) -> Self {
        let (summary, incident) = match &selection {
            Selection::Packets(p) => (export::preview(p), false),
            Selection::Incident(r) => (r.packet_preview(), true),
        };
        Self {
            selection: Some(selection),
            summary,
            incident,
            format: Format::PcapNg,
            annotations: true,
            cancel: Arc::new(AtomicBool::new(false)),
            receiver: None,
            base,
            scroll: 0,
        }
    }

    /// Handle a key. `Some` is the status line to show as the dialog closes.
    /// A cancel during a write waits for the worker to clean up, so the
    /// dialog stays open, saying so, until [`Dialog::poll`] reports it.
    pub fn key(&mut self, key: KeyEvent) -> Option<String> {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
            self.cancel.store(true, Ordering::Relaxed);
            if self.receiver.is_none() {
                return Some("Export cancelled".into());
            }
        }
        if self.receiver.is_some() {
            return self.poll();
        }
        match key.code {
            KeyCode::Char('f') if !self.incident => {
                self.format = match self.format {
                    Format::Pcap => Format::PcapNg,
                    Format::PcapNg => Format::Pcap,
                }
            }
            KeyCode::Char('a') => self.annotations = !self.annotations,
            KeyCode::Enter => self.start(),
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll = self.scroll.saturating_add(1).min(MAX_SCROLL)
            }
            KeyCode::Up | KeyCode::Char('k') => self.scroll = self.scroll.saturating_sub(1),
            _ => {}
        }
        None
    }

    fn start(&mut self) {
        let Some(selection) = self.selection.take() else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        let base = self.base.clone();
        let cancel = Arc::clone(&self.cancel);
        let (format, annotations) = (self.format, self.annotations);
        crate::sandbox::worker::spawn("capture-export", move || {
            let result = match selection {
                Selection::Packets(packets) => {
                    export_packets(&packets, &base, format, annotations, &cancel)
                }
                Selection::Incident(recorder) => recorder
                    .export_bundle_options(&base, annotations, &cancel)
                    .map(|path| format!("Incident bundle saved to {}", path.display())),
            };
            let _ = tx.send(result);
        });
    }

    /// What the file will hold with the current choices. Without comments,
    /// or in classic PCAP, which has nowhere to put them, no packet names
    /// its socket owner, as the write itself reports.
    pub fn summary(&self) -> export::ExportSummary {
        let mut summary = self.summary;
        if !self.annotations || (!self.incident && self.format == Format::Pcap) {
            summary.annotated = 0;
        }
        summary
    }

    /// The final status once the worker has finished, `None` while it runs.
    pub fn poll(&mut self) -> Option<String> {
        match self.receiver.as_ref()?.try_recv() {
            Ok(Ok(message)) => Some(message),
            // A write that finished before it saw the cancel is reported
            // as saved above, since its file exists.
            Ok(Err(_)) if self.cancel.load(Ordering::Relaxed) => Some("Export cancelled".into()),
            Ok(Err(error)) => Some(format!("Export failed: {error}")),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                Some("Export stopped: worker unavailable; see Settings".into())
            }
        }
    }

    fn body(&self, t: &crate::theme::Theme) -> Vec<Line<'static>> {
        let label = |s: &'static str| Span::styled(s, Style::default().fg(t.text_muted));
        let value = |s: String| Span::styled(s, Style::default().fg(t.text_primary).bold());
        if self.receiver.is_some() {
            let text = if self.cancel.load(Ordering::Relaxed) {
                "Cancelling the export and removing its temporary files…"
            } else {
                "Writing the frozen selection…"
            };
            return vec![Line::from(text)];
        }
        let what = if self.incident {
            "Frozen incident"
        } else {
            "Frozen packet selection"
        };
        let format = if self.incident {
            "PCAPNG, plus PCAP when one link type, plus JSON".to_string()
        } else {
            self.format.extension().to_uppercase()
        };
        let comments = if !self.incident && self.format == Format::Pcap {
            "not available in PCAP"
        } else if self.annotations {
            "on"
        } else {
            "off"
        };
        let warning = Style::default().fg(t.status_warn);
        let summary = self.summary();
        vec![
            Line::from(Span::styled(what, Style::default().fg(t.brand).bold())),
            Line::from(vec![
                value(summary.packets.to_string()),
                label(" packets to write · "),
                value(summary.annotated.to_string()),
                label(" with a socket owner · "),
                value(summary.omitted.to_string()),
                label(" omitted (no capture metadata)"),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                "Packet bytes are NOT redacted: they can hold addresses, payloads and credentials.",
                warning,
            )),
            Line::from(if self.incident {
                "The incident JSON names processes and endpoints, with packet comments on or off."
            } else {
                "Packet comments can name processes and PIDs, interfaces and TLS/QUIC server names."
            }),
            Line::from("Session keys and decrypted plaintext are never written."),
            Line::from(""),
            Line::from(vec![label("Format    "), value(format)]),
            Line::from(vec![label("Comments  "), value(comments.to_string())]),
            Line::from(vec![
                label("Folder    "),
                value(self.base.display().to_string()),
            ]),
        ]
    }

    pub fn render(&self, f: &mut Frame, area: Rect, t: &crate::theme::Theme) {
        let width = area.width.min(84);
        let height = area.height.min(16);
        let popup = Rect::new(
            area.x + (area.width - width) / 2,
            area.y + (area.height - height) / 2,
            width,
            height,
        );
        f.render_widget(Clear, popup);
        widgets::paint_overlay_bg(f, t, popup);
        let block = widgets::panel_block(t)
            .title(" Export preview ")
            .border_style(Style::default().fg(t.brand));
        let inner = block.inner(popup);
        f.render_widget(block, popup);
        let [body, footer] =
            Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(inner);
        f.render_widget(
            Paragraph::new(self.body(t))
                .wrap(Wrap { trim: false })
                .scroll((self.scroll, 0)),
            body,
        );
        let hints = if self.receiver.is_some() {
            vec![widgets::hint("esc", "cancel")]
        } else if self.incident {
            vec![
                widgets::hint("↵", "save"),
                widgets::hint("a", "comments"),
                widgets::hint("↑↓", "scroll"),
                widgets::hint("esc", "cancel"),
            ]
        } else {
            vec![
                widgets::hint("↵", "save"),
                widgets::hint("f", "format"),
                widgets::hint("a", "comments"),
                widgets::hint("↑↓", "scroll"),
                widgets::hint("esc", "cancel"),
            ]
        };
        f.render_widget(
            Paragraph::new(Line::from(widgets::hint_spans(t, &hints))),
            footer,
        );
    }
}

/// How far the preview scrolls. Generous on purpose: wrapped to a 40-column
/// terminal the body is under 30 lines, and scrolling past its end only
/// shows blank rows.
const MAX_SCROLL: u16 = 30;

/// Write a packet selection to a new, uniquely named file in `base`.
fn export_packets(
    packets: &[CapturedPacket],
    base: &std::path::Path,
    format: Format,
    annotations: bool,
    cancel: &AtomicBool,
) -> Result<String, String> {
    crate::owner_only::create_dir_all(base)
        .map_err(|e| format!("Failed to create {}: {e}", base.display()))?;
    let id = uuid::Uuid::new_v4().simple().to_string();
    let name = format!(
        "netwatch_capture_{}_{}.{}",
        chrono::Local::now().format("%Y%m%d_%H%M%S"),
        &id[..8],
        format.extension()
    );
    let path = base.join(name);
    let s = export::export_capture(packets, &path, format, annotations, cancel)?;
    Ok(format!(
        "Saved {} packets ({} omitted) to {}",
        s.packets,
        s.omitted,
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn press(dialog: &mut Dialog, code: KeyCode) -> Option<String> {
        dialog.key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn screen(dialog: &Dialog, width: u16, height: u16) -> String {
        use ratatui::{backend::TestBackend, Terminal};
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|f| dialog.render(f, f.area(), &crate::theme::by_name("default")))
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    #[test]
    fn preview_has_controls_at_small_sizes_and_cancel_does_not_write() {
        let path = std::env::temp_dir().join(format!("netwatch-preview-{}", uuid::Uuid::new_v4()));
        let mut dialog = Dialog::new(Selection::Packets(vec![]), path.clone());
        for (width, height) in [(80, 24), (60, 16), (40, 12)] {
            let text = screen(&dialog, width, height);
            assert!(text.contains("save"), "{width}x{height}");
            assert!(text.contains("Export preview"), "{width}x{height}");
        }
        assert!(screen(&dialog, 100, 30).contains("NOT redacted"));
        press(&mut dialog, KeyCode::Char('f'));
        assert_eq!(dialog.format, Format::Pcap);
        assert!(screen(&dialog, 100, 30).contains("not available in PCAP"));
        press(&mut dialog, KeyCode::Char('a'));
        assert!(!dialog.annotations);
        for _ in 0..40 {
            press(&mut dialog, KeyCode::Down);
        }
        assert_eq!(dialog.scroll, MAX_SCROLL);
        assert!(press(&mut dialog, KeyCode::Esc)
            .unwrap()
            .contains("cancelled"));
        assert!(!path.exists());
    }

    /// The owner count is what the file will name: none without comments
    /// or in classic PCAP.
    #[test]
    fn the_owner_count_follows_the_format_and_comments() {
        let mut dialog = Dialog::new(Selection::Packets(vec![]), std::env::temp_dir());
        dialog.summary.packets = 5;
        dialog.summary.annotated = 3;
        let owners = |d: &Dialog| d.summary().annotated;
        assert_eq!(owners(&dialog), 3);
        assert!(screen(&dialog, 100, 30).contains("3 with a socket owner"));
        press(&mut dialog, KeyCode::Char('a'));
        assert_eq!(owners(&dialog), 0);
        assert!(screen(&dialog, 100, 30).contains("0 with a socket owner"));
        press(&mut dialog, KeyCode::Char('a'));
        press(&mut dialog, KeyCode::Char('f'));
        assert_eq!(owners(&dialog), 0);
        press(&mut dialog, KeyCode::Char('f'));
        assert_eq!(owners(&dialog), 3);
        assert_eq!(dialog.summary().packets, 5);
    }

    #[test]
    fn q_closes_the_preview_like_esc() {
        let mut dialog = Dialog::new(Selection::Packets(vec![]), std::env::temp_dir());
        assert_eq!(
            press(&mut dialog, KeyCode::Char('q')).as_deref(),
            Some("Export cancelled")
        );
    }

    #[test]
    fn a_cancelled_write_reports_cancelled_and_leaves_nothing() {
        let base = std::env::temp_dir().join(format!("netwatch-preview-{}", uuid::Uuid::new_v4()));
        let mut dialog = Dialog::new(Selection::Packets(vec![]), base.clone());
        // Cancelled before the worker reads the flag, as Esc would during a
        // long write.
        dialog.cancel.store(true, Ordering::Relaxed);
        dialog.start();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let status = loop {
            if let Some(status) = dialog.poll() {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "export never finished"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(status, "Export cancelled");
        let left: Vec<_> = std::fs::read_dir(&base)
            .map(|d| d.map(|e| e.unwrap().file_name()).collect())
            .unwrap_or_default();
        assert!(left.is_empty(), "{left:?}");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn enter_writes_the_frozen_selection_in_the_background() {
        let base = std::env::temp_dir().join(format!("netwatch-preview-{}", uuid::Uuid::new_v4()));
        let mut dialog = Dialog::new(Selection::Packets(vec![]), base.clone());
        assert_eq!(press(&mut dialog, KeyCode::Enter), None);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let status = loop {
            if let Some(status) = dialog.poll() {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "export never finished"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(status.starts_with("Saved 0 packets"), "{status}");
        let files: Vec<_> = std::fs::read_dir(&base)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(files.len(), 1, "{files:?}");
        assert!(files[0].starts_with("netwatch_capture_") && files[0].ends_with(".pcapng"));
        std::fs::remove_dir_all(base).unwrap();
    }
}
