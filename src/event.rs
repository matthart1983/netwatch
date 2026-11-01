use anyhow::Result;
use crossterm::event::{self, Event, KeyEvent, KeyEventKind, MouseEvent, MouseEventKind};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// The longest the terminal thread waits for input before checking whether it
/// should stop. It polled for a whole tick, so a quit sat waiting for that tick
/// with the shell already back, and this thread still reading the keys typed at it.
const INPUT_WAIT: Duration = Duration::from_millis(50);

pub enum AppEvent {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Tick,
}

pub struct EventHandler {
    rx: mpsc::UnboundedReceiver<AppEvent>,
    /// Polling interval for the background thread, in milliseconds.
    /// Shared with the thread so settings changes apply within one
    /// poll cycle without requiring a restart.
    // u32, not u64: the value is clamped to 100..=5000 right below, which
    // fits comfortably, and armv5te (old Kirkwood NAS boxes) has no native
    // 64-bit atomics.
    tick_rate_ms: Arc<AtomicU32>,
}

impl EventHandler {
    pub fn start(tick_rate_ms: u64) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let tick_rate_ms = Arc::new(AtomicU32::new(tick_rate_ms.clamp(100, 5000) as u32));
        let tick_rate_thread = Arc::clone(&tick_rate_ms);

        // Use a dedicated OS thread instead of tokio::spawn, since
        // crossterm::event::poll() is a blocking call that would tie up
        // a tokio worker thread permanently.
        crate::sandbox::worker::spawn("terminal", move || {
            let mut last_tick = Instant::now();
            while !crate::sandbox::worker::stopping() {
                // Re-read the tick rate each iteration so the settings popup
                // can change refresh_rate_ms at runtime and have it take
                // effect on the next poll without a restart.
                let tick = Duration::from_millis(tick_rate_thread.load(Ordering::Relaxed) as u64);
                let wait = tick.saturating_sub(last_tick.elapsed()).min(INPUT_WAIT);
                if event::poll(wait).unwrap_or(false) {
                    match event::read() {
                        Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                            if tx.send(AppEvent::Key(key)).is_err() {
                                return;
                            }
                        }
                        Ok(Event::Mouse(mouse)) if wanted(&mouse) => {
                            if tx.send(AppEvent::Mouse(mouse)).is_err() {
                                return;
                            }
                        }
                        _ => {}
                    }
                } else if last_tick.elapsed() >= tick {
                    if tx.send(AppEvent::Tick).is_err() {
                        return;
                    }
                    last_tick = Instant::now();
                }
            }
        });

        Self { rx, tick_rate_ms }
    }

    /// Update the polling interval. Idempotent — calling with the current
    /// value is a no-op atomic store, so the run loop can call this every
    /// iteration without tracking previous state.
    pub fn set_tick_rate(&self, ms: u64) {
        self.tick_rate_ms
            .store(ms.clamp(100, 5000) as u32, Ordering::Relaxed);
    }

    pub async fn next(&mut self) -> Result<AppEvent> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Event channel closed"))
    }

    /// The next event if one is already waiting. A closed channel reads as
    /// empty here; [`next`](Self::next) reports it.
    pub fn try_next(&mut self) -> Option<AppEvent> {
        self.rx.try_recv().ok()
    }
}

/// Whether a mouse event goes to the app. Mouse capture turns on any-motion
/// reporting, so every move of the pointer arrives, each one cost a full
/// redraw, and nothing reads a move with no button held. A drag (a move with
/// a button held) still goes through.
fn wanted(mouse: &MouseEvent) -> bool {
    mouse.kind != MouseEventKind::Moved
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyModifiers, MouseButton};

    fn mouse(kind: MouseEventKind) -> MouseEvent {
        MouseEvent {
            kind,
            column: 10,
            row: 5,
            modifiers: KeyModifiers::NONE,
        }
    }

    #[test]
    fn moved_without_drag_is_dropped() {
        assert!(!wanted(&mouse(MouseEventKind::Moved)));
        for kind in [
            MouseEventKind::Drag(MouseButton::Left),
            MouseEventKind::Down(MouseButton::Left),
            MouseEventKind::Up(MouseButton::Left),
            MouseEventKind::ScrollUp,
            MouseEventKind::ScrollDown,
        ] {
            assert!(wanted(&mouse(kind)), "{kind:?}");
        }
    }
}
