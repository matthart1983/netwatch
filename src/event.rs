use anyhow::Result;
use crossterm::event::{self, Event, KeyEvent, MouseEvent};
use std::time::Duration;
use tokio::sync::mpsc;

pub enum AppEvent {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Tick,
}

pub struct EventHandler {
    rx: mpsc::UnboundedReceiver<AppEvent>,
}

impl EventHandler {
    pub fn new(tick_rate_ms: u64) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let tick_rate = Duration::from_millis(tick_rate_ms);

        // Use a dedicated OS thread instead of tokio::spawn, since
        // crossterm::event::poll() is a blocking call that would tie up
        // a tokio worker thread permanently.
        std::thread::spawn(move || {
            loop {
                if event::poll(tick_rate).unwrap_or(false) {
                    match event::read() {
                        Ok(Event::Key(key)) => {
                            if tx.send(AppEvent::Key(key)).is_err() {
                                return;
                            }
                        }
                        Ok(Event::Mouse(mouse)) => {
                            if tx.send(AppEvent::Mouse(mouse)).is_err() {
                                return;
                            }
                        }
                        _ => {}
                    }
                } else if tx.send(AppEvent::Tick).is_err() {
                    return;
                }
            }
        });

        Self { rx }
    }

    pub async fn next(&mut self) -> Result<AppEvent> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Event channel closed"))
    }
}
