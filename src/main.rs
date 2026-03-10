use anyhow::Result;
use netwatch::app;
use netwatch::config::NetwatchConfig;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::prelude::*;
use std::io;

#[tokio::main]
async fn main() -> Result<()> {
    // Handle --generate-config before entering TUI mode
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--generate-config") {
        let cfg = NetwatchConfig::default();
        cfg.save()?;
        let path = NetwatchConfig::path().unwrap();
        println!("Config written to {}", path.display());
        return Ok(());
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = app::run(&mut terminal).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Error: {e:?}");
    }

    Ok(())
}
