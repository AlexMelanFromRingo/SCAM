#![cfg_attr(not(test), deny(clippy::unwrap_used))]
//! Terminal UI dashboard for a running `scam-node rpc-serve` instance.
//!
//! Read-only. Talks plain HTTP/1.1 to `127.0.0.1:<port>` (no TLS, no auth — same
//! security boundary as the web console). Polls `/health`, `/status`, `/mempool`
//! on an interval and renders a four-panel dashboard with `ratatui`.

pub mod http;
pub mod model;
pub mod render;

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use thiserror::Error;

use crate::http::HttpError;
use crate::model::AppState;

/// Public entry point — opens the alternate terminal screen, runs the event
/// loop, and restores the terminal regardless of how we exit.
pub fn run(endpoint: &str, poll_interval: Duration) -> Result<(), TuiError> {
    let mut state = AppState::new(endpoint, poll_interval);

    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();
    enable_raw_mode().map_err(TuiError::Terminal)?;
    execute!(stdout_lock, EnterAlternateScreen).map_err(TuiError::Terminal)?;

    let backend = CrosstermBackend::new(&mut stdout_lock);
    let mut terminal = Terminal::new(backend).map_err(TuiError::Terminal)?;

    let result = event_loop(&mut terminal, &mut state);

    // Best-effort terminal restore; do not mask the loop error.
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    result
}

fn event_loop<B>(
    terminal: &mut Terminal<B>,
    state: &mut AppState,
) -> Result<(), TuiError>
where
    B: ratatui::backend::Backend,
{
    // Eager first poll so the screen is not empty for a full interval.
    state.poll_now();

    loop {
        terminal
            .draw(|frame| render::draw(frame, state))
            .map_err(TuiError::Terminal)?;

        // Wake at most every 100ms so the clock in the header ticks and the
        // poll-interval is enforced without busy-looping.
        let tick_budget = Duration::from_millis(100);
        if event::poll(tick_budget).map_err(TuiError::Terminal)? {
            match event::read().map_err(TuiError::Terminal)? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if matches!(
                        key.code,
                        KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('Q')
                    ) {
                        return Ok(());
                    }
                    if key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                    {
                        return Ok(());
                    }
                    if matches!(key.code, KeyCode::Char('r') | KeyCode::Char('R')) {
                        state.poll_now();
                    }
                    if matches!(key.code, KeyCode::Char('+') | KeyCode::Char('=')) {
                        state.bump_poll_interval(true);
                    }
                    if key.code == KeyCode::Char('-') {
                        state.bump_poll_interval(false);
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }

        if state.due_for_poll() {
            state.poll_now();
        }
    }
}

/// Test-only entry point: drive the event loop without owning the terminal,
/// so unit tests can exercise rendering/poll triggers deterministically.
#[doc(hidden)]
pub fn drive_for_test(state: &mut AppState, stop: Arc<AtomicBool>, max_ticks: usize) {
    let start = Instant::now();
    let mut ticks = 0;
    while !stop.load(Ordering::Relaxed) && ticks < max_ticks {
        if state.due_for_poll() {
            state.poll_now();
        }
        ticks += 1;
        if start.elapsed() > Duration::from_secs(5) {
            break;
        }
    }
}

#[derive(Debug, Error)]
pub enum TuiError {
    #[error("terminal io: {0}")]
    Terminal(#[source] io::Error),
    #[error("rpc transport: {0}")]
    Rpc(#[from] HttpError),
}

pub use model::{PollOutcome as Outcome, PollSnapshot};
