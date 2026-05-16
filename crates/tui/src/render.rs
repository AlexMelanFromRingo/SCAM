//! ratatui frame composition. Kept in a separate module so unit tests can
//! exercise rendering against a `TestBackend` without booting a terminal.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::model::{
    format_count, format_hashrate, local_clock_24h, truncate_hash, AppState, PollOutcome,
};

pub fn draw(frame: &mut Frame<'_>, state: &AppState) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(area);

    draw_header(frame, chunks[0], state);
    draw_body(frame, chunks[1], state);
    draw_footer(frame, chunks[2], state);
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let status_tag = match state.last_outcome {
        PollOutcome::Ok => Span::styled(
            " LIVE ",
            Style::default()
                .bg(Color::Green)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        ),
        PollOutcome::PartialFailure => Span::styled(
            " DEGR ",
            Style::default()
                .bg(Color::Yellow)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        ),
        PollOutcome::Failed => Span::styled(
            " DOWN ",
            Style::default()
                .bg(Color::Red)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            "SCAM TUI",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        status_tag,
        Span::raw("  endpoint="),
        Span::styled(state.endpoint.display(), Style::default().fg(Color::White)),
        Span::raw("  poll="),
        Span::styled(
            format!("{}ms", state.poll_interval.as_millis()),
            Style::default().fg(Color::White),
        ),
        Span::raw("  clock="),
        Span::styled(local_clock_24h(), Style::default().fg(Color::Gray)),
    ]))
    .block(Block::default().borders(Borders::ALL).title(" Header "));

    frame.render_widget(header, area);
}

fn draw_body(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(cols[0]);

    draw_status(frame, left[0], state);
    draw_stratum(frame, left[1], state);
    draw_mempool(frame, cols[1], state);
}

fn draw_status(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let block = Block::default().borders(Borders::ALL).title(" Chain ");
    let lines: Vec<Line> = if let Some(s) = state.snapshot.status.as_ref() {
        vec![
            kv("network", &s.network_id),
            kv("tip height", &format_count(s.tip_height)),
            kv("tip hash", &truncate_hash(&s.tip_hash)),
            kv("utxo count", &format_count(s.utxo_count)),
            kv("cumulative work", &compact_work(&s.cumulative_work)),
            kv("network hashrate", &format_hashrate(s.network_hashrate_hps)),
            Line::from(vec![Span::raw("")]),
            Line::from(vec![Span::styled(
                if state.snapshot.healthy {
                    "/health: ok"
                } else {
                    "/health: NOT ok"
                },
                Style::default().fg(if state.snapshot.healthy {
                    Color::Green
                } else {
                    Color::Red
                }),
            )]),
        ]
    } else {
        vec![
            Line::from(Span::styled(
                "(no /status payload yet)",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            error_line(state),
        ]
    };

    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_stratum(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let block = Block::default().borders(Borders::ALL).title(" Stratum ");
    let lines: Vec<Line> = match state.snapshot.status.as_ref() {
        Some(s) => vec![
            kv(
                "active clients",
                &s.stratum_active_clients
                    .map(format_count)
                    .unwrap_or_else(|| "(n/a)".to_owned()),
            ),
            kv(
                "active workers",
                &s.stratum_workers_active
                    .map(format_count)
                    .unwrap_or_else(|| "(n/a)".to_owned()),
            ),
            kv(
                "pool hashrate",
                &s.stratum_pool_hashrate_hps
                    .map(format_hashrate)
                    .unwrap_or_else(|| "(n/a)".to_owned()),
            ),
        ],
        None => vec![Line::from(Span::styled(
            "(no /status payload yet)",
            Style::default().fg(Color::DarkGray),
        ))],
    };

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_mempool(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let title = match state.snapshot.mempool.as_ref() {
        Some(m) => format!(
            " Mempool ({} tx) ",
            format_count(m.tx_count.unwrap_or(m.txids.len() as u64))
        ),
        None => " Mempool ".to_owned(),
    };
    let block = Block::default().borders(Borders::ALL).title(title);

    let items: Vec<ListItem> = match state.snapshot.mempool.as_ref() {
        Some(m) if !m.txids.is_empty() => m
            .txids
            .iter()
            .enumerate()
            .map(|(i, txid)| {
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{i:>3} "), Style::default().fg(Color::DarkGray)),
                    Span::styled(truncate_hash(txid), Style::default().fg(Color::White)),
                ]))
            })
            .collect(),
        Some(_) => vec![ListItem::new(Line::from(Span::styled(
            "(mempool empty)",
            Style::default().fg(Color::DarkGray),
        )))],
        None => vec![ListItem::new(error_line(state))],
    };

    frame.render_widget(List::new(items).block(block), area);
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let uptime = state.started_at.elapsed().as_secs();
    let help = Paragraph::new(Line::from(vec![
        Span::styled(
            "[q]",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" quit  "),
        Span::styled(
            "[r]",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" refresh  "),
        Span::styled(
            "[+/-]",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" poll interval  "),
        Span::styled(
            format!("uptime {uptime}s  polls {}", state.poll_count),
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL).title(" Help "));
    frame.render_widget(help, area);
}

fn kv(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label:>17}: "),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            value.to_owned(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
    ])
}

fn error_line(state: &AppState) -> Line<'static> {
    match state.snapshot.last_error.as_deref() {
        Some(msg) => Line::from(Span::styled(
            format!("err: {msg}"),
            Style::default().fg(Color::Red),
        )),
        None => Line::from(""),
    }
}

fn compact_work(raw: &str) -> String {
    if raw.len() <= 24 {
        return raw.to_owned();
    }
    format!("{}…({} digits)", &raw[..16], raw.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MempoolSnapshot, PollSnapshot, StatusSnapshot};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::time::{Duration, Instant};

    fn populated_state() -> AppState {
        let mut state = AppState::new("127.0.0.1:18080", Duration::from_secs(2));
        let snapshot = PollSnapshot {
            status: Some(StatusSnapshot {
                network_id: "devnet".to_owned(),
                tip_height: 12_345,
                tip_hash: "deadbeef".repeat(8),
                utxo_count: 9_876,
                cumulative_work: "1".repeat(40),
                network_hashrate_hps: 12.0e12,
                stratum_active_clients: Some(3),
                stratum_workers_active: Some(7),
                stratum_pool_hashrate_hps: Some(1.5e12),
            }),
            mempool: Some(MempoolSnapshot {
                tx_count: Some(2),
                txids: vec!["aa".repeat(32), "bb".repeat(32)],
            }),
            healthy: true,
            last_error: None,
            fetched_at: Instant::now(),
        };
        state.inject_snapshot(snapshot, PollOutcome::Ok);
        state
    }

    fn rendered_text(state: &AppState, w: u16, h: u16) -> String {
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal.draw(|f| draw(f, state)).expect("draw");
        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                out.push_str(buffer[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn renders_chain_panel_for_populated_state() {
        let state = populated_state();
        let text = rendered_text(&state, 120, 24);
        assert!(text.contains("SCAM TUI"));
        assert!(text.contains("LIVE"));
        assert!(text.contains("devnet"));
        assert!(text.contains("12,345"));
        assert!(text.contains("TH/s"));
        assert!(text.contains("Mempool"));
        assert!(text.contains("..aaaaaa"));
    }

    #[test]
    fn renders_error_state_when_no_snapshot() {
        let mut state = AppState::new("127.0.0.1:1", Duration::from_secs(2));
        let snap = PollSnapshot {
            status: None,
            mempool: None,
            healthy: false,
            last_error: Some("/status: connect refused".to_owned()),
            fetched_at: Instant::now(),
        };
        state.inject_snapshot(snap, PollOutcome::Failed);
        let text = rendered_text(&state, 120, 24);
        assert!(text.contains("DOWN"));
        assert!(text.contains("connect refused"));
    }

    #[test]
    fn renders_degraded_when_partial() {
        let mut state = populated_state();
        let mut snap = state.snapshot.clone();
        snap.last_error = Some("/mempool: connect refused".to_owned());
        snap.mempool = None;
        state.inject_snapshot(snap, PollOutcome::PartialFailure);
        let text = rendered_text(&state, 120, 24);
        assert!(text.contains("DEGR"));
    }

    #[test]
    fn compact_work_truncates_long_decimal() {
        assert_eq!(compact_work("12345"), "12345");
        let long = "9".repeat(60);
        let out = compact_work(&long);
        assert!(out.contains("60 digits"));
        assert!(out.starts_with("9999999999999999"));
    }
}
