//! Fleet dashboard TUI — live status of all configured hosts.
//!
//! Shows all hosts from `~/.rsh/config` with real-time probe results.
//! Auto-refreshes every 10s, manual refresh with `r`.
//! Arrow keys navigate, `q`/Esc to quit.
//! Entry point: [`run_dashboard`].

use std::io;
use std::time::{Duration, Instant};

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};
use rsh_core::config::Config;

use crate::fleet::{self, HostStatus};

/// Auto-refresh interval.
const REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// Poll timeout for keyboard events between refreshes.
const POLL_TIMEOUT: Duration = Duration::from_millis(200);

// ── Application state ───────────────────────────────────────────

struct App {
    hosts: Vec<HostStatus>,
    table_state: TableState,
    last_refresh: Instant,
    refreshing: bool,
    config: Config,
}

impl App {
    fn new(config: Config) -> Self {
        let mut table_state = TableState::default();
        table_state.select(Some(0));
        Self {
            hosts: Vec::new(),
            table_state,
            last_refresh: Instant::now() - REFRESH_INTERVAL, // force immediate refresh
            refreshing: false,
            config,
        }
    }

    fn next(&mut self) {
        if self.hosts.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => (i + 1) % self.hosts.len(),
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn prev(&mut self) {
        if self.hosts.is_empty() {
            return;
        }
        let i = match self.table_state.selected() {
            Some(0) | None => self.hosts.len() - 1,
            Some(i) => i - 1,
        };
        self.table_state.select(Some(i));
    }

    fn needs_refresh(&self) -> bool {
        !self.refreshing && self.last_refresh.elapsed() >= REFRESH_INTERVAL
    }
}

// ── Public entry point ──────────────────────────────────────────

/// Run the interactive fleet dashboard. Returns when user quits.
pub async fn run_dashboard() -> io::Result<()> {
    let config = Config::load();
    if config.hosts.is_empty() {
        eprintln!("No hosts configured. Use `rsh config-edit` to add hosts.");
        return Ok(());
    }

    let mut app = App::new(config);

    // Initial probe
    app.refreshing = true;
    app.hosts = fleet::status(&app.config).await;
    app.last_refresh = Instant::now();
    app.refreshing = false;

    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, &mut app).await;

    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;

    result
}

// ── Event loop ──────────────────────────────────────────────────

async fn run_loop(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;

        // Auto-refresh check
        if app.needs_refresh() {
            app.refreshing = true;
            app.hosts = fleet::status(&app.config).await;
            app.last_refresh = Instant::now();
            app.refreshing = false;
            // Clamp selection
            if !app.hosts.is_empty() {
                let sel = app.table_state.selected().unwrap_or(0);
                if sel >= app.hosts.len() {
                    app.table_state.select(Some(app.hosts.len() - 1));
                }
            }
            continue;
        }

        // Poll for keyboard events
        if event::poll(POLL_TIMEOUT)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('c')
                {
                    return Ok(());
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Up | KeyCode::Char('k') => app.prev(),
                    KeyCode::Down | KeyCode::Char('j') => app.next(),
                    KeyCode::Char('r') => {
                        // Force refresh
                        app.refreshing = true;
                        app.hosts = fleet::status(&app.config).await;
                        app.last_refresh = Instant::now();
                        app.refreshing = false;
                    }
                    _ => {}
                }
            }
        }
    }
}

// ── Drawing ─────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Min(5),   // table
        Constraint::Length(1), // footer
    ])
    .split(f.area());

    draw_header(f, app, chunks[0]);
    draw_table(f, app, chunks[1]);
    draw_footer(f, chunks[2]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let online = app.hosts.iter().filter(|h| h.online).count();
    let total = app.hosts.len();
    let ago = app.last_refresh.elapsed().as_secs();
    let status = if app.refreshing {
        " probing...".to_string()
    } else {
        format!(" {}s ago", ago)
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" Fleet Dashboard — {}/{} online", online, total),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  (refreshed{})", status),
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    f.render_widget(header, area);
}

fn draw_table(f: &mut Frame, app: &mut App, area: Rect) {
    let header = Row::new(vec![
        "Name", "Hostname", "Port", "Status", "Version", "Latency", "Transport",
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .hosts
        .iter()
        .map(|h| {
            let status_style = if h.online {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            };
            let status_text = if h.online { "online" } else { "offline" };

            let version = h.version.as_deref().unwrap_or("-");

            let latency = if h.online {
                format!("{}ms", h.latency_ms)
            } else {
                "-".to_string()
            };

            let error_or_transport = if h.online {
                h.transport.to_string()
            } else {
                h.error.as_deref().unwrap_or("timeout").to_string()
            };

            Row::new(vec![
                h.name.clone(),
                h.hostname.clone(),
                h.port.to_string(),
                status_text.to_string(),
                version.to_string(),
                latency,
                error_or_transport,
            ])
            .style(status_style)
        })
        .collect();

    let widths = [
        Constraint::Length(20),
        Constraint::Length(24),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Min(12),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(" Hosts "))
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn draw_footer(f: &mut Frame, area: Rect) {
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" ↑↓", Style::default().fg(Color::Yellow)),
        Span::raw(" navigate  "),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::raw(" refresh  "),
        Span::styled("q/Esc", Style::default().fg(Color::Yellow)),
        Span::raw(" quit  "),
        Span::styled("auto", Style::default().fg(Color::DarkGray)),
        Span::raw(" 10s"),
    ]));
    f.render_widget(footer, area);
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hosts() -> Vec<HostStatus> {
        vec![
            HostStatus {
                name: "gpu".into(),
                hostname: "100.64.0.1".into(),
                port: 8822,
                online: true,
                version: Some("1.2.0".into()),
                caps: vec![],
                latency_ms: 12,
                error: None,
                device_id: None,
                rendezvous_server: None,
                rendezvous_key: None,
                quic_port: None,
                transport: "tls",
            },
            HostStatus {
                name: "lab".into(),
                hostname: "lab.local".into(),
                port: 8822,
                online: false,
                version: None,
                caps: vec![],
                latency_ms: 0,
                error: Some("timeout".into()),
                device_id: None,
                rendezvous_server: None,
                rendezvous_key: None,
                quic_port: None,
                transport: "",
            },
        ]
    }

    #[test]
    fn navigation_wraps() {
        let config = Config::default();
        let mut app = App::new(config);
        app.hosts = sample_hosts();
        app.table_state.select(Some(0));

        app.prev(); // wrap to end
        assert_eq!(app.table_state.selected(), Some(1));
        app.next(); // wrap to start
        assert_eq!(app.table_state.selected(), Some(0));
    }

    #[test]
    fn needs_refresh_initially() {
        let config = Config::default();
        let app = App::new(config);
        assert!(app.needs_refresh());
    }

    #[test]
    fn no_refresh_after_recent() {
        let config = Config::default();
        let mut app = App::new(config);
        app.last_refresh = Instant::now();
        assert!(!app.needs_refresh());
    }
}
