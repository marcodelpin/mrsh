//! Fleet dashboard TUI — live status of all configured hosts.
//!
//! Shows all hosts from `~/.rsh/config` with real-time probe results.
//! Auto-refreshes every 10s, manual refresh with `r`.
//! Arrow keys navigate, Enter to open action menu, `q`/Esc to quit.
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
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};
use rsh_core::config::Config;

use crate::fleet::{self, HostStatus};

/// Auto-refresh interval.
const REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// Poll timeout for keyboard events between refreshes.
const POLL_TIMEOUT: Duration = Duration::from_millis(200);

// ── Action menu ─────────────────────────────────────────────────

/// Action the user can take on a selected host.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HostAction {
    Shell,
    Browse,
    Sftp,
    Exec,
    Push,
    Pull,
    Screenshot,
    Logs,
}

impl HostAction {
    fn label(self) -> &'static str {
        match self {
            Self::Shell => "shell       — interactive shell",
            Self::Browse => "browse      — file browser",
            Self::Sftp => "sftp        — sftp session",
            Self::Exec => "exec        — run a command",
            Self::Push => "push        — upload file",
            Self::Pull => "pull        — download file",
            Self::Screenshot => "screenshot  — capture screen",
            Self::Logs => "logs        — view host logs",
        }
    }

    fn all() -> &'static [HostAction] {
        &[
            Self::Shell,
            Self::Browse,
            Self::Sftp,
            Self::Exec,
            Self::Push,
            Self::Pull,
            Self::Screenshot,
            Self::Logs,
        ]
    }
}

/// Result from running the dashboard — either user quit or selected an action.
pub enum DashboardResult {
    Quit,
    Action {
        host: String,
        hostname: String,
        port: u16,
        action: HostAction,
    },
}

// ── Application state ───────────────────────────────────────────

struct App {
    hosts: Vec<HostStatus>,
    table_state: TableState,
    last_refresh: Instant,
    refreshing: bool,
    config: Config,
    /// When Some, shows the action menu for the selected host.
    menu: Option<MenuState>,
}

struct MenuState {
    host_idx: usize,
    list_state: ListState,
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
            menu: None,
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
        !self.refreshing && self.menu.is_none() && self.last_refresh.elapsed() >= REFRESH_INTERVAL
    }

    fn open_menu(&mut self) {
        if let Some(idx) = self.table_state.selected() {
            if idx < self.hosts.len() {
                let mut list_state = ListState::default();
                list_state.select(Some(0));
                self.menu = Some(MenuState {
                    host_idx: idx,
                    list_state,
                });
            }
        }
    }

    fn close_menu(&mut self) {
        self.menu = None;
    }

    fn menu_next(&mut self) {
        if let Some(ref mut menu) = self.menu {
            let len = HostAction::all().len();
            let i = menu.list_state.selected().map_or(0, |i| (i + 1) % len);
            menu.list_state.select(Some(i));
        }
    }

    fn menu_prev(&mut self) {
        if let Some(ref mut menu) = self.menu {
            let len = HostAction::all().len();
            let i = menu
                .list_state
                .selected()
                .map_or(0, |i| if i == 0 { len - 1 } else { i - 1 });
            menu.list_state.select(Some(i));
        }
    }

    fn menu_select(&self) -> Option<(usize, HostAction)> {
        self.menu.as_ref().and_then(|m| {
            let action_idx = m.list_state.selected()?;
            Some((m.host_idx, HostAction::all()[action_idx]))
        })
    }
}

// ── Public entry point ──────────────────────────────────────────

/// Run the interactive fleet dashboard. Returns when user quits or selects an action.
pub async fn run_dashboard() -> io::Result<()> {
    match run_dashboard_interactive().await? {
        DashboardResult::Quit => Ok(()),
        DashboardResult::Action {
            host,
            hostname,
            port,
            action,
        } => {
            // Print the command to run after exiting TUI
            let cmd = match action {
                HostAction::Shell => format!("rsh -h {} -p {} shell", hostname, port),
                HostAction::Browse => format!("rsh -h {} -p {} browse", hostname, port),
                HostAction::Sftp => format!("rsh -h {} -p {} sftp", hostname, port),
                HostAction::Exec => format!("rsh -h {} -p {} exec", hostname, port),
                HostAction::Push => format!("rsh -h {} -p {} push", hostname, port),
                HostAction::Pull => format!("rsh -h {} -p {} pull", hostname, port),
                HostAction::Screenshot => {
                    format!("rsh -h {} -p {} screenshot", hostname, port)
                }
                HostAction::Logs => format!("rsh -h {} -p {} exec \"Get-EventLog -LogName System -Newest 20\"", hostname, port),
            };
            eprintln!("→ {} ({})", host, cmd);

            // Re-exec ourselves with the right args.
            // This avoids duplicating connect/dispatch logic.
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("-h")
                .arg(&hostname)
                .arg("-p")
                .arg(port.to_string())
                .arg(match action {
                    HostAction::Shell => "shell",
                    HostAction::Browse => "browse",
                    HostAction::Sftp => "sftp",
                    HostAction::Screenshot => "screenshot",
                    _ => {
                        eprintln!("Run: {}", cmd);
                        return Ok(());
                    }
                })
                .status();

            match status {
                Ok(s) if !s.success() => {
                    eprintln!("Command exited with {}", s);
                }
                Err(e) => {
                    eprintln!("Failed to launch: {}", e);
                }
                _ => {}
            }
            Ok(())
        }
    }
}

/// Inner dashboard loop returning the user's choice.
async fn run_dashboard_interactive() -> io::Result<DashboardResult> {
    let config = Config::load();
    if config.hosts.is_empty() && config.rendezvous_server.is_none() {
        eprintln!("No hosts configured and no rendezvous server. Use `rsh config-edit` to add hosts.");
        return Ok(DashboardResult::Quit);
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
) -> io::Result<DashboardResult> {
    // Background refresh: spawned task sends results via channel.
    // This keeps the event loop responsive during long probe timeouts.
    let (refresh_tx, mut refresh_rx) = tokio::sync::mpsc::channel::<Vec<HostStatus>>(1);

    /// Spawn a background fleet status probe.
    fn spawn_refresh(config: &Config, tx: &tokio::sync::mpsc::Sender<Vec<HostStatus>>) {
        let config = config.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let hosts = fleet::status(&config).await;
            let _ = tx.send(hosts).await;
        });
    }

    loop {
        terminal.draw(|f| draw(f, app))?;

        // Check if background refresh completed
        if let Ok(hosts) = refresh_rx.try_recv() {
            app.hosts = hosts;
            app.last_refresh = Instant::now();
            app.refreshing = false;
            // Clamp selection
            if !app.hosts.is_empty() {
                let sel = app.table_state.selected().unwrap_or(0);
                if sel >= app.hosts.len() {
                    app.table_state.select(Some(app.hosts.len() - 1));
                }
            }
        }

        // Auto-refresh check (paused while menu is open)
        if app.needs_refresh() && !app.refreshing {
            app.refreshing = true;
            spawn_refresh(&app.config, &refresh_tx);
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
                    return Ok(DashboardResult::Quit);
                }

                if app.menu.is_some() {
                    // Menu mode
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('q') => app.close_menu(),
                        KeyCode::Up | KeyCode::Char('k') => app.menu_prev(),
                        KeyCode::Down | KeyCode::Char('j') => app.menu_next(),
                        KeyCode::Enter => {
                            if let Some((idx, action)) = app.menu_select() {
                                let h = &app.hosts[idx];
                                return Ok(DashboardResult::Action {
                                    host: h.name.clone(),
                                    hostname: h.hostname.clone(),
                                    port: h.port,
                                    action,
                                });
                            }
                        }
                        _ => {}
                    }
                } else {
                    // Table mode
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(DashboardResult::Quit),
                        KeyCode::Up | KeyCode::Char('k') => app.prev(),
                        KeyCode::Down | KeyCode::Char('j') => app.next(),
                        KeyCode::Enter => app.open_menu(),
                        KeyCode::Char('r') if !app.refreshing => {
                            // Force refresh
                            app.refreshing = true;
                            spawn_refresh(&app.config, &refresh_tx);
                        }
                        _ => {}
                    }
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
    draw_footer(f, app, chunks[2]);

    // Draw menu overlay if open
    if let Some(ref mut menu) = app.menu {
        let host_name = app
            .hosts
            .get(menu.host_idx)
            .map(|h| h.name.as_str())
            .unwrap_or("?");
        draw_menu(f, host_name, &mut menu.list_state);
    }
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

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let hints = if app.menu.is_some() {
        vec![
            Span::styled(" ↑↓", Style::default().fg(Color::Yellow)),
            Span::raw(" select  "),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::raw(" confirm  "),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::raw(" back"),
        ]
    } else {
        vec![
            Span::styled(" ↑↓", Style::default().fg(Color::Yellow)),
            Span::raw(" navigate  "),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::raw(" actions  "),
            Span::styled("r", Style::default().fg(Color::Yellow)),
            Span::raw(" refresh  "),
            Span::styled("q", Style::default().fg(Color::Yellow)),
            Span::raw(" quit  "),
            Span::styled("auto", Style::default().fg(Color::DarkGray)),
            Span::raw(" 10s"),
        ]
    };
    let footer = Paragraph::new(Line::from(hints));
    f.render_widget(footer, area);
}

fn draw_menu(f: &mut Frame, host_name: &str, list_state: &mut ListState) {
    let actions = HostAction::all();
    let items: Vec<ListItem> = actions
        .iter()
        .map(|a| ListItem::new(a.label()))
        .collect();

    let menu_height = (actions.len() as u16) + 2; // +2 for border
    let menu_width = 42;
    let area = f.area();
    let x = area.width.saturating_sub(menu_width) / 2;
    let y = area.height.saturating_sub(menu_height) / 2;
    let menu_area = Rect::new(x, y, menu_width.min(area.width), menu_height.min(area.height));

    // Clear background
    f.render_widget(Clear, menu_area);

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ", host_name))
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    f.render_stateful_widget(list, menu_area, list_state);
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

    #[test]
    fn menu_open_close() {
        let config = Config::default();
        let mut app = App::new(config);
        app.hosts = sample_hosts();
        app.table_state.select(Some(0));

        assert!(app.menu.is_none());
        app.open_menu();
        assert!(app.menu.is_some());
        assert_eq!(app.menu.as_ref().unwrap().host_idx, 0);

        app.close_menu();
        assert!(app.menu.is_none());
    }

    #[test]
    fn menu_navigation() {
        let config = Config::default();
        let mut app = App::new(config);
        app.hosts = sample_hosts();
        app.table_state.select(Some(0));
        app.open_menu();

        assert_eq!(app.menu.as_ref().unwrap().list_state.selected(), Some(0));
        app.menu_next();
        assert_eq!(app.menu.as_ref().unwrap().list_state.selected(), Some(1));
        app.menu_prev();
        assert_eq!(app.menu.as_ref().unwrap().list_state.selected(), Some(0));
        // Wrap backwards
        app.menu_prev();
        assert_eq!(
            app.menu.as_ref().unwrap().list_state.selected(),
            Some(HostAction::all().len() - 1)
        );
    }

    #[test]
    fn menu_select_returns_action() {
        let config = Config::default();
        let mut app = App::new(config);
        app.hosts = sample_hosts();
        app.table_state.select(Some(1));
        app.open_menu();

        let (idx, action) = app.menu_select().unwrap();
        assert_eq!(idx, 1);
        assert_eq!(action, HostAction::Shell);
    }

    #[test]
    fn no_refresh_while_menu_open() {
        let config = Config::default();
        let mut app = App::new(config);
        app.hosts = sample_hosts();
        app.last_refresh = Instant::now() - REFRESH_INTERVAL - Duration::from_secs(1);
        assert!(app.needs_refresh());

        app.table_state.select(Some(0));
        app.open_menu();
        assert!(!app.needs_refresh()); // paused while menu open
    }

    #[test]
    fn host_action_labels() {
        for action in HostAction::all() {
            assert!(!action.label().is_empty());
        }
    }
}
