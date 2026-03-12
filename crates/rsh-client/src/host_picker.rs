//! Interactive host picker TUI — select a known host to connect to.
//!
//! Shows all configured hosts from `~/.rsh/config` in a filterable list.
//! Arrow keys to navigate, type to filter, Enter to select, Esc/q to cancel.
//! Entry point: [`run_host_picker`].

use std::io;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use rsh_core::config::{Config, HostConfig};

// ── Result ──────────────────────────────────────────────────────

/// What the picker returns.
pub enum PickerResult {
    /// User selected a host.
    Selected(HostConfig),
    /// User cancelled (Esc/q).
    Cancelled,
}

// ── Application state ───────────────────────────────────────────

struct App {
    hosts: Vec<HostConfig>,
    filtered: Vec<usize>, // indices into `hosts`
    list_state: ListState,
    filter: String,
}

impl App {
    fn new(hosts: Vec<HostConfig>) -> Self {
        let filtered: Vec<usize> = (0..hosts.len()).collect();
        let mut list_state = ListState::default();
        if !filtered.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            hosts,
            filtered,
            list_state,
            filter: String::new(),
        }
    }

    fn refilter(&mut self) {
        let q = self.filter.to_lowercase();
        self.filtered = (0..self.hosts.len())
            .filter(|&i| {
                if q.is_empty() {
                    return true;
                }
                let h = &self.hosts[i];
                h.pattern.to_lowercase().contains(&q)
                    || h.hostname
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&q)
                    || h.description
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&q)
                    || h.tailscale_ip
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&q)
                    || h.device_id
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&q)
                    || h.mac
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&q)
            })
            .collect();

        // Clamp selection
        if self.filtered.is_empty() {
            self.list_state.select(None);
        } else {
            let sel = self.list_state.selected().unwrap_or(0);
            if sel >= self.filtered.len() {
                self.list_state.select(Some(self.filtered.len() - 1));
            }
        }
    }

    fn next(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => (i + 1) % self.filtered.len(),
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn prev(&mut self) {
        if self.filtered.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(0) | None => self.filtered.len() - 1,
            Some(i) => i - 1,
        };
        self.list_state.select(Some(i));
    }

    fn selected_host(&self) -> Option<&HostConfig> {
        let sel = self.list_state.selected()?;
        let idx = *self.filtered.get(sel)?;
        self.hosts.get(idx)
    }
}

// ── Public entry point ──────────────────────────────────────────

/// Run the interactive host picker. Returns the selected host or Cancelled.
pub fn run_host_picker() -> io::Result<PickerResult> {
    let cfg = Config::load();
    if cfg.hosts.is_empty() {
        eprintln!("No hosts configured. Use `rsh config-edit` to add hosts.");
        return Ok(PickerResult::Cancelled);
    }

    // Filter out wildcard patterns (e.g. "192.168.*") — only concrete hosts
    let hosts: Vec<HostConfig> = cfg
        .hosts
        .into_iter()
        .filter(|h| !h.pattern.contains('*') && !h.pattern.contains('?'))
        .collect();

    if hosts.is_empty() {
        eprintln!("No concrete hosts configured (only wildcards found). Use `rsh config-edit` to add hosts.");
        return Ok(PickerResult::Cancelled);
    }

    let mut app = App::new(hosts);

    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;

    result
}

// ── Event loop ──────────────────────────────────────────────────

fn run_loop(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> io::Result<PickerResult> {
    loop {
        terminal.draw(|f| draw(f, app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            // Ctrl+C always quits
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                return Ok(PickerResult::Cancelled);
            }
            match key.code {
                KeyCode::Esc => return Ok(PickerResult::Cancelled),
                KeyCode::Enter => {
                    if let Some(host) = app.selected_host() {
                        return Ok(PickerResult::Selected(host.clone()));
                    }
                }
                KeyCode::Up => app.prev(),
                KeyCode::Down => app.next(),
                KeyCode::Backspace => {
                    app.filter.pop();
                    app.refilter();
                }
                KeyCode::Char(c) => {
                    // 'q' with empty filter = quit, otherwise type into filter
                    if c == 'q' && app.filter.is_empty() {
                        return Ok(PickerResult::Cancelled);
                    }
                    app.filter.push(c);
                    app.refilter();
                }
                _ => {}
            }
        }
    }
}

// ── Drawing ─────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(3), // filter bar
        Constraint::Min(5),   // host list
        Constraint::Length(1), // footer
    ])
    .split(f.area());

    draw_filter(f, app, chunks[0]);
    draw_list(f, app, chunks[1]);
    draw_footer(f, app, chunks[2]);
}

fn draw_filter(f: &mut Frame, app: &App, area: Rect) {
    let text = if app.filter.is_empty() {
        "Type to filter..."
    } else {
        &app.filter
    };
    let style = if app.filter.is_empty() {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(Color::Yellow)
    };
    let paragraph = Paragraph::new(text)
        .style(style)
        .block(Block::default().borders(Borders::ALL).title(" Filter "));
    f.render_widget(paragraph, area);
}

fn draw_list(f: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app
        .filtered
        .iter()
        .map(|&idx| {
            let h = &app.hosts[idx];
            let mut spans = vec![
                Span::styled(
                    format!("{:<20}", h.pattern),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
            ];

            // Address info
            let addr = h
                .hostname
                .as_deref()
                .unwrap_or("-");
            spans.push(Span::styled(
                format!("{:<22}", format!("{}:{}", addr, h.port)),
                Style::default().fg(Color::White),
            ));

            // Tailscale IP
            if let Some(ref ts) = h.tailscale_ip {
                spans.push(Span::styled(
                    format!("ts:{}  ", ts),
                    Style::default().fg(Color::Green),
                ));
            }

            // Description
            if let Some(ref desc) = h.description {
                spans.push(Span::styled(
                    format!("— {}", desc),
                    Style::default().fg(Color::DarkGray),
                ));
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    let title = format!(" Systems ({}/{}) ", app.filtered.len(), app.hosts.len());
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    f.render_stateful_widget(list, area, &mut app.list_state);
}

fn draw_footer(f: &mut Frame, _app: &App, area: Rect) {
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" ↑↓", Style::default().fg(Color::Yellow)),
        Span::raw(" navigate  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::raw(" connect  "),
        Span::styled("type", Style::default().fg(Color::Yellow)),
        Span::raw(" filter  "),
        Span::styled("Esc/q", Style::default().fg(Color::Yellow)),
        Span::raw(" cancel"),
    ]));
    f.render_widget(footer, area);
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a default HostConfig for tests (HostConfig::new is private to rsh-core).
    fn host(pattern: &str) -> HostConfig {
        HostConfig {
            pattern: pattern.to_string(),
            hostname: None,
            port: 8822,
            identity_file: None,
            user: None,
            mac: None,
            device_id: None,
            description: None,
            tailscale_ip: None,
            rendezvous_server: None,
            rendezvous_servers: Vec::new(),
            rendezvous_key: None,
            session_log: None,
        }
    }

    fn sample_hosts() -> Vec<HostConfig> {
        vec![
            HostConfig {
                hostname: Some("100.64.0.1".to_string()),
                description: Some("Dev GPU workstation".to_string()),
                tailscale_ip: Some("100.64.0.1".to_string()),
                ..host("gpu")
            },
            HostConfig {
                hostname: Some("lab-server.local".to_string()),
                description: Some("Factory lab machine".to_string()),
                ..host("lab-server")
            },
            HostConfig {
                hostname: Some("dev-box.local".to_string()),
                ..host("dev-box")
            },
        ]
    }

    #[test]
    fn filter_by_name() {
        let mut app = App::new(sample_hosts());
        app.filter = "gpu".to_string();
        app.refilter();
        assert_eq!(app.filtered.len(), 1);
        assert_eq!(app.hosts[app.filtered[0]].pattern, "gpu");
    }

    #[test]
    fn filter_by_description() {
        let mut app = App::new(sample_hosts());
        app.filter = "factory".to_string();
        app.refilter();
        assert_eq!(app.filtered.len(), 1);
        assert_eq!(app.hosts[app.filtered[0]].pattern, "lab-server");
    }

    #[test]
    fn filter_case_insensitive() {
        let mut app = App::new(sample_hosts());
        app.filter = "GPU".to_string();
        app.refilter();
        assert_eq!(app.filtered.len(), 1);
    }

    #[test]
    fn filter_by_hostname() {
        let mut app = App::new(sample_hosts());
        app.filter = "dev-box".to_string();
        app.refilter();
        assert_eq!(app.filtered.len(), 1);
        assert_eq!(app.hosts[app.filtered[0]].pattern, "dev-box");
    }

    #[test]
    fn filter_by_tailscale_ip() {
        let mut app = App::new(sample_hosts());
        app.filter = "100.64".to_string();
        app.refilter();
        assert_eq!(app.filtered.len(), 1);
        assert_eq!(app.hosts[app.filtered[0]].pattern, "gpu");
    }

    #[test]
    fn empty_filter_shows_all() {
        let mut app = App::new(sample_hosts());
        app.filter.clear();
        app.refilter();
        assert_eq!(app.filtered.len(), 3);
    }

    #[test]
    fn no_match_filter() {
        let mut app = App::new(sample_hosts());
        app.filter = "nonexistent".to_string();
        app.refilter();
        assert_eq!(app.filtered.len(), 0);
        assert!(app.selected_host().is_none());
    }

    #[test]
    fn navigation_wraps() {
        let mut app = App::new(sample_hosts());
        assert_eq!(app.list_state.selected(), Some(0));
        app.prev(); // wrap to end
        assert_eq!(app.list_state.selected(), Some(2));
        app.next(); // wrap to start
        assert_eq!(app.list_state.selected(), Some(0));
    }

    #[test]
    fn selected_host_returns_correct() {
        let mut app = App::new(sample_hosts());
        app.list_state.select(Some(1));
        let host = app.selected_host().unwrap();
        assert_eq!(host.pattern, "lab-server");
    }

    #[test]
    fn wildcard_filter_excludes() {
        let hosts = vec![
            host("gpu"),
            HostConfig {
                pattern: "192.168.*".to_string(),
                ..host("192.168.*")
            },
        ];
        let concrete: Vec<HostConfig> = hosts
            .into_iter()
            .filter(|h| !h.pattern.contains('*') && !h.pattern.contains('?'))
            .collect();
        assert_eq!(concrete.len(), 1);
        assert_eq!(concrete[0].pattern, "gpu");
    }
}
