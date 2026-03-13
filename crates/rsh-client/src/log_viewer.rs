//! Interactive log viewer TUI — browse session logs with filtering.
//!
//! Shows log entries from `~/.rsh/logs/*.jsonl` in a scrollable table.
//! Type to filter by host, `Tab` to cycle views (entries/summary).
//! Arrow keys navigate, `q`/Esc to quit.
//! Entry point: [`run_log_viewer`].

use std::io;
use std::path::PathBuf;

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

use crate::session_log::{self, HostSummary, LogEntry, LogFilter};

// ── View mode ───────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq)]
enum View {
    Entries,
    Summary,
}

// ── Application state ───────────────────────────────────────────

struct App {
    log_dir: PathBuf,
    all_entries: Vec<LogEntry>,
    filtered: Vec<usize>, // indices into all_entries
    summaries: Vec<HostSummary>,
    table_state: TableState,
    filter: String,
    view: View,
}

impl App {
    fn new(log_dir: PathBuf) -> Self {
        let filter = LogFilter {
            host: None,
            since: None,
            until: None,
        };
        let all_entries = session_log::query_logs(&log_dir, &filter);
        let summaries = session_log::summarize_by_host(&all_entries);
        let filtered: Vec<usize> = (0..all_entries.len()).rev().collect(); // newest first
        let mut table_state = TableState::default();
        if !filtered.is_empty() {
            table_state.select(Some(0));
        }

        Self {
            log_dir,
            all_entries,
            filtered,
            summaries,
            table_state,
            filter: String::new(),
            view: View::Entries,
        }
    }

    fn refilter(&mut self) {
        let q = self.filter.to_lowercase();
        self.filtered = (0..self.all_entries.len())
            .rev() // newest first
            .filter(|&i| {
                if q.is_empty() {
                    return true;
                }
                let e = &self.all_entries[i];
                e.host.to_lowercase().contains(&q)
                    || e.cmd.to_lowercase().contains(&q)
                    || e.args
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&q)
            })
            .collect();

        // Recompute summaries from filtered entries only
        let filtered_entries: Vec<&LogEntry> = self
            .filtered
            .iter()
            .map(|&i| &self.all_entries[i])
            .collect();
        self.summaries = session_log::summarize_by_host(
            &filtered_entries.into_iter().cloned().collect::<Vec<_>>(),
        );

        // Clamp selection
        let count = self.visible_count();
        if count == 0 {
            self.table_state.select(None);
        } else {
            let sel = self.table_state.selected().unwrap_or(0);
            if sel >= count {
                self.table_state.select(Some(count - 1));
            }
        }
    }

    fn visible_count(&self) -> usize {
        match self.view {
            View::Entries => self.filtered.len(),
            View::Summary => self.summaries.len(),
        }
    }

    fn next(&mut self) {
        let count = self.visible_count();
        if count == 0 {
            return;
        }
        let i = match self.table_state.selected() {
            Some(i) => (i + 1) % count,
            None => 0,
        };
        self.table_state.select(Some(i));
    }

    fn prev(&mut self) {
        let count = self.visible_count();
        if count == 0 {
            return;
        }
        let i = match self.table_state.selected() {
            Some(0) | None => count - 1,
            Some(i) => i - 1,
        };
        self.table_state.select(Some(i));
    }

    fn toggle_view(&mut self) {
        self.view = match self.view {
            View::Entries => View::Summary,
            View::Summary => View::Entries,
        };
        self.table_state.select(Some(0));
    }
}

// ── Public entry point ──────────────────────────────────────────

/// Run the interactive log viewer TUI.
pub fn run_log_viewer() -> io::Result<()> {
    let log_dir = session_log::default_log_dir();
    if !log_dir.exists() {
        eprintln!(
            "No session logs found at {}",
            log_dir.display()
        );
        return Ok(());
    }

    let app = App::new(log_dir);
    if app.all_entries.is_empty() {
        eprintln!("No log entries found.");
        return Ok(());
    }

    let mut app = app;

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
) -> io::Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;

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
                KeyCode::Esc => return Ok(()),
                KeyCode::Tab => app.toggle_view(),
                KeyCode::Up | KeyCode::Char('k') if app.filter.is_empty() => app.prev(),
                KeyCode::Down | KeyCode::Char('j') if app.filter.is_empty() => app.next(),
                KeyCode::Up => app.prev(),
                KeyCode::Down => app.next(),
                KeyCode::Backspace => {
                    app.filter.pop();
                    app.refilter();
                }
                KeyCode::Char(c) => {
                    if c == 'q' && app.filter.is_empty() {
                        return Ok(());
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
        Constraint::Min(5),   // table
        Constraint::Length(1), // footer
    ])
    .split(f.area());

    draw_filter(f, app, chunks[0]);
    match app.view {
        View::Entries => draw_entries(f, app, chunks[1]),
        View::Summary => draw_summary(f, app, chunks[1]),
    }
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

fn draw_entries(f: &mut Frame, app: &mut App, area: Rect) {
    let header = Row::new(vec![
        "Time", "Host", "Port", "Command", "Args", "Duration", "Exit",
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .filtered
        .iter()
        .map(|&idx| {
            let e = &app.all_entries[idx];
            let time = if e.start.len() > 19 {
                &e.start[..19]
            } else {
                &e.start
            };
            let exit_style = match e.exit {
                0 => Style::default().fg(Color::Green),
                _ => Style::default().fg(Color::Red),
            };
            Row::new(vec![
                time.to_string(),
                e.host.clone(),
                e.port.to_string(),
                e.cmd.clone(),
                e.args.as_deref().unwrap_or("").to_string(),
                session_log::format_duration(e.duration_s),
                e.exit.to_string(),
            ])
            .style(exit_style)
        })
        .collect();

    let count = app.filtered.len();
    let total = app.all_entries.len();
    let title = format!(" Entries ({}/{}) ", count, total);

    let widths = [
        Constraint::Length(19),
        Constraint::Length(20),
        Constraint::Length(6),
        Constraint::Length(12),
        Constraint::Min(16),
        Constraint::Length(10),
        Constraint::Length(5),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn draw_summary(f: &mut Frame, app: &mut App, area: Rect) {
    let header = Row::new(vec![
        "Host", "Commands", "Total Time", "First Seen", "Last Seen",
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .summaries
        .iter()
        .map(|s| {
            let first = s
                .first_seen
                .as_deref()
                .and_then(|t| t.get(..10))
                .unwrap_or("-");
            let last = s
                .last_seen
                .as_deref()
                .and_then(|t| t.get(..10))
                .unwrap_or("-");
            Row::new(vec![
                s.host.clone(),
                s.command_count.to_string(),
                session_log::format_duration(s.total_seconds),
                first.to_string(),
                last.to_string(),
            ])
            .style(Style::default().fg(Color::Cyan))
        })
        .collect();

    let title = format!(" Summary ({} hosts) ", app.summaries.len());

    let widths = [
        Constraint::Length(24),
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Min(12),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let view_label = match app.view {
        View::Entries => "entries",
        View::Summary => "summary",
    };
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" ↑↓", Style::default().fg(Color::Yellow)),
        Span::raw(" navigate  "),
        Span::styled("Tab", Style::default().fg(Color::Yellow)),
        Span::raw(format!(" view ({})  ", view_label)),
        Span::styled("type", Style::default().fg(Color::Yellow)),
        Span::raw(" filter  "),
        Span::styled("Esc/q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]));
    f.render_widget(footer, area);
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn sample_entries() -> Vec<LogEntry> {
        vec![
            LogEntry {
                host: "gpu".into(),
                port: 8822,
                cmd: "exec".into(),
                args: Some("hostname".into()),
                start: "2026-03-13T10:00:00+01:00".into(),
                end: "2026-03-13T10:00:01+01:00".into(),
                duration_s: 1.0,
                exit: 0,
            },
            LogEntry {
                host: "lab".into(),
                port: 8822,
                cmd: "push".into(),
                args: Some("file.txt remote.txt".into()),
                start: "2026-03-13T09:00:00+01:00".into(),
                end: "2026-03-13T09:00:05+01:00".into(),
                duration_s: 5.0,
                exit: 0,
            },
            LogEntry {
                host: "gpu".into(),
                port: 8822,
                cmd: "exec".into(),
                args: Some("failing-cmd".into()),
                start: "2026-03-12T08:00:00+01:00".into(),
                end: "2026-03-12T08:00:02+01:00".into(),
                duration_s: 2.0,
                exit: 1,
            },
        ]
    }

    #[test]
    fn filter_by_host() {
        let entries = sample_entries();
        let log_dir = PathBuf::from("/tmp/nonexistent");
        let mut app = App {
            log_dir,
            all_entries: entries,
            filtered: vec![2, 1, 0], // reversed
            summaries: vec![],
            table_state: TableState::default(),
            filter: String::new(),
            view: View::Entries,
        };
        app.filter = "gpu".into();
        app.refilter();
        assert_eq!(app.filtered.len(), 2);
    }

    #[test]
    fn filter_by_command() {
        let entries = sample_entries();
        let log_dir = PathBuf::from("/tmp/nonexistent");
        let mut app = App {
            log_dir,
            all_entries: entries,
            filtered: vec![2, 1, 0],
            summaries: vec![],
            table_state: TableState::default(),
            filter: String::new(),
            view: View::Entries,
        };
        app.filter = "push".into();
        app.refilter();
        assert_eq!(app.filtered.len(), 1);
    }

    #[test]
    fn toggle_view() {
        let entries = sample_entries();
        let log_dir = PathBuf::from("/tmp/nonexistent");
        let mut app = App {
            log_dir,
            all_entries: entries,
            filtered: vec![2, 1, 0],
            summaries: vec![],
            table_state: TableState::default(),
            filter: String::new(),
            view: View::Entries,
        };
        assert_eq!(app.view, View::Entries);
        app.toggle_view();
        assert_eq!(app.view, View::Summary);
        app.toggle_view();
        assert_eq!(app.view, View::Entries);
    }
}
