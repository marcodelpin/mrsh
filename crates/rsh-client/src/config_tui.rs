//! Interactive config editor TUI — ratatui + crossterm.
//!
//! Entry point: [`run_config_tui`].

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
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use rsh_core::config::{Config, HostConfig};

// ── Screen states ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    List,
    Edit,
    Global,
    Confirm,
}

// ── Confirm actions ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfirmAction {
    Quit,
    Delete,
}

// ── Host-edit field indices ────────────────────────────────────

const HOST_LABELS: &[&str] = &[
    "Pattern",
    "Hostname",
    "Port",
    "IdentityFile",
    "User",
    "Description",
    "MAC",
    "DeviceID",
    "TailscaleIP",
    "RendezvousServer",
    "RendezvousServers",
    "RendezvousKey",
    "SessionLog",
];

const HOST_PLACEHOLDERS: &[&str] = &[
    "my-server or 192.168.*",
    "192.168.1.100",
    "8822",
    "~/.ssh/id_ed25519",
    "",
    "Development GPU workstation",
    "70:4d:7b:2c:7e:41",
    "118855822",
    "100.124.180.114",
    "hbbs.example.com:21116",
    "server1:21116, server2:21116",
    "BASE64KEY==",
    "inherit / true / false",
];

// ── Global-settings field indices ──────────────────────────────

const GLOBAL_LABELS: &[&str] = &[
    "DeviceID",
    "RendezvousServer",
    "RendezvousServers",
    "RendezvousKey",
    "SessionLog",
    "SessionLogRetain",
];

const GLOBAL_PLACEHOLDERS: &[&str] = &[
    "auto-generated or custom ID",
    "hbbs.example.com:21116",
    "server1:21116, server2:21116",
    "BASE64KEY==",
    "true / false (default: true)",
    "90 (days)",
];

// ── Application state ──────────────────────────────────────────

struct App {
    cfg: Config,
    screen: Screen,
    // List state
    list_state: ListState,
    // Form state
    inputs: Vec<String>,
    focus: usize,
    cursor_pos: usize, // cursor position within focused input
    edit_idx: isize,    // -1 = new, >= 0 = editing existing host
    // Confirm overlay
    confirm_action: ConfirmAction,
    confirm_msg: String,
    delete_idx: usize,
    // Status
    dirty: bool,
    saved: bool,
    error: Option<String>,
}

impl App {
    fn new(cfg: Config) -> Self {
        let mut list_state = ListState::default();
        if !cfg.hosts.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            cfg,
            screen: Screen::List,
            list_state,
            inputs: Vec::new(),
            focus: 0,
            cursor_pos: 0,
            edit_idx: -1,
            confirm_action: ConfirmAction::Quit,
            confirm_msg: String::new(),
            delete_idx: 0,
            dirty: false,
            saved: false,
            error: None,
        }
    }

    fn selected_index(&self) -> Option<usize> {
        self.list_state.selected()
    }

    // ── List screen helpers ────────────────────────────────────

    fn list_next(&mut self) {
        if self.cfg.hosts.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(i) => (i + 1) % self.cfg.hosts.len(),
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn list_prev(&mut self) {
        if self.cfg.hosts.is_empty() {
            return;
        }
        let i = match self.list_state.selected() {
            Some(0) | None => self.cfg.hosts.len() - 1,
            Some(i) => i - 1,
        };
        self.list_state.select(Some(i));
    }

    // ── Enter edit screen ──────────────────────────────────────

    fn enter_add(&mut self) {
        self.edit_idx = -1;
        self.inputs = vec![String::new(); HOST_LABELS.len()];
        self.focus = 0;
        self.cursor_pos = 0;
        self.screen = Screen::Edit;
    }

    fn enter_edit(&mut self) {
        let Some(idx) = self.selected_index() else {
            return;
        };
        if idx >= self.cfg.hosts.len() {
            return;
        }
        self.edit_idx = idx as isize;
        let h = &self.cfg.hosts[idx];
        self.inputs = vec![
            h.pattern.clone(),
            h.hostname.clone().unwrap_or_default(),
            if h.port > 0 {
                h.port.to_string()
            } else {
                String::new()
            },
            h.identity_file.clone().unwrap_or_default(),
            h.user.clone().unwrap_or_default(),
            h.description.clone().unwrap_or_default(),
            h.mac.clone().unwrap_or_default(),
            h.device_id.clone().unwrap_or_default(),
            h.tailscale_ip.clone().unwrap_or_default(),
            h.rendezvous_server.clone().unwrap_or_default(),
            h.rendezvous_servers.join(", "),
            h.rendezvous_key.clone().unwrap_or_default(),
            match h.session_log {
                Some(true) => "true".to_string(),
                Some(false) => "false".to_string(),
                None => String::new(),
            },
        ];
        self.focus = 0;
        self.cursor_pos = self.inputs[0].len();
        self.screen = Screen::Edit;
    }

    fn enter_global(&mut self) {
        self.inputs = vec![
            self.cfg.device_id.clone().unwrap_or_default(),
            self.cfg.rendezvous_server.clone().unwrap_or_default(),
            self.cfg.rendezvous_servers.join(", "),
            self.cfg.rendezvous_key.clone().unwrap_or_default(),
            if self.cfg.session_log {
                "true".to_string()
            } else {
                "false".to_string()
            },
            self.cfg.session_log_retain.to_string(),
        ];
        self.focus = 0;
        self.cursor_pos = self.inputs[0].len();
        self.screen = Screen::Global;
    }

    // ── Apply form ─────────────────────────────────────────────

    fn apply_form(&mut self) {
        if self.screen == Screen::Global {
            self.cfg.device_id = opt_str(&self.inputs[0]);
            self.cfg.rendezvous_server = opt_str(&self.inputs[1]);
            self.cfg.rendezvous_servers = split_servers(&self.inputs[2]);
            self.cfg.rendezvous_key = opt_str(&self.inputs[3]);
            self.cfg.session_log = parse_bool_default(&self.inputs[4], true);
            if let Ok(days) = self.inputs[5].trim().parse::<u32>() {
                if days > 0 {
                    self.cfg.session_log_retain = days;
                }
            }
            self.dirty = true;
            return;
        }

        let pattern = self.inputs[0].trim().to_string();
        if pattern.is_empty() {
            return;
        }

        let port = parse_port(&self.inputs[2]);
        let h = HostConfig {
            pattern,
            hostname: opt_str(&self.inputs[1]),
            port,
            identity_file: opt_str(&self.inputs[3]),
            user: opt_str(&self.inputs[4]),
            description: opt_str(&self.inputs[5]),
            mac: opt_str(&self.inputs[6]),
            device_id: opt_str(&self.inputs[7]),
            tailscale_ip: opt_str(&self.inputs[8]),
            rendezvous_server: opt_str(&self.inputs[9]),
            rendezvous_servers: split_servers(&self.inputs[10]),
            rendezvous_key: opt_str(&self.inputs[11]),
            session_log: parse_opt_bool(&self.inputs[12]),
            quic_port: None,
        };

        let idx = self.edit_idx;
        if idx >= 0 && (idx as usize) < self.cfg.hosts.len() {
            self.cfg.hosts[idx as usize] = h;
        } else {
            self.cfg.hosts.push(h);
            // Select the newly added item
            self.list_state.select(Some(self.cfg.hosts.len() - 1));
        }
        self.dirty = true;
    }

    // ── Save config file ───────────────────────────────────────

    fn save_config(&mut self) {
        match self.cfg.save() {
            Ok(()) => {
                self.dirty = false;
                self.saved = true;
                self.error = None;
            }
            Err(e) => {
                self.error = Some(format!("{}", e));
            }
        }
    }

    // ── Delete host ────────────────────────────────────────────

    fn delete_host(&mut self) {
        if self.delete_idx < self.cfg.hosts.len() {
            self.cfg.hosts.remove(self.delete_idx);
            self.dirty = true;
            // Fix selection
            if self.cfg.hosts.is_empty() {
                self.list_state.select(None);
            } else if self.delete_idx >= self.cfg.hosts.len() {
                self.list_state.select(Some(self.cfg.hosts.len() - 1));
            }
        }
    }

    // ── Form navigation ────────────────────────────────────────

    fn field_count(&self) -> usize {
        self.inputs.len()
    }

    fn focus_next(&mut self) {
        let count = self.field_count();
        if count == 0 {
            return;
        }
        self.focus = (self.focus + 1) % count;
        self.cursor_pos = self.inputs[self.focus].len();
    }

    fn focus_prev(&mut self) {
        let count = self.field_count();
        if count == 0 {
            return;
        }
        self.focus = (self.focus + count - 1) % count;
        self.cursor_pos = self.inputs[self.focus].len();
    }

    // ── Input editing ──────────────────────────────────────────

    fn input_char(&mut self, c: char) {
        if self.focus < self.inputs.len() {
            let pos = self.cursor_pos.min(self.inputs[self.focus].len());
            self.inputs[self.focus].insert(pos, c);
            self.cursor_pos = pos + c.len_utf8();
        }
    }

    fn input_backspace(&mut self) {
        if self.focus < self.inputs.len() && self.cursor_pos > 0 {
            let input = &mut self.inputs[self.focus];
            let pos = self.cursor_pos.min(input.len());
            if pos > 0 {
                // Find the char boundary before cursor_pos
                let prev = input[..pos]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                input.remove(prev);
                self.cursor_pos = prev;
            }
        }
    }

    fn input_delete(&mut self) {
        if self.focus < self.inputs.len() {
            let input = &mut self.inputs[self.focus];
            let pos = self.cursor_pos.min(input.len());
            if pos < input.len() {
                input.remove(pos);
            }
        }
    }

    fn cursor_left(&mut self) {
        if self.cursor_pos > 0 {
            let input = &self.inputs[self.focus];
            self.cursor_pos = input[..self.cursor_pos]
                .char_indices()
                .next_back()
                .map(|(i, _)| i)
                .unwrap_or(0);
        }
    }

    fn cursor_right(&mut self) {
        if self.focus < self.inputs.len() {
            let input = &self.inputs[self.focus];
            if self.cursor_pos < input.len() {
                self.cursor_pos = input[self.cursor_pos..]
                    .char_indices()
                    .nth(1)
                    .map(|(i, _)| self.cursor_pos + i)
                    .unwrap_or(input.len());
            }
        }
    }

    fn cursor_home(&mut self) {
        self.cursor_pos = 0;
    }

    fn cursor_end(&mut self) {
        if self.focus < self.inputs.len() {
            self.cursor_pos = self.inputs[self.focus].len();
        }
    }
}

// ── Helper functions ───────────────────────────────────────────

/// Return Some(trimmed) if non-empty, None otherwise.
fn opt_str(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Split comma/space-separated server list.
pub fn split_servers(s: &str) -> Vec<String> {
    if s.trim().is_empty() {
        return Vec::new();
    }
    s.split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect()
}

/// Parse port string; returns 8822 on empty or invalid.
pub fn parse_port(s: &str) -> u16 {
    let s = s.trim();
    if s.is_empty() {
        return 8822;
    }
    s.parse::<u16>().unwrap_or(8822)
}

/// Parse a bool with a default value.
fn parse_bool_default(s: &str, default: bool) -> bool {
    match s.trim().to_lowercase().as_str() {
        "true" | "yes" | "1" => true,
        "false" | "no" | "0" => false,
        _ => default,
    }
}

/// Parse an optional bool (empty = None = inherit).
fn parse_opt_bool(s: &str) -> Option<bool> {
    match s.trim().to_lowercase().as_str() {
        "true" | "yes" | "1" => Some(true),
        "false" | "no" | "0" => Some(false),
        _ => None,
    }
}

/// Format a host's description line for the list view.
/// Shows hostname:port, description, and tailscale IP when available.
fn host_description(h: &HostConfig) -> String {
    let addr = match &h.hostname {
        Some(name) if !name.is_empty() => {
            if h.port != 0 && h.port != 8822 {
                format!("{}:{}", name, h.port)
            } else {
                name.clone()
            }
        }
        _ => "(no hostname)".to_string(),
    };

    let mut parts = vec![addr];

    if let Some(ref ts) = h.tailscale_ip {
        parts.push(format!("ts:{}", ts));
    }

    if let Some(ref desc) = h.description {
        parts.push(format!("— {}", desc));
    }

    parts.join("  ")
}

// ── Styles ─────────────────────────────────────────────────────

const TITLE_COLOR: Color = Color::Rgb(170, 85, 255); // ~ansi 170
const HELP_COLOR: Color = Color::DarkGray;
const ERROR_COLOR: Color = Color::Red;
const SAVED_COLOR: Color = Color::Green;
const SELECTED_BG: Color = Color::Rgb(50, 50, 80);

// ── Drawing ────────────────────────────────────────────────────

fn draw(frame: &mut Frame, app: &mut App) {
    match app.screen {
        Screen::List => draw_list(frame, app),
        Screen::Edit => draw_form(frame, app, HOST_LABELS, HOST_PLACEHOLDERS, "Edit Host"),
        Screen::Global => {
            draw_form(frame, app, GLOBAL_LABELS, GLOBAL_PLACEHOLDERS, "Global Settings")
        }
        Screen::Confirm => {
            // Draw list in background, then overlay the confirm dialog
            draw_list(frame, app);
            draw_confirm(frame, app);
        }
    }
}

fn draw_list(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let chunks = Layout::vertical([
        Constraint::Min(3),    // list
        Constraint::Length(1), // status
        Constraint::Length(1), // help
    ])
    .split(area);

    // Build list items
    let items: Vec<ListItem> = app
        .cfg
        .hosts
        .iter()
        .map(|h| {
            let desc = host_description(h);
            ListItem::new(vec![
                Line::from(Span::styled(
                    &h.pattern,
                    Style::default().add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    format!("  {}", desc),
                    Style::default().fg(Color::DarkGray),
                )),
            ])
        })
        .collect();

    let title = format!(
        " rsh hosts ({}) ",
        app.cfg.hosts.len()
    );

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .title_style(Style::default().fg(TITLE_COLOR).add_modifier(Modifier::BOLD)),
        )
        .highlight_style(Style::default().bg(SELECTED_BG).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    frame.render_stateful_widget(list, chunks[0], &mut app.list_state);

    // Status line
    let status_line = if let Some(ref e) = app.error {
        Span::styled(format!(" error: {}", e), Style::default().fg(ERROR_COLOR))
    } else if app.saved {
        Span::styled(" saved", Style::default().fg(SAVED_COLOR))
    } else if app.dirty {
        Span::styled(" [modified]", Style::default().fg(HELP_COLOR))
    } else {
        Span::raw("")
    };
    frame.render_widget(Paragraph::new(Line::from(status_line)), chunks[1]);

    // Help line
    let help = Span::styled(
        " a:add  e/enter:edit  d:delete  g:global  s:save  q:quit",
        Style::default().fg(HELP_COLOR),
    );
    frame.render_widget(Paragraph::new(Line::from(help)), chunks[2]);
}

fn draw_form(
    frame: &mut Frame,
    app: &App,
    labels: &[&str],
    placeholders: &[&str],
    screen_title: &str,
) {
    let area = frame.area();
    let field_count = labels.len();

    // Title + fields + blank + help
    let mut constraints = vec![Constraint::Length(2)]; // title
    for _ in 0..field_count {
        constraints.push(Constraint::Length(1)); // each field row
    }
    constraints.push(Constraint::Length(1)); // blank
    constraints.push(Constraint::Length(1)); // help
    constraints.push(Constraint::Min(0)); // remaining space

    let chunks = Layout::vertical(constraints).split(area);

    // Title
    let title_text = if app.screen == Screen::Edit && app.edit_idx >= 0 {
        let idx = app.edit_idx as usize;
        if idx < app.cfg.hosts.len() {
            format!("Edit: {}", app.cfg.hosts[idx].pattern)
        } else {
            "New Host".to_string()
        }
    } else if app.screen == Screen::Edit {
        "New Host".to_string()
    } else {
        screen_title.to_string()
    };
    let title = Paragraph::new(Line::from(Span::styled(
        title_text,
        Style::default()
            .fg(TITLE_COLOR)
            .add_modifier(Modifier::BOLD),
    )));
    frame.render_widget(title, chunks[0]);

    // Fields
    for i in 0..field_count {
        let label_style = if i == app.focus {
            Style::default()
                .fg(TITLE_COLOR)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(HELP_COLOR)
        };

        let label = format!("  {:<20}", format!("{}:", labels[i]));
        let value = if i < app.inputs.len() {
            &app.inputs[i]
        } else {
            ""
        };

        let display_value = if value.is_empty() && i != app.focus {
            Span::styled(placeholders[i], Style::default().fg(Color::DarkGray))
        } else {
            Span::raw(value)
        };

        let line = Line::from(vec![Span::styled(label, label_style), display_value]);

        frame.render_widget(Paragraph::new(line), chunks[i + 1]);

        // Position cursor on focused field
        if i == app.focus {
            let x = chunks[i + 1].x + 22 + app.cursor_pos as u16;
            let y = chunks[i + 1].y;
            frame.set_cursor_position((x, y));
        }
    }

    // Help
    let help_idx = field_count + 2; // title + fields + blank
    let help = Span::styled(
        " tab:next  shift+tab:prev  ctrl+s/enter(last):save  esc:cancel",
        Style::default().fg(HELP_COLOR),
    );
    frame.render_widget(Paragraph::new(Line::from(help)), chunks[help_idx]);
}

fn draw_confirm(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Center the confirm dialog
    let dialog_width = (app.confirm_msg.len() as u16 + 6).min(area.width);
    let dialog_height = 3;
    let x = area.x + (area.width.saturating_sub(dialog_width)) / 2;
    let y = area.y + (area.height.saturating_sub(dialog_height)) / 2;
    let dialog_area = Rect::new(x, y, dialog_width, dialog_height);

    frame.render_widget(Clear, dialog_area);

    let dialog = Paragraph::new(Line::from(Span::styled(
        &app.confirm_msg,
        Style::default()
            .fg(TITLE_COLOR)
            .add_modifier(Modifier::BOLD),
    )))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(TITLE_COLOR)),
    );

    frame.render_widget(dialog, dialog_area);
}

// ── Event handling ─────────────────────────────────────────────

/// Returns true if the app should quit.
fn handle_event(app: &mut App) -> io::Result<bool> {
    if !event::poll(std::time::Duration::from_millis(100))? {
        return Ok(false);
    }
    let ev = event::read()?;

    // Handle resize for all screens
    if let Event::Resize(_, _) = ev {
        return Ok(false); // ratatui handles resize automatically
    }

    let Event::Key(key) = ev else {
        return Ok(false);
    };

    // Only handle Press events (ignore Release, Repeat on some platforms)
    if key.kind != KeyEventKind::Press {
        return Ok(false);
    }

    match app.screen {
        Screen::List => handle_list(app, key.code, key.modifiers),
        Screen::Edit | Screen::Global => handle_form(app, key.code, key.modifiers),
        Screen::Confirm => handle_confirm(app, key.code),
    }
}

fn handle_list(app: &mut App, code: KeyCode, mods: KeyModifiers) -> io::Result<bool> {
    app.saved = false;
    match (code, mods) {
        (KeyCode::Char('q'), KeyModifiers::NONE) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
            if app.dirty {
                app.confirm_action = ConfirmAction::Quit;
                app.confirm_msg = "Unsaved changes. Quit anyway? (y/n)".to_string();
                app.screen = Screen::Confirm;
                Ok(false)
            } else {
                Ok(true)
            }
        }

        (KeyCode::Char('j') | KeyCode::Down, KeyModifiers::NONE) => {
            app.list_next();
            Ok(false)
        }
        (KeyCode::Char('k') | KeyCode::Up, KeyModifiers::NONE) => {
            app.list_prev();
            Ok(false)
        }

        (KeyCode::Char('a'), KeyModifiers::NONE) => {
            app.enter_add();
            Ok(false)
        }

        (KeyCode::Char('e'), KeyModifiers::NONE) | (KeyCode::Enter, _) => {
            if !app.cfg.hosts.is_empty() {
                app.enter_edit();
            }
            Ok(false)
        }

        (KeyCode::Char('d'), KeyModifiers::NONE) => {
            if !app.cfg.hosts.is_empty() {
                if let Some(idx) = app.selected_index() {
                    app.delete_idx = idx;
                    app.confirm_action = ConfirmAction::Delete;
                    app.confirm_msg =
                        format!("Delete {:?}? (y/n)", app.cfg.hosts[idx].pattern);
                    app.screen = Screen::Confirm;
                }
            }
            Ok(false)
        }

        (KeyCode::Char('g'), KeyModifiers::NONE) => {
            app.enter_global();
            Ok(false)
        }

        (KeyCode::Char('s'), KeyModifiers::NONE) => {
            app.save_config();
            Ok(false)
        }

        _ => Ok(false),
    }
}

fn handle_form(app: &mut App, code: KeyCode, mods: KeyModifiers) -> io::Result<bool> {
    match (code, mods) {
        (KeyCode::Char('c'), KeyModifiers::CONTROL) => Ok(true),

        (KeyCode::Esc, _) => {
            app.screen = Screen::List;
            Ok(false)
        }

        (KeyCode::Tab, KeyModifiers::NONE) | (KeyCode::Down, KeyModifiers::NONE) => {
            app.focus_next();
            Ok(false)
        }

        (KeyCode::BackTab, _) | (KeyCode::Up, KeyModifiers::NONE) => {
            app.focus_prev();
            Ok(false)
        }

        (KeyCode::Char('s'), KeyModifiers::CONTROL) => {
            app.apply_form();
            app.screen = Screen::List;
            Ok(false)
        }

        (KeyCode::Enter, _) => {
            if app.focus == app.field_count() - 1 {
                // Last field — save and return to list
                app.apply_form();
                app.screen = Screen::List;
            } else {
                app.focus_next();
            }
            Ok(false)
        }

        (KeyCode::Char(c), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
            app.input_char(c);
            Ok(false)
        }

        (KeyCode::Backspace, _) => {
            app.input_backspace();
            Ok(false)
        }

        (KeyCode::Delete, _) => {
            app.input_delete();
            Ok(false)
        }

        (KeyCode::Left, KeyModifiers::NONE) => {
            app.cursor_left();
            Ok(false)
        }

        (KeyCode::Right, KeyModifiers::NONE) => {
            app.cursor_right();
            Ok(false)
        }

        (KeyCode::Home, _) => {
            app.cursor_home();
            Ok(false)
        }

        (KeyCode::End, _) => {
            app.cursor_end();
            Ok(false)
        }

        _ => Ok(false),
    }
}

fn handle_confirm(app: &mut App, code: KeyCode) -> io::Result<bool> {
    match code {
        KeyCode::Char('y' | 'Y') => match app.confirm_action {
            ConfirmAction::Quit => Ok(true),
            ConfirmAction::Delete => {
                app.delete_host();
                app.screen = Screen::List;
                Ok(false)
            }
        },
        KeyCode::Char('n' | 'N') | KeyCode::Esc => {
            app.screen = Screen::List;
            Ok(false)
        }
        _ => Ok(false),
    }
}

// ── Entry point ────────────────────────────────────────────────

/// Run the interactive config editor TUI.
///
/// Loads `~/.rsh/config`, shows hosts in a navigable list,
/// and allows add/edit/delete/global-settings/save operations.
pub fn run_config_tui() -> io::Result<()> {
    let cfg = Config::load();

    // Setup terminal
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(cfg);

    // Main loop
    let result = loop {
        terminal.draw(|f| draw(f, &mut app))?;
        match handle_event(&mut app) {
            Ok(true) => break Ok(()),
            Ok(false) => {}
            Err(e) => break Err(e),
        }
    };

    // Restore terminal
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;

    result
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_port_valid() {
        assert_eq!(parse_port("8822"), 8822);
        assert_eq!(parse_port("22"), 22);
        assert_eq!(parse_port("9822"), 9822);
        assert_eq!(parse_port(" 443 "), 443);
    }

    #[test]
    fn parse_port_empty() {
        assert_eq!(parse_port(""), 8822);
        assert_eq!(parse_port("  "), 8822);
    }

    #[test]
    fn parse_port_invalid() {
        assert_eq!(parse_port("abc"), 8822);
        assert_eq!(parse_port("99999"), 8822); // overflows u16
        assert_eq!(parse_port("-1"), 8822);
    }

    #[test]
    fn split_servers_basic() {
        let result = split_servers("a:21116, b:21116, c:21116");
        assert_eq!(result, vec!["a:21116", "b:21116", "c:21116"]);
    }

    #[test]
    fn split_servers_empty() {
        assert!(split_servers("").is_empty());
        assert!(split_servers("   ").is_empty());
    }

    #[test]
    fn split_servers_single() {
        assert_eq!(split_servers("host:21116"), vec!["host:21116"]);
    }

    #[test]
    fn split_servers_extra_commas() {
        let result = split_servers(",a:21116,,b:21116,");
        assert_eq!(result, vec!["a:21116", "b:21116"]);
    }

    #[test]
    fn opt_str_non_empty() {
        assert_eq!(opt_str("hello"), Some("hello".to_string()));
        assert_eq!(opt_str("  hello  "), Some("hello".to_string()));
    }

    #[test]
    fn opt_str_empty() {
        assert_eq!(opt_str(""), None);
        assert_eq!(opt_str("   "), None);
    }

    #[test]
    fn host_description_with_hostname() {
        let h = HostConfig {
            pattern: "test".to_string(),
            hostname: Some("example.com".to_string()),
            port: 8822,
            identity_file: None,
            user: None,
            mac: None,
            device_id: None,
            description: None,
            tailscale_ip: None,
            rendezvous_server: None,
            rendezvous_servers: vec![],
            rendezvous_key: None,
            session_log: None,
            quic_port: None,
        };
        assert_eq!(host_description(&h), "example.com");
    }

    #[test]
    fn host_description_with_custom_port() {
        let h = HostConfig {
            pattern: "test".to_string(),
            hostname: Some("example.com".to_string()),
            port: 22,
            identity_file: None,
            user: None,
            mac: None,
            device_id: None,
            description: None,
            tailscale_ip: None,
            rendezvous_server: None,
            rendezvous_servers: vec![],
            rendezvous_key: None,
            session_log: None,
            quic_port: None,
        };
        assert_eq!(host_description(&h), "example.com:22");
    }

    #[test]
    fn host_description_no_hostname() {
        let h = HostConfig {
            pattern: "test".to_string(),
            hostname: None,
            port: 8822,
            identity_file: None,
            user: None,
            mac: None,
            device_id: None,
            description: None,
            tailscale_ip: None,
            rendezvous_server: None,
            rendezvous_servers: vec![],
            rendezvous_key: None,
            session_log: None,
            quic_port: None,
        };
        assert_eq!(host_description(&h), "(no hostname)");
    }

    #[test]
    fn host_description_with_extras() {
        let h = HostConfig {
            pattern: "gpu".to_string(),
            hostname: Some("dev-server".to_string()),
            port: 8822,
            identity_file: None,
            user: None,
            mac: None,
            device_id: None,
            description: Some("Dev GPU workstation".to_string()),
            tailscale_ip: Some("100.1.2.3".to_string()),
            rendezvous_server: None,
            rendezvous_servers: vec![],
            rendezvous_key: None,
            session_log: None,
            quic_port: None,
        };
        let desc = host_description(&h);
        assert!(desc.contains("dev-server"));
        assert!(desc.contains("ts:100.1.2.3"));
        assert!(desc.contains("Dev GPU workstation"));
    }

    #[test]
    fn config_round_trip() {
        let input = "\
RendezvousServer rdv.example.com:21116
RendezvousKey TESTKEY==

Host my-server
    Hostname 192.168.1.100
    Port 8822

Host test-*
    Hostname 10.0.0.1
    Port 22
    User admin
";
        let cfg = Config::parse(input);
        assert_eq!(cfg.hosts.len(), 2);
        let output = cfg.to_string();
        let cfg2 = Config::parse(&output);
        assert_eq!(cfg2.hosts.len(), 2);
        assert_eq!(cfg2.hosts[0].pattern, "my-server");
        assert_eq!(cfg2.hosts[1].pattern, "test-*");
        assert_eq!(
            cfg2.rendezvous_server.as_deref(),
            Some("rdv.example.com:21116")
        );
        assert_eq!(cfg2.rendezvous_key.as_deref(), Some("TESTKEY=="));
    }

    #[test]
    fn app_list_navigation() {
        let cfg = Config::parse(
            "Host a\n    Hostname a.com\nHost b\n    Hostname b.com\nHost c\n    Hostname c.com\n",
        );
        let mut app = App::new(cfg);
        assert_eq!(app.selected_index(), Some(0));

        app.list_next();
        assert_eq!(app.selected_index(), Some(1));

        app.list_next();
        assert_eq!(app.selected_index(), Some(2));

        // Wrap around
        app.list_next();
        assert_eq!(app.selected_index(), Some(0));

        app.list_prev();
        assert_eq!(app.selected_index(), Some(2));
    }

    #[test]
    fn app_add_host() {
        let cfg = Config::parse("");
        let mut app = App::new(cfg);
        assert_eq!(app.cfg.hosts.len(), 0);

        app.enter_add();
        assert_eq!(app.screen, Screen::Edit);
        assert_eq!(app.edit_idx, -1);

        app.inputs[0] = "new-host".to_string();
        app.inputs[1] = "192.168.1.50".to_string();
        app.inputs[2] = "9822".to_string();
        app.apply_form();

        assert_eq!(app.cfg.hosts.len(), 1);
        assert_eq!(app.cfg.hosts[0].pattern, "new-host");
        assert_eq!(
            app.cfg.hosts[0].hostname.as_deref(),
            Some("192.168.1.50")
        );
        assert_eq!(app.cfg.hosts[0].port, 9822);
        assert!(app.dirty);
    }

    #[test]
    fn app_edit_host() {
        let cfg = Config::parse("Host existing\n    Hostname old.com\n    Port 22\n");
        let mut app = App::new(cfg);

        app.enter_edit();
        assert_eq!(app.screen, Screen::Edit);
        assert_eq!(app.edit_idx, 0);
        assert_eq!(app.inputs[0], "existing");
        assert_eq!(app.inputs[1], "old.com");
        assert_eq!(app.inputs[2], "22");

        app.inputs[1] = "new.com".to_string();
        app.apply_form();

        assert_eq!(app.cfg.hosts[0].hostname.as_deref(), Some("new.com"));
        assert!(app.dirty);
    }

    #[test]
    fn app_delete_host() {
        let cfg = Config::parse("Host a\n    Hostname a.com\nHost b\n    Hostname b.com\n");
        let mut app = App::new(cfg);
        assert_eq!(app.cfg.hosts.len(), 2);

        app.delete_idx = 0;
        app.delete_host();

        assert_eq!(app.cfg.hosts.len(), 1);
        assert_eq!(app.cfg.hosts[0].pattern, "b");
        assert!(app.dirty);
    }

    #[test]
    fn app_global_settings() {
        let cfg = Config::parse("RendezvousServer old.server:21116\n");
        let mut app = App::new(cfg);

        app.enter_global();
        assert_eq!(app.screen, Screen::Global);
        assert_eq!(app.inputs[1], "old.server:21116");

        app.inputs[0] = "my-device-id".to_string();
        app.inputs[1] = "new.server:21116".to_string();
        app.apply_form();

        assert_eq!(
            app.cfg.device_id.as_deref(),
            Some("my-device-id")
        );
        assert_eq!(
            app.cfg.rendezvous_server.as_deref(),
            Some("new.server:21116")
        );
        assert!(app.dirty);
    }

    #[test]
    fn app_input_editing() {
        let cfg = Config::parse("");
        let mut app = App::new(cfg);
        app.enter_add();

        // Type "hello"
        for c in "hello".chars() {
            app.input_char(c);
        }
        assert_eq!(app.inputs[0], "hello");
        assert_eq!(app.cursor_pos, 5);

        // Backspace
        app.input_backspace();
        assert_eq!(app.inputs[0], "hell");
        assert_eq!(app.cursor_pos, 4);

        // Move cursor left
        app.cursor_left();
        app.cursor_left();
        assert_eq!(app.cursor_pos, 2);

        // Insert 'X' at cursor
        app.input_char('X');
        assert_eq!(app.inputs[0], "heXll");
        assert_eq!(app.cursor_pos, 3);

        // Delete at cursor
        app.input_delete();
        assert_eq!(app.inputs[0], "heXl");

        // Home / End
        app.cursor_home();
        assert_eq!(app.cursor_pos, 0);
        app.cursor_end();
        assert_eq!(app.cursor_pos, 4);
    }
}
