//! Interactive TUI file browser for remote hosts.
//!
//! Navigate with arrow keys / hjkl, Enter to open dirs,
//! Backspace to go up, 'd' to download, 'q' to quit.

use std::io::{self, Write};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    terminal,
};
use mrsh_core::protocol::FileInfo;

// ── Public API ──────────────────────────────────────────────────

/// Run the interactive file browser on the remote host.
/// `fetch_dir` returns the directory listing for the given path.
/// `download` handles pulling a remote file to local.
pub fn run_browser<F, D>(start_path: &str, mut fetch_dir: F, mut download: D)
where
    F: FnMut(&str) -> Result<Vec<FileInfo>, String>,
    D: FnMut(&str, &str),
{
    let start = if start_path.is_empty() {
        ".".to_string()
    } else {
        start_path.to_string()
    };

    if !atty::is(atty::Stream::Stdin) {
        eprintln!("browse requires a terminal");
        return;
    }

    if terminal::enable_raw_mode().is_err() {
        eprintln!("Cannot set raw terminal mode");
        return;
    }

    let mut current_path = start;
    let mut cursor: usize = 0;
    let mut offset: usize = 0;

    let result = browse_loop(
        &mut current_path,
        &mut cursor,
        &mut offset,
        &mut fetch_dir,
        &mut download,
    );

    let _ = terminal::disable_raw_mode();

    if let Err(e) = result {
        eprintln!("browse error: {}", e);
    }
}

fn browse_loop<F, D>(
    current_path: &mut String,
    cursor: &mut usize,
    offset: &mut usize,
    fetch_dir: &mut F,
    download: &mut D,
) -> io::Result<()>
where
    F: FnMut(&str) -> Result<Vec<FileInfo>, String>,
    D: FnMut(&str, &str),
{
    loop {
        // Fetch directory listing
        let files = match fetch_dir(current_path) {
            Ok(f) => f,
            Err(msg) => {
                draw_error(&msg);
                wait_key();
                *current_path = parent_path(current_path);
                *cursor = 0;
                *offset = 0;
                continue;
            }
        };

        // Terminal size
        let (w, h) = terminal::size().unwrap_or((80, 25));
        let w = w as usize;
        let h = h as usize;
        let list_height = h.saturating_sub(3).max(1);

        // Clamp cursor
        if files.is_empty() {
            *cursor = 0;
        } else if *cursor >= files.len() {
            *cursor = files.len() - 1;
        }

        // Scroll
        if *offset > *cursor {
            *offset = *cursor;
        }
        if *cursor >= *offset + list_height {
            *offset = *cursor - list_height + 1;
        }

        draw_browser(w, h, current_path, &files, *cursor, *offset, list_height);

        match wait_key() {
            Key::Up => *cursor = cursor.saturating_sub(1),
            Key::Down => {
                if !files.is_empty() && *cursor < files.len() - 1 {
                    *cursor += 1;
                }
            }
            Key::Enter | Key::Right => {
                if *cursor < files.len() && files[*cursor].is_dir {
                    *current_path = join_path(current_path, &files[*cursor].name);
                    *cursor = 0;
                    *offset = 0;
                }
            }
            Key::Back | Key::Left => {
                *current_path = parent_path(current_path);
                *cursor = 0;
                *offset = 0;
            }
            Key::Quit => {
                print!("\x1b[2J\x1b[H");
                let _ = io::stdout().flush();
                return Ok(());
            }
            Key::Home => *cursor = 0,
            Key::End => {
                if !files.is_empty() {
                    *cursor = files.len() - 1;
                }
            }
            Key::PageUp => *cursor = cursor.saturating_sub(list_height),
            Key::PageDown => {
                if !files.is_empty() {
                    *cursor = (*cursor + list_height).min(files.len() - 1);
                }
            }
            Key::Download => {
                if *cursor < files.len() && !files[*cursor].is_dir {
                    let remote = join_path(current_path, &files[*cursor].name);
                    let local = files[*cursor].name.clone();
                    let _ = terminal::disable_raw_mode();
                    print!("\r\nDownloading {} -> {}...\r\n", remote, local);
                    let _ = io::stdout().flush();
                    download(&remote, &local);
                    print!("Press any key to continue...\r\n");
                    let _ = io::stdout().flush();
                    let _ = terminal::enable_raw_mode();
                    wait_key();
                }
            }
            Key::Other => {}
        }
    }
}

// ── Key abstraction ─────────────────────────────────────────────

enum Key {
    Up,
    Down,
    Left,
    Right,
    Enter,
    Back,
    Quit,
    Home,
    End,
    PageUp,
    PageDown,
    Download,
    Other,
}

fn wait_key() -> Key {
    loop {
        if let Ok(Event::Key(KeyEvent {
            code, modifiers, ..
        })) = event::read()
        {
            if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
                return Key::Quit;
            }
            return match code {
                KeyCode::Up | KeyCode::Char('k') => Key::Up,
                KeyCode::Down | KeyCode::Char('j') => Key::Down,
                KeyCode::Left | KeyCode::Char('h') => Key::Left,
                KeyCode::Right | KeyCode::Char('l') => Key::Right,
                KeyCode::Enter => Key::Enter,
                KeyCode::Backspace => Key::Back,
                KeyCode::Char('q') | KeyCode::Esc => Key::Quit,
                KeyCode::Home => Key::Home,
                KeyCode::End => Key::End,
                KeyCode::PageUp => Key::PageUp,
                KeyCode::PageDown => Key::PageDown,
                KeyCode::Char('d') => Key::Download,
                _ => Key::Other,
            };
        }
    }
}

// ── Drawing ─────────────────────────────────────────────────────

fn draw_browser(
    w: usize,
    _h: usize,
    path: &str,
    files: &[FileInfo],
    cursor: usize,
    offset: usize,
    list_height: usize,
) {
    print!("\x1b[2J\x1b[H");

    // Header (reverse video)
    let header = format!(" Remote: {} ", path);
    let header = truncate_str(&header, w);
    print!("\x1b[7m{:<width$}\x1b[0m\r\n", header, width = w);

    // File list
    let end = (offset + list_height).min(files.len());
    for (i, f) in files.iter().enumerate().skip(offset).take(list_height) {
        let prefix = if i == cursor { "> " } else { "  " };

        let mut name = f.name.clone();
        if f.is_dir {
            name.push('/');
        }

        let size = format_size(f.size);
        let mod_time = if f.mod_time.len() >= 16 {
            &f.mod_time[..16]
        } else {
            &f.mod_time
        };

        let name_width = w.saturating_sub(30);
        let line = format!(
            "{}{:<nw$} {:>8}  {}",
            prefix,
            truncate_str(&name, name_width),
            size,
            mod_time,
            nw = name_width
        );
        let line = truncate_str(&line, w);

        if i == cursor {
            print!("\x1b[36m{}\x1b[0m\r\n", line);
        } else if f.is_dir {
            print!("\x1b[34m{}\x1b[0m\r\n", line);
        } else {
            print!("{}\r\n", line);
        }
    }

    // Pad remaining lines
    let shown = end.saturating_sub(offset);
    for _ in shown..list_height {
        print!("\r\n");
    }

    // Footer
    let footer = format!(
        " [{}/{}] arrows=navigate  enter=open  backspace=up  d=download  q=quit",
        if files.is_empty() { 0 } else { cursor + 1 },
        files.len()
    );
    let footer = truncate_str(&footer, w);
    print!("\x1b[7m{:<width$}\x1b[0m", footer, width = w);
    let _ = io::stdout().flush();
}

fn draw_error(msg: &str) {
    print!(
        "\x1b[2J\x1b[H\x1b[31mError: {}\x1b[0m\r\n\r\nPress any key...",
        msg
    );
    let _ = io::stdout().flush();
}

// ── Helpers ─────────────────────────────────────────────────────

fn truncate_str(s: &str, max: usize) -> String {
    if max < 3 {
        return s.chars().take(max).collect();
    }
    if s.len() <= max {
        return s.to_string();
    }
    format!("{}...", &s[..max - 3])
}

pub fn format_size(size: i64) -> String {
    if size < 1024 {
        return format!("{}B", size);
    }
    if size < 1024 * 1024 {
        return format!("{:.1}K", size as f64 / 1024.0);
    }
    if size < 1024 * 1024 * 1024 {
        return format!("{:.1}M", size as f64 / (1024.0 * 1024.0));
    }
    format!("{:.1}G", size as f64 / (1024.0 * 1024.0 * 1024.0))
}

fn parent_path(p: &str) -> String {
    let trimmed = p.trim_end_matches(['/', '\\']);
    if let Some(pos) = trimmed.rfind(['/', '\\']) {
        trimmed[..pos].to_string()
    } else {
        ".".to_string()
    }
}

fn join_path(base: &str, name: &str) -> String {
    if base == "." || base.is_empty() {
        name.to_string()
    } else {
        format!("{}/{}", base.trim_end_matches('/'), name)
    }
}

// ── Detect terminal (no extra dep) ──────────────────────────────

mod atty {
    use std::io::IsTerminal;
    pub enum Stream {
        Stdin,
    }
    pub fn is(stream: Stream) -> bool {
        match stream {
            Stream::Stdin => std::io::stdin().is_terminal(),
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_size_bytes() {
        assert_eq!(format_size(0), "0B");
        assert_eq!(format_size(512), "512B");
        assert_eq!(format_size(1023), "1023B");
    }

    #[test]
    fn format_size_kb() {
        assert_eq!(format_size(1024), "1.0K");
        assert_eq!(format_size(1536), "1.5K");
    }

    #[test]
    fn format_size_mb() {
        assert_eq!(format_size(1048576), "1.0M");
        assert_eq!(format_size(5 * 1024 * 1024), "5.0M");
    }

    #[test]
    fn format_size_gb() {
        assert_eq!(format_size(1073741824), "1.0G");
    }

    #[test]
    fn parent_path_unix() {
        assert_eq!(parent_path("foo/bar"), "foo");
        assert_eq!(parent_path("foo/bar/"), "foo");
        assert_eq!(parent_path("foo"), ".");
        assert_eq!(parent_path("."), ".");
    }

    #[test]
    fn parent_path_windows() {
        assert_eq!(parent_path(r"C:\Users\test"), r"C:\Users");
        assert_eq!(parent_path(r"C:\Users\test\"), r"C:\Users");
    }

    #[test]
    fn join_path_basic() {
        assert_eq!(join_path(".", "test"), "test");
        assert_eq!(join_path("foo", "bar"), "foo/bar");
        assert_eq!(join_path("foo/", "bar"), "foo/bar");
    }

    #[test]
    fn truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn truncate_str_exact() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn truncate_str_long() {
        assert_eq!(truncate_str("hello world", 8), "hello...");
    }
}
