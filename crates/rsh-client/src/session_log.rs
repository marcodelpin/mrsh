//! Client-side session logging — JSONL files with rotation.
//!
//! Records every rsh command (host, command, duration) for:
//! - Operational analysis (improve routines)
//! - Effort accounting and billing (count hours per machine)
//!
//! Log format: ~/.rsh/logs/YYYY-MM.jsonl (one JSON line per command)
//! Rotation: delete files older than SessionLogRetain days.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use chrono::{Datelike, Local, NaiveDate};
use serde::{Deserialize, Serialize};

/// A single session log entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct LogEntry {
    /// Host name (as specified by user, before resolution)
    pub host: String,
    /// Port connected to
    pub port: u16,
    /// Command type (exec, shell, push, pull, ping, etc.)
    pub cmd: String,
    /// Command arguments summary (truncated for readability)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
    /// ISO 8601 start timestamp
    pub start: String,
    /// ISO 8601 end timestamp
    pub end: String,
    /// Duration in seconds
    pub duration_s: f64,
    /// Exit status (0 = success, 1 = error)
    pub exit: i32,
}

/// Tracks a session in progress. Call `finish()` to write the log entry.
pub struct SessionTracker {
    host: String,
    port: u16,
    cmd: String,
    args: Option<String>,
    start_time: Instant,
    start_ts: String,
    log_dir: PathBuf,
}

impl SessionTracker {
    /// Start tracking a new command.
    pub fn start(host: &str, port: u16, cmd: &str, args: Option<&str>, log_dir: &Path) -> Self {
        Self {
            host: host.to_string(),
            port,
            cmd: cmd.to_string(),
            args: args.map(|a| truncate_args(a, 200)),
            start_time: Instant::now(),
            start_ts: Local::now().to_rfc3339(),
            log_dir: log_dir.to_path_buf(),
        }
    }

    /// Finish tracking and write the log entry.
    pub fn finish(self, exit: i32) {
        let duration = self.start_time.elapsed();
        let end_ts = Local::now().to_rfc3339();

        let entry = LogEntry {
            host: self.host,
            port: self.port,
            cmd: self.cmd,
            args: self.args,
            start: self.start_ts,
            end: end_ts,
            duration_s: (duration.as_millis() as f64) / 1000.0,
            exit,
        };

        if let Err(e) = write_entry(&self.log_dir, &entry) {
            eprintln!("[session-log] write error: {}", e);
        }
    }
}

/// Write a log entry to the current month's JSONL file.
fn write_entry(log_dir: &Path, entry: &LogEntry) -> std::io::Result<()> {
    fs::create_dir_all(log_dir)?;

    let filename = Local::now().format("%Y-%m.jsonl").to_string();
    let path = log_dir.join(filename);

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    let json = serde_json::to_string(entry)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    writeln!(file, "{}", json)?;
    Ok(())
}

/// Delete log files older than `retain_days`.
pub fn rotate_logs(log_dir: &Path, retain_days: u32) {
    let cutoff = Local::now().date_naive() - chrono::Duration::days(retain_days as i64);

    let entries = match fs::read_dir(log_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Parse YYYY-MM.jsonl
        if let Some(stem) = name.strip_suffix(".jsonl") {
            if let Ok(date) = NaiveDate::parse_from_str(&format!("{}-01", stem), "%Y-%m-%d") {
                // If the entire month is before cutoff, delete
                let last_day = if date.month() == 12 {
                    NaiveDate::from_ymd_opt(date.year() + 1, 1, 1)
                } else {
                    NaiveDate::from_ymd_opt(date.year(), date.month() + 1, 1)
                };
                if let Some(last) = last_day {
                    let month_end = last - chrono::Duration::days(1);
                    if month_end < cutoff {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
    }
}

/// Truncate args string to max_len, adding "..." if truncated.
fn truncate_args(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

// ── Log query/report ─────────────────────────────────────────────

/// Filter criteria for log queries.
pub struct LogFilter {
    pub host: Option<String>,
    pub since: Option<NaiveDate>,
    pub until: Option<NaiveDate>,
}

/// Summary of hours per host.
#[derive(Debug, Default)]
pub struct HostSummary {
    pub host: String,
    pub total_seconds: f64,
    pub command_count: u64,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
}

/// Read and filter log entries from all JSONL files in log_dir.
pub fn query_logs(log_dir: &Path, filter: &LogFilter) -> Vec<LogEntry> {
    let mut entries = Vec::new();

    let dir_entries = match fs::read_dir(log_dir) {
        Ok(e) => e,
        Err(_) => return entries,
    };

    let mut files: Vec<_> = dir_entries
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .ends_with(".jsonl")
        })
        .collect();
    files.sort_by_key(|e| e.file_name());

    for file_entry in files {
        let content = match fs::read_to_string(file_entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let entry: LogEntry = match serde_json::from_str(line) {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Apply filters
            if let Some(ref host_filter) = filter.host {
                if !entry.host.contains(host_filter.as_str()) {
                    continue;
                }
            }

            if let Some(since) = filter.since {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&entry.start) {
                    if dt.date_naive() < since {
                        continue;
                    }
                }
            }

            if let Some(until) = filter.until {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&entry.start) {
                    if dt.date_naive() > until {
                        continue;
                    }
                }
            }

            entries.push(entry);
        }
    }

    entries
}

/// Summarize log entries by host.
pub fn summarize_by_host(entries: &[LogEntry]) -> Vec<HostSummary> {
    use std::collections::HashMap;

    let mut map: HashMap<String, HostSummary> = HashMap::new();

    for entry in entries {
        let summary = map.entry(entry.host.clone()).or_insert_with(|| HostSummary {
            host: entry.host.clone(),
            ..Default::default()
        });
        summary.total_seconds += entry.duration_s;
        summary.command_count += 1;

        if summary.first_seen.is_none() || summary.first_seen.as_ref().unwrap() > &entry.start {
            summary.first_seen = Some(entry.start.clone());
        }
        if summary.last_seen.is_none() || summary.last_seen.as_ref().unwrap() < &entry.end {
            summary.last_seen = Some(entry.end.clone());
        }
    }

    let mut result: Vec<_> = map.into_values().collect();
    result.sort_by(|a, b| b.total_seconds.partial_cmp(&a.total_seconds).unwrap());
    result
}

/// Format duration as HH:MM:SS.
pub fn format_duration(seconds: f64) -> String {
    let total = seconds as u64;
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_entry(host: &str, cmd: &str, duration_s: f64, start: &str, exit: i32) -> LogEntry {
        LogEntry {
            host: host.to_string(),
            port: 8822,
            cmd: cmd.to_string(),
            args: None,
            start: start.to_string(),
            end: start.to_string(),
            duration_s,
            exit,
        }
    }

    fn write_jsonl(dir: &Path, filename: &str, entries: &[LogEntry]) {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join(filename);
        let mut f = fs::File::create(&path).unwrap();
        for e in entries {
            let json = serde_json::to_string(e).unwrap();
            writeln!(f, "{}", json).unwrap();
        }
    }

    // ── format_duration ──

    #[test]
    fn format_duration_zero() {
        assert_eq!(format_duration(0.0), "00:00:00");
    }

    #[test]
    fn format_duration_seconds_only() {
        assert_eq!(format_duration(45.0), "00:00:45");
    }

    #[test]
    fn format_duration_minutes_and_seconds() {
        assert_eq!(format_duration(125.0), "00:02:05");
    }

    #[test]
    fn format_duration_hours() {
        assert_eq!(format_duration(3661.0), "01:01:01");
    }

    #[test]
    fn format_duration_large() {
        assert_eq!(format_duration(36000.0), "10:00:00");
    }

    // ── truncate_args ──

    #[test]
    fn truncate_args_short() {
        assert_eq!(truncate_args("hello", 10), "hello");
    }

    #[test]
    fn truncate_args_exact() {
        assert_eq!(truncate_args("12345", 5), "12345");
    }

    #[test]
    fn truncate_args_long() {
        assert_eq!(truncate_args("1234567890", 5), "12345...");
    }

    // ── LogEntry serde roundtrip ──

    #[test]
    fn log_entry_serde_roundtrip() {
        let entry = make_entry("server1", "exec", 1.5, "2026-03-08T10:00:00+01:00", 0);
        let json = serde_json::to_string(&entry).unwrap();
        let back: LogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.host, "server1");
        assert_eq!(back.cmd, "exec");
        assert_eq!(back.duration_s, 1.5);
        assert_eq!(back.exit, 0);
    }

    #[test]
    fn log_entry_args_none_omitted() {
        let entry = make_entry("h", "ping", 0.0, "2026-01-01T00:00:00Z", 0);
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("args"));
    }

    #[test]
    fn log_entry_args_some_included() {
        let mut entry = make_entry("h", "exec", 0.0, "2026-01-01T00:00:00Z", 0);
        entry.args = Some("hostname".to_string());
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"args\":\"hostname\""));
    }

    // ── SessionTracker start + finish (write roundtrip) ──

    #[test]
    fn tracker_writes_entry() {
        let dir = std::env::temp_dir().join("rsh-test-tracker");
        let _ = fs::remove_dir_all(&dir);

        let tracker = SessionTracker::start("test-host", 8822, "ping", None, &dir);
        tracker.finish(0);

        // Read back
        let filter = LogFilter { host: None, since: None, until: None };
        let entries = query_logs(&dir, &filter);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host, "test-host");
        assert_eq!(entries[0].cmd, "ping");
        assert_eq!(entries[0].exit, 0);
        assert!(entries[0].duration_s >= 0.0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tracker_with_args() {
        let dir = std::env::temp_dir().join("rsh-test-tracker-args");
        let _ = fs::remove_dir_all(&dir);

        let tracker = SessionTracker::start("srv", 9822, "exec", Some("hostname"), &dir);
        tracker.finish(1);

        let filter = LogFilter { host: None, since: None, until: None };
        let entries = query_logs(&dir, &filter);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].args.as_deref(), Some("hostname"));
        assert_eq!(entries[0].exit, 1);
        assert_eq!(entries[0].port, 9822);

        let _ = fs::remove_dir_all(&dir);
    }

    // ── query_logs ──

    #[test]
    fn query_empty_dir() {
        let dir = std::env::temp_dir().join("rsh-test-empty-query");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let filter = LogFilter { host: None, since: None, until: None };
        let entries = query_logs(&dir, &filter);
        assert!(entries.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn query_nonexistent_dir() {
        let filter = LogFilter { host: None, since: None, until: None };
        let entries = query_logs(Path::new("/nonexistent/path"), &filter);
        assert!(entries.is_empty());
    }

    #[test]
    fn query_filter_by_host() {
        let dir = std::env::temp_dir().join("rsh-test-host-filter");
        let _ = fs::remove_dir_all(&dir);

        let entries = vec![
            make_entry("alpha", "ping", 0.1, "2026-03-08T10:00:00+01:00", 0),
            make_entry("beta", "exec", 0.2, "2026-03-08T10:01:00+01:00", 0),
            make_entry("alpha-2", "ls", 0.3, "2026-03-08T10:02:00+01:00", 0),
        ];
        write_jsonl(&dir, "2026-03.jsonl", &entries);

        let filter = LogFilter {
            host: Some("alpha".to_string()),
            since: None,
            until: None,
        };
        let result = query_logs(&dir, &filter);
        assert_eq!(result.len(), 2); // "alpha" and "alpha-2" both contain "alpha"
        assert!(result.iter().all(|e| e.host.contains("alpha")));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn query_filter_by_since() {
        let dir = std::env::temp_dir().join("rsh-test-since-filter");
        let _ = fs::remove_dir_all(&dir);

        let entries = vec![
            make_entry("h", "a", 0.1, "2026-01-15T10:00:00+01:00", 0),
            make_entry("h", "b", 0.2, "2026-02-15T10:00:00+01:00", 0),
            make_entry("h", "c", 0.3, "2026-03-15T10:00:00+01:00", 0),
        ];
        write_jsonl(&dir, "2026-01.jsonl", &entries[0..1]);
        write_jsonl(&dir, "2026-02.jsonl", &entries[1..2]);
        write_jsonl(&dir, "2026-03.jsonl", &entries[2..3]);

        let filter = LogFilter {
            host: None,
            since: Some(NaiveDate::from_ymd_opt(2026, 2, 1).unwrap()),
            until: None,
        };
        let result = query_logs(&dir, &filter);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].cmd, "b");
        assert_eq!(result[1].cmd, "c");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn query_filter_by_until() {
        let dir = std::env::temp_dir().join("rsh-test-until-filter");
        let _ = fs::remove_dir_all(&dir);

        let entries = vec![
            make_entry("h", "a", 0.1, "2026-01-15T10:00:00+01:00", 0),
            make_entry("h", "b", 0.2, "2026-02-15T10:00:00+01:00", 0),
            make_entry("h", "c", 0.3, "2026-03-15T10:00:00+01:00", 0),
        ];
        write_jsonl(&dir, "2026-01.jsonl", &entries[0..1]);
        write_jsonl(&dir, "2026-02.jsonl", &entries[1..2]);
        write_jsonl(&dir, "2026-03.jsonl", &entries[2..3]);

        let filter = LogFilter {
            host: None,
            since: None,
            until: Some(NaiveDate::from_ymd_opt(2026, 2, 28).unwrap()),
        };
        let result = query_logs(&dir, &filter);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].cmd, "a");
        assert_eq!(result[1].cmd, "b");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn query_skips_malformed_lines() {
        let dir = std::env::temp_dir().join("rsh-test-malformed");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let content = r#"{"host":"ok","port":8822,"cmd":"ping","start":"2026-01-01T00:00:00Z","end":"2026-01-01T00:00:00Z","duration_s":0.1,"exit":0}
not json at all
{"broken": true}
{"host":"ok2","port":8822,"cmd":"exec","start":"2026-01-01T00:00:01Z","end":"2026-01-01T00:00:01Z","duration_s":0.2,"exit":0}
"#;
        fs::write(dir.join("2026-01.jsonl"), content).unwrap();

        let filter = LogFilter { host: None, since: None, until: None };
        let result = query_logs(&dir, &filter);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].host, "ok");
        assert_eq!(result[1].host, "ok2");

        let _ = fs::remove_dir_all(&dir);
    }

    // ── summarize_by_host ──

    #[test]
    fn summarize_empty() {
        let result = summarize_by_host(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn summarize_single_host() {
        let entries = vec![
            make_entry("srv", "ping", 1.0, "2026-03-08T10:00:00+01:00", 0),
            make_entry("srv", "exec", 2.5, "2026-03-08T10:01:00+01:00", 0),
        ];
        let result = summarize_by_host(&entries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].host, "srv");
        assert_eq!(result[0].command_count, 2);
        assert!((result[0].total_seconds - 3.5).abs() < 0.001);
    }

    #[test]
    fn summarize_multiple_hosts_sorted_by_duration() {
        let entries = vec![
            make_entry("short", "ping", 1.0, "2026-03-08T10:00:00+01:00", 0),
            make_entry("long", "exec", 100.0, "2026-03-08T10:01:00+01:00", 0),
            make_entry("medium", "ls", 50.0, "2026-03-08T10:02:00+01:00", 0),
        ];
        let result = summarize_by_host(&entries);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].host, "long");   // 100s first
        assert_eq!(result[1].host, "medium"); // 50s second
        assert_eq!(result[2].host, "short");  // 1s last
    }

    #[test]
    fn summarize_tracks_first_last_seen() {
        let entries = vec![
            make_entry("srv", "a", 1.0, "2026-01-15T10:00:00+01:00", 0),
            make_entry("srv", "b", 2.0, "2026-03-15T10:00:00+01:00", 0),
            make_entry("srv", "c", 3.0, "2026-02-15T10:00:00+01:00", 0),
        ];
        let result = summarize_by_host(&entries);
        assert_eq!(result.len(), 1);
        assert!(result[0].first_seen.as_ref().unwrap().contains("2026-01-15"));
    }

    // ── rotate_logs ──

    #[test]
    fn rotate_deletes_old_files() {
        let dir = std::env::temp_dir().join("rsh-test-rotate");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Create files: old (2020-01) and recent (current month)
        fs::write(dir.join("2020-01.jsonl"), "old").unwrap();
        fs::write(dir.join("2020-06.jsonl"), "old too").unwrap();

        let now = Local::now();
        let current = now.format("%Y-%m.jsonl").to_string();
        fs::write(dir.join(&current), "recent").unwrap();

        rotate_logs(&dir, 90);

        // Old files deleted, current kept
        assert!(!dir.join("2020-01.jsonl").exists());
        assert!(!dir.join("2020-06.jsonl").exists());
        assert!(dir.join(&current).exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotate_ignores_non_jsonl() {
        let dir = std::env::temp_dir().join("rsh-test-rotate-ignore");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(dir.join("notes.txt"), "keep me").unwrap();
        fs::write(dir.join("2020-01.jsonl"), "old").unwrap();

        rotate_logs(&dir, 90);

        assert!(dir.join("notes.txt").exists());
        assert!(!dir.join("2020-01.jsonl").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotate_nonexistent_dir_no_panic() {
        rotate_logs(Path::new("/nonexistent/dir/rsh-rotate-test"), 90);
        // should not panic
    }
}
