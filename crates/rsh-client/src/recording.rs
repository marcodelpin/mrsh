//! Session recording: list + export to asciicast v2 format.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::RshClient;

// ── Asciicast v2 ────────────────────────────────────────────────

#[derive(Serialize)]
struct AsciicastHeader {
    version: u32,
    width: u32,
    height: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    env: std::collections::HashMap<String, String>,
}

/// Convert a .log + .time file pair to asciicast v2 format.
pub fn export_asciicast(log_path: &str, out_path: &str, width: u32, height: u32) -> Result<()> {
    // Derive .time path from .log path
    let time_path = log_path
        .strip_suffix(".log")
        .unwrap_or(log_path)
        .to_string()
        + ".time";
    if !Path::new(&time_path).exists() {
        bail!("timing file not found: {}", time_path);
    }

    let log_data = std::fs::read(log_path).context("read log")?;

    // Skip script(1) header (first line)
    let start = log_data
        .iter()
        .position(|&b| b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(0);

    // Skip script(1) footer (last line starting with "Script done")
    let mut end = log_data.len();
    for i in (1..log_data.len().saturating_sub(1)).rev() {
        if log_data[i] == b'\n' {
            let line = &log_data[i + 1..];
            if line.starts_with(b"Script done") || line.starts_with(b"\nScript done") {
                end = i;
            }
            break;
        }
    }
    let payload = &log_data[start..end];

    // Parse timing file
    let time_data = std::fs::read_to_string(&time_path).context("read timing")?;

    // Open output
    let mut out: Box<dyn Write> = if out_path == "-" {
        Box::new(std::io::stdout())
    } else {
        Box::new(std::fs::File::create(out_path).context("create output")?)
    };

    // Write header
    let mut env = std::collections::HashMap::new();
    env.insert("TERM".into(), "xterm-256color".into());
    env.insert("SHELL".into(), "cmd.exe".into());
    let header = AsciicastHeader {
        version: 2,
        width,
        height,
        timestamp: None,
        title: None,
        env,
    };
    let header_json = serde_json::to_string(&header)?;
    writeln!(out, "{}", header_json)?;

    // Process timing entries
    let mut cumulative_time: f64 = 0.0;
    let mut offset: usize = 0;

    for line in time_data.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 2 {
            continue;
        }
        let delay: f64 = match parts[0].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let mut nbytes: usize = match parts[1].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        cumulative_time += delay;

        if offset + nbytes > payload.len() {
            nbytes = payload.len().saturating_sub(offset);
        }
        if nbytes == 0 {
            continue;
        }

        let chunk = &payload[offset..offset + nbytes];
        offset += nbytes;

        let data_json = serde_json::to_string(&String::from_utf8_lossy(chunk))?;
        writeln!(out, "[{:.6}, \"o\", {}]", cumulative_time, data_json)?;
    }

    Ok(())
}

/// List recordings on the remote host.
pub async fn list_remote<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
) -> Result<String> {
    let ps_cmd = "Get-ChildItem -Path (Join-Path $env:ProgramData 'remote-shell\\sessions') -Filter *.log | Select-Object Name,Length | Format-Table -AutoSize";
    crate::commands::exec(client, ps_cmd, &[]).await
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asciicast_header_serialization() {
        let mut env = std::collections::HashMap::new();
        env.insert("TERM".into(), "xterm-256color".into());
        let header = AsciicastHeader {
            version: 2,
            width: 120,
            height: 35,
            timestamp: None,
            title: None,
            env,
        };
        let json = serde_json::to_string(&header).unwrap();
        assert!(json.contains("\"version\":2"));
        assert!(json.contains("\"width\":120"));
        assert!(json.contains("\"height\":35"));
        assert!(!json.contains("timestamp")); // skipped when None
    }

    #[test]
    fn export_missing_log() {
        let result = export_asciicast("/nonexistent/file.log", "/tmp/out.cast", 120, 35);
        assert!(result.is_err());
    }

    #[test]
    fn export_missing_timing() {
        // Create a temp log file without matching .time file
        let dir = std::env::temp_dir().join("rsh-test-recording");
        let _ = std::fs::create_dir_all(&dir);
        let log_path = dir.join("test.log");
        std::fs::write(&log_path, b"Script started\nhello\nScript done").unwrap();

        let result = export_asciicast(log_path.to_str().unwrap(), "/tmp/out.cast", 120, 35);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("timing file not found")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_full_roundtrip() {
        let dir = std::env::temp_dir().join("rsh-test-recording-rt");
        let _ = std::fs::create_dir_all(&dir);

        let log_path = dir.join("session.log");
        let time_path = dir.join("session.time");
        let out_path = dir.join("session.cast");

        // Create log with header/footer
        std::fs::write(
            &log_path,
            b"Script started on 2026-03-05\nhello world\nScript done on 2026-03-05",
        )
        .unwrap();
        // Create timing: 0.1s for 5 bytes, 0.2s for 6 bytes
        std::fs::write(&time_path, "0.100000 5\n0.200000 6\n").unwrap();

        export_asciicast(
            log_path.to_str().unwrap(),
            out_path.to_str().unwrap(),
            80,
            24,
        )
        .unwrap();

        let output = std::fs::read_to_string(&out_path).unwrap();
        let lines: Vec<&str> = output.lines().collect();

        // First line = header
        assert!(lines[0].contains("\"version\":2"));
        assert!(lines[0].contains("\"width\":80"));
        // Second line = first event
        assert!(lines[1].contains("0.100000"));
        assert!(lines[1].contains("\"o\""));
        // Third line = second event
        assert!(lines[2].contains("0.300000")); // cumulative

        let _ = std::fs::remove_dir_all(&dir);
    }
}
