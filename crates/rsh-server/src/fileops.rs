//! File operations — ls, read, write.

use std::path::Path;

use base64::Engine;
use rsh_core::protocol::{FileInfo, Response};
use tracing::debug;

/// Sanitize a file path: reject null bytes and other dangerous patterns.
/// Returns the cleaned path or an error message.
fn sanitize_path(path: &str) -> Result<&str, String> {
    if path.is_empty() {
        return Err("empty path".to_string());
    }
    if path.as_bytes().contains(&0) {
        return Err("path contains null byte".to_string());
    }
    // Reject paths with newlines (could confuse log parsing or shell escapes)
    if path.contains('\n') || path.contains('\r') {
        return Err("path contains newline".to_string());
    }
    Ok(path)
}

/// List directory contents, returning JSON array of FileInfo.
pub fn handle_ls(path: &str) -> Response {
    let path = match sanitize_path(path) {
        Ok(p) => p,
        Err(e) => return error_response(&e),
    };
    debug!("ls: {}", path);

    match list_dir(path) {
        Ok(files) => {
            let json = serde_json::to_string(&files).unwrap_or_default();
            Response {
                success: true,
                output: Some(json),
                error: None,
                size: None,
                binary: None,
                gzip: None,
            }
        }
        Err(e) => Response {
            success: false,
            output: None,
            error: Some(e.to_string()),
            size: None,
            binary: None,
            gzip: None,
        },
    }
}

/// Read a file and return its content as base64.
pub fn handle_read(path: &str) -> Response {
    let path = match sanitize_path(path) {
        Ok(p) => p,
        Err(e) => return error_response(&e),
    };
    debug!("read: {}", path);

    match std::fs::read(path) {
        Ok(data) => {
            let b64 = base64::engine::general_purpose::STANDARD;
            Response {
                success: true,
                output: Some(b64.encode(&data)),
                error: None,
                size: Some(data.len() as i64),
                binary: Some(true),
                gzip: None,
            }
        }
        Err(e) => Response {
            success: false,
            output: None,
            error: Some(format!("read {}: {}", path, e)),
            size: None,
            binary: None,
            gzip: None,
        },
    }
}

/// Write base64-encoded content to a file.
pub fn handle_write(path: &str, content_b64: &str) -> Response {
    let path = match sanitize_path(path) {
        Ok(p) => p,
        Err(e) => return error_response(&e),
    };
    debug!("write: {}", path);

    let b64 = base64::engine::general_purpose::STANDARD;
    let data = match b64.decode(content_b64) {
        Ok(d) => d,
        Err(e) => {
            return Response {
                success: false,
                output: None,
                error: Some(format!("decode base64: {}", e)),
                size: None,
                binary: None,
                gzip: None,
            };
        }
    };

    // Ensure parent directory exists
    if let Some(parent) = Path::new(path).parent()
        && !parent.exists()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        return Response {
            success: false,
            output: None,
            error: Some(format!("create parent dir: {}", e)),
            size: None,
            binary: None,
            gzip: None,
        };
    }

    match std::fs::write(path, &data) {
        Ok(()) => Response {
            success: true,
            output: Some(format!("{} bytes written", data.len())),
            error: None,
            size: Some(data.len() as i64),
            binary: None,
            gzip: None,
        },
        Err(e) => Response {
            success: false,
            output: None,
            error: Some(format!("write {}: {}", path, e)),
            size: None,
            binary: None,
            gzip: None,
        },
    }
}

fn list_dir(path: &str) -> anyhow::Result<Vec<FileInfo>> {
    let mut files = Vec::new();

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        let name = entry.file_name().to_string_lossy().to_string();

        let mode = if meta.is_dir() {
            "drwxr-xr-x".to_string()
        } else {
            "-rw-r--r--".to_string()
        };

        let mod_time = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| {
                // ISO 8601 format
                let secs = d.as_secs() as i64;
                chrono_format_unix(secs)
            })
            .unwrap_or_default();

        files.push(FileInfo {
            name,
            size: meta.len() as i64,
            mode,
            mod_time,
            is_dir: meta.is_dir(),
        });
    }

    files.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(files)
}

/// Format a Unix timestamp as ISO 8601 (without chrono dependency).
fn chrono_format_unix(secs: i64) -> String {
    // Simple UTC formatting: YYYY-MM-DDThh:mm:ssZ
    // Using a basic calculation (good enough for file timestamps)
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch to date (simplified, no leap second handling)
    let (year, month, day) = days_to_date(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_date(mut days: i64) -> (i64, i64, i64) {
    // Civil calendar algorithm
    days += 719468; // shift epoch from 1970 to 0000-03-01
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = days - era * 146097; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn error_response(msg: &str) -> Response {
    Response {
        success: false,
        output: None,
        error: Some(msg.to_string()),
        size: None,
        binary: None,
        gzip: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_rejects_null_byte() {
        let resp = handle_read("/etc/pass\0wd");
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("null byte"));
    }

    #[test]
    fn sanitize_rejects_empty_path() {
        let resp = handle_read("");
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("empty path"));
    }

    #[test]
    fn sanitize_rejects_newline() {
        let resp = handle_read("/etc/passwd\nmalicious");
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("newline"));
    }

    #[test]
    fn sanitize_allows_normal_paths() {
        assert!(sanitize_path("/usr/bin/ls").is_ok());
        assert!(sanitize_path("C:\\Users\\test\\file.txt").is_ok());
        assert!(sanitize_path("../relative/path").is_ok());
        assert!(sanitize_path(".").is_ok());
    }

    #[test]
    fn ls_current_dir() {
        let resp = handle_ls(".");
        assert!(resp.success);
        let files: Vec<FileInfo> = serde_json::from_str(resp.output.as_deref().unwrap()).unwrap();
        assert!(!files.is_empty());
    }

    #[test]
    fn ls_nonexistent() {
        let resp = handle_ls("/nonexistent_dir_xyz");
        assert!(!resp.success);
    }

    #[test]
    fn read_write_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        let path_str = path.to_str().unwrap();

        // Write
        let b64 = base64::engine::general_purpose::STANDARD;
        let data = b"hello world";
        let content_b64 = b64.encode(data);
        let resp = handle_write(path_str, &content_b64);
        assert!(resp.success);
        assert_eq!(resp.size, Some(11));

        // Read back
        let resp = handle_read(path_str);
        assert!(resp.success);
        assert!(resp.binary.unwrap());
        let decoded = b64.decode(resp.output.unwrap()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn read_nonexistent() {
        let resp = handle_read("/nonexistent_file_xyz");
        assert!(!resp.success);
    }

    #[test]
    fn write_invalid_base64() {
        let resp = handle_write("/tmp/test", "not!valid!base64!!!");
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("base64"));
    }

    #[test]
    fn chrono_format_known_date() {
        // 2026-03-04T00:00:00Z = 1772582400 Unix timestamp
        let s = chrono_format_unix(1772582400);
        assert!(s.starts_with("2026-03-04T"));
        assert!(s.ends_with("Z"));
    }

    #[test]
    fn days_to_date_epoch() {
        assert_eq!(days_to_date(0), (1970, 1, 1));
    }

    #[test]
    fn days_to_date_known() {
        // 2026-03-04 = day 20516 since epoch
        let (y, m, d) = days_to_date(20516);
        assert_eq!((y, m, d), (2026, 3, 4));
    }
}
