//! Self-update mechanism — replace running binary via scheduled task.
//! Windows-only in production; cross-platform validation logic.

use anyhow::{Context, Result};
use mrsh_core::protocol::Response;
use tracing::info;

/// Minimum acceptable binary size (1 MB).
const MIN_BINARY_SIZE: u64 = 1_000_000;

/// Validate that the new binary exists and meets size requirements.
pub fn validate_update_path(path: &str) -> Result<()> {
    let metadata = std::fs::metadata(path).context(format!("new binary not found: {}", path))?;

    if metadata.len() < MIN_BINARY_SIZE {
        anyhow::bail!(
            "new binary too small: {} bytes (minimum {} bytes)",
            metadata.len(),
            MIN_BINARY_SIZE
        );
    }

    Ok(())
}

/// Handle self-update request. Validates the new binary path, then
/// schedules replacement (Windows service mode only in production).
pub fn handle_self_update(path: &str) -> Response {
    // Validate
    if let Err(e) = validate_update_path(path) {
        return Response {
            success: false,
            output: None,
            error: Some(e.to_string()),
            size: None,
            binary: None,
            gzip: None,
        };
    }

    info!("self-update requested: {}", path);

    // On Windows service mode, this would:
    // 1. Write a .bat script to stop service, replace binary, restart
    // 2. Schedule via schtasks /create /tn rsh-self-update /ru SYSTEM
    // 3. Run via schtasks /run /tn rsh-self-update
    // 4. Return success (actual update happens asynchronously)
    //
    // For now, return success with the path validated.
    // Full implementation requires Windows service detection.

    #[cfg(target_os = "windows")]
    {
        match schedule_update_windows(path) {
            Ok(msg) => Response {
                success: true,
                output: Some(msg),
                error: None,
                size: None,
                binary: None,
                gzip: None,
            },
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

    #[cfg(not(target_os = "windows"))]
    {
        match replace_binary_linux(path) {
            Ok(msg) => Response {
                success: true,
                output: Some(msg),
                error: None,
                size: None,
                binary: None,
                gzip: None,
            },
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
}

/// Replace the binary on Linux: backup current → copy new → optionally restart systemd.
#[cfg(not(target_os = "windows"))]
fn replace_binary_linux(new_binary: &str) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;

    let exe_path = std::env::current_exe()
        .context("get current exe path")?
        .to_string_lossy()
        .to_string();

    let backup_path = format!("{}.bak", exe_path);

    // Backup current binary
    std::fs::copy(&exe_path, &backup_path)
        .context(format!("backup {} → {}", exe_path, backup_path))?;
    info!("backed up {} → {}", exe_path, backup_path);

    // Copy new binary over current
    std::fs::copy(new_binary, &exe_path)
        .context(format!("copy {} → {}", new_binary, exe_path))?;

    // Ensure executable permission
    let perms = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(&exe_path, perms).context("set executable permission")?;

    // Clean up new binary
    let _ = std::fs::remove_file(new_binary);

    // Try to restart via systemd (non-blocking, best effort)
    let systemd_restart = std::process::Command::new("systemctl")
        .args(["restart", "rsh"])
        .output();

    match systemd_restart {
        Ok(out) if out.status.success() => {
            Ok(format!(
                "updated {} and restarted via systemd",
                exe_path
            ))
        }
        _ => {
            Ok(format!(
                "updated {} (manual restart required — not running as systemd service)",
                exe_path
            ))
        }
    }
}

/// Schedule the actual binary replacement on Windows.
#[cfg(target_os = "windows")]
fn schedule_update_windows(new_binary: &str) -> Result<String> {
    use std::process::Command;

    let exe_path = std::env::current_exe()
        .context("get current exe path")?
        .to_string_lossy()
        .to_string();

    let backup_path = format!("{}.bak", exe_path);
    let bat_path = format!("{}\\rsh-update.bat", std::env::temp_dir().to_string_lossy());

    // Write update bat script
    let bat_content = format!(
        r#"@echo off
net stop rsh
timeout /t 3 /nobreak >nul
taskkill /F /IM rsh.exe 2>nul
timeout /t 2 /nobreak >nul
copy /y "{exe}" "{backup}"
copy /y "{new}" "{exe}"
IF ERRORLEVEL 1 (
    copy /y "{backup}" "{exe}"
    echo ROLLBACK: restored from backup >> "{exe}.update.log"
)
net start rsh
del "{new}"
schtasks /delete /tn rsh-self-update /f
"#,
        exe = exe_path,
        backup = backup_path,
        new = new_binary,
    );

    std::fs::write(&bat_path, &bat_content).context("write update bat")?;

    // Delete existing task (idempotent)
    let _ = Command::new("schtasks")
        .args(["/delete", "/tn", "rsh-self-update", "/f"])
        .output();

    // Create scheduled task
    let output = Command::new("schtasks")
        .args([
            "/create",
            "/tn",
            "rsh-self-update",
            "/tr",
            &format!("cmd /c \"{}\"", bat_path),
            "/sc",
            "once",
            "/st",
            "00:00",
            "/f",
            "/ru",
            "SYSTEM",
        ])
        .output()
        .context("create schtask")?;

    if !output.status.success() {
        anyhow::bail!(
            "schtasks create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Run the task
    let output = Command::new("schtasks")
        .args(["/run", "/tn", "rsh-self-update"])
        .output()
        .context("run schtask")?;

    if !output.status.success() {
        anyhow::bail!(
            "schtasks run failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok("update scheduled, service will restart in ~10 seconds".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn validate_nonexistent_path() {
        let result = validate_update_path("/nonexistent/binary");
        assert!(result.is_err());
    }

    #[test]
    fn validate_too_small() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"tiny").unwrap();
        let result = validate_update_path(f.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too small"));
    }

    #[test]
    fn handle_self_update_nonexistent() {
        let resp = handle_self_update("/nonexistent/rsh-new.exe");
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("not found"));
    }

    #[test]
    fn handle_self_update_too_small() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[0u8; 100]).unwrap();
        let resp = handle_self_update(f.path().to_str().unwrap());
        assert!(!resp.success);
    }
}
