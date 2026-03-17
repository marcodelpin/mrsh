//! Command execution — runs commands via PowerShell (Windows) or sh (Linux).

use mrsh_core::protocol::Response;
use tracing::debug;

use crate::safety;

/// Execute a command and return the response.
/// On Windows: `powershell -NoProfile -Command <cmd>`
/// On Linux: `sh -c <cmd>` (for testing)
pub async fn handle_exec(command: &str, env_vars: &[String]) -> Response {
    debug!("exec: {}", command);

    if command.is_empty() {
        return Response {
            success: false,
            output: None,
            error: Some("empty command".to_string()),
            size: None,
            binary: None,
            gzip: None,
        };
    }

    // Safety guard: block commands that would kill/stop this mrsh process.
    if let safety::SafetyVerdict::Block { reason } = safety::check_exec(command) {
        return Response {
            success: false,
            output: None,
            error: Some(reason),
            size: None,
            binary: None,
            gzip: None,
        };
    }

    let result = run_command(command, env_vars).await;

    match result {
        Ok((output, success)) => Response {
            success,
            output: Some(output),
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

/// Run a command, returning (output, success).
async fn run_command(command: &str, env_vars: &[String]) -> anyhow::Result<(String, bool)> {
    let mut cmd = build_command(command);

    // Add environment variables (with sanitization)
    if !env_vars.is_empty() {
        for ev in env_vars {
            if let Some((k, v)) = ev.split_once('=') {
                if is_dangerous_env_var(k) {
                    debug!("blocked dangerous env var: {}", k);
                    continue;
                }
                cmd.env(k, v);
            }
        }
    }

    let output = cmd
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("spawn failed: {}", e))?;

    let combined = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);

    Ok((combined, output.status.success()))
}

#[cfg(target_os = "windows")]
fn build_command(command: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("powershell");
    cmd.args(["-NoProfile", "-Command", command]);
    // HideWindow equivalent via creation flags
    cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    cmd
}

#[cfg(not(target_os = "windows"))]
fn build_command(command: &str) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("sh");
    cmd.args(["-c", command]);
    cmd
}

/// Check if an environment variable name is dangerous and should be blocked.
/// Prevents privilege escalation and code injection via env vars.
fn is_dangerous_env_var(name: &str) -> bool {
    let upper = name.to_uppercase();
    matches!(
        upper.as_str(),
        // Path/library injection
        "PATH"
            | "LD_PRELOAD"
            | "LD_LIBRARY_PATH"
            | "DYLD_INSERT_LIBRARIES"
            | "DYLD_LIBRARY_PATH"
            // Shell/interpreter override
            | "SHELL"
            | "COMSPEC"
            | "IFS"
            // PowerShell profile injection
            | "PSMODULEPATH"
            | "PSModulePath"
            // Proxy hijacking
            | "HTTP_PROXY"
            | "HTTPS_PROXY"
            | "ALL_PROXY"
            | "NO_PROXY"
            | "http_proxy"
            | "https_proxy"
            // User/auth spoofing
            | "HOME"
            | "USERPROFILE"
            | "USER"
            | "USERNAME"
            | "LOGNAME"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exec_echo() {
        let resp = handle_exec("echo hello", &[]).await;
        assert!(resp.success);
        assert!(resp.output.unwrap().contains("hello"));
    }

    #[tokio::test]
    async fn exec_empty_command() {
        let resp = handle_exec("", &[]).await;
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("empty command"));
    }

    #[tokio::test]
    async fn exec_failing_command() {
        let resp = handle_exec("false", &[]).await;
        assert!(!resp.success);
    }

    #[tokio::test]
    async fn exec_with_env_vars() {
        let resp = handle_exec("echo $TEST_VAR", &["TEST_VAR=hello123".to_string()]).await;
        assert!(resp.success);
        assert!(resp.output.unwrap().contains("hello123"));
    }

    #[test]
    fn blocks_dangerous_env_vars() {
        assert!(is_dangerous_env_var("PATH"));
        assert!(is_dangerous_env_var("LD_PRELOAD"));
        assert!(is_dangerous_env_var("LD_LIBRARY_PATH"));
        assert!(is_dangerous_env_var("DYLD_INSERT_LIBRARIES"));
        assert!(is_dangerous_env_var("SHELL"));
        assert!(is_dangerous_env_var("COMSPEC"));
        assert!(is_dangerous_env_var("IFS"));
        assert!(is_dangerous_env_var("HTTP_PROXY"));
        assert!(is_dangerous_env_var("HOME"));
        assert!(is_dangerous_env_var("USERPROFILE"));
    }

    #[test]
    fn allows_safe_env_vars() {
        assert!(!is_dangerous_env_var("TEST_VAR"));
        assert!(!is_dangerous_env_var("MY_APP_CONFIG"));
        assert!(!is_dangerous_env_var("RUST_LOG"));
        assert!(!is_dangerous_env_var("LANG"));
    }
}
