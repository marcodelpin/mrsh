//! Execute commands in the logged-in user's desktop session (hidden, no console).
//!
//! On Windows service mode: uses `CreateProcessAsUserW` with the desktop user's
//! token to run commands invisibly in their session. This eliminates the need for
//! VBS wrappers (`run-hidden.vbs`) when launching hidden processes.
//!
//! On Windows tray mode or Linux: falls back to regular `exec` (already in the
//! correct user session).

use mrsh_core::protocol::Response;
use tracing::debug;

use crate::safety;

/// Execute a command in the logged-in user's desktop session (hidden window).
///
/// On Windows, attempts `CreateProcessAsUserW` (requires SYSTEM privileges).
/// Falls back to regular `exec` if not running as SYSTEM (e.g. tray mode).
pub async fn handle_exec_as_user(command: &str, env_vars: &[String]) -> Response {
    debug!("exec-as-user: {}", command);

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

    // Same safety guard as regular exec
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

    platform::exec_as_user(command, env_vars).await
}

#[cfg(target_os = "windows")]
mod platform {
    use mrsh_core::protocol::Response;
    use tracing::warn;

    pub async fn exec_as_user(command: &str, env_vars: &[String]) -> Response {
        let cmd = command.to_string();
        let env = env_vars.to_vec();

        match tokio::task::spawn_blocking(move || super::win::exec_in_user_session(&cmd, &env))
            .await
        {
            Ok(Ok((output, success))) => Response {
                success,
                output: Some(output),
                error: None,
                size: None,
                binary: None,
                gzip: None,
            },
            Ok(Err(e)) => {
                warn!("exec-as-user failed, falling back to regular exec: {}", e);
                // Fallback: tray mode or insufficient privileges
                crate::exec::handle_exec(command, env_vars).await
            }
            Err(e) => Response {
                success: false,
                output: None,
                error: Some(format!("task join error: {}", e)),
                size: None,
                binary: None,
                gzip: None,
            },
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use mrsh_core::protocol::Response;

    pub async fn exec_as_user(command: &str, env_vars: &[String]) -> Response {
        // On Linux, regular exec already runs as the current user.
        crate::exec::handle_exec(command, env_vars).await
    }
}

#[cfg(target_os = "windows")]
mod win {
    use std::io::Read;
    use std::os::windows::io::FromRawHandle;

    use anyhow::{Context, Result};
    use tracing::debug;

    use windows::core::BOOL;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenPrimary, SECURITY_ATTRIBUTES,
        TOKEN_ALL_ACCESS,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::RemoteDesktop::{
        WTSGetActiveConsoleSessionId, WTSQueryUserToken,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, GetExitCodeProcess, WaitForSingleObject, CREATE_NO_WINDOW,
        PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES, STARTUPINFOW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    /// Execute a command in the logged-in user's desktop session with hidden window.
    /// Returns (combined stdout+stderr output, success).
    pub fn exec_in_user_session(command: &str, env_vars: &[String]) -> Result<(String, bool)> {
        unsafe { exec_inner(command, env_vars) }
    }

    unsafe fn exec_inner(command: &str, env_vars: &[String]) -> Result<(String, bool)> {
        // 1. Get the active console session (logged-in desktop user)
        let session_id = unsafe { WTSGetActiveConsoleSessionId() };
        if session_id == 0xFFFFFFFF {
            anyhow::bail!("no active console session (no user logged in)");
        }
        debug!("exec-as-user: session_id={}", session_id);

        // 2. Get user token for that session (requires SYSTEM / SE_TCB_PRIVILEGE)
        let mut user_token = HANDLE::default();
        unsafe { WTSQueryUserToken(session_id, &mut user_token) }
            .context("WTSQueryUserToken (requires SYSTEM privileges)")?;

        // 3. Duplicate as primary token for CreateProcessAsUser
        let mut primary_token = HANDLE::default();
        unsafe {
            DuplicateTokenEx(
                user_token,
                TOKEN_ALL_ACCESS,
                None,
                SecurityImpersonation,
                TokenPrimary,
                &mut primary_token,
            )
        }
        .context("DuplicateTokenEx")?;
        let _ = unsafe { CloseHandle(user_token) };

        // 4. Create inheritable pipes for stdout/stderr capture
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: BOOL::from(true),
        };

        let mut stdout_read = HANDLE::default();
        let mut stdout_write = HANDLE::default();
        unsafe {
            CreatePipe(
                &mut stdout_read,
                &mut stdout_write,
                Some(&sa as *const _),
                0,
            )
        }
        .context("CreatePipe stdout")?;

        // Stdin pipe: child gets immediate EOF
        let mut stdin_read = HANDLE::default();
        let mut stdin_write = HANDLE::default();
        unsafe {
            CreatePipe(
                &mut stdin_read,
                &mut stdin_write,
                Some(&sa as *const _),
                0,
            )
        }
        .context("CreatePipe stdin")?;
        let _ = unsafe { CloseHandle(stdin_write) }; // child reads EOF immediately

        // 5. Build PowerShell command line (with env vars prepended)
        let cmdline_str = build_cmdline(command, env_vars);
        let mut cmdline: Vec<u16> = cmdline_str.encode_utf16().collect();

        // 6. Target the user's interactive desktop
        let mut desktop: Vec<u16> = "WinSta0\\Default\0".encode_utf16().collect();

        // 7. Setup STARTUPINFO: hidden window + redirected handles
        let mut si = STARTUPINFOW::default();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.lpDesktop = windows::core::PWSTR(desktop.as_mut_ptr());
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE.0 as u16;
        si.hStdInput = stdin_read;
        si.hStdOutput = stdout_write;
        si.hStdError = stdout_write;

        // 8. Create process as user
        let mut pi = PROCESS_INFORMATION::default();
        let result = unsafe {
            CreateProcessAsUserW(
                Some(primary_token),
                windows::core::PCWSTR::null(),
                Some(windows::core::PWSTR(cmdline.as_mut_ptr())),
                None,
                None,
                true, // inherit handles (for pipes)
                CREATE_NO_WINDOW,
                None, // inherit user's default environment
                windows::core::PCWSTR::null(),
                &si,
                &mut pi,
            )
        };

        // Cleanup handles the parent no longer needs
        let _ = unsafe { CloseHandle(primary_token) };
        let _ = unsafe { CloseHandle(stdout_write) }; // child has its own copy
        let _ = unsafe { CloseHandle(stdin_read) }; // child has its own copy

        result.context("CreateProcessAsUserW")?;

        // 9. Read all output (blocks until child exits and pipe closes)
        let proc_handle = pi.hProcess;
        let _ = unsafe { CloseHandle(pi.hThread) };

        let mut pipe_file = unsafe { std::fs::File::from_raw_handle(stdout_read.0) };
        let mut output = String::new();
        let _ = pipe_file.read_to_string(&mut output);
        // pipe_file drops here, closing stdout_read

        // 10. Get exit code (child should be done since pipe closed)
        let _ = unsafe { WaitForSingleObject(proc_handle, 30_000) };
        let mut exit_code: u32 = 1;
        let _ = unsafe { GetExitCodeProcess(proc_handle, &mut exit_code) };
        let _ = unsafe { CloseHandle(proc_handle) };

        Ok((output, exit_code == 0))
    }

    /// Build PowerShell command line, prepending env var assignments.
    fn build_cmdline(command: &str, env_vars: &[String]) -> String {
        let mut cmd = String::from("powershell.exe -NoProfile -Command ");
        for ev in env_vars {
            if let Some((k, v)) = ev.split_once('=') {
                let escaped = v.replace('\'', "''");
                cmd.push_str(&format!("$env:{}='{}'; ", k, escaped));
            }
        }
        cmd.push_str(command);
        cmd.push('\0'); // null terminator for wide string
        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_command_returns_error() {
        let resp = handle_exec_as_user("", &[]).await;
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("empty command"));
    }

    #[tokio::test]
    async fn safety_block_applied() {
        let resp = handle_exec_as_user("taskkill /im rsh.exe /f", &[]).await;
        assert!(!resp.success);
        let err = resp.error.unwrap();
        assert!(
            err.contains("blocked") || err.contains("BLOCKED"),
            "expected safety block, got: {}",
            err
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn linux_fallback_runs_command() {
        let resp = handle_exec_as_user("echo hello-user", &[]).await;
        assert!(resp.success);
        assert!(resp.output.unwrap().contains("hello-user"));
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn linux_fallback_with_env_vars() {
        let resp =
            handle_exec_as_user("echo $TEST_EU_VAR", &["TEST_EU_VAR=user123".to_string()]).await;
        assert!(resp.success);
        assert!(resp.output.unwrap().contains("user123"));
    }
}
