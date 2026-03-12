//! Request dispatch — routes incoming requests to handlers.
//! Some commands (connect, shell) hijack the connection.

use rsh_core::protocol::{self, Response};
use tracing::debug;

use crate::{exec, exec_user, fileops, gui, screenshot, selfupdate, session, sync};

/// Result of dispatching a request.
pub enum DispatchResult {
    /// Normal response — send to client and continue request loop.
    Response(Response),
    /// Connection is hijacked — handler takes ownership of the stream.
    Hijack(HijackAction),
    /// Sync streaming — handler writes binary data, then continues request loop.
    SyncStream(SyncStreamAction),
}

/// Streaming operations that write directly to the connection but don't hijack it.
pub enum SyncStreamAction {
    /// Binary pull-delta protocol: M (match) / D (data) / E (end) markers.
    PullDelta,
    /// Binary batch-patch: JSON metadata + raw binary blob (two messages).
    BatchPatchBin,
}

/// Actions that hijack the connection (exit the request loop).
pub enum HijackAction {
    /// TCP tunnel to target host:port.
    Connect { target: String },
    /// Interactive shell session.
    Shell { size: String, env_vars: Vec<String> },
    /// Persistent shell session (create or reattach).
    ShellPersistent {
        size: String,
        session_id: Option<String>,
        readonly: bool,
        env_vars: Vec<String>,
    },
}

/// Dispatch a request, returning either a Response or a HijackAction.
pub async fn dispatch(
    req: &protocol::Request,
    session_store: &session::SessionStore,
) -> DispatchResult {
    debug!("dispatch: type={}", req.req_type);

    match req.req_type.as_str() {
        "ping" => DispatchResult::Response(Response {
            success: true,
            output: Some("pong".to_string()),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        }),

        "exec" => {
            let cmd = req.command.as_deref().unwrap_or("");
            let env_vars = req.env_vars.as_deref().unwrap_or(&[]);
            DispatchResult::Response(exec::handle_exec(cmd, env_vars).await)
        }

        "exec-as-user" => {
            let cmd = req.command.as_deref().unwrap_or("");
            let env_vars = req.env_vars.as_deref().unwrap_or(&[]);
            DispatchResult::Response(exec_user::handle_exec_as_user(cmd, env_vars).await)
        }

        "ls" => {
            let path = req.path.as_deref().unwrap_or(".");
            DispatchResult::Response(fileops::handle_ls(path))
        }

        "read" | "cat" => {
            let path = match req.path.as_deref() {
                Some(p) => p,
                None => return DispatchResult::Response(error_response("missing path")),
            };
            DispatchResult::Response(fileops::handle_read(path))
        }

        "write" => {
            let path = match req.path.as_deref() {
                Some(p) => p,
                None => return DispatchResult::Response(error_response("missing path")),
            };
            let content = match req.content.as_deref() {
                Some(c) => c,
                None => return DispatchResult::Response(error_response("missing content")),
            };
            DispatchResult::Response(fileops::handle_write(path, content))
        }

        "connect" => {
            let target = match req.command.as_deref() {
                Some(t) => t.to_string(),
                None => {
                    return DispatchResult::Response(error_response(
                        "missing target (command field)",
                    ));
                }
            };
            DispatchResult::Hijack(HijackAction::Connect { target })
        }

        "shell" => {
            let size = req.command.as_deref().unwrap_or("80x24").to_string();
            let env_vars = req.env_vars.clone().unwrap_or_default();
            DispatchResult::Hijack(HijackAction::Shell { size, env_vars })
        }

        "shell-persistent" => {
            let size = req.command.as_deref().unwrap_or("80x24").to_string();
            let session_id = req.path.clone().filter(|s| !s.is_empty());
            let readonly = req.binary.unwrap_or(false);
            let env_vars = req.env_vars.clone().unwrap_or_default();
            DispatchResult::Hijack(HijackAction::ShellPersistent {
                size,
                session_id,
                readonly,
                env_vars,
            })
        }

        "session" => {
            let cmd = req.command.as_deref().unwrap_or("");
            let resp = handle_session_command(cmd, req.path.as_deref(), session_store).await;
            DispatchResult::Response(resp)
        }

        "sync" => {
            let sync_type = req.sync_type.as_deref().unwrap_or("");
            match sync_type {
                "pull-delta" => DispatchResult::SyncStream(SyncStreamAction::PullDelta),
                "batch-patch-bin" => DispatchResult::SyncStream(SyncStreamAction::BatchPatchBin),
                _ => DispatchResult::Response(sync::handle_sync(req)),
            }
        }

        "self-update" => {
            let path = match req.path.as_deref() {
                Some(p) => p,
                None => {
                    return DispatchResult::Response(error_response("missing path for self-update"));
                }
            };
            DispatchResult::Response(selfupdate::handle_self_update(path))
        }

        // Client sends Command="mouse move 500 300" as single string
        "input" => {
            let cmd_str = req.command.as_deref().unwrap_or("");
            let parts: Vec<&str> = cmd_str.split_whitespace().collect();
            if parts.len() < 2 {
                DispatchResult::Response(error_response(
                    "input requires: <type> <action> [args...]",
                ))
            } else {
                let args = if parts.len() > 2 {
                    parts[2..].join(" ")
                } else {
                    String::new()
                };
                DispatchResult::Response(gui::handle_input(parts[0], parts[1], &args))
            }
        }

        // Client sends Type="native", Command="screenshot 0 80 100" etc.
        "native" => {
            let cmd_str = req.command.as_deref().unwrap_or("");
            let parts: Vec<&str> = cmd_str.split_whitespace().collect();
            if parts.is_empty() {
                return DispatchResult::Response(error_response(
                    "native requires: <command> [args...]",
                ));
            }
            DispatchResult::Response(handle_native_command(parts[0], &parts[1..]).await)
        }

        // Direct screenshot (Rust client path)
        "screenshot" => {
            let display: u32 = req
                .command
                .as_deref()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let quality: u8 = req
                .content
                .as_deref()
                .and_then(|s| s.parse().ok())
                .unwrap_or(80);
            let scale: u8 = req
                .path
                .as_deref()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100);
            DispatchResult::Response(screenshot::handle_screenshot(display, quality, scale))
        }

        other => DispatchResult::Response(error_response(&format!("unknown command: {}", other))),
    }
}

/// Backward-compatible dispatch that returns only Response (no hijack).
pub async fn handle_request(req: &protocol::Request) -> Response {
    let store = session::SessionStore::new();
    match dispatch(req, &store).await {
        DispatchResult::Response(r) => r,
        DispatchResult::Hijack(_) => error_response("hijack not supported in this context"),
        DispatchResult::SyncStream(_) => {
            error_response("sync stream not supported in this context")
        }
    }
}

/// Handle session management commands (list, kill).
async fn handle_session_command(
    cmd: &str,
    path: Option<&str>,
    store: &session::SessionStore,
) -> Response {
    match cmd {
        "list" => {
            let sessions = store.list().await;
            let output = serde_json::to_string(&sessions).unwrap_or_default();
            Response {
                success: true,
                output: Some(output),
                error: None,
                size: None,
                binary: None,
                gzip: None,
            }
        }
        "kill" => {
            let id = match path {
                Some(id) => id,
                None => return error_response("missing session id"),
            };
            if store.kill(id).await {
                Response {
                    success: true,
                    output: Some("session destroyed".to_string()),
                    error: None,
                    size: None,
                    binary: None,
                    gzip: None,
                }
            } else {
                error_response(&format!("session not found: {}", id))
            }
        }
        other => error_response(&format!("unknown session command: {}", other)),
    }
}

/// Handle "native" sub-commands.
/// Command string is split by whitespace: "screenshot 0 80 100" → ["screenshot", "0", "80", "100"]
async fn handle_native_command(cmd: &str, args: &[&str]) -> Response {
    match cmd {
        "screenshot" => {
            let display: u32 = args.first().and_then(|s| s.parse().ok()).unwrap_or(0);
            let quality: u8 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(80);
            let scale: u8 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(100);
            screenshot::handle_screenshot(display, quality, scale)
        }
        "screenshot-diag" => Response {
            success: true,
            output: Some("screenshot diagnostics: rust server".to_string()),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        },
        "ps" => {
            exec::handle_exec("Get-Process | Select-Object Id,ProcessName,CPU,WorkingSet64 | ConvertTo-Json", &[]).await
        }
        "kill" => {
            let pid_str = args.first().unwrap_or(&"");
            match pid_str.parse::<u32>() {
                Ok(pid) => {
                    exec::handle_exec(&format!("Stop-Process -Id {} -Force", pid), &[]).await
                }
                Err(_) => error_response("invalid pid: must be a positive integer"),
            }
        }
        "tail" => {
            let path = args.first().unwrap_or(&"");
            let lines: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(100);
            // Escape single quotes for PowerShell ('' is literal single quote)
            let escaped_path = path.replace('\'', "''");
            exec::handle_exec(
                &format!("Get-Content '{}' -Tail {}", escaped_path, lines),
                &[],
            )
            .await
        }
        "info" => {
            exec::handle_exec("[PSCustomObject]@{Hostname=$env:COMPUTERNAME; OS=[Environment]::OSVersion.VersionString; Arch=[Environment]::Is64BitOperatingSystem} | ConvertTo-Json", &[]).await
        }
        "clip-get" => exec::handle_exec("Get-Clipboard", &[]).await,
        "clip-set" => {
            let text = args.join(" ");
            exec::handle_exec(&format!("Set-Clipboard -Value '{}'", text.replace('\'', "''")), &[]).await
        }
        other => error_response(&format!("unknown native command: {}", other)),
    }
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
    use rsh_core::protocol::{FileInfo, Request};

    fn make_request(req_type: &str) -> Request {
        Request {
            req_type: req_type.to_string(),
            command: None,
            path: None,
            content: None,
            binary: None,
            gzip: None,
            sync_type: None,
            delta: None,
            signatures: None,
            paths: None,
            batch_patches: None,
            env_vars: None,
        }
    }

    #[tokio::test]
    async fn ping_returns_pong() {
        let req = make_request("ping");
        let resp = handle_request(&req).await;
        assert!(resp.success);
        assert_eq!(resp.output.as_deref(), Some("pong"));
    }

    #[tokio::test]
    async fn unknown_command_returns_error() {
        let req = make_request("nonexistent");
        let resp = handle_request(&req).await;
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("unknown command"));
    }

    #[tokio::test]
    async fn read_without_path_returns_error() {
        let req = make_request("read");
        let resp = handle_request(&req).await;
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("missing path"));
    }

    #[tokio::test]
    async fn write_without_path_returns_error() {
        let req = make_request("write");
        let resp = handle_request(&req).await;
        assert!(!resp.success);
    }

    #[tokio::test]
    async fn ls_current_dir() {
        let mut req = make_request("ls");
        req.path = Some(".".to_string());
        let resp = handle_request(&req).await;
        assert!(resp.success);
        let files: Vec<FileInfo> = serde_json::from_str(resp.output.as_deref().unwrap()).unwrap();
        assert!(!files.is_empty());
    }

    #[tokio::test]
    async fn connect_returns_hijack() {
        let store = session::SessionStore::new();
        let mut req = make_request("connect");
        req.command = Some("localhost:8080".to_string());
        match dispatch(&req, &store).await {
            DispatchResult::Hijack(HijackAction::Connect { target }) => {
                assert_eq!(target, "localhost:8080");
            }
            _ => panic!("expected Hijack::Connect"),
        }
    }

    #[tokio::test]
    async fn shell_returns_hijack() {
        let store = session::SessionStore::new();
        let mut req = make_request("shell");
        req.command = Some("120x40".to_string());
        match dispatch(&req, &store).await {
            DispatchResult::Hijack(HijackAction::Shell { size, .. }) => {
                assert_eq!(size, "120x40");
            }
            _ => panic!("expected Hijack::Shell"),
        }
    }

    #[tokio::test]
    async fn session_list_empty() {
        let store = session::SessionStore::new();
        let mut req = make_request("session");
        req.command = Some("list".to_string());
        match dispatch(&req, &store).await {
            DispatchResult::Response(resp) => {
                assert!(resp.success);
                let sessions: Vec<session::SessionInfo> =
                    serde_json::from_str(resp.output.as_deref().unwrap()).unwrap();
                assert!(sessions.is_empty());
            }
            _ => panic!("expected Response"),
        }
    }

    #[tokio::test]
    async fn session_kill_nonexistent() {
        let store = session::SessionStore::new();
        let mut req = make_request("session");
        req.command = Some("kill".to_string());
        req.path = Some("nonexistent".to_string());
        match dispatch(&req, &store).await {
            DispatchResult::Response(resp) => {
                assert!(!resp.success);
            }
            _ => panic!("expected Response"),
        }
    }

    #[tokio::test]
    async fn self_update_missing_path() {
        let req = make_request("self-update");
        let resp = handle_request(&req).await;
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("missing path"));
    }

    #[tokio::test]
    async fn native_empty_command() {
        let mut req = make_request("native");
        req.command = Some("".to_string());
        let resp = handle_request(&req).await;
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("native requires"));
    }

    #[tokio::test]
    async fn native_unknown_subcommand() {
        let mut req = make_request("native");
        req.command = Some("nonexistent".to_string());
        let resp = handle_request(&req).await;
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("unknown native command"));
    }

    #[tokio::test]
    async fn native_kill_rejects_non_numeric_pid() {
        let mut req = make_request("native");
        req.command = Some("kill ; rm -rf /".to_string());
        let resp = handle_request(&req).await;
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("invalid pid"));
    }

    #[tokio::test]
    async fn native_kill_rejects_negative_pid() {
        let mut req = make_request("native");
        req.command = Some("kill -1".to_string());
        let resp = handle_request(&req).await;
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("invalid pid"));
    }

    #[tokio::test]
    async fn native_screenshot_diag() {
        let mut req = make_request("native");
        req.command = Some("screenshot-diag".to_string());
        let resp = handle_request(&req).await;
        assert!(resp.success);
        assert!(resp.output.unwrap().contains("diagnostics"));
    }

    #[tokio::test]
    async fn input_split_command() {
        // Client sends Command="mouse pos" as single string
        let mut req = make_request("input");
        req.command = Some("mouse pos".to_string());
        let resp = handle_request(&req).await;
        // On non-Windows: error about platform, but should parse correctly
        #[cfg(not(target_os = "windows"))]
        {
            assert!(!resp.success);
            assert!(resp.error.unwrap().contains("not available"));
        }
    }

    #[tokio::test]
    async fn input_missing_action() {
        let mut req = make_request("input");
        req.command = Some("mouse".to_string()); // only type, no action
        let resp = handle_request(&req).await;
        assert!(!resp.success);
        assert!(resp.error.unwrap().contains("input requires"));
    }

    // --- Command format regression tests (dc2289e) ---

    /// Keyboard commands: "key <action> <args>"
    #[tokio::test]
    async fn input_keyboard_command_format() {
        let mut req = make_request("input");
        req.command = Some("key type hello".to_string());
        let resp = handle_request(&req).await;
        #[cfg(not(target_os = "windows"))]
        {
            assert!(!resp.success);
            assert!(resp.error.unwrap().contains("not available"));
        }
    }

    /// Window commands: "window <action> <args>"
    #[tokio::test]
    async fn input_window_command_format() {
        let mut req = make_request("input");
        req.command = Some("window list".to_string());
        let resp = handle_request(&req).await;
        #[cfg(not(target_os = "windows"))]
        {
            assert!(!resp.success);
            assert!(resp.error.unwrap().contains("not available"));
        }
    }

    /// Mouse drag: "mouse drag x1 y1 x2 y2"
    #[tokio::test]
    async fn input_mouse_drag_format() {
        let mut req = make_request("input");
        req.command = Some("mouse drag 100 200 300 400".to_string());
        let resp = handle_request(&req).await;
        #[cfg(not(target_os = "windows"))]
        {
            assert!(!resp.success);
            assert!(resp.error.unwrap().contains("not available"));
        }
    }

    /// "native" commands dispatch correctly
    #[tokio::test]
    async fn native_info_command() {
        let mut req = make_request("native");
        req.command = Some("info".to_string());
        let resp = handle_request(&req).await;
        // On Linux: native commands delegate to exec (PowerShell) which fails
        #[cfg(not(target_os = "windows"))]
        {
            assert!(!resp.success);
        }
    }

    /// Verify "native" ps command dispatches correctly
    #[tokio::test]
    async fn native_ps_command() {
        let mut req = make_request("native");
        req.command = Some("ps".to_string());
        let resp = handle_request(&req).await;
        // On Linux: native commands delegate to exec (PowerShell) which fails
        #[cfg(not(target_os = "windows"))]
        {
            assert!(!resp.success);
        }
    }

    /// Verify that exec type is dispatched (even if command fails on Linux)
    #[tokio::test]
    async fn exec_dispatches_command() {
        let mut req = make_request("exec");
        req.command = Some("echo test".to_string());
        let resp = handle_request(&req).await;
        // On Linux: powershell not available, but dispatch happens
        // On Windows: would execute powershell
        #[cfg(not(target_os = "windows"))]
        {
            // exec uses powershell -NoProfile -Command, which doesn't exist on Linux
            // but the dispatch itself should happen (not "unknown type")
            assert!(
                !resp.error.as_deref().unwrap_or("").contains("unknown")
            );
        }
    }
}
