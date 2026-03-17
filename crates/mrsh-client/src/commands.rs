//! Client commands — ping, exec, ls, cat, screenshot, etc.
//! Each command builds a request, sends it, and formats the response.

use anyhow::{Result, bail};
use base64::Engine;
use mrsh_core::protocol::{FileInfo, Request, Response};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::{RshClient, simple_request};

// ── Ping ─────────────────────────────────────────────────────────

/// Ping the server, returns "pong" on success.
pub async fn ping<S: AsyncRead + AsyncWrite + Unpin>(client: &mut RshClient<S>) -> Result<String> {
    let resp = client.request(&simple_request("ping")).await?;
    check_response(&resp)?;
    Ok(resp.output.unwrap_or_default())
}

// ── Exec ─────────────────────────────────────────────────────────

/// Execute a command on the remote host.
pub async fn exec<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    command: &str,
    env_vars: &[String],
) -> Result<String> {
    let mut req = simple_request("exec");
    req.command = Some(command.to_string());
    if !env_vars.is_empty() {
        req.env_vars = Some(env_vars.to_vec());
    }
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(resp.output.unwrap_or_default())
}

// ── Ls ───────────────────────────────────────────────────────────

/// List a remote directory, returns parsed file entries.
pub async fn ls<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    path: &str,
) -> Result<Vec<FileInfo>> {
    let mut req = simple_request("ls");
    req.path = Some(path.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    let json = resp.output.unwrap_or_default();
    let files: Vec<FileInfo> =
        serde_json::from_str(&json).map_err(|e| anyhow::anyhow!("parse ls response: {}", e))?;
    Ok(files)
}

// ── Cat (read file) ──────────────────────────────────────────────

/// Read a remote file, returns raw bytes (decoded from base64).
pub async fn cat<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    path: &str,
) -> Result<Vec<u8>> {
    let mut req = simple_request("cat");
    req.path = Some(path.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    let b64 = resp.output.unwrap_or_default();
    if resp.binary.unwrap_or(false) {
        let data = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| anyhow::anyhow!("decode base64: {}", e))?;
        Ok(data)
    } else {
        Ok(b64.into_bytes())
    }
}

/// Read a remote file as text.
pub async fn cat_text<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    path: &str,
) -> Result<String> {
    let data = cat(client, path).await?;
    String::from_utf8(data).map_err(|e| anyhow::anyhow!("file is not valid UTF-8: {}", e))
}

// ── Write ────────────────────────────────────────────────────────

/// Write content to a remote file (base64-encoded).
pub async fn write_file<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    path: &str,
    content: &[u8],
) -> Result<()> {
    let mut req = simple_request("write");
    req.path = Some(path.to_string());
    req.content = Some(base64::engine::general_purpose::STANDARD.encode(content));
    req.binary = Some(true);
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(())
}

// ── Screenshot ───────────────────────────────────────────────────

/// Capture a screenshot from the remote host.
/// Returns raw image bytes (JPEG or raw RGBA).
pub async fn screenshot<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    display: u32,
    quality: u8,
    scale: u8,
) -> Result<Vec<u8>> {
    let mut req = simple_request("screenshot");
    req.command = Some(display.to_string());
    req.content = Some(quality.to_string());
    req.path = Some(scale.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    let b64 = resp.output.unwrap_or_default();
    let data = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| anyhow::anyhow!("decode screenshot: {}", e))?;
    Ok(data)
}

// ── Session management ───────────────────────────────────────────

/// List persistent shell sessions.
pub async fn sessions_list<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
) -> Result<String> {
    let mut req = simple_request("session");
    req.command = Some("list".to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(resp.output.unwrap_or_default())
}

/// Kill a persistent session by ID.
pub async fn session_kill<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    session_id: &str,
) -> Result<()> {
    let mut req = simple_request("session");
    req.command = Some("kill".to_string());
    req.path = Some(session_id.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(())
}

// ── Self-update ──────────────────────────────────────────────────

/// Trigger self-update on the remote server.
pub async fn self_update<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    binary_path: &str,
) -> Result<String> {
    let mut req = simple_request("self-update");
    req.path = Some(binary_path.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(resp.output.unwrap_or_default())
}

// ── GUI input ────────────────────────────────────────────────────

/// Send a GUI input command (mouse/key/window).
pub async fn input<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    command: &str,
    action: &str,
    args: &str,
) -> Result<String> {
    let mut req = simple_request("input");
    // Server expects Command="mouse pos 500,300" as single space-separated string
    let cmd = if args.is_empty() {
        format!("{} {}", command, action)
    } else {
        format!("{} {} {}", command, action, args)
    };
    req.command = Some(cmd);
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(resp.output.unwrap_or_default())
}

// ── Native commands ──────────────────────────────────────────────

/// Send a "native" command to the server.
/// Most system commands (ps, clip, eventlog, info, service, etc.)
/// use `Request { type: "native", command: "<subcmd> <args>" }`.
pub async fn native<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    command: &str,
) -> Result<String> {
    let mut req = simple_request("native");
    req.command = Some(command.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(resp.output.unwrap_or_default())
}

/// List remote processes.
pub async fn ps<S: AsyncRead + AsyncWrite + Unpin>(client: &mut RshClient<S>) -> Result<String> {
    native(client, "ps").await
}

/// Kill a remote process by PID.
pub async fn kill_process<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    pid: &str,
) -> Result<String> {
    native(client, &format!("kill {}", pid)).await
}

/// Tail a remote file.
pub async fn tail<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    path: &str,
    lines: u32,
) -> Result<String> {
    native(client, &format!("tail {} {}", path, lines)).await
}

/// Get file version info (Windows PE).
pub async fn filever<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    path: &str,
) -> Result<String> {
    native(client, &format!("filever {}", path)).await
}

/// Get system info.
pub async fn info<S: AsyncRead + AsyncWrite + Unpin>(client: &mut RshClient<S>) -> Result<String> {
    native(client, "info").await
}

/// Query Windows Event Log.
pub async fn eventlog<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    log_name: &str,
    count: u32,
) -> Result<String> {
    native(client, &format!("eventlog {} {}", log_name, count)).await
}

/// Clipboard get.
pub async fn clip_get<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
) -> Result<String> {
    native(client, "clip-get").await
}

/// Clipboard set.
pub async fn clip_set<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    text: &str,
) -> Result<String> {
    native(client, &format!("clip-set {}", text)).await
}

/// Bidirectional clipboard sync — polls local and remote, syncs changes.
///
/// Runs until cancelled (Ctrl+C). Uses `clip-get`/`clip-set` commands
/// under the hood, polling every `interval`.
pub async fn clip_sync<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    interval: std::time::Duration,
) -> Result<()> {
    use std::io::Write;

    let mut last_local = get_local_clipboard().unwrap_or_default();
    let mut last_remote = native(client, "clip-get").await.unwrap_or_default();

    eprintln!("Clipboard sync active (poll {}ms). Ctrl+C to stop.", interval.as_millis());

    loop {
        tokio::time::sleep(interval).await;

        // Check local clipboard
        let local = get_local_clipboard().unwrap_or_default();
        if !local.is_empty() && local != last_local {
            // Local changed → push to remote
            if native(client, &format!("clip-set {}", local)).await.is_ok() {
                eprint!("→ ");
                std::io::stderr().flush().ok();
                last_local = local.clone();
                last_remote = local;
            }
            continue;
        }

        // Check remote clipboard
        match native(client, "clip-get").await {
            Ok(remote) if !remote.is_empty() && remote != last_remote => {
                // Remote changed → pull to local
                if set_local_clipboard(&remote).is_ok() {
                    eprint!("← ");
                    std::io::stderr().flush().ok();
                    last_remote = remote.clone();
                    last_local = remote;
                }
            }
            _ => {}
        }
    }
}

/// Get local clipboard text (cross-platform via PowerShell on Windows, xclip/xsel on Linux).
fn get_local_clipboard() -> Result<String> {
    #[cfg(target_os = "windows")]
    {
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-Clipboard"])
            .output()?;
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Try xclip first, then xsel
        let out = std::process::Command::new("xclip")
            .args(["-selection", "clipboard", "-o"])
            .output()
            .or_else(|_| {
                std::process::Command::new("xsel")
                    .args(["--clipboard", "--output"])
                    .output()
            });
        match out {
            Ok(o) => Ok(String::from_utf8_lossy(&o.stdout).trim().to_string()),
            Err(e) => bail!("clipboard read failed (install xclip or xsel): {}", e),
        }
    }
}

/// Set local clipboard text.
fn set_local_clipboard(text: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &format!("Set-Clipboard -Value '{}'", text.replace('\'', "''"))])
            .output()?;
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        use std::io::Write;
        let mut child = std::process::Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .or_else(|_| {
                std::process::Command::new("xsel")
                    .args(["--clipboard", "--input"])
                    .stdin(std::process::Stdio::piped())
                    .spawn()
            })?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(text.as_bytes())?;
        }
        child.wait()?;
        Ok(())
    }
}

/// Service management (list, status, start, stop, restart).
pub async fn service<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    action: &str,
    name: Option<&str>,
) -> Result<String> {
    let cmd = match name {
        Some(n) => format!("service {} {}", action, n),
        None => format!("service {}", action),
    };
    native(client, &cmd).await
}

/// Plugin management.
pub async fn plugin<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    args: &str,
) -> Result<String> {
    let mut req = simple_request("plugin");
    req.command = Some(args.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;
    Ok(resp.output.unwrap_or_default())
}

// ── Helpers ──────────────────────────────────────────────────────

fn check_response(resp: &Response) -> Result<()> {
    if !resp.success {
        bail!("{}", resp.error.as_deref().unwrap_or("unknown error"));
    }
    Ok(())
}

/// Build a request with arbitrary fields.
pub fn build_request(
    req_type: &str,
    command: Option<&str>,
    path: Option<&str>,
    content: Option<&str>,
) -> Request {
    Request {
        req_type: req_type.to_string(),
        command: command.map(|s| s.to_string()),
        path: path.map(|s| s.to_string()),
        content: content.map(|s| s.to_string()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::RshClient;
    use mrsh_core::wire;
    use tokio::io::DuplexStream;

    #[test]
    fn check_response_ok() {
        let resp = Response {
            success: true,
            output: Some("ok".to_string()),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        };
        assert!(check_response(&resp).is_ok());
    }

    #[test]
    fn check_response_error() {
        let resp = Response {
            success: false,
            output: None,
            error: Some("test error".to_string()),
            size: None,
            binary: None,
            gzip: None,
        };
        let err = check_response(&resp).unwrap_err();
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn build_request_fields() {
        let req = build_request("exec", Some("hostname"), None, None);
        assert_eq!(req.req_type, "exec");
        assert_eq!(req.command.as_deref(), Some("hostname"));
        assert!(req.path.is_none());
    }

    #[test]
    fn build_request_all_fields() {
        let req = build_request("write", None, Some("/tmp/test"), Some("content"));
        assert_eq!(req.req_type, "write");
        assert_eq!(req.path.as_deref(), Some("/tmp/test"));
        assert_eq!(req.content.as_deref(), Some("content"));
    }

    // ── Mock infrastructure ─────────────────────────────────────────

    /// Create a mock client + server stream pair.
    fn mock_client() -> (RshClient<DuplexStream>, DuplexStream) {
        let (client_end, server_end) = tokio::io::duplex(8192);
        (RshClient::new_mock(client_end), server_end)
    }

    /// Spawn a mock server that reads a Request, validates it, then sends a canned Response.
    fn spawn_mock_server(
        mut server: DuplexStream,
        validate: impl FnOnce(&Request) + Send + 'static,
        response: Response,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            validate(&req);
            wire::send_json(&mut server, &response).await.unwrap();
        })
    }

    fn ok_response(output: &str) -> Response {
        Response {
            success: true,
            output: Some(output.to_string()),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        }
    }

    fn ok_response_binary(output: &str) -> Response {
        Response {
            success: true,
            output: Some(output.to_string()),
            error: None,
            size: None,
            binary: Some(true),
            gzip: None,
        }
    }

    fn err_response(error: &str) -> Response {
        Response {
            success: false,
            output: None,
            error: Some(error.to_string()),
            size: None,
            binary: None,
            gzip: None,
        }
    }

    // ── Ping ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn ping_sends_request_returns_pong() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.req_type, "ping");
        }, ok_response("pong"));

        let result = ping(&mut client).await.unwrap();
        assert_eq!(result, "pong");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn ping_propagates_error() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, err_response("server busy"));

        let err = ping(&mut client).await.unwrap_err();
        assert!(err.to_string().contains("server busy"));
        h.await.unwrap();
    }

    // ── Exec ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn exec_sends_command() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.req_type, "exec");
            assert_eq!(req.command.as_deref(), Some("hostname"));
            assert!(req.env_vars.is_none());
        }, ok_response("myhost"));

        let result = exec(&mut client, "hostname", &[]).await.unwrap();
        assert_eq!(result, "myhost");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn exec_sends_env_vars() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.req_type, "exec");
            let env = req.env_vars.as_ref().unwrap();
            assert_eq!(env, &["FOO=bar".to_string()]);
        }, ok_response("ok"));

        let result = exec(&mut client, "echo $FOO", &["FOO=bar".to_string()]).await.unwrap();
        assert_eq!(result, "ok");
        h.await.unwrap();
    }

    // ── Ls ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn ls_parses_file_info() {
        let (mut client, server) = mock_client();
        let json = r#"[{"name":"file.txt","size":42,"mode":"-rw-r--r--","is_dir":false,"mod_time":"2026-01-01T00:00:00Z"}]"#;
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.req_type, "ls");
            assert_eq!(req.path.as_deref(), Some("/tmp"));
        }, ok_response(json));

        let files = ls(&mut client, "/tmp").await.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "file.txt");
        assert_eq!(files[0].size, 42);
        assert!(!files[0].is_dir);
        h.await.unwrap();
    }

    #[tokio::test]
    async fn ls_empty_dir() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, ok_response("[]"));

        let files = ls(&mut client, "/empty").await.unwrap();
        assert!(files.is_empty());
        h.await.unwrap();
    }

    // ── Cat ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn cat_binary_decodes_base64() {
        let (mut client, server) = mock_client();
        let content = b"hello binary";
        let b64 = base64::engine::general_purpose::STANDARD.encode(content);
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.req_type, "cat");
            assert_eq!(req.path.as_deref(), Some("/bin/test"));
        }, ok_response_binary(&b64));

        let data = cat(&mut client, "/bin/test").await.unwrap();
        assert_eq!(data, content);
        h.await.unwrap();
    }

    #[tokio::test]
    async fn cat_text_returns_string() {
        let (mut client, server) = mock_client();
        // Non-binary response: output is returned as-is (bytes of the string)
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.req_type, "cat");
        }, ok_response("hello text"));

        let data = cat(&mut client, "/etc/hostname").await.unwrap();
        assert_eq!(data, b"hello text");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn cat_text_fn_returns_string() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, ok_response("line1\nline2"));

        let text = cat_text(&mut client, "/etc/hosts").await.unwrap();
        assert_eq!(text, "line1\nline2");
        h.await.unwrap();
    }

    // ── Write ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn write_file_encodes_base64() {
        let (mut client, server) = mock_client();
        let content = b"file content";
        let expected_b64 = base64::engine::general_purpose::STANDARD.encode(content);
        let h = spawn_mock_server(server, move |req| {
            assert_eq!(req.req_type, "write");
            assert_eq!(req.path.as_deref(), Some("/tmp/out.txt"));
            assert_eq!(req.content.as_deref(), Some(expected_b64.as_str()));
            assert_eq!(req.binary, Some(true));
        }, ok_response(""));

        write_file(&mut client, "/tmp/out.txt", content).await.unwrap();
        h.await.unwrap();
    }

    // ── Screenshot ───────────────────────────────────────────────────

    #[tokio::test]
    async fn screenshot_decodes_base64() {
        let (mut client, server) = mock_client();
        let fake_jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG magic
        let b64 = base64::engine::general_purpose::STANDARD.encode(&fake_jpeg);
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.req_type, "screenshot");
            assert_eq!(req.command.as_deref(), Some("0")); // display
            assert_eq!(req.content.as_deref(), Some("80")); // quality
            assert_eq!(req.path.as_deref(), Some("50")); // scale
        }, ok_response(&b64));

        let data = screenshot(&mut client, 0, 80, 50).await.unwrap();
        assert_eq!(data, fake_jpeg);
        h.await.unwrap();
    }

    // ── Sessions ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn sessions_list_sends_correct_request() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.req_type, "session");
            assert_eq!(req.command.as_deref(), Some("list"));
        }, ok_response("sess1\nsess2"));

        let result = sessions_list(&mut client).await.unwrap();
        assert!(result.contains("sess1"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn session_kill_sends_correct_request() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.req_type, "session");
            assert_eq!(req.command.as_deref(), Some("kill"));
            assert_eq!(req.path.as_deref(), Some("abc123"));
        }, ok_response(""));

        session_kill(&mut client, "abc123").await.unwrap();
        h.await.unwrap();
    }

    // ── Self-update ──────────────────────────────────────────────────

    #[tokio::test]
    async fn self_update_sends_path() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.req_type, "self-update");
            assert_eq!(req.path.as_deref(), Some("/opt/rsh/rsh-new"));
        }, ok_response("updated to v5.5.0"));

        let result = self_update(&mut client, "/opt/rsh/rsh-new").await.unwrap();
        assert!(result.contains("5.5.0"));
        h.await.unwrap();
    }

    // ── Input ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn input_formats_command() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.req_type, "input");
            assert_eq!(req.command.as_deref(), Some("mouse pos 500,300"));
        }, ok_response("ok"));

        let result = input(&mut client, "mouse", "pos", "500,300").await.unwrap();
        assert_eq!(result, "ok");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn input_no_args() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.command.as_deref(), Some("key enter"));
        }, ok_response(""));

        input(&mut client, "key", "enter", "").await.unwrap();
        h.await.unwrap();
    }

    // ── Native + wrappers ────────────────────────────────────────────

    #[tokio::test]
    async fn native_sends_command() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.req_type, "native");
            assert_eq!(req.command.as_deref(), Some("info"));
        }, ok_response("Windows 11"));

        let result = native(&mut client, "info").await.unwrap();
        assert_eq!(result, "Windows 11");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn ps_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.req_type, "native");
            assert_eq!(req.command.as_deref(), Some("ps"));
        }, ok_response("PID 1234 explorer.exe"));

        let result = ps(&mut client).await.unwrap();
        assert!(result.contains("explorer.exe"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn kill_process_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.command.as_deref(), Some("kill 1234"));
        }, ok_response("killed"));

        let result = kill_process(&mut client, "1234").await.unwrap();
        assert_eq!(result, "killed");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn tail_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.command.as_deref(), Some("tail /var/log/syslog 20"));
        }, ok_response("last line"));

        let result = tail(&mut client, "/var/log/syslog", 20).await.unwrap();
        assert_eq!(result, "last line");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn filever_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.command.as_deref(), Some("filever C:\\app.exe"));
        }, ok_response("1.0.0.0"));

        let result = filever(&mut client, "C:\\app.exe").await.unwrap();
        assert_eq!(result, "1.0.0.0");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn info_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.command.as_deref(), Some("info"));
        }, ok_response("hostname: test"));

        let result = info(&mut client).await.unwrap();
        assert!(result.contains("hostname"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn eventlog_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.command.as_deref(), Some("eventlog System 10"));
        }, ok_response("event data"));

        let result = eventlog(&mut client, "System", 10).await.unwrap();
        assert_eq!(result, "event data");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn clip_get_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.command.as_deref(), Some("clip-get"));
        }, ok_response("clipboard content"));

        let result = clip_get(&mut client).await.unwrap();
        assert_eq!(result, "clipboard content");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn clip_set_wrapper() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.command.as_deref(), Some("clip-set hello world"));
        }, ok_response("ok"));

        let result = clip_set(&mut client, "hello world").await.unwrap();
        assert_eq!(result, "ok");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn service_with_name() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.command.as_deref(), Some("service status nginx"));
        }, ok_response("running"));

        let result = service(&mut client, "status", Some("nginx")).await.unwrap();
        assert_eq!(result, "running");
        h.await.unwrap();
    }

    #[tokio::test]
    async fn service_without_name() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.command.as_deref(), Some("service list"));
        }, ok_response("svc1\nsvc2"));

        let result = service(&mut client, "list", None).await.unwrap();
        assert!(result.contains("svc1"));
        h.await.unwrap();
    }

    // ── Plugin ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn plugin_sends_correct_request() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |req| {
            assert_eq!(req.req_type, "plugin");
            assert_eq!(req.command.as_deref(), Some("list"));
        }, ok_response("plugin1 v1.0"));

        let result = plugin(&mut client, "list").await.unwrap();
        assert!(result.contains("plugin1"));
        h.await.unwrap();
    }

    // ── Error propagation ────────────────────────────────────────────

    #[tokio::test]
    async fn exec_error_propagates() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, err_response("command not found"));

        let err = exec(&mut client, "nosuchcmd", &[]).await.unwrap_err();
        assert!(err.to_string().contains("command not found"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn ls_error_propagates() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, err_response("access denied"));

        let err = ls(&mut client, "/root").await.unwrap_err();
        assert!(err.to_string().contains("access denied"));
        h.await.unwrap();
    }

    #[tokio::test]
    async fn write_file_error_propagates() {
        let (mut client, server) = mock_client();
        let h = spawn_mock_server(server, |_| {}, err_response("disk full"));

        let err = write_file(&mut client, "/tmp/big", b"data").await.unwrap_err();
        assert!(err.to_string().contains("disk full"));
        h.await.unwrap();
    }
}
