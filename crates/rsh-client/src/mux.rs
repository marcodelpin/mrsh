//! Control master: connection multiplexing via local Unix socket.
//! One master process holds an authenticated TLS connection; multiple
//! rsh invocations reuse it through the socket, avoiding TLS+auth
//! overhead on every command.
//!
//! Usage:
//!   rsh -h host -M          Start master (foreground, Ctrl+C to stop)
//!   rsh -h host exec cmd    Auto-uses master if running
//!   rsh -h host --no-mux    Skip multiplexing, always open new connection
//!   rsh -h host --mux-stop  Stop running master for this host

use std::path::PathBuf;

use anyhow::{Result, bail};
use rsh_core::protocol;

#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use rsh_core::wire;

#[cfg(unix)]
use tracing::{debug, info, warn};

#[cfg(unix)]
const IDLE_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
#[cfg(unix)]
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);

/// Get the socket path for a given host:port.
pub fn socket_path(host: &str, port: u16) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        let home = std::env::var("HOME").ok()?;
        let dir = PathBuf::from(home).join(".rsh").join("sockets");
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir.join(format!("{}-{}.sock", host, port)))
    }
    #[cfg(not(unix))]
    {
        let _ = (host, port);
        None
    }
}

/// Try to send a request through an existing master.
/// Returns the response if successful, None if no master running.
#[cfg(unix)]
pub async fn try_request(
    host: &str,
    port: u16,
    req: &protocol::Request,
) -> Option<protocol::Response> {
    let sock_path = socket_path(host, port)?;

    let mut stream = match tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::UnixStream::connect(&sock_path),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            // No master or stale socket — clean up
            let _ = std::fs::remove_file(&sock_path);
            return None;
        }
    };

    debug!("using control master socket {}", sock_path.display());

    let result = tokio::time::timeout(Duration::from_secs(60), async {
        wire::send_json(&mut stream, req).await.ok()?;
        wire::recv_json::<_, protocol::Response>(&mut stream)
            .await
            .ok()
    })
    .await;

    match result {
        Ok(Some(resp)) => Some(resp),
        _ => None,
    }
}

#[cfg(not(unix))]
pub async fn try_request(
    _host: &str,
    _port: u16,
    _req: &protocol::Request,
) -> Option<protocol::Response> {
    None
}

/// Stop a running master for the given host:port.
#[cfg(unix)]
pub async fn stop_master(host: &str, port: u16) -> Result<()> {
    let sock_path =
        socket_path(host, port).ok_or_else(|| anyhow::anyhow!("cannot determine socket path"))?;

    let mut stream = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::UnixStream::connect(&sock_path),
    )
    .await
    .map_err(|_| anyhow::anyhow!("no master running for {}:{}", host, port))?
    .map_err(|_| anyhow::anyhow!("no master running for {}:{}", host, port))?;

    let req = crate::client::simple_request("control-stop");

    let result = tokio::time::timeout(Duration::from_secs(5), async {
        wire::send_json(&mut stream, &req).await?;
        let resp: protocol::Response = wire::recv_json(&mut stream).await?;
        Ok::<_, anyhow::Error>(resp)
    })
    .await;

    match result {
        Ok(Ok(resp)) if resp.success => {
            let _ = std::fs::remove_file(&sock_path);
            eprintln!("Master stopped for {}:{}", host, port);
            Ok(())
        }
        Ok(Ok(resp)) => bail!(
            "master returned error: {}",
            resp.error.unwrap_or_default()
        ),
        Ok(Err(e)) => bail!("master communication error: {}", e),
        Err(_) => bail!("timeout communicating with master"),
    }
}

#[cfg(not(unix))]
pub async fn stop_master(_host: &str, _port: u16) -> Result<()> {
    bail!("mux not supported on this platform")
}

/// Run as control master: hold authenticated connection, serve via UDS.
/// Blocks until stopped (Ctrl+C, idle timeout, or --mux-stop).
#[cfg(unix)]
pub async fn run_master<S>(
    host: &str,
    port: u16,
    client: crate::client::RshClient<S>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use std::sync::Arc;
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    let sock_path =
        socket_path(host, port).ok_or_else(|| anyhow::anyhow!("cannot determine socket path"))?;

    // Check for existing master
    if tokio::net::UnixStream::connect(&sock_path).await.is_ok() {
        bail!(
            "master already running for {}:{} (socket: {})",
            host,
            port,
            sock_path.display()
        );
    }

    // Remove stale socket
    let _ = std::fs::remove_file(&sock_path);

    let listener = UnixListener::bind(&sock_path)?;
    let _cleanup = SocketCleanup(sock_path.clone());

    let client = Arc::new(Mutex::new(client));
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);

    // Ctrl+C handler
    let stop_sig = stop_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        stop_sig.send(true).ok();
    });

    eprintln!(
        "Control master for {}:{} (idle timeout: {:?})",
        host, port, IDLE_TIMEOUT
    );
    eprintln!("Socket: {}", sock_path.display());
    eprintln!("Press Ctrl+C to stop");

    let request_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let idle_deadline = Arc::new(Mutex::new(tokio::time::Instant::now() + IDLE_TIMEOUT));

    // Keepalive: periodic pings to detect dead connections
    let client_ka = client.clone();
    let stop_ka = stop_tx.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(KEEPALIVE_INTERVAL);
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            let mut c = client_ka.lock().await;
            let ping = crate::client::simple_request("ping");
            match tokio::time::timeout(Duration::from_secs(10), c.request(&ping)).await {
                Ok(Ok(_)) => {}
                _ => {
                    info!("control master: remote dead (keepalive failed), exiting");
                    stop_ka.send(true).ok();
                    return;
                }
            }
        }
    });

    loop {
        let deadline = *idle_deadline.lock().await;

        tokio::select! {
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    info!("control master stopped (signal)");
                    break;
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                let count = request_count.load(std::sync::atomic::Ordering::Relaxed);
                info!("control master stopped (idle timeout after {} requests)", count);
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _)) => {
                        // Reset idle timer
                        *idle_deadline.lock().await = tokio::time::Instant::now() + IDLE_TIMEOUT;

                        let client = client.clone();
                        let stop = stop_tx.clone();
                        let count = request_count.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_mux_client(stream, client, stop, count).await {
                                debug!("mux client error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("accept error: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Handle a single mux client connection.
/// Serves requests until the client disconnects.
#[cfg(unix)]
async fn handle_mux_client<S>(
    mut stream: tokio::net::UnixStream,
    client: std::sync::Arc<tokio::sync::Mutex<crate::client::RshClient<S>>>,
    stop_tx: tokio::sync::watch::Sender<bool>,
    request_count: std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    loop {
        let req: protocol::Request = match tokio::time::timeout(
            Duration::from_secs(60),
            wire::recv_json(&mut stream),
        )
        .await
        {
            Ok(Ok(req)) => req,
            _ => break, // Client disconnected or timeout
        };

        // Control commands
        if req.req_type == "control-stop" {
            let resp = protocol::Response {
                success: true,
                output: Some("stopping".to_string()),
                error: None,
                size: None,
                binary: None,
                gzip: None,
            };
            wire::send_json(&mut stream, &resp).await.ok();
            stop_tx.send(true).ok();
            return Ok(());
        }

        // Forward to remote (serialized)
        let count = request_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        debug!("forwarded request #{}: {}", count, req.req_type);

        let mut c = client.lock().await;
        let resp = match c.request(&req).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("remote request failed: {}", e);
                protocol::Response {
                    success: false,
                    output: None,
                    error: Some(format!("remote error: {}", e)),
                    size: None,
                    binary: None,
                    gzip: None,
                }
            }
        };
        drop(c);

        if wire::send_json(&mut stream, &resp).await.is_err() {
            break; // Client disconnected
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub async fn run_master<S>(
    _host: &str,
    _port: u16,
    _client: crate::client::RshClient<S>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    bail!("mux not supported on this platform")
}

/// RAII cleanup for socket file.
#[cfg(unix)]
struct SocketCleanup(PathBuf);

#[cfg(unix)]
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Build a request for muxing based on command and args.
/// Returns None for commands that cannot be muxed (streaming, binary transfer).
pub fn build_mux_request(cmd: &str, args: &[String]) -> Option<protocol::Request> {
    let req = match cmd {
        "ping" | "server-version" => crate::client::simple_request("ping"),
        "exec" => {
            if args.len() < 2 {
                return None;
            }
            let mut req = crate::client::simple_request("exec");
            req.command = Some(args[1..].join(" "));
            req
        }
        "ls" => {
            let mut req = crate::client::simple_request("ls");
            req.path = Some(
                args.get(1)
                    .map(|s| s.as_str())
                    .unwrap_or(".")
                    .to_string(),
            );
            req
        }
        "cat" => {
            if args.len() < 2 {
                return None;
            }
            let mut req = crate::client::simple_request("cat");
            req.path = Some(args[1].clone());
            req
        }
        "ps" => crate::client::simple_request("ps"),
        "info" => crate::client::simple_request("info"),
        "kill" => {
            if args.len() < 2 {
                return None;
            }
            let mut req = crate::client::simple_request("kill");
            req.command = Some(args[1].clone());
            req
        }
        "tail" => {
            if args.len() < 2 {
                return None;
            }
            let mut req = crate::client::simple_request("tail");
            req.path = Some(args[1].clone());
            if let Some(n) = args.get(2) {
                req.command = Some(n.clone());
            }
            req
        }
        "filever" => {
            if args.len() < 2 {
                return None;
            }
            let mut req = crate::client::simple_request("filever");
            req.path = Some(args[1].clone());
            req
        }
        "eventlog" | "evtlog" => {
            let mut req = crate::client::simple_request("eventlog");
            req.path = Some(
                args.get(1)
                    .map(|s| s.as_str())
                    .unwrap_or("System")
                    .to_string(),
            );
            if let Some(n) = args.get(2) {
                req.command = Some(n.clone());
            }
            req
        }
        "write" => {
            if args.len() < 3 {
                return None;
            }
            let mut req = crate::client::simple_request("write");
            req.path = Some(args[1].clone());
            req.content = Some(args[2..].join(" "));
            req
        }
        "self-update" => {
            if args.len() < 2 {
                return None;
            }
            let mut req = crate::client::simple_request("self-update");
            req.path = Some(args[1].clone());
            req
        }
        // Streaming/binary commands — cannot be muxed
        "shell" | "attach" | "browse" | "sftp" | "tunnel" | "push" | "pull" | "watch"
        | "recording" => return None,
        // Commands with special handling (interactive confirmation, etc.)
        "reboot" | "shutdown" | "sleep" | "lock" => return None,
        // Unknown commands — try as exec
        _other => {
            let mut req = crate::client::simple_request("exec");
            req.command = Some(args.join(" "));
            req
        }
    };
    Some(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_format() {
        // Just verify it doesn't panic on unix
        let path = socket_path("myhost", 8822);
        if cfg!(unix) {
            let p = path.unwrap();
            assert!(p.to_string_lossy().contains("myhost-8822.sock"));
        }
    }

    #[test]
    fn build_mux_request_ping() {
        let req = build_mux_request("ping", &[]).unwrap();
        assert_eq!(req.req_type, "ping");
    }

    #[test]
    fn build_mux_request_exec() {
        let args = vec!["exec".to_string(), "hostname".to_string()];
        let req = build_mux_request("exec", &args).unwrap();
        assert_eq!(req.req_type, "exec");
        assert_eq!(req.command.as_deref(), Some("hostname"));
    }

    #[test]
    fn build_mux_request_exec_multi_word() {
        let args = vec![
            "exec".to_string(),
            "Get-Process".to_string(),
            "|".to_string(),
            "Select".to_string(),
            "Name".to_string(),
        ];
        let req = build_mux_request("exec", &args).unwrap();
        assert_eq!(req.command.as_deref(), Some("Get-Process | Select Name"));
    }

    #[test]
    fn build_mux_request_shell_returns_none() {
        assert!(build_mux_request("shell", &[]).is_none());
    }

    #[test]
    fn build_mux_request_push_returns_none() {
        assert!(build_mux_request("push", &[]).is_none());
    }

    #[test]
    fn build_mux_request_ls() {
        let args = vec!["ls".to_string(), "C:\\Users".to_string()];
        let req = build_mux_request("ls", &args).unwrap();
        assert_eq!(req.req_type, "ls");
        assert_eq!(req.path.as_deref(), Some("C:\\Users"));
    }

    #[test]
    fn build_mux_request_unknown_becomes_exec() {
        let args = vec!["hostname".to_string()];
        let req = build_mux_request("hostname", &args).unwrap();
        assert_eq!(req.req_type, "exec");
        assert_eq!(req.command.as_deref(), Some("hostname"));
    }
}
