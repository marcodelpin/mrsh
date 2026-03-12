//! QUIC transport — multiplexed streams over UDP with same auth as TLS.
//! Auth on first stream, channels on subsequent streams.
//!
//! Protocol: ALPN "rsh-quic", newline-delimited JSON for auth,
//! channel header = `chanType\0target\n`, then raw I/O per channel type.

#![cfg(feature = "quic")]

use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;
use quinn::Endpoint;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info, warn};

use rsh_core::{auth, protocol, wire};

use crate::exec;
use crate::handler::ServerContext;
use crate::shell;
use crate::sync;
use crate::tunnel;

/// Channel type constants.
const CHAN_TYPE_TUNNEL: &str = "tunnel";
const CHAN_TYPE_UDP_TUNNEL: &str = "udp-tunnel";
const CHAN_TYPE_EXEC: &str = "exec";
const CHAN_TYPE_PUSH: &str = "push";
const CHAN_TYPE_PULL: &str = "pull";
const CHAN_TYPE_LS: &str = "ls";
const CHAN_TYPE_SHELL: &str = "shell";

/// Start the QUIC listener on the same port as TLS (UDP).
///
/// Uses the provided rustls `ServerConfig` with ALPN set to `rsh-quic`.
/// QUIC config: MaxIdle=60s, KeepAlive=15s, MaxIncoming=1000.
pub async fn start_quic_listener(
    port: u16,
    tls_config: Arc<rustls::ServerConfig>,
    ctx: Arc<ServerContext>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    // Clone and set ALPN for QUIC
    let mut quic_tls = (*tls_config).clone();
    quic_tls.alpn_protocols = vec![b"rsh-quic".to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(quic_tls))
            .context("build QUIC server crypto config")?,
    ));

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let endpoint = Endpoint::server(server_config, addr).context("bind QUIC endpoint")?;

    info!("[QUIC] listening on {}", addr);

    loop {
        let incoming = tokio::select! {
            inc = endpoint.accept() => {
                match inc {
                    Some(i) => i,
                    None => {
                        info!("[QUIC] endpoint closed");
                        return Ok(());
                    }
                }
            }
            _ = cancel.cancelled() => {
                info!("[QUIC] shutting down");
                endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
                return Ok(());
            }
        };

        let ctx = ctx.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_quic_connection(conn, ctx).await {
                        debug!("[QUIC] connection error: {}", e);
                    }
                }
                Err(e) => {
                    debug!("[QUIC] accept error: {}", e);
                }
            }
        });
    }
}

/// Handle a single QUIC connection: auth on first stream, channels on rest.
async fn handle_quic_connection(conn: quinn::Connection, ctx: Arc<ServerContext>) -> Result<()> {
    let remote = conn.remote_address();
    info!("[QUIC] new connection from {}", remote);

    // First stream = authentication
    let (send, recv) = conn
        .accept_bi()
        .await
        .context("accept auth stream")?;

    let perms = match authenticate_quic_stream(send, recv, &ctx, remote).await {
        Some(p) => p,
        None => {
            conn.close(quinn::VarInt::from_u32(1), b"auth failed");
            return Ok(());
        }
    };

    info!("[QUIC] client authenticated from {}", remote);
    let perms = Arc::new(perms);

    // Handle subsequent streams
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                debug!("[QUIC] connection closed: {}", e);
                return Ok(());
            }
        };

        let remote_str = remote.to_string();
        let perms = perms.clone();
        let allowed_tunnels = ctx.allowed_tunnels.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_quic_stream(send, recv, &remote_str, &perms, &allowed_tunnels).await {
                debug!("[QUIC] stream error: {}", e);
            }
        });
    }
}

/// Send newline-delimited JSON on a QUIC send stream.
async fn send_quic_json<T: serde::Serialize>(
    send: &mut quinn::SendStream,
    value: &T,
) -> Result<()> {
    let mut data = serde_json::to_vec(value).context("serialize JSON")?;
    data.push(b'\n');
    send.write_all(&data).await.context("write JSON")?;
    Ok(())
}

/// Read a newline-delimited JSON message from a QUIC recv stream.
async fn recv_quic_json<T: serde::de::DeserializeOwned>(
    reader: &mut BufReader<quinn::RecvStream>,
) -> Result<T> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .context("read JSON line")?;
    serde_json::from_str(&line).context("parse JSON")
}

/// Perform ed25519 challenge-response authentication on the first QUIC stream.
/// Returns `Some(permissions)` on success, `None` on failure.
async fn authenticate_quic_stream(
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    ctx: &ServerContext,
    remote: std::net::SocketAddr,
) -> Option<auth::KeyPermissions> {
    match authenticate_quic_inner(&mut send, recv, ctx).await {
        Ok(info) => {
            info!(
                "[QUIC] authenticated: {} (v{}) from {}",
                info.0.as_deref().unwrap_or("unknown"),
                info.1.as_deref().unwrap_or("?"),
                remote
            );
            Some(info.2)
        }
        Err(e) => {
            warn!("[QUIC] auth failed from {}: {}", remote, e);
            // Try to send failure result (best effort)
            let _ = send_quic_json(
                &mut send,
                &protocol::AuthResult {
                    success: false,
                    error: Some(e.to_string()),
                    version: Some(ctx.server_version.clone()),
                    mux_enabled: None,
                    caps: None,
                    banner: None,
                },
            )
            .await;
            let _ = send.finish();
            None
        }
    }
}

/// Inner auth logic, returns (comment, version, permissions) on success.
async fn authenticate_quic_inner(
    send: &mut quinn::SendStream,
    recv: quinn::RecvStream,
    ctx: &ServerContext,
) -> Result<(Option<String>, Option<String>, auth::KeyPermissions)> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut reader = BufReader::new(recv);

    // 1. Receive AuthRequest (newline-delimited JSON)
    let auth_req: protocol::AuthRequest =
        recv_quic_json(&mut reader).await.context("recv AuthRequest")?;

    debug!(
        "[QUIC] auth request: type={} version={:?}",
        auth_req.auth_type, auth_req.version
    );

    if auth_req.auth_type != "auth" && auth_req.auth_type != "pubkey" {
        anyhow::bail!("unsupported auth type: {}", auth_req.auth_type);
    }

    // 2. Look up client's public key
    let client_pubkey_b64 = auth_req
        .public_key
        .as_ref()
        .context("missing public_key")?;
    let client_pubkey_wire = b64
        .decode(client_pubkey_b64)
        .context("decode public_key base64")?;

    // Extract raw 32-byte ed25519 key
    let raw_key = extract_ed25519_raw(&client_pubkey_wire)?;

    // Find matching authorized key
    let matched_key = ctx
        .authorized_keys
        .iter()
        .find(|k| k.key_data == raw_key)
        .context("public key not authorized")?;

    // 3. Send challenge
    let challenge = auth::generate_challenge();
    let challenge_msg = protocol::AuthChallenge {
        challenge: b64.encode(&challenge),
    };
    send_quic_json(send, &challenge_msg).await?;

    // 4. Receive signed response
    let auth_resp: protocol::AuthResponse =
        recv_quic_json(&mut reader).await.context("recv AuthResponse")?;

    let signature = b64
        .decode(&auth_resp.signature)
        .context("decode signature base64")?;

    let raw_sig = extract_ed25519_sig(&signature)?;

    // 5. Verify signature
    let valid = auth::verify_ed25519_signature(&raw_key, &challenge, &raw_sig)
        .context("verify signature")?;

    if !valid {
        anyhow::bail!("signature verification failed");
    }

    // 6. Send success
    let result = protocol::AuthResult {
        success: true,
        error: None,
        version: Some(ctx.server_version.clone()),
        mux_enabled: Some(true),
        caps: Some(ctx.caps.clone()),
        banner: ctx.banner.clone(),
    };
    send_quic_json(send, &result).await?;
    send.finish().context("finish auth send stream")?;

    Ok((matched_key.comment.clone(), auth_req.version, matched_key.permissions.clone()))
}

/// Handle a single QUIC channel stream with permission checks.
/// Header format: `chanType[\0target]\n` — null byte separates type from target.
async fn handle_quic_stream(
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    remote: &str,
    perms: &auth::KeyPermissions,
    allowed_tunnels: &[String],
) -> Result<()> {
    let mut reader = BufReader::new(recv);

    // Read header line
    let mut header = String::new();
    reader
        .read_line(&mut header)
        .await
        .context("read channel header")?;

    // Strip trailing newline
    let header = header.trim_end_matches('\n');

    // Parse: chanType + optional \0 + target
    let (chan_type, target) = if let Some(idx) = header.find('\0') {
        (&header[..idx], &header[idx + 1..])
    } else {
        (header, "")
    };

    info!(
        "[QUIC] stream opened: type={} target={} from {}",
        chan_type, target, remote
    );

    match chan_type {
        CHAN_TYPE_TUNNEL | CHAN_TYPE_UDP_TUNNEL => {
            if !perms.allow_tunnel {
                send.write_all(b"ERROR: tunnel not permitted for this key\n").await.ok();
                return Ok(());
            }
            if !tunnel::is_tunnel_allowed(target, allowed_tunnels) {
                let msg = format!("ERROR: tunnel to {} not allowed by server policy\n", target);
                send.write_all(msg.as_bytes()).await.ok();
                return Ok(());
            }
            if chan_type == CHAN_TYPE_TUNNEL {
                handle_quic_tunnel(&mut send, &mut reader, target).await
            } else {
                handle_quic_udp_tunnel(&mut send, &mut reader, target).await
            }
        }
        CHAN_TYPE_EXEC => {
            if !perms.allow_exec {
                send.write_all(b"ERROR: exec not permitted for this key\n").await.ok();
                return Ok(());
            }
            handle_quic_exec(&mut send, &mut reader).await
        }
        CHAN_TYPE_PUSH => {
            if !perms.allow_push {
                send.write_all(b"ERROR: push not permitted for this key\n").await.ok();
                return Ok(());
            }
            handle_quic_push(&mut send, &mut reader, target).await
        }
        CHAN_TYPE_PULL => {
            if !perms.allow_pull {
                send.write_all(b"ERROR: pull not permitted for this key\n").await.ok();
                return Ok(());
            }
            handle_quic_pull(&mut send, &mut reader, target).await
        }
        CHAN_TYPE_LS => {
            if !perms.allow_pull {
                send.write_all(b"ERROR: ls not permitted for this key\n").await.ok();
                return Ok(());
            }
            handle_quic_ls(&mut send, &mut reader, target).await
        }
        CHAN_TYPE_SHELL => {
            if !perms.allow_shell {
                send.write_all(b"ERROR: shell not permitted for this key\n").await.ok();
                return Ok(());
            }
            handle_quic_shell(&mut send, &mut reader, target).await
        }
        _ => {
            send.write_all(b"ERROR: unknown channel type\n").await.ok();
            Ok(())
        }
    }
}

/// TCP tunnel over QUIC stream: connect to target, bidirectional relay.
async fn handle_quic_tunnel(
    send: &mut quinn::SendStream,
    reader: &mut BufReader<quinn::RecvStream>,
    target: &str,
) -> Result<()> {
    // Connect to target
    let target_stream = match TcpStream::connect(target).await {
        Ok(s) => {
            send.write_all(b"OK\n").await.context("send OK")?;
            s
        }
        Err(e) => {
            let msg = format!("ERROR: {}\n", e);
            send.write_all(msg.as_bytes()).await.ok();
            anyhow::bail!("connect to {}: {}", target, e);
        }
    };
    target_stream.set_nodelay(true).ok();

    let (mut target_read, mut target_write) = target_stream.into_split();

    // Bidirectional relay: QUIC stream <-> TCP target (raw bytes)
    let mut buf_quic = vec![0u8; 32768];
    let mut buf_tcp = vec![0u8; 32768];

    loop {
        tokio::select! {
            // QUIC -> TCP
            result = reader.read(&mut buf_quic) => {
                match result {
                    Ok(0) | Err(_) => {
                        debug!("[QUIC] tunnel: client stream ended");
                        break;
                    }
                    Ok(n) => {
                        target_write.write_all(&buf_quic[..n]).await
                            .context("write to target")?;
                    }
                }
            }
            // TCP -> QUIC
            result = target_read.read(&mut buf_tcp) => {
                match result {
                    Ok(0) => {
                        debug!("[QUIC] tunnel: target closed");
                        break;
                    }
                    Ok(n) => {
                        send.write_all(&buf_tcp[..n]).await
                            .context("write to QUIC stream")?;
                    }
                    Err(e) => {
                        debug!("[QUIC] tunnel: target read error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    info!("[QUIC] tunnel closed");
    Ok(())
}

/// UDP tunnel over QUIC stream: relay datagrams between QUIC and UDP target.
async fn handle_quic_udp_tunnel(
    send: &mut quinn::SendStream,
    reader: &mut BufReader<quinn::RecvStream>,
    target: &str,
) -> Result<()> {
    // Connect UDP to target
    let udp = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("ERROR: {}\n", e);
            send.write_all(msg.as_bytes()).await.ok();
            anyhow::bail!("bind UDP: {}", e);
        }
    };

    if let Err(e) = udp.connect(target).await {
        let msg = format!("ERROR: {}\n", e);
        send.write_all(msg.as_bytes()).await.ok();
        anyhow::bail!("connect UDP to {}: {}", target, e);
    }

    send.write_all(b"OK\n").await.context("send OK")?;
    info!("[QUIC] UDP tunnel to {} established", target);

    let mut buf_quic = vec![0u8; 65535];
    let mut buf_udp = vec![0u8; 65535];

    loop {
        tokio::select! {
            // QUIC stream -> UDP
            result = reader.read(&mut buf_quic) => {
                match result {
                    Ok(0) | Err(_) => {
                        debug!("[QUIC] UDP tunnel: QUIC stream ended");
                        break;
                    }
                    Ok(n) => {
                        udp.send(&buf_quic[..n]).await.ok();
                    }
                }
            }
            // UDP -> QUIC stream
            result = udp.recv(&mut buf_udp) => {
                match result {
                    Ok(n) => {
                        if send.write_all(&buf_udp[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("[QUIC] UDP tunnel: recv error: {}", e);
                        // Non-fatal for UDP (timeouts, etc.)
                        continue;
                    }
                }
            }
        }
    }

    info!("[QUIC] UDP tunnel closed");
    Ok(())
}

/// Execute a command over QUIC stream: read command line, run, send result.
async fn handle_quic_exec(
    send: &mut quinn::SendStream,
    reader: &mut BufReader<quinn::RecvStream>,
) -> Result<()> {
    // Read command line
    let mut cmd_line = String::new();
    reader
        .read_line(&mut cmd_line)
        .await
        .context("read command")?;
    let cmd = cmd_line.trim();

    if cmd.is_empty() {
        send.write_all(b"ERROR: empty command\n").await.ok();
        return Ok(());
    }

    // Execute
    let resp = exec::handle_exec(cmd, &[]).await;

    // Send OK then result
    send.write_all(b"OK\n").await.context("send OK")?;
    if resp.success {
        if let Some(output) = &resp.output {
            send.write_all(output.as_bytes()).await.ok();
        }
    } else {
        let err_msg = resp.error.as_deref().unwrap_or("unknown error");
        let msg = format!("ERROR: {}", err_msg);
        send.write_all(msg.as_bytes()).await.ok();
    }

    Ok(())
}

/// Push a file over QUIC: read 8-byte BE size + raw data, write to `path`.
///
/// Header already parsed: `push\0<path>\n`. `target` is the remote path.
/// Protocol: client sends 8-byte BE u64 size, then `size` bytes of raw data.
/// Response: `OK\n<bytes_written>\n` or `ERROR: <msg>\n`.
async fn handle_quic_push(
    send: &mut quinn::SendStream,
    reader: &mut BufReader<quinn::RecvStream>,
    target: &str,
) -> Result<()> {
    // Validate path
    if let Err(e) = sync::sanitize_path(target) {
        let msg = format!("ERROR: {}\n", e);
        send.write_all(msg.as_bytes()).await.ok();
        return Ok(());
    }

    if target.is_empty() {
        send.write_all(b"ERROR: empty path\n").await.ok();
        return Ok(());
    }

    // Read 8-byte BE size
    let mut size_buf = [0u8; 8];
    if let Err(e) = reader.read_exact(&mut size_buf).await {
        let msg = format!("ERROR: failed to read size: {}\n", e);
        send.write_all(msg.as_bytes()).await.ok();
        return Ok(());
    }
    let size = u64::from_be_bytes(size_buf);

    // Read raw data
    let mut data = vec![0u8; size as usize];
    if let Err(e) = reader.read_exact(&mut data).await {
        let msg = format!("ERROR: failed to read data: {}\n", e);
        send.write_all(msg.as_bytes()).await.ok();
        return Ok(());
    }

    // Create parent directories
    let path = std::path::Path::new(target);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                let msg = format!("ERROR: create dirs: {}\n", e);
                send.write_all(msg.as_bytes()).await.ok();
                return Ok(());
            }
        }
    }

    // Write file
    match tokio::fs::write(path, &data).await {
        Ok(()) => {
            let resp = format!("OK\n{}\n", size);
            send.write_all(resp.as_bytes()).await.ok();
            info!("[QUIC] push: wrote {} bytes to {}", size, target);
        }
        Err(e) => {
            let msg = format!("ERROR: write file: {}\n", e);
            send.write_all(msg.as_bytes()).await.ok();
        }
    }

    Ok(())
}

/// Pull a file over QUIC: read path from header, send file data.
///
/// Header already parsed: `pull\0<path>\n`. `target` is the remote path.
/// Response: `OK\n` + 8-byte BE u64 size + raw data, or `ERROR: <msg>\n`.
async fn handle_quic_pull(
    send: &mut quinn::SendStream,
    _reader: &mut BufReader<quinn::RecvStream>,
    target: &str,
) -> Result<()> {
    // Validate path
    if let Err(e) = sync::sanitize_path(target) {
        let msg = format!("ERROR: {}\n", e);
        send.write_all(msg.as_bytes()).await.ok();
        return Ok(());
    }

    if target.is_empty() {
        send.write_all(b"ERROR: empty path\n").await.ok();
        return Ok(());
    }

    // Read file
    let data = match tokio::fs::read(target).await {
        Ok(d) => d,
        Err(e) => {
            let msg = format!("ERROR: {}\n", e);
            send.write_all(msg.as_bytes()).await.ok();
            return Ok(());
        }
    };

    let size = data.len() as u64;

    // Send OK + size + data
    send.write_all(b"OK\n").await.context("send OK")?;
    send.write_all(&size.to_be_bytes()).await.context("send size")?;
    send.write_all(&data).await.context("send data")?;

    info!("[QUIC] pull: sent {} bytes from {}", size, target);
    Ok(())
}

/// List a remote directory over QUIC.
///
/// Header: `ls\0<path>\n`. Response: newline-delimited JSON array of FileInfo,
/// or `ERROR: <msg>\n`.
async fn handle_quic_ls(
    send: &mut quinn::SendStream,
    _reader: &mut BufReader<quinn::RecvStream>,
    target: &str,
) -> Result<()> {
    use rsh_core::protocol::FileInfo;

    let path = if target.is_empty() { "." } else { target };

    // Validate path
    if let Err(e) = sync::sanitize_path(path) {
        let msg = format!("ERROR: {}\n", e);
        send.write_all(msg.as_bytes()).await.ok();
        return Ok(());
    }

    let mut entries = match tokio::fs::read_dir(path).await {
        Ok(e) => e,
        Err(e) => {
            let msg = format!("ERROR: {}\n", e);
            send.write_all(msg.as_bytes()).await.ok();
            return Ok(());
        }
    };

    let mut files: Vec<FileInfo> = Vec::new();
    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => {
                warn!("[QUIC] ls: read_dir entry error: {}", e);
                continue;
            }
        };
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mod_time = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs().to_string())
            .unwrap_or_default();
        let name = entry.file_name().to_string_lossy().to_string();
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            format!("{:o}", meta.permissions().mode() & 0o777)
        };
        #[cfg(not(unix))]
        let mode = String::from("---");
        files.push(FileInfo {
            name,
            size: meta.len() as i64,
            mode,
            mod_time,
            is_dir: meta.is_dir(),
        });
    }

    send_quic_json(send, &files).await?;
    info!("[QUIC] ls: {} entries from {}", files.len(), path);
    Ok(())
}

/// Interactive shell over QUIC stream (Linux PTY).
/// Channel header: `shell[\0{COLSxROWS}]\n`
/// Protocol:
///   Server → Client: `OK\n` (or `ERROR: ...\n`)
///   Bidirectional: wire-framed chunks (same as TLS shell)
///   Resize: 0x01 + cols(2BE) + rows(2BE) from client
///   EOF: empty frame from either side
#[cfg(not(target_os = "windows"))]
async fn handle_quic_shell(
    send: &mut quinn::SendStream,
    reader: &mut BufReader<quinn::RecvStream>,
    target: &str,
) -> Result<()> {
    use std::os::unix::io::FromRawFd;

    let size_str = if target.is_empty() { "80x24" } else { target };
    let (cols, rows) = shell::parse_size(size_str);
    info!("[QUIC] shell: {}x{}", cols, rows);

    // Create PTY pair
    let mut master_fd: libc::c_int = 0;
    let mut slave_fd: libc::c_int = 0;
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    if unsafe {
        libc::openpty(
            &mut master_fd,
            &mut slave_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &ws as *const libc::winsize as *mut libc::winsize,
        )
    } != 0
    {
        let msg = format!(
            "ERROR: openpty: {}\n",
            std::io::Error::last_os_error()
        );
        send.write_all(msg.as_bytes()).await.ok();
        return Ok(());
    }

    let shell_bin = if std::path::Path::new("/bin/bash").exists() {
        "/bin/bash"
    } else {
        "/bin/sh"
    };

    let saved_master = master_fd;
    let saved_slave = slave_fd;

    let mut cmd = tokio::process::Command::new(shell_bin);
    cmd.env("TERM", "xterm-256color");
    cmd.kill_on_drop(true);
    unsafe {
        cmd.pre_exec(move || {
            libc::close(saved_master);
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(saved_slave, libc::TIOCSCTTY, 0 as libc::c_int) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::dup2(saved_slave, 0);
            libc::dup2(saved_slave, 1);
            libc::dup2(saved_slave, 2);
            if saved_slave > 2 {
                libc::close(saved_slave);
            }
            Ok(())
        });
    }

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            unsafe {
                libc::close(master_fd);
                libc::close(slave_fd);
            }
            let msg = format!("ERROR: spawn: {}\n", e);
            send.write_all(msg.as_bytes()).await.ok();
            return Ok(());
        }
    };
    let child_pid = child.id().unwrap_or(0) as libc::pid_t;
    let _child = child;

    // Close slave in parent (child holds its copy)
    unsafe {
        libc::close(slave_fd);
    }

    // Dup master for separate read and write ownership
    let master_write_fd = unsafe { libc::dup(master_fd) };
    if master_write_fd < 0 {
        unsafe {
            libc::close(master_fd);
        }
        anyhow::bail!("dup(master): {}", std::io::Error::last_os_error());
    }

    // Signal OK to client before entering relay loop
    send.write_all(b"OK\n").await.context("send OK")?;

    // Spawn blocking reader thread: PTY master → mpsc channel
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let reader_task = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut f = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let mut buf = [0u8; 32768];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    if e.raw_os_error() == Some(libc::EIO) {
                        break; // slave closed (child exited) — normal
                    }
                    debug!("[QUIC] shell: PTY read: {}", e);
                    break;
                }
            }
        }
    });

    let mut master_write = unsafe { std::fs::File::from_raw_fd(master_write_fd) };

    // Bidirectional relay loop
    loop {
        tokio::select! {
            // Client → PTY
            result = wire::recv_message(reader) => {
                match result {
                    Ok(data) if data.is_empty() => {
                        debug!("[QUIC] shell: client EOF");
                        break;
                    }
                    Ok(data) => {
                        if let Some((c, r)) = shell::parse_resize(&data) {
                            let new_ws = libc::winsize {
                                ws_row: r,
                                ws_col: c,
                                ws_xpixel: 0,
                                ws_ypixel: 0,
                            };
                            unsafe {
                                libc::ioctl(master_write_fd, libc::TIOCSWINSZ, &new_ws);
                                if child_pid > 0 {
                                    libc::kill(-child_pid, libc::SIGWINCH);
                                }
                            }
                            continue;
                        }
                        use std::io::Write;
                        if master_write.write_all(&data).is_err()
                            || master_write.flush().is_err()
                        {
                            debug!("[QUIC] shell: PTY write failed");
                            break;
                        }
                    }
                    Err(_) => {
                        debug!("[QUIC] shell: client disconnected");
                        break;
                    }
                }
            }
            // PTY → Client
            msg = rx.recv() => {
                match msg {
                    Some(data) => {
                        if wire::send_message(send, &data).await.is_err() {
                            debug!("[QUIC] shell: send failed");
                            break;
                        }
                    }
                    None => {
                        debug!("[QUIC] shell: process exited");
                        break;
                    }
                }
            }
        }
    }

    drop(master_write);
    reader_task.abort();
    wire::send_message(send, &[]).await.ok();
    info!("[QUIC] shell: session ended");
    Ok(())
}

/// Interactive shell over QUIC stream (Windows ConPTY).
#[cfg(target_os = "windows")]
async fn handle_quic_shell(
    send: &mut quinn::SendStream,
    reader: &mut BufReader<quinn::RecvStream>,
    target: &str,
) -> Result<()> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Console::{
        COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        STARTUPINFOEXW, UpdateProcThreadAttribute,
    };

    let size_str = if target.is_empty() { "80x24" } else { target };
    let (cols, rows) = shell::parse_size(size_str);
    info!("[QUIC] shell (ConPTY): {}x{}", cols, rows);

    let (pty_in_write, pty_out_read, hpc, proc_raw, thread_raw) = unsafe {
        let mut pty_in_read = HANDLE::default();
        let mut pty_in_write = HANDLE::default();
        let mut pty_out_read = HANDLE::default();
        let mut pty_out_write = HANDLE::default();

        CreatePipe(&mut pty_in_read, &mut pty_in_write, None, 0).context("CreatePipe input")?;
        CreatePipe(&mut pty_out_read, &mut pty_out_write, None, 0)
            .context("CreatePipe output")?;

        let size = COORD { X: cols as i16, Y: rows as i16 };
        let hpc = CreatePseudoConsole(size, pty_in_read, pty_out_write, 0)
            .context("CreatePseudoConsole")?;

        let _ = CloseHandle(pty_in_read);
        let _ = CloseHandle(pty_out_write);

        let mut attr_size: usize = 0;
        let _ = InitializeProcThreadAttributeList(None, 1, None, &mut attr_size);
        let mut attr_buf = vec![0u8; attr_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as _);
        InitializeProcThreadAttributeList(Some(attr_list), 1, None, &mut attr_size)
            .context("InitializeProcThreadAttributeList")?;

        const PSEUDOCONSOLE_ATTR: usize = 0x00020016;
        UpdateProcThreadAttribute(
            attr_list, 0, PSEUDOCONSOLE_ATTR,
            Some(&hpc as *const HPCON as *const std::ffi::c_void),
            std::mem::size_of::<HPCON>(), None, None,
        )
        .context("UpdateProcThreadAttribute")?;

        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attr_list;
        let mut pi = PROCESS_INFORMATION::default();
        let mut cmd: Vec<u16> = "powershell.exe\0".encode_utf16().collect();

        CreateProcessW(
            windows::core::PCWSTR::null(),
            Some(windows::core::PWSTR(cmd.as_mut_ptr())),
            None, None, false, EXTENDED_STARTUPINFO_PRESENT, None,
            windows::core::PCWSTR::null(), &si.StartupInfo, &mut pi,
        )
        .context("CreateProcessW")?;

        DeleteProcThreadAttributeList(attr_list);
        let proc_raw = pi.hProcess.0 as usize;
        let thread_raw = pi.hThread.0 as usize;
        (pty_in_write, pty_out_read, hpc, proc_raw, thread_raw)
    };

    use std::os::windows::io::FromRawHandle;
    let out_file = unsafe { std::fs::File::from_raw_handle(pty_out_read.0) };
    let mut in_file = unsafe { std::fs::File::from_raw_handle(pty_in_write.0) };

    send.write_all(b"OK\n").await.context("send OK")?;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let reader_task = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut f = out_file;
        let mut buf = [0u8; 32768];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    loop {
        tokio::select! {
            result = wire::recv_message(reader) => {
                match result {
                    Ok(data) if data.is_empty() => break,
                    Ok(data) => {
                        if let Some((c, r)) = shell::parse_resize(&data) {
                            unsafe {
                                let sz = COORD { X: c as i16, Y: r as i16 };
                                let _ = ResizePseudoConsole(hpc, sz);
                            }
                            continue;
                        }
                        use std::io::Write;
                        if in_file.write_all(&data).is_err() || in_file.flush().is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(data) => {
                        if wire::send_message(send, &data).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    unsafe {
        ClosePseudoConsole(hpc);
    }
    drop(in_file);
    reader_task.abort();
    unsafe {
        let _ = CloseHandle(HANDLE(proc_raw as *mut std::ffi::c_void));
        let _ = CloseHandle(HANDLE(thread_raw as *mut std::ffi::c_void));
    }
    wire::send_message(send, &[]).await.ok();
    info!("[QUIC] shell: ConPTY session ended");
    Ok(())
}

/// Extract raw 32-byte ed25519 public key from SSH wire format or raw bytes.
fn extract_ed25519_raw(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() == 32 {
        return Ok(data.to_vec());
    }
    if data.len() > 32 {
        if data.len() >= 51 {
            let type_len = u32::from_be_bytes(data[0..4].try_into()?) as usize;
            if type_len == 11 && &data[4..15] == b"ssh-ed25519" {
                return Ok(data[data.len() - 32..].to_vec());
            }
        }
        return Ok(data[data.len() - 32..].to_vec());
    }
    anyhow::bail!("invalid ed25519 public key: {} bytes", data.len());
}

/// Extract raw 64-byte ed25519 signature from SSH wire format or raw bytes.
fn extract_ed25519_sig(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() == 64 {
        return Ok(data.to_vec());
    }
    if data.len() > 64 {
        return Ok(data[data.len() - 64..].to_vec());
    }
    anyhow::bail!("invalid ed25519 signature: {} bytes", data.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rsh_core::tls;

    use crate::ratelimit;
    use crate::session;

    fn make_test_context(signing_key: &SigningKey) -> Arc<ServerContext> {
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let ak = auth::AuthorizedKey {
            key_type: "ssh-ed25519".to_string(),
            key_data: pub_bytes.to_vec(),
            comment: Some("test@host".to_string()),
            permissions: auth::KeyPermissions::default(),
        };

        Arc::new(ServerContext {
            authorized_keys: vec![ak],
            revoked_keys: std::collections::HashSet::new(),
            server_version: "0.1.0-test".to_string(),
            banner: None,
            caps: vec!["shell".to_string()],
            session_store: session::SessionStore::new(),
            rate_limiter: ratelimit::AuthRateLimiter::new(),
            allowed_tunnels: vec![],
            totp_secrets: vec![],
            totp_recovery_path: None,
        })
    }

    fn make_quic_endpoint_pair() -> Result<(
        quinn::Endpoint,
        quinn::Endpoint,
        std::net::SocketAddr,
    )> {
        // Generate TLS cert/key in a unique temp dir per test run
        let tmp = tempfile::tempdir()?;
        let (certs, key) = tls::load_or_generate_cert(tmp.path())?;

        // Server config
        let mut server_tls = (*tls::server_config(certs.clone(), key)?).clone();
        server_tls.alpn_protocols = vec![b"rsh-quic".to_vec()];
        let server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(
            Arc::new(server_tls),
        )?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));

        let server_ep =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())?;
        let server_addr = server_ep.local_addr()?;

        // Client config
        let mut client_tls = (*tls::client_config()).clone();
        client_tls.alpn_protocols = vec![b"rsh-quic".to_vec()];
        let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(
            Arc::new(client_tls),
        )?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(10)).unwrap(),
        ));
        client_config.transport_config(Arc::new(transport));

        let mut client_ep =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
        client_ep.set_default_client_config(client_config);

        Ok((server_ep, client_ep, server_addr))
    }

    /// Helper: perform client-side auth on a QUIC connection.
    async fn client_authenticate(
        conn: &quinn::Connection,
        signing_key: &SigningKey,
    ) -> Result<protocol::AuthResult> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let (mut send, recv) = conn.open_bi().await.context("open auth stream")?;

        // Send AuthRequest
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let auth_req = protocol::AuthRequest {
            auth_type: "auth".to_string(),
            public_key: Some(b64.encode(pub_bytes)),
            key_type: Some("ssh-ed25519".to_string()),
            username: None,
            password: None,
            version: Some("0.1.0".to_string()),
            want_mux: None,
            caps: Some(vec!["shell".to_string()]),
        };
        send_quic_json(&mut send, &auth_req).await?;

        let mut reader = BufReader::new(recv);

        // Receive challenge
        let challenge: protocol::AuthChallenge =
            recv_quic_json(&mut reader).await.context("recv challenge")?;
        let challenge_bytes = b64.decode(&challenge.challenge)?;

        // Sign
        let kp = auth::SshKeyPair {
            signing_key: signing_key.clone(),
            key_type: "ssh-ed25519".to_string(),
            path: std::path::PathBuf::from("/dev/null"),
        };
        let sig = kp.sign_challenge(&challenge_bytes);

        let auth_resp = protocol::AuthResponse {
            signature: b64.encode(&sig),
        };
        send_quic_json(&mut send, &auth_resp).await?;
        send.finish().context("finish auth send")?;

        // Receive result
        let result: protocol::AuthResult = recv_quic_json(&mut reader).await?;
        Ok(result)
    }

    #[tokio::test]
    async fn quic_auth_success() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        // Server: accept one connection, auth the first stream
        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        // Client: connect and authenticate
        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success, "auth should succeed");
        assert_eq!(result.version.as_deref(), Some("0.1.0-test"));
        assert!(result.mux_enabled.unwrap_or(false));

        // Close connection (server loop will exit)
        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_auth_wrong_key() {
        let server_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&server_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        // Use a different key (not authorized)
        let wrong_key = SigningKey::generate(&mut rand::thread_rng());
        let result = client_authenticate(&conn, &wrong_key).await;

        // Should get failure result or connection closed
        match result {
            Ok(r) => assert!(!r.success, "auth should fail with wrong key"),
            Err(_) => {} // Connection closed by server is also acceptable
        }

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_exec_channel() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        // Authenticate first
        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Open exec channel
        let (mut send, recv) = conn.open_bi().await.unwrap();

        // Send header: "exec\n"
        send.write_all(b"exec\n").await.unwrap();
        // Send command: "echo hello_quic\n"
        send.write_all(b"echo hello_quic\n").await.unwrap();
        send.finish().unwrap();

        // Read response
        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();

        assert!(
            response.starts_with("OK\n"),
            "expected OK prefix, got: {:?}",
            response
        );
        assert!(
            response.contains("hello_quic"),
            "expected echo output, got: {:?}",
            response
        );

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_tunnel_echo() {
        use tokio::net::TcpListener;

        // Start TCP echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = echo_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            loop {
                let n = match conn.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                if conn.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });

        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        // Auth
        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Open tunnel channel
        let (mut send, recv) = conn.open_bi().await.unwrap();

        // Header: tunnel\0target\n
        let header = format!("tunnel\0{}\n", echo_addr);
        send.write_all(header.as_bytes()).await.unwrap();

        // Read OK response
        let mut reader = BufReader::new(recv);
        let mut ok_line = String::new();
        reader.read_line(&mut ok_line).await.unwrap();
        assert_eq!(ok_line.trim(), "OK");

        // Send data through tunnel
        send.write_all(b"hello tunnel").await.unwrap();

        // Read echoed data — give the echo server some time
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Close and cleanup
        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_unknown_channel_type() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        // Auth
        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Open unknown channel type
        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(b"foobar\n").await.unwrap();
        send.finish().unwrap();

        // Should get error response
        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();
        assert!(
            response.contains("ERROR"),
            "expected error for unknown channel, got: {:?}",
            response
        );

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[test]
    fn extract_ed25519_raw_32_bytes() {
        let raw = vec![0x42u8; 32];
        assert_eq!(extract_ed25519_raw(&raw).unwrap(), raw);
    }

    #[test]
    fn extract_ed25519_raw_ssh_wire() {
        let key_type = b"ssh-ed25519";
        let raw_key = vec![0x42u8; 32];
        let mut wire = Vec::new();
        wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        wire.extend_from_slice(key_type);
        wire.extend_from_slice(&(raw_key.len() as u32).to_be_bytes());
        wire.extend_from_slice(&raw_key);

        let extracted = extract_ed25519_raw(&wire).unwrap();
        assert_eq!(extracted, raw_key);
    }

    #[test]
    fn extract_ed25519_sig_64_bytes() {
        let sig = vec![0x42u8; 64];
        assert_eq!(extract_ed25519_sig(&sig).unwrap(), sig);
    }

    #[test]
    fn extract_invalid_key_fails() {
        let short = vec![0x42u8; 10];
        assert!(extract_ed25519_raw(&short).is_err());
    }

    #[test]
    fn extract_invalid_sig_fails() {
        let short = vec![0x42u8; 10];
        assert!(extract_ed25519_sig(&short).is_err());
    }

    #[tokio::test]
    async fn quic_push_pull_roundtrip() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        // Authenticate
        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Create temp file path
        let tmp_dir = tempfile::tempdir().unwrap();
        let file_path = tmp_dir.path().join("test_push.dat");
        let file_path_str = file_path.to_str().unwrap();

        // === PUSH ===
        let test_data = b"hello QUIC push/pull!";
        {
            let (mut send, recv) = conn.open_bi().await.unwrap();
            let header = format!("push\0{}\n", file_path_str);
            send.write_all(header.as_bytes()).await.unwrap();

            let size = test_data.len() as u64;
            send.write_all(&size.to_be_bytes()).await.unwrap();
            send.write_all(test_data).await.unwrap();
            send.finish().unwrap();

            let mut response = String::new();
            let mut reader = BufReader::new(recv);
            reader.read_to_string(&mut response).await.unwrap();
            assert!(
                response.starts_with("OK\n"),
                "push should succeed, got: {:?}",
                response
            );
        }

        // Verify file was written
        let written = tokio::fs::read(&file_path).await.unwrap();
        assert_eq!(written, test_data);

        // === PULL ===
        {
            let (mut send, recv) = conn.open_bi().await.unwrap();
            let header = format!("pull\0{}\n", file_path_str);
            send.write_all(header.as_bytes()).await.unwrap();
            send.finish().unwrap();

            let mut reader = BufReader::new(recv);
            let mut status_line = String::new();
            reader.read_line(&mut status_line).await.unwrap();
            assert_eq!(status_line.trim(), "OK");

            let mut size_buf = [0u8; 8];
            reader.read_exact(&mut size_buf).await.unwrap();
            let size = u64::from_be_bytes(size_buf);
            assert_eq!(size, test_data.len() as u64);

            let mut data = vec![0u8; size as usize];
            reader.read_exact(&mut data).await.unwrap();
            assert_eq!(data, test_data);
        }

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_push_permission_denied() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());

        // Create context with push disabled
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let mut perms = auth::KeyPermissions::default();
        perms.allow_push = false;
        let ak = auth::AuthorizedKey {
            key_type: "ssh-ed25519".to_string(),
            key_data: pub_bytes.to_vec(),
            comment: Some("test@host".to_string()),
            permissions: perms,
        };
        let ctx = Arc::new(ServerContext {
            authorized_keys: vec![ak],
            revoked_keys: std::collections::HashSet::new(),
            server_version: "0.1.0-test".to_string(),
            banner: None,
            caps: vec![],
            session_store: session::SessionStore::new(),
            rate_limiter: ratelimit::AuthRateLimiter::new(),
            allowed_tunnels: vec![],
            totp_secrets: vec![],
            totp_recovery_path: None,
        });

        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Try push — should be denied
        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(b"push\0/tmp/denied.dat\n").await.unwrap();
        send.write_all(&8u64.to_be_bytes()).await.unwrap();
        send.write_all(b"testdata").await.unwrap();
        send.finish().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();
        assert!(
            response.contains("ERROR") && response.contains("not permitted"),
            "expected permission denied, got: {:?}",
            response
        );

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_pull_nonexistent_file() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Pull nonexistent file
        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(b"pull\0/tmp/nonexistent_quic_test_xyz.dat\n")
            .await
            .unwrap();
        send.finish().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();
        assert!(
            response.contains("ERROR"),
            "expected error for missing file, got: {:?}",
            response
        );

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_push_creates_parent_dirs() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Push to nested path that doesn't exist yet
        let tmp_dir = tempfile::tempdir().unwrap();
        let nested = tmp_dir.path().join("a").join("b").join("c").join("test.txt");
        let nested_str = nested.to_str().unwrap();

        let (mut send, recv) = conn.open_bi().await.unwrap();
        let header = format!("push\0{}\n", nested_str);
        send.write_all(header.as_bytes()).await.unwrap();

        let data = b"nested data";
        send.write_all(&(data.len() as u64).to_be_bytes()).await.unwrap();
        send.write_all(data).await.unwrap();
        send.finish().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("OK\n"), "got: {:?}", response);

        // Verify
        let content = tokio::fs::read(&nested).await.unwrap();
        assert_eq!(content, data);

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_push_empty_file() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        let tmp_dir = tempfile::tempdir().unwrap();
        let file_path = tmp_dir.path().join("empty.dat");
        let file_path_str = file_path.to_str().unwrap();

        // Push empty file
        let (mut send, recv) = conn.open_bi().await.unwrap();
        let header = format!("push\0{}\n", file_path_str);
        send.write_all(header.as_bytes()).await.unwrap();
        send.write_all(&0u64.to_be_bytes()).await.unwrap();
        send.finish().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("OK\n"), "got: {:?}", response);

        // Verify empty file
        let content = tokio::fs::read(&file_path).await.unwrap();
        assert!(content.is_empty());

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_ls_roundtrip() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep.connect(server_addr, "localhost").unwrap().await.unwrap();
        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Create a temp dir with a known file
        let tmp_dir = tempfile::tempdir().unwrap();
        std::fs::write(tmp_dir.path().join("hello.txt"), b"hi").unwrap();

        // List the temp dir
        let (mut send, recv) = conn.open_bi().await.unwrap();
        let header = format!("ls\0{}\n", tmp_dir.path().to_str().unwrap());
        send.write_all(header.as_bytes()).await.unwrap();
        send.finish().unwrap();

        let mut reader = BufReader::new(recv);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        // Should be valid JSON array containing "hello.txt"
        let files: Vec<rsh_core::protocol::FileInfo> = serde_json::from_str(&line)
            .unwrap_or_else(|_| panic!("expected JSON array, got: {:?}", line));
        assert!(
            files.iter().any(|f| f.name == "hello.txt"),
            "hello.txt not found in listing"
        );

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_ls_nonexistent_dir() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep.connect(server_addr, "localhost").unwrap().await.unwrap();
        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(b"ls\0/tmp/nonexistent_quic_ls_test_xyz\n").await.unwrap();
        send.finish().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();
        assert!(
            response.contains("ERROR"),
            "expected error for missing dir, got: {:?}",
            response
        );

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    #[cfg(not(target_os = "windows"))]
    async fn quic_shell_handshake() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);
        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Open shell channel: "shell\0{COLSxROWS}\n"
        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(b"shell\080x24\n").await.unwrap();

        // Server should respond with "OK\n"
        let mut reader = BufReader::new(recv);
        let mut ok_line = String::new();
        reader.read_line(&mut ok_line).await.unwrap();
        assert_eq!(ok_line.trim(), "OK", "expected OK, got: {:?}", ok_line);

        // Disconnect — server relay loop should exit cleanly
        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn quic_shell_permission_denied() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());

        // Create context with shell disabled
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let mut perms = auth::KeyPermissions::default();
        perms.allow_shell = false;
        let ak = auth::AuthorizedKey {
            key_type: "ssh-ed25519".to_string(),
            key_data: pub_bytes.to_vec(),
            comment: Some("test@host".to_string()),
            permissions: perms,
        };
        let ctx = Arc::new(ServerContext {
            authorized_keys: vec![ak],
            revoked_keys: std::collections::HashSet::new(),
            server_version: "0.1.0-test".to_string(),
            banner: None,
            caps: vec![],
            session_store: session::SessionStore::new(),
            rate_limiter: ratelimit::AuthRateLimiter::new(),
            allowed_tunnels: vec![],
            totp_secrets: vec![],
            totp_recovery_path: None,
        });

        let (server_ep, client_ep, server_addr) = make_quic_endpoint_pair().unwrap();

        let ctx_clone = ctx.clone();
        let server_handle = tokio::spawn(async move {
            let incoming = server_ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            handle_quic_connection(conn, ctx_clone).await
        });

        let conn = client_ep
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let result = client_authenticate(&conn, &signing_key).await.unwrap();
        assert!(result.success);

        // Try shell — should be denied
        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(b"shell\n").await.unwrap();
        send.finish().unwrap();

        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader.read_to_string(&mut response).await.unwrap();
        assert!(
            response.contains("ERROR") && response.contains("not permitted"),
            "expected permission denied, got: {:?}",
            response
        );

        conn.close(quinn::VarInt::from_u32(0), b"done");
        let _ = server_handle.await;
    }
}
