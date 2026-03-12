//! Client-side TCP tunnel — `ssh -L` equivalent over the rsh protocol.
//!
//! Binds a local TCP listener and forwards each accepted connection through
//! the rsh server's "connect" request type, providing transparent TCP tunneling.
//!
//! # Protocol
//!
//! 1. Client binds a local TCP port (e.g., `127.0.0.1:5432`)
//! 2. For each incoming local connection:
//!    a. Send a "connect" request to the rsh server with the remote target
//!    b. Server connects to the target and sends back success
//!    c. Bidirectional relay: local TCP ↔ rsh wire ↔ remote target
//!
//! # Wire format
//!
//! Both directions use length-prefixed framing (4-byte BE header + payload).
//! An empty message (length=0) signals EOF from either side.
//!
//! # Example
//!
//! ```text
//! # Forward local:5432 → remote_db:5432 through rsh
//! rsh -h server tunnel 127.0.0.1:5432 remote_db:5432
//! ```

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use rsh_core::{protocol, wire};

/// Parse a tunnel specification string into (local_bind, remote_target).
///
/// Accepts formats:
/// - `local_port:remote_host:remote_port` (ssh -L style)
/// - Two separate arguments via the caller
///
/// # Returns
/// `(local_bind_addr, remote_target)` tuple.
pub fn parse_tunnel_spec(local_bind: &str, remote_target: &str) -> Result<(String, String)> {
    // Ensure local_bind has a host part
    let local = if !local_bind.contains(':') {
        format!("127.0.0.1:{}", local_bind)
    } else {
        local_bind.to_string()
    };

    // Validate remote target has host:port format
    if !remote_target.contains(':') {
        anyhow::bail!(
            "remote target must be host:port format, got: {}",
            remote_target
        );
    }

    Ok((local, remote_target.to_string()))
}

/// Run a local TCP tunnel that forwards connections through the rsh server.
///
/// This function:
/// 1. Binds a local TCP listener on `local_bind`
/// 2. For each accepted connection, establishes a tunnel through the rsh server
/// 3. Relays data bidirectionally until either side closes
///
/// The rsh connection must already be authenticated. This function sends a
/// "connect" request for each incoming local connection using a fresh rsh
/// connection (since "connect" hijacks the connection).
///
/// # Arguments
/// * `stream` - Authenticated rsh stream (will be hijacked for the first connection)
/// * `local_bind` - Local address to bind (e.g., "127.0.0.1:5432")
/// * `remote_target` - Remote target for the server to connect to (e.g., "db:5432")
///
/// # Single-connection mode
///
/// Since "connect" hijacks the rsh connection, this function handles exactly
/// one tunneled connection per rsh session. For multiple simultaneous tunnels,
/// the caller should establish multiple rsh connections.
pub async fn run_tunnel<S>(
    stream: &mut S,
    local_bind: &str,
    remote_target: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let listener = TcpListener::bind(local_bind)
        .await
        .with_context(|| format!("bind local tunnel endpoint: {}", local_bind))?;

    let local_addr = listener.local_addr().context("get local address")?;
    info!(
        "tunnel listening on {} → forwarding to {} via rsh",
        local_addr, remote_target
    );

    // Accept one connection (connect hijacks the stream)
    let (local_stream, peer) = listener
        .accept()
        .await
        .context("accept local connection")?;
    local_stream.set_nodelay(true).ok();
    info!("tunnel: accepted local connection from {}", peer);

    // Send "connect" request to rsh server
    let connect_req = protocol::Request {
        req_type: "connect".to_string(),
        command: Some(remote_target.to_string()),
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
    };
    wire::send_json(stream, &connect_req)
        .await
        .context("send connect request")?;

    // Receive acknowledgment
    let ack: protocol::Response = wire::recv_json(stream)
        .await
        .context("receive connect ack")?;
    if !ack.success {
        anyhow::bail!(
            "server rejected tunnel: {}",
            ack.error.unwrap_or_else(|| "unknown error".into())
        );
    }

    info!("tunnel: server connected to {}, relaying traffic", remote_target);

    // Relay bidirectionally: local TCP ↔ rsh wire protocol
    relay_tunnel(stream, local_stream).await?;

    info!("tunnel: closed");
    Ok(())
}

/// Relay traffic between a local TCP stream and the rsh wire protocol.
///
/// - Local → rsh: read raw TCP bytes, send as length-prefixed frames
/// - rsh → Local: receive length-prefixed frames, write raw TCP bytes
/// - Empty frame (length=0) signals EOF from either direction
async fn relay_tunnel<S>(
    rsh_stream: &mut S,
    local_stream: TcpStream,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut local_read, mut local_write) = local_stream.into_split();
    let mut local_buf = vec![0u8; 32768];

    loop {
        tokio::select! {
            // Local → rsh: read from local TCP, send as wire frame
            result = local_read.read(&mut local_buf) => {
                match result {
                    Ok(0) => {
                        // Local connection closed — send EOF to server
                        debug!("tunnel: local connection closed");
                        wire::send_message(rsh_stream, &[]).await.ok();
                        break;
                    }
                    Ok(n) => {
                        wire::send_message(rsh_stream, &local_buf[..n])
                            .await
                            .context("send to rsh server")?;
                    }
                    Err(e) => {
                        debug!("tunnel: local read error: {}", e);
                        wire::send_message(rsh_stream, &[]).await.ok();
                        break;
                    }
                }
            }

            // rsh → Local: receive wire frame, write to local TCP
            result = wire::recv_message(rsh_stream) => {
                match result {
                    Ok(data) => {
                        if data.is_empty() {
                            // Server sent EOF — remote target closed
                            debug!("tunnel: server sent EOF");
                            local_write.shutdown().await.ok();
                            break;
                        }
                        local_write.write_all(&data)
                            .await
                            .context("write to local connection")?;
                    }
                    Err(_) => {
                        debug!("tunnel: rsh connection closed");
                        local_write.shutdown().await.ok();
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Run a tunnel listener that accepts multiple connections.
///
/// For each connection, establishes a new rsh session with `connect_fn`,
/// then relays traffic. This enables multiple simultaneous tunnels.
///
/// # Arguments
/// * `local_bind` - Local address to listen on
/// * `remote_target` - Remote target for the server to connect to
/// * `connect_fn` - Factory function that creates a new authenticated rsh connection
pub async fn run_multi_tunnel<F, Fut, S>(
    local_bind: &str,
    remote_target: &str,
    connect_fn: F,
) -> Result<()>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<S>> + Send,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let listener = TcpListener::bind(local_bind)
        .await
        .with_context(|| format!("bind local tunnel endpoint: {}", local_bind))?;

    let local_addr = listener.local_addr().context("get local address")?;
    info!(
        "multi-tunnel listening on {} → forwarding to {}",
        local_addr, remote_target
    );

    loop {
        let (local_stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("tunnel accept error: {}", e);
                continue;
            }
        };
        local_stream.set_nodelay(true).ok();
        info!("multi-tunnel: accepted connection from {}", peer);

        // Establish new rsh connection for this tunnel
        let remote = remote_target.to_string();
        match connect_fn().await {
            Ok(mut rsh_stream) => {
                tokio::spawn(async move {
                    // Send connect request
                    let connect_req = protocol::Request {
                        req_type: "connect".to_string(),
                        command: Some(remote.clone()),
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
                    };

                    if let Err(e) = wire::send_json(&mut rsh_stream, &connect_req).await {
                        warn!("multi-tunnel: send connect failed: {}", e);
                        return;
                    }

                    match wire::recv_json::<_, protocol::Response>(&mut rsh_stream).await {
                        Ok(ack) if ack.success => {
                            if let Err(e) = relay_tunnel(&mut rsh_stream, local_stream).await {
                                debug!("multi-tunnel: relay error: {}", e);
                            }
                        }
                        Ok(ack) => {
                            warn!(
                                "multi-tunnel: server rejected: {}",
                                ack.error.unwrap_or_default()
                            );
                        }
                        Err(e) => {
                            warn!("multi-tunnel: recv ack failed: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                warn!("multi-tunnel: failed to connect to rsh server: {}", e);
                drop(local_stream);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn parse_tunnel_spec_port_only() {
        let (local, remote) = parse_tunnel_spec("5432", "db:5432").unwrap();
        assert_eq!(local, "127.0.0.1:5432");
        assert_eq!(remote, "db:5432");
    }

    #[test]
    fn parse_tunnel_spec_full_local() {
        let (local, remote) = parse_tunnel_spec("0.0.0.0:8080", "web:80").unwrap();
        assert_eq!(local, "0.0.0.0:8080");
        assert_eq!(remote, "web:80");
    }

    #[test]
    fn parse_tunnel_spec_missing_remote_port() {
        let result = parse_tunnel_spec("5432", "db");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn relay_tunnel_echo_roundtrip() {
        // Set up a target echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut conn, _) = echo_listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            loop {
                let n = conn.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                conn.write_all(&buf[..n]).await.unwrap();
            }
        });

        // Simulate the rsh server side (reads connect request, sends ack, relays)
        let (mut rsh_client, mut rsh_server) = tokio::io::duplex(8192);

        let target = echo_addr.to_string();
        let server_handle = tokio::spawn(async move {
            // Read connect request from client
            let req: protocol::Request = wire::recv_json(&mut rsh_server).await.unwrap();
            assert_eq!(req.req_type, "connect");
            assert_eq!(req.command.as_deref(), Some(target.as_str()));

            // Send ack
            let ack = protocol::Response {
                success: true,
                output: None,
                error: None,
                size: None,
                binary: None,
                gzip: None,
            };
            wire::send_json(&mut rsh_server, &ack).await.unwrap();

            // Connect to target and relay
            let target_stream = TcpStream::connect(&target).await.unwrap();
            let (mut target_read, mut target_write) = target_stream.into_split();
            let mut target_buf = vec![0u8; 32768];

            loop {
                tokio::select! {
                    result = wire::recv_message(&mut rsh_server) => {
                        match result {
                            Ok(data) if data.is_empty() => {
                                target_write.shutdown().await.ok();
                                break;
                            }
                            Ok(data) => {
                                target_write.write_all(&data).await.unwrap();
                            }
                            Err(_) => break,
                        }
                    }
                    result = target_read.read(&mut target_buf) => {
                        match result {
                            Ok(0) => {
                                wire::send_message(&mut rsh_server, &[]).await.ok();
                                break;
                            }
                            Ok(n) => {
                                wire::send_message(&mut rsh_server, &target_buf[..n]).await.unwrap();
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        // Bind local tunnel listener
        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();

        // Run tunnel in background (uses the listener we already bound)
        let tunnel_handle = tokio::spawn(async move {
            let (local_stream, _) = local_listener.accept().await.unwrap();
            local_stream.set_nodelay(true).ok();

            // Send connect request
            let connect_req = protocol::Request {
                req_type: "connect".to_string(),
                command: Some(echo_addr.to_string()),
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
            };
            wire::send_json(&mut rsh_client, &connect_req).await.unwrap();

            let ack: protocol::Response = wire::recv_json(&mut rsh_client).await.unwrap();
            assert!(ack.success);

            relay_tunnel(&mut rsh_client, local_stream).await.unwrap();
        });

        // Connect to the local tunnel endpoint
        let mut local_conn = TcpStream::connect(local_addr).await.unwrap();

        // Send data through the tunnel
        let test_data = b"hello through tunnel";
        local_conn.write_all(test_data).await.unwrap();

        // Read echoed data
        let mut response = vec![0u8; test_data.len()];
        local_conn.read_exact(&mut response).await.unwrap();
        assert_eq!(response, test_data);

        // Close local connection
        local_conn.shutdown().await.ok();
        drop(local_conn);

        // Wait for tunnel and server to finish
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async {
                tunnel_handle.await.unwrap();
                server_handle.await.unwrap();
            },
        )
        .await;
    }

    #[tokio::test]
    async fn relay_tunnel_server_closes_first() {
        // Simulate rsh server that connects and immediately closes
        let (mut rsh_client, mut rsh_server) = tokio::io::duplex(8192);

        let server_handle = tokio::spawn(async move {
            // Read connect request
            let _: protocol::Request = wire::recv_json(&mut rsh_server).await.unwrap();

            // Send ack
            let ack = protocol::Response {
                success: true,
                output: None,
                error: None,
                size: None,
                binary: None,
                gzip: None,
            };
            wire::send_json(&mut rsh_server, &ack).await.unwrap();

            // Send EOF immediately (remote target closed)
            wire::send_message(&mut rsh_server, &[]).await.unwrap();
        });

        // Create local connection pair
        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();

        let tunnel_handle = tokio::spawn(async move {
            let (local_stream, _) = local_listener.accept().await.unwrap();

            let connect_req = protocol::Request {
                req_type: "connect".to_string(),
                command: Some("target:1234".to_string()),
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
            };
            wire::send_json(&mut rsh_client, &connect_req).await.unwrap();

            let ack: protocol::Response = wire::recv_json(&mut rsh_client).await.unwrap();
            assert!(ack.success);

            relay_tunnel(&mut rsh_client, local_stream).await.unwrap();
        });

        // Connect locally
        let mut local_conn = TcpStream::connect(local_addr).await.unwrap();

        // Try to read — should get EOF (server closed immediately)
        let mut buf = [0u8; 1];
        let n = local_conn.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "expected EOF from local connection");

        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async {
                tunnel_handle.await.unwrap();
                server_handle.await.unwrap();
            },
        )
        .await;
    }

    #[tokio::test]
    async fn relay_tunnel_server_rejects() {
        let (mut rsh_client, mut rsh_server) = tokio::io::duplex(8192);

        let server_handle = tokio::spawn(async move {
            let _: protocol::Request = wire::recv_json(&mut rsh_server).await.unwrap();

            // Reject the connection
            let ack = protocol::Response {
                success: false,
                output: None,
                error: Some("connection refused".to_string()),
                size: None,
                binary: None,
                gzip: None,
            };
            wire::send_json(&mut rsh_server, &ack).await.unwrap();
        });

        // run_tunnel should fail with server rejection
        let local_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();

        let tunnel_handle = tokio::spawn(async move {
            let (_local_stream, _) = local_listener.accept().await.unwrap();

            let connect_req = protocol::Request {
                req_type: "connect".to_string(),
                command: Some("unreachable:9999".to_string()),
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
            };
            wire::send_json(&mut rsh_client, &connect_req).await.unwrap();

            let ack: protocol::Response = wire::recv_json(&mut rsh_client).await.unwrap();
            // Server rejected — should not relay
            assert!(!ack.success);
            assert!(ack.error.unwrap().contains("refused"));
        });

        // Connect so the tunnel_handle can proceed
        let _local = TcpStream::connect(local_addr).await.unwrap();

        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            async {
                tunnel_handle.await.unwrap();
                server_handle.await.unwrap();
            },
        )
        .await;
    }

    // ------------------------------------------------------------------
    // run_tunnel entry-point tests
    // ------------------------------------------------------------------

    /// Helper: spawn a mock rsh server that handles the "connect" request
    /// and then echoes data back through wire-protocol framing.
    fn spawn_echo_rsh_server(
        mut rsh_server: tokio::io::DuplexStream,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // Read connect request
            let req: protocol::Request = wire::recv_json(&mut rsh_server).await.unwrap();
            assert_eq!(req.req_type, "connect");

            // Send success ack
            let ack = protocol::Response {
                success: true,
                output: None,
                error: None,
                size: None,
                binary: None,
                gzip: None,
            };
            wire::send_json(&mut rsh_server, &ack).await.unwrap();

            // Echo loop: read wire frames, send them back
            loop {
                match wire::recv_message(&mut rsh_server).await {
                    Ok(data) if data.is_empty() => {
                        wire::send_message(&mut rsh_server, &[]).await.ok();
                        break;
                    }
                    Ok(data) => {
                        wire::send_message(&mut rsh_server, &data).await.unwrap();
                    }
                    Err(_) => break,
                }
            }
        })
    }

    /// Helper: find a free ephemeral port by binding and immediately releasing.
    async fn free_port() -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        addr
    }

    #[tokio::test]
    async fn run_tunnel_echo_roundtrip() {
        let (mut rsh_client, rsh_server) = tokio::io::duplex(8192);
        let server_handle = spawn_echo_rsh_server(rsh_server);

        let local_addr = free_port().await;

        // run_tunnel binds the port, accepts one connection, sends connect, relays
        let tunnel_handle = tokio::spawn(async move {
            run_tunnel(&mut rsh_client, &local_addr.to_string(), "echo:1234").await
        });

        // Small delay to let run_tunnel bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect to the local tunnel endpoint
        let mut conn = TcpStream::connect(local_addr).await.unwrap();

        // Send data and read echo
        conn.write_all(b"run_tunnel works").await.unwrap();
        let mut buf = vec![0u8; 16];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"run_tunnel works");

        // Close
        conn.shutdown().await.ok();
        drop(conn);

        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tunnel_handle.await.unwrap().unwrap();
            server_handle.await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn run_tunnel_server_rejects_connect() {
        let (mut rsh_client, mut rsh_server) = tokio::io::duplex(8192);

        let server_handle = tokio::spawn(async move {
            let _: protocol::Request = wire::recv_json(&mut rsh_server).await.unwrap();
            let ack = protocol::Response {
                success: false,
                output: None,
                error: Some("target unreachable".to_string()),
                size: None,
                binary: None,
                gzip: None,
            };
            wire::send_json(&mut rsh_server, &ack).await.unwrap();
        });

        let local_addr = free_port().await;

        let tunnel_handle = tokio::spawn(async move {
            run_tunnel(&mut rsh_client, &local_addr.to_string(), "bad:9999").await
        });

        // Small delay to let run_tunnel bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect so run_tunnel's accept() returns
        let _conn = TcpStream::connect(local_addr).await.unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let r = tunnel_handle.await.unwrap();
            server_handle.await.unwrap();
            r
        })
        .await
        .unwrap();

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("target unreachable"),
            "expected rejection error, got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn run_tunnel_bind_failure() {
        // Bind a port, then try to run_tunnel on the same port — should fail
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap();

        let (mut rsh_client, _rsh_server) = tokio::io::duplex(8192);
        let result = run_tunnel(&mut rsh_client, &addr.to_string(), "host:80").await;
        assert!(result.is_err());
        // occupied port prevents bind
    }

    // ------------------------------------------------------------------
    // run_multi_tunnel entry-point tests
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn run_multi_tunnel_handles_two_connections() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let conn_count = Arc::new(AtomicU32::new(0));
        let conn_count_clone = conn_count.clone();

        let local_addr = free_port().await;

        // connect_fn returns a fresh duplex stream with a mock echo server each time
        let connect_fn = move || {
            let cc = conn_count_clone.clone();
            async move {
                cc.fetch_add(1, Ordering::SeqCst);
                let (client_end, server_end) = tokio::io::duplex(8192);
                // Spawn echo server for this connection
                spawn_echo_rsh_server(server_end);
                Ok(client_end)
            }
        };

        // run_multi_tunnel loops forever, so spawn it and use timeout
        let tunnel_handle = tokio::spawn(async move {
            run_multi_tunnel(&local_addr.to_string(), "db:5432", connect_fn).await
        });

        // Give listener time to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connection 1
        let mut conn1 = TcpStream::connect(local_addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        conn1.write_all(b"hello1").await.unwrap();
        let mut buf1 = vec![0u8; 6];
        conn1.read_exact(&mut buf1).await.unwrap();
        assert_eq!(&buf1, b"hello1");
        conn1.shutdown().await.ok();
        drop(conn1);

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Connection 2
        let mut conn2 = TcpStream::connect(local_addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        conn2.write_all(b"hello2").await.unwrap();
        let mut buf2 = vec![0u8; 6];
        conn2.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"hello2");
        conn2.shutdown().await.ok();
        drop(conn2);

        // connect_fn should have been called twice
        assert_eq!(conn_count.load(Ordering::SeqCst), 2);

        // Cancel the infinite loop
        tunnel_handle.abort();
    }

    #[tokio::test]
    async fn run_multi_tunnel_connect_fn_failure() {
        let local_addr = free_port().await;

        // connect_fn always fails
        let connect_fn = || async {
            Err::<tokio::io::DuplexStream, _>(anyhow::anyhow!("cannot connect"))
        };

        let tunnel_handle = tokio::spawn(async move {
            run_multi_tunnel(&local_addr.to_string(), "db:5432", connect_fn).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect — should be accepted but then dropped (connect_fn fails)
        let mut conn = TcpStream::connect(local_addr).await.unwrap();
        // The local stream should be dropped by the server
        let mut buf = [0u8; 1];
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            conn.read(&mut buf),
        )
        .await;
        // Should get EOF or timeout (stream dropped by multi-tunnel on connect_fn error)
        match result {
            Ok(Ok(0)) => {} // EOF — expected
            Ok(Err(_)) => {} // read error — acceptable
            Err(_) => {}     // timeout — also acceptable
            Ok(Ok(_)) => panic!("expected connection close when connect_fn fails"),
        }

        tunnel_handle.abort();
    }

    #[tokio::test]
    async fn run_multi_tunnel_server_rejects_one() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let call_count = Arc::new(AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        let local_addr = free_port().await;

        // First call: server rejects. Second call: server echoes.
        let connect_fn = move || {
            let cc = call_count_clone.clone();
            async move {
                let n = cc.fetch_add(1, Ordering::SeqCst);
                let (client_end, mut server_end) = tokio::io::duplex(8192);
                if n == 0 {
                    // First connection — reject
                    tokio::spawn(async move {
                        let _: protocol::Request =
                            wire::recv_json(&mut server_end).await.unwrap();
                        let ack = protocol::Response {
                            success: false,
                            output: None,
                            error: Some("rejected".to_string()),
                            size: None,
                            binary: None,
                            gzip: None,
                        };
                        wire::send_json(&mut server_end, &ack).await.unwrap();
                    });
                } else {
                    // Second connection — echo
                    spawn_echo_rsh_server(server_end);
                }
                Ok(client_end)
            }
        };

        let tunnel_handle = tokio::spawn(async move {
            run_multi_tunnel(&local_addr.to_string(), "db:5432", connect_fn).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // First connection — rejected, should get dropped
        let mut conn1 = TcpStream::connect(local_addr).await.unwrap();
        let mut buf = [0u8; 1];
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            conn1.read(&mut buf),
        )
        .await;
        drop(conn1);

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Second connection — should work (echo)
        let mut conn2 = TcpStream::connect(local_addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        conn2.write_all(b"ok").await.unwrap();
        let mut buf2 = vec![0u8; 2];
        conn2.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"ok");
        conn2.shutdown().await.ok();

        assert_eq!(call_count.load(Ordering::SeqCst), 2);
        tunnel_handle.abort();
    }
}
