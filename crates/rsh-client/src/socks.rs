//! SOCKS5 proxy — `ssh -D` equivalent over the rsh protocol.
//!
//! Binds a local SOCKS5 listener and for each accepted connection:
//! 1. Performs the SOCKS5 handshake (RFC 1928, no auth)
//! 2. Extracts the target host:port from the CONNECT request
//! 3. Opens a new rsh connection, sends "connect" to the rsh server
//! 4. Relays traffic bidirectionally
//!
//! # Example
//!
//! ```text
//! rsh -h server -D 1080
//! # Then configure browser/app to use SOCKS5 proxy at 127.0.0.1:1080
//! ```

use std::future::Future;
use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use rsh_core::{protocol, wire};

/// SOCKS5 protocol version.
const SOCKS5_VERSION: u8 = 0x05;

/// SOCKS5 CONNECT command.
const SOCKS5_CMD_CONNECT: u8 = 0x01;

/// SOCKS5 reply codes.
const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_GENERAL_FAILURE: u8 = 0x01;
const SOCKS5_REP_NOT_ALLOWED: u8 = 0x02;
const SOCKS5_REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const SOCKS5_REP_ADDR_NOT_SUPPORTED: u8 = 0x08;

/// SOCKS5 address types.
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

/// Run a SOCKS5 proxy that tunnels connections through the rsh server.
///
/// For each SOCKS5 CONNECT request, establishes a new rsh connection
/// via `connect_fn`, sends a "connect" request to the rsh server, and
/// relays traffic bidirectionally.
///
/// # Arguments
/// * `listen_port` - Local port to bind the SOCKS5 listener on
/// * `connect_fn` - Factory function that creates a new authenticated rsh connection
pub async fn run_socks5<F, Fut, S>(listen_port: u16, connect_fn: F) -> Result<()>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<S>> + Send,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let bind_addr = format!("127.0.0.1:{}", listen_port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("SOCKS5: bind {}", bind_addr))?;

    info!(
        "SOCKS5 proxy listening on 127.0.0.1:{}",
        listen_port
    );
    eprintln!(
        "SOCKS5 proxy listening on 127.0.0.1:{}",
        listen_port
    );

    loop {
        let (client_stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("SOCKS5: accept error: {}", e);
                continue;
            }
        };
        client_stream.set_nodelay(true).ok();
        debug!("SOCKS5: accepted connection from {}", peer);

        match connect_fn().await {
            Ok(rsh_stream) => {
                tokio::spawn(async move {
                    if let Err(e) = handle_socks5_client(client_stream, rsh_stream).await {
                        debug!("SOCKS5: client handler error: {}", e);
                    }
                });
            }
            Err(e) => {
                warn!("SOCKS5: failed to connect to rsh server: {}", e);
                drop(client_stream);
            }
        }
    }
}

/// Handle a single SOCKS5 client connection.
///
/// Performs the SOCKS5 handshake, extracts the target, sends a "connect"
/// request to the rsh server, and relays traffic.
async fn handle_socks5_client<C, S>(mut client: C, mut rsh_stream: S) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // --- SOCKS5 handshake (RFC 1928) ---

    // Read version + number of methods
    let mut buf = [0u8; 258];
    client
        .read_exact(&mut buf[..2])
        .await
        .context("read SOCKS5 greeting")?;
    if buf[0] != SOCKS5_VERSION {
        anyhow::bail!("not SOCKS5 (version={})", buf[0]);
    }
    let n_methods = buf[1] as usize;

    // Read authentication methods
    client
        .read_exact(&mut buf[..n_methods])
        .await
        .context("read SOCKS5 methods")?;

    // Reply: no authentication required (0x00)
    client
        .write_all(&[SOCKS5_VERSION, 0x00])
        .await
        .context("send SOCKS5 method selection")?;

    // Read connection request: VER CMD RSV ATYP DST.ADDR DST.PORT
    client
        .read_exact(&mut buf[..4])
        .await
        .context("read SOCKS5 request")?;
    if buf[0] != SOCKS5_VERSION {
        anyhow::bail!("invalid SOCKS5 request version");
    }
    if buf[1] != SOCKS5_CMD_CONNECT {
        // Only CONNECT supported
        send_socks5_reply(&mut client, SOCKS5_REP_CMD_NOT_SUPPORTED).await.ok();
        anyhow::bail!("unsupported SOCKS5 command: {:#04x}", buf[1]);
    }

    let atyp = buf[3];
    let target_host = match atyp {
        SOCKS5_ATYP_IPV4 => {
            client.read_exact(&mut buf[..4]).await.context("read IPv4")?;
            Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]).to_string()
        }
        SOCKS5_ATYP_DOMAIN => {
            client.read_exact(&mut buf[..1]).await.context("read domain len")?;
            let domain_len = buf[0] as usize;
            client
                .read_exact(&mut buf[..domain_len])
                .await
                .context("read domain")?;
            String::from_utf8_lossy(&buf[..domain_len]).to_string()
        }
        SOCKS5_ATYP_IPV6 => {
            client.read_exact(&mut buf[..16]).await.context("read IPv6")?;
            // Format as IPv6 address
            let mut parts = Vec::with_capacity(8);
            for i in 0..8 {
                parts.push(format!("{:x}", u16::from_be_bytes([buf[i * 2], buf[i * 2 + 1]])));
            }
            parts.join(":")
        }
        _ => {
            send_socks5_reply(&mut client, SOCKS5_REP_ADDR_NOT_SUPPORTED).await.ok();
            anyhow::bail!("unsupported SOCKS5 address type: {:#04x}", atyp);
        }
    };

    // Read destination port (2 bytes, big-endian)
    client.read_exact(&mut buf[..2]).await.context("read port")?;
    let target_port = u16::from_be_bytes([buf[0], buf[1]]);
    let target = format!("{}:{}", target_host, target_port);

    debug!("SOCKS5: CONNECT {}", target);

    // Send "connect" request to rsh server
    let connect_req = protocol::Request {
        req_type: "connect".to_string(),
        command: Some(target.clone()),
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
        send_socks5_reply(&mut client, SOCKS5_REP_GENERAL_FAILURE).await.ok();
        anyhow::bail!("send connect to rsh server: {}", e);
    }

    // Receive acknowledgment from rsh server
    let ack: protocol::Response = match wire::recv_json(&mut rsh_stream).await {
        Ok(ack) => ack,
        Err(e) => {
            send_socks5_reply(&mut client, SOCKS5_REP_GENERAL_FAILURE).await.ok();
            anyhow::bail!("recv connect ack: {}", e);
        }
    };

    if !ack.success {
        send_socks5_reply(&mut client, SOCKS5_REP_NOT_ALLOWED).await.ok();
        anyhow::bail!(
            "rsh server rejected connect to {}: {}",
            target,
            ack.error.unwrap_or_default()
        );
    }

    // SOCKS5 success reply
    send_socks5_reply(&mut client, SOCKS5_REP_SUCCESS).await?;

    debug!("SOCKS5: tunnel established to {}", target);

    // Relay traffic bidirectionally
    relay_socks5(&mut rsh_stream, client).await?;

    debug!("SOCKS5: tunnel closed for {}", target);
    Ok(())
}

/// Send a SOCKS5 reply to the client.
///
/// Reply format: VER REP RSV ATYP BND.ADDR BND.PORT
/// We always reply with 0.0.0.0:0 as bound address.
async fn send_socks5_reply<W: AsyncWrite + Unpin>(
    writer: &mut W,
    reply_code: u8,
) -> Result<()> {
    // VER=5 REP=code RSV=0 ATYP=1(IPv4) ADDR=0.0.0.0 PORT=0
    let reply = [SOCKS5_VERSION, reply_code, 0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    writer
        .write_all(&reply)
        .await
        .context("send SOCKS5 reply")?;
    Ok(())
}

/// Relay traffic between a SOCKS5 client and the rsh wire protocol.
///
/// Same as tunnel's relay but for SOCKS5 context.
async fn relay_socks5<S, C>(rsh_stream: &mut S, client: C) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let mut buf = vec![0u8; 32768];

    loop {
        tokio::select! {
            // Client → rsh: read from SOCKS5 client, send as wire frame
            result = client_read.read(&mut buf) => {
                match result {
                    Ok(0) => {
                        debug!("SOCKS5: client closed");
                        wire::send_message(rsh_stream, &[]).await.ok();
                        break;
                    }
                    Ok(n) => {
                        wire::send_message(rsh_stream, &buf[..n])
                            .await
                            .context("send to rsh")?;
                    }
                    Err(e) => {
                        debug!("SOCKS5: client read error: {}", e);
                        wire::send_message(rsh_stream, &[]).await.ok();
                        break;
                    }
                }
            }

            // rsh → Client: receive wire frame, write to SOCKS5 client
            result = wire::recv_message(rsh_stream) => {
                match result {
                    Ok(data) => {
                        if data.is_empty() {
                            debug!("SOCKS5: server sent EOF");
                            client_write.shutdown().await.ok();
                            break;
                        }
                        client_write.write_all(&data)
                            .await
                            .context("write to SOCKS5 client")?;
                    }
                    Err(_) => {
                        debug!("SOCKS5: rsh connection closed");
                        client_write.shutdown().await.ok();
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_constants() {
        assert_eq!(SOCKS5_VERSION, 0x05);
        assert_eq!(SOCKS5_CMD_CONNECT, 0x01);
        assert_eq!(SOCKS5_ATYP_IPV4, 0x01);
        assert_eq!(SOCKS5_ATYP_DOMAIN, 0x03);
        assert_eq!(SOCKS5_ATYP_IPV6, 0x04);
    }

    #[tokio::test]
    async fn socks5_handshake_ipv4() {
        // Simulate a SOCKS5 client connecting to 1.2.3.4:80
        let (mut client_end, mut server_end) = tokio::io::duplex(4096);
        let (mut rsh_client, mut rsh_server) = tokio::io::duplex(4096);

        let handler = tokio::spawn(async move {
            // Simulate rsh server: read connect request, send success ack, then EOF
            let req: protocol::Request = wire::recv_json(&mut rsh_server).await.unwrap();
            assert_eq!(req.req_type, "connect");
            assert_eq!(req.command.as_deref(), Some("1.2.3.4:80"));

            let ack = protocol::Response {
                success: true,
                output: None,
                error: None,
                size: None,
                binary: None,
                gzip: None,
            };
            wire::send_json(&mut rsh_server, &ack).await.unwrap();

            // Send EOF immediately
            wire::send_message(&mut rsh_server, &[]).await.unwrap();
        });

        let socks_handler = tokio::spawn(async move {
            handle_socks5_client(&mut server_end, &mut rsh_client).await.unwrap();
        });

        // SOCKS5 greeting: version=5, 1 method (no auth)
        client_end.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

        // Read method selection
        let mut resp = [0u8; 2];
        client_end.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]); // no auth

        // CONNECT request: version=5, cmd=CONNECT, rsv=0, atyp=IPv4, addr=1.2.3.4, port=80
        client_end
            .write_all(&[0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50])
            .await
            .unwrap();

        // Read SOCKS5 reply
        let mut reply = [0u8; 10];
        client_end.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x05); // version
        assert_eq!(reply[1], 0x00); // success

        // Read EOF (server sent empty frame → client gets closed)
        let mut buf = [0u8; 1];
        let n = client_end.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);

        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            handler.await.unwrap();
            socks_handler.await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn socks5_handshake_domain() {
        let (mut client_end, mut server_end) = tokio::io::duplex(4096);
        let (mut rsh_client, mut rsh_server) = tokio::io::duplex(4096);

        let handler = tokio::spawn(async move {
            let req: protocol::Request = wire::recv_json(&mut rsh_server).await.unwrap();
            assert_eq!(req.req_type, "connect");
            assert_eq!(req.command.as_deref(), Some("example.com:443"));

            let ack = protocol::Response {
                success: true,
                output: None,
                error: None,
                size: None,
                binary: None,
                gzip: None,
            };
            wire::send_json(&mut rsh_server, &ack).await.unwrap();
            wire::send_message(&mut rsh_server, &[]).await.unwrap();
        });

        let socks_handler = tokio::spawn(async move {
            handle_socks5_client(&mut server_end, &mut rsh_client).await.unwrap();
        });

        // Greeting
        client_end.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client_end.read_exact(&mut resp).await.unwrap();

        // CONNECT to domain "example.com:443"
        // atyp=0x03 (domain), len=11, "example.com", port=443 (0x01BB)
        let domain = b"example.com";
        let mut req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
        req.extend_from_slice(domain);
        req.extend_from_slice(&443u16.to_be_bytes());
        client_end.write_all(&req).await.unwrap();

        // Read reply
        let mut reply = [0u8; 10];
        client_end.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00); // success

        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            handler.await.unwrap();
            socks_handler.await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn socks5_handshake_ipv6() {
        let (mut client_end, mut server_end) = tokio::io::duplex(4096);
        let (mut rsh_client, mut rsh_server) = tokio::io::duplex(4096);

        let handler = tokio::spawn(async move {
            let req: protocol::Request = wire::recv_json(&mut rsh_server).await.unwrap();
            assert_eq!(req.req_type, "connect");
            // IPv6 ::1 port 443 — formatted as hex groups
            assert_eq!(req.command.as_deref(), Some("0:0:0:0:0:0:0:1:443"));

            let ack = protocol::Response {
                success: true,
                output: None,
                error: None,
                size: None,
                binary: None,
                gzip: None,
            };
            wire::send_json(&mut rsh_server, &ack).await.unwrap();
            wire::send_message(&mut rsh_server, &[]).await.unwrap();
        });

        let socks_handler = tokio::spawn(async move {
            handle_socks5_client(&mut server_end, &mut rsh_client).await.unwrap();
        });

        // Greeting
        client_end.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client_end.read_exact(&mut resp).await.unwrap();

        // CONNECT to IPv6 ::1 port 443
        // atyp=0x04, 16 bytes IPv6 addr, 2 bytes port
        let mut req = vec![0x05, 0x01, 0x00, 0x04];
        // ::1 = 15 zero bytes + 0x01
        req.extend_from_slice(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]);
        req.extend_from_slice(&443u16.to_be_bytes());
        client_end.write_all(&req).await.unwrap();

        // Read reply
        let mut reply = [0u8; 10];
        client_end.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00); // success

        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            handler.await.unwrap();
            socks_handler.await.unwrap();
        })
        .await;
    }

    /// IPv6 with a non-loopback address (fd00::cafe:1) to verify full
    /// 16-byte address parsing and formatting for real IPv6 addresses.
    #[tokio::test]
    async fn socks5_handshake_ipv6_non_loopback() {
        let (mut client_end, mut server_end) = tokio::io::duplex(4096);
        let (mut rsh_client, mut rsh_server) = tokio::io::duplex(4096);

        let handler = tokio::spawn(async move {
            let req: protocol::Request = wire::recv_json(&mut rsh_server).await.unwrap();
            assert_eq!(req.req_type, "connect");
            // fd00::cafe:1 = fd00:0:0:0:0:0:cafe:1
            assert_eq!(req.command.as_deref(), Some("fd00:0:0:0:0:0:cafe:1:8080"));

            let ack = protocol::Response {
                success: true,
                output: None,
                error: None,
                size: None,
                binary: None,
                gzip: None,
            };
            wire::send_json(&mut rsh_server, &ack).await.unwrap();
            wire::send_message(&mut rsh_server, &[]).await.unwrap();
        });

        let socks_handler = tokio::spawn(async move {
            handle_socks5_client(&mut server_end, &mut rsh_client).await.unwrap();
        });

        // Greeting
        client_end.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client_end.read_exact(&mut resp).await.unwrap();

        // CONNECT to fd00::cafe:1 port 8080
        // atyp=0x04, 16 bytes IPv6, 2 bytes port
        let mut req = vec![0x05, 0x01, 0x00, 0x04];
        // fd00::cafe:1 = fd00 0000 0000 0000 0000 0000 cafe 0001
        req.extend_from_slice(&[0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xca, 0xfe, 0, 1]);
        req.extend_from_slice(&8080u16.to_be_bytes());
        client_end.write_all(&req).await.unwrap();

        // Read reply
        let mut reply = [0u8; 10];
        client_end.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00); // success

        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            handler.await.unwrap();
            socks_handler.await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn socks5_server_rejects() {
        let (mut client_end, mut server_end) = tokio::io::duplex(4096);
        let (mut rsh_client, mut rsh_server) = tokio::io::duplex(4096);

        let handler = tokio::spawn(async move {
            let _: protocol::Request = wire::recv_json(&mut rsh_server).await.unwrap();
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

        let socks_handler = tokio::spawn(async move {
            let result = handle_socks5_client(&mut server_end, &mut rsh_client).await;
            assert!(result.is_err());
        });

        // Greeting
        client_end.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client_end.read_exact(&mut resp).await.unwrap();

        // CONNECT to 10.0.0.1:22
        client_end
            .write_all(&[0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0x00, 0x16])
            .await
            .unwrap();

        // Read reply — should be NOT_ALLOWED (0x02)
        let mut reply = [0u8; 10];
        client_end.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], SOCKS5_REP_NOT_ALLOWED);

        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            handler.await.unwrap();
            socks_handler.await.unwrap();
        })
        .await;
    }
}
