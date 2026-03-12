//! TCP tunnel — bidirectional relay over length-prefixed frames.
//! Implements the "connect" request type: client ↔ rsh ↔ target.

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

use rsh_core::wire;

/// Check if a tunnel target is blocked (SSRF protection).
/// Blocks: loopback, unspecified, link-local, cloud metadata IPs, localhost names.
fn is_blocked_target(target: &str) -> bool {
    // Split host:port — handle both "host:port" and "[ipv6]:port"
    let host = if target.starts_with('[') {
        // IPv6 bracket notation
        target.split(']').next().unwrap_or("").trim_start_matches('[')
    } else {
        target.split(':').next().unwrap_or("")
    };

    // Block by IP address
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_unspecified()
                    || v4.is_link_local()
                    // Cloud metadata: AWS/GCP/Azure 169.254.169.254
                    || v4 == std::net::Ipv4Addr::new(169, 254, 169, 254)
                    // Azure Wire Server
                    || v4 == std::net::Ipv4Addr::new(168, 63, 129, 16)
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    // IPv4-mapped loopback (::ffff:127.0.0.1)
                    || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
                    // IPv4-mapped link-local
                    || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_link_local())
                    // IPv4-mapped cloud metadata
                    || v6.to_ipv4_mapped().is_some_and(|v4| {
                        v4 == std::net::Ipv4Addr::new(169, 254, 169, 254)
                    })
            }
        };
    }

    // Block "localhost" and metadata hostnames by name
    let host_lower = host.to_ascii_lowercase();
    host_lower == "localhost"
        || host_lower == "metadata.google.internal"
        || host_lower == "metadata.google"
        || host_lower.ends_with(".internal")
            && host_lower.contains("metadata")
}

/// Check if a tunnel target is allowed by the server's PermitOpen-style rules.
/// Empty list = all allowed. Non-empty = target must match a pattern.
/// Patterns: "host:port" (exact) or "host:*" (any port on that host).
pub fn is_tunnel_allowed(target: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return true; // no restrictions
    }
    for pattern in allowed {
        if pattern == target {
            return true; // exact match
        }
        // Wildcard port: "host:*" matches "host:ANYTHING"
        if let Some(host_prefix) = pattern.strip_suffix(":*") {
            if let Some(target_host) = target.rsplit_once(':').map(|(h, _)| h) {
                if target_host == host_prefix {
                    return true;
                }
            }
        }
    }
    false
}

/// Relay traffic between the rsh client stream and a target TCP connection.
/// Both directions use length-prefixed framing. Zero-length message = EOF.
pub async fn handle_connect<S>(stream: &mut S, target: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    if is_blocked_target(target) {
        anyhow::bail!("tunnel target blocked (loopback/unspecified): {}", target);
    }

    info!("tunnel connect to {}", target);

    let target_stream = TcpStream::connect(target)
        .await
        .context(format!("connect to {}", target))?;
    target_stream.set_nodelay(true).ok();

    let (target_read, target_write) = tokio::io::split(target_stream);

    relay_bidirectional(stream, target_read, target_write).await
}

/// Bidirectional relay: client ↔ target.
/// Client side: length-prefixed frames (wire protocol).
/// Target side: raw TCP bytes.
async fn relay_bidirectional<S, R, W>(
    rsh_stream: &mut S,
    mut target_read: R,
    mut target_write: W,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let mut target_buf = vec![0u8; 32768];

    loop {
        tokio::select! {
            // Client → Target: read length-prefixed frame, write raw to target
            result = wire::recv_message(rsh_stream) => {
                match result {
                    Ok(data) => {
                        if data.is_empty() {
                            // EOF sentinel from client
                            debug!("tunnel: client sent EOF");
                            target_write.shutdown().await.ok();
                            break;
                        }
                        target_write.write_all(&data).await
                            .context("write to target")?;
                    }
                    Err(_) => {
                        debug!("tunnel: client disconnected");
                        break;
                    }
                }
            }

            // Target → Client: read raw bytes, write length-prefixed frame
            result = target_read.read(&mut target_buf) => {
                match result {
                    Ok(0) => {
                        // Target closed — send EOF sentinel to client
                        debug!("tunnel: target closed");
                        wire::send_message(rsh_stream, &[]).await.ok();
                        break;
                    }
                    Ok(n) => {
                        wire::send_message(rsh_stream, &target_buf[..n]).await
                            .context("send to client")?;
                    }
                    Err(e) => {
                        debug!("tunnel: target read error: {}", e);
                        wire::send_message(rsh_stream, &[]).await.ok();
                        break;
                    }
                }
            }
        }
    }

    info!("tunnel closed");
    Ok(())
}

/// Connect to target WITHOUT the block check (for testing with loopback).
#[cfg(test)]
async fn connect_unchecked<S>(stream: &mut S, target: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let target_stream = TcpStream::connect(target)
        .await
        .context(format!("connect to {}", target))?;
    target_stream.set_nodelay(true).ok();
    let (target_read, target_write) = tokio::io::split(target_stream);
    relay_bidirectional(stream, target_read, target_write).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    // --- is_blocked_target unit tests ---

    #[test]
    fn blocks_ipv4_loopback() {
        assert!(is_blocked_target("127.0.0.1:8080"));
        assert!(is_blocked_target("127.0.0.2:80"));
    }

    #[test]
    fn blocks_ipv4_unspecified() {
        assert!(is_blocked_target("0.0.0.0:80"));
    }

    #[test]
    fn blocks_ipv6_loopback() {
        assert!(is_blocked_target("[::1]:80"));
    }

    #[test]
    fn blocks_localhost_name() {
        assert!(is_blocked_target("localhost:80"));
        assert!(is_blocked_target("LOCALHOST:443"));
    }

    #[test]
    fn blocks_ipv4_link_local() {
        assert!(is_blocked_target("169.254.1.1:80"));
        assert!(is_blocked_target("169.254.255.255:80"));
    }

    #[test]
    fn blocks_cloud_metadata_ip() {
        assert!(is_blocked_target("169.254.169.254:80"));
    }

    #[test]
    fn blocks_azure_wire_server() {
        assert!(is_blocked_target("168.63.129.16:80"));
    }

    #[test]
    fn blocks_ipv6_mapped_loopback() {
        assert!(is_blocked_target("[::ffff:127.0.0.1]:80"));
    }

    #[test]
    fn blocks_metadata_hostnames() {
        assert!(is_blocked_target("metadata.google.internal:80"));
        assert!(is_blocked_target("metadata.google:80"));
    }

    #[test]
    fn allows_normal_targets() {
        assert!(!is_blocked_target("192.168.1.1:80"));
        assert!(!is_blocked_target("10.0.0.1:22"));
        assert!(!is_blocked_target("example.com:443"));
    }

    #[test]
    fn handle_connect_rejects_loopback() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mut _client, mut server) = tokio::io::duplex(4096);
            let result = handle_connect(&mut server, "127.0.0.1:80").await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("blocked"));
        });
    }

    // --- Integration tests (use connect_unchecked to allow loopback in tests) ---

    #[tokio::test]
    async fn tunnel_echo_roundtrip() {
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

        let (mut client, mut server) = tokio::io::duplex(4096);
        let target = echo_addr.to_string();
        let handle = tokio::spawn(async move { connect_unchecked(&mut server, &target).await });

        let test_data = b"hello tunnel";
        wire::send_message(&mut client, test_data).await.unwrap();

        let response = wire::recv_message(&mut client).await.unwrap();
        assert_eq!(response, test_data);

        wire::send_message(&mut client, &[]).await.unwrap();
        handle.await.unwrap().unwrap();
    }

    // --- is_tunnel_allowed unit tests ---

    #[test]
    fn tunnel_allowed_empty_allows_all() {
        assert!(is_tunnel_allowed("example.com:443", &[]));
    }

    #[test]
    fn tunnel_allowed_exact_match() {
        let rules = vec!["db.internal:5432".to_string()];
        assert!(is_tunnel_allowed("db.internal:5432", &rules));
        assert!(!is_tunnel_allowed("db.internal:3306", &rules));
    }

    #[test]
    fn tunnel_allowed_wildcard_port() {
        let rules = vec!["db.internal:*".to_string()];
        assert!(is_tunnel_allowed("db.internal:5432", &rules));
        assert!(is_tunnel_allowed("db.internal:3306", &rules));
        assert!(!is_tunnel_allowed("other.host:5432", &rules));
    }

    #[test]
    fn tunnel_allowed_multiple_rules() {
        let rules = vec![
            "web.internal:80".to_string(),
            "web.internal:443".to_string(),
            "db.internal:*".to_string(),
        ];
        assert!(is_tunnel_allowed("web.internal:80", &rules));
        assert!(is_tunnel_allowed("web.internal:443", &rules));
        assert!(is_tunnel_allowed("db.internal:5432", &rules));
        assert!(!is_tunnel_allowed("web.internal:8080", &rules));
        assert!(!is_tunnel_allowed("evil.com:80", &rules));
    }

    #[test]
    fn tunnel_disallowed_when_restricted() {
        let rules = vec!["allowed.host:22".to_string()];
        assert!(!is_tunnel_allowed("blocked.host:22", &rules));
    }

    #[tokio::test]
    async fn tunnel_target_closes_first() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            drop(conn);
        });

        let (mut client, mut server) = tokio::io::duplex(4096);
        let target = addr.to_string();
        let handle = tokio::spawn(async move { connect_unchecked(&mut server, &target).await });

        let msg = wire::recv_message(&mut client).await.unwrap();
        assert!(msg.is_empty(), "expected EOF sentinel");
        handle.await.unwrap().unwrap();
    }
}
