//! LAN peer discovery via UDP broadcast.
//!
//! Server: listens on a UDP port for PeerDiscovery requests, responds with its identity.
//! Client: broadcasts a PeerDiscovery request and collects responses.
//!
//! Protocol: PeerDiscovery protobuf message (field 22 in RendezvousMessage).
//! cmd="ping" → request, cmd="pong" → response.

use std::net::SocketAddr;
use std::time::Duration;

use prost::Message;
use tokio::net::UdpSocket;

use crate::proto;

/// Default discovery port (same as RustDesk LAN discovery).
pub const DISCOVERY_PORT: u16 = 21116;

/// A discovered peer on the LAN.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub id: String,
    pub hostname: String,
    pub platform: String,
    pub addr: SocketAddr,
    pub service_port: u16,
}

/// Send a LAN discovery broadcast and collect responses.
///
/// Broadcasts a PeerDiscovery "ping" on the given port, waits `timeout` for responses.
/// Returns all peers that responded.
pub async fn discover_lan(
    port: u16,
    timeout: Duration,
    local_id: &str,
) -> Vec<DiscoveredPeer> {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("discovery: bind failed: {}", e);
            return Vec::new();
        }
    };
    if let Err(e) = sock.set_broadcast(true) {
        tracing::warn!("discovery: set_broadcast failed: {}", e);
        return Vec::new();
    }

    let msg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::PeerDiscovery(
            proto::PeerDiscovery {
                cmd: "ping".to_string(),
                mac: String::new(),
                id: local_id.to_string(),
                username: String::new(),
                hostname: gethostname(),
                platform: std::env::consts::OS.to_string(),
                misc: String::new(),
            },
        )),
    };
    let bytes = msg.encode_to_vec();

    let broadcast_addr: SocketAddr = ([255, 255, 255, 255], port).into();
    if let Err(e) = sock.send_to(&bytes, broadcast_addr).await {
        tracing::warn!("discovery: broadcast send failed: {}", e);
        return Vec::new();
    }

    let mut peers = Vec::new();
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                if let Ok(resp) = proto::RendezvousMessage::decode(&buf[..n]) {
                    if let Some(proto::rendezvous_message::Union::PeerDiscovery(pd)) = resp.union {
                        if pd.cmd == "pong" && pd.id != local_id {
                            let service_port = pd.misc.parse::<u16>().unwrap_or(0);
                            peers.push(DiscoveredPeer {
                                id: pd.id,
                                hostname: pd.hostname,
                                platform: pd.platform,
                                addr: src,
                                service_port,
                            });
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::debug!("discovery: recv error: {}", e);
                break;
            }
            Err(_) => break, // timeout
        }
    }

    peers
}

/// Handle an incoming PeerDiscovery message (server side).
///
/// If cmd="ping", respond with cmd="pong" containing our identity.
/// Returns the response message to send back, or None if not a ping.
pub fn handle_discovery(
    msg: &proto::PeerDiscovery,
    local_id: &str,
    hostname: &str,
    platform: &str,
    service_port: u16,
) -> Option<proto::RendezvousMessage> {
    if msg.cmd != "ping" {
        return None;
    }
    // Don't respond to our own broadcast
    if msg.id == local_id {
        return None;
    }

    Some(proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::PeerDiscovery(
            proto::PeerDiscovery {
                cmd: "pong".to_string(),
                mac: String::new(),
                id: local_id.to_string(),
                username: String::new(),
                hostname: hostname.to_string(),
                platform: platform.to_string(),
                misc: service_port.to_string(),
            },
        )),
    })
}

/// Start a discovery listener that responds to LAN broadcasts.
///
/// Runs until cancelled. Binds to DISCOVERY_PORT on 0.0.0.0.
pub async fn run_discovery_responder(
    cancel: tokio_util::sync::CancellationToken,
    local_id: String,
    hostname: String,
    platform: String,
    service_port: u16,
) {
    let sock = match UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("discovery responder: bind {}:{} failed: {} (non-fatal)", "0.0.0.0", DISCOVERY_PORT, e);
            return;
        }
    };
    if let Err(e) = sock.set_broadcast(true) {
        tracing::debug!("discovery responder: set_broadcast failed: {}", e);
        return;
    }

    tracing::info!("LAN discovery responder on port {}", DISCOVERY_PORT);
    let mut buf = vec![0u8; 4096];

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            result = sock.recv_from(&mut buf) => {
                if let Ok((n, src)) = result {
                    if let Ok(msg) = proto::RendezvousMessage::decode(&buf[..n]) {
                        if let Some(proto::rendezvous_message::Union::PeerDiscovery(pd)) = msg.union {
                            if let Some(resp) = handle_discovery(&pd, &local_id, &hostname, &platform, service_port) {
                                let _ = sock.send_to(&resp.encode_to_vec(), src).await;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn gethostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_discovery_responds_to_ping() {
        let ping = proto::PeerDiscovery {
            cmd: "ping".to_string(),
            id: "remote-123".to_string(),
            hostname: "remote-host".to_string(),
            platform: "windows".to_string(),
            ..Default::default()
        };
        let resp = handle_discovery(&ping, "local-456", "local-host", "linux", 8822);
        assert!(resp.is_some());
        if let Some(proto::rendezvous_message::Union::PeerDiscovery(pd)) = resp.unwrap().union {
            assert_eq!(pd.cmd, "pong");
            assert_eq!(pd.id, "local-456");
            assert_eq!(pd.hostname, "local-host");
            assert_eq!(pd.misc, "8822");
        }
    }

    #[test]
    fn handle_discovery_ignores_own_ping() {
        let ping = proto::PeerDiscovery {
            cmd: "ping".to_string(),
            id: "same-id".to_string(),
            ..Default::default()
        };
        assert!(handle_discovery(&ping, "same-id", "host", "linux", 8822).is_none());
    }

    #[test]
    fn handle_discovery_ignores_pong() {
        let pong = proto::PeerDiscovery {
            cmd: "pong".to_string(),
            id: "remote-123".to_string(),
            ..Default::default()
        };
        assert!(handle_discovery(&pong, "local-456", "host", "linux", 8822).is_none());
    }

    #[test]
    fn handle_discovery_service_port_in_misc() {
        let ping = proto::PeerDiscovery {
            cmd: "ping".to_string(),
            id: "r".to_string(),
            ..Default::default()
        };
        let resp = handle_discovery(&ping, "l", "h", "linux", 9822).unwrap();
        if let Some(proto::rendezvous_message::Union::PeerDiscovery(pd)) = resp.union {
            assert_eq!(pd.misc, "9822");
        }
    }
}
