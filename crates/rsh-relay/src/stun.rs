//! Minimal STUN client for NAT type detection.
//!
//! Implements RFC 5389 Binding Request/Response to discover:
//! - External (mapped) IP address and port
//! - NAT type: open, cone, or symmetric
//!
//! No external dependencies — raw STUN packets over UDP.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::UdpSocket;

/// STUN magic cookie (RFC 5389).
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// STUN message type: Binding Request.
const BINDING_REQUEST: u16 = 0x0001;

/// STUN message type: Binding Response (success).
const BINDING_RESPONSE: u16 = 0x0101;

/// STUN attribute: MAPPED-ADDRESS.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// STUN attribute: XOR-MAPPED-ADDRESS.
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Well-known public STUN servers.
pub const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
];

/// NAT type classification.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NatType {
    /// No NAT — external IP matches local IP
    Open,
    /// Same external address from different STUN servers (full-cone, restricted-cone, or port-restricted)
    Cone,
    /// Different external address from different STUN servers
    Symmetric,
    /// Could not determine (only one server responded)
    Unknown,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::Open => write!(f, "open"),
            NatType::Cone => write!(f, "cone"),
            NatType::Symmetric => write!(f, "symmetric"),
            NatType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Result of NAT detection.
#[derive(Debug, Clone)]
pub struct NatInfo {
    pub nat_type: NatType,
    pub external_addr: Option<SocketAddr>,
}

/// Detect NAT type by querying two STUN servers from the same socket.
///
/// If both return the same mapped address → cone NAT (or open).
/// If they return different mapped addresses → symmetric NAT.
pub async fn detect_nat_type(timeout: Duration) -> NatInfo {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return NatInfo { nat_type: NatType::Unknown, external_addr: None },
    };

    let mut results = Vec::new();
    for server in STUN_SERVERS {
        match stun_binding(&sock, server, timeout).await {
            Ok(addr) => results.push(addr),
            Err(e) => tracing::debug!("STUN {} failed: {}", server, e),
        }
        if results.len() >= 2 { break; }
    }

    match results.len() {
        0 => NatInfo { nat_type: NatType::Unknown, external_addr: None },
        1 => NatInfo { nat_type: NatType::Unknown, external_addr: Some(results[0]) },
        _ => {
            let addr1 = results[0];
            let addr2 = results[1];
            let nat_type = if addr1.ip() == addr2.ip() && addr1.port() == addr2.port() {
                // Check if external matches local
                if sock.local_addr().map(|l| l.ip() == addr1.ip()).unwrap_or(false) {
                    NatType::Open
                } else {
                    NatType::Cone
                }
            } else {
                NatType::Symmetric
            };
            NatInfo { nat_type, external_addr: Some(addr1) }
        }
    }
}

/// Send a STUN Binding Request and parse the mapped address from the response.
async fn stun_binding(sock: &UdpSocket, server: &str, timeout: Duration) -> Result<SocketAddr> {
    // Build binding request (20 bytes)
    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    req[2..4].copy_from_slice(&0u16.to_be_bytes()); // length = 0
    req[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    // Transaction ID: 12 random bytes
    use rand::Rng;
    rand::thread_rng().fill(&mut req[8..20]);

    let txn_id = req[8..20].to_vec();

    sock.send_to(&req, server).await.context("send STUN request")?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .context("STUN timeout")?
        .context("recv STUN response")?;

    if n < 20 {
        bail!("STUN response too short: {} bytes", n);
    }

    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_RESPONSE {
        bail!("unexpected STUN message type: 0x{:04x}", msg_type);
    }

    // Verify transaction ID
    if buf[8..20] != txn_id[..] {
        bail!("STUN transaction ID mismatch");
    }

    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if 20 + msg_len > n {
        bail!("STUN message length exceeds packet");
    }

    // Parse attributes
    let mut offset = 20;
    while offset + 4 <= 20 + msg_len {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > 20 + msg_len {
            break;
        }

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                return parse_xor_mapped_address(&buf[offset..offset + attr_len]);
            }
            ATTR_MAPPED_ADDRESS => {
                return parse_mapped_address(&buf[offset..offset + attr_len]);
            }
            _ => {}
        }

        // Attributes are padded to 4-byte boundary
        offset += (attr_len + 3) & !3;
    }

    bail!("no mapped address in STUN response")
}

fn parse_mapped_address(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 8 {
        bail!("MAPPED-ADDRESS too short");
    }
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);
    match family {
        0x01 => {
            // IPv4
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Ok(SocketAddr::new(ip.into(), port))
        }
        _ => bail!("unsupported address family: {}", family),
    }
}

fn parse_xor_mapped_address(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 8 {
        bail!("XOR-MAPPED-ADDRESS too short");
    }
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    match family {
        0x01 => {
            // IPv4: XOR with magic cookie
            let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
            let ip = std::net::Ipv4Addr::new(
                data[4] ^ cookie_bytes[0],
                data[5] ^ cookie_bytes[1],
                data[6] ^ cookie_bytes[2],
                data[7] ^ cookie_bytes[3],
            );
            Ok(SocketAddr::new(ip.into(), port))
        }
        _ => bail!("unsupported address family: {}", family),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_type_display() {
        assert_eq!(NatType::Open.to_string(), "open");
        assert_eq!(NatType::Cone.to_string(), "cone");
        assert_eq!(NatType::Symmetric.to_string(), "symmetric");
        assert_eq!(NatType::Unknown.to_string(), "unknown");
    }

    #[test]
    fn parse_xor_mapped_address_ipv4() {
        // XOR-MAPPED-ADDRESS for 192.168.1.100:8822
        // XOR with magic cookie 0x2112A442
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let port: u16 = 8822 ^ (MAGIC_COOKIE >> 16) as u16;
        let port_bytes = port.to_be_bytes();
        let ip_bytes = [
            192 ^ cookie[0],
            168 ^ cookie[1],
            1 ^ cookie[2],
            100 ^ cookie[3],
        ];
        let data = [0x00, 0x01, port_bytes[0], port_bytes[1], ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]];
        let addr = parse_xor_mapped_address(&data).unwrap();
        assert_eq!(addr.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(addr.port(), 8822);
    }

    #[test]
    fn parse_mapped_address_ipv4() {
        let data = [0x00, 0x01, 0x22, 0x76, 10, 0, 0, 1]; // port=8822, ip=10.0.0.1
        let addr = parse_mapped_address(&data).unwrap();
        assert_eq!(addr.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(addr.port(), 0x2276); // 8822
    }

    #[test]
    fn stun_binding_request_format() {
        let mut req = [0u8; 20];
        req[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
        req[2..4].copy_from_slice(&0u16.to_be_bytes());
        req[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());

        assert_eq!(req[0], 0x00);
        assert_eq!(req[1], 0x01); // Binding Request
        assert_eq!(req[4], 0x21);
        assert_eq!(req[5], 0x12);
        assert_eq!(req[6], 0xA4);
        assert_eq!(req[7], 0x42); // Magic Cookie
    }
}
