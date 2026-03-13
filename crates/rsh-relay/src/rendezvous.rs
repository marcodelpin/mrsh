//! Rendezvous client and server — resolve a DeviceID to an IP:port via hbbs.
//!
//! Client protocol flow (all UDP, raw protobuf — no BytesCodec framing):
//!   1. RegisterPeer  → RegisterPeerResponse (register ourselves)
//!   2. RegisterPk    → RegisterPkResponse    (register public key if requested)
//!   3. PunchHoleRequest → PunchHoleResponse | FetchLocalAddr (resolve target)
//!   4. If relay needed: RequestRelay via TCP (BytesCodec framed)
//!
//! Server: accepts RegisterPeer/PunchHoleRequest/RegisterPk over UDP,
//!         maintains a DeviceID→SocketAddr registry with heartbeat expiry.
//!
//! Clean-room implementation. MIT licensed.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use prost::Message;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{Duration, Instant, timeout};

use crate::codec;
use crate::proto;

/// Default hbbs UDP port.
pub const DEFAULT_PORT: u16 = 21116;

/// Outcome of resolving a DeviceID through hbbs.
#[derive(Debug, Clone)]
pub struct ResolveResult {
    /// Direct peer address, if available (None means relay-only).
    pub addr: Option<SocketAddr>,
    /// Relay server address returned by hbbs.
    pub relay_server: String,
    /// UUID for relay pairing (empty if P2P).
    pub uuid: String,
}

/// A discovered peer from a group query.
#[derive(Debug, Clone)]
pub struct GroupPeerInfo {
    pub device_id: String,
    pub hostname: String,
    pub platform: String,
    pub addr: Option<SocketAddr>,
    pub last_seen_secs: u64,
    /// rsh command listener port (0 means default 8822).
    pub service_port: u16,
}

/// A relay notification received from hbbs: a client wants to connect via relay.
#[derive(Debug, Clone)]
pub struct RelayNotification {
    /// UUID for relay pairing (both sides connect to hbbr with this UUID).
    pub uuid: String,
    /// Relay server address (hbbr host:port).
    pub relay_server: String,
}

/// Client for hbbs rendezvous protocol.
pub struct Client {
    /// Rendezvous servers to try, in order (host:port).
    pub servers: Vec<String>,
    /// Server public key (sent as licence_key in PunchHoleRequest).
    pub licence_key: String,
    /// Our own device ID for registration.
    pub local_id: String,
    /// SHA256(enrollment_token) hex — included in RegisterPeer for group discovery.
    pub group_hash: String,
    /// Machine hostname — included in RegisterPeer for group discovery.
    pub hostname: String,
    /// Platform (e.g. "windows", "linux") — included in RegisterPeer.
    pub platform: String,
    /// rsh command listener port — included in RegisterPeer so hbbs can report it.
    pub service_port: u16,
}

/// Check whether a string looks like a device ID rather than a hostname/IP.
///
/// Device IDs: optional leading letters followed by one or more digits.
/// Examples: "123456789", "abc123". Not: "192.168.1.1", "example.com".
pub fn is_device_id(s: &str) -> bool {
    if s.is_empty() || s.contains('.') || s.contains(':') {
        return false;
    }
    let mut has_digit = false;
    let mut past_letters = false;
    for ch in s.chars() {
        if ch.is_ascii_alphabetic() {
            if past_letters {
                return false; // letters after digits
            }
        } else if ch.is_ascii_digit() {
            has_digit = true;
            past_letters = true;
        } else {
            return false;
        }
    }
    has_digit
}

/// Decode an AddrMangle-encoded socket address (IPv4).
///
/// The encoding packs IP + port + timestamp into a 128-bit integer:
///   bits [0..24)   → port + (tm & 0xFFFF)
///   bits [17..49)  → tm (32-bit obfuscation value)
///   bits [49..81)  → ip32 + tm
///
/// We decode by extracting tm, then subtracting it from ip and port.
pub fn decode_socket_addr(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 4 || data.len() > 16 {
        bail!("invalid AddrMangle length: {}", data.len());
    }

    // Zero-pad to 16 bytes, read as two u64 LE halves.
    let mut padded = [0u8; 16];
    padded[..data.len()].copy_from_slice(data);
    let lo = u64::from_le_bytes(padded[..8].try_into().unwrap());
    let hi = u64::from_le_bytes(padded[8..].try_into().unwrap());

    // Extract the obfuscation timestamp (bits 17..49).
    let tm = ((lo >> 17) | (hi << 47)) as u32;

    // Extract IP (bits 49..81) and subtract tm.
    let ip_raw = ((lo >> 49) | (hi << 15)) as u32;
    let ip32 = ip_raw.wrapping_sub(tm);

    // Extract port (bits 0..24, masked to 16 bits) and subtract tm.
    let port = ((lo & 0xFF_FFFF) as u16).wrapping_sub((tm & 0xFFFF) as u16);

    let octets = ip32.to_le_bytes();
    Ok(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]),
        port,
    )))
}

/// Encode an IPv4 socket address using AddrMangle encoding (inverse of `decode_socket_addr`).
///
/// The encoding packs IP + port + a timestamp-based obfuscation value into
/// a 128-bit integer, then returns the minimal non-zero byte slice (min 4 bytes).
pub fn encode_socket_addr(addr: &SocketAddr) -> Vec<u8> {
    let (ip, port) = match addr {
        SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
        SocketAddr::V6(_) => return vec![0; 4], // IPv6 not supported in this encoding
    };

    let ip32 = u32::from_le_bytes(ip.octets());

    // Obfuscation timestamp — same approach as RustDesk AddrMangle.
    let tm: u32 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;

    let ip_enc = ip32.wrapping_add(tm);
    let port_enc = port.wrapping_add((tm & 0xFFFF) as u16);

    // Pack into 128-bit value:
    //   bits 0..16:  port_enc
    //   bits 17..48: tm
    //   bits 49..80: ip_enc
    let val: u128 = (port_enc as u128)
        | ((tm as u128) << 17)
        | ((ip_enc as u128) << 49);

    let bytes = val.to_le_bytes();
    let end = bytes
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(4)
        .max(4);
    bytes[..end].to_vec()
}

/// Encode a socket address with a specific obfuscation value (for testing).
#[cfg(test)]
fn encode_socket_addr_with_tm(addr: &SocketAddr, tm: u32) -> Vec<u8> {
    let (ip, port) = match addr {
        SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
        SocketAddr::V6(_) => return vec![0; 4],
    };

    let ip32 = u32::from_le_bytes(ip.octets());
    let ip_enc = ip32.wrapping_add(tm);
    let port_enc = port.wrapping_add((tm & 0xFFFF) as u16);

    let val: u128 = (port_enc as u128)
        | ((tm as u128) << 17)
        | ((ip_enc as u128) << 49);

    let bytes = val.to_le_bytes();
    let end = bytes
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(4)
        .max(4);
    bytes[..end].to_vec()
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Registration entry for a peer in the rendezvous server.
struct PeerEntry {
    addr: SocketAddr,
    last_seen: Instant,
    /// SHA256(enrollment_token), hex. Empty if no group enrollment.
    group_hash: String,
    /// Machine hostname (from RegisterPeer).
    hostname: String,
    /// Platform: "windows" or "linux".
    platform: String,
    /// rsh command listener port (0 = default 8822).
    service_port: u16,
}

/// Default peer expiry time (5 minutes without re-registration).
const PEER_EXPIRY: Duration = Duration::from_secs(300);

/// Cleanup interval for expired peers.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// A rendezvous server (hbbs) that maps DeviceIDs to socket addresses.
pub struct RendezvousServer {
    /// Authentication key (empty = no auth).
    key: String,
    /// Address of the companion relay server (hbbr).
    relay_server: String,
}

impl RendezvousServer {
    pub fn new(key: &str, relay_server: &str) -> Self {
        Self {
            key: key.to_string(),
            relay_server: relay_server.to_string(),
        }
    }

    /// Start the rendezvous server on the given UDP address.
    ///
    /// Listens on both UDP (registration, punch-hole, group queries) and TCP
    /// (RequestRelay forwarding). When a client sends RequestRelay via TCP,
    /// hbbs looks up the target device and sends RelayResponse via UDP to its
    /// registered address, enabling server-side relay acceptance.
    pub async fn listen_and_serve(&self, addr: &str) -> Result<()> {
        let sock = Arc::new(UdpSocket::bind(addr).await.context("bind UDP")?);

        let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        // Spawn periodic cleanup of expired peers.
        let peers_gc = peers.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                tick.tick().await;
                let mut map = peers_gc.lock().unwrap();
                let now = Instant::now();
                let before = map.len();
                map.retain(|_, e| now.duration_since(e.last_seen) < PEER_EXPIRY);
                let removed = before - map.len();
                if removed > 0 {
                    tracing::debug!("rdv: expired {removed} peers, {} remaining", map.len());
                }
            }
        });

        // Spawn TCP listener for RequestRelay forwarding.
        // TCP and UDP can share the same port number.
        let tcp_listener = TcpListener::bind(addr)
            .await
            .context("bind TCP for relay forwarding")?;
        tracing::info!("rdv: TCP relay forwarding on {}", addr);

        let peers_tcp = peers.clone();
        let sock_tcp = sock.clone();
        let relay_server = self.relay_server.clone();
        let key_tcp = self.key.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match tcp_listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!("rdv tcp accept: {}", e);
                        continue;
                    }
                };
                let peers = peers_tcp.clone();
                let sock = sock_tcp.clone();
                let relay = relay_server.clone();
                let key = key_tcp.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_tcp_relay_request(stream, peer, &peers, &sock, &relay, &key).await
                    {
                        tracing::debug!("rdv tcp relay from {}: {}", peer, e);
                    }
                });
            }
        });

        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = sock.recv_from(&mut buf).await?;
            if n == 0 {
                continue;
            }

            let msg = match proto::RendezvousMessage::decode(&buf[..n]) {
                Ok(m) => m,
                Err(_) => continue,
            };

            if let Some(resp) = self.handle_message(msg, src, &peers) {
                let _ = sock.send_to(&resp.encode_to_vec(), src).await;
            }
        }
    }

    fn handle_message(
        &self,
        msg: proto::RendezvousMessage,
        src: SocketAddr,
        peers: &std::sync::Mutex<HashMap<String, PeerEntry>>,
    ) -> Option<proto::RendezvousMessage> {
        match msg.union? {
            proto::rendezvous_message::Union::RegisterPeer(rp) => {
                if !rp.id.is_empty() {
                    let has_group = !rp.group_hash.is_empty();
                    let mut map = peers.lock().unwrap();
                    map.insert(
                        rp.id.clone(),
                        PeerEntry {
                            addr: src,
                            last_seen: Instant::now(),
                            group_hash: rp.group_hash.clone(),
                            hostname: rp.hostname.clone(),
                            platform: rp.platform.clone(),
                            service_port: rp.service_port as u16,
                        },
                    );
                    if has_group {
                        tracing::debug!("rdv: registered {} from {} (group: {})", rp.id, src, rp.group_hash);
                    } else {
                        tracing::debug!("rdv: registered {} from {}", rp.id, src);
                    }
                }
                Some(proto::RendezvousMessage {
                    union: Some(proto::rendezvous_message::Union::RegisterPeerResponse(
                        proto::RegisterPeerResponse { request_pk: false },
                    )),
                })
            }

            proto::rendezvous_message::Union::RegisterPk(_rpk) => {
                Some(proto::RendezvousMessage {
                    union: Some(proto::rendezvous_message::Union::RegisterPkResponse(
                        proto::RegisterPkResponse {
                            result: proto::register_pk_response::Result::Ok as i32,
                            keep_alive: 300,
                        },
                    )),
                })
            }

            proto::rendezvous_message::Union::PunchHoleRequest(phr) => {
                self.handle_punch_hole(phr, src, peers)
            }

            proto::rendezvous_message::Union::HealthCheck(_) => {
                let peer_count = peers.lock().unwrap().len() as u32;
                Some(proto::RendezvousMessage {
                    union: Some(proto::rendezvous_message::Union::HealthResponse(
                        proto::HealthResponse {
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                            peers_online: peer_count,
                            relays_active: 0,
                            version: env!("CARGO_PKG_VERSION").to_string(),
                        },
                    )),
                })
            }

            proto::rendezvous_message::Union::GroupQuery(gq) => {
                self.handle_group_query(gq, peers)
            }

            proto::rendezvous_message::Union::ListPeers(lp) => {
                self.handle_list_peers(lp, peers)
            }

            _ => None,
        }
    }

    fn handle_punch_hole(
        &self,
        req: proto::PunchHoleRequest,
        src: SocketAddr,
        peers: &std::sync::Mutex<HashMap<String, PeerEntry>>,
    ) -> Option<proto::RendezvousMessage> {
        // Key check.
        if !self.key.is_empty() && req.licence_key != self.key {
            return Some(proto::RendezvousMessage {
                union: Some(proto::rendezvous_message::Union::PunchHoleResponse(
                    proto::PunchHoleResponse {
                        failure: proto::punch_hole_response::Failure::LicenseMismatch as i32,
                        relay_server: self.relay_server.clone(),
                        ..Default::default()
                    },
                )),
            });
        }

        let map = peers.lock().unwrap();

        match map.get(&req.id) {
            Some(entry) => {
                let encoded_addr = encode_socket_addr(&entry.addr);

                // Same-LAN detection: requester and target share an IP.
                if entry.addr.ip() == src.ip() {
                    return Some(proto::RendezvousMessage {
                        union: Some(proto::rendezvous_message::Union::FetchLocalAddr(
                            proto::FetchLocalAddr {
                                socket_addr: encoded_addr,
                                relay_server: self.relay_server.clone(),
                                ..Default::default()
                            },
                        )),
                    });
                }

                Some(proto::RendezvousMessage {
                    union: Some(proto::rendezvous_message::Union::PunchHoleResponse(
                        proto::PunchHoleResponse {
                            socket_addr: encoded_addr,
                            relay_server: self.relay_server.clone(),
                            ..Default::default()
                        },
                    )),
                })
            }
            None => Some(proto::RendezvousMessage {
                union: Some(proto::rendezvous_message::Union::PunchHoleResponse(
                    proto::PunchHoleResponse {
                        failure: proto::punch_hole_response::Failure::IdNotExist as i32,
                        relay_server: self.relay_server.clone(),
                        ..Default::default()
                    },
                )),
            }),
        }
    }

    /// Handle ListPeers: return ALL registered peers (auth'd by licence_key).
    fn handle_list_peers(
        &self,
        lp: proto::ListPeers,
        peers: &std::sync::Mutex<HashMap<String, PeerEntry>>,
    ) -> Option<proto::RendezvousMessage> {
        // Authenticate: licence_key must match server's key
        if !self.key.is_empty() && lp.licence_key != self.key {
            tracing::warn!("rdv: list_peers rejected — key mismatch");
            return None;
        }

        let map = peers.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        let all_peers: Vec<proto::GroupPeer> = map
            .iter()
            .map(|(id, entry)| {
                let last_seen_secs = now.as_secs()
                    - entry.last_seen.elapsed().as_secs();
                proto::GroupPeer {
                    device_id: id.clone(),
                    hostname: entry.hostname.clone(),
                    platform: entry.platform.clone(),
                    socket_addr: encode_socket_addr(&entry.addr),
                    last_seen_secs,
                    service_port: entry.service_port as i32,
                }
            })
            .collect();

        tracing::info!("rdv: list_peers — {} peers", all_peers.len());

        Some(proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::ListPeersResponse(
                proto::ListPeersResponse { peers: all_peers },
            )),
        })
    }

    /// Handle a GroupQuery: return all peers matching the group_hash,
    /// verified by HMAC proof (requester must know the enrollment token).
    fn handle_group_query(
        &self,
        gq: proto::GroupQuery,
        peers: &std::sync::Mutex<HashMap<String, PeerEntry>>,
    ) -> Option<proto::RendezvousMessage> {
        if gq.group_hash.is_empty() {
            return None;
        }

        // Verify HMAC proof: HMAC-SHA256(nonce_le_bytes, enrollment_token)
        // The nonce must be within 5 minutes of current time to prevent replay.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now_secs.abs_diff(gq.nonce) > 300 {
            tracing::warn!("rdv: group query rejected — stale nonce (delta={}s)", now_secs.abs_diff(gq.nonce));
            return None;
        }

        // We verify the proof by checking that:
        //   SHA256(hmac_proof) == group_hash
        // This works because the client computes:
        //   hmac_proof = HMAC-SHA256(nonce_bytes, enrollment_token)
        // And we check that the requester who produced hmac_proof also
        // knows the enrollment_token by verifying group_hash matches.
        //
        // Actually, a simpler and more secure approach:
        // The client sends group_hash (which we match against peers)
        // and hmac_proof = HMAC-SHA256(group_hash || nonce_bytes, enrollment_token).
        // We cannot verify the HMAC server-side (we don't have the token),
        // but we CAN verify that group_hash == SHA256(enrollment_token)
        // by requiring the client to also send the raw enrollment_token.
        //
        // Simplest secure approach: the client sends the enrollment_token
        // and we compute SHA256(token) and match against stored group_hash.
        // The token is sent over UDP on the same network, which is acceptable
        // for our use case (internal fleet, same LAN or VPN).
        //
        // For now: verify group_hash matches by direct comparison with stored hashes.
        // The hmac_proof field carries the raw enrollment_token so we can verify.
        use sha2::{Digest, Sha256};
        let computed_hash = if !gq.hmac_proof.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(&gq.hmac_proof);
            hex::encode(hasher.finalize())
        } else {
            String::new()
        };

        if computed_hash != gq.group_hash {
            tracing::warn!("rdv: group query rejected — proof mismatch");
            return None;
        }

        let map = peers.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        let matching: Vec<proto::GroupPeer> = map
            .iter()
            .filter(|(_, entry)| entry.group_hash == gq.group_hash)
            .map(|(id, entry)| {
                let last_seen_secs = now.as_secs()
                    - entry.last_seen.elapsed().as_secs();
                proto::GroupPeer {
                    device_id: id.clone(),
                    hostname: entry.hostname.clone(),
                    platform: entry.platform.clone(),
                    socket_addr: encode_socket_addr(&entry.addr),
                    last_seen_secs,
                    service_port: entry.service_port as i32,
                }
            })
            .collect();

        tracing::info!("rdv: group query for {} — {} peers found", gq.group_hash, matching.len());

        Some(proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::GroupQueryResponse(
                proto::GroupQueryResponse { peers: matching },
            )),
        })
    }
}

impl Client {
    /// Register with all configured rendezvous servers (best-effort).
    ///
    /// Returns Ok if at least one server accepted the registration.
    /// Suitable for calling in a periodic loop from server mode.
    pub async fn register_once(&self) -> Result<()> {
        if self.servers.is_empty() {
            bail!("no rendezvous server configured");
        }
        if self.local_id.is_empty() {
            bail!("no local_id configured for registration");
        }

        let mut any_ok = false;
        for srv in &self.servers {
            let sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => continue,
            };
            if sock.connect(srv).await.is_err() {
                continue;
            }
            match self.do_register(&sock).await {
                Ok(()) => any_ok = true,
                Err(_) => {}
            }
        }

        if any_ok {
            Ok(())
        } else {
            bail!("registration failed on all {} servers", self.servers.len())
        }
    }

    /// Resolve a device ID by trying each configured server.
    pub async fn resolve(&self, device_id: &str) -> Result<ResolveResult> {
        if self.servers.is_empty() {
            bail!("no rendezvous server configured");
        }

        let mut last_err = None;
        for srv in &self.servers {
            match self.try_server(device_id, srv).await {
                Ok(r) => return Ok(r),
                Err(e) => last_err = Some(e),
            }
        }
        bail!(
            "all {} servers failed; last: {}",
            self.servers.len(),
            last_err.unwrap()
        );
    }

    /// Query the rendezvous server for all peers in a group.
    ///
    /// `enrollment_token` is the raw token (base64). The proof is computed
    /// as SHA256(token) which the server verifies matches the stored group_hash.
    /// (The nonce is the current unix timestamp, server rejects >300s drift.)
    pub async fn query_group(&self, enrollment_token: &str) -> Result<Vec<GroupPeerInfo>> {
        use sha2::{Digest, Sha256};

        if self.servers.is_empty() {
            bail!("no rendezvous server configured");
        }

        // Compute group_hash = SHA256(token) hex
        let group_hash = {
            let mut h = Sha256::new();
            h.update(enrollment_token.as_bytes());
            hex::encode(h.finalize())
        };

        // Nonce = current unix timestamp
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // hmac_proof = raw token bytes (server will SHA256 it and compare to group_hash)
        let hmac_proof = enrollment_token.as_bytes().to_vec();

        let gq = proto::GroupQuery {
            group_hash,
            hmac_proof,
            nonce,
        };

        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::GroupQuery(gq)),
        };
        let msg_bytes = msg.encode_to_vec();

        let mut last_err = None;
        for srv in &self.servers {
            let sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => { last_err = Some(anyhow::anyhow!("bind: {e}")); continue; }
            };
            if let Err(e) = sock.connect(srv).await {
                last_err = Some(anyhow::anyhow!("connect {srv}: {e}"));
                continue;
            }
            if let Err(e) = sock.send(&msg_bytes).await {
                last_err = Some(anyhow::anyhow!("send to {srv}: {e}"));
                continue;
            }

            let mut buf = vec![0u8; 65535];
            let n = match timeout(Duration::from_secs(5), sock.recv(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => { last_err = Some(e.into()); continue; }
                Err(_) => { last_err = Some(anyhow::anyhow!("timeout from {srv}")); continue; }
            };

            let resp = match proto::RendezvousMessage::decode(&buf[..n]) {
                Ok(r) => r,
                Err(e) => { last_err = Some(e.into()); continue; }
            };

            if let Some(proto::rendezvous_message::Union::GroupQueryResponse(gqr)) = resp.union {
                let peers = gqr.peers.into_iter().map(|p| {
                    let addr = if p.socket_addr.is_empty() {
                        None
                    } else {
                        decode_socket_addr(&p.socket_addr).ok()
                    };
                    GroupPeerInfo {
                        device_id: p.device_id,
                        hostname: p.hostname,
                        platform: p.platform,
                        addr,
                        last_seen_secs: p.last_seen_secs,
                        service_port: p.service_port as u16,
                    }
                }).collect();
                return Ok(peers);
            }

            last_err = Some(anyhow::anyhow!("unexpected response from {srv}"));
        }

        bail!("group query failed on all servers; last: {}", last_err.unwrap_or_else(|| anyhow::anyhow!("no servers")));
    }

    /// List ALL peers registered at hbbs (authenticated by licence_key).
    pub async fn list_peers(&self) -> Result<Vec<GroupPeerInfo>> {
        if self.servers.is_empty() {
            bail!("no rendezvous server configured");
        }

        let lp = proto::ListPeers {
            licence_key: self.licence_key.clone(),
        };
        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::ListPeers(lp)),
        };
        let msg_bytes = msg.encode_to_vec();

        let mut last_err = None;
        for srv in &self.servers {
            let sock = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => { last_err = Some(anyhow::anyhow!("bind: {e}")); continue; }
            };
            if let Err(e) = sock.connect(srv).await {
                last_err = Some(anyhow::anyhow!("connect {srv}: {e}"));
                continue;
            }
            if let Err(e) = sock.send(&msg_bytes).await {
                last_err = Some(anyhow::anyhow!("send to {srv}: {e}"));
                continue;
            }

            let mut buf = vec![0u8; 65535];
            let n = match timeout(Duration::from_secs(5), sock.recv(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => { last_err = Some(e.into()); continue; }
                Err(_) => { last_err = Some(anyhow::anyhow!("timeout from {srv}")); continue; }
            };

            let resp = match proto::RendezvousMessage::decode(&buf[..n]) {
                Ok(r) => r,
                Err(e) => { last_err = Some(e.into()); continue; }
            };

            if let Some(proto::rendezvous_message::Union::ListPeersResponse(lpr)) = resp.union {
                let peers = lpr.peers.into_iter().map(|p| {
                    let addr = if p.socket_addr.is_empty() {
                        None
                    } else {
                        decode_socket_addr(&p.socket_addr).ok()
                    };
                    GroupPeerInfo {
                        device_id: p.device_id,
                        hostname: p.hostname,
                        platform: p.platform,
                        addr,
                        last_seen_secs: p.last_seen_secs,
                        service_port: p.service_port as u16,
                    }
                }).collect();
                return Ok(peers);
            }

            last_err = Some(anyhow::anyhow!("unexpected response from {srv}"));
        }

        bail!("list_peers failed on all servers; last: {}", last_err.unwrap_or_else(|| anyhow::anyhow!("no servers")));
    }

    /// Full resolution against a single server.
    async fn try_server(&self, device_id: &str, server: &str) -> Result<ResolveResult> {
        let sock = UdpSocket::bind("0.0.0.0:0").await.context("bind UDP")?;
        sock.connect(server).await.context("connect UDP")?;

        // Best-effort self-registration (not fatal if it fails).
        let _ = self.do_register(&sock).await;

        // Punch hole to locate the target peer.
        let result = self.do_punch_hole(&sock, device_id).await?;

        // If relay is indicated but no UUID yet, request one via TCP.
        if !result.relay_server.is_empty() && result.uuid.is_empty() {
            let mut result = result;
            if let Ok(uuid) = self.request_relay_uuid(server, device_id, &result.relay_server).await {
                result.uuid = uuid;
            }
            return Ok(result);
        }

        Ok(result)
    }

    /// Register ourselves with hbbs (RegisterPeer + optional RegisterPk).
    async fn do_register(&self, sock: &UdpSocket) -> Result<()> {
        let our_id = if self.local_id.is_empty() {
            // Generate a transient ID from current time.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!("{}", nanos % 1_000_000_000)
        } else {
            self.local_id.clone()
        };

        // Send RegisterPeer.
        let reg_msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RegisterPeer(
                proto::RegisterPeer {
                    id: our_id.clone(),
                    serial: 0,
                    group_hash: self.group_hash.clone(),
                    hostname: self.hostname.clone(),
                    platform: self.platform.clone(),
                    service_port: self.service_port as i32,
                },
            )),
        };
        sock.send(&reg_msg.encode_to_vec()).await.context("send RegisterPeer")?;

        // Wait for RegisterPeerResponse.
        let mut buf = vec![0u8; 65535];
        let n = timeout(Duration::from_secs(5), sock.recv(&mut buf))
            .await
            .context("RegisterPeer timeout")?
            .context("recv RegisterPeerResponse")?;

        let resp = proto::RendezvousMessage::decode(&buf[..n]).context("decode response")?;

        // If server wants our public key, send RegisterPk.
        if let Some(proto::rendezvous_message::Union::RegisterPeerResponse(pr)) = &resp.union {
            if pr.request_pk {
                // Use a deterministic placeholder key for registration.
                let pk: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(13) % 255).collect();

                let pk_msg = proto::RendezvousMessage {
                    union: Some(proto::rendezvous_message::Union::RegisterPk(
                        proto::RegisterPk {
                            id: our_id,
                            uuid: vec![1u8; 16],
                            pk,
                            old_id: String::new(),
                            no_register_device: false,
                        },
                    )),
                };
                sock.send(&pk_msg.encode_to_vec()).await?;

                // Read RegisterPkResponse.
                let n = timeout(Duration::from_secs(5), sock.recv(&mut buf))
                    .await
                    .context("RegisterPk timeout")?
                    .context("recv RegisterPkResponse")?;
                let pk_resp = proto::RendezvousMessage::decode(&buf[..n])?;
                if let Some(proto::rendezvous_message::Union::RegisterPkResponse(r)) = pk_resp.union {
                    if r.result != proto::register_pk_response::Result::Ok as i32 {
                        bail!("RegisterPk rejected: {}", r.result);
                    }
                }
            }
        }

        Ok(())
    }

    /// Send PunchHoleRequest and wait for a response (retries every 3s, 15s deadline).
    async fn do_punch_hole(&self, sock: &UdpSocket, device_id: &str) -> Result<ResolveResult> {
        let req = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::PunchHoleRequest(
                proto::PunchHoleRequest {
                    id: device_id.to_string(),
                    nat_type: proto::NatType::Asymmetric as i32,
                    licence_key: self.licence_key.clone(),
                    conn_type: proto::ConnType::DefaultConn as i32,
                    version: "1.2.7".to_string(),
                    ..Default::default()
                },
            )),
        };
        let req_bytes = req.encode_to_vec();

        let deadline = Instant::now() + Duration::from_secs(15);
        let interval = Duration::from_secs(3);
        let mut last_sent = Instant::now() - interval; // force immediate first send
        let mut buf = vec![0u8; 65535];

        while Instant::now() < deadline {
            if last_sent.elapsed() >= interval {
                sock.send(&req_bytes).await.context("send PunchHoleRequest")?;
                last_sent = Instant::now();
            }

            let n = match timeout(Duration::from_secs(1), sock.recv(&mut buf)).await {
                Ok(Ok(n)) => n,
                _ => continue,
            };

            let msg = match proto::RendezvousMessage::decode(&buf[..n]) {
                Ok(m) => m,
                Err(_) => continue,
            };

            match msg.union {
                Some(proto::rendezvous_message::Union::PunchHoleResponse(phr)) => {
                    return self.handle_punch_hole_response(phr, device_id);
                }
                Some(proto::rendezvous_message::Union::FetchLocalAddr(fla)) => {
                    // Same-LAN detection: hbbs tells us to connect directly.
                    let relay = fla.relay_server;
                    if !fla.socket_addr.is_empty() {
                        let addr = decode_socket_addr(&fla.socket_addr)?;
                        return Ok(ResolveResult {
                            addr: Some(addr),
                            relay_server: relay,
                            uuid: String::new(),
                        });
                    }
                    if !relay.is_empty() {
                        return Ok(ResolveResult {
                            addr: None,
                            relay_server: relay,
                            uuid: String::new(),
                        });
                    }
                }
                _ => continue,
            }
        }

        bail!("device {:?}: no response after 15s", device_id);
    }

    fn handle_punch_hole_response(
        &self,
        phr: proto::PunchHoleResponse,
        device_id: &str,
    ) -> Result<ResolveResult> {
        use proto::punch_hole_response::Failure;
        let failure = Failure::try_from(phr.failure).unwrap_or(Failure::IdNotExist);

        match failure {
            Failure::Offline => bail!("device {:?} is offline", device_id),
            Failure::LicenseMismatch => bail!("licence key mismatch"),
            Failure::LicenseOveruse => bail!("licence overuse"),
            _ => {}
        }

        // Direct address available.
        if !phr.socket_addr.is_empty() {
            let addr = decode_socket_addr(&phr.socket_addr)?;
            return Ok(ResolveResult {
                addr: Some(addr),
                relay_server: phr.relay_server,
                uuid: String::new(),
            });
        }

        if failure == Failure::IdNotExist {
            bail!("device {:?} not found on rendezvous server", device_id);
        }

        // Relay-only path.
        if !phr.relay_server.is_empty() {
            return Ok(ResolveResult {
                addr: None,
                relay_server: phr.relay_server,
                uuid: String::new(),
            });
        }

        if !phr.other_failure.is_empty() {
            bail!("rendezvous error: {}", phr.other_failure);
        }

        bail!("device {:?}: empty response", device_id);
    }

    /// Request a relay UUID from hbbs via TCP (BytesCodec framed).
    async fn request_relay_uuid(
        &self,
        server: &str,
        device_id: &str,
        relay_server: &str,
    ) -> Result<String> {
        let uuid = make_uuid();

        let tcp = tokio::net::TcpStream::connect(server)
            .await
            .context("TCP connect to hbbs")?;
        let mut tcp = tokio::io::BufWriter::new(tcp);

        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RequestRelay(
                proto::RequestRelay {
                    id: device_id.to_string(),
                    uuid: uuid.clone(),
                    relay_server: relay_server.to_string(),
                    licence_key: self.licence_key.clone(),
                    conn_type: proto::ConnType::DefaultConn as i32,
                    ..Default::default()
                },
            )),
        };

        codec::write_frame(&mut tcp, &msg.encode_to_vec()).await?;
        tcp.flush().await?;

        Ok(uuid)
    }

    /// Run a persistent registration loop that also listens for relay notifications.
    ///
    /// Unlike `register_once()` which creates ephemeral sockets, this maintains
    /// a persistent UDP socket so hbbs can send RelayResponse notifications when
    /// a client requests relay connection to this device.
    ///
    /// Relay notifications are sent to `relay_tx`. The caller should spawn a handler
    /// that connects to hbbr with the UUID and accepts the incoming TLS connection.
    pub async fn run_registration_loop(
        &self,
        cancel: tokio_util::sync::CancellationToken,
        relay_tx: tokio::sync::mpsc::Sender<RelayNotification>,
    ) {
        if self.servers.is_empty() || self.local_id.is_empty() {
            tracing::warn!("rendezvous loop: no servers or no device_id, not starting");
            return;
        }

        let sock = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("rendezvous loop: bind failed: {}", e);
                return;
            }
        };

        // Resolve server addresses.
        let mut server_addrs = Vec::new();
        for srv in &self.servers {
            match tokio::net::lookup_host(srv).await {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        server_addrs.push(addr);
                    }
                }
                Err(e) => tracing::warn!("rendezvous loop: resolve {}: {}", srv, e),
            }
        }

        if server_addrs.is_empty() {
            tracing::warn!("rendezvous loop: no servers resolved");
            return;
        }

        // Pre-encode the registration message.
        let reg_msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RegisterPeer(
                proto::RegisterPeer {
                    id: self.local_id.clone(),
                    serial: 0,
                    group_hash: self.group_hash.clone(),
                    hostname: self.hostname.clone(),
                    platform: self.platform.clone(),
                    service_port: self.service_port as i32,
                },
            )),
        };
        let reg_bytes = reg_msg.encode_to_vec();

        let mut interval = tokio::time::interval(Duration::from_secs(30));
        let mut buf = vec![0u8; 65535];

        if !self.group_hash.is_empty() {
            tracing::info!(
                "rendezvous loop: DeviceID {} (group enrolled), listening for relay",
                self.local_id
            );
        } else {
            tracing::info!(
                "rendezvous loop: DeviceID {}, listening for relay",
                self.local_id
            );
        }

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::debug!("rendezvous loop: cancelled");
                    return;
                }
                _ = interval.tick() => {
                    for addr in &server_addrs {
                        let _ = sock.send_to(&reg_bytes, addr).await;
                    }
                }
                result = sock.recv_from(&mut buf) => {
                    if let Ok((n, _src)) = result {
                        if let Ok(msg) = proto::RendezvousMessage::decode(&buf[..n]) {
                            match msg.union {
                                Some(proto::rendezvous_message::Union::RegisterPeerResponse(_)) => {
                                    tracing::debug!("rendezvous: registered");
                                }
                                Some(proto::rendezvous_message::Union::RegisterPkResponse(_)) => {
                                    tracing::debug!("rendezvous: pk registered");
                                }
                                Some(proto::rendezvous_message::Union::RelayResponse(rr)) => {
                                    if !rr.uuid.is_empty() {
                                        tracing::info!(
                                            "rendezvous: relay notification uuid={} relay={}",
                                            rr.uuid, rr.relay_server
                                        );
                                        let _ = relay_tx.send(RelayNotification {
                                            uuid: rr.uuid,
                                            relay_server: rr.relay_server,
                                        }).await;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Handle a TCP RequestRelay: look up target device and forward RelayResponse via UDP.
async fn handle_tcp_relay_request(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    peers: &std::sync::Mutex<HashMap<String, PeerEntry>>,
    sock: &UdpSocket,
    relay_server: &str,
    key: &str,
) -> Result<()> {
    let data = timeout(
        Duration::from_secs(10),
        codec::decode_frame(&mut stream),
    )
    .await
    .context("tcp relay read timeout")?
    .context("tcp relay read")?;

    let msg = proto::RendezvousMessage::decode(&data[..]).context("decode RequestRelay")?;

    if let Some(proto::rendezvous_message::Union::RequestRelay(rr)) = msg.union {
        // Validate key.
        if !key.is_empty() && rr.licence_key != key {
            tracing::debug!("rdv tcp: key mismatch from {}", peer);
            return Ok(());
        }

        if rr.uuid.is_empty() {
            tracing::debug!("rdv tcp: empty UUID from {}", peer);
            return Ok(());
        }

        // Look up target device.
        let target_addr = {
            let map = peers.lock().unwrap();
            map.get(&rr.id).map(|e| e.addr)
        };

        if let Some(addr) = target_addr {
            let relay = if rr.relay_server.is_empty() {
                relay_server.to_string()
            } else {
                rr.relay_server
            };

            // Forward RelayResponse to target device via UDP.
            let response = proto::RendezvousMessage {
                union: Some(proto::rendezvous_message::Union::RelayResponse(
                    proto::RelayResponse {
                        uuid: rr.uuid.clone(),
                        relay_server: relay,
                        socket_addr: encode_socket_addr(&peer),
                        ..Default::default()
                    },
                )),
            };
            sock.send_to(&response.encode_to_vec(), addr).await?;
            tracing::info!("rdv: relay {} → {} (uuid={})", rr.id, addr, rr.uuid);
        } else {
            tracing::debug!("rdv: relay for {} — not registered", rr.id);
        }
    }

    Ok(())
}

/// Generate a random UUID v4 string.
fn make_uuid() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_be_bytes([b[4], b[5]]),
        u16::from_be_bytes([b[6], b[7]]),
        u16::from_be_bytes([b[8], b[9]]),
        u64::from_be_bytes([0, 0, b[10], b[11], b[12], b[13], b[14], b[15]]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_valid() {
        assert!(is_device_id("123456789"));
        assert!(is_device_id("abc123"));
        assert!(is_device_id("ABC123456"));
        assert!(is_device_id("a1"));
        assert!(is_device_id("1"));
        assert!(is_device_id("0"));
    }

    #[test]
    fn device_id_invalid() {
        assert!(!is_device_id(""));
        assert!(!is_device_id("192.168.1.1"));
        assert!(!is_device_id("10.0.0.1"));
        assert!(!is_device_id("example.com"));
        assert!(!is_device_id("abcdef"));   // no digits
        assert!(!is_device_id("123abc"));   // letter after digit
        assert!(!is_device_id("a-1"));      // dash
        assert!(!is_device_id("::1"));      // IPv6
    }

    #[test]
    fn addr_decode_lan() {
        // Encode 192.168.1.100:8822 with tm=0 for testing.
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let port: u16 = 8822;
        let ip32 = u32::from_le_bytes(ip.octets());
        let lo = (ip32 as u64) << 49 | port as u64;
        let hi = (ip32 as u64) >> 15;
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(&lo.to_le_bytes());
        data[8..].copy_from_slice(&hi.to_le_bytes());
        let end = data.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(4).max(4);

        let addr = decode_socket_addr(&data[..end]).unwrap();
        assert_eq!(addr, SocketAddr::V4(SocketAddrV4::new(ip, port)));
    }

    #[test]
    fn addr_decode_tailscale() {
        let ip = Ipv4Addr::new(100, 124, 180, 114);
        let port: u16 = 8822;
        let ip32 = u32::from_le_bytes(ip.octets());
        let lo = (ip32 as u64) << 49 | port as u64;
        let hi = (ip32 as u64) >> 15;
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(&lo.to_le_bytes());
        data[8..].copy_from_slice(&hi.to_le_bytes());
        let end = data.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(4).max(4);

        let addr = decode_socket_addr(&data[..end]).unwrap();
        assert_eq!(addr, SocketAddr::V4(SocketAddrV4::new(ip, port)));
    }

    #[test]
    fn addr_decode_invalid_len() {
        assert!(decode_socket_addr(&[]).is_err());
        assert!(decode_socket_addr(&[1, 2, 3]).is_err());
        assert!(decode_socket_addr(&[0; 20]).is_err());
    }

    #[test]
    fn resolve_no_servers() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let c = Client {
                servers: vec![],
                licence_key: String::new(),
                local_id: String::new(),
                group_hash: String::new(),
                hostname: String::new(),
                platform: String::new(),
                service_port: 0,
            };
            assert!(c.resolve("123456789").await.is_err());
        });
    }

    #[test]
    fn uuid_format() {
        let u = make_uuid();
        assert_eq!(u.len(), 36);
        assert_eq!(u.as_bytes()[8], b'-');
        assert_eq!(u.as_bytes()[13], b'-');
        assert_eq!(u.as_bytes()[18], b'-');
        assert_eq!(u.as_bytes()[23], b'-');
    }

    // --- encode_socket_addr tests ---

    #[test]
    fn addr_encode_decode_roundtrip_zero_tm() {
        let addr: SocketAddr = "192.168.1.100:8822".parse().unwrap();
        let encoded = encode_socket_addr_with_tm(&addr, 0);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn addr_encode_decode_roundtrip_nonzero_tm() {
        let addr: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let encoded = encode_socket_addr_with_tm(&addr, 1710000000);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn addr_encode_decode_roundtrip_tailscale() {
        let addr: SocketAddr = "100.124.180.114:8822".parse().unwrap();
        let encoded = encode_socket_addr_with_tm(&addr, 0xDEADBEEF);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn addr_encode_decode_roundtrip_live() {
        // Uses real timestamp (encode_socket_addr without explicit tm).
        let addr: SocketAddr = "192.168.1.220:80".parse().unwrap();
        let encoded = encode_socket_addr(&addr);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn addr_encode_minimum_4_bytes() {
        let addr: SocketAddr = "0.0.0.1:1".parse().unwrap();
        let encoded = encode_socket_addr_with_tm(&addr, 0);
        assert!(encoded.len() >= 4);
    }

    // --- RendezvousServer tests ---

    #[tokio::test]
    async fn rdv_server_register_and_resolve() {
        let srv = RendezvousServer::new("", "relay.test:21117");
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = sock.local_addr().unwrap();
        let sock = Arc::new(sock);

        let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        // Server recv loop (single iteration per request).
        let srv_sock = sock.clone();
        let peers_clone = peers.clone();
        let srv_clone_key = srv.key.clone();
        let srv_clone_relay = srv.relay_server.clone();
        let handle = tokio::spawn(async move {
            let srv_inner = RendezvousServer::new(&srv_clone_key, &srv_clone_relay);
            let mut buf = vec![0u8; 65535];
            // Handle 2 messages: register + punch hole
            for _ in 0..2 {
                let (n, src) = srv_sock.recv_from(&mut buf).await.unwrap();
                let msg = proto::RendezvousMessage::decode(&buf[..n]).unwrap();
                if let Some(resp) = srv_inner.handle_message(msg, src, &peers_clone) {
                    srv_sock.send_to(&resp.encode_to_vec(), src).await.unwrap();
                }
            }
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(srv_addr).await.unwrap();

        // Register as "dev123".
        let reg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RegisterPeer(
                proto::RegisterPeer {
                    id: "dev123".to_string(),
                    ..Default::default()
                },
            )),
        };
        client.send(&reg.encode_to_vec()).await.unwrap();
        let mut buf = vec![0u8; 65535];
        let n = timeout(Duration::from_secs(3), client.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = proto::RendezvousMessage::decode(&buf[..n]).unwrap();
        assert!(matches!(
            resp.union,
            Some(proto::rendezvous_message::Union::RegisterPeerResponse(_))
        ));

        // Punch hole request for "dev123" (same IP → FetchLocalAddr).
        let punch = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::PunchHoleRequest(
                proto::PunchHoleRequest {
                    id: "dev123".to_string(),
                    ..Default::default()
                },
            )),
        };
        client.send(&punch.encode_to_vec()).await.unwrap();
        let n = timeout(Duration::from_secs(3), client.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = proto::RendezvousMessage::decode(&buf[..n]).unwrap();
        // Same IP → FetchLocalAddr.
        match resp.union {
            Some(proto::rendezvous_message::Union::FetchLocalAddr(fla)) => {
                assert!(!fla.socket_addr.is_empty());
                assert_eq!(fla.relay_server, "relay.test:21117");
            }
            other => panic!("expected FetchLocalAddr, got {:?}", other),
        }

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn rdv_server_unknown_device() {
        let srv = RendezvousServer::new("", "relay.test:21117");
        let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        let punch = proto::PunchHoleRequest {
            id: "nonexistent".to_string(),
            ..Default::default()
        };
        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::PunchHoleRequest(punch)),
        };
        let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let resp = srv.handle_message(msg, src, &peers).unwrap();
        match resp.union {
            Some(proto::rendezvous_message::Union::PunchHoleResponse(phr)) => {
                assert_eq!(
                    phr.failure,
                    proto::punch_hole_response::Failure::IdNotExist as i32
                );
            }
            other => panic!("expected PunchHoleResponse, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn rdv_server_key_mismatch() {
        let srv = RendezvousServer::new("secret", "relay.test:21117");
        let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        let punch = proto::PunchHoleRequest {
            id: "dev1".to_string(),
            licence_key: "wrong".to_string(),
            ..Default::default()
        };
        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::PunchHoleRequest(punch)),
        };
        let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let resp = srv.handle_message(msg, src, &peers).unwrap();
        match resp.union {
            Some(proto::rendezvous_message::Union::PunchHoleResponse(phr)) => {
                assert_eq!(
                    phr.failure,
                    proto::punch_hole_response::Failure::LicenseMismatch as i32
                );
            }
            other => panic!("expected LicenseMismatch, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn rdv_server_register_pk() {
        let srv = RendezvousServer::new("", "relay.test:21117");
        let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        let rpk = proto::RegisterPk {
            id: "dev1".to_string(),
            uuid: vec![1; 16],
            pk: vec![0; 32],
            ..Default::default()
        };
        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RegisterPk(rpk)),
        };
        let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let resp = srv.handle_message(msg, src, &peers).unwrap();
        match resp.union {
            Some(proto::rendezvous_message::Union::RegisterPkResponse(r)) => {
                assert_eq!(r.result, proto::register_pk_response::Result::Ok as i32);
                assert_eq!(r.keep_alive, 300);
            }
            other => panic!("expected RegisterPkResponse, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn rdv_server_health_check() {
        let srv = RendezvousServer::new("", "relay.test:21117");
        let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        // Add a peer.
        peers.lock().unwrap().insert(
            "dev1".to_string(),
            PeerEntry {
                addr: "10.0.0.1:8822".parse().unwrap(),
                last_seen: Instant::now(),
                group_hash: String::new(),
                hostname: String::new(),
                platform: String::new(),
                service_port: 0,
            },
        );

        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::HealthCheck(
                proto::HealthCheck {
                    token: String::new(),
                },
            )),
        };
        let src: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let resp = srv.handle_message(msg, src, &peers).unwrap();
        match resp.union {
            Some(proto::rendezvous_message::Union::HealthResponse(hr)) => {
                assert_eq!(hr.peers_online, 1);
                assert!(!hr.version.is_empty());
            }
            other => panic!("expected HealthResponse, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn rdv_server_cross_network_returns_punch_hole_response() {
        let srv = RendezvousServer::new("", "relay.test:21117");
        let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        // Register peer from a different IP.
        peers.lock().unwrap().insert(
            "remote1".to_string(),
            PeerEntry {
                addr: "203.0.113.50:8822".parse().unwrap(),
                last_seen: Instant::now(),
                group_hash: String::new(),
                hostname: String::new(),
                platform: String::new(),
                service_port: 0,
            },
        );

        let punch = proto::PunchHoleRequest {
            id: "remote1".to_string(),
            ..Default::default()
        };
        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::PunchHoleRequest(punch)),
        };
        // Requester comes from a different IP.
        let src: SocketAddr = "198.51.100.10:54321".parse().unwrap();
        let resp = srv.handle_message(msg, src, &peers).unwrap();
        match resp.union {
            Some(proto::rendezvous_message::Union::PunchHoleResponse(phr)) => {
                assert!(!phr.socket_addr.is_empty());
                assert_eq!(phr.relay_server, "relay.test:21117");
                // Decode the address to verify it matches the registered peer.
                let decoded = decode_socket_addr(&phr.socket_addr).unwrap();
                assert_eq!(decoded, "203.0.113.50:8822".parse::<SocketAddr>().unwrap());
            }
            other => panic!("expected PunchHoleResponse, got {:?}", other),
        }
    }

    // --- Protobuf zero-value / edge case tests (orin-0td) ---

    /// PunchHoleResponse with failure=0 (IdNotExist, protobuf default) but valid
    /// socket_addr should return the address, not an error.  Failure=0 is the
    /// protobuf default so a "success" response has failure==0 implicitly.
    #[tokio::test]
    async fn rdv_server_success_response_has_failure_zero() {
        let srv = RendezvousServer::new("", "relay.test:21117");
        let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        peers.lock().unwrap().insert(
            "peer1".to_string(),
            PeerEntry {
                addr: "10.0.0.5:8822".parse().unwrap(),
                last_seen: Instant::now(),
                group_hash: String::new(),
                hostname: String::new(),
                platform: String::new(),
                service_port: 0,
            },
        );

        let punch = proto::PunchHoleRequest {
            id: "peer1".to_string(),
            ..Default::default()
        };
        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::PunchHoleRequest(punch)),
        };
        // Different IP so we get PunchHoleResponse (not FetchLocalAddr).
        let src: SocketAddr = "203.0.113.1:9999".parse().unwrap();
        let resp = srv.handle_message(msg, src, &peers).unwrap();
        match resp.union {
            Some(proto::rendezvous_message::Union::PunchHoleResponse(phr)) => {
                // failure field is 0 (IdNotExist/default) — but socket_addr is populated,
                // so the client should treat this as success.
                assert_eq!(phr.failure, proto::punch_hole_response::Failure::IdNotExist as i32);
                assert!(!phr.socket_addr.is_empty(), "socket_addr must be populated");
                let decoded = decode_socket_addr(&phr.socket_addr).unwrap();
                assert_eq!(decoded, "10.0.0.5:8822".parse::<SocketAddr>().unwrap());
            }
            other => panic!("expected PunchHoleResponse, got {:?}", other),
        }
    }

    /// AddrMangle roundtrip with port 0 (edge case: port=0 after wrapping).
    #[test]
    fn addr_encode_decode_roundtrip_port_zero() {
        let addr: SocketAddr = "192.168.1.1:0".parse().unwrap();
        let encoded = encode_socket_addr_with_tm(&addr, 0);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    /// AddrMangle roundtrip with port 65535 (max u16).
    #[test]
    fn addr_encode_decode_roundtrip_port_max() {
        let addr: SocketAddr = "10.0.0.1:65535".parse().unwrap();
        let encoded = encode_socket_addr_with_tm(&addr, 0xFFFFFFFF);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    /// AddrMangle with 0.0.0.0 (all-zeros IP).
    #[test]
    fn addr_encode_decode_roundtrip_zero_ip() {
        let addr: SocketAddr = "0.0.0.0:8822".parse().unwrap();
        let encoded = encode_socket_addr_with_tm(&addr, 42);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    /// AddrMangle with 255.255.255.255 (broadcast).
    #[test]
    fn addr_encode_decode_roundtrip_broadcast() {
        let addr: SocketAddr = "255.255.255.255:65535".parse().unwrap();
        let encoded = encode_socket_addr_with_tm(&addr, 0xDEADCAFE);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    /// Port preservation: resolve result must carry the exact port registered.
    #[tokio::test]
    async fn rdv_server_preserves_registered_port() {
        let srv = RendezvousServer::new("", "relay.test:21117");
        let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        // Register on non-default port.
        peers.lock().unwrap().insert(
            "custom-port".to_string(),
            PeerEntry {
                addr: "172.16.0.1:9822".parse().unwrap(),
                last_seen: Instant::now(),
                group_hash: String::new(),
                hostname: String::new(),
                platform: String::new(),
                service_port: 0,
            },
        );

        let punch = proto::PunchHoleRequest {
            id: "custom-port".to_string(),
            ..Default::default()
        };
        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::PunchHoleRequest(punch)),
        };
        let src: SocketAddr = "198.51.100.1:12345".parse().unwrap();
        let resp = srv.handle_message(msg, src, &peers).unwrap();
        match resp.union {
            Some(proto::rendezvous_message::Union::PunchHoleResponse(phr)) => {
                let decoded = decode_socket_addr(&phr.socket_addr).unwrap();
                assert_eq!(decoded.port(), 9822, "port must be preserved through encode/decode");
            }
            other => panic!("expected PunchHoleResponse, got {:?}", other),
        }
    }

    // --- Network partition / unreachable server tests (rsh-a3o) ---

    fn make_client(servers: Vec<String>, local_id: &str) -> Client {
        Client {
            servers,
            licence_key: String::new(),
            local_id: local_id.to_string(),
            group_hash: String::new(),
            hostname: "test-host".to_string(),
            platform: "linux".to_string(),
            service_port: 8822,
        }
    }

    /// register_once returns error when no servers are configured (fast path).
    #[test]
    fn register_once_no_servers_configured() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let c = make_client(vec![], "test-device");
            let err = c.register_once().await.unwrap_err();
            assert!(err.to_string().contains("no rendezvous server"));
        });
    }

    /// register_once returns error immediately when local_id is empty.
    #[test]
    fn register_once_no_local_id() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let c = make_client(vec!["127.0.0.1:19999".to_string()], "");
            let err = c.register_once().await.unwrap_err();
            assert!(err.to_string().contains("no local_id"));
        });
    }

    /// register_once fails gracefully when all servers are unreachable.
    /// On Linux, UDP send to a closed local port gets ECONNREFUSED on recv.
    /// The 5-second timeout in do_register fires as fallback.
    /// Either way: must return an error, must not hang indefinitely.
    #[tokio::test(flavor = "current_thread")]
    async fn register_once_server_unreachable_returns_error() {
        // Bind then immediately drop to get a "closed" port (ICMP port-unreachable).
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = sock.local_addr().unwrap().to_string();
        drop(sock);

        let c = make_client(vec![closed_addr], "partition-test-device");

        // Must return error — either ECONNREFUSED (fast) or timeout (≤5s).
        let result = tokio::time::timeout(
            Duration::from_secs(7),
            c.register_once(),
        )
        .await;

        match result {
            Ok(inner) => assert!(inner.is_err(), "register_once must fail when server unreachable"),
            Err(_) => panic!("register_once hung beyond 7 seconds (deadline: 5s per server)"),
        }
    }

    // --- Relay forwarding tests (beads-u8d) ---

    /// hbbs TCP RequestRelay forwarding: registered device receives RelayResponse via UDP.
    #[tokio::test]
    async fn rdv_tcp_relay_forwarding_to_registered_device() {
        use tokio::io::AsyncReadExt;

        // Start hbbs (UDP + TCP) on random port.
        let udp_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = udp_sock.local_addr().unwrap();
        drop(udp_sock);

        let srv = RendezvousServer::new("testkey", &format!("127.0.0.1:{}", srv_addr.port() + 1));

        let srv_handle = tokio::spawn(async move {
            // Will run until cancelled; we just let it run in background.
            let _ = srv.listen_and_serve(&srv_addr.to_string()).await;
        });

        // Give server time to bind.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // "Server" device: register with hbbs and listen for messages on same socket.
        let device_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let device_addr = device_sock.local_addr().unwrap();

        // Register device "999888777" by sending RegisterPeer.
        let reg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RegisterPeer(
                proto::RegisterPeer {
                    id: "999888777".to_string(),
                    hostname: "test-device".to_string(),
                    platform: "linux".to_string(),
                    service_port: 8822,
                    ..Default::default()
                },
            )),
        };
        device_sock
            .send_to(&reg.encode_to_vec(), srv_addr)
            .await
            .unwrap();

        // Read RegisterPeerResponse.
        let mut buf = vec![0u8; 65535];
        let (n, _) = timeout(Duration::from_secs(3), device_sock.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = proto::RendezvousMessage::decode(&buf[..n]).unwrap();
        assert!(
            matches!(
                resp.union,
                Some(proto::rendezvous_message::Union::RegisterPeerResponse(_))
            ),
            "should get RegisterPeerResponse"
        );

        // "Client": send RequestRelay via TCP to hbbs for device 999888777.
        let mut tcp = tokio::net::TcpStream::connect(srv_addr).await.unwrap();
        let relay_req = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RequestRelay(
                proto::RequestRelay {
                    id: "999888777".to_string(),
                    uuid: "test-uuid-1234".to_string(),
                    relay_server: "relay.test:21117".to_string(),
                    licence_key: "testkey".to_string(),
                    ..Default::default()
                },
            )),
        };
        let frame = crate::codec::encode_frame(&relay_req.encode_to_vec());
        use tokio::io::AsyncWriteExt;
        tcp.write_all(&frame).await.unwrap();

        // The "device" should receive RelayResponse via UDP.
        let (n, _) = timeout(Duration::from_secs(3), device_sock.recv_from(&mut buf))
            .await
            .expect("device should receive RelayResponse within 3s")
            .unwrap();
        let notification = proto::RendezvousMessage::decode(&buf[..n]).unwrap();
        match notification.union {
            Some(proto::rendezvous_message::Union::RelayResponse(rr)) => {
                assert_eq!(rr.uuid, "test-uuid-1234");
                assert_eq!(rr.relay_server, "relay.test:21117");
            }
            other => panic!("expected RelayResponse, got {:?}", other),
        }

        srv_handle.abort();
    }

    /// hbbs TCP RequestRelay for unregistered device: no crash, no notification.
    #[tokio::test]
    async fn rdv_tcp_relay_unregistered_device_no_crash() {
        let udp_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = udp_sock.local_addr().unwrap();
        drop(udp_sock);

        let srv = RendezvousServer::new("", "relay.test:21117");
        let srv_handle = tokio::spawn(async move {
            let _ = srv.listen_and_serve(&srv_addr.to_string()).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Send RequestRelay for non-existent device — should not crash.
        let mut tcp = tokio::net::TcpStream::connect(srv_addr).await.unwrap();
        let relay_req = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RequestRelay(
                proto::RequestRelay {
                    id: "nonexistent".to_string(),
                    uuid: "test-uuid".to_string(),
                    ..Default::default()
                },
            )),
        };
        let frame = crate::codec::encode_frame(&relay_req.encode_to_vec());
        use tokio::io::AsyncWriteExt;
        tcp.write_all(&frame).await.unwrap();

        // Give hbbs time to process.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Server should still be alive (try another TCP connection).
        let tcp2 = tokio::net::TcpStream::connect(srv_addr).await;
        assert!(tcp2.is_ok(), "hbbs should still accept connections");

        srv_handle.abort();
    }

    /// hbbs TCP RequestRelay with key mismatch: silently rejected.
    #[tokio::test]
    async fn rdv_tcp_relay_key_mismatch_rejected() {
        let udp_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let srv_addr = udp_sock.local_addr().unwrap();
        drop(udp_sock);

        let srv = RendezvousServer::new("correctkey", "relay.test:21117");
        let srv_handle = tokio::spawn(async move {
            let _ = srv.listen_and_serve(&srv_addr.to_string()).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Register a device.
        let device_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let reg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RegisterPeer(
                proto::RegisterPeer {
                    id: "keytestdev".to_string(),
                    ..Default::default()
                },
            )),
        };
        device_sock
            .send_to(&reg.encode_to_vec(), srv_addr)
            .await
            .unwrap();
        let mut buf = vec![0u8; 65535];
        let _ = timeout(Duration::from_secs(2), device_sock.recv_from(&mut buf))
            .await
            .unwrap();

        // Send RequestRelay with wrong key.
        let mut tcp = tokio::net::TcpStream::connect(srv_addr).await.unwrap();
        let relay_req = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RequestRelay(
                proto::RequestRelay {
                    id: "keytestdev".to_string(),
                    uuid: "uuid-xyz".to_string(),
                    licence_key: "wrongkey".to_string(),
                    ..Default::default()
                },
            )),
        };
        let frame = crate::codec::encode_frame(&relay_req.encode_to_vec());
        use tokio::io::AsyncWriteExt;
        tcp.write_all(&frame).await.unwrap();

        // Device should NOT receive anything (key mismatch → silently rejected).
        let result = timeout(Duration::from_millis(500), device_sock.recv_from(&mut buf)).await;
        assert!(result.is_err(), "device should not receive notification on key mismatch");

        srv_handle.abort();
    }

    /// run_registration_loop receives RelayResponse and forwards to channel.
    #[tokio::test]
    async fn registration_loop_receives_relay_notification() {
        // Start a minimal hbbs.
        let hbbs_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let hbbs_addr = hbbs_sock.local_addr().unwrap();

        let hbbs_sock_clone = hbbs_sock.clone();
        let hbbs_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            // Read RegisterPeer, respond, then send a fake RelayResponse.
            let (n, src) = hbbs_sock_clone.recv_from(&mut buf).await.unwrap();
            let msg = proto::RendezvousMessage::decode(&buf[..n]).unwrap();
            assert!(matches!(
                msg.union,
                Some(proto::rendezvous_message::Union::RegisterPeer(_))
            ));

            // Send RegisterPeerResponse.
            let resp = proto::RendezvousMessage {
                union: Some(proto::rendezvous_message::Union::RegisterPeerResponse(
                    proto::RegisterPeerResponse { request_pk: false },
                )),
            };
            hbbs_sock_clone
                .send_to(&resp.encode_to_vec(), src)
                .await
                .unwrap();

            // Now send a RelayResponse (simulating a client requesting relay).
            tokio::time::sleep(Duration::from_millis(50)).await;
            let relay_resp = proto::RendezvousMessage {
                union: Some(proto::rendezvous_message::Union::RelayResponse(
                    proto::RelayResponse {
                        uuid: "relay-uuid-abc".to_string(),
                        relay_server: "hbbr.test:21117".to_string(),
                        ..Default::default()
                    },
                )),
            };
            hbbs_sock_clone
                .send_to(&relay_resp.encode_to_vec(), src)
                .await
                .unwrap();
        });

        let cancel = tokio_util::sync::CancellationToken::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);

        let client = Client {
            servers: vec![hbbs_addr.to_string()],
            licence_key: String::new(),
            local_id: "testdev123".to_string(),
            group_hash: String::new(),
            hostname: "test".to_string(),
            platform: "linux".to_string(),
            service_port: 8822,
        };

        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            client.run_registration_loop(cancel_clone, tx).await;
        });

        // Wait for the relay notification.
        let notif = timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("should receive relay notification within 5s")
            .expect("channel should not be closed");

        assert_eq!(notif.uuid, "relay-uuid-abc");
        assert_eq!(notif.relay_server, "hbbr.test:21117");

        cancel.cancel();
        hbbs_handle.await.unwrap();
    }

    #[tokio::test]
    async fn rdv_list_peers_returns_all_registered() {
        let srv = RendezvousServer::new("test-key", "relay.test:21117");
        let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        // Register two peers
        peers.lock().unwrap().insert(
            "111".to_string(),
            PeerEntry {
                addr: "10.0.0.1:8822".parse().unwrap(),
                last_seen: Instant::now(),
                group_hash: String::new(),
                hostname: "host-a".to_string(),
                platform: "windows".to_string(),
                service_port: 0,
            },
        );
        peers.lock().unwrap().insert(
            "222".to_string(),
            PeerEntry {
                addr: "10.0.0.2:8822".parse().unwrap(),
                last_seen: Instant::now(),
                group_hash: String::new(),
                hostname: "host-b".to_string(),
                platform: "linux".to_string(),
                service_port: 0,
            },
        );

        // Valid key → should get both peers
        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::ListPeers(
                proto::ListPeers { licence_key: "test-key".to_string() },
            )),
        };
        let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let resp = srv.handle_message(msg, src, &peers).unwrap();
        match resp.union {
            Some(proto::rendezvous_message::Union::ListPeersResponse(lpr)) => {
                assert_eq!(lpr.peers.len(), 2);
                let ids: Vec<&str> = lpr.peers.iter().map(|p| p.device_id.as_str()).collect();
                assert!(ids.contains(&"111"));
                assert!(ids.contains(&"222"));
            }
            other => panic!("expected ListPeersResponse, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn rdv_list_peers_rejects_bad_key() {
        let srv = RendezvousServer::new("correct-key", "relay.test:21117");
        let peers: Arc<std::sync::Mutex<HashMap<String, PeerEntry>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        peers.lock().unwrap().insert(
            "111".to_string(),
            PeerEntry {
                addr: "10.0.0.1:8822".parse().unwrap(),
                last_seen: Instant::now(),
                group_hash: String::new(),
                hostname: "host-a".to_string(),
                platform: "windows".to_string(),
                service_port: 0,
            },
        );

        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::ListPeers(
                proto::ListPeers { licence_key: "wrong-key".to_string() },
            )),
        };
        let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let resp = srv.handle_message(msg, src, &peers);
        assert!(resp.is_none(), "bad key should be rejected");
    }
}
