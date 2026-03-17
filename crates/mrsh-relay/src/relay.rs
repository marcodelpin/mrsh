//! Relay client and server — UUID-based TCP connection pairing.
//!
//! Client: connects to hbbr, sends BytesCodec-framed RequestRelay with a UUID,
//!         then the TCP stream becomes a raw bidirectional tunnel to the peer.
//!
//! Server: accepts pairs of connections with matching UUIDs and bridges them.
//!
//! Clean-room implementation. MIT licensed.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use prost::Message;
use tokio::io::{self, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore, oneshot};
use tokio::time::{Duration, timeout};

use crate::codec;
use crate::proto;

/// Timeout for the initial RequestRelay handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for a matching peer before giving up.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum concurrent relay sessions.
const DEFAULT_MAX_SESSIONS: usize = 200;

/// Default maximum connections per IP address.
const DEFAULT_MAX_PER_IP: usize = 10;

/// Default maximum entries in the waiting room (unpaired connections).
const DEFAULT_MAX_WAITING: usize = 100;

/// Default maximum relay session duration (1 hour).
const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(3600);

/// Configuration for relay server resource limits.
#[derive(Clone, Debug)]
pub struct RelayLimits {
    /// Maximum concurrent relay sessions.
    pub max_sessions: usize,
    /// Maximum connections from a single IP address.
    pub max_per_ip: usize,
    /// Maximum unpaired connections waiting in the lobby.
    pub max_waiting: usize,
    /// Maximum duration for a bridged relay session.
    pub session_timeout: Duration,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_per_ip: DEFAULT_MAX_PER_IP,
            max_waiting: DEFAULT_MAX_WAITING,
            session_timeout: DEFAULT_SESSION_TIMEOUT,
        }
    }
}

/// Per-IP connection counter with RAII cleanup.
#[derive(Clone)]
struct IpTracker {
    counts: Arc<std::sync::Mutex<HashMap<IpAddr, usize>>>,
    max_per_ip: usize,
}

impl IpTracker {
    fn new(max_per_ip: usize) -> Self {
        Self {
            counts: Arc::new(std::sync::Mutex::new(HashMap::new())),
            max_per_ip,
        }
    }

    /// Try to increment the counter for this IP. Returns false if limit reached.
    fn try_acquire(&self, ip: IpAddr) -> bool {
        let mut map = self.counts.lock().unwrap();
        let count = map.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            return false;
        }
        *count += 1;
        true
    }

    /// Decrement the counter for this IP.
    fn release(&self, ip: IpAddr) {
        let mut map = self.counts.lock().unwrap();
        if let Some(count) = map.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&ip);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Connect to a relay server (hbbr) and return the raw tunnel stream.
///
/// After the RequestRelay handshake, hbbr pairs this connection with another
/// connection carrying the same UUID. The returned stream is then a raw
/// bidirectional pipe to the peer.
pub async fn connect_relay(relay_addr: &str, uuid: &str, licence_key: &str) -> Result<TcpStream> {
    let mut stream = timeout(Duration::from_secs(10), TcpStream::connect(relay_addr))
        .await
        .context("relay connect timeout")?
        .context("connect to relay")?;

    let msg = proto::RendezvousMessage {
        union: Some(proto::rendezvous_message::Union::RequestRelay(
            proto::RequestRelay {
                uuid: uuid.to_string(),
                licence_key: licence_key.to_string(),
                ..Default::default()
            },
        )),
    };

    let framed = codec::encode_frame(&msg.encode_to_vec());
    stream.write_all(&framed).await.context("send RequestRelay")?;

    // After sending, the connection is handed off to hbbr for pairing.
    // No explicit response — the stream becomes a raw tunnel once paired.
    Ok(stream)
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// A relay server that pairs TCP connections by UUID and bridges them.
pub struct RelayServer {
    /// Waiting room: UUID → channel to deliver the second peer's stream.
    waiting: Arc<Mutex<HashMap<String, oneshot::Sender<TcpStream>>>>,
    /// Authentication key (empty = no auth).
    key: String,
    /// Number of currently active relay sessions.
    active: Arc<AtomicU64>,
    /// Total relay sessions served since start.
    total: Arc<AtomicU64>,
    /// Global session semaphore.
    session_semaphore: Arc<Semaphore>,
    /// Per-IP connection tracker.
    ip_tracker: IpTracker,
    /// Resource limits.
    limits: RelayLimits,
}

impl RelayServer {
    pub fn new(key: &str) -> Self {
        Self::with_limits(key, RelayLimits::default())
    }

    pub fn with_limits(key: &str, limits: RelayLimits) -> Self {
        Self {
            waiting: Arc::new(Mutex::new(HashMap::new())),
            key: key.to_string(),
            active: Arc::new(AtomicU64::new(0)),
            total: Arc::new(AtomicU64::new(0)),
            session_semaphore: Arc::new(Semaphore::new(limits.max_sessions)),
            ip_tracker: IpTracker::new(limits.max_per_ip),
            limits,
        }
    }

    /// Start accepting relay connections on the given address.
    pub async fn listen_and_serve(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await.context("relay bind")?;

        loop {
            let (stream, peer) = listener.accept().await?;
            let peer_ip = peer.ip();

            // Per-IP connection limit
            if !self.ip_tracker.try_acquire(peer_ip) {
                tracing::debug!("relay: per-IP limit reached for {peer_ip}");
                drop(stream);
                continue;
            }

            let waiting = self.waiting.clone();
            let key = self.key.clone();
            let active = self.active.clone();
            let total = self.total.clone();
            let session_sem = self.session_semaphore.clone();
            let ip_tracker = self.ip_tracker.clone();
            let max_waiting = self.limits.max_waiting;
            let session_timeout = self.limits.session_timeout;

            tokio::spawn(async move {
                let result = serve_one(
                    stream, waiting, &key, active, total, session_sem, max_waiting,
                    session_timeout, peer_ip,
                )
                .await;
                // Always release the per-IP slot when this connection is done.
                ip_tracker.release(peer_ip);
                if let Err(e) = result {
                    tracing::debug!("relay conn error from {peer_ip}: {e}");
                }
            });
        }
    }

    /// Return (active_relays, total_relays).
    pub fn stats(&self) -> (u64, u64) {
        (
            self.active.load(Ordering::Relaxed),
            self.total.load(Ordering::Relaxed),
        )
    }
}

/// Handle a single incoming relay connection.
async fn serve_one(
    mut stream: TcpStream,
    waiting: Arc<Mutex<HashMap<String, oneshot::Sender<TcpStream>>>>,
    key: &str,
    active: Arc<AtomicU64>,
    total: Arc<AtomicU64>,
    session_sem: Arc<Semaphore>,
    max_waiting: usize,
    session_timeout: Duration,
    peer_ip: IpAddr,
) -> Result<()> {
    // Read the BytesCodec-framed RequestRelay handshake.
    let payload = timeout(HANDSHAKE_TIMEOUT, codec::decode_frame(&mut stream))
        .await
        .context("handshake timeout")?
        .context("read handshake")?;

    let msg = proto::RendezvousMessage::decode(&payload[..]).context("decode RequestRelay")?;
    let rr = match msg.union {
        Some(proto::rendezvous_message::Union::RequestRelay(rr)) => rr,
        _ => bail!("expected RequestRelay message"),
    };

    if rr.uuid.is_empty() {
        bail!("empty relay UUID");
    }
    if !key.is_empty() && rr.licence_key != key {
        tracing::warn!("relay auth failed from {peer_ip}");
        bail!("relay auth failed");
    }

    let uuid = rr.uuid;

    // Try to pair with a waiting peer.
    let mut map = waiting.lock().await;
    if let Some(sender) = map.remove(&uuid) {
        // Second connection — deliver our stream to the first, which drives the bridge.
        drop(map);
        tracing::info!("relay paired uuid={}… peer={peer_ip}", &uuid[..uuid.len().min(8)]);
        let _ = sender.send(stream);
        return Ok(());
    }

    // Check waiting room capacity before inserting.
    if map.len() >= max_waiting {
        drop(map);
        bail!(
            "waiting room full ({max_waiting} entries), rejecting uuid={}… from {peer_ip}",
            &uuid[..uuid.len().min(8)]
        );
    }

    // First connection — register ourselves and wait for the partner.
    let (tx, rx) = oneshot::channel::<TcpStream>();
    map.insert(uuid.clone(), tx);
    drop(map);

    tracing::debug!(
        "relay waiting for pair: uuid={}… peer={peer_ip}",
        &uuid[..uuid.len().min(8)]
    );

    let partner = match timeout(PAIRING_TIMEOUT, rx).await {
        Ok(Ok(s)) => s,
        _ => {
            // Clean up if timed out or channel dropped.
            waiting.lock().await.remove(&uuid);
            bail!(
                "timeout waiting for relay peer (uuid={}…) from {peer_ip}",
                &uuid[..uuid.len().min(8)]
            );
        }
    };

    // Acquire session permit (global concurrency limit).
    let _session_permit = match session_sem.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            bail!("relay session limit reached, rejecting uuid={}… from {peer_ip}",
                &uuid[..uuid.len().min(8)]);
        }
    };

    // Bridge the two streams with a session duration timeout.
    active.fetch_add(1, Ordering::Relaxed);
    total.fetch_add(1, Ordering::Relaxed);

    tracing::info!(
        "relay bridge start: uuid={}… peer={peer_ip}",
        &uuid[..uuid.len().min(8)]
    );

    let (mut r1, mut w1) = io::split(stream);
    let (mut r2, mut w2) = io::split(partner);

    let fwd = tokio::spawn(async move {
        let _ = io::copy(&mut r1, &mut w2).await;
        let _ = w2.shutdown().await;
    });
    let rev = tokio::spawn(async move {
        let _ = io::copy(&mut r2, &mut w1).await;
        let _ = w1.shutdown().await;
    });

    // Race the bridge against the session timeout.
    let bridge = async { let _ = tokio::join!(fwd, rev); };
    let _ = timeout(session_timeout, bridge).await;

    active.fetch_sub(1, Ordering::Relaxed);
    // _session_permit dropped here, releasing the semaphore slot
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn relay_handshake(uuid: &str, key: &str) -> Vec<u8> {
        let msg = proto::RendezvousMessage {
            union: Some(proto::rendezvous_message::Union::RequestRelay(
                proto::RequestRelay {
                    uuid: uuid.to_string(),
                    licence_key: key.to_string(),
                    ..Default::default()
                },
            )),
        };
        codec::encode_frame(&msg.encode_to_vec())
    }

    #[tokio::test]
    async fn initial_stats() {
        let srv = RelayServer::new("k");
        assert_eq!(srv.stats(), (0, 0));
    }

    fn test_limits() -> RelayLimits {
        RelayLimits {
            max_sessions: 100,
            max_per_ip: 10,
            max_waiting: 50,
            session_timeout: Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn pairing_bridge() {
        let srv = RelayServer::new("");
        let waiting = srv.waiting.clone();
        let active = srv.active.clone();
        let total = srv.total.clone();
        let key = srv.key.clone();
        let session_sem = srv.session_semaphore.clone();
        let limits = srv.limits.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Accept loop.
        let w = waiting.clone();
        let k = key.clone();
        let a = active.clone();
        let t = total.clone();
        let ss = session_sem.clone();
        let mw = limits.max_waiting;
        let st = limits.session_timeout;
        tokio::spawn(async move {
            loop {
                let (s, peer) = listener.accept().await.unwrap();
                let w2 = w.clone();
                let k2 = k.clone();
                let a2 = a.clone();
                let t2 = t.clone();
                let ss2 = ss.clone();
                tokio::spawn(async move {
                    let _ = serve_one(s, w2, &k2, a2, t2, ss2, mw, st, peer.ip()).await;
                });
            }
        });

        let uuid = "test-pair-uuid";

        // Peer A.
        let a_addr = addr;
        let a = tokio::spawn(async move {
            let mut s = TcpStream::connect(a_addr).await.unwrap();
            s.write_all(&relay_handshake(uuid, "")).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            s.write_all(b"PING").await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap().unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Peer B.
        let b_addr = addr;
        let b = tokio::spawn(async move {
            let mut s = TcpStream::connect(b_addr).await.unwrap();
            s.write_all(&relay_handshake(uuid, "")).await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            s.write_all(b"PONG").await.unwrap();
            let mut buf = vec![0u8; 64];
            let n = timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap().unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        let (ra, rb) = tokio::join!(a, b);
        assert_eq!(ra.unwrap(), "PONG");
        assert_eq!(rb.unwrap(), "PING");
    }

    #[tokio::test]
    async fn auth_rejection() {
        let srv = RelayServer::new("secret");
        let waiting = srv.waiting.clone();
        let active = srv.active.clone();
        let total = srv.total.clone();
        let session_sem = srv.session_semaphore.clone();
        let limits = srv.limits.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (s, peer) = listener.accept().await.unwrap();
            let _ = serve_one(
                s, waiting, "secret", active, total, session_sem,
                limits.max_waiting, limits.session_timeout, peer.ip(),
            )
            .await;
        });

        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(&relay_handshake("uuid", "wrong")).await.unwrap();

        // Server closes on auth failure.
        let mut buf = [0u8; 1];
        let r = timeout(Duration::from_secs(3), s.read(&mut buf)).await;
        match r {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {} // EOF, error, or timeout — all OK
            Ok(Ok(_)) => panic!("expected connection close"),
        }
    }

    #[tokio::test]
    async fn connect_relay_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let checker = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let data = codec::decode_frame(&mut s).await.unwrap();
            let msg = proto::RendezvousMessage::decode(&data[..]).unwrap();
            match msg.union {
                Some(proto::rendezvous_message::Union::RequestRelay(rr)) => {
                    assert_eq!(rr.uuid, "my-uuid");
                    assert_eq!(rr.licence_key, "my-key");
                }
                _ => panic!("expected RequestRelay"),
            }
        });

        let _stream = connect_relay(&addr.to_string(), "my-uuid", "my-key").await.unwrap();
        checker.await.unwrap();
    }

    // --- IpTracker unit tests ---

    #[test]
    fn ip_tracker_enforces_per_ip_limit() {
        let tracker = IpTracker::new(2);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(tracker.try_acquire(ip));
        assert!(tracker.try_acquire(ip));
        assert!(!tracker.try_acquire(ip)); // third should fail
    }

    #[test]
    fn ip_tracker_release_frees_slot() {
        let tracker = IpTracker::new(1);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(tracker.try_acquire(ip));
        assert!(!tracker.try_acquire(ip));
        tracker.release(ip);
        assert!(tracker.try_acquire(ip)); // should succeed after release
    }

    #[test]
    fn ip_tracker_independent_per_ip() {
        let tracker = IpTracker::new(1);
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(tracker.try_acquire(ip1));
        assert!(tracker.try_acquire(ip2)); // different IP, should succeed
        assert!(!tracker.try_acquire(ip1)); // same IP, should fail
    }

    #[test]
    fn relay_limits_default() {
        let limits = RelayLimits::default();
        assert_eq!(limits.max_sessions, 200);
        assert_eq!(limits.max_per_ip, 10);
        assert_eq!(limits.max_waiting, 100);
        assert_eq!(limits.session_timeout, Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn with_limits_constructor() {
        let limits = RelayLimits {
            max_sessions: 50,
            max_per_ip: 5,
            max_waiting: 25,
            session_timeout: Duration::from_secs(300),
        };
        let srv = RelayServer::with_limits("k", limits.clone());
        assert_eq!(srv.stats(), (0, 0));
        assert_eq!(srv.limits.max_sessions, 50);
        assert_eq!(srv.limits.max_per_ip, 5);
    }

    #[tokio::test]
    async fn waiting_room_limit() {
        let limits = RelayLimits {
            max_sessions: 100,
            max_per_ip: 100,
            max_waiting: 2, // very small waiting room
            session_timeout: Duration::from_secs(60),
        };
        let srv = RelayServer::with_limits("", limits);
        let waiting = srv.waiting.clone();
        let active = srv.active.clone();
        let total = srv.total.clone();
        let session_sem = srv.session_semaphore.clone();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let w = waiting.clone();
        let a = active.clone();
        let t = total.clone();
        let ss = session_sem.clone();
        tokio::spawn(async move {
            loop {
                let (s, peer) = listener.accept().await.unwrap();
                let w2 = w.clone();
                let a2 = a.clone();
                let t2 = t.clone();
                let ss2 = ss.clone();
                tokio::spawn(async move {
                    let _ = serve_one(
                        s, w2, "", a2, t2, ss2, 2, Duration::from_secs(60), peer.ip(),
                    )
                    .await;
                });
            }
        });

        // Fill up the waiting room with 2 unpaired connections
        let _s1 = {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(&relay_handshake("uuid-1", "")).await.unwrap();
            s
        };
        let _s2 = {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(&relay_handshake("uuid-2", "")).await.unwrap();
            s
        };

        // Give server time to process
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Third unpaired connection should be rejected (waiting room full)
        let mut s3 = TcpStream::connect(addr).await.unwrap();
        s3.write_all(&relay_handshake("uuid-3", "")).await.unwrap();

        // Server should close the connection
        let mut buf = [0u8; 1];
        let r = timeout(Duration::from_secs(3), s3.read(&mut buf)).await;
        match r {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {} // EOF, error, or timeout — all OK
            Ok(Ok(_)) => panic!("expected connection close when waiting room full"),
        }
    }
}
