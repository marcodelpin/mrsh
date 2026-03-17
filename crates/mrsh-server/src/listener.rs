//! TCP/TLS listener with protocol multiplexing.
//! Command port: raw TCP → peek first byte (0x16 = TLS, else reject).
//! Stream port (port+1): direct TLS for push/pull file transfers.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::handler::{self, ServerContext};

/// IP-based access control — allow list or deny list.
/// If an allow list is set, only listed IPs/subnets can connect.
/// If a deny list is set, listed IPs/subnets are blocked.
/// If both are empty, all IPs are allowed (default open).
#[derive(Clone, Debug)]
pub struct IpAccessControl {
    /// If non-empty, only these IPs/subnets may connect (whitelist mode).
    allow: Vec<IpNet>,
    /// If non-empty, these IPs/subnets are blocked (blacklist mode).
    deny: Vec<IpNet>,
}

/// An IP network: either a single address or a CIDR subnet.
#[derive(Clone, Debug)]
enum IpNet {
    Single(IpAddr),
    Cidr { network: IpAddr, prefix_len: u8 },
}

impl IpNet {
    /// Parse "1.2.3.4", "10.0.0.0/8", "::1", "fd00::/8"
    fn parse(s: &str) -> Option<Self> {
        if let Some((net_str, prefix_str)) = s.split_once('/') {
            let network: IpAddr = net_str.parse().ok()?;
            let prefix_len: u8 = prefix_str.parse().ok()?;
            // Validate prefix length
            let max_prefix = if network.is_ipv4() { 32 } else { 128 };
            if prefix_len > max_prefix {
                return None;
            }
            Some(IpNet::Cidr {
                network,
                prefix_len,
            })
        } else {
            let addr: IpAddr = s.parse().ok()?;
            Some(IpNet::Single(addr))
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match self {
            IpNet::Single(addr) => *addr == ip,
            IpNet::Cidr {
                network,
                prefix_len,
            } => {
                // Compare the first prefix_len bits
                match (network, ip) {
                    (IpAddr::V4(net), IpAddr::V4(addr)) => {
                        if *prefix_len == 0 {
                            return true;
                        }
                        let mask = u32::MAX.checked_shl(32 - *prefix_len as u32).unwrap_or(0);
                        (u32::from(*net) & mask) == (u32::from(addr) & mask)
                    }
                    (IpAddr::V6(net), IpAddr::V6(addr)) => {
                        if *prefix_len == 0 {
                            return true;
                        }
                        let mask = u128::MAX.checked_shl(128 - *prefix_len as u32).unwrap_or(0);
                        (u128::from(*net) & mask) == (u128::from(addr) & mask)
                    }
                    _ => false, // v4 vs v6 mismatch
                }
            }
        }
    }
}

impl IpAccessControl {
    /// Create from allow/deny lists. Each entry is "IP" or "IP/prefix".
    pub fn new(allow_entries: &[String], deny_entries: &[String]) -> Self {
        let allow = allow_entries
            .iter()
            .filter_map(|s| {
                let parsed = IpNet::parse(s.trim());
                if parsed.is_none() {
                    tracing::warn!("invalid IP ACL entry (allow): {}", s);
                }
                parsed
            })
            .collect();
        let deny = deny_entries
            .iter()
            .filter_map(|s| {
                let parsed = IpNet::parse(s.trim());
                if parsed.is_none() {
                    tracing::warn!("invalid IP ACL entry (deny): {}", s);
                }
                parsed
            })
            .collect();
        Self { allow, deny }
    }

    /// Default: no restrictions.
    pub fn allow_all() -> Self {
        Self {
            allow: vec![],
            deny: vec![],
        }
    }

    /// Check if an IP is allowed to connect.
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        // Deny list takes precedence
        if !self.deny.is_empty() && self.deny.iter().any(|net| net.contains(ip)) {
            return false;
        }
        // Allow list: if set, IP must match
        if !self.allow.is_empty() {
            return self.allow.iter().any(|net| net.contains(ip));
        }
        true // default open
    }
}

/// OpenSSH-style MaxStartups configuration for probabilistic connection limiting.
/// When active connections exceed `start`, new connections are dropped with
/// probability that linearly increases from `rate`% at `start` to 100% at `full`.
#[derive(Clone, Debug)]
pub struct MaxStartups {
    /// Connections below this threshold are always accepted.
    pub start: usize,
    /// Base drop probability (percent, 0-100) once `start` is exceeded.
    pub rate: u8,
    /// At this many connections, 100% of new connections are dropped.
    pub full: usize,
}

impl Default for MaxStartups {
    fn default() -> Self {
        // OpenSSH default: 10:30:100
        Self {
            start: 10,
            rate: 30,
            full: 100,
        }
    }
}

/// Global + per-IP connection limiter to prevent resource exhaustion.
/// Includes OpenSSH-style MaxStartups probabilistic drop.
#[derive(Clone)]
pub struct ConnectionLimiter {
    global: Arc<Semaphore>,
    per_ip: Arc<std::sync::Mutex<HashMap<IpAddr, usize>>>,
    max_per_ip: usize,
    max_startups: MaxStartups,
}

impl ConnectionLimiter {
    pub fn new(max_global: usize, max_per_ip: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(max_global)),
            per_ip: Arc::new(std::sync::Mutex::new(HashMap::new())),
            max_per_ip,
            max_startups: MaxStartups::default(),
        }
    }

    /// Create limiter with custom MaxStartups configuration.
    pub fn with_max_startups(
        max_global: usize,
        max_per_ip: usize,
        max_startups: MaxStartups,
    ) -> Self {
        Self {
            global: Arc::new(Semaphore::new(max_global)),
            per_ip: Arc::new(std::sync::Mutex::new(HashMap::new())),
            max_per_ip,
            max_startups,
        }
    }

    /// Current number of active connections (counted from per-IP map).
    fn active_connections(&self) -> usize {
        self.per_ip.lock().unwrap().values().sum()
    }

    /// Check MaxStartups probabilistic drop. Returns true if connection should be dropped.
    fn should_drop_probabilistic(&self) -> bool {
        let current = self.active_connections();
        let ms = &self.max_startups;

        if current < ms.start {
            return false; // below threshold, always accept
        }
        if current >= ms.full {
            return true; // at or above full, always drop
        }

        // Linear interpolation: drop probability increases from rate% at start to 100% at full
        // drop_pct = rate + (100 - rate) * (current - start) / (full - start)
        let range = ms.full - ms.start;
        if range == 0 {
            return true;
        }
        let excess = current - ms.start;
        let drop_pct = ms.rate as usize + (100 - ms.rate as usize) * excess / range;

        // Random check
        let random_val = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            std::time::Instant::now().hash(&mut hasher);
            std::thread::current().id().hash(&mut hasher);
            (hasher.finish() % 100) as usize
        };

        random_val < drop_pct
    }

    /// Try to acquire a connection permit. Returns None if limits exceeded.
    pub fn try_acquire(&self, ip: IpAddr) -> Option<ConnectionPermit> {
        // MaxStartups probabilistic drop check (before acquiring any resources)
        if self.should_drop_probabilistic() {
            return None;
        }

        // Check global limit
        let global_permit = self.global.clone().try_acquire_owned().ok()?;

        // Check per-IP limit
        let mut per_ip = self.per_ip.lock().unwrap();
        let count = per_ip.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            drop(global_permit); // release global permit
            return None;
        }
        *count += 1;

        Some(ConnectionPermit {
            _global_permit: global_permit,
            per_ip: self.per_ip.clone(),
            ip,
        })
    }
}

/// RAII guard — decrements counters when connection drops.
pub struct ConnectionPermit {
    _global_permit: tokio::sync::OwnedSemaphorePermit,
    per_ip: Arc<std::sync::Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut per_ip = self.per_ip.lock().unwrap();
        if let Some(count) = per_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                per_ip.remove(&self.ip);
            }
        }
    }
}

/// Bind a TCP listener with `SO_REUSEADDR` so we can rebind over zombie sockets
/// left behind by a crashed process (Windows doesn't auto-clean TIME_WAIT/orphaned sockets).
async fn bind_reusable(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    TcpListener::from_std(socket.into())
}

/// A stream that prepends a single peeked byte before the underlying stream.
/// Used after protocol detection to replay the first byte into TLS handshake.
struct PeekStream {
    peeked: Option<u8>,
    inner: TcpStream,
}

impl PeekStream {
    fn new(byte: u8, inner: TcpStream) -> Self {
        Self {
            peeked: Some(byte),
            inner,
        }
    }
}

impl AsyncRead for PeekStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(byte) = self.peeked.take() {
            buf.put_slice(&[byte]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PeekStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Run the command port listener with protocol multiplexing.
/// Accepts raw TCP, peeks first byte:
///   0x16 → TLS ClientHello → wrap in TLS → authenticate + dispatch
///   else → close connection
pub async fn run_command_listener(
    addr: SocketAddr,
    tls_acceptor: TlsAcceptor,
    ctx: Arc<ServerContext>,
    conn_limiter: ConnectionLimiter,
    ip_acl: IpAccessControl,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let listener = bind_reusable(addr)
        .await
        .context(format!("bind command port {}", addr))?;
    info!("command listener on {}", addr);

    loop {
        let (stream, peer) = tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok(v) => v,
                    Err(e) => {
                        error!("accept error: {}", e);
                        continue;
                    }
                }
            }
            _ = cancel.cancelled() => {
                info!("command listener shutting down");
                return Ok(());
            }
        };

        // Check IP access control before anything else
        if !ip_acl.is_allowed(peer.ip()) {
            debug!("IP {} blocked by access control", peer.ip());
            continue;
        }

        // Check connection limits before spawning
        let permit = match conn_limiter.try_acquire(peer.ip()) {
            Some(p) => p,
            None => {
                warn!("connection limit reached for {}, rejecting", peer.ip());
                continue;
            }
        };

        stream.set_nodelay(true).ok();
        let acceptor = tls_acceptor.clone();
        let ctx = ctx.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            let _permit = permit; // hold until connection ends
            if let Err(e) = handle_mux_connection(stream, peer, acceptor, &ctx, cancel).await {
                debug!("connection {} error: {}", peer, e);
            }
        });
    }
}

/// Handle a single multiplexed connection: peek → TLS → auth → dispatch.
async fn handle_mux_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    ctx: &ServerContext,
    _cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    use tokio::io::AsyncReadExt;
    use tokio::time::{Duration, timeout};

    // Peek first byte with 30s deadline
    let mut buf = [0u8; 1];
    let n = timeout(Duration::from_secs(30), stream.read(&mut buf))
        .await
        .context("peek timeout")?
        .context("peek read")?;

    if n == 0 {
        return Ok(()); // client disconnected
    }

    match buf[0] {
        0x16 => {
            // TLS ClientHello — wrap stream with peeked byte replayed
            let peek_stream = PeekStream::new(buf[0], stream);
            let tls_stream = acceptor
                .accept(peek_stream)
                .await
                .context("TLS handshake")?;

            debug!("TLS connection from {}", peer);
            handler::handle_connection(tls_stream, ctx, Some(peer)).await?;
        }
        other => {
            warn!("unknown protocol byte 0x{:02x} from {}", other, peer);
            // Close connection — SSH mux not implemented yet
        }
    }

    Ok(())
}

/// Run the stream port listener (direct TLS, no protocol mux).
/// Used for push/pull file transfers on port+1.
pub async fn run_stream_listener(
    addr: SocketAddr,
    tls_acceptor: TlsAcceptor,
    ctx: Arc<ServerContext>,
    conn_limiter: ConnectionLimiter,
    ip_acl: IpAccessControl,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let listener = bind_reusable(addr)
        .await
        .context(format!("bind stream port {}", addr))?;
    info!("stream listener on {}", addr);

    loop {
        let (stream, peer) = tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok(v) => v,
                    Err(e) => {
                        error!("stream accept error: {}", e);
                        continue;
                    }
                }
            }
            _ = cancel.cancelled() => {
                info!("stream listener shutting down");
                return Ok(());
            }
        };

        // Check IP access control before anything else
        if !ip_acl.is_allowed(peer.ip()) {
            debug!("stream IP {} blocked by access control", peer.ip());
            continue;
        }

        // Check connection limits before spawning
        let permit = match conn_limiter.try_acquire(peer.ip()) {
            Some(p) => p,
            None => {
                warn!("stream connection limit reached for {}, rejecting", peer.ip());
                continue;
            }
        };

        stream.set_nodelay(true).ok();
        let acceptor = tls_acceptor.clone();
        let ctx = ctx.clone();

        tokio::spawn(async move {
            let _permit = permit; // hold until connection ends
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    debug!("stream connection from {}", peer);
                    if let Err(e) = handler::handle_connection(tls_stream, &ctx, Some(peer)).await {
                        debug!("stream {} error: {}", peer, e);
                    }
                }
                Err(e) => {
                    debug!("stream TLS handshake {} failed: {}", peer, e);
                }
            }
        });
    }
}

/// Server startup configuration.
pub struct ServerConfig {
    pub command_port: u16,
    pub tls_acceptor: TlsAcceptor,
    pub ctx: Arc<ServerContext>,
    pub ip_acl: IpAccessControl,
    /// Raw TLS config for QUIC (QUIC needs rustls ServerConfig, not TlsAcceptor).
    #[cfg(feature = "quic")]
    pub tls_config: Arc<rustls::ServerConfig>,
}

/// Start all server listeners and block until shutdown.
pub async fn run_server(
    config: ServerConfig,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let command_addr: SocketAddr = ([0, 0, 0, 0], config.command_port).into();
    let stream_addr: SocketAddr = ([0, 0, 0, 0], config.command_port + 1).into();

    let conn_limiter = ConnectionLimiter::new(500, 20);
    let mut tasks = tokio::task::JoinSet::new();

    // Command listener
    {
        let acceptor = config.tls_acceptor.clone();
        let ctx = config.ctx.clone();
        let limiter = conn_limiter.clone();
        let acl = config.ip_acl.clone();
        let cancel = cancel.clone();
        tasks.spawn(async move {
            run_command_listener(command_addr, acceptor, ctx, limiter, acl, cancel).await
        });
    }

    // Stream listener
    {
        let acceptor = config.tls_acceptor.clone();
        let ctx = config.ctx.clone();
        let limiter = conn_limiter.clone();
        let acl = config.ip_acl.clone();
        let cancel = cancel.clone();
        tasks.spawn(async move {
            run_stream_listener(stream_addr, acceptor, ctx, limiter, acl, cancel).await
        });
    }

    // QUIC listener (same command port, UDP)
    #[cfg(feature = "quic")]
    {
        let quic_port = config.command_port;
        let tls_config = config.tls_config.clone();
        let ctx = config.ctx.clone();
        let cancel = cancel.clone();
        tasks.spawn(async move {
            crate::quic::start_quic_listener(quic_port, tls_config, ctx, cancel).await
        });
    }

    info!(
        "server running: command={}, stream={}{}",
        command_addr,
        stream_addr,
        if cfg!(feature = "quic") { ", quic=enabled" } else { "" }
    );

    // Wait for all listeners to finish (they exit on cancel)
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!("listener error: {}", e),
            Err(e) => error!("listener task panic: {}", e),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrsh_core::{auth, tls};

    fn make_test_server() -> (TlsAcceptor, Arc<ServerContext>, Arc<rustls::ServerConfig>) {
        let (certs, key) =
            tls::load_or_generate_cert(&std::env::temp_dir().join("rsh-listener-test")).unwrap();
        let tls_config = tls::server_config(certs, key).unwrap();
        let tls_config_clone = tls_config.clone();
        let acceptor = TlsAcceptor::from(tls_config);

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let ak = auth::AuthorizedKey {
            key_type: "ssh-ed25519".to_string(),
            key_data: pub_bytes.to_vec(),
            comment: Some("test".to_string()),
            permissions: auth::KeyPermissions::default(),
        };

        let ctx = Arc::new(ServerContext {
            authorized_keys: vec![ak],
            revoked_keys: std::collections::HashSet::new(),
            server_version: "test".to_string(),
            banner: None,
            caps: vec![],
            session_store: crate::session::SessionStore::new(),
            rate_limiter: crate::ratelimit::AuthRateLimiter::new(),
            allowed_tunnels: vec![],
            totp_secrets: vec![],
            totp_recovery_path: None,
        });

        (acceptor, ctx, tls_config_clone)
    }

    #[tokio::test]
    async fn command_listener_accepts_and_cancels() {
        let (acceptor, ctx, _tls_config) = make_test_server();
        let cancel = tokio_util::sync::CancellationToken::new();

        // Bind to random port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener); // free port

        let limiter = ConnectionLimiter::new(500, 20);
        let acl = IpAccessControl::allow_all();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            run_command_listener(addr, acceptor, ctx, limiter, acl, cancel_clone).await
        });

        // Give listener time to bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect with unknown protocol byte → should be rejected
        let mut stream = TcpStream::connect(addr).await.unwrap();
        use tokio::io::AsyncWriteExt;
        stream.write_all(b"X").await.unwrap();
        // Server closes connection for unknown protocol
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Cancel and wait
        cancel.cancel();
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn command_listener_tls_handshake() {
        let (acceptor, ctx, _tls_config) = make_test_server();
        let cancel = tokio_util::sync::CancellationToken::new();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let limiter = ConnectionLimiter::new(500, 20);
        let acl = IpAccessControl::allow_all();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            run_command_listener(addr, acceptor, ctx, limiter, acl, cancel_clone).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect with TLS client
        let client_config = tls::client_config();
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let stream = TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls_stream = connector.connect(server_name, stream).await;

        // TLS handshake should succeed (auth will fail since we don't complete it)
        assert!(tls_stream.is_ok());

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn stream_listener_accepts_tls() {
        let (acceptor, ctx, _tls_config) = make_test_server();
        let cancel = tokio_util::sync::CancellationToken::new();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let limiter = ConnectionLimiter::new(500, 20);
        let acl = IpAccessControl::allow_all();
        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            run_stream_listener(addr, acceptor, ctx, limiter, acl, cancel_clone).await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect with TLS
        let client_config = tls::client_config();
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let stream = TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls_stream = connector.connect(server_name, stream).await;
        assert!(tls_stream.is_ok());

        cancel.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn run_server_starts_both_listeners() {
        let (acceptor, ctx, _tls_config) = make_test_server();
        let cancel = tokio_util::sync::CancellationToken::new();

        // Find two consecutive free ports
        let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l1.local_addr().unwrap().port();
        drop(l1);

        let config = ServerConfig {
            command_port: port,
            tls_acceptor: acceptor,
            ctx,
            ip_acl: IpAccessControl::allow_all(),
            #[cfg(feature = "quic")]
            tls_config: _tls_config,
        };

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { run_server(config, cancel_clone).await });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Both ports should be accepting connections
        let cmd_conn = TcpStream::connect(format!("127.0.0.1:{}", port)).await;
        assert!(cmd_conn.is_ok(), "command port should be open");

        let stream_conn = TcpStream::connect(format!("127.0.0.1:{}", port + 1)).await;
        assert!(stream_conn.is_ok(), "stream port should be open");

        cancel.cancel();
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }

    /// Regression test for solved/002 — dual-port resilience.
    /// Protocol mux on same port prevents port-replacement structurally,
    /// but we verify that non-TLS connections (e.g. SSH byte 0x53) don't crash the server
    /// and both ports remain functional afterward.
    #[tokio::test]
    async fn dual_port_survives_non_tls_connections() {
        let (acceptor, ctx, _tls_config) = make_test_server();
        let cancel = tokio_util::sync::CancellationToken::new();

        let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l1.local_addr().unwrap().port();
        drop(l1);

        let config = ServerConfig {
            command_port: port,
            tls_acceptor: acceptor,
            ctx,
            ip_acl: IpAccessControl::allow_all(),
            #[cfg(feature = "quic")]
            tls_config: _tls_config,
        };

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move { run_server(config, cancel_clone).await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Send SSH protocol byte (0x53 = 'S') to command port — should be rejected gracefully
        {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();
            use tokio::io::AsyncWriteExt;
            stream.write_all(&[0x53]).await.unwrap(); // SSH-2.0 first byte
            drop(stream);
        }

        // Send garbage bytes to command port
        {
            let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();
            use tokio::io::AsyncWriteExt;
            stream.write_all(b"\xff\xfe\x00").await.unwrap();
            drop(stream);
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Both ports must still be functional
        let cmd_conn = TcpStream::connect(format!("127.0.0.1:{}", port)).await;
        assert!(cmd_conn.is_ok(), "command port must survive non-TLS connections");

        let stream_conn = TcpStream::connect(format!("127.0.0.1:{}", port + 1)).await;
        assert!(stream_conn.is_ok(), "stream port must be unaffected by command port abuse");

        // TLS handshake on command port still works
        let client_config = tls::client_config();
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let tcp = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls_result = connector.connect(server_name, tcp).await;
        assert!(tls_result.is_ok(), "TLS must still work after non-TLS abuse");

        cancel.cancel();
        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn connection_limiter_basic() {
        let limiter = ConnectionLimiter::new(500, 20);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let permit = limiter.try_acquire(ip);
        assert!(permit.is_some());
        drop(permit);
    }

    #[test]
    fn connection_limiter_per_ip_limit() {
        let limiter = ConnectionLimiter::new(500, 3);
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        let mut permits = Vec::new();
        for _ in 0..3 {
            permits.push(limiter.try_acquire(ip).unwrap());
        }
        // Next should fail
        assert!(limiter.try_acquire(ip).is_none());
        // Different IP still works
        let ip2: IpAddr = "10.0.0.3".parse().unwrap();
        assert!(limiter.try_acquire(ip2).is_some());
    }

    #[test]
    fn connection_limiter_global_limit() {
        let limiter = ConnectionLimiter::new(2, 20);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();
        let _p1 = limiter.try_acquire(ip1).unwrap();
        let _p2 = limiter.try_acquire(ip2).unwrap();
        // Global limit reached
        assert!(limiter.try_acquire(ip3).is_none());
    }

    #[test]
    fn connection_limiter_release_on_drop() {
        let limiter = ConnectionLimiter::new(500, 20);
        let ip: IpAddr = "10.0.0.4".parse().unwrap();
        {
            let _permit = limiter.try_acquire(ip).unwrap();
        }
        // Permit dropped — can acquire again
        assert!(limiter.try_acquire(ip).is_some());
    }

    // --- IpAccessControl unit tests ---

    #[test]
    fn ip_acl_allow_all_by_default() {
        let acl = IpAccessControl::allow_all();
        assert!(acl.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(acl.is_allowed("::1".parse().unwrap()));
    }

    #[test]
    fn ip_acl_allowlist_blocks_unlisted() {
        let acl = IpAccessControl::new(
            &["192.168.1.0/24".to_string(), "10.0.0.5".to_string()],
            &[],
        );
        assert!(acl.is_allowed("192.168.1.100".parse().unwrap()));
        assert!(acl.is_allowed("10.0.0.5".parse().unwrap()));
        assert!(!acl.is_allowed("10.0.0.6".parse().unwrap()));
        assert!(!acl.is_allowed("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn ip_acl_denylist_blocks_listed() {
        let acl = IpAccessControl::new(
            &[],
            &["10.0.0.0/8".to_string(), "192.168.1.99".to_string()],
        );
        assert!(!acl.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(!acl.is_allowed("10.255.255.255".parse().unwrap()));
        assert!(!acl.is_allowed("192.168.1.99".parse().unwrap()));
        assert!(acl.is_allowed("192.168.1.100".parse().unwrap()));
        assert!(acl.is_allowed("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn ip_acl_deny_takes_precedence() {
        // IP is in both allow and deny — deny wins
        let acl = IpAccessControl::new(
            &["10.0.0.0/8".to_string()],
            &["10.0.0.5".to_string()],
        );
        assert!(acl.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(!acl.is_allowed("10.0.0.5".parse().unwrap())); // deny wins
    }

    #[test]
    fn ip_acl_cidr_ipv6() {
        let acl = IpAccessControl::new(
            &["fd00::/8".to_string()],
            &[],
        );
        assert!(acl.is_allowed("fd00::1".parse().unwrap()));
        assert!(acl.is_allowed("fdff::1".parse().unwrap()));
        assert!(!acl.is_allowed("fe80::1".parse().unwrap()));
    }

    #[test]
    fn ipnet_parse_invalid() {
        assert!(IpNet::parse("not-an-ip").is_none());
        assert!(IpNet::parse("10.0.0.1/33").is_none()); // prefix too large
        assert!(IpNet::parse("10.0.0.1/abc").is_none());
    }

    // --- MaxStartups tests ---

    #[test]
    fn max_startups_below_threshold_always_accepts() {
        // start=5, rate=30, full=10 — below 5 connections always accepted
        let limiter = ConnectionLimiter::with_max_startups(
            100,
            20,
            MaxStartups {
                start: 5,
                rate: 30,
                full: 10,
            },
        );
        let mut permits = Vec::new();
        // Acquire 4 connections (below start=5) — all must succeed
        for i in 0..4 {
            let ip: IpAddr = format!("10.0.0.{}", i + 1).parse().unwrap();
            let permit = limiter.try_acquire(ip);
            assert!(permit.is_some(), "connection {} should be accepted below start threshold", i);
            permits.push(permit.unwrap());
        }
    }

    #[test]
    fn max_startups_at_full_always_rejects() {
        // start=2, rate=30, full=5 — at 5+ connections, always reject
        let limiter = ConnectionLimiter::with_max_startups(
            100,
            20,
            MaxStartups {
                start: 2,
                rate: 30,
                full: 5,
            },
        );
        let mut permits = Vec::new();
        // Fill to 'full' threshold (5 connections)
        for i in 0..5 {
            let ip: IpAddr = format!("10.0.0.{}", i + 1).parse().unwrap();
            // Bypass probabilistic check by acquiring directly
            let per_ip = limiter.per_ip.clone();
            let mut map = per_ip.lock().unwrap();
            *map.entry(ip).or_insert(0) += 1;
            drop(map);
            let global = limiter.global.clone().try_acquire_owned().ok().unwrap();
            permits.push(ConnectionPermit {
                _global_permit: global,
                per_ip: limiter.per_ip.clone(),
                ip,
            });
        }
        // Now at 5 connections (= full), should always drop
        let ip: IpAddr = "10.0.0.99".parse().unwrap();
        // Try many times — all should be rejected since we're at full
        let mut all_rejected = true;
        for _ in 0..20 {
            if limiter.try_acquire(ip).is_some() {
                all_rejected = false;
                break;
            }
        }
        assert!(all_rejected, "at full threshold, all connections should be rejected");
    }

    #[test]
    fn max_startups_probabilistic_between_start_and_full() {
        // start=0, rate=50, full=100 — with 0 connections, drop rate starts at 50%
        // This tests that the probabilistic range works (some accept, some reject)
        let limiter = ConnectionLimiter::with_max_startups(
            1000,
            100,
            MaxStartups {
                start: 0,
                rate: 50,
                full: 100,
            },
        );
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mut accepted = 0;
        let mut rejected = 0;
        for _ in 0..100 {
            match limiter.try_acquire(ip) {
                Some(permit) => {
                    accepted += 1;
                    drop(permit); // release immediately so per-IP doesn't fill
                }
                None => rejected += 1,
            }
        }
        // With 50% rate at 0 connections, we expect roughly half accepted
        // Allow wide margin for randomness
        assert!(accepted > 10, "should accept some connections (got {})", accepted);
        assert!(rejected > 10, "should reject some connections (got {})", rejected);
    }

    #[test]
    fn max_startups_default_values() {
        let ms = MaxStartups::default();
        assert_eq!(ms.start, 10);
        assert_eq!(ms.rate, 30);
        assert_eq!(ms.full, 100);
    }
}
