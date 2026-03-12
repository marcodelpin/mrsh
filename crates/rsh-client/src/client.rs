//! Core client — TLS connect, ed25519 auth, request/response.

use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine;
use rsh_core::{auth, protocol, tls, wire};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info};

/// Client version reported during auth.
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Capabilities advertised to server.
const CLIENT_CAPS: &[&str] = &["bin-patch", "shell", "self-update"];

/// Connected and authenticated client.
pub struct RshClient<S> {
    stream: S,
    pub server_version: Option<String>,
    pub server_caps: Vec<String>,
    pub mux_enabled: bool,
}

/// Connection options.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub host: String,
    pub port: u16,
    pub key_path: Option<String>,
    /// Username for password auth (when set, uses password auth instead of pubkey).
    pub password_user: Option<String>,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 8822,
            key_path: None,
            password_user: None,
        }
    }
}

/// The concrete client stream type (TLS over TCP).
pub type TlsClient = RshClient<tokio_rustls::client::TlsStream<TcpStream>>;

/// Connect and authenticate, returning a ready-to-use client.
pub async fn connect(opts: &ConnectOptions) -> Result<TlsClient> {
    let stream = tcp_connect(&opts.host, opts.port).await?;
    let tls_stream = tls_wrap(stream, &opts.host).await?;
    if let Some(ref user) = opts.password_user {
        auth_password(tls_stream, user, &opts.host).await
    } else {
        auth_client(tls_stream, &opts.key_path).await
    }
}

/// Connect and authenticate over an existing TCP stream (e.g. from relay).
pub async fn connect_over_stream(
    stream: TcpStream,
    server_name: &str,
    key_path: &Option<String>,
) -> Result<TlsClient> {
    let tls_stream = tls_wrap(stream, server_name).await?;
    auth_client(tls_stream, key_path).await
}

/// Password-based authentication.
///
/// Reads password from stdin (terminal: hidden prompt, piped: one line).
/// Sends auth request with type="password", receives AuthResult directly.
async fn auth_password<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    username: &str,
    host: &str,
) -> Result<RshClient<S>> {
    // Read password from stdin
    let password = read_password(username, host)?;

    let mut client = RshClient {
        stream,
        server_version: None,
        server_caps: Vec::new(),
        mux_enabled: false,
    };

    let auth_req = protocol::AuthRequest {
        auth_type: "password".to_string(),
        public_key: None,
        key_type: None,
        username: Some(username.to_string()),
        password: Some(password),
        version: Some(CLIENT_VERSION.to_string()),
        want_mux: None, // MUX channel protocol not yet implemented in Rust client
        caps: Some(CLIENT_CAPS.iter().map(|s| s.to_string()).collect()),
    };
    wire::send_json(&mut client.stream, &auth_req)
        .await
        .context("send password auth request")?;

    // Password auth: no challenge, direct result
    let result: protocol::AuthResult = wire::recv_json(&mut client.stream)
        .await
        .context("receive auth result")?;

    if !result.success {
        bail!(
            "password authentication failed: {}",
            result.error.unwrap_or_default()
        );
    }

    client.server_version = result.version.clone();
    client.server_caps = result.caps.unwrap_or_default();
    client.mux_enabled = result.mux_enabled.unwrap_or(false);
    info!(
        "authenticated via password (server: {})",
        result.version.as_deref().unwrap_or("unknown")
    );
    Ok(client)
}

/// Read password from terminal (hidden) or piped stdin (one line).
fn read_password(username: &str, host: &str) -> Result<String> {
    use std::io::{BufRead, Write};

    let stdin = std::io::stdin();
    if atty::is(atty::Stream::Stdin) {
        // Interactive terminal: show prompt, hide input
        eprint!("{}@{}'s password: ", username, host);
        std::io::stderr().flush().ok();
        let password = rpassword::read_password().context("read password from terminal")?;
        Ok(password)
    } else {
        // Piped/automated: read one line
        let mut line = String::new();
        stdin.lock().read_line(&mut line).context("read password from stdin")?;
        Ok(line.trim_end().to_string())
    }
}

/// Read TOTP code from terminal or piped stdin.
fn read_totp_code() -> Result<String> {
    use std::io::{BufRead, Write};

    let stdin = std::io::stdin();
    if atty::is(atty::Stream::Stdin) {
        eprint!("TOTP code: ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        stdin.lock().read_line(&mut line).context("read TOTP code")?;
        Ok(line.trim().to_string())
    } else {
        let mut line = String::new();
        stdin.lock().read_line(&mut line).context("read TOTP code from stdin")?;
        Ok(line.trim().to_string())
    }
}

/// Common auth logic for both direct and relay connections.
async fn auth_client<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    key_path: &Option<String>,
) -> Result<RshClient<S>> {
    let key_pair = if let Some(path) = key_path {
        auth::load_ssh_key(Path::new(path)).with_context(|| format!("load key: {}", path))?
    } else {
        auth::discover_key()
            .context("no SSH key found (tried ~/.ssh/id_ed25519 and ~/.ssh/id_*)")?
    };

    let mut client = RshClient {
        stream,
        server_version: None,
        server_caps: Vec::new(),
        mux_enabled: false,
    };

    client.authenticate(&key_pair).await?;
    Ok(client)
}

/// TCP connect with timeout.
async fn tcp_connect(host: &str, port: u16) -> Result<TcpStream> {
    let addr = format!("{}:{}", host, port);
    debug!("connecting to {}", addr);
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        TcpStream::connect(&addr),
    )
    .await
    .context("connection timed out")?
    .with_context(|| format!("connect to {}", addr))?;

    // Set TCP options
    stream.set_nodelay(true).ok();
    Ok(stream)
}

/// Wrap a TCP stream in TLS using TOFU (Trust-On-First-Use) verification.
async fn tls_wrap(
    stream: TcpStream,
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let config = tls::client_config_tofu(None);
    let connector = TlsConnector::from(config);
    let server_name =
        rustls::pki_types::ServerName::try_from(host.to_string()).unwrap_or_else(|_| {
            rustls::pki_types::ServerName::IpAddress(
                host.parse()
                    .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
                    .into(),
            )
        });
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .context("TLS handshake failed")?;
    debug!("TLS handshake complete");
    Ok(tls_stream)
}

impl<S> RshClient<S> {
    /// Create a client wrapping an existing stream (for crate-internal testing).
    #[cfg(test)]
    pub(crate) fn new_mock(stream: S) -> Self {
        RshClient {
            stream,
            server_version: Some("test-server".to_string()),
            server_caps: Vec::new(),
            mux_enabled: false,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> RshClient<S> {
    /// Authenticate using ed25519 challenge-response.
    async fn authenticate(&mut self, key_pair: &auth::SshKeyPair) -> Result<()> {
        // Step 1: Send AuthRequest
        // For ed25519: old protocol (raw 32-byte key, no key_type) for backward compat.
        // For other key types: new protocol (SSH wire format with key_type).
        let (pub_key_b64, key_type) = if key_pair.key_type == "ssh-ed25519" {
            // Old format: raw 32-byte ed25519 key (legacy compat)
            (key_pair.public_key_base64_raw(), None)
        } else {
            // New format: SSH wire format with key_type (v4.18+ servers)
            (key_pair.public_key_base64_raw(), Some(key_pair.key_type.clone()))
        };
        let auth_req = protocol::AuthRequest {
            auth_type: "auth".to_string(),
            public_key: Some(pub_key_b64),
            key_type,
            username: None,
            password: None,
            version: Some(CLIENT_VERSION.to_string()),
            want_mux: None, // MUX channel protocol not yet implemented in Rust client
            caps: Some(CLIENT_CAPS.iter().map(|s| s.to_string()).collect()),
        };
        wire::send_json(&mut self.stream, &auth_req)
            .await
            .context("send auth request")?;

        // Step 2: Receive challenge (or early AuthResult on error)
        let raw = wire::recv_message(&mut self.stream)
            .await
            .context("receive auth challenge")?;
        // Try as AuthChallenge first; if it fails, check for AuthResult (error)
        let challenge_bytes = if let Ok(challenge) =
            serde_json::from_slice::<protocol::AuthChallenge>(&raw)
        {
            base64::engine::general_purpose::STANDARD
                .decode(&challenge.challenge)
                .context("decode challenge")?
        } else if let Ok(result) = serde_json::from_slice::<protocol::AuthResult>(&raw) {
            bail!(
                "server rejected auth: {}",
                result.error.unwrap_or_else(|| "unknown error".into())
            );
        } else {
            bail!(
                "unexpected server response: {}",
                String::from_utf8_lossy(&raw)
            );
        };
        debug!("received challenge ({} bytes)", challenge_bytes.len());

        // Step 3: Sign and send response
        let signature = key_pair.sign_challenge(&challenge_bytes);
        let auth_resp = protocol::AuthResponse {
            signature: base64::engine::general_purpose::STANDARD.encode(&signature),
        };
        wire::send_json(&mut self.stream, &auth_resp)
            .await
            .context("send auth response")?;

        // Step 4: Receive next message — could be TotpChallenge or AuthResult
        let raw = wire::recv_message(&mut self.stream)
            .await
            .context("receive post-signature message")?;

        // Try as TotpChallenge first (server requires 2FA for this key)
        let result = if let Ok(totp_challenge) =
            serde_json::from_slice::<protocol::TotpChallenge>(&raw)
        {
            if totp_challenge.totp_required {
                debug!("server requires TOTP for this key");
                let code = read_totp_code()?;
                let totp_resp = protocol::TotpResponse { totp_code: code };
                wire::send_json(&mut self.stream, &totp_resp)
                    .await
                    .context("send TOTP response")?;

                // Now receive the actual AuthResult
                let totp_result: protocol::AuthResult =
                    wire::recv_json(&mut self.stream)
                        .await
                        .context("receive auth result after TOTP")?;
                totp_result
            } else {
                // totp_required=false shouldn't happen, but treat as AuthResult
                serde_json::from_slice::<protocol::AuthResult>(&raw)
                    .context("parse auth result")?
            }
        } else {
            // Not a TotpChallenge — must be AuthResult
            serde_json::from_slice::<protocol::AuthResult>(&raw)
                .context("parse auth result")?
        };

        if !result.success {
            bail!(
                "authentication failed: {}",
                result.error.unwrap_or_default()
            );
        }

        self.server_version = result.version.clone();
        self.server_caps = result.caps.unwrap_or_default();
        self.mux_enabled = result.mux_enabled.unwrap_or(false);
        info!(
            "authenticated (server: {}{})",
            result.version.as_deref().unwrap_or("unknown"),
            if self.mux_enabled { ", mux" } else { "" }
        );
        Ok(())
    }

    /// Send a request and receive the response.
    pub async fn request(&mut self, req: &protocol::Request) -> Result<protocol::Response> {
        wire::send_json(&mut self.stream, req)
            .await
            .context("send request")?;
        let resp: protocol::Response = wire::recv_json(&mut self.stream)
            .await
            .context("receive response")?;
        Ok(resp)
    }

    /// Get mutable access to the underlying stream (for hijack commands).
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consume client, returning the stream (for hijack commands).
    pub fn into_stream(self) -> S {
        self.stream
    }
}

/// Build a simple request with just a type.
pub fn simple_request(req_type: &str) -> protocol::Request {
    protocol::Request {
        req_type: req_type.to_string(),
        command: None,
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_options_default() {
        let opts = ConnectOptions::default();
        assert_eq!(opts.port, 8822);
        assert!(opts.host.is_empty());
        assert!(opts.key_path.is_none());
    }

    #[test]
    fn simple_request_creates_correct_type() {
        let req = simple_request("ping");
        assert_eq!(req.req_type, "ping");
        assert!(req.command.is_none());
    }

    #[test]
    fn client_version_is_set() {
        assert!(!CLIENT_VERSION.is_empty());
    }

    #[test]
    fn client_caps_include_essentials() {
        assert!(CLIENT_CAPS.contains(&"shell"));
        assert!(CLIENT_CAPS.contains(&"self-update"));
    }

    #[tokio::test]
    async fn tcp_connect_refuses_bad_port() {
        let result = tcp_connect("127.0.0.1", 1).await;
        assert!(result.is_err());
    }

    /// connect_over_stream takes an existing TcpStream and wraps in TLS.
    /// Verifies the relay path: stream is reused (no TCP dial), TLS attempted.
    /// Error should be a TLS/IO error, NOT a TCP connect error.
    #[tokio::test]
    async fn connect_over_stream_uses_provided_stream() {
        use tokio::net::TcpListener;

        // Bind a listener; spawn a task that accepts + immediately drops
        // (sends TCP FIN), causing the TLS handshake to fail with EOF quickly.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await; // accept then drop → sends FIN
        });

        let stream = TcpStream::connect(addr).await.unwrap();

        // connect_over_stream wraps the stream in TLS then authenticates.
        // Expect TLS handshake EOF (not connect refused).
        let result = connect_over_stream(stream, "127.0.0.1", &None).await;
        let err = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected TLS/auth error"),
        };
        assert!(
            !err.contains("Connection refused"),
            "expected TLS/IO error, got connect-refused: {err}"
        );
    }

    /// connect_over_stream with explicit bad key path returns an error.
    #[tokio::test]
    async fn connect_over_stream_bad_key_path_errors() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = TcpStream::connect(addr).await.unwrap();

        let bad_key = Some("/nonexistent/path/to/key".to_string());
        let result = connect_over_stream(stream, "127.0.0.1", &bad_key).await;
        // Either key-load fails (if checked before TLS) or TLS fails first.
        assert!(result.is_err(), "expected error from bad key/no-server");
    }
}
