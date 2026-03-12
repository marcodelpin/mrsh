//! SSH protocol detection and handling stub.
//!
//! Provides protocol-level detection of SSH connections (RFC 4253: "SSH-2.0-"
//! version string) and a stub handler that logs and closes gracefully.
//!
//! The SSH protocol is extremely complex (key exchange, encryption, channels,
//! multiplexing). This module defines the structures and entry points needed
//! for future implementation without pulling in a full SSH library.
//!
//! # Feature gate
//!
//! This module is compiled only when the `ssh` feature is enabled.
//!
//! # Architecture
//!
//! When SSH support is eventually implemented, the flow will be:
//!
//! 1. **Protocol detection** (`listener.rs`): first bytes == "SSH-" → route here
//! 2. **Version exchange**: send server version string, receive client version
//! 3. **Key exchange**: Diffie-Hellman (curve25519-sha256)
//! 4. **User authentication**: public key against same authorized_keys as TLS
//! 5. **Channel multiplexing**: session, direct-tcpip, forwarded-tcpip
//! 6. **Session requests**: pty-req → ConPTY, exec → PowerShell, shell, env,
//!    window-change, subsystem (sftp)
//! 7. **Port forwarding**: direct-tcpip (ssh -L), tcpip-forward (ssh -R)
//! 8. **Agent forwarding**: auth-agent@openssh.com channel
//! 9. **Exit status**: report process exit code to client

use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{info, warn};

use crate::handler::ServerContext;

// ---------------------------------------------------------------------------
// SSH protocol constants (RFC 4253 / RFC 4254)
// ---------------------------------------------------------------------------

/// SSH version identification string sent by this server.
const SERVER_VERSION: &str = "SSH-2.0-rsh_5.1";

/// SSH protocol magic prefix for version exchange.
const SSH_VERSION_PREFIX: &[u8] = b"SSH-";

// ---------------------------------------------------------------------------
// SSH message types (RFC 4253, Section 12)
// ---------------------------------------------------------------------------

/// Transport layer messages.
#[allow(dead_code)]
#[repr(u8)]
enum SshMsgTransport {
    Disconnect = 1,
    Ignore = 2,
    Unimplemented = 3,
    Debug = 4,
    ServiceRequest = 5,
    ServiceAccept = 6,
    KexInit = 20,
    NewKeys = 21,
}

/// Diffie-Hellman key exchange messages.
#[allow(dead_code)]
#[repr(u8)]
enum SshMsgKex {
    DhInit = 30,
    DhReply = 31,
}

/// User authentication messages (RFC 4252).
#[allow(dead_code)]
#[repr(u8)]
enum SshMsgAuth {
    Request = 50,
    Failure = 51,
    Success = 52,
    Banner = 53,
    PkOk = 60,
}

/// Connection protocol messages (RFC 4254).
#[allow(dead_code)]
#[repr(u8)]
enum SshMsgConnection {
    GlobalRequest = 80,
    RequestSuccess = 81,
    RequestFailure = 82,
    ChannelOpen = 90,
    ChannelOpenConfirmation = 91,
    ChannelOpenFailure = 92,
    ChannelWindowAdjust = 93,
    ChannelData = 94,
    ChannelExtendedData = 95,
    ChannelEof = 96,
    ChannelClose = 97,
    ChannelRequest = 98,
    ChannelSuccess = 99,
    ChannelFailure = 100,
}

// ---------------------------------------------------------------------------
// SSH disconnect reason codes (RFC 4253, Section 11.1)
// ---------------------------------------------------------------------------

/// Disconnect reason codes.
#[allow(dead_code)]
#[repr(u32)]
enum DisconnectReason {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    Reserved = 4,
    MacError = 5,
    CompressionError = 6,
    ServiceNotAvailable = 7,
    ProtocolVersionNotSupported = 8,
    HostKeyNotVerifiable = 9,
    ConnectionLost = 10,
    ByApplication = 11,
    TooManyConnections = 12,
    AuthCancelledByUser = 13,
    NoMoreAuthMethodsAvailable = 14,
    IllegalUserName = 15,
}

// ---------------------------------------------------------------------------
// SSH channel types
// ---------------------------------------------------------------------------

/// Channel types that the server would handle.
#[allow(dead_code)]
enum ChannelType {
    /// Interactive or exec session.
    Session,
    /// Local port forwarding (ssh -L): client opens channel to reach target.
    DirectTcpip,
    /// Remote port forwarding (ssh -R): server-initiated channel.
    ForwardedTcpip,
    /// Unix domain socket forwarding.
    DirectStreamLocal,
    /// Agent forwarding.
    AuthAgent,
}

// ---------------------------------------------------------------------------
// SSH session request types
// ---------------------------------------------------------------------------

/// Session channel request types (RFC 4254, Section 6).
#[allow(dead_code)]
enum SessionRequest {
    /// Allocate a pseudo-terminal (pty-req).
    PtyReq,
    /// Start an interactive shell.
    Shell,
    /// Execute a single command.
    Exec,
    /// Set environment variable.
    Env,
    /// Start a subsystem (e.g., sftp).
    Subsystem,
    /// Terminal window size changed.
    WindowChange,
    /// Send signal to remote process.
    Signal,
    /// Report exit status.
    ExitStatus,
    /// Report exit due to signal.
    ExitSignal,
}

// ---------------------------------------------------------------------------
// SSH key options (authorized_keys)
// ---------------------------------------------------------------------------

/// Options that can be set per-key in authorized_keys.
#[allow(dead_code)]
struct KeyOptions {
    /// Force a specific command (command="...").
    forced_command: Option<String>,
    /// Disable port forwarding (no-port-forwarding).
    no_port_forwarding: bool,
    /// Disable agent forwarding (no-agent-forwarding).
    no_agent_forwarding: bool,
    /// Disable PTY allocation (no-pty).
    no_pty: bool,
    /// Set environment variables (environment="KEY=VALUE").
    environment: Vec<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check if the first bytes of a connection look like an SSH handshake.
///
/// SSH connections start with the version string "SSH-2.0-..." (RFC 4253, Section 4.2).
/// This function checks for the "SSH-" prefix in the peeked bytes.
///
/// # Arguments
/// * `buf` - The first bytes read from the connection (at least 4 bytes needed).
///
/// # Returns
/// `true` if the bytes match the SSH version string prefix.
pub fn is_ssh_handshake(buf: &[u8]) -> bool {
    buf.len() >= SSH_VERSION_PREFIX.len() && buf.starts_with(SSH_VERSION_PREFIX)
}

/// Handle an SSH connection.
///
/// Currently this is a **stub** that:
/// 1. Sends the server's SSH version string
/// 2. Reads the client's version string
/// 3. Sends an SSH_MSG_DISCONNECT with reason "not yet implemented"
/// 4. Closes the connection cleanly
///
/// # TODO: Full implementation would require
/// - Key exchange (curve25519-sha256, diffie-hellman-group14-sha256)
/// - Encryption (chacha20-poly1305, aes256-gcm, aes128-ctr)
/// - MAC (hmac-sha2-256, hmac-sha2-512, implicit with AEAD)
/// - Public key authentication (ed25519, rsa-sha2-256, ssh certificates)
/// - Channel multiplexing (sessions, port forwarding, agent forwarding)
/// - ConPTY integration for pty-req (reuse shell.rs)
/// - PowerShell exec for non-PTY exec (reuse exec.rs)
/// - Tunnel handler for direct-tcpip (reuse tunnel.rs)
/// - SFTP subsystem
/// - Session recording integration
pub async fn handle_ssh_connection<S>(mut stream: S, ctx: Arc<ServerContext>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let _ = &ctx; // Will be used for authorized_keys, server key, etc.

    info!("SSH connection detected — sending version and disconnecting (not yet implemented)");

    // Step 1: Send server version string (RFC 4253, Section 4.2)
    // Format: "SSH-protoversion-softwareversion SP comments CR LF"
    let version_line = format!("{}\r\n", SERVER_VERSION);
    if let Err(e) = stream.write_all(version_line.as_bytes()).await {
        info!("SSH: client disconnected before version exchange: {}", e);
        return Ok(());
    }

    // Step 2: Read client version string (up to 255 chars, terminated by CR LF)
    // We read byte-by-byte to find the line terminator, with a size limit.
    let mut client_version = Vec::with_capacity(256);
    let mut buf = [0u8; 1];
    loop {
        use tokio::io::AsyncReadExt;
        match stream.read(&mut buf).await {
            Ok(0) => {
                info!("SSH: client disconnected before sending version");
                return Ok(());
            }
            Ok(_) => {
                client_version.push(buf[0]);
                // Check for CR LF terminator
                if client_version.len() >= 2
                    && client_version[client_version.len() - 2] == b'\r'
                    && client_version[client_version.len() - 1] == b'\n'
                {
                    break;
                }
                // RFC 4253: version string MUST be less than 256 characters
                if client_version.len() > 255 {
                    warn!("SSH: client version string too long");
                    return Ok(());
                }
            }
            Err(e) => {
                warn!("SSH: error reading client version: {}", e);
                return Ok(());
            }
        }
    }

    let client_version_str =
        String::from_utf8_lossy(&client_version[..client_version.len() - 2]); // strip CR LF
    info!("SSH: client version: {}", client_version_str);

    // Step 3: Send SSH_MSG_DISCONNECT
    // Format: byte SSH_MSG_DISCONNECT (1)
    //         uint32 reason code
    //         string description (UTF-8)
    //         string language tag
    let reason = DisconnectReason::ServiceNotAvailable as u32;
    let description = b"SSH protocol not yet implemented in rsh-rs server";
    let language = b"en";

    // Build disconnect message
    let mut disconnect_msg = Vec::with_capacity(1 + 4 + 4 + description.len() + 4 + language.len());
    disconnect_msg.push(SshMsgTransport::Disconnect as u8);
    disconnect_msg.extend_from_slice(&reason.to_be_bytes());
    // SSH string: uint32 length + data
    disconnect_msg.extend_from_slice(&(description.len() as u32).to_be_bytes());
    disconnect_msg.extend_from_slice(description);
    disconnect_msg.extend_from_slice(&(language.len() as u32).to_be_bytes());
    disconnect_msg.extend_from_slice(language);

    // Note: In a real SSH implementation, this message would be wrapped in the
    // binary packet protocol (RFC 4253, Section 6):
    //   uint32 packet_length
    //   byte   padding_length
    //   byte[n1] payload (the disconnect_msg above)
    //   byte[n2] random padding
    //   byte[m]  mac (if negotiated)
    //
    // Since we haven't completed key exchange, we can't send a proper SSH packet.
    // The client will see a malformed packet and disconnect, which is the intended
    // behavior for this stub. A well-behaved SSH client will interpret the
    // connection close as a server error after version exchange.

    // For now, just close the connection cleanly. The client already has our
    // version string, so it knows we're an SSH server. Since we don't send
    // SSH_MSG_KEXINIT, the client will timeout or disconnect on its own.
    stream.shutdown().await.ok();

    info!("SSH: connection closed (stub — SSH not yet implemented)");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_ssh_handshake_detects_ssh2() {
        assert!(is_ssh_handshake(b"SSH-2.0-OpenSSH_9.6"));
        assert!(is_ssh_handshake(b"SSH-2.0-PuTTY_Release_0.80"));
        assert!(is_ssh_handshake(b"SSH-2.0-rsh_5.1\r\n"));
    }

    #[test]
    fn is_ssh_handshake_detects_ssh1() {
        // SSH-1.99 is a valid version string (compat mode)
        assert!(is_ssh_handshake(b"SSH-1.99-OpenSSH_3.4"));
    }

    #[test]
    fn is_ssh_handshake_rejects_tls() {
        // TLS ClientHello starts with 0x16 0x03
        assert!(!is_ssh_handshake(&[0x16, 0x03, 0x01, 0x00]));
    }

    #[test]
    fn is_ssh_handshake_rejects_http() {
        assert!(!is_ssh_handshake(b"GET / HTTP/1.1"));
        assert!(!is_ssh_handshake(b"POST /api"));
    }

    #[test]
    fn is_ssh_handshake_rejects_empty() {
        assert!(!is_ssh_handshake(b""));
        assert!(!is_ssh_handshake(b"SS"));
        assert!(!is_ssh_handshake(b"SSH"));
    }

    #[test]
    fn is_ssh_handshake_rejects_partial_prefix() {
        // Must match full "SSH-" prefix
        assert!(!is_ssh_handshake(b"SSX-"));
        assert!(!is_ssh_handshake(b"SsH-")); // case-sensitive
    }

    #[test]
    fn is_ssh_handshake_exact_prefix() {
        // Exactly 4 bytes = "SSH-"
        assert!(is_ssh_handshake(b"SSH-"));
    }

    #[tokio::test]
    async fn handle_ssh_connection_sends_version_and_closes() {
        use crate::session::SessionStore;
        use tokio::io::AsyncReadExt;

        let ctx = Arc::new(ServerContext {
            authorized_keys: vec![],
            revoked_keys: std::collections::HashSet::new(),
            server_version: "test".to_string(),
            banner: None,
            caps: vec![],
            session_store: SessionStore::new(),
            rate_limiter: crate::ratelimit::AuthRateLimiter::new(),
            allowed_tunnels: vec![],
            totp_secrets: vec![],
            totp_recovery_path: None,
        });

        let (mut client, server) = tokio::io::duplex(4096);

        // Run handler in background
        let ctx_clone = ctx.clone();
        let handle = tokio::spawn(async move {
            handle_ssh_connection(server, ctx_clone).await
        });

        // Client should receive server version string
        let mut version_buf = vec![0u8; 256];
        let n = client.read(&mut version_buf).await.unwrap();
        let version_str = String::from_utf8_lossy(&version_buf[..n]);
        assert!(
            version_str.starts_with("SSH-2.0-rsh_"),
            "expected SSH version string, got: {}",
            version_str
        );
        assert!(version_str.ends_with("\r\n"));

        // Client sends its version string
        use tokio::io::AsyncWriteExt;
        client
            .write_all(b"SSH-2.0-TestClient_1.0\r\n")
            .await
            .unwrap();

        // Handler should finish (stub closes connection)
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn handle_ssh_connection_client_disconnects_early() {
        use crate::session::SessionStore;

        let ctx = Arc::new(ServerContext {
            authorized_keys: vec![],
            revoked_keys: std::collections::HashSet::new(),
            server_version: "test".to_string(),
            banner: None,
            caps: vec![],
            session_store: SessionStore::new(),
            rate_limiter: crate::ratelimit::AuthRateLimiter::new(),
            allowed_tunnels: vec![],
            totp_secrets: vec![],
            totp_recovery_path: None,
        });

        let (client, server) = tokio::io::duplex(4096);

        // Drop client immediately — simulates early disconnect
        drop(client);

        let result = handle_ssh_connection(server, ctx).await;
        assert!(result.is_ok(), "should handle early disconnect gracefully");
    }
}
