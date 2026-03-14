//! Per-connection handler: auth handshake + request dispatch loop.
//! Works with any AsyncRead+AsyncWrite stream (TLS, duplex for tests).

use anyhow::{Context, Result};
use base64::Engine;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info, warn};

use rsh_core::{auth, protocol, wire};

use crate::{dispatch, ratelimit, session, shell, sync, tunnel};

/// Send a response, using zstd compression if the client supports it.
async fn send_resp<W: AsyncWrite + Unpin>(
    writer: &mut W,
    resp: &protocol::Response,
    use_zstd: bool,
) -> Result<()> {
    if use_zstd {
        wire::send_json_compressed(writer, resp).await
    } else {
        wire::send_json(writer, resp).await
    }
}

/// Server-side configuration for connection handling.
pub struct ServerContext {
    pub authorized_keys: Vec<auth::AuthorizedKey>,
    pub revoked_keys: std::collections::HashSet<String>,
    pub server_version: String,
    pub banner: Option<String>,
    pub caps: Vec<String>,
    pub session_store: session::SessionStore,
    pub rate_limiter: ratelimit::AuthRateLimiter,
    /// Allowed tunnel destinations (PermitOpen equivalent).
    /// Empty = all destinations allowed (default open behavior).
    /// Non-empty = only listed patterns allowed (host:port or host:*).
    pub allowed_tunnels: Vec<String>,
    /// TOTP secrets loaded from totp_secrets file. Empty if no TOTP configured.
    pub totp_secrets: Vec<auth::TotpSecret>,
    /// Path to totp_recovery file (for consuming one-time recovery codes).
    pub totp_recovery_path: Option<std::path::PathBuf>,
}

/// Authenticated client info.
pub struct ClientInfo {
    pub key_comment: Option<String>,
    pub client_version: Option<String>,
    pub caps: Vec<String>,
    pub permissions: auth::KeyPermissions,
    pub mux_enabled: bool,
}

/// Handle a single authenticated connection: auth handshake + request loop.
pub async fn handle_connection<S>(
    mut stream: S,
    ctx: &ServerContext,
    peer: Option<std::net::SocketAddr>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Rate limit check — reject banned IPs before wasting TLS/auth resources
    if let Some(addr) = peer {
        if ctx.rate_limiter.is_banned(&addr.ip()) {
            warn!("rate limiter: rejecting banned IP {}", addr.ip());
            return Ok(());
        }
    }

    // Phase 1: Auth (with LoginGraceTime-style timeout)
    let auth_timeout = std::time::Duration::from_secs(30);
    let client = match tokio::time::timeout(auth_timeout, authenticate(&mut stream, ctx)).await {
        Err(_) => {
            warn!("auth timeout ({}s elapsed)", auth_timeout.as_secs());
            if let Some(addr) = peer {
                ctx.rate_limiter.record_failure(addr.ip());
            }
            return Ok(());
        }
        Ok(auth_result) => match auth_result {
            Ok(c) => {
                // Clear failure count on success
                if let Some(addr) = peer {
                    ctx.rate_limiter.record_success(&addr.ip());
                }
                c
            }
            Err(e) => {
                warn!("auth failed: {}", e);
                if let Some(addr) = peer {
                    let banned = ctx.rate_limiter.record_failure(addr.ip());
                    if banned {
                        warn!("IP {} is now banned after repeated auth failures", addr.ip());
                    }
                }
                return Ok(());
            }
        }
    };
    info!(
        "authenticated: {}",
        client.key_comment.as_deref().unwrap_or("unknown")
    );

    // Notify tray icon of new connection (anti-abuse: user sees who connects)
    if let Some(addr) = peer {
        crate::notify::notify_connection(addr, client.key_comment.clone());
    }

    let use_zstd = client.caps.iter().any(|c| c == "zstd");

    // Phase 2: MUX or standard request loop
    #[cfg(windows)]
    if client.mux_enabled {
        info!("entering MUX mode for {}", client.key_comment.as_deref().unwrap_or("unknown"));
        let (mux_conn, reader) = crate::mux::ServerMuxConn::new(stream);
        return mux_conn.serve(reader).await;
    }

    // Standard request loop with idle timeout
    let idle_timeout = std::time::Duration::from_secs(300);
    loop {
        let msg = match tokio::time::timeout(idle_timeout, wire::recv_message(&mut stream)).await {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                debug!("connection closed: {}", e);
                return Ok(());
            }
            Err(_) => {
                info!("idle timeout ({}s), closing connection", idle_timeout.as_secs());
                return Ok(());
            }
        };

        let mut req: protocol::Request =
            serde_json::from_slice(&msg).context("parse request JSON")?;

        // Enforce per-key permissions
        if let Some(denial) = check_permission(&req, &client.permissions) {
            warn!(
                "permission denied: {} for key {}",
                denial,
                client.key_comment.as_deref().unwrap_or("unknown")
            );
            let resp = protocol::Response {
                success: false,
                output: None,
                error: Some(denial),
                size: None,
                binary: None,
                gzip: None,
            };
            send_resp(&mut stream, &resp, use_zstd).await?;
            continue;
        }

        // Apply forced command if set
        if let Some(ref forced) = client.permissions.forced_command {
            if req.req_type == "exec" || req.req_type == "exec-as-user" {
                req.command = Some(forced.clone());
            }
        }

        match dispatch::dispatch(&req, &ctx.session_store).await {
            dispatch::DispatchResult::Response(response) => {
                send_resp(&mut stream, &response, use_zstd).await?;
            }
            dispatch::DispatchResult::SyncStream(action) => {
                match action {
                    dispatch::SyncStreamAction::PullDelta => {
                        if let Err(e) = sync::handle_pull_delta(&mut stream, &req).await {
                            warn!("pull-delta error: {}", e);
                        }
                    }
                    dispatch::SyncStreamAction::BatchPatchBin => {
                        if let Err(e) = sync::handle_batch_patch_bin(&mut stream, &req).await {
                            warn!("batch-patch-bin error: {}", e);
                        }
                    }
                }
                // Continue request loop (stream not consumed)
            }
            dispatch::DispatchResult::Hijack(action) => {
                // Send success before hijacking the connection
                let ack = protocol::Response {
                    success: true,
                    output: None,
                    error: None,
                    size: None,
                    binary: None,
                    gzip: None,
                };
                wire::send_json(&mut stream, &ack).await?;

                match action {
                    dispatch::HijackAction::Connect { target } => {
                        if !tunnel::is_tunnel_allowed(&target, &ctx.allowed_tunnels) {
                            warn!("tunnel target not allowed: {}", target);
                            // Connection already hijacked — just return
                        } else if let Err(e) = tunnel::handle_connect(&mut stream, &target).await {
                            warn!("tunnel error: {}", e);
                        }
                    }
                    dispatch::HijackAction::Shell { size, env_vars } => {
                        if let Err(e) = shell::handle_shell(&mut stream, &size, &env_vars).await {
                            warn!("shell error: {}", e);
                        }
                    }
                    dispatch::HijackAction::ShellPersistent {
                        size,
                        session_id,
                        readonly: _,
                        env_vars,
                    } => {
                        // Create or reattach session
                        let (cols, rows) = shell::parse_size(&size);
                        let id = match session_id {
                            Some(id) if ctx.session_store.attach(&id).await => id,
                            _ => {
                                ctx.session_store
                                    .create("shell".to_string(), cols, rows)
                                    .await
                            }
                        };
                        info!("persistent shell session: {}", id);

                        if let Err(e) = shell::handle_shell(&mut stream, &size, &env_vars).await {
                            warn!("persistent shell error: {}", e);
                        }
                        ctx.session_store.detach(&id).await;
                    }
                }
                // Connection consumed — exit request loop
                return Ok(());
            }
        }
    }
}

/// Check if a request is allowed by the key's permissions.
/// Returns `None` if allowed, `Some(reason)` if denied.
fn check_permission(req: &protocol::Request, perms: &auth::KeyPermissions) -> Option<String> {
    match req.req_type.as_str() {
        // Exec commands
        "exec" | "exec-as-user" => {
            if !perms.allow_exec {
                return Some("exec not permitted for this key".to_string());
            }
        }
        // Push (write) commands
        "write" => {
            if !perms.allow_push {
                return Some("push/write not permitted for this key".to_string());
            }
        }
        // Pull (read) commands
        "ls" | "read" | "cat" => {
            if !perms.allow_pull {
                return Some("pull/read not permitted for this key".to_string());
            }
        }
        // Shell commands
        "shell" | "shell-persistent" => {
            if !perms.allow_shell {
                return Some("shell not permitted for this key".to_string());
            }
        }
        // Tunnel commands
        "connect" => {
            if !perms.allow_tunnel {
                return Some("tunnel not permitted for this key".to_string());
            }
        }
        // Sync: direction depends on sync_type
        "sync" => {
            let sync_type = req.sync_type.as_deref().unwrap_or("");
            match sync_type {
                "pull-delta" => {
                    if !perms.allow_pull {
                        return Some("pull/read not permitted for this key".to_string());
                    }
                }
                "batch-patch-bin" => {
                    if !perms.allow_push {
                        return Some("push/write not permitted for this key".to_string());
                    }
                }
                _ => {
                    // Generic sync: require both push and pull
                    if !perms.allow_push || !perms.allow_pull {
                        return Some("sync not permitted for this key".to_string());
                    }
                }
            }
        }
        // Utility/info commands: always allowed
        "ping" | "screenshot" | "native" | "self-update" | "session" | "input" | "info" => {}
        // Unknown request types: deny by default
        other => {
            return Some(format!("unknown request type '{}' denied by default", other));
        }
    }
    None
}

/// Run the server-side auth handshake.
async fn authenticate<S>(stream: &mut S, ctx: &ServerContext) -> Result<ClientInfo>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let b64 = base64::engine::general_purpose::STANDARD;

    // 1. Receive AuthRequest
    let auth_req: protocol::AuthRequest =
        wire::recv_json(stream).await.context("recv AuthRequest")?;

    debug!(
        "auth request: type={} version={:?}",
        auth_req.auth_type, auth_req.version
    );

    // Client sends "auth" for pubkey, "password" for password, "tailscale" for TS auth
    if auth_req.auth_type != "auth" && auth_req.auth_type != "pubkey" {
        let result = protocol::AuthResult {
            success: false,
            error: Some(format!("unsupported auth type: {}", auth_req.auth_type)),
            version: Some(ctx.server_version.clone()),
            mux_enabled: None,
            caps: None,
            banner: None,
        };
        wire::send_json(stream, &result).await?;
        anyhow::bail!("unsupported auth type: {}", auth_req.auth_type);
    }

    // 2. Look up client's public key
    let client_pubkey_b64 = auth_req
        .public_key
        .as_ref()
        .context("missing public_key in auth request")?;
    let client_pubkey_wire = b64
        .decode(client_pubkey_b64)
        .context("decode public_key base64")?;

    // Extract raw 32-byte ed25519 key from SSH wire format or raw bytes
    let raw_key = extract_ed25519_raw(&client_pubkey_wire)?;

    // Compute key fingerprint for logging
    let key_fingerprint = auth::key_fingerprint(&raw_key);

    // Check revocation BEFORE authorized_keys lookup
    if auth::is_key_revoked(&raw_key, &ctx.revoked_keys) {
        warn!("auth: REVOKED key {} attempted connection", key_fingerprint);
        let result = protocol::AuthResult {
            success: false,
            error: Some("public key has been revoked".to_string()),
            version: Some(ctx.server_version.clone()),
            mux_enabled: None,
            caps: None,
            banner: None,
        };
        wire::send_json(stream, &result).await?;
        anyhow::bail!("public key revoked: {}", key_fingerprint);
    }

    // Find matching authorized key
    let matched_key = ctx.authorized_keys.iter().find(|k| k.key_data == raw_key);

    if matched_key.is_none() {
        warn!("auth: unknown key {}", key_fingerprint);
        let result = protocol::AuthResult {
            success: false,
            error: Some("public key not authorized".to_string()),
            version: Some(ctx.server_version.clone()),
            mux_enabled: None,
            caps: None,
            banner: None,
        };
        wire::send_json(stream, &result).await?;
        anyhow::bail!("public key not authorized");
    }
    let matched_key = matched_key.unwrap();

    // 3. Send challenge
    let challenge = auth::generate_challenge();
    let challenge_msg = protocol::AuthChallenge {
        challenge: b64.encode(&challenge),
    };
    wire::send_json(stream, &challenge_msg).await?;

    // 4. Receive signed response
    let auth_resp: protocol::AuthResponse =
        wire::recv_json(stream).await.context("recv AuthResponse")?;

    let signature = b64
        .decode(&auth_resp.signature)
        .context("decode signature base64")?;

    // Handle both raw 64-byte ed25519 and SSH wire-format signatures
    let raw_sig = extract_ed25519_sig(&signature)?;

    // 5. Verify signature
    let valid = auth::verify_ed25519_signature(&raw_key, &challenge, &raw_sig)
        .context("verify signature")?;

    if !valid {
        warn!("auth: bad signature from key {}", key_fingerprint);
        let result = protocol::AuthResult {
            success: false,
            error: Some("signature verification failed".to_string()),
            version: Some(ctx.server_version.clone()),
            mux_enabled: None,
            caps: None,
            banner: None,
        };
        wire::send_json(stream, &result).await?;
        anyhow::bail!("signature verification failed");
    }
    info!(
        "auth: accepted key {} ({})",
        key_fingerprint,
        matched_key.comment.as_deref().unwrap_or("no comment")
    );

    // 5b. TOTP verification (if key requires it)
    if matched_key.permissions.require_totp {
        let totp_secret = auth::find_totp_secret(&key_fingerprint, &ctx.totp_secrets);
        if totp_secret.is_none() {
            warn!(
                "auth: key {} requires TOTP but no secret configured",
                key_fingerprint
            );
            let result = protocol::AuthResult {
                success: false,
                error: Some("TOTP required but not configured for this key".to_string()),
                version: Some(ctx.server_version.clone()),
                mux_enabled: None,
                caps: None,
                banner: None,
            };
            wire::send_json(stream, &result).await?;
            anyhow::bail!("TOTP required but no secret for key {}", key_fingerprint);
        }
        let totp_secret = totp_secret.unwrap();

        // Send TOTP challenge
        let challenge = protocol::TotpChallenge {
            totp_required: true,
        };
        wire::send_json(stream, &challenge).await?;

        // Receive TOTP response
        let totp_resp: protocol::TotpResponse = wire::recv_json(stream)
            .await
            .context("recv TotpResponse")?;

        // Verify TOTP code
        let totp_valid = auth::verify_totp(&totp_secret.secret_base32, &totp_resp.totp_code)
            .unwrap_or(false);

        if !totp_valid {
            // Try recovery codes
            let mut recovery_used = false;
            if let Some(ref recovery_path) = ctx.totp_recovery_path {
                if recovery_path.exists() {
                    if let Ok(mut recovery_map) = auth::load_totp_recovery(recovery_path) {
                        if auth::check_recovery_code(
                            &totp_resp.totp_code,
                            &key_fingerprint,
                            &mut recovery_map,
                        ) {
                            // Save updated recovery codes (used code removed)
                            if let Err(e) = auth::save_totp_recovery(recovery_path, &recovery_map)
                            {
                                warn!("failed to save recovery codes: {}", e);
                            }
                            info!(
                                "auth: TOTP recovery code used for key {}",
                                key_fingerprint
                            );
                            recovery_used = true;
                        }
                    }
                }
            }

            if !recovery_used {
                warn!(
                    "auth: TOTP verification failed for key {}",
                    key_fingerprint
                );
                let result = protocol::AuthResult {
                    success: false,
                    error: Some("TOTP verification failed".to_string()),
                    version: Some(ctx.server_version.clone()),
                    mux_enabled: None,
                    caps: None,
                    banner: None,
                };
                wire::send_json(stream, &result).await?;
                anyhow::bail!("TOTP verification failed for key {}", key_fingerprint);
            }
        } else {
            debug!("auth: TOTP verified for key {}", key_fingerprint);
        }
    }

    // 6. Negotiate capabilities
    let client_caps = auth_req.caps.unwrap_or_default();
    let granted_caps: Vec<String> = ctx
        .caps
        .iter()
        .filter(|c| client_caps.contains(c))
        .cloned()
        .collect();

    // 7. Send success
    let mux_enabled = if cfg!(windows) && auth_req.want_mux == Some(true) {
        Some(true)
    } else {
        None
    };
    let result = protocol::AuthResult {
        success: true,
        error: None,
        version: Some(ctx.server_version.clone()),
        mux_enabled,
        caps: Some(granted_caps.clone()),
        banner: ctx.banner.clone(),
    };
    wire::send_json(stream, &result).await?;

    Ok(ClientInfo {
        key_comment: matched_key.comment.clone(),
        client_version: auth_req.version,
        caps: granted_caps,
        permissions: matched_key.permissions.clone(),
        mux_enabled: mux_enabled == Some(true),
    })
}

/// Extract raw 32-byte ed25519 public key from either:
/// - SSH wire format: [4-byte len]["ssh-ed25519"][4-byte len][32-byte key]
/// - Raw 32 bytes
fn extract_ed25519_raw(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() == 32 {
        return Ok(data.to_vec());
    }
    // SSH wire format: last 32 bytes are the raw key
    if data.len() > 32 {
        // Verify it starts with ssh-ed25519 wire format
        if data.len() >= 51 {
            // 4 + 11 + 4 + 32
            let type_len = u32::from_be_bytes(data[0..4].try_into()?) as usize;
            if type_len == 11 && &data[4..15] == b"ssh-ed25519" {
                return Ok(data[data.len() - 32..].to_vec());
            }
        }
        // Fallback: take last 32 bytes
        return Ok(data[data.len() - 32..].to_vec());
    }
    anyhow::bail!("invalid ed25519 public key: {} bytes", data.len());
}

/// Extract raw 64-byte ed25519 signature from either:
/// - Raw 64 bytes
/// - SSH wire format: [4-byte len]["ssh-ed25519"][4-byte len][64-byte sig]
fn extract_ed25519_sig(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() == 64 {
        return Ok(data.to_vec());
    }
    // SSH wire format
    if data.len() > 64 {
        return Ok(data[data.len() - 64..].to_vec());
    }
    anyhow::bail!("invalid ed25519 signature: {} bytes", data.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn make_test_context(signing_key: &SigningKey) -> ServerContext {
        let pub_bytes = signing_key.verifying_key().to_bytes();
        // Build SSH wire format for the authorized key
        let key_type = b"ssh-ed25519";
        let mut wire = Vec::new();
        wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        wire.extend_from_slice(key_type);
        wire.extend_from_slice(&(pub_bytes.len() as u32).to_be_bytes());
        wire.extend_from_slice(&pub_bytes);

        let ak = auth::AuthorizedKey {
            key_type: "ssh-ed25519".to_string(),
            key_data: pub_bytes.to_vec(),
            comment: Some("test@host".to_string()),
            permissions: auth::KeyPermissions::default(),
        };

        ServerContext {
            authorized_keys: vec![ak],
            revoked_keys: std::collections::HashSet::new(),
            server_version: "0.1.0-test".to_string(),
            banner: None,
            caps: vec!["shell".to_string(), "self-update".to_string()],
            session_store: session::SessionStore::new(),
            rate_limiter: ratelimit::AuthRateLimiter::new(),
            allowed_tunnels: vec![],
            totp_secrets: vec![],
            totp_recovery_path: None,
        }
    }

    #[tokio::test]
    async fn full_auth_handshake() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);

        let (mut client, mut server) = tokio::io::duplex(4096);

        // Run server auth in background
        let server_handle = tokio::spawn(async move { authenticate(&mut server, &ctx).await });

        // Client side: send AuthRequest
        let b64 = base64::engine::general_purpose::STANDARD;
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let auth_req = protocol::AuthRequest {
            auth_type: "auth".to_string(),
            public_key: Some(b64.encode(pub_bytes)),
            key_type: Some("ssh-ed25519".to_string()),
            username: None,
            password: None,
            version: Some("0.1.0".to_string()),
            want_mux: None,
            caps: Some(vec!["shell".to_string()]),
        };
        wire::send_json(&mut client, &auth_req).await.unwrap();

        // Receive challenge
        let challenge: protocol::AuthChallenge = wire::recv_json(&mut client).await.unwrap();
        let challenge_bytes = b64.decode(&challenge.challenge).unwrap();

        // Sign challenge
        let kp = auth::SshKeyPair {
            signing_key: signing_key.clone(),
            key_type: "ssh-ed25519".to_string(),
            path: std::path::PathBuf::from("/dev/null"),
        };
        let sig = kp.sign_challenge(&challenge_bytes);
        let auth_resp = protocol::AuthResponse {
            signature: b64.encode(&sig),
        };
        wire::send_json(&mut client, &auth_resp).await.unwrap();

        // Receive result
        let result: protocol::AuthResult = wire::recv_json(&mut client).await.unwrap();
        assert!(result.success);
        assert_eq!(result.version.as_deref(), Some("0.1.0-test"));
        assert!(result.caps.unwrap().contains(&"shell".to_string()));

        // Server should have returned Ok(ClientInfo)
        let client_info = server_handle.await.unwrap().unwrap();
        assert_eq!(client_info.key_comment.as_deref(), Some("test@host"));
        assert!(client_info.caps.contains(&"shell".to_string()));
    }

    #[tokio::test]
    async fn auth_rejects_unknown_key() {
        let server_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&server_key);

        let (mut client, mut server) = tokio::io::duplex(4096);

        let server_handle = tokio::spawn(async move { authenticate(&mut server, &ctx).await });

        // Client uses a different key
        let wrong_key = SigningKey::generate(&mut rand::thread_rng());
        let b64 = base64::engine::general_purpose::STANDARD;
        let auth_req = protocol::AuthRequest {
            auth_type: "auth".to_string(),
            public_key: Some(b64.encode(wrong_key.verifying_key().to_bytes())),
            key_type: Some("ssh-ed25519".to_string()),
            username: None,
            password: None,
            version: None,
            want_mux: None,
            caps: None,
        };
        wire::send_json(&mut client, &auth_req).await.unwrap();

        // Should receive failure result
        let result: protocol::AuthResult = wire::recv_json(&mut client).await.unwrap();
        assert!(!result.success);
        assert!(result.error.unwrap().contains("not authorized"));

        // Server returns error
        assert!(server_handle.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn auth_with_ssh_wire_format_key() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ctx = make_test_context(&signing_key);

        let (mut client, mut server) = tokio::io::duplex(4096);

        let server_handle = tokio::spawn(async move { authenticate(&mut server, &ctx).await });

        // Client sends key in SSH wire format
        let b64 = base64::engine::general_purpose::STANDARD;
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let key_type = b"ssh-ed25519";
        let mut wire_key = Vec::new();
        wire_key.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        wire_key.extend_from_slice(key_type);
        wire_key.extend_from_slice(&(pub_bytes.len() as u32).to_be_bytes());
        wire_key.extend_from_slice(&pub_bytes);

        let auth_req = protocol::AuthRequest {
            auth_type: "auth".to_string(),
            public_key: Some(b64.encode(&wire_key)),
            key_type: Some("ssh-ed25519".to_string()),
            username: None,
            password: None,
            version: Some("4.38.0".to_string()),
            want_mux: None,
            caps: Some(vec!["shell".to_string()]),
        };
        wire::send_json(&mut client, &auth_req).await.unwrap();

        // Receive challenge, sign, send back
        let challenge: protocol::AuthChallenge = wire::recv_json(&mut client).await.unwrap();
        let challenge_bytes = b64.decode(&challenge.challenge).unwrap();
        let kp = auth::SshKeyPair {
            signing_key: signing_key.clone(),
            key_type: "ssh-ed25519".to_string(),
            path: std::path::PathBuf::from("/dev/null"),
        };
        let sig = kp.sign_challenge(&challenge_bytes);
        let auth_resp = protocol::AuthResponse {
            signature: b64.encode(&sig),
        };
        wire::send_json(&mut client, &auth_resp).await.unwrap();

        let result: protocol::AuthResult = wire::recv_json(&mut client).await.unwrap();
        assert!(result.success);

        let info = server_handle.await.unwrap().unwrap();
        assert_eq!(info.client_version.as_deref(), Some("4.38.0"));
    }

    #[test]
    fn extract_ed25519_raw_32_bytes() {
        let raw = vec![0x42u8; 32];
        assert_eq!(extract_ed25519_raw(&raw).unwrap(), raw);
    }

    #[test]
    fn extract_ed25519_raw_ssh_wire() {
        let key_type = b"ssh-ed25519";
        let raw_key = vec![0x42u8; 32];
        let mut wire = Vec::new();
        wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        wire.extend_from_slice(key_type);
        wire.extend_from_slice(&(raw_key.len() as u32).to_be_bytes());
        wire.extend_from_slice(&raw_key);

        let extracted = extract_ed25519_raw(&wire).unwrap();
        assert_eq!(extracted, raw_key);
    }

    #[test]
    fn extract_ed25519_sig_64_bytes() {
        let sig = vec![0x42u8; 64];
        assert_eq!(extract_ed25519_sig(&sig).unwrap(), sig);
    }

    // Permission enforcement tests

    fn make_req(req_type: &str) -> protocol::Request {
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

    #[test]
    fn default_permissions_allow_everything() {
        let perms = auth::KeyPermissions::default();
        for req_type in &["exec", "exec-as-user", "write", "ls", "read", "cat",
                          "shell", "shell-persistent", "connect", "ping", "screenshot"] {
            assert!(check_permission(&make_req(req_type), &perms).is_none(),
                    "{} should be allowed with default perms", req_type);
        }
    }

    #[test]
    fn restricted_permissions_deny_protected_commands() {
        let perms = auth::KeyPermissions {
            allow_exec: false,
            allow_push: false,
            allow_pull: false,
            allow_shell: false,
            allow_tunnel: false,
            forced_command: None,
            require_totp: false,
        };

        assert!(check_permission(&make_req("exec"), &perms).is_some());
        assert!(check_permission(&make_req("exec-as-user"), &perms).is_some());
        assert!(check_permission(&make_req("write"), &perms).is_some());
        assert!(check_permission(&make_req("ls"), &perms).is_some());
        assert!(check_permission(&make_req("read"), &perms).is_some());
        assert!(check_permission(&make_req("cat"), &perms).is_some());
        assert!(check_permission(&make_req("shell"), &perms).is_some());
        assert!(check_permission(&make_req("shell-persistent"), &perms).is_some());
        assert!(check_permission(&make_req("connect"), &perms).is_some());

        // Utility commands always allowed
        assert!(check_permission(&make_req("ping"), &perms).is_none());
        assert!(check_permission(&make_req("screenshot"), &perms).is_none());
        assert!(check_permission(&make_req("self-update"), &perms).is_none());
    }

    #[test]
    fn sync_permission_depends_on_sync_type() {
        let pull_only = auth::KeyPermissions {
            allow_exec: false,
            allow_push: false,
            allow_pull: true,
            allow_shell: false,
            allow_tunnel: false,
            forced_command: None,
            require_totp: false,
        };

        let mut req = make_req("sync");
        req.sync_type = Some("pull-delta".to_string());
        assert!(check_permission(&req, &pull_only).is_none());

        req.sync_type = Some("batch-patch-bin".to_string());
        assert!(check_permission(&req, &pull_only).is_some());
    }

    #[test]
    fn selective_permissions() {
        let perms = auth::KeyPermissions {
            allow_exec: true,
            allow_push: false,
            allow_pull: true,
            allow_shell: false,
            allow_tunnel: false,
            forced_command: None,
            require_totp: false,
        };

        assert!(check_permission(&make_req("exec"), &perms).is_none());
        assert!(check_permission(&make_req("read"), &perms).is_none());
        assert!(check_permission(&make_req("write"), &perms).is_some());
        assert!(check_permission(&make_req("shell"), &perms).is_some());
        assert!(check_permission(&make_req("connect"), &perms).is_some());
    }
}
