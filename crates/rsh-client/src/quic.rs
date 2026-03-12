//! QUIC transport client — connect, authenticate, and issue requests over QUIC.
//!
//! QUIC uses the same ed25519 challenge-response auth protocol as TLS, but
//! carried over newline-delimited JSON on a QUIC bidirectional stream.
//! After auth, each request opens a new bidirectional stream with a
//! `chanType[\0target]\n` header.

#![cfg(feature = "quic")]

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use base64::Engine;
use rsh_core::{auth, protocol, tls};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tracing::{debug, info};

use crate::client::CLIENT_VERSION;

// ────────────────────────── JSON helpers ──────────────────────────────────

async fn send_json<T: serde::Serialize>(send: &mut quinn::SendStream, value: &T) -> Result<()> {
    let mut data = serde_json::to_vec(value).context("serialize JSON")?;
    data.push(b'\n');
    send.write_all(&data).await.context("write JSON")?;
    Ok(())
}

async fn recv_json<T: serde::de::DeserializeOwned>(
    reader: &mut BufReader<quinn::RecvStream>,
) -> Result<T> {
    let mut line = String::new();
    reader.read_line(&mut line).await.context("read JSON line")?;
    serde_json::from_str(&line).context("parse JSON")
}

// ────────────────────────── Client type ──────────────────────────────────

/// A connected and authenticated QUIC client.
pub struct QuicClient {
    conn: quinn::Connection,
    pub server_version: Option<String>,
    pub server_caps: Vec<String>,
}

impl QuicClient {
    /// Connect to a server at `addr` with the given SNI name, authenticate
    /// using the ed25519 key at `key_path` (or the discovered default key).
    pub async fn connect(addr: SocketAddr, server_name: &str, key_path: Option<&str>) -> Result<Self> {
        let endpoint = build_client_endpoint()?;
        let conn = endpoint
            .connect(addr, server_name)
            .context("QUIC connect")?
            .await
            .context("QUIC handshake")?;

        debug!("QUIC connected to {}", addr);

        let (server_version, server_caps) = authenticate(&conn, key_path).await?;

        Ok(Self { conn, server_version, server_caps })
    }

    /// Execute a command and return the output string.
    ///
    /// Server protocol: `OK\n` + output on success, `ERROR: msg` on failure.
    pub async fn exec(&self, command: &str) -> Result<String> {
        let (mut send, recv) = self.conn.open_bi().await.context("open exec stream")?;
        send.write_all(b"exec\n").await.context("write exec header")?;
        send.write_all(command.as_bytes()).await.context("write command")?;
        send.write_all(b"\n").await?;
        send.finish().context("finish exec send")?;

        let mut response = String::new();
        let mut reader = BufReader::new(recv);
        reader
            .read_to_string(&mut response)
            .await
            .context("read exec response")?;

        if response.starts_with("OK\n") {
            Ok(response[3..].to_string())
        } else if response.starts_with("ERROR:") {
            bail!("remote exec: {}", response.trim());
        } else {
            bail!("unexpected exec response: {:?}", response);
        }
    }

    /// Open a TCP tunnel to `target` (`host:port`) and return the QUIC stream
    /// ready for bidirectional relay.
    pub async fn open_tunnel(
        &self,
        target: &str,
    ) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let (mut send, recv) = self.conn.open_bi().await.context("open tunnel stream")?;
        let header = format!("tunnel\0{}\n", target);
        send.write_all(header.as_bytes())
            .await
            .context("write tunnel header")?;

        // Wait for OK from server
        let mut reader = BufReader::new(recv);
        let mut ok_line = String::new();
        reader.read_line(&mut ok_line).await.context("read tunnel OK")?;
        let ok_line = ok_line.trim();
        if ok_line != "OK" {
            bail!("tunnel rejected: {}", ok_line);
        }
        Ok((send, reader.into_inner()))
    }

    /// Close the connection gracefully.
    pub fn close(&self) {
        self.conn.close(quinn::VarInt::from_u32(0), b"done");
    }
}

// ────────────────────────── Endpoint builder ──────────────────────────────

fn build_client_endpoint() -> Result<quinn::Endpoint> {
    let mut client_tls = (*tls::client_config()).clone();
    client_tls.alpn_protocols = vec![b"rsh-quic".to_vec()];
    let client_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(client_tls))
        .context("build QUIC client crypto")?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30))
            .context("idle timeout")?,
    ));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .context("create QUIC client endpoint")?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

// ────────────────────────── Authentication ──────────────────────────────

async fn authenticate(
    conn: &quinn::Connection,
    key_path: Option<&str>,
) -> Result<(Option<String>, Vec<String>)> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let key_pair = match key_path {
        Some(p) => auth::load_ssh_key(std::path::Path::new(p)).context("load SSH key")?,
        None => auth::discover_key().context("no SSH key found")?,
    };

    let (mut send, recv) = conn.open_bi().await.context("open auth stream")?;

    // Send AuthRequest
    let pub_bytes = key_pair.signing_key.verifying_key().to_bytes();
    let auth_req = protocol::AuthRequest {
        auth_type: "auth".to_string(),
        public_key: Some(b64.encode(pub_bytes)),
        key_type: Some("ssh-ed25519".to_string()),
        username: None,
        password: None,
        version: Some(CLIENT_VERSION.to_string()),
        want_mux: None,
        caps: Some(vec!["shell".to_string(), "exec".to_string()]),
    };
    send_json(&mut send, &auth_req).await?;

    let mut reader = BufReader::new(recv);

    // Receive challenge
    let challenge: protocol::AuthChallenge =
        recv_json(&mut reader).await.context("recv challenge")?;
    let challenge_bytes = b64.decode(&challenge.challenge).context("decode challenge")?;

    // Sign
    let sig = key_pair.sign_challenge(&challenge_bytes);
    let auth_resp = protocol::AuthResponse {
        signature: b64.encode(&sig),
    };
    send_json(&mut send, &auth_resp).await?;
    send.finish().context("finish auth send")?;

    // Receive result
    let result: protocol::AuthResult = recv_json(&mut reader).await.context("recv auth result")?;
    if !result.success {
        bail!(
            "QUIC authentication failed: {}",
            result.error.as_deref().unwrap_or("rejected")
        );
    }

    info!("QUIC authenticated: server_version={:?}", result.version);
    Ok((result.version, result.caps.unwrap_or_default()))
}

// ────────────────────────── Tests ──────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn quic_client_endpoint_builds() {
        // Verify the endpoint builder doesn't panic or fail.
        let ep = build_client_endpoint().expect("build QUIC client endpoint");
        drop(ep);
    }
}
