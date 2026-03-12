//! Length-prefixed wire protocol — 4-byte big-endian header + payload.

use anyhow::{Context, Result, bail};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum message size (50 MB).
const MAX_MESSAGE_SIZE: u32 = 50 * 1024 * 1024;

/// Send a length-prefixed message (4-byte BE header + data).
pub async fn send_message<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    let length = data.len() as u32;
    let header = length.to_be_bytes();
    writer.write_all(&header).await.context("write header")?;
    writer.write_all(data).await.context("write body")?;
    writer.flush().await.context("flush")?;
    Ok(())
}

/// Receive a length-prefixed message.
pub async fn recv_message<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    reader
        .read_exact(&mut header)
        .await
        .context("read header")?;
    let length = u32::from_be_bytes(header);
    if length > MAX_MESSAGE_SIZE {
        bail!(
            "message too large: {} bytes (max {})",
            length,
            MAX_MESSAGE_SIZE
        );
    }
    let mut data = vec![0u8; length as usize];
    reader.read_exact(&mut data).await.context("read body")?;
    Ok(data)
}

/// Send a JSON-serialized value as a length-prefixed message.
pub async fn send_json<W: AsyncWriteExt + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<()> {
    let data = serde_json::to_vec(value).context("serialize JSON")?;
    send_message(writer, &data).await
}

/// Receive and deserialize a JSON message.
pub async fn recv_json<R: AsyncReadExt + Unpin, T: DeserializeOwned>(reader: &mut R) -> Result<T> {
    let data = recv_message(reader).await?;
    serde_json::from_slice(&data).context("deserialize JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn message_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let payload = b"hello world";
        send_message(&mut client, payload).await.unwrap();
        let received = recv_message(&mut server).await.unwrap();
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn json_roundtrip() {
        use crate::protocol::Request;

        let (mut client, mut server) = tokio::io::duplex(4096);

        let req = Request {
            req_type: "exec".to_string(),
            command: Some("hostname".to_string()),
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
        };

        send_json(&mut client, &req).await.unwrap();
        let received: Request = recv_json(&mut server).await.unwrap();
        assert_eq!(received.req_type, "exec");
        assert_eq!(received.command.as_deref(), Some("hostname"));
    }

    #[tokio::test]
    async fn empty_message() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        send_message(&mut client, b"").await.unwrap();
        let received = recv_message(&mut server).await.unwrap();
        assert!(received.is_empty());
    }

    #[tokio::test]
    async fn message_too_large_rejected() {
        // Header claiming >50MB should be rejected
        let (mut client, mut server) = tokio::io::duplex(1024);

        // Write a header claiming 60MB
        let fake_len: u32 = 60 * 1024 * 1024;
        client.write_all(&fake_len.to_be_bytes()).await.unwrap();
        drop(client); // Close write side

        let result = recv_message(&mut server).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("message too large"), "expected 'too large' error, got: {}", err_msg);
    }

    #[tokio::test]
    async fn big_endian_header_format() {
        // Verify wire format: 4-byte BE length prefix
        let (mut client, mut server) = tokio::io::duplex(1024);

        let payload = vec![0x41u8; 256]; // 256 bytes of 'A'
        send_message(&mut client, &payload).await.unwrap();

        // Read raw header
        let mut header = [0u8; 4];
        server.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [0, 0, 1, 0]); // 256 in big-endian

        // Read payload
        let mut data = vec![0u8; 256];
        server.read_exact(&mut data).await.unwrap();
        assert_eq!(data, payload);
    }
}
