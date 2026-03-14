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

/// Compression flag byte prepended to compressed messages.
const ZSTD_FLAG: u8 = 0x01;
const RAW_FLAG: u8 = 0x00;

/// Minimum payload size to bother compressing (below this, overhead > savings).
const COMPRESS_THRESHOLD: usize = 256;

/// Send a JSON-serialized value with optional zstd compression.
///
/// Format: flag (1 byte) + payload.
/// flag=0x00: payload is raw JSON. flag=0x01: payload is zstd(JSON).
/// Only compresses if JSON size > COMPRESS_THRESHOLD.
pub async fn send_json_compressed<W: AsyncWriteExt + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<()> {
    let json = serde_json::to_vec(value).context("serialize JSON")?;

    if json.len() > COMPRESS_THRESHOLD {
        let compressed = zstd::encode_all(json.as_slice(), 3).context("zstd compress")?;
        // Only send compressed if it's actually smaller
        if compressed.len() < json.len() {
            let mut msg = Vec::with_capacity(1 + compressed.len());
            msg.push(ZSTD_FLAG);
            msg.extend_from_slice(&compressed);
            return send_message(writer, &msg).await;
        }
    }

    let mut msg = Vec::with_capacity(1 + json.len());
    msg.push(RAW_FLAG);
    msg.extend_from_slice(&json);
    send_message(writer, &msg).await
}

/// Receive and deserialize a JSON message that may be zstd-compressed.
///
/// Auto-detects based on flag byte (0x00=raw, 0x01=zstd).
pub async fn recv_json_compressed<R: AsyncReadExt + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<T> {
    let data = recv_message(reader).await?;
    if data.is_empty() {
        bail!("empty message");
    }
    match data[0] {
        ZSTD_FLAG => {
            let decompressed = zstd::decode_all(&data[1..]).context("zstd decompress")?;
            serde_json::from_slice(&decompressed).context("deserialize compressed JSON")
        }
        RAW_FLAG => {
            serde_json::from_slice(&data[1..]).context("deserialize JSON")
        }
        _ => {
            // Backward compatibility: no flag byte, treat entire payload as raw JSON
            serde_json::from_slice(&data).context("deserialize JSON (legacy)")
        }
    }
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
    async fn compressed_json_roundtrip() {
        use crate::protocol::Response;

        let (mut client, mut server) = tokio::io::duplex(8192);

        // Large response that should compress
        let resp = Response {
            success: true,
            output: Some("x".repeat(1000)),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        };

        send_json_compressed(&mut client, &resp).await.unwrap();
        let received: Response = recv_json_compressed(&mut server).await.unwrap();
        assert_eq!(received.success, true);
        assert_eq!(received.output.as_deref(), Some(&"x".repeat(1000)[..]));
    }

    #[tokio::test]
    async fn small_payload_not_compressed() {
        use crate::protocol::Response;

        let (mut client, mut server) = tokio::io::duplex(4096);

        // Small response — below threshold, should not compress
        let resp = Response {
            success: true,
            output: Some("ok".to_string()),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        };

        send_json_compressed(&mut client, &resp).await.unwrap();

        // Read raw to verify flag byte is RAW
        let raw = recv_message(&mut server).await.unwrap();
        assert_eq!(raw[0], RAW_FLAG, "small payload should use RAW flag");
    }

    #[tokio::test]
    async fn recv_compressed_handles_legacy_no_flag() {
        // Simulate a message sent by old server without flag byte (plain JSON)
        use crate::protocol::Response;

        let (mut client, mut server) = tokio::io::duplex(4096);

        let resp = Response {
            success: true,
            output: Some("legacy".to_string()),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        };
        // Send raw JSON without flag byte (old behavior)
        send_json(&mut client, &resp).await.unwrap();

        // recv_json_compressed should handle gracefully via fallback
        let received: Response = recv_json_compressed(&mut server).await.unwrap();
        assert_eq!(received.output.as_deref(), Some("legacy"));
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
