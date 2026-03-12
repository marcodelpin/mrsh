//! Variable-length framing codec for TCP relay messages.
//!
//! Wire format: a 1-4 byte little-endian header followed by the payload.
//! The low 2 bits of the first byte indicate header length:
//!   0b00 → 1 byte  (max payload 63 B)
//!   0b01 → 2 bytes (max payload 16 383 B)
//!   0b10 → 3 bytes (max payload 4 194 303 B)
//!   0b11 → 4 bytes (max payload 1 073 741 823 B)
//! Payload length = header_value >> 2.
//!
//! Clean-room implementation. MIT licensed.

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum payload size we accept when decoding (50 MB).
const MAX_PAYLOAD: usize = 50 * 1024 * 1024;

/// Encode a payload into a framed message (header + payload).
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let shifted = len << 2;

    if len <= 0x3F {
        let mut out = Vec::with_capacity(1 + len);
        out.push(shifted as u8);
        out.extend_from_slice(payload);
        out
    } else if len <= 0x3FFF {
        let val = (shifted | 0x01) as u16;
        let mut out = Vec::with_capacity(2 + len);
        out.extend_from_slice(&val.to_le_bytes());
        out.extend_from_slice(payload);
        out
    } else if len <= 0x3F_FFFF {
        let val = (shifted | 0x02) as u32;
        let bytes = val.to_le_bytes();
        let mut out = Vec::with_capacity(3 + len);
        out.extend_from_slice(&bytes[..3]);
        out.extend_from_slice(payload);
        out
    } else {
        let val = (shifted | 0x03) as u32;
        let mut out = Vec::with_capacity(4 + len);
        out.extend_from_slice(&val.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }
}

/// Read one framed message from an async reader.
pub async fn decode_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let b0 = reader.read_u8().await.context("read first header byte")?;
    let hdr_size = (b0 & 0x03) as usize + 1;

    // Build the full header value (little-endian).
    let header_val: u32 = match hdr_size {
        1 => b0 as u32,
        2 => {
            let b1 = reader.read_u8().await.context("read header byte 2")?;
            u16::from_le_bytes([b0, b1]) as u32
        }
        3 => {
            let mut rest = [0u8; 2];
            reader.read_exact(&mut rest).await.context("read header bytes 2-3")?;
            (b0 as u32) | ((rest[0] as u32) << 8) | ((rest[1] as u32) << 16)
        }
        4 => {
            let mut rest = [0u8; 3];
            reader.read_exact(&mut rest).await.context("read header bytes 2-4")?;
            u32::from_le_bytes([b0, rest[0], rest[1], rest[2]])
        }
        _ => unreachable!(),
    };

    let payload_len = (header_val >> 2) as usize;
    if payload_len == 0 {
        return Ok(Vec::new());
    }
    if payload_len > MAX_PAYLOAD {
        anyhow::bail!("payload too large: {} bytes (max {})", payload_len, MAX_PAYLOAD);
    }

    let mut buf = vec![0u8; payload_len];
    reader.read_exact(&mut buf).await.context("read payload")?;
    Ok(buf)
}

/// Write one framed message to an async writer.
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> Result<()> {
    let frame = encode_frame(payload);
    writer.write_all(&frame).await.context("write frame")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_payload_one_byte_header() {
        let data = b"hello";
        let frame = encode_frame(data);
        assert_eq!(frame[0], 5 << 2); // 20
        assert_eq!(&frame[1..], b"hello");
        assert_eq!(frame.len(), 1 + 5);
    }

    #[test]
    fn medium_payload_two_byte_header() {
        let data = vec![0xAB; 100];
        let frame = encode_frame(&data);
        let h = u16::from_le_bytes([frame[0], frame[1]]);
        assert_eq!(h & 0x03, 1);
        assert_eq!((h >> 2) as usize, 100);
        assert_eq!(&frame[2..], &data[..]);
    }

    #[test]
    fn empty_payload() {
        let frame = encode_frame(b"");
        assert_eq!(frame, vec![0]);
    }

    #[test]
    fn boundary_63_one_byte() {
        let data = vec![0; 63];
        let frame = encode_frame(&data);
        assert_eq!(frame[0] & 0x03, 0);
        assert_eq!(frame.len(), 1 + 63);
    }

    #[test]
    fn boundary_64_two_bytes() {
        let data = vec![0; 64];
        let frame = encode_frame(&data);
        assert_eq!(frame[0] & 0x03, 1);
        assert_eq!(frame.len(), 2 + 64);
    }

    #[test]
    fn boundary_16383_two_bytes() {
        let data = vec![0; 16383];
        let frame = encode_frame(&data);
        assert_eq!(frame[0] & 0x03, 1);
        assert_eq!(frame.len(), 2 + 16383);
    }

    #[test]
    fn boundary_16384_three_bytes() {
        let data = vec![0; 16384];
        let frame = encode_frame(&data);
        assert_eq!(frame[0] & 0x03, 2);
        assert_eq!(frame.len(), 3 + 16384);
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().build().unwrap()
    }

    #[test]
    fn roundtrip_small() {
        rt().block_on(async {
            let orig = b"test data 12345";
            let frame = encode_frame(orig);
            let mut cur = &frame[..];
            let decoded = decode_frame(&mut cur).await.unwrap();
            assert_eq!(&decoded, orig);
        });
    }

    #[test]
    fn roundtrip_medium() {
        rt().block_on(async {
            let orig = vec![0x41; 1000];
            let frame = encode_frame(&orig);
            let mut cur = &frame[..];
            let decoded = decode_frame(&mut cur).await.unwrap();
            assert_eq!(decoded, orig);
        });
    }

    #[test]
    fn roundtrip_large() {
        rt().block_on(async {
            let orig = vec![0x42; 100_000];
            let frame = encode_frame(&orig);
            let mut cur = &frame[..];
            let decoded = decode_frame(&mut cur).await.unwrap();
            assert_eq!(decoded, orig);
        });
    }
}
