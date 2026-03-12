//! Connection multiplexing — binary framing protocol for concurrent channels.
//! Server-side only. Each channel carries exec, tunnel, or shell traffic.
//!
//! Wire format (9-byte header):
//!   [4 bytes] length (BE) — covers channelID + type + payload (i.e. length = 5 + payload_len)
//!   [4 bytes] channelID (BE)
//!   [1 byte]  message type
//!   [N bytes] payload (N = length - 5)

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ── Protocol constants ──────────────────────────────────────────────

/// Protocol version that supports multiplexing.
pub const MUX_PROTOCOL_VERSION: &str = "3.8.0";

/// Maximum payload size (10 MB).
const MAX_PAYLOAD_SIZE: u32 = 10 * 1024 * 1024;

/// Channel data buffer depth (used by server module on Windows).
#[cfg(windows)]
const CHANNEL_BUFFER: usize = 16;

// ── Message types ───────────────────────────────────────────────────

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    ChannelOpen = 0x00,
    ChannelConfirm = 0x01,
    ChannelReject = 0x02,
    ChannelData = 0x03,
    ChannelClose = 0x04,
    ChannelEOF = 0x05,
}

impl MsgType {
    fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x00 => Ok(Self::ChannelOpen),
            0x01 => Ok(Self::ChannelConfirm),
            0x02 => Ok(Self::ChannelReject),
            0x03 => Ok(Self::ChannelData),
            0x04 => Ok(Self::ChannelClose),
            0x05 => Ok(Self::ChannelEOF),
            _ => bail!("unknown message type: 0x{:02x}", b),
        }
    }
}

// ── Channel types ───────────────────────────────────────────────────

/// Known channel type strings (payload of ChannelOpen).
pub const CHAN_TYPE_EXEC: &str = "exec";
pub const CHAN_TYPE_TUNNEL: &str = "tunnel";
pub const CHAN_TYPE_SHELL: &str = "shell";
pub const CHAN_TYPE_UDP_TUNNEL: &str = "udp-tunnel";

// ── Wire message ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MuxMessage {
    pub channel_id: u32,
    pub msg_type: MsgType,
    pub payload: Vec<u8>,
}

// ── Wire I/O ────────────────────────────────────────────────────────

/// Read a single mux message from the stream.
///
/// Header: 4-byte BE length + 4-byte BE channelID + 1-byte type
/// Payload: `length - 5` bytes
pub async fn read_message<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> Result<MuxMessage> {
    let mut header = [0u8; 9];
    reader
        .read_exact(&mut header)
        .await
        .context("read mux header")?;

    let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let channel_id = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let msg_type = MsgType::from_byte(header[8])?;

    let payload_len = length.saturating_sub(5);
    if payload_len > MAX_PAYLOAD_SIZE {
        bail!("message too large: {} bytes", payload_len);
    }

    let mut payload = vec![0u8; payload_len as usize];
    if payload_len > 0 {
        reader
            .read_exact(&mut payload)
            .await
            .context("read mux payload")?;
    }

    Ok(MuxMessage {
        channel_id,
        msg_type,
        payload,
    })
}

/// Write a single mux message to the stream.
///
/// Header: 4-byte BE length (= 5 + payload_len) + 4-byte BE channelID + 1-byte type
pub async fn write_message<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    msg: &MuxMessage,
) -> Result<()> {
    let payload_len = msg.payload.len();
    let total_len: u32 = 5 + payload_len as u32; // channelID(4) + type(1) + payload

    let mut buf = vec![0u8; 4 + total_len as usize];
    buf[0..4].copy_from_slice(&total_len.to_be_bytes());
    buf[4..8].copy_from_slice(&msg.channel_id.to_be_bytes());
    buf[8] = msg.msg_type as u8;
    if payload_len > 0 {
        buf[9..].copy_from_slice(&msg.payload);
    }

    writer.write_all(&buf).await.context("write mux message")?;
    writer.flush().await.context("flush mux message")?;
    Ok(())
}

/// Parse the ChannelOpen payload: `chanType\0target` or just `chanType`.
pub fn parse_open_payload(payload: &[u8]) -> (String, String) {
    if let Some(idx) = payload.iter().position(|&b| b == 0) {
        let chan_type = String::from_utf8_lossy(&payload[..idx]).to_string();
        let target = String::from_utf8_lossy(&payload[idx + 1..]).to_string();
        (chan_type, target)
    } else {
        (String::from_utf8_lossy(payload).to_string(), String::new())
    }
}

// ── Server-side mux (Windows only) ─────────────────────────────────

#[cfg(windows)]
mod server {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use tokio::net::{TcpStream, UdpSocket};
    use tokio::sync::{Mutex, RwLock, mpsc};
    use tracing::{debug, info, warn};

    // ── MuxWriter — type-erased shared writer ───────────────────────

    /// Shared writer that channel handlers use to send messages back to the client.
    #[derive(Clone)]
    struct MuxWriter {
        inner: Arc<Mutex<Box<dyn AsyncWrite + Unpin + Send>>>,
    }

    impl MuxWriter {
        fn new<W: AsyncWrite + Unpin + Send + 'static>(w: W) -> Self {
            Self {
                inner: Arc::new(Mutex::new(Box::new(w))),
            }
        }

        async fn send(&self, msg: &MuxMessage) -> Result<()> {
            let mut w = self.inner.lock().await;
            write_message(&mut **w, msg).await
        }

        async fn shutdown(&self) {
            let mut w = self.inner.lock().await;
            let _ = w.shutdown().await;
        }
    }

    // ── ServerMuxConn ───────────────────────────────────────────────

    /// Server-side multiplexed connection.
    pub struct ServerMuxConn {
        writer: MuxWriter,
        channels: Arc<RwLock<HashMap<u32, ChannelHandle>>>,
        closed: Arc<AtomicBool>,
    }

    /// Bookkeeping for a live channel.
    struct ChannelHandle {
        data_tx: mpsc::Sender<Vec<u8>>,
        closed: Arc<AtomicBool>,
        #[allow(dead_code)]
        eof_recv: Arc<AtomicBool>,
    }

    /// Opaque reader half, passed to `serve()`.
    pub struct MuxReader {
        inner: Box<dyn AsyncRead + Unpin + Send>,
    }

    impl ServerMuxConn {
        /// Create a mux from a stream, splitting it into read and write halves.
        pub fn new<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
            stream: S,
        ) -> (Self, MuxReader) {
            let (read_half, write_half) = tokio::io::split(stream);

            let conn = Self {
                writer: MuxWriter::new(write_half),
                channels: Arc::new(RwLock::new(HashMap::new())),
                closed: Arc::new(AtomicBool::new(false)),
            };

            let reader = MuxReader {
                inner: Box::new(read_half),
            };

            (conn, reader)
        }

        /// Main serve loop — reads messages and dispatches them.
        /// Returns when the connection is closed or a read error occurs.
        pub async fn serve(self, mut reader: MuxReader) -> Result<()> {
            let result = self.read_loop(&mut reader).await;
            self.close().await;
            result
        }

        async fn read_loop(&self, reader: &mut MuxReader) -> Result<()> {
            loop {
                match read_message(&mut *reader.inner).await {
                    Ok(msg) => self.handle_message(msg).await,
                    Err(e) => {
                        if !self.closed.load(Ordering::Acquire) {
                            warn!("[MUX] read error: {}", e);
                        }
                        return Ok(());
                    }
                }
            }
        }

        async fn handle_message(&self, msg: MuxMessage) {
            match msg.msg_type {
                MsgType::ChannelOpen => {
                    self.handle_channel_open(msg).await;
                }

                MsgType::ChannelData => {
                    let channels = self.channels.read().await;
                    if let Some(ch) = channels.get(&msg.channel_id) {
                        if !ch.closed.load(Ordering::Acquire) {
                            let _ = ch.data_tx.send(msg.payload).await;
                        }
                    }
                }

                MsgType::ChannelEOF => {
                    let channels = self.channels.read().await;
                    if let Some(ch) = channels.get(&msg.channel_id) {
                        ch.eof_recv.store(true, Ordering::Release);
                    }
                }

                MsgType::ChannelClose => {
                    let mut channels = self.channels.write().await;
                    if let Some(ch) = channels.remove(&msg.channel_id) {
                        ch.closed.store(true, Ordering::Release);
                    }
                }

                _ => {
                    debug!(
                        "[MUX] ignoring server-unexpected msg type {:?}",
                        msg.msg_type
                    );
                }
            }
        }

        async fn handle_channel_open(&self, msg: MuxMessage) {
            let (chan_type, target) = parse_open_payload(&msg.payload);

            let (data_tx, data_rx) = mpsc::channel(CHANNEL_BUFFER);
            let closed = Arc::new(AtomicBool::new(false));
            let eof_recv = Arc::new(AtomicBool::new(false));

            let handle = ChannelHandle {
                data_tx,
                closed: Arc::clone(&closed),
                eof_recv: Arc::clone(&eof_recv),
            };

            {
                let mut channels = self.channels.write().await;
                channels.insert(msg.channel_id, handle);
            }

            info!(
                "[MUX] channel {} opened: type={} target={}",
                msg.channel_id, chan_type, target
            );

            let ch = ChannelWriter {
                id: msg.channel_id,
                writer: self.writer.clone(),
                closed,
                eof_sent: AtomicBool::new(false),
            };

            let channels = Arc::clone(&self.channels);
            let channel_id = msg.channel_id;

            match chan_type.as_str() {
                CHAN_TYPE_TUNNEL => {
                    let target = target.clone();
                    tokio::spawn(async move {
                        handle_tunnel_channel(&ch, &target, data_rx).await;
                        channels.write().await.remove(&channel_id);
                    });
                }
                CHAN_TYPE_UDP_TUNNEL => {
                    let target = target.clone();
                    tokio::spawn(async move {
                        handle_udp_tunnel_channel(&ch, &target, data_rx).await;
                        channels.write().await.remove(&channel_id);
                    });
                }
                CHAN_TYPE_EXEC => {
                    tokio::spawn(async move {
                        handle_exec_channel(&ch, data_rx).await;
                        channels.write().await.remove(&channel_id);
                    });
                }
                CHAN_TYPE_SHELL => {
                    tokio::spawn(async move {
                        handle_shell_channel(&ch).await;
                        channels.write().await.remove(&channel_id);
                    });
                }
                _ => {
                    self.reject_channel(
                        msg.channel_id,
                        &format!("unknown channel type: {}", chan_type),
                    )
                    .await;
                }
            }
        }

        async fn reject_channel(&self, channel_id: u32, reason: &str) {
            let msg = MuxMessage {
                channel_id,
                msg_type: MsgType::ChannelReject,
                payload: reason.as_bytes().to_vec(),
            };
            if let Err(e) = self.writer.send(&msg).await {
                warn!(
                    "[MUX] failed to send reject for channel {}: {}",
                    channel_id, e
                );
            }

            let mut channels = self.channels.write().await;
            if let Some(ch) = channels.remove(&channel_id) {
                ch.closed.store(true, Ordering::Release);
            }
        }

        /// Close the mux connection and all channels.
        async fn close(&self) {
            if self
                .closed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return;
            }

            let mut channels = self.channels.write().await;
            for (_, ch) in channels.drain() {
                ch.closed.store(true, Ordering::Release);
            }

            self.writer.shutdown().await;
        }
    }

    // ── ChannelWriter ───────────────────────────────────────────────

    /// Write-side handle for a single channel.  Used by spawned channel handlers
    /// to send data, EOF, and close messages back to the client.
    struct ChannelWriter {
        id: u32,
        writer: MuxWriter,
        closed: Arc<AtomicBool>,
        eof_sent: AtomicBool,
    }

    impl ChannelWriter {
        async fn confirm(&self) {
            let msg = MuxMessage {
                channel_id: self.id,
                msg_type: MsgType::ChannelConfirm,
                payload: Vec::new(),
            };
            let _ = self.writer.send(&msg).await;
        }

        async fn reject(&self, reason: &str) {
            let msg = MuxMessage {
                channel_id: self.id,
                msg_type: MsgType::ChannelReject,
                payload: reason.as_bytes().to_vec(),
            };
            let _ = self.writer.send(&msg).await;
        }

        async fn write_data(&self, data: &[u8]) -> Result<()> {
            if self.closed.load(Ordering::Acquire) {
                bail!("channel closed");
            }
            let msg = MuxMessage {
                channel_id: self.id,
                msg_type: MsgType::ChannelData,
                payload: data.to_vec(),
            };
            self.writer.send(&msg).await
        }

        async fn send_eof(&self) {
            if self
                .eof_sent
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let msg = MuxMessage {
                    channel_id: self.id,
                    msg_type: MsgType::ChannelEOF,
                    payload: Vec::new(),
                };
                let _ = self.writer.send(&msg).await;
            }
        }

        async fn close_channel(&self) {
            if self
                .closed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let msg = MuxMessage {
                    channel_id: self.id,
                    msg_type: MsgType::ChannelClose,
                    payload: Vec::new(),
                };
                let _ = self.writer.send(&msg).await;
            }
        }
    }

    // ── Channel handlers ────────────────────────────────────────────

    /// TCP tunnel: connect to target, bidirectional relay.
    async fn handle_tunnel_channel(
        ch: &ChannelWriter,
        target: &str,
        mut data_rx: mpsc::Receiver<Vec<u8>>,
    ) {
        let target_conn = match TcpStream::connect(target).await {
            Ok(c) => c,
            Err(e) => {
                warn!("[MUX] tunnel connect to {} failed: {}", target, e);
                ch.reject(&e.to_string()).await;
                return;
            }
        };
        target_conn.set_nodelay(true).ok();

        info!("[MUX] tunnel established to {}", target);
        ch.confirm().await;

        let (mut target_read, mut target_write) = target_conn.into_split();
        let closed = &ch.closed;

        // Client -> Target
        let client_to_target = async {
            while let Some(data) = data_rx.recv().await {
                if closed.load(Ordering::Acquire) {
                    break;
                }
                if target_write.write_all(&data).await.is_err() {
                    break;
                }
            }
        };

        // Target -> Client
        let target_to_client = async {
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                match target_read.read(&mut buf).await {
                    Ok(0) => {
                        ch.send_eof().await;
                        break;
                    }
                    Ok(n) => {
                        if ch.write_data(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        ch.send_eof().await;
                        break;
                    }
                }
            }
        };

        tokio::select! {
            _ = client_to_target => {}
            _ = target_to_client => {}
        }

        ch.close_channel().await;
    }

    /// UDP tunnel: connect to target, datagram relay.
    async fn handle_udp_tunnel_channel(
        ch: &ChannelWriter,
        target: &str,
        mut data_rx: mpsc::Receiver<Vec<u8>>,
    ) {
        let udp_conn = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                warn!("[MUX] UDP bind failed: {}", e);
                ch.reject(&e.to_string()).await;
                return;
            }
        };

        if let Err(e) = udp_conn.connect(target).await {
            warn!("[MUX] UDP connect to {} failed: {}", target, e);
            ch.reject(&e.to_string()).await;
            return;
        }

        info!("[MUX] UDP tunnel established to {}", target);
        ch.confirm().await;

        let closed = &ch.closed;

        // Client -> Target (each channel message = one UDP datagram)
        let client_to_target = async {
            while let Some(data) = data_rx.recv().await {
                if closed.load(Ordering::Acquire) {
                    break;
                }
                if let Err(e) = udp_conn.send(&data).await {
                    warn!("[MUX] UDP write error: {}", e);
                    break;
                }
            }
        };

        // Target -> Client (each UDP packet = one channel message)
        let target_to_client = async {
            let mut buf = vec![0u8; 65535];
            loop {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    udp_conn.recv(&mut buf),
                )
                .await
                {
                    Ok(Ok(n)) => {
                        if ch.write_data(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Ok(Err(_)) => break,
                    Err(_) => {
                        // Timeout — check if channel is still alive
                        if closed.load(Ordering::Acquire) {
                            break;
                        }
                        continue;
                    }
                }
            }
        };

        tokio::select! {
            _ = client_to_target => {}
            _ = target_to_client => {}
        }

        ch.close_channel().await;
    }

    /// Exec channel: read command from first data message, execute, send response.
    async fn handle_exec_channel(ch: &ChannelWriter, mut data_rx: mpsc::Receiver<Vec<u8>>) {
        let cmd_data = tokio::select! {
            Some(data) = data_rx.recv() => data,
            else => return,
        };

        let command = String::from_utf8_lossy(&cmd_data).to_string();
        let resp = crate::exec::handle_exec(&command, &[]).await;

        ch.confirm().await;

        let resp_bytes = if resp.success {
            resp.output.unwrap_or_default().into_bytes()
        } else {
            format!("ERROR: {}", resp.error.unwrap_or_default()).into_bytes()
        };

        let _ = ch.write_data(&resp_bytes).await;
        ch.send_eof().await;
        ch.close_channel().await;
    }

    /// Shell channel: stub (not yet implemented).
    async fn handle_shell_channel(ch: &ChannelWriter) {
        ch.confirm().await;
        let _ = ch.write_data(b"Shell not yet implemented over mux\n").await;
        ch.close_channel().await;
    }
}

#[cfg(windows)]
pub use server::*;

// ── Tests (cross-platform — protocol only) ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn message_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let msg = MuxMessage {
            channel_id: 42,
            msg_type: MsgType::ChannelData,
            payload: b"hello mux".to_vec(),
        };

        write_message(&mut client, &msg).await.unwrap();
        let received = read_message(&mut server).await.unwrap();

        assert_eq!(received.channel_id, 42);
        assert_eq!(received.msg_type, MsgType::ChannelData);
        assert_eq!(received.payload, b"hello mux");
    }

    #[tokio::test]
    async fn message_empty_payload() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let msg = MuxMessage {
            channel_id: 1,
            msg_type: MsgType::ChannelConfirm,
            payload: Vec::new(),
        };

        write_message(&mut client, &msg).await.unwrap();
        let received = read_message(&mut server).await.unwrap();

        assert_eq!(received.channel_id, 1);
        assert_eq!(received.msg_type, MsgType::ChannelConfirm);
        assert!(received.payload.is_empty());
    }

    #[tokio::test]
    async fn message_all_types_roundtrip() {
        let types = [
            MsgType::ChannelOpen,
            MsgType::ChannelConfirm,
            MsgType::ChannelReject,
            MsgType::ChannelData,
            MsgType::ChannelClose,
            MsgType::ChannelEOF,
        ];

        for msg_type in types {
            let (mut client, mut server) = tokio::io::duplex(4096);

            let msg = MuxMessage {
                channel_id: 99,
                msg_type,
                payload: vec![0xAA, 0xBB],
            };

            write_message(&mut client, &msg).await.unwrap();
            let received = read_message(&mut server).await.unwrap();

            assert_eq!(received.msg_type, msg_type);
            assert_eq!(received.payload, vec![0xAA, 0xBB]);
        }
    }

    #[tokio::test]
    async fn wire_format_layout() {
        // Verify the exact binary layout:
        //   [4B length=5+payload_len] [4B channelID] [1B type] [payload]
        let (mut client, mut server) = tokio::io::duplex(4096);

        let msg = MuxMessage {
            channel_id: 7,
            msg_type: MsgType::ChannelData, // 0x03
            payload: b"AB".to_vec(),
        };

        write_message(&mut client, &msg).await.unwrap();

        // Read raw bytes
        let mut raw = [0u8; 11]; // 4 + 4 + 1 + 2
        server.read_exact(&mut raw).await.unwrap();

        // length = 5 + 2 = 7 -> [0,0,0,7]
        assert_eq!(&raw[0..4], &[0, 0, 0, 7]);
        // channelID = 7 -> [0,0,0,7]
        assert_eq!(&raw[4..8], &[0, 0, 0, 7]);
        // type = 0x03
        assert_eq!(raw[8], 0x03);
        // payload = "AB"
        assert_eq!(&raw[9..11], b"AB");
    }

    #[tokio::test]
    async fn wire_format_no_payload() {
        // Verify wire format for messages with no payload (e.g. ChannelClose)
        let (mut client, mut server) = tokio::io::duplex(4096);

        let msg = MuxMessage {
            channel_id: 3,
            msg_type: MsgType::ChannelClose, // 0x04
            payload: Vec::new(),
        };

        write_message(&mut client, &msg).await.unwrap();

        let mut raw = [0u8; 9]; // 4 + 4 + 1, no payload
        server.read_exact(&mut raw).await.unwrap();

        // length = 5 (channelID + type, no payload)
        assert_eq!(&raw[0..4], &[0, 0, 0, 5]);
        assert_eq!(&raw[4..8], &[0, 0, 0, 3]);
        assert_eq!(raw[8], 0x04);
    }

    #[test]
    fn parse_open_payload_with_target() {
        let payload = b"tunnel\0127.0.0.1:8080";
        let (chan_type, target) = parse_open_payload(payload);
        assert_eq!(chan_type, "tunnel");
        assert_eq!(target, "127.0.0.1:8080");
    }

    #[test]
    fn parse_open_payload_no_target() {
        let payload = b"exec";
        let (chan_type, target) = parse_open_payload(payload);
        assert_eq!(chan_type, "exec");
        assert_eq!(target, "");
    }

    #[test]
    fn parse_open_payload_udp_tunnel() {
        let payload = b"udp-tunnel\0192.168.1.1:53";
        let (chan_type, target) = parse_open_payload(payload);
        assert_eq!(chan_type, "udp-tunnel");
        assert_eq!(target, "192.168.1.1:53");
    }

    #[test]
    fn msg_type_from_byte_valid() {
        assert_eq!(MsgType::from_byte(0x00).unwrap(), MsgType::ChannelOpen);
        assert_eq!(MsgType::from_byte(0x01).unwrap(), MsgType::ChannelConfirm);
        assert_eq!(MsgType::from_byte(0x02).unwrap(), MsgType::ChannelReject);
        assert_eq!(MsgType::from_byte(0x03).unwrap(), MsgType::ChannelData);
        assert_eq!(MsgType::from_byte(0x04).unwrap(), MsgType::ChannelClose);
        assert_eq!(MsgType::from_byte(0x05).unwrap(), MsgType::ChannelEOF);
    }

    #[test]
    fn msg_type_from_byte_invalid() {
        assert!(MsgType::from_byte(0x06).is_err());
        assert!(MsgType::from_byte(0xFF).is_err());
    }

    #[tokio::test]
    async fn message_too_large_rejected() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        // Craft a header claiming length = 5 + 11MB (exceeds MAX_PAYLOAD_SIZE)
        let fake_length: u32 = 5 + 11 * 1024 * 1024;
        let mut header = [0u8; 9];
        header[0..4].copy_from_slice(&fake_length.to_be_bytes());
        header[4..8].copy_from_slice(&0u32.to_be_bytes());
        header[8] = 0x03;

        client.write_all(&header).await.unwrap();
        client.flush().await.unwrap();

        let result = read_message(&mut server).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[tokio::test]
    async fn multiple_messages_sequential() {
        let (mut client, mut server) = tokio::io::duplex(8192);

        for i in 0..5u32 {
            let msg = MuxMessage {
                channel_id: i,
                msg_type: MsgType::ChannelData,
                payload: format!("msg-{}", i).into_bytes(),
            };
            write_message(&mut client, &msg).await.unwrap();
        }

        for i in 0..5u32 {
            let received = read_message(&mut server).await.unwrap();
            assert_eq!(received.channel_id, i);
            assert_eq!(received.payload, format!("msg-{}", i).into_bytes());
        }
    }

    #[tokio::test]
    async fn large_payload_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(2 * 1024 * 1024);

        // 1MB payload — within limit
        let payload = vec![0x42u8; 1024 * 1024];
        let msg = MuxMessage {
            channel_id: 10,
            msg_type: MsgType::ChannelData,
            payload: payload.clone(),
        };

        write_message(&mut client, &msg).await.unwrap();
        let received = read_message(&mut server).await.unwrap();

        assert_eq!(received.channel_id, 10);
        assert_eq!(received.payload.len(), 1024 * 1024);
        assert_eq!(received.payload, payload);
    }

    #[tokio::test]
    async fn interleaved_channels() {
        // Simulate messages from different channels interleaved on the wire
        let (mut client, mut server) = tokio::io::duplex(8192);

        let messages = vec![
            MuxMessage {
                channel_id: 1,
                msg_type: MsgType::ChannelData,
                payload: b"ch1-a".to_vec(),
            },
            MuxMessage {
                channel_id: 2,
                msg_type: MsgType::ChannelData,
                payload: b"ch2-a".to_vec(),
            },
            MuxMessage {
                channel_id: 1,
                msg_type: MsgType::ChannelData,
                payload: b"ch1-b".to_vec(),
            },
            MuxMessage {
                channel_id: 2,
                msg_type: MsgType::ChannelEOF,
                payload: Vec::new(),
            },
            MuxMessage {
                channel_id: 1,
                msg_type: MsgType::ChannelClose,
                payload: Vec::new(),
            },
        ];

        for msg in &messages {
            write_message(&mut client, msg).await.unwrap();
        }

        for expected in &messages {
            let received = read_message(&mut server).await.unwrap();
            assert_eq!(received.channel_id, expected.channel_id);
            assert_eq!(received.msg_type, expected.msg_type);
            assert_eq!(received.payload, expected.payload);
        }
    }
}
