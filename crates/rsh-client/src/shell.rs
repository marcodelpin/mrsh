//! Interactive shell relay — bidirectional terminal over wire protocol.
//! Client-side counterpart to rsh-server's ConPTY shell handler.
//! SSH-like tilde escape sequences: ~. disconnect, ~~ literal ~, ~? help.

use anyhow::{Context, Result, bail};
use crossterm::terminal;
use rsh_core::wire;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

use crate::client::{RshClient, simple_request};

/// Run an interactive shell session.
/// Puts the terminal into raw mode, relays I/O between stdin/stdout and
/// the server's ConPTY, handles resize and tilde escapes.
pub async fn run_shell<S: AsyncRead + AsyncWrite + Unpin + Send>(
    client: &mut RshClient<S>,
    env_vars: &[String],
) -> Result<()> {
    // Get terminal size
    let (cols, rows) = terminal::size().unwrap_or((80, 24));
    let size_str = format!("{}x{}", cols, rows);

    // Send shell request
    let mut req = simple_request("shell");
    req.command = Some(size_str);
    if !env_vars.is_empty() {
        req.env_vars = Some(env_vars.to_vec());
    }
    let resp = client.request(&req).await?;
    if !resp.success {
        bail!(
            "shell failed: {}",
            resp.error.as_deref().unwrap_or("unknown error")
        );
    }

    // Enter raw mode
    terminal::enable_raw_mode().context("enable raw terminal mode")?;

    // Run the relay, ensuring we restore terminal on any exit path
    let result = relay_loop(client.stream_mut()).await;

    // Always restore terminal
    terminal::disable_raw_mode().ok();

    match result {
        Ok(ShellExit::Disconnect) => {
            eprintln!("\r\nConnection closed.\r");
            Ok(())
        }
        Ok(ShellExit::ServerEof) => {
            eprintln!("\r\nShell session ended.\r");
            Ok(())
        }
        Err(e) => {
            eprintln!("\r\nShell error: {}\r", e);
            Err(e)
        }
    }
}

enum ShellExit {
    Disconnect,
    ServerEof,
}

/// Bidirectional relay between local terminal and remote shell.
async fn relay_loop<S: AsyncRead + AsyncWrite + Unpin + Send>(stream: &mut S) -> Result<ShellExit> {
    let mut stdin_buf = vec![0u8; 4096];
    let mut after_newline = true;
    let mut in_escape = false;

    // Use tokio's stdin for non-blocking async reads
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    loop {
        tokio::select! {
            // stdin → server
            result = stdin.read(&mut stdin_buf) => {
                match result {
                    Ok(0) => {
                        // EOF on stdin
                        wire::send_message(stream, &[]).await.ok();
                        return Ok(ShellExit::Disconnect);
                    }
                    Ok(n) => {
                        let input = &stdin_buf[..n];
                        let (out, action) = process_escapes(
                            input,
                            &mut after_newline,
                            &mut in_escape,
                        );

                        match action {
                            EscapeAction::Continue => {
                                if !out.is_empty() {
                                    wire::send_message(stream, &out).await
                                        .context("send to server")?;
                                }
                            }
                            EscapeAction::Disconnect => {
                                wire::send_message(stream, &[]).await.ok();
                                return Ok(ShellExit::Disconnect);
                            }
                            EscapeAction::Help => {
                                let help = "\r\nSupported escape sequences:\r\n  ~.  - terminate connection\r\n  ~~  - send the escape character (~)\r\n  ~?  - this help\r\n";
                                stdout.write_all(help.as_bytes()).await.ok();
                                stdout.flush().await.ok();
                                // Also send any non-escape output
                                if !out.is_empty() {
                                    wire::send_message(stream, &out).await
                                        .context("send to server")?;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("stdin read error: {}", e);
                        wire::send_message(stream, &[]).await.ok();
                        return Ok(ShellExit::Disconnect);
                    }
                }
            }

            // server → stdout
            result = wire::recv_message(stream) => {
                match result {
                    Ok(data) if data.is_empty() => {
                        return Ok(ShellExit::ServerEof);
                    }
                    Ok(data) => {
                        stdout.write_all(&data).await
                            .context("write to stdout")?;
                        stdout.flush().await.ok();
                    }
                    Err(_) => {
                        return Ok(ShellExit::ServerEof);
                    }
                }
            }
        }
    }
}

enum EscapeAction {
    Continue,
    Disconnect,
    Help,
}

/// Process SSH-like tilde escape sequences.
/// Returns (output_bytes, action).
fn process_escapes(
    input: &[u8],
    after_newline: &mut bool,
    in_escape: &mut bool,
) -> (Vec<u8>, EscapeAction) {
    let mut out = Vec::with_capacity(input.len());
    let mut action = EscapeAction::Continue;

    for &b in input {
        if *in_escape {
            *in_escape = false;
            match b {
                b'.' => {
                    action = EscapeAction::Disconnect;
                    return (out, action);
                }
                b'~' => {
                    out.push(b'~');
                    *after_newline = false;
                }
                b'?' => {
                    action = EscapeAction::Help;
                    *after_newline = true;
                }
                _ => {
                    // Not an escape — send both ~ and the char
                    out.push(b'~');
                    out.push(b);
                    *after_newline = b == b'\r' || b == b'\n';
                }
            }
            continue;
        }

        if *after_newline && b == b'~' {
            *in_escape = true;
            continue;
        }

        *after_newline = b == b'\r' || b == b'\n';
        out.push(b);
    }

    (out, action)
}

/// Encode a resize control message: [0x01][cols_hi][cols_lo][rows_hi][rows_lo].
pub fn encode_resize(cols: u16, rows: u16) -> Vec<u8> {
    vec![
        0x01,
        (cols >> 8) as u8,
        (cols & 0xff) as u8,
        (rows >> 8) as u8,
        (rows & 0xff) as u8,
    ]
}

/// Send a terminal resize control message.
pub async fn send_resize<S: AsyncWrite + Unpin>(
    stream: &mut S,
    cols: u16,
    rows: u16,
) -> Result<()> {
    let msg = encode_resize(cols, rows);
    wire::send_message(stream, &msg).await
}

// ── Persistent session (attach) ──────────────────────────────

/// Attach to a persistent shell session.
/// If `session_id` is empty, creates a new persistent session.
/// If `read_only` is true, attaches in read-only mode.
pub async fn run_attach<S: AsyncRead + AsyncWrite + Unpin + Send>(
    client: &mut RshClient<S>,
    session_id: &str,
    read_only: bool,
    env_vars: &[String],
) -> Result<()> {
    let (cols, rows) = terminal::size().unwrap_or((80, 24));
    let size_str = format!("{}x{}", cols, rows);

    let mut req = simple_request("shell-persistent");
    req.command = Some(size_str);
    if !session_id.is_empty() {
        req.path = Some(session_id.to_string());
    }
    if read_only {
        req.binary = Some(true);
    }
    if !env_vars.is_empty() {
        req.env_vars = Some(env_vars.to_vec());
    }
    let resp = client.request(&req).await?;
    if !resp.success {
        bail!(
            "attach failed: {}",
            resp.error.as_deref().unwrap_or("unknown error")
        );
    }

    // Print session info if server returned it
    if let Some(ref output) = resp.output
        && !output.is_empty()
    {
        eprintln!("session: {}", output);
    }

    terminal::enable_raw_mode().context("enable raw terminal mode")?;
    let result = relay_loop(client.stream_mut()).await;
    terminal::disable_raw_mode().ok();

    match result {
        Ok(ShellExit::Disconnect) => {
            eprintln!("\r\nDetached from session.\r");
            Ok(())
        }
        Ok(ShellExit::ServerEof) => {
            eprintln!("\r\nSession ended.\r");
            Ok(())
        }
        Err(e) => {
            eprintln!("\r\nSession error: {}\r", e);
            Err(e)
        }
    }
}

// ── Wake on LAN ──────────────────────────────────────────────

/// Send a Wake-on-LAN magic packet.
pub fn send_wol(mac: &str) -> Result<()> {
    let mac_bytes = parse_mac(mac)?;
    let mut packet = vec![0xFF; 6];
    for _ in 0..16 {
        packet.extend_from_slice(&mac_bytes);
    }

    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").context("bind UDP")?;
    socket.set_broadcast(true).context("set broadcast")?;
    socket
        .send_to(&packet, "255.255.255.255:9")
        .context("send WoL packet")?;
    Ok(())
}

fn parse_mac(mac: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = mac.split([':', '-']).collect();
    if parts.len() != 6 {
        bail!("invalid MAC address: {}", mac);
    }
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] =
            u8::from_str_radix(part, 16).with_context(|| format!("invalid MAC byte: {}", part))?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_disconnect() {
        let mut after_nl = true;
        let mut in_esc = false;
        let (out, action) = process_escapes(b"~.", &mut after_nl, &mut in_esc);
        assert!(out.is_empty());
        assert!(matches!(action, EscapeAction::Disconnect));
    }

    #[test]
    fn escape_literal_tilde() {
        let mut after_nl = true;
        let mut in_esc = false;
        let (out, action) = process_escapes(b"~~", &mut after_nl, &mut in_esc);
        assert_eq!(out, b"~");
        assert!(matches!(action, EscapeAction::Continue));
    }

    #[test]
    fn escape_help() {
        let mut after_nl = true;
        let mut in_esc = false;
        let (out, _action) = process_escapes(b"~?", &mut after_nl, &mut in_esc);
        assert!(out.is_empty());
    }

    #[test]
    fn escape_not_after_newline() {
        let mut after_nl = false;
        let mut in_esc = false;
        let (out, action) = process_escapes(b"~.", &mut after_nl, &mut in_esc);
        assert_eq!(out, b"~.");
        assert!(matches!(action, EscapeAction::Continue));
    }

    #[test]
    fn escape_after_cr() {
        let mut after_nl = false;
        let mut in_esc = false;
        let (out, _) = process_escapes(b"\r", &mut after_nl, &mut in_esc);
        assert_eq!(out, b"\r");
        assert!(after_nl);
    }

    #[test]
    fn normal_text_passthrough() {
        let mut after_nl = false;
        let mut in_esc = false;
        let (out, action) = process_escapes(b"hello world", &mut after_nl, &mut in_esc);
        assert_eq!(out, b"hello world");
        assert!(matches!(action, EscapeAction::Continue));
    }

    #[test]
    fn encode_resize_format() {
        let msg = encode_resize(120, 40);
        assert_eq!(msg.len(), 5);
        assert_eq!(msg[0], 0x01);
        assert_eq!((msg[1] as u16) << 8 | msg[2] as u16, 120);
        assert_eq!((msg[3] as u16) << 8 | msg[4] as u16, 40);
    }

    #[test]
    fn parse_mac_valid() {
        let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn parse_mac_dashes() {
        let mac = parse_mac("AA-BB-CC-DD-EE-FF").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn parse_mac_invalid() {
        assert!(parse_mac("invalid").is_err());
        assert!(parse_mac("aa:bb:cc:dd:ee").is_err());
        assert!(parse_mac("aa:bb:cc:dd:ee:gg").is_err());
    }

    #[test]
    fn wol_packet_structure() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut packet = vec![0xFF; 6];
        for _ in 0..16 {
            packet.extend_from_slice(&mac);
        }
        assert_eq!(packet.len(), 6 + 16 * 6); // 102 bytes
        assert!(packet[0..6].iter().all(|&b| b == 0xFF));
        assert_eq!(&packet[6..12], &mac);
    }

    #[test]
    fn escape_unknown_sequence() {
        let mut after_nl = true;
        let mut in_esc = false;
        let (out, action) = process_escapes(b"~x", &mut after_nl, &mut in_esc);
        assert_eq!(out, b"~x");
        assert!(matches!(action, EscapeAction::Continue));
    }

    #[test]
    fn escape_split_across_reads() {
        let mut after_nl = true;
        let mut in_esc = false;
        // First read: just the tilde
        let (out1, _) = process_escapes(b"~", &mut after_nl, &mut in_esc);
        assert!(out1.is_empty());
        assert!(in_esc);
        // Second read: the command char
        let (out2, action) = process_escapes(b".", &mut after_nl, &mut in_esc);
        assert!(out2.is_empty());
        assert!(matches!(action, EscapeAction::Disconnect));
    }
}
