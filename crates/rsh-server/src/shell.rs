//! Shell relay protocol — bidirectional terminal over length-prefixed frames.
//! On Windows: uses ConPTY. On Linux (testing): uses /bin/sh with pty.
//! Control message: 0x01 + cols(2 BE) + rows(2 BE) = resize.

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, info};

use rsh_core::wire;

/// Resize control byte prefix.
const RESIZE_PREFIX: u8 = 0x01;

/// Parse terminal size from "COLSxROWS" string (e.g., "80x24").
pub fn parse_size(size_str: &str) -> (u16, u16) {
    let parts: Vec<&str> = size_str.split('x').collect();
    if parts.len() == 2 {
        let cols = parts[0].parse().unwrap_or(80);
        let rows = parts[1].parse().unwrap_or(24);
        (cols, rows)
    } else {
        (80, 24)
    }
}

/// Check if a message is a resize control message.
/// Format: [0x01][cols_high][cols_low][rows_high][rows_low]
pub fn parse_resize(data: &[u8]) -> Option<(u16, u16)> {
    if data.len() >= 5 && data[0] == RESIZE_PREFIX {
        let cols = (data[1] as u16) << 8 | data[2] as u16;
        let rows = (data[3] as u16) << 8 | data[4] as u16;
        Some((cols, rows))
    } else {
        None
    }
}

/// Encode a resize control message.
pub fn encode_resize(cols: u16, rows: u16) -> Vec<u8> {
    vec![
        RESIZE_PREFIX,
        (cols >> 8) as u8,
        (cols & 0xff) as u8,
        (rows >> 8) as u8,
        (rows & 0xff) as u8,
    ]
}

/// Handle a shell session over the rsh stream using a real PTY.
/// Uses openpty(3) to create a pseudo-terminal pair, spawns the shell with
/// the slave as its controlling terminal. Resize messages are translated to
/// TIOCSWINSZ ioctls + SIGWINCH.
#[cfg(not(target_os = "windows"))]
pub async fn handle_shell<S>(stream: &mut S, size_str: &str, env_vars: &[String]) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use std::os::unix::io::{FromRawFd, RawFd};

    let (cols, rows) = parse_size(size_str);
    info!("PTY shell session: {}x{}", cols, rows);

    // Create PTY pair with initial window size
    let mut master: RawFd = 0;
    let mut slave: RawFd = 0;
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &ws as *const libc::winsize as *mut libc::winsize,
        )
    } != 0
    {
        anyhow::bail!("openpty failed: {}", std::io::Error::last_os_error());
    }

    // Choose best available shell
    let shell = if std::path::Path::new("/bin/bash").exists() {
        "/bin/bash"
    } else {
        "/bin/sh"
    };

    // Spawn child with slave PTY as controlling terminal
    let slave_fd = slave;
    let master_fd = master;
    let mut cmd = tokio::process::Command::new(shell);
    cmd.env("TERM", "xterm-256color");
    cmd.kill_on_drop(true);
    for e in env_vars {
        if let Some((k, v)) = e.split_once('=') {
            cmd.env(k, v);
        }
    }
    unsafe {
        cmd.pre_exec(move || {
            // Close master fd in child (only parent uses it)
            libc::close(master_fd);
            // Create new session
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Set controlling terminal
            if libc::ioctl(slave_fd, libc::TIOCSCTTY, 0 as libc::c_int) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Redirect stdio to slave PTY
            libc::dup2(slave_fd, 0);
            libc::dup2(slave_fd, 1);
            libc::dup2(slave_fd, 2);
            if slave_fd > 2 {
                libc::close(slave_fd);
            }
            Ok(())
        });
    }

    let child = cmd.spawn().context("spawn shell")?;
    let child_pid = child.id().unwrap_or(0) as libc::pid_t;
    // Keep child alive (kill_on_drop fires when dropped at end of scope)
    let _child = child;

    // Close slave in parent (child has its own copy after fork)
    unsafe {
        libc::close(slave);
    }

    // Duplicate master fd for separate read/write ownership
    let master_write_fd = unsafe { libc::dup(master) };
    if master_write_fd < 0 {
        anyhow::bail!(
            "dup(master) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    // Spawn blocking reader thread (PTY master → channel)
    // Same pattern as Windows ConPTY reader at lines 244-260.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let reader_task = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut f = unsafe { std::fs::File::from_raw_fd(master) };
        let mut buf = [0u8; 32768];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    // EIO = slave side closed (child exited) — normal PTY teardown
                    if e.raw_os_error() == Some(libc::EIO) {
                        break;
                    }
                    debug!("PTY read error: {}", e);
                    break;
                }
            }
        }
        // f dropped here → closes master fd
    });

    // Write handle for master PTY
    let mut master_file = unsafe { std::fs::File::from_raw_fd(master_write_fd) };

    // Bidirectional relay loop
    loop {
        tokio::select! {
            // Client → PTY
            result = wire::recv_message(stream) => {
                match result {
                    Ok(data) if data.is_empty() => {
                        debug!("shell: client EOF");
                        break;
                    }
                    Ok(data) => {
                        // Check for resize control message
                        if let Some((c, r)) = parse_resize(&data) {
                            let new_ws = libc::winsize {
                                ws_row: r,
                                ws_col: c,
                                ws_xpixel: 0,
                                ws_ypixel: 0,
                            };
                            unsafe {
                                libc::ioctl(master_write_fd, libc::TIOCSWINSZ, &new_ws);
                                // TIOCSWINSZ on master sends SIGWINCH to foreground pgrp,
                                // but also signal child process group explicitly
                                if child_pid > 0 {
                                    libc::kill(-child_pid, libc::SIGWINCH);
                                }
                            }
                            continue;
                        }
                        // Forward data to PTY
                        use std::io::Write;
                        if master_file.write_all(&data).is_err()
                            || master_file.flush().is_err()
                        {
                            debug!("shell: PTY write failed");
                            break;
                        }
                    }
                    Err(_) => {
                        debug!("shell: client disconnected");
                        break;
                    }
                }
            }
            // PTY → Client
            msg = rx.recv() => {
                match msg {
                    Some(data) => {
                        if wire::send_message(stream, &data).await.is_err() {
                            debug!("shell: send to client failed");
                            break;
                        }
                    }
                    None => {
                        // Reader thread exited — child process ended
                        debug!("shell: process exited");
                        break;
                    }
                }
            }
        }
    }

    // Cleanup: close master write → reader thread gets EIO → exits
    drop(master_file);
    reader_task.abort();
    // Send EOF to client
    wire::send_message(stream, &[]).await.ok();
    info!("PTY shell session ended");
    Ok(())
}

/// Windows ConPTY shell handler — real pseudo-console implementation.
///
/// Creates a ConPTY (pseudo-console) attached to powershell.exe, then relays
/// I/O between the rsh wire protocol and the ConPTY pipes.  Resize control
/// messages (0x01 prefix) are translated to `ResizePseudoConsole` calls.
#[cfg(target_os = "windows")]
pub async fn handle_shell<S>(stream: &mut S, size_str: &str, env_vars: &[String]) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Console::{
        COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, ResizePseudoConsole,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        STARTUPINFOEXW, UpdateProcThreadAttribute,
    };

    let _ = env_vars; // TODO: pass environment to child process
    let (cols, rows) = parse_size(size_str);
    info!("ConPTY shell session: {}x{}", cols, rows);

    // --- Create anonymous pipes for ConPTY ---
    let (pty_in_write, pty_out_read, hpc, proc_raw, thread_raw) = unsafe {
        let mut pty_in_read = HANDLE::default();
        let mut pty_in_write = HANDLE::default();
        let mut pty_out_read = HANDLE::default();
        let mut pty_out_write = HANDLE::default();

        CreatePipe(&mut pty_in_read, &mut pty_in_write, None, 0).context("CreatePipe input")?;
        CreatePipe(&mut pty_out_read, &mut pty_out_write, None, 0).context("CreatePipe output")?;

        // --- Create pseudo console ---
        let size = COORD {
            X: cols as i16,
            Y: rows as i16,
        };
        let hpc = CreatePseudoConsole(size, pty_in_read, pty_out_write, 0)
            .context("CreatePseudoConsole")?;

        // ConPTY now owns copies of these pipe ends
        let _ = CloseHandle(pty_in_read);
        let _ = CloseHandle(pty_out_write);

        // --- Prepare process attribute list ---
        let mut attr_size: usize = 0;
        // First call: get required buffer size (returns error by design)
        let _ = InitializeProcThreadAttributeList(None, 1, None, &mut attr_size);

        let mut attr_buf = vec![0u8; attr_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as _);
        InitializeProcThreadAttributeList(Some(attr_list), 1, None, &mut attr_size)
            .context("InitializeProcThreadAttributeList")?;

        // PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
        const PSEUDOCONSOLE_ATTR: usize = 0x00020016;
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PSEUDOCONSOLE_ATTR,
            Some(&hpc as *const HPCON as *const std::ffi::c_void),
            std::mem::size_of::<HPCON>(),
            None,
            None,
        )
        .context("UpdateProcThreadAttribute")?;

        // --- Create child process (powershell) ---
        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attr_list;

        let mut pi = PROCESS_INFORMATION::default();
        let mut cmd: Vec<u16> = "powershell.exe\0".encode_utf16().collect();

        CreateProcessW(
            windows::core::PCWSTR::null(),
            Some(windows::core::PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            windows::core::PCWSTR::null(),
            &si.StartupInfo,
            &mut pi,
        )
        .context("CreateProcessW")?;

        DeleteProcThreadAttributeList(attr_list);
        // attr_buf dropped here — safe, attribute list no longer needed

        // Extract raw handle values from PROCESS_INFORMATION.
        // HANDLE(*mut c_void) is !Send, but the raw values (usize) are Send.
        // We reconstruct HANDLE only in the non-async cleanup section.
        let proc_raw = pi.hProcess.0 as usize;
        let thread_raw = pi.hThread.0 as usize;

        (pty_in_write, pty_out_read, hpc, proc_raw, thread_raw)
    };

    // --- Convert pipe handles to File for blocking I/O ---
    // HANDLE(pub *mut c_void) — .0 is already RawHandle
    use std::os::windows::io::FromRawHandle;
    let out_file = unsafe { std::fs::File::from_raw_handle(pty_out_read.0) };
    let mut in_file = unsafe { std::fs::File::from_raw_handle(pty_in_write.0) };

    // --- Spawn blocking reader thread (ConPTY output → channel) ---
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let reader_task = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut f = out_file;
        let mut buf = [0u8; 32768];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break, // pipe broken (ConPTY closed)
            }
        }
    });

    // --- Bidirectional relay loop ---
    loop {
        tokio::select! {
            // Client → ConPTY input pipe
            result = wire::recv_message(stream) => {
                match result {
                    Ok(data) if data.is_empty() => {
                        debug!("shell: client EOF");
                        break;
                    }
                    Ok(data) => {
                        // Check for resize control message
                        if let Some((c, r)) = parse_resize(&data) {
                            unsafe {
                                let sz = COORD { X: c as i16, Y: r as i16 };
                                let _ = ResizePseudoConsole(hpc, sz);
                            }
                            continue;
                        }
                        // Forward data to ConPTY input
                        use std::io::Write;
                        if in_file.write_all(&data).is_err()
                            || in_file.flush().is_err()
                        {
                            debug!("shell: input pipe broken");
                            break;
                        }
                    }
                    Err(_) => {
                        debug!("shell: client disconnected");
                        break;
                    }
                }
            }
            // ConPTY output → Client
            msg = rx.recv() => {
                match msg {
                    Some(data) => {
                        if wire::send_message(stream, &data).await.is_err() {
                            debug!("shell: send to client failed");
                            break;
                        }
                    }
                    None => {
                        // Reader thread exited — process ended
                        debug!("shell: process exited");
                        break;
                    }
                }
            }
        }
    }

    // --- Cleanup ---
    // Close ConPTY first — this breaks the pipe and unblocks the reader thread
    unsafe {
        ClosePseudoConsole(hpc);
    }
    // Drop input pipe to signal EOF to ConPTY
    drop(in_file);
    // Wait for reader thread to finish (it should exit once pipe breaks)
    reader_task.abort();
    // Close process handles (reconstruct HANDLE from raw usize values)
    unsafe {
        let _ = CloseHandle(HANDLE(proc_raw as *mut std::ffi::c_void));
        let _ = CloseHandle(HANDLE(thread_raw as *mut std::ffi::c_void));
    }
    // Signal EOF to client
    wire::send_message(stream, &[]).await.ok();
    info!("ConPTY shell session ended");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_valid() {
        assert_eq!(parse_size("80x24"), (80, 24));
        assert_eq!(parse_size("120x40"), (120, 40));
    }

    #[test]
    fn parse_size_invalid_defaults() {
        assert_eq!(parse_size("invalid"), (80, 24));
        assert_eq!(parse_size(""), (80, 24));
    }

    #[test]
    fn parse_resize_valid() {
        let msg = encode_resize(120, 40);
        let (cols, rows) = parse_resize(&msg).unwrap();
        assert_eq!(cols, 120);
        assert_eq!(rows, 40);
    }

    #[test]
    fn parse_resize_too_short() {
        assert!(parse_resize(&[0x01, 0, 80]).is_none());
    }

    #[test]
    fn parse_resize_wrong_prefix() {
        assert!(parse_resize(&[0x02, 0, 80, 0, 24]).is_none());
    }

    #[test]
    fn encode_resize_roundtrip() {
        let encoded = encode_resize(200, 50);
        assert_eq!(encoded.len(), 5);
        let (cols, rows) = parse_resize(&encoded).unwrap();
        assert_eq!(cols, 200);
        assert_eq!(rows, 50);
    }

    #[tokio::test]
    async fn shell_echo_test() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let handle = tokio::spawn(async move { handle_shell(&mut server, "80x24", &[]).await });

        // Send a command
        wire::send_message(&mut client, b"echo hello\n")
            .await
            .unwrap();

        // Read output (may get prompt + echo)
        let output = wire::recv_message(&mut client).await.unwrap();
        assert!(!output.is_empty());

        // Send EOF
        wire::send_message(&mut client, &[]).await.unwrap();

        // Wait for shell to exit
        let _ = handle.await;
    }

    #[tokio::test]
    async fn shell_resize_is_filtered() {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let handle = tokio::spawn(async move { handle_shell(&mut server, "80x24", &[]).await });

        // Send resize control message — should not be forwarded to shell
        let resize = encode_resize(120, 40);
        wire::send_message(&mut client, &resize).await.unwrap();

        // Send actual command after resize
        wire::send_message(&mut client, b"echo resized\n")
            .await
            .unwrap();

        // Should get output (resize was silently consumed)
        let output = wire::recv_message(&mut client).await.unwrap();
        assert!(!output.is_empty());

        wire::send_message(&mut client, &[]).await.unwrap();
        let _ = handle.await;
    }
}
