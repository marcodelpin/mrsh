//! rsh — Remote Shell (Rust rewrite)
//! CLI entry point: client commands + server mode (Windows).
//!
//! Server mode detection:
//!   - `-install`   → register Windows service
//!   - `-uninstall` → remove Windows service
//!   - `-console`   → run server in foreground (debug)
//!   - No `-h` + no local subcommand on Windows → server mode (tray or service)

// Suppress console window on Windows.
// CLI output uses AttachConsole to reattach to parent's console when needed.
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::sync::Arc;

use anyhow::{Result, bail};
use clap::Parser;
use rsh_client::client::ConnectOptions;
use tracing::info;

/// rsh — Remote Shell
#[derive(Parser, Debug)]
#[command(
    name = "rsh",
    version,
    about = "Remote shell tool",
    disable_help_flag = true
)]
struct Cli {
    /// Remote host (IP, hostname, or DeviceID)
    #[arg(short = 'h', long)]
    host: Option<String>,

    /// Print help
    #[arg(long)]
    help: bool,

    /// Remote port
    #[arg(short, long, default_value_t = 8822)]
    port: u16,

    /// SSH key file
    #[arg(short = 'i', long)]
    key: Option<String>,

    /// Verbose output (-v, -vv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Install as system service (Windows: SCM service, Linux: systemd unit)
    #[arg(long = "install", hide = true)]
    install: bool,

    /// Uninstall system service
    #[arg(long = "uninstall", hide = true)]
    uninstall: bool,

    /// Run server in foreground (debug mode)
    #[arg(long = "console", hide = true)]
    console: bool,

    /// Internal: launched by SCM as service (Windows only)
    #[cfg(target_os = "windows")]
    #[arg(long = "service", hide = true)]
    service: bool,

    /// Run as tray (skip SCM dispatch, go directly to tray mode on port 9822)
    #[cfg(target_os = "windows")]
    #[arg(long = "tray", hide = true)]
    tray: bool,

    /// Run as background daemon (Linux only)
    #[cfg(not(target_os = "windows"))]
    #[arg(long = "daemon", hide = true)]
    daemon: bool,

    /// Delete remote files not present locally (mirror mode, push only)
    #[arg(long = "delete")]
    delete: bool,

    /// Username for password auth (fallback when no SSH key)
    #[arg(long = "user")]
    user: Option<String>,

    /// SOCKS5 dynamic proxy port (ssh -D equivalent)
    #[arg(short = 'D', long = "dynamic")]
    dynamic_port: Option<u16>,

    /// Show progress bar with rate and ETA during transfers
    #[arg(long = "progress")]
    progress: bool,

    /// Dry run: show what would be transferred without doing it
    #[arg(long = "dry-run")]
    dry_run: bool,

    /// Backup suffix for overwritten files (e.g. --backup=.bak)
    #[arg(long = "backup")]
    backup: Option<String>,

    /// Bandwidth limit in KB/s (0 = unlimited)
    #[arg(long = "bwlimit", default_value_t = 0)]
    bwlimit: u32,

    /// Global operation timeout in seconds (0 = per-command default)
    #[arg(long = "timeout", default_value_t = 0)]
    timeout: u64,

    /// Start control master (hold connection, serve via UDS)
    #[arg(short = 'M')]
    master: bool,

    /// Skip multiplexing, always open new connection
    #[arg(long = "no-mux")]
    no_mux: bool,

    /// Stop running master for this host
    #[arg(long = "mux-stop")]
    mux_stop: bool,

    /// Use QUIC transport instead of TLS/TCP (experimental, requires --features quic)
    #[cfg(feature = "quic")]
    #[arg(long = "quic")]
    use_quic: bool,

    /// Subcommand and arguments
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,
}

/// Known local subcommands that don't require -h (used in server mode detection).
#[cfg(target_os = "windows")]
const LOCAL_COMMANDS: &[&str] = &["version", "fleet", "wake", "config-edit", "connect", "log", "keygen", "totp-setup", "totp-verify", "install-pack", "relay", "rendezvous"];

/// Returns the effective operation timeout in seconds.
/// Explicit `--timeout N` (N > 0) overrides everything.
/// Per-command defaults: push/pull → 300s, interactive cmds → 0, others → 120s.
fn compute_timeout_secs(explicit: u64, cmd: &str) -> u64 {
    if explicit > 0 {
        return explicit;
    }
    match cmd {
        "shell" | "browse" | "sftp" | "tunnel" | "watch" | "attach" | "socks5" => 0,
        "push" | "pull" => 300,
        _ => 120,
    }
}

fn main() -> Result<()> {
    // Reattach to parent console for CLI output (we're a windowsgui subsystem binary).
    // Skip for --tray mode (tray is a GUI app, no console needed — AllocConsole causes
    // 0xC0000409 crashes on Windows 10 IoT Enterprise LTSC build 19044).
    #[cfg(target_os = "windows")]
    {
        let is_tray_mode = std::env::args().any(|a| a == "--tray");
        if !is_tray_mode {
            unsafe {
                use windows::Win32::System::Console::{
                    AllocConsole, AttachConsole, ATTACH_PARENT_PROCESS,
                    GetConsoleWindow,
                };
                use windows::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE};
                if AttachConsole(ATTACH_PARENT_PROCESS).is_err() {
                    if AllocConsole().is_ok() {
                        let hwnd = GetConsoleWindow();
                        if !hwnd.is_invalid() {
                            let _ = ShowWindow(hwnd, SW_HIDE);
                        }
                    }
                }
            }
        }
    }

    let cli = Cli::parse();

    // Determine if we're running in server mode (needs audit log to file)
    let is_server_mode = cli.console
        || cli.install
        || cli.uninstall
        || {
            #[cfg(target_os = "windows")]
            { cli.service || cli.tray || cli.host.is_none() }
            #[cfg(not(target_os = "windows"))]
            { cli.daemon }
        };

    if is_server_mode {
        // Server mode: log to audit file (+ stderr if console available)
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let data_dir = server_data_dir();
        std::fs::create_dir_all(&data_dir).ok();
        // Use different log file for tray vs service to avoid lock contention
        #[cfg(target_os = "windows")]
        let log_prefix = if std::env::args().any(|a| a == "--tray") { "audit-tray.log" } else { "audit.log" };
        #[cfg(not(target_os = "windows"))]
        let log_prefix = "audit.log";
        let file_appender = tracing_appender::rolling::daily(&data_dir, log_prefix);
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(file_appender)
            .with_ansi(false);
        let filter = tracing_subscriber::EnvFilter::new(match cli.verbose {
            0 => "info",
            1 => "info",
            _ => "debug",
        });

        // Tray mode has no console — skip stderr layer to avoid writing to
        // invalid handle (causes 0xC0000409 on Windows 10 IoT LTSC).
        #[cfg(target_os = "windows")]
        let has_console = !std::env::args().any(|a| a == "--tray");
        #[cfg(not(target_os = "windows"))]
        let has_console = true;

        let stderr_layer = if has_console {
            Some(tracing_subscriber::fmt::layer())
        } else {
            None
        };
        tracing_subscriber::registry()
            .with(filter)
            .with(stderr_layer)
            .with(file_layer)
            .init();
    } else {
        // Client mode: stderr only
        tracing_subscriber::fmt()
            .with_env_filter(match cli.verbose {
                0 => "warn",
                1 => "info",
                _ => "debug",
            })
            .init();
    }
    // ── Cross-platform service/install/uninstall ────────────
    if cli.install {
        let exe = std::env::current_exe()?.to_string_lossy().to_string();
        rsh_server::service::install_service(&exe)?;
        return Ok(());
    }
    if cli.uninstall {
        rsh_server::service::uninstall_service()?;
        return Ok(());
    }
    if cli.console {
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(run_server_mode(cli.port, false));
    }

    // ── Explicit tray mode (Windows) ─────────────────────────
    // Skips SCM dispatch entirely — goes straight to tray on port 9822.
    // Use when service_dispatcher::start() interferes (e.g. schtask launch).
    #[cfg(target_os = "windows")]
    if cli.tray {
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(run_server_mode(9822, true));
    }

    // ── Linux daemon mode ────────────────────────────────────
    #[cfg(not(target_os = "windows"))]
    if cli.daemon {
        let port = cli.port;
        rsh_server::service::run_as_service(move |cancel| {
            let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
            rt.block_on(async {
                if let Err(e) = run_server_mode_with_cancel(port, cancel).await {
                    tracing::error!("server error: {}", e);
                }
            });
        })?;
        return Ok(());
    }

    // ── Windows server mode detection ────────────────────────
    // Must happen BEFORE tokio runtime, because service_dispatcher::start()
    // blocks the main thread and spawns service_main on a new thread.
    #[cfg(target_os = "windows")]
    {
        // Auto-detect service mode:
        // If no -h and no local subcommand → try SCM dispatch first.
        // If SCM dispatch fails → fall through to tray mode.
        let is_local_cmd = cli.args.first().map_or(false, |a| {
            LOCAL_COMMANDS.contains(&a.as_str()) || a == "help" || a == "recording" || a == "config-edit"
        });
        if cli.host.is_none() && !is_local_cmd {
            // Try service mode — service_dispatcher::start() blocks if SCM launched us,
            // returns error immediately if we're not a service.
            let port = cli.port;
            let result = rsh_server::service::run_as_service(move |cancel| {
                let rt = tokio::runtime::Runtime::new().expect("create tokio runtime");
                rt.block_on(async {
                    if let Err(e) = run_server_mode_with_cancel(port, cancel).await {
                        tracing::error!("server error: {}", e);
                    }
                });
            });
            match result {
                Ok(()) => return Ok(()),          // Service ran and stopped cleanly
                Err(_) => {
                    // Not launched by SCM → fall through to tray mode
                    let rt = tokio::runtime::Runtime::new()?;
                    return rt.block_on(run_server_mode(9822, true));
                }
            }
        }
    }

    // ── Non-service path: build tokio runtime and run async main ──
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> Result<()> {
    let args = &cli.args;
    // Default: "version" without -h, "shell" with -h
    let cmd = args
        .first()
        .map(|s| s.as_str())
        .unwrap_or(if cli.host.is_some() {
            "shell"
        } else {
            "version"
        });

    // Help (--help flag or "help" subcommand)
    if cli.help || cmd == "help" {
        print_usage();
        return Ok(());
    }

    // ── Local commands (no -h needed) ────────────────────────
    match cmd {
        "version" => {
            println!("rsh {} (rust)", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        "fleet" => {
            return run_fleet(&args[1..]).await;
        }
        "wake" => {
            if args.len() < 2 {
                bail!("wake requires a MAC address (aa:bb:cc:dd:ee:ff)");
            }
            rsh_client::shell::send_wol(&args[1])?;
            eprintln!("WoL packet sent to {}", args[1]);
            return Ok(());
        }
        "recording" => {
            let sub = args.get(1).map(|s| s.as_str()).unwrap_or("");
            if sub == "export" {
                // Local-only: convert .log+.time to asciicast
                let rest = &args[2..];
                let mut width: u32 = 120;
                let mut height: u32 = 35;
                let mut log_file = String::new();
                let mut out_file = String::new();
                for a in rest {
                    if let Some(w) = a.strip_prefix("--width=") {
                        width = w.parse().unwrap_or(120);
                    } else if let Some(h) = a.strip_prefix("--height=") {
                        height = h.parse().unwrap_or(35);
                    } else if log_file.is_empty() {
                        log_file = a.clone();
                    } else {
                        out_file = a.clone();
                    }
                }
                if log_file.is_empty() {
                    bail!("Usage: rsh recording export <file.log> [output.cast]");
                }
                if out_file.is_empty() {
                    out_file = log_file
                        .strip_suffix(".log")
                        .unwrap_or(&log_file)
                        .to_string()
                        + ".cast";
                }
                rsh_client::recording::export_asciicast(&log_file, &out_file, width, height)?;
                eprintln!("Exported to {}", out_file);
                return Ok(());
            }
            // "list" with no -h → fall through to client section
            if cli.host.is_none() && sub != "list" {
                bail!("Usage: rsh recording <export|list>");
            }
            // list with -h falls through to client commands
        }
        "keygen" => {
            let output = args.get(1).map(|s| std::path::PathBuf::from(s));
            return run_keygen(output.as_deref());
        }
        "totp-setup" => {
            let fingerprint = args.get(1).map(|s| s.as_str());
            return run_totp_setup(fingerprint);
        }
        "totp-verify" => {
            if args.len() < 3 {
                bail!("Usage: rsh totp-verify <fingerprint> <code>");
            }
            return run_totp_verify(&args[1], &args[2]);
        }
        "config-edit" => {
            rsh_client::config_tui::run_config_tui()?;
            return Ok(());
        }
        "connect" => {
            match rsh_client::host_picker::run_host_picker()? {
                rsh_client::host_picker::PickerResult::Selected(host) => {
                    let target = host.hostname.as_deref().unwrap_or(&host.pattern);
                    let port = if host.port > 0 { host.port } else { 8822 };
                    eprintln!("Connecting to {} ({}:{})...", host.pattern, target, port);
                    let opts = ConnectOptions {
                        host: target.to_string(),
                        port,
                        key_path: host.identity_file.clone(),
                        password_user: cli.user.clone(),
                    };
                    let mut client = rsh_client::client::connect(&opts).await?;
                    rsh_client::shell::run_shell(&mut client, &[]).await?;
                    return Ok(());
                }
                rsh_client::host_picker::PickerResult::Cancelled => {
                    return Ok(());
                }
            }
        }
        "log" => {
            return run_log_query(&args[1..]);
        }
        "install-pack" => {
            return run_install_pack(&args[1..]);
        }
        "relay" => {
            return run_relay_server(&args[1..]).await;
        }
        "rendezvous" => {
            return run_rendezvous_server(&args[1..]).await;
        }
        _ => {}
    }

    // ── --mux-stop: stop running master ─────────────────────
    if cli.mux_stop {
        let host = cli.host.as_deref().unwrap_or_else(|| {
            eprintln!("error: -h <host> required for --mux-stop");
            std::process::exit(1);
        });
        return rsh_client::mux::stop_master(host, cli.port).await;
    }

    // ── Server mode: no -h, no local command, on Windows ────
    #[cfg(target_os = "windows")]
    if cli.host.is_none() && !LOCAL_COMMANDS.contains(&cmd) {
        // No host specified, unknown command → default to tray server mode
        info!("no -h flag, launching tray server mode");
        return run_server_mode(9822, true).await;
    }

    // ── Client commands (require -h) ─────────────────────────
    let host = cli.host.as_deref().unwrap_or_else(|| {
        eprintln!("error: -h <host> required");
        std::process::exit(1);
    });

    // Resolve from config
    let config = rsh_core::config::Config::load();
    let host_config = config.find_host(host);
    let (resolved_host, resolved_port) = if let Some(hc) = host_config {
        (
            hc.hostname.as_deref().unwrap_or(host).to_string(),
            if cli.port != 8822 { cli.port } else { hc.port },
        )
    } else {
        (host.to_string(), cli.port)
    };

    // ── Auto-mux: try UDS before opening new connection ──────
    if !cli.no_mux && !cli.master {
        if let Some(mux_req) = rsh_client::mux::build_mux_request(cmd, args) {
            if let Some(resp) = rsh_client::mux::try_request(host, resolved_port, &mux_req).await {
                if resp.success {
                    if let Some(ref output) = resp.output {
                        print!("{}", output);
                    }
                } else {
                    let msg = resp.error.as_deref().unwrap_or("unknown error");
                    eprintln!("error: {}", msg);
                    std::process::exit(1);
                }
                return Ok(());
            }
            // No master running → fall through to normal connect
        }
    }

    // Check for DeviceID — from config or raw host
    let device_id = host_config
        .and_then(|hc| hc.device_id.clone())
        .or_else(|| {
            if rsh_relay::rendezvous::is_device_id(host) {
                Some(host.to_string())
            } else {
                None
            }
        });

    // ── QUIC transport (experimental, --quic flag) ───────────
    #[cfg(feature = "quic")]
    if cli.use_quic {
        use anyhow::Context as _;
        use std::net::ToSocketAddrs;
        let addr = format!("{}:{}", resolved_host, resolved_port)
            .to_socket_addrs()
            .context("resolve host")?
            .next()
            .with_context(|| format!("no address for {}", resolved_host))?;

        let quic = rsh_client::quic::QuicClient::connect(
            addr,
            &resolved_host,
            cli.key.as_deref(),
        )
        .await
        .context("QUIC connect")?;

        match cmd {
            "ping" => {
                println!("PONG (QUIC)");
            }
            "exec" => {
                if args.len() < 2 {
                    bail!("exec requires a command");
                }
                let command = args[1..].join(" ");
                let output = quic.exec(&command).await?;
                print!("{}", output);
            }
            _ => bail!("command {:?} is not supported over QUIC (omit --quic)", cmd),
        }
        quic.close();
        return Ok(());
    }

    let mut client = if let Some(ref dev_id) = device_id {
        // Relay path: resolve via hbbs, connect via P2P or hbbr
        let relay_opts = rsh_client::relay_connect::RelayConnectOptions {
            device_id: dev_id.clone(),
            rendezvous_server: config
                .rendezvous_server
                .as_deref()
                .unwrap_or("localhost:21116")
                .to_string(),
            rendezvous_key: config.rendezvous_key.clone().unwrap_or_default(),
            key_path: cli.key.clone(),
            server_name: resolved_host.clone(),
            port: resolved_port,
        };
        rsh_client::relay_connect::connect_via_relay(&relay_opts).await?
    } else {
        // Direct connection
        let opts = ConnectOptions {
            host: resolved_host.clone(),
            port: resolved_port,
            key_path: cli.key.clone(),
            password_user: cli.user.clone(),
        };
        rsh_client::client::connect(&opts).await?
    };

    // ── Control master mode (-M) ──────────────────────────────
    if cli.master {
        return rsh_client::mux::run_master(host, resolved_port, client).await;
    }

    // ── Session logging ────────────────────────────────────────
    let tracker = if config.is_session_log_enabled(host) {
        let cmd_args = if args.len() > 1 {
            Some(args[1..].join(" "))
        } else {
            None
        };
        // Rotate old logs on session start (cheap: just readdir)
        let log_dir = config.session_log_dir();
        rsh_client::session_log::rotate_logs(&log_dir, config.session_log_retain);
        Some(rsh_client::session_log::SessionTracker::start(
            host,
            resolved_port,
            cmd,
            cmd_args.as_deref(),
            &log_dir,
        ))
    } else {
        None
    };

    // ── SOCKS5 dynamic proxy (-D flag) ───────────────────────
    if let Some(socks_port) = cli.dynamic_port {
        // Drop the initial client — SOCKS5 creates new connections per request
        drop(client);

        let connect_opts = Arc::new(ConnectOptions {
            host: resolved_host.clone(),
            port: resolved_port,
            key_path: cli.key.clone(),
            password_user: cli.user.clone(),
        });

        eprintln!(
            "SOCKS5 proxy: 127.0.0.1:{} → {}:{}",
            socks_port, resolved_host, resolved_port
        );

        let connect_fn = move || {
            let opts = connect_opts.clone();
            async move {
                let client = rsh_client::client::connect(&opts).await?;
                Ok(client.into_stream())
            }
        };

        rsh_client::socks::run_socks5(socks_port, connect_fn).await?;
        return Ok(());
    }

    // Determine operation timeout: explicit --timeout overrides per-command defaults.
    let timeout_secs = compute_timeout_secs(cli.timeout, cmd);

    let cmd_future = async {
    match cmd {
        "ping" => {
            let result = rsh_client::commands::ping(&mut client).await?;
            println!("{}", result);
        }
        "exec" => {
            if args.len() < 2 {
                bail!("exec requires a command");
            }
            let command = args[1..].join(" ");
            let result = rsh_client::commands::exec(&mut client, &command, &[]).await?;
            print!("{}", result);
        }
        "ls" => {
            let path = args.get(1).map(|s| s.as_str()).unwrap_or(".");
            let files = rsh_client::commands::ls(&mut client, path).await?;
            for f in &files {
                let kind = if f.is_dir { "d" } else { "-" };
                println!(
                    "{}{} {:>10} {} {}",
                    kind, f.mode, f.size, f.mod_time, f.name
                );
            }
        }
        "cat" => {
            if args.len() < 2 {
                bail!("cat requires a path");
            }
            let text = rsh_client::commands::cat_text(&mut client, &args[1]).await?;
            print!("{}", text);
        }
        "push" => {
            if args.len() < 3 {
                bail!("push requires <local> <remote>");
            }
            let local_path = std::path::Path::new(&args[1]);
            let meta = std::fs::metadata(local_path)
                .map_err(|e| anyhow::anyhow!("cannot stat {}: {}", args[1], e))?;
            let xfer_opts = rsh_client::sync::TransferOptions {
                progress: cli.progress,
                dry_run: cli.dry_run,
                backup_suffix: cli.backup.clone(),
                bwlimit_kbps: cli.bwlimit,
            };
            if meta.is_dir() {
                let result = rsh_client::sync::push_dir(&mut client, local_path, &args[2], &xfer_opts).await?;
                eprintln!(
                    "pushed directory: {}/{} files, {} bytes",
                    result.files_transferred, result.files_total, result.bytes_total
                );
                if cli.delete {
                    let deleted = rsh_client::sync::delete_remote_extras(
                        &mut client, local_path, &args[2],
                    ).await?;
                    if deleted > 0 {
                        eprintln!("--delete: removed {} remote files", deleted);
                    }
                }
            } else {
                if cli.dry_run {
                    eprintln!("[dry-run] would push {} -> {}", args[1], args[2]);
                } else {
                    let data = std::fs::read(local_path)?;
                    let result = rsh_client::sync::push(&mut client, &data, &args[2]).await?;
                    eprintln!(
                        "pushed {} bytes to {} (delta: {})",
                        result.bytes_sent, result.path, result.delta
                    );
                }
            }
        }
        "pull" => {
            if args.len() < 3 {
                bail!("pull requires <remote> <local>");
            }
            let xfer_opts = rsh_client::sync::TransferOptions {
                progress: cli.progress,
                dry_run: cli.dry_run,
                backup_suffix: cli.backup.clone(),
                bwlimit_kbps: cli.bwlimit,
            };
            // Check if remote is a directory (ls succeeds on dirs)
            let is_dir = {
                let files = rsh_client::commands::ls(&mut client, &args[1]).await;
                files.is_ok()
            };
            if is_dir {
                let local_path = std::path::Path::new(&args[2]);
                let result = rsh_client::sync::pull_dir(&mut client, &args[1], local_path, &xfer_opts).await?;
                eprintln!(
                    "pulled directory: {}/{} files, {} bytes",
                    result.files_transferred, result.files_total, result.bytes_total
                );
            } else {
                if cli.dry_run {
                    eprintln!("[dry-run] would pull {} -> {}", args[1], args[2]);
                } else {
                    let local_data = std::fs::read(&args[2]).ok();
                    let result =
                        rsh_client::sync::pull(&mut client, local_data.as_deref(), &args[1]).await?;
                    std::fs::write(&args[2], &result.data)?;
                    eprintln!(
                        "pulled {} bytes (delta: {})",
                        result.data.len(),
                        result.delta
                    );
                }
            }
        }
        "screenshot" => {
            let display_idx: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let quality: u8 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(75);
            let scale: u8 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(100);
            let data =
                rsh_client::commands::screenshot(&mut client, display_idx, quality, scale).await?;
            let out_path = format!("screenshot_{}.jpg", display_idx);
            std::fs::write(&out_path, &data)?;
            eprintln!("saved {} ({} bytes)", out_path, data.len());
        }
        "sessions" => {
            let action = args.get(1).map(|s| s.as_str()).unwrap_or("list");
            match action {
                "list" => {
                    let result = rsh_client::commands::sessions_list(&mut client).await?;
                    println!("{}", result);
                }
                "kill" => {
                    if args.len() < 3 {
                        bail!("sessions kill requires <session-id>");
                    }
                    rsh_client::commands::session_kill(&mut client, &args[2]).await?;
                    eprintln!("session killed");
                }
                other => bail!("unknown sessions action: {}", other),
            }
        }
        "shell" => {
            let env_vars: Vec<String> = args.iter().skip(1).cloned().collect();
            rsh_client::shell::run_shell(&mut client, &env_vars).await?;
        }
        "attach" => {
            // attach [session-id] [--ro]
            let mut session_id = "";
            let mut read_only = false;
            let mut env_vars = Vec::new();
            for arg in args.iter().skip(1) {
                match arg.as_str() {
                    "--ro" | "--read-only" | "-r" => read_only = true,
                    s if !s.starts_with('-') && session_id.is_empty() => session_id = s,
                    _ => env_vars.push(arg.clone()),
                }
            }
            rsh_client::shell::run_attach(&mut client, session_id, read_only, &env_vars).await?;
        }
        "browse" => {
            let start_path = args.get(1).map(|s| s.as_str()).unwrap_or(".");
            // browse is synchronous TUI — bridge async client via Handle
            let handle = tokio::runtime::Handle::current();
            // RefCell borrow held across block_on is safe: closures run synchronously
            use std::cell::RefCell;
            let client_cell = RefCell::new(client);
            rsh_client::browse::run_browser(
                start_path,
                |dir_path| {
                    let mut c = client_cell.borrow_mut();
                    let result = handle.block_on(rsh_client::commands::ls(&mut *c, dir_path));
                    result.map_err(|e| e.to_string())
                },
                |remote_path, local_path| {
                    let mut c = client_cell.borrow_mut();
                    let result =
                        handle.block_on(rsh_client::sync::pull(&mut *c, None, remote_path));
                    match result {
                        Ok(pr) => {
                            if let Err(e) = std::fs::write(local_path, &pr.data) {
                                eprintln!("write error: {}", e);
                            } else {
                                eprintln!("saved {} ({} bytes)", local_path, pr.data.len());
                            }
                        }
                        Err(e) => eprintln!("pull error: {}", e),
                    }
                },
            );
            // Recover client for clean shutdown
            client = client_cell.into_inner();
            drop(client);
            return Ok(());
        }
        "sftp" => {
            let host_display = cli.host.as_deref().unwrap_or("unknown");
            rsh_client::sftp::run_sftp(&mut client, host_display).await?;
        }
        "tunnel" => {
            // rsh -h host tunnel <local_bind> <remote_host:remote_port>
            // rsh -h host tunnel 127.0.0.1:5432 db-server:5432
            // rsh -h host tunnel 5432 db-server:5432
            if args.len() < 3 {
                bail!("tunnel requires: <local_bind> <remote_host:port>");
            }
            let (local_bind, remote_target) =
                rsh_client::tunnel::parse_tunnel_spec(&args[1], &args[2])?;
            eprintln!("tunnel: {} → {} via {}", local_bind, remote_target, resolved_host);
            rsh_client::tunnel::run_tunnel(client.stream_mut(), &local_bind, &remote_target).await?;
        }
        "recording" => {
            // Only "list" reaches here (export handled in local section)
            let output = rsh_client::recording::list_remote(&mut client).await?;
            print!("{}", output);
        }
        "write" => {
            if args.len() < 3 {
                bail!("write requires <remote-path> <content>");
            }
            let content = args[2..].join(" ");
            rsh_client::commands::write_file(&mut client, &args[1], content.as_bytes()).await?;
            eprintln!("wrote {} bytes to {}", content.len(), args[1]);
        }
        "self-update" => {
            if args.len() < 2 {
                bail!("self-update requires <remote-binary-path>");
            }
            let result = rsh_client::commands::self_update(&mut client, &args[1]).await?;
            eprintln!("{}", result);
        }
        "input" => {
            // rsh -h host input mouse pos
            // rsh -h host input mouse move 500,300
            if args.len() < 3 {
                bail!("input requires <type> <action> [args...]");
            }
            let extra = if args.len() > 3 {
                args[3..].join(" ")
            } else {
                String::new()
            };
            let result =
                rsh_client::commands::input(&mut client, &args[1], &args[2], &extra)
                    .await?;
            println!("{}", result);
        }
        "ps" => {
            let result = rsh_client::commands::ps(&mut client).await?;
            println!("{}", result);
        }
        "kill" => {
            if args.len() < 2 {
                bail!("kill requires a PID");
            }
            let result = rsh_client::commands::kill_process(&mut client, &args[1]).await?;
            println!("{}", result);
        }
        "tail" => {
            if args.len() < 2 {
                bail!("tail requires <path> [lines]");
            }
            let lines: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
            let result = rsh_client::commands::tail(&mut client, &args[1], lines).await?;
            print!("{}", result);
        }
        "filever" => {
            if args.len() < 2 {
                bail!("filever requires <path>");
            }
            let result = rsh_client::commands::filever(&mut client, &args[1]).await?;
            println!("{}", result);
        }
        "info" => {
            let result = rsh_client::commands::info(&mut client).await?;
            println!("{}", result);
        }
        "eventlog" | "evtlog" => {
            let log_name = args.get(1).map(|s| s.as_str()).unwrap_or("System");
            let count: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(50);
            let result = rsh_client::commands::eventlog(&mut client, log_name, count).await?;
            println!("{}", result);
        }
        "clip" | "clipboard" => {
            let action = args.get(1).map(|s| s.as_str()).unwrap_or("get");
            match action {
                "get" | "read" => {
                    let result = rsh_client::commands::clip_get(&mut client).await?;
                    print!("{}", result);
                }
                "set" | "write" | "copy" => {
                    if args.len() < 3 {
                        bail!("clip set requires text");
                    }
                    let text = args[2..].join(" ");
                    let result = rsh_client::commands::clip_set(&mut client, &text).await?;
                    println!("{}", result);
                }
                other => bail!("unknown clip action: {} (use get|set)", other),
            }
        }
        "service" | "svc" => {
            if args.len() < 2 {
                bail!("service requires: list|status|start|stop|restart [name]");
            }
            let name = args.get(2).map(|s| s.as_str());
            let result = rsh_client::commands::service(&mut client, &args[1], name).await?;
            println!("{}", result);
        }
        "plugin" => {
            if args.len() < 2 {
                bail!("plugin requires <action> [args...]");
            }
            let plugin_args = args[1..].join(" ");
            let result = rsh_client::commands::plugin(&mut client, &plugin_args).await?;
            if !result.is_empty() {
                println!("{}", result);
            }
        }
        "reboot" => {
            let force = args
                .get(1)
                .map(|s| s == "-f" || s == "--force")
                .unwrap_or(false);
            if !force {
                eprint!("Reboot {}:{}? [y/N] ", resolved_host, resolved_port);
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                let a = answer.trim().to_lowercase();
                if a != "y" && a != "yes" && a != "si" {
                    return Ok(());
                }
            }
            eprintln!("Rebooting {}:{}...", resolved_host, resolved_port);
            rsh_client::commands::exec(&mut client, "Restart-Computer -Force", &[])
                .await
                .ok();
        }
        "shutdown" => {
            let force = args
                .get(1)
                .map(|s| s == "-f" || s == "--force")
                .unwrap_or(false);
            if !force {
                eprint!("Shutdown {}:{}? [y/N] ", resolved_host, resolved_port);
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                let a = answer.trim().to_lowercase();
                if a != "y" && a != "yes" && a != "si" {
                    return Ok(());
                }
            }
            eprintln!("Shutting down {}:{}...", resolved_host, resolved_port);
            rsh_client::commands::exec(&mut client, "Stop-Computer -Force", &[])
                .await
                .ok();
            eprintln!("Shutdown command sent.");
        }
        "sleep" => {
            let force = args
                .get(1)
                .map(|s| s == "-f" || s == "--force")
                .unwrap_or(false);
            if !force {
                eprint!("Sleep {}:{}? [y/N] ", resolved_host, resolved_port);
                let mut answer = String::new();
                std::io::stdin().read_line(&mut answer)?;
                let a = answer.trim().to_lowercase();
                if a != "y" && a != "yes" && a != "si" {
                    return Ok(());
                }
            }
            eprintln!("Putting {}:{} to sleep...", resolved_host, resolved_port);
            rsh_client::commands::exec(
                &mut client,
                "Add-Type -Assembly System.Windows.Forms; [System.Windows.Forms.Application]::SetSuspendState([System.Windows.Forms.PowerState]::Suspend, $true, $false)",
                &[],
            ).await.ok();
            eprintln!("Sleep command sent.");
        }
        "lock" => {
            eprintln!(
                "Locking workstation on {}:{}...",
                resolved_host, resolved_port
            );
            rsh_client::commands::exec(&mut client, "rundll32.exe user32.dll,LockWorkStation", &[])
                .await?;
            eprintln!("Workstation locked.");
        }
        "mouse" | "key" | "window" => {
            // GUI automation: rsh -h host mouse move 500 300
            if args.len() < 3 {
                bail!("{} requires <action> <args>", cmd);
            }
            let result =
                rsh_client::commands::input(&mut client, cmd, &args[1], &args[2..].join(" "))
                    .await?;
            if !result.is_empty() {
                println!("{}", result);
            }
        }
        "cache" => {
            if args.len() < 2 {
                bail!("cache requires: stats|index [path]");
            }
            match args[1].as_str() {
                "stats" => {
                    let req = rsh_client::commands::build_request("sync", None, None, None);
                    let mut req = req;
                    req.sync_type = Some("cache-stats".to_string());
                    let resp = client.request(&req).await?;
                    if !resp.success {
                        bail!("{}", resp.error.as_deref().unwrap_or("cache stats failed"));
                    }
                    println!("{}", resp.output.unwrap_or_default());
                }
                "index" => {
                    if args.len() < 3 {
                        bail!("cache index requires <remote-path>");
                    }
                    let mut req =
                        rsh_client::commands::build_request("sync", None, Some(&args[2]), None);
                    req.sync_type = Some("index-dir".to_string());
                    let resp = client.request(&req).await?;
                    if !resp.success {
                        bail!("{}", resp.error.as_deref().unwrap_or("index failed"));
                    }
                    println!("{}", resp.output.unwrap_or_default());
                }
                other => bail!("unknown cache action: {} (use stats|index)", other),
            }
        }
        "status" => {
            let count: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
            let mut rtts = Vec::with_capacity(count);
            let mut failures = 0usize;

            for i in 0..count {
                let start = std::time::Instant::now();
                match rsh_client::commands::ping(&mut client).await {
                    Ok(_) => {
                        let elapsed = start.elapsed();
                        eprintln!("  ping {}: {:.1?}", i + 1, elapsed);
                        rtts.push(elapsed);
                    }
                    Err(e) => {
                        failures += 1;
                        eprintln!("  ping {}: FAILED ({})", i + 1, e);
                    }
                }
                if i < count - 1 {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }

            eprintln!();
            if !rtts.is_empty() {
                rtts.sort();
                let min = rtts[0];
                let max = rtts[rtts.len() - 1];
                let p50 = rtts[rtts.len() / 2];
                let avg = rtts.iter().sum::<std::time::Duration>() / rtts.len() as u32;
                let loss = failures as f64 / count as f64 * 100.0;

                println!(
                    "--- {}:{} ping statistics ---",
                    resolved_host, resolved_port
                );
                println!(
                    "{} transmitted, {} received, {:.0}% loss",
                    count,
                    rtts.len(),
                    loss
                );
                println!(
                    "rtt min/avg/max/p50 = {:.1?}/{:.1?}/{:.1?}/{:.1?}",
                    min, avg, max, p50
                );

                let quality = if loss > 50.0 {
                    "POOR (high packet loss)"
                } else if avg > std::time::Duration::from_millis(500) {
                    "POOR (high latency)"
                } else if loss > 10.0 || avg > std::time::Duration::from_millis(200) {
                    "FAIR"
                } else if avg > std::time::Duration::from_millis(50) {
                    "GOOD"
                } else {
                    "EXCELLENT"
                };
                println!("quality: {}", quality);
            }

            // Remote info
            println!("\n--- remote info ---");
            if let Ok(info_json) = rsh_client::commands::info(&mut client).await {
                println!("{}", info_json)
            }
        }
        "watch" => {
            if args.len() < 3 {
                bail!("watch requires <local-dir> <remote-dir>");
            }
            run_watch(&mut client, &args[1], &args[2]).await?;
        }
        "server-version" => {
            let result = rsh_client::commands::ping(&mut client).await?;
            println!("{}", result);
        }
        _other => {
            // Unknown command → treat as exec
            let command = args.join(" ");
            let result = rsh_client::commands::exec(&mut client, &command, &[]).await?;
            print!("{}", result);
        }
    }
    Ok(())
    };

    let cmd_result: Result<()> = if timeout_secs > 0 {
        match tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            cmd_future,
        ).await {
            Ok(result) => result,
            Err(_) => bail!("operation timed out after {}s (use --timeout to override)", timeout_secs),
        }
    } else {
        cmd_future.await
    };

    // Finish session log
    if let Some(tracker) = tracker {
        tracker.finish(if cmd_result.is_ok() { 0 } else { 1 });
    }

    cmd_result
}

/// Generate ed25519 keypair in OpenSSH format.
fn run_keygen(output: Option<&std::path::Path>) -> Result<()> {
    use anyhow::Context;
    use rsh_core::auth;

    let default_dir = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".rsh");
    let default_key = default_dir.join("id_ed25519");
    let key_path = output.unwrap_or(&default_key);

    if key_path.exists() {
        bail!(
            "key file already exists: {}\nUse a different path or remove the existing key first.",
            key_path.display()
        );
    }

    // Generate using the same logic as server key generation
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let ed_kp = ssh_key::private::Ed25519Keypair {
        public: ssh_key::public::Ed25519PublicKey(signing_key.verifying_key().to_bytes()),
        private: ssh_key::private::Ed25519PrivateKey::from_bytes(&signing_key.to_bytes()),
    };
    let comment = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "rsh".to_string());
    let private_key =
        ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Ed25519(ed_kp), &comment)
            .context("create ed25519 private key")?;

    let openssh_str = private_key
        .to_openssh(ssh_key::LineEnding::LF)
        .context("serialize key to OpenSSH format")?
        .to_string();

    // Ensure parent directory exists
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create directory: {}", parent.display()))?;
    }

    // Write private key
    std::fs::write(&key_path, &openssh_str)
        .with_context(|| format!("write key: {}", key_path.display()))?;

    // Set permissions to 0600 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Write public key (.pub) — SSH wire format: [4-byte len]["ssh-ed25519"][4-byte len][32-byte key]
    let pub_key_path = std::path::PathBuf::from(format!("{}.pub", key_path.display()));
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let key_type_bytes = b"ssh-ed25519";
    let mut wire = Vec::new();
    wire.extend_from_slice(&(key_type_bytes.len() as u32).to_be_bytes());
    wire.extend_from_slice(key_type_bytes);
    wire.extend_from_slice(&(pub_bytes.len() as u32).to_be_bytes());
    wire.extend_from_slice(&pub_bytes);
    let pub_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &wire);
    let pub_key_str = format!("ssh-ed25519 {} {}\n", pub_b64, comment);

    std::fs::write(&pub_key_path, &pub_key_str)
        .with_context(|| format!("write public key: {}", pub_key_path.display()))?;

    let fingerprint = auth::key_fingerprint(&pub_bytes);
    eprintln!("Generated ed25519 key pair:");
    eprintln!("  Private: {}", key_path.display());
    eprintln!("  Public:  {}", pub_key_path.display());
    eprintln!("  Fingerprint: {}", fingerprint);
    eprintln!();
    eprintln!("Add to server's authorized_keys:");
    eprintln!("  {}", pub_key_str.trim());

    Ok(())
}

/// Generate TOTP secret for a key fingerprint.
///
/// Creates a random base32 secret and outputs:
/// - The secret (for adding to server's totp_secrets file)
/// - An otpauth:// URI (for QR code / authenticator app import)
/// - Recovery codes (for adding to server's totp_recovery file)
fn run_totp_setup(fingerprint: Option<&str>) -> Result<()> {
    use anyhow::Context;
    use rsh_core::auth;
    use sha2::{Digest, Sha256};

    let fp = if let Some(fp) = fingerprint {
        fp.to_string()
    } else {
        // Try to read the default key and compute its fingerprint
        let key_pair = auth::discover_key().context(
            "no fingerprint provided and no default key found.\n\
             Usage: rsh totp-setup [fingerprint]\n\
             Or ensure ~/.ssh/id_ed25519 exists.",
        )?;
        let raw_pub = key_pair.public_key_bytes();
        auth::key_fingerprint(&raw_pub)
    };

    let secret = auth::generate_totp_secret();

    // Generate recovery codes (10 random 8-char hex codes)
    let mut recovery_codes = Vec::new();
    let mut recovery_hashes = Vec::new();
    for _ in 0..10 {
        let mut buf = [0u8; 4];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut buf);
        let code = buf.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let digest = Sha256::digest(code.as_bytes());
        let hash = digest.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        recovery_codes.push(code);
        recovery_hashes.push(hash);
    }

    let uri = format!(
        "otpauth://totp/rsh:{}?secret={}&issuer=rsh&algorithm=SHA1&digits=6&period=30",
        fp, secret
    );

    eprintln!("TOTP setup for key: {}", fp);
    eprintln!();
    eprintln!("Secret (base32): {}", secret);
    eprintln!();
    eprintln!("otpauth URI (for authenticator app):");
    eprintln!("  {}", uri);
    eprintln!();
    eprintln!("Add to server's totp_secrets file:");
    eprintln!("  {} {}", fp, secret);
    eprintln!();
    eprintln!("Recovery codes (save these! each can be used once):");
    for code in &recovery_codes {
        eprintln!("  {}", code);
    }
    eprintln!();
    eprintln!("Add to server's totp_recovery file:");
    eprintln!("  {} {}", fp, recovery_hashes.join(" "));
    eprintln!();
    eprintln!("Add 'totp' option to the key in authorized_keys:");
    eprintln!("  totp ssh-ed25519 AAAA... comment");

    Ok(())
}

/// Verify a TOTP code against a secret (for testing setup).
fn run_totp_verify(secret_or_fingerprint: &str, code: &str) -> Result<()> {
    use rsh_core::auth;

    // If it looks like a base32 secret (all uppercase + digits, length 32+), use directly.
    // Otherwise treat as fingerprint and look up in totp_secrets file.
    let secret = if secret_or_fingerprint.len() >= 16
        && secret_or_fingerprint
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '=')
    {
        secret_or_fingerprint.to_string()
    } else {
        // Look up fingerprint in server data dir
        let data_dir = server_data_dir();
        let totp_path = data_dir.join("totp_secrets");
        if !totp_path.exists() {
            bail!(
                "totp_secrets file not found at {}\nProvide a base32 secret directly, or create the file.",
                totp_path.display()
            );
        }
        let secrets = auth::load_totp_secrets(&totp_path)?;
        let found = auth::find_totp_secret(secret_or_fingerprint, &secrets);
        match found {
            Some(s) => s.secret_base32.clone(),
            None => bail!(
                "no TOTP secret found for fingerprint: {}",
                secret_or_fingerprint
            ),
        }
    };

    match auth::verify_totp(&secret, code)? {
        true => {
            eprintln!("TOTP code is valid.");
            Ok(())
        }
        false => {
            bail!("TOTP code is invalid.");
        }
    }
}

/// Query and display session logs.
fn run_log_query(args: &[String]) -> Result<()> {
    let config = rsh_core::config::Config::load();
    let log_dir = config.session_log_dir();

    let mut host_filter = None;
    let mut since = None;
    let mut until = None;
    let mut show_detail = false;
    let mut json_output = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--host" => {
                i += 1;
                host_filter = args.get(i).map(|s| s.to_string());
            }
            "--since" => {
                i += 1;
                if let Some(s) = args.get(i) {
                    since = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok();
                }
            }
            "--until" => {
                i += 1;
                if let Some(s) = args.get(i) {
                    until = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok();
                }
            }
            "--detail" | "-d" => show_detail = true,
            "--json" => json_output = true,
            other if other.starts_with("--host=") => {
                host_filter = Some(other.strip_prefix("--host=").unwrap().to_string());
            }
            other if other.starts_with("--since=") => {
                since = chrono::NaiveDate::parse_from_str(
                    other.strip_prefix("--since=").unwrap(),
                    "%Y-%m-%d",
                )
                .ok();
            }
            other if other.starts_with("--until=") => {
                until = chrono::NaiveDate::parse_from_str(
                    other.strip_prefix("--until=").unwrap(),
                    "%Y-%m-%d",
                )
                .ok();
            }
            _ => {}
        }
        i += 1;
    }

    let filter = rsh_client::session_log::LogFilter {
        host: host_filter,
        since,
        until,
    };

    let entries = rsh_client::session_log::query_logs(&log_dir, &filter);

    if entries.is_empty() {
        eprintln!("No session log entries found in {}", log_dir.display());
        if !config.session_log {
            eprintln!("Hint: session logging is disabled. Remove 'SessionLog false' from ~/.rsh/config to re-enable.");
        }
        return Ok(());
    }

    if json_output {
        for entry in &entries {
            println!("{}", serde_json::to_string(entry)?);
        }
        return Ok(());
    }

    if show_detail {
        println!(
            "{:<20} {:>5} {:<8} {:<30} {:>10} {:>4}",
            "HOST", "PORT", "CMD", "ARGS", "DURATION", "EXIT"
        );
        println!("{}", "-".repeat(80));
        for entry in &entries {
            println!(
                "{:<20} {:>5} {:<8} {:<30} {:>10} {:>4}",
                entry.host,
                entry.port,
                entry.cmd,
                entry
                    .args
                    .as_deref()
                    .unwrap_or("")
                    .chars()
                    .take(30)
                    .collect::<String>(),
                rsh_client::session_log::format_duration(entry.duration_s),
                entry.exit,
            );
        }
        println!("{}", "-".repeat(80));
    }

    // Summary by host
    let summaries = rsh_client::session_log::summarize_by_host(&entries);

    println!(
        "\n{:<25} {:>10} {:>8} {:>12} {:>12}",
        "HOST", "COMMANDS", "HOURS", "FIRST", "LAST"
    );
    println!("{}", "=".repeat(70));

    let mut total_seconds = 0.0;
    let mut total_commands = 0u64;

    for s in &summaries {
        total_seconds += s.total_seconds;
        total_commands += s.command_count;
        let hours = s.total_seconds / 3600.0;
        let first = s
            .first_seen
            .as_ref()
            .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_default();
        let last = s
            .last_seen
            .as_ref()
            .and_then(|ts| chrono::DateTime::parse_from_rfc3339(ts).ok())
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_default();
        println!(
            "{:<25} {:>10} {:>8.1} {:>12} {:>12}",
            s.host, s.command_count, hours, first, last,
        );
    }

    println!("{}", "-".repeat(70));
    println!(
        "{:<25} {:>10} {:>8.1}",
        "TOTAL",
        total_commands,
        total_seconds / 3600.0,
    );

    Ok(())
}

/// Generate an install pack for deploying rsh to a new machine.
fn run_install_pack(args: &[String]) -> Result<()> {
    let mut platform = if cfg!(target_os = "windows") {
        "windows".to_string()
    } else {
        "linux".to_string()
    };
    let mut output = None;
    let mut binary = None;
    let mut extra_keys = Vec::new();
    let mut port = 8822u16;
    let mut nas_auth = None;
    let mut group = None;
    let mut rendezvous_server = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--platform" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    platform = p.clone();
                }
            }
            "--output" | "-o" => {
                i += 1;
                if let Some(o) = args.get(i) {
                    output = Some(std::path::PathBuf::from(o));
                }
            }
            "--binary" => {
                i += 1;
                if let Some(b) = args.get(i) {
                    binary = Some(std::path::PathBuf::from(b));
                }
            }
            "--key" => {
                i += 1;
                if let Some(k) = args.get(i) {
                    // Could be a key string or a path to a file
                    let path = std::path::Path::new(k);
                    if path.exists() {
                        let content =
                            std::fs::read_to_string(path).with_context(|| format!("read key file: {}", k))?;
                        extra_keys.push(content.trim().to_string());
                    } else {
                        extra_keys.push(k.clone());
                    }
                }
            }
            "--port" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    port = p.parse().unwrap_or(8822);
                }
            }
            "--nas-auth" => {
                i += 1;
                if let Some(n) = args.get(i) {
                    nas_auth = Some(n.clone());
                }
            }
            "--group" => {
                i += 1;
                if let Some(g) = args.get(i) {
                    group = Some(g.clone());
                }
            }
            "--rendezvous-server" => {
                i += 1;
                if let Some(r) = args.get(i) {
                    rendezvous_server = Some(r.clone());
                }
            }
            other if other.starts_with("--platform=") => {
                platform = other.strip_prefix("--platform=").unwrap().to_string();
            }
            other if other.starts_with("--output=") || other.starts_with("-o=") => {
                let val = other.split_once('=').unwrap().1;
                output = Some(std::path::PathBuf::from(val));
            }
            other if other.starts_with("--binary=") => {
                binary = Some(std::path::PathBuf::from(
                    other.strip_prefix("--binary=").unwrap(),
                ));
            }
            other if other.starts_with("--port=") => {
                port = other
                    .strip_prefix("--port=")
                    .unwrap()
                    .parse()
                    .unwrap_or(8822);
            }
            other if other.starts_with("--nas-auth=") => {
                nas_auth = Some(other.strip_prefix("--nas-auth=").unwrap().to_string());
            }
            other if other.starts_with("--group=") => {
                group = Some(other.strip_prefix("--group=").unwrap().to_string());
            }
            other if other.starts_with("--rendezvous-server=") => {
                rendezvous_server = Some(other.strip_prefix("--rendezvous-server=").unwrap().to_string());
            }
            _ => {
                bail!(
                    "Unknown install-pack option: {other}\n\
                     Usage: rsh install-pack [--platform windows|linux] [--output FILE] [--binary PATH]\n\
                     \x20      [--key KEY_OR_FILE] [--port PORT] [--nas-auth CMD]\n\
                     \x20      [--group NAME] [--rendezvous-server HOST:PORT]\n\
                     \x20      Linux: produces self-extracting .sh (bash + tar.gz)\n\
                     \x20      Windows: produces NSIS installer .exe (requires makensis)",
                    other = args[i]
                );
            }
        }
        i += 1;
    }

    use anyhow::Context;
    let opts = rsh_client::install_pack::InstallPackOptions {
        platform,
        output,
        binary,
        extra_keys,
        port,
        nas_auth,
        group,
        rendezvous_server,
    };

    println!("Generating install pack...");
    let out_file = rsh_client::install_pack::generate(&opts)?;
    println!("\nDone: {}", out_file.display());
    Ok(())
}

/// Run the relay server (hbbr).
async fn run_relay_server(args: &[String]) -> Result<()> {
    let mut port: u16 = 21117;
    let mut key = String::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                i += 1;
                port = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(21117);
            }
            "--key" | "-k" => {
                i += 1;
                key = args.get(i).cloned().unwrap_or_default();
            }
            _ => {
                if let Some(p) = args[i].strip_prefix("--port=") {
                    port = p.parse().unwrap_or(21117);
                } else if let Some(k) = args[i].strip_prefix("--key=") {
                    key = k.to_string();
                } else {
                    bail!("unknown relay arg: {}", args[i]);
                }
            }
        }
        i += 1;
    }

    let server = rsh_relay::relay::RelayServer::new(&key);
    let addr = format!("0.0.0.0:{port}");
    eprintln!("relay server (hbbr) listening on {addr}");
    server.listen_and_serve(&addr).await
}

/// Run the rendezvous server (hbbs).
async fn run_rendezvous_server(args: &[String]) -> Result<()> {
    let mut port: u16 = 21116;
    let mut key = String::new();
    let mut relay = String::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                i += 1;
                port = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(21116);
            }
            "--key" | "-k" => {
                i += 1;
                key = args.get(i).cloned().unwrap_or_default();
            }
            "--relay" | "-r" => {
                i += 1;
                relay = args.get(i).cloned().unwrap_or_default();
            }
            _ => {
                if let Some(p) = args[i].strip_prefix("--port=") {
                    port = p.parse().unwrap_or(21116);
                } else if let Some(k) = args[i].strip_prefix("--key=") {
                    key = k.to_string();
                } else if let Some(r) = args[i].strip_prefix("--relay=") {
                    relay = r.to_string();
                } else {
                    bail!("unknown rendezvous arg: {}", args[i]);
                }
            }
        }
        i += 1;
    }

    if relay.is_empty() {
        bail!("--relay <host:port> is required (address of hbbr relay server)");
    }

    let server = rsh_relay::rendezvous::RendezvousServer::new(&key, &relay);
    let addr = format!("0.0.0.0:{port}");
    eprintln!("rendezvous server (hbbs) listening on {addr} (relay: {relay})");
    server.listen_and_serve(&addr).await
}

/// Fleet status and update across configured hosts.
async fn run_fleet(args: &[String]) -> Result<()> {
    let action = args.first().map(|s| s.as_str()).unwrap_or("status");
    let config = rsh_core::config::Config::load();

    match action {
        "status" => {
            let statuses = rsh_client::fleet::status(&config).await;
            println!("{}", rsh_client::fleet::format_status_table(&statuses));
        }
        "update" => {
            let binary_path = args.get(1).map(|s| s.as_str()).unwrap_or("deploy/rsh.exe");

            let binary_data = std::fs::read(binary_path)
                .map_err(|e| anyhow::anyhow!("read {}: {}", binary_path, e))?;

            if binary_data.len() < 1_000_000 {
                bail!(
                    "binary {} is too small ({} bytes) — expected >1MB",
                    binary_path,
                    binary_data.len()
                );
            }

            let target_version = env!("CARGO_PKG_VERSION");
            eprintln!(
                "Fleet update: {} ({} bytes) → v{}",
                binary_path,
                binary_data.len(),
                target_version
            );

            // Show current status first
            let statuses = rsh_client::fleet::status(&config).await;
            println!("{}\n", rsh_client::fleet::format_status_table(&statuses));

            let results =
                rsh_client::fleet::update_fleet(&config, &binary_data, target_version).await;
            println!("{}", rsh_client::fleet::format_update_results(&results));
        }
        "config" => {
            // Check rendezvous config consistency across fleet
            let statuses = rsh_client::fleet::status(&config).await;
            let online: Vec<_> = statuses.iter().filter(|s| s.online).collect();

            if online.is_empty() {
                eprintln!("No hosts online.");
                return Ok(());
            }

            let expected_rdv = config.rendezvous_server.clone().unwrap_or_default();

            println!("Expected rendezvous: {}", expected_rdv);
            println!();

            for host in &online {
                let opts = ConnectOptions {
                    host: host.hostname.clone(),
                    port: host.port,
                    key_path: None,
                    password_user: None,
                };
                match rsh_client::client::connect(&opts).await {
                    Ok(mut c) => match rsh_client::commands::native(&mut c, "config").await {
                        Ok(cfg) => {
                            let matches = cfg.contains(&expected_rdv);
                            let mark = if matches { "OK" } else { "DRIFT" };
                            println!("{:<20} [{}]", host.name, mark);
                            if !matches {
                                println!("  remote: {}", cfg.trim());
                            }
                        }
                        Err(e) => println!("{:<20} [ERROR: {}]", host.name, e),
                    },
                    Err(e) => println!("{:<20} [CONNECT FAILED: {}]", host.name, e),
                }
            }
        }
        "discover" => {
            // Fleet discovery via rendezvous group query.
            // Usage: rsh fleet discover --group <name>
            let mut group_name = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--group" | "-g" => {
                        i += 1;
                        group_name = args.get(i).cloned();
                    }
                    other if other.starts_with("--group=") => {
                        group_name = Some(other.strip_prefix("--group=").unwrap().to_string());
                    }
                    _ => {}
                }
                i += 1;
            }
            let group_name = group_name
                .ok_or_else(|| anyhow::anyhow!("--group <name> required\nUsage: rsh fleet discover --group <name>"))?;

            // Look up enrollment token
            let token = rsh_client::install_pack::get_group_token(&group_name)?;

            // Build rendezvous client
            let rdv_server = config.rendezvous_server.clone()
                .unwrap_or_else(|| "localhost:21116".to_string());

            let rdv_client = rsh_relay::rendezvous::Client {
                servers: vec![rdv_server.clone()],
                licence_key: config.rendezvous_key.clone().unwrap_or_default(),
                local_id: String::new(),
                group_hash: String::new(),
                hostname: String::new(),
                platform: String::new(),
            };

            eprintln!("Querying {} for group '{}'...", rdv_server, group_name);
            let peers = rdv_client.query_group(&token).await?;

            if peers.is_empty() {
                println!("No peers found in group '{}'.", group_name);
                return Ok(());
            }

            // Detect which peers are on the same LAN
            let local_addrs = get_local_addrs();

            println!("{:<15} {:<20} {:<10} {:<22} {:<8} {}",
                "DEVICE ID", "HOSTNAME", "PLATFORM", "ADDRESS", "NETWORK", "LAST SEEN");
            println!("{}", "-".repeat(90));

            for peer in &peers {
                let addr_str = peer.addr
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "relay-only".to_string());

                let is_lan = peer.addr.map_or(false, |a| is_same_lan(a, &local_addrs));
                let net_label = if is_lan { "LAN" } else { "WAN/Relay" };

                let ago = {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let diff = now.saturating_sub(peer.last_seen_secs);
                    if diff < 60 { format!("{}s ago", diff) }
                    else if diff < 3600 { format!("{}m ago", diff / 60) }
                    else { format!("{}h ago", diff / 3600) }
                };

                println!("{:<15} {:<20} {:<10} {:<22} {:<8} {}",
                    peer.device_id, peer.hostname, peer.platform, addr_str, net_label, ago);
            }

            let lan_count = peers.iter().filter(|p| p.addr.map_or(false, |a| is_same_lan(a, &local_addrs))).count();
            println!("\n{} peer(s) total, {} on LAN", peers.len(), lan_count);
        }
        other => bail!("unknown fleet action: {} (use status|update|config|discover)", other),
    }

    Ok(())
}

// ── Watch mode ──────────────────────────────────────────────

/// Watch a local directory for changes and auto-push to remote.
async fn run_watch<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>(
    client: &mut rsh_client::client::RshClient<S>,
    local_dir: &str,
    remote_dir: &str,
) -> Result<()> {
    use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::mpsc;

    let local_dir = std::fs::canonicalize(local_dir)?;
    if !local_dir.is_dir() {
        bail!("{} is not a directory", local_dir.display());
    }

    let (tx, rx) = mpsc::channel();

    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
    watcher.watch(&local_dir, RecursiveMode::Recursive)?;

    eprintln!(
        "Watching {} -> {} (Ctrl+C to stop)",
        local_dir.display(),
        remote_dir
    );

    // Debounce: collect changes, flush every 500ms of quiet
    let debounce = std::time::Duration::from_millis(500);
    let mut pending: HashSet<PathBuf> = HashSet::new();

    loop {
        match rx.recv_timeout(debounce) {
            Ok(Ok(event)) => {
                let dominated_by_write =
                    matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_));
                if !dominated_by_write {
                    continue;
                }

                for path in event.paths {
                    // Skip directories and hidden/ignored
                    if path.is_dir() {
                        continue;
                    }
                    if let Some(name) = path.file_name().and_then(|n| n.to_str())
                        && name.starts_with('.')
                    {
                        continue;
                    }
                    // Skip common ignores
                    let path_str = path.to_string_lossy();
                    if path_str.contains("node_modules")
                        || path_str.contains("__pycache__")
                        || path_str.contains(".git")
                    {
                        continue;
                    }
                    pending.insert(path);
                }
            }
            Ok(Err(e)) => {
                eprintln!("watch error: {}", e);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Debounce expired — flush pending
                if pending.is_empty() {
                    continue;
                }

                let files: Vec<PathBuf> = pending.drain().collect();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    % 86400;
                let hh = now / 3600;
                let mm = (now % 3600) / 60;
                let ss = now % 60;
                let now = format!("{:02}:{:02}:{:02}", hh, mm, ss);
                eprintln!("\n[{}] Pushing {} file(s)...", now, files.len());

                for path in &files {
                    let rel = path
                        .strip_prefix(&local_dir)
                        .unwrap_or(path)
                        .to_string_lossy();
                    // Convert to Windows remote path
                    let remote_path = format!("{}\\{}", remote_dir, rel.replace('/', "\\"));

                    match std::fs::read(path) {
                        Ok(data) => {
                            match rsh_client::sync::push(client, &data, &remote_path).await {
                                Ok(result) => {
                                    eprintln!(
                                        "  {} ({} bytes, delta: {})",
                                        rel, result.bytes_sent, result.delta
                                    );
                                }
                                Err(e) => {
                                    eprintln!("  {} FAILED: {}", rel, e);
                                }
                            }
                        }
                        Err(_) => {
                            // File may have been deleted
                            continue;
                        }
                    }
                }

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    % 86400;
                let hh = now / 3600;
                let mm = (now % 3600) / 60;
                let ss = now % 60;
                let now = format!("{:02}:{:02}:{:02}", hh, mm, ss);
                eprintln!("[{}] Done.", now);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    Ok(())
}

// ── Server mode (cross-platform) ──────────────────────────────

/// Run the server: load TLS certs, authorized keys, start listeners.
/// `with_tray`: true = show system tray icon (Windows only), false = headless.
async fn run_server_mode(port: u16, with_tray: bool) -> Result<()> {
    let cancel = tokio_util::sync::CancellationToken::new();
    run_server_mode_inner(port, with_tray, cancel).await
}

/// Run server with an externally provided cancel token (from service control).
async fn run_server_mode_with_cancel(
    port: u16,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    run_server_mode_inner(port, false, cancel).await
}

async fn run_server_mode_inner(
    port: u16,
    _with_tray: bool,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    use rsh_core::{auth, tls};
    use rsh_server::{handler::ServerContext, listener, session};
    use tokio_rustls::TlsAcceptor;

    let data_dir = server_data_dir();
    std::fs::create_dir_all(&data_dir)?;

    info!("server starting: port={}, tray={}", port, _with_tray);

    // Load or generate TLS certificate
    let (certs, key) = tls::load_or_generate_cert(&data_dir)?;
    let tls_config = tls::server_config(certs, key)?;
    #[cfg(feature = "quic")]
    let tls_config_for_quic = tls_config.clone();
    let tls_acceptor = TlsAcceptor::from(tls_config);

    // Load authorized keys
    let ak_path = data_dir.join("authorized_keys");
    let authorized_keys = if ak_path.exists() {
        auth::load_authorized_keys(&ak_path, true)?
    } else {
        tracing::warn!("no authorized_keys file at {}", ak_path.display());
        Vec::new()
    };

    // Load revoked keys (optional — empty set if file doesn't exist)
    let rk_path = data_dir.join("revoked_keys");
    let revoked_keys = if rk_path.exists() {
        auth::load_revoked_keys(&rk_path)?
    } else {
        std::collections::HashSet::new()
    };

    let caps = vec![
        "shell".to_string(),
        "self-update".to_string(),
        "bin-patch".to_string(),
    ];

    // Load TOTP secrets (optional — empty vec if file doesn't exist)
    let totp_path = data_dir.join("totp_secrets");
    let totp_secrets = if totp_path.exists() {
        auth::load_totp_secrets(&totp_path)?
    } else {
        Vec::new()
    };

    let totp_recovery_path = {
        let p = data_dir.join("totp_recovery");
        if p.exists() { Some(p) } else { None }
    };

    // Initialize connection notification channel (for tray toast notifications)
    let _notify_rx = rsh_server::notify::init();

    let ctx = Arc::new(ServerContext {
        authorized_keys,
        revoked_keys,
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        banner: None,
        caps,
        session_store: session::SessionStore::new(),
        rate_limiter: rsh_server::ratelimit::AuthRateLimiter::new(),
        allowed_tunnels: load_allowed_tunnels(&data_dir),
        totp_secrets,
        totp_recovery_path,
    });

    let config = listener::ServerConfig {
        command_port: port,
        tls_acceptor,
        ctx,
        ip_acl: load_ip_acl(&data_dir),
        #[cfg(feature = "quic")]
        tls_config: tls_config_for_quic,
    };

    // Spawn rendezvous registration loop (if configured).
    {
        let user_config = rsh_core::config::Config::load();
        let rdv_servers = user_config.get_rendezvous_servers();
        let device_id = user_config.device_id.clone().unwrap_or_default();
        let rdv_key = user_config.rendezvous_key.clone().unwrap_or_default();
        // Compute group_hash from enrollment_token (if present in config).
        let group_hash = if let Some(ref token) = user_config.enrollment_token {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(token.as_bytes());
            let digest = h.finalize();
            digest.iter().map(|b| format!("{b:02x}")).collect::<String>()
        } else {
            String::new()
        };
        let hostname = std::process::Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let platform = std::env::consts::OS.to_string();
        if !rdv_servers.is_empty() && !device_id.is_empty() {
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let client = rsh_relay::rendezvous::Client {
                    servers: rdv_servers,
                    licence_key: rdv_key,
                    local_id: device_id.clone(),
                    group_hash: group_hash.clone(),
                    hostname,
                    platform,
                };
                if !group_hash.is_empty() {
                    info!("rendezvous registration started for DeviceID {} (group enrolled)", device_id);
                } else {
                    info!("rendezvous registration started for DeviceID {}", device_id);
                }
                // Register immediately on startup, then every 30s.
                loop {
                    match client.register_once().await {
                        Ok(()) => tracing::debug!("rendezvous registered"),
                        Err(e) => tracing::warn!("rendezvous registration failed: {}", e),
                    }
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
                    }
                }
            });
        }
    }

    #[cfg(target_os = "windows")]
    if _with_tray {
        use rsh_server::tray;

        // Tray mode — run listener in background, tray on main thread
        let cancel_clone = cancel.clone();
        let server_handle =
            tokio::spawn(async move { listener::run_server(config, cancel_clone).await });

        // Tray blocks the current thread's message loop
        let tray_cancel = cancel.clone();
        let tray_port = port;
        let tray_handle =
            tokio::task::spawn_blocking(move || tray::run_tray(tray_cancel, tray_port));

        // Wait for either to finish
        tokio::select! {
            result = server_handle => {
                result??;
            }
            result = tray_handle => {
                result??;
            }
        }
        return Ok(());
    }

    // Service, console, or daemon mode — listener blocks, no tray
    listener::run_server(config, cancel).await?;

    Ok(())
}

/// Get all local IPv4 addresses (for LAN detection).
fn get_local_addrs() -> Vec<std::net::Ipv4Addr> {
    let mut addrs = Vec::new();
    // Read from /proc/net/fib_trie on Linux, or use getifaddrs equivalent.
    // Cross-platform: just try binding UDP to discover local IPs.
    if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
        // Try connecting to common LAN gateways to discover our IPs.
        for target in &["192.168.0.1:80", "192.168.1.1:80", "10.0.0.1:80", "172.16.0.1:80"] {
            if sock.connect(target).is_ok() {
                if let Ok(local) = sock.local_addr() {
                    if let std::net::SocketAddr::V4(v4) = local {
                        if !addrs.contains(v4.ip()) {
                            addrs.push(*v4.ip());
                        }
                    }
                }
            }
        }
    }
    // Also try to parse from system interfaces
    #[cfg(unix)]
    {
        if let Ok(output) = std::process::Command::new("hostname").arg("-I").output() {
            if let Ok(s) = std::str::from_utf8(&output.stdout) {
                for part in s.split_whitespace() {
                    if let Ok(ip) = part.parse::<std::net::Ipv4Addr>() {
                        if !addrs.contains(&ip) {
                            addrs.push(ip);
                        }
                    }
                }
            }
        }
    }
    addrs
}

/// Check if a remote address is on the same /24 subnet as any local address.
fn is_same_lan(remote: std::net::SocketAddr, local_addrs: &[std::net::Ipv4Addr]) -> bool {
    let remote_ip = match remote {
        std::net::SocketAddr::V4(v4) => *v4.ip(),
        _ => return false,
    };
    let remote_octets = remote_ip.octets();
    for local in local_addrs {
        let local_octets = local.octets();
        // Same /24 network
        if remote_octets[0] == local_octets[0]
            && remote_octets[1] == local_octets[1]
            && remote_octets[2] == local_octets[2]
        {
            return true;
        }
    }
    false
}

fn print_usage() {
    let version = env!("CARGO_PKG_VERSION");
    println!(
        r#"rsh {version} (rust) — Remote Shell Tool

USAGE:
  rsh [options] <command> [args...]
  rsh -h <host> [-p port] [-i key] <command> [args...]

OPTIONS:
  -h <host>     Remote host (IP, hostname, or DeviceID)
  -p <port>     Remote port (default: 8822)
  -i <key>      SSH key file
  -v, -vv       Verbose output

LOCAL COMMANDS (no -h needed):
  version       Show version
  fleet status  Show all configured hosts and their versions
  fleet update  Push binary to all outdated hosts
  fleet config  Check rendezvous config consistency across fleet
  fleet discover --group <name>  Discover peers enrolled in a group
                  Uses enrollment token HMAC for authentication.
                  Returns: DeviceID, hostname, platform, LAN status
  wake <host|mac>  Send Wake-on-LAN packet (MAC from config or argument)
  config-edit   Interactive config editor (TUI)
  connect       Pick a known host from TUI list and connect
  log           Session log report (hours per host)
                  --host=X  --since=YYYY-MM-DD  --until=YYYY-MM-DD
                  --detail  --json
  keygen [path] Generate ed25519 key pair
  totp-setup [fp] Generate TOTP secret + recovery codes for a key
  totp-verify <secret|fp> <code>  Verify a TOTP code
  recording export <file.log> [output.cast]  Convert session log to asciicast
  install-pack  Generate single-file installer for target machine
                  Linux:   self-extracting .sh (bash header + tar.gz)
                  Windows: NSIS installer .exe (requires makensis on build host)
                  --platform=windows|linux  --output=FILE  --binary=PATH
                  --key=KEY_OR_FILE  --port=PORT  --nas-auth=CMD
                  --group=NAME  --rendezvous-server=HOST:PORT
                  Group enrollment: embeds EnrollmentToken in config so the
                  installed server registers with SHA256(token) as group_hash.
  relay         Run relay server (hbbr) for connection pairing
                  --port=PORT (default: 21117)  --key=KEY
  rendezvous    Run rendezvous server (hbbs) for device discovery
                  --port=PORT (default: 21116)  --key=KEY  --relay=HOST:PORT
                  Stores peer group_hash for fleet group discovery.
  help          This help

CLIENT COMMANDS (require -h):
  ping          Test connectivity
  exec <cmd>    Execute command (PowerShell on Windows)
  shell         Interactive shell (ConPTY on Windows, PTY on Linux)
  attach [id]   Persistent session (--ro for read-only)
  browse [path] Interactive file browser (TUI)
  sftp          SFTP-like interactive file transfer shell
  server-version  Show remote server version
  recording list  List session recordings on remote host
  push <l> <r>  Push file (delta sync)
  pull <r> <l>  Pull file (delta sync)

TRANSFER OPTIONS:
  --progress    Show progress bar with rate and ETA
  --dry-run     Show what would be transferred without doing it
  --backup=.bak Rename remote files before overwriting
  --bwlimit=N   Bandwidth limit in KB/s (0 = unlimited)
  --delete      Mirror mode: remove remote files not in local (push only)
  --timeout=N   Global operation timeout in seconds (0 = per-command default)
                  Default: exec 120s, push/pull 300s, shell/tunnel/watch 0 (none)
  ls [path]     List directory
  cat <path>    Read file
  write <r> <c> Write content to file
  screenshot    Capture screen
  watch <l> <r> Watch dir, auto-push changes
  status [n]    RTT statistics (n pings)
  ps            List processes
  kill <pid>    Kill process
  tail <f> [n]  Tail file (default 20 lines)
  info          System info
  eventlog      Windows Event Log
  clip get|set  Clipboard
  service       Service management
  filever       PE version info
  sessions      List/kill persistent sessions
  self-update   Trigger remote self-update
  input         GUI automation (mouse/key/window)
  mouse         Mouse control (alias for input mouse)
  key           Keyboard control (alias for input key)
  window        Window control (alias for input window)
  plugin        Plugin management
  cache         Block cache stats/index
  tunnel <l> <r> TCP tunnel (ssh -L equivalent)
  -D <port>     SOCKS5 proxy (ssh -D equivalent)
  --user <name> Password auth (fallback when no SSH key)
  reboot [-f]   Reboot remote host
  shutdown [-f] Shutdown remote host
  sleep [-f]    Sleep remote host
  lock          Lock workstation

MUX (connection multiplexing):
  -M            Start control master (hold connection, serve via UDS)
  --no-mux      Skip multiplexing, always open new connection
  --mux-stop    Stop running master for this host

AI USAGE:
  rsh is a unified remote shell tool (client+server in one binary) for AI agents.
  It replaces SSH for Windows targets with ed25519 auth, file transfer, GUI automation.

  CONNECTIVITY:
  - CONNECTION PRIORITY: LAN direct > Tailscale > Relay (DeviceID)
  - CONFIG FILE: ~/.rsh/config defines Host aliases with Hostname, Port, DeviceID, MAC.
    Always check config before assuming default ports.
  - AUTO-TRY PORTS: Without -p, rsh tries 8822 → 9822 → 22 in sequence.
    Port 22 covers hosts running rsh on the SSH port. No manual -p needed.
  - WSL CONNECTIVITY: WSL cannot reach Tailscale hosts (100.x.x.x) via TCP.
    For Tailscale targets, use the Windows rsh client:
      powershell.exe -Command "C:\ProgramData\remote-shell\rsh.exe -h <IP> -p <port> exec '<cmd>' | Out-String"
    For LAN targets (192.168.x.x), WSL rsh works directly.
  - RELAY FALLBACK: When LAN and Tailscale both fail, try DeviceID:
      rsh -h <DeviceID> exec '<cmd>'
    DeviceIDs are in ~/.rsh/config. Relay races P2P and hbbr in parallel.
  - ALWAYS use UNC paths for network shares, NEVER mapped drive letters.
    Prefer DNS hostnames in UNC: \\nas-server\share not \\10.0.0.1\share

  EXEC BEHAVIOR:
  - rsh exec runs commands via PowerShell (-NoProfile -Command), NOT CMD.
    Use PowerShell syntax: Get-ChildItem (not dir), Remove-Item (not del),
    Get-Content (not type), Set-Content (not echo >), Test-Path (not if exist).
  - The destination path in push is resolved by the SERVER, not the client.

  TRANSFER:
  - Push/pull use CDC delta sync by default (block-level, resumable).
  - Use --raw to skip delta and transfer full files (simpler, no cache).
  - Use --log-file to write logs to file AND console simultaneously.

  OUTPUT FORMATS:
    ls       → JSON array: [{{"name":"f.txt","size":1234,"mode":"0644","mod":"...","isDir":false}}]
    cat      → base64-encoded content (decode with base64 -d)
    screenshot → JPEG saved locally (default: screenshot_HOST_TIMESTAMP.jpg)
    exec     → stdout as plain text, stderr on error
    ping     → "OK" or "FAILED: <reason>"
    info     → system info; use --json for structured output
    service list/status → Windows service management

  SYSTEM DISCOVERY:
    rsh info --json          System info (hostname, OS, RAM, disk, NICs)
    rsh service list         List Windows services
    rsh service status <svc> Service details (state, PID, binary path)
    rsh wake <host|MAC>      Wake-on-LAN (send magic packet, MAC from config)
    rsh fleet status         Show version/status of all configured hosts

  SELF-UPDATE:
  - CRITICAL: NEVER kill/stop/restart rsh through its own connection using /ru SYSTEM.
    SYSTEM cannot start tray-mode apps in user desktop session — locks you out.
  - SAFE UPDATE PROCEDURE:
    0. DETERMINE MODE: service (port 8822) or tray (port 9822)?
       Service mode: fleet update or schtask with net stop/start remote-shell is safe.
       Tray mode: use schtask with /ru <USERNAME> (NOT /ru SYSTEM).
    1. BEFORE touching the service, verify alternative access (SSH, WinRM, RDP).
       If rsh is the ONLY access channel, DO NOT proceed — ask for recovery path.
    2. Canonical install directory: C:\ProgramData\remote-shell\
    3. Push new binary alongside: rsh push deploy/rsh.exe "C:\ProgramData\remote-shell\rsh-new.exe"
    4. Create ONE schtask (never overwrite without verifying outcome of previous).
    5. Wait 15s, verify: rsh ping
    WARNING: rsh exec may report exit code 1 even on success (output formatting).

  GUI INTERACTION:
    Service port 8822 (SYSTEM) has NO access to user desktop session.
    For screenshot/window list/find, launch tray-mode as logged-in user:
      1. Find user: rsh -p 8822 exec "quser"
      2. Launch: schtasks /create ... /ru <USERNAME> + schtasks /run
      3. Connect tray: rsh -p 9822 ping
    Capability matrix:
      | Feature           | Port 8822 (SYSTEM) | Port 9822 (tray/user) |
      | exec, push/pull   | Yes                | Yes                   |
      | mouse/key input   | Yes (cross-session)| Yes                   |
      | window list/find  | null (no desktop)  | Yes (JSON)            |
      | screenshot        | fails              | Yes                   |
    Cleanup: rsh -p 8822 exec 'schtasks /delete /tn "rsh-tray" /f'

  REMOTE EXECUTION — NO ORPHAN PROCESSES:
  - Use rsh exec DIRECTLY for commands. Do NOT create intermediate .bat/.ps1 wrappers
    that leave orphan processes on the remote desktop.
      CORRECT: rsh exec 'Get-Process | Where-Object {{ $_.Name -eq "app" }}'
      WRONG:   rsh exec 'cmd /k "dir"'        ← leaves orphan cmd.exe window
      WRONG:   rsh exec 'start /b script.bat'  ← leaves orphan console
  - If you need cmd.exe features (pipes, cd /d): rsh exec 'cmd /c "..."'
    Always use /c (auto-exits after command), NEVER /k (keeps console open).
  - If you need PowerShell: rsh exec 'powershell -NoProfile -Command "..."'

  HIDDEN SCHTASK EXECUTION (no console window on remote desktop):
  - Bare schtasks /tr "powershell ..." shows a console window to the remote user.
  - Use VBS wrapper (run-hidden.vbs) to launch PowerShell hidden (window style 0):
      Set objShell = CreateObject("WScript.Shell")
      objShell.Run "powershell ... -File """ & WScript.Arguments(0) & """", 0, True
  - Deploy once: rsh push run-hidden.vbs 'C:/Temp/run-hidden.vbs'
  - Usage: /tr "wscript C:\Temp\run-hidden.vbs C:\Temp\script.ps1"
    instead of: /tr "powershell -ExecutionPolicy Bypass -File ..."
  - PS1 output: use *> C:\Temp\<name>.log redirect (NOT Start-Transcript).
  - NEVER use /it flag with schtasks via SSH/rsh — /it requires interactive desktop logon.
"#,
        version = version
    );
}

/// Get the server data directory.
/// Windows service: C:\ProgramData\remote-shell\
/// Windows user: %USERPROFILE%\.rsh\
/// Linux root/service: /etc/rsh/
/// Linux user: ~/.rsh/
/// Load allowed tunnel targets from `allowed_tunnels` file (one per line).
/// Empty file or missing file = all tunnels allowed (default open).
/// Format: `host:port` or `host:*` (wildcard port).
/// Load IP access control from `allowed_ips` and/or `denied_ips` files.
/// Each file: one IP or CIDR per line, `#` comments, blank lines ignored.
/// - `allowed_ips` only → whitelist mode (only listed IPs can connect)
/// - `denied_ips` only → blacklist mode (listed IPs are blocked)
/// - Both files → allow list + deny list (deny takes precedence)
/// - Neither file → all IPs allowed (default open)
fn load_ip_acl(data_dir: &std::path::Path) -> rsh_server::listener::IpAccessControl {
    let load_file = |name: &str| -> Vec<String> {
        let path = data_dir.join(name);
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                let entries: Vec<String> = content
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(|l| l.to_string())
                    .collect();
                if !entries.is_empty() {
                    info!("loaded {} IP rules from {}", entries.len(), path.display());
                }
                entries
            }
            Err(_) => vec![],
        }
    };

    let allow = load_file("allowed_ips");
    let deny = load_file("denied_ips");

    if allow.is_empty() && deny.is_empty() {
        rsh_server::listener::IpAccessControl::allow_all()
    } else {
        rsh_server::listener::IpAccessControl::new(&allow, &deny)
    }
}

fn load_allowed_tunnels(data_dir: &std::path::Path) -> Vec<String> {
    let path = data_dir.join("allowed_tunnels");
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let targets: Vec<String> = content
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| l.to_string())
                .collect();
            if !targets.is_empty() {
                info!(
                    "loaded {} tunnel restrictions from {}",
                    targets.len(),
                    path.display()
                );
            }
            targets
        }
        Err(_) => vec![], // file not found = all allowed
    }
}

fn server_data_dir() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        // Check canonical service location first
        let service_dir = std::path::PathBuf::from(r"C:\ProgramData\remote-shell");
        if service_dir.exists() {
            return service_dir;
        }

        // Fall back to user home
        if let Some(home) = std::env::var_os("USERPROFILE") {
            return std::path::PathBuf::from(home).join(".rsh");
        }

        // Last resort
        return service_dir;
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Root/service mode: /etc/rsh/
        if unsafe { libc::geteuid() } == 0 {
            let service_dir = std::path::PathBuf::from("/etc/rsh");
            return service_dir;
        }

        // User mode: ~/.rsh/
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home).join(".rsh");
        }

        std::path::PathBuf::from("/etc/rsh")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // --- compute_timeout_secs ---

    #[test]
    fn timeout_explicit_overrides_all_commands() {
        assert_eq!(compute_timeout_secs(60, "push"), 60);
        assert_eq!(compute_timeout_secs(60, "shell"), 60);
        assert_eq!(compute_timeout_secs(60, "exec"), 60);
        assert_eq!(compute_timeout_secs(1, "pull"), 1);
    }

    #[test]
    fn timeout_zero_uses_per_command_defaults() {
        // Interactive commands: no timeout
        assert_eq!(compute_timeout_secs(0, "shell"), 0);
        assert_eq!(compute_timeout_secs(0, "browse"), 0);
        assert_eq!(compute_timeout_secs(0, "sftp"), 0);
        assert_eq!(compute_timeout_secs(0, "tunnel"), 0);
        assert_eq!(compute_timeout_secs(0, "watch"), 0);
        assert_eq!(compute_timeout_secs(0, "attach"), 0);
        assert_eq!(compute_timeout_secs(0, "socks5"), 0);

        // Transfer commands: 300s default
        assert_eq!(compute_timeout_secs(0, "push"), 300);
        assert_eq!(compute_timeout_secs(0, "pull"), 300);

        // All other commands: 120s default
        assert_eq!(compute_timeout_secs(0, "ping"), 120);
        assert_eq!(compute_timeout_secs(0, "exec"), 120);
        assert_eq!(compute_timeout_secs(0, "ls"), 120);
        assert_eq!(compute_timeout_secs(0, "cat"), 120);
        assert_eq!(compute_timeout_secs(0, "info"), 120);
        assert_eq!(compute_timeout_secs(0, "kill"), 120);
        assert_eq!(compute_timeout_secs(0, "screenshot"), 120);
    }

    // --- CLI arg parsing ---

    #[test]
    fn cli_timeout_default_is_zero() {
        let cli = Cli::try_parse_from(["rsh", "-h", "host", "ping"]).unwrap();
        assert_eq!(cli.timeout, 0);
    }

    #[test]
    fn cli_timeout_explicit_value_parsed() {
        let cli = Cli::try_parse_from(["rsh", "-h", "host", "--timeout", "45", "ping"]).unwrap();
        assert_eq!(cli.timeout, 45);
    }

    #[test]
    fn cli_timeout_zero_explicit_parsed() {
        let cli = Cli::try_parse_from(["rsh", "-h", "host", "--timeout", "0", "exec", "ls"]).unwrap();
        assert_eq!(cli.timeout, 0);
    }

    // --- tokio timeout wrapper behaviour ---

    #[tokio::test]
    async fn timeout_wrapper_fires_on_slow_future() {
        let slow = tokio::time::sleep(std::time::Duration::from_secs(60));
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(10),
            slow,
        ).await;
        assert!(result.is_err(), "expected timeout to fire");
    }

    #[tokio::test]
    async fn timeout_wrapper_passes_fast_future() {
        let fast = async { 42u32 };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fast,
        ).await;
        assert_eq!(result.unwrap(), 42);
    }
}
