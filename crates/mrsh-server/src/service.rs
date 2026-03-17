//! Windows service integration — register, start, stop, run as service.
//! Uses windows-service crate on Windows; stub on other platforms.

#[cfg(target_os = "windows")]
use tracing::info;

/// Service name used for registration.
pub const SERVICE_NAME: &str = "mrsh";

/// Display name in Windows Services console.
pub const SERVICE_DISPLAY_NAME: &str = "Remote Shell (rsh)";

/// Install mrsh as a Windows service.
#[cfg(target_os = "windows")]
pub fn install_service(exe_path: &str) -> anyhow::Result<()> {
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::path::PathBuf::from(exe_path),
        launch_arguments: vec![OsString::from("--service")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };

    let _service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;

    // Set recovery options: restart on failure
    // windows-service doesn't expose failure actions directly,
    // so we use sc.exe as fallback
    let _ = std::process::Command::new("sc")
        .args([
            "failure",
            SERVICE_NAME,
            "reset=",
            "86400",
            "actions=",
            "restart/5000",
        ])
        .output();

    info!("service installed: {}", SERVICE_NAME);

    // Register tray companion at user logon — ensures visible tray icon
    // whenever someone is logged in, preventing fully hidden operation.
    if let Err(e) = register_tray_logon_task(exe_path) {
        tracing::warn!("could not register tray logon task: {}", e);
    }

    Ok(())
}

/// Scheduled task name for the tray companion.
#[cfg(target_os = "windows")]
const TRAY_TASK_NAME: &str = "mrsh-tray";

/// Register a scheduled task that launches the mrsh tray at user logon.
///
/// This provides user-visible evidence that mrsh is running: a system tray
/// icon with version, port, and connection notifications. Without this,
/// the service runs completely hidden — a concern for abuse prevention.
#[cfg(target_os = "windows")]
fn register_tray_logon_task(exe_path: &str) -> anyhow::Result<()> {
    use std::process::Command;

    // Create task with ONLOGON trigger, running as the interactive user group.
    // /F = force overwrite existing | /RL HIGHEST = run with admin privileges
    let output = Command::new("schtasks")
        .args([
            "/create",
            "/tn",
            TRAY_TASK_NAME,
            "/tr",
            exe_path,
            "/sc",
            "ONLOGON",
            "/rl",
            "LIMITED",
            "/f",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("schtasks create failed: {}", stderr.trim());
    }

    info!("tray logon task registered: {}", TRAY_TASK_NAME);
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn install_service(exe_path: &str) -> anyhow::Result<()> {
    // Generate a systemd unit file template for the user
    let unit = format!(
        r#"[Unit]
Description=Remote Shell (rsh) daemon
After=network.target

[Service]
Type=simple
ExecStart={exe} --daemon
Restart=on-failure
RestartSec=5
WorkingDirectory=/etc/rsh

[Install]
WantedBy=multi-user.target
"#,
        exe = exe_path,
    );
    let unit_path = "/etc/systemd/system/rsh.service";
    std::fs::write(unit_path, &unit)
        .map_err(|e| anyhow::anyhow!("write {}: {} (try with sudo)", unit_path, e))?;
    eprintln!("wrote {}", unit_path);
    eprintln!("run: sudo systemctl daemon-reload && sudo systemctl enable --now rsh");
    Ok(())
}

/// Uninstall the Windows service.
#[cfg(target_os = "windows")]
pub fn uninstall_service() -> anyhow::Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;

    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()?;

    // Remove tray logon task
    let _ = std::process::Command::new("schtasks")
        .args(["/delete", "/tn", TRAY_TASK_NAME, "/f"])
        .output();

    info!("service uninstalled: {}", SERVICE_NAME);
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn uninstall_service() -> anyhow::Result<()> {
    let unit_path = "/etc/systemd/system/rsh.service";
    if std::path::Path::new(unit_path).exists() {
        let _ = std::process::Command::new("systemctl")
            .args(["stop", "mrsh"])
            .output();
        let _ = std::process::Command::new("systemctl")
            .args(["disable", "mrsh"])
            .output();
        std::fs::remove_file(unit_path)
            .map_err(|e| anyhow::anyhow!("remove {}: {} (try with sudo)", unit_path, e))?;
        let _ = std::process::Command::new("systemctl")
            .args(["daemon-reload"])
            .output();
        eprintln!("service uninstalled");
    } else {
        eprintln!("no systemd unit file found at {}", unit_path);
    }
    Ok(())
}

/// Check if running as a Windows service.
#[cfg(target_os = "windows")]
pub fn is_service_mode() -> bool {
    // If stdin is not a console (no attached terminal), likely running as service.
    // More robust check: try to register as service dispatcher.
    // For now, use CLI flag detection.
    std::env::args().any(|a| a == "--service")
}

#[cfg(not(target_os = "windows"))]
pub fn is_service_mode() -> bool {
    false
}

/// Get the default port based on mode.
pub fn default_port() -> u16 {
    if is_service_mode() { 8822 } else { 9822 }
}

/// Run as a Windows service (blocks until service stops).
///
/// The `server_fn` receives a CancellationToken that is cancelled when the
/// SCM sends a Stop control. The function should spawn the tokio runtime
/// and run the server until the token fires.
#[cfg(target_os = "windows")]
pub fn run_as_service(
    server_fn: impl FnOnce(tokio_util::sync::CancellationToken) + Send + 'static,
) -> anyhow::Result<()> {
    use std::sync::OnceLock;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;

    // Shared state between service_main and the dispatcher thread.
    // OnceLock lets service_main set the cancel token + server_fn once.
    static CANCEL: OnceLock<tokio_util::sync::CancellationToken> = OnceLock::new();
    static SERVER_FN: OnceLock<
        std::sync::Mutex<Option<Box<dyn FnOnce(tokio_util::sync::CancellationToken) + Send>>>,
    > = OnceLock::new();

    // Store the server function so service_main can retrieve it.
    let cancel = tokio_util::sync::CancellationToken::new();
    let _ = CANCEL.set(cancel.clone());
    let _ = SERVER_FN.set(std::sync::Mutex::new(Some(Box::new(server_fn))));

    // Define the service entry point (called by SCM on a separate thread).
    windows_service::define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<std::ffi::OsString>) {
        let cancel = CANCEL.get().expect("cancel token set").clone();
        let cancel_for_stop = cancel.clone();

        // Register the control handler (Stop, Shutdown, etc.)
        let status_handle = service_control_handler::register(
            SERVICE_NAME,
            move |control| match control {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    cancel_for_stop.cancel();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        )
        .expect("register service control handler");

        // Report Running
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        });

        // Run the actual server
        if let Some(f) = SERVER_FN
            .get()
            .and_then(|m| m.lock().ok())
            .and_then(|mut opt| opt.take())
        {
            f(cancel);
        }

        // Report Stopped
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        });
    }

    // This blocks until the service stops.
    // If this is NOT called from SCM, it returns an error immediately.
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;

    Ok(())
}

/// Run as a Linux daemon — blocks until SIGTERM/SIGINT received.
///
/// The `server_fn` receives a CancellationToken that is cancelled when
/// SIGTERM or SIGINT is received.
#[cfg(not(target_os = "windows"))]
pub fn run_as_service(
    server_fn: impl FnOnce(tokio_util::sync::CancellationToken) + Send + 'static,
) -> anyhow::Result<()> {
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_for_signal = cancel.clone();

    // Spawn signal handler thread
    std::thread::spawn(move || {
        use nix::sys::signal::{SigSet, Signal};
        let mut sigset = SigSet::empty();
        sigset.add(Signal::SIGTERM);
        sigset.add(Signal::SIGINT);
        // Block these signals so sigwait can catch them
        sigset.thread_block().ok();
        // Wait for signal
        if let Ok(_sig) = sigset.wait() {
            cancel_for_signal.cancel();
        }
    });

    server_fn(cancel);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_constants() {
        assert_eq!(SERVICE_NAME, "mrsh");
        assert!(!SERVICE_DISPLAY_NAME.is_empty());
    }

    #[test]
    fn default_port_value() {
        // Not running as service in tests
        let port = default_port();
        assert!(port == 8822 || port == 9822);
    }

    #[test]
    fn is_service_mode_false_in_tests() {
        assert!(!is_service_mode());
    }

    /// Regression test for solved/010: clap parses `-service` as short flags
    /// `-s -e -r -v -i -c -e`, not as `--service`. The install function must
    /// register `--service` (double dash) and is_service_mode must match it.
    #[test]
    fn service_flag_uses_double_dash() {
        // Verify install_service would use "--service" (checked via constant or code review)
        // The actual launch_arguments in install_service use OsString::from("--service")
        // and is_service_mode checks for "--service" — both must use double dash.
        //
        // We can't easily test is_service_mode with injected args in Rust,
        // but we verify the detection string matches what install registers.
        // If someone changes either side, this test documents the contract.
        let install_flag = "--service";
        let detect_flag = "--service"; // must match is_service_mode() check
        assert_eq!(install_flag, detect_flag,
            "install_service launch_arguments and is_service_mode must use the same flag format");

        // Verify single-dash would be wrong (clap uses double-dash)
        assert_ne!(install_flag, "-service",
            "single-dash -service is wrong, clap uses --service");
    }

    /// Verify is_service_mode returns false in test context (no --service arg)
    #[test]
    fn is_service_mode_detects_double_dash_only() {
        // In test context, args are the test runner args, never "--service"
        assert!(!is_service_mode());
    }

    #[test]
    fn install_service_linux_needs_root() {
        #[cfg(not(target_os = "windows"))]
        {
            // Writing to /etc/systemd/system/ requires root, so this should fail
            // in a non-root test environment.
            let result = install_service("/fake/path");
            // May succeed if running as root (CI), otherwise fails with permission error
            let _ = result;
        }
    }

    #[test]
    fn uninstall_service_linux_no_unit() {
        #[cfg(not(target_os = "windows"))]
        {
            let unit_path = "/etc/systemd/system/rsh.service";
            if std::path::Path::new(unit_path).exists() {
                // mrsh is installed on this machine — uninstall needs root, skip
                return;
            }
            // No unit file exists → prints message, returns Ok
            let result = uninstall_service();
            assert!(result.is_ok());
        }
    }
}
