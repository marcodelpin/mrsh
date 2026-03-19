//! Generate a ready-to-deploy installer package for a target machine.
//!
//! - **Linux**: Self-extracting `.sh` (bash header + tar.gz payload).
//! - **Windows**: NSIS-based installer `.exe` (requires `makensis` on build host).
//!
//! Both produce a **single executable file** for easy deployment.

use std::io::Write as IoWrite;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

/// Options for generating an install pack.
pub struct InstallPackOptions {
    /// Target platform: "windows" or "linux".
    pub platform: String,
    /// Output file path. If None, auto-named based on version+platform.
    pub output: Option<PathBuf>,
    /// Path to the mrsh binary to include.
    pub binary: Option<PathBuf>,
    /// Extra public keys to add to authorized_keys.
    pub extra_keys: Vec<String>,
    /// Port the target server will listen on (default 8822).
    pub port: u16,
    /// Optional NAS auth command for startup.bat.
    pub nas_auth: Option<String>,
    /// Fleet enrollment group name.
    pub group: Option<String>,
    /// Rendezvous server address for fleet enrollment.
    pub rendezvous_server: Option<String>,
}

/// Generate the install pack — returns the path to the single output file.
pub fn generate(opts: &InstallPackOptions) -> Result<PathBuf> {
    let version = env!("CARGO_PKG_VERSION");
    let is_windows = opts.platform == "windows";

    // Collect all pack contents in memory
    let binary_src = find_binary(&opts.binary, is_windows)?;
    let binary_name = if is_windows { "mrsh.exe" } else { "mrsh" };
    let binary_data = std::fs::read(&binary_src).with_context(|| {
        format!("read binary: {}", binary_src.display())
    })?;
    println!("  binary: {} ({} bytes)", binary_name, binary_data.len());

    let auth_keys_content = build_authorized_keys(&opts.extra_keys)?;
    let key_count = auth_keys_content.lines().count();
    println!("  authorized_keys: {} key(s)", key_count);

    let install_script = if is_windows {
        generate_windows_script(opts.port, &opts.nas_auth)
    } else {
        generate_linux_script(opts.port)
    };
    let script_name = if is_windows { "install.bat" } else { "install.sh" };
    println!("  {}: service install", script_name);

    // Optional files
    let startup_bat = if is_windows {
        opts.nas_auth.as_ref().map(|nas| {
            println!("  startup.bat: NAS auth at service start");
            format!("@echo off\r\n{}\r\n", nas)
        })
    } else {
        None
    };

    let config_content = if let Some(ref group_name) = opts.group {
        let rdv_server = opts.rendezvous_server.as_deref()
            .unwrap_or("localhost:21116");
        let token = load_or_create_group_token(group_name)?;

        use sha2::{Digest, Sha256};
        let group_hash = {
            let mut h = Sha256::new();
            h.update(token.as_bytes());
            hex::encode(h.finalize())
        };

        let content = format!(
            "# mrsh fleet enrollment config (auto-generated)\n\
             RendezvousServer {rdv_server}\n\
             EnrollmentToken {token}\n\
             GroupHash {group_hash}\n",
        );
        save_group_mapping(group_name, &token)?;
        println!("  config: group={}, rendezvous={}", group_name, rdv_server);
        Some(content)
    } else {
        None
    };

    // Generate single output file
    let out_path = if is_windows {
        generate_nsis_installer(opts, version, &binary_data, &auth_keys_content,
                                &install_script, startup_bat.as_deref(), config_content.as_deref())?
    } else {
        generate_self_extracting_sh(opts, version, &binary_data, &auth_keys_content,
                                     &install_script, config_content.as_deref())?
    };

    let file_size = std::fs::metadata(&out_path)?.len();
    let size_mb = file_size as f64 / 1_048_576.0;
    println!("\nInstall pack ready: {} ({:.1} MB)", out_path.display(), size_mb);

    if is_windows {
        println!("Deploy: copy to target and run as Administrator.");
        println!("The installer extracts, installs the service, and configures the firewall.");
    } else {
        println!("Deploy: copy to target and run:");
        println!("  chmod +x {} && sudo ./{}", out_path.display(), out_path.display());
    }

    if let Some(ref g) = opts.group {
        println!("Discover enrolled machines with: mrsh fleet discover --group {}", g);
    }

    Ok(out_path)
}

/// Generate a self-extracting .sh file (bash header + tar.gz payload).
fn generate_self_extracting_sh(
    opts: &InstallPackOptions,
    version: &str,
    binary_data: &[u8],
    auth_keys: &str,
    install_script: &str,
    config: Option<&str>,
) -> Result<PathBuf> {
    let out_path = match &opts.output {
        Some(p) => p.clone(),
        None => PathBuf::from(format!("mrsh-{}-linux-install.sh", version)),
    };

    // Build tar.gz in memory
    let tar_gz_data = {
        let mut tar_gz = Vec::new();
        {
            let gz = flate2::write::GzEncoder::new(&mut tar_gz, flate2::Compression::best());
            let mut ar = tar::Builder::new(gz);

            // Add binary
            add_tar_entry(&mut ar, "mrsh", binary_data, 0o755)?;

            // Add authorized_keys
            add_tar_entry(&mut ar, "authorized_keys", auth_keys.as_bytes(), 0o600)?;

            // Add install.sh (the inner installer, used by the wrapper)
            add_tar_entry(&mut ar, "install.sh", install_script.as_bytes(), 0o755)?;

            // Add config if present
            if let Some(cfg) = config {
                add_tar_entry(&mut ar, "config", cfg.as_bytes(), 0o600)?;
            }

            ar.into_inner()?.finish()?;
        }
        tar_gz
    };

    // Write self-extracting script
    let mut f = std::fs::File::create(&out_path)
        .with_context(|| format!("create {}", out_path.display()))?;

    // Bash header that extracts and runs
    write!(f, "{}", generate_sfx_header(version, opts.port))?;

    // Append tar.gz payload
    f.write_all(&tar_gz_data)?;
    f.flush()?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o755))?;
    }

    Ok(out_path)
}

/// Add a file entry to a tar archive.
fn add_tar_entry<W: IoWrite>(
    ar: &mut tar::Builder<W>,
    name: &str,
    data: &[u8],
    mode: u32,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(mode);
    header.set_mtime(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs());
    header.set_cksum();
    ar.append_data(&mut header, name, data)?;
    Ok(())
}

/// Generate the bash header for the self-extracting script.
fn generate_sfx_header(version: &str, port: u16) -> String {
    format!(r#"#!/bin/bash
# mrsh v{version} — Self-extracting installer
# Run: chmod +x <this-file> && sudo ./<this-file>
set -e

echo "=== mrsh v{version} Installer ==="
echo "Port: {port}"
echo

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run as root: sudo $0"
    exit 1
fi

# Extract payload to temp dir
TMPDIR=$(mktemp -d /tmp/rsh-install.XXXXXX)
trap "rm -rf '$TMPDIR'" EXIT

ARCHIVE=$(awk '/^__ARCHIVE_BELOW__$/ {{print NR + 1; exit 0;}}' "$0")
tail -n+"$ARCHIVE" "$0" | tar xzf - -C "$TMPDIR"

# Run inner installer
cd "$TMPDIR"
chmod +x install.sh
./install.sh

exit 0
__ARCHIVE_BELOW__
"#)
}

/// Generate an NSIS-based Windows installer (.exe).
///
/// Requires `makensis` (NSIS compiler) on the build host.
/// Install on Ubuntu: `apt install nsis`
fn generate_nsis_installer(
    opts: &InstallPackOptions,
    version: &str,
    binary_data: &[u8],
    auth_keys: &str,
    install_script: &str,
    startup_bat: Option<&str>,
    config: Option<&str>,
) -> Result<PathBuf> {
    let out_path = match &opts.output {
        Some(p) => p.clone(),
        None => PathBuf::from(format!("mrsh-{}-windows-install.exe", version)),
    };

    // Verify makensis is available
    let makensis = find_makensis()?;

    // Create temp directory with all files to embed
    let tmp = tempfile::tempdir().context("create temp dir for NSIS")?;
    let src_dir = tmp.path();

    std::fs::write(src_dir.join("mrsh.exe"), binary_data)
        .context("write mrsh.exe to temp")?;
    std::fs::write(src_dir.join("authorized_keys"), auth_keys.as_bytes())
        .context("write authorized_keys to temp")?;
    std::fs::write(src_dir.join("install.bat"), install_script.as_bytes())
        .context("write install.bat to temp")?;

    if let Some(startup) = startup_bat {
        std::fs::write(src_dir.join("startup.bat"), startup.as_bytes())
            .context("write startup.bat to temp")?;
    }
    if let Some(cfg) = config {
        std::fs::write(src_dir.join("config"), cfg.as_bytes())
            .context("write config to temp")?;
    }

    // Generate .nsi script
    let has_startup = startup_bat.is_some();
    let has_config = config.is_some();
    let nsi_script = generate_nsi_script(version, opts.port, has_startup, has_config);
    let nsi_path = src_dir.join("installer.nsi");
    std::fs::write(&nsi_path, &nsi_script).context("write installer.nsi")?;

    // Resolve absolute output path before invoking makensis
    let abs_out = if out_path.is_absolute() {
        out_path.clone()
    } else {
        std::env::current_dir()?.join(&out_path)
    };

    // Run makensis
    println!("  nsis: compiling installer...");
    let status = std::process::Command::new(&makensis)
        .arg("-V2")
        .arg(format!("-DOUTFILE={}", abs_out.display()))
        .arg(format!("-DSRCDIR={}", src_dir.display()))
        .arg(&nsi_path)
        .status()
        .with_context(|| format!("run {}", makensis.display()))?;

    if !status.success() {
        bail!("makensis failed with exit code: {:?}", status.code());
    }

    if !abs_out.exists() {
        bail!("makensis succeeded but output not found: {}", abs_out.display());
    }

    Ok(out_path)
}

/// Generate the NSIS .nsi installer script.
fn generate_nsi_script(version: &str, port: u16, has_startup: bool, has_config: bool) -> String {
    let mut s = String::new();

    // Header
    s.push_str("!include \"MUI2.nsh\"\n\n");
    s.push_str(&format!("Name \"mrsh {}\"\n", version));
    s.push_str("OutFile \"${OUTFILE}\"\n");
    s.push_str("InstallDir \"C:\\ProgramData\\mrsh\"\n");
    s.push_str("RequestExecutionLevel admin\n");
    s.push_str("SetCompressor /SOLID lzma\n\n");

    // Branding
    s.push_str(&format!("!define VERSION \"{}\"\n", version));
    s.push_str(&format!("!define PORT \"{}\"\n", port));
    s.push_str("BrandingText \"mrsh ${VERSION}\"\n\n");

    // Pages
    s.push_str("!insertmacro MUI_PAGE_INSTFILES\n");
    s.push_str("!insertmacro MUI_LANGUAGE \"English\"\n\n");

    // Install section
    s.push_str("Section \"Install\"\n");
    s.push_str("    SetOutPath $INSTDIR\n\n");

    // Stop existing services and kill all processes (ignore errors)
    s.push_str("    DetailPrint \"Stopping existing services...\"\n");
    s.push_str("    nsExec::ExecToStack 'net stop mrsh'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'net stop rsh'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'sc delete rsh'\n"); // delete legacy service registration
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'sc delete mrsh'\n"); // delete to re-register with correct binary path
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'taskkill /F /IM mrsh.exe'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'taskkill /F /IM rsh.exe'\n");
    s.push_str("    Pop $0\n");
    // Remove old rsh.exe from mrsh dir (legacy rename artifact)
    s.push_str("    Delete \"$INSTDIR\\rsh.exe\"\n");
    s.push_str("    Delete \"$INSTDIR\\rsh.exe.bak\"\n\n");

    // Extract files
    s.push_str("    DetailPrint \"Extracting files...\"\n");
    s.push_str("    File \"${SRCDIR}\\mrsh.exe\"\n");
    s.push_str("    File \"${SRCDIR}\\authorized_keys\"\n");
    s.push_str("    File \"${SRCDIR}\\install.bat\"\n");
    if has_startup {
        s.push_str("    File \"${SRCDIR}\\startup.bat\"\n");
    }
    if has_config {
        s.push_str("    File \"${SRCDIR}\\config\"\n");
    }
    s.push_str("\n");

    // Install service
    s.push_str("    DetailPrint \"Installing mrsh service...\"\n");
    s.push_str("    nsExec::ExecToStack '\"$INSTDIR\\mrsh.exe\" --install'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    StrCmp $0 \"0\" +2 0\n");
    s.push_str("    DetailPrint \"Warning: service install returned $0\"\n\n");

    // Start service
    s.push_str("    DetailPrint \"Starting mrsh service...\"\n");
    s.push_str("    nsExec::ExecToStack 'net start mrsh'\n");
    s.push_str("    Pop $0\n\n");

    // Firewall rule
    s.push_str("    DetailPrint \"Adding firewall rule...\"\n");
    s.push_str("    nsExec::ExecToStack 'netsh advfirewall firewall add rule name=\"mrsh\" dir=in action=allow program=\"$INSTDIR\\mrsh.exe\" enable=yes'\n");
    s.push_str("    Pop $0\n\n");

    // Legacy cleanup: migrate data from C:\ProgramData\remote-shell\ → mrsh\, then delete
    s.push_str("    ; --- Legacy cleanup ---\n");
    s.push_str("    IfFileExists \"C:\\ProgramData\\remote-shell\\*.*\" 0 +11\n");
    s.push_str("    DetailPrint \"Migrating data from legacy remote-shell directory...\"\n");
    s.push_str("    nsExec::ExecToStack 'xcopy /E /I /Y \"C:\\ProgramData\\remote-shell\\cache\" \"$INSTDIR\\cache\"'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'xcopy /E /I /Y \"C:\\ProgramData\\remote-shell\\sessions\" \"$INSTDIR\\sessions\"'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'cmd /c copy /y \"C:\\ProgramData\\remote-shell\\banner.txt\" \"$INSTDIR\\banner.txt\"'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'cmd /c copy /y \"C:\\ProgramData\\remote-shell\\screen-token\" \"$INSTDIR\\screen-token\"'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'sc delete rsh'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    nsExec::ExecToStack 'cmd /c rmdir /s /q \"C:\\ProgramData\\remote-shell\"'\n");
    s.push_str("    Pop $0\n");
    s.push_str("    DetailPrint \"Legacy directory cleaned up.\"\n\n");

    // Launch tray in user session via scheduled task (ONLOGON task registered by --install).
    // Cannot use Exec — NSIS runs elevated (SYSTEM), Exec inherits that session.
    // schtasks /run launches the ONLOGON task in the interactive user session.
    s.push_str("    DetailPrint \"Starting tray icon...\"\n");
    s.push_str("    nsExec::ExecToStack 'schtasks /run /tn mrsh-tray'\n");
    s.push_str("    Pop $0\n\n");

    // Done
    s.push_str(&format!(
        "    DetailPrint \"Installation complete. mrsh listening on port {}.\"\n",
        port
    ));
    s.push_str("SectionEnd\n");

    s
}

/// Find the makensis executable.
fn find_makensis() -> Result<PathBuf> {
    // Check PATH
    for name in ["makensis", "makensis.exe"] {
        if let Ok(output) = std::process::Command::new("which")
            .arg(name)
            .output()
        {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return Ok(PathBuf::from(path));
                }
            }
        }
    }

    // Check PATH using `where` on Windows, `which` on Unix
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("where")
            .arg("makensis.exe")
            .output()
        {
            if output.status.success() {
                let path = String::from_utf8_lossy(&output.stdout).trim().lines().next().unwrap_or("").to_string();
                if !path.is_empty() {
                    return Ok(PathBuf::from(path));
                }
            }
        }
    }

    // Common locations
    for candidate in [
        "/usr/bin/makensis",
        "/usr/local/bin/makensis",
        r"C:\Program Files (x86)\NSIS\makensis.exe",
        r"C:\Program Files\NSIS\makensis.exe",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Ok(p);
        }
    }

    bail!(
        "makensis not found. Install NSIS:\n\
         \x20 Ubuntu/Debian: sudo apt install nsis\n\
         \x20 Windows: winget install NSIS.NSIS\n\
         \x20 macOS: brew install makensis"
    )
}

/// Find the mrsh binary to bundle.
fn find_binary(explicit: &Option<PathBuf>, is_windows: bool) -> Result<PathBuf> {
    if let Some(p) = explicit {
        if p.exists() {
            return Ok(p.clone());
        }
        bail!("specified binary not found: {}", p.display());
    }

    let binary_name = if is_windows { "mrsh.exe" } else { "mrsh" };
    let deploy_name = format!("deploy/{binary_name}");

    // Check deploy/ relative to CWD
    let deploy_path = PathBuf::from(&deploy_name);
    if deploy_path.exists() {
        return Ok(deploy_path);
    }

    // Check relative to the running executable's directory
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            let near_exe = exe_dir.join(format!("../deploy/{binary_name}"));
            if near_exe.exists() {
                return Ok(near_exe);
            }
        }
    }

    if !is_windows {
        let self_exe = std::env::current_exe().context("get current executable path")?;
        if self_exe.exists() {
            return Ok(self_exe);
        }
    }

    bail!(
        "cannot find mrsh binary. Specify with --binary or place in {}",
        deploy_name
    );
}

/// Build authorized_keys content from the user's SSH public keys.
fn build_authorized_keys(extra_keys: &[String]) -> Result<String> {
    let mut lines = Vec::new();

    let home = dirs::home_dir().context("cannot determine home directory")?;
    let ssh_dir = home.join(".ssh");
    let mrsh_dir = home.join(".mrsh");
    let rsh_dir = home.join(".rsh"); // legacy compat

    let candidates = [
        ssh_dir.join("id_ed25519.pub"),
        mrsh_dir.join("id_ed25519.pub"),
        rsh_dir.join("id_ed25519.pub"),
        ssh_dir.join("id_rsa.pub"),
    ];

    for path in &candidates {
        if path.exists() {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("read public key: {}", path.display()))?;
            let key_line = content.trim().to_string();
            if !key_line.is_empty() && !lines.contains(&key_line) {
                lines.push(key_line);
            }
        }
    }

    for key in extra_keys {
        let trimmed = key.trim().to_string();
        if !trimmed.is_empty() && !lines.contains(&trimmed) {
            lines.push(trimmed);
        }
    }

    if lines.is_empty() {
        bail!(
            "no public keys found. Generate one with: mrsh keygen\n\
             Or specify with: --key <path-to-public-key>"
        );
    }

    Ok(lines.join("\n") + "\n")
}

/// Path to the local groups registry file (~/.mrsh/groups.json).
fn groups_file() -> Result<PathBuf> {
    let home = dirs::home_dir().context("cannot determine home directory")?;
    let mrsh_path = home.join(".mrsh").join("groups.json");
    let rsh_path = home.join(".rsh").join("groups.json");
    // Prefer new location, fall back to legacy
    Ok(if mrsh_path.exists() { mrsh_path } else { rsh_path })
}

fn load_groups() -> Result<std::collections::HashMap<String, String>> {
    let path = groups_file()?;
    if !path.exists() {
        return Ok(std::collections::HashMap::new());
    }
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&data).context("parse groups.json")
}

fn save_groups(groups: &std::collections::HashMap<String, String>) -> Result<()> {
    let path = groups_file()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(groups)?;
    std::fs::write(&path, data).with_context(|| format!("write {}", path.display()))
}

fn load_or_create_group_token(group_name: &str) -> Result<String> {
    let mut groups = load_groups()?;
    if let Some(token) = groups.get(group_name) {
        return Ok(token.clone());
    }
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    use base64::Engine;
    let token = base64::engine::general_purpose::STANDARD.encode(bytes);
    groups.insert(group_name.to_string(), token.clone());
    save_groups(&groups)?;
    Ok(token)
}

fn save_group_mapping(group_name: &str, token: &str) -> Result<()> {
    let mut groups = load_groups()?;
    groups.insert(group_name.to_string(), token.to_string());
    save_groups(&groups)
}

/// Look up the enrollment token for a named group.
pub fn get_group_token(group_name: &str) -> Result<String> {
    let groups = load_groups()?;
    groups.get(group_name).cloned()
        .with_context(|| format!("group '{}' not found in ~/.mrsh/groups.json — create it with: mrsh install-pack --group {}", group_name, group_name))
}

/// Generate Windows install.bat script.
fn generate_windows_script(port: u16, nas_auth: &Option<String>) -> String {
    let mut script = String::from("@echo off\r\n");
    script.push_str("setlocal\r\n");
    script.push_str("echo === mrsh Installer ===\r\n");
    script.push_str("echo.\r\n");
    script.push_str(&format!(
        "echo Version: {}\r\n",
        env!("CARGO_PKG_VERSION")
    ));
    script.push_str(&format!("echo Port: {}\r\n", port));
    script.push_str("echo.\r\n\r\n");

    script.push_str("net session >nul 2>&1\r\n");
    script.push_str("if %errorlevel% neq 0 (\r\n");
    script.push_str("    echo ERROR: Run this script as Administrator.\r\n");
    script.push_str("    echo Right-click install.bat and select \"Run as administrator\".\r\n");
    script.push_str("    pause\r\n");
    script.push_str("    exit /b 1\r\n");
    script.push_str(")\r\n\r\n");

    let data_dir = r"C:\ProgramData\mrsh";
    // Stop everything and clean up before installing
    script.push_str("echo Stopping all services...\r\n");
    script.push_str("net stop mrsh >nul 2>&1\r\n");
    script.push_str("net stop rsh >nul 2>&1\r\n");
    script.push_str("sc delete rsh >nul 2>&1\r\n");
    script.push_str("sc delete mrsh >nul 2>&1\r\n");
    script.push_str("taskkill /F /IM mrsh.exe >nul 2>&1\r\n");
    script.push_str("taskkill /F /IM rsh.exe >nul 2>&1\r\n");
    script.push_str("timeout /t 3 /nobreak >nul\r\n\r\n");

    script.push_str(&format!(
        "if not exist \"{}\" mkdir \"{}\"\r\n",
        data_dir, data_dir
    ));

    // Remove old rsh.exe from mrsh dir (legacy rename artifact)
    script.push_str(&format!(
        "del /q \"{}\\rsh.exe\" >nul 2>&1\r\n", data_dir));
    script.push_str(&format!(
        "del /q \"{}\\rsh.exe.bak\" >nul 2>&1\r\n\r\n", data_dir));

    script.push_str(&format!(
        "copy /Y \"%~dp0mrsh.exe\" \"{}\\mrsh.exe\"\r\n",
        data_dir
    ));
    script.push_str(&format!(
        "copy /Y \"%~dp0authorized_keys\" \"{}\\authorized_keys\"\r\n",
        data_dir
    ));

    if nas_auth.is_some() {
        script.push_str(&format!(
            "if exist \"%~dp0startup.bat\" copy /Y \"%~dp0startup.bat\" \"{}\\startup.bat\"\r\n",
            data_dir
        ));
    }

    script.push_str(&format!(
        "if exist \"%~dp0config\" copy /Y \"%~dp0config\" \"{}\\config\"\r\n",
        data_dir
    ));

    script.push_str("echo.\r\n");
    script.push_str("echo Files copied.\r\n\r\n");

    script.push_str(&format!(
        "\"{}\\mrsh.exe\" --install\r\n",
        data_dir
    ));
    script.push_str("if %errorlevel% neq 0 (\r\n");
    script.push_str("    echo ERROR: Service installation failed.\r\n");
    script.push_str("    pause\r\n");
    script.push_str("    exit /b 1\r\n");
    script.push_str(")\r\n\r\n");

    script.push_str("net start mrsh\r\n");
    script.push_str("echo.\r\n\r\n");

    script.push_str(&format!(
        "netsh advfirewall firewall add rule name=\"mrsh\" dir=in action=allow \
         program=\"{}\\mrsh.exe\" enable=yes >nul 2>&1\r\n",
        data_dir
    ));
    script.push_str("echo Firewall rule added.\r\n\r\n");

    // Legacy cleanup
    script.push_str("if exist C:\\ProgramData\\remote-shell (\r\n");
    script.push_str("    echo Cleaning up legacy directory...\r\n");
    script.push_str(&format!(
        "    xcopy /E /I /Y C:\\ProgramData\\remote-shell\\cache \"{}\\cache\" >nul 2>&1\r\n", data_dir));
    script.push_str(&format!(
        "    xcopy /E /I /Y C:\\ProgramData\\remote-shell\\sessions \"{}\\sessions\" >nul 2>&1\r\n", data_dir));
    script.push_str(&format!(
        "    copy /Y C:\\ProgramData\\remote-shell\\banner.txt \"{}\\banner.txt\" >nul 2>&1\r\n", data_dir));
    script.push_str(&format!(
        "    copy /Y C:\\ProgramData\\remote-shell\\screen-token \"{}\\screen-token\" >nul 2>&1\r\n", data_dir));
    script.push_str("    sc delete rsh >nul 2>&1\r\n");
    script.push_str("    rmdir /s /q C:\\ProgramData\\remote-shell\r\n");
    script.push_str("    echo Legacy directory removed.\r\n");
    script.push_str(")\r\n\r\n");

    // Launch tray in user session (start /b = background, no new window)
    script.push_str(&format!(
        "start \"\" \"{}\\mrsh.exe\" --tray\r\n\r\n", data_dir));

    script.push_str("echo === Installation complete ===\r\n");
    script.push_str(&format!(
        "echo mrsh is now listening on port {}.\r\n",
        port
    ));
    script.push_str("echo You can connect from the source machine with:\r\n");
    script.push_str("echo   mrsh -h <this-machine-ip> ping\r\n");
    script.push_str("echo.\r\n");
    script.push_str("pause\r\n");

    script
}

/// Generate Linux install.sh script.
fn generate_linux_script(port: u16) -> String {
    let mut script = String::from("#!/bin/bash\n");
    script.push_str("set -e\n\n");
    script.push_str(&format!(
        "echo \"=== mrsh Installer (v{}) ===\"\n",
        env!("CARGO_PKG_VERSION")
    ));
    script.push_str(&format!("echo \"Port: {}\"\n", port));
    script.push_str("echo\n\n");

    script.push_str("if [ \"$(id -u)\" -ne 0 ]; then\n");
    script.push_str("    echo \"ERROR: Run as root: sudo $0\"\n");
    script.push_str("    exit 1\n");
    script.push_str("fi\n\n");

    let bin_dir = "/usr/local/bin";
    let conf_dir = "/etc/mrsh";

    script.push_str(&format!("install -m 755 \"$(dirname \"$0\")/mrsh\" \"{}/mrsh\"\n", bin_dir));
    script.push_str(&format!("ln -sf \"{0}/mrsh\" \"{0}/rsh\" 2>/dev/null\n", bin_dir)); // compat symlink
    script.push_str(&format!("echo \"Binary installed: {}/mrsh\"\n\n", bin_dir));

    script.push_str(&format!("mkdir -p \"{}\"\n", conf_dir));
    script.push_str(&format!(
        "install -m 600 \"$(dirname \"$0\")/authorized_keys\" \"{}/authorized_keys\"\n",
        conf_dir
    ));
    script.push_str(&format!(
        "if [ -f \"$(dirname \"$0\")/config\" ]; then\n\
         \x20   install -m 600 \"$(dirname \"$0\")/config\" \"{}/config\"\n\
         \x20   echo \"Fleet enrollment config installed.\"\n\
         fi\n",
        conf_dir
    ));

    script.push_str(&format!("echo \"Config directory: {}\"\n\n", conf_dir));

    script.push_str(&format!("{}/mrsh --install\n", bin_dir));
    script.push_str("echo \"Systemd service installed.\"\n\n");

    script.push_str("systemctl daemon-reload\n");
    script.push_str("systemctl enable --now mrsh\n");
    script.push_str("echo \"Service started.\"\n\n");

    script.push_str("echo\n");
    script.push_str("echo \"=== Installation complete ===\"\n");
    script.push_str(&format!("echo \"mrsh listening on port {}\"\n", port));
    script.push_str("echo \"Connect with: mrsh -h <this-machine-ip> ping\"\n");

    script
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_authorized_keys_with_extras() {
        let keys = vec!["ssh-ed25519 AAAA testkey".to_string()];
        let result = build_authorized_keys(&keys).unwrap();
        assert!(result.contains("ssh-ed25519 AAAA testkey"));
        assert!(result.ends_with('\n'));
    }

    #[test]
    fn build_authorized_keys_deduplicates() {
        let keys = vec![
            "ssh-ed25519 AAAA key1".to_string(),
            "ssh-ed25519 AAAA key1".to_string(),
        ];
        let result = build_authorized_keys(&keys).unwrap();
        assert_eq!(result.matches("key1").count(), 1);
    }

    #[test]
    fn windows_script_contains_essentials() {
        let script = generate_windows_script(8822, &None);
        assert!(script.contains("net session"));
        assert!(script.contains("mrsh.exe"));
        assert!(script.contains("--install"));
        assert!(script.contains("net start mrsh"));
        assert!(script.contains("netsh advfirewall"));
        assert!(script.contains("ProgramData"));
    }

    #[test]
    fn windows_script_includes_startup_bat() {
        let script =
            generate_windows_script(8822, &Some("net use \\\\nas\\share".to_string()));
        assert!(script.contains("startup.bat"));
    }

    #[test]
    fn linux_script_contains_essentials() {
        let script = generate_linux_script(8822);
        assert!(script.contains("id -u"));
        assert!(script.contains("install -m 755"));
        assert!(script.contains("--install"));
        assert!(script.contains("systemctl enable"));
        assert!(script.contains("/etc/mrsh"));
    }

    #[test]
    fn sfx_header_has_archive_marker() {
        let header = generate_sfx_header("5.13.0", 8822);
        assert!(header.contains("__ARCHIVE_BELOW__"));
        assert!(header.starts_with("#!/bin/bash"));
        assert!(header.contains("tar xzf"));
    }

    #[test]
    fn generate_linux_sfx() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("test-install.sh");
        let fake_bin = dir.path().join("mrsh");
        std::fs::write(&fake_bin, b"fake-binary-content").unwrap();

        let opts = InstallPackOptions {
            platform: "linux".to_string(),
            output: Some(out.clone()),
            binary: Some(fake_bin),
            extra_keys: vec!["ssh-ed25519 AAAA testkey".to_string()],
            port: 8822,
            nas_auth: None,
            group: None,
            rendezvous_server: None,
        };

        let result = generate(&opts).unwrap();
        assert_eq!(result, out);
        assert!(out.exists());

        // Verify it starts with shebang
        let content = std::fs::read(&out).unwrap();
        assert!(content.starts_with(b"#!/bin/bash"));
        // Verify it contains the archive marker
        let text = String::from_utf8_lossy(&content);
        assert!(text.contains("__ARCHIVE_BELOW__"));
    }

    #[test]
    fn nsi_script_has_required_sections() {
        let script = generate_nsi_script("5.15.0", 8822, false, false);
        assert!(script.contains("MUI2.nsh"));
        assert!(script.contains("mrsh 5.15.0"));
        assert!(script.contains("RequestExecutionLevel admin"));
        assert!(script.contains("ProgramData\\mrsh"));
        assert!(script.contains("mrsh.exe"));
        assert!(script.contains("authorized_keys"));
        assert!(script.contains("--install"));
        assert!(script.contains("net start mrsh"));
        assert!(script.contains("netsh advfirewall"));
        assert!(script.contains("8822"));
    }

    #[test]
    fn nsi_script_includes_optional_files() {
        let script = generate_nsi_script("5.15.0", 9822, true, true);
        assert!(script.contains("startup.bat"));
        assert!(script.contains("config"));
        assert!(script.contains("9822"));
    }

    #[test]
    fn nsi_script_excludes_optional_files_when_absent() {
        let script = generate_nsi_script("5.15.0", 8822, false, false);
        assert!(!script.contains("startup.bat"));
        // "config" appears in other contexts (like "Installing"), check File directive
        assert!(!script.contains("File \"${SRCDIR}\\config\""));
    }

    #[test]
    fn nsis_installer_e2e() {
        // Skip if makensis not available
        if find_makensis().is_err() {
            eprintln!("skipping nsis_installer_e2e: makensis not found");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("test-install.exe");
        let fake_bin = dir.path().join("mrsh.exe");
        std::fs::write(&fake_bin, b"fake-windows-binary").unwrap();

        let opts = InstallPackOptions {
            platform: "windows".to_string(),
            output: Some(out.clone()),
            binary: Some(fake_bin),
            extra_keys: vec!["ssh-ed25519 AAAA winkey".to_string()],
            port: 9822,
            nas_auth: Some("net use \\\\nas\\share /user:dom\\usr pass".to_string()),
            group: None,
            rendezvous_server: None,
        };

        let result = generate(&opts).unwrap();
        assert_eq!(result, out);
        assert!(out.exists());

        // NSIS installer should be a valid PE (starts with MZ)
        let data = std::fs::read(&out).unwrap();
        assert!(data.len() > 100, "installer too small: {} bytes", data.len());
        assert_eq!(&data[0..2], b"MZ", "not a valid PE executable");
    }
}
