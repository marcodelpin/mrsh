//! Fleet management — status and update across configured hosts.
//! Reads ~/.rsh/config for host list, probes concurrently.
//! Update: push binary + self-update to all outdated hosts.

use std::time::{Duration, Instant};

use rsh_core::config::{Config, HostConfig};
use tracing::{debug, warn};

/// Fleet host status after probing.
#[derive(Debug, Clone)]
pub struct HostStatus {
    pub name: String,
    pub hostname: String,
    pub port: u16,
    pub online: bool,
    pub version: Option<String>,
    pub caps: Vec<String>,
    pub latency_ms: u64,
    pub error: Option<String>,
    /// Device ID for relay fallback (from config).
    pub device_id: Option<String>,
    /// Rendezvous server for relay fallback.
    pub rendezvous_server: Option<String>,
    /// Rendezvous key for relay fallback.
    pub rendezvous_key: Option<String>,
    /// QUIC port for this host (None = QUIC not configured).
    pub quic_port: Option<u16>,
    /// Transport used to reach the host ("tls", "relay", "quic").
    pub transport: &'static str,
}

/// Maximum concurrent probes.
const MAX_CONCURRENT: usize = 10;

/// Probe timeout per host.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Get status of all fleet hosts.
///
/// Merges two sources:
/// 1. Config hosts (local `~/.rsh/config` Host blocks) — user-defined aliases/overrides
/// 2. hbbs peers (dynamic, via `ListPeers` query) — all registered peers
///
/// Config hosts take precedence: if a config host's DeviceID matches an hbbs peer,
/// the config entry is used (with its alias name and hostname override).
/// hbbs peers not covered by config are added as dynamic entries.
pub async fn status(config: &Config) -> Vec<HostStatus> {
    // Collect config hosts
    let config_hosts: Vec<&HostConfig> = config.hosts.iter().collect();

    // Query hbbs for dynamic peers (best-effort, non-blocking)
    let hbbs_peers = discover_from_hbbs(config).await;

    // Build the probe list: config hosts + any hbbs peers not already in config
    let config_device_ids: std::collections::HashSet<String> = config_hosts
        .iter()
        .filter_map(|h| h.device_id.clone())
        .collect();

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT));
    let mut handles = Vec::new();

    // Probe config hosts
    for host in &config_hosts {
        let sem = semaphore.clone();
        let name = host.pattern.clone();
        let hostname = host
            .hostname
            .clone()
            .unwrap_or_else(|| host.pattern.clone());
        let port = host.port;
        let device_id = host.device_id.clone();
        let rdv_server = config.rendezvous_server.clone();
        let rdv_key = config.rendezvous_key.clone();
        let quic_port = host.quic_port;

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            probe_host(&name, &hostname, port, device_id, rdv_server, rdv_key, quic_port).await
        }));
    }

    // Probe hbbs peers not already in config (by DeviceID match)
    for peer in &hbbs_peers {
        if config_device_ids.contains(&peer.device_id) {
            continue; // config host takes precedence
        }
        let sem = semaphore.clone();
        let name = if peer.hostname.is_empty() {
            peer.device_id.clone()
        } else {
            peer.hostname.clone()
        };
        let hostname = peer.addr
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| name.clone());
        let device_id = Some(peer.device_id.clone());
        let rdv_server = config.rendezvous_server.clone();
        let rdv_key = config.rendezvous_key.clone();
        let port = if peer.service_port > 0 { peer.service_port } else { 8822 };

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            probe_host(&name, &hostname, port, device_id, rdv_server, rdv_key, None).await
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(status) => results.push(status),
            Err(e) => warn!("probe task failed: {}", e),
        }
    }

    results
}

/// Query hbbs for all registered peers (best-effort).
async fn discover_from_hbbs(config: &Config) -> Vec<rsh_relay::rendezvous::GroupPeerInfo> {
    let rdv_server = match &config.rendezvous_server {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return Vec::new(),
    };
    let rdv_key = config.rendezvous_key.clone().unwrap_or_default();

    let client = rsh_relay::rendezvous::Client {
        servers: vec![rdv_server],
        licence_key: rdv_key,
        local_id: String::new(),
        group_hash: String::new(),
        hostname: String::new(),
        platform: String::new(),
        service_port: 0,
    };

    match client.list_peers().await {
        Ok(peers) => {
            debug!("hbbs: discovered {} peers", peers.len());
            peers
        }
        Err(e) => {
            debug!("hbbs: list_peers failed (non-fatal): {}", e);
            Vec::new()
        }
    }
}

/// Probe a single host for version and capabilities.
/// Tries TLS direct first, then relay, then QUIC (if quic_port configured).
async fn probe_host(
    name: &str,
    hostname: &str,
    port: u16,
    device_id: Option<String>,
    rdv_server: Option<String>,
    rdv_key: Option<String>,
    quic_port: Option<u16>,
) -> HostStatus {
    let start = Instant::now();
    debug!("probing {} ({}:{})", name, hostname, port);

    // Try direct TLS connection first
    let result = tokio::time::timeout(PROBE_TIMEOUT, async {
        let opts = crate::client::ConnectOptions {
            host: hostname.to_string(),
            port,
            key_path: None,
            password_user: None,
        };
        crate::client::connect(&opts).await
    })
    .await;

    let latency = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(client)) => HostStatus {
            name: name.to_string(),
            hostname: hostname.to_string(),
            port,
            online: true,
            version: client.server_version,
            caps: client.server_caps,
            latency_ms: latency,
            error: None,
            device_id,
            rendezvous_server: rdv_server,
            rendezvous_key: rdv_key,
            quic_port,
            transport: "tls",
        },
        direct_err => {
            // Direct TLS failed — try relay if device_id present
            if let Some(ref dev_id) = device_id {
                let relay_start = Instant::now();
                debug!("direct failed for {}, trying relay via {}", name, dev_id);
                let relay_opts = crate::relay_connect::RelayConnectOptions {
                    device_id: dev_id.clone(),
                    rendezvous_server: rdv_server
                        .clone()
                        .unwrap_or_else(|| "rdv.example.com:21116".to_string()),
                    rendezvous_key: rdv_key.clone().unwrap_or_default(),
                    key_path: None,
                    server_name: hostname.to_string(),
                    port,
                };
                match tokio::time::timeout(
                    Duration::from_secs(15),
                    crate::relay_connect::connect_via_relay(&relay_opts),
                )
                .await
                {
                    Ok(Ok(client)) => {
                        let relay_latency = relay_start.elapsed().as_millis() as u64;
                        return HostStatus {
                            name: name.to_string(),
                            hostname: hostname.to_string(),
                            port,
                            online: true,
                            version: client.server_version,
                            caps: client.server_caps,
                            latency_ms: relay_latency,
                            error: None,
                            device_id: Some(dev_id.clone()),
                            rendezvous_server: rdv_server,
                            rendezvous_key: rdv_key,
                            quic_port,
                            transport: "relay",
                        };
                    }
                    Ok(Err(relay_e)) => {
                        debug!("relay also failed for {}: {}", name, relay_e);
                    }
                    Err(_) => {
                        debug!("relay timeout for {}", name);
                    }
                }
            }

            // TLS + relay failed — try QUIC if configured
            #[cfg(feature = "quic")]
            if let Some(qport) = quic_port {
                let quic_start = Instant::now();
                debug!("tls+relay failed for {}, trying QUIC on port {}", name, qport);
                let addr_str = format!("{}:{}", hostname, qport);
                if let Ok(addr) = addr_str.parse() {
                    match tokio::time::timeout(
                        PROBE_TIMEOUT,
                        crate::quic::QuicClient::connect(addr, hostname, None),
                    )
                    .await
                    {
                        Ok(Ok(client)) => {
                            let quic_latency = quic_start.elapsed().as_millis() as u64;
                            return HostStatus {
                                name: name.to_string(),
                                hostname: hostname.to_string(),
                                port,
                                online: true,
                                version: client.server_version,
                                caps: client.server_caps,
                                latency_ms: quic_latency,
                                error: None,
                                device_id,
                                rendezvous_server: rdv_server,
                                rendezvous_key: rdv_key,
                                quic_port: Some(qport),
                                transport: "quic",
                            };
                        }
                        Ok(Err(e)) => {
                            debug!("QUIC also failed for {}: {}", name, e);
                        }
                        Err(_) => {
                            debug!("QUIC timeout for {}", name);
                        }
                    }
                }
            }

            // All transports failed
            let error_msg = match direct_err {
                Ok(Err(e)) => format!("{}", e),
                Err(_) => "timeout".to_string(),
                _ => unreachable!(),
            };
            HostStatus {
                name: name.to_string(),
                hostname: hostname.to_string(),
                port,
                online: false,
                version: None,
                caps: Vec::new(),
                latency_ms: latency,
                error: Some(error_msg),
                device_id,
                rendezvous_server: rdv_server,
                rendezvous_key: rdv_key,
                quic_port,
                transport: "none",
            }
        }
    }
}

/// Filter hosts that support a specific capability.
pub fn hosts_with_cap<'a>(statuses: &'a [HostStatus], cap: &str) -> Vec<&'a HostStatus> {
    statuses
        .iter()
        .filter(|s| s.online && s.caps.iter().any(|c| c == cap))
        .collect()
}

/// Format fleet status as a table string.
pub fn format_status_table(statuses: &[HostStatus]) -> String {
    if statuses.is_empty() {
        return "No hosts configured.".to_string();
    }

    let mut lines = Vec::new();
    lines.push(format!(
        "{:<20} {:<6} {:<10} {:<12} {:<8}",
        "HOST", "PORT", "STATUS", "VERSION", "LATENCY"
    ));
    lines.push("-".repeat(60));

    for s in statuses {
        let status = if s.online { "online" } else { "offline" };
        let version = s.version.as_deref().unwrap_or("-");
        let latency = if s.online {
            format!("{}ms", s.latency_ms)
        } else {
            "-".to_string()
        };
        lines.push(format!(
            "{:<20} {:<6} {:<10} {:<12} {:<8}",
            s.name, s.port, status, version, latency
        ));
    }

    lines.join("\n")
}

/// Get list of hosts that need updating (version mismatch).
pub fn hosts_needing_update<'a>(
    statuses: &'a [HostStatus],
    target_version: &str,
) -> Vec<&'a HostStatus> {
    statuses
        .iter()
        .filter(|s| s.online && s.version.as_ref().is_none_or(|v| v != target_version))
        .collect()
}

/// Result of updating a single host.
#[derive(Debug)]
pub struct UpdateResult {
    pub name: String,
    pub success: bool,
    pub old_version: Option<String>,
    pub new_version: Option<String>,
    pub error: Option<String>,
}

/// Remote temp path for the new binary.
const REMOTE_UPDATE_PATH: &str = r"C:\Temp\rsh-new.exe";

/// Update all outdated hosts in the fleet.
/// Pushes binary, sends self-update request, waits, verifies.
/// Returns results for each host attempted.
pub async fn update_fleet(
    config: &Config,
    binary_data: &[u8],
    target_version: &str,
) -> Vec<UpdateResult> {
    // Step 1: Probe all hosts
    let statuses = status(config).await;

    // Step 2: Filter outdated hosts with self-update capability
    let to_update: Vec<&HostStatus> = statuses
        .iter()
        .filter(|s| {
            s.online
                && s.caps.iter().any(|c| c == "self-update")
                && s.version.as_ref().is_none_or(|v| v != target_version)
        })
        .collect();

    if to_update.is_empty() {
        eprintln!("All hosts are current (v{}).", target_version);
        return Vec::new();
    }

    eprintln!(
        "Updating {} host(s) to v{}...\n",
        to_update.len(),
        target_version
    );

    let mut results = Vec::new();

    // Step 3: Sequential update (not parallel — avoid overwhelming network)
    for host in &to_update {
        let result = update_single_host(host, binary_data).await;
        results.push(result);
    }

    results
}

/// Update a single host: push binary → self-update → wait → verify.
async fn update_single_host(host: &HostStatus, binary_data: &[u8]) -> UpdateResult {
    let old_version = host.version.clone();
    eprint!("  {} ({}:{})... ", host.name, host.hostname, host.port);

    // Step A: Connect — try TLS direct first, then relay, then QUIC
    let opts = crate::client::ConnectOptions {
        host: host.hostname.clone(),
        port: host.port,
        key_path: None,
        password_user: None,
    };

    // Try TLS direct
    match crate::client::connect(&opts).await {
        Ok(client) => {
            return push_and_update_tls(host, client, binary_data, old_version).await;
        }
        Err(direct_err) => {
            // Try relay fallback
            if let Some(ref dev_id) = host.device_id {
                debug!(
                    "direct connect failed for {}, trying relay via {}",
                    host.name, dev_id
                );
                let relay_opts = crate::relay_connect::RelayConnectOptions {
                    device_id: dev_id.clone(),
                    rendezvous_server: host
                        .rendezvous_server
                        .clone()
                        .unwrap_or_else(|| "rdv.example.com:21116".to_string()),
                    rendezvous_key: host.rendezvous_key.clone().unwrap_or_default(),
                    key_path: None,
                    server_name: host.hostname.clone(),
                    port: host.port,
                };
                if let Ok(client) = crate::relay_connect::connect_via_relay(&relay_opts).await {
                    return push_and_update_tls(host, client, binary_data, old_version).await;
                }
            }

            // Try QUIC if configured
            #[cfg(feature = "quic")]
            if let Some(qport) = host.quic_port {
                let addr_str = format!("{}:{}", host.hostname, qport);
                if let Ok(addr) = addr_str.parse() {
                    match crate::quic::QuicClient::connect(addr, &host.hostname, None).await {
                        Ok(quic) => {
                            return push_and_update_quic(host, quic, binary_data, old_version).await;
                        }
                        Err(e) => {
                            debug!("QUIC connect also failed for {}: {}", host.name, e);
                        }
                    }
                }
            }

            eprintln!("CONNECT FAILED: {}", direct_err);
            return UpdateResult {
                name: host.name.clone(),
                success: false,
                old_version,
                new_version: None,
                error: Some(format!("all transports failed: {}", direct_err)),
            };
        }
    }
}

/// Push binary and send self-update via TLS client (direct or relay).
async fn push_and_update_tls(
    host: &HostStatus,
    mut client: crate::client::TlsClient,
    binary_data: &[u8],
    old_version: Option<String>,
) -> UpdateResult {
    // Push binary to remote temp path
    match crate::sync::push(&mut client, binary_data, REMOTE_UPDATE_PATH).await {
        Ok(r) => {
            eprint!("pushed ({} bytes)... ", r.bytes_sent);
        }
        Err(e) => {
            eprintln!("PUSH FAILED: {}", e);
            return UpdateResult {
                name: host.name.clone(),
                success: false,
                old_version,
                new_version: None,
                error: Some(format!("push: {}", e)),
            };
        }
    }

    // Send self-update request
    match crate::commands::self_update(&mut client, REMOTE_UPDATE_PATH).await {
        Ok(_) => {
            eprint!("update sent... ");
        }
        Err(e) => {
            eprintln!("UPDATE FAILED: {}", e);
            return UpdateResult {
                name: host.name.clone(),
                success: false,
                old_version,
                new_version: None,
                error: Some(format!("self-update: {}", e)),
            };
        }
    }

    drop(client); // close connection before server restarts

    // Wait for restart (20s)
    eprint!("waiting... ");
    tokio::time::sleep(Duration::from_secs(20)).await;

    verify_after_update(host, old_version).await
}

/// Push binary and trigger self-update via QUIC (schtask-based restart).
#[cfg(feature = "quic")]
async fn push_and_update_quic(
    host: &HostStatus,
    quic: crate::quic::QuicClient,
    binary_data: &[u8],
    old_version: Option<String>,
) -> UpdateResult {
    // Push binary to remote temp path
    match quic.push(REMOTE_UPDATE_PATH, binary_data).await {
        Ok(bytes) => {
            eprint!("pushed ({} bytes, quic)... ", bytes);
        }
        Err(e) => {
            eprintln!("PUSH FAILED (quic): {}", e);
            return UpdateResult {
                name: host.name.clone(),
                success: false,
                old_version,
                new_version: None,
                error: Some(format!("quic push: {}", e)),
            };
        }
    }

    // Trigger update via scheduled task (service mode)
    let win_path = REMOTE_UPDATE_PATH.replace('/', "\\");
    let update_cmd = format!(
        "schtasks /create /tn rsh-fleet-upd /tr \
         \"cmd /c net stop rsh & \
         timeout /t 2 /nobreak >nul & \
         copy /y {win} C:\\ProgramData\\remote-shell\\rsh.exe & \
         net start rsh & \
         del {win} & \
         schtasks /delete /tn rsh-fleet-upd /f\" \
         /sc once /st 00:00 /f /ru SYSTEM",
        win = win_path
    );
    if let Err(e) = quic.exec(&update_cmd).await {
        eprintln!("SCHTASK CREATE FAILED: {}", e);
        return UpdateResult {
            name: host.name.clone(),
            success: false,
            old_version,
            new_version: None,
            error: Some(format!("schtask: {}", e)),
        };
    }
    if let Err(e) = quic.exec("schtasks /run /tn rsh-fleet-upd").await {
        eprintln!("SCHTASK RUN FAILED: {}", e);
        return UpdateResult {
            name: host.name.clone(),
            success: false,
            old_version,
            new_version: None,
            error: Some(format!("schtask run: {}", e)),
        };
    }
    eprint!("update triggered (quic)... ");

    drop(quic);

    // Wait for restart (25s — schtask has extra scheduling delay)
    eprint!("waiting... ");
    tokio::time::sleep(Duration::from_secs(25)).await;

    verify_after_update(host, old_version).await
}

/// Probe host post-update and return UpdateResult.
async fn verify_after_update(host: &HostStatus, old_version: Option<String>) -> UpdateResult {
    let verify = probe_host(
        &host.name,
        &host.hostname,
        host.port,
        host.device_id.clone(),
        host.rendezvous_server.clone(),
        host.rendezvous_key.clone(),
        host.quic_port,
    )
    .await;

    if verify.online {
        let new_ver = verify.version.clone();
        eprintln!("OK (v{})", new_ver.as_deref().unwrap_or("?"));
        UpdateResult {
            name: host.name.clone(),
            success: true,
            old_version,
            new_version: new_ver,
            error: None,
        }
    } else {
        eprintln!("OFFLINE after update");
        UpdateResult {
            name: host.name.clone(),
            success: false,
            old_version,
            new_version: None,
            error: Some("host offline after update".to_string()),
        }
    }
}

/// Format update results as a summary table.
pub fn format_update_results(results: &[UpdateResult]) -> String {
    if results.is_empty() {
        return String::new();
    }

    let mut lines = Vec::new();
    lines.push(format!(
        "\n{:<20} {:<10} {:<12} {:<12} {}",
        "HOST", "RESULT", "OLD", "NEW", "ERROR"
    ));
    lines.push("-".repeat(70));

    let mut success_count = 0;
    for r in results {
        let result = if r.success {
            success_count += 1;
            "OK"
        } else {
            "FAILED"
        };
        let old = r.old_version.as_deref().unwrap_or("-");
        let new = r.new_version.as_deref().unwrap_or("-");
        let error = r.error.as_deref().unwrap_or("");
        lines.push(format!(
            "{:<20} {:<10} {:<12} {:<12} {}",
            r.name, result, old, new, error
        ));
    }

    lines.push(format!(
        "\n{}/{} hosts updated successfully.",
        success_count,
        results.len()
    ));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_status(name: &str, online: bool, version: Option<&str>) -> HostStatus {
        HostStatus {
            name: name.to_string(),
            hostname: format!("{}.local", name),
            port: 8822,
            online,
            version: version.map(|v| v.to_string()),
            caps: vec!["self-update".to_string(), "shell".to_string()],
            latency_ms: 42,
            error: None,
            device_id: None,
            rendezvous_server: None,
            rendezvous_key: None,
            quic_port: None,
            transport: "tls",
        }
    }

    #[test]
    fn hosts_with_cap_filters() {
        let statuses = vec![
            mock_status("host1", true, Some("4.38.0")),
            mock_status("host2", false, None),
            mock_status("host3", true, Some("4.38.0")),
        ];
        let with_update = hosts_with_cap(&statuses, "self-update");
        assert_eq!(with_update.len(), 2); // only online hosts
    }

    #[test]
    fn hosts_needing_update_filters() {
        let statuses = vec![
            mock_status("host1", true, Some("4.38.0")),
            mock_status("host2", true, Some("4.39.0")),
            mock_status("host3", false, None),
        ];
        let need_update = hosts_needing_update(&statuses, "4.39.0");
        assert_eq!(need_update.len(), 1);
        assert_eq!(need_update[0].name, "host1");
    }

    #[test]
    fn format_status_table_empty() {
        let result = format_status_table(&[]);
        assert_eq!(result, "No hosts configured.");
    }

    #[test]
    fn format_status_table_with_hosts() {
        let statuses = vec![
            mock_status("host1", true, Some("4.38.0")),
            mock_status("host2", false, None),
        ];
        let table = format_status_table(&statuses);
        assert!(table.contains("host1"));
        assert!(table.contains("online"));
        assert!(table.contains("offline"));
        assert!(table.contains("4.38.0"));
    }

    #[test]
    fn host_status_debug() {
        let s = mock_status("test", true, Some("1.0.0"));
        let debug = format!("{:?}", s);
        assert!(debug.contains("test"));
        assert!(debug.contains("1.0.0"));
    }

    #[tokio::test]
    async fn status_empty_config() {
        let config = Config::default();
        let results = status(&config).await;
        assert!(results.is_empty());
    }

    #[test]
    fn format_update_results_empty() {
        let result = format_update_results(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn format_update_results_mixed() {
        let results = vec![
            UpdateResult {
                name: "host1".to_string(),
                success: true,
                old_version: Some("0.1.0".to_string()),
                new_version: Some("0.2.0".to_string()),
                error: None,
            },
            UpdateResult {
                name: "host2".to_string(),
                success: false,
                old_version: Some("0.1.0".to_string()),
                new_version: None,
                error: Some("connect failed".to_string()),
            },
        ];
        let table = format_update_results(&results);
        assert!(table.contains("host1"));
        assert!(table.contains("OK"));
        assert!(table.contains("host2"));
        assert!(table.contains("FAILED"));
        assert!(table.contains("1/2 hosts updated"));
    }

    #[test]
    fn update_result_debug() {
        let r = UpdateResult {
            name: "test".to_string(),
            success: true,
            old_version: Some("1.0".to_string()),
            new_version: Some("2.0".to_string()),
            error: None,
        };
        let debug = format!("{:?}", r);
        assert!(debug.contains("test"));
        assert!(debug.contains("true"));
    }

    #[tokio::test]
    async fn update_fleet_empty_config() {
        let config = Config::default();
        let results = update_fleet(&config, &[0u8; 100], "1.0.0").await;
        assert!(results.is_empty());
    }

    #[test]
    fn host_status_with_relay_fields() {
        let s = HostStatus {
            name: "relay-host".to_string(),
            hostname: "relay-host.local".to_string(),
            port: 8822,
            online: false,
            version: None,
            caps: Vec::new(),
            latency_ms: 0,
            error: Some("timeout".to_string()),
            device_id: Some("118855822".to_string()),
            rendezvous_server: Some("rdv.example.com:21116".to_string()),
            rendezvous_key: Some("testkey".to_string()),
            quic_port: None,
            transport: "none",
        };
        assert_eq!(s.device_id.as_deref(), Some("118855822"));
        assert!(s.rendezvous_server.is_some());
        let debug = format!("{:?}", s);
        assert!(debug.contains("118855822"));
    }

    #[test]
    fn mock_status_has_no_relay_fields() {
        let s = mock_status("test", true, Some("1.0.0"));
        assert!(s.device_id.is_none());
        assert!(s.rendezvous_server.is_none());
        assert!(s.rendezvous_key.is_none());
    }
}
