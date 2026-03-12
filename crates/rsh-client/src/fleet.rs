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
}

/// Maximum concurrent probes.
const MAX_CONCURRENT: usize = 10;

/// Probe timeout per host.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Get status of all configured hosts.
pub async fn status(config: &Config) -> Vec<HostStatus> {
    let hosts: Vec<&HostConfig> = config.hosts.iter().collect();
    if hosts.is_empty() {
        return Vec::new();
    }

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT));
    let mut handles = Vec::new();

    for host in &hosts {
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

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok();
            probe_host(&name, &hostname, port, device_id, rdv_server, rdv_key).await
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

/// Probe a single host for version and capabilities.
/// Tries direct connection first; falls back to relay if device_id is present.
async fn probe_host(
    name: &str,
    hostname: &str,
    port: u16,
    device_id: Option<String>,
    rdv_server: Option<String>,
    rdv_key: Option<String>,
) -> HostStatus {
    let start = Instant::now();
    debug!("probing {} ({}:{})", name, hostname, port);

    // Try direct connection first
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
        },
        direct_err => {
            // Direct failed — try relay if device_id present
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

            // Both failed (or no device_id)
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

    // Step A: Connect (direct first, relay fallback if device_id present)
    let opts = crate::client::ConnectOptions {
        host: host.hostname.clone(),
        port: host.port,
        key_path: None,
        password_user: None,
    };

    let mut client = match crate::client::connect(&opts).await {
        Ok(c) => c,
        Err(direct_err) => {
            // Try relay fallback if device_id is available
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
                match crate::relay_connect::connect_via_relay(&relay_opts).await {
                    Ok(c) => c,
                    Err(relay_err) => {
                        eprintln!("CONNECT FAILED (direct + relay): {}", relay_err);
                        return UpdateResult {
                            name: host.name.clone(),
                            success: false,
                            old_version,
                            new_version: None,
                            error: Some(format!(
                                "direct: {}, relay: {}",
                                direct_err, relay_err
                            )),
                        };
                    }
                }
            } else {
                eprintln!("CONNECT FAILED: {}", direct_err);
                return UpdateResult {
                    name: host.name.clone(),
                    success: false,
                    old_version,
                    new_version: None,
                    error: Some(format!("connect: {}", direct_err)),
                };
            }
        }
    };

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

    // Step B: Send self-update request
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

    drop(client); // close connection before restart

    // Step C: Wait for restart (20s)
    eprint!("waiting... ");
    tokio::time::sleep(Duration::from_secs(20)).await;

    // Step D: Verify new version
    let verify = probe_host(
        &host.name,
        &host.hostname,
        host.port,
        host.device_id.clone(),
        host.rendezvous_server.clone(),
        host.rendezvous_key.clone(),
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
