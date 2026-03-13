//! Relay connection — resolve DeviceID via rendezvous, connect via P2P or relay.
//! Extracted from main.rs for reuse by fleet and other callers.

use anyhow::{Context, Result, bail};
use tracing::{debug, info};

use crate::client::{ConnectOptions, TlsClient};

/// Options for connecting via relay (rendezvous + P2P/hbbr).
#[derive(Debug, Clone)]
pub struct RelayConnectOptions {
    /// Target device ID (numeric or alphanumeric).
    pub device_id: String,
    /// Rendezvous server address (host:port). Defaults to hbbs port 21116.
    pub rendezvous_server: String,
    /// Rendezvous key (licence_key for hbbs authentication).
    pub rendezvous_key: String,
    /// SSH key path for TLS auth after relay connection.
    pub key_path: Option<String>,
    /// Server name for TLS SNI (used in cert verification).
    pub server_name: String,
    /// Port for P2P direct connection attempts.
    pub port: u16,
}

/// P2P timeout when relay is available (shortened to let relay win faster).
const P2P_TIMEOUT_SECS: u64 = 5;

/// Connect to a remote host via DeviceID resolution.
///
/// Flow:
/// 1. Resolve DeviceID via hbbs (rendezvous server, UDP)
/// 2. If P2P address available: race P2P (5s timeout) vs relay fallback
/// 3. If relay-only: connect directly through hbbr relay
/// 4. Authenticate over the established stream (TLS + ed25519)
pub async fn connect_via_relay(opts: &RelayConnectOptions) -> Result<TlsClient> {
    debug!(
        "resolving DeviceID {} via {}",
        opts.device_id, opts.rendezvous_server
    );

    let rdv_client = rsh_relay::rendezvous::Client {
        servers: vec![opts.rendezvous_server.clone()],
        licence_key: opts.rendezvous_key.clone(),
        local_id: String::new(),
        group_hash: String::new(),
        hostname: String::new(),
        platform: String::new(),
        service_port: 0,
    };

    let result = rdv_client
        .resolve(&opts.device_id)
        .await
        .context("rendezvous resolve failed")?;

    // Try P2P first if address available
    if let Some(addr) = result.addr {
        debug!("P2P: trying {}:{}", addr.ip(), opts.port);
        let p2p_result = tokio::time::timeout(
            std::time::Duration::from_secs(P2P_TIMEOUT_SECS),
            crate::client::connect(&ConnectOptions {
                host: addr.ip().to_string(),
                port: opts.port,
                key_path: opts.key_path.clone(),
                password_user: None,
            }),
        )
        .await;

        match p2p_result {
            Ok(Ok(c)) => {
                info!("P2P: connected to {}", addr.ip());
                return Ok(c);
            }
            _ => {
                // P2P failed, fall through to relay
                if result.relay_server.is_empty() {
                    bail!("P2P failed and no relay server available");
                }
                debug!("P2P failed, connecting via relay {}", result.relay_server);
            }
        }
    } else if result.relay_server.is_empty() {
        bail!(
            "device {} resolved but no address or relay available",
            opts.device_id
        );
    }

    // Relay path
    let relay_addr = if result.relay_server.contains(':') {
        result.relay_server.clone()
    } else {
        format!("{}:21117", result.relay_server)
    };

    let relay_stream =
        rsh_relay::relay::connect_relay(&relay_addr, &result.uuid, &opts.rendezvous_key)
            .await
            .context("relay connect failed")?;

    debug!("relay: connected, authenticating...");
    crate::client::connect_over_stream(relay_stream, &opts.server_name, &opts.key_path).await
}

/// Build RelayConnectOptions from a HostConfig and global Config.
pub fn relay_options_from_config(
    host_config: &rsh_core::config::HostConfig,
    config: &rsh_core::config::Config,
    key_path: &Option<String>,
) -> Option<RelayConnectOptions> {
    let device_id = host_config.device_id.as_ref()?;
    let hostname = host_config
        .hostname
        .clone()
        .unwrap_or_else(|| host_config.pattern.clone());

    let rdv_server = config
        .rendezvous_server
        .as_deref()
        .unwrap_or("rdv.example.com:21116")
        .to_string();
    let rdv_key = config.rendezvous_key.clone().unwrap_or_default();

    Some(RelayConnectOptions {
        device_id: device_id.clone(),
        rendezvous_server: rdv_server,
        rendezvous_key: rdv_key,
        key_path: key_path.clone(),
        server_name: hostname,
        port: host_config.port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsh_core::config::{Config, HostConfig};

    #[test]
    fn relay_options_from_config_with_device_id() {
        let host = HostConfig {
            pattern: "myserver".to_string(),
            hostname: Some("192.168.1.100".to_string()),
            port: 8822,
            device_id: Some("118855822".to_string()),
            ..Default::default()
        };
        let mut config = Config::default();
        config.rendezvous_server = Some("rdv.example.com:21116".to_string());
        config.rendezvous_key = Some("testkey".to_string());

        let opts = relay_options_from_config(&host, &config, &None).unwrap();
        assert_eq!(opts.device_id, "118855822");
        assert_eq!(opts.rendezvous_server, "rdv.example.com:21116");
        assert_eq!(opts.rendezvous_key, "testkey");
        assert_eq!(opts.server_name, "192.168.1.100");
        assert_eq!(opts.port, 8822);
    }

    #[test]
    fn relay_options_none_without_device_id() {
        let host = HostConfig {
            pattern: "myserver".to_string(),
            hostname: Some("192.168.1.100".to_string()),
            port: 8822,
            device_id: None,
            ..Default::default()
        };
        let config = Config::default();

        assert!(relay_options_from_config(&host, &config, &None).is_none());
    }

    #[test]
    fn relay_options_uses_pattern_as_fallback_hostname() {
        let host = HostConfig {
            pattern: "myserver".to_string(),
            hostname: None, // no explicit hostname
            port: 9822,
            device_id: Some("999".to_string()),
            ..Default::default()
        };
        let config = Config::default();

        let opts = relay_options_from_config(&host, &config, &Some("/tmp/key".to_string()))
            .unwrap();
        assert_eq!(opts.server_name, "myserver");
        assert_eq!(opts.key_path, Some("/tmp/key".to_string()));
    }

    #[test]
    fn relay_connect_options_debug() {
        let opts = RelayConnectOptions {
            device_id: "12345".to_string(),
            rendezvous_server: "rdv.example.com:21116".to_string(),
            rendezvous_key: String::new(),
            key_path: None,
            server_name: "host".to_string(),
            port: 8822,
        };
        let debug = format!("{:?}", opts);
        assert!(debug.contains("12345"));
        assert!(debug.contains("rdv.example.com"));
    }
}
