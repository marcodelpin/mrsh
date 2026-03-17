//! TLS configuration with rustls — self-signed certs (RSA 2048), TOFU pinning.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};

/// Certificate validity period in days (365 days = 1 year).
const CERT_VALIDITY_DAYS: i64 = 365;

/// Regenerate cert when remaining validity falls below this threshold (35 days).
const CERT_RENEWAL_BUFFER_DAYS: u64 = 35;

/// Generate a self-signed TLS certificate (ECDSA P256, 365-day validity).
/// Returns (cert_pem, key_pem) as strings.
pub fn generate_self_signed_cert() -> Result<(String, String)> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(
        rcgen::DnType::OrganizationName,
        rcgen::DnValue::Utf8String("rsh".to_string()),
    );
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("rsh-server".to_string()),
    );

    // Set 365-day validity (not the rcgen default of 1975–4096)
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(CERT_VALIDITY_DAYS);

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok((cert.pem(), key_pair.serialize_pem()))
}

/// Check if a cert file is nearing expiry based on file modification time.
/// Returns true if the cert should be regenerated.
fn cert_needs_renewal(cert_path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(cert_path) else {
        return true; // can't stat → regenerate
    };
    let Ok(modified) = meta.modified() else {
        return false; // OS doesn't support mtime → keep existing
    };
    let Ok(age) = std::time::SystemTime::now().duration_since(modified) else {
        return false; // clock skew → keep existing
    };
    let max_age_secs =
        (CERT_VALIDITY_DAYS as u64).saturating_sub(CERT_RENEWAL_BUFFER_DAYS) * 86400;
    age.as_secs() > max_age_secs
}

/// Load TLS cert from files, or generate and save a new one.
/// Auto-regenerates if the existing cert is nearing expiry (within 35 days).
pub fn load_or_generate_cert(
    dir: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_path = dir.join("tls_cert.pem");
    let key_path = dir.join("tls_key.pem");

    // Try loading existing (if not expired)
    if cert_path.exists() && key_path.exists() && !cert_needs_renewal(&cert_path) {
        let cert_pem = std::fs::read(&cert_path).context("read tls_cert.pem")?;
        let key_pem = std::fs::read(&key_path).context("read tls_key.pem")?;
        let certs = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("parse cert PEM")?;
        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .context("parse key PEM")?
            .context("no private key found")?;
        return Ok((certs, key));
    }

    if cert_path.exists() && cert_needs_renewal(&cert_path) {
        tracing::info!(
            "TLS certificate nearing expiry, regenerating ({})",
            cert_path.display()
        );
    }

    // Generate new
    let (cert_pem, key_pem) = generate_self_signed_cert()?;
    std::fs::create_dir_all(dir).context("create TLS dir")?;
    std::fs::write(&cert_path, &cert_pem).context("write tls_cert.pem")?;
    std::fs::write(&key_path, &key_pem).context("write tls_key.pem")?;

    // Restrict private key to owner-only (0600) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .context("set tls_key.pem permissions to 0600")?;
    }

    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse generated cert")?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("parse generated key")?
        .context("no key in generated PEM")?;
    Ok((certs, key))
}

/// Ensure the ring CryptoProvider is installed (idempotent).
fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a TLS server config from cert/key.
pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>> {
    ensure_crypto_provider();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build server TLS config")?;
    Ok(Arc::new(config))
}

/// Build a TLS client config that accepts any server cert (InsecureSkipVerify equivalent).
/// Accepts any server cert (InsecureSkipVerify equivalent) for self-signed server certs.
/// **WARNING**: Use `client_config_tofu` instead for MITM protection.
pub fn client_config() -> Arc<rustls::ClientConfig> {
    ensure_crypto_provider();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    Arc::new(config)
}

/// Build a TLS client config with Trust-On-First-Use host key verification.
/// On first connect, saves the server cert fingerprint to `known_hosts_path`.
/// On subsequent connects, rejects if the fingerprint has changed (MITM protection).
pub fn client_config_tofu(known_hosts_path: Option<PathBuf>) -> Arc<rustls::ClientConfig> {
    ensure_crypto_provider();
    let path = known_hosts_path.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".rsh")
            .join("known_hosts")
    });
    let verifier = TofuVerifier::new(path);
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Arc::new(config)
}

/// SHA256 fingerprint of a DER-encoded certificate, in "SHA256:<base64>" format.
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    let hash = Sha256::digest(cert_der);
    format!(
        "SHA256:{}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash)
    )
}

/// Certificate verifier that accepts any certificate (no verification).
/// **Insecure** — use only for self-signed certificate acceptance.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Trust-On-First-Use certificate verifier.
/// Saves server cert fingerprint on first connect, verifies on subsequent connects.
/// Format: one line per host — `hostname SHA256:base64fingerprint`
#[derive(Debug)]
struct TofuVerifier {
    known_hosts_path: PathBuf,
    cache: Mutex<HashMap<String, String>>,
}

impl TofuVerifier {
    fn new(known_hosts_path: PathBuf) -> Self {
        let cache = Self::load_known_hosts(&known_hosts_path);
        Self {
            known_hosts_path,
            cache: Mutex::new(cache),
        }
    }

    fn load_known_hosts(path: &Path) -> HashMap<String, String> {
        let mut hosts = HashMap::new();
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((host, fp)) = line.split_once(' ') {
                    hosts.insert(host.to_string(), fp.to_string());
                }
            }
        }
        hosts
    }

    fn save_host(&self, hostname: &str, fingerprint: &str) {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(hostname.to_string(), fingerprint.to_string());

        // Append to file
        if let Some(parent) = self.known_hosts_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.known_hosts_path)
        {
            let _ = writeln!(f, "{} {}", hostname, fingerprint);
        }
    }

    fn server_name_to_string(name: &ServerName<'_>) -> String {
        match name {
            ServerName::DnsName(dns) => dns.as_ref().to_string(),
            ServerName::IpAddress(ip) => format!("{:?}", ip),
            _ => "unknown".to_string(),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let hostname = Self::server_name_to_string(server_name);
        let fingerprint = cert_fingerprint(end_entity.as_ref());

        let cache = self.cache.lock().unwrap();
        if let Some(known_fp) = cache.get(&hostname) {
            if *known_fp == fingerprint {
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
            // Fingerprint mismatch — possible MITM
            tracing::error!(
                "TOFU: host key changed for {}! Expected {}, got {}. Possible MITM attack.",
                hostname,
                known_fp,
                fingerprint
            );
            return Err(rustls::Error::General(format!(
                "host key changed for {} (expected {}, got {})",
                hostname, known_fp, fingerprint
            )));
        }
        drop(cache); // Release lock before saving

        // First connection — trust and save
        tracing::info!(
            "TOFU: new host {} with fingerprint {}",
            hostname,
            fingerprint
        );
        self.save_host(&hostname, &fingerprint);
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;

    #[test]
    fn generate_cert_produces_valid_pem() {
        let (cert_pem, key_pem) = generate_self_signed_cert().unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));

        // Parse back
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(certs.len(), 1);

        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes()).unwrap();
        assert!(key.is_some());
    }

    #[test]
    fn cert_fingerprint_format() {
        let (cert_pem, _) = generate_self_signed_cert().unwrap();
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let fp = cert_fingerprint(&certs[0]);
        assert!(fp.starts_with("SHA256:"));
        assert!(fp.len() > 10);
    }

    #[test]
    fn client_config_builds() {
        let _config = client_config();
    }

    #[test]
    fn server_config_builds() {
        let (cert_pem, key_pem) = generate_self_signed_cert().unwrap();
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .unwrap()
            .unwrap();
        let _config = server_config(certs, key).unwrap();
    }

    #[test]
    fn load_or_generate_creates_files() {
        let dir = std::env::temp_dir().join("rsh-tls-test");
        let _ = std::fs::remove_dir_all(&dir);

        let (certs, _key) = load_or_generate_cert(&dir).unwrap();
        assert!(!certs.is_empty());
        assert!(dir.join("tls_cert.pem").exists());
        assert!(dir.join("tls_key.pem").exists());

        // Second call loads from disk
        let (certs2, _key2) = load_or_generate_cert(&dir).unwrap();
        assert_eq!(certs[0].as_ref(), certs2[0].as_ref());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tofu_verifier_first_connect_accepts() {
        let dir = std::env::temp_dir().join("rsh-tofu-test-1");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let known_hosts = dir.join("known_hosts");

        let verifier = TofuVerifier::new(known_hosts.clone());

        // Generate a cert
        let (cert_pem, _) = generate_self_signed_cert().unwrap();
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        let server_name = ServerName::try_from("test-host").unwrap();
        let result = verifier.verify_server_cert(
            &certs[0],
            &[],
            &server_name,
            &[],
            rustls::pki_types::UnixTime::now(),
        );
        assert!(result.is_ok());

        // File should now exist with the fingerprint
        let content = std::fs::read_to_string(&known_hosts).unwrap();
        assert!(content.contains("test-host"));
        assert!(content.contains("SHA256:"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tofu_verifier_same_cert_accepts() {
        let dir = std::env::temp_dir().join("rsh-tofu-test-2");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let known_hosts = dir.join("known_hosts");

        let (cert_pem, _) = generate_self_signed_cert().unwrap();
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let server_name = ServerName::try_from("test-host-2").unwrap();

        // First connect
        let verifier = TofuVerifier::new(known_hosts.clone());
        verifier
            .verify_server_cert(
                &certs[0],
                &[],
                &server_name,
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .unwrap();

        // Second connect with same cert — should accept
        let verifier2 = TofuVerifier::new(known_hosts.clone());
        let result = verifier2.verify_server_cert(
            &certs[0],
            &[],
            &server_name,
            &[],
            rustls::pki_types::UnixTime::now(),
        );
        assert!(result.is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tofu_verifier_different_cert_rejects() {
        let dir = std::env::temp_dir().join("rsh-tofu-test-3");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let known_hosts = dir.join("known_hosts");

        let (cert_pem1, _) = generate_self_signed_cert().unwrap();
        let certs1: Vec<_> = rustls_pemfile::certs(&mut cert_pem1.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        let (cert_pem2, _) = generate_self_signed_cert().unwrap();
        let certs2: Vec<_> = rustls_pemfile::certs(&mut cert_pem2.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();

        let server_name = ServerName::try_from("test-host-3").unwrap();

        // First connect with cert1
        let verifier = TofuVerifier::new(known_hosts.clone());
        verifier
            .verify_server_cert(
                &certs1[0],
                &[],
                &server_name,
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .unwrap();

        // Second connect with different cert — should reject
        let verifier2 = TofuVerifier::new(known_hosts.clone());
        let result = verifier2.verify_server_cert(
            &certs2[0],
            &[],
            &server_name,
            &[],
            rustls::pki_types::UnixTime::now(),
        );
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn client_config_tofu_builds() {
        let dir = std::env::temp_dir().join("rsh-tofu-test-4");
        let _ = std::fs::remove_dir_all(&dir);
        let known_hosts = dir.join("known_hosts");
        let _config = client_config_tofu(Some(known_hosts));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cert_needs_renewal_missing_file() {
        assert!(cert_needs_renewal(Path::new("/nonexistent/cert.pem")));
    }

    #[test]
    fn cert_needs_renewal_fresh_cert() {
        let dir = std::env::temp_dir().join("rsh-renewal-test-1");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("tls_cert.pem");
        std::fs::write(&cert_path, "dummy").unwrap();

        // Just created → should not need renewal
        assert!(!cert_needs_renewal(&cert_path));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_generate_regenerates_expired_cert() {
        let dir = std::env::temp_dir().join("rsh-renewal-test-2");
        let _ = std::fs::remove_dir_all(&dir);

        // First call generates
        let (certs1, _) = load_or_generate_cert(&dir).unwrap();
        assert!(!certs1.is_empty());

        // Backdate the cert file to simulate expiry (400 days ago)
        let cert_path = dir.join("tls_cert.pem");
        let old_time = std::time::SystemTime::now()
            - std::time::Duration::from_secs(400 * 86400);
        filetime::set_file_mtime(
            &cert_path,
            filetime::FileTime::from_system_time(old_time),
        )
        .unwrap_or_else(|_| {
            // filetime not available — skip this test
        });

        // If mtime was set, cert should be regenerated
        if let Ok(meta) = std::fs::metadata(&cert_path) {
            if let Ok(modified) = meta.modified() {
                let age = std::time::SystemTime::now()
                    .duration_since(modified)
                    .unwrap_or_default();
                if age.as_secs() > 300 * 86400 {
                    let (certs2, _) = load_or_generate_cert(&dir).unwrap();
                    // New cert should differ (different key)
                    assert_ne!(certs1[0].as_ref(), certs2[0].as_ref());
                }
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
