//! Ed25519 challenge-response authentication — old raw format and SSH wire format.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ssh_key::private::PrivateKey;

/// Loaded SSH key pair for authentication.
#[derive(Debug)]
pub struct SshKeyPair {
    /// The ed25519 signing key
    pub signing_key: SigningKey,
    /// Key type string (e.g., "ssh-ed25519")
    pub key_type: String,
    /// Path the key was loaded from
    pub path: PathBuf,
}

impl SshKeyPair {
    /// Get the raw 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the public key in base64 (raw 32-byte format for ed25519 old protocol).
    pub fn public_key_base64_raw(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.public_key_bytes())
    }

    /// Sign a challenge and return raw signature bytes (64 bytes for ed25519).
    pub fn sign_challenge(&self, challenge: &[u8]) -> Vec<u8> {
        let sig = self.signing_key.sign(challenge);
        sig.to_bytes().to_vec()
    }
}

/// Load an ed25519 private key from an OpenSSH key file.
pub fn load_ssh_key(path: &Path) -> Result<SshKeyPair> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read key file: {}", path.display()))?;

    let private_key = PrivateKey::from_openssh(&content)
        .with_context(|| format!("parse SSH key: {}", path.display()))?;

    match private_key.key_data() {
        ssh_key::private::KeypairData::Ed25519(kp) => {
            let signing_key = SigningKey::from_bytes(kp.private.as_ref());
            Ok(SshKeyPair {
                signing_key,
                key_type: "ssh-ed25519".to_string(),
                path: path.to_path_buf(),
            })
        }
        _ => anyhow::bail!(
            "unsupported key type: expected ed25519, got {:?}",
            private_key.algorithm()
        ),
    }
}

/// Load an existing server key, or generate a new one and save it.
///
/// The key is stored in OpenSSH format at `dir/server_key`.
/// On Unix, the file is created with mode 0600.
pub fn load_or_generate_server_key(dir: &Path) -> Result<SshKeyPair> {
    let key_path = dir.join("server_key");

    // Try loading existing key first
    if key_path.exists() {
        return load_ssh_key(&key_path);
    }

    // Generate new ed25519 key
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let ed_kp = ssh_key::private::Ed25519Keypair {
        public: ssh_key::public::Ed25519PublicKey(signing_key.verifying_key().to_bytes()),
        private: ssh_key::private::Ed25519PrivateKey::from_bytes(&signing_key.to_bytes()),
    };
    let private_key =
        ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Ed25519(ed_kp), "rsh-server")
            .context("create ed25519 private key")?;

    let openssh_str = private_key
        .to_openssh(ssh_key::LineEnding::LF)
        .context("serialize key to OpenSSH format")?
        .to_string();

    // Ensure directory exists
    std::fs::create_dir_all(dir)
        .with_context(|| format!("create server key directory: {}", dir.display()))?;

    std::fs::write(&key_path, &openssh_str)
        .with_context(|| format!("write server key: {}", key_path.display()))?;

    // Set permissions to 0600 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set permissions on server key: {}", key_path.display()))?;
    }

    tracing::info!("generated new server key: {}", key_path.display());
    load_ssh_key(&key_path)
}

/// Auto-discover SSH keys: try id_ed25519, then scan ~/.ssh/id_*.
pub fn discover_key() -> Option<SshKeyPair> {
    let home = dirs::home_dir()?;
    let ssh_dir = home.join(".ssh");

    // Try default first
    let default_key = ssh_dir.join("id_ed25519");
    if let Ok(kp) = load_ssh_key(&default_key) {
        return Some(kp);
    }

    // Scan ~/.ssh/id_* for other keys
    let pattern = ssh_dir.join("id_*");
    if let Ok(entries) = glob::glob(&pattern.to_string_lossy()) {
        for entry in entries.flatten() {
            if entry.extension().is_some_and(|e| e == "pub") {
                continue;
            }
            if entry == default_key {
                continue;
            }
            if let Ok(kp) = load_ssh_key(&entry) {
                return Some(kp);
            }
        }
    }

    None
}

/// SHA256 fingerprint of a raw ed25519 public key, in "SHA256:<base64>" format.
pub fn key_fingerprint(raw_key: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(raw_key);
    format!(
        "SHA256:{}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash)
    )
}

/// Parse an authorized_keys file, returning ed25519 public keys as 32-byte arrays.
/// On Unix, checks file permissions (mode & 0o077 != 0).
/// When `strict` is true (recommended for servers), refuses to load if permissions are insecure.
/// When `strict` is false, only warns.
pub fn load_authorized_keys(path: &Path, strict: bool) -> Result<Vec<AuthorizedKey>> {
    // Check file permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                if strict {
                    anyhow::bail!(
                        "authorized_keys {} has insecure permissions {:o} (should be 0600). \
                         Fix with: chmod 600 {}",
                        path.display(),
                        mode & 0o777,
                        path.display(),
                    );
                }
                tracing::warn!(
                    "authorized_keys {} has insecure permissions {:o} (should be 0600)",
                    path.display(),
                    mode & 0o777
                );
            }
        }
    }

    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read authorized_keys: {}", path.display()))?;

    let mut keys = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(key) = parse_authorized_key_line(line) {
            keys.push(key);
        }
    }
    Ok(keys)
}

/// Per-key capability permissions, parsed from authorized_keys options.
///
/// Modeled after OpenSSH: by default all capabilities are allowed.
/// Use `restrict` to deny all, then selectively re-enable with `permit-*`.
/// Supported options:
///   `restrict`             — deny all capabilities (start from zero)
///   `permit-exec`          — allow exec/exec-as-user commands
///   `permit-push`          — allow push (write/sync) commands
///   `permit-pull`          — allow pull (read/ls/cat) commands
///   `permit-shell`         — allow shell/shell-persistent
///   `permit-tunnel`        — allow TCP tunneling (connect)
///   `command="CMD"`        — force this command for all exec requests
///   `no-exec`              — deny exec
///   `no-push`              — deny push
///   `no-pull`              — deny pull
///   `no-shell`             — deny shell
///   `no-tunnel`            — deny tunnel
#[derive(Debug, Clone, PartialEq)]
pub struct KeyPermissions {
    pub allow_exec: bool,
    pub allow_push: bool,
    pub allow_pull: bool,
    pub allow_shell: bool,
    pub allow_tunnel: bool,
    pub allow_gui: bool,
    pub allow_clipboard: bool,
    pub allow_reboot: bool,
    pub allow_screenshot: bool,
    pub allow_self_update: bool,
    /// If set, all exec requests are forced to run this command instead.
    pub forced_command: Option<String>,
    /// If true, TOTP 2FA is required after signature verification for this key.
    pub require_totp: bool,
}

impl Default for KeyPermissions {
    fn default() -> Self {
        Self {
            allow_exec: true,
            allow_push: true,
            allow_pull: true,
            allow_shell: true,
            allow_tunnel: true,
            allow_gui: true,
            allow_clipboard: true,
            allow_reboot: true,
            allow_screenshot: true,
            allow_self_update: true,
            forced_command: None,
            require_totp: false,
        }
    }
}

impl KeyPermissions {
    /// Start with everything denied (used after `restrict`).
    fn restricted() -> Self {
        Self {
            allow_exec: false,
            allow_push: false,
            allow_pull: false,
            allow_shell: false,
            allow_tunnel: false,
            allow_gui: false,
            allow_clipboard: false,
            allow_reboot: false,
            allow_screenshot: false,
            allow_self_update: false,
            forced_command: None,
            require_totp: false,
        }
    }
}

/// A parsed authorized key entry.
#[derive(Debug, Clone)]
pub struct AuthorizedKey {
    pub key_type: String,
    pub key_data: Vec<u8>, // Raw key bytes (32 bytes for ed25519)
    pub comment: Option<String>,
    pub permissions: KeyPermissions,
}

/// Parse a single authorized_keys line with optional OpenSSH-style options:
///   `[options] ssh-ed25519 AAAA... [comment]`
/// Options are comma-separated before the key type.
fn parse_authorized_key_line(line: &str) -> Option<AuthorizedKey> {
    // Detect if the line starts with options (not a key type).
    // Key types always start with "ssh-" or "ecdsa-".
    let (options_str, rest) = if line.starts_with("ssh-") || line.starts_with("ecdsa-") {
        (None, line)
    } else {
        // Options come before the key type — find where key type starts
        if let Some(idx) = line.find("ssh-").or_else(|| line.find("ecdsa-")) {
            (Some(line[..idx].trim()), &line[idx..])
        } else {
            return None; // no key type found
        }
    };

    let parts: Vec<&str> = rest.splitn(3, char::is_whitespace).collect();
    if parts.len() < 2 {
        return None;
    }

    let key_type = parts[0];
    let key_b64 = parts[1];
    let comment = parts.get(2).map(|s| s.to_string());

    // Parse permissions from options
    let permissions = parse_key_options(options_str);

    use base64::Engine;
    let key_data = base64::engine::general_purpose::STANDARD
        .decode(key_b64)
        .ok()?;

    // For ed25519: SSH wire format is [4-byte len]["ssh-ed25519"][4-byte len][32-byte key]
    // Extract the raw 32-byte key from the end
    if key_type == "ssh-ed25519" && key_data.len() >= 32 {
        let raw_key = key_data[key_data.len() - 32..].to_vec();
        Some(AuthorizedKey {
            key_type: key_type.to_string(),
            key_data: raw_key,
            comment,
            permissions,
        })
    } else {
        // For other key types, store the full wire format
        Some(AuthorizedKey {
            key_type: key_type.to_string(),
            key_data,
            comment,
            permissions,
        })
    }
}

/// Parse OpenSSH-style options string into KeyPermissions.
/// Options are comma-separated. Supports:
///   restrict, permit-exec, permit-push, permit-pull, permit-shell, permit-tunnel,
///   no-exec, no-push, no-pull, no-shell, no-tunnel, command="CMD"
fn parse_key_options(options_str: Option<&str>) -> KeyPermissions {
    let Some(opts) = options_str else {
        return KeyPermissions::default();
    };
    if opts.is_empty() {
        return KeyPermissions::default();
    }

    let mut perms = KeyPermissions::default();
    let mut has_restrict = false;

    // Split by commas, but respect quoted strings (for command="...")
    for opt in split_options(opts) {
        let opt = opt.trim();
        match opt {
            "restrict" => {
                has_restrict = true;
                perms = KeyPermissions::restricted();
            }
            "permit-exec" => perms.allow_exec = true,
            "permit-push" => perms.allow_push = true,
            "permit-pull" => perms.allow_pull = true,
            "permit-shell" => perms.allow_shell = true,
            "permit-tunnel" => perms.allow_tunnel = true,
            "permit-gui" => perms.allow_gui = true,
            "permit-clipboard" => perms.allow_clipboard = true,
            "permit-reboot" => perms.allow_reboot = true,
            "permit-screenshot" => perms.allow_screenshot = true,
            "permit-self-update" => perms.allow_self_update = true,
            "totp" => perms.require_totp = true,
            "no-exec" => perms.allow_exec = false,
            "no-push" => perms.allow_push = false,
            "no-pull" => perms.allow_pull = false,
            "no-shell" => perms.allow_shell = false,
            "no-tunnel" => perms.allow_tunnel = false,
            "no-gui" => perms.allow_gui = false,
            "no-clipboard" => perms.allow_clipboard = false,
            "no-reboot" => perms.allow_reboot = false,
            "no-screenshot" => perms.allow_screenshot = false,
            "no-self-update" => perms.allow_self_update = false,
            _ if opt.starts_with("command=\"") && opt.ends_with('"') => {
                let cmd = &opt[9..opt.len() - 1];
                perms.forced_command = Some(cmd.to_string());
                // command= implies restrict + permit-exec unless already set
                if !has_restrict {
                    // Don't override explicit permissions, but force exec context
                }
            }
            _ => {
                tracing::debug!("unknown authorized_keys option: {}", opt);
            }
        }
    }
    perms
}

/// Split comma-separated options, respecting quoted strings.
fn split_options(s: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;

    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                let part = s[start..i].trim();
                if !part.is_empty() {
                    result.push(part);
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    let last = s[start..].trim();
    if !last.is_empty() {
        result.push(last);
    }
    result
}

/// Verify that a public key (raw 32-byte ed25519) signed the challenge correctly.
pub fn verify_ed25519_signature(
    public_key: &[u8],
    challenge: &[u8],
    signature: &[u8],
) -> Result<bool> {
    if public_key.len() != 32 {
        anyhow::bail!(
            "ed25519 public key must be 32 bytes, got {}",
            public_key.len()
        );
    }
    if signature.len() != 64 {
        anyhow::bail!(
            "ed25519 signature must be 64 bytes, got {}",
            signature.len()
        );
    }

    let verifying_key = VerifyingKey::from_bytes(public_key.try_into().unwrap())
        .context("invalid ed25519 public key")?;
    let sig = ed25519_dalek::Signature::from_bytes(signature.try_into().unwrap());

    Ok(verifying_key.verify_strict(challenge, &sig).is_ok())
}

/// Load a revoked_keys file. Same format as authorized_keys.
/// Returns SHA256 fingerprints of revoked keys for fast lookup.
pub fn load_revoked_keys(path: &Path) -> Result<std::collections::HashSet<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read revoked_keys: {}", path.display()))?;

    let mut fingerprints = std::collections::HashSet::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(key) = parse_authorized_key_line(line) {
            fingerprints.insert(key_fingerprint(&key.key_data));
        }
    }
    tracing::info!(
        "loaded {} revoked keys from {}",
        fingerprints.len(),
        path.display()
    );
    Ok(fingerprints)
}

/// Check if a raw ed25519 public key is in the revoked set.
pub fn is_key_revoked(
    raw_key: &[u8],
    revoked: &std::collections::HashSet<String>,
) -> bool {
    if revoked.is_empty() {
        return false;
    }
    revoked.contains(&key_fingerprint(raw_key))
}

/// TOTP secret entry mapping key fingerprint to base32 secret.
#[derive(Debug, Clone)]
pub struct TotpSecret {
    pub fingerprint: String,
    pub secret_base32: String,
}

/// Load TOTP secrets file. Format: one entry per line, `fingerprint base32_secret`.
/// Lines starting with `#` are comments, empty lines are ignored.
pub fn load_totp_secrets(path: &Path) -> Result<Vec<TotpSecret>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read totp_secrets: {}", path.display()))?;

    let mut secrets = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
        if parts.len() == 2 {
            secrets.push(TotpSecret {
                fingerprint: parts[0].to_string(),
                secret_base32: parts[1].trim().to_string(),
            });
        }
    }
    Ok(secrets)
}

/// Find the TOTP secret for a given key fingerprint.
pub fn find_totp_secret<'a>(
    fingerprint: &str,
    secrets: &'a [TotpSecret],
) -> Option<&'a TotpSecret> {
    secrets.iter().find(|s| s.fingerprint == fingerprint)
}

/// Verify a TOTP code against a base32 secret.
/// Allows +/- 1 time step (30s) skew for clock drift.
pub fn verify_totp(secret_base32: &str, code: &str) -> Result<bool> {
    use totp_rs::{Algorithm, Secret, TOTP};

    let secret_bytes = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .map_err(|e| anyhow::anyhow!("invalid base32 TOTP secret: {}", e))?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6, // digits
        1, // skew (allow 1 step before/after)
        30, // step (seconds)
        secret_bytes,
    )
    .map_err(|e| anyhow::anyhow!("invalid TOTP config: {}", e))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system time")?
        .as_secs();

    Ok(totp.check(code, now))
}

/// Load TOTP recovery codes file. Format: `fingerprint hash1 hash2 hash3...`
/// Hashes are SHA256 hex of one-time recovery codes.
pub fn load_totp_recovery(path: &Path) -> Result<std::collections::HashMap<String, Vec<String>>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read totp_recovery: {}", path.display()))?;

    let mut map = std::collections::HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let fingerprint = parts[0].to_string();
            let hashes: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
            map.insert(fingerprint, hashes);
        }
    }
    Ok(map)
}

/// Check if a recovery code matches any hash for the given fingerprint.
/// Returns true and removes the used hash from the map if matched.
pub fn check_recovery_code(
    code: &str,
    fingerprint: &str,
    recovery_map: &mut std::collections::HashMap<String, Vec<String>>,
) -> bool {
    use sha2::{Digest, Sha256};
    let code_hash = format!("{:x}", Sha256::digest(code.as_bytes()));

    if let Some(hashes) = recovery_map.get_mut(fingerprint) {
        if let Some(pos) = hashes.iter().position(|h| h == &code_hash) {
            hashes.remove(pos);
            return true;
        }
    }
    false
}

/// Save updated recovery codes back to file.
pub fn save_totp_recovery(
    path: &Path,
    recovery_map: &std::collections::HashMap<String, Vec<String>>,
) -> Result<()> {
    let mut content = String::from("# TOTP recovery codes (SHA256 hashes)\n");
    for (fp, hashes) in recovery_map {
        if !hashes.is_empty() {
            content.push_str(fp);
            for h in hashes {
                content.push(' ');
                content.push_str(h);
            }
            content.push('\n');
        }
    }
    std::fs::write(path, &content)
        .with_context(|| format!("write totp_recovery: {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set permissions on totp_recovery: {}", path.display()))?;
    }
    Ok(())
}

/// Generate a random TOTP secret (base32 encoded, 20 bytes / 160 bits).
pub fn generate_totp_secret() -> String {
    use totp_rs::{Algorithm, TOTP};
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        totp_rs::Secret::generate_secret().to_bytes().unwrap(),
    )
    .expect("valid TOTP config");
    totp_rs::Secret::Raw(totp.secret.clone())
        .to_encoded()
        .to_string()
}

/// Generate a random challenge (32 bytes).
pub fn generate_challenge() -> Vec<u8> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut challenge = vec![0u8; 32];
    rng.fill_bytes(&mut challenge[..]);
    challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let challenge = generate_challenge();

        let kp = SshKeyPair {
            signing_key: signing_key.clone(),
            key_type: "ssh-ed25519".to_string(),
            path: PathBuf::from("/dev/null"),
        };

        let signature = kp.sign_challenge(&challenge);
        assert_eq!(signature.len(), 64);

        let public_key = signing_key.verifying_key().to_bytes();
        let valid = verify_ed25519_signature(&public_key, &challenge, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn verify_wrong_challenge_fails() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let challenge = generate_challenge();
        let wrong_challenge = generate_challenge();

        let kp = SshKeyPair {
            signing_key: signing_key.clone(),
            key_type: "ssh-ed25519".to_string(),
            path: PathBuf::from("/dev/null"),
        };

        let signature = kp.sign_challenge(&challenge);
        let public_key = signing_key.verifying_key().to_bytes();
        let valid = verify_ed25519_signature(&public_key, &wrong_challenge, &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn parse_authorized_key_ed25519() {
        // Build a valid SSH wire-format ed25519 public key:
        // [4-byte len]["ssh-ed25519"][4-byte len][32-byte key]
        let key_type = b"ssh-ed25519";
        let raw_key = [0x42u8; 32]; // 32 bytes of test data
        let mut wire = Vec::new();
        wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        wire.extend_from_slice(key_type);
        wire.extend_from_slice(&(raw_key.len() as u32).to_be_bytes());
        wire.extend_from_slice(&raw_key);

        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&wire);
        let line = format!("ssh-ed25519 {} user@host", b64);

        let key = parse_authorized_key_line(&line);
        assert!(key.is_some());
        let key = key.unwrap();
        assert_eq!(key.key_type, "ssh-ed25519");
        assert_eq!(key.key_data.len(), 32);
        assert_eq!(key.key_data, raw_key);
        assert_eq!(key.comment.as_deref(), Some("user@host"));
    }

    #[test]
    fn public_key_base64_raw() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let kp = SshKeyPair {
            signing_key,
            key_type: "ssh-ed25519".to_string(),
            path: PathBuf::from("/dev/null"),
        };
        let b64 = kp.public_key_base64_raw();
        // Base64 of 32 bytes = 44 chars
        assert_eq!(b64.len(), 44);
    }

    #[test]
    fn load_ssh_key_from_tempfile() {
        // Generate an ed25519 key, write it in OpenSSH format, load it back
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let ed_kp = ssh_key::private::Ed25519Keypair {
            public: ssh_key::public::Ed25519PublicKey(signing_key.verifying_key().to_bytes()),
            private: ssh_key::private::Ed25519PrivateKey::from_bytes(&signing_key.to_bytes()),
        };
        let private_key =
            ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Ed25519(ed_kp), "").unwrap();

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ed25519");
        std::fs::write(
            &key_path,
            private_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
        )
        .unwrap();

        let loaded = load_ssh_key(&key_path).unwrap();
        assert_eq!(loaded.key_type, "ssh-ed25519");
        assert_eq!(
            loaded.public_key_bytes(),
            signing_key.verifying_key().to_bytes()
        );
    }

    #[test]
    fn load_authorized_keys_from_tempfile() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let pub_bytes = signing_key.verifying_key().to_bytes();

        // Build SSH wire format: [4-byte len]["ssh-ed25519"][4-byte len][32-byte key]
        let key_type = b"ssh-ed25519";
        let mut wire = Vec::new();
        wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        wire.extend_from_slice(key_type);
        wire.extend_from_slice(&(pub_bytes.len() as u32).to_be_bytes());
        wire.extend_from_slice(&pub_bytes);

        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&wire);
        let content = format!(
            "# comment line\nssh-ed25519 {} testuser@host\n\n# another comment\n",
            b64
        );

        let dir = tempfile::tempdir().unwrap();
        let ak_path = dir.path().join("authorized_keys");
        std::fs::write(&ak_path, &content).unwrap();

        let keys = load_authorized_keys(&ak_path, false).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, "ssh-ed25519");
        assert_eq!(keys[0].key_data, pub_bytes);
        assert_eq!(keys[0].comment.as_deref(), Some("testuser@host"));
    }

    #[cfg(unix)]
    #[test]
    fn strict_mode_rejects_insecure_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let ak_path = dir.path().join("authorized_keys");
        std::fs::write(&ak_path, "# empty\n").unwrap();

        // Set world-readable
        std::fs::set_permissions(&ak_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        // strict=true should fail
        let result = load_authorized_keys(&ak_path, true);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("insecure permissions"));

        // strict=false should succeed (just warns)
        let result = load_authorized_keys(&ak_path, false);
        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn strict_mode_accepts_secure_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let ak_path = dir.path().join("authorized_keys");
        std::fs::write(&ak_path, "# empty\n").unwrap();

        // Set 0600
        std::fs::set_permissions(&ak_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        // strict=true should succeed
        let result = load_authorized_keys(&ak_path, true);
        assert!(result.is_ok());
    }

    #[test]
    fn load_or_generate_creates_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("server_key");
        assert!(!key_path.exists());

        // First call generates
        let kp1 = load_or_generate_server_key(dir.path()).unwrap();
        assert!(key_path.exists());
        assert_eq!(kp1.key_type, "ssh-ed25519");

        // Second call loads the same key
        let kp2 = load_or_generate_server_key(dir.path()).unwrap();
        assert_eq!(kp1.public_key_bytes(), kp2.public_key_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn load_or_generate_sets_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let _ = load_or_generate_server_key(dir.path()).unwrap();
        let key_path = dir.path().join("server_key");
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn generate_challenge_is_32_bytes() {
        let c = generate_challenge();
        assert_eq!(c.len(), 32);
        // Two challenges should be different (probabilistic but near-certain)
        let c2 = generate_challenge();
        assert_ne!(c, c2);
    }

    #[test]
    fn parse_key_options_default() {
        let perms = parse_key_options(None);
        assert!(perms.allow_exec);
        assert!(perms.allow_push);
        assert!(perms.allow_pull);
        assert!(perms.allow_shell);
        assert!(perms.allow_tunnel);
        assert!(perms.forced_command.is_none());
    }

    #[test]
    fn parse_key_options_restrict_then_permit() {
        let perms = parse_key_options(Some("restrict,permit-exec,permit-pull"));
        assert!(perms.allow_exec);
        assert!(!perms.allow_push);
        assert!(perms.allow_pull);
        assert!(!perms.allow_shell);
        assert!(!perms.allow_tunnel);
    }

    #[test]
    fn parse_key_options_no_flags() {
        let perms = parse_key_options(Some("no-shell,no-tunnel"));
        assert!(perms.allow_exec);
        assert!(perms.allow_push);
        assert!(perms.allow_pull);
        assert!(!perms.allow_shell);
        assert!(!perms.allow_tunnel);
    }

    #[test]
    fn parse_key_options_forced_command() {
        let perms = parse_key_options(Some("restrict,permit-exec,command=\"/bin/backup\""));
        assert!(perms.allow_exec);
        assert!(!perms.allow_push);
        assert_eq!(perms.forced_command.as_deref(), Some("/bin/backup"));
    }

    #[test]
    fn parse_authorized_key_with_options() {
        // Build a valid ed25519 key
        let key_type = b"ssh-ed25519";
        let raw_key = [0x42u8; 32];
        let mut wire = Vec::new();
        wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        wire.extend_from_slice(key_type);
        wire.extend_from_slice(&(raw_key.len() as u32).to_be_bytes());
        wire.extend_from_slice(&raw_key);

        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&wire);
        let line = format!("restrict,permit-exec ssh-ed25519 {} deploy@ci", b64);

        let key = parse_authorized_key_line(&line).unwrap();
        assert_eq!(key.comment.as_deref(), Some("deploy@ci"));
        assert!(key.permissions.allow_exec);
        assert!(!key.permissions.allow_push);
        assert!(!key.permissions.allow_pull);
        assert!(!key.permissions.allow_shell);
        assert!(!key.permissions.allow_tunnel);
    }

    #[test]
    fn split_options_respects_quotes() {
        let parts = split_options("restrict,command=\"echo hello, world\",permit-exec");
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "restrict");
        assert_eq!(parts[1], "command=\"echo hello, world\"");
        assert_eq!(parts[2], "permit-exec");
    }

    #[test]
    fn parse_key_options_totp() {
        let perms = parse_key_options(Some("totp"));
        assert!(perms.require_totp);
        // All other permissions remain default (allowed)
        assert!(perms.allow_exec);
        assert!(perms.allow_push);
        assert!(perms.allow_pull);
        assert!(perms.allow_shell);
        assert!(perms.allow_tunnel);
    }

    #[test]
    fn parse_key_options_restrict_totp_permit_exec() {
        let perms = parse_key_options(Some("restrict,totp,permit-exec"));
        assert!(perms.require_totp);
        assert!(perms.allow_exec);
        assert!(!perms.allow_push);
        assert!(!perms.allow_pull);
        assert!(!perms.allow_shell);
        assert!(!perms.allow_tunnel);
    }

    #[test]
    fn parse_key_options_default_no_totp() {
        let perms = parse_key_options(None);
        assert!(!perms.require_totp);
    }

    #[test]
    fn load_revoked_keys_and_check() {
        let signing_key1 = SigningKey::generate(&mut rand::thread_rng());
        let signing_key2 = SigningKey::generate(&mut rand::thread_rng());
        let pub1 = signing_key1.verifying_key().to_bytes();
        let pub2 = signing_key2.verifying_key().to_bytes();

        // Build SSH wire format for key1
        let key_type = b"ssh-ed25519";
        let mut wire = Vec::new();
        wire.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        wire.extend_from_slice(key_type);
        wire.extend_from_slice(&(pub1.len() as u32).to_be_bytes());
        wire.extend_from_slice(&pub1);

        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&wire);
        let content = format!("# Revoked keys\nssh-ed25519 {} revoked@host\n", b64);

        let dir = tempfile::tempdir().unwrap();
        let rk_path = dir.path().join("revoked_keys");
        std::fs::write(&rk_path, &content).unwrap();

        let revoked = load_revoked_keys(&rk_path).unwrap();
        assert_eq!(revoked.len(), 1);

        // key1 is revoked
        assert!(is_key_revoked(&pub1, &revoked));
        // key2 is NOT revoked
        assert!(!is_key_revoked(&pub2, &revoked));
        // empty set never revokes
        assert!(!is_key_revoked(&pub1, &std::collections::HashSet::new()));
    }
}
