//! Wire protocol types — JSON-serialized request/response structs.

use serde::{Deserialize, Serialize};

/// Authentication request from client to server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    #[serde(rename = "type")]
    pub auth_type: String, // "pubkey" or "password"
    #[serde(alias = "key", skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>, // "ssh-ed25519", "ssh-rsa", etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub want_mux: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caps: Option<Vec<String>>,
}

/// Server sends challenge for pubkey auth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub challenge: String,
}

/// Client returns signed challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub signature: String,
}

/// Server requests TOTP code after successful signature verification.
/// Only sent when the matched key has `totp` option set.
/// Only keys with `totp` option trigger the challenge — clients without
/// TOTP support will not encounter this message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpChallenge {
    pub totp_required: bool,
}

/// Client sends TOTP code in response to TotpChallenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpResponse {
    pub totp_code: String,
}

/// Server auth result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mux_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caps: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

/// Client command request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    #[serde(rename = "type")]
    pub req_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gzip: Option<bool>,
    #[serde(alias = "syncType", skip_serializing_if = "Option::is_none")]
    pub sync_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<Vec<DeltaOp>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<BlockSig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_patches: Option<Vec<BatchPatchItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_vars: Option<Vec<String>>,
}

/// Server response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gzip: Option<bool>,
}

/// Delta transfer operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaOp {
    #[serde(rename = "t")]
    pub op_type: String, // "match" or "data"
    #[serde(rename = "i", skip_serializing_if = "Option::is_none")]
    pub index: Option<i32>,
    #[serde(rename = "d", skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// Block signature for delta sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSig {
    #[serde(rename = "i")]
    pub index: i32,
    #[serde(rename = "w")]
    pub weak: u32, // adler32
    #[serde(rename = "s")]
    pub strong: String, // md5 hex
}

/// Single file in a batch patch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchPatchItem {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<Vec<DeltaOp>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(rename = "backup", skip_serializing_if = "Option::is_none")]
    pub backup_suffix: Option<String>,
}

/// File info for directory listings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub size: i64,
    pub mode: String,
    pub mod_time: String,
    pub is_dir: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_request_roundtrip() {
        let req = AuthRequest {
            auth_type: "pubkey".to_string(),
            public_key: Some("AAAAC3NzaC1lZDI1NTE5...".to_string()),
            key_type: Some("ssh-ed25519".to_string()),
            username: None,
            password: None,
            version: Some("4.38.2".to_string()),
            want_mux: None,
            caps: Some(vec!["self-update".to_string()]),
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: AuthRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.auth_type, "pubkey");
        assert_eq!(decoded.caps.unwrap()[0], "self-update");
    }

    #[test]
    fn request_roundtrip() {
        let req = Request {
            req_type: "exec".to_string(),
            command: Some("hostname".to_string()),
            path: None,
            content: None,
            binary: None,
            gzip: None,
            sync_type: None,
            delta: None,
            signatures: None,
            paths: None,
            batch_patches: None,
            env_vars: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"type\":\"exec\""));
        assert!(json.contains("\"command\":\"hostname\""));
        // Verify None fields are omitted
        assert!(!json.contains("\"path\""));
    }

    #[test]
    fn response_roundtrip() {
        let resp = Response {
            success: true,
            output: Some("DESKTOP-TLC-800".to_string()),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: Response = serde_json::from_str(&json).unwrap();
        assert!(decoded.success);
        assert_eq!(decoded.output.unwrap(), "DESKTOP-TLC-800");
    }

    #[test]
    fn auth_challenge_roundtrip() {
        let ac = AuthChallenge {
            challenge: "dGVzdC1jaGFsbGVuZ2U=".to_string(),
        };
        let json = serde_json::to_string(&ac).unwrap();
        let decoded: AuthChallenge = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.challenge, ac.challenge);
    }

    #[test]
    fn auth_response_roundtrip() {
        let ar = AuthResponse {
            signature: "c2lnbmF0dXJl".to_string(),
        };
        let json = serde_json::to_string(&ar).unwrap();
        let decoded: AuthResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.signature, ar.signature);
    }

    #[test]
    fn auth_result_roundtrip() {
        let ar = AuthResult {
            success: true,
            error: None,
            version: Some("4.38.2".to_string()),
            mux_enabled: Some(true),
            caps: Some(vec!["self-update".to_string()]),
            banner: None,
        };
        let json = serde_json::to_string(&ar).unwrap();
        let decoded: AuthResult = serde_json::from_str(&json).unwrap();
        assert!(decoded.success);
        assert_eq!(decoded.version.unwrap(), "4.38.2");
        assert!(decoded.mux_enabled.unwrap());
        // Verify None fields are omitted
        assert!(!json.contains("\"error\""));
        assert!(!json.contains("\"banner\""));
    }

    #[test]
    fn batch_patch_item_roundtrip() {
        let item = BatchPatchItem {
            path: "/tmp/test.txt".to_string(),
            delta: Some(vec![DeltaOp {
                op_type: "data".to_string(),
                index: None,
                data: Some("aGVsbG8=".to_string()),
            }]),
            content: None,
            backup_suffix: Some(".bak".to_string()),
        };
        let json = serde_json::to_string(&item).unwrap();
        let decoded: BatchPatchItem = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.path, "/tmp/test.txt");
        assert_eq!(decoded.delta.unwrap().len(), 1);
        assert_eq!(decoded.backup_suffix.unwrap(), ".bak");
        // Verify rename
        assert!(json.contains("\"backup\":\".bak\""));
    }

    #[test]
    fn file_info_roundtrip() {
        let fi = FileInfo {
            name: "test.txt".to_string(),
            size: 1024,
            mode: "-rw-r--r--".to_string(),
            mod_time: "2026-03-04T10:00:00Z".to_string(),
            is_dir: false,
        };
        let json = serde_json::to_string(&fi).unwrap();
        let decoded: FileInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, "test.txt");
        assert_eq!(decoded.size, 1024);
        assert!(!decoded.is_dir);
    }

    #[test]
    fn totp_challenge_roundtrip() {
        let tc = TotpChallenge {
            totp_required: true,
        };
        let json = serde_json::to_string(&tc).unwrap();
        let decoded: TotpChallenge = serde_json::from_str(&json).unwrap();
        assert!(decoded.totp_required);
    }

    #[test]
    fn totp_response_roundtrip() {
        let tr = TotpResponse {
            totp_code: "123456".to_string(),
        };
        let json = serde_json::to_string(&tr).unwrap();
        let decoded: TotpResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.totp_code, "123456");
    }

    #[test]
    fn totp_challenge_false_omits_nothing() {
        // Even totp_required=false is serialized (not optional)
        let tc = TotpChallenge {
            totp_required: false,
        };
        let json = serde_json::to_string(&tc).unwrap();
        assert!(json.contains("\"totp_required\":false"));
    }

    #[test]
    fn block_sig_json_tags() {
        let sig = BlockSig {
            index: 0,
            weak: 12345678,
            strong: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
        };
        let json = serde_json::to_string(&sig).unwrap();
        // Verify short JSON field names
        assert!(json.contains("\"i\":0"));
        assert!(json.contains("\"w\":12345678"));
        assert!(json.contains("\"s\":\"d41d8cd98f00b204"));
    }

    // --- Wire-format regression tests ---
    // Golden JSON strings verify serde field names and optional-field handling.
    // Regressions: 225d640, dc2289e, 437d51f all broke wire format.

    /// Auth message without key_type (ed25519 legacy format).
    #[test]
    fn auth_message_without_key_type_parses() {
        let json = r#"{"type":"auth","key":"AAAAC3NzaC1lZDI1NTE5AAAAIGFrZXkxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFy","version":"4.38.2"}"#;
        let req: AuthRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.auth_type, "auth");
        assert!(req.public_key.is_some());
        assert!(req.key_type.is_none(), "legacy format omits key_type for ed25519");
        assert_eq!(req.version.as_deref(), Some("4.38.2"));
    }

    /// Exec request: {"type":"exec","command":"hostname"}
    #[test]
    fn exec_request_parses() {
        let json = r#"{"type":"exec","command":"hostname"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.req_type, "exec");
        assert_eq!(req.command.as_deref(), Some("hostname"));
        assert!(req.path.is_none());
    }

    /// Native command: {"type":"native","command":"screenshot 0 80 100"}
    #[test]
    fn native_command_parses() {
        let json = r#"{"type":"native","command":"screenshot 0 80 100"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.req_type, "native");
        let cmd = req.command.unwrap();
        let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
        assert_eq!(parts[0], "screenshot", "first token is sub-command");
        assert_eq!(parts[1], "0 80 100", "rest is args");
    }

    /// Input command: {"type":"input","command":"mouse move 500 300"}
    #[test]
    fn input_command_parses() {
        let json = r#"{"type":"input","command":"mouse move 500 300"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.req_type, "input");
        let cmd = req.command.unwrap();
        let parts: Vec<&str> = cmd.splitn(3, ' ').collect();
        assert_eq!(parts[0], "mouse");
        assert_eq!(parts[1], "move");
        assert_eq!(parts[2], "500 300");
    }

    /// Response serialization: None fields must be omitted.
    #[test]
    fn response_omits_none_fields() {
        let resp = Response {
            success: true,
            output: Some("DESKTOP-TLC-800".to_string()),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"output\":\"DESKTOP-TLC-800\""));
        assert!(!json.contains("\"error\""), "absent error must be omitted");
        assert!(!json.contains("\"binary\""), "absent binary must be omitted");
    }

    /// Sync request with path: {"type":"sync","path":"/C/Users","syncType":"push"}
    #[test]
    fn sync_request_with_path_parses() {
        let json = r#"{"type":"sync","path":"/C/Users","syncType":"push"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.req_type, "sync");
        assert_eq!(req.path.as_deref(), Some("/C/Users"));
        assert_eq!(req.sync_type.as_deref(), Some("push"));
    }
}
