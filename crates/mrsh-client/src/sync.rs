//! Push/pull file transfer — delta sync using rsh-transfer.
//! Sends block signatures, receives delta, applies patches.
//! Supports single files and directories (walk + per-file delta).

use anyhow::{Result, bail};
use base64::Engine;
use mrsh_core::protocol::{Request, Response};
use mrsh_transfer::delta;
use std::path::Path;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::{RshClient, simple_request};

// ── Transfer options ────────────────────────────────────────────

/// Options controlling directory transfer behavior.
#[derive(Debug, Clone, Default)]
pub struct TransferOptions {
    /// Show progress bar with rate and ETA.
    pub progress: bool,
    /// Dry run: list files without transferring.
    pub dry_run: bool,
    /// Backup suffix for overwritten files (e.g. ".bak").
    pub backup_suffix: Option<String>,
    /// Bandwidth limit in KB/s (0 = unlimited). Reserved for future use.
    pub bwlimit_kbps: u32,
}

// ── Push ────────────────────────────────────────────────────────

/// Push a local file to the remote host.
/// Uses delta sync: sends sigs of remote → computes delta → sends delta.
pub async fn push<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    local_data: &[u8],
    remote_path: &str,
) -> Result<PushResult> {
    // Step 1: Request remote file signatures
    let mut req = simple_request("push-sigs");
    req.path = Some(remote_path.to_string());
    let resp = client.request(&req).await?;

    if !resp.success {
        // Remote file doesn't exist — do full upload
        return push_full(client, local_data, remote_path).await;
    }

    // Step 2: Parse remote signatures
    let sigs_json = resp.output.unwrap_or_default();
    let remote_sigs: Vec<mrsh_core::protocol::BlockSig> =
        serde_json::from_str(&sigs_json).unwrap_or_default();

    if remote_sigs.is_empty() {
        return push_full(client, local_data, remote_path).await;
    }

    // Step 3: Compute delta against remote
    let transfer_sigs: Vec<delta::BlockSig> = remote_sigs
        .iter()
        .map(|s| delta::BlockSig {
            index: s.index as usize,
            weak: s.weak,
            strong: s.strong.clone(),
        })
        .collect();

    let ops = delta::compute_delta(local_data, &transfer_sigs);

    // Step 4: Convert to protocol delta ops and send
    let proto_ops: Vec<mrsh_core::protocol::DeltaOp> = ops
        .iter()
        .map(|op| mrsh_core::protocol::DeltaOp {
            op_type: op.op_type.clone(),
            index: if op.op_type == "match" {
                Some(op.index as i32)
            } else {
                None
            },
            data: if op.op_type == "data" {
                Some(op.data.clone())
            } else {
                None
            },
        })
        .collect();

    let mut patch_req = simple_request("push-delta");
    patch_req.path = Some(remote_path.to_string());
    patch_req.delta = Some(proto_ops);

    let patch_resp = client.request(&patch_req).await?;
    check_response(&patch_resp)?;

    Ok(PushResult {
        path: remote_path.to_string(),
        bytes_sent: local_data.len(),
        delta: true,
    })
}

/// Full upload without delta (remote file doesn't exist).
async fn push_full<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    data: &[u8],
    remote_path: &str,
) -> Result<PushResult> {
    let mut req = simple_request("write");
    req.path = Some(remote_path.to_string());
    req.content = Some(base64::engine::general_purpose::STANDARD.encode(data));
    req.binary = Some(true);
    let resp = client.request(&req).await?;
    check_response(&resp)?;

    Ok(PushResult {
        path: remote_path.to_string(),
        bytes_sent: data.len(),
        delta: false,
    })
}

// ── Pull ────────────────────────────────────────────────────────

/// Pull a remote file to local.
/// Uses delta sync: sends sigs of local → server computes delta → applies.
pub async fn pull<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    local_data: Option<&[u8]>,
    remote_path: &str,
) -> Result<PullResult> {
    // Step 1: Compute local signatures (empty if no local file)
    let local_sigs = match local_data {
        Some(data) if !data.is_empty() => delta::compute_signatures(data),
        _ => Vec::new(),
    };

    // Step 2: Send pull request with local sigs
    let proto_sigs: Vec<mrsh_core::protocol::BlockSig> = local_sigs
        .iter()
        .map(|s| mrsh_core::protocol::BlockSig {
            index: s.index as i32,
            weak: s.weak,
            strong: s.strong.clone(),
        })
        .collect();

    let mut req = simple_request("pull-delta");
    req.path = Some(remote_path.to_string());
    req.signatures = Some(proto_sigs);
    let resp = client.request(&req).await?;
    check_response(&resp)?;

    // Step 3: Apply delta or decode full content
    let output = resp.output.unwrap_or_default();

    if resp.binary.unwrap_or(false) {
        // Full file transfer (base64-encoded)
        let data = base64::engine::general_purpose::STANDARD
            .decode(&output)
            .map_err(|e| anyhow::anyhow!("decode base64: {}", e))?;
        Ok(PullResult { data, delta: false })
    } else {
        // Delta response — parse and apply
        let delta_ops: Vec<delta::DeltaOp> = serde_json::from_str(&output).unwrap_or_default();

        if delta_ops.is_empty() {
            // No changes needed (files are identical)
            Ok(PullResult {
                data: local_data.unwrap_or_default().to_vec(),
                delta: true,
            })
        } else {
            let base = local_data.unwrap_or_default();
            let result = delta::apply_delta(base, &delta_ops);
            Ok(PullResult {
                data: result,
                delta: true,
            })
        }
    }
}

// ── Push directory ──────────────────────────────────────────────

/// Walk entry from server (wire format: `json:"p"`, `json:"s"`).
#[derive(serde::Deserialize, Debug)]
struct WalkEntry {
    #[serde(rename = "p")]
    path: String,
    #[serde(rename = "s")]
    size: i64,
}

/// Push a local directory to the remote host recursively.
/// Walks local tree, creates remote dirs, pushes each file with delta sync.
pub async fn push_dir<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    local_dir: &Path,
    remote_dir: &str,
    opts: &TransferOptions,
) -> Result<DirSyncResult> {
    // Walk local directory
    let mut files: Vec<(std::path::PathBuf, String)> = Vec::new();
    walk_local(local_dir, local_dir, remote_dir, &mut files)?;

    eprintln!("push directory: {} -> {} ({} files)", local_dir.display(), remote_dir, files.len());

    if files.is_empty() {
        return Ok(DirSyncResult { files_total: 0, files_transferred: 0, bytes_total: 0 });
    }

    if opts.dry_run {
        for (local_path, remote_path) in &files {
            let size = std::fs::metadata(local_path).map(|m| m.len()).unwrap_or(0);
            eprintln!("  [dry-run] {} ({} bytes) -> {}", local_path.display(), size, remote_path);
        }
        return Ok(DirSyncResult { files_total: files.len(), files_transferred: 0, bytes_total: 0 });
    }

    // Collect unique remote parent directories and create them
    let mut remote_parents: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (_, remote_path) in &files {
        if let Some(parent) = remote_path.rsplit_once('\\').map(|(p, _)| p.to_string()) {
            remote_parents.insert(parent);
        }
    }
    for dir in &remote_parents {
        let cmd = format!("cmd /c if not exist \"{}\" mkdir \"{}\"", dir, dir);
        let mut req = simple_request("exec");
        req.command = Some(cmd);
        let _ = client.request(&req).await;
    }

    // Push each file with delta sync
    let total = files.len();
    let mut transferred = 0usize;
    let mut bytes_total = 0u64;
    let start_time = Instant::now();

    for (i, (local_path, remote_path)) in files.iter().enumerate() {
        let data = match std::fs::read(local_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("  skip {}: {}", local_path.display(), e);
                continue;
            }
        };
        bytes_total += data.len() as u64;

        if opts.progress {
            print_progress(i, total, bytes_total, start_time,
                &local_path.file_name().unwrap_or_default().to_string_lossy());
        } else {
            eprintln!("  [{}/{}] {}", i + 1, total,
                local_path.file_name().unwrap_or_default().to_string_lossy());
        }

        // Backup before overwrite if requested
        if let Some(ref suffix) = opts.backup_suffix {
            backup_remote(client, remote_path, suffix).await;
        }

        push(client, &data, remote_path).await?;
        transferred += 1;
    }

    if opts.progress {
        eprintln!(); // clear progress line
    }

    Ok(DirSyncResult { files_total: total, files_transferred: transferred, bytes_total })
}

/// Walk local directory tree, collecting (local_path, remote_path) pairs.
fn walk_local(
    root: &Path,
    dir: &Path,
    remote_dir: &str,
    files: &mut Vec<(std::path::PathBuf, String)>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk_local(root, &entry.path(), remote_dir, files)?;
        } else {
            let rel = entry.path().strip_prefix(root)
                .map_err(|e| anyhow::anyhow!("strip prefix: {}", e))?
                .to_string_lossy()
                .replace('/', "\\");
            let remote_path = format!("{}\\{}", remote_dir, rel);
            files.push((entry.path(), remote_path));
        }
    }
    Ok(())
}

// ── Pull directory ──────────────────────────────────────────────

/// Pull a remote directory to local recursively.
/// Requests walk from server, then pulls each file with delta sync.
pub async fn pull_dir<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    remote_dir: &str,
    local_dir: &Path,
    opts: &TransferOptions,
) -> Result<DirSyncResult> {
    // Request recursive file listing from server
    let mut req = simple_request("sync");
    req.sync_type = Some("walk".to_string());
    req.path = Some(remote_dir.to_string());
    let resp = client.request(&req).await?;
    check_response(&resp)?;

    let json = resp.output.unwrap_or_default();
    let entries: Vec<WalkEntry> = serde_json::from_str(&json)
        .map_err(|e| anyhow::anyhow!("parse walk response: {}", e))?;

    eprintln!("pull directory: {} -> {} ({} files)", remote_dir, local_dir.display(), entries.len());

    if opts.dry_run {
        for entry in &entries {
            eprintln!("  [dry-run] {} ({} bytes)", entry.path, entry.size);
        }
        return Ok(DirSyncResult { files_total: entries.len(), files_transferred: 0, bytes_total: 0 });
    }

    std::fs::create_dir_all(local_dir)?;

    let total = entries.len();
    let mut transferred = 0usize;
    let mut bytes_total = 0u64;
    let start_time = Instant::now();

    for (i, entry) in entries.iter().enumerate() {
        // Build paths — server walk returns paths relative to remote_dir or absolute.
        // Server may return relative paths (forward slashes) or absolute.
        let rel_path = if entry.path.starts_with(remote_dir) {
            // Absolute path from server — strip the remote_dir prefix
            entry.path[remote_dir.len()..].trim_start_matches(['/', '\\']).to_string()
        } else {
            // Already relative
            entry.path.clone()
        };

        let remote_file = format!("{}\\{}", remote_dir, rel_path.replace('/', "\\"));
        let local_file = local_dir.join(rel_path.replace('\\', "/"));

        // Ensure local parent exists
        if let Some(parent) = local_file.parent() {
            std::fs::create_dir_all(parent)?;
        }

        if opts.progress {
            print_progress(i, total, bytes_total, start_time, &rel_path);
        } else {
            eprintln!("  [{}/{}] {} ({} bytes)", i + 1, total, rel_path, entry.size);
        }

        // Backup local file before overwrite if requested
        if let Some(ref suffix) = opts.backup_suffix {
            if local_file.exists() {
                let backup_path = format!("{}{}", local_file.display(), suffix);
                if let Err(e) = std::fs::copy(&local_file, &backup_path) {
                    eprintln!("  backup warning: {}: {}", backup_path, e);
                }
            }
        }

        // Read existing local file for delta sync
        let local_data = std::fs::read(&local_file).ok();
        let result = pull(client, local_data.as_deref(), &remote_file).await?;
        std::fs::write(&local_file, &result.data)?;

        bytes_total += result.data.len() as u64;
        transferred += 1;
    }

    if opts.progress {
        eprintln!(); // clear progress line
    }

    Ok(DirSyncResult { files_total: total, files_transferred: transferred, bytes_total })
}

// ── Delete remote extras (--delete / mirror mode) ──────────────

/// Remove remote files not present in the local directory.
/// Uses server walk to get remote file list, compares with local tree.
pub async fn delete_remote_extras<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    local_dir: &Path,
    remote_dir: &str,
) -> Result<usize> {
    // Walk remote directory via server
    let mut req = simple_request("sync");
    req.sync_type = Some("walk".to_string());
    req.path = Some(remote_dir.to_string());
    let resp = client.request(&req).await?;
    if !resp.success {
        eprintln!("--delete: could not walk remote: {}", resp.error.as_deref().unwrap_or("unknown"));
        return Ok(0);
    }

    let json = resp.output.unwrap_or_default();
    let remote_entries: Vec<WalkEntry> = serde_json::from_str(&json).unwrap_or_default();

    // Build set of local relative paths (normalized with backslash for Windows remote)
    let mut local_files: Vec<(std::path::PathBuf, String)> = Vec::new();
    walk_local(local_dir, local_dir, remote_dir, &mut local_files)?;
    let local_set: std::collections::HashSet<String> =
        local_files.iter().map(|(_, remote)| remote.clone()).collect();

    // Find remote files not in local set
    let mut to_delete: Vec<String> = Vec::new();
    for entry in &remote_entries {
        let full_path = if entry.path.starts_with(remote_dir) {
            entry.path.clone()
        } else {
            format!("{}\\{}", remote_dir, entry.path.replace('/', "\\"))
        };
        if !local_set.contains(&full_path) {
            to_delete.push(full_path);
        }
    }

    if to_delete.is_empty() {
        return Ok(0);
    }

    eprintln!("--delete: {} remote files to remove", to_delete.len());

    // Delete in batches of 50 via exec (PowerShell Remove-Item)
    for chunk in to_delete.chunks(50) {
        let paths: Vec<String> = chunk.iter().map(|p| format!("'{}'", p)).collect();
        let cmd = format!("Remove-Item -Force {}", paths.join(", "));
        let mut del_req = simple_request("exec");
        del_req.command = Some(cmd);
        let _ = client.request(&del_req).await;
    }

    Ok(to_delete.len())
}

// ── Types ───────────────────────────────────────────────────────

/// Result of a push operation.
#[derive(Debug)]
pub struct PushResult {
    pub path: String,
    pub bytes_sent: usize,
    pub delta: bool,
}

/// Result of a pull operation.
#[derive(Debug)]
pub struct PullResult {
    pub data: Vec<u8>,
    pub delta: bool,
}

/// Result of a directory sync operation.
#[derive(Debug)]
pub struct DirSyncResult {
    pub files_total: usize,
    pub files_transferred: usize,
    pub bytes_total: u64,
}

// ── Progress & helpers ──────────────────────────────────────────

/// Print a progress line with percentage, rate, and ETA.
fn print_progress(current: usize, total: usize, bytes_done: u64, start: Instant, name: &str) {
    let elapsed = start.elapsed().as_secs_f64();
    let pct = if total > 0 {
        (current + 1) as f64 / total as f64 * 100.0
    } else {
        0.0
    };

    let rate = if elapsed > 0.1 {
        bytes_done as f64 / elapsed
    } else {
        0.0
    };

    let eta = if rate > 0.0 && current < total {
        let remaining_files = total - current - 1;
        let avg_per_file = elapsed / (current + 1) as f64;
        remaining_files as f64 * avg_per_file
    } else {
        0.0
    };

    let rate_str = format_rate(rate);
    let eta_str = format_duration(eta);

    // Truncate name to fit in one line
    let display_name = if name.len() > 30 {
        format!("...{}", &name[name.len() - 27..])
    } else {
        name.to_string()
    };

    eprint!(
        "\r  [{}/{}] {:5.1}% {:>8} {:>6} {}          ",
        current + 1, total, pct, rate_str, eta_str, display_name
    );
}

/// Format bytes/sec as human-readable rate.
fn format_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec >= 1_048_576.0 {
        format!("{:.1}MB/s", bytes_per_sec / 1_048_576.0)
    } else if bytes_per_sec >= 1024.0 {
        format!("{:.0}KB/s", bytes_per_sec / 1024.0)
    } else {
        format!("{:.0}B/s", bytes_per_sec)
    }
}

/// Format seconds as mm:ss or hh:mm:ss.
fn format_duration(secs: f64) -> String {
    let s = secs as u64;
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
    } else {
        format!("{}:{:02}", s / 60, s % 60)
    }
}

/// Rename a remote file with a backup suffix before overwriting.
async fn backup_remote<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    remote_path: &str,
    suffix: &str,
) {
    let backup_path = format!("{}{}", remote_path, suffix);
    let cmd = format!(
        "if (Test-Path '{}') {{ Move-Item -Force '{}' '{}' }}",
        remote_path, remote_path, backup_path
    );
    let mut req = simple_request("exec");
    req.command = Some(cmd);
    let _ = client.request(&req).await;
}

// ── Helpers ─────────────────────────────────────────────────────

fn check_response(resp: &Response) -> Result<()> {
    if !resp.success {
        bail!("{}", resp.error.as_deref().unwrap_or("unknown error"));
    }
    Ok(())
}

/// Build a sync request with signatures.
pub fn build_sync_request(
    req_type: &str,
    path: &str,
    sigs: Vec<mrsh_core::protocol::BlockSig>,
) -> Request {
    Request {
        req_type: req_type.to_string(),
        command: None,
        path: Some(path.to_string()),
        content: None,
        binary: None,
        gzip: None,
        sync_type: None,
        delta: None,
        signatures: Some(sigs),
        paths: None,
        batch_patches: None,
        env_vars: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::RshClient;
    use mrsh_core::wire;
    use tokio::io::DuplexStream;

    fn mock_client() -> (RshClient<DuplexStream>, DuplexStream) {
        let (client_end, server_end) = tokio::io::duplex(16384);
        (RshClient::new_mock(client_end), server_end)
    }

    fn ok_response(output: &str) -> Response {
        Response {
            success: true,
            output: Some(output.to_string()),
            error: None,
            size: None,
            binary: None,
            gzip: None,
        }
    }

    fn err_response(error: &str) -> Response {
        Response {
            success: false,
            output: None,
            error: Some(error.to_string()),
            size: None,
            binary: None,
            gzip: None,
        }
    }

    fn ok_binary(output: &str) -> Response {
        Response {
            success: true,
            output: Some(output.to_string()),
            error: None,
            size: None,
            binary: Some(true),
            gzip: None,
        }
    }

    // ── Existing tests ──────────────────────────────────────────────

    #[test]
    fn push_result_debug() {
        let r = PushResult {
            path: "/tmp/test".to_string(),
            bytes_sent: 1024,
            delta: true,
        };
        assert!(format!("{:?}", r).contains("delta: true"));
    }

    #[test]
    fn pull_result_debug() {
        let r = PullResult {
            data: vec![1, 2, 3],
            delta: false,
        };
        assert!(format!("{:?}", r).contains("delta: false"));
    }

    #[test]
    fn build_sync_request_fields() {
        let sigs = vec![mrsh_core::protocol::BlockSig {
            index: 0,
            weak: 12345,
            strong: "abc".to_string(),
        }];
        let req = build_sync_request("pull-delta", "/tmp/file", sigs);
        assert_eq!(req.req_type, "pull-delta");
        assert_eq!(req.path.as_deref(), Some("/tmp/file"));
        assert_eq!(req.signatures.unwrap().len(), 1);
    }

    #[test]
    fn check_response_ok() {
        let resp = ok_response("ok");
        assert!(check_response(&resp).is_ok());
    }

    #[test]
    fn check_response_error() {
        let resp = err_response("file not found");
        let err = check_response(&resp).unwrap_err();
        assert!(err.to_string().contains("file not found"));
    }

    // ── Push: full upload (no remote file) ──────────────────────────

    #[tokio::test]
    async fn push_full_upload_when_no_remote() {
        let (mut client, mut server) = mock_client();
        let data = b"new file content";

        let h = tokio::spawn(async move {
            // Step 1: push-sigs request → error (no remote file)
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "push-sigs");
            assert_eq!(req.path.as_deref(), Some("/tmp/test.txt"));
            wire::send_json(&mut server, &err_response("file not found")).await.unwrap();

            // Step 2: write request (full upload)
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "write");
            assert_eq!(req.path.as_deref(), Some("/tmp/test.txt"));
            assert!(req.binary.unwrap_or(false));
            // Verify content is base64-encoded
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(req.content.as_deref().unwrap()).unwrap();
            assert_eq!(decoded, b"new file content");
            wire::send_json(&mut server, &ok_response("ok")).await.unwrap();
        });

        let result = push(&mut client, data, "/tmp/test.txt").await.unwrap();
        assert_eq!(result.bytes_sent, data.len());
        assert!(!result.delta); // full upload, not delta
        h.await.unwrap();
    }

    // ── Push: delta sync (remote file exists) ───────────────────────

    #[tokio::test]
    async fn push_delta_when_remote_exists() {
        let (mut client, mut server) = mock_client();
        let data = b"updated content here";

        let h = tokio::spawn(async move {
            // Step 1: push-sigs → return sigs
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "push-sigs");
            let sigs = vec![mrsh_core::protocol::BlockSig {
                index: 0,
                weak: 123456,
                strong: "abc123".to_string(),
            }];
            let sigs_json = serde_json::to_string(&sigs).unwrap();
            wire::send_json(&mut server, &ok_response(&sigs_json)).await.unwrap();

            // Step 2: push-delta with computed delta ops
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "push-delta");
            assert_eq!(req.path.as_deref(), Some("/tmp/delta.txt"));
            assert!(req.delta.is_some());
            wire::send_json(&mut server, &ok_response("ok")).await.unwrap();
        });

        let result = push(&mut client, data, "/tmp/delta.txt").await.unwrap();
        assert_eq!(result.bytes_sent, data.len());
        assert!(result.delta);
        h.await.unwrap();
    }

    // ── Pull: full download ─────────────────────────────────────────

    #[tokio::test]
    async fn pull_full_download_no_local() {
        let (mut client, mut server) = mock_client();
        let remote_content = b"remote file data";
        let b64 = base64::engine::general_purpose::STANDARD.encode(remote_content);

        let h = tokio::spawn(async move {
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "pull-delta");
            assert_eq!(req.path.as_deref(), Some("/tmp/remote.txt"));
            // No local file → empty sigs
            assert!(req.signatures.as_ref().map_or(true, |s| s.is_empty()));
            wire::send_json(&mut server, &ok_binary(&b64)).await.unwrap();
        });

        let result = pull(&mut client, None, "/tmp/remote.txt").await.unwrap();
        assert_eq!(result.data, remote_content);
        assert!(!result.delta);
        h.await.unwrap();
    }

    // ── Pull: identical files (empty delta) ─────────────────────────

    #[tokio::test]
    async fn pull_identical_files_no_transfer() {
        let (mut client, mut server) = mock_client();
        let local_data = b"same content";

        let h = tokio::spawn(async move {
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "pull-delta");
            // Local sigs should be present
            assert!(req.signatures.as_ref().map_or(false, |s| !s.is_empty()));
            // Return empty delta ops = files identical
            wire::send_json(&mut server, &ok_response("[]")).await.unwrap();
        });

        let result = pull(&mut client, Some(local_data), "/tmp/same.txt").await.unwrap();
        assert_eq!(result.data, local_data);
        assert!(result.delta);
        h.await.unwrap();
    }

    // ── Push dir: dry run ───────────────────────────────────────────

    #[tokio::test]
    async fn push_dir_dry_run() {
        let (mut client, _server) = mock_client();
        let tmp = std::env::temp_dir().join("rsh_test_push_dir");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("a.txt"), "aaa").unwrap();
        std::fs::write(tmp.join("b.txt"), "bbb").unwrap();

        let opts = TransferOptions { dry_run: true, ..Default::default() };
        let result = push_dir(&mut client, &tmp, "C:\\dest", &opts).await.unwrap();
        assert_eq!(result.files_total, 2);
        assert_eq!(result.files_transferred, 0); // dry run = no transfer

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Pull dir: basic ─────────────────────────────────────────────

    #[tokio::test]
    async fn pull_dir_basic() {
        let (mut client, mut server) = mock_client();
        let tmp = std::env::temp_dir().join("rsh_test_pull_dir");
        let _ = std::fs::remove_dir_all(&tmp);

        let file_content = b"pulled content";
        let b64 = base64::engine::general_purpose::STANDARD.encode(file_content);

        let h = tokio::spawn(async move {
            // Step 1: walk request
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "sync");
            assert_eq!(req.sync_type.as_deref(), Some("walk"));
            let walk = r#"[{"p":"file.txt","s":14}]"#;
            wire::send_json(&mut server, &ok_response(walk)).await.unwrap();

            // Step 2: pull-delta for file.txt
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "pull-delta");
            wire::send_json(&mut server, &ok_binary(&b64)).await.unwrap();
        });

        let opts = TransferOptions::default();
        let result = pull_dir(&mut client, "C:\\src", &tmp, &opts).await.unwrap();
        assert_eq!(result.files_total, 1);
        assert_eq!(result.files_transferred, 1);

        let pulled = std::fs::read(tmp.join("file.txt")).unwrap();
        assert_eq!(pulled, file_content);

        h.await.unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Pull dir: dry run ───────────────────────────────────────────

    #[tokio::test]
    async fn pull_dir_dry_run() {
        let (mut client, mut server) = mock_client();
        let tmp = std::env::temp_dir().join("rsh_test_pull_dir_dry");
        let _ = std::fs::remove_dir_all(&tmp);

        let h = tokio::spawn(async move {
            let _req: Request = wire::recv_json(&mut server).await.unwrap();
            let walk = r#"[{"p":"a.txt","s":100},{"p":"b.txt","s":200}]"#;
            wire::send_json(&mut server, &ok_response(walk)).await.unwrap();
        });

        let opts = TransferOptions { dry_run: true, ..Default::default() };
        let result = pull_dir(&mut client, "C:\\src", &tmp, &opts).await.unwrap();
        assert_eq!(result.files_total, 2);
        assert_eq!(result.files_transferred, 0);

        h.await.unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Delete remote extras ────────────────────────────────────────

    #[tokio::test]
    async fn delete_remote_extras_removes_missing() {
        let (mut client, mut server) = mock_client();
        let tmp = std::env::temp_dir().join("rsh_test_delete_extras");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("keep.txt"), "keep").unwrap();

        let h = tokio::spawn(async move {
            // Walk request
            let _req: Request = wire::recv_json(&mut server).await.unwrap();
            let walk = r#"[{"p":"keep.txt","s":4},{"p":"delete_me.txt","s":10}]"#;
            wire::send_json(&mut server, &ok_response(walk)).await.unwrap();

            // Delete exec request
            let req: Request = wire::recv_json(&mut server).await.unwrap();
            assert_eq!(req.req_type, "exec");
            let cmd = req.command.as_deref().unwrap();
            assert!(cmd.contains("Remove-Item"));
            assert!(cmd.contains("delete_me.txt"));
            wire::send_json(&mut server, &ok_response("")).await.unwrap();
        });

        let count = delete_remote_extras(&mut client, &tmp, "C:\\remote").await.unwrap();
        assert_eq!(count, 1);

        h.await.unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn delete_remote_extras_nothing_to_delete() {
        let (mut client, mut server) = mock_client();
        let tmp = std::env::temp_dir().join("rsh_test_delete_empty");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("same.txt"), "same").unwrap();

        let h = tokio::spawn(async move {
            let _req: Request = wire::recv_json(&mut server).await.unwrap();
            let walk = r#"[{"p":"same.txt","s":4}]"#;
            wire::send_json(&mut server, &ok_response(walk)).await.unwrap();
        });

        let count = delete_remote_extras(&mut client, &tmp, "C:\\remote").await.unwrap();
        assert_eq!(count, 0);

        h.await.unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Format helpers ──────────────────────────────────────────────

    #[test]
    fn format_rate_bytes() {
        assert_eq!(format_rate(500.0), "500B/s");
    }

    #[test]
    fn format_rate_kilobytes() {
        assert_eq!(format_rate(2048.0), "2KB/s");
    }

    #[test]
    fn format_rate_megabytes() {
        assert_eq!(format_rate(5_242_880.0), "5.0MB/s");
    }

    #[test]
    fn format_duration_seconds() {
        assert_eq!(format_duration(45.0), "0:45");
    }

    #[test]
    fn format_duration_minutes() {
        assert_eq!(format_duration(125.0), "2:05");
    }

    #[test]
    fn format_duration_hours() {
        assert_eq!(format_duration(3665.0), "1:01:05");
    }

    // ── Transfer options ────────────────────────────────────────────

    #[test]
    fn transfer_options_default() {
        let opts = TransferOptions::default();
        assert!(!opts.progress);
        assert!(!opts.dry_run);
        assert!(opts.backup_suffix.is_none());
        assert_eq!(opts.bwlimit_kbps, 0);
    }

    // ── Walk entry deserialization ──────────────────────────────────

    #[test]
    fn walk_entry_parse() {
        let json = r#"{"p":"subdir/file.txt","s":1024}"#;
        let entry: WalkEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.path, "subdir/file.txt");
        assert_eq!(entry.size, 1024);
    }
}
