//! Rsync-like delta file transfer — Adler32 weak hash + MD5 strong hash.

use base64::Engine;
use md5::{Digest as Md5Digest, Md5};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Block size for delta computation (4KB).
pub const BLOCK_SIZE: usize = 4096;

/// Block signature for delta sync.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockSig {
    #[serde(rename = "i")]
    pub index: usize,
    #[serde(rename = "w")]
    pub weak: u32,
    #[serde(rename = "s")]
    pub strong: String,
}

/// Delta operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeltaOp {
    #[serde(rename = "t")]
    pub op_type: String,
    #[serde(rename = "i", default, skip_serializing_if = "is_zero")]
    pub index: usize,
    #[serde(rename = "d", default, skip_serializing_if = "String::is_empty")]
    pub data: String,
}

fn is_zero(v: &usize) -> bool {
    *v == 0
}

/// Compute block signatures for a file.
pub fn compute_signatures(data: &[u8]) -> Vec<BlockSig> {
    let mut sigs = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let end = (i + BLOCK_SIZE).min(data.len());
        let block = &data[i..end];
        let weak = adler32::adler32(block).unwrap_or(0);
        let strong = {
            let hash = Md5::digest(block);
            base64::engine::general_purpose::STANDARD.encode(hash)
        };
        sigs.push(BlockSig {
            index: i / BLOCK_SIZE,
            weak,
            strong,
        });
        i += BLOCK_SIZE;
    }
    sigs
}

/// Compute delta operations to transform remote file to local.
pub fn compute_delta(new_data: &[u8], remote_sigs: &[BlockSig]) -> Vec<DeltaOp> {
    if remote_sigs.is_empty() {
        return vec![DeltaOp {
            op_type: "data".to_string(),
            data: base64::engine::general_purpose::STANDARD.encode(new_data),
            index: 0,
        }];
    }

    // Build lookup map: weak checksum -> list of sigs
    let mut weak_map: HashMap<u32, Vec<&BlockSig>> = HashMap::new();
    for sig in remote_sigs {
        weak_map.entry(sig.weak).or_default().push(sig);
    }

    let mut ops = Vec::new();
    let mut unmatched: Vec<u8> = Vec::new();
    let mut i = 0;

    while i < new_data.len() {
        let mut matched = false;

        // Try to match a block at current position
        if i + BLOCK_SIZE <= new_data.len() || i == new_data.len() - new_data.len() % BLOCK_SIZE {
            let end = (i + BLOCK_SIZE).min(new_data.len());
            let block = &new_data[i..end];
            let weak = adler32::adler32(block).unwrap_or(0);

            if let Some(candidates) = weak_map.get(&weak) {
                let strong = {
                    let hash = Md5::digest(block);
                    base64::engine::general_purpose::STANDARD.encode(hash)
                };

                for sig in candidates {
                    if sig.strong == strong {
                        if !unmatched.is_empty() {
                            ops.push(DeltaOp {
                                op_type: "data".to_string(),
                                data: base64::engine::general_purpose::STANDARD.encode(&unmatched),
                                index: 0,
                            });
                            unmatched.clear();
                        }
                        ops.push(DeltaOp {
                            op_type: "match".to_string(),
                            index: sig.index,
                            data: String::new(),
                        });
                        i = end;
                        matched = true;
                        break;
                    }
                }
            }
        }

        if !matched {
            unmatched.push(new_data[i]);
            i += 1;
        }
    }

    if !unmatched.is_empty() {
        ops.push(DeltaOp {
            op_type: "data".to_string(),
            data: base64::engine::general_purpose::STANDARD.encode(&unmatched),
            index: 0,
        });
    }

    ops
}

/// Reconstruct file from existing data and delta operations.
pub fn apply_delta(existing_data: &[u8], delta: &[DeltaOp]) -> Vec<u8> {
    let mut result = Vec::new();
    for op in delta {
        match op.op_type.as_str() {
            "match" => {
                let start = op.index * BLOCK_SIZE;
                let end = (start + BLOCK_SIZE).min(existing_data.len());
                if start < existing_data.len() {
                    result.extend_from_slice(&existing_data[start..end]);
                }
            }
            "data" => {
                if let Ok(data) = base64::engine::general_purpose::STANDARD.decode(&op.data) {
                    result.extend_from_slice(&data);
                }
            }
            _ => {}
        }
    }
    result
}

/// Returns (match_blocks, data_bytes) statistics for delta operations.
pub fn delta_stats(delta: &[DeltaOp]) -> (usize, usize) {
    let mut match_blocks = 0;
    let mut data_bytes = 0;
    for op in delta {
        match op.op_type.as_str() {
            "match" => match_blocks += 1,
            "data" => {
                if let Ok(data) = base64::engine::general_purpose::STANDARD.decode(&op.data) {
                    data_bytes += data.len();
                }
            }
            _ => {}
        }
    }
    (match_blocks, data_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_block_count() {
        let data = vec![0x41u8; BLOCK_SIZE * 3 + 100]; // 3 full + 1 partial
        let sigs = compute_signatures(&data);
        assert_eq!(sigs.len(), 4);
        assert_eq!(sigs[0].index, 0);
        assert_eq!(sigs[3].index, 3);
    }

    #[test]
    fn delta_identical_file() {
        let data = vec![0x42u8; BLOCK_SIZE * 2];
        let sigs = compute_signatures(&data);
        let delta = compute_delta(&data, &sigs);
        assert!(delta.iter().all(|op| op.op_type == "match"));
        assert_eq!(delta.len(), 2);
    }

    #[test]
    fn delta_no_remote() {
        let data = b"hello world";
        let delta = compute_delta(data, &[]);
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].op_type, "data");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&delta[0].data)
            .unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn apply_delta_append() {
        let original = vec![0x41u8; BLOCK_SIZE * 3];
        let mut modified = original.clone();
        modified.extend_from_slice(b"extra data at the end");

        let sigs = compute_signatures(&original);
        let delta = compute_delta(&modified, &sigs);
        let reconstructed = apply_delta(&original, &delta);
        assert_eq!(reconstructed, modified);
    }

    #[test]
    fn apply_delta_truncation() {
        let original = vec![0x41u8; BLOCK_SIZE * 4];
        let modified = vec![0x41u8; BLOCK_SIZE * 2];

        let sigs = compute_signatures(&original);
        let delta = compute_delta(&modified, &sigs);
        let reconstructed = apply_delta(&original, &delta);
        assert_eq!(reconstructed, modified);
    }

    #[test]
    fn delta_stats_counts() {
        let original = vec![0x41u8; BLOCK_SIZE * 2];
        let mut modified = original.clone();
        modified.extend_from_slice(b"new content");

        let sigs = compute_signatures(&original);
        let delta = compute_delta(&modified, &sigs);
        let (matches, data_bytes) = delta_stats(&delta);
        assert_eq!(matches, 2);
        assert_eq!(data_bytes, b"new content".len());
    }

    #[test]
    fn json_wire_compat() {
        let sig = BlockSig {
            index: 0,
            weak: 123456,
            strong: "dGVzdA==".to_string(),
        };
        let json = serde_json::to_string(&sig).unwrap();
        assert!(json.contains("\"i\":"));
        assert!(json.contains("\"w\":"));
        assert!(json.contains("\"s\":"));

        let op = DeltaOp {
            op_type: "match".to_string(),
            index: 5,
            data: String::new(),
        };
        let json = serde_json::to_string(&op).unwrap();
        assert!(json.contains("\"t\":\"match\""));
        assert!(json.contains("\"i\":5"));
        assert!(!json.contains("\"d\":")); // empty data skipped
    }
}
