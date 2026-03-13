//! Block-level deduplication cache — in-memory maps + msgpack persistence.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::chunking::{chunk_data, hash_sha256};

/// Default max age for cache entries (48 hours).
pub const DEFAULT_MAX_AGE_SECS: u64 = 48 * 3600;

/// Where a block can be found on disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockSource {
    #[serde(rename = "p")]
    pub path: String,
    #[serde(rename = "o")]
    pub offset: usize,
    #[serde(rename = "s")]
    pub size: usize,
}

/// Cached file metadata.
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
    pub mod_time: i64,
    pub block_hashes: Vec<String>,
    pub content_hash: String,
}

/// Internal block record (msgpack-serialized).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockRecord {
    #[serde(rename = "s")]
    sources: Vec<BlockSource>,
    #[serde(rename = "lu")]
    last_used: i64,
    #[serde(rename = "cr")]
    created: i64,
}

/// Internal file record (msgpack-serialized).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileRecord {
    #[serde(rename = "sz")]
    size: u64,
    #[serde(rename = "mt")]
    mod_time: i64,
    #[serde(rename = "bh")]
    block_hashes: Vec<String>,
    #[serde(rename = "ch")]
    content_hash: String,
    #[serde(rename = "ls")]
    last_seen: i64,
}

/// On-disk serialization format.
#[derive(Debug, Serialize, Deserialize, Default)]
struct CacheStore {
    #[serde(rename = "b")]
    blocks: HashMap<String, BlockRecord>,
    #[serde(rename = "f")]
    files: HashMap<String, FileRecord>,
}

/// Persistent block-level deduplication cache.
pub struct Cache {
    blocks: HashMap<String, BlockRecord>,
    files: HashMap<String, FileRecord>,
    data_path: PathBuf,
    max_age_secs: u64,
    dirty: bool,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl Cache {
    /// Create or load a cache from the given msgpack file path.
    pub fn new(data_path: &Path) -> Result<Self> {
        if let Some(parent) = data_path.parent() {
            std::fs::create_dir_all(parent).context("create cache dir")?;
        }

        let mut cache = Cache {
            blocks: HashMap::new(),
            files: HashMap::new(),
            data_path: data_path.to_path_buf(),
            max_age_secs: DEFAULT_MAX_AGE_SECS,
            dirty: false,
        };

        // Load existing data
        if let Ok(data) = std::fs::read(data_path)
            && !data.is_empty()
            && let Ok(store) = rmp_serde::from_slice::<CacheStore>(&data)
        {
            cache.blocks = store.blocks;
            cache.files = store.files;
        }

        Ok(cache)
    }

    /// Flush dirty data to disk (atomic write via temp + rename).
    pub fn flush(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }

        let store = CacheStore {
            blocks: self.blocks.clone(),
            files: self.files.clone(),
        };
        let data = rmp_serde::to_vec(&store).context("serialize cache")?;

        let tmp_path = self.data_path.with_extension("tmp");
        std::fs::write(&tmp_path, &data).context("write cache tmp")?;
        std::fs::rename(&tmp_path, &self.data_path).unwrap_or_else(|_| {
            let _ = std::fs::remove_file(&tmp_path);
        });
        self.dirty = false;
        Ok(())
    }

    /// Index a file: chunk it and add all blocks to the cache.
    /// Returns cached info if file is unchanged (same size + mtime).
    pub fn index_file(&mut self, path: &str) -> Result<FileInfo> {
        let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path))?;
        let size = meta.len();
        let mtime = meta
            .modified()
            .unwrap_or(UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Check if already indexed and unchanged
        if let Some(existing) = self.files.get_mut(path)
            && existing.size == size
            && existing.mod_time == mtime
        {
            existing.last_seen = now_unix();
            self.dirty = true;
            return Ok(FileInfo {
                path: path.to_string(),
                size: existing.size,
                mod_time: existing.mod_time,
                block_hashes: existing.block_hashes.clone(),
                content_hash: existing.content_hash.clone(),
            });
        }

        // Read and chunk file
        let data = std::fs::read(path).with_context(|| format!("read {}", path))?;
        let chunks = chunk_data(&data);
        let content_hash = hash_sha256(&data);
        let now = now_unix();

        let block_hashes: Vec<String> = chunks
            .iter()
            .map(|c| {
                self.add_block_source(&c.hash, path, c.offset, c.length, now);
                c.hash.clone()
            })
            .collect();

        self.files.insert(
            path.to_string(),
            FileRecord {
                size,
                mod_time: mtime,
                block_hashes: block_hashes.clone(),
                content_hash: content_hash.clone(),
                last_seen: now,
            },
        );
        self.dirty = true;

        Ok(FileInfo {
            path: path.to_string(),
            size,
            mod_time: mtime,
            block_hashes,
            content_hash,
        })
    }

    /// Find files with matching content hash (rename/move detection).
    pub fn find_by_content_hash(&mut self, hash: &str) -> Vec<String> {
        let now = now_unix();
        let mut paths = Vec::new();
        let mut to_remove = Vec::new();

        for (path, entry) in &mut self.files {
            if entry.content_hash == hash {
                if Path::new(path).exists() {
                    paths.push(path.clone());
                    entry.last_seen = now;
                    self.dirty = true;
                } else {
                    to_remove.push(path.clone());
                }
            }
        }

        for path in to_remove {
            self.files.remove(&path);
            self.dirty = true;
        }

        paths
    }

    /// Find where a block hash exists on disk.
    pub fn find_block_sources(&mut self, hash: &str) -> Vec<BlockSource> {
        let entry = match self.blocks.get_mut(hash) {
            Some(e) => e,
            None => return Vec::new(),
        };

        let now = now_unix();
        let valid: Vec<BlockSource> = entry
            .sources
            .iter()
            .filter(|s| Path::new(&s.path).exists())
            .cloned()
            .collect();

        if valid.is_empty() {
            self.blocks.remove(hash);
            self.dirty = true;
            return Vec::new();
        }

        if valid.len() != entry.sources.len() {
            entry.sources = valid.clone();
        }
        entry.last_used = now;
        self.dirty = true;

        valid
    }

    /// Get cached file info.
    pub fn get_file_info(&self, path: &str) -> Option<FileInfo> {
        self.files.get(path).map(|e| FileInfo {
            path: path.to_string(),
            size: e.size,
            mod_time: e.mod_time,
            block_hashes: e.block_hashes.clone(),
            content_hash: e.content_hash.clone(),
        })
    }

    /// Remove a stale cache entry.
    pub fn remove_file(&mut self, path: &str) {
        if self.files.remove(path).is_some() {
            self.dirty = true;
        }
    }

    /// Remove expired entries. Returns count of removed entries.
    pub fn cleanup(&mut self) -> usize {
        let cutoff = now_unix() - self.max_age_secs as i64;
        let mut removed = 0;

        self.blocks.retain(|_, entry| {
            if entry.last_used < cutoff {
                removed += 1;
                false
            } else {
                true
            }
        });

        self.files.retain(|_, entry| {
            if entry.last_seen < cutoff {
                removed += 1;
                false
            } else {
                true
            }
        });

        if removed > 0 {
            self.dirty = true;
        }
        removed
    }

    /// Cache statistics: (block_count, file_count).
    pub fn stats(&self) -> (usize, usize) {
        (self.blocks.len(), self.files.len())
    }

    fn add_block_source(&mut self, hash: &str, path: &str, offset: usize, size: usize, now: i64) {
        let entry = self.blocks.entry(hash.to_string()).or_insert_with(|| {
            self.dirty = true;
            BlockRecord {
                sources: Vec::new(),
                last_used: now,
                created: now,
            }
        });

        // Deduplicate: don't add if same path+offset already exists
        for s in &entry.sources {
            if s.path == path && s.offset == offset {
                entry.last_used = now;
                self.dirty = true;
                return;
            }
        }

        entry.sources.push(BlockSource {
            path: path.to_string(),
            offset,
            size,
        });
        entry.last_used = now;
        self.dirty = true;
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_cache() -> (Cache, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.msgpack");
        let cache = Cache::new(&path).unwrap();
        (cache, dir)
    }

    #[test]
    fn new_cache_empty() {
        let (cache, _dir) = temp_cache();
        assert_eq!(cache.stats(), (0, 0));
    }

    #[test]
    fn index_file_and_retrieve() {
        let (mut cache, dir) = temp_cache();
        let test_file = dir.path().join("test.bin");
        std::fs::write(&test_file, vec![0x41u8; 10000]).unwrap();

        let info = cache.index_file(test_file.to_str().unwrap()).unwrap();
        assert_eq!(info.size, 10000);
        assert!(!info.content_hash.is_empty());
        assert!(!info.block_hashes.is_empty());

        let (blocks, files) = cache.stats();
        assert!(blocks > 0);
        assert_eq!(files, 1);
    }

    #[test]
    fn index_file_unchanged_returns_cached() {
        let (mut cache, dir) = temp_cache();
        let test_file = dir.path().join("test.bin");
        std::fs::write(&test_file, vec![0x41u8; 10000]).unwrap();

        let info1 = cache.index_file(test_file.to_str().unwrap()).unwrap();
        let info2 = cache.index_file(test_file.to_str().unwrap()).unwrap();
        assert_eq!(info1.content_hash, info2.content_hash);
        assert_eq!(info1.block_hashes, info2.block_hashes);
    }

    #[test]
    fn find_by_content_hash() {
        let (mut cache, dir) = temp_cache();
        let test_file = dir.path().join("test.bin");
        let data = vec![0x42u8; 5000];
        std::fs::write(&test_file, &data).unwrap();

        let info = cache.index_file(test_file.to_str().unwrap()).unwrap();
        let found = cache.find_by_content_hash(&info.content_hash);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], test_file.to_str().unwrap());
    }

    #[test]
    fn persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("cache.msgpack");
        let test_file = dir.path().join("test.bin");
        std::fs::write(&test_file, vec![0x41u8; 5000]).unwrap();

        // Write
        {
            let mut cache = Cache::new(&cache_path).unwrap();
            cache.index_file(test_file.to_str().unwrap()).unwrap();
            cache.flush().unwrap();
        }

        // Read back
        {
            let cache = Cache::new(&cache_path).unwrap();
            let (blocks, files) = cache.stats();
            assert!(blocks > 0);
            assert_eq!(files, 1);
        }
    }

    #[test]
    fn remove_file_clears_entry() {
        let (mut cache, dir) = temp_cache();
        let test_file = dir.path().join("test.bin");
        std::fs::write(&test_file, vec![0x41u8; 5000]).unwrap();

        cache.index_file(test_file.to_str().unwrap()).unwrap();
        assert_eq!(cache.stats().1, 1);

        cache.remove_file(test_file.to_str().unwrap());
        assert_eq!(cache.stats().1, 0);
    }

    #[test]
    fn get_file_info_returns_indexed() {
        let (mut cache, dir) = temp_cache();
        let test_file = dir.path().join("test.bin");
        std::fs::write(&test_file, vec![0x41u8; 10000]).unwrap();

        cache.index_file(test_file.to_str().unwrap()).unwrap();
        let info = cache.get_file_info(test_file.to_str().unwrap());
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.size, 10000);
        assert!(!info.content_hash.is_empty());
        assert!(!info.block_hashes.is_empty());

        // Non-existent path
        assert!(cache.get_file_info("/nonexistent").is_none());
    }

    #[test]
    fn find_block_sources_returns_locations() {
        let (mut cache, dir) = temp_cache();
        let test_file = dir.path().join("test.bin");
        std::fs::write(&test_file, vec![0x41u8; 10000]).unwrap();

        let info = cache.index_file(test_file.to_str().unwrap()).unwrap();
        assert!(!info.block_hashes.is_empty());

        let sources = cache.find_block_sources(&info.block_hashes[0]);
        assert!(!sources.is_empty());
        assert_eq!(sources[0].path, test_file.to_str().unwrap());
        assert_eq!(sources[0].offset, 0);

        // Non-existent hash
        let empty = cache.find_block_sources("nonexistent_hash");
        assert!(empty.is_empty());
    }

    /// Regression: index file → delete from disk → re-index must fail (not return
    /// stale cached data).  Previously cache trusted entries for deleted files.
    #[test]
    fn reindex_after_delete_returns_error() {
        let (mut cache, dir) = temp_cache();
        let test_file = dir.path().join("ephemeral.bin");
        std::fs::write(&test_file, vec![0xABu8; 8000]).unwrap();

        // Index succeeds.
        let info = cache.index_file(test_file.to_str().unwrap()).unwrap();
        assert_eq!(info.size, 8000);

        // Delete the file from disk.
        std::fs::remove_file(&test_file).unwrap();

        // Re-index must fail — file no longer exists.
        let result = cache.index_file(test_file.to_str().unwrap());
        assert!(result.is_err(), "index_file must fail for deleted file, not return stale cache");
    }

    /// Index file → modify content (same name) → re-index detects change.
    #[test]
    fn reindex_after_modify_detects_new_content() {
        let (mut cache, dir) = temp_cache();
        let test_file = dir.path().join("mutable.bin");
        std::fs::write(&test_file, vec![0x01u8; 5000]).unwrap();

        let info1 = cache.index_file(test_file.to_str().unwrap()).unwrap();

        // Overwrite with different content and different size to ensure mtime/size changes.
        std::fs::write(&test_file, vec![0x02u8; 6000]).unwrap();

        let info2 = cache.index_file(test_file.to_str().unwrap()).unwrap();
        assert_ne!(info1.content_hash, info2.content_hash, "content hash must change after modification");
        assert_eq!(info2.size, 6000);
    }

    #[test]
    fn cleanup_removes_old_entries() {
        let (mut cache, dir) = temp_cache();
        let test_file = dir.path().join("test.bin");
        std::fs::write(&test_file, vec![0x41u8; 5000]).unwrap();

        cache.index_file(test_file.to_str().unwrap()).unwrap();
        let (blocks_before, files_before) = cache.stats();
        assert!(blocks_before > 0);
        assert_eq!(files_before, 1);

        // With default max_age (48h), nothing should be cleaned
        let removed = cache.cleanup();
        assert_eq!(removed, 0);
        assert_eq!(cache.stats(), (blocks_before, files_before));

        // Backdate all entries so they're older than any max_age
        for entry in cache.blocks.values_mut() {
            entry.last_used -= 100;
        }
        for entry in cache.files.values_mut() {
            entry.last_seen -= 100;
        }
        cache.max_age_secs = 50;
        let removed = cache.cleanup();
        assert!(removed > 0);
        assert_eq!(cache.stats(), (0, 0));
    }
}
