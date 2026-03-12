//! Rabin polynomial content-defined chunking (CDC).

use sha2::{Digest, Sha256};

/// Minimum chunk size (2 KB).
pub const MIN_CHUNK_SIZE: usize = 2 * 1024;
/// Average chunk size (64 KB).
pub const AVG_CHUNK_SIZE: usize = 64 * 1024;
/// Maximum chunk size (256 KB).
pub const MAX_CHUNK_SIZE: usize = 256 * 1024;
/// Rolling window size.
pub const WINDOW_SIZE: usize = 48;
/// Rabin polynomial (irreducible polynomial for GF(2^64)).
pub const RABIN_POLY: u64 = 0x3DA3358B4DC173;
/// Mask for average chunk size (avg_size must be power of 2).
pub const CHUNK_MASK: u64 = (AVG_CHUNK_SIZE - 1) as u64;

/// A content-defined chunk.
#[derive(Debug, Clone, PartialEq)]
pub struct Chunk {
    pub offset: usize,
    pub length: usize,
    pub hash: String, // SHA-256 hex
}

/// Precomputed Rabin lookup tables.
struct RabinTables {
    out: [u64; 256],
    modtab: [u64; 256],
}

impl RabinTables {
    fn new() -> Self {
        let mut tables = RabinTables {
            out: [0u64; 256],
            modtab: [0u64; 256],
        };

        // out table: hash of byte shifted out of window
        for i in 0..256 {
            let mut hash = i as u64;
            for _ in 0..WINDOW_SIZE {
                hash = (hash << 1) ^ ((hash >> 63) * RABIN_POLY);
            }
            tables.out[i] = hash;
        }

        // mod table: polynomial reduction
        for i in 0..256 {
            let mut hash = i as u64;
            for _ in 0..8 {
                if hash & 1 != 0 {
                    hash = (hash >> 1) ^ RABIN_POLY;
                } else {
                    hash >>= 1;
                }
            }
            tables.modtab[i] = hash;
        }

        tables
    }

    #[inline]
    fn roll_in(&self, hash: u64, b: u8) -> u64 {
        (hash << 8) ^ self.modtab[(hash >> 56) as u8 as usize] ^ (b as u64)
    }

    #[inline]
    fn roll(&self, hash: u64, out: u8, inp: u8) -> u64 {
        let hash = hash ^ self.out[out as usize];
        self.roll_in(hash, inp)
    }
}

/// Rabin chunker — splits data into content-defined chunks.
pub struct RabinChunker<'a> {
    data: &'a [u8],
    pos: usize,
    tables: RabinTables,
}

impl<'a> RabinChunker<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        RabinChunker {
            data,
            pos: 0,
            tables: RabinTables::new(),
        }
    }
}

impl<'a> Iterator for RabinChunker<'a> {
    type Item = Chunk;

    fn next(&mut self) -> Option<Chunk> {
        if self.pos >= self.data.len() {
            return None;
        }

        let start = self.pos;
        let min_pos = (start + MIN_CHUNK_SIZE).min(self.data.len());
        let max_pos = (start + MAX_CHUNK_SIZE).min(self.data.len());

        // Skip to minimum chunk size
        self.pos = min_pos;

        // Initialize rolling hash with window
        let window_start = if self.pos >= WINDOW_SIZE + start {
            self.pos - WINDOW_SIZE
        } else {
            start
        };

        let mut hash = 0u64;
        for i in window_start..self.pos.min(self.data.len()) {
            hash = self.tables.roll_in(hash, self.data[i]);
        }

        // Roll until we find a boundary or hit max size
        while self.pos < max_pos {
            if self.pos >= self.data.len() {
                break;
            }

            let out_byte = if self.pos >= WINDOW_SIZE + start {
                self.data[self.pos - WINDOW_SIZE]
            } else {
                0
            };
            hash = self.tables.roll(hash, out_byte, self.data[self.pos]);
            self.pos += 1;

            if (hash & CHUNK_MASK) == 0 {
                break;
            }
        }

        let chunk_data = &self.data[start..self.pos];
        Some(Chunk {
            offset: start,
            length: chunk_data.len(),
            hash: hash_sha256(chunk_data),
        })
    }
}

/// Split data into content-defined chunks.
pub fn chunk_data(data: &[u8]) -> Vec<Chunk> {
    RabinChunker::new(data).collect()
}

/// Compute content hash and block hashes for data.
pub fn file_hashes(data: &[u8]) -> (String, Vec<String>) {
    let content_hash = hash_sha256(data);
    let chunks = chunk_data(data);
    let block_hashes: Vec<String> = chunks.into_iter().map(|c| c.hash).collect();
    (content_hash, block_hashes)
}

/// SHA-256 hex digest.
pub fn hash_sha256(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex::encode(hash)
}

/// Hex encoding (no extra dependency, reuse sha2's output).
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().fold(
            String::with_capacity(data.as_ref().len() * 2),
            |mut s, b| {
                use std::fmt::Write;
                write!(s, "{:02x}", b).unwrap();
                s
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_small_data() {
        // Data smaller than MIN_CHUNK_SIZE → single chunk
        let data = vec![0x42u8; 1000];
        let chunks = chunk_data(&data);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].offset, 0);
        assert_eq!(chunks[0].length, 1000);
    }

    #[test]
    fn chunk_respects_min_size() {
        let data = vec![0x41u8; MIN_CHUNK_SIZE + 100];
        let chunks = chunk_data(&data);
        for chunk in &chunks {
            // Each chunk should be at least MIN_CHUNK_SIZE (except possibly last)
            if chunk.offset + chunk.length < data.len() {
                assert!(chunk.length >= MIN_CHUNK_SIZE);
            }
        }
    }

    #[test]
    fn chunk_respects_max_size() {
        let data = vec![0x41u8; MAX_CHUNK_SIZE * 3];
        let chunks = chunk_data(&data);
        for chunk in &chunks {
            assert!(chunk.length <= MAX_CHUNK_SIZE);
        }
    }

    #[test]
    fn chunk_covers_all_data() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();
        let chunks = chunk_data(&data);

        // Chunks must be contiguous and cover all data
        let mut offset = 0;
        for chunk in &chunks {
            assert_eq!(chunk.offset, offset);
            offset += chunk.length;
        }
        assert_eq!(offset, data.len());
    }

    #[test]
    fn chunk_deterministic() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 256) as u8).collect();
        let chunks1 = chunk_data(&data);
        let chunks2 = chunk_data(&data);
        assert_eq!(chunks1, chunks2);
    }

    #[test]
    fn hash_sha256_known_value() {
        let hash = hash_sha256(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn file_hashes_returns_both() {
        let data = vec![0x41u8; MIN_CHUNK_SIZE * 3];
        let (content_hash, block_hashes) = file_hashes(&data);
        assert!(!content_hash.is_empty());
        assert!(!block_hashes.is_empty());
        // Content hash is of whole data, block hashes are per-chunk
        assert_eq!(content_hash, hash_sha256(&data));
    }
}
