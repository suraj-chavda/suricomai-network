// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Single-use `(chain_id, job_id, contract_hash)` cache.
//!
//! The contract hash is part of the key so a stranger who learns a job id cannot
//! burn the real job's slot by sealing a different contract under the same id.
//! The chain, not this cache, decides which contract for a job id gets paid.
//!
//! A presented id is consumed only after a successful open. A bad ciphertext does
//! not burn the id. Expired jobs are rejected before open so they do not fill the cache.

use std::collections::HashMap;

use crate::error::EnvelopeError;

/// Process-local replay window.
#[derive(Debug)]
pub struct ReplayCache {
    seen: HashMap<(u64, [u8; 32], [u8; 32]), u64>,
    limit: usize,
}

impl ReplayCache {
    /// Create an empty cache that holds at most `limit` ids.
    pub fn new(limit: usize) -> Self {
        Self {
            seen: HashMap::new(),
            limit,
        }
    }

    /// Insert `id` or refuse because it was already seen or the cache is full.
    ///
    /// `expiry` is the contract expiry. An expired job is rejected before it
    /// reaches the cache, so once `now >= expiry` the entry can no longer matter
    /// and is dropped when the cache fills up.
    pub fn insert(
        &mut self,
        chain_id: u64,
        job_id: [u8; 32],
        contract_hash: [u8; 32],
        expiry: u64,
        now: u64,
    ) -> Result<(), EnvelopeError> {
        let key = (chain_id, job_id, contract_hash);
        if self.seen.contains_key(&key) {
            return Err(EnvelopeError::Replay);
        }
        if self.seen.len() >= self.limit {
            self.seen.retain(|_, held_until| *held_until > now);
            if self.seen.len() >= self.limit {
                return Err(EnvelopeError::CacheFull);
            }
        }
        self.seen.insert(key, expiry);
        Ok(())
    }
}

const SNAPSHOT_MAGIC: &[u8; 4] = b"SRC1";
const ENTRY_LEN: usize = 8 + 32 + 32 + 8;

impl ReplayCache {
    /// Canonical bytes for writing the cache to disk, so a restart keeps its memory.
    /// Entries are sorted, so equal caches give equal bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut entries: Vec<_> = self.seen.iter().collect();
        entries.sort();
        let mut out = Vec::with_capacity(8 + entries.len() * ENTRY_LEN);
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.extend_from_slice(
            &u32::try_from(entries.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for ((chain_id, job_id, contract_hash), expiry) in entries {
            out.extend_from_slice(&chain_id.to_be_bytes());
            out.extend_from_slice(job_id);
            out.extend_from_slice(contract_hash);
            out.extend_from_slice(&expiry.to_be_bytes());
        }
        out
    }

    /// Read a cache written by [`Self::to_bytes`]. Any malformed input is `bad_snapshot`
    /// and the caller must start empty and refuse jobs until it has a good copy.
    pub fn from_bytes(bytes: &[u8], limit: usize) -> Result<Self, EnvelopeError> {
        let body = bytes
            .strip_prefix(SNAPSHOT_MAGIC.as_slice())
            .ok_or(EnvelopeError::BadSnapshot)?;
        let (count, rows) = body.split_at_checked(4).ok_or(EnvelopeError::BadSnapshot)?;
        let count = u32::from_be_bytes(count.try_into().map_err(|_| EnvelopeError::BadSnapshot)?);
        let count = usize::try_from(count).map_err(|_| EnvelopeError::BadSnapshot)?;
        if rows.len()
            != count
                .checked_mul(ENTRY_LEN)
                .ok_or(EnvelopeError::BadSnapshot)?
            || count > limit
        {
            return Err(EnvelopeError::BadSnapshot);
        }
        let mut cache = Self::new(limit);
        let (rows, _) = rows.as_chunks::<ENTRY_LEN>();
        for row in rows {
            let chain_id = u64::from_be_bytes(
                row[0..8]
                    .try_into()
                    .map_err(|_| EnvelopeError::BadSnapshot)?,
            );
            let job_id: [u8; 32] = row[8..40]
                .try_into()
                .map_err(|_| EnvelopeError::BadSnapshot)?;
            let contract_hash: [u8; 32] = row[40..72]
                .try_into()
                .map_err(|_| EnvelopeError::BadSnapshot)?;
            let expiry = u64::from_be_bytes(
                row[72..80]
                    .try_into()
                    .map_err(|_| EnvelopeError::BadSnapshot)?,
            );
            if cache
                .seen
                .insert((chain_id, job_id, contract_hash), expiry)
                .is_some()
            {
                return Err(EnvelopeError::BadSnapshot);
            }
        }
        Ok(cache)
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new(100_000)
    }
}
