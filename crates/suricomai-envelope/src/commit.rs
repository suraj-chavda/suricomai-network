// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Domain-separated BLAKE3 commitments.
//!
//! Each label is a BLAKE3 context string passed to [`blake3::Hasher::new_derive_key`].
//! The prompt itself is the raw byte string. It is not canonicalized as text.

use crate::error::EnvelopeError;

/// Commitment to the exact prompt bytes the user asked to run.
pub fn commit_prompt(prompt: &[u8]) -> [u8; 32] {
    domain_hash("suricomai.prompt.v1", &[prompt])
}

/// Commitment to the answer ciphertext the user received (`enc || enc_answer`).
pub(crate) fn commit_answer_ciphertext(enc: &[u8], enc_answer: &[u8]) -> [u8; 32] {
    domain_hash("suricomai.answer_ct.v1", &[enc, enc_answer])
}

/// Hash of the canonical contract bytes. A proof carries it so it closes one contract only.
pub(crate) fn commit_contract(contract_bytes: &[u8]) -> [u8; 32] {
    domain_hash("suricomai.contract.v1", &[contract_bytes])
}

/// Report data bound into an advertisement quote before a prompt is sent.
pub(crate) fn advertise_report(
    hpke_public: &[u8],
    receipt_public: &[u8; 32],
    executor_id: &[u8; 32],
    nonce: &[u8; 32],
    issued_at: u64,
    valid_until: u64,
    transport_public: &[u8; 32],
) -> [u8; 32] {
    domain_hash(
        "suricomai.advertise.v2",
        &[
            hpke_public,
            receipt_public,
            executor_id,
            nonce,
            &issued_at.to_be_bytes(),
            &valid_until.to_be_bytes(),
            transport_public,
        ],
    )
}

/// Report data bound into the per-job quote.
pub(crate) fn job_report(fields: &JobReportFields<'_>) -> [u8; 32] {
    let flag = [u8::from(fields.gpu_evidence.is_some())];
    let gpu = fields.gpu_evidence.unwrap_or([0u8; 32]);
    domain_hash(
        "suricomai.report_data.v1",
        &[
            fields.job_id,
            fields.prompt_commitment,
            fields.answer_ciphertext_hash,
            fields.model_digest,
            fields.executor_id,
            fields.receipt_public,
            fields.hpke_public,
            fields.quote_nonce,
            &flag,
            &gpu,
            fields.contract_hash,
        ],
    )
}

/// Inputs to [`job_report`]. Every slice the caller supplies is fixed-width except `hpke_public`.
pub(crate) struct JobReportFields<'a> {
    pub job_id: &'a [u8; 32],
    pub prompt_commitment: &'a [u8; 32],
    pub answer_ciphertext_hash: &'a [u8; 32],
    pub model_digest: &'a [u8; 32],
    pub executor_id: &'a [u8; 32],
    pub receipt_public: &'a [u8; 32],
    pub hpke_public: &'a [u8],
    pub quote_nonce: &'a [u8; 32],
    pub gpu_evidence: Option<[u8; 32]>,
    pub contract_hash: &'a [u8; 32],
}

/// Round a raw token count up into a public bucket. Zero stays zero.
pub fn token_bucket(token_count: u64) -> Result<u64, EnvelopeError> {
    if token_count == 0 {
        return Ok(0);
    }
    const BUCKETS: [u64; 12] = [
        32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
    ];
    BUCKETS
        .into_iter()
        .find(|bucket| *bucket >= token_count)
        .ok_or(EnvelopeError::TooManyTokens)
}

pub(crate) fn domain_hash(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

pub(crate) fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}
