// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Pinned tiny model.
//!
//! The weights are derived from a fixed domain string, then hashed into `model_digest`.
//! Inference is a pure function of those weights, the prompt, and the sealed parameters.
//! Swapping the weights changes both the digest and the answer.

use suricomai_envelope::InferenceParams;

/// Name committed into the runtime measurement.
pub const MODEL_NAME: &str = "suricomai-tiny-v1";
/// Build identity committed into the runtime measurement.
pub const RUNTIME_VERSION: &str = "suricomai-runtime-0.1.0";

/// Expand the pinned weight table. The same call always returns the same bytes.
pub fn pinned_weights() -> [u8; 256] {
    let mut out = [0u8; 256];
    for (index, chunk) in out.chunks_mut(32).enumerate() {
        let mut hasher = blake3::Hasher::new_derive_key("suricomai.tiny-weights.v1");
        hasher.update(&[index as u8]);
        let block = hasher.finalize();
        chunk.copy_from_slice(&block.as_bytes()[..chunk.len()]);
    }
    out
}

/// Digest of a weights file, byte for byte. This is a manifest's `model_digest`.
pub fn weights_file_digest(bytes: &[u8]) -> [u8; 32] {
    domain_hash("suricomai.model.v1", &[bytes])
}

/// Digest of a tokenizer file, byte for byte. This is a manifest's `tokenizer_digest`.
pub fn tokenizer_file_digest(bytes: &[u8]) -> [u8; 32] {
    domain_hash("suricomai.tokenizer.v1", &[bytes])
}

/// Digest that names this inference runtime build. A manifest's `runtime_digest` must equal it.
pub fn runtime_digest() -> [u8; 32] {
    domain_hash("suricomai.runtime-build.v1", &[RUNTIME_VERSION.as_bytes()])
}

/// Digest the executor requires in the prompt contract.
pub fn model_digest(weights: &[u8; 256]) -> [u8; 32] {
    domain_hash("suricomai.model.v1", &[weights])
}

/// Measurement bound into the lab quote. It covers the runtime version and the model digest.
pub fn runtime_measurement(model_digest: &[u8; 32]) -> [u8; 32] {
    domain_hash(
        "suricomai.runtime.v1",
        &[
            RUNTIME_VERSION.as_bytes(),
            MODEL_NAME.as_bytes(),
            model_digest,
        ],
    )
}

/// Run the pinned model. `max_output` is the contract's byte cap.
pub fn infer(
    weights: &[u8; 256],
    prompt: &[u8],
    params: &InferenceParams,
    max_output: u64,
) -> Vec<u8> {
    let mut state = params.seed;
    state[0] ^= params.temperature_millis as u8;
    state[1] ^= (params.temperature_millis >> 8) as u8;
    for (index, byte) in prompt.iter().enumerate() {
        let weight = weights[usize::from(*byte)];
        state[index % 32] = state[index % 32].wrapping_add(byte.wrapping_add(weight));
        state[(index + 1) % 32] ^= weight;
    }
    let count = (params.max_tokens as usize)
        .min(max_output as usize)
        .min(256);
    let mut answer = Vec::with_capacity(count);
    for index in 0..count {
        let weight = weights[index % 256];
        let mixed = state[index % 32]
            .wrapping_mul(weight ^ 0x5b)
            .wrapping_add(state[(index + 7) % 32]);
        state[index % 32] = state[index % 32].wrapping_add(mixed);
        answer.push(mixed);
    }
    answer
}

fn domain_hash(domain: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}
