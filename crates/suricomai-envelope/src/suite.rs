// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Pinned cryptographic suite for envelope version 1.
//!
//! KEM `0x647a` is MLKEM768-X25519 (X-Wing) from the HPKE post-quantum draft.
//! KDF `0x0011` is SHAKE256. AEAD `0x0003` is ChaCha20-Poly1305.

/// Wire version written into every control message.
pub const PROTOCOL_VERSION: u64 = 1;

/// Suite id carried in every contract header. Id 1 is X-Wing, SHAKE256, ChaCha20-Poly1305.
/// Ids are never reused. A new suite gets a new id and a spec entry with vectors.
pub const SUITE_ID: u64 = 1;

/// HPKE KEM id: MLKEM768-X25519.
pub const HPKE_KEM_ID: u16 = 0x647a;
/// HPKE KDF id: SHAKE256.
pub const HPKE_KDF_ID: u16 = 0x0011;
/// HPKE AEAD id: ChaCha20-Poly1305.
pub const HPKE_AEAD_ID: u16 = 0x0003;

/// X-Wing encapsulation key length (`Nek`).
pub const HPKE_PUBLIC_LEN: usize = 1216;
/// X-Wing ciphertext length (`Nct`).
pub const HPKE_ENC_LEN: usize = 1120;

/// BLAKE3 digest, Ed25519 public key, and id length.
pub const DIGEST_LEN: usize = 32;
/// Ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;

/// Version byte of an advertisement. Version 1 is retired.
pub const ADVERTISEMENT_VERSION: u64 = 2;

/// Longest an advertisement may claim to be valid, in seconds.
pub const MAX_ADVERTISEMENT_SECS: u64 = 86_400;

/// Furthest a contract expiry may sit past the executor's clock, in seconds.
/// Bounds how long a replay entry must be kept, and so how long a flood of paid
/// but unwanted jobs can occupy the cache.
pub const MAX_CONTRACT_TTL_SECS: u64 = 86_400;

/// How far two honest clocks may disagree, in seconds. Applied when a client checks an
/// advertisement window and when it checks a worker's receipt times.
pub const MAX_CLOCK_SKEW_SECS: u64 = 30;

/// Sampling-parameter plaintext is padded to this size before it is sealed.
pub const PARAMS_PAD: usize = 256;

/// Largest control message this decoder will accept.
pub(crate) const MAX_MESSAGE: usize = 8 * 1024 * 1024;

/// HPKE `info` for the sealed prompt and its sampling parameters.
pub(crate) const INFO_JOB: &[u8] = b"suricomai-seal-1";
/// HPKE `info` for the sealed answer.
pub(crate) const INFO_ANSWER: &[u8] = b"suricomai-answer-1";

/// True when `n` is a padding bucket the wire format allows.
pub fn valid_size_class(n: u64) -> bool {
    matches!(n, 4_096 | 16_384 | 65_536 | 262_144)
        || (n > 262_144 && n <= 4_194_304 && n.is_multiple_of(262_144))
}
