// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Control-plane structs. The prompt is not a field of any of them.

use std::collections::{BTreeMap, HashSet};

use crate::cbor::{self, Cbor};
use crate::error::EnvelopeError;
use crate::suite::{valid_size_class, DIGEST_LEN, HPKE_PUBLIC_LEN, PROTOCOL_VERSION, SUITE_ID};

/// Who is allowed to see the prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Tier {
    /// Public job. The prompt is not confidential.
    P0 = 0,
    /// Sealed in transit. The worker process sees the prompt. The user must opt in.
    P1 = 1,
    /// Sealed to a measured enclave. This is the private tier.
    P2 = 2,
}

impl Tier {
    pub(crate) fn from_u64(value: u64) -> Result<Self, EnvelopeError> {
        match value {
            0 => Ok(Self::P0),
            1 => Ok(Self::P1),
            2 => Ok(Self::P2),
            _ => Err(EnvelopeError::BadTier),
        }
    }

    pub(crate) const fn as_u64(self) -> u64 {
        self as u64
    }
}

/// Measurements a caller currently trusts for P2.
pub type MeasurementAllowlist = HashSet<[u8; DIGEST_LEN]>;

/// Public prompt contract. Wire format is a canonical CBOR map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptContract {
    /// 32 random bytes chosen by the user.
    pub job_id: [u8; DIGEST_LEN],
    /// Settlement chain this contract belongs to.
    pub chain_id: u64,
    /// Privacy tier. P2 is private. P1 and P0 are explicit.
    pub tier: Tier,
    /// Digest of the model manifest the executor must load.
    pub model_digest: [u8; DIGEST_LEN],
    /// [`crate::commit_prompt`] of the prompt that will be sealed.
    pub prompt_commitment: [u8; DIGEST_LEN],
    /// Maximum answer length, in bytes, before padding.
    pub max_output_bytes: u64,
    /// Padding bucket for the prompt and the answer.
    pub size_class: u64,
    /// Fee in the smallest SUR unit. The envelope does not move coins.
    pub fee: u64,
    /// Bond the executor must have posted. Not checked against a ledger here.
    pub bond_required: u64,
    /// Unix seconds. The executor rejects the job when `now >= expiry`.
    pub expiry: u64,
    /// Hash of the measurement policy the user required.
    pub privacy_policy_id: [u8; DIGEST_LEN],
    /// One-time key the settlement layer will refund to.
    pub user_pay_key: [u8; DIGEST_LEN],
    /// User's X-Wing public key. The answer is sealed to this key.
    pub user_hpke_public: Vec<u8>,
    /// Minimum executor stake the user is willing to accept.
    pub min_stake: u64,
    /// Minimum canary score, in parts per thousand (0..=1000).
    pub min_canary_ppt: u64,
    /// Maximum latency hint. Zero means the user did not set one.
    pub max_latency_ms: u64,
    /// P2 job whose model runs on a GPU and therefore needs GPU evidence.
    pub needs_gpu: bool,
    /// Opaque region hint, at most 64 bytes. The envelope does not interpret it.
    pub region: Vec<u8>,
}

impl PromptContract {
    /// Set `prompt_commitment` to the commitment of `prompt`.
    pub fn bind_prompt(&mut self, prompt: &[u8]) {
        self.prompt_commitment = crate::commit_prompt(prompt);
    }

    /// Canonical bytes. This encoding is the HPKE associated data's first half.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        validate_contract(self)?;
        Ok(cbor::encode(&Cbor::Map(contract_map(self))))
    }

    /// Decode and require the canonical encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let value = cbor::decode(bytes)?;
        let contract = contract_from_map(cbor::as_map(&value)?)?;
        if contract.to_bytes()? != bytes {
            return Err(EnvelopeError::NonCanonical);
        }
        Ok(contract)
    }
}

pub(crate) fn validate_contract(contract: &PromptContract) -> Result<(), EnvelopeError> {
    if contract.user_hpke_public.len() != HPKE_PUBLIC_LEN {
        return Err(EnvelopeError::BadLength);
    }
    if !valid_size_class(contract.size_class) {
        return Err(EnvelopeError::BadSize);
    }
    if contract.max_output_bytes == 0 || contract.max_output_bytes > contract.size_class - 4 {
        return Err(EnvelopeError::PlaintextTooLarge);
    }
    if contract.min_canary_ppt > 1000 {
        return Err(EnvelopeError::Malformed);
    }
    if contract.region.len() > 64 {
        return Err(EnvelopeError::BadLength);
    }
    if contract.needs_gpu && contract.tier != Tier::P2 {
        return Err(EnvelopeError::UnexpectedGpuEvidence);
    }
    Ok(())
}

fn contract_map(contract: &PromptContract) -> BTreeMap<u64, Cbor> {
    let mut map = BTreeMap::new();
    map.insert(1, Cbor::UInt(PROTOCOL_VERSION));
    map.insert(2, Cbor::Bytes(contract.job_id.to_vec()));
    map.insert(3, Cbor::UInt(contract.chain_id));
    map.insert(4, Cbor::UInt(contract.tier.as_u64()));
    map.insert(5, Cbor::Bytes(contract.model_digest.to_vec()));
    map.insert(6, Cbor::Bytes(contract.prompt_commitment.to_vec()));
    map.insert(7, Cbor::UInt(contract.max_output_bytes));
    map.insert(8, Cbor::UInt(contract.size_class));
    map.insert(9, Cbor::UInt(contract.fee));
    map.insert(10, Cbor::UInt(contract.bond_required));
    map.insert(11, Cbor::UInt(contract.expiry));
    map.insert(12, Cbor::Bytes(contract.privacy_policy_id.to_vec()));
    map.insert(13, Cbor::Bytes(contract.user_pay_key.to_vec()));
    map.insert(14, Cbor::Bytes(contract.user_hpke_public.clone()));
    map.insert(15, Cbor::UInt(contract.min_stake));
    map.insert(16, Cbor::UInt(contract.min_canary_ppt));
    map.insert(17, Cbor::UInt(contract.max_latency_ms));
    map.insert(18, Cbor::UInt(u64::from(contract.needs_gpu)));
    map.insert(19, Cbor::Bytes(contract.region.clone()));
    map.insert(20, Cbor::UInt(SUITE_ID));
    map
}

fn contract_from_map(map: &BTreeMap<u64, Cbor>) -> Result<PromptContract, EnvelopeError> {
    require_keys(
        map,
        &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ],
    )?;
    if cbor::as_u64(req(map, 1)?)? != PROTOCOL_VERSION {
        return Err(EnvelopeError::BadVersion);
    }
    if cbor::as_u64(req(map, 20)?)? != SUITE_ID {
        return Err(EnvelopeError::BadSuite);
    }
    let contract = PromptContract {
        job_id: digest_at(map, 2)?,
        chain_id: cbor::as_u64(req(map, 3)?)?,
        tier: Tier::from_u64(cbor::as_u64(req(map, 4)?)?)?,
        model_digest: digest_at(map, 5)?,
        prompt_commitment: digest_at(map, 6)?,
        max_output_bytes: cbor::as_u64(req(map, 7)?)?,
        size_class: cbor::as_u64(req(map, 8)?)?,
        fee: cbor::as_u64(req(map, 9)?)?,
        bond_required: cbor::as_u64(req(map, 10)?)?,
        expiry: cbor::as_u64(req(map, 11)?)?,
        privacy_policy_id: digest_at(map, 12)?,
        user_pay_key: digest_at(map, 13)?,
        user_hpke_public: bytes_at(map, 14, Some(HPKE_PUBLIC_LEN))?.to_vec(),
        min_stake: cbor::as_u64(req(map, 15)?)?,
        min_canary_ppt: cbor::as_u64(req(map, 16)?)?,
        max_latency_ms: cbor::as_u64(req(map, 17)?)?,
        needs_gpu: match cbor::as_u64(req(map, 18)?)? {
            0 => false,
            1 => true,
            _ => return Err(EnvelopeError::Malformed),
        },
        region: bytes_at(map, 19, None)?.to_vec(),
    };
    validate_contract(&contract)?;
    Ok(contract)
}

pub(crate) fn require_keys(
    map: &BTreeMap<u64, Cbor>,
    allowed: &[u64],
) -> Result<(), EnvelopeError> {
    if map.keys().any(|key| !allowed.contains(key)) {
        return Err(EnvelopeError::UnknownField);
    }
    if allowed.iter().any(|key| !map.contains_key(key)) {
        return Err(EnvelopeError::Malformed);
    }
    Ok(())
}

pub(crate) fn require_keys_allow_optional(
    map: &BTreeMap<u64, Cbor>,
    required: &[u64],
    optional: &[u64],
) -> Result<(), EnvelopeError> {
    if map
        .keys()
        .any(|key| !required.contains(key) && !optional.contains(key))
    {
        return Err(EnvelopeError::UnknownField);
    }
    if required.iter().any(|key| !map.contains_key(key)) {
        return Err(EnvelopeError::Malformed);
    }
    Ok(())
}

pub(crate) fn req(map: &BTreeMap<u64, Cbor>, key: u64) -> Result<&Cbor, EnvelopeError> {
    map.get(&key).ok_or(EnvelopeError::Malformed)
}

pub(crate) fn digest_at(
    map: &BTreeMap<u64, Cbor>,
    key: u64,
) -> Result<[u8; DIGEST_LEN], EnvelopeError> {
    let bytes = bytes_at(map, key, Some(DIGEST_LEN))?;
    let mut out = [0u8; DIGEST_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

pub(crate) fn bytes_at(
    map: &BTreeMap<u64, Cbor>,
    key: u64,
    len: Option<usize>,
) -> Result<&[u8], EnvelopeError> {
    let bytes = cbor::as_bytes(req(map, key)?)?;
    if len.is_some_and(|expected| bytes.len() != expected) {
        return Err(EnvelopeError::BadLength);
    }
    Ok(bytes)
}
