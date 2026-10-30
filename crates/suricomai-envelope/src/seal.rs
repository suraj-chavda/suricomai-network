// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Seal a prompt to an executor and open it only after the control checks pass.

use std::collections::BTreeMap;

use zeroize::{Zeroize, Zeroizing};

use crate::cbor::{self, Cbor};
use crate::commit::{commit_contract, commit_prompt};
use crate::error::EnvelopeError;
use crate::keys::{seal_to, EnclaveKeys};
use crate::log::AttemptLog;
use crate::quote::SealTarget;
use crate::replay::ReplayCache;
use crate::suite::{
    valid_size_class, INFO_JOB, MAX_CONTRACT_TTL_SECS, PARAMS_PAD, PROTOCOL_VERSION,
};
use crate::types::{bytes_at, digest_at, require_keys, MeasurementAllowlist, PromptContract, Tier};

/// Sampling rules sealed next to the prompt. These are control data, not the prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceParams {
    /// Seed the executor must use. Creative sampling stays inside the seal.
    pub seed: [u8; 32],
    /// Temperature times 1000. `0` is the deterministic setting. Maximum is 2000.
    pub temperature_millis: u64,
    /// Upper bound the runtime should honor, from 1 to 65536.
    pub max_tokens: u64,
}

impl InferenceParams {
    /// Build parameters or refuse values outside the schema.
    pub fn new(
        seed: [u8; 32],
        temperature_millis: u64,
        max_tokens: u64,
    ) -> Result<Self, EnvelopeError> {
        let params = Self {
            seed,
            temperature_millis,
            max_tokens,
        };
        validate_params(&params)?;
        Ok(params)
    }
}

/// A sealed job. The prompt is inside `enc_prompt` and is not a public field.
#[derive(Clone, Debug)]
pub struct SealedJob {
    contract: PromptContract,
    header_bytes: Vec<u8>,
    executor_id: [u8; 32],
    enc: Vec<u8>,
    enc_prompt: Vec<u8>,
    enc_params: Vec<u8>,
}

impl SealedJob {
    /// Public contract. This view has the commitment, not the prompt.
    pub fn contract(&self) -> &PromptContract {
        &self.contract
    }

    /// Executor the ciphertext was sealed to.
    pub fn executor_id(&self) -> [u8; 32] {
        self.executor_id
    }

    /// Canonical bytes a relay is allowed to carry.
    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::encode(&Cbor::Map(sealed_map(self)))
    }

    /// Decode the control plane. This does not decrypt the prompt.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let value = cbor::decode(bytes)?;
        let map = cbor::as_map(&value)?;
        require_keys(map, &[1, 2, 3, 4, 5, 6])?;
        if cbor::as_u64(map.get(&1).ok_or(EnvelopeError::Malformed)?)? != PROTOCOL_VERSION {
            return Err(EnvelopeError::BadVersion);
        }
        let header_bytes = bytes_at(map, 2, None)?.to_vec();
        let contract = PromptContract::from_bytes(&header_bytes)?;
        let job = Self {
            contract,
            header_bytes,
            executor_id: digest_at(map, 3)?,
            enc: bytes_at(map, 4, None)?.to_vec(),
            enc_prompt: bytes_at(map, 5, None)?.to_vec(),
            enc_params: bytes_at(map, 6, None)?.to_vec(),
        };
        if job.to_bytes() != bytes {
            return Err(EnvelopeError::NonCanonical);
        }
        Ok(job)
    }

    pub(crate) fn header_bytes(&self) -> &[u8] {
        &self.header_bytes
    }
}

/// Prompt and parameters after a successful open. The prompt is wiped on drop.
///
/// Debug output redacts the prompt.
pub struct OpenedJob {
    contract: PromptContract,
    header_bytes: Vec<u8>,
    executor_id: [u8; 32],
    prompt: Zeroizing<Vec<u8>>,
    params: InferenceParams,
}

impl std::fmt::Debug for OpenedJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedJob")
            .field("job_id", &self.contract.job_id)
            .field("prompt", &"redacted")
            .finish()
    }
}

impl OpenedJob {
    /// Contract that was bound into the seal.
    pub fn contract(&self) -> &PromptContract {
        &self.contract
    }

    /// Prompt bytes. Callers must not log this slice.
    pub fn prompt(&self) -> &[u8] {
        &self.prompt
    }

    /// Sampling parameters.
    pub fn params(&self) -> &InferenceParams {
        &self.params
    }

    pub(crate) fn header_bytes(&self) -> &[u8] {
        &self.header_bytes
    }

    pub(crate) fn executor_id(&self) -> [u8; 32] {
        self.executor_id
    }
}

/// Seal `prompt` to `target`. Fails before encryption if the commitment or tier does not match.
pub fn seal_job(
    contract: &PromptContract,
    prompt: &[u8],
    params: &InferenceParams,
    target: &SealTarget,
) -> Result<SealedJob, EnvelopeError> {
    contract.to_bytes()?;
    validate_params(params)?;
    target.matches_tier(contract.tier)?;
    if commit_prompt(prompt) != contract.prompt_commitment {
        return Err(EnvelopeError::CommitmentMismatch);
    }
    if prompt.len() + 4
        > usize::try_from(contract.size_class).map_err(|_| EnvelopeError::BadSize)?
    {
        return Err(EnvelopeError::PlaintextTooLarge);
    }
    let (executor_id, hpke_public, _) = target.identity();
    let header_bytes = contract.to_bytes()?;
    let aad = associated_data(&header_bytes, &executor_id);
    let padded_prompt = pad(prompt, contract.size_class as usize)?;
    let padded_params = pad(&encode_params(params)?, PARAMS_PAD)?;
    let (enc, mut cts) = seal_to(
        hpke_public,
        INFO_JOB,
        &aad,
        &[padded_prompt.as_slice(), padded_params.as_slice()],
    )?;
    let enc_params = cts.pop().ok_or(EnvelopeError::BadSeal)?;
    let enc_prompt = cts.pop().ok_or(EnvelopeError::BadSeal)?;
    Ok(SealedJob {
        contract: contract.clone(),
        header_bytes,
        executor_id,
        enc,
        enc_prompt,
        enc_params,
    })
}

/// Open a sealed job for this executor.
///
/// Structural checks happen before HPKE open. Replay insert runs only after open succeeds.
/// One log line is written. It contains the job id, size class, executor id, and a static code.
pub fn open_job(
    bytes: &[u8],
    keys: &EnclaveKeys,
    allowlist: &MeasurementAllowlist,
    now: u64,
    replay: &mut ReplayCache,
    log: &mut crate::log::HostLog,
) -> Result<OpenedJob, EnvelopeError> {
    let mut attempt = AttemptLog::new(log);
    let job = match SealedJob::from_bytes(bytes) {
        Ok(job) => job,
        Err(err) => return attempt.reject(err),
    };
    attempt.set_meta(
        job.contract.job_id,
        job.contract.size_class,
        job.executor_id,
    );

    if now >= job.contract.expiry {
        return attempt.reject(EnvelopeError::Expired);
    }
    if job.contract.expiry - now > MAX_CONTRACT_TTL_SECS {
        return attempt.reject(EnvelopeError::TtlTooLong);
    }
    if job.executor_id != keys.executor_id() {
        return attempt.reject(EnvelopeError::MeasurementRejected);
    }
    if job.contract.tier == Tier::P2 && !allowlist.contains(&job.executor_id) {
        return attempt.reject(EnvelopeError::MeasurementRejected);
    }
    if !valid_size_class(job.contract.size_class) {
        return attempt.reject(EnvelopeError::BadSize);
    }

    let aad = associated_data(&job.header_bytes, &job.executor_id);
    let mut plains = match keys.open_seals(
        &job.enc,
        INFO_JOB,
        &aad,
        &[job.enc_prompt.as_slice(), job.enc_params.as_slice()],
    ) {
        Ok(opened) => opened,
        Err(err) => return attempt.reject(err),
    };
    let Some(params_padded) = plains.pop() else {
        return attempt.reject(EnvelopeError::BadSeal);
    };
    let Some(prompt_padded) = plains.pop() else {
        return attempt.reject(EnvelopeError::BadSeal);
    };
    let prompt = match unpad(prompt_padded.to_vec()) {
        Ok(prompt) => prompt,
        Err(err) => return attempt.reject(err),
    };
    let params_bytes = match unpad(params_padded.to_vec()) {
        Ok(params) => params,
        Err(err) => return attempt.reject(err),
    };
    if commit_prompt(&prompt) != job.contract.prompt_commitment {
        return attempt.reject(EnvelopeError::CommitmentMismatch);
    }
    let params = match decode_params(&params_bytes) {
        Ok(params) => params,
        Err(err) => return attempt.reject(err),
    };
    if let Err(err) = replay.insert(
        job.contract.chain_id,
        job.contract.job_id,
        commit_contract(&job.header_bytes),
        job.contract.expiry,
        now,
    ) {
        return attempt.reject(err);
    }
    attempt.accept();
    Ok(OpenedJob {
        contract: job.contract,
        header_bytes: job.header_bytes,
        executor_id: job.executor_id,
        prompt,
        params,
    })
}

pub(crate) fn associated_data(header: &[u8], executor_id: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + 32);
    aad.extend_from_slice(header);
    aad.extend_from_slice(executor_id);
    aad
}

fn sealed_map(job: &SealedJob) -> BTreeMap<u64, Cbor> {
    let mut map = BTreeMap::new();
    map.insert(1, Cbor::UInt(PROTOCOL_VERSION));
    map.insert(2, Cbor::Bytes(job.header_bytes.clone()));
    map.insert(3, Cbor::Bytes(job.executor_id.to_vec()));
    map.insert(4, Cbor::Bytes(job.enc.clone()));
    map.insert(5, Cbor::Bytes(job.enc_prompt.clone()));
    map.insert(6, Cbor::Bytes(job.enc_params.clone()));
    map
}

fn encode_params(params: &InferenceParams) -> Result<Vec<u8>, EnvelopeError> {
    validate_params(params)?;
    let mut map = BTreeMap::new();
    map.insert(1, Cbor::Bytes(params.seed.to_vec()));
    map.insert(2, Cbor::UInt(params.temperature_millis));
    map.insert(3, Cbor::UInt(params.max_tokens));
    Ok(cbor::encode(&Cbor::Map(map)))
}

fn decode_params(bytes: &[u8]) -> Result<InferenceParams, EnvelopeError> {
    let value = cbor::decode(bytes).map_err(|_| EnvelopeError::BadParams)?;
    let map = cbor::as_map(&value).map_err(|_| EnvelopeError::BadParams)?;
    require_keys(map, &[1, 2, 3]).map_err(|err| match err {
        EnvelopeError::UnknownField => EnvelopeError::BadParams,
        other => other,
    })?;
    let seed_bytes = bytes_at(map, 1, Some(32)).map_err(|_| EnvelopeError::BadParams)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(seed_bytes);
    let params = InferenceParams {
        seed,
        temperature_millis: cbor::as_u64(map.get(&2).ok_or(EnvelopeError::BadParams)?)
            .map_err(|_| EnvelopeError::BadParams)?,
        max_tokens: cbor::as_u64(map.get(&3).ok_or(EnvelopeError::BadParams)?)
            .map_err(|_| EnvelopeError::BadParams)?,
    };
    validate_params(&params)?;
    Ok(params)
}

fn validate_params(params: &InferenceParams) -> Result<(), EnvelopeError> {
    if params.temperature_millis > 2000 || params.max_tokens == 0 || params.max_tokens > 65_536 {
        return Err(EnvelopeError::BadParams);
    }
    Ok(())
}

pub(crate) fn pad(bytes: &[u8], size: usize) -> Result<Vec<u8>, EnvelopeError> {
    if bytes.len() + 4 > size {
        return Err(EnvelopeError::PlaintextTooLarge);
    }
    let mut out = vec![0u8; size];
    let len = u32::try_from(bytes.len()).map_err(|_| EnvelopeError::PlaintextTooLarge)?;
    out[..4].copy_from_slice(&len.to_be_bytes());
    out[4..4 + bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

pub(crate) fn unpad(mut padded: Vec<u8>) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    let result = (|| {
        if padded.len() < 4 {
            return Err(EnvelopeError::BadSeal);
        }
        let len = u32::from_be_bytes(padded[..4].try_into().map_err(|_| EnvelopeError::BadSeal)?)
            as usize;
        if len > padded.len() - 4 {
            return Err(EnvelopeError::BadSeal);
        }
        if padded[4 + len..].iter().any(|byte| *byte != 0) {
            return Err(EnvelopeError::BadSeal);
        }
        Ok(Zeroizing::new(padded[4..4 + len].to_vec()))
    })();
    padded.zeroize();
    result
}
