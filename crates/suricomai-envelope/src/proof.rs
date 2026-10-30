// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Proof bundles and sealed answers.
//!
//! The bundle is what an auditor can re-check. It holds commitments, a quote, and a
//! receipt signature. It does not hold the prompt or the answer.

use std::collections::BTreeMap;

use ed25519_dalek::Signature;
use zeroize::Zeroizing;

use crate::cbor::{self, Cbor};
use crate::commit::{
    commit_answer_ciphertext, commit_contract, job_report, token_bucket, JobReportFields,
};
use crate::error::EnvelopeError;
use crate::keys::{seal_to, verifying_key, EnclaveKeys, UserKeys};
use crate::log::{AttemptLog, HostLog};
use crate::quote::{QuoteAttester, QuoteVerifier, SealTarget};
use crate::seal::{associated_data, pad, unpad, OpenedJob, SealedJob};
use crate::suite::{
    DIGEST_LEN, HPKE_ENC_LEN, HPKE_PUBLIC_LEN, INFO_ANSWER, PROTOCOL_VERSION, SIGNATURE_LEN,
};
use crate::types::{
    bytes_at, digest_at, require_keys_allow_optional, MeasurementAllowlist, PromptContract, Tier,
};

const RECEIPT_DOMAIN: &[u8] = b"suricomai.receipt.v1\0";

/// How a finished P2 job gets its quote. P0 and P1 must use [`NotRequired`](JobAttestation::NotRequired).
pub enum JobAttestation<'a> {
    /// No hardware quote. Required for P0 and P1.
    NotRequired,
    /// Attester that binds the job report. Required for P2.
    Quote(&'a dyn QuoteAttester),
}

/// How the user checks a returned proof.
pub enum JobVerification<'a> {
    /// Receipt signature only. Required for P0 and P1.
    SignatureOnly,
    /// Receipt signature plus a quote check. Required for P2.
    Quote(&'a dyn QuoteVerifier),
}

/// Public proof. Safe to put on a settlement chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofBundle {
    /// Job this proof closes.
    pub job_id: [u8; DIGEST_LEN],
    /// Tier copied from the contract.
    pub tier: Tier,
    /// Commitment the executor opened.
    pub prompt_commitment: [u8; DIGEST_LEN],
    /// Hash of the answer's HPKE encapsulation and ciphertext.
    pub answer_ciphertext_hash: [u8; DIGEST_LEN],
    /// Model the receipt claims to have run.
    pub model_digest: [u8; DIGEST_LEN],
    /// Measurement or worker id.
    pub executor_id: [u8; DIGEST_LEN],
    /// Present only for GPU P2 jobs.
    pub gpu_evidence: Option<[u8; DIGEST_LEN]>,
    /// Padded token count. Not the exact count.
    pub token_bucket: u64,
    /// Vendor or lab quote. Empty for P0 and P1.
    pub quote: Vec<u8>,
    /// Hash bound into `quote`.
    pub report_data: [u8; DIGEST_LEN],
    /// Ed25519 signature over the proof with this field removed.
    pub receipt_sig: [u8; SIGNATURE_LEN],
    /// VRF output. It is carried in the bundle and must be all zero until assignment proofs are verified.
    pub assignment_vrf: [u8; DIGEST_LEN],
    /// One-time payout key.
    pub worker_stealth_key: [u8; DIGEST_LEN],
    /// Unix seconds when execution started.
    pub started_at: u64,
    /// Unix seconds when the receipt was signed.
    pub finished_at: u64,
    /// HPKE key of the executor that sealed the answer path's peer.
    pub enclave_hpke_public: Vec<u8>,
    /// Nonce inside `report_data`.
    pub quote_nonce: [u8; DIGEST_LEN],
    /// Receipt key. The signature must verify under this key.
    pub receipt_public: [u8; DIGEST_LEN],
    /// Hash of the canonical contract this proof closes.
    pub contract_hash: [u8; DIGEST_LEN],
}

/// The worker an auditor expects, taken from the assignment and never from the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditTarget {
    /// Measurement (P2) or worker id (P0, P1).
    pub executor_id: [u8; DIGEST_LEN],
    /// Receipt key the worker registered.
    pub receipt_public: [u8; DIGEST_LEN],
}

impl AuditTarget {
    /// Build a target from the assigned worker's ids.
    pub fn new(executor_id: [u8; DIGEST_LEN], receipt_public: [u8; DIGEST_LEN]) -> Self {
        Self {
            executor_id,
            receipt_public,
        }
    }
}

impl ProofBundle {
    /// Canonical CBOR.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        Ok(cbor::encode(&Cbor::Map(proof_map(self, true)?)))
    }

    /// Decode a canonical proof.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let value = cbor::decode(bytes)?;
        let proof = proof_from_map(cbor::as_map(&value)?)?;
        if proof.to_bytes()? != bytes {
            return Err(EnvelopeError::NonCanonical);
        }
        Ok(proof)
    }
}

/// Answer ciphertext plus the proof. The answer plaintext is not a field.
#[derive(Clone, Debug)]
pub struct SealedResult {
    job_id: [u8; DIGEST_LEN],
    enc: Vec<u8>,
    enc_answer: Vec<u8>,
    proof: ProofBundle,
}

impl SealedResult {
    /// Job id bound into the result.
    pub fn job_id(&self) -> [u8; DIGEST_LEN] {
        self.job_id
    }

    /// Proof an auditor can verify without the answer.
    pub fn proof(&self) -> &ProofBundle {
        &self.proof
    }

    /// Canonical bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        let mut map = BTreeMap::new();
        map.insert(1, Cbor::UInt(PROTOCOL_VERSION));
        map.insert(2, Cbor::Bytes(self.job_id.to_vec()));
        map.insert(3, Cbor::Bytes(self.enc.clone()));
        map.insert(4, Cbor::Bytes(self.enc_answer.clone()));
        map.insert(5, Cbor::Bytes(self.proof.to_bytes()?));
        Ok(cbor::encode(&Cbor::Map(map)))
    }

    /// Decode a canonical result. This does not decrypt the answer.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let value = cbor::decode(bytes)?;
        let map = cbor::as_map(&value)?;
        crate::types::require_keys(map, &[1, 2, 3, 4, 5])?;
        if cbor::as_u64(map.get(&1).ok_or(EnvelopeError::Malformed)?)? != PROTOCOL_VERSION {
            return Err(EnvelopeError::BadVersion);
        }
        let result = Self {
            job_id: digest_at(map, 2)?,
            enc: bytes_at(map, 3, Some(HPKE_ENC_LEN))?.to_vec(),
            enc_answer: bytes_at(map, 4, None)?.to_vec(),
            proof: ProofBundle::from_bytes(bytes_at(map, 5, None)?)?,
        };
        if result.to_bytes()? != bytes {
            return Err(EnvelopeError::NonCanonical);
        }
        Ok(result)
    }
}

/// Seal `answer` to the user and attach a proof.
#[allow(clippy::too_many_arguments)]
pub fn finish_job(
    opened: &OpenedJob,
    answer: &[u8],
    token_count: u64,
    quote_nonce: [u8; DIGEST_LEN],
    assignment_vrf: [u8; DIGEST_LEN],
    worker_stealth_key: [u8; DIGEST_LEN],
    started_at: u64,
    finished_at: u64,
    gpu_evidence: Option<[u8; DIGEST_LEN]>,
    keys: &EnclaveKeys,
    attestation: JobAttestation<'_>,
) -> Result<SealedResult, EnvelopeError> {
    if keys.executor_id() != opened.executor_id() {
        return Err(EnvelopeError::MeasurementRejected);
    }
    if finished_at < started_at {
        return Err(EnvelopeError::Malformed);
    }
    if answer.len() as u64 > opened.contract().max_output_bytes {
        return Err(EnvelopeError::PlaintextTooLarge);
    }
    let gpu_evidence = normalize_gpu(
        opened.contract().tier,
        opened.contract().needs_gpu,
        gpu_evidence,
    )?;
    match (&attestation, opened.contract().tier) {
        (JobAttestation::Quote(_), Tier::P2) => {}
        (JobAttestation::NotRequired, Tier::P0 | Tier::P1) => {}
        (JobAttestation::NotRequired, Tier::P2) => return Err(EnvelopeError::BadQuote),
        (JobAttestation::Quote(_), Tier::P0 | Tier::P1) => return Err(EnvelopeError::BadQuote),
    }

    let bucket = token_bucket(token_count)?;
    let aad = associated_data(opened.header_bytes(), &opened.executor_id());
    let padded = pad(answer, opened.contract().size_class as usize)?;
    let (enc, mut cts) = seal_to(
        &opened.contract().user_hpke_public,
        INFO_ANSWER,
        &aad,
        &[padded.as_slice()],
    )?;
    let enc_answer = cts.pop().ok_or(EnvelopeError::BadSeal)?;
    let answer_ciphertext_hash = commit_answer_ciphertext(&enc, &enc_answer);
    let contract_hash = commit_contract(opened.header_bytes());
    let report_data = job_report(&JobReportFields {
        job_id: &opened.contract().job_id,
        prompt_commitment: &opened.contract().prompt_commitment,
        answer_ciphertext_hash: &answer_ciphertext_hash,
        model_digest: &opened.contract().model_digest,
        executor_id: &opened.executor_id(),
        receipt_public: &keys.receipt_public(),
        hpke_public: keys.hpke_public(),
        quote_nonce: &quote_nonce,
        gpu_evidence,
        contract_hash: &contract_hash,
    });
    let quote = match attestation {
        JobAttestation::Quote(attester) => attester.attest(&opened.executor_id(), &report_data)?,
        JobAttestation::NotRequired => Vec::new(),
    };
    if opened.contract().tier == Tier::P2 && quote.is_empty() {
        return Err(EnvelopeError::BadQuote);
    }

    let mut proof = ProofBundle {
        job_id: opened.contract().job_id,
        tier: opened.contract().tier,
        prompt_commitment: opened.contract().prompt_commitment,
        answer_ciphertext_hash,
        model_digest: opened.contract().model_digest,
        executor_id: opened.executor_id(),
        gpu_evidence,
        token_bucket: bucket,
        quote,
        report_data,
        receipt_sig: [0; SIGNATURE_LEN],
        assignment_vrf,
        worker_stealth_key,
        started_at,
        finished_at,
        enclave_hpke_public: keys.hpke_public().to_vec(),
        quote_nonce,
        receipt_public: keys.receipt_public(),
        contract_hash,
    };
    let message = receipt_message(&proof)?;
    proof.receipt_sig = keys.sign_receipt(&message);
    Ok(SealedResult {
        job_id: opened.contract().job_id,
        enc,
        enc_answer,
        proof,
    })
}

/// Check a proof without decrypting the answer.
///
/// A validator calls this with the public contract and the sealed result. The
/// prompt and the answer stay sealed.
pub fn audit_proof(
    contract: &PromptContract,
    result: &SealedResult,
    target: &AuditTarget,
    allowlist: &MeasurementAllowlist,
    verification: JobVerification<'_>,
    audit_now: u64,
) -> Result<(), EnvelopeError> {
    let proof = &result.proof;
    if proof.executor_id != target.executor_id || proof.receipt_public != target.receipt_public {
        return Err(EnvelopeError::IdentityMismatch);
    }
    verify_bundle(contract, result, allowlist, verification, audit_now)
}

/// Check the proof, then decrypt the answer.
///
/// Identity, hash, signature, and quote failures return before HPKE open.
#[allow(clippy::too_many_arguments)] // fail-closed checks are explicit parameters, not a config blob
pub fn open_answer(
    job: &SealedJob,
    result_bytes: &[u8],
    user: &UserKeys,
    expected: &SealTarget,
    allowlist: &MeasurementAllowlist,
    verification: JobVerification<'_>,
    audit_now: u64,
    log: &mut HostLog,
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    let mut attempt = AttemptLog::new(log);
    attempt.set_meta(
        job.contract().job_id,
        job.contract().size_class,
        job.executor_id(),
    );
    let result = match SealedResult::from_bytes(result_bytes) {
        Ok(result) => result,
        Err(err) => return attempt.reject(err),
    };
    if let Err(err) = check_proof(
        job,
        &result,
        user,
        expected,
        allowlist,
        verification,
        audit_now,
    ) {
        return attempt.reject(err);
    }
    let aad = associated_data(job.header_bytes(), &job.executor_id());
    let mut plains = match user.open_seals(
        &result.enc,
        INFO_ANSWER,
        &aad,
        &[result.enc_answer.as_slice()],
    ) {
        Ok(plains) => plains,
        Err(err) => return attempt.reject(err),
    };
    let Some(padded) = plains.pop() else {
        return attempt.reject(EnvelopeError::BadSeal);
    };
    let answer = match unpad(padded.to_vec()) {
        Ok(answer) => answer,
        Err(err) => return attempt.reject(err),
    };
    if answer.len() as u64 > job.contract().max_output_bytes {
        return attempt.reject(EnvelopeError::PlaintextTooLarge);
    }
    attempt.accept();
    Ok(answer)
}

fn check_proof(
    job: &SealedJob,
    result: &SealedResult,
    user: &UserKeys,
    expected: &SealTarget,
    allowlist: &MeasurementAllowlist,
    verification: JobVerification<'_>,
    audit_now: u64,
) -> Result<(), EnvelopeError> {
    let contract = job.contract();
    let proof = &result.proof;
    if user.hpke_public() != contract.user_hpke_public.as_slice() {
        return Err(EnvelopeError::KeyMismatch);
    }
    if result.job_id != contract.job_id
        || proof.job_id != contract.job_id
        || proof.tier != contract.tier
        || proof.prompt_commitment != contract.prompt_commitment
        || proof.model_digest != contract.model_digest
        || proof.executor_id != job.executor_id()
    {
        return Err(EnvelopeError::IdentityMismatch);
    }
    expected.matches_tier(contract.tier)?;
    let (executor_id, hpke_public, receipt_public) = expected.identity();
    if proof.executor_id != executor_id
        || proof.enclave_hpke_public.as_slice() != hpke_public
        || proof.receipt_public != receipt_public
    {
        return Err(EnvelopeError::IdentityMismatch);
    }
    verify_bundle(contract, result, allowlist, verification, audit_now)?;
    Ok(())
}

fn verify_bundle(
    contract: &PromptContract,
    result: &SealedResult,
    allowlist: &MeasurementAllowlist,
    verification: JobVerification<'_>,
    audit_now: u64,
) -> Result<(), EnvelopeError> {
    let proof = &result.proof;
    if contract.needs_gpu {
        return Err(EnvelopeError::MissingGpuEvidence);
    }
    if proof.assignment_vrf != [0u8; 32] {
        return Err(EnvelopeError::BadAssignmentVrf);
    }
    verify_proof_timestamps(contract, proof, audit_now)?;
    if result.job_id != contract.job_id
        || proof.job_id != contract.job_id
        || proof.tier != contract.tier
        || proof.prompt_commitment != contract.prompt_commitment
        || proof.model_digest != contract.model_digest
    {
        return Err(EnvelopeError::IdentityMismatch);
    }
    if proof.contract_hash != commit_contract(&contract.to_bytes()?) {
        return Err(EnvelopeError::IdentityMismatch);
    }
    if contract.tier == Tier::P2 && !allowlist.contains(&proof.executor_id) {
        return Err(EnvelopeError::MeasurementRejected);
    }
    normalize_gpu(contract.tier, contract.needs_gpu, proof.gpu_evidence)?;
    if contract.tier == Tier::P2 && proof.quote.is_empty() {
        return Err(EnvelopeError::BadQuote);
    }
    if contract.tier != Tier::P2 && !proof.quote.is_empty() {
        return Err(EnvelopeError::BadQuote);
    }
    let answer_hash = commit_answer_ciphertext(&result.enc, &result.enc_answer);
    if answer_hash != proof.answer_ciphertext_hash {
        return Err(EnvelopeError::AnswerHashMismatch);
    }
    let report = job_report(&JobReportFields {
        job_id: &proof.job_id,
        prompt_commitment: &proof.prompt_commitment,
        answer_ciphertext_hash: &proof.answer_ciphertext_hash,
        model_digest: &proof.model_digest,
        executor_id: &proof.executor_id,
        receipt_public: &proof.receipt_public,
        hpke_public: &proof.enclave_hpke_public,
        quote_nonce: &proof.quote_nonce,
        gpu_evidence: proof.gpu_evidence,
        contract_hash: &proof.contract_hash,
    });
    if report != proof.report_data {
        return Err(EnvelopeError::BadReportData);
    }
    let message = receipt_message(proof)?;
    let verifying = verifying_key(&proof.receipt_public)?;
    let signature =
        Signature::from_slice(&proof.receipt_sig).map_err(|_| EnvelopeError::BadSignature)?;
    verifying
        .verify_strict(&message, &signature)
        .map_err(|_| EnvelopeError::BadSignature)?;
    match (contract.tier, verification) {
        (Tier::P2, JobVerification::Quote(verifier)) => {
            verifier.verify_quote(&proof.executor_id, &proof.report_data, &proof.quote)?;
        }
        (Tier::P0 | Tier::P1, JobVerification::SignatureOnly) => {}
        (Tier::P2, JobVerification::SignatureOnly) => return Err(EnvelopeError::BadQuote),
        (Tier::P0 | Tier::P1, JobVerification::Quote(_)) => return Err(EnvelopeError::BadQuote),
    }
    Ok(())
}

/// Check only the receipt signature, under the key the proof carries.
///
/// A valid result proves the key holder signed these bytes. It says nothing about whether
/// the contents are acceptable. A settlement layer uses it to tell a worker's own signed
/// fault from a forgery by someone else.
pub fn verify_receipt_signature(proof: &ProofBundle) -> Result<(), EnvelopeError> {
    let message = receipt_message(proof)?;
    let verifying = verifying_key(&proof.receipt_public)?;
    let signature =
        Signature::from_slice(&proof.receipt_sig).map_err(|_| EnvelopeError::BadSignature)?;
    verifying
        .verify_strict(&message, &signature)
        .map_err(|_| EnvelopeError::BadSignature)
}

fn verify_proof_timestamps(
    contract: &PromptContract,
    proof: &ProofBundle,
    audit_now: u64,
) -> Result<(), EnvelopeError> {
    if proof.finished_at < proof.started_at {
        return Err(EnvelopeError::Malformed);
    }
    if proof.started_at >= contract.expiry || proof.finished_at >= contract.expiry {
        return Err(EnvelopeError::ProofExpired);
    }
    if audit_now >= contract.expiry {
        return Err(EnvelopeError::ProofExpired);
    }
    if proof.finished_at > audit_now || proof.started_at > audit_now {
        return Err(EnvelopeError::ProofExpired);
    }
    Ok(())
}

fn normalize_gpu(
    tier: Tier,
    needs_gpu: bool,
    gpu_evidence: Option<[u8; DIGEST_LEN]>,
) -> Result<Option<[u8; DIGEST_LEN]>, EnvelopeError> {
    match (tier == Tier::P2 && needs_gpu, gpu_evidence) {
        (true, Some(digest)) if digest.iter().any(|byte| *byte != 0) => Ok(Some(digest)),
        (true, _) => Err(EnvelopeError::MissingGpuEvidence),
        (false, Some(_)) => Err(EnvelopeError::UnexpectedGpuEvidence),
        (false, None) => Ok(None),
    }
}

fn receipt_message(proof: &ProofBundle) -> Result<Vec<u8>, EnvelopeError> {
    let mut message = Vec::from(RECEIPT_DOMAIN);
    message.extend(cbor::encode(&Cbor::Map(proof_map(proof, false)?)));
    Ok(message)
}

fn proof_map(proof: &ProofBundle, include_sig: bool) -> Result<BTreeMap<u64, Cbor>, EnvelopeError> {
    if proof.enclave_hpke_public.len() != HPKE_PUBLIC_LEN {
        return Err(EnvelopeError::BadLength);
    }
    if proof.finished_at < proof.started_at {
        return Err(EnvelopeError::Malformed);
    }
    let mut map = BTreeMap::new();
    map.insert(1, Cbor::UInt(PROTOCOL_VERSION));
    map.insert(2, Cbor::Bytes(proof.job_id.to_vec()));
    map.insert(3, Cbor::UInt(proof.tier as u64));
    map.insert(4, Cbor::Bytes(proof.prompt_commitment.to_vec()));
    map.insert(5, Cbor::Bytes(proof.answer_ciphertext_hash.to_vec()));
    map.insert(6, Cbor::Bytes(proof.model_digest.to_vec()));
    map.insert(7, Cbor::Bytes(proof.executor_id.to_vec()));
    if let Some(gpu) = proof.gpu_evidence {
        if gpu.iter().all(|byte| *byte == 0) {
            return Err(EnvelopeError::MissingGpuEvidence);
        }
        map.insert(8, Cbor::Bytes(gpu.to_vec()));
    }
    map.insert(9, Cbor::UInt(proof.token_bucket));
    map.insert(10, Cbor::Bytes(proof.quote.clone()));
    map.insert(11, Cbor::Bytes(proof.report_data.to_vec()));
    if include_sig {
        map.insert(12, Cbor::Bytes(proof.receipt_sig.to_vec()));
    }
    map.insert(13, Cbor::Bytes(proof.assignment_vrf.to_vec()));
    map.insert(14, Cbor::Bytes(proof.worker_stealth_key.to_vec()));
    map.insert(15, Cbor::UInt(proof.started_at));
    map.insert(16, Cbor::UInt(proof.finished_at));
    map.insert(17, Cbor::Bytes(proof.enclave_hpke_public.clone()));
    map.insert(18, Cbor::Bytes(proof.quote_nonce.to_vec()));
    map.insert(19, Cbor::Bytes(proof.receipt_public.to_vec()));
    map.insert(20, Cbor::Bytes(proof.contract_hash.to_vec()));
    Ok(map)
}

fn valid_bucket(count: u64) -> Result<u64, EnvelopeError> {
    match token_bucket(count) {
        Ok(bucket) if bucket == count => Ok(count),
        _ => Err(EnvelopeError::Malformed),
    }
}

fn proof_from_map(map: &BTreeMap<u64, Cbor>) -> Result<ProofBundle, EnvelopeError> {
    require_keys_allow_optional(
        map,
        &[
            1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ],
        &[8],
    )?;
    if cbor::as_u64(map.get(&1).ok_or(EnvelopeError::Malformed)?)? != PROTOCOL_VERSION {
        return Err(EnvelopeError::BadVersion);
    }
    let sig = bytes_at(map, 12, Some(SIGNATURE_LEN))?;
    let mut receipt_sig = [0u8; SIGNATURE_LEN];
    receipt_sig.copy_from_slice(sig);
    let gpu_evidence = if let Some(value) = map.get(&8) {
        let bytes = cbor::as_bytes(value)?;
        if bytes.len() != DIGEST_LEN {
            return Err(EnvelopeError::BadLength);
        }
        let mut digest = [0u8; DIGEST_LEN];
        digest.copy_from_slice(bytes);
        if digest.iter().all(|byte| *byte == 0) {
            return Err(EnvelopeError::MissingGpuEvidence);
        }
        Some(digest)
    } else {
        None
    };
    Ok(ProofBundle {
        job_id: digest_at(map, 2)?,
        tier: Tier::from_u64(cbor::as_u64(map.get(&3).ok_or(EnvelopeError::Malformed)?)?)?,
        prompt_commitment: digest_at(map, 4)?,
        answer_ciphertext_hash: digest_at(map, 5)?,
        model_digest: digest_at(map, 6)?,
        executor_id: digest_at(map, 7)?,
        gpu_evidence,
        token_bucket: valid_bucket(cbor::as_u64(map.get(&9).ok_or(EnvelopeError::Malformed)?)?)?,
        quote: bytes_at(map, 10, None)?.to_vec(),
        report_data: digest_at(map, 11)?,
        receipt_sig,
        assignment_vrf: digest_at(map, 13)?,
        worker_stealth_key: digest_at(map, 14)?,
        started_at: cbor::as_u64(map.get(&15).ok_or(EnvelopeError::Malformed)?)?,
        finished_at: cbor::as_u64(map.get(&16).ok_or(EnvelopeError::Malformed)?)?,
        enclave_hpke_public: bytes_at(map, 17, Some(HPKE_PUBLIC_LEN))?.to_vec(),
        quote_nonce: digest_at(map, 18)?,
        receipt_public: digest_at(map, 19)?,
        contract_hash: digest_at(map, 20)?,
    })
}
