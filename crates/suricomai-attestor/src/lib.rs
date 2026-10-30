// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Committee attestation for `SuriComAIEscrow`.
//!
//! An attestor checks a finished job with the envelope's auditor **and** a second,
//! independently written verifier. Only when both agree does it sign the EIP-712 message the
//! escrow contract accepts. The API has no way to sign without a second opinion.
//!
//! The digests here must match `contracts/test/Signatures.t.sol` byte for byte. The
//! reference values in the tests were computed with a separate tool.

#![forbid(unsafe_code)]

mod digest;
mod error;
mod signer;
mod verifier;

pub use digest::{
    domain_separator, job_id_for, settle_digest, slash_digest, Address, Domain, Fault,
    SettleFields, SlashFields,
};
pub use error::AttestError;
pub use signer::{assemble, recover, CommitteeSignature, CommitteeSigner};
pub use verifier::{AuditRequest, PythonVerifier, SecondVerifier};

use suricomai_envelope::{
    audit_proof, verify_receipt_signature, AuditTarget, EnvelopeError, JobVerification,
    MeasurementAllowlist, PromptContract, SealedResult,
};

/// Smallest amount the contract will settle, in the token's smallest unit.
pub const MIN_JOB_FEE: u128 = 100;

/// What the contract holds for one job, read from chain state and events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobOnChain {
    /// `keccak256(abi.encode(user, salt))`. Equals the wire contract's `job_id`.
    pub job_id: [u8; 32],
    /// BLAKE3 hash of the sealed job header that the user locked against.
    pub contract_hash: [u8; 32],
    /// The pinned worker address.
    pub worker: Address,
    /// Receipt key the worker recorded when it posted the bond.
    pub receipt_key: [u8; 32],
    /// Fee locked.
    pub cap: u128,
}

/// The worker the user pinned, taken from the assignment and never from the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assignment {
    /// Measurement (P2) or worker id (P0, P1) from the verified advertisement.
    pub executor_id: [u8; 32],
    /// Receipt key from the same advertisement.
    pub receipt_public: [u8; 32],
}

/// Signs outcomes after two verifiers agree.
pub struct Attestor<'a> {
    signer: CommitteeSigner,
    domain: Domain,
    second: &'a dyn SecondVerifier,
}

/// Everything the auditors need besides the job's on-chain record.
pub struct Evidence<'a> {
    /// Public contract from the sealed job header.
    pub contract: &'a PromptContract,
    /// The worker's sealed result, including the proof.
    pub result: &'a SealedResult,
    /// The pinned worker.
    pub assigned: Assignment,
    /// Measurements the network trusts for private jobs.
    pub allowlist: &'a MeasurementAllowlist,
    /// The attestor's own clock. It never comes from the proof.
    pub audit_now: u64,
}

impl<'a> Attestor<'a> {
    /// Build an attestor. `second` is required: there is no unchecked path.
    pub fn new(signer: CommitteeSigner, domain: Domain, second: &'a dyn SecondVerifier) -> Self {
        Self {
            signer,
            domain,
            second,
        }
    }

    /// This attestor's committee address.
    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// Sign a settlement for `amount_due` after both verifiers accept the proof.
    pub fn attest_settlement(
        &self,
        job: &JobOnChain,
        evidence: &Evidence<'_>,
        verification: JobVerification<'_>,
        amount_due: u128,
        relay_payee: Address,
    ) -> Result<CommitteeSignature, AttestError> {
        check_binding(job, evidence)?;
        if amount_due < MIN_JOB_FEE || amount_due > job.cap {
            return Err(AttestError::AmountOutOfRange);
        }
        let target = AuditTarget::new(
            evidence.assigned.executor_id,
            evidence.assigned.receipt_public,
        );
        audit_proof(
            evidence.contract,
            evidence.result,
            &target,
            evidence.allowlist,
            verification,
            evidence.audit_now,
        )
        .map_err(AttestError::Rejected)?;
        let second = self.second_opinion(evidence)?;
        if second != "ok" {
            return Err(AttestError::Disagreement {
                first: "ok".to_string(),
                second,
            });
        }
        let fields = SettleFields {
            job_id: job.job_id,
            contract_hash: job.contract_hash,
            worker: job.worker,
            receipt_key: job.receipt_key,
            amount_due,
            relay_payee,
        };
        self.signer.sign(&settle_digest(&self.domain, &fields))
    }

    /// Sign a slash when the worker itself signed a proof that fails for a fault the contract
    /// recognises, and both verifiers name the same fault.
    ///
    /// A proof that fails for any other reason, or whose signature does not verify under the
    /// pinned key, is not the worker's signed fault and is never slashed here.
    pub fn attest_slash(
        &self,
        job: &JobOnChain,
        evidence: &Evidence<'_>,
        verification: JobVerification<'_>,
    ) -> Result<(Fault, [u8; 32], CommitteeSignature), AttestError> {
        check_binding(job, evidence)?;
        verify_receipt_signature(evidence.result.proof()).map_err(AttestError::Rejected)?;
        let target = AuditTarget::new(
            evidence.assigned.executor_id,
            evidence.assigned.receipt_public,
        );
        let first = audit_proof(
            evidence.contract,
            evidence.result,
            &target,
            evidence.allowlist,
            verification,
            evidence.audit_now,
        );
        let Err(error) = first else {
            return Err(AttestError::NothingToSlash);
        };
        let fault = fault_for(error).ok_or(AttestError::NotASlashableFault(error))?;
        let second = self.second_opinion(evidence)?;
        if second != error.code() {
            return Err(AttestError::Disagreement {
                first: error.code().to_string(),
                second,
            });
        }
        let evidence_hash = digest::keccak256(&[&evidence
            .result
            .proof()
            .to_bytes()
            .map_err(AttestError::Rejected)?]);
        let fields = SlashFields {
            job_id: job.job_id,
            contract_hash: job.contract_hash,
            worker: job.worker,
            receipt_key: job.receipt_key,
            fault,
            evidence: evidence_hash,
        };
        let signature = self.signer.sign(&slash_digest(&self.domain, &fields))?;
        Ok((fault, evidence_hash, signature))
    }

    fn second_opinion(&self, evidence: &Evidence<'_>) -> Result<String, AttestError> {
        let request = AuditRequest {
            contract: evidence
                .contract
                .to_bytes()
                .map_err(AttestError::Rejected)?,
            result: evidence.result.to_bytes().map_err(AttestError::Rejected)?,
            allow: evidence.allowlist.iter().copied().collect(),
            private_tier: evidence.contract.tier == suricomai_envelope::Tier::P2,
            audit_now: evidence.audit_now,
            target_executor_id: evidence.assigned.executor_id,
            target_receipt_public: evidence.assigned.receipt_public,
        };
        self.second.verify(&request)
    }
}

/// Faults the contract recognises. Anything else is not a slash.
fn fault_for(error: EnvelopeError) -> Option<Fault> {
    match error {
        EnvelopeError::MeasurementRejected => Some(Fault::MeasurementRejected),
        EnvelopeError::MissingGpuEvidence => Some(Fault::MissingGpuEvidence),
        EnvelopeError::BadQuote => Some(Fault::BadQuote),
        _ => None,
    }
}

/// The wire contract, the proof, and the chain record must all describe the same job.
fn check_binding(job: &JobOnChain, evidence: &Evidence<'_>) -> Result<(), AttestError> {
    let proof = evidence.result.proof();
    if evidence.contract.job_id != job.job_id {
        return Err(AttestError::Binding("job id"));
    }
    if u128::from(evidence.contract.fee) != job.cap {
        return Err(AttestError::Binding("fee does not equal the locked cap"));
    }
    if proof.contract_hash != job.contract_hash {
        return Err(AttestError::Binding("contract hash"));
    }
    if proof.receipt_public != job.receipt_key {
        return Err(AttestError::Binding("receipt key recorded at bond"));
    }
    if evidence.assigned.receipt_public != job.receipt_key {
        return Err(AttestError::Binding(
            "assignment does not match the recorded key",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
