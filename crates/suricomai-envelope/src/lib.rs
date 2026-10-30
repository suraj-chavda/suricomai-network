// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! SuriComAI **network envelope**: wire cryptography for sealed jobs and proofs.
//!
//! Users seal prompts to executor keys; executors open only after fail-closed
//! checks; answers return sealed with proof bundles validators audit without
//! decrypting conversation text.
//!
//! Does not run models or mint SUR. Mainnet P2 requires a vendor quote verifier;
//! The software quote exists only with the `lab` feature and is never a hardware root.
//!
//! Wire layout, suite ids, and fail-closed order are defined in the implementation and `vectors/`.

#![forbid(unsafe_code)]

mod cbor;
mod commit;
mod error;
mod keys;
#[cfg(feature = "lab")]
mod lab_quote;
mod log;
mod manifest;
mod proof;
mod quote;
mod replay;
mod seal;
mod suite;
mod types;

pub use commit::{commit_prompt, token_bucket};
pub use error::EnvelopeError;
pub use keys::{EnclaveKeys, UserKeys};
#[cfg(feature = "lab")]
pub use lab_quote::{LabAttester, LabVerifier};
pub use log::HostLog;
pub use manifest::{
    ApprovalStatus, ModelApproval, ModelCatalog, ModelEntry, ModelManifest, ModelStanding,
};
pub use proof::{
    audit_proof, finish_job, open_answer, verify_receipt_signature, AuditTarget, JobAttestation,
    JobVerification, ProofBundle, SealedResult,
};
pub use quote::{
    advertise, verify_advertisement, verify_transit_advertisement, Advertisement, QuoteAttester,
    QuoteVerifier, SealTarget, TransitTarget, VerifiedAdvertisement,
};
pub use replay::ReplayCache;
pub use seal::{open_job, seal_job, InferenceParams, OpenedJob, SealedJob};
pub use suite::{
    valid_size_class, ADVERTISEMENT_VERSION, HPKE_AEAD_ID, HPKE_ENC_LEN, HPKE_KDF_ID, HPKE_KEM_ID,
    HPKE_PUBLIC_LEN, MAX_ADVERTISEMENT_SECS, MAX_CLOCK_SKEW_SECS, MAX_CONTRACT_TTL_SECS,
    PROTOCOL_VERSION, SUITE_ID,
};
pub use types::{MeasurementAllowlist, PromptContract, Tier};

#[cfg(test)]
mod tests;
