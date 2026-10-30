// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Fail-closed errors. Variants carry no plaintext, ciphertext, or keys.
//! [`Display`](std::fmt::Display) is a fixed code so a log line cannot absorb a prompt.

use std::fmt;

/// Why an envelope operation refused to continue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Bytes are not the encoding this crate accepts.
    Malformed,
    /// Encoding is valid CBOR but not the single canonical form.
    NonCanonical,
    /// A map key outside the schema was present.
    UnknownField,
    /// `version` is not 1.
    BadVersion,
    /// The advertisement is not yet valid, has expired, or claims too long a lifetime.
    StaleAdvertisement,
    /// The contract expiry is further out than the allowed lifetime.
    TtlTooLong,
    /// A saved replay cache could not be read back.
    BadSnapshot,
    /// The model has no valid approval from a trusted approver.
    ModelNotApproved,
    /// The approval was issued by a key this catalog does not trust.
    UntrustedApprover,
    /// The approval is revoked, not yet valid, or past its end.
    ApprovalWindow,
    /// `suite_id` names a suite this build does not implement.
    BadSuite,
    /// A field has the wrong length.
    BadLength,
    /// Tier byte is not 0, 1, or 2.
    BadTier,
    /// `size_class` is not an allowed bucket.
    BadSize,
    /// Sealed sampling parameters failed their schema.
    BadParams,
    /// `now >= expiry` when the executor opened the job.
    Expired,
    /// This `(chain_id, job_id)` was already presented.
    Replay,
    /// The replay cache is full and will not drop old ids.
    CacheFull,
    /// P2 measurement is not on the caller's allowlist, or the job was aimed at another executor.
    MeasurementRejected,
    /// HPKE open or seal failed. Truncation, a swapped header, and a bad tag share this code.
    BadSeal,
    /// Prompt bytes do not match `prompt_commitment`.
    CommitmentMismatch,
    /// A GPU P2 job did not carry a non-zero GPU evidence digest.
    MissingGpuEvidence,
    /// GPU evidence was attached to a job that must not have it.
    UnexpectedGpuEvidence,
    /// Quote magic, binding, or signature check failed.
    BadQuote,
    /// Ed25519 receipt signature failed.
    BadSignature,
    /// `report_data` does not match the job fields.
    BadReportData,
    /// Hash of the answer ciphertext does not match the proof.
    AnswerHashMismatch,
    /// Proof identity does not match the advertisement or transit key the user pinned.
    IdentityMismatch,
    /// Plaintext does not fit the declared size class.
    PlaintextTooLarge,
    /// Token count does not fit the public buckets.
    TooManyTokens,
    /// A P2 job was not sealed to a verified advertisement.
    NotPrivateTarget,
    /// A P0 or P1 job was sealed as if it were private.
    NotTransitTarget,
    /// The HPKE library's key sizes are not the pinned suite.
    SuiteMismatch,
    /// `assignment_vrf` is not the all-zero placeholder. Assignment proofs are not verified yet.
    BadAssignmentVrf,
    /// Receipt timestamps are after the contract expiry or after the auditor clock.
    ProofExpired,
    /// Recipient public key does not match the contract or the local private key.
    KeyMismatch,
}

impl EnvelopeError {
    /// Stable log code. This is the only string form of an error.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::NonCanonical => "non_canonical",
            Self::UnknownField => "unknown_field",
            Self::BadVersion => "bad_version",
            Self::BadSuite => "bad_suite",
            Self::StaleAdvertisement => "stale_advertisement",
            Self::TtlTooLong => "ttl_too_long",
            Self::BadSnapshot => "bad_snapshot",
            Self::ModelNotApproved => "model_not_approved",
            Self::UntrustedApprover => "untrusted_approver",
            Self::ApprovalWindow => "approval_window",
            Self::BadLength => "bad_length",
            Self::BadTier => "bad_tier",
            Self::BadSize => "bad_size",
            Self::BadParams => "bad_params",
            Self::Expired => "expired",
            Self::Replay => "replay",
            Self::CacheFull => "cache_full",
            Self::MeasurementRejected => "measurement_rejected",
            Self::BadSeal => "bad_seal",
            Self::CommitmentMismatch => "commitment_mismatch",
            Self::MissingGpuEvidence => "missing_gpu_evidence",
            Self::UnexpectedGpuEvidence => "unexpected_gpu_evidence",
            Self::BadQuote => "bad_quote",
            Self::BadSignature => "bad_signature",
            Self::BadReportData => "bad_report_data",
            Self::AnswerHashMismatch => "answer_hash_mismatch",
            Self::IdentityMismatch => "identity_mismatch",
            Self::PlaintextTooLarge => "plaintext_too_large",
            Self::TooManyTokens => "too_many_tokens",
            Self::NotPrivateTarget => "not_private_target",
            Self::NotTransitTarget => "not_transit_target",
            Self::SuiteMismatch => "suite_mismatch",
            Self::KeyMismatch => "key_mismatch",
            Self::BadAssignmentVrf => "bad_assignment_vrf",
            Self::ProofExpired => "proof_expired",
        }
    }

    /// Parse a log code produced by [`Self::code`]. Unknown text is rejected.
    pub fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "malformed" => Self::Malformed,
            "non_canonical" => Self::NonCanonical,
            "unknown_field" => Self::UnknownField,
            "bad_version" => Self::BadVersion,
            "bad_suite" => Self::BadSuite,
            "stale_advertisement" => Self::StaleAdvertisement,
            "ttl_too_long" => Self::TtlTooLong,
            "bad_snapshot" => Self::BadSnapshot,
            "model_not_approved" => Self::ModelNotApproved,
            "untrusted_approver" => Self::UntrustedApprover,
            "approval_window" => Self::ApprovalWindow,
            "bad_length" => Self::BadLength,
            "bad_tier" => Self::BadTier,
            "bad_size" => Self::BadSize,
            "bad_params" => Self::BadParams,
            "expired" => Self::Expired,
            "replay" => Self::Replay,
            "cache_full" => Self::CacheFull,
            "measurement_rejected" => Self::MeasurementRejected,
            "bad_seal" => Self::BadSeal,
            "commitment_mismatch" => Self::CommitmentMismatch,
            "missing_gpu_evidence" => Self::MissingGpuEvidence,
            "unexpected_gpu_evidence" => Self::UnexpectedGpuEvidence,
            "bad_quote" => Self::BadQuote,
            "bad_signature" => Self::BadSignature,
            "bad_report_data" => Self::BadReportData,
            "answer_hash_mismatch" => Self::AnswerHashMismatch,
            "identity_mismatch" => Self::IdentityMismatch,
            "plaintext_too_large" => Self::PlaintextTooLarge,
            "too_many_tokens" => Self::TooManyTokens,
            "not_private_target" => Self::NotPrivateTarget,
            "not_transit_target" => Self::NotTransitTarget,
            "suite_mismatch" => Self::SuiteMismatch,
            "key_mismatch" => Self::KeyMismatch,
            "bad_assignment_vrf" => Self::BadAssignmentVrf,
            "proof_expired" => Self::ProofExpired,
            _ => return None,
        })
    }
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for EnvelopeError {}
