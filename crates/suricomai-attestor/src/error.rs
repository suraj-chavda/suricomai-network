// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
use std::fmt;

use suricomai_envelope::EnvelopeError;

/// Why an attestation was refused. Nothing here carries a prompt or an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestError {
    /// The envelope auditor rejected the proof or the contract.
    Rejected(EnvelopeError),
    /// The two verifiers gave different answers. Nothing is signed.
    Disagreement {
        /// Answer from the envelope auditor.
        first: String,
        /// Answer from the second verifier.
        second: String,
    },
    /// The wire contract, the proof, and the chain record do not describe the same job.
    Binding(&'static str),
    /// The amount is below the minimum fee or above the locked cap.
    AmountOutOfRange,
    /// The proof is valid, so there is no fault to slash.
    NothingToSlash,
    /// The proof fails, but not for a fault the contract can slash.
    NotASlashableFault(EnvelopeError),
    /// The second verifier could not be run or gave an unreadable answer.
    Verifier(String),
    /// A secret key was not a valid secp256k1 scalar.
    BadKey,
    /// Signing failed.
    Signing,
    /// The same signer appeared twice, or the set was empty.
    BadSignatureSet,
}

impl fmt::Display for AttestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(err) => write!(f, "rejected: {}", err.code()),
            Self::Disagreement { first, second } => {
                write!(f, "verifiers disagree: {first} versus {second}")
            }
            Self::Binding(what) => write!(f, "binding mismatch: {what}"),
            Self::AmountOutOfRange => f.write_str("amount out of range"),
            Self::NothingToSlash => f.write_str("nothing to slash"),
            Self::NotASlashableFault(err) => write!(f, "not slashable: {}", err.code()),
            Self::Verifier(why) => write!(f, "second verifier failed: {why}"),
            Self::BadKey => f.write_str("bad key"),
            Self::Signing => f.write_str("signing failed"),
            Self::BadSignatureSet => f.write_str("bad signature set"),
        }
    }
}

impl std::error::Error for AttestError {}
