// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Software quote for development builds. Compiled only with the `lab` feature.
//!
//! It proves nothing about hardware: whoever holds the signing key can produce any quote.
//! A build without the feature contains none of this code.

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

const LAB_MAGIC: &[u8] = b"suricomai-lab-quote-v1";
const LAB_DOMAIN: &[u8] = b"suricomai.lab-quote.v1\0";

use crate::error::EnvelopeError;
use crate::quote::{QuoteAttester, QuoteVerifier};
use crate::suite::{DIGEST_LEN, SIGNATURE_LEN};

/// Software attester used in tests and the local example.
pub struct LabAttester {
    signing: SigningKey,
}

impl std::fmt::Debug for LabAttester {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LabAttester { redacted }")
    }
}

impl Clone for LabAttester {
    fn clone(&self) -> Self {
        Self {
            signing: self.signing.clone(),
        }
    }
}

impl LabAttester {
    /// Generate a throwaway lab root. This key is not a hardware root.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    /// Rebuild a lab root from its secret. Development nodes use this to keep one lab
    /// root across restarts. It is not a hardware root.
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(secret),
        }
    }

    /// The secret half of this lab root. Handle it like any private key.
    pub fn secret_bytes(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.signing.to_bytes())
    }

    /// Verifier for quotes this attester produces.
    pub fn verifier(&self) -> LabVerifier {
        LabVerifier {
            verifying: self.signing.verifying_key(),
        }
    }

    /// Ed25519 public key of this lab root. Not a vendor root.
    pub fn verifying_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }
}

impl QuoteAttester for LabAttester {
    fn attest(
        &self,
        executor_id: &[u8; DIGEST_LEN],
        report_data: &[u8; DIGEST_LEN],
    ) -> Result<Vec<u8>, EnvelopeError> {
        let mut message = Vec::with_capacity(LAB_DOMAIN.len() + 64);
        message.extend_from_slice(LAB_DOMAIN);
        message.extend_from_slice(executor_id);
        message.extend_from_slice(report_data);
        let sig = self.signing.sign(&message).to_bytes();
        let mut quote = Vec::with_capacity(LAB_MAGIC.len() + 32 + 32 + 64);
        quote.extend_from_slice(LAB_MAGIC);
        quote.extend_from_slice(executor_id);
        quote.extend_from_slice(report_data);
        quote.extend_from_slice(&sig);
        Ok(quote)
    }
}

/// Checks [`LabAttester`] quotes and rejects every other magic.
#[derive(Clone)]
pub struct LabVerifier {
    verifying: ed25519_dalek::VerifyingKey,
}

impl std::fmt::Debug for LabVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LabVerifier { redacted }")
    }
}

impl LabVerifier {
    /// Build a verifier from a 32-byte Ed25519 public key.
    ///
    /// The caller still has to decide whether this key is a lab root or a vendor root.
    /// This function does not make that decision.
    pub fn from_verifying_bytes(bytes: &[u8; 32]) -> Result<Self, EnvelopeError> {
        let verifying =
            ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| EnvelopeError::BadQuote)?;
        Ok(Self { verifying })
    }
}

impl QuoteVerifier for LabVerifier {
    fn verify_quote(
        &self,
        executor_id: &[u8; DIGEST_LEN],
        report_data: &[u8; DIGEST_LEN],
        quote: &[u8],
    ) -> Result<(), EnvelopeError> {
        let need = LAB_MAGIC.len() + DIGEST_LEN + DIGEST_LEN + SIGNATURE_LEN;
        if quote.len() != need || !quote.starts_with(LAB_MAGIC) {
            return Err(EnvelopeError::BadQuote);
        }
        let id = &quote[LAB_MAGIC.len()..LAB_MAGIC.len() + DIGEST_LEN];
        let report = &quote[LAB_MAGIC.len() + DIGEST_LEN..LAB_MAGIC.len() + 2 * DIGEST_LEN];
        let sig_bytes = &quote[LAB_MAGIC.len() + 2 * DIGEST_LEN..];
        if id != executor_id.as_slice() || report != report_data.as_slice() {
            return Err(EnvelopeError::BadQuote);
        }
        let mut message = Vec::with_capacity(LAB_DOMAIN.len() + 64);
        message.extend_from_slice(LAB_DOMAIN);
        message.extend_from_slice(executor_id);
        message.extend_from_slice(report_data);
        let signature =
            ed25519_dalek::Signature::from_slice(sig_bytes).map_err(|_| EnvelopeError::BadQuote)?;
        self.verifying
            .verify_strict(&message, &signature)
            .map_err(|_| EnvelopeError::BadQuote)
    }
}
