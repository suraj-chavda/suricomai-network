// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Key ownership for a user and an executor.
//!
//! Debug output is redacted. Private keys are not serialized.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::KdfShake256;
use hpke::kem::XWing;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

use crate::error::EnvelopeError;
use crate::suite::{HPKE_ENC_LEN, HPKE_PUBLIC_LEN};

pub(crate) type AeadAlg = ChaCha20Poly1305;
pub(crate) type KdfAlg = KdfShake256;
pub(crate) type KemAlg = XWing;

/// Executor HPKE key, receipt key, and the id those keys are bound to.
pub struct EnclaveKeys {
    hpke_sk: <KemAlg as KemTrait>::PrivateKey,
    hpke_pk_bytes: Vec<u8>,
    receipt: SigningKey,
    executor_id: [u8; 32],
}

impl std::fmt::Debug for EnclaveKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnclaveKeys { redacted }")
    }
}

impl EnclaveKeys {
    /// Generate a fresh X-Wing key and a fresh Ed25519 receipt key.
    ///
    /// `executor_id` is the TEE measurement for a P2 worker, or a worker id for P0/P1.
    pub fn generate(executor_id: [u8; 32]) -> Result<Self, EnvelopeError> {
        let (hpke_sk, hpke_pk) = KemAlg::gen_keypair();
        let hpke_pk_bytes = hpke_pk.to_bytes().to_vec();
        if hpke_pk_bytes.len() != HPKE_PUBLIC_LEN {
            return Err(EnvelopeError::SuiteMismatch);
        }
        let receipt = SigningKey::generate(&mut OsRng);
        Ok(Self {
            hpke_sk,
            hpke_pk_bytes,
            receipt,
            executor_id,
        })
    }

    /// Id these keys were generated for.
    pub fn executor_id(&self) -> [u8; 32] {
        self.executor_id
    }

    /// X-Wing public key, 1216 bytes.
    pub fn hpke_public(&self) -> &[u8] {
        &self.hpke_pk_bytes
    }

    /// Ed25519 receipt public key.
    pub fn receipt_public(&self) -> [u8; 32] {
        self.receipt.verifying_key().to_bytes()
    }

    pub(crate) fn sign_receipt(&self, message: &[u8]) -> [u8; 64] {
        self.receipt.sign(message).to_bytes()
    }

    pub(crate) fn open_seals(
        &self,
        enc: &[u8],
        info: &[u8],
        aad: &[u8],
        ciphertexts: &[&[u8]],
    ) -> Result<Vec<Zeroizing<Vec<u8>>>, EnvelopeError> {
        open_seals(&self.hpke_sk, enc, info, aad, ciphertexts)
    }
}

impl Drop for EnclaveKeys {
    fn drop(&mut self) {
        let mut receipt_seed = self.receipt.to_bytes();
        receipt_seed.zeroize();
        self.hpke_pk_bytes.zeroize();
    }
}

/// User key that receives the sealed answer.
pub struct UserKeys {
    hpke_sk: <KemAlg as KemTrait>::PrivateKey,
    hpke_pk_bytes: Vec<u8>,
}

impl std::fmt::Debug for UserKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserKeys { redacted }")
    }
}

impl UserKeys {
    /// Generate a fresh X-Wing key for one user.
    pub fn generate() -> Result<Self, EnvelopeError> {
        let (hpke_sk, hpke_pk) = KemAlg::gen_keypair();
        let hpke_pk_bytes = hpke_pk.to_bytes().to_vec();
        if hpke_pk_bytes.len() != HPKE_PUBLIC_LEN {
            return Err(EnvelopeError::SuiteMismatch);
        }
        Ok(Self {
            hpke_sk,
            hpke_pk_bytes,
        })
    }

    /// X-Wing public key to put in the prompt contract.
    pub fn hpke_public(&self) -> &[u8] {
        &self.hpke_pk_bytes
    }

    pub(crate) fn open_seals(
        &self,
        enc: &[u8],
        info: &[u8],
        aad: &[u8],
        ciphertexts: &[&[u8]],
    ) -> Result<Vec<Zeroizing<Vec<u8>>>, EnvelopeError> {
        open_seals(&self.hpke_sk, enc, info, aad, ciphertexts)
    }
}

impl Drop for UserKeys {
    fn drop(&mut self) {
        self.hpke_pk_bytes.zeroize();
    }
}

pub(crate) fn seal_to(
    pk_bytes: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintexts: &[&[u8]],
) -> Result<(Vec<u8>, Vec<Vec<u8>>), EnvelopeError> {
    if pk_bytes.len() != HPKE_PUBLIC_LEN {
        return Err(EnvelopeError::BadLength);
    }
    let pk = <KemAlg as KemTrait>::PublicKey::from_bytes(pk_bytes)
        .map_err(|_| EnvelopeError::KeyMismatch)?;
    let (enc, mut ctx) = hpke::setup_sender::<AeadAlg, KdfAlg, KemAlg>(&OpModeS::Base, &pk, info)
        .map_err(|_| EnvelopeError::BadSeal)?;
    let enc_bytes = enc.to_bytes().to_vec();
    if enc_bytes.len() != HPKE_ENC_LEN {
        return Err(EnvelopeError::SuiteMismatch);
    }
    let mut ciphertexts = Vec::with_capacity(plaintexts.len());
    for plaintext in plaintexts {
        ciphertexts.push(
            ctx.seal(plaintext, aad)
                .map_err(|_| EnvelopeError::BadSeal)?,
        );
    }
    Ok((enc_bytes, ciphertexts))
}

fn open_seals(
    sk: &<KemAlg as KemTrait>::PrivateKey,
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertexts: &[&[u8]],
) -> Result<Vec<Zeroizing<Vec<u8>>>, EnvelopeError> {
    if enc.len() != HPKE_ENC_LEN {
        return Err(EnvelopeError::BadSeal);
    }
    let enc_key =
        <KemAlg as KemTrait>::EncappedKey::from_bytes(enc).map_err(|_| EnvelopeError::BadSeal)?;
    let mut ctx =
        hpke::setup_receiver::<AeadAlg, KdfAlg, KemAlg>(&OpModeR::Base, sk, &enc_key, info)
            .map_err(|_| EnvelopeError::BadSeal)?;
    let mut plains = Vec::with_capacity(ciphertexts.len());
    for ciphertext in ciphertexts {
        let mut opened = ctx
            .open(ciphertext, aad)
            .map_err(|_| EnvelopeError::BadSeal)?;
        plains.push(Zeroizing::new(std::mem::take(&mut opened)));
    }
    Ok(plains)
}

pub(crate) fn verifying_key(bytes: &[u8; 32]) -> Result<VerifyingKey, EnvelopeError> {
    VerifyingKey::from_bytes(bytes).map_err(|_| EnvelopeError::BadSignature)
}
