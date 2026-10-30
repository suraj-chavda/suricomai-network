// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use zeroize::Zeroizing;

use crate::digest::{keccak256, Address};
use crate::error::AttestError;

/// One committee member's key.
pub struct CommitteeSigner {
    key: SigningKey,
    address: Address,
}

/// A 65 byte signature (`r || s || v`, `v` is 27 or 28, `s` in the lower half) and its signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitteeSignature {
    /// Address recovered from the signature.
    pub signer: Address,
    /// The signature bytes the contract expects.
    pub bytes: [u8; 65],
}

impl std::fmt::Debug for CommitteeSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CommitteeSigner { redacted }")
    }
}

impl CommitteeSigner {
    /// Load a secret key. The caller keeps the bytes safe and wipes them.
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, AttestError> {
        let secret = Zeroizing::new(*secret);
        let key = SigningKey::from_bytes(&(*secret).into()).map_err(|_| AttestError::BadKey)?;
        let point = key.verifying_key().to_encoded_point(false);
        let hash = keccak256(&[&point.as_bytes()[1..]]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        Ok(Self { key, address })
    }

    /// The committee address the contract knows this member by.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Sign a 32 byte digest. The signature is canonical: `s` is never in the upper half.
    pub fn sign(&self, digest: &[u8; 32]) -> Result<CommitteeSignature, AttestError> {
        let (signature, recovery) = self
            .key
            .sign_prehash_recoverable(digest)
            .map_err(|_| AttestError::Signing)?;
        let (signature, recovery) = match signature.normalize_s() {
            Some(low) => (
                low,
                RecoveryId::new(!recovery.is_y_odd(), recovery.is_x_reduced()),
            ),
            None => (signature, recovery),
        };
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&signature.to_bytes());
        bytes[64] = 27 + u8::from(recovery.is_y_odd());
        Ok(CommitteeSignature {
            signer: self.address,
            bytes,
        })
    }
}

/// Join signatures into the form the contract takes: ascending by signer address, no
/// duplicates.
pub fn assemble(mut signatures: Vec<CommitteeSignature>) -> Result<Vec<u8>, AttestError> {
    if signatures.is_empty() {
        return Err(AttestError::BadSignatureSet);
    }
    signatures.sort_by_key(|signature| signature.signer);
    if signatures
        .windows(2)
        .any(|pair| pair[0].signer == pair[1].signer)
    {
        return Err(AttestError::BadSignatureSet);
    }
    Ok(signatures
        .iter()
        .flat_map(|signature| signature.bytes)
        .collect())
}

/// Recover the signer of `signature` over `digest`. For tests and diagnostics.
pub fn recover(digest: &[u8; 32], signature: &[u8; 65]) -> Option<Address> {
    let parsed = Signature::from_slice(&signature[..64]).ok()?;
    let id = RecoveryId::from_byte(signature[64].checked_sub(27)?)?;
    let key = k256::ecdsa::VerifyingKey::recover_from_prehash(digest, &parsed, id).ok()?;
    let point = key.to_encoded_point(false);
    let hash = keccak256(&[&point.as_bytes()[1..]]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Some(address)
}
