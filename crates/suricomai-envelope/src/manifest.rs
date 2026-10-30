// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Model manifests, approvals, and the catalog a client checks before it uses a model.
//!
//! A **manifest** says what a model is: its digest, tokenizer, runtime, license, and who
//! published it. A publisher signs it. An **approval** says that a trusted approver has
//! reviewed that exact manifest and allows it, for a window of time. An approver can also
//! revoke. The **catalog** holds only manifests that carry a valid approval from an approver
//! the caller trusts. The private tier uses approved models only.

use std::collections::{BTreeMap, HashMap};

use ed25519_dalek::{Signature, Signer, SigningKey};

use crate::cbor::{self, Cbor};
use crate::commit::domain_hash;
use crate::error::EnvelopeError;
use crate::keys::verifying_key;
use crate::suite::{DIGEST_LEN, PROTOCOL_VERSION, SIGNATURE_LEN};
use crate::types::{bytes_at, digest_at, require_keys};

const MANIFEST_SIG_DOMAIN: &[u8] = b"suricomai.manifest.sig.v1\0";
const APPROVAL_SIG_DOMAIN: &[u8] = b"suricomai.approval.sig.v1\0";
const MAX_ID_LEN: usize = 64;
const MAX_LICENSE_LEN: usize = 32;

/// What a model is. Signed by its publisher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelManifest {
    /// Short name such as `smollm2-135m-instruct`. Lowercase letters, digits, `.`, `_`, `-`.
    pub model_id: String,
    /// The digest that goes in a prompt contract and in every receipt for this model.
    pub model_digest: [u8; DIGEST_LEN],
    /// Hash of the tokenizer files.
    pub tokenizer_digest: [u8; DIGEST_LEN],
    /// Hash of the inference runtime build that is allowed to run these weights.
    pub runtime_digest: [u8; DIGEST_LEN],
    /// Size in millions of parameters. Used for pricing class and display, not for security.
    pub params_millions: u64,
    /// SPDX license identifier.
    pub license: String,
    /// Key that signed this manifest.
    pub publisher_public: [u8; DIGEST_LEN],
    /// Signature over every other field.
    pub publisher_sig: [u8; SIGNATURE_LEN],
}

/// Whether an approver allows a manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalStatus {
    /// The approver allows this manifest during the window.
    Approved,
    /// The approver withdraws permission.
    Revoked,
}

/// A trusted approver's decision about one exact manifest. Signed by the approver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelApproval {
    /// Content id of the manifest this decision is about.
    pub manifest_id: [u8; DIGEST_LEN],
    /// Approved or revoked.
    pub status: ApprovalStatus,
    /// Unix seconds when the decision takes effect.
    pub valid_from: u64,
    /// Unix seconds when it ends. A decision never lasts forever, so approvals must be renewed.
    pub valid_until: u64,
    /// Key that signed this decision.
    pub approver_public: [u8; DIGEST_LEN],
    /// Signature over every other field.
    pub approver_sig: [u8; SIGNATURE_LEN],
}

fn text(bytes: &[u8], max: usize, allow: impl Fn(u8) -> bool) -> Result<String, EnvelopeError> {
    if bytes.is_empty() || bytes.len() > max || !bytes.iter().copied().all(allow) {
        return Err(EnvelopeError::Malformed);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| EnvelopeError::Malformed)
}

fn id_char(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
}

fn license_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+')
}

impl ModelManifest {
    /// Build a manifest and sign it. The caller supplies everything except the signature.
    #[allow(clippy::too_many_arguments)]
    pub fn publish(
        model_id: &str,
        model_digest: [u8; DIGEST_LEN],
        tokenizer_digest: [u8; DIGEST_LEN],
        runtime_digest: [u8; DIGEST_LEN],
        params_millions: u64,
        license: &str,
        publisher: &SigningKey,
    ) -> Result<Self, EnvelopeError> {
        let mut manifest = Self {
            model_id: model_id.to_string(),
            model_digest,
            tokenizer_digest,
            runtime_digest,
            params_millions,
            license: license.to_string(),
            publisher_public: publisher.verifying_key().to_bytes(),
            publisher_sig: [0u8; SIGNATURE_LEN],
        };
        manifest.validate()?;
        manifest.publisher_sig = publisher.sign(&manifest.signed_bytes()?).to_bytes();
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), EnvelopeError> {
        text(self.model_id.as_bytes(), MAX_ID_LEN, id_char)?;
        text(self.license.as_bytes(), MAX_LICENSE_LEN, license_char)?;
        if self.params_millions == 0 {
            return Err(EnvelopeError::Malformed);
        }
        Ok(())
    }

    fn map(&self, include_sig: bool) -> BTreeMap<u64, Cbor> {
        let mut map = BTreeMap::new();
        map.insert(1, Cbor::UInt(PROTOCOL_VERSION));
        map.insert(2, Cbor::Bytes(self.model_id.as_bytes().to_vec()));
        map.insert(3, Cbor::Bytes(self.model_digest.to_vec()));
        map.insert(4, Cbor::Bytes(self.tokenizer_digest.to_vec()));
        map.insert(5, Cbor::Bytes(self.runtime_digest.to_vec()));
        map.insert(6, Cbor::UInt(self.params_millions));
        map.insert(7, Cbor::Bytes(self.license.as_bytes().to_vec()));
        map.insert(8, Cbor::Bytes(self.publisher_public.to_vec()));
        if include_sig {
            map.insert(9, Cbor::Bytes(self.publisher_sig.to_vec()));
        }
        map
    }

    fn signed_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        let mut message = Vec::from(MANIFEST_SIG_DOMAIN);
        message.extend(cbor::encode(&Cbor::Map(self.map(false))));
        Ok(message)
    }

    /// Canonical bytes, signature included.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        self.validate()?;
        Ok(cbor::encode(&Cbor::Map(self.map(true))))
    }

    /// Decode canonical bytes. This does not check the signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let value = cbor::decode(bytes)?;
        let map = cbor::as_map(&value)?;
        require_keys(map, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
        if cbor::as_u64(map.get(&1).ok_or(EnvelopeError::Malformed)?)? != PROTOCOL_VERSION {
            return Err(EnvelopeError::BadVersion);
        }
        let mut sig = [0u8; SIGNATURE_LEN];
        sig.copy_from_slice(bytes_at(map, 9, Some(SIGNATURE_LEN))?);
        let manifest = Self {
            model_id: text(bytes_at(map, 2, None)?, MAX_ID_LEN, id_char)?,
            model_digest: digest_at(map, 3)?,
            tokenizer_digest: digest_at(map, 4)?,
            runtime_digest: digest_at(map, 5)?,
            params_millions: cbor::as_u64(map.get(&6).ok_or(EnvelopeError::Malformed)?)?,
            license: text(bytes_at(map, 7, None)?, MAX_LICENSE_LEN, license_char)?,
            publisher_public: digest_at(map, 8)?,
            publisher_sig: sig,
        };
        manifest.validate()?;
        if manifest.to_bytes()? != bytes {
            return Err(EnvelopeError::NonCanonical);
        }
        Ok(manifest)
    }

    /// Content id: a hash of the canonical bytes. Approvals name a manifest by this id, so an
    /// approval for one manifest can never be moved onto an edited copy.
    pub fn id(&self) -> Result<[u8; DIGEST_LEN], EnvelopeError> {
        Ok(domain_hash("suricomai.manifest.v1", &[&self.to_bytes()?]))
    }

    /// Check the publisher's signature.
    pub fn verify_signature(&self) -> Result<(), EnvelopeError> {
        let key = verifying_key(&self.publisher_public)?;
        let signature =
            Signature::from_slice(&self.publisher_sig).map_err(|_| EnvelopeError::BadSignature)?;
        key.verify_strict(&self.signed_bytes()?, &signature)
            .map_err(|_| EnvelopeError::BadSignature)
    }
}

impl ModelApproval {
    /// Sign a decision about `manifest`.
    pub fn issue(
        manifest: &ModelManifest,
        status: ApprovalStatus,
        valid_from: u64,
        valid_until: u64,
        approver: &SigningKey,
    ) -> Result<Self, EnvelopeError> {
        if valid_until <= valid_from {
            return Err(EnvelopeError::ApprovalWindow);
        }
        let mut approval = Self {
            manifest_id: manifest.id()?,
            status,
            valid_from,
            valid_until,
            approver_public: approver.verifying_key().to_bytes(),
            approver_sig: [0u8; SIGNATURE_LEN],
        };
        approval.approver_sig = approver.sign(&approval.signed_bytes()).to_bytes();
        Ok(approval)
    }

    fn map(&self, include_sig: bool) -> BTreeMap<u64, Cbor> {
        let mut map = BTreeMap::new();
        map.insert(1, Cbor::UInt(PROTOCOL_VERSION));
        map.insert(2, Cbor::Bytes(self.manifest_id.to_vec()));
        map.insert(
            3,
            Cbor::UInt(match self.status {
                ApprovalStatus::Approved => 1,
                ApprovalStatus::Revoked => 2,
            }),
        );
        map.insert(4, Cbor::UInt(self.valid_from));
        map.insert(5, Cbor::UInt(self.valid_until));
        map.insert(6, Cbor::Bytes(self.approver_public.to_vec()));
        if include_sig {
            map.insert(7, Cbor::Bytes(self.approver_sig.to_vec()));
        }
        map
    }

    fn signed_bytes(&self) -> Vec<u8> {
        let mut message = Vec::from(APPROVAL_SIG_DOMAIN);
        message.extend(cbor::encode(&Cbor::Map(self.map(false))));
        message
    }

    /// Canonical bytes, signature included.
    pub fn to_bytes(&self) -> Vec<u8> {
        cbor::encode(&Cbor::Map(self.map(true)))
    }

    /// Decode canonical bytes. This does not check the signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let value = cbor::decode(bytes)?;
        let map = cbor::as_map(&value)?;
        require_keys(map, &[1, 2, 3, 4, 5, 6, 7])?;
        if cbor::as_u64(map.get(&1).ok_or(EnvelopeError::Malformed)?)? != PROTOCOL_VERSION {
            return Err(EnvelopeError::BadVersion);
        }
        let status = match cbor::as_u64(map.get(&3).ok_or(EnvelopeError::Malformed)?)? {
            1 => ApprovalStatus::Approved,
            2 => ApprovalStatus::Revoked,
            _ => return Err(EnvelopeError::Malformed),
        };
        let mut sig = [0u8; SIGNATURE_LEN];
        sig.copy_from_slice(bytes_at(map, 7, Some(SIGNATURE_LEN))?);
        let approval = Self {
            manifest_id: digest_at(map, 2)?,
            status,
            valid_from: cbor::as_u64(map.get(&4).ok_or(EnvelopeError::Malformed)?)?,
            valid_until: cbor::as_u64(map.get(&5).ok_or(EnvelopeError::Malformed)?)?,
            approver_public: digest_at(map, 6)?,
            approver_sig: sig,
        };
        if approval.valid_until <= approval.valid_from {
            return Err(EnvelopeError::ApprovalWindow);
        }
        if approval.to_bytes() != bytes {
            return Err(EnvelopeError::NonCanonical);
        }
        Ok(approval)
    }

    /// Check the approver's signature.
    pub fn verify_signature(&self) -> Result<(), EnvelopeError> {
        let key = verifying_key(&self.approver_public)?;
        let signature =
            Signature::from_slice(&self.approver_sig).map_err(|_| EnvelopeError::BadSignature)?;
        key.verify_strict(&self.signed_bytes(), &signature)
            .map_err(|_| EnvelopeError::BadSignature)
    }
}

/// Where a model stands right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelStanding {
    /// A trusted approver allows it now.
    Approved,
    /// The catalog has never heard of it.
    Unknown,
    /// An approver revoked it.
    Revoked,
    /// Its approval has ended and was not renewed.
    Expired,
    /// No decision about it has taken effect yet.
    NotYetValid,
}

/// One model in the catalog: its manifest and every decision made about exactly that manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelEntry {
    /// The manifest.
    pub manifest: ModelManifest,
    /// Decisions about this manifest, oldest first by `valid_from`.
    pub approvals: Vec<ModelApproval>,
}

impl ModelEntry {
    /// The decision in force at `now`, as `(status, valid_until)`.
    ///
    /// Signatures that agree on status and window form one decision. An approval counts only
    /// when at least `threshold` distinct approvers signed it. A revocation counts with one
    /// signature, so removing a model is faster than adding one. Among counted decisions that
    /// have taken effect the newest governs, and a revocation wins a tie.
    fn governing(&self, now: u64, threshold: usize) -> Option<(ApprovalStatus, u64)> {
        let mut groups: HashMap<(u64, u8, u64), Vec<[u8; DIGEST_LEN]>> = HashMap::new();
        for approval in self.approvals.iter().filter(|a| a.valid_from <= now) {
            let status = u8::from(approval.status == ApprovalStatus::Revoked);
            let signers = groups
                .entry((approval.valid_from, status, approval.valid_until))
                .or_default();
            if !signers.contains(&approval.approver_public) {
                signers.push(approval.approver_public);
            }
        }
        groups
            .into_iter()
            .filter(|((_, revoked, _), signers)| *revoked == 1 || signers.len() >= threshold)
            .max_by_key(|((from, revoked, _), _)| (*from, *revoked))
            .map(|((_, revoked, until), _)| {
                let status = if revoked == 1 {
                    ApprovalStatus::Revoked
                } else {
                    ApprovalStatus::Approved
                };
                (status, until)
            })
    }
}

/// Models a caller trusts, each backed by a valid approval from an approver the caller trusts.
#[derive(Clone, Debug)]
pub struct ModelCatalog {
    approvers: Vec<[u8; DIGEST_LEN]>,
    threshold: usize,
    entries: HashMap<[u8; DIGEST_LEN], ModelEntry>,
}

impl ModelCatalog {
    /// A catalog that trusts exactly these approver keys, any one of which can approve.
    pub fn new(approvers: Vec<[u8; DIGEST_LEN]>) -> Self {
        Self {
            approvers,
            threshold: 1,
            entries: HashMap::new(),
        }
    }

    /// A catalog where an approval needs `threshold` distinct approvers to sign it. A single
    /// approver can still revoke. The approvers must be distinct and the threshold must be at
    /// least 1 and at most their number.
    pub fn with_threshold(
        approvers: Vec<[u8; DIGEST_LEN]>,
        threshold: usize,
    ) -> Result<Self, EnvelopeError> {
        let mut distinct = approvers.clone();
        distinct.sort();
        distinct.dedup();
        if distinct.len() != approvers.len() || threshold == 0 || threshold > approvers.len() {
            return Err(EnvelopeError::Malformed);
        }
        Ok(Self {
            approvers,
            threshold,
            entries: HashMap::new(),
        })
    }

    /// Add a manifest with a decision about it.
    ///
    /// Both signatures must verify, the approver must be trusted, and the decision must name
    /// exactly this manifest. Every decision is kept. At any moment the newest decision that has
    /// already taken effect governs, so a revocation dated in the future leaves the model
    /// approved until that date, and replaying an old approval cannot undo a later revocation.
    ///
    /// A different publisher cannot take over a digest that is already known. The same publisher
    /// may publish an edited manifest, but it starts with no approvals and needs a fresh one.
    pub fn add(
        &mut self,
        manifest: ModelManifest,
        approval: ModelApproval,
    ) -> Result<(), EnvelopeError> {
        manifest.verify_signature()?;
        approval.verify_signature()?;
        if !self.approvers.contains(&approval.approver_public) {
            return Err(EnvelopeError::UntrustedApprover);
        }
        let id = manifest.id()?;
        if approval.manifest_id != id {
            return Err(EnvelopeError::IdentityMismatch);
        }
        match self.entries.get_mut(&manifest.model_digest) {
            Some(entry) if entry.manifest.id()? == id => {
                if !entry.approvals.contains(&approval) {
                    entry.approvals.push(approval);
                    entry.approvals.sort_by_key(|decision| decision.valid_from);
                }
            }
            Some(entry) if entry.manifest.publisher_public != manifest.publisher_public => {
                return Err(EnvelopeError::IdentityMismatch);
            }
            _ => {
                self.entries.insert(
                    manifest.model_digest,
                    ModelEntry {
                        manifest,
                        approvals: vec![approval],
                    },
                );
            }
        }
        Ok(())
    }

    /// Where `model_digest` stands at time `now`.
    pub fn standing(&self, model_digest: &[u8; DIGEST_LEN], now: u64) -> ModelStanding {
        let Some(entry) = self.entries.get(model_digest) else {
            return ModelStanding::Unknown;
        };
        let Some((status, valid_until)) = entry.governing(now, self.threshold) else {
            return ModelStanding::NotYetValid;
        };
        match status {
            ApprovalStatus::Revoked => ModelStanding::Revoked,
            ApprovalStatus::Approved if now >= valid_until => ModelStanding::Expired,
            ApprovalStatus::Approved => ModelStanding::Approved,
        }
    }

    /// Require `model_digest` to be approved at `now`, or say why not.
    pub fn require_approved(
        &self,
        model_digest: &[u8; DIGEST_LEN],
        now: u64,
    ) -> Result<&ModelEntry, EnvelopeError> {
        match self.standing(model_digest, now) {
            ModelStanding::Approved => self
                .entries
                .get(model_digest)
                .ok_or(EnvelopeError::ModelNotApproved),
            ModelStanding::Expired | ModelStanding::NotYetValid | ModelStanding::Revoked => {
                Err(EnvelopeError::ApprovalWindow)
            }
            ModelStanding::Unknown => Err(EnvelopeError::ModelNotApproved),
        }
    }

    /// Look a model up by its short name. Names are for display. The digest is the identity.
    pub fn by_id(&self, model_id: &str) -> Option<&ModelEntry> {
        self.entries
            .values()
            .find(|entry| entry.manifest.model_id == model_id)
    }

    /// Every entry, in a stable order by name.
    pub fn entries(&self) -> Vec<&ModelEntry> {
        let mut all: Vec<&ModelEntry> = self.entries.values().collect();
        all.sort_by(|a, b| a.manifest.model_id.cmp(&b.manifest.model_id));
        all
    }
}
