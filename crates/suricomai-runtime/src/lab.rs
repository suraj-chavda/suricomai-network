// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! The development catalog: which models the lab client treats as approved.
//!
//! The approver and publisher keys here are derived from fixed strings in public source code.
//! That is acceptable only because this catalog is for a development build on non-TEE hardware
//! and every label it produces says so. A production client trusts a different, offline-held
//! approver key and never ships its secret.

use ed25519_dalek::SigningKey;
use suricomai_envelope::{
    ApprovalStatus, EnvelopeError, ModelApproval, ModelCatalog, ModelManifest,
};

use crate::model::{self, MODEL_NAME};
use crate::text_model::{self, TEXT_MODEL_NAME};

/// End of the lab approvals: 1 January 2100. A real approval is much shorter and is renewed.
const LAB_APPROVAL_END: u64 = 4_102_444_800;

fn derive(domain: &str) -> SigningKey {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(b"suricomai lab key, public by design");
    SigningKey::from_bytes(hasher.finalize().as_bytes())
}

fn lab_approver() -> SigningKey {
    derive("suricomai.lab-approver.v1")
}

fn lab_publisher() -> SigningKey {
    derive("suricomai.lab-publisher.v1")
}

/// The public key of the lab approver, which a lab client trusts.
pub fn lab_approver_public() -> [u8; 32] {
    lab_approver().verifying_key().to_bytes()
}

fn runtime_digest() -> [u8; 32] {
    model::runtime_digest()
}

/// Build the lab catalog: the built-in test model, and the text model when its weights are
/// installed. Both are approved by the lab approver for the whole lab period.
pub fn lab_catalog() -> Result<ModelCatalog, EnvelopeError> {
    let mut catalog = ModelCatalog::new(vec![lab_approver_public()]);
    let publisher = lab_publisher();
    let approver = lab_approver();

    let tiny = ModelManifest::publish(
        MODEL_NAME,
        model::model_digest(&model::pinned_weights()),
        model::tokenizer_file_digest(b""),
        runtime_digest(),
        1,
        "MIT",
        &publisher,
    )?;
    let tiny_approval = ModelApproval::issue(
        &tiny,
        ApprovalStatus::Approved,
        0,
        LAB_APPROVAL_END,
        &approver,
    )?;
    catalog.add(tiny, tiny_approval)?;

    if let (Some(digest), Some(tokenizer_digest)) = (
        text_model::installed_digest(),
        text_model::installed_tokenizer_digest(),
    ) {
        let text = ModelManifest::publish(
            TEXT_MODEL_NAME,
            digest,
            tokenizer_digest,
            runtime_digest(),
            135,
            "Apache-2.0",
            &publisher,
        )?;
        let approval = ModelApproval::issue(
            &text,
            ApprovalStatus::Approved,
            0,
            LAB_APPROVAL_END,
            &approver,
        )?;
        catalog.add(text, approval)?;
    }
    Ok(catalog)
}
