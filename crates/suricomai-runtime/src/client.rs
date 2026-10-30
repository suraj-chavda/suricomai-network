// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Client for a second machine.
//!
//! The client seals the prompt locally. The only bytes it hands to `exchange` are
//! the sealed job. The privacy label it can return is [`PrivacyLabel::LabUntrusted`].

use std::fmt;
use std::time::Instant;

use suricomai_envelope::{
    open_answer, seal_job, verify_advertisement, verify_transit_advertisement, HostLog,
    InferenceParams, JobVerification, LabVerifier, MeasurementAllowlist, ModelCatalog,
    PromptContract, SealTarget, Tier, UserKeys, MAX_CLOCK_SKEW_SECS,
};
use zeroize::Zeroizing;

use crate::error::RuntimeError;
use crate::model::{self, MODEL_NAME};
use crate::node::NodeCard;

/// The only privacy claim this client will attach to an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivacyLabel {
    /// The quote checked out as a lab software quote. The host was not proven to be a TEE.
    LabUntrusted,
    /// The user opted into a job the worker process can read.
    NotPrivate,
}

/// The caller's clock after a round trip: its own start time plus the time it waited,
/// rounded up, plus the skew tolerance. It never comes from the worker's receipt, and it
/// is never later than the last second before `expiry` unless the job really expired.
pub(crate) fn audit_clock(start: u64, sent: Instant, expiry: u64) -> u64 {
    let real = start
        .saturating_add(sent.elapsed().as_secs())
        .saturating_add(1);
    if real >= expiry {
        return real;
    }
    real.saturating_add(MAX_CLOCK_SKEW_SECS)
        .min(expiry.saturating_sub(1))
}

/// What the caller wants run. Debug output redacts the prompt.
pub struct JobRequest {
    /// 32-byte id. One use per executor.
    pub job_id: [u8; 32],
    /// Settlement chain id carried in the contract. Not settled here.
    pub chain_id: u64,
    /// Prompt. It leaves this struct only inside a seal.
    pub prompt: Vec<u8>,
    /// Sampling parameters, sealed beside the prompt.
    pub params: InferenceParams,
    /// Caller's clock in unix seconds. Checks the advertisement window and starts the
    /// audit clock.
    pub now: u64,
    /// Unix seconds. The executor rejects the job at this instant.
    pub expiry: u64,
    /// Fee field. The envelope does not move coins.
    pub fee: u64,
    /// Bond field. The envelope does not check a ledger.
    pub bond_required: u64,
    /// Cap on the answer, in bytes.
    pub max_output_bytes: u64,
    /// Padding bucket. Must be a size class the envelope accepts.
    pub size_class: u64,
    /// Latency hint copied into the contract.
    pub max_latency_ms: u64,
    /// One-time refund key. Not a prompt.
    pub user_pay_key: [u8; 32],
}

impl fmt::Debug for JobRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JobRequest")
            .field("job_id", &self.job_id)
            .field("prompt", &"redacted")
            .finish()
    }
}

/// Answer plus the proof. Debug output redacts the answer.
pub struct Completion {
    /// Model output. Wiped on drop.
    pub answer: Zeroizing<Vec<u8>>,
    /// Public proof bundle.
    pub proof: suricomai_envelope::ProofBundle,
    /// Always [`PrivacyLabel::LabUntrusted`] in this crate.
    pub privacy: PrivacyLabel,
}

impl fmt::Debug for Completion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Completion")
            .field("privacy", &self.privacy)
            .field("answer", &"redacted")
            .finish()
    }
}

/// User side of one lab executor. It does not hold the executor's private keys.
pub struct Client {
    user: UserKeys,
    verifier: LabVerifier,
    allowlist: MeasurementAllowlist,
    catalog: ModelCatalog,
    denied: Vec<[u8; 32]>,
    allow_unapproved_non_private: bool,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Client { redacted }")
    }
}

impl Client {
    /// Trust `verifier` as the lab root and allow exactly one measurement.
    pub fn new(verifier: LabVerifier, measurement: [u8; 32]) -> Result<Self, RuntimeError> {
        let mut allowlist = MeasurementAllowlist::new();
        allowlist.insert(measurement);
        Ok(Self {
            user: UserKeys::generate()?,
            verifier,
            allowlist,
            catalog: crate::lab::lab_catalog()?,
            denied: Vec::new(),
            allow_unapproved_non_private: false,
        })
    }

    /// Trust `catalog` instead of the lab catalog. Private jobs use approved models only.
    pub fn with_catalog(mut self, catalog: ModelCatalog) -> Self {
        self.catalog = catalog;
        self
    }

    /// Refuse these model digests whatever the catalog says. This is the operator's own
    /// switch for a takedown, and it also overrides `allow_unapproved_non_private`.
    pub fn with_denied(mut self, denied: Vec<[u8; 32]>) -> Self {
        self.denied = denied;
        self
    }

    /// Let a non-private (P1) job use a model that has no valid approval. Off by default.
    /// A private (P2) job never can.
    pub fn allow_unapproved_non_private(mut self, allow: bool) -> Self {
        self.allow_unapproved_non_private = allow;
        self
    }

    /// The models this client treats as approved.
    pub fn catalog(&self) -> &ModelCatalog {
        &self.catalog
    }

    /// Every check a card must pass before anything is sealed to it: the label, the model,
    /// the catalog, the measurement allowlist, and the advertisement itself with this
    /// client's own clock. A client that selects among nodes uses this to decide who is
    /// eligible, and [`Self::complete`] runs the same checks again before it seals.
    pub fn verify_card(
        &self,
        card: &NodeCard,
        now: u64,
    ) -> Result<suricomai_envelope::VerifiedAdvertisement, RuntimeError> {
        if card.hardware_p2 {
            return Err(RuntimeError::NotHardwareP2);
        }
        if card.quote_kind != "lab-untrusted" || card.model_name != MODEL_NAME {
            return Err(RuntimeError::ModelMismatch);
        }
        if self.denied.contains(&card.model_digest) {
            return Err(RuntimeError::Envelope(
                suricomai_envelope::EnvelopeError::ModelNotApproved,
            ));
        }
        self.catalog.require_approved(&card.model_digest, now)?;
        let expected = model::runtime_measurement(&card.model_digest);
        if card.advertisement.executor_id != expected
            || !self.allowlist.contains(&card.advertisement.executor_id)
        {
            return Err(RuntimeError::ModelMismatch);
        }
        Ok(verify_advertisement(
            &card.advertisement,
            &self.allowlist,
            &self.verifier,
            now,
        )?)
    }

    /// Every check a card must pass before a non-private job is sealed to it: the label, the
    /// deny list, the catalog (unless unapproved models are allowed), and the advertisement
    /// with this client's own clock. The model name is display only and decides nothing.
    pub fn verify_transit_card(
        &self,
        card: &NodeCard,
        now: u64,
    ) -> Result<suricomai_envelope::TransitTarget, RuntimeError> {
        if card.hardware_p2 {
            return Err(RuntimeError::NotHardwareP2);
        }
        if card.quote_kind != "lab-untrusted" {
            return Err(RuntimeError::ModelMismatch);
        }
        if self.denied.contains(&card.model_digest) {
            return Err(RuntimeError::Envelope(
                suricomai_envelope::EnvelopeError::ModelNotApproved,
            ));
        }
        if !self.allow_unapproved_non_private {
            self.catalog.require_approved(&card.model_digest, now)?;
        }
        Ok(verify_transit_advertisement(
            &card.advertisement,
            &self.verifier,
            now,
        )?)
    }

    /// Seal `request`, exchange ciphertext, verify the proof, then decrypt.
    ///
    /// A card that claims hardware P2 is rejected before the prompt is sealed.
    pub fn complete(
        &self,
        card: &NodeCard,
        request: &JobRequest,
        exchange: impl FnOnce(&[u8]) -> Result<Vec<u8>, RuntimeError>,
    ) -> Result<Completion, RuntimeError> {
        let verified = self.verify_card(card, request.now)?;
        let expected = model::runtime_measurement(&card.model_digest);
        let target = SealTarget::Private(verified);
        let mut contract = PromptContract {
            job_id: request.job_id,
            chain_id: request.chain_id,
            tier: Tier::P2,
            model_digest: card.model_digest,
            prompt_commitment: [0u8; 32],
            max_output_bytes: request.max_output_bytes,
            size_class: request.size_class,
            fee: request.fee,
            bond_required: request.bond_required,
            expiry: request.expiry,
            privacy_policy_id: expected,
            user_pay_key: request.user_pay_key,
            user_hpke_public: self.user.hpke_public().to_vec(),
            min_stake: 0,
            min_canary_ppt: 0,
            max_latency_ms: request.max_latency_ms,
            needs_gpu: false,
            region: Vec::new(),
        };
        contract.bind_prompt(&request.prompt);
        let sealed = seal_job(&contract, &request.prompt, &request.params, &target)?;
        let wire = sealed.to_bytes();
        let sent = Instant::now();
        let response = exchange(&wire)?;
        let audit_now = audit_clock(request.now, sent, request.expiry);
        let answer = open_answer(
            &sealed,
            &response,
            &self.user,
            &target,
            &self.allowlist,
            JobVerification::Quote(&self.verifier),
            audit_now,
            &mut HostLog::default(),
        )?;
        let proof = suricomai_envelope::SealedResult::from_bytes(&response)?
            .proof()
            .clone();
        Ok(Completion {
            answer,
            proof,
            privacy: PrivacyLabel::LabUntrusted,
        })
    }

    /// Seal a P1 job to `card`. The worker process can read the prompt.
    ///
    /// This path does not check the measurement allowlist. The label is
    /// [`PrivacyLabel::NotPrivate`].
    pub fn complete_transit(
        &self,
        card: &NodeCard,
        request: &JobRequest,
        exchange: impl FnOnce(&[u8]) -> Result<Vec<u8>, RuntimeError>,
    ) -> Result<Completion, RuntimeError> {
        let transit = self.verify_transit_card(card, request.now)?;
        let target = SealTarget::Transit(transit);
        let mut contract = PromptContract {
            job_id: request.job_id,
            chain_id: request.chain_id,
            tier: Tier::P1,
            model_digest: card.model_digest,
            prompt_commitment: [0u8; 32],
            max_output_bytes: request.max_output_bytes,
            size_class: request.size_class,
            fee: request.fee,
            bond_required: request.bond_required,
            expiry: request.expiry,
            privacy_policy_id: [0u8; 32],
            user_pay_key: request.user_pay_key,
            user_hpke_public: self.user.hpke_public().to_vec(),
            min_stake: 0,
            min_canary_ppt: 0,
            max_latency_ms: request.max_latency_ms,
            needs_gpu: false,
            region: Vec::new(),
        };
        contract.bind_prompt(&request.prompt);
        let sealed = seal_job(&contract, &request.prompt, &request.params, &target)?;
        let sent = Instant::now();
        let response = exchange(&sealed.to_bytes())?;
        let audit_now = audit_clock(request.now, sent, request.expiry);
        let answer = open_answer(
            &sealed,
            &response,
            &self.user,
            &target,
            &MeasurementAllowlist::new(),
            JobVerification::SignatureOnly,
            audit_now,
            &mut HostLog::default(),
        )?;
        let proof = suricomai_envelope::SealedResult::from_bytes(&response)?
            .proof()
            .clone();
        Ok(Completion {
            answer,
            proof,
            privacy: PrivacyLabel::NotPrivate,
        })
    }
}
