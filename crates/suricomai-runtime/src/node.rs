// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Local executor.
//!
//! The quote it can produce is the lab software quote from the envelope crate.
//! [`Executor::status`] reports `hardware_p2: false` on every build of this crate.

use rand::rngs::OsRng;
use rand::RngCore;
use suricomai_envelope::{
    advertise, finish_job, open_job, Advertisement, EnclaveKeys, HostLog, JobAttestation,
    LabAttester, LabVerifier, MeasurementAllowlist, ModelCatalog, ReplayCache, SealedJob, Tier,
};

use crate::error::RuntimeError;
use crate::model::{self, MODEL_NAME};
use crate::pack::HostedSet;

/// What this process is allowed to claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStatus {
    /// Always false here. A confidential GPU or CPU is not present in this build.
    pub hardware_p2: bool,
    /// Always false here. Consumer GPUs and this host are not NVIDIA CC.
    pub gpu_confidential: bool,
    /// `lab-untrusted` until a vendor quote verifier is wired in.
    pub quote_kind: &'static str,
    /// Pinned model name.
    pub model_name: &'static str,
    /// Digest of the loaded weights.
    pub model_digest: [u8; 32],
    /// Runtime measurement, also the executor id.
    pub measurement: [u8; 32],
}

/// Public card a client reads before it seals. It contains no prompt.
#[derive(Clone, Debug)]
pub struct NodeCard {
    /// Lab advertisement. Verify it before sealing.
    pub advertisement: Advertisement,
    /// Model the executor loaded.
    pub model_digest: [u8; 32],
    /// Model name, for display. Trust decisions use the digest, never the name.
    pub model_name: String,
    /// Always false from [`Executor::card`].
    pub hardware_p2: bool,
    /// Always `lab-untrusted` from [`Executor::card`].
    pub quote_kind: &'static str,
}

/// How long a card stays valid, in seconds. Clients refuse it after that.
pub const ADVERTISEMENT_SECS: u64 = 3_600;

/// One local worker: keys, lab attester, pinned weights, replay cache.
pub struct Executor {
    keys: EnclaveKeys,
    attester: LabAttester,
    transport_public: [u8; 32],
    weights: [u8; 256],
    model_digest: [u8; 32],
    replay: ReplayCache,
    log: HostLog,
    catalog: Option<ModelCatalog>,
    hosted: HostedSet,
    denied: Vec<[u8; 32]>,
}

impl std::fmt::Debug for Executor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Executor { redacted }")
    }
}

impl Executor {
    /// Start a lab executor. The quote root is fresh and is not a hardware root.
    pub fn lab() -> Result<Self, RuntimeError> {
        Self::lab_measured(LabAttester::generate())
    }

    /// Lab executor whose quote root is `attester` and whose id is the pinned measurement.
    ///
    /// Several processes can share one lab root. They still have distinct HPKE keys.
    pub fn lab_measured(attester: LabAttester) -> Result<Self, RuntimeError> {
        let weights = model::pinned_weights();
        let model_digest = model::model_digest(&weights);
        let measurement = model::runtime_measurement(&model_digest);
        Self::from_attester(attester, measurement, weights, model_digest)
    }

    /// Ordinary worker. Its id is not the pinned measurement, so it cannot take P2.
    pub fn consumer(attester: LabAttester) -> Result<Self, RuntimeError> {
        let weights = model::pinned_weights();
        let model_digest = model::model_digest(&weights);
        let measurement = model::runtime_measurement(&model_digest);
        let mut worker_id = [0u8; 32];
        OsRng.fill_bytes(&mut worker_id);
        if worker_id == measurement {
            worker_id[0] ^= 0xff;
        }
        Self::from_attester(attester, worker_id, weights, model_digest)
    }

    fn from_attester(
        attester: LabAttester,
        worker_id: [u8; 32],
        weights: [u8; 256],
        model_digest: [u8; 32],
    ) -> Result<Self, RuntimeError> {
        let keys = EnclaveKeys::generate(worker_id)?;
        Ok(Self {
            keys,
            attester,
            transport_public: [0u8; 32],
            weights,
            model_digest,
            replay: ReplayCache::default(),
            log: HostLog::default(),
            catalog: None,
            hosted: HostedSet::new(),
            denied: Vec::new(),
        })
    }

    /// Name the transport key this node serves on. Its cards carry the key inside the
    /// quoted report data, so a client can tell the node holds it. A node that never
    /// calls this advertises 32 zero bytes, which no network client accepts.
    pub fn set_transport_public(&mut self, key: [u8; 32]) {
        self.transport_public = key;
    }

    /// Replace the set of hosted models in one step. A job sees all of the old set or all of
    /// the new. `catalog` decides whether each model is approved at the moment of each job,
    /// and a digest in `denied` is refused whatever the catalog says.
    pub fn set_models(&mut self, catalog: ModelCatalog, hosted: HostedSet, denied: Vec<[u8; 32]>) {
        self.catalog = Some(catalog);
        self.hosted = hosted;
        self.denied = denied;
    }

    /// The hosted models, for a reload that keeps the ones already loaded.
    pub fn hosted_snapshot(&self) -> HostedSet {
        self.hosted.clone()
    }

    /// Names of the hosted models, sorted.
    pub fn hosted_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.hosted.values().map(|m| m.id.clone()).collect();
        ids.sort();
        ids
    }

    /// Why a hosted model may not run right now, or `Ok` when it may.
    fn check_hosted(&self, digest: &[u8; 32], now: u64) -> Result<(), RuntimeError> {
        if self.denied.contains(digest) {
            return Err(RuntimeError::Envelope(
                suricomai_envelope::EnvelopeError::ModelNotApproved,
            ));
        }
        let catalog = self
            .catalog
            .as_ref()
            .ok_or(RuntimeError::ModelUnavailable)?;
        catalog.require_approved(digest, now)?;
        Ok(())
    }

    /// The card for a hosted model, valid from `now`. It fails when the model is not
    /// hosted, is denied, or is not approved at `now`.
    pub fn model_card(
        &self,
        digest: &[u8; 32],
        nonce: [u8; 32],
        now: u64,
    ) -> Result<NodeCard, RuntimeError> {
        let model = self
            .hosted
            .get(digest)
            .ok_or(RuntimeError::ModelUnavailable)?;
        self.check_hosted(digest, now)?;
        Ok(NodeCard {
            advertisement: advertise(
                &self.keys,
                nonce,
                now,
                now.saturating_add(ADVERTISEMENT_SECS),
                self.transport_public,
                &self.attester,
            )?,
            model_digest: *digest,
            model_name: model.id.clone(),
            hardware_p2: false,
            quote_kind: "lab-untrusted",
        })
    }

    /// Verifier a second machine needs. This does not reveal the signing key.
    pub fn verifier(&self) -> LabVerifier {
        self.attester.verifier()
    }

    /// Host log. Lines are metadata and static codes.
    pub fn log(&self) -> &HostLog {
        &self.log
    }

    /// Status a caller can show. Hardware P2 is false.
    pub fn status(&self) -> NodeStatus {
        NodeStatus {
            hardware_p2: false,
            gpu_confidential: false,
            quote_kind: "lab-untrusted",
            model_name: MODEL_NAME,
            model_digest: self.model_digest,
            measurement: self.keys.executor_id(),
        }
    }

    /// This function exists so a caller cannot quietly relabel the node.
    pub fn claim_hardware_p2(&self) -> Result<(), RuntimeError> {
        Err(RuntimeError::NotHardwareP2)
    }

    /// Advertisement plus the model digest, valid for [`ADVERTISEMENT_SECS`] from `now`.
    /// `nonce` is chosen by the caller.
    pub fn card(&self, nonce: [u8; 32], now: u64) -> Result<NodeCard, RuntimeError> {
        let status = self.status();
        Ok(NodeCard {
            advertisement: advertise(
                &self.keys,
                nonce,
                now,
                now.saturating_add(ADVERTISEMENT_SECS),
                self.transport_public,
                &self.attester,
            )?,
            model_digest: status.model_digest,
            model_name: status.model_name.to_string(),
            hardware_p2: false,
            quote_kind: "lab-untrusted",
        })
    }

    /// Card for the local text model. Fails when the weights are not installed.
    pub fn text_card(&self, nonce: [u8; 32], now: u64) -> Result<NodeCard, RuntimeError> {
        let digest = crate::text_model::installed_digest().ok_or(RuntimeError::ModelUnavailable)?;
        Ok(NodeCard {
            advertisement: advertise(
                &self.keys,
                nonce,
                now,
                now.saturating_add(ADVERTISEMENT_SECS),
                self.transport_public,
                &self.attester,
            )?,
            model_digest: digest,
            model_name: crate::text_model::TEXT_MODEL_NAME.to_string(),
            hardware_p2: false,
            quote_kind: "lab-untrusted",
        })
    }

    /// Public key of this node's lab quote root. A development client needs it to verify
    /// the node's quote. A vendor root replaces it once a hardware verifier exists.
    pub fn lab_root(&self) -> [u8; 32] {
        self.attester.verifying_bytes()
    }

    /// Open one sealed job, run the pinned model, and return a sealed result.
    ///
    /// GPU jobs and wrong model digests are refused from the public header,
    /// before the prompt is decrypted.
    pub fn handle(&mut self, sealed: &[u8], now: u64) -> Result<Vec<u8>, RuntimeError> {
        let job = SealedJob::from_bytes(sealed)?;
        let contract = job.contract();
        if contract.needs_gpu {
            self.log.record(
                &contract.job_id,
                contract.size_class,
                &job.executor_id(),
                RuntimeError::GpuNotConfidential.code(),
            );
            return Err(RuntimeError::GpuNotConfidential);
        }
        let hosted_job = self.hosted.get(&contract.model_digest).cloned();
        if hosted_job.is_some() {
            // Refused before the prompt is decrypted: a hosted model runs on this host, so it
            // is never private, and it must be approved at this moment, not only at load.
            let refusal = if contract.tier == Tier::P2 {
                Some(RuntimeError::NotHardwareP2)
            } else {
                self.check_hosted(&contract.model_digest, now).err()
            };
            if let Some(err) = refusal {
                self.log.record(
                    &contract.job_id,
                    contract.size_class,
                    &job.executor_id(),
                    err.code(),
                );
                return Err(err);
            }
        }
        let text_digest = crate::text_model::installed_digest();
        let text_job = hosted_job.is_none() && text_digest == Some(contract.model_digest);
        if contract.model_digest != self.model_digest && !text_job && hosted_job.is_none() {
            self.log.record(
                &contract.job_id,
                contract.size_class,
                &job.executor_id(),
                RuntimeError::ModelMismatch.code(),
            );
            return Err(RuntimeError::ModelMismatch);
        }
        let mut allowlist = MeasurementAllowlist::new();
        allowlist.insert(self.keys.executor_id());
        let opened = open_job(
            sealed,
            &self.keys,
            &allowlist,
            now,
            &mut self.replay,
            &mut self.log,
        )?;
        let started = std::time::Instant::now();
        let (answer, token_count) = if let Some(model) = &hosted_job {
            model
                .engine
                .lock()
                .map_err(|_| RuntimeError::TextFailed)?
                .answer(
                    opened.prompt(),
                    opened.params(),
                    opened.contract().max_output_bytes,
                )?
        } else if text_job {
            crate::text_model::generate(
                opened.prompt(),
                opened.params(),
                opened.contract().max_output_bytes,
            )?
        } else {
            let answer = model::infer(
                &self.weights,
                opened.prompt(),
                opened.params(),
                opened.contract().max_output_bytes,
            );
            let token_count = u64::try_from(answer.len()).unwrap_or(u64::MAX);
            (answer, token_count)
        };
        let elapsed = started.elapsed().as_secs();
        let started_at = now;
        let finished_at = now.saturating_add(elapsed);
        let mut quote_nonce = [0u8; 32];
        let mut stealth = [0u8; 32];
        OsRng.fill_bytes(&mut quote_nonce);
        OsRng.fill_bytes(&mut stealth);
        let attestation = match opened.contract().tier {
            Tier::P2 => JobAttestation::Quote(&self.attester),
            Tier::P0 | Tier::P1 => JobAttestation::NotRequired,
        };
        let result = finish_job(
            &opened,
            &answer,
            token_count,
            quote_nonce,
            [0u8; 32],
            stealth,
            started_at,
            finished_at,
            None,
            &self.keys,
            attestation,
        )?;
        let job_id = opened.contract().job_id;
        let size_class = opened.contract().size_class;
        let executor_id = self.keys.executor_id();
        self.log
            .record(&job_id, size_class, &executor_id, "finished");
        Ok(result.to_bytes()?)
    }
}
