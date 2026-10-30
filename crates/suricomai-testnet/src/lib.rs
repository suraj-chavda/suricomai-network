// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! SuriComAI **settlement simulator**.
//!
//! Exercises multi-role fee split, proof audit, and [`suricomai_escrow`] transitions
//! before the live chain module exists. Simulated ledger units follow the fee
//! rules but are not on-chain SUR. Quotes are lab quotes, never hardware evidence.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::time::Instant;

use rand::rngs::OsRng;
use rand::RngCore;
use suricomai_envelope::{
    audit_proof, AuditTarget, InferenceParams, JobVerification, LabAttester, MeasurementAllowlist,
    SealedJob, SealedResult, Tier,
};
use suricomai_escrow::{EscrowError, JobEscrow, Release, Split};
use suricomai_runtime::{
    model_digest, pinned_weights, runtime_measurement, Client, Completion, Executor, JobRequest,
    PrivacyLabel, RuntimeError,
};

const JOB_FEE: u64 = 1_000;
const EXECUTORS: usize = 3;
const VALIDATORS: usize = 3;
const RELAYS: usize = 2;

/// Why a testnet call stopped. Display text is a fixed code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestnetError {
    /// The runtime or the envelope refused the call.
    Runtime(RuntimeError),
    /// A relay on the chosen path is stopped.
    RelayDown,
    /// The proof did not pay anyone.
    NotPaid,
    /// The escrow machine refused the transition.
    Escrow(EscrowError),
}

impl std::fmt::Display for TestnetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for TestnetError {}

impl TestnetError {
    /// Stable code. It is not a prompt.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Runtime(err) => err.code(),
            Self::RelayDown => "relay_down",
            Self::NotPaid => "not_paid",
            Self::Escrow(err) => err.code(),
        }
    }
}

impl From<EscrowError> for TestnetError {
    fn from(err: EscrowError) -> Self {
        Self::Escrow(err)
    }
}

impl From<RuntimeError> for TestnetError {
    fn from(err: RuntimeError) -> Self {
        Self::Runtime(err)
    }
}

impl From<suricomai_envelope::EnvelopeError> for TestnetError {
    fn from(err: suricomai_envelope::EnvelopeError) -> Self {
        Self::Runtime(RuntimeError::from(err))
    }
}

/// What the chain holds for one job before any proof arrives.
#[derive(Clone, Copy, Debug)]
pub struct JobLock {
    /// Job being locked.
    pub job_id: [u8; 32],
    /// Hash of the one contract a proof may close.
    pub contract_hash: [u8; 32],
    /// Fee held for the job.
    pub fee: u64,
    /// Bond the worker posts.
    pub bond: u64,
    /// Expiry in unix seconds.
    pub expiry: u64,
    /// Worker key that is proven and paid.
    pub worker: [u8; 32],
}

/// A settled job kept so the replay scenario can submit it again.
type LastWire = (Vec<u8>, Vec<u8>, bool, [u8; 32], u64);

/// The chain's clock when a proof is submitted: the caller's start time, the wait, and one
/// second of rounding. It never comes from the proof.
fn settlement_clock(now: u64, began: Instant) -> u64 {
    now.saturating_add(began.elapsed().as_secs())
        .saturating_add(1)
}

/// Mock balances after the gate scenario. Units are the job fee, not issued SUR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Balances {
    /// Attested lab executors, in index order.
    pub executors: [u64; EXECUTORS],
    /// Ordinary worker that may take P1 jobs.
    pub consumer: u64,
    /// Validators that checked proofs.
    pub validators: [u64; VALIDATORS],
    /// Relays that forwarded a sealed job.
    pub relays: [u64; RELAYS],
    /// Fee remainder, including the no-relay share.
    pub burn: u64,
    /// Worker whose measurement is not registered. Stays zero.
    pub impostor: u64,
    /// Fee and bond returned to the user. Not a payment to a worker.
    pub refunded: u64,
}

/// What the gate scenario observed. Prompt bytes are not a field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateReport {
    /// Mock ledger.
    pub balances: Balances,
    /// P2 to the consumer was rejected before the prompt was sealed.
    pub consumer_rejected_for_p2: bool,
    /// A stopped relay did not stop a job pinned straight to an executor.
    pub direct_job_survived_relay_failure: bool,
    /// A relay path failed while that relay was stopped.
    pub relay_path_failed: bool,
    /// Some relay stored bytes that contain the canary prompt.
    pub relay_saw_prompt: bool,
    /// An executor log line contains the canary prompt.
    pub log_saw_prompt: bool,
    /// Any node accepted a hardware P2 claim.
    pub hardware_p2_claimed: bool,
    /// Privacy label on a lab P2 completion.
    pub private_label: PrivacyLabel,
    /// Privacy label on the consumer P1 completion.
    pub transit_label: PrivacyLabel,
}

struct Relay {
    up: bool,
    carried: Vec<Vec<u8>>,
}

/// Three executors, one consumer, one unregistered worker, two relays, three validators.
pub struct Testnet {
    client: Client,
    executors: Vec<Executor>,
    consumer: Executor,
    impostor: Executor,
    relays: [Relay; RELAYS],
    allowlist: MeasurementAllowlist,
    verifier: suricomai_envelope::LabVerifier,
    measurement: [u8; 32],
    executor_receipts: [[u8; 32]; EXECUTORS],
    consumer_receipt: [u8; 32],
    ledger: Balances,
    escrows: HashMap<[u8; 32], JobEscrow>,
    /// Jobs with a fee and a bond held and no proof yet.
    open: HashMap<[u8; 32], JobEscrow>,
    last_wire: Option<LastWire>,
    pinned_job_id: Option<[u8; 32]>,
}

impl Testnet {
    /// Start the local roles. Quotes share one lab root. Hardware P2 stays false.
    pub fn local() -> Result<Self, TestnetError> {
        let attester = LabAttester::generate();
        let verifier = attester.verifier();
        let weights = pinned_weights();
        let digest = model_digest(&weights);
        let measurement = runtime_measurement(&digest);
        let mut allowlist = MeasurementAllowlist::new();
        allowlist.insert(measurement);
        let client = Client::new(verifier.clone(), measurement)?;
        let mut executors = Vec::with_capacity(EXECUTORS);
        let mut executor_receipts = [[0u8; 32]; EXECUTORS];
        for (index, receipt) in executor_receipts.iter_mut().enumerate() {
            let executor = Executor::lab_measured(attester.clone())?;
            *receipt = executor
                .card([u8::try_from(index).unwrap_or(0); 32], 0)?
                .advertisement
                .receipt_public;
            executors.push(executor);
        }
        let consumer = Executor::consumer(attester.clone())?;
        let impostor = Executor::consumer(attester)?;
        let consumer_receipt = consumer.card([9u8; 32], 0)?.advertisement.receipt_public;
        Ok(Self {
            client,
            executors,
            consumer,
            impostor,
            relays: [
                Relay {
                    up: true,
                    carried: Vec::new(),
                },
                Relay {
                    up: true,
                    carried: Vec::new(),
                },
            ],
            allowlist,
            verifier,
            measurement,
            executor_receipts,
            consumer_receipt,
            ledger: Balances {
                executors: [0; EXECUTORS],
                consumer: 0,
                validators: [0; VALIDATORS],
                relays: [0; RELAYS],
                burn: 0,
                impostor: 0,
                refunded: 0,
            },
            escrows: HashMap::new(),
            open: HashMap::new(),
            last_wire: None,
            pinned_job_id: None,
        })
    }

    /// Balances so far.
    pub fn balances(&self) -> Balances {
        self.ledger
    }

    /// Stop one relay. The other relay and every direct path stay up.
    pub fn stop_relay(&mut self, index: usize) {
        if let Some(relay) = self.relays.get_mut(index) {
            relay.up = false;
        }
    }

    /// P2 job pinned to one attested executor, with no relay.
    pub fn run_private_direct(
        &mut self,
        executor: usize,
        prompt: &[u8],
        now: u64,
    ) -> Result<Completion, TestnetError> {
        self.run_private(executor, prompt, now, false)
    }

    /// P2 job carried by both relays, then pinned to one attested executor.
    pub fn run_private_via_relays(
        &mut self,
        executor: usize,
        prompt: &[u8],
        now: u64,
    ) -> Result<Completion, TestnetError> {
        self.run_private(executor, prompt, now, true)
    }

    /// P1 job on the consumer. The worker can read the prompt. The relays do not.
    pub fn run_consumer_job(
        &mut self,
        prompt: &[u8],
        now: u64,
    ) -> Result<Completion, TestnetError> {
        let card = self.consumer.card([4u8; 32], now)?;
        let request = job_request(prompt, now, self.take_job_id());
        let mut sealed_job = Vec::new();
        let mut response = Vec::new();
        let began = Instant::now();
        let completion = {
            let client = &self.client;
            let consumer = &mut self.consumer;
            client.complete_transit(&card, &request, |sealed| {
                sealed_job = sealed.to_vec();
                let bytes = consumer.handle(sealed, now)?;
                response = bytes.clone();
                Ok(bytes)
            })?
        };
        let assigned = self.consumer_receipt;
        let settled = settlement_clock(now, began);
        if !self.settle(&sealed_job, &response, false, assigned, settled)? {
            return Err(TestnetError::NotPaid);
        }
        Ok(completion)
    }

    /// Try a P2 job on the consumer. The prompt is not sealed. The balance does not move.
    pub fn reject_consumer_private_job(
        &mut self,
        prompt: &[u8],
        now: u64,
    ) -> Result<(), TestnetError> {
        let before = self.ledger.consumer;
        let card = self.consumer.card([5u8; 32], now)?;
        let mut called = false;
        let probe = job_request(prompt, now, self.take_job_id());
        let err = self
            .client
            .complete(&card, &probe, |_| {
                called = true;
                Ok(Vec::new())
            })
            .unwrap_err();
        if called || err != RuntimeError::ModelMismatch || self.ledger.consumer != before {
            return Err(TestnetError::Runtime(err));
        }
        Ok(())
    }

    /// Run a P1 job on an unregistered worker and pay nothing for it.
    pub fn run_unregistered_job(&mut self, prompt: &[u8], now: u64) -> Result<(), TestnetError> {
        let card = self.impostor.card([6u8; 32], now)?;
        let request = job_request(prompt, now, self.take_job_id());
        let mut sealed_job = Vec::new();
        let mut response = Vec::new();
        let began = Instant::now();
        let _completion = {
            let client = &self.client;
            let impostor = &mut self.impostor;
            client.complete_transit(&card, &request, |sealed| {
                sealed_job = sealed.to_vec();
                let bytes = impostor.handle(sealed, now)?;
                response = bytes.clone();
                Ok(bytes)
            })?
        };
        let assigned = self
            .impostor
            .card([6u8; 32], now)?
            .advertisement
            .receipt_public;
        let paid = self.settle(
            &sealed_job,
            &response,
            false,
            assigned,
            settlement_clock(now, began),
        )?;
        if paid || self.ledger.impostor != 0 {
            return Err(TestnetError::NotPaid);
        }
        let private_card = self.impostor.card([7u8; 32], now)?;
        let mut called = false;
        let probe = job_request(prompt, now, self.take_job_id());
        let err = self
            .client
            .complete(&private_card, &probe, |_| {
                called = true;
                Ok(Vec::new())
            })
            .unwrap_err();
        if called || err != RuntimeError::ModelMismatch {
            return Err(TestnetError::Runtime(err));
        }
        Ok(())
    }

    fn run_private(
        &mut self,
        executor: usize,
        prompt: &[u8],
        now: u64,
        via_relays: bool,
    ) -> Result<Completion, TestnetError> {
        if executor >= EXECUTORS {
            return Err(TestnetError::NotPaid);
        }
        if via_relays && self.relays.iter().any(|relay| !relay.up) {
            return Err(TestnetError::RelayDown);
        }
        let card = self.executors[executor].card([executor as u8; 32], now)?;
        let request = job_request(prompt, now, self.take_job_id());
        let mut sealed_job = Vec::new();
        let mut response = Vec::new();
        let began = Instant::now();
        let completion = {
            let client = &self.client;
            let executors = &mut self.executors;
            let relays = &mut self.relays;
            client.complete(&card, &request, |sealed| {
                sealed_job = sealed.to_vec();
                if via_relays {
                    for relay in relays.iter_mut() {
                        relay.carried.push(sealed.to_vec());
                    }
                }
                let bytes = executors[executor].handle(sealed, now)?;
                response = bytes.clone();
                Ok(bytes)
            })?
        };
        let assigned = self.executor_receipts[executor];
        let settled = settlement_clock(now, began);
        if !self.settle(&sealed_job, &response, via_relays, assigned, settled)? {
            return Err(TestnetError::NotPaid);
        }
        Ok(completion)
    }

    /// Credit the assigned, registered worker for this result. Unknown measurements credit
    /// nothing. `assigned` is the receipt key of the worker the user pinned. It comes from the
    /// assignment, never from the proof. `settlement_now` is the chain's clock.
    fn settle(
        &mut self,
        sealed: &[u8],
        response: &[u8],
        via_relays: bool,
        assigned: [u8; 32],
        settlement_now: u64,
    ) -> Result<bool, TestnetError> {
        let job = SealedJob::from_bytes(sealed)?;
        let result = SealedResult::from_bytes(response)?;
        let contract = job.contract();
        let proof = result.proof();
        if settlement_now >= contract.expiry {
            return Ok(false);
        }
        let payee = if proof.tier == Tier::P2 && proof.executor_id == self.measurement {
            self.executor_receipts
                .iter()
                .position(|receipt| receipt == &assigned)
                .map(Payee::Executor)
        } else if proof.tier == Tier::P1 && assigned == self.consumer_receipt {
            Some(Payee::Consumer)
        } else {
            None
        };
        let Some(payee) = payee else {
            return Ok(false);
        };
        let target = AuditTarget::new(job.executor_id(), assigned);
        if !self.validators_accept(contract, &result, &target, settlement_now)? {
            return Ok(false);
        }
        if self.escrows.contains_key(&contract.job_id) || self.open.contains_key(&contract.job_id) {
            return Err(EscrowError::Replay.into());
        }
        let mut escrow = JobEscrow::lock(
            contract.job_id,
            proof.contract_hash,
            contract.fee,
            contract.bond_required,
            contract.expiry,
        )?;
        escrow.accept(
            settlement_now,
            proof.worker_stealth_key,
            contract.bond_required,
        )?;
        match escrow.prove(
            settlement_now,
            proof.worker_stealth_key,
            proof.contract_hash,
        ) {
            Ok(()) => {}
            Err(EscrowError::Expired) => {
                escrow.expire(settlement_now)?;
                self.remember_refund(contract.job_id, escrow)?;
                return Ok(false);
            }
            Err(err) => return Err(err.into()),
        }
        let release = escrow.pay(via_relays)?;
        let split = release.fee_split.ok_or(TestnetError::NotPaid)?;
        self.escrows.insert(contract.job_id, escrow);
        self.credit(payee, split, via_relays);
        self.last_wire = Some((
            sealed.to_vec(),
            response.to_vec(),
            via_relays,
            assigned,
            settlement_now,
        ));
        Ok(true)
    }

    /// Use `job_id` for the next job instead of a random one. For scenarios that need a job
    /// id known in advance.
    pub fn pin_next_job_id(&mut self, job_id: [u8; 32]) {
        self.pinned_job_id = Some(job_id);
    }

    fn take_job_id(&mut self) -> [u8; 32] {
        self.pinned_job_id.take().unwrap_or_else(|| {
            let mut id = [0u8; 32];
            OsRng.fill_bytes(&mut id);
            id
        })
    }

    /// Submit the previous settled job again. The escrow stays paid and the error is `replay`.
    pub fn replay_last(&mut self) -> Result<bool, TestnetError> {
        let Some((sealed, response, via_relays, assigned, settlement_now)) = self.last_wire.clone()
        else {
            return Err(TestnetError::NotPaid);
        };
        self.settle(&sealed, &response, via_relays, assigned, settlement_now)
    }

    /// Hold a fee and a worker's bond for a job. No proof has arrived yet.
    pub fn lock_job(&mut self, lock: JobLock, now: u64) -> Result<(), TestnetError> {
        let job_id = lock.job_id;
        if self.escrows.contains_key(&job_id) || self.open.contains_key(&job_id) {
            return Err(EscrowError::Replay.into());
        }
        let mut escrow =
            JobEscrow::lock(job_id, lock.contract_hash, lock.fee, lock.bond, lock.expiry)?;
        escrow.accept(now, lock.worker, lock.bond)?;
        self.open.insert(job_id, escrow);
        Ok(())
    }

    /// No proof arrived before the job's expiry.
    ///
    /// The amounts come from what [`Self::lock_job`] held, never from the caller. The fee
    /// and the bond go back to the user. No executor is credited.
    pub fn refund_expired(&mut self, job_id: [u8; 32], now: u64) -> Result<Release, TestnetError> {
        let mut escrow = self.open.remove(&job_id).ok_or(EscrowError::BadPhase)?;
        if let Err(err) = escrow.expire(now) {
            self.open.insert(job_id, escrow);
            return Err(err.into());
        }
        self.remember_refund(job_id, escrow)
    }

    fn remember_refund(
        &mut self,
        job_id: [u8; 32],
        mut escrow: JobEscrow,
    ) -> Result<Release, TestnetError> {
        if self.escrows.contains_key(&job_id) {
            return Err(EscrowError::Replay.into());
        }
        let release = escrow.refund()?;
        self.ledger.refunded = self
            .ledger
            .refunded
            .saturating_add(release.fee_to_user)
            .saturating_add(release.bond_to_user);
        self.escrows.insert(job_id, escrow);
        Ok(release)
    }

    fn validators_accept(
        &self,
        contract: &suricomai_envelope::PromptContract,
        result: &SealedResult,
        target: &AuditTarget,
        audit_now: u64,
    ) -> Result<bool, TestnetError> {
        let mut accepts = 0;
        for _ in 0..VALIDATORS {
            let verification = match contract.tier {
                Tier::P2 => JobVerification::Quote(&self.verifier),
                Tier::P0 | Tier::P1 => JobVerification::SignatureOnly,
            };
            if audit_proof(
                contract,
                result,
                target,
                &self.allowlist,
                verification,
                audit_now,
            )
            .is_ok()
            {
                accepts += 1;
            }
        }
        Ok(accepts == VALIDATORS)
    }

    fn credit(&mut self, payee: Payee, split: Split, via_relays: bool) {
        let relay_count = if via_relays { RELAYS } else { 0 };
        let validator_each = split.validators / VALIDATORS as u64;
        let relay_each = if relay_count == 0 {
            0
        } else {
            split.relays / relay_count as u64
        };
        let burn = split
            .burn
            .saturating_add(split.validators % VALIDATORS as u64)
            .saturating_add(if relay_count == 0 {
                0
            } else {
                split.relays % relay_count as u64
            });
        match payee {
            Payee::Executor(index) => {
                let paid = &mut self.ledger.executors[index];
                *paid = paid.saturating_add(split.executor);
            }
            Payee::Consumer => {
                self.ledger.consumer = self.ledger.consumer.saturating_add(split.executor);
            }
        }
        for share in &mut self.ledger.validators {
            *share = share.saturating_add(validator_each);
        }
        if via_relays {
            for share in &mut self.ledger.relays {
                *share = share.saturating_add(relay_each);
            }
        }
        self.ledger.burn = self.ledger.burn.saturating_add(burn);
    }
}

enum Payee {
    Executor(usize),
    Consumer,
}

/// Run the full gate scenario on a fresh local testnet.
pub fn run_gates(prompt: &[u8]) -> Result<GateReport, TestnetError> {
    let mut net = Testnet::local()?;
    let via = net.run_private_via_relays(0, prompt, 10)?;
    let _direct = net.run_private_direct(1, prompt, 20)?;
    net.stop_relay(0);
    let survived = net.run_private_direct(2, prompt, 30)?;
    let relay_path_failed = matches!(
        net.run_private_via_relays(0, prompt, 40).unwrap_err(),
        TestnetError::RelayDown
    );
    let transit = net.run_consumer_job(prompt, 50)?;
    net.reject_consumer_private_job(prompt, 60)?;
    net.run_unregistered_job(prompt, 70)?;
    let relay_saw_prompt = net.relays.iter().any(|relay| {
        relay
            .carried
            .iter()
            .any(|bytes| bytes.windows(prompt.len()).any(|window| window == prompt))
    });
    let log_saw_prompt = net
        .executors
        .iter()
        .chain(std::iter::once(&net.consumer))
        .chain(std::iter::once(&net.impostor))
        .any(|executor| executor.log().contains(&String::from_utf8_lossy(prompt)));
    let hardware_p2_claimed = net
        .executors
        .iter()
        .any(|executor| executor.claim_hardware_p2().is_ok())
        || net.consumer.claim_hardware_p2().is_ok();
    Ok(GateReport {
        balances: net.balances(),
        consumer_rejected_for_p2: true,
        direct_job_survived_relay_failure: survived.privacy == PrivacyLabel::LabUntrusted,
        relay_path_failed,
        relay_saw_prompt,
        log_saw_prompt,
        hardware_p2_claimed,
        private_label: via.privacy,
        transit_label: transit.privacy,
    })
}

fn job_request(prompt: &[u8], now: u64, job_id: [u8; 32]) -> JobRequest {
    JobRequest {
        job_id,
        chain_id: 7,
        prompt: prompt.to_vec(),
        params: InferenceParams::new([0u8; 32], 0, 16).expect("params"),
        now,
        expiry: now.saturating_add(120),
        fee: JOB_FEE,
        bond_required: JOB_FEE,
        max_output_bytes: 16,
        size_class: 4_096,
        max_latency_ms: 0,
        user_pay_key: [0u8; 32],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &[u8] = b"CANARY-SECRET-suricomai-9f3a wire-canary";

    #[test]
    fn gate_scenario() {
        let report = run_gates(CANARY).unwrap();
        assert_eq!(report.balances.executors, [700, 700, 700]);
        assert_eq!(report.balances.consumer, 700);
        assert_eq!(report.balances.validators, [200, 200, 200]);
        assert_eq!(report.balances.relays, [25, 25]);
        assert_eq!(report.balances.burn, 550);
        assert_eq!(report.balances.impostor, 0);
        assert_eq!(report.balances.refunded, 0);
        assert!(report.consumer_rejected_for_p2);
        assert!(report.direct_job_survived_relay_failure);
        assert!(report.relay_path_failed);
        assert!(!report.relay_saw_prompt);
        assert!(!report.log_saw_prompt);
        assert!(!report.hardware_p2_claimed);
        assert_eq!(report.private_label, PrivacyLabel::LabUntrusted);
        assert_eq!(report.transit_label, PrivacyLabel::NotPrivate);
    }

    #[test]
    fn a_second_settle_is_replay_and_an_expired_job_refunds() {
        let mut net = Testnet::local().unwrap();
        net.run_private_direct(0, b"ping", 10).unwrap();
        assert_eq!(net.replay_last().unwrap_err().code(), "replay");
        assert_eq!(net.balances().executors[0], 700);
        net.lock_job(lock([3u8; 32], 50), 20).unwrap();
        assert_eq!(
            net.refund_expired([3u8; 32], 49).unwrap_err().code(),
            "not_expired"
        );
        assert_eq!(
            net.refund_expired([4u8; 32], 60).unwrap_err().code(),
            "bad_phase",
            "an unknown job has nothing held to refund"
        );
        let release = net.refund_expired([3u8; 32], 50).unwrap();
        assert_eq!(
            net.refund_expired([3u8; 32], 50).unwrap_err().code(),
            "bad_phase",
            "a refunded job cannot be refunded twice"
        );
        assert_eq!(release.fee_to_user, 1_000);
        assert_eq!(release.bond_to_user, 1_000);
        assert_eq!(release.fee_split, None);
        assert_eq!(net.balances().refunded, 2_000);
        assert_eq!(net.balances().executors, [700, 0, 0]);
        assert_eq!(net.balances().burn, 150);
    }
    fn lock(job_id: [u8; 32], expiry: u64) -> JobLock {
        JobLock {
            job_id,
            contract_hash: [6u8; 32],
            fee: 1_000,
            bond: 1_000,
            expiry,
            worker: [8u8; 32],
        }
    }

    #[test]
    fn a_job_locked_on_chain_cannot_also_be_settled_and_refunded() {
        let mut net = Testnet::local().unwrap();
        let job = [0x5a; 32];
        net.lock_job(lock(job, 130), 5).unwrap();
        net.pin_next_job_id(job);
        assert_eq!(
            net.run_private_direct(0, b"ping", 10).unwrap_err().code(),
            "replay",
            "a locked job id cannot be paid through the open path"
        );
        assert_eq!(net.balances().executors, [0, 0, 0]);
        let release = net.refund_expired(job, 130).unwrap();
        assert_eq!(release.fee_to_user, 1_000);
        assert_eq!(net.balances().refunded, 2_000);
    }

    #[test]
    fn a_paid_job_cannot_be_locked_or_refunded_afterwards() {
        let mut net = Testnet::local().unwrap();
        let job = [0x6b; 32];
        net.pin_next_job_id(job);
        net.run_private_direct(0, b"ping", 10).unwrap();
        assert_eq!(net.balances().executors[0], 700);
        assert_eq!(
            net.lock_job(lock(job, 130), 5).unwrap_err().code(),
            "replay"
        );
        assert_eq!(
            net.refund_expired(job, 500).unwrap_err().code(),
            "bad_phase"
        );
        assert_eq!(net.balances().refunded, 0);
        assert_eq!(net.balances().executors[0], 700);
    }

    #[test]
    fn a_worker_cannot_complete_a_job_assigned_to_another_worker() {
        let mut net = Testnet::local().unwrap();
        let card = net.executors[1].card([1u8; 32], 10).unwrap();
        let request = job_request(b"ping", 10, [0x7c; 32]);
        let mut sealed_job = Vec::new();
        let mut response = Vec::new();
        net.client
            .complete(&card, &request, |sealed| {
                sealed_job = sealed.to_vec();
                response = net.executors[1].handle(sealed, 10)?;
                Ok(response.clone())
            })
            .unwrap();
        let other = net.executor_receipts[2];
        assert!(!net
            .settle(&sealed_job, &response, false, other, 12)
            .unwrap());
        assert_eq!(net.balances().executors, [0, 0, 0]);
        let right = net.executor_receipts[1];
        assert!(net
            .settle(&sealed_job, &response, false, right, 12)
            .unwrap());
        assert_eq!(net.balances().executors, [0, 700, 0]);
    }
}
