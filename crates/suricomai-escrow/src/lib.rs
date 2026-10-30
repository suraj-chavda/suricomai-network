// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Typed escrow for one prompt-contract job.
//!
//! Typed job escrow transitions. This crate does not mint
//! SUR, open a seal, or choose a worker. A later settlement module can call it.
//! Amounts are the fee and the bond the contract already named.

#![forbid(unsafe_code)]

pub mod fees;

/// Smallest fee a job may lock, in the smallest SUR unit. Below this the 70/15/5 split
/// rounds some shares to zero, so dust jobs would cost validators more than they pay.
pub const MIN_JOB_FEE: u64 = 100;

/// Phase of one job. The names match the spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Fee is locked. A bond may or may not be posted yet.
    Locked,
    /// An auditor accepted the proof before expiry.
    Proven,
    /// The fee was split once.
    Paid,
    /// Expiry won before a proof.
    Expired,
    /// The proof was a fault. The bond is not released to the worker.
    Slashed,
    /// The user has been paid back. Terminal.
    Refunded,
}

/// Why a proof was refused for payment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// P2 measurement was not on the allowlist.
    MeasurementRejected,
    /// A GPU P2 job arrived without GPU evidence.
    MissingGpuEvidence,
    /// The quote did not verify.
    BadQuote,
}

impl Fault {
    /// Stable code. It is not a prompt.
    pub const fn code(self) -> &'static str {
        match self {
            Self::MeasurementRejected => "measurement_rejected",
            Self::MissingGpuEvidence => "missing_gpu_evidence",
            Self::BadQuote => "bad_quote",
        }
    }
}

/// Why a transition was refused. Display text is a fixed code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EscrowError {
    /// The phase does not allow this event.
    BadPhase,
    /// The posted bond is below `bond_required`.
    BondTooSmall,
    /// `now >= expiry` on a prove.
    Expired,
    /// Expire was asked before `expiry`.
    NotExpired,
    /// Settle was asked again after `Paid`.
    Replay,
    /// A fee share overflowed `u64`.
    Overflow,
    /// The worker named at `prove` is not the worker who posted the bond.
    WrongWorker,
    /// The proof closes a different contract than the one this escrow was locked for.
    WrongContract,
    /// A slash must carry the hash of the proof or quote that shows the fault.
    NoEvidence,
    /// The fee is below [`MIN_JOB_FEE`], so a split would pay a worker nothing.
    FeeTooSmall,
}

impl EscrowError {
    /// Stable code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::BadPhase => "bad_phase",
            Self::BondTooSmall => "bond_too_small",
            Self::Expired => "expired",
            Self::NotExpired => "not_expired",
            Self::Replay => "replay",
            Self::Overflow => "overflow",
            Self::FeeTooSmall => "fee_too_small",
            Self::WrongWorker => "wrong_worker",
            Self::WrongContract => "wrong_contract",
            Self::NoEvidence => "no_evidence",
        }
    }
}

impl std::fmt::Display for EscrowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for EscrowError {}

/// Integer fee split. The four amounts sum to the fee.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Split {
    /// 70% to the executor.
    pub executor: u64,
    /// 15% to validators.
    pub validators: u64,
    /// 5% when a relay carried the job, otherwise 0.
    pub relays: u64,
    /// The remainder, including the relay share when no relay carried the job.
    pub burn: u64,
}

/// Where locked coins go on a terminal transition. This is not a mint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Release {
    /// Fee returned to the user.
    pub fee_to_user: u64,
    /// Bond returned to the worker.
    pub bond_to_worker: u64,
    /// Bond paid to the user because the worker missed expiry.
    pub bond_to_user: u64,
    /// Bond seized on a fault. The referee/user ratio is not frozen.
    pub bond_seized: u64,
    /// Present only on a successful settle.
    pub fee_split: Option<Split>,
    /// Worker who receives the fee split and the returned bond. Present only on a settle.
    pub payee: Option<[u8; 32]>,
}

/// One job's escrow. The prompt is not a field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobEscrow {
    job_id: [u8; 32],
    contract_hash: [u8; 32],
    fee: u64,
    bond_required: u64,
    bond: u64,
    expiry: u64,
    accepted: bool,
    phase: Phase,
    worker: Option<[u8; 32]>,
    fault: Option<Fault>,
    evidence: Option<[u8; 32]>,
}

impl JobEscrow {
    /// Lock `fee` for the contract with hash `contract_hash` until a proof, an expiry, or
    /// a fault. A proof for any other contract is refused.
    pub fn lock(
        job_id: [u8; 32],
        contract_hash: [u8; 32],
        fee: u64,
        bond_required: u64,
        expiry: u64,
    ) -> Result<Self, EscrowError> {
        if fee < MIN_JOB_FEE {
            return Err(EscrowError::FeeTooSmall);
        }
        Ok(Self {
            job_id,
            contract_hash,
            fee,
            bond_required,
            bond: 0,
            expiry,
            accepted: false,
            phase: Phase::Locked,
            worker: None,
            fault: None,
            evidence: None,
        })
    }

    /// Current phase.
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Job this escrow was locked for.
    pub fn job_id(&self) -> [u8; 32] {
        self.job_id
    }

    /// Fault recorded by [`Self::slash`], if any.
    pub fn fault(&self) -> Option<Fault> {
        self.fault
    }

    /// Evidence hash recorded by [`Self::slash`], if any.
    pub fn evidence(&self) -> Option<[u8; 32]> {
        self.evidence
    }

    /// Worker posts the bond and names who is paid. One post, only while locked, and
    /// only before expiry.
    pub fn accept(&mut self, now: u64, worker: [u8; 32], bond: u64) -> Result<(), EscrowError> {
        if self.phase != Phase::Locked || self.accepted {
            return Err(EscrowError::BadPhase);
        }
        if now >= self.expiry {
            return Err(EscrowError::Expired);
        }
        if bond < self.bond_required {
            return Err(EscrowError::BondTooSmall);
        }
        self.bond = bond;
        self.worker = Some(worker);
        self.accepted = true;
        Ok(())
    }

    /// Auditor accepted the proof before expiry.
    pub fn prove(
        &mut self,
        now: u64,
        worker: [u8; 32],
        contract_hash: [u8; 32],
    ) -> Result<(), EscrowError> {
        if self.phase != Phase::Locked || !self.accepted {
            return Err(EscrowError::BadPhase);
        }
        if now >= self.expiry {
            return Err(EscrowError::Expired);
        }
        if self.worker != Some(worker) {
            return Err(EscrowError::WrongWorker);
        }
        if self.contract_hash != contract_hash {
            return Err(EscrowError::WrongContract);
        }
        self.phase = Phase::Proven;
        Ok(())
    }

    /// Split the fee once. A second call is `replay` and leaves the phase at `Paid`.
    pub fn pay(&mut self, relays_carried: bool) -> Result<Release, EscrowError> {
        if self.phase == Phase::Paid {
            return Err(EscrowError::Replay);
        }
        if self.phase != Phase::Proven {
            return Err(EscrowError::BadPhase);
        }
        let split = split_fee(self.fee, relays_carried)?;
        let release = Release {
            fee_to_user: 0,
            bond_to_worker: self.bond,
            bond_to_user: 0,
            bond_seized: 0,
            fee_split: Some(split),
            payee: self.worker,
        };
        self.phase = Phase::Paid;
        Ok(release)
    }

    /// Move a locked job to `Expired` when `now >= expiry`.
    pub fn expire(&mut self, now: u64) -> Result<(), EscrowError> {
        if self.phase != Phase::Locked {
            return Err(EscrowError::BadPhase);
        }
        if now < self.expiry {
            return Err(EscrowError::NotExpired);
        }
        self.phase = Phase::Expired;
        Ok(())
    }

    /// Refuse payment. Legal from `Locked` or `Proven`. `evidence` is the hash of the
    /// proof or quote that shows the fault, so the slash can be checked later.
    pub fn slash(&mut self, fault: Fault, evidence: [u8; 32]) -> Result<(), EscrowError> {
        if self.phase != Phase::Locked && self.phase != Phase::Proven {
            return Err(EscrowError::BadPhase);
        }
        if evidence == [0u8; 32] {
            return Err(EscrowError::NoEvidence);
        }
        self.fault = Some(fault);
        self.evidence = Some(evidence);
        self.phase = Phase::Slashed;
        Ok(())
    }

    /// Pay the user back from `Expired` or `Slashed`.
    pub fn refund(&mut self) -> Result<Release, EscrowError> {
        let release = match self.phase {
            Phase::Expired => Release {
                fee_to_user: self.fee,
                bond_to_worker: 0,
                bond_to_user: self.bond,
                bond_seized: 0,
                fee_split: None,
                payee: None,
            },
            Phase::Slashed => Release {
                fee_to_user: self.fee,
                bond_to_worker: 0,
                bond_to_user: 0,
                bond_seized: self.bond,
                fee_split: None,
                payee: None,
            },
            _ => return Err(EscrowError::BadPhase),
        };
        self.phase = Phase::Refunded;
        Ok(release)
    }
}

/// Split `fee`. The parts sum to `fee`.
pub fn split_fee(fee: u64, relays_carried: bool) -> Result<Split, EscrowError> {
    let executor = share(fee, 70)?;
    let validators = share(fee, 15)?;
    let relays = if relays_carried { share(fee, 5)? } else { 0 };
    let assigned = executor
        .checked_add(validators)
        .and_then(|sum| sum.checked_add(relays))
        .ok_or(EscrowError::Overflow)?;
    if assigned > fee {
        return Err(EscrowError::Overflow);
    }
    Ok(Split {
        executor,
        validators,
        relays,
        burn: fee - assigned,
    })
}

fn share(fee: u64, percent: u64) -> Result<u64, EscrowError> {
    let product = u128::from(fee) * u128::from(percent) / 100;
    u64::try_from(product).map_err(|_| EscrowError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKER: [u8; 32] = [1u8; 32];
    const CONTRACT: [u8; 32] = [7u8; 32];
    const EVIDENCE: [u8; 32] = [9u8; 32];

    fn locked() -> JobEscrow {
        JobEscrow::lock([9u8; 32], CONTRACT, 1_000, 400, 100).unwrap()
    }

    #[test]
    fn pay_splits_the_fee_once_and_returns_the_bond() {
        let mut job = locked();
        job.accept(0, WORKER, 400).unwrap();
        job.prove(50, WORKER, CONTRACT).unwrap();
        let paid = job.pay(false).unwrap();
        assert_eq!(job.phase(), Phase::Paid);
        assert_eq!(
            paid.fee_split.unwrap(),
            Split {
                executor: 700,
                validators: 150,
                relays: 0,
                burn: 150,
            }
        );
        assert_eq!(paid.bond_to_worker, 400);
        assert_eq!(job.pay(false).unwrap_err(), EscrowError::Replay);
        assert_eq!(job.phase(), Phase::Paid);
    }

    #[test]
    fn relays_take_five_percent_from_the_burn() {
        let split = split_fee(1_000, true).unwrap();
        assert_eq!(split.relays, 50);
        assert_eq!(split.burn, 100);
        assert_eq!(
            split.executor + split.validators + split.relays + split.burn,
            1_000
        );
    }

    #[test]
    fn expiry_refunds_the_user_from_the_bond() {
        let mut job = locked();
        job.accept(0, WORKER, 400).unwrap();
        assert_eq!(job.expire(99).unwrap_err(), EscrowError::NotExpired);
        job.expire(100).unwrap();
        let back = job.refund().unwrap();
        assert_eq!(job.phase(), Phase::Refunded);
        assert_eq!(back.fee_to_user, 1_000);
        assert_eq!(back.bond_to_user, 400);
        assert_eq!(back.bond_to_worker, 0);
        assert_eq!(job.pay(false).unwrap_err(), EscrowError::BadPhase);
    }

    #[test]
    fn a_rejected_measurement_seizes_the_bond_and_returns_the_fee() {
        let mut job = locked();
        job.accept(0, WORKER, 400).unwrap();
        job.slash(Fault::MeasurementRejected, EVIDENCE).unwrap();
        assert_eq!(job.fault().unwrap().code(), "measurement_rejected");
        let back = job.refund().unwrap();
        assert_eq!(back.fee_to_user, 1_000);
        assert_eq!(back.bond_seized, 400);
        assert_eq!(back.fee_split, None);
        assert_eq!(job.refund().unwrap_err(), EscrowError::BadPhase);
    }

    #[test]
    fn missing_gpu_evidence_and_a_bad_quote_slash() {
        let mut gpu = locked();
        gpu.slash(Fault::MissingGpuEvidence, EVIDENCE).unwrap();
        assert_eq!(gpu.phase(), Phase::Slashed);
        let mut quote = locked();
        quote.accept(0, WORKER, 400).unwrap();
        quote.prove(1, WORKER, CONTRACT).unwrap();
        quote.slash(Fault::BadQuote, EVIDENCE).unwrap();
        assert_eq!(quote.refund().unwrap().bond_seized, 400);
    }

    #[test]
    fn prove_after_expiry_does_not_pay() {
        let mut job = locked();
        job.accept(0, WORKER, 400).unwrap();
        assert_eq!(
            job.prove(100, WORKER, CONTRACT).unwrap_err(),
            EscrowError::Expired
        );
        assert_eq!(job.phase(), Phase::Locked);
    }

    #[test]
    fn a_short_bond_and_a_second_accept_are_refused() {
        let mut job = locked();
        assert_eq!(
            job.accept(0, WORKER, 399).unwrap_err(),
            EscrowError::BondTooSmall
        );
        job.accept(0, WORKER, 400).unwrap();
        assert_eq!(
            job.accept(0, WORKER, 400).unwrap_err(),
            EscrowError::BadPhase
        );
        assert_eq!(job.pay(false).unwrap_err(), EscrowError::BadPhase);
    }

    #[test]
    fn every_fee_up_to_u64_max_splits_and_conserves_value() {
        for fee in [0, 1, 99, 101, u64::MAX / 70 + 1, u64::MAX - 1, u64::MAX] {
            for relays in [false, true] {
                let split = split_fee(fee, relays).unwrap();
                let total = u128::from(split.executor)
                    + u128::from(split.validators)
                    + u128::from(split.relays)
                    + u128::from(split.burn);
                assert_eq!(total, u128::from(fee), "fee {fee} relays {relays}");
            }
        }
    }

    #[test]
    fn only_the_worker_who_posted_the_bond_can_be_proven_and_paid() {
        let mut job = locked();
        job.accept(0, WORKER, 400).unwrap();
        assert_eq!(
            job.prove(1, [2u8; 32], CONTRACT).unwrap_err(),
            EscrowError::WrongWorker
        );
        assert_eq!(job.phase(), Phase::Locked);
        job.prove(1, WORKER, CONTRACT).unwrap();
        assert_eq!(job.pay(false).unwrap().payee, Some(WORKER));
    }

    #[test]
    fn a_proof_for_another_contract_does_not_close_this_escrow() {
        let mut job = locked();
        job.accept(0, WORKER, 400).unwrap();
        assert_eq!(
            job.prove(1, WORKER, [8u8; 32]).unwrap_err(),
            EscrowError::WrongContract
        );
        assert_eq!(job.phase(), Phase::Locked);
        job.prove(1, WORKER, CONTRACT).unwrap();
    }

    #[test]
    fn a_slash_needs_evidence_and_records_it() {
        let mut job = locked();
        assert_eq!(
            job.slash(Fault::BadQuote, [0u8; 32]).unwrap_err(),
            EscrowError::NoEvidence
        );
        assert_eq!(job.phase(), Phase::Locked);
        job.slash(Fault::BadQuote, EVIDENCE).unwrap();
        assert_eq!(job.evidence(), Some(EVIDENCE));
    }

    #[test]
    fn dust_fees_are_refused_at_lock() {
        for fee in [0, 1, MIN_JOB_FEE - 1] {
            assert_eq!(
                JobEscrow::lock([1u8; 32], CONTRACT, fee, 0, 100).unwrap_err(),
                EscrowError::FeeTooSmall
            );
        }
        let min = JobEscrow::lock([1u8; 32], CONTRACT, MIN_JOB_FEE, 0, 100).unwrap();
        let split = split_fee(MIN_JOB_FEE, true).unwrap();
        assert!(split.executor > 0 && split.validators > 0 && split.relays > 0);
        assert_eq!(min.phase(), Phase::Locked);
    }

    #[test]
    fn a_bond_posted_at_or_after_expiry_is_refused() {
        let mut job = locked();
        assert_eq!(
            job.accept(100, WORKER, 400).unwrap_err(),
            EscrowError::Expired
        );
        assert_eq!(
            job.accept(5_000, WORKER, 400).unwrap_err(),
            EscrowError::Expired
        );
        job.accept(99, WORKER, 400).unwrap();
    }

    #[test]
    fn display_is_the_code() {
        assert_eq!(EscrowError::Replay.to_string(), "replay");
    }
}
