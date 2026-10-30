// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! EIP-712 digests for `SuriComAIEscrow`. Mirrors `contracts/src/SuriComAIEscrow.sol`.

use sha3::{Digest, Keccak256};

/// A 20 byte account address.
pub type Address = [u8; 20];

const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const SETTLE_TYPE: &str = "Settle(bytes32 jobId,bytes32 contractHash,address worker,bytes32 receiptKey,uint256 amountDue,address relayPayee)";
const SLASH_TYPE: &str = "Slash(bytes32 jobId,bytes32 contractHash,address worker,bytes32 receiptKey,uint8 fault,bytes32 evidence)";

/// The chain and contract a signature is valid for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Domain {
    /// EVM chain id.
    pub chain_id: u64,
    /// Address of the deployed `SuriComAIEscrow`.
    pub verifying_contract: Address,
}

/// Faults the contract can slash. The numbers are the contract's enum values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Fault {
    /// The measurement is not on the allowlist.
    MeasurementRejected = 1,
    /// A GPU job arrived without GPU evidence.
    MissingGpuEvidence = 2,
    /// The hardware quote did not verify.
    BadQuote = 3,
    /// The proof is invalid for another signed reason.
    InvalidProof = 4,
}

/// Fields of the `Settle` typed message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettleFields {
    /// Job id.
    pub job_id: [u8; 32],
    /// Contract hash recorded at lock.
    pub contract_hash: [u8; 32],
    /// Pinned worker.
    pub worker: Address,
    /// Receipt key recorded at bond.
    pub receipt_key: [u8; 32],
    /// Amount to pay out of the locked fee.
    pub amount_due: u128,
    /// Relay paid the relay share, or zero for none.
    pub relay_payee: Address,
}

/// Fields of the `Slash` typed message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlashFields {
    /// Job id.
    pub job_id: [u8; 32],
    /// Contract hash recorded at lock.
    pub contract_hash: [u8; 32],
    /// Pinned worker.
    pub worker: Address,
    /// Receipt key recorded at bond, or zero when no bond was posted.
    pub receipt_key: [u8; 32],
    /// The fault.
    pub fault: Fault,
    /// Hash of the evidence. Never zero.
    pub evidence: [u8; 32],
}

pub(crate) fn keccak256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn address_word(address: &Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

fn u128_word(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

fn u64_word(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn u8_word(value: u8) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[31] = value;
    word
}

/// The on-chain job id: `keccak256(abi.encode(user, salt))`. It commits to the user, so no
/// one else can lock the same id. The wire contract's `job_id` must equal it.
pub fn job_id_for(user: &Address, salt: &[u8; 32]) -> [u8; 32] {
    keccak256(&[&address_word(user), salt])
}

/// EIP-712 domain separator for `SuriComAIEscrow` version 1.
pub fn domain_separator(domain: &Domain) -> [u8; 32] {
    keccak256(&[
        &keccak256(&[DOMAIN_TYPE.as_bytes()]),
        &keccak256(&[b"SuriComAIEscrow"]),
        &keccak256(&[b"1"]),
        &u64_word(domain.chain_id),
        &address_word(&domain.verifying_contract),
    ])
}

fn typed(domain: &Domain, struct_hash: [u8; 32]) -> [u8; 32] {
    keccak256(&[&[0x19, 0x01], &domain_separator(domain), &struct_hash])
}

/// The 32 bytes a committee member signs to approve a settlement.
pub fn settle_digest(domain: &Domain, fields: &SettleFields) -> [u8; 32] {
    typed(
        domain,
        keccak256(&[
            &keccak256(&[SETTLE_TYPE.as_bytes()]),
            &fields.job_id,
            &fields.contract_hash,
            &address_word(&fields.worker),
            &fields.receipt_key,
            &u128_word(fields.amount_due),
            &address_word(&fields.relay_payee),
        ]),
    )
}

/// The 32 bytes a committee member signs to approve a slash.
pub fn slash_digest(domain: &Domain, fields: &SlashFields) -> [u8; 32] {
    typed(
        domain,
        keccak256(&[
            &keccak256(&[SLASH_TYPE.as_bytes()]),
            &fields.job_id,
            &fields.contract_hash,
            &address_word(&fields.worker),
            &fields.receipt_key,
            &u8_word(fields.fault as u8),
            &fields.evidence,
        ]),
    )
}
