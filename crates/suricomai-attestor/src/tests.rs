// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
use std::path::PathBuf;

use suricomai_envelope::{
    advertise, finish_job, open_job, seal_job, verify_advertisement, EnclaveKeys, EnvelopeError,
    HostLog, InferenceParams, JobAttestation, JobVerification, LabAttester, LabVerifier,
    MeasurementAllowlist, PromptContract, ReplayCache, SealTarget, SealedJob, SealedResult, Tier,
    TransitTarget, UserKeys,
};

use crate::*;

fn hex32(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn addr(last: u8) -> Address {
    let mut a = [0u8; 20];
    a[19] = last;
    a
}

/// Answers the same thing every time. Stands in for the independent verifier.
struct Fixed(&'static str);

impl SecondVerifier for Fixed {
    fn verify(&self, _: &AuditRequest) -> Result<String, AttestError> {
        Ok(self.0.to_string())
    }
}

const DOMAIN: Domain = Domain {
    chain_id: 31337,
    verifying_contract: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6],
};

// ------------------------------------------------------------ digests and keys

/// The same reference values are pinned in `contracts/test/Signatures.t.sol`. They were
/// computed with `cast`, a separate implementation.
#[test]
fn the_typed_data_digests_match_the_reference_vectors() {
    let job = hex32(&"11".repeat(32));
    let ch = hex32(&"22".repeat(32));
    let key = hex32(&"44".repeat(32));
    let settle = settle_digest(
        &DOMAIN,
        &SettleFields {
            job_id: job,
            contract_hash: ch,
            worker: addr(3),
            receipt_key: key,
            amount_due: 1000,
            relay_payee: addr(5),
        },
    );
    assert_eq!(
        settle,
        hex32("305b610578f7ad08d19ed189485e8656c3a42733a4a8de871f057e88e33e9105")
    );
    let slash = slash_digest(
        &DOMAIN,
        &SlashFields {
            job_id: job,
            contract_hash: ch,
            worker: addr(3),
            receipt_key: key,
            fault: Fault::BadQuote,
            evidence: hex32(&"55".repeat(32)),
        },
    );
    assert_eq!(
        slash,
        hex32("c6dc92800a258588669e0608d11ef1279da9e7bc0d0d6e486ee40224d52cf5bf")
    );
}

fn signer(n: u8) -> CommitteeSigner {
    let mut secret = [0u8; 32];
    secret[31] = n;
    CommitteeSigner::from_secret(&secret).unwrap()
}

#[test]
fn a_known_secret_gives_the_known_address() {
    // Private key 1 is a well known test key. Foundry's `vm.addr(1)` is the same address.
    let expected: Address = [
        0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2, 0x65,
        0x90, 0x29, 0x39, 0x5b, 0xdf,
    ];
    assert_eq!(signer(1).address(), expected);
    assert!(CommitteeSigner::from_secret(&[0u8; 32]).is_err());
}

#[test]
fn signatures_are_canonical_and_recover_to_the_signer() {
    let member = signer(2);
    for i in 0..200u32 {
        let mut digest = [0u8; 32];
        digest[..4].copy_from_slice(&i.to_be_bytes());
        let signature = member.sign(&digest).unwrap();
        assert!(signature.bytes[64] == 27 || signature.bytes[64] == 28);
        // s must be in the lower half of the curve order.
        let half = hex32("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
        let mut s = [0u8; 32];
        s.copy_from_slice(&signature.bytes[32..64]);
        assert!(s <= half, "high s at {i}");
        assert_eq!(recover(&digest, &signature.bytes), Some(member.address()));
    }
}

#[test]
fn signatures_are_assembled_in_ascending_signer_order_without_duplicates() {
    let digest = [9u8; 32];
    let sigs: Vec<_> = (1..=5u8)
        .map(|n| signer(n).sign(&digest).unwrap())
        .collect();
    let mut shuffled = vec![sigs[3], sigs[0], sigs[4], sigs[1], sigs[2]];
    let joined = assemble(shuffled.clone()).unwrap();
    assert_eq!(joined.len(), 5 * 65);
    let mut signers: Vec<Address> = joined
        .chunks(65)
        .map(|chunk| {
            let mut one = [0u8; 65];
            one.copy_from_slice(chunk);
            recover(&digest, &one).unwrap()
        })
        .collect();
    let sorted = {
        let mut copy = signers.clone();
        copy.sort();
        copy
    };
    assert_eq!(signers, sorted);
    signers.dedup();
    assert_eq!(signers.len(), 5);
    shuffled.push(sigs[0]);
    assert_eq!(
        assemble(shuffled).unwrap_err(),
        AttestError::BadSignatureSet
    );
    assert_eq!(
        assemble(Vec::new()).unwrap_err(),
        AttestError::BadSignatureSet
    );
}

// ------------------------------------------------------------ job fixtures

struct Case {
    sealed: SealedJob,
    result: SealedResult,
    assigned: Assignment,
    allowlist: MeasurementAllowlist,
    verifier: Option<LabVerifier>,
    lab_public: Option<[u8; 32]>,
    job: JobOnChain,
}

impl Case {
    fn contract(&self) -> &PromptContract {
        self.sealed.contract()
    }

    fn evidence<'a>(&'a self, allowlist: &'a MeasurementAllowlist, audit_now: u64) -> Evidence<'a> {
        Evidence {
            contract: self.contract(),
            result: &self.result,
            assigned: self.assigned,
            allowlist,
            audit_now,
        }
    }

    fn verification(&self) -> JobVerification<'_> {
        match &self.verifier {
            Some(verifier) => JobVerification::Quote(verifier),
            None => JobVerification::SignatureOnly,
        }
    }
}

fn contract(tier: Tier, user: &UserKeys, job: u8) -> PromptContract {
    let mut job_id = [0u8; 32];
    job_id[31] = job;
    let mut c = PromptContract {
        job_id,
        chain_id: 31337,
        tier,
        model_digest: [2u8; 32],
        prompt_commitment: [0u8; 32],
        max_output_bytes: 64,
        size_class: 4096,
        fee: 1000,
        bond_required: 100,
        expiry: 1_000,
        privacy_policy_id: [4u8; 32],
        user_pay_key: [5u8; 32],
        user_hpke_public: user.hpke_public().to_vec(),
        min_stake: 0,
        min_canary_ppt: 0,
        max_latency_ms: 150,
        needs_gpu: false,
        region: b"lab".to_vec(),
    };
    c.bind_prompt(b"ping");
    c
}

fn case(tier: Tier, job: u8) -> Case {
    let measurement = [7u8; 32];
    let attester = LabAttester::generate();
    let lab_verifier = attester.verifier();
    let executor = EnclaveKeys::generate(measurement).unwrap();
    let user = UserKeys::generate().unwrap();
    let mut allowlist = MeasurementAllowlist::new();
    allowlist.insert(measurement);
    let contract = contract(tier, &user, job);
    let target = match tier {
        Tier::P2 => {
            let ad = advertise(&executor, [9u8; 32], 0, 3_600, [0u8; 32], &attester).unwrap();
            SealTarget::Private(verify_advertisement(&ad, &allowlist, &lab_verifier, 10).unwrap())
        }
        _ => SealTarget::Transit(
            TransitTarget::new(
                measurement,
                executor.hpke_public().to_vec(),
                executor.receipt_public(),
            )
            .unwrap(),
        ),
    };
    let params = InferenceParams::new([3u8; 32], 0, 16).unwrap();
    let sealed = seal_job(&contract, b"ping", &params, &target).unwrap();
    let opened = open_job(
        &sealed.to_bytes(),
        &executor,
        &allowlist,
        10,
        &mut ReplayCache::default(),
        &mut HostLog::default(),
    )
    .unwrap();
    let attestation = match tier {
        Tier::P2 => JobAttestation::Quote(&attester),
        _ => JobAttestation::NotRequired,
    };
    let result = finish_job(
        &opened,
        b"pong",
        16,
        [8u8; 32],
        [0u8; 32],
        [6u8; 32],
        11,
        12,
        None,
        &executor,
        attestation,
    )
    .unwrap();
    let hash = result.proof().contract_hash;
    let job = JobOnChain {
        job_id: contract.job_id,
        contract_hash: hash,
        worker: addr(0xB0),
        receipt_key: executor.receipt_public(),
        cap: u128::from(contract.fee),
    };
    Case {
        sealed,
        result,
        assigned: Assignment {
            executor_id: executor.executor_id(),
            receipt_public: executor.receipt_public(),
        },
        allowlist,
        verifier: (tier == Tier::P2).then_some(lab_verifier),
        lab_public: (tier == Tier::P2).then(|| attester.verifying_bytes()),
        job,
    }
}

fn attestor(second: &dyn SecondVerifier) -> Attestor<'_> {
    Attestor::new(signer(1), DOMAIN, second)
}

// ------------------------------------------------------------ settlement

#[test]
fn a_settlement_is_signed_only_after_both_verifiers_accept() {
    let c = case(Tier::P1, 1);
    let second = Fixed("ok");
    let a = attestor(&second);
    let signature = a
        .attest_settlement(
            &c.job,
            &c.evidence(&c.allowlist, 100),
            c.verification(),
            1000,
            addr(0),
        )
        .unwrap();
    let digest = settle_digest(
        &DOMAIN,
        &SettleFields {
            job_id: c.job.job_id,
            contract_hash: c.job.contract_hash,
            worker: c.job.worker,
            receipt_key: c.job.receipt_key,
            amount_due: 1000,
            relay_payee: addr(0),
        },
    );
    assert_eq!(recover(&digest, &signature.bytes), Some(a.address()));
}

#[test]
fn a_private_job_with_a_lab_quote_is_signed_too() {
    let c = case(Tier::P2, 2);
    let second = Fixed("ok");
    let a = attestor(&second);
    a.attest_settlement(
        &c.job,
        &c.evidence(&c.allowlist, 100),
        c.verification(),
        700,
        addr(1),
    )
    .unwrap();
}

#[test]
fn a_disagreeing_second_verifier_blocks_the_signature() {
    let c = case(Tier::P1, 3);
    for answer in ["bad_signature", "identity_mismatch", "malformed"] {
        let second = Fixed(answer);
        let err = attestor(&second)
            .attest_settlement(
                &c.job,
                &c.evidence(&c.allowlist, 100),
                c.verification(),
                1000,
                addr(0),
            )
            .unwrap_err();
        assert_eq!(
            err,
            AttestError::Disagreement {
                first: "ok".to_string(),
                second: answer.to_string()
            }
        );
    }
}

#[test]
fn the_envelope_auditor_can_block_what_a_lenient_second_verifier_would_pass() {
    let c = case(Tier::P1, 4);
    let second = Fixed("ok");
    let a = attestor(&second);
    // Audited after expiry: the envelope refuses, whatever the second verifier says.
    let late = c.evidence(&c.allowlist, 5_000);
    assert_eq!(
        a.attest_settlement(&c.job, &late, c.verification(), 1000, addr(0))
            .unwrap_err(),
        AttestError::Rejected(EnvelopeError::ProofExpired)
    );
    // A different assigned worker.
    let mut other = c.evidence(&c.allowlist, 100);
    other.assigned.executor_id = [0xEE; 32];
    assert_eq!(
        a.attest_settlement(&c.job, &other, c.verification(), 1000, addr(0))
            .unwrap_err(),
        AttestError::Rejected(EnvelopeError::IdentityMismatch)
    );
}

#[test]
fn the_chain_record_the_proof_and_the_contract_must_all_agree() {
    let c = case(Tier::P1, 5);
    let second = Fixed("ok");
    let a = attestor(&second);
    let ev = c.evidence(&c.allowlist, 100);
    let try_job = |job: JobOnChain| a.attest_settlement(&job, &ev, c.verification(), 1000, addr(0));

    let mut bad = c.job;
    bad.job_id[0] ^= 1;
    assert_eq!(try_job(bad).unwrap_err(), AttestError::Binding("job id"));
    let mut bad = c.job;
    bad.cap += 1;
    assert_eq!(
        try_job(bad).unwrap_err(),
        AttestError::Binding("fee does not equal the locked cap")
    );
    let mut bad = c.job;
    bad.contract_hash[0] ^= 1;
    assert_eq!(
        try_job(bad).unwrap_err(),
        AttestError::Binding("contract hash")
    );
    let mut bad = c.job;
    bad.receipt_key[0] ^= 1;
    assert_eq!(
        try_job(bad).unwrap_err(),
        AttestError::Binding("receipt key recorded at bond")
    );
    let mut wrong_assignment = c.evidence(&c.allowlist, 100);
    wrong_assignment.assigned.receipt_public[0] ^= 1;
    assert_eq!(
        a.attest_settlement(&c.job, &wrong_assignment, c.verification(), 1000, addr(0))
            .unwrap_err(),
        AttestError::Binding("assignment does not match the recorded key")
    );
}

#[test]
fn the_amount_must_be_between_the_minimum_fee_and_the_cap() {
    let c = case(Tier::P1, 6);
    let second = Fixed("ok");
    let a = attestor(&second);
    let ev = c.evidence(&c.allowlist, 100);
    for amount in [0, 99, 1001, u128::MAX] {
        assert_eq!(
            a.attest_settlement(&c.job, &ev, c.verification(), amount, addr(0))
                .unwrap_err(),
            AttestError::AmountOutOfRange
        );
    }
    a.attest_settlement(&c.job, &ev, c.verification(), 100, addr(0))
        .unwrap();
    a.attest_settlement(&c.job, &ev, c.verification(), 1000, addr(0))
        .unwrap();
}

// ------------------------------------------------------------ slash

#[test]
fn a_worker_signed_measurement_fault_is_slashable_when_both_verifiers_agree() {
    let c = case(Tier::P2, 7);
    let empty = MeasurementAllowlist::new();
    let second = Fixed("measurement_rejected");
    let a = attestor(&second);
    let (fault, evidence, signature) = a
        .attest_slash(&c.job, &c.evidence(&empty, 100), c.verification())
        .unwrap();
    assert_eq!(fault, Fault::MeasurementRejected);
    assert_ne!(evidence, [0u8; 32]);
    let digest = slash_digest(
        &DOMAIN,
        &SlashFields {
            job_id: c.job.job_id,
            contract_hash: c.job.contract_hash,
            worker: c.job.worker,
            receipt_key: c.job.receipt_key,
            fault,
            evidence,
        },
    );
    assert_eq!(recover(&digest, &signature.bytes), Some(a.address()));
}

#[test]
fn a_slash_needs_the_second_verifier_to_name_the_same_fault() {
    let c = case(Tier::P2, 8);
    let empty = MeasurementAllowlist::new();
    for answer in ["ok", "bad_quote", "bad_signature"] {
        let second = Fixed(answer);
        let err = attestor(&second)
            .attest_slash(&c.job, &c.evidence(&empty, 100), c.verification())
            .unwrap_err();
        assert!(matches!(err, AttestError::Disagreement { .. }), "{answer}");
    }
}

#[test]
fn a_valid_proof_is_never_slashed() {
    let c = case(Tier::P1, 9);
    let second = Fixed("ok");
    assert_eq!(
        attestor(&second)
            .attest_slash(&c.job, &c.evidence(&c.allowlist, 100), c.verification())
            .unwrap_err(),
        AttestError::NothingToSlash
    );
}

#[test]
fn a_failure_that_is_not_a_signed_fault_is_never_slashed() {
    let c = case(Tier::P1, 10);
    let second = Fixed("identity_mismatch");
    let a = attestor(&second);
    // A proof for a different worker is a mix-up, not the pinned worker's fault.
    let mut other = c.evidence(&c.allowlist, 100);
    other.assigned.executor_id = [0xEE; 32];
    assert_eq!(
        a.attest_slash(&c.job, &other, c.verification())
            .unwrap_err(),
        AttestError::NotASlashableFault(EnvelopeError::IdentityMismatch)
    );
    // Audited too late is the user's clock, not a fault.
    let second = Fixed("proof_expired");
    assert_eq!(
        attestor(&second)
            .attest_slash(&c.job, &c.evidence(&c.allowlist, 5_000), c.verification())
            .unwrap_err(),
        AttestError::NotASlashableFault(EnvelopeError::ProofExpired)
    );
}

#[test]
fn a_forged_proof_whose_signature_is_not_the_workers_cannot_slash_the_worker() {
    let c = case(Tier::P2, 11);
    let empty = MeasurementAllowlist::new();
    let mut forged_proof = c.result.proof().clone();
    forged_proof.receipt_sig[0] ^= 0xff;
    let forged = SealedResult::from_bytes(&{
        // Rebuild the result bytes with the broken signature inside.
        let original = c.result.to_bytes().unwrap();
        let good = c.result.proof().to_bytes().unwrap();
        let bad = forged_proof.to_bytes().unwrap();
        let at = original
            .windows(good.len())
            .position(|w| w == good.as_slice())
            .unwrap();
        let mut out = original.clone();
        out[at..at + good.len()].copy_from_slice(&bad);
        out
    })
    .unwrap();
    let second = Fixed("measurement_rejected");
    let ev = Evidence {
        contract: c.contract(),
        result: &forged,
        assigned: c.assigned,
        allowlist: &empty,
        audit_now: 100,
    };
    assert_eq!(
        attestor(&second)
            .attest_slash(&c.job, &ev, c.verification())
            .unwrap_err(),
        AttestError::Rejected(EnvelopeError::BadSignature)
    );
}

// ------------------------------------------------------------ the real second verifier

fn python() -> PythonVerifier {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../");
    let venv = if cfg!(windows) {
        root.join("verifiers/python/.venv/Scripts/python.exe")
    } else {
        root.join("verifiers/python/.venv/bin/python")
    };
    let system = if cfg!(windows) { "python" } else { "python3" };
    PythonVerifier {
        python: if venv.exists() {
            venv
        } else {
            PathBuf::from(system)
        },
        script: root.join("verifiers/python/audit_proof.py"),
        lab_public: None,
    }
}

#[test]
fn the_python_verifier_agrees_with_the_attestor_end_to_end() {
    let c = case(Tier::P1, 12);
    let second = python();
    let a = attestor(&second);
    let ev = c.evidence(&c.allowlist, 100);
    a.attest_settlement(&c.job, &ev, c.verification(), 1000, addr(0))
        .unwrap();

    // The worker the python verifier is told to expect differs: it must answer with an
    // error code, and the attestor reports a disagreement or a rejection, never a signature.
    let mut other = c.evidence(&c.allowlist, 100);
    other.assigned.executor_id = [0xEE; 32];
    assert!(a
        .attest_settlement(&c.job, &other, c.verification(), 1000, addr(0))
        .is_err());

    let request = AuditRequest {
        contract: c.contract().to_bytes().unwrap(),
        result: c.result.to_bytes().unwrap(),
        allow: Vec::new(),
        private_tier: false,
        audit_now: 100,
        target_executor_id: [0xEE; 32],
        target_receipt_public: c.assigned.receipt_public,
    };
    assert_eq!(second.verify(&request).unwrap(), "identity_mismatch");
}

#[test]
fn a_missing_second_verifier_means_no_signature() {
    let c = case(Tier::P1, 13);
    let missing = PythonVerifier {
        python: PathBuf::from("/definitely/not/python"),
        script: PathBuf::from("/nope.py"),
        lab_public: None,
    };
    let err = attestor(&missing)
        .attest_settlement(
            &c.job,
            &c.evidence(&c.allowlist, 100),
            c.verification(),
            1000,
            addr(0),
        )
        .unwrap_err();
    assert!(matches!(err, AttestError::Verifier(_)));
}

#[test]
fn the_python_verifier_checks_a_private_job_with_the_lab_quote_root() {
    let c = case(Tier::P2, 14);
    let mut second = python();
    second.lab_public = c.lab_public;
    assert!(second.lab_public.is_some());
    let a = attestor(&second);
    a.attest_settlement(
        &c.job,
        &c.evidence(&c.allowlist, 100),
        c.verification(),
        1000,
        addr(0),
    )
    .unwrap();

    // With an empty allowlist both verifiers refuse the measurement, and agree on the fault.
    let empty = MeasurementAllowlist::new();
    let (fault, _, _) = a
        .attest_slash(&c.job, &c.evidence(&empty, 100), c.verification())
        .unwrap();
    assert_eq!(fault, Fault::MeasurementRejected);
}
