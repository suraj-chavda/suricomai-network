// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Write `vectors/audit-v1.json` for the Rust and Python auditors.
//!
//! The file holds contracts and sealed results. It does not hold a prompt.

use std::path::PathBuf;

use suricomai_envelope::{
    advertise, audit_proof, finish_job, open_job, seal_job, verify_advertisement, AuditTarget,
    EnclaveKeys, HostLog, InferenceParams, JobAttestation, JobVerification, MeasurementAllowlist,
    PromptContract, ReplayCache, SealTarget, SealedResult, Tier, TransitTarget, UserKeys,
};

fn main() {
    let measurement = [7u8; 32];
    let attester = suricomai_envelope::LabAttester::generate();
    let verifier = attester.verifier();
    let executor = EnclaveKeys::generate(measurement).unwrap();
    let user = UserKeys::generate().unwrap();
    let mut allowlist = MeasurementAllowlist::new();
    allowlist.insert(measurement);

    let p2 = job(
        &executor,
        &user,
        &attester,
        &verifier,
        &allowlist,
        Tier::P2,
        measurement,
    );
    let p1 = job(
        &executor,
        &user,
        &attester,
        &verifier,
        &allowlist,
        Tier::P1,
        measurement,
    );

    let mut richer = PromptContract::from_bytes(&p1.contract).unwrap();
    richer.fee *= 100;
    let p1_richer_contract = richer.to_bytes().unwrap();

    let mut bad = p2.result_bytes.clone();
    let good_proof = p2.proof_bytes.clone();
    let mut flipped = SealedResult::from_bytes(&p2.result_bytes)
        .unwrap()
        .proof()
        .clone();
    flipped.receipt_sig[0] ^= 0xff;
    let bad_proof = flipped.to_bytes().unwrap();
    let pos = bad
        .windows(good_proof.len())
        .position(|window| window == good_proof.as_slice())
        .expect("proof bytes sit inside the result");
    bad[pos..pos + good_proof.len()].copy_from_slice(&bad_proof);

    let cases_json = vec![
        case("p2_ok", &p2, vec![measurement], "quote", "ok"),
        case(
            "p2_empty_allowlist",
            &p2,
            vec![],
            "quote",
            "measurement_rejected",
        ),
        case(
            "p2_bad_signature",
            &JobBytes {
                contract: p2.contract.clone(),
                result_bytes: bad,
                proof_bytes: bad_proof,
                executor_id: p2.executor_id,
                receipt_public: p2.receipt_public,
            },
            vec![measurement],
            "quote",
            "bad_signature",
        ),
        case("p1_ok", &p1, vec![], "signature", "ok"),
        case_with(
            "p1_wrong_worker_key",
            &p1,
            vec![],
            "signature",
            "identity_mismatch",
            Some(("ee".repeat(32), hex(&p1.receipt_public))),
            None,
        ),
        case_with(
            "p1_other_contract",
            &JobBytes {
                contract: p1_richer_contract,
                ..p1.clone()
            },
            vec![],
            "signature",
            "identity_mismatch",
            None,
            None,
        ),
        case_with(
            "p1_audited_after_expiry",
            &p1,
            vec![],
            "signature",
            "proof_expired",
            None,
            Some(1_000),
        ),
    ];

    let doc = serde_json::json!({
        "version": 1,
        "lab_public": hex(&attester.verifying_bytes()),
        "note": "Audit vectors. No prompt and no answer plaintext.",
        "cases": cases_json,
    });

    let path = workspace_vectors();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    println!("{}", path.display());
}

#[derive(Clone)]
struct JobBytes {
    contract: Vec<u8>,
    result_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
    executor_id: [u8; 32],
    receipt_public: [u8; 32],
}

fn case(
    name: &str,
    job: &JobBytes,
    allow: Vec<[u8; 32]>,
    mode: &str,
    expect: &str,
) -> serde_json::Value {
    case_with(name, job, allow, mode, expect, None, None)
}

/// `target` overrides the expected `(executor_id, receipt_public)` hex pair.
/// `audit_now` overrides the auditor clock.
fn case_with(
    name: &str,
    job: &JobBytes,
    allow: Vec<[u8; 32]>,
    mode: &str,
    expect: &str,
    target: Option<(String, String)>,
    audit_now: Option<u64>,
) -> serde_json::Value {
    let (executor_id, receipt_public) =
        target.unwrap_or_else(|| (hex(&job.executor_id), hex(&job.receipt_public)));
    let mut value = serde_json::json!({
        "name": name,
        "contract": hex(&job.contract),
        "result": hex(&job.result_bytes),
        "allow": allow.iter().map(|id| hex(id)).collect::<Vec<_>>(),
        "mode": mode,
        "target_executor_id": executor_id,
        "target_receipt_public": receipt_public,
        "expect": expect,
    });
    if let Some(now) = audit_now {
        value["audit_now"] = serde_json::json!(now);
    }
    value
}

fn job(
    executor: &EnclaveKeys,
    user: &UserKeys,
    attester: &suricomai_envelope::LabAttester,
    verifier: &suricomai_envelope::LabVerifier,
    allowlist: &MeasurementAllowlist,
    tier: Tier,
    measurement: [u8; 32],
) -> JobBytes {
    let mut job_id = [0u8; 32];
    job_id[0] = match tier {
        Tier::P2 => 2,
        Tier::P1 => 1,
        Tier::P0 => 0,
    };
    let prompt = b"ping";
    let mut contract = PromptContract {
        job_id,
        chain_id: 7,
        tier,
        model_digest: [2u8; 32],
        prompt_commitment: [0u8; 32],
        max_output_bytes: 64,
        size_class: 4096,
        fee: 1000,
        bond_required: 1000,
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
    contract.bind_prompt(prompt);
    let target = match tier {
        Tier::P2 => {
            let ad = advertise(executor, [9u8; 32], 0, 3_600, [0u8; 32], attester).unwrap();
            let verified = verify_advertisement(&ad, allowlist, verifier, 10).unwrap();
            SealTarget::Private(verified)
        }
        Tier::P0 | Tier::P1 => SealTarget::Transit(
            TransitTarget::new(
                measurement,
                executor.hpke_public().to_vec(),
                executor.receipt_public(),
            )
            .unwrap(),
        ),
    };
    let params = InferenceParams::new([3u8; 32], 0, 16).unwrap();
    let sealed = seal_job(&contract, prompt, &params, &target).unwrap();
    let opened = open_job(
        &sealed.to_bytes(),
        executor,
        allowlist,
        10,
        &mut ReplayCache::default(),
        &mut HostLog::default(),
    )
    .unwrap();
    let attestation = match tier {
        Tier::P2 => JobAttestation::Quote(attester),
        Tier::P0 | Tier::P1 => JobAttestation::NotRequired,
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
        executor,
        attestation,
    )
    .unwrap();
    let verification = match tier {
        Tier::P2 => JobVerification::Quote(verifier),
        Tier::P0 | Tier::P1 => JobVerification::SignatureOnly,
    };
    let target = AuditTarget::new(executor.executor_id(), executor.receipt_public());
    audit_proof(&contract, &result, &target, allowlist, verification, 999).unwrap();
    let result_bytes = result.to_bytes().unwrap();
    assert!(
        !result_bytes.windows(4).any(|window| window == b"ping"),
        "prompt leaked into the vector"
    );
    JobBytes {
        contract: contract.to_bytes().unwrap(),
        proof_bytes: result.proof().to_bytes().unwrap(),
        result_bytes,
        executor_id: executor.executor_id(),
        receipt_public: executor.receipt_public(),
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn workspace_vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors/audit-v1.json")
}
