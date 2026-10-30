// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Seal one private prompt and check the proof. The prompt and answer are not printed.

use std::collections::HashSet;

use suricomai_envelope::{
    advertise, finish_job, open_answer, open_job, seal_job, verify_advertisement, EnclaveKeys,
    HostLog, InferenceParams, JobAttestation, JobVerification, LabAttester, PromptContract,
    ReplayCache, SealTarget, Tier, UserKeys,
};

fn main() {
    let measurement = [7u8; 32];
    let attester = LabAttester::generate();
    let verifier = attester.verifier();
    let executor = EnclaveKeys::generate(measurement).expect("executor keys");
    let user = UserKeys::generate().expect("user keys");
    let mut allowlist = HashSet::new();
    allowlist.insert(measurement);

    let ad =
        advertise(&executor, [9u8; 32], 0, 3_600, [0u8; 32], &attester).expect("advertisement");
    let verified =
        verify_advertisement(&ad, &allowlist, &verifier, 10).expect("verify before send");
    let target = SealTarget::Private(verified);

    let prompt = b"CANARY-SECRET-suricomai-9f3a";
    let mut contract = PromptContract {
        job_id: [1u8; 32],
        chain_id: 7,
        tier: Tier::P2,
        model_digest: [2u8; 32],
        prompt_commitment: [0u8; 32],
        max_output_bytes: 128,
        size_class: 4096,
        fee: 1,
        bond_required: 1,
        expiry: 1_000,
        privacy_policy_id: [4u8; 32],
        user_pay_key: [5u8; 32],
        user_hpke_public: user.hpke_public().to_vec(),
        min_stake: 0,
        min_canary_ppt: 0,
        max_latency_ms: 150,
        needs_gpu: false,
        region: Vec::new(),
    };
    contract.bind_prompt(prompt);
    let params = InferenceParams::new([3u8; 32], 0, 16).expect("params");
    let sealed = seal_job(&contract, prompt, &params, &target).expect("seal");

    let mut open_log = HostLog::default();
    let opened = open_job(
        &sealed.to_bytes(),
        &executor,
        &allowlist,
        10,
        &mut ReplayCache::default(),
        &mut open_log,
    )
    .expect("open");
    let result = finish_job(
        &opened,
        b"sealed-answer",
        20,
        [8u8; 32],
        [0u8; 32],
        [6u8; 32],
        11,
        12,
        None,
        &executor,
        JobAttestation::Quote(&attester),
    )
    .expect("finish");

    let mut answer_log = HostLog::default();
    let answer = open_answer(
        &sealed,
        &result.to_bytes().expect("result bytes"),
        &user,
        &target,
        &allowlist,
        JobVerification::Quote(&verifier),
        100,
        &mut answer_log,
    )
    .expect("open answer");

    let proof = result.proof().to_bytes().expect("proof bytes");
    let leaked = open_log.contains("CANARY-SECRET-suricomai-9f3a")
        || answer_log.contains("CANARY-SECRET-suricomai-9f3a")
        || proof.windows(prompt.len()).any(|window| window == prompt);
    assert!(!leaked, "prompt appeared in the log or the proof");
    assert_eq!(answer.as_slice(), b"sealed-answer");

    println!("suricomai envelope roundtrip ok");
    println!("tier=P2");
    println!("proof_bytes={}", proof.len());
    println!("token_bucket={}", result.proof().token_bucket);
    println!("log_has_canary=false");
}
