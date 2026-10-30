// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
use std::collections::BTreeMap;

use zeroize::Zeroize;

use hpke::aead::Aead;
use hpke::kdf::Kdf;
use hpke::Kem;

use crate::cbor::{self, Cbor};
use crate::commit::{domain_hash, hex32};
use crate::keys::{AeadAlg, KdfAlg, KemAlg};
use crate::*;

const CANARY: &[u8] =
    b"CANARY-SECRET-suricomai-9f3a $(rm -rf /) ../../etc/passwd {\"exec\":true}\n\xff";

struct Fixture {
    attester: LabAttester,
    verifier: LabVerifier,
    executor: EnclaveKeys,
    user: UserKeys,
    allowlist: MeasurementAllowlist,
    measurement: [u8; 32],
}

impl Fixture {
    fn target(&self) -> AuditTarget {
        AuditTarget::new(self.executor.executor_id(), self.executor.receipt_public())
    }

    fn new() -> Self {
        let measurement = [7u8; 32];
        let attester = LabAttester::generate();
        let verifier = attester.verifier();
        let executor = EnclaveKeys::generate(measurement).unwrap();
        let user = UserKeys::generate().unwrap();
        let mut allowlist = MeasurementAllowlist::new();
        allowlist.insert(measurement);
        Self {
            attester,
            verifier,
            executor,
            user,
            allowlist,
            measurement,
        }
    }

    fn target_p2(&self) -> SealTarget {
        let ad = advertise(
            &self.executor,
            [9u8; 32],
            0,
            3_600,
            [0u8; 32],
            &self.attester,
        )
        .unwrap();
        let verified = verify_advertisement(&ad, &self.allowlist, &self.verifier, 10).unwrap();
        SealTarget::Private(verified)
    }

    fn contract(
        &self,
        tier: Tier,
        needs_gpu: bool,
        expiry: u64,
        job: u8,
        prompt: &[u8],
    ) -> PromptContract {
        let mut job_id = [0u8; 32];
        job_id[31] = job;
        let mut contract = PromptContract {
            job_id,
            chain_id: 7,
            tier,
            model_digest: [2u8; 32],
            prompt_commitment: [0u8; 32],
            max_output_bytes: 256,
            size_class: 4096,
            fee: 10,
            bond_required: 10,
            expiry,
            privacy_policy_id: [4u8; 32],
            user_pay_key: [5u8; 32],
            user_hpke_public: self.user.hpke_public().to_vec(),
            min_stake: 0,
            min_canary_ppt: 0,
            max_latency_ms: 150,
            needs_gpu,
            region: b"lab".to_vec(),
        };
        contract.bind_prompt(prompt);
        contract
    }
}

fn params() -> InferenceParams {
    InferenceParams::new([3u8; 32], 0, 32).unwrap()
}

fn tamper_map(bytes: &[u8], edit: impl FnOnce(&mut BTreeMap<u64, Cbor>)) -> Vec<u8> {
    let mut value = cbor::decode(bytes).unwrap();
    edit(cbor::as_map_mut(&mut value).unwrap());
    cbor::encode(&value)
}

fn assert_secret_absent(bytes: &[u8]) {
    assert!(
        !bytes.windows(CANARY.len()).any(|window| window == CANARY),
        "canary leaked into a public artifact"
    );
}

#[test]
fn suite_ids_match_the_pinned_hpke_draft() {
    assert_eq!(<KemAlg as Kem>::KEM_ID, HPKE_KEM_ID);
    assert_eq!(<KdfAlg as Kdf>::KDF_ID, HPKE_KDF_ID);
    assert_eq!(<AeadAlg as Aead>::AEAD_ID, HPKE_AEAD_ID);
    assert_eq!(HPKE_KEM_ID, 0x647a);
    assert_eq!(HPKE_KDF_ID, 0x0011);
    assert_eq!(HPKE_AEAD_ID, 0x0003);
}

#[test]
fn prompt_commitment_is_domain_separated() {
    let prompt = commit_prompt(b"ping");
    assert_ne!(prompt, commit_prompt(b"pong"));
    assert_ne!(prompt, domain_hash("suricomai.answer_ct.v1", &[b"ping"]));
    assert_eq!(
        hex32(&prompt),
        "27c5460634c02f90cc5891a14aa4b179b09f704d16fe6d216324f9405782d1b1"
    );
}

#[test]
fn private_roundtrip_hides_prompt_from_proof_and_log() {
    let fix = Fixture::new();
    let target = fix.target_p2();
    let contract = fix.contract(Tier::P2, false, 1_000, 1, CANARY);
    let sealed = seal_job(&contract, CANARY, &params(), &target).unwrap();
    let wire = sealed.to_bytes();
    assert_secret_absent(sealed.contract().to_bytes().unwrap().as_slice());
    assert_secret_absent(&sealed.contract().prompt_commitment);

    let mut log = HostLog::default();
    let mut replay = ReplayCache::default();
    let opened = open_job(
        &wire,
        &fix.executor,
        &fix.allowlist,
        10,
        &mut replay,
        &mut log,
    )
    .unwrap();
    assert_eq!(opened.prompt(), CANARY);
    assert!(!format!("{opened:?}").contains("CANARY-SECRET-suricomai-9f3a"));
    assert!(log.contains("code=accepted"));
    assert!(!log.contains("CANARY-SECRET-suricomai-9f3a"));
    assert!(!log.as_text().contains("rm -rf"));

    let result = finish_job(
        &opened,
        CANARY,
        100,
        [8u8; 32],
        [0u8; 32],
        [6u8; 32],
        11,
        12,
        None,
        &fix.executor,
        JobAttestation::Quote(&fix.attester),
    )
    .unwrap();
    assert_eq!(result.proof().token_bucket, 128);
    let proof_bytes = result.proof().to_bytes().unwrap();
    assert_secret_absent(&proof_bytes);
    assert_secret_absent(&result.to_bytes().unwrap());

    let mut answer_log = HostLog::default();
    let answer = open_answer(
        &sealed,
        &result.to_bytes().unwrap(),
        &fix.user,
        &target,
        &fix.allowlist,
        JobVerification::Quote(&fix.verifier),
        100,
        &mut answer_log,
    )
    .unwrap();
    assert_eq!(answer.as_slice(), CANARY);
    assert!(answer_log.contains("code=accepted"));
    assert!(!answer_log.contains("CANARY-SECRET-suricomai-9f3a"));
    audit_proof(
        sealed.contract(),
        &result,
        &fix.target(),
        &fix.allowlist,
        JobVerification::Quote(&fix.verifier),
        100,
    )
    .unwrap();
    assert_eq!(
        audit_proof(
            sealed.contract(),
            &result,
            &fix.target(),
            &MeasurementAllowlist::new(),
            JobVerification::Quote(&fix.verifier),
            100,
        )
        .unwrap_err(),
        EnvelopeError::MeasurementRejected
    );
}

#[test]
fn transit_roundtrip_is_not_a_private_quote() {
    let fix = Fixture::new();
    let target = SealTarget::Transit(
        TransitTarget::new(
            fix.measurement,
            fix.executor.hpke_public().to_vec(),
            fix.executor.receipt_public(),
        )
        .unwrap(),
    );
    let prompt = b"visible-to-worker";
    let contract = fix.contract(Tier::P1, false, 1_000, 2, prompt);
    let sealed = seal_job(&contract, prompt, &params(), &target).unwrap();
    let mut log = HostLog::default();
    let opened = open_job(
        &sealed.to_bytes(),
        &fix.executor,
        &MeasurementAllowlist::new(),
        10,
        &mut ReplayCache::default(),
        &mut log,
    )
    .unwrap();
    let result = finish_job(
        &opened,
        b"ok",
        1,
        [1u8; 32],
        [0u8; 32],
        [6u8; 32],
        1,
        2,
        None,
        &fix.executor,
        JobAttestation::NotRequired,
    )
    .unwrap();
    assert!(result.proof().quote.is_empty());
    audit_proof(
        sealed.contract(),
        &result,
        &fix.target(),
        &MeasurementAllowlist::new(),
        JobVerification::SignatureOnly,
        100,
    )
    .unwrap();
    let answer = open_answer(
        &sealed,
        &result.to_bytes().unwrap(),
        &fix.user,
        &target,
        &MeasurementAllowlist::new(),
        JobVerification::SignatureOnly,
        100,
        &mut HostLog::default(),
    )
    .unwrap();
    assert_eq!(answer.as_slice(), b"ok");
}

#[test]
fn p2_refuses_a_transit_target_and_p1_refuses_a_private_one() {
    let fix = Fixture::new();
    let private = fix.target_p2();
    let transit = SealTarget::Transit(
        TransitTarget::new(
            fix.measurement,
            fix.executor.hpke_public().to_vec(),
            fix.executor.receipt_public(),
        )
        .unwrap(),
    );
    let p2 = fix.contract(Tier::P2, false, 1_000, 3, b"a");
    let p1 = fix.contract(Tier::P1, false, 1_000, 4, b"b");
    assert_eq!(
        seal_job(&p2, b"a", &params(), &transit).unwrap_err(),
        EnvelopeError::NotPrivateTarget
    );
    assert_eq!(
        seal_job(&p1, b"b", &params(), &private).unwrap_err(),
        EnvelopeError::NotTransitTarget
    );
}

#[test]
fn tampered_header_swapped_job_unknown_field_and_truncation_fail() {
    let fix = Fixture::new();
    let target = fix.target_p2();
    let contract = fix.contract(Tier::P2, false, 1_000, 5, CANARY);
    let sealed = seal_job(&contract, CANARY, &params(), &target).unwrap();
    let wire = sealed.to_bytes();
    let mut log = HostLog::default();

    let mut flipped = wire.clone();
    let at = flipped
        .windows(32)
        .position(|window| window == contract.job_id.as_slice())
        .unwrap();
    flipped[at + 31] ^= 0x01;
    let err = open_job(
        &flipped,
        &fix.executor,
        &fix.allowlist,
        10,
        &mut ReplayCache::default(),
        &mut log,
    )
    .unwrap_err();
    assert_eq!(err, EnvelopeError::BadSeal);
    assert_eq!(err.to_string(), "bad_seal");
    assert!(!log.contains("CANARY-SECRET-suricomai-9f3a"));

    let swapped = tamper_map(&wire, |map| {
        let header = cbor::as_bytes(map.get(&2).unwrap()).unwrap().to_vec();
        let mut parsed = PromptContract::from_bytes(&header).unwrap();
        parsed.job_id[0] ^= 0xff;
        map.insert(2, Cbor::Bytes(parsed.to_bytes().unwrap()));
    });
    assert_eq!(
        open_job(
            &swapped,
            &fix.executor,
            &fix.allowlist,
            10,
            &mut ReplayCache::default(),
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::BadSeal
    );

    let unknown = tamper_map(&wire, |map| {
        map.insert(99, Cbor::UInt(1));
    });
    assert_eq!(
        open_job(
            &unknown,
            &fix.executor,
            &fix.allowlist,
            10,
            &mut ReplayCache::default(),
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::UnknownField
    );

    let unknown_header = tamper_map(&wire, |map| {
        let header = cbor::as_bytes(map.get(&2).unwrap()).unwrap().to_vec();
        let edited = tamper_map(&header, |contract_map| {
            contract_map.insert(99, Cbor::UInt(1));
        });
        map.insert(2, Cbor::Bytes(edited));
    });
    assert_eq!(
        open_job(
            &unknown_header,
            &fix.executor,
            &fix.allowlist,
            10,
            &mut ReplayCache::default(),
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::UnknownField
    );

    let truncated = tamper_map(&wire, |map| {
        let mut prompt_ct = cbor::as_bytes(map.get(&5).unwrap()).unwrap().to_vec();
        prompt_ct.pop();
        map.insert(5, Cbor::Bytes(prompt_ct));
    });
    assert_eq!(
        open_job(
            &truncated,
            &fix.executor,
            &fix.allowlist,
            10,
            &mut ReplayCache::default(),
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::BadSeal
    );
}

fn p1_result(fix: &Fixture, job: u8) -> (SealedJob, SealedResult) {
    let target = SealTarget::Transit(
        TransitTarget::new(
            fix.measurement,
            fix.executor.hpke_public().to_vec(),
            fix.executor.receipt_public(),
        )
        .unwrap(),
    );
    let contract = fix.contract(Tier::P1, false, 1_000, job, b"bind");
    let sealed = seal_job(&contract, b"bind", &params(), &target).unwrap();
    let opened = open_job(
        &sealed.to_bytes(),
        &fix.executor,
        &MeasurementAllowlist::new(),
        10,
        &mut ReplayCache::default(),
        &mut HostLog::default(),
    )
    .unwrap();
    let result = finish_job(
        &opened,
        b"ok",
        1,
        [1u8; 32],
        [0u8; 32],
        [6u8; 32],
        1,
        2,
        None,
        &fix.executor,
        JobAttestation::NotRequired,
    )
    .unwrap();
    (sealed, result)
}

#[test]
fn audit_refuses_a_proof_signed_by_a_key_that_is_not_the_assigned_worker() {
    let fix = Fixture::new();
    let (sealed, result) = p1_result(&fix, 40);
    let attacker = EnclaveKeys::generate(fix.measurement).unwrap();
    let wrong_key = AuditTarget::new(fix.executor.executor_id(), attacker.receipt_public());
    let wrong_id = AuditTarget::new([0xee; 32], fix.executor.receipt_public());
    for target in [wrong_key, wrong_id] {
        assert_eq!(
            audit_proof(
                sealed.contract(),
                &result,
                &target,
                &MeasurementAllowlist::new(),
                JobVerification::SignatureOnly,
                100,
            )
            .unwrap_err(),
            EnvelopeError::IdentityMismatch
        );
    }
}

#[test]
fn a_proof_closes_only_the_contract_it_was_made_for() {
    let fix = Fixture::new();
    let (sealed, result) = p1_result(&fix, 41);
    let mut richer = sealed.contract().clone();
    richer.fee *= 100;
    let mut other_chain = sealed.contract().clone();
    other_chain.chain_id += 1;
    for contract in [richer, other_chain] {
        assert_eq!(
            audit_proof(
                &contract,
                &result,
                &fix.target(),
                &MeasurementAllowlist::new(),
                JobVerification::SignatureOnly,
                100,
            )
            .unwrap_err(),
            EnvelopeError::IdentityMismatch
        );
    }
}

#[test]
fn audit_refuses_a_proof_once_the_contract_has_expired() {
    let fix = Fixture::new();
    let (sealed, result) = p1_result(&fix, 42);
    assert_eq!(
        audit_proof(
            sealed.contract(),
            &result,
            &fix.target(),
            &MeasurementAllowlist::new(),
            JobVerification::SignatureOnly,
            sealed.contract().expiry,
        )
        .unwrap_err(),
        EnvelopeError::ProofExpired
    );
}

#[test]
fn contract_validation_codes_match_the_python_verifier() {
    let fix = Fixture::new();
    let good = fix.contract(Tier::P1, false, 1_000, 70, b"codes");
    type Mutation = fn(&mut PromptContract);
    let cases: [(&str, Mutation); 8] = [
        ("bad_size", |c| c.size_class = 5_000),
        ("plaintext_too_large", |c| c.max_output_bytes = u64::MAX),
        ("plaintext_too_large", |c| c.max_output_bytes = 4_093),
        ("plaintext_too_large", |c| c.max_output_bytes = 0),
        ("malformed", |c| c.min_canary_ppt = 1_001),
        ("bad_length", |c| c.region = vec![b'x'; 65]),
        ("bad_length", |c| c.user_hpke_public = vec![0u8; 10]),
        ("unexpected_gpu_evidence", |c| c.needs_gpu = true),
    ];
    for (code, mutate) in cases {
        let mut contract = good.clone();
        mutate(&mut contract);
        assert_eq!(contract.to_bytes().unwrap_err().code(), code);
    }
}

#[test]
fn every_contract_field_is_type_and_length_checked_like_the_python_verifier() {
    let fix = Fixture::new();
    let good = fix.contract(Tier::P1, false, 1_000, 72, b"fields");
    let original = good.to_bytes().unwrap();
    let Cbor::Map(base) = cbor::decode(&original).unwrap() else {
        panic!("contract is a map");
    };
    let bytes = |len: usize| Cbor::Bytes(vec![b'x'; len]);
    let cases: [(&str, u64, Cbor); 19] = [
        ("bad_length", 2, bytes(31)),
        ("bad_length", 5, bytes(33)),
        ("bad_length", 6, bytes(0)),
        ("bad_length", 12, bytes(31)),
        ("bad_length", 13, bytes(33)),
        ("malformed", 3, bytes(1)),
        ("malformed", 9, bytes(1)),
        ("malformed", 10, bytes(1)),
        ("malformed", 11, bytes(1)),
        ("malformed", 15, bytes(1)),
        ("malformed", 17, bytes(1)),
        ("malformed", 19, Cbor::UInt(1)),
        ("bad_size", 8, Cbor::UInt(5_000)),
        ("malformed", 16, Cbor::UInt(1_001)),
        ("bad_length", 19, bytes(65)),
        ("bad_length", 14, bytes(10)),
        ("malformed", 18, Cbor::UInt(2)),
        ("bad_tier", 4, Cbor::UInt(3)),
        ("bad_suite", 20, Cbor::UInt(2)),
    ];
    for (code, key, value) in cases {
        let mut map = base.clone();
        map.insert(key, value);
        let mutated = cbor::encode(&Cbor::Map(map));
        assert_eq!(
            PromptContract::from_bytes(&mutated).unwrap_err().code(),
            code,
            "key {key}"
        );
    }
}

#[test]
fn a_proof_with_a_token_count_that_is_not_a_bucket_is_refused() {
    let fix = Fixture::new();
    let (_, result) = p1_result(&fix, 71);
    let mut proof = result.proof().clone();
    assert!(ProofBundle::from_bytes(&proof.to_bytes().unwrap()).is_ok());
    for count in [1, 33, 100, 65_537] {
        proof.token_bucket = count;
        assert_eq!(
            ProofBundle::from_bytes(&proof.to_bytes().unwrap()).unwrap_err(),
            EnvelopeError::Malformed
        );
    }
}

#[test]
fn a_contract_naming_an_unknown_suite_is_refused() {
    let fix = Fixture::new();
    let contract = fix.contract(Tier::P1, false, 1_000, 50, b"suite");
    let mut bytes = contract.to_bytes().unwrap();
    // Key 20 is the last map entry, encoded as `0x14 0x01`.
    assert_eq!(bytes[bytes.len() - 2..], [0x14, 0x01]);
    assert!(PromptContract::from_bytes(&bytes).is_ok());
    *bytes.last_mut().unwrap() = 0x02;
    assert_eq!(
        PromptContract::from_bytes(&bytes).unwrap_err(),
        EnvelopeError::BadSuite
    );
}

#[test]
fn max_output_bytes_near_u64_max_is_refused_without_wrapping() {
    let fix = Fixture::new();
    let target = fix.target_p2();
    for huge in [u64::MAX, u64::MAX - 1, u64::MAX - 3] {
        let mut contract = fix.contract(Tier::P2, false, 1_000, 30, b"x");
        contract.max_output_bytes = huge;
        assert_eq!(
            seal_job(&contract, b"x", &params(), &target).unwrap_err(),
            EnvelopeError::PlaintextTooLarge
        );
    }
}

#[test]
fn a_full_replay_cache_drops_expired_ids_and_keeps_live_ones() {
    let mut cache = ReplayCache::new(2);
    cache.insert(1, [1u8; 32], [0u8; 32], 100, 0).unwrap();
    cache.insert(1, [2u8; 32], [0u8; 32], 500, 0).unwrap();
    assert_eq!(
        cache.insert(1, [3u8; 32], [0u8; 32], 900, 50).unwrap_err(),
        EnvelopeError::CacheFull
    );
    cache.insert(1, [3u8; 32], [0u8; 32], 900, 100).unwrap();
    assert_eq!(
        cache.insert(1, [2u8; 32], [0u8; 32], 500, 100).unwrap_err(),
        EnvelopeError::Replay
    );
}

#[test]
fn a_stranger_cannot_burn_a_job_id_with_a_different_contract() {
    let fix = Fixture::new();
    let target = fix.target_p2();
    let mut replay = ReplayCache::default();
    let real = fix.contract(Tier::P2, false, 1_000, 60, b"real prompt");
    let squat = fix.contract(Tier::P2, false, 900, 60, b"squatter");
    assert_eq!(real.job_id, squat.job_id);
    let squat_job = seal_job(&squat, b"squatter", &params(), &target).unwrap();
    let real_job = seal_job(&real, b"real prompt", &params(), &target).unwrap();
    let open = |job: &SealedJob, replay: &mut ReplayCache| {
        open_job(
            &job.to_bytes(),
            &fix.executor,
            &fix.allowlist,
            10,
            replay,
            &mut HostLog::default(),
        )
    };
    assert!(open(&squat_job, &mut replay).is_ok());
    assert!(open(&real_job, &mut replay).is_ok());
    assert_eq!(
        open(&real_job, &mut replay).unwrap_err(),
        EnvelopeError::Replay
    );
}

#[test]
fn the_replay_cache_survives_a_restart_and_rejects_a_damaged_copy() {
    let mut cache = ReplayCache::new(8);
    cache.insert(7, [1u8; 32], [2u8; 32], 500, 0).unwrap();
    cache.insert(7, [3u8; 32], [4u8; 32], 600, 0).unwrap();
    let saved = cache.to_bytes();
    let mut restored = ReplayCache::from_bytes(&saved, 8).unwrap();
    assert_eq!(restored.to_bytes(), saved);
    assert_eq!(
        restored
            .insert(7, [1u8; 32], [2u8; 32], 500, 10)
            .unwrap_err(),
        EnvelopeError::Replay
    );
    for damaged in [
        &saved[..saved.len() - 1],
        &saved[1..],
        b"SRC1\x00\x00\x00\x09".as_slice(),
        b"".as_slice(),
    ] {
        assert_eq!(
            ReplayCache::from_bytes(damaged, 8).unwrap_err(),
            EnvelopeError::BadSnapshot
        );
    }
    assert_eq!(
        ReplayCache::from_bytes(&saved, 1).unwrap_err(),
        EnvelopeError::BadSnapshot
    );
}

#[test]
fn a_contract_with_an_absurdly_far_expiry_is_refused() {
    let fix = Fixture::new();
    let target = fix.target_p2();
    let far = fix.contract(Tier::P2, false, 10 + MAX_CONTRACT_TTL_SECS + 1, 61, b"far");
    let sealed = seal_job(&far, b"far", &params(), &target).unwrap();
    assert_eq!(
        open_job(
            &sealed.to_bytes(),
            &fix.executor,
            &fix.allowlist,
            10,
            &mut ReplayCache::default(),
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::TtlTooLong
    );
}

#[test]
fn advertisements_must_be_fresh_and_bounded() {
    let fix = Fixture::new();
    let ad = advertise(&fix.executor, [9u8; 32], 100, 200, [0u8; 32], &fix.attester).unwrap();
    let check = |now: u64| verify_advertisement(&ad, &fix.allowlist, &fix.verifier, now);
    assert!(check(100).is_ok());
    assert!(check(199).is_ok());
    assert!(
        check(70).is_ok(),
        "a client clock slightly behind still accepts a fresh card"
    );
    for now in [0, 69, 200, 10_000] {
        assert_eq!(check(now).unwrap_err(), EnvelopeError::StaleAdvertisement);
    }
    assert_eq!(
        verify_transit_advertisement(&ad, &fix.verifier, 500).unwrap_err(),
        EnvelopeError::StaleAdvertisement
    );
    // A window longer than a day, or an empty one, cannot be built at all.
    for (from, to) in [(0, MAX_ADVERTISEMENT_SECS + 1), (50, 50), (60, 10)] {
        assert_eq!(
            advertise(&fix.executor, [9u8; 32], from, to, [0u8; 32], &fix.attester).unwrap_err(),
            EnvelopeError::StaleAdvertisement
        );
    }
    // Stretching the window after the quote was made breaks the quote.
    let mut stretched = ad.clone();
    stretched.valid_until = 100 + MAX_ADVERTISEMENT_SECS;
    assert_eq!(
        verify_advertisement(&stretched, &fix.allowlist, &fix.verifier, 150).unwrap_err(),
        EnvelopeError::BadQuote
    );
}

#[test]
fn the_host_log_stays_bounded() {
    let mut log = HostLog::default();
    for i in 0..10_000u32 {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&i.to_be_bytes());
        log.record(&id, 4096, &[0u8; 32], "bad_seal");
    }
    assert!(log.as_text().lines().count() <= 4096);
}

#[test]
fn replay_consumes_the_job_id_and_expiry_does_not() {
    let fix = Fixture::new();
    let target = fix.target_p2();
    let contract = fix.contract(Tier::P2, false, 1_000, 6, b"once");
    let sealed = seal_job(&contract, b"once", &params(), &target).unwrap();
    let mut replay = ReplayCache::new(8);
    assert!(open_job(
        &sealed.to_bytes(),
        &fix.executor,
        &fix.allowlist,
        10,
        &mut replay,
        &mut HostLog::default(),
    )
    .is_ok());
    assert_eq!(
        open_job(
            &sealed.to_bytes(),
            &fix.executor,
            &fix.allowlist,
            10,
            &mut replay,
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::Replay
    );

    let truncated = tamper_map(&sealed.to_bytes(), |map| {
        let mut prompt_ct = cbor::as_bytes(map.get(&5).unwrap()).unwrap().to_vec();
        prompt_ct.pop();
        map.insert(5, Cbor::Bytes(prompt_ct));
    });
    let mut replay = ReplayCache::default();
    assert_eq!(
        open_job(
            &truncated,
            &fix.executor,
            &fix.allowlist,
            10,
            &mut replay,
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::BadSeal
    );
    assert_eq!(
        open_job(
            &truncated,
            &fix.executor,
            &fix.allowlist,
            10,
            &mut replay,
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::BadSeal
    );

    let expired = fix.contract(Tier::P2, false, 50, 7, b"later");
    let sealed_expired = seal_job(&expired, b"later", &params(), &target).unwrap();
    let mut replay = ReplayCache::default();
    assert_eq!(
        open_job(
            &sealed_expired.to_bytes(),
            &fix.executor,
            &fix.allowlist,
            50,
            &mut replay,
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::Expired
    );
    let mut renewed = expired.clone();
    renewed.expiry = 500;
    let sealed_ok = seal_job(&renewed, b"later", &params(), &target).unwrap();
    assert!(open_job(
        &sealed_ok.to_bytes(),
        &fix.executor,
        &fix.allowlist,
        50,
        &mut replay,
        &mut HostLog::default(),
    )
    .is_ok());
}

#[test]
fn expired_truncated_job_is_expired_before_the_seal_is_opened() {
    let fix = Fixture::new();
    let target = fix.target_p2();
    let contract = fix.contract(Tier::P2, false, 20, 8, CANARY);
    let sealed = seal_job(&contract, CANARY, &params(), &target).unwrap();
    let truncated = tamper_map(&sealed.to_bytes(), |map| {
        let mut prompt_ct = cbor::as_bytes(map.get(&5).unwrap()).unwrap().to_vec();
        prompt_ct.pop();
        map.insert(5, Cbor::Bytes(prompt_ct));
    });
    let mut log = HostLog::default();
    let err = open_job(
        &truncated,
        &fix.executor,
        &fix.allowlist,
        20,
        &mut ReplayCache::default(),
        &mut log,
    )
    .unwrap_err();
    assert_eq!(err, EnvelopeError::Expired);
    assert!(!log.contains("CANARY-SECRET-suricomai-9f3a"));
}

#[test]
fn wrong_executor_and_missing_allowlist_fail_closed() {
    let fix = Fixture::new();
    let target = fix.target_p2();
    let contract = fix.contract(Tier::P2, false, 1_000, 9, b"nope");
    let sealed = seal_job(&contract, b"nope", &params(), &target).unwrap();
    let other = EnclaveKeys::generate([1u8; 32]).unwrap();
    assert_eq!(
        open_job(
            &sealed.to_bytes(),
            &other,
            &fix.allowlist,
            10,
            &mut ReplayCache::default(),
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::MeasurementRejected
    );

    let mut empty = MeasurementAllowlist::new();
    empty.insert(other.executor_id());
    assert_eq!(
        open_job(
            &sealed.to_bytes(),
            &fix.executor,
            &empty,
            10,
            &mut ReplayCache::default(),
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::MeasurementRejected
    );
}

#[test]
fn gpu_evidence_rules_and_answer_checks_happen_before_decrypt() {
    let fix = Fixture::new();
    let target = fix.target_p2();
    let contract = fix.contract(Tier::P2, true, 1_000, 10, b"gpu");
    let sealed = seal_job(&contract, b"gpu", &params(), &target).unwrap();
    let mut log = HostLog::default();
    let opened = open_job(
        &sealed.to_bytes(),
        &fix.executor,
        &fix.allowlist,
        10,
        &mut ReplayCache::default(),
        &mut log,
    )
    .unwrap();
    assert_eq!(
        finish_job(
            &opened,
            b"out",
            1,
            [8u8; 32],
            [0u8; 32],
            [6u8; 32],
            1,
            2,
            None,
            &fix.executor,
            JobAttestation::Quote(&fix.attester),
        )
        .unwrap_err(),
        EnvelopeError::MissingGpuEvidence
    );
    let result = finish_job(
        &opened,
        b"out",
        1,
        [8u8; 32],
        [0u8; 32],
        [6u8; 32],
        1,
        2,
        Some([9u8; 32]),
        &fix.executor,
        JobAttestation::Quote(&fix.attester),
    )
    .unwrap();
    let gpu_bytes = result.to_bytes().unwrap();
    assert_eq!(
        audit_proof(
            &contract,
            &result,
            &fix.target(),
            &fix.allowlist,
            JobVerification::Quote(&fix.verifier),
            100,
        )
        .unwrap_err(),
        EnvelopeError::MissingGpuEvidence
    );
    assert_eq!(
        open_answer(
            &sealed,
            &gpu_bytes,
            &fix.user,
            &target,
            &fix.allowlist,
            JobVerification::Quote(&fix.verifier),
            100,
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::MissingGpuEvidence
    );

    let cpu = fix.contract(Tier::P2, false, 1_000, 11, b"cpu");
    let sealed_cpu = seal_job(&cpu, b"cpu", &params(), &target).unwrap();
    let opened_cpu = open_job(
        &sealed_cpu.to_bytes(),
        &fix.executor,
        &fix.allowlist,
        10,
        &mut ReplayCache::default(),
        &mut HostLog::default(),
    )
    .unwrap();
    assert_eq!(
        finish_job(
            &opened_cpu,
            b"out",
            1,
            [8u8; 32],
            [0u8; 32],
            [6u8; 32],
            1,
            2,
            Some([9u8; 32]),
            &fix.executor,
            JobAttestation::Quote(&fix.attester),
        )
        .unwrap_err(),
        EnvelopeError::UnexpectedGpuEvidence
    );

    let opened_cpu_ok = open_job(
        &sealed_cpu.to_bytes(),
        &fix.executor,
        &fix.allowlist,
        10,
        &mut ReplayCache::default(),
        &mut HostLog::default(),
    )
    .unwrap();
    let result_cpu = finish_job(
        &opened_cpu_ok,
        b"out",
        1,
        [8u8; 32],
        [0u8; 32],
        [6u8; 32],
        1,
        2,
        None,
        &fix.executor,
        JobAttestation::Quote(&fix.attester),
    )
    .unwrap();
    let bytes = result_cpu.to_bytes().unwrap();
    let bad_sig = tamper_map(&bytes, |map| {
        let proof_bytes = cbor::as_bytes(map.get(&5).unwrap()).unwrap().to_vec();
        let edited = tamper_map(&proof_bytes, |proof| {
            let mut sig = cbor::as_bytes(proof.get(&12).unwrap()).unwrap().to_vec();
            let last = sig.len() - 1;
            sig[last] ^= 0xff;
            proof.insert(12, Cbor::Bytes(sig));
        });
        map.insert(5, Cbor::Bytes(edited));
    });
    assert_eq!(
        open_answer(
            &sealed_cpu,
            &bad_sig,
            &fix.user,
            &target,
            &fix.allowlist,
            JobVerification::Quote(&fix.verifier),
            100,
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::BadSignature
    );

    let truncated = tamper_map(&bytes, |map| {
        let mut answer_ct = cbor::as_bytes(map.get(&4).unwrap()).unwrap().to_vec();
        answer_ct.pop();
        map.insert(4, Cbor::Bytes(answer_ct));
    });
    assert_eq!(
        open_answer(
            &sealed_cpu,
            &truncated,
            &fix.user,
            &target,
            &fix.allowlist,
            JobVerification::Quote(&fix.verifier),
            100,
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::AnswerHashMismatch
    );

    let other = Fixture::new();
    let wrong_target = other.target_p2();
    let wrong_and_truncated = truncated;
    assert_eq!(
        open_answer(
            &sealed_cpu,
            &wrong_and_truncated,
            &fix.user,
            &wrong_target,
            &fix.allowlist,
            JobVerification::Quote(&fix.verifier),
            100,
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::IdentityMismatch
    );
}

#[test]
fn garbage_and_empty_inputs_fail() {
    let fix = Fixture::new();
    assert!(SealedJob::from_bytes(&[]).is_err());
    assert!(SealedJob::from_bytes(&[0xff; 32]).is_err());
    assert_eq!(
        open_job(
            &[0xff; 8],
            &fix.executor,
            &fix.allowlist,
            0,
            &mut ReplayCache::default(),
            &mut HostLog::default(),
        )
        .unwrap_err(),
        EnvelopeError::Malformed
    );
    assert_eq!(format!("{}", EnvelopeError::Malformed), "malformed");
    assert_eq!(format!("{:?}", fix.executor), "EnclaveKeys { redacted }");
    assert_eq!(format!("{:?}", fix.user), "UserKeys { redacted }");
}

#[test]
fn opened_answer_zeroizes_in_place() {
    let fix = Fixture::new();
    let target = fix.target_p2();
    let contract = fix.contract(Tier::P2, false, 1_000, 21, CANARY);
    let sealed = seal_job(&contract, CANARY, &params(), &target).unwrap();
    let opened = open_job(
        &sealed.to_bytes(),
        &fix.executor,
        &fix.allowlist,
        10,
        &mut ReplayCache::default(),
        &mut HostLog::default(),
    )
    .unwrap();
    let result = finish_job(
        &opened,
        CANARY,
        8,
        [8u8; 32],
        [0u8; 32],
        [6u8; 32],
        11,
        12,
        None,
        &fix.executor,
        JobAttestation::Quote(&fix.attester),
    )
    .unwrap();
    let mut answer = open_answer(
        &sealed,
        &result.to_bytes().unwrap(),
        &fix.user,
        &target,
        &fix.allowlist,
        JobVerification::Quote(&fix.verifier),
        100,
        &mut HostLog::default(),
    )
    .unwrap();
    assert!(answer.windows(CANARY.len()).any(|window| window == CANARY));
    answer.zeroize();
    assert!(answer.iter().all(|byte| *byte == 0));
    assert!(!answer.windows(CANARY.len()).any(|window| window == CANARY));
}

#[test]
fn audit_rejects_a_late_receipt_timestamp() {
    let fix = Fixture::new();
    let target = fix.target_p2();
    let contract = fix.contract(Tier::P2, false, 50, 9, b"late");
    let sealed = seal_job(&contract, b"late", &params(), &target).unwrap();
    let opened = open_job(
        &sealed.to_bytes(),
        &fix.executor,
        &fix.allowlist,
        10,
        &mut ReplayCache::default(),
        &mut HostLog::default(),
    )
    .unwrap();
    let result = finish_job(
        &opened,
        b"late",
        4,
        [8u8; 32],
        [0u8; 32],
        [6u8; 32],
        10,
        60,
        None,
        &fix.executor,
        JobAttestation::Quote(&fix.attester),
    )
    .unwrap();
    assert_eq!(
        audit_proof(
            sealed.contract(),
            &result,
            &fix.target(),
            &fix.allowlist,
            JobVerification::Quote(&fix.verifier),
            40,
        )
        .unwrap_err(),
        EnvelopeError::ProofExpired
    );
}

#[test]
fn token_buckets_round_up() {
    assert_eq!(token_bucket(0).unwrap(), 0);
    assert_eq!(token_bucket(1).unwrap(), 32);
    assert_eq!(token_bucket(32).unwrap(), 32);
    assert_eq!(token_bucket(33).unwrap(), 64);
    assert_eq!(token_bucket(100).unwrap(), 128);
    assert!(token_bucket(70_000).is_err());
}

// ------------------------------------------------------------ model manifests and approvals

mod models {
    use ed25519_dalek::SigningKey;

    use crate::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn manifest(id: &str, digest: u8, publisher: u8) -> ModelManifest {
        ModelManifest::publish(
            id,
            [digest; 32],
            [2u8; 32],
            [3u8; 32],
            135,
            "Apache-2.0",
            &key(publisher),
        )
        .unwrap()
    }

    fn approve(m: &ModelManifest, from: u64, until: u64, approver: u8) -> ModelApproval {
        ModelApproval::issue(m, ApprovalStatus::Approved, from, until, &key(approver)).unwrap()
    }

    fn catalog() -> ModelCatalog {
        ModelCatalog::new(vec![key(100).verifying_key().to_bytes()])
    }

    #[test]
    fn a_manifest_round_trips_and_its_signature_verifies() {
        let m = manifest("smollm2-135m-instruct", 1, 50);
        let bytes = m.to_bytes().unwrap();
        let back = ModelManifest::from_bytes(&bytes).unwrap();
        assert_eq!(back, m);
        back.verify_signature().unwrap();
        assert_eq!(back.id().unwrap(), m.id().unwrap());
    }

    #[test]
    fn any_change_to_a_manifest_breaks_its_signature_or_its_encoding() {
        let m = manifest("tiny", 1, 50);
        let edits: [fn(&mut ModelManifest); 6] = [
            |m| m.model_digest[0] ^= 1,
            |m| m.tokenizer_digest[0] ^= 1,
            |m| m.runtime_digest[0] ^= 1,
            |m| m.params_millions += 1,
            |m| m.license = "MIT".to_string(),
            |m| m.model_id = "other".to_string(),
        ];
        for edit in edits {
            let mut edited = m.clone();
            edit(&mut edited);
            assert_eq!(
                edited.verify_signature().unwrap_err(),
                EnvelopeError::BadSignature
            );
        }
        let mut swapped = m.clone();
        swapped.publisher_public = key(51).verifying_key().to_bytes();
        assert_eq!(
            swapped.verify_signature().unwrap_err(),
            EnvelopeError::BadSignature
        );
    }

    #[test]
    fn manifest_fields_are_validated() {
        let publisher = key(50);
        let build = |id: &str, license: &str, params: u64| {
            ModelManifest::publish(id, [1; 32], [2; 32], [3; 32], params, license, &publisher)
        };
        assert!(build("ok.model_1-b", "MIT", 1).is_ok());
        for bad in ["", "Upper", "has space", "slash/name", &"x".repeat(65)] {
            assert_eq!(
                build(bad, "MIT", 1).unwrap_err(),
                EnvelopeError::Malformed,
                "{bad}"
            );
        }
        for bad in ["", "bad license", &"x".repeat(33)] {
            assert_eq!(
                build("m", bad, 1).unwrap_err(),
                EnvelopeError::Malformed,
                "{bad}"
            );
        }
        assert_eq!(build("m", "MIT", 0).unwrap_err(), EnvelopeError::Malformed);
    }

    #[test]
    fn manifest_and_approval_bytes_must_be_canonical_and_complete() {
        let m = manifest("tiny", 1, 50);
        let bytes = m.to_bytes().unwrap();
        assert!(ModelManifest::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(ModelManifest::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_err());
        let a = approve(&m, 10, 20, 100);
        let ab = a.to_bytes();
        assert_eq!(ModelApproval::from_bytes(&ab).unwrap(), a);
        assert!(ModelApproval::from_bytes(&ab[..ab.len() - 1]).is_err());
        assert!(ModelApproval::from_bytes(&[ab.as_slice(), &[0]].concat()).is_err());
    }

    #[test]
    fn an_approval_needs_a_real_window_and_a_valid_signature() {
        let m = manifest("tiny", 1, 50);
        for (from, until) in [(10, 10), (20, 10)] {
            assert_eq!(
                ModelApproval::issue(&m, ApprovalStatus::Approved, from, until, &key(100))
                    .unwrap_err(),
                EnvelopeError::ApprovalWindow
            );
        }
        let mut a = approve(&m, 10, 20, 100);
        a.verify_signature().unwrap();
        a.valid_until = 10_000_000;
        assert_eq!(
            a.verify_signature().unwrap_err(),
            EnvelopeError::BadSignature
        );
        let mut a = approve(&m, 10, 20, 100);
        a.status = ApprovalStatus::Revoked;
        assert_eq!(
            a.verify_signature().unwrap_err(),
            EnvelopeError::BadSignature
        );
    }

    #[test]
    fn only_an_approved_and_in_window_model_passes() {
        let m = manifest("tiny", 1, 50);
        let mut c = catalog();
        assert_eq!(c.standing(&m.model_digest, 15), ModelStanding::Unknown);
        assert_eq!(
            c.require_approved(&m.model_digest, 15).unwrap_err(),
            EnvelopeError::ModelNotApproved
        );
        c.add(m.clone(), approve(&m, 10, 20, 100)).unwrap();
        assert_eq!(c.standing(&m.model_digest, 9), ModelStanding::NotYetValid);
        assert_eq!(c.standing(&m.model_digest, 10), ModelStanding::Approved);
        assert_eq!(c.standing(&m.model_digest, 19), ModelStanding::Approved);
        assert_eq!(c.standing(&m.model_digest, 20), ModelStanding::Expired);
        assert!(c.require_approved(&m.model_digest, 15).is_ok());
        for now in [9, 20, 1_000] {
            assert_eq!(
                c.require_approved(&m.model_digest, now).unwrap_err(),
                EnvelopeError::ApprovalWindow
            );
        }
    }

    #[test]
    fn an_approval_from_an_untrusted_key_or_for_another_manifest_is_refused() {
        let m = manifest("tiny", 1, 50);
        let mut c = catalog();
        assert_eq!(
            c.add(m.clone(), approve(&m, 10, 20, 101)).unwrap_err(),
            EnvelopeError::UntrustedApprover
        );
        let other = manifest("other", 9, 50);
        assert_eq!(
            c.add(m.clone(), approve(&other, 10, 20, 100)).unwrap_err(),
            EnvelopeError::IdentityMismatch
        );
        // A forged manifest signature is refused even with a good approval.
        let mut forged = m.clone();
        forged.params_millions += 1;
        let good_approval = approve(&m, 10, 20, 100);
        assert_eq!(
            c.add(forged, good_approval).unwrap_err(),
            EnvelopeError::BadSignature
        );
    }

    #[test]
    fn an_approval_cannot_be_moved_onto_an_edited_copy_of_the_manifest() {
        let original = manifest("tiny", 1, 50);
        let approval = approve(&original, 10, 20, 100);
        // The same publisher edits the license and signs again: a new manifest, a new id.
        let edited =
            ModelManifest::publish("tiny", [1; 32], [2; 32], [3; 32], 135, "GPL-3.0", &key(50))
                .unwrap();
        assert_ne!(edited.id().unwrap(), original.id().unwrap());
        let mut c = catalog();
        assert_eq!(
            c.add(edited, approval).unwrap_err(),
            EnvelopeError::IdentityMismatch
        );
    }

    #[test]
    fn a_scheduled_revocation_keeps_the_model_approved_until_its_date() {
        let m = manifest("tiny", 1, 50);
        let mut c = catalog();
        c.add(m.clone(), approve(&m, 10, 1_000, 100)).unwrap();
        let revoke =
            ModelApproval::issue(&m, ApprovalStatus::Revoked, 100, 1_000, &key(100)).unwrap();
        c.add(m.clone(), revoke).unwrap();
        assert_eq!(c.standing(&m.model_digest, 50), ModelStanding::Approved);
        assert_eq!(c.standing(&m.model_digest, 99), ModelStanding::Approved);
        assert_eq!(c.standing(&m.model_digest, 100), ModelStanding::Revoked);
        assert_eq!(c.standing(&m.model_digest, 150), ModelStanding::Revoked);
        // A revocation does not expire back into approval.
        assert_eq!(c.standing(&m.model_digest, 5_000), ModelStanding::Revoked);
        assert_eq!(
            c.require_approved(&m.model_digest, 150).unwrap_err(),
            EnvelopeError::ApprovalWindow
        );
        // A still later approval restores it.
        c.add(m.clone(), approve(&m, 200, 2_000, 100)).unwrap();
        assert_eq!(c.standing(&m.model_digest, 150), ModelStanding::Revoked);
        assert_eq!(c.standing(&m.model_digest, 250), ModelStanding::Approved);
        assert_eq!(c.standing(&m.model_digest, 2_000), ModelStanding::Expired);
    }

    #[test]
    fn an_older_decision_never_replaces_a_newer_one() {
        let m = manifest("tiny", 1, 50);
        let mut c = catalog();
        let revoke =
            ModelApproval::issue(&m, ApprovalStatus::Revoked, 100, 1_000, &key(100)).unwrap();
        c.add(m.clone(), revoke).unwrap();
        // Replaying the original, older approval must not undo the revocation.
        c.add(m.clone(), approve(&m, 10, 1_000, 100)).unwrap();
        assert_eq!(c.standing(&m.model_digest, 500), ModelStanding::Revoked);
    }

    #[test]
    fn a_different_publisher_cannot_take_over_a_known_digest() {
        let real = manifest("tiny", 1, 50);
        let mut c = catalog();
        c.add(real.clone(), approve(&real, 10, 1_000, 100)).unwrap();
        let squatter = manifest("tiny-fake", 1, 60);
        assert_eq!(
            c.add(squatter.clone(), approve(&squatter, 20, 1_000, 100))
                .unwrap_err(),
            EnvelopeError::IdentityMismatch
        );
        assert_eq!(
            c.by_id("tiny").unwrap().manifest.publisher_public,
            real.publisher_public
        );
    }

    #[test]
    fn models_are_found_by_name_and_listed_in_a_stable_order() {
        let a = manifest("b-model", 1, 50);
        let b = manifest("a-model", 2, 50);
        let mut c = catalog();
        c.add(a.clone(), approve(&a, 10, 20, 100)).unwrap();
        c.add(b.clone(), approve(&b, 10, 20, 100)).unwrap();
        let names: Vec<&str> = c
            .entries()
            .iter()
            .map(|e| e.manifest.model_id.as_str())
            .collect();
        assert_eq!(names, ["a-model", "b-model"]);
        assert!(c.by_id("a-model").is_some());
        assert!(c.by_id("missing").is_none());
    }

    fn trio(threshold: usize) -> ModelCatalog {
        let keys = (100..103)
            .map(|n| key(n).verifying_key().to_bytes())
            .collect();
        ModelCatalog::with_threshold(keys, threshold).unwrap()
    }

    #[test]
    fn an_approval_needs_the_threshold_of_distinct_approvers() {
        let m = manifest("tiny", 1, 50);
        let mut c = trio(2);
        c.add(m.clone(), approve(&m, 10, 1_000, 100)).unwrap();
        assert_eq!(c.standing(&m.model_digest, 50), ModelStanding::NotYetValid);
        assert_eq!(
            c.require_approved(&m.model_digest, 50).unwrap_err(),
            EnvelopeError::ApprovalWindow
        );
        c.add(m.clone(), approve(&m, 10, 1_000, 101)).unwrap();
        assert_eq!(c.standing(&m.model_digest, 50), ModelStanding::Approved);
    }

    #[test]
    fn one_approver_signing_twice_never_reaches_the_threshold() {
        let m = manifest("tiny", 1, 50);
        let mut c = trio(2);
        c.add(m.clone(), approve(&m, 10, 1_000, 100)).unwrap();
        c.add(m.clone(), approve(&m, 10, 1_000, 100)).unwrap();
        assert_eq!(c.standing(&m.model_digest, 50), ModelStanding::NotYetValid);
    }

    #[test]
    fn signatures_for_different_windows_do_not_add_up() {
        let m = manifest("tiny", 1, 50);
        let mut c = trio(2);
        c.add(m.clone(), approve(&m, 10, 1_000, 100)).unwrap();
        c.add(m.clone(), approve(&m, 10, 2_000, 101)).unwrap();
        assert_eq!(c.standing(&m.model_digest, 50), ModelStanding::NotYetValid);
    }

    #[test]
    fn one_approver_can_revoke_what_two_approved() {
        let m = manifest("tiny", 1, 50);
        let mut c = trio(2);
        c.add(m.clone(), approve(&m, 10, 1_000, 100)).unwrap();
        c.add(m.clone(), approve(&m, 10, 1_000, 101)).unwrap();
        let revoke =
            ModelApproval::issue(&m, ApprovalStatus::Revoked, 100, 1_000, &key(102)).unwrap();
        c.add(m.clone(), revoke).unwrap();
        assert_eq!(c.standing(&m.model_digest, 99), ModelStanding::Approved);
        assert_eq!(c.standing(&m.model_digest, 100), ModelStanding::Revoked);
        // Restoring needs the threshold again.
        c.add(m.clone(), approve(&m, 200, 1_000, 100)).unwrap();
        assert_eq!(c.standing(&m.model_digest, 250), ModelStanding::Revoked);
        c.add(m.clone(), approve(&m, 200, 1_000, 101)).unwrap();
        assert_eq!(c.standing(&m.model_digest, 250), ModelStanding::Approved);
    }

    #[test]
    fn a_revocation_wins_a_tie_with_an_approval() {
        let m = manifest("tiny", 1, 50);
        let mut c = trio(1);
        c.add(m.clone(), approve(&m, 10, 1_000, 100)).unwrap();
        let revoke =
            ModelApproval::issue(&m, ApprovalStatus::Revoked, 10, 1_000, &key(101)).unwrap();
        c.add(m.clone(), revoke).unwrap();
        assert_eq!(c.standing(&m.model_digest, 50), ModelStanding::Revoked);
    }

    #[test]
    fn threshold_settings_are_validated() {
        let keys: Vec<[u8; 32]> = (100..103)
            .map(|n| key(n).verifying_key().to_bytes())
            .collect();
        assert!(ModelCatalog::with_threshold(keys.clone(), 0).is_err());
        assert!(ModelCatalog::with_threshold(keys.clone(), 4).is_err());
        assert!(ModelCatalog::with_threshold(keys.clone(), 3).is_ok());
        let dup = vec![keys[0], keys[0], keys[1]];
        assert!(ModelCatalog::with_threshold(dup, 2).is_err());
    }
}

fn ad_with_transport(fix: &Fixture, transport: [u8; 32]) -> Advertisement {
    advertise(&fix.executor, [9u8; 32], 0, 3_600, transport, &fix.attester).unwrap()
}

#[test]
fn the_transport_key_is_inside_the_quoted_report_data() {
    let fix = Fixture::new();
    let mut ad = ad_with_transport(&fix, [7u8; 32]);
    let verified = verify_advertisement(&ad, &fix.allowlist, &fix.verifier, 10).unwrap();
    assert_eq!(verified.transport_public(), [7u8; 32]);
    ad.transport_public = [8u8; 32];
    assert_eq!(
        verify_advertisement(&ad, &fix.allowlist, &fix.verifier, 10).unwrap_err(),
        EnvelopeError::BadQuote
    );
    assert_eq!(
        verify_transit_advertisement(&ad, &fix.verifier, 10).unwrap_err(),
        EnvelopeError::BadQuote
    );
}

#[test]
fn a_quote_over_the_retired_report_data_is_refused() {
    let fix = Fixture::new();
    let mut ad = ad_with_transport(&fix, [7u8; 32]);
    let old_report = domain_hash(
        "suricomai.advertise.v1",
        &[
            &ad.hpke_public,
            &ad.receipt_public,
            &ad.executor_id,
            &ad.nonce,
            &ad.issued_at.to_be_bytes(),
            &ad.valid_until.to_be_bytes(),
        ],
    );
    ad.quote = fix.attester.attest(&ad.executor_id, &old_report).unwrap();
    assert_eq!(
        verify_advertisement(&ad, &fix.allowlist, &fix.verifier, 10).unwrap_err(),
        EnvelopeError::BadQuote
    );
}

#[test]
fn an_advertisement_round_trips_with_its_transport_key() {
    let fix = Fixture::new();
    let ad = ad_with_transport(&fix, [7u8; 32]);
    let back = Advertisement::from_bytes(&ad.to_bytes().unwrap()).unwrap();
    assert_eq!(back, ad);
    assert_eq!(back.transport_public, [7u8; 32]);
}

#[test]
fn a_version_one_or_incomplete_advertisement_is_refused() {
    let fix = Fixture::new();
    let bytes = ad_with_transport(&fix, [7u8; 32]).to_bytes().unwrap();
    let value = cbor::decode(&bytes).unwrap();

    let mut v1 = value.clone();
    cbor::as_map_mut(&mut v1).unwrap().insert(1, Cbor::UInt(1));
    assert_eq!(
        Advertisement::from_bytes(&cbor::encode(&v1)).unwrap_err(),
        EnvelopeError::BadVersion
    );

    let mut without_key = value.clone();
    cbor::as_map_mut(&mut without_key).unwrap().remove(&9);
    assert!(Advertisement::from_bytes(&cbor::encode(&without_key)).is_err());

    for bad in [vec![7u8; 31], vec![7u8; 33], Vec::new()] {
        let mut short = value.clone();
        cbor::as_map_mut(&mut short)
            .unwrap()
            .insert(9, Cbor::Bytes(bad));
        assert!(Advertisement::from_bytes(&cbor::encode(&short)).is_err());
    }

    let mut extra = value.clone();
    cbor::as_map_mut(&mut extra)
        .unwrap()
        .insert(10, Cbor::UInt(0));
    assert!(Advertisement::from_bytes(&cbor::encode(&extra)).is_err());
}
