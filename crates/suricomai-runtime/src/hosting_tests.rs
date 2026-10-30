// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! A node that hosts approved models, from the pack files to a sealed answer.

use std::fs;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use suricomai_envelope::{
    seal_job, verify_advertisement, ApprovalStatus, EnvelopeError, InferenceParams, LabAttester,
    MeasurementAllowlist, ModelCatalog, PromptContract, SealTarget, Tier,
};

use crate::chat::{pack_messages, ChatMessage};
use crate::client::{Client, JobRequest, PrivacyLabel};
use crate::error::RuntimeError;
use crate::pack::{load_catalog, load_hosted, HostLimits, HostedSet};
use crate::select::{survey, Candidate, Wanted};
use crate::testkit::{approve, good_pack, node_with, policy, HOSTED_NOW as NOW};
use crate::transport::{
    exchange_secure_via, fetch_model_card_via, serve_secure, Route, ServerLimits, TransportKey,
};
use crate::Executor;

struct Rig {
    dir: std::path::PathBuf,
    executor: Executor,
    client: Client,
    catalog: ModelCatalog,
    digest: [u8; 32],
    measurement: [u8; 32],
    manifest: suricomai_envelope::ModelManifest,
    attester: LabAttester,
}

fn rig() -> Rig {
    let (dir, model, manifest) = good_pack("fixture-a", 1);
    let digest = crate::model::weights_file_digest(&model.weights);
    let (catalog, _) = load_catalog(&dir, &policy()).unwrap();
    let (hosted, notes) = load_hosted(
        &dir,
        &catalog,
        NOW,
        HostLimits::default(),
        &[],
        &HostedSet::new(),
    );
    assert!(notes.is_empty(), "{notes:?}");
    let attester = LabAttester::generate();
    let mut executor = Executor::lab_measured(attester.clone()).unwrap();
    executor.set_transport_public([5u8; 32]);
    executor.set_models(catalog.clone(), hosted, Vec::new());
    let measurement = executor.status().measurement;
    let client = Client::new(executor.verifier(), measurement)
        .unwrap()
        .with_catalog(catalog.clone());
    Rig {
        dir,
        executor,
        client,
        catalog,
        digest,
        measurement,
        manifest,
        attester,
    }
}

/// A fresh client that trusts `catalog`.
fn client_with(rig: &Rig, catalog: &ModelCatalog) -> Client {
    Client::new(rig.executor.verifier(), rig.measurement)
        .unwrap()
        .with_catalog(catalog.clone())
}

fn request(now: u64) -> JobRequest {
    JobRequest {
        job_id: [8u8; 32],
        chain_id: 7,
        prompt: pack_messages(&[ChatMessage {
            role: "user".into(),
            content: "w3 w4 w5".into(),
        }])
        .unwrap(),
        params: InferenceParams::new([1u8; 32], 0, 8).unwrap(),
        now,
        expiry: now + 1_000,
        fee: 1,
        bond_required: 1,
        max_output_bytes: 64,
        size_class: 4_096,
        max_latency_ms: 150,
        user_pay_key: [5u8; 32],
    }
}

fn job(rig: &mut Rig, client: &Client, now: u64) -> Result<Vec<u8>, RuntimeError> {
    let card = rig.executor.model_card(&rig.digest, [4u8; 32], now)?;
    let executor = &mut rig.executor;
    client
        .complete_transit(&card, &request(now), |sealed| executor.handle(sealed, now))
        .map(|done| done.answer.to_vec())
}

#[test]
fn a_hosted_model_answers_a_non_private_job_through_the_real_path() {
    let mut rig = rig();
    let card = rig
        .executor
        .model_card(&rig.digest, [4u8; 32], NOW)
        .unwrap();
    assert_eq!(card.model_name, "fixture-a");
    let executor = &mut rig.executor;
    let done = rig
        .client
        .complete_transit(&card, &request(NOW), |sealed| executor.handle(sealed, NOW))
        .unwrap();
    assert_eq!(done.privacy, PrivacyLabel::NotPrivate);
    assert!(!done.answer.is_empty());
    fs::remove_dir_all(&rig.dir).unwrap();
}

#[test]
fn a_model_that_is_not_hosted_gets_no_card() {
    let rig = rig();
    assert_eq!(
        rig.executor
            .model_card(&[9u8; 32], [4u8; 32], NOW)
            .unwrap_err(),
        RuntimeError::ModelUnavailable
    );
    fs::remove_dir_all(&rig.dir).unwrap();
}

#[test]
fn a_private_job_for_a_hosted_model_is_refused_before_decryption() {
    let mut rig = rig();
    let builtin = rig.executor.card([4u8; 32], NOW).unwrap();
    let mut allowlist = MeasurementAllowlist::new();
    allowlist.insert(builtin.advertisement.executor_id);
    let verified = verify_advertisement(
        &builtin.advertisement,
        &allowlist,
        &rig.executor.verifier(),
        NOW,
    )
    .unwrap();
    let req = request(NOW);
    let mut contract = PromptContract {
        job_id: req.job_id,
        chain_id: req.chain_id,
        tier: Tier::P2,
        model_digest: rig.digest,
        prompt_commitment: [0u8; 32],
        max_output_bytes: req.max_output_bytes,
        size_class: req.size_class,
        fee: req.fee,
        bond_required: req.bond_required,
        expiry: req.expiry,
        privacy_policy_id: builtin.advertisement.executor_id,
        user_pay_key: req.user_pay_key,
        user_hpke_public: suricomai_envelope::UserKeys::generate()
            .unwrap()
            .hpke_public()
            .to_vec(),
        min_stake: 0,
        min_canary_ppt: 0,
        max_latency_ms: req.max_latency_ms,
        needs_gpu: false,
        region: Vec::new(),
    };
    contract.bind_prompt(&req.prompt);
    let sealed = seal_job(
        &contract,
        &req.prompt,
        &req.params,
        &SealTarget::Private(verified),
    )
    .unwrap();
    assert_eq!(
        rig.executor.handle(&sealed.to_bytes(), NOW).unwrap_err(),
        RuntimeError::NotHardwareP2
    );
    assert!(rig.executor.log().as_text().contains("not_hardware_p2"));
    fs::remove_dir_all(&rig.dir).unwrap();
}

#[test]
fn a_model_that_expires_while_the_node_runs_is_refused_at_the_next_job() {
    let mut rig = rig();
    let client = client_with(&rig, &rig.catalog);
    job(&mut rig, &client, NOW).unwrap();
    // This client would seal anyway, so the refusal below is the node's own check.
    let eager = client_with(&rig, &rig.catalog).allow_unapproved_non_private(true);
    // A card taken one second before the approval ends, so it is still fresh afterwards.
    let card = rig
        .executor
        .model_card(&rig.digest, [4u8; 32], 9_999)
        .unwrap();
    let late = 10_001;
    let mut req = request(late);
    req.job_id = [9u8; 32];
    let executor = &mut rig.executor;
    let err = eager
        .complete_transit(&card, &req, |sealed| executor.handle(sealed, late))
        .unwrap_err();
    assert_eq!(err, RuntimeError::Envelope(EnvelopeError::ApprovalWindow));
    assert!(rig.executor.log().as_text().contains("approval_window"));
    fs::remove_dir_all(&rig.dir).unwrap();
}

#[test]
fn a_model_revoked_while_the_node_runs_is_refused_at_the_next_job_without_a_restart() {
    let mut rig = rig();
    let client = client_with(&rig, &rig.catalog);
    job(&mut rig, &client, NOW).unwrap();
    // A card and a client from before the revocation, as a client that looked earlier would hold.
    let held_card = rig
        .executor
        .model_card(&rig.digest, [4u8; 32], NOW)
        .unwrap();

    approve(
        &rig.dir,
        &rig.manifest,
        1,
        ApprovalStatus::Revoked,
        500,
        10_000,
    );
    let (revoked, _) = load_catalog(&rig.dir, &policy()).unwrap();
    let hosted = rig.executor.hosted_snapshot();
    rig.executor.set_models(revoked, hosted, Vec::new());

    assert_eq!(
        rig.executor
            .model_card(&rig.digest, [4u8; 32], NOW)
            .unwrap_err(),
        RuntimeError::Envelope(EnvelopeError::ApprovalWindow),
        "no new card for a revoked model"
    );
    // The client still approves, so the node's own per-job check is what stops the job.
    let mut req = request(NOW);
    req.job_id = [10u8; 32];
    let executor = &mut rig.executor;
    let err = client
        .complete_transit(&held_card, &req, |sealed| executor.handle(sealed, NOW))
        .unwrap_err();
    assert_eq!(err, RuntimeError::Envelope(EnvelopeError::ApprovalWindow));
    fs::remove_dir_all(&rig.dir).unwrap();
}

#[test]
fn a_denied_model_is_refused_by_card_and_job_whatever_the_approvals_say() {
    let mut rig = rig();
    let card = rig
        .executor
        .model_card(&rig.digest, [4u8; 32], NOW)
        .unwrap();
    let hosted = rig.executor.hosted_snapshot();
    rig.executor
        .set_models(rig.catalog.clone(), hosted, vec![rig.digest]);
    assert_eq!(
        rig.executor
            .model_card(&rig.digest, [4u8; 32], NOW)
            .unwrap_err(),
        RuntimeError::Envelope(EnvelopeError::ModelNotApproved)
    );
    let executor = &mut rig.executor;
    let err = rig
        .client
        .complete_transit(&card, &request(NOW), |sealed| executor.handle(sealed, NOW))
        .unwrap_err();
    assert_eq!(err, RuntimeError::Envelope(EnvelopeError::ModelNotApproved));
    assert!(rig.executor.log().as_text().contains("model_not_approved"));
    fs::remove_dir_all(&rig.dir).unwrap();
}

#[test]
fn a_client_that_does_not_approve_or_denies_the_model_never_seals() {
    let rig = rig();
    let card = rig
        .executor
        .model_card(&rig.digest, [4u8; 32], NOW)
        .unwrap();
    let measurement = rig.executor.status().measurement;
    let verifier = rig.executor.verifier();

    let mut sent = false;
    let empty = Client::new(verifier.clone(), measurement)
        .unwrap()
        .with_catalog(policy_catalog());
    let err = empty
        .complete_transit(&card, &request(NOW), |_| {
            sent = true;
            Err(RuntimeError::Wire)
        })
        .unwrap_err();
    assert_eq!(err, RuntimeError::Envelope(EnvelopeError::ModelNotApproved));
    assert!(!sent, "nothing is sealed or sent to an unapproved model");

    for allow in [false, true] {
        let denying = Client::new(verifier.clone(), measurement)
            .unwrap()
            .with_catalog(rig.catalog.clone())
            .allow_unapproved_non_private(allow)
            .with_denied(vec![rig.digest]);
        let err = denying
            .complete_transit(&card, &request(NOW), |_| {
                sent = true;
                Err(RuntimeError::Wire)
            })
            .unwrap_err();
        assert_eq!(
            err,
            RuntimeError::Envelope(EnvelopeError::ModelNotApproved),
            "{allow}"
        );
    }
    assert!(!sent);
    fs::remove_dir_all(&rig.dir).unwrap();
}

fn policy_catalog() -> ModelCatalog {
    policy().catalog().unwrap()
}

#[test]
fn the_card_and_the_job_work_over_the_wire_and_a_malformed_card_request_closes() {
    let rig = rig();
    let key = Arc::new(TransportKey::generate().unwrap());
    let pinned = key.public();
    let mut executor = rig.executor;
    executor.set_transport_public(pinned);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(Mutex::new(executor));
    let server = thread::spawn({
        let (stop, shared) = (Arc::clone(&stop), Arc::clone(&shared));
        move || {
            serve_secure(
                listener,
                key,
                shared,
                ServerLimits::default(),
                Arc::new(|| NOW),
                stop,
            )
        }
    });
    let routes = [Route::Direct(addr)];
    let card = fetch_model_card_via(&routes, &pinned, [4u8; 32], &rig.digest, "fixture-a").unwrap();
    assert_eq!(card.model_digest, rig.digest);
    let done = rig
        .client
        .complete_transit(&card, &request(NOW), |sealed| {
            exchange_secure_via(&routes, &pinned, sealed)
        })
        .unwrap();
    assert!(!done.answer.is_empty());

    // A model the node does not host is refused by the node, not guessed at.
    assert_eq!(
        fetch_model_card_via(&routes, &pinned, [4u8; 32], &[9u8; 32], "nope").unwrap_err(),
        RuntimeError::ModelUnavailable
    );
    // A card for a different digest than the one requested is refused by the client.
    let other = crate::transport::exchange_secure_via(&routes, &pinned, &[0u8; 8]);
    assert!(other.is_err());
    stop.store(true, Ordering::Release);
    server.join().unwrap().unwrap();
    fs::remove_dir_all(&rig.dir).unwrap();
}

#[test]
fn a_survey_for_a_hosted_model_keeps_only_nodes_that_host_it() {
    let rig = rig();
    let verifier = rig.executor.verifier();
    let hosting_key = Arc::new(TransportKey::generate().unwrap());
    let hosting_pinned = hosting_key.public();
    let mut executor = rig.executor;
    executor.set_transport_public(hosting_pinned);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let hosting_addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(Mutex::new(executor));
    let server = thread::spawn({
        let (stop, shared) = (Arc::clone(&stop), Arc::clone(&shared));
        move || {
            serve_secure(
                listener,
                hosting_key,
                shared,
                ServerLimits::default(),
                Arc::new(|| NOW),
                stop,
            )
        }
    });
    // A second node with the same quote root that does not host the model.
    let bare = node_with(rig.attester.clone());
    let wanted = Wanted::Hosted {
        digest: rig.digest,
        name: "fixture-a".into(),
    };
    let candidates = [
        Candidate {
            addr: hosting_addr,
            key: hosting_pinned,
        },
        Candidate {
            addr: bare.addr,
            key: bare.pinned,
        },
    ];
    let client = Client::new(verifier, rig.measurement)
        .unwrap()
        .with_catalog(rig.catalog.clone());
    let eligible = survey(&client, &candidates, &wanted, NOW);
    assert_eq!(eligible.len(), 1);
    assert_eq!(eligible[0].candidate.addr, hosting_addr);
    stop.store(true, Ordering::Release);
    server.join().unwrap().unwrap();
    bare.shut_down();
    fs::remove_dir_all(&rig.dir).unwrap();
}
