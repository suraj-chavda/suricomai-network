// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use suricomai_envelope::{
    seal_job, InferenceParams, PromptContract, SealTarget, Tier, TransitTarget, UserKeys,
};

use crate::model::{self, infer};
use crate::wire::{exchange_tcp, serve_one};
use crate::{
    format_elapsed, serve_chat_once, ChatMessage, ChatRequest, Client, Executor, JobRequest,
    Outcome, PrivacyLabel, RuntimeError, Session, ADVERTISEMENT_SECS, MODEL_NAME,
};

const CANARY: &[u8] = b"CANARY-SECRET-suricomai-9f3a runtime-wire";

fn request(prompt: &[u8], job: u8) -> JobRequest {
    let mut job_id = [4u8; 32];
    job_id[31] = job;
    JobRequest {
        job_id,
        chain_id: 7,
        prompt: prompt.to_vec(),
        params: InferenceParams::new([3u8; 32], 0, 24).unwrap(),
        now: 10,
        expiry: 1_000,
        fee: 1,
        bond_required: 1,
        max_output_bytes: 64,
        size_class: 4_096,
        max_latency_ms: 150,
        user_pay_key: [5u8; 32],
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[test]
fn model_is_deterministic_and_weight_bound() {
    let weights = model::pinned_weights();
    assert_eq!(weights, model::pinned_weights());
    let digest = model::model_digest(&weights);
    let params = InferenceParams::new([3u8; 32], 0, 16).unwrap();
    let first = infer(&weights, b"alpha", &params, 64);
    let second = infer(&weights, b"alpha", &params, 64);
    assert_eq!(first, second);
    assert_ne!(first, infer(&weights, b"beta", &params, 64));
    let mut other = weights;
    other[0] ^= 1;
    assert_ne!(digest, model::model_digest(&other));
    assert_ne!(first, infer(&other, b"alpha", &params, 64));
    let measurement = model::runtime_measurement(&digest);
    assert_ne!(
        measurement,
        model::runtime_measurement(&model::model_digest(&other))
    );
}

#[test]
fn lab_node_refuses_a_hardware_p2_label() {
    let exec = Executor::lab().unwrap();
    let status = exec.status();
    assert!(!status.hardware_p2);
    assert!(!status.gpu_confidential);
    assert_eq!(status.quote_kind, "lab-untrusted");
    assert_eq!(status.measurement, exec.status().measurement);
    assert_eq!(
        exec.claim_hardware_p2().unwrap_err(),
        RuntimeError::NotHardwareP2
    );
    assert_eq!(format!("{exec:?}"), "Executor { redacted }");
}

#[test]
fn in_memory_job_keeps_the_prompt_out_of_the_log_and_proof() {
    let mut exec = Executor::lab().unwrap();
    let card = exec.card([9u8; 32], 0).unwrap();
    let client = Client::new(exec.verifier(), card.advertisement.executor_id).unwrap();
    let job = request(CANARY, 1);
    let completion = client
        .complete(&card, &job, |sealed| {
            assert!(!contains(sealed, CANARY));
            exec.handle(sealed, 10)
        })
        .unwrap();
    assert_eq!(completion.privacy, PrivacyLabel::LabUntrusted);
    assert!(!contains(&completion.proof.to_bytes().unwrap(), CANARY));
    assert!(!contains(exec.log().as_text().as_bytes(), CANARY));
    assert!(exec.log().contains("code=accepted"));
    assert!(exec.log().contains("code=finished"));
    assert!(!format!("{completion:?}").contains("CANARY-SECRET"));
    assert_ne!(completion.answer.as_slice(), CANARY);
    assert_eq!(completion.proof.model_digest, card.model_digest);
    assert_eq!(completion.proof.started_at, 10);
    assert!(completion.proof.finished_at >= completion.proof.started_at);
}

#[test]
fn wrong_model_and_gpu_jobs_fail_before_they_can_echo_the_prompt() {
    let mut exec = Executor::lab().unwrap();
    let card = exec.card([9u8; 32], 0).unwrap();
    let user = UserKeys::generate().unwrap();
    let mut allowlist = suricomai_envelope::MeasurementAllowlist::new();
    allowlist.insert(card.advertisement.executor_id);
    let verified = suricomai_envelope::verify_advertisement(
        &card.advertisement,
        &allowlist,
        &exec.verifier(),
        50,
    )
    .unwrap();
    let target = SealTarget::Private(verified);

    let mut contract = PromptContract {
        job_id: [8u8; 32],
        chain_id: 7,
        tier: Tier::P2,
        model_digest: [1u8; 32],
        prompt_commitment: [0u8; 32],
        max_output_bytes: 64,
        size_class: 4_096,
        fee: 1,
        bond_required: 1,
        expiry: 1_000,
        privacy_policy_id: [0u8; 32],
        user_pay_key: [5u8; 32],
        user_hpke_public: user.hpke_public().to_vec(),
        min_stake: 0,
        min_canary_ppt: 0,
        max_latency_ms: 0,
        needs_gpu: false,
        region: Vec::new(),
    };
    contract.bind_prompt(CANARY);
    let sealed = seal_job(&contract, CANARY, &request(CANARY, 1).params, &target).unwrap();
    let err = exec.handle(&sealed.to_bytes(), 10).unwrap_err();
    assert_eq!(err, RuntimeError::ModelMismatch);
    assert_eq!(err.to_string(), "model_mismatch");
    assert!(!contains(exec.log().as_text().as_bytes(), CANARY));

    contract.job_id[31] = 2;
    contract.model_digest = card.model_digest;
    contract.needs_gpu = true;
    contract.bind_prompt(CANARY);
    let sealed = seal_job(&contract, CANARY, &request(CANARY, 1).params, &target).unwrap();
    assert_eq!(
        exec.handle(&sealed.to_bytes(), 10).unwrap_err(),
        RuntimeError::GpuNotConfidential
    );
    assert!(!contains(exec.log().as_text().as_bytes(), CANARY));

    contract.needs_gpu = false;
    contract.bind_prompt(CANARY);
    let sealed = seal_job(&contract, CANARY, &request(CANARY, 1).params, &target).unwrap();
    assert!(exec.handle(&sealed.to_bytes(), 10).is_ok());
}

#[test]
fn the_audit_clock_tolerates_small_skew_and_never_passes_expiry() {
    use crate::client::audit_clock;
    use std::time::Instant;
    use suricomai_envelope::MAX_CLOCK_SKEW_SECS as CLOCK_SKEW_SECS;
    let sent = Instant::now();
    let far = audit_clock(1_000, sent, 1_000_000);
    assert_eq!(far, 1_000 + 1 + CLOCK_SKEW_SECS);
    let near = audit_clock(1_000, sent, 1_010);
    assert_eq!(near, 1_009, "skew may not reach the expiry");
    assert!(
        audit_clock(1_000, sent, 1_001) >= 1_001,
        "a job that really expired stays expired"
    );
}

#[test]
fn a_worker_clock_a_few_seconds_ahead_still_completes() {
    let mut exec = Executor::lab().unwrap();
    let card = exec.card([9u8; 32], 0).unwrap();
    let client = Client::new(exec.verifier(), card.advertisement.executor_id).unwrap();
    let req = request(b"skew", 6);
    let worker_now = req.now + 20;
    let completion = client
        .complete(&card, &req, |sealed| exec.handle(sealed, worker_now))
        .unwrap();
    assert_eq!(completion.privacy, PrivacyLabel::LabUntrusted);
}

#[test]
fn a_worker_clock_far_ahead_is_refused() {
    let mut exec = Executor::lab().unwrap();
    let card = exec.card([9u8; 32], 0).unwrap();
    let client = Client::new(exec.verifier(), card.advertisement.executor_id).unwrap();
    let req = request(b"skew", 7);
    let worker_now = req.now + 500;
    let err = client
        .complete(&card, &req, |sealed| exec.handle(sealed, worker_now))
        .unwrap_err();
    assert_eq!(
        err,
        RuntimeError::Envelope(suricomai_envelope::EnvelopeError::ProofExpired)
    );
}

#[test]
fn a_slow_worker_is_waited_for_over_the_wire() {
    let mut exec = Executor::lab().unwrap();
    let card = exec.card([9u8; 32], 0).unwrap();
    let client = Client::new(exec.verifier(), card.advertisement.executor_id).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        // Take the request, then think for longer than the short per-read timeout.
        let (mut stream, _) = listener.accept().unwrap();
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut body).unwrap();
        thread::sleep(Duration::from_millis(2_500));
        let reply = exec.handle(&body[1..], 10).unwrap();
        let mut framed = vec![0u8];
        framed.extend_from_slice(&reply);
        stream
            .write_all(&(framed.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(&framed).unwrap();
    });
    let completion = client
        .complete(&card, &request(b"slow", 8), |sealed| {
            exchange_tcp(addr, sealed)
        })
        .unwrap();
    worker.join().unwrap();
    assert_eq!(completion.privacy, PrivacyLabel::LabUntrusted);
}

mod model_policy {
    use ed25519_dalek::SigningKey;
    use suricomai_envelope::{
        ApprovalStatus, EnvelopeError, ModelApproval, ModelCatalog, ModelManifest,
    };

    use super::*;
    use crate::model::{model_digest, pinned_weights};

    fn approver() -> SigningKey {
        SigningKey::from_bytes(&[77u8; 32])
    }

    fn tiny_manifest() -> ModelManifest {
        ModelManifest::publish(
            MODEL_NAME,
            model_digest(&pinned_weights()),
            [1u8; 32],
            [2u8; 32],
            1,
            "MIT",
            &SigningKey::from_bytes(&[78u8; 32]),
        )
        .unwrap()
    }

    /// A catalog whose only decision about the tiny model is `status` during `[from, until)`.
    fn catalog(status: Option<(ApprovalStatus, u64, u64)>) -> ModelCatalog {
        let mut catalog = ModelCatalog::new(vec![approver().verifying_key().to_bytes()]);
        if let Some((status, from, until)) = status {
            let manifest = tiny_manifest();
            let approval =
                ModelApproval::issue(&manifest, status, from, until, &approver()).unwrap();
            catalog.add(manifest, approval).unwrap();
        }
        catalog
    }

    fn setup(catalog: ModelCatalog) -> (Executor, crate::NodeCard, Client) {
        let exec = Executor::lab().unwrap();
        let card = exec.card([9u8; 32], 0).unwrap();
        let client = Client::new(exec.verifier(), card.advertisement.executor_id)
            .unwrap()
            .with_catalog(catalog);
        (exec, card, client)
    }

    fn envelope(err: EnvelopeError) -> RuntimeError {
        RuntimeError::Envelope(err)
    }

    #[test]
    fn a_model_the_catalog_does_not_know_is_refused_before_anything_is_sealed() {
        let (_, card, client) = setup(catalog(None));
        let mut called = false;
        let err = client
            .complete(&card, &request(b"x", 20), |_| {
                called = true;
                Ok(Vec::new())
            })
            .unwrap_err();
        assert_eq!(err, envelope(EnvelopeError::ModelNotApproved));
        assert!(!called, "nothing may leave the client");
    }

    #[test]
    fn approval_windows_and_revocations_are_enforced_at_the_callers_time() {
        let (mut exec, card, client) = setup(catalog(Some((ApprovalStatus::Approved, 100, 200))));
        let mut req = request(b"window", 21);
        let run = |now: u64, exec: &mut Executor| {
            let mut r = request(b"window", 21);
            r.now = now;
            r.expiry = now + 500;
            client.complete(&card, &r, |sealed| exec.handle(sealed, now))
        };
        assert_eq!(
            run(50, &mut exec).unwrap_err(),
            envelope(EnvelopeError::ApprovalWindow)
        );
        assert!(run(150, &mut exec).is_ok());
        let mut again = request(b"window", 22);
        again.now = 250;
        again.expiry = 750;
        assert_eq!(
            client
                .complete(&card, &again, |_| Ok(Vec::new()))
                .unwrap_err(),
            envelope(EnvelopeError::ApprovalWindow),
            "an approval that has ended is not renewed by itself"
        );
        req.now = 150;
        let (_, card, revoked) = setup(catalog(Some((ApprovalStatus::Revoked, 0, 1_000))));
        assert_eq!(
            revoked
                .complete(&card, &req, |_| Ok(Vec::new()))
                .unwrap_err(),
            envelope(EnvelopeError::ApprovalWindow)
        );
    }

    #[test]
    fn a_non_private_job_may_use_an_unapproved_model_only_when_the_user_opts_in() {
        let (mut exec, card, strict) = setup(catalog(None));
        let err = strict
            .complete_transit(&card, &request(b"p1", 23), |_| Ok(Vec::new()))
            .unwrap_err();
        assert_eq!(err, envelope(EnvelopeError::ModelNotApproved));

        let relaxed = Client::new(exec.verifier(), card.advertisement.executor_id)
            .unwrap()
            .with_catalog(catalog(None))
            .allow_unapproved_non_private(true);
        let done = relaxed
            .complete_transit(&card, &request(b"p1", 24), |sealed| exec.handle(sealed, 10))
            .unwrap();
        assert_eq!(done.privacy, PrivacyLabel::NotPrivate);

        // The opt-in never reaches the private tier.
        let mut called = false;
        let err = relaxed
            .complete(&card, &request(b"p2", 25), |_| {
                called = true;
                Ok(Vec::new())
            })
            .unwrap_err();
        assert_eq!(err, envelope(EnvelopeError::ModelNotApproved));
        assert!(!called);
    }

    #[test]
    fn an_approved_model_works_for_both_tiers() {
        let (mut exec, card, client) = setup(catalog(Some((ApprovalStatus::Approved, 0, 10_000))));
        assert!(client
            .complete(&card, &request(b"ok", 26), |sealed| exec.handle(sealed, 10))
            .is_ok());
        assert!(client
            .complete_transit(&card, &request(b"ok", 27), |sealed| exec.handle(sealed, 10))
            .is_ok());
    }

    #[test]
    fn the_session_lists_models_with_their_standing_and_refuses_unknown_ones() {
        let mut session = Session::start(0).unwrap();
        let Outcome::Note(list) = session.submit_line("/models", 10) else {
            panic!("expected a list");
        };
        assert!(list.contains("suricomai-tiny-v1"), "{list}");
        assert!(list.contains("approved"), "{list}");
        assert!(list.contains("lab-untrusted"), "{list}");
        let Outcome::Note(unknown) = session.submit_line("/model not-a-model", 10) else {
            panic!("expected a note");
        };
        assert!(unknown.contains("Unknown model"));
        // The lab approval covers the lab period, so the built-in model is selectable.
        assert!(matches!(
            session.submit_line("/model suricomai-tiny-v1", 10),
            Outcome::Note(_)
        ));
    }
}

#[test]
fn a_stale_card_is_refused_before_anything_is_sealed() {
    let exec = Executor::lab().unwrap();
    let card = exec.card([9u8; 32], 100).unwrap();
    let client = Client::new(exec.verifier(), card.advertisement.executor_id).unwrap();
    let mut called = false;
    for now in [69, 100 + ADVERTISEMENT_SECS] {
        let mut late = request(b"stale", 5);
        late.now = now;
        late.expiry = now + 120;
        let err = client
            .complete(&card, &late, |_| {
                called = true;
                Ok(Vec::new())
            })
            .unwrap_err();
        assert_eq!(
            err,
            RuntimeError::Envelope(suricomai_envelope::EnvelopeError::StaleAdvertisement)
        );
    }
    assert!(!called, "nothing may leave the client for a stale card");
}

#[test]
fn forged_hardware_card_is_rejected_before_seal() {
    let exec = Executor::lab().unwrap();
    let mut card = exec.card([9u8; 32], 0).unwrap();
    let client = Client::new(exec.verifier(), card.advertisement.executor_id).unwrap();
    card.hardware_p2 = true;
    let err = client
        .complete(&card, &request(b"nope", 3), |_| Ok(Vec::new()))
        .unwrap_err();
    assert_eq!(err, RuntimeError::NotHardwareP2);
}

#[test]
fn socket_capture_does_not_contain_the_prompt() {
    let mut exec = Executor::lab().unwrap();
    let card = exec.card([9u8; 32], 0).unwrap();
    let client = Client::new(exec.verifier(), card.advertisement.executor_id).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let worker = thread::spawn(move || serve_one(listener, &mut exec, 10).unwrap());
    let job = request(CANARY, 4);
    let completion = client
        .complete(&card, &job, |sealed| exchange_tcp(addr, sealed))
        .unwrap();
    let captured = worker.join().unwrap();
    assert!(!contains(&captured, CANARY));
    assert_eq!(completion.privacy, PrivacyLabel::LabUntrusted);
    assert!(!contains(&completion.proof.to_bytes().unwrap(), CANARY));
}

#[test]
fn transit_worker_can_run_a_non_private_job() {
    let mut exec = Executor::lab().unwrap();
    let measurement = exec.status().measurement;
    let user = UserKeys::generate().unwrap();
    let card = exec.card([1u8; 32], 0).unwrap();
    let target = SealTarget::Transit(
        TransitTarget::new(
            measurement,
            card.advertisement.hpke_public.clone(),
            card.advertisement.receipt_public,
        )
        .unwrap(),
    );
    let prompt = b"worker-can-read-this";
    let mut contract = PromptContract {
        job_id: [6u8; 32],
        chain_id: 7,
        tier: Tier::P1,
        model_digest: card.model_digest,
        prompt_commitment: [0u8; 32],
        max_output_bytes: 32,
        size_class: 4_096,
        fee: 1,
        bond_required: 1,
        expiry: 1_000,
        privacy_policy_id: [0u8; 32],
        user_pay_key: [5u8; 32],
        user_hpke_public: user.hpke_public().to_vec(),
        min_stake: 0,
        min_canary_ppt: 0,
        max_latency_ms: 0,
        needs_gpu: false,
        region: Vec::new(),
    };
    contract.bind_prompt(prompt);
    let params = InferenceParams::new([3u8; 32], 0, 8).unwrap();
    let sealed = seal_job(&contract, prompt, &params, &target).unwrap();
    let result = exec.handle(&sealed.to_bytes(), 10).unwrap();
    assert!(!contains(&result, prompt));
    assert!(suricomai_envelope::SealedResult::from_bytes(&result)
        .unwrap()
        .proof()
        .quote
        .is_empty());
}

#[test]
fn chat_rejects_a_foreign_model_before_exchange() {
    let exec = Executor::lab().unwrap();
    let card = exec.card([9u8; 32], 0).unwrap();
    let client = Client::new(exec.verifier(), card.advertisement.executor_id).unwrap();
    let mut called = false;
    let err = client
        .chat(
            &card,
            &ChatRequest {
                model: "other-model".to_string(),
                messages: vec![ChatMessage {
                    role: "user".to_string(),
                    content: CANARY_TEXT.to_string(),
                }],
                temperature: Some(0.0),
                max_tokens: Some(8),
            },
            10,
            |_| {
                called = true;
                Ok(Vec::new())
            },
        )
        .unwrap_err();
    assert!(!called);
    assert_eq!(err, RuntimeError::ModelMismatch);
    let request = ChatRequest {
        model: MODEL_NAME.to_string(),
        messages: vec![ChatMessage {
            role: "user".to_string(),
            content: CANARY_TEXT.to_string(),
        }],
        temperature: None,
        max_tokens: None,
    };
    assert!(!format!("{request:?}").contains("CANARY-SECRET"));
}

#[test]
fn chat_http_keeps_the_prompt_off_the_executor_socket() {
    let mut exec = Executor::lab().unwrap();
    let card = exec.card([9u8; 32], 0).unwrap();
    let client = Client::new(exec.verifier(), card.advertisement.executor_id).unwrap();
    let executor = TcpListener::bind("127.0.0.1:0").unwrap();
    let executor_addr = executor.local_addr().unwrap();
    let worker = thread::spawn(move || serve_one(executor, &mut exec, 10).unwrap());

    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    let api_addr = api.local_addr().unwrap();
    let api_thread = thread::spawn(move || {
        serve_chat_once(api, &client, &card, executor_addr, 10).unwrap();
    });

    let body = format!(
        "{{\"model\":\"{MODEL_NAME}\",\"messages\":[{{\"role\":\"user\",\"content\":\"{CANARY_TEXT}\"}}],\"temperature\":0,\"max_tokens\":16}}"
    );
    let response = http_post(api_addr, &body);
    api_thread.join().unwrap();
    let captured = worker.join().unwrap();

    assert!(!contains(&captured, CANARY));
    assert!(!response.contains(CANARY_TEXT));
    assert!(response.contains("\"privacy\":\"lab-untrusted\""));
    assert!(response.contains("\"hardware_p2\":false"));
    assert!(response.contains("\"object\":\"chat.completion\""));
}

const CANARY_TEXT: &str = "CANARY-SECRET-suricomai-9f3a runtime-wire";

#[test]
fn interactive_session_keeps_typed_text_out_of_the_seal() {
    let mut session = Session::start(0).unwrap();
    let typed = "CANARY-SECRET-suricomai-9f3a cli-user";
    let outcome = session.submit_line(typed, 10);
    let Outcome::Reply(reply) = outcome else {
        panic!("expected a reply");
    };
    assert!(reply.prompt_checked);
    assert!(!reply.prompt_in_seal);
    assert!(!reply.prompt_in_log);
    assert_eq!(reply.privacy, "lab-untrusted");
    assert!(!reply.hardware_p2);
    assert!(!reply.content.contains("CANARY-SECRET"));
    assert!(session.lines().iter().any(|line| line.text == typed));
    assert!(session
        .lines()
        .iter()
        .any(|line| line.text.contains("second")));
    assert!(matches!(session.submit_line("/nope", 11), Outcome::Note(_)));
    assert_eq!(session.header().turns, 1);
    let switched = session.submit_line(MODEL_NAME, 12);
    let Outcome::Note(note) = switched else {
        panic!("a model name is a switch, not a prompt");
    };
    assert!(note.contains(MODEL_NAME));
    assert!(session.lines().is_empty());
    assert_eq!(session.header().model, MODEL_NAME);
}

#[test]
fn selected_text_model_returns_words_and_stays_not_private() {
    let mut session = Session::start(0).unwrap();
    let listed = session.submit_line("/models", 10);
    let Outcome::Note(listed) = listed else {
        panic!("expected the model list");
    };
    assert!(listed.contains(MODEL_NAME));
    assert!(listed.contains("smollm2-135m-instruct"));
    if !listed.contains("installed, not private") {
        return;
    }
    let switched = session.submit_line("/model smollm2-135m-instruct", 11);
    assert!(matches!(switched, Outcome::Note(_)));
    assert_eq!(session.header().privacy, "not-private");
    assert!(!session.header().hardware_p2);
    let typed = "CANARY-SECRET-suricomai-9f3a say hello";
    let outcome = session.submit_line(typed, 12);
    let Outcome::Reply(reply) = outcome else {
        panic!("expected a text reply");
    };
    assert_eq!(reply.privacy, "not-private");
    assert!(!reply.prompt_in_seal);
    assert!(!reply.prompt_in_log);
    assert!(reply.content.chars().any(|ch| ch.is_ascii_alphabetic()));
}

#[test]
fn a_typed_message_is_never_read_as_a_command() {
    let mut session = Session::start(0).unwrap();
    for text in [
        "/clear",
        "/quit",
        "/exit",
        "/temp 2",
        "/tokens 1",
        "/model smollm2-135m-instruct",
        "/proof",
    ] {
        let outcome = session.say_prompt(text, 10);
        assert!(
            matches!(outcome, Outcome::Reply(_)),
            "{text:?} must reach the model as a message, got {outcome:?}"
        );
    }
    let header = session.header();
    assert_eq!(header.turns, 7, "every line counted as a message");
    assert_eq!(header.model, MODEL_NAME, "no typed line switched the model");
    assert_eq!(header.max_tokens, 16, "no typed line changed a setting");
    assert!((header.temperature - 0.0).abs() < f64::EPSILON);
    assert!(session.lines().iter().any(|line| line.text == "/clear"));
}

#[test]
fn an_empty_message_is_a_note_and_sends_nothing() {
    let mut session = Session::start(0).unwrap();
    for text in ["", " ", "\n\t  "] {
        assert!(matches!(session.say_prompt(text, 10), Outcome::Note(_)));
    }
    assert_eq!(session.header().turns, 0);
    assert!(session.lines().is_empty());
}

#[test]
fn the_model_list_is_data_with_one_active_model() {
    let session = Session::start(0).unwrap();
    let rows = session.model_rows(10);
    let tiny = rows.iter().find(|row| row.id == MODEL_NAME).unwrap();
    assert_eq!(tiny.standing, "approved");
    assert_eq!(tiny.privacy, "lab-untrusted");
    assert!(tiny.installed && tiny.active);
    assert_eq!(tiny.digest_prefix.len(), 12);
    assert!(tiny.digest_prefix.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(rows.iter().filter(|row| row.active).count(), 1);
    let text = rows
        .iter()
        .find(|row| row.id == "smollm2-135m-instruct")
        .unwrap();
    assert_eq!(text.privacy, "not-private");
    assert!(!text.active);
    assert_eq!(text.installed, !text.digest_prefix.is_empty());
}

#[test]
fn choosing_a_model_changes_the_active_row_and_unknown_names_change_nothing() {
    let mut session = Session::start(0).unwrap();
    assert!(matches!(
        session.select_model("no-such-model", 10),
        Outcome::Note(_)
    ));
    assert_eq!(session.header().model, MODEL_NAME);
    assert!(matches!(
        session.select_model("../../etc/passwd", 10),
        Outcome::Note(_)
    ));
    let installed = session
        .model_rows(10)
        .iter()
        .any(|row| row.id == "smollm2-135m-instruct" && row.installed);
    let outcome = session.select_model("smollm2-135m-instruct", 10);
    if installed {
        assert!(matches!(outcome, Outcome::Note(_)));
        let active: Vec<_> = session
            .model_rows(10)
            .into_iter()
            .filter(|row| row.active)
            .map(|row| row.id)
            .collect();
        assert_eq!(active, vec!["smollm2-135m-instruct".to_string()]);
        assert_eq!(session.header().privacy, "not-private");
        assert!(matches!(
            session.select_model(MODEL_NAME, 10),
            Outcome::Note(_)
        ));
    } else {
        assert_eq!(outcome, Outcome::Failed("model_unavailable"));
        assert_eq!(session.header().model, MODEL_NAME);
    }
}

#[test]
fn settings_accept_their_range_and_refuse_everything_else() {
    let mut session = Session::start(0).unwrap();
    for ok in [0.0, 0.7, 2.0] {
        assert!(session.set_temperature(ok).is_ok());
    }
    for bad in [-0.1, 2.1, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(session.set_temperature(bad), Err(RuntimeError::BadRequest));
    }
    assert!(
        (session.header().temperature - 2.0).abs() < f64::EPSILON,
        "a refused value changes nothing"
    );
    for ok in [1, 16, 256] {
        assert!(session.set_max_tokens(ok).is_ok());
    }
    for bad in [0, 257, u64::MAX] {
        assert_eq!(session.set_max_tokens(bad), Err(RuntimeError::BadRequest));
    }
    assert_eq!(session.header().max_tokens, 256);
}

#[test]
fn clear_forgets_the_chat_and_the_receipt() {
    let mut session = Session::start(0).unwrap();
    assert!(session.last_proof().is_none());
    assert!(matches!(
        session.say_prompt("hello there", 10),
        Outcome::Reply(_)
    ));
    assert_eq!(session.header().turns, 1);
    let proof = session.last_proof().expect("a receipt after a job").clone();
    assert_eq!(proof.privacy, "lab-untrusted");
    assert!(proof.bytes > 0);
    session.clear();
    assert_eq!(session.header().turns, 0);
    assert!(session.lines().is_empty());
    assert!(session.last_proof().is_none());
}

#[test]
fn elapsed_words_follow_the_receipt_seconds() {
    assert_eq!(format_elapsed(0), "under 1 second");
    assert_eq!(format_elapsed(1), "1 second");
    assert_eq!(format_elapsed(8), "8 seconds");
    assert_eq!(format_elapsed(60), "1 minute");
    assert_eq!(format_elapsed(125), "2 minutes 5 seconds");
    assert_eq!(format_elapsed(3_600), "1 hour");
    assert_eq!(format_elapsed(7_381), "2 hours 3 minutes 1 second");
}

fn http_post(addr: std::net::SocketAddr, json: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let payload = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
        json.len()
    );
    stream.write_all(payload.as_bytes()).unwrap();
    let mut buf = String::new();
    stream.read_to_string(&mut buf).unwrap();
    buf
}
