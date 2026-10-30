// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! One lab executor and one client on localhost.
//!
//! The quote is a software stand-in. The process refuses to call itself hardware P2.
//! The prompt is not printed, and it is not what the socket carries.

use std::net::TcpListener;
use std::thread;

use suricomai_envelope::InferenceParams;
use suricomai_runtime::{exchange_tcp, serve_one, Client, Executor, JobRequest, PrivacyLabel};

fn main() {
    let mut executor = Executor::lab().expect("executor");
    let status = executor.status();
    assert!(!status.hardware_p2);
    assert!(executor.claim_hardware_p2().is_err());

    let card = executor.card([9u8; 32], 0).expect("card");
    let client = Client::new(executor.verifier(), status.measurement).expect("client");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let worker = thread::spawn(move || serve_one(listener, &mut executor, 50).expect("serve"));

    let prompt = b"CANARY-SECRET-suricomai-9f3a";
    let request = JobRequest {
        job_id: [1u8; 32],
        chain_id: 7,
        prompt: prompt.to_vec(),
        params: InferenceParams::new([3u8; 32], 0, 16).expect("params"),
        now: 50,
        expiry: 1_000,
        fee: 1,
        bond_required: 1,
        max_output_bytes: 64,
        size_class: 4_096,
        max_latency_ms: 150,
        user_pay_key: [5u8; 32],
    };
    let completion = client
        .complete(&card, &request, |sealed| exchange_tcp(addr, sealed))
        .expect("complete");
    let captured = worker.join().expect("server thread");
    let leaked = captured
        .windows(prompt.len())
        .any(|window| window == prompt);

    assert!(!leaked, "prompt was on the socket");
    assert_eq!(completion.privacy, PrivacyLabel::LabUntrusted);
    println!("privacy=lab-untrusted");
    println!("hardware_p2=false");
    println!("gpu_confidential=false");
    println!("prompt_on_wire=false");
    println!("answer_len={}", completion.answer.len());
    println!(
        "proof_bytes={}",
        completion.proof.to_bytes().expect("proof").len()
    );
}
