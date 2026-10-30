// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! One local `POST /v1/chat/completions`.
//!
//! The HTTP body stays on this machine. The executor socket receives a sealed job.
//! The response privacy field is lab-untrusted, and hardware P2 is false.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use suricomai_runtime::{serve_chat_once, serve_one, Client, Executor, MODEL_NAME};

fn main() {
    let mut executor = Executor::lab().expect("executor");
    assert!(executor.claim_hardware_p2().is_err());
    let card = executor.card([9u8; 32], 0).expect("card");
    let client = Client::new(executor.verifier(), card.advertisement.executor_id).expect("client");

    let executor_listener = TcpListener::bind("127.0.0.1:0").expect("executor bind");
    let executor_addr = executor_listener.local_addr().expect("executor addr");
    let worker =
        thread::spawn(move || serve_one(executor_listener, &mut executor, 50).expect("serve"));

    let api = TcpListener::bind("127.0.0.1:0").expect("api bind");
    let api_addr = api.local_addr().expect("api addr");
    let api_thread = thread::spawn(move || {
        serve_chat_once(api, &client, &card, executor_addr, 50).expect("chat");
    });

    let prompt = "CANARY-SECRET-suricomai-9f3a";
    let body = format!(
        "{{\"model\":\"{MODEL_NAME}\",\"messages\":[{{\"role\":\"user\",\"content\":\"{prompt}\"}}],\"temperature\":0,\"max_tokens\":16}}"
    );
    let response = post(api_addr, &body);
    api_thread.join().expect("api thread");
    let captured = worker.join().expect("executor thread");
    assert!(!captured
        .windows(prompt.len())
        .any(|window| window == prompt.as_bytes()));
    assert!(response.contains("\"privacy\":\"lab-untrusted\""));
    assert!(response.contains("\"hardware_p2\":false"));
    assert!(!response.contains(prompt));

    println!("privacy=lab-untrusted");
    println!("hardware_p2=false");
    println!("prompt_on_executor_wire=false");
    println!("api=http://{api_addr}/v1/chat/completions");
}

fn post(addr: std::net::SocketAddr, json: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let payload = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
        json.len()
    );
    stream.write_all(payload.as_bytes()).expect("write");
    let mut buf = String::new();
    stream.read_to_string(&mut buf).expect("read");
    buf
}
