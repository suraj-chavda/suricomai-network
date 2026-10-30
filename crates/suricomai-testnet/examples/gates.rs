// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Run the settlement simulator gates and print the simulated ledger.
//!
//! Checks the fee, slash, and replay rules in process. Nothing here is live SUR.

use suricomai_testnet::run_gates;

fn main() {
    let prompt = b"CANARY-SECRET-suricomai-9f3a wire-canary";
    let report = run_gates(prompt).expect("gates");
    assert!(!report.relay_saw_prompt);
    assert!(!report.log_saw_prompt);
    assert!(!report.hardware_p2_claimed);
    assert!(report.consumer_rejected_for_p2);
    assert!(report.direct_job_survived_relay_failure);
    assert!(report.relay_path_failed);
    assert_eq!(report.balances.impostor, 0);
    println!("executors={:?}", report.balances.executors);
    println!("consumer={}", report.balances.consumer);
    println!("validators={:?}", report.balances.validators);
    println!("relays={:?}", report.balances.relays);
    println!("burn={}", report.balances.burn);
    println!("refunded={}", report.balances.refunded);
    println!("impostor={}", report.balances.impostor);
    println!("private_label={:?}", report.private_label);
    println!("transit_label={:?}", report.transit_label);
    println!("prompt_on_relay=false");
    println!("hardware_p2=false");
}
