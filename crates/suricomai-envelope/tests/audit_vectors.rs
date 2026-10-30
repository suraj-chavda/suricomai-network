// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Rust and Python must agree on the committed audit vectors.

use std::path::PathBuf;
use std::process::Command;

use suricomai_envelope::{
    audit_proof, AuditTarget, JobVerification, LabVerifier, MeasurementAllowlist, PromptContract,
    SealedResult,
};

#[test]
fn rust_and_python_agree_on_audit_vectors() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../");
    let vectors = root.join("vectors/audit-v1.json");
    let script = root.join("verifiers/python/audit_proof.py");
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vectors).expect("vectors/audit-v1.json"))
            .expect("vector json");
    let lab = decode32(document["lab_public"].as_str().unwrap());
    let verifier = LabVerifier::from_verifying_bytes(&lab).unwrap();

    for case in document["cases"].as_array().unwrap() {
        let contract =
            PromptContract::from_bytes(&decode_hex(case["contract"].as_str().unwrap())).unwrap();
        let result =
            SealedResult::from_bytes(&decode_hex(case["result"].as_str().unwrap())).unwrap();
        let mut allow = MeasurementAllowlist::new();
        for id in case["allow"].as_array().unwrap() {
            allow.insert(decode32(id.as_str().unwrap()));
        }
        let target = AuditTarget::new(
            decode32(case["target_executor_id"].as_str().unwrap()),
            decode32(case["target_receipt_public"].as_str().unwrap()),
        );
        let audit_now = case["audit_now"].as_u64().unwrap_or(999);
        let outcome = match case["mode"].as_str().unwrap() {
            "quote" => audit_proof(
                &contract,
                &result,
                &target,
                &allow,
                JobVerification::Quote(&verifier),
                audit_now,
            ),
            "signature" => audit_proof(
                &contract,
                &result,
                &target,
                &allow,
                JobVerification::SignatureOnly,
                audit_now,
            ),
            other => panic!("unknown mode {other}"),
        };
        let got = match outcome {
            Ok(()) => "ok".to_string(),
            Err(err) => err.code().to_string(),
        };
        assert_eq!(got, case["expect"].as_str().unwrap(), "{}", case["name"]);
    }

    let python = root.join("verifiers/python/.venv/bin/python");
    let python = if python.exists() {
        python
    } else {
        PathBuf::from("python3")
    };
    let ran = Command::new(python)
        .arg(&script)
        .arg(&vectors)
        .status()
        .expect("python3");
    assert!(ran.success(), "python verifier disagreed");
}

fn decode32(hex: &str) -> [u8; 32] {
    let bytes = decode_hex(hex);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}
