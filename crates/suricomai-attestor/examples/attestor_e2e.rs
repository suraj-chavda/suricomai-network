// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Drives the end-to-end check in `contracts/e2e.sh`.
//!
//! `prepare` builds a real sealed job and a real worker result, and prints the values the
//! chain needs (job id, contract hash, receipt key, committee addresses). `sign` reloads that
//! evidence, runs both verifiers, and prints the committee signatures for a settlement. The
//! script moves the money on a local EVM chain in between.
//!
//! Usage:
//!   attestor_e2e prepare <dir> <user 0x..> <salt 0x..> <now> <cap>
//!   attestor_e2e sign <dir> <chain id> <escrow 0x..> <worker 0x..> <amount> <relay 0x..> <audit_now>

use std::fs;
use std::path::{Path, PathBuf};

use suricomai_attestor::{
    assemble, job_id_for, Address, Assignment, Attestor, CommitteeSigner, Domain, Evidence,
    JobOnChain, PythonVerifier,
};
use suricomai_envelope::{
    finish_job, open_job, seal_job, EnclaveKeys, HostLog, InferenceParams, JobAttestation,
    JobVerification, MeasurementAllowlist, PromptContract, ReplayCache, SealTarget, SealedResult,
    Tier, TransitTarget, UserKeys,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    let text = text.trim().trim_start_matches("0x");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn array<const N: usize>(text: &str) -> [u8; N] {
    unhex(text).try_into().expect("length")
}

fn secret(n: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = n;
    s
}

fn committee() -> Vec<CommitteeSigner> {
    let mut members: Vec<CommitteeSigner> = (1..=5u8)
        .map(|n| CommitteeSigner::from_secret(&secret(n)).expect("key"))
        .collect();
    members.sort_by_key(|member| member.address());
    members
}

fn write(dir: &Path, name: &str, data: impl AsRef<[u8]>) {
    fs::write(dir.join(name), data).expect("write");
}

fn read(dir: &Path, name: &str) -> Vec<u8> {
    fs::read(dir.join(name)).expect("read")
}

fn prepare(args: &[String]) {
    let dir = PathBuf::from(&args[0]);
    fs::create_dir_all(&dir).expect("dir");
    let user: Address = array(&args[1]);
    let salt: [u8; 32] = array(&args[2]);
    let now: u64 = args[3].parse().expect("now");
    let cap: u64 = args[4].parse().expect("cap");

    let measurement = [7u8; 32];
    let executor = EnclaveKeys::generate(measurement).expect("executor");
    let user_keys = UserKeys::generate().expect("user keys");
    let mut contract = PromptContract {
        job_id: job_id_for(&user, &salt),
        chain_id: 31337,
        tier: Tier::P1,
        model_digest: [2u8; 32],
        prompt_commitment: [0u8; 32],
        max_output_bytes: 64,
        size_class: 4096,
        fee: cap,
        bond_required: 100,
        expiry: now + 3_600,
        privacy_policy_id: [4u8; 32],
        user_pay_key: [5u8; 32],
        user_hpke_public: user_keys.hpke_public().to_vec(),
        min_stake: 0,
        min_canary_ppt: 0,
        max_latency_ms: 150,
        needs_gpu: false,
        region: b"e2e".to_vec(),
    };
    contract.bind_prompt(b"ping");
    let target = SealTarget::Transit(
        TransitTarget::new(
            measurement,
            executor.hpke_public().to_vec(),
            executor.receipt_public(),
        )
        .expect("target"),
    );
    let params = InferenceParams::new([3u8; 32], 0, 16).expect("params");
    let sealed = seal_job(&contract, b"ping", &params, &target).expect("seal");
    let opened = open_job(
        &sealed.to_bytes(),
        &executor,
        &MeasurementAllowlist::new(),
        now,
        &mut ReplayCache::default(),
        &mut HostLog::default(),
    )
    .expect("open");
    let result = finish_job(
        &opened,
        b"pong",
        16,
        [8u8; 32],
        [0u8; 32],
        [6u8; 32],
        now + 1,
        now + 2,
        None,
        &executor,
        JobAttestation::NotRequired,
    )
    .expect("finish");

    write(&dir, "contract.bin", contract.to_bytes().expect("contract"));
    write(&dir, "result.bin", result.to_bytes().expect("result"));
    write(&dir, "executor_id.hex", hex(&executor.executor_id()));
    write(&dir, "receipt_key.hex", hex(&executor.receipt_public()));
    write(
        &dir,
        "contract_hash.hex",
        hex(&result.proof().contract_hash),
    );
    write(&dir, "job_id.hex", hex(&contract.job_id));
    println!("job_id=0x{}", hex(&contract.job_id));
    println!("contract_hash=0x{}", hex(&result.proof().contract_hash));
    println!("receipt_key=0x{}", hex(&executor.receipt_public()));
    let addresses: Vec<String> = committee()
        .iter()
        .map(|member| format!("0x{}", hex(&member.address())))
        .collect();
    println!("committee=[{}]", addresses.join(","));
}

fn sign(args: &[String]) {
    let dir = PathBuf::from(&args[0]);
    let chain_id: u64 = args[1].parse().expect("chain id");
    let escrow: Address = array(&args[2]);
    let worker: Address = array(&args[3]);
    let amount: u128 = args[4].parse().expect("amount");
    let relay: Address = array(&args[5]);
    let audit_now: u64 = args[6].parse().expect("audit now");

    let contract = PromptContract::from_bytes(&read(&dir, "contract.bin")).expect("contract");
    let result = SealedResult::from_bytes(&read(&dir, "result.bin")).expect("result");
    let job = JobOnChain {
        job_id: array(&String::from_utf8(read(&dir, "job_id.hex")).expect("utf8")),
        contract_hash: array(&String::from_utf8(read(&dir, "contract_hash.hex")).expect("utf8")),
        worker,
        receipt_key: array(&String::from_utf8(read(&dir, "receipt_key.hex")).expect("utf8")),
        cap: u128::from(contract.fee),
    };
    let assigned = Assignment {
        executor_id: array(&String::from_utf8(read(&dir, "executor_id.hex")).expect("utf8")),
        receipt_public: job.receipt_key,
    };
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../");
    let venv = root.join("verifiers/python/.venv/bin/python");
    let second = PythonVerifier {
        python: if venv.exists() {
            venv
        } else {
            PathBuf::from("python3")
        },
        script: root.join("verifiers/python/audit_proof.py"),
        lab_public: None,
    };
    let allowlist = MeasurementAllowlist::new();
    let domain = Domain {
        chain_id,
        verifying_contract: escrow,
    };
    let evidence = Evidence {
        contract: &contract,
        result: &result,
        assigned,
        allowlist: &allowlist,
        audit_now,
    };
    // Three of the five members sign, which is the contract's threshold.
    let mut signatures = Vec::new();
    for member in committee().into_iter().take(3) {
        let key = member.address();
        let attestor = Attestor::new(member, domain, &second);
        let signature = attestor
            .attest_settlement(
                &job,
                &evidence,
                JobVerification::SignatureOnly,
                amount,
                relay,
            )
            .unwrap_or_else(|err| panic!("attestor 0x{} refused: {err}", hex(&key)));
        signatures.push(signature);
    }
    println!("0x{}", hex(&assemble(signatures).expect("assemble")));
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("prepare") if args.len() == 6 => prepare(&args[1..]),
        Some("sign") if args.len() == 8 => sign(&args[1..]),
        _ => {
            eprintln!("usage: attestor_e2e prepare|sign (see the file header)");
            std::process::exit(2);
        }
    }
}
