// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Print the signatures that `contracts/test/Signatures.t.sol` pins, so a change to the Rust
//! signer shows up as a diff against the contract tests.

use suricomai_attestor::{settle_digest, CommitteeSigner, Domain, SettleFields};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let mut verifying = [0u8; 20];
    verifying[19] = 6;
    let domain = Domain {
        chain_id: 31337,
        verifying_contract: verifying,
    };
    let mut worker = [0u8; 20];
    worker[19] = 3;
    let mut relay = [0u8; 20];
    relay[19] = 5;
    let digest = settle_digest(
        &domain,
        &SettleFields {
            job_id: [0x11; 32],
            contract_hash: [0x22; 32],
            worker,
            receipt_key: [0x44; 32],
            amount_due: 1000,
            relay_payee: relay,
        },
    );
    println!("digest 0x{}", hex(&digest));
    for n in 1..=5u8 {
        let mut secret = [0u8; 32];
        secret[31] = n;
        let signer = CommitteeSigner::from_secret(&secret).expect("key");
        let signature = signer.sign(&digest).expect("sign");
        println!(
            "key{n} address 0x{} sig 0x{}",
            hex(&signer.address()),
            hex(&signature.bytes)
        );
    }
}
