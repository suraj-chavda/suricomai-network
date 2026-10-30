// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Create and check model manifests and approvals.
//!
//!   suricomai-models keygen <secret-file>
//!   suricomai-models publish <publisher-secret> <model-id> <model-digest> <tokenizer-digest> \
//!                          <runtime-digest> <params-millions> <license> <out>
//!   suricomai-models approve <approver-secret> <manifest> approved|revoked <valid-from> <valid-until> <out>
//!   suricomai-models verify <manifest> [approval...]
//!
//! Helpers that remove copy and paste mistakes:
//!   suricomai-models digest model|tokenizer <file>
//!   suricomai-models runtime-digest
//!   suricomai-models publish-files <publisher-secret> <model-id> <weights.gguf> <tokenizer.json> \
//!                                <params-millions> <license> <out>
//!   suricomai-models revoke <approver-secret> <manifest> <valid-from> <valid-until> <out>
//!
//! Registry:
//!   suricomai-models push <registry-addr>/<registry-key> <file>...
//!   suricomai-models sync <registry-addr>/<registry-key> <pack-directory>
//!
//! Development fixture (random weights, real file formats):
//!   suricomai-models make-test-model <directory> <model-id> <seed>
//!
//! Digests are 64 hex characters. Times are unix seconds. A secret file holds 64 hex
//! characters and is created readable by its owner only. Keep approver secrets offline.

use std::fs;
use std::io::Write;
use std::process::exit;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use suricomai_envelope::{ApprovalStatus, ModelApproval, ModelManifest};
use suricomai_runtime::{
    key_from_hex, registry_put, runtime_digest, sync_registry, testing, OBJECT_APPROVAL,
    OBJECT_MANIFEST,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    let text = text.trim();
    if text.len() != N * 2 || !text.is_ascii() {
        return Err(format!("expected {} hex characters", N * 2));
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|_| "not hex".to_string())?;
    }
    Ok(out)
}

fn load_key(path: &str) -> Result<SigningKey, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    Ok(SigningKey::from_bytes(&unhex::<32>(&text)?))
}

fn write_secret(path: &str, secret: &[u8; 32]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).map_err(|e| format!("{path}: {e}"))?;
    file.write_all(hex(secret).as_bytes())
        .map_err(|e| e.to_string())
}

fn num(text: &str) -> Result<u64, String> {
    text.parse().map_err(|_| format!("{text} is not a number"))
}

/// Hash a file in chunks under a domain, so a multi-gigabyte weights file is never held in memory.
fn stream_digest(domain: &str, path: &str) -> Result<[u8; 32], String> {
    use std::io::Read;
    let mut file = fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err(format!("{path}: not a regular file"));
    }
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf).map_err(|e| format!("{path}: {e}"))?;
        if n == 0 {
            return Ok(*hasher.finalize().as_bytes());
        }
        hasher.update(&buf[..n]);
    }
}

fn registry_target(text: &str) -> Result<(std::net::SocketAddr, [u8; 32]), String> {
    let (addr, key) = text.rsplit_once('/').ok_or("the registry is ADDRESS/KEY")?;
    Ok((
        addr.parse()
            .map_err(|_| "bad registry address".to_string())?,
        key_from_hex(key).map_err(|_| "bad registry key".to_string())?,
    ))
}

fn run(args: &[String]) -> Result<(), String> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["keygen", path] => {
            let mut secret = [0u8; 32];
            OsRng.fill_bytes(&mut secret);
            write_secret(path, &secret)?;
            println!(
                "public {}",
                hex(&SigningKey::from_bytes(&secret).verifying_key().to_bytes())
            );
        }
        ["publish", key, id, model, tokenizer, runtime, params, license, out] => {
            let manifest = ModelManifest::publish(
                id,
                unhex(model)?,
                unhex(tokenizer)?,
                unhex(runtime)?,
                num(params)?,
                license,
                &load_key(key)?,
            )
            .map_err(|e| e.code().to_string())?;
            fs::write(out, manifest.to_bytes().map_err(|e| e.code().to_string())?)
                .map_err(|e| e.to_string())?;
            println!(
                "manifest_id {}",
                hex(&manifest.id().map_err(|e| e.code().to_string())?)
            );
        }
        ["approve", key, manifest, status, from, until, out] => {
            let bytes = fs::read(manifest).map_err(|e| format!("{manifest}: {e}"))?;
            let manifest = ModelManifest::from_bytes(&bytes).map_err(|e| e.code().to_string())?;
            manifest
                .verify_signature()
                .map_err(|e| e.code().to_string())?;
            let status = match *status {
                "approved" => ApprovalStatus::Approved,
                "revoked" => ApprovalStatus::Revoked,
                _ => return Err("status must be approved or revoked".to_string()),
            };
            let approval =
                ModelApproval::issue(&manifest, status, num(from)?, num(until)?, &load_key(key)?)
                    .map_err(|e| e.code().to_string())?;
            fs::write(out, approval.to_bytes()).map_err(|e| e.to_string())?;
            println!("approver {}", hex(&approval.approver_public));
        }
        ["verify", manifest, approvals @ ..] => {
            let bytes = fs::read(manifest).map_err(|e| format!("{manifest}: {e}"))?;
            let m = ModelManifest::from_bytes(&bytes).map_err(|e| e.code().to_string())?;
            m.verify_signature().map_err(|e| e.code().to_string())?;
            let id = m.id().map_err(|e| e.code().to_string())?;
            println!(
                "manifest ok: {} {} publisher {}",
                m.model_id,
                m.license,
                hex(&m.publisher_public)
            );
            for path in approvals {
                let bytes = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
                let ap = ModelApproval::from_bytes(&bytes).map_err(|e| e.code().to_string())?;
                ap.verify_signature().map_err(|e| e.code().to_string())?;
                if ap.manifest_id != id {
                    return Err(format!("{path} is about a different manifest"));
                }
                println!(
                    "approval ok: {:?} {}..{} by {}",
                    ap.status,
                    ap.valid_from,
                    ap.valid_until,
                    hex(&ap.approver_public)
                );
            }
        }
        ["digest", kind, file] => {
            let domain = match *kind {
                "model" => "suricomai.model.v1",
                "tokenizer" => "suricomai.tokenizer.v1",
                _ => return Err("digest takes model or tokenizer".to_string()),
            };
            println!("{}", hex(&stream_digest(domain, file)?));
        }
        ["runtime-digest"] => println!("{}", hex(&runtime_digest())),
        ["publish-files", key, id, weights, tokenizer, params, license, out] => {
            let manifest = ModelManifest::publish(
                id,
                stream_digest("suricomai.model.v1", weights)?,
                stream_digest("suricomai.tokenizer.v1", tokenizer)?,
                runtime_digest(),
                num(params)?,
                license,
                &load_key(key)?,
            )
            .map_err(|e| e.code().to_string())?;
            fs::write(out, manifest.to_bytes().map_err(|e| e.code().to_string())?)
                .map_err(|e| e.to_string())?;
            println!(
                "manifest_id {}",
                hex(&manifest.id().map_err(|e| e.code().to_string())?)
            );
        }
        ["revoke", key, manifest, from, until, out] => {
            let bytes = fs::read(manifest).map_err(|e| format!("{manifest}: {e}"))?;
            let manifest = ModelManifest::from_bytes(&bytes).map_err(|e| e.code().to_string())?;
            manifest
                .verify_signature()
                .map_err(|e| e.code().to_string())?;
            let approval = ModelApproval::issue(
                &manifest,
                ApprovalStatus::Revoked,
                num(from)?,
                num(until)?,
                &load_key(key)?,
            )
            .map_err(|e| e.code().to_string())?;
            fs::write(out, approval.to_bytes()).map_err(|e| e.to_string())?;
            println!("revoked by {}", hex(&approval.approver_public));
        }
        ["push", registry, files @ ..] if !files.is_empty() => {
            let (addr, key) = registry_target(registry)?;
            for path in files {
                let bytes = fs::read(path).map_err(|e| format!("{path}: {e}"))?;
                let kind = if ModelManifest::from_bytes(&bytes).is_ok() {
                    OBJECT_MANIFEST
                } else if ModelApproval::from_bytes(&bytes).is_ok() {
                    OBJECT_APPROVAL
                } else {
                    return Err(format!("{path}: not a manifest or an approval"));
                };
                let id = registry_put(addr, &key, kind, &bytes)
                    .map_err(|e| format!("{path}: the registry refused it ({e})"))?;
                println!("pushed {path} {}", hex(&id));
            }
        }
        ["sync", registry, dir] => {
            let (addr, key) = registry_target(registry)?;
            let out = sync_registry(addr, &key, std::path::Path::new(dir))
                .map_err(|e| format!("sync failed ({e})"))?;
            println!(
                "fetched {} already_there {} rejected {}",
                out.fetched, out.present, out.rejected
            );
        }
        ["make-test-model", dir, id, seed] => {
            let seed = u8::try_from(num(seed)?).map_err(|_| "seed is 0 to 255".to_string())?;
            if !std::path::Path::new(dir).is_dir() {
                return Err(format!("{dir}: not a directory"));
            }
            let model = testing::fixture_model(seed);
            testing::write_model_files(std::path::Path::new(dir), id, &model);
            println!("wrote {dir}/{id}.gguf and {dir}/{id}.tokenizer.json (random weights)");
        }
        _ => return Err("usage: see the header of this file".to_string()),
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(why) = run(&args) {
        eprintln!("suricomai-models: {why}");
        exit(1);
    }
}
