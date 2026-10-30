// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Development registry process.
//!
//! Stores signed model manifests and approvals so approvals and revocations can reach nodes
//! and clients. It is not trusted for anything: everything it serves is checked again by whoever
//! loads it, under their own trust policy. It can withhold or delay an object. It cannot make
//! a client use a model that client's trust policy does not approve.
//!
//!   suricomai-registry [--listen ADDR] [--store DIR] [--trust FILE [--allow-single-approver]]
//!                    [--key-file PATH] [--max-objects N] [--max-connections N] [--max-per-peer N]
//!
//! With `--store` the objects are kept in that directory and checked again at start. With
//! `--trust` the registry refuses approvals from approvers outside the policy. Prints
//! `registry-key <hex>` and then `listening <addr>` on standard output. Clients pin that key.

use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use suricomai_runtime::{
    key_to_hex, serve_secure, Registry, RegistryConfig, ServerLimits, TransportKey, TrustPolicy,
};

const USAGE: &str = "usage: suricomai-registry [--listen ADDR] [--store DIR] [--trust FILE [--allow-single-approver]] [--key-file PATH] [--max-objects N] [--max-connections N] [--max-per-peer N]";

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

fn transport_key(key_file: Option<&PathBuf>) -> Result<TransportKey, String> {
    let Some(path) = key_file else {
        return TransportKey::generate().map_err(|e| e.to_string());
    };
    #[cfg(unix)]
    {
        suricomai_runtime::NodeIdentity::load_or_create(path)
            .map(|id| id.transport)
            .map_err(|_| {
                format!(
                    "{}: not a safe key file (regular file, mode 0600, made by this tool); it was left unchanged",
                    path.display()
                )
            })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err("--key-file needs a Unix system".to_string())
    }
}

fn run() -> Result<(), String> {
    let mut listen = String::from("127.0.0.1:7950");
    let mut config = RegistryConfig::default();
    let mut trust: Option<PathBuf> = None;
    let mut allow_single = false;
    let mut key_file = None;
    let mut limits = ServerLimits::default();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        if flag == "--allow-single-approver" {
            allow_single = true;
            continue;
        }
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let number = |v: &str| {
            v.parse::<usize>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| format!("{flag} needs a positive number"))
        };
        match flag.as_str() {
            "--listen" => listen = value,
            "--store" => config.store = Some(PathBuf::from(value)),
            "--trust" => trust = Some(PathBuf::from(value)),
            "--key-file" => key_file = Some(PathBuf::from(value)),
            "--max-objects" => config.max_objects = number(&value)?,
            "--max-connections" => limits.max_connections = number(&value)?,
            "--max-per-peer" => limits.max_per_peer = number(&value)?,
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    if let Some(path) = trust {
        config.trust = Some(TrustPolicy::load(&path, allow_single).map_err(|_| {
            format!(
                "{}: not a usable trust policy (see docs/publishing-models.md, step 2)",
                path.display()
            )
        })?);
    } else if allow_single {
        return Err("--allow-single-approver needs --trust".into());
    }
    let key = transport_key(key_file.as_ref())?;
    let registry = Arc::new(Registry::open(config).map_err(|_| {
        "the store holds a file that fails its checks; nothing was changed".to_string()
    })?);
    let listener = TcpListener::bind(&listen).map_err(|e| format!("{listen}: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let mut out = std::io::stdout();
    writeln!(out, "registry-key {}", key_to_hex(&key.public()))
        .and_then(|()| writeln!(out, "listening {addr}"))
        .and_then(|()| out.flush())
        .map_err(|e| e.to_string())?;
    serve_secure(
        listener,
        Arc::new(key),
        registry,
        limits,
        Arc::new(unix_now),
        Arc::new(AtomicBool::new(false)),
    )
    .map_err(|e| e.to_string())
}

fn main() {
    if let Err(message) = run() {
        eprintln!("suricomai-registry: {message}\n{USAGE}");
        std::process::exit(2);
    }
}
