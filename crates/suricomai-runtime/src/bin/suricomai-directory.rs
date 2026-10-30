// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Development directory process.
//!
//! Lists nodes a client can try. It is an index and a hint: it probes every address
//! that is published to it, stores only what the probe returned, and never sees a job.
//! A client that picks a listed node still checks that node's card itself.
//!
//!   suricomai-directory --accept-lab-root HEX [--accept-lab-root HEX ...] [--listen ADDR]
//!                     [--key-file PATH] [--allow-local] [--max-entries N]
//!                     [--peer DIRECTORY/KEY ...] [--sync-secs N]
//!                     [--max-connections N] [--max-per-peer N]
//!
//! With `--peer` it also learns from other directories: every `--sync-secs` seconds it reads
//! each peer's list and treats every listed address as a claim, admitted only by its own
//! probe. A peer cannot push an entry, and at most 16 claims per peer are probed per round.
//!
//! Prints `directory-key <hex>` and then `listening <addr>` on standard output. Clients
//! pin that key. `--allow-local` lets it probe loopback and private addresses, which a
//! network on one machine needs and a public directory must not allow.

use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use suricomai_envelope::LabVerifier;
use suricomai_runtime::{
    key_from_hex, key_to_hex, serve_secure, Directory, DirectoryConfig, ServerLimits, TransportKey,
};

type Peer = (SocketAddr, [u8; 32]);

const USAGE: &str = "usage: suricomai-directory --accept-lab-root HEX [--accept-lab-root HEX ...] [--listen ADDR] [--key-file PATH] [--allow-local] [--max-entries N] [--peer DIRECTORY/KEY ...] [--sync-secs N] [--max-connections N] [--max-per-peer N]";

/// A clock that reads before 1970 makes every card look stale, so nothing is listed.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

struct Options {
    listen: String,
    roots: Vec<LabVerifier>,
    key_file: Option<PathBuf>,
    allow_local: bool,
    max_entries: Option<usize>,
    peers: Vec<Peer>,
    sync_secs: Option<u64>,
    limits: ServerLimits,
}

fn parse_args() -> Result<Options, String> {
    let mut options = Options {
        listen: String::from("127.0.0.1:7900"),
        roots: Vec::new(),
        key_file: None,
        allow_local: false,
        max_entries: None,
        peers: Vec::new(),
        sync_secs: None,
        limits: ServerLimits::default(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        if flag == "--allow-local" {
            options.allow_local = true;
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
            "--listen" => options.listen = value,
            "--key-file" => options.key_file = Some(PathBuf::from(value)),
            "--accept-lab-root" => {
                let bytes = key_from_hex(&value)
                    .map_err(|_| format!("{flag}: not a 64-character hex key"))?;
                options.roots.push(
                    LabVerifier::from_verifying_bytes(&bytes)
                        .map_err(|_| format!("{flag}: not a valid public key"))?,
                );
            }
            "--max-entries" => options.max_entries = Some(number(&value)?),
            "--sync-secs" => options.sync_secs = Some(number(&value)? as u64),
            "--peer" => {
                let (addr, key) = value.rsplit_once('/').ok_or("--peer needs DIRECTORY/KEY")?;
                options.peers.push((
                    addr.parse::<SocketAddr>()
                        .map_err(|_| "--peer: bad address".to_string())?,
                    key_from_hex(key).map_err(|_| "--peer: bad key".to_string())?,
                ));
            }
            "--max-connections" => options.limits.max_connections = number(&value)?,
            "--max-per-peer" => options.limits.max_per_peer = number(&value)?,
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    if options.roots.is_empty() {
        return Err("at least one --accept-lab-root is required".into());
    }
    Ok(options)
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
                    "{}: not a safe key file (it must be a regular file, mode 0600, made by this tool); it was left unchanged",
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
    let options = parse_args()?;
    let key = transport_key(options.key_file.as_ref())?;
    let mut config = DirectoryConfig::new(options.roots);
    config.allow_local = options.allow_local;
    if let Some(max) = options.max_entries {
        config.max_entries = max;
    }
    if let Some(secs) = options.sync_secs {
        config.sync_secs = secs;
    }
    let sync_secs = config.sync_secs;
    let listener =
        TcpListener::bind(&options.listen).map_err(|e| format!("{}: {e}", options.listen))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let mut out = std::io::stdout();
    writeln!(out, "directory-key {}", key_to_hex(&key.public()))
        .and_then(|()| writeln!(out, "listening {addr}"))
        .and_then(|()| out.flush())
        .map_err(|e| e.to_string())?;
    let directory = Arc::new(Directory::new(config));
    for (peer, peer_key) in options.peers {
        let directory = Arc::clone(&directory);
        std::thread::spawn(move || loop {
            match directory.sync_from(peer, &peer_key, &unix_now) {
                Ok(_) => {}
                Err(err) => eprintln!("suricomai-directory: peer {peer}: {err}"),
            }
            std::thread::sleep(std::time::Duration::from_secs(sync_secs));
        });
    }
    serve_secure(
        listener,
        Arc::new(key),
        directory,
        options.limits,
        Arc::new(unix_now),
        Arc::new(AtomicBool::new(false)),
    )
    .map_err(|e| e.to_string())
}

fn main() {
    if let Err(message) = run() {
        eprintln!("suricomai-directory: {message}\n{USAGE}");
        std::process::exit(2);
    }
}
