// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Development node process.
//!
//! Serves sealed jobs over an authenticated Noise channel. It prints two lines on
//! standard output: the ticket a development client needs, then `listening <addr>`.
//! The quote is a lab quote, so answers are
//! `lab-untrusted` and not private.
//!
//!   suricomai-node [--listen ADDR] [--key-file PATH] [--announce DIRECTORY/KEY [--advertise ADDR]]
//!                [--models DIR --trust FILE [--allow-single-approver]] [--reload-secs N]
//!                [--max-connections N] [--max-per-peer N]
//!
//! With `--models` the node also hosts every approved model in that pack directory (see
//! the protocol specification, Model pack), as non-private jobs. `--trust` names the policy file that says which
//! approvers to believe. The pack is read again every `--reload-secs` seconds (default 30), so
//! new approvals and revocations take effect without a restart. A pack that fails its checks at
//! start stops the node from starting, and one that fails on reload stops model hosting until
//! it loads again.
//!
//! With `--announce` the node asks a directory to list it, and again before each listing
//! expires. The directory probes the node itself. `--advertise` is the address the
//! directory should probe, for a node whose public address differs from `--listen`.
//!
//! With `--key-file` the node keeps its transport key and lab root in that file, so a
//! restart prints the same ticket. The file is created with mode 0600 when it does not
//! exist, and a file that is not exactly the safe form is refused and left alone. Without
//! it, identity is fresh on every start. HPKE and receipt keys are always fresh.

use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use suricomai_envelope::LabAttester;
use suricomai_runtime::{
    key_from_hex, load_catalog, load_hosted, publish_to_directory, serve_secure, Executor,
    HostLimits, HostedSet, NodeTicket, ServerLimits, TransportKey, TrustPolicy,
};

const USAGE: &str =
    "usage: suricomai-node [--listen ADDR] [--key-file PATH] [--announce DIRECTORY/KEY [--advertise ADDR]] [--models DIR --trust FILE [--allow-single-approver]] [--reload-secs N] [--max-connections N] [--max-per-peer N]";

/// A clock that reads before 1970 makes every job and card look expired, so the node
/// refuses work instead of serving on a wrong time.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

struct Options {
    listen: String,
    limits: ServerLimits,
    key_file: Option<PathBuf>,
    announce: Option<(SocketAddr, [u8; 32])>,
    advertise: Option<SocketAddr>,
    models: Option<PathBuf>,
    trust: Option<PathBuf>,
    allow_single: bool,
    reload_secs: u64,
}

fn parse_args() -> Result<Options, String> {
    let mut listen = String::from("127.0.0.1:7700");
    let mut limits = ServerLimits::default();
    let mut key_file = None;
    let mut announce = None;
    let mut advertise = None;
    let mut models = None;
    let mut trust = None;
    let mut allow_single = false;
    let mut reload_secs = 30u64;
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
            "--key-file" => key_file = Some(PathBuf::from(value)),
            "--models" => models = Some(PathBuf::from(value)),
            "--trust" => trust = Some(PathBuf::from(value)),
            "--reload-secs" => reload_secs = number(&value)? as u64,
            "--announce" => {
                let (addr, key) = value
                    .rsplit_once('/')
                    .ok_or("--announce needs DIRECTORY/KEY")?;
                announce = Some((
                    addr.parse::<SocketAddr>()
                        .map_err(|_| "--announce: bad directory address".to_string())?,
                    key_from_hex(key).map_err(|_| "--announce: bad directory key".to_string())?,
                ));
            }
            "--advertise" => {
                advertise = Some(
                    value
                        .parse::<SocketAddr>()
                        .map_err(|_| "--advertise: bad address".to_string())?,
                );
            }
            "--max-connections" => limits.max_connections = number(&value)?,
            "--max-per-peer" => limits.max_per_peer = number(&value)?,
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    Ok(Options {
        listen,
        limits,
        key_file,
        announce,
        advertise,
        models,
        trust,
        allow_single,
        reload_secs,
    })
}

/// Read the pack once. Returns the catalog, the models that verified, and what was left out.
fn read_pack(
    dir: &Path,
    policy: &TrustPolicy,
    previous: &HostedSet,
) -> Result<(suricomai_envelope::ModelCatalog, HostedSet, Vec<String>), String> {
    let (catalog, mut notes) = load_catalog(dir, policy)
        .map_err(|_| format!("{}: the model pack failed its checks", dir.display()))?;
    let (hosted, more) = load_hosted(
        dir,
        &catalog,
        unix_now(),
        HostLimits::default(),
        policy.denied(),
        previous,
    );
    notes.extend(more);
    Ok((catalog, hosted, notes))
}

fn describe(hosted: &HostedSet) -> String {
    let mut ids: Vec<&str> = hosted.values().map(|m| m.id.as_str()).collect();
    ids.sort_unstable();
    if ids.is_empty() {
        "no models".to_string()
    } else {
        ids.join(", ")
    }
}

/// Re-read the pack on an interval. A pack that fails its checks stops model hosting until it
/// loads again, because a revocation could be what the failure hides.
fn reload_forever(executor: Arc<Mutex<Executor>>, dir: PathBuf, policy: TrustPolicy, every: u64) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(every));
        let previous = match executor.lock() {
            Ok(guard) => guard.hosted_snapshot(),
            Err(_) => return,
        };
        let (catalog, hosted) = match read_pack(&dir, &policy, &previous) {
            Ok((catalog, hosted, notes)) => {
                for note in notes {
                    eprintln!("suricomai-node: {note}");
                }
                (catalog, hosted)
            }
            Err(message) => {
                eprintln!("suricomai-node: {message}; hosting no models until it loads again");
                match policy.catalog() {
                    Ok(empty) => (empty, HostedSet::new()),
                    Err(_) => return,
                }
            }
        };
        if let Ok(mut guard) = executor.lock() {
            guard.set_models(catalog, hosted, policy.denied().to_vec());
        }
    });
}

/// Ask the directory to list this node now, and again well before each listing expires.
/// The directory probes the node, so the first attempt can only succeed once the
/// listener is serving and it retries soon after a failure.
fn announce_forever(
    directory: SocketAddr,
    directory_key: [u8; 32],
    node: SocketAddr,
    key: [u8; 32],
) {
    std::thread::spawn(move || loop {
        let wait = match publish_to_directory(directory, &directory_key, node, &key) {
            Ok(_) => 240,
            Err(err) => {
                eprintln!("suricomai-node: directory refused the listing: {err}");
                10
            }
        };
        std::thread::sleep(std::time::Duration::from_secs(wait));
    });
}

/// The keys that outlive a restart: from the key file when one is named, otherwise fresh.
fn identity(key_file: Option<&PathBuf>) -> Result<(TransportKey, LabAttester), String> {
    let Some(path) = key_file else {
        let key = TransportKey::generate().map_err(|e| e.to_string())?;
        return Ok((key, LabAttester::generate()));
    };
    #[cfg(unix)]
    {
        let id = suricomai_runtime::NodeIdentity::load_or_create(path).map_err(|_| {
            format!(
                "{}: not a safe key file (it must be a regular file, mode 0600, made by this tool); it was left unchanged",
                path.display()
            )
        })?;
        Ok((id.transport, id.lab_attester))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err("--key-file needs a Unix system".to_string())
    }
}

fn run() -> Result<(), String> {
    let Options {
        listen,
        limits,
        key_file,
        announce,
        advertise,
        models,
        trust,
        allow_single,
        reload_secs,
    } = parse_args()?;
    let (ticket_key, attester) = identity(key_file.as_ref())?;
    let mut executor = Executor::lab_measured(attester).map_err(|e| e.to_string())?;
    executor.set_transport_public(ticket_key.public());
    let mut reload: Option<(PathBuf, TrustPolicy)> = None;
    if let Some(dir) = models {
        let trust_path = trust.as_ref().ok_or("--models needs --trust")?;
        let policy = TrustPolicy::load(trust_path, allow_single).map_err(|_| {
            format!(
                "{}: not a usable trust policy (see docs/publishing-models.md, step 2)",
                trust_path.display()
            )
        })?;
        let (catalog, hosted, notes) = read_pack(&dir, &policy, &HostedSet::new())?;
        for note in notes {
            eprintln!("suricomai-node: {note}");
        }
        eprintln!("suricomai-node: hosting {}", describe(&hosted));
        executor.set_models(catalog, hosted, policy.denied().to_vec());
        reload = Some((dir, policy));
    } else if trust.is_some() || allow_single {
        return Err("--trust and --allow-single-approver need --models".into());
    }
    let ticket = NodeTicket {
        transport_key: ticket_key.public(),
        lab_root: executor.lab_root(),
    };
    let listener = TcpListener::bind(&listen).map_err(|e| format!("{listen}: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let mut out = std::io::stdout();
    writeln!(out, "{}", ticket.to_line())
        .and_then(|()| writeln!(out, "listening {addr}"))
        .and_then(|()| out.flush())
        .map_err(|e| e.to_string())?;
    eprintln!("suricomai-node: development build, lab-untrusted, not private");
    if let Some((directory, directory_key)) = announce {
        announce_forever(
            directory,
            directory_key,
            advertise.unwrap_or(addr),
            ticket.transport_key,
        );
    }
    let executor = Arc::new(Mutex::new(executor));
    if let Some((dir, policy)) = reload {
        reload_forever(Arc::clone(&executor), dir, policy, reload_secs);
    }
    serve_secure(
        listener,
        Arc::new(ticket_key),
        executor,
        limits,
        Arc::new(unix_now),
        Arc::new(AtomicBool::new(false)),
    )
    .map_err(|e| e.to_string())
}

fn main() {
    if let Err(message) = run() {
        eprintln!("suricomai-node: {message}\n{USAGE}");
        std::process::exit(2);
    }
}
