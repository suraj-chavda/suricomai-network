// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Send one prompt to a development node and print the answer.
//!
//!   suricomai-ask [--via RELAY/INDEX]... [--no-direct] <addr> <ticket> <prompt...>
//!   suricomai-ask --directory DIRECTORY/KEY --lab-root HEX [--allow-local] <prompt...>
//!   ... --model ID --models PACK_DIR --trust FILE [--allow-single-approver]
//!
//! `--model` asks a hosted model by its name in the pack, instead of the built-in test model.
//! The client reads the manifests and approvals in `--models`, applies the trust policy in
//! `--trust`, and refuses to seal to a model that policy does not approve right now or denies.
//! The job is non-private: the node that hosts the model can read the prompt.
//!
//! With a ticket, the node is the one the ticket names. Each `--via` names a relay and the
//! index of the node in that relay's upstream list. Routes are tried in the order given,
//! then the direct route unless `--no-direct`. A route that fails before the request is
//! written moves on to the next one.
//!
//! With `--directory`, the client lists the directory, then chooses among the listed nodes:
//! it fetches a card from up to 8 of them in parallel, keeps those that pass the client's own
//! checks, and picks one at random from the ones near the fastest it measured. If the pick
//! cannot be reached it tries the next, and a failure after a request was written is final.
//! The listing is only a hint.
//! `--lab-root` is the quote root the client trusts. Listed addresses in private or loopback
//! ranges are skipped unless `--allow-local`.
//!
//! The answer is `lab-untrusted` and not private.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use rand::RngCore;
use suricomai_envelope::{InferenceParams, LabVerifier};
use suricomai_runtime::{
    address_allowed, complete_on_first_reachable, fetch_card_via, fetch_model_card_via,
    key_from_hex, list_directory, load_catalog, model_digest, pack_user_prompt, pinned_weights,
    runtime_measurement, select, Attempt, Candidate, Client, JobRequest, NodeTicket, Route,
    TrustPolicy, Wanted,
};

const USAGE: &str = "usage: suricomai-ask [--via RELAY/INDEX]... [--no-direct] <addr> <ticket> <prompt...>\n       suricomai-ask --directory DIRECTORY/KEY --lab-root HEX [--allow-local] <prompt...>";

/// Most directory pages read in one run, so a directory cannot keep a client listing forever.
const MAX_PAGES: usize = 4;

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "the system clock is before 1970".to_string())
}

/// A node the client may talk to: its pinned key, and the routes to reach it.
struct Target {
    key: [u8; 32],
    routes: Vec<Route>,
}

struct Plan {
    /// A hosted model to ask for: its name, the pack, the trust policy, and the single-approver flag.
    hosted: Option<(String, PathBuf, PathBuf, bool)>,
    /// True when the user did not pin a node and the client should choose among the targets.
    choose: bool,
    lab_root: [u8; 32],
    targets: Vec<Target>,
    prompt: String,
}

fn split_pair(value: &str, what: &str) -> Result<(SocketAddr, String), String> {
    let (addr, rest) = value
        .rsplit_once('/')
        .ok_or_else(|| format!("{what} needs ADDRESS/VALUE"))?;
    let addr = addr
        .parse::<SocketAddr>()
        .map_err(|_| format!("{what}: bad address"))?;
    Ok((addr, rest.to_string()))
}

fn plan() -> Result<Plan, String> {
    let mut args = std::env::args().skip(1).peekable();
    let mut relays = Vec::new();
    let mut direct = true;
    let mut directory = None;
    let mut lab_root = None;
    let mut allow_local = false;
    let mut model_id: Option<String> = None;
    let mut pack: Option<PathBuf> = None;
    let mut trust: Option<PathBuf> = None;
    let mut allow_single = false;
    while let Some(flag) = args.next_if(|a| a.starts_with("--")) {
        match flag.as_str() {
            "--no-direct" => direct = false,
            "--allow-local" => allow_local = true,
            "--allow-single-approver" => allow_single = true,
            "--model" => model_id = Some(args.next().ok_or(USAGE)?),
            "--models" => pack = Some(PathBuf::from(args.next().ok_or(USAGE)?)),
            "--trust" => trust = Some(PathBuf::from(args.next().ok_or(USAGE)?)),
            "--via" => {
                let value = args.next().ok_or(USAGE)?;
                let (relay, index) = split_pair(&value, "--via")?;
                relays.push((
                    relay,
                    index
                        .parse::<u8>()
                        .map_err(|_| "bad relay index".to_string())?,
                ));
            }
            "--directory" => {
                let value = args.next().ok_or(USAGE)?;
                let (addr, key) = split_pair(&value, "--directory")?;
                let key = key_from_hex(&key).map_err(|_| "--directory: bad key".to_string())?;
                directory = Some((addr, key));
            }
            "--lab-root" => {
                let value = args.next().ok_or(USAGE)?;
                lab_root = Some(key_from_hex(&value).map_err(|_| "bad lab root".to_string())?);
            }
            _ => return Err(format!("unknown option {flag}\n{USAGE}")),
        }
    }

    let hosted = match (model_id, pack, trust) {
        (Some(id), Some(pack), Some(trust)) => Some((id, pack, trust, allow_single)),
        (None, None, None) if !allow_single => None,
        _ => return Err("--model, --models and --trust go together".into()),
    };
    if let Some((directory_addr, directory_key)) = directory {
        let lab_root = lab_root.ok_or("--directory needs --lab-root")?;
        if !relays.is_empty() || !direct {
            return Err("--via and --no-direct apply to a ticket, not a directory".into());
        }
        let prompt = args.collect::<Vec<_>>().join(" ");
        let mut targets = Vec::new();
        let mut cursor = 0;
        for _ in 0..MAX_PAGES {
            let (entries, next) = list_directory(directory_addr, &directory_key, cursor)
                .map_err(|e| format!("directory: {e}"))?;
            targets.extend(
                entries
                    .into_iter()
                    .filter(|e| address_allowed(&e.addr, allow_local))
                    .map(|e| Target {
                        key: e.transport_key,
                        routes: vec![Route::Direct(e.addr)],
                    }),
            );
            if next == 0 {
                break;
            }
            cursor = next;
        }
        if targets.is_empty() {
            return Err("the directory lists no usable node".into());
        }
        return Ok(Plan {
            hosted,
            choose: true,
            lab_root,
            targets,
            prompt,
        });
    }

    if lab_root.is_some() || allow_local {
        return Err("--lab-root and --allow-local apply to --directory".into());
    }
    let (Some(addr), Some(ticket)) = (args.next(), args.next()) else {
        return Err(USAGE.into());
    };
    let addr: SocketAddr = addr.parse().map_err(|_| "bad address".to_string())?;
    let ticket = NodeTicket::parse(&ticket).map_err(|_| "bad ticket".to_string())?;
    let mut routes: Vec<Route> = relays
        .into_iter()
        .map(|(relay, upstream)| Route::Relay { relay, upstream })
        .collect();
    if direct {
        routes.push(Route::Direct(addr));
    }
    if routes.is_empty() {
        return Err("no route: --no-direct needs at least one --via".into());
    }
    Ok(Plan {
        hosted,
        choose: false,
        lab_root: ticket.lab_root,
        targets: vec![Target {
            key: ticket.transport_key,
            routes,
        }],
        prompt: args.collect::<Vec<_>>().join(" "),
    })
}

fn run() -> Result<(), String> {
    let plan = plan()?;
    if plan.prompt.is_empty() {
        return Err("the prompt is empty".into());
    }
    let verifier = LabVerifier::from_verifying_bytes(&plan.lab_root)
        .map_err(|_| "bad lab root".to_string())?;
    let measurement = runtime_measurement(&model_digest(&pinned_weights()));
    let mut client = Client::new(verifier, measurement).map_err(|e| e.to_string())?;
    let now = unix_now()?;
    let wanted = match &plan.hosted {
        None => Wanted::Builtin,
        Some((id, pack, trust, allow_single)) => {
            let policy = TrustPolicy::load(trust, *allow_single)
                .map_err(|_| format!("{}: not a usable trust policy", trust.display()))?;
            let (catalog, notes) = load_catalog(pack, &policy)
                .map_err(|_| format!("{}: the model pack failed its checks", pack.display()))?;
            for note in notes {
                eprintln!("suricomai-ask: {note}");
            }
            let entry = catalog
                .by_id(id)
                .ok_or_else(|| format!("{id}: not in the model pack"))?;
            let digest = entry.manifest.model_digest;
            if policy.denies(&digest) {
                return Err(format!("{id}: denied by your trust policy"));
            }
            catalog
                .require_approved(&digest, now)
                .map_err(|e| format!("{id}: not approved right now ({})", e.code()))?;
            client = client
                .with_catalog(catalog.clone())
                .with_denied(policy.denied().to_vec());
            Wanted::Hosted {
                digest,
                name: id.clone(),
            }
        }
    };
    // Each attempt is a node, the routes to it, and a card that already passed this
    // client's checks.
    let mut attempts: Vec<Attempt> = Vec::new();
    if plan.choose {
        let candidates = plan
            .targets
            .iter()
            .filter_map(|t| match t.routes.first() {
                Some(Route::Direct(addr)) => Some(Candidate {
                    addr: *addr,
                    key: t.key,
                }),
                _ => None,
            })
            .collect();
        attempts.extend(
            select(&client, candidates, &wanted, now)
                .into_iter()
                .map(Attempt::from),
        );
        if attempts.is_empty() {
            return Err("no listed node returned a card that passed the checks".into());
        }
    } else {
        let mut last = String::from("no node answered");
        for target in &plan.targets {
            let mut nonce = [0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            let fetched = match &wanted {
                Wanted::Builtin => fetch_card_via(&target.routes, &target.key, nonce),
                Wanted::Hosted { digest, name } => {
                    fetch_model_card_via(&target.routes, &target.key, nonce, digest, name)
                }
            };
            match fetched {
                Ok(card) => {
                    attempts.push(Attempt {
                        routes: target.routes.clone(),
                        key: target.key,
                        card,
                    });
                    break;
                }
                Err(err) => last = err.to_string(),
            }
        }
        if attempts.is_empty() {
            return Err(last);
        }
    }

    let hosted_job = matches!(wanted, Wanted::Hosted { .. });
    let prompt = if hosted_job {
        pack_user_prompt(&plan.prompt).map_err(|e| e.to_string())?
    } else {
        plan.prompt.into_bytes()
    };
    let params = InferenceParams::new([3u8; 32], 0, if hosted_job { 64 } else { 24 })
        .map_err(|e| e.to_string())?;
    let make_request = || {
        let mut job_id = [0u8; 32];
        OsRng.fill_bytes(&mut job_id);
        JobRequest {
            job_id,
            chain_id: 7,
            prompt: prompt.clone(),
            params: params.clone(),
            now,
            expiry: now + 600,
            fee: 1,
            bond_required: 1,
            max_output_bytes: if hosted_job { 512 } else { 64 },
            size_class: 4_096,
            max_latency_ms: 150,
            user_pay_key: [5u8; 32],
        }
    };
    let completion = complete_on_first_reachable(&client, &attempts, &wanted, &make_request)
        .map_err(|e| e.to_string())?;
    if hosted_job {
        println!("privacy=not-private (the node that hosts this model can read the prompt)");
    } else {
        println!("privacy=lab-untrusted (not private)");
    }
    println!("hardware_p2=false");
    println!("answer={}", String::from_utf8_lossy(&completion.answer));
    Ok(())
}

fn main() {
    if let Err(message) = run() {
        eprintln!("suricomai-ask: {message}");
        std::process::exit(1);
    }
}
