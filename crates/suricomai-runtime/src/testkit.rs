// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Shared helpers for tests that need a real node on a real socket.

use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use suricomai_envelope::{InferenceParams, LabAttester, LabVerifier};

use crate::client::{Client, JobRequest};
use crate::error::RuntimeError;
use crate::node::NodeCard;
use crate::transport::{exchange_secure_via, serve_secure, Route, ServerLimits, TransportKey};
use crate::Executor;

pub(crate) const CANARY: &[u8] = b"CANARY-SECRET-suricomai-9f3a testkit";

/// The clock every test node and test directory uses.
pub(crate) const NOW: u64 = 10;

pub(crate) struct Node {
    pub(crate) addr: SocketAddr,
    pub(crate) pinned: [u8; 32],
    pub(crate) card: NodeCard,
    pub(crate) client: Client,
    pub(crate) verifier: LabVerifier,
    pub(crate) stop: Arc<AtomicBool>,
    pub(crate) thread: thread::JoinHandle<Result<(), RuntimeError>>,
}

pub(crate) fn node() -> Node {
    node_with(LabAttester::generate())
}

/// A node whose quote root is `attester`. Several nodes can share one root.
pub(crate) fn node_with(attester: LabAttester) -> Node {
    let mut executor = Executor::lab_measured(attester).unwrap();
    let key = Arc::new(TransportKey::generate().unwrap());
    executor.set_transport_public(key.public());
    let card = executor.card([9u8; 32], 0).unwrap();
    let verifier = executor.verifier();
    let client = Client::new(verifier.clone(), card.advertisement.executor_id).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let pinned = key.public();
    let stop = Arc::new(AtomicBool::new(false));
    let thread = thread::spawn({
        let stop = Arc::clone(&stop);
        move || {
            serve_secure(
                listener,
                key,
                Arc::new(Mutex::new(executor)),
                ServerLimits::default(),
                Arc::new(|| NOW),
                stop,
            )
        }
    });
    Node {
        addr,
        pinned,
        card,
        client,
        verifier,
        stop,
        thread,
    }
}

impl Node {
    pub(crate) fn job(&self, routes: &[Route], id: u8) -> Result<Vec<u8>, RuntimeError> {
        let mut job_id = [4u8; 32];
        job_id[31] = id;
        let request = JobRequest {
            job_id,
            chain_id: 7,
            prompt: CANARY.to_vec(),
            params: InferenceParams::new([3u8; 32], 0, 24).unwrap(),
            now: NOW,
            expiry: 1_000,
            fee: 1,
            bond_required: 1,
            max_output_bytes: 64,
            size_class: 4_096,
            max_latency_ms: 150,
            user_pay_key: [5u8; 32],
        };
        self.client
            .complete(&self.card, &request, |sealed| {
                exchange_secure_via(routes, &self.pinned, sealed)
            })
            .map(|done| done.answer.to_vec())
    }

    pub(crate) fn shut_down(self) {
        self.stop.store(true, Ordering::Release);
        self.thread.join().unwrap().unwrap();
    }
}

// Helpers for tests that build a model pack: keys, a trust policy, files and approvals.

use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use suricomai_envelope::{ApprovalStatus, ModelApproval, ModelManifest};

use crate::model::{runtime_digest, tokenizer_file_digest, weights_file_digest};
use crate::pack::{load_catalog, load_hosted, HostLimits, HostedSet};
use crate::testing::{fixture_model, write_model_files, FixtureModel};
use crate::trust::TrustPolicy;

pub(crate) const HOSTED_NOW: u64 = 1_000;

pub(crate) fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

pub(crate) fn policy() -> TrustPolicy {
    let text = format!(
        "suricomai-trust-v1\nthreshold 2\napprover {}\napprover {}\n",
        hex(&key(1).verifying_key().to_bytes()),
        hex(&key(2).verifying_key().to_bytes())
    );
    TrustPolicy::parse(&text, false).unwrap()
}

pub(crate) fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn dir() -> std::path::PathBuf {
    use rand::RngCore;
    let mut suffix = [0u8; 6];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let path = std::env::temp_dir().join(format!(
        "suricomai-pack-{}",
        suffix
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    fs::create_dir(&path).unwrap();
    path
}

pub(crate) fn manifest_for(id: &str, model: &FixtureModel) -> ModelManifest {
    ModelManifest::publish(
        id,
        weights_file_digest(&model.weights),
        tokenizer_file_digest(&model.tokenizer),
        runtime_digest(),
        1,
        "MIT",
        &key(9),
    )
    .unwrap()
}

pub(crate) fn write_manifest(dir: &Path, manifest: &ModelManifest) {
    let name = format!("{}.manifest", manifest.model_id);
    fs::write(dir.join(name), manifest.to_bytes().unwrap()).unwrap();
}

pub(crate) fn approve(
    dir: &Path,
    manifest: &ModelManifest,
    by: u8,
    status: ApprovalStatus,
    from: u64,
    until: u64,
) {
    let approval = ModelApproval::issue(manifest, status, from, until, &key(by)).unwrap();
    let name = format!("{}.{by}-{from}-{until}.approval", manifest.model_id);
    fs::write(dir.join(name), approval.to_bytes()).unwrap();
}

/// A pack with one model, approved by both approvers for the whole test period.
pub(crate) fn good_pack(id: &str, seed: u8) -> (std::path::PathBuf, FixtureModel, ModelManifest) {
    let dir = dir();
    let model = fixture_model(seed);
    write_model_files(&dir, id, &model);
    let manifest = manifest_for(id, &model);
    write_manifest(&dir, &manifest);
    for by in [1, 2] {
        approve(&dir, &manifest, by, ApprovalStatus::Approved, 0, 10_000);
    }
    (dir, model, manifest)
}

pub(crate) fn host(dir: &Path, now: u64, limits: HostLimits) -> (HostedSet, Vec<String>) {
    let (catalog, _) = load_catalog(dir, &policy()).unwrap();
    load_hosted(dir, &catalog, now, limits, &[], &HostedSet::new())
}

/// A handler served on a real socket, with a clock that tests can move.
pub(crate) struct Served {
    pub(crate) addr: SocketAddr,
    pub(crate) pinned: [u8; 32],
    pub(crate) clock: Arc<std::sync::atomic::AtomicU64>,
    stop: Arc<AtomicBool>,
    thread: thread::JoinHandle<Result<(), RuntimeError>>,
}

impl Served {
    pub(crate) fn set_time(&self, now: u64) {
        self.clock.store(now, Ordering::Release);
    }

    pub(crate) fn shut_down(self) {
        self.stop.store(true, Ordering::Release);
        self.thread.join().unwrap().unwrap();
    }
}

/// Serve `handler` on loopback with wide connection limits.
pub(crate) fn serve_handler<H: crate::transport::Handler + 'static>(handler: Arc<H>) -> Served {
    let key = Arc::new(TransportKey::generate().unwrap());
    let pinned = key.public();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let clock = Arc::new(std::sync::atomic::AtomicU64::new(NOW));
    let stop = Arc::new(AtomicBool::new(false));
    let thread = thread::spawn({
        let (clock, stop) = (Arc::clone(&clock), Arc::clone(&stop));
        move || {
            serve_secure(
                listener,
                key,
                handler,
                ServerLimits {
                    max_connections: 64,
                    max_per_peer: 32,
                },
                Arc::new(move || clock.load(Ordering::Acquire)),
                stop,
            )
        }
    });
    Served {
        addr,
        pinned,
        clock,
        stop,
        thread,
    }
}
