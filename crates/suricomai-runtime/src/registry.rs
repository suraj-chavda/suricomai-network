// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Registry of signed model objects, and the sync that copies them into a pack directory.
//! Rules are in the protocol specification, "Registry". A registry is not trusted for anything: whoever loads
//! an object verifies it again under their own trust policy.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rand::rngs::OsRng;
use rand::RngCore;
use suricomai_envelope::{ModelApproval, ModelManifest};

use crate::error::RuntimeError;
use crate::transport::{request_direct, Handler};
use crate::trust::TrustPolicy;
use crate::wire::tagged;

const KIND_PUT: u8 = 6;
const KIND_LIST: u8 = 7;
const KIND_GET: u8 = 8;
/// Object type byte of a manifest.
pub const OBJECT_MANIFEST: u8 = 1;
/// Object type byte of an approval.
pub const OBJECT_APPROVAL: u8 = 2;
const MAX_OBJECT_BYTES: usize = 4 * 1024;
const PAGE: usize = 64;
const MAX_TRACKED_PEERS: usize = 4_096;
/// Most list pages a sync reads, so a registry cannot keep a client listing forever.
const MAX_SYNC_PAGES: usize = 80;

/// The id of an object: BLAKE3 in key derivation mode over the type byte and the bytes.
pub fn object_id(kind: u8, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("suricomai.registry.object.v1");
    hasher.update(&[kind]);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn hex(id: &[u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Structure and signature check shared by the registry and by sync. Trust is not checked.
fn check_object(kind: u8, bytes: &[u8]) -> Result<Option<[u8; 32]>, RuntimeError> {
    if bytes.len() > MAX_OBJECT_BYTES {
        return Err(RuntimeError::BadRequest);
    }
    match kind {
        OBJECT_MANIFEST => {
            let manifest =
                ModelManifest::from_bytes(bytes).map_err(|_| RuntimeError::BadRequest)?;
            manifest
                .verify_signature()
                .map_err(|_| RuntimeError::BadRequest)?;
            Ok(None)
        }
        OBJECT_APPROVAL => {
            let approval =
                ModelApproval::from_bytes(bytes).map_err(|_| RuntimeError::BadRequest)?;
            approval
                .verify_signature()
                .map_err(|_| RuntimeError::BadRequest)?;
            Ok(Some(approval.approver_public))
        }
        _ => Err(RuntimeError::BadRequest),
    }
}

/// What a registry accepts and how much it holds.
pub struct RegistryConfig {
    /// When set, approvals from approvers outside this policy are refused. Manifests are not
    /// restricted, because an unapproved manifest is inert.
    pub trust: Option<TrustPolicy>,
    /// Most objects held.
    pub max_objects: usize,
    /// Most puts from one peer address per window.
    pub puts_per_window: usize,
    /// Length of that window in seconds.
    pub window_secs: u64,
    /// Directory the objects are kept in, or `None` to keep them in memory only.
    pub store: Option<PathBuf>,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            trust: None,
            max_objects: 4_096,
            puts_per_window: 30,
            window_secs: 60,
            store: None,
        }
    }
}

struct Stored {
    kind: u8,
    id: [u8; 32],
    bytes: Vec<u8>,
}

#[derive(Default)]
struct State {
    next_seq: u64,
    objects: BTreeMap<u64, Stored>,
    by_id: HashMap<[u8; 32], u64>,
    puts: HashMap<IpAddr, Vec<u64>>,
}

/// The objects and the rules around them.
pub struct Registry {
    config: RegistryConfig,
    state: Mutex<State>,
}

fn file_name(kind: u8, id: &[u8; 32]) -> String {
    let ext = if kind == OBJECT_MANIFEST {
        "manifest"
    } else {
        "approval"
    };
    format!("{}.{ext}", hex(id))
}

impl Registry {
    /// Start a registry. When `config.store` names a directory, every file in it is checked
    /// again and loaded. A file whose name is not `<id>.manifest` or `<id>.approval`, whose
    /// bytes do not hash to that id, or that fails the structure check refuses the start.
    pub fn open(config: RegistryConfig) -> Result<Self, RuntimeError> {
        let mut state = State::default();
        if let Some(dir) = &config.store {
            let meta = fs::symlink_metadata(dir).map_err(|_| RuntimeError::Pack)?;
            if !meta.file_type().is_dir() {
                return Err(RuntimeError::Pack);
            }
            let mut files: Vec<PathBuf> = fs::read_dir(dir)
                .map_err(|_| RuntimeError::Pack)?
                .map(|e| e.map(|e| e.path()).map_err(|_| RuntimeError::Pack))
                .collect::<Result<_, _>>()?;
            if files.len() > config.max_objects {
                return Err(RuntimeError::Pack);
            }
            files.sort();
            for path in files {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let (stem, ext) = name.rsplit_once('.').ok_or(RuntimeError::Pack)?;
                let kind = match ext {
                    "manifest" => OBJECT_MANIFEST,
                    "approval" => OBJECT_APPROVAL,
                    _ => return Err(RuntimeError::Pack),
                };
                let bytes = read_object_file(&path).map_err(|_| RuntimeError::Pack)?;
                let id = object_id(kind, &bytes);
                if stem != hex(&id) || check_object(kind, &bytes).is_err() {
                    return Err(RuntimeError::Pack);
                }
                state.next_seq += 1;
                let seq = state.next_seq;
                state.by_id.insert(id, seq);
                state.objects.insert(seq, Stored { kind, id, bytes });
            }
        }
        Ok(Self {
            config,
            state: Mutex::new(state),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn within_quota(&self, peer: IpAddr, now: u64) -> bool {
        let mut state = self.lock();
        let window = self.config.window_secs;
        if !state.puts.contains_key(&peer) && state.puts.len() >= MAX_TRACKED_PEERS {
            state.puts.retain(|_, times| {
                times.retain(|t| now.saturating_sub(*t) < window);
                !times.is_empty()
            });
            if state.puts.len() >= MAX_TRACKED_PEERS {
                return false;
            }
        }
        let times = state.puts.entry(peer).or_default();
        times.retain(|t| now.saturating_sub(*t) < window);
        if times.len() >= self.config.puts_per_window {
            return false;
        }
        times.push(now);
        true
    }

    fn put(&self, peer: IpAddr, body: &[u8], now: u64) -> Result<Vec<u8>, RuntimeError> {
        let (kind, bytes) = body.split_first().ok_or(RuntimeError::Wire)?;
        let refused = |err: RuntimeError| Ok(tagged(1, err.code().as_bytes()));
        let approver = match check_object(*kind, bytes) {
            Ok(approver) => approver,
            Err(err) => return refused(err),
        };
        if let (Some(policy), Some(approver)) = (&self.config.trust, approver) {
            if !policy.approvers().contains(&approver) {
                return refused(RuntimeError::Envelope(
                    suricomai_envelope::EnvelopeError::UntrustedApprover,
                ));
            }
        }
        let id = object_id(*kind, bytes);
        if self.lock().by_id.contains_key(&id) {
            return Ok(tagged(0, &id));
        }
        if !self.within_quota(peer, now) {
            return refused(RuntimeError::Busy);
        }
        let mut state = self.lock();
        if state.by_id.contains_key(&id) {
            return Ok(tagged(0, &id));
        }
        if state.objects.len() >= self.config.max_objects {
            return refused(RuntimeError::Busy);
        }
        if let Some(dir) = &self.config.store {
            if write_object_file(dir, *kind, &id, bytes).is_err() {
                return refused(RuntimeError::Busy);
            }
        }
        state.next_seq += 1;
        let seq = state.next_seq;
        state.by_id.insert(id, seq);
        state.objects.insert(
            seq,
            Stored {
                kind: *kind,
                id,
                bytes: bytes.to_vec(),
            },
        );
        Ok(tagged(0, &id))
    }

    fn list(&self, body: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        let cursor = u64::from_be_bytes(body.try_into().map_err(|_| RuntimeError::Wire)?);
        let state = self.lock();
        let mut rest = state.objects.range(cursor..);
        let page: Vec<_> = rest.by_ref().take(PAGE).collect();
        let next = rest.next().map_or(0, |(seq, _)| *seq);
        let mut out = next.to_be_bytes().to_vec();
        out.push(u8::try_from(page.len()).map_err(|_| RuntimeError::Wire)?);
        for (_, stored) in page {
            out.push(stored.kind);
            out.extend_from_slice(&stored.id);
        }
        Ok(tagged(0, &out))
    }

    fn get(&self, body: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        let id: [u8; 32] = body.try_into().map_err(|_| RuntimeError::Wire)?;
        let state = self.lock();
        let Some(stored) = state.by_id.get(&id).and_then(|seq| state.objects.get(seq)) else {
            return Ok(tagged(1, RuntimeError::BadRequest.code().as_bytes()));
        };
        let mut out = vec![stored.kind];
        out.extend_from_slice(&stored.bytes);
        Ok(tagged(0, &out))
    }

    /// Number of objects held.
    pub fn len(&self) -> usize {
        self.lock().objects.len()
    }

    /// True when no object is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Handler for Registry {
    fn respond(
        &self,
        peer: IpAddr,
        request: &[u8],
        clock: &(dyn Fn() -> u64 + Send + Sync),
    ) -> Result<Vec<u8>, RuntimeError> {
        match request.split_first() {
            Some((&KIND_PUT, body)) => self.put(peer, body, clock()),
            Some((&KIND_LIST, body)) => self.list(body),
            Some((&KIND_GET, body)) => self.get(body),
            _ => Err(RuntimeError::Wire),
        }
    }
}

fn read_object_file(path: &Path) -> Result<Vec<u8>, RuntimeError> {
    let before = fs::symlink_metadata(path).map_err(|_| RuntimeError::Pack)?;
    if !before.file_type().is_file() || before.len() > MAX_OBJECT_BYTES as u64 {
        return Err(RuntimeError::Pack);
    }
    fs::read(path).map_err(|_| RuntimeError::Pack)
}

/// Create `<id>.<ext>` in `dir` without ever overwriting: write a temporary file, then hard
/// link it to the final name, which fails if the name exists.
fn write_object_file(dir: &Path, kind: u8, id: &[u8; 32], bytes: &[u8]) -> std::io::Result<bool> {
    let mut suffix = [0u8; 6];
    OsRng.fill_bytes(&mut suffix);
    let temp = dir.join(format!(
        ".{}.{}.tmp",
        hex(id),
        suffix
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()));
    let linked = written.and_then(|()| fs::hard_link(&temp, dir.join(file_name(kind, id))));
    let _ = fs::remove_file(&temp);
    match linked {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

/// Put one object into the registry at `registry` (holding `pinned`). Returns its id.
pub fn registry_put(
    registry: SocketAddr,
    pinned: &[u8; 32],
    kind: u8,
    bytes: &[u8],
) -> Result<[u8; 32], RuntimeError> {
    let mut body = vec![kind];
    body.extend_from_slice(bytes);
    let out = request_direct(registry, pinned, &tagged(KIND_PUT, &body))?;
    let id: [u8; 32] = out.as_slice().try_into().map_err(|_| RuntimeError::Wire)?;
    if id != object_id(kind, bytes) {
        return Err(RuntimeError::Wire);
    }
    Ok(id)
}

/// An object type byte and its id, as a registry lists it.
pub type ObjectRef = (u8, [u8; 32]);

/// One page of object ids from the registry. The second value is the next cursor, or `0`.
pub fn registry_list(
    registry: SocketAddr,
    pinned: &[u8; 32],
    cursor: u64,
) -> Result<(Vec<ObjectRef>, u64), RuntimeError> {
    let out = request_direct(registry, pinned, &tagged(KIND_LIST, &cursor.to_be_bytes()))?;
    let (head, rows) = out.split_at_checked(9).ok_or(RuntimeError::Wire)?;
    let next = u64::from_be_bytes(head[..8].try_into().map_err(|_| RuntimeError::Wire)?);
    let count = usize::from(head[8]);
    if count > PAGE || rows.len() != count * 33 {
        return Err(RuntimeError::Wire);
    }
    let mut entries = Vec::with_capacity(count);
    let (rows, _) = rows.as_chunks::<33>();
    for row in rows {
        if row[0] != OBJECT_MANIFEST && row[0] != OBJECT_APPROVAL {
            return Err(RuntimeError::Wire);
        }
        entries.push((row[0], row[1..].try_into().map_err(|_| RuntimeError::Wire)?));
    }
    Ok((entries, next))
}

/// Fetch one object by id. The bytes must hash to the id asked for.
pub fn registry_get(
    registry: SocketAddr,
    pinned: &[u8; 32],
    id: &[u8; 32],
) -> Result<(u8, Vec<u8>), RuntimeError> {
    let out = request_direct(registry, pinned, &tagged(KIND_GET, id))?;
    let (kind, bytes) = out.split_first().ok_or(RuntimeError::Wire)?;
    if object_id(*kind, bytes) != *id {
        return Err(RuntimeError::Wire);
    }
    Ok((*kind, bytes.to_vec()))
}

/// What one sync did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Objects written into the pack directory.
    pub fetched: usize,
    /// Objects already there.
    pub present: usize,
    /// Objects the registry listed that failed a check and were not written.
    pub rejected: usize,
}

/// Copy the registry's objects into `dest`. Nothing is ever overwritten, and an object whose
/// bytes do not match its id, or whose structure or signature fails, is not written.
pub fn sync_registry(
    registry: SocketAddr,
    pinned: &[u8; 32],
    dest: &Path,
) -> Result<SyncOutcome, RuntimeError> {
    let meta = fs::symlink_metadata(dest).map_err(|_| RuntimeError::Pack)?;
    if !meta.file_type().is_dir() {
        return Err(RuntimeError::Pack);
    }
    let mut outcome = SyncOutcome::default();
    let mut cursor = 0;
    for _ in 0..MAX_SYNC_PAGES {
        let (page, next) = registry_list(registry, pinned, cursor)?;
        for (kind, id) in page {
            if dest.join(file_name(kind, &id)).exists() {
                outcome.present += 1;
                continue;
            }
            let fetched = registry_get(registry, pinned, &id)
                .ok()
                .filter(|(got_kind, _)| *got_kind == kind)
                .filter(|(got_kind, bytes)| check_object(*got_kind, bytes).is_ok());
            match fetched {
                Some((got_kind, bytes)) => match write_object_file(dest, got_kind, &id, &bytes) {
                    Ok(true) => outcome.fetched += 1,
                    Ok(false) => outcome.present += 1,
                    Err(_) => return Err(RuntimeError::Pack),
                },
                None => outcome.rejected += 1,
            }
        }
        if next == 0 {
            return Ok(outcome);
        }
        cursor = next;
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use suricomai_envelope::ApprovalStatus;

    use super::*;
    use crate::testing::fixture_model;
    use crate::testkit::{dir, key, manifest_for, policy, serve_handler};

    fn manifest_bytes(id: &str, seed: u8) -> Vec<u8> {
        manifest_for(id, &fixture_model(seed)).to_bytes().unwrap()
    }

    fn approval_bytes(id: &str, seed: u8, by: u8) -> Vec<u8> {
        let manifest = manifest_for(id, &fixture_model(seed));
        ModelApproval::issue(&manifest, ApprovalStatus::Approved, 0, 10_000, &key(by))
            .unwrap()
            .to_bytes()
    }

    fn registry(config: RegistryConfig) -> Arc<Registry> {
        Arc::new(Registry::open(config).unwrap())
    }

    #[test]
    fn objects_can_be_put_listed_and_fetched_and_putting_twice_changes_nothing() {
        let reg = registry(RegistryConfig::default());
        let served = serve_handler(Arc::clone(&reg));
        let m = manifest_bytes("fixture-a", 1);
        let a = approval_bytes("fixture-a", 1, 1);
        let m_id = registry_put(served.addr, &served.pinned, OBJECT_MANIFEST, &m).unwrap();
        let a_id = registry_put(served.addr, &served.pinned, OBJECT_APPROVAL, &a).unwrap();
        assert_eq!(m_id, object_id(OBJECT_MANIFEST, &m));
        assert_eq!(
            registry_put(served.addr, &served.pinned, OBJECT_MANIFEST, &m).unwrap(),
            m_id
        );
        assert_eq!(reg.len(), 2);
        let (rows, next) = registry_list(served.addr, &served.pinned, 0).unwrap();
        assert_eq!(rows, vec![(OBJECT_MANIFEST, m_id), (OBJECT_APPROVAL, a_id)]);
        assert_eq!(next, 0);
        assert_eq!(
            registry_get(served.addr, &served.pinned, &a_id).unwrap(),
            (OBJECT_APPROVAL, a)
        );
        assert!(registry_get(served.addr, &served.pinned, &[7u8; 32]).is_err());
        served.shut_down();
    }

    #[test]
    fn unsigned_tampered_truncated_oversize_and_mistyped_objects_are_refused() {
        let reg = registry(RegistryConfig::default());
        let served = serve_handler(Arc::clone(&reg));
        let m = manifest_bytes("fixture-a", 1);
        let mut flipped = m.clone();
        let mid = flipped.len() / 2;
        flipped[mid] ^= 1;
        let mut padded = m.clone();
        padded.push(0);
        let cases: Vec<(u8, Vec<u8>)> = vec![
            (OBJECT_MANIFEST, flipped),
            (OBJECT_MANIFEST, m[..m.len() - 1].to_vec()),
            (OBJECT_MANIFEST, padded),
            (OBJECT_MANIFEST, Vec::new()),
            (OBJECT_MANIFEST, vec![0u8; 5_000]),
            (OBJECT_APPROVAL, m.clone()),
            (OBJECT_MANIFEST, approval_bytes("fixture-a", 1, 1)),
            (9, m.clone()),
            (0, m.clone()),
        ];
        for (kind, bytes) in cases {
            assert_eq!(
                registry_put(served.addr, &served.pinned, kind, &bytes),
                Err(RuntimeError::BadRequest),
                "kind {kind} len {}",
                bytes.len()
            );
        }
        assert!(reg.is_empty());
        served.shut_down();
    }

    #[test]
    fn a_registry_with_a_policy_refuses_untrusted_approvers_but_stores_manifests() {
        let policy = policy();
        let reg = registry(RegistryConfig {
            trust: Some(policy),
            ..RegistryConfig::default()
        });
        let served = serve_handler(Arc::clone(&reg));
        registry_put(
            served.addr,
            &served.pinned,
            OBJECT_MANIFEST,
            &manifest_bytes("fixture-a", 1),
        )
        .unwrap();
        registry_put(
            served.addr,
            &served.pinned,
            OBJECT_APPROVAL,
            &approval_bytes("fixture-a", 1, 1),
        )
        .unwrap();
        assert_eq!(
            registry_put(
                served.addr,
                &served.pinned,
                OBJECT_APPROVAL,
                &approval_bytes("fixture-a", 1, 5)
            ),
            Err(RuntimeError::Envelope(
                suricomai_envelope::EnvelopeError::UntrustedApprover
            ))
        );
        assert_eq!(reg.len(), 2);
        served.shut_down();
    }

    #[test]
    fn a_flood_from_one_peer_and_a_full_registry_answer_busy_and_keep_what_they_hold() {
        let reg = registry(RegistryConfig {
            puts_per_window: 3,
            max_objects: 4,
            ..RegistryConfig::default()
        });
        let served = serve_handler(Arc::clone(&reg));
        for seed in 1..=3u8 {
            registry_put(
                served.addr,
                &served.pinned,
                OBJECT_MANIFEST,
                &manifest_bytes(&format!("m{seed}"), seed),
            )
            .unwrap();
        }
        assert_eq!(
            registry_put(
                served.addr,
                &served.pinned,
                OBJECT_MANIFEST,
                &manifest_bytes("m4", 4)
            ),
            Err(RuntimeError::Busy)
        );
        served.set_time(NOW_LATER);
        registry_put(
            served.addr,
            &served.pinned,
            OBJECT_MANIFEST,
            &manifest_bytes("m4", 4),
        )
        .unwrap();
        // Four are held, which is the bound. A fifth is refused even with quota to spare.
        assert_eq!(
            registry_put(
                served.addr,
                &served.pinned,
                OBJECT_MANIFEST,
                &manifest_bytes("m5", 5)
            ),
            Err(RuntimeError::Busy)
        );
        assert_eq!(reg.len(), 4);
        // Putting an object already held still works when the registry is full.
        registry_put(
            served.addr,
            &served.pinned,
            OBJECT_MANIFEST,
            &manifest_bytes("m1", 1),
        )
        .unwrap();
        served.shut_down();
    }

    const NOW_LATER: u64 = 10_000;

    #[test]
    fn malformed_requests_close_the_connection() {
        let reg = registry(RegistryConfig::default());
        let served = serve_handler(Arc::clone(&reg));
        for request in [
            tagged(KIND_PUT, &[]),
            tagged(KIND_LIST, &[0u8; 7]),
            tagged(KIND_LIST, &[0u8; 9]),
            tagged(KIND_GET, &[0u8; 31]),
            tagged(KIND_GET, &[0u8; 33]),
            tagged(9, &[]),
        ] {
            assert_eq!(
                request_direct(served.addr, &served.pinned, &request),
                Err(RuntimeError::Wire),
                "{request:?}"
            );
        }
        served.shut_down();
    }

    #[test]
    fn objects_kept_in_a_directory_survive_a_restart_and_a_bad_file_refuses_the_start() {
        let store = dir();
        let first = registry(RegistryConfig {
            store: Some(store.clone()),
            ..RegistryConfig::default()
        });
        let m = manifest_bytes("fixture-a", 1);
        first
            .put(
                "127.0.0.1".parse().unwrap(),
                &[&[OBJECT_MANIFEST], m.as_slice()].concat(),
                1,
            )
            .unwrap();
        assert_eq!(first.len(), 1);
        drop(first);
        let reopened = Registry::open(RegistryConfig {
            store: Some(store.clone()),
            ..RegistryConfig::default()
        })
        .unwrap();
        assert_eq!(reopened.len(), 1);
        drop(reopened);
        let path = fs::read_dir(&store)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut tampered = fs::read(&path).unwrap();
        tampered[10] ^= 1;
        fs::write(&path, &tampered).unwrap();
        let reopen = || {
            Registry::open(RegistryConfig {
                store: Some(store.clone()),
                ..RegistryConfig::default()
            })
        };
        assert!(
            reopen().is_err(),
            "bytes no longer match the id in the name"
        );
        fs::write(&path, &m).unwrap();
        assert!(reopen().is_ok());
        fs::write(store.join("stray.txt"), b"x").unwrap();
        assert!(reopen().is_err(), "an unknown file refuses the start");
        fs::remove_file(store.join("stray.txt")).unwrap();
        fs::rename(&path, store.join(format!("{}.manifest", "00".repeat(32)))).unwrap();
        assert!(
            reopen().is_err(),
            "a name that is not the id refuses the start"
        );
        fs::remove_dir_all(store).unwrap();
    }

    #[test]
    fn sync_copies_objects_once_and_never_overwrites() {
        let reg = registry(RegistryConfig::default());
        let served = serve_handler(Arc::clone(&reg));
        let m = manifest_bytes("fixture-a", 1);
        let a1 = approval_bytes("fixture-a", 1, 1);
        let a2 = approval_bytes("fixture-a", 1, 2);
        for (kind, bytes) in [
            (OBJECT_MANIFEST, &m),
            (OBJECT_APPROVAL, &a1),
            (OBJECT_APPROVAL, &a2),
        ] {
            registry_put(served.addr, &served.pinned, kind, bytes).unwrap();
        }
        let dest = dir();
        let first = sync_registry(served.addr, &served.pinned, &dest).unwrap();
        assert_eq!(
            first,
            SyncOutcome {
                fetched: 3,
                present: 0,
                rejected: 0
            }
        );
        let second = sync_registry(served.addr, &served.pinned, &dest).unwrap();
        assert_eq!(
            second,
            SyncOutcome {
                fetched: 0,
                present: 3,
                rejected: 0
            }
        );

        // A file already in the place an object would go is left exactly as it is.
        let id = object_id(OBJECT_APPROVAL, &a1);
        let target = dest.join(file_name(OBJECT_APPROVAL, &id));
        fs::write(&target, b"mine").unwrap();
        sync_registry(served.addr, &served.pinned, &dest).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"mine");
        assert_eq!(
            sync_registry(served.addr, &served.pinned, &dest.join("missing")),
            Err(RuntimeError::Pack)
        );
        fs::remove_dir_all(dest).unwrap();
        served.shut_down();
    }

    /// A registry that lists real ids but serves other bytes, or invalid bytes.
    struct Lying {
        rows: Vec<(u8, [u8; 32])>,
        reply: Vec<u8>,
    }

    impl Handler for Lying {
        fn respond(
            &self,
            _peer: IpAddr,
            request: &[u8],
            _clock: &(dyn Fn() -> u64 + Send + Sync),
        ) -> Result<Vec<u8>, RuntimeError> {
            match request.first() {
                Some(&KIND_LIST) => {
                    let mut out = 0u64.to_be_bytes().to_vec();
                    out.push(self.rows.len() as u8);
                    for (kind, id) in &self.rows {
                        out.push(*kind);
                        out.extend_from_slice(id);
                    }
                    Ok(tagged(0, &out))
                }
                Some(&KIND_GET) => Ok(tagged(0, &self.reply)),
                _ => Err(RuntimeError::Wire),
            }
        }
    }

    #[test]
    fn sync_rejects_objects_whose_bytes_do_not_match_their_id_or_fail_the_checks() {
        let genuine = manifest_bytes("fixture-a", 1);
        let other = manifest_bytes("fixture-b", 2);
        let mut flipped = genuine.clone();
        let mid = flipped.len() / 2;
        flipped[mid] ^= 1;
        let cases: Vec<(&str, [u8; 32], Vec<u8>)> = vec![
            (
                "other object under this id",
                object_id(OBJECT_MANIFEST, &genuine),
                [&[OBJECT_MANIFEST], other.as_slice()].concat(),
            ),
            (
                "tampered under its own hash",
                object_id(OBJECT_MANIFEST, &flipped),
                [&[OBJECT_MANIFEST], flipped.as_slice()].concat(),
            ),
            (
                "wrong type byte",
                object_id(OBJECT_MANIFEST, &genuine),
                [&[OBJECT_APPROVAL], genuine.as_slice()].concat(),
            ),
            (
                "empty reply",
                object_id(OBJECT_MANIFEST, &genuine),
                Vec::new(),
            ),
        ];
        for (name, id, reply) in cases {
            let lying = serve_handler(Arc::new(Lying {
                rows: vec![(OBJECT_MANIFEST, id)],
                reply,
            }));
            let dest = dir();
            let out = sync_registry(lying.addr, &lying.pinned, &dest).unwrap();
            assert_eq!(out.fetched, 0, "{name}");
            assert_eq!(out.rejected, 1, "{name}");
            assert_eq!(
                fs::read_dir(&dest).unwrap().count(),
                0,
                "{name}: nothing written"
            );
            fs::remove_dir_all(dest).unwrap();
            lying.shut_down();
        }
    }

    #[test]
    fn published_synced_and_hosted_works_end_to_end_and_a_revocation_stops_the_model() {
        use crate::pack::{load_catalog, load_hosted, HostLimits, HostedSet};
        use crate::testing::write_model_files;
        use suricomai_envelope::ModelCatalog;

        let reg = registry(RegistryConfig::default());
        let served = serve_handler(Arc::clone(&reg));
        let model = fixture_model(1);
        let manifest = manifest_for("fixture-a", &model);
        registry_put(
            served.addr,
            &served.pinned,
            OBJECT_MANIFEST,
            &manifest.to_bytes().unwrap(),
        )
        .unwrap();
        for by in [1, 2] {
            registry_put(
                served.addr,
                &served.pinned,
                OBJECT_APPROVAL,
                &approval_bytes("fixture-a", 1, by),
            )
            .unwrap();
        }
        let node_dir = dir();
        write_model_files(&node_dir, "fixture-a", &model);
        sync_registry(served.addr, &served.pinned, &node_dir).unwrap();
        let host = |catalog: &ModelCatalog| {
            load_hosted(
                &node_dir,
                catalog,
                1_000,
                HostLimits::default(),
                &[],
                &HostedSet::new(),
            )
            .0
        };
        let (catalog, report) = load_catalog(&node_dir, &policy()).unwrap();
        assert!(report.is_empty(), "{report:?}");
        assert_eq!(
            host(&catalog).len(),
            1,
            "synced approvals make the model hostable"
        );

        // One approver revokes. The revocation travels the same way and stops the model.
        let revoke = ModelApproval::issue(&manifest, ApprovalStatus::Revoked, 500, 10_000, &key(1))
            .unwrap()
            .to_bytes();
        registry_put(served.addr, &served.pinned, OBJECT_APPROVAL, &revoke).unwrap();
        sync_registry(served.addr, &served.pinned, &node_dir).unwrap();
        let (revoked, _) = load_catalog(&node_dir, &policy()).unwrap();
        assert!(
            host(&revoked).is_empty(),
            "a revocation synced from the registry stops the model"
        );
        fs::remove_dir_all(node_dir).unwrap();
        served.shut_down();
    }
}
