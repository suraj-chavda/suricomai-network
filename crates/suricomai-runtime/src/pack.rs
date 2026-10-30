// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Model packs: loading manifests and approvals into a catalog, and loading the weights of
//! approved models to host. The rules and every refusal are in the protocol specification, "Model pack".

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};

use suricomai_envelope::{ModelApproval, ModelCatalog, ModelManifest, ModelStanding};

use crate::error::RuntimeError;
use crate::model::{runtime_digest, tokenizer_file_digest, weights_file_digest};
use crate::text_model::Engine;
use crate::trust::TrustPolicy;

/// Largest manifest or approval file.
const MAX_OBJECT_BYTES: u64 = 4 * 1024;
/// Most manifest and approval files in one pack.
const MAX_OBJECT_FILES: usize = 4_096;
/// Most directory entries looked at, so a directory full of junk cannot stall a load.
const MAX_ENTRIES: usize = 20_000;
/// Largest tokenizer file.
const MAX_TOKENIZER_BYTES: u64 = 64 * 1024 * 1024;

/// A model a node is hosting: weights in memory, checked against its manifest.
#[derive(Clone)]
pub struct HostedModel {
    /// The manifest's model id.
    pub id: String,
    /// The manifest's model digest.
    pub digest: [u8; 32],
    tokenizer_digest: [u8; 32],
    /// Size of the weights file the model was loaded from.
    pub bytes: u64,
    pub(crate) engine: Arc<Mutex<Engine>>,
}

impl std::fmt::Debug for HostedModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostedModel")
            .field("id", &self.id)
            .field("bytes", &self.bytes)
            .finish()
    }
}

/// The models a node hosts, by digest.
pub type HostedSet = HashMap<[u8; 32], HostedModel>;

/// Bounds on what a node will load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostLimits {
    /// Largest weights file.
    pub max_file_bytes: u64,
    /// Most total weights bytes hosted at once.
    pub memory_budget: u64,
}

impl Default for HostLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 8 * 1024 * 1024 * 1024,
            memory_budget: 16 * 1024 * 1024 * 1024,
        }
    }
}

/// Read a regular file that is not a symbolic link and not longer than `max`.
/// The checks run on the opened file as well as the path.
fn read_regular(path: &Path, max: u64) -> Result<Vec<u8>, &'static str> {
    let before = fs::symlink_metadata(path).map_err(|_| "cannot be read")?;
    if !before.file_type().is_file() {
        return Err("is not a regular file");
    }
    let file = File::open(path).map_err(|_| "cannot be read")?;
    let meta = file.metadata().map_err(|_| "cannot be read")?;
    if !meta.is_file() {
        return Err("is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (meta.dev(), meta.ino()) != (before.dev(), before.ino()) {
            return Err("changed while it was being opened");
        }
    }
    if meta.len() > max {
        return Err("is larger than the allowed size");
    }
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).map_err(|_| "is too large")?);
    file.take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot be read")?;
    if bytes.len() as u64 > max {
        return Err("is larger than the allowed size");
    }
    Ok(bytes)
}

/// Load every manifest and approval in `dir` into a catalog that applies `policy`.
///
/// One bad manifest or approval file refuses the whole load. The second value lists things
/// that were left out without being an error: an approval from an untrusted key, one for no
/// loaded manifest, and a manifest with no usable approval.
pub fn load_catalog(
    dir: &Path,
    policy: &TrustPolicy,
) -> Result<(ModelCatalog, Vec<String>), RuntimeError> {
    let meta = fs::symlink_metadata(dir).map_err(|_| RuntimeError::Pack)?;
    if !meta.file_type().is_dir() {
        return Err(RuntimeError::Pack);
    }
    let mut manifest_files = Vec::new();
    let mut approval_files = Vec::new();
    for (seen, entry) in fs::read_dir(dir)
        .map_err(|_| RuntimeError::Pack)?
        .enumerate()
    {
        if seen >= MAX_ENTRIES {
            return Err(RuntimeError::Pack);
        }
        let path = entry.map_err(|_| RuntimeError::Pack)?.path();
        match path.extension().and_then(|e| e.to_str()) {
            Some("manifest") => manifest_files.push(path),
            Some("approval") => approval_files.push(path),
            _ => {}
        }
        if manifest_files.len() + approval_files.len() > MAX_OBJECT_FILES {
            return Err(RuntimeError::Pack);
        }
    }
    manifest_files.sort();
    approval_files.sort();

    let mut manifests: HashMap<[u8; 32], ModelManifest> = HashMap::new();
    for path in &manifest_files {
        let bytes = read_regular(path, MAX_OBJECT_BYTES).map_err(|_| RuntimeError::Pack)?;
        let manifest = ModelManifest::from_bytes(&bytes).map_err(|_| RuntimeError::Pack)?;
        manifest
            .verify_signature()
            .map_err(|_| RuntimeError::Pack)?;
        let id = manifest.id().map_err(|_| RuntimeError::Pack)?;
        manifests.insert(id, manifest);
    }
    let mut approvals = Vec::new();
    for path in &approval_files {
        let bytes = read_regular(path, MAX_OBJECT_BYTES).map_err(|_| RuntimeError::Pack)?;
        let approval = ModelApproval::from_bytes(&bytes).map_err(|_| RuntimeError::Pack)?;
        approval
            .verify_signature()
            .map_err(|_| RuntimeError::Pack)?;
        approvals.push((path.clone(), approval));
    }

    let mut catalog = policy.catalog()?;
    let mut report = Vec::new();
    let mut approved_manifests = std::collections::HashSet::new();
    for (path, approval) in approvals {
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let Some(manifest) = manifests.get(&approval.manifest_id) else {
            report.push(format!("{name}: names a manifest that is not in this pack"));
            continue;
        };
        match catalog.add(manifest.clone(), approval.clone()) {
            Ok(()) => {
                approved_manifests.insert(approval.manifest_id);
            }
            Err(err) => report.push(format!("{name}: not used ({})", err.code())),
        }
    }
    for (id, manifest) in &manifests {
        if !approved_manifests.contains(id) {
            report.push(format!("{}: no usable approval", manifest.model_id));
        }
    }
    report.sort();
    Ok((catalog, report))
}

/// Load the weights of every model the catalog approves at `now`, checking each against its
/// manifest. A model that fails any check is left out and the reason is reported. A model
/// already in `previous` under the same digests is kept without loading it again. A digest in
/// `denied` is never loaded.
pub fn load_hosted(
    dir: &Path,
    catalog: &ModelCatalog,
    now: u64,
    limits: HostLimits,
    denied: &[[u8; 32]],
    previous: &HostedSet,
) -> (HostedSet, Vec<String>) {
    let mut hosted = HostedSet::new();
    let mut report = Vec::new();
    let mut used = 0u64;
    for entry in catalog.entries() {
        let manifest = &entry.manifest;
        let id = &manifest.model_id;
        let mut skip = |why: &str| report.push(format!("{id}: not hosted, {why}"));
        if denied.contains(&manifest.model_digest) {
            skip("the operator has denied it");
            continue;
        }
        if catalog.standing(&manifest.model_digest, now) != ModelStanding::Approved {
            skip("it is not approved right now");
            continue;
        }
        if manifest.runtime_digest != runtime_digest() {
            skip("it names a different runtime build");
            continue;
        }
        if let Some(kept) = previous.get(&manifest.model_digest) {
            if kept.tokenizer_digest == manifest.tokenizer_digest
                && kept.id == *id
                && used.saturating_add(kept.bytes) <= limits.memory_budget
            {
                used += kept.bytes;
                hosted.insert(manifest.model_digest, kept.clone());
                continue;
            }
        }
        let weights = match read_regular(&dir.join(format!("{id}.gguf")), limits.max_file_bytes) {
            Ok(bytes) => bytes,
            Err(why) => {
                skip(&format!("the weights file {why}"));
                continue;
            }
        };
        if used.saturating_add(weights.len() as u64) > limits.memory_budget {
            skip("it would go past the memory budget");
            continue;
        }
        if weights_file_digest(&weights) != manifest.model_digest {
            skip("the weights do not match the manifest digest");
            continue;
        }
        let tokenizer = match read_regular(
            &dir.join(format!("{id}.tokenizer.json")),
            MAX_TOKENIZER_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(why) => {
                skip(&format!("the tokenizer file {why}"));
                continue;
            }
        };
        if tokenizer_file_digest(&tokenizer) != manifest.tokenizer_digest {
            skip("the tokenizer does not match the manifest digest");
            continue;
        }
        // The engine is built from the bytes that were just hashed, never from the file again.
        let engine = match Engine::from_verified(&weights, &tokenizer) {
            Ok(engine) => engine,
            Err(_) => {
                skip("the weights are not a model this runtime can load");
                continue;
            }
        };
        used += weights.len() as u64;
        hosted.insert(
            manifest.model_digest,
            HostedModel {
                id: id.clone(),
                digest: manifest.model_digest,
                tokenizer_digest: manifest.tokenizer_digest,
                bytes: weights.len() as u64,
                engine: Arc::new(Mutex::new(engine)),
            },
        );
    }
    report.sort();
    (hosted, report)
}

#[cfg(test)]
mod tests {
    use suricomai_envelope::{ApprovalStatus, InferenceParams};

    use super::*;
    use crate::chat::{pack_messages, ChatMessage};
    use crate::testing::{fixture_model, write_model_files, FixtureModel};

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    /// Windows needs the file or directory form chosen up front.
    #[cfg(windows)]
    fn symlink(
        target: impl AsRef<std::path::Path>,
        link: impl AsRef<std::path::Path>,
    ) -> std::io::Result<()> {
        if target.as_ref().is_dir() {
            std::os::windows::fs::symlink_dir(target, link)
        } else {
            std::os::windows::fs::symlink_file(target, link)
        }
    }

    use crate::testkit::{
        approve, dir, good_pack, host, key, manifest_for, policy, write_manifest, HOSTED_NOW as NOW,
    };

    #[test]
    fn an_approved_model_with_matching_files_is_loaded_and_answers() {
        let (dir, model, _) = good_pack("fixture-a", 1);
        let (catalog, report) = load_catalog(&dir, &policy()).unwrap();
        assert!(report.is_empty(), "{report:?}");
        let (hosted, notes) = load_hosted(
            &dir,
            &catalog,
            NOW,
            HostLimits::default(),
            &[],
            &HostedSet::new(),
        );
        assert!(notes.is_empty(), "{notes:?}");
        let entry = hosted.get(&weights_file_digest(&model.weights)).unwrap();
        assert_eq!(entry.id, "fixture-a");
        let prompt = pack_messages(&[ChatMessage {
            role: "user".into(),
            content: "w3 w4".into(),
        }])
        .unwrap();
        let params = InferenceParams::new([1u8; 32], 0, 8).unwrap();
        let answer = entry
            .engine
            .lock()
            .unwrap()
            .answer(&prompt, &params, 64)
            .unwrap();
        assert!(!answer.0.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn one_approval_under_a_threshold_of_two_does_not_approve_the_model() {
        let dir = dir();
        let model = fixture_model(1);
        write_model_files(&dir, "fixture-a", &model);
        let manifest = manifest_for("fixture-a", &model);
        write_manifest(&dir, &manifest);
        approve(&dir, &manifest, 1, ApprovalStatus::Approved, 0, 10_000);
        let (hosted, notes) = host(&dir, NOW, HostLimits::default());
        assert!(hosted.is_empty());
        assert!(
            notes.iter().any(|n| n.contains("not approved")),
            "{notes:?}"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_tampered_manifest_or_approval_or_a_stray_byte_refuses_the_whole_load() {
        for target in ["manifest", "approval"] {
            let (dir, _, _) = good_pack("fixture-a", 1);
            let path = fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| p.extension().is_some_and(|e| e == target))
                .unwrap();
            let mut bytes = fs::read(&path).unwrap();
            let mid = bytes.len() / 2;
            bytes[mid] ^= 1;
            fs::write(&path, bytes).unwrap();
            assert_eq!(
                load_catalog(&dir, &policy()).unwrap_err(),
                RuntimeError::Pack,
                "{target}"
            );
            fs::remove_dir_all(dir).unwrap();
        }
        let (dir, _, manifest) = good_pack("fixture-a", 1);
        let mut padded = manifest.to_bytes().unwrap();
        padded.push(0);
        fs::write(dir.join("fixture-a.manifest"), padded).unwrap();
        assert_eq!(
            load_catalog(&dir, &policy()).unwrap_err(),
            RuntimeError::Pack
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_link_an_oversize_file_too_many_files_or_a_linked_directory_is_refused() {
        let (dir, _, _) = good_pack("fixture-a", 1);
        symlink(dir.join("fixture-a.manifest"), dir.join("alias.manifest")).unwrap();
        assert_eq!(
            load_catalog(&dir, &policy()).unwrap_err(),
            RuntimeError::Pack
        );
        fs::remove_dir_all(dir).unwrap();

        let (dir, _, _) = good_pack("fixture-a", 1);
        fs::write(dir.join("big.approval"), vec![0u8; 5_000]).unwrap();
        assert_eq!(
            load_catalog(&dir, &policy()).unwrap_err(),
            RuntimeError::Pack
        );
        fs::remove_dir_all(dir).unwrap();

        let (dir, _, _) = good_pack("fixture-a", 1);
        for i in 0..MAX_OBJECT_FILES {
            fs::write(dir.join(format!("junk{i}.approval")), b"x").unwrap();
        }
        assert_eq!(
            load_catalog(&dir, &policy()).unwrap_err(),
            RuntimeError::Pack
        );
        fs::remove_dir_all(dir).unwrap();

        let (dir, _, _) = good_pack("fixture-a", 1);
        let link = std::env::temp_dir().join(format!("suricomai-pack-link-{}", std::process::id()));
        let _ = fs::remove_file(&link);
        symlink(&dir, &link).unwrap();
        assert_eq!(
            load_catalog(&link, &policy()).unwrap_err(),
            RuntimeError::Pack
        );
        assert_eq!(
            load_catalog(&dir.join("missing"), &policy()).unwrap_err(),
            RuntimeError::Pack
        );
        // A directory link is removed as a directory on Windows and as a file elsewhere.
        fs::remove_dir(&link)
            .or_else(|_| fs::remove_file(&link))
            .unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_approval_from_an_untrusted_key_or_for_no_manifest_is_reported_and_not_used() {
        let dir = dir();
        let model = fixture_model(1);
        write_model_files(&dir, "fixture-a", &model);
        let manifest = manifest_for("fixture-a", &model);
        write_manifest(&dir, &manifest);
        approve(&dir, &manifest, 1, ApprovalStatus::Approved, 0, 10_000);
        approve(&dir, &manifest, 5, ApprovalStatus::Approved, 0, 10_000);
        let other = manifest_for("fixture-b", &fixture_model(2));
        approve(&dir, &other, 2, ApprovalStatus::Approved, 0, 10_000);
        let (catalog, report) = load_catalog(&dir, &policy()).unwrap();
        assert!(report.iter().any(|r| r.contains("not used")), "{report:?}");
        assert!(
            report.iter().any(|r| r.contains("not in this pack")),
            "{report:?}"
        );
        assert_ne!(
            catalog.standing(&manifest.model_digest, NOW),
            ModelStanding::Approved,
            "one trusted signature of two required"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn weights_a_tokenizer_or_a_runtime_that_do_not_match_the_manifest_are_not_hosted() {
        let dir = dir();
        let good = fixture_model(1);
        let bad_weights = fixture_model(2);
        let other_tokenizer = FixtureModel {
            weights: fixture_model(3).weights,
            tokenizer: [fixture_model(3).tokenizer.as_slice(), b" "].concat(),
        };
        write_model_files(&dir, "good", &good);
        // The manifest names `good` weights but the file on disk is a different model.
        write_model_files(&dir, "weights-swapped", &bad_weights);
        let swapped = ModelManifest::publish(
            "weights-swapped",
            weights_file_digest(&fixture_model(7).weights),
            tokenizer_file_digest(&bad_weights.tokenizer),
            runtime_digest(),
            1,
            "MIT",
            &key(9),
        )
        .unwrap();
        // The manifest names a tokenizer that differs from the file on disk.
        write_model_files(&dir, "tokenizer-swapped", &other_tokenizer);
        let wrong_tok = ModelManifest::publish(
            "tokenizer-swapped",
            weights_file_digest(&other_tokenizer.weights),
            tokenizer_file_digest(b"something else"),
            runtime_digest(),
            1,
            "MIT",
            &key(9),
        )
        .unwrap();
        // The manifest names a runtime build that is not this one.
        write_model_files(&dir, "other-runtime", &fixture_model(4));
        let other_runtime = ModelManifest::publish(
            "other-runtime",
            weights_file_digest(&fixture_model(4).weights),
            tokenizer_file_digest(&fixture_model(4).tokenizer),
            [9u8; 32],
            1,
            "MIT",
            &key(9),
        )
        .unwrap();
        for m in [
            manifest_for("good", &good),
            swapped,
            wrong_tok,
            other_runtime,
        ] {
            write_manifest(&dir, &m);
            for by in [1, 2] {
                approve(&dir, &m, by, ApprovalStatus::Approved, 0, 10_000);
            }
        }
        let (hosted, notes) = host(&dir, NOW, HostLimits::default());
        let names: Vec<_> = hosted.values().map(|h| h.id.clone()).collect();
        assert_eq!(names, vec!["good".to_string()], "{notes:?}");
        assert!(notes
            .iter()
            .any(|n| n.contains("weights-swapped") && n.contains("do not match")));
        assert!(notes
            .iter()
            .any(|n| n.contains("tokenizer-swapped") && n.contains("tokenizer does not match")));
        assert!(notes
            .iter()
            .any(|n| n.contains("other-runtime") && n.contains("runtime")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn weights_that_are_not_a_model_missing_files_links_and_size_limits_are_not_hosted() {
        let dir = dir();
        let junk = FixtureModel {
            weights: vec![7u8; 400],
            tokenizer: fixture_model(1).tokenizer,
        };
        write_model_files(&dir, "junk", &junk);
        let junk_manifest = manifest_for("junk", &junk);
        let absent = manifest_for("absent", &fixture_model(2));
        let linked_model = fixture_model(3);
        write_model_files(&dir, "real", &linked_model);
        fs::rename(dir.join("real.gguf"), dir.join("elsewhere.bin")).unwrap();
        symlink(dir.join("elsewhere.bin"), dir.join("real.gguf")).unwrap();
        let linked = manifest_for("real", &linked_model);
        let big = fixture_model(5);
        write_model_files(&dir, "big", &big);
        let big_manifest = manifest_for("big", &big);
        for m in [&junk_manifest, &absent, &linked, &big_manifest] {
            write_manifest(&dir, m);
            for by in [1, 2] {
                approve(&dir, m, by, ApprovalStatus::Approved, 0, 10_000);
            }
        }
        let (hosted, notes) = host(&dir, NOW, HostLimits::default());
        let names: Vec<_> = hosted.values().map(|h| h.id.clone()).collect();
        assert_eq!(names, vec!["big".to_string()], "{notes:?}");
        assert!(
            notes
                .iter()
                .any(|n| n.contains("junk") && n.contains("this runtime can load"))
                || notes
                    .iter()
                    .any(|n| n.contains("junk") && n.contains("do not match")),
            "{notes:?}"
        );
        assert!(notes.iter().any(|n| n.contains("absent")));
        assert!(notes
            .iter()
            .any(|n| n.contains("real") && n.contains("not a regular file")));
        let tight = HostLimits {
            max_file_bytes: 100,
            memory_budget: u64::MAX,
        };
        assert!(host(&dir, NOW, tight).0.is_empty());
        let one_byte_budget = HostLimits {
            max_file_bytes: u64::MAX,
            memory_budget: 1,
        };
        let (none, notes) = host(&dir, NOW, one_byte_budget);
        assert!(none.is_empty());
        assert!(
            notes.iter().any(|n| n.contains("memory budget")),
            "{notes:?}"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn expired_not_yet_valid_and_revoked_models_are_not_hosted() {
        let (dir, _, manifest) = good_pack("fixture-a", 1);
        assert_eq!(host(&dir, NOW, HostLimits::default()).0.len(), 1);
        assert!(
            host(&dir, 10_001, HostLimits::default()).0.is_empty(),
            "expired"
        );
        approve(&dir, &manifest, 1, ApprovalStatus::Revoked, 500, 10_000);
        assert!(
            host(&dir, NOW, HostLimits::default()).0.is_empty(),
            "one revocation is enough"
        );
        assert_eq!(
            host(&dir, 400, HostLimits::default()).0.len(),
            1,
            "before the revocation took effect"
        );
        fs::remove_dir_all(dir).unwrap();

        let dir2 = dir_with_future_approval();
        assert!(
            host(&dir2, NOW, HostLimits::default()).0.is_empty(),
            "not yet valid"
        );
        fs::remove_dir_all(dir2).unwrap();
    }

    fn dir_with_future_approval() -> std::path::PathBuf {
        let dir = dir();
        let model = fixture_model(1);
        write_model_files(&dir, "fixture-a", &model);
        let manifest = manifest_for("fixture-a", &model);
        write_manifest(&dir, &manifest);
        for by in [1, 2] {
            approve(&dir, &manifest, by, ApprovalStatus::Approved, 5_000, 10_000);
        }
        dir
    }

    #[test]
    fn weights_swapped_after_loading_do_not_change_what_runs() {
        let (dir, model, _) = good_pack("fixture-a", 1);
        let (hosted, _) = host(&dir, NOW, HostLimits::default());
        let entry = hosted.values().next().unwrap().clone();
        let prompt = pack_messages(&[ChatMessage {
            role: "user".into(),
            content: "w3 w4".into(),
        }])
        .unwrap();
        let params = InferenceParams::new([1u8; 32], 0, 8).unwrap();
        let before = entry
            .engine
            .lock()
            .unwrap()
            .answer(&prompt, &params, 64)
            .unwrap();
        fs::write(dir.join("fixture-a.gguf"), fixture_model(99).weights).unwrap();
        let after = entry
            .engine
            .lock()
            .unwrap()
            .answer(&prompt, &params, 64)
            .unwrap();
        assert_eq!(
            before, after,
            "the model in memory is the one that was verified"
        );
        // And a fresh load now refuses the swapped file.
        assert!(host(&dir, NOW, HostLimits::default()).0.is_empty());
        let _ = model;
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_denied_digest_is_never_loaded_even_with_full_approvals_and_an_earlier_load() {
        let (dir, model, _) = good_pack("fixture-a", 1);
        let digest = weights_file_digest(&model.weights);
        let (catalog, _) = load_catalog(&dir, &policy()).unwrap();
        let (kept, _) = load_hosted(
            &dir,
            &catalog,
            NOW,
            HostLimits::default(),
            &[],
            &HostedSet::new(),
        );
        assert_eq!(kept.len(), 1);
        let (after, notes) =
            load_hosted(&dir, &catalog, NOW, HostLimits::default(), &[digest], &kept);
        assert!(after.is_empty(), "a model already loaded is dropped too");
        assert!(notes.iter().any(|n| n.contains("denied")), "{notes:?}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_reload_keeps_an_unchanged_model_and_drops_a_revoked_one() {
        let (dir, _, manifest) = good_pack("fixture-a", 1);
        let (catalog, _) = load_catalog(&dir, &policy()).unwrap();
        let (first, _) = load_hosted(
            &dir,
            &catalog,
            NOW,
            HostLimits::default(),
            &[],
            &HostedSet::new(),
        );
        let (second, _) = load_hosted(&dir, &catalog, NOW, HostLimits::default(), &[], &first);
        let a = first.values().next().unwrap();
        let b = second.values().next().unwrap();
        assert!(Arc::ptr_eq(&a.engine, &b.engine), "no second load");
        approve(&dir, &manifest, 2, ApprovalStatus::Revoked, 100, 10_000);
        let (catalog, _) = load_catalog(&dir, &policy()).unwrap();
        let (third, notes) = load_hosted(&dir, &catalog, NOW, HostLimits::default(), &[], &second);
        assert!(third.is_empty(), "{notes:?}");
        fs::remove_dir_all(dir).unwrap();
    }
}
