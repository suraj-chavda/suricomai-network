// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Long-term identity of a development node, kept in a protected file.
//!
//! Layout, creation and refusal rules are in the protocol specification, "Node identity file". The HPKE
//! and receipt keys are not part of it and are never written to disk.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use suricomai_envelope::LabAttester;
use zeroize::Zeroizing;

use crate::error::RuntimeError;
use crate::transport::TransportKey;

const MAGIC: &[u8; 4] = b"SNK1";
const FILE_LEN: usize = 4 + 32 + 32;

/// The keys that outlive a restart.
pub struct NodeIdentity {
    /// Key clients pin.
    pub transport: TransportKey,
    /// Development quote root. A vendor root replaces it once a hardware verifier exists.
    pub lab_attester: LabAttester,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NodeIdentity { redacted }")
    }
}

impl NodeIdentity {
    /// Load the identity at `path`, or create it when the path does not exist.
    ///
    /// Any file that is not exactly the safe form is refused and left as it was.
    pub fn load_or_create(path: &Path) -> Result<Self, RuntimeError> {
        match fs::symlink_metadata(path) {
            Ok(_) => load(path),
            Err(err) if err.kind() == ErrorKind::NotFound => create(path),
            Err(_) => Err(RuntimeError::KeyFile),
        }
    }
}

fn load(path: &Path) -> Result<NodeIdentity, RuntimeError> {
    let before = fs::symlink_metadata(path).map_err(|_| RuntimeError::KeyFile)?;
    if !before.file_type().is_file() {
        return Err(RuntimeError::KeyFile);
    }
    let mut file = File::open(path).map_err(|_| RuntimeError::KeyFile)?;
    // Checked on the opened file, so a path swapped after the check above is caught.
    let meta = file.metadata().map_err(|_| RuntimeError::KeyFile)?;
    if !meta.is_file()
        || meta.mode() & 0o077 != 0
        || meta.len() != FILE_LEN as u64
        || (meta.dev(), meta.ino()) != (before.dev(), before.ino())
    {
        return Err(RuntimeError::KeyFile);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(FILE_LEN + 1));
    (&mut file)
        .take(FILE_LEN as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeError::KeyFile)?;
    if bytes.len() != FILE_LEN || &bytes[..4] != MAGIC {
        return Err(RuntimeError::KeyFile);
    }
    let transport: [u8; 32] = bytes[4..36].try_into().map_err(|_| RuntimeError::KeyFile)?;
    let lab_root: Zeroizing<[u8; 32]> = Zeroizing::new(
        bytes[36..68]
            .try_into()
            .map_err(|_| RuntimeError::KeyFile)?,
    );
    if *lab_root == [0u8; 32] {
        return Err(RuntimeError::KeyFile);
    }
    Ok(NodeIdentity {
        transport: TransportKey::from_secret(transport)?,
        lab_attester: LabAttester::from_secret(&lab_root),
    })
}

fn temp_path(path: &Path) -> Result<PathBuf, RuntimeError> {
    let name = path.file_name().ok_or(RuntimeError::KeyFile)?;
    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(
        ".{}.tmp",
        suffix
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    Ok(path.with_file_name(temp_name))
}

fn create(path: &Path) -> Result<NodeIdentity, RuntimeError> {
    let transport = TransportKey::generate()?;
    let lab_attester = LabAttester::generate();
    let mut bytes = Zeroizing::new(Vec::with_capacity(FILE_LEN));
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&*transport.secret());
    bytes.extend_from_slice(&*lab_attester.secret_bytes());

    let temp = temp_path(path)?;
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .and_then(|mut file| file.write_all(&bytes).and_then(|()| file.sync_all()));
    // A hard link fails when the name exists, so two starts at once keep one identity.
    let linked = written.and_then(|()| fs::hard_link(&temp, path));
    let _ = fs::remove_file(&temp);
    match linked {
        Ok(()) => load(path),
        Err(err) if err.kind() == ErrorKind::AlreadyExists => load(path),
        Err(_) => Err(RuntimeError::KeyFile),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::Arc;
    use std::thread;

    use super::*;

    fn dir() -> PathBuf {
        let mut suffix = [0u8; 8];
        OsRng.fill_bytes(&mut suffix);
        let path = std::env::temp_dir().join(format!(
            "suricomai-identity-{}",
            suffix
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn same(a: &NodeIdentity, b: &NodeIdentity) -> bool {
        a.transport.public() == b.transport.public()
            && a.lab_attester.verifying_bytes() == b.lab_attester.verifying_bytes()
    }

    #[test]
    fn a_created_identity_reloads_with_the_same_keys() {
        let dir = dir();
        let path = dir.join("node.key");
        let first = NodeIdentity::load_or_create(&path).unwrap();
        let second = NodeIdentity::load_or_create(&path).unwrap();
        assert!(same(&first, &second));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_created_file_is_private_and_exact_and_leaves_no_temporary_file() {
        let dir = dir();
        let path = dir.join("node.key");
        NodeIdentity::load_or_create(&path).unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(meta.len(), FILE_LEN as u64);
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("node.key")]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn eight_starts_at_once_agree_on_one_identity() {
        let dir = dir();
        let path = Arc::new(dir.join("node.key"));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let path = Arc::clone(&path);
                thread::spawn(move || NodeIdentity::load_or_create(&path).unwrap())
            })
            .collect();
        let all: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(all.iter().all(|id| same(id, &all[0])));
        let leftovers = fs::read_dir(&dir).unwrap().count();
        assert_eq!(leftovers, 1);
        fs::remove_dir_all(dir).unwrap();
    }

    /// Write `bytes` at `mode`, ask for the identity, and require a refusal that leaves the
    /// file exactly as it was.
    fn refused_and_unchanged(bytes: &[u8], mode: u32) {
        let dir = dir();
        let path = dir.join("node.key");
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            NodeIdentity::load_or_create(&path).unwrap_err(),
            RuntimeError::KeyFile
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            mode
        );
        fs::remove_dir_all(dir).unwrap();
    }

    fn good_bytes() -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&[5u8; 32]);
        bytes.extend_from_slice(&[6u8; 32]);
        bytes
    }

    #[test]
    fn a_well_formed_file_loads() {
        let dir = dir();
        let path = dir.join("node.key");
        fs::write(&path, good_bytes()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(NodeIdentity::load_or_create(&path).is_ok());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_readable_by_others_file_is_refused_unchanged() {
        refused_and_unchanged(&good_bytes(), 0o640);
        refused_and_unchanged(&good_bytes(), 0o604);
        refused_and_unchanged(&good_bytes(), 0o644);
    }

    #[test]
    fn a_short_long_or_empty_file_is_refused_unchanged() {
        let good = good_bytes();
        refused_and_unchanged(&good[..FILE_LEN - 1], 0o600);
        refused_and_unchanged(&[good.clone(), vec![0]].concat(), 0o600);
        refused_and_unchanged(&[], 0o600);
    }

    #[test]
    fn a_wrong_magic_or_all_zero_secret_is_refused_unchanged() {
        let mut wrong = good_bytes();
        wrong[0] = b'X';
        refused_and_unchanged(&wrong, 0o600);

        let mut zero_transport = good_bytes();
        zero_transport[4..36].fill(0);
        refused_and_unchanged(&zero_transport, 0o600);

        let mut zero_root = good_bytes();
        zero_root[36..68].fill(0);
        refused_and_unchanged(&zero_root, 0o600);
    }

    #[test]
    fn a_symbolic_link_a_directory_and_a_missing_parent_are_refused() {
        let dir = dir();
        let real = dir.join("real.key");
        NodeIdentity::load_or_create(&real).unwrap();
        let link = dir.join("link.key");
        symlink(&real, &link).unwrap();
        assert_eq!(
            NodeIdentity::load_or_create(&link).unwrap_err(),
            RuntimeError::KeyFile
        );
        let dangling = dir.join("dangling.key");
        symlink(dir.join("nowhere"), &dangling).unwrap();
        assert_eq!(
            NodeIdentity::load_or_create(&dangling).unwrap_err(),
            RuntimeError::KeyFile
        );
        assert!(!dir.join("nowhere").exists());
        assert_eq!(
            NodeIdentity::load_or_create(&dir).unwrap_err(),
            RuntimeError::KeyFile
        );
        assert_eq!(
            NodeIdentity::load_or_create(&dir.join("missing").join("node.key")).unwrap_err(),
            RuntimeError::KeyFile
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_key_restored_from_its_secret_completes_a_real_handshake() {
        use crate::transport::{exchange_secure, serve_secure_one};
        use crate::Executor;
        use std::net::TcpListener;

        let dir = dir();
        let path = dir.join("node.key");
        let created = NodeIdentity::load_or_create(&path).unwrap();
        let pinned = created.transport.public();
        drop(created);
        let reloaded = NodeIdentity::load_or_create(&path).unwrap();
        assert_eq!(reloaded.transport.public(), pinned);

        let mut executor = Executor::lab().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            serve_secure_one(&listener, &reloaded.transport, &mut executor, 10)
        });
        // The bytes are not a sealed job, so the executor refuses them with a static
        // code. That answer only arrives if the handshake against `pinned` worked.
        let answer = exchange_secure(addr, &pinned, &[0u8; 64]);
        assert!(
            matches!(answer, Err(RuntimeError::Envelope(_))),
            "{answer:?}"
        );
        worker.join().unwrap().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_identity_is_not_printed() {
        let dir = dir();
        let id = NodeIdentity::load_or_create(&dir.join("node.key")).unwrap();
        assert_eq!(format!("{id:?}"), "NodeIdentity { redacted }");
        fs::remove_dir_all(dir).unwrap();
    }
}
