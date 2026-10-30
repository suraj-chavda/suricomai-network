// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Trust policy: which approvers a node or client believes, and how many must agree.
//! The file format and refusals are in the protocol specification, "Trust policy file". No key is compiled in.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use suricomai_envelope::ModelCatalog;

use crate::error::RuntimeError;
use crate::ticket::key_from_hex;

const MAGIC: &str = "suricomai-trust-v1";
const MAX_BYTES: u64 = 8 * 1024;
const MAX_APPROVERS: usize = 64;
const MAX_DENIED: usize = 1_024;

/// The approvers to trust and how many distinct ones must sign the same approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustPolicy {
    approvers: Vec<[u8; 32]>,
    threshold: usize,
    denied: Vec<[u8; 32]>,
}

impl TrustPolicy {
    /// Read a policy from text. A threshold of 1 is refused unless `allow_single_approver`.
    pub fn parse(text: &str, allow_single_approver: bool) -> Result<Self, RuntimeError> {
        let mut lines = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'));
        if lines.next() != Some(MAGIC) {
            return Err(RuntimeError::BadRequest);
        }
        let mut threshold = None;
        let mut approvers: Vec<[u8; 32]> = Vec::new();
        let mut denied: Vec<[u8; 32]> = Vec::new();
        for line in lines {
            let mut words = line.split_whitespace();
            match (words.next(), words.next(), words.next()) {
                (Some("threshold"), Some(n), None) if threshold.is_none() => {
                    threshold = Some(n.parse::<usize>().map_err(|_| RuntimeError::BadRequest)?);
                }
                (Some("approver"), Some(key), None) => {
                    let key = key_from_hex(key)?;
                    if approvers.contains(&key) || approvers.len() == MAX_APPROVERS {
                        return Err(RuntimeError::BadRequest);
                    }
                    approvers.push(key);
                }
                (Some("deny"), Some(digest), None) => {
                    let digest = key_from_hex(digest)?;
                    if denied.contains(&digest) || denied.len() == MAX_DENIED {
                        return Err(RuntimeError::BadRequest);
                    }
                    denied.push(digest);
                }
                _ => return Err(RuntimeError::BadRequest),
            }
        }
        let threshold = threshold.ok_or(RuntimeError::BadRequest)?;
        if threshold == 0 || threshold > approvers.len() {
            return Err(RuntimeError::BadRequest);
        }
        if threshold == 1 && !allow_single_approver {
            return Err(RuntimeError::BadRequest);
        }
        // Distinct by construction above, so a set only guards against future edits.
        debug_assert_eq!(
            approvers.iter().collect::<BTreeSet<_>>().len(),
            approvers.len()
        );
        Ok(Self {
            approvers,
            threshold,
            denied,
        })
    }

    /// Read a policy from a file the operator controls. On Unix the file must be a regular
    /// file, not a symbolic link, and not writable by group or others.
    pub fn load(path: &Path, allow_single_approver: bool) -> Result<Self, RuntimeError> {
        let before = fs::symlink_metadata(path).map_err(|_| RuntimeError::KeyFile)?;
        if !before.file_type().is_file() {
            return Err(RuntimeError::KeyFile);
        }
        let file = File::open(path).map_err(|_| RuntimeError::KeyFile)?;
        let meta = file.metadata().map_err(|_| RuntimeError::KeyFile)?;
        if !meta.is_file() || meta.len() > MAX_BYTES {
            return Err(RuntimeError::KeyFile);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.mode() & 0o022 != 0 || (meta.dev(), meta.ino()) != (before.dev(), before.ino())
            {
                return Err(RuntimeError::KeyFile);
            }
        }
        let mut text = String::new();
        file.take(MAX_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|_| RuntimeError::KeyFile)?;
        if text.len() as u64 > MAX_BYTES {
            return Err(RuntimeError::KeyFile);
        }
        Self::parse(&text, allow_single_approver)
    }

    /// The trusted approver keys.
    pub fn approvers(&self) -> &[[u8; 32]] {
        &self.approvers
    }

    /// Model digests the operator has blocked, whatever any approval says.
    pub fn denied(&self) -> &[[u8; 32]] {
        &self.denied
    }

    /// True when the operator has blocked this model digest.
    pub fn denies(&self, model_digest: &[u8; 32]) -> bool {
        self.denied.contains(model_digest)
    }

    /// How many distinct approvers must sign the same approval.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// An empty catalog that applies this policy.
    pub fn catalog(&self) -> Result<ModelCatalog, RuntimeError> {
        Ok(ModelCatalog::with_threshold(
            self.approvers.clone(),
            self.threshold,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    fn policy(threshold: usize, approvers: &[u8]) -> String {
        let mut out = format!("{MAGIC}\nthreshold {threshold}\n");
        for a in approvers {
            out.push_str(&format!("approver {}\n", key(*a)));
        }
        out
    }

    #[test]
    fn a_well_formed_policy_parses() {
        let parsed = TrustPolicy::parse(&policy(2, &[1, 2, 3]), false).unwrap();
        assert_eq!(parsed.threshold(), 2);
        assert_eq!(parsed.approvers().len(), 3);
        assert_eq!(parsed.approvers()[0], [1u8; 32]);
        let with_comments = format!("# who we trust\n\n{}", policy(2, &[1, 2]));
        assert!(TrustPolicy::parse(&with_comments, false).is_ok());
        assert!(parsed.catalog().is_ok());
    }

    #[test]
    fn a_malformed_policy_is_refused() {
        let many: Vec<u8> = (1..=65).collect();
        let bad: Vec<(&str, String)> = vec![
            ("empty", String::new()),
            ("wrong magic", policy(2, &[1, 2]).replace("v1", "v2")),
            ("no magic", "threshold 2\n".to_string()),
            ("repeated approver", policy(2, &[1, 1])),
            ("threshold zero", policy(0, &[1, 2])),
            ("threshold over count", policy(3, &[1, 2])),
            (
                "no threshold",
                format!("{MAGIC}\napprover {}\napprover {}\n", key(1), key(2)),
            ),
            (
                "two thresholds",
                format!("{}threshold 1\n", policy(2, &[1, 2])),
            ),
            ("no approvers", format!("{MAGIC}\nthreshold 1\n")),
            ("65 approvers", policy(2, &many)),
            (
                "short key",
                format!("{MAGIC}\nthreshold 2\napprover abcd\napprover {}\n", key(2)),
            ),
            (
                "non hex key",
                format!(
                    "{MAGIC}\nthreshold 2\napprover {}\napprover {}\n",
                    "zz".repeat(32),
                    key(2)
                ),
            ),
            (
                "unknown line",
                format!("{}extra thing\n", policy(2, &[1, 2])),
            ),
            (
                "approver with a trailing word",
                format!(
                    "{MAGIC}\nthreshold 2\napprover {} x\napprover {}\n",
                    key(1),
                    key(2)
                ),
            ),
            (
                "negative threshold",
                policy(2, &[1, 2]).replace("threshold 2", "threshold -1"),
            ),
        ];
        for (name, text) in bad {
            assert_eq!(
                TrustPolicy::parse(&text, true),
                Err(RuntimeError::BadRequest),
                "{name}"
            );
        }
    }

    #[test]
    fn deny_lines_are_read_and_a_bad_one_is_refused() {
        let text = format!("{}deny {}\ndeny {}\n", policy(2, &[1, 2]), key(7), key(8));
        let parsed = TrustPolicy::parse(&text, false).unwrap();
        assert_eq!(parsed.denied(), &[[7u8; 32], [8u8; 32]]);
        assert!(parsed.denies(&[7u8; 32]));
        assert!(!parsed.denies(&[9u8; 32]));
        assert!(TrustPolicy::parse(&policy(2, &[1, 2]), false)
            .unwrap()
            .denied()
            .is_empty());
        let repeated = format!("{}deny {}\ndeny {}\n", policy(2, &[1, 2]), key(7), key(7));
        let short = format!("{}deny abcd\n", policy(2, &[1, 2]));
        let trailing = format!("{}deny {} x\n", policy(2, &[1, 2]), key(7));
        let mut many = policy(2, &[1, 2]);
        for i in 0..=1_024u32 {
            many.push_str(&format!("deny {:064x}\n", i + 1));
        }
        for bad in [repeated, short, trailing, many] {
            assert_eq!(
                TrustPolicy::parse(&bad, false),
                Err(RuntimeError::BadRequest)
            );
        }
    }

    #[test]
    fn a_single_approver_needs_the_explicit_flag() {
        let single = policy(1, &[1]);
        assert_eq!(
            TrustPolicy::parse(&single, false),
            Err(RuntimeError::BadRequest)
        );
        assert!(TrustPolicy::parse(&single, true).is_ok());
        assert_eq!(
            TrustPolicy::parse(&policy(1, &[1, 2]), false),
            Err(RuntimeError::BadRequest),
            "one of two is still one approver"
        );
    }

    #[cfg(unix)]
    mod files {
        use std::os::unix::fs::{symlink, PermissionsExt};

        use super::*;

        fn dir() -> std::path::PathBuf {
            use rand::RngCore;
            let mut suffix = [0u8; 6];
            rand::rngs::OsRng.fill_bytes(&mut suffix);
            let path = std::env::temp_dir().join(format!(
                "suricomai-trust-{}",
                suffix
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ));
            fs::create_dir(&path).unwrap();
            path
        }

        fn write(dir: &Path, name: &str, text: &str, mode: u32) -> std::path::PathBuf {
            let path = dir.join(name);
            fs::write(&path, text).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path
        }

        #[test]
        fn a_private_regular_file_loads() {
            let dir = dir();
            let path = write(&dir, "trust", &policy(2, &[1, 2]), 0o600);
            assert_eq!(TrustPolicy::load(&path, false).unwrap().threshold(), 2);
            let readable = write(&dir, "trust-r", &policy(2, &[1, 2]), 0o644);
            assert!(TrustPolicy::load(&readable, false).is_ok());
            fs::remove_dir_all(dir).unwrap();
        }

        #[test]
        fn a_writable_by_others_oversize_link_or_directory_is_refused() {
            let dir = dir();
            for mode in [0o620, 0o602, 0o660, 0o666] {
                let path = write(&dir, "w", &policy(2, &[1, 2]), mode);
                assert_eq!(
                    TrustPolicy::load(&path, false),
                    Err(RuntimeError::KeyFile),
                    "{mode:o}"
                );
            }
            let big = write(
                &dir,
                "big",
                &format!("{}\n{}", policy(2, &[1, 2]), "#".repeat(9_000)),
                0o600,
            );
            assert_eq!(TrustPolicy::load(&big, false), Err(RuntimeError::KeyFile));
            let real = write(&dir, "real", &policy(2, &[1, 2]), 0o600);
            let link = dir.join("link");
            symlink(&real, &link).unwrap();
            assert_eq!(TrustPolicy::load(&link, false), Err(RuntimeError::KeyFile));
            assert_eq!(TrustPolicy::load(&dir, false), Err(RuntimeError::KeyFile));
            assert_eq!(
                TrustPolicy::load(&dir.join("missing"), false),
                Err(RuntimeError::KeyFile)
            );
            fs::remove_dir_all(dir).unwrap();
        }
    }
}
