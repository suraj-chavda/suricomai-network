// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::error::AttestError;

/// Everything an independent verifier needs, as bytes. It carries no prompt and no answer.
#[derive(Clone, Debug)]
pub struct AuditRequest {
    /// Canonical contract bytes.
    pub contract: Vec<u8>,
    /// Canonical sealed result bytes.
    pub result: Vec<u8>,
    /// Allowlisted measurements.
    pub allow: Vec<[u8; 32]>,
    /// True for a private (P2) job, which needs a quote check.
    pub private_tier: bool,
    /// The attestor's clock.
    pub audit_now: u64,
    /// Assigned worker's executor id.
    pub target_executor_id: [u8; 32],
    /// Assigned worker's receipt key.
    pub target_receipt_public: [u8; 32],
}

/// A second, independently written verifier. It answers `"ok"` or the same snake-case error
/// code the envelope uses. An attestor signs only when this and the envelope auditor agree.
pub trait SecondVerifier {
    /// Check the request and return `"ok"` or an error code.
    fn verify(&self, request: &AuditRequest) -> Result<String, AttestError>;
}

/// Runs `verifiers/python/audit_proof.py --one` in a separate process.
pub struct PythonVerifier {
    /// Python interpreter to run.
    pub python: PathBuf,
    /// Path to `audit_proof.py`.
    pub script: PathBuf,
    /// Lab quote root, needed only for private jobs on a development build.
    pub lab_public: Option<[u8; 32]>,
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

impl PythonVerifier {
    fn request_json(&self, request: &AuditRequest) -> String {
        let allow: Vec<String> = request
            .allow
            .iter()
            .map(|id| format!("\"{}\"", hex(id)))
            .collect();
        let lab = self.lab_public.map(|key| hex(&key)).unwrap_or_default();
        format!(
            "{{\"contract\":\"{}\",\"result\":\"{}\",\"allow\":[{}],\"mode\":\"{}\",\"lab_public\":\"{}\",\"audit_now\":{},\"target_executor_id\":\"{}\",\"target_receipt_public\":\"{}\"}}",
            hex(&request.contract),
            hex(&request.result),
            allow.join(","),
            if request.private_tier { "quote" } else { "signature" },
            lab,
            request.audit_now,
            hex(&request.target_executor_id),
            hex(&request.target_receipt_public),
        )
    }
}

impl SecondVerifier for PythonVerifier {
    fn verify(&self, request: &AuditRequest) -> Result<String, AttestError> {
        let mut child = Command::new(&self.python)
            .arg("-I")
            .arg(&self.script)
            .arg("--one")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|err| AttestError::Verifier(err.to_string()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| AttestError::Verifier("no stdin".to_string()))?
            .write_all(self.request_json(request).as_bytes())
            .map_err(|err| AttestError::Verifier(err.to_string()))?;
        let output = child
            .wait_with_output()
            .map_err(|err| AttestError::Verifier(err.to_string()))?;
        if !output.status.success() {
            return Err(AttestError::Verifier(
                "verifier exited with an error".to_string(),
            ));
        }
        let text = String::from_utf8(output.stdout)
            .map_err(|_| AttestError::Verifier("unreadable answer".to_string()))?;
        let code = text.trim();
        if code.is_empty()
            || code.len() > 64
            || !code.chars().all(|c| c.is_ascii_lowercase() || c == '_')
        {
            return Err(AttestError::Verifier("unreadable answer".to_string()));
        }
        Ok(code.to_string())
    }
}
