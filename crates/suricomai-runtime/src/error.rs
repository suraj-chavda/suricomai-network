// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Runtime failures. Display text is a fixed code. Payloads from the wire are not stored.

use std::fmt;

use suricomai_envelope::EnvelopeError;

/// Why the local executor or client stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeError {
    /// The envelope refused the job. The inner value carries no plaintext.
    Envelope(EnvelopeError),
    /// The contract names a different model than the one this process loaded.
    ModelMismatch,
    /// This build has no confidential GPU or CPU and will not claim hardware P2.
    NotHardwareP2,
    /// The job asked for GPU evidence. This process cannot produce it.
    GpuNotConfidential,
    /// The socket framing was not a sealed job or a known error code.
    Wire,
    /// The chat request failed local checks. The message is not the prompt.
    BadRequest,
    /// The selected text model weights are not on this machine.
    ModelUnavailable,
    /// The text model failed without a prompt in the error.
    TextFailed,
    /// The node identity file is missing a safe form. Nothing was written or changed.
    KeyFile,
    /// A model pack or trust file was refused. Nothing was changed.
    Pack,
    /// No route reached the node, so no request byte was written. Safe to try another node.
    Unreachable,
    /// A quota or capacity bound was reached. Nothing was changed. Try again later.
    Busy,
}

impl RuntimeError {
    /// Stable code, safe to put in a host log or on the wire.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Envelope(err) => err.code(),
            Self::ModelMismatch => "model_mismatch",
            Self::NotHardwareP2 => "not_hardware_p2",
            Self::GpuNotConfidential => "gpu_not_confidential",
            Self::Wire => "wire",
            Self::BadRequest => "bad_request",
            Self::ModelUnavailable => "model_unavailable",
            Self::TextFailed => "text_failed",
            Self::KeyFile => "key_file",
            Self::Busy => "busy",
            Self::Unreachable => "unreachable",
            Self::Pack => "pack",
        }
    }

    pub(crate) fn from_remote_code(code: &str) -> Self {
        if let Some(err) = EnvelopeError::from_code(code) {
            return Self::Envelope(err);
        }
        match code {
            "model_mismatch" => Self::ModelMismatch,
            "not_hardware_p2" => Self::NotHardwareP2,
            "gpu_not_confidential" => Self::GpuNotConfidential,
            "wire" => Self::Wire,
            "bad_request" => Self::BadRequest,
            "model_unavailable" => Self::ModelUnavailable,
            "text_failed" => Self::TextFailed,
            "key_file" => Self::KeyFile,
            "busy" => Self::Busy,
            "unreachable" => Self::Unreachable,
            "pack" => Self::Pack,
            _ => Self::Wire,
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for RuntimeError {}

impl From<EnvelopeError> for RuntimeError {
    fn from(err: EnvelopeError) -> Self {
        Self::Envelope(err)
    }
}
