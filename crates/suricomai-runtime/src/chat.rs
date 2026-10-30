// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! OpenAI-shaped chat call.
//!
//! Messages are packed into the prompt on the client. The executor receives a sealed
//! job, not this JSON. The only privacy label the response can carry is lab-untrusted.

use std::fmt;

use rand::rngs::OsRng;
use rand::RngCore;
use suricomai_envelope::{valid_size_class, EnvelopeError, InferenceParams};

use crate::client::{Client, Completion};
use crate::error::RuntimeError;
use crate::model::MODEL_NAME;
use crate::node::NodeCard;

/// One chat turn. Debug output redacts `content`.
#[derive(Clone)]
pub struct ChatMessage {
    /// `system`, `user`, or `assistant`.
    pub role: String,
    /// Turn text. Packed into the sealed prompt. Not a protocol message.
    pub content: String,
}

impl fmt::Debug for ChatMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChatMessage")
            .field("role", &self.role)
            .field("content", &"redacted")
            .finish()
    }
}

/// Local chat request. `model` must be [`MODEL_NAME`].
pub struct ChatRequest {
    /// Must be `suricomai-tiny-v1`.
    pub model: String,
    /// Conversation, in order.
    pub messages: Vec<ChatMessage>,
    /// OpenAI temperature, `0.0..=2.0`. `None` means `0`.
    pub temperature: Option<f64>,
    /// Answer cap in model bytes. `None` means 16. Maximum is 256.
    pub max_tokens: Option<u64>,
}

impl fmt::Debug for ChatRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChatRequest")
            .field("model", &self.model)
            .field("messages", &self.messages.len())
            .field("content", &"redacted")
            .finish()
    }
}

/// Chat response. `privacy` is always lab-untrusted. `hardware_p2` is always false.
/// Debug output redacts the assistant text.
pub struct ChatCompletion {
    /// Completion id. It is not the prompt.
    pub id: String,
    /// `chat.completion`.
    pub object: &'static str,
    /// Pinned model name.
    pub model: &'static str,
    /// Assistant text. The tiny model emits bytes, so this is lowercase hex.
    pub content: String,
    /// Always lab-untrusted.
    pub privacy: &'static str,
    /// Always false in this crate.
    pub hardware_p2: bool,
    /// Proof byte length. The proof itself stays on [`Completion`].
    pub proof_bytes: usize,
    /// Underlying sealed completion, answer redacted in debug.
    pub completion: Completion,
}

impl fmt::Debug for ChatCompletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChatCompletion")
            .field("id", &self.id)
            .field("privacy", &self.privacy)
            .field("hardware_p2", &self.hardware_p2)
            .field("content", &"redacted")
            .finish()
    }
}

impl Client {
    /// Pack `request` into a sealed job, exchange it, and return a chat completion.
    ///
    /// `exchange` is given the sealed job only. A wrong model name fails before that call.
    pub fn chat(
        &self,
        card: &NodeCard,
        request: &ChatRequest,
        now: u64,
        exchange: impl FnOnce(&[u8]) -> Result<Vec<u8>, RuntimeError>,
    ) -> Result<ChatCompletion, RuntimeError> {
        if request.model != MODEL_NAME {
            return Err(RuntimeError::ModelMismatch);
        }
        if request.messages.is_empty() {
            return Err(RuntimeError::BadRequest);
        }
        let prompt = pack_messages(&request.messages)?;
        let temperature = temperature_millis(request.temperature.unwrap_or(0.0))?;
        let max_tokens = request.max_tokens.unwrap_or(16);
        if max_tokens == 0 || max_tokens > 256 {
            return Err(RuntimeError::BadRequest);
        }
        let need = (prompt.len() as u64)
            .saturating_add(4)
            .max(max_tokens.saturating_add(4));
        let size_class = choose_size_class(need)?;
        let mut job_id = [0u8; 32];
        OsRng.fill_bytes(&mut job_id);
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let job = crate::client::JobRequest {
            job_id,
            chain_id: 7,
            prompt,
            params: InferenceParams::new(seed, temperature, max_tokens)?,
            now,
            expiry: now.saturating_add(120),
            fee: 1,
            bond_required: 1,
            max_output_bytes: max_tokens,
            size_class,
            max_latency_ms: 0,
            user_pay_key: [0u8; 32],
        };
        let completion = self.complete(card, &job, exchange)?;
        let proof_bytes = completion.proof.to_bytes()?.len();
        let id = format!("chatcmpl-{}", hex_prefix(&job_id));
        let content = hex_encode(&completion.answer);
        Ok(ChatCompletion {
            id,
            object: "chat.completion",
            model: MODEL_NAME,
            content,
            privacy: "lab-untrusted",
            hardware_p2: false,
            proof_bytes,
            completion,
        })
    }
}

/// Pack one user message the way a hosted model expects its prompt.
pub fn pack_user_prompt(text: &str) -> Result<Vec<u8>, RuntimeError> {
    pack_messages(&[ChatMessage {
        role: "user".to_string(),
        content: text.to_string(),
    }])
}

pub(crate) fn pack_messages(messages: &[ChatMessage]) -> Result<Vec<u8>, RuntimeError> {
    let mut out = Vec::new();
    for message in messages {
        let tag = match message.role.as_str() {
            "system" => 1u8,
            "user" => 2,
            "assistant" => 3,
            _ => return Err(RuntimeError::BadRequest),
        };
        let bytes = message.content.as_bytes();
        let len = u32::try_from(bytes.len()).map_err(|_| RuntimeError::BadRequest)?;
        out.push(tag);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
    }
    Ok(out)
}

pub(crate) fn unpack_messages(bytes: &[u8]) -> Result<Vec<ChatMessage>, RuntimeError> {
    let mut messages = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let tag = *bytes.get(index).ok_or(RuntimeError::BadRequest)?;
        index += 1;
        let len_bytes: [u8; 4] = bytes
            .get(index..index + 4)
            .ok_or(RuntimeError::BadRequest)?
            .try_into()
            .map_err(|_| RuntimeError::BadRequest)?;
        index += 4;
        let len = u32::from_be_bytes(len_bytes) as usize;
        let content = bytes
            .get(index..index + len)
            .ok_or(RuntimeError::BadRequest)?;
        index += len;
        let role = match tag {
            1 => "system",
            2 => "user",
            3 => "assistant",
            _ => return Err(RuntimeError::BadRequest),
        };
        let content = std::str::from_utf8(content).map_err(|_| RuntimeError::BadRequest)?;
        messages.push(ChatMessage {
            role: role.to_string(),
            content: content.to_string(),
        });
    }
    if messages.is_empty() {
        return Err(RuntimeError::BadRequest);
    }
    Ok(messages)
}

pub(crate) fn temperature_millis(temperature: f64) -> Result<u64, RuntimeError> {
    if !temperature.is_finite() || !(0.0..=2.0).contains(&temperature) {
        return Err(RuntimeError::BadRequest);
    }
    Ok((temperature * 1000.0).round() as u64)
}

pub(crate) fn choose_size_class(need: u64) -> Result<u64, RuntimeError> {
    const CLASSES: [u64; 8] = [
        4_096, 16_384, 65_536, 262_144, 524_288, 1_048_576, 2_097_152, 4_194_304,
    ];
    CLASSES
        .into_iter()
        .find(|class| *class >= need && valid_size_class(*class))
        .ok_or(RuntimeError::Envelope(EnvelopeError::PlaintextTooLarge))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn hex_prefix(bytes: &[u8; 32]) -> String {
    hex_encode(&bytes[..8])
}
