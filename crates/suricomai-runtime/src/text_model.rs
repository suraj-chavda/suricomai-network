// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Local SmolLM2 instruct model.
//!
//! The weights are a pinned GGUF file. This process decrypts the prompt to run
//! them, so a job that selects this model is not private. The built-in test model stays
//! available when this file is absent.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use candle_core::{Device, Tensor};
use candle_transformers::generation::{LogitsProcessor, Sampling};
use candle_transformers::models::quantized_llama::ModelWeights;
use suricomai_envelope::InferenceParams;
use tokenizers::Tokenizer;

use crate::chat::{unpack_messages, ChatMessage};
use crate::error::RuntimeError;

/// Name the client sends when the user picks the text model.
pub const TEXT_MODEL_NAME: &str = "smollm2-135m-instruct";

const WEIGHTS_FILE: &str = "SmolLM2-135M-Instruct-Q4_K_M.gguf";

/// A loaded model: weights in memory, its tokenizer, and the tokens that end an answer.
pub(crate) struct Engine {
    model: ModelWeights,
    tokenizer: Tokenizer,
    device: Device,
    eos: Vec<u32>,
}

/// Digest of the installed weights, or `None` when the file is absent.
pub fn installed_digest() -> Option<[u8; 32]> {
    static CACHED: OnceLock<Option<[u8; 32]>> = OnceLock::new();
    *CACHED.get_or_init(|| file_digest(&weights_path()).ok())
}

/// Digest of the installed tokenizer file, or `None` when it is absent.
pub fn installed_tokenizer_digest() -> Option<[u8; 32]> {
    static CACHED: OnceLock<Option<[u8; 32]>> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::fs::read(tokenizer_path())
            .ok()
            .map(|bytes| crate::model::tokenizer_file_digest(&bytes))
    })
}

/// Run the text model on a packed chat prompt.
pub fn generate(
    prompt: &[u8],
    params: &InferenceParams,
    max_output: u64,
) -> Result<(Vec<u8>, u64), RuntimeError> {
    let messages = unpack_messages(prompt)?;
    let rendered = render_chat(&messages);
    let mut engine = Engine::load()?;
    engine.complete(&rendered, params, max_output)
}

fn weights_path() -> PathBuf {
    if let Ok(path) = std::env::var("SURICOMAI_TEXT_MODEL") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../models")
        .join(WEIGHTS_FILE)
}

fn tokenizer_path() -> PathBuf {
    if let Ok(path) = std::env::var("SURICOMAI_TOKENIZER") {
        return PathBuf::from(path);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../models/tokenizer.json")
}

fn file_digest(path: &Path) -> Result<[u8; 32], RuntimeError> {
    let mut file = File::open(path).map_err(|_| RuntimeError::ModelUnavailable)?;
    reader_digest(&mut file)
}

fn reader_digest<R: Read>(file: &mut R) -> Result<[u8; 32], RuntimeError> {
    let mut hasher = blake3::Hasher::new_derive_key("suricomai.model.v1");
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buf)
            .map_err(|_| RuntimeError::ModelUnavailable)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Hash the open handle and rewind it, so the bytes that were approved are the
/// bytes that get loaded. Hashing the same handle closes the gap in which a path
/// is swapped between the check and the load.
fn verify_open_weights<R: Read + Seek>(
    file: &mut R,
    approved: Option<[u8; 32]>,
) -> Result<(), RuntimeError> {
    let actual = reader_digest(file)?;
    if approved != Some(actual) {
        return Err(RuntimeError::ModelUnavailable);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| RuntimeError::ModelUnavailable)?;
    Ok(())
}

pub(crate) fn render_chat(messages: &[ChatMessage]) -> String {
    let mut out = String::from(
        "<|im_start|>system\nYou answer in plain sentences. You do not call tools.<|im_end|>\n",
    );
    for message in messages {
        let role = match message.role.as_str() {
            "system" => "system",
            "assistant" => "assistant",
            _ => "user",
        };
        out.push_str("<|im_start|>");
        out.push_str(role);
        out.push('\n');
        out.push_str(&message.content);
        out.push_str("<|im_end|>\n");
    }
    out.push_str("<|im_start|>assistant\n");
    out
}

impl Engine {
    /// Build an engine from bytes the caller already hashed and checked. Nothing is read from
    /// disk here, so a file swapped after the check cannot change what runs.
    pub(crate) fn from_verified(weights: &[u8], tokenizer: &[u8]) -> Result<Self, RuntimeError> {
        let mut cursor = std::io::Cursor::new(weights);
        let content = candle_core::quantized::gguf_file::Content::read(&mut cursor)
            .map_err(|_| RuntimeError::TextFailed)?;
        let device = Device::Cpu;
        let model = ModelWeights::from_gguf(content, &mut cursor, &device)
            .map_err(|_| RuntimeError::TextFailed)?;
        let tokenizer = Tokenizer::from_bytes(tokenizer).map_err(|_| RuntimeError::TextFailed)?;
        let vocab = tokenizer.get_vocab(true);
        let eos = ["<|im_end|>", "<|endoftext|>", "<|end_of_text|>"]
            .into_iter()
            .filter_map(|token| vocab.get(token).copied())
            .collect();
        Ok(Self {
            model,
            tokenizer,
            device,
            eos,
        })
    }

    /// Answer a packed chat prompt. The key-value cache restarts at position zero, so
    /// nothing from an earlier job carries into this one.
    pub(crate) fn answer(
        &mut self,
        prompt: &[u8],
        params: &InferenceParams,
        max_output: u64,
    ) -> Result<(Vec<u8>, u64), RuntimeError> {
        let messages = unpack_messages(prompt)?;
        self.complete(&render_chat(&messages), params, max_output)
    }

    fn load() -> Result<Self, RuntimeError> {
        let weights = weights_path();
        let tokens = tokenizer_path();
        if !weights.is_file() || !tokens.is_file() {
            return Err(RuntimeError::ModelUnavailable);
        }
        let mut file = File::open(&weights).map_err(|_| RuntimeError::TextFailed)?;
        verify_open_weights(&mut file, installed_digest())?;
        let content = candle_core::quantized::gguf_file::Content::read(&mut file)
            .map_err(|_| RuntimeError::TextFailed)?;
        let device = Device::Cpu;
        let model = ModelWeights::from_gguf(content, &mut file, &device)
            .map_err(|_| RuntimeError::TextFailed)?;
        let tokenizer = Tokenizer::from_file(&tokens).map_err(|_| RuntimeError::TextFailed)?;
        let vocab = tokenizer.get_vocab(true);
        let eos = ["<|im_end|>", "<|endoftext|>", "<|end_of_text|>"]
            .into_iter()
            .filter_map(|token| vocab.get(token).copied())
            .collect();
        Ok(Self {
            model,
            tokenizer,
            device,
            eos,
        })
    }

    fn complete(
        &mut self,
        rendered: &str,
        params: &InferenceParams,
        max_output: u64,
    ) -> Result<(Vec<u8>, u64), RuntimeError> {
        let encoding = self
            .tokenizer
            .encode(rendered, true)
            .map_err(|_| RuntimeError::TextFailed)?;
        let prompt_tokens = encoding.get_ids().to_vec();
        if prompt_tokens.is_empty() {
            return Err(RuntimeError::TextFailed);
        }
        let temperature = params.temperature_millis as f64 / 1000.0;
        let sampling = if temperature <= 0.0 {
            Sampling::ArgMax
        } else {
            Sampling::All { temperature }
        };
        let seed = u64::from_le_bytes(params.seed[..8].try_into().unwrap_or([0; 8]));
        let mut processor = LogitsProcessor::from_sampling(seed, sampling);
        let input = Tensor::new(prompt_tokens.as_slice(), &self.device)
            .and_then(|tensor| tensor.unsqueeze(0))
            .map_err(|_| RuntimeError::TextFailed)?;
        let logits = self
            .model
            .forward(&input, 0)
            .and_then(|logits| logits.squeeze(0))
            .map_err(|_| RuntimeError::TextFailed)?;
        let mut next = processor
            .sample(&logits)
            .map_err(|_| RuntimeError::TextFailed)?;
        let limit = (params.max_tokens as usize).clamp(1, 256);
        let mut generated = Vec::new();
        for index in 0..limit {
            if self.eos.contains(&next) {
                break;
            }
            generated.push(next);
            if index + 1 == limit {
                break;
            }
            let input = Tensor::new(&[next], &self.device)
                .and_then(|tensor| tensor.unsqueeze(0))
                .map_err(|_| RuntimeError::TextFailed)?;
            let logits = self
                .model
                .forward(&input, prompt_tokens.len() + index)
                .and_then(|logits| logits.squeeze(0))
                .map_err(|_| RuntimeError::TextFailed)?;
            next = processor
                .sample(&logits)
                .map_err(|_| RuntimeError::TextFailed)?;
        }
        if generated.is_empty() {
            return Err(RuntimeError::TextFailed);
        }
        let text = self
            .tokenizer
            .decode(&generated, true)
            .map_err(|_| RuntimeError::TextFailed)?;
        let text = text
            .trim()
            .trim_end_matches("<|im_end|>")
            .trim()
            .to_string();
        let mut bytes = text.into_bytes();
        if bytes.len() as u64 > max_output {
            bytes.truncate(max_output as usize);
            while std::str::from_utf8(&bytes).is_err() {
                bytes.pop();
            }
        }
        if bytes.is_empty() {
            return Err(RuntimeError::TextFailed);
        }
        let tokens = u64::try_from(generated.len()).unwrap_or(u64::MAX);
        Ok((bytes, tokens))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn weights_that_differ_from_the_approved_digest_are_refused() {
        let approved = reader_digest(&mut Cursor::new(b"approved weights".to_vec())).unwrap();
        let mut swapped = Cursor::new(b"swapped weights".to_vec());
        assert!(matches!(
            verify_open_weights(&mut swapped, Some(approved)),
            Err(RuntimeError::ModelUnavailable)
        ));
    }

    #[test]
    fn weights_that_appear_after_startup_are_refused() {
        let mut late = Cursor::new(b"late weights".to_vec());
        assert!(matches!(
            verify_open_weights(&mut late, None),
            Err(RuntimeError::ModelUnavailable)
        ));
    }

    #[test]
    fn approved_weights_are_rewound_for_loading() {
        let bytes = b"approved weights".to_vec();
        let approved = reader_digest(&mut Cursor::new(bytes.clone())).unwrap();
        let mut file = Cursor::new(bytes);
        verify_open_weights(&mut file, Some(approved)).unwrap();
        assert_eq!(file.position(), 0);
    }
}
