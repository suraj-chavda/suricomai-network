// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Development fixtures: a tiny random-weight model in the real GGUF and tokenizer formats.
//!
//! The weights are noise, so the answers are meaningless. The files are real: they go through
//! the same loader, digest checks and inference code as any other model. This module exists so
//! tests and the publishing walkthrough can run the whole flow without downloading weights.

use std::fs;
use std::path::Path;

use candle_core::quantized::gguf_file::{write, Value};
use candle_core::quantized::{GgmlDType, QTensor};
use candle_core::{Device, Tensor};

const EMBD: usize = 16;
const HEADS: usize = 2;
const FFN: usize = 32;
const VOCAB: usize = 32;

/// The bytes of a fixture model.
pub struct FixtureModel {
    /// A GGUF file of the llama architecture.
    pub weights: Vec<u8>,
    /// A tokenizer file in the `tokenizers` JSON format.
    pub tokenizer: Vec<u8>,
}

fn noise(seed: u8, label: &str, len: usize) -> Vec<f32> {
    let mut hasher = blake3::Hasher::new_derive_key("suricomai.fixture.v1");
    hasher.update(&[seed]);
    hasher.update(label.as_bytes());
    let mut reader = hasher.finalize_xof();
    let mut bytes = vec![0u8; len];
    reader.fill(&mut bytes);
    bytes
        .iter()
        .map(|b| (f32::from(*b) - 127.5) / 640.0)
        .collect()
}

fn tensor(seed: u8, label: &str, shape: &[usize]) -> QTensor {
    let len: usize = shape.iter().product();
    let t = Tensor::from_vec(noise(seed, label, len), shape.to_vec(), &Device::Cpu).unwrap();
    QTensor::quantize(&t, GgmlDType::F32).unwrap()
}

fn ones(shape: &[usize]) -> QTensor {
    let len: usize = shape.iter().product();
    let t = Tensor::from_vec(vec![1.0f32; len], shape.to_vec(), &Device::Cpu).unwrap();
    QTensor::quantize(&t, GgmlDType::F32).unwrap()
}

/// Build a fixture model. Different `seed` values give different weights and so different digests.
pub fn fixture_model(seed: u8) -> FixtureModel {
    let u32v = |n: usize| Value::U32(u32::try_from(n).unwrap());
    let metadata = [
        ("general.architecture", Value::String("llama".to_string())),
        ("llama.attention.head_count", u32v(HEADS)),
        ("llama.attention.head_count_kv", u32v(HEADS)),
        ("llama.block_count", u32v(1)),
        ("llama.embedding_length", u32v(EMBD)),
        ("llama.feed_forward_length", u32v(FFN)),
        ("llama.rope.dimension_count", u32v(EMBD / HEADS)),
        ("llama.attention.layer_norm_rms_epsilon", Value::F32(1e-5)),
        ("llama.rope.freq_base", Value::F32(10_000.0)),
    ];
    let named: Vec<(String, QTensor)> = vec![
        (
            "token_embd.weight".into(),
            tensor(seed, "embd", &[VOCAB, EMBD]),
        ),
        ("output_norm.weight".into(), ones(&[EMBD])),
        ("output.weight".into(), tensor(seed, "out", &[VOCAB, EMBD])),
        ("blk.0.attn_norm.weight".into(), ones(&[EMBD])),
        ("blk.0.ffn_norm.weight".into(), ones(&[EMBD])),
        (
            "blk.0.attn_q.weight".into(),
            tensor(seed, "q", &[EMBD, EMBD]),
        ),
        (
            "blk.0.attn_k.weight".into(),
            tensor(seed, "k", &[EMBD, EMBD]),
        ),
        (
            "blk.0.attn_v.weight".into(),
            tensor(seed, "v", &[EMBD, EMBD]),
        ),
        (
            "blk.0.attn_output.weight".into(),
            tensor(seed, "o", &[EMBD, EMBD]),
        ),
        (
            "blk.0.ffn_gate.weight".into(),
            tensor(seed, "g", &[FFN, EMBD]),
        ),
        (
            "blk.0.ffn_up.weight".into(),
            tensor(seed, "u", &[FFN, EMBD]),
        ),
        (
            "blk.0.ffn_down.weight".into(),
            tensor(seed, "d", &[EMBD, FFN]),
        ),
    ];
    let meta_refs: Vec<(&str, &Value)> = metadata.iter().map(|(k, v)| (*k, v)).collect();
    let tensor_refs: Vec<(&str, &QTensor)> = named.iter().map(|(k, v)| (k.as_str(), v)).collect();
    let mut weights = std::io::Cursor::new(Vec::new());
    write(&mut weights, &meta_refs, &tensor_refs).unwrap();

    let mut vocab = String::from("\"<unk>\":0");
    for i in 1..VOCAB {
        vocab.push_str(&format!(",\"w{i}\":{i}"));
    }
    let tokenizer = format!(
        "{{\"version\":\"1.0\",\"truncation\":null,\"padding\":null,\"added_tokens\":[],\
         \"normalizer\":null,\"pre_tokenizer\":{{\"type\":\"WhitespaceSplit\"}},\
         \"post_processor\":null,\"decoder\":null,\
         \"model\":{{\"type\":\"WordLevel\",\"vocab\":{{{vocab}}},\"unk_token\":\"<unk>\"}}}}"
    );
    FixtureModel {
        weights: weights.into_inner(),
        tokenizer: tokenizer.into_bytes(),
    }
}

/// Write a fixture's files into `dir` under the names a node expects for `model_id`.
pub fn write_model_files(dir: &Path, model_id: &str, model: &FixtureModel) {
    fs::write(dir.join(format!("{model_id}.gguf")), &model.weights).unwrap();
    fs::write(
        dir.join(format!("{model_id}.tokenizer.json")),
        &model.tokenizer,
    )
    .unwrap();
}

#[cfg(test)]
mod tests {
    use suricomai_envelope::InferenceParams;

    use super::*;
    use crate::chat::{pack_messages, ChatMessage};
    use crate::text_model::Engine;

    #[test]
    fn a_fixture_model_loads_through_the_real_loader_and_answers() {
        let model = fixture_model(1);
        let mut engine = Engine::from_verified(&model.weights, &model.tokenizer).unwrap();
        let prompt = pack_messages(&[ChatMessage {
            role: "user".into(),
            content: "w3 w4 w5".into(),
        }])
        .unwrap();
        let params = InferenceParams::new([1u8; 32], 0, 8).unwrap();
        let first = engine.answer(&prompt, &params, 64).unwrap();
        let again = engine.answer(&prompt, &params, 64).unwrap();
        assert!(!first.0.is_empty());
        assert_eq!(
            first, again,
            "a second job on the same engine matches the first"
        );
    }

    #[test]
    fn different_seeds_make_different_models() {
        let a = fixture_model(1);
        let b = fixture_model(2);
        assert_ne!(a.weights, b.weights);
        assert_eq!(a.tokenizer, b.tokenizer);
        assert_eq!(
            fixture_model(1).weights,
            a.weights,
            "the same seed gives the same bytes"
        );
    }

    #[test]
    fn bytes_that_are_not_a_model_are_refused_without_a_panic() {
        let model = fixture_model(1);
        for bad in [
            Vec::new(),
            vec![0u8; 100],
            model.weights[..model.weights.len() / 2].to_vec(),
        ] {
            assert!(Engine::from_verified(&bad, &model.tokenizer).is_err());
        }
        assert!(Engine::from_verified(&model.weights, b"not a tokenizer").is_err());
        assert!(Engine::from_verified(&model.weights, b"").is_err());
    }
}
