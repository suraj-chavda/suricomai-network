// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Interactive session for one local lab executor.
//!
//! The typed line is sealed before the executor runs. The screen may show that
//! line, because the person typed it. The seal check looks for it in the ciphertext
//! and the host log.

use rand::rngs::OsRng;
use rand::RngCore;
use suricomai_envelope::InferenceParams;

use crate::chat::{choose_size_class, pack_messages, temperature_millis, ChatMessage, ChatRequest};
use crate::client::{Client, JobRequest};
use crate::error::RuntimeError;
use crate::model::MODEL_NAME;
use crate::node::{Executor, NodeCard};
use crate::text_model::TEXT_MODEL_NAME;

const MIN_NEEDLE: usize = 8;

/// One local chat. The executor and the client share this process.
pub struct Session {
    executor: Executor,
    client: Client,
    card: NodeCard,
    messages: Vec<ChatMessage>,
    lines: Vec<ViewLine>,
    temperature: f64,
    max_tokens: u64,
    last_proof: Option<ProofSummary>,
    text: bool,
    text_card: Option<NodeCard>,
}

/// Who a transcript row belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Text the person typed.
    You,
    /// Hex from the built-in test model.
    Assistant,
    /// Seal and proof line under an answer.
    Detail,
}

/// One row the screen can paint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewLine {
    /// Row kind.
    pub role: Role,
    /// Display text. A `You` row is the typed line.
    pub text: String,
}

/// Fields painted in the header on every turn.
#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    /// Always `lab-untrusted` from this executor.
    pub privacy: &'static str,
    /// Always false in this build.
    pub hardware_p2: bool,
    /// Pinned model name.
    pub model: &'static str,
    /// Sampling temperature sent with the next job.
    pub temperature: f64,
    /// Answer cap in bytes.
    pub max_tokens: u64,
    /// User turns accepted so far.
    pub turns: usize,
}

/// Last receipt, without the prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofSummary {
    /// Completion id.
    pub id: String,
    /// Proof size in bytes.
    pub bytes: usize,
    /// Padded token count from the receipt.
    pub token_bucket: u64,
    /// `finished_at - started_at` from the receipt, in whole seconds.
    pub elapsed_secs: u64,
    /// Privacy label copied from the completion.
    pub privacy: &'static str,
}

/// One accepted answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// Lowercase hex of the model bytes.
    pub content: String,
    /// Proof size.
    pub proof_bytes: usize,
    /// Sealed job size, before the executor opened it.
    pub sealed_bytes: usize,
    /// True when a typed line of at least 8 bytes was searched for.
    pub prompt_checked: bool,
    /// True when that text was found in the sealed job.
    pub prompt_in_seal: bool,
    /// True when that text was found in the host log.
    pub prompt_in_log: bool,
    /// Always `lab-untrusted` here.
    pub privacy: &'static str,
    /// Always false here.
    pub hardware_p2: bool,
}

/// What one input line did.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// Leave the program.
    Quit,
    /// Transcript cleared.
    Cleared,
    /// Help was requested.
    Help,
    /// Header values.
    Status(Header),
    /// Last proof, when one exists.
    Proof(ProofSummary),
    /// A job finished.
    Reply(Reply),
    /// A setting or a hint. This string is not a prompt.
    Note(String),
    /// A static failure code.
    Failed(&'static str),
}

impl Session {
    /// Start the lab executor and a client that trusts its measurement.
    pub fn start(now: u64) -> Result<Self, RuntimeError> {
        let executor = Executor::lab()?;
        let card = executor.card([9u8; 32], now)?;
        let text_card = executor.text_card([4u8; 32], now).ok();
        let client = Client::new(executor.verifier(), card.advertisement.executor_id)?;
        Ok(Self {
            executor,
            client,
            card,
            messages: Vec::new(),
            lines: Vec::new(),
            temperature: 0.0,
            max_tokens: 16,
            last_proof: None,
            text: false,
            text_card,
        })
    }

    /// Header values for the screen.
    pub fn header(&self) -> Header {
        let status = self.executor.status();
        Header {
            privacy: if self.text {
                "not-private"
            } else {
                status.quote_kind
            },
            hardware_p2: status.hardware_p2,
            model: if self.text {
                TEXT_MODEL_NAME
            } else {
                status.model_name
            },
            temperature: self.temperature,
            max_tokens: self.max_tokens,
            turns: self
                .messages
                .iter()
                .filter(|message| message.role == "user")
                .count(),
        }
    }

    /// Transcript rows, oldest first.
    pub fn lines(&self) -> &[ViewLine] {
        &self.lines
    }

    /// Issue new advertisements when the current ones are about to lapse, so a long
    /// session does not start failing the freshness check.
    fn refresh_cards(&mut self, now: u64) {
        const MARGIN: u64 = 60;
        if now.saturating_add(MARGIN) < self.card.advertisement.valid_until {
            return;
        }
        if let Ok(card) = self.executor.card([9u8; 32], now) {
            self.card = card;
        }
        if self.text_card.is_some() {
            self.text_card = self.executor.text_card([4u8; 32], now).ok();
        }
    }

    /// Handle one typed line. `now` is unix seconds.
    pub fn submit_line(&mut self, line: &str, now: u64) -> Outcome {
        self.refresh_cards(now);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Outcome::Note("Type a message, or /help.".to_string());
        }
        match parse(trimmed) {
            Action::Quit => Outcome::Quit,
            Action::Help => Outcome::Help,
            Action::Clear => {
                self.messages.clear();
                self.lines.clear();
                self.last_proof = None;
                Outcome::Cleared
            }
            Action::Status => Outcome::Status(self.header()),
            Action::Proof => self
                .last_proof
                .clone()
                .map(Outcome::Proof)
                .unwrap_or_else(|| {
                    Outcome::Note("No proof yet. Send a message first.".to_string())
                }),
            Action::Temp(value) => match value {
                Ok(temperature)
                    if temperature.is_finite() && (0.0..=2.0).contains(&temperature) =>
                {
                    self.temperature = temperature;
                    Outcome::Note(format!("Temperature set to {temperature}."))
                }
                _ => Outcome::Failed(RuntimeError::BadRequest.code()),
            },
            Action::Tokens(value) => match value {
                Ok(tokens) if (1..=256).contains(&tokens) => {
                    self.max_tokens = tokens;
                    Outcome::Note(format!("Max tokens set to {tokens}."))
                }
                _ => Outcome::Failed(RuntimeError::BadRequest.code()),
            },
            Action::Models => Outcome::Note(self.catalog_note(now)),
            Action::Use(name) => self.use_model(name, now),
            Action::Say(text) => {
                if self.text {
                    self.say_text(text, now)
                } else {
                    self.say(text, now)
                }
            }
            Action::Unknown => Outcome::Note("Unknown command. Try /help.".to_string()),
        }
    }

    /// One row per model the catalog knows, with where it stands today.
    fn catalog_note(&self, now: u64) -> String {
        let catalog = self.client.catalog();
        let mut rows: Vec<String> = catalog
            .entries()
            .iter()
            .map(|entry| {
                let manifest = &entry.manifest;
                let tier = if manifest.model_id == MODEL_NAME {
                    "lab-untrusted"
                } else {
                    "not-private"
                };
                format!(
                    "{}    {}, {}, {}M parameters, {}",
                    manifest.model_id,
                    standing_word(catalog.standing(&manifest.model_digest, now)),
                    tier,
                    manifest.params_millions,
                    manifest.license
                )
            })
            .collect();
        if self.text_card.is_none() {
            rows.push(format!("{TEXT_MODEL_NAME}    weights not installed"));
        }
        rows.join("\n")
    }

    fn use_model(&mut self, name: String, now: u64) -> Outcome {
        self.messages.clear();
        self.lines.clear();
        self.last_proof = None;
        if name == TEXT_MODEL_NAME && self.text_card.is_none() {
            self.text = false;
            return Outcome::Failed(RuntimeError::ModelUnavailable.code());
        }
        let catalog = self.client.catalog();
        let Some(entry) = catalog.by_id(&name) else {
            return Outcome::Note("Unknown model. Try /models.".to_string());
        };
        if let Err(err) = catalog.require_approved(&entry.manifest.model_digest, now) {
            return Outcome::Failed(err.code());
        }
        if name == MODEL_NAME {
            self.text = false;
            self.max_tokens = 16;
            return Outcome::Note(
                "Using suricomai-tiny-v1. The answer is hex. Privacy is lab-untrusted.".to_string(),
            );
        }
        if name == TEXT_MODEL_NAME {
            if self.text_card.is_none() {
                self.text = false;
                return Outcome::Failed(RuntimeError::ModelUnavailable.code());
            }
            self.text = true;
            if self.max_tokens < 32 {
                self.max_tokens = 64;
            }
            return Outcome::Note(
                "Using smollm2-135m-instruct. This computer can read the prompt. Privacy is not-private."
                    .to_string(),
            );
        }
        Outcome::Note("Unknown model. Try /models.".to_string())
    }

    fn say(&mut self, text: String, now: u64) -> Outcome {
        self.messages.push(ChatMessage {
            role: "user".to_string(),
            content: text.clone(),
        });
        let request = ChatRequest {
            model: MODEL_NAME.to_string(),
            messages: self.messages.clone(),
            temperature: Some(self.temperature),
            max_tokens: Some(self.max_tokens),
        };
        let mut sealed_bytes = 0;
        let mut prompt_in_seal = false;
        let result = {
            let executor = &mut self.executor;
            self.client.chat(&self.card, &request, now, |sealed| {
                sealed_bytes = sealed.len();
                prompt_in_seal = user_text(&request.messages).any(|text| found_in(sealed, text));
                executor.handle(sealed, now)
            })
        };
        let chat = match result {
            Ok(chat) => chat,
            Err(err) => {
                self.messages.pop();
                return Outcome::Failed(err.code());
            }
        };
        let log = self.executor.log().as_text();
        let prompt_in_log = user_text(&self.messages).any(|text| found_in(log.as_bytes(), text));
        let prompt_checked = user_text(&self.messages).any(|text| text.len() >= MIN_NEEDLE);
        self.messages.push(ChatMessage {
            role: "assistant".to_string(),
            content: chat.content.clone(),
        });
        self.last_proof = Some(ProofSummary {
            id: chat.id.clone(),
            bytes: chat.proof_bytes,
            token_bucket: chat.completion.proof.token_bucket,
            elapsed_secs: chat
                .completion
                .proof
                .finished_at
                .saturating_sub(chat.completion.proof.started_at),
            privacy: chat.privacy,
        });
        self.lines.push(ViewLine {
            role: Role::You,
            text,
        });
        self.lines.push(ViewLine {
            role: Role::Assistant,
            text: chat.content.clone(),
        });
        self.lines.push(ViewLine {
            role: Role::Detail,
            text: detail_line(
                chat.proof_bytes,
                sealed_bytes,
                chat.completion
                    .proof
                    .finished_at
                    .saturating_sub(chat.completion.proof.started_at),
                prompt_checked,
                prompt_in_seal,
                prompt_in_log,
            ),
        });
        Outcome::Reply(Reply {
            content: chat.content,
            proof_bytes: chat.proof_bytes,
            sealed_bytes,
            prompt_checked,
            prompt_in_seal,
            prompt_in_log,
            privacy: chat.privacy,
            hardware_p2: chat.hardware_p2,
        })
    }

    fn say_text(&mut self, text: String, now: u64) -> Outcome {
        let Some(card) = self.text_card.clone() else {
            return Outcome::Failed(RuntimeError::ModelUnavailable.code());
        };
        self.messages.push(ChatMessage {
            role: "user".to_string(),
            content: text.clone(),
        });
        let prompt = match pack_messages(&self.messages) {
            Ok(prompt) => prompt,
            Err(err) => {
                self.messages.pop();
                return Outcome::Failed(err.code());
            }
        };
        let temperature = match temperature_millis(self.temperature) {
            Ok(temperature) => temperature,
            Err(err) => {
                self.messages.pop();
                return Outcome::Failed(err.code());
            }
        };
        let need = (prompt.len() as u64).saturating_add(4).max(1_028);
        let size_class = match choose_size_class(need) {
            Ok(size_class) => size_class,
            Err(err) => {
                self.messages.pop();
                return Outcome::Failed(err.code());
            }
        };
        let mut job_id = [0u8; 32];
        OsRng.fill_bytes(&mut job_id);
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let request = match InferenceParams::new(seed, temperature, self.max_tokens) {
            Ok(params) => JobRequest {
                job_id,
                chain_id: 7,
                prompt,
                params,
                now,
                expiry: now.saturating_add(120),
                fee: 1,
                bond_required: 1,
                max_output_bytes: 1_024,
                size_class,
                max_latency_ms: 0,
                user_pay_key: [0u8; 32],
            },
            Err(err) => {
                self.messages.pop();
                return Outcome::Failed(RuntimeError::from(err).code());
            }
        };
        let needles: Vec<String> = user_text(&self.messages).map(str::to_string).collect();
        let mut sealed_bytes = 0;
        let mut prompt_in_seal = false;
        let result = {
            let executor = &mut self.executor;
            self.client.complete_transit(&card, &request, |sealed| {
                sealed_bytes = sealed.len();
                prompt_in_seal = needles.iter().any(|text| found_in(sealed, text));
                executor.handle(sealed, now)
            })
        };
        let completion = match result {
            Ok(completion) => completion,
            Err(err) => {
                self.messages.pop();
                return Outcome::Failed(err.code());
            }
        };
        let content = String::from_utf8_lossy(&completion.answer).into_owned();
        let log = self.executor.log().as_text();
        let prompt_in_log = user_text(&self.messages).any(|text| found_in(log.as_bytes(), text));
        let prompt_checked = user_text(&self.messages).any(|text| text.len() >= MIN_NEEDLE);
        let proof_bytes = completion
            .proof
            .to_bytes()
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        let elapsed_secs = completion
            .proof
            .finished_at
            .saturating_sub(completion.proof.started_at);
        self.messages.push(ChatMessage {
            role: "assistant".to_string(),
            content: content.clone(),
        });
        self.last_proof = Some(ProofSummary {
            id: format!("chatcmpl-{}", hex_id(&job_id)),
            bytes: proof_bytes,
            token_bucket: completion.proof.token_bucket,
            elapsed_secs,
            privacy: "not-private",
        });
        self.lines.push(ViewLine {
            role: Role::You,
            text,
        });
        self.lines.push(ViewLine {
            role: Role::Assistant,
            text: content.clone(),
        });
        self.lines.push(ViewLine {
            role: Role::Detail,
            text: detail_line(
                proof_bytes,
                sealed_bytes,
                elapsed_secs,
                prompt_checked,
                prompt_in_seal,
                prompt_in_log,
            ),
        });
        Outcome::Reply(Reply {
            content,
            proof_bytes,
            sealed_bytes,
            prompt_checked,
            prompt_in_seal,
            prompt_in_log,
            privacy: "not-private",
            hardware_p2: false,
        })
    }
}

fn hex_id(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(16);
    for byte in &bytes[..8] {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

enum Action {
    Quit,
    Help,
    Clear,
    Status,
    Proof,
    Temp(Result<f64, ()>),
    Tokens(Result<u64, ()>),
    Say(String),
    Models,
    Use(String),
    Unknown,
}

fn parse(line: &str) -> Action {
    if line == MODEL_NAME || line == TEXT_MODEL_NAME {
        return Action::Use(line.to_string());
    }
    if !line.starts_with('/') {
        return Action::Say(line.to_string());
    }
    let (command, rest) = line
        .split_once(|ch: char| ch.is_whitespace())
        .unwrap_or((line, ""));
    let rest = rest.trim();
    match command {
        "/quit" | "/exit" if rest.is_empty() => Action::Quit,
        "/help" if rest.is_empty() => Action::Help,
        "/clear" if rest.is_empty() => Action::Clear,
        "/status" if rest.is_empty() => Action::Status,
        "/proof" if rest.is_empty() => Action::Proof,
        "/temp" => Action::Temp(rest.parse::<f64>().map_err(|_| ())),
        "/tokens" => Action::Tokens(rest.parse::<u64>().map_err(|_| ())),
        "/models" if rest.is_empty() => Action::Models,
        "/model" if rest.is_empty() => Action::Models,
        "/model" => Action::Use(rest.to_string()),
        _ => Action::Unknown,
    }
}

fn user_text(messages: &[ChatMessage]) -> impl Iterator<Item = &str> {
    messages.iter().filter_map(|message| {
        if message.role == "user" {
            Some(message.content.as_str())
        } else {
            None
        }
    })
}

fn found_in(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes();
    needle.len() >= MIN_NEEDLE
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn detail_line(
    proof_bytes: usize,
    sealed_bytes: usize,
    elapsed_secs: u64,
    checked: bool,
    in_seal: bool,
    in_log: bool,
) -> String {
    let seal = if !checked {
        format!("sealed {sealed_bytes} bytes")
    } else if in_seal || in_log {
        "your text was found outside the seal".to_string()
    } else {
        format!("sealed {sealed_bytes} bytes, and your text was not in that ciphertext")
    };
    format!(
        "proof {proof_bytes} bytes · {} · {seal}",
        format_elapsed(elapsed_secs)
    )
}

/// One model the catalog knows, for a screen that lists them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelRow {
    /// The model's name in the catalog.
    pub id: String,
    /// `approved`, `approval expired`, `revoked`, `approval not started` or `unknown`.
    pub standing: &'static str,
    /// `lab-untrusted` for the built-in test model, `not-private` for a model that runs on
    /// this computer's own processor.
    pub privacy: &'static str,
    /// Model size in millions of parameters. Display only.
    pub params_millions: u64,
    /// The license the publisher named.
    pub license: String,
    /// The first 12 hex characters of the model digest. The full digest is the identity.
    pub digest_prefix: String,
    /// False when the weights are not on this computer, so the model cannot be used.
    pub installed: bool,
    /// True for the model the next message goes to.
    pub active: bool,
}

impl Session {
    /// One row per model the catalog knows, as data for a screen. The weights that are not
    /// installed are listed too, with `installed` false.
    pub fn model_rows(&self, now: u64) -> Vec<ModelRow> {
        let catalog = self.client.catalog();
        let mut rows: Vec<ModelRow> = catalog
            .entries()
            .iter()
            .map(|entry| {
                let manifest = &entry.manifest;
                let builtin = manifest.model_id == MODEL_NAME;
                ModelRow {
                    id: manifest.model_id.clone(),
                    standing: standing_word(catalog.standing(&manifest.model_digest, now)),
                    privacy: if builtin {
                        "lab-untrusted"
                    } else {
                        "not-private"
                    },
                    params_millions: manifest.params_millions,
                    license: manifest.license.clone(),
                    digest_prefix: manifest.model_digest[..6]
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                    installed: true,
                    active: if self.text {
                        manifest.model_id == TEXT_MODEL_NAME
                    } else {
                        builtin
                    },
                }
            })
            .collect();
        if self.text_card.is_none() {
            rows.push(ModelRow {
                id: TEXT_MODEL_NAME.to_string(),
                standing: "unknown",
                privacy: "not-private",
                params_millions: 135,
                license: "Apache-2.0".to_string(),
                digest_prefix: String::new(),
                installed: false,
                active: false,
            });
        }
        rows
    }

    /// Send `text` to the current model as a message. The text is never read as a command:
    /// `/quit` and `/clear` are ordinary words here. This is the entry point for a screen
    /// where a person types, because a typed line must not be able to change a setting.
    pub fn say_prompt(&mut self, text: &str, now: u64) -> Outcome {
        self.refresh_cards(now);
        if text.trim().is_empty() {
            return Outcome::Note("Type a message first.".to_string());
        }
        if self.text {
            self.say_text(text.to_string(), now)
        } else {
            self.say(text.to_string(), now)
        }
    }

    /// Choose the model the next message goes to. A different model starts a new chat.
    pub fn select_model(&mut self, name: &str, now: u64) -> Outcome {
        self.refresh_cards(now);
        self.use_model(name.to_string(), now)
    }

    /// Set the sampling temperature. `0.0` to `2.0`, finite.
    pub fn set_temperature(&mut self, temperature: f64) -> Result<(), RuntimeError> {
        if temperature.is_finite() && (0.0..=2.0).contains(&temperature) {
            self.temperature = temperature;
            Ok(())
        } else {
            Err(RuntimeError::BadRequest)
        }
    }

    /// Set the answer length cap. `1` to `256`.
    pub fn set_max_tokens(&mut self, tokens: u64) -> Result<(), RuntimeError> {
        if (1..=256).contains(&tokens) {
            self.max_tokens = tokens;
            Ok(())
        } else {
            Err(RuntimeError::BadRequest)
        }
    }

    /// Forget this chat.
    pub fn clear(&mut self) {
        self.messages.clear();
        self.lines.clear();
        self.last_proof = None;
    }

    /// The receipt of the last finished job, when there is one.
    pub fn last_proof(&self) -> Option<&ProofSummary> {
        self.last_proof.as_ref()
    }
}

/// Whole seconds from a receipt, as hours, minutes, and seconds.
pub fn format_elapsed(seconds: u64) -> String {
    if seconds == 0 {
        return "under 1 second".to_string();
    }
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let secs = seconds % 60;
    let mut parts = Vec::new();
    if hours > 0 {
        parts.push(unit(hours, "hour", "hours"));
    }
    if minutes > 0 {
        parts.push(unit(minutes, "minute", "minutes"));
    }
    if secs > 0 {
        parts.push(unit(secs, "second", "seconds"));
    }
    parts.join(" ")
}

fn unit(count: u64, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

fn standing_word(standing: suricomai_envelope::ModelStanding) -> &'static str {
    use suricomai_envelope::ModelStanding as S;
    match standing {
        S::Approved => "approved",
        S::Unknown => "unknown",
        S::Revoked => "revoked",
        S::Expired => "approval expired",
        S::NotYetValid => "approval not started",
    }
}
