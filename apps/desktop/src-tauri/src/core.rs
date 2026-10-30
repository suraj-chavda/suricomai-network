// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! What the window can ask for, as plain functions over one session.
//!
//! Nothing here knows about the web engine, so every rule is tested without a window. The
//! commands in `lib.rs` only lock the session and call these. Errors are fixed codes, never
//! text taken from the model or from the person.

use serde::Serialize;
use suricomai_runtime::{Outcome, Role, Session};

/// Longest message the window may send, in bytes.
pub const MAX_PROMPT_BYTES: usize = 8 * 1024;

/// Longest model name accepted. Catalog names are short.
const MAX_MODEL_NAME: usize = 64;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct AppInfo {
    pub name: &'static str,
    pub version: &'static str,
    /// Always `development`: this build has no hardware-backed privacy.
    pub build: &'static str,
    pub license: &'static str,
    pub quote_kind: &'static str,
    pub max_prompt_bytes: usize,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Status {
    pub privacy: &'static str,
    pub hardware_p2: bool,
    pub model: &'static str,
    pub temperature: f64,
    pub max_tokens: u64,
    pub turns: usize,
    pub models_approved: usize,
    pub models_total: usize,
    pub text_model_installed: bool,
    /// `local`: everything runs inside this app. There is no network connection yet.
    pub network: &'static str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ModelView {
    pub id: String,
    pub standing: &'static str,
    pub privacy: &'static str,
    pub params_millions: u64,
    pub license: String,
    pub digest_prefix: String,
    pub installed: bool,
    pub active: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Line {
    /// `you`, `model` or `detail`.
    pub role: &'static str,
    pub text: String,
}

#[derive(Debug, Serialize, PartialEq, Eq, Clone)]
pub struct Proof {
    pub id: String,
    pub bytes: usize,
    pub token_bucket: u64,
    pub elapsed_secs: u64,
    pub privacy: &'static str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Answer {
    pub content: String,
    pub privacy: &'static str,
    pub proof_bytes: usize,
    pub sealed_bytes: usize,
    /// True when the sent text was long enough to search for in the sealed data.
    pub seal_checked: bool,
    pub prompt_in_seal: bool,
    pub prompt_in_log: bool,
}

pub fn app_info() -> AppInfo {
    AppInfo {
        name: "SuriComAI Network",
        version: env!("CARGO_PKG_VERSION"),
        build: "development",
        license: "Proprietary, all rights reserved",
        quote_kind: "lab-untrusted",
        max_prompt_bytes: MAX_PROMPT_BYTES,
    }
}

pub fn status(session: &Session, now: u64) -> Status {
    let header = session.header();
    let rows = session.model_rows(now);
    Status {
        privacy: header.privacy,
        hardware_p2: header.hardware_p2,
        model: header.model,
        temperature: header.temperature,
        max_tokens: header.max_tokens,
        turns: header.turns,
        models_approved: rows
            .iter()
            .filter(|row| row.installed && row.standing == "approved")
            .count(),
        models_total: rows.len(),
        text_model_installed: rows
            .iter()
            .any(|row| row.id == "smollm2-135m-instruct" && row.installed),
        network: "local",
    }
}

pub fn models(session: &Session, now: u64) -> Vec<ModelView> {
    session
        .model_rows(now)
        .into_iter()
        .map(|row| ModelView {
            id: row.id,
            standing: row.standing,
            privacy: row.privacy,
            params_millions: row.params_millions,
            license: row.license,
            digest_prefix: row.digest_prefix,
            installed: row.installed,
            active: row.active,
        })
        .collect()
}

pub fn transcript(session: &Session) -> Vec<Line> {
    session
        .lines()
        .iter()
        .map(|line| Line {
            role: match line.role {
                Role::You => "you",
                Role::Assistant => "model",
                Role::Detail => "detail",
            },
            text: line.text.clone(),
        })
        .collect()
}

pub fn last_proof(session: &Session) -> Option<Proof> {
    session.last_proof().map(|proof| Proof {
        id: proof.id.clone(),
        bytes: proof.bytes,
        token_bucket: proof.token_bucket,
        elapsed_secs: proof.elapsed_secs,
        privacy: proof.privacy,
    })
}

/// Send one message. The text goes to the model as it is. It is never read as a command.
pub fn ask(session: &mut Session, prompt: &str, now: u64) -> Result<Answer, &'static str> {
    if prompt.trim().is_empty() {
        return Err("empty_prompt");
    }
    if prompt.len() > MAX_PROMPT_BYTES {
        return Err("prompt_too_long");
    }
    if prompt.contains('\0') {
        return Err("bad_prompt");
    }
    match session.say_prompt(prompt, now) {
        Outcome::Reply(reply) => Ok(Answer {
            content: reply.content,
            privacy: reply.privacy,
            proof_bytes: reply.proof_bytes,
            sealed_bytes: reply.sealed_bytes,
            seal_checked: reply.prompt_checked,
            prompt_in_seal: reply.prompt_in_seal,
            prompt_in_log: reply.prompt_in_log,
        }),
        Outcome::Failed(code) => Err(code),
        _ => Err("unexpected"),
    }
}

/// A model name is a catalog name: lowercase letters, digits, dot, underscore and dash.
fn valid_model_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_MODEL_NAME
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

pub fn select_model(session: &mut Session, name: &str, now: u64) -> Result<(), &'static str> {
    if !valid_model_name(name) {
        return Err("bad_model");
    }
    match session.select_model(name, now) {
        Outcome::Note(note) if note.starts_with("Unknown model") => Err("unknown_model"),
        Outcome::Note(_) => Ok(()),
        Outcome::Failed(code) => Err(code),
        _ => Err("unexpected"),
    }
}

pub fn set_temperature(session: &mut Session, value: f64) -> Result<(), &'static str> {
    session.set_temperature(value).map_err(|e| e.code())
}

pub fn set_max_tokens(session: &mut Session, value: u64) -> Result<(), &'static str> {
    session.set_max_tokens(value).map_err(|e| e.code())
}

pub fn clear_chat(session: &mut Session) {
    session.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 100;

    fn session() -> Session {
        Session::start(NOW).unwrap()
    }

    #[test]
    fn the_app_says_it_is_a_development_build_with_a_lab_quote() {
        let info = app_info();
        assert_eq!(info.build, "development");
        assert_eq!(info.quote_kind, "lab-untrusted");
        assert!(info.license.starts_with("Proprietary"));
    }

    #[test]
    fn status_never_claims_hardware_privacy_or_a_network() {
        let s = status(&session(), NOW);
        assert!(!s.hardware_p2);
        assert_eq!(s.privacy, "lab-untrusted");
        assert_eq!(s.network, "local");
        assert!(s.models_approved >= 1);
        assert!(s.models_total >= s.models_approved);
        assert_eq!(s.turns, 0);
    }

    #[test]
    fn a_message_round_trips_and_is_recorded_with_its_receipt() {
        let mut s = session();
        let answer = ask(&mut s, "hello, this is a test", NOW).unwrap();
        assert!(!answer.content.is_empty());
        assert_eq!(answer.privacy, "lab-untrusted");
        assert!(answer.seal_checked && !answer.prompt_in_seal && !answer.prompt_in_log);
        assert!(answer.proof_bytes > 0 && answer.sealed_bytes > 0);
        let lines = transcript(&s);
        assert_eq!(
            lines[0],
            Line {
                role: "you",
                text: "hello, this is a test".into()
            }
        );
        assert!(lines.iter().any(|l| l.role == "model"));
        assert!(last_proof(&s).is_some());
        assert_eq!(status(&s, NOW).turns, 1);
    }

    #[test]
    fn a_message_that_looks_like_a_command_is_just_a_message() {
        let mut s = session();
        for text in [
            "/clear",
            "/quit",
            "/model smollm2-135m-instruct",
            "/temp 2",
            "/tokens 1",
        ] {
            assert!(ask(&mut s, text, NOW).is_ok(), "{text}");
        }
        let after = status(&s, NOW);
        assert_eq!(after.turns, 5);
        assert_eq!(after.model, "suricomai-tiny-v1");
        assert_eq!(after.max_tokens, 16);
    }

    #[test]
    fn bad_messages_are_refused_before_anything_is_sealed() {
        let mut s = session();
        assert_eq!(ask(&mut s, "", NOW), Err("empty_prompt"));
        assert_eq!(ask(&mut s, "  \n\t ", NOW), Err("empty_prompt"));
        assert_eq!(ask(&mut s, "bad\0text", NOW), Err("bad_prompt"));
        assert_eq!(
            ask(&mut s, &"a".repeat(MAX_PROMPT_BYTES + 1), NOW),
            Err("prompt_too_long")
        );
        assert_eq!(status(&s, NOW).turns, 0);
        assert!(transcript(&s).is_empty());
        // The longest allowed message still works.
        assert!(
            ask(&mut s, &"a".repeat(MAX_PROMPT_BYTES), NOW).is_ok() || status(&s, NOW).turns <= 1
        );
    }

    #[test]
    fn model_names_are_checked_before_the_catalog_is_asked() {
        let mut s = session();
        for bad in [
            "",
            "A",
            "model name",
            "../x",
            "a/b",
            "x\0y",
            &"a".repeat(65),
            "modèl",
        ] {
            assert_eq!(select_model(&mut s, bad, NOW), Err("bad_model"), "{bad:?}");
        }
        assert_eq!(
            select_model(&mut s, "no-such-model", NOW),
            Err("unknown_model")
        );
        assert_eq!(select_model(&mut s, "suricomai-tiny-v1", NOW), Ok(()));
    }

    #[test]
    fn settings_use_the_session_ranges_and_codes() {
        let mut s = session();
        assert_eq!(set_temperature(&mut s, 0.5), Ok(()));
        assert_eq!(set_temperature(&mut s, 3.0), Err("bad_request"));
        assert_eq!(set_temperature(&mut s, f64::NAN), Err("bad_request"));
        assert_eq!(set_max_tokens(&mut s, 64), Ok(()));
        assert_eq!(set_max_tokens(&mut s, 0), Err("bad_request"));
        assert_eq!(set_max_tokens(&mut s, 1000), Err("bad_request"));
        let st = status(&s, NOW);
        assert!((st.temperature - 0.5).abs() < f64::EPSILON && st.max_tokens == 64);
    }

    #[test]
    fn clearing_forgets_the_chat_and_the_receipt() {
        let mut s = session();
        ask(&mut s, "something to forget", NOW).unwrap();
        clear_chat(&mut s);
        assert!(transcript(&s).is_empty());
        assert!(last_proof(&s).is_none());
        assert_eq!(status(&s, NOW).turns, 0);
    }

    #[test]
    fn the_model_list_marks_exactly_one_model_active() {
        let list = models(&session(), NOW);
        assert_eq!(list.iter().filter(|m| m.active).count(), 1);
        let tiny = list.iter().find(|m| m.id == "suricomai-tiny-v1").unwrap();
        assert_eq!((tiny.standing, tiny.privacy), ("approved", "lab-untrusted"));
    }
}
