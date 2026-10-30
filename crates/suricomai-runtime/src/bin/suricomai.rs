// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Local SuriComAI chat.
//!
//! Type a line and press return. The line is sealed to the executor in this
//! process. The built-in test model answers in hex and is labeled lab-untrusted. Typing
//! `smollm2-135m-instruct` switches to a text answer labeled not-private.

use std::io::{self, BufRead, IsTerminal, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use suricomai_runtime::{format_elapsed, Header, Outcome, ProofSummary, Role, Session};

const HELP: &str = "\
/help     show this list
/status   privacy, model, temperature, tokens
/proof    last receipt
/clear    forget this chat
/models   list models
/model    choose suricomai-tiny-v1 or smollm2-135m-instruct
/temp     set temperature, 0.0 to 2.0
/tokens   set the answer cap, 1 to 256
/quit     leave";

fn main() {
    let mut session = match Session::start(unix_now()) {
        Ok(session) => session,
        Err(err) => {
            eprintln!("suricomai: {err}");
            std::process::exit(1);
        }
    };
    let mut note =
        String::from("For a text answer, type smollm2-135m-instruct and then your prompt.");
    if io::stdin().is_terminal() {
        interactive(&mut session, &mut note);
    } else {
        plain(&mut session, &mut note);
    }
}

fn interactive(session: &mut Session, note: &mut String) {
    let mut editor = match DefaultEditor::new() {
        Ok(editor) => editor,
        Err(err) => {
            eprintln!("suricomai: {err}");
            std::process::exit(1);
        }
    };
    loop {
        paint(session, note);
        match editor.readline(&prompt()) {
            Ok(line) => {
                let _ = editor.add_history_entry(line.as_str());
                if apply(session, note, &line) {
                    break;
                }
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
            Err(err) => {
                eprintln!("suricomai: {err}");
                break;
            }
        }
    }
    println!();
}

fn plain(session: &mut Session, note: &mut String) {
    let stdin = io::stdin();
    println!("{}", frame(session, note));
    for line in stdin.lock().lines() {
        let Ok(line) = line else {
            break;
        };
        if apply(session, note, &line) {
            break;
        }
        println!("{}", frame(session, note));
    }
}

fn apply(session: &mut Session, note: &mut String, line: &str) -> bool {
    match session.submit_line(line, unix_now()) {
        Outcome::Quit => true,
        Outcome::Cleared => {
            *note = "Chat cleared.".to_string();
            false
        }
        Outcome::Help => {
            *note = HELP.to_string();
            false
        }
        Outcome::Status(header) => {
            *note = status_text(&header);
            false
        }
        Outcome::Proof(proof) => {
            *note = proof_text(&proof);
            false
        }
        Outcome::Reply(_) => {
            *note = String::new();
            false
        }
        Outcome::Note(text) => {
            *note = text;
            false
        }
        Outcome::Failed(code) => {
            *note = format!("Could not run that. {code}");
            false
        }
    }
}

fn paint(session: &Session, note: &str) {
    print!("\x1b[2J\x1b[H");
    print!("{}", frame(session, note));
    let _ = io::stdout().flush();
}

fn frame(session: &Session, note: &str) -> String {
    let header = session.header();
    let mut out = String::new();
    out.push_str("\x1b[1mSuriComAI\x1b[0m\n");
    if header.privacy == "not-private" {
        out.push_str(
            "Text model on this computer. It can read the prompt. The answer is the model's text.\n",
        );
    } else {
        out.push_str("Test model. The answer is hex, not a sentence. Privacy is lab-untrusted.\n");
    }
    out.push('\n');
    out.push_str(&field(
        "privacy",
        &format!("\x1b[33m{}\x1b[0m", header.privacy),
    ));
    out.push_str(&field(
        "hardware P2",
        if header.hardware_p2 {
            "yes"
        } else {
            "\x1b[32mno\x1b[0m"
        },
    ));
    out.push_str(&field("model", header.model));
    out.push_str(&field("temperature", &header.temperature.to_string()));
    out.push_str(&field("max tokens", &header.max_tokens.to_string()));
    out.push('\n');
    if session.lines().is_empty() {
        out.push_str("\x1b[2mNo messages yet.\x1b[0m\n");
    }
    for line in visible(session.lines()) {
        match line.role {
            Role::You => {
                out.push_str("\n\x1b[36myou\x1b[0m\n");
                out.push_str(&wrap(&line.text, "  "));
            }
            Role::Assistant => {
                out.push_str("\n\x1b[35massistant\x1b[0m\n");
                out.push_str(&wrap(&line.text, "  "));
            }
            Role::Detail => {
                out.push_str(&color_detail(&line.text));
                out.push('\n');
            }
        }
    }
    out.push('\n');
    if !note.is_empty() {
        out.push_str(note);
        if !note.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
    }
    out.push_str(
        "\x1b[2m/help   /models   /model   /status   /proof   /clear   /temp   /tokens   /quit\x1b[0m\n",
    );
    out
}

fn visible(lines: &[suricomai_runtime::ViewLine]) -> &[suricomai_runtime::ViewLine] {
    const KEEP: usize = 24;
    if lines.len() <= KEEP {
        lines
    } else {
        &lines[lines.len() - KEEP..]
    }
}

fn field(name: &str, value: &str) -> String {
    format!("\x1b[2m{name:<14}\x1b[0m{value}\n")
}

fn color_detail(text: &str) -> String {
    if text.contains("was not in that ciphertext") {
        format!("\x1b[32m{text}\x1b[0m")
    } else if text.contains("was found outside") {
        format!("\x1b[31m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn wrap(text: &str, indent: &str) -> String {
    const WIDTH: usize = 72;
    let mut out = String::new();
    let mut line = String::new();
    for ch in text.chars() {
        if ch == '\n' || line.chars().count() >= WIDTH {
            out.push_str(indent);
            out.push_str(line.trim_end());
            out.push('\n');
            line.clear();
            if ch == '\n' {
                continue;
            }
        }
        line.push(ch);
    }
    if !line.is_empty() {
        out.push_str(indent);
        out.push_str(&line);
        out.push('\n');
    }
    out
}

fn prompt() -> String {
    "\x1b[1myou › \x1b[0m".to_string()
}

fn status_text(header: &Header) -> String {
    format!(
        "privacy {}\nhardware P2 {}\nmodel {}\ntemperature {}\nmax tokens {}",
        header.privacy,
        if header.hardware_p2 { "yes" } else { "no" },
        header.model,
        header.temperature,
        header.max_tokens
    )
}

fn proof_text(proof: &ProofSummary) -> String {
    format!(
        "{} · {} bytes · {} · token bucket {} · {}",
        proof.id,
        proof.bytes,
        format_elapsed(proof.elapsed_secs),
        proof.token_bucket,
        proof.privacy
    )
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
