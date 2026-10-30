// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Loopback HTTP for `POST /v1/chat/completions`.
//!
//! The body is the OpenAI-shaped request. This process seals it and forwards only
//! the sealed job to the executor. The listener must be a loopback address.

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde::Serialize;

use crate::chat::{ChatMessage, ChatRequest};
use crate::client::Client;
use crate::error::RuntimeError;
use crate::node::NodeCard;
use crate::wire::{exchange_tcp, read_chunk, REQUEST_DEADLINE};

const MAX_HEADER: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;

/// Serve one chat completion, then close.
pub fn serve_chat_once(
    listener: TcpListener,
    client: &Client,
    card: &NodeCard,
    executor: SocketAddr,
    now: u64,
) -> Result<(), RuntimeError> {
    let bound = listener.local_addr().map_err(|_| RuntimeError::Wire)?;
    if !bound.ip().is_loopback() {
        return Err(RuntimeError::Wire);
    }
    let (mut stream, _) = listener.accept().map_err(|_| RuntimeError::Wire)?;
    stream.set_nodelay(true).map_err(|_| RuntimeError::Wire)?;
    let timeout = Some(Duration::from_secs(2));
    stream
        .set_read_timeout(timeout)
        .map_err(|_| RuntimeError::Wire)?;
    stream
        .set_write_timeout(timeout)
        .map_err(|_| RuntimeError::Wire)?;

    let body = match read_chat_body(&mut stream) {
        Ok(body) => body,
        Err(err) => {
            write_error(&mut stream, err.code())?;
            return Ok(());
        }
    };
    let incoming: Incoming = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            write_error(&mut stream, RuntimeError::BadRequest.code())?;
            return Ok(());
        }
    };
    if incoming.stream {
        write_error(&mut stream, RuntimeError::BadRequest.code())?;
        return Ok(());
    }
    let request = ChatRequest {
        model: incoming.model,
        messages: incoming
            .messages
            .into_iter()
            .map(|message| ChatMessage {
                role: message.role,
                content: message.content,
            })
            .collect(),
        temperature: incoming.temperature,
        max_tokens: incoming.max_tokens,
    };
    match client.chat(card, &request, now, |sealed| exchange_tcp(executor, sealed)) {
        Ok(chat) => {
            let outgoing = Outgoing {
                id: chat.id,
                object: chat.object,
                model: chat.model,
                choices: vec![Choice {
                    index: 0,
                    message: OutMessage {
                        role: "assistant",
                        content: chat.content,
                    },
                    finish_reason: "stop",
                }],
                suricomai: SuriComAIMeta {
                    privacy: chat.privacy,
                    hardware_p2: chat.hardware_p2,
                    proof_bytes: chat.proof_bytes,
                },
            };
            let bytes = serde_json::to_vec(&outgoing).map_err(|_| RuntimeError::Wire)?;
            write_response(&mut stream, 200, "OK", &bytes)?;
        }
        Err(err) => write_error(&mut stream, err.code())?,
    }
    Ok(())
}

#[derive(Deserialize)]
struct Incoming {
    model: String,
    messages: Vec<IncomingMessage>,
    #[serde(default)]
    temperature: Option<f64>,
    #[serde(default)]
    max_tokens: Option<u64>,
    #[serde(default)]
    stream: bool,
}

#[derive(Deserialize)]
struct IncomingMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct Outgoing {
    id: String,
    object: &'static str,
    model: &'static str,
    choices: Vec<Choice>,
    suricomai: SuriComAIMeta,
}

#[derive(Serialize)]
struct Choice {
    index: u32,
    message: OutMessage,
    finish_reason: &'static str,
}

#[derive(Serialize)]
struct OutMessage {
    role: &'static str,
    content: String,
}

#[derive(Serialize)]
struct SuriComAIMeta {
    privacy: &'static str,
    hardware_p2: bool,
    proof_bytes: usize,
}

fn read_chat_body(stream: &mut TcpStream) -> Result<Vec<u8>, RuntimeError> {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        if buf.len() > MAX_HEADER {
            return Err(RuntimeError::BadRequest);
        }
        let read = read_chunk(stream, &mut tmp, deadline)?;
        if read == 0 {
            return Err(RuntimeError::Wire);
        }
        let scan_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&tmp[..read]);
        if let Some(end) = find_subsequence(&buf[scan_from..], b"\r\n\r\n").map(|at| at + scan_from)
        {
            break end;
        }
    };
    let header = std::str::from_utf8(&buf[..header_end]).map_err(|_| RuntimeError::BadRequest)?;
    let mut lines = header.lines();
    let request_line = lines.next().ok_or(RuntimeError::BadRequest)?;
    if request_line != "POST /v1/chat/completions HTTP/1.1"
        && request_line != "POST /v1/chat/completions HTTP/1.0"
    {
        return Err(RuntimeError::BadRequest);
    }
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| RuntimeError::BadRequest)?,
            );
        }
    }
    let content_length = content_length.ok_or(RuntimeError::BadRequest)?;
    if content_length > MAX_BODY {
        return Err(RuntimeError::BadRequest);
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let read = read_chunk(stream, &mut tmp, deadline)?;
        if read == 0 {
            return Err(RuntimeError::Wire);
        }
        body.extend_from_slice(&tmp[..read]);
    }
    body.truncate(content_length);
    Ok(body)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn write_error(stream: &mut TcpStream, code: &'static str) -> Result<(), RuntimeError> {
    let body =
        format!("{{\"error\":{{\"message\":\"{code}\",\"type\":\"invalid_request_error\"}}}}");
    write_response(stream, 400, "Bad Request", body.as_bytes())
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
) -> Result<(), RuntimeError> {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .map_err(|_| RuntimeError::Wire)?;
    stream.write_all(body).map_err(|_| RuntimeError::Wire)?;
    stream.flush().map_err(|_| RuntimeError::Wire)?;
    Ok(())
}
