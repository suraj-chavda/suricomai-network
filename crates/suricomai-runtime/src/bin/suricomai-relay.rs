// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Development relay process.
//!
//! Carries the bytes of a node channel to a fixed list of upstream nodes. It holds no
//! keys and cannot read, alter or forge a channel. A client names an upstream by its
//! position in the list given here, never by address.
//!
//!   suricomai-relay --upstream ADDR [--upstream ADDR ...] [--listen ADDR]
//!                 [--max-connections N] [--max-per-peer N]
//!
//! Prints `listening <addr>` on standard output.

use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use suricomai_runtime::{serve_relay, RelayLimits};

const USAGE: &str = "usage: suricomai-relay --upstream ADDR [--upstream ADDR ...] [--listen ADDR] [--max-connections N] [--max-per-peer N]";

fn parse_args() -> Result<(String, Vec<SocketAddr>, RelayLimits), String> {
    let mut listen = String::from("127.0.0.1:7800");
    let mut upstreams = Vec::new();
    let mut limits = RelayLimits::default();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let number = |v: &str| {
            v.parse::<usize>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| format!("{flag} needs a positive number"))
        };
        match flag.as_str() {
            "--listen" => listen = value,
            "--upstream" => upstreams.push(
                value
                    .parse::<SocketAddr>()
                    .map_err(|_| format!("{value}: not an address"))?,
            ),
            "--max-connections" => limits.connections.max_connections = number(&value)?,
            "--max-per-peer" => limits.connections.max_per_peer = number(&value)?,
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    if upstreams.is_empty() {
        return Err("at least one --upstream is required".into());
    }
    Ok((listen, upstreams, limits))
}

fn run() -> Result<(), String> {
    let (listen, upstreams, limits) = parse_args()?;
    let listener = TcpListener::bind(&listen).map_err(|e| format!("{listen}: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let mut out = std::io::stdout();
    writeln!(out, "listening {addr}")
        .and_then(|()| out.flush())
        .map_err(|e| e.to_string())?;
    serve_relay(
        listener,
        upstreams,
        limits,
        Arc::new(AtomicBool::new(false)),
    )
    .map_err(|e| e.to_string())
}

fn main() {
    if let Err(message) = run() {
        eprintln!("suricomai-relay: {message}\n{USAGE}");
        std::process::exit(2);
    }
}
