// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! One-shot TCP exchange. The payload is a sealed job or a sealed result, plus a kind byte.
//!
//! Error payloads are static codes. A code that is not one of those codes becomes [`RuntimeError::Wire`]
//! and the bytes are dropped.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::error::RuntimeError;
use crate::node::Executor;

pub(crate) const MAX_FRAME: u32 = 8 * 1024 * 1024;

/// How long a client waits for the worker to start answering. Inference can take far
/// longer than the short per-read timeout, which only guards a stalled peer.
pub(crate) const RESPONSE_WAIT: Duration = Duration::from_secs(120);

/// Wall-clock limit for reading one whole request. The per-read timeout alone
/// lets a client that sends one byte at a time hold a serial handler for hours.
pub(crate) const REQUEST_DEADLINE: Duration = Duration::from_secs(15);

/// Read a socket in chunks, fail once `deadline` passes, and never allocate more
/// than the bytes that actually arrived.
pub(crate) fn read_chunk(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<usize, RuntimeError> {
    if Instant::now() >= deadline {
        return Err(RuntimeError::Wire);
    }
    stream.read(buf).map_err(|_| RuntimeError::Wire)
}

/// Accept one connection, run one job, and return the request bytes the socket delivered.
pub fn serve_one(
    listener: TcpListener,
    executor: &mut Executor,
    now: u64,
) -> Result<Vec<u8>, RuntimeError> {
    let (mut stream, peer) = listener.accept().map_err(|_| RuntimeError::Wire)?;
    ensure_loopback(&peer)?;
    configure(&stream)?;
    let payload = read_frame(&mut stream)?;
    let sealed = match payload.split_first() {
        Some((0, rest)) => rest,
        _ => return Err(RuntimeError::Wire),
    };
    let response = match executor.handle(sealed, now) {
        Ok(bytes) => tagged(0, &bytes),
        Err(err) => tagged(1, err.code().as_bytes()),
    };
    write_frame(&mut stream, &response)?;
    Ok(payload)
}

/// Send one sealed job and return the sealed result.
pub fn exchange_tcp(addr: SocketAddr, sealed: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    ensure_loopback(&addr)?;
    let mut stream = TcpStream::connect(addr).map_err(|_| RuntimeError::Wire)?;
    configure(&stream)?;
    write_frame(&mut stream, &tagged(0, sealed))?;
    stream
        .set_read_timeout(Some(RESPONSE_WAIT))
        .map_err(|_| RuntimeError::Wire)?;
    let payload = read_frame(&mut stream)?;
    match payload.split_first() {
        Some((0, rest)) => Ok(rest.to_vec()),
        Some((1, rest)) => {
            let code = std::str::from_utf8(rest).unwrap_or("");
            Err(RuntimeError::from_remote_code(code))
        }
        _ => Err(RuntimeError::Wire),
    }
}

pub(crate) fn tagged(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(kind);
    out.extend_from_slice(payload);
    out
}

fn ensure_loopback(addr: &SocketAddr) -> Result<(), RuntimeError> {
    let ok = match addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    };
    // There is no authenticated remote transport yet, so a non-loopback peer is refused.
    if ok {
        Ok(())
    } else {
        Err(RuntimeError::Wire)
    }
}

fn configure(stream: &TcpStream) -> Result<(), RuntimeError> {
    stream.set_nodelay(true).map_err(|_| RuntimeError::Wire)?;
    let timeout = Some(Duration::from_secs(2));
    stream
        .set_read_timeout(timeout)
        .map_err(|_| RuntimeError::Wire)?;
    stream
        .set_write_timeout(timeout)
        .map_err(|_| RuntimeError::Wire)?;
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, RuntimeError> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|_| RuntimeError::Wire)?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 || len > MAX_FRAME {
        return Err(RuntimeError::Wire);
    }
    let len = len as usize;
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let mut buf = Vec::with_capacity(len.min(64 * 1024));
    let mut chunk = [0u8; 16 * 1024];
    while buf.len() < len {
        let want = (len - buf.len()).min(chunk.len());
        let read = read_chunk(stream, &mut chunk[..want], deadline)?;
        if read == 0 {
            return Err(RuntimeError::Wire);
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    Ok(buf)
}

fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), RuntimeError> {
    if payload.len() > MAX_FRAME as usize {
        return Err(RuntimeError::Wire);
    }
    let len = u32::try_from(payload.len()).map_err(|_| RuntimeError::Wire)?;
    stream
        .write_all(&len.to_be_bytes())
        .map_err(|_| RuntimeError::Wire)?;
    stream.write_all(payload).map_err(|_| RuntimeError::Wire)?;
    stream.flush().map_err(|_| RuntimeError::Wire)?;
    Ok(())
}
