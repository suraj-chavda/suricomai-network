// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Noise channel between separate processes. Frame bytes are in the protocol specification, "Node transport".
//!
//! The sealed job stays HPKE-sealed inside the channel. A swapped or broken channel can
//! stop a job. It cannot read or forge one.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use snow::params::{DHChoice, NoiseParams};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::{Builder, TransportState};
use zeroize::Zeroize;

use crate::error::RuntimeError;
use crate::model::{model_digest, pinned_weights, MODEL_NAME};
use crate::node::{Executor, NodeCard};
use crate::wire::{tagged, MAX_FRAME, REQUEST_DEADLINE, RESPONSE_WAIT};
use suricomai_envelope::{Advertisement, EnvelopeError};

const PATTERN: &str = "Noise_XK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"suricomai.transport.v1";
const NOISE_MAX: usize = 65_535;
const TAG: usize = 16;
pub(crate) const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
const WRITE_DEADLINE: Duration = Duration::from_secs(5);

/// A node's long-term transport key. Clients pin the public half.
pub struct TransportKey {
    private: [u8; 32],
    public: [u8; 32],
}

impl TransportKey {
    /// A fresh key from the operating system's randomness.
    pub fn generate() -> Result<Self, RuntimeError> {
        let pair = Builder::new(params()?)
            .generate_keypair()
            .map_err(|_| RuntimeError::Wire)?;
        let mut pair = pair;
        let private: [u8; 32] = pair
            .private
            .as_slice()
            .try_into()
            .map_err(|_| RuntimeError::Wire)?;
        pair.private.zeroize();
        let public: [u8; 32] = pair
            .public
            .as_slice()
            .try_into()
            .map_err(|_| RuntimeError::Wire)?;
        Ok(Self { private, public })
    }

    /// Rebuild a key from its secret, for a node that keeps its identity in a file.
    ///
    /// The public half comes from the same X25519 code the Noise handshake uses, so the
    /// two cannot disagree. An all-zero secret is refused.
    pub fn from_secret(secret: [u8; 32]) -> Result<Self, RuntimeError> {
        if secret == [0u8; 32] {
            return Err(RuntimeError::KeyFile);
        }
        let mut dh = DefaultResolver
            .resolve_dh(&DHChoice::Curve25519)
            .ok_or(RuntimeError::Wire)?;
        dh.set(&secret);
        let public: [u8; 32] = dh.pubkey().try_into().map_err(|_| RuntimeError::Wire)?;
        Ok(Self {
            private: secret,
            public,
        })
    }

    /// The secret half, for writing an identity file. Handle it like any private key.
    #[cfg(unix)]
    pub(crate) fn secret(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.private)
    }

    /// The key a client pins before it connects.
    pub fn public(&self) -> [u8; 32] {
        self.public
    }
}

impl Drop for TransportKey {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

impl std::fmt::Debug for TransportKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransportKey { redacted }")
    }
}

fn params() -> Result<NoiseParams, RuntimeError> {
    PATTERN.parse().map_err(|_| RuntimeError::Wire)
}

fn remaining(deadline: Instant) -> Result<Duration, RuntimeError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or(RuntimeError::Wire)
}

/// Fill `buf` or fail at `deadline`. The timeout is the time left, so a peer that
/// sends one byte at a time still meets the whole-request deadline.
pub(crate) fn read_exact_by(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<(), RuntimeError> {
    let mut filled = 0;
    while filled < buf.len() {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| RuntimeError::Wire)?;
        let read = stream
            .read(&mut buf[filled..])
            .map_err(|_| RuntimeError::Wire)?;
        if read == 0 {
            return Err(RuntimeError::Wire);
        }
        filled += read;
    }
    Ok(())
}

fn read_noise_message(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>, RuntimeError> {
    let mut len = [0u8; 2];
    read_exact_by(stream, &mut len, deadline)?;
    let len = usize::from(u16::from_be_bytes(len));
    if len == 0 {
        return Err(RuntimeError::Wire);
    }
    let mut body = vec![0u8; len];
    read_exact_by(stream, &mut body, deadline)?;
    Ok(body)
}

fn write_noise_message(stream: &mut TcpStream, body: &[u8]) -> Result<(), RuntimeError> {
    let len = u16::try_from(body.len()).map_err(|_| RuntimeError::Wire)?;
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    stream
        .write_all(&out)
        .and_then(|()| stream.flush())
        .map_err(|_| RuntimeError::Wire)
}

/// An established channel: Noise transport state over one TCP stream.
struct Channel {
    stream: TcpStream,
    state: TransportState,
}

impl Channel {
    fn send(&mut self, data: &[u8]) -> Result<(), RuntimeError> {
        if data.is_empty() || data.len() > MAX_FRAME as usize {
            return Err(RuntimeError::Wire);
        }
        let len = u32::try_from(data.len()).map_err(|_| RuntimeError::Wire)?;
        let mut framed = Vec::with_capacity(4 + data.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(data);
        let mut out = Vec::with_capacity(framed.len() + framed.len() / (NOISE_MAX - TAG) * 18 + 18);
        let mut cipher = vec![0u8; NOISE_MAX];
        for chunk in framed.chunks(NOISE_MAX - TAG) {
            let n = self
                .state
                .write_message(chunk, &mut cipher)
                .map_err(|_| RuntimeError::Wire)?;
            let n16 = u16::try_from(n).map_err(|_| RuntimeError::Wire)?;
            out.extend_from_slice(&n16.to_be_bytes());
            out.extend_from_slice(&cipher[..n]);
        }
        self.stream
            .set_write_timeout(Some(WRITE_DEADLINE))
            .map_err(|_| RuntimeError::Wire)?;
        self.stream
            .write_all(&out)
            .and_then(|()| self.stream.flush())
            .map_err(|_| RuntimeError::Wire)
    }

    fn recv(&mut self, deadline: Instant) -> Result<Vec<u8>, RuntimeError> {
        let mut plain: Vec<u8> = Vec::new();
        let mut total: Option<usize> = None;
        let mut buf = vec![0u8; NOISE_MAX];
        loop {
            let cipher = read_noise_message(&mut self.stream, deadline)?;
            let n = self
                .state
                .read_message(&cipher, &mut buf)
                .map_err(|_| RuntimeError::Wire)?;
            plain.extend_from_slice(&buf[..n]);
            if total.is_none() && plain.len() >= 4 {
                let declared = u32::from_be_bytes([plain[0], plain[1], plain[2], plain[3]]);
                if declared == 0 || declared > MAX_FRAME {
                    return Err(RuntimeError::Wire);
                }
                total = Some(4 + declared as usize);
            }
            match total {
                Some(want) if plain.len() == want => {
                    plain.drain(..4);
                    return Ok(plain);
                }
                Some(want) if plain.len() > want => return Err(RuntimeError::Wire),
                _ => {}
            }
        }
    }
}

fn handshake_responder(mut stream: TcpStream, key: &TransportKey) -> Result<Channel, RuntimeError> {
    let deadline = Instant::now() + HANDSHAKE_DEADLINE;
    let mut state = Builder::new(params()?)
        .prologue(PROLOGUE)
        .and_then(|b| b.local_private_key(&key.private))
        .and_then(Builder::build_responder)
        .map_err(|_| RuntimeError::Wire)?;
    let mut scratch = vec![0u8; NOISE_MAX];
    let first = read_noise_message(&mut stream, deadline)?;
    state
        .read_message(&first, &mut scratch)
        .map_err(|_| RuntimeError::Wire)?;
    let n = state
        .write_message(&[], &mut scratch)
        .map_err(|_| RuntimeError::Wire)?;
    write_noise_message(&mut stream, &scratch[..n])?;
    let third = read_noise_message(&mut stream, deadline)?;
    state
        .read_message(&third, &mut scratch)
        .map_err(|_| RuntimeError::Wire)?;
    let state = state
        .into_transport_mode()
        .map_err(|_| RuntimeError::Wire)?;
    Ok(Channel { stream, state })
}

#[cfg(test)]
fn handshake_initiator(stream: TcpStream, pinned: &[u8; 32]) -> Result<Channel, RuntimeError> {
    handshake_initiator_within(stream, pinned, HANDSHAKE_DEADLINE)
}

fn handshake_initiator_within(
    mut stream: TcpStream,
    pinned: &[u8; 32],
    budget: Duration,
) -> Result<Channel, RuntimeError> {
    let deadline = Instant::now() + budget;
    let mut ephemeral_static = Builder::new(params()?)
        .generate_keypair()
        .map_err(|_| RuntimeError::Wire)?;
    let built = Builder::new(params()?)
        .prologue(PROLOGUE)
        .and_then(|b| b.local_private_key(&ephemeral_static.private))
        .and_then(|b| b.remote_public_key(pinned))
        .and_then(Builder::build_initiator);
    ephemeral_static.private.zeroize();
    let mut state = built.map_err(|_| RuntimeError::Wire)?;
    let mut scratch = vec![0u8; NOISE_MAX];
    let n = state
        .write_message(&[], &mut scratch)
        .map_err(|_| RuntimeError::Wire)?;
    write_noise_message(&mut stream, &scratch[..n])?;
    let second = read_noise_message(&mut stream, deadline)?;
    state
        .read_message(&second, &mut scratch)
        .map_err(|_| RuntimeError::Wire)?;
    let n = state
        .write_message(&[], &mut scratch)
        .map_err(|_| RuntimeError::Wire)?;
    write_noise_message(&mut stream, &scratch[..n])?;
    let state = state
        .into_transport_mode()
        .map_err(|_| RuntimeError::Wire)?;
    Ok(Channel { stream, state })
}

/// Kind byte of a card request.
const KIND_CARD: u8 = 2;
/// Kind byte of a request for the card of one hosted model.
const KIND_MODEL_CARD: u8 = 3;

/// Answer one request on an authenticated channel. A malformed request closes the
/// connection. A refused job is a static error code.
fn respond(executor: &mut Executor, request: &[u8], now: u64) -> Result<Vec<u8>, RuntimeError> {
    match request.split_first() {
        Some((0, sealed)) => Ok(match executor.handle(sealed, now) {
            Ok(bytes) => tagged(0, &bytes),
            Err(err) => tagged(1, err.code().as_bytes()),
        }),
        Some((&KIND_CARD, nonce)) => {
            let nonce: [u8; 32] = nonce.try_into().map_err(|_| RuntimeError::Wire)?;
            Ok(match executor.card(nonce, now) {
                Ok(card) => {
                    let mut body = card.model_digest.to_vec();
                    body.extend_from_slice(&card.advertisement.to_bytes()?);
                    tagged(0, &body)
                }
                Err(err) => tagged(1, err.code().as_bytes()),
            })
        }
        Some((&KIND_MODEL_CARD, body)) => {
            let body: [u8; 64] = body.try_into().map_err(|_| RuntimeError::Wire)?;
            let (nonce, digest) = (
                <[u8; 32]>::try_from(&body[..32]).map_err(|_| RuntimeError::Wire)?,
                <[u8; 32]>::try_from(&body[32..]).map_err(|_| RuntimeError::Wire)?,
            );
            Ok(match executor.model_card(&digest, nonce, now) {
                Ok(card) => {
                    let mut out = card.model_digest.to_vec();
                    out.extend_from_slice(&card.advertisement.to_bytes()?);
                    tagged(0, &out)
                }
                Err(err) => tagged(1, err.code().as_bytes()),
            })
        }
        _ => Err(RuntimeError::Wire),
    }
}

/// Answers requests on an authenticated channel. The server calls it only after the
/// handshake and a whole, well-formed frame. `peer` is the connecting address.
pub trait Handler: Send + Sync {
    /// Return the response bytes, or an error to close the connection.
    fn respond(
        &self,
        peer: IpAddr,
        request: &[u8],
        clock: &(dyn Fn() -> u64 + Send + Sync),
    ) -> Result<Vec<u8>, RuntimeError>;
}

impl Handler for Mutex<Executor> {
    fn respond(
        &self,
        _peer: IpAddr,
        request: &[u8],
        clock: &(dyn Fn() -> u64 + Send + Sync),
    ) -> Result<Vec<u8>, RuntimeError> {
        // A poisoned lock means a job panicked mid-update. Refuse rather than
        // continue on state nobody can vouch for.
        let mut executor = self.lock().map_err(|_| RuntimeError::Wire)?;
        respond(&mut executor, request, clock())
    }
}

/// Accept one connection, authenticate it, answer one request, and close.
///
/// The executor is called only after the handshake and a whole, well-formed frame.
pub fn serve_secure_one(
    listener: &TcpListener,
    key: &TransportKey,
    executor: &mut Executor,
    now: u64,
) -> Result<(), RuntimeError> {
    let (stream, _) = listener.accept().map_err(|_| RuntimeError::Wire)?;
    stream.set_nodelay(true).map_err(|_| RuntimeError::Wire)?;
    let mut channel = handshake_responder(stream, key)?;
    let request = channel.recv(Instant::now() + REQUEST_DEADLINE)?;
    let response = respond(executor, &request, now)?;
    channel.send(&response)
}

/// Bounds on what one server process will hold open at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerLimits {
    /// Connections held open in total.
    pub max_connections: usize,
    /// Connections held open from one peer IP address.
    pub max_per_peer: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            max_per_peer: 4,
        }
    }
}

#[derive(Default)]
pub(crate) struct Slots {
    total: usize,
    per_peer: HashMap<IpAddr, usize>,
}

/// One held connection slot. Dropping it frees the slot on every exit path.
pub(crate) struct SlotGuard {
    slots: Arc<Mutex<Slots>>,
    peer: IpAddr,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        slots.total = slots.total.saturating_sub(1);
        if let Some(held) = slots.per_peer.get_mut(&self.peer) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                slots.per_peer.remove(&self.peer);
            }
        }
    }
}

pub(crate) fn take_slot(
    slots: &Arc<Mutex<Slots>>,
    peer: IpAddr,
    limits: ServerLimits,
) -> Option<SlotGuard> {
    let mut held = slots.lock().unwrap_or_else(PoisonError::into_inner);
    let from_peer = held.per_peer.get(&peer).copied().unwrap_or(0);
    if held.total >= limits.max_connections || from_peer >= limits.max_per_peer {
        return None;
    }
    held.total += 1;
    *held.per_peer.entry(peer).or_insert(0) += 1;
    Some(SlotGuard {
        slots: Arc::clone(slots),
        peer,
    })
}

fn run_connection(
    stream: TcpStream,
    peer: IpAddr,
    key: &TransportKey,
    handler: &dyn Handler,
    clock: &(dyn Fn() -> u64 + Send + Sync),
) -> Result<(), RuntimeError> {
    stream.set_nodelay(true).map_err(|_| RuntimeError::Wire)?;
    let mut channel = handshake_responder(stream, key)?;
    let request = channel.recv(Instant::now() + REQUEST_DEADLINE)?;
    let response = handler.respond(peer, &request, clock)?;
    channel.send(&response)
}

/// Serve requests to `handler` until `stop` is set.
///
/// Connections past `limits` are closed before a byte is read. Handshakes and frame
/// reads run in parallel. A node handler runs one job at a time. Connections already
/// running when `stop` is set finish or hit their deadlines before this returns.
pub fn serve_secure<H: Handler + 'static>(
    listener: TcpListener,
    key: Arc<TransportKey>,
    handler: Arc<H>,
    limits: ServerLimits,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    stop: Arc<AtomicBool>,
) -> Result<(), RuntimeError> {
    listener
        .set_nonblocking(true)
        .map_err(|_| RuntimeError::Wire)?;
    let slots = Arc::new(Mutex::new(Slots::default()));
    let mut running: Vec<thread::JoinHandle<()>> = Vec::new();
    while !stop.load(Ordering::Acquire) {
        running.retain(|handle| !handle.is_finished());
        let (stream, peer) = match listener.accept() {
            Ok(pair) => pair,
            Err(_) => {
                thread::sleep(Duration::from_millis(20));
                continue;
            }
        };
        let Some(guard) = take_slot(&slots, peer.ip().to_canonical(), limits) else {
            continue;
        };
        if stream.set_nonblocking(false).is_err() {
            continue;
        }
        let key = Arc::clone(&key);
        let handler = Arc::clone(&handler);
        let clock = Arc::clone(&clock);
        let peer_ip = peer.ip().to_canonical();
        let spawned = thread::Builder::new().spawn(move || {
            let _held = guard;
            let _ = run_connection(stream, peer_ip, &key, handler.as_ref(), clock.as_ref());
        });
        if let Ok(handle) = spawned {
            running.push(handle);
        }
    }
    for handle in running {
        let _ = handle.join();
    }
    Ok(())
}

/// One way to reach a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// Connect to the node itself.
    Direct(SocketAddr),
    /// Connect to a relay and name one of its configured upstreams by index.
    Relay {
        /// The relay's address.
        relay: SocketAddr,
        /// Index into the relay's upstream list.
        upstream: u8,
    },
}

/// Open the stream for a route. A relay route has sent its preamble when this returns.
fn connect_route(route: &Route) -> Result<(TcpStream, Duration), RuntimeError> {
    match route {
        Route::Direct(addr) => {
            let stream = TcpStream::connect_timeout(addr, HANDSHAKE_DEADLINE)
                .map_err(|_| RuntimeError::Wire)?;
            Ok((stream, HANDSHAKE_DEADLINE))
        }
        Route::Relay { relay, upstream } => {
            let mut stream = TcpStream::connect_timeout(relay, HANDSHAKE_DEADLINE)
                .map_err(|_| RuntimeError::Wire)?;
            stream
                .set_write_timeout(Some(WRITE_DEADLINE))
                .map_err(|_| RuntimeError::Wire)?;
            let mut preamble = crate::relay::PREAMBLE_MAGIC.to_vec();
            preamble.push(*upstream);
            stream
                .write_all(&preamble)
                .map_err(|_| RuntimeError::Wire)?;
            // The relay may spend up to its own connect bound reaching the node.
            Ok((stream, HANDSHAKE_DEADLINE * 2))
        }
    }
}

/// Send one request to the node that holds `pinned` and return the response body.
///
/// Routes are tried in order. A route that fails before the request is written moves on
/// to the next one. Once the request has been written, a failure is final: the node may
/// already have run the job, and a second run on another route would be a replay.
fn request_via(
    routes: &[Route],
    pinned: &[u8; 32],
    request: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    request_via_within(routes, pinned, request, RESPONSE_WAIT)
}

/// [`request_via`] with a bound on how long to wait for the response.
fn request_via_within(
    routes: &[Route],
    pinned: &[u8; 32],
    request: &[u8],
    wait: Duration,
) -> Result<Vec<u8>, RuntimeError> {
    for route in routes {
        let reached = connect_route(route).and_then(|(stream, budget)| {
            stream.set_nodelay(true).map_err(|_| RuntimeError::Wire)?;
            handshake_initiator_within(stream, pinned, budget)
        });
        let Ok(mut channel) = reached else {
            continue;
        };
        channel.send(request)?;
        let response = channel.recv(Instant::now() + wait)?;
        return match response.split_first() {
            Some((0, rest)) => Ok(rest.to_vec()),
            Some((1, rest)) => Err(RuntimeError::from_remote_code(
                std::str::from_utf8(rest).unwrap_or(""),
            )),
            _ => Err(RuntimeError::Wire),
        };
    }
    // No route got as far as writing the request, so trying another node is safe.
    Err(RuntimeError::Unreachable)
}

/// One request to one address over the secure channel, with no relay and no fallback.
pub(crate) fn request_direct(
    addr: SocketAddr,
    pinned: &[u8; 32],
    request: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    request_via(&[Route::Direct(addr)], pinned, request)
}

/// Send one sealed job to the node that holds `pinned` and return the sealed result.
pub fn exchange_secure(
    addr: SocketAddr,
    pinned: &[u8; 32],
    sealed: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    exchange_secure_via(&[Route::Direct(addr)], pinned, sealed)
}

/// Like [`exchange_secure`], trying `routes` in order until one reaches the node.
pub fn exchange_secure_via(
    routes: &[Route],
    pinned: &[u8; 32],
    sealed: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    request_via(routes, pinned, &tagged(0, sealed))
}

/// Ask the node that holds `pinned` for its card, bound to `nonce`.
///
/// The card still has to pass the client's own advertisement check before anything is sealed.
pub fn fetch_card(
    addr: SocketAddr,
    pinned: &[u8; 32],
    nonce: [u8; 32],
) -> Result<NodeCard, RuntimeError> {
    fetch_card_via(&[Route::Direct(addr)], pinned, nonce)
}

/// Like [`fetch_card`], trying `routes` in order until one reaches the node.
pub fn fetch_card_via(
    routes: &[Route],
    pinned: &[u8; 32],
    nonce: [u8; 32],
) -> Result<NodeCard, RuntimeError> {
    let body = request_via(routes, pinned, &tagged(KIND_CARD, &nonce))?;
    check_card(&body, &nonce, pinned)
}

/// Ask the node that holds `pinned` for the card of the hosted model `digest`, bound to `nonce`.
///
/// The card still has to pass the client's own transit checks before anything is sealed.
pub fn fetch_model_card_via(
    routes: &[Route],
    pinned: &[u8; 32],
    nonce: [u8; 32],
    digest: &[u8; 32],
    name: &str,
) -> Result<NodeCard, RuntimeError> {
    let mut body = nonce.to_vec();
    body.extend_from_slice(digest);
    let response = request_via(routes, pinned, &tagged(KIND_MODEL_CARD, &body))?;
    check_card_for(&response, &nonce, pinned, digest, name)
}

/// [`fetch_model_card_via`] straight to one address that gives up on a silent node after `wait`.
pub(crate) fn fetch_model_card_bounded(
    addr: SocketAddr,
    pinned: &[u8; 32],
    nonce: [u8; 32],
    digest: &[u8; 32],
    name: &str,
    wait: Duration,
) -> Result<NodeCard, RuntimeError> {
    let mut body = nonce.to_vec();
    body.extend_from_slice(digest);
    let response = request_via_within(
        &[Route::Direct(addr)],
        pinned,
        &tagged(KIND_MODEL_CARD, &body),
        wait,
    )?;
    check_card_for(&response, &nonce, pinned, digest, name)
}

/// [`fetch_card`] that gives up on a silent node after `wait`. A client surveying several
/// nodes uses it so one stalled node cannot hold the survey.
pub(crate) fn fetch_card_bounded(
    addr: SocketAddr,
    pinned: &[u8; 32],
    nonce: [u8; 32],
    wait: Duration,
) -> Result<NodeCard, RuntimeError> {
    let body = request_via_within(
        &[Route::Direct(addr)],
        pinned,
        &tagged(KIND_CARD, &nonce),
        wait,
    )?;
    check_card(&body, &nonce, pinned)
}

fn check_card(body: &[u8], nonce: &[u8; 32], pinned: &[u8; 32]) -> Result<NodeCard, RuntimeError> {
    check_card_for(
        body,
        nonce,
        pinned,
        &model_digest(&pinned_weights()),
        MODEL_NAME,
    )
}

/// Check a card body against what the client asked for: the model digest it requested, the
/// nonce it sent, and the transport key it pinned. `name` is for display only.
fn check_card_for(
    body: &[u8],
    nonce: &[u8; 32],
    pinned: &[u8; 32],
    expected_digest: &[u8; 32],
    name: &str,
) -> Result<NodeCard, RuntimeError> {
    let (digest, advertisement) = body.split_at_checked(32).ok_or(RuntimeError::Wire)?;
    let digest: [u8; 32] = digest.try_into().map_err(|_| RuntimeError::Wire)?;
    if digest != *expected_digest {
        return Err(RuntimeError::ModelMismatch);
    }
    let advertisement = Advertisement::from_bytes(advertisement)?;
    if advertisement.nonce != *nonce {
        return Err(RuntimeError::Envelope(EnvelopeError::StaleAdvertisement));
    }
    // The quote covers this field, so a matching key proves the measured node holds
    // the key this client connected with. A zero key means no network transport.
    if advertisement.transport_public != *pinned || *pinned == [0u8; 32] {
        return Err(RuntimeError::Envelope(EnvelopeError::KeyMismatch));
    }
    Ok(NodeCard {
        advertisement,
        model_digest: digest,
        model_name: name.to_string(),
        hardware_p2: false,
        quote_kind: "lab-untrusted",
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Instant;

    use snow::TransportState;
    use suricomai_envelope::InferenceParams;

    use super::*;
    use crate::client::{Client, JobRequest, PrivacyLabel};
    use crate::wire::{exchange_tcp, serve_one};

    const CANARY: &[u8] = b"CANARY-SECRET-suricomai-9f3a transport";

    fn request(prompt: &[u8]) -> JobRequest {
        JobRequest {
            job_id: [6u8; 32],
            chain_id: 7,
            prompt: prompt.to_vec(),
            params: InferenceParams::new([3u8; 32], 0, 24).unwrap(),
            now: 10,
            expiry: 1_000,
            fee: 1,
            bond_required: 1,
            max_output_bytes: 64,
            size_class: 4_096,
            max_latency_ms: 150,
            user_pay_key: [5u8; 32],
        }
    }

    /// A peer that speaks the handshake correctly and then writes whatever bytes a test wants.
    struct RawPeer {
        stream: TcpStream,
        state: TransportState,
    }

    impl RawPeer {
        fn connect(addr: SocketAddr, pinned: &[u8; 32]) -> Self {
            let stream = TcpStream::connect(addr).unwrap();
            let channel = handshake_initiator(stream, pinned).unwrap();
            Self {
                stream: channel.stream,
                state: channel.state,
            }
        }

        fn encrypt(&mut self, plain: &[u8]) -> Vec<u8> {
            let mut cipher = vec![0u8; NOISE_MAX];
            let n = self.state.write_message(plain, &mut cipher).unwrap();
            cipher.truncate(n);
            cipher
        }

        fn write_raw(&mut self, cipher: &[u8]) {
            let len = u16::try_from(cipher.len()).unwrap();
            let _ = self.stream.write_all(&len.to_be_bytes());
            let _ = self.stream.write_all(cipher);
            let _ = self.stream.flush();
        }
    }

    fn node() -> (Executor, TransportKey, TcpListener, SocketAddr) {
        let mut executor = Executor::lab().unwrap();
        let key = TransportKey::generate().unwrap();
        executor.set_transport_public(key.public());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        (executor, key, listener, addr)
    }

    /// Serve one connection and report whether it failed and whether the executor ran.
    fn serve_expecting_refusal(
        mut executor: Executor,
        key: TransportKey,
        listener: TcpListener,
    ) -> thread::JoinHandle<(Result<(), RuntimeError>, bool)> {
        thread::spawn(move || {
            let out = serve_secure_one(&listener, &key, &mut executor, 10);
            (out, !executor.log().as_text().is_empty())
        })
    }

    #[test]
    fn a_job_over_the_channel_matches_the_loopback_job() {
        let (mut executor, key, listener, addr) = node();
        let card = executor.card([9u8; 32], 0).unwrap();
        let client = Client::new(executor.verifier(), card.advertisement.executor_id).unwrap();
        let pinned = key.public();
        let worker =
            thread::spawn(move || serve_secure_one(&listener, &key, &mut executor, 10).unwrap());
        let secure = client
            .complete(&card, &request(CANARY), |sealed| {
                exchange_secure(addr, &pinned, sealed)
            })
            .unwrap();
        worker.join().unwrap();

        let mut plain_exec = Executor::lab().unwrap();
        let plain_card = plain_exec.card([9u8; 32], 0).unwrap();
        let plain_client =
            Client::new(plain_exec.verifier(), plain_card.advertisement.executor_id).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let plain_addr = listener.local_addr().unwrap();
        let worker = thread::spawn(move || serve_one(listener, &mut plain_exec, 10).unwrap());
        let plain = plain_client
            .complete(&plain_card, &request(CANARY), |sealed| {
                exchange_tcp(plain_addr, sealed)
            })
            .unwrap();
        worker.join().unwrap();

        assert_eq!(*secure.answer, *plain.answer);
        assert_eq!(secure.privacy, PrivacyLabel::LabUntrusted);
    }

    #[test]
    fn a_client_that_pins_the_wrong_key_writes_no_job_and_the_executor_never_runs() {
        let (executor, key, listener, addr) = node();
        let wrong = TransportKey::generate().unwrap().public();
        let worker = serve_expecting_refusal(executor, key, listener);
        let sealed = vec![7u8; 64];
        assert_eq!(
            exchange_secure(addr, &wrong, &sealed),
            Err(RuntimeError::Unreachable)
        );
        let (served, ran) = worker.join().unwrap();
        assert_eq!(served, Err(RuntimeError::Wire));
        assert!(!ran);
    }

    #[test]
    fn a_peer_that_fails_the_handshake_never_reaches_the_executor() {
        let (executor, key, listener, addr) = node();
        let worker = serve_expecting_refusal(executor, key, listener);
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(&[0, 48]).unwrap();
        stream.write_all(&[0xAB; 48]).unwrap();
        let (served, ran) = worker.join().unwrap();
        assert_eq!(served, Err(RuntimeError::Wire));
        assert!(!ran);
    }

    #[test]
    fn a_flipped_transport_message_is_refused() {
        let (executor, key, listener, addr) = node();
        let pinned = key.public();
        let worker = serve_expecting_refusal(executor, key, listener);
        let mut peer = RawPeer::connect(addr, &pinned);
        let mut frame = 8u32.to_be_bytes().to_vec();
        frame.extend_from_slice(&[0u8; 8]);
        let mut cipher = peer.encrypt(&frame);
        cipher[3] ^= 0x01;
        peer.write_raw(&cipher);
        let (served, ran) = worker.join().unwrap();
        assert_eq!(served, Err(RuntimeError::Wire));
        assert!(!ran);
    }

    #[test]
    fn a_repeated_transport_message_is_refused() {
        let (executor, key, listener, addr) = node();
        let pinned = key.public();
        let worker = serve_expecting_refusal(executor, key, listener);
        let mut peer = RawPeer::connect(addr, &pinned);
        let mut frame = 100u32.to_be_bytes().to_vec();
        frame.extend_from_slice(&[0u8; 10]);
        let first = peer.encrypt(&frame);
        peer.write_raw(&first);
        peer.write_raw(&first);
        let (served, ran) = worker.join().unwrap();
        assert_eq!(served, Err(RuntimeError::Wire));
        assert!(!ran);
    }

    #[test]
    fn reordered_transport_messages_are_refused() {
        let (executor, key, listener, addr) = node();
        let pinned = key.public();
        let worker = serve_expecting_refusal(executor, key, listener);
        let mut peer = RawPeer::connect(addr, &pinned);
        let mut frame = 100u32.to_be_bytes().to_vec();
        frame.extend_from_slice(&[0u8; 10]);
        let first = peer.encrypt(&frame);
        let second = peer.encrypt(&[0u8; 90]);
        peer.write_raw(&second);
        peer.write_raw(&first);
        let (served, ran) = worker.join().unwrap();
        assert_eq!(served, Err(RuntimeError::Wire));
        assert!(!ran);
    }

    #[test]
    fn a_truncated_transport_message_is_refused() {
        let (executor, key, listener, addr) = node();
        let pinned = key.public();
        let worker = serve_expecting_refusal(executor, key, listener);
        let mut peer = RawPeer::connect(addr, &pinned);
        let cipher = peer.encrypt(&[0, 0, 0, 5, 1, 2, 3, 4, 5]);
        let len = u16::try_from(cipher.len()).unwrap();
        peer.stream.write_all(&len.to_be_bytes()).unwrap();
        peer.stream.write_all(&cipher[..cipher.len() / 2]).unwrap();
        drop(peer);
        let (served, ran) = worker.join().unwrap();
        assert_eq!(served, Err(RuntimeError::Wire));
        assert!(!ran);
    }

    #[test]
    fn frames_declaring_zero_or_more_than_the_maximum_are_refused() {
        for declared in [0u32, MAX_FRAME + 1, u32::MAX] {
            let (executor, key, listener, addr) = node();
            let pinned = key.public();
            let worker = serve_expecting_refusal(executor, key, listener);
            let mut peer = RawPeer::connect(addr, &pinned);
            let cipher = peer.encrypt(&declared.to_be_bytes());
            peer.write_raw(&cipher);
            let (served, ran) = worker.join().unwrap();
            assert_eq!(served, Err(RuntimeError::Wire), "declared {declared}");
            assert!(!ran);
        }
    }

    #[test]
    fn a_frame_with_bytes_past_its_declared_length_is_refused() {
        let (executor, key, listener, addr) = node();
        let pinned = key.public();
        let worker = serve_expecting_refusal(executor, key, listener);
        let mut peer = RawPeer::connect(addr, &pinned);
        let mut frame = 2u32.to_be_bytes().to_vec();
        frame.extend_from_slice(&[0u8; 3]);
        let cipher = peer.encrypt(&frame);
        peer.write_raw(&cipher);
        let (served, ran) = worker.join().unwrap();
        assert_eq!(served, Err(RuntimeError::Wire));
        assert!(!ran);
    }

    #[test]
    fn a_peer_that_stalls_the_handshake_is_dropped_at_the_deadline() {
        let (executor, key, listener, addr) = node();
        let worker = serve_expecting_refusal(executor, key, listener);
        let started = Instant::now();
        let _silent = TcpStream::connect(addr).unwrap();
        let (served, ran) = worker.join().unwrap();
        assert_eq!(served, Err(RuntimeError::Wire));
        assert!(!ran);
        assert!(started.elapsed() < HANDSHAKE_DEADLINE + Duration::from_secs(2));
    }

    #[test]
    fn a_peer_that_drips_one_byte_at_a_time_is_dropped_at_the_deadline() {
        let (executor, key, listener, addr) = node();
        let worker = serve_expecting_refusal(executor, key, listener);
        let started = Instant::now();
        let mut stream = TcpStream::connect(addr).unwrap();
        while started.elapsed() < HANDSHAKE_DEADLINE + Duration::from_secs(1) {
            if stream.write_all(&[0]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }
        let (served, ran) = worker.join().unwrap();
        assert_eq!(served, Err(RuntimeError::Wire));
        assert!(!ran);
        assert!(started.elapsed() < HANDSHAKE_DEADLINE + Duration::from_secs(3));
    }

    #[test]
    fn a_frame_larger_than_one_noise_message_arrives_whole() {
        let (_executor, key, listener, addr) = node();
        let pinned = key.public();
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut channel = handshake_responder(stream, &key).unwrap();
            let got = channel.recv(Instant::now() + REQUEST_DEADLINE).unwrap();
            channel.send(&got).unwrap();
        });
        let stream = TcpStream::connect(addr).unwrap();
        let mut channel = handshake_initiator(stream, &pinned).unwrap();
        channel.send(&payload).unwrap();
        let echoed = channel.recv(Instant::now() + REQUEST_DEADLINE).unwrap();
        server.join().unwrap();
        assert_eq!(echoed, expected);
    }

    struct Running {
        addr: SocketAddr,
        pinned: [u8; 32],
        stop: Arc<AtomicBool>,
        server: thread::JoinHandle<Result<(), RuntimeError>>,
        card: crate::node::NodeCard,
        client: Client,
    }

    fn start(limits: ServerLimits) -> Running {
        let mut executor = Executor::lab().unwrap();
        let key = Arc::new(TransportKey::generate().unwrap());
        executor.set_transport_public(key.public());
        let card = executor.card([9u8; 32], 0).unwrap();
        let client = Client::new(executor.verifier(), card.advertisement.executor_id).unwrap();
        let pinned = key.public();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server = thread::spawn({
            let stop = Arc::clone(&stop);
            move || {
                serve_secure(
                    listener,
                    key,
                    Arc::new(Mutex::new(executor)),
                    limits,
                    Arc::new(|| 10),
                    stop,
                )
            }
        });
        Running {
            addr,
            pinned,
            stop,
            server,
            card,
            client,
        }
    }

    impl Running {
        fn job(&self, job: u8) -> Result<(), RuntimeError> {
            let mut req = request(CANARY);
            req.job_id[31] = job;
            self.client
                .complete(&self.card, &req, |sealed| {
                    exchange_secure(self.addr, &self.pinned, sealed)
                })
                .map(|_| ())
        }

        /// A job retried until a freed slot lets it through, for at most two seconds.
        fn job_soon(&self, job: u8) -> Result<(), RuntimeError> {
            let until = Instant::now() + Duration::from_secs(2);
            loop {
                match self.job(job) {
                    Ok(()) => return Ok(()),
                    Err(err) if Instant::now() >= until => return Err(err),
                    Err(_) => thread::sleep(Duration::from_millis(50)),
                }
            }
        }

        fn shut_down(self) {
            self.stop.store(true, Ordering::Release);
            self.server.join().unwrap().unwrap();
        }
    }

    /// True when the server closed the connection without waiting for bytes.
    fn closed_unread(stream: &mut TcpStream) -> bool {
        stream
            .set_read_timeout(Some(Duration::from_millis(800)))
            .unwrap();
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => true,
            Ok(_) => false,
            Err(err) => !matches!(
                err.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
        }
    }

    #[test]
    fn two_clients_at_once_both_get_correct_results() {
        let running = Arc::new(start(ServerLimits::default()));
        let handles: Vec<_> = (1..=2u8)
            .map(|job| {
                let running = Arc::clone(&running);
                thread::spawn(move || running.job(job))
            })
            .collect();
        for handle in handles {
            handle.join().unwrap().unwrap();
        }
        Arc::into_inner(running).unwrap().shut_down();
    }

    #[test]
    fn connections_past_the_total_bound_are_closed_unread_while_a_job_still_finishes() {
        let running = start(ServerLimits {
            max_connections: 3,
            max_per_peer: 10,
        });
        let mut held = vec![
            TcpStream::connect(running.addr).unwrap(),
            TcpStream::connect(running.addr).unwrap(),
        ];
        thread::sleep(Duration::from_millis(150));
        running.job(1).unwrap();
        held.push(TcpStream::connect(running.addr).unwrap());
        thread::sleep(Duration::from_millis(150));
        let mut over = TcpStream::connect(running.addr).unwrap();
        assert!(closed_unread(&mut over));
        drop(held);
        running.shut_down();
    }

    #[test]
    fn connections_past_the_per_peer_bound_are_closed_and_the_slot_frees_on_close() {
        let running = start(ServerLimits {
            max_connections: 10,
            max_per_peer: 2,
        });
        let held = vec![
            TcpStream::connect(running.addr).unwrap(),
            TcpStream::connect(running.addr).unwrap(),
        ];
        thread::sleep(Duration::from_millis(150));
        let mut over = TcpStream::connect(running.addr).unwrap();
        assert!(closed_unread(&mut over));
        drop(held);
        running.job_soon(2).unwrap();
        running.shut_down();
    }

    #[test]
    fn a_failed_handshake_frees_its_slot() {
        let running = start(ServerLimits {
            max_connections: 1,
            max_per_peer: 1,
        });
        let mut bad = TcpStream::connect(running.addr).unwrap();
        bad.write_all(&[0, 48]).unwrap();
        bad.write_all(&[0xAB; 48]).unwrap();
        running.job_soon(3).unwrap();
        running.shut_down();
    }

    #[test]
    fn the_stop_flag_ends_the_serving_loop() {
        let running = start(ServerLimits::default());
        let started = Instant::now();
        running.shut_down();
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_card_request_returns_a_card_bound_to_the_nonce() {
        let (mut executor, key, listener, addr) = node();
        let pinned = key.public();
        let measurement = executor.status().measurement;
        let verifier = executor.verifier();
        let worker =
            thread::spawn(move || serve_secure_one(&listener, &key, &mut executor, 10).unwrap());
        let card = fetch_card(addr, &pinned, [4u8; 32]).unwrap();
        worker.join().unwrap();
        assert_eq!(card.advertisement.nonce, [4u8; 32]);
        assert_eq!(card.advertisement.executor_id, measurement);
        assert!(!card.hardware_p2);
        let client = Client::new(verifier, measurement).unwrap();
        let mut req = request(CANARY);
        req.job_id[31] = 9;
        assert!(client
            .complete(&card, &req, |_| Err(RuntimeError::Wire))
            .is_err());
    }

    #[test]
    fn a_card_with_the_wrong_nonce_digest_key_or_trailing_byte_is_refused() {
        let mut executor = Executor::lab().unwrap();
        executor.set_transport_public([8u8; 32]);
        let card = executor.card([4u8; 32], 0).unwrap();
        let mut body = card.model_digest.to_vec();
        body.extend_from_slice(&card.advertisement.to_bytes().unwrap());
        let nonce = [4u8; 32];
        let pinned = [8u8; 32];
        assert!(check_card(&body, &nonce, &pinned).is_ok());
        assert_eq!(
            check_card(&body, &[5u8; 32], &pinned).unwrap_err(),
            RuntimeError::Envelope(EnvelopeError::StaleAdvertisement)
        );
        assert_eq!(
            check_card(&body, &nonce, &[9u8; 32]).unwrap_err(),
            RuntimeError::Envelope(EnvelopeError::KeyMismatch)
        );
        let mut wrong_digest = body.clone();
        wrong_digest[0] ^= 1;
        assert_eq!(
            check_card(&wrong_digest, &nonce, &pinned).unwrap_err(),
            RuntimeError::ModelMismatch
        );
        let mut trailing = body.clone();
        trailing.push(0);
        assert!(check_card(&trailing, &nonce, &pinned).is_err());
        assert!(check_card(&body[..20], &nonce, &pinned).is_err());
        assert!(check_card(&[], &nonce, &pinned).is_err());
    }

    #[test]
    fn a_card_that_names_no_transport_key_is_refused_even_when_pinned_as_zero() {
        let executor = Executor::lab().unwrap();
        let card = executor.card([4u8; 32], 0).unwrap();
        assert_eq!(card.advertisement.transport_public, [0u8; 32]);
        let mut body = card.model_digest.to_vec();
        body.extend_from_slice(&card.advertisement.to_bytes().unwrap());
        assert_eq!(
            check_card(&body, &[4u8; 32], &[0u8; 32]).unwrap_err(),
            RuntimeError::Envelope(EnvelopeError::KeyMismatch)
        );
        assert_eq!(
            check_card(&body, &[4u8; 32], &[8u8; 32]).unwrap_err(),
            RuntimeError::Envelope(EnvelopeError::KeyMismatch)
        );
    }

    #[test]
    fn a_node_that_advertises_a_different_key_than_it_serves_on_is_refused() {
        let (mut executor, key, listener, addr) = node();
        executor.set_transport_public(TransportKey::generate().unwrap().public());
        let pinned = key.public();
        let worker =
            thread::spawn(move || serve_secure_one(&listener, &key, &mut executor, 10).unwrap());
        assert_eq!(
            fetch_card(addr, &pinned, [4u8; 32]).unwrap_err(),
            RuntimeError::Envelope(EnvelopeError::KeyMismatch)
        );
        worker.join().unwrap();
    }

    #[test]
    fn a_card_request_that_is_not_a_32_byte_nonce_closes_the_connection() {
        for payload_len in [0usize, 31, 33] {
            let (executor, key, listener, addr) = node();
            let pinned = key.public();
            let worker = serve_expecting_refusal(executor, key, listener);
            let mut peer = RawPeer::connect(addr, &pinned);
            let mut frame = u32::try_from(1 + payload_len)
                .unwrap()
                .to_be_bytes()
                .to_vec();
            frame.push(KIND_CARD);
            frame.extend(std::iter::repeat_n(0u8, payload_len));
            let cipher = peer.encrypt(&frame);
            peer.write_raw(&cipher);
            let (served, ran) = worker.join().unwrap();
            assert_eq!(served, Err(RuntimeError::Wire), "payload {payload_len}");
            assert!(!ran);
        }
    }

    #[test]
    fn an_unknown_request_kind_closes_the_connection() {
        let (executor, key, listener, addr) = node();
        let pinned = key.public();
        let worker = serve_expecting_refusal(executor, key, listener);
        let mut peer = RawPeer::connect(addr, &pinned);
        let mut frame = 2u32.to_be_bytes().to_vec();
        frame.extend_from_slice(&[9, 0]);
        let cipher = peer.encrypt(&frame);
        peer.write_raw(&cipher);
        let (served, ran) = worker.join().unwrap();
        assert_eq!(served, Err(RuntimeError::Wire));
        assert!(!ran);
    }

    #[test]
    fn a_route_that_dies_after_the_request_is_written_is_not_retried_on_the_next_route() {
        let (executor, key, listener, addr) = node();
        let dying_key = TransportKey::generate().unwrap();
        let dying = TcpListener::bind("127.0.0.1:0").unwrap();
        let dying_addr = dying.local_addr().unwrap();
        let pinned = dying_key.public();
        let killer = thread::spawn(move || {
            let (stream, _) = dying.accept().unwrap();
            let mut channel = handshake_responder(stream, &dying_key).unwrap();
            let request = channel.recv(Instant::now() + REQUEST_DEADLINE).unwrap();
            assert!(!request.is_empty());
            // Closes without answering: the request was written and is now unanswerable.
        });
        // The second route is a live node that would answer if it were ever contacted.
        listener.set_nonblocking(true).unwrap();
        let routes = [Route::Direct(dying_addr), Route::Direct(addr)];
        let out = exchange_secure_via(&routes, &pinned, &[7u8; 64]);
        assert_eq!(out, Err(RuntimeError::Wire));
        killer.join().unwrap();
        let untouched = listener.accept();
        assert!(
            matches!(&untouched, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "the next route was contacted after the request was written"
        );
        drop((executor, key));
    }

    #[test]
    fn the_transport_key_is_not_printed() {
        let key = TransportKey::generate().unwrap();
        assert_eq!(format!("{key:?}"), "TransportKey { redacted }");
    }
}
