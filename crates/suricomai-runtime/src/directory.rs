// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Directory of nodes a client can try. Rules are in the protocol specification, "Directory".
//!
//! It is an index and a hint. It stores only what its own probe of an address returned,
//! and a client that picks a listed node still checks that node's card itself.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rand::rngs::OsRng;
use rand::RngCore;
use suricomai_envelope::{verify_advertisement, EnvelopeError, LabVerifier, MeasurementAllowlist};

use crate::error::RuntimeError;
use crate::model::{model_digest, pinned_weights, runtime_measurement};
use crate::transport::{fetch_card, request_direct, Handler};
use crate::wire::tagged;

const KIND_PUBLISH: u8 = 4;
const KIND_LIST: u8 = 5;
const ENTRY_LEN: usize = 1 + 16 + 2 + 32 + 32 + 32 + 8;
const PAGE: usize = 32;
const MAX_TRACKED_PEERS: usize = 4_096;
/// Most list pages read from one peer in one round.
pub const MAX_SYNC_PAGES: usize = 4;

/// One listed node, as the directory's own probe saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// Where the node answered.
    pub addr: SocketAddr,
    /// Transport key the node proved it holds.
    pub transport_key: [u8; 32],
    /// Model the node's card named.
    pub model_digest: [u8; 32],
    /// Measurement or worker id from the verified advertisement.
    pub executor_id: [u8; 32],
    /// End of the advertisement window the probe saw.
    pub valid_until: u64,
}

/// What a directory accepts and how much it holds.
pub struct DirectoryConfig {
    /// Quote roots a probed advertisement may verify under.
    pub roots: Vec<LabVerifier>,
    /// Permit loopback and private addresses. A development network on one machine needs it.
    pub allow_local: bool,
    /// Most live entries.
    pub max_entries: usize,
    /// Most publishes from one peer IP address per window.
    pub publishes_per_window: usize,
    /// Length of that window in seconds.
    pub window_secs: u64,
    /// Most probes at once.
    pub max_probes: usize,
    /// Longest an entry lives after its probe, in seconds.
    pub ttl_secs: u64,
    /// Entries per list page, at most 32.
    pub page_size: usize,
    /// Seconds between rounds of learning from peers. A claim with less than this left is probed again.
    pub sync_secs: u64,
    /// Most probes per peer per round.
    pub sync_budget: usize,
}

impl DirectoryConfig {
    /// The limits in the protocol specification, for the given accepted roots.
    pub fn new(roots: Vec<LabVerifier>) -> Self {
        Self {
            roots,
            allow_local: false,
            max_entries: 1_024,
            publishes_per_window: 4,
            window_secs: 60,
            max_probes: 8,
            ttl_secs: 600,
            page_size: PAGE,
            sync_secs: 60,
            sync_budget: 16,
        }
    }
}

struct Stored {
    entry: DirectoryEntry,
    expires_at: u64,
}

#[derive(Default)]
struct State {
    next_seq: u64,
    entries: BTreeMap<u64, Stored>,
    by_addr: HashMap<SocketAddr, u64>,
    by_key: HashMap<[u8; 32], u64>,
    publishes: HashMap<IpAddr, Vec<u64>>,
}

/// What one round of learning from a peer did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Claims that passed this directory's own probe and are now listed.
    pub listed: usize,
    /// Claims probed this round, whether they passed or not.
    pub probed: usize,
    /// Claims not probed or not listed: refused by policy, already fresh, over budget, or failed.
    pub skipped: usize,
}

/// The table and the rules around it.
pub struct Directory {
    config: DirectoryConfig,
    allowlist: MeasurementAllowlist,
    state: Mutex<State>,
    probing: AtomicUsize,
}

/// Frees a probe slot on every exit path.
struct ProbeSlot<'a>(&'a AtomicUsize);

impl Drop for ProbeSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// True when a client or a directory may connect to `addr`.
///
/// This keeps a directory from being used to open connections into a private network,
/// and keeps a client from being steered at one.
pub fn address_allowed(addr: &SocketAddr, allow_local: bool) -> bool {
    if addr.port() == 0 {
        return false;
    }
    match addr.ip().to_canonical() {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            if ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_link_local()
                || ip.is_documentation()
                || o[0] == 0
            {
                return false;
            }
            let local = ip.is_loopback() || ip.is_private() || (o[0] == 100 && o[1] & 0xc0 == 64);
            !local || allow_local
        }
        IpAddr::V6(ip) => {
            let seg = ip.segments();
            if ip.is_unspecified() || ip.is_multicast() || seg[0] & 0xffc0 == 0xfe80 {
                return false;
            }
            let local = ip.is_loopback() || seg[0] & 0xfe00 == 0xfc00;
            !local || allow_local
        }
    }
}

fn busy() -> Vec<u8> {
    tagged(1, RuntimeError::Busy.code().as_bytes())
}

fn refused(err: RuntimeError) -> Vec<u8> {
    tagged(1, err.code().as_bytes())
}

impl Directory {
    /// A directory with `config`. It accepts the one measurement the built-in model runs under.
    pub fn new(config: DirectoryConfig) -> Self {
        let mut allowlist = MeasurementAllowlist::new();
        allowlist.insert(runtime_measurement(&model_digest(&pinned_weights())));
        Self {
            config,
            allowlist,
            state: Mutex::new(State::default()),
            probing: AtomicUsize::new(0),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // The table holds only values the probe produced, and every update is a few map
        // operations, so a panic elsewhere leaves it usable.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Count this publish against the peer's window. False when the peer is over its quota.
    fn within_quota(&self, peer: IpAddr, now: u64) -> bool {
        let mut state = self.lock();
        let window = self.config.window_secs;
        if !state.publishes.contains_key(&peer) && state.publishes.len() >= MAX_TRACKED_PEERS {
            state.publishes.retain(|_, times| {
                times.retain(|t| now.saturating_sub(*t) < window);
                !times.is_empty()
            });
            if state.publishes.len() >= MAX_TRACKED_PEERS {
                return false;
            }
        }
        let times = state.publishes.entry(peer).or_default();
        times.retain(|t| now.saturating_sub(*t) < window);
        if times.len() >= self.config.publishes_per_window {
            return false;
        }
        times.push(now);
        true
    }

    /// Fetch a card from `addr` and check it as a client would, under any accepted root.
    fn probe(
        &self,
        addr: SocketAddr,
        key: &[u8; 32],
        now: u64,
    ) -> Result<DirectoryEntry, RuntimeError> {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let card = fetch_card(addr, key, nonce)?;
        // Report the most specific reason: a stale window or a rejected measurement says
        // more than "this root did not match".
        let mut refusal = None;
        let mut verified = false;
        for root in &self.config.roots {
            match verify_advertisement(&card.advertisement, &self.allowlist, root, now) {
                Ok(_) => {
                    verified = true;
                    break;
                }
                Err(EnvelopeError::BadQuote) => {
                    refusal.get_or_insert(EnvelopeError::BadQuote);
                }
                Err(other) => refusal = Some(other),
            }
        }
        if !verified {
            return Err(RuntimeError::Envelope(
                refusal.unwrap_or(EnvelopeError::BadQuote),
            ));
        }
        Ok(DirectoryEntry {
            addr,
            transport_key: *key,
            model_digest: card.model_digest,
            executor_id: card.advertisement.executor_id,
            valid_until: card.advertisement.valid_until,
        })
    }

    fn publish(
        &self,
        peer: IpAddr,
        body: &[u8],
        clock: &(dyn Fn() -> u64 + Send + Sync),
    ) -> Result<Vec<u8>, RuntimeError> {
        let (addr, key) = parse_publish(body)?;
        if !address_allowed(&addr, self.config.allow_local) {
            return Ok(refused(RuntimeError::BadRequest));
        }
        if !self.within_quota(peer, clock()) {
            return Ok(busy());
        }
        match self.admit(addr, &key, clock) {
            Ok(expires_at) => Ok(tagged(0, &expires_at.to_be_bytes())),
            Err(RuntimeError::Busy) => Ok(busy()),
            Err(err) => Ok(refused(err)),
        }
    }

    /// Probe `addr` and list it if the card passes. Returns when the entry expires.
    ///
    /// This is the only way an entry gets into the table, whether a publisher or a peer
    /// named the address. Everything stored comes from the probe.
    fn admit(
        &self,
        addr: SocketAddr,
        key: &[u8; 32],
        clock: &(dyn Fn() -> u64 + Send + Sync),
    ) -> Result<u64, RuntimeError> {
        if self.probing.fetch_add(1, Ordering::AcqRel) >= self.config.max_probes {
            self.probing.fetch_sub(1, Ordering::AcqRel);
            return Err(RuntimeError::Busy);
        }
        let _slot = ProbeSlot(&self.probing);
        // The probe runs without the table lock, so a slow address cannot stall a list.
        let entry = self.probe(addr, key, clock())?;
        let now = clock();
        let expires_at = entry
            .valid_until
            .min(now.saturating_add(self.config.ttl_secs));
        let mut state = self.lock();
        state.entries.retain(|_, stored| stored.expires_at > now);
        let State {
            entries,
            by_addr,
            by_key,
            ..
        } = &mut *state;
        by_addr.retain(|_, seq| entries.contains_key(seq));
        by_key.retain(|_, seq| entries.contains_key(seq));
        let replaces = by_addr.contains_key(&addr) || by_key.contains_key(key);
        if !replaces && entries.len() >= self.config.max_entries {
            return Err(RuntimeError::Busy);
        }
        for old in [by_addr.remove(&addr), by_key.remove(key)]
            .into_iter()
            .flatten()
        {
            entries.remove(&old);
        }
        state.next_seq += 1;
        let seq = state.next_seq;
        state.entries.insert(seq, Stored { entry, expires_at });
        state.by_addr.insert(addr, seq);
        state.by_key.insert(*key, seq);
        Ok(expires_at)
    }

    /// True when `addr` with `key` is listed and stays live for at least one more interval.
    fn is_fresh(&self, addr: &SocketAddr, key: &[u8; 32], now: u64) -> bool {
        let state = self.lock();
        state
            .by_addr
            .get(addr)
            .and_then(|seq| state.entries.get(seq))
            .is_some_and(|stored| {
                stored.entry.transport_key == *key
                    && stored.expires_at > now.saturating_add(self.config.sync_secs)
            })
    }

    /// Learn from one peer directory. Each address the peer lists is only a claim: it is
    /// admitted by this directory's own probe, so nothing the peer returned is stored.
    ///
    /// A peer that cannot be read, or that answers badly, changes nothing.
    pub fn sync_from(
        &self,
        peer: SocketAddr,
        peer_key: &[u8; 32],
        clock: &(dyn Fn() -> u64 + Send + Sync),
    ) -> Result<SyncReport, RuntimeError> {
        let mut report = SyncReport::default();
        let mut cursor = 0;
        for _ in 0..MAX_SYNC_PAGES {
            let (claims, next) = list_directory(peer, peer_key, cursor)?;
            for claim in claims {
                if !address_allowed(&claim.addr, self.config.allow_local)
                    || self.is_fresh(&claim.addr, &claim.transport_key, clock())
                    || report.probed >= self.config.sync_budget
                {
                    report.skipped += 1;
                    continue;
                }
                report.probed += 1;
                match self.admit(claim.addr, &claim.transport_key, clock) {
                    Ok(_) => report.listed += 1,
                    // The table or the probe bound is full. Stop and try next round.
                    Err(RuntimeError::Busy) => return Ok(report),
                    Err(_) => report.skipped += 1,
                }
            }
            if next == 0 {
                break;
            }
            cursor = next;
        }
        Ok(report)
    }

    fn list(&self, body: &[u8], now: u64) -> Result<Vec<u8>, RuntimeError> {
        let cursor = u64::from_be_bytes(body.try_into().map_err(|_| RuntimeError::Wire)?);
        let state = self.lock();
        let mut live = state
            .entries
            .range(cursor..)
            .filter(|(_, stored)| stored.expires_at > now);
        let page: Vec<_> = live
            .by_ref()
            .take(self.config.page_size.clamp(1, PAGE))
            .collect();
        let next = live.next().map_or(0, |(seq, _)| *seq);
        let mut out = Vec::with_capacity(9 + page.len() * ENTRY_LEN);
        out.extend_from_slice(&next.to_be_bytes());
        out.push(u8::try_from(page.len()).map_err(|_| RuntimeError::Wire)?);
        for (_, stored) in page {
            encode_entry(&stored.entry, &mut out);
        }
        Ok(tagged(0, &out))
    }
}

impl Handler for Directory {
    fn respond(
        &self,
        peer: IpAddr,
        request: &[u8],
        clock: &(dyn Fn() -> u64 + Send + Sync),
    ) -> Result<Vec<u8>, RuntimeError> {
        match request.split_first() {
            Some((&KIND_PUBLISH, body)) => self.publish(peer, body, clock),
            Some((&KIND_LIST, body)) => self.list(body, clock()),
            _ => Err(RuntimeError::Wire),
        }
    }
}

fn encode_addr(addr: &SocketAddr, out: &mut Vec<u8>) {
    match addr.ip().to_canonical() {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&[0u8; 12]);
        }
        IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

fn encode_entry(entry: &DirectoryEntry, out: &mut Vec<u8>) {
    encode_addr(&entry.addr, out);
    out.extend_from_slice(&entry.transport_key);
    out.extend_from_slice(&entry.model_digest);
    out.extend_from_slice(&entry.executor_id);
    out.extend_from_slice(&entry.valid_until.to_be_bytes());
}

fn decode_entry(row: &[u8; ENTRY_LEN]) -> Result<DirectoryEntry, RuntimeError> {
    let ip = match row[0] {
        4 => {
            if row[5..17].iter().any(|b| *b != 0) {
                return Err(RuntimeError::Wire);
            }
            IpAddr::V4(Ipv4Addr::new(row[1], row[2], row[3], row[4]))
        }
        6 => {
            let octets: [u8; 16] = row[1..17].try_into().map_err(|_| RuntimeError::Wire)?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return Err(RuntimeError::Wire),
    };
    let port = u16::from_be_bytes([row[17], row[18]]);
    if port == 0 {
        return Err(RuntimeError::Wire);
    }
    let field = |from: usize| -> Result<[u8; 32], RuntimeError> {
        row[from..from + 32]
            .try_into()
            .map_err(|_| RuntimeError::Wire)
    };
    Ok(DirectoryEntry {
        addr: SocketAddr::new(ip, port),
        transport_key: field(19)?,
        model_digest: field(51)?,
        executor_id: field(83)?,
        valid_until: u64::from_be_bytes(row[115..123].try_into().map_err(|_| RuntimeError::Wire)?),
    })
}

fn parse_publish(body: &[u8]) -> Result<(SocketAddr, [u8; 32]), RuntimeError> {
    let (family, rest) = body.split_first().ok_or(RuntimeError::Wire)?;
    let ip_len = match family {
        4 => 4,
        6 => 16,
        _ => return Err(RuntimeError::Wire),
    };
    if rest.len() != ip_len + 2 + 32 {
        return Err(RuntimeError::Wire);
    }
    let ip = if ip_len == 4 {
        IpAddr::V4(Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]))
    } else {
        let octets: [u8; 16] = rest[..16].try_into().map_err(|_| RuntimeError::Wire)?;
        IpAddr::V6(Ipv6Addr::from(octets))
    };
    let port = u16::from_be_bytes([rest[ip_len], rest[ip_len + 1]]);
    if port == 0 {
        return Err(RuntimeError::Wire);
    }
    let key: [u8; 32] = rest[ip_len + 2..]
        .try_into()
        .map_err(|_| RuntimeError::Wire)?;
    Ok((SocketAddr::new(ip, port), key))
}

/// Ask the directory at `directory` (holding `pinned`) to list the node at `node`.
///
/// Returns when the listing expires. The directory probes the node itself.
pub fn publish_to_directory(
    directory: SocketAddr,
    pinned: &[u8; 32],
    node: SocketAddr,
    node_key: &[u8; 32],
) -> Result<u64, RuntimeError> {
    let mut body = Vec::with_capacity(1 + 16 + 2 + 32);
    match node.ip().to_canonical() {
        IpAddr::V4(ip) => {
            body.push(4);
            body.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            body.push(6);
            body.extend_from_slice(&ip.octets());
        }
    }
    body.extend_from_slice(&node.port().to_be_bytes());
    body.extend_from_slice(node_key);
    let response = request_direct(directory, pinned, &tagged(KIND_PUBLISH, &body))?;
    let bytes: [u8; 8] = response
        .as_slice()
        .try_into()
        .map_err(|_| RuntimeError::Wire)?;
    Ok(u64::from_be_bytes(bytes))
}

/// One page of the directory, starting at `cursor` (`0` for the start).
///
/// The second value is the cursor for the next page, or `0` when there are no more.
/// Entries are hints: the caller still fetches and checks each node's card.
pub fn list_directory(
    directory: SocketAddr,
    pinned: &[u8; 32],
    cursor: u64,
) -> Result<(Vec<DirectoryEntry>, u64), RuntimeError> {
    let response = request_direct(directory, pinned, &tagged(KIND_LIST, &cursor.to_be_bytes()))?;
    let (head, rows) = response.split_at_checked(9).ok_or(RuntimeError::Wire)?;
    let next = u64::from_be_bytes(head[..8].try_into().map_err(|_| RuntimeError::Wire)?);
    let count = usize::from(head[8]);
    if count > PAGE || rows.len() != count * ENTRY_LEN {
        return Err(RuntimeError::Wire);
    }
    let (rows, _) = rows.as_chunks::<ENTRY_LEN>();
    let entries = rows
        .iter()
        .map(decode_entry)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((entries, next))
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::testkit::{node, Node, NOW};
    use crate::transport::{serve_secure, ServerLimits, TransportKey};

    struct Dir {
        directory: Arc<Directory>,
        addr: SocketAddr,
        pinned: [u8; 32],
        clock: Arc<AtomicU64>,
        stop: Arc<AtomicBool>,
        thread: thread::JoinHandle<Result<(), RuntimeError>>,
    }

    fn dir(config: DirectoryConfig) -> Dir {
        let key = Arc::new(TransportKey::generate().unwrap());
        let pinned = key.public();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let clock = Arc::new(AtomicU64::new(NOW));
        let stop = Arc::new(AtomicBool::new(false));
        let directory = Arc::new(Directory::new(config));
        let thread = thread::spawn({
            let (clock, stop, directory) = (
                Arc::clone(&clock),
                Arc::clone(&stop),
                Arc::clone(&directory),
            );
            move || {
                serve_secure(
                    listener,
                    key,
                    directory,
                    // Wide enough that these tests meet the directory's own bounds, not the
                    // connection bound.
                    ServerLimits {
                        max_connections: 64,
                        max_per_peer: 32,
                    },
                    Arc::new(move || clock.load(Ordering::Acquire)),
                    stop,
                )
            }
        });
        Dir {
            directory,
            addr,
            pinned,
            clock,
            stop,
            thread,
        }
    }

    fn local(roots: Vec<LabVerifier>) -> DirectoryConfig {
        DirectoryConfig {
            allow_local: true,
            ..DirectoryConfig::new(roots)
        }
    }

    impl Dir {
        fn publish(&self, node: &Node) -> Result<u64, RuntimeError> {
            publish_to_directory(self.addr, &self.pinned, node.addr, &node.pinned)
        }

        fn list_all(&self) -> Vec<DirectoryEntry> {
            let mut all = Vec::new();
            let mut cursor = 0;
            loop {
                let (page, next) = list_directory(self.addr, &self.pinned, cursor).unwrap();
                all.extend(page);
                if next == 0 {
                    return all;
                }
                cursor = next;
            }
        }

        /// One round of learning from `peer`, on this directory's clock.
        fn sync_from(&self, peer: &Dir) -> Result<SyncReport, RuntimeError> {
            let clock = Arc::clone(&self.clock);
            self.directory.sync_from(peer.addr, &peer.pinned, &move || {
                clock.load(Ordering::Acquire)
            })
        }

        fn set_time(&self, now: u64) {
            self.clock.store(now, Ordering::Release);
        }

        fn shut_down(self) {
            self.stop.store(true, Ordering::Release);
            self.thread.join().unwrap().unwrap();
        }
    }

    fn dead_addr() -> SocketAddr {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    #[test]
    fn a_live_node_that_publishes_is_listed_with_what_the_probe_saw() {
        let node = node();
        let dir = dir(local(vec![node.verifier.clone()]));
        let expires = dir.publish(&node).unwrap();
        assert_eq!(expires, NOW + 600);
        let listed = dir.list_all();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].addr, node.addr);
        assert_eq!(listed[0].transport_key, node.pinned);
        assert_eq!(listed[0].executor_id, node.card.advertisement.executor_id);
        assert_eq!(listed[0].model_digest, node.card.model_digest);
        dir.shut_down();
        node.shut_down();
    }

    #[test]
    fn a_client_pages_through_the_cursor_and_sees_each_entry_once() {
        let nodes: Vec<_> = (0..5).map(|_| node()).collect();
        let roots = nodes.iter().map(|n| n.verifier.clone()).collect();
        let dir = dir(DirectoryConfig {
            page_size: 2,
            publishes_per_window: 100,
            ..local(roots)
        });
        for n in &nodes {
            dir.publish(n).unwrap();
        }
        let (first, next) = list_directory(dir.addr, &dir.pinned, 0).unwrap();
        assert_eq!(first.len(), 2);
        assert_ne!(next, 0);
        let all = dir.list_all();
        assert_eq!(all.len(), 5);
        let mut addrs: Vec<_> = all.iter().map(|e| e.addr).collect();
        addrs.sort();
        addrs.dedup();
        assert_eq!(addrs.len(), 5);
        let (past_the_end, next) = list_directory(dir.addr, &dir.pinned, u64::MAX).unwrap();
        assert!(past_the_end.is_empty());
        assert_eq!(next, 0);
        dir.shut_down();
        for n in nodes {
            n.shut_down();
        }
    }

    #[test]
    fn an_address_that_does_not_answer_or_holds_another_key_is_refused_and_not_listed() {
        let node = node();
        let dir = dir(local(vec![node.verifier.clone()]));
        let nobody = dead_addr();
        assert_eq!(
            publish_to_directory(dir.addr, &dir.pinned, nobody, &node.pinned),
            Err(RuntimeError::Unreachable)
        );
        let wrong_key = TransportKey::generate().unwrap().public();
        assert_eq!(
            publish_to_directory(dir.addr, &dir.pinned, node.addr, &wrong_key),
            Err(RuntimeError::Unreachable)
        );
        assert!(dir.list_all().is_empty());
        dir.shut_down();
        node.shut_down();
    }

    #[test]
    fn a_quote_under_an_unaccepted_root_or_outside_its_window_is_refused() {
        let node = node();
        let stranger = crate::Executor::lab().unwrap().verifier();
        let wrong_root = dir(local(vec![stranger]));
        assert_eq!(
            wrong_root.publish(&node),
            Err(RuntimeError::Envelope(
                suricomai_envelope::EnvelopeError::BadQuote
            ))
        );
        assert!(wrong_root.list_all().is_empty());
        wrong_root.shut_down();

        let stale = dir(local(vec![node.verifier.clone()]));
        stale.set_time(NOW + 100_000);
        assert_eq!(
            stale.publish(&node),
            Err(RuntimeError::Envelope(
                suricomai_envelope::EnvelopeError::StaleAdvertisement
            ))
        );
        assert!(stale.list_all().is_empty());
        stale.shut_down();
        node.shut_down();
    }

    #[test]
    fn the_address_policy_refuses_private_and_special_ranges_by_default() {
        let refused = [
            "0.0.0.0:80",
            "0.1.2.3:80",
            "127.0.0.1:80",
            "10.0.0.1:80",
            "172.16.0.1:80",
            "192.168.1.1:80",
            "100.64.0.1:80",
            "169.254.1.1:80",
            "224.0.0.1:80",
            "255.255.255.255:80",
            "192.0.2.1:80",
            "[::]:80",
            "[::1]:80",
            "[fc00::1]:80",
            "[fe80::1]:80",
            "[ff02::1]:80",
            "[::ffff:10.0.0.1]:80",
            "[::ffff:127.0.0.1]:80",
            "8.8.8.8:0",
        ];
        for text in refused {
            let addr: SocketAddr = text.parse().unwrap();
            assert!(!address_allowed(&addr, false), "{text}");
        }
        for text in [
            "8.8.8.8:80",
            "[2001:4860:4860::8888]:443",
            "[::ffff:8.8.8.8]:80",
        ] {
            let addr: SocketAddr = text.parse().unwrap();
            assert!(address_allowed(&addr, false), "{text}");
        }
        for text in ["127.0.0.1:80", "10.0.0.1:80", "[::1]:80", "[fc00::1]:80"] {
            let addr: SocketAddr = text.parse().unwrap();
            assert!(address_allowed(&addr, true), "{text}");
        }
        for text in [
            "0.0.0.0:80",
            "224.0.0.1:80",
            "[::]:80",
            "[fe80::1]:80",
            "8.8.8.8:0",
        ] {
            let addr: SocketAddr = text.parse().unwrap();
            assert!(!address_allowed(&addr, true), "{text} with allow_local");
        }
    }

    #[test]
    fn a_directory_without_allow_local_will_not_probe_a_loopback_node() {
        let node = node();
        let dir = dir(DirectoryConfig::new(vec![node.verifier.clone()]));
        assert_eq!(dir.publish(&node), Err(RuntimeError::BadRequest));
        assert!(dir.list_all().is_empty());
        dir.shut_down();
        node.shut_down();
    }

    #[test]
    fn the_fifth_publish_from_one_peer_in_a_window_is_busy_and_a_later_one_is_not() {
        let dir = dir(local(Vec::new()));
        let nobody = dead_addr();
        let key = [1u8; 32];
        for _ in 0..4 {
            assert_ne!(
                publish_to_directory(dir.addr, &dir.pinned, nobody, &key),
                Err(RuntimeError::Busy)
            );
        }
        assert_eq!(
            publish_to_directory(dir.addr, &dir.pinned, nobody, &key),
            Err(RuntimeError::Busy)
        );
        dir.set_time(NOW + 61);
        assert_ne!(
            publish_to_directory(dir.addr, &dir.pinned, nobody, &key),
            Err(RuntimeError::Busy)
        );
        dir.shut_down();
    }

    #[test]
    fn a_full_table_refuses_a_new_entry_keeps_the_old_ones_and_makes_room_on_expiry() {
        let nodes: Vec<_> = (0..3).map(|_| node()).collect();
        let roots = nodes.iter().map(|n| n.verifier.clone()).collect();
        let dir = dir(DirectoryConfig {
            max_entries: 2,
            publishes_per_window: 100,
            ..local(roots)
        });
        dir.publish(&nodes[0]).unwrap();
        dir.publish(&nodes[1]).unwrap();
        assert_eq!(dir.publish(&nodes[2]), Err(RuntimeError::Busy));
        assert_eq!(dir.list_all().len(), 2);
        assert_eq!(
            dir.publish(&nodes[0]).map(|_| ()),
            Ok(()),
            "refreshing a listed node needs no room"
        );
        dir.set_time(NOW + 601);
        assert!(dir.list_all().is_empty(), "expired entries are not listed");
        dir.publish(&nodes[2]).unwrap();
        assert_eq!(dir.list_all().len(), 1, "an expired entry made room");
        dir.shut_down();
        for n in nodes {
            n.shut_down();
        }
    }

    #[test]
    fn publishing_the_same_node_twice_leaves_one_entry() {
        let node = node();
        let dir = dir(local(vec![node.verifier.clone()]));
        dir.publish(&node).unwrap();
        dir.publish(&node).unwrap();
        assert_eq!(dir.list_all().len(), 1);
        dir.shut_down();
        node.shut_down();
    }

    #[test]
    fn probes_past_the_bound_are_busy_and_a_list_still_answers_meanwhile() {
        let stalled = TcpListener::bind("127.0.0.1:0").unwrap();
        let stalled_addr = stalled.local_addr().unwrap();
        let holder = thread::spawn(move || {
            let mut held = Vec::new();
            let until = Instant::now() + Duration::from_secs(7);
            stalled.set_nonblocking(true).unwrap();
            while Instant::now() < until {
                if let Ok((stream, _)) = stalled.accept() {
                    held.push(stream);
                }
                thread::sleep(Duration::from_millis(20));
            }
        });
        let dir = Arc::new(dir(DirectoryConfig {
            max_probes: 2,
            publishes_per_window: 100,
            ..local(Vec::new())
        }));
        let handles: Vec<_> = (0..5)
            .map(|_| {
                let dir = Arc::clone(&dir);
                thread::spawn(move || {
                    publish_to_directory(dir.addr, &dir.pinned, stalled_addr, &[1u8; 32])
                })
            })
            .collect();
        thread::sleep(Duration::from_millis(800));
        let started = Instant::now();
        assert!(list_directory(dir.addr, &dir.pinned, 0)
            .unwrap()
            .0
            .is_empty());
        assert!(started.elapsed() < Duration::from_secs(2));
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let busy_count = results
            .iter()
            .filter(|r| **r == Err(RuntimeError::Busy))
            .count();
        assert!(busy_count >= 3, "{results:?}");
        holder.join().unwrap();
        Arc::into_inner(dir).unwrap().shut_down();
    }

    #[test]
    fn malformed_publish_and_list_requests_close_the_connection() {
        let dir = dir(local(Vec::new()));
        let mut good = vec![4u8, 8, 8, 8, 8];
        good.extend_from_slice(&80u16.to_be_bytes());
        good.extend_from_slice(&[1u8; 32]);
        let mut bad_family = good.clone();
        bad_family[0] = 5;
        let mut zero_port = good.clone();
        zero_port[5] = 0;
        zero_port[6] = 0;
        let mut trailing = good.clone();
        trailing.push(0);
        let bodies: Vec<(u8, Vec<u8>)> = vec![
            (KIND_PUBLISH, Vec::new()),
            (KIND_PUBLISH, good[..good.len() - 1].to_vec()),
            (KIND_PUBLISH, bad_family),
            (KIND_PUBLISH, zero_port),
            (KIND_PUBLISH, trailing),
            (KIND_LIST, Vec::new()),
            (KIND_LIST, vec![0u8; 7]),
            (KIND_LIST, vec![0u8; 9]),
        ];
        for (kind, body) in bodies {
            let out = request_direct(dir.addr, &dir.pinned, &tagged(kind, &body));
            assert_eq!(out, Err(RuntimeError::Wire), "kind {kind} body {body:?}");
        }
        assert_eq!(
            request_direct(dir.addr, &dir.pinned, &tagged(9, &[])),
            Err(RuntimeError::Wire)
        );
        dir.shut_down();
    }

    /// A peer that answers a list request from a script, to stand in for a dishonest or
    /// broken directory. It never probes anything and stores nothing.
    struct Scripted {
        pages: Vec<Vec<u8>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl Handler for Scripted {
        fn respond(
            &self,
            _peer: IpAddr,
            request: &[u8],
            _clock: &(dyn Fn() -> u64 + Send + Sync),
        ) -> Result<Vec<u8>, RuntimeError> {
            if request.first() != Some(&KIND_LIST) {
                return Err(RuntimeError::Wire);
            }
            let call = self.calls.fetch_add(1, Ordering::AcqRel);
            let page = &self.pages[call.min(self.pages.len() - 1)];
            Ok(tagged(0, page))
        }
    }

    fn page_of(entries: &[DirectoryEntry], next: u64) -> Vec<u8> {
        let mut out = next.to_be_bytes().to_vec();
        out.push(u8::try_from(entries.len()).unwrap());
        for entry in entries {
            encode_entry(entry, &mut out);
        }
        out
    }

    fn claim(addr: SocketAddr, key: [u8; 32]) -> DirectoryEntry {
        DirectoryEntry {
            addr,
            transport_key: key,
            model_digest: [0u8; 32],
            executor_id: [0u8; 32],
            valid_until: u64::MAX,
        }
    }

    struct Peer {
        addr: SocketAddr,
        pinned: [u8; 32],
        script: Arc<Scripted>,
        stop: Arc<AtomicBool>,
        thread: thread::JoinHandle<Result<(), RuntimeError>>,
    }

    fn scripted_peer(pages: Vec<Vec<u8>>) -> Peer {
        let key = Arc::new(TransportKey::generate().unwrap());
        let pinned = key.public();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let script = Arc::new(Scripted {
            pages,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let thread = thread::spawn({
            let (script, stop) = (Arc::clone(&script), Arc::clone(&stop));
            move || {
                serve_secure(
                    listener,
                    key,
                    script,
                    ServerLimits {
                        max_connections: 64,
                        max_per_peer: 32,
                    },
                    Arc::new(|| NOW),
                    stop,
                )
            }
        });
        Peer {
            addr,
            pinned,
            script,
            stop,
            thread,
        }
    }

    impl Peer {
        fn shut_down(self) {
            self.stop.store(true, Ordering::Release);
            self.thread.join().unwrap().unwrap();
        }
    }

    fn sync_from_peer(dir: &Dir, peer: &Peer) -> Result<SyncReport, RuntimeError> {
        let clock = Arc::clone(&dir.clock);
        dir.directory.sync_from(peer.addr, &peer.pinned, &move || {
            clock.load(Ordering::Acquire)
        })
    }

    #[test]
    fn a_directory_learns_a_peers_live_node_from_its_own_probe() {
        let node = node();
        let a = dir(local(vec![node.verifier.clone()]));
        let b = dir(local(vec![node.verifier.clone()]));
        a.publish(&node).unwrap();
        assert!(b.list_all().is_empty());
        let report = b.sync_from(&a).unwrap();
        assert_eq!((report.listed, report.probed), (1, 1));
        let listed = b.list_all();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].addr, node.addr);
        assert_eq!(listed[0].transport_key, node.pinned);
        assert_eq!(listed[0].executor_id, node.card.advertisement.executor_id);
        a.shut_down();
        b.shut_down();
        node.shut_down();
    }

    #[test]
    fn a_directory_that_does_not_accept_the_nodes_root_lists_nothing_from_a_peer() {
        let node = node();
        let stranger = crate::Executor::lab().unwrap().verifier();
        let a = dir(local(vec![node.verifier.clone()]));
        let b = dir(local(vec![stranger]));
        a.publish(&node).unwrap();
        let report = b.sync_from(&a).unwrap();
        assert_eq!((report.listed, report.probed, report.skipped), (0, 1, 1));
        assert!(b.list_all().is_empty());
        a.shut_down();
        b.shut_down();
        node.shut_down();
    }

    #[test]
    fn a_fresh_entry_is_not_probed_again_and_the_budget_spreads_claims_over_rounds() {
        let nodes: Vec<_> = (0..5).map(|_| node()).collect();
        let roots: Vec<_> = nodes.iter().map(|n| n.verifier.clone()).collect();
        let a = dir(DirectoryConfig {
            publishes_per_window: 100,
            ..local(roots.clone())
        });
        for n in &nodes {
            a.publish(n).unwrap();
        }
        let b = dir(DirectoryConfig {
            sync_budget: 2,
            ..local(roots)
        });
        let first = b.sync_from(&a).unwrap();
        assert_eq!((first.listed, first.probed, first.skipped), (2, 2, 3));
        let second = b.sync_from(&a).unwrap();
        assert_eq!((second.listed, second.probed), (2, 2), "{second:?}");
        let third = b.sync_from(&a).unwrap();
        assert_eq!((third.listed, third.probed), (1, 1), "{third:?}");
        let fourth = b.sync_from(&a).unwrap();
        assert_eq!((fourth.listed, fourth.probed), (0, 0), "{fourth:?}");
        assert_eq!(b.list_all().len(), 5);
        a.shut_down();
        b.shut_down();
        for n in nodes {
            n.shut_down();
        }
    }

    #[test]
    fn claims_for_addresses_that_do_not_answer_or_hold_other_keys_list_nothing() {
        let node = node();
        let b = dir(local(vec![node.verifier.clone()]));
        let peer = scripted_peer(vec![page_of(
            &[
                claim(dead_addr(), [1u8; 32]),
                claim(node.addr, [2u8; 32]),
                claim(dead_addr(), node.pinned),
            ],
            0,
        )]);
        let report = sync_from_peer(&b, &peer).unwrap();
        assert_eq!((report.listed, report.probed), (0, 3));
        assert!(b.list_all().is_empty());
        peer.shut_down();
        b.shut_down();
        node.shut_down();
    }

    #[test]
    fn claims_in_private_ranges_are_not_probed_unless_local_is_allowed() {
        let b = dir(DirectoryConfig::new(Vec::new()));
        let claims: Vec<_> = [
            "127.0.0.1:9",
            "10.0.0.5:9",
            "192.168.1.5:9",
            "[::1]:9",
            "0.0.0.0:9",
        ]
        .iter()
        .map(|a| claim(a.parse().unwrap(), [1u8; 32]))
        .collect();
        let peer = scripted_peer(vec![page_of(&claims, 0)]);
        let report = sync_from_peer(&b, &peer).unwrap();
        assert_eq!((report.listed, report.probed, report.skipped), (0, 0, 5));
        peer.shut_down();
        b.shut_down();
    }

    #[test]
    fn a_peer_that_lists_more_claims_than_the_budget_causes_no_more_probes_than_the_budget() {
        let b = dir(DirectoryConfig {
            sync_budget: 3,
            ..local(Vec::new())
        });
        let claims: Vec<_> = (0..30u8).map(|i| claim(dead_addr(), [i + 1; 32])).collect();
        let peer = scripted_peer(vec![page_of(&claims, 0)]);
        let report = sync_from_peer(&b, &peer).unwrap();
        assert_eq!(report.probed, 3);
        assert_eq!(report.skipped, 30);
        peer.shut_down();
        b.shut_down();
    }

    #[test]
    fn a_peer_that_never_ends_its_listing_is_read_for_at_most_the_page_cap() {
        let b = dir(local(Vec::new()));
        let peer = scripted_peer(vec![page_of(&[], 7)]);
        let report = sync_from_peer(&b, &peer).unwrap();
        assert_eq!(report, SyncReport::default());
        assert_eq!(peer.script.calls.load(Ordering::Acquire), MAX_SYNC_PAGES);
        peer.shut_down();
        b.shut_down();
    }

    #[test]
    fn an_unreachable_or_malformed_peer_changes_nothing() {
        let node = node();
        let b = dir(local(vec![node.verifier.clone()]));
        let gone = Peer {
            addr: dead_addr(),
            pinned: [3u8; 32],
            script: Arc::new(Scripted {
                pages: vec![Vec::new()],
                calls: std::sync::atomic::AtomicUsize::new(0),
            }),
            stop: Arc::new(AtomicBool::new(false)),
            thread: thread::spawn(|| Ok(())),
        };
        assert_eq!(sync_from_peer(&b, &gone), Err(RuntimeError::Unreachable));

        let mut too_many = page_of(&[claim(node.addr, node.pinned)], 0);
        too_many[8] = 33;
        let mut short = page_of(&[claim(node.addr, node.pinned)], 0);
        short.pop();
        let mut bad_family = page_of(&[claim(node.addr, node.pinned)], 0);
        bad_family[9] = 9;
        for body in [too_many, short, bad_family, vec![1, 2, 3]] {
            let peer = scripted_peer(vec![body]);
            assert_eq!(sync_from_peer(&b, &peer), Err(RuntimeError::Wire));
            peer.shut_down();
        }
        assert!(b.list_all().is_empty());
        b.shut_down();
        node.shut_down();
    }

    #[test]
    fn a_full_table_ends_the_round_early_and_keeps_what_it_has() {
        let nodes: Vec<_> = (0..2).map(|_| node()).collect();
        let roots: Vec<_> = nodes.iter().map(|n| n.verifier.clone()).collect();
        let a = dir(DirectoryConfig {
            publishes_per_window: 100,
            ..local(roots.clone())
        });
        for n in &nodes {
            a.publish(n).unwrap();
        }
        let b = dir(DirectoryConfig {
            max_entries: 1,
            ..local(roots)
        });
        let report = b.sync_from(&a).unwrap();
        assert_eq!(report.listed, 1);
        assert_eq!(b.list_all().len(), 1);
        a.shut_down();
        b.shut_down();
        for n in nodes {
            n.shut_down();
        }
    }

    #[test]
    fn a_listing_with_a_bad_row_is_refused_by_the_client() {
        let entry = DirectoryEntry {
            addr: "8.8.8.8:80".parse().unwrap(),
            transport_key: [1u8; 32],
            model_digest: [2u8; 32],
            executor_id: [3u8; 32],
            valid_until: 9,
        };
        let mut row = Vec::new();
        encode_entry(&entry, &mut row);
        let good: [u8; ENTRY_LEN] = row.clone().try_into().unwrap();
        assert_eq!(decode_entry(&good).unwrap(), entry);

        let mut bad = good;
        bad[0] = 9;
        assert!(decode_entry(&bad).is_err());
        let mut bad = good;
        bad[10] = 1;
        assert!(decode_entry(&bad).is_err(), "v4 padding must be zero");
        let mut bad = good;
        bad[17] = 0;
        bad[18] = 0;
        assert!(decode_entry(&bad).is_err());
    }
}
