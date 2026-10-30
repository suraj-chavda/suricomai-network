// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Relay: carries the bytes of a node channel it cannot read. Rules are in the protocol specification, "Relay".

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::RuntimeError;
use crate::transport::{read_exact_by, take_slot, ServerLimits, Slots, HANDSHAKE_DEADLINE};

/// First four bytes a client sends to a relay.
pub(crate) const PREAMBLE_MAGIC: &[u8; 4] = b"SRL1";

/// Most upstreams a relay can name, because the index is one byte.
const MAX_UPSTREAMS: usize = 256;

/// Bounds on what one relay process will carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayLimits {
    /// Connections and per-peer connections held open at once.
    pub connections: ServerLimits,
    /// Most bytes carried in each direction of one connection.
    pub max_bytes_per_direction: u64,
    /// Longest one connection may live.
    pub lifetime: Duration,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            connections: ServerLimits::default(),
            max_bytes_per_direction: 9 * 1024 * 1024,
            lifetime: Duration::from_secs(180),
        }
    }
}

/// Copy `from` to `to` until `from` ends. Any error, a cap breach or the deadline cuts
/// both sockets so the other direction stops too. Bytes past the cap are never forwarded.
fn pump(mut from: TcpStream, mut to: TcpStream, cap: u64, deadline: Instant) {
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    let clean = loop {
        let Some(left) = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
        else {
            break false;
        };
        if from.set_read_timeout(Some(left)).is_err() {
            break false;
        }
        match from.read(&mut buf) {
            Ok(0) => break true,
            Ok(n) => {
                total = total.saturating_add(n as u64);
                if total > cap || to.write_all(&buf[..n]).is_err() {
                    break false;
                }
            }
            Err(_) => break false,
        }
    };
    if clean {
        let _ = to.shutdown(Shutdown::Write);
    } else {
        let _ = from.shutdown(Shutdown::Both);
        let _ = to.shutdown(Shutdown::Both);
    }
}

fn carry(
    client: TcpStream,
    upstreams: &[SocketAddr],
    limits: RelayLimits,
) -> Result<(), RuntimeError> {
    let deadline = Instant::now() + limits.lifetime;
    let mut preamble = [0u8; 5];
    let mut reader = client.try_clone().map_err(|_| RuntimeError::Wire)?;
    read_exact_by(
        &mut reader,
        &mut preamble,
        (Instant::now() + HANDSHAKE_DEADLINE).min(deadline),
    )?;
    if &preamble[..4] != PREAMBLE_MAGIC {
        return Err(RuntimeError::Wire);
    }
    let upstream = *upstreams
        .get(usize::from(preamble[4]))
        .ok_or(RuntimeError::Wire)?;
    let node = TcpStream::connect_timeout(&upstream, HANDSHAKE_DEADLINE)
        .map_err(|_| RuntimeError::Wire)?;
    for socket in [&client, &node] {
        socket.set_nodelay(true).map_err(|_| RuntimeError::Wire)?;
        socket
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|_| RuntimeError::Wire)?;
    }
    let cap = limits.max_bytes_per_direction;
    let (client_in, node_out) = (
        client.try_clone().map_err(|_| RuntimeError::Wire)?,
        node.try_clone().map_err(|_| RuntimeError::Wire)?,
    );
    let back = thread::Builder::new()
        .spawn(move || pump(node, client, cap, deadline))
        .map_err(|_| RuntimeError::Wire)?;
    pump(client_in, node_out, cap, deadline);
    let _ = back.join();
    Ok(())
}

/// Carry node channels to the configured `upstreams` until `stop` is set.
///
/// The relay holds no keys and reads only the 5-byte preamble. A connection past the
/// bounds, with a bad preamble, or naming an index past the list is closed unread.
pub fn serve_relay(
    listener: TcpListener,
    upstreams: Vec<SocketAddr>,
    limits: RelayLimits,
    stop: Arc<AtomicBool>,
) -> Result<(), RuntimeError> {
    if upstreams.is_empty() || upstreams.len() > MAX_UPSTREAMS {
        return Err(RuntimeError::BadRequest);
    }
    listener
        .set_nonblocking(true)
        .map_err(|_| RuntimeError::Wire)?;
    let upstreams: Arc<[SocketAddr]> = upstreams.into();
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
        let Some(guard) = take_slot(&slots, peer.ip().to_canonical(), limits.connections) else {
            continue;
        };
        if stream.set_nonblocking(false).is_err() {
            continue;
        }
        let upstreams = Arc::clone(&upstreams);
        let spawned = thread::Builder::new().spawn(move || {
            let _held = guard;
            let _ = carry(stream, &upstreams, limits);
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

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use super::*;
    use crate::testkit::node;
    use crate::transport::{fetch_card_via, Route};

    struct Relay {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        thread: thread::JoinHandle<Result<(), RuntimeError>>,
    }

    fn relay(upstreams: Vec<SocketAddr>, limits: RelayLimits) -> Relay {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let thread = thread::spawn({
            let stop = Arc::clone(&stop);
            move || serve_relay(listener, upstreams, limits, stop)
        });
        Relay { addr, stop, thread }
    }

    impl Relay {
        fn shut_down(self) {
            self.stop.store(true, Ordering::Release);
            self.thread.join().unwrap().unwrap();
        }
    }

    fn quiet_upstream() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    fn never_contacted(listener: &TcpListener) -> bool {
        thread::sleep(Duration::from_millis(300));
        matches!(listener.accept(), Err(e) if e.kind() == ErrorKind::WouldBlock)
    }

    fn closed_by_peer(stream: &mut TcpStream, within: Duration) -> bool {
        stream.set_read_timeout(Some(within)).unwrap();
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) => !matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
        }
    }

    fn dead_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    }

    #[test]
    fn a_job_through_a_relay_matches_a_direct_job() {
        let node = node();
        let relay = relay(vec![node.addr], RelayLimits::default());
        let direct = node.job(&[Route::Direct(node.addr)], 1).unwrap();
        let relayed = node
            .job(
                &[Route::Relay {
                    relay: relay.addr,
                    upstream: 0,
                }],
                2,
            )
            .unwrap();
        assert_eq!(direct, relayed);
        let card = fetch_card_via(
            &[Route::Relay {
                relay: relay.addr,
                upstream: 0,
            }],
            &node.pinned,
            [4u8; 32],
        )
        .unwrap();
        assert_eq!(card.advertisement.transport_public, node.pinned);
        relay.shut_down();
        node.shut_down();
    }

    #[test]
    fn a_bad_silent_short_or_out_of_range_preamble_never_reaches_an_upstream() {
        let (upstream, upstream_addr) = quiet_upstream();
        let relay = relay(vec![upstream_addr], RelayLimits::default());
        for bytes in [
            b"SRL2\x00".to_vec(),
            b"XXXX\x00".to_vec(),
            b"SRL1\x01".to_vec(),
            b"SRL1\xff".to_vec(),
            b"SRL".to_vec(),
        ] {
            let mut client = TcpStream::connect(relay.addr).unwrap();
            client.write_all(&bytes).unwrap();
            if bytes.len() < 5 {
                client.shutdown(Shutdown::Write).unwrap();
            }
            assert!(
                closed_by_peer(&mut client, Duration::from_secs(3)),
                "{bytes:?}"
            );
        }
        let mut silent = TcpStream::connect(relay.addr).unwrap();
        assert!(closed_by_peer(
            &mut silent,
            HANDSHAKE_DEADLINE + Duration::from_secs(2)
        ));
        assert!(never_contacted(&upstream));
        relay.shut_down();
    }

    #[test]
    fn a_relay_without_upstreams_does_not_start() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let out = serve_relay(
            listener,
            Vec::new(),
            RelayLimits::default(),
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(out, Err(RuntimeError::BadRequest));
    }

    #[test]
    fn an_unreachable_upstream_fails_over_to_the_direct_route() {
        let node = node();
        let relay = relay(vec![dead_addr()], RelayLimits::default());
        let routes = [
            Route::Relay {
                relay: relay.addr,
                upstream: 0,
            },
            Route::Direct(node.addr),
        ];
        node.job(&routes, 3).unwrap();
        relay.shut_down();
        node.shut_down();
    }

    #[test]
    fn a_stopped_relay_does_not_stall_a_direct_job() {
        let node = node();
        let gone = dead_addr();
        let routes = [
            Route::Relay {
                relay: gone,
                upstream: 0,
            },
            Route::Direct(node.addr),
        ];
        let started = Instant::now();
        node.job(&routes, 4).unwrap();
        assert!(started.elapsed() < Duration::from_secs(3));
        node.shut_down();
    }

    #[test]
    fn a_relay_that_accepts_and_says_nothing_fails_over_within_the_handshake_budget() {
        let node = node();
        let stalled = TcpListener::bind("127.0.0.1:0").unwrap();
        let stalled_addr = stalled.local_addr().unwrap();
        let holder = thread::spawn(move || {
            let (stream, _) = stalled.accept().unwrap();
            thread::sleep(Duration::from_secs(12));
            drop(stream);
        });
        let routes = [
            Route::Relay {
                relay: stalled_addr,
                upstream: 0,
            },
            Route::Direct(node.addr),
        ];
        let started = Instant::now();
        node.job(&routes, 5).unwrap();
        assert!(started.elapsed() < Duration::from_secs(12));
        holder.join().unwrap();
        node.shut_down();
    }

    #[test]
    fn a_connection_past_the_byte_cap_is_cut_and_the_upstream_sees_no_more_than_the_cap() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let reader = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut total = 0usize;
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => total += n,
                }
            }
            total
        });
        let relay = relay(
            vec![upstream_addr],
            RelayLimits {
                max_bytes_per_direction: 100,
                ..RelayLimits::default()
            },
        );
        let mut client = TcpStream::connect(relay.addr).unwrap();
        client.write_all(b"SRL1\x00").unwrap();
        let _ = client.write_all(&[7u8; 1_000]);
        assert!(closed_by_peer(&mut client, Duration::from_secs(3)));
        assert!(reader.join().unwrap() <= 100);
        relay.shut_down();
    }

    #[test]
    fn a_connection_is_cut_at_its_lifetime() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let holder = thread::spawn(move || {
            let (stream, _) = upstream.accept().unwrap();
            thread::sleep(Duration::from_secs(4));
            drop(stream);
        });
        let relay = relay(
            vec![upstream_addr],
            RelayLimits {
                lifetime: Duration::from_secs(1),
                ..RelayLimits::default()
            },
        );
        let started = Instant::now();
        let mut client = TcpStream::connect(relay.addr).unwrap();
        client.write_all(b"SRL1\x00").unwrap();
        assert!(closed_by_peer(&mut client, Duration::from_secs(3)));
        assert!(started.elapsed() < Duration::from_millis(2_500));
        holder.join().unwrap();
        relay.shut_down();
    }

    #[test]
    fn connections_past_the_bounds_are_closed_unread_and_slots_free_on_close() {
        let node = node();
        let relay = relay(
            vec![node.addr],
            RelayLimits {
                connections: ServerLimits {
                    max_connections: 10,
                    max_per_peer: 2,
                },
                ..RelayLimits::default()
            },
        );
        let held = vec![
            TcpStream::connect(relay.addr).unwrap(),
            TcpStream::connect(relay.addr).unwrap(),
        ];
        thread::sleep(Duration::from_millis(150));
        let mut over = TcpStream::connect(relay.addr).unwrap();
        assert!(closed_by_peer(&mut over, Duration::from_millis(800)));
        drop(held);
        let routes = [Route::Relay {
            relay: relay.addr,
            upstream: 0,
        }];
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            match node.job(&routes, 6) {
                Ok(_) => break,
                Err(err) if Instant::now() >= until => panic!("slot never freed: {err}"),
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
        relay.shut_down();
        node.shut_down();
    }
}
