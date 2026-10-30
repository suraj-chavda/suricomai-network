// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! Client selection among nodes when the user does not pin one. Rules are in the protocol specification,
//! "Client selection". This is a client policy: nothing here goes on the wire, and it is
//! not the verifiable assignment that `assignment_vrf` is reserved for.

use std::net::SocketAddr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::{Rng, RngCore};

use crate::client::{Client, Completion, JobRequest};
use crate::error::RuntimeError;
use crate::node::NodeCard;
use crate::transport::{exchange_secure_via, fetch_card_bounded, fetch_model_card_bounded, Route};

/// Most candidates surveyed at once.
pub const SURVEY_CANDIDATES: usize = 8;

/// Total time a survey may take.
pub const SURVEY_DEADLINE: Duration = Duration::from_secs(6);

/// Which model the client wants served.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Wanted {
    /// The built-in lab model, run as a private-labelled lab job.
    Builtin,
    /// A hosted model, run as a non-private job. The name is for display only.
    Hosted {
        /// The model digest the client's catalog approves.
        digest: [u8; 32],
        /// The catalog's name for it.
        name: String,
    },
}

/// A node the client may choose, and the key it pins for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// Where the node answers.
    pub addr: SocketAddr,
    /// Transport key the client pins.
    pub key: [u8; 32],
}

/// A candidate that passed every client check, with the latency the client measured.
#[derive(Debug)]
pub struct Surveyed {
    /// The candidate.
    pub candidate: Candidate,
    /// Its card, already checked with [`Client::verify_card`].
    pub card: NodeCard,
    /// Time to connect, handshake and return the card.
    pub latency: Duration,
}

/// Order candidates by the pick rule. `latencies_ms[i]` belongs to candidate `i`, and
/// `draw` is the client's own random number.
///
/// The pool is every candidate within `max(2 * best, best + 50)` ms. The first index
/// returned is the pool member `draw` selects. The rest follow by latency, ties by index.
pub fn pick_order(latencies_ms: &[u64], draw: u64) -> Vec<usize> {
    let Some(best) = latencies_ms.iter().copied().min() else {
        return Vec::new();
    };
    let limit = best.saturating_mul(2).max(best.saturating_add(50));
    let pool: Vec<usize> = (0..latencies_ms.len())
        .filter(|&i| latencies_ms[i] <= limit)
        .collect();
    let first = pool[usize::try_from(draw % pool.len() as u64).unwrap_or(0)];
    let mut rest: Vec<usize> = (0..latencies_ms.len()).filter(|&i| i != first).collect();
    rest.sort_by_key(|&i| (latencies_ms[i], i));
    let mut order = vec![first];
    order.extend(rest);
    order
}

/// A uniform shuffle with the client's own randomness, then the first `keep`.
fn shuffle_take(mut candidates: Vec<Candidate>, keep: usize) -> Vec<Candidate> {
    for i in (1..candidates.len()).rev() {
        candidates.swap(i, OsRng.gen_range(0..=i));
    }
    candidates.truncate(keep);
    candidates
}

/// Fetch a card from each candidate in parallel and keep the ones that pass every check.
///
/// Returns within [`SURVEY_DEADLINE`] whatever the candidates do. A candidate that fails a
/// check, does not answer, or answers late is left out.
pub fn survey(
    client: &Client,
    candidates: &[Candidate],
    wanted: &Wanted,
    now: u64,
) -> Vec<Surveyed> {
    let started = Instant::now();
    let (send, receive) = mpsc::channel();
    for (index, candidate) in candidates.iter().copied().enumerate() {
        let send = send.clone();
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        // A stalled node holds its own thread for at most the survey deadline. The
        // survey does not wait for it.
        let wanted = wanted.clone();
        let _ = thread::Builder::new().spawn(move || {
            let card = match &wanted {
                Wanted::Builtin => {
                    fetch_card_bounded(candidate.addr, &candidate.key, nonce, SURVEY_DEADLINE)
                }
                Wanted::Hosted { digest, name } => fetch_model_card_bounded(
                    candidate.addr,
                    &candidate.key,
                    nonce,
                    digest,
                    name,
                    SURVEY_DEADLINE,
                ),
            };
            let _ = send.send((index, card, started.elapsed()));
        });
    }
    drop(send);
    let mut eligible = Vec::new();
    while let Some(left) = SURVEY_DEADLINE.checked_sub(started.elapsed()) {
        let Ok((index, card, latency)) = receive.recv_timeout(left) else {
            break;
        };
        if let Ok(card) = card {
            let passed = match wanted {
                Wanted::Builtin => client.verify_card(&card, now).is_ok(),
                Wanted::Hosted { .. } => client.verify_transit_card(&card, now).is_ok(),
            };
            if passed {
                eligible.push(Surveyed {
                    candidate: candidates[index],
                    card,
                    latency,
                });
            }
        }
    }
    eligible
}

/// One node to try: the routes to it, the key it is pinned by, and a card that already
/// passed the client's checks.
#[derive(Debug)]
pub struct Attempt {
    /// Routes to the node, in the order to try them.
    pub routes: Vec<Route>,
    /// Transport key the client pins.
    pub key: [u8; 32],
    /// The node's checked card.
    pub card: NodeCard,
}

impl From<Surveyed> for Attempt {
    fn from(surveyed: Surveyed) -> Self {
        Self {
            routes: vec![Route::Direct(surveyed.candidate.addr)],
            key: surveyed.candidate.key,
            card: surveyed.card,
        }
    }
}

/// Run a job on the first attempt that can be reached.
///
/// The next attempt is tried only when the error is `unreachable`, which means no request
/// byte was written to this node. Any other failure is final: the node may already have
/// run the job, and a second run elsewhere would be a replay. Every attempt gets its own
/// request, so a new job is sealed for each node.
pub fn complete_on_first_reachable(
    client: &Client,
    attempts: &[Attempt],
    wanted: &Wanted,
    make_request: &dyn Fn() -> JobRequest,
) -> Result<Completion, RuntimeError> {
    for attempt in attempts {
        let exchange = |sealed: &[u8]| exchange_secure_via(&attempt.routes, &attempt.key, sealed);
        let request = make_request();
        let outcome = match wanted {
            Wanted::Builtin => client.complete(&attempt.card, &request, exchange),
            Wanted::Hosted { .. } => client.complete_transit(&attempt.card, &request, exchange),
        };
        match outcome {
            Err(RuntimeError::Unreachable) => continue,
            other => return other,
        }
    }
    Err(RuntimeError::Unreachable)
}

/// Choose among `candidates`: shuffle, survey the first [`SURVEY_CANDIDATES`], and return
/// the eligible ones in the order to try them, best pick first.
pub fn select(
    client: &Client,
    candidates: Vec<Candidate>,
    wanted: &Wanted,
    now: u64,
) -> Vec<Surveyed> {
    let picked = shuffle_take(candidates, SURVEY_CANDIDATES);
    let mut eligible = survey(client, &picked, wanted, now);
    let latencies: Vec<u64> = eligible
        .iter()
        .map(|s| u64::try_from(s.latency.as_millis()).unwrap_or(u64::MAX))
        .collect();
    let order = pick_order(&latencies, OsRng.next_u64());
    let mut slots: Vec<Option<Surveyed>> = eligible.drain(..).map(Some).collect();
    order.into_iter().filter_map(|i| slots[i].take()).collect()
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use suricomai_envelope::LabAttester;

    use super::*;
    use crate::testkit::{node_with, NOW};

    #[test]
    fn the_pick_is_always_in_the_pool_and_the_rest_follow_by_latency() {
        let cases: Vec<Vec<u64>> = vec![
            vec![10],
            vec![10, 10, 10],
            vec![100, 30, 55, 400, 59, 60],
            vec![0, 49, 50, 51],
            vec![200, 100, 101, 199, 201],
            vec![u64::MAX, u64::MAX - 1],
        ];
        for latencies in cases {
            let best = *latencies.iter().min().unwrap();
            let limit = best.saturating_mul(2).max(best.saturating_add(50));
            for draw in [0, 1, 2, 3, 7, 1_000_003, u64::MAX] {
                let order = pick_order(&latencies, draw);
                assert_eq!(order.len(), latencies.len(), "{latencies:?}");
                assert!(latencies[order[0]] <= limit, "{latencies:?} draw {draw}");
                let mut seen = order.clone();
                seen.sort();
                assert_eq!(seen, (0..latencies.len()).collect::<Vec<_>>());
                let rest: Vec<u64> = order[1..].iter().map(|&i| latencies[i]).collect();
                assert!(rest.windows(2).all(|w| w[0] <= w[1]), "{latencies:?}");
            }
        }
    }

    #[test]
    fn every_pool_member_is_picked_and_nobody_outside_it_is() {
        let latencies = [100u64, 120, 199, 201, 400];
        // best 100, so the pool is 100, 120 and 199 (limit 200).
        let mut firsts = std::collections::BTreeSet::new();
        for draw in 0..60u64 {
            firsts.insert(pick_order(&latencies, draw)[0]);
        }
        assert_eq!(firsts, [0usize, 1, 2].into_iter().collect());
    }

    #[test]
    fn a_pool_has_a_floor_of_fifty_milliseconds_over_the_best() {
        let latencies = [1u64, 40, 51, 52];
        // best 1: limit is max(2, 51) = 51, so 1, 40 and 51 are in the pool and 52 is not.
        let firsts: std::collections::BTreeSet<usize> =
            (0..60u64).map(|d| pick_order(&latencies, d)[0]).collect();
        assert_eq!(firsts, [0usize, 1, 2].into_iter().collect());
    }

    #[test]
    fn no_candidates_gives_no_order() {
        assert!(pick_order(&[], 5).is_empty());
    }

    #[test]
    fn a_shuffle_keeps_only_the_first_few_and_loses_nobody() {
        let all: Vec<Candidate> = (0..20u16)
            .map(|i| Candidate {
                addr: SocketAddr::from(([127, 0, 0, 1], 1000 + i)),
                key: [i as u8; 32],
            })
            .collect();
        let kept = shuffle_take(all.clone(), 8);
        assert_eq!(kept.len(), 8);
        assert!(kept.iter().all(|c| all.contains(c)));
        let mut distinct = kept.clone();
        distinct.dedup();
        assert_eq!(distinct.len(), 8);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..200 {
            for c in shuffle_take(all.clone(), 8) {
                seen.insert(c.addr.port());
            }
        }
        assert_eq!(seen.len(), 20, "every candidate gets a turn");
        assert_eq!(shuffle_take(all[..3].to_vec(), 8).len(), 3);
    }

    fn candidate(node: &crate::testkit::Node) -> Candidate {
        Candidate {
            addr: node.addr,
            key: node.pinned,
        }
    }

    #[test]
    fn only_candidates_that_pass_every_client_check_are_eligible() {
        let shared = LabAttester::generate();
        let good = node_with(shared.clone());
        let other_root = node_with(LabAttester::generate());
        let nobody = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = Candidate {
            addr: nobody.local_addr().unwrap(),
            key: [1u8; 32],
        };
        drop(nobody);
        let wrong_key = Candidate {
            addr: good.addr,
            key: [2u8; 32],
        };
        let candidates = [candidate(&good), candidate(&other_root), dead, wrong_key];
        let eligible = survey(&good.client, &candidates, &Wanted::Builtin, NOW);
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].candidate, candidate(&good));
        assert!(eligible[0].latency < SURVEY_DEADLINE);
        good.shut_down();
        other_root.shut_down();
    }

    /// Completes the handshake, then takes far longer than the survey allows to answer.
    struct Slow;

    impl crate::transport::Handler for Slow {
        fn respond(
            &self,
            _peer: std::net::IpAddr,
            _request: &[u8],
            _clock: &(dyn Fn() -> u64 + Send + Sync),
        ) -> Result<Vec<u8>, crate::error::RuntimeError> {
            thread::sleep(Duration::from_secs(9));
            Err(crate::error::RuntimeError::Wire)
        }
    }

    #[test]
    fn a_candidate_that_handshakes_and_then_stalls_does_not_hold_the_survey_past_its_deadline() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        use crate::transport::{serve_secure, ServerLimits, TransportKey};

        let good = node_with(LabAttester::generate());
        let key = Arc::new(TransportKey::generate().unwrap());
        let slow_key = key.public();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let slow_addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let server = thread::spawn({
            let stop = Arc::clone(&stop);
            move || {
                serve_secure(
                    listener,
                    key,
                    Arc::new(Slow),
                    ServerLimits::default(),
                    Arc::new(|| NOW),
                    stop,
                )
            }
        });
        let candidates = [
            Candidate {
                addr: slow_addr,
                key: slow_key,
            },
            candidate(&good),
        ];
        let started = Instant::now();
        let eligible = survey(&good.client, &candidates, &Wanted::Builtin, NOW);
        assert!(
            started.elapsed() < SURVEY_DEADLINE + Duration::from_secs(1),
            "took {:?}",
            started.elapsed()
        );
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].candidate, candidate(&good));
        stop.store(true, Ordering::Release);
        server.join().unwrap().unwrap();
        good.shut_down();
    }

    #[test]
    fn select_returns_every_eligible_candidate_and_each_gets_picked_over_many_runs() {
        let shared = LabAttester::generate();
        let nodes: Vec<_> = (0..3).map(|_| node_with(shared.clone())).collect();
        let candidates: Vec<_> = nodes.iter().map(candidate).collect();
        let mut first = std::collections::BTreeSet::new();
        for _ in 0..40 {
            let ordered = select(&nodes[0].client, candidates.clone(), &Wanted::Builtin, NOW);
            assert_eq!(ordered.len(), 3);
            first.insert(ordered[0].candidate.addr);
        }
        // Loopback latencies sit well inside the 50 ms floor, so all three share the pool.
        assert_eq!(first.len(), 3, "load spreads across the pool");
        for n in nodes {
            n.shut_down();
        }
    }

    struct Counting {
        calls: std::sync::atomic::AtomicUsize,
        answer: Result<Vec<u8>, RuntimeError>,
    }

    impl crate::transport::Handler for Counting {
        fn respond(
            &self,
            _peer: std::net::IpAddr,
            _request: &[u8],
            _clock: &(dyn Fn() -> u64 + Send + Sync),
        ) -> Result<Vec<u8>, RuntimeError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.answer.clone()
        }
    }

    struct Fake {
        key: [u8; 32],
        addr: SocketAddr,
        handler: std::sync::Arc<Counting>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        thread: thread::JoinHandle<Result<(), RuntimeError>>,
    }

    /// A server that reads one request and then closes, so the client wrote its request and
    /// never got an answer.
    fn closing_server() -> Fake {
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        use std::sync::Arc;

        use crate::transport::{serve_secure, ServerLimits, TransportKey};

        let key = Arc::new(TransportKey::generate().unwrap());
        let pinned = key.public();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(Counting {
            calls: AtomicUsize::new(0),
            answer: Err(RuntimeError::Wire),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let thread = thread::spawn({
            let (handler, stop) = (Arc::clone(&handler), Arc::clone(&stop));
            move || {
                serve_secure(
                    listener,
                    key,
                    handler,
                    ServerLimits::default(),
                    Arc::new(|| NOW),
                    stop,
                )
            }
        });
        Fake {
            key: pinned,
            addr,
            handler,
            stop,
            thread,
        }
    }

    impl Fake {
        fn attempt(&self, card: &NodeCard) -> Attempt {
            Attempt {
                routes: vec![Route::Direct(self.addr)],
                key: self.key,
                card: NodeCard {
                    advertisement: card.advertisement.clone(),
                    model_digest: card.model_digest,
                    model_name: card.model_name.clone(),
                    hardware_p2: false,
                    quote_kind: "lab-untrusted",
                },
            }
        }

        fn calls(&self) -> usize {
            self.handler
                .calls
                .load(std::sync::atomic::Ordering::Acquire)
        }

        fn shut_down(self) {
            self.stop.store(true, std::sync::atomic::Ordering::Release);
            self.thread.join().unwrap().unwrap();
        }
    }

    fn request() -> JobRequest {
        JobRequest {
            job_id: [8u8; 32],
            chain_id: 7,
            prompt: b"hello".to_vec(),
            params: suricomai_envelope::InferenceParams::new([3u8; 32], 0, 24).unwrap(),
            now: NOW,
            expiry: 1_000,
            fee: 1,
            bond_required: 1,
            max_output_bytes: 64,
            size_class: 4_096,
            max_latency_ms: 150,
            user_pay_key: [5u8; 32],
        }
    }

    #[test]
    fn an_unreachable_first_choice_falls_through_to_the_next_node_and_completes() {
        let gone = node_with(LabAttester::generate());
        let live = node_with(LabAttester::generate());
        let shared_client = &live.client;
        // Both cards come from the live node, so they pass the client's checks.
        let dead_attempt = Attempt {
            routes: vec![Route::Direct(gone.addr)],
            key: gone.pinned,
            card: NodeCard {
                advertisement: live.card.advertisement.clone(),
                model_digest: live.card.model_digest,
                model_name: live.card.model_name.clone(),
                hardware_p2: false,
                quote_kind: "lab-untrusted",
            },
        };
        gone.shut_down();
        let live_attempt = Attempt {
            routes: vec![Route::Direct(live.addr)],
            key: live.pinned,
            card: NodeCard {
                advertisement: live.card.advertisement.clone(),
                model_digest: live.card.model_digest,
                model_name: live.card.model_name.clone(),
                hardware_p2: false,
                quote_kind: "lab-untrusted",
            },
        };
        let done = complete_on_first_reachable(
            shared_client,
            &[dead_attempt, live_attempt],
            &Wanted::Builtin,
            &request,
        );
        assert!(done.is_ok(), "{done:?}");
        live.shut_down();
    }

    #[test]
    fn a_failure_after_the_request_was_written_is_final_and_the_next_node_is_never_contacted() {
        let real = node_with(LabAttester::generate());
        let first = closing_server();
        let second = closing_server();
        let attempts = [first.attempt(&real.card), second.attempt(&real.card)];
        let out = complete_on_first_reachable(&real.client, &attempts, &Wanted::Builtin, &request);
        assert_eq!(out.unwrap_err(), RuntimeError::Wire);
        assert_eq!(first.calls(), 1, "the first node got the request");
        assert_eq!(second.calls(), 0, "the next node must not see it");
        first.shut_down();
        second.shut_down();
        real.shut_down();
    }

    #[test]
    fn when_no_node_can_be_reached_the_error_says_so() {
        let real = node_with(LabAttester::generate());
        let gone = node_with(LabAttester::generate());
        let attempt = Attempt {
            routes: vec![Route::Direct(gone.addr)],
            key: gone.pinned,
            card: NodeCard {
                advertisement: real.card.advertisement.clone(),
                model_digest: real.card.model_digest,
                model_name: real.card.model_name.clone(),
                hardware_p2: false,
                quote_kind: "lab-untrusted",
            },
        };
        gone.shut_down();
        assert_eq!(
            complete_on_first_reachable(&real.client, &[attempt], &Wanted::Builtin, &request)
                .unwrap_err(),
            RuntimeError::Unreachable
        );
        assert_eq!(
            complete_on_first_reachable(&real.client, &[], &Wanted::Builtin, &request).unwrap_err(),
            RuntimeError::Unreachable
        );
        real.shut_down();
    }

    #[test]
    fn selecting_among_nothing_or_only_ineligible_nodes_gives_nothing() {
        let good = node_with(LabAttester::generate());
        let stranger = node_with(LabAttester::generate());
        assert!(select(&good.client, Vec::new(), &Wanted::Builtin, NOW).is_empty());
        assert!(select(
            &good.client,
            vec![candidate(&stranger)],
            &Wanted::Builtin,
            NOW
        )
        .is_empty());
        good.shut_down();
        stranger.shut_down();
    }
}
