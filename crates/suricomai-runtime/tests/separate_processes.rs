// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! A node process and a client process that share nothing but the printed ticket.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

struct Node {
    child: Child,
    ticket: String,
    addr: String,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_node() -> Node {
    start_node_with(&[])
}

fn start_node_with(extra: &[&str]) -> Node {
    let mut child = Command::new(env!("CARGO_BIN_EXE_suricomai-node"))
        .args(["--listen", "127.0.0.1:0"])
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ticket = lines.next().unwrap().unwrap();
    let addr = lines
        .next()
        .unwrap()
        .unwrap()
        .strip_prefix("listening ")
        .unwrap()
        .to_string();
    Node {
        child,
        ticket,
        addr,
    }
}

fn ask(addr: &str, ticket: &str, prompt: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_suricomai-ask"))
        .args([addr, ticket, prompt])
        .output()
        .unwrap()
}

#[test]
fn a_client_process_completes_a_job_on_a_separate_node_process() {
    let node = start_node();
    let out = ask(&node.addr, &node.ticket, "hello from another process");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("privacy=lab-untrusted"));
    assert!(text.contains("hardware_p2=false"));
    assert!(text.contains("answer="));
}

#[test]
fn a_ticket_from_a_different_node_is_refused() {
    let node = start_node();
    let other = start_node();
    let out = ask(&node.addr, &other.ticket, "hello");
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("answer="));
}

#[test]
fn a_malformed_ticket_is_refused_before_any_connection() {
    let out = ask("127.0.0.1:1", "not-a-ticket", "hello");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("bad ticket"));
}

#[test]
fn the_node_refuses_bad_options_with_a_message_and_exit_code_two() {
    for args in [
        vec!["--max-connections", "0"],
        vec!["--max-per-peer", "many"],
        vec!["--listen"],
        vec!["--key-file"],
        vec!["--bogus", "1"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_suricomai-node"))
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?} printed a ticket");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("usage: suricomai-node"),
            "{args:?}: {stderr}"
        );
    }
}

#[cfg(unix)]
mod key_file {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn temp_key_path() -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("suricomai-node-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        dir.join("node.key")
    }

    #[test]
    fn a_restarted_node_keeps_its_ticket_and_the_old_client_still_works() {
        let path = temp_key_path();
        let path_str = path.to_str().unwrap();
        let first = start_node_with(&["--key-file", path_str]);
        let ticket = first.ticket.clone();
        assert!(ask(&first.addr, &ticket, "before restart").status.success());
        drop(first);

        let second = start_node_with(&["--key-file", path_str]);
        assert_eq!(second.ticket, ticket);
        let out = ask(&second.addr, &ticket, "after restart");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn two_nodes_without_a_key_file_do_not_share_a_ticket() {
        let a = start_node();
        let b = start_node();
        assert_ne!(a.ticket, b.ticket);
    }

    #[test]
    fn the_node_refuses_an_unsafe_key_file_and_leaves_it_alone() {
        let path = temp_key_path();
        fs::write(&path, b"not a key").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_suricomai-node"))
            .args([
                "--listen",
                "127.0.0.1:0",
                "--key-file",
                path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("not a safe key file"));
        assert_eq!(fs::read(&path).unwrap(), b"not a key");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

mod relay {
    use super::*;

    struct Relay {
        child: Child,
        addr: String,
    }

    impl Drop for Relay {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn start_relay(upstream: &str) -> Relay {
        let mut child = Command::new(env!("CARGO_BIN_EXE_suricomai-relay"))
            .args(["--listen", "127.0.0.1:0", "--upstream", upstream])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let line = BufReader::new(child.stdout.take().unwrap())
            .lines()
            .next()
            .unwrap()
            .unwrap();
        let addr = line.strip_prefix("listening ").unwrap().to_string();
        Relay { child, addr }
    }

    fn ask_via(args: &[&str], addr: &str, ticket: &str) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_suricomai-ask"))
            .args(args)
            .args([addr, ticket, "hello through a relay"])
            .output()
            .unwrap()
    }

    #[test]
    fn three_processes_complete_a_job_through_the_relay_alone() {
        let node = start_node();
        let relay = start_relay(&node.addr);
        let via = format!("{}/0", relay.addr);
        let out = ask_via(&["--via", &via, "--no-direct"], &node.addr, &node.ticket);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("answer="));
    }

    #[test]
    fn a_killed_relay_does_not_stop_a_job_that_allows_the_direct_route() {
        let node = start_node();
        let mut relay = start_relay(&node.addr);
        let via = format!("{}/0", relay.addr);
        relay.child.kill().unwrap();
        relay.child.wait().unwrap();
        let out = ask_via(&["--via", &via], &node.addr, &node.ticket);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let relay_only = ask_via(&["--via", &via, "--no-direct"], &node.addr, &node.ticket);
        assert!(!relay_only.status.success());
    }

    #[test]
    fn the_relay_refuses_to_start_without_an_upstream_or_with_a_bad_one() {
        for args in [
            vec![],
            vec!["--upstream", "not-an-address"],
            vec!["--upstream", "127.0.0.1:1", "--max-connections", "0"],
            vec!["--bogus", "1"],
        ] {
            let out = Command::new(env!("CARGO_BIN_EXE_suricomai-relay"))
                .args(&args)
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(2), "{args:?}");
            assert!(out.stdout.is_empty(), "{args:?}");
            assert!(String::from_utf8_lossy(&out.stderr).contains("usage: suricomai-relay"));
        }
    }

    #[test]
    fn the_client_refuses_bad_route_options() {
        for args in [
            vec!["--via", "127.0.0.1:1"],
            vec!["--via", "127.0.0.1:1/300"],
            vec!["--via", "nope/0"],
            vec!["--no-direct"],
        ] {
            let out = ask_via(&args, "127.0.0.1:1", "not-a-ticket");
            assert!(!out.status.success(), "{args:?}");
            assert!(!String::from_utf8_lossy(&out.stdout).contains("answer="));
        }
    }
}

#[cfg(unix)]
mod directory {
    use std::fs;
    use std::time::{Duration, Instant};

    use super::*;

    struct Directory {
        child: Child,
        addr: String,
        key: String,
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn start_directory(roots: &[&str], extra: &[&str]) -> Directory {
        let mut command = Command::new(env!("CARGO_BIN_EXE_suricomai-directory"));
        command.args(["--listen", "127.0.0.1:0", "--allow-local"]);
        for root in roots {
            command.args(["--accept-lab-root", root]);
        }
        let mut child = command
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let key = lines
            .next()
            .unwrap()
            .unwrap()
            .strip_prefix("directory-key ")
            .unwrap()
            .to_string();
        let addr = lines
            .next()
            .unwrap()
            .unwrap()
            .strip_prefix("listening ")
            .unwrap()
            .to_string();
        Directory { child, addr, key }
    }

    fn key_path(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("suricomai-dir-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        dir.join("node.key")
    }

    /// The lab root a node will use, learned by starting it once on a key file.
    fn root_of(path: &std::path::Path) -> String {
        let node = start_node_with(&["--key-file", path.to_str().unwrap()]);
        node.ticket.rsplit('.').next().unwrap().to_string()
    }

    fn start_announcing(path: &std::path::Path, directory: &Directory) -> Node {
        let announce = format!("{}/{}", directory.addr, directory.key);
        start_node_with(&[
            "--key-file",
            path.to_str().unwrap(),
            "--announce",
            &announce,
        ])
    }

    fn ask_directory(directory: &Directory, root: &str, extra: &[&str]) -> std::process::Output {
        let pair = format!("{}/{}", directory.addr, directory.key);
        Command::new(env!("CARGO_BIN_EXE_suricomai-ask"))
            .args(["--directory", &pair, "--lab-root", root])
            .args(extra)
            .arg("hello through a directory")
            .output()
            .unwrap()
    }

    /// Ask until it works or `within` passes: a node is listed a moment after it starts.
    fn ask_until_listed(
        directory: &Directory,
        root: &str,
        extra: &[&str],
        within: Duration,
    ) -> std::process::Output {
        let until = Instant::now() + within;
        loop {
            let out = ask_directory(directory, root, extra);
            if out.status.success() || Instant::now() >= until {
                return out;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    #[test]
    fn a_client_finds_an_announcing_node_through_the_directory_and_completes_a_job() {
        let path = key_path("one");
        let root = root_of(&path);
        let directory = start_directory(&[&root], &[]);
        let _node = start_announcing(&path, &directory);
        let out = ask_until_listed(
            &directory,
            &root,
            &["--allow-local"],
            Duration::from_secs(8),
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("privacy=lab-untrusted"));
        assert!(text.contains("answer="));
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_dead_listed_node_is_skipped_and_a_live_one_is_used() {
        let (first_path, second_path) = (key_path("a"), key_path("b"));
        let (first_root, second_root) = (root_of(&first_path), root_of(&second_path));
        let directory = start_directory(&[&first_root, &second_root], &[]);
        let first = start_announcing(&first_path, &directory);
        let second = start_announcing(&second_path, &directory);
        // Wait until the directory itself lists both, so the dead one really is listed.
        let directory_addr: std::net::SocketAddr = directory.addr.parse().unwrap();
        let directory_key = suricomai_runtime::key_from_hex(&directory.key).unwrap();
        let both = Instant::now() + Duration::from_secs(10);
        let listed = loop {
            let (entries, _) =
                suricomai_runtime::list_directory(directory_addr, &directory_key, 0).unwrap();
            if entries.len() == 2 || Instant::now() >= both {
                break entries;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        assert_eq!(listed.len(), 2, "both nodes should be listed");
        // Take down whichever node is listed first, so the client must skip a dead entry.
        let listed_first = listed[0].addr.to_string();
        let (dead, survivor_root) = if first.addr == listed_first {
            (first, second_root.clone())
        } else {
            (second, first_root.clone())
        };
        drop(dead);
        let out = ask_directory(&directory, &survivor_root, &["--allow-local"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        for path in [first_path, second_path] {
            fs::remove_dir_all(path.parent().unwrap()).unwrap();
        }
    }

    #[test]
    fn an_empty_directory_and_a_loopback_listing_without_allow_local_give_no_node() {
        let path = key_path("c");
        let root = root_of(&path);
        let directory = start_directory(&[&root], &[]);
        let out = ask_directory(&directory, &root, &["--allow-local"]);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("lists no usable node"));

        let _node = start_announcing(&path, &directory);
        let listed = ask_until_listed(
            &directory,
            &root,
            &["--allow-local"],
            Duration::from_secs(8),
        );
        assert!(listed.status.success());
        let without = ask_directory(&directory, &root, &[]);
        assert!(!without.status.success());
        assert!(String::from_utf8_lossy(&without.stderr).contains("lists no usable node"));
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_node_whose_root_the_directory_does_not_accept_is_never_listed() {
        let path = key_path("d");
        let root = root_of(&path);
        let stranger = "11".repeat(32);
        let directory = start_directory(&[&stranger], &[]);
        let _node = start_announcing(&path, &directory);
        std::thread::sleep(Duration::from_secs(2));
        let out = ask_directory(&directory, &root, &["--allow-local"]);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("lists no usable node"));
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn the_directory_and_the_announce_option_refuse_bad_input() {
        for args in [
            vec![],
            vec!["--accept-lab-root", "zz"],
            vec!["--accept-lab-root", "00"],
            vec!["--accept-lab-root", &"11".repeat(32), "--max-entries", "0"],
            vec!["--bogus"],
        ] {
            let out = Command::new(env!("CARGO_BIN_EXE_suricomai-directory"))
                .args(&args)
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(2), "{args:?}");
            assert!(out.stdout.is_empty(), "{args:?}");
        }
        for announce in ["nope", "127.0.0.1:1/zz", "bad/00", "127.0.0.1:1"] {
            let out = Command::new(env!("CARGO_BIN_EXE_suricomai-node"))
                .args(["--announce", announce])
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(2), "{announce}");
            assert!(out.stdout.is_empty(), "{announce}");
        }
    }

    #[test]
    fn a_second_directory_that_syncs_from_the_first_serves_a_client_the_node_it_learned() {
        let path = key_path("sync");
        let root = root_of(&path);
        let first = start_directory(&[&root], &[]);
        let _node = start_announcing(&path, &first);
        // Nothing is announced to the second directory. It only learns from the first.
        let peer = format!("{}/{}", first.addr, first.key);
        let second = start_directory(&[&root], &["--peer", &peer, "--sync-secs", "1"]);
        let out = ask_until_listed(&second, &root, &["--allow-local"], Duration::from_secs(12));
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("answer="));
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_directory_that_does_not_accept_the_nodes_root_does_not_learn_it_from_a_peer() {
        let path = key_path("sync2");
        let root = root_of(&path);
        let first = start_directory(&[&root], &[]);
        let _node = start_announcing(&path, &first);
        let peer = format!("{}/{}", first.addr, first.key);
        let stranger = "11".repeat(32);
        let second = start_directory(&[&stranger], &["--peer", &peer, "--sync-secs", "1"]);
        std::thread::sleep(Duration::from_secs(3));
        let out = ask_directory(&second, &root, &["--allow-local"]);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("lists no usable node"));
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn the_directory_refuses_bad_peer_options() {
        for args in [
            vec!["--peer", "nope"],
            vec!["--peer", "127.0.0.1:1/zz"],
            vec!["--peer", "bad/00"],
            vec!["--sync-secs", "0"],
        ] {
            let out = Command::new(env!("CARGO_BIN_EXE_suricomai-directory"))
                .args(["--accept-lab-root", &"11".repeat(32)])
                .args(&args)
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(2), "{args:?}");
            assert!(out.stdout.is_empty(), "{args:?}");
        }
    }

    #[test]
    fn the_client_refuses_conflicting_discovery_options() {
        for args in [
            vec!["--directory", "127.0.0.1:1/00"],
            vec!["--directory", &format!("127.0.0.1:1/{}", "11".repeat(32))],
            vec!["--lab-root", &"11".repeat(32), "--no-direct", "x", "y", "z"],
        ] {
            let out = Command::new(env!("CARGO_BIN_EXE_suricomai-ask"))
                .args(&args)
                .output()
                .unwrap();
            assert!(!out.status.success(), "{args:?}");
            assert!(!String::from_utf8_lossy(&out.stdout).contains("answer="));
        }
    }
}
