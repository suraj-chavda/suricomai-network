// Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
//! The whole model flow as separate processes, the same steps a person runs: make keys,
//! publish a model, approve it, push it to a registry, sync it, host it, ask it, then revoke it.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const FAR_FUTURE: &str = "4102444800";

struct Proc {
    child: Child,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn models(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_suricomai-models"))
        .args(args)
        .output()
        .unwrap()
}

fn models_ok(args: &[&str]) -> String {
    let out = models(args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Start a process that prints some lines first, and return the first `n` of them.
fn spawn_printing(bin: &str, args: &[&str], n: usize) -> (Proc, Vec<String>) {
    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let got = (0..n).map(|_| lines.next().unwrap().unwrap()).collect();
    (Proc { child }, got)
}

struct World {
    root: PathBuf,
}

impl World {
    fn new(tag: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("suricomai-publish-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("node")).unwrap();
        fs::create_dir_all(root.join("client")).unwrap();
        Self { root }
    }

    fn p(&self, name: &str) -> String {
        self.root.join(name).to_string_lossy().into_owned()
    }

    fn keygen(&self, name: &str) -> String {
        let out = models_ok(&["keygen", &self.p(name)]);
        out.trim().strip_prefix("public ").unwrap().to_string()
    }

    fn trust_file(&self, name: &str, threshold: u32, approvers: &[&str], deny: &[&str]) -> String {
        let mut text = format!("suricomai-trust-v1\nthreshold {threshold}\n");
        for a in approvers {
            text.push_str(&format!("approver {a}\n"));
        }
        for d in deny {
            text.push_str(&format!("deny {d}\n"));
        }
        let path = self.p(name);
        fs::write(&path, text).unwrap();
        set_private(&path);
        path
    }
}

#[cfg(unix)]
fn set_private(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(not(unix))]
fn set_private(_: &str) {}

impl Drop for World {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct Published {
    approver_pubs: Vec<String>,
    model_digest: String,
}

/// Steps 1 to 5 of the guide: keys, files, manifest, two approvals.
fn publish_and_approve(w: &World) -> Published {
    let _publisher = w.keygen("publisher.key");
    let a1 = w.keygen("approver1.key");
    let a2 = w.keygen("approver2.key");
    models_ok(&["make-test-model", &w.p("node"), "my-model", "5"]);
    let model_digest = models_ok(&["digest", "model", &w.p("node/my-model.gguf")])
        .trim()
        .to_string();
    models_ok(&[
        "publish-files",
        &w.p("publisher.key"),
        "my-model",
        &w.p("node/my-model.gguf"),
        &w.p("node/my-model.tokenizer.json"),
        "1",
        "MIT",
        &w.p("my-model.manifest"),
    ]);
    for (key, out) in [
        ("approver1.key", "a1.approval"),
        ("approver2.key", "a2.approval"),
    ] {
        models_ok(&[
            "approve",
            &w.p(key),
            &w.p("my-model.manifest"),
            "approved",
            "0",
            FAR_FUTURE,
            &w.p(out),
        ]);
    }
    Published {
        approver_pubs: vec![a1, a2],
        model_digest,
    }
}

fn start_registry(w: &World, trust: &str) -> (Proc, String, String) {
    let (proc, lines) = spawn_printing(
        env!("CARGO_BIN_EXE_suricomai-registry"),
        &["--listen", "127.0.0.1:0", "--trust", trust],
        2,
    );
    let key = lines[0].strip_prefix("registry-key ").unwrap().to_string();
    let addr = lines[1].strip_prefix("listening ").unwrap().to_string();
    let _ = w;
    (proc, addr, key)
}

fn start_node(pack: &str, trust: &str, extra: &[&str]) -> (Proc, String, String) {
    let (proc, lines) = spawn_printing(
        env!("CARGO_BIN_EXE_suricomai-node"),
        &[
            "--listen",
            "127.0.0.1:0",
            "--models",
            pack,
            "--trust",
            trust,
            "--reload-secs",
            "1",
        ]
        .iter()
        .chain(extra.iter())
        .copied()
        .collect::<Vec<_>>(),
        2,
    );
    let ticket = lines[0].clone();
    let addr = lines[1].strip_prefix("listening ").unwrap().to_string();
    (proc, addr, ticket)
}

fn ask(pack: &str, trust: &str, addr: &str, ticket: &str, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_suricomai-ask"))
        .args(["--model", "my-model", "--models", pack, "--trust", trust])
        .args(extra)
        .args([addr, ticket, "w3 w4 w5"])
        .output()
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn push_and_sync(w: &World, registry: &str, key: &str, files: &[&str], into: &[&str]) {
    let target = format!("{registry}/{key}");
    let mut args = vec!["push", target.as_str()];
    args.extend_from_slice(files);
    models_ok(&args);
    for dir in into {
        models_ok(&["sync", &target, dir]);
    }
    let _ = w;
}

fn wait_until(what: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + within;
    while !done() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[test]
fn publish_approve_sync_host_ask_then_revoke() {
    let w = World::new("flow");
    let p = publish_and_approve(&w);
    let trust = w.trust_file("trust", 2, &[&p.approver_pubs[0], &p.approver_pubs[1]], &[]);
    let (_registry, reg_addr, reg_key) = start_registry(&w, &trust);
    push_and_sync(
        &w,
        &reg_addr,
        &reg_key,
        &[
            &w.p("my-model.manifest"),
            &w.p("a1.approval"),
            &w.p("a2.approval"),
        ],
        &[&w.p("node"), &w.p("client")],
    );
    let (_node, addr, ticket) = start_node(&w.p("node"), &trust, &[]);

    let out = ask(&w.p("client"), &trust, &addr, &ticket, &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("privacy=not-private"),
        "{}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("answer="));

    // A client with a stale view still seals, so this refusal is the node's own check.
    let stale = w.p("stale");
    fs::create_dir(&stale).unwrap();
    models_ok(&["sync", &format!("{reg_addr}/{reg_key}"), &stale]);

    // One approver revokes. It travels the same way and stops the model on the node.
    models_ok(&[
        "revoke",
        &w.p("approver1.key"),
        &w.p("my-model.manifest"),
        "1",
        FAR_FUTURE,
        &w.p("revoke.approval"),
    ]);
    push_and_sync(
        &w,
        &reg_addr,
        &reg_key,
        &[&w.p("revoke.approval")],
        &[&w.p("node"), &w.p("client")],
    );

    // The client that synced the revocation refuses before it seals anything.
    let refused = ask(&w.p("client"), &trust, &addr, &ticket, &[]);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("not approved right now"),
        "{}",
        stderr(&refused)
    );
    assert!(!stdout(&refused).contains("answer="));

    // The stale client has not seen the revocation. The node has, after its next reload.
    wait_until(
        "the node to stop the model",
        Duration::from_secs(10),
        || {
            let out = ask(&stale, &trust, &addr, &ticket, &[]);
            !out.status.success()
        },
    );
    let by_node = ask(&stale, &trust, &addr, &ticket, &[]);
    assert!(!stdout(&by_node).contains("answer="));
    let message = stderr(&by_node);
    assert!(
        message.contains("approval_window") || message.contains("model_unavailable"),
        "{message}"
    );
}

#[test]
fn a_model_signed_by_one_approver_when_two_are_required_is_not_hosted_or_used() {
    let w = World::new("threshold");
    let p = publish_and_approve(&w);
    let trust = w.trust_file("trust", 2, &[&p.approver_pubs[0], &p.approver_pubs[1]], &[]);
    // Only one approval reaches the pack.
    fs::copy(w.p("my-model.manifest"), w.p("node/my-model.manifest")).unwrap();
    fs::copy(w.p("a1.approval"), w.p("node/a1.approval")).unwrap();
    fs::copy(w.p("my-model.manifest"), w.p("client/my-model.manifest")).unwrap();
    fs::copy(w.p("a1.approval"), w.p("client/a1.approval")).unwrap();
    let (_node, addr, ticket) = start_node(&w.p("node"), &trust, &[]);
    let out = ask(&w.p("client"), &trust, &addr, &ticket, &[]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("not approved right now"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn an_operator_deny_line_stops_the_model_whatever_the_approvals_say() {
    let w = World::new("deny");
    let p = publish_and_approve(&w);
    let allow = w.trust_file("trust", 2, &[&p.approver_pubs[0], &p.approver_pubs[1]], &[]);
    let deny = w.trust_file(
        "trust-deny",
        2,
        &[&p.approver_pubs[0], &p.approver_pubs[1]],
        &[&p.model_digest],
    );
    for dir in ["node", "client"] {
        for f in ["my-model.manifest", "a1.approval", "a2.approval"] {
            fs::copy(w.p(f), w.p(&format!("{dir}/{f}"))).unwrap();
        }
    }
    // A client that denies it refuses before sealing.
    let (_node, addr, ticket) = start_node(&w.p("node"), &allow, &[]);
    assert!(ask(&w.p("client"), &allow, &addr, &ticket, &[])
        .status
        .success());
    let by_client = ask(&w.p("client"), &deny, &addr, &ticket, &[]);
    assert!(!by_client.status.success());
    assert!(
        stderr(&by_client).contains("denied by your trust policy"),
        "{}",
        stderr(&by_client)
    );

    // A node that denies it does not host it, so a client that allows it gets nothing.
    let (_denying, addr2, ticket2) = start_node(&w.p("node"), &deny, &[]);
    let by_node = ask(&w.p("client"), &allow, &addr2, &ticket2, &[]);
    assert!(!by_node.status.success());
    assert!(!stdout(&by_node).contains("answer="));
    assert!(
        stderr(&by_node).contains("model_unavailable"),
        "{}",
        stderr(&by_node)
    );
}

#[test]
fn a_tampered_pack_a_weak_trust_file_or_missing_options_stop_the_node_from_starting() {
    let w = World::new("refuse");
    let p = publish_and_approve(&w);
    let trust = w.trust_file("trust", 2, &[&p.approver_pubs[0], &p.approver_pubs[1]], &[]);
    let single = w.trust_file("single", 1, &[&p.approver_pubs[0]], &[]);
    for f in ["my-model.manifest", "a1.approval", "a2.approval"] {
        fs::copy(w.p(f), w.p(&format!("node/{f}"))).unwrap();
    }
    let node = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_suricomai-node"))
            .args(["--listen", "127.0.0.1:0"])
            .args(args)
            .output()
            .unwrap()
    };
    // The trust file asks for one approver, which needs the explicit flag.
    let out = node(&["--models", &w.p("node"), "--trust", &single]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    // Models need a policy, and a policy needs models.
    assert_eq!(node(&["--models", &w.p("node")]).status.code(), Some(2));
    assert_eq!(node(&["--trust", &trust]).status.code(), Some(2));
    // A tampered approval refuses the start and names the problem.
    let path = w.p("node/a1.approval");
    let mut bytes = fs::read(&path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 1;
    fs::write(&path, bytes).unwrap();
    let out = node(&["--models", &w.p("node"), "--trust", &trust]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("failed its checks"));
}

#[test]
fn the_registry_and_the_tools_refuse_bad_input() {
    let w = World::new("bad-input");
    let p = publish_and_approve(&w);
    let trust = w.trust_file("trust", 2, &[&p.approver_pubs[0], &p.approver_pubs[1]], &[]);
    for args in [
        vec!["--allow-single-approver"],
        vec!["--trust", "/nonexistent"],
        vec!["--max-objects", "0"],
        vec!["--bogus"],
        vec!["--store", "/nonexistent-dir"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_suricomai-registry"))
            .args(["--listen", "127.0.0.1:0"])
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
    for args in [
        vec!["digest", "weights", "x"],
        vec!["digest", "model", "/nonexistent"],
        vec!["push", "nonsense", "x"],
        vec!["push", "127.0.0.1:1/00", "x"],
        vec!["sync", "127.0.0.1:1/zz", "x"],
        vec!["make-test-model", "/nonexistent", "id", "300"],
        vec!["publish-files"],
    ] {
        assert!(!models(&args).status.success(), "{args:?}");
    }
    // Pushing a file that is neither a manifest nor an approval is refused by the tool.
    let junk = w.p("junk");
    fs::write(&junk, b"hello").unwrap();
    let (_registry, reg_addr, reg_key) = start_registry(&w, &trust);
    let out = models(&["push", &format!("{reg_addr}/{reg_key}"), &junk]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not a manifest or an approval"));
    let _ = Path::new(&junk);
}

/// The same flow with a real open model, when its files are installed (see the README).
#[test]
fn a_real_open_model_can_be_published_hosted_and_answers_in_words() {
    let models_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models");
    let weights = models_dir.join("SmolLM2-135M-Instruct-Q4_K_M.gguf");
    let tokenizer = models_dir.join("tokenizer.json");
    if !weights.is_file() || !tokenizer.is_file() {
        eprintln!("skipped: the SmolLM2 files are not installed");
        return;
    }
    let w = World::new("real");
    w.keygen("publisher.key");
    let a1 = w.keygen("approver1.key");
    let a2 = w.keygen("approver2.key");
    fs::copy(&weights, w.p("node/my-model.gguf")).unwrap();
    fs::copy(&tokenizer, w.p("node/my-model.tokenizer.json")).unwrap();
    models_ok(&[
        "publish-files",
        &w.p("publisher.key"),
        "my-model",
        &w.p("node/my-model.gguf"),
        &w.p("node/my-model.tokenizer.json"),
        "135",
        "Apache-2.0",
        &w.p("my-model.manifest"),
    ]);
    for (key, out) in [
        ("approver1.key", "a1.approval"),
        ("approver2.key", "a2.approval"),
    ] {
        models_ok(&[
            "approve",
            &w.p(key),
            &w.p("my-model.manifest"),
            "approved",
            "0",
            FAR_FUTURE,
            &w.p(out),
        ]);
    }
    for f in ["my-model.manifest", "a1.approval", "a2.approval"] {
        fs::copy(w.p(f), w.p(&format!("node/{f}"))).unwrap();
        fs::copy(w.p(f), w.p(&format!("client/{f}"))).unwrap();
    }
    let trust = w.trust_file("trust", 2, &[&a1, &a2], &[]);
    let (_node, addr, ticket) = start_node(&w.p("node"), &trust, &[]);
    let out = Command::new(env!("CARGO_BIN_EXE_suricomai-ask"))
        .args([
            "--model",
            "my-model",
            "--models",
            &w.p("client"),
            "--trust",
            &trust,
        ])
        .args([&addr, &ticket, "Say hello in one short sentence."])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("privacy=not-private"));
    let answer = text.split("answer=").nth(1).unwrap_or("");
    assert!(
        answer.chars().filter(|c| c.is_alphabetic()).count() > 3,
        "{text}"
    );
}

/// The bundled test model: a small model trained for this platform, answering in plain words.
#[test]
fn the_bundled_mini_model_is_published_hosted_and_answers_in_words() {
    let models_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models");
    let weights = models_dir.join("suricomai-mini-chat.gguf");
    let tokenizer = models_dir.join("suricomai-mini-chat.tokenizer.json");
    assert!(weights.is_file() && tokenizer.is_file());
    let w = World::new("mini");
    w.keygen("publisher.key");
    let a1 = w.keygen("approver1.key");
    let a2 = w.keygen("approver2.key");
    fs::copy(&weights, w.p("node/my-model.gguf")).unwrap();
    fs::copy(&tokenizer, w.p("node/my-model.tokenizer.json")).unwrap();
    models_ok(&[
        "publish-files",
        &w.p("publisher.key"),
        "my-model",
        &w.p("node/my-model.gguf"),
        &w.p("node/my-model.tokenizer.json"),
        "2",
        "MIT",
        &w.p("my-model.manifest"),
    ]);
    for (key, out) in [
        ("approver1.key", "a1.approval"),
        ("approver2.key", "a2.approval"),
    ] {
        models_ok(&[
            "approve",
            &w.p(key),
            &w.p("my-model.manifest"),
            "approved",
            "0",
            FAR_FUTURE,
            &w.p(out),
        ]);
    }
    for f in ["my-model.manifest", "a1.approval", "a2.approval"] {
        fs::copy(w.p(f), w.p(&format!("node/{f}"))).unwrap();
        fs::copy(w.p(f), w.p(&format!("client/{f}"))).unwrap();
    }
    let trust = w.trust_file("trust", 2, &[&a1, &a2], &[]);
    let (_node, addr, ticket) = start_node(&w.p("node"), &trust, &[]);
    for (question, expected) in [
        ("What is 2 plus 3?", "5"),
        ("What sound does a cow make?", "moo"),
        ("What is the capital of Japan?", "Tokyo"),
        ("Who will win the election?", "know"),
        ("Is SuriComAI private?", "private"),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_suricomai-ask"))
            .args([
                "--model",
                "my-model",
                "--models",
                &w.p("client"),
                "--trust",
                &trust,
            ])
            .args([&addr, &ticket, question])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", stderr(&out));
        let text = stdout(&out);
        assert!(text.contains("privacy=not-private"), "{text}");
        let answer = text.split("answer=").nth(1).unwrap_or("");
        assert!(answer.contains(expected), "{question}: {text}");
    }
}
