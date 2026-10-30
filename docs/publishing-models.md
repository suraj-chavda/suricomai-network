# Publishing a model, step by step

This is the full flow for getting an AI model into SuriComAI, hosting it, using it, and taking it down. Every command below is run by the test suite (`crates/suricomai-runtime/tests/model_publishing.rs`), so the steps match what the code does.

> **Permission.** SuriComAI Network is proprietary. Running these tools requires the Owner's written permission. See the [license](../LICENSE).

> **Development build.** SuriComAI is a prototype. Models run on the host's own machine, so a hosted model is **not private**: the node that hosts it can read your prompt. Quotes are software quotes (`lab-untrusted`). There is no public network, no payment and no token. Use this guide to learn the flow and to run it on machines you control.

## What you need to know first

**A model is identified by its fingerprint, not its name.** A fingerprint (digest) is a hash of the weights file. If one byte changes, the fingerprint changes, and every approval for the old one stops applying.

**Nobody uploads weights to the network.** The network only carries small signed records about a model. The weights stay in files on the machine that hosts the model, and anyone can check that those files match the record.

| Role | What they do | What they hold |
| --- | --- | --- |
| **Publisher** | Makes the manifest, a signed description of the model | A publisher key |
| **Approvers** | Sign an approval that says "I vouch for exactly this manifest until this date" | One key each, kept offline |
| **Registry operator** | Runs a store for manifests and approvals | Nothing secret. A registry is not trusted. |
| **Node operator** | Hosts the model and serves jobs | The weights files |
| **User** | Asks the model | A trust file saying which approvers to believe |

**Who is trusted?** Only the approvers named in each operator's own trust file. The publisher cannot approve their own model. The registry cannot approve anything. A model works for you only if enough of **your** trusted approvers signed it.

## What models can be hosted today

- Weights as a **GGUF** file of the **llama architecture** that the pinned loader accepts. Many popular open models ship this way.
- A `tokenizer.json` from the `tokenizers` library.
- The **ChatML** prompt layout (`<|im_start|>`, `<|im_end|>`). This is part of the runtime build, not of the manifest, so no signed or unsigned text can change how a prompt is rendered.

A model that needs a different architecture or prompt layout needs a new runtime build, which has a different runtime fingerprint. Until one exists, the node refuses it and says why.

## Step 0: set up the tools

From the repository root:

```bash
alias suricomai-models='cargo run -q -p suricomai-runtime --features lab --bin suricomai-models --'
```

The other programs are `suricomai-registry`, `suricomai-node` and `suricomai-ask`, run the same way with `--bin <name> --`.

## Step 1: make the keys

Make one key for the publisher and one for **each** approver. Use at least two approvers.

```bash
suricomai-models keygen publisher.key       # prints: public <64 hex characters>
suricomai-models keygen approver1.key       # prints: public <64 hex characters>
suricomai-models keygen approver2.key       # prints: public <64 hex characters>
```

Each file holds a secret and is created readable by its owner only. **Keep approver keys offline** and on different people's machines. Write down the three `public` values.

## Step 2: write the trust file

Everyone who runs a node, a registry or a client needs a trust file. It lists the approvers they believe and how many must agree.

```text
suricomai-trust-v1
threshold 2
approver <approver1 public hex>
approver <approver2 public hex>
```

Save it as `trust` and make it private:

```bash
chmod 600 trust
```

Rules the programs enforce:

- A threshold of 1 is refused unless you add `--allow-single-approver`. One key should not be able to approve a model alone.
- The file must be a regular file, not a symbolic link, and not writable by group or others.
- At most 64 approvers.

## Step 3: prepare the model files

Put the two files in a directory named for the model, using the model's id (lowercase letters, digits, `.`, `_`, `-`, up to 64 characters):

```text
node/my-model.gguf
node/my-model.tokenizer.json
```

Do not have the real weights yet? Make a tiny random-weight model in the same real formats to try the flow:

```bash
mkdir -p node client
suricomai-models make-test-model node my-model 5
```

Its answers are noise. The files are real and go through the same checks.

## Step 4: publish the manifest

```bash
suricomai-models publish-files publisher.key my-model \
  node/my-model.gguf node/my-model.tokenizer.json 1 MIT my-model.manifest
```

The numbers and words are: the model size in millions of parameters (used for display), and its license. The command computes the weights and tokenizer fingerprints itself and writes `my-model.manifest`.

To see the fingerprints:

```bash
suricomai-models digest model node/my-model.gguf
suricomai-models digest tokenizer node/my-model.tokenizer.json
suricomai-models runtime-digest
```

## Step 5: approve it

Each approver, on their own machine, checks what they are vouching for and signs. Approvals always have an end date and must be renewed. A 90 day window:

```bash
FROM=$(date +%s)
UNTIL=$((FROM + 7776000))
suricomai-models approve approver1.key my-model.manifest approved $FROM $UNTIL a1.approval
```

The second approver does the same and produces `a2.approval`. Check the files:

```bash
suricomai-models verify my-model.manifest a1.approval a2.approval
```

With a threshold of 2, the model counts as approved only when **both** have signed the same decision.

## Step 6: put the records in a registry

A registry stores manifests and approvals so everyone can fetch them. Anyone can run one.

```bash
mkdir registry-store
cargo run -q -p suricomai-runtime --features lab --bin suricomai-registry -- \
  --listen 127.0.0.1:7950 --store registry-store --trust trust
# prints: registry-key <hex>
#         listening 127.0.0.1:7950
```

`--store` keeps the records in that directory across restarts and checks them again at start. `--trust` makes the registry refuse approvals from approvers you did not list, which keeps it from filling with noise.

Push the records, using the address and key it printed:

```bash
suricomai-models push 127.0.0.1:7950/<registry-key> my-model.manifest a1.approval a2.approval
```

The registry only checks that each record is well formed and correctly signed. It does **not** decide whether a model is approved. Every node and client decides that again for itself.

## Step 7: host the model

The node operator puts the records next to the weights and starts a node. The records come from the registry:

```bash
suricomai-models sync 127.0.0.1:7950/<registry-key> node

cargo run -q -p suricomai-runtime --features lab --bin suricomai-node -- \
  --listen 127.0.0.1:7700 --models node --trust trust
# prints the node's ticket, then: listening 127.0.0.1:7700
```

At start the node loads every model it is allowed to host. A model is hosted only if all of these hold:

1. Your trust file says it is approved right now.
2. The manifest names this node's runtime build.
3. The weights file hashes to the manifest's fingerprint.
4. The tokenizer file hashes to the manifest's tokenizer fingerprint.
5. The weights load. They are loaded from the same bytes that were just hashed, so swapping the file afterwards changes nothing.

A model that fails a step is skipped and the node prints why. If the pack itself is damaged, for example a tampered record, the node **does not start**.

The node re-reads the directory every 30 seconds by default (`--reload-secs`). New approvals and revocations take effect without a restart.

## Step 8: ask the model

The user syncs the records into their own directory and asks:

```bash
suricomai-models sync 127.0.0.1:7950/<registry-key> client

cargo run -q -p suricomai-runtime --features lab --bin suricomai-ask -- \
  --model my-model --models client --trust trust \
  127.0.0.1:7700 <ticket> "Say hello in one short sentence."
```

The client refuses to seal your prompt to a model your trust file does not approve right now, or that you denied. The result is labeled:

```text
privacy=not-private (the node that hosts this model can read the prompt)
answer=...
```

You can also let the client choose among nodes that announce themselves to a directory: replace the address and ticket with `--directory <addr>/<key> --lab-root <hex> --allow-local`, as described in the README.

## Renewing an approval

Approvals end. Before one does, each approver signs a new approval with a later end date and the new records go through steps 6 to 8. A model whose approval ends is refused at the next job, with no restart.

## Taking a model down

You may need to remove a model, for example after a legal notice or a safety problem. There are three tools, and they do different things.

### 1. Revocation (any trusted approver)

One approver signs a revocation. It needs only one signature, on purpose, so removal is faster than approval:

```bash
FROM=$(date +%s)
suricomai-models revoke approver1.key my-model.manifest $FROM 4102444800 revoke.approval
suricomai-models push 127.0.0.1:7950/<registry-key> revoke.approval
```

Then everyone syncs. Nodes stop serving the model at their next reload, and clients that synced refuse to use it. A revocation stays in force until a **later** approval, and replaying an older approval cannot undo it.

The cost of a one-signature revocation: any one trusted approver can remove a model the others want. Choose your approvers with that in mind.

### 2. Deny line (the operator, immediately)

If you cannot wait for approvers or for a sync, add the model's fingerprint to your own trust file:

```text
deny <model fingerprint hex>
```

Restart the node or client. That operator's node never loads or serves the model, and that operator's client never seals to it, whatever any approval says. A deny line is not undone by an approval. Only you editing the file undoes it. Get the fingerprint with `suricomai-models digest model <weights file>`.

### 3. Delisting (a registry operator)

A registry operator can delete the records from their own store directory. That stops **that registry** from serving them. Another registry may still hold the signed records.

### What removal does not do

- **It cannot erase copies.** The network never holds weights. Revoking or denying a model stops this network from using it. It does not delete files anyone already has.
- **It does not hide history.** Manifests and approvals are signed public records. A revoked model's records remain visible.
- **It does not decide legal questions.** Whether a notice requires more, such as telling a hosting provider or removing a record, is for your counsel. The software only gives you the switches above.

## What protects you, and what does not

Protected, and covered by tests:

- A model nobody trusted approved is never sealed to or hosted.
- Renaming a model does not help an attacker, because only the fingerprint counts.
- An edited manifest needs a fresh approval. A different publisher cannot take over a model's fingerprint.
- A forged approval needs an approver's private key. A signature from a key you did not list is refused.
- An old approval cannot undo a revocation.
- Swapping weights or the tokenizer on a node's disk is detected, and swapping them after loading changes nothing.
- A tampered record, a symbolic link, an oversized file or a flood of files refuses the load.
- A node checks approval before it decrypts each job, so a revoked or expired model stops at the next job.
- A hosted model is never run as a private job.
- A dishonest registry cannot make anyone accept a record whose bytes or signature do not check out, and sync never overwrites an existing file.

Not protected, so do not assume it:

- **An approval is not a safety guarantee.** A signature means "this approver vouches for these exact weights." It does not prove the model is harmless or has no hidden behavior. Trust rests on who your approvers are.
- **Hosted jobs are not private.** The node reads the prompt.
- **This is a development build.** Software quotes prove nothing about hardware, nothing here has been audited, and there is no public network.

## Troubleshooting

| You see | Usually means |
| --- | --- |
| `not a usable trust policy` | Bad first line, a repeated approver, threshold 0 or too high, threshold 1 without `--allow-single-approver`, or the file is writable by others or is a link |
| `the model pack failed its checks` | A manifest or approval in the directory is tampered, a link, over 4 KiB, or there are too many files |
| `... not in the model pack` | No manifest with that model id in the client directory. Run `sync`. |
| `... not approved right now` | Not enough trusted approvals, or expired, or revoked |
| `... denied by your trust policy` | The fingerprint is on your own `deny` list |
| `not hosted, the weights do not match the manifest digest` | The weights file is not the one that was published |
| `not hosted, it names a different runtime build` | The manifest was made for another runtime build |
| `not hosted, the weights are not a model this runtime can load` | Not a GGUF of the supported architecture |
| `model_unavailable` | The node does not host that model right now |
| `approval_window` | The model expired or was revoked and the node noticed |
| `refused it (busy)` | The registry is full or you pushed too fast. Wait and retry. |
