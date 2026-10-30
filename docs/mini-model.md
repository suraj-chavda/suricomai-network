# suricomai-mini-chat: a small model for testing

`suricomai-mini-chat` is a language model trained for this project. It is small enough to run on any processor and answers in plain sentences, so you can test the whole platform (publish, approve, host, ask, check the proof) without a graphics card or a large download.

> **Development build.** The model runs on the host's own machine, so answers are labeled `not-private`. The node that hosts it can read your prompt. Running it requires the Owner's written permission. See the [license](../LICENSE).

## What it is

| | |
| --- | --- |
| Size | About 2.2 million parameters, a 4.3 MB file (16-bit weights) |
| Layout | Llama architecture: 4 layers, 192 wide, 6 heads, 1,024-token vocabulary |
| Prompt format | The runtime's ChatML layout with its fixed system line |
| Speed | A whole job, from connect to checked proof, takes about a second on a laptop processor. Generation itself is a few milliseconds per word. |
| Training | From scratch, on a corpus written for this project (`tools/mini-model/corpus.py`). No other model's output is used. |
| Files | `models/suricomai-mini-chat.gguf` and `models/suricomai-mini-chat.tokenizer.json` |

## What it knows

It knows a few hundred plain facts and says so when it does not know the rest:

- greetings, thanks and goodbyes, and what it is
- how the SuriComAI development build works: privacy labels, models, fingerprints, approvals, proofs, and what does not exist yet (no wallet, token or public network)
- animals and their sounds, colors, opposites, days, months, seasons, a few capitals
- short sums, differences and small times tables
- a few everyday tips and jokes

Anything else gets a plain "I do not know that" answer. It is a test model: it can be wrong, it can repeat itself, and a question phrased in a way it has not seen may get an odd reply. Do not use it for facts that matter.

It never calls tools. Text typed into the chat cannot move money or change a setting, and the model has been trained to say so when asked to.

## Try it

```bash
scripts/try-mini-model.sh "What is the capital of Japan?"
```

The script builds the tools, then in a scratch directory it makes keys, publishes the model, collects two approvals, starts a node and asks your question through the real client. It removes everything afterwards. To do the steps by hand, follow [publishing-models.md](publishing-models.md) with the two files above.

The test `the_bundled_mini_model_is_published_hosted_and_answers_in_words` runs the same flow on every `cargo test`.

## Rebuild it

```bash
python3 -m venv tools/mini-model/.venv
tools/mini-model/.venv/bin/pip install -r tools/mini-model/requirements.txt
tools/mini-model/.venv/bin/python tools/mini-model/build.py out 2400
```

The script trains on the processor in several minutes and writes the weights and the tokenizer into `out/`. A rebuilt model has a different fingerprint, so it needs new approvals. The training network uses the same rotary-position layout as the runtime, and the exported file loads with the runtime's own loader.

## Not done yet

- The desktop app and the `suricomai` command still know only the built-in test model and the optional SmolLM2 model. This model is reached through the publishing flow above.
- It is hosted from files, so it is not private. Hosted models become private only on measured confidential hardware, which does not exist yet.
