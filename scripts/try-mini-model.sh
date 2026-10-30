#!/bin/sh
# Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
# Publish, approve, host and ask the bundled mini chat model with the real tools, in a scratch
# directory that is removed afterwards. This is a development build: answers are not private.
#   usage: scripts/try-mini-model.sh ["your question"]
set -eu
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
QUESTION="${1:-What can you do?}"
WORK="$(mktemp -d)"
NODE_PID=""
cleanup() { [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

cargo build -q -p suricomai-runtime --features lab --bins
BIN="$ROOT/target/debug"
mkdir -p "$WORK/node" "$WORK/client"
cp models/suricomai-mini-chat.gguf "$WORK/node/suricomai-mini-chat.gguf"
cp models/suricomai-mini-chat.tokenizer.json "$WORK/node/suricomai-mini-chat.tokenizer.json"
cd "$WORK"

"$BIN/suricomai-models" keygen publisher.key >/dev/null
A1="$("$BIN/suricomai-models" keygen approver1.key | awk '{print $2}')"
A2="$("$BIN/suricomai-models" keygen approver2.key | awk '{print $2}')"
printf 'suricomai-trust-v1\nthreshold 2\napprover %s\napprover %s\n' "$A1" "$A2" > trust
chmod 600 trust
"$BIN/suricomai-models" publish-files publisher.key suricomai-mini-chat \
  node/suricomai-mini-chat.gguf node/suricomai-mini-chat.tokenizer.json 2 MIT mini.manifest >/dev/null
FROM="$(date +%s)"; UNTIL=$((FROM + 86400))
"$BIN/suricomai-models" approve approver1.key mini.manifest approved "$FROM" "$UNTIL" a1.approval >/dev/null
"$BIN/suricomai-models" approve approver2.key mini.manifest approved "$FROM" "$UNTIL" a2.approval >/dev/null
for f in mini.manifest a1.approval a2.approval; do cp "$f" node/; cp "$f" client/; done

"$BIN/suricomai-node" --listen 127.0.0.1:0 --models node --trust trust > node.log 2>&1 &
NODE_PID=$!
i=0
until grep -q '^listening ' node.log 2>/dev/null; do
  i=$((i + 1)); [ "$i" -gt 100 ] && { echo "the node did not start"; cat node.log; exit 1; }
  sleep 0.1
done
TICKET="$(sed -n 2p node.log)"
ADDR="$(grep '^listening ' node.log | awk '{print $2}')"
echo "question: $QUESTION"
"$BIN/suricomai-ask" --model suricomai-mini-chat --models client --trust trust "$ADDR" "$TICKET" "$QUESTION"
