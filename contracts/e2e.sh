#!/bin/sh
# End to end: a real sealed job, a real worker result, both verifiers, committee signatures
# made in Rust, and the money moved by the real contract on a local EVM chain.
#
# Needs Docker and a Rust toolchain. Uses the well known Anvil test accounts, which hold no
# real value. Never use these keys anywhere else.
set -eu

IMAGE="ghcr.io/foundry-rs/foundry@sha256:4a16a86f41d30418fbdca47ce2868121bbb0aeaa0a34bde2dd1e2911c4be2464"
NAME="suricomai-e2e-anvil"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RPC="http://host.docker.internal:8545"
WORK="$(mktemp -d)"

# Anvil default accounts (public test keys).
K_DEPLOY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
USER=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
K_USER=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
WORKER=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC
K_WORKER=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
PAYEE=0x90F79bf6EB2c4f870365E785982E1f101E93b906
K_PAYEE=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
RESERVE=0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65
GUARDIAN=0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc
ZERO=0x0000000000000000000000000000000000000000

fx() { docker run --rm -v "$ROOT/contracts:/work" -w /work "$IMAGE" "$*"; }
stop() { docker rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap stop EXIT

BAD_SIGNATURES=$(docker run --rm "$IMAGE" "cast sig 'BadSignatures()'")
BAD_PHASE=$(docker run --rm "$IMAGE" "cast sig 'BadPhase()'")

fail() { echo "FAIL: $1" >&2; exit 1; }
num() { awk '{print $1}'; }
expect() { [ "$2" = "$3" ] || fail "$1: got $2, want $3"; echo "ok   $1 = $2"; }

echo "== start a local chain"
stop
mkdir -p "$WORK"
docker run -d --rm --name "$NAME" -p 8545:8545 "$IMAGE" "anvil --host 0.0.0.0 --chain-id 31337" >/dev/null
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  fx "cast chain-id --rpc-url $RPC" >/dev/null 2>&1 && break
  sleep 2
done
fx "cast chain-id --rpc-url $RPC" >/dev/null 2>&1 || fail "chain did not start"

NOW=$(date +%s)
SALT=0x00000000000000000000000000000000000000000000000000000000000000a1
CAP=1000

echo "== prepare a real job and result (Rust)"
cd "$ROOT"
PREP=$(cargo run -q -p suricomai-attestor --example attestor_e2e -- prepare "$WORK" "$USER" "$SALT" "$NOW" "$CAP")
echo "$PREP" | sed 's/^/   /'
JOB_ID=$(echo "$PREP" | sed -n 's/^job_id=//p')
CONTRACT_HASH=$(echo "$PREP" | sed -n 's/^contract_hash=//p')
RECEIPT_KEY=$(echo "$PREP" | sed -n 's/^receipt_key=//p')
COMMITTEE=$(echo "$PREP" | sed -n 's/^committee=//p')

echo "== deploy the token and the escrow"
TOKEN=$(fx "forge create test/Mocks.sol:MockUSDC --rpc-url $RPC --private-key $K_DEPLOY --broadcast --json" | tr -d '\n ' | sed -n 's/.*"deployedTo":"\([^"]*\)".*/\1/p')
[ -n "$TOKEN" ] || fail "token not deployed"
ARGS="($TOKEN,$COMMITTEE,3,$RESERVE,$GUARDIAN,5000,1000000000000,0,86400,1000000000000,1000000000000)"
ESCROW=$(fx "forge create src/SuriComAIEscrow.sol:SuriComAIEscrow --rpc-url $RPC --private-key $K_DEPLOY --broadcast --json --constructor-args '$ARGS'" | tr -d '\n ' | sed -n 's/.*"deployedTo":"\([^"]*\)".*/\1/p')
[ -n "$ESCROW" ] || fail "escrow not deployed"
echo "   token=$TOKEN escrow=$ESCROW"

send() { fx "cast send $* --rpc-url $RPC" >/dev/null; }
call() { fx "cast call $* --rpc-url $RPC"; }

echo "== fund and approve"
send "$TOKEN 'mint(address,uint256)' $USER 1000000"  --private-key $K_DEPLOY
send "$TOKEN 'mint(address,uint256)' $WORKER 1000000" --private-key $K_DEPLOY
send "$TOKEN 'approve(address,uint256)' $ESCROW 1000000" --private-key $K_USER
send "$TOKEN 'approve(address,uint256)' $ESCROW 1000000" --private-key $K_WORKER

echo "== user locks the fee and pins the worker"
EXPIRY=$((NOW + 3600))
send "$ESCROW 'lock(bytes32,bytes32,uint128,uint64,uint128,address)' $SALT $CONTRACT_HASH $CAP $EXPIRY 100 $WORKER" --private-key $K_USER
HELD=$(call "$ESCROW 'heldFees()(uint256)'" | num)
expect "fee held on chain" "$HELD" "$CAP"
OWNER=$(call "$ESCROW 'jobs(bytes32)(address,uint64,uint8,uint128,uint128,address,address,bytes32,bytes32)' $JOB_ID" | sed -n 1p)
[ "$(echo "$OWNER" | tr 'A-F' 'a-f')" = "$(echo "$USER" | tr 'A-F' 'a-f')" ] || fail "the job id Rust computed is not the id the contract made"
echo "ok   the job id computed in Rust equals the contract's id"

echo "== worker posts the bond and records its receipt key"
send "$ESCROW 'postBond(bytes32,address,bytes32)' $JOB_ID $PAYEE $RECEIPT_KEY" --private-key $K_WORKER
expect "bond held on chain" "$(call "$ESCROW 'heldBonds()(uint256)'" | num)" 100

echo "== committee verifies the proof with two verifiers and signs (Rust)"
CHAIN_TIME=$(fx "cast block latest --field timestamp --rpc-url $RPC" | num)
SIGS=$(cargo run -q -p suricomai-attestor --example attestor_e2e -- sign "$WORK" 31337 "$ESCROW" "$WORKER" 1000 "$ZERO" $((NOW + 10)))
echo "   signatures: $(echo "$SIGS" | wc -c) characters"

echo "== a tampered amount is refused by the contract"
ERR=$(fx "cast call $ESCROW 'settle(bytes32,uint256,address,bytes)' $JOB_ID 999 $ZERO $SIGS --from $USER --rpc-url $RPC 2>&1" || true)
echo "$ERR" | grep -q "$BAD_SIGNATURES" || fail "expected BadSignatures ($BAD_SIGNATURES), got: $ERR"
echo "ok   signatures for 1000 cannot pay 999 (BadSignatures)"

echo "== settle on chain with the Rust signatures"
send "$ESCROW 'settle(bytes32,uint256,address,bytes)' $JOB_ID 1000 $ZERO $SIGS" --private-key $K_USER
expect "worker share owed" "$(call "$ESCROW 'claimableOf(address)(uint256)' $PAYEE" | num)" 700
expect "reserve owed (10 percent plus the unused relay 5 percent)" "$(call "$ESCROW 'claimableOf(address)(uint256)' $RESERVE" | num)" 150
expect "worker bond owed back" "$(call "$ESCROW 'claimableOf(address)(uint256)' $WORKER" | num)" 100
expect "user refund owed" "$(call "$ESCROW 'claimableOf(address)(uint256)' $USER" | num)" 0

echo "== a second settlement is refused"
ERR=$(fx "cast call $ESCROW 'settle(bytes32,uint256,address,bytes)' $JOB_ID 1000 $ZERO $SIGS --from $USER --rpc-url $RPC 2>&1" || true)
echo "$ERR" | grep -q "$BAD_PHASE" || fail "expected BadPhase ($BAD_PHASE), got: $ERR"
echo "ok   a job pays once (BadPhase)"

echo "== the worker is paid by pull"
send "$ESCROW 'withdraw(address)' $PAYEE" --private-key $K_PAYEE
expect "tokens received by the payee" "$(call "$TOKEN 'balanceOf(address)(uint256)' $PAYEE" | num)" 700
expect "owed after withdrawing" "$(call "$ESCROW 'claimableOf(address)(uint256)' $PAYEE" | num)" 0
SOLVENT=$(call "$TOKEN 'balanceOf(address)(uint256)' $ESCROW" | num)
OWED=$(call "$ESCROW 'totalClaimable()(uint256)'" | num)
expect "contract balance equals what it still owes" "$SOLVENT" "$OWED"

echo "== a job nobody completes is refunded to the user after expiry, with no one's help"
SALT2=0x00000000000000000000000000000000000000000000000000000000000000a2
send "$ESCROW 'lock(bytes32,bytes32,uint128,uint64,uint128,address)' $SALT2 $CONTRACT_HASH 500 $((CHAIN_TIME + 600)) 0 $WORKER" --private-key $K_USER
JOB2=$(fx "cast keccak \$(cast abi-encode 'f(address,bytes32)' $USER $SALT2)")
fx "cast rpc evm_increaseTime 4000 --rpc-url $RPC" >/dev/null
fx "cast rpc evm_mine --rpc-url $RPC" >/dev/null
send "$ESCROW 'expire(bytes32)' $JOB2" --private-key $K_PAYEE
expect "user owed the whole fee" "$(call "$ESCROW 'claimableOf(address)(uint256)' $USER" | num)" 500

echo
echo "E2E PASSED"
