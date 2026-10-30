# SuriComAIEscrow

Reference escrow contract for paying inference jobs on an EVM chain.

> **Status: reference implementation. Unaudited. Not deployed. Do not use it with real funds.**
> It exists so the rules can be reviewed and tested before any money is involved.

## What it does

A user locks a fee for one job and names the worker who may take it. The worker posts a bond. A fixed committee of signers then attests either that a valid proof was shown (the worker is paid) or that a fault occurred (the user is refunded and the bond is seized). After expiry, anyone can return the fee and the bond to the user with no help from the worker or the committee.

- One ERC-20 (such as USDC), fixed at deployment.
- Immutable: no admin key can move user funds, change a rule, or change the committee.
- Every payout is a pull, so one frozen or reverting recipient cannot block anyone else.
- The contract never sees a prompt, an answer, or a proof. It sees only a 32 byte contract hash.
- Launch caps limit the total value held and rise on a fixed public schedule.

## Trust assumptions

1. The committee is trusted to sign only valid outcomes. In this version it is **not bonded on-chain**. A threshold of colluding members could pay for work that was never done.
2. The token issuer can freeze addresses, including this contract.
3. The chain can halt or censor.

## Layout

| Path | Purpose |
| --- | --- |
| `src/SuriComAIEscrow.sol` | The contract |
| `test/` | Tests: lifecycle, signature attacks, hostile tokens, configuration, and invariants |
| `run.sh` | Runs Foundry from the official image, pinned by digest. Nothing is installed on the host. |

There are no third-party Solidity dependencies. Cheatcodes and mocks are in `test/`.

## Run the tests

You need Docker. 67 tests: lifecycle, signature attacks, hostile tokens, configuration, fuzz, and four invariants checked over 16,384 random calls. Line coverage of the contract is 100 percent and branch coverage is about 93 percent.

```bash
contracts/run.sh "forge test"
contracts/run.sh "forge test --gas-report"
contracts/run.sh "forge coverage --report summary --no-match-coverage 'test|script'"
```

## End to end on a local chain

`contracts/e2e.sh` starts a local EVM chain in Docker and runs a whole job: Rust seals a job and builds a worker result, the real contract locks the fee and the bond, both verifiers (Rust and an independent Python one) check the proof, three of five committee members sign in Rust, and the contract pays out. It also checks that signatures for a different amount are refused, that a job cannot be paid twice, and that an unfinished job is refunded after expiry. It uses the public Anvil test keys, which hold no value.

```bash
contracts/e2e.sh
```

The signer lives in `crates/suricomai-attestor`. It will not sign unless a second, independently written verifier agrees with the envelope auditor.

## Measured gas (execution, median)

| Call | Gas |
| --- | ---: |
| `lock` | about 240,000 |
| `postBond` | about 133,000 |
| `settle` | about 228,000 |
| `slash` | about 158,000 |
| `expire` | about 97,000 |
| `withdraw` | about 77,000 |

A full paid job uses about 600,000 gas before withdrawals. That is cheap on a layer-2 and costly on Ethereum mainnet, and it is too much to pay per chat message, which is why payment channels are planned.

## Signing format

Committee signatures use EIP-712 typed data. Reference digests, computed with a separate tool, are pinned in `test/Signatures.t.sol` so other implementations can check themselves against them.
