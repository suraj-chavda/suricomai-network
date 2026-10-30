# Payments and fees: the plan

> **This is a plan. Nothing here is live.** No contract is deployed, no money moves, and no fee is collected. The fee math described below exists as tested code and test vectors. The escrow contract does not enforce it yet, so no product may show these prices as real until it does.

This document is for the project owner, for people who will test, and for anyone who wants to know what SuriComAI will charge before it asks them for money. It states what is decided, what is only recommended, and what still needs a lawyer, an auditor, or a measurement.

## 1. The short version

| Question | Answer |
| --- | --- |
| Which chain | **Arbitrum One** for launch, **Arbitrum Sepolia** for the public testnet, with Base Sepolia as a second test chain for measuring gas and portability. Recommended, not final: it is final only after the gas measurement and a fresh stage check on L2BEAT. |
| Which money | **Native USDC only.** No bridged USDC, no other token at launch. |
| What a user pays | The worker's price plus three named lines: protocol, attestation, relay. About 3 percent on top of the price at the proposed rates, and the relay line only when a relay was used. Network gas is separate and shown separately. |
| Hidden charges | None by construction. The user locks one total. The contract can pay out only the lines in the quote. A failed job refunds everything, including every fee. |
| Who earns the protocol fee | A multisig wallet controlled by the project's operating entity. **Not a personal wallet.** |
| Can it be unbreakable | No software can promise that. The plan bounds the loss instead: deposit caps, an audit, a bug bounty, immutable code, pull payments and tested invariants. |
| Can it serve 100,000 million users | Not by sending every job to a chain. It needs payment channels and batched settlement, and it must be proven by load tests before anyone says it. Section 7 shows the arithmetic. |

## 2. What is decided and what is not

| Item | State | Who decides |
| --- | --- | --- |
| Settle on an existing Ethereum layer-2, no new token at first | Decided (owner, 2026-10-29) | Done |
| Arbitrum One plus native USDC | Recommended here | Owner, after measurement and counsel |
| Protocol fee rate | Proposed 1 percent, hard cap 3 percent | Owner |
| Protocol fee recipient is a multisig | Recommended here | Owner and counsel |
| Operating entity and jurisdiction | Open | Owner and counsel |
| Committee operators and their bonds | Open | Owner |
| Card or bank on-ramp partner | Open. A licensed third party only. | Owner and counsel |

## 3. The chain and the money

### 3.1 Chain: Arbitrum One

Why it is the recommendation:

- Settlement on an Ethereum layer-2 inherits Ethereum's security for finality, and the contract is plain Solidity, so it can be deployed on other EVM chains without a rewrite.
- Arbitrum One is reported at L2BEAT Stage 1 by several 2026 sources ([summary](https://www.spotedcrypto.com/best-ethereum-l2-2026-arbitrum-base-optimism-zksync/)). Stage 1 means users have a limited way to exit without the operator's help. Base is reported inconsistently, as Stage 0 in some sources and Stage 1 in others ([discussion](https://www.growthepie.com/answers/ethereum-l2-maturity-stages)). Check [l2beat.com](https://l2beat.com) directly before finalizing, because these are secondary sources and stages change.
- Native USDC and Circle's test faucet exist on its test network (see 3.3).

What it costs, stated plainly:

- **The sequencer is centralized** on Arbitrum, Base and OP alike. It can delay or censor your transactions. Users can force inclusion through Ethereum after a delay. Job expiry times must be longer than that delay, or a user could miss a refund window. The delay length must be confirmed from current Arbitrum documentation before the expiry rules are frozen.
- **Base would give better reach** to people who already use Coinbase products. That is a real advantage, and a later second deployment can use it. The contract's chain binding means a job on one chain can never be replayed on another.

### 3.2 Money: native USDC only

- **Native only.** Circle-issued USDC on Arbitrum, never the older bridged `USDC.e` and never a wrapped copy. The contract is built for exactly one token address, fixed at deployment, and the client shows that address.
- **One token.** A second token is a separate deployment, never a switch inside one.
- **No Tether.** Reports say it has frozen far more than USDC, and its rules are less predictable.

### 3.3 The honest risk of USDC

USDC is issued by a company, and the token contract has a blacklist. The issuer can freeze any address, including a contract. This is not hypothetical: US law now expects issuers to keep that ability ([GENIUS Act summary](https://phemex.com/academy/genius-act-stablecoin-rules-usdc-usdt)), and in March 2026 Circle froze 16 wallets including a bridge helper contract ([report](https://blog.amlbot.com/circle-froze-16-business-hot-wallets-including-a-blockchain-bridge-smart-contract/)). These are third-party reports, so read the primary sources before relying on the details.

What that means for SuriComAI:

- If the escrow contract's own address were frozen, funds in it would be stuck. The contract cannot prevent that.
- What we do about it: launch deposit caps so exposure stays small, pull payments so one frozen recipient cannot block anyone else, a public statement of this risk in the product, and a later option for a second deployment on a different asset.
- A payee that is frozen simply cannot withdraw their own share. Nobody else is affected.

## 4. What a user pays

### 4.1 The quote

Every job has exactly one price, shown before it is sent. Proposed rates, all fixed per deployment:

| Line | Amount | Paid to |
| --- | --- | --- |
| Worker price | Set by the worker for the job size. Minimum 1 cent. | The worker, in full |
| Protocol fee | 1 percent of the price, rounded up. Hard cap 3 percent. | The protocol fee recipient |
| Attestation fee | 1 percent of the price, but never under 0.2 cents. Hard cap 3 percent. | The committee that signs the settlement |
| Relay fee | Up to 1 percent, only if a relay carried the job. Hard cap 3 percent. | That relay. The unused part is refunded. |

Example for a one dollar job carried by a relay: price 1.0000 USD, protocol 0.0100, attestation 0.0100, relay 0.0100. The user locks 1.0300 USD. If no relay is used, 0.0100 comes back. If the job fails or expires, all 1.0300 comes back.

**The smallest jobs.** The attestation line has a fixed floor because signing and settling cost the same however small the job is. A 1 cent job therefore pays 0.2 cents of attestation, which is 20 percent. That is why micro jobs must go through payment channels (section 7) and why the minimum price is 1 cent.

**Today's contract is different.** The reference contract takes 30 percent off the worker's side (70 percent worker, 15 committee, 5 relay, 10 reserve). The plan replaces that with the on-top schedule above, which is far cheaper for users and shows every line. That change needs the contract to be rewritten and tested first.

### 4.2 The rules that make hidden charges impossible

1. **One total.** The user locks the quote total and nothing else. There is no second deduction anywhere.
2. **The contract pays only what the quote names.** The committee signs the quote, not a free amount, and each line is checked against the schedule fixed in the contract. A committee cannot invent a bigger fee.
3. **Failure is free.** An expired or failed job refunds everything, including the protocol fee. The protocol earns only on delivered work.
4. **Hard caps in code.** No schedule can exceed 3 percent on any line, so the worst case overhead is bounded and published.
5. **The schedule is visible.** The client shows the contract address and the hash of its fee schedule before any money moves.
6. **The schedule is fixed.** A deployment cannot change its rates. Different rates mean a new deployment, announced at least 30 days ahead, and jobs already locked are untouched.
7. **No spread.** Prices are in USDC. A local currency amount is an estimate for display only and is marked as one.
8. **No custody.** Funds sit in the contract, not with us. We have no way to move a user's money, and neither does anyone else.
9. **No withdrawal fee, no subscription, no minimum balance.**
10. **Same math everywhere.** The fee calculation is implemented twice, in Rust and in Python, and both are checked against the same published vectors.

Things that cost money but are not ours, shown so nobody is surprised:

- **Network gas** for each on-chain transaction, paid by whoever sends it. A later gasless option lets a user sign instead of sending, with any relayer submitting, and the cost of that goes into the attestation line.
- **Card or bank top-up** charges by the licensed third-party provider, shown by that provider.
- **Exchange spreads** wherever a user converts money.

## 5. Where the money goes, and your fee

### 5.1 The protocol fee recipient

The protocol fee is how the project earns. It is paid to one address set when the contract is deployed.

**Use a multisig wallet, not a personal wallet.** A multisig (for example a Safe with 2 of 3 or 3 of 5 signers) needs several people to move funds and can replace a lost or compromised key without changing the address the contract pays. A personal wallet is one lost phone or one stolen key away from losing every future fee, and it makes the project look like one person's account. It also blurs the line between your money and the entity's money, which matters for tax and for liability.

- The address is published and shown in the client.
- Fees are credited to a balance that the recipient withdraws. A frozen recipient blocks only itself.
- The address cannot be changed after deployment. A multisig lets its owners change who controls it.

### 5.2 What the protocol fee is for

Audits, the bug bounty, the sandbox network, infrastructure, legal costs and people. Publish a yearly statement of fees received and spent. That is what makes a protocol fee trustworthy.

### 5.3 What revenue to expect

This is arithmetic, not a forecast. At a 1 percent protocol fee, revenue is 1 percent of the money paid to workers.

| Worker payments per day | Protocol fee per day | Per year |
| --- | --- | --- |
| 1,000 USD | 10 USD | 3,650 USD |
| 100,000 USD | 1,000 USD | 365,000 USD |
| 10,000,000 USD | 100,000 USD | 36,500,000 USD |

Early on, revenue will not cover an audit. Plan the first year on separate funding, and treat fee revenue as something that grows only with real paid use.

## 6. Security of the money

An honest statement first: **no system is unbreakable.** The plan is to make failure rare, small, visible and recoverable.

| Protection | What it does | State |
| --- | --- | --- |
| Conservation | Every payout path sums to what was locked. A test checks it. | Built and tested for the current contract. The fee math is tested and has independent vectors. |
| Immutable contract | No admin key can move funds or change a rule. | Built (reference) |
| Expiry refund | After expiry anyone can return the fee to the user, with nobody else needed. | Built (reference) |
| Pull payments | One frozen or reverting recipient cannot block others. | Built (reference) |
| Launch caps | Total and per-user deposit limits that rise on a published schedule, so an unknown bug can only lose a small amount. | Built (reference). Numbers not chosen. |
| Pause | May stop new locks only. It can never block a refund. | Built (reference) |
| Committee threshold | N of M signers must sign a settlement. | Built (reference) |
| **Committee bonding** | Committee members post bonds that are slashed for signing something false. | **Not built.** Today a threshold of colluding members could approve unpaid work. |
| **External audit** | Independent review of the contract and the committee design. | **Not done. Required before mainnet.** |
| **Bug bounty** | Paid reports before caps rise. | **Not live. Required before caps rise.** |
| Monitoring | Alerts on unusual volume, a changed committee, a frozen contract. | Not built |
| Incident plan | Who does what within the first hour, how users are told. | Not written |

The reference contract is unaudited and not deployed. **Do not put real funds in it.**

## 7. Scale: from one user to a very large number

"100,000 million" is 100 billion. That is more than ten times the world's population, so read it as a design ceiling for **jobs and records**, not people. Here is what that means for money.

- **One on-chain transaction per job cannot reach that.** The measured gas for a job is about 600,000 across lock, bond and settle. Even at cheap layer-2 prices, and even if the chain could take it, that is too much per small job.
- **Payment channels fix this.** A user opens one channel with one deposit. Each job is a signed voucher passed off-chain between user and worker. Many jobs settle in one on-chain transaction. The fee lines are computed per voucher with the same exact math and summed.
- **The arithmetic.**

| Jobs per day | Jobs per second | On-chain transactions needed |
| --- | --- | --- |
| 1 million | about 12 | Direct per-job settlement is possible. It is costly. |
| 100 million | about 1,160 | Channels are required. |
| 10 billion | about 116,000 | Channels plus several deployments across chains. |
| 100 billion | about 1.16 million | Channels, many deployments, and batched settlement. A load test must show it. |

- **What is promised.** Nothing about these top rows until a test proves them. What can be promised now is the design: bounded cost per job, no global lock, fixed-size records, and money math that does not depend on how many jobs exist.
- **What is not built.** Payment channels, batching and multi-chain deployment. They come after the single-job path is audited.

## 8. Legal and tax

This is a list of questions for a qualified lawyer and accountant in each country you serve. It is not advice.

- **Entity.** Which company or foundation receives the protocol fee, where, and who is liable.
- **Money transmission.** Whether a contract that holds user funds between a user and a worker triggers licensing, and whether the answer changes with the contract having no admin.
- **Sanctions.** USDC can be frozen and US sanctions apply to its issuer. Decide what the product layer does, such as blocking by country or by listed address, without putting a switch in the protocol.
- **Tax.** Fee income is business income in most places. Workers' earnings are theirs to report.
- **On-ramp.** Only a licensed third party takes cards or bank transfers. We never touch card data or hold customer funds.
- **Terms and notices.** Terms of use, a privacy notice, a clear statement that hosted models are not private, and a statement of the USDC risk in 3.3.
- **Securities.** There is no token in this stage, so no token question yet.

Nothing here ships to mainnet without written advice on file.

## 9. Testnet and sandbox

Goal: anyone can try the whole payment flow with worthless money, see the exact quote, and break things safely.

### 9.1 What testers get

| Piece | Detail |
| --- | --- |
| Chain | Arbitrum Sepolia. A second deployment on Base Sepolia to compare gas and portability. |
| Money | Circle's test USDC. Circle's public faucet gives test USDC on both networks, limited to one request every 24 hours per test network, and it does not give gas. Gas comes from a separate faucet ([Circle faucet notes](https://eco.com/support/en/articles/17593747-usdc-testnet-faucets-2026-sepolia-base-sepolia-arc-solana-devnet)). Confirm current limits and addresses in Circle's own documentation before publishing instructions. |
| Contract | The same code and the same fee schedule as the planned mainnet, deployed to the test chain. |
| Network | A seed directory, a registry, a few nodes running test models, and a test attestation committee. All run by the project and all labeled. |
| Labels | Every screen and every command says `TESTNET: no value`. The client refuses a mainnet address in sandbox mode and a testnet address in mainnet mode. |
| Committee keys | Public test keys, so anyone can reproduce a settlement. They are labeled as insecure by design. |

### 9.2 What testers can do

1. Get test USDC and test gas.
2. See an itemized quote before sending, with the contract address and schedule hash.
3. Run a job, watch it settle, and check that the payout matches the quote to the unit.
4. Let a job expire and check the full refund, including the fee.
5. Try a hostile case: replay a settlement, settle twice, use the wrong chain. Each must fail.
6. Report problems. A testnet bounty with a clear scope is worth running before mainnet.

### 9.3 What it needs that only the owner can provide

- A funded deployer wallet and a multisig for the test fee recipient.
- Hosting for the directory, registry, nodes and a faucet service, plus a domain.
- A decision on how long testnet data is kept and when it is reset.
- Docker or Foundry on a machine, to run the contract tests. They could not be run in the environment this plan was written in.

## 10. Build order

| # | Work | State |
| --- | --- | --- |
| 1 | Fee math with exact rounding, hard caps, schedule bytes | **Done and tested** |
| 2 | Test vectors checked by a second, independent implementation | **Done** |
| 3 | Write the rules into the wire spec | **Done** |
| 4 | Rewrite the escrow contract to this schedule, with the new corner cases as tests | **Next. Needs Foundry or Docker.** |
| 5 | Update the Rust escrow state machine and the committee message so they carry the quote lines | After 4 |
| 6 | Deploy to Arbitrum Sepolia and Base Sepolia, measure real gas, check the sequencer delay | Needs a funded deployer wallet |
| 7 | Client shows the itemized quote, the contract address and the schedule hash, and refuses the wrong network | After 5 |
| 8 | Sandbox network, faucet and tester guide | After 6 and 7 |
| 9 | Committee bonding and key custody | Before any mainnet funds |
| 10 | External audit, bug bounty, legal sign-off | Before any mainnet funds |
| 11 | Mainnet with small caps, then raise caps on the published schedule | After 9 and 10 |
| 12 | Payment channels and batched settlement | After a stable single-job path |

## 11. Decisions for the owner

1. Is a 1 percent protocol fee right, within the 3 percent cap? A lower rate wins users and a higher one funds work. It cannot change after deployment.
2. Who are the multisig signers, and how many are needed?
3. Which entity receives the fee, and in which country?
4. Who runs the committee, how many members, and what bond?
5. Arbitrum One as recommended, or Base for reach, once the measurement is in?
6. Is Circle's blacklist acceptable at launch with small caps, given the risk in 3.3?
