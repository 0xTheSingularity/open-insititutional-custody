---
type: testing-guide
title: Deterministic chain simulators
description: Reproducible EVM and Solana development chains with real native signatures, explicit mining/finality, reorg/fork controls, economic effects, and adversarial evidence sources.
tags: [testing, simulator, evm, solana, determinism, finality]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:16:28.312Z
sources:
  - id: openwiki-source-c888f5f1e497e29ef6435a0b
    resource: repo://crates/chain-simulator/src/clock.rs
  - id: openwiki-source-75046cdd8a0a5ae5348afe95
    resource: repo://crates/chain-simulator/src/evm.rs
  - id: openwiki-source-4557d0fe6dfeef73252340e1
    resource: repo://crates/chain-simulator/src/lib.rs
  - id: openwiki-source-97cb2f0c75b5ed8f8eb38ec5
    resource: repo://crates/chain-simulator/src/solana.rs
  - id: openwiki-source-6c9467432de7b3b5b98c57c3
    resource: repo://crates/chain-simulator/tests/evm.rs
  - id: openwiki-source-e45dd1e96ca5e965393abce6
    resource: repo://crates/chain-simulator/tests/solana.rs
generated: { by: "codex", at: "2026-10-20T20:16:28.312Z" }
---

# Deterministic chain simulators

`oic-chain-simulator` supplies in-process `EvmSimulator` and `SolanaSimulator`. Each is a signed-transaction target, evidence source in the pinned adapter's format, and block/effects feed. Shared mutable state is mutex-protected and can be passed through `Arc` to builder, broadcaster and tests.

All emitted bundles carry `DevelopmentSimulator` trust. Faucet/mint authority keys derive from public seeds; these are development chains. The policy kernel only accepts simulator evidence in environment `dev`.

## Reproducibility and progression

`SimClock` is shared and manually advanced. It refuses backwards time and arithmetic overflow. Block timestamps and evidence observation times use this clock rather than wall time. Identical configuration seeds and scripts produce the same results.

Submission acknowledges a mempool/queue handoff; it does not mine. Explicit progression APIs control the test:

| EVM | Solana |
| --- | --- |
| `fund`, `deploy_erc20`, `erc20_fund`, `install_code` | `airdrop`, `create_mint`, `create_ata`, `mint_to`, `create_lookup_table` |
| `submit` | `submit` |
| `mine`, `mine_blocks` | `advance_slot`, `advance_slots` |
| `reorg(depth, drop_tx_ids)` | `fork(discard_after_slot, drop_tx_ids)` |
| `receipt`, `block`, balances/nonce, `evidence` | `tx_status`, `block`, lamports/token balances, `evidence` |
| `evidence_from`, `set_lie`, `clear_lies` | `evidence_from`, `set_lie`, `clear_lies` |

Setup system operations affect working state immediately but enter block evidence only after the next block/slot. Mine after setup before expecting a builder to observe the new token/account state. Both fork APIs restore snapshots, replay system operations and optionally requeue discarded transactions; crossing finalized history is refused.

## EVM model

Accounts track native balance, nonce and code. Submission verifies native ECDSA recovery and chain id, checks nonce progression/replacement, balance and fee cap, and queues exact signed bytes. A replacement must raise priority fee strictly and by at least ten percent.

Mining processes includable transactions in sender nonce order and charges modeled gas at `min(max_fee, base_fee + priority)` for type 2. Fee spikes can leave a transaction pending. Registered ERC-20 `transfer` updates token balances and emits `Transfer` logs; reverted calls move neither value nor tokens but still pay fees. Legacy replay-protected transactions also execute.

`set_fees` controls fees explicitly. This is not a general EVM: it omits contract-internal native movement, arbitrary execution, contract-creation transactions, access lists, calldata gas/refunds, and fullness-driven base fee adjustment. Adapter acceptance is narrower still; a simulator capability does not automatically become an authorized custody operation.

## Solana model

One block is produced per slot, so block height equals slot **in this model**. Recent blockhashes have a configurable validity window. Accounts track lamports, owner and data; classic token/mint data uses real packed layouts. Submission verifies exact-message Ed25519 signatures, programs/instructions, lookup resolution, blockhash window, replay and fee-payer funds.

Slot progression includes queued transactions in arrival order. An expired/orphaned blockhash or inability to pay drops a queued transaction. Otherwise signature/priority fees are charged and instructions execute atomically: a failed instruction preserves fees while rolling back instruction effects. Commitment is processed at head, confirmed below head and finalized after configured depth.

The simulator models SOL, classic SPL, ATA setup, compute budget and Memo. The custody adapter rejects Memo, demonstrating that chain execution support and authorization support differ. Rent collection/system-account exemption, delegates/multisig/wrapped SOL, durable nonces, lookup-table lifecycle and CPI are outside the model.

## Adversarial evidence

`evidence_from` stamps a chosen source identity. `set_lie` overrides transaction observations for one source without changing the actual chain, enabling tests where providers disagree about success/finality. The broadcaster compares all configured sources and quarantines conflict. Multiple labeled simulator sources exercise cross-check logic; they are not independent production nodes.

EVM queries can expose a foreign nonce consumer for invalidation. Solana queries include per-blockhash validity and exact signed bytes so the adapter can prove expiry without treating a timeout as cancellation. See [broadcast and finality](../workflows/broadcast-and-finality.md).

## Runnable examples and tests

```sh
cargo test -p oic-chain-simulator --locked
cargo test -p oic-service-coordinator --locked --test coordinator
cargo test -p oic-service-broadcaster --locked
```

[`tests/evm.rs`](../../crates/chain-simulator/tests/evm.rs) demonstrates funded native/ERC-20 transfer, replacement, fee spikes, finality, reorg atomicity and source conflict. [`tests/solana.rs`](../../crates/chain-simulator/tests/solana.rs) covers SOL/SPL with ATA setup, blockhash expiry, atomic failure, forks, v0 lookups and conflict. Both check deterministic results and sharing across threads.

Use [EVM adapter](../integrations/evm-adapter.md) and [Solana adapter](../integrations/solana-adapter.md) for custody verification constraints; use the [test guide](verification-guide.md) to distinguish simulator integration from SDK differential checks and bounded model checking.
