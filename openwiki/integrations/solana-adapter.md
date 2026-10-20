---
type: integration
title: Solana message adapter
description: Exact Solana message signing, strict legacy/v0 verification, lookup and token-account evidence, SOL/SPL transfers, fee accounting, and finalized blockhash invalidation.
tags: [solana, adapter, spl-token, ed25519, blockhash, lookup-tables]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:16:28.312Z
sources:
  - id: openwiki-source-ff50a5ef5ea888b3f156d3de
    resource: repo://crates/adapter-solana/README.md
  - id: openwiki-source-52729557ed0f1fd7befd9ec7
    resource: repo://crates/adapter-solana/src/instruction.rs
  - id: openwiki-source-6454c64e67ef267ee2f3253d
    resource: repo://crates/adapter-solana/src/lib.rs
  - id: openwiki-source-35c27683276ba52c4c1fb983
    resource: repo://crates/adapter-solana/src/message.rs
  - id: openwiki-source-4c0dec1b61f8c59ef7c2e131
    resource: repo://crates/adapter-solana/tests/adapter.rs
generated: { by: "codex", at: "2026-10-20T20:16:28.312Z" }
---

# Solana message adapter

`oic-adapter-solana::SolanaAdapter` implements `ChainAdapter` with handwritten wire formats and no RPC or clock access. Solana SDK packages are differential test dependencies. The adapter uses pure Ed25519 over the **full message**, never a prehash.

## Message and network contract

The candidate's `native_unsigned_bytes` is a serialized message, not a transaction. Signed bytes are `shortvec(1) || signature(64) || message`, and the transaction id is the base58 signature. The builder produces legacy messages; verification/assembly additionally accept v0 when enrolled in the profile. Other version prefixes fail closed.

The profile binds a 32-byte genesis hash checked against evidence. Solana messages contain no native network id: this is an off-chain enrollment/evidence binding, not an extra chain signature domain. The recent blockhash in the signed message must match evidence and remain within its validity height.

## Supported meaning

Exactly one required signer is supported: the wallet public key, which must be the writable fee payer at static account index zero. Every top-level instruction is decoded, and exactly one value-moving instruction is permitted:

| Transfer | Required interpretation |
| --- | --- |
| SOL | System `Transfer` from the wallet to the registered destination |
| Classic SPL | `TransferChecked` for the registered mint/decimals under the original Token program, with wallet authority |
| Optional destination setup | One ATA `Create`/`CreateIdempotent` before the SPL transfer, creating exactly its destination |
| Optional fee settings | At most one compute-unit limit and one compute-unit price instruction |

Account counts and signer/writable permissions are checked. Extra multisig signers, plain SPL `Transfer`, authority/approve/close/mint/burn/freeze changes, Memo and other unknown programs, Token-2022, durable nonce operations, multiple transfers and nonstandard assets are denied.

For SPL, source account evidence must establish initialized state, wallet ownership and the registered mint. A destination is either the derived ATA of the registered owner/mint or a token account with explicit owner evidence. Any supplied destination account evidence must satisfy mint/state/delegate/close-authority constraints. ATA creation checks payer, owner, mint, token/system program, exact account list and the derived PDA; address shape alone is insufficient.

## v0 lookup resolution and parser limits

Every address lookup table must have `alt:<table>` evidence. Deactivating/deactivated tables, out-of-range lookup indices and duplicate resolved accounts are rejected. Lookup accounts cannot become signers, and instruction programs must be static accounts. The complete resolved account list and table bindings enter the decoded native detail.

The serialized transaction must fit 1,232 bytes; the combined static/resolved account list is capped at 64. Compact-u16 encodings are minimal and bounded to three bytes. Header/index/signer counts must be consistent, static keys unique, and messages must decode and re-encode byte-exactly without trailing data.

## Fee and resource claims

```text
maximum native fee = required_signatures * lamports_per_signature
                   + ceil(compute_limit * micro_lamports_per_unit / 1_000_000)
                   + worst-case ATA rent
```

All calculations are checked `u128`. Without an explicit compute limit, the default is 200,000 units per non-compute-budget instruction capped at 1,400,000. An explicit larger limit is rejected. Without a compute price, priority fee is zero. ATA rent is charged even for idempotent creation as a worst case, kept separate from the token amount, and represented in decoded native movement and maximum native fee.

The native resource is `(network_id, fee_payer, recent_blockhash)`. A rebuilt message with a new blockhash is a different resource and may execute alongside the previous candidate, so the [authority](../architecture/authorization-authority.md) counts those claims additively. A bounded template must permit `SolanaRecentBlockhash` and cannot permit EVM fields; beneficiary, asset and amount remain fixed.

## Evidence and validity

Evidence item integers are little-endian and address/signature suffixes are base58. Required families include genesis hash, recent blockhash and last-valid block height, signature fee, optional compute settings, ATA rent when created, source/destination token accounts, lookup tables, transaction observations, and signed bytes for possibly issued candidates. Older blockhashes use `blockhash_last_valid_height:<blockhash>`.

For expiry, `EvidenceBundle.state.height` means **block height**, not slot. Transaction observations separately carry slot/commitment. The supplied simulator makes slot and block height equal, which must not be generalized to a live network implementation.

`observe` compares processed/confirmed/finalized commitment against the profile and returns included/finalized. Missing transaction evidence returns `StaleEvidence`. `prove_invalidation` requires the profile's finalized view, every candidate's blockhash beyond `last_valid_height + finality_depth`, every candidate's signed bytes matching its message, valid native signatures, and no successful family signature in the evidence. Otherwise it returns `Unknown`; timeout alone is insufficient. The [broadcaster](../workflows/broadcast-and-finality.md) polls actual landings before trying invalidation.

```sh
cargo test -p oic-adapter-solana --locked
```

Adapter tests cover SOL/SPL and ATA variants, fees, wrong mint, ALT resolution, unsupported instructions, blockhash retries, altered bytes, templates, signatures and parser bounds. [`tests/differential.rs`](../../crates/adapter-solana/tests/differential.rs) cross-checks SDK wire encodings, signatures, program ids and ATA derivation. Read [crypto providers](crypto-providers.md) for FROST and [chain simulators](../testing/chain-simulators.md) for the executable chain model.
