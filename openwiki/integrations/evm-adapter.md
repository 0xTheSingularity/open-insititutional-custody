---
type: integration
title: EVM transaction adapter
description: Deterministic EVM native/ERC-20 transfer verification, strict transaction parsing, native signature derivation, evidence requirements, nonce locks, and finality-based invalidation.
tags: [evm, adapter, erc20, eip1559, nonce, evidence]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:16:28.312Z
sources:
  - id: openwiki-source-3e9ed89e7108b498912ca0a7
    resource: repo://crates/adapter-evm/Cargo.toml
  - id: openwiki-source-d2d0d8e02d4fb1f75b4b9824
    resource: repo://crates/adapter-evm/README.md
  - id: openwiki-source-22d154eedc408ab4a2b5aa40
    resource: repo://crates/adapter-evm/src/calldata.rs
  - id: openwiki-source-d825e5660cb1d63b0a3d217d
    resource: repo://crates/adapter-evm/src/lib.rs
  - id: openwiki-source-50ff52bdba37c5a5a457b104
    resource: repo://crates/adapter-evm/src/rlp.rs
  - id: openwiki-source-9c19b7e734e30a80814ba375
    resource: repo://crates/adapter-evm/src/tx.rs
  - id: openwiki-source-402deb1d87fb0fb53dc18850
    resource: repo://crates/adapter-evm/tests/differential.rs
generated: { by: "codex", at: "2026-10-20T20:16:28.312Z" }
---

# EVM transaction adapter

`oic-adapter-evm::EvmAdapter` implements the deterministic `ChainAdapter` contract without RPC or clock access. The shared API standardizes authorization and lifecycle; the adapter owns native transaction meaning. All chain state arrives through `EvidenceBundle`. Alloy appears only in differential tests.

## Enrolled capabilities

| Surface | Supported behavior |
| --- | --- |
| Build | EIP-1559 type-2 native and registered standard ERC-20 direct transfers |
| Decode/verify/assemble | Type 2 and replay-protected EIP-155 legacy, each explicitly enabled by profile |
| Scheme | `EcdsaSecp256k1Keccak256Prehashed` |
| Network binding | Eight-byte big-endian chain id checked against evidence and native transaction |
| Resource | `(network_id, sender, nonce)`; nonce cannot precede evidence account nonce |
| Native expiry | None; envelope approval deadlines do not expire an EOA transaction on chain |

Unknown profile versions fail closed. Legacy transaction building is unsupported even when legacy verification is enabled. Verifier identity is the adapter version plus `SHA256(VERIFIER_BUILD_ID)` and must match enrolled signer trust.

## Build and independent verification

`build_candidate` derives sender and transfer fields from wallet/key/intent/asset/destination plus nonce and fee evidence. The builder chooses `max_fee_per_gas = 2 * base_fee + priority_fee` with checked arithmetic.

`verify_candidate` parses exact unsigned bytes, re-derives the signing payload, compares the candidate's declared payload array, and checks network/asset/destination/intent or template bindings. Token identity is the registered contract on the network, never symbol and decimals. Standard ERC-20 calldata must be exactly `transfer(address,uint256)`, 68 bytes, with a clean recipient word, a supported-width amount, and zero native value. ERC-20 verification also requires a nonempty code-hash evidence item for the registered contract; this is not a proof that arbitrary token code behaves like a standard asset.

The maximum native fee is `gas_limit * max_fee_per_gas` or legacy `gas_limit * gas_price`, using checked `u128`. There is no L2 data-fee component. Verification compares the result with authorized fee ceilings and produces separate asset outflow, native fee and nonce claims.

Bounded templates permit only enrolled fillable fields. Non-fillable fee/gas/nonce fields remain constrained by evidence; amount and beneficiary remain fixed. See [independent approval](../workflows/independent-approval.md).

## Parsing and native signatures

The handwritten RLP codec caps input at 128 KiB and list nesting at eight levels. It rejects nonminimal lengths/integers, leading zeros, truncation and trailing data. Nonce, gas and chain id fit `u64`; amount and fee fields fit `u128` even though a chain encoding could represent larger values.

Type-2 signing uses Keccak-256 of `0x02 || RLP(unsigned fields)`. Legacy signing includes EIP-155 chain-id protection. Signed transaction ids hash the signed encoding. Signature assembly and verification require a 65-byte `r || s || recovery_id` signature, valid scalars, low-s and recovery parity 0/1, and recover the enrolled sender.

Rejected capability families include contract creation, nonempty access lists, EIP-2930/4844/7702 and unknown transaction types, unprotected legacy signatures, arbitrary contract calls/approvals/permits/batches/account execution, nonstandard assets, and arbitrary message signing. Changing to an unsupported selector is not an approved direct-transfer extension.

## Evidence contract

| Item | Meaning |
| --- | --- |
| `chain_id` | Eight-byte chain identity |
| `nonce:<sender>` | Eight-byte account nonce |
| `base_fee`, `priority_fee` | Sixteen-byte big-endian fee values |
| `gas_limit` | Eight-byte gas limit |
| `code:<contract>` | Keccak-256 code hash at the evidence block |
| `tx:<hash>` | Canonically encoded `TxObservation` |
| `signed_tx:<candidate_id>:<revision>` | Possibly issued signed bytes for invalidation proof |

Key suffix hex is lowercase without `0x`. Shared evidence checks validate profile/network/trust/staleness declarations. Time-aware callers supply current time and policy freshness checks; deterministic adapter methods do not fetch a fresh chain view themselves.

## Settlement and invalidation

`observe` maps evidence to submitted, included, or finalized according to confirmation depth. Missing transaction evidence returns `StaleEvidence`. The [broadcaster](../workflows/broadcast-and-finality.md) distinguishes missing visibility from finality and cross-checks configured sources.

`prove_invalidation` requires the profile's finalized view, signed bytes for every candidate, a consistent recovered sender, an account nonce beyond every candidate nonce, explicit evidence that every family candidate is absent, and a finalized **non-family** transaction that consumed the nonce. A submitted replacement or a family member landing is not proof of family invalidation. Missing or insufficient evidence returns `Unknown`.

Same-family same-nonce replacement exposure is accounted by maximum in the [authority](../architecture/authorization-authority.md). No elapsed approval deadline alone releases that obligation.

```sh
cargo test -p oic-adapter-evm --locked
```

[`tests/adapter.rs`](../../crates/adapter-evm/tests/adapter.rs) checks changed recipients, wrong token contracts, denied selectors/types, template fields, malformed signatures, lifecycle and bounded no-panic parsing. [`tests/differential.rs`](../../crates/adapter-evm/tests/differential.rs) compares published vectors, signing hashes, signed bytes and recovered signers with Alloy. Compare [Solana semantics](solana-adapter.md) and [simulators](../testing/chain-simulators.md) before generalizing nonce or expiry behavior.
