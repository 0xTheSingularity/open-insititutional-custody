# Handoff — Open Institutional Custody build

Last updated: 2026-10-20. Companion to `spec/rfc-0001-open-institutional-custody.md`
and `spec/rfc-0002-product-completion.md`. Everything below describes the repository
as it is, not as planned.

## How to work in this repo

- Rust workspace; `source ~/.cargo/env` first. Full suite: `cargo test --workspace`
  (~4 min on 4 cores; last run **363 passed, 0 failed**). Per crate: `cargo test -p <crate>`.
- Count passes: `cargo test --workspace 2>&1 | grep -E "^test result" | awk '{s+=$4; f+=$6} END {print "passed="s" failed="f}'`
- rustfmt is not installed in the orb; clippy is. New crates are clippy-clean apart
  from a few style lints (complex type, OR-pattern range) in test code.
- Rules in force from the owner: **no stubs** (`todo!`, `unimplemented!`, placeholder
  crates, "future work" comments standing in for behavior). Workspace `members`
  lists only real, tested crates. Take the spec as absolute. Push only on an
  explicit Ship instruction.
- Golden vectors: `OIC_REGENERATE_VECTORS=1 cargo test -p oic-golden-vectors --test generate`
  rewrites `tests/golden-vectors/vectors/*.json`; the conformance test fails if
  the files differ from what the generator produces.

## Crate map (all green)

| Path | Package | What it is |
|---|---|---|
| crates/domain-types | oic-domain-types | Every RFC 0001 §3 / RFC 0002 §4–§6 object, ids, errors, `domains` hash tags, `ApprovalPackage` |
| crates/canonical-encoding | oic-canonical-encoding | Deterministic CBOR, `domain_hash`, `sha256` |
| crates/crypto-provider | oic-crypto-provider | Backend trait, `ProtocolStep`, `PeerMessage`, `BackendDescriptor` |
| crates/crypto-provider-dev | oic-crypto-provider-dev | `DevSingleKeyProvider` (secp256k1, development only; kernel forbids on mainnet) |
| crates/crypto-provider-frost-ed25519 | oic-crypto-provider-frost-ed25519 | FROST ed25519 2-of-3 (`run_dkg`, `build_signing_package`) |
| crates/adapter-api / adapter-evm / adapter-solana | oic-adapter-* | `ChainAdapter` contract; EVM EIP-1559 + ERC-20; Solana legacy/v0, SPL |
| crates/policy-kernel | oic-policy-kernel | `evaluate`, `match_rule`, hashes (`policy_hash`, `intent_hash`, `destination_hash`, `preview_hash`) |
| crates/authorization-state | oic-authorization-state | `Authority` (reserve/release/freeze/observe), receipts, in-memory + file stores |
| models/authorization-state-machine | oic-model-authorization-state | stateright model of reserve/release/freeze |
| crates/one-time-state-ledger | oic-one-time-state-ledger | One-time MPC state ledger |
| crates/signer | oic-signer | Signer: 9-step envelope verification + 4b destination quorum, sessions, release gating, generation fencing |
| crates/approval-verifier | oic-approval-verifier | Grants, `ApprovalDisplay` card, `IndependentVerifier` |
| crates/audit | oic-audit | Signed hash-chained audit log + checkpoints |
| crates/chain-simulator | oic-chain-simulator | Deterministic EVM and Solana dev chains (reorg/fork, lies, faucets) |
| services/builder | oic-service-builder | `EvidenceSource` (simulator impls), `build`, `evaluate`, `required_approvals`, `envelope_body`, `signing_materials` |
| services/coordinator | oic-service-coordinator | `SignerEndpoint` (+`InProcessSigner`), FROST/dev `BackendDriver`s, `Coordinator::execute` (reserve → sessions → release → aggregate → verified signed tx), `OperationStore` memory/file |
| services/broadcaster | oic-service-broadcaster | `ChainClient` (simulator impls, multi-source cross-check), `Broadcaster::{submit, rebroadcast, recover, poll, resolve_unknown}`, durable `SubmissionStore` |
| apps/independent-approval-client | oic-approval-client (bin `oic-approve`) | `init-trust`, `keygen`, `show`, `approve`, `verify-grant`, `inspect-envelope`; encrypted 0600 key files |
| tests/golden-vectors | oic-golden-vectors | `vectors/*.json` for every `domains::*` tag plus native EVM/Solana payloads; conformance + differential (alloy, solana SDK) tests |

Empty, untracked directories (not members, not stubs): `services/api`,
`services/reconciler`, `cli/oic`, `sdk/typescript`, `deploy/development-only`,
`tests/{adversarial,differential,crash-and-rollback}`,
`crates/adapter-{bitcoin,cosmos,sui,aptos,xrpl}`. Root `Cargo.toml` already declares
workspace dependency paths for `oic-service-api` and `oic-service-reconciler`.

## Settled design decisions

- Destinations are admin-quorum-signed objects (`CounterpartyDestination.administrative_signatures`
  over `destination_hash`); the envelope binds `destination_hash`; signer step 4b and the
  independent verifier enforce it (A02 destination-substitution closed).
- Threshold backends: FROST ed25519 2-of-3 for Solana; EVM uses the dev single-key backend.
  `cggmp24` (LFDT-Lockness) is the pinned production ECDSA candidate and is **not integrated**
  (RFC 0001 G0 open item; surface to the owner).
- Canonical encoding: deterministic CBOR; serde enums externally tagged; `Bytes`/`Hash32` hex in
  JSON, raw in CBOR; `Amount(u128)` decimal string.
- Coordinator failure semantics: any error before `authority.release` → `abort_before_issuance`
  + session aborts; any error after → `IssuanceUnknown`, exposure retained, `IssuanceUncertain`
  error. Broadcaster records a pending attempt before calling the chain; crash before ack reopens
  as `SubmissionUnknown`, resolved only by `prove_invalidation` evidence.
- G5 adapters (Bitcoin/Cosmos/Sui/Aptos/XRPL) and the Python SDK are deferred: building them
  now would be stubs.

## Acceptance coverage so far

RFC 0001: A01, A02 (three variants), A03, A04, A06, A08, A11, A12, A13, A14, A17, A18, A30,
A31, A34 exercised in signer, coordinator, broadcaster, and approval-client tests.
RFC 0002: C15 (approval client), C14 partly (destination/policy version binding), conformance
vectors for §3 item 2.

## What remains (in order)

1. `services/reconciler` (`oic-service-reconciler`, RFC 0002 §4–§6): `BlockSource` over the
   simulators (EVM value + ERC-20 Transfer logs + fees; Solana lamport/token deltas), `Indexer`
   with durable `IndexCursor`, backfill, reorg correction, dedup on `(network_id, tx_id,
   effect_index)`, finality promotion, quarantine + `DepositCase`; hash-chained `Journal`
   (`domains::JOURNAL`), `Holdings` derived minus authority reservations; signed
   `ReconciliationCheckpoint` with cases (C19, never a balancing entry); `WorkflowController`
   (gas funding + sweeps with `TriggerId = domain_hash(WORKFLOW_TRIGGER, trigger)` dedup,
   pause reasons, `Exhausted{case_id}`); gap-free `LifecycleEvent` log. A partial attempt was
   discarded before this handoff; start from the domain types in
   `crates/domain-types/src/operations.rs`. Tests: C03–C11, C19, §4 "Done" loop.
2. `services/api` (axum 0.8, RFC 0001 §13.1 routes, idempotency scoped to institution/route/body,
   signed sequenced webhooks with `events_since` replay (C18), destination/policy proposals with
   admin quorum, OpenAPI), using builder/coordinator/broadcaster/reconciler.
3. `spec/protocol-v1.md` (RFC 0002 §3): byte-level description of what the code does, referencing
   `tests/golden-vectors/vectors/*`; `tests/golden-vectors/schemas/` JSON Schemas (a `jsonschema`
   dev dependency is already pinned at `=0.58.6` in the root manifest).
4. `cli/oic`, `sdk/rust`, `sdk/typescript` (generated from the OpenAPI), `deploy/development-only`
   (API + authority + three signers + both simulators), `tests/{adversarial,crash-and-rollback,
   differential}` harnesses for the remaining A-cases, then run RFC 0001 gates G0–G2 and
   RFC 0002 Gate B end to end: deposit → fund fees → authorized send → reconcile, plus the
   "failed theft" demonstration (recipient change after approval, coordinator invoked directly,
   approval replay, budget race).
