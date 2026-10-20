---
type: architecture
title: Signer verification and share release
description: Independent envelope verification, enrolled trust roots, native payload re-derivation, and durable release gating around the key-share boundary.
tags: [signer, authorization, threshold-signatures, trust, replay-protection]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:16:28.312Z
sources:
  - id: openwiki-source-44237c1fa8e3e6f1f5830b21
    resource: repo://crates/signer/src/lib.rs
  - id: openwiki-source-dafac7c46dcd9494f03343cb
    resource: repo://crates/signer/src/verify.rs
  - id: openwiki-source-efdfe75c1cb0326a95743862
    resource: repo://crates/signer/tests/evm.rs
  - id: openwiki-source-20cb494a0c862dd49c886c83
    resource: repo://crates/signer/tests/generation.rs
generated: { by: "codex", at: "2026-10-20T20:16:28.312Z" }
---

# Signer verification and share release

`oic-signer` is the key-share boundary. A coordinator supplies an `AuthorizationEnvelope` and `SigningMaterials`, but the signer reconstructs their meaning before allowing its crypto provider to contribute an output. `Signer::open` takes an identity, out-of-band trust roots, pinned adapters, a provider, a one-time ledger, and a generation store.

## Enrolled trust

`TrustRoots` contains the authority key id and public key, administrative quorum and keys, approver roster, accepted verifier build hashes per adapter, enrolled chain profiles, and clock-skew allowance. These are configured independently of the coordinator. `load_key` checks the descriptor against the provider and identity before loading a sealed share; key loading also tombstones older-generation state for that key.

## Envelope verification order

`verify_envelope` delegates to [`verify.rs`](../../crates/signer/src/verify.rs) and emits a verification or rejection event. Checks fail closed with domain error codes:

1. Scope: institution/environment, loaded key and epoch, public key hash, wallet/vault/intent/candidate references, and a distinct enrolled participant set containing this signer and meeting threshold.
2. Chain profile: an enrolled profile and matching canonical hash, evidence scope/freshness, and evidence bundle hash.
3. Adapter: adapter id/version, verifier build hash accepted by trust roots, and equality of candidate and envelope native bytes.
4. Policy: administrative signatures, policy identity/epoch/hash, allowlist version, and intent commitment.
5. Destination, implemented as step **4b**: administrative quorum over the destination record and equality with the envelope's `destination_hash`. Changing an address under an existing destination id is therefore insufficient, including for automated rules.
6. Grants: signatures against the enrolled credential roster, declared roles, time window, and intent/vault/policy/scope bindings.
7. Native operation: the signer's adapter decodes the bytes against the intent or bounded template, re-derives payloads and semantic commitments, and compares resource claims, outflow/fee maxima, and exact-candidate previews.
8. Policy kernel: require `Allow` after local policy evaluation.
9. Reserved receipt: verify its signature, authority key, deterministic reservation id, envelope/session/candidate/version/policy bindings, validity window, and issuance deadline.
10. Payload selection: require exactly one payload for this key and provider scheme. Multiple payloads are currently unsupported.

This list expands the crate's documented nine stages by showing destination step 4b separately. A freshly computed envelope hash alone does not authorize altered bytes: the authority receipt must cover that exact body.

## Local versus global limits

The signer can validate a single operation but cannot establish a global spending counter. Its `local_exposure_view` supplies zero prior settled/outstanding exposure for every declared rolling window, so one operation must fit each window. The [authority](authorization-authority.md) performs cumulative accounting and binds its reservation decision into a signed receipt. Passing an empty exposure view would deny rules that require a missing window.

## Session lifecycle and output gate

```text
verify envelope → open provider session → exchange non-share rounds
                                     → buffer share rounds
authority Release receipt → validate receipt → process buffered rounds
                          → require durable consumption → emit share/signature
```

`open_session` rejects a session id already present in that signer instance. A provider declaring one-time state must allocate exactly one unconsumed record bound to the session, key epoch, and current signer generation. Failed starts burn allocated records when the ledger permits it.

`receive` checks session/key scope, sender membership, recipient, and sender generation. Rounds below the provider's `share_producing_round` may progress immediately. Later messages are buffered up to `MAX_BUFFERED_MESSAGES` until a valid `Release` receipt is presented.

`release` verifies the same envelope/session/reservation binding and checks consistency with the reserved receipt before feeding the buffer. Any `Share` or `Complete` output is withheld unless the session is released and, for a stateful backend, the ledger reports its record consumed for `SHA256(message_or_digest)`. A backend producing early or unconsumed output causes an abort. After one output, further calls fail the session's live check.

Aborting clears buffered messages and attempts to consume the one-time record against an abort sentinel. Burning is best effort when the ledger already consumed/tombstoned the record or is unavailable; an aborted session never becomes live again. A share-round backend error also aborts conservatively.

## Restart and peer fencing

Opening a signer advances and persists its generation and places a fence in the ledger. If a prior generation exists but its ledger fence is missing, open fails with `RecoveryRequired`. Key loading retires older key generations, and peer generation knowledge moves monotonically. This detects an older ledger paired with newer generation state; rolling every local witness back together still requires an independent freshness witness. See [recovery](../operations/durable-state-and-recovery.md).

`SignerEndpoint` and `InProcessSigner` in the coordinator are integration seams; they do not implement the proposed authenticated institution network from RFC 0003. [Implementation boundaries](../concepts/implementation-boundaries.md) explains that distinction.

## Focused verification

```sh
cargo test -p oic-signer --locked
```

[`tests/evm.rs`](../../crates/signer/tests/evm.rs) covers changed recipients/bytes, substituted destination records, replay across scopes, failed ledger consumption, early outputs, receipt expiry, unsupported builds, and local rolling limits. [`tests/solana.rs`](../../crates/signer/tests/solana.rs) exercises a genuine FROST two-of-three signature, malicious shares, stale clones, and bounded templates. [`tests/generation.rs`](../../crates/signer/tests/generation.rs) checks monotonic generations, restored ledgers, and key loading. Continue with [crypto providers](../integrations/crypto-providers.md) or [build and coordination](../workflows/build-and-coordinate.md).
