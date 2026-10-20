---
type: operations
title: Durable state, fencing, and recovery
description: Authority snapshots and witnesses, one-time cryptographic ledgers, signer generation fencing, service replay logs, and conservative restart boundaries.
tags: [durability, recovery, rollback, fencing, one-time-state]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:16:28.312Z
sources:
  - id: openwiki-source-56d48214cbbee952a642f6fe
    resource: repo://crates/authorization-state/src/store.rs
  - id: openwiki-source-f62d5f8e38bb5714deb2733d
    resource: repo://crates/one-time-state-ledger/src/lib.rs
  - id: openwiki-source-018205aa790ed7edc74a7c31
    resource: repo://crates/signer/src/generation.rs
  - id: openwiki-source-44237c1fa8e3e6f1f5830b21
    resource: repo://crates/signer/src/lib.rs
  - id: openwiki-source-f2d7e04e05cb94c5f8a03b8c
    resource: repo://services/broadcaster/src/broadcaster.rs
  - id: openwiki-source-142c6e0968ceb44c3537639d
    resource: repo://services/broadcaster/src/store.rs
  - id: openwiki-source-67606445bbd5c0b16f4b87fc
    resource: repo://services/coordinator/src/store.rs
generated: { by: "codex", at: "2026-10-20T20:16:28.312Z" }
---

# Durable state, fencing, and recovery

The workspace has several durable stores with different contracts. Preserving one file does not preserve all custody safety state. Authority receipts establish possible issuance; one-time records prevent cryptographic reuse; generations fence old instances; operation/submission logs preserve workflow uncertainty; audit checkpoints expose history divergence.

## Persistence map

| State | Implementations | Disk format and important boundary |
| --- | --- | --- |
| Authority | `InMemoryAuthorityStore`, `FileAuthorityStore` | Versioned canonical CBOR snapshot plus commit-sequence `.hwm` |
| One-time state | `InMemoryLedger`, `FileLedger` | Length-prefixed checksummed canonical mutation log plus sequence `.hwm` |
| Signer generation | `InMemoryGenerationStore`, `FileGenerationStore` | Versioned canonical generation file, atomic replacement |
| Coordinator lifecycle | `InMemoryOperationStore`, `FileOperationStore` | Synced JSON-lines transitions with issuance monotonicity checks |
| Broadcaster | `MemorySubmissionStore`, `FileSubmissionStore` | Synced JSON-lines snapshots; last record per family wins |
| Audit | `MemoryAuditLog`, `FileAuditLog` | Signed chained canonical events and independent checkpoints |

These stores serialize callers through their in-process mutexes. They do not form a cross-process transactional database or a replicated consensus service. In particular, `FileLedger` explicitly has no OS-level file lock; generation/operational fencing must prevent two processes using the same log.

## Authority snapshots and witnesses

`AuthorityStore::transact` mutates a private copy and installs it in memory only after successful persistence. The file store canonicalizes and validates the snapshot, writes/syncs a temporary file, renames it, and advances the high-water mark. It refuses snapshots that exceed canonical decoder limits rather than writing state it cannot reopen.

`FileAuthorityStore::open(path, expected_min_commit_sequence)` rejects a snapshot below the maximum of the local high-water mark and supplied minimum. Missing snapshot state is treated as empty, so a retained positive high-water mark detects deletion. Corrupt snapshots or foreign format versions require recovery.

`open_with_witness` verifies an authority-signed checkpoint and requires at least its sequence. At the **same** sequence it also compares the full canonical state hash. For a newer local sequence it establishes a sequence floor, not a cryptographic proof of every intervening state transition. Checkpoint trust/key/scope selection remains the caller's responsibility.

An authority opens by taking the expected fence token and advancing token/epoch. Older `Authority` instances over that store fail their fence check. This is an in-store writer-generation contract, not an operating-system lock or a guarantee about independently opened file-store instances.

## One-time cryptographic state

A ledger record binds key id/epoch, signer generation, session and an allocation counter into its identity. Consumption succeeds once for one message hash; repeated consumption, a tombstoned record, or an older-generation allocation is refused. `tombstone_generations_before` both retires unconsumed older records and advances the per-key generation floor.

`FileLedger` replays every contiguous mutation and validates checksums and derived record ids. It syncs mutations before acknowledging success. An incomplete final frame is unacknowledged and truncated; other corrupt frames require recovery. Opening below a supplied minimum or `.hwm` also requires recovery.

The ledger holds **metadata**, not secret nonce/preprocessing material. Providers keep that material themselves and must consume the record before producing a share. The signer checks the consumed record again at its output boundary. See [providers](../integrations/crypto-providers.md) and [signer](../architecture/signer-boundary.md).

## Signer restart and cloned state

`Signer::open` advances durable generation before allocating normal key state. A ledger fence records the last open; reopening with a newer generation store but older ledger is refused. `load_key` tombstones older key generations, and peer-generation checks reject messages below known floors. Generation files refuse backwards writes and unreadable/foreign formats.

Provider signing sessions and FROST nonces are in memory. A crash loses the session; callers must use a new session and fresh one-time state instead of resuming uncertain nonce material. A lost session after authority release does not prove that no signature exists.

## Service replay and uncertainty

The coordinator log rejects moving a possibly issued candidate back into pre-issuance state. Complete JSON lines are replayed and validated; incomplete final lines are truncated. This preserves recorded `IssuanceCommitted`/`IssuanceUnknown` history across reopen, without implementing an automatic recovery controller for every crash point.

The broadcaster writes `Pending` **before** handing bytes to the chain. A reopened pending attempt becomes `Interrupted` and, when unresolved, `SubmissionUnknown`; it never becomes proof of “not sent.” Recovery polls the chain, and invalidation proofs use retained exact signed bytes. [Broadcast and finality](../workflows/broadcast-and-finality.md) covers those transitions.

## Recovery limits

High-water marks and generation files are useful local witnesses, but rolling back all local files together cannot establish freshness. Preserve independent authority/audit checkpoints or externally supplied sequence floors. Reopen failures should be reconciled against those witnesses, not bypassed by deleting sidecars or resetting generations.

A failed persistence call may have completed some disk I/O before returning an error. The private-copy transaction contract prevents publishing a partial in-memory mutation; it is not a distributed atomic commit across every file and service. Reopen, replay and independent evidence are the relevant recovery mechanisms.

```sh
cargo test -p oic-authorization-state -p oic-one-time-state-ledger -p oic-signer --locked
cargo test -p oic-service-coordinator -p oic-service-broadcaster -p oic-audit --locked
```

Focused tests cover failed persist/consume, snapshot deletion/rollback, witness divergence, torn tails, restored ledgers, generation monotonicity, and interrupted submission. The [audit guide](audit-log.md) distinguishes signed history from authorization state.
