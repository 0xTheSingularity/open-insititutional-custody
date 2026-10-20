---
type: operations
title: Signed audit log and checkpoints
description: Signed event chains, replayable file storage, witness checkpoint comparison, authority sink integration, and the limits of audit redaction and failure coupling.
tags: [audit, checkpoints, persistence, witnesses, integrity]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:16:28.312Z
sources:
  - id: openwiki-source-09a0bdd0a43480a51cba765d
    resource: repo://crates/audit/src/chain.rs
  - id: openwiki-source-29afb995103ab0c5cdbf6ebb
    resource: repo://crates/audit/src/checkpoint.rs
  - id: openwiki-source-a95667a6f632a73c6fb8e2bf
    resource: repo://crates/audit/src/file.rs
  - id: openwiki-source-c2e9a23e1d2a6d361b374624
    resource: repo://crates/audit/src/sink.rs
  - id: openwiki-source-94c645cf438f32d119ca39ca
    resource: repo://crates/authorization-state/src/authority.rs
generated: { by: "codex", at: "2026-10-20T20:16:28.312Z" }
---

# Signed audit log and checkpoints

`oic-audit` supplies `AuditLog`, `MemoryAuditLog`, `FileAuditLog`, signed checkpoints, and an adapter from authority events. It records verifiable history of actions and object commitments; it does not serve as the authorization-state database or a financial journal.

## Event integrity

Each event body includes sequence, previous event hash, timestamp, actor/action, object commitments, policy epoch and detail. Sequences begin at one and advance exactly by one; the first previous hash is zero.

```text
event_hash = SHA256("OIC/AUDIT/v1" || canonical_bytes(body))
```

The service key signs that hash with explicit-scheme Ed25519. Event ids are derived separately from a domain-separated commitment to all body fields except the id itself, avoiding a circular hash. `verify_event` checks content validity, id and signature. `verify_chain` additionally enforces contiguous order and hash linkage, optionally continuing from an already verified head.

`events_since(sequence, limit)` returns entries strictly after the supplied sequence. A caller can export/replay a prefix, retain its verified head and continue incrementally.

## File durability and replay

`FileAuditLog` stores frames of four-byte big-endian length plus canonical CBOR event, bounded by `MAX_FRAME_BYTES`. It syncs event data before acknowledgement and advances `<path>.hwm` using atomic replacement. Opening replays and verifies event ids, signatures, service-key identity, order and linkage.

| Reopen condition | Behavior |
| --- | --- |
| Incomplete final frame | Discard the unacknowledged tail; expose discarded byte count |
| Complete malformed or invalid event | `RecoveryRequired` |
| Wrong service key or broken hash chain | `RecoveryRequired` |
| Verified head below high-water mark or caller's expected minimum | `RecoveryRequired` |

Incomplete writes and invalid complete history are treated differently. Supplying an independent minimum sequence matters when a backup could include both the log and its local high-water mark. See [durable state and recovery](durable-state-and-recovery.md).

## Independent witnesses

An `AuditCheckpoint` signs service key id, sequence, head event hash and time under `OIC/AUDIT_CHECKPOINT/v1`. Hash chaining alone cannot prevent an operator who controls the signing key from presenting different signed histories.

`compare_checkpoints` verifies both checkpoints and returns consistency, extension or divergence. Different-sequence comparisons require exactly the bridging events; each is verified before a verdict. Missing or malformed bridging history is an error, not proof of equivocation. `first_divergence` verifies two complete histories and identifies their first differing event.

Witness storage and checkpoint exchange are caller responsibilities. A local checkpoint never becomes independent merely because it is signed.

## Authority and signer integration

`AuthorityAuditSink` maps every authority event to an `authority.*` action, a commitment to the complete authority event, and commitments to referenced objects. Detail includes the authority commit sequence; the sink tracks the last known policy epoch and explicitly marks unknown epochs.

The authority's `AuditSink::record` has no result channel and runs after the state mutation commits. An audit append failure therefore **does not roll back or block that committed authorization operation**. The adapter exposes `last_error`, `failure_count` and `recorded_count`; callers must monitor them and enforce any operational halt policy outside this hook. The sink's own lock serializes mapping/appends, while authority commit sequence remains the ordering reference for the underlying state.

The signer separately exposes `SignerEvent` and `with_event_sink`; applications can wire that hook to audit. This crate ships an authority adapter, not a complete signer/network audit collection service.

## Input and disclosure bounds

Append validation bounds actor/action and commitment labels to 256 bytes, detail to 4,096 bytes, and object commitments to 64 entries. Detail containing case-insensitive `begin private key`, `seed:` or `share:` markers is rejected. This is a narrow tripwire rather than a comprehensive secret scanner. Never supply secrets or protocol nonce/share material; prefer commitments to the relevant objects.

```sh
cargo test -p oic-audit --locked
```

[`tests/audit.rs`](../../crates/audit/tests/audit.rs) covers signed chaining/tampering, validation, replay, partial tail recovery, foreign keys, rollback, witness divergence, complete authority event mapping, sink failures and file reopen. For the events' stateful meaning, read [authorization authority](../architecture/authorization-authority.md); for signer output gating, read [signer boundary](../architecture/signer-boundary.md).
