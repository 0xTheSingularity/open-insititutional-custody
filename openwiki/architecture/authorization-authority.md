---
type: architecture
title: Authorization authority and exposure
description: Atomic reservations, native resource locks, exposure accounting, ordered freezes, and conservative resolution of possibly issued custody transactions.
tags: [authorization, reservations, exposure, lifecycle, fencing]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:16:28.312Z
sources:
  - id: openwiki-source-94c645cf438f32d119ca39ca
    resource: repo://crates/authorization-state/src/authority.rs
  - id: openwiki-source-d98a28704e5a9fc7a29c3879
    resource: repo://crates/authorization-state/src/state.rs
  - id: openwiki-source-56d48214cbbee952a642f6fe
    resource: repo://crates/authorization-state/src/store.rs
  - id: openwiki-source-43c834152520e5105b8be702
    resource: repo://crates/authorization-state/tests/authority.rs
generated: { by: "codex", at: "2026-10-20T20:16:28.312Z" }
---

# Authorization authority and exposure

`oic-authorization-state` owns the globally ordered state that individual signers cannot infer: active policy, native resource locks, outstanding exposure, freezes, and issuance records. `Authority<S>` runs mutations through `AuthorityStore::transact`; its clock and signing key are injected. It is a library API, with memory and file store implementations.

## Ownership and caller responsibilities

An authority opens against an expected fence token, increments the writer generation and authority epoch, and rejects calls from older instances. Store transactions operate on a private state copy and publish it only after both the closure and persistence succeed. See [durable state and recovery](../operations/durable-state-and-recovery.md).

The authority enforces stateful authorization. `reserve` accepts a `Decision::Allow`, grant objects, and verified resource claims supplied by its caller; it does not independently decode native transaction bytes or authenticate every approval signature. It checks the active rule, grant bindings and distinct approver count, per-operation maxima, and global exposure. Native decoding and cryptographic approval checks belong to the [builder and signers](../workflows/build-and-coordinate.md). Likewise, `record_observation` consumes already established chain observations; the [broadcaster](../workflows/broadcast-and-finality.md) obtains and cross-checks evidence.

## Register, reserve, release

1. `register_intent` recomputes the intent hash, checks institution/environment and idempotency scope, and creates a deterministic operation family. Repeating the same idempotency key and body returns the existing result; a changed body is a `Conflict`.
2. `set_policy` verifies the administrative quorum and requires a strictly newer policy epoch. A reservation must name the active epoch and hash.
3. `reserve` checks freeze state, policy, family ownership, approvals, deadline, duplicate resources, and the selected rule's amount/fee limits. Caller-supplied rolling limits must exactly equal limits derived from that rule.
4. Within the same transaction, it locks native resources in sorted order, inserts the proposed reservation, and computes the resulting global exposure. A conflict, overflow, or limit breach aborts the whole mutation. A successful call returns the reservation and a signed `Reserved` receipt bound to the envelope body and signer session.
5. `release` checks reservation version, envelope/session binding, freeze state, current policy epoch, issuance deadline, and agreement with the authority clock. It also rejects a second possibly live payment when a sibling is not provably mutually exclusive.
6. Before returning a signed `Release` receipt, it persists an `IssuanceRecord`, changes the reservation to `Released`, and marks the candidate possibly issued. This commit is the boundary after which an output may exist.

The same candidate revision cannot be silently reused for a different envelope or session. A matching reservation replay is idempotent while still `Reserved`. A matching release replay returns the existing issuance and a fresh receipt; that replay branch precedes new-issuance freeze/deadline checks because the issuance has already been committed.

## Exposure and replacement families

For a vault and asset budget:

```text
exposure(window, now) = settled debits still in the window + outstanding potential debits
```

Outstanding claims do not age out. Both `Reserved` and `Released` reservations remain active. Settled debits are retained while `settled_at + window_seconds > now`; future-dated entries are conservatively included. Checked integer arithmetic turns overflow into failure.

The authority derives replacement treatment from native resources:

| Candidate relationship | Outstanding charge |
| --- | --- |
| Same family with the same sole EVM nonce claim | Maximum claim within that exclusive group |
| Different families | Sum; the same native resource cannot be locked by both |
| Solana messages rebuilt with different recent blockhashes | Additive claims |

A new Solana blockhash does not prove that the old transaction is unusable. Before releasing a non-exclusive sibling, the old possibly issued candidate must be resolved. EVM nonce exclusivity permits replacement accounting by maximum without inventing an extra payment allowance.

## Freeze and issuance ordering

A designated responder can sign a vault or global freeze proposal. Unfreeze requires the administrative quorum over a proposal naming the particular freeze commit sequence, preventing an older approval from lifting a later freeze. Every mutation has a commit sequence; a freeze racing a first release has one ordered outcome. `releases_before(sequence)` identifies issuance already committed before the freeze.

Freeze blocks new issuance; it cannot revoke an output already released. Approval expiry has the same boundary: `approval_expired`, `expire_approvals`, and `abort_before_issuance` can release an unissued reservation, while a possibly issued reservation requires chain resolution.

## Chain resolution

| Observation | Authority effect |
| --- | --- |
| Submitted or included | Update lifecycle; retain exposure and locks |
| Reorg before finality | Mark `Reorged`; retain obligations |
| Finalized success | Record asset debit and actual fee, settle the reservation, release unused locks |
| Finalized failure | Record actual fee only; release the asset obligation |
| Definitive invalidation | Release that candidate's obligation; keep other active family claims |
| Conflicting sources | Quarantine the family |

Finalization of an exclusive EVM nonce candidate also invalidates its active exclusive siblings. A reorg of an already resolved candidate returns `RecoveryRequired`: the implementation does not automatically reverse settlement beyond the profile's assumed finality. Source disagreement is handled conservatively by the broadcaster, which stops feeding a quarantined family.

## Source and test routes

Read [`authority.rs`](../../crates/authorization-state/src/authority.rs) for transitions and [`state.rs`](../../crates/authorization-state/src/state.rs) for accounting. Focused tests in [`tests/authority.rs`](../../crates/authorization-state/tests/authority.rs) cover concurrent budget races (`a08`), split nonce views (`a09`), failed persistence (`a10`), stale policy (`a14`), freeze races (`a16`), expiry after issuance (`a17`), window reset (`a36`), EVM maximum versus Solana additive replacements, and fee-only failure settlement.

```sh
cargo test -p oic-authorization-state --locked
```

For stateless decision ordering, read [policy evaluation](../concepts/policy-evaluation.md). For how native evidence reaches these transitions, read [broadcast and finality](../workflows/broadcast-and-finality.md).
