---
type: workflow
title: Broadcast, finality, and uncertain outcomes
description: Durable signed-byte submission, recovery after lost acknowledgements, cross-source observations, reorg handling, quarantine, and proof-based release of uncertain custody obligations.
tags: [broadcast, finality, uncertainty, reorg, lifecycle]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:39:06.439Z
sources:
  - id: openwiki-source-f2d7e04e05cb94c5f8a03b8c
    resource: repo://services/broadcaster/src/broadcaster.rs
  - id: openwiki-source-7a6e9a2f9a5b7a1f7a74041c
    resource: repo://services/broadcaster/src/client.rs
  - id: openwiki-source-054a7fe530b5b5b17e90144b
    resource: repo://services/broadcaster/tests/evm.rs
  - id: openwiki-source-8a948746392ef0492a242936
    resource: repo://services/broadcaster/tests/solana.rs
generated: { by: "codex", at: "2026-10-20T20:39:06.439Z" }
---

# Broadcast, finality, and uncertain outcomes

`oic-service-broadcaster::Broadcaster<S>` delivers already signed bytes and feeds verified chain observations to the authority. It holds no signing keys. A successful coordinator issuance still has an outstanding reservation; broadcast acknowledgement does not settle it.

## Network and client enrollment

Construct a broadcaster from authority, submission store and clock, then `register_network(profile, adapter, client)`. Registration requires matching client network, adapter identity and at least one evidence source. `ChainClient` abstracts signed-byte submission, transaction/candidate evidence and head/finalized views. The shipped client implementations wrap the deterministic EVM/Solana simulators.

The broadcaster verifies candidate/signed-transaction/family/profile bindings before storing or sending. `register_possibly_issued` records recovered signed bytes without broadcasting and starts with `IssuanceUnknown`. A family already bound to different signed content is a conflict; this implementation does not silently replace its stored transaction.

## Submission boundary

1. `submit` receives a `VerifiedSignedTransaction`, checks family quarantine, and prepares a `SubmissionRecord` retaining exact candidate and signed bytes.
2. Append a `Pending` attempt and durably store the record **before** invoking the chain client.
3. If the returned transaction id matches, store `Acknowledged` and report `Submitted` to the authority when appropriate.
4. On an error or wrong id, store `ErrorReported`. Without earlier acknowledgement/inclusion/resolution, the lifecycle becomes `SubmissionUnknown`.

The result record can represent an unknown submission after a client error; callers must inspect its lifecycle/attempt outcome rather than treating an `Ok(record)` return as chain acceptance. An RPC error cannot prove that bytes were never accepted.

`rebroadcast` resends the **same recorded bytes**. It cannot produce a new signature and refuses resolved or quarantined families. Rebuilding a candidate or changing fees belongs to the authorization pipeline, not this method.

## Restart recovery

`FileSubmissionStore` appends synced JSON snapshots; replay keeps the latest snapshot per family. `recover` changes interrupted `Pending` attempts to `Interrupted`, retains uncertainty, persists the changed records, and returns affected family ids. It does not poll the chain: call `poll` or `resolve_unknown` separately. A crash after sending but before acknowledgement is never reclassified as “not sent.” Corrupt complete log records prevent store opening; an incomplete final line is discarded as unacknowledged.

See [durable state](../operations/durable-state-and-recovery.md) for store formats and independent rollback witnesses.

## Observation, disagreement and reorg

`poll` examines **every** configured source, requesting latest evidence and then a finalized view when the transaction is visible. Shared checks enforce scope, trust/staleness, and current time. Reported heights cannot exceed the client's head; finalized evidence must meet the profile commitment and client finalized bound. The adapter interprets the transaction item.

All source classifications must agree. After shared evidence checks, the classifier maps an adapter `StaleEvidence` result to not visible, including the usual missing-transaction-item case; other adapter error codes propagate. This mapping is by error code, not by checking whether a particular item was absent. Differences between sources produce `ChainObservation::Conflict`, quarantine the family, and stop further observation-driven release. Named sources in a simulator test do not establish real provider independence.

| Agreed view | Result |
| --- | --- |
| Not visible, never previously included | Retain current unresolved obligations |
| Not visible after an inclusion | Report `Reorged` and retain exposure |
| Included at a changed block | Report prior reorg then new inclusion |
| Included below required finality | Keep locks and exposure |
| Finalized success/failure | Authority settles asset/actual-fee effects according to execution result |

The authority decides reservation accounting. A finalized failure charges actual fees but no asset debit. A chain RPC saying “submitted” never performs that settlement.

## Resolving unknown outcomes

`resolve_unknown` first polls the transaction, so an actual landing takes precedence over an expiry guess. If the record is unresolved, unquarantined and not currently included, it requests finalized candidate evidence from every source and invokes `adapter.prove_invalidation` with the retained signed bytes.

Every source must return `Definitive`; an `Unknown` keeps the obligation active. Once all proofs succeed, the broadcaster reports `DefinitivelyInvalidated` to the authority. EVM requires a finalized non-family nonce consumer; Solana requires proven blockhash expiry and no successful family signature in the evidence. Timeouts, approval expiry and submission failure alone cannot authorize a fresh live payment.

This proof loop requires a definitive result from every source; it does not require textual proof reasons/state objects to be byte-identical. Transaction observations use the stricter common classification comparison. Read the [EVM](../integrations/evm-adapter.md) and [Solana](../integrations/solana-adapter.md) contracts before implementing a live `ChainClient`.

```sh
cargo test -p oic-service-broadcaster --locked
```

EVM tests cover submitted→included→finalized settlement, a client reporting failure while the transaction lands (A18), dropped/reincluded transactions (A31), source conflict (A30), crash-before-ack recovery and binding checks. Solana tests cover two-source finality, forks/rebroadcast and definitive expiry resolution. See [simulators](../testing/chain-simulators.md) and [authorization authority](../architecture/authorization-authority.md).
