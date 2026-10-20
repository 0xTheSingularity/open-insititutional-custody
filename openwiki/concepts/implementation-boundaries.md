---
type: implementation-status
title: Implementation boundaries and RFC roadmap
description: Distinguishes executable custody components and tested domain schemas from proposed accounting, deployment, Commonware networking, and browser light-client requirements.
tags: [implementation-status, roadmap, rfc, product-scope, commonware]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:16:28.312Z
sources:
  - id: openwiki-source-d8c6df206fe2a2bd0435a38f
    resource: repo://apps/independent-approval-client/src/main.rs
  - id: openwiki-source-651d1fb6c9e49916a916ab51
    resource: repo://Cargo.toml
  - id: openwiki-source-691bc010a4ada9c113226035
    resource: repo://crates/crypto-provider-frost-ed25519/src/lib.rs
  - id: openwiki-source-ee93f77464e55dd46adfa911
    resource: repo://crates/domain-types/src/operations.rs
  - id: openwiki-source-1e03fc7d5b4fc2a225d5b4c3
    resource: repo://handoff.md
  - id: openwiki-source-109e19ea3dc6c23aa12978cf
    resource: repo://services/coordinator/src/endpoint.rs
  - id: openwiki-source-b333bb79b39c514ae443fe07
    resource: repo://spec/rfc-0002-product-completion.md
  - id: openwiki-source-2005ba25a7293ca218613f2d
    resource: repo://spec/rfc-0003-institution-operated-signer-network.md
generated: { by: "codex", at: "2026-10-20T20:16:28.312Z" }
---

# Implementation boundaries and RFC roadmap

The authoritative implementation map is the root [`Cargo.toml`](../../Cargo.toml), tracked source, and executable tests. The RFCs describe requirements and design options; a normative sentence or reserved dependency name does not prove that a service exists. This wiki documents the source after the October 20 update to `0910530`.

## What can execute today

| Area | Implemented surface | Relevant boundary |
| --- | --- | --- |
| Authorization | Deterministic policy kernel; atomic reserve/release; signed policy/destination/grant verification; freezes, exposure, resource locks | Authority methods are library calls with explicit caller contracts |
| Signing | Independent envelope verification, provider drivers, release gating, one-time ledger and generation fencing | In-process endpoint integration; no institution network implementation |
| EVM | Strict native/ERC-20 adapter and genuine ECDSA signing in development | Current provider is single-key, with no threshold security |
| Solana | SOL/classic SPL adapter, legacy/v0 verification, real FROST threshold signing and DKG | In-process DKG; no authenticated network transport, refresh, or recover/replace |
| Approval | Independent `oic-approve` CLI with pinned roots, recomputed display, encrypted Ed25519 credential files | Local CLI credentials rather than browser passkeys |
| Delivery | Builder, coordinator, broadcaster, durable operation/submission records, multi-source observation and invalidation | Supplied evidence/chain client implementations use simulators |
| Audit/recovery | Signed audit chain/checkpoints; file authority snapshots, ledger, and generation state | Local rollback witnesses need independent freshness anchors |
| Verification | Unit/property/differential tests, simulator integration, golden-vector conformance, bounded authority model | These are evidence for tested cases, not a security audit or deployment proof |

The workspace suite at this source checkpoint passed 363 tests with zero failures and zero ignored tests. See [verification guide](../testing/verification-guide.md) for the exact command and scope.

## Product objects versus product services

[`operations.rs`](../../crates/domain-types/src/operations.rs) defines deposit address state and custody mode, movement identities and acceptance, index cursors, journal entries and holdings, reconciliation checkpoints and cases, workflow triggers/steps/rules, and lifecycle events. Some helpers perform real calculations and consistency checks. Their serialization and commitments participate in the golden vectors.

These types do not supply an indexer, deposit monitoring service, journal persistence engine, reconciler, gas-funding controller, webhook server, or operator console. For example, `LifecycleEventBody.sequence` describes an institution-global gap-free sequence, but a schema field alone does not implement durable webhook delivery and replay. `WorkflowTrigger` provides a deduplicable object shape; a running controller still has to enforce deduplication, spending ceilings, and pause behavior.

The tracked service manifests currently cover builder, coordinator, and broadcaster. Root workspace dependencies also name paths such as `services/api`, `services/reconciler`, and additional chain adapters that are not workspace members or implemented packages. Start new work from the domain contracts and relevant RFC tests rather than treating those declarations as runnable services.

## How the RFCs relate

| Document | Role in this repository | How to use it |
| --- | --- | --- |
| [RFC 0001](../../spec/rfc-0001-open-institutional-custody.md) | Custody authorization, provider, adapter and lifecycle requirements, A-series acceptance scenarios | Trace each claimed invariant to its implementation and focused test |
| [RFC 0002](../../spec/rfc-0002-product-completion.md) | Proposed complete treasury workflow, accounting, distribution and C-series completion tests | Distinguish implemented schemas/components from a complete deposit-to-reconciliation product |
| [RFC 0003](../../spec/rfc-0003-institution-operated-signer-network.md) | Proposed institution-operated Commonware network and approver light client, N-series requirements | Treat membership, transport, replicated ordering and client trust as new work |

RFC 0002's delivery gates progress from executable protocol contract, through the first complete money loop, to independent operation and a restricted pilot. Its proposed performance/comparison criteria are not measured results. [`handoff.md`](../../handoff.md) records intended next work, including reconciler, API, protocol documentation, schemas, SDK/distribution, and remaining acceptance harnesses; verify that list against source before implementing it.

## Commonware and approver light client

RFC 0003 explicitly labels itself proposed architecture and disclaims an existing Commonware integration, network deployment, performance result, audit, or consensus-safety result for this composition. No current workspace manifest adds Commonware.

Its design introduces signed membership rosters and network admission, authenticated transport around the signer core, optional replicated authority ordering, public verification evidence, witness roles, and an approver client that verifies certified content before signing. These are separate mechanisms from the existing local approval CLI. The CLI's Ed25519 grant verification does not establish WebAuthn origin/RP-id/user-verification enforcement or browser certificate verification.

Some RFC 0003 implementation notes still call signer, audit, coordinator, and FROST packages reserved. Current source contains those packages, so use the executable map above for their present status. Conversely, the presence of `SignerEndpoint` does not establish a socket transport, signed roster enforcement, BFT authority, or client light-verification pipeline. External Commonware version/stability/toolchain statements in the RFC are dated research, not facts revalidated by this wiki generation.

## Safe extension path

Use [system overview](../architecture/system-overview.md) to locate ownership, [crypto providers](../integrations/crypto-providers.md) for topology and backend limits, and [test guide](../testing/verification-guide.md) for existing proof points. A new chain, backend, service, or transport must preserve envelope binding, common authorization state, release ordering, one-time state, and conservative uncertainty handling. Add a concrete executable path and its failure tests before claiming the corresponding RFC requirement complete.
