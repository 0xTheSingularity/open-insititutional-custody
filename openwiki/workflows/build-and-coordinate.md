---
type: workflow
title: Build, authorize, and coordinate signing
description: Builder scope validation and independent previews, approval package/envelope construction, signer-provider orchestration, and failure handling around authority release.
tags: [builder, coordinator, signing, approvals, issuance]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:16:28.312Z
sources:
  - id: openwiki-source-e793f42b3a5f8174c8f456c9
    resource: repo://services/builder/src/lib.rs
  - id: openwiki-source-463bb52ba93b9226cd092a76
    resource: repo://services/coordinator/src/driver.rs
  - id: openwiki-source-109e19ea3dc6c23aa12978cf
    resource: repo://services/coordinator/src/endpoint.rs
  - id: openwiki-source-1a6f79f0e829aa916057cc0a
    resource: repo://services/coordinator/src/lib.rs
generated: { by: "codex", at: "2026-10-20T20:16:28.312Z" }
---

# Build, authorize, and coordinate signing

`oic-service-builder` prepares a candidate; `oic-service-coordinator` drives its signing protocol. Both are libraries. They do not provide the proposed HTTP API or a deployment command. Their integration tests construct the current runnable workflow.

## Prerequisites and objects

Enroll matching institution/environment, vault and policy, wallet/key/profile, asset and admin-signed destination. Register the intent with the authority to obtain its deterministic operation family. Configure pinned adapters, enrolled signer trust roots, loaded sealed shares, provider/ledger/generation stores, and a trusted clock.

`BuildInputs` carries those objects, evidence, candidate identity/revision/family and build time. `EvidenceSource` supplies adapter-specific chain state. The supplied sources wrap simulators and require request scope/profile to match the served chain. Missing mandatory evidence remains an adapter failure; sources do not invent nonexistent accounts.

## Build and explain

1. `build` cross-checks intent/vault/wallet/key/asset/destination/policy/profile/family references before invoking the adapter.
2. `adapter.build_candidate` produces native bytes. The builder then verifies them against the intent and checks rederived payloads, decoded hash and evidence binding.
3. In bounded mode it derives a direct-transfer template and verifies the same bytes against it, requiring identical decoded meaning/payloads.
4. Return `BuiltCandidate`, its `ApprovalPackage`, decoded/verified operation, template when applicable, and preview commitment.

`required_approvals` explains the first matching rule; it returns no requirement for a zero-approval path or no match. That is not an authorization decision. `evaluate` first authenticates grants against an enrolled roster, requires the same policy as the package, and calls the kernel with expected policy epoch, explicit time and supplied exposure view. See [policy evaluation](../concepts/policy-evaluation.md).

The package goes to the [independent approval client](independent-approval.md). A console's human-readable summary is not an input to its trust decision. Approval returns grants binding the exact preview or bounded template.

## Envelope preparation

`envelope_body` builds commitments from the candidate/package, adapter/profile, grants, fresh signer session, participant set and issuance deadline. It derives the reservation id from family/candidate/revision and uses reservation version one. The envelope includes native bytes/payloads, semantic/evidence/destination hashes, policy/build/key/profile commitments and worst-case resource/asset/fee claims.

`signing_materials` presents the same object set to every signer. Those helpers construct the requested data; signers still authenticate and rederive it independently.

## Coordinator sequence

`SigningJob` carries the built candidate, policy, profile, grants, evaluation, participants and deadline. `Coordinator::execute` follows this order:

| Step | Operation | Durable meaning |
| --- | --- | --- |
| Decision gate | Require `Allow`; otherwise record awaiting approval/rejection | No authority reservation |
| Static preparation | Check policy/matched rule, registered adapter, backend driver, participants/endpoints; create fresh UUID session and body | Reject bad configuration before reserve |
| Reserve | Submit rule-derived limits and claims to the authority; attach returned `Reserved` receipt | `Reserved` |
| Open and relay | Every participant verifies the envelope; collect/relay non-share rounds; deliver buffered share rounds | `Authorized` |
| Release | Authority rechecks and commits possible issuance | `IssuanceCommitted` |
| Aggregate | Present the actual release receipt to every participant, aggregate output on a participant, assemble and natively verify signed bytes | `SignatureObserved` |

The returned `Issuance` includes envelope, release receipt, issuance record and verified signed transaction. It has not yet been broadcast or finalized. The authority reservation remains outstanding.

## Drivers and endpoints

`SignerEndpoint` defines session open, message delivery, release, public aggregation and abort; `InProcessSigner` forwards to a real signer. The trait permits future authenticated transport but implements no network by itself.

`FrostEd25519Driver` relays each participant's commitment and constructs a signing package with the exact session payload/subset. `DevSingleKeyDriver` sends one payload-hash-bound protocol message. Drivers hold no key shares and cannot bypass signer verification or release gating. Driver selection is explicit by key backend; unsupported backends fail preparation.

## Failure boundary

Before successful authority release, the coordinator aborts opened sessions and attempts `abort_before_issuance` on the reservation. Successful cleanup releases locks/exposure and records `AbortedBeforeIssuance`. Cleanup errors are included in returned context; a failed reservation abort leaves the reservation held with a pre-issuance lifecycle rather than claiming it was released.

After successful release, the coordinator never aborts the reservation. Any signing, aggregation, assembly or lifecycle-log failure returns `IssuanceUncertain` naming reservation/session and attempts to record `IssuanceUnknown`. A missing final result does not prove that no participant produced output. Chain evidence must resolve that obligation.

`OperationStore` records transitions and prevents a possibly issued candidate being represented as pre-issuance again. It is workflow history, not the authority's global accounting state. For file replay and crash limits, see [durable state](../operations/durable-state-and-recovery.md).

```sh
cargo test -p oic-service-builder --locked
cargo test -p oic-service-coordinator --locked --test coordinator
```

Tests cover EVM ERC-20 mining, Solana FROST every two-of-three pair, bounded mode, changed bytes before release, participant failure after release, two jobs racing a global limit, missing grants, counterfeit receipts and bad configuration. Continue with [signer boundary](../architecture/signer-boundary.md) and [broadcast/finality](broadcast-and-finality.md).
