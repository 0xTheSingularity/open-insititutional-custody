---
type: concept
title: Deterministic policy evaluation
description: Policy binding, hard-deny precedence, first-match rule selection, approval semantics, time windows, and the split between local and globally reserved exposure.
tags: [policy, approvals, limits, determinism, fail-closed]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:16:28.312Z
sources:
  - id: openwiki-source-5ff1aed094752687edeb7935
    resource: repo://crates/policy-kernel/src/hashing.rs
  - id: openwiki-source-32fee8b5f4857b2429c56512
    resource: repo://crates/policy-kernel/src/lib.rs
generated: { by: "codex", at: "2026-10-20T20:16:28.312Z" }
---

# Deterministic policy evaluation

`oic-policy-kernel::evaluate(&PolicyInput)` is a pure decision function. It takes explicit time, verified operation semantics, authenticated grants, enrolled objects, and an exposure view. It performs no I/O, reads no clock, uses no randomness or floating point, and returns `Allow`, `Deny`, or `RequireApprovals` with stable reason codes.

## Authentication comes before evaluation

`PolicyInput` assumes that its caller authenticated policy, grants, and evidence. The kernel recomputes policy and intent hashes and checks bindings; `evaluate` does not itself verify every grant signature. The builder calls `verify_grants`, signers independently authenticate policy/destination/grants, and the authority verifies administrative policy activation. Helpers in [`hashing.rs`](../../crates/policy-kernel/src/hashing.rs) verify explicit-scheme Ed25519 signatures and count distinct enrolled administrative credentials.

## Fixed decision pipeline

| Stage | Checks | Failure result |
| --- | --- | --- |
| Binding | Exact current policy epoch, activation epoch, canonical policy/intent hashes, matching institution/environment/vault/policy identity | `Deny` |
| Hard denials | Denied destinations/assets, registered destination id/version/activation/assets, network and asset identity, standard asset behavior, evidence freshness/trust, decoded recipient/amount/native value/fee, grant count | `Deny`, before rules |
| Rule selection | First rule in bundle order matching vault, asset, destination, and purpose | `Deny` if no match |
| Rule requirements | Per-operation amount/fee caps, UTC operating window, rolling exposure, explicit automated-role permission | `Deny` |
| Approval count | Bound, current grants from distinct allowed credentials, optional proposer exclusion | `Allow` or `RequireApprovals` |

A later permissive rule cannot override hard denials or rescue a failed first matching rule. Empty rule scope lists match anything. `match_rule` is a public explanation helper that performs only selection; it does not authorize a candidate.

## Native meaning and freshness

The decoded recipient must equal the registered destination address; the amount and concrete native/ERC-20/SPL asset identity must match the intent and asset object. Native transfer value must equal its amount, while ERC-20 native value must be zero. SPL native movement for account creation is bounded by adapter fee accounting. `Nonstandard` assets are rejected.

Evidence observed in the future is rejected. Its permitted age is the tighter of the policy's limit and the bundle's declared staleness; equality at the age boundary is accepted. Evidence trust is checked against the policy environment. More than `MAX_GRANTS` (64) grants is a hard denial. An intent requesting zero successful payments is unsupported.

## Limits and time boundaries

Amounts use checked integer base units. For a rolling limit, the operation charge is the larger of its decoded amount and the sum of adapter-claimed outflows for the asset. The kernel evaluates:

```text
settled + outstanding + operation_charge <= max_outflow_base_units
```

The exposure view must contain the exact asset/window pair; absent data yields `MissingExposureData`, and overflow yields `ExposureOverflow`. Equality at a limit is allowed. Outstanding exposure remains a separate input from settled window usage; the [authority](../architecture/authorization-authority.md) ensures it does not age out.

Operating windows use UTC seconds of day and the half-open interval `[start, end)`. `start > end` wraps midnight; equal endpoints or out-of-range bounds form an empty window. No configured window permits all times.

The [signer](../architecture/signer-boundary.md) supplies zero prior exposure for each configured window to enforce single-operation limits locally. The authority atomically checks accumulated exposure during reserve. A preview cannot replace that reservation check.

## Grant semantics

Every counted grant must bind the intent id/hash, institution/environment/vault, policy id/epoch, allowed role, and scope. Time validity is `issued_at <= now < expires_at`; expiry is exclusive. When `exclude_proposer` is set, the proposer's credential cannot count.

Exact grants bind candidate id, revision, and preview hash. Bounded grants bind wallet, network, asset, amount, destination id/version/address, maximum native fee, and a positive successful-payment allowance. Adapter verification additionally constrains which native fields may vary; the grant alone does not authorize arbitrary retries.

Distinct valid credential ids count once. Invalid or duplicate grants add reasons but do not force denial if enough other valid grants satisfy the threshold. If too few satisfy it, the result is `RequireApprovals`. The surrounding cryptographic verifier is stricter about malformed/unauthenticated grants and rejects an invalid grant set before evaluation. A zero-approval rule must explicitly list `ApprovalRole::Automated`.

## Commitments and focused tests

`policy_hash` and `destination_hash` exclude their own administrative signature arrays; signatures authenticate the unsigned object content. `preview_hash` commits candidate id, revision, decoded operation hash, and evidence bundle hash. See [security objects and encoding](security-objects-and-encoding.md).

```sh
cargo test -p oic-policy-kernel --locked
```

[`tests.rs`](../../crates/policy-kernel/src/tests.rs) covers hard-deny dominance, epoch/hash/scope mismatches, freshness/trust, exclusive grant expiry, duplicate approvers, proposer rules, bounded templates, midnight windows, limit equality, missing exposure and overflow, automated rules, and deterministic/property-based behavior. For the complete approval path, read [independent approval](../workflows/independent-approval.md).
