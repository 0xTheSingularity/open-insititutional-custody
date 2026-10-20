---
type: orientation-guide
title: Open Institutional Custody quickstart
description: Entry-point orientation and task-routing map for the implemented custody workspace, runnable tests, independent approval CLI, and source-grounded architecture and workflow documentation.
tags: [quickstart, orientation, custody, rust, task-routing]
sources:
  - id: openwiki-source-d8c6df206fe2a2bd0435a38f
    resource: repo://apps/independent-approval-client/src/main.rs
  - id: openwiki-source-651d1fb6c9e49916a916ab51
    resource: repo://Cargo.toml
  - id: openwiki-source-1a6f79f0e829aa916057cc0a
    resource: repo://services/coordinator/src/lib.rs
  - id: openwiki-source-718c366195d907d22d3b4498
    resource: repo://services/coordinator/tests/coordinator.rs
  - id: openwiki-source-77536073843dda08e6a7ae69
    resource: repo://tests/golden-vectors/tests/conformance.rs
generated: { by: "codex", at: "2026-10-20T20:39:06.439Z" }
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:39:06.439Z
---

# Open Institutional Custody quickstart

For human-facing setup and usage, start with the [root README](../README.md) and [documentation home](../docs/README.md). The guides cover [getting started](../docs/getting-started.md), [approval client commands](../docs/approval-client.md), and [development](../docs/development.md). This wiki supplies the deeper source-and-test reference and task map.

This repository implements Rust components for independently verified EVM/Solana custody authorization and signing. Its current 21-package workspace includes a policy kernel, authorization authority, pinned chain adapters, signer, development/FROST providers, independent approval CLI, builder/coordinator/broadcaster libraries, durable stores, audit, simulators and conformance/model tests.

The source and tests are authoritative. RFCs specify additional product and network work; they do not establish a production installation, complete accounting/API service, or security audit. Read [implementation boundaries](concepts/implementation-boundaries.md) before treating a proposed requirement as shipped behavior.

## Start here

Run from the repository root with a Rust toolchain and native linker:

```sh
cargo test --workspace --locked
cargo run -p oic-approval-client --locked --bin oic-approve -- --help
```

The initialization run at `0910530` passed **363 tests, 0 failed, 0 ignored** using Rust/Cargo 1.99.0 and the lower-disk command documented in the [verification guide](testing/verification-guide.md). The manifest declares Rust 1.85, but that minimum was not separately tested with the current lockfile.

To try the implemented transfer flow without live credentials:

```sh
cargo test -p oic-service-coordinator --locked --test coordinator \
  evm_erc20_end_to_end_signs_and_mines_in_the_simulator -- --exact
cargo test -p oic-service-coordinator --locked --test coordinator \
  solana_frost_2_of_3_end_to_end_for_every_signing_pair -- --exact
```

These execute real cryptography and simulator effects through the library integration. Service crates do not supply an API-server launcher. The approval CLI consumes independently enrolled trust/profile files and a builder-produced package; [approval workflow](workflows/independent-approval.md) documents its complete command sequence.

## Runtime flow

```text
register intent → acquire evidence → build/re-verify candidate → independent approval
→ evaluate policy → reserve global budget/resources → verify signer sessions
→ commit authority release → produce/aggregate shares → verify signed transaction
→ durably submit → cross-check inclusion/finality → settle or prove invalidation
```

The builder explains and constructs. Signers independently verify meaning and gate outputs. The authority owns cumulative exposure and ordered issuance/freezes. The broadcaster cannot sign; it preserves exact bytes and uncertainty. A missing acknowledgement or expired approval does not prove a possibly issued transaction was cancelled.

## Task-routing map

| I want to… | Read |
| --- | --- |
| Understand components, ownership, crate map and trust boundaries | [System overview](architecture/system-overview.md) |
| Understand amounts, byte formats, object relationships and envelope hashes | [Security objects and canonical encoding](concepts/security-objects-and-encoding.md) |
| Change rule ordering, hard denials, role/time or rolling-limit behavior | [Policy evaluation](concepts/policy-evaluation.md) |
| Trace idempotency, reservations, nonce locks, replacement exposure and freeze races | [Authorization authority](architecture/authorization-authority.md) |
| Build a preview/package and drive signing, including failures around release | [Build and coordinate](workflows/build-and-coordinate.md) |
| Run `oic-approve`, enroll roots, review a card or sign/verify a grant | [Independent approval](workflows/independent-approval.md) |
| Understand signer-local checks, destination quorum and output gating | [Signer boundary](architecture/signer-boundary.md) |
| Extend EVM semantics, calldata, native signing, nonce or fee evidence | [EVM adapter](integrations/evm-adapter.md) |
| Extend Solana messages, lookups, SPL/ATA checks or blockhash validity | [Solana adapter](integrations/solana-adapter.md) |
| Change backend topology, FROST DKG/signing or sealed shares | [Crypto providers](integrations/crypto-providers.md) |
| Recover file state, detect rollback, fence old generations or protect one-time state | [Durable state and recovery](operations/durable-state-and-recovery.md) |
| Verify/export signed audit history or compare witness checkpoints | [Audit log](operations/audit-log.md) |
| Handle lost acknowledgements, rebroadcast, reorg, source conflict or expiry proof | [Broadcast and finality](workflows/broadcast-and-finality.md) |
| Write deterministic economic/finality/fork scenarios | [Chain simulators](testing/chain-simulators.md) |
| Choose tests, run SDK differential checks, review vectors or bound model search | [Verification guide](testing/verification-guide.md) |
| Separate implemented libraries from accounting/API/Commonware/light-client proposals | [Implementation boundaries](concepts/implementation-boundaries.md) |

## Source entrypoints

The root `Cargo.toml` lists real members and dependencies. `services/coordinator/tests/coordinator.rs` is the shortest complete integration route. `apps/independent-approval-client/src/main.rs` defines the user CLI. `crates/signer/src/verify.rs`, `crates/authorization-state/src/authority.rs` and `crates/policy-kernel/src/lib.rs` own the main verification/state/decision boundaries. `tests/golden-vectors/tests/conformance.rs` checks protocol commitments and native payload compatibility.

For exact capability limits, follow the adapter and provider pages. For planned work, read the three RFCs under `spec/` and compare their requirements with current code. Empty/reserved paths and declarations do not count as implemented systems.

## Using and maintaining this wiki

Use this page as a task map, then read the relevant page and its source/tests. Wiki pages include repository-grounded Claims; generated provenance and Claim sidecars are managed by OpenWiki. When source changes, run the host-driven OpenWiki update lifecycle with Codex as researcher/writer and OpenWiki as queue/Claims/finalization manager. Do not manually rewrite its indexes or control files.

Maintain the root README and `docs/` as the human usage entrypoints. [Development documentation](../docs/development.md#updating-documentation) explains how to request a Codex-authored update and preserve the split between usage guides, implementation reference, and proposed RFCs.

The checked-in generated workflow is a separate scheduling mechanism; creating it does not establish that CI credentials, GitHub Actions, or a scheduled refresh have executed. Verify its configuration before relying on automation.
