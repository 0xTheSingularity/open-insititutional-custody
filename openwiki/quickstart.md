---
type: repository-guide
title: Repository guide
description: Start a runnable development custody flow, then use this map to select the smallest architecture, workflow, integration, operations, or verification reference for a proposed change.
tags: [repository-guide, custody, rust, development, task-routing]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-24T08:14:21.486Z
sources:
  - id: openwiki-source-d8c6df206fe2a2bd0435a38f
    resource: repo://apps/independent-approval-client/src/main.rs
  - id: openwiki-source-651d1fb6c9e49916a916ab51
    resource: repo://Cargo.toml
  - id: openwiki-source-14dbd82655071f5f89f9940f
    resource: repo://cli/oic/src/main.rs
  - id: openwiki-source-70991026f1538e8215a8789e
    resource: repo://docs/development.md
  - id: openwiki-source-04ce3d9a842d131a15af54ea
    resource: repo://docs/local-stack.md
  - id: openwiki-source-1a6f79f0e829aa916057cc0a
    resource: repo://services/coordinator/src/lib.rs
  - id: openwiki-source-718c366195d907d22d3b4498
    resource: repo://services/coordinator/tests/coordinator.rs
  - id: openwiki-source-77536073843dda08e6a7ae69
    resource: repo://tests/golden-vectors/tests/conformance.rs
generated: { by: "openwiki/0.7.2", at: "2026-10-24T08:14:21.486Z" }
---

# Repository guide

Use this page to choose an entrypoint and then the narrowest reference page that owns the behavior you intend to change. The repository is a Rust workspace of libraries, services, development tooling, tests, and two CLIs; the root manifest currently lists **38 workspace members** and declares Rust 1.95.

The repository supports a runnable **development** custody flow with real signatures and deterministic simulated chains. That is not a claim of a production deployment, live-chain operation, production threshold ECDSA, or a completed institutional product. Start with [Implementation and deployment boundaries](concepts/implementation-boundaries.md) whenever a request could cross that boundary.

For human-facing installation and use, begin with the [root README](../README.md), [documentation home](../docs/README.md), and [getting started](../docs/getting-started.md). This page routes implementation work to the deeper reference.

## Run the smallest useful flow

From the repository root, with Rust 1.95 or newer, Cargo, a native linker/build toolchain, and network access for an initial locked dependency download:

```sh
cargo run -p oic-cli -- demo
```

`oic demo` runs the custody money loop in one process against throwaway development simulators. It settles an EVM development 1-of-1 secp256k1 transfer and a Solana FROST Ed25519 2-of-3 transfer, exercises independent verification against a tampered package, and discards its temporary state at exit. It neither accepts a user state directory nor moves real funds.

For a source-level integration starting at the coordinator, run either focused test:

```sh
cargo test -p oic-service-coordinator --locked --test coordinator \
  evm_erc20_end_to_end_signs_and_mines_in_the_simulator -- --exact
cargo test -p oic-service-coordinator --locked --test coordinator \
  solana_frost_2_of_3_end_to_end_for_every_signing_pair -- --exact
```

The EVM test builds, authorizes, signs, submits, and mines a registered ERC-20 transfer in the simulator. The Solana test performs the same signing path for every two-member subset of a three-member FROST key. These are simulator-backed integration tests, not live-chain qualification.

Use `cargo test --workspace --locked` for the broad suite after focused checks. The checked-in development guide records a 363-test successful run at source checkpoint `0910530` with Rust/Cargo 1.99.0, but it does not establish a separately tested minimum-Rust, release, clippy, or coverage gate. On a constrained disk, use the [documented lower-disk profile](../docs/getting-started.md#run-the-full-suite).

To exercise the authenticated HTTP flow and durable simulator state on one machine, follow the [local development stack](../docs/local-stack.md). It is explicitly a single-machine D1 trial with development credentials and simulators, not a production installation.

## How the runnable flow maps to code

The shortest complete library route is `services/coordinator/tests/coordinator.rs` and its `common` fixture. It enrolls trust and policy objects, builds a candidate with evidence, obtains independent approval, runs `Coordinator::execute`, and submits the verified transaction to a simulator. During signing, the coordinator reserves global state before opening signer sessions, commits authority release before collecting shares, and treats a post-release failure as possible issuance rather than a safe abort. Exposure therefore remains outstanding until chain resolution.

The main ownership boundaries are:

- **Builder** derives and verifies a candidate and evaluates policy; it explains a proposed payment but does not issue a signature.
- **Authority** owns global reservations, resource locks, exposure, releases, freezes, and settlement.
- **Signer** independently verifies the envelope and native meaning, consumes durable one-time state, and gates signature output on a valid release.
- **Coordinator** performs signer protocol orchestration; after a committed release it must preserve uncertainty rather than retry as though no output occurred.
- **Broadcaster and reconciler** preserve signed bytes, observe chain outcomes, and resolve outstanding exposure.

Follow [Build, authorize, and coordinate signing](workflows/build-and-coordinate.md) for the caller contract and failure ordering; do not turn low-level authority calls into an unauthenticated external API.

## Task-routing map

| Proposed change or question | Smallest page to read first |
| --- | --- |
| Locate runtime owners, trust boundaries, runnable entrypoints, or the D1/D2 split | [Custody system overview](architecture/system-overview.md) |
| Change canonical objects, typed JSON, CBOR, hash domains, commitments, or signed envelopes | [Security objects and canonical encoding](concepts/security-objects-and-encoding.md) |
| Change rule precedence, denials, required approvals, evidence trust, or exposure inputs | [Policy evaluation](concepts/policy-evaluation.md) |
| Change reservations, idempotency, locks, releases, freezes, receipts, or settlement | [Authorization authority and exposure](architecture/authorization-authority.md) |
| Change D2 finalized authority, authenticated members, replicated state, or what followers verify before signing | [Replicated authorization and signer network](architecture/replicated-authorization-and-signer-network.md) |
| Change signer-local verification, generations, one-time state, D1 release gating, or share output | [Signer verification and release boundary](architecture/signer-boundary.md) |
| Change candidate construction, evaluation, coordinator sequencing, aggregation, or before/after-release recovery | [Build, authorize, and coordinate signing](workflows/build-and-coordinate.md) |
| Change HTTP intent creation, idempotency, catalog/approval ingestion, dispatch, refresh, or evidence export | [HTTP intent lifecycle](workflows/http-intent-lifecycle.md) |
| Change the independent approval package, confirmation, signed grant, or revalidation | [Independent approval](workflows/independent-approval.md) |
| Change submission records, rebroadcast, finality, source conflicts, reorgs, or invalidation proof | [Broadcast, finality, and uncertain outcomes](workflows/broadcast-and-finality.md) |
| Change EVM transaction semantics, evidence, signing payloads, replacement, or live-client integration | [EVM adapter contract](integrations/evm-adapter.md) |
| Change Solana message semantics, lookups, SPL/ATA checks, expiry, or live-client integration | [Solana adapter contract](integrations/solana-adapter.md) |
| Add or alter a cryptographic backend, FROST behavior, key-material boundary, or one-time signing contract | [Cryptographic providers](integrations/crypto-providers.md) |
| Change durable stores, reopen behavior, fences, rollback floors, or conservative recovery | [Durable state and recovery](operations/durable-state-and-recovery.md) |
| Change audit framing, signed history, checkpoints, projections, sink errors, or audit monitoring | [Audit log and checkpoints](operations/audit-log.md) |
| Change indexing, holdings/journal reconciliation, deposits, funding, sweeps, or pause conditions | [Reconciliation and treasury workflows](operations/reconciliation-and-treasury-workflows.md) |
| Add deterministic chain behavior, simulator faults, forks, or chain integration scenarios | [Chain simulators and chain integration tests](testing/chain-simulators.md) |
| Select focused tests, vectors, model exploration, local-stack, network, or browser verification | [Build and verification guide](testing/verification-guide.md) |
| Assess whether a request is implemented rather than runnable only in a development stack or proposed in an RFC | [Implementation and deployment boundaries](concepts/implementation-boundaries.md) |

## Focused verification and extension work

Run a focused package test before a workspace run. The [verification guide](testing/verification-guide.md) maps package commands to encoding, policy, authority, adapters, providers, signer state, approval, orchestration, network, audit, simulators, vectors, and the bounded authority model.

For serialized or adapter changes, run:

```sh
cargo test -p oic-golden-vectors --locked --test conformance
```

The conformance suite checks that committed files equal generator output, every declared domain has vectors, real producers reproduce canonical bytes and hashes, strict decoding round-trips, and EVM/Solana payloads agree with the respective independent Alloy and Solana SDK checks. Regenerate vectors only for an intentional protocol change, review the byte/hash diff, then rerun conformance.

Use [chain simulators](testing/chain-simulators.md) for deterministic behavior and fault coverage; simulator success is not live RPC, validator, or production deployment coverage. Use the [local-stack guide](../docs/local-stack.md) for the separate runnable HTTP/D1 stack and its operational limits.

## Entrypoints and documentation boundaries

- `cli/oic/src/main.rs` owns the development-only `oic demo` entrypoint.
- `apps/independent-approval-client/src/main.rs` owns `oic-approve`: `init-trust`, `keygen`, `show`, `approve`, `verify-grant`, and `inspect-envelope`.
- `services/coordinator/tests/coordinator.rs` is the compact working construction example for custody orchestration.
- `tests/golden-vectors/tests/conformance.rs` is the protocol-compatibility gate for canonical objects and native payload encodings.

Keep user setup and commands in `README.md` and `docs/`; use `openwiki/` for source-grounded implementation reference. RFCs under `spec/` describe requirements or proposals and do not themselves make a feature implemented. When a public command, input, or supported workflow changes, update the relevant human guide as well as the owning implementation reference.
