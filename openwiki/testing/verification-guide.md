---
type: testing-guide
title: Build and verification guide
description: Workspace and focused Rust checks, executable transfer examples, SDK differential tests, golden-vector conformance, bounded model checking, and the scope of observed validation.
tags: [testing, build, conformance, golden-vectors, model-checking]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:16:28.312Z
sources:
  - id: openwiki-source-83f58dc8808d5c7f7db1e866
    resource: repo://apps/independent-approval-client/Cargo.toml
  - id: openwiki-source-651d1fb6c9e49916a916ab51
    resource: repo://Cargo.toml
  - id: openwiki-source-cad0bb1f9cd7304ac91ba24e
    resource: repo://models/authorization-state-machine/Cargo.toml
  - id: openwiki-source-ff57d24ef6232bcdc61339ee
    resource: repo://models/authorization-state-machine/src/lib.rs
  - id: openwiki-source-afac7467047ac802dae93ad8
    resource: repo://models/authorization-state-machine/src/main.rs
  - id: openwiki-source-1f44b95909775b86c28d5b71
    resource: repo://services/coordinator/Cargo.toml
  - id: openwiki-source-718c366195d907d22d3b4498
    resource: repo://services/coordinator/tests/coordinator.rs
  - id: openwiki-source-77536073843dda08e6a7ae69
    resource: repo://tests/golden-vectors/tests/conformance.rs
  - id: openwiki-source-e6634054c89c46e62f4d1ca7
    resource: repo://tests/golden-vectors/tests/generate.rs
generated: { by: "codex", at: "2026-10-20T20:16:28.312Z" }
---

# Build and verification guide

Run Cargo from the repository root. The workspace declares Rust edition 2021, `rust-version = 1.85`, and 21 member packages; that manifest minimum is not evidence that every current locked dependency was tested on 1.85. The initialization run used Homebrew Rust/Cargo 1.99.0 on macOS.

## Standard commands

```sh
cargo build --workspace --locked
cargo test --workspace --locked
cargo run -p oic-approval-client --bin oic-approve -- --help
```

Use `--locked` to preserve the committed dependency resolution. `--offline` works only after all locked crates and required index entries are available locally. Initial setup needs Cargo registry access. The source does not require live chain credentials for the simulator-backed tests.

When disk or build concurrency is constrained, the verified lower-disk test command is:

```sh
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo test --workspace --locked -j 2
```

These overrides remove debug information/incremental artifacts for that invocation; they do not change repository configuration. Choose a consistent profile when reusing artifacts between test and `cargo run` commands.

## Observed validation

At source checkpoint `0910530` on October 20, 2026, the lower-disk workspace command exited successfully with **363 passed, 0 failed, 0 ignored**, including all test binaries and documentation-test targets. No source code was changed for wiki generation.

The first offline attempt stopped on missing pinned `solana-message = 6.0.0`. After dependency download, an unrestricted-debug build hit `No space left on device` and compiler process failures. Cleaning this repository's generated `target` output and using the command above completed the suite. These were setup/resource failures, not hidden passing results. This record does not claim a separate MSRV, release build, clippy, coverage, live-network, or production deployment check.

## Pick the narrow test surface

| Change | Package / focused test |
| --- | --- |
| Canonical bytes and strict parsing | `cargo test -p oic-canonical-encoding --locked` |
| Rule precedence, grants, limits/time | `cargo test -p oic-policy-kernel --locked` |
| Reservations, freezes, races, file snapshots | `cargo test -p oic-authorization-state --locked` |
| Native EVM or Solana meaning | `cargo test -p oic-adapter-evm -p oic-adapter-solana --locked` |
| Provider topology/protocol/state | `cargo test -p oic-crypto-provider-dev -p oic-crypto-provider-frost-ed25519 --locked` |
| Envelope, release gate, restored signer | `cargo test -p oic-signer --locked` |
| One-time record persistence | `cargo test -p oic-one-time-state-ledger --locked` |
| Independent card/grants/CLI | `cargo test -p oic-approval-verifier -p oic-approval-client --locked` |
| Build and execute signing | `cargo test -p oic-service-builder -p oic-service-coordinator --locked` |
| Submission uncertainty and finality | `cargo test -p oic-service-broadcaster --locked` |
| Audit history/witnesses | `cargo test -p oic-audit --locked` |
| Simulated economics/forks | `cargo test -p oic-chain-simulator --locked` |

For an executable transfer path, start with coordinator tests `evm_erc20_end_to_end_signs_and_mines_in_the_simulator` and `solana_frost_2_of_3_end_to_end_for_every_signing_pair`. Builder/coordinator/broadcaster are library services; these tests construct their dependencies rather than launching an API server. See [build and coordination](../workflows/build-and-coordinate.md).

## Golden-vector conformance

`tests/golden-vectors/vectors/` contains 30 JSON files: one per covered internal domain and two native payload files. The conformance suite checks exact generator output, domain coverage, canonical round trips, real producer hashes/derived ids/signatures, and native signing payloads against adapters plus Alloy/Solana SDK implementations.

```sh
cargo test -p oic-golden-vectors --locked --test conformance
```

Only regenerate after an intentional protocol/fixture change, then review every changed byte/hash and rerun conformance:

```sh
OIC_REGENERATE_VECTORS=1 cargo test -p oic-golden-vectors --locked --test generate
```

Without that environment value, the generator test returns without writing. Its passing result is not evidence that files were regenerated. A helper naming `schemas/` and a pinned JSON Schema dependency do not establish a committed schema suite or completed `spec/protocol-v1.md`; see [implementation boundaries](../concepts/implementation-boundaries.md).

## Bounded state exploration

`oic-model-authorization-state` calls the **real** authority over in-memory snapshots; it does not implement a second transition algorithm. The bounded universe has one vault, one asset budget, one EVM nonce, two families and three candidate/replacement choices. Reopen-only generation/epoch/commit noise is normalized for state deduplication.

```sh
cargo run -p oic-model-authorization-state --locked -- --depth 8
```

The default CLI depth is ten; the workspace test explicitly checks depth eight. `check` runs breadth-first search and asserts five safety properties: bounded total exposure, retained possibly issued obligations, exclusive resource ownership, ordered freeze/release, and no abort after possible issuance. Reachability assertions ensure interesting releases/replacements/freeze states are explored. Invalid arguments return exit code two; violations or missed reachability targets fail the checker.

This is bounded evidence for that universe. It does not prove distributed consensus, arbitrary chains, every interleaving at unlimited depth, or complete RFC acceptance coverage. SDK differential checks, adversarial tests and [simulator tests](chain-simulators.md) establish different boundaries and complement it.
