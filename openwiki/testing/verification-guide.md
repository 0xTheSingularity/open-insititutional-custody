---
type: testing-guide
title: Build and verification guide
description: Select focused checks for custody behavior and understand what unit, integration, vector, model, simulator, network, local-stack, and browser verification each establish—and what they do not.
tags: [testing, build, conformance, golden-vectors, model-checking, integration-testing]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-24T08:14:21.486Z
sources:
  - id: openwiki-source-3e471a4edde60a680ed87fbe
    resource: repo://apps/approver-client/tests/browser.mjs
  - id: openwiki-source-651d1fb6c9e49916a916ab51
    resource: repo://Cargo.toml
  - id: openwiki-source-170efe1594155429dcb94970
    resource: repo://docs/acceptance-coverage.md
  - id: openwiki-source-ff57d24ef6232bcdc61339ee
    resource: repo://models/authorization-state-machine/src/lib.rs
  - id: openwiki-source-afac7467047ac802dae93ad8
    resource: repo://models/authorization-state-machine/src/main.rs
  - id: openwiki-source-7bc924df180ddcc658a2819d
    resource: repo://scripts/local-stack/check-d2.sh
  - id: openwiki-source-1f44b95909775b86c28d5b71
    resource: repo://services/coordinator/Cargo.toml
  - id: openwiki-source-718c366195d907d22d3b4498
    resource: repo://services/coordinator/tests/coordinator.rs
  - id: openwiki-source-da9b08928ed7f4c3321bc383
    resource: repo://services/signer-net/Cargo.toml
  - id: openwiki-source-21501e9ae88723c4a841e46a
    resource: repo://services/signer-net/tests/network.rs
  - id: openwiki-source-77536073843dda08e6a7ae69
    resource: repo://tests/golden-vectors/tests/conformance.rs
  - id: openwiki-source-e6634054c89c46e62f4d1ca7
    resource: repo://tests/golden-vectors/tests/generate.rs
generated: { by: "openwiki/0.7.2", at: "2026-10-24T08:14:21.486Z" }
---

# Build and verification guide

Verification is layered. A fast package test is the right first check for a local change, but it cannot establish cross-component signing behavior, compatibility bytes, a bounded state-space invariant, or a real process/browser boundary. Start narrowly, then expand the test surface to the boundary changed. No test command below by itself proves a production deployment, live-chain behavior, or distributed consensus.

The root workspace uses Rust edition 2021 and declares Rust 1.95 as its minimum; individual packages can set their own edition (for example, `oic-service-signer-net` uses edition 2024). Run Cargo commands at the repository root and retain `--locked` so they use the committed dependency resolution.

```sh
cargo build --workspace --locked
cargo test --workspace --locked
```

`--offline` is appropriate only after the locked registry dependencies have been cached. The development setup hook downloads locked dependencies, while the resume hook verifies offline resolution; neither requires chain credentials, environment files, a database, or a persistent development server.

## Choose the smallest meaningful check

Use a focused package suite while developing, then run `cargo test --workspace --locked` before handing off a cross-workspace change.

| Changed boundary | Focused command | What it is meant to catch |
| --- | --- | --- |
| Canonical encoding, strict decoding, commitments | `cargo test -p oic-canonical-encoding --locked` | Byte-level representation and hashing regressions |
| Policy decisions | `cargo test -p oic-policy-kernel --locked` | Rule precedence, grants, limits, and time constraints |
| Authorization state | `cargo test -p oic-authorization-state --locked` | Reservations, exposure, freezes, races, and snapshots |
| EVM or Solana interpretation | `cargo test -p oic-adapter-evm -p oic-adapter-solana --locked` | Native transaction meaning and payload verification |
| Signing providers | `cargo test -p oic-crypto-provider-dev -p oic-crypto-provider-frost-ed25519 --locked` | Provider topology, protocol behavior, and durable signing state |
| Signer release boundary | `cargo test -p oic-signer -p oic-one-time-state-ledger --locked` | Envelope checks, release gating, restored signer state, and one-time records |
| Independent approval | `cargo test -p oic-approval-verifier -p oic-approval-client --locked` | Review display, grants, and CLI behavior |
| Orchestration and delivery | `cargo test -p oic-service-builder -p oic-service-coordinator -p oic-service-broadcaster --locked` | Construction, coordination, submission uncertainty, and finality handling |
| Audit history | `cargo test -p oic-audit --locked` | Audit-chain and witness behavior |
| Simulated chain behavior | `cargo test -p oic-chain-simulator --locked` | Deterministic EVM/Solana execution, evidence, finality, and forks |

These are complementary scopes, not a ranking of confidence. Unit and package tests isolate component contracts and refusal paths. Integration tests construct real component dependencies and test their bindings. The [security-object and encoding model](../concepts/security-objects-and-encoding.md) explains why byte-level encoding and native signing payload checks deserve their own surface.

### Coordinator integration path

The coordinator integration suite is the best focused starting point for an end-to-end signing change:

```sh
cargo test -p oic-service-coordinator --locked
```

Its EVM case builds, authorizes, signs, submits, and mines an ERC-20 transfer in the simulator, then checks the recorded lifecycle and retained exposure. Its Solana FROST case executes a transfer with each of the three possible two-of-three participant pairs. These are in-process dependency assemblies, not a server-launch or live-network workflow. They also exercise adverse behavior such as changed native bytes and signer failure after release, where issuance becomes uncertain and exposure must remain retained rather than being silently released.

For deterministic chain execution, evidence, and reorganization semantics beyond the coordinator path, use [chain simulators and chain integration tests](chain-simulators.md). Simulator coverage is an executable contract for the repository's model, not equivalence with every public-chain implementation.

## Golden vectors: protocol compatibility checks

Run committed-vector conformance separately when a signed object, domain tag, canonical bytes, adapter payload, or fixture generator changes:

```sh
cargo test -p oic-golden-vectors --locked --test conformance
```

The conformance suite requires the checked-in JSON files to exactly match fresh domain and native-vector construction, and requires one nonempty file for every declared domain tag. It re-encodes typed inputs through the actual producer, verifies recorded canonical bytes, domain-hash construction, derived identifiers, strict decode round trips, signatures, and selected private derivations through real signing/authority/audit flows. For EVM and Solana payloads it also has the adapters re-derive the recorded payload, then cross-checks serialization and signing conventions against Alloy and the Solana SDK. This detects a shared internal implementation drifting from its intended wire contract; it is stronger than a JSON shape check.

Regenerate only for an intentional fixture or protocol change, inspect the resulting byte and hash diff, then rerun conformance:

```sh
OIC_REGENERATE_VECTORS=1 cargo test -p oic-golden-vectors --locked --test generate
git diff -- tests/golden-vectors/vectors
cargo test -p oic-golden-vectors --locked --test conformance
```

Without `OIC_REGENERATE_VECTORS=1`, the generator test makes no writes. A passing generator invocation without that environment value is therefore not regeneration evidence.

## Bounded model exploration

The authorization model checker invokes the real `Authority` against an in-memory authority store; it is not a second hand-written transition implementation. Its finite universe has one vault, one asset budget, a shared EVM nonce, two operation families, and three candidates including a same-nonce replacement. It searches reserve, release, abort, freeze/unfreeze, finalization, invalidation, expiry, and clock-tick actions, treating rejected authority calls as no transition.

```sh
cargo run -p oic-model-authorization-state --locked -- --depth 8
```

The library's workspace test checks depth eight. The CLI defaults to authority depth ten and also runs a replication-composition check at default depth eleven; `--depth` and `--replication-depth` accept either a separate value or `=<N>`. Bad arguments, including help, print a diagnostic and return exit status 2. A successful run reports frontier/action bounds and total/unique state counts for both checks.

The authority exploration asserts: exposure never exceeds its limit; a possibly issued candidate retains exposure until chain resolution; different families cannot hold the same resource; no release is committed while a freeze is in force; and a possibly issued reservation cannot be aborted. It additionally requires reachability of a release, a replacement, a frozen retained release, and both families settled. State identity normalizes writer generation, authority epoch, and reopening commit noise so equivalent authority states deduplicate.

The replication composition model is a separate finite model of two followers applying three fixed valid histories with delivery, halt/unhalt, crash/restart, roster epochs, and session/output fencing. It re-executes real canonical authority commands, but explicitly assumes one authenticated fork-free finalized order, authenticated roster/operator inputs, monotonic time, and atomic durable recovery. It does **not** verify Simplex voting, a production D2 runtime, arbitrary storage faults, real MPC, or eventual delivery. See [replicated authorization and signer network](../architecture/replicated-authorization-and-signer-network.md) for the implemented D2 boundary.

Thus model results are bounded evidence for stated universes and assumptions. They complement adversarial unit tests and integration tests; they are not a consensus or unbounded-concurrency proof.

## Network, local-stack, and browser boundaries

The network integration suite crosses a boundary deliberately absent from coordinator tests: real Commonware TCP, private Unix IPC, and separate FROST signer-core processes. Run its network target with:

```sh
cargo test -p oic-service-signer-net --test network --locked
```

Its fixture provisions DKG before network startup and drops the in-process fixture signers; no bridge holds a live signer share. The child signer cores use private fixture directories and file-backed ledger, generation, and audit state. This suite provides process and transport evidence for the D1 path, but it does not make a production deployment claim.

For the broader development-only D2 demonstration, use a **new, private, nonexistent** run directory:

```sh
bash scripts/local-stack/check-d2.sh NEW_PRIVATE_RUN_DIRECTORY [both|evm|solana]
```

The script refuses to replace an existing run directory, checks its toolchain/browser prerequisites, builds the network example locked and offline, then—for each selected chain—runs four TCP replicas, two HTTP nodes, a real WASM/Chromium verification, and installation-integrity checks. It retains logs and private run state on failure. Its prerequisites include Rust 1.95 with the `wasm32-unknown-unknown` target, `mold`, `wasm-bindgen` 0.2.117, Node, cached Cargo dependencies, and Playwright Chromium. This is development evidence with simulated chain inputs and virtual user verification; it explicitly does not demonstrate production installation, independently authenticated distribution, physical attestation, or a live-chain transfer.

The browser harness uses headless Chromium with a virtual WebAuthn authenticator and exercises the compiled WASM public boundary. In live mode it forwards to the local nodes, verifies the certified log before enabling approval, checks bounded-history resume, mobile layout, pending-versus-recorded status, ordered replication to four replicas, and refusal of non-advancing pagination. It treats HTTP acceptance as enqueue acknowledgement rather than confirmation: the UI records approval only after it observes verified finalized history. Virtual WebAuthn and browser entropy validate the browser integration mechanics, not hardware-attestation or production-fund security.

## Acceptance references are not proof

`docs/acceptance-coverage.md` is a generated map from RFC acceptance IDs to source citations. Regenerate it after adding or renaming a citation. A citation is a coverage lead, not a passing-test guarantee: examine the cited assertions, and do not infer that an uncited test has no relevant coverage. The current map also marks several acceptance IDs as having no reference, so it must not be presented as complete acceptance evidence.

## Suggested escalation order

1. Run the smallest package test that owns the changed invariant.
2. Run a coordinator or simulator integration test if the change crosses build, authorization, signer, or chain boundaries.
3. Run golden-vector conformance for any committed representation or native payload change.
4. Run the bounded model when reservation, issuance, freeze, replacement, or replicated-authority semantics change; increase a bound only as an intentional cost/coverage decision.
5. Run network and local-stack/browser checks when changing process isolation, D1/D2 transport, local-node HTTP, approver WASM, or WebAuthn-facing behavior.
6. Finish with the locked workspace suite.

This sequence keeps feedback fast while ensuring that a change is tested at the boundary where its failure would be observable.
