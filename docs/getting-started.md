# Getting started

The current repository is a Rust workspace of libraries plus the `oic-approve`
independent approval CLI. Start by running the transfer integration tests. They
exercise the implemented workflow with real signatures and simulated chain effects,
without RPC credentials or a funded wallet.

## Prerequisites

- Git, Cargo, Rust, and a native linker/build toolchain.
- Network access to crates.io for the initial locked dependency download.
- Build space for Cargo's `target/` directory.

If Rust is new to you, use the
[official installation guide](https://rust-lang.org/learn/get-started/#installing-rust),
including its platform build tools. Cargo is Rust's build and package tool.
A workspace groups related packages under one build; see the root `Cargo.toml`
for current members.

Use Rust 1.95 or newer for the full workspace. The Commonware network packages
require 1.95 and edition 2024; other packages retain edition 2021. The inherited
workspace Rust 1.85 declaration is not a verified minimum for the locked dependency
graph. Network builds also require CMake and a native C/C++ toolchain on Linux.

```sh
git clone https://github.com/0xTheSingularity/oss-wallet-insitutional.git
cd oss-wallet-insitutional
rustc --version
cargo --version
cargo build --workspace --locked
```

No environment or secret file is required for these tests. `--locked` preserves
the committed dependency resolution. Use `--offline` only after the required
dependencies and registry metadata are cached.

## Run an EVM transfer

```sh
cargo test -p oic-service-coordinator --locked --test coordinator \
  evm_erc20_end_to_end_signs_and_mines_in_the_simulator -- --exact
```

Expected result: `1 passed; 0 failed`. The fixture enrolls policy/destination and
signer trust, builds an ERC-20 candidate, obtains an approval, and reserves exposure.
It verifies signer authorization, commits release, creates a native ECDSA signature,
and mines the transfer in the EVM simulator. It checks the recipient balance and
that exposure remains outstanding until finality is recorded.

The EVM provider here is development-only and single-key. A genuine ECDSA
signature does not establish threshold custody.

`-p` selects a package, `--locked` preserves dependency versions, and `--exact`
selects the named test. Filtered tests did not run in that invocation.

## Run Solana threshold signing

```sh
cargo test -p oic-service-coordinator --locked --test coordinator \
  solana_frost_2_of_3_end_to_end_for_every_signing_pair -- --exact
```

Expected result: `1 passed; 0 failed`. The test repeats the transfer with all
three possible two-participant subsets of a three-participant FROST key. It checks
native acceptance and recipient lamports. DKG and signer endpoints run in process.
For separate signer processes and Commonware TCP, use the
[D1 signer-network tests](signer-network.md).

For submission-to-finality behavior and recovery scenarios:

```sh
cargo test -p oic-service-broadcaster --locked
```

## Run the full suite

```sh
cargo test --workspace --locked
```

The October 20 run at `0910530` passed **363 tests, 0 failed, 0 ignored**. This
includes unit/property tests, SDK differential tests, golden-vector conformance,
service integration and bounded model checking.

On a machine with constrained build space, use this tested profile:

```sh
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo test --workspace --locked -j 2
```

Use the same overrides for subsequent `cargo build`/`cargo run` invocations when
you want to reuse that artifact profile. An initial default-profile run in this
session failed on disk space. The command above completed successfully after
clearing generated build output. Do not treat an interrupted build as a test pass.

## Run the approval CLI

```sh
cargo build -p oic-approval-client --locked
./target/debug/oic-approve --help
```

The commands are `init-trust`, `keygen`, `show`, `approve`, `verify-grant`, and
`inspect-envelope`. Continue with [approval client](approval-client.md) for the
required trust/profile/package files and the exact invocation sequence.

## Integrate the libraries

Use [`services/coordinator/tests/coordinator.rs`](../services/coordinator/tests/coordinator.rs)
and its [`common` fixture](../services/coordinator/tests/common/mod.rs) as the
working construction example. The integration order is:

1. Enroll objects/trust and providers. Register the intent with `Authority`.
2. Acquire an evidence bundle and call `oic_service_builder::build`.
3. Obtain independently verified approval grants and call builder `evaluate`.
4. Pass an allowing `SigningJob` to `Coordinator::execute`.
5. Pass its verified signed transaction to `Broadcaster::submit`.
6. Poll inclusion/finality or resolve uncertainty with evidence.

Read [build and coordination](../openwiki/workflows/build-and-coordinate.md) for
the detailed caller contracts. Do not expose low-level authority calls as an
unauthenticated external API. They rely on surrounding verification.

## Current product boundary

| Capability | Current implementation and boundary |
| --- | --- |
| EVM transfers | Native value and registered standard ERC-20 `transfer` calls. Builds EIP-1559 transactions and verifies profile-enabled EIP-155 legacy transactions. |
| Solana transfers | SOL and classic SPL `TransferChecked`, checked destination token-account creation, and legacy/v0 message verification. Builder emits legacy messages. |
| Threshold signing | FROST Ed25519 with real DKG and threshold signing, plus D1 network integration tests. No network DKG, share refresh, or recover/replace yet. |
| EVM signing backend | Development single-key ECDSA. Production threshold ECDSA is not integrated. |
| Authorization | Policy rules, independent approvals, shared exposure, resource reservations, policy versions, and freezes. |
| Delivery and recovery | Recorded submission attempts, simulated chain clients, source disagreement handling, reorgs, and invalidation proofs. |
| Durable state and audit | File-backed stores, one-time-state consumption, signer generations, signed audit events, and checkpoints. |
| Product and networking | Runnable local D1 HTTP stack and roster-admitted Commonware libraries; fixed-committee D2 consensus and synced signing capabilities. No production launcher or committee handoff. |

The [local-stack recipe](local-stack.md) bootstraps independent development
approval credentials and runs authenticated HTTP payments against durable EVM
and Solana simulators. It is a single-machine D1 trial, not a production deployment.
The separate [Rust/WASM approver](../apps/approver-client/README.md) verifies D2
certificates and native candidates and exercises passkeys with Chromium's virtual
authenticator. Its HTTP fixture bridge is not a live Simplex witness service.
Live-chain clients, production threshold ECDSA, browser witness/gateway integration
and independently trusted client distribution remain separate implementation work.
The [network guide](signer-network.md#checks-and-current-limits) lists the remaining
RFC003 phases; the [protocol v1 contract](../spec/protocol-v1.md) describes RFC002
behavior and its production limits.

The simulator suites do not establish a production deployment or independent
security audit. The [chain concepts guide](concepts.md#how-evm-and-solana-express-a-transfer)
explains signature schemes, fee formats, mints, token accounts, and message versions.

## Troubleshooting

| Symptom | Next step |
| --- | --- |
| `cargo` is unavailable | Install the Rust toolchain, reopen the shell, and check `cargo --version`. |
| Offline dependency resolution fails | Run without `--offline` to download the locked crates and registry metadata. |
| Build runs out of space | Use the [lower-disk build profile](#run-the-full-suite). Review generated build output if space remains insufficient. |
| A named demo runs zero tests | Copy the full test name and keep `--test coordinator` and `-- --exact`. |
| Approval input files are missing | Create enrolled roots/profile and export a builder package using the [client guide](approval-client.md). |
| Evidence is stale or a grant expired | A candidate's evidence cannot be refreshed. Create a new intent, then approve and submit it within the evidence window (60s for the local approver). |
| A payment outcome is unknown | Preserve its reservation and signed bytes. Use chain observation or invalidation proof to resolve it. |

Read the [documentation map](README.md), [implementation boundaries](../openwiki/concepts/implementation-boundaries.md),
and [development guide](development.md) for the next step.
