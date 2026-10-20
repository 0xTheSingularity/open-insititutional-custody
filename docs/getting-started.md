# Getting started

The current repository is a Rust workspace of libraries plus the `oic-approve`
independent approval CLI. Start by running the transfer integration tests. They
exercise the implemented workflow with real signatures and simulated chain effects,
without RPC credentials or a funded wallet.

## Prerequisites

- Git, Cargo, Rust, and a native linker/build toolchain.
- Network access to crates.io for the initial locked dependency download.
- Build space for Cargo's `target/` directory.

The workspace declares Rust 1.85 and edition 2021. The current lockfile and tests
were verified with Rust/Cargo 1.99.0 on macOS; the declared minimum was not
separately verified. Dependency compatibility can require a newer toolchain.

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
signer trust, builds an ERC-20 candidate, obtains an approval, reserves exposure,
verifies signer authorization, commits release, creates a native ECDSA signature,
and mines the transfer in the EVM simulator. It checks the recipient balance and
that exposure remains outstanding until finality is recorded.

The EVM provider here is development-only and single-key. A genuine ECDSA
signature does not establish threshold custody.

## Run Solana threshold signing

```sh
cargo test -p oic-service-coordinator --locked --test coordinator \
  solana_frost_2_of_3_end_to_end_for_every_signing_pair -- --exact
```

Expected result: `1 passed; 0 failed`. The test repeats the transfer with all
three possible two-participant subsets of a three-participant FROST key. It checks
native acceptance and recipient lamports. DKG and signer endpoints run in process;
this does not start the proposed institution peer network.

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
session failed on disk space; the command above completed successfully after
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

1. Enroll objects/trust and providers; register the intent with `Authority`.
2. Acquire an evidence bundle and call `oic_service_builder::build`.
3. Obtain independently verified approval grants and call builder `evaluate`.
4. Pass an allowing `SigningJob` to `Coordinator::execute`.
5. Pass its verified signed transaction to `Broadcaster::submit`.
6. Poll inclusion/finality or resolve uncertainty with evidence.

Read [build and coordination](../openwiki/workflows/build-and-coordinate.md) for
the detailed caller contracts. Do not expose low-level authority calls as an
unauthenticated external API; they rely on surrounding verification.

## Current product boundary

There is no API-server or complete product deployment launcher in the current
workspace. Live-chain clients, a full reconciler/journal/workflow controller,
production threshold ECDSA, Commonware transport/ordering, and browser passkey
approval remain separate implementation work. Operational schemas and proposed
RFC interfaces do not make those services executable.

Read the [documentation map](README.md), [implementation boundaries](../openwiki/concepts/implementation-boundaries.md),
and [development guide](development.md) for the next step.
