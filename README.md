# Open Institutional Custody

Rust components for independently verified EVM and Solana custody: build a transfer,
approve its actual meaning, reserve spending authority, sign through a guarded
provider, and track submission through finality.

The current implementation includes an independent approval CLI and composable
service libraries. Its runnable examples use deterministic development chains.
The Commonware signer network, browser approval light client, HTTP API, and full
deposit/accounting/reconciliation product are proposed work, described in the RFCs.

## Get started

Install a current Rust toolchain and a native linker, then run from the repository
root. The workspace declares Rust 1.85; the current lockfile was verified here with
Rust/Cargo 1.99.0.

```sh
git clone https://github.com/0xTheSingularity/oss-wallet-insitutional.git
cd oss-wallet-insitutional
cargo test --workspace --locked
cargo run -p oic-approval-client --locked --bin oic-approve -- --help
```

The tests require no live-chain credentials. First use downloads dependencies from
crates.io. At `0910530`, the workspace passed **363 tests, 0 failed, 0 ignored**.
See [getting started](docs/getting-started.md) for prerequisites, expected results,
and the tested command for machines with limited build space.

## Try the transfer flow

Run the EVM ERC-20 example through builder, approval, authority and signer, then
mine the signed transaction in the simulator:

```sh
cargo test -p oic-service-coordinator --locked --test coordinator \
  evm_erc20_end_to_end_signs_and_mines_in_the_simulator -- --exact
```

Run genuine Solana FROST two-of-three signing with every participant pair:

```sh
cargo test -p oic-service-coordinator --locked --test coordinator \
  solana_frost_2_of_3_end_to_end_for_every_signing_pair -- --exact
```

These are executable library examples. Builder, coordinator and broadcaster do not
currently ship server launchers. The EVM signing example uses a development
single-key provider; FROST supplies threshold Ed25519 for Solana.

## Use the approval client

```sh
cargo build -p oic-approval-client --locked
./target/debug/oic-approve --help
```

`oic-approve` can initialize pinned trust roots, generate an encrypted approver
credential, display a builder-produced package, sign and verify a grant, and inspect
envelope bindings. Follow the [approval client guide](docs/approval-client.md) for
input files, commands, confirmation behavior and exit codes.

## Documentation

| Start with | Purpose |
| --- | --- |
| [Documentation home](docs/README.md) | Human-facing guide and reading order |
| [Getting started](docs/getting-started.md) | Build, run transfer examples, and understand the current usage model |
| [Approval client](docs/approval-client.md) | Review and sign approvals from the command line |
| [Development](docs/development.md) | Focused tests, vectors, model checks, and updating documentation with Codex |
| [OpenWiki quickstart](openwiki/quickstart.md) | Task map into 17 source-and-test-grounded reference pages |
| [System overview](openwiki/architecture/system-overview.md) | Components, ownership, trust boundaries and source entrypoints |
| [Implementation boundaries](openwiki/concepts/implementation-boundaries.md) | What exists, what is proposed, and where the limits are |

## How the components fit

```text
Intent → Builder → Independent approval → Policy evaluation
       → Authority reservation → Signer verification → Authority release
       → Native signature → Broadcaster → Chain finality → Settlement
```

The authority serializes global exposure, resource locks, policy epochs and
freezes. Every signer independently checks the envelope and native transaction
bytes, then waits for a release receipt before producing output. Once a signature
may exist, uncertainty retains exposure until chain settlement or a definitive
invalidation proof.

The [RFCs](spec/rfc-0001-open-institutional-custody.md) describe the custody
contract; [RFC 0002](spec/rfc-0002-product-completion.md) defines product completion,
and [RFC 0003](spec/rfc-0003-institution-operated-signer-network.md) proposes the
institution-operated signer network and approver light client. Use source and
tests to establish implemented behavior.
