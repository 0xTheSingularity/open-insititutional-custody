# Development

Use the root [`Cargo.toml`](../Cargo.toml) to identify implemented workspace
members. Start from a focused test when changing behavior, then run the full
workspace suite before handing off a code change.

## Verification commands

```sh
cargo test --workspace --locked
cargo build --workspace --locked
```

The source checkpoint `0910530` passed 363 tests with no failures or ignored tests
on Rust/Cargo 1.99.0. That run used the lower-disk profile in
[getting started](getting-started.md#run-the-full-suite). A separate minimum-Rust,
release, clippy or coverage gate was not run for this documentation task.

| Area | Focused command |
| --- | --- |
| Encoding and hashes | `cargo test -p oic-canonical-encoding --locked` |
| Policy semantics | `cargo test -p oic-policy-kernel --locked` |
| Authority, locks, exposure and freezes | `cargo test -p oic-authorization-state --locked` |
| Native semantics | `cargo test -p oic-adapter-evm -p oic-adapter-solana --locked` |
| Provider cryptography/protocol | `cargo test -p oic-crypto-provider-dev -p oic-crypto-provider-frost-ed25519 --locked` |
| Signer and one-time state | `cargo test -p oic-signer -p oic-one-time-state-ledger --locked` |
| Independent approval | `cargo test -p oic-approval-verifier -p oic-approval-client --locked` |
| Orchestration and finality | `cargo test -p oic-service-builder -p oic-service-coordinator -p oic-service-broadcaster --locked` |
| Audit | `cargo test -p oic-audit --locked` |
| Test-chain behavior | `cargo test -p oic-chain-simulator --locked` |

## Protocol vectors

```sh
cargo test -p oic-golden-vectors --locked --test conformance
```

The committed 30 JSON vector files cover internal hash domains and native EVM /
Solana payloads. Tests rederive bytes and hashes through the real producers,
verify strict round trips, compare expected fixture files, and cross-check native
payloads against Alloy and Solana SDK implementations.

After an intentional serialized-contract or fixture change, regenerate explicitly:

```sh
OIC_REGENERATE_VECTORS=1 cargo test -p oic-golden-vectors --locked --test generate
git diff -- tests/golden-vectors/vectors
cargo test -p oic-golden-vectors --locked --test conformance
```

Review the changed bytes/hashes as protocol changes. Do not regenerate merely to
silence a conformance failure. Without the environment value, the generator test
returns without writing files.

## Bounded authority model

```sh
cargo run -p oic-model-authorization-state --locked -- --depth 8
```

Expected output begins `all properties hold:` and includes explored state counts.
The checker calls the real authority in a bounded one-vault/one-asset/one-nonce
universe with two families and a replacement. It tests exposure retention, limits,
resource exclusivity, freeze ordering and no post-issuance abort, plus reachability.
The workspace test uses depth eight; CLI default depth is ten. This is bounded
evidence, not an unbounded or distributed-consensus proof.

## Integrating a new component

Use the [system map](../openwiki/architecture/system-overview.md) to find ownership.
New adapters must derive transaction meaning and native payloads from bytes. New
providers must state an honest topology, message convention and consume-before-share
contract. Live evidence clients must preserve profile/freshness/finality and source
conflict handling. A new transport must authenticate peer/session/generation context
and preserve signer release gating.

Distinguish declared schemas and proposed RFC requirements from implemented
services. In particular, adding an API, reconciler or Commonware peer network
requires a real entrypoint and failure tests; reserved paths do not supply one.

## Updating documentation

Maintain `README.md` and `docs/` with user-facing commands and entrypoints. Keep
deep mechanisms in the [OpenWiki reference](../openwiki/quickstart.md), grounded
against source and tests. Update the affected human guide when a public command,
required input or supported workflow changes.

To use Codex as the writer, ask:

> Update this repository's OpenWiki from the current source and tests. Use Codex
> as the main researcher and writer, and preserve the README/docs usage guides.

The installed OpenWiki skill drives `begin → submit_plan → next_page → submit_page
→ finish`. Codex researches and writes assigned pages; OpenWiki persists the queue,
validates Claims/evidence, updates indexes/provenance and finalizes. Use its lifecycle
for generated-page changes instead of editing Claim sidecars, indexes or run state.

Initialization also generates [a GitHub Actions workflow](../.github/workflows/openwiki-update.yml).
That template uses OpenWiki's native OpenAI-provider run and repository secrets;
it is separate from host-driven Codex authoring. It has not been configured or
executed by this documentation task. No commit, push, or remote scheduling activation
is implied by creating the local files.

Return to the [documentation home](README.md) or the [full verification reference](../openwiki/testing/verification-guide.md).
