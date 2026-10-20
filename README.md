<h1 align="center" id="open-institutional-custody">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/custody-banner-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/custody-banner-light.svg">
    <img src="docs/assets/custody-banner-light.svg" alt="Open Institutional Custody: approved scope, budget reservation, transaction verification, and a release receipt precede a native signature." width="1600" height="400">
  </picture>
</h1>

<p align="center">
  <strong>Control who can approve a payment, what the wallet can sign,<br>and how much it can spend.</strong>
</p>

<p align="center">
  <a href="#try-it-locally"><strong>Run a transfer</strong></a> ·
  <a href="docs/payment-flow.md">Understand the flow</a> ·
  <a href="docs/README.md">Documentation</a> ·
  <a href="#troubleshooting-and-help">Get help</a>
</p>

---

Open Institutional Custody is a Rust toolkit for organizational wallets. It checks
payment rules before EVM or Solana transfers, coordinates signing, and tracks chain outcomes.
Approvals, shared spending limits, and signer verification connect a treasury's
decisions to the actual transaction bytes.

> [!NOTE]
> **Current stage: Rust libraries and an approval CLI, with local integration demos.**
> The demos use simulated chains. A complete production deployment is still under development.

## Try it locally

No funds or RPC account is required. Install
[Git, Rust/Cargo, and platform build tools](docs/getting-started.md#prerequisites), then run:

```sh
git clone https://github.com/0xTheSingularity/oss-wallet-insitutional.git
cd oss-wallet-insitutional
cargo test -p oic-service-coordinator --locked --test coordinator \
  evm_erc20_end_to_end_signs_and_mines_in_the_simulator -- --exact
```

This test approves, signs, and mines an ERC-20 transfer locally. Expected result:
**1 passed, 0 failed**.

[Solana demo](docs/getting-started.md#run-solana-threshold-signing) · [Full test suite](docs/getting-started.md#run-the-full-suite) · [Setup help](docs/getting-started.md#troubleshooting)

## How a payment works

**Request → approve → reserve budget → verify → sign → observe → settle**

Each signer verifies the transaction independently. Shared reservations account for
pending payments before signatures leave the system. Approval, signing, and chain
settlement are separate decisions.

Follow [one treasury payment](docs/payment-flow.md) for the diagram, component
responsibilities, and failure cases. The [concepts guide](docs/concepts.md) explains
the vocabulary from first principles.

## What works today

| Area | Supported path |
| --- | --- |
| EVM | Native transfers and registered ERC-20 `transfer` calls, using a development single-key signer. |
| Solana | SOL and classic SPL token transfers, with FROST threshold Ed25519 signing. |
| Payment controls | Independent approvals, policy rules, shared exposure, resource reservations, fee limits, and freezes. |

These are off-chain custody components. Arbitrary contract calls, production
threshold ECDSA, and authenticated signer networking need additional implementation.
See the [capability details](docs/getting-started.md#current-product-boundary) before integrating.

## Documentation

If you have written one smart contract, start with the payment walkthrough.

| You want to… | Read |
| --- | --- |
| Understand custody | [Payment walkthrough](docs/payment-flow.md) → [Core concepts](docs/concepts.md) |
| Run demos and fix setup | [Getting started](docs/getting-started.md) |
| Review and approve payments | [Approval client](docs/approval-client.md) |
| Integrate, test, or contribute | [Development](docs/development.md) |
| Inspect a subsystem | [OpenWiki reference](openwiki/quickstart.md) |

The [documentation home](docs/README.md) also maps subsystem references and design RFCs.

## Troubleshooting and help

Use the [setup troubleshooting table](docs/getting-started.md#troubleshooting) for
build, approval-input, and uncertain-payment problems. To ask a question or report
a bug, [open an issue](https://github.com/0xTheSingularity/oss-wallet-insitutional/issues)
with the commit, command, toolchain, expected result, and error output.
Keep keys, shares, passphrases, and secret files out of reports.

For contributions, start with the [workspace map and verification commands](docs/development.md).
Package metadata declares Apache-2.0.
