<p>
<picture>
  <source media="(prefers-color-scheme: dark) and (max-width: 640px)" srcset="docs/assets/custody-banner-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="docs/assets/custody-banner-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/custody-banner-dark.svg">
  <img src="docs/assets/custody-banner-light.svg" alt="The Singularity — Open Institutional Custody. Your rules. Before the signature." width="1200">
</picture>
</p>

# Open Institutional Custody

An open-source project by [The Singularity](https://thesingularity.so/).

**Rust components for institutional payment authorization and signing.**

Connect payment approvals and shared spending limits to the exact EVM or Solana
transaction each signer verifies. Approvers review the payment independently.
Signers check the bytes, rules, and receipts before producing signature output.

[Run a transfer](#try-it-locally) · [Follow a payment](docs/payment-flow.md) · [Documentation](docs/README.md) · [Contribute](docs/development.md)

> **Development preview.** Rust libraries and an approval CLI, with real signatures
> and simulated chains. A complete production deployment is still under development.

## 5-minute quickstart

Run the whole custody flow on your own machine — no accounts, no RPC
credentials, no prompts. `oic demo` blocks a theft (a destination swapped after
approval is refused by the independent signer), then settles two transfers:

- **EVM** — a development **single-key** secp256k1 signer (1-of-1, *not*
  threshold).
- **Solana** — a **FROST ed25519 2-of-3** threshold signature.

It ends on the receipt and the signed audit log.

<!-- GIF PLACEHOLDER: recording tools (asciinema+agg / vhs) were not available
     on the build host, so the <=20s demo GIF is not yet committed. Generate it
     with docs/assets/record-demo.sh, then uncomment the <img> below.
<p><img src="docs/assets/oic-demo.gif" alt="oic demo: a theft is blocked, then an EVM single-key and a Solana FROST 2-of-3 transfer settle." width="900"></p>
-->
> **Demo recording pending.** The ≤20s `oic demo` GIF is not yet committed —
> generate it with [`docs/assets/record-demo.sh`](docs/assets/record-demo.sh)
> (needs `asciinema`+`agg` or `vhs`), then embed `docs/assets/oic-demo.gif` here.

### 1. Download, verify, then run (recommended)

The security-minded path: download the installer, read it, let it **verify the
SHA-256 checksum (and the cosign signature) before it runs anything**, then it
runs `oic demo`.

```sh
# Download the installer and read it first
curl -fsSLO https://raw.githubusercontent.com/0xTheSingularity/open-insititutional-custody/main/install.sh

# Run it: downloads the oic binary for your platform, verifies the SHA-256
# (fail-closed on mismatch) and the cosign signature when cosign is installed,
# then runs `oic demo`.
sh ./install.sh
```

Verify the signature yourself, before trusting the binary:

```sh
# For your platform's tarball (e.g. oic-0.1.0-aarch64-apple-darwin.tar.gz),
# download the .sha256, .sha256.sig and .sha256.pem from the GitHub release, then:
cosign verify-blob \
  --certificate   oic-0.1.0-<target>.tar.gz.sha256.pem \
  --signature     oic-0.1.0-<target>.tar.gz.sha256.sig \
  --certificate-identity-regexp '^https://github.com/0xTheSingularity/open-insititutional-custody/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  oic-0.1.0-<target>.tar.gz.sha256
```

### 2. `curl | sh` (convenience fallback)

Faster, but you are piping a remote script into your shell. The installer still
enforces the SHA-256 check before running:

```sh
curl -fsSL https://raw.githubusercontent.com/0xTheSingularity/open-insititutional-custody/main/install.sh | sh
```

### 3. `docker run` (any OS, no toolchain)

The published GHCR image runs `oic demo` as its default command:

```sh
docker run --rm ghcr.io/0xthesingularity/open-insititutional-custody:latest
```

---

Prefer to build from source? Install
[Git, Rust/Cargo, and platform build tools](docs/getting-started.md#prerequisites),
then run the demo straight from the workspace:

```sh
git clone https://github.com/0xTheSingularity/open-insititutional-custody.git
cd open-insititutional-custody
cargo run -p oic-cli -- demo
```

[Try Solana 2-of-3 signing](docs/getting-started.md#run-solana-threshold-signing) · [Start the local HTTP stack](docs/local-stack.md) · [Run the full suite](docs/getting-started.md#run-the-full-suite)

## Every decision has a boundary

<p>
<picture>
  <source media="(prefers-color-scheme: dark) and (max-width: 640px)" srcset="docs/assets/custody-flow-mobile-dark.svg">
  <source media="(max-width: 640px)" srcset="docs/assets/custody-flow-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/custody-flow-dark.svg">
  <img src="docs/assets/custody-flow-light.svg" alt="Authorize: build the transaction, review and approve, reserve shared exposure. Sign: verify at each signer, commit release, produce the signature. Resolve: broadcast and observe, establish chain finality, settle the reservation." width="1200">
</picture>
</p>

- **Review independently.** Approvers decode the proposed payment from native transaction bytes.
- **Reserve shared exposure.** Pending payments count toward the same spending limits.
- **Verify at the signer.** Each signer checks authorization. A recorded release gates signature output.
- **Resolve with evidence.** Uncertain payments retain their reservation until chain evidence resolves them.

Approval, signature issuance, and settlement are separate decisions. The default
D1 authority is a trusted single writer. The experimental D2 profile verifies
quorum-finalized authority blocks and re-executes them before authorizing signing.
Read the [payment walkthrough](docs/payment-flow.md) for responsibilities and failure cases.

## What works today

| Area | Implemented | Boundary |
| --- | --- | --- |
| **EVM** | Native value and registered ERC-20 transfers | Development single-key ECDSA |
| **Solana** | SOL and classic SPL transfers with FROST Ed25519 | Simulator-backed signing; no live-chain client |
| **Signer network** | Roster-admitted Commonware transport, separate signer cores, D1 authority RPC, and fixed-committee D2 Simplex consensus | [Network tests and limits](docs/signer-network.md); no production launcher or committee handoff |
| **Payment controls** | Independent approvals, policy rules, shared exposure, fee limits, and freezes | Off-chain authorization components |
| **Operations** | Durable deposits/backfill, reorg reversals, fee/rent journal, reconciliation, and bounded gas-funding/sweeps | Deterministic chain simulators; no live indexer |
| **Integration** | Vault-scoped HTTP intents, independent grants, crash-safe dispatch, status/evidence, and signed event replay | [Runnable local D1 stack](docs/local-stack.md) with durable simulators; no production launcher |
| **Recovery and audit** | File-backed state, recorded submissions, signed audit events, and checkpoints | Whole-host rollback needs an independent retained checkpoint |

Production threshold ECDSA, live-chain clients, arbitrary contract calls, and a complete
deployment stack need further implementation. The [protocol v1 contract](spec/protocol-v1.md)
documents the executable RFC002 behavior and remaining production gates. See the
[capability details](docs/getting-started.md#current-product-boundary) before integrating.

Exercise both zero-gas token funding/sweep loops and both HTTP approval flows:

```sh
cargo test --locked -p oic-service-reconciler --test money_loop
cargo test --locked -p oic-service-api --test http_flow
```

## Go deeper

| Start here | What you will find |
| --- | --- |
| [Payment walkthrough](docs/payment-flow.md) | One treasury payment, from request to settlement |
| [Core concepts](docs/concepts.md) | Keys, shares, approvals, exposure, and finality |
| [Approval client](docs/approval-client.md) | Review and approve payments with `oic-approve` |
| [Local HTTP stack](docs/local-stack.md) | Bootstrap independent development credentials, send payments, and restart the same stores |
| [Signer network](docs/signer-network.md) | D1 signing, D2 consensus, embedding contracts, and remaining RFC003 work |
| [Development](docs/development.md) | Workspace map, focused tests, protocol vectors, and bounded state exploration |
| [Documentation index](docs/README.md) | Subsystem references and design RFCs |

## Contribute

Start with the [development guide](docs/development.md). For setup problems, use
[troubleshooting](docs/getting-started.md#troubleshooting). For a question or bug,
[open an issue](https://github.com/0xTheSingularity/open-insititutional-custody/issues)
with the commit, command, toolchain, expected result, and error output.
Keep keys, shares, passphrases, and secret files out of reports.

Package metadata declares [Apache-2.0](Cargo.toml).
