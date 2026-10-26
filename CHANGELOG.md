# Changelog

User-facing changes per release. Unreleased work is on `main`.
Release artifacts, checksums, signatures, and provenance attestations are on
the [GitHub releases page](https://github.com/0xTheSingularity/open-insititutional-custody/releases).

## Unreleased

**Compatibility break.** The authorization envelope moved to
`OIC/AUTHORIZATION/v2`: it now commits to the enrolled asset, wallet, vault,
and key descriptor by hash, and signers verify those commitments (see
`docs/designs/signing-material-commitment.md`). This fails closed with no
transition window: post-change software refuses v1 envelopes and v0.1.4 and
earlier refuse v2. Do not mix v0.1.4 components with later ones; a local
stack rebuilt from one checkout stays consistent. Golden vectors were
regenerated for v2.

- Authorization-state hardening: pre-freeze-epoch snapshots migrate on load,
  releases are refused across a freeze-epoch change, and stale v1 reservations
  recover by abort only.
- Signers verify what the D1 authority charged; the replicated authority
  rejects proposals for unregistered intent bodies.
- Local-stack and approval-client errors now state the fix: an unprovisioned
  state directory names the bootstrap recovery path, and stale-evidence
  refusals say to create a new intent inside the evidence window.
- `scripts/local-stack/bootstrap.sh` and `approve.sh` use
  `OIC_LOCAL_APPROVAL_PASSPHRASE` from the environment when set, so approval
  can run without typing inside the evidence window.

## v0.1.3 — 2026-10-22

- Hardened the release supply chain after independent review findings.
- Mirrored `docs/` and `openwiki/` into the GitHub wiki.

## v0.1.2 — 2026-10-22

- Added the `custody-check` GitHub Action and release build provenance
  ([SLSA](https://slsa.dev) attestations on tarballs and the `oic` binary).
- Added `oic demo --check`: a CI mode with its own regression exit code.
- Versioned only the `oic` CLI, not the workspace.

## v0.1.1 — 2026-10-22

- Added a GitHub Codespaces one-click devcontainer for `oic demo`.
- Built the Intel macOS release target on a macos-14 runner.
- Security posture: installer verifies SHA-256 fail-closed and the cosign
  signature when cosign is installed.

## v0.1.0 — 2026-10-21

- First tagged release: `oic demo` runs the full custody flow end-to-end
  against local simulators — an EVM single-key transfer, a Solana FROST
  2-of-3 transfer, a blocked theft, and a signed audit log.
