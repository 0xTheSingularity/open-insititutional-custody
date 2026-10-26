# Design: commit the signer's materials to the envelope

Status: ACCEPTED 2026-10-26 — the user chose "A then B": Option A is
implemented in this change (envelope domain `OIC/AUTHORIZATION/v2` with
`asset_hash`, `wallet_hash`, `vault_hash`, `key_descriptor_hash`, verified by
the signer and the D2 replica execution boundary; golden vectors regenerated
as a justified break). Option B (admin-signed objects) remains a deliberate
later layer. This closes the signer-trust aspect of audit finding `0001-01`
in [`docs/rfc-gap-audit.json`](../rfc-gap-audit.json).

## Problem

RFC 0001 §1.3 says a compromised API or coordinator must not be able to bypass
signer checks, and §2 (I2/I3) requires scope binding over the vault, key, and
asset identity. Today the signer receives `SigningMaterials` from the
coordinator (`crates/signer/src/lib.rs`). Before this change, the verifier
bound only selected fields of those objects to the envelope: key fields are
checked against the envelope and the supplied `KeyDescriptor` must equal the
descriptor the signer loaded; wallet and vault identifiers are checked against
the envelope and the signer's scope. The destination alone got a full-content
commitment (`destination_hash`) plus an admin-signature check. `Asset`,
`ChainWallet`, and `Vault` had no commitment to their complete contents, so
any field outside the identifier checks was trusted from the coordinator.

Consequences a compromised coordinator can reach:

- **Forged wallet.** A fake `ChainWallet { vault_id: operating }` plus an
  intent naming the operating vault lets the treasury key sign under the
  operating vault's rule — possibly a rule requiring zero approvals.
- **Forged asset.** A fake `Asset` maps an `asset_id` to a different ERC-20
  contract or SPL mint, or relabels a non-standard asset as `Standard`;
  limits are then charged to the wrong asset (the A04 scenario).
- `KeyDescriptor` is described as "signed" in §7.3 but has no signature field.

Human approvals do NOT fully close this: `preview_hash` commits only to the
candidate id/revision, the decoded-operation hash, and the evidence hash
(`PreviewCommitment` in `crates/policy-kernel/src/hashing.rs`). A forged
`Asset.behavior` reaches both the approval client and the signer
unauthenticated even under exact-candidate approval, and bounded-transfer
grants do not use `preview_hash` at all. The exposure is therefore not limited
to zero-approval rules, and the commitment checks must hold with or without
grants present.

## Option A — hash-bind the materials in the envelope (recommended)

Extend the envelope with commitments, verified by the signer exactly the way
`destination_hash` is verified today:

- `asset_hash`, `wallet_hash`, `vault_hash`, `key_hash`: the canonical-CBOR
  hash of each supplied object.
- The authority computes these hashes from its enrolled catalog when the
  envelope is created; the signer recomputes each from the materials the
  coordinator supplied and refuses on any mismatch.

Why recommended: it reuses an existing, tested mechanism; the signer needs no
new trust inputs (no admin roster distribution); verification cost is four
hash comparisons; and it covers `KeyDescriptor`, resolving the §7.3 wording.

What it does not do: it does not prove the objects were ever admin-approved —
it proves the signer saw exactly what the authority bound. That matches the
trust model: the authority is the ordering boundary; the coordinator is not.

## Option B — admin-sign the objects

Give `Asset`, `ChainWallet`, `Vault`, and `KeyDescriptor` the
`administrative_signatures` treatment `CounterpartyDestination` has, and have
the signer verify those signatures against its trust roots.

Stronger provenance (end-to-end admin approval, independent of the authority),
but: a larger schema change touching enrollment and provisioning; the signer
must hold and rotate the admin roster; and epochs/supersession for four more
object kinds need defining — the same supersession problem destinations have
(finding `0001-02`) would be inherited by four new objects on day one.

Option B can be layered on later; it does not conflict with Option A.

## Migration plan (applies to either option)

1. Bump the envelope `schema_version`; the signer refuses the old version in
   the same release (fail closed, no dual acceptance window — this is a
   pre-production protocol).
2. Regenerate golden vectors in `tests/golden-vectors` in a dedicated commit
   whose message justifies the compatibility break, per CONTRIBUTING.
3. Extend the A03 test: today it mutates the wallet without rebuilding the
   envelope. Add the forged-but-consistent case — forge each of the asset,
   wallet, vault, and key descriptor in `SigningMaterials` with identifiers
   intact and assert the signer refuses on the envelope commitment, not on
   internal inconsistency. The commitment checks run before grant handling,
   so they hold with or without approvals present.
4. Update RFC 0001 §3.3 (envelope fields) and §7.3 (`KeyDescriptor` wording),
   and mark `0001-01` closed in `docs/rfc-gap-audit.json` with the commit.

## Decision needed

Pick Option A, Option B, or A now with B as a later layer. The recommendation
is **A now**. Blast radius, stated fully: the envelope schema and its domain
tag, every envelope producer (the builder service and the D2 replica
execution boundary, which re-derives the envelope independently), the signer
verifier, every test fixture that constructs an envelope, and the golden
vectors.
