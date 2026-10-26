# Design: commit the signer's materials to the envelope

Status: DRAFT — awaiting a decision. This draft proposes changes to address
audit finding `0001-01` in
[`docs/rfc-gap-audit.json`](../rfc-gap-audit.json), the top-ranked gap from the
2026-10-26 RFC audit. It changes the signed envelope format, so it needs an
explicit decision, a `schema_version` bump, and golden-vector regeneration.
Nothing in this document is implemented.

## Problem

RFC 0001 §1.3 says a compromised API or coordinator must not be able to bypass
signer checks, and §2 (I2/I3) requires scope binding over the vault, key, and
asset identity. Today the signer receives `SigningMaterials` from the
coordinator (`crates/signer/src/lib.rs`), and three of the objects in it carry
no admin signature and no hash commitment: `Asset`, `ChainWallet`, and `Vault`
(`crates/domain-types/src/objects.rs`). Only the destination is protected,
through `destination_hash` in the envelope (`crates/signer/src/verify.rs`).
The signer checks these objects only for internal consistency with the intent.

Consequences a compromised coordinator can reach:

- **Forged wallet.** A fake `ChainWallet { vault_id: operating }` plus an
  intent naming the operating vault lets the treasury key sign under the
  operating vault's rule — possibly a rule requiring zero approvals.
- **Forged asset.** A fake `Asset` maps an `asset_id` to a different ERC-20
  contract or SPL mint, or relabels a non-standard asset as `Standard`;
  limits are then charged to the wrong asset (the A04 scenario).
- `KeyDescriptor` is described as "signed" in §7.3 but has no signature field.

Exact-candidate human approvals bind the whole package through `preview_hash`,
so the practical exposure is rules that require no approvals — but the threat
model does not permit trusting the coordinator either way.

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
   envelope. Add the forged-but-consistent case — rebuild `SigningMaterials`
   wholesale with a forged wallet/asset/vault set and assert the signer
   refuses on the envelope commitment, not on internal inconsistency.
4. Update RFC 0001 §3.3 (envelope fields) and §7.3 (`KeyDescriptor` wording),
   and mark `0001-01` closed in `docs/rfc-gap-audit.json` with the commit.

## Decision needed

Pick Option A, Option B, or A now with B as a later layer. The recommendation
is **A now**; it is one focused change to the envelope plus verifier, with the
blast radius confined to the signing path and the vectors.
