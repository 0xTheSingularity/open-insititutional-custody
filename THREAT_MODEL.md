# Threat Model

> **Status: development preview.** This document describes the custody protocol
> as it exists in this repository today. It is honest about what is enforced in
> code and what is not yet built. Where a property is enforced, a `file:line`
> citation points at the exact check. Where something is not yet implemented, it
> is listed in [Known limitations](#known-limitations--not-yet-production).
>
> Every security claim below was read against the source at the cited location.
> If you find a claim that the code does not support, that is itself a finding —
> please report it (see [SECURITY.md](SECURITY.md)).

## System model

Open Institutional Custody turns a payment intent into a native EVM or Solana
transaction only after independent parties have verified the *exact bytes* and
the *exact rules* that govern them. A coordinator proposes a transfer; a policy
kernel decides whether the rules permit it; an independent approver re-derives
the operation from the candidate transaction bytes and signs an approval grant
for only what it verified; a signer re-checks every referenced object and the
approval grants before it produces a signature. No approval, no signature.

The core property is **"your rules, before the signature."** Approval, signature
issuance, and settlement are separate decisions made by separate components, and
each one re-derives what it is about to authorize from first principles rather
than trusting an upstream component's summary. A compromised or buggy
coordinator cannot make an approver or signer act on anything the approver or
signer did not independently reconstruct and check.

## Trust boundaries and actors

| Actor | Role | Trusted for | NOT trusted for |
| --- | --- | --- | --- |
| **Console / coordinator** | Proposes intents, assembles candidate transactions, routes messages, serves the HTTP API. In the repo this is the `oic` CLI (`cli/oic`), the local-stack API service, and the sample Next.js console (`apps/console`). | Liveness, convenience, display. | Correctness of the operation, the destination, the amount, or the rules. Everything it asserts is re-derived downstream. |
| **Independent approver** | Human-operated verifier (`crates/approval-verifier`) that decodes the candidate from bytes, compares it to the registry, and signs an approval grant only for what it verified. | Holding one approval credential; refusing to sign on any mismatch. | Being the only check — the signer re-verifies the grant and all objects again. |
| **Signer / D1 authority** | Holds key shares, re-verifies the authorization envelope end-to-end, records a one-time-state release, and produces the signature (`crates/signer`). The D1 authority is a **trusted single writer** for shared authorization state (README.md:122-124). | Producing a signature only after full re-verification; gating it on recorded release state. | A production-grade threshold EVM backend (not yet integrated — see limitations). |
| **Policy kernel** | Pure decision function (`crates/policy-kernel`) that binds policy, intent, vault, asset, destination, and evidence to one security domain and epoch, and bounds evidence trust by environment. | Deterministic allow/deny over supplied objects. | Fetching objects or evidence itself; it decides over what it is given. |
| **Chain simulators** | Deterministic in-process EVM/Solana simulators (`crates/chain-simulator`) standing in for real chains in the dev preview. | Deterministic, repeatable test evidence. | Being real chains. They are test fixtures, not an attack target (see out of scope). |

## Assets

1. **Key shares / signing keys** — the material that can move funds. Dev EVM is a
   single secp256k1 key; Solana is a FROST ed25519 threshold key (shares).
2. **Approval authority** — the approver credential and the grants it signs; the
   admin-quorum keys that sign policies and destination-registry entries.
3. **Funds** — the on-chain value a signature would move.
4. **Audit-log integrity** — the signed, hash-linked record of what was
   authorized, so an operator cannot silently rewrite history.

## Threats and mitigations

Each row states what an attacker tries to do and the exact check that stops it.

### T1 — A compromised coordinator / console substitutes the destination address

**Attack.** The coordinator assembles the candidate transaction. A malicious or
buggy coordinator encodes a transfer to an attacker's address while presenting a
legitimate-looking destination id/label to approvers.

**Mitigation.** The destination is an admin-quorum-signed registry object, and
the authorization envelope commits to its hash. The signer re-checks
`destination_hash(d)? == b.destination_hash` and the destination's admin-quorum
signatures before signing (`crates/signer/src/verify.rs:241-242`; the in-code
comment at `:235-239` ties this to RFC 0001 §3.3). The independent approver
decodes the recipient from the candidate *bytes* and sets
`destination_matches_registry` from `decoded.recipient() == &destination.address`
(`crates/approval-verifier/src/client.rs:150`); if it does not match, `approve`
refuses to sign: `"decoded recipient does not match the registry destination;
refusing to sign"` (`crates/approval-verifier/src/client.rs:313-315`). An
*unsigned* destination record is not a registry entry however plausible its label
(`crates/approval-verifier/src/client.rs:102-106`).

### T2 — Destination (or amount) changed *after* approval

**Attack.** An approval grant exists for a legitimate payment; the coordinator
then swaps the destination or amount before the signer runs, hoping the earlier
approval still applies.

**Mitigation.** An approval grant is bound to the exact candidate (an
`ExactCandidate` scope commits to `candidate_id`, `candidate_revision`, and
`preview_hash` — `crates/approval-verifier/src/client.rs:319-323`) or to a bounded
transfer template. The signer re-derives the operation from the candidate bytes
and re-checks the destination hash (T1), so a post-approval change breaks the
binding. The `oic demo` proves this at runtime: it clones an already-approved
package, changes `amount_base_units` by one unit, and asks the verifier to sign
the tampered package against the display it genuinely rendered; `approve` returns
an error and **no signature is produced** — the demo treats a success here as a
`"SECURITY REGRESSION"` (`cli/oic/src/main.rs:555-582`). The refusal comes from
re-deriving the display/operation from the tampered bytes and seeing it differ
from what was confirmed (`crates/approval-verifier/src/client.rs:307-315`,
`:160-163`). *(See caveat in [Known limitations](#known-limitations--not-yet-production)
on the exact error variant.)*

### T3 — Forged, replayed, or wrong-scope approval grant

**Attack.** An attacker presents a grant that was never signed by an enrolled
approver, a grant for a different intent/vault/policy, or re-uses a past grant.

**Mitigation.** The signer verifies each grant's signature against enrolled
approvers (`crates/signer/src/verify.rs:246`) and rejects any grant not bound to
this exact intent, intent-hash, vault, policy, policy-epoch, institution, and
environment (`crates/signer/src/verify.rs:247-256`). Approval grants carry an
explicit expiry (`expires_at`, set from a required positive TTL —
`crates/approval-verifier/src/client.rs:303-306,339`). Signing replay is further
bounded by a one-time-state ledger consumed before a signature is produced (the
FROST backend binds and durably consumes a one-time record keyed to
`SHA-256(message)` before `round2::sign` — `crates/crypto-provider-frost-ed25519/src/lib.rs:27-29`).

### T4 — A development single-key backend masquerades as a threshold

**Attack.** The dev EVM backend holds a single key (no threshold security). An
attacker or a misconfiguration tries to present it as, e.g., a 2-of-3 so it looks
production-grade.

**Mitigation.** The dev backend self-declares
`ThresholdTopology::SingleKeyDevelopmentOnly`
(`crates/crypto-provider-dev/src/lib.rs:259`). `check_topology` refuses to accept
that topology as anything but 1-of-1 and returns an error naming it
`"single-key development-only; it provides no threshold security and cannot be
exposed as {threshold}-of-{n}"` (`crates/crypto-provider/src/lib.rs:271-279`). The
signer calls `check_topology` before loading any key share / keygen
(`crates/signer/src/lib.rs:393`).

### T5 — Development-simulator evidence is trusted on a real network

**Attack.** Evidence produced by the in-process simulator (the lowest trust
level) is submitted for a payment on `mainnet` or another non-dev environment.

**Mitigation.** The kernel bounds evidence trust by environment in
`trust_sufficient` (`crates/policy-kernel/src/lib.rs:227-233`):
`DevelopmentSimulator` evidence is accepted **only** when the environment string
is exactly `"dev"` (`:231`); a single un-cross-checked `SingleProvider` is
accepted everywhere **except** `mainnet` (`:230`); `ValidatingNode` and
`TrustedProviderCrossChecked` are accepted everywhere (`:229`). Environments are
first-class: keys and policies never cross them. `EnvironmentId` is an opaque
string newtype (`crates/domain-types/src/ids.rs:15-60,63`, doc: *"Keys and
policies never cross environments (I8)"*), and the kernel's binding stage emits
`EnvironmentMismatch` if policy, intent, and vault do not all share one
environment (`crates/policy-kernel/src/lib.rs:211-213`). The local-stack hard-codes
its environment to `dev` (`services/local-stack/src/provision.rs:15-18`), the only
environment where simulator evidence is accepted.

### T6 — Audit-log tampering by the operator

**Attack.** The party that runs the service rewrites or truncates the operations
journal to hide an unauthorized payment.

**Mitigation.** The exported operations journal (`OperationsExport`,
`services/reconciler/src/store.rs:49`) is both hash-linked and Ed25519-signed. Its
`verify` method re-checks that each entry links to the previous entry hash and
re-hashes to its stored `entry_hash` (`services/reconciler/src/store.rs:82-93`),
that every webhook event's service signature verifies
(`:102-105`), and that every reconciliation checkpoint's signature and
journal-head commitment verify (`:109-120`); signatures are Ed25519 checked with
`verify_strict` (`services/reconciler/src/store.rs:135-148`). Hash chaining alone
does not stop an operator from rewriting history, so independently held,
service-signed checkpoints are the real defense — this is the stated design of
the audit crate (`crates/audit/src/lib.rs:6-13`). The `oic demo` fetches the
export and verifies its signature against the catalog's event verifying key before
printing it (`cli/oic/src/main.rs:600-628`).

### T7 — Cross-institution / cross-domain object confusion

**Attack.** Objects from one institution, vault, or policy are mixed into another
to bypass rules.

**Mitigation.** The kernel's binding stage (`check_binding`) rejects any
mismatch between policy/intent/vault on institution, environment, vault id, and
policy id, and verifies the policy and intent hashes and epoch
(`crates/policy-kernel/src/lib.rs:191-221`). The independent verifier runs the
same cross-reference checks across policy, vault, wallet, key, candidate, asset,
and destination before rendering (`crates/approval-verifier/src/client.rs:108-122`).

## Known limitations / not yet production

This is a **development preview** (README.md:22-23;
`docs/designs/five-minute-self-host-quickstart.md:51`). Do not place real funds at
risk against this code.

- **No production ECDSA signing backend for EVM.** The EVM path uses a
  development single-key secp256k1 backend
  (`services/local-stack/src/provision.rs:195-196`); it is 1-of-1 and provides no
  threshold security. The pinned production ECDSA candidate, `cggmp24`
  (LFDT-Lockness), is **not integrated** (`handoff.md:58`;
  `docs/getting-started.md:132`). Solana's FROST ed25519 2-of-3 threshold path
  (`services/local-stack/src/provision.rs:179,210-212`;
  `crates/crypto-provider-frost-ed25519/src/lib.rs:4,13,551`) is real threshold
  signing, but is exercised against simulators, not a live chain.
- **Chains are deterministic simulators, not real networks**
  (`crates/chain-simulator`). There is no live-chain client or indexer
  (README.md:132,135).
- **Single-process, co-resident signers in the local stack / demo.** The `oic
  demo` and local stack run the signer cores, approver, and coordinator in one
  process (the CLI wraps the in-process `services/local-stack` library — design
  doc `docs/designs/five-minute-self-host-quickstart.md:139`). The separate-process
  signer network exists but has no production launcher or committee handoff
  (README.md:133; `docs/signer-network.md`).
- **Exact theft-block error variant not pinned in this document.** We confirmed
  that `verifier.approve` on a tampered package returns an `Err` and produces no
  signature, and that the demo fails loudly on any success
  (`cli/oic/src/main.rs:555-582`). We did not trace, end-to-end through the EVM
  adapter, which specific `ErrorCode` variant is returned (the re-derivation path
  can surface `UnverifiableTransaction` at
  `crates/approval-verifier/src/client.rs:160-163` or the display-mismatch guard at
  `:310-312`); the demo prints the actual code at runtime
  (`cli/oic/src/main.rs:594`). The *guarantee* — no signature on a mismatch — is
  what is enforced and tested.
- **D1 authority is a trusted single writer.** The experimental D2 profile
  verifies quorum-finalized authority blocks, but production consensus/launcher
  work is incomplete (README.md:122-124,133).

## Out of scope

The following are **not** considered reportable vulnerabilities against this
preview:

- The deterministic chain simulators (`crates/chain-simulator`) as an attack
  target. They are test doubles, not a production chain; bugs in simulator
  realism are feature gaps, not security findings.
- Denial of service, resource exhaustion, and traffic-volume attacks.
- The sample console application (`apps/console`) as a product surface. It is a
  demonstration UI; its correctness relies on the downstream re-verification
  described above, not on the console itself.
- Anything that requires compromising the operator's host, stealing an
  already-exported key share, or a privileged local user — i.e., attacks that
  assume the trust boundary has already been breached by other means.
- Issues that only manifest when the software is run outside the `dev`
  environment it currently targets (production deployment is not yet supported).

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.
