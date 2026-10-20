---
type: workflow
title: Independent approval workflow
description: Verify and display an approval package independently, pin trust roots, generate protected approver credentials, sign exact or bounded grants, and inspect envelope bindings with the local CLI.
tags: [approval, cli, verification, credentials, display]
sources:
  - id: openwiki-source-3e07a24493723baddccec72b
    resource: repo://apps/independent-approval-client/src/commands.rs
  - id: openwiki-source-fae15ed03c8fc392e1cc0f36
    resource: repo://apps/independent-approval-client/src/keyfile.rs
  - id: openwiki-source-92a83847ba57ab8ab9dca4d5
    resource: repo://apps/independent-approval-client/src/lib.rs
  - id: openwiki-source-d8c6df206fe2a2bd0435a38f
    resource: repo://apps/independent-approval-client/src/main.rs
  - id: openwiki-source-04315589794678311270f065
    resource: repo://apps/independent-approval-client/tests/approval_client.rs
  - id: openwiki-source-696182ea5ebbbeff3f375730
    resource: repo://crates/adapter-api/src/lib.rs
  - id: openwiki-source-1fd8cdd3f0cea446db516a4a
    resource: repo://crates/approval-verifier/src/client.rs
  - id: openwiki-source-6b420f5377c0c8f7175c24da
    resource: repo://crates/approval-verifier/src/grants.rs
  - id: openwiki-source-32fee8b5f4857b2429c56512
    resource: repo://crates/policy-kernel/src/lib.rs
  - id: openwiki-source-dafac7c46dcd9494f03343cb
    resource: repo://crates/signer/src/verify.rs
generated: { by: "codex", at: "2026-10-20T20:39:06.439Z" }
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:39:06.439Z
---

# Independent approval workflow

`oic-approval-verifier::IndependentVerifier` reconstructs transaction meaning from an `ApprovalPackage`; `oic-approval-client` exposes it as `oic-approve`. The client approves business meaning, not a chain transaction signature, and never holds MPC key shares.

For a shorter operator walkthrough and input-file checklist, start with the [human approval client guide](../../docs/approval-client.md).

## What is independently checked

The verifier authenticates administrative policy and destination quorums, checks cross-references, finds an enrolled chain profile and pinned adapter, binds evidence by hash, derives wallet address from the key, and decodes native bytes. Registry labels and an editable destination display string cannot override the decoded recipient.

It derives preview/intent/semantic commitments and, in bounded mode, the permitted direct-transfer template. The card shows scope, network and concrete asset identity, full sender/recipient, registry destination/version, amount in base units and registry decimals, maximum native fee, purpose/policy epoch, evidence age and warnings. Terminal text is sanitized to prevent untrusted control/bidi text rewriting what is shown.

Rendering can expose a destination mismatch or stale evidence to explain refusal. The CLI's `approvable` checks reject wrong beneficiary and future/stale evidence before signing. Adapter checks enforce the profile's accepted evidence trust levels; the policy kernel and signers separately enforce environment-specific trust restrictions. The core `approve` re-renders from current inputs, requires agreement with the confirmed display (allowing evidence age to advance), and signs only the corresponding exact preview or bounded template.

## Build and command discovery

```sh
cargo build -p oic-approval-client --locked
./target/debug/oic-approve --help
./target/debug/oic-approve approve --help
```

All examples below run from the repository root after building. They require operator-supplied enrolled profile and public administrator keys, plus an actual package exported from the builder. Test fixtures in [`tests/common/mod.rs`](../../apps/independent-approval-client/tests/common/mod.rs) demonstrate construction; no production enrollment or package service is shipped.

## Trust and credential setup

```sh
./target/debug/oic-approve init-trust \
  --out /tmp/oic-trust.json \
  --admin-key "admin-a=<ED25519_PUBLIC_KEY_HEX>" \
  --admin-key "admin-b=<ED25519_PUBLIC_KEY_HEX>" \
  --admin-quorum 2 --profile /path/to/enrolled-profile.json
```

Replace angle-bracket values with independently enrolled **public** keys. `init-trust` pins the adapters compiled into this binary; loading roots with foreign build hashes is refused. Trust files are not obtained from an untrusted coordinator as authority to broaden approvals.

Provide a passphrase of at least 12 bytes in an environment variable through an operator-controlled secret mechanism, then run:

```sh
./target/debug/oic-approve keygen \
  --out /path/to/approver.key.json --credential-id treasury-1 \
  --role treasury_approver --passphrase-env OIC_APPROVER_PASSPHRASE
```

The generated Ed25519 credential uses PBKDF2-HMAC-SHA256 (default/minimum 600,000 iterations) and ChaCha20-Poly1305. Header fields are associated data; tampering or a wrong passphrase refuses decryption. New credential files are mode `0600`. Public credential id/key/role must separately be enrolled in the approver roster used by the builder and signers; local key creation does not enroll it.

## Review, approve, verify

```sh
./target/debug/oic-approve show \
  --trust /tmp/oic-trust.json --package /path/to/package.json

./target/debug/oic-approve approve \
  --trust /tmp/oic-trust.json --package /path/to/package.json \
  --key /path/to/approver.key.json --passphrase-env OIC_APPROVER_PASSPHRASE \
  --grant-id grant-1 --ttl-seconds 300 --out /path/to/grant.json

./target/debug/oic-approve verify-grant \
  --trust /tmp/oic-trust.json --package /path/to/package.json \
  --grant /path/to/grant.json \
  --approver "treasury-1=<ED25519_PUBLIC_KEY_HEX>=treasury_approver"
```

`approve` prints the independently computed card and requires `y`/`yes` by default. `--yes` explicitly bypasses interactive confirmation but preserves verification. A positive TTL is required, expiry arithmetic is checked, and existing output files are not overwritten. Failed verification, wrong passphrase or declined confirmation writes no grant.

Exact mode binds candidate id/revision/preview hash. Bounded mode binds fixed wallet/network/asset/amount/destination/version/address/fee ceiling and adapter-permitted fillable fields. Deliver the grant to the builder/coordinator; creating it neither reserves a budget nor broadcasts a payment. `verify_grants` rejects the whole set if any signature/role/time check fails, and returns distinct enrolled credentials for successful verification.

`--now <unix-seconds>` is available for reproducible fixture inspection; absent it, the CLI uses its system clock. Choosing a historical time for a test is not a way to revive a stale production approval.

## Inspecting an envelope

```sh
./target/debug/oic-approve inspect-envelope \
  --trust /tmp/oic-trust.json --package /path/to/package.json \
  --envelope /path/to/envelope.json
```

This recomputes the envelope body hash and reports field-by-field package bindings and mismatches. It explicitly does not verify the authority receipt signature because the authority key is not an approval-client trust root. Every signer performs that check along with its release and one-time-state checks; global exposure belongs to the authority. See [signer boundary](../architecture/signer-boundary.md).

| Exit | Meaning |
| --- | --- |
| 0 | Command succeeded |
| 2 | Usage or argument error |
| 3 | Verification/freshness/confirmation refused |
| 4 | Decoded destination differs from registry |
| 5 | File read/parse/write failure |

`cargo test -p oic-approval-verifier -p oic-approval-client --locked` covers compromised-console address text, wrong native recipient, missing quorum, stale evidence, pinned roots, protected key files, wrong passphrase, confirmation, exact/bounded grants, envelope mismatch reporting and executable CLI flows. Continue with [build and coordination](build-and-coordinate.md) or [security objects](../concepts/security-objects-and-encoding.md).
