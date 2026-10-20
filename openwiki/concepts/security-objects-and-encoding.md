---
type: protocol-concept
title: Security objects and canonical encoding
description: Custody object relationships, exact and bounded approvals, envelope commitments, deterministic CBOR, hash domains, and precision-safe amounts and bytes.
tags: [protocol, canonical-encoding, cbor, commitments, domain-types]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:16:28.312Z
sources:
  - id: openwiki-source-1fd8cdd3f0cea446db516a4a
    resource: repo://crates/approval-verifier/src/client.rs
  - id: openwiki-source-43d328a4d551c5a461542c5f
    resource: repo://crates/canonical-encoding/src/de.rs
  - id: openwiki-source-d02d0fb13b8714cd7c12204b
    resource: repo://crates/canonical-encoding/src/lib.rs
  - id: openwiki-source-8b4fdd63669a4b13eb165e4c
    resource: repo://crates/canonical-encoding/src/value.rs
  - id: openwiki-source-3593b39c0b20d85c24b491d9
    resource: repo://crates/domain-types/src/lib.rs
  - id: openwiki-source-c259b1d02c7dacd0d1c62448
    resource: repo://crates/domain-types/src/objects.rs
  - id: openwiki-source-ce0e29c32bf5cfe3162c2e4b
    resource: repo://crates/domain-types/src/primitives.rs
  - id: openwiki-source-5ff1aed094752687edeb7935
    resource: repo://crates/policy-kernel/src/hashing.rs
generated: { by: "codex", at: "2026-10-20T20:16:28.312Z" }
---

# Security objects and canonical encoding

`oic-domain-types` defines the objects shared across builders, approvers, authority, signers, adapters, and audit. `oic-canonical-encoding` turns those objects into deterministic bytes for internal commitments. JSON is a transport and fixture representation; its serializer output does not define the signed security format.

## Object relationships

| Object | Meaning and bindings |
| --- | --- |
| `Vault`, `ChainWallet`, `KeyDescriptor` | Institution/environment/policy scope, chain address and profile, signing scheme, key epoch, backend and participants |
| `Asset` | Network plus concrete native/ERC-20-contract/SPL-mint identity, decimals and behavior profile |
| `CounterpartyDestination` | Versioned network/address, allowed assets, activation and administrative signatures |
| `Intent` | Immutable business request: transfer asset/amount/destination version, wallet/profile, purpose, fee cap and approval mode |
| `Candidate` | One revision of exact native unsigned bytes and declared native signing payloads in an operation family |
| `EvidenceBundle` | Scoped observed state, source identities, trust level, staleness and adapter-defined items |
| `VerifiedOperation` | Adapter-rederived decoded operation, payloads, semantic hash and resource/outflow/fee claims |
| `ApprovalGrant` | Credential-signed body binding intent, policy epoch, time and exact or bounded scope |
| `ApprovalPackage` | Serialized object bundle independently consumed by approvers and signers |
| `AuthorizationEnvelope` | Body commitments plus authority `Reserved` receipt; the `Release` receipt is delivered separately |

The only `IntentOperation` currently implemented is `AssetTransfer`. Additional `NativeResource` variants provide domain vocabulary rather than proving corresponding chain adapters exist. [Implementation boundaries](implementation-boundaries.md) distinguishes that schema surface from runtime support.

## Exact and bounded approvals

An exact grant names candidate id, revision, and `preview_hash`. That preview commits decoded operation and evidence hashes as well as candidate identity, so replacing the evidence or transaction meaning changes the approved preview.

A bounded direct-transfer grant names a `BoundedTransferTemplate`: wallet, network, asset, amount, destination id/version/address, maximum fee, successful-payment allowance, and permitted fillable fields. EVM permits nonce, fee fields, and gas limit; Solana permits a recent blockhash. The adapters still verify every byte and the authority still accounts for possibly live siblings. A template is not a general signing request or an automatic retry exemption.

## Envelope and receipt commitments

The envelope body commits scope, intent hash, family and candidate revision, enrolled profile hash, key/public key/epoch, adapter version/build, policy/allowlist epoch, native bytes and payloads, decoded/evidence/destination hashes, grants, reservation identity/version, resource/asset/fee maxima, issuance deadline, validity constraints, session and participants.

```text
envelope_body_hash = SHA256("OIC/AUTHORIZATION/v1" || canonical_bytes(body))
```

Both authority receipt kinds bind that body hash, signer session, reservation, candidate, policy epoch, time window and commit sequence. Keeping the receipt outside the body avoids a circular commitment; the final release receipt is the separate authorization to expose share-producing output. See [signer boundary](../architecture/signer-boundary.md).

## Canonical profile

The codec accepts integers, byte strings, text, arrays, maps, booleans and null. It rejects floats, tags, indefinite lengths, undefined/unsupported simple values, non-shortest integer encodings, duplicate or unsorted map keys, invalid UTF-8, excessive nesting/items/size and trailing bytes. Map ordering follows bytewise lexicographic order of canonical key encodings. Successful byte-level decode must re-encode identically.

The decoder bounds are `MAX_DEPTH = 64`, `MAX_ITEMS = 65_536`, and `MAX_TOTAL_LEN = 4 MiB`. Typed deserialization rejects unknown struct fields. Enums use Serde's externally tagged representation: unit variants as text and payload variants as a one-entry map, respecting declared Serde names.

`canonical_bytes` serializes through the restricted value model; `from_canonical_bytes` applies byte-level and typed checks. `is_canonical` validates the byte-level value, not whether it is a particular authorized domain object. Hashing a value does not replace semantic validation or schema-version checks at an entrypoint.

## Primitive representations

`Amount(u128)` serializes as a decimal string to preserve exact precision, including in canonical encoding. Calculations expose checked arithmetic; callers must handle overflow or underflow. Display decimals come from registry metadata rather than floating-point calculations.

`Bytes` and `Hash32` are hex strings in human-readable formats and raw byte strings in canonical CBOR. `Hash32` requires exactly 32 bytes. `Bytes::new` and deserialization enforce the 1 MiB bound, but public tuple construction and infallible conversions can bypass that constructor, so external-facing paths still need their own validation and parser bounds.

Opaque identifiers distinguish object categories at the type level. Constructors and deserialization enforce identifier constraints; `unchecked` exists for already validated/internal construction. A typed value is not proof that every cross-reference or cryptographic binding has been verified.

## Hash domains and conformance

`domain_hash(domain, value)` computes SHA-256 over the domain string followed by canonical bytes. Tags in `domains` separate authorization, intent, candidate, evidence, policy, approval, preview, receipt, profile, audit, destination and operational commitments. They are **internal** domains, never replacements for EVM's native Keccak signing digest or Solana's exact message signing.

Policy and destination hashes use explicit unsigned views excluding their signature arrays. Dedicated authority, audit and ledger formats add their own domain/format boundaries. Golden vectors cover these commitments and native payloads; use the [verification guide](../testing/verification-guide.md) before changing a serialized field, enum name, ordering rule or domain tag.

```sh
cargo test -p oic-canonical-encoding --locked
cargo test -p oic-golden-vectors --locked --test conformance
```

Codec tests include a layout vector, strict unknown-field and noncanonical rejection, domain separation, arbitrary-input no-panic behavior and decode/re-encode identity. Continue with [policy evaluation](policy-evaluation.md) and [independent approval](../workflows/independent-approval.md).
