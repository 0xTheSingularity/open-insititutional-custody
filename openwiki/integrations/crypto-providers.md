---
type: integration
title: Development and FROST crypto providers
description: Provider capability and topology contracts, native signature conventions, development single-key and FROST implementations, sealed shares, and one-time state requirements.
tags: [crypto-provider, frost, ed25519, ecdsa, threshold-signatures]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-20T20:16:28.312Z
sources:
  - id: openwiki-source-286c94a0f75504b1aaa359d1
    resource: repo://crates/crypto-provider-dev/src/lib.rs
  - id: openwiki-source-91c570c83e723b849803ebdf
    resource: repo://crates/crypto-provider-dev/src/seal.rs
  - id: openwiki-source-26a25d441f665eb4ea207117
    resource: repo://crates/crypto-provider-dev/tests/dev_provider.rs
  - id: openwiki-source-691bc010a4ada9c113226035
    resource: repo://crates/crypto-provider-frost-ed25519/src/lib.rs
  - id: openwiki-source-ac7ba88c8f7b458fb9ff95f6
    resource: repo://crates/crypto-provider-frost-ed25519/src/seal.rs
  - id: openwiki-source-b15752e5f74ec2287264cede
    resource: repo://crates/crypto-provider-frost-ed25519/tests/frost_provider.rs
  - id: openwiki-source-5a1df9931f309c25fa1422fd
    resource: repo://crates/crypto-provider/src/lib.rs
generated: { by: "codex", at: "2026-10-20T20:16:28.312Z" }
---

# Development and FROST crypto providers

`oic-crypto-provider` separates custody authorization from the selected cryptographic backend. The signer verifies the envelope and controls release; the provider holds its participant's key material, manages protocol sessions, consumes one-time state, and produces native-compatible signatures.

## Capability contract

`BackendDescriptor` declares scheme, upstream version, license, message convention, topology, refresh/recovery support, native compatibility, one-time-state requirement, and the first share-producing round. Absence of a declared capability is not permission to emulate it. `check_topology` distinguishes real threshold signing, all-participant signing, and development single-key operation.

`CryptoProvider` exposes key generation, sealed-share loading, session start, protocol advance, aggregation, and native result verification. Default refresh and recover/replace methods return `UnsupportedCapability`. `PeerMessage` binds session, key/epoch, sender/generation, recipient, round, sequence, protocol version and payload; the surrounding transport must authenticate its claimed sender.

## Implemented backends

| Property | `DevSingleKeyProvider` | `FrostEd25519Provider` |
| --- | --- | --- |
| Security topology | Exactly one-of-one, complete private key in one process | `2 <= threshold <= participants <= 16` |
| Native scheme | Prehashed secp256k1 ECDSA or pure Ed25519 | Pure Ed25519 |
| Message input | ECDSA: exactly 32-byte digest; Ed25519: full message | Full authorized message |
| Output | ECDSA `r || s || recovery_id`, low-s; or 64-byte Ed25519 | Standard 64-byte aggregate Ed25519 signature |
| First share-producing round | 1 | 2 |
| Key generation | Local development key | Per-participant DKG, with explicit development dealer option |
| Restart behavior | Sessions are in memory | Nonces/sessions are in memory; lost sessions are never resumed |

Real native signatures from the development backend do not provide threshold security. Current EVM coordinator tests use that backend. The FROST implementation supplies actual threshold signing for Solana, but its network, recovery, and deployment limits remain separate work.

## Development protocol

`start_signing_session` checks the configured scheme, loaded key, one-participant set and session uniqueness, allocates a ledger record, then returns `Waiting`. Its one protocol message must bind `SHA256(message_or_digest)` under the expected version/session/key/round.

`advance_protocol` serializes the session, consumes the one-time record, signs, and returns `Complete`. A consumption failure yields no signature; later advances cannot sign again. The [signer](../architecture/signer-boundary.md) buffers this round until an authority release receipt exists, exercising the same issuance boundary as a threshold provider.

## FROST key generation and signing

`run_dkg` drives `dkg_part1`, `dkg_part2`, and `dkg_part3` across provider instances. The normal distributed path establishes participant shares and public verification material without constructing the group private key. A single instance's `generate_distributed_key` only permits the explicitly named `dev-trusted-dealer` recovery profile; that dealer sees the full secret and all shares and is development-only.

For signing:

1. Start a session for an enrolled participant subset meeting threshold. Allocate one ledger record, generate fresh in-memory nonces, and emit a round-one commitment.
2. Exchange commitments. `build_signing_package` constructs the round-two package from commitments and the authorized message.
3. Validate package message, exact participant set, own commitment, and any directly received peer commitments. Validate message scope, protocol version, monotonic sender sequence and generation floor.
4. Durably consume the ledger record for `SHA256(message)` **before** producing the round-two share. Failure aborts the session; retry requires fresh session/nonces/record.
5. Aggregate shares with participant verification and verify the final signature independently using strict `ed25519-dalek` verification.

Coordinator substitution is rejected before nonce consumption. A malicious share prevents a signature and identifies the offending participant. A non-cooperating participant can still block its chosen subset; this backend does not promise robust signing or seamless continuation with a different subset.

## Sealed shares and durable state

Both providers use `OICSEAL1 || random 12-byte nonce || ChaCha20-Poly1305 ciphertext/tag`. Associated data is canonical CBOR binding format, backend, key id, key epoch and participant. Replay under a different context fails authentication. Provider sealing keys and decrypted buffers are zeroized on drop.

The ledger stores identity and consumption metadata, not secret nonces. The provider owns nonce material. [Durable state and recovery](../operations/durable-state-and-recovery.md) explains log replay, high-water marks, signer generations, and independent freshness requirements.

## Integration and limits

The coordinator's `FrostEd25519Driver` relays commitments and a signing package; `DevSingleKeyDriver` sends the one payload-hash-bound release message. Signers enforce the release gate independently of driver claims. Adding a backend requires an honest descriptor, native signature compatibility, precise one-time-state semantics, and a driver matching its protocol.

The FROST crate does not provide authenticated broadcast or encrypted point-to-point DKG transport, share refresh, or recover/replace. Its in-process `run_dkg` is not a deployed institution network. Production threshold ECDSA is not integrated in this workspace. See [implementation boundaries](../concepts/implementation-boundaries.md).

```sh
cargo test -p oic-crypto-provider-dev -p oic-crypto-provider-frost-ed25519 --locked
```

Provider tests cover every two-of-three subset, three-of-five DKG, sealed reload, explicit dealer gating, malicious shares, package substitution, replay, failed consumption and stale generations. Differential/native integration continues in the adapter, signer and coordinator suites.
