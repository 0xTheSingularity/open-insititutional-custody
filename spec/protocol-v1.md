# OIC protocol v1 — development interoperability contract

Reference for implementers of authorization producers, independent approval
clients, signers, and direct-transfer integrations. Run the conformance and money
loop tests with a Rust toolchain and the dependencies in `Cargo.lock`:

```sh
cargo test --locked -p oic-golden-vectors
cargo test --locked -p oic-service-api -p oic-service-reconciler
```

This contract describes executable development behavior, not production approval.
RFC002 Gate B is exercised against deterministic EVM/Solana simulators. Live RPC
integration, independently operated signer domains, production threshold ECDSA,
installation/recovery qualification, independent security review, and pilot
operating approval remain separate gates. RFC003 defines the network deployment.

## 1. Versions and sources of truth

Security objects live in `crates/domain-types/src/{objects,operations}.rs`.
`schema_version = 1` is accepted for HTTP intents. Hash domains end in `/v1`;
they are protocol constants, not negotiated from an HTTP header. Participants
must pin compatible adapters, verifier build hashes, profiles, backend descriptors,
policy epochs, key epochs, and signer generations. An unknown version, unsupported
operation, or mismatched commitment fails closed.

JSON Schemas in `tests/golden-vectors/schemas/protocol-v1.json` describe the
producer representation of `Intent`, `ApprovalGrantBody`, `ApprovalGrant`,
`LifecycleEventBody`, and `LifecycleEvent`. They do not replace signature checks,
catalog enrollment, u128 parsing, native-message decoding, or policy evaluation.
[The OpenAPI 3.1 contract](../services/api/openapi.json) names every HTTP route,
capability, mutation/retry contract, and these shared schemas. Complex evidence
responses retain their typed Rust and canonical-CBOR contracts and are opaque
objects in OpenAPI; this is not complete generated-SDK coverage.

## 2. Native cryptography and topology

| Profile | Executable backend | Issuance-enabling output | Limits |
|---|---|---|---|
| EVM development | `oic-crypto-provider-dev`, `k256` secp256k1 ECDSA | Complete signature, low-s `r \|\| s \|\| recovery_id` (65 bytes), over the adapter's Keccak-256 digest | Exactly 1-of-1; **no threshold security** |
| Solana development | `oic-crypto-provider-frost-ed25519`, FROST(Ed25519, SHA-512), pure Ed25519 output | FROST round-2 signature share | 2-of-3 acceptance tests; any permitted threshold subset; standard 64-byte Ed25519 signature |

`Cargo.lock` freezes registry versions and source checksums. The FROST provider's
`PINNED_VERSIONS` declares `frost-ed25519=2.2.0`, `frost-core=2.2.0`,
`ed25519-dalek=2.2.0`, and `chacha20poly1305=0.10.1`. Its wire protocol is
`frost-ed25519/2`; backend identity and commit/version strings are in the key
descriptor and authorization envelope. Changing a dependency requires rerunning
the native/differential and crash/rollback suites, not silently retaining a
previous build's measurement. Workspace code is Apache-2.0; dependency licensing
is recorded by the pinned upstream packages. No independent review of this
composition is asserted.

FROST DKG has separate per-participant phases. The current `run_dkg` harness
exchanges them in-process; it is not a production ceremony. The trusted-dealer
profile is explicitly development-only. Shares are sealed with ChaCha20-Poly1305;
session nonces remain in memory. A crashed session is abandoned, never resumed.
The one-time-state ledger consumes its record, bound to the payload hash, before
share production. Neither share refresh nor lost-share recovery is implemented;
supported surviving subsets can sign, otherwise key replacement and asset
migration are required. Commonware consensus signatures are not custody shares.

## 3. Canonical bytes

The signed format is `oic-canonical-encoding`, not REST JSON. It is a restricted
deterministic CBOR profile:

- Definite-length integers, byte strings, UTF-8 strings, arrays, maps, booleans,
  and null only. Use shortest integer/length arguments. Negative integers are
  limited to the codec's signed range. No tags, floats, indefinite lengths,
  undefined, duplicate keys, or trailing bytes.
- Sort map keys lexicographically by their **complete canonical CBOR encodings**,
  including the type/length prefix. This is not JSON key order or string-only
  lexical order. Struct fields are maps keyed by their exact serialized names.
- Unit enums are text. Payload enums are one-entry maps `{variant: payload}`.
  Arrays retain order; do not sort participant sets, grants, rules, or other
  lists unless their producer explicitly does so.
- `Amount(u128)` is canonical decimal **text**, including in CBOR: `0` or a
  nonzero leading digit followed by digits, no sign/leading zeros, maximum
  340282366920938463463374607431768211455. Arithmetic is checked.
- `Bytes` and `Hash32` are raw CBOR byte strings. JSON producers emit lowercase
  hex: `Bytes` has a `0x` prefix; `Hash32` has none and contains 32 bytes.
  JSON readers also accept supported hex prefixes/case. Time and epochs are unsigned integer seconds/counters,
  not floating point or formatted dates. Preserve u64 precision in clients.
- An absent optional value is represented by null when the struct serializes
  it; do not omit it from a signed preimage. Typed canonical decoding rejects
  unknown fields. REST JSON parsing is distinct; intent create rejects unknown
  top-level fields with HTTP 400, and other routes may normalize ignored
  fields. Always sign the reconstructed typed object's canonical bytes.
- Decoder bounds: depth 64, 65,536 collection items, total input 4 MiB; individual
  `Bytes` values are bounded to 1 MiB. HTTP request bodies are bounded to 1 MiB.
  Identifier constructors accept 1–128 ASCII graphic bytes. The transparent
  serde identifier wrappers are not themselves an enrollment validator.

The encoder and strict decoder must round-trip accepted bytes identically.
Cross-language clients must compare with committed vectors before signing.

## 4. Hashes and signatures

`domain_hash(tag, object) = SHA256(UTF8(tag) || CanonicalEncode(object))`, with
no separator, length prefix, or terminating NUL beyond the literal tag. Raw
byte commitments use SHA-256 directly where the typed producer specifies it.
Every domain in `crates/domain-types/src/domains.rs`, plus authority/audit local
domains, has committed vectors naming its real producer and encoded type.

Use those producers: `policy_hash` and `destination_hash` exclude their own
administrative signature arrays; audit and checkpoint producers also have
explicit signed views. Hashing the entire JSON object is not equivalent.
`grant_signing_hash` signs the grant body under `OIC/APPROVAL/v1`; the envelope
body uses `OIC/AUTHORIZATION/v1`; journal entries use `OIC/JOURNAL/v1`; event
bodies use `OIC/WEBHOOK/v1`. Credential/service signatures are strict Ed25519
over the 32-byte hash, not Ed25519ph. Native transaction signatures use the
adapter's own chain signing preimage, not these service hashes.

## 5. Policy, approvals, and time

The policy kernel is pure. Time and exposure enter as authenticated inputs;
there is no system-clock read inside evaluation. Configuration/hash/epoch
mismatches and hard asset/destination denials precede allow rules. Rules are
ordered; the first matching rule applies. Roles and distinct credential counts,
proposer exclusion, amount/fee ceilings, operating windows, and rolling limits
are enforced before an `Allow` can reserve authority. Automated rules explicitly
allow the `automated` role; zero approvals alone does not enable automation.

Grant validity is `[issued_at, expires_at)`. Exact grants bind candidate ID,
revision, and preview hash. Bounded grants bind the verified direct-transfer
template and permitted fillable fields; they are not arbitrary transaction
permissions. Signature/role verification uses the enrolled approver roster.
An API bearer capability is not an approval grant. Stored approval material is
re-evaluated at submission, reservation, release, and at honest signers.

Operating windows are UTC seconds-of-day, half-open, with explicit overnight
handling. Rolling settled outflows are included strictly after the lower time
boundary; future-dated entries are conservatively retained. Outstanding
reservations do not age out merely because a window elapses. Exposure is aggregated at the authority across every
enabled entry point. Mutually exclusive EVM replacements share the maximum
claim for the same family/native resource; unrelated obligations add. Missing
exposure, arithmetic overflow, stale/future evidence, or a freeze denies issuance.
Native maximum fee claims include Solana account creation. Final settlement
charges actual network fees **and actual account funding**, even on a token send.

## 6. Durable state and release point

The authority owns immutable intent hashes, institution/route-scoped idempotency
keys, candidate/family binding, native locks, reservations, issuance records,
settlements, policy activation, and freeze ordering. `AuthorityStore::transact`
commits a private state copy atomically or commits nothing. The current file
store is a fenced single-writer development store, not a PostgreSQL production
deployment or a replicated database. A production SQL implementation must
preserve serializable transactions, conflict retries, durable acknowledgements,
and fencing; adding SQL without these invariants is not equivalent.

The API's SQLite store uses WAL, synchronous FULL, and a compare-and-swap record
update. It commits `dispatching` **before** calling the coordinator. Concurrent
cancel/submit cannot overwrite the winner. API, authority, signer ledgers,
broadcaster, and reconciler are separate stores, not one distributed transaction.
An ambiguous API dispatch stays blocked for evidence/recovery, including after
restart. Once completed, the API persists the envelope, release receipt,
issuance record, and exact verified signed bytes before broadcast. A retry can
rebroadcast those same bytes; it cannot request another issuance.

The coordinator reserves exposure, opens/verifies signer sessions, and buffers
share-producing rounds. `Authority::release` durably commits issuance before a
signer receives the release receipt and produces signature-enabling output.
Before that point, verified abort releases reservations. After that point,
timeouts retain exposure as `ISSUANCE_UNKNOWN`. Signature observation, RPC
acknowledgement, inclusion, and finality are separate facts. Unknown submission
is taken from the broadcaster, not replaced with an earlier authority state.

```diagram
┌─────────┐    ┌────────────┐    ┌────────────────────┐
│ Intent  │───▶│ Reserved   │───▶│ Issuance committed │
└─────────┘    └─────┬──────┘    └─────────┬──────────┘
                    │                    │ release receipt → signer output
                    ▼                    ▼
           ┌────────────────┐   ┌────────────────────┐
           │ Aborted safely │   │ Signature / unknown│
           └────────────────┘   └─────────┬──────────┘
                                          ▼
                              ┌────────────────────────┐
                              │ Submitted / unknown    │
                              │ → included → finalized │
                              └────────────────────────┘
```

## 7. Deposits, journal, and reconciliation

Controlled addresses remain inactive until key/address agreement, asset/network
configuration, recovery metadata, and monitoring commitments are all nonzero.
Watch-only monitoring never claims custody. Finality promotes accepted supported
effects to per-asset journal postings; unknown/nonstandard assets, dust, and
inactive/retired address cases remain quarantined. Effect identity includes the
network, transaction, and effect index. Reorgs append reversals and retain prior
observations. Backfill is explicit and idempotent.

The reconciler stores a journal hash chain, signed checkpoints, signed event
sequence, durable cursors, workflows, and cases in a single-writer atomic
snapshot. A high-water fence is fsynced before the snapshot; ambiguous writes
poison the handle. Reopening an older snapshot against a newer retained fence
fails closed. **Rolling back the snapshot and its fence together is not detected
without an independent checkpoint/witness.** File fencing is not whole-host
rollback protection, and signatures do not prove chain evidence was truthful.

Holdings, pending movements, outstanding reservations, available balance, and
remaining policy allowance are distinct quantities. Reconciliation compares the
journal to balances at one fully indexed finalized state. A mismatch opens a
scoped case; only an exact, admin-quorum-signed correction appends an adjustment.
There is no automatic balancing entry. Internal transfers match both network
profile and controlled counterparty; they are not external revenue/payments.

Gas funding and sweeps create ordinary intents. Accepted triggers are durably
deduplicated. Funding and token movement have separate approved destinations,
ceilings, fees, dependencies, and child IDs. Refill accounting includes allocated
work, not only completed transfers. Restart reuses the recorded child; stale
evidence, fee spikes, freeze, uncertainty, or insufficient available funds pauses
work rather than expanding authority.

## 8. Evidence profiles

The EVM simulator profile is `evm-devsim-v1`, chain ID 31337, finality depth 2.
It verifies native transfers and enrolled standard ERC-20 transfer calldata/logs.
It does **not** discover universal contract-internal native transfers or support
arbitrary contract calls. The Solana simulator profile is `solana-devsim-v1`;
its genesis/network binding and finality are pinned by `ChainProfile` rather than
inferred from display names. It verifies supported system/SPL transfers and
associated-token-account creation with rent charged separately in the journal.

Profiles commit accepted versions, evidence ages, source trust levels, and finality
criteria. Broadcaster source disagreement quarantines operations. Two RPC URLs
are not proof of provider independence. The simulators are deterministic test
sources, not independent live-chain finality witnesses. An on-chain transfer to
an exchange is not evidence that the exchange credited an account.

## 9. Identity, enrollment, and recovery

Trusted deployment catalogs enroll keys, wallets, adapters, profiles, evidence
sources, participant sets, and versioned destinations. Policy and destination
activation require distinct administrative signatures. Independent approval
clients pin their own trust roots and decode native bytes themselves. Do not
bootstrap those roots from untrusted console text. Local bearer-token hashes
carry vault-specific `read`, `propose`, `approve`, and `submit` capabilities;
revoking a bearer token does not revoke an approval key, signer share, or previously
issued native signature. Keep an inventory of each authority type.

RFC003 owns authenticated discovery, transport keys, roster activation, placement,
and separate signer-core/network processes. This in-process development contract
does not provide expiring network invitations or production domain bootstrap.
Restore must compare retained checkpoints/fences and advance signer generation
without reviving consumed nonce state. If recovery cannot prove safety, halt;
never clear a ledger to make a test transfer succeed.

## 10. HTTP and replay

`services/api` exposes authenticated `/v1/intents`, preview, approval, submit,
pre-dispatch cancel, operations/status/evidence, wallet balances, events, and
export routes. A create requires a nonblank external business reference and an
`Idempotency-Key` of at most 128 bytes. Reusing a key with a different canonical
intent conflicts. Idempotency records are retained for the operation lifecycle;
there is no time-based deletion. There is no arbitrary-hash signing endpoint.

HTTP 200 from submit means durable completed issuance material and a recorded
broadcast attempt, **not** acknowledgement, inclusion, or finality. Follow the
operation's lifecycle and submission evidence. `dispatching` without completed
issuance refuses automatic retry; cancellation is only a pre-dispatch API action
and cannot revoke native authority already issued. Errors carry `code` and
`detail`: malformed input 400, missing/invalid bearer 401, insufficient scope or
invalid approval signature 403, absent resource 404, conflicts/policy/uncertainty
409, storage/recovery unavailability 503, internal failure 500.

`GET /v1/events?after=S&limit=N` returns institution-global events with sequence
strictly greater than S, in ascending order; N is 1–1000 (default 100). Persist
the sequence only after verifying the signature and processing the event.
Deduplicate by institution/environment and sequence/event ID, detect gaps, and
replay from the last processed sequence. Event signing keys are pinned separately
from custody and authority keys. The current store verifies one event key on
open; historical-key rotation and webhook push delivery are **not implemented**.

Events are signed **operational observations**, not a transactional outbox for
every intermediate authority transition. Repeated observations of the same
operation state/transaction do not append a new event. A crash between an
authority/API commit and event append can omit an observation until the
operation is refreshed/retried; authorization receipts and issuance records
remain authoritative. Do not infer a complete issuance audit solely from events.
An export contains no custody shares; independent reconstruction also requires
the referenced approval/issuance records and declared chain evidence.

## 11. Upgrade and rollout

There is no automatic compatibility negotiation or storage migration. Pin the
lockfile and build measurements, test the mixed-version set against committed
vectors and retained state, stop intake, reconcile in-flight operations, retain
independent checkpoints, and only then activate an approved compatible build.
An unsupported backend version, key epoch, profile/verifier measurement, or
snapshot format halts. Restoring old binaries must never roll back authority
epochs, signer generations, release records, or one-time nonce consumption.
Production upgrade/restore procedures require qualification before Gate C.

## 12. Executable acceptance

- `tests/golden-vectors/tests/conformance.rs`: every domain producer, strict CBOR
  round-trip, signatures, native EVM/Solana preimages, differential SDK checks.
- `tests/golden-vectors/tests/schema_conformance.rs`: public structural schemas
  versus committed vectors and precision/shape mutations.
- `services/reconciler/tests/money_loop.rs`: both zero-gas funding/sweep loops,
  accepted reorgs, durable replay/backfill, quarantine, signed corrections,
  fee/rent accounting, and file-store fences.
- `services/api/tests/http_flow.rs`: both HTTP approval/signature flows,
  idempotency, vault capabilities, event replay, release evidence, concurrent
  dispatch/cancel, and accepted RPC submission with a lost acknowledgement.
- Existing authority, signer, coordinator, broadcaster, one-time-state, and
  independent approval-client tests remain required. Simulator tests do not
  replace RFC003 socket/process tests or independent review.

Continue with [RFC003](rfc-0003-institution-operated-signer-network.md) for the
network boundary and [RFC002 gates](rfc-0002-product-completion.md#13-delivery-sequence)
for installation, operator, and real-value readiness requirements.
