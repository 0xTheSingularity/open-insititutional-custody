# Open Institutional Custody — RFC 0001

**Version:** 0.1-draft  
**Prepared:** 2026-10-19  
**Status:** Proposed architecture; not an implemented, audited, or production-approved custody system.  
**Scope:** EVM and Solana first; explicit extension contracts for Bitcoin, Cosmos SDK, Sui, Aptos, and XRP Ledger.  
**Working title:** Open Institutional Custody. No affiliation with or claim of compatibility with Fireblocks.

## 0. Decision and interpretation

[Likely] Build a self-hosted institutional transaction-authorization and custody system with chain-specific transaction verification, distributed signing, and independently operated security domains. Do not build a universal private-key API and then place an approval interface in front of it.

The product contract is:

> An institution defines who may authorize a precisely bounded operation. A signing quorum produces the chain-native signatures only after independently checking the authorization, the exact signing payloads, and the reserved exposure. Every consequential transition is recoverable and auditable.

This is an authorization-at-signing contract, not a guarantee of future execution outcomes. An issued signature may remain usable after an internal approval expires or a wallet is frozen. EVM type-2 transactions have no general expiry field; Solana durable-nonce transactions deliberately remove the normal recent-blockhash expiry window. [S3, S7]

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** describe proposed implementation requirements. They are not claims that the system already satisfies them. Numeric quorums and limits below are design choices, not universally optimal security settings.

### 0.1 Initial scope

The first shipping profile is one institution per deployment, multiple named vaults, separate treasury and operational keys, EVM native/curated ERC-20 transfers, and Solana SOL/curated original SPL Token transfers. Provide proposals, independent approvals, policy administration, address registration, balance reconciliation, distributed signing, broadcasts, signed audit receipts, and recovery ceremonies.

Automatic low-limit transfers require an explicit preapproved policy grant. Human-approved transfers use distinct approvers. No transaction receives implicit permission merely because an API credential is valid.

### 0.2 Explicit non-goals

The first release does not provide a qualified-custodian designation, insurance, a counterparty network, cross-chain atomic settlement, proof of solvency, exchange credit, consensus security for another blockchain, arbitrary smart-contract safety, an unrestricted dapp connector, general raw-message signing, validator staking keys, or a public multi-tenant SaaS service. Operational/legal approval to hold client assets is a separate workstream; the software specification does not establish that approval.

### 0.3 Important unknowns

Actual assets under custody, jurisdictions, client-money versus proprietary-treasury use, chains and assets required by the first customer, transaction rates, recovery objectives, approver availability, and the exact MPC implementation/commit are not specified. The architecture is designed to expose these choices, not assume them away.

## 1. Architecture and trust boundaries

```text
                        INSTITUTION
              Treasury staff / execution systems
                              |
                    Custody Management API
                    [not trusted to authorize]
                              |
                    Intent / transaction builder
                              |
               Chain evidence + transaction preview
                              |
                   Deterministic policy evaluation
                    /            |            \
                  Limits      Approvals     Allowlist
                    \            |            /
                  Authorization + reservation authority
                      [separate security domain]
                              |
                  Exact Authorization Envelope
                              |
                    Untrusted MPC coordinator
                  /              |              \
                 v               v               v
           Signer A          Signer B          Signer C
        verifier + share  verifier + share  verifier + share
          institution       independent      recovery/third
           domain A          domain B          domain C
                  \              |              /
                    Native signature assembly
                              |
                   Signature verification/storage
                              |
                       Chain broadcaster
                              |
                      Blockchain network
                              |
                Independent finality/reconciliation
                              |
                   Exposure and audit updates
```

The diagram is logical. It does not require a different microservice for every box. It does require different administrative and security domains where marked.

### 1.1 Component responsibilities

| Component | Responsibility | Must not possess |
|---|---|---|
| Management API | Authentication, proposals, status, read-only reporting | MPC shares, approval-root keys |
| Intent service | Immutable business intent and idempotency | Unrestricted signing authority |
| Builder | Construct candidates using a chain profile | Authority to determine what is approved |
| Evidence service | Retrieve and package chain state and simulation | Permission to silently redefine network identity |
| Policy preview service | Explain requirements and denials | Sole control of enforcement |
| Approval client | Independently render the operation and sign an approval challenge | Other approvers' credentials |
| Authorization-state authority | Current policy epoch, budget/resource reservations, release and freeze ordering | MPC signing threshold |
| Signer | Independently validate envelope and native payload; contribute a share | Other signers' shares |
| MPC coordinator | Deliver protocol messages and assemble results | Policy override or share storage |
| Broadcaster | Submit only approved signed bytes and retry submission | Ability to change and re-sign bytes |
| Reconciler | Determine canonical outcome and retain unresolved exposure | Permission to declare failure based on one timeout |
| Audit service | Signed, ordered evidence and independent checkpoints | Secrets or approval power |

### 1.2 Three different kinds of quorum

**Business approval quorum:** people or explicitly delegated machines approving an operation. Example: two of three designated treasury approvers, excluding the proposer.

**MPC quorum:** key-share participants necessary to produce a signature. Desired operational profile: two of three. A reserve profile may use three of five or an offline path, but is a different deployment profile.

**Administrative quorum:** authorities who can change policies, signer membership, approval roots, approved software measurements, or recovery configuration. Example: three of five with a delay for privilege expansion.

These quorums MUST have separate credentials and documented membership. Three credentials held in the same browser session, cloud root account, or password vault do not represent three independent failure domains.

The two-of-three MPC profile is a requirement to validate against a selected backend, not an assertion that every open-source MPC library supports interchangeable two-of-three operation, resharing, and backup. A backend that needs all participants MUST NOT be exposed as a two-of-three implementation.

### 1.3 Threat model

The baseline target is to preserve unauthorized-signing resistance when an adversary controls the management API, builder, coordinator, broadcaster, and at most one of the three MPC domains. The adversary may replay, reorder, delay, corrupt, and drop messages, and may operate a dishonest RPC endpoint.

This target depends on:

- A correctly implemented and appropriately reviewed threshold protocol, with fewer corrupted shares than its signing threshold.
- Honest enforcement inside the remaining participating signers, including their boot, update, storage, and recovery paths.
- An uncompromised authorization-state authority for global budgets, release ordering, policy freshness, and resource reservations.
- A sufficient number of independent uncompromised approval/admin credentials for the selected policy.
- The declared trust assumptions of each chain-evidence profile.
- No common software or hardware vulnerability defeating the assumed independent domains simultaneously.

An adversary may still deny service. Sufficiently many colluding signers can bypass off-chain policy because the blockchain verifies the native signature, not this authorization envelope. A common decoder bug can mislead every honest signer. A compromised quorum of authorized humans can approve a theft within their powers. Token issuers and smart-contract administrators can introduce risks unrelated to custody-key secrecy.

## 2. Security properties

The implementation MUST make these properties explicit in tests and reviews.

**I1 — Exact-payload authorization.** Every honest signing participant checks the actual chain-native signing payload against an authenticated authorization envelope, not a coordinator-provided description alone.

**I2 — Scope binding.** Authorization binds institution, environment, vault, key identifier and epoch, network identity, operation purpose, adapter version, asset identity, destination, amounts, fees, and native resource/anti-replay fields.

**I3 — Independent enforcement.** Compromising the API/coordinator cannot bypass signer-side policy checks. No debug, recovery, or maintenance endpoint supplies a general bypass.

**I4 — Reserved exposure.** Operations reserve worst-case authorized outflows and fees before releasing a signature-enabling contribution. Simultaneous operations cannot each consume the same remaining budget.

**I5 — No false cancellation.** A request timeout, approval expiry, broadcaster error, or UI cancellation never proves that a signed transaction cannot execute.

**I6 — Policy/configuration integrity.** Only properly approved, ordered configuration changes can alter authority. Unknown, stale, or rolled-back policy/configuration epochs fail closed.

**I7 — Cryptographic state safety.** Protocol-specific one-time state is durably consumed and never reused across retries, crashes, clones, or backup restores.

**I8 — Tenant and environment isolation.** Mainnet/testnet and institutions use separate keys and policies. A wallet identifier is not a substitute for enforcing these boundaries.

**I9 — Recovery is not a weaker signing route.** All permitted recovery routes preserve the intended security threshold or explicitly declare an approved exceptional reconstruction ceremony.

**I10 — Honest observability.** The system distinguishes a created signature, an RPC acknowledgement, an included transaction, an executed effect, and the deployment's selected finality condition.

**I11 — Capability containment.** A delegation, allowance, authority change, or off-chain spending signature is treated as a new spending capability, not as a zero-value transaction.

**I12 — Bounded claims.** Simulation is evidence about a particular state, not proof of all future effects. Unsupported semantics are denied, not labeled safe.

## 3. State and authorization objects

### 3.1 Core objects

| Object | Required meaning |
|---|---|
| Institution | Security root, deployment/environment, administrative policy |
| Vault | Logical group of chain wallets with a risk tier and spending policy |
| ChainWallet | One native address/account, network profile, key binding, supported operations |
| KeyDescriptor | Algorithm/protocol, public key, participants, threshold, epoch, recovery profile |
| Asset | Network + token/mint/denomination/type identity; metadata is not identity |
| CounterpartyDestination | Versioned network/address/asset restrictions and verification evidence |
| PolicyBundle | Versioned deterministic rules, administrative signatures, activation conditions |
| Intent | Immutable requested business operation and idempotency scope |
| ApprovalGrant | A human or authorized service's signed permission over exact bytes or a narrow template |
| Candidate | Exact unsigned native transaction/message and signing-payload array |
| EvidenceBundle | State references, source identities, decoded dependencies, simulation and freshness |
| Reservation | Atomic budget and native-resource allocation for an operation family |
| AuthorizationEnvelope | Candidate binding, policy binding, grants, reservation, validity and session |
| SigningSession | One backend protocol execution, participants, key epoch, transcript references |
| IssuanceRecord | Durable record that a signature may now exist |
| ChainObservation | Submission, inclusion, effects, finality, or definitive invalidation evidence |
| AuditEvent | Signed security-relevant transition with ordering and previous-event commitment |

All security identifiers MUST be globally unambiguous within their domain. Amounts are bounded integers in base units; display decimals are separately obtained from an approved asset registry. No floating-point values enter policy accounting.

### 3.2 Encoding and hashing

Choose one specified deterministic encoding for security objects: a restricted deterministic-CBOR profile is proposed. Reject duplicate fields, unknown mandatory fields, non-canonical encodings, floating-point numbers, ambiguous null/default handling, oversized collections, and unrecognized enum values. Cryptographic field encodings MUST be specified at byte level and published with cross-language test vectors before implementation is considered conformant.

Use domain-separated hashes for internal commitments, for example:

```text
EnvelopeHash = SHA256("OIC/AUTHORIZATION/v1" || CanonicalEncode(envelope_body))
IntentHash   = SHA256("OIC/INTENT/v1"        || CanonicalEncode(intent))
```

These are **internal authorization hashes**, not substitutes for chain-native signing messages. REST JSON and protobuf/gRPC may transport the objects, but their incidental serializer output MUST NOT silently become the canonical security encoding.

### 3.3 Authorization envelope

The envelope must contain or commit to the following authenticated data. Sensitive content may be retrieved by commitment from authenticated storage; absence or inconsistency fails closed.

```text
AuthorizationEnvelopeV1
  domain = OIC/AUTHORIZATION/v1
  institution_id, environment_id
  vault_id, chain_wallet_id
  intent_id, intent_hash, operation_family_id
  candidate_id, candidate_revision
  chain_profile_id, chain_profile_hash
  key_id, key_epoch, public_key_hash
  adapter_id, adapter_version, verifier_build_hash
  policy_id, policy_epoch, policy_hash, allowlist_version
  native_unsigned_bytes
  native_signing_payloads[]:
    payload_index
    scheme_id
    message_or_digest
    required_key_id
    native_signing_context
  decoded_operation_hash
  evidence_bundle_hash
  approval_grants[]
  budget_reservation_id, reservation_version
  resource_reservations[]
  maximum_asset_outflows[], maximum_native_fees[]
  issuance_deadline
  expected_chain_validity_constraints
  signer_session_id, participant_set
  authorization_state_receipt
```

The signer MUST derive the native signing payloads from `native_unsigned_bytes` itself. An envelope-supplied payload array is a comparison target, not trusted input to a generic `sign()` call. Bitcoin may require several input-specific payloads; a transaction is not universally a single hash.

### 3.4 Approval modes

**Exact-candidate mode:** the approval covers one fully specified candidate and preview hash. Changing any signing-relevant field requires a new candidate, policy evaluation, and fresh approval. Re-broadcasting identical signed bytes does not require another signature.

**Bounded-intent mode:** the approver permits a narrowly typed operation such as “one transfer of exactly X base units of mint M, from wallet W to registered destination D, on network N, with fees no greater than F.” An explicit template declares which fields may be filled later, such as a fresh Solana blockhash. The authority must show that each final candidate satisfies the grant, reserve it atomically, and produce an exact-candidate envelope. The signer repeats that verification.

V0 bounded grants support direct transfers only. No wildcard calldata, arbitrary instruction list, dynamic recipient, dynamic asset, unconstrained gas payer, or generic arbitrary-message capability.

A one-use grant limits authorized successful payment, not merely the number of API calls. Fresh-blockhash retries are not automatically mutually exclusive with earlier Solana transactions. After a possibly issued signature, a replacement requires chain-specific invalidation evidence or a supported on-chain uniqueness mechanism.

## 4. Policy engine and approval security

### 4.1 Policy model

Use a deterministic restricted policy representation. A declarative compiler and simulator are suitable outside the signer; the signer runs the pinned, testable enforcement kernel. Do not put arbitrary user-written code, network calls, system time lookups, floating-point oracle computations, or dynamic imports inside policy evaluation.

Inputs are the verified operation, authenticated identity/grants, signed policy bundle, reservation receipt, evidence with a declared trust level, and a validated freshness context. Outputs are `ALLOW`, `DENY`, or `REQUIRE_APPROVALS`, with stable reason codes.

Hard denials dominate broad allow rules. Missing data, unsupported semantics, stale evidence, policy-version mismatch, and verifier disagreement fail closed. Simulations or a security team's manual “looks fine” flag cannot override an unsupported transaction type.

Policy dimensions include asset and destination identity, per-operation and rolling exposure limits, vault tier, transaction purpose, fees, approval roles, program/contract/function restrictions, permitted authority changes, chain-evidence freshness, and operating windows.

### 4.2 Administration

Adding a beneficiary, changing a policy, increasing a limit, changing approvers, permitting a new chain, upgrading a decoder, accepting a new enclave measurement, or altering recovery is a privileged configuration transaction with its own before/after diff, approval quorum, activation epoch, and audit receipt.

Proposed default: emergency freeze can be triggered by one designated responder; unfreeze and privilege expansion require the administrative quorum. A freeze stops new issuance after its ordered commit point. It does not retract prior issuance or necessarily interrupt an already committed signing release.

An illustrative 24-hour delay on new beneficiaries and privilege expansion is a configurable policy, not a security theorem. Define an emergency path before deployment; do not discover during an incident that the only usable recovery mechanism requires disabling policy.

### 4.3 Independent approval display

The approval client independently verifies the candidate or permitted intent template, policy identity, and destination registration. It displays the exact asset/network, full verified beneficiary identity/address, amount, maximum fees, authority changes, operation purpose, and warnings.

Use hardware-backed authentication/signing credentials where supported. A passkey signature proves that a credential approved a challenge; it does not prove that its holder saw an honest transaction description. High-value approvals therefore require an independently distributed verifier client or another trusted review channel, not three people reading the same compromised web application.

Approval credentials, administrative credentials, and blockchain signing shares MUST be distinct. Enrollment and device replacement require stronger controls than ordinary login.

## 5. Global limits, reservations, and consistency

### 5.1 Why a quorum alone is insufficient

Suppose a two-of-three signer set is A, B, C, with C malicious. A+C can authorize one operation from one budget view while B+C authorizes a different operation from another view. Their only common participant is malicious. Two signatures do not establish a globally consistent spending counter.

The baseline therefore includes an independent **authorization-state authority** as an explicit trusted component. It atomically manages reservations, native resource locks, policy epochs, freezes, and issuance records. Do not market this baseline as Byzantine fault tolerant against compromise of that authority.

### 5.2 Practical baseline

A dedicated authorization service with a serializable transactional store is the initial design. A PostgreSQL implementation is a candidate, not a claim that PostgreSQL by itself prevents malicious administrators or snapshot rollback. Keep its administration separate from the application/coordinator and restrict restore/failover operations. Require durable committed issuance records, fencing against split-brain writers, and independent signed checkpoints.

Every signer validates the authority's signed receipt, the policy, and the transaction. An honest authority can serialize conflicting requests even when the application is malicious. If the authority is unreachable, new issuance stops.

A hardened later profile may use an independently reviewed Byzantine-replicated state machine. With four replicas and a one-Byzantine threat model, three-replica quorums have honest intersection, but signature counting alone is still not a consensus protocol: locking, view change, ordering, and recovery must all be specified. Reuse a reviewed implementation rather than creating a new consensus algorithm for this product.

### 5.3 Accounting rule

For each scoped asset budget:

```text
exposure = settled_debits_in_window
         + outstanding_potential_debits_from_issued_or_releasable_operations
         + new_reservations
```

Outstanding signatures that can still execute remain charged even across a rolling-window boundary. A signature signed yesterday cannot become “free” today just because the counter reset. Finalization moves a debit from outstanding to settled accounting without double charging it; definitive invalidation releases the relevant reservation.

Reserve fees separately in native units. Reverted transactions can still consume fees. For Solana, account creation/rent funding and other lamport movements must be distinguished from token amounts. Netting expected incoming assets against outgoing exposure is disabled by default.

If several signed candidates are provably mutually exclusive, reserve the maximum combined exposure of any possible executable branch rather than summing impossible alternatives. Without such a proof, sum them. Shared EVM sender/nonce conflicts differ from a Solana transaction rebuilt with a new blockhash. A Bitcoin child-pays-for-parent transaction is additional exposure, not a replacement of its parent.

### 5.4 Atomic operation

Within the authorization-state boundary:

1. Validate intent uniqueness, policy epoch, grants, and candidate integrity.
2. Acquire all affected budget and native-resource reservations in a defined ordering.
3. Confirm the maximum possible exposure remains inside policy.
4. Persist reservation and operation-family state.
5. At final release, recheck freeze/policy/freshness and atomically mark the operation as **possibly issued**.
6. Return a short-lived, candidate/session-bound release receipt.

The final receipt is obtained before any MPC output that could allow signature completion is released. The exact protocol point must be reviewed for the selected backend; it cannot be guessed from a generic workflow diagram.

Once any honest signer has crossed this release point, assume a valid signature may exist, even if the coordinator claims it crashed before assembly. Failed signing attempts may conservatively retain exposure until a protocol-safe abort proof or chain invalidation resolves them.

## 6. Signing and cryptographic backend

### 6.1 Backend selection

[Certain] Fireblocks publishes a GPL-3.0 C++ MPC library implementing ECDSA and EdDSA variants. Its published integration contract leaves transaction authorization, authenticated transport, and production persistent-state enforcement to the integrator. [S1, S2]

Treat it as a candidate backend. Pin a commit and dependency set; validate its exact protocols, threshold topology, supported curves, message conventions, address derivation, refresh/resharing, and licensing before selecting it. Do not add unaudited secret-sharing wrappers to simulate a threshold mode the protocol does not support.

A crypto-provider interface must support declared capabilities, not a fictitious universal set:

```text
capabilities()
generate_distributed_key(ceremony)
start_signing_session(authorized_native_payloads, participant_set)
advance_protocol(session_id, authenticated_peer_message)
verify_result(public_key, native_payload, signature)
refresh_shares(ceremony)       # only if reviewed backend supports it
recover_or_replace(ceremony)   # explicit profile, never generic export
```

### 6.2 Message conventions

The backend descriptor MUST distinguish prehashed ECDSA, pure Ed25519 over a message, and chain-specific Schnorr modes. EVM type-2 transactions use secp256k1 signatures over their specified Keccak signing digest. Solana signatures cover serialized transaction messages using Ed25519. [S3, S6]

Do not externally prehash every message to 32 bytes and assume it is equivalent. Do not substitute Ed25519ph for pure Ed25519. Do not assume generic Schnorr or a library with Schnorr-related proofs implements Bitcoin BIP-340/Taproot signing. [S6, S11]

### 6.3 Persistent cryptographic state

Every one-time nonce/preprocessing record has an immutable identity, key epoch, protocol/session binding, and durable consumption state. Consumption must precede releasing dependent protocol output. A retry must not allocate or reuse the same one-time secret under another signing message.

The design must survive process crashes at every protocol boundary, loss of acknowledgement, competing coordinator retries, VM/enclave cloning, snapshot rollback, restored backups, and stale disaster-recovery replicas. Local disk encryption alone does not establish freshness.

For the initial profile, keep external durable fencing/tombstones and signer-instance generations under the authorization-state security boundary, without exporting secret preprocessing values. The protocol/storage integration must define how a signer proves it is the current live instance and how peers reject stale session generations. After uncertain restore or recovery, discard outstanding preprocessing generations and complete the approved re-enrollment/refresh procedure before signing again. A detected possibility of nonce reuse requires incident handling and potentially migration to a new key; deleting a reused nonce afterwards does not undo the damage.

Backups MUST NOT reintroduce already consumed preprocessing. A backup bundle stores long-term encrypted share material, protocol metadata, policy/roster references, and recovery instructions, with independently verifiable freshness requirements. Do not restore one signer image into two active quorum members.

### 6.4 Transport and process boundary

MPC protocol channels authenticate both sender and recipient, tenant/key/session/round context, protocol version, and sequence. Use pinned participant identities, mutually authenticated encrypted channels, bounded message sizes, replay checks, and resource limits. A hostile coordinator can transport encrypted traffic but cannot impersonate a peer.

The final authorization verifier and share-using code belong inside the same protected signing boundary. A network-accessible C++ worker that trusts an upstream API's “approved” flag is not acceptable. A proposed implementation uses a small Rust verifier with a narrow reviewed interface to the selected crypto implementation inside the signer boundary; backend crashes must not expose other tenants or secrets.

## 7. TEE/HSM deployment and key ceremonies

### 7.1 Hardware is a profile, not a label

A TEE can protect a measured signer process; an HSM may protect wrapping keys, credential keys, or supported signing operations. Do not assume a standard HSM signing mechanism can execute arbitrary rounds of a selected MPC protocol. AWS, for example, documents explicit cryptographic mechanisms and attestation-conditioned key-release features, rather than a generic ability to run any MPC implementation inside an HSM. [S14, S15]

A candidate TEE profile uses measured signer images, attested key unsealing, authenticated peers, no debug image, restricted egress, encrypted external persistence, and independently approved software measurements. Attestation proves properties about a measured execution environment under its hardware/vendor assumptions; it does not prove application correctness or automatically stop state rollback. [S14]

### 7.2 Failure-domain placement

For a two-of-three operational vault, place shares in genuinely independent administrative domains. Example: institution security account A, an independently administered provider/on-premises domain B, and a separately administered recovery domain C.

Document which party controls root IAM, firmware/hardware trust, approved-image signing, backups, KMS policy, operator credentials, and recovery materials for each share. Two regions of one administrator-controlled cloud account are not independent against that administrator.

Different providers can reduce correlated administrative/vendor failure, but introduce more operational complexity and do not remove common code vulnerabilities. Choose the independence model before promising its benefits.

### 7.3 Key generation

Conduct authenticated distributed key generation within the selected backend. Produce a signed `KeyDescriptor` with public key, algorithm, participant roster, threshold, network/environment bindings, and recovery profile. Verify public-key agreement and chain address derivation independently before enabling deposits.

Avoid a universal master seed across networks and institutions. Prefer independent key material for distinct environments and high-value vaults. Any hierarchical derivation feature requires backend-specific review and test vectors; ordinary Ed25519 wallet seed derivation cannot be assumed to work unchanged with distributed shares.

### 7.4 Recovery, replacement, and rotation

Separate these procedures:

- **Restore one share:** recover encrypted material into an approved replacement instance, fence the old instance, reconcile one-time state, and complete the re-enrollment procedure.
- **Refresh/reshare:** use only a reviewed backend protocol to change shares/participants while preserving the public key where supported.
- **Replace the blockchain key:** generate a new distributed key and move assets or update permitted on-chain authority through an approved transaction.

Off-chain participant removal does not invalidate a stolen full private key or a previously stolen signing threshold. Preserving an address after threshold compromise is not a recovery guarantee. For simple key-controlled accounts, migrating assets to a new key may be necessary.

Recovery testing must demonstrate an actual transfer from a test wallet after losing one permitted participant, without relying on the lost cloud account or unavailable operator. Retain old addresses as monitored watch-only accounts after migration to detect late deposits.

## 8. Chain adapter contract

The shared core standardizes authorization and lifecycle, not transaction semantics.

Each adapter is released with a capability manifest and pinned verification code. Proposed logical interface:

```text
identify_network(profile, evidence) -> VerifiedNetworkContext
build_candidate(intent, resources, evidence) -> NativeCandidate
decode_candidate(candidate, evidence) -> DecodedOperation
verify_candidate(candidate, intent_or_grant, evidence) -> VerifiedOperation
resource_requirements(verified_operation) -> ResourceClaims
signing_payloads(verified_operation) -> NativeSigningPayload[]
assemble_signed_transaction(candidate, signatures) -> SignedTransaction
verify_signed_transaction(signed_transaction, candidate) -> VerifiedSignedTransaction
observe(transaction_id, chain_evidence) -> LifecycleObservation
prove_invalidation(operation_family, chain_evidence) -> InvalidationEvidence | Unknown
```

Building/simulation can run outside the protected signer. The minimal decoding and verification functions used to justify authorization run inside it or inside an equivalently trusted separately authenticated verification boundary explicitly included in the threat model. The default is signer-local verification.

An adapter manifest declares network identity, accepted transaction versions, exact signing schemes, supported asset standards and instruction types, replay/expiry behavior, resource-lock rules, fee accounting, evidence trust profile, finality levels, replacement rules, known external authorities, and conformance test vectors.

An unsupported version or token extension MUST be rejected. A new chain does not become safe because an RPC URL responds to familiar methods.

## 9. EVM profile

### 9.1 Initial capabilities

Support EIP-155 replay-protected legacy transactions only where required by the enrolled network profile, and EIP-1559 type-2 transactions where enabled. Start with native transfers and direct `transfer` calls for a reviewed list of ERC-20 contract instances. All other transaction types and semantics are denied until separately enabled.

For type-2 transactions, independently derive the specified signing digest from chain ID, nonce, fee fields, gas limit, destination, value, calldata, and access list. Require a valid canonical signature and verify recovered sender against the registered key. [S3]

### 9.2 Required verification

Bind the configured network/chain ID and trusted checkpoint/genesis profile. Reserve `(network, sender, nonce)` together with all applicable asset/fee budgets. Decode actual calldata with a pinned schema; do not trust an ABI name, wallet label, token symbol, or function selector without arguments.

For an ERC-20 transfer, verify the token contract, recipient, amount, and permitted native value. Apply contract-specific behavior profiles to fee-on-transfer, rebasing, pausable, proxy-upgradeable, or otherwise nonstandard assets. Unsupported assets can be watched but not automatically sent.

Estimate gas using evidence, cap approved gas exposure, and handle network-specific L2 fee components. Code/proxy-state checks must identify what was verified at the evidence block. A later contract upgrade or changing state can still affect execution; do not claim that a pinned simulation alone prevents that race.

### 9.3 Denied by default

General `eth_sign`, unrecognized `personal_sign`, arbitrary EIP-712 messages, token `approve`/permit, Permit2-style grants, operator approvals, arbitrary multicalls, bridges, delegatecalls through account infrastructure, session keys, contract deployment, account upgrades, EIP-7702 authorization, and ERC-4337 execution all require dedicated operation profiles.

EIP-712 explicitly does not provide replay protection by itself. EIP-7702 can authorize delegated account code, so a small or zero-value request can have authority consequences beyond a transfer. [S4, S5]

Already-delegated accounts and wallets with existing allowances require inventory and a compatible policy profile; merely refusing new delegation requests does not eliminate existing authority.

### 9.4 Replacement and validity

Any gas bump or cancellation is a new candidate with its own exact payload and approval/template checks. Replacement candidates share an operation family and sender/nonce reservation. A submitted replacement is not proof that the original is invalidated.

A pending EOA transfer has no platform-enforced expiry merely because the authorization envelope has a deadline. Retain its exposure until the nonce is definitively consumed under the network's finality policy, the transaction executes, or another supported proof establishes invalidation. [S3]

Report submission, inclusion, execution success/revert, confirmations/finality, and—where relevant—L2 inclusion versus L1 settlement as distinct fields. Do not collapse all EVM chains into a fixed confirmation count.

## 10. Solana / SVM profile

### 10.1 Initial capabilities

First certify Solana itself, rather than claiming every SVM deployment. Initial supported message formats are legacy and v0 under an enrolled network profile. Treat newer formats as separate capabilities requiring tests; support is a product scope choice, not a claim that legacy/v0 are the only formats in existence.

Support SOL transfers, original SPL Token checked transfers for approved mints, and strictly verified associated-token-account setup where necessary. Token-2022 requires extension-aware onboarding and is not implicitly supported.

### 10.2 Signature and message verification

Every required signature covers the exact serialized message using Ed25519. Verify the fee payer, ordered required signer set, account permissions, all top-level instructions, and any message-version fields. A changed blockhash changes the signed message. [S6]

For v0, independently resolve all referenced address lookup tables at a permitted state context and bind their identities and resolved addresses into evidence. Lookup-resolved accounts cannot be signers. Never approve a transaction only from its static account list. [S8]

### 10.3 Token and authority checks

Verify program ID, token program ownership, mint identity, source token-account owner/authority, destination token account's mint and beneficiary ownership, amount, decimals, delegates, close authorities, and account-creation payer. Do not infer ownership from a UI label or from an address merely resembling an associated token account.

Decode every instruction, including compute-budget changes, account creation, authority changes, closes, and lamport transfers. V0 auto-transfer templates MUST NOT accept an extra arbitrary program instruction.

For any later DeFi integration, explicitly validate the allowed program, instruction schema, account list, upgrade authority/state, anticipated CPI paths, and on-chain economic bounds. Simulation can reveal anticipated CPIs but cannot guarantee every possible execution path under changing state.

### 10.4 Token-2022 risk profiles

Read mint/account extensions before accepting a mint. In particular, transfer hooks add program execution to transfers, while a permanent delegate can move or burn tokens irrespective of an individual holder's ordinary account authority. These are external-authority risks, not problems MPC removes. [S9, S10]

Default-deny unknown extensions. Publish exactly which combinations are supported. A feature supporting simple Token-2022 transfers does not establish support for confidential balances, hooks, fees, nontransferable assets, or all extension combinations.

### 10.5 Blockhash, durable nonce, and retries

Prefer a bounded-intent approval followed by final construction with a fresh recent blockhash, so human deliberation does not require a pre-signed message to remain valid indefinitely. Store blockhash validity context and track confirmation using an explicit commitment/finality profile.

Durable-nonce support is optional and requires nonce-account ownership/authority validation, correct instruction ordering, reservation of the nonce account/value, and advance-based invalidation handling. Current Solana documentation warns that durable nonces may be deprecated in a future release; do not make them the only long-approval workflow. [S7]

Never re-sign the same payment using a fresh blockhash solely because an RPC call timed out. The earlier transaction may still land. A replacement needs definitive invalidation/nonexecution evidence appropriate to the chain or a reviewed on-chain one-use payment mechanism.

The replay protections are those actually committed by the native message and chain protocol. A network identifier in an internal envelope does not magically add a new on-chain signature domain.

## 11. Additional chain profiles

### 11.1 Bitcoin

Initial proposal: a descriptor-based SegWit wallet, PSBT interchange, and independently verified input-specific signing. Start with a deliberately narrow script set; support native multisig as a separate custody backend when it is a better fit than forcing all functionality through MPC.

PSBT provides the structured material used by signers and can support offline workflows; it is not a guarantee that the supplied inputs or outputs are trustworthy. [S12]

Verify every input's referenced output, script and amount using appropriate validated data; every external output; every change output against approved descriptors/derivation; transaction fees and fee rate; locktime/sequence; and sighash policy. Reserve UTXOs before signing. Default to full-commitment sighash policies appropriate to the enrolled script type; forbid `ANYONECANPAY`, `NONE`, or `SINGLE` unless a specific reviewed operation needs them.

Taproot is a separate capability gate: exact BIP-340 signature behavior, BIP-341 sighashes and key tweaks, and relevant PSBT fields must be implemented and tested. Generic ECDSA/EdDSA support is insufficient. [S11, S13]

Treat replace-by-fee candidates as operation families with explicit input conflicts and fee ceilings. Treat child-pays-for-parent as additional fee-bearing activity. Bitcoin locktime is not a general transaction-expiry mechanism; unresolved signed transactions retain exposure. Confirmation/reorg policy is chain-specific.

### 11.2 Cosmos SDK chains

Start with selected chain profiles and `SIGN_MODE_DIRECT`, explicit bank-send message allowlists, and pinned protobuf type definitions. The signed `SignDoc` commits to body bytes, auth-info bytes, chain ID, and account number; signer sequence resides within auth info. [S16]

Verify every message in a batch, denominations, recipient, memo where required, signer/account sequence, fees, fee payer/granter, timeout fields, and the chain's actual signing algorithm. Do not assume all Cosmos SDK chains use identical key/address/signature conventions.

Unknown messages, authorization grants, fee grants, governance actions, staking, and CosmWasm execution are separate capabilities. IBC support additionally verifies source port/channel, destination identity, denomination trace, receiver, timeout, and acknowledgement/refund lifecycle. A finalized source transaction is not proof that the destination payment completed.

### 11.3 Sui

Use Sui's own BCS transaction-data and intent-signing conventions; for the first profile choose one supported account signature scheme and test against the native verifier. Sui supports several schemes and uses intent-message hashing distinct from Solana's raw-message signing. [S17]

Verify programmable transaction commands, sender, recipient, package/module/function/type arguments, object identities/versions/digests and ownership, gas payment/owner/budget, and permitted transaction expiration. Reserve conflicting owned objects and gas resources; reject stale-object candidates rather than treating their signatures as reusable across changed inputs.

Initially permit direct coin transfers and a narrowly reviewed fungible-asset path. Package upgrades, shared-object DeFi, arbitrary programmable transactions, sponsored flows, zkLogin, and passkey authentication are independent capabilities. Account-balance and protocol-version features also require explicit profile support.

### 11.4 Aptos

Use Aptos's own transaction/authenticator format, domain separation, and BCS encoding. Initial scope is one supported single-sender authentication scheme, sequence-based transactions, native transfers, and selected fungible-asset entry functions. Verify sender, chain ID, sequence, function/type arguments, amount/recipient, gas bounds, and chain-enforced expiration. Aptos also documents orderless transactions; they are not automatically covered by a sequence-based implementation. [S18]

Multi-agent, fee-payer, orderless, account-key rotation, resource-account authority, module publication/upgrade, and arbitrary Move calls each require a dedicated profile. Sharing the Move language with Sui does not make the two transaction adapters interchangeable.

### 11.5 XRP Ledger

Later support can begin with native XRP payments, enrolled account signing mode, canonical serialization, explicit destination tags when required, and fee bounds. Reserve sequence/ticket resources according to the enabled transaction type. Include `LastLedgerSequence` and distinguish provisional submission from a validated ledger outcome. [S19]

Issued assets, trust lines, partial payments, path payments, signer-list changes, regular-key changes, and escrow operations are separate capabilities. When partial payments are added, reconciliation must use actual delivered amounts and not merely the requested amount field.

## 12. Lifecycle and reconciliation

### 12.1 States

```text
DRAFT -> BUILT -> VERIFIED -> POLICY_EVALUATED -> AWAITING_APPROVAL
      -> RESERVED -> AUTHORIZED -> ISSUANCE_COMMITTED
      -> SIGNING -> SIGNATURE_OBSERVED -> SUBMITTED
      -> INCLUDED -> FINALIZED_SUCCESS | FINALIZED_FAILURE
```

Additional states include `REJECTED`, `APPROVAL_EXPIRED`, `ABORTED_BEFORE_ISSUANCE`, `ISSUANCE_UNKNOWN`, `SUBMISSION_UNKNOWN`, `REORGED`, `REPLACEMENT_PENDING`, and `DEFINITIVELY_INVALIDATED`.

A linear display may simplify this lifecycle, but the underlying model tracks intent, candidate, issuance, and chain outcome separately. An operation can have several replacement candidates and only some may have produced signatures.

### 12.2 Transition rules

`AUTHORIZED` does not mean a signature exists. `ISSUANCE_COMMITTED` means assume one can exist. An issuance timeout moves to `ISSUANCE_UNKNOWN`, not safely canceled. A submission timeout moves to `SUBMISSION_UNKNOWN`, not definitive failure.

`CANCEL` before issuance is an internal state transition. After issuance it is a request for a chain-specific replacement/invalidation workflow; the API must not return a guarantee that money cannot move.

Reorgs move chain observations back to an unresolved state and restore appropriate outstanding exposure. Only the chain profile's accepted finality or invalidation evidence releases obligations. Reconciliation independently checks balances, fees, asset movements, and transaction effects rather than trusting broadcaster callbacks.

### 12.3 Chain evidence

Operate a validating node or explicitly trusted evidence infrastructure where practical, with independent providers for cross-checks. Conflicting sources quarantine affected operations. Two matching RPC responses are not a cryptographic proof, and two endpoints from one provider may share one failure domain.

Record state block/slot/ledger, source identities, observed finality/commitment, verifier version, and maximum permitted staleness. Never authorize against a simulator's silently replaced state. Execution can still happen at a later state, which is why general smart-contract activity needs enforceable on-chain bounds or an explicit accepted trust model.

## 13. API and SDK specification

### 13.1 Public resources

```text
POST /v1/vaults
POST /v1/vaults/{vault_id}/wallets
GET  /v1/wallets/{wallet_id}
GET  /v1/wallets/{wallet_id}/balances

POST /v1/destinations/proposals
POST /v1/policies/proposals
GET  /v1/configuration-proposals/{proposal_id}
POST /v1/configuration-proposals/{proposal_id}/approvals

POST /v1/intents
GET  /v1/intents/{intent_id}
GET  /v1/intents/{intent_id}/preview
POST /v1/intents/{intent_id}/approvals
POST /v1/intents/{intent_id}/submit
POST /v1/intents/{intent_id}/cancel

GET  /v1/operations/{operation_id}
GET  /v1/operations/{operation_id}/evidence
GET  /v1/events
POST /v1/vaults/{vault_id}/freeze
POST /v1/recovery-ceremonies/proposals
```

`submit` requests execution of an already approved intent; it is not an authorization bypass. There is no public `sign_arbitrary_hash` endpoint. Native unsigned-transaction import is allowed only for explicitly supported profiles and still undergoes complete decoding and policy verification.

Wallet creation may trigger key generation and configuration approval asynchronously within the application's request lifecycle; it must not expose a deposit address as active until the ceremony and recovery metadata are committed. This is product behavior, not a promise of background work by the author of this RFC.

### 13.2 Example transfer request

```json
{
  "schema_version": 1,
  "vault_id": "treasury-operating",
  "wallet_id": "wallet-evm-enrolled-01",
  "chain_profile_id": "evm-network-approved-v1",
  "operation": {
    "kind": "asset_transfer",
    "asset_id": "asset-registry-entry-42",
    "amount_base_units": "1000000000",
    "destination_id": "approved-counterparty-17",
    "destination_version": 4
  },
  "constraints": {
    "max_network_fee_base_units": "5000000000000000",
    "approval_mode": "bounded_direct_transfer",
    "maximum_successful_payments": 1
  },
  "purpose": "settlement",
  "external_reference": "execution-12345"
}
```

Identifiers and amounts are illustrative; this is not a live transfer. The asset registry entry resolves to exact network and contract/mint identity. The destination resolves to a versioned verified address, not a mutable alias looked up after approval. A Solana request has the same business structure but a different chain profile and wallet/asset identity.

### 13.3 API guarantees

Scope idempotency keys to institution, route, and canonical request body. Repeating a key with a changed request is a conflict. Preserve idempotency and operation-family history across restore and failover.

Use explicit credentials and scopes for proposer, approver, administrator, broadcaster, auditor, and recovery roles. API authentication does not substitute for transaction approval. Webhooks are signed, sequenced, retryable, and treated as at-least-once delivery; consumers deduplicate and reconcile missing sequences.

Representative errors: `UNSUPPORTED_CAPABILITY`, `UNVERIFIABLE_TRANSACTION`, `POLICY_DENIED`, `STALE_POLICY`, `APPROVAL_REQUIRED`, `BUDGET_EXCEEDED`, `RESOURCE_CONFLICT`, `STALE_EVIDENCE`, `ISSUANCE_UNCERTAIN`, `RECOVERY_REQUIRED`, and `AUTHORITY_UNAVAILABLE`. Do not leak cryptographic secrets or sensitive transcript contents through error details.

## 14. Persistence, audit, and observability

Proposed stores: relational operational state for the control plane; separately administered authorization/reservation state; encrypted per-signer protocol state; and append-only audit/evidence storage with independent signed checkpoints.

An audit record contains actor identity, exact object commitments, policy epoch, reservation/issuance transition, signer participation evidence, configuration changes, chain outcome references, previous-event hash, and a signature under the relevant service/domain key. Keep secrets, raw shares, private preprocessing, and sensitive RNG state out of logs.

Hash chaining detects alterations relative to a known checkpoint; by itself it does not stop a malicious operator from presenting two different histories. Independent checkpoints, witness comparison, and a defined authoritative ordering are required. Audit evidence shows what was recorded and validated under declared assumptions; it is not a proof that no other signing path exists.

Observe queue depth, approval wait, evidence age, policy denials, reserved/outstanding exposure, nonce/UTXO/object conflicts, preprocessing exhaustion, signer participation, clock/freshness faults, issuance uncertainty, submitted-versus-finalized divergence, recovery status, and configuration drift. An unexplained balance movement freezes the relevant signing scope pending review.

## 15. Implementation organization and open-source release

### 15.1 Proposed implementation stack

Use Rust for the security model, canonical encoding, minimal transaction verifiers, signer service, and high-assurance state transitions. Use a selected existing crypto backend through a narrowly reviewed binding rather than rewriting its mathematics. Control-plane services may also use Rust; a TypeScript web console and SDK are reasonable outside the signing boundary.

Use existing chain SDKs for building and RPC integration, but keep the verifier logic explicit, pinned, and testable. SDK updates are security changes, not routine dependency bumps when serialization or message semantics change.

A monorepo can look like:

```text
spec/
  threat-model.md
  authorization-envelope.md
  policy-language.md
  lifecycle.md
  chain-profiles/
crates/
  domain-types/
  canonical-encoding/
  policy-kernel/
  authorization-state/
  approval-verifier/
  signer/
  crypto-provider/
  crypto-provider-selected-backend/
  adapter-evm/
  adapter-solana/
  adapter-bitcoin/
  adapter-cosmos/
  adapter-sui/
  adapter-aptos/
  adapter-xrpl/
  audit/
services/
  api/
  builder/
  coordinator/
  broadcaster/
  reconciler/
apps/
  operator-console/
  independent-approval-client/
sdk/
  typescript/
  python/
deploy/
  development-only/
  signer-profiles/
  production-reference/
tests/
  golden-vectors/
  differential/
  fuzz/
  crash-and-rollback/
  adversarial/
  recovery/
models/
  authorization-state-machine/
```

This structure describes ownership and boundaries, not a requirement to deploy dozens of separate services.

### 15.2 Licensing and release integrity

A Fireblocks-backed distribution must account for its GPL-3.0 license and the licenses/notices of all dependencies. Do not assume an FFI or process boundary automatically eliminates obligations. Select a coherent licensing/distribution plan after reviewing the actual chosen sources and intended distribution. [S1]

Publish the core security policy, adapter capability matrix, reproducible-build instructions, dependency inventory, signed releases, upgrade/rollback procedures, security disclosure policy, and audit scope. Do not advertise “audited” based solely on an upstream library's review or on tests of a different commit.

No unaudited remote plugin installation inside signers. New verifier/backend versions require the administrative update process and regression suite. A compromised auto-updater must not install arbitrary share-accessing code across all domains.

## 16. Acceptance test matrix

The tests below are release requirements. Passing them supplies evidence about specified properties; it does not establish comprehensive security.

| ID | Adversarial case | Required result |
|---|---|---|
| A01 | API requests signing without approvals | Every honest signer rejects |
| A02 | Coordinator changes native transaction bytes after approval | Payload/intent mismatch; no honest contribution |
| A03 | Same envelope reused for another vault/network/key | Scope rejection |
| A04 | Wrong asset identity with same symbol/decimals | Registry/identity rejection |
| A05 | One participant malicious, authorized transaction | Safety maintained; progress only if backend and available honest quorum permit |
| A06 | One participant malicious, unauthorized transaction | No valid unauthorized signature |
| A07 | Duplicate request after lost API response | Same operation, no extra payment authorization |
| A08 | Concurrent requests each below remaining limit but over it together | At most permitted aggregate exposure reserved |
| A09 | Split views sent to A+C and B+C | Independent authority prevents inconsistent reservations |
| A10 | Authority unavailable | New issuance fails closed |
| A11 | Crash before/after every MPC state write/output | No one-time-state reuse; uncertainty retained |
| A12 | Snapshot clone/rollback and duplicate active signer | Stale generation fenced; no reusable secret/session |
| A13 | Restore old preprocessing backup | Consumed state cannot reenter circulation |
| A14 | Old policy/configuration presented after privilege revocation | Freshness/epoch rejection |
| A15 | One admin adds a beneficiary or malicious image | Quorum/delay prevents activation |
| A16 | Emergency freeze races signature release | Ordered result; prior releases identified, no false revocation claim |
| A17 | Approval expires after signature issuance | Exposure remains if signature can execute |
| A18 | Broadcaster claims failure while transaction lands | Reconciler records actual chain outcome |
| A19 | EVM fee bump changes recipient/calldata | New unauthorized semantics rejected |
| A20 | EVM EIP-712 permit or EIP-7702 disguised as harmless request | Unsupported/delegation denial |
| A21 | Solana lookup table resolves hidden malicious account | Full account-resolution verification rejects |
| A22 | Solana transfer includes extra authority/close instruction | Unsupported instruction/semantic mismatch |
| A23 | Solana timeout followed by fresh-blockhash retry | No second live payment without invalidation/uniqueness evidence |
| A24 | Token-2022 mint has unknown hook/delegate extension | Unsupported capability rejected |
| A25 | Bitcoin attacker labels external output as change | Descriptor verification rejects |
| A26 | Bitcoin unauthorized sighash mode or misleading input value | Verification rejects |
| A27 | Cosmos unknown message/authz hidden in a batch | Entire candidate rejected |
| A28 | Sui stale/conflicting object or altered gas owner | Resource/semantic rejection |
| A29 | Aptos changes fee payer, signer set, expiration, or chain ID | Candidate/profile verification rejects |
| A30 | False finality or conflicting RPC evidence | Quarantine; no premature budget release |
| A31 | Reorg reverses previously observed inclusion | Lifecycle/exposure corrected |
| A32 | Loss of a permitted signer domain | Reviewed recovery completes a test transfer |
| A33 | Removed signer retains old material | Residual authority evaluated; migration required when threshold could remain compromised |
| A34 | All approvers use compromised primary web frontend | Independent approval verifier detects actual operation mismatch |
| A35 | Incoming/outgoing effect differs from expected contract behavior | Reconciliation discrepancy and containment |
| A36 | Signed transaction held across daily budget reset | Outstanding exposure still counted |
| A37 | Unexpected parser encoding/oversized transaction | Bounded rejection, no service-wide compromise |
| A38 | Unauthorized plugin/update or debug image attempts key unseal | Attestation/configuration policy rejects |

Use model checking for reservation/issuance/freeze/replacement state transitions and property tests for canonicalization and accounting. Fuzz both parsers and MPC integration boundaries. Differential tests must use independent chain-native verifiers, not two wrappers around the same serialization implementation.

## 17. Benchmarks and operational readiness

Benchmark rather than invent throughput. Workloads should include direct native transfers, supported token transfers, varied transaction sizes, concurrency levels such as 1/8/32, all allowed signer subsets, and injected inter-domain RTTs such as 1/20/100 ms. Record p50/p95/p99 policy verification, evidence retrieval, reservation, signing, and end-to-end issuance separately. Report cold/preprocessed crypto paths and honest/malicious/unavailable participant cases independently.

Human approval delay and blockchain finality are separate from signing throughput. A fast crypto microbenchmark does not measure safe custody operations. Benchmark parser limits, recovery time, crash replay, and burst behavior as well as signatures per second.

Before real-value operation, assign named owners for cryptography/integration, EVM semantics, Solana semantics, infrastructure/identity, recovery, and incident response. Obtain independent review of the whole composition, resolve material findings, conduct recovery drills, and agree on explicit exposure limits and stopping criteria with the pilot institution.

## 18. Delivery gates, not calendar promises

| Gate | Deliverable | Pass condition |
|---|---|---|
| G0 — Cryptography and scope | Pinned backend, license decision, exact capabilities and threat model | Native EVM/Solana verification works; desired threshold subsets, failure cases, persistence and recovery interfaces understood |
| G1 — Complete vertical slice | API, immutable intent, independent approvals, local verifiers, reservations, signing, broadcast, reconciliation | EVM and Solana test transfers; API/coordinator compromise cannot bypass policy |
| G2 — State correctness | Issuance uncertainty, replacement, budget concurrency, freeze, crashes, fencing and restore | State-machine/adversarial suite passes, including A08–A18 and A23/A36 |
| G3 — Operational custody | Hardened signer domains, recovery ceremonies, independent approval client, monitored deployment | External architecture/implementation review and actual recovery drill complete |
| G4 — Restricted pilot | Narrow asset/operation allowlists with institution-approved limits | Reconciled operation, staffed response, no unresolved material findings; no broad security claims |
| G5 — Extensions | Bitcoin, then demand-driven Cosmos/Sui/Aptos/XRPL and selected DeFi operations | Separate capability tests, reviews, and rollout for every added profile |

The first demonstration should show not only a successful transfer, but a failed theft attempt: change the recipient after approval, bypass the API and invoke the coordinator directly, replay an approval, and race two withdrawals against one budget. Then delete an allowed signer instance and demonstrate the approved recovery workflow.

[Likely] This is a useful engineering contribution if an institution can independently deploy, verify, recover, and integrate it without surrendering its policy boundary. It becomes a commercially defensible product only with demonstrated demand, credible operations, maintained chain semantics, and repeatable customer deployment—not because the MPC source is public.

## 19. Open design decisions before code freeze

1. Exact MPC backend/commit, supported threshold topology, share refresh/recovery behavior, signature formats, and license plan.
2. Institution-administered authorization-state boundary versus an explicitly Byzantine-tolerant hardened profile.
3. Accepted evidence sources and finality criteria per enrolled network.
4. Exact allowed assets and operation templates for the initial customer.
5. Approver/admin membership, signer failure domains, recovery operators, and software-update roots.
6. Independent approval-client distribution and trusted-display requirements.
7. Canonical encoding field specification and native-payload conformance vectors.
8. Whether future policies require execution-time enforcement through audited on-chain accounts/programs rather than signing-time controls alone.

## Sources

Public protocol/vendor facts were checked against the following primary documentation on 2026-10-19. References establish specific documented behaviors, not the correctness or production readiness of this proposed architecture. Pin source and implementation versions at project kickoff; mutable documentation is not a release specification.

- **S1 — Fireblocks MPC library and license:** `https://github.com/fireblocks/mpc-lib`
- **S2 — Fireblocks MPC integrator/security model:** `https://github.com/fireblocks/mpc-lib/blob/main/SECURITY-MODEL.md`
- **S3 — EIP-1559 transaction and signing format:** `https://eips.ethereum.org/EIPS/eip-1559`
- **S4 — EIP-712 typed data; replay-protection limitation:** `https://eips.ethereum.org/EIPS/eip-712`
- **S5 — EIP-7702 delegated account code:** `https://eips.ethereum.org/EIPS/eip-7702`
- **S6 — Solana transaction/message signatures:** `https://solana.com/docs/core/transactions/transaction-structure`
- **S7 — Solana durable nonces and lifecycle warning:** `https://solana.com/docs/core/transactions/durable-nonces`
- **S8 — Solana versioned transactions and lookup tables:** `https://solana.com/docs/core/transactions/versioned-transactions`
- **S9 — Solana transfer-hook integration:** `https://solana.com/docs/tokens/extensions/transfer-hook-integration`
- **S10 — Solana permanent delegates:** `https://solana.com/docs/tokens/extensions/permanent-delegate`
- **S11 — BIP-340 Schnorr signatures:** `https://bips.dev/340/`
- **S12 — BIP-174 PSBT:** `https://bips.dev/174/`
- **S13 — BIP-341 Taproot:** `https://bips.dev/341/`
- **S14 — AWS Nitro attestation-conditioned key release:** `https://docs.aws.amazon.com/enclaves/latest/user/kms.html`
- **S15 — AWS CloudHSM supported mechanisms:** `https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html`
- **S16 — Cosmos SDK SignDoc and signing:** `https://docs.cosmos.network/sdk/latest/learn/concepts/encoding`
- **S17 — Sui transaction authentication:** `https://docs.sui.io/develop/transactions/transaction-auth/auth-overview`
- **S18 — Aptos transaction structure:** `https://aptos.dev/build/guides/first-transaction`
- **S19 — XRP Ledger reliable submission:** `https://xrpl.org/docs/concepts/transactions/reliable-transaction-submission`
- **S20 — Fireblocks signing-boundary callback architecture:** `https://developers.fireblocks.com/cosigners/callback-handler/create-api-co-signer-callback-handler`
