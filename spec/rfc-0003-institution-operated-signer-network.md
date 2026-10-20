# Open Institutional Custody — RFC 0003
## Institution-operated signer networks on Commonware

Version: 0.2-proposed (adds §15, the approver light client)  
Prepared: October 20, 2026  
Companion to: Open Institutional Custody — RFC 0001 and RFC 0002 (October 19, 2026)  
Status: Proposed architecture. No Commonware integration, network deployment, performance result, security audit, or consensus-safety claim exists for this composition. Commonware interfaces named below were read from the published `v2026.9.0` source on 2026-10-20 and must be re-pinned at kickoff.

## 0. Decision

[Likely] Let each institution run the RFC 0001 signing quorum as a small permissioned peer network that only it administers. Build the network from Commonware primitives for authenticated transport, peer-set management, optional Byzantine ordering, and storage. Keep chain-native threshold signing behind `oic-crypto-provider`. Keep the RFC 0001 authorization contract unchanged. Never place secret material in an ordered log or a multi-recipient message.

The product contract is:

> An institution installs signer nodes in trust domains it chooses and admits them through a roster signed by its administrative quorum. The result is a private network in which every honest signer independently verifies the policy and the exact native payload before contributing to a threshold signature. Peers outside the roster cannot connect. Ordering records, verification attestations, and audit evidence are public inside the institution. Key shares, one-time state, and protocol secrets never leave the signer boundary, except as point-to-point protocol messages to named session participants.

The network is a deployment shape for RFC 0001, not a new trust model. It is not a public blockchain, a token, a cross-institution consensus system, or a hosted service. It does not remove the trust placed in the authorization-state authority unless the replicated profile (§6.3) is selected and its assumptions hold. Even then, it does not protect against the institution's own root administrator if one person controls every trust domain.

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** describe proposed requirements, as in RFC 0001.

### 0.1 What Commonware supplies and what it does not

[Certain] The following primitives and stability levels appear in Commonware `v2026.9.0`. Commonware defines ALPHA as "breaking changes expected" and BETA as "wire and storage formats stable". [K1]

| Need | Commonware primitive (`v2026.9.0`) | Stability | Use in this RFC |
|---|---|---|---|
| Authenticated, encrypted P2P between known keys at known addresses | `commonware_p2p::authenticated::lookup` | BETA | Default transport (§4) |
| The same, with addresses discovered among authorized keys | `commonware_p2p::authenticated::discovery` | BETA | Optional when node addresses are dynamic |
| Mutually authenticated encrypted streams | `commonware_stream::encrypted` (signed handshake, X25519, ChaCha20-Poly1305) | BETA | Used through p2p |
| Node identity keys | `commonware_cryptography::ed25519` | BETA | Transport identity |
| HSM-friendly identity keys | `commonware_cryptography::secp256r1` | ALPHA | Excluded from production until promoted |
| BFT ordering | `commonware_consensus::simplex` with `marshal` | BETA | Replicated-authority profile only (§6.3) |
| Attributable certificates | `simplex::scheme::ed25519`, `commonware_cryptography::certificate::Scheme` | BETA | Ordering and fault evidence |
| Threshold BLS12-381 DKG and resharing | `commonware_cryptography::bls12381::dkg` (BETA); `commonware_glue::dkg` (ALPHA) | — | Not used for chain keys; excluded from v1 (§8.4) |
| Certificates over an externally sequenced stream | `commonware_consensus::aggregation` | ALPHA | Not in the production profile |
| Fetching content by key from peers | `commonware_resolver::p2p` | BETA | Content distribution (§4.2) |
| Append-only and key-value storage | `commonware_storage::{journal, archive, metadata}` | BETA | Audit journal and node state |
| Authenticated databases | `commonware_storage::qmdb` | ALPHA | Excluded |
| Production async runtime | `commonware_runtime::tokio` | BETA | Node runtime |
| Deterministic simulation | `commonware_runtime::deterministic`, `commonware_p2p::simulated` | ALPHA | Tests only |
| Simplex certificate verification in the browser | Exoware `@exowarexyz/simplex/wasm` (separate project, not part of the Commonware Library) | ALPHA | Optional read path for the approver client (§15.7) |

[Certain] Commonware does **not** supply threshold ECDSA over secp256k1, FROST or another threshold Ed25519 scheme, BIP-340 signing, chain transaction semantics, policy evaluation, approvals, or custody recovery. Its threshold primitives are BLS12-381 only. A search of the `v2026.9.0` source finds no secp256k1 or FROST implementation. Commonware therefore cannot serve as the MPC backend for EVM or Solana keys. It is the network, ordering, and storage substrate around that backend. [K1, K9]

Production builds MUST compile with `RUSTFLAGS="--cfg commonware_stability_BETA"`, which Commonware provides to fail builds that use lower-stability APIs. Depending on an ALPHA primitive then becomes a build failure rather than a review comment. [K1]

### 0.2 Initial scope and non-goals

Initial scope: one institution and one environment per network; three to seven signer nodes; deployment modes D1 and D2 (§12); the RFC 0001 EVM and Solana adapters; a FROST-Ed25519 candidate backend for Solana (`frost-ed25519 = "2.1"` is already pinned in the workspace, and `oic-crypto-provider-frost-ed25519` is reserved); a secp256k1 backend chosen under the open RFC 0001 §6.1 decision.

Non-goals: peering between institutions (open question §19.11); public validators, staking, or a token; permissionless discovery; a hosted multi-tenant network; Byzantine tolerance against an administrator who controls every trust domain; running third-party code inside signer nodes.

## 1. Architecture

```text
 INSTITUTION X, environment "mainnet"
 p2p namespace = OIC/P2P/v1 || X || mainnet || roster_genesis_hash

   Treasury apps, RFC 0002 workflow controller, approval clients
                    | node API (mTLS; not trusted to authorize)
           +--------v---------+
           |  Gateway node(s) |  intake, content store, session coordinator
           +--------+---------+
                    | Commonware p2p (lookup): roster-admitted keys and IPs only
 ---------------------------------------------------------------------------
     |                    |                    |                     |
 +---v----------+  +------v-------+  +---------v----+   +------------v------+
 | Signer A     |  | Signer B     |  | Signer C     |   | Authority         |
 | domain:      |  | domain:      |  | domain:      |   | D1: one node      |
 | security-ops |  | treasury-inf |  | recovery     |   | D2: simplex x 3f+1|
 | net process  |  | net process  |  | net process  |   +---------+---------+
 |   | IPC      |  |   | IPC      |  |   | IPC      |             |
 | signer-core  |  | signer-core  |  | signer-core  |    ordered public and
 | verifier +   |  | verifier +   |  | verifier +   |    confidential records;
 | one share    |  | one share    |  | one share    |    never secrets
 +--------------+  +--------------+  +--------------+
 ---------------------------------------------------------------------------
          | secondary peers (read-only)          |
   +------v-------+                      +-------v--------+
   | Witness /    |                      | Extension node |
   | auditor      |                      | (own protocol) |
   +--------------+                      +----------------+
```

The diagram is logical. One host may run several roles, subject to the placement rules in §2.1 and §3.2. Distinct administrative domains are required where marked, as in RFC 0001 §1.

### 1.1 Layers

| Layer | Owner | Contents | Carries secrets? |
|---|---|---|---|
| L0 Runtime and transport | Commonware `runtime`, `p2p`, `stream` | Connections, channels, quotas | Transport keys only, held in the net process |
| L1 Membership | `oic-membership` (new) | Signed roster, committees, peer-set derivation, channel ACL | No |
| L2 Ordering | `oic-authorization-state`, optionally `simplex` | Policy epochs, reservations, releases, freezes, roster activations | No |
| L3 Custody protocol | `oic-peer-wire` (new) | Verification requests, attestations, session control, protocol frames | Class S frames on `mpc.*` channels only (§8.1) |
| L4 Signer core | `oic-signer` (reserved), `oic-crypto-provider`, adapters, `oic-policy-kernel` | Local verification, release gate, shares, one-time ledger | Yes, and they never leave |
| L5 Extensions | Institution code | Custom services and protocols | No |

### 1.2 Design rules

- **R1 — Roster is admission.** The admin-signed roster is the only source of peer identities, addresses, roles, and committees. Nothing is learned by trust on first use.
- **R2 — Local verification is mandatory.** Attestations, certificates, and receipts received from the network are evidence. They never authorize a signer to skip its own payload and policy verification (I1, I3).
- **R3 — No secrets on ordering.** Class S data (§8.1) MUST NOT appear in an ordered log, a block, a broadcast, a resolver response, an audit record, a metric, or a crash dump.
- **R4 — One security encoding.** Security objects keep the RFC 0001 canonical CBOR encoding and domain-separated hashes. `commonware-codec` frames transport messages and block containers only. A security object is never decoded through a second canonical codec.
- **R5 — Process separation.** The Commonware stack runs in a network process. Shares run in a separate signer-core process or enclave behind a narrow local interface (§8.2).
- **R6 — Fail closed.** Roster, policy, ordering, or generation uncertainty stops new issuance. No degraded single-node signing mode exists.
- **R7 — One network per institution and environment.** Mainnet and testnet nodes never share a namespace, roster, or keys (I8).
- **R8 — BETA or better.** Production depends only on Commonware primitives at BETA or higher (§0.1).
- **R9 — Extensions stay outside signers.** Extension code never runs on a signer node and never reaches signer-core.
- **R10 — Distinct keys.** Node transport keys, signer-core participant keys, share material, approval and administrative credentials, audit keys, and the D1 authority receipt key are all different keys.
- **R11 — Browsers verify; they do not vote or sign.** An approver's browser is a light client that verifies certificates and payloads and produces a passkey approval. It never runs consensus, never holds a key share, and never signs a chain transaction (§15).

## 2. Node roles

| Role | Responsibilities | Holds | Must not hold | Peer class |
|---|---|---|---|---|
| Gateway | Node API intake; content-addressed store of intents, candidates, and evidence; RFC 0001 coordinator (opens sessions, relays protocol frames, aggregates public outputs) | Transport key | Shares, admin credentials, authority key | Primary |
| Verifier | Re-decodes candidates, re-evaluates policy, signs attestations; holds no share | Transport key, attestation key | Shares | Primary |
| Signer | Verifier duties, plus one participant share per enrolled key, the release gate, and a durable one-time state ledger | Net process: transport key. Signer-core: participant key, sealed shares | Other shares, authority key, admin credentials | Primary |
| Authority | D1: runs the existing `oic_authorization_state::Authority`. D2: a `simplex` replica executing the authority state machine | D1: receipt key. D2: consensus vote key | Shares | Primary |
| Witness | Follows checkpoints or the finalized log, verifies them, stores evidence, alerts on divergence | Transport key | Votes, shares | Secondary |
| Recovery | Cold participant for an approved recovery path; offline by default | Sealed share | — | Absent; primary only inside a ceremony roster epoch |
| Extension | Institution-built service on reserved channels with read-only record subscriptions | Its own keys | Signer-core access, `mpc.*` channels | Secondary, or primary on its own channels only |

[Certain] In `lookup`, secondary peers can still receive `Recipients::All` traffic on established connections, although they are never dialed outbound. [K2] Therefore no restricted channel may use `Recipients::All` (§4.2).

### 2.1 Placement rules

- A signer and the D1 authority MUST be in different administrative domains (RFC 0001 §5.2).
- Gateway and signer roles MAY share a host, because the coordinator is untrusted. Signer-core stays a separate process.
- In D2, an authority replica MAY share a domain with a signer if the domain-compromise check in §3.2 still passes.
- Witness and extension nodes MUST NOT hold shares or vote.

## 3. Trust boundaries, committees, and membership

### 3.1 Trust hierarchy

`Institution → Environment → TrustDomain → Node`.

A `TrustDomain` records the facts RFC 0001 §7.2 requires to be documented: who controls root IAM, hardware or firmware trust, approved-image signing, backups, KMS policy, operator credentials, and recovery material. Two regions in one cloud account under one administrator are one trust domain.

### 3.2 Committees

| Committee | Members | Defined by | Rule |
|---|---|---|---|
| `KeyCommittee(key_id, key_epoch)` | Signer participants for one `KeyDescriptor` | Keygen ceremony output | Threshold `t` MUST pass `oic_crypto_provider::check_topology` against the backend descriptor |
| `VerificationCommittee` | Signers by default, plus optional diverse verifiers | Roster | May be required by policy (§7) |
| `AuthorityCommittee` | D1: one authority plus a fenced standby. D2: `n = 3f + 1` replicas | Roster | At most `f` replicas per tolerated compromise set |
| `WitnessSet` | Witness nodes | Roster | Read-only |
| `AdminQuorum` | Human or HSM credentials, never node keys | RFC 0001 §1.2 | Signs rosters, policies, and freezes |

The roster declares `tolerated_domain_compromises` (default 1). Roster validation MUST reject a roster in which any tolerated set of compromised domains holds `t` or more shares of any key, or more than `f` authority replicas. This turns the RFC 0001 failure-domain requirement into a mechanical check instead of a deployment note.

### 3.3 Roster object

```text
NetworkRosterV1
  domain = OIC/NETWORK_ROSTER/v1
  institution_id, environment_id
  roster_epoch                    # equals the Commonware peer-set index (u64)
  previous_roster_hash            # zero for genesis
  genesis_hash                    # hash of epoch 0; part of the p2p namespace
  commonware_release, wire_version
  trust_domains[]: domain_id, administrators, failure-domain notes
  nodes[]:
    node_id, domain_id, roles[]
    transport_public_key          # commonware_cryptography::ed25519::PublicKey
    address                       # SocketAddr, or DNS name when allow_dns
    peer_class = primary | secondary
    participant_keys[]            # signer-core keys, one per ParticipantId
    approved_build_hashes[]       # verifier and signer measurements
    signer_instance_generation    # RFC 0001 §6.3 fencing
  committees[]: committee_id, kind, members[], threshold, key_id?, key_epoch?
  channel_acl[]: channel, sender_roles[], receiver_roles[], max_message_size, quota
  tolerated_domain_compromises
  activation: not_before, authority_commit_reference
  admin_signatures[]              # CONFIG_PROPOSAL quorum, RFC 0001 §4.2
```

Proposed new domain tags for `oic_domain_types::domains`: `OIC/NETWORK_ROSTER/v1`, `OIC/VERIFY_ATTESTATION/v1`, `OIC/PEER_MESSAGE/v1`, `OIC/AUTHORITY_BLOCK/v1`, and the namespace prefix `OIC/P2P/v1`. Proposed new identifiers: `NodeId`, `TrustDomainId`, and `CommitteeId`, using the existing `id_type!` macro.

### 3.4 Membership lifecycle

**Genesis.** In an offline ceremony, each domain generates its node transport key and signer-core participant keys locally and submits the public keys with build measurements. The admin quorum signs roster epoch 0. The roster is distributed out of band, and every domain compares its hash over an independent channel. No node accepts a roster it learned from a peer before genesis.

**Change.** A roster change is a privileged configuration transaction (RFC 0001 §4.2) with a before/after diff, an admin quorum, and an ordered activation. Nodes apply epoch `e` only after the authority has committed it. Each node then calls `AddressableManager::track(e, peers)` on its `lookup::Oracle`, with primary and secondary peers taken from the roster. `tracked_peer_sets` is at least 2 so that the old and new sets overlap during transition. [K2, K4]

**Address-only change.** Use `AddressableManager::overwrite`. This is not a privilege change, but it is still signed by the owning domain's administrator and recorded in the log, because addresses feed the IP filter.

**Removal.** Publish a new epoch without the node and call `Blocker::block` for its key. Removing a signer does not revoke its share. A share refresh is possible only if the backend declares it; otherwise RFC 0001 §7.4 key replacement and asset migration apply (A33).

**Replacement of a signer instance.** Allocate a new `signer_instance_generation` and order a `SignerFence` command (`OIC/SIGNER_FENCE/v1` already exists). Peers reject protocol frames from older generations.

**Divergence.** Nodes exchange `(roster_epoch, roster_hash)` on the control channel. A node on a different roster participates in no session until it converges. [Certain] Commonware warns that discovery messages can be misinterpreted when peers disagree on peer-set composition. [K3]

## 4. Networking

### 4.1 Transport profile

- Use `commonware_p2p::authenticated::lookup::Network::new(context, cfg)`. Start from `lookup::Config::recommended(crypto, namespace, listen, max_peers_per_set, max_message_size)`, then set `allow_private_ips = true` for private networks (the recommended default is `false`), set `bypass_ip_check = false` (MUST), set `allow_dns` per deployment, and set `tracked_peer_sets >= 2`. [K15]
- Namespace: `OIC/P2P/v1 || institution_id || environment_id || genesis_hash`. [Certain] The encrypted stream requires a pre-shared, application-specific namespace to prevent cross-application replay. Binding the institution, environment, and genesis keeps testnet and other institutions' nodes from completing a handshake. [K5]
- [Certain] The handshake provides mutual authentication, forward secrecy, and session uniqueness. It does **not** provide anonymity, padding against traffic analysis, or future secrecy after a static key compromise. [K5] Node transport keys are therefore security-critical, and message sizes on `mpc.*` and `content` channels SHOULD be padded to fixed buckets in D3.
- [Certain] The handshake validates timestamps against `synchrony_bound`. [K5] Nodes need disciplined time (NTP or PTP). Clock skew is a liveness failure, never a safety failure.
- [Certain] Inbound connections from IPs outside the registered peer union are rejected. Commonware describes its rate limits as best-effort and recommends an external proxy against targeted abuse. [K2] Deployments place nodes on private subnets, VPN, or dedicated links, with firewall allowlists generated from the roster.
- Use `authenticated::discovery` only when node addresses are dynamic. It still admits only tracked keys, and its bootstrappers MUST be the institution's own nodes. [K3]

### 4.2 Channel plan

[Certain] `Channel` is a `u64`. Channels are registered with `Network::register(channel, quota)` before `Network::start`. Each channel has one bounded inbound mailbox shared by all peers, and arrivals are dropped when it is full. The network does not inspect payload semantics. Sending a payload larger than `max_message_size` panics. [K2]

| Channel | Name | Data class | Senders → receivers | Recipients | Mode |
|---|---|---|---|---|---|
| 0 | `control` | P | All primary ↔ all primary | `Some` | All |
| 1–3 | `consensus.vote`, `consensus.certificate`, `consensus.resolver` | P, C | Authority replicas | Engine-managed | D2 |
| 4–5 | `marshal.blocks`, `marshal.backfill` | P, C | Replicas → followers (signers, witnesses) | `Some` | D2 |
| 10 | `content` | C | Gateway ↔ verification committee | `Some` | All |
| 11 | `attest` | P | Verifiers, signers → gateway, authority | `Some` | All |
| 12 | `authority.rpc` | C | Gateway ↔ D1 authority | `One` | D1 |
| 20 | `mpc.sign` | S | Members of one session's `participant_set` | `One` only | All |
| 21 | `mpc.ceremony` | S | Ceremony participants | `One` only | All |
| 30 | `audit` | P | All → witnesses | `Some` | All |
| ≥ 1024 | extension range | P, C | As granted in `channel_acl` | Never `All` | D4 |

[Certain] `simplex::Engine::start` takes three network pairs (vote, certificate, resolver), which is why channels 1–3 are reserved. [K6]

Channel rules:

- `Recipients::All` is forbidden on channels 10–21 and in the extension range. Even protocol rounds that are logically broadcast are sent as individual `Recipients::One` messages to roster-listed participants.
- Senders check the `channel_acl` and message size before sending. Receivers check again that the authenticated sender holds a permitted role for that channel and roster epoch.
- Every message is idempotent under `(session_id, round, sequence)` or a content hash, because mailbox drops are normal.

### 4.3 Wire frame

```text
PeerFrameV1                     # commonware-codec framed; metadata is an untrusted hint
  wire_version: u16
  roster_epoch: u64
  kind: u16                     # per-channel message enum
  body: bytes                   # canonical CBOR security object or backend payload
```

## 5. Request lifecycle over the network

```text
control plane      gateway         verifiers/signers       authority          signer-cores
     | intent,candidate,  |                 |                    |                    |
     | evidence --------->| store by hash   |                    |                    |
     |                    |-- VerifyReq --->| fetch, decode,     |                    |
     |                    |<-- Attestation -| evaluate policy    |                    |
     | approvals (approval clients, outside the peer network)    |                    |
     |                    |-- Reserve ------------------------->| ordered; Reserved   |
     |                    |-- Release ------------------------->| ordered; possibly   |
     |                    |                                     | issued              |
     |                    |-- SessionOpen(envelope, release evidence) -------------->|
     |                    |                                     |  re-verify all,    |
     |                    |<=========== mpc.sign frames (One-to-One) ===============>|
     |                    | aggregate (public op), verify_result                     |
     |<-- signature ------| record SignatureObserved ---------->|                    |
```

| Step | RFC 0001 state | Network action | Verified by |
|---|---|---|---|
| 1 | `DRAFT` → `BUILT` | The control plane submits the intent, candidate, and evidence bundle to a gateway | Gateway stores by content hash only |
| 2 | `VERIFIED` → `POLICY_EVALUATED` | The gateway sends `VerificationRequest{intent_hash, candidate_id, revision, evidence_bundle_hash, policy_epoch}`; members fetch content over `content` | Each member runs the adapter's `verify_candidate` and `oic_policy_kernel::evaluate`, then signs an attestation |
| 3 | `AWAITING_APPROVAL` | Each approver's light client verifies the operation itself and submits a passkey approval through the node API; the authority orders it as an `Approve` command (§15.5) | The authority verifies the WebAuthn assertion; signers re-verify the grants in the envelope. Approver credentials are never node keys |
| 4 | `RESERVED` | D1: `Authority::reserve` returns a `Reserved` receipt. D2: a `Reserve` command is finalized in a block | D2 replicas re-evaluate policy themselves and never trust the proposer's `policy_decision` |
| 5 | `AUTHORIZED` → `ISSUANCE_COMMITTED` | D1: `Authority::release` returns a `Release` receipt and an `IssuanceRecord`. D2: a `Release` command is finalized | Ordered against freezes by commit sequence |
| 6 | `SIGNING` | The coordinator sends `SessionOpen` to exactly `envelope.participant_set` | Each signer-core checks the envelope hash, the release evidence (`verify_receipt` in D1; finalized inclusion in D2), its own re-verification of candidate and policy, key epoch, and generation, then calls `CryptoProvider::start_signing_session` |
| 7 | `SIGNATURE_OBSERVED` | The coordinator aggregates public outputs (only when the descriptor declares aggregation public) and calls `verify_result` | The signature and transcript hash are recorded and ordered |
| 8 | `SUBMITTED` … `FINALIZED_*` | The RFC 0001 broadcaster and reconciler run, possibly as extension nodes | Observations are ordered through `record_observation` |

### 5.1 Verification attestations

```text
VerificationAttestationV1
  domain = OIC/VERIFY_ATTESTATION/v1
  institution_id, environment_id, roster_epoch
  node_id, verifier_build_hash, adapter_id, adapter_version
  intent_hash, candidate_id, candidate_revision
  decoded_operation_hash, evidence_bundle_hash
  policy_id, policy_epoch, policy_hash
  decision = ALLOW | DENY | REQUIRE_APPROVALS, reason_codes[]
  attested_at
  signature                      # attestation key from the roster, ed25519
```

Policy may require an attestation quorum before reservation (§7). An attestation never replaces signer-local verification. The kernel is deterministic, so two approved builds that disagree on identical inputs indicate a bug or a compromise. The operation is quarantined and an alert is raised (RFC 0001 §4.1: verifier disagreement fails closed).

### 5.2 Coordinators, sessions, and timeouts

Any gateway may coordinate, and coordinators are untrusted. Signer-cores accept only the `signer_session_id` bound in both the envelope and the release evidence. The one-time state ledger rejects a second session for the same release. A session that times out after release moves the operation to `ISSUANCE_UNKNOWN` with exposure retained. A new session requires a new release under RFC 0001 rules, never a silent retry.

## 6. Ordering and the authorization-state authority

### 6.1 Why the network still needs an authority

RFC 0001 §5.1 shows that two overlapping signer quorums sharing one malicious member can each authorize against a different budget view. Gossip among signers does not fix this: P2P delivery is not a counter. Every release therefore passes through a single ordered authority state, either one trusted service (D1) or a replicated state machine (D2).

### 6.2 D1: single authority over the network

The existing `oic_authorization_state::Authority` runs on a node in its own domain, behind channel 12. Receipts stay Ed25519 signatures over `OIC/AUTHORITY_RECEIPT/v1` hashes, and signer-cores check them with `verify_receipt`. Witnesses hold `SignedCheckpoint`s (`verify_checkpoint`). An authority that reopens storage uses `FileAuthorityStore::open_with_witness` to detect rollback. A standby is fenced by the existing fence token passed to `Authority::open`. The trust statement is exactly RFC 0001's: the authority is trusted and not Byzantine fault tolerant.

### 6.3 D2: replicated authority over `simplex`

- **Size.** `n = 3f + 1` replicas, with `f = 1` initially: four replicas in at least four trust domains, subject to the §3.2 check.
- **Scheme.** `simplex::scheme::ed25519`. [Certain] It is attributable, needs no DKG, and its activity stream exposes `ConflictingNotarize`, `ConflictingFinalize`, and `NullifyFinalize` fault evidence. [K6, K8] The `bls12381_threshold` scheme is rejected for v1: its signatures are non-attributable, it requires a DKG, and its benefits (succinct certificates, embedded VRF) matter little at four to seven nodes.
- **Blocks.** A block is an ordered list of authority commands: `RegisterIntent`, `EnrollCredential`, `Approve` (§15.5), `SetPolicy`, `Reserve`, `Release`, `Freeze`, `Unfreeze`, `AbortBeforeIssuance`, `ApprovalExpired`, `RecordObservation`, `RosterActivate`, and `SignerFence`. Command bodies are canonical CBOR inside a `commonware-codec` container. The authority application implements `commonware_consensus::Automaton` (`propose`, `verify`), `Relay`, and `Reporter`. [K7]
- **Determinism.** The existing `Authority` mixes transition logic, receipt signing, and storage. D2 requires extracting a pure transition, `apply(state, command, now) -> (state', result)`, that D1 keeps using through `AuthorityStore::transact`. `verify` re-executes every command, including policy evaluation, rather than trusting values the proposer supplies.
- **Time.** The block timestamp feeds the existing `Clock` trait. Voters reject proposals whose timestamps go backwards or exceed a skew bound from local time. This adds a new assumption about time (§19.2).
- **Release evidence.** Signer-cores act only on **finalized** commands, never on notarized ones. Signer nodes follow the log through `marshal` and execute the same transition function. Their release evidence is local re-execution of the finalized log plus the finalization certificate. No authority signing key exists in D2.
- **Freeze.** A freeze is an ordered command and remains totally ordered against releases. The local emergency halt (§10.1) needs no consensus.
- **Liveness.** If more than `f` replicas are lost, finalization stops and new issuance stops (RFC 0001 A10). There is no forced-finalization path.
- **Honest scope.** D2 tolerates `f` Byzantine replicas inside one institution. It does not tolerate an administrator who controls a quorum of domains. RFC 0001 §5.2 requires reusing a reviewed implementation. `simplex` is BETA and maintained, but whether that amounts to sufficient review of this composition is open (§19.1).

## 7. Policy verification in a peer network

- **One kernel everywhere.** Every verifier and signer-core runs the pinned `oic_policy_kernel::evaluate`. Its `verifier_build_hash` MUST appear in the node's `approved_build_hashes`. Signer-core refuses to start on an unlisted build, and peers ignore attestations from unlisted builds.
- **Ordered policy.** `SetPolicy` carries admin signatures checked with `verify_policy_admin_signatures` and is activated only by the authority. Nodes reject policy epochs that have not been committed (I6). `PolicyInput.expected_policy_epoch` comes from the authority state, not from the gateway.
- **No network inside evaluation.** Content is fetched over `content` before evaluation, checked against the bound hashes, and passed in. Evaluation stays pure (RFC 0001 §4.1).
- **Attestation requirements.** Proposed optional rule field: `required_attestations { committee_id, threshold, require_distinct_domains }`. The rule is checked against attestation signatures and bindings. Whether this belongs in the kernel or at the authority is open (§19.9).
- **Diverse verification.** RFC 0001 §1.3 notes that a common decoder bug misleads every honest signer. High-tier vaults MAY require attestations from a verifier built on an independent decoder implementation.

## 8. MPC boundaries

### 8.1 Data classes

| Class | Examples | Allowed carriers | Forbidden carriers |
|---|---|---|---|
| P: public inside the institution | Roster, policy hashes, envelope hashes, receipts, issuance records, attestations, certificates, checkpoints, public keys, `KeyDescriptor` | Any channel, ordered log, audit, witnesses | — |
| C: confidential | Intents, candidates, evidence, approval grants, counterparties, amounts | `content` to committee members; D2 blocks (replicas must execute them); encrypted at rest | Extensions without a grant; logs and metrics in clear |
| S: secret | Key shares, sealed share blobs, nonces and preprocessing, DKG private dealings, signer-core participant private keys, node transport private keys, sealing and KMS keys, all `mpc.*` frames | Inside signer-core only, except protocol frames sent `One`-to-one to named session participants | Ordered log, blocks, broadcast, resolver, audit, crash dumps, metrics, extensions |

Some threshold-signing round outputs, such as commitments and signature shares, are not secret in the cryptographic sense. They are release-sensitive, so everything on `mpc.*` is handled as Class S. At the type level, Class S types MUST NOT implement the traits used for block, broadcast, or resolver encoding.

### 8.2 Process boundary

The network process runs the Commonware runtime, p2p, the consensus follower, and the gateway or coordinator logic. Signer-core runs `oic-signer`, `oic-crypto-provider`, adapters, the policy kernel, and the `OneTimeStateLedger`. They communicate through a narrow local interface:

```text
signer-core local interface (proposed, oic-signer)
  attest(verification_request, content) -> VerificationAttestation
  open_session(envelope, release_evidence) -> Accepted | Rejected(reason)
  deliver(signed_peer_message) -> Outbound(Vec<signed_peer_message>) | ShareReady | Aborted
  status(signer_session_id) -> SessionStatus
  halt(domain_operator_signature)       # local emergency stop; no consensus
```

There is no `sign(hash)` call. A compromised network process can delay, drop, or replay inputs, but it cannot make signer-core contribute outside an envelope that signer-core has verified and that is backed by release evidence.

### 8.3 End-to-end protocol authentication

Commonware authenticates the node's transport key, which lives in the network process. To keep a compromised network process from forging protocol frames for its own participant, signer-core SHOULD sign each outbound `oic_crypto_provider::PeerMessage` with its participant key under `OIC/PEER_MESSAGE/v1`. The signature binds `session_id`, `key_id`, `key_epoch`, `from`, `to`, `round`, `sequence`, `protocol_version`, and the payload hash. Receivers check the signature against the roster participant key and `signer_instance_generation`. [Guessing] The cost of one Ed25519 signature per frame is acceptable at three to seven participants; this must be measured (§19.4). When a backend protocol needs confidential point-to-point payloads (for example, private DKG dealings), signer-core additionally encrypts them to the recipient's signer-core key, so the network process never sees them in plaintext.

### 8.4 Backends and Commonware threshold cryptography

- **Chain keys.** Chain keys use `CryptoProvider` only. The release gate is unchanged: `advance_protocol` MUST NOT return a share-revealing step until release evidence is verified and the one-time record is consumed (RFC 0001 §5.4, §6.3). Keygen runs over `mpc.ceremony`. Only the resulting `KeyDescriptor` is ordered; sealed shares stay in each signer-core.
- **Commonware BLS12-381 threshold.** It is not used for chain keys, which it cannot sign for. It is also excluded from v1 internal certificates. [Certain] `feldman_desmedt` relies on synchrony to bound share reveals. Up to `2f` shares can be revealed under asynchrony. Revealed shares are public. `commonware_glue::dkg` is ALPHA and places dealer logs on chain. [K9, K10] Any later use for compact attestation certificates must treat every revealed share as compromised and trigger a reshare.
- **One-time state.** The ledger stays local and durable. `SignerFence` commands order generation changes, and peers reject frames from stale generations.

## 9. Auditability

- **Per-node journal.** Each node appends `AuditEvent`s (the existing type, with `previous_event_hash` and a service signature under a dedicated audit key) to a `commonware_storage::journal`. Events include roster applied, attestation issued, session opened or rejected with reason, one-time record consumed, share released, halt toggled, and peer blocked.
- **Signer-local evidence.** Before contributing, a signer records the envelope hash, its verification decision, and its release-evidence reference. This shows what that signer verified. It does not show that no other signing path exists (RFC 0001 §14).
- **Ordered history.** D1: authority events plus signed checkpoints held by witnesses. D2: the finalized log with attributable certificates, plus exportable equivocation evidence.
- **Witnesses.** Witnesses are secondary peers that verify and store checkpoints or blocks. An auditor outside the institution receives offline exports or checkpoint hashes rather than becoming a peer, which preserves "only own nodes".
- **Export bundle.** The roster chain (each epoch signed and linked by `previous_roster_hash`), policy activations, attestations, receipts or finalizations, issuance records, signatures, observations, per-node journals, the Commonware release, and build hashes. RFC 0002 C25 applies: an independent party reconstructs the history from the export.
- **Limits.** Hash chains and witnesses detect tampering relative to a known checkpoint. They do not prevent a D1 authority from presenting different histories to parties that never compare.
- **Observability.** Connectivity per roster epoch, blocked peers, handshake failures (often clock skew), mailbox drops per channel, consensus views and nullifications, finalization latency, attestation disagreements, session aborts, remaining preprocessing, and roster divergence. Metrics and labels never contain Class C or Class S content, and Commonware telemetry labels are reviewed for this.

## 10. Failure and recovery

| Failure | Detection | Safe behavior | Recovery |
|---|---|---|---|
| One signer down, threshold still reachable | Control heartbeats | Sessions use another allowed subset if the backend supports it; otherwise wait | Restart, or RFC 0001 §7.4 restore |
| Signers below threshold | Session cannot start | No signatures | Approved restore or recovery ceremony |
| Coordinator crashes mid-session | Session timeout | `ISSUANCE_UNKNOWN`; exposure retained | New session only under RFC 0001 rules |
| D1 authority unavailable | RPC failure | No new issuance | Fenced standby; witness checkpoint check on open |
| D2: at most `f` replicas down | Missing votes | Progress continues | Restart and state sync through `marshal` |
| D2: more than `f` down or partitioned | No finalization | Issuance halts | Restore replicas; never force finalization |
| Network partition | Connectivity metrics | Minority cannot release; no split-brain issuance | Heal |
| Clock skew beyond `synchrony_bound` | Handshake failures | Liveness loss only | Fix time |
| Roster divergence | Control-channel hash mismatch | Refuse sessions | Apply the missing epoch from the ordered log |
| Signer snapshot rollback or clone | Stale generation; duplicate identity | Peers reject the stale generation; old one-time records are tombstoned | Re-enrollment (RFC 0001 §6.3) |
| Node transport key compromise | Investigation, alerts | Block the peer; publish a new roster epoch | Rotate the key; if signer-core is suspected, refresh or replace shares |
| Domain compromise | Alerts, reconciliation | Freeze; remove the domain | Key replacement where the threshold could be compromised (A33) |
| Commonware upgrade changes storage format | Release notes, staging | Staged rollout with a rollback path | [Certain] `v2026.9.0` writes V1 blobs that older binaries cannot read unless layouts are restricted first. [K12] Upgrades follow RFC 0002 C22 |
| Local storage corruption | Checksums on open | Node refuses to start | Resync or restore |

### 10.1 Local emergency halt

Every signer-core accepts a halt signed by its own domain's operator credential. Halting is always safe because it only removes liveness, so it needs no consensus and keeps working during an ordering outage. Unhalting requires the same credential and is recorded in the log. A halt is distinct from the global ordered freeze of RFC 0001 §4.2.

## 11. Security and threat model

### 11.1 Assets

Chain key shares, authorization integrity, budget and resource consistency, audit integrity, availability, and confidentiality of business data.

### 11.2 Adversary

The adversary may control the institution's network path; any gateway, coordinator, extension, or witness; the network process of any signer; up to `tolerated_domain_compromises` trust domains, provided the §3.2 check passed; and arbitrary internet hosts. As in RFC 0001 §1.3, it may replay, reorder, delay, corrupt, and drop messages.

### 11.3 Not defended

An administrator or coalition controlling every domain or the admin quorum; `t` colluding signer domains; more than `f` replica domains in D2; a common-mode bug in Commonware, the kernel, or an adapter on every node; physical coercion. The chain verifies only the native signature, so sufficiently many colluding signers can bypass off-chain policy (RFC 0001 §1.3).

### 11.4 Threats

| ID | Threat | Mitigation | Residual |
|---|---|---|---|
| T01 | Outsider connects as a peer | `lookup` admits only tracked keys from registered IPs; firewall allowlist | Handshake-path DoS |
| T02 | Testnet or other-institution node replays into mainnet | Namespace binds institution, environment, and genesis | Misconfiguration still blocked by separate keys |
| T03 | Gateway alters candidate or envelope | Signer-local verification against the envelope and release evidence | — |
| T04 | Gateway impersonates a signer | Transport authentication plus participant signatures | — |
| T05 | Signer network process compromised | No shares in the network process; signed `PeerMessage`s; signer-core verification | Withholding or delay (DoS) |
| T06 | Witness or extension observes MPC traffic | `One`-only recipients; channel ACL on both ends; secondary peers are never committee members | Traffic analysis without padding |
| T07 | D2 replica equivocates | `simplex` safety with `n ≥ 3f + 1`; attributable evidence | More than `f` compromised replicas means RFC 0001 authority-compromise semantics apply |
| T08 | D1 authority shows split views | Single ordering; witnesses compare checkpoints | Authority compromise (RFC 0001 baseline) |
| T09 | Stale roster or policy replayed | Epochs are ordered and monotone; nodes reject older epochs | — |
| T10 | One administrator forges a roster | Admin quorum signatures | Quorum compromise |
| T11 | Signer instance cloned | Generation fencing | Window before detection |
| T12 | Channel flooding | Per-channel quotas, bounded sizes, idempotent retries | Liveness |
| T13 | ALPHA Commonware code reaches production | `commonware_stability_BETA` build gate | — |
| T14 | Malicious dependency update | Pinned versions; updates reviewed as security changes; reproducible builds (RFC 0001 §15.2) | Supply-chain compromise before pinning |
| T15 | Common decoder bug | Optional diverse verifier | Without one, all honest signers are misled |
| T16 | Metadata leakage of operation patterns | Optional padding on `mpc.*` and `content` | Timing within the private network |

## 12. Deployment modes

| Mode | Nodes | Ordering | Use | Claims allowed |
|---|---|---|---|---|
| D0 Development | One process: `deterministic` runtime, `p2p::simulated`, dev crypto provider | In-memory authority | Local development and tests; ALPHA allowed | None. Keys labeled development; refuses production profiles (RFC 0002 C02) |
| D1 Networked signers | Three signers (2-of-3) in three domains, one or two gateways, a single authority in a separate domain, at least one witness | D1 authority | Minimum production profile | RFC 0001 baseline |
| D2 Replicated authority | D1 plus four `simplex` replicas across at least four domains; signers follow the log | `simplex` | Hardened authority | Authority tolerates one Byzantine replica under `simplex` assumptions |
| D3 Hardened | D1 or D2 plus a TEE signer-core profile (RFC 0001 §7.1), diverse verifiers, padded channels, external witness exports | As base | High-value vaults | As base, plus the declared TEE assumptions |
| D4 Extended | Any mode plus extension nodes (§14) | As base | Institution services | No change to custody claims |

Example D2 placement that passes the §3.2 check with one tolerated domain compromise:

| Domain | Signer share (2-of-3) | Authority replica (`f = 1`) | Other |
|---|---|---|---|
| security-ops | A | R1 | Gateway |
| treasury-infra | B | R2 | Gateway |
| recovery | C (may be cold) | R3 | — |
| audit | — | R4 | Witness |

Compromising any single domain yields at most one share (below 2) and one replica (at most `f`). [Certain] Commonware supports Linux and macOS, recommends only Linux for production, requires AVX2, BMI2, and ADX on x86-64, and does not support Windows. [K1]

## 13. APIs

### 13.1 Embedding API (proposed `oic-node`)

```rust
// Proposed. Types marked "existing" are in this repository today;
// commonware_* paths are from v2026.9.0. Everything else is new.
pub struct NodeConfig {
    pub institution_id: InstitutionId,                      // existing
    pub environment_id: EnvironmentId,                      // existing
    pub node_id: NodeId,
    pub roster: SignedRoster,                               // oic-membership
    pub identity: commonware_cryptography::ed25519::PrivateKey,
    pub listen: std::net::SocketAddr,
    pub storage_root: std::path::PathBuf,
    pub signer_core: Option<SignerCoreEndpoint>,            // signers only
    pub authority: AuthorityProfile,                        // Single { .. } | Replicated { .. }
    pub extensions: Vec<Box<dyn Extension>>,
}

pub trait Extension: Send + 'static {
    /// Channels this extension owns; all must be >= 1024 and granted in the roster ACL.
    fn channels(&self) -> Vec<ChannelSpec>;
    fn start(self: Box<Self>, ctx: ExtensionContext) -> ExtensionHandle;
}
```

`ExtensionContext` provides Commonware `Sender` and `Receiver` handles for the extension's own channels, a read-only stream of ordered public records, a roster view, and a node API client with proposer scope. It does not provide a signer-core handle, `mpc.*` channels, or the raw `lookup::Oracle`. Commonware registers channels before `Network::start`, so adding an extension requires a node restart and a roster ACL change.

### 13.2 Node API

Served on mTLS (HTTP or gRPC) on an operator network, never on the P2P port:

```text
POST /v1/node/requests                       # gateway intake: intent, candidate, evidence
GET  /v1/node/requests/{candidate_hash}/attestations
GET  /v1/node/sessions/{signer_session_id}
GET  /v1/node/roster                         # active epoch, peers, connectivity
POST /v1/node/roster/proposals               # returns an unsigned proposal for the admin quorum
GET  /v1/node/log?from={commit_sequence}     # ordered public records (D1 events or D2 blocks)
GET  /v1/node/audit/export
POST /v1/node/halt                           # local emergency halt; domain operator signature
GET  /v1/node/health
POST /v1/node/approvals                      # approver client: grant + WebAuthn assertion -> Approve (§15.5)
GET  /v1/node/approvals/{intent_id}          # approvals recorded on the finalized log
```

The RFC 0001 §13 resources remain the institution-facing API and call the node API. The node API has no signing endpoint, just as RFC 0001 has no `sign_arbitrary_hash`.

### 13.3 Peer messages

| Channel | Message kinds |
|---|---|
| `control` | `Hello{roster_epoch, roster_hash, generation, build_hash}`, `Heartbeat` |
| `content` | `Get{hash}`, `Put{hash, body}`, served through `commonware_resolver::p2p` |
| `attest` | `VerificationRequest`, `VerificationAttestation` |
| `authority.rpc` | `RegisterIntent`, `Reserve`, `Release`, `Abort`, `Observe`, and the corresponding receipts or errors |
| `mpc.sign` | `SessionOpen`, `SessionAccept`, `SessionReject`, `SignedPeerMessage`, `SessionAbort` |
| `mpc.ceremony` | `CeremonyOpen`, `SignedPeerMessage`, `CeremonyResult{KeyDescriptor}` |
| `audit` | `Checkpoint`, `JournalHead` |

### 13.4 Errors

Reuse the existing `ErrorCode` values and add `ROSTER_MISMATCH`, `PEER_NOT_ADMITTED`, `STALE_GENERATION`, `ATTESTATION_DISAGREEMENT`, `SESSION_REJECTED`, `NODE_HALTED`, and `ORDERING_UNAVAILABLE`. Error details never include Class C or Class S content.

## 14. Building services and protocols on top

Supported patterns:

1. **Read-only consumers** of ordered records: reconciliation, the RFC 0002 §6 journal, alerting, and reporting.
2. **Proposers** that submit intents through the node API, such as the RFC 0002 §5 workflow controller. They receive no signing shortcut.
3. **Peer protocols among the institution's own nodes** on extension channels. Examples: reconciliation attestations in which nodes sign chain-observation digests (a candidate for `consensus::aggregation` once it reaches BETA), or netting between the institution's subsidiaries.
4. **Separate Commonware networks** with their own namespace and roster for heavy protocols, isolating them from the custody network.

Extension rules:

- **E1.** No extension runs on a signer node or reaches signer-core (R9).
- **E2.** In-protocol signatures use a distinct namespace, `OIC/EXT/<name>/v1`.
- **E3.** Channels are at or above 1024 and listed in the roster `channel_acl` with quotas and size limits.
- **E4.** No Class S data. Class C data only with an explicit grant in the roster.
- **E5.** Extensions never use `Recipients::All`.
- **E6.** An extension's failure must not block custody channels; quotas and separate mailboxes enforce this.

## 15. Approver light client

### 15.1 Decision

[Likely] Each approver uses a pinned approver client. It is a WASM light client that learns institution state only from verified, finalized records. It decodes the candidate itself, shows the exact operation, and asks the approver's passkey to sign a challenge that commits to that operation. The signed approval is then ordered as an authority command. The client never trusts the console's description, the gateway, or the storage service that served the data.

This implements the independent approval display of RFC 0001 §4.3 and the independent approval client of RFC 0002 §8. It does not change who signs: business approval quorums, MPC quorums, and administrative quorums stay separate (RFC 0001 §1.2). When the policy's approval threshold is met, signer nodes sign as in §5. The browser does not.

### 15.2 What we take from Commonware's end-to-end verification demo

Patrick O'Grady's Paradigm Frontiers talk introducing Exoware (transcript supplied by the RFC author, not independently checked; T1) describes a design that verifies everything end to end. Its claims: a chain whose validators verify passkey signatures directly; a browser that verifies, in WASM, certificates and inclusion and state proofs against a static network identity; and Exoware, a log and store that serves those artifacts. The talk also says Exoware's own replication is crash-fault tolerant rather than Byzantine fault tolerant, because clients verify everything against the chain's certificates. And it says the Exoware interface is a ConnectRPC and protobuf specification, so a team can replicate the data into its own instance.

| Pattern in the talk | Adaptation here | Reason |
|---|---|---|
| Static network identity (Tempo reshares a BLS threshold key every epoch and keeps the group key constant) embedded in the site; a change is a red alert | Pin the roster genesis hash, admin quorum public keys, and threshold in the client build. Follow the admin-signed roster chain (§3.3) to learn each epoch's ed25519 replica set | D2 uses the attributable `ed25519` scheme without a DKG (§6.3). A static BLS identity needs `commonware_glue::dkg` (ALPHA) and accepts share-reveal semantics (§8.4). Kept as an option (§19.15) |
| Identity kept in the site or in browser storage | Identity is compiled into a signed, reproducible client build, never stored in `localStorage` or cookies. A mismatch blocks approval; it is not a warning | Whoever serves the page controls what the browser verifies (§15.4) |
| The chain verifies passkeys directly | The authority state machine verifies each WebAuthn assertion deterministically in D1 and D2. Signers re-verify the grants carried in the envelope | Same idea; the approval becomes an ordered, auditable record |
| All cryptography and proof code compiled to WASM | The same, plus adapter decoding and preview hashing compiled to WASM, so the approver sees decoded native bytes | RFC 0001 §4.3: a passkey signature proves approval of a challenge, not that the holder saw an honest description |
| Exoware serves certificates and proofs; clients verify | Exoware is an optional, self-hosted, untrusted read path (§15.7). The client can read the same artifacts from witness nodes instead | Business data is Class C; a hosted service would see it (§15.8) |
| QMDB state proofs for balances and history | Deferred. v1 verifies whole finalized blocks, which are small at institution scale | `commonware_storage::qmdb` is ALPHA (§0.1) |

### 15.3 Architecture

```text
 Approver device
 +-------------------------------------------------------------+
 | Approver client (signed, reproducible build)                 |
 |  pinned: institution, environment, roster genesis hash,      |
 |          admin quorum keys, approved verifier build hashes,  |
 |          simplex namespace, approver client origin           |
 |  WASM:   roster-chain check, simplex ed25519 certificate     |
 |          check, block decode, oic-adapter-* decode,          |
 |          preview hash, canonical CBOR                        |
 |  passkey: WebAuthn get(challenge = approval grant hash)      |
 +-----------+-----------------------------------+-------------+
             | read (untrusted)                  | write
             v                                   v
 +-----------------------------+     +---------------------------+
 | Exoware store (self-hosted) |     | Gateway node API          |
 | or witness node /v1/node/log|     | POST approval -> Approve  |
 +--------------+--------------+     +-------------+-------------+
                ^ upload finalized                 | ordered
                | blocks + certificates            v
 +--------------+---------------------------------------------------+
 | Authority (D1 single, or D2 simplex x 4): verifies WebAuthn,     |
 | records Approve; later Reserve and Release need its quorum       |
 +------------------------------------------------------------------+
```

The browser is a light client (R11). It is not a consensus participant: tabs close, devices sleep, and a browser cannot accept the inbound TCP connections `p2p::authenticated` uses. Even if three approver devices stayed online permanently, three nodes tolerate zero faults under `n = 3f + 1`, so they could not form a safe consensus set.

### 15.4 Trust anchors and distribution

The client build pins `institution_id`, `environment_id`, the roster genesis hash, the admin quorum public keys and threshold, the approved adapter and verifier build hashes, the simplex namespace, and the client's own WebAuthn origin and RP ID. From these it verifies the roster chain (each epoch admin-signed and linked by `previous_roster_hash`) and derives the ed25519 participant set used to verify finalizations in that epoch.

Distribution is the hard part. If the same server that runs the console also serves the verifier, a compromised server can ship a verifier that lies, and a pinned key does not help. The client MUST therefore come from a channel the console cannot rewrite: a signed desktop application, a signed browser extension, or an installed web app whose build hash is checked against an independently published value. WebAuthn binds each credential to an RP ID and reports the calling origin in `clientDataJSON`. Each distribution channel produces a different origin, and platform support for asserting the institution's RP ID varies. The authority enrolls the exact accepted origins, and each channel must be tested per platform (§19.16).

In D1 there are no consensus certificates. The client verifies authority-signed receipts and events with the D1 authority key and compares checkpoints with a witness. This is weaker: it inherits the single-authority trust of RFC 0001 §5.2. The full end-to-end verification story requires D2.

### 15.5 Approval flow

1. **Notification.** The approver receives a pointer (`intent_id`, `candidate_id`, revision). The pointer is untrusted.
2. **Fetch and verify state.** The client fetches the latest finalized blocks and certificates and checks them against the current roster epoch. It confirms that the intent is registered with the expected `intent_hash`, that the active policy epoch and hash match, that the destination registry version matches, that the approver's credential is enrolled with the required role, and that no freeze covers the vault.
3. **Fetch and decode the operation.** The client fetches the candidate and evidence bundle (Class C) and checks them against their committed hashes. It decodes them with the pinned adapter compiled to WASM and computes `preview_hash(candidate_id, candidate_revision, decoded_operation_hash, evidence_bundle_hash)` with the existing `oic-policy-kernel` function. It MAY run `oic_policy_kernel::evaluate` locally to show which rules apply. Enforcement remains with the authority and signers.
4. **Display.** Exact asset and network, full beneficiary address and registry version, amount in base units with registry decimals, maximum fees, authority changes, purpose, policy epoch, warnings, and how many approvals already exist on the finalized log.
5. **Sign.** The client builds the existing `ApprovalGrantBody` with `GrantScope::ExactCandidate` or `BoundedDirectTransfer`. The WebAuthn challenge is the 32-byte grant hash, `SHA256("OIC/APPROVAL/v1" || CanonicalEncode(body))`. The client calls `navigator.credentials.get` with that challenge, the institution's RP ID, `allowCredentials` restricted to the enrolled credential, and `userVerification: "required"`.
6. **Submit.** The client posts the grant and assertion to the gateway node API. The gateway submits an `Approve` command. The approval travels through the gateway and the authority, never through the store.
7. **Authority verification.** The authority checks:
   - the credential is enrolled through an admin-approved `EnrollCredential` and holds the role the grant claims;
   - the ES256 signature verifies over `authenticatorData || SHA256(clientDataJSON)`;
   - `clientDataJSON.type == "webauthn.get"`, its `challenge` equals the base64url grant hash, and its `origin` is an enrolled approver-client origin;
   - `rpIdHash == SHA256(rp_id)` and the user-present and user-verified flags are set;
   - the grant is unexpired, its policy epoch is current, the approver is not the proposer, and each credential approves an intent at most once.
8. **Confirmation.** The client waits until the `Approve` command is finalized, verifies that finalization, and only then shows "approval recorded".
9. **Signing.** Later, `Reserve` and `Release` require the policy quorum of recorded approvals. Signer-cores re-verify every grant in `AuthorizationEnvelopeBody.approval_grants` (I1, I3).

Representation: add `SchemeId::WebAuthnEs256`. For that scheme, `SignatureBytes.bytes` is the canonical CBOR of `{authenticator_data, client_data_json, signature}`. `ApprovalGrant` keeps its current shape. Today approval credentials are verified as `Ed25519Pure` only, so the policy kernel and the authority both need a pure WebAuthn verifier. [Certain] Neither the Commonware `v2026.9.0` source nor the Exoware repository contains a WebAuthn verifier; the talk's passkey-verifying chain is a demo whose code is not in either repository. The verifier is new code. It belongs in the workspace's reserved `oic-approval-verifier` crate, shared by the kernel, the authority, and the WASM client, and is reviewed as part of the security kernel.

### 15.6 Passkey guidelines

- **Separate approval credentials from login.** Approval credentials MUST NOT double as console login credentials, and the approver RP ID SHOULD differ from the console's. Otherwise a compromised console could request a "login" assertion whose challenge is a grant hash and receive a valid approval. The origin check in step 7 is the second line of defense.
- **Enrollment is configuration.** Enrollment, replacement, and removal are configuration transactions with an admin quorum, an activation order, and an audit record (RFC 0001 §4.2). Account recovery by email or SMS MUST NOT enroll an approval credential.
- **Prefer device-bound authenticators.** Synced passkeys can be restored through the provider account that syncs them, so that account effectively controls the credential. Policy SHOULD require device-bound, attested authenticators (allowlisted AAGUIDs) for high-tier vaults and MAY accept synced passkeys for low tiers. Many synced passkeys provide no attestation, which itself rules them out wherever attestation is required.
- **Do not rely on signature counters.** Many passkeys report a counter of zero. A counter that decreases is treated as a clone alert, but counters are not a clone defense.
- **Distinct people, two of three.** Policies SHOULD use two of three approvers rather than three of three, so one absent approver does not stop operations. Three credentials on one person's devices count as one approver.
- **Bounded lifetime.** Grants carry short `expires_at` values. An expired grant needs a fresh approval and is never silently extended.

### 15.7 Exoware usage

- **Role.** Exoware is an optional read path that caches finalized blocks and certificates (later, proofs) so many approver clients can read them with low latency. It is never a source of truth and never part of the approval write path. Because clients verify everything, it needs no Byzantine fault tolerance, matching the talk's description (T1).
- **Writer.** A witness or extension node, never a signer (E1), uploads finalized artifacts with `exoware-simplex` (`SimplexClient`) or the TypeScript `SimplexWriter`. [K17]
- **Reader.** The client uses `SimplexReader` with a verifier from `createWasmSimplexVerifier({ scheme: 'ed25519', payload: 'sha256', identity: 'ed25519', namespace, verificationMaterial, verifyHeader })`. `verificationMaterial` is the epoch's ed25519 participant set, derived from the verified roster chain. A caller-owned WASM `verify_block(payload, header, body)` decodes the authority block format and checks that the body matches the certified header. [Certain] The Exoware verifier supports the `ed25519` Simplex scheme with `ed25519` identities. It treats certificates as opaque records whose payload-to-header relationship the caller must verify, and it does not trust a server's flag that a body is present. [K17]
- **Hosting.** Self-host `exoware-server` behind institution access control, or run the local simulator for development. Hosted Exoware would see Class C business data and is not used unless that data is encrypted for approvers or the institution decides otherwise. [Certain] `exoware-server` and both Exoware SDKs are labeled ALPHA. Exoware pins Commonware by git revision (`2fd3af88`), not by the `2026.9.0` release. [K16, K18] Certificate-encoding compatibility with the pinned Commonware release therefore needs conformance tests. Until Exoware reaches a stability level this RFC accepts, it stays out of the production profile, and the client reads the same artifacts from witness nodes through `GET /v1/node/log`.
- **Freshness.** A store can withhold the newest finalization but cannot forge one. A stale view cannot produce an unsafe approval, because the authority rejects grants bound to a superseded policy epoch, destination version, or frozen vault. The client still shows how old its latest verified finalization is, refuses approval beyond a configured age, and cross-checks the height with a second source (a witness node).

### 15.8 Data access and privacy

The talk's demo shows public payment data. An institution's intents, counterparties, and amounts are Class C. The client authenticates to the node API or store with a session credential separate from its approval credential. Read access is scoped to the vaults the approver may approve. Blocks shown to an approver may carry other vaults' commands, so v1 either scopes block reads by vault through a per-vault content projection that is verified against the block commitment, or accepts that approvers see the whole block. This is open (§19.17).

### 15.9 Rules

- **AL1.** The client never holds key shares and never signs chain transactions.
- **AL2.** The client verifies finalization, never notarization alone, before showing state as committed.
- **AL3.** Trust anchors are compiled into a signed, reproducible build; changes ship only as a new release.
- **AL4.** Every displayed field comes from verified records or from content checked against a committed hash.
- **AL5.** The WebAuthn challenge is always the grant hash; the client never signs a challenge it did not construct.
- **AL6.** Approval credentials are separate from login, admin, and node credentials.
- **AL7.** Approvals are submitted through the gateway and are effective only once ordered by the authority.
- **AL8.** Stores, including Exoware, are untrusted and optional.
- **AL9.** Missing, stale, or unverifiable data blocks approval; there is no "approve anyway" button.
- **AL10.** Approval outcomes are recorded in the per-node audit journals and in the export bundle (§9).

## 16. Interoperability

### 16.1 With this repository

| Crate | Role here | Required change |
|---|---|---|
| `oic-domain-types` | Shared objects | Add `NodeId`, `TrustDomainId`, `CommitteeId`, and the new domain tags |
| `oic-canonical-encoding` | Canonical CBOR for new objects | None |
| `oic-policy-kernel` | Evaluation on every verifier and signer | Optional attestation rule (§7) |
| `oic-authorization-state` | D1 authority | D1: none. D2: extract the pure transition; block-time `Clock` |
| `oic-crypto-provider` | Backend boundary; `PeerMessage` travels on `mpc.sign` | Participant-signature wrapper outside the backend |
| `oic-adapter-evm`, `oic-adapter-solana` | Verification in signer-core and verifiers | None |
| `models/authorization-state-machine` | Stateright model | Extend with ordered replication, halt, and roster epochs |
| New: `oic-membership`, `oic-peer-wire`, `oic-node`, `services/signer-node` | Roster, wire protocol, embedding, binary | New |
| Reserved: `oic-signer`, `oic-audit`, `services/coordinator` | Signer-core, journals, coordinator | Implement as described here |
| New: `apps/approver-client`; reserved: `oic-approval-verifier` | §15 light client and WebAuthn verification | WASM build of the crates below; `oic-approval-verifier` is shared by the kernel, authority, and client |
| `oic-domain-types`, `oic-canonical-encoding`, `oic-policy-kernel`, `oic-adapter-api`, `oic-adapter-solana` | Compiled into the approver client | [Certain] Each passes `cargo check --target wasm32-unknown-unknown` today |
| `oic-adapter-evm` | Compiled into the approver client | [Certain] Fails for `wasm32-unknown-unknown` today: the workspace enables `rand_core`'s `getrandom` feature, which `k256` pulls in, and `getrandom 0.2` needs its `js` feature on that target. Fix with a wasm-only `getrandom` feature or by removing the feature from verification-only builds |

The envelope is unchanged. `participant_set` names a subset of the `KeyCommittee`, and `verifier_build_hash` is checked against the roster.

### 16.2 With Commonware

- **Toolchain.** [Certain] Commonware `v2026.9.0` declares `rust-version = "1.95.0"` and `edition = "2024"`. This workspace declares `rust-version = "1.85"`. Either the workspace MSRV is raised, or Commonware is confined to crates with their own `rust-version`. Decision required (§19.7).
- **Transport refactor.** [Certain] On `main` (commit `c18a6b9`, 2026-10-19), `commonware_stream` replaces `encrypted` with an `Upgrader` trait and `SakeCups` (a SAKE handshake inside CUPS), and `lookup::Config::local` takes an upgrader instead of a signer. This is not released. [K13] Pin `2026.9.0` and treat the upgrade as a wire-protocol migration with mixed-version tests. BETA promises a migration path for wire and storage changes, not API stability. [K1]
- **Licensing.** Commonware is MIT OR Apache-2.0, compatible with this workspace's Apache-2.0. The GPL backend question in RFC 0001 §15.2 is unchanged.

### 16.3 With external systems

- **HSM and KMS.** Node transport keys and audit keys SHOULD live in an HSM where the Ed25519 mechanism is supported. Commonware's HSM-friendly `secp256r1` is ALPHA (§19.6).
- **D1 storage.** The D1 authority can keep the RFC 0001 PostgreSQL candidate behind `AuthorityStore`; the network only transports requests to it.
- **Approval clients.** They stay outside the peer network and keep their own credentials.
- **Third-party cosigners.** A recovery provider's domain may be admitted only as a trust domain the institution lists explicitly in its own roster. It is still the institution's network.
- **Other institutions.** Not in v1. A future profile may export finalized certificates or receipts to a counterparty as verifiable evidence without sharing peers. Commonware's `bridge` example demonstrates sending consensus certificates between networks, but it is an ALPHA example. [K14]

## 17. Acceptance tests

These complement A01–A38 (RFC 0001) and C01–C28 (RFC 0002).

| ID | Scenario | Required result |
|---|---|---|
| N01 | Key not in the roster dials a signer | Rejected; nothing delivered on any channel |
| N02 | Roster key connects from an unregistered IP | Rejected (`bypass_ip_check = false`) |
| N03 | Testnet node with a valid testnet key connects to mainnet | Handshake fails on the namespace |
| N04 | Gateway alters the candidate in `SessionOpen` | Signer-core rejects; no protocol output |
| N05 | Gateway replays `SessionOpen` under a new session id for the same release | Rejected by binding and the one-time ledger |
| N06 | Compromised network process forges a frame from another participant | Transport authentication fails |
| N07 | Compromised network process forges a frame for its own participant | Participant signature check fails |
| N08 | Extension node sends or listens on `mpc.sign` | ACL rejection at both ends; no Class S delivered |
| N09 | Code sends `Recipients::All` on a restricted channel | Sender refuses; covered by a test |
| N10 | Class S type is passed to a block, broadcast, or resolver encoder | Compile-time failure |
| N11 | Roster change signed below the admin quorum | Not applied |
| N12 | Nodes on different roster epochs | Sessions refused until convergence |
| N13 | Removed signer retains its share | Residual authority flagged; key replacement workflow required (A33) |
| N14 | Cloned signer joins with an old generation | Peers reject; old one-time records tombstoned |
| N15 | D2 replica equivocates | Safety maintained; evidence exported |
| N16 | D2 loses two of four replicas | No finalization; no issuance; resumes after recovery |
| N17 | Signer receives a notarized but unfinalized release | No contribution |
| N18 | D2 proposer claims `Allow` for a denied candidate | Replicas reject the block |
| N19 | D2 proposer timestamp beyond the skew bound | Block rejected |
| N20 | Freeze races release in D2 | Single total order; identical result on all followers |
| N21 | Local halt during an active session | That signer stops contributing; no unsafe partial state |
| N22 | Verifiers disagree on identical inputs | Quarantine and alert |
| N23 | One peer floods a channel | Quotas apply; other channels progress |
| N24 | Clock skew beyond `synchrony_bound` | Handshake failures; liveness loss only |
| N25 | Commonware upgrade during in-flight operations | Compatible progression or safe halt; rollback path documented |
| N26 | Production build uses an ALPHA Commonware module | Build fails under `commonware_stability_BETA` |
| N27 | Seeded partitions, drops, and crashes in the deterministic simulation | RFC 0001 invariants hold across all seeds |
| N28 | Store serves a finalization signed by a non-roster key, or one from a superseded epoch | Client rejects; approval blocked |
| N29 | Store serves a block body that does not match the certified header | `verify_block` fails; nothing displayed |
| N30 | Console shows a different beneficiary than the candidate bytes | Client shows the decoded beneficiary; the grant binds the real `preview_hash` |
| N31 | Console requests a login assertion whose challenge is a grant hash | Separate RP ID or credential prevents it; authority rejects the wrong origin |
| N32 | Assertion with user verification absent, wrong `type`, wrong origin, or wrong `rpIdHash` | Authority rejects |
| N33 | Replayed approval for a second intent, or a second approval by the same credential | Rejected by grant binding and once-per-credential rule |
| N34 | Approval bound to an old policy epoch or destination version after a change | Authority rejects; a fresh approval is required |
| N35 | Store withholds the newest finalization, hiding a freeze | Grant rejected at the authority; client shows stale-view age and refuses beyond the limit |
| N36 | Client build hash differs from the published value, or trust anchors are modified | Client refuses to run in production mode |
| N37 | Proposer approves their own intent | Authority rejects |
| N38 | Unenrolled or removed passkey approves | Authority rejects; signers reject the grant in the envelope |

## 18. Phased implementation

| Phase | Deliverable | Pass condition |
|---|---|---|
| N0 — Pin and spike | MSRV decision; Commonware `2026.9.0` in an isolated crate; stability gate in CI; three simulated nodes exchanging `PeerMessage`s over `p2p::simulated` with the dev provider | N26; simulation reproducible by seed |
| N1 — Membership and transport | `oic-membership` with roster validation (placement, topology) and golden vectors; `oic-peer-wire`; `lookup` bring-up with channel ACLs | N01–N03, N11, N12 |
| N2 — Signer network (D1) | Signer-core interface; gateway coordinator; single authority over the network; dev provider, then FROST-Ed25519 on Solana devnet | A01–A12 over real sockets; N04–N10, N13, N14, N21 |
| N3 — Attestations and audit | Attestation objects, journals, witness checkpoints, export | N22; C25 reproducible from the export |
| N4 — Replicated authority (D2) | Pure authority transition; `simplex` application; `marshal` followers; extended stateright model | N15–N20; model check passes |
| N5 — Extensions and hardening | Extension API with one reference read-only consumer; TEE profile; padding | N23–N25; independent review of the composition |
| N6 — Approver light client | WebAuthn verifier in the kernel and authority; `EnrollCredential` and `Approve`; WASM client reading from witness nodes, then optionally from a self-hosted Exoware store | N28–N38; client builds reproducibly; an approval recorded in D2 is verified end to end in the browser |

D1 is on the critical path for RFC 0001 G1 and RFC 0002 Gate B. D2 is an optional hardened profile and does not block the pilot. If N0 shows that Commonware cannot meet a requirement here without ALPHA code, either the profile changes or that requirement waits. Lowering the stability gate is not an option.

## 19. Unresolved questions

1. Is BETA `simplex` a sufficient "reviewed implementation" for the RFC 0001 §5.2 hardened profile, and what independent review of this composition is required before real value depends on D2?
2. What is the time source in D2: proposer timestamps with a skew bound, or external time attestations? How does the choice affect rolling windows and receipt expiry?
3. Are Class C commands acceptable in D2 blocks on every replica, or should blocks carry only commitments, with content fetched separately?
4. What does end-to-end participant signing cost per frame, and does a selected backend's transcript already bind sender authentication?
5. Which encryption scheme protects confidential backend payloads (such as DKG dealings) to signer-core keys?
6. Can node identity keys live in HSMs: Ed25519 support across target HSMs versus waiting for `secp256r1` to leave ALPHA?
7. Should the workspace raise its MSRV to 1.95, or should Commonware be isolated in crates with their own `rust-version`?
8. When should the network migrate to the unreleased `Upgrader` / SAKE / CUPS transport, and how long must mixed versions interoperate?
9. Should attestation quorums be a policy-kernel input (a kernel change) or be enforced by the authority or gateway?
10. Should recovery participants stay in the roster while offline, or be admitted only in per-ceremony roster epochs?
11. Should third-party cosigner domains or cross-institution evidence exchange be allowed, and with what federation semantics?
12. What traffic-padding policy is affordable on `mpc.*` and `content`?
13. Is there any acceptable use of Commonware BLS threshold certificates given the share-reveal semantics?
14. What is the minimum viable node count for small institutions? Can D1 run on four hosts, with gateway and signer co-located and the authority on the fourth?
15. Should the approver client pin the roster chain (current design) or a static BLS threshold identity maintained by resharing, as Tempo does per the talk? The second gives one long-lived key but needs a DKG, non-attributable certificates, and acceptance of share reveals.
16. Which client distribution channel (signed desktop app, extension, installed web app) can assert the institution's WebAuthn RP ID on each target platform without letting the console's origin produce approvals?
17. Should approvers see whole authority blocks, or only per-vault projections verified against block commitments?
18. When does Exoware reach a stability level acceptable for the production read path, and which Commonware release will it pin?

## Sources

Commonware facts were checked on 2026-10-20 against tag `v2026.9.0` (commit `d476a2361ce6840d2b9d0aa6fb30a924429046d4`) unless noted. Exoware facts were checked the same day at the commit named in K16. crates.io lists `2026.9.0` as the latest release of every Commonware crate named here. Documentation and source comments describe intended behavior; they are not an audit of the library or of this composition.

- **K1 — Commonware primitives, stability levels, stability cfg, platforms, license:** `https://github.com/commonwarexyz/monorepo/blob/v2026.9.0/README.md`
- **K2 — `p2p::authenticated::lookup`: peer sets, IP filter, secondary peers, mailboxes, size panic, rate limits:** `https://github.com/commonwarexyz/monorepo/blob/v2026.9.0/p2p/src/authenticated/lookup/mod.rs`
- **K3 — `p2p::authenticated::discovery` and peer-set synchronization warning:** `https://github.com/commonwarexyz/monorepo/blob/v2026.9.0/p2p/src/authenticated/discovery/mod.rs`
- **K4 — p2p traits (`Recipients`, `Sender`, `Receiver`, `Manager`, `AddressableManager`, `Blocker`):** `https://github.com/commonwarexyz/monorepo/blob/v2026.9.0/p2p/src/lib.rs`
- **K5 — Encrypted stream handshake properties and requirements:** `https://github.com/commonwarexyz/monorepo/blob/v2026.9.0/stream/src/encrypted.rs`
- **K6 — `consensus::simplex` protocol, engine channels, activity and fault evidence:** `https://github.com/commonwarexyz/monorepo/blob/v2026.9.0/consensus/src/simplex/mod.rs`
- **K7 — Consensus traits (`Automaton`, `Relay`, `Reporter`) and `aggregation` stability:** `https://github.com/commonwarexyz/monorepo/blob/v2026.9.0/consensus/src/lib.rs`
- **K8 — Certificate schemes; attributable versus non-attributable signatures:** `https://github.com/commonwarexyz/monorepo/blob/v2026.9.0/cryptography/src/certificate.rs`
- **K9 — BLS12-381 Feldman-Desmedt DKG and share reveals:** `https://github.com/commonwarexyz/monorepo/blob/v2026.9.0/cryptography/src/bls12381/dkg/feldman_desmedt.rs`
- **K10 — `glue::dkg` (ALPHA): resharing, `SecretStore`, public reveals:** `https://github.com/commonwarexyz/monorepo/blob/v2026.9.0/glue/src/dkg/mod.rs`
- **K11 — Storage primitive stability:** `https://github.com/commonwarexyz/monorepo/blob/v2026.9.0/storage/src/lib.rs`
- **K12 — `v2026.9.0` release notes, blob layout, and rollback procedure:** `https://github.com/commonwarexyz/monorepo/blob/v2026.9.0/RELEASE_NOTES.md`
- **K13 — Unreleased transport refactor on `main` (`Upgrader`, `SakeCups`):** `https://github.com/commonwarexyz/monorepo/blob/c18a6b9c47b8e55d0a6f2fdef3fa10a75d6641da/stream/src/lib.rs`
- **K14 — `bridge` example (certificates between networks):** `https://github.com/commonwarexyz/monorepo/blob/v2026.9.0/examples/bridge/README.md`
- **K15 — `lookup::Config` fields and `recommended` defaults:** `https://github.com/commonwarexyz/monorepo/blob/v2026.9.0/p2p/src/authenticated/lookup/config.rs`
- **K16 — Exoware repository: primitives, components, Commonware git pin, licenses** (checked at commit `19c6fc4`): `https://github.com/exowarexyz/monorepo/blob/19c6fc447cd19fcb77f3bb7b937c4a476a75a425/README.md`
- **K17 — Exoware Simplex TypeScript helpers and WASM verifier (schemes, verification material, `verify_block`):** `https://github.com/exowarexyz/monorepo/blob/19c6fc447cd19fcb77f3bb7b937c4a476a75a425/simplex/ts/README.md`
- **K18 — `exoware-server` ALPHA status and ConnectRPC server:** `https://github.com/exowarexyz/monorepo/blob/19c6fc447cd19fcb77f3bb7b937c4a476a75a425/server/README.md`
- **T1 — Patrick O'Grady, Commonware and Exoware talk at Paradigm Frontiers (2026), transcript supplied by the RFC author.** The talk's statements about Tempo's static identity, passkey verification on chain, in-browser WASM verification, Exoware's crash-fault-tolerant replication, and performance figures are claims from the talk. They were not independently verified for this RFC.
