# Open Institutional Custody — RFC 0002
## Product completion, implementation decisions, and comparison tests

Version: 0.1-proposed  
Prepared: October 19, 2026  
Companion to: Open Institutional Custody — RFC 0001 (October 19, 2026)  
Status: Proposed requirements and test plan. No implementation, performance result, security audit, customer commitment, or competitive superiority is asserted.

## 1. Decision

[Likely] Build one complete institution-operated treasury workflow before increasing chain or transaction-type coverage. Reuse an existing reviewed threshold-signature implementation. Differentiate through independent operability, consistent authorization semantics, complete money-movement workflows, and measured operator effort—not a claim to have invented MPC custody.

The proposed initial buyer is an engineering-led institution managing its own operating treasury. This is a working assumption, not verified demand. Holding customer assets, maintaining pooled customer balances, and offering a hosted multi-tenant custody service require separate product, accounting, operational, and legal decisions. They are not silently included.

Initial scope: one institution per deployment; one explicitly enrolled EVM network and Solana; native assets and a reviewed token list; treasury/operational separation; direct transfers; one approved settlement destination. Repeat the complete workflow on both networks without claiming cross-chain atomicity.

### Product acceptance story

An independent institution engineer builds the complete distribution from public source, starts a development environment, provisions a supported production topology through separately authorized domain-specific steps, enrolls approvers and signers, creates a recoverable vault, receives and reconciles a deposit, funds fees, executes an authorized payout, diagnoses a failure, restores an allowed lost signer, and exports the evidence. Routine operation does not require a private vendor binary or a support engineer's terminal access.

External blockchain connectivity, hardware trust, identity providers, and declared RPC dependencies remain explicit. Independence from our service does not mean independence from every infrastructure provider.

## 2. Gap audit against RFC 0001

“Present” means a proposed requirement appears in the RFC, not that software exists. “Incomplete” means more implementation detail is required. An omission in our RFC does not establish an omission in a competitor.

| Area | Existing RFC coverage | Required addition | Priority |
|---|---|---|---|
| Security and native authorization | Sections 1–7 define threat boundaries, envelopes, quorum separation, exposure, and recovery | Freeze backend/protocol/commit, byte encoding, credential formats, transaction schemas, storage contract, release point, and topology | P0 |
| Deposit operations | Key activation and generic chain observation are described | Address lifecycle, backfill, finality-aware crediting, attribution, unrecognized-asset handling, reorg correction | P0 |
| Treasury automation | Fees, policy, and direct transfers are covered | Authorized gas funding, consolidation/sweeps, balance targets, trigger deduplication, paused/quarantined workflows | P0 |
| Financial reconciliation | Exposure arithmetic and an independent reconciler are covered | Implementable per-asset journal, postings, reservations, fee attribution, comparison at a common chain state, exception resolution | P0 |
| Operator and approver products | Independent display, API resources, and console directories are specified | Screen states, enrollment/replacement flows, policy diffs, errors and remediation, independent verifier distribution | P0 |
| Authorization coverage | Every honest signer must verify the envelope | Explicit entry-point/effect matrix, deterministic policy semantics, stateful grant accounting, negative coverage tests | P0 |
| Distribution and lifecycle | Reproducible builds, signed releases, domain separation, and recovery are required | Supported dependency/topology matrix, domain-local provisioning, upgrade protocol, rollback-safe migrations, recovery package | P0 |
| Developer integration | Endpoint sketches, scopes, idempotency, and webhooks exist | Versioned schemas, generated clients, pagination/event contracts, replay tooling, runnable integration examples, compatibility policy | P0 |
| Custody adoption and exit | Crypto-provider abstraction and key replacement exist | Watch-only onboarding, authoritative-path inventory, canary funding, export/exit procedure; full alternate-backend execution later if demanded | P0/P1 |
| Performance and readiness | Sections 16–18 define test categories and delivery gates | Executable harness, workload data, baseline measurements, customer service objectives, resource/cost reports, responsible owners | P0 |

## 3. P0 protocol and implementation freeze

Before interoperable implementation, record decisions with explicit tests:

1. **Crypto backend:** exact commit, ECDSA/Ed25519 variants, two-of-three behavior and allowed subsets, key generation, session isolation, persistence and recovery APIs, audit scope, licensing. Do not invent missing threshold capabilities with an unreviewed wrapper.
2. **Canonical authorization encoding:** byte-level types, field ordering/default rules, version negotiation, signature algorithms, hash domains, rejection rules, maximum sizes, test vectors. Do not let a REST serializer define the signed format by accident.
3. **Policy semantics:** rule ordering, deny precedence, role changes, amount units, window boundaries, time authority, grant revocation, fee treatment, exposure aggregation, and consistency with replayed history.
4. **Database contract:** schema and state transitions for intent, candidate, operation family, reservation, grant use, issuance, observations, and idempotency. Specify serializable conflict retries, durable writes, transaction boundaries, and restore invariants.
5. **MPC issuance boundary:** identify the exact protocol output that can enable completion and how the durable release authorization gates it. Instrument crashes on both sides of this point.
6. **Identity and enrollment:** authenticated participant discovery, invitation expiry, approval/admin credential registration and replacement, independent software roots, domain-local bootstrap.
7. **Evidence:** one named finality/freshness profile per network; source trust and failover; behavior when providers disagree or lag.
8. **Rollout:** software measurement approval, compatible mixed versions, storage migration sequencing, halt conditions, and restoration without reviving consumed cryptographic state.

Deliver `protocol-v1.md`, machine-readable schemas, golden vectors, state diagrams, and executable conformance tests. A folder named `policy-kernel` is not an implementation contract.

## 4. Deposits and address management

Add objects: `DepositAddress`, `AddressActivation`, `ObservedMovement`, `IndexCursor`, `BackfillJob`, `DepositCase`, and `ReconciliationCheckpoint`.

An address is inactive until public-key/address agreement, supported asset/network configuration, recovery metadata, and monitoring registration are committed. Watch-only enrollment must never suggest the platform controls the address.

For each supported transfer mechanism, specify how inbound effects are discovered. For EVM, declare which native movements require traces or other evidence rather than promising universal coverage from token logs. For Solana, reconcile actual account/lamport/token effects using the enrolled program profile. Unknown semantics are monitored or quarantined, not silently credited as supported assets.

Store observations with enough chain identity, transaction/effect identity, and canonicality context to replay and reverse them. An index cursor must survive restarts and backfill missing ranges. Repeated notifications must not create another credit. A reorg changes canonicality and creates appropriate corrective records rather than deleting the audit trail.

Display separately: observed, accepted under the configured finality profile, quarantined, and available for the specified operation. A transaction acknowledgement is not a confirmed deposit. Monitoring a balance does not prove who beneficially owns a deposit.

Unknown tokens, dust deposits, wrong networks, missing routing references, and transfers to retired addresses create explicit cases. Unrecognized deposits must not trigger automatic fee funding.

**Done:** deposit → process crash → backfill → replay → reorg correction yields the expected canonical balance and one effective credit per accepted movement, with complete evidence.

## 5. Gas funding, sweeping, and operational liquidity

Add an explicit workflow controller above the intent API. It creates ordinary authorized intents and cannot call a signing bypass.

A workflow records its trigger identity, child intents, ordering dependencies, reservations, retry state, observations, and completion conditions. A gas-funding transaction and the token movement it enables are separate economic actions with separate limits.

Support:

- Native-fee minimum/target balances, maximum refill per operation and period, source wallet restrictions, and approved recipient wallets.
- Consolidation/sweep thresholds based on supported assets, minimum useful value, maximum fee, and current network evidence.
- Treasury-to-operational funding bounded by policy. Broad strategy-driven rebalancing is not implied.
- Gas funding for the exact approved recipient and token workflow; no arbitrary spender or arbitrary fee payer.
- Solana fee-payer and account-creation behavior only when the final message and all lamport exposure are verified.
- Durable trigger deduplication and dependencies: a detected deposit does not produce unlimited top-ups on notification replay.
- Explicit paused states for fee ceilings, uncertain issuance, stale evidence, insufficient funds, or policy conflicts.

An attacker-triggered deposit must not become an unbounded faucet from the institution's gas wallet. After the maximum refill attempts or spend, stop and surface an exception.

**Done:** receive an allowed token into a configured wallet without fee funds, safely fund the fee requirement where the profile permits it, move the tokens to the approved treasury destination, and reconcile every amount and fee without manual chain transactions.

## 6. Accounting and reconciliation

Do not confuse three different quantities:

- Chain holdings under a stated observation/finality context.
- Amount available to authorize after outstanding obligations and reservations.
- Remaining policy allowance within its scope and window.

RFC 0001 defines exposure accounting. It does not yet define a complete operational money journal. Add immutable per-asset entries for accepted receipts, actual outgoing movements, network fees, account funding/rent where relevant, internal wallet transfers, reversals/corrections, and accepted external adjustments. Reservations are their own lifecycle and must not be double-counted as settled outflows.

For a proprietary treasury, a well-defined movement journal and accounting export can be sufficient for the pilot; do not build customer liabilities unless customer-fund custody is explicitly in scope. In that later profile, customer ownership, liabilities, segregation, and conservation rules require a separately reviewed ledger design.

Every internal movement links both legs to the operation, without mistaking a treasury consolidation for revenue or external spending in reporting. Any exemption from a policy spending limit must be explicitly authorized; internal labels alone cannot create an exemption.

Reconciliation compares the journal and independently obtained chain state at a compatible checkpoint. Unexplained differences create cases with severity, affected scope, evidence, owner, and authorized resolution. Changing the journal to match a balance without explaining the difference is not reconciliation.

When an exchange is the settlement destination, expose on-chain delivery and exchange-account credit as different milestones. Add a read-only exchange receipt integration only for the selected pilot; source-chain success alone does not establish that funds are available to trade.

**Done:** an operator can explain opening holdings, every movement, fees, pending exposure, closing holdings, and exceptions per asset and wallet. An independent engineer can reproduce the report from exported records and declared chain evidence.

## 7. Policy coverage and semantics

Create a capability-and-enforcement matrix. For every entry point, declare:

- API/worker/import path and operation type.
- Actual economic effects and native transaction bindings.
- Approval rules and global/local budget scopes.
- Enforcement location: mandatory signer path, on-chain execution rule, monitored-only, or unsupported.
- Alternative signing/execution paths and who can enable them.
- Native expiry/revocation behavior and residual authority after freeze.

In v1, direct transfer, workflow transfer, and supported imported transaction paths must normalize into the same verified economic representation before authorization. They consume the same applicable reservations. Unsupported paths fail closed instead of receiving weaker policy.

A grant for a strategy can be session-scoped, destination-scoped, asset-scoped, fee-bounded, and time-bounded at issuance. Do not describe an internal grant expiry as revocation of already issued native signatures. Avoid approvals/permits/delegation until a reviewed operation profile models their future authority.

A cross-network token budget needs an explicitly governed asset group and unit-conversion rule. The same ticker on two networks does not prove economic equivalence. A USD budget requires a trusted pricing and staleness model; a per-asset integer budget is the simpler v1 default.

Add policy preview, simulation over historical operations, and before/after diffs. Historical simulation helps reveal behavior changes but cannot prove future transactions safe. Every policy expansion, beneficiary change, authority change, and trusted verifier update follows the administrative quorum process.

### Concrete comparison candidate

[Certain] Fystack's public policies documentation states that its `web3.transfer` action does not expose withdrawal velocity fields. It also documents guarded withdrawals, contract calls, and message signing. This is a documented difference in policy semantics, not proof of a vulnerability or proof that the same customer outcome is impossible to configure. [E1]

[Likely] Test whether our normalized operation model makes a customer's limit easier to express and reliably enforce across every supported entry point. Compare with the best reasonable configuration of the alternative; publish limitations and configuration details.

**Done:** one remaining budget is raced through the withdrawal API, treasury automation, and supported transaction-import paths. Aggregate authorization stays inside the limit. Unknown/delegating operations are rejected rather than omitted from accounting.

## 8. Operator console and independent approval client

The console has four operational views:

1. **Funds:** canonical/available/reserved quantities, wallet purpose, asset identity, checkpoint age, and exceptions.
2. **Approvals:** full beneficiary, actual operation, fee ceiling, policy/grant context, previous and new configuration, and required signers/approvers.
3. **Exceptions:** exact blocker, affected funds, permissible remediation, whether a signature may exist, and recovery ownership.
4. **Security and lifecycle:** domain health, approved software versions, stale policies, authority inventory, backups, last recovery test, and incident controls.

Specify screen behavior for policy denial, approval wait, fee ceiling, stale evidence, signer outage, uncertain issuance, broadcast timeout, failed execution, reorg, and finalization. Distinguish actionable failure from “retrying” where another attempt could duplicate a payment.

The independent approval client must not trust the console's text or share its entire delivery compromise domain. It verifies the signed objects and displays their meaning through a pinned, independently distributed build. Passkeys authenticate an approval challenge but do not independently establish the honesty of a display.

Versioned address-book entries include network, asset restrictions, verification evidence, effective time, and full change history. Prefer secure institutional verification procedures for beneficiaries; do not invent verified legal identity from an address label.

Identity offboarding covers console access, proposer credentials, approver/admin roles, automation grants, and share/recovery authority separately. A removed UI user may still retain another authority until that path is explicitly revoked or migrated.

**Done:** a non-developer operator resolves each supported routine exception using documented UI/CLI actions without database edits, generic hash signing, or turning off policy. A compromised primary frontend cannot deceive the independent verifier about transaction contents under its declared threat model.

## 9. Distribution, production installation, recovery, and exit

### Development

Provide a local, source-buildable deployment with deterministic test assets, seeded examples, and both chain profiles. Label it development-only and prevent accidental reuse of its keys or default configuration for production. Collocated development signers are not independent production domains.

### Production

Publish a narrowly supported reference topology and dependency/version matrix. Provide separate provisioning steps per security domain rather than one privileged installer that silently owns every share. Require reviewable configuration and domain-local approval of identities and software roots.

The readiness check reports root administrators, network exposure, active measurements, transport credentials, backup location/freshness, authority-store durability, rollback fencing, and remaining correlated trust. It must not print “secure” merely because three containers are healthy.

Publish build provenance, dependency inventory, signed artifacts, reproducibility results for specified toolchains, vulnerability disclosure and patch processes, and compatibility/retirement policy. No hidden proprietary core image is required to operate the OSS distribution.

### Disaster recovery

Specify recovery objectives per failure case, not a universal number. Losing one signer is different from losing two signers, the authorization authority, or multiple independent domains. Where the failure is within the declared supported case, recovery must preserve committed issuance and one-time-state safety. Otherwise halt and state that the profile's guarantee does not apply.

The recovery kit includes encrypted material and metadata required by the chosen protocol, exact source/build references, approved identities, an inventory of residual authority, and offline-readable instructions. Test without access to the failed cloud account or our hosted services.

### Adoption and exit

Start with watch-only enrollment, then an authority inventory, a small canary transfer, and gradual operational funding. Never import a plaintext full private key as a convenience migration unless a separately approved design explicitly permits it.

Provide policy, destination, journal, operation, and evidence exports. Demonstrate continued operation using independently built artifacts with our service and registry credentials unavailable, while retaining declared blockchain connectivity. Migration may require new addresses and on-chain transfers; do not promise universal key-share interoperability across protocols.

**Done:** an independent operator completes the supported deployment and recovery path without proprietary application code or undocumented vendor steps, and can explain all remaining external trust dependencies.

## 10. Integration contracts

Deliver versioned OpenAPI and event schemas, actual TypeScript/Python client packages where required by the pilot, stable error semantics, pagination, webhook signing/key rotation, sequence-gap replay, and idempotency retention aligned with the operation lifecycle. HTTP success means only the documented stage, not chain finality.

Ship one small example that starts with an external business reference, requests an intent, handles approvals, follows the operation, and obtains final accounting evidence. An execution application is a proposer, not a generic signing authority.

If the selected use case needs swaps or trading authorization, add exactly one reviewed operation profile after direct transfers pass their gates. Include economic limits, native-message verification, allowance inventory, reconciliation, and protocol-update handling. Do not bundle an unrestricted dapp browser and call it institutional coverage.

A threshold-crypto backend interface is not a universal custody-backend interface. Safe, Squads, and commercial custody integrations may require different proposal/approval/execution and recovery models. Full execution integration is P1 and customer-driven; the UI must expose which rules the platform actually enforces and which remain advisory.

## 11. Performance and economic scorecard

No superiority or throughput numbers are known. The following are proposed measurement methods and decision thresholds, not results.

| Dimension | Measurement | Proposed decision gate |
|---|---|---|
| Developer adoption | Independent engineer: source checkout to both local test transfers and event consumption | Target <=30 minutes after documented prerequisites, with no private support or missing core artifacts |
| Workflow usability | Same deposit-to-reconciled-payout scenario on our implementation and the strongest suitable alternative | Target at least 2x lower hands-on operator time, without removing required safeguards |
| Runtime latency | Approved, fresh-evidence operation to durably committed valid signature; broadcast separately | Establish customer-required p95/p99 first; claim improvement only against a matched baseline |
| Routine burden | Manual interventions per 1,000 defined operations, exception severity, repair time | Material reduction versus baseline and no hidden manual database fixes |
| Recovery | Time and success after each permitted failure, loss of confirmed issuance records, stale-share rejection | Customer-agreed objective per topology; zero lost committed issuance within the declared supported failure model |
| Total operating cost | Infrastructure, RPC, storage, review/maintenance, and operator hours at a stated workload | Lower total cost or a required control unavailable at the baseline cost; no assumption that OSS has zero cost |

Benchmark the same threat model, hardware, quorum topology, region RTT, verifier/evidence freshness, durable storage semantics, and workload. Separate ECDSA/Ed25519 and native/token operations, cold versus safely preprocessed paths, single hot wallet versus independent wallets, burst versus sustained demand, and permitted signer subsets. Include partitions, signer loss, backend errors, queue limits, and resource exhaustion.

Record p50/p95/p99 by stage: queueing, evidence, decoding/policy, reservation, MPC, durable issuance, RPC submission, inclusion/finality. A fully automatic path and a human-approved path must not be mixed into one latency number.

Optimize only the measured bottleneck. Candidate techniques include maintained RPC connections, freshness-bounded caches, protocol-approved preprocessing, safe parallel work across independent wallets, and reduced serialization overhead. Every optimization reruns the failure suite. Never improve a benchmark by skipping fsync, freshness checks, signature verification, or the accounting authority.

Off-chain order execution, wallet transaction signing, and blockchain finality are distinct workloads. This product should not claim that a fast signature makes an on-chain settlement atomic or an exchange order execute faster.

## 12. Completion tests added to A01–A38

These tests complement, not replace, the security suite in RFC 0001.

| ID | Scenario | Required result |
|---|---|---|
| C01 | New engineer builds local distribution from source | Both network test workflows run with documented prerequisites |
| C02 | Development configuration pointed at production | Enrolled-profile/environment controls reject unsafe reuse |
| C03 | Address creation crashes before monitoring/recovery activation | Inactive address is not shown as ready for deposits |
| C04 | Deposit notification is repeated and indexer restarts | One effective accepted movement; consistent replay |
| C05 | Indexer misses a supported range | Backfill restores complete supported observations and surfaces uncertainty until resolved |
| C06 | Accepted observation is reorged | Canonicality, journal, availability, and exposure are corrected with retained history |
| C07 | Unknown token/dust arrives repeatedly | No uncontrolled credit, gas top-up, or automatic unsupported transfer |
| C08 | Approved token arrives without native fee funds | Bounded authorized funding and movement complete, or a precise safe exception is raised |
| C09 | A refill trigger repeats after lost acknowledgement | No unbounded repeated fee funding |
| C10 | Fee prices exceed the cap | Workflow pauses rather than increasing authority |
| C11 | Internal sweep executes | Both wallet effects and fees reconcile without a false external payment or revenue posting |
| C12 | Withdrawal, workflow, and supported import race one budget | All enabled paths consume the same applicable reservation |
| C13 | Transaction kind cannot be represented by verified effects | Fail closed, not an unaccounted general-signing path |
| C14 | Policy or destination edit broadens authority | Reviewed before/after diff, quorum, activation ordering, and immutable version binding |
| C15 | Main console is compromised | Independent approval verifier checks actual bound meaning |
| C16 | Employee is offboarded | Each authority type is revoked/retained explicitly; no false all-access-removed claim |
| C17 | Normal operator handles an uncertain transaction | No unsafe re-signing or false cancellation; actionable evidence remains visible |
| C18 | Subscriber misses/duplicates webhook deliveries | Sequence recovery and deduplication reproduce operation history |
| C19 | Journal differs from chain checkpoint | Scoped exception and authorized correction, never silent rebalance of the books |
| C20 | Settlement destination is an exchange | On-chain receipt and venue credit remain separate until actual evidence exists |
| C21 | One permitted signer domain is lost | Supported recovery transfer succeeds with issuance safety preserved |
| C22 | Software upgrade occurs during in-flight operations | Compatible progression or safe halt; no policy rollback or resurrected preprocessing |
| C23 | Our services/registry credentials are unavailable | Declared self-hosted deployment continues/rebuilds through documented independent paths |
| C24 | Watch-only customer adopts custody | Canary and authority inventory precede funding; no pretend control of external wallets |
| C25 | Customer exports operation history | Independent reconstruction of policy, issuance, observations, journal, and exceptions |
| C26 | Benchmark has single-wallet nonce contention | Report bottleneck honestly; do not substitute many-wallet throughput |
| C27 | Preprocessing/cache optimization is enabled | Same authorization, freshness, durability, and restore tests pass |
| C28 | Real-value pilot is proposed | Named operations owners, reviewed configuration, independent security review, limits, and stop criteria exist |

## 13. Delivery sequence

**Gate A — Freeze the executable core contract.** Resolve the eight decisions in Section 3. Produce a passing native-signature harness using the selected existing backend. Failure to obtain the required topology/storage/recovery contract changes the backend or deployment profile, not the security claim.

**Gate B — Complete the first money loop.** On an EVM development network, deploy, enroll, receive, fund fees, authorize, send, reconcile, show evidence, and handle failures. Add Solana using the same business objects while preserving its native semantics. Advance only when both are complete.

**Gate C — Make it independently operable.** Ship domain-specific production provisioning, console and independent approval client, full journal, schema/SDK examples, export, upgrade tests, and tested recovery. Include A01–A38 and the applicable C-tests.

**Gate D — Compare and admit a restricted pilot.** Independent operators run the same workflow against a suitable configured alternative. Record engineering time, manual work, correctness evidence, and total operating cost. A customer must identify a concrete reason to adopt; a positive developer reaction is not a deployment commitment. Real-value exposure is gated by independent review and institutional operating approval.

**Gate E — Add one requested capability.** A selected alternate custody backend, exchange credit integration, swap operation, or chain gets its own semantic, authorization, lifecycle, and recovery tests. Do not expand all dimensions at once.

Stop or contribute upstream instead if an existing project satisfies the same workflow and independence requirements with reasonable configuration or a small accepted patch. Continue when the missing behavior is material, the implementation passes the relevant gates, and an institution commits to using it.

## 14. Public evidence and comparison limits

Public documentation was checked October 19, 2026. Documentation is not a code audit or deployed-behavior test, and mutable sources must be pinned before publishing benchmark conclusions.

- **E1 — Fystack policies:** https://docs.fystack.io/policies . Documents the action types and the unavailability of withdrawal velocity fields on `web3.transfer`. This motivates a semantics comparison, not an allegation of a security bypass.
- **E2 — Fystack self-host distribution notice:** https://github.com/fystack/fystack-selfhost-scripts/blob/main/NOTICE . Limits the repository's Apache license to orchestration/deployment material and identifies platform software, images, and binaries as proprietary under separate terms. Complete open-source buildability is a concrete possible distinction from this distribution.
- **E3 — Fystack cosigner:** https://docs.fystack.io/cosigner . Documents a self-hosted participant, raw-byte approval callback, signed releases, and supported regular deployment, with Nitro listed as forthcoming. Local authorization is not a novel feature claim for our system.
- **E4 — Fystack deployment repository:** https://github.com/fystack/fystack-selfhost-scripts . Documents an indexer/rescanner, API, UI, MPC nodes, developer deployment, and wallet-creation E2E test; labels the quick start as testing-only. Do not compare our proposed hardened profile with its development topology and call that a fair security comparison.
- **E5 — Fireblocks sweep workflow:** https://fireblocks.readme.io/docs/sweep-funds . Documents sweeping, fee funding, triggers, and reconciliation concerns. These are product-completeness requirements, not new inventions.
- **E6 — Safe workspaces:** https://help.safe.global/articles/6605478254-what-is-a-workspace . Documents shared organizational context, roles, addresses, activity, policies, and dashboards. A unified console is not itself novel.
- **E7 — Vultisig plugin architecture:** https://docs.vultisig.com/developer-docs/marketplace/plugins . Documents policy-bound automation with verifier participation in threshold signing. Automation plus an independent verifier is not itself novel.

[Likely] A demonstrably easier, fully source-buildable, complete implementation is a useful engineering/product contribution even without new cryptography. [Guessing] Its adoption, commercial economics, and defensibility remain unproven until operator comparisons and actual customer commitments exist.
