# Custody concepts from first principles

This guide assumes you have sent a blockchain transaction or written a smart
contract. It explains the additional ideas behind the custody components in this
repository. The examples describe possible configurations, not product defaults.

Use [getting started](getting-started.md) to run a transfer and the
[payment walkthrough](payment-flow.md) to follow its components. This guide connects
each concept to its implementation.

## Start with a payment

An organization wants to pay a supplier 1,000 tokens from its treasury wallet.
It needs to answer several different questions:

1. Is this the intended supplier, token, and network?
2. Did the required people approve this payment?
3. Does it fit the shared spending rules, including pending payments?
4. Did the signers authorize exactly the transaction the approvers reviewed?
5. Did that transaction actually settle on chain?

A private key alone does not answer all five. The following concepts assign each
answer to an object, component, or source of evidence.

## The objects around a payment

| Term | Plain meaning | Example |
| --- | --- | --- |
| Custody | Control of the keys that can authorize asset movement | The organization's signing participants control its wallet key material. |
| Institution | The organization whose objects and credentials share a scope | A company's treasury organization. |
| Environment | A scope separating development from other uses | Simulator evidence is accepted by the policy kernel only in `dev`. |
| Vault | A logical group of wallets governed by a policy | The operating treasury's EVM and Solana wallets. |
| Chain wallet | A native address/account bound to a key and network profile | One EVM address belonging to that vault. |
| Chain profile | The enrolled network identity and verification settings | Chain id, accepted transaction versions, evidence age, and finality settings. |
| Asset | The concrete thing being transferred on a network | A native coin, one ERC-20 contract, or one classic SPL mint. |
| Destination | A versioned, administratively signed recipient record | Supplier A's address, version 3, with permitted assets. |
| Intent | The business payment request | Pay 1,000 registered tokens to Supplier A version 3 under a fee ceiling. |
| Candidate | One exact native transaction attempt for that intent | A transfer using EVM nonce 12 and specific fee fields. |
| Operation family | The intent's related candidate attempts | The original candidate and its permitted replacement. |

A vault is not a smart contract or an address. The assets exist on chain at
wallet addresses. Vault grouping and policy enforcement live in these off-chain
components.

An asset's symbol is descriptive metadata. Two contracts can share a symbol and
decimals. Verification uses network and concrete contract/mint identity.

Amounts use **base units**, the smallest integer units defined by the asset.
For an example token with six decimals, 1,000 tokens equal 1,000,000,000 base units.
The code uses exact integers and decimal strings rather than floating-point amounts.
Native fees are separate from the transferred token amount.

See [security objects](../openwiki/concepts/security-objects-and-encoding.md)
for the shared data structures and commitments.

## Keys, shares, and quorums

A **digital signature** authorizes particular bytes under a public key. The
native chain verifies its required signature format before accepting the transaction.
ECDSA means Elliptic Curve Digital Signature Algorithm. The EVM adapter uses
secp256k1 ECDSA. The Solana adapter uses pure Ed25519 over the
complete message. These schemes have different signing-input requirements.

A **quorum** is the number of participants required for a decision. This project
separates three powers:

- **Approvers** sign grants permitting a business payment.
- **Signing participants** contribute to a chain transaction signature.
- **Administrators** authorize policy and destination changes.

An approval credential is a separate key from a custody key share. The credential
does not itself permit movement of chain assets. The policy counts enrolled
credential identities, so enrollment and credential ownership matter.

### MPC and threshold signing

**Multiparty computation**, or MPC, lets participants compute a result while
keeping their private inputs separate. **Threshold signing** applies distributed
cryptography to creating a signature.

In a two-of-three setup, participants A, B, and C hold different private key
shares. Any permitted pair can complete signing. One participant has insufficient
shares for that threshold. The result is one native signature, not three business
approval signatures bundled together.

The Solana provider implements **FROST**, a threshold Ed25519 protocol. Its normal
**distributed key generation**, or DKG, creates shares without reconstructing the
group private key. Each participant then uses fresh private nonce material when
signing. The nonce material must never be reused.

This private signing nonce differs from an EVM transaction's public sequence number.
They share a name but serve different purposes.

The FROST crate also exposes an explicitly named development trusted-dealer path.
A dealer sees the whole secret and all shares. That path has a different trust
boundary from DKG and must not be described as secret-free key generation.

The current **development single-key provider** holds a complete key in one
process. It produces real signatures and tests authorization controls, but it has
no threshold security. Current EVM integration uses this provider.

### A protocol is not a deployed network

FROST and the coordinator define how signing messages move between participants.
The integration tests exchange those messages in process. Authenticated transport,
separate administrative domains, deployment, and recovery need their own implementation.
RFC 0003 proposes that institution network.

Read [crypto providers](../openwiki/integrations/crypto-providers.md) and
[signer verification](../openwiki/architecture/signer-boundary.md) for supported
topologies and the boundary around each share.

## Policy and independent approval

A **policy** defines allowed payment behavior. Rules can restrict assets,
destinations, purposes, amounts, fees, time windows, approval roles, and shared spending.

The **policy kernel** is the deterministic function that evaluates those rules.
Deterministic means equal inputs produce equal decisions. Time and exposure enter
as explicit inputs. Hard denials run first, then the first matching rule applies.

Its decisions are `Allow`, `Deny`, or `RequireApprovals`. `Allow` is a policy
result, not a chain signature or completed payment.

The **independent approval client** decodes the transaction itself instead of
trusting the console's payment description. It verifies the enrolled policy and
destination records and shows the operation reconstructed from native bytes.
An **approval grant** signs the permitted scope and its expiry.

**Trust roots** are the keys, chain profiles, and verifier builds enrolled in
advance. **Enrollment** establishes what the system accepts. A key file created
on a laptop does not automatically become an enrolled approver credential.

A **policy epoch** identifies a policy version. Approvals and authority receipts
bind to that version so an older approval cannot silently authorize a changed policy.
Destination records also have versions and administrative signatures.

See [policy evaluation](../openwiki/concepts/policy-evaluation.md) and the
[approval client guide](approval-client.md).

## Balance, budget, and exposure

These quantities answer different questions:

| Quantity | Question |
| --- | --- |
| Chain balance | How many assets does the observed chain state show at an address? |
| Policy limit | How much spending does the configured rule permit? |
| Settled spending | Which finalized debits remain inside the rule's rolling window? |
| Outstanding exposure | How much could reserved or possibly issued payments still spend? |
| Reservation | Which claims has the authority accepted and kept active for an attempt? |

For a rolling limit, exposure combines settled spending within the window and
outstanding claims. A new reservation must fit the resulting exposure.

Consider a 1,500-token rule and two concurrent 1,000-token requests:

```text
Initial state:             0 settled +    0 outstanding
After request A reserves:  0 settled + 1000 outstanding
Request B would require:   0 settled + 2000 outstanding  → exceeds 1500
```

Both requests could have passed a stateless preview. The **authorization authority**
checks and updates shared state together, preventing that preview race from
accepting both reservations.

A reservation is an off-chain accounting and resource lock. It does not transfer
tokens or create an on-chain escrow. It also does not make a policy limit equal
to a verified available balance. Full holdings/accounting/reconciliation services
remain separate product work.

Outstanding claims do not disappear when a rolling window advances. If a usable
signature might still exist, those claims can still become real spending.

See [authority accounting](../openwiki/architecture/authorization-authority.md).

## Bytes, hashes, and envelopes

A **chain adapter** translates between native transaction bytes and the payment
meaning that custody components can check. It also derives the **signing payload**,
the exact digest or message the native signature must authorize.

**Evidence** supplies chain observations required by that adapter. EVM examples
include chain id, nonce, fees, and token-contract code hash. Solana examples include
genesis hash, recent blockhash, token-account data, and address lookup tables.

Evidence has a source, observed state, trust level, and freshness bound. A recent
timestamp does not by itself prove the source is truthful. Enrollment, cross-checking,
and the selected finality assumptions remain part of the trust boundary.

A **hash** is a fixed-size commitment to input bytes. Changing committed content
changes the expected hash. A hash does not encrypt content or establish who approved
it. A verified signature authenticates a commitment under an enrolled key.

**Canonical encoding** defines one deterministic representation of an object.
This project uses a restricted deterministic CBOR format for internal commitments.
**CBOR** means Concise Binary Object Representation, a binary data encoding.
It does not sign arbitrary JSON text, whose representation can vary between serializers.

**Domain separation** gives different object types distinct hash prefixes. An
approval commitment and an authorization-envelope commitment use different domains.
Internal commitment hashing remains separate from the native chain signing rules.

The **authorization envelope** ties the payment, native bytes, grants, policy,
key/network/profile, evidence, resource claims, reservation, and signer session together.
The authority's receipt signs a commitment to that body. Rehashing altered bytes
does not create a valid authority signature for the altered envelope.

An **epoch** or revision identifies a particular version. A **session** identifies
one signing-protocol attempt. Those bindings prevent unrelated versions, networks,
or protocol attempts from sharing authorization accidentally.

Read [encoding and objects](../openwiki/concepts/security-objects-and-encoding.md)
and [signer verification](../openwiki/architecture/signer-boundary.md).

## How EVM and Solana express a transfer

The business request can say "pay 1,000 tokens," but each chain encodes different
instructions, account identities, fees, and validity conditions.

**EVM** means Ethereum Virtual Machine, the execution environment used by Ethereum
and compatible chains. **SPL** means Solana Program Library, which includes token programs.

| Idea | EVM | Solana |
| --- | --- | --- |
| Native coin | The chain's native currency pays fees and can move as transaction value. | SOL is the native currency. One SOL equals one billion lamports. |
| Token identity | An ERC-20 contract address identifies the token. | A mint account identifies a token managed by a token program. |
| Token balance | The token contract tracks balances for addresses. | A token account holds one mint's balance for an owner. |
| Transfer instruction | An ERC-20 payment calls `transfer(address,uint256)` on the registered contract. | Classic SPL `TransferChecked` names token accounts and checks the mint's decimals. |
| Fee resources | Gas measures execution work. A gas limit caps permitted work. | Compute units measure work. Compute-budget instructions can set limits and priority pricing. |
| Network identity | Chain id participates in replay protection for supported signing formats. | The profile binds a genesis hash. The native message itself does not encode that network domain. |

### EVM fee formats

**EIP** means Ethereum Improvement Proposal. EIP-1559 defines the type-2 transaction
format this builder emits. It includes a maximum fee per gas and priority-fee fields.
EIP-155 legacy transactions use a gas-price field. This adapter verifies that legacy
format only when the enrolled profile enables it.

The adapter checks the permitted transaction format and fee bounds alongside payment
meaning. Current EVM support does not include a separate layer-2 data-fee calculation.

### Solana token accounts and message versions

An **associated token account**, or ATA, is a token account derived for an owner
and mint under a particular token program. The adapter checks supported destination
ATA creation as part of a transfer. A token account and its owner address are different objects.

**Legacy** and **v0** are Solana message formats. A v0 message can reference an
**address lookup table**, an on-chain list supplying account addresses. Verification
needs evidence for those resolved addresses. The current builder emits legacy messages.

The supported token path uses the classic SPL Token program. **Token-2022** is a
different token-program variant and is outside this adapter's current capabilities.
The adapter also rejects arbitrary program instructions outside its accepted transfer shape.

These checks enforce a narrow payment meaning. They do not make every valid EVM
or Solana transaction a supported custody transaction.

See [EVM support](../openwiki/integrations/evm-adapter.md) and
[Solana support](../openwiki/integrations/solana-adapter.md) for the precise accepted formats.

## Approvals, attempts, and retries

An **exact-candidate approval** binds one candidate id, revision, and preview hash.
Changing that approved candidate requires authorization for the new content.

A **bounded direct-transfer approval** fixes the wallet, network, token, amount,
recipient, and fee ceiling while explicitly permitting certain native fields to vary.
EVM templates can permit nonce, gas limit, and fee fields. Solana templates permit
the recent blockhash. Adapters still enforce the resulting transaction's meaning.

An EVM **nonce** is the sender's transaction sequence number. Candidates with the
same sender and nonce are mutually exclusive on that chain. The authority groups
same-family replacements sharing that nonce by their maximum claim.

A Solana **recent blockhash** is part of the signed message's validity context.
A new blockhash creates a different attempt that can coexist with the old one
until evidence resolves the old signature's outcome. The authority counts those claims
additively and restricts release of a non-exclusive sibling.

An **idempotency key** identifies a request retry. Repeating the same key and body
can return the existing intent/family. Reusing the key with a different body fails.
Retrying a request does not authorize another payment or rebuild a native transaction.

See [EVM semantics](../openwiki/integrations/evm-adapter.md),
[Solana semantics](../openwiki/integrations/solana-adapter.md), and
[build and coordination](../openwiki/workflows/build-and-coordinate.md).

## Release, finality, and uncertainty

Two different commitments occur during a payment:

- **Issuance committed:** the authority records that a signature may exist.
- **Chain finalized:** chain evidence meets the profile's condition for settling the payment obligation.

The first does not imply the second. A **release receipt** permits the signer to
expose its signature contribution for the exact envelope and session.
A **one-time-state ledger** records consumption of signing state before that
output leaves the provider. It protects against reusing nonce material.

The **broadcaster** submits already signed bytes. An **RPC acknowledgement** reports
acceptance by the chain interface. **Inclusion** means the transaction appeared
in observed chain history. **Finality** is the enrolled profile's settlement condition.

A **reorg** or fork changes which chain history observers treat as canonical.
Before finality, an included payment can disappear. Its outstanding obligation must
remain until it settles or becomes provably unusable.

| Situation | Conservative behavior |
| --- | --- |
| Verification fails before release | Abort the unissued attempt and release claims when cleanup succeeds. |
| A signer fails after authority release | Record `IssuanceUnknown` and retain exposure. |
| An RPC reports failure after seeing the bytes | Preserve possible submission, then inspect chain evidence. |
| Sources disagree | Quarantine the family instead of releasing its obligation. |
| Finalized execution succeeds | Settle the asset claim and actual fee. |
| Finalized execution fails | Charge the actual fee without an asset debit. |
| Validated evidence proves the candidate cannot execute | Release the invalidated obligation. |

**Definitive invalidation** needs chain-specific evidence. An elapsed approval
deadline or a network timeout cannot revoke a signature already produced.
EVM proof requires finalized evidence of a non-family nonce consumer. Solana proof
requires finalized blockhash-expiry evidence and checks for successful family signatures.

An emergency **freeze** blocks new reservations/releases after its ordered commit.
It cannot revoke an earlier signature. Before issuing another payment, resolve the
original uncertainty through the [broadcast workflow](../openwiki/workflows/broadcast-and-finality.md).

## Recovery and audit

**Durable state** survives process restart. File-backed stores sync reservations,
one-time records, generations, workflow transitions, or submission attempts before
acknowledging their defined write boundary.

A **signer generation** identifies a newer instance. **Fencing** rejects messages
or writes from an older generation. A **high-water mark** records the newest sequence
a local store has seen, helping detect a restored older snapshot.

Restoring every local witness to the same older state can hide a rollback.
An independent **checkpoint** supplies an externally retained signed state/hash
and sequence for comparison. Local persistence and independent freshness are different
requirements.

An **audit log** links signed events through hashes. Independent witnesses can
compare signed checkpoints to expose conflicting histories. The audit log is not
the financial journal, and an authority audit-hook failure does not roll back
an already committed authorization action.

Read [durable state and recovery](../openwiki/operations/durable-state-and-recovery.md)
and [audit logging](../openwiki/operations/audit-log.md).

## What the tests establish

A **simulator** models supported chain behavior with controlled time and reproducible
state. It verifies real native signatures, executes supported transfers, and can
produce forks or conflicting evidence. It is not a live validating node.

A **differential test** compares an implementation with another implementation.
Here, adapter tests compare native formats/signatures with Alloy and Solana SDK code.

A **golden vector** records a known input and expected bytes, hashes, or output.
It catches unreviewed changes to the protocol representation.

A **model checker** explores combinations of actions in a bounded system and tests
invariants. This repository calls the real authority within a restricted universe.
That checks more orderings than one happy-path test without proving every possible
production deployment.

The current tests provide evidence for their defined cases. They do not establish
a completed security audit, live deployment, or every acceptance requirement in
the RFCs. Start with [development](development.md) to run the relevant checks.
