# oic-adapter-solana

Solana chain adapter for Open Institutional Custody (RFC 0001 §8, §10). It implements
`oic_adapter_api::ChainAdapter` with no I/O, no clock, and no Solana SDK code in production.
The message, transaction, and compact-u16 formats are hand-written. The adapter derives PDAs
with SHA-256, and checks that a PDA is off the Ed25519 curve with `curve25519-dalek`. It checks
signatures with `ed25519-dalek` `verify_strict`. All chain state comes in through
`EvidenceBundle` items.

## Capability manifest

| Field | Value |
|---|---|
| `adapter_id` | `solana` |
| `adapter_version` | crate version (`ADAPTER_VERSION`) |
| `verifier_build_hash` | `SHA256(VERIFIER_BUILD_ID)`, where `VERIFIER_BUILD_ID` includes the crate version |
| `signing_schemes` | `Ed25519Pure` only (RFC 8032 over the full serialized message; never Ed25519ph, never a prehash) |
| `accepted_transaction_versions` | `legacy`, `v0`. A profile must list each version it enables. An unknown string in a profile fails closed. |
| `supported_operations` | System Program `Transfer`; SPL Token `TransferChecked`; ATA `Create` / `CreateIdempotent` for the destination only; Compute Budget `SetComputeUnitLimit` / `SetComputeUnitPrice` |
| `supported_asset_standards` | native SOL; SPL mints under the original Token program (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`) registered as `AssetKind::SplToken{mint, token_program}` with `behavior = Standard` |
| replay protection | Ed25519 signature over the exact message, which commits to the recent blockhash. The genesis hash in `profile.network_binding` (32 bytes) must equal evidence `genesis_hash`. The message itself carries no network id, so this is an off-chain binding, not an on-chain signature domain. |
| expiry | The message expires when the chain passes the blockhash's last valid block height. That height is committed as `ChainValidityConstraints.expires_at_height`. |
| resource locks | `NativeResource::SolanaBlockhash{network_id, fee_payer, blockhash}`. A fresh blockhash is a different resource and does **not** conflict with the earlier candidate. |
| fee accounting | `max fee = num_signatures * lamports_per_signature + ceil(cu_limit * cu_price_micro_lamports / 1_000_000) + rent` (rent only when an ATA is created). Computed with checked `u128`. |
| replacement | A fresh-blockhash rebuild is a new candidate in the same family. It is not mutually exclusive with the original, so exposure is summed until `prove_invalidation` is `Definitive`. |
| known external authorities | mint authority; freeze authority; token-2022 permanent delegate (unsupported); transfer hook (unsupported) |

### Message versions

* **Legacy**: build, decode, verify, assemble, and verify-signed. Signing context: `solana-message-legacy`.
* **v0** (version prefix `0x80`): decode, verify, assemble, and verify-signed, only when the profile lists `v0`.
  Signing context: `solana-message-v0`. **Building v0 messages is not supported.**
* Any other version prefix (`0x81`–`0xff`, including the SDK's newer v1 format) returns `UnsupportedCapability`.

The candidate's `native_unsigned_bytes` is the serialized **message**, not the transaction. The single signing
payload is `{payload_index: 0, scheme_id: Ed25519Pure, message_or_digest: <full message bytes>}`.
Signed bytes are `shortvec(1) || signature(64) || message`. `chain_tx_id` is the base58 signature.

### Fee details

* If `SetComputeUnitLimit` is absent, the limit defaults to 200,000 per non-compute-budget top-level instruction,
  capped at 1,400,000. This is the runtime rule.
* An explicit limit above 1,400,000 is rejected (`UnverifiableTransaction`).
* The priority fee is zero when `SetComputeUnitPrice` is absent.
* When an ATA is created, the token-account rent counts toward both `native_value_base_units` and
  `max_native_fee_base_units`. Rent is a lamport movement, kept apart from the token amount. It is charged even
  for `CreateIdempotent`, as the worst case.

## Decoding rules

Every top-level instruction must decode, or the candidate is rejected. A rejection names the program and the tag.

* The message has exactly one required signature: the fee payer at static index 0. The fee payer must be the
  wallet address, which is the 32-byte Ed25519 public key.
* Exactly one value-moving instruction is allowed: a System `Transfer` (SOL) or a Token `TransferChecked` (SPL).
* At most one `SetComputeUnitLimit` and one `SetComputeUnitPrice` are allowed. They take no accounts and must have exact data lengths.
* At most one ATA creation is allowed, and only together with `TransferChecked`. It must come before the transfer, and it must create the
  transfer destination. The payer must be the fee payer and the owner must be the destination owner. The mint must
  be the registered mint. The token program must be the original one. The ATA address must equal the PDA of
  `[owner, token_program, mint]` under `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`. The account list must be
  exactly 6 accounts, with the System Program in position 5.
* Account permissions follow the message header:
  * transfer `from` is signer and writable; `to` is writable
  * token `source` and `destination` are writable; `authority` is a signer
  * the ATA payer is signer and writable; the ATA account is writable
* Extra accounts are rejected. This includes SPL multisig signers.
* SPL:
  * Decimals must equal the registered decimals.
  * The mint must equal the registered mint (`ScopeMismatch` otherwise, A04).
  * The authority must be the wallet.
  * Source token-account evidence is required. It must show owner = wallet, the registered mint, and state initialized.
  * The destination owner is established by PDA derivation, never from address shape:
    * The destination is the ATA of (registered destination, mint), or
    * explicit `token_account:` evidence names the owner.
  * Destination evidence, if present, must show the registered mint, initialized state, no delegate, and no close
    authority other than the owner.
* v0 address lookup tables:
  * Every referenced table must be present as `alt:<table>` evidence; a missing table is `StaleEvidence`.
  * A table whose `deactivation_slot != u64::MAX` is rejected, including tables that are deactivating.
  * An index outside the table is rejected.
  * A resolved account that duplicates another account is rejected.
  * Programs cannot come from lookups.
  * Lookup-resolved accounts can never be signers.
  * The full resolved account list and every table binding go into `native_detail`.

The verifier always compares the recent blockhash with evidence `recent_blockhash`. That includes bounded
templates. A template must declare `SolanaRecentBlockhash` fillable. A template that declares any EVM fillable
field is a `ScopeMismatch`. If the evidence height is past `blockhash_last_valid_height`, the result is `StaleEvidence`.

## Denied (returns `UnsupportedCapability` unless noted)

* any other program, including Memo, Stake, Vote, the Address Lookup Table program, loaders, and unknown programs
* System Program `CreateAccount`, `Assign`, `Allocate`, `*WithSeed`, `TransferWithSeed`, and all nonce operations
  (`AdvanceNonceAccount`, so durable nonces are unsupported, plus `Withdraw`, `Initialize`, `Authorize`, and `Upgrade`)
* Compute Budget `RequestHeapFrame`, `SetLoadedAccountsDataSizeLimit`, and deprecated `RequestUnits`
* SPL Token instructions other than `TransferChecked`, including:
  * plain `Transfer` (tag 3), because only checked transfers are allowed
  * `Approve` and `Revoke`
  * `SetAuthority`
  * `MintTo` and `Burn`
  * `CloseAccount`
  * `Freeze` and `Thaw`
  * `*Checked` variants other than `TransferChecked`
  * initializers and `SyncNative`
* Token-2022 (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`), whether as an instruction program, an asset token
  program, or the token program for ATA creation (A24)
* ATA `RecoverNested`, and ATA instructions with trailing data
* more than one value-moving instruction, a duplicate compute-budget instruction, or a second ATA creation
* more than one required signer
* assets with a `Nonstandard` behavior profile (watch-only)

## Strict parsing (A37)

* compact-u16: at most 3 bytes, minimal encoding, value at most `u16::MAX`
* the serialized transaction (`shortvec(n) || n*64 || message`) must be at most 1232 bytes
* at most 64 accounts (static plus lookup-resolved)
* header rules:
  * at least one signer
  * the fee payer is writable
  * signer and readonly counts fit inside the static key list
* no trailing bytes; a decoded message must re-encode byte-exactly
* duplicate static keys are rejected; the fee payer cannot be a program; program ids must be static keys;
  every account index must be in range; a lookup that loads no accounts is rejected
* signature count must equal `num_required_signatures`

## Evidence items

Addresses and signatures in keys are base58. Integers are **little-endian**. Canonical structs use
`oic-canonical-encoding`.

| Key | Value |
|---|---|
| `genesis_hash` | 32-byte genesis hash. Must equal `profile.network_binding`. |
| `recent_blockhash` | 32 bytes. The candidate's blockhash must equal it. |
| `blockhash_last_valid_height` | u64 LE. Last valid block height of `recent_blockhash`; becomes `expires_at_height`. |
| `blockhash_last_valid_height:<blockhash>` | u64 LE. Per-blockhash last valid height, used by `prove_invalidation` for older family candidates. |
| `lamports_per_signature` | u64 LE |
| `rent_exempt_minimum:token_account` | u64 LE. Required when an ATA is created. |
| `cu_limit` | u32 LE. Optional; the builder adds `SetComputeUnitLimit`. |
| `cu_price` | u64 LE, in micro-lamports. Optional; the builder adds `SetComputeUnitPrice`. |
| `alt:<table>` | canonical `AddressLookupTableEvidence { addresses: Vec<32 bytes>, deactivation_slot (u64::MAX = active), last_extended_slot }` |
| `token_account:<account>` | canonical `TokenAccountEvidence { mint, owner, amount, delegate: Option, close_authority: Option, state: 0/1/2 }` |
| `tx:<signature>` | canonical `TxObservation { slot, block_hash (32), commitment: processed/confirmed/finalized, success, fee, err: Option<String> }`. `success` must equal `err.is_none()`. |
| `signed_tx:<candidate_id>:<rev>` | signed transaction bytes of each possibly-issued candidate (`prove_invalidation`) |

For this profile, `EvidenceBundle.state.height` is a **block height**, because blockhash expiry is defined in
block height. It is not a slot.

## Builder

The builder produces legacy messages only. The fee payer is the wallet. The compiler orders accounts as
signer-writable, signer-readonly, writable, readonly. For a plain SOL transfer, the result is byte-identical to the
SDK's `Message::new` output.

* SOL: `[SetComputeUnitLimit?] [SetComputeUnitPrice?] Transfer(wallet → destination)`.
* SPL: `[compute budget?] [CreateIdempotent(destination ATA)?] TransferChecked(wallet ATA → destination ATA, wallet authority)`.
  The ATA creation is added when evidence has no `token_account:<destination ATA>`. The source token account evidence is required.
* The builder fails with `BudgetExceeded` when the worst-case fee is above the intent's maximum. It then runs the signer's `verify_candidate` on its own output.

## Lifecycle

* `observe`:
  * A missing `tx:` item is `StaleEvidence`.
  * A commitment at or above `profile.finality_commitment` (`processed` < `confirmed` < `finalized`) maps to `Finalized`.
  * Below that, the observation maps to `Included` with the observed commitment.
* `prove_invalidation` returns `Definitive` only when all of the following hold:
  * The evidence is at the profile's finality commitment.
  * For **every** family candidate, `state.height ≥ last_valid_height(blockhash) + finality_depth`.
  * Every candidate's `signed_tx:` bytes are present. They must match the candidate message, and their signatures must verify.
  * No `tx:<signature>` item for a family signature shows success. A failed landing is still a non-payment.

  Otherwise it returns `Unknown`. A timeout never counts as proof (A23).

## Tests

`cargo test -p oic-adapter-solana` runs these tests:

* unit tests: shortvec vectors and strictness, message codec, permissions, program-id constants, PDA bounds
* `tests/adapter.rs`:
  * build, verify, and sign round trips for SOL and for SPL with and without ATA creation
  * compute-budget fee accounting
  * A02, A04, A21 (resolved destination, absent table, deactivated table, out-of-range index, lookup signer, duplicates),
    A22 (SetAuthority, CloseAccount, Approve, Memo, unknown program, Assign, AdvanceNonce), A23, A24, and A37 (oversize at exactly 1232/1233 bytes, more than 64 accounts, proptest fuzzing of every decoder)
  * templates, scope and evidence checks, observe, manifest
* `tests/differential.rs`: differential tests against the Solana SDK crates, which are pinned dev-dependencies only:
  * 64 random SDK-built legacy and v0 messages decode with ours and re-encode byte-exactly; bincode and wincode agree
  * 64 random messages built by our code decode with the SDK, pass `sanitize`, and re-serialize to our bytes
  * transaction framing
  * SDK `Keypair` signatures are accepted by `verify_signed_transaction`, and SDK `verify` accepts our ed25519-dalek signatures (legacy SOL, legacy SPL, and an SDK-compiled v0 message whose destination comes from a lookup table)
  * the instruction data and account metas from our encoders match `solana-system-interface`, `solana-compute-budget-interface`, `spl-token-interface`, and `spl-associated-token-account-interface`
  * ATA derivation matches `Pubkey::find_program_address` and `get_associated_token_address`, both as a proptest and as a fixed vector
  * program ids match the SDK constants
