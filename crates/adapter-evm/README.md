# oic-adapter-evm

EVM chain adapter for Open Institutional Custody (RFC 0001 §8, §9). It implements
`oic_adapter_api::ChainAdapter` with no I/O, no clock, and no alloy/ethers code in
production. All chain state comes in through `EvidenceBundle` items.

## Capability manifest

| Field | Value |
|---|---|
| `adapter_id` | `evm` |
| `adapter_version` | crate version (`ADAPTER_VERSION`) |
| `verifier_build_hash` | `SHA256(VERIFIER_BUILD_ID)`, where `VERIFIER_BUILD_ID` includes the crate version |
| `signing_schemes` | `EcdsaSecp256k1Keccak256Prehashed` only |
| `accepted_transaction_versions` | `eip1559-type2`, `eip155-legacy`. A profile must list each version it enables. An unknown string in a profile fails closed. |
| `supported_operations` | native transfer; ERC-20 `transfer(address,uint256)` |
| `supported_asset_standards` | native; ERC-20 instances registered as `AssetKind::Erc20{contract}` with `behavior = Standard` |
| replay protection | chain id in the signing digest, checked against `profile.network_binding` (8-byte big-endian chain id); uniqueness per `(sender, nonce)` |
| expiry | none. EOA transactions do not expire on chain. `validity_constraints` returns `expires_at_height: None`. |
| resource locks | `NativeResource::EvmNonce{network_id, sender, nonce}`; the nonce must be ≥ evidence `nonce:<sender>` |
| fee accounting | worst-case fee = `gas_limit * max_fee_per_gas` (legacy: `gas_price`), computed with checked `u128`. The builder sets `max_fee_per_gas = 2*base_fee + priority_fee`. There is no L2 data-fee component. |
| replacement | a replacement shares `(sender, nonce)`. Exposure is retained until the nonce is consumed under profile finality. A submitted replacement never counts as proof of invalidation. |

### Transaction versions

* **EIP-1559 type 2**: build, decode, verify, assemble, and verify-signed. The signing payload is
  `keccak256(0x02 || rlp([chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data, access_list]))`
  with context `evm-type2-eip1559`.
* **EIP-155 legacy**: decode, verify, assemble, and verify-signed, only when the profile lists
  `eip155-legacy`. The signing context is `evm-legacy-eip155`. **Building legacy transactions is not supported.**

## Denied (returns `UnsupportedCapability` unless noted)

* EIP-2930 (0x01), EIP-4844 (0x03), EIP-7702 (0x04), and unknown EIP-2718 types (0x00, 0x05–0x7f)
* pre-EIP-155 legacy transactions (6 fields, or v = 27/28)
* contract creation (empty `to`)
* a non-empty access list
* any calldata other than ERC-20 `transfer`. The reason names the selector when it is known: `approve`,
  `transferFrom`, EIP-2612/DAI `permit`, `increase/decreaseAllowance`, `setApprovalForAll`,
  Permit2, `multicall`/`aggregate`, Safe `execTransaction`, account `execute`/`executeBatch`, and ERC-4337 `handleOps`
* ERC-20 transfers to a contract other than the registered one (`ScopeMismatch`)
* assets with a `Nonstandard` behavior profile (watch-only)
* ERC-20 calldata that is malformed, not exactly 68 bytes, has a dirty recipient word, has an amount above `u128`,
  or carries a non-zero `value` (`UnverifiableTransaction`)
* `eth_sign`, `personal_sign`, EIP-712, and arbitrary messages. These are never exposed, because only transaction bytes are signed.

## Strict parsing (A37)

The hand-written RLP codec enforces these bounds:

* input is limited to 128 KiB and list nesting to 8 levels
* single bytes and lengths must be in canonical form
* integers must have no leading zeros
* trailing bytes are rejected
* integer fields must fit their width: `u64` for nonce, gas, and chain id; `u128` for value and fees, even though RLP allows 32 bytes

Signatures must be low-s (EIP-2), with r and s in [1, n-1] and v ∈ {0, 1}. Signature bytes are 65 bytes: `r || s || v`.

## Evidence items

All hex is lowercase with no `0x` prefix.

| Key | Value |
|---|---|
| `chain_id` | 8-byte BE chain id (`identify_network`) |
| `nonce:<sender>` | 8-byte BE account nonce (required by build and verify) |
| `base_fee`, `priority_fee` | 16-byte BE per-gas fees (build; templates without `EvmFeeFields`) |
| `gas_limit` | 8-byte BE gas limit (build; templates without `EvmGasLimit`) |
| `code:<contract>` | 32-byte keccak256 of contract code at the evidence block. Required for ERC-20. The empty-code hash is rejected. |
| `tx:<hash>` | canonical bytes of `evidence::TxObservation` (`observe`, `prove_invalidation`) |
| `signed_tx:<candidate_id>:<rev>` | signed bytes of each possibly-issued candidate (`prove_invalidation`) |

## Lifecycle

* `observe`: a missing `tx:` item returns `StaleEvidence`. `included = false` maps to `Submitted`.
  An included transaction maps to `Included` until `confirmations ≥ finality_depth`, then to `Finalized`.
* `prove_invalidation` returns `Definitive` only when all of the following hold:
  * the evidence is at the profile's finality commitment
  * every candidate's signed bytes are present and recover to a single sender
  * the account nonce is greater than every candidate nonce
  * every family transaction is `included = false` with `nonce_consumed_by` naming a non-family transaction
  * that non-family transaction is included with at least `finality_depth` confirmations

  In every other case it returns `Unknown`.

## Tests

`cargo test -p oic-adapter-evm` runs the following:

* RLP classic vectors
* published EIP-1559 encodings and the EIP-155 example (digest and signed bytes)
* a proptest differential against `alloy-consensus` (dev-dependency only): signing hash, legacy hash, signer recovery, and tx hash
* acceptance cases A02, A04, A19, A20, and A37
* template fillable-field enforcement
* observation and invalidation
* fuzz-style proptests that feed arbitrary bytes to every decoder
