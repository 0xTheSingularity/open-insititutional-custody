//! # oic-adapter-evm
//!
//! EVM chain adapter for Open Institutional Custody (RFC 0001 §8, §9).
//!
//! Supported: EIP-1559 type-2 transactions (build, decode, verify, assemble)
//! and, only when the profile enables `"eip155-legacy"`, decode/verify/assemble
//! of EIP-155 legacy transactions. Semantics: native transfers and ERC-20
//! `transfer(address,uint256)` to a registered `Standard` contract instance.
//! Everything else fails with `UnsupportedCapability`.
//!
//! The adapter is pure: no I/O, no clock. All chain state arrives through
//! `EvidenceBundle` items described in [`evidence`].

pub mod address;
pub mod calldata;
pub mod evidence;
pub mod rlp;
pub mod tx;

use address::{address_from_public_key, address_from_uncompressed, eip55, keccak256, Address};
use evidence::*;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use oic_adapter_api::*;
use oic_domain_types::*;
use serde::Serialize;
use tx::{Eip1559Tx, EvmTx, RawSignature};

pub const ADAPTER_ID: &str = "evm";
pub const ADAPTER_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Identity of the pinned verification code; its SHA-256 is `verifier_build_hash`.
pub const VERIFIER_BUILD_ID: &str = concat!("oic-adapter-evm/", env!("CARGO_PKG_VERSION"), "/verifier/strict-rlp-eip1559-erc20transfer-v1");

/// `ChainProfile.accepted_versions` strings understood by this adapter.
pub const VERSION_TYPE2: &str = "eip1559-type2";
pub const VERSION_LEGACY: &str = "eip155-legacy";

pub const SIGNING_CONTEXT_TYPE2: &str = "evm-type2-eip1559";
pub const SIGNING_CONTEXT_LEGACY: &str = "evm-legacy-eip155";

pub const REPLACEMENT_RULE: &str =
    "EIP-1559 EOA transactions do not expire; replacement shares (sender, nonce); exposure retained until nonce consumed under profile finality";

/// floor(n / 2) for the secp256k1 group order n. Signatures with s above this are rejected (EIP-2).
pub const SECP256K1_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4,
    0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// `SHA256(VERIFIER_BUILD_ID)`.
pub fn verifier_build_hash() -> Hash32 {
    oic_canonical_encoding::sha256(VERIFIER_BUILD_ID.as_bytes())
}

/// Canonically-encoded `native_detail` of a decoded EVM operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct EvmNativeDetail {
    pub tx_type: String,
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: Amount,
    pub max_fee_per_gas: Amount,
    pub gas_limit: u64,
    pub to: Bytes,
    pub value: Amount,
    pub selector: Option<Bytes>,
    pub signing_digest: Hash32,
}

/// The EVM adapter. Stateless.
#[derive(Clone, Copy, Debug, Default)]
pub struct EvmAdapter;

impl EvmAdapter {
    pub fn new() -> Self {
        EvmAdapter
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Chain id from `profile.network_binding` (8-byte big-endian).
pub fn chain_id_from_profile(profile: &ChainProfile) -> OicResult<u64> {
    let b: [u8; 8] = profile
        .network_binding
        .as_slice()
        .try_into()
        .map_err(|_| OicError::scope("EVM profile network_binding must be the 8-byte big-endian chain id"))?;
    Ok(u64::from_be_bytes(b))
}

/// Encode a chain id for `ChainProfile.network_binding`.
pub fn network_binding_for_chain_id(chain_id: u64) -> Bytes {
    Bytes(chain_id.to_be_bytes().to_vec())
}

fn check_profile(profile: &ChainProfile) -> OicResult<u64> {
    if profile.adapter_id.as_str() != ADAPTER_ID {
        return Err(OicError::scope(format!("profile adapter_id `{}` is not `{ADAPTER_ID}`", profile.adapter_id)));
    }
    if profile.accepted_versions.is_empty() {
        return Err(OicError::unsupported("profile enables no EVM transaction versions"));
    }
    for v in &profile.accepted_versions {
        if v != VERSION_TYPE2 && v != VERSION_LEGACY {
            return Err(OicError::unsupported(format!("profile accepted version `{v}` is not supported by this adapter")));
        }
    }
    chain_id_from_profile(profile)
}

fn version_enabled(profile: &ChainProfile, v: &str) -> bool {
    profile.accepted_versions.iter().any(|x| x == v)
}

fn check_key_scheme(key: &KeyDescriptor) -> OicResult<Address> {
    if key.scheme != SchemeId::EcdsaSecp256k1Keccak256Prehashed {
        return Err(OicError::unsupported(format!("EVM adapter does not support key scheme {:?}", key.scheme)));
    }
    address_from_public_key(&key.public_key)
}

/// Wallet/key/profile binding. Returns the sender address derived from the key.
fn check_wallet_scope(profile: &ChainProfile, wallet: &ChainWallet, key: &KeyDescriptor) -> OicResult<Address> {
    let derived = check_key_scheme(key)?;
    if wallet.address.as_slice() != derived {
        return Err(OicError::scope("wallet address does not match the address derived from the key's public key"));
    }
    if wallet.chain_profile_id != profile.chain_profile_id {
        return Err(OicError::scope("wallet chain_profile_id does not match profile"));
    }
    if wallet.network_id != profile.network_id {
        return Err(OicError::scope("wallet network_id does not match profile"));
    }
    if wallet.key_id != key.key_id || wallet.key_epoch != key.key_epoch {
        return Err(OicError::scope("wallet key_id/key_epoch does not match key descriptor"));
    }
    if !key.networks.contains(&profile.network_id) {
        return Err(OicError::scope("key descriptor is not enrolled for this network"));
    }
    Ok(derived)
}

fn check_candidate_scope(candidate: &Candidate, profile: &ChainProfile) -> OicResult<()> {
    if candidate.chain_profile_id != profile.chain_profile_id {
        return Err(OicError::scope("candidate chain_profile_id does not match profile"));
    }
    if candidate.adapter_id.as_str() != ADAPTER_ID {
        return Err(OicError::scope("candidate was not built for the EVM adapter"));
    }
    if candidate.adapter_version != ADAPTER_VERSION {
        return Err(OicError::scope(format!(
            "candidate adapter_version `{}` does not match pinned verifier `{ADAPTER_VERSION}`",
            candidate.adapter_version
        )));
    }
    Ok(())
}

/// Strictly decode candidate bytes and apply profile gating.
fn parse_candidate_tx(bytes: &[u8], profile: &ChainProfile) -> OicResult<EvmTx> {
    let chain_id = check_profile(profile)?;
    let tx = EvmTx::decode_unsigned(bytes)?;
    if !version_enabled(profile, tx.type_name()) {
        return Err(OicError::unsupported(format!("transaction version `{}` is not enabled by the chain profile", tx.type_name())));
    }
    reject_access_list(&tx)?;
    if tx.chain_id() != chain_id {
        return Err(OicError::scope(format!("transaction chain_id {} does not match profile chain_id {chain_id}", tx.chain_id())));
    }
    Ok(tx)
}

fn reject_access_list(tx: &EvmTx) -> OicResult<()> {
    if let EvmTx::Type2(t) = tx {
        if !t.access_list.is_empty() {
            return Err(OicError::unsupported("non-empty EIP-2930 access list is not supported by this profile"));
        }
    }
    Ok(())
}

fn payloads_for(tx: &EvmTx, key: &KeyDescriptor) -> Vec<NativeSigningPayload> {
    vec![NativeSigningPayload {
        payload_index: 0,
        scheme_id: SchemeId::EcdsaSecp256k1Keccak256Prehashed,
        message_or_digest: Bytes(tx.signing_digest().to_vec()),
        required_key_id: key.key_id.clone(),
        native_signing_context: tx.signing_context().to_string(),
    }]
}

/// Semantic decode: (asset, recipient, amount).
fn decode_semantics(tx: &EvmTx, ctx: &VerifyContext<'_>) -> OicResult<(AssetKind, Address, u128)> {
    let data = tx.data();
    if data.is_empty() {
        return Ok((AssetKind::Native, *tx.to(), tx.value()));
    }
    calldata::require_transfer_selector(data)?;
    let contract = match &ctx.asset.asset {
        AssetKind::Erc20 { contract } => contract,
        other => {
            return Err(OicError::unsupported(format!(
                "ERC-20 transfer calldata but the registered asset is {other:?}, not an ERC-20 instance"
            )))
        }
    };
    if ctx.asset.network_id != ctx.profile.network_id {
        return Err(OicError::scope("registered asset belongs to a different network"));
    }
    if contract.as_slice() != tx.to() {
        return Err(OicError::scope("transaction target is not the registered ERC-20 contract for this asset"));
    }
    if ctx.asset.behavior != AssetBehaviorProfile::Standard {
        return Err(OicError::unsupported("asset behavior profile is non-standard; watch-only, not automatically sendable"));
    }
    let t = calldata::decode_transfer(data)?;
    if tx.value() != 0 {
        return Err(OicError::unverifiable("ERC-20 transfer must carry zero native value"));
    }
    Ok((AssetKind::Erc20 { contract: Bytes(tx.to().to_vec()) }, t.recipient, t.amount))
}

fn decode_tx(tx: &EvmTx, ctx: &VerifyContext<'_>, sender: &Address) -> OicResult<DecodedOperation> {
    let (asset, recipient, amount) = decode_semantics(tx, ctx)?;
    let max_fee = tx.max_fee()?;
    let detail = EvmNativeDetail {
        tx_type: tx.type_name().to_string(),
        chain_id: tx.chain_id(),
        nonce: tx.nonce(),
        max_priority_fee_per_gas: Amount(tx.priority_fee_per_gas()),
        max_fee_per_gas: Amount(tx.fee_cap_per_gas()),
        gas_limit: tx.gas_limit(),
        to: Bytes(tx.to().to_vec()),
        value: Amount(tx.value()),
        selector: calldata::selector(tx.data()).map(|s| Bytes(s.to_vec())),
        signing_digest: Hash32(tx.signing_digest()),
    };
    Ok(DecodedOperation::DirectTransfer {
        network_id: ctx.profile.network_id.clone(),
        asset,
        sender: Bytes(sender.to_vec()),
        recipient: Bytes(recipient.to_vec()),
        amount_base_units: Amount(amount),
        native_value_base_units: Amount(tx.value()),
        max_native_fee_base_units: Amount(max_fee),
        native_detail: Bytes(oic_canonical_encoding::canonical_bytes(&detail)?),
    })
}

fn check_code_evidence(evidence: &EvidenceBundle, contract: &[u8]) -> OicResult<()> {
    let contract: Address = address::to_address(contract, "ERC-20 contract")?;
    let code_hash = get_hash(evidence, &code_key(&contract))?;
    if code_hash == EMPTY_CODE_HASH {
        return Err(OicError::unverifiable("evidence shows no code at the registered ERC-20 contract"));
    }
    Ok(())
}

fn fee_cap_from_evidence(evidence: &EvidenceBundle) -> OicResult<(u128, u128)> {
    let base = get_u128(evidence, KEY_BASE_FEE)?;
    let prio = get_u128(evidence, KEY_PRIORITY_FEE)?;
    let max = base
        .checked_mul(2)
        .and_then(|x| x.checked_add(prio))
        .ok_or_else(|| OicError::unverifiable("2*base_fee + priority_fee overflows u128"))?;
    Ok((max, prio))
}

/// Bounded-template rule: only fields declared fillable may differ from the
/// evidence-determined build.
fn check_template_fill(tx: &EvmTx, template: &BoundedTransferTemplate, evidence: &EvidenceBundle, sender: &Address) -> OicResult<()> {
    let fill = |f: FillableField| template.fillable.contains(&f);
    if fill(FillableField::SolanaRecentBlockhash) {
        return Err(OicError::scope("template declares a Solana fillable field for an EVM wallet"));
    }
    if !fill(FillableField::EvmNonce) {
        let n = get_u64(evidence, &nonce_key(sender))?;
        if tx.nonce() != n {
            return Err(OicError::unverifiable("nonce differs from evidence but template does not permit filling EvmNonce"));
        }
    }
    if !fill(FillableField::EvmFeeFields) {
        let (max, prio) = fee_cap_from_evidence(evidence)?;
        let ok = match tx {
            EvmTx::Type2(t) => t.max_fee_per_gas == max && t.max_priority_fee_per_gas == prio,
            EvmTx::Legacy(t) => t.gas_price == max,
        };
        if !ok {
            return Err(OicError::unverifiable("fee fields differ from evidence but template does not permit filling EvmFeeFields"));
        }
    }
    if !fill(FillableField::EvmGasLimit) {
        let g = get_u64(evidence, KEY_GAS_LIMIT)?;
        if tx.gas_limit() != g {
            return Err(OicError::unverifiable("gas_limit differs from evidence but template does not permit filling EvmGasLimit"));
        }
    }
    Ok(())
}

fn check_low_s(s: &[u8; 32]) -> OicResult<()> {
    if s.as_slice() > SECP256K1_HALF_ORDER.as_slice() {
        return Err(OicError::invalid_signature("signature s is above n/2 (high-s, non-canonical)"));
    }
    Ok(())
}

/// Recover the signing address from a digest and canonical signature.
pub fn recover_address(digest: &[u8; 32], sig: &RawSignature) -> OicResult<Address> {
    check_low_s(&sig.s)?;
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(&sig.r);
    rs[32..].copy_from_slice(&sig.s);
    let signature = Signature::from_slice(&rs).map_err(|_| OicError::invalid_signature("r or s out of range"))?;
    if sig.y_parity > 1 {
        return Err(OicError::invalid_signature("recovery id must be 0 or 1"));
    }
    let recid = RecoveryId::from_byte(sig.y_parity).ok_or_else(|| OicError::invalid_signature("invalid recovery id"))?;
    let vk = VerifyingKey::recover_from_prehash(digest, &signature, recid)
        .map_err(|_| OicError::invalid_signature("public key recovery failed"))?;
    address_from_uncompressed(vk.to_encoded_point(false).as_bytes())
}

fn parse_tx_id(tx_id: &ChainTxId) -> OicResult<[u8; 32]> {
    let s = tx_id.as_str();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let v = hex::decode(s).map_err(|_| OicError::invalid_request("EVM tx id must be hex"))?;
    v.try_into().map_err(|_| OicError::invalid_request("EVM tx id must be 32 bytes"))
}

fn chain_tx_id(hash: &[u8; 32]) -> ChainTxId {
    ChainTxId::unchecked(format!("0x{}", hex::encode(hash)))
}

// ---------------------------------------------------------------------------
// ChainAdapter
// ---------------------------------------------------------------------------

impl ChainAdapter for EvmAdapter {
    fn manifest(&self) -> AdapterManifest {
        AdapterManifest {
            adapter_id: AdapterId::unchecked(ADAPTER_ID),
            adapter_version: ADAPTER_VERSION.to_string(),
            verifier_build_hash: verifier_build_hash(),
            signing_schemes: vec![SchemeId::EcdsaSecp256k1Keccak256Prehashed],
            accepted_transaction_versions: vec![VERSION_TYPE2.to_string(), VERSION_LEGACY.to_string()],
            supported_operations: vec![
                "native_transfer".to_string(),
                "erc20_transfer(address,uint256)".to_string(),
            ],
            supported_asset_standards: vec![
                "native".to_string(),
                "erc20 (registered contract instance, behavior=standard)".to_string(),
            ],
            replay_protection: "chain_id bound in the signing digest (EIP-1559 / EIP-155) and checked against profile network_binding; \
                per-(sender, nonce) uniqueness"
                .to_string(),
            expiry_behavior: "none: EOA transactions never expire on-chain; envelope deadlines do not limit chain validity".to_string(),
            resource_lock_rules: "reserve (network_id, sender, nonce); nonce must be >= evidence `nonce:<sender>`".to_string(),
            fee_accounting: "worst-case native fee = gas_limit * max_fee_per_gas (legacy: gas_price), checked u128; \
                builder sets max_fee_per_gas = 2*base_fee + priority_fee; no L2 data-fee component"
                .to_string(),
            replacement_rules: REPLACEMENT_RULE.to_string(),
            known_external_authorities: vec![
                "ERC-20 contract owner/admin (pause, blocklist, upgrade) for any enrolled token".to_string(),
                "existing EIP-7702 delegation or token allowances on the sender account (inventory required)".to_string(),
            ],
            conformance_vector_set: format!(
                "oic-adapter-evm/{ADAPTER_VERSION}: rlp classic vectors, published EIP-1559 encodings, alloy-consensus differential (signing hash, signer recovery)"
            ),
        }
    }

    fn identify_network(&self, profile: &ChainProfile, evidence: &EvidenceBundle) -> OicResult<VerifiedNetworkContext> {
        let chain_id = check_profile(profile)?;
        check_evidence_scope(profile, evidence, None)?;
        let observed = get_u64(evidence, KEY_CHAIN_ID)?;
        if observed != chain_id {
            return Err(OicError::scope(format!("evidence chain_id {observed} does not match profile chain_id {chain_id}")));
        }
        Ok(VerifiedNetworkContext {
            chain_profile_id: profile.chain_profile_id.clone(),
            chain_profile_hash: profile.hash()?,
            network_id: profile.network_id.clone(),
            state: evidence.state.clone(),
        })
    }

    fn build_candidate(&self, ctx: &BuildContext) -> OicResult<Candidate> {
        let profile = &ctx.profile;
        let chain_id = check_profile(profile)?;
        if !version_enabled(profile, VERSION_TYPE2) {
            return Err(OicError::unsupported("building requires `eip1559-type2` to be enabled; legacy building is not supported"));
        }
        check_evidence_scope(profile, &ctx.evidence, Some(ctx.built_at))?;
        let sender = check_wallet_scope(profile, &ctx.wallet, &ctx.key)?;
        let intent = &ctx.intent;
        if intent.chain_profile_id != profile.chain_profile_id || intent.chain_wallet_id != ctx.wallet.chain_wallet_id || intent.vault_id != ctx.wallet.vault_id {
            return Err(OicError::scope("intent wallet/profile/vault does not match build context"));
        }
        let IntentOperation::AssetTransfer { asset_id, amount_base_units, destination_id, destination_version } = &intent.operation;
        if *asset_id != ctx.asset.asset_id || ctx.asset.network_id != profile.network_id {
            return Err(OicError::scope("intent asset does not match the registered asset for this network"));
        }
        if *destination_id != ctx.destination.destination_id
            || *destination_version != ctx.destination.version
            || ctx.destination.network_id != profile.network_id
        {
            return Err(OicError::scope("intent destination/version/network does not match the registered destination"));
        }
        let dest = address::to_address(ctx.destination.address.as_slice(), "destination address")?;

        let nonce = get_u64(&ctx.evidence, &nonce_key(&sender))?;
        let (max_fee_per_gas, priority) = fee_cap_from_evidence(&ctx.evidence)?;
        let gas_limit = get_u64(&ctx.evidence, KEY_GAS_LIMIT)?;
        let fee_cap = (gas_limit as u128)
            .checked_mul(max_fee_per_gas)
            .ok_or_else(|| OicError::budget("gas_limit * max_fee_per_gas overflows u128"))?;
        if fee_cap > intent.constraints.max_network_fee_base_units.0 {
            return Err(OicError::budget(format!(
                "worst-case fee {fee_cap} exceeds intent max network fee {}",
                intent.constraints.max_network_fee_base_units
            )));
        }

        let (to, value, data) = match &ctx.asset.asset {
            AssetKind::Native => (dest, amount_base_units.0, Vec::new()),
            AssetKind::Erc20 { contract } => {
                if ctx.asset.behavior != AssetBehaviorProfile::Standard {
                    return Err(OicError::unsupported("asset behavior profile is non-standard; not automatically sendable"));
                }
                check_code_evidence(&ctx.evidence, contract.as_slice())?;
                let c = address::to_address(contract.as_slice(), "ERC-20 contract")?;
                (c, 0, calldata::encode_transfer(&dest, amount_base_units.0))
            }
            other => return Err(OicError::unsupported(format!("asset kind {other:?} is not an EVM asset"))),
        };
        let tx = EvmTx::Type2(Eip1559Tx {
            chain_id,
            nonce,
            max_priority_fee_per_gas: priority,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data,
            access_list: vec![],
        });
        let candidate = Candidate {
            candidate_id: ctx.candidate_id.clone(),
            candidate_revision: ctx.candidate_revision,
            intent_id: intent.intent_id.clone(),
            operation_family_id: ctx.operation_family_id.clone(),
            chain_profile_id: profile.chain_profile_id.clone(),
            adapter_id: AdapterId::unchecked(ADAPTER_ID),
            adapter_version: ADAPTER_VERSION.to_string(),
            native_unsigned_bytes: Bytes(tx.encode_unsigned()),
            signing_payloads: payloads_for(&tx, &ctx.key),
            evidence_bundle_hash: evidence_hash(&ctx.evidence)?,
            built_at: ctx.built_at,
        };
        // Builder self-check with the same verifier the signer runs.
        let vctx = VerifyContext {
            profile,
            wallet: &ctx.wallet,
            key: &ctx.key,
            asset: &ctx.asset,
            destination: &ctx.destination,
            evidence: &ctx.evidence,
        };
        self.verify_candidate(&candidate, &AuthorizationTarget::Intent(intent), &vctx)?;
        Ok(candidate)
    }

    fn decode_candidate(&self, candidate: &Candidate, ctx: &VerifyContext<'_>) -> OicResult<DecodedOperation> {
        check_candidate_scope(candidate, ctx.profile)?;
        let sender = check_key_scheme(ctx.key)?;
        let tx = parse_candidate_tx(candidate.native_unsigned_bytes.as_slice(), ctx.profile)?;
        decode_tx(&tx, ctx, &sender)
    }

    fn verify_candidate(&self, candidate: &Candidate, target: &AuthorizationTarget<'_>, ctx: &VerifyContext<'_>) -> OicResult<VerifiedOperation> {
        let profile = ctx.profile;
        check_evidence_scope(profile, ctx.evidence, None)?;
        check_candidate_scope(candidate, profile)?;
        let sender = check_wallet_scope(profile, ctx.wallet, ctx.key)?;
        let tx = parse_candidate_tx(candidate.native_unsigned_bytes.as_slice(), profile)?;
        let decoded = decode_tx(&tx, ctx, &sender)?;

        // The signer derives payloads itself; the candidate's array is only a comparison target.
        let payloads = payloads_for(&tx, ctx.key);
        if candidate.signing_payloads != payloads {
            return Err(OicError::unverifiable("candidate signing payloads differ from payloads derived from native bytes"));
        }

        // Asset identity is network + contract, never symbol/decimals.
        if ctx.asset.network_id != profile.network_id {
            return Err(OicError::scope("registered asset belongs to a different network"));
        }
        if decoded.asset() != &ctx.asset.asset {
            return Err(OicError::scope("decoded asset identity does not match the registered asset"));
        }

        // Destination binding.
        let dest = ctx.destination;
        if dest.network_id != profile.network_id {
            return Err(OicError::scope("destination network does not match profile"));
        }
        if dest.address.as_slice() != decoded.recipient().as_slice() {
            return Err(OicError::scope("decoded recipient does not match the registered destination address"));
        }
        if !dest.allowed_assets.is_empty() && !dest.allowed_assets.contains(&ctx.asset.asset_id) {
            return Err(OicError::scope("destination does not allow this asset"));
        }

        // Authorization target binding.
        let (asset_id, amount, dest_id, dest_version, max_fee, wallet_id) = match target {
            AuthorizationTarget::Intent(intent) => {
                if intent.chain_profile_id != profile.chain_profile_id {
                    return Err(OicError::scope("intent chain_profile_id does not match profile"));
                }
                if candidate.intent_id != intent.intent_id {
                    return Err(OicError::scope("candidate intent_id does not match intent"));
                }
                let IntentOperation::AssetTransfer { asset_id, amount_base_units, destination_id, destination_version } = &intent.operation;
                (
                    asset_id,
                    *amount_base_units,
                    destination_id,
                    *destination_version,
                    intent.constraints.max_network_fee_base_units,
                    &intent.chain_wallet_id,
                )
            }
            AuthorizationTarget::Template(t) => {
                if t.network_id != profile.network_id {
                    return Err(OicError::scope("template network does not match profile"));
                }
                if t.destination_address != dest.address {
                    return Err(OicError::scope("template destination address does not match the registered destination"));
                }
                check_template_fill(&tx, t, ctx.evidence, &sender)?;
                (&t.asset_id, t.amount_base_units, &t.destination_id, t.destination_version, t.max_native_fee_base_units, &t.chain_wallet_id)
            }
        };
        if *wallet_id != ctx.wallet.chain_wallet_id {
            return Err(OicError::scope("authorization target is for a different chain wallet"));
        }
        if *asset_id != ctx.asset.asset_id {
            return Err(OicError::scope("authorization target asset_id does not match the registered asset"));
        }
        if *dest_id != dest.destination_id || dest_version != dest.version {
            return Err(OicError::scope("authorization target destination/version does not match the registered destination"));
        }
        if decoded.amount() != amount {
            return Err(OicError::unverifiable(format!("decoded amount {} differs from authorized amount {amount}", decoded.amount())));
        }
        if decoded.max_native_fee() > max_fee {
            return Err(OicError::budget(format!(
                "worst-case native fee {} exceeds authorized maximum {max_fee}",
                decoded.max_native_fee()
            )));
        }

        // Nonce freshness: evidence is required.
        let ev_nonce = get_u64(ctx.evidence, &nonce_key(&sender))?;
        if tx.nonce() < ev_nonce {
            return Err(OicError::resource_conflict(format!("nonce {} already consumed (account nonce {ev_nonce})", tx.nonce())));
        }
        if let AssetKind::Erc20 { contract } = decoded.asset() {
            check_code_evidence(ctx.evidence, contract.as_slice())?;
        }

        let claims = ResourceClaims {
            resources: vec![NativeResource::EvmNonce { network_id: profile.network_id.clone(), sender: Bytes(sender.to_vec()), nonce: tx.nonce() }],
            asset_outflows: vec![AssetOutflow { asset_id: ctx.asset.asset_id.clone(), amount_base_units: decoded.amount() }],
            native_fees: vec![NativeFee { network_id: profile.network_id.clone(), amount_base_units: decoded.max_native_fee() }],
        };
        Ok(VerifiedOperation {
            decoded_operation_hash: decoded_operation_hash(&decoded)?,
            decoded,
            signing_payloads: payloads,
            claims,
            adapter_id: AdapterId::unchecked(ADAPTER_ID),
            adapter_version: ADAPTER_VERSION.to_string(),
            verifier_build_hash: verifier_build_hash(),
        })
    }

    fn signing_payloads(&self, native_unsigned_bytes: &Bytes, key: &KeyDescriptor) -> OicResult<Vec<NativeSigningPayload>> {
        check_key_scheme(key)?;
        let tx = EvmTx::decode_unsigned(native_unsigned_bytes.as_slice())?;
        reject_access_list(&tx)?;
        Ok(payloads_for(&tx, key))
    }

    fn assemble_signed_transaction(&self, candidate: &Candidate, key: &KeyDescriptor, signatures: &[SignatureBytes]) -> OicResult<SignedTransaction> {
        let [sig] = signatures else {
            return Err(OicError::invalid_signature(format!("EVM transactions need exactly one signature, got {}", signatures.len())));
        };
        if sig.scheme != SchemeId::EcdsaSecp256k1Keccak256Prehashed {
            return Err(OicError::invalid_signature(format!("signature scheme {:?} is not secp256k1/keccak256", sig.scheme)));
        }
        let b = sig.bytes.as_slice();
        if b.len() != 65 {
            return Err(OicError::invalid_signature("signature must be 65 bytes r||s||v"));
        }
        if b[64] > 1 {
            return Err(OicError::invalid_signature("recovery id v must be 0 or 1"));
        }
        let raw = RawSignature { y_parity: b[64], r: b[..32].try_into().expect("32"), s: b[32..64].try_into().expect("32") };
        check_low_s(&raw.s)?;
        Signature::from_slice(&b[..64]).map_err(|_| OicError::invalid_signature("r or s out of range"))?;
        let tx = EvmTx::decode_unsigned(candidate.native_unsigned_bytes.as_slice())?;
        reject_access_list(&tx)?;
        let signed_bytes = tx.encode_signed(&raw);
        let signed = SignedTransaction {
            candidate_id: candidate.candidate_id.clone(),
            candidate_revision: candidate.candidate_revision,
            chain_tx_id: chain_tx_id(&tx::tx_hash(&signed_bytes)),
            signed_bytes: Bytes(signed_bytes),
        };
        self.verify_signed_transaction(&signed, candidate, key)?;
        Ok(signed)
    }

    fn verify_signed_transaction(&self, signed: &SignedTransaction, candidate: &Candidate, key: &KeyDescriptor) -> OicResult<VerifiedSignedTransaction> {
        if signed.candidate_id != candidate.candidate_id || signed.candidate_revision != candidate.candidate_revision {
            return Err(OicError::scope("signed transaction is for a different candidate/revision"));
        }
        let expected = check_key_scheme(key)?;
        let (tx, sig) = EvmTx::decode_signed(signed.signed_bytes.as_slice())?;
        if tx.encode_unsigned() != candidate.native_unsigned_bytes.as_slice() {
            return Err(OicError::unverifiable("signed transaction does not re-encode to the approved candidate bytes"));
        }
        if tx.encode_signed(&sig) != signed.signed_bytes.as_slice() {
            return Err(OicError::unverifiable("signed transaction bytes are not canonical"));
        }
        let hash = tx::tx_hash(signed.signed_bytes.as_slice());
        if parse_tx_id(&signed.chain_tx_id)? != hash {
            return Err(OicError::unverifiable("chain_tx_id is not keccak256 of the signed bytes"));
        }
        let recovered = recover_address(&tx.signing_digest(), &sig)?;
        if recovered != expected {
            return Err(OicError::invalid_signature("recovered signer does not match the registered key"));
        }
        Ok(VerifiedSignedTransaction { signed: signed.clone(), verified_signers: vec![Bytes(recovered.to_vec())] })
    }

    fn observe(&self, tx_id: &ChainTxId, profile: &ChainProfile, evidence: &EvidenceBundle) -> OicResult<ChainObservation> {
        check_evidence_scope(profile, evidence, None)?;
        let hash = parse_tx_id(tx_id)?;
        let obs = get_tx_observation(evidence, &hash)?;
        if !obs.included {
            let source = evidence.sources.first().cloned().ok_or_else(|| OicError::stale_evidence("evidence names no source"))?;
            return Ok(ChainObservation::Submitted { tx_id: tx_id.clone(), source, at: evidence.observed_at });
        }
        if obs.block_height > evidence.state.height {
            return Err(OicError::stale_evidence("inclusion height is above the evidence state height"));
        }
        let fee_paid = (obs.gas_used as u128)
            .checked_mul(obs.effective_gas_price.0)
            .ok_or_else(|| OicError::unverifiable("gas_used * effective_gas_price overflows u128"))?;
        // RFC 0001 §9.4: finality comes from the chain's own finalized view,
        // not from a confirmation count over the latest block. Evidence taken
        // at any other commitment can show inclusion at most. Inclusion at the
        // finalized view is already final: the view itself sits behind the head
        // by the finality depth, so counting confirmations again would demand
        // that depth twice.
        if evidence.state.commitment == profile.finality_commitment {
            let raw = get_item(evidence, &tx_key(&hash))?;
            Ok(ChainObservation::Finalized {
                tx_id: tx_id.clone(),
                state: StateReference { height: obs.block_height, hash: obs.block_hash, commitment: profile.finality_commitment.clone() },
                execution_success: obs.success,
                fee_paid: Amount(fee_paid),
                effects_hash: oic_canonical_encoding::sha256(raw),
            })
        } else {
            Ok(ChainObservation::Included {
                tx_id: tx_id.clone(),
                state: StateReference { height: obs.block_height, hash: obs.block_hash, commitment: "included".to_string() },
                execution_success: obs.success,
                fee_paid: Amount(fee_paid),
            })
        }
    }

    fn prove_invalidation(
        &self,
        family: &OperationFamilyId,
        candidates: &[Candidate],
        profile: &ChainProfile,
        evidence: &EvidenceBundle,
    ) -> OicResult<InvalidationEvidence> {
        check_evidence_scope(profile, evidence, None)?;
        if candidates.is_empty() {
            return Ok(InvalidationEvidence::Unknown);
        }
        for c in candidates {
            if &c.operation_family_id != family {
                return Err(OicError::invalid_request("candidate does not belong to the operation family"));
            }
            check_candidate_scope(c, profile)?;
        }
        // The nonce must be consumed under the profile's finality commitment.
        if evidence.state.commitment != profile.finality_commitment {
            return Ok(InvalidationEvidence::Unknown);
        }
        // Every possibly-issued candidate must be accounted for by its signed bytes.
        let mut sender: Option<Address> = None;
        let mut family_txs: Vec<([u8; 32], u64)> = Vec::with_capacity(candidates.len());
        for c in candidates {
            let tx = EvmTx::decode_unsigned(c.native_unsigned_bytes.as_slice())?;
            let Some(signed) = evidence.items.get(&signed_tx_key(c.candidate_id.as_str(), c.candidate_revision)) else {
                return Ok(InvalidationEvidence::Unknown);
            };
            let (stx, sig) = EvmTx::decode_signed(signed.as_slice())?;
            if stx.encode_unsigned() != c.native_unsigned_bytes.as_slice() || stx != tx {
                return Err(OicError::unverifiable("signed_tx evidence does not match the candidate bytes"));
            }
            let who = recover_address(&stx.signing_digest(), &sig)?;
            match sender {
                None => sender = Some(who),
                Some(s) if s != who => return Err(OicError::unverifiable("operation family candidates have different senders")),
                _ => {}
            }
            family_txs.push((tx::tx_hash(signed.as_slice()), tx.nonce()));
        }
        let sender = sender.expect("non-empty");
        let Ok(account_nonce) = get_u64(evidence, &nonce_key(&sender)) else {
            return Ok(InvalidationEvidence::Unknown);
        };
        let mut consumers = Vec::new();
        for (hash, nonce) in &family_txs {
            if account_nonce <= *nonce {
                return Ok(InvalidationEvidence::Unknown);
            }
            let Ok(obs) = get_tx_observation(evidence, hash) else {
                return Ok(InvalidationEvidence::Unknown);
            };
            if obs.included {
                // It executed (success or revert): not an invalidation.
                return Ok(InvalidationEvidence::Unknown);
            }
            let Some(consumer) = obs.nonce_consumed_by else {
                return Ok(InvalidationEvidence::Unknown);
            };
            let consumer: [u8; 32] = consumer.as_slice().try_into().expect("validated length");
            if family_txs.iter().any(|(h, _)| *h == consumer) {
                // A family member consumed the nonce; a replacement landing is not invalidation of the family.
                return Ok(InvalidationEvidence::Unknown);
            }
            let Ok(cobs) = get_tx_observation(evidence, &consumer) else {
                return Ok(InvalidationEvidence::Unknown);
            };
            if !cobs.included || cobs.confirmations < profile.finality_depth.max(1) {
                return Ok(InvalidationEvidence::Unknown);
            }
            consumers.push(hex::encode(consumer));
        }
        consumers.sort();
        consumers.dedup();
        Ok(InvalidationEvidence::Definitive {
            reason: format!(
                "sender {} nonce advanced to {account_nonce}; family nonce(s) consumed under `{}` by non-family tx(s) 0x{}",
                eip55(&sender),
                profile.finality_commitment,
                consumers.join(",0x")
            ),
            state: evidence.state.clone(),
        })
    }

    fn validity_constraints(&self, candidate: &Candidate, _evidence: &EvidenceBundle) -> OicResult<ChainValidityConstraints> {
        let tx = EvmTx::decode_unsigned(candidate.native_unsigned_bytes.as_slice())?;
        reject_access_list(&tx)?;
        Ok(ChainValidityConstraints { expires_at_height: None, replacement_rule: REPLACEMENT_RULE.to_string() })
    }

    fn derive_address(&self, key: &PublicKey) -> OicResult<(Bytes, String)> {
        let a = address_from_public_key(key)?;
        Ok((Bytes(a.to_vec()), eip55(&a)))
    }
}

/// Keccak-256 re-export for callers computing `code:` evidence values.
pub fn code_hash(code: &[u8]) -> [u8; 32] {
    keccak256(code)
}
