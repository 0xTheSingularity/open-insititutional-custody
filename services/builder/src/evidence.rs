//! Evidence acquisition (RFC 0001 §1.1 "Evidence service", §12.3).
//!
//! The builder never performs I/O itself: chain state reaches it only
//! through an [`EvidenceSource`]. A source is asked for exactly the items the
//! pinned adapter consumes for one transfer:
//!
//! | Adapter | Asset | Items |
//! |---|---|---|
//! | EVM | native, ERC-20 | `chain_id`, `base_fee`, `priority_fee`, `gas_limit`, `nonce:<sender>`; ERC-20 adds `code:<contract>` |
//! | Solana | native, SPL | `genesis_hash`, `recent_blockhash`, `blockhash_last_valid_height`, `lamports_per_signature`, `rent_exempt_minimum:token_account` (and `cu_limit`/`cu_price` when the chain publishes them); SPL adds `token_account:<source ATA>` and `token_account:<destination ATA>`; v0 candidates add `alt:<table>` per lookup table |
//!
//! A source never invents an item. An absent account (for example a
//! destination ATA that does not exist yet, or a source ATA that was never
//! created) is simply missing from the bundle, so the adapter decides what
//! that means and fails with its own error when the item is mandatory.

use oic_adapter_api::ChainProfile;
use oic_adapter_evm::address::Address;
use oic_adapter_solana::address::{associated_token_address, to_pubkey, Pubkey};
use oic_adapter_solana::message::Message;
use oic_chain_simulator::evm::{EvmEvidenceQuery, EvmSimulator};
use oic_chain_simulator::solana::{SolanaEvidenceQuery, SolanaSimulator};
use oic_domain_types::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Which chain view the evidence is taken from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCommitment {
    /// The newest state the source knows (EVM `latest`, Solana `processed`).
    Latest,
    /// The profile's finality commitment (EVM `finalized`, Solana `finalized`).
    Finalized,
}

/// One evidence request: everything a source needs to decide which items
/// the adapter will read for this transfer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRequest {
    pub profile: ChainProfile,
    pub wallet: ChainWallet,
    pub asset: Asset,
    pub destination: CounterpartyDestination,
    pub commitment: EvidenceCommitment,
    /// Solana address lookup tables a (v0) candidate reads; empty for
    /// candidates the builder constructs (legacy messages) and always empty
    /// for EVM. See [`solana_lookup_tables`].
    pub lookup_tables: Vec<Bytes>,
}

/// A chain-state provider. Implementations package state in the item
/// formats of the pinned adapters (see the module docs).
pub trait EvidenceSource: Send + Sync {
    fn evidence(&self, req: &EvidenceRequest) -> OicResult<EvidenceBundle>;
}

/// The request's objects must all describe the network the source serves,
/// and the requested profile must be exactly the source's enrolled profile.
fn check_request_scope(req: &EvidenceRequest, served: &ChainProfile) -> OicResult<()> {
    if req.profile.hash()? != served.hash()? {
        return Err(OicError::scope(format!(
            "requested chain profile {} is not the profile this evidence source serves ({})",
            req.profile.chain_profile_id, served.chain_profile_id
        )));
    }
    let net = &served.network_id;
    if &req.wallet.network_id != net || req.wallet.chain_profile_id != served.chain_profile_id {
        return Err(OicError::scope("wallet is enrolled on a different network or chain profile"));
    }
    if &req.asset.network_id != net {
        return Err(OicError::scope("asset is registered on a different network"));
    }
    if &req.destination.network_id != net {
        return Err(OicError::scope("destination is registered on a different network"));
    }
    Ok(())
}

fn evm_address(b: &Bytes, what: &str) -> OicResult<Address> {
    b.as_slice().try_into().map_err(|_| OicError::scope(format!("{what} must be a 20-byte EVM address")))
}

/// Evidence from the in-process EVM development simulator.
#[derive(Clone)]
pub struct EvmSimulatorEvidence(pub Arc<EvmSimulator>);

impl EvidenceSource for EvmSimulatorEvidence {
    fn evidence(&self, req: &EvidenceRequest) -> OicResult<EvidenceBundle> {
        check_request_scope(req, &self.0.profile())?;
        if !req.lookup_tables.is_empty() {
            return Err(OicError::invalid_request("EVM evidence has no address lookup tables"));
        }
        let sender = evm_address(&req.wallet.address, "wallet address")?;
        let mut q = match req.commitment {
            EvidenceCommitment::Latest => EvmEvidenceQuery::latest(),
            EvidenceCommitment::Finalized => EvmEvidenceQuery::finalized(),
        }
        .sender(sender);
        match &req.asset.asset {
            AssetKind::Native => {}
            AssetKind::Erc20 { contract } => q = q.contract(evm_address(contract, "ERC-20 contract")?),
            other => return Err(OicError::unsupported(format!("asset kind {other:?} is not an EVM asset"))),
        }
        self.0.evidence(&q)
    }
}

/// Evidence from the in-process Solana development simulator.
#[derive(Clone)]
pub struct SolanaSimulatorEvidence(pub Arc<SolanaSimulator>);

impl EvidenceSource for SolanaSimulatorEvidence {
    fn evidence(&self, req: &EvidenceRequest) -> OicResult<EvidenceBundle> {
        check_request_scope(req, &self.0.profile())?;
        let mut q = match req.commitment {
            EvidenceCommitment::Latest => SolanaEvidenceQuery::processed(),
            EvidenceCommitment::Finalized => SolanaEvidenceQuery::finalized(),
        };
        match &req.asset.asset {
            AssetKind::Native => {}
            AssetKind::SplToken { mint, token_program } => {
                let wallet: Pubkey = to_pubkey(req.wallet.address.as_slice(), "wallet address")?;
                let owner: Pubkey = to_pubkey(req.destination.address.as_slice(), "destination address")?;
                let mint: Pubkey = to_pubkey(mint.as_slice(), "asset mint")?;
                let program: Pubkey = to_pubkey(token_program.as_slice(), "asset token program")?;
                q = q.token_account(associated_token_address(&wallet, &mint, &program)?).token_account(associated_token_address(&owner, &mint, &program)?);
            }
            other => return Err(OicError::unsupported(format!("asset kind {other:?} is not a Solana asset"))),
        }
        for t in &req.lookup_tables {
            q = q.lookup_table(to_pubkey(t.as_slice(), "lookup table address")?);
        }
        self.0.evidence(&q)
    }
}

/// Address lookup tables a Solana candidate's message reads (empty for
/// legacy messages), in message order, for [`EvidenceRequest::lookup_tables`]
/// when re-acquiring evidence to verify an existing candidate.
pub fn solana_lookup_tables(candidate: &Candidate) -> OicResult<Vec<Bytes>> {
    if candidate.adapter_id.as_str() != oic_adapter_solana::ADAPTER_ID {
        return Err(OicError::unsupported(format!("candidate adapter {} is not the Solana adapter", candidate.adapter_id)));
    }
    let msg = Message::decode(candidate.native_unsigned_bytes.as_slice())?;
    Ok(msg.address_table_lookups.iter().map(|l| Bytes(l.account_key.to_vec())).collect())
}
