//! Explicit development-chain discovery profiles. EVM covers transaction
//! value and classic Transfer logs, not internal calls/traces. Solana covers
//! actual lamport and classic-token deltas, including failed-transaction fees.
use oic_adapter_api::ChainProfile;
use oic_chain_simulator::{evm::*, solana::*};
use oic_domain_types::*;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectKind {
    Transfer,
    Fee,
    AccountFunding { account: Bytes },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainEffect {
    pub tx_id: ChainTxId,
    /// Unique per transaction *and leg*. Two monitored internal wallets do
    /// not collide on the deduplication identity.
    pub index: u32,
    pub address: Bytes,
    pub counterparty: Bytes,
    pub direction: MovementDirection,
    pub asset: AssetKind,
    pub amount: Amount,
    pub mechanism: DiscoveryMechanism,
    pub kind: EffectKind,
}

pub struct IndexedBlock {
    pub state: StateReference,
    pub parent_hash: Bytes,
    pub effects: Vec<ChainEffect>,
}

pub trait BlockSource: Send + Sync {
    fn profile(&self) -> ChainProfile;
    fn source_id(&self) -> EvidenceSourceId;
    fn now(&self) -> UnixSeconds;
    fn head(&self) -> StateReference;
    fn finalized(&self) -> StateReference;
    fn block(&self, height: u64) -> OicResult<IndexedBlock>;
    fn balance(
        &self,
        state: &StateReference,
        address: &Bytes,
        asset: &AssetKind,
    ) -> OicResult<Amount>;
}

fn missing() -> OicError {
    OicError::stale_evidence("missing block; backfill required")
}

pub struct EvmBlocks(pub Arc<EvmSimulator>);

impl BlockSource for EvmBlocks {
    fn profile(&self) -> ChainProfile {
        self.0.profile()
    }
    fn source_id(&self) -> EvidenceSourceId {
        EvidenceSourceId::unchecked(oic_chain_simulator::evm::SOURCE_ID)
    }
    fn now(&self) -> UnixSeconds {
        self.0.clock().now()
    }
    fn head(&self) -> StateReference {
        self.0.head()
    }
    fn finalized(&self) -> StateReference {
        self.0.finalized()
    }
    fn balance(
        &self,
        state: &StateReference,
        address: &Bytes,
        asset: &AssetKind,
    ) -> OicResult<Amount> {
        self.0.balance_at(
            state,
            &address
                .as_slice()
                .try_into()
                .map_err(|_| OicError::invalid_request("EVM address length"))?,
            asset,
        )
    }
    fn block(&self, height: u64) -> OicResult<IndexedBlock> {
        let b = self.0.block(height).ok_or_else(missing)?;
        let state = StateReference {
            height,
            hash: Bytes(b.hash.to_vec()),
            commitment: "latest".into(),
        };
        let mut effects = Vec::new();
        for tx in b.transactions {
            let id = oic_chain_simulator::evm::tx_id(&tx.hash);
            let mut push = |index,
                            address: [u8; 20],
                            counterparty: [u8; 20],
                            direction,
                            asset,
                            amount,
                            mechanism,
                            kind| {
                if amount > 0 {
                    effects.push(ChainEffect {
                        tx_id: id.clone(),
                        index,
                        address: Bytes(address.to_vec()),
                        counterparty: Bytes(counterparty.to_vec()),
                        direction,
                        asset,
                        amount: Amount(amount),
                        mechanism,
                        kind,
                    });
                }
            };
            push(
                0,
                tx.from,
                [0; 20],
                MovementDirection::Outbound,
                AssetKind::Native,
                tx.receipt.fee_paid(),
                DiscoveryMechanism::EvmTransactionValue,
                EffectKind::Fee,
            );
            if tx.receipt.success {
                push(
                    1,
                    tx.from,
                    tx.to,
                    MovementDirection::Outbound,
                    AssetKind::Native,
                    tx.value,
                    DiscoveryMechanism::EvmTransactionValue,
                    EffectKind::Transfer,
                );
                push(
                    2,
                    tx.to,
                    tx.from,
                    MovementDirection::Inbound,
                    AssetKind::Native,
                    tx.value,
                    DiscoveryMechanism::EvmTransactionValue,
                    EffectKind::Transfer,
                );
                for (i, log) in tx.receipt.logs.iter().enumerate() {
                    if log.topics.len() != 3 || log.topics[0] != transfer_topic0() {
                        continue;
                    }
                    if log.data.len() != 32
                        || log.data[..16].iter().any(|b| *b != 0)
                        || log.topics[1][..12]
                            .iter()
                            .chain(&log.topics[2][..12])
                            .any(|b| *b != 0)
                    {
                        return Err(OicError::unverifiable("malformed Transfer log"));
                    }
                    let from = log.topics[1][12..].try_into().expect("20 bytes");
                    let to = log.topics[2][12..].try_into().expect("20 bytes");
                    let amount = u128::from_be_bytes(log.data[16..].try_into().expect("16 bytes"));
                    let asset = AssetKind::Erc20 {
                        contract: Bytes(log.address.to_vec()),
                    };
                    let index = u32::try_from(i)
                        .ok()
                        .and_then(|i| i.checked_mul(2))
                        .and_then(|i| i.checked_add(3))
                        .ok_or_else(|| OicError::unverifiable("too many logs"))?;
                    push(
                        index,
                        from,
                        to,
                        MovementDirection::Outbound,
                        asset.clone(),
                        amount,
                        DiscoveryMechanism::EvmErc20TransferLog,
                        EffectKind::Transfer,
                    );
                    push(
                        index + 1,
                        to,
                        from,
                        MovementDirection::Inbound,
                        asset,
                        amount,
                        DiscoveryMechanism::EvmErc20TransferLog,
                        EffectKind::Transfer,
                    );
                }
            }
        }
        // Simulator-only mint setup is explicit evidence, never inferred revenue.
        for (i, op) in b.system_ops.iter().enumerate() {
            if let EvmSystemOp::DeployErc20 {
                address,
                holder,
                supply,
                ..
            } = op
            {
                if *supply > 0 {
                    effects.push(ChainEffect {
                        tx_id: ChainTxId::unchecked(format!(
                            "setup-evm-{}-{i}",
                            state.hash.to_hex()
                        )),
                        index: 0,
                        address: Bytes(holder.to_vec()),
                        counterparty: Bytes(vec![0; 20]),
                        direction: MovementDirection::Inbound,
                        asset: AssetKind::Erc20 {
                            contract: Bytes(address.to_vec()),
                        },
                        amount: Amount(*supply),
                        mechanism: DiscoveryMechanism::EvmErc20TransferLog,
                        kind: EffectKind::Transfer,
                    });
                }
            }
        }
        Ok(IndexedBlock {
            state,
            parent_hash: Bytes(b.parent_hash.to_vec()),
            effects,
        })
    }
}

pub struct SolanaBlocks(pub Arc<SolanaSimulator>);

impl BlockSource for SolanaBlocks {
    fn profile(&self) -> ChainProfile {
        self.0.profile()
    }
    fn source_id(&self) -> EvidenceSourceId {
        EvidenceSourceId::unchecked(oic_chain_simulator::solana::SOURCE_ID)
    }
    fn now(&self) -> UnixSeconds {
        self.0.clock().now()
    }
    fn head(&self) -> StateReference {
        self.0.head()
    }
    fn finalized(&self) -> StateReference {
        self.0.finalized()
    }
    fn balance(
        &self,
        state: &StateReference,
        address: &Bytes,
        asset: &AssetKind,
    ) -> OicResult<Amount> {
        self.0.balance_at(
            state,
            &address
                .as_slice()
                .try_into()
                .map_err(|_| OicError::invalid_request("Solana address length"))?,
            asset,
        )
    }
    fn block(&self, height: u64) -> OicResult<IndexedBlock> {
        let b = self.0.block(height).ok_or_else(missing)?;
        let state = StateReference {
            height,
            hash: Bytes(b.blockhash.to_vec()),
            commitment: "processed".into(),
        };
        let mut effects = Vec::new();
        for tx in b.transactions {
            let mut index = 0;
            let mut push = |address: [u8; 32], asset, pre: u128, post: u128, mechanism, kind| {
                if pre != post {
                    effects.push(ChainEffect {
                        tx_id: tx.tx_id(),
                        index,
                        address: Bytes(address.to_vec()),
                        counterparty: Bytes::default(),
                        direction: if pre > post {
                            MovementDirection::Outbound
                        } else {
                            MovementDirection::Inbound
                        },
                        asset,
                        amount: Amount(pre.abs_diff(post)),
                        mechanism,
                        kind,
                    });
                }
                index += 1;
            };
            if let Some(payer) = tx.account_keys.first() {
                push(
                    *payer,
                    AssetKind::Native,
                    tx.fee as u128,
                    0,
                    DiscoveryMechanism::SolanaLamportDelta,
                    EffectKind::Fee,
                );
            }
            // Attribute newly created token-account rent separately from fees.
            let created: Vec<_> = tx
                .post_token_balances
                .iter()
                .filter(|t| !tx.pre_token_balances.iter().any(|p| p.account == t.account))
                .collect();
            let mut rent = 0u128;
            for t in &created {
                let amount = tx.post_lamports[t.account_index] as u128;
                rent = rent
                    .checked_add(amount)
                    .ok_or_else(|| OicError::unverifiable("rent overflow"))?;
                push(
                    tx.account_keys[0],
                    AssetKind::Native,
                    amount,
                    0,
                    DiscoveryMechanism::SolanaLamportDelta,
                    EffectKind::AccountFunding {
                        account: Bytes(t.account.to_vec()),
                    },
                );
            }
            for (i, account) in tx.account_keys.iter().enumerate() {
                // Token-account rent is not the owner's spendable native holdings.
                if tx
                    .pre_token_balances
                    .iter()
                    .chain(&tx.post_token_balances)
                    .any(|t| t.account == *account)
                {
                    continue;
                }
                let post =
                    tx.post_lamports[i] as u128 + if i == 0 { tx.fee as u128 + rent } else { 0 };
                push(
                    *account,
                    AssetKind::Native,
                    tx.pre_lamports[i] as u128,
                    post,
                    DiscoveryMechanism::SolanaLamportDelta,
                    EffectKind::Transfer,
                );
            }
            for post in &tx.post_token_balances {
                let pre = tx
                    .pre_token_balances
                    .iter()
                    .find(|p| p.account == post.account)
                    .map(|p| p.amount)
                    .unwrap_or(0);
                push(
                    post.owner,
                    AssetKind::SplToken {
                        mint: Bytes(post.mint.to_vec()),
                        token_program: Bytes(
                            oic_adapter_solana::address::TOKEN_PROGRAM_ID.to_vec(),
                        ),
                    },
                    pre as u128,
                    post.amount as u128,
                    DiscoveryMechanism::SolanaTokenBalanceDelta,
                    EffectKind::Transfer,
                );
            }
        }
        for (i, op) in b.system_ops.iter().enumerate() {
            if let SolanaSystemOp::MintTo {
                mint,
                account,
                amount,
            } = op
            {
                // Setup operations precede transactions. Resolve the owner from the
                // account creation record, which remains available across forks.
                let owner = (0..=height)
                    .rev()
                    .filter_map(|h| self.0.block(h))
                    .flat_map(|b| b.system_ops)
                    .find_map(|op| match op {
                        SolanaSystemOp::CreateTokenAccount {
                            account: a, owner, ..
                        } if a == *account => Some(owner),
                        _ => None,
                    })
                    .ok_or_else(|| OicError::unverifiable("mint setup account owner missing"))?;
                effects.push(ChainEffect {
                    tx_id: ChainTxId::unchecked(format!("setup-sol-{}-{i}", state.hash.to_hex())),
                    index: 0,
                    address: Bytes(owner.to_vec()),
                    counterparty: Bytes::default(),
                    direction: MovementDirection::Inbound,
                    asset: AssetKind::SplToken {
                        mint: Bytes(mint.to_vec()),
                        token_program: Bytes(
                            oic_adapter_solana::address::TOKEN_PROGRAM_ID.to_vec(),
                        ),
                    },
                    amount: Amount(*amount as u128),
                    mechanism: DiscoveryMechanism::SolanaTokenBalanceDelta,
                    kind: EffectKind::Transfer,
                });
            }
        }
        Ok(IndexedBlock {
            state,
            parent_hash: Bytes(b.parent_blockhash.to_vec()),
            effects,
        })
    }
}
