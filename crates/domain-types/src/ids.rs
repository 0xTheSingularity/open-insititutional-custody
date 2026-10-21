//! Globally unambiguous identifiers (RFC 0001 §3.1).
//!
//! Every identifier is a distinct newtype so that an `IntentId` can never be
//! passed where a `VaultId` is expected. Identifiers are opaque strings bounded
//! to a conservative length so they cannot be used to smuggle large payloads
//! through canonical encoding.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum identifier length in bytes. Longer identifiers are rejected at
/// construction and at decode time.
pub const MAX_ID_LEN: usize = 128;

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Construct an identifier. Returns `None` if empty or too long.
            pub fn new(s: impl Into<String>) -> Option<Self> {
                let s = s.into();
                if s.is_empty() || s.len() > MAX_ID_LEN || !s.bytes().all(|b| b.is_ascii_graphic()) {
                    return None;
                }
                Some(Self(s))
            }

            /// Construct without validation. Only for literals in tests and fixtures.
            pub fn unchecked(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

id_type!(#[doc = "Security root for one deployment."] InstitutionId);
id_type!(#[doc = "`mainnet`, `testnet`, `dev`... Keys and policies never cross environments (I8)."] EnvironmentId);
id_type!(#[doc = "Logical group of chain wallets sharing a risk tier and policy."] VaultId);
id_type!(#[doc = "One native address/account bound to one key and network profile."] ChainWalletId);
id_type!(#[doc = "Distributed key identity; combined with `KeyEpoch` for freshness."] KeyId);
id_type!(#[doc = "Immutable business intent."] IntentId);
id_type!(#[doc = "Groups all candidates (original + replacements) for one intent."] OperationFamilyId);
id_type!(#[doc = "One exact unsigned native transaction."] CandidateId);
id_type!(#[doc = "Enrolled network profile (`evm-sepolia-v1`, `solana-devnet-v1`)."] ChainProfileId);
id_type!(#[doc = "Network identity string committed into evidence and envelopes."] NetworkId);
id_type!(#[doc = "Chain adapter identity (`evm`, `solana`)."] AdapterId);
id_type!(#[doc = "Policy bundle identity."] PolicyId);
id_type!(#[doc = "Asset registry entry. Metadata is not identity."] AssetId);
id_type!(#[doc = "Versioned counterparty destination."] DestinationId);
id_type!(#[doc = "Reservation at the authorization-state authority."] ReservationId);
id_type!(#[doc = "One backend protocol execution."] SigningSessionId);
id_type!(#[doc = "Configuration proposal (destination, policy, membership...)."] ProposalId);
id_type!(#[doc = "MPC participant / signer domain identity."] ParticipantId);
id_type!(#[doc = "Approval or administrative credential identity."] CredentialId);
id_type!(#[doc = "Approval grant identity."] GrantId);
id_type!(#[doc = "Issuance record identity."] IssuanceId);
id_type!(#[doc = "Chain transaction identity (hash / signature) as the chain presents it."] ChainTxId);
id_type!(#[doc = "Audit event identity."] AuditEventId);
id_type!(#[doc = "Evidence source identity (node, provider)."] EvidenceSourceId);
id_type!(#[doc = "Signer instance generation / fencing token issuer."] SignerInstanceId);
// RFC 0002 operational objects.
id_type!(#[doc = "Deposit address lifecycle record (RFC 0002 §4)."] DepositAddressId);
id_type!(#[doc = "One observed chain movement (RFC 0002 §4)."] MovementId);
id_type!(#[doc = "Indexer cursor per chain profile (RFC 0002 §4)."] CursorId);
id_type!(#[doc = "Backfill job over a height range (RFC 0002 §4)."] BackfillJobId);
id_type!(#[doc = "Deposit or reconciliation exception case (RFC 0002 §4, §6)."] CaseId);
id_type!(#[doc = "Reconciliation checkpoint (RFC 0002 §6)."] CheckpointId);
id_type!(#[doc = "Immutable journal entry (RFC 0002 §6)."] JournalEntryId);
id_type!(#[doc = "Workflow instance above the intent API (RFC 0002 §5)."] WorkflowId);
id_type!(#[doc = "Durable workflow trigger identity (RFC 0002 §5)."] TriggerId);
id_type!(#[doc = "Webhook subscription (RFC 0001 §13.4)."] WebhookSubscriptionId);
id_type!(#[doc = "Lifecycle/webhook event identity (RFC 0001 §13.4)."] EventId);
// RFC 0003 institution-operated networks.
id_type!(#[doc = "Roster-admitted network node."] NodeId);
id_type!(#[doc = "Independent administrative and failure domain."] TrustDomainId);
id_type!(#[doc = "Roster-defined key, verification, authority, or witness committee."] CommitteeId);

/// Monotonic epoch counter used for keys, policies, and signer generations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct Epoch(pub u64);

impl Epoch {
    pub fn next(self) -> Epoch {
        Epoch(self.0 + 1)
    }
}

impl fmt::Display for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
