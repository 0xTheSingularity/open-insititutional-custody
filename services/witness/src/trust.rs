use crate::{invalid, require};
use ed25519_dalek::VerifyingKey;
use oic_authorization_state::SignedCheckpoint;
use oic_domain_types::*;
use oic_membership::{AdminTrust, Role, SignedRoster, validate_roster};
use std::collections::{BTreeMap, BTreeSet};

/// Out-of-band service identity. Audit and receipt keys are NOT transport or
/// attestation keys. Audit checkpoints lack scope fields, so their enrolled key
/// binding is mandatory and must never be populated from incoming messages.
#[derive(Clone, Debug)]
pub struct ServiceKey {
    pub node_id: NodeId,
    pub key_id: KeyId,
    pub key: VerifyingKey,
}

#[derive(Clone, Debug)]
pub struct WitnessTrust {
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub witness_id: NodeId,
    pub admins: AdminTrust,
    pub committed_roster_hashes: BTreeMap<u64, Hash32>,
    pub rosters: Vec<SignedRoster>,
    pub authority: ServiceKey,
    pub audits: Vec<ServiceKey>,
    pub operations: ServiceKey,
    pub policy_admin_keys: Vec<(CredentialId, VerifyingKey)>,
    pub policy_admin_quorum: u8,
}

impl WitnessTrust {
    pub fn validate(&self, now: UnixSeconds) -> OicResult<()> {
        require(
            !self.rosters.is_empty(),
            "witness needs independently committed roster chain",
        )?;
        require(
            self.rosters.last().map(|r| r.body.roster_epoch)
                == self
                    .committed_roster_hashes
                    .last_key_value()
                    .map(|(epoch, _)| *epoch),
            "roster chain omits independently committed epochs",
        )?;
        let mut previous = None;
        for roster in &self.rosters {
            let hash = self
                .committed_roster_hashes
                .get(&roster.body.roster_epoch)
                .ok_or_else(|| invalid("missing independent roster activation commitment"))?;
            validate_roster(
                roster,
                &self.admins,
                &self.institution_id,
                &self.environment_id,
                previous,
                now,
                *hash,
            )?;
            let local = roster
                .node(&self.witness_id)
                .ok_or_else(|| invalid("witness absent from roster"))?;
            require(
                local.roles == [Role::Witness],
                "local identity is not an isolated witness",
            )?;
            let authority = roster
                .node(&self.authority.node_id)
                .ok_or_else(|| invalid("authority service absent from roster"))?;
            require(
                authority.roles.contains(&Role::Authority),
                "authority key binding lacks authority role",
            )?;
            for key in self.audits.iter().chain([&self.operations]) {
                require(
                    roster.node(&key.node_id).is_some(),
                    "service key bound to unknown node",
                )?;
            }
            previous = Some(roster);
        }
        let mut purpose_keys = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for binding in self
            .audits
            .iter()
            .chain([&self.authority, &self.operations])
        {
            require(!binding.key.is_weak(), "weak service verification key")?;
            require(
                purpose_keys.insert(binding.key.to_bytes()),
                "service keys reused across purposes",
            )?;
            require(
                ids.insert(&binding.key_id),
                "service key identifiers reused across purposes",
            )?;
        }
        for roster in &self.rosters {
            for node in &roster.body.nodes {
                for key in std::iter::once(&node.transport_key)
                    .chain(node.participant_keys.values())
                    .chain(node.attestation_key.iter())
                    .chain(node.consensus_key.iter())
                {
                    require(
                        !purpose_keys.iter().any(|p| key.bytes.as_slice() == p),
                        "service key reused as network/participant/attestation key",
                    )?;
                }
            }
        }
        for key in self.admins.credentials.values() {
            require(
                !purpose_keys.iter().any(|p| key.bytes.as_slice() == p),
                "service key reused as roster admin key",
            )?;
        }
        let mut admins = BTreeSet::new();
        let mut admin_keys = BTreeSet::new();
        require(
            self.policy_admin_quorum > 0,
            "policy admin quorum must be positive",
        )?;
        for (id, key) in &self.policy_admin_keys {
            require(
                admins.insert(id) && admin_keys.insert(key.to_bytes()) && !key.is_weak(),
                "duplicate or weak policy admin credential",
            )?;
            require(
                !purpose_keys.contains(&key.to_bytes()),
                "service key reused as policy admin key",
            )?;
        }
        require(
            usize::from(self.policy_admin_quorum) <= admins.len(),
            "policy admin quorum exceeds enrolled credentials",
        )
    }

    pub(crate) fn roster(&self, epoch: u64) -> OicResult<&SignedRoster> {
        self.rosters
            .iter()
            .find(|r| r.body.roster_epoch == epoch)
            .ok_or_else(|| invalid("untrusted roster epoch"))
    }

    pub(crate) fn active_roster(&self, now: UnixSeconds) -> OicResult<&SignedRoster> {
        self.rosters
            .iter()
            .rev()
            .find(|r| r.body.activation.not_before <= now)
            .ok_or_else(|| invalid("no active witness roster"))
    }

    pub(crate) fn audit(&self, id: &KeyId) -> OicResult<&ServiceKey> {
        self.audits
            .iter()
            .find(|k| &k.key_id == id)
            .ok_or_else(|| invalid("unenrolled audit key"))
    }

    pub(crate) fn verify_authority(&self, checkpoint: &SignedCheckpoint) -> OicResult<()> {
        let b = &checkpoint.body;
        if b.institution_id != self.institution_id || b.environment_id != self.environment_id {
            return Err(OicError::scope("authority checkpoint scope mismatch"));
        }
        require(
            checkpoint.authority_key_id == self.authority.key_id,
            "authority checkpoint key identity mismatch",
        )?;
        oic_authorization_state::verify_checkpoint(checkpoint, &self.authority.key)
    }
}
