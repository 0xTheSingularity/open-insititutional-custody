//! RFC 0003 membership. This crate validates public configuration; it performs
//! no I/O, consensus, share revocation, or signer-state tombstoning.
//!
//! Administrative credentials sign [`roster_hash`], using pure Ed25519 over
//! the 32-byte domain-separated canonical-CBOR commitment. Trust anchors and
//! the authority's committed hash come from the caller, never from the roster.
//! Call [`validate_roster`] before using any lookup or ACL method. A previous
//! roster must be the caller's already-validated active roster, not peer input.

use ed25519_dalek::{Signature, VerifyingKey};
use oic_canonical_encoding::{canonical_bytes, domain_hash};
use oic_crypto_provider::{check_topology, BackendDescriptor};
use oic_domain_types::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

mod attestation;
pub use attestation::*;

pub const COMMONWARE_RELEASE: &str = "2026.9.0";
pub const WIRE_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Gateway,
    Verifier,
    Signer,
    Authority,
    Witness,
    Recovery,
    Extension,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerClass {
    Primary,
    Secondary,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub node_id: NodeId,
    pub domain_id: TrustDomainId,
    pub roles: Vec<Role>,
    pub transport_key: PublicKey,
    /// Dedicated Simplex vote key, required exactly for D2 authority members.
    /// Omitted D1 fields retain their original canonical encoding and hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consensus_key: Option<PublicKey>,
    /// Separate verifier credential; required exactly for signer/verifier roles.
    pub attestation_key: Option<PublicKey>,
    /// Canonical socket-address text, including IPv6 scope. Nonzero IPv6
    /// flowinfo is unsupported because SocketAddr's text format omits it.
    #[serde(with = "socket_address")]
    pub address: SocketAddr,
    pub peer_class: PeerClass,
    /// Public signer-core authentication keys, not chain keys or shares.
    pub participant_keys: BTreeMap<ParticipantId, PublicKey>,
    pub approved_build_hashes: Vec<Hash32>,
    pub signer_instance_generation: Epoch,
}

impl Node {
    fn has(&self, role: Role) -> bool {
        self.roles.contains(&role) || (role == Role::Verifier && self.roles.contains(&Role::Signer))
    }
}

mod socket_address {
    use serde::{de::Error as _, ser::Error as _, Deserialize, Deserializer, Serializer};
    use std::net::SocketAddr;

    pub fn serialize<S: Serializer>(address: &SocketAddr, serializer: S) -> Result<S::Ok, S::Error> {
        if matches!(address, SocketAddr::V6(address) if address.flowinfo() != 0) {
            return Err(S::Error::custom("IPv6 flowinfo is unsupported"));
        }
        serializer.serialize_str(&address.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SocketAddr, D::Error> {
        let text = String::deserialize(deserializer)?;
        let address: SocketAddr = text.parse().map_err(D::Error::custom)?;
        if address.to_string() != text {
            return Err(D::Error::custom("socket address must use canonical text"));
        }
        Ok(address)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustDomain {
    pub domain_id: TrustDomainId,
    pub administrators: Vec<CredentialId>,
    /// Root IAM, hardware/firmware, image signing, backups, KMS, operator and
    /// recovery control. These declarations still require human review.
    pub failure_domain_notes: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommitteeKind {
    Key {
        key_id: KeyId,
        key_epoch: Epoch,
        participants: Vec<ParticipantId>,
        backend: BackendDescriptor,
    },
    Verification,
    /// Exactly one active authority. A standby is not an active member.
    AuthorityD1,
    /// Placement/count checks only; this does not implement consensus.
    AuthorityD2 {
        faults: u16,
    },
    Witness,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Committee {
    pub committee_id: CommitteeId,
    pub kind: CommitteeKind,
    pub members: Vec<NodeId>,
    pub threshold: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelSpec {
    pub channel: u64,
    pub sender_roles: Vec<Role>,
    pub receiver_roles: Vec<Role>,
    pub max_message_size: u32,
    /// Positive messages-per-second allowance; transport enforces the quota.
    pub quota: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    pub not_before: UnixSeconds,
    /// Opaque reference to the ordered activation command, not a certificate.
    /// Genesis is bootstrapped out of band and may omit this reference.
    pub authority_commit_reference: Option<Hash32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterBody {
    pub institution_id: InstitutionId,
    pub environment_id: EnvironmentId,
    pub roster_epoch: u64,
    pub previous_roster_hash: Hash32,
    /// Zero in epoch zero to avoid a self-referential hash; subsequent bodies
    /// contain the hash of the epoch-zero body.
    pub genesis_hash: Hash32,
    pub commonware_release: String,
    pub wire_version: u16,
    pub trust_domains: Vec<TrustDomain>,
    pub nodes: Vec<Node>,
    pub committees: Vec<Committee>,
    pub channel_acl: Vec<ChannelSpec>,
    /// Must be positive. Default deployment recommendation is one.
    pub tolerated_domain_compromises: u16,
    pub activation: Activation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRoster {
    pub body: RosterBody,
    pub signatures: Vec<CredentialSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminTrust {
    pub threshold: u16,
    pub credentials: BTreeMap<CredentialId, PublicKey>,
}

/// `SHA256(OIC/NETWORK_ROSTER/v1 || CanonicalEncode(body))`.
pub fn roster_hash(body: &RosterBody) -> OicResult<Hash32> {
    domain_hash(domains::NETWORK_ROSTER, body)
}

impl SignedRoster {
    /// `OIC/P2P/v1 || CanonicalEncode((institution, environment, anchor))`.
    /// The tuple prevents ambiguous concatenation of variable-length IDs.
    pub fn namespace(&self) -> OicResult<Vec<u8>> {
        let b = &self.body;
        let anchor = if b.roster_epoch == 0 { roster_hash(b)? } else { b.genesis_hash };
        let mut namespace = domains::P2P.as_bytes().to_vec();
        namespace.extend(canonical_bytes(&(&b.institution_id, &b.environment_id, anchor))?);
        Ok(namespace)
    }

    pub fn node(&self, node_id: &NodeId) -> Option<&Node> {
        self.body.nodes.iter().find(|node| &node.node_id == node_id)
    }

    pub fn participant(&self, participant_id: &ParticipantId) -> Option<&Node> {
        self.body.nodes.iter().find(|node| node.participant_keys.contains_key(participant_id))
    }

    /// Exact equality rejects both stale and uncommitted future instances.
    pub fn accepts_generation(&self, participant_id: &ParticipantId, generation: Epoch) -> bool {
        self.participant(participant_id).is_some_and(|node| node.signer_instance_generation == generation)
    }

    fn in_committee(&self, node: &Node, predicate: impl Fn(&CommitteeKind) -> bool) -> bool {
        self.body.committees.iter().any(|c| predicate(&c.kind) && c.members.contains(&node.node_id))
    }

    fn verifier(&self, node: &Node) -> bool {
        node.has(Role::Signer) || (node.has(Role::Verifier) && self.in_committee(node, |k| matches!(k, CommitteeKind::Verification)))
    }

    /// Roster-level admission only. The wire layer must additionally enforce
    /// epoch/hash convergence, message size, explicit recipients, session
    /// participant sets, participant signatures, and signer generations.
    pub fn allows(&self, channel: u64, from: &NodeId, to: &NodeId) -> bool {
        let (Some(from), Some(to)) = (self.node(from), self.node(to)) else { return false };
        let Some(acl) = self.body.channel_acl.iter().find(|acl| acl.channel == channel) else { return false };
        if !acl.sender_roles.iter().any(|r| from.has(*r)) || !acl.receiver_roles.iter().any(|r| to.has(*r)) {
            return false;
        }
        let primary = |node: &Node| node.peer_class == PeerClass::Primary;
        let authority =
            |node: &Node| node.has(Role::Authority) && self.in_committee(node, |k| matches!(k, CommitteeKind::AuthorityD1 | CommitteeKind::AuthorityD2 { .. }));
        let d2 = |node: &Node| self.in_committee(node, |k| matches!(k, CommitteeKind::AuthorityD2 { .. }));
        match channel {
            0 => primary(from) && primary(to) && !from.has(Role::Extension) && !to.has(Role::Extension),
            1 | 3 => primary(from) && primary(to) && d2(from) && d2(to),
            2 => primary(from) && primary(to) && d2(from) && (d2(to) || to.has(Role::Signer)),
            4 => primary(from) && d2(from) && (d2(to) || to.has(Role::Signer) || to.has(Role::Witness)),
            5 => {
                (primary(from) && d2(from) && (d2(to) || to.has(Role::Signer) || to.has(Role::Witness)))
                    || (primary(from) && from.has(Role::Signer) && primary(to) && d2(to))
            }
            10 => primary(from) && primary(to) && ((from.has(Role::Gateway) && self.verifier(to)) || (self.verifier(from) && to.has(Role::Gateway))),
            11 => primary(from) && primary(to) && self.verifier(from) && (to.has(Role::Gateway) || authority(to)),
            12 => {
                let d1 = |n: &Node| self.in_committee(n, |k| matches!(k, CommitteeKind::AuthorityD1));
                primary(from) && primary(to) && ((from.has(Role::Gateway) && d1(to)) || (d1(from) && to.has(Role::Gateway)))
            }
            20..=21 => {
                let eligible = |n: &Node| n.has(Role::Signer) || (channel == 21 && n.has(Role::Recovery));
                primary(from)
                    && primary(to)
                    && eligible(from)
                    && eligible(to)
                    && self
                        .body
                        .committees
                        .iter()
                        .any(|c| matches!(c.kind, CommitteeKind::Key { .. }) && c.members.contains(&from.node_id) && c.members.contains(&to.node_id))
            }
            30 => to.has(Role::Witness),
            1024.. => true,
            _ => false,
        }
    }
}

fn require(ok: bool, detail: &str) -> OicResult<()> {
    if ok {
        Ok(())
    } else {
        Err(OicError::invalid_request(detail))
    }
}

fn unique<T: Ord>(values: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|value| seen.insert(value))
}

fn verifying_key(key: &PublicKey) -> OicResult<VerifyingKey> {
    require(key.scheme == SchemeId::Ed25519Pure, "membership keys must use Ed25519Pure")?;
    let bytes: &[u8; 32] = key.bytes.as_slice().try_into().map_err(|_| OicError::invalid_request("membership key must be 32 bytes"))?;
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| OicError::invalid_request("invalid Ed25519 key"))?;
    require(!key.is_weak(), "weak Ed25519 key")?;
    Ok(key)
}

/// Validate signatures, binding, activation, linked epochs, fencing, placement,
/// and structural admission invariants. This does not authenticate a supplied
/// commit reference: the caller obtains `committed_roster_hash` from its trusted
/// authority (or the independently compared genesis ceremony hash).
/// Fencing compares adjacent rosters. The caller must retain durable generation
/// floors for removed identities before re-admitting them after an absence.
pub fn validate_roster(
    signed: &SignedRoster,
    admins: &AdminTrust,
    institution: &InstitutionId,
    environment: &EnvironmentId,
    previous: Option<&SignedRoster>,
    now: UnixSeconds,
    committed_roster_hash: Hash32,
) -> OicResult<()> {
    let b = &signed.body;
    if &b.institution_id != institution || &b.environment_id != environment {
        return Err(OicError::scope("roster institution or environment mismatch"));
    }
    require(b.commonware_release == COMMONWARE_RELEASE && b.wire_version == WIRE_VERSION, "unsupported roster transport version")?;
    require(now >= b.activation.not_before, "roster activation is in the future")?;
    let hash = roster_hash(b)?;
    if hash != committed_roster_hash {
        return Err(OicError::new(ErrorCode::AuthorityUnavailable, "roster hash is not authority committed"));
    }
    match previous {
        None => require(
            b.roster_epoch == 0 && b.previous_roster_hash == Hash32::ZERO && b.genesis_hash == Hash32::ZERO,
            "bootstrap requires epoch zero with zero previous/genesis hashes",
        )?,
        Some(old) => {
            let p = &old.body;
            require(p.institution_id == b.institution_id && p.environment_id == b.environment_id, "previous roster scope mismatch")?;
            require(p.roster_epoch.checked_add(1) == Some(b.roster_epoch), "roster epoch must advance exactly once")?;
            require(b.previous_roster_hash == roster_hash(p)?, "previous roster hash mismatch")?;
            let anchor = if p.roster_epoch == 0 { roster_hash(p)? } else { p.genesis_hash };
            require(b.genesis_hash != Hash32::ZERO && b.genesis_hash == anchor, "genesis anchor mismatch")?;
            require(b.activation.not_before >= p.activation.not_before, "activation time regressed")?;
            require(b.activation.authority_commit_reference.is_some_and(|h| h != Hash32::ZERO), "roster update lacks activation reference")?;
            for node in &b.nodes {
                if let Some(prior) = old.node(&node.node_id) {
                    require(node.signer_instance_generation >= prior.signer_instance_generation, "node generation regressed")?;
                    let changed = !node.participant_keys.is_empty()
                        && (node.domain_id != prior.domain_id || node.transport_key != prior.transport_key || node.participant_keys != prior.participant_keys);
                    require(!changed || node.signer_instance_generation > prior.signer_instance_generation, "replacement signer requires a newer generation")?;
                }
                for (id, key) in &node.participant_keys {
                    if let Some(prior) = old.participant(id) {
                        let changed = node.node_id != prior.node_id
                            || node.domain_id != prior.domain_id
                            || node.transport_key != prior.transport_key
                            || prior.participant_keys.get(id) != Some(key);
                        require(
                            node.signer_instance_generation >= prior.signer_instance_generation
                                && (!changed || node.signer_instance_generation > prior.signer_instance_generation),
                            "replacement participant requires a newer generation",
                        )?;
                    }
                }
            }
        }
    }
    require(admins.threshold > 0 && usize::from(admins.threshold) <= admins.credentials.len(), "invalid administrative threshold")?;
    let mut keys = BTreeSet::new();
    for key in admins.credentials.values() {
        verifying_key(key)?;
        require(keys.insert(key.clone()), "administrative credentials reuse a key")?;
    }
    let mut credentials = BTreeSet::new();
    for signature in &signed.signatures {
        require(credentials.insert(&signature.credential_id), "duplicate administrative signature")?;
        let key = admins.credentials.get(&signature.credential_id).ok_or_else(|| OicError::invalid_signature("untrusted administrative credential"))?;
        if signature.signature.scheme != SchemeId::Ed25519Pure {
            return Err(OicError::invalid_signature("administrative signature is not Ed25519Pure"));
        }
        let signature =
            Signature::from_slice(signature.signature.bytes.as_slice()).map_err(|_| OicError::invalid_signature("malformed administrative signature"))?;
        verifying_key(key)?.verify_strict(hash.as_ref(), &signature).map_err(|_| OicError::invalid_signature("roster signature does not verify"))?;
    }
    if credentials.len() < usize::from(admins.threshold) {
        return Err(OicError::new(ErrorCode::ApprovalRequired, "administrative roster quorum not met"));
    }
    require(b.tolerated_domain_compromises > 0, "domain compromise tolerance must be positive")?;
    require(!b.trust_domains.is_empty() && unique(b.trust_domains.iter().map(|d| &d.domain_id)), "empty or duplicate trust domains")?;
    for domain in &b.trust_domains {
        require(
            !domain.administrators.is_empty() && unique(&domain.administrators) && !domain.failure_domain_notes.trim().is_empty(),
            "trust domain lacks distinct administrators or failure-domain documentation",
        )?;
    }
    require(!b.nodes.is_empty() && unique(b.nodes.iter().map(|n| &n.node_id)), "empty or duplicate nodes")?;
    let mut participants = BTreeSet::new();
    for node in &b.nodes {
        require(b.trust_domains.iter().any(|d| d.domain_id == node.domain_id), "node has unknown trust domain")?;
        require(!node.roles.is_empty() && unique(&node.roles), "empty or duplicate node roles")?;
        require(
            node.address.port() != 0 && !node.address.ip().is_unspecified() && !node.address.ip().is_multicast(),
            "node needs a unicast address and nonzero port",
        )?;
        verifying_key(&node.transport_key)?;
        require(keys.insert(node.transport_key.clone()), "transport key reused across identities or administrators")?;
        let replica = b.committees.iter().any(|committee| matches!(committee.kind, CommitteeKind::AuthorityD2 { .. }) && committee.members.contains(&node.node_id));
        require(replica == node.consensus_key.is_some(), "D2 replicas require dedicated consensus keys; other nodes must not hold them")?;
        if let Some(key) = &node.consensus_key {
            verifying_key(key)?;
            require(keys.insert(key.clone()), "consensus key reused across identities or key purposes")?;
        }
        let participant = node.has(Role::Signer) || node.has(Role::Recovery);
        require(participant != node.participant_keys.is_empty(), "signer/recovery roles must own participant keys, and other roles must not")?;
        for (id, key) in &node.participant_keys {
            verifying_key(key)?;
            require(participants.insert(id), "participant identity appears on multiple nodes")?;
            require(keys.insert(key.clone()), "participant key reused across identities or administrators")?;
        }
        if node.has(Role::Signer) || node.has(Role::Verifier) {
            require(!node.approved_build_hashes.is_empty(), "signer/verifier needs an approved build hash")?;
        }
        require(node.has(Role::Verifier) == node.attestation_key.is_some(), "signer/verifier must have an attestation key, and other roles must not")?;
        if let Some(key) = &node.attestation_key {
            verifying_key(key)?;
            require(keys.insert(key.clone()), "attestation key reused across identities or key purposes")?;
        }
        require(unique(&node.approved_build_hashes) && !node.approved_build_hashes.contains(&Hash32::ZERO), "duplicate or zero approved build hash")?;
        if node.has(Role::Witness) || node.has(Role::Extension) || node.has(Role::Recovery) {
            require(node.roles.len() == 1, "witness, extension, and recovery roles must be isolated")?;
        }
        require(!(node.has(Role::Signer) && node.has(Role::Authority)), "authority cannot hold shares")?;
        if node.has(Role::Witness) {
            require(node.peer_class == PeerClass::Secondary, "witness must be secondary")?;
        } else if !node.has(Role::Extension) {
            require(node.peer_class == PeerClass::Primary, "active custody role must be primary")?;
        }
        if node.has(Role::Recovery) {
            require(
                b.channel_acl.iter().any(|a| a.channel == 21 && a.sender_roles.contains(&Role::Recovery) && a.receiver_roles.contains(&Role::Recovery)),
                "recovery may be online only in a ceremony roster",
            )?;
        }
    }
    validate_committees(signed)?;
    require(unique(b.channel_acl.iter().map(|a| a.channel)), "duplicate channel ACL")?;
    for acl in &b.channel_acl {
        require(matches!(acl.channel, 0..=5 | 10..=12 | 20..=21 | 30 | 1024..), "unknown reserved channel")?;
        require(
            !acl.sender_roles.is_empty() && !acl.receiver_roles.is_empty() && unique(&acl.sender_roles) && unique(&acl.receiver_roles),
            "empty or duplicate channel roles",
        )?;
        require(acl.max_message_size > 0 && acl.max_message_size as usize <= MAX_BYTES_LEN && acl.quota > 0, "invalid channel size or quota")?;
        if acl.channel < 1024 && acl.channel != 30 {
            require(
                !acl.sender_roles.contains(&Role::Extension) && !acl.receiver_roles.contains(&Role::Extension),
                "extension is limited to extension channels and read-only audit",
            )?;
        }
        if acl.channel == 30 {
            require(acl.receiver_roles.iter().all(|r| *r == Role::Witness), "audit recipients must be witnesses")?;
        }
        if matches!(acl.channel, 20..=21) {
            let eligible = |r: &Role| *r == Role::Signer || (acl.channel == 21 && *r == Role::Recovery);
            require(acl.sender_roles.iter().all(eligible) && acl.receiver_roles.iter().all(eligible), "MPC ACL must name only signer/ceremony roles")?;
        }
    }
    Ok(())
}

/// The largest `tolerated` domain counts dominate every possible compromise
/// set, so checking their sum is equivalent to enumerating all such sets.
fn compromised(counts: BTreeMap<TrustDomainId, usize>, tolerated: u16) -> usize {
    let mut counts: Vec<_> = counts.into_values().collect();
    counts.sort_unstable_by(|a, b| b.cmp(a));
    counts.into_iter().take(usize::from(tolerated)).sum()
}

fn validate_committees(signed: &SignedRoster) -> OicResult<()> {
    let b = &signed.body;
    require(unique(b.committees.iter().map(|c| &c.committee_id)), "duplicate committee identity")?;
    let mut key_epochs = BTreeSet::new();
    let mut authorities = Vec::new();
    for committee in &b.committees {
        require(!committee.members.is_empty() && unique(&committee.members) && committee.threshold > 0, "invalid committee members or threshold")?;
        let members = committee
            .members
            .iter()
            .map(|id| signed.node(id).ok_or_else(|| OicError::invalid_request("unknown committee member")))
            .collect::<OicResult<Vec<_>>>()?;
        let mut counts = BTreeMap::new();
        for member in &members {
            *counts.entry(member.domain_id.clone()).or_insert(0) += 1;
        }
        match &committee.kind {
            CommitteeKind::Key { key_id, key_epoch, participants, backend } => {
                require(key_epochs.insert((key_id, key_epoch)), "duplicate key committee for key epoch")?;
                require(!participants.is_empty() && unique(participants), "empty or duplicate key participants")?;
                check_topology(backend, participants.len(), committee.threshold)?;
                let mut owners = BTreeSet::new();
                counts.clear();
                for id in participants {
                    let node = signed.participant(id).ok_or_else(|| OicError::invalid_request("unknown key participant"))?;
                    require(node.has(Role::Signer) || node.has(Role::Recovery), "key participant lacks signer/ceremony role")?;
                    owners.insert(&node.node_id);
                    *counts.entry(node.domain_id.clone()).or_insert(0) += 1;
                }
                require(owners == committee.members.iter().collect(), "key committee members differ from participant owners")?;
                require(compromised(counts, b.tolerated_domain_compromises) < usize::from(committee.threshold), "tolerated domains can reconstruct a key")?;
            }
            CommitteeKind::AuthorityD1 => {
                require(members.len() == 1 && committee.threshold == 1 && members[0].has(Role::Authority), "D1 requires one active authority")?;
                require(
                    !b.nodes.iter().any(|n| (n.has(Role::Signer) || n.has(Role::Recovery)) && n.domain_id == members[0].domain_id),
                    "D1 authority must have a separate trust domain from shares",
                )?;
                authorities.push(committee);
            }
            CommitteeKind::AuthorityD2 { faults } => {
                let f = usize::from(*faults);
                require(
                    f > 0 && members.len() == 3 * f + 1 && usize::from(committee.threshold) == 2 * f + 1 && members.iter().all(|n| n.has(Role::Authority)),
                    "D2 requires n=3f+1 and threshold=2f+1 authority replicas",
                )?;
                require(compromised(counts, b.tolerated_domain_compromises) <= f, "tolerated domains exceed D2 fault bound")?;
                authorities.push(committee);
            }
            CommitteeKind::Verification => {
                require(usize::from(committee.threshold) <= members.len() && members.iter().all(|n| n.has(Role::Verifier)), "invalid verification committee")?;
            }
            CommitteeKind::Witness => {
                require(usize::from(committee.threshold) <= members.len() && members.iter().all(|n| n.has(Role::Witness)), "invalid witness committee")?;
            }
        }
    }
    require(authorities.len() == 1, "roster needs exactly one authority committee/profile")?;
    for node in b.nodes.iter().filter(|n| n.has(Role::Authority)) {
        require(authorities[0].members.contains(&node.node_id), "authority role outside active authority committee")?;
    }
    Ok(())
}
