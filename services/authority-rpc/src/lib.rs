//! D1 RPC for the existing trusted, single-writer authority. This adds no
//! consensus, policy evaluation, retry loop, authentication, or audit storage.
//! Transport authenticates NodeIds; callers validate/activate rosters before
//! constructing either endpoint and replace them when that roster changes.

use oic_authorization_state::{Authority, AuthorityStore, ReleaseRequest, ReserveRequest};
use oic_domain_types::*;
use oic_membership::{CommitteeKind, Role, SignedRoster};
use oic_peer_wire::{AuthorityReply, AuthorityRequest, AuthorityResult, HEADER_LEN, MAX_BODY_LEN};
use std::sync::atomic::{AtomicU64, Ordering};

// Shared across client instances and transport types; never reset or wrap.
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// The coordinator's authority seam. The in-process implementation preserves
/// the authority's own policy, freeze, freshness, fencing and release semantics.
pub trait AuthorityEndpoint: Send + Sync {
    fn reserve(&self, request: ReserveRequest) -> OicResult<(Reservation, AuthorityReceipt)>;
    fn release(&self, request: ReleaseRequest) -> OicResult<(AuthorityReceipt, IssuanceRecord)>;
    fn abort_before_issuance(&self, reservation_id: &ReservationId) -> OicResult<u64>;
}

impl<S: AuthorityStore> AuthorityEndpoint for Authority<S> {
    fn reserve(&self, request: ReserveRequest) -> OicResult<(Reservation, AuthorityReceipt)> {
        Authority::reserve(self, request)
    }

    fn release(&self, request: ReleaseRequest) -> OicResult<(AuthorityReceipt, IssuanceRecord)> {
        Authority::release(self, request)
    }

    fn abort_before_issuance(&self, reservation_id: &ReservationId) -> OicResult<u64> {
        Authority::abort_before_issuance(self, reservation_id)
    }
}

fn denied() -> OicError {
    OicError::new(ErrorCode::PeerNotAdmitted, "D1 authority RPC peer or channel not admitted")
}

fn authority_node(roster: &SignedRoster, node_id: &NodeId) -> bool {
    roster.node(node_id).is_some_and(|node| node.roles.contains(&Role::Authority))
        && roster.body.committees.iter().any(|committee| matches!(committee.kind, CommitteeKind::AuthorityD1) && committee.members.contains(node_id))
}

fn gateway_allowed(roster: &SignedRoster, gateway: &NodeId, authority: &NodeId) -> bool {
    roster.node(gateway).is_some_and(|node| node.roles.contains(&Role::Gateway))
        && roster.allows(12, gateway, authority)
        && roster.allows(12, authority, gateway)
}

fn body_limit(roster: &SignedRoster) -> OicResult<usize> {
    let channel = roster.body.channel_acl.iter().find(|acl| acl.channel == 12).ok_or_else(denied)?;
    // Roster/transport cap covers the complete frame, not just its CBOR body.
    let limit = (channel.max_message_size as usize).saturating_sub(HEADER_LEN).min(MAX_BODY_LEN);
    if limit == 0 {
        return Err(OicError::invalid_request("authority RPC frame limit is too small"));
    }
    Ok(limit)
}

/// Handler for a caller-validated active roster and the actual local authority.
/// The supplied sender must come from transport authentication, never a field
/// decoded from the request. No administration/freeze endpoint is exposed.
/// Receipt-key separation covers roster node keys and the authority's configured
/// administrative/responder keys. Roster-only admin trust anchors and other
/// out-of-band key purposes still require caller-side provisioning checks.
pub struct AuthorityRpcServer<'a, S: AuthorityStore> {
    authority: &'a Authority<S>,
    roster: &'a SignedRoster,
    authority_node_id: NodeId,
    max_body_len: usize,
}

impl<'a, S: AuthorityStore> AuthorityRpcServer<'a, S> {
    pub fn new(authority: &'a Authority<S>, roster: &'a SignedRoster, authority_node_id: &NodeId) -> OicResult<Self> {
        if !authority_node(roster, authority_node_id) {
            return Err(denied());
        }
        if authority.config().institution_id != roster.body.institution_id || authority.config().environment_id != roster.body.environment_id {
            return Err(OicError::scope("authority configuration differs from roster scope"));
        }
        let receipt_key = authority.verifying_key();
        let reuses_receipt_key = |key: &PublicKey| key.bytes.as_slice() == receipt_key.as_bytes();
        if roster.body.nodes.iter().any(|node| {
            reuses_receipt_key(&node.transport_key)
                || node.participant_keys.values().any(reuses_receipt_key)
                || node.attestation_key.as_ref().is_some_and(reuses_receipt_key)
        }) || authority.config().admin_keys.iter().chain(&authority.config().freeze_responders).any(|(_, key)| key == &receipt_key)
        {
            return Err(OicError::invalid_request("authority receipt key must be distinct from node and administrative keys"));
        }
        Ok(Self { authority, roster, authority_node_id: authority_node_id.clone(), max_body_len: body_limit(roster)? })
    }

    /// Admission and strict epoch/kind/size/CBOR checks precede any mutation.
    /// A lost or unencodable reply does not roll a committed issuance back.
    pub fn handle(&self, authenticated_sender: &NodeId, frame: &[u8]) -> OicResult<Vec<u8>> {
        if !gateway_allowed(self.roster, authenticated_sender, &self.authority_node_id) {
            return Err(denied());
        }
        let request = AuthorityRequest::decode(frame, self.roster.body.roster_epoch, self.max_body_len)
            .map_err(|_| OicError::invalid_request("invalid authority RPC frame"))?;
        let request_id = request.request_id();
        let result = match request {
            AuthorityRequest::Reserve { request, .. } => {
                self.authority.reserve(request).map(|(reservation, receipt)| AuthorityResult::Reserved { reservation, receipt })
            }
            AuthorityRequest::Release { request, .. } => {
                self.authority.release(request).map(|(receipt, issuance)| AuthorityResult::Released { receipt, issuance })
            }
            AuthorityRequest::AbortBeforeIssuance { reservation_id, .. } => {
                self.authority.abort_before_issuance(&reservation_id).map(|commit_sequence| AuthorityResult::Aborted { commit_sequence })
            }
        };
        // Preserve stable codes but never transmit authority error details that
        // might include claims, identifiers, or policy contents (Class C).
        let result = result.map_err(|error| OicError::new(error.code, "authority rejected request"));
        AuthorityReply { request_id, result }
            .encode(self.roster.body.roster_epoch, self.max_body_len)
            .map_err(|_| OicError::new(ErrorCode::AuthorityUnavailable, "authority RPC reply unavailable"))
    }
}

/// Synchronous named-peer request correlation, implemented by signer-net.
/// Send exactly once over authenticated, confidential channel 12 to `authority`
/// and return only that peer's correlated reply. Enforce a deadline, current
/// roster admission and convergence; never retry mutations automatically.
/// Client request IDs are process-global and checked against exhaustion, so
/// rebuilding a client on a shared transport cannot reuse an earlier ID.
/// A process restart must close the old authenticated connection/correlation
/// scope before IDs start over; Gateway lifetime restart provides that boundary.
pub trait AuthorityRpcTransport: Send + Sync {
    fn request(&self, authority: &NodeId, request_id: u64, frame: Vec<u8>) -> OicResult<Vec<u8>>;
}

/// Opt-in remote implementation. A network failure after a Release was handed
/// to transport means `IssuanceUncertain`, not safe-to-abort. Receipt signature
/// and envelope binding checks remain mandatory at each signer-core.
pub struct AuthorityRpcClient<T: AuthorityRpcTransport> {
    transport: T,
    authority_node_id: NodeId,
    roster_epoch: u64,
    max_body_len: usize,
}

impl<T: AuthorityRpcTransport> AuthorityRpcClient<T> {
    pub fn new(transport: T, roster: &SignedRoster, gateway_node_id: &NodeId, authority_node_id: &NodeId) -> OicResult<Self> {
        if !authority_node(roster, authority_node_id) || !gateway_allowed(roster, gateway_node_id, authority_node_id) {
            return Err(denied());
        }
        Ok(Self { transport, authority_node_id: authority_node_id.clone(), roster_epoch: roster.body.roster_epoch, max_body_len: body_limit(roster)? })
    }

    // `try_update` is newer than this crate's MSRV (Rust 1.85).
    #[allow(deprecated)]
    fn next_id() -> OicResult<u64> {
        NEXT_REQUEST_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| OicError::new(ErrorCode::AuthorityUnavailable, "authority RPC request IDs exhausted"))
    }

    fn exchange(&self, request: AuthorityRequest) -> OicResult<AuthorityResult> {
        let is_release = matches!(request, AuthorityRequest::Release { .. });
        let lost_reply = || {
            OicError::new(
                if is_release { ErrorCode::IssuanceUncertain } else { ErrorCode::AuthorityUnavailable },
                "authority RPC outcome unavailable; no automatic retry",
            )
        };
        let frame = request
            .encode(self.roster_epoch, self.max_body_len)
            .map_err(|_| OicError::invalid_request("authority RPC request cannot be encoded within limits"))?;
        let reply = self.transport.request(&self.authority_node_id, request.request_id(), frame).map_err(|_| lost_reply())?;
        let reply = AuthorityReply::decode(&reply, self.roster_epoch, self.max_body_len).map_err(|_| lost_reply())?;
        if reply.request_id != request.request_id() {
            return Err(lost_reply());
        }
        match reply.result {
            Ok(result) => {
                let matches = matches!(
                    (&request, &result),
                    (AuthorityRequest::Reserve { .. }, AuthorityResult::Reserved { .. })
                        | (AuthorityRequest::Release { .. }, AuthorityResult::Released { .. })
                        | (AuthorityRequest::AbortBeforeIssuance { .. }, AuthorityResult::Aborted { .. })
                );
                if matches {
                    Ok(result)
                } else {
                    Err(lost_reply())
                }
            }
            Err(error) => {
                if is_release && matches!(error.code, ErrorCode::AuthorityUnavailable | ErrorCode::OrderingUnavailable | ErrorCode::Internal) {
                    Err(lost_reply())
                } else {
                    Err(OicError::new(error.code, "authority rejected request"))
                }
            }
        }
    }
}

impl<T: AuthorityRpcTransport> AuthorityEndpoint for AuthorityRpcClient<T> {
    fn reserve(&self, request: ReserveRequest) -> OicResult<(Reservation, AuthorityReceipt)> {
        match self.exchange(AuthorityRequest::Reserve { request_id: Self::next_id()?, request })? {
            AuthorityResult::Reserved { reservation, receipt } => Ok((reservation, receipt)),
            _ => unreachable!("exchange validates the result variant"),
        }
    }

    fn release(&self, request: ReleaseRequest) -> OicResult<(AuthorityReceipt, IssuanceRecord)> {
        match self.exchange(AuthorityRequest::Release { request_id: Self::next_id()?, request })? {
            AuthorityResult::Released { receipt, issuance } => Ok((receipt, issuance)),
            _ => unreachable!("exchange validates the result variant"),
        }
    }

    fn abort_before_issuance(&self, reservation_id: &ReservationId) -> OicResult<u64> {
        match self.exchange(AuthorityRequest::AbortBeforeIssuance { request_id: Self::next_id()?, reservation_id: reservation_id.clone() })? {
            AuthorityResult::Aborted { commit_sequence } => Ok(commit_sequence),
            _ => unreachable!("exchange validates the result variant"),
        }
    }
}
