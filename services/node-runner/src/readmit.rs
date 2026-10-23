//! DEVELOPMENT ONLY readmission ceremony (RFC 0002 §9).
//!
//! A signer that stopped cannot rejoin on its own: `Signer::open` bumps its
//! durable instance generation on every open, and the roster pins each
//! signer's generation, so the restarted core is refused with
//! `StaleGeneration`. Readmission is an administrative act: this command
//! builds the next roster epoch, pins every signer's next generation from
//! its durable store, signs the update with two of the three provisioned
//! admin keys, and stages it in every node directory. The operator then
//! restarts the fleet onto it.
//!
//! Development honesty: the admin keys live in `admin-ceremony/` only
//! because `provision` created this topology on one machine. Production
//! admins are people with their own credentials, and
//! `authority_commit_reference` would name an authority log commit; here it
//! self-attests with the prior roster hash, which satisfies the transition
//! validation but binds nothing external.

use crate::{files, provision};
use ed25519_dalek::{Signer as _, SigningKey};
use oic_membership::{roster_hash, Activation, SignedRoster};
use oic_domain_types::*;
use std::path::Path;

pub fn readmit(base: &Path, now: UnixSeconds) -> OicResult<()> {
    let roster: SignedRoster = files::read_canonical(&base.join("node-0"), "roster.bin")?;
    let prior_hash = roster_hash(&roster.body)?;

    let ceremony = base.join("admin-ceremony");
    let mut admin_keys = Vec::new();
    for n in 1..=3u8 {
        let bytes = files::read_key32(&ceremony, &format!("dev-admin-{n}.key"))?;
        admin_keys.push((CredentialId::unchecked(format!("dev-admin-{n}")), SigningKey::from_bytes(&bytes)));
    }

    // Pin the generation each signer core will hold on its NEXT open: the
    // durable store's value plus the bump that open performs. Every signer
    // gets a fresh pin because the rolling restart reopens all of them.
    let mut body = roster.body.clone();
    for index in 0..provision::SIGNERS {
        let store = oic_signer::FileGenerationStore::new(base.join(format!("node-{index}")).join("generation"));
        let next = match oic_signer::GenerationStore::load(&store)? {
            Some(generation) => {
                Epoch(generation.0.checked_add(1).ok_or_else(|| OicError::internal("signer generation overflow"))?)
            }
            None => Epoch(1),
        };
        let node_id = files::node_id(index);
        let node = body
            .nodes
            .iter_mut()
            .find(|n| n.node_id == node_id)
            .ok_or_else(|| OicError::invalid_request(format!("{node_id} is not in the roster")))?;
        node.signer_instance_generation = next;
    }

    body.roster_epoch =
        body.roster_epoch.checked_add(1).ok_or_else(|| OicError::internal("roster epoch overflow"))?;
    body.previous_roster_hash = prior_hash;
    body.genesis_hash = if roster.body.roster_epoch == 0 { prior_hash } else { roster.body.genesis_hash };
    body.activation = Activation { not_before: now, authority_commit_reference: Some(prior_hash) };

    let hash = roster_hash(&body)?;
    let signatures = admin_keys[..2]
        .iter()
        .map(|(id, key)| CredentialSignature {
            credential_id: id.clone(),
            signature: SignatureBytes {
                scheme: SchemeId::Ed25519Pure,
                bytes: key.sign(hash.as_ref()).to_bytes().to_vec().into(),
            },
        })
        .collect();
    let updated = SignedRoster { body, signatures };

    for index in 0..provision::NODES {
        let dir = base.join(format!("node-{index}"));
        files::replace_canonical(&dir.join("roster-previous.bin"), &roster)?;
        files::replace_canonical(&dir.join("roster.bin"), &updated)?;
    }
    println!(
        "DEVELOPMENT ONLY: roster epoch {} staged in every node directory (hash {}); restart each node onto it",
        updated.body.roster_epoch,
        hash.to_hex()
    );
    Ok(())
}
