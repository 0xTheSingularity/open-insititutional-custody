//! In-memory audit log (tests, embedding, witnesses replaying a stream).

use crate::chain::{seal_event, AuditLog, AuditLogConfig, SealInput};
use crate::checkpoint::{sign_audit_checkpoint, AuditCheckpoint, AuditCheckpointBody};
use ed25519_dalek::VerifyingKey;
use oic_domain_types::*;
use parking_lot::Mutex;
use std::collections::BTreeMap;

struct Inner {
    events: Vec<AuditEvent>,
    head: Option<(u64, Hash32)>,
}

/// Audit log held in memory behind one lock. Not durable.
pub struct MemoryAuditLog {
    config: AuditLogConfig,
    inner: Mutex<Inner>,
}

impl MemoryAuditLog {
    pub fn new(config: AuditLogConfig) -> Self {
        MemoryAuditLog { config, inner: Mutex::new(Inner { events: Vec::new(), head: None }) }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.config.verifying_key()
    }

    /// Every event in sequence order.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.inner.lock().events.clone()
    }
}

impl AuditLog for MemoryAuditLog {
    fn append(&self, actor: &str, action: &str, object_commitments: BTreeMap<String, Hash32>, policy_epoch: Epoch, detail: &str) -> OicResult<AuditEvent> {
        let mut inner = self.inner.lock();
        let (event, h) = seal_event(&self.config, SealInput { head: inner.head, actor, action, object_commitments, policy_epoch, detail })?;
        inner.head = Some((event.body.sequence, h));
        inner.events.push(event.clone());
        Ok(event)
    }

    fn head(&self) -> OicResult<Option<(u64, Hash32)>> {
        Ok(self.inner.lock().head)
    }

    fn events_since(&self, sequence: u64, limit: usize) -> OicResult<Vec<AuditEvent>> {
        let inner = self.inner.lock();
        // Sequence n lives at index n-1, so events after `sequence` start at index `sequence`.
        let start = usize::try_from(sequence).unwrap_or(usize::MAX).min(inner.events.len());
        Ok(inner.events[start..].iter().take(limit).cloned().collect())
    }

    fn checkpoint(&self) -> OicResult<AuditCheckpoint> {
        let head = self.inner.lock().head.unwrap_or((0, Hash32::ZERO));
        sign_audit_checkpoint(
            &self.config.signing_key,
            AuditCheckpointBody { service_key_id: self.config.service_key_id.clone(), sequence: head.0, head_event_hash: head.1, at: self.config.clock.now() },
        )
    }
}
