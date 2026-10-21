use crate::IntentRecord;
use oic_domain_types::*;
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

/// Public operation material only. The authority and signer ledgers remain
/// separate stores with their own fencing and issuance contracts.
pub struct ApiStore {
    db: Mutex<Connection>,
    institution: InstitutionId,
    environment: EnvironmentId,
}

/// Convert database or serialization failures to `AuthorityUnavailable`.
fn storage(error: impl std::fmt::Display) -> OicError {
    OicError::new(
        ErrorCode::AuthorityUnavailable,
        format!("API store: {error}"),
    )
}

impl ApiStore {
    /// Open or initialize a SQLite intake store bound to one institution and
    /// environment. Creates its tables and requests WAL with full synchronization.
    /// Returns `ScopeMismatch` for an existing database with another binding;
    /// database setup errors return `AuthorityUnavailable`.
    pub fn open(
        path: impl AsRef<Path>,
        institution: InstitutionId,
        environment: EnvironmentId,
    ) -> OicResult<Self> {
        let db = Connection::open(path).map_err(storage)?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(storage)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS api_scope (singleton INTEGER PRIMARY KEY CHECK(singleton=1), institution TEXT NOT NULL, environment TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS api_intents (id TEXT PRIMARY KEY, body TEXT NOT NULL);")
            .map_err(storage)?;
        db.execute(
            "INSERT INTO api_scope VALUES (1,?1,?2) ON CONFLICT(singleton) DO NOTHING",
            params![institution.as_str(), environment.as_str()],
        )
        .map_err(storage)?;
        let (stored_institution, stored_environment): (String, String) = db
            .query_row(
                "SELECT institution,environment FROM api_scope WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(storage)?;
        if stored_institution != institution.as_str() || stored_environment != environment.as_str()
        {
            return Err(OicError::scope(
                "API database belongs to another institution/environment",
            ));
        }
        Ok(Self {
            db: Mutex::new(db),
            institution,
            environment,
        })
    }

    /// Reject an authority binding different from this store's institution or
    /// environment with `ScopeMismatch`.
    pub(crate) fn check_scope(
        &self,
        institution: &InstitutionId,
        environment: &EnvironmentId,
    ) -> OicResult<()> {
        if institution != &self.institution || environment != &self.environment {
            return Err(OicError::scope("API store and authority scopes differ"));
        }
        Ok(())
    }

    /// Load an intent by ID. Returns `NotFound` if absent, `RecoveryRequired`
    /// if its JSON is corrupt, or `AuthorityUnavailable` on a database error.
    pub fn get(&self, id: &IntentId) -> OicResult<IntentRecord> {
        let body: Option<String> = self
            .db
            .lock()
            .query_row(
                "SELECT body FROM api_intents WHERE id=?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        serde_json::from_str(&body.ok_or_else(|| OicError::new(ErrorCode::NotFound, "intent"))?)
            .map_err(|_| OicError::new(ErrorCode::RecoveryRequired, "API intent record is corrupt"))
    }

    /// Insert an intent record or return the existing record for the same intent.
    /// Existing candidate and dispatch state are preserved. A different intent
    /// body under the same ID returns `Conflict`; serialization, database, and
    /// record-read errors propagate.
    pub(crate) fn insert(&self, record: &IntentRecord) -> OicResult<IntentRecord> {
        let body = serde_json::to_string(record).map_err(storage)?;
        self.db
            .lock()
            .execute(
                "INSERT INTO api_intents (id,body) VALUES (?1,?2) ON CONFLICT(id) DO NOTHING",
                params![record.intent.intent_id.as_str(), body],
            )
            .map_err(storage)?;
        let existing = self.get(&record.intent.intent_id)?;
        if existing.intent != record.intent {
            return Err(OicError::new(
                ErrorCode::Conflict,
                "intent id already has a different body",
            ));
        }
        Ok(existing)
    }

    /// Compare-and-swap prevents two API processes from dropping approvals or
    /// starting two coordinators. Dispatch is committed before any signer call.
    /// Returns `Conflict` if the old record is absent or no longer matches;
    /// serialization and database errors return `AuthorityUnavailable`.
    pub(crate) fn replace(&self, old: &IntentRecord, new: &IntentRecord) -> OicResult<()> {
        let old_body = serde_json::to_string(old).map_err(storage)?;
        let new_body = serde_json::to_string(new).map_err(storage)?;
        let count = self
            .db
            .lock()
            .execute(
                "UPDATE api_intents SET body=?1 WHERE id=?2 AND body=?3",
                params![new_body, old.intent.intent_id.as_str(), old_body],
            )
            .map_err(storage)?;
        if count != 1 {
            return Err(OicError::new(
                ErrorCode::Conflict,
                "intent changed concurrently; read its current state",
            ));
        }
        Ok(())
    }
}
