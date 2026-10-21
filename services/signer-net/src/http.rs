//! Authenticated D2 log reads and approval-only intake. Embed behind operator
//! mTLS/HTTPS; this router is not a TLS terminator or a session/login service.
//! Every credential grants read access to the entire confidential authority
//! log. Do not substitute a vault-scoped console bearer for this permission.

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequest, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use oic_authorization_state::{AuthorityCommand, Clock};
use oic_canonical_encoding::sha256;
use oic_domain_types::*;
use oic_replicated_authority::{
    Command, Executor, FinalizedFloor,
    runtime::{FinalizedReader, FinalizedSnapshot, Running},
};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::{Semaphore, watch};

/// Provision an unpredictable session token outside this router, retain only
/// its SHA-256 here, and use an HttpOnly cookie or an Authorization bearer.
/// `None` cannot submit approvals; `Some` binds approval intake to that exact
/// ordered credential. Possession of the session is not a passkey signature.
pub struct NodeCredential {
    pub token_hash: Hash32,
    pub approver: Option<CredentialId>,
}

pub struct NodeApi {
    history: FinalizedReader,
    progress: watch::Receiver<FinalizedSnapshot>,
    proposer: Option<oic_replicated_authority::Proposer>,
    executor: Executor,
    credentials: BTreeMap<Hash32, Option<CredentialId>>,
    origin: HeaderValue,
    clock: Arc<dyn Clock>,
    workers: Arc<Semaphore>,
}

impl NodeApi {
    /// The host supplies the same independently pinned executor as the runtime.
    /// The consensus application still re-executes submitted approvals; this
    /// preflight is not ordering, finality, or a signing authorization shortcut.
    pub fn new(
        runtime: &Running,
        executor: Executor,
        credentials: Vec<NodeCredential>,
        origin: String,
        clock: Arc<dyn Clock>,
    ) -> OicResult<Self> {
        let uri: Uri = origin.parse().map_err(|_| OicError::invalid_request("invalid installed origin"))?;
        if (uri.scheme_str() != Some("https") && !(uri.scheme_str() == Some("http") && uri.host() == Some("localhost")))
            || uri.authority().is_none_or(|a| a.as_str().contains('@'))
            || uri.path() != "/"
            || uri.query().is_some()
            || origin.ends_with('/')
            || credentials.is_empty()
        {
            return Err(OicError::invalid_request("exact HTTPS installed origin and full-log credentials required"));
        }
        let origin = origin.parse().map_err(|_| OicError::invalid_request("invalid origin header"))?;
        let mut sessions = BTreeMap::new();
        for credential in credentials {
            if credential.token_hash == Hash32::ZERO
                || credential.token_hash == sha256(b"")
                || sessions.insert(credential.token_hash, credential.approver).is_some()
            {
                return Err(OicError::invalid_request("empty or duplicate node credential"));
            }
        }
        Ok(Self {
            history: runtime.history.clone(),
            progress: runtime.progress.clone(),
            proposer: runtime.proposer.clone(),
            executor,
            credentials: sessions,
            origin,
            clock,
            workers: Arc::new(Semaphore::new(8)),
        })
    }

    pub fn router(self) -> Router {
        let api = Arc::new(self);
        Router::new()
            .route("/v1/node/log", get(log).options(preflight))
            .route("/v1/node/approvals", post(approve).options(preflight))
            .layer(DefaultBodyLimit::max(1024 * 1024))
            .layer(middleware::from_fn_with_state(api.clone(), security_headers))
            .with_state(api)
    }

    fn credential(&self, headers: &HeaderMap) -> Result<&Option<CredentialId>, ApiError> {
        // Reject ambiguous/multiple session carriers, rather than choosing an
        // approval identity based on header order or a conflicting cookie.
        let bearer = headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
        let cookies: Vec<_> = headers
            .get_all("cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .filter_map(|v| v.trim().strip_prefix("oic_node_session="))
            .collect();
        if headers.get_all("authorization").iter().count() > 1
            || cookies.len() > 1
            || (headers.contains_key("authorization") && !cookies.is_empty())
        {
            return Err(ApiError(StatusCode::UNAUTHORIZED, ErrorCode::ScopeMismatch));
        }
        let token = bearer
            .or_else(|| cookies.first().copied())
            .filter(|token| (32..=512).contains(&token.len()) && token.is_ascii())
            .ok_or(ApiError(StatusCode::UNAUTHORIZED, ErrorCode::ScopeMismatch))?;
        self.credentials.get(&sha256(token.as_bytes())).ok_or(ApiError(StatusCode::UNAUTHORIZED, ErrorCode::ScopeMismatch))
    }
}

struct ApiError(StatusCode, ErrorCode);
impl From<OicError> for ApiError {
    fn from(error: OicError) -> Self {
        let status = match error.code {
            ErrorCode::ScopeMismatch | ErrorCode::InvalidSignature => StatusCode::FORBIDDEN,
            ErrorCode::InvalidRequest | ErrorCode::UnsupportedCapability => StatusCode::BAD_REQUEST,
            ErrorCode::AuthorityUnavailable | ErrorCode::RecoveryRequired => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::CONFLICT,
        };
        Self(status, error.code)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(OicError::new(self.1, "node request refused; reconcile finalized state before retrying"))).into_response()
    }
}

async fn security_headers(State(api): State<Arc<NodeApi>>, request: Request, next: Next) -> Response {
    let origin = request.headers().get("origin");
    let unique_origin = request.headers().get_all("origin").iter().count() <= 1;
    let permitted = unique_origin && origin == Some(&api.origin);
    let mut response = if (origin.is_some() || request.method() == Method::POST) && !permitted {
        ApiError(StatusCode::FORBIDDEN, ErrorCode::ScopeMismatch).into_response()
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("vary", HeaderValue::from_static("Origin"));
    if permitted {
        headers.insert("access-control-allow-origin", api.origin.clone());
        headers.insert("access-control-allow-credentials", HeaderValue::from_static("true"));
    }
    response
}

async fn preflight(headers: HeaderMap) -> Response {
    let method = headers.get("access-control-request-method").and_then(|v| v.to_str().ok());
    let fields = headers.get("access-control-request-headers").and_then(|v| v.to_str().ok());
    if !matches!(method, Some("GET" | "POST"))
        || fields.is_some_and(|fields| {
            fields.split(',').any(|name| !matches!(name.trim().to_ascii_lowercase().as_str(), "content-type" | "authorization"))
        })
    {
        return ApiError(StatusCode::FORBIDDEN, ErrorCode::ScopeMismatch).into_response();
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert("access-control-allow-methods", HeaderValue::from_static("GET, POST"));
    response.headers_mut().insert("access-control-allow-headers", HeaderValue::from_static("Content-Type, Authorization"));
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    after_height: u64,
    after_digest: Hash32,
}

async fn log(
    State(api): State<Arc<NodeApi>>,
    headers: HeaderMap,
    cursor: Result<Query<Cursor>, axum::extract::rejection::QueryRejection>,
) -> Result<Response, ApiError> {
    api.credential(&headers)?;
    let Query(cursor) = cursor.map_err(|_| ApiError(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest))?;
    let page = tokio::time::timeout(
        Duration::from_secs(5),
        api.history.read_page(FinalizedFloor { height: cursor.after_height, digest: cursor.after_digest }),
    )
    .await
    .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::AuthorityUnavailable))??;
    Ok(Json(page).into_response())
}

async fn approve(State(api): State<Arc<NodeApi>>, request: Request) -> Result<Response, ApiError> {
    // Refuse unauthenticated and read-only sessions before reading or decoding
    // their bodies, not merely before the more expensive native preflight.
    let identity = api.credential(request.headers())?.as_ref().ok_or(ApiError(StatusCode::FORBIDDEN, ErrorCode::ScopeMismatch))?.clone();
    let Json(command) =
        Json::<Command>::from_request(request, &()).await.map_err(|error| ApiError(error.status(), ErrorCode::InvalidRequest))?;
    let Command::Authority(inner) = &command else {
        return Err(ApiError(StatusCode::FORBIDDEN, ErrorCode::ScopeMismatch));
    };
    let AuthorityCommand::Approve { grant, .. } = inner.as_ref() else {
        return Err(ApiError(StatusCode::FORBIDDEN, ErrorCode::ScopeMismatch));
    };
    if grant.body.approver_credential_id != identity {
        return Err(ApiError(StatusCode::FORBIDDEN, ErrorCode::ScopeMismatch));
    }
    if api.progress.has_changed().is_err() {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::RecoveryRequired));
    }
    let snapshot = api.progress.borrow().clone();
    if snapshot.floor.height == 0 {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::RecoveryRequired));
    }
    let proposer = api.proposer.clone().ok_or(ApiError(StatusCode::FORBIDDEN, ErrorCode::ScopeMismatch))?;
    let permit = api.workers.clone().try_acquire_owned().map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS, ErrorCode::Conflict))?;
    let executor = api.executor.clone();
    let now = api.clock.now();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        executor.execute((*snapshot.state).clone(), std::slice::from_ref(&command), now)?;
        proposer.submit(vec![command])
    })
    .await
    .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::AuthorityUnavailable))??;
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "accepted": true }))).into_response())
}
