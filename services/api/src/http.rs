use crate::*;
use axum::{
    extract::{rejection::JsonRejection, DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

pub struct HttpError(StatusCode, OicError);
impl From<OicError> for HttpError {
    fn from(error: OicError) -> Self {
        let status = match error.code {
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::ScopeMismatch | ErrorCode::InvalidSignature => StatusCode::FORBIDDEN,
            ErrorCode::InvalidRequest
            | ErrorCode::UnsupportedCapability
            | ErrorCode::UnverifiableTransaction => StatusCode::BAD_REQUEST,
            ErrorCode::AuthorityUnavailable | ErrorCode::RecoveryRequired => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::CONFLICT,
        };
        Self(status, error)
    }
}
impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

fn principal<S: AuthorityStore>(
    api: &Api<S>,
    headers: &HeaderMap,
) -> Result<ApiCredential, HttpError> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    token.and_then(|t| api.authenticate(t).ok()).ok_or_else(|| {
        HttpError(
            StatusCode::UNAUTHORIZED,
            OicError::scope("bearer credential required"),
        )
    })
}

async fn blocking<T: Serialize + Send + 'static>(
    f: impl FnOnce() -> OicResult<T> + Send + 'static,
) -> Result<Json<T>, HttpError> {
    let result = tokio::task::spawn_blocking(f).await.map_err(|_| {
        HttpError::from(OicError::internal(
            "API worker stopped; inspect operation before retrying",
        ))
    })?;
    Ok(Json(result?))
}

/// All routes are authenticated. No CORS wildcard or unauthenticated signing,
/// enrollment, key import, administrative update, or arbitrary-tx endpoint.
pub fn router<S: AuthorityStore + 'static>(api: Arc<Api<S>>) -> Router {
    Router::new()
        .route("/v1/intents", post(create::<S>))
        .route("/v1/intents/{id}", get(intent::<S>))
        .route("/v1/intents/{id}/preview", get(preview::<S>))
        .route("/v1/intents/{id}/approvals", post(approve::<S>))
        .route("/v1/intents/{id}/submit", post(submit::<S>))
        .route("/v1/intents/{id}/cancel", post(cancel::<S>))
        .route("/v1/operations/{id}", get(operation::<S>))
        .route("/v1/operations/{id}/refresh", post(refresh::<S>))
        .route("/v1/operations/{id}/evidence", get(evidence::<S>))
        .route("/v1/wallets/{id}/balances", get(balances::<S>))
        .route("/v1/events", get(events::<S>))
        .route("/v1/export", get(export::<S>))
        .layer(DefaultBodyLimit::max(1_048_576))
        .with_state(api)
}

async fn create<S: AuthorityStore + 'static>(
    State(api): State<Arc<Api<S>>>,
    headers: HeaderMap,
    body: Result<Json<Intent>, JsonRejection>,
) -> Result<Json<IntentRecord>, HttpError> {
    let p = principal(&api, &headers)?;
    let Json(intent) =
        body.map_err(|_| OicError::invalid_request("invalid intent JSON or request size"))?;
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| HttpError::from(OicError::invalid_request("Idempotency-Key required")))?
        .to_string();
    blocking(move || api.create(&p, intent, &key)).await
}
async fn intent<S: AuthorityStore + 'static>(
    State(api): State<Arc<Api<S>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<IntentRecord>, HttpError> {
    let p = principal(&api, &headers)?;
    blocking(move || api.get(&p, &IntentId::unchecked(id), Scope::Read)).await
}
async fn preview<S: AuthorityStore + 'static>(
    State(api): State<Arc<Api<S>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApprovalPackage>, HttpError> {
    let p = principal(&api, &headers)?;
    blocking(move || {
        Ok(api
            .get(&p, &IntentId::unchecked(id), Scope::Read)?
            .built
            .package)
    })
    .await
}
async fn approve<S: AuthorityStore + 'static>(
    State(api): State<Arc<Api<S>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<Json<ApprovalGrant>, JsonRejection>,
) -> Result<Json<IntentRecord>, HttpError> {
    let p = principal(&api, &headers)?;
    let Json(grant) =
        body.map_err(|_| OicError::invalid_request("invalid approval JSON or request size"))?;
    blocking(move || api.approve(&p, &IntentId::unchecked(id), grant)).await
}
async fn submit<S: AuthorityStore + 'static>(
    State(api): State<Arc<Api<S>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<IntentRecord>, HttpError> {
    let p = principal(&api, &headers)?;
    blocking(move || api.submit(&p, &IntentId::unchecked(id))).await
}
async fn cancel<S: AuthorityStore + 'static>(
    State(api): State<Arc<Api<S>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<IntentRecord>, HttpError> {
    let p = principal(&api, &headers)?;
    blocking(move || api.cancel(&p, &IntentId::unchecked(id))).await
}

fn operation_scope<S: AuthorityStore>(
    api: &Api<S>,
    p: &ApiCredential,
    id: &str,
    scope: Scope,
) -> OicResult<OperationFamilyId> {
    let id = OperationFamilyId::unchecked(id);
    let vault = api
        .coordinator
        .authority()
        .store()
        .read(|s| s.families.get(&id).map(|f| f.vault_id.clone()))?
        .ok_or_else(|| missing("operation"))?;
    api.authorize(p, &vault, scope)?;
    Ok(id)
}
async fn operation<S: AuthorityStore + 'static>(
    State(api): State<Arc<Api<S>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, HttpError> {
    let p = principal(&api, &headers)?;
    blocking(move || {
        let id = operation_scope(&api, &p, &id, Scope::Read)?;
        Ok(json!({ "operation_family_id": id, "lifecycle": api.lifecycle(&id)?, "issuance": api.coordinator.store().operation(&id), "submission": api.broadcaster.record(&id)? }))
    }).await
}
async fn refresh<S: AuthorityStore + 'static>(
    State(api): State<Arc<Api<S>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<LifecycleState>, HttpError> {
    let p = principal(&api, &headers)?;
    blocking(move || {
        let id = operation_scope(&api, &p, &id, Scope::Submit)?;
        let state = api.broadcaster.poll(&id)?;
        let intent = api
            .coordinator
            .authority()
            .store()
            .read(|s| s.families[&id].intent_id.clone())?;
        match api.store.get(&intent) {
            Ok(record) => api.publish_operation(&record)?,
            Err(e) if e.code == ErrorCode::NotFound => (),
            Err(e) => return Err(e),
        }
        Ok(state)
    })
    .await
}
async fn evidence<S: AuthorityStore + 'static>(
    State(api): State<Arc<Api<S>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<IntentRecord>, HttpError> {
    let p = principal(&api, &headers)?;
    blocking(move || {
        let id = operation_scope(&api, &p, &id, Scope::Read)?;
        let intent = api
            .coordinator
            .authority()
            .store()
            .read(|s| s.families[&id].intent_id.clone())?;
        api.get(&p, &intent, Scope::Read)
    })
    .await
}

async fn balances<S: AuthorityStore + 'static>(
    State(api): State<Arc<Api<S>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, HttpError> {
    let p = principal(&api, &headers)?;
    blocking(move || {
        let wallet = api.catalog.wallets.get(&ChainWalletId::unchecked(id)).ok_or_else(|| missing("wallet"))?;
        api.authorize(&p, &wallet.vault_id, Scope::Read)?;
        let data = api.reconciler.export()?;
        let native = data.assets.values().filter(|a| a.asset == AssetKind::Native).map(|a| (a.network_id.clone(), a.asset_id.clone())).collect();
        let wallets: Vec<_> = api.catalog.wallets.values().cloned().collect();
        let reserved = oic_service_reconciler::outstanding_reservations(api.coordinator.authority().store().as_ref(), &wallets, &native)?;
        let balances: Vec<_> = data.assets.values().filter(|a| a.network_id == wallet.network_id).map(|a| api.reconciler.holdings(&wallet.chain_wallet_id, &a.asset_id, reserved.get(&(wallet.chain_wallet_id.clone(), a.asset_id.clone())).copied().unwrap_or_default())).collect::<OicResult<_>>()?;
        Ok(json!({ "chain_wallet_id": wallet.chain_wallet_id, "balances": balances, "cursor": data.cursors.get(&wallet.chain_profile_id) }))
    }).await
}

fn institution_read<S: AuthorityStore>(api: &Api<S>, p: &ApiCredential) -> OicResult<()> {
    if api.catalog.vaults.is_empty() {
        return Err(OicError::scope("institution has no enrolled vaults"));
    }
    for vault in api.catalog.vaults.keys() {
        api.authorize(p, vault, Scope::Read)?;
    }
    Ok(())
}
#[derive(Deserialize)]
struct Replay {
    #[serde(default)]
    after: u64,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    100
}
async fn events<S: AuthorityStore + 'static>(
    State(api): State<Arc<Api<S>>>,
    headers: HeaderMap,
    replay: Result<Query<Replay>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<Vec<LifecycleEvent>>, HttpError> {
    let p = principal(&api, &headers)?;
    let Query(replay) =
        replay.map_err(|_| OicError::invalid_request("invalid event cursor or limit"))?;
    blocking(move || {
        institution_read(&api, &p)?;
        api.reconciler.events_since(replay.after, replay.limit)
    })
    .await
}
async fn export<S: AuthorityStore + 'static>(
    State(api): State<Arc<Api<S>>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, HttpError> {
    let p = principal(&api, &headers)?;
    blocking(move || { institution_read(&api, &p)?; Ok(json!({ "schema_version": 1, "operations": api.reconciler.export()?, "authority": api.coordinator.authority().checkpoint()? })) }).await
}
