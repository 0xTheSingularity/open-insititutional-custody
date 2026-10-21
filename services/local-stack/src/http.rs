use crate::*;
use axum::{
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};

struct HttpError(StatusCode, OicError);
impl From<OicError> for HttpError {
    fn from(e: OicError) -> Self {
        let status = match e.code {
            ErrorCode::ScopeMismatch => StatusCode::FORBIDDEN,
            ErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
            ErrorCode::Conflict => StatusCode::CONFLICT,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        Self(status, e)
    }
}
impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}
fn bearer(h: &HeaderMap) -> Result<&str, HttpError> {
    h.get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| HttpError(StatusCode::UNAUTHORIZED, OicError::scope("bearer required")))
}
fn read_scope(s: &Stack, h: &HeaderMap) -> Result<(), HttpError> {
    let p = s
        .api
        .authenticate(bearer(h)?)
        .map_err(|e| HttpError(StatusCode::UNAUTHORIZED, e))?;
    s.api.authorize(&p, &vault_id(), Scope::Read)?;
    Ok(())
}

pub(crate) fn router(stack: Arc<Stack>) -> Router {
    let extensions = Router::new()
        .route("/local/v1/catalog", get(catalog))
        .route("/local/v1/intents", get(intents))
        .route("/local/v1/status", get(status))
        .route("/local/v1/controls", post(control))
        .with_state(stack.clone());
    oic_service_api::router(stack.api.clone())
        .merge(extensions)
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(middleware::from_fn_with_state(stack, tick))
}
async fn tick(State(s): State<Arc<Stack>>, request: Request, next: Next) -> Response {
    if let Err(e) = s.chains.tick(s.api.clock.now()) {
        return HttpError::from(e).into_response();
    }
    next.run(request).await
}
async fn catalog(State(s): State<Arc<Stack>>, h: HeaderMap) -> Result<Json<Value>, HttpError> {
    read_scope(&s, &h)?;
    Ok(Json(s.catalog()))
}
async fn intents(
    State(s): State<Arc<Stack>>,
    h: HeaderMap,
) -> Result<Json<Vec<IntentId>>, HttpError> {
    read_scope(&s, &h)?;
    Ok(Json(
        s.api
            .coordinator
            .authority()
            .store()
            .read(|st| st.intents.keys().cloned().collect())?,
    ))
}
async fn status(State(s): State<Arc<Stack>>, h: HeaderMap) -> Result<Json<Value>, HttpError> {
    read_scope(&s, &h)?;
    let result = tokio::task::spawn_blocking(move || s.sync())
        .await
        .map_err(io)??;
    Ok(Json(result))
}
async fn control(
    State(s): State<Arc<Stack>>,
    h: HeaderMap,
    body: Result<Json<Control>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, HttpError> {
    if oic_canonical_encoding::sha256(bearer(&h)?.as_bytes()) != s.operator_hash {
        return Err(HttpError(
            StatusCode::FORBIDDEN,
            OicError::scope("separate local simulator operator credential required"),
        ));
    }
    let Json(control) =
        body.map_err(|_| OicError::invalid_request("invalid local control JSON"))?;
    if control.action == Action::LoseNextSubmissionAck && !s.faults {
        return Err(OicError::invalid_request(
            "fault injection is disabled; start with --enable-faults",
        )
        .into());
    }
    let result = tokio::task::spawn_blocking(move || {
        let outcome = s.chains.control(control, s.api.clock.now())?;
        Ok::<_, OicError>(json!({"outcome":outcome,"status":s.sync()?}))
    })
    .await
    .map_err(io)??;
    Ok(Json(result))
}
