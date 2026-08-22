use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, Request, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use thunderbolt_config::{AuthIdentity, Config, Environment, Network, NodeRole, TokenScope, TokenStore};
use thunderbolt_protocol::{
    ChannelEvent, ChannelId, ChannelSnapshot, Digest, ImplementationId, LedgerEntry, ParticipantId,
    VerificationEvidence, PROTOCOL_VERSION,
};
use thunderbolt_storage::{IntegrityReport, SqliteStorage, StorageError, DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::{DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::{error, info_span, Level};

use crate::{NodeError, NodeOptions};

const API_VERSION: u16 = 1;
const DEMO_ID: &str = "development-unverified-demo";

#[derive(Clone)]
pub(crate) struct AppState {
    config: Arc<Config>,
    tokens: Arc<TokenStore>,
    storage: Arc<SqliteStorage>,
    database_slots: Arc<Semaphore>,
    ready: Arc<AtomicBool>,
    stop: CancellationToken,
    started_at: Instant,
    options: NodeOptions,
}

impl AppState {
    pub(crate) fn new(
        config: Arc<Config>,
        tokens: Arc<TokenStore>,
        storage: Arc<SqliteStorage>,
        database_workers: usize,
        options: NodeOptions,
    ) -> Self {
        Self {
            config,
            tokens,
            storage,
            database_slots: Arc::new(Semaphore::new(database_workers)),
            ready: Arc::new(AtomicBool::new(true)),
            stop: CancellationToken::new(),
            started_at: Instant::now(),
            options,
        }
    }

    pub(crate) fn mark_not_ready(&self) {
        self.ready.store(false, Ordering::Release);
    }

    pub(crate) async fn stop_requested(&self) {
        self.stop.cancelled().await;
    }

    async fn database<T, F>(&self, operation: F) -> Result<T, ApiError>
    where
        T: Send + 'static,
        F: FnOnce(&SqliteStorage) -> Result<T, StorageError> + Send + 'static,
    {
        self.database_with(operation, |storage_error| {
            error!(error = %storage_error, "database operation failed");
            ApiError::internal()
        })
        .await
    }

    async fn database_with<T, F, M>(&self, operation: F, map_storage_error: M) -> Result<T, ApiError>
    where
        T: Send + 'static,
        F: FnOnce(&SqliteStorage) -> Result<T, StorageError> + Send + 'static,
        M: FnOnce(StorageError) -> ApiError + Send,
    {
        let permit = self
            .database_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ApiError::internal())?;
        let storage = self.storage.clone();
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation(&storage)
        });
        task.await
            .map_err(|join_error| {
                error!(error = %join_error, "bounded database worker terminated");
                ApiError::internal()
            })?
            .map_err(map_storage_error)
    }
}

pub(crate) fn build_router(state: AppState) -> Result<Router, NodeError> {
    let max_body = usize::try_from(state.config.limits.max_request_body_bytes)
        .map_err(|_| NodeError::Configuration("max_request_body_bytes does not fit this platform".to_owned()))?;
    let max_headers = usize::try_from(state.config.limits.max_request_header_bytes)
        .map_err(|_| NodeError::Configuration("max_request_header_bytes does not fit this platform".to_owned()))?;
    let max_concurrent = usize::try_from(state.config.limits.max_concurrent_requests)
        .map_err(|_| NodeError::Configuration("max_concurrent_requests does not fit this platform".to_owned()))?;
    let request_timeout = state.config.limits.request_timeout();

    let router = Router::new()
        .route("/live", get(live))
        .route("/ready", get(ready))
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/v1/health/live", get(live))
        .route("/v1/health/ready", get(ready))
        .route("/v1/info", get(info))
        .route("/v1/config", get(redacted_config))
        .route("/v1/config/redacted", get(redacted_config))
        .route("/v1/channels", get(list_channels))
        .route("/v1/channels/{channel_id}", get(get_channel))
        .route("/v1/channels/{channel_id}/events", get(list_events).post(append_event))
        .route("/v1/channels/{channel_id}/events/{sequence}", get(get_event))
        .route("/v1/database/integrity", post(database_integrity))
        .route("/v1/database/backup", post(database_backup))
        .route("/v1/storage/integrity", post(database_integrity))
        .route("/v1/storage/backup", post(database_backup))
        .route("/v1/admin/stop", post(stop))
        .with_state(state)
        .layer(ConcurrencyLimitLayer::new(max_concurrent))
        .layer(middleware::from_fn_with_state(request_timeout, enforce_request_timeout))
        .layer(RequestBodyLimitLayer::new(max_body))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<Body>| {
                    info_span!(
                        "http.request",
                        method = %request.method(),
                        path = %request.uri().path(),
                        version = ?request.version(),
                    )
                })
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO))
                .on_failure(DefaultOnFailure::new().level(Level::ERROR)),
        )
        .layer(middleware::from_fn_with_state(max_headers, enforce_header_limit));
    Ok(router)
}

/// Minimal unauthenticated health response for supervisors.
#[derive(Clone, Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

/// Public, non-secret runtime metadata.
#[derive(Clone, Debug, Serialize)]
pub struct InfoResponse {
    pub name: &'static str,
    pub version: &'static str,
    pub api_version: u16,
    pub protocol_version: u16,
    pub node_id: String,
    pub role: NodeRole,
    pub environment: Environment,
    pub network: Network,
    pub mainnet_enabled: bool,
    pub verification_mode: &'static str,
    pub uptime_seconds: u64,
}

/// Result returned after an append or exact idempotent replay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppendResponse {
    pub sequence: u64,
    pub entry_hash: thunderbolt_protocol::EntryHash,
    pub replayed: bool,
    pub snapshot: ChannelSnapshot,
}

/// One stable page of channel snapshots.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelPage {
    pub channels: Vec<ChannelSnapshot>,
    pub next_after: Option<ChannelId>,
}

/// One stable page of ledger entries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventPage {
    pub events: Vec<LedgerEntry>,
    pub next_after_sequence: Option<u64>,
}

/// Storage integrity counts.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct IntegrityResponse {
    pub channels_checked: usize,
    pub entries_checked: usize,
}

impl From<IntegrityReport> for IntegrityResponse {
    fn from(report: IntegrityReport) -> Self {
        Self {
            channels_checked: report.channels_checked,
            entries_checked: report.entries_checked,
        }
    }
}

/// A safe backup filename relative to the configured backup directory.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRequest {
    pub filename: Option<String>,
}

/// Verified backup result.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackupResponse {
    pub filename: String,
    pub integrity: IntegrityResponse,
}

#[derive(Debug, Deserialize)]
struct ChannelListQuery {
    after: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct EventListQuery {
    after_sequence: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}

async fn live() -> Json<HealthResponse> {
    Json(HealthResponse { status: "live" })
}

async fn ready(State(state): State<AppState>) -> Response {
    if state.ready.load(Ordering::Acquire) {
        Json(HealthResponse { status: "ready" }).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse { status: "not_ready" }),
        )
            .into_response()
    }
}

async fn info(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<InfoResponse>, ApiError> {
    let _identity = authorize(&state, &headers, TokenScope::Read)?;
    let verification_mode = if state.options.allow_unverified_demo_events {
        DEMO_ID
    } else {
        "verification-required-no-verifier-configured"
    };
    Ok(Json(InfoResponse {
        name: "Bitcoin Thunderbolt",
        version: env!("CARGO_PKG_VERSION"),
        api_version: API_VERSION,
        protocol_version: PROTOCOL_VERSION,
        node_id: state.config.node.id.clone(),
        role: state.config.node.role,
        environment: state.config.deployment.environment,
        network: state.config.deployment.network,
        mainnet_enabled: false,
        verification_mode,
        uptime_seconds: state.started_at.elapsed().as_secs(),
    }))
}

async fn redacted_config(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Config>, ApiError> {
    let _identity = authorize(&state, &headers, TokenScope::Read)?;
    Ok(Json(state.config.redacted()))
}

async fn list_channels(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ChannelListQuery>,
) -> Result<Json<ChannelPage>, ApiError> {
    let _identity = authorize(&state, &headers, TokenScope::Read)?;
    let after = query.after.map(|value| parse_channel_id(&value)).transpose()?;
    let limit = page_limit(query.limit)?;
    let after_for_query = after;
    let channels = state
        .database_with(
            move |storage| storage.list_channels(after_for_query.as_ref(), limit),
            page_storage_error,
        )
        .await?;
    let next_after = if channels.len() == limit {
        channels.last().map(|channel| channel.channel_id)
    } else {
        None
    };
    Ok(Json(ChannelPage { channels, next_after }))
}

async fn get_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
) -> Result<Json<ChannelSnapshot>, ApiError> {
    let _identity = authorize(&state, &headers, TokenScope::Read)?;
    let channel_id = parse_channel_id(&channel_id)?;
    let query_id = channel_id;
    let channel = state
        .database(move |storage| storage.get_channel(&query_id))
        .await?
        .ok_or_else(|| ApiError::not_found("channel_not_found", "channel does not exist"))?;
    Ok(Json(channel))
}

async fn list_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
    Query(query): Query<EventListQuery>,
) -> Result<Json<EventPage>, ApiError> {
    let _identity = authorize(&state, &headers, TokenScope::Read)?;
    let channel_id = parse_channel_id(&channel_id)?;
    let limit = page_limit(query.limit)?;
    let events = state
        .database_with(
            move |storage| storage.list_entries(&channel_id, query.after_sequence, limit),
            page_storage_error,
        )
        .await?;
    let next_after_sequence = if events.len() == limit {
        events.last().map(|event| event.sequence)
    } else {
        None
    };
    Ok(Json(EventPage {
        events,
        next_after_sequence,
    }))
}

async fn get_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((channel_id, sequence)): Path<(String, u64)>,
) -> Result<Json<LedgerEntry>, ApiError> {
    let _identity = authorize(&state, &headers, TokenScope::Read)?;
    let channel_id = parse_channel_id(&channel_id)?;
    let event = state
        .database(move |storage| storage.get_entry(&channel_id, sequence))
        .await?
        .ok_or_else(|| ApiError::not_found("event_not_found", "ledger event does not exist"))?;
    Ok(Json(event))
}

async fn append_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(channel_id): Path<String>,
    payload: Result<Json<LedgerEntry>, JsonRejection>,
) -> Result<(StatusCode, Json<AppendResponse>), ApiError> {
    let identity = authorize(&state, &headers, TokenScope::Write)?;
    let path_channel_id = parse_channel_id(&channel_id)?;
    let Json(mut entry) = payload.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::payload_too_large()
        } else {
            ApiError::bad_request("invalid_json", format!("invalid ledger entry: {rejection}"))
        }
    })?;
    if path_channel_id != entry.channel_id {
        return Err(ApiError::bad_request(
            "channel_mismatch",
            "path channel id does not match the ledger entry".to_owned(),
        ));
    }
    if identity
        .as_ref()
        .is_some_and(|identity| identity.id != entry.actor.participant_id.as_str())
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "actor_identity_mismatch",
            "the authenticated token id must match the ledger actor participant id".to_owned(),
        ));
    }
    prepare_verification(&state, &mut entry)?;

    let outcome = state
        .database_with(move |storage| storage.append_entry(&entry), append_storage_error)
        .await?;
    let status = if outcome.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((
        status,
        Json(AppendResponse {
            sequence: outcome.sequence,
            entry_hash: outcome.entry_hash,
            replayed: outcome.replayed,
            snapshot: outcome.snapshot,
        }),
    ))
}

async fn database_integrity(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<EmptyRequest>, JsonRejection>,
) -> Result<Json<IntegrityResponse>, ApiError> {
    let _identity = authorize(&state, &headers, TokenScope::Operator)?;
    let Json(_request) = payload.map_err(json_rejection)?;
    let report = state.database(SqliteStorage::integrity_check).await?;
    Ok(Json(report.into()))
}

async fn database_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<BackupRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<BackupResponse>), ApiError> {
    let _identity = authorize(&state, &headers, TokenScope::Admin)?;
    let Json(request) = payload.map_err(json_rejection)?;
    let filename = request.filename.unwrap_or(default_backup_filename()?);
    validate_backup_filename(&filename)?;
    let directory = state.config.backup.directory.clone();
    tokio::fs::create_dir_all(&directory).await.map_err(|io_error| {
        error!(error = %io_error, "failed to prepare backup directory");
        ApiError::internal()
    })?;
    let destination = directory.join(&filename);
    let report = state
        .database_with(move |storage| storage.backup_to(destination), backup_storage_error)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(BackupResponse {
            filename,
            integrity: report.into(),
        }),
    ))
}

async fn stop(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<EmptyRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let _identity = authorize(&state, &headers, TokenScope::Admin)?;
    let Json(_request) = payload.map_err(json_rejection)?;
    state.mark_not_ready();
    let stop = state.stop.clone();
    tokio::spawn(async move {
        tokio::task::yield_now().await;
        stop.cancel();
    });
    Ok(StatusCode::ACCEPTED)
}

fn json_rejection(rejection: JsonRejection) -> ApiError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::payload_too_large()
    } else {
        ApiError::bad_request("invalid_json", format!("invalid JSON request: {rejection}"))
    }
}

fn prepare_verification(state: &AppState, entry: &mut LedgerEntry) -> Result<(), ApiError> {
    if !entry.event.verification().is_empty() {
        return Err(ApiError::unprocessable(
            "client_verification_rejected",
            "verification evidence must be produced by a trusted node verifier, not supplied by a client".to_owned(),
        ));
    }
    if !state.options.allow_unverified_demo_events {
        return Err(ApiError::unavailable(
            "verification_unavailable",
            "no production verifier is configured; unverified events are disabled".to_owned(),
        ));
    }

    let verifier = ParticipantId::new(DEMO_ID).map_err(|_| ApiError::internal())?;
    let implementation = ImplementationId::new(DEMO_ID).map_err(|_| ApiError::internal())?;
    let evidence: Vec<VerificationEvidence> = entry
        .event
        .required_verifications()
        .iter()
        .copied()
        .map(|kind| {
            VerificationEvidence::verified(
                kind,
                verifier.clone(),
                implementation.clone(),
                Digest::ZERO,
                entry.occurred_at_ms,
            )
        })
        .collect();
    match &mut entry.event {
        ChannelEvent::Open(event) => event.verification = evidence,
        ChannelEvent::Invoice(event) => event.verification = evidence,
        ChannelEvent::Transfer(event) => event.verification = evidence,
        ChannelEvent::Finalize(event) => event.verification = evidence,
    }
    Ok(())
}

fn authorize(state: &AppState, headers: &HeaderMap, required: TokenScope) -> Result<Option<AuthIdentity>, ApiError> {
    if !state.config.auth.enabled {
        return Ok(None);
    }
    if headers.get_all(AUTHORIZATION).iter().count() != 1 {
        return Err(ApiError::unauthorized());
    }
    let value = headers
        .get(AUTHORIZATION)
        .ok_or_else(ApiError::unauthorized)?
        .as_bytes();
    let Some(space) = value.iter().position(|byte| *byte == b' ') else {
        return Err(ApiError::unauthorized());
    };
    let (scheme, token_with_space) = value.split_at(space);
    let token = token_with_space.get(1..).ok_or_else(ApiError::unauthorized)?;
    if !scheme.eq_ignore_ascii_case(b"bearer")
        || token.is_empty()
        || token.iter().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ApiError::unauthorized());
    }
    let identity = state.tokens.authenticate(token).ok_or_else(ApiError::unauthorized)?;
    if !identity.allows(required) {
        return Err(ApiError::forbidden());
    }
    Ok(Some(identity))
}

fn append_storage_error(error: StorageError) -> ApiError {
    error!(error = %error, "ledger append rejected");
    match error {
        StorageError::Protocol(_) | StorageError::InvalidInput(_) | StorageError::SequenceConflict { .. } => {
            ApiError::conflict(
                "ledger_transition_rejected",
                "the event conflicts with the durable channel lifecycle".to_owned(),
            )
        }
        _ => ApiError::internal(),
    }
}

fn backup_storage_error(error: StorageError) -> ApiError {
    error!(error = %error, "database backup failed");
    match error {
        StorageError::BackupDestinationExists(_) => ApiError::conflict(
            "backup_exists",
            "the requested backup filename already exists".to_owned(),
        ),
        StorageError::InvalidInput(_) => ApiError::bad_request(
            "invalid_backup_destination",
            "the configured backup destination is invalid".to_owned(),
        ),
        _ => ApiError::internal(),
    }
}

fn page_storage_error(error: StorageError) -> ApiError {
    error!(error = %error, "database page could not be returned");
    match error {
        StorageError::PageByteBudgetExceeded { .. } => ApiError::unprocessable(
            "page_byte_budget_exceeded",
            "the requested page is too large; retry with a smaller limit".to_owned(),
        ),
        _ => ApiError::internal(),
    }
}

fn parse_channel_id(value: &str) -> Result<ChannelId, ApiError> {
    ChannelId::from_str(value)
        .map_err(|error| ApiError::bad_request("invalid_channel_id", format!("invalid channel id: {error}")))
}

fn page_limit(limit: Option<usize>) -> Result<usize, ApiError> {
    let limit = limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if !(1..=MAX_PAGE_LIMIT).contains(&limit) {
        return Err(ApiError::bad_request(
            "invalid_page_limit",
            format!("limit must be between 1 and {MAX_PAGE_LIMIT}"),
        ));
    }
    Ok(limit)
}

fn validate_backup_filename(filename: &str) -> Result<(), ApiError> {
    if filename.is_empty()
        || filename.len() > 128
        || filename == "."
        || filename == ".."
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ApiError::bad_request(
            "invalid_backup_filename",
            "filename must contain only ASCII letters, digits, '.', '_' and '-'".to_owned(),
        ));
    }
    Ok(())
}

fn default_backup_filename() -> Result<String, ApiError> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::internal())?
        .as_millis();
    Ok(format!("thunderbolt-{milliseconds}.sqlite3"))
}

async fn enforce_header_limit(State(maximum): State<usize>, request: Request<Body>, next: Next) -> Response {
    let total = request.headers().iter().try_fold(0_usize, |total, (name, value)| {
        total
            .checked_add(name.as_str().len())?
            .checked_add(value.as_bytes().len())
            .and_then(|total| total.checked_add(4))
    });
    if total.is_none_or(|total| total > maximum) {
        return ApiError::new(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "headers_too_large",
            "request headers exceed the configured limit".to_owned(),
        )
        .into_response();
    }
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn enforce_request_timeout(
    State(maximum): State<std::time::Duration>,
    request: Request<Body>,
    next: Next,
) -> Response {
    match tokio::time::timeout(maximum, next.run(request)).await {
        Ok(response) => response,
        Err(_) => ApiError::new(
            StatusCode::REQUEST_TIMEOUT,
            "request_timeout",
            "request processing exceeded the configured timeout".to_owned(),
        )
        .into_response(),
    }
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: String) -> Self {
        Self { status, code, message }
    }

    fn bad_request(code: &'static str, message: String) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "a valid bearer token is required".to_owned(),
        )
    }

    fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "the bearer token does not grant the required scope".to_owned(),
        )
    }

    fn not_found(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::NOT_FOUND, code, message.to_owned())
    }

    fn conflict(code: &'static str, message: String) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    fn unprocessable(code: &'static str, message: String) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, code, message)
    }

    fn unavailable(code: &'static str, message: String) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, code, message)
    }

    fn payload_too_large() -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            "request body exceeds the configured limit".to_owned(),
        )
    }

    fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "the node could not complete the operation".to_owned(),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status;
        let mut response = (
            status,
            Json(ErrorEnvelope {
                error: ErrorBody {
                    code: self.code,
                    message: self.message,
                },
            }),
        )
            .into_response();
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"bitcoin-thunderbolt\""),
            );
        }
        response
    }
}
