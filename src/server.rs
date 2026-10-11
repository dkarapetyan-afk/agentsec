use crate::audit::{AuditEvent, AuditLog};
use crate::client::DaemonClient;
use crate::config::{AppConfig, DaemonInfo};
use crate::secret::SecretMetadata;
use crate::store::{Vault, VaultStats};
use crate::token::{default_permissions, ClientToken, ClientTokenStore, Permission, TokenMetadata};
use anyhow::{Context, Result};
use axum::{
    extract::{Path, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{signal, sync::RwLock};
use tracing::{error, info};

#[derive(Clone)]
pub struct ServerState {
    pub vault: Vault,
    pub auth_token: Arc<RwLock<String>>,
    pub external_token: Option<String>,
    pub client_tokens: Arc<RwLock<ClientTokenStore>>,
    pub audit: AuditLog,
    pub config: AppConfig,
    pub started_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub pid: u32,
    pub version: String,
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_url: Option<String>,
    pub started_at: DateTime<Utc>,
    pub uptime_seconds: i64,
    pub stats: VaultStats,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespacesResponse {
    pub namespaces: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsListResponse {
    pub namespace: String,
    pub count: usize,
    pub secrets: Vec<SecretMetadata>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretDetailResponse {
    pub name: String,
    pub namespace: String,
    pub value: String,
    pub metadata: SecretMetadata,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetSecretRequest {
    pub value: String,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub ttl_seconds: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteSecretResponse {
    pub deleted: bool,
    pub name: String,
    pub namespace: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteNamespaceResponse {
    pub namespace: String,
    pub deleted_count: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportNamespaceResponse {
    pub namespace: String,
    pub secrets: HashMap<String, String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    pub description: Option<String>,
    pub ttl_seconds: Option<u64>,
    #[serde(default)]
    pub namespaces: Vec<String>,
    #[serde(default = "default_permissions")]
    pub permissions: Vec<Permission>,
    #[serde(default)]
    pub keys: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenListResponse {
    pub tokens: Vec<TokenMetadata>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeTokenResponse {
    pub revoked: bool,
    pub name: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewRequest {
    pub ttl_seconds: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectRequest {
    pub keys: Option<Vec<String>>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct RotateTokenResponse {
    pub token: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResponse {
    pub events: Vec<AuditEvent>,
}
#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
}
type ApiError = (StatusCode, Json<ErrorResponse>);
type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Clone)]
struct Principal {
    name: String,
    token: Option<ClientToken>,
}
impl Principal {
    fn allows(&self, permission: Permission, namespace: Option<&str>, key: Option<&str>) -> bool {
        self.token
            .as_ref()
            .is_none_or(|t| t.allows(permission, namespace, key))
    }
    fn namespace_visible(&self, ns: &str) -> bool {
        self.token
            .as_ref()
            .is_none_or(|t| t.namespaces.is_empty() || t.namespaces.iter().any(|n| n == ns))
    }
    fn key_visible(&self, key: &str) -> bool {
        self.token
            .as_ref()
            .is_none_or(|t| t.keys.is_empty() || t.keys.iter().any(|k| k == key))
    }
}
fn api_error(status: StatusCode, message: impl Into<String>) -> ApiError {
    (
        status,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
}
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-auth-token").and_then(|v| v.to_str().ok()))
}
async fn authorize(
    state: &ServerState,
    headers: &HeaderMap,
    operation: &str,
    permission: Option<Permission>,
    namespace: Option<&str>,
    key: Option<&str>,
) -> ApiResult<Principal> {
    let principal = if let Some(value) = bearer(headers) {
        if value == *state.auth_token.read().await {
            Some(Principal {
                name: "master".into(),
                token: None,
            })
        } else if state.external_token.as_deref() == Some(value) {
            Some(Principal {
                name: "external-owner".into(),
                token: None,
            })
        } else {
            state
                .client_tokens
                .read()
                .await
                .find(value)
                .map(|token| Principal {
                    name: token.name.clone(),
                    token: Some(token),
                })
        }
    } else {
        None
    };
    let Some(principal) = principal else {
        state
            .audit
            .record("unauthenticated", operation, namespace, key, "denied")
            .map_err(|_| {
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Audit storage unavailable",
                )
            })?;
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "Invalid or expired authentication token",
        ));
    };
    if permission.is_some_and(|p| !principal.allows(p, namespace, key)) {
        state
            .audit
            .record(&principal.name, operation, namespace, key, "denied")
            .map_err(|_| {
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Audit storage unavailable",
                )
            })?;
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "Token does not permit this operation, namespace, or key",
        ));
    }
    state
        .audit
        .record(&principal.name, operation, namespace, key, "allowed")
        .map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Audit storage unavailable",
            )
        })?;
    Ok(principal)
}
fn record_result(
    state: &ServerState,
    principal: &Principal,
    operation: &str,
    ns: Option<&str>,
    key: Option<&str>,
    success: bool,
) {
    if state
        .audit
        .record(
            &principal.name,
            operation,
            ns,
            key,
            if success { "succeeded" } else { "failed" },
        )
        .is_err()
    {
        error!("Failed to persist operation audit result");
    }
}

pub fn create_router(state: ServerState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/v1/status", get(status_handler))
        .route("/v1/namespaces", get(list_namespaces_handler))
        .route(
            "/v1/namespaces/:namespace",
            delete(delete_namespace_handler),
        )
        .route("/v1/secrets/:namespace", get(list_secrets_handler))
        .route(
            "/v1/secrets/:namespace/:key",
            get(get_secret_handler)
                .post(set_secret_handler)
                .delete(delete_secret_handler),
        )
        .route(
            "/v1/secrets/:namespace/:key/renew",
            post(renew_secret_handler),
        )
        .route("/v1/export/:namespace", get(export_namespace_handler))
        .route("/v1/inject/:namespace", post(inject_handler))
        .route(
            "/v1/tokens",
            get(list_tokens_handler).post(create_token_handler),
        )
        .route("/v1/tokens/:name", delete(revoke_token_handler))
        .route("/v1/tokens/:name/renew", post(renew_token_handler))
        .route("/v1/token/rotate", post(rotate_token_handler))
        .route("/v1/audit", get(audit_handler))
        .route("/mcp", post(mcp_post_handler).get(mcp_get_handler))
        .route("/v1/mcp", post(mcp_post_handler).get(mcp_get_handler))
        .with_state(Arc::new(state))
}
pub fn is_external_request(headers: &HeaderMap) -> bool {
    [
        "cf-connecting-ip",
        "cf-ray",
        "cf-visitor",
        "x-forwarded-for",
    ]
    .iter()
    .any(|h| headers.contains_key(*h))
        || headers
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|host| {
                let domain = host.split(':').next().unwrap_or(host).trim();
                !["127.0.0.1", "localhost", "", "[", "::1"].contains(&domain)
            })
}
async fn health_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> ApiResult<Json<HealthResponse>> {
    if is_external_request(&headers) {
        authorize(&state, &headers, "health", None, None, None).await?;
    }
    Ok(Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    }))
}
async fn status_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> ApiResult<Json<StatusResponse>> {
    let principal = authorize(&state, &headers, "status", None, None, None).await?;
    let mut stats = state.vault.stats();
    if principal.token.is_some() {
        let namespaces = state
            .vault
            .list_namespaces()
            .into_iter()
            .filter(|ns| principal.namespace_visible(ns))
            .collect::<Vec<_>>();
        stats.namespaces_count = namespaces.len();
        stats.active_secrets_count = namespaces
            .iter()
            .map(|ns| {
                state
                    .vault
                    .list_secrets(ns)
                    .iter()
                    .filter(|s| principal.key_visible(&s.name))
                    .count()
            })
            .sum();
        stats.vault_path = None;
    }
    Ok(Json(StatusResponse {
        pid: std::process::id(),
        version: env!("CARGO_PKG_VERSION").into(),
        host: state.config.host.clone(),
        port: state.config.port,
        tunnel_url: state.config.read_tunnel_url(),
        started_at: state.started_at,
        uptime_seconds: (Utc::now() - state.started_at).num_seconds(),
        stats,
    }))
}
async fn list_namespaces_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> ApiResult<Json<NamespacesResponse>> {
    let principal = authorize(
        &state,
        &headers,
        "list_namespaces",
        Some(Permission::Read),
        None,
        None,
    )
    .await?;
    let namespaces = state
        .vault
        .list_namespaces()
        .into_iter()
        .filter(|ns| principal.namespace_visible(ns))
        .collect();
    Ok(Json(NamespacesResponse { namespaces }))
}
async fn delete_namespace_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(ns): Path<String>,
) -> ApiResult<Json<DeleteNamespaceResponse>> {
    let principal = authorize(
        &state,
        &headers,
        "delete_namespace",
        Some(Permission::Write),
        Some(&ns),
        None,
    )
    .await?;
    if principal.token.as_ref().is_some_and(|t| !t.keys.is_empty()) {
        state
            .audit
            .record(
                &principal.name,
                "delete_namespace",
                Some(&ns),
                None,
                "denied",
            )
            .map_err(|_| {
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Audit storage unavailable",
                )
            })?;
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "Key-restricted tokens cannot delete namespaces",
        ));
    }
    let result = state.vault.delete_namespace(&ns);
    record_result(
        &state,
        &principal,
        "delete_namespace",
        Some(&ns),
        None,
        result.is_ok(),
    );
    Ok(Json(DeleteNamespaceResponse {
        namespace: ns,
        deleted_count: result
            .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Vault update failed"))?,
    }))
}
async fn list_secrets_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(ns): Path<String>,
) -> ApiResult<Json<SecretsListResponse>> {
    let principal = authorize(
        &state,
        &headers,
        "list_secrets",
        Some(Permission::Read),
        Some(&ns),
        None,
    )
    .await?;
    let secrets = state
        .vault
        .list_secrets(&ns)
        .into_iter()
        .filter(|s| principal.key_visible(&s.name))
        .collect::<Vec<_>>();
    Ok(Json(SecretsListResponse {
        namespace: ns,
        count: secrets.len(),
        secrets,
    }))
}
async fn get_secret_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path((ns, key)): Path<(String, String)>,
) -> ApiResult<Json<SecretDetailResponse>> {
    let principal = authorize(
        &state,
        &headers,
        "get_secret",
        Some(Permission::Read),
        Some(&ns),
        Some(&key),
    )
    .await?;
    let entry = state.vault.get(&ns, &key);
    record_result(
        &state,
        &principal,
        "get_secret",
        Some(&ns),
        Some(&key),
        entry.is_some(),
    );
    let entry =
        entry.ok_or_else(|| api_error(StatusCode::NOT_FOUND, "Secret not found or expired"))?;
    Ok(Json(SecretDetailResponse {
        name: key,
        namespace: ns,
        value: entry.value.expose_secret().into(),
        metadata: entry.metadata,
    }))
}
async fn set_secret_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path((ns, key)): Path<(String, String)>,
    Json(payload): Json<SetSecretRequest>,
) -> ApiResult<(StatusCode, Json<SecretMetadata>)> {
    let principal = authorize(
        &state,
        &headers,
        "set_secret",
        Some(Permission::Write),
        Some(&ns),
        Some(&key),
    )
    .await?;
    if payload.value.trim().is_empty() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Secret value cannot be empty",
        ));
    }
    if let Some(ttl) = payload.ttl_seconds {
        crate::lease::expires_after(ttl)
            .map_err(|e| api_error(StatusCode::BAD_REQUEST, e.to_string()))?;
    }
    let result = state.vault.set(
        &ns,
        &key,
        &payload.value,
        payload.description,
        payload.tags,
        payload.ttl_seconds,
    );
    record_result(
        &state,
        &principal,
        "set_secret",
        Some(&ns),
        Some(&key),
        result.is_ok(),
    );
    Ok((
        StatusCode::CREATED,
        Json(
            result
                .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Vault update failed"))?,
        ),
    ))
}
async fn delete_secret_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path((ns, key)): Path<(String, String)>,
) -> ApiResult<Json<DeleteSecretResponse>> {
    let principal = authorize(
        &state,
        &headers,
        "delete_secret",
        Some(Permission::Write),
        Some(&ns),
        Some(&key),
    )
    .await?;
    let result = state.vault.delete(&ns, &key);
    record_result(
        &state,
        &principal,
        "delete_secret",
        Some(&ns),
        Some(&key),
        result.is_ok(),
    );
    Ok(Json(DeleteSecretResponse {
        deleted: result
            .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Vault update failed"))?,
        name: key,
        namespace: ns,
    }))
}
async fn renew_secret_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path((ns, key)): Path<(String, String)>,
    Json(request): Json<RenewRequest>,
) -> ApiResult<Json<SecretMetadata>> {
    let principal = authorize(
        &state,
        &headers,
        "renew_secret",
        Some(Permission::Write),
        Some(&ns),
        Some(&key),
    )
    .await?;
    let result = state.vault.renew(&ns, &key, request.ttl_seconds);
    record_result(
        &state,
        &principal,
        "renew_secret",
        Some(&ns),
        Some(&key),
        result.is_ok(),
    );
    Ok(Json(result.map_err(|e| {
        api_error(StatusCode::BAD_REQUEST, e.to_string())
    })?))
}
async fn export_namespace_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(ns): Path<String>,
) -> ApiResult<Json<ExportNamespaceResponse>> {
    let principal = authorize(
        &state,
        &headers,
        "export",
        Some(Permission::Read),
        Some(&ns),
        None,
    )
    .await?;
    let mut secrets = state.vault.export_namespace(&ns);
    secrets.retain(|key, _| principal.key_visible(key));
    Ok(Json(ExportNamespaceResponse {
        namespace: ns,
        secrets,
    }))
}
async fn inject_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(ns): Path<String>,
    Json(request): Json<InjectRequest>,
) -> ApiResult<Json<ExportNamespaceResponse>> {
    let principal = authorize(
        &state,
        &headers,
        "run",
        Some(Permission::Run),
        Some(&ns),
        None,
    )
    .await?;
    if let Some(keys) = &request.keys {
        if keys.is_empty() {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "Select at least one key",
            ));
        }
        for key in keys {
            if !principal.key_visible(key) {
                state
                    .audit
                    .record(&principal.name, "run", Some(&ns), Some(key), "denied")
                    .map_err(|_| {
                        api_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Audit storage unavailable",
                        )
                    })?;
                return Err(api_error(
                    StatusCode::FORBIDDEN,
                    "Requested key is outside token scope",
                ));
            }
        }
    }
    let mut secrets = state.vault.export_namespace(&ns);
    secrets.retain(|key, _| {
        principal.key_visible(key) && request.keys.as_ref().is_none_or(|keys| keys.contains(key))
    });
    if request
        .keys
        .as_ref()
        .is_some_and(|keys| keys.iter().any(|key| !secrets.contains_key(key)))
    {
        record_result(&state, &principal, "run", Some(&ns), None, false);
        return Err(api_error(
            StatusCode::NOT_FOUND,
            "A requested secret is missing or expired",
        ));
    }
    for key in secrets.keys() {
        record_result(&state, &principal, "inject", Some(&ns), Some(key), true);
    }
    Ok(Json(ExportNamespaceResponse {
        namespace: ns,
        secrets,
    }))
}
async fn list_tokens_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> ApiResult<Json<TokenListResponse>> {
    authorize(
        &state,
        &headers,
        "list_tokens",
        Some(Permission::Admin),
        None,
        None,
    )
    .await?;
    Ok(Json(TokenListResponse {
        tokens: state
            .client_tokens
            .read()
            .await
            .list()
            .iter()
            .map(ClientToken::metadata)
            .collect(),
    }))
}
async fn create_token_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Json(payload): Json<CreateTokenRequest>,
) -> ApiResult<(StatusCode, Json<ClientToken>)> {
    let principal = authorize(
        &state,
        &headers,
        "create_token",
        Some(Permission::Admin),
        None,
        None,
    )
    .await?;
    let result = state.client_tokens.write().await.add_with_policy(
        &payload.name,
        payload.description,
        payload.ttl_seconds,
        payload.namespaces,
        payload.permissions,
        payload.keys,
    );
    record_result(
        &state,
        &principal,
        "create_token",
        None,
        Some(&payload.name),
        result.is_ok(),
    );
    Ok((
        StatusCode::CREATED,
        Json(result.map_err(|e| api_error(StatusCode::BAD_REQUEST, e.to_string()))?),
    ))
}
async fn revoke_token_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult<Json<RevokeTokenResponse>> {
    let principal = authorize(
        &state,
        &headers,
        "revoke_token",
        Some(Permission::Admin),
        None,
        None,
    )
    .await?;
    let result = state.client_tokens.write().await.revoke(&name);
    record_result(
        &state,
        &principal,
        "revoke_token",
        None,
        Some(&name),
        result.is_ok(),
    );
    Ok(Json(RevokeTokenResponse {
        name,
        revoked: result
            .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Token update failed"))?,
    }))
}
async fn renew_token_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(request): Json<RenewRequest>,
) -> ApiResult<Json<TokenMetadata>> {
    let principal = authorize(
        &state,
        &headers,
        "renew_token",
        Some(Permission::Admin),
        None,
        None,
    )
    .await?;
    let result = state
        .client_tokens
        .write()
        .await
        .renew(&name, request.ttl_seconds);
    record_result(
        &state,
        &principal,
        "renew_token",
        None,
        Some(&name),
        result.is_ok(),
    );
    Ok(Json(result.map_err(|e| {
        api_error(StatusCode::BAD_REQUEST, e.to_string())
    })?))
}
async fn rotate_token_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> ApiResult<Json<RotateTokenResponse>> {
    let principal = authorize(
        &state,
        &headers,
        "rotate_master",
        Some(Permission::Admin),
        None,
        None,
    )
    .await?;
    if state.config.custom_token.is_some() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Externally supplied master tokens must be rotated by their issuer",
        ));
    }
    let mut current = state.auth_token.write().await;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    state.config.save_auth_token(&token).map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not persist rotated token",
        )
    })?;
    *current = token.clone();
    record_result(&state, &principal, "rotate_master", None, None, true);
    Ok(Json(RotateTokenResponse { token }))
}
async fn audit_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<AuditResponse>> {
    authorize(
        &state,
        &headers,
        "audit",
        Some(Permission::Admin),
        None,
        None,
    )
    .await?;
    Ok(Json(AuditResponse {
        events: state.audit.recent(query.limit.unwrap_or(50)),
    }))
}
async fn mcp_get_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    if is_external_request(&headers) {
        authorize(&state, &headers, "mcp_discovery", None, None, None).await?;
    }
    Ok(Json(
        serde_json::json!({ "status": "ok", "service": "agentsec-mcp", "transport": "streamable-http", "protocolVersion": "2024-11-05", "tools": crate::mcp::get_tool_definitions() }),
    ))
}
async fn mcp_post_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Json(mut payload): Json<Value>,
) -> ApiResult<Json<Value>> {
    let principal = authorize(&state, &headers, "mcp", None, None, None).await?;
    if payload.get("method").and_then(Value::as_str) == Some("tools/call") {
        if let Some(token) = &principal.token {
            if token.namespaces.len() == 1
                && payload.pointer("/params/arguments/namespace").is_none()
            {
                if let Some(params) = payload.get_mut("params").and_then(Value::as_object_mut) {
                    let arguments = params
                        .entry("arguments")
                        .or_insert_with(|| serde_json::json!({}));
                    if let Some(arguments) = arguments.as_object_mut() {
                        arguments.insert(
                            "namespace".into(),
                            Value::String(token.namespaces[0].clone()),
                        );
                    }
                }
            }
        }
    }
    let host = match state.config.host.as_str() {
        "0.0.0.0" => "127.0.0.1",
        "::" => "::1",
        other => other,
    };
    let address: SocketAddr = (
        host.parse::<std::net::IpAddr>()
            .map_err(|_| api_error(StatusCode::INTERNAL_SERVER_ERROR, "Invalid daemon address"))?,
        state.config.port,
    )
        .into();
    let client = DaemonClient::with_explicit_target(
        format!("http://{}", address),
        bearer(&headers).unwrap().into(),
    )
    .map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not initialize MCP client",
        )
    })?;
    Ok(Json(crate::mcp::handle_mcp_request(&client, payload).await))
}
struct CleanupTask(tokio::task::JoinHandle<()>);
impl Drop for CleanupTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub async fn start_server(mut config: AppConfig, vault: Vault, auth_token: String) -> Result<()> {
    let started_at = Utc::now();
    let address = SocketAddr::new(
        config.host.parse().context("Invalid daemon bind address")?,
        config.port,
    );
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .context("Failed to bind daemon listener")?;
    config.port = listener.local_addr()?.port();
    let external_token = std::env::var("AGENTSEC_EXTERNAL_TOKEN")
        .or_else(|_| std::env::var("TUNNEL_AUTH_TOKEN"))
        .ok()
        .filter(|s| !s.trim().is_empty());
    let client_tokens = Arc::new(RwLock::new(config.load_client_tokens()?));
    let audit = AuditLog::new(if vault.stats().is_ephemeral {
        None
    } else {
        Some(config.data_dir.join("audit.jsonl"))
    });
    let state = ServerState {
        vault: vault.clone(),
        auth_token: Arc::new(RwLock::new(auth_token)),
        external_token,
        client_tokens: client_tokens.clone(),
        audit: audit.clone(),
        config: config.clone(),
        started_at,
    };
    let cleanup = CleanupTask(tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            match vault.purge_expired() {
                Ok(count) if count > 0 => {
                    let _ = audit.record("daemon", "expire_secrets", None, None, "succeeded");
                }
                Err(_) => error!("Expired-secret cleanup failed"),
                _ => {}
            }
            let mut tokens = client_tokens.write().await;
            if tokens.clean_expired() > 0 {
                if tokens.save().is_err() {
                    error!("Expired-token cleanup failed");
                }
                let _ = audit.record("daemon", "expire_tokens", None, None, "succeeded");
            }
        }
    }));
    config.write_daemon_info(&DaemonInfo {
        pid: std::process::id(),
        port: config.port,
        host: config.host.clone(),
        socket_path: config.socket_path.clone(),
        started_at,
        tunnel_url: config.read_tunnel_url(),
    })?;
    info!("agentsec daemon started (PID: {})", std::process::id());
    let shutdown = async {
        let ctrl_c = async {
            signal::ctrl_c()
                .await
                .expect("failed to install Ctrl+C handler");
        };
        #[cfg(unix)]
        let terminate = async {
            signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("failed to install signal handler")
                .recv()
                .await;
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();
        tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
    };
    let result = axum::serve(listener, create_router(state))
        .with_graceful_shutdown(shutdown)
        .await;
    drop(cleanup);
    config.remove_daemon_info();
    result.context("Daemon server failed")
}
