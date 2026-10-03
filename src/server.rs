use crate::config::{AppConfig, DaemonInfo};
use crate::secret::SecretMetadata;
use crate::store::{Vault, VaultStats};
use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};

#[derive(Clone)]
pub struct ServerState {
    pub vault: Vault,
    pub auth_token: String,
    pub started_at: DateTime<Utc>,
    pub port: u16,
    pub host: String,
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
pub struct ErrorResponse {
    pub error: String,
}

pub fn create_router(state: ServerState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/v1/status", get(status_handler))
        .route("/v1/namespaces", get(list_namespaces_handler))
        .route("/v1/namespaces/:namespace", delete(delete_namespace_handler))
        .route(
            "/v1/secrets/:namespace",
            get(list_secrets_handler),
        )
        .route(
            "/v1/secrets/:namespace/:key",
            get(get_secret_handler)
                .post(set_secret_handler)
                .delete(delete_secret_handler),
        )
        .route("/v1/export/:namespace", get(export_namespace_handler))
        .with_state(Arc::new(state))
}

// Authentication helper
fn verify_auth(headers: &HeaderMap, expected_token: &str) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let auth_header = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok());

    match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..];
            if token == expected_token {
                Ok(())
            } else {
                Err((
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "Invalid authentication token".to_string(),
                    }),
                ))
            }
        }
        _ => Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Missing or malformed Authorization header (Bearer <token> required)".to_string(),
            }),
        )),
    }
}

// Handlers

async fn health_handler() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn status_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    verify_auth(&headers, &state.auth_token)?;

    let now = Utc::now();
    let uptime = (now - state.started_at).num_seconds();

    Ok(Json(StatusResponse {
        pid: std::process::id(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        host: state.host.clone(),
        port: state.port,
        started_at: state.started_at,
        uptime_seconds: uptime,
        stats: state.vault.stats(),
    }))
}

async fn list_namespaces_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    verify_auth(&headers, &state.auth_token)?;

    let namespaces = state.vault.list_namespaces();
    Ok(Json(NamespacesResponse { namespaces }))
}

async fn delete_namespace_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    verify_auth(&headers, &state.auth_token)?;

    match state.vault.delete_namespace(&namespace) {
        Ok(count) => Ok(Json(DeleteNamespaceResponse {
            namespace,
            deleted_count: count,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to delete namespace: {}", e),
            }),
        )),
    }
}

async fn list_secrets_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    verify_auth(&headers, &state.auth_token)?;

    let secrets = state.vault.list_secrets(&namespace);
    let count = secrets.len();
    Ok(Json(SecretsListResponse {
        namespace,
        count,
        secrets,
    }))
}

async fn get_secret_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path((namespace, key)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    verify_auth(&headers, &state.auth_token)?;

    match state.vault.get(&namespace, &key) {
        Some(entry) => Ok(Json(SecretDetailResponse {
            name: entry.metadata.name.clone(),
            namespace: entry.metadata.namespace.clone(),
            value: entry.value.expose_secret().to_string(),
            metadata: entry.metadata,
        })),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Secret '{}' not found in namespace '{}'", key, namespace),
            }),
        )),
    }
}

async fn set_secret_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path((namespace, key)): Path<(String, String)>,
    Json(payload): Json<SetSecretRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    verify_auth(&headers, &state.auth_token)?;

    if payload.value.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Secret value cannot be empty".to_string(),
            }),
        ));
    }

    match state.vault.set(
        &namespace,
        &key,
        &payload.value,
        payload.description,
        payload.tags,
        payload.ttl_seconds,
    ) {
        Ok(metadata) => Ok((StatusCode::CREATED, Json(metadata))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to set secret: {}", e),
            }),
        )),
    }
}

async fn delete_secret_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path((namespace, key)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    verify_auth(&headers, &state.auth_token)?;

    match state.vault.delete(&namespace, &key) {
        Ok(deleted) => Ok(Json(DeleteSecretResponse {
            deleted,
            name: key,
            namespace,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to delete secret: {}", e),
            }),
        )),
    }
}

async fn export_namespace_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Path(namespace): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    verify_auth(&headers, &state.auth_token)?;

    let secrets = state.vault.export_namespace(&namespace);
    Ok(Json(ExportNamespaceResponse {
        namespace,
        secrets,
    }))
}

/// Run the background HTTP daemon server with graceful shutdown handling
pub async fn start_server(config: AppConfig, vault: Vault, auth_token: String) -> Result<()> {
    let started_at = Utc::now();
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .with_context(|| format!("Invalid host/port: {}:{}", config.host, config.port))?;

    let state = ServerState {
        vault,
        auth_token,
        started_at,
        port: config.port,
        host: config.host.clone(),
    };

    let app = create_router(state);

    let tcp_listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind TCP listener to {}", addr))?;

    let daemon_info = DaemonInfo {
        pid: std::process::id(),
        port: config.port,
        host: config.host.clone(),
        socket_path: config.socket_path.clone(),
        started_at,
    };

    config.write_daemon_info(&daemon_info)?;

    info!(
        "🚀 agentsec daemon started on http://{} (PID: {})",
        addr, daemon_info.pid
    );

    let shutdown_signal = async {
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

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }
    };

    // Serve TCP with graceful shutdown
    if let Err(e) = axum::serve(tcp_listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await
    {
        error!("Server error: {}", e);
    }

    info!("🛑 Shutting down agentsec daemon...");
    config.remove_daemon_info();
    info!("👋 Daemon stopped cleanly.");

    Ok(())
}
