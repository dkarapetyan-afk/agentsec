use crate::audit::AuditEvent;
use crate::client::DaemonClient;
use crate::config::AppConfig;
use crate::direct::DirectClient;
use crate::secret::SecretMetadata;
use crate::server::{HealthResponse, SecretDetailResponse, StatusResponse};
use crate::token::{ClientToken, Permission, TokenMetadata};
use anyhow::Result;
use std::collections::HashMap;

#[derive(Clone)]
pub enum ClientBackend {
    Daemon(DaemonClient),
    Direct(Box<DirectClient>),
}

impl From<DaemonClient> for ClientBackend {
    fn from(c: DaemonClient) -> Self {
        Self::Daemon(c)
    }
}

impl From<&DaemonClient> for ClientBackend {
    fn from(c: &DaemonClient) -> Self {
        Self::Daemon(c.clone())
    }
}

impl From<DirectClient> for ClientBackend {
    fn from(c: DirectClient) -> Self {
        Self::Direct(Box::new(c))
    }
}

impl From<&DirectClient> for ClientBackend {
    fn from(c: &DirectClient) -> Self {
        Self::Direct(Box::new(c.clone()))
    }
}

impl ClientBackend {
    pub async fn connect(
        config: &AppConfig,
        daemonless: bool,
        require_daemon: bool,
    ) -> Result<Self> {
        let env_daemonless = std::env::var("AGENTSEC_DAEMONLESS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if daemonless || env_daemonless {
            return Ok(Self::Direct(Box::new(DirectClient::connect(config).await?)));
        }

        // If an explicit custom/remote URL is set, always use DaemonClient
        if config.custom_url.is_some() {
            return Ok(Self::Daemon(DaemonClient::new(config)?));
        }

        // Try connecting to the local daemon
        match DaemonClient::new(config) {
            Ok(client) => {
                // Check if the local daemon is responsive
                if client.health().await.is_ok() {
                    Ok(Self::Daemon(client))
                } else if require_daemon {
                    Err(anyhow::anyhow!(
                        "Unable to connect to agentsec daemon at http://{}:{}.\n\
                        --require-daemon was specified. Start the daemon with:\n  agentsec daemon",
                        config.host,
                        config.port
                    ))
                } else {
                    // Graceful auto-fallback to direct local vault mode
                    Ok(Self::Direct(Box::new(DirectClient::connect(config).await?)))
                }
            }
            Err(e) => {
                if require_daemon {
                    Err(e)
                } else {
                    Ok(Self::Direct(Box::new(DirectClient::connect(config).await?)))
                }
            }
        }
    }

    pub fn is_daemonless(&self) -> bool {
        matches!(self, Self::Direct(_))
    }

    pub async fn health(&self) -> Result<HealthResponse> {
        match self {
            Self::Daemon(c) => c.health().await,
            Self::Direct(c) => c.health().await,
        }
    }

    pub async fn status(&self) -> Result<StatusResponse> {
        match self {
            Self::Daemon(c) => c.status().await,
            Self::Direct(c) => c.status().await,
        }
    }

    pub async fn list_namespaces(&self) -> Result<Vec<String>> {
        match self {
            Self::Daemon(c) => c.list_namespaces().await,
            Self::Direct(c) => c.list_namespaces().await,
        }
    }

    pub async fn list_secrets(&self, namespace: &str) -> Result<Vec<SecretMetadata>> {
        match self {
            Self::Daemon(c) => c.list_secrets(namespace).await,
            Self::Direct(c) => c.list_secrets(namespace).await,
        }
    }

    pub async fn get_secret(&self, namespace: &str, key: &str) -> Result<SecretDetailResponse> {
        match self {
            Self::Daemon(c) => c.get_secret(namespace, key).await,
            Self::Direct(c) => c.get_secret(namespace, key).await,
        }
    }

    pub async fn set_secret(
        &self,
        namespace: &str,
        key: &str,
        value: &str,
        description: Option<String>,
        tags: Vec<String>,
        ttl_seconds: Option<u64>,
    ) -> Result<SecretMetadata> {
        match self {
            Self::Daemon(c) => {
                c.set_secret(namespace, key, value, description, tags, ttl_seconds)
                    .await
            }
            Self::Direct(c) => {
                c.set_secret(namespace, key, value, description, tags, ttl_seconds)
                    .await
            }
        }
    }

    pub async fn delete_secret(&self, namespace: &str, key: &str) -> Result<bool> {
        match self {
            Self::Daemon(c) => c.delete_secret(namespace, key).await,
            Self::Direct(c) => c.delete_secret(namespace, key).await,
        }
    }

    pub async fn delete_namespace(&self, namespace: &str) -> Result<usize> {
        match self {
            Self::Daemon(c) => c.delete_namespace(namespace).await,
            Self::Direct(c) => c.delete_namespace(namespace).await,
        }
    }

    pub async fn export_namespace(&self, namespace: &str) -> Result<HashMap<String, String>> {
        match self {
            Self::Daemon(c) => c.export_namespace(namespace).await,
            Self::Direct(c) => c.export_namespace(namespace).await,
        }
    }

    pub async fn inject_secrets(
        &self,
        namespace: &str,
        only: Option<Vec<String>>,
    ) -> Result<HashMap<String, String>> {
        match self {
            Self::Daemon(c) => c.inject_secrets(namespace, only).await,
            Self::Direct(c) => c.inject_secrets(namespace, only).await,
        }
    }

    pub async fn renew_secret(
        &self,
        namespace: &str,
        key: &str,
        ttl_seconds: u64,
    ) -> Result<SecretMetadata> {
        match self {
            Self::Daemon(c) => c.renew_secret(namespace, key, ttl_seconds).await,
            Self::Direct(c) => c.renew_secret(namespace, key, ttl_seconds).await,
        }
    }

    pub async fn audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>> {
        match self {
            Self::Daemon(c) => c.audit_events(limit).await,
            Self::Direct(c) => c.audit_events(limit).await,
        }
    }

    pub async fn list_client_tokens(&self) -> Result<Vec<TokenMetadata>> {
        match self {
            Self::Daemon(c) => c.list_client_tokens().await,
            Self::Direct(c) => c.list_client_tokens().await,
        }
    }

    pub async fn create_client_token_with_policy(
        &self,
        name: &str,
        description: Option<String>,
        ttl_seconds: Option<u64>,
        namespaces: Vec<String>,
        permissions: Vec<Permission>,
        keys: Vec<String>,
    ) -> Result<ClientToken> {
        match self {
            Self::Daemon(c) => {
                c.create_client_token_with_policy(
                    name,
                    description,
                    ttl_seconds,
                    namespaces,
                    permissions,
                    keys,
                )
                .await
            }
            Self::Direct(c) => {
                c.create_client_token_with_policy(
                    name,
                    description,
                    ttl_seconds,
                    namespaces,
                    permissions,
                    keys,
                )
                .await
            }
        }
    }

    pub async fn revoke_client_token(&self, name: &str) -> Result<bool> {
        match self {
            Self::Daemon(c) => c.revoke_client_token(name).await,
            Self::Direct(c) => c.revoke_client_token(name).await,
        }
    }

    pub async fn renew_client_token(&self, name: &str, seconds: u64) -> Result<TokenMetadata> {
        match self {
            Self::Daemon(c) => c.renew_client_token(name, seconds).await,
            Self::Direct(c) => c.renew_client_token(name, seconds).await,
        }
    }

    pub async fn rotate_master_token(&self) -> Result<String> {
        match self {
            Self::Daemon(c) => c.rotate_master_token().await,
            Self::Direct(c) => c.rotate_master_token().await,
        }
    }

    pub async fn mcp_request(&self, request: serde_json::Value) -> Result<serde_json::Value> {
        match self {
            Self::Daemon(c) => c.mcp_request(request).await,
            Self::Direct(c) => c.mcp_request(request).await,
        }
    }
}
