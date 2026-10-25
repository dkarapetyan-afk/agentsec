use crate::audit::{AuditEvent, AuditLog};
use crate::config::AppConfig;
use crate::crypto::get_or_create_master_key;
use crate::secret::SecretMetadata;
use crate::server::{HealthResponse, SecretDetailResponse, StatusResponse};
use crate::store::Vault;
use crate::token::{ClientToken, ClientTokenStore, Permission, TokenMetadata};
use anyhow::{anyhow, Result};
use chrono::Utc;
use std::collections::HashMap;

#[derive(Clone)]
pub struct DirectClient {
    vault: Vault,
    config: AppConfig,
    audit: AuditLog,
    started_at: chrono::DateTime<Utc>,
}

impl DirectClient {
    pub fn new(config: &AppConfig) -> Result<Self> {
        let master_key = get_or_create_master_key(&config.master_key_path)?;
        let vault = Vault::new(master_key, Some(config.vault_path.clone()))?;
        let audit = AuditLog::new(Some(config.audit_log_path.clone()));

        Ok(Self {
            vault,
            config: config.clone(),
            audit,
            started_at: Utc::now(),
        })
    }

    pub fn with_ephemeral_vault(config: &AppConfig) -> Result<Self> {
        let master_key = crate::crypto::MasterKey::generate();
        let vault = Vault::new(master_key, None)?;
        let audit = AuditLog::new(None);

        Ok(Self {
            vault,
            config: config.clone(),
            audit,
            started_at: Utc::now(),
        })
    }

    pub fn with_vault_and_audit(vault: Vault, config: AppConfig, audit: AuditLog) -> Self {
        Self {
            vault,
            config,
            audit,
            started_at: Utc::now(),
        }
    }

    pub async fn health(&self) -> Result<HealthResponse> {
        Ok(HealthResponse {
            status: "ok".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        })
    }

    pub async fn status(&self) -> Result<StatusResponse> {
        let stats = self.vault.stats();
        Ok(StatusResponse {
            pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").into(),
            host: "direct (daemonless)".into(),
            port: 0,
            tunnel_url: None,
            started_at: self.started_at,
            uptime_seconds: 0,
            stats,
        })
    }

    pub async fn list_namespaces(&self) -> Result<Vec<String>> {
        let namespaces = self.vault.list_namespaces();
        let _ = self
            .audit
            .record("cli-direct", "list_namespaces", None, None, "success");
        Ok(namespaces)
    }

    pub async fn list_secrets(&self, namespace: &str) -> Result<Vec<SecretMetadata>> {
        let secrets = self.vault.list_secrets(namespace);
        let _ = self.audit.record(
            "cli-direct",
            "list_secrets",
            Some(namespace),
            None,
            "success",
        );
        Ok(secrets)
    }

    pub async fn get_secret(&self, namespace: &str, key: &str) -> Result<SecretDetailResponse> {
        let entry = self.vault.get(namespace, key).ok_or_else(|| {
            let _ = self.audit.record(
                "cli-direct",
                "get_secret",
                Some(namespace),
                Some(key),
                "not_found",
            );
            anyhow!("Secret '{}' not found in namespace '{}'", key, namespace)
        })?;

        let _ = self.audit.record(
            "cli-direct",
            "get_secret",
            Some(namespace),
            Some(key),
            "success",
        );
        Ok(SecretDetailResponse {
            name: entry.metadata.name.clone(),
            namespace: entry.metadata.namespace.clone(),
            value: entry.value.expose_secret().to_string(),
            metadata: entry.metadata,
        })
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
        let meta = self
            .vault
            .set(namespace, key, value, description, tags, ttl_seconds)?;
        let _ = self.audit.record(
            "cli-direct",
            "set_secret",
            Some(namespace),
            Some(key),
            "success",
        );
        Ok(meta)
    }

    pub async fn delete_secret(&self, namespace: &str, key: &str) -> Result<bool> {
        let deleted = self.vault.delete(namespace, key)?;
        let outcome = if deleted { "success" } else { "not_found" };
        let _ = self.audit.record(
            "cli-direct",
            "delete_secret",
            Some(namespace),
            Some(key),
            outcome,
        );
        Ok(deleted)
    }

    pub async fn delete_namespace(&self, namespace: &str) -> Result<usize> {
        let count = self.vault.delete_namespace(namespace)?;
        let _ = self.audit.record(
            "cli-direct",
            "delete_namespace",
            Some(namespace),
            None,
            "success",
        );
        Ok(count)
    }

    pub async fn export_namespace(&self, namespace: &str) -> Result<HashMap<String, String>> {
        let secrets = self.vault.export_namespace(namespace);
        let _ = self.audit.record(
            "cli-direct",
            "export_namespace",
            Some(namespace),
            None,
            "success",
        );
        Ok(secrets)
    }

    pub async fn inject_secrets(
        &self,
        namespace: &str,
        only: Option<Vec<String>>,
    ) -> Result<HashMap<String, String>> {
        let mut all = self.vault.export_namespace(namespace);
        if let Some(keys) = only {
            all.retain(|k, _| keys.contains(k));
        }
        let _ = self.audit.record(
            "cli-direct",
            "inject_secrets",
            Some(namespace),
            None,
            "success",
        );
        Ok(all)
    }

    pub async fn renew_secret(
        &self,
        namespace: &str,
        key: &str,
        ttl_seconds: u64,
    ) -> Result<SecretMetadata> {
        let meta = self.vault.renew(namespace, key, ttl_seconds)?;
        let _ = self.audit.record(
            "cli-direct",
            "renew_secret",
            Some(namespace),
            Some(key),
            "success",
        );
        Ok(meta)
    }

    pub async fn audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>> {
        let events = self.audit.recent(limit);
        Ok(events)
    }

    pub async fn list_client_tokens(&self) -> Result<Vec<TokenMetadata>> {
        let store = ClientTokenStore::load_or_create(self.config.client_tokens_path.clone())?;
        Ok(store.list().iter().map(|t| t.metadata()).collect())
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
        let mut store = ClientTokenStore::load_or_create(self.config.client_tokens_path.clone())?;
        let token = store.add_with_policy(
            name,
            description,
            ttl_seconds,
            namespaces,
            permissions,
            keys,
        )?;
        let _ = self.audit.record(
            "cli-direct",
            "create_client_token",
            None,
            Some(name),
            "success",
        );
        Ok(token)
    }

    pub async fn revoke_client_token(&self, name: &str) -> Result<bool> {
        let mut store = ClientTokenStore::load_or_create(self.config.client_tokens_path.clone())?;
        let revoked = store.revoke(name)?;
        let outcome = if revoked { "success" } else { "not_found" };
        let _ = self.audit.record(
            "cli-direct",
            "revoke_client_token",
            None,
            Some(name),
            outcome,
        );
        Ok(revoked)
    }

    pub async fn renew_client_token(&self, name: &str, seconds: u64) -> Result<TokenMetadata> {
        let mut store = ClientTokenStore::load_or_create(self.config.client_tokens_path.clone())?;
        let meta = store.renew(name, seconds)?;
        let _ = self.audit.record(
            "cli-direct",
            "renew_client_token",
            None,
            Some(name),
            "success",
        );
        Ok(meta)
    }

    pub async fn rotate_master_token(&self) -> Result<String> {
        let token = self.config.rotate_auth_token()?;
        let _ = self
            .audit
            .record("cli-direct", "rotate_master_token", None, None, "success");
        Ok(token)
    }

    pub async fn mcp_request(&self, request: serde_json::Value) -> Result<serde_json::Value> {
        let backend = crate::backend::ClientBackend::from(self.clone());
        Ok(crate::mcp::handle_mcp_request(&backend, request).await)
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    pub fn config(&self) -> &AppConfig {
        &self.config
    }
}
