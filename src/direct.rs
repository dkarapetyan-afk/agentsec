use crate::audit::{AuditEvent, AuditLog};
use crate::config::AppConfig;
use crate::crypto::get_or_create_master_key;
use crate::secret::SecretMetadata;
use crate::server::{HealthResponse, SecretDetailResponse, StatusResponse};
use crate::store::Vault;
use crate::token::{ClientToken, ClientTokenStore, Permission, TokenMetadata};
use anyhow::{anyhow, Context, Result};
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
    pub async fn new(config: &AppConfig) -> Result<Self> {
        let key_path = config.master_key_path.clone();
        let audit_path = config.audit_log_path.clone();
        let (master_key, audit) = tokio::task::spawn_blocking(move || {
            anyhow::Ok((
                get_or_create_master_key(&key_path)?,
                AuditLog::new(Some(audit_path)),
            ))
        })
        .await
        .context("Vault initialization worker failed")??;
        let vault = Vault::new(master_key, Some(config.vault_path.clone())).await?;
        Ok(Self {
            vault,
            config: config.clone(),
            audit,
            started_at: Utc::now(),
        })
    }

    pub async fn connect(config: &AppConfig) -> Result<Self> {
        Self::new(config).await
    }

    async fn blocking<T: Send + 'static>(
        &self,
        operation: impl FnOnce(Self) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let client = self.clone();
        tokio::task::spawn_blocking(move || operation(client))
            .await
            .context("Local vault worker failed")?
    }

    pub async fn with_ephemeral_vault(config: &AppConfig) -> Result<Self> {
        let master_key = crate::crypto::MasterKey::generate();
        let vault = Vault::new(master_key, None).await?;
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
        let stats = self.vault.try_stats().await?;
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
        let namespaces = self.vault.try_list_namespaces().await?;
        let _ = self
            .audit
            .record_async("cli-direct", "list_namespaces", None, None, "success")
            .await;
        Ok(namespaces)
    }

    pub async fn list_secrets(&self, namespace: &str) -> Result<Vec<SecretMetadata>> {
        let namespace = namespace.to_owned();

        let secrets = self.vault.try_list_secrets(&namespace).await?;
        let _ = self
            .audit
            .record_async(
                "cli-direct",
                "list_secrets",
                Some(&namespace),
                None,
                "success",
            )
            .await;
        Ok(secrets)
    }

    pub async fn get_secret(&self, namespace: &str, key: &str) -> Result<SecretDetailResponse> {
        let namespace = namespace.to_owned();
        let key = key.to_owned();

        let Some(entry) = self.vault.try_get(&namespace, &key).await? else {
            let _ = self
                .audit
                .record_async(
                    "cli-direct",
                    "get_secret",
                    Some(&namespace),
                    Some(&key),
                    "not_found",
                )
                .await;
            return Err(anyhow!(
                "Secret '{}' not found in namespace '{}'",
                key,
                namespace
            ));
        };

        let _ = self
            .audit
            .record_async(
                "cli-direct",
                "get_secret",
                Some(&namespace),
                Some(&key),
                "success",
            )
            .await;
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
        let namespace = namespace.to_owned();
        let key = key.to_owned();
        let value = value.to_owned();

        let meta = self
            .vault
            .set(&namespace, &key, &value, description, tags, ttl_seconds)
            .await?;
        let _ = self
            .audit
            .record_async(
                "cli-direct",
                "set_secret",
                Some(&namespace),
                Some(&key),
                "success",
            )
            .await;
        Ok(meta)
    }

    pub async fn delete_secret(&self, namespace: &str, key: &str) -> Result<bool> {
        let namespace = namespace.to_owned();
        let key = key.to_owned();

        let deleted = self.vault.delete(&namespace, &key).await?;
        let outcome = if deleted { "success" } else { "not_found" };
        let _ = self
            .audit
            .record_async(
                "cli-direct",
                "delete_secret",
                Some(&namespace),
                Some(&key),
                outcome,
            )
            .await;
        Ok(deleted)
    }

    pub async fn delete_namespace(&self, namespace: &str) -> Result<usize> {
        let namespace = namespace.to_owned();

        let count = self.vault.delete_namespace(&namespace).await?;
        let _ = self
            .audit
            .record_async(
                "cli-direct",
                "delete_namespace",
                Some(&namespace),
                None,
                "success",
            )
            .await;
        Ok(count)
    }

    pub async fn export_namespace(&self, namespace: &str) -> Result<HashMap<String, String>> {
        let namespace = namespace.to_owned();

        let secrets = self.vault.try_export_namespace(&namespace).await?;
        let _ = self
            .audit
            .record_async(
                "cli-direct",
                "export_namespace",
                Some(&namespace),
                None,
                "success",
            )
            .await;
        Ok(secrets)
    }

    pub async fn inject_secrets(
        &self,
        namespace: &str,
        only: Option<Vec<String>>,
    ) -> Result<HashMap<String, String>> {
        let namespace = namespace.to_owned();

        let mut all = self.vault.try_export_namespace(&namespace).await?;
        if let Some(keys) = only {
            if keys.is_empty() {
                anyhow::bail!("Select at least one key");
            }
            if keys.iter().any(|key| !all.contains_key(key)) {
                anyhow::bail!("A requested secret is missing or expired");
            }
            all.retain(|key, _| keys.contains(key));
        }
        let _ = self
            .audit
            .record_async(
                "cli-direct",
                "inject_secrets",
                Some(&namespace),
                None,
                "success",
            )
            .await;
        Ok(all)
    }

    pub async fn renew_secret(
        &self,
        namespace: &str,
        key: &str,
        ttl_seconds: u64,
    ) -> Result<SecretMetadata> {
        let namespace = namespace.to_owned();
        let key = key.to_owned();

        let meta = self.vault.renew(&namespace, &key, ttl_seconds).await?;
        let _ = self
            .audit
            .record_async(
                "cli-direct",
                "renew_secret",
                Some(&namespace),
                Some(&key),
                "success",
            )
            .await;
        Ok(meta)
    }

    pub async fn audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>> {
        self.blocking(move |client| {
            let events = client.audit.recent(limit);
            Ok(events)
        })
        .await
    }

    pub async fn list_client_tokens(&self) -> Result<Vec<TokenMetadata>> {
        self.blocking(move |client| {
            let store = ClientTokenStore::load_or_create(client.config.client_tokens_path.clone())?;
            Ok(store.list().iter().map(|t| t.metadata()).collect())
        })
        .await
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
        let name = name.to_owned();
        self.blocking(move |client| {
            let mut store =
                ClientTokenStore::load_or_create(client.config.client_tokens_path.clone())?;
            let token = store.add_with_policy(
                &name,
                description,
                ttl_seconds,
                namespaces,
                permissions,
                keys,
            )?;
            let _ = client.audit.record(
                "cli-direct",
                "create_client_token",
                None,
                Some(&name),
                "success",
            );
            Ok(token)
        })
        .await
    }

    pub async fn revoke_client_token(&self, name: &str) -> Result<bool> {
        let name = name.to_owned();
        self.blocking(move |client| {
            let mut store =
                ClientTokenStore::load_or_create(client.config.client_tokens_path.clone())?;
            let revoked = store.revoke(&name)?;
            let outcome = if revoked { "success" } else { "not_found" };
            let _ = client.audit.record(
                "cli-direct",
                "revoke_client_token",
                None,
                Some(&name),
                outcome,
            );
            Ok(revoked)
        })
        .await
    }

    pub async fn renew_client_token(&self, name: &str, seconds: u64) -> Result<TokenMetadata> {
        let name = name.to_owned();
        self.blocking(move |client| {
            let mut store =
                ClientTokenStore::load_or_create(client.config.client_tokens_path.clone())?;
            let meta = store.renew(&name, seconds)?;
            let _ = client.audit.record(
                "cli-direct",
                "renew_client_token",
                None,
                Some(&name),
                "success",
            );
            Ok(meta)
        })
        .await
    }

    pub async fn rotate_master_token(&self) -> Result<String> {
        self.blocking(move |client| {
            let token = client.config.rotate_auth_token()?;
            let _ = client
                .audit
                .record("cli-direct", "rotate_master_token", None, None, "success");
            Ok(token)
        })
        .await
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
