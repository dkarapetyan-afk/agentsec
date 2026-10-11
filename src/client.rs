use crate::config::AppConfig;
use crate::secret::SecretMetadata;
use crate::server::{
    CreateTokenRequest, DeleteNamespaceResponse, DeleteSecretResponse, ErrorResponse,
    ExportNamespaceResponse, HealthResponse, NamespacesResponse, RevokeTokenResponse,
    SecretDetailResponse, SecretsListResponse, SetSecretRequest, StatusResponse, TokenListResponse,
};
use crate::token::{default_permissions, ClientToken, Permission, TokenMetadata};
use anyhow::{anyhow, Context, Result};
use reqwest::{Client, StatusCode};
use std::collections::HashMap;

#[derive(Clone)]
pub struct DaemonClient {
    client: Client,
    base_url: String,
    auth_token: String,
}

impl DaemonClient {
    pub fn new(config: &AppConfig) -> Result<Self> {
        let base_url = if let Some(ref url) = config.custom_url {
            let trimmed = url.trim().trim_end_matches('/');
            if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                trimmed.to_string()
            } else {
                format!("https://{}", trimmed)
            }
        } else if let Ok(Some(info)) = config.read_daemon_info() {
            format!("http://{}:{}", info.host, info.port)
        } else {
            format!("http://{}:{}", config.host, config.port)
        };

        let auth_token = config.get_or_create_auth_token()?;

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            client,
            base_url,
            auth_token,
        })
    }

    pub fn with_explicit_target(base_url: String, auth_token: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .context("Failed to build HTTP client")?;

        Ok(Self {
            client,
            base_url,
            auth_token,
        })
    }

    fn check_connection_error(&self, err: reqwest::Error) -> anyhow::Error {
        if err.is_connect() || err.is_timeout() {
            anyhow!(
                "Unable to connect to agentsec daemon at {}.\n\
                Is the daemon running? Start it in the background using:\n  agentsec daemon",
                self.base_url
            )
        } else {
            anyhow!("Request error: {}", err)
        }
    }

    pub async fn health(&self) -> Result<HealthResponse> {
        let url = format!("{}/health", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| self.check_connection_error(e))?;

        if !resp.status().is_success() {
            return Err(anyhow!(
                "Health check failed with status: {}",
                resp.status()
            ));
        }

        let body: HealthResponse = resp.json().await?;
        Ok(body)
    }

    pub async fn status(&self) -> Result<StatusResponse> {
        let url = format!("{}/v1/status", self.base_url);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| self.check_connection_error(e))?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            return Err(anyhow!("Unauthorized: invalid daemon auth token"));
        }

        if !resp.status().is_success() {
            let err_body: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown server error".into(),
            });
            return Err(anyhow!("Server error: {}", err_body.error));
        }

        let body: StatusResponse = resp.json().await?;
        Ok(body)
    }

    pub async fn list_namespaces(&self) -> Result<Vec<String>> {
        let url = format!("{}/v1/namespaces", self.base_url);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| self.check_connection_error(e))?;

        if !resp.status().is_success() {
            let err_body: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown server error".into(),
            });
            return Err(anyhow!("Server error: {}", err_body.error));
        }

        let body: NamespacesResponse = resp.json().await?;
        Ok(body.namespaces)
    }

    pub async fn list_secrets(&self, namespace: &str) -> Result<Vec<SecretMetadata>> {
        let url = format!("{}/v1/secrets/{}", self.base_url, urlencoding(namespace));
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| self.check_connection_error(e))?;

        if !resp.status().is_success() {
            let err_body: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown server error".into(),
            });
            return Err(anyhow!("Server error: {}", err_body.error));
        }

        let body: SecretsListResponse = resp.json().await?;
        Ok(body.secrets)
    }

    pub async fn get_secret(&self, namespace: &str, key: &str) -> Result<SecretDetailResponse> {
        let url = format!(
            "{}/v1/secrets/{}/{}",
            self.base_url,
            urlencoding(namespace),
            urlencoding(key)
        );
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| self.check_connection_error(e))?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Err(anyhow!(
                "Secret '{}' not found in namespace '{}'",
                key,
                namespace
            ));
        }

        if !resp.status().is_success() {
            let err_body: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown server error".into(),
            });
            return Err(anyhow!("Server error: {}", err_body.error));
        }

        let body: SecretDetailResponse = resp.json().await?;
        Ok(body)
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
        let url = format!(
            "{}/v1/secrets/{}/{}",
            self.base_url,
            urlencoding(namespace),
            urlencoding(key)
        );

        let req = SetSecretRequest {
            value: value.to_string(),
            description,
            tags,
            ttl_seconds,
        };

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.auth_token)
            .json(&req)
            .send()
            .await
            .map_err(|e| self.check_connection_error(e))?;

        if !resp.status().is_success() {
            let err_body: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown server error".into(),
            });
            return Err(anyhow!("Server error: {}", err_body.error));
        }

        let metadata: SecretMetadata = resp.json().await?;
        Ok(metadata)
    }

    pub async fn delete_secret(&self, namespace: &str, key: &str) -> Result<bool> {
        let url = format!(
            "{}/v1/secrets/{}/{}",
            self.base_url,
            urlencoding(namespace),
            urlencoding(key)
        );

        let resp = self
            .client
            .delete(&url)
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| self.check_connection_error(e))?;

        if !resp.status().is_success() {
            let err_body: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown server error".into(),
            });
            return Err(anyhow!("Server error: {}", err_body.error));
        }

        let body: DeleteSecretResponse = resp.json().await?;
        Ok(body.deleted)
    }

    pub async fn delete_namespace(&self, namespace: &str) -> Result<usize> {
        let url = format!("{}/v1/namespaces/{}", self.base_url, urlencoding(namespace));

        let resp = self
            .client
            .delete(&url)
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| self.check_connection_error(e))?;

        if !resp.status().is_success() {
            let err_body: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown server error".into(),
            });
            return Err(anyhow!("Server error: {}", err_body.error));
        }

        let body: DeleteNamespaceResponse = resp.json().await?;
        Ok(body.deleted_count)
    }

    pub async fn export_namespace(&self, namespace: &str) -> Result<HashMap<String, String>> {
        let url = format!("{}/v1/export/{}", self.base_url, urlencoding(namespace));

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| self.check_connection_error(e))?;

        if !resp.status().is_success() {
            let err_body: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown server error".into(),
            });
            return Err(anyhow!("Server error: {}", err_body.error));
        }

        let body: ExportNamespaceResponse = resp.json().await?;
        Ok(body.secrets)
    }

    pub async fn list_client_tokens(&self) -> Result<Vec<TokenMetadata>> {
        let url = format!("{}/v1/tokens", self.base_url);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| self.check_connection_error(e))?;

        if !resp.status().is_success() {
            let err_body: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown server error".into(),
            });
            return Err(anyhow!("Server error: {}", err_body.error));
        }

        let body: TokenListResponse = resp.json().await?;
        Ok(body.tokens)
    }

    pub async fn create_client_token(
        &self,
        name: &str,
        description: Option<String>,
        ttl_seconds: Option<u64>,
        namespaces: Vec<String>,
    ) -> Result<ClientToken> {
        self.create_client_token_with_policy(
            name,
            description,
            ttl_seconds,
            namespaces,
            default_permissions(),
            vec![],
        )
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
        let url = format!("{}/v1/tokens", self.base_url);
        let req = CreateTokenRequest {
            name: name.to_string(),
            description,
            ttl_seconds,
            namespaces,
            permissions,
            keys,
        };

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.auth_token)
            .json(&req)
            .send()
            .await
            .map_err(|e| self.check_connection_error(e))?;

        if !resp.status().is_success() {
            let err_body: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown server error".into(),
            });
            return Err(anyhow!("Failed to create token: {}", err_body.error));
        }

        let token: ClientToken = resp.json().await?;
        Ok(token)
    }

    pub async fn revoke_client_token(&self, name: &str) -> Result<bool> {
        let url = format!("{}/v1/tokens/{}", self.base_url, urlencoding(name));
        let resp = self
            .client
            .delete(&url)
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| self.check_connection_error(e))?;

        if !resp.status().is_success() {
            let err_body: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown server error".into(),
            });
            return Err(anyhow!("Failed to revoke token: {}", err_body.error));
        }

        let body: RevokeTokenResponse = resp.json().await?;
        Ok(body.revoked)
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        route: &str,
        payload: impl serde::Serialize,
    ) -> Result<T> {
        let response = self
            .client
            .post(format!("{}{}", self.base_url, route))
            .bearer_auth(&self.auth_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| self.check_connection_error(e))?;
        if !response.status().is_success() {
            let status = response.status();
            let error = response
                .json::<ErrorResponse>()
                .await
                .unwrap_or(ErrorResponse {
                    error: "Daemon request failed".into(),
                });
            return Err(anyhow!("{}: {}", status, error.error));
        }
        Ok(response.json().await?)
    }

    pub async fn inject_secrets(
        &self,
        namespace: &str,
        keys: Option<Vec<String>>,
    ) -> Result<HashMap<String, String>> {
        let result: ExportNamespaceResponse = self
            .post_json(
                &format!("/v1/inject/{}", urlencoding(namespace)),
                crate::server::InjectRequest { keys },
            )
            .await?;
        Ok(result.secrets)
    }

    pub async fn renew_secret(
        &self,
        namespace: &str,
        key: &str,
        seconds: u64,
    ) -> Result<SecretMetadata> {
        self.post_json(
            &format!(
                "/v1/secrets/{}/{}/renew",
                urlencoding(namespace),
                urlencoding(key)
            ),
            crate::server::RenewRequest {
                ttl_seconds: seconds,
            },
        )
        .await
    }

    pub async fn renew_client_token(&self, name: &str, seconds: u64) -> Result<TokenMetadata> {
        self.post_json(
            &format!("/v1/tokens/{}/renew", urlencoding(name)),
            crate::server::RenewRequest {
                ttl_seconds: seconds,
            },
        )
        .await
    }

    pub async fn rotate_master_token(&self) -> Result<String> {
        let result: crate::server::RotateTokenResponse = self
            .post_json("/v1/token/rotate", serde_json::json!({}))
            .await?;
        Ok(result.token)
    }

    pub async fn audit_events(&self, limit: usize) -> Result<Vec<crate::audit::AuditEvent>> {
        let response = self
            .client
            .get(format!(
                "{}/v1/audit?limit={}",
                self.base_url,
                limit.min(1000)
            ))
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .map_err(|e| self.check_connection_error(e))?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "Audit access denied or unavailable ({})",
                response.status()
            ));
        }
        Ok(response
            .json::<crate::server::AuditResponse>()
            .await?
            .events)
    }

    pub async fn mcp_request(&self, payload: serde_json::Value) -> Result<serde_json::Value> {
        let response = self
            .client
            .post(format!("{}/mcp", self.base_url))
            .bearer_auth(&self.auth_token)
            .json(&payload)
            .timeout(std::time::Duration::from_secs(120))
            .send()
            .await
            .map_err(|e| self.check_connection_error(e))?;
        if !response.status().is_success() {
            anyhow::bail!("MCP request rejected with status {}", response.status());
        }
        Ok(response.json().await?)
    }
}

fn urlencoding(input: &str) -> String {
    let mut encoded = String::new();
    for byte in input.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
}
