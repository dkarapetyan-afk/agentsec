use crate::config::AppConfig;
use crate::secret::SecretMetadata;
use crate::server::{
    DeleteNamespaceResponse, DeleteSecretResponse, ErrorResponse, ExportNamespaceResponse,
    HealthResponse, NamespacesResponse, SecretDetailResponse, SecretsListResponse,
    SetSecretRequest, StatusResponse,
};
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
        let (host, port) = if let Ok(Some(info)) = config.read_daemon_info() {
            (info.host, info.port)
        } else {
            (config.host.clone(), config.port)
        };

        let auth_token = config.get_or_create_auth_token()?;
        let base_url = format!("http://{}:{}", host, port);

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
            return Err(anyhow!("Health check failed with status: {}", resp.status()));
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
