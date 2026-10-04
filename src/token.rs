use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientToken {
    pub name: String,
    pub token: String,
    pub masked_preview: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientTokenStore {
    #[serde(default)]
    pub tokens: Vec<ClientToken>,
    #[serde(skip)]
    pub path: PathBuf,
}

impl ClientTokenStore {
    pub fn load_or_create(path: PathBuf) -> Result<Self> {
        if path.exists() {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read client tokens file: {:?}", path))?;
            let mut store: ClientTokenStore = serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse client tokens JSON: {:?}", path))?;
            store.path = path;
            store.clean_expired();
            Ok(store)
        } else {
            let store = Self {
                tokens: Vec::new(),
                path,
            };
            store.save()?;
            Ok(store)
        }
    }

    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&self.path, content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn clean_expired(&mut self) {
        let now = Utc::now();
        self.tokens.retain(|t| {
            if let Some(exp) = t.expires_at {
                exp > now
            } else {
                true
            }
        });
    }

    pub fn add(
        &mut self,
        name: &str,
        description: Option<String>,
        ttl_seconds: Option<u64>,
        namespaces: Vec<String>,
    ) -> Result<ClientToken> {
        self.clean_expired();

        let name = name.trim();
        if name.is_empty() {
            anyhow::bail!("Token name cannot be empty");
        }

        // Check if name already exists
        if self.tokens.iter().any(|t| t.name.eq_ignore_ascii_case(name)) {
            anyhow::bail!("A token with the name '{}' already exists", name);
        }

        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let raw_token = hex::encode(bytes);

        let masked_preview = format!("{}...****...{}", &raw_token[..6], &raw_token[raw_token.len() - 6..]);
        let now = Utc::now();
        let expires_at = ttl_seconds.map(|secs| now + chrono::Duration::seconds(secs as i64));

        let client_token = ClientToken {
            name: name.to_string(),
            token: raw_token,
            masked_preview,
            created_at: now,
            description,
            expires_at,
            namespaces,
        };

        self.tokens.push(client_token.clone());
        self.save()?;
        Ok(client_token)
    }

    pub fn revoke(&mut self, name_or_token: &str) -> Result<bool> {
        let before_count = self.tokens.len();
        self.tokens.retain(|t| !t.name.eq_ignore_ascii_case(name_or_token) && t.token != name_or_token);
        let changed = self.tokens.len() < before_count;
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    pub fn validate(&self, token_value: &str, target_namespace: Option<&str>) -> bool {
        let now = Utc::now();
        for t in &self.tokens {
            if t.token == token_value {
                // Check expiry
                if let Some(exp) = t.expires_at {
                    if exp <= now {
                        return false;
                    }
                }
                // Check namespace restriction if target_namespace is specified
                if let Some(ns) = target_namespace {
                    if !t.namespaces.is_empty() && !t.namespaces.iter().any(|allowed| allowed == ns) {
                        return false;
                    }
                }
                return true;
            }
        }
        false
    }

    pub fn list(&self) -> Vec<ClientToken> {
        let now = Utc::now();
        self.tokens
            .iter()
            .filter(|t| t.expires_at.map_or(true, |exp| exp > now))
            .cloned()
            .collect()
    }
}
