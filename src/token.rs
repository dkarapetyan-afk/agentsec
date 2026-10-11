use crate::lease::{expires_after, renewed_expiry};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Read,
    Write,
    Run,
    Admin,
}

pub fn default_permissions() -> Vec<Permission> {
    vec![Permission::Read, Permission::Write, Permission::Run]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMetadata {
    pub name: String,
    pub masked_preview: String,
    pub created_at: DateTime<Utc>,
    pub description: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub remaining_ttl_seconds: Option<i64>,
    pub namespaces: Vec<String>,
    pub permissions: Vec<Permission>,
    pub keys: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
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
    #[serde(default = "default_permissions")]
    pub permissions: Vec<Permission>,
    #[serde(default)]
    pub keys: Vec<String>,
}

impl std::fmt::Debug for ClientToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.metadata().fmt(f)
    }
}

impl ClientToken {
    pub fn metadata(&self) -> TokenMetadata {
        TokenMetadata {
            name: self.name.clone(),
            masked_preview: self.masked_preview.clone(),
            created_at: self.created_at,
            description: self.description.clone(),
            expires_at: self.expires_at,
            remaining_ttl_seconds: self
                .expires_at
                .map(|e| (e - Utc::now()).num_seconds().max(0)),
            namespaces: self.namespaces.clone(),
            permissions: self.permissions.clone(),
            keys: self.keys.clone(),
        }
    }
    pub fn allows(
        &self,
        permission: Permission,
        namespace: Option<&str>,
        key: Option<&str>,
    ) -> bool {
        if !self.permissions.contains(&permission) && !self.permissions.contains(&Permission::Admin)
        {
            return false;
        }
        if permission == Permission::Admin && (!self.namespaces.is_empty() || !self.keys.is_empty())
        {
            return false;
        }
        if let Some(ns) = namespace {
            if !self.namespaces.is_empty() && !self.namespaces.iter().any(|allowed| allowed == ns) {
                return false;
            }
        }
        key.is_none_or(|k| self.keys.is_empty() || self.keys.iter().any(|allowed| allowed == k))
    }
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
            if store.clean_expired() > 0 {
                store.save()?;
            }
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
        use std::io::Write;
        let pending = self
            .path
            .with_extension(format!("{}.pending", rand::random::<u64>()));
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&pending)?;
        let result = (|| -> Result<()> {
            file.write_all(content.as_bytes())?;
            file.sync_all()?;
            fs::rename(&pending, &self.path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(pending);
        }
        result
    }

    pub fn clean_expired(&mut self) -> usize {
        let before = self.tokens.len();
        let now = Utc::now();
        self.tokens.retain(|t| {
            if let Some(exp) = t.expires_at {
                exp > now
            } else {
                true
            }
        });
        before - self.tokens.len()
    }

    pub fn add(
        &mut self,
        name: &str,
        description: Option<String>,
        ttl_seconds: Option<u64>,
        namespaces: Vec<String>,
    ) -> Result<ClientToken> {
        self.add_with_policy(
            name,
            description,
            ttl_seconds,
            namespaces,
            default_permissions(),
            vec![],
        )
    }

    pub fn add_with_policy(
        &mut self,
        name: &str,
        description: Option<String>,
        ttl_seconds: Option<u64>,
        namespaces: Vec<String>,
        permissions: Vec<Permission>,
        keys: Vec<String>,
    ) -> Result<ClientToken> {
        self.clean_expired();

        let name = name.trim();
        if name.is_empty() {
            anyhow::bail!("Token name cannot be empty");
        }

        // Check if name already exists
        if self
            .tokens
            .iter()
            .any(|t| t.name.eq_ignore_ascii_case(name))
        {
            anyhow::bail!("A token with the name '{}' already exists", name);
        }

        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let raw_token = hex::encode(bytes);

        let masked_preview = format!(
            "{}...****...{}",
            &raw_token[..6],
            &raw_token[raw_token.len() - 6..]
        );
        let now = Utc::now();
        let expires_at = ttl_seconds.map(expires_after).transpose()?;
        if permissions.is_empty() {
            anyhow::bail!("At least one permission is required");
        }
        if permissions.contains(&Permission::Admin) && (!namespaces.is_empty() || !keys.is_empty())
        {
            anyhow::bail!("Admin tokens must be unscoped; use read/write/run for scoped agents");
        }

        let client_token = ClientToken {
            name: name.to_string(),
            token: raw_token,
            masked_preview,
            created_at: now,
            description,
            expires_at,
            namespaces,
            permissions,
            keys,
        };

        self.tokens.push(client_token.clone());
        self.save()?;
        Ok(client_token)
    }

    pub fn revoke(&mut self, name_or_token: &str) -> Result<bool> {
        let before_count = self.tokens.len();
        self.tokens
            .retain(|t| !t.name.eq_ignore_ascii_case(name_or_token) && t.token != name_or_token);
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
                    if !t.namespaces.is_empty() && !t.namespaces.iter().any(|allowed| allowed == ns)
                    {
                        return false;
                    }
                }
                return true;
            }
        }
        false
    }

    pub fn find(&self, value: &str) -> Option<ClientToken> {
        self.tokens
            .iter()
            .find(|t| t.token == value && t.expires_at.is_none_or(|e| e > Utc::now()))
            .cloned()
    }

    pub fn renew(&mut self, name: &str, seconds: u64) -> Result<TokenMetadata> {
        let token = self
            .tokens
            .iter_mut()
            .find(|t| t.name == name)
            .ok_or_else(|| anyhow::anyhow!("Client token not found"))?;
        token.expires_at = Some(renewed_expiry(token.expires_at, seconds)?);
        let metadata = token.metadata();
        self.save()?;
        Ok(metadata)
    }

    pub fn list(&self) -> Vec<ClientToken> {
        let now = Utc::now();
        self.tokens
            .iter()
            .filter(|t| t.expires_at.is_none_or(|exp| exp > now))
            .cloned()
            .collect()
    }
}
