use crate::crypto::{decrypt_bytes, encrypt_bytes, MasterKey};
use crate::secret::{SecretEntry, SecretMetadata};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStats {
    pub namespaces_count: usize,
    pub active_secrets_count: usize,
    pub is_ephemeral: bool,
    pub vault_path: Option<String>,
}

struct VaultInner {
    // Map: namespace -> (secret_name -> SecretEntry)
    data: HashMap<String, HashMap<String, SecretEntry>>,
    master_key: MasterKey,
    vault_path: Option<PathBuf>,
}

#[derive(Clone)]
pub struct Vault {
    inner: Arc<RwLock<VaultInner>>,
}

impl Vault {
    pub fn new(master_key: MasterKey, vault_path: Option<PathBuf>) -> Result<Self> {
        let mut initial_data = HashMap::new();

        if let Some(ref path) = vault_path {
            if path.exists() {
                let encrypted_bytes = fs::read(path)
                    .with_context(|| format!("Failed to read vault file at {:?}", path))?;
                if !encrypted_bytes.is_empty() {
                    let decrypted =
                        decrypt_bytes(&master_key, &encrypted_bytes).with_context(|| {
                            "Failed to decrypt vault! Corrupted file or invalid master key."
                        })?;
                    let loaded_map: HashMap<String, HashMap<String, SecretEntry>> =
                        serde_json::from_slice(&decrypted)
                            .with_context(|| "Failed to deserialize vault data structure")?;
                    initial_data = loaded_map;
                }
            }
        }

        let inner = VaultInner {
            data: initial_data,
            master_key,
            vault_path,
        };

        Ok(Self {
            inner: Arc::new(RwLock::new(inner)),
        })
    }

    /// Helper to persist the current vault state to encrypted storage on disk
    fn persist_locked(inner: &VaultInner) -> Result<()> {
        let path = match &inner.vault_path {
            Some(p) => p,
            None => return Ok(()), // Ephemeral RAM mode
        };

        let json_bytes = serde_json::to_vec(&inner.data)?;
        let encrypted = encrypt_bytes(&inner.master_key, &json_bytes)?;

        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, &encrypted)
            .with_context(|| format!("Failed to write temporary vault file: {:?}", tmp_path))?;

        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
        }

        fs::rename(&tmp_path, path)
            .with_context(|| format!("Failed to rename {:?} to {:?}", tmp_path, path))?;

        Ok(())
    }

    pub fn set(
        &self,
        namespace: &str,
        key: &str,
        value: &str,
        description: Option<String>,
        tags: Vec<String>,
        ttl_seconds: Option<u64>,
    ) -> Result<SecretMetadata> {
        if let Some(seconds) = ttl_seconds {
            crate::lease::expires_after(seconds)?;
        }
        let mut inner = self.inner.write().unwrap();
        let ns_map = inner.data.entry(namespace.to_string()).or_default();

        let metadata = match ns_map.get_mut(key) {
            Some(existing) => {
                existing.update(value, description, Some(tags), ttl_seconds);
                existing.metadata.clone()
            }
            None => {
                let entry = SecretEntry::new(key, namespace, value, description, tags, ttl_seconds);
                let meta = entry.metadata.clone();
                ns_map.insert(key.to_string(), entry);
                meta
            }
        };

        Self::persist_locked(&inner)?;
        Ok(metadata)
    }

    pub fn get(&self, namespace: &str, key: &str) -> Option<SecretEntry> {
        let mut inner = self.inner.write().unwrap();
        if let Some(ns_map) = inner.data.get_mut(namespace) {
            if let Some(entry) = ns_map.get(key) {
                if entry.is_expired() {
                    ns_map.remove(key);
                    let _ = Self::persist_locked(&inner);
                    return None;
                }
                return Some(entry.clone());
            }
        }
        None
    }

    pub fn list_secrets(&self, namespace: &str) -> Vec<SecretMetadata> {
        let mut inner = self.inner.write().unwrap();
        let mut expired_keys = Vec::new();
        let mut results = Vec::new();

        if let Some(ns_map) = inner.data.get_mut(namespace) {
            for (k, entry) in ns_map.iter() {
                if entry.is_expired() {
                    expired_keys.push(k.clone());
                } else {
                    results.push(entry.metadata.clone());
                }
            }

            if !expired_keys.is_empty() {
                for k in expired_keys {
                    ns_map.remove(&k);
                }
                let _ = Self::persist_locked(&inner);
            }
        }

        results.sort_by(|a, b| a.name.cmp(&b.name));
        results
    }

    pub fn list_namespaces(&self) -> Vec<String> {
        let inner = self.inner.read().unwrap();
        let mut namespaces: Vec<String> = inner.data.keys().cloned().collect();
        namespaces.sort();
        namespaces
    }

    pub fn delete(&self, namespace: &str, key: &str) -> Result<bool> {
        let mut inner = self.inner.write().unwrap();
        let removed = if let Some(ns_map) = inner.data.get_mut(namespace) {
            let res = ns_map.remove(key).is_some();
            if ns_map.is_empty() {
                inner.data.remove(namespace);
            }
            res
        } else {
            false
        };

        if removed {
            Self::persist_locked(&inner)?;
        }
        Ok(removed)
    }

    pub fn delete_namespace(&self, namespace: &str) -> Result<usize> {
        let mut inner = self.inner.write().unwrap();
        let count = if let Some(ns_map) = inner.data.remove(namespace) {
            ns_map.len()
        } else {
            0
        };

        if count > 0 {
            Self::persist_locked(&inner)?;
        }
        Ok(count)
    }

    pub fn export_namespace(&self, namespace: &str) -> HashMap<String, String> {
        let mut inner = self.inner.write().unwrap();
        let mut result = HashMap::new();
        let mut expired_keys = Vec::new();

        if let Some(ns_map) = inner.data.get_mut(namespace) {
            for (key, entry) in ns_map.iter() {
                if entry.is_expired() {
                    expired_keys.push(key.clone());
                } else {
                    result.insert(key.clone(), entry.value.expose_secret().to_string());
                }
            }

            if !expired_keys.is_empty() {
                for k in expired_keys {
                    ns_map.remove(&k);
                }
                let _ = Self::persist_locked(&inner);
            }
        }

        result
    }

    pub fn stats(&self) -> VaultStats {
        let inner = self.inner.read().unwrap();
        let namespaces_count = inner.data.len();
        let mut active_secrets_count = 0;

        for ns_map in inner.data.values() {
            for entry in ns_map.values() {
                if !entry.is_expired() {
                    active_secrets_count += 1;
                }
            }
        }

        VaultStats {
            namespaces_count,
            active_secrets_count,
            is_ephemeral: inner.vault_path.is_none(),
            vault_path: inner
                .vault_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
        }
    }

    pub fn renew(&self, namespace: &str, key: &str, seconds: u64) -> Result<SecretMetadata> {
        let mut inner = self.inner.write().unwrap();
        let entry = inner
            .data
            .get_mut(namespace)
            .and_then(|ns| ns.get_mut(key))
            .ok_or_else(|| anyhow::anyhow!("Secret not found"))?;
        entry.metadata.expires_at = Some(crate::lease::renewed_expiry(
            entry.metadata.expires_at,
            seconds,
        )?);
        entry.metadata.updated_at = chrono::Utc::now();
        let metadata = entry.metadata.clone();
        Self::persist_locked(&inner)?;
        Ok(metadata)
    }

    pub fn purge_expired(&self) -> Result<usize> {
        let mut inner = self.inner.write().unwrap();
        let before: usize = inner.data.values().map(HashMap::len).sum();
        let old_namespaces = inner.data.len();
        inner.data.retain(|_, ns| {
            ns.retain(|_, entry| !entry.is_expired());
            !ns.is_empty()
        });
        let after: usize = inner.data.values().map(HashMap::len).sum();
        if before != after || old_namespaces != inner.data.len() {
            Self::persist_locked(&inner)?;
        }
        Ok(before - after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_ephemeral_vault_crud() {
        let master_key = MasterKey::generate();
        let vault = Vault::new(master_key, None).unwrap();

        vault
            .set(
                "repo:demo",
                "API_KEY",
                "secret-val-123",
                Some("Test API key".into()),
                vec!["api".into()],
                None,
            )
            .unwrap();

        let secret = vault.get("repo:demo", "API_KEY").expect("secret not found");
        assert_eq!(secret.value.expose_secret(), "secret-val-123");

        let list = vault.list_secrets("repo:demo");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "API_KEY");

        let exported = vault.export_namespace("repo:demo");
        assert_eq!(exported.get("API_KEY").unwrap(), "secret-val-123");

        let deleted = vault.delete("repo:demo", "API_KEY").unwrap();
        assert!(deleted);
        assert!(vault.get("repo:demo", "API_KEY").is_none());
    }

    #[test]
    fn test_persistent_vault_reload() {
        let temp_dir =
            env::temp_dir().join(format!("agentsec_vault_test_{}", rand::random::<u64>()));
        let _ = fs::create_dir_all(&temp_dir);
        let vault_file = temp_dir.join("vault.enc");
        let master_key = MasterKey::generate();

        {
            let vault = Vault::new(master_key.clone(), Some(vault_file.clone())).unwrap();
            vault
                .set("prod", "DB_PASS", "postgres123", None, vec![], None)
                .unwrap();
        }

        // Vault was dropped, re-open with same master key
        {
            let vault_reloaded = Vault::new(master_key, Some(vault_file.clone())).unwrap();
            let entry = vault_reloaded
                .get("prod", "DB_PASS")
                .expect("Should find secret");
            assert_eq!(entry.value.expose_secret(), "postgres123");
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
