use crate::crypto::{decrypt_bytes, encrypt_bytes, MasterKey};
use crate::secret::{SecretEntry, SecretMetadata};
use anyhow::{Context, Result};
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Notify, RwLock};

const INDEX_SHARDS: usize = 64;
type Namespace = HashMap<String, SecretEntry>;
type NamespaceHandle = Arc<Mutex<Namespace>>;
type MemoryIndex = [RwLock<HashMap<String, NamespaceHandle>>; INDEX_SHARDS];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStats {
    pub namespaces_count: usize,
    pub active_secrets_count: usize,
    pub is_ephemeral: bool,
    pub vault_path: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct NamespaceFile {
    namespace: String,
    secrets: Namespace,
}

#[derive(Clone)]
pub struct Vault {
    master_key: Arc<MasterKey>,
    vault_path: Option<PathBuf>,
    // Only ephemeral storage uses this index. Its shard locks are released before
    // taking a namespace lock, and never cover encryption, I/O, or an operation.
    memory: Arc<MemoryIndex>,
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
}

struct OperationGuard {
    active: Arc<AtomicUsize>,
    idle: Arc<Notify>,
}
impl Drop for OperationGuard {
    fn drop(&mut self) {
        if self.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.idle.notify_waiters();
        }
    }
}

struct FileLock {
    _file: std::fs::File,
}
impl FileLock {
    async fn acquire(namespace_path: &Path) -> Result<Self> {
        let mut options = fs::OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(namespace_path.with_extension("lock"))
            .await
            .context("Failed to open namespace lock")?
            .into_std()
            .await;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { _file: file }),
                Err(std::fs::TryLockError::WouldBlock) => {}
                Err(std::fs::TryLockError::Error(error))
                    if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!("Timed out acquiring namespace file lock");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
}

async fn is_file(path: &Path) -> Result<bool> {
    match fs::metadata(path).await {
        Ok(metadata) => Ok(metadata.is_file()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

impl Vault {
    pub async fn new(master_key: MasterKey, vault_path: Option<PathBuf>) -> Result<Self> {
        if let Some(path) = &vault_path {
            if is_file(path).await? {
                anyhow::bail!("Legacy single-file vault detected. Stop older agentsec clients and run 'agentsec migrate' before opening it.");
            }
            fs::create_dir_all(path)
                .await
                .context("Failed to create namespace storage")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
            }
            if fs::try_exists(path.with_extension("legacy.enc")).await?
                && !fs::try_exists(path.join("migration.complete")).await?
            {
                anyhow::bail!(
                    "Namespace migration is incomplete; run 'agentsec migrate' to resume it."
                );
            }
        }
        Ok(Self::open(master_key, vault_path))
    }

    fn open(master_key: MasterKey, vault_path: Option<PathBuf>) -> Self {
        Self {
            master_key: Arc::new(master_key),
            vault_path,
            memory: Arc::new(std::array::from_fn(|_| RwLock::new(HashMap::new()))),
            active: Arc::new(AtomicUsize::new(0)),
            idle: Arc::new(Notify::new()),
        }
    }

    /// Offline, resumable format conversion. Older writers must be stopped by
    /// the operator; the encrypted original is retained and never overwritten.
    /// Migration takes only individual namespace locks, just like normal I/O.
    pub async fn migrate_legacy(master_key: MasterKey, path: PathBuf) -> Result<usize> {
        let backup = path.with_extension("legacy.enc");
        let complete = path.join("migration.complete");
        if !is_file(&path).await? && fs::try_exists(&complete).await? {
            return Ok(0);
        }
        let source = if is_file(&path).await? {
            &path
        } else {
            &backup
        };
        let encrypted = fs::read(source)
            .await
            .context("No legacy vault is available to migrate")?;
        let migration_key = master_key.clone();
        let data: HashMap<String, Namespace> = tokio::task::spawn_blocking(move || {
            anyhow::Ok(serde_json::from_slice(&decrypt_bytes(
                &migration_key,
                &encrypted,
            )?)?)
        })
        .await
        .context("Legacy decryption worker failed")??;
        if is_file(&path).await? {
            anyhow::ensure!(
                !fs::try_exists(&backup).await?,
                "Legacy backup already exists; refusing to overwrite it"
            );
            fs::rename(&path, &backup)
                .await
                .context("Failed to preserve encrypted legacy vault")?;
        }
        fs::create_dir_all(&path).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).await?;
        }
        let vault = Self::open(master_key, Some(path.clone()));
        let mut imported = 0;
        for (namespace, secrets) in data {
            let target = vault.namespace_path(&namespace).unwrap();
            let _lock = FileLock::acquire(&target).await?;
            if fs::try_exists(&complete).await? {
                return Ok(imported);
            }
            if !fs::try_exists(&target).await? && !secrets.is_empty() {
                vault
                    .persist(&target, &NamespaceFile { namespace, secrets })
                    .await?;
                imported += 1;
            }
        }
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(complete)
            .await
        {
            Ok(mut marker) => marker.write_all(b"namespace-storage-v1\n").await?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        Ok(imported)
    }

    pub fn namespace_path(&self, namespace: &str) -> Option<PathBuf> {
        let name = hex::encode(Blake2s256::digest(namespace.as_bytes()));
        self.vault_path
            .as_ref()
            .map(|root| root.join(name).with_extension("enc"))
    }

    async fn memory_namespace(&self, namespace: &str) -> Result<NamespaceHandle> {
        let shard = Blake2s256::digest(namespace.as_bytes())[0] as usize % INDEX_SHARDS;
        let index = &self.memory[shard];
        if let Some(handle) = index.read().await.get(namespace).cloned() {
            return Ok(handle);
        }
        let mut index = index.write().await;
        Ok(index
            .entry(namespace.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(HashMap::new())))
            .clone())
    }

    async fn read_namespace(&self, path: &Path) -> Result<Option<NamespaceFile>> {
        let encrypted = match fs::read(path).await {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let master_key = self.master_key.clone();
        let data: NamespaceFile = tokio::task::spawn_blocking(move || {
            anyhow::Ok(serde_json::from_slice(&decrypt_bytes(
                &master_key,
                &encrypted,
            )?)?)
        })
        .await
        .context("Namespace decryption worker failed")??;
        anyhow::ensure!(
            self.namespace_path(&data.namespace).as_deref() == Some(path),
            "Namespace file identity mismatch"
        );
        Ok(Some(data))
    }

    async fn persist(&self, path: &Path, data: &NamespaceFile) -> Result<()> {
        if data.secrets.is_empty() {
            match fs::remove_file(path).await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            return Ok(());
        }
        let master_key = self.master_key.clone();
        let data = data.clone();
        let encrypted = tokio::task::spawn_blocking(move || {
            encrypt_bytes(&master_key, &serde_json::to_vec(&data)?)
        })
        .await
        .context("Namespace encryption worker failed")??;
        let pending = path.with_extension(format!("{}.pending", rand::random::<u64>()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut file = options.open(&pending).await?;
        let result: Result<()> = async {
            file.write_all(&encrypted).await?;
            file.flush().await?;
            file.sync_all().await?;
            drop(file);
            fs::rename(&pending, path).await?;
            #[cfg(unix)]
            if let Some(parent) = path.parent() {
                fs::File::open(parent).await?.sync_all().await?;
            }
            // Confirm publication before releasing this namespace's lock.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                match fs::read(path).await {
                    Ok(committed) if committed == encrypted => break,
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                anyhow::ensure!(
                    tokio::time::Instant::now() < deadline,
                    "Namespace commit did not become visible"
                );
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            Ok(())
        }
        .await;
        if result.is_err() {
            let _ = fs::remove_file(pending).await;
        }
        result
    }

    // A cancelled HTTP/MCP caller must not release the namespace lock while an
    // already-submitted filesystem commit is still running. The independent task
    // owns the transaction to completion; only shutdown waits for all transactions.
    pub async fn wait_for_pending(&self) {
        loop {
            let idle = self.idle.notified();
            tokio::pin!(idle);
            idle.as_mut().enable();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            idle.await;
        }
    }

    async fn with_namespace<T: Send + 'static>(
        &self,
        namespace: &str,
        operation: impl FnOnce(&mut Namespace) -> Result<(T, bool)> + Send + 'static,
    ) -> Result<T> {
        let vault = self.clone();
        let namespace = namespace.to_owned();
        self.active.fetch_add(1, Ordering::AcqRel);
        let guard = OperationGuard {
            active: self.active.clone(),
            idle: self.idle.clone(),
        };
        tokio::spawn(async move {
            let _guard = guard;
            vault.namespace_transaction(&namespace, operation).await
        })
        .await
        .context("Namespace transaction task failed")?
    }

    async fn namespace_transaction<T>(
        &self,
        namespace: &str,
        operation: impl FnOnce(&mut Namespace) -> Result<(T, bool)>,
    ) -> Result<T> {
        if let Some(path) = self.namespace_path(namespace) {
            let _lock = FileLock::acquire(&path).await?;
            let mut data = self
                .read_namespace(&path)
                .await?
                .unwrap_or_else(|| NamespaceFile {
                    namespace: namespace.to_owned(),
                    secrets: HashMap::new(),
                });
            let (result, changed) = operation(&mut data.secrets)?;
            if changed {
                self.persist(&path, &data).await?;
            }
            Ok(result)
        } else {
            let handle = self.memory_namespace(namespace).await?;
            let mut data = handle.lock().await;
            operation(&mut data).map(|(result, _)| result)
        }
    }

    async fn snapshots(&self) -> Result<Vec<NamespaceFile>> {
        let mut data = Vec::new();
        if let Some(root) = &self.vault_path {
            let mut entries = fs::read_dir(root).await?;
            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                if path.extension().is_some_and(|extension| extension == "enc") {
                    if let Some(namespace) = self.read_namespace(&path).await? {
                        if !namespace.secrets.is_empty() {
                            data.push(namespace);
                        }
                    }
                }
            }
        } else {
            for index in self.memory.iter() {
                let handles: Vec<_> = index
                    .read()
                    .await
                    .iter()
                    .map(|(name, handle)| (name.clone(), handle.clone()))
                    .collect();
                for (namespace, handle) in handles {
                    let secrets = handle.lock().await.clone();
                    if !secrets.is_empty() {
                        data.push(NamespaceFile { namespace, secrets });
                    }
                }
            }
        }
        Ok(data)
    }

    pub async fn set(
        &self,
        namespace: &str,
        key: &str,
        value: &str,
        description: Option<String>,
        tags: Vec<String>,
        ttl_seconds: Option<u64>,
    ) -> Result<SecretMetadata> {
        let key = key.to_owned();
        let value = value.to_owned();
        let entry_namespace = namespace.to_owned();
        if let Some(seconds) = ttl_seconds {
            crate::lease::expires_after(seconds)?;
        }
        self.with_namespace(namespace, move |data| {
            let metadata = match data.get_mut(&key) {
                Some(existing) => {
                    existing.update(value, description, Some(tags), ttl_seconds);
                    existing.metadata.clone()
                }
                None => {
                    let entry = SecretEntry::new(
                        &key,
                        &entry_namespace,
                        &value,
                        description,
                        tags,
                        ttl_seconds,
                    );
                    let metadata = entry.metadata.clone();
                    data.insert(key.to_owned(), entry);
                    metadata
                }
            };
            Ok((metadata, true))
        })
        .await
    }
    pub async fn get(&self, namespace: &str, key: &str) -> Option<SecretEntry> {
        self.try_get(namespace, key).await.ok().flatten()
    }
    pub async fn try_get(&self, namespace: &str, key: &str) -> Result<Option<SecretEntry>> {
        let key = key.to_owned();
        self.with_namespace(namespace, move |data| {
            if data.get(&key).is_some_and(SecretEntry::is_expired) {
                data.remove(&key);
                return Ok((None, true));
            }
            Ok((data.get(&key).cloned(), false))
        })
        .await
    }
    pub async fn list_secrets(&self, namespace: &str) -> Vec<SecretMetadata> {
        self.try_list_secrets(namespace).await.unwrap_or_default()
    }
    pub async fn try_list_secrets(&self, namespace: &str) -> Result<Vec<SecretMetadata>> {
        self.with_namespace(namespace, |data| {
            let before = data.len();
            data.retain(|_, entry| !entry.is_expired());
            let mut metadata: Vec<_> = data.values().map(|entry| entry.metadata.clone()).collect();
            metadata.sort_by(|a, b| a.name.cmp(&b.name));
            Ok((metadata, data.len() != before))
        })
        .await
    }
    pub async fn list_namespaces(&self) -> Vec<String> {
        self.try_list_namespaces().await.unwrap_or_default()
    }
    pub async fn try_list_namespaces(&self) -> Result<Vec<String>> {
        let mut names: Vec<_> = self
            .snapshots()
            .await?
            .into_iter()
            .map(|data| data.namespace)
            .collect();
        names.sort();
        Ok(names)
    }
    pub async fn delete(&self, namespace: &str, key: &str) -> Result<bool> {
        let key = key.to_owned();
        self.with_namespace(namespace, move |data| {
            let removed = data.remove(&key).is_some();
            Ok((removed, removed))
        })
        .await
    }
    pub async fn delete_namespace(&self, namespace: &str) -> Result<usize> {
        self.with_namespace(namespace, |data| {
            let count = data.len();
            data.clear();
            Ok((count, count > 0))
        })
        .await
    }
    pub async fn export_namespace(&self, namespace: &str) -> HashMap<String, String> {
        self.try_export_namespace(namespace)
            .await
            .unwrap_or_default()
    }
    pub async fn try_export_namespace(&self, namespace: &str) -> Result<HashMap<String, String>> {
        self.with_namespace(namespace, |data| {
            let before = data.len();
            data.retain(|_, entry| !entry.is_expired());
            let values = data
                .iter()
                .map(|(key, entry)| (key.clone(), entry.value.expose_secret().to_owned()))
                .collect();
            Ok((values, data.len() != before))
        })
        .await
    }
    pub async fn stats(&self) -> VaultStats {
        self.try_stats()
            .await
            .unwrap_or_else(|_| self.empty_stats())
    }
    fn empty_stats(&self) -> VaultStats {
        VaultStats {
            namespaces_count: 0,
            active_secrets_count: 0,
            is_ephemeral: self.vault_path.is_none(),
            vault_path: self
                .vault_path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
        }
    }
    pub async fn try_stats(&self) -> Result<VaultStats> {
        let data = self.snapshots().await?;
        Ok(VaultStats {
            namespaces_count: data.len(),
            active_secrets_count: data
                .iter()
                .map(|namespace| {
                    namespace
                        .secrets
                        .values()
                        .filter(|entry| !entry.is_expired())
                        .count()
                })
                .sum(),
            ..self.empty_stats()
        })
    }
    pub async fn renew(&self, namespace: &str, key: &str, seconds: u64) -> Result<SecretMetadata> {
        let key = key.to_owned();
        self.with_namespace(namespace, move |data| {
            let entry = data
                .get_mut(&key)
                .ok_or_else(|| anyhow::anyhow!("Secret not found"))?;
            entry.metadata.expires_at = Some(crate::lease::renewed_expiry(
                entry.metadata.expires_at,
                seconds,
            )?);
            entry.metadata.updated_at = chrono::Utc::now();
            Ok((entry.metadata.clone(), true))
        })
        .await
    }
    pub async fn purge_expired(&self) -> Result<usize> {
        let mut purged = 0;
        for namespace in self.try_list_namespaces().await? {
            purged += self
                .with_namespace(&namespace, |data| {
                    let before = data.len();
                    data.retain(|_, entry| !entry.is_expired());
                    let count = before - data.len();
                    Ok((count, count > 0))
                })
                .await?;
        }
        Ok(purged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[tokio::test]
    async fn test_ephemeral_vault_crud() {
        let master_key = MasterKey::generate();
        let vault = Vault::new(master_key, None).await.unwrap();

        vault
            .set(
                "repo:demo",
                "API_KEY",
                "secret-val-123",
                Some("Test API key".into()),
                vec!["api".into()],
                None,
            )
            .await
            .unwrap();

        let secret = vault
            .get("repo:demo", "API_KEY")
            .await
            .expect("secret not found");
        assert_eq!(secret.value.expose_secret(), "secret-val-123");

        let list = vault.list_secrets("repo:demo").await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "API_KEY");

        let exported = vault.export_namespace("repo:demo").await;
        assert_eq!(exported.get("API_KEY").unwrap(), "secret-val-123");

        let deleted = vault.delete("repo:demo", "API_KEY").await.unwrap();
        assert!(deleted);
        assert!(vault.get("repo:demo", "API_KEY").await.is_none());
    }

    #[tokio::test]
    async fn test_persistent_vault_reload() {
        let temp_dir =
            env::temp_dir().join(format!("agentsec_vault_test_{}", rand::random::<u64>()));
        let _ = fs::create_dir_all(&temp_dir).await;
        let vault_file = temp_dir.join("vault.enc");
        let master_key = MasterKey::generate();

        {
            let vault = Vault::new(master_key.clone(), Some(vault_file.clone()))
                .await
                .unwrap();
            vault
                .set("prod", "DB_PASS", "postgres123", None, vec![], None)
                .await
                .unwrap();
        }

        // Vault was dropped, re-open with same master key
        {
            let vault_reloaded = Vault::new(master_key, Some(vault_file.clone()))
                .await
                .unwrap();
            let entry = vault_reloaded
                .get("prod", "DB_PASS")
                .await
                .expect("Should find secret");
            assert_eq!(entry.value.expose_secret(), "postgres123");
        }

        let _ = fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn legacy_migration_preserves_values_metadata_and_encrypted_backup() {
        let root = env::temp_dir().join(format!("agentsec_migration_{}", rand::random::<u64>()));
        fs::create_dir_all(&root).await.unwrap();
        let path = root.join("vault.enc");
        let key = MasterKey::generate();
        let original = SecretEntry::new(
            "KEY",
            "legacy",
            "fixture-migration-value",
            Some("fixture description".into()),
            vec!["fixture".into()],
            Some(60),
        );
        let data = HashMap::from([(
            "legacy".to_owned(),
            HashMap::from([("KEY".to_owned(), original.clone())]),
        )]);
        let encrypted = encrypt_bytes(&key, &serde_json::to_vec(&data).unwrap()).unwrap();
        fs::write(&path, &encrypted).await.unwrap();
        assert!(Vault::new(key.clone(), Some(path.clone())).await.is_err());
        assert_eq!(
            Vault::migrate_legacy(key.clone(), path.clone())
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            fs::read(path.with_extension("legacy.enc")).await.unwrap(),
            encrypted
        );
        let vault = Vault::new(key.clone(), Some(path.clone())).await.unwrap();
        let migrated = vault.get("legacy", "KEY").await.unwrap();
        assert_eq!(
            migrated.value.expose_secret(),
            original.value.expose_secret()
        );
        assert_eq!(
            serde_json::to_value(&migrated.metadata).unwrap(),
            serde_json::to_value(&original.metadata).unwrap()
        );
        assert!(!root.join("vault.lock").exists());
        vault.delete_namespace("legacy").await.unwrap();
        assert_eq!(Vault::migrate_legacy(key, path).await.unwrap(), 0);
        assert!(vault.get("legacy", "KEY").await.is_none());
        fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn incomplete_migration_resumes_without_overwriting_imported_namespaces() {
        let root = env::temp_dir().join(format!(
            "agentsec_migration_resume_{}",
            rand::random::<u64>()
        ));
        fs::create_dir_all(&root).await.unwrap();
        let path = root.join("vault.enc");
        let key = MasterKey::generate();
        let entry = SecretEntry::new("KEY", "legacy", "fixture-original", None, vec![], Some(60));
        let data = HashMap::from([(
            "legacy".to_owned(),
            HashMap::from([("KEY".to_owned(), entry)]),
        )]);
        fs::write(
            &path,
            encrypt_bytes(&key, &serde_json::to_vec(&data).unwrap()).unwrap(),
        )
        .await
        .unwrap();
        Vault::migrate_legacy(key.clone(), path.clone())
            .await
            .unwrap();
        let vault = Vault::new(key.clone(), Some(path.clone())).await.unwrap();
        vault
            .set("legacy", "KEY", "fixture-updated", None, vec![], Some(60))
            .await
            .unwrap();
        fs::remove_file(path.join("migration.complete"))
            .await
            .unwrap();
        assert!(Vault::new(key.clone(), Some(path.clone())).await.is_err());
        Vault::migrate_legacy(key, path).await.unwrap();
        assert_eq!(
            vault
                .get("legacy", "KEY")
                .await
                .unwrap()
                .value
                .expose_secret(),
            "fixture-updated"
        );
        fs::remove_dir_all(root).await.unwrap();
    }
}
