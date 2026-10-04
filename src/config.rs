use anyhow::{Context, Result};
use directories::ProjectDirs;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub const DEFAULT_PORT: u16 = 52199;
pub const DEFAULT_HOST: &str = "127.0.0.1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonInfo {
    pub pid: u32,
    pub port: u16,
    pub host: String,
    pub socket_path: PathBuf,
    pub started_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub vault_path: PathBuf,
    pub master_key_path: PathBuf,
    pub token_path: PathBuf,
    pub socket_path: PathBuf,
    pub daemon_info_path: PathBuf,
    pub tunnel_url_path: PathBuf,
    pub port: u16,
    pub host: String,
    pub custom_url: Option<String>,
    pub custom_token: Option<String>,
}

impl AppConfig {
    pub fn load(custom_config_dir: Option<PathBuf>, custom_port: Option<u16>) -> Result<Self> {
        Self::load_with_overrides(custom_config_dir, custom_port, None, None)
    }

    pub fn load_with_overrides(
        custom_config_dir: Option<PathBuf>,
        custom_port: Option<u16>,
        custom_url: Option<String>,
        custom_token: Option<String>,
    ) -> Result<Self> {
        let (config_dir, data_dir) = if let Some(dir) = custom_config_dir {
            (dir.clone(), dir)
        } else if let Ok(env_dir) = std::env::var("AGENTSEC_CONFIG_DIR") {
            let p = PathBuf::from(env_dir);
            (p.clone(), p)
        } else if let Some(proj_dirs) = ProjectDirs::from("com", "antigravity", "agentsec") {
            (
                proj_dirs.config_dir().to_path_buf(),
                proj_dirs.data_local_dir().to_path_buf(),
            )
        } else {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let base = PathBuf::from(home).join(".config").join("agentsec");
            (base.clone(), base)
        };

        fs::create_dir_all(&config_dir)
            .with_context(|| format!("Failed to create config dir: {:?}", config_dir))?;
        fs::create_dir_all(&data_dir)
            .with_context(|| format!("Failed to create data dir: {:?}", data_dir))?;

        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700));
            let _ = fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700));
        }

        let vault_path = config_dir.join("vault.enc");
        let master_key_path = config_dir.join("master.key");
        let token_path = config_dir.join("token");
        let socket_path = data_dir.join("daemon.sock");
        let daemon_info_path = data_dir.join("daemon.json");
        let tunnel_url_path = config_dir.join("tunnel.url");

        let port = custom_port
            .or_else(|| {
                std::env::var("AGENTSEC_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
            })
            .unwrap_or(DEFAULT_PORT);

        let host = std::env::var("AGENTSEC_HOST").unwrap_or_else(|_| DEFAULT_HOST.to_string());

        let url = custom_url
            .or_else(|| std::env::var("AGENTSEC_URL").ok())
            .or_else(|| std::env::var("AGENTSEC_SERVER_URL").ok());

        let token_override = custom_token
            .or_else(|| std::env::var("AGENTSEC_TOKEN").ok());

        Ok(Self {
            config_dir,
            data_dir,
            vault_path,
            master_key_path,
            token_path,
            socket_path,
            daemon_info_path,
            tunnel_url_path,
            port,
            host,
            custom_url: url,
            custom_token: token_override,
        })
    }

    /// Retrieve or generate the persistent API authentication token
    pub fn get_or_create_auth_token(&self) -> Result<String> {
        if let Some(ref t) = self.custom_token {
            let trimmed = t.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }

        if self.token_path.exists() {
            let token = fs::read_to_string(&self.token_path)?;
            let token = token.trim().to_string();
            if !token.is_empty() {
                return Ok(token);
            }
        }

        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = hex::encode(bytes);

        fs::write(&self.token_path, &token)
            .with_context(|| format!("Failed to write token file: {:?}", self.token_path))?;

        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&self.token_path, fs::Permissions::from_mode(0o600));
        }

        Ok(token)
    }

    /// Read the active Cloudflare tunnel URL if recorded
    pub fn read_tunnel_url(&self) -> Option<String> {
        if self.tunnel_url_path.exists() {
            if let Ok(content) = fs::read_to_string(&self.tunnel_url_path) {
                let trimmed = content.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
        None
    }

    /// Save the active Cloudflare tunnel URL
    pub fn write_tunnel_url(&self, url: &str) -> Result<()> {
        fs::write(&self.tunnel_url_path, url.trim())?;
        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&self.tunnel_url_path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Save the active daemon process metadata
    pub fn write_daemon_info(&self, info: &DaemonInfo) -> Result<()> {
        let content = serde_json::to_string_pretty(info)?;
        fs::write(&self.daemon_info_path, content)?;
        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&self.daemon_info_path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Read the active daemon process metadata if present
    pub fn read_daemon_info(&self) -> Result<Option<DaemonInfo>> {
        if !self.daemon_info_path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&self.daemon_info_path)?;
        let info: DaemonInfo = serde_json::from_str(&content)?;
        Ok(Some(info))
    }

    /// Remove the active daemon process metadata
    pub fn remove_daemon_info(&self) {
        let _ = fs::remove_file(&self.daemon_info_path);
        let _ = fs::remove_file(&self.socket_path);
        let _ = fs::remove_file(&self.tunnel_url_path);
    }
}

/// Automatically detects the current workspace namespace based on Git repository root or directory
pub fn detect_workspace_namespace(start_dir: Option<&Path>) -> String {
    let cwd = match start_dir {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };

    // Traverse upwards to find .git directory or file (worktrees)
    let mut current = cwd.as_path();
    loop {
        let git_marker = current.join(".git");
        if git_marker.exists() {
            if let Some(folder_name) = current.file_name().and_then(|n| n.to_str()) {
                return format!("repo:{}", folder_name);
            }
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => break,
        }
    }

    // Fallback: directory name
    if let Some(name) = cwd.file_name().and_then(|n| n.to_str()) {
        if !name.is_empty() {
            return format!("ws:{}", name);
        }
    }

    "default".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_detect_workspace_namespace() {
        let ns = detect_workspace_namespace(None);
        assert!(!ns.is_empty());
    }

    #[test]
    fn test_token_creation() {
        let temp_dir = env::temp_dir().join(format!("agentsec_test_{}", rand::random::<u64>()));
        let config = AppConfig::load(Some(temp_dir.clone()), Some(53100)).unwrap();
        let token1 = config.get_or_create_auth_token().unwrap();
        assert_eq!(token1.len(), 64);
        let token2 = config.get_or_create_auth_token().unwrap();
        assert_eq!(token1, token2);
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
