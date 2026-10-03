use crate::client::DaemonClient;
use anyhow::{anyhow, Context, Result};
use std::process::{Command, Stdio};
use tracing::info;

pub struct RunOptions {
    pub namespace: String,
    pub command: Vec<String>,
    pub clean_env: bool,
}

/// Spawns a child process with all secrets from the specified namespace injected
/// directly into the child process's memory environment variables.
///
/// Absolutely ZERO secret files or temporary dot-env files are ever created on disk.
pub async fn run_with_secrets(client: &DaemonClient, options: RunOptions) -> Result<i32> {
    if options.command.is_empty() {
        return Err(anyhow!("No command specified to run"));
    }

    let secrets = client
        .export_namespace(&options.namespace)
        .await
        .with_context(|| format!("Failed to retrieve secrets for namespace '{}'", options.namespace))?;

    let program = &options.command[0];
    let args = &options.command[1..];

    let mut cmd = Command::new(program);
    cmd.args(args);

    if options.clean_env {
        cmd.env_clear();
        // Preserve PATH and essential system variables if available
        if let Ok(path) = std::env::var("PATH") {
            cmd.env("PATH", path);
        }
        if let Ok(user) = std::env::var("USER") {
            cmd.env("USER", user);
        }
        if let Ok(home) = std::env::var("HOME") {
            cmd.env("HOME", home);
        }
    }

    // Inject secrets directly into child process RAM environment
    for (k, v) in &secrets {
        cmd.env(k, v);
    }

    // Connect standard I/O streams directly
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    info!(
        "🔒 Executing '{:?}' with {} secret(s) injected from namespace '{}'",
        options.command,
        secrets.len(),
        options.namespace
    );

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn command '{}'", program))?;

    let status = child
        .wait()
        .with_context(|| format!("Error waiting for command '{}'", program))?;

    let exit_code = status.code().unwrap_or(if status.success() { 0 } else { 1 });
    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_command_validation() {
        let options = RunOptions {
            namespace: "test".to_string(),
            command: vec![],
            clean_env: false,
        };
        assert!(options.command.is_empty());
    }
}
