use crate::backend::ClientBackend;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub async fn scan_workspace(
    client: &(impl Into<ClientBackend> + Clone),
    namespace: &str,
    target_dir: Option<PathBuf>,
) -> Result<usize> {
    let backend: ClientBackend = client.clone().into();
    let dir = target_dir.unwrap_or_else(|| PathBuf::from("."));
    println!(
        "🔍 Scanning directory {:?} for potential leaks of secrets from namespace '{}'...",
        dir, namespace
    );

    let secrets = backend
        .export_namespace(namespace)
        .await
        .with_context(|| format!("Failed to retrieve secrets for namespace '{}'", namespace))?;

    if secrets.is_empty() {
        println!(
            "ℹ️ No secrets found in namespace '{}' to scan for.",
            namespace
        );
        return Ok(0);
    }

    // Filter out very short secrets to avoid false positives (minimum 6 chars)
    let check_secrets: Vec<(&String, &String)> = secrets
        .iter()
        .filter(|(_k, v)| v.trim().len() >= 6)
        .collect();

    let mut leak_count = 0;
    scan_dir_recursive(&dir, &check_secrets, &mut leak_count)?;

    if leak_count == 0 {
        println!("✅ Clean! No stored secrets detected in workspace files.");
    } else {
        eprintln!(
            "\n🚨 CRITICAL: Found {} potential secret leak(s) in workspace files!\n\
            Immediate action required: Remove raw credentials from files and use 'agentsec run' instead.",
            leak_count
        );
    }

    Ok(leak_count)
}

fn scan_dir_recursive(
    dir: &Path,
    secrets: &[(&String, &String)],
    leak_count: &mut usize,
) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // Skip ignored directories and files
        if file_name == ".git"
            || file_name == "node_modules"
            || file_name == "target"
            || file_name == ".cargo"
            || file_name == "dist"
            || file_name == "build"
            || file_name == ".vault"
            || file_name.ends_with(".enc")
        {
            continue;
        }

        if path.is_dir() {
            scan_dir_recursive(&path, secrets, leak_count)?;
        } else if path.is_file() {
            // Check file size (skip files > 5MB)
            if let Ok(meta) = entry.metadata() {
                if meta.len() > 5 * 1024 * 1024 {
                    continue;
                }
            }

            if let Ok(content) = fs::read_to_string(&path) {
                for (line_idx, line) in content.lines().enumerate() {
                    for (key, secret_val) in secrets {
                        if line.contains(secret_val.as_str()) {
                            *leak_count += 1;
                            eprintln!(
                                "🚨 LEAK FOUND: {:?}:{}: matches secret key '{}'",
                                path,
                                line_idx + 1,
                                key
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
