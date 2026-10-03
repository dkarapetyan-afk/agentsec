use agentsec::cli::{Cli, Commands};
use agentsec::client::DaemonClient;
use agentsec::config::{detect_workspace_namespace, AppConfig};
use agentsec::crypto::get_or_create_master_key;
use agentsec::runner::{run_with_secrets, RunOptions};
use agentsec::scanner::scan_workspace;
use agentsec::server::start_server;
use agentsec::store::Vault;
use anyhow::Result;
use clap::Parser;
use std::io::{self, IsTerminal, Read};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Configure logging: show info for daemon, warn/error for CLI unless RUST_LOG is set
    let default_level = match &cli.command {
        Commands::Daemon(_) => Level::INFO,
        _ => Level::WARN,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(default_level)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level.as_str())),
        )
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let config = AppConfig::load(cli.config_dir.clone(), cli.port)?;

    match cli.command {
        Commands::Daemon(daemon_args) => {
            let master_key = get_or_create_master_key(&config.master_key_path)?;
            let vault_path = if daemon_args.ephemeral {
                None
            } else {
                Some(config.vault_path.clone())
            };

            let vault = Vault::new(master_key, vault_path.clone())?;
            let token = config.get_or_create_auth_token()?;

            println!("╔══════════════════════════════════════════════════════════╗");
            println!("║              agentsec Secret Manager Daemon              ║");
            println!("╠══════════════════════════════════════════════════════════╣");
            println!("║ Status:     Active & Listening                           ║");
            println!("║ Address:    http://{:<36} ║", format!("{}:{}", config.host, config.port));
            println!("║ Storage:    {:<44} ║", if daemon_args.ephemeral { "Ephemeral RAM-only" } else { "AES-256 / ChaCha20 Encrypted Vault" });
            if let Some(ref path) = vault_path {
                let path_str = path.to_string_lossy();
                let short_path = if path_str.len() > 40 {
                    format!("...{}", &path_str[path_str.len() - 37..])
                } else {
                    path_str.to_string()
                };
                println!("║ Vault File: {:<44} ║", short_path);
            }
            println!("║ Auth Token: {:<44} ║", format!("{}...{}", &token[..8], &token[token.len() - 8..]));
            println!("╚══════════════════════════════════════════════════════════╝");

            start_server(config, vault, token).await?;
        }

        Commands::Status => {
            let client = DaemonClient::new(&config)?;
            match client.status().await {
                Ok(status) => {
                    println!("Daemon Status:    ONLINE");
                    println!("Process ID:       {}", status.pid);
                    println!("Version:          {}", status.version);
                    println!("Endpoint:         http://{}:{}", status.host, status.port);
                    println!("Uptime:           {}s", status.uptime_seconds);
                    println!("Namespaces:       {}", status.stats.namespaces_count);
                    println!("Active Secrets:   {}", status.stats.active_secrets_count);
                    println!("Storage Mode:     {}", if status.stats.is_ephemeral { "Ephemeral (RAM only)" } else { "Encrypted On-Disk Vault" });
                    if let Some(path) = status.stats.vault_path {
                        println!("Vault Location:   {}", path);
                    }
                }
                Err(e) => {
                    eprintln!("❌ {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Set(args) => {
            let client = DaemonClient::new(&config)?;
            let namespace = args
                .namespace
                .unwrap_or_else(|| detect_workspace_namespace(None));

            let value = if let Some(val) = args.value {
                val
            } else {
                // Read from stdin if piped
                if !atty_is_terminal() {
                    let mut buffer = String::new();
                    io::stdin().read_to_string(&mut buffer)?;
                    buffer.trim_end().to_string()
                } else {
                    // Prompt user securely
                    eprint!("Enter secret value for '{}': ", args.key);
                    let mut line = String::new();
                    io::stdin().read_line(&mut line)?;
                    line.trim_end().to_string()
                }
            };

            if value.is_empty() {
                eprintln!("❌ Error: secret value cannot be empty.");
                std::process::exit(1);
            }

            match client
                .set_secret(
                    &namespace,
                    &args.key,
                    &value,
                    args.description,
                    args.tag,
                    args.ttl,
                )
                .await
            {
                Ok(meta) => {
                    println!("✅ Secret '{}' stored securely in namespace '{}'", meta.name, meta.namespace);
                    println!("   Masked Preview: {}", meta.masked_preview);
                    if let Some(desc) = meta.description {
                        println!("   Description:    {}", desc);
                    }
                    if let Some(exp) = meta.expires_at {
                        println!("   Expires At:     {}", exp.to_rfc3339());
                    }
                }
                Err(e) => {
                    eprintln!("❌ Failed to store secret: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Get(args) => {
            let client = DaemonClient::new(&config)?;
            let namespace = args
                .namespace
                .unwrap_or_else(|| detect_workspace_namespace(None));

            match client.get_secret(&namespace, &args.key).await {
                Ok(detail) => {
                    if args.raw {
                        print!("{}", detail.value);
                    } else {
                        println!("Key:            {}", detail.name);
                        println!("Namespace:      {}", detail.namespace);
                        println!("Masked Preview: {}", detail.metadata.masked_preview);
                        if let Some(desc) = detail.metadata.description {
                            println!("Description:    {}", desc);
                        }
                        if !detail.metadata.tags.is_empty() {
                            println!("Tags:           {}", detail.metadata.tags.join(", "));
                        }
                        println!("Created At:     {}", detail.metadata.created_at.to_rfc3339());
                        println!("Updated At:     {}", detail.metadata.updated_at.to_rfc3339());
                        if let Some(exp) = detail.metadata.expires_at {
                            println!("Expires At:     {}", exp.to_rfc3339());
                        }
                        println!("\n💡 Tip: pass '--raw' to output the secret value directly for scripts.");
                    }
                }
                Err(e) => {
                    eprintln!("❌ {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::List(args) => {
            let client = DaemonClient::new(&config)?;

            if args.all_namespaces {
                match client.list_namespaces().await {
                    Ok(namespaces) => {
                        println!("Found {} namespace(s):", namespaces.len());
                        for ns in namespaces {
                            println!("  • {}", ns);
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                let namespace = args
                    .namespace
                    .unwrap_or_else(|| detect_workspace_namespace(None));

                match client.list_secrets(&namespace).await {
                    Ok(secrets) => {
                        if secrets.is_empty() {
                            println!("No secrets found in namespace '{}'.", namespace);
                        } else {
                            println!("Secrets in namespace '{}' ({} total):", namespace, secrets.len());
                            println!("{:<24} {:<24} {:<24}", "NAME", "PREVIEW", "EXPIRES");
                            println!("{}", "─".repeat(72));
                            for s in secrets {
                                let exp_str = match s.expires_at {
                                    Some(exp) => exp.format("%Y-%m-%d %H:%M").to_string(),
                                    None => "Never".to_string(),
                                };
                                println!("{:<24} {:<24} {:<24}", s.name, s.masked_preview, exp_str);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }

        Commands::Delete(args) => {
            let client = DaemonClient::new(&config)?;
            let namespace = args
                .namespace
                .unwrap_or_else(|| detect_workspace_namespace(None));

            if args.all_namespace {
                match client.delete_namespace(&namespace).await {
                    Ok(count) => {
                        println!("🗑️ Deleted entire namespace '{}' ({} secret(s) removed)", namespace, count);
                    }
                    Err(e) => {
                        eprintln!("❌ {}", e);
                        std::process::exit(1);
                    }
                }
            } else if let Some(key) = args.key {
                match client.delete_secret(&namespace, &key).await {
                    Ok(deleted) => {
                        if deleted {
                            println!("🗑️ Deleted secret '{}' from namespace '{}'", key, namespace);
                        } else {
                            println!("ℹ️ Secret '{}' not found in namespace '{}'", key, namespace);
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("❌ Please specify a secret key to delete, or pass '--all-namespace'.");
                std::process::exit(1);
            }
        }

        Commands::Run(args) => {
            let client = DaemonClient::new(&config)?;
            let namespace = args
                .namespace
                .unwrap_or_else(|| detect_workspace_namespace(None));

            let options = RunOptions {
                namespace,
                command: args.command,
                clean_env: args.clean_env,
            };

            match run_with_secrets(&client, options).await {
                Ok(code) => {
                    if code != 0 {
                        std::process::exit(code);
                    }
                }
                Err(e) => {
                    eprintln!("❌ Error running command with secrets: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::Mcp => {
            let client = DaemonClient::new(&config)?;
            agentsec::mcp::run_mcp_server(client).await?;
        }

        Commands::Token(args) => {
            if args.rotate {
                let _ = std::fs::remove_file(&config.token_path);
                let new_token = config.get_or_create_auth_token()?;
                println!("🔑 Rotated API Auth Token:");
                println!("{}", new_token);
            } else {
                let token = config.get_or_create_auth_token()?;
                println!("🔑 Active Daemon API Auth Token:");
                println!("{}", token);
            }
        }

        Commands::Scan(args) => {
            let client = DaemonClient::new(&config)?;
            let namespace = args
                .namespace
                .unwrap_or_else(|| detect_workspace_namespace(None));

            let leaks = scan_workspace(&client, &namespace, args.target_dir).await?;
            if leaks > 0 {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

fn atty_is_terminal() -> bool {
    io::stdin().is_terminal()
}
