use agentsec::cli::{Cli, Commands, TokenAction};
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

    // Skill operations need neither daemon credentials nor a configuration-directory write.
    match &cli.command {
        Commands::Skill(args) => {
            let locations = agentsec::setup::SkillLocations::from_environment()?;
            match &args.action {
                Some(agentsec::cli::SkillAction::List) => {
                    println!("Known Agent Skill Locations:");
                    println!("{:<24} {:<12} {:<}", "AGENT", "STATUS", "PATH");
                    println!("{}", "─".repeat(70));
                    for (label, path) in locations.all_known_targets() {
                        let installed = agentsec::setup::check_skill_installed(path);
                        println!(
                            "{:<24} {:<12} {}",
                            label,
                            if installed { "Installed" } else { "Missing" },
                            path.display()
                        );
                    }
                    return Ok(());
                }
                Some(agentsec::cli::SkillAction::Install(install_args)) => {
                    let targets = agentsec::setup::resolve_targets(
                        &locations,
                        &install_args.agent,
                        install_args.target.as_deref(),
                    );
                    for (label, path) in
                        agentsec::setup::install_to_targets(&targets, install_args.dry_run)?
                    {
                        println!(
                            "{}: {} ({})",
                            if install_args.dry_run {
                                "Would install"
                            } else {
                                "Installed"
                            },
                            label,
                            path.display()
                        );
                    }
                    println!("Reload agent skills after installation. MCP stdio: command=agentsec, args=[mcp].");
                    return Ok(());
                }
                None => {
                    let targets = agentsec::setup::resolve_targets(
                        &locations,
                        &args.agent,
                        args.target.as_deref(),
                    );
                    for (label, path) in
                        agentsec::setup::install_to_targets(&targets, args.dry_run)?
                    {
                        println!(
                            "{}: {} ({})",
                            if args.dry_run {
                                "Would install"
                            } else {
                                "Installed"
                            },
                            label,
                            path.display()
                        );
                    }
                    println!("Reload agent skills after installation. MCP stdio: command=agentsec, args=[mcp].");
                    return Ok(());
                }
            }
        }
        Commands::Setup(args) => {
            let locations = agentsec::setup::SkillLocations::from_environment()?;
            for label in agentsec::setup::install(&locations, args.resolved_agent(), args.dry_run)?
            {
                println!(
                    "{}: {}",
                    if args.dry_run {
                        "Would update"
                    } else {
                        "Updated"
                    },
                    label
                );
            }
            println!("Reload agent skills after installation. MCP stdio: command=agentsec, args=[mcp]. Existing MCP configuration is not overwritten.");
            return Ok(());
        }
        _ => {}
    }

    let mut config = AppConfig::load_with_overrides(
        cli.config_dir.clone(),
        cli.port,
        cli.url.clone(),
        cli.token.clone(),
    )?;
    if let Some(host) = cli.host {
        config.host = host;
    }

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
            let tunnel_url = config.read_tunnel_url();

            println!("╔══════════════════════════════════════════════════════════╗");
            println!("║              agentsec Secret Manager Daemon              ║");
            println!("╠══════════════════════════════════════════════════════════╣");
            println!("║ Status:     Active & Listening                           ║");
            println!(
                "║ Address:    http://{:<36} ║",
                format!("{}:{}", config.host, config.port)
            );
            if let Some(ref tunnel) = tunnel_url {
                let short_tunnel = if tunnel.len() > 44 {
                    format!("{}...", &tunnel[..41])
                } else {
                    tunnel.clone()
                };
                println!("║ Tunnel URL: {:<44} ║", short_tunnel);
            }
            println!(
                "║ Storage:    {:<44} ║",
                if daemon_args.ephemeral {
                    "Ephemeral RAM-only"
                } else {
                    "ChaCha20-Poly1305 Encrypted Vault"
                }
            );
            if vault_path.is_some() {
                println!(
                    "║ Vault File: {:<44} ║",
                    "Configured private storage location"
                );
            }
            println!(
                "║ Auth Token: {:<44} ║",
                agentsec::secret::mask_secret(&token)
            );
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
                    if let Some(ref tunnel) = status.tunnel_url {
                        println!("Tunnel URL:       {}", tunnel);
                    }
                    println!("Uptime:           {}s", status.uptime_seconds);
                    println!("Namespaces:       {}", status.stats.namespaces_count);
                    println!("Active Secrets:   {}", status.stats.active_secrets_count);
                    println!(
                        "Storage Mode:     {}",
                        if status.stats.is_ephemeral {
                            "Ephemeral (RAM only)"
                        } else {
                            "Encrypted On-Disk Vault"
                        }
                    );
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
                    // Hide terminal echo; fail closed if the platform cannot do so.
                    eprint!("Enter secret value for '{}': ", args.key);
                    let _hidden = HiddenInput::new()?;
                    let mut line = String::new();
                    io::stdin().read_line(&mut line)?;
                    eprintln!();
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
                    println!(
                        "✅ Secret '{}' stored securely in namespace '{}'",
                        meta.name, meta.namespace
                    );
                    println!("   Masked Preview: {}", meta.masked_preview);
                    if let Some(desc) = &meta.description {
                        println!("   Description:    {}", desc);
                    }
                    if let Some(exp) = meta.expires_at {
                        println!("   Expires At:     {}", exp.to_rfc3339());
                        println!(
                            "   Remaining TTL:  {}s",
                            meta.remaining_ttl_seconds().unwrap_or(0)
                        );
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
                        if let Some(desc) = &detail.metadata.description {
                            println!("Description:    {}", desc);
                        }
                        if !detail.metadata.tags.is_empty() {
                            println!("Tags:           {}", detail.metadata.tags.join(", "));
                        }
                        println!(
                            "Created At:     {}",
                            detail.metadata.created_at.to_rfc3339()
                        );
                        println!(
                            "Updated At:     {}",
                            detail.metadata.updated_at.to_rfc3339()
                        );
                        if let Some(exp) = detail.metadata.expires_at {
                            println!("Expires At:     {}", exp.to_rfc3339());
                            println!(
                                "Remaining TTL:  {}s",
                                detail.metadata.remaining_ttl_seconds().unwrap_or(0)
                            );
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
                            println!(
                                "Secrets in namespace '{}' ({} total):",
                                namespace,
                                secrets.len()
                            );
                            println!(
                                "{:<24} {:<24} {:<24} {:<12}",
                                "NAME", "PREVIEW", "EXPIRES", "TTL LEFT"
                            );
                            println!("{}", "─".repeat(72));
                            for s in secrets {
                                let exp_str = match s.expires_at {
                                    Some(exp) => exp.format("%Y-%m-%d %H:%M").to_string(),
                                    None => "Never".to_string(),
                                };
                                let ttl = s
                                    .remaining_ttl_seconds()
                                    .map(|v| format!("{}s", v))
                                    .unwrap_or_else(|| "Permanent".into());
                                println!(
                                    "{:<24} {:<24} {:<24} {:<12}",
                                    s.name, s.masked_preview, exp_str, ttl
                                );
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
                        println!(
                            "🗑️ Deleted entire namespace '{}' ({} secret(s) removed)",
                            namespace, count
                        );
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
                only: args.only,
                redact: !args.no_redact,
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
            let action = if let Some(act) = args.action {
                Some(act)
            } else if let Some(name) = args.create {
                Some(TokenAction::Create(agentsec::cli::CreateTokenArgs {
                    name,
                    description: args.description,
                    ttl: args.ttl,
                    namespace: args.namespace,
                    permission: args.permission,
                    key: args.key,
                }))
            } else if args.list {
                Some(TokenAction::List)
            } else {
                args.revoke
                    .map(|name| TokenAction::Revoke(agentsec::cli::RevokeTokenArgs { name }))
            };

            match action {
                Some(TokenAction::Create(create_args)) => {
                    let client = DaemonClient::new(&config)?;
                    match client
                        .create_client_token_with_policy(
                            &create_args.name,
                            create_args.description,
                            create_args.ttl,
                            create_args.namespace,
                            create_args.permission,
                            create_args.key,
                        )
                        .await
                    {
                        Ok(token) => {
                            println!("🔑 Created Client Token '{}':", token.name);
                            println!("   Token:          {}", token.token);
                            println!("   Masked Preview: {}", token.masked_preview);
                            println!("   Permissions:    {:?}", token.permissions);
                            println!(
                                "   Allowed Keys:   {}",
                                if token.keys.is_empty() {
                                    "*".into()
                                } else {
                                    token.keys.join(", ")
                                }
                            );
                            if let Some(desc) = &token.description {
                                println!("   Description:    {}", desc);
                            }
                            if token.namespaces.is_empty() {
                                println!("   Namespaces:     * (All namespaces)");
                            } else {
                                println!("   Namespaces:     {}", token.namespaces.join(", "));
                            }
                            let exp_str = match token.expires_at {
                                Some(exp) => exp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                                None => "Never (Permanent)".to_string(),
                            };
                            println!("   Expires At:     {}", exp_str);
                            println!("\n💡 Tip: Use with 'agentsec --token <TOKEN> <COMMAND>' or Bearer auth header.");
                        }
                        Err(e) => {
                            eprintln!("❌ Failed to create token: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                Some(TokenAction::List) => {
                    let client = DaemonClient::new(&config)?;
                    match client.list_client_tokens().await {
                        Ok(tokens) => {
                            if tokens.is_empty() {
                                println!("No named client tokens registered.");
                                println!("💡 Create one with: agentsec token create <name>");
                            } else {
                                println!("Named Client Tokens ({} total):", tokens.len());
                                println!(
                                    "{:<20} {:<16} {:<24} {:<24}",
                                    "NAME", "PREVIEW", "NAMESPACES", "EXPIRES"
                                );
                                println!("{}", "─".repeat(84));
                                for t in tokens {
                                    let exp_str = match t.expires_at {
                                        Some(exp) => exp.format("%Y-%m-%d %H:%M").to_string(),
                                        None => "Never".to_string(),
                                    };
                                    let ns_str = if t.namespaces.is_empty() {
                                        "*".to_string()
                                    } else {
                                        t.namespaces.join(", ")
                                    };
                                    println!(
                                        "{:<20} {:<16} {:<24} {:<24}",
                                        t.name, t.masked_preview, ns_str, exp_str
                                    );
                                    println!(
                                        "  permissions: {:?}; keys: {}; TTL left: {}",
                                        t.permissions,
                                        if t.keys.is_empty() {
                                            "*".into()
                                        } else {
                                            t.keys.join(",")
                                        },
                                        t.remaining_ttl_seconds
                                            .map(|v| format!("{}s", v))
                                            .unwrap_or_else(|| "Permanent".into())
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("❌ Failed to list tokens: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                Some(TokenAction::Revoke(revoke_args)) => {
                    let client = DaemonClient::new(&config)?;
                    match client.revoke_client_token(&revoke_args.name).await {
                        Ok(revoked) => {
                            if revoked {
                                println!(
                                    "🗑️ Successfully revoked client token '{}'",
                                    revoke_args.name
                                );
                            } else {
                                println!("ℹ️ Client token '{}' was not found", revoke_args.name);
                            }
                        }
                        Err(e) => {
                            eprintln!("❌ Failed to revoke token: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                Some(TokenAction::Renew(renew_args)) => {
                    let metadata = DaemonClient::new(&config)?
                        .renew_client_token(&renew_args.name, renew_args.ttl)
                        .await?;
                    println!(
                        "Renewed client token '{}'; remaining TTL: {}s",
                        metadata.name,
                        metadata.remaining_ttl_seconds.unwrap_or(0)
                    );
                }
                None => {
                    if args.rotate {
                        let new_token = DaemonClient::new(&config)?.rotate_master_token().await?;
                        println!("🔑 Rotated API Auth Token:");
                        println!("{}", new_token);
                    } else {
                        let token = config.get_or_create_auth_token()?;
                        println!("🔑 Active Daemon API Auth Token:");
                        println!("{}", token);
                    }
                }
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

        Commands::Renew(args) => {
            let namespace = args
                .namespace
                .unwrap_or_else(|| detect_workspace_namespace(None));
            let metadata = DaemonClient::new(&config)?
                .renew_secret(&namespace, &args.key, args.ttl)
                .await?;
            println!(
                "Renewed '{}' in '{}'; remaining TTL: {}s",
                metadata.name,
                namespace,
                metadata.remaining_ttl_seconds().unwrap_or(0)
            );
        }
        Commands::Audit(args) => {
            let events = DaemonClient::new(&config)?
                .audit_events(args.limit.min(1000))
                .await?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else {
                for event in events {
                    println!(
                        "{} {} {} {} {} {}",
                        event.timestamp.to_rfc3339(),
                        event.client,
                        event.operation,
                        event.namespace.as_deref().unwrap_or("-"),
                        event.key.as_deref().unwrap_or("-"),
                        event.outcome
                    );
                }
            }
        }
        Commands::Doctor(args) => {
            let namespace = args
                .namespace
                .unwrap_or_else(|| detect_workspace_namespace(None));
            let report = agentsec::doctor::diagnose(
                &DaemonClient::new(&config)?,
                &namespace,
                args.required_keys,
            )
            .await;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Namespace: {}", report.namespace);
                for check in &report.checks {
                    println!(
                        "{} {}: {}",
                        if check.passed { "PASS" } else { "FAIL" },
                        check.name,
                        check.detail
                    );
                }
            }
            if !report.ok {
                std::process::exit(1);
            }
        }
        Commands::Service(args) => match &args.action {
            agentsec::service::ServiceAction::Status => {
                agentsec::service::show_service_status(&config).await?;
            }
            agentsec::service::ServiceAction::Watchdog(watchdog_args) => {
                agentsec::service::run_watchdog(&config, watchdog_args.quiet).await?;
            }
            agentsec::service::ServiceAction::Install(install_args) => {
                agentsec::service::install_supervision(
                    &install_args.backend,
                    install_args.dry_run,
                )?;
            }
        },
        Commands::Setup(_) | Commands::Skill(_) => {
            unreachable!("Skill operations are handled before configuration loading")
        }
    }

    Ok(())
}

fn atty_is_terminal() -> bool {
    io::stdin().is_terminal()
}

struct HiddenInput;
impl HiddenInput {
    fn new() -> Result<Self> {
        #[cfg(unix)]
        {
            let status = std::process::Command::new("stty")
                .arg("-echo")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()?;
            anyhow::ensure!(
                status.success(),
                "Cannot disable terminal echo; supply the value through stdin instead"
            );
            Ok(Self)
        }
        #[cfg(not(unix))]
        {
            anyhow::bail!("Supply the secret value through stdin; hidden terminal input is unavailable on this platform");
        }
    }
}
impl Drop for HiddenInput {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let _ = std::process::Command::new("stty")
                .arg("echo")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
}
