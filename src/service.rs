use crate::client::DaemonClient;
use crate::config::AppConfig;
use anyhow::{Context, Result};
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone, clap::Subcommand)]
pub enum ServiceAction {
    #[command(about = "Check supervision status (daemon, systemd, launchd, and cron)")]
    Status,

    #[command(about = "Run health watchdog probe; automatically starts daemon if offline")]
    Watchdog(WatchdogArgs),

    #[command(about = "Install background supervision (systemd user service, launchd, or cron)")]
    Install(InstallServiceArgs),
}

#[derive(Debug, Clone, clap::Args, Default)]
pub struct WatchdogArgs {
    #[arg(long, help = "Suppress normal status output; only log warnings/errors")]
    pub quiet: bool,
}

#[derive(Debug, Clone, clap::Args, Default)]
pub struct InstallServiceArgs {
    #[arg(
        long,
        help = "Supervision backend to install (auto, systemd, cron, or launchd)",
        default_value = "auto"
    )]
    pub backend: String,

    #[arg(long, help = "Preview planned configuration without making changes")]
    pub dry_run: bool,
}

pub async fn run_watchdog(config: &AppConfig, quiet: bool) -> Result<()> {
    let client = DaemonClient::new(config)?;

    // 1. Probe health endpoint
    if let Ok(health) = client.health().await {
        if health.status == "ok" {
            if !quiet {
                println!("✅ agentsec daemon is online and healthy.");
            }
            return Ok(());
        }
    }

    if !quiet {
        eprintln!("⚠️ agentsec daemon is offline or unresponsive. Initiating recovery...");
    }

    // 2. Attempt recovery
    // Try systemd user service first if available and enabled
    let mut recovered_via_systemd = false;
    if is_command_available("systemctl") {
        let is_enabled = Command::new("systemctl")
            .args(["--user", "is-enabled", "agentsec"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if is_enabled {
            if !quiet {
                println!("Restarting daemon via systemctl --user restart agentsec...");
            }
            let _ = Command::new("systemctl")
                .args(["--user", "restart", "agentsec"])
                .status();
            recovered_via_systemd = true;
        }
    }

    if !recovered_via_systemd {
        // Fallback: spawn current executable with `daemon`
        let exe = std::env::current_exe().context("Cannot determine agentsec binary path")?;
        if !quiet {
            println!(
                "Spawning daemon in background using {} daemon...",
                exe.display()
            );
        }

        let mut cmd = Command::new(&exe);
        cmd.arg("daemon");
        cmd.arg("--config-dir").arg(&config.config_dir);

        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        cmd.spawn()
            .with_context(|| format!("Failed to spawn daemon process from {}", exe.display()))?;
    }

    // 3. Poll for up to 10 seconds for health check to report OK
    for _ in 0..20 {
        sleep(Duration::from_millis(500)).await;
        if let Ok(health) = client.health().await {
            if health.status == "ok" {
                if !quiet {
                    println!("✅ agentsec daemon successfully recovered and listening.");
                }
                return Ok(());
            }
        }
    }

    anyhow::bail!(
        "agentsec daemon failed to report healthy within 10 seconds after recovery attempt"
    );
}

pub async fn show_service_status(config: &AppConfig) -> Result<()> {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║             agentsec Supervision & Monitoring            ║");
    println!("╠══════════════════════════════════════════════════════════╣");

    // 1. Daemon HTTP status
    let client = DaemonClient::new(config)?;
    match client.status().await {
        Ok(status) => {
            println!(
                "║ Daemon Status:    ONLINE (PID: {}){:>20} ║",
                status.pid, ""
            );
            println!(
                "║ Endpoint:         http://{:<32} ║",
                format!("{}:{}", status.host, status.port)
            );
            println!(
                "║ Uptime:           {:<38} ║",
                format!("{}s", status.uptime_seconds)
            );
        }
        Err(_) => {
            println!("║ Daemon Status:    OFFLINE (unreachable){:>17} ║", "");
        }
    }

    // 2. Systemd status
    if is_command_available("systemctl") {
        let active = run_cmd_output("systemctl", &["--user", "is-active", "agentsec"])
            .unwrap_or_else(|| "inactive".into());
        let enabled = run_cmd_output("systemctl", &["--user", "is-enabled", "agentsec"])
            .unwrap_or_else(|| "disabled".into());
        println!(
            "║ systemd Service:  {} ({}){:>24} ║",
            active.trim(),
            enabled.trim(),
            ""
        );
    } else {
        println!(
            "║ systemd:          Not available on this platform{:>12} ║",
            ""
        );
    }

    // 3. Cron status
    if is_command_available("crontab") {
        let crontab_out = run_cmd_output("crontab", &["-l"]).unwrap_or_default();
        let has_watchdog = crontab_out.lines().any(|l| {
            let t = l.trim();
            !t.starts_with('#')
                && (t.contains("agentsec service watchdog") || t.contains("agentsec-watchdog"))
        });
        println!(
            "║ cron Watchdog:    {}{:>24} ║",
            if has_watchdog {
                "Configured & Active"
            } else {
                "Not configured"
            },
            ""
        );
    } else {
        println!(
            "║ cron:             Not available on this platform{:>12} ║",
            ""
        );
    }

    // 4. macOS launchd status
    #[cfg(target_os = "macos")]
    {
        let has_launchd = run_cmd_output("launchctl", &["list", "com.agentsec.daemon"]).is_some();
        println!(
            "║ launchd Agent:    {}{:>24} ║",
            if has_launchd {
                "Loaded & Active"
            } else {
                "Not loaded"
            },
            ""
        );
    }

    println!("╚══════════════════════════════════════════════════════════╝");
    println!("\n💡 Tip: Run 'agentsec service watchdog' to verify or start the daemon on demand.");
    println!("💡 Run 'agentsec service install' to set up automatic supervision.");

    Ok(())
}

pub fn install_supervision(backend: &str, dry_run: bool) -> Result<()> {
    let home = directories::BaseDirs::new()
        .context("Cannot determine home directory")?
        .home_dir()
        .to_path_buf();
    let current_exe = std::env::current_exe().context("Cannot determine agentsec binary path")?;

    let target_backend = if backend == "auto" {
        if cfg!(target_os = "macos") {
            "launchd"
        } else if is_command_available("systemctl")
            && run_cmd_output("systemctl", &["--user", "status"]).is_some()
        {
            "systemd"
        } else {
            "cron"
        }
    } else {
        backend
    };

    println!("Installing supervision using backend: {}", target_backend);

    match target_backend {
        "systemd" => {
            let service_dir = home.join(".config/systemd/user");
            let service_file = service_dir.join("agentsec.service");
            let content = format!(
                "[Unit]\n\
                 Description=agentsec secret management daemon\n\
                 Documentation=https://github.com/dkarapetyan-afk/agentsec\n\
                 After=network.target\n\n\
                 [Service]\n\
                 Type=simple\n\
                 ExecStart={}\n\
                 Restart=on-failure\n\
                 RestartSec=5s\n\
                 Environment=RUST_LOG=info\n\n\
                 [Install]\n\
                 WantedBy=default.target\n",
                current_exe.display()
            );

            if dry_run {
                println!("Would create file: {}", service_file.display());
                println!("Content:\n{}", content);
                println!("Would run: systemctl --user daemon-reload");
                println!("Would run: systemctl --user enable --now agentsec");
            } else {
                std::fs::create_dir_all(&service_dir)?;
                std::fs::write(&service_file, content)?;
                println!("✅ Created {}", service_file.display());

                let _ = Command::new("systemctl")
                    .args(["--user", "daemon-reload"])
                    .status();
                let status = Command::new("systemctl")
                    .args(["--user", "enable", "--now", "agentsec"])
                    .status();

                if status.map(|s| s.success()).unwrap_or(false) {
                    println!("✅ systemd user service enabled and started.");
                } else {
                    println!("⚠️ Created unit file. Run 'systemctl --user enable --now agentsec' to activate.");
                }
            }
        }
        "cron" => {
            let cron_line1 = format!(
                "* * * * * {} service watchdog --quiet >> ~/.config/agentsec/watchdog.log 2>&1",
                current_exe.display()
            );
            let cron_line2 = format!(
                "@reboot   {} service watchdog --quiet >> ~/.config/agentsec/watchdog.log 2>&1",
                current_exe.display()
            );

            if dry_run {
                println!("Would append to crontab:\n{}\n{}", cron_line1, cron_line2);
            } else {
                let existing = run_cmd_output("crontab", &["-l"]).unwrap_or_default();
                if existing.contains("agentsec service watchdog") {
                    println!("ℹ️ Watchdog cron entry already exists in crontab.");
                } else {
                    let mut updated = existing;
                    if !updated.is_empty() && !updated.ends_with('\n') {
                        updated.push('\n');
                    }
                    updated.push_str("# agentsec secret manager daemon watchdog\n");
                    updated.push_str(&cron_line1);
                    updated.push('\n');
                    updated.push_str(&cron_line2);
                    updated.push('\n');

                    let mut child = Command::new("crontab")
                        .stdin(Stdio::piped())
                        .spawn()
                        .context("Failed to spawn crontab command")?;

                    if let Some(mut stdin) = child.stdin.take() {
                        use std::io::Write;
                        stdin.write_all(updated.as_bytes())?;
                    }
                    let res = child.wait()?;
                    if res.success() {
                        println!("✅ Added periodic watchdog monitoring tasks to crontab.");
                    } else {
                        anyhow::bail!("Failed to update crontab");
                    }
                }
            }
        }
        "launchd" => {
            let launch_dir = home.join("Library/LaunchAgents");
            let plist_file = launch_dir.join("com.agentsec.daemon.plist");
            let content = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                 <plist version=\"1.0\">\n\
                 <dict>\n\
                     <key>Label</key>\n\
                     <string>com.agentsec.daemon</string>\n\
                     <key>ProgramArguments</key>\n\
                     <array>\n\
                         <string>{}</string>\n\
                         <string>daemon</string>\n\
                     </array>\n\
                     <key>RunAtLoad</key>\n\
                     <true/>\n\
                     <key>KeepAlive</key>\n\
                     <true/>\n\
                 </dict>\n\
                 </plist>\n",
                current_exe.display()
            );

            if dry_run {
                println!("Would create file: {}", plist_file.display());
                println!("Content:\n{}", content);
            } else {
                std::fs::create_dir_all(&launch_dir)?;
                std::fs::write(&plist_file, content)?;
                let _ = Command::new("launchctl")
                    .arg("load")
                    .arg(&plist_file)
                    .status();
                println!(
                    "✅ Installed and loaded launchd agent at {}",
                    plist_file.display()
                );
            }
        }
        other => anyhow::bail!(
            "Unsupported backend: '{}'. Use systemd, cron, launchd, or auto",
            other
        ),
    }

    Ok(())
}

fn is_command_available(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_cmd_output(cmd: &str, args: &[&str]) -> Option<String> {
    Command::new(cmd).args(args).output().ok().and_then(|o| {
        if o.status.success() {
            String::from_utf8(o.stdout).ok()
        } else {
            None
        }
    })
}
