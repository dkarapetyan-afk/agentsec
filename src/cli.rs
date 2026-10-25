use crate::token::Permission;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "agentsec",
    author = "Antigravity Team",
    version,
    about = "Secure namespaced secret management daemon and CLI for coding agents",
    long_about = "agentsec provides an isolated, encrypted secret store and local daemon so coding agents\n\
                  can securely access and inject API keys and credentials without writing .env files to disk."
)]
pub struct Cli {
    #[arg(
        short,
        long,
        global = true,
        help = "Path to custom configuration directory"
    )]
    pub config_dir: Option<PathBuf>,

    #[arg(long, global = true, help = "Daemon host address override")]
    pub host: Option<String>,

    #[arg(short, long, global = true, help = "Daemon port override")]
    pub port: Option<u16>,

    #[arg(
        long,
        global = true,
        env = "AGENTSEC_URL",
        help = "Remote daemon or tunnel URL override (e.g. https://xxx.trycloudflare.com)"
    )]
    pub url: Option<String>,

    #[arg(
        long,
        global = true,
        env = "AGENTSEC_TOKEN",
        hide_env_values = true,
        help = "Authentication token for connecting to the daemon"
    )]
    pub token: Option<String>,

    #[arg(
        long,
        short = 'D',
        global = true,
        env = "AGENTSEC_DAEMONLESS",
        help = "Execute directly against the local encrypted vault without connecting to a daemon"
    )]
    pub daemonless: bool,

    #[arg(
        long,
        global = true,
        help = "Require a running daemon and disable automatic fallback to direct vault mode"
    )]
    pub require_daemon: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Start the agentsec secret manager daemon server")]
    Daemon(DaemonArgs),

    #[command(about = "Check daemon connection, process status, and storage metrics")]
    Status,

    #[command(about = "Set or update a secret under a namespace")]
    Set(SetArgs),

    #[command(about = "Retrieve a secret value or inspect its metadata")]
    Get(GetArgs),

    #[command(about = "List secrets in a namespace (or list all namespaces)")]
    List(ListArgs),

    #[command(about = "Delete a secret or an entire namespace")]
    Delete(DeleteArgs),

    #[command(
        about = "Execute a command with secrets injected into environment variables (RAM only, zero files on disk)"
    )]
    Run(RunArgs),

    #[command(about = "Start the Model Context Protocol (MCP) stdio server for AI coding agents")]
    Mcp,

    #[command(about = "View or rotate the daemon API authentication token")]
    Token(TokenArgs),

    #[command(about = "Scan workspace files for accidental plaintext leaks of stored secrets")]
    Scan(ScanArgs),

    #[command(about = "Extend an active temporary secret lease (maximum 24 hours from now)")]
    Renew(RenewArgs),

    #[command(about = "Inspect secret-free access audit events (admin only)")]
    Audit(AuditArgs),

    #[command(about = "Check authentication, required keys, namespace access, and MCP discovery")]
    Doctor(DoctorArgs),

    #[command(
        about = "Manage and install agent skills across coding agents (e.g. 'agentsec skill install [agent]')",
        alias = "skills"
    )]
    Skill(SkillArgs),

    #[command(
        about = "Install the bundled agentsec skill for coding agents",
        alias = "install-skill"
    )]
    Setup(SetupArgs),

    #[command(
        about = "Manage background daemon supervision, monitoring cron tasks, and auto-recovery",
        alias = "supervisor"
    )]
    Service(ServiceArgs),
}

#[derive(Args, Debug)]
pub struct DaemonArgs {
    #[arg(
        long,
        help = "Run in ephemeral mode: secrets reside strictly in RAM and are never persisted to disk"
    )]
    pub ephemeral: bool,
}

#[derive(Args, Debug)]
pub struct SetArgs {
    #[arg(help = "The secret key / environment variable name (e.g. OPENAI_API_KEY)")]
    pub key: String,

    #[arg(
        help = "The secret value (if omitted, will be securely read from standard input or hidden prompt)"
    )]
    pub value: Option<String>,

    #[arg(
        short,
        long,
        help = "Namespace for the secret (defaults to auto-detected workspace/repo namespace)"
    )]
    pub namespace: Option<String>,

    #[arg(
        short,
        long,
        help = "Optional human-readable description for this secret"
    )]
    pub description: Option<String>,

    #[arg(short, long, help = "Tags associated with the secret")]
    pub tag: Vec<String>,

    #[arg(
        long,
        help = "Time-to-live in seconds before this secret automatically expires"
    )]
    pub ttl: Option<u64>,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    #[arg(help = "The secret key to retrieve")]
    pub key: String,

    #[arg(
        short,
        long,
        help = "Namespace for the secret (defaults to auto-detected workspace/repo namespace)"
    )]
    pub namespace: Option<String>,

    #[arg(
        long,
        help = "Output raw plaintext secret value directly to stdout (useful for piping)"
    )]
    pub raw: bool,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    #[arg(
        short,
        long,
        help = "Namespace to list (defaults to auto-detected workspace/repo namespace)"
    )]
    pub namespace: Option<String>,

    #[arg(long, help = "List all existing namespaces in the daemon")]
    pub all_namespaces: bool,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    #[arg(help = "The secret key to delete (required unless --all-namespace is used)")]
    pub key: Option<String>,

    #[arg(
        short,
        long,
        help = "Namespace for the secret (defaults to auto-detected workspace/repo namespace)"
    )]
    pub namespace: Option<String>,

    #[arg(
        long,
        help = "Delete the entire specified namespace and all secrets inside it"
    )]
    pub all_namespace: bool,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    #[arg(
        short,
        long,
        help = "Namespace from which to inject secrets (defaults to auto-detected workspace namespace)"
    )]
    pub namespace: Option<String>,

    #[arg(
        long,
        help = "Clear ambient environment variables and only inject essential system variables + secrets"
    )]
    pub clean_env: bool,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Inject only these keys; missing or forbidden keys fail closed"
    )]
    pub only: Option<Vec<String>>,

    #[arg(
        long,
        help = "Explicitly disable exact-value output redaction (unsafe for agent transcripts)"
    )]
    pub no_redact: bool,

    #[arg(
        trailing_var_arg = true,
        required = true,
        help = "The command and arguments to execute with secrets injected into RAM"
    )]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct TokenArgs {
    #[command(subcommand)]
    pub action: Option<TokenAction>,

    #[arg(
        long,
        help = "Generate and replace the current master authentication token"
    )]
    pub rotate: bool,

    #[arg(long, help = "Create a new named token for a client or agent")]
    pub create: Option<String>,

    #[arg(long, help = "List all active named client tokens")]
    pub list: bool,

    #[arg(long, help = "Revoke a named client token by name")]
    pub revoke: Option<String>,

    #[arg(long, help = "Optional human-readable description for the named token")]
    pub description: Option<String>,

    #[arg(long, help = "Optional time-to-live in seconds for the named token")]
    pub ttl: Option<u64>,

    #[arg(short, long, help = "Restrict named token to specific namespace(s)")]
    pub namespace: Vec<String>,

    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        default_value = "read,write,run"
    )]
    pub permission: Vec<Permission>,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Restrict a client token to these exact secret key names"
    )]
    pub key: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum TokenAction {
    #[command(about = "Create a new named token for a client or agent")]
    Create(CreateTokenArgs),

    #[command(about = "List all active named client tokens")]
    List,

    #[command(about = "Revoke a named client token by name")]
    Revoke(RevokeTokenArgs),

    #[command(about = "Extend an active temporary client-token lease (admin only)")]
    Renew(RenewTokenArgs),
}

#[derive(Args, Debug)]
pub struct CreateTokenArgs {
    #[arg(help = "The unique name for this client token (e.g. agent-laptop, ci-runner)")]
    pub name: String,

    #[arg(short, long, help = "Optional description for this client token")]
    pub description: Option<String>,

    #[arg(
        long,
        help = "Optional time-to-live in seconds before this token expires"
    )]
    pub ttl: Option<u64>,

    #[arg(
        short,
        long,
        help = "Restrict token access to specific namespace(s) (can be passed multiple times)"
    )]
    pub namespace: Vec<String>,

    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        default_value = "read,write,run"
    )]
    pub permission: Vec<Permission>,

    #[arg(
        long,
        value_delimiter = ',',
        help = "Restrict access to exact secret key names"
    )]
    pub key: Vec<String>,
}

#[derive(Args, Debug)]
pub struct RenewTokenArgs {
    pub name: String,
    #[arg(long, required = true)]
    pub ttl: u64,
}

#[derive(Args, Debug)]
pub struct RenewArgs {
    pub key: String,
    #[arg(short, long)]
    pub namespace: Option<String>,
    #[arg(long, required = true)]
    pub ttl: u64,
}

#[derive(Args, Debug)]
pub struct AuditArgs {
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct DoctorArgs {
    #[arg(short, long)]
    pub namespace: Option<String>,
    #[arg(long = "require", value_delimiter = ',')]
    pub required_keys: Vec<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct SkillArgs {
    #[command(subcommand)]
    pub action: Option<SkillAction>,

    #[arg(
        help = "Agent to install skill for (e.g. all, codex, grok, gemini, antigravity, claude, cursor, aider, or any custom agent name)",
        default_value = "all"
    )]
    pub agent: String,

    #[arg(long, help = "Custom target directory for skill installation")]
    pub target: Option<PathBuf>,

    #[arg(long, help = "Report planned installs without writing files")]
    pub dry_run: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SkillAction {
    #[command(
        about = "Install the agentsec skill for a specific agent or all agents",
        alias = "add"
    )]
    Install(SkillInstallArgs),

    #[command(about = "List known agent skill locations and installation status")]
    List,
}

#[derive(Args, Debug, Clone, Default)]
pub struct SkillInstallArgs {
    #[arg(
        help = "Agent to install skill for (e.g. all, codex, grok, gemini, antigravity, claude, cursor, aider, or any custom agent name)",
        default_value = "all"
    )]
    pub agent: String,

    #[arg(long, help = "Custom target directory to install skill into")]
    pub target: Option<PathBuf>,

    #[arg(long, help = "Report planned installs without writing files")]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct SetupArgs {
    #[arg(value_enum, help = "Agent to install skill for (default: all)")]
    pub agent_pos: Option<crate::setup::Agent>,

    #[arg(long, value_enum, default_value = "all")]
    pub agent: crate::setup::Agent,

    #[arg(long, help = "Report planned installs without writing files")]
    pub dry_run: bool,
}

impl SetupArgs {
    pub fn resolved_agent(&self) -> crate::setup::Agent {
        self.agent_pos.unwrap_or(self.agent)
    }
}

#[derive(Args, Debug, Clone)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub action: crate::service::ServiceAction,
}

#[derive(Args, Debug)]
pub struct RevokeTokenArgs {
    #[arg(help = "The name of the client token to revoke")]
    pub name: String,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    #[arg(
        short,
        long,
        help = "Namespace of secrets to scan for (defaults to auto-detected workspace namespace)"
    )]
    pub namespace: Option<String>,

    #[arg(help = "Target directory to scan (defaults to current working directory)")]
    pub target_dir: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    #[test]
    fn cli_schema_and_new_flags_parse() {
        Cli::command().debug_assert();
        let cli = Cli::try_parse_from([
            "agentsec",
            "run",
            "--only",
            "A,B",
            "--clean-env",
            "--",
            "echo",
            "ok",
        ])
        .unwrap();
        let Commands::Run(args) = cli.command else {
            panic!("Expected run")
        };
        assert_eq!(args.only.unwrap(), vec!["A", "B"]);
        assert!(!args.no_redact);
        assert!(args.clean_env);
        let cli = Cli::try_parse_from([
            "agentsec",
            "token",
            "create",
            "deploy",
            "--permission",
            "run",
            "--key",
            "A,B",
            "-n",
            "repo:one",
            "--ttl",
            "60",
        ])
        .unwrap();
        let Commands::Token(args) = cli.command else {
            panic!("Expected token")
        };
        let Some(TokenAction::Create(args)) = args.action else {
            panic!("Expected create")
        };
        assert_eq!(args.permission, vec![Permission::Run]);
        assert_eq!(args.key, vec!["A", "B"]);
        assert!(Cli::try_parse_from(["agentsec", "renew", "API_KEY"]).is_err());
        assert!(Cli::try_parse_from(["agentsec", "setup", "--agent", "unknown"]).is_err());

        // Test skill command parsing and aliases
        let cli = Cli::try_parse_from(["agentsec", "skill", "install", "codex"]).unwrap();
        let Commands::Skill(args) = cli.command else {
            panic!("Expected skill");
        };
        assert!(matches!(args.action, Some(SkillAction::Install(a)) if a.agent == "codex"));

        let cli = Cli::try_parse_from(["agentsec", "skills", "install", "claude"]).unwrap();
        let Commands::Skill(args) = cli.command else {
            panic!("Expected skill via skills alias");
        };
        assert!(matches!(args.action, Some(SkillAction::Install(a)) if a.agent == "claude"));

        let cli = Cli::try_parse_from(["agentsec", "skill", "list"]).unwrap();
        let Commands::Skill(args) = cli.command else {
            panic!("Expected skill");
        };
        assert!(matches!(args.action, Some(SkillAction::List)));

        let cli = Cli::try_parse_from(["agentsec", "install-skill", "--agent", "grok"]).unwrap();
        let Commands::Setup(args) = cli.command else {
            panic!("Expected setup via install-skill alias");
        };
        assert_eq!(args.resolved_agent(), crate::setup::Agent::Grok);

        // Test service commands and supervisor alias
        let cli = Cli::try_parse_from(["agentsec", "service", "status"]).unwrap();
        let Commands::Service(args) = cli.command else {
            panic!("Expected service");
        };
        assert!(matches!(args.action, crate::service::ServiceAction::Status));

        let cli = Cli::try_parse_from(["agentsec", "supervisor", "watchdog", "--quiet"]).unwrap();
        let Commands::Service(args) = cli.command else {
            panic!("Expected service via supervisor alias");
        };
        assert!(matches!(args.action, crate::service::ServiceAction::Watchdog(a) if a.quiet));
    }
}
