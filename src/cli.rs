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
    #[arg(short, long, global = true, help = "Path to custom configuration directory")]
    pub config_dir: Option<PathBuf>,

    #[arg(short, long, global = true, help = "Daemon host address override")]
    pub host: Option<String>,

    #[arg(short, long, global = true, help = "Daemon port override")]
    pub port: Option<u16>,

    #[arg(long, global = true, env = "AGENTSEC_URL", help = "Remote daemon or tunnel URL override (e.g. https://xxx.trycloudflare.com)")]
    pub url: Option<String>,

    #[arg(long, global = true, env = "AGENTSEC_TOKEN", help = "Authentication token for connecting to the daemon")]
    pub token: Option<String>,

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

    #[command(
        about = "Scan workspace files for accidental plaintext leaks of stored secrets"
    )]
    Scan(ScanArgs),
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

    #[arg(short, long, help = "Optional human-readable description for this secret")]
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

    #[arg(long, help = "Delete the entire specified namespace and all secrets inside it")]
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

    #[arg(long, help = "Generate and replace the current master authentication token")]
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
}

#[derive(Subcommand, Debug)]
pub enum TokenAction {
    #[command(about = "Create a new named token for a client or agent")]
    Create(CreateTokenArgs),

    #[command(about = "List all active named client tokens")]
    List,

    #[command(about = "Revoke a named client token by name")]
    Revoke(RevokeTokenArgs),
}

#[derive(Args, Debug)]
pub struct CreateTokenArgs {
    #[arg(help = "The unique name for this client token (e.g. agent-laptop, ci-runner)")]
    pub name: String,

    #[arg(short, long, help = "Optional description for this client token")]
    pub description: Option<String>,

    #[arg(long, help = "Optional time-to-live in seconds before this token expires")]
    pub ttl: Option<u64>,

    #[arg(short, long, help = "Restrict token access to specific namespace(s) (can be passed multiple times)")]
    pub namespace: Vec<String>,
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

    #[arg(
        help = "Target directory to scan (defaults to current working directory)"
    )]
    pub target_dir: Option<PathBuf>,
}
