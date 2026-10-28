use agentsec::{
    client::DaemonClient,
    config::AppConfig,
    crypto::MasterKey,
    runner::{run_capture, RunOptions},
    server::start_server,
    store::Vault,
    token::Permission,
};
use serde_json::{json, Value};
use std::{path::PathBuf, time::Duration};

struct Fixture {
    directory: PathBuf,
    config: AppConfig,
    client: DaemonClient,
    vault: Vault,
    task: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("agentsec-security-{}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let mut config = AppConfig::load(Some(directory.clone()), Some(0)).unwrap();
        config.host = "127.0.0.1".into();
        config.custom_token = None;
        config.custom_url = None;
        let token = config.get_or_create_auth_token().unwrap();
        let vault = Vault::new(MasterKey::generate(), Some(config.vault_path.clone()))
            .await
            .unwrap();
        let (server_config, server_vault) = (config.clone(), vault.clone());
        let task = tokio::spawn(async move {
            start_server(server_config, server_vault, token)
                .await
                .unwrap();
        });
        let mut ready = None;
        for _ in 0..100 {
            if config.read_daemon_info().ok().flatten().is_some() {
                let client = DaemonClient::new(&config).unwrap();
                if client.health().await.is_ok() {
                    ready = Some(client);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Self {
            directory,
            config,
            client: ready.expect("Test daemon did not start"),
            vault,
            task,
        }
    }
    fn client_for(&self, token: &str) -> DaemonClient {
        let info = self.config.read_daemon_info().unwrap().unwrap();
        DaemonClient::with_explicit_target(format!("http://127.0.0.1:{}", info.port), token.into())
            .unwrap()
    }
    async fn secret(&self, ns: &str, key: &str, value: &str, ttl: Option<u64>) {
        self.client
            .set_secret(ns, key, value, None, vec![], ttl)
            .await
            .unwrap();
    }
    async fn mcp(&self, client: &DaemonClient, tool: &str, args: Value) -> Value {
        client.mcp_request(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool,"arguments":args}})).await.unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
        // This uniquely-created test directory contains only this fixture's artifacts.
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[tokio::test]
async fn read_token_enforces_permissions_namespace_keys_and_mcp() {
    let fixture = Fixture::new().await;
    fixture
        .secret("repo:one", "ALLOWED", "dummy-allowed-value", None)
        .await;
    fixture
        .secret("repo:one", "OTHER", "dummy-other-value", None)
        .await;
    fixture
        .secret("repo:two", "ALLOWED", "dummy-second-value", None)
        .await;
    let token = fixture
        .client
        .create_client_token_with_policy(
            "reader",
            None,
            Some(60),
            vec!["repo:one".into()],
            vec![Permission::Read],
            vec!["ALLOWED".into()],
        )
        .await
        .unwrap();
    let client = fixture.client_for(&token.token);
    assert!(client.get_secret("repo:one", "ALLOWED").await.is_ok());
    assert!(client.get_secret("repo:one", "OTHER").await.is_err());
    assert!(client.get_secret("repo:two", "ALLOWED").await.is_err());
    assert_eq!(client.list_namespaces().await.unwrap(), vec!["repo:one"]);
    assert_eq!(client.list_secrets("repo:one").await.unwrap().len(), 1);
    assert_eq!(client.export_namespace("repo:one").await.unwrap().len(), 1);
    assert!(client
        .set_secret("repo:one", "ALLOWED", "dummy-new-value", None, vec![], None)
        .await
        .is_err());
    assert!(client.inject_secrets("repo:one", None).await.is_err());
    assert!(client.delete_secret("repo:one", "ALLOWED").await.is_err());
    assert!(client
        .renew_secret("repo:one", "ALLOWED", 60)
        .await
        .is_err());
    for args in [
        json!({"key":"OTHER","namespace":"repo:one"}),
        json!({"key":"ALLOWED","namespace":"repo:two"}),
    ] {
        assert_eq!(
            fixture.mcp(&client, "get_secret", args).await["result"]["isError"],
            true
        );
    }
    // HTTP MCP infers a single restricted namespace, but never expands permissions.
    assert!(fixture
        .mcp(&client, "get_secret", json!({"key":"ALLOWED"}))
        .await["result"]
        .get("isError")
        .is_none());
    assert_eq!(
        fixture
            .mcp(
                &client,
                "set_secret",
                json!({"key":"ALLOWED","value":"dummy-denied","namespace":"repo:one"})
            )
            .await["result"]["isError"],
        true
    );
}

#[tokio::test]
async fn ordinary_tokens_cannot_administer_or_leak_client_tokens() {
    let fixture = Fixture::new().await;
    let token = fixture
        .client
        .create_client_token("ordinary", None, Some(60), vec![])
        .await
        .unwrap();
    let client = fixture.client_for(&token.token);
    assert!(client.list_client_tokens().await.is_err());
    assert!(client
        .create_client_token("escalated", None, None, vec![])
        .await
        .is_err());
    assert!(client.revoke_client_token("ordinary").await.is_err());
    assert!(client.renew_client_token("ordinary", 120).await.is_err());
    assert!(client.rotate_master_token().await.is_err());
    assert!(client.audit_events(10).await.is_err());
    let listed = serde_json::to_value(fixture.client.list_client_tokens().await.unwrap()).unwrap();
    assert!(listed[0].get("token").is_none());
    assert!(!listed.to_string().contains(&token.token));
    let info = fixture.config.read_daemon_info().unwrap().unwrap();
    let wire: Value = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/v1/tokens", info.port))
        .bearer_auth(fixture.config.get_or_create_auth_token().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(wire["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .all(|t| t.get("token").is_none()));
    assert!(!wire.to_string().contains(&token.token));
    assert!(!format!("{:?}", token).contains(&token.token));
    assert_eq!(
        fixture.mcp(&client, "get_audit_events", json!({})).await["result"]["isError"],
        true
    );
    assert!(fixture
        .client
        .create_client_token_with_policy(
            "invalid-admin",
            None,
            None,
            vec!["repo:one".into()],
            vec![Permission::Admin],
            vec![]
        )
        .await
        .is_err());
    let admin = fixture
        .client
        .create_client_token_with_policy(
            "administrator",
            None,
            None,
            vec![],
            vec![Permission::Admin],
            vec![],
        )
        .await
        .unwrap();
    assert!(fixture
        .client_for(&admin.token)
        .list_client_tokens()
        .await
        .is_ok());
}

#[tokio::test]
async fn run_only_scope_selective_injection_and_stream_redaction() {
    let fixture = Fixture::new().await;
    fixture
        .secret("repo:one", "API_KEY", "dummy-secret-stream-value", None)
        .await;
    fixture
        .secret("repo:one", "OTHER_KEY", "dummy-never-inject", None)
        .await;
    let token = fixture
        .client
        .create_client_token_with_policy(
            "runner",
            None,
            None,
            vec!["repo:one".into()],
            vec![Permission::Run],
            vec!["API_KEY".into()],
        )
        .await
        .unwrap();
    let client = fixture.client_for(&token.token);
    assert!(client.get_secret("repo:one", "API_KEY").await.is_err());
    assert!(client.export_namespace("repo:one").await.is_err());
    let injected = client
        .inject_secrets("repo:one", Some(vec!["API_KEY".into()]))
        .await
        .unwrap();
    assert_eq!(injected.len(), 1);
    assert!(client
        .inject_secrets("repo:one", Some(vec!["OTHER_KEY".into()]))
        .await
        .is_err());
    assert!(client
        .inject_secrets("repo:one", Some(vec![]))
        .await
        .is_err());
    assert!(fixture
        .client
        .inject_secrets("repo:one", Some(vec!["MISSING".into()]))
        .await
        .is_err());
    #[cfg(unix)]
    {
        let script = "test -z \"${OTHER_KEY:-}\" && test -z \"${AGENTSEC_TOKEN:-}\" || exit 9; printf '%s' \"$API_KEY\"; printf '%s' \"$API_KEY\" >&2; exit 7";
        let options = RunOptions {
            namespace: "repo:one".into(),
            command: vec!["sh".into(), "-c".into(), script.into()],
            clean_env: true,
            only: Some(vec!["API_KEY".into()]),
            ..Default::default()
        };
        let output = run_capture(&client, options).await.unwrap();
        assert_eq!(output.exit_code, 7);
        assert_eq!(output.stdout, "[REDACTED]");
        assert_eq!(output.stderr, "[REDACTED]");
        let response = fixture
            .mcp(
                &client,
                "run_command_with_secrets",
                json!({"argv":["sh","-c",script],"namespace":"repo:one","only":["API_KEY"]}),
            )
            .await;
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains("dummy-secret-stream-value"));
        assert_eq!(serde_json::from_str::<Value>(text).unwrap()["exit_code"], 7);
    }
}

#[tokio::test]
async fn leases_are_bounded_renewable_and_proactively_purged() {
    let fixture = Fixture::new().await;
    fixture
        .secret("repo:one", "TEMP", "dummy-temporary-value", Some(2))
        .await;
    let old = fixture
        .client
        .get_secret("repo:one", "TEMP")
        .await
        .unwrap()
        .metadata
        .expires_at
        .unwrap();
    let renewed = fixture
        .client
        .renew_secret("repo:one", "TEMP", 10)
        .await
        .unwrap();
    assert!(renewed.expires_at.unwrap() > old);
    assert!(renewed.remaining_ttl_seconds().unwrap() >= 8);
    assert!(fixture
        .client
        .renew_secret("repo:one", "TEMP", 0)
        .await
        .is_err());
    assert!(fixture
        .client
        .renew_secret("repo:one", "TEMP", 86401)
        .await
        .is_err());
    assert!(fixture
        .client
        .renew_secret("repo:one", "TEMP", 1)
        .await
        .is_err());
    fixture
        .secret("repo:one", "PERMANENT", "dummy-permanent-value", None)
        .await;
    assert!(fixture
        .client
        .renew_secret("repo:one", "PERMANENT", 10)
        .await
        .is_err());
    assert!(fixture
        .client
        .set_secret(
            "repo:one",
            "INVALID",
            "dummy-invalid-value",
            None,
            vec![],
            Some(0)
        )
        .await
        .is_err());
    let token = fixture
        .client
        .create_client_token("temporary-client", None, Some(2), vec![])
        .await
        .unwrap();
    let renewed = fixture
        .client
        .renew_client_token("temporary-client", 10)
        .await
        .unwrap();
    assert!(renewed.expires_at.unwrap() > token.expires_at.unwrap());
    assert!(fixture
        .client
        .renew_client_token("temporary-client", 86401)
        .await
        .is_err());
    fixture
        .secret(
            "repo:expire",
            "EXPIRES",
            "dummy-expire-without-read",
            Some(1),
        )
        .await;
    let expiring = fixture
        .client
        .create_client_token("expires-without-read", None, Some(1), vec![])
        .await
        .unwrap();
    let expiring_client = fixture.client_for(&expiring.token);
    assert!(expiring_client.status().await.is_ok());
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert_eq!(fixture.vault.stats().await.active_secrets_count, 2);
    assert_eq!(fixture.vault.stats().await.namespaces_count, 1);
    assert!(expiring_client.status().await.is_err());
    let persisted = std::fs::read_to_string(fixture.config.client_tokens_path.clone()).unwrap();
    assert!(!persisted.contains("expires-without-read"));
    assert!(fixture
        .client
        .renew_secret("repo:expire", "EXPIRES", 10)
        .await
        .is_err());
    assert!(fixture
        .client
        .renew_client_token("expires-without-read", 10)
        .await
        .is_err());
}

#[tokio::test]
async fn rotation_is_live_and_audit_contains_metadata_only() {
    let fixture = Fixture::new().await;
    fixture
        .secret("repo:one", "API_KEY", "dummy-audit-private-value", None)
        .await;
    let token = fixture
        .client
        .create_client_token("ordinary", None, None, vec!["repo:one".into()])
        .await
        .unwrap();
    let scoped = fixture.client_for(&token.token);
    scoped.get_secret("repo:one", "API_KEY").await.unwrap();
    assert!(scoped.get_secret("repo:denied", "API_KEY").await.is_err());
    let pid = fixture.client.status().await.unwrap().pid;
    let rotated = fixture.client.rotate_master_token().await.unwrap();
    assert!(fixture.client.status().await.is_err());
    let replacement = fixture.client_for(&rotated);
    assert_eq!(replacement.status().await.unwrap().pid, pid);
    assert!(scoped.status().await.is_ok());
    assert_eq!(fixture.config.get_or_create_auth_token().unwrap(), rotated);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let probe_path = fixture.directory.join(".perm_probe");
        let _ = std::fs::write(&probe_path, b"probe");
        let _ = std::fs::set_permissions(&probe_path, std::fs::Permissions::from_mode(0o600));
        let fs_supports_permissions = std::fs::metadata(&probe_path)
            .map(|m| (m.permissions().mode() & 0o777) == 0o600)
            .unwrap_or(false);
        let _ = std::fs::remove_file(&probe_path);

        if fs_supports_permissions {
            assert_eq!(
                std::fs::metadata(&fixture.config.token_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    let events = replacement.audit_events(1000).await.unwrap();
    assert!(events
        .iter()
        .any(|e| e.client == "ordinary" && e.operation == "get_secret" && e.outcome == "denied"));
    assert!(events
        .iter()
        .any(|e| e.operation == "rotate_master" && e.outcome == "succeeded"));
    for content in [
        serde_json::to_string(&events).unwrap(),
        std::fs::read_to_string(fixture.directory.join("audit.jsonl")).unwrap(),
    ] {
        assert!(!content.contains("dummy-audit-private-value"));
        assert!(!content.contains(&rotated));
        assert!(!content.contains(&token.token));
        assert!(!content.contains("Authorization"));
    }
}

#[tokio::test]
async fn doctor_reports_health_required_keys_and_mcp_without_values() {
    let fixture = Fixture::new().await;
    fixture
        .secret("repo:one", "API_KEY", "dummy-doctor-private-value", None)
        .await;
    let report =
        agentsec::doctor::diagnose(&fixture.client, "repo:one", vec!["API_KEY".into()]).await;
    assert!(report.ok, "{:?}", report);
    assert!(!serde_json::to_string(&report)
        .unwrap()
        .contains("dummy-doctor-private-value"));
    assert!(
        !agentsec::doctor::diagnose(&fixture.client, "repo:one", vec!["MISSING".into()])
            .await
            .ok
    );
    assert!(
        !agentsec::doctor::diagnose(
            &fixture.client_for("invalid-dummy-token"),
            "repo:one",
            vec![]
        )
        .await
        .ok
    );
    let response = fixture
        .mcp(
            &fixture.client,
            "doctor",
            json!({"namespace":"repo:one","required_keys":["API_KEY"]}),
        )
        .await;
    let report: Value =
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(report["ok"], true);
}

#[tokio::test]
async fn stdio_mcp_rejects_out_of_scope_keys_and_redacts_child_output() {
    let fixture = Fixture::new().await;
    fixture
        .secret("repo:one", "API_KEY", "dummy-stdio-private-value", None)
        .await;
    fixture
        .secret("repo:one", "OTHER_KEY", "dummy-forbidden-value", None)
        .await;
    let token = fixture
        .client
        .create_client_token_with_policy(
            "stdio-agent",
            None,
            Some(60),
            vec!["repo:one".into()],
            vec![Permission::Read, Permission::Run],
            vec!["API_KEY".into()],
        )
        .await
        .unwrap();
    let config_dir = fixture.directory.clone();
    #[cfg(unix)]
    let command = "printf '%s' \"$API_KEY\"; printf '%s' \"$API_KEY\" >&2";
    #[cfg(windows)]
    let command = "echo %API_KEY%&echo %API_KEY% 1>&2";

    let input = [
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_secret","arguments":{"namespace":"repo:one","key":"OTHER_KEY"}}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_command_with_secrets","arguments":{"namespace":"repo:one","only":["API_KEY"],"command":command}}}),
    ];
    let result = tokio::task::spawn_blocking(move || {
        use std::io::Write;
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_agentsec"))
            .args(["--config-dir", config_dir.to_str().unwrap(), "mcp"])
            .env("AGENTSEC_TOKEN", token.token)
            .env_remove("AGENTSEC_URL")
            .env_remove("AGENTSEC_SERVER_URL")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        for request in input {
            writeln!(stdin, "{}", request).unwrap();
        }
        drop(stdin);
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    assert!(result.status.success());
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(!stdout.contains("dummy-stdio-private-value"));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("dummy-stdio-private-value"));
    let messages = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0]["result"]["isError"], true);
    let output: Value = serde_json::from_str(
        messages[1]["result"]["content"][0]["text"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(output["stdout"].as_str().unwrap().trim(), "[REDACTED]");
    assert_eq!(output["stderr"].as_str().unwrap().trim(), "[REDACTED]");
}

#[test]
fn cli_help_never_discloses_injected_daemon_token() {
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_agentsec"))
        .arg("--help")
        .env("AGENTSEC_TOKEN", "dummy-help-private-token")
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("dummy-help-private-token"));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("dummy-help-private-token"));
}

#[test]
fn setup_dry_run_does_not_create_configuration_files() {
    let directory =
        std::env::temp_dir().join(format!("agentsec-dry-run-{}", rand::random::<u64>()));
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_agentsec"))
        .args([
            "--config-dir",
            directory.to_str().unwrap(),
            "setup",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(!directory.exists());
}
