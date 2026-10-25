use agentsec::backend::ClientBackend;
use agentsec::config::AppConfig;
use agentsec::direct::DirectClient;
use agentsec::mcp::handle_mcp_request;
use agentsec::runner::{run_capture, RunOptions};
use agentsec::token::Permission;
use serde_json::{json, Value};
use std::env;
use std::fs;

#[tokio::test]
async fn test_direct_client_crud_and_disk_persistence() {
    let test_id = rand::random::<u64>();
    let temp_dir = env::temp_dir().join(format!("agentsec_direct_{}", test_id));
    fs::create_dir_all(&temp_dir).unwrap();

    let config = AppConfig::load(Some(temp_dir.clone()), Some(59999)).unwrap();
    let client = DirectClient::new(&config).expect("Failed to initialize DirectClient");

    let status = client.status().await.expect("Status failed");
    assert_eq!(status.stats.active_secrets_count, 0);

    // Set secrets
    let ns = "test:daemonless";
    let meta = client
        .set_secret(
            ns,
            "DATABASE_URL",
            "postgres://user:pass@localhost:5432/db",
            Some("Main DB".into()),
            vec!["db".into(), "production".into()],
            Some(3600),
        )
        .await
        .expect("Failed to set secret");
    assert_eq!(meta.name, "DATABASE_URL");
    assert_eq!(meta.namespace, ns);
    assert_eq!(meta.masked_preview, "post...****...2/db");

    // Get secret
    let detail = client
        .get_secret(ns, "DATABASE_URL")
        .await
        .expect("Failed to get secret");
    assert_eq!(detail.name, "DATABASE_URL");
    assert_eq!(detail.value, "postgres://user:pass@localhost:5432/db");
    assert_eq!(detail.metadata.tags, vec!["db", "production"]);

    // List secrets
    let secrets = client
        .list_secrets(ns)
        .await
        .expect("Failed to list secrets");
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].name, "DATABASE_URL");

    // List namespaces
    let namespaces = client
        .list_namespaces()
        .await
        .expect("Failed to list namespaces");
    assert!(namespaces.contains(&ns.to_string()));

    // Audit events
    let events = client.audit_events(10).await.expect("Failed to get audit");
    assert!(events.iter().any(|e| e.operation == "set_secret"));
    assert!(events.iter().any(|e| e.operation == "get_secret"));

    // Verify audit.log file on disk
    assert!(config.audit_log_path.exists());

    // Delete secret
    let deleted = client
        .delete_secret(ns, "DATABASE_URL")
        .await
        .expect("Failed to delete secret");
    assert!(deleted);

    // Verify gone
    assert!(client.get_secret(ns, "DATABASE_URL").await.is_err());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_direct_client_cross_process_disk_reload() {
    let test_id = rand::random::<u64>();
    let temp_dir = env::temp_dir().join(format!("agentsec_reload_{}", test_id));
    fs::create_dir_all(&temp_dir).unwrap();

    let config = AppConfig::load(Some(temp_dir.clone()), Some(59998)).unwrap();

    // Client 1 writes a secret to the vault file
    let client1 = DirectClient::new(&config).unwrap();
    client1
        .set_secret("ws:shared", "KEY_FROM_C1", "val1", None, vec![], None)
        .await
        .unwrap();

    // Client 2 is created independently pointing to the same vault path
    let client2 = DirectClient::new(&config).unwrap();
    let detail = client2
        .get_secret("ws:shared", "KEY_FROM_C1")
        .await
        .expect("Client 2 should read secret written by Client 1");
    assert_eq!(detail.value, "val1");

    // Client 2 writes a new secret
    client2
        .set_secret("ws:shared", "KEY_FROM_C2", "val2", None, vec![], None)
        .await
        .unwrap();

    // Client 1 reads it (triggers reload_from_disk_locked)
    let detail2 = client1
        .get_secret("ws:shared", "KEY_FROM_C2")
        .await
        .expect("Client 1 should observe secret written by Client 2");
    assert_eq!(detail2.value, "val2");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_backend_connect_auto_fallback_and_require_daemon() {
    let test_id = rand::random::<u64>();
    let temp_dir = env::temp_dir().join(format!("agentsec_fallback_{}", test_id));
    fs::create_dir_all(&temp_dir).unwrap();

    // Pick an unused port so daemon is guaranteed offline
    let port = 58100 + (test_id % 1000) as u16;
    let config = AppConfig::load(Some(temp_dir.clone()), Some(port)).unwrap();

    // 1. Without daemon, connect falls back to Direct
    let backend = ClientBackend::connect(&config, false, false)
        .await
        .expect("Auto-fallback to direct mode should succeed");
    assert!(backend.is_daemonless());

    backend
        .set_secret(
            "fallback:test",
            "FALLBACK_KEY",
            "fallback_val",
            None,
            vec![],
            None,
        )
        .await
        .unwrap();
    let sec = backend
        .get_secret("fallback:test", "FALLBACK_KEY")
        .await
        .unwrap();
    assert_eq!(sec.value, "fallback_val");

    // 2. With require_daemon = true, connect fails
    let err = ClientBackend::connect(&config, false, true).await;
    assert!(err.is_err());
    let err_msg = err.err().unwrap().to_string();
    assert!(err_msg.contains("--require-daemon was specified"));

    // 3. With daemonless = true, connect succeeds as Direct
    let direct_backend = ClientBackend::connect(&config, true, false).await.unwrap();
    assert!(direct_backend.is_daemonless());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_daemonless_runner_injection_and_redaction() {
    let test_id = rand::random::<u64>();
    let temp_dir = env::temp_dir().join(format!("agentsec_run_{}", test_id));
    fs::create_dir_all(&temp_dir).unwrap();

    let config = AppConfig::load(Some(temp_dir.clone()), Some(59997)).unwrap();
    let backend = ClientBackend::connect(&config, true, false).await.unwrap();

    let ns = "test:run";
    backend
        .set_secret(
            ns,
            "MY_SECRET_VAR",
            "super-secret-token-123",
            None,
            vec![],
            None,
        )
        .await
        .unwrap();

    // Run command that prints the injected env var
    let command = if cfg!(windows) {
        vec!["cmd".into(), "/C".into(), "echo var=%MY_SECRET_VAR%".into()]
    } else {
        vec!["sh".into(), "-c".into(), "echo var=$MY_SECRET_VAR".into()]
    };

    let options = RunOptions {
        namespace: ns.to_string(),
        command,
        clean_env: false,
        only: None,
        redact: true,
    };

    let output = run_capture(&backend, options).await.unwrap();
    assert_eq!(output.exit_code, 0);
    // Redaction should mask the secret value in output
    assert!(output.stdout.contains("var=[REDACTED]"));
    assert!(!output.stdout.contains("super-secret-token-123"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_daemonless_mcp_requests() {
    let test_id = rand::random::<u64>();
    let temp_dir = env::temp_dir().join(format!("agentsec_mcp_{}", test_id));
    fs::create_dir_all(&temp_dir).unwrap();

    let config = AppConfig::load(Some(temp_dir.clone()), Some(59996)).unwrap();
    let backend = ClientBackend::connect(&config, true, false).await.unwrap();

    // 1. tools/list
    let list_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list"
    });
    let list_res = handle_mcp_request(&backend, list_req).await;
    assert_eq!(list_res["id"], 1);
    let tools = list_res["result"]["tools"].as_array().unwrap();
    assert!(tools.iter().any(|t| t["name"] == "set_secret"));
    assert!(tools.iter().any(|t| t["name"] == "get_secret"));

    // 2. set_secret via tools/call
    let set_call = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "set_secret",
            "arguments": {
                "namespace": "mcp:test",
                "key": "API_KEY",
                "value": "mcp-secret-val-999"
            }
        }
    });
    let set_res = handle_mcp_request(&backend, set_call).await;
    assert_eq!(set_res["id"], 2);
    assert_eq!(set_res["error"], Value::Null);

    // 3. get_secret via tools/call
    let get_call = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "get_secret",
            "arguments": {
                "namespace": "mcp:test",
                "key": "API_KEY"
            }
        }
    });
    let get_res = handle_mcp_request(&backend, get_call).await;
    assert_eq!(get_res["id"], 3);
    let text = get_res["result"]["content"][0]["text"].as_str().unwrap();
    assert_eq!(text, "mcp-secret-val-999");

    // 4. doctor via tools/call
    let doctor_call = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "doctor",
            "arguments": {
                "namespace": "mcp:test"
            }
        }
    });
    let doctor_res = handle_mcp_request(&backend, doctor_call).await;
    assert_eq!(doctor_res["id"], 4);
    assert_eq!(doctor_res["error"], Value::Null);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_daemonless_token_operations() {
    let test_id = rand::random::<u64>();
    let temp_dir = env::temp_dir().join(format!("agentsec_token_{}", test_id));
    fs::create_dir_all(&temp_dir).unwrap();

    let config = AppConfig::load(Some(temp_dir.clone()), Some(59995)).unwrap();
    let backend = ClientBackend::connect(&config, true, false).await.unwrap();

    // Create client token
    let token = backend
        .create_client_token_with_policy(
            "agent-worker",
            Some("Worker agent token".into()),
            Some(3600),
            vec!["repo:test".into()],
            vec![Permission::Read, Permission::Write],
            vec![],
        )
        .await
        .expect("Failed to create client token");
    assert_eq!(token.name, "agent-worker");
    assert_eq!(token.namespaces, vec!["repo:test"]);

    // List tokens
    let tokens = backend
        .list_client_tokens()
        .await
        .expect("Failed to list client tokens");
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].name, "agent-worker");

    // Renew token
    let renewed = backend
        .renew_client_token("agent-worker", 7200)
        .await
        .expect("Failed to renew client token");
    assert_eq!(renewed.name, "agent-worker");

    // Revoke token
    let revoked = backend
        .revoke_client_token("agent-worker")
        .await
        .expect("Failed to revoke client token");
    assert!(revoked);

    let tokens_after = backend.list_client_tokens().await.unwrap();
    assert_eq!(tokens_after.len(), 0);

    // Rotate master token
    let rotated = backend
        .rotate_master_token()
        .await
        .expect("Failed to rotate master token");
    assert!(!rotated.is_empty());
    assert_eq!(config.get_or_create_auth_token().unwrap(), rotated);

    let _ = fs::remove_dir_all(&temp_dir);
}
