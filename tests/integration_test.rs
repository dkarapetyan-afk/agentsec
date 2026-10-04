use agentsec::client::DaemonClient;
use agentsec::config::AppConfig;
use agentsec::crypto::MasterKey;
use agentsec::runner::{run_with_secrets, RunOptions};
use agentsec::scanner::scan_workspace;
use agentsec::server::start_server;
use agentsec::store::Vault;
use std::env;
use std::fs;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_full_daemon_lifecycle_and_features() {
    let test_id = rand::random::<u64>();
    let temp_dir = env::temp_dir().join(format!("agentsec_e2e_{}", test_id));
    fs::create_dir_all(&temp_dir).unwrap();

    let port = 54000 + (test_id % 5000) as u16;
    let config = AppConfig::load(Some(temp_dir.clone()), Some(port)).unwrap();
    let auth_token = config.get_or_create_auth_token().unwrap();
    let master_key = MasterKey::generate();
    let vault = Vault::new(master_key, Some(config.vault_path.clone())).unwrap();

    // Spawn server in background
    let server_config = config.clone();
    let server_vault = vault.clone();
    let server_token = auth_token.clone();
    let server_handle = tokio::spawn(async move {
        let _ = start_server(server_config, server_vault, server_token).await;
    });

    // Wait for server to bind
    sleep(Duration::from_millis(150)).await;

    let client = DaemonClient::new(&config).expect("Failed to initialize client");

    // 1. Test Health
    let health = client.health().await.expect("Health check failed");
    assert_eq!(health.status, "ok");

    // 2. Test Status
    let status = client.status().await.expect("Status check failed");
    assert_eq!(status.port, port);
    assert_eq!(status.stats.active_secrets_count, 0);

    // 3. Set secrets in two namespaces
    let ns1 = "repo:payment-service";
    let ns2 = "repo:auth-service";

    client
        .set_secret(
            ns1,
            "STRIPE_API_KEY",
            "sk_test_51Mz00000000000000000000000000000",
            Some("Stripe sandbox key".to_string()),
            vec!["payments".to_string(), "stripe".to_string()],
            None,
        )
        .await
        .expect("Failed to set secret");

    client
        .set_secret(
            ns1,
            "DATABASE_URL",
            "postgres://user:pass123@localhost:5432/payments",
            None,
            vec![],
            None,
        )
        .await
        .expect("Failed to set secret");

    client
        .set_secret(
            ns2,
            "JWT_SECRET",
            "super-secret-jwt-signing-key-998877",
            None,
            vec!["auth".to_string()],
            None,
        )
        .await
        .expect("Failed to set secret");

    // 4. Test Namespaces Listing
    let namespaces = client.list_namespaces().await.expect("List namespaces failed");
    assert!(namespaces.contains(&ns1.to_string()));
    assert!(namespaces.contains(&ns2.to_string()));

    // 5. Test Secrets Listing (masked previews)
    let secrets1 = client.list_secrets(ns1).await.expect("List secrets failed");
    assert_eq!(secrets1.len(), 2);
    let stripe_sec = secrets1.iter().find(|s| s.name == "STRIPE_API_KEY").unwrap();
    assert_ne!(stripe_sec.masked_preview, "sk_test_51Mz00000000000000000000000000000");
    assert!(stripe_sec.masked_preview.contains("****"));

    // 6. Test Secret Detail (get plaintext)
    let detail = client
        .get_secret(ns1, "STRIPE_API_KEY")
        .await
        .expect("Get secret failed");
    assert_eq!(detail.value, "sk_test_51Mz00000000000000000000000000000");
    assert_eq!(detail.metadata.tags, vec!["payments", "stripe"]);

    // 7. Test TTL Expiration
    client
        .set_secret(
            ns1,
            "TEMP_TOKEN",
            "ephemeral-token-val-xyz",
            None,
            vec![],
            Some(1), // 1 second TTL
        )
        .await
        .expect("Failed to set temp secret");

    // Immediately present
    assert!(client.get_secret(ns1, "TEMP_TOKEN").await.is_ok());

    // Sleep 1.2s to exceed TTL
    sleep(Duration::from_millis(1200)).await;

    // Now expired and automatically cleaned up
    assert!(client.get_secret(ns1, "TEMP_TOKEN").await.is_err());

    // 8. Test Subprocess Environment Injection (runner)
    let output_file = temp_dir.join("injected_env.txt");
    let run_opts = RunOptions {
        namespace: ns1.to_string(),
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("echo INJECTED_STRIPE=$STRIPE_API_KEY > {:?}", output_file),
        ],
        clean_env: false,
    };

    let exit_code = run_with_secrets(&client, run_opts)
        .await
        .expect("Runner execution failed");
    assert_eq!(exit_code, 0);

    let output_content = fs::read_to_string(&output_file).expect("Failed to read runner output");
    assert!(output_content.contains("INJECTED_STRIPE=sk_test_51Mz00000000000000000000000000000"));

    // 9. Test Workspace Leak Scanner
    let fake_workspace = temp_dir.join("workspace");
    fs::create_dir_all(&fake_workspace).unwrap();

    // A clean file
    fs::write(
        fake_workspace.join("clean.py"),
        "import os\napi_key = os.environ.get('STRIPE_API_KEY')\n",
    )
    .unwrap();

    let clean_leaks = scan_workspace(&client, ns1, Some(fake_workspace.clone()))
        .await
        .unwrap();
    assert_eq!(clean_leaks, 0);

    // Now intentionally leak the secret to test detection
    fs::write(
        fake_workspace.join("leaked.js"),
        "const stripe = require('stripe')('sk_test_51Mz00000000000000000000000000000');\n",
    )
    .unwrap();

    let detected_leaks = scan_workspace(&client, ns1, Some(fake_workspace.clone()))
        .await
        .unwrap();
    assert_eq!(detected_leaks, 1);

    // 10. Test Deletion
    let deleted = client
        .delete_secret(ns1, "DATABASE_URL")
        .await
        .expect("Delete secret failed");
    assert!(deleted);

    let secrets_after = client.list_secrets(ns1).await.unwrap();
    assert_eq!(secrets_after.len(), 1);

    let deleted_ns = client.delete_namespace(ns2).await.unwrap();
    assert_eq!(deleted_ns, 1);

    let ns_list_after = client.list_namespaces().await.unwrap();
    assert!(!ns_list_after.contains(&ns2.to_string()));

    // Cleanup server & temporary test directory
    server_handle.abort();
    let _ = fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_external_vs_local_authentication_and_tunnel_url() {
    let test_id = rand::random::<u64>();
    let temp_dir = env::temp_dir().join(format!("agentsec_auth_test_{}", test_id));
    fs::create_dir_all(&temp_dir).unwrap();

    let port = 55000 + (test_id % 5000) as u16;
    let config = AppConfig::load(Some(temp_dir.clone()), Some(port)).unwrap();
    let auth_token = config.get_or_create_auth_token().unwrap();
    let master_key = MasterKey::generate();
    let vault = Vault::new(master_key, Some(config.vault_path.clone())).unwrap();

    // Write a mock tunnel URL
    let mock_tunnel_url = "https://agentsec-test-demo.trycloudflare.com";
    config.write_tunnel_url(mock_tunnel_url).unwrap();

    // Spawn server
    let server_config = config.clone();
    let server_vault = vault.clone();
    let server_token = auth_token.clone();
    let server_handle = tokio::spawn(async move {
        let _ = start_server(server_config, server_vault, server_token).await;
    });

    sleep(Duration::from_millis(150)).await;

    let http_client = reqwest::Client::new();
    let base_local = format!("http://127.0.0.1:{}", port);

    // 1. Local /health without auth should succeed (local connections still work as they are)
    let resp_local = http_client
        .get(format!("{}/health", base_local))
        .send()
        .await
        .expect("Local health request failed");
    assert_eq!(resp_local.status(), reqwest::StatusCode::OK);

    // 2. External /health (with CF-Connecting-IP header) without auth MUST be rejected (401)
    let resp_ext_unauth = http_client
        .get(format!("{}/health", base_local))
        .header("cf-connecting-ip", "203.0.113.195")
        .send()
        .await
        .expect("External health request failed");
    assert_eq!(resp_ext_unauth.status(), reqwest::StatusCode::UNAUTHORIZED);

    // 3. External /health with invalid token MUST be rejected (401)
    let resp_ext_bad_token = http_client
        .get(format!("{}/health", base_local))
        .header("cf-connecting-ip", "203.0.113.195")
        .bearer_auth("invalid-token-12345")
        .send()
        .await
        .expect("External health request failed");
    assert_eq!(resp_ext_bad_token.status(), reqwest::StatusCode::UNAUTHORIZED);

    // 4. External /health with valid Bearer token MUST succeed (200)
    let resp_ext_valid = http_client
        .get(format!("{}/health", base_local))
        .header("cf-connecting-ip", "203.0.113.195")
        .bearer_auth(&auth_token)
        .send()
        .await
        .expect("External health request failed");
    assert_eq!(resp_ext_valid.status(), reqwest::StatusCode::OK);

    // 5. External request with external Host header without auth MUST be rejected (401)
    let resp_host_unauth = http_client
        .get(format!("{}/health", base_local))
        .header("Host", "custom-agentsec.trycloudflare.com")
        .send()
        .await
        .expect("External host request failed");
    assert_eq!(resp_host_unauth.status(), reqwest::StatusCode::UNAUTHORIZED);

    // 6. Verify status reports the recorded tunnel_url
    let client = DaemonClient::new(&config).expect("Client init failed");
    let status = client.status().await.expect("Status check failed");
    assert_eq!(status.tunnel_url.as_deref(), Some(mock_tunnel_url));

    // 7. Verify DaemonClient with custom_url and custom_token works
    let remote_config = AppConfig::load_with_overrides(
        Some(temp_dir.clone()),
        Some(port),
        Some(format!("http://127.0.0.1:{}", port)),
        Some(auth_token.clone()),
    )
    .unwrap();
    let remote_client = DaemonClient::new(&remote_config).unwrap();
    let remote_status = remote_client.status().await.unwrap();
    assert_eq!(remote_status.pid, std::process::id());

    server_handle.abort();
    let _ = fs::remove_dir_all(&temp_dir);
}
