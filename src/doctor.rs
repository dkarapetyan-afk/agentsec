use crate::client::DaemonClient;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub namespace: String,
    pub checks: Vec<Check>,
}
pub async fn diagnose(
    client: &DaemonClient,
    namespace: &str,
    required_keys: Vec<String>,
) -> DoctorReport {
    let mut checks = vec![];
    let health = client.health().await;
    checks.push(Check {
        name: "daemon_health".into(),
        passed: health.is_ok(),
        detail: if health.is_ok() {
            "Reachable".into()
        } else {
            "Daemon unavailable; check endpoint and daemon status".into()
        },
    });
    let status = client.status().await;
    checks.push(Check {
        name: "authentication".into(),
        passed: status.is_ok(),
        detail: if status.is_ok() {
            "Accepted".into()
        } else {
            "Authentication or connection failed".into()
        },
    });
    let version_ok = status
        .as_ref()
        .is_ok_and(|s| s.version == env!("CARGO_PKG_VERSION"));
    checks.push(Check {
        name: "version".into(),
        passed: version_ok,
        detail: if version_ok {
            "Daemon and CLI versions match".into()
        } else {
            "Install the matching binary and restart the daemon after upgrading".into()
        },
    });
    let secrets = client.list_secrets(namespace).await;
    checks.push(Check {
        name: "namespace_access".into(),
        passed: secrets.is_ok(),
        detail: if secrets.is_ok() {
            "Namespace metadata accessible".into()
        } else {
            "Namespace unavailable or token lacks read permission".into()
        },
    });
    for key in required_keys {
        let present = secrets
            .as_ref()
            .is_ok_and(|values| values.iter().any(|s| s.name == key && !s.is_expired()));
        checks.push(Check {
            name: format!("required_key:{}", key),
            passed: present,
            detail: if present {
                "Present and active".into()
            } else {
                "Missing, expired, or inaccessible".into()
            },
        });
    }
    let mcp = client
        .mcp_request(serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .await;
    let expected = crate::mcp::get_tool_definitions();
    let mcp_ok = mcp.as_ref().is_ok_and(|response| {
        expected.as_array().unwrap().iter().all(|tool| {
            response
                .pointer("/result/tools")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|tools| {
                    tools
                        .iter()
                        .any(|found| found.get("name") == tool.get("name"))
                })
        })
    });
    checks.push(Check {
        name: "mcp_discovery".into(),
        passed: mcp_ok,
        detail: if mcp_ok {
            "All supported tools advertised".into()
        } else {
            "MCP unavailable or tool definitions are out of date".into()
        },
    });
    DoctorReport {
        ok: checks.iter().all(|c| c.passed),
        namespace: namespace.into(),
        checks,
    }
}
