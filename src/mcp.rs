use crate::backend::ClientBackend;
use crate::config::detect_workspace_namespace;
use crate::runner::{run_capture, RunOptions};
use anyhow::Result;
use serde_json::{json, Value};
use std::future::Future;
use std::io::{self, BufRead, Write};
use std::pin::Pin;

pub async fn run_mcp_server(client: impl Into<ClientBackend>) -> Result<()> {
    let client: ClientBackend = client.into();
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let request = match serde_json::from_str::<Value>(&line) {
            Ok(value) => value,
            Err(_) => {
                writeln!(
                    stdout,
                    "{}",
                    json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Invalid JSON"}})
                )?;
                stdout.flush()?;
                continue;
            }
        };
        let response = handle_mcp_request(&client, request).await;
        if !response.is_null() {
            writeln!(stdout, "{}", response)?;
            stdout.flush()?;
        }
    }
    Ok(())
}

pub fn get_tool_definitions() -> Value {
    json!([
        {
            "name": "list_namespaces",
            "description": "Lists all available secret namespaces in the agentsec daemon.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        },
        {
            "name": "list_secrets",
            "description": "Lists all secrets in a given namespace. Shows metadata and masked previews (e.g. sk-****1234) without exposing full raw values.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "namespace": {
                        "type": "string",
                        "description": "Optional namespace. If omitted, automatically resolves to current workspace namespace."
                    }
                }
            }
        },
        {
            "name": "get_secret",
            "description": "Retrieves the full plaintext value of a secret by its name and namespace.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "The secret key or name (e.g. OPENAI_API_KEY, DATABASE_URL)"
                    },
                    "namespace": {
                        "type": "string",
                        "description": "Optional namespace. If omitted, automatically resolves to current workspace namespace."
                    }
                },
                "required": ["key"]
            }
        },
        {
            "name": "set_secret",
            "description": "Securely stores or updates a secret in the daemon under a specified namespace. Never writes anything to the local project files.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "The secret key or variable name (e.g. STRIPE_SECRET_KEY)"
                    },
                    "value": {
                        "type": "string",
                        "description": "The secret value to store safely"
                    },
                    "namespace": {
                        "type": "string",
                        "description": "Optional namespace. If omitted, automatically resolves to current workspace namespace."
                    },
                    "description": {
                        "type": "string",
                        "description": "Optional human-readable description for what this secret is used for"
                    },
                    "ttl_seconds": {
                        "type": "integer",
                        "description": "Optional time-to-live in seconds before this secret expires automatically"
                    }
                },
                "required": ["key", "value"]
            }
        },
        {
            "name": "renew_secret",
            "description": "Extend an active expiring secret lease, up to 86400 seconds from now. Cannot revive expired secrets.",
            "inputSchema": {"type": "object", "properties": {"key": {"type": "string"}, "namespace": {"type": "string"}, "ttl_seconds": {"type": "integer", "minimum": 1, "maximum": 86400}}, "required": ["key", "ttl_seconds"]}
        },
        {
            "name": "doctor",
            "description": "Check daemon health, namespace, required key metadata, version compatibility, and MCP discovery without exposing values.",
            "inputSchema": {"type": "object", "properties": {"namespace": {"type": "string"}, "required_keys": {"type": "array", "items": {"type": "string"}}}}
        },
        {
            "name": "get_audit_events",
            "description": "Read recent secret-free audit metadata. Requires an administrator credential.",
            "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 1000}}}
        },
        {
            "name": "delete_secret",
            "description": "Deletes a secret from a namespace in the daemon.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "key": {
                        "type": "string",
                        "description": "The secret key or name to remove"
                    },
                    "namespace": {
                        "type": "string",
                        "description": "Optional namespace. If omitted, automatically resolves to current workspace namespace."
                    }
                },
                "required": ["key"]
            }
        },
        {
            "name": "run_command_with_secrets",
            "description": "Executes a shell command with secrets from the specified namespace injected into its environment variables in-memory, without ever writing a .env file to disk.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1, "description": "Program and arguments; prefer this over a shell string."},
                    "only": {"type": "array", "items": {"type": "string"}, "minItems": 1, "description": "Inject only these secret keys."},
                    "clean_env": {"type": "boolean", "default": true},
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute (e.g. 'npm test', 'python app.py')"
                    },
                    "namespace": {
                        "type": "string",
                        "description": "Optional namespace. If omitted, automatically resolves to current workspace namespace."
                    }
                },
                "anyOf": [{"required": ["command"]}, {"required": ["argv"]}]
            }
        }
    ])
}

fn tool_result(id: Value, content: String) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":content}]}})
}
fn tool_error(id: Value, message: impl ToString) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":{"isError":true,"content":[{"type":"text","text":message.to_string()}]}})
}
fn string_array(args: &Value, key: &str) -> Result<Option<Vec<String>>> {
    let Some(value) = args.get(key) else {
        return Ok(None);
    };
    let array = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("'{}' must be an array", key))?;
    Ok(Some(
        array
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow::anyhow!("'{}' must contain strings", key))
            })
            .collect::<Result<Vec<_>>>()?,
    ))
}
async fn call(client: &ClientBackend, name: &str, args: &Value) -> Result<String> {
    let default_ns = detect_workspace_namespace(None);
    let namespace = match args.get("namespace") {
        Some(value) => value
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Namespace must be a string"))?,
        None => &default_ns,
    };
    let key = || {
        args.get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Missing 'key' argument"))
    };
    match name {
        "list_namespaces" => Ok(serde_json::to_string(&client.list_namespaces().await?)?),
        "list_secrets" => Ok(serde_json::to_string(
            &client.list_secrets(namespace).await?,
        )?),
        "get_secret" => Ok(client.get_secret(namespace, key()?).await?.value),
        "set_secret" => {
            let value = args
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("Missing 'value' argument"))?;
            let description = args
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let ttl = match args.get("ttl_seconds") {
                Some(value) => Some(
                    value
                        .as_u64()
                        .ok_or_else(|| anyhow::anyhow!("TTL must be a positive integer"))?,
                ),
                None => None,
            };
            let meta = client
                .set_secret(namespace, key()?, value, description, vec![], ttl)
                .await?;
            Ok(serde_json::to_string(&meta)?)
        }
        "delete_secret" => Ok(serde_json::to_string(
            &json!({"deleted":client.delete_secret(namespace, key()?).await?}),
        )?),
        "renew_secret" => {
            let ttl = args
                .get("ttl_seconds")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow::anyhow!("Missing integer 'ttl_seconds'"))?;
            Ok(serde_json::to_string(
                &client.renew_secret(namespace, key()?, ttl).await?,
            )?)
        }
        "get_audit_events" => Ok(serde_json::to_string(
            &client
                .audit_events(
                    args.get("limit")
                        .and_then(Value::as_u64)
                        .unwrap_or(50)
                        .min(1000) as usize,
                )
                .await?,
        )?),
        "doctor" => Ok(serde_json::to_string(
            &crate::doctor::diagnose(
                client,
                namespace,
                string_array(args, "required_keys")?.unwrap_or_default(),
            )
            .await,
        )?),
        "run_command_with_secrets" => {
            let argv = string_array(args, "argv")?;
            let legacy = args.get("command").and_then(Value::as_str);
            if argv.is_some() && legacy.is_some() {
                anyhow::bail!("Supply either argv or command, not both");
            }
            let command = if let Some(argv) = argv {
                argv
            } else {
                let command = legacy.ok_or_else(|| anyhow::anyhow!("Supply argv or command"))?;
                #[cfg(unix)]
                let argv = vec!["sh".into(), "-c".into(), command.into()];
                #[cfg(windows)]
                let argv = vec!["cmd".into(), "/C".into(), command.into()];
                argv
            };
            let clean_env = match args.get("clean_env") {
                Some(value) => value
                    .as_bool()
                    .ok_or_else(|| anyhow::anyhow!("clean_env must be a boolean"))?,
                None => true,
            };
            let output = run_capture(
                client,
                RunOptions {
                    namespace: namespace.into(),
                    command,
                    clean_env,
                    only: string_array(args, "only")?,
                    redact: true,
                },
            )
            .await?;
            Ok(serde_json::to_string(&output)?)
        }
        _ => anyhow::bail!("Unknown tool"),
    }
}
pub fn handle_mcp_request<'a>(
    client: &'a (impl Into<ClientBackend> + Clone + Send + Sync),
    request: Value,
) -> Pin<Box<dyn Future<Output = Value> + Send + 'a>> {
    let client: ClientBackend = client.clone().into();
    Box::pin(async move { handle_mcp_request_inner(&client, request).await })
}

async fn handle_mcp_request_inner(client: &ClientBackend, request: Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32600,"message":"Invalid JSON-RPC request"}});
    }
    match request.get("method").and_then(Value::as_str) {
        Some("initialize") => {
            json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"agentsec","version":env!("CARGO_PKG_VERSION")}}})
        }
        Some("notifications/initialized") => Value::Null,
        Some("ping") => json!({"jsonrpc":"2.0","id":id,"result":{}}),
        Some("tools/list") => {
            json!({"jsonrpc":"2.0","id":id,"result":{"tools":get_tool_definitions()}})
        }
        Some("tools/call") => {
            let params = request.get("params").unwrap_or(&Value::Null);
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return tool_error(id, "Missing tool name");
            };
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            if !args.is_object() {
                return tool_error(id, "Arguments must be an object");
            }
            match call(client, name, &args).await {
                Ok(content) => tool_result(id, content),
                Err(error) => tool_error(id, error),
            }
        }
        _ => json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Method not found"}}),
    }
}
