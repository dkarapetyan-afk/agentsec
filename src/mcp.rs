use crate::client::DaemonClient;
use crate::config::detect_workspace_namespace;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::process::{Command, Stdio};

#[derive(Serialize, Deserialize, Debug)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}



pub async fn run_mcp_server(client: DaemonClient) -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[agentsec-mcp] Error reading stdin: {}", e);
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(req) => req,
            Err(e) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32700,
                        "message": format!("Parse error: {}", e)
                    }
                });
                writeln!(stdout, "{}", serde_json::to_string(&err_resp)?)?;
                stdout.flush()?;
                continue;
            }
        };

        let id = request.id.clone().unwrap_or(Value::Null);

        match request.method.as_str() {
            "initialize" => {
                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "agentsec",
                            "version": env!("CARGO_PKG_VERSION")
                        }
                    }
                });
                writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                stdout.flush()?;
            }
            "notifications/initialized" => {
                // No response needed for notification
            }
            "ping" => {
                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {}
                });
                writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                stdout.flush()?;
            }
            "tools/list" => {
                let tools = get_tool_definitions();
                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "tools": tools
                    }
                });
                writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                stdout.flush()?;
            }
            "tools/call" => {
                let response = handle_tool_call(&client, id, request.params).await;
                writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                stdout.flush()?;
            }
            other => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32601,
                        "message": format!("Method not found: {}", other)
                    }
                });
                writeln!(stdout, "{}", serde_json::to_string(&err_resp)?)?;
                stdout.flush()?;
            }
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
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute (e.g. 'npm test', 'python app.py')"
                    },
                    "namespace": {
                        "type": "string",
                        "description": "Optional namespace. If omitted, automatically resolves to current workspace namespace."
                    }
                },
                "required": ["command"]
            }
        }
    ])
}

async fn handle_tool_call(client: &DaemonClient, id: Value, params: Option<Value>) -> Value {
    let params = match params {
        Some(p) => p,
        None => {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32602, "message": "Missing params" }
            })
        }
    };

    let name = match params.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32602, "message": "Missing tool name" }
            })
        }
    };

    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    let default_ns = detect_workspace_namespace(None);

    let resolve_ns = |args: &Value| -> String {
        args.get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or(&default_ns)
            .to_string()
    };

    match name {
        "list_namespaces" => match client.list_namespaces().await {
            Ok(ns) => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&ns).unwrap()
                    }]
                }
            }),
            Err(e) => make_tool_error(id, &e.to_string()),
        },
        "list_secrets" => {
            let ns = resolve_ns(&arguments);
            match client.list_secrets(&ns).await {
                Ok(secrets) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&secrets).unwrap()
                        }]
                    }
                }),
                Err(e) => make_tool_error(id, &e.to_string()),
            }
        }
        "get_secret" => {
            let key = match arguments.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return make_tool_error(id, "Missing 'key' argument"),
            };
            let ns = resolve_ns(&arguments);
            match client.get_secret(&ns, key).await {
                Ok(detail) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": detail.value
                        }]
                    }
                }),
                Err(e) => make_tool_error(id, &e.to_string()),
            }
        }
        "set_secret" => {
            let key = match arguments.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return make_tool_error(id, "Missing 'key' argument"),
            };
            let value = match arguments.get("value").and_then(|v| v.as_str()) {
                Some(v) => v,
                None => return make_tool_error(id, "Missing 'value' argument"),
            };
            let ns = resolve_ns(&arguments);
            let desc = arguments.get("description").and_then(|v| v.as_str()).map(String::from);
            let ttl = arguments.get("ttl_seconds").and_then(|v| v.as_u64());

            match client.set_secret(&ns, key, value, desc, vec![], ttl).await {
                Ok(meta) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": format!("Successfully stored secret '{}' in namespace '{}' (preview: {})", meta.name, meta.namespace, meta.masked_preview)
                        }]
                    }
                }),
                Err(e) => make_tool_error(id, &e.to_string()),
            }
        }
        "delete_secret" => {
            let key = match arguments.get("key").and_then(|v| v.as_str()) {
                Some(k) => k,
                None => return make_tool_error(id, "Missing 'key' argument"),
            };
            let ns = resolve_ns(&arguments);
            match client.delete_secret(&ns, key).await {
                Ok(deleted) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": if deleted {
                                format!("Secret '{}' removed from namespace '{}'", key, ns)
                            } else {
                                format!("Secret '{}' did not exist in namespace '{}'", key, ns)
                            }
                        }]
                    }
                }),
                Err(e) => make_tool_error(id, &e.to_string()),
            }
        }
        "run_command_with_secrets" => {
            let cmd_str = match arguments.get("command").and_then(|v| v.as_str()) {
                Some(c) => c,
                None => return make_tool_error(id, "Missing 'command' argument"),
            };
            let ns = resolve_ns(&arguments);
            match client.export_namespace(&ns).await {
                Ok(secrets) => {
                    let mut cmd = Command::new("sh");
                    cmd.arg("-c").arg(cmd_str);
                    for (k, v) in secrets {
                        cmd.env(k, v);
                    }
                    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

                    match cmd.output() {
                        Ok(output) => {
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            let code = output.status.code().unwrap_or(-1);
                            json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "content": [{
                                        "type": "text",
                                        "text": format!("Exit Code: {}\nSTDOUT:\n{}\nSTDERR:\n{}", code, stdout, stderr)
                                    }]
                                }
                            })
                        }
                        Err(e) => make_tool_error(id, &format!("Failed to execute command: {}", e)),
                    }
                }
                Err(e) => make_tool_error(id, &e.to_string()),
            }
        }
        other => make_tool_error(id, &format!("Unknown tool: {}", other)),
    }
}

fn make_tool_error(id: Value, msg: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{
                "type": "text",
                "text": format!("Error: {}", msg)
            }],
            "isError": true
        }
    })
}

pub fn handle_mcp_request(vault: &crate::store::Vault, req: Value) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = match req.get("method").and_then(|v| v.as_str()) {
        Some(m) => m,
        None => {
            return json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32600, "message": "Invalid Request: missing method" }
            });
        }
    };
    let params = req.get("params").cloned();

    match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "agentsec",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        }),
        "notifications/initialized" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        }),
        "ping" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        }),
        "tools/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "tools": get_tool_definitions()
            }
        }),
        "tools/call" => {
            let params = match params {
                Some(p) => p,
                None => return json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32602, "message": "Missing params" }
                }),
            };
            let name = match params.get("name").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => return json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32602, "message": "Missing tool name" }
                }),
            };
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            let default_ns = detect_workspace_namespace(None);
            let resolve_ns = |args: &Value| -> String {
                args.get("namespace")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&default_ns)
                    .to_string()
            };

            match name {
                "list_namespaces" => {
                    let ns = vault.list_namespaces();
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&ns).unwrap_or_default()
                            }]
                        }
                    })
                }
                "list_secrets" => {
                    let ns = resolve_ns(&arguments);
                    let secrets = vault.list_secrets(&ns);
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": serde_json::to_string_pretty(&secrets).unwrap_or_default()
                            }]
                        }
                    })
                }
                "get_secret" => {
                    let key = match arguments.get("key").and_then(|v| v.as_str()) {
                        Some(k) => k,
                        None => return make_tool_error(id, "Missing 'key' argument"),
                    };
                    let ns = resolve_ns(&arguments);
                    match vault.get(&ns, key) {
                        Some(entry) => json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": entry.value.expose_secret()
                                }]
                            }
                        }),
                        None => make_tool_error(id, &format!("Secret '{}' not found in namespace '{}'", key, ns)),
                    }
                }
                "set_secret" => {
                    let key = match arguments.get("key").and_then(|v| v.as_str()) {
                        Some(k) => k,
                        None => return make_tool_error(id, "Missing 'key' argument"),
                    };
                    let value = match arguments.get("value").and_then(|v| v.as_str()) {
                        Some(v) => v,
                        None => return make_tool_error(id, "Missing 'value' argument"),
                    };
                    let ns = resolve_ns(&arguments);
                    let desc = arguments.get("description").and_then(|v| v.as_str()).map(String::from);
                    let ttl = arguments.get("ttl_seconds").and_then(|v| v.as_u64());

                    match vault.set(&ns, key, value, desc, vec![], ttl) {
                        Ok(meta) => json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": format!("Stored secret '{}' in namespace '{}' (preview: {})", meta.name, meta.namespace, meta.masked_preview)
                                }]
                            }
                        }),
                        Err(e) => make_tool_error(id, &e.to_string()),
                    }
                }
                "delete_secret" => {
                    let key = match arguments.get("key").and_then(|v| v.as_str()) {
                        Some(k) => k,
                        None => return make_tool_error(id, "Missing 'key' argument"),
                    };
                    let ns = resolve_ns(&arguments);
                    match vault.delete(&ns, key) {
                        Ok(deleted) => json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": if deleted {
                                        format!("Deleted secret '{}' from namespace '{}'", key, ns)
                                    } else {
                                        format!("Secret '{}' not found in namespace '{}'", key, ns)
                                    }
                                }]
                            }
                        }),
                        Err(e) => make_tool_error(id, &e.to_string()),
                    }
                }
                other => make_tool_error(id, &format!("Unknown tool: {}", other)),
            }
        }
        other => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": format!("Method not found: {}", other)
            }
        }),
    }
}
