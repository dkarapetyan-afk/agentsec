#![cfg(unix)]

use agentsec::backend::ClientBackend;
use agentsec::client::DaemonClient;
use agentsec::config::AppConfig;
use agentsec::direct::DirectClient;
use agentsec::mcp::serve_mcp;
use agentsec::runner::{run_capture, RunOptions};
use agentsec::store::Vault;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

struct Fixture {
    dir: PathBuf,
    config: AppConfig,
    daemon: Option<Child>,
}
impl Fixture {
    fn new() -> Self {
        let dir =
            std::env::temp_dir().join(format!("agentsec_concurrency_{}", rand::random::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        let config = AppConfig::load(Some(dir.clone()), Some(0)).unwrap();
        Self {
            dir,
            config,
            daemon: None,
        }
    }
    async fn start(&mut self) -> DaemonClient {
        self.daemon = Some(
            Command::new(env!("CARGO_BIN_EXE_agentsec"))
                .args(["--config-dir"])
                .arg(&self.dir)
                .args(["--port", "0", "daemon"])
                .env("TOKIO_WORKER_THREADS", "2")
                .env_remove("AGENTSEC_URL")
                .env_remove("AGENTSEC_SERVER_URL")
                .env_remove("AGENTSEC_TOKEN")
                .env_remove("AGENTSEC_HOST")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        timeout(Duration::from_secs(5), async {
            loop {
                if self.config.read_daemon_info().unwrap().is_some() {
                    let client = DaemonClient::new(&self.config).unwrap();
                    if client.health().await.is_ok() {
                        break client;
                    }
                }
                assert!(
                    self.daemon.as_mut().unwrap().try_wait().unwrap().is_none(),
                    "daemon exited during startup"
                );
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("daemon startup timed out")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(child) = &mut self.daemon {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

// A separate process could hold this lock. A safety deadline also lets the old
// blocking implementation fail an assertion instead of hanging the test runner.
struct HeldLock {
    release: Option<mpsc::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl HeldLock {
    fn new(vault: &Vault, namespace: &str) -> Self {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(
                vault
                    .namespace_path(namespace)
                    .unwrap()
                    .with_extension("lock"),
            )
            .unwrap();
        assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) }, 0);
        let (release, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = receiver.recv_timeout(Duration::from_secs(3));
            drop(file);
        });
        Self {
            release: Some(release),
            worker: Some(worker),
        }
    }
}
impl Drop for HeldLock {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_remains_responsive_while_many_requests_wait_for_the_vault() {
    let mut fixture = Fixture::new();
    let client = fixture.start().await;
    client
        .set_secret(
            "concurrency",
            "TEST_VALUE",
            "fixture-value",
            None,
            vec![],
            Some(60),
        )
        .await
        .unwrap();
    let lock_client = DirectClient::new(&fixture.config).await.unwrap();
    let held = HeldLock::new(lock_client.vault(), "concurrency");
    let mut readers = JoinSet::new();
    for _ in 0..24 {
        let client = client.clone();
        readers.spawn(async move { client.get_secret("concurrency", "TEST_VALUE").await });
    }
    sleep(Duration::from_millis(100)).await;
    let start = Instant::now();
    assert_eq!(
        timeout(Duration::from_millis(500), client.health())
            .await
            .expect("health was blocked by vault I/O")
            .unwrap()
            .status,
        "ok"
    );
    assert!(start.elapsed() < Duration::from_millis(500));
    timeout(
        Duration::from_millis(500),
        client.set_secret(
            "independent",
            "OTHER",
            "fixture-other-value",
            None,
            vec![],
            Some(60),
        ),
    )
    .await
    .expect("a locked namespace blocked a different namespace")
    .unwrap();
    assert_eq!(
        timeout(
            Duration::from_millis(500),
            client.get_secret("independent", "OTHER")
        )
        .await
        .unwrap()
        .unwrap()
        .value,
        "fixture-other-value"
    );
    drop(held);
    while let Some(result) = readers.join_next().await {
        assert_eq!(result.unwrap().unwrap().value, "fixture-value");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn direct_vault_io_does_not_block_the_async_executor() {
    let fixture = Fixture::new();
    let client = DirectClient::new(&fixture.config).await.unwrap();
    client
        .set_secret(
            "concurrency",
            "TEST_VALUE",
            "fixture-value",
            None,
            vec![],
            Some(60),
        )
        .await
        .unwrap();
    let lock_client = DirectClient::new(&fixture.config).await.unwrap();
    let held = HeldLock::new(lock_client.vault(), "concurrency");
    let start = Instant::now();
    let reader = tokio::spawn(async move { client.get_secret("concurrency", "TEST_VALUE").await });
    sleep(Duration::from_millis(50)).await;
    assert!(
        start.elapsed() < Duration::from_millis(500),
        "a synchronous file lock stalled the executor"
    );
    drop(held);
    assert_eq!(reader.await.unwrap().unwrap().value, "fixture-value");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_and_direct_processes_preserve_concurrent_writes_during_expiry() {
    let mut fixture = Fixture::new();
    let client = fixture.start().await;
    client
        .set_secret(
            "concurrency",
            "EXPIRES",
            "fixture-expiring",
            None,
            vec![],
            Some(1),
        )
        .await
        .unwrap();
    let work = async {
        let mut workers = JoinSet::new();
        for writer in 0..8 {
            let client = client.clone();
            workers.spawn(async move {
                for item in 0..8 {
                    let key = format!("HTTP_{writer}_{item}");
                    client
                        .set_secret("concurrency", &key, "fixture-value", None, vec![], Some(60))
                        .await
                        .unwrap();
                    assert_eq!(
                        client.get_secret("concurrency", &key).await.unwrap().value,
                        "fixture-value"
                    );
                    client.export_namespace("concurrency").await.unwrap();
                }
            });
        }
        for writer in 0..16 {
            let dir = fixture.dir.clone();
            workers.spawn(async move {
                let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_agentsec"))
                    .args(["--daemonless", "--config-dir"])
                    .arg(dir)
                    .args([
                        "set",
                        &format!("DIRECT_{writer}"),
                        "--namespace",
                        "concurrency",
                        "--ttl",
                        "60",
                    ])
                    .env_remove("AGENTSEC_TOKEN")
                    .env("TOKIO_WORKER_THREADS", "2")
                    .kill_on_drop(true)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(b"fixture-direct-value")
                    .await
                    .unwrap();
                assert!(child.wait().await.unwrap().success());
            });
        }
        while let Some(result) = workers.join_next().await {
            result.unwrap();
        }
        sleep(Duration::from_millis(1100)).await;
        assert!(client.get_secret("concurrency", "EXPIRES").await.is_err());
        let secrets = client.list_secrets("concurrency").await.unwrap();
        assert_eq!(secrets.len(), 80, "a concurrent writer lost updates");
        assert_eq!(client.health().await.unwrap().status, "ok");
    };
    timeout(Duration::from_secs(30), work)
        .await
        .expect("concurrent requests deadlocked");
}

#[tokio::test]
async fn mcp_serves_other_requests_during_a_command_and_drains_requests_at_eof() {
    let fixture = Fixture::new();
    let client = ClientBackend::from(DirectClient::new(&fixture.config).await.unwrap());
    let (mut input, reader) = tokio::io::duplex(32_768);
    let (writer, output) = tokio::io::duplex(32_768);
    let server = tokio::spawn(serve_mcp(client, BufReader::new(reader), writer));
    let slow = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_command_with_secrets","arguments":{"namespace":"concurrency","argv":["sh","-c","sleep 1"],"clean_env":true}}});
    input
        .write_all(format!("{slow}\n").as_bytes())
        .await
        .unwrap();
    input.write_all(b"{invalid json}\n").await.unwrap();
    let initialized = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
    input
        .write_all(format!("{initialized}\n").as_bytes())
        .await
        .unwrap();
    for id in 2..=70 {
        let request = json!({"jsonrpc":"2.0","id":id,"method":"ping"});
        input
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
    }
    input.shutdown().await.unwrap();
    let mut output = BufReader::new(output).lines();
    let responses = timeout(Duration::from_secs(5), async {
        let mut responses = Vec::new();
        while let Some(line) = output.next_line().await.unwrap() {
            responses.push(serde_json::from_str::<Value>(&line).unwrap());
        }
        responses
    })
    .await
    .unwrap();
    server.await.unwrap().unwrap();
    assert_eq!(responses.len(), 71);
    assert_ne!(
        responses[0]["id"], 1,
        "a command blocked unrelated MCP requests"
    );
    let ids: HashSet<_> = responses.iter().filter_map(|r| r["id"].as_u64()).collect();
    assert_eq!(ids, (1..=70).collect());
    assert_eq!(
        responses
            .iter()
            .filter(|r| r["error"]["code"] == -32700)
            .count(),
        1
    );
    assert!(responses.iter().find(|r| r["id"] == 1).unwrap()["result"]
        .get("isError")
        .is_none());
}

#[tokio::test]
async fn failed_vault_lock_cannot_overwrite_persisted_secrets() {
    let fixture = Fixture::new();
    let client = DirectClient::new(&fixture.config).await.unwrap();
    client
        .set_secret(
            "concurrency",
            "PRESERVED",
            "fixture-value",
            None,
            vec![],
            Some(60),
        )
        .await
        .unwrap();
    let namespace_file = client.vault().namespace_path("concurrency").unwrap();
    let namespace_lock = namespace_file.with_extension("lock");
    let before = fs::read(&namespace_file).unwrap_or_else(|error| {
        let files: Vec<_> = fs::read_dir(&fixture.config.vault_path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        panic!(
            "committed namespace missing: {error}; expected {:?}; found {files:?}",
            namespace_file.file_name()
        );
    });
    fs::remove_file(&namespace_lock).unwrap();
    fs::create_dir(&namespace_lock).unwrap();
    assert!(client
        .set_secret(
            "concurrency",
            "SHOULD_FAIL",
            "fixture-value",
            None,
            vec![],
            Some(60)
        )
        .await
        .is_err());
    assert_eq!(before, fs::read(&namespace_file).unwrap());
}

#[test]
fn a_running_child_does_not_occupy_the_only_blocking_worker() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let fixture = Fixture::new();
        let client = DirectClient::new(&fixture.config).await.unwrap();
        client
            .set_secret(
                "concurrency",
                "TEST_VALUE",
                "fixture-child-value",
                None,
                vec![],
                Some(60),
            )
            .await
            .unwrap();
        let ready = fixture.dir.join("child-ready");
        client
            .set_secret(
                "concurrency",
                "READY_FILE",
                &ready.to_string_lossy(),
                None,
                vec![],
                Some(60),
            )
            .await
            .unwrap();
        let runner = client.clone();
        let child = tokio::spawn(async move {
            run_capture(
                &runner,
                RunOptions {
                    namespace: "concurrency".into(),
                    command: vec![
                        "sh".into(),
                        "-c".into(),
                        "printf ready > \"$READY_FILE\"; sleep 2; printf '%s' \"$TEST_VALUE\""
                            .into(),
                    ],
                    only: Some(vec!["TEST_VALUE".into(), "READY_FILE".into()]),
                    clean_env: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap()
        });
        timeout(Duration::from_millis(500), async {
            while !tokio::fs::try_exists(&ready).await.unwrap() {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("process startup retained the only blocking worker");
        assert!(
            !child.is_finished(),
            "child already exited before the concurrency check"
        );
        timeout(
            Duration::from_millis(500),
            client.set_secret(
                "concurrency",
                "TEST_VALUE",
                "fixture-updated-value",
                None,
                vec![],
                Some(60),
            ),
        )
        .await
        .expect("a child wait retained a vault lock or blocking worker")
        .unwrap();
        assert_eq!(
            timeout(
                Duration::from_millis(500),
                client.get_secret("concurrency", "TEST_VALUE")
            )
            .await
            .unwrap()
            .unwrap()
            .value,
            "fixture-updated-value"
        );
        let output = child.await.unwrap();
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.stdout, "[REDACTED]");
    });
}

#[test]
fn a_contended_namespace_does_not_occupy_the_only_blocking_worker() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let fixture = Fixture::new();
        let client = DirectClient::new(&fixture.config).await.unwrap();
        client
            .set_secret(
                "concurrency",
                "TEST_VALUE",
                "fixture-value",
                None,
                vec![],
                Some(60),
            )
            .await
            .unwrap();
        let held = HeldLock::new(client.vault(), "concurrency");
        let waiting_client = client.clone();
        let waiter =
            tokio::spawn(
                async move { waiting_client.get_secret("concurrency", "TEST_VALUE").await },
            );
        sleep(Duration::from_millis(50)).await;
        timeout(
            Duration::from_millis(500),
            client.set_secret(
                "independent",
                "OTHER",
                "fixture-other-value",
                None,
                vec![],
                Some(60),
            ),
        )
        .await
        .expect("namespace contention blocked unrelated storage")
        .unwrap();
        drop(held);
        waiter.await.unwrap().unwrap();
    });
}

#[tokio::test]
async fn saturated_mcp_commands_leave_capacity_for_other_operations() {
    let fixture = Fixture::new();
    let client = ClientBackend::from(DirectClient::new(&fixture.config).await.unwrap());
    let (mut input, reader) = tokio::io::duplex(65_536);
    let (writer, output) = tokio::io::duplex(65_536);
    let server = tokio::spawn(serve_mcp(client, BufReader::new(reader), writer));
    for id in 1..=32 {
        let request = json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"run_command_with_secrets","arguments":{"namespace":"concurrency","argv":["sleep","2"],"clean_env":true}}});
        input
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
    }
    let ping = json!({"jsonrpc":"2.0","id":1000,"method":"ping"});
    input
        .write_all(format!("{ping}\n").as_bytes())
        .await
        .unwrap();
    input.shutdown().await.unwrap();
    let mut lines = BufReader::new(output).lines();
    let first = timeout(Duration::from_millis(500), lines.next_line())
        .await
        .expect("running commands blocked the MCP request reader")
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&first).unwrap()["id"], 1000);
    let mut responses = 1;
    timeout(Duration::from_secs(10), async {
        while lines.next_line().await.unwrap().is_some() {
            responses += 1;
        }
    })
    .await
    .unwrap();
    assert_eq!(responses, 33);
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn cancelled_callers_do_not_release_a_transaction_before_its_commit() {
    let fixture = Fixture::new();
    let client = DirectClient::new(&fixture.config).await.unwrap();
    client
        .set_secret(
            "concurrency",
            "TEST_VALUE",
            "fixture-original",
            None,
            vec![],
            Some(60),
        )
        .await
        .unwrap();
    let held = HeldLock::new(client.vault(), "concurrency");
    let writer = client.clone();
    let task = tokio::spawn(async move {
        writer
            .set_secret(
                "concurrency",
                "TEST_VALUE",
                "fixture-committed",
                None,
                vec![],
                Some(60),
            )
            .await
    });
    sleep(Duration::from_millis(50)).await;
    task.abort();
    let _ = task.await;
    drop(held);
    timeout(Duration::from_secs(5), client.vault().wait_for_pending())
        .await
        .unwrap();
    assert_eq!(
        client
            .get_secret("concurrency", "TEST_VALUE")
            .await
            .unwrap()
            .value,
        "fixture-committed"
    );
}

#[tokio::test]
async fn missing_selected_credentials_prevent_process_startup() {
    let fixture = Fixture::new();
    let client = DirectClient::new(&fixture.config).await.unwrap();
    let output = run_capture(
        &client,
        RunOptions {
            namespace: "concurrency".into(),
            command: vec!["sh".into(), "-c".into(), "exit 0".into()],
            only: Some(vec!["MISSING".into()]),
            clean_env: true,
            ..Default::default()
        },
    )
    .await;
    assert!(
        output.is_err(),
        "a command started without its required credential"
    );
}
