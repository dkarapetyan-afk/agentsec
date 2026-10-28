use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
const AUDIT_SHARDS: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub client: String,
    pub operation: String,
    pub namespace: Option<String>,
    pub key: Option<String>,
    pub outcome: String,
}

#[derive(Clone)]
pub struct AuditLog {
    events: Arc<[Mutex<VecDeque<AuditEvent>>; AUDIT_SHARDS]>,
    next: Arc<AtomicUsize>,
    path: Option<PathBuf>,
}

impl AuditLog {
    pub fn new(path: Option<PathBuf>) -> Self {
        let events = path
            .as_ref()
            .and_then(|p| fs::read_to_string(p).ok())
            .map(|text| {
                text.lines()
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .rev()
                    .take(1000)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let count = events.len();
        let mut buffers: [VecDeque<AuditEvent>; AUDIT_SHARDS] =
            std::array::from_fn(|_| VecDeque::new());
        for (index, event) in events.into_iter().rev().enumerate() {
            buffers[index % AUDIT_SHARDS].push_back(event);
        }
        Self {
            events: Arc::new(std::array::from_fn(|index| {
                Mutex::new(std::mem::take(&mut buffers[index]))
            })),
            next: Arc::new(AtomicUsize::new(count)),
            path,
        }
    }

    pub fn record(
        &self,
        client: &str,
        operation: &str,
        namespace: Option<&str>,
        key: Option<&str>,
        outcome: &str,
    ) -> Result<()> {
        let event = AuditEvent {
            timestamp: Utc::now(),
            client: client.into(),
            operation: operation.into(),
            namespace: namespace.map(str::to_owned),
            key: key.map(str::to_owned),
            outcome: outcome.into(),
        };
        if let Some(path) = &self.path {
            let mut options = OpenOptions::new();
            options.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(path)?;
            let mut line = serde_json::to_vec(&event)?;
            line.push(b'\n');
            file.write_all(&line)?;
        }
        let shard = self.next.fetch_add(1, Ordering::Relaxed) % AUDIT_SHARDS;
        let mut events = self.events[shard].lock().unwrap();
        events.push_back(event);
        while events.len() > 64 {
            events.pop_front();
        }
        Ok(())
    }

    pub async fn record_async(
        &self,
        client: &str,
        operation: &str,
        namespace: Option<&str>,
        key: Option<&str>,
        outcome: &str,
    ) -> Result<()> {
        let audit = self.clone();
        let client = client.to_owned();
        let operation = operation.to_owned();
        let namespace = namespace.map(str::to_owned);
        let key = key.map(str::to_owned);
        let outcome = outcome.to_owned();
        tokio::task::spawn_blocking(move || {
            audit.record(
                &client,
                &operation,
                namespace.as_deref(),
                key.as_deref(),
                &outcome,
            )
        })
        .await??;
        Ok(())
    }

    pub fn recent(&self, limit: usize) -> Vec<AuditEvent> {
        let mut events: Vec<_> = self
            .events
            .iter()
            .flat_map(|shard| shard.lock().unwrap().iter().cloned().collect::<Vec<_>>())
            .collect();
        events.sort_by_key(|event| std::cmp::Reverse(event.timestamp));
        events.truncate(limit.min(1000));
        events
    }
}
