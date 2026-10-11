use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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
    events: Arc<Mutex<VecDeque<AuditEvent>>>,
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
        Self {
            events: Arc::new(Mutex::new(events.into_iter().rev().collect())),
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
        let mut events = self.events.lock().unwrap();
        if let Some(path) = &self.path {
            let mut options = OpenOptions::new();
            options.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(path)?;
            serde_json::to_writer(&mut file, &event)?;
            file.write_all(b"\n")?;
        }
        events.push_back(event);
        while events.len() > 1000 {
            events.pop_front();
        }
        Ok(())
    }

    pub fn recent(&self, limit: usize) -> Vec<AuditEvent> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .rev()
            .take(limit.min(1000))
            .cloned()
            .collect()
    }
}
