use crate::backend::ClientBackend;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::{self, Read, Write},
    process::{Command, Stdio},
    thread,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone)]
pub struct RunOptions {
    pub namespace: String,
    pub command: Vec<String>,
    pub clean_env: bool,
    pub only: Option<Vec<String>>,
    pub redact: bool,
}
impl Default for RunOptions {
    fn default() -> Self {
        Self {
            namespace: String::new(),
            command: vec![],
            clean_env: false,
            only: None,
            redact: true,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Redactor {
    patterns: Vec<Vec<u8>>,
    buffer: Vec<u8>,
    longest: usize,
}
impl Redactor {
    pub fn new(values: impl IntoIterator<Item = String>) -> Self {
        let mut patterns = values
            .into_iter()
            .filter(|s| !s.is_empty())
            .map(String::into_bytes)
            .collect::<Vec<_>>();
        patterns.sort_by_key(|p| std::cmp::Reverse(p.len()));
        patterns.dedup();
        let longest = patterns.first().map_or(0, Vec::len);
        Self {
            patterns,
            buffer: vec![],
            longest,
        }
    }
    pub fn feed(&mut self, bytes: &[u8], eof: bool) -> Vec<u8> {
        self.buffer.extend_from_slice(bytes);
        let mut output = Vec::new();
        let mut cursor = 0;
        while cursor < self.buffer.len() {
            if !eof && self.buffer.len() - cursor < self.longest {
                break;
            }
            if let Some(pattern) = self
                .patterns
                .iter()
                .find(|p| self.buffer[cursor..].starts_with(p))
            {
                output.extend_from_slice(b"[REDACTED]");
                cursor += pattern.len();
            } else {
                output.push(self.buffer[cursor]);
                cursor += 1;
            }
        }
        self.buffer.drain(..cursor);
        output
    }
}
struct LimitedBuffer {
    bytes: Vec<u8>,
    truncated: bool,
}
impl LimitedBuffer {
    fn new() -> Self {
        Self {
            bytes: vec![],
            truncated: false,
        }
    }
    fn finish(mut self) -> String {
        if self.truncated {
            self.bytes.extend_from_slice(b"\n[output truncated]\n");
        }
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}
impl Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes
            .len()
            .min((1024 * 1024usize).saturating_sub(self.bytes.len()));
        self.bytes.extend_from_slice(&bytes[..count]);
        self.truncated |= count < bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn copy_filtered(
    mut reader: impl Read,
    mut writer: impl Write,
    values: Vec<String>,
) -> io::Result<()> {
    let mut redactor = Redactor::new(values);
    let mut bytes = [0u8; 8192];
    loop {
        let count = reader.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        writer.write_all(&redactor.feed(&bytes[..count], false))?;
        writer.flush()?;
    }
    writer.write_all(&redactor.feed(&[], true))?;
    writer.flush()
}
fn execute(
    options: RunOptions,
    secrets: HashMap<String, String>,
    capture: bool,
) -> Result<RunOutput> {
    let program = options
        .command
        .first()
        .ok_or_else(|| anyhow!("No command specified"))?;
    let mut command = Command::new(program);
    command.args(&options.command[1..]);
    if options.clean_env {
        command.env_clear();
        for name in ["PATH", "USER", "HOME"] {
            if let Ok(value) = std::env::var(name) {
                command.env(name, value);
            }
        }
    }
    // A child must never inherit the CLI's daemon administration credential.
    for name in [
        "AGENTSEC_TOKEN",
        "AGENTSEC_EXTERNAL_TOKEN",
        "TUNNEL_AUTH_TOKEN",
    ] {
        command.env_remove(name);
    }
    for (name, value) in &secrets {
        command.env(name, value);
    }
    let values = if options.redact {
        secrets.values().cloned().collect::<Vec<_>>()
    } else {
        vec![]
    };
    command
        .stdin(if capture {
            Stdio::null()
        } else {
            Stdio::inherit()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().context("Failed to start child command")?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let stdout_values = values.clone();
    let stdout_task = thread::spawn(move || -> io::Result<String> {
        if capture {
            let mut output = LimitedBuffer::new();
            copy_filtered(stdout, &mut output, stdout_values)?;
            Ok(output.finish())
        } else {
            copy_filtered(stdout, io::stdout().lock(), stdout_values)?;
            Ok(String::new())
        }
    });
    let stderr_task = thread::spawn(move || -> io::Result<String> {
        if capture {
            let mut output = LimitedBuffer::new();
            copy_filtered(stderr, &mut output, values)?;
            Ok(output.finish())
        } else {
            copy_filtered(stderr, io::stderr().lock(), values)?;
            Ok(String::new())
        }
    });
    let status = child.wait().context("Failed to wait for child command")?;
    let stdout = stdout_task
        .join()
        .map_err(|_| anyhow!("Output reader failed"))??;
    let stderr = stderr_task
        .join()
        .map_err(|_| anyhow!("Error-output reader failed"))??;
    Ok(RunOutput {
        exit_code: status.code().unwrap_or(1),
        stdout,
        stderr,
    })
}
async fn run(
    client: &(impl Into<ClientBackend> + Clone),
    options: RunOptions,
    capture: bool,
) -> Result<RunOutput> {
    if options.command.is_empty() {
        return Err(anyhow!("No command specified"));
    }
    let backend: ClientBackend = client.clone().into();
    let secrets = backend
        .inject_secrets(&options.namespace, options.only.clone())
        .await?;
    tokio::task::spawn_blocking(move || execute(options, secrets, capture))
        .await
        .context("Command worker failed")?
}
pub async fn run_with_secrets(
    client: &(impl Into<ClientBackend> + Clone),
    options: RunOptions,
) -> Result<i32> {
    Ok(run(client, options, false).await?.exit_code)
}
pub async fn run_capture(
    client: &(impl Into<ClientBackend> + Clone),
    options: RunOptions,
) -> Result<RunOutput> {
    run(client, options, true).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redaction_handles_every_chunk_boundary_and_overlapping_values() {
        let text = "prefix abcdefghi middle café-token suffix abc";
        for boundary in 0..=text.len() {
            let mut redactor =
                Redactor::new(vec!["abc".into(), "abcdefghi".into(), "café-token".into()]);
            let mut output = redactor.feed(&text.as_bytes()[..boundary], false);
            output.extend(redactor.feed(&text.as_bytes()[boundary..], false));
            output.extend(redactor.feed(&[], true));
            assert_eq!(
                String::from_utf8(output).unwrap(),
                "prefix [REDACTED] middle [REDACTED] suffix [REDACTED]"
            );
        }
    }
    #[test]
    fn redaction_preserves_non_secret_binary_data() {
        let mut redactor = Redactor::new(vec!["secret".into()]);
        assert_eq!(redactor.feed(&[0, 255, 1, 2], true), [0, 255, 1, 2]);
    }
}
