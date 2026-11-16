use crate::{Error, Gate, Outcome, Scrubber, secrets::expose, wire};
use bogo_config::Upstream;
use rmcp::{
    RoleClient,
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    transport::Transport,
};
use std::{
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::Mutex,
};
const MAX_LINE: u64 = 16 * 1024 * 1024;
struct Writer {
    child: Child,
    stdin: ChildStdin,
}
pub struct ExactChildTransport {
    writer: Arc<Mutex<Writer>>,
    reader: BufReader<ChildStdout>,
    alive: Arc<AtomicBool>,
    gate: Arc<dyn Gate>,
    upstream: String,
    scrubber: Scrubber,
}
impl ExactChildTransport {
    pub fn spawn(
        upstream: String,
        config: &Upstream,
        gate: Arc<dyn Gate>,
        scrubber: Scrubber,
    ) -> Result<Self, Error> {
        let Upstream::Local { command, args, env } = config else {
            return Err(Error::Configuration);
        };
        let mut cmd = Command::new(command);
        // A fixed working directory: relative paths in `args` mean the same thing
        // to the owner's startup check and to the child, whatever directory BOGO
        // was started from.
        cmd.args(args)
            .current_dir("/")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // PATH is the only inherited variable. HOME, tokens, and unrelated credentials are absent.
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        for (name, value) in env {
            cmd.env(name, expose(value));
        }
        let mut child = cmd.spawn().map_err(|_| Error::NotSent)?;
        let stdin = child.stdin.take().ok_or(Error::NotSent)?;
        let stdout = child.stdout.take().ok_or(Error::NotSent)?;
        let stderr = child.stderr.take().ok_or(Error::NotSent)?;
        let scan = scrubber.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            loop {
                let mut line = Vec::new();
                match (&mut reader)
                    .take(MAX_LINE + 1)
                    .read_until(b'\n', &mut line)
                    .await
                {
                    Ok(0) | Err(_) => break,
                    Ok(_) if line.len() as u64 > MAX_LINE => {
                        tracing::warn!("upstream stderr withheld: oversized line");
                        break;
                    }
                    Ok(_) => {
                        tracing::debug!(stderr = %scan.text(&String::from_utf8_lossy(&line)), "upstream stderr")
                    }
                }
            }
        });
        Ok(Self {
            writer: Arc::new(Mutex::new(Writer { child, stdin })),
            reader: BufReader::new(stdout),
            alive: Arc::new(AtomicBool::new(true)),
            gate,
            upstream,
            scrubber,
        })
    }
}
impl Transport<RoleClient> for ExactChildTransport {
    type Error = Error;
    fn send(
        &mut self,
        message: ClientJsonRpcMessage,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'static {
        let writer = self.writer.clone();
        let alive = self.alive.clone();
        let gate = self.gate.clone();
        let upstream = self.upstream.clone();
        async move {
            let call = wire::marker(&message)?;
            let mut writer = writer.lock().await; // all queues and health checks precede dispatch
            if !alive.load(Ordering::SeqCst)
                || writer
                    .child
                    .try_wait()
                    .map_err(|_| Error::NotSent)?
                    .is_some()
            {
                if let Some(id) = &call {
                    gate.outcome(id, Outcome::NotSent);
                }
                return Err(Error::NotSent);
            }
            let mut bytes = if let Some(id) = &call {
                let forward = gate.dispatch(id.clone()).await?;
                wire::forward(&message, forward, &upstream)?
            } else {
                serde_json::to_vec(&message).map_err(|_| Error::Protocol)?
            };
            bytes.push(b'\n');
            // Linearization: no await between dispatch and this single write attempt.
            let written = match writer.stdin.write(&bytes).await {
                Ok(n) if n > 0 => n,
                _ => {
                    if let Some(id) = &call {
                        gate.outcome(id, Outcome::NotSent);
                    }
                    alive.store(false, Ordering::SeqCst);
                    return Err(Error::NotSent);
                }
            };
            if writer.stdin.write_all(&bytes[written..]).await.is_err() {
                if let Some(id) = &call {
                    gate.outcome(id, Outcome::Unknown);
                }
                alive.store(false, Ordering::SeqCst);
                return Err(Error::Unknown);
            }
            Ok(())
        }
    }
    async fn receive(&mut self) -> Option<ServerJsonRpcMessage> {
        let mut line = Vec::new();
        let message = match (&mut self.reader)
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut line)
            .await
        {
            Ok(n) if n > 0 && n as u64 <= MAX_LINE => self.scrubber.message(&line).ok(),
            _ => None,
        };
        if message.is_none() {
            self.alive.store(false, Ordering::SeqCst);
        }
        message
    }
    async fn close(&mut self) -> Result<(), Error> {
        self.alive.store(false, Ordering::SeqCst);
        let mut writer = self.writer.lock().await;
        let _ = writer.child.kill().await;
        Ok(())
    }
}
