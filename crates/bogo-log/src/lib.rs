//! BOGO's audit log: the only durable authority (ARCHITECTURE §3.9).
//!
//! One JSON object per line. Each line carries the SHA-256 of the previous
//! line, newline included. A writer thread commits every waiting entry, runs
//! one full sync (`F_FULLFSYNC` on macOS, through `File::sync_all`) and only
//! then releases the callers, so whatever a caller does after `append`
//! returns happens after its record is durable.
mod event;
pub mod outcome;
pub mod registry;
pub mod verify;

pub use event::{ApproverEntry, Hex, LogEvent, RevokedBy};
pub use outcome::Outcome;
pub use registry::{AgentState, ApproverState, Registry};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::mpsc,
    time::{SystemTime, UNIX_EPOCH},
};

pub const VERSION: u32 = 1;
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("audit log I/O failed: {0}")]
    Io(String),
    #[error("audit log line {line} is corrupt: {why}")]
    Corrupt { line: usize, why: String },
    #[error("audit log writer has failed; nothing more is recorded until it is fixed")]
    Failed,
}

#[derive(Serialize, Deserialize)]
struct Line {
    v: u32,
    seq: u64,
    prev: String,
    ts: String,
    #[serde(flatten)]
    event: LogEvent,
}

/// One verified entry.
#[derive(Clone, Debug)]
pub struct Entry {
    pub seq: u64,
    pub ts: String,
    pub event: LogEvent,
    /// SHA-256 of this line including its newline.
    pub hash: [u8; 32],
    /// 1-based line number in the file.
    pub line: usize,
    pub raw: String,
}

/// Read and check the whole chain. A final line without a newline is reported
/// as `torn` and not returned; any complete bad line is corruption.
pub fn read(path: &Path) -> Result<(Vec<Entry>, Option<Vec<u8>>), LogError> {
    let mut bytes = Vec::new();
    match File::open(path) {
        Ok(mut f) => {
            f.read_to_end(&mut bytes).map_err(io)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), None)),
        Err(e) => return Err(io(e)),
    }
    let (complete, torn) = match bytes.iter().rposition(|b| *b == b'\n') {
        Some(i) if i + 1 == bytes.len() => (&bytes[..], None),
        Some(i) => (&bytes[..=i], Some(bytes[i + 1..].to_vec())),
        None if bytes.is_empty() => (&bytes[..], None),
        None => (&bytes[..0], Some(bytes.clone())),
    };
    let mut entries = Vec::new();
    let mut prev = GENESIS.to_string();
    for (i, raw) in complete.split_inclusive(|b| *b == b'\n').enumerate() {
        let line = i + 1;
        let corrupt = |why: &str| LogError::Corrupt {
            line,
            why: why.into(),
        };
        let text = std::str::from_utf8(raw).map_err(|_| corrupt("not UTF-8"))?;
        let parsed: Line =
            serde_json::from_str(text.trim_end_matches('\n')).map_err(|e| corrupt(&e.to_string()))?;
        if parsed.v != VERSION {
            return Err(corrupt("unknown entry version"));
        }
        if parsed.seq != line as u64 {
            return Err(corrupt("sequence number out of order"));
        }
        if parsed.prev != prev {
            return Err(corrupt("previous-hash link broken"));
        }
        let hash: [u8; 32] = Sha256::digest(raw).into();
        prev = hex::encode(hash);
        entries.push(Entry {
            seq: parsed.seq,
            ts: parsed.ts,
            event: parsed.event,
            hash,
            line,
            raw: text.trim_end_matches('\n').into(),
        });
    }
    Ok((entries, torn))
}

fn io(e: std::io::Error) -> LogError {
    LogError::Io(e.to_string())
}

/// RFC 3339 UTC with milliseconds, from the wall clock. Timestamps are for the
/// owner; ordering comes from `seq`.
pub fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let (secs, ms) = (now.as_secs() as i64, now.subsec_millis());
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        tod / 3600,
        tod % 3600 / 60,
        tod % 60
    )
}

struct Job {
    events: Vec<LogEvent>,
    reply: tokio::sync::oneshot::Sender<Result<Vec<u64>, LogError>>,
}

/// The single writer. Cloning shares the same writer thread.
#[derive(Clone)]
pub struct Log {
    tx: mpsc::Sender<Job>,
    path: PathBuf,
}

pub struct Opened {
    pub log: Log,
    pub entries: Vec<Entry>,
    /// Set when a torn final line was moved aside on open.
    pub recovered_tail: Option<PathBuf>,
}

impl Log {
    /// Open, check the chain, and set aside a torn tail (recording
    /// `tail_recovered`). Refuses to open a log with a corrupt complete line.
    /// The caller must hold the single-writer lock.
    pub fn open(path: &Path) -> Result<Opened, LogError> {
        let (mut entries, torn) = read(path)?;
        let mut recovered_tail = None;
        if let Some(torn) = &torn {
            let aside = path.with_file_name(format!(
                "audit.torn.{}",
                timestamp().replace([':', '.'], "-")
            ));
            std::fs::write(&aside, torn).map_err(io)?;
            File::open(&aside).and_then(|f| f.sync_all()).map_err(io)?;
            let keep: u64 = entries.iter().map(|e| e.raw.len() as u64 + 1).sum();
            let f = OpenOptions::new().write(true).open(path).map_err(io)?;
            f.set_len(keep).map_err(io)?;
            f.sync_all().map_err(io)?;
            recovered_tail = Some(aside);
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(io)?;
        let mut writer = Writer {
            file,
            seq: entries.last().map_or(0, |e| e.seq),
            prev: entries
                .last()
                .map_or(GENESIS.to_string(), |e| hex::encode(e.hash)),
            failed: false,
        };
        if let (Some(torn), Some(aside)) = (&torn, &recovered_tail) {
            let event = LogEvent::TailRecovered {
                torn_sha256: hex::encode(Sha256::digest(torn)),
                moved_to: aside
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            };
            writer.commit(std::slice::from_ref(&event))?;
            entries = read(path)?.0;
        }
        let (tx, rx) = mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name("bogo-log-writer".into())
            .spawn(move || writer.run(rx))
            .map_err(io)?;
        Ok(Opened {
            log: Log {
                tx,
                path: path.to_path_buf(),
            },
            entries,
            recovered_tail,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append entries in order as one durable batch; returns their `seq`s once
    /// they are on disk.
    pub async fn append_all(&self, events: Vec<LogEvent>) -> Result<Vec<u64>, LogError> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.tx
            .send(Job { events, reply })
            .map_err(|_| LogError::Failed)?;
        rx.await.map_err(|_| LogError::Failed)?
    }

    pub async fn append(&self, event: LogEvent) -> Result<u64, LogError> {
        Ok(self.append_all(vec![event]).await?[0])
    }

    /// Re-read and check the whole chain from disk.
    pub fn entries(&self) -> Result<Vec<Entry>, LogError> {
        Ok(read(&self.path)?.0)
    }
}

struct Writer {
    file: File,
    seq: u64,
    prev: String,
    failed: bool,
}

impl Writer {
    fn run(mut self, rx: mpsc::Receiver<Job>) {
        while let Ok(first) = rx.recv() {
            let mut jobs = vec![first];
            while let Ok(more) = rx.try_recv() {
                jobs.push(more);
            }
            let all: Vec<LogEvent> = jobs.iter().flat_map(|j| j.events.clone()).collect();
            match self.commit(&all) {
                Ok(seqs) => {
                    let mut seqs = seqs.into_iter();
                    for job in jobs {
                        let mine: Vec<u64> = seqs.by_ref().take(job.events.len()).collect();
                        let _ = job.reply.send(Ok(mine));
                    }
                }
                Err(e) => {
                    let why = e.to_string();
                    for job in jobs {
                        let _ = job.reply.send(Err(LogError::Io(why.clone())));
                    }
                }
            }
        }
    }

    /// Write every line, then one full sync. On any failure the writer stops
    /// for good: nothing further is acknowledged as durable.
    fn commit(&mut self, events: &[LogEvent]) -> Result<Vec<u64>, LogError> {
        if self.failed {
            return Err(LogError::Failed);
        }
        let mut buf = Vec::new();
        let mut seqs = Vec::new();
        let (mut seq, mut prev) = (self.seq, self.prev.clone());
        for event in events {
            seq += 1;
            let mut line = serde_json::to_vec(&Line {
                v: VERSION,
                seq,
                prev: prev.clone(),
                ts: timestamp(),
                event: event.clone(),
            })
            .map_err(|e| LogError::Io(e.to_string()))?;
            line.push(b'\n');
            prev = hex::encode(Sha256::digest(&line));
            buf.extend_from_slice(&line);
            seqs.push(seq);
        }
        let result = self
            .file
            .write_all(&buf)
            .and_then(|_| self.file.sync_all());
        if let Err(e) = result {
            self.failed = true;
            return Err(io(e));
        }
        self.seq = seq;
        self.prev = prev;
        Ok(seqs)
    }
}
