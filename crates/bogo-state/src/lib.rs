//! `~/.bogo` (ARCHITECTURE §6): layout and permissions, the single-writer
//! lock, BOGO's own keys, the boot counter, and the registry caches. Every
//! cache is rebuilt from the log whenever it is missing, unreadable or does
//! not match the log, so none of this is security state the log can't rebuild.
use bogo_log::{AgentState, ApproverState, Entry, Log, Registry};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("{path}: {why}")]
    Unsafe { path: String, why: String },
    #[error("another BOGO process holds the writer lock ({0}); stop it first")]
    Locked(String),
    #[error("{0}")]
    Io(String),
    #[error(transparent)]
    Log(#[from] bogo_log::LogError),
}

fn io(path: &Path) -> impl Fn(std::io::Error) -> StateError + '_ {
    move |e| StateError::Io(format!("{}: {e}", path.display()))
}

pub struct Home {
    root: PathBuf,
}

/// Held for as long as this process is BOGO's single writer.
pub struct WriterLock {
    _file: File,
}

pub struct MacKeys {
    pub e2e: bogo_e2e::SecretKey,
    pub e2e_public: [u8; 32],
    pub relay: SigningKey,
    /// SHA-256 of the E2E public key.
    pub bogo_id: [u8; 32],
}

/// How the registry was obtained at startup.
#[derive(Debug, PartialEq, Eq)]
pub enum RegistrySource {
    /// Checkpoint at `checkpoint`, then `replayed` later entries.
    Checkpoint { checkpoint: u64, replayed: usize },
    /// Rebuilt from the whole log; `why` says what was wrong with the cache.
    Rebuilt { why: String },
}

#[derive(Serialize, Deserialize)]
struct ApproversCache {
    v: u32,
    log_seq: u64,
    log_hash: String,
    approvers: Vec<ApproverState>,
}

#[derive(Serialize, Deserialize)]
struct AgentsCache {
    v: u32,
    log_seq: u64,
    log_hash: String,
    agents: Vec<AgentState>,
}

#[derive(Serialize, Deserialize)]
struct Boot {
    v: u32,
    boot_seq: u64,
}

impl Home {
    pub fn default_root() -> Result<PathBuf, StateError> {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join(".bogo"))
            .ok_or_else(|| StateError::Io("HOME is not set".into()))
    }

    /// Create the layout if needed and refuse a home that others can reach.
    pub fn open(root: &Path) -> Result<Home, StateError> {
        let home = Home {
            root: root.to_path_buf(),
        };
        for dir in [root, &home.keys_dir(), &home.log_dir(), &home.state_dir(), &home.run_dir()] {
            match std::fs::symlink_metadata(dir) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::create_dir(dir).map_err(io(dir))?;
                    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                        .map_err(io(dir))?;
                }
                Err(e) => return Err(io(dir)(e)),
            }
            let meta = std::fs::symlink_metadata(dir).map_err(io(dir))?;
            if !meta.is_dir() {
                return Err(unsafe_path(dir, "must be a directory, not a symlink or file"));
            }
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(unsafe_path(
                    dir,
                    &format!("has mode {:o}; it must be 0700", meta.permissions().mode() & 0o777),
                ));
            }
        }
        Ok(home)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    fn keys_dir(&self) -> PathBuf {
        self.root.join("keys")
    }
    fn log_dir(&self) -> PathBuf {
        self.root.join("log")
    }
    fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }
    fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }
    pub fn log_path(&self) -> PathBuf {
        self.log_dir().join("audit.jsonl")
    }

    /// Take the single-writer lock (`run/lock`), refusing if it is held.
    pub fn lock(&self) -> Result<WriterLock, StateError> {
        let path = self.run_dir().join("lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(io(&path))?;
        let mine = file.metadata().map_err(io(&path))?.uid();
        let root_owner = std::fs::metadata(&self.root).map_err(io(&self.root))?.uid();
        if mine != root_owner {
            return Err(unsafe_path(&self.root, "is not owned by the user running BOGO"));
        }
        match file.try_lock() {
            Ok(()) => Ok(WriterLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => {
                Err(StateError::Locked(path.display().to_string()))
            }
            Err(std::fs::TryLockError::Error(e)) => Err(io(&path)(e)),
        }
    }

    /// Load BOGO's keys, creating them on first use (0600, owner only).
    pub fn keys(&self, _lock: &WriterLock) -> Result<MacKeys, StateError> {
        let e2e_path = self.keys_dir().join("mac_e2e.key");
        let relay_path = self.keys_dir().join("mac_relay.key");
        let mut e2e_raw = self.key_file(&e2e_path, || {
            bogo_e2e::secret_bytes(&bogo_e2e::keypair().0)
        })?;
        let mut relay_raw = self.key_file(&relay_path, || {
            SigningKey::generate(&mut rand::rngs::OsRng).to_bytes()
        })?;
        let e2e = bogo_e2e::secret_from(&e2e_raw)
            .map_err(|_| unsafe_path(&e2e_path, "is not an X25519 key"))?;
        let relay = SigningKey::from_bytes(&relay_raw);
        e2e_raw.zeroize();
        relay_raw.zeroize();
        let e2e_public = bogo_e2e::public_bytes(&bogo_e2e::public_of(&e2e));
        Ok(MacKeys {
            bogo_id: Sha256::digest(e2e_public).into(),
            e2e,
            e2e_public,
            relay,
        })
    }

    fn key_file(&self, path: &Path, make: impl Fn() -> [u8; 32]) -> Result<[u8; 32], StateError> {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut key = make();
                write_atomic(path, &key)?;
                let out = key;
                key.zeroize();
                Ok(out)
            }
            Err(e) => Err(io(path)(e)),
            Ok(meta) => {
                if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
                    return Err(unsafe_path(path, "must be a regular file with mode 0600"));
                }
                let mut buf = Vec::new();
                File::open(path)
                    .and_then(|mut f| f.read_to_end(&mut buf))
                    .map_err(io(path))?;
                let key: [u8; 32] = buf
                    .as_slice()
                    .try_into()
                    .map_err(|_| unsafe_path(path, "must hold exactly 32 bytes"))?;
                buf.zeroize();
                Ok(key)
            }
        }
    }

    /// Increment and sync `state/boot`. It orders boot notices only. The log
    /// is authoritative: a lost or stale `state/boot` never goes below the
    /// highest boot it records.
    pub fn next_boot(&self, _lock: &WriterLock) -> Result<u64, StateError> {
        let path = self.state_dir().join("boot");
        let stored = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Boot>(&b).ok())
            .map_or(0, |b| b.boot_seq);
        let logged = bogo_log::read(&self.log_path())?
            .0
            .iter()
            .filter_map(|e| match e.event {
                bogo_log::LogEvent::Boot { boot_seq, .. } => Some(boot_seq),
                _ => None,
            })
            .max()
            .unwrap_or(0);
        let next = stored.max(logged) + 1;
        write_atomic(
            &path,
            &serde_json::to_vec(&Boot {
                v: 1,
                boot_seq: next,
            })
            .map_err(|e| StateError::Io(e.to_string()))?,
        )?;
        Ok(next)
    }

    /// Open the log (setting aside a torn tail) and derive the registry: from
    /// the checkpoint caches plus the entries after them, or from the whole
    /// log if the caches are missing, unreadable or disagree with the log.
    pub fn open_log(
        &self,
        _lock: &WriterLock,
    ) -> Result<(Log, Vec<Entry>, Registry, RegistrySource), StateError> {
        let opened = Log::open(&self.log_path())?;
        let entries = opened.entries;
        let (registry, source) = match self.checkpoint(&entries) {
            Ok((mut registry, checkpoint)) => {
                let tail: Vec<&Entry> = entries.iter().filter(|e| e.seq > checkpoint).collect();
                for e in &tail {
                    registry.apply(e);
                }
                (
                    registry,
                    RegistrySource::Checkpoint {
                        checkpoint,
                        replayed: tail.len(),
                    },
                )
            }
            Err(why) => (Registry::replay(&entries), RegistrySource::Rebuilt { why }),
        };
        self.save_registry(&registry, &entries)?;
        Ok((opened.log, entries, registry, source))
    }

    fn checkpoint(&self, entries: &[Entry]) -> Result<(Registry, u64), String> {
        let read = |name: &str| -> Result<Vec<u8>, String> {
            std::fs::read(self.state_dir().join(name)).map_err(|e| format!("{name}: {e}"))
        };
        let approvers: ApproversCache = serde_json::from_slice(&read("approvers.json")?)
            .map_err(|e| format!("approvers.json unreadable: {e}"))?;
        let agents: AgentsCache = serde_json::from_slice(&read("agents.json")?)
            .map_err(|e| format!("agents.json unreadable: {e}"))?;
        if approvers.v != 1 || agents.v != 1 {
            return Err("cache version unknown".into());
        }
        if approvers.log_seq != agents.log_seq || approvers.log_hash != agents.log_hash {
            return Err("caches reflect different log positions".into());
        }
        let seq = approvers.log_seq;
        let expected = if seq == 0 {
            String::new()
        } else {
            entries
                .get(seq as usize - 1)
                .map(|e| hex::encode(e.hash))
                .ok_or("cache is ahead of the log")?
        };
        if expected != approvers.log_hash {
            return Err("cache was written for a different log".into());
        }
        Ok((
            Registry {
                seq,
                approvers: approvers
                    .approvers
                    .into_iter()
                    .map(|a| (a.entry.id.text(), a))
                    .collect(),
                agents: agents.agents.into_iter().map(|a| (a.id.text(), a)).collect(),
            },
            seq,
        ))
    }

    /// Rewrite both caches atomically. Call only after the entries they
    /// reflect are durable; `entries` must include entry `registry.seq`.
    pub fn save_registry(&self, registry: &Registry, entries: &[Entry]) -> Result<(), StateError> {
        let log_hash = if registry.seq == 0 {
            String::new()
        } else {
            entries
                .iter()
                .find(|e| e.seq == registry.seq)
                .map(|e| hex::encode(e.hash))
                .ok_or_else(|| StateError::Io("registry is ahead of the entries given".into()))?
        };
        write_atomic(
            &self.state_dir().join("approvers.json"),
            &json(&ApproversCache {
                v: 1,
                log_seq: registry.seq,
                log_hash: log_hash.clone(),
                approvers: registry.approvers.values().cloned().collect(),
            })?,
        )?;
        write_atomic(
            &self.state_dir().join("agents.json"),
            &json(&AgentsCache {
                v: 1,
                log_seq: registry.seq,
                log_hash,
                agents: registry.agents.values().cloned().collect(),
            })?,
        )
    }
}

fn json<T: Serialize>(value: &T) -> Result<Vec<u8>, StateError> {
    serde_json::to_vec_pretty(value).map_err(|e| StateError::Io(e.to_string()))
}

fn unsafe_path(path: &Path, why: &str) -> StateError {
    StateError::Unsafe {
        path: path.display().to_string(),
        why: why.into(),
    }
}

/// Temp file (0600), sync, rename, sync the directory.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StateError> {
    let dir = path
        .parent()
        .ok_or_else(|| StateError::Io(format!("{} has no parent", path.display())))?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()
    ));
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(io(&tmp))?;
    f.write_all(bytes).and_then(|_| f.sync_all()).map_err(io(&tmp))?;
    std::fs::rename(&tmp, path).map_err(io(path))?;
    File::open(dir).and_then(|d| d.sync_all()).map_err(io(dir))
}
