use super::*;
use a::{ApproverRoute, OwnerPrompt};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Status,
    Tools,
    AgentList,
    AgentAdd {
        name: String,
    },
    AgentRevoke {
        name: String,
    },
    Pause {
        name: String,
    },
    Unpause {
        name: String,
    },
    ApproverList,
    ApproverAdd {
        name: String,
        kind: String,
    },
    ApproverRevoke {
        name: String,
    },
    Requests,
    Cancel {
        id: String,
    },
    Log {
        search: Option<String>,
    },
    Verify,
    Export {
        format: String,
    },
    Stop,
    #[cfg(feature = "test-approvers")]
    Soft {
        name: String,
        id: String,
        deny: bool,
        note: Option<String>,
    },
    #[cfg(feature = "test-approvers")]
    PrepareSoft {
        name: String,
    },
    // Internal messages use the same owner-only transport, with identical checks.
    RevokeApproverId {
        id: String,
        by_self: bool,
    },
    RouteUpdate {
        id: String,
        seq: u64,
        route: Value,
    },
    Outcome {
        id: String,
    },
}
fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
pub fn init(root: &Path) -> Result<()> {
    let home = bogo_state::Home::open(root).map_err(error)?;
    let lock = home.lock().map_err(error)?;
    home.keys(&lock).map_err(error)?;
    for (name, bytes) in [
        ("bogo.toml", TEMPLATE.as_bytes()),
        (
            "secrets.toml",
            b"# Upstream credentials and test approver seeds only.\n".as_slice(),
        ),
    ] {
        let path = root.join(name);
        if !path.exists() {
            bogo_state::write_atomic(&path, bytes).map_err(error)?;
        }
    }
    let plist = plist(root)?;
    bogo_state::write_atomic(&root.join("si.eilmer.bogo.plist"), plist.as_bytes())
        .map_err(error)?;
    println!(
        "Created {}. Set the commented owner values in bogo.toml before starting.\nMCP URL: http://127.0.0.1:8790/mcp\nStdio shim: bogo-shim, with BOGO_URL=http://127.0.0.1:8790/mcp and BOGO_AGENT_TOKEN from `bogo agent add`.\nUser LaunchAgent prepared at {}.",
        root.display(),
        root.join("si.eilmer.bogo.plist").display()
    );
    Ok(())
}
const TEMPLATE: &str = r#"version = 1
[server]
port = 8790
max_body = "1MiB"
[defaults]
policy = "approve"
hide_denied = true
# max_pending = OWNER_SETS_INTEGER
# Add upstreams with `bogo upstream add` or edit this file.
# [relay]
# url = "https://bogo.eilmer.si:PORT"
# max_message_age = "OWNER_SETS_DURATION"
# mailbox_capacity = OWNER_SETS_INTEGER
# [apns]
# key = { secret = "apns_p8" }
# key_id = "OWNER_SETS"
# team_id = "OWNER_SETS"
# topic = "OWNER_SETS"
# [approvers.iphone]
# app_id = "OWNER_SETS"
# app_attest = ["production"]
# approve_arm_delay = "OWNER_SETS_DURATION"
"#;
fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn plist(root: &Path) -> Result<String> {
    let root = normalize(root)?;
    let bin = std::env::current_exe().map_err(error)?;
    let mut environment = format!(
        "<key>PATH</key><string>{}</string>",
        xml(&std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into()))
    );
    for name in ["BOGO_RELAY_CA", "BOGO_MAC_NAME", "BOGO_APP_BUNDLE_VERSIONS"] {
        if let Ok(value) = std::env::var(name) {
            environment.push_str(&format!(
                "<key>{name}</key><string>{}</string>",
                xml(&value)
            ));
        }
    }

    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>si.eilmer.bogo</string>
<key>ProgramArguments</key><array><string>{}</string><string>--home</string><string>{}</string><string>serve</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>{}/run/stdout.log</string>
<key>StandardErrorPath</key><string>{}/run/stderr.log</string>
<key>EnvironmentVariables</key><dict>{}</dict>
</dict></plist>
"#,
        xml(&bin.to_string_lossy()),
        xml(&root.to_string_lossy()),
        xml(&root.to_string_lossy()),
        xml(&root.to_string_lossy()),
        environment
    ))
}
pub fn launch(root: &Path, start: bool) -> Result<()> {
    if !cfg!(target_os = "macos") {
        return Err("start/stop requires macOS launchd".into());
    }
    let domain = format!("gui/{}", nix::unistd::getuid());
    let dest = PathBuf::from(std::env::var_os("HOME").ok_or("HOME not set")?)
        .join("Library/LaunchAgents/si.eilmer.bogo.plist");
    if start {
        load(root)?;
        std::fs::create_dir_all(dest.parent().unwrap()).map_err(error)?;
        bogo_state::write_atomic(&dest, plist(root)?.as_bytes()).map_err(error)?;
        let out = std::process::Command::new("launchctl")
            .args(["bootstrap", &domain])
            .arg(&dest)
            .output()
            .map_err(error)?;
        if !out.status.success() {
            return Err(format!(
                "launchctl bootstrap failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    } else {
        let out = std::process::Command::new("launchctl")
            .args(["bootout", &format!("{domain}/si.eilmer.bogo")])
            .output()
            .map_err(error)?;
        if !out.status.success() {
            return Err(format!(
                "launchctl bootout failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    Ok(())
}
fn normalize(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(error)?.join(path)
    };
    if let Ok(p) = path.canonicalize() {
        return Ok(p);
    }
    let parent = path.parent().ok_or("invalid path")?;
    Ok(normalize(parent)?.join(path.file_name().ok_or("invalid path")?))
}
fn load(root: &Path) -> Result<(Config, bogo_config::Secrets)> {
    let secrets = bogo_config::Secrets::load(
        &root.join("secrets.toml"),
        std::env::var_os("HOME").as_deref().map(Path::new),
    )
    .map_err(error)?;
    let text = std::fs::read_to_string(root.join("bogo.toml")).map_err(error)?;
    let config = Config::parse(&text, &secrets).map_err(error)?;
    if config.server.max_body as usize > bogo_json::Limits::default().max_bytes {
        return Err("server max_body exceeds the strict parser limit (1MiB)".into());
    }
    let protected = normalize(root)?;
    for name in secrets.names() {
        if let bogo_config::SecretValue::Path(p) = secrets.get(name).unwrap().expose()
            && !normalize(p)?.starts_with(&protected)
        {
            return Err(format!("path secret {name} must live inside BOGO home"));
        }
    }
    for u in config.upstreams.values() {
        if let bogo_config::Upstream::Local { command, args, .. } = u {
            for s in std::iter::once(command).chain(args) {
                let s = s.split_once('=').map_or(s.as_str(), |(_, v)| v);
                let expanded = if let Some(tail) = s.strip_prefix("~/") {
                    PathBuf::from(std::env::var_os("HOME").ok_or("HOME not set")?).join(tail)
                } else {
                    PathBuf::from(s)
                };
                if expanded.is_absolute()
                    || s.contains('/')
                    || s.starts_with('.')
                    || expanded.exists()
                {
                    let path = normalize(&expanded)?;
                    if protected.starts_with(&path) || path.starts_with(&protected) {
                        return Err("upstream command/args reaches BOGO home or its parent".into());
                    }
                }
            }
        }
    }
    Ok((config, secrets))
}
fn mutation(registry: &Registry, c: &Command) -> Result<Option<(LogEvent, Value)>> {
    let agent = |name: &str| {
        registry
            .agents
            .values()
            .find(|a| a.name == name && !a.revoked)
            .ok_or("no active agent with that name")
    };
    let result = match c {
        Command::AgentAdd { name } => {
            if name.trim().is_empty() {
                return Err("agent name is empty".into());
            }
            if registry
                .agents
                .values()
                .any(|a| !a.revoked && a.name == *name)
            {
                return Err("agent name already exists; revoke it first".into());
            }
            let token = format!(
                "bogo_agt_{}",
                URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
            );
            (
                LogEvent::AgentAdded {
                    id: Hex::of(&rand::random::<[u8; 32]>()),
                    name: name.clone(),
                    token_sha256: hex::encode(Sha256::digest(token.as_bytes())),
                },
                json!({"token":token,"name":name}),
            )
        }
        Command::AgentRevoke { name } => (
            LogEvent::AgentRevoked {
                id: agent(name)?.id.clone(),
            },
            json!("revoked"),
        ),
        Command::Pause { name } => (
            LogEvent::AgentPaused {
                id: agent(name)?.id.clone(),
                by: "owner".into(),
            },
            json!("paused"),
        ),
        Command::Unpause { name } => (
            LogEvent::AgentUnpaused {
                id: agent(name)?.id.clone(),
            },
            json!("unpaused"),
        ),
        Command::ApproverRevoke { name } => {
            let a = registry
                .approver_named(name)
                .ok_or("no active approver with that name")?;
            (
                LogEvent::ApproverRevoked {
                    id: a.entry.id.clone(),
                    by: bogo_log::RevokedBy::Owner,
                },
                json!("revoked"),
            )
        }
        Command::RevokeApproverId { id, by_self } => {
            let a = registry.approvers.get(id).ok_or("unknown approver")?;
            if !a.active() {
                return Ok(None);
            }
            (
                LogEvent::ApproverRevoked {
                    id: a.entry.id.clone(),
                    by: if *by_self {
                        bogo_log::RevokedBy::Approver
                    } else {
                        bogo_log::RevokedBy::Owner
                    },
                },
                json!("revoked"),
            )
        }
        _ => return Ok(None),
    };
    Ok(Some(result))
}
fn input(e: &LogEvent, seq: u64) -> Option<Input> {
    match e {
        LogEvent::AgentAdded { id, name, .. } => Some(Input::AgentSet {
            seq,
            id: id.0.clone(),
            name: name.clone(),
        }),
        LogEvent::AgentRevoked { id } => Some(Input::AgentRevoked {
            seq,
            id: id.0.clone(),
        }),
        LogEvent::AgentPaused { id, .. } => Some(Input::OwnerPause {
            seq,
            agent: id.0.clone(),
        }),
        LogEvent::AgentUnpaused { id } => Some(Input::AgentUnpaused {
            seq,
            id: id.0.clone(),
        }),
        LogEvent::ApproverRegistered { approver, .. } => Some(Input::ApproverSet {
            seq,
            approver: bogo_core::Approver {
                id: approver.id.0.clone(),
                name: approver.name.clone(),
                alg: approver.alg,
                pk: approver.sig_pk.0.clone(),
            },
        }),
        LogEvent::ApproverRevoked { id, .. } => Some(Input::ApproverRevoked {
            seq,
            id: id.0.clone(),
        }),
        _ => None,
    }
}
fn read_command(root: &Path, c: &Command, core: Option<&Core>) -> Result<Option<Value>> {
    let (entries, torn) = bogo_log::read(&root.join("log/audit.jsonl")).map_err(error)?;
    let registry = Registry::replay(&entries);
    Ok(Some(match c {
        Command::Status => json!({"running":false}),
        Command::AgentList => json!(registry.agents.values().collect::<Vec<_>>()),
        Command::ApproverList => json!(registry.approvers.values().collect::<Vec<_>>()),
        Command::Log { search } => json!(
            entries
                .iter()
                .filter(|e| search.as_ref().is_none_or(|s| e.raw.contains(s)))
                .map(|e| serde_json::from_str::<Value>(&e.raw).unwrap())
                .collect::<Vec<_>>()
        ),
        Command::Export { format } => match format.as_str() {
            "jsonl" => json!(bogo_log::reader::export_jsonl(&entries)),
            "csv" => json!(bogo_log::reader::export_csv(&entries)),
            _ => return Err("format must be jsonl or csv".into()),
        },
        Command::Verify => {
            if torn.is_some() {
                return Err("audit log has an incomplete final line".into());
            }
            let local_core;
            let core = match core {
                Some(core) => core,
                None => {
                    local_core = Core::start(&[0; 32], &[0; 32]).map_err(error)?;
                    &local_core
                }
            };
            let report = bogo_log::verify::verify_with_core(&entries, core).map_err(error)?;
            json!(format!("chain intact; {report:?}"))
        }
        Command::Outcome { id } => {
            json!(bogo_log::outcome::outcome(&entries, &hex::decode(id).map_err(error)?).wire())
        }
        _ => return Ok(None),
    }))
}
pub async fn local(root: &Path, c: Command) -> Result<Value> {
    if let Some(v) = read_command(root, &c, None)? {
        return Ok(v);
    }
    let home = bogo_state::Home::open(root).map_err(error)?;
    let lock = home.lock().map_err(error)?;
    let (log, entries, _, _) = home.open_log(&lock).map_err(error)?;
    let reg = Registry::replay(&entries);
    if let Some((e, v)) = mutation(&reg, &c)? {
        log.append(e).await.map_err(error)?;
        return Ok(v);
    }
    if matches!(c, Command::Tools) {
        let catalog =
            bogo_upstream::Catalog::load(&root.join("state/tools.json")).map_err(error)?;
        return Ok(json!(catalog));
    }
    Err("this command requires the running daemon".into())
}
// A bounded JSON line. Never allocate an unbounded owner-provided frame.
async fn line<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> Result<String> {
    let mut out = Vec::new();
    loop {
        let buf = r.fill_buf().await.map_err(error)?;
        if buf.is_empty() {
            return Err("control connection closed".into());
        }
        let n = buf
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buf.len(), |i| i + 1);
        if out.len() + n > 1 << 20 {
            return Err("control message too large".into());
        }
        out.extend_from_slice(&buf[..n]);
        r.consume(n);
        if out.last() == Some(&b'\n') {
            break;
        }
    }
    String::from_utf8(out).map_err(error)
}
pub async fn request(root: &Path, c: Command) -> Result<Value> {
    let stream = match UnixStream::connect(root.join("run/bogo.sock")).await {
        Ok(s) => s,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return local(root, c).await;
        }
        Err(e) => return Err(error(e)),
    };
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r);
    w.write_all(format!("{}\n", serde_json::to_string(&c).map_err(error)?).as_bytes())
        .await
        .map_err(error)?;
    loop {
        let v: Value = serde_json::from_str(&line(&mut r).await?).map_err(error)?;
        if let Some(s) = v.get("status").and_then(Value::as_str) {
            eprintln!("{s}");
            continue;
        }
        if let Some(code) = v.get("confirm_code").and_then(Value::as_str) {
            eprint!("Does the approver show {code}? [y/N] ");
            std::io::stderr().flush().map_err(error)?;
            let answer = tokio::task::spawn_blocking(|| {
                let mut s = String::new();
                std::io::stdin()
                    .read_line(&mut s)
                    .map(|_| matches!(s.trim(), "y" | "Y" | "yes"))
            })
            .await
            .map_err(error)?
            .map_err(error)?;
            w.write_all(format!("{}\n", json!({"confirmed":answer})).as_bytes())
                .await
                .map_err(error)?;
            continue;
        }
        if let Some(e) = v.get("error").and_then(Value::as_str) {
            return Err(e.into());
        }
        return Ok(v["result"].clone());
    }
}
struct RemotePrompt {
    r: tokio::sync::Mutex<BufReader<tokio::net::unix::OwnedReadHalf>>,
    w: tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>,
}
impl RemotePrompt {
    async fn send(&self, v: Value) -> Result<()> {
        self.w
            .lock()
            .await
            .write_all(format!("{v}\n").as_bytes())
            .await
            .map_err(error)
    }
}
#[async_trait::async_trait]
impl OwnerPrompt for RemotePrompt {
    async fn status(&self, s: &str) {
        let _ = self.send(json!({"status":s})).await;
    }
    async fn confirm_code(&self, code: &str) -> bool {
        if self.send(json!({"confirm_code":code})).await.is_err() {
            return false;
        }
        let mut r = self.r.lock().await;
        tokio::time::timeout(std::time::Duration::from_secs(120), line(&mut *r))
            .await
            .ok()
            .and_then(|r| r.ok())
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .is_some_and(|v| v["confirmed"] == true)
    }
}
impl Shell {
    async fn commit_approver(
        &mut self,
        name: String,
        kind: String,
        new: a::NewApprover,
    ) -> Result<a::Committed> {
        if name.trim().is_empty() {
            return Err("approver name is empty".into());
        }
        if self.registry.approvers.values().any(|a| {
            a.entry.id.0 == new.id || a.entry.tx_id.0 == new.tx_id || a.entry.sig_pk.0 == new.sig_pk
        }) {
            return Err("duplicate approver ID, transaction, or approval key".into());
        }
        let replaced = self
            .registry
            .approver_named(&name)
            .map(|a| a.entry.id.clone());
        let event = LogEvent::ApproverRegistered {
            approver: bogo_log::ApproverEntry {
                id: Hex::of(&new.id),
                name,
                kind,
                alg: new.alg,
                sig_pk: Hex(new.sig_pk),
                tx_id: Hex::of(&new.tx_id),
                route: new.route,
                attest: new.attest,
            },
            replaces: replaced.clone(),
        };
        let seq = self.append(vec![event.clone()]).await?[0];
        if let Some(id) = &replaced {
            self.step(Input::ApproverRevoked {
                seq,
                id: id.0.clone(),
            })
            .await?;
        }
        self.step(input(&event, seq).ok_or("bad registration")?)
            .await?;
        Ok(a::Committed {
            record: record(
                self.registry
                    .approver(&new.id)
                    .ok_or("registration not replayed")?,
            )
            .ok_or("bad record")?,
            replaced: replaced.and_then(|b| b.0.try_into().ok()),
        })
    }
    async fn control(&mut self, c: Command) -> Result<Value> {
        if !matches!(c, Command::Status)
            && let Some(v) = read_command(self.home.root(), &c, Some(&self.core))?
        {
            return Ok(v);
        }
        if let Some((e, v)) = mutation(&self.registry, &c)? {
            let seq = self.append(vec![e.clone()]).await?[0];
            if let Some(i) = input(&e, seq) {
                self.step(i).await?;
            }
            if let LogEvent::ApproverRevoked { id, .. } = e {
                let hub = self.hub.clone();
                let id = id.0.try_into().map_err(|_| "bad id")?;
                tokio::spawn(async move {
                    hub.revoked(&id).await;
                });
            }
            self.catalog().await?;
            return Ok(v);
        }
        match c {
            Command::Status => Ok(json!({
                "running": true, "boot_seq": self.boot.boot_seq,
                "agents": self.registry.agents.len(),
                "approvers": self.registry.active_approvers().count(),
                "requests": self.requests.len(), "upstreams": self.manager.health().await
            })),
            Command::Tools => Ok(self.tool_report().await),
            Command::Requests => Ok(json!(
                self.requests
                    .iter()
                    .map(|(id, (bytes, to))| {
                        json!({"id":hex::encode(id), "request":hex::encode(bytes),
                    "to":to.iter().map(hex::encode).collect::<Vec<_>>(),
                    "counted":self.counted.get(id).map_or(0,Vec::len)})
                    })
                    .collect::<Vec<_>>()
            )),
            Command::Cancel { id } => {
                let req = hex::decode(id).map_err(error)?;
                if !self.requests.contains_key(&req) {
                    return Err("no live request with that ID".into());
                }
                self.step(Input::OwnerCancel { req }).await?;
                Ok(json!("cancelled"))
            }
            Command::RouteUpdate { id, seq, route } => {
                let Some(a) = self.registry.approvers.get(&id) else {
                    return Ok(json!(false));
                };
                if !a.active() || seq <= a.route_seq {
                    return Ok(json!(false));
                }
                self.append(vec![LogEvent::RouteUpdated {
                    id: a.entry.id.clone(),
                    route_seq: seq,
                    route,
                }])
                .await?;
                Ok(json!(true))
            }
            Command::RevokeApproverId { .. } => Ok(json!("already revoked")),
            #[cfg(feature = "test-approvers")]
            Command::PrepareSoft { name } => {
                let seed = rand::random::<[u8; 32]>();
                let path = self.home.root().join("secrets.toml");
                let text = std::fs::read_to_string(&path).map_err(error)?;
                let key = format!("soft_{}", hex::encode(Sha256::digest(name.as_bytes())));
                let mut table: toml::Table = text.parse().map_err(|_| "invalid secrets file")?;
                table.insert(key, toml::Value::String(hex::encode(seed)));
                let text = toml::to_string(&table).map_err(|_| "cannot serialize secrets")?;
                bogo_state::write_atomic(&path, text.as_bytes()).map_err(error)?;
                self.soft.install(name, seed);
                Ok(json!(true))
            }
            #[cfg(feature = "test-approvers")]
            Command::Soft {
                name,
                id,
                deny,
                note,
            } => {
                let a = self
                    .registry
                    .approver_named(&name)
                    .filter(|a| a.entry.kind == "soft")
                    .ok_or("no active soft approver with that name")?;
                let approver = a.entry.id.0.clone();
                let req = hex::decode(id).map_err(error)?;
                let bytes = &self
                    .requests
                    .get(&req)
                    .ok_or("no live request with that ID")?
                    .0;
                let input = if deny {
                    Input::Denial {
                        approver,
                        req,
                        note,
                    }
                } else {
                    Input::Approval {
                        approver,
                        req,
                        alg: 0xff00,
                        proof: self.soft.sign(&name, bytes)?,
                        now_ms: self.handle.clock.now(),
                    }
                };
                self.step(input).await?;
                Ok(json!("decision recorded"))
            }
            Command::Stop => Err("use `bogo stop` to unload the KeepAlive LaunchAgent".into()),
            _ => Err("unsupported owner command".into()),
        }
    }
    async fn tool_report(&self) -> Value {
        let catalog = self.manager.catalog().await;
        let tools: Vec<Value> = catalog
            .tools
            .iter()
            .map(|(name, t)| {
                let overrides: Value = self
                    .config
                    .agents
                    .iter()
                    .filter_map(|(agent, ts)| {
                        ts.get(name).map(|_| {
                            (
                                agent.clone(),
                                json!(format!(
                                    "{:?}",
                                    policy::effective(&self.config, agent, name)
                                )),
                            )
                        })
                    })
                    .collect();
                let policy = self.config.tools.get(name);
                let eligible = self
                    .registry
                    .active_approvers()
                    .filter(|a| {
                        policy.is_none_or(|t| {
                            t.approvers.is_empty() || t.approvers.contains(&a.entry.name)
                        })
                    })
                    .count();
                let k = policy.map_or(1, |t| match t.requirement {
                    bogo_config::Requirement::AnyOf => 1,
                    bogo_config::Requirement::KOfN(k) => k,
                });
                json!({"name":name,"policy":format!("{:?}",policy::effective(&self.config,"",name)),
                "overrides":overrides,"strict_client_risk":t.strict_client_risk,
                "justification_key":t.justification,"eligible_approvers":eligible,"require":k,
                "no_eligible_approver":eligible<(k as usize),"first_seen":t.first_seen})
            })
            .collect();
        json!({"tools":tools,"unexposable":catalog.unexposable})
    }
    async fn decision(&mut self, d: a::Decision) -> Result<()> {
        let input = match d {
            a::Decision::Approval {
                approver,
                req,
                alg,
                proof,
            } => Input::Approval {
                approver: approver.to_vec(),
                req: req.to_vec(),
                alg,
                proof,
                now_ms: self.handle.clock.now(),
            },
            a::Decision::Denial {
                approver,
                req,
                note,
            } => Input::Denial {
                approver: approver.to_vec(),
                req: req.to_vec(),
                note,
            },
            a::Decision::Pause {
                approver,
                agent,
                epoch,
            } => Input::PauseAgent {
                approver: approver.to_vec(),
                agent,
                epoch,
            },
        };
        self.step(input).await?;
        Ok(())
    }
}
async fn connection(stream: UnixStream, handle: Handle, hub: Arc<a::Hub>) -> Result<()> {
    let uid = stream.peer_cred().map_err(error)?.uid();
    if uid != nix::unistd::getuid().as_raw() {
        return Err("control peer UID differs from owner".into());
    }
    let (r, w) = stream.into_split();
    let remote = RemotePrompt {
        r: tokio::sync::Mutex::new(BufReader::new(r)),
        w: tokio::sync::Mutex::new(w),
    };
    let c: Command = {
        let mut r = remote.r.lock().await;
        serde_json::from_str(&line(&mut *r).await?).map_err(|_| "invalid control command")?
    };
    let result = if let Command::ApproverAdd { name, kind } = c {
        #[cfg(feature = "test-approvers")]
        if kind == "soft" {
            handle
                .control(Command::PrepareSoft { name: name.clone() })
                .await?;
        }
        hub.register(&kind, &name, &remote)
            .await
            .map(|a| json!({"name":a.name,"id":hex::encode(a.id),"kind":a.kind}))
            .map_err(error)
    } else {
        handle.control(c).await
    };
    remote
        .send(match result {
            Ok(v) => json!({"result":v}),
            Err(e) => json!({"error":e}),
        })
        .await
}

pub async fn serve(root: &Path) -> Result<()> {
    let home = bogo_state::Home::open(root).map_err(error)?;
    let lock = home.lock().map_err(error)?;
    let (config, secrets) = load(root)?;
    let keys = home.keys(&lock).map_err(error)?;
    let (log, entries, _, _) = home.open_log(&lock).map_err(error)?;
    let registry = Registry::replay(&entries);
    let core = Core::start(&keys.bogo_id, &rand::random::<[u8; 32]>()).map_err(error)?;
    bogo_log::verify::verify_with_core(&entries, &core).map_err(error)?;
    let boot = a::BootNotice {
        boot_seq: home.next_boot(&lock).map_err(error)?,
        boot_id: rand::random(),
    };
    core.restart(&keys.bogo_id, &boot.boot_id).map_err(error)?;
    log.append(LogEvent::Boot {
        boot_seq: boot.boot_seq,
        boot_id: Hex::of(&boot.boot_id),
    })
    .await
    .map_err(error)?;
    // Replay owner inputs in historical order, preserving pause epochs and revoked keys.
    for e in &entries {
        if let LogEvent::ApproverRegistered {
            replaces: Some(id), ..
        } = &e.event
        {
            core.step(&Input::ApproverRevoked {
                seq: e.seq,
                id: id.0.clone(),
            })
            .map_err(error)?;
        }
        if let Some(i) = input(&e.event, e.seq) {
            core.step(&i).map_err(error)?;
        } else if let LogEvent::AgentPaused { id, .. } = &e.event {
            core.step(&Input::OwnerPause {
                seq: e.seq,
                agent: id.0.clone(),
            })
            .map_err(error)?;
        }
    }
    let (tx, mut rx) = mpsc::unbounded_channel();
    let handle = Handle {
        tx,
        snapshot: Arc::new(RwLock::new(Snapshot {
            registry: registry.clone(),
            ..Default::default()
        })),
        clock: Arc::new(clock::Clock::default()),
    };
    let mut routes: Vec<Arc<dyn ApproverRoute>> = vec![];
    #[cfg(feature = "test-approvers")]
    let soft = {
        let soft = Arc::new(bogo_approver_soft::SoftRoute::default());
        for a in registry
            .approvers
            .values()
            .filter(|a| a.entry.kind == "soft" && a.active())
        {
            let name = format!(
                "soft_{}",
                hex::encode(Sha256::digest(a.entry.name.as_bytes()))
            );
            if let Some(s) = secrets.get(&name)
                && let bogo_config::SecretValue::Value(v) = s.expose()
            {
                let seed: [u8; 32] = hex::decode(v)
                    .map_err(|_| "bad soft key")?
                    .try_into()
                    .map_err(|_| "bad soft key")?;
                soft.install(a.entry.name.clone(), seed);
            }
        }
        routes.push(soft.clone());
        soft
    };
    if let Some(iphone) = &config.iphone {
        let relay = config.relay.as_ref().ok_or("iPhone requires relay")?;
        let relay_url = url::Url::parse(&relay.url).map_err(|_| "invalid relay URL")?;
        let apns = config
            .apns
            .as_ref()
            .map(|a| match a.key.expose() {
                bogo_config::SecretValue::Path(path) => Ok(bogo_approver_iphone::ApnsConfig {
                    key_path: path.clone(),
                    key_id: a.key_id.clone(),
                    team_id: a.team_id.clone(),
                    topic: a.topic.clone(),
                }),
                _ => Err("APNs key must be a path secret"),
            })
            .transpose()?;
        let bundle_versions = std::env::var("BOGO_APP_BUNDLE_VERSIONS").map_err(
            |_| "set BOGO_APP_BUNDLE_VERSIONS to the accepted App Attest bundle versions",
        )?;
        let route = bogo_approver_iphone::IphoneRoute::new(
            bogo_approver_iphone::Config {
                relay_url: relay.url.clone(),
                relay_service: relay_url[url::Position::BeforeHost..url::Position::AfterPort]
                    .into(),
                relay_root_pem: std::env::var_os("BOGO_RELAY_CA")
                    .map(std::fs::read)
                    .transpose()
                    .map_err(error)?,
                mac_name: std::env::var("BOGO_MAC_NAME").unwrap_or_else(|_| "BOGO Mac".into()),
                app_id: iphone.app_id.clone(),
                environments: iphone
                    .app_attest
                    .iter()
                    .map(|e| match e {
                        bogo_config::AttestEnvironment::Production => {
                            bogo_attest::Environment::Production
                        }
                        bogo_config::AttestEnvironment::Development => {
                            bogo_attest::Environment::Development
                        }
                    })
                    .collect(),
                bundle_versions: bundle_versions.split(',').map(str::to_owned).collect(),
                apns,
            },
            bogo_approver_iphone::MacKeys {
                e2e: keys.e2e,
                e2e_public: keys.e2e_public,
                relay: keys.relay,
                bogo_id: keys.bogo_id,
            },
        )?;
        routes.push(route);
    }
    let hub = a::Hub::new(routes, Arc::new(handle.clone()));
    let previous = bogo_upstream::Catalog::load(&root.join("state/tools.json")).unwrap_or_default();
    let manager = Arc::new(
        bogo_upstream::Manager::start(config.clone(), &secrets, Arc::new(handle.clone()), previous)
            .await,
    );
    let mut changes = manager.subscribe();
    let port = config.server.port;
    let max_body = config.server.max_body as usize;
    let mut shell = Shell {
        core,
        log,
        registry,
        config,
        calls: HashMap::new(),
        sessions: HashMap::new(),
        requests: HashMap::new(),
        counted: HashMap::new(),
        manager,
        hub: hub.clone(),
        handle: handle.clone(),
        home,
        _lock: lock,
        boot,
        deadline: None,
        #[cfg(feature = "test-approvers")]
        soft,
    };
    shell.catalog().await?;
    // Start the actor before hub.start, which can receive inbound decisions immediately.
    let records: Vec<_> = shell
        .registry
        .approvers
        .values()
        .filter_map(record)
        .collect();
    let startup_hub = hub.clone();
    let actor_handle = handle.clone();
    let actor = tokio::spawn(async move {
        loop {
            let delay = shell
                .deadline
                .map(|d| {
                    std::time::Duration::from_millis(d.saturating_sub(shell.handle.clock.now()))
                })
                .unwrap_or(std::time::Duration::from_secs(86400));
            let job = tokio::select! {biased;job=rx.recv()=>{let Some(job)=job else{break Ok(())};job},_=tokio::time::sleep(delay)=>Job::Event(Input::Tick{now_ms:shell.handle.clock.now()})};
            let result: Result<()> = async {
                match job {
                    Job::Event(i) => {
                        shell.step(i).await?;
                    }
                    Job::Invoke(i, tx) => {
                        let Input::Call {
                            call,
                            session,
                            name,
                            args,
                            ..
                        } = &i
                        else {
                            return Err("non-call invocation".into());
                        };
                        shell
                            .append(vec![LogEvent::Call {
                                call: Hex(call.clone()),
                                session: Hex(session.clone()),
                                tool: name.clone(),
                                arguments: args.as_ref().map(bogo_json::JVal::write),
                            }])
                            .await?;
                        shell.calls.insert(
                            call.clone(),
                            Call {
                                name: name.clone(),
                                req: None,
                                waiters: vec![tx],
                                staged: false,
                            },
                        );
                        shell.step(i).await?;
                    }
                    Job::Dispatch(call, tx) => {
                        let outputs = shell
                            .step(Input::Dispatch {
                                call,
                                now_ms: shell.handle.clock.now(),
                            })
                            .await?;
                        let forward = outputs.into_iter().find_map(|o| {
                            if let Output::Forward {
                                upstream,
                                tool,
                                args,
                                ..
                            } = o
                            {
                                Some(bogo_upstream::Forward {
                                    upstream,
                                    tool,
                                    arguments: args,
                                })
                            } else {
                                None
                            }
                        });
                        let _ = tx.send(forward.ok_or(bogo_upstream::Error::Rejected));
                    }
                    Job::Finished(c, r) => shell.finished(c, r).await?,
                    Job::Decision(d, tx) => {
                        let result = shell.decision(d).await;
                        let failed = result.is_err();
                        let _ = tx.send(result);
                        if failed {
                            return Err("decision durability failed".into());
                        }
                    }
                    Job::Commit(n, k, a, tx) => {
                        let _ = tx.send(shell.commit_approver(n, k, a).await);
                    }
                    Job::Control(c, tx) => {
                        let _ = tx.send(shell.control(c).await);
                    }
                    Job::Catalog => shell.catalog().await?,
                }
                Ok(())
            }
            .await;
            if let Err(e) = result {
                actor_handle.snapshot.write().unwrap().failed = true;
                break Err(e);
            }
            if actor_handle.snapshot.read().unwrap().failed {
                break Err("audit writer failed".into());
            }
        }
    });
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(error)?;
    let socket = root.join("run/bogo.sock");
    if socket.exists() {
        std::fs::remove_file(&socket).map_err(error)?;
    }
    let control = UnixListener::bind(&socket).map_err(error)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).map_err(error)?;
    let front = bogo_front::Front::new(Arc::new(handle.clone()), boot.boot_id.to_vec());
    let h = handle.clone();
    let control_task = tokio::spawn(async move {
        loop {
            let (stream, _) = control.accept().await.map_err(error)?;
            let (h, hub) = (h.clone(), hub.clone());
            tokio::spawn(async move {
                let _ = connection(stream, h, hub).await;
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), String>(())
    });
    let h = handle.clone();
    let catalog_task = tokio::spawn(async move {
        while changes.changed().await.is_ok() {
            if h.tx.send(Job::Catalog).is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        startup_hub.start(records, boot).await;
    });
    let shutdown = front.clone();
    let mut actor = actor;
    let server = axum::serve(
        listener,
        front
            .router()
            .layer(tower_http::limit::RequestBodyLimitLayer::new(max_body)),
    )
    .with_graceful_shutdown(async move {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
        shutdown.shutdown();
    });
    tokio::select! {r=server=>r.map_err(error)?,r=&mut actor=>{front.shutdown();return Err(r.map_err(error)?.err().unwrap_or("effects shell stopped".into()))}}
    control_task.abort();
    catalog_task.abort();
    // Barrier: all sessionClosed events from Front::shutdown precede this status.
    let _ = handle.control(Command::Status).await;
    actor.abort();
    let _ = std::fs::remove_file(socket);
    Ok(())
}
pub fn add_upstream(
    root: &Path,
    name: &str,
    url: Option<String>,
    command: Vec<String>,
) -> Result<()> {
    let home = bogo_state::Home::open(root).map_err(error)?;
    let _lock = home.lock().map_err(error)?;
    let path = root.join("bogo.toml");
    let text = std::fs::read_to_string(&path).map_err(error)?;
    let mut doc: toml::Table = text.parse().map_err(|_| "invalid config")?;
    let mut u = toml::Table::new();
    match (url, command.split_first()) {
        (Some(url), None) => {
            u.insert("url".into(), toml::Value::String(url));
        }
        (None, Some((exe, args))) => {
            u.insert("command".into(), toml::Value::String(exe.clone()));
            u.insert(
                "args".into(),
                toml::Value::Array(args.iter().cloned().map(toml::Value::String).collect()),
            );
        }
        _ => return Err("provide either --url or command and arguments after --".into()),
    }
    let upstreams = doc
        .entry("upstreams")
        .or_insert(toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or("invalid upstreams")?;
    if upstreams.contains_key(name) {
        return Err("upstream name already exists".into());
    }
    upstreams.insert(name.into(), toml::Value::Table(u));
    let text = toml::to_string_pretty(&doc).map_err(error)?;
    let secrets = bogo_config::Secrets::load(&root.join("secrets.toml"), None).map_err(error)?;
    Config::parse(&text, &secrets).map_err(error)?;
    bogo_state::write_atomic(&path, text.as_bytes()).map_err(error)?;
    println!("Added upstream {name}; start BOGO to discover its tools.");
    Ok(())
}
