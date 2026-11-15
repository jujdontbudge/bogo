//! `bogo-standin`: BOGO's Mac side without the daemon (ARCHITECTURE §8 step 5).
//!
//! It registers a phone over the real relay, sends requests built from the
//! Lean vectors, verifies every decision with `bogo-verify` against the exact
//! request bytes, records everything in the hash-chained log, and sends
//! `settled`, `ended`, `boot` and `outcome` on command. It stands in for the
//! core with the same acceptance rules for decisions, so a replayed, late or
//! reordered message never applies twice.
use bogo_standin::request;

use async_trait::async_trait;
use bogo_approver::*;
use bogo_approver_iphone::{ApnsConfig, Config, IphoneRoute, MacKeys};
use bogo_log::{ApproverEntry, Hex, Log, LogEvent, Registry, RevokedBy};
use bogo_state::{Home, WriterLock};
use clap::Parser;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader, Lines, Stdin},
    sync::Mutex,
};

const APPROVAL_DOMAIN: &[u8] = b"BOGO-APPROVAL\x00v1";

#[derive(Parser)]
#[command(about = "BOGO stand-in Mac: registration, requests from the Lean vectors, verified decisions")]
struct Args {
    /// BOGO's state directory.
    #[arg(long)]
    home: Option<PathBuf>,
    /// The relay base URL, e.g. https://bogo.eilmer.si:8443/
    #[arg(long)]
    relay: String,
    /// The relay's service identity (normally host:port).
    #[arg(long)]
    relay_service: String,
    /// An extra trusted root certificate (PEM) for a private or local relay.
    #[arg(long)]
    relay_ca: Option<PathBuf>,
    /// The name the phone shows for this Mac.
    #[arg(long, default_value = "BOGO stand-in")]
    mac_name: String,
    /// Lean vectors directory (requests.json).
    #[arg(long)]
    vectors: Option<PathBuf>,
    #[arg(long, default_value_t = 2000)]
    arm_delay_ms: u64,
    /// Keep the vector's own bogoId in requests (to drive the app's built-in
    /// stand-in identity); by default requests carry this Mac's bogoId.
    #[arg(long)]
    keep_vector_bogo_id: bool,
    #[arg(long, default_value = "AX3C2B78YD.com.johansardar.applebridge.ios")]
    app_id: String,
    /// Accepted App Attest environments: production, development.
    #[arg(long, value_delimiter = ',', default_value = "production")]
    app_attest: Vec<String>,
    /// Accepted CFBundleVersion values for App Attest.
    #[arg(long)]
    bundle_version: Vec<String>,
    /// The owner's APNs .p8 (read at run time only).
    #[arg(long)]
    apns_key: Option<PathBuf>,
    #[arg(long, default_value = "L2854KRF5Z")]
    apns_key_id: String,
    #[arg(long, default_value = "AX3C2B78YD")]
    apns_team: String,
    #[arg(long, default_value = "com.johansardar.applebridge.ios")]
    apns_topic: String,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

fn short(b: &[u8]) -> String {
    bogo_standin::rid(b)
}

#[derive(Clone, Debug, PartialEq)]
enum State {
    Pending,
    Settled,
    Ended(String),
}

struct Req {
    id: ReqId,
    vector: String,
    bytes: Vec<u8>,
    to: Vec<ApproverId>,
    k: usize,
    agent: Vec<u8>,
    state: State,
    counted: BTreeSet<ApproverId>,
}

/// The stand-in's decision state and its log. Every method appends its
/// entries and waits until they are durable before it changes anything a
/// caller can observe.
struct Mac {
    home: Home,
    _lock: WriterLock,
    log: Log,
    registry: Registry,
    boot_seq: u64,
    boot_id: [u8; 32],
    seq: u64,
    reqs: Vec<Req>,
    epochs: HashMap<Vec<u8>, u64>,
}

impl Mac {
    async fn append(&mut self, events: Vec<LogEvent>) -> Result<Vec<u64>, SinkError> {
        let seqs = self.log.append_all(events).await.map_err(|e| SinkError(e.to_string()))?;
        let entries = self.log.entries().map_err(|e| SinkError(e.to_string()))?;
        for e in &entries {
            self.registry.apply(e);
        }
        self.home
            .save_registry(&self.registry, &entries)
            .map_err(|e| SinkError(e.to_string()))?;
        Ok(seqs)
    }

    fn req_mut(&mut self, id: &ReqId) -> Option<&mut Req> {
        self.reqs.iter_mut().find(|r| &r.id == id)
    }

    fn active(&self, id: &ApproverId) -> Option<&bogo_log::ApproverState> {
        self.registry.approver(id).filter(|a| a.active())
    }

    fn name(&self, id: &[u8]) -> String {
        self.registry
            .approver(id)
            .map_or_else(|| short(id), |a| a.entry.name.clone())
    }

    fn epoch(&self, agent: &[u8]) -> u64 {
        self.epochs.get(agent).copied().unwrap_or(1)
    }

    async fn approval(&mut self, approver: ApproverId, req: ReqId, alg: u16, proof: Vec<u8>) -> Result<Vec<Effect>, SinkError> {
        let who = self.name(&approver);
        let ignored = |why: &str| LogEvent::Approval {
            req: Hex::of(&req),
            approver: Hex::of(&approver),
            alg,
            proof: Hex(proof.clone()),
            counted: false,
            why: Some(why.into()),
        };
        if self.active(&approver).is_none() {
            self.append(vec![ignored("revoked")]).await?;
            println!("✗ approval from {who} for {} REJECTED: that approver is revoked", short(&req));
            return Ok(vec![]);
        }
        let Some(r) = self.reqs.iter().find(|r| r.id == req) else {
            self.append(vec![ignored("unknown")]).await?;
            println!("✗ approval from {who} for {} ignored: no such request in this boot", short(&req));
            return Ok(vec![]);
        };
        let (bytes, to, k, vector) = (r.bytes.clone(), r.to.clone(), r.k, r.vector.clone());
        let why = match &r.state {
            State::Settled => Some("settled"),
            State::Ended(_) => Some("ended"),
            State::Pending if self.active(&approver).is_none() => Some("revoked"),
            State::Pending if !to.contains(&approver) => Some("not_eligible"),
            State::Pending if r.counted.contains(&approver) => Some("duplicate"),
            State::Pending => None,
        };
        if let Some(why) = why {
            self.append(vec![ignored(why)]).await?;
            println!("✗ approval from {who} for #{vector} ignored ({why})");
            return Ok(vec![]);
        }
        let pk = self.active(&approver).map(|a| (a.entry.alg, a.entry.sig_pk.0.clone()));
        let valid = pk.is_some_and(|(a, pk)| {
            a == alg && bogo_verify::verify(alg, &pk, &[APPROVAL_DOMAIN, &bytes].concat(), &proof)
        });
        if !valid {
            self.append(vec![ignored("bad_signature")]).await?;
            println!("✗ approval from {who} for #{vector} REJECTED: signature does not verify over the request bytes");
            return Ok(vec![]);
        }
        let r = self.req_mut(&req).expect("found above");
        r.counted.insert(approver);
        let settles = r.counted.len() >= k;
        let mut events = vec![LogEvent::Approval {
            req: Hex::of(&req),
            approver: Hex::of(&approver),
            alg,
            proof: Hex(proof),
            counted: true,
            why: None,
        }];
        if settles {
            let approvers = r.counted.iter().map(|a| Hex::of(a)).collect();
            events.push(LogEvent::RequestSettled { req: Hex::of(&req), approvers });
            events.push(LogEvent::Authorized { req: Hex::of(&req) });
        }
        let seqs = self.append(events).await?;
        println!(
            "✔ APPROVED #{vector} by {who}: P-256 signature verified over the exact request bytes (sha256 {}), log seq {}",
            hex::encode(Sha256::digest(&bytes)),
            seqs[0]
        );
        if !settles {
            return Ok(vec![]);
        }
        self.req_mut(&req).expect("found above").state = State::Settled;
        println!("  request #{vector} settled; telling its approvers");
        Ok(vec![Effect::Settled { req, to }])
    }

    async fn denial(&mut self, approver: ApproverId, req: ReqId, note: Option<String>) -> Result<Vec<Effect>, SinkError> {
        let who = self.name(&approver);
        let found = self.reqs.iter().find(|r| r.id == req).map(|r| (r.state.clone(), r.to.clone(), r.vector.clone()));
        let why = match &found {
            _ if self.active(&approver).is_none() => Some("revoked"),
            None => Some("unknown"),
            Some((State::Settled, ..)) => Some("settled"),
            Some((State::Ended(_), ..)) => Some("ended"),
            Some(_) if self.active(&approver).is_none() => Some("revoked"),
            Some((_, to, _)) if !to.contains(&approver) => Some("not_eligible"),
            Some(_) => None,
        };
        let entry = LogEvent::Denial {
            req: Hex::of(&req),
            approver: Hex::of(&approver),
            note: note.clone(),
            applied: why.is_none(),
            why: why.map(Into::into),
        };
        if let Some(why) = why {
            self.append(vec![entry]).await?;
            println!("✗ denial from {who} for {} ignored ({why})", short(&req));
            return Ok(vec![]);
        }
        let (_, to, vector) = found.expect("checked");
        let seqs = self
            .append(vec![entry, LogEvent::RequestEnded { req: Hex::of(&req), why: "denied".into() }])
            .await?;
        self.req_mut(&req).expect("found").state = State::Ended("denied".into());
        println!(
            "✔ DENIED #{vector} by {who}{}; log seq {}",
            note.map(|n| format!(" with note {n:?}")).unwrap_or_default(),
            seqs[0]
        );
        Ok(vec![Effect::Outcome { req, outcome: "denied".into(), to }])
    }

    async fn pause(&mut self, approver: ApproverId, agent: Vec<u8>, epoch: u64) -> Result<Vec<Effect>, SinkError> {
        let who = self.name(&approver);
        if self.active(&approver).is_none() || epoch != self.epoch(&agent) {
            let why = if self.active(&approver).is_none() { "revoked" } else { "stale_epoch" };
            self.append(vec![LogEvent::Ignored {
                what: "pause".into(),
                approver: Some(Hex::of(&approver)),
                req: None,
                why: why.into(),
            }])
            .await?;
            println!("✗ pause from {who} ignored ({why})");
            return Ok(vec![]);
        }
        let live: Vec<(ReqId, Vec<ApproverId>)> = self
            .reqs
            .iter()
            .filter(|r| r.agent == agent && matches!(r.state, State::Pending | State::Settled))
            .map(|r| (r.id, r.to.clone()))
            .collect();
        let mut events = vec![LogEvent::AgentPaused { id: Hex(agent.clone()), by: hex::encode(approver) }];
        events.extend(live.iter().map(|(id, _)| LogEvent::RequestEnded { req: Hex::of(id), why: "agentPaused".into() }));
        self.append(events).await?;
        for (id, _) in &live {
            self.req_mut(id).expect("live").state = State::Ended("agentPaused".into());
        }
        println!("✔ agent {} paused by {who}; {} live request(s) ended", short(&agent), live.len());
        Ok(live
            .into_iter()
            .map(|(req, to)| Effect::Ended { req, why: EndWhy::AgentPaused, to })
            .collect())
    }

    /// End every live request that can no longer reach its threshold.
    fn unreachable(&self) -> Vec<(ReqId, Vec<ApproverId>)> {
        self.reqs
            .iter()
            .filter(|r| r.state == State::Pending)
            .filter(|r| r.to.iter().filter(|a| self.active(a).is_some()).count() < r.k)
            .map(|r| (r.id, r.to.clone()))
            .collect()
    }

    async fn revoke(&mut self, id: ApproverId, by: RevokedBy) -> Result<Vec<Effect>, SinkError> {
        if self.active(&id).is_none() {
            return Ok(vec![]);
        }
        self.append(vec![LogEvent::ApproverRevoked { id: Hex::of(&id), by }]).await?;
        let dead = self.unreachable();
        if !dead.is_empty() {
            self.append(
                dead.iter()
                    .map(|(r, _)| LogEvent::RequestEnded { req: Hex::of(r), why: "approverRevoked".into() })
                    .collect(),
            )
            .await?;
        }
        for (r, _) in &dead {
            self.req_mut(r).expect("live").state = State::Ended("approverRevoked".into());
        }
        Ok(dead
            .into_iter()
            .map(|(req, to)| Effect::Ended { req, why: EndWhy::ApproverRevoked, to })
            .collect())
    }
}

fn record(a: &bogo_log::ApproverState) -> Option<ApproverRecord> {
    Some(ApproverRecord {
        id: a.entry.id.0.as_slice().try_into().ok()?,
        name: a.entry.name.clone(),
        kind: a.entry.kind.clone(),
        alg: a.entry.alg,
        sig_pk: a.entry.sig_pk.0.clone(),
        tx_id: a.entry.tx_id.0.as_slice().try_into().ok()?,
        route: a.entry.route.clone(),
        active: a.active(),
    })
}

struct Standin(Arc<Mutex<Mac>>);

#[async_trait]
impl Sink for Standin {
    async fn decision(&self, d: Decision) -> Result<Vec<Effect>, SinkError> {
        let mut mac = self.0.lock().await;
        match d {
            Decision::Approval { approver, req, alg, proof } => mac.approval(approver, req, alg, proof).await,
            Decision::Denial { approver, req, note } => mac.denial(approver, req, note).await,
            Decision::Pause { approver, agent, epoch } => mac.pause(approver, agent, epoch).await,
        }
    }

    async fn removed(&self, approver: ApproverId) -> Result<Vec<Effect>, SinkError> {
        let mut mac = self.0.lock().await;
        let was_active = mac.active(&approver).is_some();
        let effects = mac.revoke(approver, RevokedBy::Approver).await?;
        let name = mac.name(&approver);
        if was_active {
            println!("✔ {name} removed this Mac on the phone: approver revoked (by self), recorded in the log");
        } else {
            println!("  {name} sent `removed` again; it is already revoked, acknowledging again");
        }
        Ok(effects)
    }

    async fn route_update(&self, approver: ApproverId, seq: u64, route: serde_json::Value) -> Result<bool, SinkError> {
        let mut mac = self.0.lock().await;
        let newer = mac.registry.approver(&approver).is_some_and(|a| seq > a.route_seq);
        if newer {
            mac.append(vec![LogEvent::RouteUpdated { id: Hex::of(&approver), route_seq: seq, route }])
                .await?;
            println!("  push token updated for {}", mac.name(&approver));
        }
        Ok(newer)
    }

    async fn outcome(&self, req: &ReqId) -> String {
        let mac = self.0.lock().await;
        let entries = mac.log.entries().unwrap_or_default();
        let o = bogo_log::outcome::outcome(&entries, req);
        println!("  sync: outcome of {} is {}", short(req), o.wire());
        o.wire().into()
    }

    async fn commit(&self, name: &str, kind: &str, new: &NewApprover) -> Result<Committed, SinkError> {
        let mut mac = self.0.lock().await;
        let replaced: Option<ApproverId> = mac
            .registry
            .approver_named(name)
            .and_then(|a| a.entry.id.0.as_slice().try_into().ok());
        let seqs = mac
            .append(vec![LogEvent::ApproverRegistered {
                approver: ApproverEntry {
                    id: Hex::of(&new.id),
                    name: name.into(),
                    kind: kind.into(),
                    alg: new.alg,
                    sig_pk: Hex(new.sig_pk.clone()),
                    tx_id: Hex::of(&new.tx_id),
                    route: new.route.clone(),
                    attest: new.attest.clone(),
                },
                replaces: replaced.map(|r| Hex::of(&r)),
            }])
            .await?;
        let state = mac.registry.approver(&new.id).ok_or_else(|| SinkError("not in registry".into()))?;
        println!("✔ approver_registered is durable (log seq {})", seqs[0]);
        Ok(Committed { record: record(state).ok_or_else(|| SinkError("bad record".into()))?, replaced })
    }
}

struct Terminal {
    lines: Mutex<Lines<BufReader<Stdin>>>,
}

#[async_trait]
impl OwnerPrompt for Terminal {
    async fn status(&self, line: &str) {
        println!("  {line}");
    }
    async fn confirm_code(&self, code: &str) -> bool {
        println!();
        println!("    ┌───────────┐");
        println!("    │  {}  │   Does the phone show the same 6 digits? [y/N]", bogo_approver_iphone::wire::spaced(code));
        println!("    └───────────┘");
        let answer = self.lines.lock().await.next_line().await.ok().flatten().unwrap_or_default();
        println!("  owner answered: {answer:?}");
        matches!(answer.trim(), "y" | "Y" | "yes")
    }
}

struct App {
    mac: Arc<Mutex<Mac>>,
    hub: Arc<Hub>,
    terminal: Arc<Terminal>,
    vectors: HashMap<String, Vec<u8>>,
    bogo_id: [u8; 32],
    keep_vector_bogo_id: bool,
    arm_delay_ms: u64,
}

impl App {
    async fn find(&self, sel: &str) -> Option<(ReqId, Vec<ApproverId>, String)> {
        let mac = self.mac.lock().await;
        let n: Option<usize> = sel.trim_start_matches('#').parse().ok();
        mac.reqs
            .iter()
            .enumerate()
            .find(|(i, r)| n == Some(i + 1) || hex::encode(r.id).starts_with(sel))
            .map(|(_, r)| (r.id, r.to.clone(), r.vector.clone()))
    }

    async fn command(&self, line: &str) -> Result<bool, String> {
        let words: Vec<&str> = line.split_whitespace().collect();
        let rest = |i: usize| words.get(i..).map(|w| w.join(" ")).unwrap_or_default();
        match words.first().copied() {
            None => {}
            Some("quit" | "exit") => return Ok(false),
            Some("help") => println!(
                "commands: register <name> | approvers | revoke <name> | vectors | send <vector> [k=<n>] | requests\n          settled <#> | ended <#> [why] | outcome <#> <executed|notSent|unknown> | boot | log [n] | verify | quit"
            ),
            Some("register") => {
                let name = rest(1);
                if name.is_empty() {
                    return Err("register <name>".into());
                }
                println!("Registering approver \"{name}\" (numeric comparison through the relay)…");
                match self.hub.register("iphone", &name, self.terminal.as_ref()).await {
                    Ok(a) => println!("✔ registered \"{}\" approver {} (tx {})", a.name, short(&a.id), short(&a.tx_id)),
                    Err(e) => println!("✗ {e}"),
                }
            }
            Some("approvers") => {
                let mac = self.mac.lock().await;
                for a in mac.registry.approvers.values() {
                    println!(
                        "  {} {:<16} {} alg={} attest={} registered@{}{}",
                        &a.entry.id.text()[..12],
                        a.entry.name,
                        if a.active() { "active " } else { "REVOKED" },
                        a.entry.alg,
                        a.entry.attest.get("environment").and_then(|v| v.as_str()).unwrap_or("?"),
                        a.registered_seq,
                        a.revoked_by.map(|b| format!(" by {b:?}")).unwrap_or_default()
                    );
                }
            }
            Some("revoke") => {
                let name = rest(1);
                let id = {
                    let mac = self.mac.lock().await;
                    mac.registry.approver_named(&name).and_then(|a| <ApproverId>::try_from(a.entry.id.0.as_slice()).ok())
                };
                let id = id.ok_or("no active approver with that name")?;
                let effects = self.mac.lock().await.revoke(id, RevokedBy::Owner).await.map_err(|e| e.0)?;
                self.hub.revoked(&id).await;
                self.hub.apply(effects);
                println!("✔ revoked \"{name}\" (by owner)");
            }
            Some("vectors") => {
                let mut names: Vec<_> = self.vectors.keys().collect();
                names.sort();
                for n in names {
                    let f = request::parse(&self.vectors[n]);
                    println!("  {n:<22} {}", f.map(|f| format!("{}__{}", f.upstream, f.tool)).unwrap_or_default());
                }
            }
            Some("send") => {
                let name = words.get(1).ok_or("send <vector> [k=<n>]")?;
                let k: usize = words
                    .iter()
                    .find_map(|w| w.strip_prefix("k="))
                    .map(|k| k.parse().map_err(|_| "k must be a number"))
                    .transpose()?
                    .unwrap_or(1);
                let vector = self.vectors.get(*name).ok_or("no such vector (try `vectors`)")?;
                let mut mac = self.mac.lock().await;
                let to: Vec<ApproverId> = mac
                    .registry
                    .active_approvers()
                    .filter_map(|a| a.entry.id.0.as_slice().try_into().ok())
                    .collect();
                if to.len() < k {
                    return Err(format!("only {} active approver(s); need {k}", to.len()));
                }
                mac.seq += 1;
                let mut req = [0u8; 40];
                req[..32].copy_from_slice(&mac.boot_id);
                req[32..].copy_from_slice(&mac.seq.to_be_bytes());
                let own = (!self.keep_vector_bogo_id).then_some(&self.bogo_id);
                let bytes = request::restamp(vector, own, &req, now_ms()).ok_or("vector does not parse")?;
                let f = request::parse(&bytes).ok_or("restamped request does not parse")?;
                let epoch = mac.epoch(&f.agent_id);
                let seqs = mac
                    .append(vec![LogEvent::RequestCreated {
                        req: Hex::of(&req),
                        request: Hex(bytes.clone()),
                        to: to.iter().map(|a| Hex::of(a)).collect(),
                        k: k as u32,
                        pause_epoch: epoch,
                    }])
                    .await
                    .map_err(|e| e.0)?;
                let index = mac.reqs.len() + 1;
                mac.reqs.push(Req {
                    id: req,
                    vector: name.to_string(),
                    bytes: bytes.clone(),
                    to: to.clone(),
                    k,
                    agent: f.agent_id.clone(),
                    state: State::Pending,
                    counted: BTreeSet::new(),
                });
                let names: Vec<String> = to.iter().map(|a| mac.name(a)).collect();
                let boot_seq = mac.boot_seq;
                drop(mac);
                println!(
                    "→ #{index} {name}: {}__{} by \"{}\"{} — req {} — request_created durable (seq {}), delivering to {}",
                    f.upstream,
                    f.tool,
                    f.agent_name,
                    f.justification.map(|j| format!(", reason {j:?}")).unwrap_or_default(),
                    short(&req),
                    seqs[0],
                    names.join(", ")
                );
                self.hub.ask(
                    Outbound { req, bytes, boot_seq, pause_epoch: epoch, arm_delay_ms: self.arm_delay_ms, group_key: vec![] },
                    &to,
                );
            }
            Some("requests") => {
                let mac = self.mac.lock().await;
                for (i, r) in mac.reqs.iter().enumerate() {
                    println!(
                        "  #{:<2} {:<20} {:?} counted={}/{} req {}",
                        i + 1,
                        r.vector,
                        r.state,
                        r.counted.len(),
                        r.k,
                        short(&r.id)
                    );
                }
            }
            Some("settled") => {
                let (req, to, v) = self.find(words.get(1).ok_or("settled <#>")?).await.ok_or("no such request")?;
                self.hub.settled(req, &to);
                println!("→ sent `settled` for #{v}");
            }
            Some("ended") => {
                let (req, to, v) = self.find(words.get(1).ok_or("ended <#> [why]")?).await.ok_or("no such request")?;
                let why = EndWhy::parse(words.get(2).copied().unwrap_or("callEnded")).ok_or("unknown reason")?;
                {
                    let mut mac = self.mac.lock().await;
                    let live = mac.req_mut(&req).is_some_and(|r| matches!(r.state, State::Pending | State::Settled));
                    if live {
                        mac.append(vec![LogEvent::RequestEnded { req: Hex::of(&req), why: why.wire().into() }])
                            .await
                            .map_err(|e| e.0)?;
                        mac.req_mut(&req).expect("live").state = State::Ended(why.wire().into());
                    }
                }
                self.hub.ended(req, why, &to);
                println!("→ sent `ended {}` for #{v}", why.wire());
            }
            Some("outcome") => {
                let (req, to, v) = self.find(words.get(1).ok_or("outcome <#> <word>")?).await.ok_or("no such request")?;
                let word = words.get(2).copied().unwrap_or("executed");
                // `quiet`: record the evidence but send nothing, as if the Mac
                // stopped before telling the phone; `sync` must recover it.
                let quiet = words.get(3) == Some(&"quiet");
                let evidence = match word {
                    "executed" => vec![
                        LogEvent::Forwarded { req: Hex::of(&req), registry_seq: 0 },
                        LogEvent::Result { req: Hex::of(&req), ok: true },
                    ],
                    "notSent" => vec![LogEvent::NotSent { req: Hex::of(&req) }],
                    "unknown" => vec![LogEvent::Forwarded { req: Hex::of(&req), registry_seq: 0 }],
                    _ => vec![],
                };
                if !evidence.is_empty() {
                    self.mac.lock().await.append(evidence).await.map_err(|e| e.0)?;
                }
                if quiet {
                    println!("  recorded outcome {word} for #{v} in the log; no notice sent");
                } else {
                    self.hub.outcome(req, word, &to);
                    println!("→ sent `outcome {word}` for #{v}");
                }
            }
            Some("boot") => {
                let notice = {
                    let mut mac = self.mac.lock().await;
                    let boot_seq = mac.home.next_boot(&mac._lock).map_err(|e| e.to_string())?;
                    let boot_id: [u8; 32] = rand::random();
                    mac.append(vec![LogEvent::Boot { boot_seq, boot_id: Hex::of(&boot_id) }])
                        .await
                        .map_err(|e| e.0)?;
                    (mac.boot_seq, mac.boot_id, mac.seq) = (boot_seq, boot_id, 0);
                    for r in mac.reqs.iter_mut().filter(|r| matches!(r.state, State::Pending | State::Settled)) {
                        r.state = State::Ended("otherBoot".into());
                    }
                    BootNotice { boot_seq, boot_id }
                };
                self.hub.boot_notice(notice);
                println!("→ new boot {} ({}); every earlier request has ended; sent `boot`", notice.boot_seq, short(&notice.boot_id));
            }
            Some("log") => {
                let n: usize = words.get(1).and_then(|n| n.parse().ok()).unwrap_or(10);
                let entries = self.mac.lock().await.log.entries().map_err(|e| e.to_string())?;
                for e in entries.iter().rev().take(n).rev() {
                    println!("  {}", summarize(&e.raw));
                }
            }
            Some("verify") => {
                let entries = self.mac.lock().await.log.entries().map_err(|e| e.to_string())?;
                let report = bogo_log::verify::verify(&entries, &|alg, pk, m, p| bogo_verify::verify(alg, pk, m, p))
                    .map_err(|e| e.to_string())?;
                println!("✔ chain intact; {report:?}");
            }
            Some(other) => return Err(format!("unknown command {other:?} (try `help`)")),
        }
        Ok(true)
    }
}

/// One log line, with long hex fields shortened for the terminal.
fn summarize(raw: &str) -> String {
    let mut v: serde_json::Value = serde_json::from_str(raw).unwrap_or_default();
    fn shorten(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::String(s) if s.len() == 80 && s.bytes().all(|b| b.is_ascii_hexdigit()) => {
                *s = bogo_standin::rid(&hex::decode(&*s).unwrap_or_default());
            }
            serde_json::Value::String(s) if s.len() > 24 && s.bytes().all(|b| b.is_ascii_hexdigit()) => {
                *s = format!("{}…({}B)", &s[..12], s.len() / 2);
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(shorten),
            serde_json::Value::Object(o) => o.values_mut().for_each(shorten),
            _ => {}
        }
    }
    shorten(&mut v);
    v.to_string()
}

fn load_vectors(dir: &std::path::Path) -> Result<HashMap<String, Vec<u8>>, String> {
    let text = std::fs::read_to_string(dir.join("requests.json")).map_err(|e| format!("vectors: {e}"))?;
    let root: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("vectors: {e}"))?;
    Ok(root["requests"]
        .as_array()
        .ok_or("vectors: no requests")?
        .iter()
        .filter_map(|r| Some((r["name"].as_str()?.to_string(), hex::decode(r["encoded_hex"].as_str()?).ok()?)))
        .collect())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();
    if let Err(e) = run(Args::parse()).await {
        eprintln!("bogo-standin: {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), String> {
    let root = match &args.home {
        Some(h) => h.clone(),
        None => Home::default_root().map_err(|e| e.to_string())?,
    };
    let home = Home::open(&root).map_err(|e| e.to_string())?;
    let lock = home.lock().map_err(|e| e.to_string())?;
    let keys = home.keys(&lock).map_err(|e| e.to_string())?;
    let (log, entries, registry, source) = home.open_log(&lock).map_err(|e| e.to_string())?;
    let boot_seq = home.next_boot(&lock).map_err(|e| e.to_string())?;
    let boot_id: [u8; 32] = rand::random();
    println!("BOGO stand-in — home {}", root.display());
    println!("  bogoId {}", hex::encode(keys.bogo_id));
    println!(
        "  log: {} entries, chain intact; registry {:?}; {} approver(s), {} active",
        entries.len(),
        source,
        registry.approvers.len(),
        registry.active_approvers().count()
    );
    println!(
        "  build: {}",
        if bogo_approver_iphone::accepts_simulator_registration() {
            "TEST (accepts the simulator-only registration path)"
        } else {
            "default (App Attest required)"
        }
    );
    let vectors_dir = args
        .vectors
        .clone()
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors"));
    let vectors = load_vectors(&vectors_dir)?;
    let environments = args
        .app_attest
        .iter()
        .map(|e| match e.as_str() {
            "production" => Ok(bogo_attest::Environment::Production),
            "development" => Ok(bogo_attest::Environment::Development),
            _ => Err(format!("unknown App Attest environment {e:?}")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let relay_root_pem = args
        .relay_ca
        .as_ref()
        .map(std::fs::read)
        .transpose()
        .map_err(|e| format!("relay CA: {e}"))?;
    let cfg = Config {
        relay_url: args.relay.clone(),
        relay_service: args.relay_service.clone(),
        relay_root_pem,
        mac_name: args.mac_name.clone(),
        app_id: args.app_id.clone(),
        environments,
        bundle_versions: args.bundle_version.clone(),
        apns: args.apns_key.clone().map(|key_path| ApnsConfig {
            key_path,
            key_id: args.apns_key_id.clone(),
            team_id: args.apns_team.clone(),
            topic: args.apns_topic.clone(),
        }),
    };
    let route = IphoneRoute::new(
        cfg,
        MacKeys { e2e: keys.e2e.clone(), e2e_public: keys.e2e_public, relay: keys.relay.clone(), bogo_id: keys.bogo_id },
    )?;
    println!("  relay mailbox {}", route.mailbox());
    let approvers: Vec<ApproverRecord> = registry.approvers.values().filter_map(record).collect();
    let seq = log
        .append(LogEvent::Boot { boot_seq, boot_id: Hex::of(&boot_id) })
        .await
        .map_err(|e| e.to_string())?;
    println!("  boot {boot_seq} ({}) recorded at log seq {seq}", short(&boot_id));
    let mac = Arc::new(Mutex::new(Mac {
        home,
        _lock: lock,
        log,
        registry,
        boot_seq,
        boot_id,
        seq: 0,
        reqs: vec![],
        epochs: HashMap::new(),
    }));
    let hub = Hub::new(vec![route.clone() as Arc<dyn ApproverRoute>], Arc::new(Standin(mac.clone())));
    hub.start(approvers, BootNotice { boot_seq, boot_id }).await;
    println!("  allowlist applied; `boot` and `registered` sent to every active approver. Type `help`.");
    let terminal = Arc::new(Terminal { lines: Mutex::new(BufReader::new(tokio::io::stdin()).lines()) });
    let app = App {
        mac,
        hub,
        terminal: terminal.clone(),
        vectors,
        bogo_id: keys.bogo_id,
        keep_vector_bogo_id: args.keep_vector_bogo_id,
        arm_delay_ms: args.arm_delay_ms,
    };
    loop {
        let line = terminal.lines.lock().await.next_line().await.map_err(|e| e.to_string())?;
        let Some(line) = line else { break };
        if !line.trim().is_empty() {
            println!("» {}", line.trim());
        }
        match app.command(&line).await {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => println!("✗ {e}"),
        }
    }
    Ok(())
}
