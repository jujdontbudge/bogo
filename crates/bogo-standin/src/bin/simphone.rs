//! `bogo-simphone`: the phone's half of BOGO's relay protocol, in test builds
//! only. It stands in for BogoKit's `RelayMacLink`, which the app does not
//! have yet, so the stand-in Mac can be exercised end to end through a real
//! relay.
//!
//! With `--app-data`, it bridges the iOS Simulator app: requests that arrive
//! over the relay are handed to the app's Debug stand-in link (its `inbox/`
//! drop folder), and every message the app sends (`received.jsonl`) is sealed
//! and sent to the Mac unchanged, with the app's own message ID. The app
//! signs; this program never signs an approval in that mode. Registration
//! uses the app's simulator-only approval key (a file that exists only in
//! Simulator Debug builds) for the proof of possession, and sends no App
//! Attest evidence: the simulator-only path, which only a test build of the
//! Mac accepts.
//!
//! Without `--app-data`, it is a whole software phone with its own key.
use bogo_approver_iphone::wire::*;
use bogo_e2e::{Direction, Header};
use bogo_relay_proto::{Client, LobbySend, SigningKey};
use clap::Parser;
use p256::ecdsa::signature::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader, Lines, Stdin},
    sync::Mutex,
};

#[derive(Parser)]
struct Args {
    /// Where this phone keeps its store (keys, records, outbox).
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    relay: String,
    #[arg(long)]
    relay_service: String,
    #[arg(long)]
    relay_ca: Option<PathBuf>,
    /// The Simulator app's data container, to bridge the app.
    #[arg(long)]
    app_data: Option<PathBuf>,
    /// Send this file as the App Attest object (to check that bad evidence is refused).
    #[arg(long)]
    attestation_file: Option<PathBuf>,
    /// Register with this APNs device token (64 hex) so the Mac sends wake-ups.
    #[arg(long)]
    push_token: Option<String>,
    /// APNs environment for --push-token: development or production.
    #[arg(long, default_value = "development")]
    push_env: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct MacReg {
    name: String,
    bogo_id: B,
    mac_e2e: B,
    mac_mailbox: String,
    approver_id: B,
    tx_id: B,
    /// waiting | active | removed | gone
    state: String,
    boot_seq: u64,
    e2e_secret: B,
    /// Raw P-256 scalar of this phone's own key; empty in app mode.
    approval_key: B,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Rec {
    req_id: B,
    /// Empty for a placeholder: a notice that arrived before its request.
    bytes: B,
    boot_seq: u64,
    pause_epoch: u64,
    /// pending | sent | settled | ended | finished
    phase: String,
    decision: Option<String>,
    detail: Option<String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Out {
    n: usize,
    msg_id: B,
    kind: String,
    body: String,
    envelope: B,
    sent: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    relay_seed: B,
    mac: Option<MacReg>,
    records: Vec<Rec>,
    /// Applied inbound message IDs (tombstones).
    done: Vec<String>,
    outbox: Vec<Out>,
    /// Lines of the app's `received.jsonl` already forwarded; on first use,
    /// everything the app wrote before the bridge started is skipped.
    app_lines: Option<usize>,
}

struct Phone {
    path: PathBuf,
    store: Store,
    held: bool,
    app: Option<PathBuf>,
}

impl Phone {
    /// Atomic write: temp, sync, rename. Nothing is acknowledged before this.
    fn save(&self) {
        let tmp = self.path.with_extension("tmp");
        let bytes = serde_json::to_vec_pretty(&self.store).expect("store serializes");
        std::fs::write(&tmp, bytes)
            .and_then(|_| std::fs::File::open(&tmp)?.sync_all())
            .and_then(|_| std::fs::rename(&tmp, &self.path))
            .expect("phone store write");
    }

    fn mac(&self) -> Option<&MacReg> {
        self.store.mac.as_ref()
    }

    fn rec(&mut self, req: &[u8]) -> Option<&mut Rec> {
        self.store.records.iter_mut().find(|r| r.req_id.0 == req)
    }

    /// The app's state machine (BogoModel `RequestPhase.applying`).
    fn apply(&mut self, req: &[u8], event: &str, detail: Option<String>) {
        let rec = match self.rec(req) {
            Some(r) => r,
            None => {
                self.store.records.push(Rec {
                    req_id: B(req.to_vec()),
                    phase: "pending".into(),
                    ..Rec::default()
                });
                self.store.records.last_mut().expect("pushed")
            }
        };
        let next = match (rec.phase.as_str(), event) {
            ("finished", _) => None,
            ("pending", "settled") | ("sent", "settled") => Some("settled"),
            ("pending" | "sent" | "settled", "ended") => Some("ended"),
            (_, "outcome") => Some("finished"),
            _ => None,
        };
        if let Some(next) = next {
            rec.phase = next.into();
            rec.detail = detail;
        }
    }

    fn enqueue(&mut self, msg: &PhoneMsg, id: [u8; 16], body: Option<String>) -> Option<usize> {
        let mac = self.mac()?.clone();
        let body = body.unwrap_or_else(|| serde_json::to_string(msg).expect("message serializes"));
        // A resend under the same message ID must be the same bytes, or the
        // relay refuses it as a conflict while the first copy is queued.
        let sealed = self.store.outbox.iter().find(|o| o.msg_id.0 == id && o.body == body);
        let envelope = match sealed {
            Some(o) => o.envelope.0.clone(),
            None => self.seal(&mac, msg, id, &body)?,
        };
        let n = self.store.outbox.len() + 1;
        let kind = body_kind(&body);
        self.store.outbox.push(Out { n, msg_id: B(id.to_vec()), kind, body, envelope: B(envelope), sent: false });
        Some(n)
    }

    fn seal(&self, mac: &MacReg, msg: &PhoneMsg, id: [u8; 16], body: &str) -> Option<Vec<u8>> {
        let secret = bogo_e2e::secret_from(&mac.e2e_secret.0).ok()?;
        bogo_e2e::seal(
            &secret,
            &bogo_e2e::public_from(&mac.mac_e2e.0).ok()?,
            &mac.bogo_id.array()?,
            &mac.approver_id.array()?,
            Header { direction: Direction::PhoneToMac, kind: msg.kind(), id },
            body.as_bytes(),
        )
        .ok()
    }

    fn app_inbox(&self, command: serde_json::Value) {
        let Some(app) = &self.app else { return };
        let dir = app.join("Library/Application Support/BOGO/stand-in/inbox");
        let _ = std::fs::create_dir_all(&dir);
        let name = format!("{}-{}", std::process::id(), rand::random::<u64>());
        let tmp = dir.join(format!("{name}.tmp"));
        if std::fs::write(&tmp, command.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, dir.join(format!("{name}.json")));
        }
    }
}

fn body_kind(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["type"].as_str().map(String::from))
        .unwrap_or_default()
}

fn short(b: &[u8]) -> String {
    bogo_standin::rid(b)
}

type Shared = Arc<Mutex<Phone>>;

struct Ctx {
    phone: Shared,
    attestation: Option<Vec<u8>>,
    push: Option<(B, String)>,
    client: Arc<Client>,
    mailbox: String,
    lines: Mutex<Lines<BufReader<Stdin>>>,
}

async fn connect(args: &Args, key: &SigningKey) -> Result<Client, String> {
    let root = args
        .relay_ca
        .as_ref()
        .map(|p| std::fs::read(p).map_err(|e| e.to_string()).and_then(|b| reqwest::Certificate::from_pem(&b).map_err(|e| e.to_string())))
        .transpose()?;
    let http = Client::http(root).map_err(|e| e.to_string())?;
    Client::connect(&args.relay, &args.relay_service, key, http).await.map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Err(e) = run(args).await {
        eprintln!("bogo-simphone: {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), String> {
    std::fs::create_dir_all(&args.store).map_err(|e| e.to_string())?;
    let path = args.store.join("phone.json");
    let mut store: Store = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    if store.relay_seed.0.len() != 32 {
        store.relay_seed = B(SigningKey::generate(&mut rand::rngs::OsRng).to_bytes().to_vec());
    }
    let key = SigningKey::from_bytes(&store.relay_seed.array().ok_or("bad relay seed")?);
    let phone = Arc::new(Mutex::new(Phone { path, store, held: false, app: args.app_data.clone() }));
    phone.lock().await.save();
    let client = Arc::new(connect(&args, &key).await?);
    let mailbox = client.mailbox.clone();
    println!("BOGO sim phone — store {} — relay mailbox {}", args.store.display(), &mailbox[..16]);
    if let Some(app) = &args.app_data {
        println!("  bridging the Simulator app at {}", app.display());
    }
    if let Some(mac) = phone.lock().await.mac() {
        println!("  registered Mac: {} ({}), state {}", mac.name, short(&mac.bogo_id.0), mac.state);
        if mac.state != "gone" {
            client.allow(vec![mac.mac_mailbox.clone()]).await.map_err(|e| e.to_string())?;
        }
    }
    let attestation = args.attestation_file.as_ref().map(std::fs::read).transpose().map_err(|e| e.to_string())?;
    let push = match &args.push_token {
        Some(t) => Some((B(hex::decode(t).ok().filter(|t| t.len() == 32).ok_or("--push-token must be 64 hex")?), args.push_env.clone())),
        None => None,
    };
    let ctx = Arc::new(Ctx {
        phone: phone.clone(),
        attestation,
        push,
        client: client.clone(),
        mailbox,
        lines: Mutex::new(BufReader::new(tokio::io::stdin()).lines()),
    });
    // Reconnect loop for the inbound side: one long-poll at a time.
    {
        let (ctx, args_relay, args_service, ca, seed) =
            (ctx.clone(), args.relay.clone(), args.relay_service.clone(), args.relay_ca.clone(), key.clone());
        tokio::spawn(async move {
            let args = Args {
                store: PathBuf::new(),
                relay: args_relay,
                relay_service: args_service,
                relay_ca: ca,
                app_data: None,
                attestation_file: None,
                push_token: None,
                push_env: String::new(),
            };
            let mut client = ctx.client.clone();
            loop {
                match inbound(&ctx, &client).await {
                    Ok(()) => {}
                    Err(e) => {
                        eprintln!("  (relay fetch: {e}; reconnecting)");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        if let Ok(c) = connect(&args, &seed).await {
                            client = Arc::new(c);
                        }
                    }
                }
            }
        });
    }
    {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            loop {
                flush(&ctx).await;
                if ctx.phone.lock().await.app.is_some() {
                    tail_app(&ctx).await;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });
    }
    loop {
        let line = ctx.lines.lock().await.next_line().await.map_err(|e| e.to_string())?;
        let Some(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        println!("» {}", line.trim());
        match command(&ctx, &line).await {
            Ok(true) => {}
            Ok(false) => break,
            Err(e) => println!("✗ {e}"),
        }
    }
    Ok(())
}

async fn flush(ctx: &Ctx) {
    let pending: Vec<(usize, Out, String)> = {
        let p = ctx.phone.lock().await;
        if p.held {
            return;
        }
        let Some(mac) = p.mac() else { return };
        let to = mac.mac_mailbox.clone();
        p.store.outbox.iter().filter(|o| !o.sent).map(|o| (o.n, o.clone(), to.clone())).collect()
    };
    for (n, o, to) in pending {
        if send(ctx, &o, &to).await {
            let mut p = ctx.phone.lock().await;
            if let Some(x) = p.store.outbox.iter_mut().find(|x| x.n == n) {
                x.sent = true;
            }
            p.save();
            println!("  → sent #{n} {} ({})", o.kind, short(&o.msg_id.0));
        }
    }
}

async fn send(ctx: &Ctx, o: &Out, to: &str) -> bool {
    let Some(id) = o.msg_id.array::<16>() else { return false };
    ctx.client.send(to, id, &o.envelope.0).await.is_ok()
}

/// Forward every new line the app wrote to its stand-in log, unchanged.
async fn tail_app(ctx: &Ctx) {
    let mut p = ctx.phone.lock().await;
    let Some(app) = p.app.clone() else { return };
    if p.mac().is_none_or(|m| m.state == "gone" || m.state == "waiting") {
        return;
    }
    let file = app.join("Library/Application Support/BOGO/stand-in/received.jsonl");
    let Ok(text) = std::fs::read_to_string(&file) else { return };
    let lines: Vec<&str> = text.lines().collect();
    let start = match p.store.app_lines {
        Some(n) if n <= lines.len() => n,
        Some(_) => 0,
        None => lines.len(),
    };
    p.store.app_lines = Some(start);
    for line in &lines[start..] {
        p.store.app_lines = p.store.app_lines.map(|n| n + 1);
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let (Some(body), Some(id)) = (v["body"].as_str(), v["msgId"].as_str()) else { continue };
        let Ok(msg) = serde_json::from_str::<PhoneMsg>(body) else { continue };
        let id: [u8; 16] = match hex::decode(id).ok().and_then(|b| b.try_into().ok()) {
            Some(id) => id,
            None => Sha256::digest(id.as_bytes())[..16].try_into().expect("16"),
        };
        if matches!(msg, PhoneMsg::Removed {})
            && let Some(m) = p.store.mac.as_mut()
        {
            m.state = "removed".into();
        }
        if let PhoneMsg::Approval { req_id, .. } | PhoneMsg::Denial { req_id, .. } = &msg
            && let Some(r) = p.rec(&req_id.0)
            && r.phase == "pending"
        {
            r.phase = "sent".into();
            r.decision = Some(msg_kind(&msg).into());
        }
        if let Some(n) = p.enqueue(&msg, id, Some(body.to_string())) {
            println!("  app → #{n} {} (the app's own message {}, forwarded unchanged)", msg_kind(&msg), short(&id));
        }
    }
    p.save();
}

fn msg_kind(m: &PhoneMsg) -> &'static str {
    match m {
        PhoneMsg::Approval { .. } => "approval",
        PhoneMsg::Denial { .. } => "denial",
        PhoneMsg::Pause { .. } => "pause",
        PhoneMsg::Seen { .. } => "seen",
        PhoneMsg::PushToken { .. } => "pushToken",
        PhoneMsg::Sync { .. } => "sync",
        PhoneMsg::RegResend { .. } => "regResend",
        PhoneMsg::Removed {} => "removed",
    }
}

/// Store first, then `seen`, then acknowledge.
async fn inbound(ctx: &Ctx, client: &Client) -> Result<(), String> {
    let batch = client.fetch(true).await.map_err(|e| e.to_string())?;
    for m in batch {
        let mut p = ctx.phone.lock().await;
        if p.store.done.contains(&m.msg_id) {
            drop(p);
            client.ack(vec![m.msg_id.clone()]).await.map_err(|e| e.to_string())?;
            println!("  ← duplicate {} already applied; acknowledged again", &m.msg_id[..12]);
            continue;
        }
        let Some(mac) = p.mac().cloned().filter(|mac| mac.mac_mailbox == m.from) else {
            drop(p);
            client.ack(vec![m.msg_id]).await.map_err(|e| e.to_string())?;
            continue;
        };
        let opened = (|| {
            let body = hex::decode(&m.body).ok()?;
            let o = bogo_e2e::open(
                &bogo_e2e::secret_from(&mac.e2e_secret.0).ok()?,
                &bogo_e2e::public_from(&mac.mac_e2e.0).ok()?,
                &mac.bogo_id.array()?,
                &mac.approver_id.array()?,
                Direction::MacToPhone,
                &body,
            )
            .ok()?;
            let msg: MacMsg = serde_json::from_slice(&o.plaintext).ok()?;
            (msg.kind() == o.kind).then_some(msg)
        })();
        let Some(msg) = opened else {
            println!("  ← dropped an envelope that failed to open");
            drop(p);
            client.ack(vec![m.msg_id]).await.map_err(|e| e.to_string())?;
            continue;
        };
        let own = mac.approval_key.0.len() == 32;
        print!("  [{}]", &m.msg_id[..8]);
        match msg {
            MacMsg::Request { req_id, boot_seq, bytes, pause_epoch, arm_delay_ms } => {
                let late = p.rec(&req_id.0).map(|r| r.phase.clone());
                let fresh = late.as_ref().is_none_or(|_| p.rec(&req_id.0).is_some_and(|r| r.bytes.0.is_empty()));
                if fresh {
                    let mut phase = late.clone().unwrap_or_else(|| "pending".into());
                    let mut detail = p.rec(&req_id.0).and_then(|r| r.detail.clone());
                    if phase == "pending" && boot_seq < mac.boot_seq {
                        (phase, detail) = ("ended".into(), Some("otherBoot".into()));
                    }
                    p.store.records.retain(|r| r.req_id != req_id);
                    p.store.records.push(Rec {
                        req_id: req_id.clone(),
                        bytes: bytes.clone(),
                        boot_seq,
                        pause_epoch,
                        phase: phase.clone(),
                        decision: None,
                        detail,
                    });
                    let n = p.store.records.len();
                    println!(
                        "  ← request #{n} {} (boot {boot_seq}, epoch {pause_epoch}, arm {arm_delay_ms} ms){}",
                        short(&req_id.0),
                        if phase == "pending" { String::new() } else { format!(" — arrived after its end: shown greyed ({phase})") }
                    );
                    if p.app.is_some() {
                        p.app_inbox(serde_json::json!({ "hex": hex::encode(&bytes.0) }));
                        println!("    handed to the app's stand-in link");
                    }
                }
                if own {
                    p.enqueue(&PhoneMsg::Seen { req_id: req_id.clone() }, bogo_e2e::message_id(), None);
                }
            }
            MacMsg::Settled { req_id } => {
                p.apply(&req_id.0, "settled", None);
                println!("  ← settled {}{}", short(&req_id.0), app_note(&p));
            }
            MacMsg::Ended { req_id, why } => {
                p.apply(&req_id.0, "ended", Some(why.clone()));
                println!("  ← ended {} ({why}){}", short(&req_id.0), app_note(&p));
            }
            MacMsg::Outcome { req_id, outcome } => {
                if outcome != "live" {
                    p.apply(&req_id.0, "outcome", Some(outcome.clone()));
                }
                println!("  ← outcome {} = {outcome}{}", short(&req_id.0), app_note(&p));
            }
            MacMsg::Boot { boot_seq, boot_id } => {
                let current = p.mac().map_or(0, |m| m.boot_seq);
                if boot_seq > current {
                    for r in p.store.records.iter_mut().filter(|r| r.boot_seq < boot_seq && r.phase == "pending" && !r.bytes.0.is_empty()) {
                        r.phase = "ended".into();
                        r.detail = Some("otherBoot".into());
                    }
                    if let Some(m) = p.store.mac.as_mut() {
                        m.boot_seq = boot_seq;
                    }
                    let open: Vec<B> = p
                        .store
                        .records
                        .iter()
                        .filter(|r| r.phase == "sent" || (r.phase == "settled" && matches!(r.decision.as_deref(), Some("approval" | "approve"))))
                        .map(|r| r.req_id.clone())
                        .collect();
                    if !open.is_empty() && own {
                        p.enqueue(&PhoneMsg::Sync { req_ids: open }, bogo_e2e::message_id(), None);
                    }
                    if p.app.is_some() {
                        p.app_inbox(serde_json::json!({ "boot": true }));
                    }
                    println!("  ← boot {boot_seq} ({}): requests from earlier boots ended", short(&boot_id.0));
                } else {
                    println!("  ← boot {boot_seq} (not newer; nothing to do)");
                }
            }
            MacMsg::Registered { tx_id, approver_id } => {
                if let Some(m) = p.store.mac.as_mut()
                    && m.tx_id == tx_id
                    && m.approver_id == approver_id
                    && m.state == "waiting"
                {
                    m.state = "active".into();
                    println!("  ← registered (mailbox copy): this phone is now active");
                } else {
                    println!("  ← registered again (already active; ignored)");
                }
            }
            MacMsg::RevokedAck {} => match p.store.mac.as_mut() {
                Some(m) if m.state == "removed" => {
                    m.state = "gone".into();
                    println!("  ← revokedAck: the Mac confirmed the removal; channel keys can go");
                }
                _ => println!("  ← revokedAck, but this phone did not remove the Mac; ignored"),
            },
        }
        p.store.done.push(m.msg_id.clone());
        p.save();
        drop(p);
        client.ack(vec![m.msg_id]).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn app_note(p: &Phone) -> &'static str {
    if p.app.is_some() {
        " — the app's Debug stand-in link can't take this notice for a relay request, so it is applied here only"
    } else {
        ""
    }
}

async fn ask(ctx: &Ctx, prompt: &str) -> bool {
    println!("{prompt} [y/N]");
    let a = ctx.lines.lock().await.next_line().await.ok().flatten().unwrap_or_default();
    println!("  answered {a:?}");
    matches!(a.trim(), "y" | "Y" | "yes")
}

fn app_key(app: &Path) -> Result<(p256::ecdsa::SigningKey, String), String> {
    let dir = app.join("Library/Application Support/BOGO/simulator-keys");
    let newest = std::fs::read_dir(&dir)
        .map_err(|_| "no simulator key yet: add the stand-in Mac in the app first (BOGO → Macs → Add Mac)".to_string())?
        .filter_map(Result::ok)
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .max()
        .ok_or("no simulator key yet: add the stand-in Mac in the app first")?
        .1;
    let raw = std::fs::read(&newest).map_err(|e| e.to_string())?;
    let key = p256::ecdsa::SigningKey::from_slice(&raw).map_err(|e| e.to_string())?;
    Ok((key, newest.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()))
}

async fn lobby_wait(client: &Client, offer: &str, offer_id: &[u8; 16], want: u8) -> Result<Vec<u8>, String> {
    for _ in 0..2000 {
        let msgs = match client.lobby_fetch(offer).await {
            Err(bogo_relay_proto::Error::Status(404)) => return Err("the Mac closed the offer".into()),
            other => other.map_err(|e| e.to_string())?,
        };
        for m in msgs {
            let Ok(body) = hex::decode(&m.body) else { continue };
            let Some(&phase) = body.first() else { continue };
            if m.msg_id != hex::encode(phase_msg_id(offer_id, phase)) {
                continue;
            }
            if phase == PHASE_MAC_ABORT {
                return Err("the Mac cancelled (the owner said the codes do not match)".into());
            }
            if phase == want || (want == PHASE_REGISTERED && phase == PHASE_REFUSED) {
                return Ok(body);
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    Err("timed out".into())
}

async fn lobby_send(client: &Client, offer: &str, offer_id: &[u8; 16], phase: u8, payload: &[u8]) -> Result<(), String> {
    client
        .lobby_send(
            offer,
            &LobbySend { msg_id: hex::encode(phase_msg_id(offer_id, phase)), body: hex::encode(phase_body(phase, payload)) },
        )
        .await
        .map_err(|e| e.to_string())
}

async fn add(ctx: &Ctx, label: &str) -> Result<(), String> {
    let client = &ctx.client;
    let offers = client.offers().await.map_err(|e| e.to_string())?;
    let o = offers
        .iter()
        .find(|o| label.is_empty() || o.offer.mac_label == label)
        .ok_or("no open offer: run `register <name>` on the Mac first")?;
    println!("  Add Mac: \"{}\" (offer opened {}s ago)", o.offer.mac_label, o.age_seconds);
    let offer = o.offer.offer_id.clone();
    let offer_id: [u8; 16] = hex::decode(&offer).ok().and_then(|b| b.try_into().ok()).ok_or("bad offer id")?;
    let e_pub_m: [u8; 32] = hex::decode(&o.offer.e_pub_m).ok().and_then(|b| b.try_into().ok()).ok_or("bad offer key")?;
    let e_p = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let e_pub_p = x25519_dalek::PublicKey::from(&e_p).to_bytes();
    lobby_send(client, &offer, &offer_id, PHASE_HELLO, &e_pub_p).await?;
    let commit: [u8; 32] = lobby_wait(client, &offer, &offer_id, PHASE_COMMIT).await?[1..].try_into().map_err(|_| "bad commit")?;
    let n_p: [u8; 16] = rand::random();
    lobby_send(client, &offer, &offer_id, PHASE_PHONE_NONCE, &n_p).await?;
    let n_m: [u8; 16] = lobby_wait(client, &offer, &offer_id, PHASE_REVEAL).await?[1..].try_into().map_err(|_| "bad reveal")?;
    if commitment(&e_pub_m, &e_pub_p, &n_m) != commit {
        lobby_send(client, &offer, &offer_id, PHASE_PHONE_ABORT, &[]).await?;
        return Err("the Mac's reveal does not match its commitment: aborted".into());
    }
    let shared = e_p.diffie_hellman(&x25519_dalek::PublicKey::from(e_pub_m));
    if !shared.was_contributory() {
        return Err("low-order key".into());
    }
    let t = Transcript { offer_id, e_pub_m, e_pub_p, commit, n_m, n_p };
    let th = t.hash();
    let key = phase_key(shared.as_bytes(), &th);
    println!();
    println!("    ┌───────────┐");
    println!("    │  {}  │   phone screen: check it matches the Mac", spaced(&t.code()));
    println!("    └───────────┘");
    let sealed = lobby_wait(client, &offer, &offer_id, PHASE_MAC_CONFIRMED).await?;
    let confirmed: MacConfirmed = open_phase(&key, &offer_id, PHASE_MAC_CONFIRMED, &sealed[1..])
        .and_then(|p| serde_json::from_slice(&p).ok())
        .ok_or("the Mac's confirmation did not open")?;
    if Sha256::digest(&confirmed.mac_e2e.0).as_slice() != confirmed.bogo_id.0.as_slice() {
        return Err("bogoId is not the hash of the Mac's E2E key".into());
    }
    println!("  The Mac confirmed \"{}\" ({}).", confirmed.mac_name, short(&confirmed.bogo_id.0));
    if !ask(ctx, "  Confirm on the phone (simulated Face ID)?").await {
        lobby_send(client, &offer, &offer_id, PHASE_PHONE_ABORT, &[]).await?;
        return Err("cancelled on the phone".into());
    }
    let app = ctx.phone.lock().await.app.clone();
    let (signing, own_raw) = match &app {
        Some(app) => {
            let (k, file) = app_key(app)?;
            println!("  approval key: the app's simulator-only key {file}");
            (k, B::default())
        }
        None => {
            let k = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
            let raw = B(k.to_bytes().to_vec());
            (k, raw)
        }
    };
    let challenge: [u8; 32] = confirmed.challenge.array().ok_or("bad challenge")?;
    let proof: p256::ecdsa::Signature = signing.sign(&pop_message(&th, &challenge));
    let approval_key = signing.verifying_key().to_encoded_point(false).as_bytes().to_vec();
    let (e2e_secret, e2e_public) = bogo_e2e::keypair();
    let relay_pub = ctx.phone.lock().await.store.relay_seed.array::<32>().map(|s| SigningKey::from_bytes(&s).verifying_key().to_bytes()).ok_or("seed")?;
    let mac_relay: [u8; 32] = confirmed.mac_relay.array().ok_or("bad Mac relay key")?;
    let mac_mailbox = bogo_relay_proto::mailbox(&mac_relay);
    client.allow(vec![mac_mailbox.clone()]).await.map_err(|e| e.to_string())?;
    let tx = tx_id(&th);
    {
        let mut p = ctx.phone.lock().await;
        p.store.mac = Some(MacReg {
            name: confirmed.mac_name.clone(),
            bogo_id: confirmed.bogo_id.clone(),
            mac_e2e: confirmed.mac_e2e.clone(),
            mac_mailbox,
            approver_id: B(approver_id(&tx).to_vec()),
            tx_id: B(tx.to_vec()),
            state: "waiting".into(),
            boot_seq: 0,
            e2e_secret: B(bogo_e2e::secret_bytes(&e2e_secret).to_vec()),
            approval_key: own_raw,
        });
        p.save();
    }
    let attestation = ctx.attestation.as_ref().map(|object| {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        AttestationEvidence { key_id: b64.encode(rand::random::<[u8; 32]>()), object: b64.encode(object) }
    });
    match &attestation {
        Some(_) => println!("  App Attest: sending the given file as the attestation object"),
        None => println!("  App Attest: none (simulator-only test path; only a test build of the Mac accepts it)"),
    }
    let submit = RegSubmit {
        approval_key: B(approval_key),
        proof: B(proof.to_bytes().to_vec()),
        phone_e2e: B(bogo_e2e::public_bytes(&e2e_public).to_vec()),
        phone_relay: B(relay_pub.to_vec()),
        attestation,
        push_token: ctx.push.as_ref().map(|(t, _)| t.clone()),
        push_env: ctx.push.as_ref().map(|(_, e)| e.clone()),
        encoding_versions: vec![1],
    };
    let plaintext = serde_json::to_vec(&submit).map_err(|e| e.to_string())?;
    lobby_send(client, &offer, &offer_id, PHASE_REG_SUBMIT, &seal_phase(&key, &offer_id, PHASE_REG_SUBMIT, &plaintext)).await?;
    println!("  submitted; waiting for the Mac…");
    let answer = lobby_wait(client, &offer, &offer_id, PHASE_REGISTERED).await?;
    let mut p = ctx.phone.lock().await;
    if answer[0] == PHASE_REFUSED {
        let why = open_phase(&key, &offer_id, PHASE_REFUSED, &answer[1..])
            .and_then(|b| serde_json::from_slice::<RefusedPhase>(&b).ok())
            .map(|r| r.why)
            .unwrap_or_default();
        p.store.mac = None;
        p.save();
        return Err(format!("the Mac refused the registration: {why}"));
    }
    let reg: RegisteredPhase = open_phase(&key, &offer_id, PHASE_REGISTERED, &answer[1..])
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or("registered did not open")?;
    if let Some(m) = p.store.mac.as_mut()
        && reg.tx_id == m.tx_id
        && reg.approver_id == m.approver_id
    {
        m.state = "active".into();
    }
    p.save();
    println!("✔ registered with \"{}\": approver {}", confirmed.mac_name, short(&reg.approver_id.0));
    Ok(())
}

async fn command(ctx: &Ctx, line: &str) -> Result<bool, String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let pick = |p: &Phone, s: Option<&&str>| -> Result<Rec, String> {
        let n: usize = s.ok_or("which request (#)")?.trim_start_matches('#').parse().map_err(|_| "a number")?;
        p.store.records.get(n.wrapping_sub(1)).cloned().ok_or_else(|| "no such request".to_string())
    };
    match words[0] {
        "quit" | "exit" => return Ok(false),
        "help" => println!("offers | add [label] | status | requests | approve <#> | deny <#> [note] | pause <#> | sync | remove | outbox | replay <n> | copy <n> | hold | release [reverse] | quit"),
        "offers" => {
            for o in ctx.client.offers().await.map_err(|e| e.to_string())? {
                println!("  \"{}\" opened {}s ago", o.offer.mac_label, o.age_seconds);
            }
        }
        "add" => add(ctx, &words[1..].join(" ")).await?,
        "status" => {
            let p = ctx.phone.lock().await;
            match p.mac() {
                Some(m) => println!("  Mac \"{}\" {} — state {} — boot {} — approver {}", m.name, short(&m.bogo_id.0), m.state, m.boot_seq, short(&m.approver_id.0)),
                None => println!("  no Mac"),
            }
            println!("  mailbox {}", &ctx.mailbox[..16]);
        }
        "requests" => {
            let p = ctx.phone.lock().await;
            for (i, r) in p.store.records.iter().enumerate() {
                println!(
                    "  #{:<2} {} {:<8} {}{}{}",
                    i + 1,
                    short(&r.req_id.0),
                    r.phase,
                    r.decision.clone().unwrap_or_default(),
                    r.detail.as_ref().map(|d| format!(" ({d})")).unwrap_or_default(),
                    if r.bytes.0.is_empty() { " [placeholder: notice before request]" } else { "" }
                );
            }
        }
        "approve" | "deny" | "pause" => {
            let mut p = ctx.phone.lock().await;
            let mac = p.mac().cloned().ok_or("no Mac")?;
            if mac.approval_key.0.len() != 32 {
                return Err("decide in the app: this phone bridges the app's own decisions".into());
            }
            let r = pick(&p, words.get(1))?;
            if r.phase != "pending" {
                return Err(format!("request is {}; it can't be decided", r.phase));
            }
            let msg = match words[0] {
                "approve" => {
                    let key = p256::ecdsa::SigningKey::from_slice(&mac.approval_key.0).map_err(|e| e.to_string())?;
                    let sig: p256::ecdsa::Signature = key.sign(&[b"BOGO-APPROVAL\x00v1".as_slice(), &r.bytes.0].concat());
                    PhoneMsg::Approval { req_id: r.req_id.clone(), alg: 1, sig: B(sig.to_bytes().to_vec()) }
                }
                "deny" => PhoneMsg::Denial { req_id: r.req_id.clone(), note: Some(words[2..].join(" ")).filter(|n| !n.is_empty()) },
                _ => {
                    let agent = request_agent(&r.bytes.0).ok_or("unreadable request")?;
                    PhoneMsg::Pause { agent_id: B(agent), epoch: r.pause_epoch }
                }
            };
            if let Some(rec) = p.rec(&r.req_id.0) {
                rec.phase = "sent".into();
                rec.decision = Some(msg_kind(&msg).into());
            }
            let n = p.enqueue(&msg, bogo_e2e::message_id(), None).ok_or("could not seal")?;
            p.save();
            println!("  stored decision as outbox #{n} before sending");
        }
        "sync" => {
            let mut p = ctx.phone.lock().await;
            let open: Vec<B> = p.store.records.iter().filter(|r| r.phase != "finished").map(|r| r.req_id.clone()).collect();
            let n = p.enqueue(&PhoneMsg::Sync { req_ids: open.clone() }, bogo_e2e::message_id(), None).ok_or("no Mac")?;
            p.save();
            println!("  sync for {} request(s) queued as #{n}", open.len());
        }
        "remove" => {
            let mut p = ctx.phone.lock().await;
            if let Some(m) = p.store.mac.as_mut() {
                m.state = "removed".into();
                m.approval_key = B::default();
            }
            let n = p.enqueue(&PhoneMsg::Removed {}, bogo_e2e::message_id(), None).ok_or("no Mac")?;
            p.save();
            println!("  approval key deleted; `removed` queued as #{n}");
        }
        "outbox" => {
            let p = ctx.phone.lock().await;
            for o in &p.store.outbox {
                println!("  #{:<3} {} {:<9} sent={}", o.n, short(&o.msg_id.0), o.kind, o.sent);
            }
        }
        "replay" => {
            let n: usize = words.get(1).and_then(|n| n.parse().ok()).ok_or("replay <n>")?;
            let (o, to) = {
                let p = ctx.phone.lock().await;
                (p.store.outbox.get(n - 1).cloned().ok_or("no such item")?, p.mac().ok_or("no Mac")?.mac_mailbox.clone())
            };
            let ok = send(ctx, &o, &to).await;
            println!("  replayed #{n} {} with the same message ID and bytes: relay {}", o.kind, if ok { "accepted" } else { "refused" });
        }
        "copy" => {
            let n: usize = words.get(1).and_then(|n| n.parse().ok()).ok_or("copy <n>")?;
            let mut p = ctx.phone.lock().await;
            let o = p.store.outbox.get(n - 1).cloned().ok_or("no such item")?;
            let msg: PhoneMsg = serde_json::from_str(&o.body).map_err(|e| e.to_string())?;
            let m = p.enqueue(&msg, bogo_e2e::message_id(), Some(o.body.clone())).ok_or("seal")?;
            p.save();
            println!("  #{m} is a fresh envelope (new message ID) carrying #{n}'s {} again", o.kind);
        }
        "hold" => {
            ctx.phone.lock().await.held = true;
            println!("  holding outgoing messages");
        }
        "release" => {
            let reverse = words.get(1) == Some(&"reverse");
            let pending: Vec<Out> = {
                let mut p = ctx.phone.lock().await;
                p.held = false;
                let mut v: Vec<Out> = p.store.outbox.iter().filter(|o| !o.sent).cloned().collect();
                if reverse {
                    v.reverse();
                }
                // Mark them so the flusher doesn't race this ordered send.
                for o in p.store.outbox.iter_mut().filter(|o| !o.sent) {
                    o.sent = true;
                }
                p.save();
                v
            };
            let to = ctx.phone.lock().await.mac().ok_or("no Mac")?.mac_mailbox.clone();
            for o in pending {
                let ok = send(ctx, &o, &to).await;
                println!("  → released #{} {} ({})", o.n, o.kind, if ok { "sent" } else { "FAILED" });
                if !ok {
                    let mut p = ctx.phone.lock().await;
                    if let Some(x) = p.store.outbox.iter_mut().find(|x| x.n == o.n) {
                        x.sent = false;
                    }
                    p.save();
                }
            }
        }
        other => return Err(format!("unknown command {other:?}")),
    }
    Ok(true)
}

fn request_agent(b: &[u8]) -> Option<Vec<u8>> {
    bogo_standin::request::parse(b).map(|f| f.agent_id)
}
