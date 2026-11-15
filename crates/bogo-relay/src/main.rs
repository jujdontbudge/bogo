//! Standalone ciphertext mailbox. No daemon, E2E or APNs dependencies.
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
};
use bogo_relay_proto::*;
use clap::Parser;
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8843")]
    listen: std::net::SocketAddr,
    #[arg(long)]
    database: PathBuf,
    #[arg(long)]
    cert: PathBuf,
    #[arg(long)]
    key: PathBuf,
    /// Public identity bound into every mailbox challenge (normally host:port).
    #[arg(long)]
    service: String,
    /// Explicit retention; never interpreted as approval expiry.
    #[arg(long)]
    max_message_age: u64,
    #[arg(long, default_value_t = 1000)]
    mailbox_capacity: u64,
}
struct Lobby {
    offer: Offer,
    owner: String,
    peer: Option<String>,
    created: Instant,
    refreshed: Instant,
    messages: Vec<LobbyMessage>,
}
struct Memory {
    challenges: HashMap<String, (String, Instant)>,
    sessions: HashMap<String, (String, Instant)>,
    lobby: HashMap<String, Lobby>,
}
struct App {
    db: Mutex<Connection>,
    memory: Mutex<Memory>,
    service: String,
    max_age: u64,
    capacity: u64,
    changed: watch::Sender<u64>,
}
type Shared = Arc<App>;
type Failure = StatusCode;
type Result<T> = std::result::Result<T, Failure>;
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn internal<T>(r: rusqlite::Result<T>) -> Result<T> {
    r.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
fn owner(app: &App, headers: &HeaderMap) -> Result<String> {
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let mut m = app
        .memory
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    m.sessions.retain(|_, (_, until)| *until > Instant::now());
    m.sessions
        .get(token)
        .map(|(id, _)| id.clone())
        .ok_or(StatusCode::UNAUTHORIZED)
}
fn valid_ids(ids: &[String]) -> bool {
    ids.len() <= 1000 && ids.iter().all(|s| valid_hex(s, 16))
}
fn prune(m: &mut Memory) {
    let now = Instant::now();
    m.lobby
        .retain(|_, l| now.duration_since(l.refreshed) < Duration::from_secs(120));
}

async fn challenge(
    State(app): State<Shared>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<Challenge>> {
    if !valid_hex(&req.r#pub, 32) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut m = app
        .memory
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let now = Instant::now();
    m.challenges.retain(|_, (_, until)| *until > now);
    if m.challenges.len() >= 4096 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let challenge = random_hex();
    m.challenges.insert(
        req.r#pub,
        (challenge.clone(), now + Duration::from_secs(60)),
    );
    Ok(Json(Challenge { challenge }))
}
async fn verify(State(app): State<Shared>, Json(req): Json<VerifyRequest>) -> Result<Json<Token>> {
    let mut m = app
        .memory
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Remove before verifying: even a bad signature consumes the challenge.
    let (challenge, until) = m
        .challenges
        .remove(&req.r#pub)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if Instant::now() >= until {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let id = verify_auth(&app.service, &req.r#pub, &challenge, &req.sig)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    m.sessions.retain(|_, (_, until)| *until > Instant::now());
    if m.sessions.len() >= 4096 {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let token = random_hex();
    m.sessions.insert(
        token.clone(),
        (id, Instant::now() + Duration::from_secs(3600)),
    );
    Ok(Json(Token { token }))
}
async fn allow(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<Allow>,
) -> Result<StatusCode> {
    let id = owner(&app, &headers)?;
    if req.senders.len() > 1000 || !req.senders.iter().all(|s| valid_hex(s, 32)) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut db = app
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let tx = internal(db.transaction())?;
    internal(tx.execute("DELETE FROM allowlist WHERE recipient=?", [&id]))?;
    for sender in req.senders {
        internal(tx.execute(
            "INSERT OR IGNORE INTO allowlist VALUES (?,?)",
            params![id, sender],
        ))?;
    }
    internal(tx.commit())?;
    Ok(StatusCode::OK)
}
async fn send(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<Send>,
) -> Result<StatusCode> {
    let id = owner(&app, &headers)?;
    if !valid_hex(&req.to, 32)
        || !valid_hex(&req.msg_id, 16)
        || req.body.len() < 166
        || req.body.len() > 2 * (1024 * 1024 + 83)
        || !valid_hex(&req.body, req.body.len() / 2)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let body = hex::decode(&req.body).map_err(|_| StatusCode::BAD_REQUEST)?;
    // Only validate outer framing. Never open, decode, or log application data.
    if &body[..8] != b"BOGOE2E\0"
        || body[8] != 1
        || hex::encode(&body[11..27]) != req.msg_id
        || body[27..31] != 32u32.to_be_bytes()
        || u32::from_be_bytes(body[63..67].try_into().unwrap()) as usize != body.len() - 67
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut db = app
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let tx = internal(db.transaction())?;
    let allowed: bool = internal(tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM allowlist WHERE recipient=? AND sender=?)",
        params![req.to, id],
        |r| r.get(0),
    ))?;
    if !allowed {
        return Err(StatusCode::FORBIDDEN);
    }
    internal(tx.execute(
        "DELETE FROM messages WHERE created < ?",
        [now().saturating_sub(app.max_age as i64)],
    ))?;
    let existing: Option<(String, Vec<u8>)> = internal(
        tx.query_row(
            "SELECT sender,body FROM messages WHERE recipient=? AND msg_id=?",
            params![req.to, req.msg_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional(),
    )?;
    if let Some((sender, stored)) = existing {
        return if sender == id && stored == body {
            Ok(StatusCode::OK)
        } else {
            Err(StatusCode::CONFLICT)
        };
    }
    let count: u64 = internal(tx.query_row(
        "SELECT COUNT(*) FROM messages WHERE recipient=?",
        [&req.to],
        |r| r.get(0),
    ))?;
    if count >= app.capacity {
        return Err(StatusCode::CONFLICT);
    }
    internal(tx.execute(
        "INSERT INTO messages VALUES (?,?,?,?,?)",
        params![req.to, req.msg_id, id, body, now()],
    ))?;
    internal(tx.commit())?;
    app.changed.send_modify(|n| *n = n.wrapping_add(1));
    Ok(StatusCode::OK)
}
fn read_messages(app: &App, id: &str) -> Result<Vec<Message>> {
    let db = app
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    internal(db.execute(
        "DELETE FROM messages WHERE created < ?",
        [now().saturating_sub(app.max_age as i64)],
    ))?;
    let mut stmt = internal(db.prepare(
        "SELECT msg_id,sender,body FROM messages WHERE recipient=? ORDER BY created,rowid LIMIT 32",
    ))?;
    let rows = internal(stmt.query_map([id], |r| {
        Ok(Message {
            msg_id: r.get(0)?,
            from: r.get(1)?,
            body: hex::encode(r.get::<_, Vec<u8>>(2)?),
        })
    }))?;
    internal(rows.collect())
}
async fn fetch(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<Fetch>,
) -> Result<Json<Vec<Message>>> {
    let id = owner(&app, &headers)?;
    let mut change = app.changed.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    loop {
        change.borrow_and_update();
        let messages = read_messages(&app, &id)?;
        if !messages.is_empty() || !req.wait {
            return Ok(Json(messages));
        }
        if tokio::time::timeout_at(deadline, change.changed())
            .await
            .is_err()
        {
            return Ok(Json(Vec::new()));
        }
    }
}
async fn ack(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<Ack>,
) -> Result<StatusCode> {
    let id = owner(&app, &headers)?;
    if !valid_ids(&req.msg_ids) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut db = app
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let tx = internal(db.transaction())?;
    for msg in req.msg_ids {
        internal(tx.execute(
            "DELETE FROM messages WHERE recipient=? AND msg_id=?",
            params![id, msg],
        ))?;
    }
    internal(tx.commit())?;
    Ok(StatusCode::OK)
}
async fn retract(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<Retract>,
) -> Result<StatusCode> {
    let id = owner(&app, &headers)?;
    if !valid_hex(&req.to, 32) || !valid_ids(&req.msg_ids) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut db = app
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let tx = internal(db.transaction())?;
    for msg in req.msg_ids {
        internal(tx.execute(
            "DELETE FROM messages WHERE recipient=? AND sender=? AND msg_id=?",
            params![req.to, id, msg],
        ))?;
    }
    internal(tx.commit())?;
    Ok(StatusCode::OK)
}
async fn offer(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<Offer>,
) -> Result<StatusCode> {
    let id = owner(&app, &headers)?;
    if !valid_hex(&req.offer_id, 16)
        || !valid_hex(&req.e_pub_m, 32)
        || req.mac_label.is_empty()
        || req.mac_label.len() > 128
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut m = app
        .memory
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    prune(&mut m);
    if let Some(l) = m.lobby.get_mut(&req.offer_id) {
        if l.owner != id {
            return Err(StatusCode::FORBIDDEN);
        }
        if l.offer.e_pub_m != req.e_pub_m || l.offer.mac_label != req.mac_label {
            return Err(StatusCode::CONFLICT);
        }
        l.refreshed = Instant::now();
    } else {
        if m.lobby.len() >= 256 {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        m.lobby.insert(
            req.offer_id.clone(),
            Lobby {
                offer: req,
                owner: id,
                peer: None,
                created: Instant::now(),
                refreshed: Instant::now(),
                messages: Vec::new(),
            },
        );
    }
    Ok(StatusCode::OK)
}
async fn offers(State(app): State<Shared>, headers: HeaderMap) -> Result<Json<Vec<ListedOffer>>> {
    owner(&app, &headers)?;
    let mut m = app
        .memory
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    prune(&mut m);
    Ok(Json(
        m.lobby
            .values()
            .filter(|l| l.peer.is_none())
            .map(|l| ListedOffer {
                offer: l.offer.clone(),
                age_seconds: l.created.elapsed().as_secs(),
            })
            .collect(),
    ))
}
async fn lobby_send(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(offer_id): Path<String>,
    Json(req): Json<LobbySend>,
) -> Result<StatusCode> {
    let id = owner(&app, &headers)?;
    if !valid_hex(&req.msg_id, 16)
        || req.body.len() > 128 * 1024
        || !valid_hex(&req.body, req.body.len() / 2)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut m = app
        .memory
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    prune(&mut m);
    let l = m.lobby.get_mut(&offer_id).ok_or(StatusCode::NOT_FOUND)?;
    if l.owner != id {
        if l.peer.as_ref().is_some_and(|p| p != &id) {
            return Err(StatusCode::FORBIDDEN);
        }
        if l.peer.is_none() {
            l.peer = Some(id.clone());
        }
    }
    if let Some(old) = l.messages.iter().find(|m| m.msg_id == req.msg_id) {
        return if old.from == id && old.body == req.body {
            Ok(StatusCode::OK)
        } else {
            Err(StatusCode::CONFLICT)
        };
    }
    if l.messages.len() >= 64 {
        return Err(StatusCode::CONFLICT);
    }
    l.messages.push(LobbyMessage {
        msg_id: req.msg_id,
        from: id,
        body: req.body,
    });
    Ok(StatusCode::OK)
}
async fn lobby_fetch(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(offer_id): Path<String>,
) -> Result<Json<Vec<LobbyMessage>>> {
    let id = owner(&app, &headers)?;
    let mut m = app
        .memory
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    prune(&mut m);
    let l = m.lobby.get(&offer_id).ok_or(StatusCode::NOT_FOUND)?;
    if id != l.owner && l.peer.as_ref() != Some(&id) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Json(
        l.messages
            .iter()
            .filter(|m| m.from != id)
            .cloned()
            .collect(),
    ))
}
async fn delete_offer(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(offer_id): Path<String>,
) -> Result<StatusCode> {
    let id = owner(&app, &headers)?;
    let mut m = app
        .memory
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    prune(&mut m);
    let l = m.lobby.get(&offer_id).ok_or(StatusCode::NOT_FOUND)?;
    if id != l.owner {
        return Err(StatusCode::FORBIDDEN);
    }
    m.lobby.remove(&offer_id);
    Ok(StatusCode::OK)
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("bogo-relay: startup or service failed");
        std::process::exit(1)
    }
}
async fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.service.is_empty()
        || args.max_message_age == 0
        || args.max_message_age > i64::MAX as u64
        || args.mailbox_capacity == 0
    {
        return Err("invalid limits".into());
    }
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "TLS provider")?;
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&args.cert, &args.key).await?;
    // SIGHUP atomically reloads the configured cert/key after an external renew hook.
    #[cfg(unix)]
    {
        let tls = tls.clone();
        let cert = args.cert.clone();
        let key = args.key.clone();
        tokio::spawn(async move {
            let Ok(mut signal) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            else {
                return;
            };
            while signal.recv().await.is_some() {
                if tls.reload_from_pem_file(&cert, &key).await.is_err() {
                    eprintln!("bogo-relay: certificate reload failed");
                }
            }
        });
    }
    let db = Connection::open(&args.database)?;
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS allowlist(recipient TEXT NOT NULL,sender TEXT NOT NULL,PRIMARY KEY(recipient,sender));
        CREATE TABLE IF NOT EXISTS messages(recipient TEXT NOT NULL,msg_id TEXT NOT NULL,sender TEXT NOT NULL,body BLOB NOT NULL,created INTEGER NOT NULL,PRIMARY KEY(recipient,msg_id));")?;
    let app = Arc::new(App {
        db: Mutex::new(db),
        memory: Mutex::new(Memory {
            challenges: HashMap::new(),
            sessions: HashMap::new(),
            lobby: HashMap::new(),
        }),
        service: args.service,
        max_age: args.max_message_age,
        capacity: args.mailbox_capacity,
        changed: watch::channel(0).0,
    });
    let router = Router::new()
        .route("/v1/auth/challenge", post(challenge))
        .route("/v1/auth/verify", post(verify))
        .route("/v1/allow", post(allow))
        .route("/v1/send", post(send))
        .route("/v1/fetch", post(fetch))
        .route("/v1/ack", post(ack))
        .route("/v1/retract", post(retract))
        .route("/v1/lobby/offer", post(offer))
        .route("/v1/lobby", get(offers))
        .route("/v1/lobby/{id}/msg", post(lobby_send))
        .route("/v1/lobby/{id}/fetch", post(lobby_fetch))
        .route("/v1/lobby/{id}", delete(delete_offer))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024 + 4096))
        .with_state(app);
    println!("bogo-relay listening with TLS on {}", args.listen);
    axum_server::bind_rustls(args.listen, tls)
        .serve(router.into_make_service())
        .await?;
    Ok(())
}
