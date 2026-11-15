//! Byte-preserving stdio bridge. Only JSON-RPC envelope fields are inspected.
#![forbid(unsafe_code)]
use bogo_json::JVal;
use futures::StreamExt;
use rand::RngCore;
use reqwest::{Client, Response};
use std::{
    env,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    sync::{mpsc, watch},
    task::JoinSet,
};

#[derive(Default)]
struct Headers {
    mcp: Option<String>,
    version: Option<String>,
}
#[derive(Clone, Default)]
struct Handshake {
    initialize: Option<Vec<u8>>,
    initialized: Option<Vec<u8>>,
}
struct Session {
    id: String,
    headers: Mutex<Headers>,
    ended: watch::Sender<bool>,
    ready: tokio::sync::Notify,
}
fn field<'a>(v: &'a JVal, k: &str) -> Option<&'a JVal> {
    if let JVal::Obj(o) = v { o.get(k) } else { None }
}
fn text(v: &JVal) -> Option<&str> {
    if let JVal::Str(s) = v { Some(s) } else { None }
}
fn request(
    client: &Client,
    method: reqwest::Method,
    url: &str,
    token: &str,
    session: &Session,
) -> reqwest::RequestBuilder {
    let h = session.headers.lock().unwrap();
    let mut r = client
        .request(method, url)
        .bearer_auth(token)
        .header("Bogo-Session", &session.id)
        .header("Accept", "application/json, text/event-stream");
    if let Some(mcp) = &h.mcp {
        r = r.header("Mcp-Session-Id", mcp);
    }
    if let Some(version) = &h.version {
        r = r.header("MCP-Protocol-Version", version);
    }
    r
}
fn new_session() -> Arc<Session> {
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    Arc::new(Session {
        id: id.iter().map(|b| format!("{b:02x}")).collect(),
        headers: Mutex::new(Headers::default()),
        ended: watch::channel(false).0,
        ready: tokio::sync::Notify::new(),
    })
}
fn error(id: &JVal) -> Vec<u8> {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{},\"error\":{{\"code\":-32000,\"message\":\"BOGO is unreachable; the call was not retried.\"}}}}", id.write()).into_bytes()
}
async fn emit(
    bytes: Vec<u8>,
    session: &Session,
    initialize: bool,
    out: &mpsc::Sender<Vec<u8>>,
) -> Result<(), String> {
    let value = bogo_json::parse(&bytes).map_err(|e| e.to_string())?;
    if initialize
        && let Some(version) = field(&value, "result")
            .and_then(|v| field(v, "protocolVersion"))
            .and_then(text)
    {
        session.headers.lock().unwrap().version = Some(version.into());
    }
    if initialize && session.headers.lock().unwrap().mcp.is_some() {
        session.ready.notify_one();
    }
    // SSE payloads can contain line breaks. Stdio is one line per message: JSON permits
    // insignificant whitespace outside strings only. Do not re-encode the payload.
    let line = bytes
        .into_iter()
        .filter(|b| *b != b'\n' && *b != b'\r')
        .collect();
    out.send(line).await.map_err(|_| "stdout closed".into())
}
async fn response(
    response: Response,
    session: &Session,
    initialize: bool,
    out: &mpsc::Sender<Vec<u8>>,
) -> Result<(), String> {
    if !response.status().is_success() {
        return Err(format!("BOGO returned HTTP {}", response.status()));
    }
    if let Some(mcp) = response
        .headers()
        .get("mcp-session-id")
        .and_then(|h| h.to_str().ok())
    {
        session.headers.lock().unwrap().mcp = Some(mcp.into());
    }
    if response.status() == reqwest::StatusCode::ACCEPTED {
        return Ok(());
    }
    if response
        .headers()
        .get("content-type")
        .is_some_and(|v| v.as_bytes().starts_with(b"text/event-stream"))
    {
        let mut events = sse_stream::SseStream::from_bytes_stream(response.bytes_stream());
        while let Some(event) = events.next().await {
            if let Some(data) = event.map_err(|e| e.to_string())?.data {
                emit(data.into_bytes(), session, initialize, out).await?;
            }
        }
        Ok(())
    } else {
        emit(
            response.bytes().await.map_err(|e| e.to_string())?.to_vec(),
            session,
            initialize,
            out,
        )
        .await
    }
}
// Only the original lifecycle messages may be replayed, into a fresh BOGO session.
// No tool call or pending approval is retained across connections.
async fn restore_handshake(
    client: &Client,
    url: &str,
    token: &str,
    session: &Session,
    handshake: Handshake,
) -> Result<(), String> {
    let Some(initialize) = handshake.initialize else {
        return Ok(());
    };
    let (out, mut received) = mpsc::channel(4);
    let reply = request(client, reqwest::Method::POST, url, token, session)
        .header("Content-Type", "application/json")
        .body(initialize)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    // Capture the new MCP headers, but never emit a duplicate initialize response to stdio.
    response(reply, session, true, &out).await?;
    let reply = received
        .try_recv()
        .map_err(|_| "Missing replacement initialize response")?;
    let reply = bogo_json::parse(&reply).map_err(|e| e.to_string())?;
    if field(&reply, "result").is_none() || session.headers.lock().unwrap().version.is_none() {
        return Err("Replacement MCP initialize failed".into());
    }
    if let Some(initialized) = handshake.initialized {
        let reply = request(client, reqwest::Method::POST, url, token, session)
            .header("Content-Type", "application/json")
            .body(initialized)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !reply.status().is_success() {
            return Err(format!(
                "Replacement MCP initialized returned HTTP {}",
                reply.status()
            ));
        }
    }
    Ok(())
}

async fn run() -> Result<(), String> {
    let url = env::var("BOGO_URL").map_err(|_| "BOGO_URL is required")?;
    let url = url.trim_end_matches('/').to_owned();
    let token = env::var("BOGO_AGENT_TOKEN").map_err(|_| "BOGO_AGENT_TOKEN is required")?;
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| e.to_string())?;
    let (live, mut state) = watch::channel::<Option<Arc<Session>>>(None);
    let (out, mut rx) = mpsc::channel::<Vec<u8>>(64);
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(bytes) = rx.recv().await {
            stdout.write_all(&bytes).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
        Ok::<_, std::io::Error>(())
    });
    let handshake = Arc::new(Mutex::new(Handshake::default()));
    // Calls arriving while a replacement connects must wait for its handshake, rather
    // than observing the gap between its liveness stream and MCP session becoming ready.
    let connecting = Arc::new(tokio::sync::Mutex::new(()));
    let liveness = {
        let handshake = handshake.clone();
        let connecting = connecting.clone();
        let (client, token, url, out) = (client.clone(), token.clone(), url.clone(), out.clone());
        tokio::spawn(async move {
            loop {
                let mut connection = Some(connecting.lock().await);
                let session = new_session();
                match request(
                    &client,
                    reqwest::Method::GET,
                    &format!("{url}/bogo-liveness"),
                    &token,
                    &session,
                )
                .send()
                .await
                {
                    Ok(r) if r.status().is_success() => {
                        let saved = handshake.lock().unwrap().clone();
                        if let Err(e) =
                            restore_handshake(&client, &url, &token, &session, saved).await
                        {
                            eprintln!("bogo-shim: reconnect handshake: {e}");
                            session.ended.send_replace(true);
                            live.send_replace(None);
                            drop(connection.take());
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            continue;
                        }
                        live.send_replace(Some(session.clone()));
                        drop(connection.take());
                        // Legacy server-to-client tool-list notifications use the MCP GET
                        // stream, independently of the BOGO liveness stream.
                        let notifications = {
                            let (client, token, url, session, out) = (
                                client.clone(),
                                token.clone(),
                                url.clone(),
                                session.clone(),
                                out.clone(),
                            );
                            tokio::spawn(async move {
                                session.ready.notified().await;
                                match request(&client, reqwest::Method::GET, &url, &token, &session)
                                    .send()
                                    .await
                                {
                                    Ok(r) => {
                                        if let Err(e) = response(r, &session, false, &out).await {
                                            eprintln!("bogo-shim: notification stream: {e}");
                                        }
                                    }
                                    Err(e) => eprintln!("bogo-shim: notification stream: {e}"),
                                }
                            })
                        };
                        let mut stream = r.bytes_stream();
                        while let Some(chunk) = stream.next().await {
                            if chunk.is_err() {
                                break;
                            }
                        }
                        session.ended.send_replace(true);
                        notifications.abort();
                    }
                    Ok(r) => eprintln!("bogo-shim: liveness HTTP {}", r.status()),
                    Err(e) => eprintln!("bogo-shim: liveness: {e}"),
                }
                live.send_replace(None);
                drop(connection.take());
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
    };
    // Let the first connection attempt establish the session before reading initialize.
    state.changed().await.map_err(|e| e.to_string())?;
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut jobs = JoinSet::new();
    loop {
        let mut line = Vec::new();
        // A bounded frame prevents a peer from growing the shim without limit.
        let read = (&mut stdin).take(bogo_json::Limits::default().max_bytes as u64 + 1);
        let mut read = read;
        let count = read
            .read_until(b'\n', &mut line)
            .await
            .map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        if line.len() > bogo_json::Limits::default().max_bytes {
            return Err("stdio message exceeds the size limit".into());
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        let value = bogo_json::parse(&line).map_err(|e| e.to_string())?;
        let id = field(&value, "id").cloned();
        let method = field(&value, "method").and_then(text);
        let initialize = method == Some("initialize");
        if initialize {
            let mut saved = handshake.lock().unwrap();
            saved.initialize = Some(line.clone());
            saved.initialized = None;
        } else if method == Some("notifications/initialized") {
            handshake.lock().unwrap().initialized = Some(line.clone());
        }
        let session = {
            let _connection = connecting.lock().await;
            state.borrow().clone()
        };
        let (client, token, url, out) = (client.clone(), token.clone(), url.clone(), out.clone());
        jobs.spawn(async move {
            let result = if let Some(session) = session {
                let mut ended = session.ended.subscribe();
                if *ended.borrow() { Err("BOGO session ended".into()) }
                else { tokio::select! {
                    biased;
                    _ = ended.changed() => Err("BOGO session ended".into()),
                    result = async {
                        let r = request(&client, reqwest::Method::POST, &url, &token, &session).header("Content-Type", "application/json").body(line).send().await.map_err(|e| e.to_string())?;
                        response(r, &session, initialize, &out).await
                    } => result,
                } }
            } else { Err("BOGO is unreachable".into()) };
            if let Err(e) = result { eprintln!("bogo-shim: {e}"); if let Some(id) = id { let _ = out.send(error(&id)).await; } }
        });
        while jobs.try_join_next().is_some() {}
    }
    // DELETE is best effort; dropping liveness is the authoritative crash-safe close.
    let session = state.borrow().clone();
    if let Some(session) = session {
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            request(&client, reqwest::Method::DELETE, &url, &token, &session).send(),
        )
        .await;
    }
    liveness.abort();
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    drop(out);
    writer
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("bogo-shim: {e}");
        std::process::exit(1);
    }
}
