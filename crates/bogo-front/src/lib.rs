//! Authenticated MCP edge. The effects shell implements [`Backend`]; only the linked core
//! may authorize a call. Neither rmcp's argument tree nor agent metadata enters the core.
#![forbid(unsafe_code)]

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use bogo_core::{Input, Rejection};
use bogo_json::JVal;
use futures::{StreamExt, future::BoxFuture};
use rand::RngCore;
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::*,
    service::{Peer, RequestContext},
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

pub const ENDED: &str = "Approval was not received in time; the action was not performed.";
pub const PENDING: &str = "Pending owner approval. Retry this exact call (same arguments and justification) in this session to run it once approved.";
pub const SESSION_REQUIRED: &str =
    "This tool needs a session-based MCP connection (protocol 2025-11-25) or the BOGO stdio shim.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Agent {
    pub id: Vec<u8>,
}

/// A prepared, per-agent catalog view supplied by the shell (schema widening and output
/// schema filtering belong to the catalog producer). Denied entries are already hidden.
#[derive(Clone)]
pub struct CatalogTool {
    pub tool: Tool,
    pub mode: bogo_core::Mode,
}

/// The full POST is retained for audit/debugging; `input` contains the strict lexical
/// argument tree. Object keys are sorted by bogo-json; number tokens remain untouched.
#[derive(Clone)]
pub struct Invocation {
    pub input: Input,
    pub body: Bytes,
    pub session_capable: bool,
}

/// Daemon boundary. All events must reach the effects shell in order and all returned
/// results must have passed its durability barrier. `invoke` must submit `input` to the
/// core, resolve Attach/Ask/Authorized there, and use the gated upstream transport.
/// Dropping its future must not spawn an untracked execution.
pub trait Backend: Send + Sync + 'static {
    /// Look up SHA-256(token) among non-revoked agents. Never log tokens.
    fn authenticate(&self, token_hash: &[u8; 32]) -> Option<Agent>;
    fn available(&self, agent: &Agent) -> Result<(), String>;
    fn catalog(&self, agent: &Agent) -> Result<Vec<CatalogTool>, String>;
    /// Synchronously enqueue a lifecycle event; return only after it is accepted.
    fn event(&self, input: Input) -> Result<(), String>;
    fn now_ms(&self) -> u64;
    /// Submit the Call synchronously before returning the future, in lifecycle order.
    fn invoke(&self, call: Invocation) -> BoxFuture<'_, Outcome>;
}

pub enum Outcome {
    Result(CallToolResult),
    Rejected(Rejection),
    Pending,
    NotSent,
    Unknown,
    Error(String),
}
impl Outcome {
    pub fn into_result(self) -> CallToolResult {
        let message = match self {
            Self::Result(r) => return r,
            Self::Rejected(Rejection::Denied(note)) => format!("The owner denied this action.{}", note.map(|n| format!(" {n}")).unwrap_or_default()),
            Self::Rejected(Rejection::EndedWithoutDecision) => ENDED.into(),
            Self::Pending => PENDING.into(),
            Self::NotSent | Self::Rejected(Rejection::UpstreamUnavailable) => "The upstream was unavailable; the action was not performed.".into(),
            Self::Unknown => "The upstream connection failed after the call was sent; the action may or may not have happened. BOGO will not retry it.".into(),
            Self::Rejected(why) => match why {
                Rejection::DenyPolicy => "This tool is denied by policy.",
                Rejection::PausedAgent => "This agent is paused.",
                Rejection::RevokedAgent => "This agent is revoked.",
                Rejection::JustificationRequired => "A justification is required for this tool.",
                Rejection::UnknownTool => "Unknown tool.",
                Rejection::Exhausted => "The pending request limit was reached.",
                _ => "BOGO rejected the call; the action was not performed.",
            }.into(),
            Self::Error(s) => s,
        };
        CallToolResult::error(vec![ContentBlock::text(message)])
    }
}

fn random() -> [u8; 16] {
    let mut b = [0; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b
}
fn header(req: &Request, key: &str) -> Option<String> {
    req.headers().get(key)?.to_str().ok().map(str::to_owned)
}
fn field<'a>(value: &'a JVal, key: &str) -> Option<&'a JVal> {
    if let JVal::Obj(o) = value {
        o.get(key)
    } else {
        None
    }
}
fn string(value: &JVal) -> Option<&str> {
    if let JVal::Str(s) = value {
        Some(s)
    } else {
        None
    }
}

struct Session {
    id: Vec<u8>,
    agent: Agent,
    calls: HashMap<String, Arc<Call>>,
    peer: Option<Peer<RoleServer>>,
    alive: CancellationToken,
}
struct Call {
    id: Vec<u8>,
    cancel: CancellationToken,
}
struct Inner {
    backend: Arc<dyn Backend>,
    boot: Vec<u8>,
    sessions: Mutex<HashMap<String, Session>>,
    stop: CancellationToken,
    hosts: Vec<std::net::Ipv4Addr>,
}
#[derive(Clone)]
pub struct Front(Arc<Inner>);

impl Front {
    pub fn new(backend: Arc<dyn Backend>, boot_id: Vec<u8>) -> Self {
        Self::with_hosts(backend, boot_id, Vec::new())
    }
    /// Also accepts these IPv4 literals in `Host` (e.g. the sandbox gate's address).
    pub fn with_hosts(
        backend: Arc<dyn Backend>,
        boot_id: Vec<u8>,
        hosts: Vec<std::net::Ipv4Addr>,
    ) -> Self {
        Self(Arc::new(Inner {
            backend,
            boot: boot_id,
            sessions: Mutex::new(HashMap::new()),
            stop: CancellationToken::new(),
            hosts,
        }))
    }
    /// Mount only on a loopback listener. Host/Origin checks also protect the liveness route.
    pub fn router(&self) -> Router {
        let mut manager = LocalSessionManager::default();
        manager.session_config.keep_alive = None;
        manager.session_config.sse_retry = None;
        let mut config = StreamableHttpServerConfig::default().enforce_origin_validation();
        config.legacy_session_mode = true;
        config.sse_retry = None;
        config.cancellation_token = self.0.stop.clone();
        let handler = Handler(self.clone());
        let service =
            StreamableHttpService::new(move || Ok(handler.clone()), Arc::new(manager), config);
        Router::new()
            .route("/mcp/bogo-liveness", get(liveness))
            .with_state(self.clone())
            .nest_service("/mcp", service)
            .layer(middleware::from_fn_with_state(self.clone(), edge))
    }
    fn open(
        &self,
        key: &str,
        agent: &Agent,
        client: Option<String>,
        new_only: bool,
    ) -> Result<Vec<u8>, String> {
        let mut sessions = self.0.sessions.lock().unwrap();
        if let Some(s) = sessions.get(key) {
            return if s.agent == *agent && !new_only {
                Ok(s.id.clone())
            } else {
                Err("Session belongs to another agent.".into())
            };
        }
        let mut id = self.0.boot.clone();
        id.extend(random());
        self.0.backend.event(Input::SessionOpened {
            session: id.clone(),
            agent: agent.id.clone(),
            client,
        })?;
        sessions.insert(
            key.into(),
            Session {
                id: id.clone(),
                agent: agent.clone(),
                calls: HashMap::new(),
                peer: None,
                alive: CancellationToken::new(),
            },
        );
        Ok(id)
    }
    fn close(&self, key: &str) {
        self.close_generation(key, None);
    }
    fn close_generation(&self, key: &str, expected: Option<&[u8]>) {
        let mut sessions = self.0.sessions.lock().unwrap();
        if expected.is_some_and(|id| !sessions.get(key).is_some_and(|s| s.id == id)) {
            return;
        }
        if let Some(s) = sessions.remove(key) {
            // Revoke core liveness before waking waiters.
            let _ = self.0.backend.event(Input::SessionClosed { session: s.id });
            s.alive.cancel();
            for call in s.calls.values() {
                call.cancel.cancel();
            }
        }
    }
    /// Call immediately when the registry revokes an agent.
    pub fn revoke(&self, agent: &Agent) {
        let keys: Vec<_> = self
            .0
            .sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, s)| s.agent == *agent)
            .map(|(k, _)| k.clone())
            .collect();
        for key in keys {
            self.close(&key);
        }
    }
    pub fn shutdown(&self) {
        self.0.stop.cancel();
        let keys: Vec<_> = self.0.sessions.lock().unwrap().keys().cloned().collect();
        for key in keys {
            self.close(&key);
        }
    }
    pub async fn catalog_changed(&self) {
        let peers: Vec<_> = self
            .0
            .sessions
            .lock()
            .unwrap()
            .values()
            .filter_map(|s| s.peer.clone())
            .collect();
        for peer in peers {
            let _ = peer.notify_tool_list_changed().await;
        }
    }
}

#[derive(Clone)]
struct Exact {
    agent: Agent,
    session: Vec<u8>,
    key: String,
    name: String,
    args: Option<JVal>,
    body: Bytes,
    rpc_id: String,
    call: Arc<Call>,
    capable: bool,
}
#[derive(Clone)]
struct Identity(Agent, Option<String>);

/// Owns the response stream, and also exists while rmcp is producing its response.
struct Guard {
    front: Front,
    key: String,
    rpc_id: Option<String>,
    call: Option<Arc<Call>>,
    ephemeral: bool,
    session_id: Vec<u8>,
    finished: bool,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(call) = &self.call {
            let mut sessions = self.front.0.sessions.lock().unwrap();
            if !self.finished {
                let _ = self.front.0.backend.event(Input::CallEnded {
                    call: call.id.clone(),
                });
                call.cancel.cancel();
            }
            if let Some(session) = sessions.get_mut(&self.key) {
                session.calls.remove(self.rpc_id.as_ref().unwrap());
            }
        }
        if self.ephemeral {
            self.front
                .close_generation(&self.key, Some(&self.session_id));
        }
    }
}

async fn edge(State(front): State<Front>, mut req: Request, next: Next) -> Response {
    let token =
        header(&req, "authorization").and_then(|s| s.strip_prefix("Bearer ").map(str::to_owned));
    let Some(agent) = token.and_then(|s| {
        front
            .0
            .backend
            .authenticate(&Sha256::digest(s.as_bytes()).into())
    }) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // This applies to all routes, including the stream that does not enter rmcp.
    let host = header(&req, "host").unwrap_or_default();
    let hostname = host.split(':').next().unwrap_or("");
    let listed = hostname
        .parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| front.0.hosts.contains(&ip));
    if !(matches!(hostname, "localhost" | "127.0.0.1") || listed)
        || req.headers().contains_key("origin")
        || req.headers().contains_key("last-event-id")
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Err(reason) = front.0.backend.available(&agent) {
        front.revoke(&agent);
        if req.method() == Method::POST {
            let Ok(bytes) = to_bytes(req.into_body(), bogo_json::Limits::default().max_bytes).await
            else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let Ok(value @ JVal::Obj(_)) = bogo_json::parse(&bytes) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let id = field(&value, "id")
                .map(JVal::write)
                .unwrap_or_else(|| "null".into());
            let reason = serde_json::to_string(&reason).expect("string encoding");
            return ([("content-type", "application/json")], format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":-32000,\"message\":{reason}}}}}")).into_response();
        }
        return (StatusCode::FORBIDDEN, reason).into_response();
    }
    let shim = header(&req, "bogo-session");
    if shim
        .as_ref()
        .is_some_and(|s| s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let mut key = shim
        .as_ref()
        .map(|s| format!("shim:{s}"))
        .or_else(|| header(&req, "mcp-session-id").map(|s| format!("mcp:{s}")));
    if let Some(key) = &key {
        let matches = front
            .0
            .sessions
            .lock()
            .unwrap()
            .get(key)
            .map(|s| s.agent == agent);
        if matches == Some(false) {
            front.close(key);
            return StatusCode::FORBIDDEN.into_response();
        }
        if matches.is_none() && (shim.is_some() && req.uri().path() != "/mcp/bogo-liveness") {
            return StatusCode::NOT_FOUND.into_response();
        }
        if matches.is_none() && shim.is_none() {
            return StatusCode::NOT_FOUND.into_response();
        }
    }
    req.extensions_mut()
        .insert(Identity(agent.clone(), key.clone()));
    if req.method() == Method::DELETE && shim.is_some() {
        front.close(key.as_ref().unwrap());
        return StatusCode::ACCEPTED.into_response();
    }
    let mut guard = None;
    let mut initialize_client = None;
    if req.method() == Method::POST {
        let (mut parts, body) = req.into_parts();
        let Ok(bytes) = to_bytes(body, bogo_json::Limits::default().max_bytes).await else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        let Ok(value @ JVal::Obj(_)) = bogo_json::parse(&bytes) else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        let method = field(&value, "method").and_then(string);
        let version = field(&value, "params")
            .and_then(|p| field(p, "_meta"))
            .and_then(|m| field(m, "io.modelcontextprotocol/protocolVersion"))
            .and_then(string)
            .map(str::to_owned)
            .or_else(|| {
                parts
                    .headers
                    .get("mcp-protocol-version")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
            });
        if shim.is_none() && version.as_deref().is_some_and(|v| v >= "2026-07-28") {
            key = None;
            parts.extensions.insert(Identity(agent.clone(), None));
        }
        // A stdio message has no HTTP routing headers. Derive those here, where the
        // strict body is already available; the shim still reads no params.
        if shim.is_some() {
            if let Some(version) = &version
                && !parts.headers.contains_key("mcp-protocol-version")
            {
                let Ok(v) = version.parse() else {
                    return StatusCode::BAD_REQUEST.into_response();
                };
                parts.headers.insert("mcp-protocol-version", v);
            }
            if let Some(method) = method
                && !parts.headers.contains_key("mcp-method")
            {
                let Ok(v) = method.parse() else {
                    return StatusCode::BAD_REQUEST.into_response();
                };
                parts.headers.insert("mcp-method", v);
            }
            if let Some(name) = field(&value, "params")
                .and_then(|p| field(p, "name"))
                .and_then(string)
                && !parts.headers.contains_key("mcp-name")
            {
                let Ok(v) = name.parse() else {
                    return StatusCode::BAD_REQUEST.into_response();
                };
                parts.headers.insert("mcp-name", v);
            }
        }
        if method == Some("initialize") {
            initialize_client = field(&value, "params")
                .and_then(|p| field(p, "clientInfo"))
                .and_then(|p| field(p, "name"))
                .and_then(string)
                .map(str::to_owned);
        }
        if method == Some("notifications/cancelled")
            && let (Some(key), Some(id)) = (
                &key,
                field(&value, "params").and_then(|p| field(p, "requestId")),
            )
            && let Some(call) = front
                .0
                .sessions
                .lock()
                .unwrap()
                .get(key)
                .and_then(|s| s.calls.get(&id.write()))
                .cloned()
        {
            let _ = front.0.backend.event(Input::CallEnded {
                call: call.id.clone(),
            });
            call.cancel.cancel();
        }
        if method == Some("tools/call") {
            let Some(id @ (JVal::Str(_) | JVal::Num(_))) = field(&value, "id") else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let Some(params) = field(&value, "params") else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let Some(name) = field(params, "name").and_then(string) else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            // Compare the exact envelope against the SDK decoder, including number IDs.
            let Ok(ClientJsonRpcMessage::Request(decoded)) =
                serde_json::from_slice::<ClientJsonRpcMessage>(&bytes)
            else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            let ClientRequest::CallToolRequest(ref decoded_call) = decoded.request else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            if decoded_call.params.name != name
                || serde_json::to_string(&decoded.id).ok().as_deref() != Some(&id.write())
            {
                return StatusCode::BAD_REQUEST.into_response();
            }
            let capable = key.is_some();
            let session_key = key
                .clone()
                .unwrap_or_else(|| format!("call:{}", hex(&random())));
            let client = field(params, "_meta")
                .and_then(|m| field(m, "io.modelcontextprotocol/clientInfo"))
                .and_then(|i| field(i, "name"))
                .and_then(string)
                .map(str::to_owned);
            let session = match front.open(&session_key, &agent, client, false) {
                Ok(s) => s,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
            };
            let call = Arc::new(Call {
                id: random().to_vec(),
                cancel: CancellationToken::new(),
            });
            {
                let mut sessions = front.0.sessions.lock().unwrap();
                let Some(s) = sessions.get_mut(&session_key) else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                if s.calls.contains_key(&id.write()) {
                    return (StatusCode::CONFLICT, "JSON-RPC ID is already in flight.")
                        .into_response();
                }
                s.calls.insert(id.write(), call.clone());
            }
            parts.extensions.insert(Exact {
                agent: agent.clone(),
                session: session.clone(),
                key: session_key.clone(),
                name: name.into(),
                args: field(params, "arguments").cloned(),
                body: bytes.clone(),
                rpc_id: id.write(),
                call: call.clone(),
                capable,
            });
            guard = Some(Guard {
                front: front.clone(),
                key: session_key,
                rpc_id: Some(id.write()),
                call: Some(call),
                ephemeral: !capable,
                session_id: session,
                finished: false,
            });
        }
        req = Request::from_parts(parts, Body::from(bytes));
    }
    let delete = req.method() == Method::DELETE;
    let mut response = next.run(req).await;
    if delete
        && response.status().is_success()
        && let Some(key) = &key
    {
        front.close(key);
    }
    if let Some(mcp_id) = response
        .headers()
        .get("mcp-session-id")
        .and_then(|s| s.to_str().ok())
        && shim.is_none()
        && response.status().is_success()
        && let Err(e) = front.open(&format!("mcp:{mcp_id}"), &agent, initialize_client, true)
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response();
    }
    if let Some(guard) = guard {
        let is_json = response
            .headers()
            .get("content-type")
            .is_some_and(|v| v.as_bytes().starts_with(b"application/json"));
        let (parts, body) = response.into_parts();
        let stream = body.into_data_stream();
        let buffer = Vec::new();
        // unfold owns the guard immediately: dropping an unpolled body still ends the call.
        let stream = futures::stream::unfold(
            (stream, guard, buffer),
            move |(mut stream, mut guard, mut buffer)| async move {
                match stream.next().await {
                    Some(chunk) => {
                        if let Ok(bytes) = &chunk {
                            buffer.extend_from_slice(bytes);
                            let final_message = |data: &[u8]| {
                                serde_json::from_slice::<serde_json::Value>(data)
                                    .ok()
                                    .is_some_and(|v| {
                                        (v.get("result").is_some() || v.get("error").is_some())
                                            && v.get("id").is_some_and(|i| {
                                                Some(i.to_string()) == guard.rpc_id
                                            })
                                    })
                            };
                            if is_json {
                                if final_message(&buffer) {
                                    guard.finished = true;
                                }
                            } else {
                                while let Some(end) = buffer.windows(2).position(|s| s == b"\n\n") {
                                    let event: Vec<_> = buffer.drain(..end + 2).collect();
                                    for line in event.split(|b| *b == b'\n') {
                                        if let Some(data) = line
                                            .strip_prefix(b"data: ")
                                            .or_else(|| line.strip_prefix(b"data:"))
                                            && final_message(data)
                                        {
                                            guard.finished = true;
                                        }
                                    }
                                }
                            }
                        }
                        Some((chunk, (stream, guard, buffer)))
                    }
                    None => None,
                }
            },
        );
        response = Response::from_parts(parts, Body::from_stream(stream));
    }
    response
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn liveness(State(front): State<Front>, req: Request) -> Response {
    let Some(Identity(agent, Some(key))) = req.extensions().get::<Identity>().cloned() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    // A second stream cannot take ownership of an existing session.
    if front.0.sessions.lock().unwrap().contains_key(&key) {
        return StatusCode::CONFLICT.into_response();
    }
    let session_id = match front.open(&key, &agent, None, true) {
        Ok(id) => id,
        Err(_) => return StatusCode::CONFLICT.into_response(),
    };
    let Some(alive) = front
        .0
        .sessions
        .lock()
        .unwrap()
        .get(&key)
        .map(|s| s.alive.clone())
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let guard = Guard {
        front: front.clone(),
        key,
        rpc_id: None,
        call: None,
        ephemeral: true,
        session_id,
        finished: false,
    };
    let stream = futures::stream::unfold(
        (guard, alive, false),
        |(guard, alive, sent)| async move {
            if !sent {
                Some((
                    Ok::<_, std::io::Error>(Bytes::from_static(b": alive\n\n")),
                    (guard, alive, true),
                ))
            } else {
                tokio::select! { _ = guard.front.0.stop.cancelled() => {}, _ = alive.cancelled() => {} };
                None
            }
        },
    );
    (
        [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-store"),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}

#[derive(Clone)]
struct Handler(Front);
fn parts(context: &RequestContext<RoleServer>) -> Result<&axum::http::request::Parts, ErrorData> {
    context
        .extensions
        .get()
        .ok_or_else(|| ErrorData::invalid_request("Missing authenticated HTTP request.", None))
}
impl ServerHandler for Handler {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
        )
        .with_server_info(Implementation::new("bogo", env!("CARGO_PKG_VERSION")))
    }
    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let Identity(agent, key) = parts(&context)?
            .extensions
            .get::<Identity>()
            .ok_or_else(|| ErrorData::invalid_request("Missing agent.", None))?;
        if let Some(key) = key
            && let Some(s) = self.0.0.sessions.lock().unwrap().get_mut(key)
        {
            s.peer = Some(context.peer.clone());
        }
        let mut tools: Vec<_> = self
            .0
            .0
            .backend
            .catalog(agent)
            .map_err(|e| ErrorData::invalid_request(e, None))?
            .into_iter()
            .map(|t| t.tool)
            .collect();
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(ListToolsResult {
            tools,
            cache_scope: Some(CacheScope::Private),
            ttl_ms: Some(0),
            ..Default::default()
        })
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let exact = parts(&context)?
            .extensions
            .get::<Exact>()
            .ok_or_else(|| ErrorData::invalid_request("Missing exact call.", None))?
            .clone();
        if request.name != exact.name
            || serde_json::to_string(&context.id).ok().as_deref() != Some(&exact.rpc_id)
        {
            return Err(ErrorData::invalid_request("Envelope mismatch.", None));
        }
        let catalog = self
            .0
            .0
            .backend
            .catalog(&exact.agent)
            .map_err(|e| ErrorData::invalid_request(e, None))?;
        if !exact.capable
            && catalog
                .iter()
                .any(|t| t.tool.name == exact.name && t.mode == bogo_core::Mode::PendingRetry)
        {
            return Ok(Outcome::Error(SESSION_REQUIRED.into()).into_result().into());
        }
        let call = Invocation {
            input: Input::Call {
                call: exact.call.id.clone(),
                session: exact.session,
                name: exact.name,
                args: exact.args,
                now_ms: self.0.0.backend.now_ms(),
            },
            body: exact.body,
            session_capable: exact.capable,
        };
        let future = {
            let sessions = self.0.0.sessions.lock().unwrap();
            if !sessions
                .get(&exact.key)
                .is_some_and(|s| s.calls.contains_key(&exact.rpc_id))
                || exact.call.cancel.is_cancelled()
            {
                return Ok(Outcome::Rejected(Rejection::EndedWithoutDecision)
                    .into_result()
                    .into());
            }
            self.0.0.backend.invoke(call)
        };
        let result = tokio::select! {
            biased;
            _ = exact.call.cancel.cancelled() => Outcome::Rejected(Rejection::EndedWithoutDecision),
            _ = context.ct.cancelled() => { let _ = self.0.0.backend.event(Input::CallEnded { call: exact.call.id.clone() }); Outcome::Rejected(Rejection::EndedWithoutDecision) },
            result = future => result,
        };
        Ok(result.into_result().into())
    }
}
