use crate::{
    CALL_MARKER, CallId, Catalog, CatalogTool, Error, ExactChildTransport, ExactHttpClient, Gate,
    Outcome, Scrubber,
    catalog::{exposable, widen},
};
use bogo_config::{Config, Policy, Upstream};
use rmcp::{
    RoleClient, ServiceExt,
    model::*,
    service::{NotificationContext, Peer, RequestContext, RunningService, Service},
    transport::{
        StreamableHttpClientTransport, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Notify, RwLock, watch};

struct Client {
    changed: Arc<Notify>,
}
impl Service<RoleClient> for Client {
    async fn handle_request(
        &self,
        _: ServerRequest,
        _: RequestContext<RoleClient>,
    ) -> Result<ClientResult, ErrorData> {
        Err(ErrorData::internal_error(
            Error::Interactive.to_string(),
            None,
        ))
    }
    async fn handle_notification(
        &self,
        notification: ServerNotification,
        _: NotificationContext<RoleClient>,
    ) -> Result<(), ErrorData> {
        if matches!(
            notification,
            ServerNotification::ToolListChangedNotification(_)
        ) {
            self.changed.notify_one();
        }
        Ok(()) // upstream logging notifications are intentionally not logged
    }
    fn get_info(&self) -> ClientConfig {
        let mut info = ClientConfig::new(
            ClientCapabilities::default(),
            Implementation::new("bogo", env!("CARGO_PKG_VERSION")),
        );
        // Stable MCP tools/list notifications, without the newer subscription protocol.
        info.protocol_version = ProtocolVersion::V_2025_11_25;
        info
    }
}
struct State {
    config: Config,
    gate: Arc<dyn Gate>,
    scrubber: Scrubber,
    peers: RwLock<BTreeMap<String, Peer<RoleClient>>>,
    catalog: RwLock<Catalog>,
    updates: watch::Sender<u64>,
}
/// One shared connection per upstream. Drop shuts connections and restart tasks down.
/// Subscribe to catalog changes and send the snapshot to core configure before admission.
pub struct Manager {
    state: Arc<State>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for Manager {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl Manager {
    pub async fn start(
        config: Config,
        secrets: &bogo_config::Secrets,
        gate: Arc<dyn Gate>,
        previous: Catalog,
    ) -> Self {
        let (updates, _) = watch::channel(0);
        let mut previous = previous;
        previous
            .tools
            .retain(|_, t| config.upstreams.contains_key(&t.upstream));
        let state = Arc::new(State {
            config,
            gate,
            scrubber: Scrubber::new(secrets),
            peers: RwLock::new(BTreeMap::new()),
            catalog: RwLock::new(previous),
            updates,
        });
        let mut tasks = Vec::new();
        let mut ready = Vec::new();
        for (name, config) in &state.config.upstreams {
            let (tx, rx) = tokio::sync::oneshot::channel();
            ready.push(rx);
            let state = state.clone();
            let name = name.clone();
            let config = config.clone();
            tasks.push(tokio::spawn(run(state, name, config, tx)));
        }
        for rx in ready {
            let _ = rx.await;
        }
        Self { state, tasks }
    }
    pub async fn catalog(&self) -> Catalog {
        self.state.catalog.read().await.clone()
    }
    /// Connection and catalog changes. Read fresh snapshots after each change.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.state.updates.subscribe()
    }
    pub async fn health(&self) -> BTreeMap<String, bool> {
        let peers = self.state.peers.read().await;
        self.state
            .config
            .upstreams
            .keys()
            .map(|name| {
                (
                    name.clone(),
                    peers.get(name).is_some_and(|p| !p.is_transport_closed()),
                )
            })
            .collect()
    }
    /// Policy-specific catalog projection; overrides are resolved by core again at admission.
    pub async fn tools_for(&self, agent: &str) -> Result<Vec<Value>, Error> {
        let catalog = self.state.catalog.read().await;
        let mut tools = Vec::new();
        for (name, entry) in &catalog.tools {
            let (any_approve, all_deny) = listed(&self.state.config, agent, name);
            if all_deny && self.state.config.defaults.hide_denied {
                continue;
            }
            let mut tool = entry.original.clone();
            tool["name"] = json!(name);
            if any_approve {
                let (schema, key, _) = widen(&tool["inputSchema"])?;
                if entry.justification.as_ref() != Some(&key) {
                    return Err(Error::Protocol);
                }
                tool["inputSchema"] = schema;
            }
            adjust_output(&self.state.config, name, &mut tool);
            tools.push(tool);
        }
        Ok(tools)
    }
    /// The caller stages only a core CallId; arguments never pass through rmcp.
    /// Returns credential-scrubbed output. The daemon must apply bogo-filter before
    /// exposing this output to an agent or persisting it (ARCHITECTURE §9).
    pub async fn call(&self, name: &str, call: CallId) -> Result<CallToolResult, Error> {
        let upstream = {
            let catalog = self.state.catalog.read().await;
            catalog
                .tools
                .get(name)
                .ok_or(Error::NotSent)?
                .upstream
                .clone()
        };
        let peer = self.state.peers.read().await.get(&upstream).cloned();
        let Some(peer) = peer.filter(|p| !p.is_transport_closed()) else {
            self.state.gate.outcome(&call, Outcome::NotSent);
            return Err(Error::NotSent);
        };
        let mut params =
            CallToolRequestParams::new(name.split_once("__").ok_or(Error::Protocol)?.1.to_owned());
        params.meta = Some(
            serde_json::from_value(json!({(CALL_MARKER):call.0})).map_err(|_| Error::Protocol)?,
        );
        let response = peer.call_tool_once(params).await.map_err(|error| {
            if let rmcp::ServiceError::TransportSend(transport) = &error {
                if let Some(error) = transport.error.downcast_ref::<Error>() { return *error; }
                if let Some(rmcp::transport::streamable_http_client::StreamableHttpError::Client(error)) =
                    transport.error.downcast_ref::<rmcp::transport::streamable_http_client::StreamableHttpError<Error>>() { return *error; }
            }
            self.state.gate.outcome(&call, Outcome::Unknown);
            Error::Unknown
        })?;
        let CallToolResponse::Complete(result) = response else {
            return Err(Error::Interactive);
        };
        let mut value = serde_json::to_value(result).map_err(|_| Error::Protocol)?;
        self.state.scrubber.json(&mut value);
        serde_json::from_value(value).map_err(|_| Error::Protocol)
    }
}
fn adjust_output(config: &Config, name: &str, tool: &mut Value) {
    if config
        .tools
        .get(name)
        .is_some_and(|t| !t.filter_output.is_empty())
        && let Some(m) = tool.as_object_mut()
    {
        m.remove("outputSchema");
    }
}

/// How one listed tool looks to an agent, across the tool and each per-action entry: whether
/// any of them needs approval (so the agent sees the justification field), and whether all of
/// them are denied (so `hide_denied` may hide it).
fn listed(config: &Config, agent: &str, name: &str) -> (bool, bool) {
    let policies: Vec<Policy> = config
        .policy_names(name)
        .map(|n| config.effective_policy(agent, n))
        .collect();
    (
        policies.contains(&Policy::Approve),
        policies.iter().all(|p| *p == Policy::Deny),
    )
}
async fn connect(
    state: &State,
    name: &str,
    config: &Upstream,
    changed: Arc<Notify>,
) -> Result<RunningService<RoleClient, Client>, Error> {
    let client = Client { changed };
    match config {
        Upstream::Local { .. } => client
            .serve(ExactChildTransport::spawn(
                name.into(),
                config,
                state.gate.clone(),
                state.scrubber.clone(),
            )?)
            .await
            .map_err(|_| Error::NotSent),
        Upstream::Remote { url, .. } => {
            let client_http = ExactHttpClient::new(
                name.into(),
                config,
                state.gate.clone(),
                state.scrubber.clone(),
            )?;
            let transport = StreamableHttpClientTransport::with_client(
                client_http,
                StreamableHttpClientTransportConfig::with_uri(url.clone())
                    .reinit_on_expired_session(false),
            );
            client.serve(transport).await.map_err(|_| Error::NotSent)
        }
    }
}
async fn discover(state: &State, name: &str, peer: &Peer<RoleClient>) -> Result<(), Error> {
    let mut tools = Vec::new();
    let mut cursor = None;
    let mut seen = BTreeSet::new();
    loop {
        let page = peer
            .list_tools(Some({
                let mut p = PaginatedRequestParams::default();
                p.cursor = cursor;
                p
            }))
            .await
            .map_err(|_| Error::Protocol)?;
        tools.extend(page.tools);
        cursor = page.next_cursor;
        if let Some(c) = &cursor {
            if !seen.insert(c.clone()) {
                return Err(Error::Protocol);
            }
        } else {
            break;
        }
    }
    let mut catalog = state.catalog.write().await;
    let previous = catalog.tools.clone();
    catalog.tools.retain(|_, t| t.upstream != name);
    catalog
        .unexposable
        .retain(|n| !n.starts_with(&format!("{name}__")));
    for tool in tools {
        let name_full = format!("{name}__{}", tool.name);
        let original = serde_json::to_value(tool).map_err(|_| Error::Protocol)?;
        let (schema, key, risk) = match widen(&original["inputSchema"]) {
            Ok(v) if exposable(&name_full) => v,
            _ => {
                catalog.unexposable.push(name_full);
                continue;
            }
        };
        let mut advertised = original.clone();
        advertised["name"] = json!(name_full);
        // Keep one stable chosen key even when a per-agent override changes policy.
        if listed(&state.config, "", &name_full).0 {
            advertised["inputSchema"] = schema;
        }
        adjust_output(&state.config, &name_full, &mut advertised);
        let first_seen = previous
            .get(&name_full)
            .map(|t| t.first_seen)
            .unwrap_or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            });
        catalog.tools.insert(
            name_full,
            CatalogTool {
                upstream: name.into(),
                original,
                advertised,
                justification: Some(key),
                strict_client_risk: risk,
                first_seen,
            },
        );
    }
    state.updates.send_modify(|v| *v = v.wrapping_add(1));
    Ok(())
}
async fn run(
    state: Arc<State>,
    name: String,
    config: Upstream,
    ready: tokio::sync::oneshot::Sender<()>,
) {
    let mut ready = Some(ready);
    let mut backoff = Duration::from_millis(100);
    loop {
        let changed = Arc::new(Notify::new());
        let connected = tokio::time::timeout(
            Duration::from_secs(30),
            connect(&state, &name, &config, changed.clone()),
        )
        .await;
        if let Ok(Ok(service)) = connected {
            let peer = service.peer().clone();
            if discover(&state, &name, &peer).await.is_ok() {
                state.peers.write().await.insert(name.clone(), peer.clone());
                state.updates.send_modify(|v| *v = v.wrapping_add(1));
                if let Some(tx) = ready.take() {
                    let _ = tx.send(());
                }
                let waiting = service.waiting();
                tokio::pin!(waiting);
                loop {
                    tokio::select! {
                        _ = &mut waiting => break,
                        _ = changed.notified() => { if discover(&state, &name, &peer).await.is_err() { break; } }
                    }
                }
                state.peers.write().await.remove(&name);
                state.updates.send_modify(|v| *v = v.wrapping_add(1));
            }
        }
        if let Some(tx) = ready.take() {
            let _ = tx.send(());
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}
