//! Serialized effects shell: core output, durable audit record, then effect.
mod clock;
mod owner;
mod policy;
use bogo_approver as a;
use bogo_config::Config;
use bogo_core::{Bytes, Core, Input, Output};
use bogo_front::{Backend, CatalogTool, Invocation, Outcome};
// Retain the verifier providing the Lean core's C extern hook.
use bogo_log::{Hex, Log, LogEvent, Registry};
use bogo_verify as _;
use futures::future::BoxFuture;
pub use owner::{Command, add_upstream, init, launch, local, request, serve};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tokio::sync::{mpsc, oneshot};

type Result<T> = std::result::Result<T, String>;
#[derive(Default)]
struct Snapshot {
    registry: Registry,
    tools: HashMap<Bytes, Vec<CatalogTool>>,
    failed: bool,
}
#[derive(Clone)]
struct Handle {
    tx: mpsc::UnboundedSender<Job>,
    snapshot: Arc<RwLock<Snapshot>>,
    clock: Arc<clock::Clock>,
}
enum Job {
    Event(Input),
    Invoke(Input, oneshot::Sender<Outcome>),
    Dispatch(
        Bytes,
        oneshot::Sender<std::result::Result<bogo_upstream::Forward, bogo_upstream::Error>>,
    ),
    Finished(
        Bytes,
        std::result::Result<rmcp::model::CallToolResult, bogo_upstream::Error>,
    ),
    Decision(a::Decision, oneshot::Sender<Result<()>>),
    Commit(
        String,
        String,
        a::NewApprover,
        oneshot::Sender<Result<a::Committed>>,
    ),
    Control(Command, oneshot::Sender<Result<serde_json::Value>>),
    Catalog,
}
impl Handle {
    async fn control(&self, c: Command) -> Result<serde_json::Value> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Job::Control(c, tx))
            .map_err(|_| "daemon stopped")?;
        rx.await.map_err(|_| "daemon stopped")?
    }
}
impl Backend for Handle {
    fn authenticate(&self, h: &[u8; 32]) -> Option<bogo_front::Agent> {
        let s = self.snapshot.read().ok()?;
        if s.failed {
            return None;
        }
        s.registry
            .agents
            .values()
            .find(|a| !a.revoked && a.token_sha256 == hex::encode(h))
            .map(|a| bogo_front::Agent { id: a.id.0.clone() })
    }
    fn available(&self, a: &bogo_front::Agent) -> Result<()> {
        let s = self.snapshot.read().unwrap();
        if s.failed {
            return Err("BOGO audit writer failed; admission closed".into());
        }
        match s.registry.agents.get(&hex::encode(&a.id)) {
            Some(a) if !a.revoked && !a.paused => Ok(()),
            Some(a) if a.paused => Err("This agent is paused.".into()),
            _ => Err("This agent is revoked.".into()),
        }
    }
    fn catalog(&self, a: &bogo_front::Agent) -> Result<Vec<CatalogTool>> {
        self.available(a)?;
        Ok(self
            .snapshot
            .read()
            .unwrap()
            .tools
            .get(&a.id)
            .cloned()
            .unwrap_or_default())
    }
    fn event(&self, i: Input) -> Result<()> {
        self.tx
            .send(Job::Event(i))
            .map_err(|_| "daemon stopped".into())
    }
    fn now_ms(&self) -> u64 {
        self.clock.now()
    }
    fn invoke(&self, c: Invocation) -> BoxFuture<'_, Outcome> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(Job::Invoke(c.input, tx));
        Box::pin(async move {
            rx.await.unwrap_or(Outcome::Error(
                "BOGO stopped; outcome unknown; never retried.".into(),
            ))
        })
    }
}
impl bogo_upstream::Gate for Handle {
    fn dispatch(
        &self,
        c: bogo_upstream::CallId,
    ) -> BoxFuture<'_, std::result::Result<bogo_upstream::Forward, bogo_upstream::Error>> {
        Box::pin(async move {
            let call = hex::decode(c.0).map_err(|_| bogo_upstream::Error::Rejected)?;
            let (tx, rx) = oneshot::channel();
            self.tx
                .send(Job::Dispatch(call, tx))
                .map_err(|_| bogo_upstream::Error::Rejected)?;
            rx.await.unwrap_or(Err(bogo_upstream::Error::Rejected))
        })
    }
}
#[async_trait::async_trait]
impl a::Sink for Handle {
    async fn decision(&self, d: a::Decision) -> std::result::Result<Vec<a::Effect>, a::SinkError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Job::Decision(d, tx))
            .map_err(|_| a::SinkError("daemon stopped".into()))?;
        rx.await
            .map_err(|_| a::SinkError("daemon stopped".into()))?
            .map_err(a::SinkError)?;
        Ok(vec![])
    }
    async fn removed(
        &self,
        id: a::ApproverId,
    ) -> std::result::Result<Vec<a::Effect>, a::SinkError> {
        self.control(Command::RevokeApproverId {
            id: hex::encode(id),
            by_self: true,
        })
        .await
        .map_err(a::SinkError)?;
        Ok(vec![])
    }
    async fn route_update(
        &self,
        id: a::ApproverId,
        seq: u64,
        route: serde_json::Value,
    ) -> std::result::Result<bool, a::SinkError> {
        let v = self
            .control(Command::RouteUpdate {
                id: hex::encode(id),
                seq,
                route,
            })
            .await
            .map_err(a::SinkError)?;
        Ok(v == true)
    }
    async fn outcome(&self, req: &a::ReqId) -> String {
        self.control(Command::Outcome {
            id: hex::encode(req),
        })
        .await
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or("unknown".into())
    }
    async fn commit(
        &self,
        name: &str,
        kind: &str,
        new: &a::NewApprover,
    ) -> std::result::Result<a::Committed, a::SinkError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Job::Commit(name.into(), kind.into(), new.clone(), tx))
            .map_err(|_| a::SinkError("daemon stopped".into()))?;
        rx.await
            .map_err(|_| a::SinkError("daemon stopped".into()))?
            .map_err(a::SinkError)
    }
}
struct Call {
    name: String,
    req: Option<Bytes>,
    waiters: Vec<oneshot::Sender<Outcome>>,
    staged: bool,
}
struct Shell {
    core: Core,
    log: Log,
    registry: Registry,
    config: Config,
    calls: HashMap<Bytes, Call>,
    sessions: HashMap<Bytes, Bytes>,
    requests: HashMap<Bytes, (Bytes, Vec<Bytes>)>,
    counted: HashMap<Bytes, Vec<Bytes>>,
    manager: Arc<bogo_upstream::Manager>,
    hub: Arc<a::Hub>,
    handle: Handle,
    home: bogo_state::Home,
    _lock: bogo_state::WriterLock,
    boot: a::BootNotice,
    deadline: Option<u64>,
    #[cfg(feature = "test-approvers")]
    soft: Arc<bogo_approver_soft::SoftRoute>,
}
fn record(s: &bogo_log::ApproverState) -> Option<a::ApproverRecord> {
    Some(a::ApproverRecord {
        id: s.entry.id.0.as_slice().try_into().ok()?,
        name: s.entry.name.clone(),
        kind: s.entry.kind.clone(),
        alg: s.entry.alg,
        sig_pk: s.entry.sig_pk.0.clone(),
        tx_id: s.entry.tx_id.0.as_slice().try_into().ok()?,
        route: s.entry.route.clone(),
        active: s.active(),
    })
}
fn ids(to: &[Bytes]) -> Vec<a::ApproverId> {
    to.iter()
        .filter_map(|b| b.as_slice().try_into().ok())
        .collect()
}
fn end(why: bogo_core::EndReason) -> (&'static str, a::EndWhy) {
    use bogo_core::EndReason::*;
    match why {
        Denied => ("denied", a::EndWhy::Unknown),
        Cancelled => ("ownerCancel", a::EndWhy::OwnerCancel),
        CallEnded => ("callEnded", a::EndWhy::CallEnded),
        SessionClosed => ("sessionClosed", a::EndWhy::SessionClosed),
        AgentRevoked => ("agentRevoked", a::EndWhy::AgentRevoked),
        AgentPaused => ("agentPaused", a::EndWhy::AgentPaused),
        Expired => ("expired", a::EndWhy::Expired),
        Unreachable => ("approverRevoked", a::EndWhy::ApproverRevoked),
        DispatchFailed => ("dispatchFailed", a::EndWhy::Unknown),
        NotSent => ("notSent", a::EndWhy::Unknown),
    }
}
impl Shell {
    async fn append(&mut self, events: Vec<LogEvent>) -> Result<Vec<u64>> {
        let seqs = self.log.append_all(events).await.map_err(|e| {
            self.handle.snapshot.write().unwrap().failed = true;
            e.to_string()
        })?;
        self.registry = Registry::replay(&self.log.entries().map_err(|e| e.to_string())?);
        self.handle.snapshot.write().unwrap().registry = self.registry.clone();
        Ok(seqs)
    }
    async fn catalog(&mut self) -> Result<()> {
        let catalog = self.manager.catalog().await;
        let seq = self
            .append(vec![LogEvent::Configured {
                sha256: hex::encode(Sha256::digest(
                    std::fs::read(self.home.root().join("bogo.toml")).map_err(|e| e.to_string())?,
                )),
            }])
            .await?[0];
        self.step(Input::Configure {
            seq,
            cfg: policy::config(&self.config),
            catalog: catalog
                .tools
                .iter()
                .map(|(n, t)| bogo_core::CatalogEntry {
                    name: n.clone(),
                    upstream: t.upstream.clone(),
                    tool: n.split_once("__").unwrap().1.into(),
                    just_key: t.justification.clone().unwrap_or_default(),
                })
                .collect(),
        })
        .await?;
        let mut views = HashMap::new();
        for a in self.registry.agents.values().filter(|a| !a.revoked) {
            let mut tools = vec![];
            for tool in self
                .manager
                .tools_for(&a.name)
                .await
                .map_err(|e| e.to_string())?
            {
                let name = tool["name"].as_str().ok_or("invalid catalog")?;
                let mode = self
                    .config
                    .tools
                    .get(name)
                    .map(|t| policy::mode(t.mode))
                    .unwrap_or(bogo_core::Mode::Wait);
                tools.push(CatalogTool {
                    tool: serde_json::from_value(tool).map_err(|_| "invalid catalog")?,
                    mode,
                })
            }
            views.insert(a.id.0.clone(), tools);
        }
        self.handle.snapshot.write().unwrap().tools = views;
        bogo_state::write_atomic(
            &self.home.root().join("state/tools.json"),
            &serde_json::to_vec(&catalog).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
    fn deliver(&mut self, call: &[u8], out: Outcome) {
        if let Some(c) = self.calls.remove(call) {
            let serialized = out.into_result();
            for tx in c.waiters {
                let _ = tx.send(Outcome::Result(serialized.clone()));
            }
        }
    }
    async fn step(&mut self, input: Input) -> Result<Vec<Output>> {
        match &input {
            Input::SessionOpened { session, agent, .. } => {
                self.sessions.insert(session.clone(), agent.clone());
            }
            Input::SessionClosed { session } => {
                self.sessions.remove(session);
            }
            _ => {}
        }
        let step = self.core.step(&input).map_err(|e| {
            self.handle.snapshot.write().unwrap().failed = true;
            e.to_string()
        })?;
        self.deadline = step.deadline_ms;
        let outputs = step.outputs;
        let mut events = vec![];
        if let Input::Approval {
            approver,
            req,
            alg,
            proof,
            ..
        } = &input
        {
            let counted = outputs
                .iter()
                .any(|o| matches!(o,Output::Counted{approver:a,req:r} if a==approver && r==req));
            let why = outputs.iter().find_map(|o| {
                if let Output::Ignored { why, .. } = o {
                    Some(format!("{why:?}"))
                } else {
                    None
                }
            });
            events.push(LogEvent::Approval {
                req: Hex(req.clone()),
                approver: Hex(approver.clone()),
                alg: *alg,
                proof: Hex(proof.clone()),
                counted,
                why,
            });
        }
        if let Input::Denial {
            approver,
            req,
            note,
        } = &input
        {
            let why = outputs.iter().find_map(|o| {
                if let Output::Ignored { why, .. } = o {
                    Some(format!("{why:?}"))
                } else {
                    None
                }
            });
            events.push(LogEvent::Denial {
                req: Hex(req.clone()),
                approver: Hex(approver.clone()),
                note: note.clone(),
                applied: why.is_none(),
                why,
            });
        }
        for o in &outputs {
            match o {
                Output::Ask {
                    req,
                    bytes,
                    to,
                    pause_epoch,
                    ..
                } => {
                    events.push(LogEvent::RequestCreated {
                        req: Hex(req.clone()),
                        request: Hex(bytes.clone()),
                        to: to.iter().cloned().map(Hex).collect(),
                        k: self.request_k(&input)?,
                        pause_epoch: *pause_epoch,
                    });
                }
                Output::Authorized { call, req } => {
                    events.push(LogEvent::CallOutcome {
                        call: Hex(call.clone()),
                        outcome: "authorized".into(),
                        registry_seq: None,
                    });
                    if let Some(req) = req {
                        events.push(LogEvent::Authorized {
                            req: Hex(req.clone()),
                        });
                    }
                }
                Output::Forward {
                    call,
                    req,
                    registry_seq,
                    ..
                } => {
                    events.push(LogEvent::CallOutcome {
                        call: Hex(call.clone()),
                        outcome: "forwarded".into(),
                        registry_seq: Some(*registry_seq),
                    });
                    if let Some(req) = req {
                        events.push(LogEvent::Forwarded {
                            req: Hex(req.clone()),
                            registry_seq: *registry_seq,
                        });
                    }
                }
                Output::Reject { call, why } => events.push(LogEvent::CallOutcome {
                    call: Hex(call.clone()),
                    outcome: format!("rejected:{why:?}"),
                    registry_seq: None,
                }),
                Output::Attach { call, primary } => events.push(LogEvent::CallOutcome {
                    call: Hex(call.clone()),
                    outcome: format!("attached:{}", hex::encode(primary)),
                    registry_seq: None,
                }),
                Output::PendingApproval { call } => events.push(LogEvent::CallOutcome {
                    call: Hex(call.clone()),
                    outcome: "pending_approval".into(),
                    registry_seq: None,
                }),
                Output::Ignored { req, approver, why }
                    if !matches!(input, Input::Approval { .. } | Input::Denial { .. }) =>
                {
                    events.push(LogEvent::Ignored {
                        what: "core_input".into(),
                        approver: Some(Hex(approver.clone())),
                        req: Some(Hex(req.clone())),
                        why: format!("{why:?}"),
                    })
                }
                Output::FloodDropped { call } => events.push(LogEvent::CallOutcome {
                    call: Hex(call.clone()),
                    outcome: "flood_dropped".into(),
                    registry_seq: None,
                }),
                Output::Settled { req, .. } => {
                    let mut approvers = self.counted.get(req).cloned().unwrap_or_default();
                    for o in &outputs {
                        if let Output::Counted { req: r, approver } = o
                            && r == req
                            && !approvers.contains(approver)
                        {
                            approvers.push(approver.clone())
                        }
                    }
                    events.push(LogEvent::RequestSettled {
                        req: Hex(req.clone()),
                        approvers: approvers.into_iter().map(Hex).collect(),
                    });
                }
                Output::Ended { req, why, .. } => events.push(LogEvent::RequestEnded {
                    req: Hex(req.clone()),
                    why: end(*why).0.into(),
                }),
                Output::AgentPaused { agent } => {
                    let by = if let Input::PauseAgent { approver, .. } = &input {
                        hex::encode(approver)
                    } else {
                        "owner".into()
                    };
                    if !matches!(input, Input::OwnerPause { .. }) {
                        events.push(LogEvent::AgentPaused {
                            id: Hex(agent.clone()),
                            by,
                        });
                    }
                }
                _ => {}
            }
        }
        if !events.is_empty() {
            self.append(events).await?;
        }
        for o in &outputs {
            match o {
                Output::Ask {
                    req,
                    bytes,
                    to,
                    group_key,
                    pause_epoch,
                } => {
                    self.requests
                        .insert(req.clone(), (bytes.clone(), to.clone()));
                    self.hub.ask(
                        a::Outbound {
                            req: req
                                .as_slice()
                                .try_into()
                                .map_err(|_| "invalid core request id")?,
                            bytes: bytes.clone(),
                            boot_seq: self.boot.boot_seq,
                            pause_epoch: *pause_epoch,
                            arm_delay_ms: self
                                .config
                                .iphone
                                .as_ref()
                                .map_or(0, |i| i.approve_arm_delay.as_millis() as u64),
                            group_key: group_key.clone(),
                        },
                        &ids(to),
                    );
                }
                Output::Counted { req, approver } => self
                    .counted
                    .entry(req.clone())
                    .or_default()
                    .push(approver.clone()),
                Output::Settled { req, to } => self
                    .hub
                    .settled(req.as_slice().try_into().map_err(|_| "bad req")?, &ids(to)),
                Output::Ended { req, why, to } => {
                    self.requests.remove(req);
                    self.counted.remove(req);
                    self.hub.ended(
                        req.as_slice().try_into().map_err(|_| "bad req")?,
                        end(*why).1,
                        &ids(to),
                    );
                }
                Output::Authorized { call, req } => {
                    if let Some(c) = self.calls.get_mut(call) {
                        c.req = req.clone();
                        if !c.staged {
                            c.staged = true;
                            let manager = self.manager.clone();
                            let name = c.name.clone();
                            let call = call.clone();
                            let tx = self.handle.tx.clone();
                            tokio::spawn(async move {
                                let result = manager
                                    .call(&name, bogo_upstream::CallId(hex::encode(&call)))
                                    .await;
                                let _ = tx.send(Job::Finished(call, result));
                            });
                        }
                    }
                }
                Output::Attach { call, primary } => {
                    if let Some(c) = self.calls.remove(call)
                        && let Some(p) = self.calls.get_mut(primary)
                    {
                        p.waiters.extend(c.waiters)
                    }
                }
                Output::PendingApproval { call } => self.deliver(call, Outcome::Pending),
                Output::Reject { call, why } => self.deliver(call, Outcome::Rejected(why.clone())),
                Output::FloodDropped { call } => {
                    self.deliver(call, Outcome::Rejected(bogo_core::Rejection::Exhausted))
                }
                _ => {}
            }
        }
        Ok(outputs)
    }
    fn request_k(&self, input: &Input) -> Result<u32> {
        let Input::Call { session, name, .. } = input else {
            return Err("core created a request outside a call".into());
        };
        let agent = self
            .sessions
            .get(session)
            .and_then(|id| self.registry.agents.get(&hex::encode(id)))
            .ok_or("request has no authenticated session")?;
        let requirement = self
            .config
            .agents
            .get(&agent.name)
            .and_then(|a| a.get(name))
            .and_then(|o| o.requirement)
            .or_else(|| self.config.tools.get(name).map(|t| t.requirement))
            .unwrap_or(bogo_config::Requirement::AnyOf);
        Ok(match requirement {
            bogo_config::Requirement::AnyOf => 1,
            bogo_config::Requirement::KOfN(k) => k,
        })
    }
    async fn finished(
        &mut self,
        call: Bytes,
        result: std::result::Result<rmcp::model::CallToolResult, bogo_upstream::Error>,
    ) -> Result<()> {
        let Some(c) = self.calls.get(&call) else {
            return Ok(());
        };
        let req = c.req.clone();
        let name = c.name.clone();
        let mut is_error = false;
        let mut filtered = bogo_filter::Report::default();
        let (out, word) = match result {
            Ok(r) => {
                is_error = r.is_error.unwrap_or(false);
                let rules = self
                    .config
                    .tools
                    .get(&name)
                    .map(|t| bogo_filter::Rules {
                        paths: t.filter_output.clone(),
                        action: match t.filter_action {
                            bogo_config::FilterAction::Strip => bogo_filter::Action::Strip,
                            bogo_config::FilterAction::Redact => bogo_filter::Action::Redact,
                        },
                    })
                    .unwrap_or_default();
                let (v, report) = bogo_filter::filter(
                    &rules,
                    serde_json::to_value(r).map_err(|_| "result serialization")?,
                );
                filtered = report;
                (
                    Outcome::Result(serde_json::from_value(v).map_err(|_| "filtered result")?),
                    "executed",
                )
            }
            Err(bogo_upstream::Error::NotSent) => {
                self.step(Input::NotSent { call: call.clone() }).await?;
                (Outcome::NotSent, "notSent")
            }
            Err(_) => (Outcome::Unknown, "unknown"),
        };
        let mut events = vec![LogEvent::CallResult {
            call: Hex(call.clone()),
            outcome: word.into(),
            is_error,
            filtered_fields: filtered.fields,
            withheld: filtered.withheld,
        }];
        if let Some(r) = &req {
            events.push(if word == "notSent" {
                LogEvent::NotSent {
                    req: Hex(r.clone()),
                }
            } else {
                LogEvent::Result {
                    req: Hex(r.clone()),
                    ok: word == "executed",
                }
            })
        }
        self.append(events).await?;
        if let Some(req) = req {
            self.counted.remove(&req);
            if let Some((_, to)) = self.requests.remove(&req) {
                self.hub.outcome(
                    req.as_slice().try_into().map_err(|_| "bad req")?,
                    word,
                    &ids(&to),
                );
            }
        }
        self.deliver(&call, out);
        Ok(())
    }
}
