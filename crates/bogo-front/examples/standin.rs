//! Runnable integration fixture, not a production daemon. The linked Lean core makes every
//! decision; a local P-256 signer and echo result replace approvers and upstreams.
use bogo_core::*;
use bogo_front::{Agent, Backend, CatalogTool, Front, Invocation, Outcome};
use bogo_verify as _;
use futures::future::BoxFuture;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use rmcp::model::{CallToolResult, ContentBlock, Tool};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::oneshot;

struct Shell {
    core: Core,
    key: SigningKey,
    waiters: HashMap<Bytes, Vec<oneshot::Sender<Outcome>>>,
}
struct Standin {
    shell: Mutex<Shell>,
    clock: Instant,
}
const NAMES: &[&str] = &[
    "fixture__allow",
    "fixture__approved",
    "fixture__denied",
    "fixture__ended",
    "fixture__pending",
    "fixture__hold",
    "fixture__forbidden",
    "fixture__not_sent",
    "fixture__unknown",
];
fn mode(name: &str) -> Mode {
    if name == "fixture__pending" {
        Mode::PendingRetry
    } else {
        Mode::Wait
    }
}
impl Shell {
    fn step(&mut self, input: Input) -> Vec<Output> {
        eprintln!("CORE INPUT {input:?}");
        let result = self.core.step(&input).unwrap();
        eprintln!("CORE OUTPUT {:?}", result.outputs);
        result.outputs
    }
    fn deliver(&mut self, call: Bytes, outcome: impl Fn() -> Outcome) {
        for tx in self.waiters.remove(&call).unwrap_or_default() {
            let _ = tx.send(outcome());
        }
    }
    fn outputs(&mut self, outputs: Vec<Output>, now: u64) {
        for output in outputs {
            match output {
                Output::Authorized { call, .. } => {
                    let outputs = self.step(Input::Dispatch { call, now_ms: now });
                    self.outputs(outputs, now);
                }
                Output::Forward {
                    call, args, tool, ..
                } => {
                    if tool == "not_sent" {
                        self.deliver(call, || Outcome::NotSent);
                        continue;
                    }
                    if tool == "unknown" {
                        self.deliver(call, || Outcome::Unknown);
                        continue;
                    }
                    let text = args.map(|a| a.write()).unwrap_or_else(|| "<absent>".into());
                    eprintln!("UPSTREAM EXACT {text}");
                    self.deliver(call, || {
                        Outcome::Result(CallToolResult::success(vec![ContentBlock::text(format!(
                            "Stand-in result: {text}"
                        ))]))
                    });
                }
                Output::PendingApproval { call } => self.deliver(call, || Outcome::Pending),
                Output::Reject { call, why } => {
                    self.deliver(call, || Outcome::Rejected(why.clone()))
                }
                Output::FloodDropped { call } => self.deliver(call, || {
                    Outcome::Error("The pending request limit was reached.".into())
                }),
                Output::Attach { call, primary } => {
                    let waiters = self.waiters.remove(&call).unwrap_or_default();
                    self.waiters.entry(primary).or_default().extend(waiters);
                }
                _ => {}
            }
        }
    }
}
impl Backend for Standin {
    fn authenticate(&self, hash: &[u8; 32]) -> Option<Agent> {
        for (token, id) in [("standin-trip", "trip"), ("standin-research", "research")] {
            if hash.as_slice() == Sha256::digest(token.as_bytes()).as_slice() {
                return Some(Agent {
                    id: id.as_bytes().to_vec(),
                });
            }
        }
        None
    }
    fn available(&self, _: &Agent) -> Result<(), String> {
        Ok(())
    }
    fn catalog(&self, agent: &Agent) -> Result<Vec<CatalogTool>, String> {
        Ok(NAMES.iter().filter(|n| **n != "fixture__forbidden" && (agent.id != b"research" || **n == "fixture__allow")).map(|name| {
            let schema = if *name == "fixture__allow" { serde_json::json!({"type":"object","properties":{}}) }
            else { serde_json::json!({"type":"object","properties":{"justification":{"type":"string","description":"Agent's reason (unverified)"}}}) };
            CatalogTool { tool: Tool::new(name.to_string(), "BOGO linked-core verification fixture", Arc::new(schema.as_object().unwrap().clone())), mode: mode(name) }
        }).collect())
    }
    fn now_ms(&self) -> u64 {
        self.clock.elapsed().as_millis() as u64
    }
    fn event(&self, input: Input) -> Result<(), String> {
        let mut shell = self.shell.lock().unwrap();
        let outputs = shell.step(input);
        shell.outputs(outputs, self.now_ms());
        Ok(())
    }
    fn invoke(&self, call: Invocation) -> BoxFuture<'_, Outcome> {
        let (tx, rx) = oneshot::channel();
        let mut shell = self.shell.lock().unwrap();
        let Input::Call { call: id, name, .. } = &call.input else {
            unreachable!()
        };
        let (id, name) = (id.clone(), name.clone());
        eprintln!("HTTP BODY HEX {}", bogo_front::hex(&call.body));
        shell.waiters.insert(id, vec![tx]);
        let outputs = shell.step(call.input);
        let asks: Vec<_> = outputs
            .iter()
            .filter_map(|o| {
                if let Output::Ask { req, bytes, .. } = o {
                    Some((req.clone(), bytes.clone()))
                } else {
                    None
                }
            })
            .collect();
        shell.outputs(outputs, self.now_ms());
        for (req, bytes) in asks {
            let input = match name.as_str() {
                "fixture__approved" | "fixture__pending" => {
                    let mut signed = b"BOGO-APPROVAL\x00v1".to_vec();
                    signed.extend(bytes);
                    let signature: Signature = shell.key.sign(&signed);
                    Some(Input::Approval {
                        approver: b"fixture".to_vec(),
                        req,
                        alg: 1,
                        proof: signature.to_bytes().to_vec(),
                        now_ms: self.now_ms(),
                    })
                }
                "fixture__denied" => Some(Input::Denial {
                    approver: b"fixture".to_vec(),
                    req,
                    note: Some("wrong amount".into()),
                }),
                "fixture__ended" => Some(Input::OwnerCancel { req }),
                _ => None,
            };
            if let Some(input) = input {
                let outputs = shell.step(input);
                shell.outputs(outputs, self.now_ms());
            }
        }
        Box::pin(async {
            rx.await
                .unwrap_or(Outcome::Error("Stand-in stopped.".into()))
        })
    }
}
#[tokio::main]
async fn main() {
    let boot = [7u8; 32];
    let core = Core::start(b"front-fixture", &boot).unwrap();
    let key = SigningKey::from_bytes(&[1u8; 32].into()).unwrap();
    let policies = NAMES
        .iter()
        .map(|n| {
            let mut policy = ToolPolicy::new(match *n {
                "fixture__allow" | "fixture__not_sent" | "fixture__unknown" => PolicyKind::Allow,
                "fixture__forbidden" => PolicyKind::Deny,
                _ => PolicyKind::Approve,
            });
            policy.mode = mode(n);
            (n.to_string(), policy)
        })
        .collect();
    let mut shell = Shell {
        core,
        key,
        waiters: HashMap::new(),
    };
    shell.step(Input::Configure {
        seq: 1,
        cfg: PolicyConfig {
            default_policy: DefaultPolicy::Deny,
            max_pending: 32,
            tools: policies,
            overrides: NAMES
                .iter()
                .filter(|n| **n != "fixture__allow")
                .map(|n| AgentOverride {
                    agent_name: "Researcher".into(),
                    tool: n.to_string(),
                    kind: Some(PolicyKind::Deny),
                    approvers: None,
                    requirement: None,
                })
                .collect(),
        },
        catalog: NAMES
            .iter()
            .map(|n| CatalogEntry {
                name: n.to_string(),
                upstream: "fixture".into(),
                tool: n.strip_prefix("fixture__").unwrap().into(),
                just_key: "justification".into(),
            })
            .collect(),
    });
    let pk = shell
        .key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    shell.step(Input::ApproverSet {
        seq: 2,
        approver: Approver {
            id: b"fixture".to_vec(),
            name: "Fixture approver".into(),
            alg: 1,
            pk,
        },
    });
    shell.step(Input::AgentSet {
        seq: 3,
        id: b"trip".to_vec(),
        name: "Trip planner".into(),
    });
    shell.step(Input::AgentSet {
        seq: 4,
        id: b"research".to_vec(),
        name: "Researcher".into(),
    });
    let front = Front::new(
        Arc::new(Standin {
            shell: Mutex::new(shell),
            clock: Instant::now(),
        }),
        boot.to_vec(),
    );
    let address = std::env::var("BOGO_FRONT_ADDR").unwrap_or_else(|_| "127.0.0.1:18763".into());
    let address: std::net::SocketAddr = address.parse().unwrap();
    assert!(address.ip().is_loopback());
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    eprintln!("BOGO stand-in http://{address}/mcp; fixture tokens: standin-trip, standin-research");
    let shutdown = front.clone();
    axum::serve(listener, front.router())
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c().await.unwrap();
            shutdown.shutdown();
        })
        .await
        .unwrap();
}
