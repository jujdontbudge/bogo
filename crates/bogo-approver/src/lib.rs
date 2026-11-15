//! Approver routes and the hub (ARCHITECTURE §3.10).
//!
//! The hub knows nothing about the decision logic or the log. It talks to
//! them through [`Sink`], which must make every effect durable before it
//! returns; only then does the hub let the route acknowledge the message to
//! the relay. Delivery state and seen message IDs live in memory: every
//! approver message is idempotent, so a duplicate after a crash gives the
//! same result.
mod hub;
pub use hub::Hub;

use async_trait::async_trait;
use std::sync::Arc;

pub type ApproverId = [u8; 32];
/// `bootId (32) ‖ u64 seq`: the nonce and the request ID everywhere.
pub type ReqId = [u8; 40];

/// What the hub and routes know about an approver. The decision logic sees
/// only `(id, name, alg, sig_pk, active)`.
#[derive(Clone, Debug, PartialEq)]
pub struct ApproverRecord {
    pub id: ApproverId,
    pub name: String,
    pub kind: String,
    pub alg: u16,
    pub sig_pk: Vec<u8>,
    pub tx_id: [u8; 32],
    /// Route-owned delivery data (for the iPhone: channel keys, mailbox, push token).
    pub route: serde_json::Value,
    pub active: bool,
}

/// A registration the route has fully checked and is ready to commit.
#[derive(Clone, Debug)]
pub struct NewApprover {
    pub id: ApproverId,
    pub alg: u16,
    pub sig_pk: Vec<u8>,
    pub tx_id: [u8; 32],
    pub route: serde_json::Value,
    /// Route-owned evidence of the key's origin (App Attest results).
    pub attest: serde_json::Value,
}

/// One request for one approver.
#[derive(Clone, Debug)]
pub struct Outbound {
    pub req: ReqId,
    pub bytes: Vec<u8>,
    pub boot_seq: u64,
    pub pause_epoch: u64,
    pub arm_delay_ms: u64,
    pub group_key: Vec<u8>,
}

/// Why a request ended, in the phone's vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndWhy {
    CallEnded,
    SessionClosed,
    OwnerCancel,
    Expired,
    AgentRevoked,
    ApproverRevoked,
    AgentPaused,
    OtherBoot,
    Unknown,
}

impl EndWhy {
    pub const ALL: [EndWhy; 9] = [
        EndWhy::CallEnded,
        EndWhy::SessionClosed,
        EndWhy::OwnerCancel,
        EndWhy::Expired,
        EndWhy::AgentRevoked,
        EndWhy::ApproverRevoked,
        EndWhy::AgentPaused,
        EndWhy::OtherBoot,
        EndWhy::Unknown,
    ];
    pub fn wire(self) -> &'static str {
        match self {
            EndWhy::CallEnded => "callEnded",
            EndWhy::SessionClosed => "sessionClosed",
            EndWhy::OwnerCancel => "ownerCancel",
            EndWhy::Expired => "expired",
            EndWhy::AgentRevoked => "agentRevoked",
            EndWhy::ApproverRevoked => "approverRevoked",
            EndWhy::AgentPaused => "agentPaused",
            EndWhy::OtherBoot => "otherBoot",
            EndWhy::Unknown => "unknown",
        }
    }
    pub fn parse(s: &str) -> Option<EndWhy> {
        EndWhy::ALL.into_iter().find(|w| w.wire() == s)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    Settled,
    Ended(EndWhy),
    /// `live | executed | notSent | denied | ended | unknown | noRecord`.
    Outcome(String),
}

#[derive(Clone, Copy, Debug)]
pub struct BootNotice {
    pub boot_seq: u64,
    pub boot_id: [u8; 32],
}

/// A message from an approver, after the route authenticated its channel.
#[derive(Clone, Debug, PartialEq)]
pub enum Inbound {
    Approval { approver: ApproverId, req: ReqId, alg: u16, proof: Vec<u8> },
    Denial { approver: ApproverId, req: ReqId, note: Option<String> },
    Pause { approver: ApproverId, agent: Vec<u8>, epoch: u64 },
    Seen { approver: ApproverId, req: ReqId },
    Removed { approver: ApproverId },
    Sync { approver: ApproverId, reqs: Vec<ReqId> },
    RegResend { approver: ApproverId, tx_id: [u8; 32] },
    /// Route data changed (for the iPhone: `pushToken` with a higher `tokenSeq`).
    RouteUpdate { approver: ApproverId, seq: u64, route: serde_json::Value },
}

impl Inbound {
    pub fn approver(&self) -> &ApproverId {
        match self {
            Inbound::Approval { approver, .. }
            | Inbound::Denial { approver, .. }
            | Inbound::Pause { approver, .. }
            | Inbound::Seen { approver, .. }
            | Inbound::Removed { approver }
            | Inbound::Sync { approver, .. }
            | Inbound::RegResend { approver, .. }
            | Inbound::RouteUpdate { approver, .. } => approver,
        }
    }
}

/// Returned when a message's effect could not be made durable: the route must
/// leave it unacknowledged so it is fetched again.
#[derive(Debug)]
pub struct Retry;

#[async_trait]
pub trait InboundHandler: Send + Sync {
    /// `Ok` means the effect is durable and the message may be acknowledged.
    async fn handle(&self, msg: Inbound) -> Result<(), Retry>;
}

/// The owner's side of registration (the Mac terminal).
#[async_trait]
pub trait OwnerPrompt: Send + Sync {
    async fn status(&self, line: &str);
    /// Show the code and ask the owner whether the approver shows the same.
    async fn confirm_code(&self, code: &str) -> bool;
}

#[derive(Debug, thiserror::Error)]
pub enum RegError {
    #[error("registration aborted: {0}")]
    Aborted(String),
    #[error("the owner said the codes do not match; nothing was registered")]
    Mismatch,
    #[error("registration refused: {0}")]
    Refused(String),
    #[error("relay: {0}")]
    Transport(String),
    #[error("could not record the registration: {0}")]
    Commit(String),
}

/// A registration that passed every check and waits for the commit.
#[async_trait]
pub trait PendingRegistration: Send {
    fn approver(&self) -> &NewApprover;
    /// Called only after the commit is durable and the route knows the record.
    async fn answer(self: Box<Self>, committed: &ApproverRecord) -> Result<(), RegError>;
    async fn refuse(self: Box<Self>, why: &str);
}

#[derive(Debug, thiserror::Error)]
#[error("delivery failed: {0}")]
pub struct DeliveryError(pub String);

#[async_trait]
pub trait ApproverRoute: Send + Sync + 'static {
    fn kind(&self) -> &'static str;
    /// Run the route's registration up to (not including) the commit.
    async fn register(
        &self,
        name: &str,
        owner: &dyn OwnerPrompt,
    ) -> Result<Box<dyn PendingRegistration>, RegError>;
    /// The full registry for this route (active and revoked): channel keys and
    /// who may write to BOGO's mailbox.
    async fn set_approvers(&self, all: &[ApproverRecord]) -> Result<(), DeliveryError>;
    /// Idempotent per `(a, r.req)`.
    async fn deliver(&self, a: &ApproverRecord, r: &Outbound) -> Result<(), DeliveryError>;
    /// Withdraw an undelivered request.
    async fn retract(&self, a: &ApproverRecord, req: &ReqId) -> Result<(), DeliveryError>;
    async fn notice(&self, a: &ApproverRecord, req: &ReqId, n: &Notice) -> Result<(), DeliveryError>;
    async fn boot(&self, a: &ApproverRecord, b: &BootNotice) -> Result<(), DeliveryError>;
    /// Send `registered {txId, approverId}` again (idempotent on the approver).
    async fn registered(&self, a: &ApproverRecord) -> Result<(), DeliveryError>;
    async fn revoked_ack(&self, a: &ApproverRecord) -> Result<(), DeliveryError>;
    /// Fetch, authenticate and hand over approver messages; acknowledge each
    /// only after `handler` returns `Ok`. Runs until the process ends.
    async fn run_inbound(&self, handler: Arc<dyn InboundHandler>);
}

/// An approval, denial or pause, as the decision logic receives it.
#[derive(Clone, Debug, PartialEq)]
pub enum Decision {
    Approval { approver: ApproverId, req: ReqId, alg: u16, proof: Vec<u8> },
    Denial { approver: ApproverId, req: ReqId, note: Option<String> },
    Pause { approver: ApproverId, agent: Vec<u8>, epoch: u64 },
}

/// What the hub sends after a decision took effect.
#[derive(Clone, Debug, PartialEq)]
pub enum Effect {
    Settled { req: ReqId, to: Vec<ApproverId> },
    Ended { req: ReqId, why: EndWhy, to: Vec<ApproverId> },
    Outcome { req: ReqId, outcome: String, to: Vec<ApproverId> },
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SinkError(pub String);

pub struct Committed {
    pub record: ApproverRecord,
    /// An active approver of the same name this registration replaced.
    pub replaced: Option<ApproverId>,
}

/// The decision logic and the log, as the hub sees them. Every method returns
/// only after its log entries are durable.
#[async_trait]
pub trait Sink: Send + Sync {
    async fn decision(&self, d: Decision) -> Result<Vec<Effect>, SinkError>;
    /// The approver removed this Mac. Idempotent: an approver already revoked
    /// is `Ok` with no effects.
    async fn removed(&self, approver: ApproverId) -> Result<Vec<Effect>, SinkError>;
    async fn route_update(
        &self,
        approver: ApproverId,
        seq: u64,
        route: serde_json::Value,
    ) -> Result<bool, SinkError>;
    /// The outcome word for `sync`, from the log.
    async fn outcome(&self, req: &ReqId) -> String;
    async fn commit(&self, name: &str, kind: &str, new: &NewApprover) -> Result<Committed, SinkError>;
}
