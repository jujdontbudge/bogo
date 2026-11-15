//! Typed mirrors of the Lean core's `Input` and `Output` (`lean/BogoCore/Core.lean`).
//! They carry data; every decision is the Lean core's.

use bogo_json::JVal;

pub type Bytes = Vec<u8>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKind {
    Allow,
    Approve,
    Deny,
}

/// The default for unlisted tools. It has no `Allow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultPolicy {
    Approve,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    AnyOf,
    KOfN(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyRule {
    AnyDenial,
    WhenUnreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Wait,
    PendingRetry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathElem {
    Key(String),
    Index(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Format {
    Text,
    MoneyMinor(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPolicy {
    pub kind: PolicyKind,
    pub justification_required: bool,
    pub hints: Vec<(Vec<PathElem>, Format)>,
    pub expiry_ms: Option<u64>,
    /// Eligible approvers by name; empty means every registered approver.
    pub approvers: Vec<String>,
    pub requirement: Requirement,
    pub deny_rule: DenyRule,
    pub mode: Mode,
}

impl ToolPolicy {
    /// A policy of this kind with nothing else set.
    pub fn new(kind: PolicyKind) -> ToolPolicy {
        ToolPolicy {
            kind,
            justification_required: false,
            hints: Vec::new(),
            expiry_ms: None,
            approvers: Vec::new(),
            requirement: Requirement::AnyOf,
            deny_rule: DenyRule::AnyDenial,
            mode: Mode::Wait,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOverride {
    pub agent_name: String,
    pub tool: String,
    pub kind: Option<PolicyKind>,
    pub approvers: Option<Vec<String>>,
    pub requirement: Option<Requirement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConfig {
    pub default_policy: DefaultPolicy,
    pub max_pending: u64,
    pub tools: Vec<(String, ToolPolicy)>,
    pub overrides: Vec<AgentOverride>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    pub name: String,
    pub upstream: String,
    pub tool: String,
    pub just_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approver {
    pub id: Bytes,
    pub name: String,
    pub alg: u16,
    pub pk: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    Configure {
        seq: u64,
        cfg: PolicyConfig,
        catalog: Vec<CatalogEntry>,
    },
    ApproverSet {
        seq: u64,
        approver: Approver,
    },
    ApproverRevoked {
        seq: u64,
        id: Bytes,
    },
    AgentSet {
        seq: u64,
        id: Bytes,
        name: String,
    },
    AgentRevoked {
        seq: u64,
        id: Bytes,
    },
    OwnerPause {
        seq: u64,
        agent: Bytes,
    },
    AgentUnpaused {
        seq: u64,
        id: Bytes,
    },
    OwnerCancel {
        req: Bytes,
    },
    SessionOpened {
        session: Bytes,
        agent: Bytes,
        client: Option<String>,
    },
    SessionClosed {
        session: Bytes,
    },
    Call {
        call: Bytes,
        session: Bytes,
        name: String,
        args: Option<JVal>,
        now_ms: u64,
    },
    CallEnded {
        call: Bytes,
    },
    Approval {
        approver: Bytes,
        req: Bytes,
        alg: u16,
        proof: Bytes,
        now_ms: u64,
    },
    Denial {
        approver: Bytes,
        req: Bytes,
        note: Option<String>,
    },
    PauseAgent {
        approver: Bytes,
        agent: Bytes,
        epoch: u64,
    },
    Dispatch {
        call: Bytes,
        now_ms: u64,
    },
    NotSent {
        call: Bytes,
    },
    Tick {
        now_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    Malformed,
    UnknownSession,
    UnknownAgent,
    RevokedAgent,
    PausedAgent,
    DuplicateCall,
    UnknownTool,
    DenyPolicy,
    JustificationRequired,
    NoEligibleApprover,
    Denied(Option<String>),
    EndedWithoutDecision,
    NotAuthorized,
    GateClosed,
    UpstreamUnavailable,
    Exhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    Denied,
    Cancelled,
    CallEnded,
    SessionClosed,
    AgentRevoked,
    AgentPaused,
    Expired,
    Unreachable,
    DispatchFailed,
    NotSent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreReason {
    Unknown,
    Settled,
    Expired,
    NotEligible,
    Duplicate,
    BadSignature,
    StaleEpoch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Authorized {
        call: Bytes,
        req: Option<Bytes>,
    },
    /// The only permission to write upstream.
    Forward {
        call: Bytes,
        req: Option<Bytes>,
        upstream: String,
        tool: String,
        args: Option<JVal>,
        registry_seq: u64,
    },
    Attach {
        call: Bytes,
        primary: Bytes,
    },
    Reject {
        call: Bytes,
        why: Rejection,
    },
    PendingApproval {
        call: Bytes,
    },
    Ask {
        req: Bytes,
        bytes: Bytes,
        to: Vec<Bytes>,
        group_key: Bytes,
        pause_epoch: u64,
    },
    Settled {
        req: Bytes,
        to: Vec<Bytes>,
    },
    Ended {
        req: Bytes,
        why: EndReason,
        to: Vec<Bytes>,
    },
    Counted {
        req: Bytes,
        approver: Bytes,
    },
    Ignored {
        req: Bytes,
        approver: Bytes,
        why: IgnoreReason,
    },
    FloodDropped {
        call: Bytes,
    },
    AgentPaused {
        agent: Bytes,
    },
}
