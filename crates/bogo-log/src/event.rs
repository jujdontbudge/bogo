//! Log entry kinds. Credentials can never appear: no variant holds a `Secret`,
//! and agent entries carry only a token's SHA-256.
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Raw bytes written as lowercase hex.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hex(pub Vec<u8>);

impl Hex {
    pub fn of(bytes: &[u8]) -> Hex {
        Hex(bytes.to_vec())
    }
    pub fn text(&self) -> String {
        hex::encode(&self.0)
    }
}
impl Serialize for Hex {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(&self.0))
    }
}
impl<'de> Deserialize<'de> for Hex {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Hex, D::Error> {
        let s = String::deserialize(d)?;
        if s.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(serde::de::Error::custom("hex must be lowercase"));
        }
        hex::decode(&s).map(Hex).map_err(serde::de::Error::custom)
    }
}

/// What an approver registration commits. `route` and `attest` belong to the
/// route; the log stores them as written and never interprets them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApproverEntry {
    pub id: Hex,
    pub name: String,
    pub kind: String,
    pub alg: u16,
    pub sig_pk: Hex,
    pub tx_id: Hex,
    pub route: serde_json::Value,
    pub attest: serde_json::Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokedBy {
    Owner,
    /// The approver removed this Mac itself (`removed`).
    #[serde(rename = "self")]
    Approver,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LogEvent {
    Boot {
        boot_seq: u64,
        boot_id: Hex,
    },
    TailRecovered {
        torn_sha256: String,
        moved_to: String,
    },
    ApproverRegistered {
        approver: ApproverEntry,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        replaces: Option<Hex>,
    },
    ApproverRevoked {
        id: Hex,
        by: RevokedBy,
    },
    /// A route's delivery data changed (for the iPhone: a newer push token).
    RouteUpdated {
        id: Hex,
        route_seq: u64,
        route: serde_json::Value,
    },
    AgentAdded {
        id: Hex,
        name: String,
        token_sha256: String,
    },
    AgentRevoked {
        id: Hex,
    },
    /// `by` is "owner" or the approver's hex ID.
    AgentPaused {
        id: Hex,
        by: String,
    },
    /// This entry's `seq` becomes the agent's new pause epoch.
    AgentUnpaused {
        id: Hex,
    },
    RequestCreated {
        req: Hex,
        request: Hex,
        to: Vec<Hex>,
        k: u32,
        pause_epoch: u64,
    },
    Approval {
        req: Hex,
        approver: Hex,
        alg: u16,
        proof: Hex,
        counted: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        why: Option<String>,
    },
    Denial {
        req: Hex,
        approver: Hex,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        applied: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        why: Option<String>,
    },
    RequestSettled {
        req: Hex,
        approvers: Vec<Hex>,
    },
    Authorized {
        req: Hex,
    },
    RequestEnded {
        req: Hex,
        why: String,
    },
    Forwarded {
        req: Hex,
        registry_seq: u64,
    },
    NotSent {
        req: Hex,
    },
    Result {
        req: Hex,
        ok: bool,
    },
    /// A relay message that had no effect: unknown approver, stale epoch,
    /// another boot's request, a revoked approver.
    Ignored {
        what: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approver: Option<Hex>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req: Option<Hex>,
        why: String,
    },
    /// A kind written by a newer BOGO. It still chains; its fields are kept
    /// only in the raw line.
    #[serde(other)]
    Other,
}

impl LogEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            LogEvent::Boot { .. } => "boot",
            LogEvent::TailRecovered { .. } => "tail_recovered",
            LogEvent::ApproverRegistered { .. } => "approver_registered",
            LogEvent::ApproverRevoked { .. } => "approver_revoked",
            LogEvent::RouteUpdated { .. } => "route_updated",
            LogEvent::AgentAdded { .. } => "agent_added",
            LogEvent::AgentRevoked { .. } => "agent_revoked",
            LogEvent::AgentPaused { .. } => "agent_paused",
            LogEvent::AgentUnpaused { .. } => "agent_unpaused",
            LogEvent::RequestCreated { .. } => "request_created",
            LogEvent::Approval { .. } => "approval",
            LogEvent::Denial { .. } => "denial",
            LogEvent::RequestSettled { .. } => "request_settled",
            LogEvent::Authorized { .. } => "authorized",
            LogEvent::RequestEnded { .. } => "request_ended",
            LogEvent::Forwarded { .. } => "forwarded",
            LogEvent::NotSent { .. } => "not_sent",
            LogEvent::Result { .. } => "result",
            LogEvent::Ignored { .. } => "ignored",
            LogEvent::Other => "other",
        }
    }

    /// The request this entry is about, if any.
    pub fn req(&self) -> Option<&[u8]> {
        match self {
            LogEvent::RequestCreated { req, .. }
            | LogEvent::Approval { req, .. }
            | LogEvent::Denial { req, .. }
            | LogEvent::RequestSettled { req, .. }
            | LogEvent::Authorized { req }
            | LogEvent::RequestEnded { req, .. }
            | LogEvent::Forwarded { req, .. }
            | LogEvent::NotSent { req }
            | LogEvent::Result { req, .. } => Some(&req.0),
            LogEvent::Ignored { req: Some(req), .. } => Some(&req.0),
            _ => None,
        }
    }
}
