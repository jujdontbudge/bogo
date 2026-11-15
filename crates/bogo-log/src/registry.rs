//! The agent and approver registry, derived only from the log.
use crate::{ApproverEntry, Entry, Hex, LogEvent, RevokedBy};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApproverState {
    #[serde(flatten)]
    pub entry: ApproverEntry,
    pub revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<RevokedBy>,
    pub registered_seq: u64,
    #[serde(default)]
    pub route_seq: u64,
}

impl ApproverState {
    pub fn active(&self) -> bool {
        !self.revoked
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentState {
    pub id: Hex,
    pub name: String,
    pub token_sha256: String,
    pub revoked: bool,
    pub paused: bool,
    pub pause_epoch: u64,
}

/// `seq` is the last log entry applied.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Registry {
    pub seq: u64,
    /// Keyed by hex ID, in registration order of IDs.
    pub approvers: BTreeMap<String, ApproverState>,
    pub agents: BTreeMap<String, AgentState>,
}

impl Registry {
    pub fn replay<'a>(entries: impl IntoIterator<Item = &'a Entry>) -> Registry {
        let mut r = Registry::default();
        for e in entries {
            r.apply(e);
        }
        r
    }

    /// Apply one entry. Entries at or below `seq` are skipped, so replaying
    /// the tail after a checkpoint is safe.
    pub fn apply(&mut self, e: &Entry) {
        if e.seq <= self.seq {
            return;
        }
        self.seq = e.seq;
        match &e.event {
            LogEvent::ApproverRegistered { approver, replaces } => {
                if let Some(old) = replaces.as_ref().and_then(|id| self.approvers.get_mut(&id.text())) {
                    old.revoked = true;
                    old.revoked_by = Some(RevokedBy::Owner);
                }
                self.approvers.insert(
                    approver.id.text(),
                    ApproverState {
                        entry: approver.clone(),
                        revoked: false,
                        revoked_by: None,
                        registered_seq: e.seq,
                        route_seq: 0,
                    },
                );
            }
            LogEvent::ApproverRevoked { id, by } => {
                if let Some(a) = self.approvers.get_mut(&id.text())
                    && !a.revoked
                {
                    a.revoked = true;
                    a.revoked_by = Some(*by);
                }
            }
            LogEvent::RouteUpdated {
                id,
                route_seq,
                route,
            } => {
                if let Some(a) = self.approvers.get_mut(&id.text())
                    && *route_seq > a.route_seq
                {
                    a.route_seq = *route_seq;
                    a.entry.route = route.clone();
                }
            }
            LogEvent::AgentAdded {
                id,
                name,
                token_sha256,
            } => {
                self.agents.insert(
                    id.text(),
                    AgentState {
                        id: id.clone(),
                        name: name.clone(),
                        token_sha256: token_sha256.clone(),
                        revoked: false,
                        paused: false,
                        pause_epoch: e.seq,
                    },
                );
            }
            LogEvent::AgentRevoked { id } => {
                if let Some(a) = self.agents.get_mut(&id.text()) {
                    a.revoked = true;
                }
            }
            LogEvent::AgentPaused { id, .. } => {
                if let Some(a) = self.agents.get_mut(&id.text()) {
                    a.paused = true;
                }
            }
            LogEvent::AgentUnpaused { id } => {
                if let Some(a) = self.agents.get_mut(&id.text()) {
                    a.paused = false;
                    a.pause_epoch = e.seq;
                }
            }
            _ => {}
        }
    }

    pub fn approver(&self, id: &[u8]) -> Option<&ApproverState> {
        self.approvers.get(&hex::encode(id))
    }

    pub fn approver_named(&self, name: &str) -> Option<&ApproverState> {
        self.approvers
            .values()
            .filter(|a| a.entry.name == name && a.active())
            .max_by_key(|a| a.registered_seq)
    }

    pub fn active_approvers(&self) -> impl Iterator<Item = &ApproverState> {
        self.approvers.values().filter(|a| a.active())
    }
}
