use bogo_config as c;
use bogo_core as k;
pub fn kind(p: c::Policy) -> k::PolicyKind {
    match p {
        c::Policy::Allow => k::PolicyKind::Allow,
        c::Policy::Approve => k::PolicyKind::Approve,
        c::Policy::Deny => k::PolicyKind::Deny,
    }
}
pub fn requirement(r: c::Requirement) -> k::Requirement {
    match r {
        c::Requirement::AnyOf => k::Requirement::AnyOf,
        c::Requirement::KOfN(k) => k::Requirement::KOfN(k),
    }
}
pub fn mode(m: c::Mode) -> k::Mode {
    match m {
        c::Mode::Wait => k::Mode::Wait,
        c::Mode::PendingRetry => k::Mode::PendingRetry,
    }
}
pub fn config(c: &c::Config) -> k::PolicyConfig {
    k::PolicyConfig {
        default_policy: match c.defaults.policy {
            c::DefaultPolicy::Approve => k::DefaultPolicy::Approve,
            c::DefaultPolicy::Deny => k::DefaultPolicy::Deny,
        },
        max_pending: c.defaults.max_pending.into(),
        tools: c
            .tools
            .iter()
            .map(|(n, t)| {
                (
                    n.clone(),
                    k::ToolPolicy {
                        kind: kind(t.policy),
                        justification_required: t.justification_required,
                        hints: t
                            .hints
                            .iter()
                            .map(|(p, f)| {
                                (
                                    p.iter()
                                        .map(|e| match e {
                                            c::PathElem::Key(s) => k::PathElem::Key(s.clone()),
                                            c::PathElem::Index(i) => k::PathElem::Index(*i),
                                        })
                                        .collect(),
                                    match f {
                                        c::Format::Text => k::Format::Text,
                                        c::Format::MoneyMinor(s) => {
                                            k::Format::MoneyMinor(s.clone())
                                        }
                                    },
                                )
                            })
                            .collect(),
                        expiry_ms: t.expiry.map(|d| d.as_millis() as u64),
                        approvers: t.approvers.clone(),
                        requirement: requirement(t.requirement),
                        deny_rule: match t.deny_rule {
                            c::DenyRule::AnyDenial => k::DenyRule::AnyDenial,
                            c::DenyRule::WhenUnreachable => k::DenyRule::WhenUnreachable,
                        },
                        mode: mode(t.mode),
                    },
                )
            })
            .collect(),
        overrides: c
            .agents
            .iter()
            .flat_map(|(a, ts)| {
                ts.iter().map(move |(n, o)| k::AgentOverride {
                    agent_name: a.clone(),
                    tool: n.clone(),
                    kind: o.policy.map(kind),
                    approvers: o.approvers.clone(),
                    requirement: o.requirement.map(requirement),
                })
            })
            .collect(),
    }
}
pub fn effective(c: &c::Config, agent: &str, tool: &str) -> c::Policy {
    c.effective_policy(agent, tool)
}
