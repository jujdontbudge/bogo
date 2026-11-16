//! Parsing and validating `~/.bogo/bogo.toml` and `~/.bogo/secrets.toml` (SPEC §3.4, §7;
//! ARCHITECTURE §6).
//!
//! * `version = 1`; any other version is refused.
//! * Unknown fields are refused everywhere, so a typo never silently does nothing.
//! * The default policy is `approve` or `deny`, never `allow`: a tool the owner never listed
//!   must never run without approval (SPEC Principle 5, ARCHITECTURE §11 question 11).
//! * Every `{ secret = "name" }` must name an entry in `secrets.toml`. Secret values never
//!   appear in `Debug` output or errors (see [`Secret`]).
//! * Values the spec leaves to the owner (`max_pending`, the relay's `max_message_age`, the
//!   iPhone `approve_arm_delay`) ship unset, and BOGO refuses to start until they are set.

#![forbid(unsafe_code)]

mod raw;
mod secret;

pub use secret::{MIN_SECRET_LEN, Secret, SecretValue, Secrets};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A refused configuration: which file, and what is wrong in plain words.
#[derive(Clone, PartialEq, Eq)]
pub struct ConfigError {
    file: &'static str,
    message: String,
}

impl ConfigError {
    pub(crate) fn new(file: &'static str, message: impl Into<String>) -> Self {
        ConfigError {
            file,
            message: message.into(),
        }
    }

    pub fn file(&self) -> &str {
        self.file
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.file, self.message)
    }
}

impl fmt::Debug for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for ConfigError {}

// ---------------------------------------------------------------------------------------------
// The validated configuration

/// The one `bogo.toml` version this BOGO reads.
pub const VERSION: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub server: Server,
    pub relay: Option<Relay>,
    pub apns: Option<Apns>,
    pub iphone: Option<IphoneApprover>,
    pub upstreams: BTreeMap<String, Upstream>,
    pub defaults: Defaults,
    /// Keyed by the namespaced tool name, `<upstream>__<tool>`, or by a policy key
    /// `<upstream>__<tool>[<arg>=<value>]` for one action of a tool with `select`. A key's
    /// entry is already merged with its base tool's.
    pub tools: BTreeMap<String, ToolPolicy>,
    /// Keyed by agent name, then by namespaced tool name or policy key. An override on a base
    /// tool is already copied to each of its keys, under any override the key has itself.
    pub agents: BTreeMap<String, BTreeMap<String, AgentOverride>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub port: u16,
    /// The parser's size limit for one request body, in bytes.
    pub max_body: u32,
    /// IPv4 literals accepted in the `Host` header besides `localhost` and `127.0.0.1`,
    /// such as the reference sandbox's gate address. Names are refused, so DNS
    /// rebinding can never match one.
    pub allowed_hosts: Vec<std::net::Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relay {
    pub url: String,
    /// How long the relay keeps an undelivered message. Never a request expiry.
    pub max_message_age: Duration,
    pub mailbox_capacity: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Apns {
    pub key: Secret,
    pub key_id: String,
    pub team_id: String,
    pub topic: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestEnvironment {
    Production,
    Development,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IphoneApprover {
    pub app_id: String,
    pub app_attest: Vec<AttestEnvironment>,
    /// How long Approve stays untappable after the review screen opens.
    pub approve_arm_delay: Duration,
}

/// An environment variable or header value: plain text, or a secret by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Plain(String),
    Secret(Secret),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    /// Started as a child process, spoken to over stdio.
    Local {
        command: String,
        args: Vec<String>,
        env: BTreeMap<String, Value>,
    },
    /// Reached over Streamable HTTP.
    Remote {
        url: String,
        headers: BTreeMap<String, Value>,
    },
}

/// A tool's policy. Mirrors Lean's `PolicyKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Allow,
    Approve,
    Deny,
}

/// The policy for tools the owner never listed. Mirrors Lean's `DefaultPolicy`: it has no
/// `Allow`, so no configuration can make an unlisted tool run without approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultPolicy {
    Approve,
    Deny,
}

impl From<DefaultPolicy> for Policy {
    fn from(d: DefaultPolicy) -> Policy {
        match d {
            DefaultPolicy::Approve => Policy::Approve,
            DefaultPolicy::Deny => Policy::Deny,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Defaults {
    pub policy: DefaultPolicy,
    pub hide_denied: bool,
    /// Per-agent flood limit: live (pending plus settled) requests at once.
    pub max_pending: u32,
}

/// One step into the arguments. Mirrors Lean's `PathElem`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathElem {
    Key(String),
    Index(u32),
}

/// How the phone formats a highlighted field. Mirrors Lean's `Format`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Format {
    Text,
    /// An integer amount in the currency's minor unit; `"usd_cents"` is `MoneyMinor("USD")`.
    MoneyMinor(String),
}

/// Mirrors Lean's `Requirement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    AnyOf,
    KOfN(u32),
}

/// Mirrors Lean's `DenyRule`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyRule {
    AnyDenial,
    WhenUnreachable,
}

/// Mirrors Lean's `Mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Wait,
    PendingRetry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    Strip,
    Redact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPolicy {
    /// The tool's own policy; the default policy when the entry sets none.
    pub policy: Policy,
    pub justification_required: bool,
    pub hints: Vec<(Vec<PathElem>, Format)>,
    /// Eligible approvers by name. Empty means every registered approver.
    pub approvers: Vec<String>,
    pub requirement: Requirement,
    pub deny_rule: DenyRule,
    pub expiry: Option<Duration>,
    pub mode: Mode,
    pub filter_output: Vec<String>,
    pub filter_action: FilterAction,
    /// The top-level argument whose string value picks a per-action entry (`[tools."X[arg=v]"]`).
    /// Set only on a base tool; a key's own entry has `None`.
    pub select: Option<String>,
}

impl ToolPolicy {
    /// What an entry that sets nothing means: `policy` from `[defaults]`, everything else off.
    fn unset(policy: Policy) -> ToolPolicy {
        ToolPolicy {
            policy,
            justification_required: false,
            hints: Vec::new(),
            approvers: Vec::new(),
            requirement: Requirement::AnyOf,
            deny_rule: DenyRule::AnyDenial,
            expiry: None,
            mode: Mode::Wait,
            filter_output: Vec::new(),
            filter_action: FilterAction::Strip,
            select: None,
        }
    }
}

/// A per-agent override. Mirrors Lean's `AgentOverride`: unset fields fall back to the tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOverride {
    pub policy: Option<Policy>,
    pub approvers: Option<Vec<String>>,
    pub requirement: Option<Requirement>,
}

// ---------------------------------------------------------------------------------------------
// Loading

impl Config {
    /// The name the policy of a call to tool `name` is looked up by. When the tool has `select`
    /// and the call's selected argument is a string with an entry of its own, that is the policy
    /// key `name[arg=value]`; otherwise it is `name` itself. `selected` returns the call's
    /// top-level argument of that name when it is a JSON string, and `None` otherwise.
    ///
    /// The agent chooses the argument, so a value without an entry, a non-string or a missing
    /// argument always lands on the base tool's policy, never on another key.
    pub fn policy_key<'a>(
        &self,
        name: &str,
        selected: impl FnOnce(&str) -> Option<&'a str>,
    ) -> String {
        if let Some(arg) = self.tools.get(name).and_then(|t| t.select.as_deref())
            && let Some(value) = selected(arg)
        {
            let key = format!("{name}[{arg}={value}]");
            if self.tools.contains_key(&key) {
                return key;
            }
        }
        name.to_owned()
    }

    /// The base tool and every policy key configured for one of its actions.
    pub fn policy_names<'a>(&'a self, base: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        let prefix = format!("{base}[");
        let keys = self
            .tools
            .range(prefix.clone()..)
            .map(|(k, _)| k.as_str())
            .take_while(move |k| k.starts_with(&prefix));
        std::iter::once(base).chain(keys)
    }

    /// The policy one agent has for a tool name or policy key: its override, else the tool's
    /// entry, else the default policy.
    pub fn effective_policy(&self, agent: &str, name: &str) -> Policy {
        self.agents
            .get(agent)
            .and_then(|a| a.get(name))
            .and_then(|o| o.policy)
            .unwrap_or_else(|| {
                self.tools
                    .get(name)
                    .map_or(self.defaults.policy.into(), |t| t.policy)
            })
    }

    /// Load `bogo.toml` and `secrets.toml` from files. `home` expands `~/` in path secrets.
    pub fn load(
        bogo_toml: &Path,
        secrets_toml: &Path,
        home: Option<&Path>,
    ) -> Result<Config, ConfigError> {
        let secrets = Secrets::load(secrets_toml, home)?;
        let text = std::fs::read_to_string(bogo_toml).map_err(|e| {
            ConfigError::new(BOGO, format!("cannot read {}: {e}", bogo_toml.display()))
        })?;
        Config::parse(&text, &secrets)
    }

    /// Load `~/.bogo/bogo.toml` and `~/.bogo/secrets.toml`.
    pub fn load_default() -> Result<Config, ConfigError> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| ConfigError::new(BOGO, "HOME is not set, so ~/.bogo cannot be found"))?;
        let dir = home.join(".bogo");
        Config::load(
            &dir.join("bogo.toml"),
            &dir.join("secrets.toml"),
            Some(&home),
        )
    }

    /// Parse and validate the text of `bogo.toml` against already-loaded secrets.
    pub fn parse(text: &str, secrets: &Secrets) -> Result<Config, ConfigError> {
        // The version first, so a newer file is reported as a version, not as unknown fields.
        let table: toml::Table = text
            .parse()
            .map_err(|e: toml::de::Error| err(e.to_string()))?;
        match table.get("version") {
            None => return Err(err("`version` is missing; this BOGO reads `version = 1`")),
            Some(toml::Value::Integer(VERSION)) => {}
            Some(other) => {
                return Err(err(format!(
                    "version {other} is not supported; this BOGO reads `version = {VERSION}`"
                )));
            }
        }
        let file: raw::File = toml::from_str(text).map_err(|e| err(e.to_string()))?;
        Validator { secrets }.config(file)
    }
}

const BOGO: &str = "bogo.toml";

fn err(message: impl Into<String>) -> ConfigError {
    ConfigError::new(BOGO, message)
}

struct Validator<'a> {
    secrets: &'a Secrets,
}

impl Validator<'_> {
    fn config(&self, f: raw::File) -> Result<Config, ConfigError> {
        debug_assert_eq!(f.version, VERSION);
        let server = self.server(f.server)?;
        let relay = f.relay.map(|r| self.relay(r)).transpose()?;
        let apns = f.apns.map(|a| self.apns(a)).transpose()?;
        let iphone = f.approvers.iphone.map(|i| self.iphone(i)).transpose()?;
        if iphone.is_some() {
            if relay.is_none() {
                return Err(err(
                    "[approvers.iphone] needs a [relay] section to reach the phone",
                ));
            }
            if apns.is_none() && !cfg!(feature = "test-registration") {
                return Err(err(
                    "[approvers.iphone] needs an [apns] section to wake the phone",
                ));
            }
        }
        let mut upstreams = BTreeMap::new();
        for (name, u) in f.upstreams {
            let u = self.upstream(&name, u)?;
            upstreams.insert(name, u);
        }
        let defaults = self.defaults(f.defaults)?;
        let mut tools = BTreeMap::new();
        let mut actions = Vec::new();
        for (name, t) in f.tools {
            let at = format!("[tools.\"{}\"]", name.escape_debug());
            if name.contains('[') {
                actions.push((name, at, t));
                continue;
            }
            check_tool_name(&name, &upstreams, &at)?;
            let t = self.tool(&at, t, &ToolPolicy::unset(defaults.policy.into()))?;
            tools.insert(name, t);
        }
        // A per-action entry starts from its base tool's, so it must come after all bases.
        for (name, at, t) in actions {
            let (base, arg, value) = split_key(&name).ok_or_else(|| {
                err(format!(
                    "{at}: a per-action entry is `<upstream>__<tool>[<arg>=<value>]`, e.g. \
                     \"stripe__call_write_tool[name=spend-request_retrieve]\""
                ))
            })?;
            check_tool_name(base, &upstreams, &at)?;
            let Some(inherit) = tools.get(base).filter(|b| b.select.as_deref() == Some(arg)) else {
                return Err(err(format!(
                    "{at}: [tools.\"{base}\"] needs select = \"{}\" for per-action entries",
                    arg.escape_debug()
                )));
            };
            if value.is_empty() || value.chars().any(char::is_control) {
                return Err(err(format!(
                    "{at}: the value after `=` must be nonempty and have no control characters"
                )));
            }
            for (field, set) in [
                ("select", t.select.is_some()),
                ("mode", t.mode.is_some()),
                ("filter_output", t.filter_output.is_some()),
                ("filter_action", t.filter_action.is_some()),
            ] {
                if set {
                    return Err(err(format!(
                        "{at}: `{field}` belongs on [tools.\"{base}\"]; every action of the tool shares it"
                    )));
                }
            }
            let mut t = self.tool(&at, t, inherit)?;
            t.select = None;
            add_selector_hint(&mut t.hints, arg);
            tools.insert(name, t);
        }
        let mut agents = BTreeMap::new();
        for (agent, a) in f.agents {
            if agent.trim().is_empty() {
                return Err(err("[agents] has an agent with an empty name"));
            }
            let mut overrides = BTreeMap::new();
            for (name, o) in a.tools {
                let at = format!(
                    "[agents.\"{}\".tools.\"{}\"]",
                    agent.escape_debug(),
                    name.escape_debug()
                );
                if name.contains('[') {
                    if !tools.contains_key(&name) {
                        return Err(err(format!(
                            "{at}: there is no [tools.\"{}\"] for this action",
                            name.escape_debug()
                        )));
                    }
                } else {
                    check_tool_name(&name, &upstreams, &at)?;
                }
                overrides.insert(name, self.agent_override(&at, o)?);
            }
            // An agent's override of a tool covers every action of it, so choosing an action
            // never escapes it; the action's own override, if any, wins field by field.
            for key in tools.keys().filter(|k| k.contains('[')) {
                let Some(base) = key.split_once('[').and_then(|(b, _)| overrides.get(b)) else {
                    continue;
                };
                let merged = match overrides.get(key) {
                    Some(own) => AgentOverride {
                        policy: own.policy.or(base.policy),
                        approvers: own.approvers.clone().or_else(|| base.approvers.clone()),
                        requirement: own.requirement.or(base.requirement),
                    },
                    None => base.clone(),
                };
                overrides.insert(key.clone(), merged);
            }
            agents.insert(agent, overrides);
        }
        Ok(Config {
            server,
            relay,
            apns,
            iphone,
            upstreams,
            defaults,
            tools,
            agents,
        })
    }

    fn server(&self, s: raw::Server) -> Result<Server, ConfigError> {
        let port = u16::try_from(s.port)
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(|| {
                err(format!(
                    "[server] port = {} is not a port (1–65535)",
                    s.port
                ))
            })?;
        let max_body = match s.max_body {
            None => 1 << 20,
            Some(text) => parse_size(&text)
                .filter(|&n| n > 0 && n <= u64::from(u32::MAX))
                .ok_or_else(|| {
                    err(format!(
                        "[server] max_body = {text:?} is not a size like \"1MiB\" (from 1 byte up to 4GiB − 1)"
                    ))
                })? as u32,
        };
        let allowed_hosts = s
            .allowed_hosts
            .unwrap_or_default()
            .into_iter()
            .map(|h| {
                h.parse::<std::net::Ipv4Addr>()
                    .ok()
                    .filter(|ip| !ip.is_unspecified() && !ip.is_broadcast())
                    .ok_or_else(|| {
                        err(format!(
                            "[server] allowed_hosts entry {h:?} is not an IPv4 address like \"172.30.0.2\"; host names are refused"
                        ))
                    })
            })
            .collect::<Result<_, _>>()?;
        Ok(Server {
            port,
            max_body,
            allowed_hosts,
        })
    }

    fn relay(&self, r: raw::Relay) -> Result<Relay, ConfigError> {
        if !r.url.starts_with("https://") || r.url.len() <= "https://".len() {
            return Err(err(format!(
                "[relay] url = {:?} must be an https:// URL",
                r.url
            )));
        }
        let max_message_age = owner_sets_duration(r.max_message_age, "[relay] max_message_age")?;
        let mailbox_capacity = r.mailbox_capacity
            .and_then(|v| u64::try_from(v).ok())
            .filter(|v| *v > 0)
            .ok_or_else(|| err("[relay] mailbox_capacity is not set or is not positive; BOGO will not start until it is set"))?;
        Ok(Relay {
            url: r.url,
            max_message_age,
            mailbox_capacity,
        })
    }

    fn apns(&self, a: raw::Apns) -> Result<Apns, ConfigError> {
        let key = self.secret(&a.key.secret, "[apns] key")?;
        for (field, v) in [
            ("key_id", &a.key_id),
            ("team_id", &a.team_id),
            ("topic", &a.topic),
        ] {
            if v.trim().is_empty() {
                return Err(err(format!("[apns] {field} is empty")));
            }
        }
        Ok(Apns {
            key,
            key_id: a.key_id,
            team_id: a.team_id,
            topic: a.topic,
        })
    }

    fn iphone(&self, i: raw::Iphone) -> Result<IphoneApprover, ConfigError> {
        if i.app_id.trim().is_empty() {
            return Err(err("[approvers.iphone] app_id is empty"));
        }
        if i.app_attest.is_empty() {
            return Err(err(
                "[approvers.iphone] app_attest is empty; list \"production\" (and \"development\" only for development builds)",
            ));
        }
        let mut envs = Vec::new();
        for e in &i.app_attest {
            let env = match e.as_str() {
                "production" => AttestEnvironment::Production,
                "development" => AttestEnvironment::Development,
                other => {
                    return Err(err(format!(
                        "[approvers.iphone] app_attest has {other:?}; use \"production\" or \"development\""
                    )));
                }
            };
            if envs.contains(&env) {
                return Err(err(format!(
                    "[approvers.iphone] app_attest lists {e:?} twice"
                )));
            }
            envs.push(env);
        }
        let delay =
            owner_sets_duration(i.approve_arm_delay, "[approvers.iphone] approve_arm_delay")?;
        Ok(IphoneApprover {
            app_id: i.app_id,
            app_attest: envs,
            approve_arm_delay: delay,
        })
    }

    fn upstream(&self, name: &str, u: raw::Upstream) -> Result<Upstream, ConfigError> {
        let at = format!("[upstreams.{}]", name.escape_debug());
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(err(format!(
                "{at}: upstream names use only a–z, 0–9 and `-`, so `<upstream>__<tool>` splits one way"
            )));
        }
        match (u.command, u.url) {
            (Some(command), None) => {
                if u.headers.is_some() {
                    return Err(err(format!(
                        "{at}: `headers` is for remote upstreams (with `url`)"
                    )));
                }
                if command.trim().is_empty() {
                    return Err(err(format!("{at}: command is empty")));
                }
                let env = self.values(&at, "env", u.env.unwrap_or_default())?;
                Ok(Upstream::Local {
                    command,
                    args: u.args.unwrap_or_default(),
                    env,
                })
            }
            (None, Some(url)) => {
                if u.args.is_some() || u.env.is_some() {
                    return Err(err(format!(
                        "{at}: `args` and `env` are for local upstreams (with `command`)"
                    )));
                }
                if !(url.starts_with("https://") || url.starts_with("http://")) {
                    return Err(err(format!(
                        "{at}: url = {url:?} must be an http(s):// URL"
                    )));
                }
                let headers = self.values(&at, "headers", u.headers.unwrap_or_default())?;
                Ok(Upstream::Remote { url, headers })
            }
            (Some(_), Some(_)) => Err(err(format!(
                "{at}: set either `command` or `url`, not both"
            ))),
            (None, None) => Err(err(format!(
                "{at}: set `command` (local) or `url` (remote)"
            ))),
        }
    }

    /// `env` or `headers`: each value is a string or `{ secret = "name" }`.
    fn values(
        &self,
        at: &str,
        field: &str,
        m: BTreeMap<String, toml::Value>,
    ) -> Result<BTreeMap<String, Value>, ConfigError> {
        let mut out = BTreeMap::new();
        for (k, v) in m {
            let what = format!("{at} {field}.{}", k.escape_debug());
            let v = match v {
                toml::Value::String(s) => Value::Plain(s),
                toml::Value::Table(t) => {
                    if let Some(extra) = t.keys().find(|x| x.as_str() != "secret") {
                        return Err(err(format!(
                            "{what}: unknown field `{}` (expected {{ secret = \"name\" }})",
                            extra.escape_debug()
                        )));
                    }
                    match t.get("secret") {
                        Some(toml::Value::String(name)) => Value::Secret(self.secret(name, &what)?),
                        _ => return Err(err(format!("{what}: expected {{ secret = \"name\" }}"))),
                    }
                }
                other => {
                    return Err(err(format!(
                        "{what} must be a string or {{ secret = \"name\" }} (found: {})",
                        other.type_str()
                    )));
                }
            };
            out.insert(k, v);
        }
        Ok(out)
    }

    fn secret(&self, name: &str, what: &str) -> Result<Secret, ConfigError> {
        self.secrets.get(name).cloned().ok_or_else(|| {
            err(format!(
                "{what} refers to secret `{}`, which is not in secrets.toml",
                name.escape_debug()
            ))
        })
    }

    fn defaults(&self, d: raw::Defaults) -> Result<Defaults, ConfigError> {
        let policy = match d.policy.as_deref() {
            None | Some("approve") => DefaultPolicy::Approve,
            Some("deny") => DefaultPolicy::Deny,
            Some("allow") => {
                return Err(err(
                    "[defaults] policy = \"allow\" is refused: a tool you never listed must never run \
                     without your approval. Use \"approve\" or \"deny\", and set policy = \"allow\" \
                     on the [tools.\"…\"] entries you want open.",
                ));
            }
            Some(other) => {
                return Err(err(format!(
                    "[defaults] policy = {other:?} is not a policy; use \"approve\" or \"deny\""
                )));
            }
        };
        let max_pending = match d.max_pending {
            None => {
                return Err(err(
                    "[defaults] max_pending is not set: choose how many requests one agent may have \
                     waiting at once (the flood limit). BOGO will not start until it is set.",
                ));
            }
            Some(n) => u32::try_from(n).ok().filter(|&n| n >= 1).ok_or_else(|| {
                err(format!(
                    "[defaults] max_pending = {n} must be a whole number of at least 1"
                ))
            })?,
        };
        Ok(Defaults {
            policy,
            hide_denied: d.hide_denied.unwrap_or(true),
            max_pending,
        })
    }

    fn tool(
        &self,
        at: &str,
        t: raw::Tool,
        inherit: &ToolPolicy,
    ) -> Result<ToolPolicy, ConfigError> {
        let policy = match t.policy.as_deref() {
            None => inherit.policy,
            Some(p) => parse_policy(p).ok_or_else(|| {
                err(format!(
                    "{at} policy = {p:?} is not a policy; use \"allow\", \"approve\" or \"deny\""
                ))
            })?,
        };
        let justification_required = match t.justification.as_deref() {
            None => inherit.justification_required,
            Some("optional") => false,
            Some("required") => true,
            Some(other) => {
                return Err(err(format!(
                    "{at} justification = {other:?}; use \"required\" or \"optional\""
                )));
            }
        };
        let mut hints = if t.highlight.is_some() {
            Vec::new()
        } else {
            inherit.hints.clone()
        };
        for (path, fmt) in t.highlight.unwrap_or_default() {
            let p = parse_path(&path).ok_or_else(|| {
                err(format!(
                    "{at} highlight key {path:?} is not a field path like \"amount\", \"payment.amount\" or \"items[0].price\""
                ))
            })?;
            let f = parse_format(&fmt).ok_or_else(|| {
                err(format!(
                    "{at} highlight {path:?} = {fmt:?}; use \"text\", \"usd_cents\" or \"<iso4217>_minor\" (e.g. \"eur_minor\")"
                ))
            })?;
            hints.push((p, f));
        }
        let approvers = match t.approvers {
            None => inherit.approvers.clone(),
            Some(a) => approver_names(at, a)?,
        };
        let requirement = match t.require {
            None => inherit.requirement,
            Some(v) => parse_requirement(at, &v)?,
        };
        if let Requirement::KOfN(k) = requirement
            && !approvers.is_empty()
            && k as usize > approvers.len()
        {
            return Err(err(format!(
                "{at} requires {k} approvals but lists only {} approver(s)",
                approvers.len()
            )));
        }
        let deny_rule = match t.on_deny.as_deref() {
            None => inherit.deny_rule,
            Some("any") => DenyRule::AnyDenial,
            Some("when_unreachable") => DenyRule::WhenUnreachable,
            Some(other) => {
                return Err(err(format!(
                    "{at} on_deny = {other:?}; use \"any\" or \"when_unreachable\""
                )));
            }
        };
        let expiry = match t.expiry {
            None => inherit.expiry,
            Some(e) => Some(parse_duration(&e).filter(|d| !d.is_zero()).ok_or_else(|| {
                err(format!(
                    "{at} expiry = {e:?} is not a duration like \"10m\" (ms, s, m, h or d)"
                ))
            })?),
        };
        let mode = match t.mode.as_deref() {
            None => inherit.mode,
            Some("wait") => Mode::Wait,
            Some("pending_retry") => Mode::PendingRetry,
            Some(other) => {
                return Err(err(format!(
                    "{at} mode = {other:?}; use \"wait\" or \"pending_retry\""
                )));
            }
        };
        let filter_output = t
            .filter_output
            .unwrap_or_else(|| inherit.filter_output.clone());
        if let Some(bad) = filter_output
            .iter()
            .find(|p| p.is_empty() || p.split('.').any(str::is_empty))
        {
            return Err(err(format!(
                "{at} filter_output has an empty field path {bad:?}"
            )));
        }
        let filter_action = match t.filter_action.as_deref() {
            None => inherit.filter_action,
            Some("strip") => FilterAction::Strip,
            Some("redact") => FilterAction::Redact,
            Some(other) => {
                return Err(err(format!(
                    "{at} filter_action = {other:?}; use \"strip\" or \"redact\""
                )));
            }
        };
        let select = match t.select {
            None => inherit.select.clone(),
            Some(arg) if valid_selector(&arg) => {
                add_selector_hint(&mut hints, &arg);
                Some(arg)
            }
            Some(arg) => {
                return Err(err(format!(
                    "{at} select = {arg:?} must name one top-level argument using only A–Z, a–z, 0–9, `_`, `.` and `-`"
                )));
            }
        };
        Ok(ToolPolicy {
            policy,
            justification_required,
            hints,
            approvers,
            requirement,
            deny_rule,
            expiry,
            mode,
            filter_output,
            filter_action,
            select,
        })
    }

    fn agent_override(&self, at: &str, o: raw::AgentTool) -> Result<AgentOverride, ConfigError> {
        let policy = match o.policy.as_deref() {
            None => None,
            Some(p) => Some(parse_policy(p).ok_or_else(|| {
                err(format!(
                    "{at} policy = {p:?} is not a policy; use \"allow\", \"approve\" or \"deny\""
                ))
            })?),
        };
        let approvers = o.approvers.map(|a| approver_names(at, a)).transpose()?;
        let requirement = o.require.map(|v| parse_requirement(at, &v)).transpose()?;
        if policy.is_none() && approvers.is_none() && requirement.is_none() {
            return Err(err(format!(
                "{at} is empty; set policy, approvers or require"
            )));
        }
        Ok(AgentOverride {
            policy,
            approvers,
            requirement,
        })
    }
}

/// Values the spec leaves to the owner: unset is an error that says what to choose.
fn owner_sets_duration(v: Option<String>, what: &str) -> Result<Duration, ConfigError> {
    let Some(text) = v else {
        return Err(err(format!(
            "{what} is not set. BOGO ships it unset on purpose; choose a value (for example \"2s\") \
             and BOGO will start."
        )));
    };
    parse_duration(&text)
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            err(format!(
                "{what} = {text:?} is not a duration like \"2s\" (ms, s, m, h or d)"
            ))
        })
}

fn check_tool_name(
    name: &str,
    upstreams: &BTreeMap<String, Upstream>,
    at: &str,
) -> Result<(), ConfigError> {
    let Some((upstream, tool)) = name.split_once("__") else {
        return Err(err(format!(
            "{at}: tool names are `<upstream>__<tool>`, e.g. \"stripe__create_payment_link\""
        )));
    };
    if !upstreams.contains_key(upstream) {
        return Err(err(format!(
            "{at}: there is no upstream `{}`",
            upstream.escape_debug()
        )));
    }
    if tool.is_empty()
        || !tool
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Err(err(format!(
            "{at}: the tool part may use only A–Z, a–z, 0–9, `_`, `.` and `-`"
        )));
    }
    Ok(())
}

/// `stripe__call_write_tool[name=spend-request_retrieve]` → base, argument and value.
fn split_key(name: &str) -> Option<(&str, &str, &str)> {
    let (base, rest) = name.split_once('[')?;
    let (arg, value) = rest.strip_suffix(']')?.split_once('=')?;
    valid_selector(arg).then_some((base, arg, value))
}

fn valid_selector(arg: &str) -> bool {
    !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// The approver sees which action a call asks for first: the selected argument leads the
/// highlighted fields, as text, unless the owner already highlights it.
fn add_selector_hint(hints: &mut Vec<(Vec<PathElem>, Format)>, arg: &str) {
    let path = vec![PathElem::Key(arg.to_owned())];
    if !hints.iter().any(|(p, _)| *p == path) {
        hints.insert(0, (path, Format::Text));
    }
}

fn parse_policy(p: &str) -> Option<Policy> {
    match p {
        "allow" => Some(Policy::Allow),
        "approve" => Some(Policy::Approve),
        "deny" => Some(Policy::Deny),
        _ => None,
    }
}

fn approver_names(at: &str, names: Vec<String>) -> Result<Vec<String>, ConfigError> {
    let mut seen = BTreeSet::new();
    for n in &names {
        if n.trim().is_empty() {
            return Err(err(format!("{at} approvers has an empty name")));
        }
        if !seen.insert(n.as_str()) {
            return Err(err(format!("{at} approvers lists {n:?} twice")));
        }
    }
    Ok(names)
}

/// `"any"` or `{ k = N }` with N ≥ 1.
fn parse_requirement(at: &str, v: &toml::Value) -> Result<Requirement, ConfigError> {
    let bad = || {
        err(format!(
            "{at} require must be \"any\" or {{ k = N }} with N at least 1"
        ))
    };
    match v {
        toml::Value::String(s) if s == "any" => Ok(Requirement::AnyOf),
        toml::Value::Table(t) => {
            if t.keys().any(|k| k != "k") {
                return Err(bad());
            }
            match t.get("k") {
                Some(toml::Value::Integer(k)) => u32::try_from(*k)
                    .ok()
                    .filter(|&k| k >= 1)
                    .map(Requirement::KOfN)
                    .ok_or_else(bad),
                _ => Err(bad()),
            }
        }
        _ => Err(bad()),
    }
}

/// `"text"`, `"usd_cents"`, or `"<iso4217>_minor"` such as `"eur_minor"`.
fn parse_format(f: &str) -> Option<Format> {
    match f {
        "text" => Some(Format::Text),
        "usd_cents" => Some(Format::MoneyMinor("USD".to_owned())),
        _ => {
            let code = f.strip_suffix("_minor")?;
            (code.len() == 3 && code.bytes().all(|b| b.is_ascii_lowercase()))
                .then(|| Format::MoneyMinor(code.to_ascii_uppercase()))
        }
    }
}

/// `amount`, `payment.amount`, `items[0].price`, `[2]`.
fn parse_path(p: &str) -> Option<Vec<PathElem>> {
    let mut out = Vec::new();
    for seg in p.split('.') {
        let (key, mut rest) = match seg.find('[') {
            Some(i) => (&seg[..i], &seg[i..]),
            None => (seg, ""),
        };
        if key.contains(']') {
            return None;
        }
        if !key.is_empty() {
            out.push(PathElem::Key(key.to_owned()));
        } else if rest.is_empty() {
            return None;
        }
        while !rest.is_empty() {
            let close = rest.find(']')?;
            let digits = rest.strip_prefix('[')?.get(..close - 1)?;
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            out.push(PathElem::Index(digits.parse().ok()?));
            rest = &rest[close + 1..];
        }
    }
    Some(out)
}

/// `"500ms"`, `"30s"`, `"10m"`, `"2h"`, `"1d"`.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let split = s.find(|c: char| !c.is_ascii_digit())?;
    let (n, unit) = s.split_at(split);
    if n.is_empty() {
        return None;
    }
    let n: u64 = n.parse().ok()?;
    let ms = match unit {
        "ms" => Some(n),
        "s" => n.checked_mul(1000),
        "m" => n.checked_mul(60_000),
        "h" => n.checked_mul(3_600_000),
        "d" => n.checked_mul(86_400_000),
        _ => None,
    }?;
    Some(Duration::from_millis(ms))
}

/// `"1048576"`, `"512KiB"`, `"1MiB"`, `"1GiB"` (binary units only).
pub fn parse_size(s: &str) -> Option<u64> {
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (n, unit) = s.split_at(split);
    if n.is_empty() {
        return None;
    }
    let n: u64 = n.parse().ok()?;
    match unit {
        "" | "B" => Some(n),
        "KiB" => n.checked_mul(1 << 10),
        "MiB" => n.checked_mul(1 << 20),
        "GiB" => n.checked_mul(1 << 30),
        _ => None,
    }
}
