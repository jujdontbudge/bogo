//! The literal shape of `bogo.toml` (ARCHITECTURE §6). Unknown fields are refused everywhere.
//! Values that need checking (durations, sizes, policies, paths, secret references) stay raw
//! here and are validated in `lib.rs`.

use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    pub version: i64,
    pub server: Server,
    pub relay: Option<Relay>,
    pub apns: Option<Apns>,
    #[serde(default)]
    pub approvers: Approvers,
    #[serde(default)]
    pub upstreams: BTreeMap<String, Upstream>,
    pub defaults: Defaults,
    #[serde(default)]
    pub tools: BTreeMap<String, Tool>,
    #[serde(default)]
    pub agents: BTreeMap<String, Agent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub port: i64,
    pub max_body: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    pub url: String,
    pub max_message_age: Option<String>,
    pub mailbox_capacity: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    pub secret: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Apns {
    pub key: SecretRef,
    pub key_id: String,
    pub team_id: String,
    pub topic: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Approvers {
    pub iphone: Option<Iphone>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Iphone {
    pub app_id: String,
    pub app_attest: Vec<String>,
    pub approve_arm_delay: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    pub env: Option<BTreeMap<String, toml::Value>>,
    pub url: Option<String>,
    pub headers: Option<BTreeMap<String, toml::Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    pub policy: Option<String>,
    pub hide_denied: Option<bool>,
    pub max_pending: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub policy: Option<String>,
    pub justification: Option<String>,
    pub highlight: Option<BTreeMap<String, String>>,
    pub approvers: Option<Vec<String>>,
    pub require: Option<toml::Value>,
    pub on_deny: Option<String>,
    pub expiry: Option<String>,
    pub mode: Option<String>,
    pub filter_output: Option<Vec<String>>,
    pub filter_action: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    #[serde(default)]
    pub tools: BTreeMap<String, AgentTool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTool {
    pub policy: Option<String>,
    pub approvers: Option<Vec<String>>,
    pub require: Option<toml::Value>,
}
