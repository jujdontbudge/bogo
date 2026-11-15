//! Unmodified upstream MCP servers, with the final dispatch inside the exact transports.
//! Argument trees come only from Gate::dispatch; rmcp arguments are never inspected.
mod catalog;
mod child;
mod http;
mod manager;
mod secrets;
mod wire;
pub use catalog::{Catalog, CatalogTool, widen};
pub use child::ExactChildTransport;
pub use http::ExactHttpClient;
pub use manager::Manager;
pub use secrets::Scrubber;

use bogo_json::JVal;
use futures::future::BoxFuture;

pub const CALL_MARKER: &str = "si.eilmer.bogo/call";
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CallId(pub String);
/// Contains the core's authoritative destination and exact, justification-free arguments.
/// The daemon adapts its core channel here; it must consume IDs once and sample its
/// sleep-aware monotonic clock when processing dispatch, not when staging the call.
pub struct Forward {
    pub upstream: String,
    pub tool: String,
    pub arguments: Option<JVal>,
}
pub trait Gate: Send + Sync + 'static {
    fn dispatch(&self, call: CallId) -> BoxFuture<'_, Result<Forward, Error>>;
    /// Durable effect-shell reporting belongs in the daemon adapter. No response content.
    fn outcome(&self, _call: &CallId, _outcome: Outcome) {}
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    NotSent,
    Unknown,
}
/// Fixed errors deliberately never retain upstream bodies, URLs, headers, or SDK errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InternalSendRefused,
    Rejected,
    NotSent,
    Unknown,
    Protocol,
    Configuration,
    Interactive,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InternalSendRefused => "internal_send_refused",
            Self::Rejected => "dispatch refused",
            Self::NotSent => "upstream unavailable: not_sent",
            Self::Unknown => "upstream outcome unknown; never retried",
            Self::Protocol => "upstream protocol error",
            Self::Configuration => "invalid upstream configuration",
            Self::Interactive => {
                "upstream asked for interactive input, which BOGO does not pass through."
            }
        })
    }
}
impl std::error::Error for Error {}
