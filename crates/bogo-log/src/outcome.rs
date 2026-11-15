//! What became of a request, read from the log alone. This is how a phone's
//! `sync` is answered, so the Mac needs no separate outbox.
use crate::{Entry, LogEvent};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Live,
    Executed,
    NotSent,
    Denied,
    /// The wire reason, in the phone's vocabulary (`callEnded`, `otherBoot`, …).
    Ended(String),
    Unknown,
    NoRecord,
}

impl Outcome {
    /// The phone's outcome word.
    pub fn wire(&self) -> &'static str {
        match self {
            Outcome::Live => "live",
            Outcome::Executed => "executed",
            Outcome::NotSent => "notSent",
            Outcome::Denied => "denied",
            Outcome::Ended(_) => "ended",
            Outcome::Unknown => "unknown",
            Outcome::NoRecord => "noRecord",
        }
    }
}

/// Classify conservatively. Only positive evidence counts as "not sent": a
/// request authorized (or forwarded) without a result before the next `boot`
/// is `Unknown`, never replayed. A request still undecided when its boot ended
/// ended with that boot.
pub fn outcome(entries: &[Entry], req: &[u8]) -> Outcome {
    let Some(start) = entries
        .iter()
        .position(|e| matches!(&e.event, LogEvent::RequestCreated { req: r, .. } if r.0 == req))
    else {
        return Outcome::NoRecord;
    };
    let (mut authorized, mut forwarded) = (false, false);
    for e in &entries[start + 1..] {
        match &e.event {
            LogEvent::Boot { .. } => {
                return if authorized || forwarded {
                    Outcome::Unknown
                } else {
                    Outcome::Ended("otherBoot".into())
                };
            }
            ev if ev.req() != Some(req) => {}
            LogEvent::Authorized { .. } => authorized = true,
            LogEvent::Forwarded { .. } => forwarded = true,
            LogEvent::NotSent { .. } => return Outcome::NotSent,
            LogEvent::Result { ok: true, .. } => return Outcome::Executed,
            LogEvent::Result { ok: false, .. } => return Outcome::Unknown,
            LogEvent::RequestEnded { why, .. } if why == "denied" => return Outcome::Denied,
            LogEvent::RequestEnded { why, .. } => return Outcome::Ended(why.clone()),
            _ => {}
        }
    }
    if forwarded {
        Outcome::Unknown
    } else {
        Outcome::Live
    }
}
