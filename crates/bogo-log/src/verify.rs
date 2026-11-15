//! `bogo log verify` for the registry part: the chain, the registry replay,
//! and every counted approval against the key registered at that moment.
use crate::{Entry, LogError, LogEvent, Registry};
use std::collections::HashMap;

/// `(alg, public_key, message, proof) -> valid`.
pub type Check<'a> = &'a dyn Fn(u16, &[u8], &[u8], &[u8]) -> bool;
/// Request bytes and the approvers it was sent to, by request ID.
type Sent = HashMap<Vec<u8>, (Vec<u8>, Vec<Vec<u8>>)>;

pub const APPROVAL_DOMAIN: &[u8] = b"BOGO-APPROVAL\x00v1";

#[derive(Debug, Default)]
pub struct Report {
    pub entries: usize,
    pub approvers_registered: usize,
    pub approvers_revoked: usize,
    pub approvals_counted: usize,
    pub approvals_ignored: usize,
    pub denials_applied: usize,
    pub denials_ignored: usize,
}

/// `check(alg, public_key, message, proof)` is the signature check; the
/// daemon passes the Lean core's, the stand-in passes `bogo-verify`'s.
pub fn verify(
    entries: &[Entry],
    check: Check<'_>,
) -> Result<Report, LogError> {
    let mut registry = Registry::default();
    let mut requests: Sent = HashMap::new();
    let mut report = Report {
        entries: entries.len(),
        ..Report::default()
    };
    for e in entries {
        let bad = |why: String| LogError::Corrupt { line: e.line, why };
        match &e.event {
            LogEvent::ApproverRegistered { .. } => report.approvers_registered += 1,
            LogEvent::ApproverRevoked { .. } => report.approvers_revoked += 1,
            LogEvent::RequestCreated { req, request, to, .. } => {
                if req.0.len() != 40 {
                    return Err(bad("request ID is not 40 bytes".into()));
                }
                requests.insert(req.0.clone(), (request.0.clone(), to.iter().map(|t| t.0.clone()).collect()));
            }
            LogEvent::Approval { req, approver, alg, proof, counted, .. } => {
                if *counted {
                    let (bytes, to) = requests
                        .get(&req.0)
                        .ok_or_else(|| bad("approval counted for a request with no request_created".into()))?;
                    if !to.contains(&approver.0) {
                        return Err(bad("approval counted from an approver the request was not sent to".into()));
                    }
                    let a = registry
                        .approver(&approver.0)
                        .filter(|a| a.active())
                        .ok_or_else(|| bad("approval counted from an approver not registered and active at that point".into()))?;
                    if a.entry.alg != *alg {
                        return Err(bad("approval algorithm differs from the registered one".into()));
                    }
                    let message = [APPROVAL_DOMAIN, bytes].concat();
                    if !check(*alg, &a.entry.sig_pk.0, &message, &proof.0) {
                        return Err(bad("counted approval does not verify against the registered key".into()));
                    }
                    report.approvals_counted += 1;
                } else {
                    report.approvals_ignored += 1;
                }
            }
            LogEvent::Denial { applied, .. } => {
                if *applied {
                    report.denials_applied += 1
                } else {
                    report.denials_ignored += 1
                }
            }
            _ => {}
        }
        registry.apply(e);
    }
    Ok(report)
}

/// Verify canonical request bytes and signatures through the same compiled Lean code
/// that handles live calls. The existing `verify` remains available to the stand-in.
pub fn verify_with_core(entries: &[Entry], core: &bogo_core::Core) -> Result<Report, LogError> {
    for entry in entries {
        if let LogEvent::RequestCreated { request, .. } = &entry.event {
            let decoded=core.decode_request(&request.0).map_err(|e|LogError::Corrupt{line:entry.line,why:e.to_string()})?;
            if decoded.as_deref()!=Some(request.0.as_slice()) {
                return Err(LogError::Corrupt{line:entry.line,why:"request is not canonical BOGO encoding".into()});
            }
        }
    }
    verify(entries, &|alg,pk,message,proof| {
        message.strip_prefix(APPROVAL_DOMAIN).is_some_and(|request|core.check_approval(alg,pk,request,proof).unwrap_or(false))
    })
}
