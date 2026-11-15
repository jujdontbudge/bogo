//! The Rust side of the wire codec (`lean/BogoCore/Wire.lean`): `Input` encoding and `Output`
//! decoding. The Lean side decodes every input itself and rejects anything malformed, so this
//! encoder is a convenience, never a check.

use crate::types::*;
use bogo_json::{JVal, Num, Obj};

// ---------------------------------------------------------------------------------------------
// Encoding

#[derive(Default)]
struct W(Vec<u8>);

impl W {
    fn u8(&mut self, b: u8) {
        self.0.push(b);
    }
    fn u16(&mut self, n: u16) {
        self.0.extend_from_slice(&n.to_be_bytes());
    }
    fn u32(&mut self, n: u32) {
        self.0.extend_from_slice(&n.to_be_bytes());
    }
    fn u64(&mut self, n: u64) {
        self.0.extend_from_slice(&n.to_be_bytes());
    }
    fn len(&mut self, n: usize) {
        // Anything over u32 is refused by Lean as malformed; saturate so it stays malformed.
        self.u32(u32::try_from(n).unwrap_or(u32::MAX));
    }
    fn bytes(&mut self, b: &[u8]) {
        self.len(b.len());
        self.0.extend_from_slice(b);
    }
    fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
    fn opt<T>(&mut self, o: &Option<T>, f: impl FnOnce(&mut W, &T)) {
        match o {
            None => self.u8(0),
            Some(x) => {
                self.u8(1);
                f(self, x);
            }
        }
    }
    fn list<T>(&mut self, xs: &[T], mut f: impl FnMut(&mut W, &T)) {
        self.len(xs.len());
        for x in xs {
            f(self, x);
        }
    }
    fn value(&mut self, v: &JVal) {
        match v {
            JVal::Null => self.u8(0),
            JVal::Bool(false) => self.u8(1),
            JVal::Bool(true) => self.u8(2),
            JVal::Num(n) => {
                self.u8(3);
                self.str(n.as_str());
            }
            JVal::Str(s) => {
                self.u8(4);
                self.str(s);
            }
            JVal::Arr(xs) => {
                self.u8(5);
                self.list(xs, |w, x| w.value(x));
            }
            JVal::Obj(o) => {
                self.u8(6);
                self.len(o.len());
                for (k, x) in o.iter() {
                    self.str(k);
                    self.value(x);
                }
            }
        }
    }
    fn kind(&mut self, k: PolicyKind) {
        self.u8(match k {
            PolicyKind::Allow => 0,
            PolicyKind::Approve => 1,
            PolicyKind::Deny => 2,
        });
    }
    fn requirement(&mut self, r: Requirement) {
        match r {
            Requirement::AnyOf => self.u8(0),
            Requirement::KOfN(k) => {
                self.u8(1);
                self.u32(k);
            }
        }
    }
    fn hint(&mut self, h: &(Vec<PathElem>, Format)) {
        self.list(&h.0, |w, e| match e {
            PathElem::Key(k) => {
                w.u8(0);
                w.str(k);
            }
            PathElem::Index(i) => {
                w.u8(1);
                w.u32(*i);
            }
        });
        match &h.1 {
            Format::Text => self.u8(0),
            Format::MoneyMinor(c) => {
                self.u8(1);
                self.str(c);
            }
        }
    }
    fn tool_policy(&mut self, p: &ToolPolicy) {
        self.kind(p.kind);
        self.u8(p.justification_required as u8);
        self.list(&p.hints, |w, h| w.hint(h));
        self.opt(&p.expiry_ms, |w, e| w.u64(*e));
        self.list(&p.approvers, |w, a| w.str(a));
        self.requirement(p.requirement);
        self.u8(match p.deny_rule {
            DenyRule::AnyDenial => 0,
            DenyRule::WhenUnreachable => 1,
        });
        self.u8(match p.mode {
            Mode::Wait => 0,
            Mode::PendingRetry => 1,
        });
    }
    fn config(&mut self, c: &PolicyConfig) {
        self.u8(match c.default_policy {
            DefaultPolicy::Approve => 0,
            DefaultPolicy::Deny => 1,
        });
        self.u64(c.max_pending);
        self.list(&c.tools, |w, (n, p)| {
            w.str(n);
            w.tool_policy(p);
        });
        self.list(&c.overrides, |w, o| {
            w.str(&o.agent_name);
            w.str(&o.tool);
            w.opt(&o.kind, |w, k| w.kind(*k));
            w.opt(&o.approvers, |w, a| w.list(a, |w, s| w.str(s)));
            w.opt(&o.requirement, |w, r| w.requirement(*r));
        });
    }
}

/// The wire bytes of one input.
pub fn encode_input(i: &Input) -> Vec<u8> {
    let mut w = W::default();
    match i {
        Input::Configure { seq, cfg, catalog } => {
            w.u8(0);
            w.u64(*seq);
            w.config(cfg);
            w.list(catalog, |w, e| {
                w.str(&e.name);
                w.str(&e.upstream);
                w.str(&e.tool);
                w.str(&e.just_key);
            });
        }
        Input::ApproverSet { seq, approver } => {
            w.u8(1);
            w.u64(*seq);
            w.bytes(&approver.id);
            w.str(&approver.name);
            w.u16(approver.alg);
            w.bytes(&approver.pk);
        }
        Input::ApproverRevoked { seq, id } => {
            w.u8(2);
            w.u64(*seq);
            w.bytes(id);
        }
        Input::AgentSet { seq, id, name } => {
            w.u8(3);
            w.u64(*seq);
            w.bytes(id);
            w.str(name);
        }
        Input::AgentRevoked { seq, id } => {
            w.u8(4);
            w.u64(*seq);
            w.bytes(id);
        }
        Input::OwnerPause { seq, agent } => {
            w.u8(5);
            w.u64(*seq);
            w.bytes(agent);
        }
        Input::AgentUnpaused { seq, id } => {
            w.u8(6);
            w.u64(*seq);
            w.bytes(id);
        }
        Input::OwnerCancel { req } => {
            w.u8(7);
            w.bytes(req);
        }
        Input::SessionOpened {
            session,
            agent,
            client,
        } => {
            w.u8(8);
            w.bytes(session);
            w.bytes(agent);
            w.opt(client, |w, c| w.str(c));
        }
        Input::SessionClosed { session } => {
            w.u8(9);
            w.bytes(session);
        }
        Input::Call {
            call,
            session,
            name,
            args,
            now_ms,
        } => {
            w.u8(10);
            w.bytes(call);
            w.bytes(session);
            w.str(name);
            w.opt(args, |w, v| w.value(v));
            w.u64(*now_ms);
        }
        Input::CallEnded { call } => {
            w.u8(11);
            w.bytes(call);
        }
        Input::Approval {
            approver,
            req,
            alg,
            proof,
            now_ms,
        } => {
            w.u8(12);
            w.bytes(approver);
            w.bytes(req);
            w.u16(*alg);
            w.bytes(proof);
            w.u64(*now_ms);
        }
        Input::Denial {
            approver,
            req,
            note,
        } => {
            w.u8(13);
            w.bytes(approver);
            w.bytes(req);
            w.opt(note, |w, n| w.str(n));
        }
        Input::PauseAgent {
            approver,
            agent,
            epoch,
        } => {
            w.u8(14);
            w.bytes(approver);
            w.bytes(agent);
            w.u64(*epoch);
        }
        Input::Dispatch { call, now_ms } => {
            w.u8(15);
            w.bytes(call);
            w.u64(*now_ms);
        }
        Input::NotSent { call } => {
            w.u8(16);
            w.bytes(call);
        }
        Input::Tick { now_ms } => {
            w.u8(17);
            w.u64(*now_ms);
        }
    }
    w.0
}

// ---------------------------------------------------------------------------------------------
// Decoding

/// The Lean core produced output bytes this crate cannot read: a build mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub &'static str);

struct R<'a>(&'a [u8]);

type Res<T> = Result<T, DecodeError>;

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Res<&'a [u8]> {
        if self.0.len() < n {
            return Err(DecodeError("output ends early"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Res<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Res<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Res<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> Res<Bytes> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn str(&mut self) -> Res<String> {
        String::from_utf8(self.bytes()?).map_err(|_| DecodeError("string is not UTF-8"))
    }
    fn opt<T>(&mut self, f: impl FnOnce(&mut Self) -> Res<T>) -> Res<Option<T>> {
        match self.u8()? {
            0 => Ok(None),
            1 => f(self).map(Some),
            _ => Err(DecodeError("bad option byte")),
        }
    }
    fn list<T>(&mut self, mut f: impl FnMut(&mut Self) -> Res<T>) -> Res<Vec<T>> {
        let n = self.u32()? as usize;
        let mut v = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            v.push(f(self)?);
        }
        Ok(v)
    }
    fn value(&mut self) -> Res<JVal> {
        Ok(match self.u8()? {
            0 => JVal::Null,
            1 => JVal::Bool(false),
            2 => JVal::Bool(true),
            3 => JVal::Num(Num::new(self.str()?).ok_or(DecodeError("bad number text"))?),
            4 => JVal::Str(self.str()?),
            5 => JVal::Arr(self.list(|r| r.value())?),
            6 => {
                let kvs = self.list(|r| Ok((r.str()?, r.value()?)))?;
                JVal::Obj(Obj::new(kvs).map_err(|_| DecodeError("duplicate key"))?)
            }
            _ => return Err(DecodeError("bad value tag")),
        })
    }
    fn rejection(&mut self) -> Res<Rejection> {
        Ok(match self.u8()? {
            0 => Rejection::Malformed,
            1 => Rejection::UnknownSession,
            2 => Rejection::UnknownAgent,
            3 => Rejection::RevokedAgent,
            4 => Rejection::PausedAgent,
            5 => Rejection::DuplicateCall,
            6 => Rejection::UnknownTool,
            7 => Rejection::DenyPolicy,
            8 => Rejection::JustificationRequired,
            9 => Rejection::NoEligibleApprover,
            10 => Rejection::Denied(self.opt(|r| r.str())?),
            11 => Rejection::EndedWithoutDecision,
            12 => Rejection::NotAuthorized,
            13 => Rejection::GateClosed,
            14 => Rejection::UpstreamUnavailable,
            15 => Rejection::Exhausted,
            _ => return Err(DecodeError("bad rejection tag")),
        })
    }
    fn end_reason(&mut self) -> Res<EndReason> {
        use EndReason::*;
        Ok(match self.u8()? {
            0 => Denied,
            1 => Cancelled,
            2 => CallEnded,
            3 => SessionClosed,
            4 => AgentRevoked,
            5 => AgentPaused,
            6 => Expired,
            7 => Unreachable,
            8 => DispatchFailed,
            9 => NotSent,
            _ => return Err(DecodeError("bad end reason")),
        })
    }
    fn ignore_reason(&mut self) -> Res<IgnoreReason> {
        use IgnoreReason::*;
        Ok(match self.u8()? {
            0 => Unknown,
            1 => Settled,
            2 => Expired,
            3 => NotEligible,
            4 => Duplicate,
            5 => BadSignature,
            6 => StaleEpoch,
            _ => return Err(DecodeError("bad ignore reason")),
        })
    }
    fn output(&mut self) -> Res<Output> {
        Ok(match self.u8()? {
            0 => Output::Authorized {
                call: self.bytes()?,
                req: self.opt(|r| r.bytes())?,
            },
            1 => Output::Forward {
                call: self.bytes()?,
                req: self.opt(|r| r.bytes())?,
                upstream: self.str()?,
                tool: self.str()?,
                args: self.opt(|r| r.value())?,
                registry_seq: self.u64()?,
            },
            2 => Output::Attach {
                call: self.bytes()?,
                primary: self.bytes()?,
            },
            3 => Output::Reject {
                call: self.bytes()?,
                why: self.rejection()?,
            },
            4 => Output::PendingApproval {
                call: self.bytes()?,
            },
            5 => Output::Ask {
                req: self.bytes()?,
                bytes: self.bytes()?,
                to: self.list(|r| r.bytes())?,
                group_key: self.bytes()?,
                pause_epoch: self.u64()?,
            },
            6 => Output::Settled {
                req: self.bytes()?,
                to: self.list(|r| r.bytes())?,
            },
            7 => Output::Ended {
                req: self.bytes()?,
                why: self.end_reason()?,
                to: self.list(|r| r.bytes())?,
            },
            8 => Output::Counted {
                req: self.bytes()?,
                approver: self.bytes()?,
            },
            9 => Output::Ignored {
                req: self.bytes()?,
                approver: self.bytes()?,
                why: self.ignore_reason()?,
            },
            10 => Output::FloodDropped {
                call: self.bytes()?,
            },
            11 => Output::AgentPaused {
                agent: self.bytes()?,
            },
            _ => return Err(DecodeError("bad output tag")),
        })
    }
}

/// The outputs of one step and the core's next deadline.
pub fn decode_outputs(b: &[u8]) -> Result<(Vec<Output>, Option<u64>), DecodeError> {
    let mut r = R(b);
    let outs = r.list(|r| r.output())?;
    let deadline = r.opt(|r| r.u64())?;
    if !r.0.is_empty() {
        return Err(DecodeError("trailing bytes after outputs"));
    }
    Ok((outs, deadline))
}
