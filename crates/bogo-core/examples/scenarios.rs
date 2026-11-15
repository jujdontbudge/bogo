//! Runs real scenarios against the compiled Lean core through `bogo-core`, the way the daemon
//! will: inputs in, decisions out, with real P-256 approvals verified by `bogo-verify` behind
//! the core's verify hook.
//!
//! `cargo run -p bogo-core --example scenarios` runs every scenario and exits non-zero if any
//! decision differs from what the spec requires.
//! `cargo run -p bogo-core --example scenarios -- --expect-abi 2` shows the startup ABI check.

use bogo_core::*;
use bogo_json::JVal;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};

// Link the verifier the Lean hook calls.
use bogo_verify as _;

const MIN: u64 = 60_000;

struct Key {
    id: Bytes,
    name: String,
    sk: SigningKey,
}

impl Key {
    fn new(seed: u8, name: &str) -> Key {
        let mut b = [0u8; 32];
        b[31] = seed;
        b[0] = 1;
        Key {
            id: format!("approver-{seed}").into_bytes(),
            name: name.into(),
            sk: SigningKey::from_bytes(&b.into()).unwrap(),
        }
    }
    fn approver(&self) -> Approver {
        Approver {
            id: self.id.clone(),
            name: self.name.clone(),
            alg: 1,
            pk: self
                .sk
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
        }
    }
    /// What the phone does: sign the domain tag and the exact request bytes it received.
    fn sign(&self, request_bytes: &[u8]) -> Bytes {
        let mut m = b"BOGO-APPROVAL\x00v1".to_vec();
        m.extend_from_slice(request_bytes);
        let sig: Signature = self.sk.sign(&m);
        sig.to_bytes().to_vec()
    }
}

struct World {
    core: Core,
    seq: u64,
    calls: u64,
    failures: u32,
    checks: u32,
}

fn args(text: &str) -> Option<JVal> {
    Some(bogo_json::parse(text.as_bytes()).expect("test args are JSON"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn short(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) if !s.is_empty() && s.chars().all(|c| c.is_ascii_graphic()) => s.to_string(),
        _ => {
            let h = hex(b);
            if h.len() > 12 {
                format!("…{}", &h[h.len() - 8..])
            } else {
                h
            }
        }
    }
}

fn show(o: &Output) -> String {
    match o {
        Output::Authorized { call, req } => format!(
            "authorized({}{})",
            short(call),
            req.as_ref()
                .map(|r| format!(", req {}", short(r)))
                .unwrap_or_default()
        ),
        Output::Forward {
            call,
            req,
            upstream,
            tool,
            args,
            ..
        } => format!(
            "FORWARD({}, {}{}, {}__{} {})",
            short(call),
            if req.is_some() { "req " } else { "allowed" },
            req.as_ref().map(|r| short(r)).unwrap_or_default(),
            upstream,
            tool,
            args.as_ref()
                .map(|a| a.write())
                .unwrap_or("<no arguments>".into())
        ),
        Output::Attach { call, primary } => format!("attach({} → {})", short(call), short(primary)),
        Output::Reject { call, why } => format!("reject({}, {why:?})", short(call)),
        Output::PendingApproval { call } => format!("pendingApproval({})", short(call)),
        Output::Ask { req, to, .. } => format!(
            "ask(req {}, to {:?})",
            short(req),
            to.iter().map(|t| short(t)).collect::<Vec<_>>()
        ),
        Output::Settled { req, .. } => format!("settled(req {})", short(req)),
        Output::Ended { req, why, .. } => format!("ended(req {}, {why:?})", short(req)),
        Output::Counted { req, approver } => {
            format!("counted(req {}, {})", short(req), short(approver))
        }
        Output::Ignored { req, approver, why } => {
            format!("ignored(req {}, {}, {why:?})", short(req), short(approver))
        }
        Output::FloodDropped { call } => format!("floodDropped({})", short(call)),
        Output::AgentPaused { agent } => format!("agentPaused({})", short(agent)),
    }
}

const BOOT: [u8; 32] = [7; 32];
const TRIP: &[u8] = b"agent-trip";
const RESEARCHER: &[u8] = b"agent-researcher";

impl World {
    fn new(core: Core) -> World {
        World {
            core,
            seq: 0,
            calls: 0,
            failures: 0,
            checks: 0,
        }
    }

    fn step(&mut self, label: &str, i: Input) -> Vec<Output> {
        let s = self.core.step(&i).expect("core answers");
        println!(
            "    {label:<44} → {}",
            s.outputs.iter().map(show).collect::<Vec<_>>().join(", ")
        );
        s.outputs
    }

    fn check(&mut self, what: &str, ok: bool) {
        self.checks += 1;
        if ok {
            println!("      ✓ {what}");
        } else {
            self.failures += 1;
            println!("      ✗ {what}");
        }
    }

    fn owner(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn call_id(&mut self) -> Bytes {
        self.calls += 1;
        format!("call-{}", self.calls).into_bytes()
    }

    /// A fresh boot with the standard setup: two agents, two approvers, the scenario tools.
    fn boot(&mut self, keys: &[&Key], max_pending: u64) {
        self.core.restart(b"bogo-mac", &BOOT).unwrap();
        let tool = |kind, f: &dyn Fn(&mut ToolPolicy)| {
            let mut p = ToolPolicy::new(kind);
            f(&mut p);
            p
        };
        let cfg = PolicyConfig {
            default_policy: DefaultPolicy::Approve,
            max_pending,
            tools: vec![
                ("files__read_file".into(), tool(PolicyKind::Allow, &|_| {})),
                (
                    "stripe__pay".into(),
                    tool(PolicyKind::Approve, &|p| {
                        p.justification_required = true;
                        p.hints = vec![(
                            vec![PathElem::Key("amount".into())],
                            Format::MoneyMinor("USD".into()),
                        )];
                        p.approvers = vec!["Johan iPhone".into()];
                    }),
                ),
                (
                    "stripe__pay_expiring".into(),
                    tool(PolicyKind::Approve, &|p| {
                        p.expiry_ms = Some(10 * MIN);
                        p.approvers = vec!["Johan iPhone".into()];
                    }),
                ),
                (
                    "stripe__retry".into(),
                    tool(PolicyKind::Approve, &|p| {
                        p.mode = Mode::PendingRetry;
                        p.approvers = vec!["Johan iPhone".into()];
                    }),
                ),
                (
                    "vault__two_keys".into(),
                    tool(PolicyKind::Approve, &|p| {
                        p.requirement = Requirement::KOfN(2)
                    }),
                ),
                ("files__delete".into(), tool(PolicyKind::Deny, &|_| {})),
            ],
            overrides: vec![AgentOverride {
                agent_name: "Researcher".into(),
                tool: "stripe__pay".into(),
                kind: Some(PolicyKind::Deny),
                approvers: None,
                requirement: None,
            }],
        };
        let entry = |up: &str, t: &str| CatalogEntry {
            name: format!("{up}__{t}"),
            upstream: up.into(),
            tool: t.into(),
            just_key: "justification".into(),
        };
        let catalog = vec![
            entry("files", "read_file"),
            entry("files", "delete"),
            entry("files", "list_directory"),
            entry("stripe", "pay"),
            entry("stripe", "pay_expiring"),
            entry("stripe", "retry"),
            entry("vault", "two_keys"),
        ];
        let seq = self.owner();
        self.core
            .step(&Input::Configure { seq, cfg, catalog })
            .unwrap();
        for (id, name) in [(TRIP, "Trip planner"), (RESEARCHER, "Researcher")] {
            let seq = self.owner();
            self.core
                .step(&Input::AgentSet {
                    seq,
                    id: id.to_vec(),
                    name: name.into(),
                })
                .unwrap();
        }
        for k in keys {
            let seq = self.owner();
            self.core
                .step(&Input::ApproverSet {
                    seq,
                    approver: k.approver(),
                })
                .unwrap();
        }
        for (s, a) in [
            (b"session-1".as_slice(), TRIP),
            (b"session-2", TRIP),
            (b"session-r", RESEARCHER),
        ] {
            self.core
                .step(&Input::SessionOpened {
                    session: s.to_vec(),
                    agent: a.to_vec(),
                    client: Some("claude-code".into()),
                })
                .unwrap();
        }
    }

    fn call(
        &mut self,
        label: &str,
        session: &[u8],
        name: &str,
        a: Option<JVal>,
        now: u64,
    ) -> (Bytes, Vec<Output>) {
        let c = self.call_id();
        let outs = self.step(
            label,
            Input::Call {
                call: c.clone(),
                session: session.to_vec(),
                name: name.into(),
                args: a,
                now_ms: now,
            },
        );
        (c, outs)
    }

    fn approve(&mut self, label: &str, k: &Key, req: &[u8], proof: Bytes, now: u64) -> Vec<Output> {
        self.step(
            label,
            Input::Approval {
                approver: k.id.clone(),
                req: req.to_vec(),
                alg: 1,
                proof,
                now_ms: now,
            },
        )
    }

    fn dispatch(&mut self, label: &str, c: &[u8], now: u64) -> Vec<Output> {
        self.step(
            label,
            Input::Dispatch {
                call: c.to_vec(),
                now_ms: now,
            },
        )
    }
}

fn ask_of(outs: &[Output]) -> Option<(Bytes, Bytes)> {
    outs.iter().find_map(|o| match o {
        Output::Ask { req, bytes, .. } => Some((req.clone(), bytes.clone())),
        _ => None,
    })
}

fn forwards(outs: &[Output]) -> Vec<&Output> {
    outs.iter()
        .filter(|o| matches!(o, Output::Forward { .. }))
        .collect()
}

fn has_authorized(outs: &[Output], c: &[u8]) -> bool {
    outs.iter()
        .any(|o| matches!(o, Output::Authorized { call, .. } if call == c))
}

fn rejected(outs: &[Output], c: &[u8]) -> Option<Rejection> {
    outs.iter().find_map(|o| match o {
        Output::Reject { call, why } if call == c => Some(why.clone()),
        _ => None,
    })
}

fn ignored(outs: &[Output]) -> Option<IgnoreReason> {
    outs.iter().find_map(|o| match o {
        Output::Ignored { why, .. } => Some(*why),
        _ => None,
    })
}

fn main() {
    let args_: Vec<String> = std::env::args().collect();
    if let Some(i) = args_.iter().position(|a| a == "--expect-abi") {
        let expected: u32 = args_[i + 1].parse().unwrap();
        match Core::start_expecting(b"bogo-mac", &BOOT, expected) {
            Ok(_) => println!("started: library ABI matches {expected}"),
            Err(e) => {
                println!("refused: {e}");
                std::process::exit(2);
            }
        }
        return;
    }

    let core = match Core::start(b"bogo-mac", &BOOT) {
        Ok(c) => c,
        Err(e) => {
            println!("refused: {e}");
            std::process::exit(2);
        }
    };
    println!("core started; library ABI = {ABI}");
    let a = Key::new(1, "Johan iPhone");
    let b = Key::new(2, "Second phone");
    let mut w = World::new(core);
    let t0 = 1_800_000_000_000u64;
    let pay = |amount: &str, why: &str| {
        args(&format!(
            "{{\"amount\":{amount},\"currency\":\"usd\",\"justification\":\"{why}\"}}"
        ))
    };
    let flight = "booking the 6pm flight you asked for, $47";

    println!("\n1. An allowed call forwards at once");
    w.boot(&[&a, &b], 5);
    let (c, outs) = w.call(
        "files__read_file {path}",
        b"session-1",
        "files__read_file",
        args(r#"{"path":"/tmp/x"}"#),
        t0,
    );
    w.check(
        "authorized with no request, nothing asked",
        has_authorized(&outs, &c) && ask_of(&outs).is_none(),
    );
    let outs = w.dispatch("dispatch at the upstream write", &c, t0 + 1);
    w.check("forward with the exact arguments", matches!(forwards(&outs)[..], [Output::Forward { args: Some(x), req: None, .. }] if x.write() == r#"{"path":"/tmp/x"}"#));

    println!("\n2. A protected call approved once forwards once");
    let (c, outs) = w.call(
        "stripe__pay amount 4700 + justification",
        b"session-1",
        "stripe__pay",
        pay("4700", flight),
        t0,
    );
    let (r, bytes) = ask_of(&outs).expect("ask");
    w.check(
        "asked the eligible approver, nothing authorized yet",
        !has_authorized(&outs, &c),
    );
    let proof = a.sign(&bytes);
    let outs = w.approve(
        "Johan iPhone approves (Face ID, P-256)",
        &a,
        &r,
        proof.clone(),
        t0 + 5_000,
    );
    w.check("counted, settled and authorized", has_authorized(&outs, &c));
    let outs = w.dispatch("dispatch", &c, t0 + 6_000);
    w.check(
        "forwarded once, justification stripped, 4700 kept as text",
        matches!(forwards(&outs)[..], [Output::Forward { args: Some(x), .. }] if x.write() == r#"{"amount":4700,"currency":"usd"}"#),
    );
    let outs = w.dispatch("dispatch the same call again", &c, t0 + 7_000);
    w.check(
        "no second forward",
        forwards(&outs).is_empty() && rejected(&outs, &c) == Some(Rejection::NotAuthorized),
    );

    println!("\n3. The same approval reused");
    let outs = w.approve(
        "replay the approval on the spent request",
        &a,
        &r,
        proof.clone(),
        t0 + 8_000,
    );
    w.check(
        "ignored: the request is gone",
        ignored(&outs) == Some(IgnoreReason::Unknown),
    );
    let (c2, outs) = w.call(
        "the identical call again",
        b"session-1",
        "stripe__pay",
        pay("4700", flight),
        t0 + 9_000,
    );
    let (r2, _) = ask_of(&outs).expect("a new request");
    w.check("a new request with a new nonce", r2 != r);
    let outs = w.approve(
        "replay the old signature on the new request",
        &a,
        &r2,
        proof.clone(),
        t0 + 9_500,
    );
    w.check(
        "bad signature: it signed other bytes",
        ignored(&outs) == Some(IgnoreReason::BadSignature),
    );
    let outs = w.dispatch("dispatch it anyway", &c2, t0 + 9_600);
    w.check("no forward", forwards(&outs).is_empty());

    println!("\n4. amount 4700 approved, then 4701 sent");
    let (c47, outs) = w.call(
        "stripe__pay amount 4700",
        b"session-1",
        "stripe__pay",
        pay("4700", flight),
        t0 + 10_000,
    );
    let (r47, b47) = ask_of(&outs).unwrap();
    let p47 = a.sign(&b47);
    let (c4701, outs) = w.call(
        "stripe__pay amount 4701",
        b"session-1",
        "stripe__pay",
        pay("4701", flight),
        t0 + 10_001,
    );
    let (r4701, b4701) = ask_of(&outs).unwrap();
    w.check(
        "4701 is its own request with different bytes",
        r4701 != r47 && b4701 != b47,
    );
    let outs = w.approve(
        "the 4700 approval sent for the 4701 request",
        &a,
        &r4701,
        p47.clone(),
        t0 + 11_000,
    );
    w.check(
        "bad signature",
        ignored(&outs) == Some(IgnoreReason::BadSignature),
    );
    let outs = w.dispatch("dispatch the 4701 call", &c4701, t0 + 11_001);
    w.check("rejected, nothing forwarded", forwards(&outs).is_empty());
    let outs = w.approve(
        "the 4700 approval on its own request",
        &a,
        &r47,
        p47,
        t0 + 11_002,
    );
    w.check("authorizes only the 4700 call", has_authorized(&outs, &c47));
    let outs = w.dispatch("dispatch the 4700 call", &c47, t0 + 11_003);
    w.check("forwards amount 4700", matches!(forwards(&outs)[..], [Output::Forward { args: Some(x), .. }] if x.write().contains("4700")));

    println!("\n5. The identical call from another session");
    let (c1, outs) = w.call(
        "session-1: stripe__retry (pending-and-retry)",
        b"session-1",
        "stripe__retry",
        pay("4700", "x"),
        t0 + 20_000,
    );
    let (rs, bs) = ask_of(&outs).unwrap();
    let ps = a.sign(&bs);
    w.check(
        "pending approval",
        outs.iter()
            .any(|o| matches!(o, Output::PendingApproval { call } if *call == c1)),
    );
    w.approve(
        "Johan iPhone approves session-1's request",
        &a,
        &rs,
        ps.clone(),
        t0 + 21_000,
    );
    let (c2, outs) = w.call(
        "session-2 sends the identical call",
        b"session-2",
        "stripe__retry",
        pay("4700", "x"),
        t0 + 22_000,
    );
    let (rs2, _) = ask_of(&outs).expect("a separate request for session-2");
    w.check(
        "session-2 does not get session-1's approval",
        !has_authorized(&outs, &c2) && rs2 != rs,
    );
    let outs = w.approve(
        "session-1's signature sent for session-2's request",
        &a,
        &rs2,
        ps,
        t0 + 22_500,
    );
    w.check(
        "bad signature",
        ignored(&outs) == Some(IgnoreReason::BadSignature),
    );
    let (c3, outs) = w.call(
        "session-1 retries the identical call",
        b"session-1",
        "stripe__retry",
        pay("4700", "x"),
        t0 + 23_000,
    );
    w.check(
        "authorized in the session that asked",
        has_authorized(&outs, &c3),
    );
    let outs = w.dispatch("dispatch", &c3, t0 + 23_001);
    w.check("forwards once", forwards(&outs).len() == 1);

    println!("\n6. A different justification is a new request");
    let (_, outs) = w.call(
        "stripe__pay, reason A",
        b"session-1",
        "stripe__pay",
        pay("4700", "reason A"),
        t0 + 30_000,
    );
    let (ra, ba) = ask_of(&outs).unwrap();
    let pa = a.sign(&ba);
    let (cb, outs) = w.call(
        "stripe__pay, reason B",
        b"session-1",
        "stripe__pay",
        pay("4700", "reason B"),
        t0 + 30_001,
    );
    let (rb, bb) = ask_of(&outs).unwrap();
    w.check(
        "a new request, different signed bytes",
        ra != rb && ba != bb,
    );
    let outs = w.approve(
        "reason A's approval sent for reason B",
        &a,
        &rb,
        pa,
        t0 + 31_000,
    );
    w.check(
        "bad signature",
        ignored(&outs) == Some(IgnoreReason::BadSignature),
    );
    w.check(
        "nothing authorized for reason B",
        !has_authorized(&outs, &cb),
    );
    let (_, outs) = w.call(
        "stripe__pay without a justification",
        b"session-1",
        "stripe__pay",
        args(r#"{"amount":4700}"#),
        t0 + 31_500,
    );
    w.check(
        "rejected: justification required",
        outs.iter().any(|o| {
            matches!(
                o,
                Output::Reject {
                    why: Rejection::JustificationRequired,
                    ..
                }
            )
        }),
    );

    println!("\n7. Late approvals");
    let (_, outs) = w.call(
        "stripe__pay in session-2",
        b"session-2",
        "stripe__pay",
        pay("4700", flight),
        t0 + 40_000,
    );
    let (rl, bl) = ask_of(&outs).unwrap();
    let outs = w.step(
        "session-2 ends",
        Input::SessionClosed {
            session: b"session-2".to_vec(),
        },
    );
    w.check(
        "the request ended",
        outs.iter().any(|o| {
            matches!(
                o,
                Output::Ended {
                    why: EndReason::SessionClosed,
                    ..
                }
            )
        }),
    );
    let outs = w.approve(
        "Johan iPhone approves late",
        &a,
        &rl,
        a.sign(&bl),
        t0 + 50_000,
    );
    w.check(
        "ignored: the request is gone",
        ignored(&outs) == Some(IgnoreReason::Unknown),
    );
    let (ce, outs) = w.call(
        "stripe__pay_expiring (10 min expiry)",
        b"session-1",
        "stripe__pay_expiring",
        args(r#"{"amount":4700}"#),
        t0,
    );
    let (re, be) = ask_of(&outs).unwrap();
    let outs = w.approve(
        "approval 10 min + 1 ms later",
        &a,
        &re,
        a.sign(&be),
        t0 + 10 * MIN + 1,
    );
    w.check(
        "ignored as expired, request ended",
        ignored(&outs) == Some(IgnoreReason::Expired) && rejected(&outs, &ce).is_some(),
    );
    let (ce2, outs) = w.call(
        "stripe__pay_expiring again",
        b"session-1",
        "stripe__pay_expiring",
        args(r#"{"amount":4700}"#),
        t0,
    );
    let (re2, be2) = ask_of(&outs).unwrap();
    let outs = w.approve("approved in time", &a, &re2, a.sign(&be2), t0 + MIN);
    w.check("authorized", has_authorized(&outs, &ce2));
    let outs = w.dispatch("dispatch after the expiry passed", &ce2, t0 + 10 * MIN);
    w.check(
        "rejected at the gate, nothing forwarded",
        forwards(&outs).is_empty() && rejected(&outs, &ce2).is_some(),
    );
    let (_, outs) = w.call(
        "stripe__pay_expiring a third time",
        b"session-1",
        "stripe__pay_expiring",
        args(r#"{"amount":1}"#),
        t0,
    );
    let r3 = ask_of(&outs).unwrap().0;
    let st = w
        .core
        .step(&Input::Tick {
            now_ms: t0 + 10 * MIN,
        })
        .unwrap();
    println!(
        "    tick at the expiry                           → {}",
        st.outputs.iter().map(show).collect::<Vec<_>>().join(", ")
    );
    w.check(
        "tick ends it",
        st.outputs
            .iter()
            .any(|o| matches!(o, Output::Ended { req, why: EndReason::Expired, .. } if *req == r3)),
    );

    println!("\n8. A revoked approver");
    let (cr, outs) = w.call(
        "stripe__pay",
        b"session-1",
        "stripe__pay",
        pay("4700", flight),
        t0 + 60_000,
    );
    let (rr, br) = ask_of(&outs).unwrap();
    let pr = a.sign(&br);
    let seq = w.owner();
    let outs = w.step(
        "bogo approver revoke \"Johan iPhone\"",
        Input::ApproverRevoked {
            seq,
            id: a.id.clone(),
        },
    );
    w.check(
        "its pending request can no longer be approved, so it ends",
        rejected(&outs, &cr).is_some(),
    );
    let outs = w.approve("the revoked phone approves", &a, &rr, pr, t0 + 61_000);
    w.check(
        "ignored",
        ignored(&outs).is_some() && forwards(&outs).is_empty(),
    );
    let seq = w.owner();
    let outs = w.step(
        "approver re-registered under the same ID",
        Input::ApproverSet {
            seq,
            approver: a.approver(),
        },
    );
    w.check(
        "refused: revocation is permanent for that ID",
        outs.is_empty(),
    );
    let (_, outs) = w.call(
        "stripe__pay again",
        b"session-1",
        "stripe__pay",
        pay("4700", flight),
        t0 + 62_000,
    );
    w.check(
        "no eligible approver left",
        outs.iter().any(|o| {
            matches!(
                o,
                Output::Reject {
                    why: Rejection::NoEligibleApprover,
                    ..
                }
            )
        }),
    );
    // Settled, then revoked before the write.
    w.boot(&[&a, &b], 5);
    let (cs, outs) = w.call(
        "stripe__pay (fresh boot)",
        b"session-1",
        "stripe__pay",
        pay("4700", flight),
        t0,
    );
    let (rs, bs) = ask_of(&outs).unwrap();
    w.approve("approved", &a, &rs, a.sign(&bs), t0 + 1);
    let seq = w.owner();
    w.step(
        "approver revoked before the write",
        Input::ApproverRevoked {
            seq,
            id: a.id.clone(),
        },
    );
    let outs = w.dispatch("dispatch", &cs, t0 + 2);
    w.check(
        "the gate rejects: counted approver no longer registered",
        forwards(&outs).is_empty(),
    );

    println!("\n9. 2-of-2");
    w.boot(&[&a, &b], 5);
    let (c2k, outs) = w.call(
        "vault__two_keys",
        b"session-1",
        "vault__two_keys",
        args(r#"{"op":"open"}"#),
        t0,
    );
    let (r2k, b2k) = ask_of(&outs).unwrap();
    let outs = w.approve("Johan iPhone approves", &a, &r2k, a.sign(&b2k), t0 + 1);
    w.check("counted, not settled", !has_authorized(&outs, &c2k));
    let outs = w.dispatch("dispatch with one approval", &c2k, t0 + 2);
    w.check(
        "no forward (and the request ends)",
        forwards(&outs).is_empty(),
    );
    let (c2k, outs) = w.call(
        "vault__two_keys again",
        b"session-1",
        "vault__two_keys",
        args(r#"{"op":"open"}"#),
        t0 + 3,
    );
    let (r2k, b2k) = ask_of(&outs).unwrap();
    let pa = a.sign(&b2k);
    w.approve("Johan iPhone approves", &a, &r2k, pa.clone(), t0 + 4);
    let outs = w.approve("Johan iPhone approves again", &a, &r2k, pa, t0 + 5);
    w.check(
        "counts once",
        ignored(&outs) == Some(IgnoreReason::Duplicate) && !has_authorized(&outs, &c2k),
    );
    let outs = w.approve("Second phone approves", &b, &r2k, b.sign(&b2k), t0 + 6);
    w.check("settled and authorized", has_authorized(&outs, &c2k));
    let outs = w.dispatch("dispatch", &c2k, t0 + 7);
    w.check("forwards", forwards(&outs).len() == 1);
    let (_, outs) = w.call(
        "vault__two_keys, then a denial",
        b"session-1",
        "vault__two_keys",
        args(r#"{"op":"open"}"#),
        t0 + 8,
    );
    let (rd, _) = ask_of(&outs).unwrap();
    let outs = w.step(
        "Second phone denies (note \"no\")",
        Input::Denial {
            approver: b.id.clone(),
            req: rd,
            note: Some("no".into()),
        },
    );
    w.check(
        "any denial denies",
        outs.iter().any(
            |o| matches!(o, Output::Reject { why: Rejection::Denied(Some(n)), .. } if n == "no"),
        ),
    );

    println!("\n10. A paused agent");
    w.boot(&[&a, &b], 5);
    let (cp, outs) = w.call(
        "stripe__pay",
        b"session-1",
        "stripe__pay",
        pay("4700", flight),
        t0,
    );
    let (rp, bp) = ask_of(&outs).unwrap();
    let outs = w.step(
        "pauseAgent from the phone with a stale epoch",
        Input::PauseAgent {
            approver: a.id.clone(),
            agent: TRIP.to_vec(),
            epoch: 99,
        },
    );
    w.check("ignored", outs.is_empty());
    let outs = w.step(
        "pauseAgent from the phone, current epoch",
        Input::PauseAgent {
            approver: a.id.clone(),
            agent: TRIP.to_vec(),
            epoch: 0,
        },
    );
    w.check(
        "its pending request is denied",
        rejected(&outs, &cp) == Some(Rejection::PausedAgent),
    );
    let outs = w.approve(
        "late approval of that request",
        &a,
        &rp,
        a.sign(&bp),
        t0 + 1,
    );
    w.check("ignored", ignored(&outs) == Some(IgnoreReason::Unknown));
    let (cq, outs) = w.call(
        "files__read_file while paused",
        b"session-1",
        "files__read_file",
        args("{}"),
        t0 + 2,
    );
    w.check(
        "rejected",
        rejected(&outs, &cq) == Some(Rejection::PausedAgent),
    );
    let seq = w.owner();
    w.step(
        "agent unpaused on the Mac",
        Input::AgentUnpaused {
            seq,
            id: TRIP.to_vec(),
        },
    );
    let outs = w.step(
        "a pause composed before the unpause",
        Input::PauseAgent {
            approver: a.id.clone(),
            agent: TRIP.to_vec(),
            epoch: 0,
        },
    );
    w.check("stale, ignored", outs.is_empty());
    let (cq, outs) = w.call(
        "files__read_file after unpause",
        b"session-1",
        "files__read_file",
        args("{}"),
        t0 + 3,
    );
    w.check("runs again", has_authorized(&outs, &cq));

    println!("\n11. Over the pending limit (max_pending = 2)");
    w.boot(&[&a, &b], 2);
    w.call(
        "stripe__pay #1",
        b"session-1",
        "stripe__pay",
        pay("1", "a"),
        t0,
    );
    w.call(
        "stripe__pay #2",
        b"session-1",
        "stripe__pay",
        pay("2", "b"),
        t0,
    );
    let (c3, outs) = w.call(
        "stripe__pay #3",
        b"session-1",
        "stripe__pay",
        pay("3", "c"),
        t0,
    );
    w.check(
        "flood-dropped quietly: no ask, no notification",
        outs == vec![Output::FloodDropped { call: c3 }],
    );

    println!("\n12. Malformed input bytes");
    for (label, bytes) in [
        ("empty input", vec![]),
        ("unknown tag 0x7f", vec![0x7f]),
        ("random bytes", vec![0x0a, 0xff, 0x00, 0x13, 0x37]),
    ] {
        let st = w.core.step_bytes(&bytes).unwrap();
        println!(
            "    {label:<44} → {}",
            st.outputs.iter().map(show).collect::<Vec<_>>().join(", ")
        );
        w.check(
            "rejected as malformed",
            st.outputs.len() == 1
                && matches!(
                    st.outputs[0],
                    Output::Reject {
                        why: Rejection::Malformed,
                        ..
                    }
                ),
        );
    }
    let good = encode_input(&Input::Call {
        call: b"call-bad".to_vec(),
        session: b"session-1".to_vec(),
        name: "files__read_file".into(),
        args: args(r#"{"n":4.7E3}"#),
        now_ms: t0,
    });
    let mut truncated = good.clone();
    truncated.pop();
    let mut trailing = good.clone();
    trailing.push(0);
    let mut bad_number = good.clone();
    let at = good.windows(5).position(|w| w == b"4.7E3").unwrap();
    bad_number[at + 4] = b'E';
    let unsorted = encode_input(&Input::Call {
        call: b"call-bad".to_vec(),
        session: b"session-1".to_vec(),
        name: "files__read_file".into(),
        args: None,
        now_ms: t0,
    });
    // Hand-build an argument object with keys out of order: {"b":null,"a":null}.
    let mut unsorted_obj = unsorted[..unsorted.len() - 9].to_vec();
    unsorted_obj.extend_from_slice(&[1, 6, 0, 0, 0, 2, 0, 0, 0, 1, b'b', 0, 0, 0, 0, 1, b'a', 0]);
    unsorted_obj.extend_from_slice(&t0.to_be_bytes());
    for (label, bytes) in [
        ("a call with its last byte cut off", truncated),
        ("a call with a trailing byte", trailing),
        ("a call whose number text is 4.7EE", bad_number),
        ("a call whose object keys are unsorted", unsorted_obj),
    ] {
        let st = w.core.step_bytes(&bytes).unwrap();
        println!(
            "    {label:<44} → {}",
            st.outputs.iter().map(show).collect::<Vec<_>>().join(", ")
        );
        w.check(
            "rejected as malformed, to that call",
            st.outputs
                == vec![Output::Reject {
                    call: b"call-bad".to_vec(),
                    why: Rejection::Malformed,
                }],
        );
    }
    let st = w.core.step_bytes(&good).unwrap();
    println!(
        "    {:<44} → {}",
        "the same call, well formed",
        st.outputs.iter().map(show).collect::<Vec<_>>().join(", ")
    );
    let outs = w.dispatch("dispatch", b"call-bad", t0);
    w.check("4.7E3 forwarded as exactly 4.7E3", matches!(forwards(&outs)[..], [Output::Forward { args: Some(x), .. }] if x.write() == r#"{"n":4.7E3}"#));

    println!("\n13. Policy: deny, per-agent override, unknown and unlisted tools");
    w.boot(&[&a, &b], 5);
    let (c, outs) = w.call(
        "files__delete (deny)",
        b"session-1",
        "files__delete",
        args("{}"),
        t0,
    );
    w.check(
        "rejected",
        rejected(&outs, &c) == Some(Rejection::DenyPolicy),
    );
    let (c, outs) = w.call(
        "Researcher: stripe__pay (override deny)",
        b"session-r",
        "stripe__pay",
        pay("4700", flight),
        t0,
    );
    w.check(
        "rejected for Researcher",
        rejected(&outs, &c) == Some(Rejection::DenyPolicy),
    );
    let (c, outs) = w.call(
        "files__nope (not in the catalog)",
        b"session-1",
        "files__nope",
        args("{}"),
        t0,
    );
    w.check(
        "unknown tool",
        rejected(&outs, &c) == Some(Rejection::UnknownTool),
    );
    let (c, outs) = w.call(
        "files__list_directory (unlisted → default)",
        b"session-1",
        "files__list_directory",
        args("{}"),
        t0,
    );
    w.check(
        "needs approval, not allowed",
        ask_of(&outs).is_some() && !has_authorized(&outs, &c),
    );
    let outs = w.dispatch("dispatch it without approval", &c, t0);
    w.check("no forward", forwards(&outs).is_empty());

    println!("\n14. Request bytes and approval checks through Lean");
    w.boot(&[&a, &b], 5);
    let (_, outs) = w.call(
        "stripe__pay",
        b"session-1",
        "stripe__pay",
        pay("4700", flight),
        t0,
    );
    let (_, rb) = ask_of(&outs).unwrap();
    let back = w.core.decode_request(&rb).unwrap();
    w.check(
        "Lean decodes the request bytes it made",
        back.as_deref() == Some(&rb[..]),
    );
    let mut bad = rb.clone();
    bad.push(0);
    w.check(
        "and refuses them with a trailing byte",
        w.core.decode_request(&bad).unwrap().is_none(),
    );
    let pk = a.approver().pk;
    w.check(
        "a real signature checks out",
        w.core.check_approval(1, &pk, &rb, &a.sign(&rb)).unwrap(),
    );
    w.check(
        "another key's does not",
        !w.core.check_approval(1, &pk, &rb, &b.sign(&rb)).unwrap(),
    );
    w.check(
        "an unknown algorithm tag never verifies",
        !w.core
            .check_approval(0xff00, &pk, &rb, &a.sign(&rb))
            .unwrap(),
    );

    println!("\n{} checks, {} failed", w.checks, w.failures);
    if w.failures > 0 {
        std::process::exit(1);
    }
}
