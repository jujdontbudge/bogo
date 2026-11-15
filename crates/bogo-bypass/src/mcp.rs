//! Attempts against BOGO itself, made the way an agent would make them: over MCP.
use crate::{Env, Report, Verdict};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use std::time::Duration;

const PROTOCOL: &str = "2025-11-25";
/// How long a protected call is left waiting before the connection is dropped.
const HOLD: Duration = Duration::from_secs(4);

struct Resp {
    status: u16,
    session: Option<String>,
    msgs: Vec<Value>,
    body: String,
}

struct Mcp {
    client: Client,
    url: String,
}

enum Sent {
    Answered(Resp),
    TimedOut,
}

impl Mcp {
    fn post(
        &self,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: &str,
        timeout: Duration,
    ) -> Result<Sent, String> {
        let mut req = self
            .client
            .post(&self.url)
            .timeout(timeout)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", PROTOCOL)
            .body(body.to_owned());
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = match req.send() {
            Ok(r) => r,
            Err(e) if e.is_timeout() => return Ok(Sent::TimedOut),
            Err(e) => return Err(e.to_string()),
        };
        let status = resp.status().as_u16();
        let session = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = match resp.text() {
            Ok(b) => b,
            Err(e) if e.is_timeout() => return Ok(Sent::TimedOut),
            Err(e) => return Err(e.to_string()),
        };
        let msgs = if body.trim_start().starts_with('{') {
            serde_json::from_str(&body).into_iter().collect()
        } else {
            body.lines()
                .filter_map(|l| l.strip_prefix("data:"))
                .filter_map(|d| serde_json::from_str(d.trim()).ok())
                .collect()
        };
        Ok(Sent::Answered(Resp {
            status,
            session,
            msgs,
            body,
        }))
    }

    fn answered(
        &self,
        token: Option<&str>,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Result<Resp, String> {
        match self.post(token, headers, body, Duration::from_secs(20))? {
            Sent::Answered(r) => Ok(r),
            Sent::TimedOut => Err("no answer in 20s".into()),
        }
    }

    /// `initialize` plus `notifications/initialized`; returns the MCP session ID.
    fn open(&self, token: &str, extra: &[(&str, &str)]) -> Result<String, String> {
        let init = json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":PROTOCOL,"capabilities":{},"clientInfo":{"name":"bogo-bypass","version":"1"}}});
        let r = self.answered(Some(token), extra, &init.to_string())?;
        if r.status != 200 || r.msgs.first().and_then(|m| m.get("result")).is_none() {
            return Err(format!(
                "initialize answered HTTP {}: {}",
                r.status,
                short(&r.body)
            ));
        }
        let sid = r.session.ok_or("no Mcp-Session-Id")?;
        let mut headers = extra.to_vec();
        headers.push(("Mcp-Session-Id", &sid));
        self.answered(
            Some(token),
            &headers,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        )?;
        Ok(sid)
    }

    fn close(&self, token: &str, sid: &str) {
        let _ = self
            .client
            .delete(&self.url)
            .bearer_auth(token)
            .header("Mcp-Session-Id", sid)
            .header("MCP-Protocol-Version", PROTOCOL)
            .timeout(Duration::from_secs(5))
            .send();
    }

    /// `at` is (token, MCP session ID).
    fn call(
        &self,
        (token, sid): (&str, &str),
        id: u64,
        name: &str,
        args: Value,
        meta: Option<Value>,
        timeout: Duration,
    ) -> Result<Sent, String> {
        let mut params = json!({"name": name, "arguments": args});
        if let Some(m) = meta {
            params["_meta"] = m;
        }
        let body = json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params});
        self.post(
            Some(token),
            &[("Mcp-Session-Id", sid)],
            &body.to_string(),
            timeout,
        )
    }
}

fn short(s: &str) -> String {
    let s = s.replace('\n', " ");
    if s.chars().count() > 160 {
        format!("{}…", s.chars().take(160).collect::<String>())
    } else {
        s
    }
}

/// The final message's outcome: (is_error, text).
fn outcome(r: &Resp) -> (bool, String) {
    let Some(m) = r.msgs.iter().rev().find(|m| m.get("id").is_some()) else {
        return (true, format!("HTTP {} {}", r.status, short(&r.body)));
    };
    if let Some(e) = m.get("error") {
        return (
            true,
            format!(
                "JSON-RPC error {}: {}",
                e["code"],
                e["message"].as_str().unwrap_or("")
            ),
        );
    }
    let res = &m["result"];
    let text = res["content"]
        .as_array()
        .map(|c| {
            c.iter()
                .filter_map(|b| b["text"].as_str())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    (res["isError"].as_bool().unwrap_or(false), short(&text))
}

/// True when a result carries no content: every array in it is empty.
fn nothing(v: &Value) -> bool {
    match v {
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.values().all(nothing),
        _ => true,
    }
}

fn hex(n: usize) -> String {
    (0..n)
        .map(|_| format!("{:x}", rand::random::<u8>() & 15))
        .collect()
}

pub fn run(r: &mut Report, env: &Env) {
    let (Some(url), Some(token)) = (env.url.clone(), env.token.clone()) else {
        r.add(
            Verdict::Fail,
            "mcp",
            "BOGO attempts",
            "BOGO_URL and BOGO_AGENT_TOKEN are required",
        );
        return;
    };
    let m = Mcp {
        client: Client::builder().no_proxy().build().expect("http client"),
        url,
    };
    let token = token.as_str();

    // Control: BOGO answers through the gate with a valid token.
    let sid = match m.open(token, &[]) {
        Ok(s) => {
            r.add(
                Verdict::Ok,
                "mcp",
                format!("initialize at {} with this agent's token", m.url),
                "BOGO answered through the gate",
            );
            s
        }
        Err(e) => {
            r.add(
                Verdict::Fail,
                "mcp",
                format!("initialize at {}", m.url),
                format!("control failed: {e}"),
            );
            return;
        }
    };
    let list = m.answered(
        Some(token),
        &[("Mcp-Session-Id", &sid)],
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    );
    let tools: Vec<String> = list
        .ok()
        .and_then(|l| l.msgs.into_iter().find(|m| m.get("result").is_some()))
        .and_then(|m| m["result"]["tools"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_owned))
        .collect();
    r.add(
        Verdict::Info,
        "mcp",
        "tools/list",
        format!("{} tools: {}", tools.len(), tools.join(", ")),
    );
    r.stopped(
        !tools.contains(&env.deny_tool),
        "mcp",
        format!("see the deny-policy tool {} in tools/list", env.deny_tool),
        if tools.contains(&env.deny_tool) {
            "listed"
        } else {
            "hidden (hide_denied)"
        },
    );

    // Authentication.
    let init = json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":PROTOCOL,"capabilities":{},"clientInfo":{"name":"x","version":"1"}}}).to_string();
    let wrong = format!("bogo_agt_{}", hex(43));
    for (label, tok, headers) in [
        ("MCP initialize with no token", None, vec![]),
        (
            "MCP initialize with a wrong token",
            Some(wrong.as_str()),
            vec![],
        ),
        (
            "MCP initialize with a browser Origin header",
            Some(token),
            vec![("Origin", "http://evil.example")],
        ),
        (
            "MCP initialize with a foreign Host header",
            Some(token),
            vec![("Host", "api.stripe.com")],
        ),
    ] {
        match m.answered(tok, &headers, &init) {
            Ok(resp) => r.stopped(
                resp.status >= 400,
                "auth",
                label,
                format!("HTTP {}", resp.status),
            ),
            Err(e) => r.stopped(true, "auth", label, e),
        }
    }
    for (label, body) in [
        ("JSON-RPC batch", format!("[{init}]")),
        ("duplicate keys (smuggling a second name)", r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"files__read_text_file","name":"files__write_file","arguments":{}}}"#.to_owned()),
    ] {
        match m.answered(Some(token), &[("Mcp-Session-Id", &sid)], &body) {
            Ok(resp) => r.stopped(resp.status >= 400, "parse", label, format!("HTTP {}", resp.status)),
            Err(e) => r.stopped(true, "parse", label, e),
        }
    }

    // Capabilities BOGO does not proxy, each of which would route around the gate.
    for (id, method, params) in [
        (20, "resources/list", json!({})),
        (21, "resources/read", json!({"uri":"file:///etc/passwd"})),
        (22, "prompts/list", json!({})),
        (
            23,
            "completion/complete",
            json!({"ref":{"type":"ref/prompt","name":"x"},"argument":{"name":"a","value":"b"}}),
        ),
    ] {
        let body = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}).to_string();
        match m.answered(Some(token), &[("Mcp-Session-Id", &sid)], &body) {
            Ok(resp) => {
                let (err, text) = outcome(&resp);
                let empty = resp
                    .msgs
                    .iter()
                    .rev()
                    .find(|m| m.get("id").is_some())
                    .is_some_and(|m| nothing(&m["result"]));
                let how = if err {
                    text
                } else if empty {
                    format!(
                        "answered by BOGO itself with an empty result: {}",
                        short(&resp.body.replace("data: ", ""))
                    )
                } else {
                    format!("upstream content came back: {}", short(&resp.body))
                };
                r.stopped(err || empty, "mcp", format!("{method} (not proxied)"), how);
            }
            Err(e) => r.stopped(true, "mcp", format!("{method} (not proxied)"), e),
        }
    }

    // The filesystem root, from the allowed listing tool.
    let root = match m.call(
        (token, &sid),
        30,
        "files__list_allowed_directories",
        json!({}),
        None,
        Duration::from_secs(20),
    ) {
        Ok(Sent::Answered(resp)) => {
            let (_, text) = outcome(&resp);
            text.split_whitespace()
                .find(|w| w.starts_with('/'))
                .map(str::to_owned)
        }
        _ => None,
    }
    .or_else(|| std::env::var("BYPASS_FS_ROOT").ok());
    let Some(root) = root else {
        r.add(
            Verdict::Fail,
            "mcp",
            "learn the filesystem root",
            "files__list_allowed_directories gave no path and BYPASS_FS_ROOT is unset",
        );
        return;
    };
    r.add(
        Verdict::Info,
        "mcp",
        "filesystem upstream root",
        root.clone(),
    );

    // Calling around the namespace, or a denied tool.
    let probe = format!("{root}/bypass-{}.txt", hex(8));
    for (id, name, args) in [
        (40, "write_file", json!({"path": probe, "content": "x"})),
        (
            41,
            "Files__write_file",
            json!({"path": probe, "content": "x"}),
        ),
        (
            42,
            "files__write_file ",
            json!({"path": probe, "content": "x"}),
        ),
        (
            43,
            env.deny_tool.as_str(),
            json!({"source": format!("{root}/a"), "destination": format!("{root}/b")}),
        ),
    ] {
        let label = if name == env.deny_tool {
            format!("call deny-policy tool {name}")
        } else {
            format!("call un-namespaced or altered name {name:?}")
        };
        match m.call((token, &sid), id, name, args, None, Duration::from_secs(20)) {
            Ok(Sent::Answered(resp)) => {
                let (err, text) = outcome(&resp);
                r.stopped(err, "mcp", label, text);
            }
            Ok(Sent::TimedOut) => r.stopped(false, "mcp", label, "held as if it were a real tool"),
            Err(e) => r.stopped(true, "mcp", label, e),
        }
    }
    check_absent(r, &m, token, &sid, env, &probe);

    // A protected call without approval, then with forged and replayed approvals.
    let fake_sig = hex(128);
    let mut attempts: Vec<(String, Value, Option<Value>)> = vec![
        (
            "protected call with no approval".into(),
            json!({"content": "bypass: no approval\n"}),
            None,
        ),
        (
            "fake approval smuggled in _meta (incl. BOGO's internal call marker)".into(),
            json!({"content": "bypass: forged _meta\n"}),
            Some(
                json!({"si.eilmer.bogo/call": hex(32), "si.eilmer.bogo/approval": {"approver": "Soft A", "sig": fake_sig}, "approved": true}),
            ),
        ),
        (
            "fake approval smuggled in the arguments".into(),
            json!({"content": "bypass: forged args\n", "approval": {"approver": "Soft A", "sig": fake_sig}, "approved": true, "bogo_approved": true}),
            None,
        ),
    ];
    if let Some(sig) = &env.replay_sig {
        attempts.push((
            "replay a real approval signature taken from the audit log".into(),
            json!({"content": "bypass: replayed approval\n", "approval": sig}),
            Some(json!({"si.eilmer.bogo/approval": sig, "approval": sig})),
        ));
    } else {
        r.add(Verdict::Info, "approval", "replay a real approval signature", "BYPASS_REPLAY_SIG not given (no approval in the log yet); the forged ones above cover the shape");
    }
    for (i, (label, mut args, meta)) in attempts.into_iter().enumerate() {
        let path = format!("{root}/bypass-held-{}.txt", hex(8));
        args["path"] = json!(path);
        args["justification"] = json!("bogo-bypass: this call must never run");
        let id = 50 + i as u64;
        match m.call((token, &sid), id, &env.protected_tool, args, meta, HOLD) {
            Ok(Sent::TimedOut) => r.stopped(true, "approval", format!("{label} ({})", env.protected_tool), format!("held for owner approval; after {}s the connection was dropped, which ends the call", HOLD.as_secs())),
            Ok(Sent::Answered(resp)) => {
                let (err, text) = outcome(&resp);
                r.stopped(err, "approval", format!("{label} ({})", env.protected_tool), text);
            }
            Err(e) => r.stopped(true, "approval", label, e),
        }
        check_absent(r, &m, token, &sid, env, &path);
    }

    // The same call again in a new session cannot inherit anything.
    match m.open(token, &[]) {
        Ok(sid2) => {
            let path = format!("{root}/bypass-held-{}.txt", hex(8));
            let args = json!({"path": path, "content": "bypass: new session\n", "justification": "bogo-bypass"});
            match m.call((token, &sid2), 60, &env.protected_tool, args, None, HOLD) {
                Ok(Sent::TimedOut) => r.stopped(
                    true,
                    "approval",
                    "repeat a protected call in a fresh session",
                    "held again: a new session is a new request",
                ),
                Ok(Sent::Answered(resp)) => {
                    let (err, text) = outcome(&resp);
                    r.stopped(
                        err,
                        "approval",
                        "repeat a protected call in a fresh session",
                        text,
                    );
                }
                Err(e) => r.stopped(
                    true,
                    "approval",
                    "repeat a protected call in a fresh session",
                    e,
                ),
            }
            check_absent(r, &m, token, &sid2, env, &path);
            m.close(token, &sid2);
        }
        Err(e) => r.add(Verdict::Fail, "approval", "open a second session", e),
    }

    sessions(r, &m, token, env);
    m.close(token, &sid);
}

fn check_absent(r: &mut Report, m: &Mcp, token: &str, sid: &str, env: &Env, path: &str) {
    match m.call(
        (token, sid),
        90,
        &env.read_tool,
        json!({"path": path}),
        None,
        Duration::from_secs(20),
    ) {
        Ok(Sent::Answered(resp)) => {
            let (err, text) = outcome(&resp);
            r.stopped(
                err,
                "effect",
                format!("read {path} back through BOGO"),
                if err {
                    format!("not written: {text}")
                } else {
                    format!("the file exists: {text}")
                },
            );
        }
        Ok(Sent::TimedOut) => r.add(
            Verdict::Fail,
            "effect",
            format!("read {path} back"),
            "the allowed read was held",
        ),
        Err(e) => r.add(Verdict::Fail, "effect", format!("read {path} back"), e),
    }
}

fn sessions(r: &mut Report, m: &Mcp, token: &str, env: &Env) {
    let Some(second) = env.second_token.as_deref() else {
        r.add(
            Verdict::Fail,
            "session",
            "reuse a session with another agent's token",
            "BOGO_BYPASS_SECOND_TOKEN is not set",
        );
        return;
    };
    let list = r#"{"jsonrpc":"2.0","id":70,"method":"tools/list"}"#;
    // An MCP session opened by this agent, then used with the second agent's token.
    match m.open(token, &[]) {
        Ok(sid) => {
            match m.answered(Some(second), &[("Mcp-Session-Id", &sid)], list) {
                Ok(resp) => {
                    let (err, text) = outcome(&resp);
                    r.stopped(
                        err || resp.status >= 400,
                        "session",
                        "reuse this agent's Mcp-Session-Id with another agent's token",
                        text,
                    );
                }
                Err(e) => r.stopped(
                    true,
                    "session",
                    "reuse this agent's Mcp-Session-Id with another agent's token",
                    e,
                ),
            }
            match m.answered(Some(token), &[("Mcp-Session-Id", &sid)], list) {
                Ok(resp) => {
                    let (err, text) = outcome(&resp);
                    r.add(
                        Verdict::Info,
                        "session",
                        "the original agent's session afterwards",
                        if err || resp.status >= 400 {
                            format!("closed: {text}")
                        } else {
                            "still open".into()
                        },
                    );
                }
                Err(e) => r.add(
                    Verdict::Info,
                    "session",
                    "the original agent's session afterwards",
                    e,
                ),
            }
            m.close(token, &sid);
        }
        Err(e) => r.add(Verdict::Fail, "session", "open a session", e),
    }
    // A shim session (Bogo-Session with its liveness stream), then used with the second token.
    let bogo_session = hex(32);
    let live_url = m.url.replace("/mcp", "/mcp/bogo-liveness");
    let (bs, tk) = (bogo_session.clone(), token.to_owned());
    let (opened, status) = std::sync::mpsc::channel();
    // The shim session lives only while this stream is held open, so the thread keeps
    // reading it until the process ends.
    std::thread::spawn(move || {
        let client = Client::builder().no_proxy().build().unwrap();
        match client
            .get(live_url)
            .bearer_auth(tk)
            .header("Bogo-Session", bs)
            .send()
        {
            Ok(mut resp) => {
                let _ = opened.send(Ok(resp.status().as_u16()));
                let _ = std::io::copy(&mut resp, &mut std::io::sink());
            }
            Err(e) => {
                let _ = opened.send(Err(e.to_string()));
            }
        }
    });
    match status.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(200)) => {}
        other => {
            r.add(
                Verdict::Fail,
                "session",
                "open a shim liveness stream",
                format!("{other:?}"),
            );
            return;
        }
    }
    let headers = [("Bogo-Session", bogo_session.as_str())];
    match m.open(token, &headers) {
        Ok(sid) => {
            let mut h = headers.to_vec();
            h.push(("Mcp-Session-Id", &sid));
            match m.answered(Some(second), &h, list) {
                Ok(resp) => {
                    let (err, text) = outcome(&resp);
                    r.stopped(
                        err || resp.status >= 400,
                        "session",
                        "reuse this agent's Bogo-Session with another agent's token",
                        text,
                    );
                }
                Err(e) => r.stopped(
                    true,
                    "session",
                    "reuse this agent's Bogo-Session with another agent's token",
                    e,
                ),
            }
            m.close(token, &sid);
        }
        Err(e) => r.add(Verdict::Fail, "session", "open a shim-style session", e),
    }
}
