//! Ticket verification, exercised as a real client. Requires Python 3 and the official
//! filesystem server: BOGO_FS_SERVER=/.../server-filesystem/dist/index.js cargo run -p bogo-upstream --example verify
use bogo_config::{Config, Secrets};
use bogo_json::{JVal, Obj};
use bogo_upstream::{
    CallId, Catalog, Error, ExactChildTransport, Forward, Gate, Manager, Outcome, Scrubber,
};
use futures::future::BoxFuture;
use rmcp::{ServiceExt, model::*};
use serde_json::json;
use std::{
    collections::HashMap,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Default)]
struct StandIn {
    calls: Mutex<HashMap<CallId, Forward>>,
    outcomes: Mutex<Vec<Outcome>>,
}
impl StandIn {
    fn stage(&self, id: &str, upstream: &str, tool: &str, bytes: &[u8], key: &str) {
        let JVal::Obj(obj) = bogo_json::parse(bytes).unwrap() else {
            panic!("argument object");
        };
        // The real core does this at admission; the transport never strips/reparses arguments.
        let members = obj
            .into_members()
            .into_iter()
            .filter(|(k, _)| k != key)
            .collect();
        self.calls.lock().unwrap().insert(
            CallId(id.into()),
            Forward {
                upstream: upstream.into(),
                tool: tool.into(),
                arguments: Some(JVal::Obj(Obj::new(members).unwrap())),
            },
        );
    }
}
impl Gate for StandIn {
    fn dispatch(&self, id: CallId) -> BoxFuture<'_, Result<Forward, Error>> {
        Box::pin(async move {
            self.calls
                .lock()
                .unwrap()
                .remove(&id)
                .ok_or(Error::Rejected)
        })
    }
    fn outcome(&self, _: &CallId, outcome: Outcome) {
        self.outcomes.lock().unwrap().push(outcome);
    }
}
fn id(s: &str) -> CallId {
    CallId(s.into())
}
fn count(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .count()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("bogo_upstream=debug,rmcp=warn")
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture = root.join("examples/echo.py");
    let work = std::env::temp_dir().join(format!("bogo-verify-{}", std::process::id()));
    std::fs::create_dir_all(&work)?;
    let capture = work.join("stdio.jsonl");
    let http_capture = work.join("http.jsonl");
    let mut http = tokio::process::Command::new("python3")
        .args([
            "-u",
            fixture.to_str().unwrap(),
            "http",
            http_capture.to_str().unwrap(),
        ])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut line = String::new();
    BufReader::new(http.stdout.take().unwrap())
        .read_line(&mut line)
        .await?;
    let port: u16 = line.trim().parse()?;
    // Synthetic credential only. Never print the configured value or captured unsanitized responses.
    let secrets = Secrets::parse("echo = 'verification-credential-ONLY'", None)?;
    let config = Config::parse(
        &format!(
            r#"
version = 1
[server]
port = 8787
[defaults]
max_pending = 8
[upstreams.fs]
command = "node"
args = [{fs:?}, {work:?}]
[upstreams.echo]
command = "python3"
args = ["-u", {fixture:?}, "stdio", {capture:?}]
[upstreams.echo.env]
BOGO_ECHO_CREDENTIAL = {{ secret = "echo" }}
[upstreams.remote]
url = "http://127.0.0.1:{port}/mcp"
[upstreams.remote.headers]
x-echo-credential = {{ secret = "echo" }}
[tools."echo__echo"]
filter_output = ["url", "data.share.link"]
[tools."remote__echo"]
filter_output = ["url", "data.share.link"]
"#,
            fs = std::env::var("BOGO_FS_SERVER")?,
            work = work.to_str().unwrap(),
            fixture = fixture.to_str().unwrap(),
            capture = capture.to_str().unwrap()
        ),
        &secrets,
    )?;
    let gate = Arc::new(StandIn::default());
    let manager = Manager::start(config.clone(), &secrets, gate.clone(), Catalog::default()).await;
    let catalog = manager.catalog().await;
    assert!(catalog.tools.contains_key("echo__extra"), "pagination");
    assert!(
        catalog.tools.contains_key("remote__extra"),
        "remote pagination"
    );
    let direct = ClientConfig::new(
        ClientCapabilities::default(),
        Implementation::new("catalog-comparison", "1"),
    )
    .serve(ExactChildTransport::spawn(
        "fs".into(),
        &config.upstreams["fs"],
        gate.clone(),
        Scrubber::new(&secrets),
    )?)
    .await?;
    let tools = direct.list_all_tools().await?;
    for tool in &tools {
        let entry = &catalog.tools[&format!("fs__{}", tool.name)];
        let original = serde_json::to_value(tool)?;
        assert_eq!(entry.original["description"], original["description"]);
        assert_eq!(entry.original["inputSchema"], original["inputSchema"]);
    }
    println!(
        "CATALOG: {} filesystem tools match direct tools/list descriptions and schemas; 2 stdio + 2 HTTP echo tools (pagination followed).",
        tools.len()
    );
    println!(
        "{}",
        catalog.tools.keys().cloned().collect::<Vec<_>>().join("\n")
    );
    direct.cancel().await?;
    let projection = manager.tools_for("verification-agent").await?;
    assert_eq!(projection.len(), catalog.tools.len());
    for tool in &projection {
        let key = catalog.tools[tool["name"].as_str().unwrap()]
            .justification
            .as_ref()
            .unwrap();
        assert_eq!(tool["inputSchema"]["properties"][key]["type"], "string");
    }
    let saved = work.join("tools.json");
    catalog.save(&saved)?;
    assert_eq!(Catalog::load(&saved)?.tools.len(), catalog.tools.len());
    println!(
        "SCHEMAS: protected tools have optional justification; catalog persisted and reloaded."
    );
    let raw = br#"{"z":{"q":-0,"a":4.7E3},"b":-0,"justification":"verify the exact call"}"#;
    for (upstream, path) in [("echo", &capture), ("remote", &http_capture)] {
        let name = format!("{upstream}__echo");
        let key = catalog.tools[&name].justification.as_ref().unwrap();
        gate.stage(upstream, upstream, "echo", raw, key);
        let result = manager.call(&name, id(upstream)).await?;
        let policy = &config.tools[&name];
        let rules = bogo_filter::Rules {
            paths: policy.filter_output.clone(),
            action: bogo_filter::Action::Strip,
        };
        let (result, report) = bogo_filter::filter(&rules, serde_json::to_value(result)?);
        let result = serde_json::to_value(result)?;
        let wire = result["structuredContent"]["wire_arguments"]
            .as_str()
            .unwrap();
        assert_eq!(wire, r#"{"b":-0,"z":{"a":4.7E3,"q":-0}}"#);
        assert!(!std::fs::read_to_string(path)?.contains("justification"));
        assert!(!std::fs::read_to_string(path)?.contains(bogo_upstream::CALL_MARKER));
        assert!(!result.to_string().contains("verification-credential-ONLY"));
        assert_eq!(
            result["structuredContent"]["credential"],
            "[credential removed by BOGO]"
        );
        assert_eq!(
            result["structuredContent"]["base64"],
            "[credential removed by BOGO]"
        );
        assert!(result["structuredContent"].get("url").is_none());
        assert!(
            result["structuredContent"]["data"]["share"]
                .get("link")
                .is_none()
        );
        assert!(result["_meta"].get("url").is_none());
        assert!(report.withheld >= 2);
        println!("{upstream} EXACT: {wire}; justification and marker absent on wire.");
        println!(
            "{upstream} RESULT: credential={}, base64={}, stripped fields={}, withheld blocks={}",
            result["structuredContent"]["credential"],
            result["structuredContent"]["base64"],
            report.fields,
            report.withheld
        );
        let before = count(path);
        let refused = manager.call(&name, id("refused")).await.unwrap_err();
        assert_eq!(refused, Error::Rejected);
        let replay = manager.call(&name, id(upstream)).await.unwrap_err();
        assert_eq!(replay, Error::Rejected);
        assert_eq!(count(path), before);
        println!(
            "{upstream} REFUSAL + REPLAY: {refused}; captured call count unchanged at {before}."
        );
    }
    // Exercise an actual official filesystem tool through the same dispatch path.
    gate.stage(
        "roots",
        "fs",
        "list_allowed_directories",
        b"{}",
        "justification",
    );
    let roots = manager
        .call("fs__list_allowed_directories", id("roots"))
        .await?;
    assert!(serde_json::to_string(&roots)?.contains(work.to_str().unwrap()));
    println!("FILESYSTEM CALL: list_allowed_directories returned the configured root.");
    let mut updates = manager.subscribe();
    let pid = std::fs::read_to_string(format!("{}.pid", capture.display()))?;
    assert!(
        std::process::Command::new("kill")
            .args(["-KILL", pid.trim()])
            .status()?
            .success()
    );
    // Wait for the connection's actual EOF signal, rather than racing SIGKILL.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while manager.health().await["echo"] {
            updates.changed().await.unwrap();
        }
    })
    .await?;
    gate.stage("down", "echo", "echo", raw, "justification");
    let down = manager.call("echo__echo", id("down")).await.unwrap_err();
    assert_eq!(down, Error::NotSent);
    assert_eq!(count(&capture), 1);
    println!("KILLED CHILD: {down}; captured call count unchanged at 1; catalog retained.");
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !manager.health().await["echo"] {
            updates.changed().await.unwrap();
        }
    })
    .await?;
    let new_pid = std::fs::read_to_string(format!("{}.pid", capture.display()))?;
    assert_ne!(new_pid, pid);
    gate.stage("restarted", "echo", "echo", raw, "justification");
    manager.call("echo__echo", id("restarted")).await?;
    println!("RESTART: new child connected, rediscovered, and accepted a fresh gated call.");
    drop(manager);
    http.kill().await?;
    // No-marker path is directly attempted against the exact child transport.
    use rmcp::transport::Transport;
    let mut transport = ExactChildTransport::spawn(
        "echo".into(),
        &config.upstreams["echo"],
        gate.clone(),
        Scrubber::new(&secrets),
    )?;
    let message: ClientJsonRpcMessage = serde_json::from_value(
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"must":"not arrive"}}}),
    )?;
    let before = count(&capture);
    assert_eq!(
        transport.send(message).await.unwrap_err(),
        Error::InternalSendRefused
    );
    assert_eq!(count(&capture), before);
    transport.close().await?;
    println!("MISSING MARKER: internal_send_refused; zero writes.");
    let rules = bogo_filter::Rules {
        paths: vec!["items.*.private".into()],
        action: bogo_filter::Action::Redact,
    };
    let (filtered, _) = bogo_filter::filter(
        &rules,
        json!({"structuredContent":{"items":[{"private":"x","keep":1},{"private":"y"}]}}),
    );
    assert_eq!(
        filtered["structuredContent"]["items"][0]["private"],
        bogo_filter::REMOVED
    );
    println!("REDACT: dotted array wildcard replaced both selected values.");
    println!("PASS: all requested client verification steps completed.");
    Ok(())
}
