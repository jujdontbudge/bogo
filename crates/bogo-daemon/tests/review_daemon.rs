use bogo_daemon::{Command, init, request};
use bogo_log::{Hex, LogEvent};
use std::{
    path::PathBuf,
    process::{Child, Command as Process, Stdio},
};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "bogo-review-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        init(&root).unwrap();
        Self(root)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn review_r1_verify_rejects_forward_without_threshold() {
    let scratch = Scratch::new();
    let home = bogo_state::Home::open(&scratch.0).unwrap();
    let lock = home.lock().unwrap();
    let (log, _, _, _) = home.open_log(&lock).unwrap();
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../../vectors/requests.json")).unwrap();
    let vector = &vectors["requests"][0];
    let req = Hex(hex::decode(vector["decoded"]["nonce_hex"].as_str().unwrap()).unwrap());
    log.append_all(vec![
        LogEvent::RequestCreated {
            req: req.clone(),
            request: Hex(hex::decode(vector["encoded_hex"].as_str().unwrap()).unwrap()),
            to: vec![Hex(vec![1; 32]), Hex(vec![2; 32])],
            k: 2,
            pause_epoch: 0,
        },
        LogEvent::Authorized { req: req.clone() },
        LogEvent::Forwarded {
            req,
            registry_seq: 1,
        },
    ])
    .await
    .unwrap();
    let result = request(&scratch.0, Command::Verify).await;
    assert!(
        result.is_err(),
        "log verify accepted a protected forward with zero approvals for k=2: {result:?}"
    );
}

#[tokio::test]
async fn review_r2_running_log_query_survives_one_megabyte() {
    let scratch = Scratch::new();
    // Use an unused loopback port and explicit owner values, without launchd.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(scratch.0.join("bogo.toml"), format!("version = 1\n[server]\nport = {port}\nmax_body = \"1MiB\"\n[defaults]\npolicy = \"approve\"\nmax_pending = 2\n")).unwrap();
    {
        let home = bogo_state::Home::open(&scratch.0).unwrap();
        let lock = home.lock().unwrap();
        let (log, _, _, _) = home.open_log(&lock).unwrap();
        let events = (0..4)
            .map(|i| LogEvent::Call {
                call: Hex(vec![i; 16]),
                session: Hex(vec![0; 16]),
                tool: "files__write_file".into(),
                arguments: Some(serde_json::json!({"content":"x".repeat(300_000)}).to_string()),
                agent: None,
                agent_name: None,
                policy: Some("Approve".into()),
            })
            .collect();
        log.append_all(events).await.unwrap();
    }
    // The stopped command can read this exact log.
    assert!(
        request(&scratch.0, Command::Log { search: None })
            .await
            .is_ok()
    );
    let _daemon = Daemon(
        Process::new(env!("CARGO_BIN_EXE_bogo-daemon"))
            .arg("--home")
            .arg(&scratch.0)
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if scratch.0.join("run/bogo.sock").exists()
                && request(&scratch.0, Command::Status)
                    .await
                    .is_ok_and(|v| v["running"] == true)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("daemon did not become ready");
    let result = request(&scratch.0, Command::Log { search: None }).await;
    assert!(
        result.is_ok(),
        "running log query failed on four ordinary 300KB call records: {result:?}"
    );
}
