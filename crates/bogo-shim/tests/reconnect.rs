use std::{fs::File, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
};

async fn start_front(address: &str, log: &std::path::Path) -> Child {
    let child = Command::new(
        std::env::var_os("BOGO_REVIEW_STANDIN")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::current_exe()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("examples/standin")
            }),
    )
    .env("BOGO_FRONT_ADDR", address)
    .stderr(File::options().create(true).append(true).open(log).unwrap())
    .kill_on_drop(true)
    .spawn()
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    child
}

#[tokio::test]
async fn legacy_stdio_client_can_call_after_daemon_reconnect() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    drop(listener);
    let log =
        std::env::temp_dir().join(format!("bogo-review-reconnect-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&log);
    let mut front = start_front(&address, &log).await;
    let mut shim = Command::new(env!("CARGO_BIN_EXE_bogo-shim"))
        .env("BOGO_URL", format!("http://{address}/mcp"))
        .env("BOGO_AGENT_TOKEN", "standin-trip")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = shim.stdin.take().unwrap();
    let mut output = BufReader::new(shim.stdout.take().unwrap()).lines();
    input.write_all(br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"review","version":"1"}}}
"#).await.unwrap();
    let initialized = tokio::time::timeout(Duration::from_secs(5), output.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(initialized.contains("serverInfo"), "{initialized}");
    input
        .write_all(
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fixture__allow","arguments":{}}}
"#,
        )
        .await
        .unwrap();
    let before = tokio::time::timeout(Duration::from_secs(5), output.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(before.contains("Stand-in result"), "{before}");

    front.kill().await.unwrap();
    let mut front = start_front(&address, &log).await;
    // Wait for the shim's new BOGO session, rather than racing its reconnect timer.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if std::fs::read_to_string(&log)
                .unwrap()
                .matches("CORE INPUT SessionOpened")
                .count()
                == 2
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    input.write_all(br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fixture__allow","arguments":{}}}
"#).await.unwrap();
    let after = tokio::time::timeout(Duration::from_secs(5), output.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    shim.kill().await.unwrap();
    front.kill().await.unwrap();
    assert!(
        after.contains("Stand-in result"),
        "daemon is back and liveness reopened, but the legacy client cannot call: {after}"
    );
}
