use bogo_approver_iphone::wire::{B, PhoneMsg, RouteData};
use bogo_e2e::{Direction, Header};
use bogo_log::{ApproverEntry, Hex, LogEvent};
use bogo_relay_proto::{Client, SigningKey};
use bogo_state::Home;
use p256::ecdsa::{Signature, signature::Signer};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "bogo-review-{}",
            hex::encode(rand::random::<[u8; 16]>())
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn until(lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>, needle: &str) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let line = lines.next_line().await.unwrap().expect("stand-in exited");
            println!("{line}");
            if line.contains(needle) {
                break;
            }
        }
    })
    .await
    .expect("stand-in did not reach expected state");
}

// Run `cargo build -p bogo-relay` before this test, as for the relay conversation example.
#[tokio::test]
async fn revoked_vote_cannot_help_settle_a_two_of_three_request() {
    let tmp = Temp::new();
    let cert = tmp.0.join("cert.pem");
    let key = tmp.0.join("key.pem");
    assert!(
        std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-out",
            ])
            .arg(&cert)
            .arg("-keyout")
            .arg(&key)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_bogo-standin"));
    let mut relay = tokio::process::Command::new(binary.with_file_name("bogo-relay"))
        .args([
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--service",
            "review-local",
            "--max-message-age",
            "86400",
            "--mailbox-capacity",
            "100",
            "--database",
        ])
        .arg(tmp.0.join("relay.sqlite"))
        .arg("--cert")
        .arg(&cert)
        .arg("--key")
        .arg(&key)
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut ready = BufReader::new(relay.stdout.take().unwrap()).lines();
    until(&mut ready, "listening with TLS").await;
    let base = format!("https://localhost:{port}/");
    let http = Client::http(Some(
        reqwest::Certificate::from_pem(&std::fs::read(&cert).unwrap()).unwrap(),
    ))
    .unwrap();
    let root = tmp.0.join("home");
    let home = Home::open(&root).unwrap();
    let lock = home.lock().unwrap();
    let mac_keys = home.keys(&lock).unwrap();
    let (log, _, _, _) = home.open_log(&lock).unwrap();
    let mut phones = Vec::new();
    // Seed the log with three previously registered approvers. The behavior
    // under review starts after registration; all decisions use real keys/HPKE.
    for n in 1..=3u8 {
        let relay_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let client = Client::connect(&base, "review-local", &relay_key, http.clone())
            .await
            .unwrap();
        client
            .allow(vec![bogo_relay_proto::mailbox(
                &mac_keys.relay.verifying_key().to_bytes(),
            )])
            .await
            .unwrap();
        let (secret, public) = bogo_e2e::keypair();
        let approval = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let route = RouteData {
            phone_e2e: B(bogo_e2e::public_bytes(&public).to_vec()),
            phone_relay: B(relay_key.verifying_key().to_bytes().to_vec()),
            mailbox: client.mailbox.clone(),
            push: None,
            encoding_versions: vec![1],
        };
        log.append(LogEvent::ApproverRegistered {
            approver: ApproverEntry {
                id: Hex(vec![n; 32]),
                name: format!("phone{n}"),
                kind: "iphone".into(),
                alg: 1,
                sig_pk: Hex(approval
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec()),
                tx_id: Hex(vec![n; 32]),
                route: serde_json::to_value(route).unwrap(),
                attest: serde_json::json!({"environment":"simulator-test"}),
            },
            replaces: None,
        })
        .await
        .unwrap();
        phones.push((client, secret, approval));
    }
    drop(log);
    drop(lock);
    let mut mac = tokio::process::Command::new(binary)
        .arg("--home")
        .arg(&root)
        .args([
            "--relay",
            &base,
            "--relay-service",
            "review-local",
            "--relay-ca",
        ])
        .arg(&cert)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(mac.stdout.take().unwrap()).lines();
    let mut input = mac.stdin.take().unwrap();
    until(&mut lines, "Type `help`").await;
    input
        .write_all(b"send payment-approved k=2\n")
        .await
        .unwrap();
    until(&mut lines, "delivering to").await;
    let entries = bogo_log::read(&home.log_path()).unwrap().0;
    let (req, bytes) = entries
        .iter()
        .find_map(|e| match &e.event {
            LogEvent::RequestCreated { req, request, .. } => {
                Some((req.0.clone(), request.0.clone()))
            }
            _ => None,
        })
        .unwrap();
    for (index, (client, secret, approval)) in phones.iter().take(2).enumerate() {
        let signature: Signature =
            approval.sign(&[b"BOGO-APPROVAL\0v1".as_slice(), &bytes].concat());
        let msg = PhoneMsg::Approval {
            req_id: B(req.clone()),
            alg: 1,
            sig: B(signature.to_bytes().to_vec()),
        };
        let id = bogo_e2e::message_id();
        let envelope = bogo_e2e::seal(
            secret,
            &bogo_e2e::public_of(&mac_keys.e2e),
            &mac_keys.bogo_id,
            &[(index + 1) as u8; 32],
            Header {
                direction: Direction::PhoneToMac,
                kind: msg.kind(),
                id,
            },
            &serde_json::to_vec(&msg).unwrap(),
        )
        .unwrap();
        client
            .send(
                &bogo_relay_proto::mailbox(&mac_keys.relay.verifying_key().to_bytes()),
                id,
                &envelope,
            )
            .await
            .unwrap();
        until(&mut lines, "✔ APPROVED").await;
        if index == 0 {
            input.write_all(b"revoke phone1\n").await.unwrap();
            until(&mut lines, "✔ revoked").await;
        }
    }
    // Serialize the observation after the second decision has completed.
    input.write_all(b"requests\n").await.unwrap();
    until(&mut lines, "counted=").await;
    let entries = bogo_log::read(&home.log_path()).unwrap().0;
    assert!(
        !entries
            .iter()
            .any(|e| matches!(e.event, LogEvent::RequestSettled { .. })),
        "request settled with only one active approver's approval: phone1 was revoked before phone2 voted"
    );
}
