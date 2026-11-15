//! A real local TLS conversation, including kill/restart. Args: relay binary,
//! temporary directory containing cert.pem and key.pem (generated outside repo).
use bogo_e2e::{Direction as D, Header, keypair, message_id, open, peek_id, seal};
use bogo_relay_proto::*;
use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};
struct Relay(Child);
impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn start(binary: &str, dir: &Path, port: u16) -> Relay {
    let mut child = Command::new(binary)
        .args([
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--service",
            "bogo-local",
            "--max-message-age",
            "86400",
            "--mailbox-capacity",
            "2",
            "--database",
            dir.join("relay.sqlite").to_str().unwrap(),
            "--cert",
            dir.join("cert.pem").to_str().unwrap(),
            "--key",
            dir.join("key.pem").to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert!(ready.contains("listening with TLS"), "relay failed startup");
    println!("{}", ready.trim());
    Relay(child)
}
async fn connect(base: &str, key: &SigningKey, http: &reqwest::Client) -> Client {
    Client::connect(base, "bogo-local", key, http.clone())
        .await
        .unwrap()
}
fn refused<T>(result: Result<T, Error>, status: u16) {
    assert!(matches!(result,Err(Error::Status(s)) if s==status));
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let dir = PathBuf::from(&args[2]);
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let base = format!("https://localhost:{port}");
    let root = reqwest::Certificate::from_pem(&std::fs::read(dir.join("cert.pem"))?)?;
    let http = Client::http(Some(root))?;
    let mut relay = start(&args[1], &dir, port);
    let mac_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let phone_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let rogue_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mac = connect(&base, &mac_key, &http).await;
    let phone = connect(&base, &phone_key, &http).await;
    let rogue = connect(&base, &rogue_key, &http).await;
    let no_auth = http
        .post(format!("{base}/v1/fetch"))
        .json(&Fetch { wait: false })
        .send()
        .await?;
    assert_eq!(no_auth.status(), 401);
    // Signature from a different service identity is not valid here.
    refused(
        Client::connect(&base, "another-relay", &rogue_key, http.clone()).await,
        401,
    );
    // Verify replay consumes a challenge, including after a successful verification.
    use ed25519_dalek::Signer;
    let public = hex::encode(rogue_key.verifying_key().as_bytes());
    let c: Challenge = http
        .post(format!("{base}/v1/auth/challenge"))
        .json(&ChallengeRequest {
            r#pub: public.clone(),
        })
        .send()
        .await?
        .json()
        .await?;
    let sig = rogue_key.sign(&auth_bytes(
        "bogo-local",
        &rogue_key.verifying_key().to_bytes(),
        &c.challenge,
    )?);
    let request = VerifyRequest {
        r#pub: public,
        sig: hex::encode(sig.to_bytes()),
    };
    assert_eq!(
        http.post(format!("{base}/v1/auth/verify"))
            .json(&request)
            .send()
            .await?
            .status(),
        200
    );
    assert_eq!(
        http.post(format!("{base}/v1/auth/verify"))
            .json(&request)
            .send()
            .await?
            .status(),
        401
    );
    println!("auth: missing bearer, wrong service, replayed challenge -> 401");
    let (ms, mp) = keypair();
    let (ps, pp) = keypair();
    let bogo = [1; 32];
    let approver = [2; 32];
    let id = message_id();
    let plain = b"private approval request, never visible to relay";
    let envelope = seal(
        &ms,
        &pp,
        &bogo,
        &approver,
        Header {
            direction: D::MacToPhone,
            kind: 1,
            id,
        },
        plain,
    )?;
    refused(mac.send(&phone.mailbox, id, &envelope).await, 403);
    phone.allow(vec![mac.mailbox.clone()]).await?;
    mac.allow(vec![phone.mailbox.clone()]).await?;
    refused(rogue.send(&phone.mailbox, id, &envelope).await, 403);
    println!("allowlists: owner-only configuration, unlisted writer -> 403");
    mac.send(&phone.mailbox, id, &envelope).await?;
    mac.send(&phone.mailbox, id, &envelope).await?;
    let messages = phone.fetch(false).await?;
    assert_eq!(messages.len(), 1);
    let received = hex::decode(&messages[0].body)?;
    let opened = open(&ps, &mp, &bogo, &approver, D::MacToPhone, &received)?;
    assert_eq!(opened.plaintext, plain);
    let mut seen = std::collections::HashSet::new();
    assert!(seen.insert(opened.id));
    assert!(!seen.insert(peek_id(&received)?));
    let mut bad = received.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(open(&ps, &mp, &bogo, &approver, D::MacToPhone, &bad).is_err());
    let mut bad_header = received.clone();
    bad_header[10] ^= 1;
    assert!(open(&ps, &mp, &bogo, &approver, D::MacToPhone, &bad_header).is_err());
    assert!(open(&ps, &mp, &[3; 32], &approver, D::MacToPhone, &received).is_err());
    assert!(open(&ps, &pp, &bogo, &approver, D::MacToPhone, &received).is_err());
    println!(
        "HPKE: Mac -> phone exact plaintext; replay ID recognised; ciphertext/header/context/sender tampering refused"
    );
    let reply_id = message_id();
    let reply = seal(
        &ps,
        &mp,
        &bogo,
        &approver,
        Header {
            direction: D::PhoneToMac,
            kind: 1,
            id: reply_id,
        },
        b"signed decision bytes",
    )?;
    phone.send(&mac.mailbox, reply_id, &reply).await?;
    let inbound = mac.fetch(false).await?;
    assert_eq!(
        open(
            &ms,
            &pp,
            &bogo,
            &approver,
            D::PhoneToMac,
            &hex::decode(&inbound[0].body)?
        )?
        .plaintext,
        b"signed decision bytes"
    );
    mac.ack(vec![hex::encode(reply_id)]).await?;
    // SQLite holds an opaque BLOB identical to what was sent; no message plaintext.
    let db = rusqlite::Connection::open(dir.join("relay.sqlite"))?;
    let (rows, bytes): (u64, u64) =
        db.query_row("SELECT count(*),sum(length(body)) FROM messages", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    assert_eq!(rows, 1);
    let blob: Vec<u8> = db.query_row("SELECT body FROM messages", [], |r| r.get(0))?;
    assert_eq!(blob, envelope);
    assert!(!blob.windows(plain.len()).any(|w| w == plain));
    let schema: Vec<String> = db
        .prepare("SELECT name FROM pragma_table_info('messages')")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    println!("SQLite: columns={schema:?}; rows={rows}, ciphertext_bytes={bytes}; plaintext absent");
    drop(db);
    // One additional pending message fills this explicitly tiny mailbox.
    let id2 = message_id();
    let env2 = seal(
        &ms,
        &pp,
        &bogo,
        &approver,
        Header {
            direction: D::MacToPhone,
            kind: 2,
            id: id2,
        },
        b"second",
    )?;
    mac.send(&phone.mailbox, id2, &env2).await?;
    let id3 = message_id();
    let env3 = seal(
        &ms,
        &pp,
        &bogo,
        &approver,
        Header {
            direction: D::MacToPhone,
            kind: 2,
            id: id3,
        },
        b"third",
    )?;
    refused(mac.send(&phone.mailbox, id3, &env3).await, 409);
    // A different ciphertext with an existing ID is a conflict, even for the owner sender.
    let collision = seal(
        &ms,
        &pp,
        &bogo,
        &approver,
        Header {
            direction: D::MacToPhone,
            kind: 1,
            id,
        },
        b"changed",
    )?;
    refused(mac.send(&phone.mailbox, id, &collision).await, 409);
    println!("durability: idempotent resend; full mailbox and ID collision -> 409");
    relay.0.kill()?;
    relay.0.wait()?;
    drop(relay);
    relay = start(&args[1], &dir, port);
    refused(phone.fetch(false).await, 401); // old bearer does not survive restart
    let phone = connect(&base, &phone_key, &http).await;
    let mac = connect(&base, &mac_key, &http).await;
    let rogue = connect(&base, &rogue_key, &http).await;
    let messages = phone.fetch(false).await?;
    assert_eq!(messages.len(), 2);
    assert!(
        messages
            .iter()
            .any(|m| hex::decode(&m.body).unwrap() == envelope)
    );
    println!(
        "restart after kill: both undelivered ciphertexts recovered; allowlists retained; old bearer rejected"
    );
    // A stranger cannot retract another sender's delivery.
    rogue
        .retract(phone.mailbox.clone(), vec![hex::encode(id)])
        .await?;
    assert_eq!(phone.fetch(false).await?.len(), 2);
    mac.retract(phone.mailbox.clone(), vec![hex::encode(id2)])
        .await?;
    phone.ack(vec![hex::encode(id)]).await?;
    assert!(phone.fetch(false).await?.is_empty());
    let (delivery, sent) = tokio::join!(phone.fetch(true), mac.send(&phone.mailbox, id3, &env3));
    sent?;
    assert_eq!(delivery?.len(), 1);
    phone.ack(vec![hex::encode(id3)]).await?;
    println!("ack/retract: recipient ack, sender-only retract, and long-poll delivery passed");
    let offer = Offer {
        offer_id: hex::encode(message_id()),
        e_pub_m: hex::encode([6; 32]),
        mac_label: "Local BOGO Mac".into(),
    };
    mac.offer(&offer).await?;
    mac.offer(&offer).await?;
    assert_eq!(phone.offers().await?.len(), 1);
    refused(rogue.offer(&offer).await, 403);
    phone
        .lobby_send(
            &offer.offer_id,
            &LobbySend {
                msg_id: hex::encode(message_id()),
                body: "abcd".into(),
            },
        )
        .await?;
    refused(
        rogue
            .lobby_send(
                &offer.offer_id,
                &LobbySend {
                    msg_id: hex::encode(message_id()),
                    body: "abcd".into(),
                },
            )
            .await,
        403,
    );
    refused(rogue.lobby_fetch(&offer.offer_id).await, 403);
    assert_eq!(mac.lobby_fetch(&offer.offer_id).await?.len(), 1);
    mac.lobby_send(
        &offer.offer_id,
        &LobbySend {
            msg_id: hex::encode(message_id()),
            body: "cdef".into(),
        },
    )
    .await?;
    assert_eq!(phone.lobby_fetch(&offer.offer_id).await?.len(), 1);
    assert!(phone.offers().await?.is_empty());
    refused(phone.delete_offer(&offer.offer_id).await, 403);
    mac.delete_offer(&offer.offer_id).await?;
    refused(phone.lobby_fetch(&offer.offer_id).await, 404);
    println!(
        "lobby: publish/refresh/list, one peer, bidirectional opaque phase data, owner-only delete passed"
    );
    phone.allow(vec![]).await?;
    refused(mac.send(&phone.mailbox, id, &envelope).await, 403);
    println!("allowlist revocation persisted; conversation complete");
    drop(relay);
    Ok(())
}
