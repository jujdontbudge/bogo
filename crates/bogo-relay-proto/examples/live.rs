//! Two real clients against a deployed relay. Pause for a BOGO-only restart.
//! cargo run -p bogo-relay-proto --example live -- https://bogo.eilmer.si:8443
use bogo_e2e::{Direction, Header, keypair, message_id, open, seal};
use bogo_relay_proto::{Client, Error, SigningKey};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::args().nth(1).ok_or("supply relay HTTPS URL")?;
    let service = base.strip_prefix("https://").ok_or("HTTPS required")?;
    let http = Client::http(None)?;
    let mac_auth = SigningKey::generate(&mut rand::rngs::OsRng);
    let phone_auth = SigningKey::generate(&mut rand::rngs::OsRng);
    let mac = Client::connect(&base, service, &mac_auth, http.clone()).await?;
    let phone = Client::connect(&base, service, &phone_auth, http.clone()).await?;
    assert!(matches!(
        Client::connect(&base, "wrong-service", &mac_auth, http.clone()).await,
        Err(Error::Status(401))
    ));
    println!("TLS validated; both mailbox identities authenticated; wrong service rejected");

    let (mac_secret, mac_public) = keypair();
    let (phone_secret, phone_public) = keypair();
    let bogo_id = [41; 32];
    let approver_id = [42; 32];
    let held_id = message_id();
    let held = seal(
        &mac_secret,
        &phone_public,
        &bogo_id,
        &approver_id,
        Header {
            direction: Direction::MacToPhone,
            kind: 1,
            id: held_id,
        },
        b"BOGO live encrypted approval request",
    )?;
    assert!(matches!(
        mac.send(&phone.mailbox, held_id, &held).await,
        Err(Error::Status(403))
    ));
    phone.allow(vec![mac.mailbox.clone()]).await?;
    mac.allow(vec![phone.mailbox.clone()]).await?;
    mac.send(&phone.mailbox, held_id, &held).await?;
    mac.send(&phone.mailbox, held_id, &held).await?;
    let received = phone.fetch(false).await?;
    assert_eq!(received.len(), 1);
    assert_eq!(hex::decode(&received[0].body)?, held);
    assert_eq!(
        open(
            &phone_secret,
            &mac_public,
            &bogo_id,
            &approver_id,
            Direction::MacToPhone,
            &held,
        )?
        .plaintext,
        b"BOGO live encrypted approval request"
    );
    println!(
        "Mac -> phone: sealed bytes delivered and decrypted; resend deduplicated; unlisted sender rejected"
    );

    let reply_id = message_id();
    let reply = seal(
        &phone_secret,
        &mac_public,
        &bogo_id,
        &approver_id,
        Header {
            direction: Direction::PhoneToMac,
            kind: 1,
            id: reply_id,
        },
        b"BOGO live encrypted reply",
    )?;
    let (received, sent) =
        tokio::join!(mac.fetch(true), phone.send(&mac.mailbox, reply_id, &reply));
    sent?;
    let received = received?;
    assert_eq!(received.len(), 1);
    assert_eq!(
        open(
            &mac_secret,
            &phone_public,
            &bogo_id,
            &approver_id,
            Direction::PhoneToMac,
            &hex::decode(&received[0].body)?,
        )?
        .plaintext,
        b"BOGO live encrypted reply"
    );
    mac.ack(vec![hex::encode(reply_id)]).await?;
    println!("Phone -> Mac: concurrent long-poll delivered and decrypted reply; ack succeeded");
    println!("Held ciphertext remains unacknowledged. Restart ONLY bogo-relay, then press Enter.");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    assert!(matches!(phone.fetch(false).await, Err(Error::Status(401))));
    let phone = Client::connect(&base, service, &phone_auth, http.clone()).await?;
    let mac = Client::connect(&base, service, &mac_auth, http).await?;
    let received = phone.fetch(false).await?;
    assert_eq!(received.len(), 1);
    let recovered = hex::decode(&received[0].body)?;
    assert_eq!(recovered, held);
    assert_eq!(
        open(
            &phone_secret,
            &mac_public,
            &bogo_id,
            &approver_id,
            Direction::MacToPhone,
            &recovered,
        )?
        .plaintext,
        b"BOGO live encrypted approval request"
    );
    // Idempotent send after restart also demonstrates the durable allowlist.
    mac.send(&phone.mailbox, held_id, &held).await?;
    phone.ack(vec![hex::encode(held_id)]).await?;
    assert!(phone.fetch(false).await?.is_empty());
    assert!(mac.fetch(false).await?.is_empty());
    phone.allow(vec![]).await?;
    mac.allow(vec![]).await?;
    println!(
        "BOGO-only restart: old bearer rejected; held ciphertext and allowlist survived; decrypted exact request; mailboxes cleaned"
    );
    Ok(())
}
