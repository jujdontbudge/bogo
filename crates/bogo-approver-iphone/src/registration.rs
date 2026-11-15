//! Registration on the Mac: numeric comparison over the relay lobby, then
//! proof of possession and App Attest (ARCHITECTURE §3.11). Nothing becomes
//! trusted here; the hub commits only what [`MacRegistration`] hands it.
use crate::{IphoneRoute, wire::*};
use async_trait::async_trait;
use base64::Engine;
use bogo_approver::*;
use bogo_relay_proto::{LobbySend, Offer};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long each side waits for the other during registration.
const STEP_TIMEOUT: Duration = Duration::from_secs(600);
const POLL: Duration = Duration::from_millis(300);
const REFRESH: Duration = Duration::from_secs(30);

/// True only in a test build (`test-registration`), which accepts the
/// simulator-only path: a registration without App Attest evidence.
pub const fn accepts_simulator_registration() -> bool {
    cfg!(feature = "test-registration")
}

fn transport(e: impl std::fmt::Display) -> RegError {
    RegError::Transport(e.to_string())
}

struct Lobby<'a> {
    route: &'a IphoneRoute,
    offer_id: [u8; 16],
    offer_hex: String,
    peer: Option<String>,
    seen: std::collections::HashSet<String>,
    refresher: tokio::task::JoinHandle<()>,
}

impl Lobby<'_> {
    async fn send(&self, phase: u8, payload: &[u8]) -> Result<(), RegError> {
        let msg = LobbySend {
            msg_id: hex::encode(phase_msg_id(&self.offer_id, phase)),
            body: hex::encode(phase_body(phase, payload)),
        };
        let id = self.offer_hex.clone();
        self.route
            .relay
            .call(|c| {
                let (id, msg) = (id.clone(), msg.clone());
                async move { c.lobby_send(&id, &msg).await }
            })
            .await
            .map_err(transport)
    }

    /// Wait for the phone's next phase, accepting only `want` or an abort,
    /// and only from the one phone that claimed this offer.
    async fn next(&mut self, want: u8) -> Result<Vec<u8>, RegError> {
        let deadline = Instant::now() + STEP_TIMEOUT;
        loop {
            let id = self.offer_hex.clone();
            let msgs = self
                .route
                .relay
                .call(|c| {
                    let id = id.clone();
                    async move { c.lobby_fetch(&id).await }
                })
                .await
                .map_err(transport)?;
            for m in msgs {
                if self.seen.contains(&m.msg_id) {
                    continue;
                }
                self.seen.insert(m.msg_id.clone());
                if self.peer.as_ref().is_some_and(|p| p != &m.from) {
                    continue;
                }
                let Ok(body) = hex::decode(&m.body) else { continue };
                let Some((&phase, payload)) = body.split_first() else { continue };
                if m.msg_id != hex::encode(phase_msg_id(&self.offer_id, phase)) {
                    continue;
                }
                if phase == PHASE_PHONE_ABORT {
                    return Err(RegError::Aborted("the phone cancelled".into()));
                }
                if phase == want {
                    self.peer.get_or_insert(m.from.clone());
                    return Ok(payload.to_vec());
                }
            }
            if Instant::now() > deadline {
                return Err(RegError::Aborted("timed out waiting for the phone".into()));
            }
            tokio::time::sleep(POLL).await;
        }
    }

    async fn close(&self) {
        self.refresher.abort();
        let id = self.offer_hex.clone();
        let _ = self
            .route
            .relay
            .call(|c| {
                let id = id.clone();
                async move { c.delete_offer(&id).await }
            })
            .await;
    }

    async fn abort(&self) {
        let _ = self.send(PHASE_MAC_ABORT, &[]).await;
        self.close().await;
    }
}

pub(crate) async fn run(
    route: &IphoneRoute,
    name: &str,
    owner: &dyn OwnerPrompt,
) -> Result<Box<dyn PendingRegistration>, RegError> {
    let e_m = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let e_pub_m = x25519_dalek::PublicKey::from(&e_m).to_bytes();
    let offer_id: [u8; 16] = rand::random();
    let offer = Offer {
        offer_id: hex::encode(offer_id),
        e_pub_m: hex::encode(e_pub_m),
        mac_label: route.cfg.mac_name.clone(),
    };
    {
        let offer = offer.clone();
        route
            .relay
            .call(|c| {
                let offer = offer.clone();
                async move { c.offer(&offer).await }
            })
            .await
            .map_err(transport)?;
    }
    // Keep the offer alive while the command runs. The refresher needs its own
    // relay connection because the lobby refresh must come from the owner key.
    let refresher = {
        let relay = crate::relay::Relay::new(
            &route.cfg.relay_url,
            &route.cfg.relay_service,
            route.cfg.relay_root_pem.as_deref(),
            route.keys.relay.clone(),
        )
        .map_err(RegError::Transport)?;
        let offer = offer.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(REFRESH).await;
                let offer = offer.clone();
                let _ = relay
                    .call(|c| {
                        let offer = offer.clone();
                        async move { c.offer(&offer).await }
                    })
                    .await;
            }
        })
    };
    let mut lobby = Lobby {
        route,
        offer_hex: offer.offer_id.clone(),
        offer_id,
        peer: None,
        seen: Default::default(),
        refresher,
    };
    owner
        .status(&format!(
            "Waiting for the phone: open BOGO → Macs → Add Mac and pick \"{}\".",
            route.cfg.mac_name
        ))
        .await;
    match exchange(&mut lobby, e_m, e_pub_m, name, owner).await {
        Ok(p) => Ok(p),
        Err(e) => {
            if matches!(e, RegError::Refused(_)) {
                lobby.close().await;
            } else {
                lobby.abort().await;
            }
            Err(e)
        }
    }
}

async fn exchange<'a>(
    lobby: &mut Lobby<'a>,
    e_m: x25519_dalek::StaticSecret,
    e_pub_m: [u8; 32],
    name: &str,
    owner: &dyn OwnerPrompt,
) -> Result<Box<dyn PendingRegistration>, RegError> {
    let route = lobby.route;
    let e_pub_p: [u8; 32] = lobby
        .next(PHASE_HELLO)
        .await?
        .try_into()
        .map_err(|_| RegError::Aborted("malformed hello".into()))?;
    let n_m: [u8; 16] = rand::random();
    let commit = commitment(&e_pub_m, &e_pub_p, &n_m);
    lobby.send(PHASE_COMMIT, &commit).await?;
    let n_p: [u8; 16] = lobby
        .next(PHASE_PHONE_NONCE)
        .await?
        .try_into()
        .map_err(|_| RegError::Aborted("malformed phone nonce".into()))?;
    lobby.send(PHASE_REVEAL, &n_m).await?;
    let shared = e_m.diffie_hellman(&x25519_dalek::PublicKey::from(e_pub_p));
    if !shared.was_contributory() {
        return Err(RegError::Aborted("the phone sent a low-order key".into()));
    }
    let t = Transcript { offer_id: lobby.offer_id, e_pub_m, e_pub_p, commit, n_m, n_p };
    let th = t.hash();
    let key = phase_key(shared.as_bytes(), &th);
    let code = t.code();
    if !owner.confirm_code(&code).await {
        return Err(RegError::Mismatch);
    }
    let challenge: [u8; 32] = rand::random();
    let confirmed = MacConfirmed {
        mac_e2e: B(route.keys.e2e_public.to_vec()),
        mac_relay: B(route.keys.relay.verifying_key().to_bytes().to_vec()),
        bogo_id: B(route.keys.bogo_id.to_vec()),
        mac_name: route.cfg.mac_name.clone(),
        challenge: B(challenge.to_vec()),
    };
    let plaintext = serde_json::to_vec(&confirmed).map_err(transport)?;
    lobby
        .send(PHASE_MAC_CONFIRMED, &seal_phase(&key, &lobby.offer_id, PHASE_MAC_CONFIRMED, &plaintext))
        .await?;
    owner.status("Confirmed on the Mac. Now confirm on the phone with Face ID.").await;
    let sealed = lobby.next(PHASE_REG_SUBMIT).await?;
    let submit: RegSubmit = open_phase(&key, &lobby.offer_id, PHASE_REG_SUBMIT, &sealed)
        .and_then(|p| serde_json::from_slice(&p).ok())
        .ok_or_else(|| RegError::Aborted("the phone's submission did not open".into()))?;
    let peer = lobby.peer.clone().unwrap_or_default();
    let checked = check(route, &submit, &peer, &th, &challenge);
    let new = match checked {
        Ok(new) => new,
        Err(why) => {
            let refused = serde_json::to_vec(&RefusedPhase { why: why.clone() }).unwrap_or_default();
            let _ = lobby
                .send(PHASE_REFUSED, &seal_phase(&key, &lobby.offer_id, PHASE_REFUSED, &refused))
                .await;
            return Err(RegError::Refused(why));
        }
    };
    owner
        .status(&format!("Phone checks passed for \"{name}\"; recording the registration."))
        .await;
    let relay = crate::relay::Relay::new(
        &route.cfg.relay_url,
        &route.cfg.relay_service,
        route.cfg.relay_root_pem.as_deref(),
        route.keys.relay.clone(),
    )
    .map_err(RegError::Transport)?;
    let phone_e2e = bogo_e2e::public_from(&submit.phone_e2e.0).map_err(|_| RegError::Aborted("bad key".into()))?;
    Ok(Box::new(MacRegistration {
        relay,
        offer_hex: lobby.offer_hex.clone(),
        offer_id: lobby.offer_id,
        key,
        new,
        e2e: route.keys.e2e.clone(),
        bogo_id: route.keys.bogo_id,
        phone_e2e,
        refresher: std::mem::replace(&mut lobby.refresher, tokio::spawn(async {})),
    }))
}

/// Every check before anything is trusted. Any failure refuses.
fn check(
    route: &IphoneRoute,
    s: &RegSubmit,
    lobby_peer: &str,
    th: &[u8; 32],
    challenge: &[u8; 32],
) -> Result<NewApprover, String> {
    let approval_key: [u8; 65] = s.approval_key.array().ok_or("approval key must be 65-byte SEC1")?;
    let phone_e2e: [u8; 32] = s.phone_e2e.array().ok_or("phone E2E key must be 32 bytes")?;
    let phone_relay: [u8; 32] = s.phone_relay.array().ok_or("phone relay key must be 32 bytes")?;
    bogo_e2e::public_from(&phone_e2e).map_err(|_| "phone E2E key is invalid")?;
    let mailbox = bogo_relay_proto::mailbox(&phone_relay);
    if mailbox != lobby_peer {
        return Err("the submission's relay key is not the phone that joined the offer".into());
    }
    if !bogo_verify::verify(bogo_verify::P256, &approval_key, &pop_message(th, challenge), &s.proof.0) {
        return Err("proof of possession does not verify".into());
    }
    if !s.encoding_versions.contains(&1) {
        return Err("the phone does not support request encoding version 1".into());
    }
    let attest = match &s.attestation {
        Some(a) => attest(route, a, th, challenge, &approval_key, &phone_e2e, &phone_relay)?,
        None if accepts_simulator_registration() => serde_json::json!({
            "environment": "simulator-test",
            "note": "accepted without App Attest by a test build"
        }),
        None => return Err("App Attest evidence is missing".into()),
    };
    let push = match (&s.push_token, &s.push_env) {
        (Some(t), Some(env)) if t.0.len() == 32 && (env == "development" || env == "production") => {
            Some(Push { token: t.clone(), env: env.clone(), seq: 0 })
        }
        _ => None,
    };
    let route_data = RouteData {
        phone_e2e: B(phone_e2e.to_vec()),
        phone_relay: B(phone_relay.to_vec()),
        mailbox,
        push,
        encoding_versions: s.encoding_versions.clone(),
    };
    let tx = tx_id(th);
    Ok(NewApprover {
        id: approver_id(&tx),
        alg: bogo_verify::P256,
        sig_pk: approval_key.to_vec(),
        tx_id: tx,
        route: serde_json::to_value(route_data).map_err(|e| e.to_string())?,
        attest,
    })
}

fn attest(
    route: &IphoneRoute,
    a: &AttestationEvidence,
    th: &[u8; 32],
    challenge: &[u8; 32],
    approval_key: &[u8; 65],
    phone_e2e: &[u8; 32],
    phone_relay: &[u8; 32],
) -> Result<serde_json::Value, String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let key_id: [u8; 32] = b64
        .decode(&a.key_id)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or("App Attest key ID must be 32 bytes")?;
    let object = b64.decode(&a.object).map_err(|_| "App Attest object is not base64")?;
    let cdh = bogo_attest::registration_client_data_hash(th, challenge, approval_key, phone_e2e, phone_relay);
    let versions: Vec<&str> = route.cfg.bundle_versions.iter().map(String::as_str).collect();
    let policy = bogo_attest::Policy {
        app_id: &route.cfg.app_id,
        environments: &route.cfg.environments,
        bundle_versions: &versions,
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "clock")?.as_secs();
    let v = bogo_attest::verify(&object, &cdh, &key_id, &policy, now).map_err(|e| e.to_string())?;
    use sha2::Digest;
    Ok(serde_json::json!({
        "keyId": a.key_id,
        "environment": match v.environment {
            bogo_attest::Environment::Production => "production",
            bogo_attest::Environment::Development => "development",
        },
        "validationCategory": v.validation_category,
        "bundleVersion": v.bundle_version,
        "attestationSha256": hex::encode(sha2::Sha256::digest(&object)),
    }))
}

struct MacRegistration {
    relay: crate::relay::Relay,
    offer_hex: String,
    offer_id: [u8; 16],
    key: [u8; 32],
    new: NewApprover,
    e2e: bogo_e2e::SecretKey,
    bogo_id: [u8; 32],
    phone_e2e: bogo_e2e::PublicKey,
    refresher: tokio::task::JoinHandle<()>,
}

impl MacRegistration {
    async fn lobby_send(&self, phase: u8, plaintext: &[u8]) -> Result<(), RegError> {
        let msg = LobbySend {
            msg_id: hex::encode(phase_msg_id(&self.offer_id, phase)),
            body: hex::encode(phase_body(phase, &seal_phase(&self.key, &self.offer_id, phase, plaintext))),
        };
        let id = self.offer_hex.clone();
        self.relay
            .call(|c| {
                let (id, msg) = (id.clone(), msg.clone());
                async move { c.lobby_send(&id, &msg).await }
            })
            .await
            .map_err(transport)
    }

    async fn close(&self) {
        self.refresher.abort();
        let id = self.offer_hex.clone();
        let _ = self
            .relay
            .call(|c| {
                let id = id.clone();
                async move { c.delete_offer(&id).await }
            })
            .await;
    }
}

#[async_trait]
impl PendingRegistration for MacRegistration {
    fn approver(&self) -> &NewApprover {
        &self.new
    }

    /// Answer on the lobby channel and as an envelope in the phone's mailbox,
    /// which survives if the lobby answer is lost.
    async fn answer(self: Box<Self>, committed: &ApproverRecord) -> Result<(), RegError> {
        let registered = RegisteredPhase { tx_id: B(committed.tx_id.to_vec()), approver_id: B(committed.id.to_vec()) };
        let lobby = self
            .lobby_send(PHASE_REGISTERED, &serde_json::to_vec(&registered).map_err(transport)?)
            .await;
        let route: RouteData = serde_json::from_value(committed.route.clone()).map_err(transport)?;
        let msg = MacMsg::Registered { tx_id: registered.tx_id.clone(), approver_id: registered.approver_id.clone() };
        let id = bogo_e2e::message_id();
        let envelope = bogo_e2e::seal(
            &self.e2e,
            &self.phone_e2e,
            &self.bogo_id,
            &committed.id,
            bogo_e2e::Header { direction: bogo_e2e::Direction::MacToPhone, kind: msg.kind(), id },
            &serde_json::to_vec(&msg).map_err(transport)?,
        )
        .map_err(transport)?;
        let mailbox = self
            .relay
            .call(|c| {
                let (to, envelope) = (route.mailbox.clone(), envelope.clone());
                async move { c.send(&to, id, &envelope).await }
            })
            .await;
        // Give the phone a moment to read the lobby answer, then close the
        // offer. A phone that misses both gets `registered` again on every
        // boot, or by asking with `regResend`.
        tokio::time::sleep(Duration::from_secs(3)).await;
        self.close().await;
        match (lobby, mailbox) {
            (Err(e), Err(_)) => Err(e),
            _ => Ok(()),
        }
    }

    async fn refuse(self: Box<Self>, why: &str) {
        let refused = serde_json::to_vec(&RefusedPhase { why: why.into() }).unwrap_or_default();
        let _ = self.lobby_send(PHASE_REFUSED, &refused).await;
        self.close().await;
    }
}
