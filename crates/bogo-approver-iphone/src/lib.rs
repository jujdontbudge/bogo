//! The iPhone approver route (ARCHITECTURE §3.11).
//!
//! Every message is an HPKE envelope in the phone's (or BOGO's) relay
//! mailbox. Messages are accepted or refused by their content, never by their
//! position, so a late, early or repeated one does no harm. Inbound messages
//! are acknowledged to the relay only after the hub reports their effect
//! durable.
mod registration;
mod relay;
pub mod wire;

use async_trait::async_trait;
use bogo_approver::*;
use bogo_e2e::{Direction, Header, PublicKey, SecretKey};
use bogo_relay_proto::SigningKey;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use wire::{B, MacMsg, PhoneMsg, RouteData};

pub use registration::accepts_simulator_registration;

pub struct ApnsConfig {
    /// The owner's `.p8`, read at run time only.
    pub key_path: PathBuf,
    pub key_id: String,
    pub team_id: String,
    pub topic: String,
}

pub struct Config {
    pub relay_url: String,
    /// The relay's public service identity bound into mailbox auth.
    pub relay_service: String,
    /// Extra trusted root for a private or local relay certificate (PEM).
    pub relay_root_pem: Option<Vec<u8>>,
    /// The name the phone sees in Add Mac and in its Macs list.
    pub mac_name: String,
    /// `[approvers.iphone] app_id`.
    pub app_id: String,
    pub environments: Vec<bogo_attest::Environment>,
    /// Accepted `CFBundleVersion`s for App Attest.
    pub bundle_versions: Vec<String>,
    pub apns: Option<ApnsConfig>,
}

pub struct MacKeys {
    pub e2e: SecretKey,
    pub e2e_public: [u8; 32],
    pub relay: SigningKey,
    pub bogo_id: [u8; 32],
}

struct Channel {
    approver_id: [u8; 32],
    phone_e2e: PublicKey,
    route: RouteData,
}

pub struct IphoneRoute {
    cfg: Config,
    keys: MacKeys,
    relay: relay::Relay,
    apns: Option<tokio::sync::Mutex<bogo_apns::Client>>,
    channels: Mutex<HashMap<[u8; 32], Arc<Channel>>>,
    by_mailbox: Mutex<HashMap<String, [u8; 32]>>,
    /// Sealed bytes per message ID, so every resend is the same bytes.
    sealed: Mutex<HashMap<[u8; 16], Vec<u8>>>,
    /// Requests APNs already accepted a push for.
    pushed: Mutex<HashSet<([u8; 32], ReqId)>>,
    /// Message IDs whose effect is durable and that were acknowledged.
    acked: Mutex<HashSet<String>>,
    /// Random per process: notices get fresh IDs in each run, so a resend
    /// sealed again after a restart never collides with an old pending copy.
    instance: [u8; 16],
}

fn hold<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn err(e: impl std::fmt::Display) -> DeliveryError {
    DeliveryError(e.to_string())
}

impl IphoneRoute {
    pub fn new(cfg: Config, keys: MacKeys) -> Result<Arc<IphoneRoute>, String> {
        let relay = relay::Relay::new(
            &cfg.relay_url,
            &cfg.relay_service,
            cfg.relay_root_pem.as_deref(),
            keys.relay.clone(),
        )?;
        let apns = match &cfg.apns {
            Some(a) => Some(tokio::sync::Mutex::new(
                bogo_apns::Client::from_file(&a.key_path, &a.key_id, &a.team_id, &a.topic)
                    .map_err(|e| format!("APNs: {e}"))?,
            )),
            None => None,
        };
        Ok(Arc::new(IphoneRoute {
            cfg,
            keys,
            relay,
            apns,
            channels: Mutex::new(HashMap::new()),
            by_mailbox: Mutex::new(HashMap::new()),
            sealed: Mutex::new(HashMap::new()),
            pushed: Mutex::new(HashSet::new()),
            acked: Mutex::new(HashSet::new()),
            instance: rand::random(),
        }))
    }

    pub fn bogo_id(&self) -> [u8; 32] {
        self.keys.bogo_id
    }

    pub fn mailbox(&self) -> String {
        self.relay.mailbox()
    }

    fn channel(&self, id: &[u8; 32]) -> Result<Arc<Channel>, DeliveryError> {
        hold(&self.channels)
            .get(id)
            .cloned()
            .ok_or_else(|| err("no channel for this approver"))
    }

    fn notice_id(&self, what: &[u8], approver: &[u8; 32]) -> [u8; 16] {
        Sha256::digest([b"bogo-notice".as_slice(), &self.instance, what, approver].concat())[..16]
            .try_into()
            .unwrap()
    }

    /// Seal once per message ID and send; a resend is the same bytes.
    async fn send(&self, ch: &Channel, id: [u8; 16], msg: &MacMsg) -> Result<(), DeliveryError> {
        let cached = hold(&self.sealed).get(&id).cloned();
        let envelope = match cached {
            Some(e) => e,
            None => {
                let plaintext = serde_json::to_vec(msg).map_err(err)?;
                let e = bogo_e2e::seal(
                    &self.keys.e2e,
                    &ch.phone_e2e,
                    &self.keys.bogo_id,
                    &ch.approver_id,
                    Header { direction: Direction::MacToPhone, kind: msg.kind(), id },
                    &plaintext,
                )
                .map_err(err)?;
                hold(&self.sealed).insert(id, e.clone());
                e
            }
        };
        let to = ch.route.mailbox.clone();
        self.relay
            .call(|c| {
                let (to, envelope) = (to.clone(), envelope.clone());
                async move { c.send(&to, id, &envelope).await }
            })
            .await
            .map_err(err)
    }

    async fn push(&self, approver: &[u8; 32], ch: &Channel, req: &ReqId) {
        let (Some(apns), Some(push)) = (&self.apns, &ch.route.push) else {
            return;
        };
        if hold(&self.pushed).contains(&(*approver, *req)) {
            return;
        }
        let env = if push.env == "development" {
            bogo_apns::Environment::Sandbox
        } else {
            bogo_apns::Environment::Production
        };
        let result = apns
            .lock()
            .await
            .wake(env, &hex::encode(&push.token.0), &hex::encode(&self.keys.bogo_id[..8]), &hex::encode(req))
            .await;
        match result {
            Ok(r) if r.status == 200 => {
                hold(&self.pushed).insert((*approver, *req));
            }
            Ok(r) => tracing::warn!("APNs refused the wake-up: {} {:?}", r.status, r.reason),
            Err(e) => tracing::warn!("APNs: {e}"),
        }
    }

    /// Turn an opened phone message into what the hub takes in.
    fn inbound(&self, approver: [u8; 32], ch: &Channel, msg: PhoneMsg) -> Option<Inbound> {
        let req = |b: &B| b.array::<40>();
        Some(match msg {
            PhoneMsg::Approval { req_id, alg, sig } => Inbound::Approval { approver, req: req(&req_id)?, alg, proof: sig.0 },
            PhoneMsg::Denial { req_id, note } => Inbound::Denial { approver, req: req(&req_id)?, note },
            PhoneMsg::Pause { agent_id, epoch } => Inbound::Pause { approver, agent: agent_id.0, epoch },
            PhoneMsg::Seen { req_id } => Inbound::Seen { approver, req: req(&req_id)? },
            PhoneMsg::Sync { req_ids } => Inbound::Sync {
                approver,
                reqs: req_ids.iter().filter_map(req).collect(),
            },
            PhoneMsg::RegResend { tx_id } => Inbound::RegResend { approver, tx_id: tx_id.array()? },
            PhoneMsg::Removed {} => Inbound::Removed { approver },
            PhoneMsg::PushToken { token_seq, token, env, encoding_versions } => {
                if env != "development" && env != "production" || token.0.len() != 32 {
                    return None;
                }
                let mut route = ch.route.clone();
                route.push = Some(wire::Push { token, env, seq: token_seq });
                if !encoding_versions.is_empty() {
                    route.encoding_versions = encoding_versions;
                }
                Inbound::RouteUpdate { approver, seq: token_seq, route: serde_json::to_value(route).ok()? }
            }
        })
    }

    async fn ack(&self, id: &str) -> bool {
        let ids = vec![id.to_string()];
        self.relay
            .call(|c| {
                let ids = ids.clone();
                async move { c.ack(ids).await }
            })
            .await
            .is_ok()
    }
}

#[async_trait]
impl ApproverRoute for IphoneRoute {
    fn kind(&self) -> &'static str {
        "iphone"
    }

    async fn register(&self, name: &str, owner: &dyn OwnerPrompt) -> Result<Box<dyn PendingRegistration>, RegError> {
        registration::run(self, name, owner).await
    }

    async fn set_approvers(&self, all: &[ApproverRecord]) -> Result<(), DeliveryError> {
        let mut channels = HashMap::new();
        let mut by_mailbox = HashMap::new();
        for a in all {
            let route: RouteData = serde_json::from_value(a.route.clone()).map_err(err)?;
            let phone_e2e = bogo_e2e::public_from(&route.phone_e2e.0).map_err(err)?;
            by_mailbox.insert(route.mailbox.clone(), a.id);
            channels.insert(a.id, Arc::new(Channel { approver_id: a.id, phone_e2e, route }));
        }
        // Revoked approvers stay allowed to write, so a `removed` still gets
        // `revokedAck` and their decisions are recorded as rejected.
        let mut senders: Vec<String> = by_mailbox.keys().cloned().collect();
        senders.sort();
        self.relay
            .call(|c| {
                let senders = senders.clone();
                async move { c.allow(senders).await }
            })
            .await
            .map_err(err)?;
        *hold(&self.channels) = channels;
        *hold(&self.by_mailbox) = by_mailbox;
        Ok(())
    }

    async fn deliver(&self, a: &ApproverRecord, r: &Outbound) -> Result<(), DeliveryError> {
        let ch = self.channel(&a.id)?;
        let id = bogo_e2e::request_message_id(&r.req, &a.id);
        let msg = MacMsg::Request {
            req_id: B(r.req.to_vec()),
            boot_seq: r.boot_seq,
            bytes: B(r.bytes.clone()),
            pause_epoch: r.pause_epoch,
            arm_delay_ms: r.arm_delay_ms,
        };
        // The mailbox is the queue; the push is only a wake-up.
        let (sent, ()) = tokio::join!(self.send(&ch, id, &msg), self.push(&a.id, &ch, &r.req));
        sent
    }

    async fn retract(&self, a: &ApproverRecord, req: &ReqId) -> Result<(), DeliveryError> {
        let ch = self.channel(&a.id)?;
        let ids = vec![hex::encode(bogo_e2e::request_message_id(req, &a.id))];
        let to = ch.route.mailbox.clone();
        self.relay
            .call(|c| {
                let (to, ids) = (to.clone(), ids.clone());
                async move { c.retract(to, ids).await }
            })
            .await
            .map_err(err)
    }

    async fn notice(&self, a: &ApproverRecord, req: &ReqId, n: &Notice) -> Result<(), DeliveryError> {
        let ch = self.channel(&a.id)?;
        let req_id = B(req.to_vec());
        let (msg, tag) = match n {
            Notice::Settled => (MacMsg::Settled { req_id }, "settled".to_string()),
            Notice::Ended(why) => (MacMsg::Ended { req_id, why: why.wire().into() }, format!("ended/{}", why.wire())),
            Notice::Outcome(o) => (MacMsg::Outcome { req_id, outcome: o.clone() }, format!("outcome/{o}")),
        };
        let id = self.notice_id(&[tag.as_bytes(), req].concat(), &a.id);
        self.send(&ch, id, &msg).await
    }

    async fn boot(&self, a: &ApproverRecord, b: &BootNotice) -> Result<(), DeliveryError> {
        let ch = self.channel(&a.id)?;
        let id = self.notice_id(&[b"boot".as_slice(), &b.boot_id].concat(), &a.id);
        self.send(&ch, id, &MacMsg::Boot { boot_seq: b.boot_seq, boot_id: B(b.boot_id.to_vec()) })
            .await
    }

    async fn registered(&self, a: &ApproverRecord) -> Result<(), DeliveryError> {
        let ch = self.channel(&a.id)?;
        let id = self.notice_id(&[b"registered".as_slice(), &a.tx_id].concat(), &a.id);
        self.send(&ch, id, &MacMsg::Registered { tx_id: B(a.tx_id.to_vec()), approver_id: B(a.id.to_vec()) })
            .await
    }

    async fn revoked_ack(&self, a: &ApproverRecord) -> Result<(), DeliveryError> {
        let ch = self.channel(&a.id)?;
        let id = self.notice_id(b"revokedAck", &a.id);
        self.send(&ch, id, &MacMsg::RevokedAck {}).await
    }

    async fn run_inbound(&self, handler: Arc<dyn InboundHandler>) {
        let mut backoff = Duration::from_millis(500);
        loop {
            let batch = match self.relay.call(|c| async move { c.fetch(true).await }).await {
                Ok(b) => {
                    backoff = Duration::from_millis(500);
                    b
                }
                Err(e) => {
                    tracing::warn!("relay fetch: {e}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    continue;
                }
            };
            for m in batch {
                // Already applied and acknowledged once: the relay is showing
                // it again (a resend after our ack). Acknowledge again only.
                if hold(&self.acked).contains(&m.msg_id) {
                    tracing::info!("message {} was already applied; acknowledged again, not applied", &m.msg_id[..12]);
                    self.ack(&m.msg_id).await;
                    continue;
                }
                let opened = hold(&self.by_mailbox)
                    .get(&m.from)
                    .copied()
                    .and_then(|id| hold(&self.channels).get(&id).cloned().map(|ch| (id, ch)))
                    .and_then(|(id, ch)| {
                        let body = hex::decode(&m.body).ok()?;
                        let o = bogo_e2e::open(
                            &self.keys.e2e,
                            &ch.phone_e2e,
                            &self.keys.bogo_id,
                            &id,
                            Direction::PhoneToMac,
                            &body,
                        )
                        .ok()?;
                        (hex::encode(o.id) == m.msg_id).then_some((id, ch, o))
                    });
                let Some((id, ch, o)) = opened else {
                    // Unauthenticated or from nobody we know: no effect, drop it.
                    tracing::warn!("dropped an envelope that failed to open");
                    self.ack(&m.msg_id).await;
                    continue;
                };
                let parsed: Option<PhoneMsg> = serde_json::from_slice(&o.plaintext).ok();
                let inbound = parsed
                    .filter(|p| p.kind() == o.kind)
                    .and_then(|p| self.inbound(id, &ch, p));
                let Some(inbound) = inbound else {
                    // An unknown non-critical type, or a malformed payload.
                    self.ack(&m.msg_id).await;
                    continue;
                };
                match handler.handle(inbound).await {
                    Ok(()) => {
                        if self.ack(&m.msg_id).await {
                            hold(&self.acked).insert(m.msg_id.clone());
                        }
                    }
                    Err(Retry) => {
                        // Not durable: leave it in the mailbox and fetch again.
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        break;
                    }
                }
            }
        }
    }
}
