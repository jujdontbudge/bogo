//! Relay v1 wire contract. Binary values are lowercase hex. Auth keys never
//! implement Debug or Serialize. Tokens stay in memory and are sent only over TLS.
pub use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("relay transport failed")]
    Transport,
    #[error("relay refused request (HTTP {0})")]
    Status(u16),
    #[error("invalid relay wire value")]
    Wire,
}

pub fn mailbox(public: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(public))
}
pub fn random_hex() -> String {
    use rand::RngCore;
    let mut b = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
pub fn valid_hex(s: &str, bytes: usize) -> bool {
    s.len() == bytes * 2
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn auth_bytes(service: &str, public: &[u8; 32], challenge: &str) -> Result<Vec<u8>, Error> {
    if !valid_hex(challenge, 32) {
        return Err(Error::Wire);
    }
    let mut out = b"bogo/relay/auth/v1\0".to_vec();
    out.extend_from_slice(&(service.len() as u32).to_be_bytes());
    out.extend_from_slice(service.as_bytes());
    out.extend_from_slice(&Sha256::digest(public));
    out.extend(hex::decode(challenge).map_err(|_| Error::Wire)?);
    Ok(out)
}
pub fn verify_auth(
    service: &str,
    public: &str,
    challenge: &str,
    signature: &str,
) -> Option<String> {
    if !valid_hex(public, 32) || !valid_hex(signature, 64) {
        return None;
    }
    let pk: [u8; 32] = hex::decode(public).ok()?.try_into().ok()?;
    let key = VerifyingKey::from_bytes(&pk).ok()?;
    let sig = Signature::from_slice(&hex::decode(signature).ok()?).ok()?;
    key.verify_strict(&auth_bytes(service, &pk, challenge).ok()?, &sig)
        .ok()?;
    Some(mailbox(&pk))
}

#[derive(Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub r#pub: String,
}
#[derive(Serialize, Deserialize)]
pub struct Challenge {
    pub challenge: String,
}
#[derive(Serialize, Deserialize)]
pub struct VerifyRequest {
    pub r#pub: String,
    pub sig: String,
}
#[derive(Serialize, Deserialize)]
pub struct Token {
    pub token: String,
}
#[derive(Serialize, Deserialize)]
pub struct Allow {
    pub senders: Vec<String>,
}
#[derive(Serialize, Deserialize)]
pub struct Send {
    pub to: String,
    pub msg_id: String,
    pub body: String,
}
#[derive(Serialize, Deserialize)]
pub struct Fetch {
    pub wait: bool,
}
#[derive(Serialize, Deserialize)]
pub struct Message {
    pub msg_id: String,
    pub from: String,
    pub body: String,
}
#[derive(Serialize, Deserialize)]
pub struct Ack {
    pub msg_ids: Vec<String>,
}
#[derive(Serialize, Deserialize)]
pub struct Retract {
    pub to: String,
    pub msg_ids: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Offer {
    pub offer_id: String,
    pub e_pub_m: String,
    pub mac_label: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ListedOffer {
    #[serde(flatten)]
    pub offer: Offer,
    pub age_seconds: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct LobbySend {
    pub msg_id: String,
    pub body: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct LobbyMessage {
    pub msg_id: String,
    pub from: String,
    pub body: String,
}

pub struct Client {
    http: reqwest::Client,
    base: String,
    token: String,
    pub mailbox: String,
}
impl Client {
    /// Additional root certificate support is for private/local TLS. Certificate
    /// and hostname verification remain enabled; redirects are always disabled.
    pub fn http(root: Option<reqwest::Certificate>) -> Result<reqwest::Client, Error> {
        let mut b = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(40));
        if let Some(root) = root {
            b = b.add_root_certificate(root);
        }
        b.build().map_err(|_| Error::Transport)
    }
    pub async fn connect(
        base: &str,
        service: &str,
        key: &SigningKey,
        http: reqwest::Client,
    ) -> Result<Self, Error> {
        let url = reqwest::Url::parse(base).map_err(|_| Error::Wire)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(Error::Wire);
        }
        let mut c = Self {
            http,
            base: base.trim_end_matches('/').into(),
            token: String::new(),
            mailbox: mailbox(&key.verifying_key().to_bytes()),
        };
        let public = hex::encode(key.verifying_key().as_bytes());
        let challenge: Challenge = c
            .post(
                "/v1/auth/challenge",
                &ChallengeRequest {
                    r#pub: public.clone(),
                },
            )
            .await?;
        let sig = key.sign(&auth_bytes(
            service,
            &key.verifying_key().to_bytes(),
            &challenge.challenge,
        )?);
        let token: Token = c
            .post(
                "/v1/auth/verify",
                &VerifyRequest {
                    r#pub: public,
                    sig: hex::encode(sig.to_bytes()),
                },
            )
            .await?;
        c.token = token.token;
        Ok(c)
    }
    async fn response(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<reqwest::Response, Error> {
        let mut r = self.http.request(method, format!("{}{path}", self.base));
        if !self.token.is_empty() {
            r = r.bearer_auth(&self.token);
        }
        if let Some(body) = body {
            r = r.json(body);
        }
        let response = r.send().await.map_err(|_| Error::Transport)?;
        if !response.status().is_success() {
            return Err(Error::Status(response.status().as_u16()));
        }
        Ok(response)
    }
    async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, Error> {
        self.response(reqwest::Method::POST, path, Some(body))
            .await?
            .json()
            .await
            .map_err(|_| Error::Wire)
    }
    async fn empty(&self, path: &str, body: &impl Serialize) -> Result<(), Error> {
        self.response(reqwest::Method::POST, path, Some(body))
            .await?;
        Ok(())
    }
    pub async fn allow(&self, senders: Vec<String>) -> Result<(), Error> {
        self.empty("/v1/allow", &Allow { senders }).await
    }
    /// Body must be a sealed envelope. Relay never interprets application data.
    pub async fn send(&self, to: &str, id: [u8; 16], envelope: &[u8]) -> Result<(), Error> {
        self.empty(
            "/v1/send",
            &Send {
                to: to.into(),
                msg_id: hex::encode(id),
                body: hex::encode(envelope),
            },
        )
        .await
    }
    pub async fn fetch(&self, wait: bool) -> Result<Vec<Message>, Error> {
        self.post("/v1/fetch", &Fetch { wait }).await
    }
    /// Call only after the endpoint's effect and replay tombstone are durable.
    pub async fn ack(&self, msg_ids: Vec<String>) -> Result<(), Error> {
        self.empty("/v1/ack", &Ack { msg_ids }).await
    }
    pub async fn retract(&self, to: String, msg_ids: Vec<String>) -> Result<(), Error> {
        self.empty("/v1/retract", &Retract { to, msg_ids }).await
    }
    pub async fn offer(&self, offer: &Offer) -> Result<(), Error> {
        self.empty("/v1/lobby/offer", offer).await
    }
    pub async fn offers(&self) -> Result<Vec<ListedOffer>, Error> {
        self.response(reqwest::Method::GET, "/v1/lobby", None::<&()>)
            .await?
            .json()
            .await
            .map_err(|_| Error::Wire)
    }
    pub async fn lobby_send(&self, id: &str, msg: &LobbySend) -> Result<(), Error> {
        if !valid_hex(id, 16) {
            return Err(Error::Wire);
        }
        self.empty(&format!("/v1/lobby/{id}/msg"), msg).await
    }
    pub async fn lobby_fetch(&self, id: &str) -> Result<Vec<LobbyMessage>, Error> {
        if !valid_hex(id, 16) {
            return Err(Error::Wire);
        }
        self.post(&format!("/v1/lobby/{id}/fetch"), &()).await
    }
    pub async fn delete_offer(&self, id: &str) -> Result<(), Error> {
        if !valid_hex(id, 16) {
            return Err(Error::Wire);
        }
        self.response(
            reqwest::Method::DELETE,
            &format!("/v1/lobby/{id}"),
            None::<&()>,
        )
        .await?;
        Ok(())
    }
}
