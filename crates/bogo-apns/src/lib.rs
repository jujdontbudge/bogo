//! Direct APNs provider client. No relay or Apple Bridge dependencies.
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy)]
pub enum Environment {
    Sandbox,
    Production,
}
impl Environment {
    fn host(self) -> &'static str {
        match self {
            Self::Sandbox => "https://api.sandbox.push.apple.com",
            Self::Production => "https://api.push.apple.com",
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("APNs key could not be loaded")]
    Key,
    #[error("APNs configuration is invalid")]
    Config,
    #[error("APNs transport failed")]
    Transport,
    #[error("APNs response is invalid")]
    Response,
}
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub reason: Option<String>,
    pub apns_id: Option<String>,
}
pub struct Client {
    http: reqwest::Client,
    key: EncodingKey,
    key_id: String,
    team_id: String,
    topic: String,
    cached: Option<(u64, String)>,
}
#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    iat: u64,
}
impl Client {
    /// Reads the owner's key at runtime. Never logs the path, key or provider token.
    pub fn from_file(path: &Path, key_id: &str, team_id: &str, topic: &str) -> Result<Self, Error> {
        if key_id.len() != 10
            || team_id.len() != 10
            || topic.is_empty()
            || !key_id.bytes().all(|c| c.is_ascii_alphanumeric())
            || !team_id.bytes().all(|c| c.is_ascii_alphanumeric())
        {
            return Err(Error::Config);
        }
        let mut pem = std::fs::read(path).map_err(|_| Error::Key)?;
        let result = EncodingKey::from_ec_pem(&pem).map_err(|_| Error::Key);
        // Clear the transient PEM buffer. The parsed signing key stays private.
        use zeroize::Zeroize;
        pem.zeroize();
        let key = result?;
        let http = reqwest::Client::builder()
            .https_only(true)
            .http2_prior_knowledge()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| Error::Transport)?;
        Ok(Self {
            http,
            key,
            key_id: key_id.into(),
            team_id: team_id.into(),
            topic: topic.into(),
            cached: None,
        })
    }
    fn token(&mut self) -> Result<&str, Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Config)?
            .as_secs();
        // Reuse for 50 minutes: below Apple's 1-hour expiry, above its 20-minute minimum refresh interval.
        if self
            .cached
            .as_ref()
            .is_none_or(|(issued, _)| now < *issued || now - *issued >= 3000)
        {
            let mut header = Header::new(Algorithm::ES256);
            header.kid = Some(self.key_id.clone());
            let token = jsonwebtoken::encode(
                &header,
                &Claims {
                    iss: &self.team_id,
                    iat: now,
                },
                &self.key,
            )
            .map_err(|_| Error::Key)?;
            self.cached = Some((now, token));
        }
        Ok(&self.cached.as_ref().unwrap().1)
    }
    /// APNs is a wake-up only. This fixed payload carries routing IDs, never request content.
    pub async fn wake(
        &mut self,
        environment: Environment,
        device_token: &str,
        mac_prefix: &str,
        req_id: &str,
    ) -> Result<Response, Error> {
        if device_token.len() != 64
            || !device_token.bytes().all(|c| c.is_ascii_hexdigit())
            || mac_prefix.len() > 64
            || mac_prefix.is_empty()
            || !mac_prefix.bytes().all(|c| c.is_ascii_hexdigit())
            || req_id.len() != 80
            || !req_id.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err(Error::Config);
        }
        let token = self.token()?.to_owned();
        let payload = serde_json::json!({"aps":{"alert":{"title":"BOGO","body":"Approval requested"},
            "interruption-level":"time-sensitive","category":"bogo.request","thread-id":"bogo","content-available":1,"sound":"default"},
            "bogo":{"v":1,"mac":mac_prefix,"rid":req_id}});
        let response = self
            .http
            .post(format!("{}/3/device/{device_token}", environment.host()))
            .bearer_auth(token)
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("apns-expiration", "0")
            .header(
                "apns-collapse-id",
                format!("{:x}", Sha256::digest(req_id.as_bytes())),
            )
            .json(&payload)
            .send()
            .await
            .map_err(|_| Error::Transport)?;
        if response.version() != reqwest::Version::HTTP_2 {
            return Err(Error::Response);
        }
        let status = response.status().as_u16();
        let apns_id = response
            .headers()
            .get("apns-id")
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);
        let reason = if status == 200 {
            None
        } else {
            #[derive(serde::Deserialize)]
            struct Rejection {
                reason: String,
            }
            let r: Rejection = response.json().await.map_err(|_| Error::Response)?;
            // Apple-controlled reason only; cap output before exposing it.
            if r.reason.len() > 128 || !r.reason.bytes().all(|c| c.is_ascii_alphanumeric()) {
                return Err(Error::Response);
            }
            Some(r.reason)
        };
        Ok(Response {
            status,
            reason,
            apns_id,
        })
    }
}
