//! A relay connection that re-authenticates on 401 and is shared by every
//! task of the route.
use bogo_relay_proto::{Client, Error, SigningKey};
use std::{future::Future, sync::Arc};
use tokio::sync::RwLock;

pub struct Relay {
    url: String,
    service: String,
    http: reqwest::Client,
    key: SigningKey,
    client: RwLock<Option<Arc<Client>>>,
}

impl Relay {
    pub fn new(url: &str, service: &str, root_pem: Option<&[u8]>, key: SigningKey) -> Result<Relay, String> {
        let root = root_pem
            .map(reqwest::Certificate::from_pem)
            .transpose()
            .map_err(|e| format!("relay CA certificate: {e}"))?;
        Ok(Relay {
            url: url.into(),
            service: service.into(),
            http: Client::http(root).map_err(|e| e.to_string())?,
            key,
            client: RwLock::new(None),
        })
    }

    pub fn mailbox(&self) -> String {
        bogo_relay_proto::mailbox(&self.key.verifying_key().to_bytes())
    }

    async fn get(&self) -> Result<Arc<Client>, Error> {
        if let Some(c) = self.client.read().await.clone() {
            return Ok(c);
        }
        let mut slot = self.client.write().await;
        if let Some(c) = slot.clone() {
            return Ok(c);
        }
        let c = Arc::new(Client::connect(&self.url, &self.service, &self.key, self.http.clone()).await?);
        *slot = Some(c.clone());
        Ok(c)
    }

    async fn reset(&self, failed: &Arc<Client>) {
        let mut slot = self.client.write().await;
        if slot.as_ref().is_some_and(|c| Arc::ptr_eq(c, failed)) {
            *slot = None;
        }
    }

    /// Run one relay call, re-authenticating once if the bearer expired.
    pub async fn call<T, F, Fut>(&self, f: F) -> Result<T, Error>
    where
        F: Fn(Arc<Client>) -> Fut,
        Fut: Future<Output = Result<T, Error>>,
    {
        let c = self.get().await?;
        match f(c.clone()).await {
            Err(Error::Status(401)) => {
                self.reset(&c).await;
                f(self.get().await?).await
            }
            Err(Error::Transport) => {
                self.reset(&c).await;
                Err(Error::Transport)
            }
            other => other,
        }
    }
}
