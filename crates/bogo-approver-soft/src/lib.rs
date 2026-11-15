//! Explicitly insecure software approver, available only in a test feature build.
#![cfg(feature = "test-approvers")]
use async_trait::async_trait;
use bogo_approver::*;
use ed25519_dalek::{Signer, SigningKey};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
pub struct SoftRoute {
    keys: Mutex<HashMap<String, SigningKey>>,
}
impl SoftRoute {
    pub fn install(&self, name: String, seed: [u8; 32]) {
        self.keys
            .lock()
            .unwrap()
            .insert(name, SigningKey::from_bytes(&seed));
    }
    pub fn sign(&self, name: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let keys = self.keys.lock().unwrap();
        let key = keys.get(name).ok_or("soft approver key unavailable")?;
        Ok(key
            .sign(&[b"BOGO-APPROVAL\0v1".as_slice(), bytes].concat())
            .to_bytes()
            .to_vec())
    }
}
struct Pending(NewApprover);
#[async_trait]
impl PendingRegistration for Pending {
    fn approver(&self) -> &NewApprover {
        &self.0
    }
    async fn answer(self: Box<Self>, _: &ApproverRecord) -> Result<(), RegError> {
        Ok(())
    }
    async fn refuse(self: Box<Self>, _: &str) {}
}
#[async_trait]
impl ApproverRoute for SoftRoute {
    fn kind(&self) -> &'static str {
        "soft"
    }
    async fn register(
        &self,
        name: &str,
        _: &dyn OwnerPrompt,
    ) -> Result<Box<dyn PendingRegistration>, RegError> {
        let keys = self.keys.lock().unwrap();
        let key = keys
            .get(name)
            .ok_or_else(|| RegError::Refused("soft key not provisioned".into()))?;
        Ok(Box::new(Pending(NewApprover {
            id: rand::random(),
            alg: 0xff00,
            sig_pk: key.verifying_key().to_bytes().to_vec(),
            tx_id: rand::random(),
            route: serde_json::json!({}),
            attest: serde_json::json!({"environment":"software-test"}),
        })))
    }
    async fn set_approvers(&self, _: &[ApproverRecord]) -> Result<(), DeliveryError> {
        Ok(())
    }
    async fn deliver(&self, _: &ApproverRecord, _: &Outbound) -> Result<(), DeliveryError> {
        Ok(())
    }
    async fn retract(&self, _: &ApproverRecord, _: &ReqId) -> Result<(), DeliveryError> {
        Ok(())
    }
    async fn notice(&self, _: &ApproverRecord, _: &ReqId, _: &Notice) -> Result<(), DeliveryError> {
        Ok(())
    }
    async fn boot(&self, _: &ApproverRecord, _: &BootNotice) -> Result<(), DeliveryError> {
        Ok(())
    }
    async fn registered(&self, _: &ApproverRecord) -> Result<(), DeliveryError> {
        Ok(())
    }
    async fn revoked_ack(&self, _: &ApproverRecord) -> Result<(), DeliveryError> {
        Ok(())
    }
    async fn run_inbound(&self, _: Arc<dyn InboundHandler>) {
        std::future::pending::<()>().await
    }
}
