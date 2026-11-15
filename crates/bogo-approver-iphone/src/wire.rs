//! The iPhone route's wire formats, shared by the Mac route and any phone
//! implementation: envelope payloads (ARCHITECTURE §3.11) and the
//! registration phases carried by the relay lobby. Documented in
//! `docs/RELAY-PROTOCOL.md` § "iPhone route messages".
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead, aead::Payload};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// Bytes as lowercase hex in JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct B(pub Vec<u8>);

impl Serialize for B {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(&self.0))
    }
}
impl<'de> Deserialize<'de> for B {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<B, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s.to_ascii_lowercase()).map(B).map_err(serde::de::Error::custom)
    }
}
impl B {
    pub fn array<const N: usize>(&self) -> Option<[u8; N]> {
        self.0.as_slice().try_into().ok()
    }
}

/// Mac → phone envelope payloads. The JSON `type` must agree with the
/// envelope header's type byte ([`MacMsg::kind`]).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum MacMsg {
    Request { req_id: B, boot_seq: u64, bytes: B, pause_epoch: u64, arm_delay_ms: u64 },
    Settled { req_id: B },
    Ended { req_id: B, why: String },
    Boot { boot_seq: u64, boot_id: B },
    Outcome { req_id: B, outcome: String },
    Registered { tx_id: B, approver_id: B },
    RevokedAck {},
}

impl MacMsg {
    pub fn kind(&self) -> u8 {
        match self {
            MacMsg::Request { .. } => 1,
            MacMsg::Settled { .. } => 2,
            MacMsg::Ended { .. } => 3,
            MacMsg::Boot { .. } => 4,
            MacMsg::Outcome { .. } => 5,
            MacMsg::Registered { .. } => 6,
            MacMsg::RevokedAck {} => 7,
        }
    }
}

/// Phone → Mac envelope payloads.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum PhoneMsg {
    Approval { req_id: B, alg: u16, sig: B },
    Denial { req_id: B, #[serde(default)] note: Option<String> },
    Pause { agent_id: B, epoch: u64 },
    Seen { req_id: B },
    PushToken { token_seq: u64, token: B, env: String, #[serde(default)] encoding_versions: Vec<u16> },
    Sync { req_ids: Vec<B> },
    RegResend { tx_id: B },
    Removed {},
}

impl PhoneMsg {
    pub fn kind(&self) -> u8 {
        match self {
            PhoneMsg::Approval { .. } => 1,
            PhoneMsg::Denial { .. } => 2,
            PhoneMsg::Pause { .. } => 3,
            PhoneMsg::Seen { .. } => 4,
            PhoneMsg::PushToken { .. } => 5,
            PhoneMsg::Sync { .. } => 6,
            PhoneMsg::RegResend { .. } => 7,
            PhoneMsg::Removed {} => 8,
        }
    }
}

// ---- Registration (numeric comparison over the relay lobby) ----

pub const PHASE_HELLO: u8 = 0x01; // phone: ePubP (32)
pub const PHASE_COMMIT: u8 = 0x02; // Mac: Cm (32)
pub const PHASE_PHONE_NONCE: u8 = 0x03; // phone: Np (16)
pub const PHASE_REVEAL: u8 = 0x04; // Mac: Nm (16)
pub const PHASE_MAC_CONFIRMED: u8 = 0x05; // Mac, sealed MacConfirmed
pub const PHASE_REG_SUBMIT: u8 = 0x06; // phone, sealed RegSubmit
pub const PHASE_REGISTERED: u8 = 0x07; // Mac, sealed Registered
pub const PHASE_REFUSED: u8 = 0x08; // Mac, sealed Refused
pub const PHASE_MAC_ABORT: u8 = 0x09; // Mac, empty
pub const PHASE_PHONE_ABORT: u8 = 0x0a; // phone, empty

/// The proof-of-possession domain: the approval key signs
/// `REG_DOMAIN ‖ transcriptHash ‖ challenge`.
pub const REG_DOMAIN: &[u8] = b"BOGO-REG\x00v1";

/// A lobby phase's message ID: fixed per offer and phase, so a resend of the
/// same phase is idempotent at the relay.
pub fn phase_msg_id(offer_id: &[u8; 16], phase: u8) -> [u8; 16] {
    Sha256::digest([b"bogo-reg-msg".as_slice(), offer_id, &[phase]].concat())[..16]
        .try_into()
        .unwrap()
}

pub fn commitment(e_pub_m: &[u8; 32], e_pub_p: &[u8; 32], n_m: &[u8; 16]) -> [u8; 32] {
    Sha256::digest([b"bogo-reg-commit".as_slice(), e_pub_m, e_pub_p, n_m].concat()).into()
}

/// The six digits both screens show: `u64be(SHA-256(…)[0..8]) mod 10^6`.
pub fn code(e_pub_m: &[u8; 32], e_pub_p: &[u8; 32], n_m: &[u8; 16], n_p: &[u8; 16]) -> String {
    let d = Sha256::digest([b"bogo-reg-code".as_slice(), e_pub_m, e_pub_p, n_m, n_p].concat());
    let v = u64::from_be_bytes(d[..8].try_into().unwrap()) % 1_000_000;
    format!("{v:06}")
}

/// `382917` → `382 917`.
pub fn spaced(code: &str) -> String {
    format!("{} {}", &code[..3], &code[3..])
}

pub struct Transcript {
    pub offer_id: [u8; 16],
    pub e_pub_m: [u8; 32],
    pub e_pub_p: [u8; 32],
    pub commit: [u8; 32],
    pub n_m: [u8; 16],
    pub n_p: [u8; 16],
}

impl Transcript {
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(
            [
                b"bogo-reg-transcript/v1".as_slice(),
                &self.offer_id,
                &self.e_pub_m,
                &self.e_pub_p,
                &self.commit,
                &self.n_m,
                &self.n_p,
            ]
            .concat(),
        )
        .into()
    }
    pub fn code(&self) -> String {
        code(&self.e_pub_m, &self.e_pub_p, &self.n_m, &self.n_p)
    }
}

/// `txId = SHA-256(transcriptHash)`.
pub fn tx_id(transcript_hash: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(transcript_hash).into()
}

/// Both ends derive the approver ID from the transcript, so a phone can
/// address `removed` to a registration the Mac may or may not have committed.
pub fn approver_id(tx_id: &[u8; 32]) -> [u8; 32] {
    Sha256::digest([b"bogo-approver-id/v1".as_slice(), tx_id].concat()).into()
}

pub fn pop_message(transcript_hash: &[u8; 32], challenge: &[u8; 32]) -> Vec<u8> {
    [REG_DOMAIN, transcript_hash, challenge].concat()
}

/// `K = HKDF-SHA256(salt = transcriptHash, ikm = X25519(eM, eP), "bogo-reg-key/v1")`.
pub fn phase_key(shared: &[u8; 32], transcript_hash: &[u8; 32]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(transcript_hash), shared);
    let mut k = [0u8; 32];
    hk.expand(b"bogo-reg-key/v1", &mut k).expect("32 bytes is a valid HKDF length");
    k
}

fn phase_nonce(phase: u8) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[11] = phase;
    n
}

fn phase_aad(offer_id: &[u8; 16], phase: u8) -> Vec<u8> {
    [b"bogo-reg/v1".as_slice(), offer_id, &[phase]].concat()
}

/// Each phase is sealed once under its own nonce, so a key never reuses one.
pub fn seal_phase(key: &[u8; 32], offer_id: &[u8; 16], phase: u8, plaintext: &[u8]) -> Vec<u8> {
    let aead = ChaCha20Poly1305::new(key.into());
    aead.encrypt(
        &phase_nonce(phase).into(),
        Payload { msg: plaintext, aad: &phase_aad(offer_id, phase) },
    )
    .expect("ChaCha20-Poly1305 sealing does not fail")
}

pub fn open_phase(key: &[u8; 32], offer_id: &[u8; 16], phase: u8, sealed: &[u8]) -> Option<Vec<u8>> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(&phase_nonce(phase).into(), Payload { msg: sealed, aad: &phase_aad(offer_id, phase) })
        .ok()
}

/// Lobby body: `phase ‖ payload`.
pub fn phase_body(phase: u8, payload: &[u8]) -> Vec<u8> {
    [&[phase][..], payload].concat()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MacConfirmed {
    pub mac_e2e: B,
    pub mac_relay: B,
    pub bogo_id: B,
    pub mac_name: String,
    pub challenge: B,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationEvidence {
    /// `DCAppAttestService`'s key ID, base64.
    pub key_id: String,
    /// The attestation object, base64.
    pub object: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegSubmit {
    /// SEC1 uncompressed P-256 (65 bytes).
    pub approval_key: B,
    /// Raw `r ‖ s` over [`pop_message`].
    pub proof: B,
    pub phone_e2e: B,
    pub phone_relay: B,
    /// `null` only from the simulator-only test path.
    pub attestation: Option<AttestationEvidence>,
    #[serde(default)]
    pub push_token: Option<B>,
    #[serde(default)]
    pub push_env: Option<String>,
    pub encoding_versions: Vec<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredPhase {
    pub tx_id: B,
    pub approver_id: B,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RefusedPhase {
    pub why: String,
}

/// Route data stored with each iPhone approver (`ApproverRecord::route`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteData {
    pub phone_e2e: B,
    pub phone_relay: B,
    pub mailbox: String,
    #[serde(default)]
    pub push: Option<Push>,
    pub encoding_versions: Vec<u16>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Push {
    pub token: B,
    /// `development` or `production`.
    pub env: String,
    pub seq: u64,
}
