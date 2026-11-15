//! Single-shot RFC 9180 authenticated envelopes. No network or replay state.
use hpke::{
    Deserializable, Kem as _, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use sha2::{Digest, Sha256};

pub type Kem = X25519HkdfSha256;
pub type SecretKey = <Kem as hpke::Kem>::PrivateKey;
pub type PublicKey = <Kem as hpke::Kem>::PublicKey;
pub type MessageId = [u8; 16];
pub const HEADER_LEN: usize = 27;
pub const MAX_PLAINTEXT: usize = 1024 * 1024;
const MAGIC: &[u8; 8] = b"BOGOE2E\0";

#[derive(Debug, thiserror::Error)]
#[error("invalid or unauthenticated BOGO envelope")]
pub struct Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    MacToPhone = 0,
    PhoneToMac = 1,
}

pub fn keypair() -> (SecretKey, PublicKey) {
    Kem::gen_keypair(&mut rand::rng())
}
pub fn message_id() -> MessageId {
    rand::random()
}
pub fn request_message_id(req_id: &[u8; 40], approver_id: &[u8; 32]) -> MessageId {
    Sha256::digest([req_id.as_slice(), approver_id].concat())[..16]
        .try_into()
        .unwrap()
}

/// Variable fields use u32 big-endian lengths; enc is exactly 32 bytes.
/// Direction and type are authenticated along with the message ID.
pub struct Header {
    pub direction: Direction,
    pub kind: u8,
    pub id: MessageId,
}

pub fn seal(
    sender: &SecretKey,
    recipient: &PublicKey,
    bogo: &[u8; 32],
    approver: &[u8; 32],
    header: Header,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let Header {
        direction,
        kind,
        id,
    } = header;
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(Error);
    }
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&[1, direction as u8, kind]);
    out.extend_from_slice(&id);
    let info = [b"bogo/e2e/v1".as_slice(), bogo, approver].concat();
    let (enc, mut ctx) = hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
        &OpModeS::Auth((sender.clone(), Kem::sk_to_pk(sender))),
        recipient,
        &info,
        &mut rand::rng(),
    )
    .map_err(|_| Error)?;
    let ct = ctx.seal(plaintext, &out).map_err(|_| Error)?;
    out.extend_from_slice(&32u32.to_be_bytes());
    out.extend_from_slice(&enc.to_bytes());
    out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

pub struct Opened {
    pub id: MessageId,
    pub kind: u8,
    pub plaintext: Vec<u8>,
}

/// Read the ID to consult the endpoint's durable deduplication table. Only
/// record new IDs after successful authentication and a durable effect.
pub fn peek_id(envelope: &[u8]) -> Result<MessageId, Error> {
    if envelope.len() < HEADER_LEN || &envelope[..8] != MAGIC || envelope[8] != 1 {
        return Err(Error);
    }
    envelope[11..27].try_into().map_err(|_| Error)
}

pub fn open(
    recipient: &SecretKey,
    sender: &PublicKey,
    bogo: &[u8; 32],
    approver: &[u8; 32],
    direction: Direction,
    envelope: &[u8],
) -> Result<Opened, Error> {
    let id = peek_id(envelope)?;
    if envelope.len() < 83
        || envelope.len() > MAX_PLAINTEXT + 83
        || envelope[9] != direction as u8
        || envelope[27..31] != 32u32.to_be_bytes()
    {
        return Err(Error);
    }
    let n = u32::from_be_bytes(envelope[63..67].try_into().map_err(|_| Error)?) as usize;
    if n != envelope.len() - 67 {
        return Err(Error);
    }
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&envelope[31..63]).map_err(|_| Error)?;
    let info = [b"bogo/e2e/v1".as_slice(), bogo, approver].concat();
    let mut ctx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Auth(sender.clone()),
        recipient,
        &enc,
        &info,
    )
    .map_err(|_| Error)?;
    let plaintext = ctx
        .open(&envelope[67..], &envelope[..HEADER_LEN])
        .map_err(|_| Error)?;
    let kind = envelope[10];
    if kind & 0x80 != 0 {
        return Err(Error);
    }
    Ok(Opened {
        id,
        kind,
        plaintext,
    })
}
