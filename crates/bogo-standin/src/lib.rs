//! Shared by the stand-in and its test phone.
pub mod request;

/// A short, distinguishing form of an ID: a 40-byte request ID shows its
/// boot prefix and sequence number (`400b75e9·3`), anything else its first bytes.
pub fn rid(b: &[u8]) -> String {
    match <[u8; 40]>::try_from(b) {
        Ok(r) => format!("{}·{}", hex::encode(&r[..4]), u64::from_be_bytes(r[32..].try_into().unwrap_or_default())),
        Err(_) => hex::encode(&b[..b.len().min(6)]),
    }
}
