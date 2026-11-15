//! Signature tags shared with the Lean extern hook. Messages are exact bytes.
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

pub const P256: u16 = 1;
pub const SOFT_ED25519: u16 = 0xff00;

pub fn verify(algorithm: u16, public_key: &[u8], message: &[u8], proof: &[u8]) -> bool {
    match algorithm {
        P256 => VerifyingKey::from_sec1_bytes(public_key)
            .ok()
            .zip(Signature::from_slice(proof).ok())
            .is_some_and(|(key, sig)| key.verify(message, &sig).is_ok()),
        #[cfg(feature = "test-approvers")]
        SOFT_ED25519 => {
            let Ok(bytes) = <&[u8; 32]>::try_from(public_key) else {
                return false;
            };
            ed25519_dalek::VerifyingKey::from_bytes(bytes)
                .ok()
                .zip(ed25519_dalek::Signature::from_slice(proof).ok())
                .is_some_and(|(key, sig)| key.verify_strict(message, &sig).is_ok())
        }
        _ => false,
    }
}

/// C ABI used by the Lean shim. No panic or borrowed buffer escapes this call.
///
/// # Safety
/// Each pointer must identify a readable buffer of its given length, valid for
/// this call. A null pointer is accepted only for a zero length buffer.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bogo_rs_verify(
    alg: u16,
    pk: *const u8,
    pk_len: usize,
    msg: *const u8,
    msg_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> u8 {
    // Bounds also prevent oversized lengths from reaching from_raw_parts.
    if pk_len > 65
        || proof_len > 64
        || msg_len > isize::MAX as usize
        || (pk.is_null() && pk_len != 0)
        || (msg.is_null() && msg_len != 0)
        || (proof.is_null() && proof_len != 0)
    {
        return 0;
    }
    unsafe fn bytes<'a>(p: *const u8, n: usize) -> &'a [u8] {
        if n == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(p, n) }
        }
    }
    std::panic::catch_unwind(|| unsafe {
        verify(
            alg,
            bytes(pk, pk_len),
            bytes(msg, msg_len),
            bytes(proof, proof_len),
        ) as u8
    })
    .unwrap_or(0)
}
