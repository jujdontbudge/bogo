//! Authenticator data from a real iPhone 13 (iOS 27.0.1, Debug build, development
//! App Attest), captured during the first device registration on 2026-11-16.
//! Apple's real format ends at the COSE credential key: flags 0x40, no extensions.
use bogo_attest::{counter, credential_id, credential_key};

const AUTH: &str = "0548c99840878843f5064efb1427d24fe6299b0145ff88f897df266019d15d114000000000617070617474657374646576656c6f700020d85661f95ad062f9a8190175154362aafa49e514d76ecfac0e0b3a60985bb177a501020326200121582098dc7a13b2231b7cfa2b4691a0aff6481100b9749bb5afc76a8e78f7c9a48ff82258204cf27e5e90098c921899e86bf0cdcf84fd334e8d9d0ab3c90f2d63d996257e5b";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn real_device_authenticator_data_has_no_extensions() {
    let auth = hex(AUTH);
    assert_eq!(auth.len(), 164);
    let id: [u8; 32] = auth[55..87].try_into().unwrap();
    counter(&auth).unwrap();
    credential_id(&auth, &id).unwrap();
    // Rebuild the X9.62 key from the COSE x/y coordinates at the end of authData.
    let mut key = vec![4u8];
    key.extend_from_slice(&auth[auth.len() - 67..auth.len() - 35]);
    key.extend_from_slice(&auth[auth.len() - 32..]);
    assert_eq!(credential_key(&auth, &key).unwrap(), None);
    // A changed coordinate is still refused.
    let mut wrong = key.clone();
    wrong[64] ^= 1;
    assert!(credential_key(&auth, &wrong).is_err());
    // Trailing bytes without the ED flag are refused.
    let mut trailing = auth.clone();
    trailing.push(0xa0);
    assert!(credential_key(&trailing, &key).is_err());
}
