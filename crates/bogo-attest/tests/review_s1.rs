//! Public fixture source:
//! https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide
use bogo_attest::certificate_chain;

#[test]
fn apple_p384_issuer_can_sign_a_sha256_leaf() {
    // Apple's sample chain is valid at 2026-04-21 18:00:00 UTC.
    // Independently verified with openssl verify against the pinned root.
    let certs = vec![
        include_bytes!("fixtures/apple-guide-leaf.der").to_vec(),
        include_bytes!("fixtures/apple-guide-intermediate.der").to_vec(),
    ];
    let result = certificate_chain(&certs, 1_776_794_400);
    assert!(
        result.is_ok(),
        "Apple sample chain rejected: {:?}",
        result.err()
    );
}
