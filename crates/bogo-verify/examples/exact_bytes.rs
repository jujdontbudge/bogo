use p256::ecdsa::{Signature, SigningKey, signature::Signer};
fn main() {
    let key = SigningKey::from_bytes((&[42u8; 32]).into()).unwrap();
    let pk = key.verifying_key().to_encoded_point(false);
    let msg = b"BOGO exact request bytes";
    let sig: Signature = key.sign(msg);
    assert!(bogo_verify::verify(1, pk.as_bytes(), msg, &sig.to_bytes()));
    assert!(!bogo_verify::verify(
        1,
        pk.as_bytes(),
        b"BOGO Exact request bytes",
        &sig.to_bytes()
    ));
    let mut changed = sig.to_bytes();
    changed[0] ^= 1;
    assert!(!bogo_verify::verify(1, pk.as_bytes(), msg, &changed));
    assert!(!bogo_verify::verify(
        1,
        pk.as_bytes(),
        msg,
        &sig.to_der().as_bytes()[..64]
    ));
    assert!(!bogo_verify::verify(7, pk.as_bytes(), msg, &sig.to_bytes()));
    println!(
        "P-256: exact bytes accepted; changed message/signature, DER and unknown tag rejected"
    );
    #[cfg(not(feature = "test-approvers"))]
    {
        assert!(!bogo_verify::verify(0xff00, &[0; 32], msg, &[0; 64]));
        println!("default build: soft Ed25519 tag refused");
    }
    #[cfg(feature = "test-approvers")]
    {
        let soft = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let sig = soft.sign(msg);
        assert!(bogo_verify::verify(
            0xff00,
            soft.verifying_key().as_bytes(),
            msg,
            &sig.to_bytes()
        ));
        assert!(!bogo_verify::verify(
            0xff00,
            soft.verifying_key().as_bytes(),
            b"changed",
            &sig.to_bytes()
        ));
        println!("test-approvers build: valid soft signature accepted; changed bytes rejected");
    }
}
