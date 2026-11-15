//! Exercises the public named steps with synthetic data and an untrusted local
//! certificate. This does not claim a real-device attestation succeeds.
use bogo_attest::*;
use ciborium::value::Value;
use der::{
    DecodePem, Encode,
    asn1::{ObjectIdentifier, OctetString},
};
use sha2::{Digest, Sha256};
use x509_cert::{Certificate, ext::Extension};
fn encoded(v: &Value) -> Vec<u8> {
    let mut b = Vec::new();
    ciborium::into_writer(v, &mut b).unwrap();
    b
}
fn map(pairs: Vec<(&str, Value)>) -> Value {
    Value::Map(
        pairs
            .into_iter()
            .map(|(k, v)| (Value::Text(k.into()), v))
            .collect(),
    )
}
fn rejected<T>(name: &str, r: Result<T, Error>, step: Step) {
    match r {
        Err(e) => {
            assert_eq!(e.step, step);
            println!("{name}: invalid input rejected at {:?}", e.step)
        }
        Ok(_) => panic!("invalid input passed {name}"),
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .expect("local untrusted P-256 certificate PEM path");
    let mut cert = Certificate::from_pem(&std::fs::read(path)?)?;
    let key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .unwrap()
        .to_vec();
    let id: [u8; 32] = Sha256::digest(&key).into();
    let mut auth = Sha256::digest(b"AX3C2B78YD.com.johansardar.applebridge.ios").to_vec();
    auth.push(0xc0);
    auth.extend([0; 4]);
    auth.extend(b"appattest\0\0\0\0\0\0\0");
    auth.extend([0, 32]);
    auth.extend(id);
    let cose = Value::Map(vec![
        (1.into(), 2.into()),
        (3.into(), (-7).into()),
        ((-1).into(), 1.into()),
        ((-2).into(), Value::Bytes(key[1..33].to_vec())),
        ((-3).into(), Value::Bytes(key[33..65].to_vec())),
    ]);
    auth.extend(encoded(&cose));
    let extensions = map(vec![
        (
            "apple_validation_category_01",
            Value::Bytes(4u32.to_le_bytes().to_vec()),
        ),
        ("apple_bundle_version_01", Value::Text("42".into())),
    ]);
    auth.extend(encoded(&extensions));
    let client_hash = registration_client_data_hash(
        &[1; 32],
        &[2; 32],
        key.as_slice().try_into()?,
        &[3; 32],
        &[4; 32],
    );
    let n = Sha256::digest([auth.as_slice(), &client_hash].concat());
    let mut nonce_der = vec![0x30, 0x24, 0xa1, 0x22, 0x04, 0x20];
    nonce_der.extend(n);
    cert.tbs_certificate
        .extensions
        .get_or_insert_default()
        .push(Extension {
            extn_id: ObjectIdentifier::new_unwrap("1.2.840.113635.100.8.2"),
            critical: false,
            extn_value: OctetString::new(nonce_der)?,
        });
    let cert_der = cert.to_der()?;
    let object = map(vec![
        ("fmt", Value::Text("apple-appattest".into())),
        ("authData", Value::Bytes(auth.clone())),
        (
            "attStmt",
            map(vec![
                (
                    "x5c",
                    Value::Array(vec![
                        Value::Bytes(cert_der.clone()),
                        Value::Bytes(cert_der.clone()),
                    ]),
                ),
                ("receipt", Value::Bytes(vec![1])),
            ]),
        ),
    ]);
    let decoded = decode(&encoded(&object))?;
    assert_eq!(decoded.auth_data, auth);
    rejected("decode (invalid CBOR)", decode(&[0xff]), Step::Decode);
    rejected(
        "pinned chain (self-signed local certificate)",
        certificate_chain(&[cert_der.clone(), cert_der], 1794700000),
        Step::CertificateChain,
    );
    nonce(&cert, &auth, &client_hash)?;
    rejected(
        "nonce (different registration binding)",
        nonce(&cert, &auth, &[0; 32]),
        Step::Nonce,
    );
    assert_eq!(key_id(&cert, &id)?, key);
    rejected(
        "key ID (different public-key hash)",
        key_id(&cert, &[0; 32]),
        Step::KeyId,
    );
    rp_id_hash(&auth, "AX3C2B78YD.com.johansardar.applebridge.ios")?;
    rejected(
        "RP ID (another app)",
        rp_id_hash(&auth, "another.app"),
        Step::RpIdHash,
    );
    counter(&auth)?;
    let mut changed = auth.clone();
    changed[36] = 1;
    rejected("counter (nonzero)", counter(&changed), Step::Counter);
    assert_eq!(
        aaguid(&auth, &[Environment::Production])?,
        Environment::Production
    );
    rejected(
        "AAGUID (production disallowed)",
        aaguid(&auth, &[Environment::Development]),
        Step::Aaguid,
    );
    changed = auth.clone();
    changed[37] ^= 1;
    rejected(
        "AAGUID (unknown constant)",
        aaguid(&changed, &[Environment::Production]),
        Step::Aaguid,
    );
    credential_id(&auth, &id)?;
    rejected(
        "credential ID (different ID)",
        credential_id(&auth, &[0; 32]),
        Step::CredentialId,
    );
    credential_key(&auth, &key)?;
    rejected(
        "COSE key (different certified point)",
        credential_key(&auth, &[0; 65]),
        Step::CredentialKey,
    );
    assert_eq!(
        validation_category(&extensions, Environment::Production)?,
        4
    );
    rejected(
        "category (development binary in production)",
        validation_category(
            &map(vec![(
                "apple_validation_category_01",
                Value::Bytes(3u32.to_le_bytes().to_vec()),
            )]),
            Environment::Production,
        ),
        Step::ValidationCategory,
    );
    assert_eq!(bundle_version(&extensions, &["42"])?, "42");
    rejected(
        "bundle version (not accepted)",
        bundle_version(&extensions, &["43"]),
        Step::BundleVersion,
    );
    rejected(
        "bundle version (wrong CBOR type)",
        bundle_version(&map(vec![("apple_bundle_version_01", 42.into())]), &["42"]),
        Step::BundleVersion,
    );
    let policy = Policy {
        app_id: "AX3C2B78YD.com.johansardar.applebridge.ios",
        environments: &[Environment::Production],
        bundle_versions: &["42"],
    };
    rejected(
        "full verifier (untrusted synthetic chain)",
        verify(&encoded(&object), &client_hash, &id, &policy, 1794700000),
        Step::CertificateChain,
    );
    println!(
        "All named steps exercised; positive synthetic fields accepted; real-device chain pending device session"
    );
    Ok(())
}
