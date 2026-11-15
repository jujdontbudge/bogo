//! Apple's App Attest validation, without network or the system trust store.
//! The caller supplies the registration-bound clientDataHash and trusted time,
//! consumes its one-use challenge, and durably prevents duplicate registration.
use ciborium::value::Value;
use der::{
    Decode, DecodePem, Encode, Sequence,
    asn1::{ObjectIdentifier, OctetString},
};
use p256::ecdsa::signature::Verifier;
use sha2::{Digest, Sha256};
use std::time::Duration;
use x509_cert::{
    Certificate,
    ext::pkix::{BasicConstraints, KeyUsage},
};

pub const APPLE_ROOT_PEM: &[u8] = include_bytes!("../assets/apple-app-attestation-root.pem");
pub const APPLE_ROOT_SHA256: &str =
    "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Decode,
    CertificateChain,
    Nonce,
    KeyId,
    RpIdHash,
    Counter,
    Aaguid,
    CredentialId,
    CredentialKey,
    ValidationCategory,
    BundleVersion,
}
#[derive(Debug, thiserror::Error)]
#[error("App Attest rejected at {step:?}")]
pub struct Error {
    pub step: Step,
}
type Result<T> = std::result::Result<T, Error>;
fn reject<T>(step: Step) -> Result<T> {
    Err(Error { step })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Environment {
    Production,
    Development,
}
pub struct Policy<'a> {
    pub app_id: &'a str,
    pub environments: &'a [Environment],
    /// Explicit accepted CFBundleVersion strings, supplied by the owner.
    pub bundle_versions: &'a [&'a str],
}
pub struct Attestation {
    pub certificates: Vec<Vec<u8>>,
    pub receipt: Vec<u8>,
    pub auth_data: Vec<u8>,
}
pub struct Verified {
    pub public_key: Vec<u8>,
    pub receipt: Vec<u8>,
    pub environment: Environment,
    pub validation_category: u32,
    pub bundle_version: String,
}
fn field<'a>(v: &'a Value, key: &str, step: Step) -> Result<&'a Value> {
    let Value::Map(m) = v else {
        return reject(step);
    };
    let mut values = m.iter().filter(|(k, _)| k.as_text() == Some(key));
    let value = values.next().map(|(_, v)| v).ok_or(Error { step })?;
    if values.next().is_some() {
        return reject(step);
    }
    Ok(value)
}
fn binary(v: &Value, step: Step) -> Result<&[u8]> {
    v.as_bytes().map(Vec::as_slice).ok_or(Error { step })
}
fn read_value(bytes: &[u8], step: Step) -> Result<(Value, usize)> {
    let mut r = std::io::Cursor::new(bytes);
    let value = ciborium::from_reader(&mut r).map_err(|_| Error { step })?;
    Ok((value, r.position() as usize))
}
/// Step 0: bounded CBOR, expected format and statement, no trailing data.
pub fn decode(bytes: &[u8]) -> Result<Attestation> {
    let step = Step::Decode;
    if bytes.len() > 65536 {
        return reject(step);
    }
    let (v, n) = read_value(bytes, step)?;
    if n != bytes.len() || field(&v, "fmt", step)?.as_text() != Some("apple-appattest") {
        return reject(step);
    }
    let stmt = field(&v, "attStmt", step)?;
    let certs = field(stmt, "x5c", step)?.as_array().ok_or(Error { step })?;
    if certs.len() != 2 {
        return reject(step);
    }
    let certificates = certs
        .iter()
        .map(|v| binary(v, step).map(<[u8]>::to_vec))
        .collect::<Result<_>>()?;
    let receipt = binary(field(stmt, "receipt", step)?, step)?.to_vec();
    let auth_data = binary(field(&v, "authData", step)?, step)?.to_vec();
    if receipt.is_empty() || auth_data.len() < 55 {
        return reject(step);
    }
    Ok(Attestation {
        certificates,
        receipt,
        auth_data,
    })
}
fn public_key(cert: &Certificate, step: Step) -> Result<&[u8]> {
    cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(Error { step })
}
fn ec_curve(cert: &Certificate, curve: ObjectIdentifier) -> bool {
    let a = &cert.tbs_certificate.subject_public_key_info.algorithm;
    a.oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1")
        && a.parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
            == Some(curve)
}
fn certificate_signature(cert: &Certificate, issuer: &Certificate) -> Result<()> {
    let step = Step::CertificateChain;
    if cert.signature_algorithm != cert.tbs_certificate.signature
        || cert.signature_algorithm.parameters.is_some()
    {
        return reject(step);
    }
    let bytes = cert.tbs_certificate.to_der().map_err(|_| Error { step })?;
    let sig = cert.signature.as_bytes().ok_or(Error { step })?;
    let ok = match cert.signature_algorithm.oid.to_string().as_str() {
        "1.2.840.10045.4.3.2"
            if ec_curve(issuer, ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7")) =>
        {
            p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key(issuer, step)?)
                .ok()
                .zip(p256::ecdsa::Signature::from_der(sig).ok())
                .is_some_and(|(k, s)| k.verify(&bytes, &s).is_ok())
        }
        "1.2.840.10045.4.3.3" if ec_curve(issuer, ObjectIdentifier::new_unwrap("1.3.132.0.34")) => {
            p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key(issuer, step)?)
                .ok()
                .zip(p384::ecdsa::Signature::from_der(sig).ok())
                .is_some_and(|(k, s)| k.verify(&bytes, &s).is_ok())
        }
        _ => false,
    };
    if !ok {
        return reject(step);
    }
    Ok(())
}
fn cert_constraints(cert: &Certificate, is_ca: bool, below: u8, time: Duration) -> Result<()> {
    let step = Step::CertificateChain;
    let t = &cert.tbs_certificate;
    if t.validity.not_before.to_unix_duration() > time
        || t.validity.not_after.to_unix_duration() < time
    {
        return reject(step);
    }
    let bc = t.get::<BasicConstraints>().map_err(|_| Error { step })?;
    if is_ca {
        let Some((_, bc)) = bc else {
            return reject(step);
        };
        if !bc.ca || bc.path_len_constraint.is_some_and(|n| n < below) {
            return reject(step);
        }
    } else if bc.is_some_and(|(_, bc)| bc.ca) {
        return reject(step);
    }
    if let Some((_, usage)) = t.get::<KeyUsage>().map_err(|_| Error { step })? {
        if (is_ca && !usage.key_cert_sign()) || (!is_ca && !usage.digital_signature()) {
            return reject(step);
        }
    } else if is_ca {
        return reject(step);
    }
    if let Some(exts) = &t.extensions {
        let mut seen = std::collections::HashSet::new();
        for e in exts {
            if !seen.insert(e.extn_id) {
                return reject(step);
            }
            // Only critical extensions whose semantics we enforce are accepted.
            if e.critical && !["2.5.29.19", "2.5.29.15"].contains(&e.extn_id.to_string().as_str()) {
                return reject(step);
            }
        }
    }
    Ok(())
}
/// Step 1: leaf -> intermediate -> compile-time pinned Apple root; signatures,
/// validity, issuer names, CA/path constraints, key usage and critical extensions.
pub fn certificate_chain(certificates: &[Vec<u8>], unix_seconds: u64) -> Result<Certificate> {
    let step = Step::CertificateChain;
    if certificates.len() != 2 {
        return reject(step);
    }
    let leaf = Certificate::from_der(&certificates[0]).map_err(|_| Error { step })?;
    let ca = Certificate::from_der(&certificates[1]).map_err(|_| Error { step })?;
    let root = Certificate::from_pem(APPLE_ROOT_PEM).map_err(|_| Error { step })?;
    let time = Duration::from_secs(unix_seconds);
    cert_constraints(&root, true, 1, time)?;
    cert_constraints(&ca, true, 0, time)?;
    cert_constraints(&leaf, false, 0, time)?;
    if leaf.tbs_certificate.issuer != ca.tbs_certificate.subject
        || ca.tbs_certificate.issuer != root.tbs_certificate.subject
        || root.tbs_certificate.issuer != root.tbs_certificate.subject
        || !ec_curve(&leaf, ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7"))
    {
        return reject(step);
    }
    certificate_signature(&root, &root)?;
    certificate_signature(&ca, &root)?;
    certificate_signature(&leaf, &ca)?;
    Ok(leaf)
}
#[derive(Sequence)]
struct NonceExtension {
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
    nonce: OctetString,
}
/// Steps 2-4: nonce = SHA256(authData || clientDataHash), exact DER extension.
pub fn nonce(cert: &Certificate, auth_data: &[u8], client_data_hash: &[u8; 32]) -> Result<()> {
    let step = Step::Nonce;
    let exts = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(Error { step })?;
    let mut found = exts
        .iter()
        .filter(|e| e.extn_id == ObjectIdentifier::new_unwrap("1.2.840.113635.100.8.2"));
    let ext = found.next().ok_or(Error { step })?;
    if found.next().is_some() {
        return reject(step);
    }
    let n = NonceExtension::from_der(ext.extn_value.as_bytes()).map_err(|_| Error { step })?;
    let expected = Sha256::digest([auth_data, client_data_hash].concat());
    if n.nonce.as_bytes() != expected.as_slice() {
        return reject(step);
    }
    Ok(())
}
/// Step 5: hash the X9.62 uncompressed credential public key, never SPKI DER.
pub fn key_id(cert: &Certificate, id: &[u8; 32]) -> Result<Vec<u8>> {
    let step = Step::KeyId;
    let key = public_key(cert, step)?;
    if key.len() != 65
        || key[0] != 4
        || p256::PublicKey::from_sec1_bytes(key).is_err()
        || Sha256::digest(key).as_slice() != id
    {
        return reject(step);
    }
    Ok(key.to_vec())
}
/// Step 6: RP ID hash must match the configured App ID prefix + bundle ID.
pub fn rp_id_hash(auth: &[u8], app_id: &str) -> Result<()> {
    if app_id.is_empty() || auth.get(..32) != Some(Sha256::digest(app_id.as_bytes()).as_slice()) {
        return reject(Step::RpIdHash);
    }
    Ok(())
}
/// Step 7: an attestation is new (counter zero).
pub fn counter(auth: &[u8]) -> Result<()> {
    if auth.get(33..37) != Some(&[0; 4]) {
        return reject(Step::Counter);
    }
    Ok(())
}
/// Step 8: environment constant and explicit owner policy.
pub fn aaguid(auth: &[u8], allowed: &[Environment]) -> Result<Environment> {
    let step = Step::Aaguid;
    let env = match auth.get(37..53) {
        Some(b"appattestdevelop") => Environment::Development,
        Some(b"appattest\0\0\0\0\0\0\0") => Environment::Production,
        _ => return reject(step),
    };
    if !allowed.contains(&env) {
        return reject(step);
    }
    Ok(env)
}
/// Step 9: credential ID length and value, and attested-credential flag.
pub fn credential_id(auth: &[u8], id: &[u8; 32]) -> Result<()> {
    if auth.get(32).is_none_or(|f| f & 0x40 == 0)
        || auth.get(53..55) != Some(&[0, 32])
        || auth.get(55..87) != Some(id)
    {
        return reject(Step::CredentialId);
    }
    Ok(())
}
fn number(v: &Value) -> Option<i128> {
    v.as_integer().map(Into::into)
}
fn cose_field(v: &Value, key: i128) -> Result<&Value> {
    let step = Step::CredentialKey;
    let m = v.as_map().ok_or(Error { step })?;
    let mut found = m.iter().filter(|(k, _)| number(k) == Some(key));
    let (_, value) = found.next().ok_or(Error { step })?;
    if found.next().is_some() {
        return reject(step);
    }
    Ok(value)
}
/// The embedded COSE EC2 key must agree with the certified P-256 key.
/// Returns the extension dictionary following that key (flag ED required).
pub fn credential_key(auth: &[u8], key: &[u8]) -> Result<Value> {
    let step = Step::CredentialKey;
    let remaining = auth.get(87..).ok_or(Error { step })?;
    let (cose, n) = read_value(remaining, step)?;
    if number(cose_field(&cose, 1)?) != Some(2)
        || number(cose_field(&cose, 3)?) != Some(-7)
        || number(cose_field(&cose, -1)?) != Some(1)
        || key.len() != 65
        || binary(cose_field(&cose, -2)?, step)? != &key[1..33]
        || binary(cose_field(&cose, -3)?, step)? != &key[33..65]
        || auth[32] & 0x80 == 0
    {
        return reject(step);
    }
    let (extensions, used) = read_value(&remaining[n..], step)?;
    if n + used != remaining.len() || !extensions.is_map() {
        return reject(step);
    }
    Ok(extensions)
}
/// Step 10: Apple launch category; production accepts TestFlight/App Store,
/// development accepts the development signing identity category only.
pub fn validation_category(extensions: &Value, env: Environment) -> Result<u32> {
    let step = Step::ValidationCategory;
    let n = number(field(extensions, "apple_validation_category_01", step)?)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or(Error { step })?;
    if !match env {
        Environment::Production => [2, 4].contains(&n),
        Environment::Development => n == 3,
    } {
        return reject(step);
    }
    Ok(n)
}
/// Step 11: signed bundle version must be a string explicitly accepted by the owner.
pub fn bundle_version(extensions: &Value, allowed: &[&str]) -> Result<String> {
    let step = Step::BundleVersion;
    let s = field(extensions, "apple_bundle_version_01", step)?
        .as_text()
        .ok_or(Error { step })?;
    if s.is_empty() || s.len() > 64 || !allowed.contains(&s) {
        return reject(step);
    }
    Ok(s.into())
}
pub fn verify(
    bytes: &[u8],
    client_data_hash: &[u8; 32],
    id: &[u8; 32],
    policy: &Policy<'_>,
    unix_seconds: u64,
) -> Result<Verified> {
    let a = decode(bytes)?;
    let cert = certificate_chain(&a.certificates, unix_seconds)?;
    nonce(&cert, &a.auth_data, client_data_hash)?;
    let public_key = key_id(&cert, id)?;
    rp_id_hash(&a.auth_data, policy.app_id)?;
    counter(&a.auth_data)?;
    let environment = aaguid(&a.auth_data, policy.environments)?;
    credential_id(&a.auth_data, id)?;
    let extensions = credential_key(&a.auth_data, &public_key)?;
    let validation_category = validation_category(&extensions, environment)?;
    let bundle_version = bundle_version(&extensions, policy.bundle_versions)?;
    Ok(Verified {
        public_key,
        receipt: a.receipt,
        environment,
        validation_category,
        bundle_version,
    })
}

/// BOGO registration binding used as App Attest's clientDataHash. The caller
/// supplies the locally computed transcript hash and fresh one-use challenge,
/// never values selected by the untrusted regSubmit message.
pub fn registration_client_data_hash(
    transcript_hash: &[u8; 32],
    challenge: &[u8; 32],
    approval_public_key: &[u8; 65],
    phone_e2e_public_key: &[u8; 32],
    phone_relay_public_key: &[u8; 32],
) -> [u8; 32] {
    Sha256::digest(
        [
            transcript_hash.as_slice(),
            challenge,
            approval_public_key,
            phone_e2e_public_key,
            phone_relay_public_key,
        ]
        .concat(),
    )
    .into()
}
