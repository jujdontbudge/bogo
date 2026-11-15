//! Public fixture source:
//! https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide
use bogo_attest::{Environment, validation_category};
use ciborium::value::Value;

#[test]
fn distributed_app_category_uses_apples_uint32_byte_encoding() {
    // Apple's sample encodes category 1 as the CBOR byte string h'01000000'.
    // The same UInt32 encoding for a TestFlight/App Store app must be accepted.
    for category in [2u32, 4] {
        let extensions = Value::Map(vec![(
            Value::Text("apple_validation_category_01".into()),
            Value::Bytes(category.to_le_bytes().to_vec()),
        )]);
        let result = validation_category(&extensions, Environment::Production);
        assert_eq!(result.ok(), Some(category), "category {category} rejected");
    }
}
