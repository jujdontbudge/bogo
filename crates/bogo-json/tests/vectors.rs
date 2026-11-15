//! `bogo-json` against the vectors the Lean encoder generated (`vectors/`, ARCHITECTURE §3.2).
//! Every expected value here comes from Lean, never from this crate.

use bogo_json::{JVal, parse};
use serde_json::{Value, json};
use std::path::PathBuf;

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).expect("vector file is JSON")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The vectors' tagged form of a value.
fn tagged(v: &JVal) -> Value {
    match v {
        JVal::Null => json!(["null"]),
        JVal::Bool(b) => json!(["bool", b]),
        JVal::Num(n) => json!(["num", n.as_str()]),
        JVal::Str(s) => json!(["str", s]),
        JVal::Arr(xs) => json!(["arr", xs.iter().map(tagged).collect::<Vec<_>>()]),
        JVal::Obj(o) => json!([
            "obj",
            o.iter()
                .map(|(k, v)| json!([k, tagged(v)]))
                .collect::<Vec<_>>()
        ]),
    }
}

fn s<'a>(c: &'a Value, k: &str) -> &'a str {
    c[k].as_str().unwrap_or_else(|| panic!("{k} in {c}"))
}

#[test]
fn json_texts() {
    let file = load("json.json");
    let accept = file["accept"].as_array().unwrap();
    for c in accept {
        let name = s(c, "name");
        let src = unhex(s(c, "source_hex"));
        let v = parse(&src).unwrap_or_else(|e| panic!("{name}: refused: {e}"));
        assert_eq!(tagged(&v), c["value"], "{name}: value");
        let written = v.write();
        assert_eq!(
            written.as_bytes(),
            s(c, "written").as_bytes(),
            "{name}: written text"
        );
        if c["written_is_source"] == json!(true) {
            assert_eq!(
                written.as_bytes(),
                &src[..],
                "{name}: written differs from source"
            );
        }
        // The written text is a fixed point, byte for byte.
        let again = parse(written.as_bytes()).unwrap().write();
        assert_eq!(again.as_bytes(), written.as_bytes(), "{name}: rewrite");
    }
    let reject = file["reject"].as_array().unwrap();
    for c in reject {
        let name = s(c, "name");
        match parse(&unhex(s(c, "source_hex"))) {
            Ok(v) => panic!("{name}: accepted as {v:?}"),
            Err(e) => assert_eq!(e.kind.as_str(), s(c, "error"), "{name}: error kind"),
        }
    }
    assert!(accept.len() >= 20 && reject.len() >= 20);
}

#[test]
fn request_arguments() {
    let file = load("requests.json");
    let reqs = file["requests"].as_array().unwrap();
    for c in reqs {
        let name = s(c, "name");
        let d = &c["decoded"];
        match c["args_source"].as_str() {
            None => {
                assert!(
                    d["args"].is_null() && d["args_written"].is_null(),
                    "{name}: absent args"
                );
            }
            Some(src) => {
                let v = parse(src.as_bytes()).unwrap_or_else(|e| panic!("{name}: refused: {e}"));
                assert_eq!(tagged(&v), d["args"], "{name}: value");
                let written = v.write();
                assert_eq!(
                    written.as_bytes(),
                    s(d, "args_written").as_bytes(),
                    "{name}: written"
                );
                let again = parse(written.as_bytes()).unwrap().write();
                assert_eq!(again.as_bytes(), written.as_bytes(), "{name}: rewrite");
            }
        }
    }
    assert!(reqs.len() >= 20);
}
