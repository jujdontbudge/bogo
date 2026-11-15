use crate::Error;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Catalog {
    pub tools: BTreeMap<String, CatalogTool>,
    pub unexposable: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogTool {
    pub upstream: String,
    pub original: Value,
    pub advertised: Value,
    pub justification: Option<String>,
    pub strict_client_risk: bool,
    pub first_seen: u64,
}
impl Catalog {
    /// An atomic catalog snapshot for the daemon's state/tools.json, usable while stopped.
    pub fn save(&self, path: &std::path::Path) -> Result<(), Error> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|_| Error::Protocol)?;
        let tmp = path.with_extension("json.new");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|_| Error::Configuration)?;
        use std::io::Write;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::Configuration)?;
        std::fs::rename(tmp, path).map_err(|_| Error::Configuration)
    }
    pub fn load(path: &std::path::Path) -> Result<Self, Error> {
        serde_json::from_slice(&std::fs::read(path).map_err(|_| Error::Configuration)?)
            .map_err(|_| Error::Protocol)
    }
}
pub(crate) fn exposable(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}
/// Choose an unused key across the entire schema, then widen whole-object constraints.
/// Pathological patterns that reserve every candidate fail closed as unexposable.
pub fn widen(schema: &Value) -> Result<(Value, String, bool), Error> {
    let mut properties = BTreeSet::new();
    let mut patterns = Vec::new();
    reservations(schema, &mut properties, &mut patterns)?;
    let key = (0..4096)
        .map(|i| match i {
            0 => "justification".into(),
            1 => "bogo_justification".into(),
            n => format!("bogo_justification_{n}"),
        })
        .find(|k: &String| !properties.contains(k) && !patterns.iter().any(|p| p.is_match(k)))
        .ok_or(Error::Configuration)?;
    let mut result = schema.clone();
    let mut risk = false;
    let mut refs = BTreeSet::new();
    whole(&mut result, &key, &mut risk, &mut refs);
    // Only a unique, local reference target is safe to widen in place.
    let mut visited = BTreeSet::new();
    while let Some(reference) = refs.pop_first() {
        if !visited.insert(reference.clone()) {
            risk = true;
            continue;
        }
        if reference.starts_with("#/") && ref_count(schema, &reference) == 1 {
            if let Some(target) = result.pointer_mut(&reference[1..]) {
                whole(target, &key, &mut risk, &mut refs);
            } else {
                risk = true;
            }
        } else {
            risk = true;
        }
    }
    Ok((result, key, risk))
}
fn reservations(
    v: &Value,
    keys: &mut BTreeSet<String>,
    patterns: &mut Vec<Regex>,
) -> Result<(), Error> {
    match v {
        Value::Object(m) => {
            if let Some(p) = m.get("properties").and_then(Value::as_object) {
                keys.extend(p.keys().cloned());
            }
            if let Some(p) = m.get("patternProperties").and_then(Value::as_object) {
                for pattern in p.keys() {
                    patterns.push(Regex::new(pattern).map_err(|_| Error::Configuration)?);
                }
            }
            for v in m.values() {
                reservations(v, keys, patterns)?;
            }
        }
        Value::Array(a) => {
            for v in a {
                reservations(v, keys, patterns)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn ref_count(v: &Value, reference: &str) -> usize {
    match v {
        Value::Object(m) => {
            usize::from(m.get("$ref").and_then(Value::as_str) == Some(reference))
                + m.values().map(|v| ref_count(v, reference)).sum::<usize>()
        }
        Value::Array(a) => a.iter().map(|v| ref_count(v, reference)).sum(),
        _ => 0,
    }
}
fn whole(v: &mut Value, key: &str, risk: &mut bool, refs: &mut BTreeSet<String>) {
    let Some(m) = v.as_object_mut() else {
        return;
    };
    *risk |= [
        "const",
        "enum",
        "if",
        "then",
        "else",
        "$dynamicRef",
        "dependentSchemas",
        "not",
        "dependencies",
    ]
    .iter()
    .any(|k| m.contains_key(*k));
    if let Some(reference) = m.get("$ref").and_then(Value::as_str) {
        refs.insert(reference.into());
    }
    if let Some(n) = m.get("maxProperties").and_then(Value::as_u64) {
        if let Some(n) = n.checked_add(1) {
            m.insert("maxProperties".into(), json!(n));
        } else {
            m.remove("maxProperties");
        }
    }
    if let Some(names) = m.remove("propertyNames") {
        m.insert(
            "propertyNames".into(),
            json!({"anyOf":[names, {"const":key}]}),
        );
    }
    let field = json!({"type":"string","description":"Why you are making this call (shown to the owner as your unverified claim)."});
    if let Some(props) = m.entry("properties").or_insert(json!({})).as_object_mut() {
        props.insert(key.into(), field);
    } else {
        *risk = true;
    }
    for combinator in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = m.get_mut(combinator).and_then(Value::as_array_mut) {
            for branch in branches {
                whole(branch, key, risk, refs);
            }
        }
    }
}
