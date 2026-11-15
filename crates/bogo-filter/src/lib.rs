//! Pure filtering of the serialized MCP CallToolResult. No argument values enter here.
use serde_json::Value;

pub const REMOVED: &str = "[removed by BOGO]";
pub const WITHHELD: &str = "[output withheld by BOGO: not filterable]";
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Action {
    #[default]
    Strip,
    Redact,
}
#[derive(Clone, Debug, Default)]
pub struct Rules {
    pub paths: Vec<String>,
    pub action: Action,
}
#[derive(Clone, Debug, Default)]
pub struct Report {
    pub fields: usize,
    pub withheld: usize,
}

/// Filters all representations, preserving unrelated MCP envelope fields.
pub fn filter(rules: &Rules, mut result: Value) -> (Value, Report) {
    let mut report = Report::default();
    if rules.paths.is_empty() {
        return (result, report);
    }
    for key in ["structuredContent", "_meta"] {
        if let Some(v) = result.get_mut(key) {
            apply(rules, v, &mut report);
        }
    }
    if let Some(blocks) = result.get_mut("content").and_then(Value::as_array_mut) {
        for block in blocks {
            if let Some(meta) = block.get_mut("_meta") {
                apply(rules, meta, &mut report);
            }
            match block.get("type").and_then(Value::as_str) {
                Some("text") => text(rules, block.get_mut("text"), &mut report),
                Some("resource_link") => {
                    apply(rules, block, &mut report);
                    text(rules, block.get_mut("uri"), &mut report);
                    text(rules, block.get_mut("text"), &mut report);
                    if block.get("type").and_then(Value::as_str) != Some("resource_link")
                        || !["uri", "name"]
                            .iter()
                            .all(|key| block.get(*key).is_some_and(Value::is_string))
                    {
                        withhold(block, &mut report);
                    }
                }
                Some("resource") => {
                    if let Some(resource) = block.get_mut("resource") {
                        apply(rules, resource, &mut report);
                        text(rules, resource.get_mut("uri"), &mut report);
                        text(rules, resource.get_mut("text"), &mut report);
                        if !resource.get("uri").is_some_and(Value::is_string)
                            || !["text", "blob"]
                                .iter()
                                .any(|key| resource.get(*key).is_some_and(Value::is_string))
                        {
                            withhold(block, &mut report);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    (result, report)
}
fn withhold(block: &mut Value, report: &mut Report) {
    *block = serde_json::json!({"type": "text", "text": WITHHELD});
    report.withheld += 1;
}
fn text(rules: &Rules, value: Option<&mut Value>, report: &mut Report) {
    if let Some(value) = value
        && let Some(s) = value.as_str()
    {
        *value = match serde_json::from_str::<Value>(s) {
            Ok(mut json) => {
                apply(rules, &mut json, report);
                Value::String(json.to_string())
            }
            Err(_) => {
                report.withheld += 1;
                Value::String(WITHHELD.into())
            }
        };
    }
}
fn apply(rules: &Rules, value: &mut Value, report: &mut Report) {
    for path in &rules.paths {
        let parts: Vec<_> = path.split('.').collect();
        if parts.len() == 1 {
            bare(value, path, rules.action, report);
        } else {
            dotted(value, &parts, rules.action, report);
        }
    }
}
fn change(
    map: &mut serde_json::Map<String, Value>,
    key: &str,
    action: Action,
    report: &mut Report,
) {
    if !map.contains_key(key) {
        return;
    }
    report.fields += 1;
    match action {
        Action::Strip => {
            map.remove(key);
        }
        Action::Redact => {
            map.insert(key.into(), Value::String(REMOVED.into()));
        }
    }
}
fn bare(v: &mut Value, key: &str, action: Action, report: &mut Report) {
    match v {
        Value::Object(m) => {
            change(m, key, action, report);
            for v in m.values_mut() {
                bare(v, key, action, report);
            }
        }
        Value::Array(a) => {
            for v in a {
                bare(v, key, action, report);
            }
        }
        _ => {}
    }
}
fn dotted(v: &mut Value, parts: &[&str], action: Action, report: &mut Report) {
    if parts.is_empty() {
        return;
    }
    match v {
        Value::Object(m) => {
            if parts.len() == 1 {
                change(m, parts[0], action, report);
            } else if let Some(v) = m.get_mut(parts[0]) {
                dotted(v, &parts[1..], action, report);
            }
        }
        Value::Array(a) if parts[0] == "*" => {
            for v in a {
                dotted(v, &parts[1..], action, report);
            }
        }
        _ => {}
    }
}

/// A conservative schema view: stripping may invalidate constraints anywhere in a schema.
/// Omit it rather than advertising a contract a filtered result cannot meet.
pub fn output_schema(rules: &Rules, schema: Option<Value>) -> Option<Value> {
    if rules.paths.is_empty() { schema } else { None }
}
