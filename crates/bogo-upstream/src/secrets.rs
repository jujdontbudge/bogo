use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE},
};
use bogo_config::{SecretValue, Secrets, Value};
use serde_json::Value as Json;

#[derive(Clone, Default)]
pub struct Scrubber {
    needles: Vec<String>,
}
impl Scrubber {
    /// Include every configured secret, even secrets belonging to another upstream.
    pub fn new(secrets: &Secrets) -> Self {
        let mut needles = Vec::new();
        for name in secrets.names() {
            if let Some(s) = secrets.get(name) {
                let value = match s.expose() {
                    SecretValue::Value(v) => v.clone(),
                    SecretValue::Path(p) => p.to_string_lossy().into_owned(),
                };
                for encoded in [STANDARD.encode(&value), URL_SAFE.encode(&value)] {
                    needles.push(encoded.trim_end_matches('=').to_owned());
                    needles.push(encoded);
                }
                // Stderr arrives as lines; reserve every component of multiline secrets
                // too, so line-oriented logging cannot disclose pieces of a credential.
                needles.extend(value.lines().map(str::to_owned));
                needles.push(value);
            }
        }
        needles.retain(|s| !s.is_empty());
        needles.sort_by_key(|s| std::cmp::Reverse(s.len()));
        needles.dedup();
        Self { needles }
    }
    pub fn text(&self, text: &str) -> String {
        // Scan source once: a replacement must never become input to another replacement.
        let mut out = String::new();
        let mut i = 0;
        while i < text.len() {
            if let Some(n) = self
                .needles
                .iter()
                .find(|n| text[i..].starts_with(n.as_str()))
            {
                out.push_str("[credential removed by BOGO]");
                i += n.len();
            } else {
                let c = text[i..].chars().next().expect("nonempty suffix");
                out.push(c);
                i += c.len_utf8();
            }
        }
        out
    }
    pub fn json(&self, value: &mut Json) {
        match value {
            Json::String(s) => *s = self.text(s),
            Json::Array(a) => {
                for v in a {
                    self.json(v);
                }
            }
            Json::Object(m) => {
                let old = std::mem::take(m);
                for (k, mut v) in old {
                    self.json(&mut v);
                    m.insert(self.text(&k), v);
                }
            }
            Json::Number(n) => {
                let raw = n.to_string();
                let clean = self.text(&raw);
                if clean != raw {
                    *value = Json::String(clean);
                }
            }
            _ => {}
        }
    }
    pub(crate) fn message(
        &self,
        bytes: &[u8],
    ) -> Result<rmcp::model::ServerJsonRpcMessage, crate::Error> {
        let mut value: Json = serde_json::from_slice(bytes).map_err(|_| crate::Error::Protocol)?;
        self.json(&mut value);
        serde_json::from_value(value).map_err(|_| crate::Error::Protocol)
    }
}
pub(crate) fn expose(value: &Value) -> String {
    match value {
        Value::Plain(s) => s.clone(),
        Value::Secret(s) => match s.expose() {
            SecretValue::Value(v) => v.clone(),
            SecretValue::Path(p) => p.to_string_lossy().into_owned(),
        },
    }
}
