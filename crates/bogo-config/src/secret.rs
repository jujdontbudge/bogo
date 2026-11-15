//! `secrets.toml` and the [`Secret`] type.
//!
//! A secret's value never appears in `Debug` output or in any error this crate returns.
//! [`Secret`] has no `Display` and no `Serialize`, so it can't be logged or written by accident;
//! the only way to the value is [`Secret::expose`].

use crate::ConfigError;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// What a secret holds.
#[derive(Clone, PartialEq, Eq)]
pub enum SecretValue {
    /// The credential itself, e.g. an API token.
    Value(String),
    /// A file the credential lives in, handed to an upstream as a path (e.g. Link CLI's
    /// auth file, which it refreshes itself).
    Path(PathBuf),
}

/// One named credential from `secrets.toml`.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    name: String,
    value: SecretValue,
}

impl Secret {
    /// The name `bogo.toml` refers to it by. Names are not secret.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The credential. Call this only where it is handed to an upstream, never to log it.
    pub fn expose(&self) -> &SecretValue {
        &self.value
    }

    pub fn is_path(&self) -> bool {
        matches!(self.value, SecretValue::Path(_))
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.is_path() { "path" } else { "value" };
        f.debug_struct("Secret")
            .field("name", &self.name)
            .field("kind", &kind)
            .field("value", &format_args!("<redacted>"))
            .finish()
    }
}

/// Every secret in `secrets.toml`, by name.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secrets {
    by_name: BTreeMap<String, Secret>,
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.by_name.values()).finish()
    }
}

impl Secrets {
    pub fn get(&self, name: &str) -> Option<&Secret> {
        self.by_name.get(name)
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.by_name.keys().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Parse the text of `secrets.toml`. `home` expands a leading `~/` in path secrets.
    ///
    /// Each entry is `name = "value"` or `name = { path = "…" }`. Errors name the entry and
    /// the line, never the value: TOML's own messages are not passed on, because they can
    /// quote the offending text.
    pub fn parse(text: &str, home: Option<&Path>) -> Result<Secrets, ConfigError> {
        let err = |msg: String| ConfigError::new("secrets.toml", msg);
        let table: toml::Table = text.parse().map_err(|e: toml::de::Error| {
            let line = e.span().map(|s| {
                let end = s.start.min(text.len());
                text.as_bytes()[..end]
                    .iter()
                    .filter(|&&b| b == b'\n')
                    .count()
                    + 1
            });
            err(match line {
                Some(l) => format!("not valid TOML (near line {l})"),
                None => "not valid TOML".to_owned(),
            })
        })?;
        let mut by_name = BTreeMap::new();
        for (name, v) in table {
            if !valid_name(&name) {
                return Err(err(format!(
                    "secret name `{}` must use only letters, digits, `_` and `-`",
                    name.escape_debug()
                )));
            }
            let value = match v {
                toml::Value::String(s) => {
                    if s.is_empty() {
                        return Err(err(format!("secret `{name}` is empty")));
                    }
                    SecretValue::Value(s)
                }
                toml::Value::Table(t) => {
                    if let Some(k) = t.keys().find(|k| k.as_str() != "path") {
                        return Err(err(format!(
                            "secret `{name}`: unknown field `{}` (expected only `path`)",
                            k.escape_debug()
                        )));
                    }
                    match t.get("path") {
                        Some(toml::Value::String(p)) if !p.is_empty() => {
                            SecretValue::Path(expand_home(p, home))
                        }
                        _ => {
                            return Err(err(format!(
                                "secret `{name}`: `path` must be a non-empty string"
                            )));
                        }
                    }
                }
                other => {
                    return Err(err(format!(
                        "secret `{name}` must be a string or {{ path = \"…\" }}, not a {}",
                        other.type_str()
                    )));
                }
            };
            by_name.insert(name.clone(), Secret { name, value });
        }
        Ok(Secrets { by_name })
    }

    /// Read `secrets.toml`, refusing it unless it is a regular file (not a symlink) that only
    /// its owner can read or write (0600 or stricter).
    pub fn load(path: &Path, home: Option<&Path>) -> Result<Secrets, ConfigError> {
        let err = |msg: String| ConfigError::new("secrets.toml", msg);
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| err(format!("cannot read {}: {e}", path.display())))?;
        if !meta.file_type().is_file() {
            return Err(err(format!(
                "{} must be a regular file, not a symlink",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(err(format!(
                    "{} has mode {mode:o}; it must be readable only by its owner (chmod 600)",
                    path.display()
                )));
            }
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| err(format!("cannot read {}: {e}", path.display())))?;
        Secrets::parse(&text, home)
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub(crate) fn expand_home(p: &str, home: Option<&Path>) -> PathBuf {
    match (p.strip_prefix("~/"), home) {
        (Some(rest), Some(h)) => h.join(rest),
        _ => PathBuf::from(p),
    }
}
