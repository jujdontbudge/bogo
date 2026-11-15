//! BOGO's exact JSON: a strict lexical parser into the [`JVal`] tree, and the exact writer.
//!
//! This is the Rust side of `lean/BogoCore/Json.lean` (ARCHITECTURE §3.2):
//!
//! * **Numbers keep their exact text.** `4700`, `4700.0`, `4.7e3`, `4.7E3`, `4.7e+3` and `-0`
//!   are six different values. A [`Num`] is never read as a number, so nothing here can round,
//!   normalise or re-spell one.
//! * **Strings are Unicode scalar values.** Escapes are decoded, so `"é"` and `"é"` are the
//!   same string. Lone surrogates (escaped or as raw bytes), invalid UTF-8 and raw control
//!   characters are refused.
//! * **Objects are sorted by key bytes** and duplicate keys are refused, at any depth.
//! * **One exact writer.** [`JVal::write`] gives the one text the Lean writer defines: compact,
//!   keys in tree order, numbers as their text, and only the escapes JSON requires.
//!
//! Tool arguments are parsed only by this crate (ARCHITECTURE §7).

#![forbid(unsafe_code)]

use std::fmt;

/// The exact JSON tree. Mirrors Lean's `Bogo.JVal`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum JVal {
    Null,
    Bool(bool),
    Num(Num),
    Str(String),
    Arr(Vec<JVal>),
    Obj(Obj),
}

/// A JSON number, kept as its exact source text. Always matches the RFC 8259 number grammar.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Num(String);

impl Num {
    /// Accepts `text` only if it is exactly one JSON number, with nothing around it.
    pub fn new(text: impl Into<String>) -> Option<Num> {
        let text = text.into();
        is_json_number(text.as_bytes()).then_some(Num(text))
    }

    /// The exact text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Num {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Num({})", self.0)
    }
}

/// Object members, strictly ascending by key bytes (so no key occurs twice).
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct Obj(Vec<(String, JVal)>);

impl Obj {
    /// Sorts members by key bytes. Returns the repeated key if one occurs twice.
    pub fn new(mut members: Vec<(String, JVal)>) -> Result<Obj, String> {
        members.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        if let Some(w) = members.windows(2).find(|w| w[0].0 == w[1].0) {
            return Err(w[0].0.clone());
        }
        Ok(Obj(members))
    }

    pub fn get(&self, key: &str) -> Option<&JVal> {
        self.0
            .binary_search_by(|(k, _)| k.as_bytes().cmp(key.as_bytes()))
            .ok()
            .map(|i| &self.0[i].1)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &JVal)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_members(self) -> Vec<(String, JVal)> {
        self.0
    }
}

impl fmt::Debug for Obj {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.iter().map(|(k, v)| (k, v)))
            .finish()
    }
}

impl fmt::Debug for JVal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JVal::Null => f.write_str("null"),
            JVal::Bool(b) => write!(f, "{b}"),
            JVal::Num(n) => n.fmt(f),
            JVal::Str(s) => s.fmt(f),
            JVal::Arr(xs) => f.debug_list().entries(xs).finish(),
            JVal::Obj(o) => o.fmt(f),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Errors and limits

/// Why a text was refused. The names match the vector files' `error` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Syntax,
    BadNumber,
    ControlCharacter,
    BadEscape,
    LoneSurrogate,
    InvalidUtf8,
    DuplicateKey,
    Trailing,
    TooLarge,
    TooDeep,
}

impl ErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Syntax => "syntax",
            ErrorKind::BadNumber => "bad_number",
            ErrorKind::ControlCharacter => "control_character",
            ErrorKind::BadEscape => "bad_escape",
            ErrorKind::LoneSurrogate => "lone_surrogate",
            ErrorKind::InvalidUtf8 => "invalid_utf8",
            ErrorKind::DuplicateKey => "duplicate_key",
            ErrorKind::Trailing => "trailing",
            ErrorKind::TooLarge => "too_large",
            ErrorKind::TooDeep => "too_deep",
        }
    }
}

/// A refused text: what was wrong and the byte offset where it was found. It never quotes
/// the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub offset: usize,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            ErrorKind::Syntax => "invalid JSON syntax",
            ErrorKind::BadNumber => "a number that is not valid JSON",
            ErrorKind::ControlCharacter => "an unescaped control character in a string",
            ErrorKind::BadEscape => "an invalid escape in a string",
            ErrorKind::LoneSurrogate => "a lone UTF-16 surrogate in a string",
            ErrorKind::InvalidUtf8 => "invalid UTF-8 in a string",
            ErrorKind::DuplicateKey => "a duplicate object key",
            ErrorKind::Trailing => "data after the JSON value",
            ErrorKind::TooLarge => "a JSON text over the size limit",
            ErrorKind::TooDeep => "JSON nested deeper than the limit",
        };
        write!(f, "{what} (at byte {})", self.offset)
    }
}

impl std::error::Error for Error {}

/// Parser limits. Anything over a limit is refused, never truncated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The largest input, in bytes. Never more than `u32::MAX`, the encoding's length limit.
    pub max_bytes: usize,
    /// The deepest nesting of arrays and objects.
    pub max_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_bytes: 1 << 20,
            max_depth: 128,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Parsing

/// Parse one JSON text with the default limits (1 MiB, depth 128).
pub fn parse(bytes: &[u8]) -> Result<JVal, Error> {
    parse_with(bytes, &Limits::default())
}

/// Parse one JSON text: optional whitespace, one value, optional whitespace, the end.
pub fn parse_with(bytes: &[u8], limits: &Limits) -> Result<JVal, Error> {
    let max_bytes = limits.max_bytes.min(u32::MAX as usize);
    if bytes.len() > max_bytes {
        return Err(Error {
            kind: ErrorKind::TooLarge,
            offset: max_bytes,
        });
    }
    let mut p = Parser {
        b: bytes,
        i: 0,
        max_depth: limits.max_depth,
    };
    let v = p.value(0)?;
    p.skip_ws();
    if p.i != bytes.len() {
        return p.err(ErrorKind::Trailing);
    }
    Ok(v)
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

fn is_num_byte(b: u8) -> bool {
    b.is_ascii_digit() || matches!(b, b'-' | b'+' | b'.' | b'e' | b'E')
}

/// RFC 8259 §6: `[ "-" ] ( "0" / digit1-9 *DIGIT ) [ "." 1*DIGIT ] [ ("e"/"E") ["-"/"+"] 1*DIGIT ]`.
pub fn is_json_number(t: &[u8]) -> bool {
    let mut i = 0;
    let digits = |i: &mut usize| {
        let start = *i;
        while *i < t.len() && t[*i].is_ascii_digit() {
            *i += 1;
        }
        *i > start
    };
    if t.get(i) == Some(&b'-') {
        i += 1;
    }
    match t.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            digits(&mut i);
        }
        _ => return false,
    }
    if t.get(i) == Some(&b'.') {
        i += 1;
        if !digits(&mut i) {
            return false;
        }
    }
    if matches!(t.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(t.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        if !digits(&mut i) {
            return false;
        }
    }
    i == t.len()
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    max_depth: usize,
}

impl Parser<'_> {
    fn err<T>(&self, kind: ErrorKind) -> Result<T, Error> {
        Err(Error {
            kind,
            offset: self.i,
        })
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(is_ws) {
            self.i += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<JVal, Error> {
        self.skip_ws();
        let Some(b) = self.peek() else {
            return self.err(ErrorKind::Syntax);
        };
        match b {
            b'{' | b'[' => {
                if depth >= self.max_depth {
                    return self.err(ErrorKind::TooDeep);
                }
                self.i += 1;
                if b == b'{' {
                    self.object(depth + 1)
                } else {
                    self.array(depth + 1)
                }
            }
            b'"' => {
                self.i += 1;
                Ok(JVal::Str(self.string()?))
            }
            b't' => self.literal(b"true", JVal::Bool(true)),
            b'f' => self.literal(b"false", JVal::Bool(false)),
            b'n' => self.literal(b"null", JVal::Null),
            b'-' | b'0'..=b'9' => {
                // The maximal run of number bytes, then the grammar: "01" and "1.e" are bad
                // numbers, while "0x1" is the number 0 followed by junk.
                let start = self.i;
                while self.peek().is_some_and(is_num_byte) {
                    self.i += 1;
                }
                let text = &self.b[start..self.i];
                if !is_json_number(text) {
                    self.i = start;
                    return self.err(ErrorKind::BadNumber);
                }
                // The grammar admits only ASCII, so this cannot fail.
                let text = std::str::from_utf8(text).map_err(|_| Error {
                    kind: ErrorKind::BadNumber,
                    offset: start,
                })?;
                Ok(JVal::Num(Num(text.to_owned())))
            }
            b'+' | b'.' => self.err(ErrorKind::BadNumber),
            _ => self.err(ErrorKind::Syntax),
        }
    }

    fn literal(&mut self, word: &[u8], v: JVal) -> Result<JVal, Error> {
        if self.b[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(v)
        } else {
            self.err(ErrorKind::Syntax)
        }
    }

    fn hex4(&mut self) -> Result<u32, Error> {
        let mut n = 0u32;
        for k in 0..4 {
            let d = match self.b.get(self.i + k) {
                Some(c @ b'0'..=b'9') => c - b'0',
                Some(c @ b'a'..=b'f') => c - b'a' + 10,
                Some(c @ b'A'..=b'F') => c - b'A' + 10,
                _ => return self.err(ErrorKind::BadEscape),
            };
            n = n * 16 + u32::from(d);
        }
        self.i += 4;
        Ok(n)
    }

    /// The rest of a string after its opening quote. Raw bytes are collected and checked as
    /// UTF-8 at the closing quote, exactly as the Lean vector parser does.
    fn string(&mut self) -> Result<String, Error> {
        let start = self.i;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let Some(b) = self.peek() else {
                return self.err(ErrorKind::Syntax);
            };
            match b {
                b'"' => {
                    self.i += 1;
                    return String::from_utf8(buf).map_err(|e| {
                        let bytes = e.as_bytes();
                        let surrogate = bytes.windows(2).any(|w| w[0] == 0xED && w[1] >= 0xA0);
                        Error {
                            kind: if surrogate {
                                ErrorKind::LoneSurrogate
                            } else {
                                ErrorKind::InvalidUtf8
                            },
                            offset: start,
                        }
                    });
                }
                b'\\' => {
                    self.i += 1;
                    let Some(e) = self.peek() else {
                        return self.err(ErrorKind::Syntax);
                    };
                    self.i += 1;
                    let short = match e {
                        b'"' => Some(b'"'),
                        b'\\' => Some(b'\\'),
                        b'/' => Some(b'/'),
                        b'b' => Some(0x08),
                        b'f' => Some(0x0C),
                        b'n' => Some(b'\n'),
                        b'r' => Some(b'\r'),
                        b't' => Some(b'\t'),
                        b'u' => None,
                        _ => {
                            self.i -= 2;
                            return self.err(ErrorKind::BadEscape);
                        }
                    };
                    if let Some(c) = short {
                        buf.push(c);
                        continue;
                    }
                    let esc = self.i - 2;
                    let u = self.hex4()?;
                    let scalar = match u {
                        0xD800..=0xDBFF => {
                            if !(self.peek() == Some(b'\\')
                                && self.b.get(self.i + 1) == Some(&b'u'))
                            {
                                self.i = esc;
                                return self.err(ErrorKind::LoneSurrogate);
                            }
                            self.i += 2;
                            let lo = self.hex4()?;
                            if !(0xDC00..=0xDFFF).contains(&lo) {
                                self.i = esc;
                                return self.err(ErrorKind::LoneSurrogate);
                            }
                            0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00)
                        }
                        0xDC00..=0xDFFF => {
                            self.i = esc;
                            return self.err(ErrorKind::LoneSurrogate);
                        }
                        _ => u,
                    };
                    // Every value here is a Unicode scalar: surrogates were handled above.
                    let c = char::from_u32(scalar).ok_or(Error {
                        kind: ErrorKind::LoneSurrogate,
                        offset: esc,
                    })?;
                    let mut tmp = [0u8; 4];
                    buf.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes());
                }
                0x00..=0x1F => return self.err(ErrorKind::ControlCharacter),
                _ => {
                    buf.push(b);
                    self.i += 1;
                }
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<JVal, Error> {
        let open = self.i - 1;
        let mut members: Vec<(String, JVal)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(JVal::Obj(Obj::default()));
        }
        loop {
            if self.peek() != Some(b'"') {
                return self.err(ErrorKind::Syntax);
            }
            self.i += 1;
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return self.err(ErrorKind::Syntax);
            }
            self.i += 1;
            let v = self.value(depth)?;
            members.push((key, v));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                    self.skip_ws();
                }
                Some(b'}') => {
                    self.i += 1;
                    return Obj::new(members).map(JVal::Obj).map_err(|_| Error {
                        kind: ErrorKind::DuplicateKey,
                        offset: open,
                    });
                }
                _ => return self.err(ErrorKind::Syntax),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<JVal, Error> {
        let mut xs = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(JVal::Arr(xs));
        }
        loop {
            xs.push(self.value(depth)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                    self.skip_ws();
                }
                Some(b']') => {
                    self.i += 1;
                    return Ok(JVal::Arr(xs));
                }
                _ => return self.err(ErrorKind::Syntax),
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Writing

impl JVal {
    /// The exact JSON text of this value (Lean `JVal.write`).
    pub fn write(&self) -> String {
        let mut out = String::new();
        self.write_into(&mut out);
        out
    }

    /// Append the exact JSON text of this value.
    pub fn write_into(&self, out: &mut String) {
        match self {
            JVal::Null => out.push_str("null"),
            JVal::Bool(true) => out.push_str("true"),
            JVal::Bool(false) => out.push_str("false"),
            JVal::Num(n) => out.push_str(n.as_str()),
            JVal::Str(s) => write_string(s, out),
            JVal::Arr(xs) => {
                out.push('[');
                for (i, x) in xs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    x.write_into(out);
                }
                out.push(']');
            }
            JVal::Obj(o) => {
                out.push('{');
                for (i, (k, v)) in o.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(k, out);
                    out.push(':');
                    v.write_into(out);
                }
                out.push('}');
            }
        }
    }
}

/// `"` and `\` as `\"` and `\\`; U+0008, U+0009, U+000A, U+000C, U+000D as `\b \t \n \f \r`;
/// every other code point below U+0020 as `\u00xx` (lowercase hex); everything else raw.
fn write_string(s: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let n = c as usize;
                out.push_str("\\u00");
                out.push(HEX[n >> 4] as char);
                out.push(HEX[n & 15] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

impl fmt::Display for JVal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.write())
    }
}
