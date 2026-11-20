//! Minimal, dependency-free JSON reader and canonical writer.
//!
//! Signed documents use the same canonical form as the Python reference:
//! sorted object keys, no whitespace, ASCII-only strings, integer numbers.
//! Floats are rejected because their canonical form is implementation-specific;
//! the trust protocol only uses strings, integers, booleans, arrays and objects.

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(map) => map.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(map) => Some(map),
            _ => None,
        }
    }

    pub fn str_at(&self, key: &str, default: &str) -> String {
        self.get(key).and_then(Value::as_str).unwrap_or(default).to_owned()
    }

    pub fn int_at(&self, key: &str, default: i64) -> i64 {
        self.get(key).and_then(Value::as_i64).unwrap_or(default)
    }

    pub fn bool_at(&self, key: &str, default: bool) -> bool {
        self.get(key).and_then(Value::as_bool).unwrap_or(default)
    }

    /// Canonical JSON bytes used for every signature in the protocol.
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out
    }

    fn write_canonical(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Int(n) => out.push_str(&n.to_string()),
            Value::Str(s) => write_string(s, out),
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write_canonical(out);
                }
                out.push(']');
            }
            Value::Object(map) => {
                out.push('{');
                for (index, (key, item)) in map.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_string(key, out);
                    out.push(':');
                    item.write_canonical(out);
                }
                out.push('}');
            }
        }
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Value::Str(value.to_owned())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Value::Str(value)
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Value::Int(value)
    }
}

pub fn object(entries: Vec<(&str, Value)>) -> Value {
    Value::Object(entries.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

pub fn strings(items: &[String]) -> Value {
    Value::Array(items.iter().cloned().map(Value::Str).collect())
}

pub fn parse(input: &str) -> Result<Value, String> {
    let mut reader = Reader { bytes: input.as_bytes(), pos: 0 };
    reader.ws();
    let value = reader.value()?;
    reader.ws();
    if reader.pos != reader.bytes.len() {
        return Err(format!("unexpected trailing JSON at byte {}", reader.pos));
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn ws(&mut self) {
        while self.pos < self.bytes.len() && matches!(self.bytes[self.pos], b' ' | b'\n' | b'\r' | b'\t') {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn value(&mut self) -> Result<Value, String> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b't') => { self.literal(b"true")?; Ok(Value::Bool(true)) }
            Some(b'f') => { self.literal(b"false")?; Ok(Value::Bool(false)) }
            Some(b'n') => { self.literal(b"null")?; Ok(Value::Null) }
            Some(b'-' | b'0'..=b'9') => self.integer(),
            Some(byte) => Err(format!("unexpected JSON byte {:?} at {}", byte as char, self.pos)),
            None => Err("unexpected end of JSON".to_owned()),
        }
    }

    fn literal(&mut self, expected: &[u8]) -> Result<(), String> {
        if self.bytes.get(self.pos..self.pos + expected.len()) == Some(expected) {
            self.pos += expected.len();
            Ok(())
        } else {
            Err(format!("invalid JSON literal at {}", self.pos))
        }
    }

    fn object(&mut self) -> Result<Value, String> {
        self.pos += 1;
        let mut map = BTreeMap::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(format!("object key must be a string at {}", self.pos));
            }
            let key = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' at {}", self.pos));
            }
            self.pos += 1;
            self.ws();
            let value = self.value()?;
            map.insert(key, value);
            self.ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => { self.pos += 1; return Ok(Value::Object(map)); }
                _ => return Err(format!("expected ',' or '}}' at {}", self.pos)),
            }
        }
    }

    fn array(&mut self) -> Result<Value, String> {
        self.pos += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => { self.pos += 1; return Ok(Value::Array(items)); }
                _ => return Err(format!("expected ',' or ']' at {}", self.pos)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let byte = self.bytes[self.pos];
            match byte {
                b'"' => { self.pos += 1; return Ok(out); }
                b'\\' => {
                    self.pos += 1;
                    let escape = *self.bytes.get(self.pos)
                        .ok_or_else(|| "unterminated JSON escape".to_owned())?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let first = self.hex4()?;
                            let code = if (0xD800..=0xDBFF).contains(&first) {
                                if self.bytes.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                    return Err("missing low surrogate in JSON string".to_owned());
                                }
                                self.pos += 2;
                                let second = self.hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&second) {
                                    return Err("invalid low surrogate in JSON string".to_owned());
                                }
                                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                            } else {
                                first
                            };
                            out.push(char::from_u32(code)
                                .ok_or_else(|| format!("invalid Unicode code point {}", code))?);
                        }
                        other => return Err(format!("invalid JSON escape \\{}", other as char)),
                    }
                }
                0x00..=0x1F => return Err(format!("control character in JSON string at {}", self.pos)),
                _ => {
                    let rest = std::str::from_utf8(&self.bytes[self.pos..])
                        .map_err(|_| "invalid UTF-8 in JSON string".to_owned())?;
                    let ch = rest.chars().next()
                        .ok_or_else(|| "unexpected end of JSON string".to_owned())?;
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
        }
        Err("unterminated JSON string".to_owned())
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let slice = self.bytes.get(self.pos..self.pos + 4)
            .ok_or_else(|| "short Unicode escape".to_owned())?;
        self.pos += 4;
        let text = std::str::from_utf8(slice).map_err(|_| "invalid Unicode escape".to_owned())?;
        u32::from_str_radix(text, 16).map_err(|_| "invalid Unicode escape".to_owned())
    }

    fn integer(&mut self) -> Result<Value, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits_start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == digits_start {
            return Err(format!("invalid number at {}", start));
        }
        let token = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap();
        if token.starts_with("-0") && token.len() > 2 || (!token.starts_with('-') && token.starts_with('0') && token.len() > 1) {
            return Err(format!("non-canonical number {} at {}", token, start));
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(format!("floating-point numbers are not allowed in signed documents at {}", start));
        }
        let value = token.parse::<i64>().map_err(|_| format!("number out of range: {}", token))?;
        Ok(Value::Int(value))
    }
}

fn write_string(value: &str, out: &mut String) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7E => {
                let code = c as u32;
                if code <= 0xFFFF {
                    out.push_str(&format!("\\u{:04x}", code));
                } else {
                    let adjusted = code - 0x10000;
                    let high = 0xD800 + (adjusted >> 10);
                    let low = 0xDC00 + (adjusted & 0x3FF);
                    out.push_str(&format!("\\u{:04x}\\u{:04x}", high, low));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_output_is_sorted_ascii_and_compact() {
        let value = parse("{\"b\":2,\"a\":\"café\",\"n\":[1,-3]}").unwrap();
        assert_eq!(value.canonical(), "{\"a\":\"caf\\u00e9\",\"b\":2,\"n\":[1,-3]}");
    }

    #[test]
    fn floats_are_rejected_to_keep_signatures_deterministic() {
        assert!(parse("{\"x\":1.5}").is_err());
    }

    #[test]
    fn surrogate_pairs_round_trip() {
        let value = parse("\"\\ud83d\\ude00\"").unwrap();
        assert_eq!(value.as_str(), Some("😀"));
        assert_eq!(value.canonical(), "\"\\ud83d\\ude00\"");
    }
}
