use crate::error::{DecodeError, ErrorKind, Result};

#[derive(Clone, Debug)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| DecodeError::new(ErrorKind::Truncated, self.pos, "expected byte"))?;
        self.pos += 1;
        Ok(b)
    }

    pub fn read_u16_le(&mut self) -> Result<u16> {
        let s = self.read_slice(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    pub fn read_u32_le(&mut self) -> Result<u32> {
        let s = self.read_slice(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub fn read_u64_le(&mut self) -> Result<u64> {
        let s = self.read_slice(8)?;
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    pub fn read_var_u32(&mut self) -> Result<u32> {
        let start = self.pos;
        let mut shift = 0;
        let mut value = 0u32;
        for _ in 0..5 {
            let b = self.read_u8()?;
            value |= ((b & 0x7f) as u32) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
        Err(DecodeError::new(
            ErrorKind::BadLength,
            start,
            "varint too long",
        ))
    }

    pub fn read_slice(&mut self, len: usize) -> Result<&'a [u8]> {
        let start = self.pos;
        let end = start
            .checked_add(len)
            .ok_or_else(|| DecodeError::new(ErrorKind::BadLength, start, "length overflow"))?;
        if end > self.data.len() {
            return Err(DecodeError::new(
                ErrorKind::Truncated,
                start,
                "expected slice",
            ));
        }
        self.pos = end;
        Ok(&self.data[start..end])
    }

    pub fn read_to_end(&mut self) -> &'a [u8] {
        let start = self.pos;
        self.pos = self.data.len();
        &self.data[start..]
    }

    pub fn skip(&mut self, len: usize) -> Result<()> {
        self.read_slice(len).map(|_| ())
    }

    pub fn take_until(&mut self, byte: u8) -> &'a [u8] {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != byte {
            self.pos += 1;
        }
        &self.data[start..self.pos]
    }

    pub fn read_line(&mut self) -> Option<&'a [u8]> {
        if self.pos >= self.data.len() {
            return None;
        }
        let start = self.pos;
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            self.pos += 1;
            if b == b'\n' {
                let mut end = self.pos - 1;
                if end > start && self.data[end - 1] == b'\r' {
                    end -= 1;
                }
                return Some(&self.data[start..end]);
            }
        }
        Some(&self.data[start..])
    }

    pub fn rewind(&mut self, pos: usize) {
        self.pos = pos.min(self.data.len());
    }
}

pub fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while matches!(s.first(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        s = &s[1..];
    }
    while matches!(s.last(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        s = &s[..s.len() - 1];
    }
    s
}

pub fn text_lossy(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
            out.push(b as char);
        } else {
            out.push('\u{fffd}');
        }
    }
    out
}

pub fn parse_u32(bytes: &[u8]) -> Option<u32> {
    let s = core::str::from_utf8(trim_ascii(bytes)).ok()?;
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}

pub fn parse_i32(bytes: &[u8]) -> Option<i32> {
    let s = core::str::from_utf8(trim_ascii(bytes)).ok()?;
    if let Some(hex) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        i32::from_str_radix(hex, 16).ok().map(|v| -v)
    } else if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<i32>().ok()
    }
}

pub fn parse_bool(bytes: &[u8]) -> bool {
    matches!(
        trim_ascii(bytes),
        b"1" | b"y" | b"Y" | b"yes" | b"YES" | b"true" | b"TRUE" | b"on" | b"ON"
    )
}

pub fn split_fields(bytes: &[u8], sep: u8) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(move |&b| b == sep)
        .map(trim_ascii)
        .filter(|p| !p.is_empty())
}

pub fn key_value(field: &[u8]) -> Option<(&[u8], &[u8])> {
    let idx = field.iter().position(|&b| b == b'=' || b == b':')?;
    let (k, v) = field.split_at(idx);
    Some((trim_ascii(k), trim_ascii(&v[1..])))
}

pub fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn decode_hex(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut hi = None;
    for &b in input {
        if matches!(b, b' ' | b'\t' | b':' | b'-' | b'_') {
            continue;
        }
        if let Some(n) = hex_nibble(b) {
            if let Some(h) = hi.take() {
                out.push((h << 4) | n);
            } else {
                hi = Some(n);
            }
        }
    }
    out
}
