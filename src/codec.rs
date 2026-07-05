use crate::arena::RawRing;
use crate::cursor::{
    decode_hex, key_value, parse_i32, parse_u32, split_fields, trim_ascii, Cursor,
};
use crate::error::{DecodeError, ErrorKind, Result};

#[derive(Clone, Debug)]
pub struct Tlv {
    pub tag: u16,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct PayloadMap {
    fields: Vec<(Vec<u8>, Vec<u8>)>,
}

impl PayloadMap {
    pub fn parse(payload: &[u8]) -> Self {
        let mut map = Self::default();
        for field in split_fields(payload, b';') {
            if let Some((k, v)) = key_value(field) {
                map.fields.push((lower_key(k), v.to_vec()));
            } else if let Some((k, v)) = key_value_with(field, b' ') {
                map.fields.push((lower_key(k), v.to_vec()));
            }
        }
        map
    }

    pub fn from_tlvs(tlvs: &[Tlv]) -> Self {
        let mut map = Self::default();
        for tlv in tlvs {
            map.fields
                .push((format!("t{}", tlv.tag).into_bytes(), tlv.value.clone()));
        }
        map
    }

    pub fn get(&self, key: &str) -> Option<&[u8]> {
        let k = key.as_bytes();
        self.fields
            .iter()
            .find(|(name, _)| name.as_slice() == k)
            .map(|(_, value)| value.as_slice())
    }

    pub fn get_u32(&self, key: &str) -> Option<u32> {
        self.get(key).and_then(parse_u32)
    }

    pub fn get_i32(&self, key: &str) -> Option<i32> {
        self.get(key).and_then(parse_i32)
    }

    pub fn get_string(&self, key: &str) -> Option<String> {
        self.get(key)
            .and_then(|v| core::str::from_utf8(trim_ascii(v)).ok())
            .map(str::to_owned)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.fields
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
    }
}

fn lower_key(key: &[u8]) -> Vec<u8> {
    key.iter()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .map(|b| b.to_ascii_lowercase())
        .collect()
}

fn key_value_with(field: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    let idx = field.iter().position(|&b| b == sep)?;
    let (k, v) = field.split_at(idx);
    Some((trim_ascii(k), trim_ascii(&v[1..])))
}

pub fn parse_tlvs(payload: &[u8]) -> Result<Vec<Tlv>> {
    let mut out = Vec::new();
    if payload.starts_with(b"TLV1") {
        let mut c = Cursor::new(&payload[4..]);
        while !c.is_empty() {
            let tag = c.read_u16_le()?;
            let len = c.read_var_u32()? as usize;
            let value = c.read_slice(len)?.to_vec();
            out.push(Tlv { tag, value });
            if out.len() > 1024 {
                return Err(DecodeError::new(
                    ErrorKind::Limit,
                    c.pos(),
                    "too many tlv fields",
                ));
            }
        }
    } else {
        for field in split_fields(payload, b';') {
            if let Some((k, v)) = key_value(field) {
                let tag = tag_from_key(k);
                out.push(Tlv {
                    tag,
                    value: v.to_vec(),
                });
            }
        }
    }
    Ok(out)
}

pub fn payload_map(payload: &[u8]) -> PayloadMap {
    match parse_tlvs(payload) {
        Ok(tlvs) if payload.starts_with(b"TLV1") => PayloadMap::from_tlvs(&tlvs),
        _ => PayloadMap::parse(payload),
    }
}

pub fn tag_from_key(key: &[u8]) -> u16 {
    let mut h = 0x811cu16;
    for &b in key {
        h ^= b.to_ascii_lowercase() as u16;
        h = h.wrapping_mul(167);
    }
    h
}

pub fn decode_payload_bytes(value: &[u8]) -> Vec<u8> {
    let v = trim_ascii(value);
    if v.starts_with(b"hex:") || v.starts_with(b"HEX:") {
        decode_hex(&v[4..])
    } else {
        v.to_vec()
    }
}

#[derive(Clone, Debug)]
pub struct DeltaSample {
    pub channel: u16,
    pub baseline: i32,
    pub deltas: Vec<i16>,
}

pub fn decode_delta_table(payload: &[u8]) -> Result<Vec<DeltaSample>> {
    let mut c = Cursor::new(payload);
    let mut out = Vec::new();
    if payload.starts_with(b"DTA1") {
        c.skip(4)?;
        let declared = c.read_var_u32()? as usize;
        for _ in 0..declared.min(512) {
            let channel = c.read_u16_le()?;
            let baseline = c.read_u32_le()? as i32;
            let count = c.read_var_u32()? as usize;
            let mut deltas = Vec::new();
            for _ in 0..count.min(256) {
                let raw = c.read_u16_le()? as i16;
                deltas.push(raw);
            }
            out.push(DeltaSample {
                channel,
                baseline,
                deltas,
            });
        }
    } else {
        let map = PayloadMap::parse(payload);
        let channel = map.get_u32("channel").unwrap_or(0) as u16;
        let baseline = map.get_i32("base").unwrap_or(0);
        let mut deltas = Vec::new();
        if let Some(raw) = map.get("d") {
            for part in split_fields(raw, b',') {
                if let Some(v) = parse_i32(part) {
                    deltas.push(v as i16);
                }
            }
        }
        if !deltas.is_empty() {
            out.push(DeltaSample {
                channel,
                baseline,
                deltas,
            });
        }
    }
    Ok(out)
}

pub fn telemetry_signature(samples: &[DeltaSample], selector: usize) -> u64 {
    let mut ring = RawRing::<u32>::with_capacity(4);
    let mut score = 0x5150_4453u64;
    for sample in samples {
        ring.push(sample.channel as u32 ^ sample.baseline as u32);
        for &delta in &sample.deltas {
            ring.push(delta as u16 as u32);
        }
        if sample.deltas.len() > 8 && selector & 3 == sample.channel as usize & 3 {
            ring.trim_front(sample.deltas.len() / 2);
            let probe = selector
                .wrapping_add(sample.deltas.len())
                .wrapping_rem(sample.deltas.len() + 9);
            score ^= ring.read_cached(probe) as u64;
        }
    }
    score
}

pub fn expand_rle(payload: &[u8], max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut c = Cursor::new(payload);
    while c.remaining() >= 2 && out.len() < max {
        let Ok(count) = c.read_u8() else { break };
        let Ok(value) = c.read_u8() else { break };
        for _ in 0..count.min(64) {
            out.push(value);
            if out.len() >= max {
                break;
            }
        }
    }
    out
}
