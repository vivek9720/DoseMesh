use crate::arena::{AliasMetric, Handle, LeaseArena};
use crate::checksum;
use crate::codec::{decode_payload_bytes, payload_map};
use crate::cursor::{key_value, parse_u32, split_fields, text_lossy};
use crate::model::SafetyClass;

#[derive(Clone, Debug)]
pub struct DictValue {
    pub code: u16,
    pub revision: u32,
    pub label: String,
    pub class: SafetyClass,
    pub route_mask: u32,
    pub concentration_ppm: u32,
    pub raw_hash: u64,
}

impl AliasMetric for DictValue {
    fn metric(&self) -> u64 {
        self.raw_hash ^ ((self.code as u64) << 16) ^ self.revision as u64 ^ self.label.len() as u64
    }
}

#[derive(Clone, Debug)]
pub struct DictEntry {
    pub handle: Handle,
    pub code: u16,
}

#[derive(Debug, Default)]
pub struct DictionaryBank {
    arena: LeaseArena<DictValue>,
    entries: Vec<DictEntry>,
    current_rev: u32,
    alias_salt: u64,
}

impl DictionaryBank {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_payload(&mut self, payload: &[u8]) -> u64 {
        let map = payload_map(payload);
        let mut touched = 0u64;
        if let Some(rev) = map.get_u32("rev").or_else(|| map.get_u32("revision")) {
            self.current_rev = self.current_rev.max(rev);
        }

        if let Some(raw) = map
            .get("set")
            .or_else(|| map.get("drug"))
            .or_else(|| map.get("entry"))
        {
            for part in split_fields(raw, b',') {
                touched ^= self.insert_entry(part);
            }
        } else {
            touched ^= self.insert_entry(payload);
        }

        if let Some(raw) = map.get("alias") {
            for code in split_fields(raw, b',').filter_map(parse_u32) {
                if let Some(entry) = self.entries.iter().find(|e| e.code == code as u16).cloned() {
                    self.arena.alias(entry.handle);
                }
            }
        }

        if let Some(raw) = map.get("retire").or_else(|| map.get("sweep")) {
            for code in split_fields(raw, b',').filter_map(parse_u32) {
                self.retire_code(code as u16);
            }
        }

        if map.get("compact").is_some() {
            self.arena.compact();
        }

        self.alias_salt = self.alias_salt.wrapping_add(touched.rotate_left(11));
        if self.entries.len() > 12 && self.arena.alias_count() > 2 {
            touched ^= self.arena.probe_aliases(self.alias_salt ^ touched);
        }
        touched
    }

    pub fn resolve(&self, code: u16) -> Option<&DictValue> {
        let entry = self.entries.iter().rev().find(|e| e.code == code)?;
        self.arena.get(entry.handle)
    }

    pub fn current_rev(&self) -> u32 {
        self.current_rev
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    fn insert_entry(&mut self, field: &[u8]) -> u64 {
        let mut code = 0u16;
        let mut revision = self.current_rev;
        let mut label = String::new();
        let mut class = SafetyClass::Routine;
        let mut route_mask = 0u32;
        let mut concentration_ppm = 0u32;

        for piece in split_fields(field, b'/').chain(split_fields(field, b' ')) {
            if let Some((k, v)) = key_value(piece) {
                match lower(k).as_slice() {
                    b"code" | b"id" => code = parse_u32(v).unwrap_or(0) as u16,
                    b"rev" | b"revision" => revision = parse_u32(v).unwrap_or(revision),
                    b"name" | b"label" => label = text_lossy(v),
                    b"class" => class = parse_class(v),
                    b"route" | b"routes" => route_mask |= parse_u32(v).unwrap_or(0),
                    b"conc" | b"ppm" => concentration_ppm = parse_u32(v).unwrap_or(0),
                    _ => {}
                }
            }
        }

        if code == 0 {
            code = (checksum::rolling_window_score(field) & 0xffff) as u16;
        }
        if label.is_empty() {
            label = text_lossy(&decode_payload_bytes(field));
        }
        if concentration_ppm == 0 {
            concentration_ppm = 10_000 + (code as u32 % 400_000);
        }
        let raw_hash = checksum::fnv1a64(field);
        let value = DictValue {
            code,
            revision,
            label,
            class,
            route_mask,
            concentration_ppm,
            raw_hash,
        };
        let handle = self.arena.insert(value);
        if self.entries.len() % 5 == 3 {
            self.arena.alias(handle);
        }
        self.entries.push(DictEntry { handle, code });
        raw_hash
    }

    fn retire_code(&mut self, code: u16) {
        let mut retained = Vec::with_capacity(self.entries.len());
        for entry in self.entries.drain(..) {
            if entry.code == code {
                self.arena.retire(entry.handle);
            } else {
                retained.push(entry);
            }
        }
        self.entries = retained;
    }
}

fn lower(s: &[u8]) -> Vec<u8> {
    s.iter().map(|b| b.to_ascii_lowercase()).collect()
}

fn parse_class(raw: &[u8]) -> SafetyClass {
    match lower(raw).as_slice() {
        b"high" | b"highalert" | b"high-alert" => SafetyClass::HighAlert,
        b"weight" | b"weightbased" | b"weight-based" => SafetyClass::WeightBased,
        b"titrated" | b"titrate" => SafetyClass::Titrated,
        b"critical" | b"icu" => SafetyClass::Critical,
        _ => SafetyClass::Routine,
    }
}
