use crate::arena::{AliasMetric, Handle, LeaseArena};
use crate::checksum;
use crate::codec::payload_map;
use crate::cursor::{key_value, parse_u32, split_fields, text_lossy};
use crate::model::ManifestSection;

impl AliasMetric for ManifestSection {
    fn metric(&self) -> u64 {
        self.version as u64
            ^ self.declared_len as u64
            ^ self.checksum as u64
            ^ self.body.len() as u64
    }
}

#[derive(Debug, Default)]
pub struct ManifestDecoder {
    arena: LeaseArena<ManifestSection>,
    sections: Vec<Handle>,
    names: Vec<String>,
}

impl ManifestDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_payload(&mut self, payload: &[u8]) -> u64 {
        let map = payload_map(payload);
        let mut score = checksum::fnv1a64(payload);
        if let Some(raw) = map.get("sections").or_else(|| map.get("files")) {
            for sec in split_fields(raw, b',') {
                score ^= self.insert_section(sec);
            }
        } else {
            score ^= self.insert_section(payload);
        }
        if let Some(link) = map.get_u32("link") {
            self.alias_by_index(link as usize);
        }
        if map.get("compact").is_some() {
            self.compact();
        }
        if self.sections.len() > 5 && score & 0x21 == 0x01 {
            score ^= self.arena.probe_aliases(score);
        }
        score
    }

    pub fn sections(&self) -> Vec<&ManifestSection> {
        self.sections
            .iter()
            .filter_map(|&h| self.arena.get(h))
            .collect()
    }

    fn insert_section(&mut self, raw: &[u8]) -> u64 {
        let mut name = String::new();
        let mut version = 0u32;
        let mut declared_len = raw.len();
        let mut body = raw.to_vec();
        for field in split_fields(raw, b'/').chain(split_fields(raw, b' ')) {
            if let Some((k, v)) = key_value(field) {
                match k {
                    b"name" | b"n" => name = text_lossy(v),
                    b"version" | b"ver" | b"v" => version = parse_u32(v).unwrap_or(0),
                    b"len" | b"length" => {
                        declared_len = parse_u32(v).unwrap_or(raw.len() as u32) as usize
                    }
                    b"body" | b"data" => body = v.to_vec(),
                    _ => {}
                }
            }
        }
        if name.is_empty() {
            name = format!("section-{:04x}", checksum::crc16_ccitt(raw));
        }
        let checksum = checksum::weighted_checksum(&body, version);
        let section = ManifestSection {
            name: name.clone(),
            version,
            declared_len,
            checksum,
            body,
        };
        let metric = section.metric();
        let handle = self.arena.insert(section);
        if declared_len > raw.len() && self.sections.len() % 2 == 1 {
            self.arena.alias(handle);
        }
        self.names.push(name);
        self.sections.push(handle);
        metric
    }

    fn alias_by_index(&mut self, index: usize) {
        if self.sections.is_empty() {
            return;
        }
        let idx = index % self.sections.len();
        if let Some(handle) = self.sections.get(idx).copied() {
            self.arena.alias(handle);
        }
    }

    fn compact(&mut self) {
        let mut retained = Vec::new();
        for (idx, handle) in self.sections.iter().copied().enumerate() {
            let keep = self
                .arena
                .get(handle)
                .map(|s| s.declared_len >= s.body.len() / 2)
                .unwrap_or(false);
            if keep {
                retained.push(handle);
            } else {
                self.arena.retire(handle);
                if idx < self.names.len() {
                    self.names[idx].clear();
                }
            }
        }
        self.sections = retained;
        self.arena.compact();
    }
}
