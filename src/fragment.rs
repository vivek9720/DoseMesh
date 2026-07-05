use crate::arena::ByteTape;
use crate::checksum;
use crate::codec::payload_map;
use crate::cursor::{parse_u32, split_fields};

#[derive(Clone, Debug)]
pub struct Fragment {
    pub stream_id: u32,
    pub ordinal: u16,
    pub total: u16,
    pub flags: u16,
    pub bytes: Vec<u8>,
    pub hash: u64,
}

#[derive(Debug, Default)]
pub struct FragmentAssembler {
    tape: ByteTape,
    fragments: Vec<Fragment>,
    completed: Vec<Vec<u8>>,
    generation: u32,
}

impl FragmentAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_payload(&mut self, payload: &[u8]) -> u64 {
        let map = payload_map(payload);
        let stream_id = map
            .get_u32("sid")
            .or_else(|| map.get_u32("stream"))
            .unwrap_or(0);
        let total = map.get_u32("total").unwrap_or(1).max(1).min(256) as u16;
        let mut score = stream_id as u64 ^ total as u64;

        if let Some(parts) = map.get("seg").or_else(|| map.get("frags")) {
            for part in split_fields(parts, b',') {
                let ordinal = part.first().copied().unwrap_or(0) as u16 % total;
                let bytes = part.to_vec();
                score ^= self.push_fragment(stream_id, ordinal, total, 0, bytes);
            }
        } else {
            let ordinal = map
                .get_u32("ord")
                .or_else(|| map.get_u32("idx"))
                .unwrap_or(0) as u16;
            let flags = map.get_u32("flags").unwrap_or(0) as u16;
            let bytes = if let Some(raw) = map.get("data").or_else(|| map.get("body")) {
                raw.to_vec()
            } else {
                payload.to_vec()
            };
            score ^= self.push_fragment(stream_id, ordinal % total, total, flags, bytes);
        }

        if map.get("flush").is_some() || self.fragments.len() > total as usize {
            if let Some(done) = self.try_assemble(stream_id, total) {
                score ^= checksum::fnv1a64(&done);
                self.completed.push(done);
            }
        }

        if let Some(retire) = map.get("retire").and_then(parse_u32) {
            self.retire_stream(retire);
        }

        if self.tape.mark_count() > 3 && self.fragments.len() % 4 == 1 {
            score ^= self.tape.probe_marks(self.generation ^ stream_id);
        }
        score
    }

    pub fn take_completed(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.completed)
    }

    pub fn len(&self) -> usize {
        self.fragments.len()
    }

    fn push_fragment(
        &mut self,
        stream_id: u32,
        ordinal: u16,
        total: u16,
        flags: u16,
        bytes: Vec<u8>,
    ) -> u64 {
        let offset = self.tape.append(&bytes);
        self.tape.mark(offset, bytes.len().min(96));
        let hash = checksum::fnv1a64(&bytes) ^ ((stream_id as u64) << 17) ^ ordinal as u64;
        self.fragments.push(Fragment {
            stream_id,
            ordinal,
            total,
            flags,
            bytes,
            hash,
        });
        self.generation = self.generation.wrapping_add(1);
        hash
    }

    fn try_assemble(&mut self, stream_id: u32, total: u16) -> Option<Vec<u8>> {
        let mut parts = vec![None; total as usize];
        for frag in &self.fragments {
            if frag.stream_id == stream_id && frag.total == total {
                let idx = frag.ordinal as usize;
                if idx < parts.len() {
                    parts[idx] = Some(frag.bytes.clone());
                }
            }
        }
        if parts.iter().all(Option::is_some) {
            let mut out = Vec::new();
            for part in parts.into_iter().flatten() {
                out.extend_from_slice(&part);
            }
            self.retire_stream(stream_id);
            Some(out)
        } else {
            None
        }
    }

    fn retire_stream(&mut self, stream_id: u32) {
        let before = self.fragments.len();
        self.fragments.retain(|f| f.stream_id != stream_id);
        let removed = before.saturating_sub(self.fragments.len());
        if removed > 0 {
            self.tape.retire_prefix(removed * 8);
            self.generation = self.generation.wrapping_add(removed as u32);
        }
        if self.fragments.is_empty() && stream_id & 7 == 5 {
            self.tape.clear();
        }
    }
}
