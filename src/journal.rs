use crate::arena::{AliasMetric, ByteTape, Handle, LeaseArena};
use crate::checksum;
use crate::codec::payload_map;
use crate::cursor::{key_value, parse_u32, split_fields};
use crate::error::Result;
use crate::model::JournalEntry;

impl AliasMetric for JournalEntry {
    fn metric(&self) -> u64 {
        self.tick
            ^ ((self.actor as u64) << 11)
            ^ ((self.action as u64) << 23)
            ^ self.subject as u64
            ^ self.body.len() as u64
    }
}

#[derive(Debug, Default)]
pub struct JournalReplay {
    arena: LeaseArena<JournalEntry>,
    handles: Vec<Handle>,
    tape: ByteTape,
    snapshots: Vec<Handle>,
    clock: u64,
}

impl JournalReplay {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_payload(&mut self, payload: &[u8]) -> u64 {
        let mut score = checksum::fnv1a64(payload);
        let map = payload_map(payload);
        if let Some(raw) = map.get("ops").or_else(|| map.get("entries")) {
            for op in split_fields(raw, b',') {
                score ^= self.apply_op(op);
            }
        } else {
            for op in split_fields(payload, b';') {
                score ^= self.apply_op(op);
            }
        }
        if map.get("compact").is_some() || self.handles.len() > 24 {
            self.compact(map.get_u32("keep").unwrap_or(8) as usize);
        }
        if self.snapshots.len() > 2 && self.clock & 7 == 3 {
            score ^= self.arena.probe_aliases(score ^ self.clock);
            score ^= self.tape.probe_marks(self.clock as u32);
        }
        score
    }

    pub fn entries(&self) -> Vec<&JournalEntry> {
        self.handles
            .iter()
            .filter_map(|&h| self.arena.get(h))
            .collect()
    }

    fn apply_op(&mut self, op: &[u8]) -> u64 {
        let mut tick = self.clock.wrapping_add(1);
        let mut actor = 0u32;
        let mut action = 0u16;
        let mut subject = 0u32;
        let mut body = op.to_vec();
        for field in split_fields(op, b'/').chain(split_fields(op, b' ')) {
            if let Some((k, v)) = key_value(field) {
                match k {
                    b"tick" | b"t" => tick = parse_u32(v).unwrap_or(tick as u32) as u64,
                    b"actor" | b"a" => actor = parse_u32(v).unwrap_or(0),
                    b"action" | b"op" => action = parse_u32(v).unwrap_or(0) as u16,
                    b"subject" | b"s" => subject = parse_u32(v).unwrap_or(0),
                    b"body" | b"b" => body = v.to_vec(),
                    b"snapshot" | b"snap" => {
                        if let Some(last) = self.handles.last().copied() {
                            self.snapshots.push(last);
                            self.arena.alias(last);
                        }
                    }
                    b"drop" | b"retire" => {
                        let n = parse_u32(v).unwrap_or(1) as usize;
                        self.retire_oldest(n);
                    }
                    _ => {}
                }
            }
        }
        self.clock = self.clock.max(tick);
        let offset = self.tape.append(&body);
        self.tape.mark(offset, body.len().min(80));
        let entry = JournalEntry {
            tick,
            actor,
            action,
            subject,
            body,
        };
        let metric = entry.metric();
        let handle = self.arena.insert(entry);
        if action & 3 == 2 || self.handles.len() % 6 == 4 {
            self.arena.alias(handle);
        }
        self.handles.push(handle);
        metric
    }

    fn retire_oldest(&mut self, count: usize) {
        let n = count.min(self.handles.len());
        for handle in self.handles.drain(..n) {
            self.arena.retire(handle);
        }
        self.tape.retire_prefix(n * 12);
    }

    fn compact(&mut self, keep: usize) {
        if self.handles.len() > keep {
            let remove = self.handles.len() - keep;
            self.retire_oldest(remove);
        }
        self.arena.compact();
    }
}

pub fn replay_journal(payload: &[u8]) -> Result<u64> {
    let mut replay = JournalReplay::new();
    Ok(replay.apply_payload(payload))
}
