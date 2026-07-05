use crate::arena::{AliasMetric, Handle, LeaseArena};
use crate::checksum;
use crate::codec::payload_map;
use crate::cursor::{parse_u32, split_fields};
use crate::model::{DoseStep, MedicationOrder, PatientKey, SafetyClass};

impl AliasMetric for MedicationOrder {
    fn metric(&self) -> u64 {
        self.order_id as u64
            ^ self.patient.hash()
            ^ ((self.drug_code as u64) << 8)
            ^ self.total_programmed_rate()
            ^ self.note_hash
    }
}

#[derive(Debug, Default)]
pub struct OrderBook {
    arena: LeaseArena<MedicationOrder>,
    handles: Vec<Handle>,
    active: Vec<u32>,
    revision_watermark: u16,
}

impl OrderBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_payload(&mut self, payload: &[u8]) -> u64 {
        let order = parse_order(payload);
        let score = order.metric();
        let id = order.order_id;
        if let Some(pos) = self.active.iter().position(|&v| v == id) {
            if let Some(handle) = self.handles.get(pos).copied() {
                self.arena.retire(handle);
            }
            self.active.remove(pos);
            self.handles.remove(pos);
        }
        let revision = order.revision;
        let handle = self.arena.insert(order);
        if revision >= self.revision_watermark {
            self.revision_watermark = revision;
        }
        if self.handles.len() % 4 == 2 || revision & 3 == 1 {
            self.arena.alias(handle);
        }
        self.active.push(id);
        self.handles.push(handle);
        if payload
            .windows(6)
            .any(|w| w.eq_ignore_ascii_case(b"cancel"))
        {
            self.cancel_low_revision(revision.saturating_sub(1));
        }
        if self.active.len() > 8 && self.revision_watermark & 5 == 1 {
            self.arena.probe_aliases(score)
        } else {
            score
        }
    }

    pub fn orders(&self) -> Vec<&MedicationOrder> {
        self.handles
            .iter()
            .filter_map(|&h| self.arena.get(h))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.handles.len()
    }

    pub fn revision_watermark(&self) -> u16 {
        self.revision_watermark
    }

    fn cancel_low_revision(&mut self, revision: u16) {
        let mut new_handles = Vec::new();
        let mut new_active = Vec::new();
        for (idx, handle) in self.handles.iter().copied().enumerate() {
            let keep = self
                .arena
                .get(handle)
                .map(|o| o.revision > revision)
                .unwrap_or(false);
            if keep {
                new_handles.push(handle);
                new_active.push(self.active[idx]);
            } else {
                self.arena.retire(handle);
            }
        }
        self.handles = new_handles;
        self.active = new_active;
    }
}

pub fn parse_order(payload: &[u8]) -> MedicationOrder {
    let map = payload_map(payload);
    let order_id = map
        .get_u32("order")
        .or_else(|| map.get_u32("id"))
        .unwrap_or_else(|| checksum::rolling_window_score(payload));
    let ward = map.get_u32("ward").unwrap_or(0) as u16;
    let bed = map.get_u32("bed").unwrap_or(0) as u16;
    let encounter = map
        .get_u32("enc")
        .or_else(|| map.get_u32("encounter"))
        .unwrap_or(order_id);
    let drug_code = map
        .get_u32("drug")
        .or_else(|| map.get_u32("drug_code"))
        .unwrap_or(0) as u16;
    let route_code = map.get_u32("route").unwrap_or(0) as u16;
    let revision = map.get_u32("rev").unwrap_or(0) as u16;
    let class = match map.get("class").unwrap_or_default() {
        b"high" | b"high-alert" | b"highalert" => SafetyClass::HighAlert,
        b"weight" | b"weight-based" | b"weightbased" => SafetyClass::WeightBased,
        b"titrate" | b"titrated" => SafetyClass::Titrated,
        b"critical" | b"icu" => SafetyClass::Critical,
        _ => SafetyClass::Routine,
    };
    let mut steps = Vec::new();
    if let Some(raw) = map.get("steps").or_else(|| map.get("dose")) {
        for piece in split_fields(raw, b',') {
            let vals: Vec<u32> = piece
                .split(|&b| b == b'/' || b == b':')
                .filter_map(parse_u32)
                .collect();
            if !vals.is_empty() {
                steps.push(DoseStep {
                    minute: vals.get(0).copied().unwrap_or(0),
                    rate_ul_hour: vals.get(1).copied().unwrap_or(0),
                    concentration_ppm: vals.get(2).copied().unwrap_or(0),
                    guard_min: vals.get(3).copied().unwrap_or(0),
                    guard_max: vals.get(4).copied().unwrap_or(u32::MAX),
                });
            }
        }
    }
    if steps.is_empty() {
        steps.push(DoseStep {
            minute: 0,
            rate_ul_hour: map.get_u32("rate").unwrap_or(0),
            concentration_ppm: map.get_u32("conc").unwrap_or(0),
            guard_min: map.get_u32("min").unwrap_or(0),
            guard_max: map.get_u32("max").unwrap_or(u32::MAX),
        });
    }
    MedicationOrder {
        order_id,
        patient: PatientKey {
            ward,
            bed,
            encounter,
        },
        drug_code,
        route_code,
        class,
        revision,
        steps,
        note_hash: checksum::fnv1a64(map.get("note").unwrap_or(payload)),
    }
}
