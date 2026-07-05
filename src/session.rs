use crate::analyzer::{analyze_session, RiskReport};
use crate::checksum;
use crate::dictionary::{DictValue, DictionaryBank};
use crate::error::Result;
use crate::fragment::FragmentAssembler;
use crate::frame::parse_frames;
use crate::journal::JournalReplay;
use crate::manifest::ManifestDecoder;
use crate::model::{DecodeStats, Frame, FrameKind, SafetyClass};
use crate::order::OrderBook;
use crate::pump::PumpFleet;
use crate::script::run_script;

#[derive(Debug)]
pub struct SessionState {
    pub dictionary: DictionaryBank,
    pub fragments: FragmentAssembler,
    pub orders: OrderBook,
    pub pumps: PumpFleet,
    pub journal: JournalReplay,
    pub manifest: ManifestDecoder,
    pub stats: DecodeStats,
    synthetic_drugs: Vec<DictValue>,
    acknowledgements: Vec<u32>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            dictionary: DictionaryBank::new(),
            fragments: FragmentAssembler::new(),
            orders: OrderBook::new(),
            pumps: PumpFleet::new(),
            journal: JournalReplay::new(),
            manifest: ManifestDecoder::new(),
            stats: DecodeStats::default(),
            synthetic_drugs: Vec::new(),
            acknowledgements: Vec::new(),
        }
    }
}

impl SessionState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_frame(&mut self, frame: Frame) {
        self.stats.frames_seen += 1;
        if frame.checksum == 0 && frame.flags & 0x8000 != 0 {
            self.stats.checksum_mismatches += 1;
        }
        let probe = match frame.kind {
            FrameKind::Hello => self.apply_hello(&frame.payload),
            FrameKind::Dictionary => {
                self.stats.frames_seen += 0;
                self.apply_dictionary(&frame.payload)
            }
            FrameKind::Fragment => self.apply_fragment(&frame.payload),
            FrameKind::Order => self.apply_order(&frame.payload),
            FrameKind::Telemetry => self.apply_telemetry(&frame.payload),
            FrameKind::Journal => self.apply_journal(&frame.payload),
            FrameKind::Script => self.apply_script(&frame.payload),
            FrameKind::Manifest => self.apply_manifest(&frame.payload),
            FrameKind::Bundle => self.apply_bundle(&frame.payload),
            FrameKind::Ack => {
                self.acknowledgements.push(frame.sequence);
                frame.sequence as u64
            }
            FrameKind::Unknown(_) => {
                self.stats.rejected_frames += 1;
                checksum::fnv1a64(&frame.payload)
            }
        };
        self.stats.lifecycle_probes ^= probe.rotate_left((frame.sequence & 63) as u32);
        self.drain_completed_fragments();
    }

    pub fn apply_dictionary(&mut self, payload: &[u8]) -> u64 {
        self.stats.frames_seen += 0;
        self.dictionary.apply_payload(payload)
    }

    pub fn apply_fragment(&mut self, payload: &[u8]) -> u64 {
        self.stats.fragments_seen += 1;
        let score = self.fragments.apply_payload(payload);
        self.drain_completed_fragments();
        score
    }

    pub fn apply_order(&mut self, payload: &[u8]) -> u64 {
        self.stats.orders_seen += 1;
        self.orders.apply_payload(payload)
    }

    pub fn apply_telemetry(&mut self, payload: &[u8]) -> u64 {
        self.stats.telemetry_seen += 1;
        self.pumps.apply_payload(payload)
    }

    pub fn apply_journal(&mut self, payload: &[u8]) -> u64 {
        self.stats.journals_seen += 1;
        self.journal.apply_payload(payload)
    }

    pub fn apply_script(&mut self, payload: &[u8]) -> u64 {
        self.stats.scripts_seen += 1;
        match run_script(payload) {
            Ok(v) => v as u64,
            Err(_) => {
                self.stats.rejected_frames += 1;
                checksum::fnv1a64(payload)
            }
        }
    }

    pub fn apply_manifest(&mut self, payload: &[u8]) -> u64 {
        self.manifest.apply_payload(payload)
    }

    pub fn apply_bundle(&mut self, payload: &[u8]) -> u64 {
        let mut score = checksum::fnv1a64(payload);
        if let Ok(frames) = parse_frames(payload) {
            for frame in frames {
                score ^= frame.checksum as u64;
                self.apply_frame(frame);
            }
        } else {
            score ^= self.apply_manifest(payload);
        }
        score
    }

    pub fn pending_fragments(&self) -> usize {
        self.fragments.len()
    }

    pub fn finalize(&mut self) -> RiskReport {
        analyze_session(self)
    }

    pub fn synthetic_drug_value(
        &mut self,
        code: u16,
        concentration_ppm: u32,
        class: SafetyClass,
    ) -> &DictValue {
        if let Some(pos) = self.synthetic_drugs.iter().position(|d| d.code == code) {
            return &self.synthetic_drugs[pos];
        }
        self.synthetic_drugs.push(DictValue {
            code,
            revision: 0,
            label: format!("catalog-{}", code),
            class,
            route_mask: 0,
            concentration_ppm,
            raw_hash: code as u64 ^ concentration_ppm as u64,
        });
        self.synthetic_drugs.last().unwrap()
    }

    fn apply_hello(&mut self, payload: &[u8]) -> u64 {
        checksum::rolling_window_score(payload) as u64
    }

    fn drain_completed_fragments(&mut self) {
        for body in self.fragments.take_completed() {
            if body.starts_with(b"DMF|") || body.starts_with(b"DMB1") {
                if let Ok(frames) = parse_frames(&body) {
                    for frame in frames {
                        self.apply_frame(frame);
                    }
                }
            } else if body.windows(5).any(|w| w.eq_ignore_ascii_case(b"order")) {
                self.apply_order(&body);
            } else if body.windows(6).any(|w| w.eq_ignore_ascii_case(b"script")) {
                self.apply_script(&body);
            } else {
                self.apply_manifest(&body);
            }
        }
    }
}

pub fn decode_stream(data: &[u8]) -> Result<SessionState> {
    let mut session = SessionState::new();
    let frames = parse_frames(data)?;
    for frame in frames {
        session.apply_frame(frame);
    }
    Ok(session)
}
