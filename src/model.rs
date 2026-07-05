use crate::checksum;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind {
    Hello,
    Dictionary,
    Fragment,
    Order,
    Telemetry,
    Journal,
    Script,
    Manifest,
    Bundle,
    Ack,
    Unknown(u8),
}

impl FrameKind {
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Hello,
            1 => Self::Dictionary,
            2 => Self::Fragment,
            3 => Self::Order,
            4 => Self::Telemetry,
            5 => Self::Journal,
            6 => Self::Script,
            7 => Self::Manifest,
            8 => Self::Bundle,
            9 => Self::Ack,
            other => Self::Unknown(other),
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::Hello => 0,
            Self::Dictionary => 1,
            Self::Fragment => 2,
            Self::Order => 3,
            Self::Telemetry => 4,
            Self::Journal => 5,
            Self::Script => 6,
            Self::Manifest => 7,
            Self::Bundle => 8,
            Self::Ack => 9,
            Self::Unknown(v) => v,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Hello => "hello",
            Self::Dictionary => "dictionary",
            Self::Fragment => "fragment",
            Self::Order => "order",
            Self::Telemetry => "telemetry",
            Self::Journal => "journal",
            Self::Script => "script",
            Self::Manifest => "manifest",
            Self::Bundle => "bundle",
            Self::Ack => "ack",
            Self::Unknown(_) => "unknown",
        }
    }

    pub fn from_name(name: &[u8]) -> Option<Self> {
        let lower = name
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .collect::<Vec<_>>();
        match lower.as_slice() {
            b"hello" | b"hlo" => Some(Self::Hello),
            b"dict" | b"dictionary" | b"druglib" => Some(Self::Dictionary),
            b"frag" | b"fragment" | b"segment" => Some(Self::Fragment),
            b"order" | b"dose" | b"rx" => Some(Self::Order),
            b"telemetry" | b"tele" | b"pump" => Some(Self::Telemetry),
            b"journal" | b"audit" | b"log" => Some(Self::Journal),
            b"script" | b"vm" | b"guard" => Some(Self::Script),
            b"manifest" | b"man" => Some(Self::Manifest),
            b"bundle" | b"bndl" => Some(Self::Bundle),
            b"ack" => Some(Self::Ack),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub kind: FrameKind,
    pub sequence: u32,
    pub flags: u16,
    pub payload: Vec<u8>,
    pub checksum: u32,
}

impl Frame {
    pub fn new(kind: FrameKind, sequence: u32, flags: u16, payload: Vec<u8>) -> Self {
        let checksum = checksum::weighted_checksum(&payload, sequence ^ ((flags as u32) << 16));
        Self {
            kind,
            sequence,
            flags,
            payload,
            checksum,
        }
    }

    pub fn is_reliable(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    pub fn is_compressed(&self) -> bool {
        self.flags & 0x0002 != 0
    }

    pub fn wants_ack(&self) -> bool {
        self.flags & 0x0004 != 0 || self.is_reliable()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafetyClass {
    Routine,
    HighAlert,
    WeightBased,
    Titrated,
    Critical,
}

impl SafetyClass {
    pub fn weight(self) -> u16 {
        match self {
            Self::Routine => 1,
            Self::HighAlert => 4,
            Self::WeightBased => 5,
            Self::Titrated => 7,
            Self::Critical => 10,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PatientKey {
    pub ward: u16,
    pub bed: u16,
    pub encounter: u32,
}

impl PatientKey {
    pub fn hash(&self) -> u64 {
        ((self.ward as u64) << 48) ^ ((self.bed as u64) << 32) ^ self.encounter as u64
    }
}

#[derive(Clone, Debug)]
pub struct DoseStep {
    pub minute: u32,
    pub rate_ul_hour: u32,
    pub concentration_ppm: u32,
    pub guard_min: u32,
    pub guard_max: u32,
}

impl DoseStep {
    pub fn normalized_rate(&self) -> u32 {
        if self.concentration_ppm == 0 {
            self.rate_ul_hour
        } else {
            self.rate_ul_hour.saturating_mul(self.concentration_ppm) / 1_000_000
        }
    }
}

#[derive(Clone, Debug)]
pub struct MedicationOrder {
    pub order_id: u32,
    pub patient: PatientKey,
    pub drug_code: u16,
    pub route_code: u16,
    pub class: SafetyClass,
    pub revision: u16,
    pub steps: Vec<DoseStep>,
    pub note_hash: u64,
}

impl MedicationOrder {
    pub fn empty(order_id: u32) -> Self {
        Self {
            order_id,
            patient: PatientKey {
                ward: 0,
                bed: 0,
                encounter: 0,
            },
            drug_code: 0,
            route_code: 0,
            class: SafetyClass::Routine,
            revision: 0,
            steps: Vec::new(),
            note_hash: 0,
        }
    }

    pub fn total_programmed_rate(&self) -> u64 {
        self.steps.iter().map(|s| s.normalized_rate() as u64).sum()
    }
}

#[derive(Clone, Debug)]
pub struct PumpStatus {
    pub pump_id: u32,
    pub channel: u8,
    pub battery_mv: u16,
    pub pressure_mm_hg: i16,
    pub air_inline_score: u16,
    pub motor_ticks: u32,
    pub library_rev: u32,
    pub alarm_bits: u32,
}

impl PumpStatus {
    pub fn severity_hint(&self) -> u16 {
        let mut score = 0u16;
        if self.battery_mv < 10_800 {
            score += 10;
        }
        if self.pressure_mm_hg > 420 {
            score += 20;
        }
        if self.air_inline_score > 700 {
            score += 40;
        }
        score + self.alarm_bits.count_ones() as u16
    }
}

#[derive(Clone, Debug)]
pub struct TelemetryPoint {
    pub tick: u64,
    pub pump_id: u32,
    pub metric: u16,
    pub value: i32,
    pub quality: u8,
}

#[derive(Clone, Debug)]
pub struct JournalEntry {
    pub tick: u64,
    pub actor: u32,
    pub action: u16,
    pub subject: u32,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ManifestSection {
    pub name: String,
    pub version: u32,
    pub declared_len: usize,
    pub checksum: u32,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DoseBundle {
    pub library_rev: u32,
    pub hospital_id: u32,
    pub sections: Vec<ManifestSection>,
}

#[derive(Clone, Debug)]
pub struct Alert {
    pub code: &'static str,
    pub score: u16,
    pub detail: String,
}

#[derive(Clone, Debug, Default)]
pub struct DecodeStats {
    pub frames_seen: usize,
    pub orders_seen: usize,
    pub telemetry_seen: usize,
    pub journals_seen: usize,
    pub fragments_seen: usize,
    pub scripts_seen: usize,
    pub rejected_frames: usize,
    pub checksum_mismatches: usize,
    pub lifecycle_probes: u64,
}
