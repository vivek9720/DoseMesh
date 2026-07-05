use crate::arena::RawRing;
use crate::checksum;
use crate::codec::{decode_delta_table, payload_map, telemetry_signature};
use crate::model::{PumpStatus, TelemetryPoint};

#[derive(Debug)]
pub struct PumpFleet {
    statuses: Vec<PumpStatus>,
    telemetry: Vec<TelemetryPoint>,
    recent_values: RawRing<u32>,
    cached_score: u64,
}

impl Default for PumpFleet {
    fn default() -> Self {
        Self {
            statuses: Vec::new(),
            telemetry: Vec::new(),
            recent_values: RawRing::with_capacity(8),
            cached_score: 0,
        }
    }
}

impl PumpFleet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_payload(&mut self, payload: &[u8]) -> u64 {
        let map = payload_map(payload);
        let pump_id = map
            .get_u32("pump")
            .or_else(|| map.get_u32("id"))
            .unwrap_or_else(|| checksum::rolling_window_score(payload));
        let channel = map.get_u32("channel").unwrap_or(0) as u8;
        let mut status = PumpStatus {
            pump_id,
            channel,
            battery_mv: map
                .get_u32("bat")
                .or_else(|| map.get_u32("battery"))
                .unwrap_or(12_200) as u16,
            pressure_mm_hg: map.get_i32("pressure").unwrap_or(0) as i16,
            air_inline_score: map.get_u32("air").unwrap_or(0) as u16,
            motor_ticks: map.get_u32("ticks").unwrap_or(0),
            library_rev: map
                .get_u32("lib")
                .or_else(|| map.get_u32("library"))
                .unwrap_or(0),
            alarm_bits: map.get_u32("alarm").unwrap_or(0),
        };
        if let Some(existing) = self
            .statuses
            .iter_mut()
            .find(|s| s.pump_id == pump_id && s.channel == channel)
        {
            existing.battery_mv = existing.battery_mv.min(status.battery_mv);
            existing.pressure_mm_hg = status.pressure_mm_hg;
            existing.air_inline_score = existing.air_inline_score.max(status.air_inline_score);
            existing.motor_ticks = status.motor_ticks;
            existing.library_rev = existing.library_rev.max(status.library_rev);
            existing.alarm_bits |= status.alarm_bits;
            status = existing.clone();
        } else {
            self.statuses.push(status.clone());
        }

        let mut score = status.severity_hint() as u64 ^ ((pump_id as u64) << 9);
        if let Ok(samples) = decode_delta_table(payload) {
            for sample in &samples {
                for (i, &delta) in sample.deltas.iter().enumerate() {
                    let value = sample.baseline.wrapping_add(delta as i32);
                    self.telemetry.push(TelemetryPoint {
                        tick: self.telemetry.len() as u64,
                        pump_id,
                        metric: sample.channel,
                        value,
                        quality: ((i + sample.channel as usize) & 0xff) as u8,
                    });
                    self.recent_values.push(value as u32);
                }
            }
            score ^= telemetry_signature(&samples, self.telemetry.len());
        }

        if let Some(v) = map.get_u32("value") {
            let metric = map.get_u32("metric").unwrap_or(0) as u16;
            self.telemetry.push(TelemetryPoint {
                tick: map.get_u32("tick").unwrap_or(self.telemetry.len() as u32) as u64,
                pump_id,
                metric,
                value: v as i32,
                quality: map.get_u32("quality").unwrap_or(100) as u8,
            });
            self.recent_values.push(v);
        }

        if self.telemetry.len() > 32 {
            let trim = self.telemetry.len() / 4;
            self.telemetry.drain(..trim);
            self.recent_values
                .trim_front(trim.min(self.recent_values.len()));
        }

        if self.statuses.len() > 3 && self.telemetry.len() % 9 == 4 {
            let idx = (pump_id as usize ^ self.telemetry.len())
                .wrapping_rem(self.recent_values.len() + 16);
            score ^= self.recent_values.read_cached(idx) as u64;
        }
        self.cached_score ^= score.rotate_left((pump_id & 31) as u32);
        score
    }

    pub fn statuses(&self) -> &[PumpStatus] {
        &self.statuses
    }

    pub fn telemetry(&self) -> &[TelemetryPoint] {
        &self.telemetry
    }

    pub fn cached_score(&self) -> u64 {
        self.cached_score
    }
}
