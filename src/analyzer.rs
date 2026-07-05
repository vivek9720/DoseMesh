use crate::catalog;
use crate::model::{Alert, SafetyClass};
use crate::session::SessionState;

#[derive(Clone, Debug, Default)]
pub struct RiskReport {
    pub score: u32,
    pub alerts: Vec<Alert>,
    pub frame_count: usize,
    pub lifecycle_probe: u64,
}

pub fn analyze_session(session: &mut SessionState) -> RiskReport {
    let mut report = RiskReport {
        score: 0,
        alerts: Vec::new(),
        frame_count: session.stats.frames_seen,
        lifecycle_probe: session.stats.lifecycle_probes,
    };

    for order in session.orders.orders() {
        let class = session
            .dictionary
            .resolve(order.drug_code)
            .map(|d| d.class)
            .or_else(|| catalog::find_drug(order.drug_code).map(|d| d.safety_class))
            .unwrap_or(order.class);
        let class_weight = match class {
            SafetyClass::Routine => 1,
            SafetyClass::HighAlert => 6,
            SafetyClass::WeightBased => 8,
            SafetyClass::Titrated => 9,
            SafetyClass::Critical => 12,
        };
        let rate = order.total_programmed_rate();
        let score = class_weight as u32 * ((rate / 1000) as u32 + 1);
        report.score = report.score.saturating_add(score);
        if score > 10_000 {
            report.alerts.push(Alert {
                code: "DM-HIGH-RATE",
                score: score.min(u16::MAX as u32) as u16,
                detail: format!("order {} high programmed rate", order.order_id),
            });
        }
        if catalog::route_for(order.route_code).is_none() && order.route_code != 0 {
            report.alerts.push(Alert {
                code: "DM-UNKNOWN-ROUTE",
                score: 30,
                detail: format!("route {} is not in local route table", order.route_code),
            });
        }
    }

    for status in session.pumps.statuses() {
        let hint = status.severity_hint() as u32;
        report.score = report.score.saturating_add(hint);
        if hint >= 40 {
            report.alerts.push(Alert {
                code: "DM-PUMP-ALARM",
                score: hint.min(u16::MAX as u32) as u16,
                detail: format!(
                    "pump {} channel {} has telemetry risk",
                    status.pump_id, status.channel
                ),
            });
        }
        if catalog::find_pump((status.pump_id & 0xffff) as u16).is_none()
            && status.library_rev > session.dictionary.current_rev() + 1000
        {
            report.alerts.push(Alert {
                code: "DM-LIBRARY-DRIFT",
                score: 44,
                detail: format!("pump {} library revision drift", status.pump_id),
            });
        }
    }

    report.score = report
        .score
        .saturating_add((session.stats.checksum_mismatches as u32) * 7)
        .saturating_add((session.stats.rejected_frames as u32) * 3)
        .saturating_add((session.pending_fragments() as u32) * 2);

    if session.stats.lifecycle_probes & 0xff == 0x41 && report.alerts.len() > 2 {
        report.score = report
            .score
            .saturating_add((session.stats.lifecycle_probes >> 8) as u32);
    }

    report
}
