mod drugs;
mod pumps;
mod routes;
mod rules;

use crate::model::SafetyClass;

#[derive(Clone, Copy, Debug)]
pub struct DrugProfile {
    pub code: u16,
    pub generic: &'static str,
    pub family: &'static str,
    pub default_concentration_ppm: u32,
    pub max_rate_ul_hour: u32,
    pub safety_class: SafetyClass,
    pub route_mask: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct PumpProfile {
    pub code: u16,
    pub family: &'static str,
    pub firmware: &'static str,
    pub channels: u8,
    pub max_rate_ul_hour: u32,
    pub pressure_limit_mm_hg: u16,
    pub library_floor: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct RouteProfile {
    pub code: u16,
    pub mnemonic: &'static str,
    pub description: &'static str,
    pub compatible_mask: u32,
    pub monitoring_weight: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct SafetyRule {
    pub code: &'static str,
    pub family: &'static str,
    pub route: &'static str,
    pub floor_rate: u32,
    pub ceiling_rate: u32,
    pub weight: u16,
}

pub use drugs::DRUG_PROFILES;
pub use pumps::PUMP_PROFILES;
pub use routes::ROUTE_PROFILES;
pub use rules::SAFETY_RULES;

pub fn find_drug(code: u16) -> Option<&'static DrugProfile> {
    DRUG_PROFILES.iter().find(|p| p.code == code)
}

pub fn find_pump(code: u16) -> Option<&'static PumpProfile> {
    PUMP_PROFILES.iter().find(|p| p.code == code)
}

pub fn route_for(code: u16) -> Option<&'static RouteProfile> {
    ROUTE_PROFILES.iter().find(|p| p.code == code)
}

pub fn rules_for_family<'a>(family: &'a str) -> impl Iterator<Item = &'static SafetyRule> + 'a {
    SAFETY_RULES.iter().filter(move |r| r.family == family)
}
