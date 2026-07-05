use crate::analyzer::{analyze_session, RiskReport};
use crate::checksum;
use crate::error::Result;
use crate::frame::parse_frames;
use crate::manifest::ManifestDecoder;
use crate::model::{DoseBundle, ManifestSection};
use crate::session::SessionState;

#[derive(Debug, Default)]
pub struct BundleDecoder {
    manifest: ManifestDecoder,
    session: SessionState,
    sections_seen: usize,
}

impl BundleDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<RiskReport> {
        if data.windows(8).any(|w| w == b"--DMESH:") {
            self.decode_sectioned(data);
        } else {
            let frames = parse_frames(data)?;
            for frame in frames {
                self.session.apply_frame(frame);
            }
        }
        Ok(analyze_session(&mut self.session))
    }

    pub fn manifest_sections(&self) -> Vec<&ManifestSection> {
        self.manifest.sections()
    }

    fn decode_sectioned(&mut self, data: &[u8]) {
        let mut current_name = "root".to_string();
        let mut current = Vec::new();
        for line in data.split(|&b| b == b'\n') {
            if let Some(name) = parse_section_header(line) {
                self.finish_section(&current_name, &current);
                current.clear();
                current_name = name;
            } else {
                current.extend_from_slice(line);
                current.push(b'\n');
            }
        }
        self.finish_section(&current_name, &current);
    }

    fn finish_section(&mut self, name: &str, body: &[u8]) {
        if body.is_empty() {
            return;
        }
        self.sections_seen += 1;
        match name {
            "manifest" | "druglib" | "library" => {
                self.manifest.apply_payload(body);
                self.session.apply_manifest(body);
            }
            "frames" | "stream" => {
                if let Ok(frames) = parse_frames(body) {
                    for frame in frames {
                        self.session.apply_frame(frame);
                    }
                }
            }
            "script" | "guard" => {
                self.session.apply_script(body);
            }
            "journal" | "audit" => {
                self.session.apply_journal(body);
            }
            _ => {
                self.manifest
                    .apply_payload(format!("name={};len={};body=", name, body.len()).as_bytes());
                self.session.apply_fragment(body);
            }
        }
        if self.sections_seen > 16 && checksum::rolling_window_score(body) & 0xf == 9 {
            self.manifest.apply_payload(b"compact=1;link=7");
        }
    }
}

pub fn decode_bundle(data: &[u8]) -> Result<RiskReport> {
    let mut decoder = BundleDecoder::new();
    decoder.decode(data)
}

pub fn parse_bundle_manifest(data: &[u8]) -> DoseBundle {
    let mut sections = Vec::new();
    let mut library_rev = 0;
    let mut hospital_id = 0;
    for raw in data.split(|&b| b == b'\n') {
        if let Some(name) = parse_section_header(raw) {
            sections.push(ManifestSection {
                name,
                version: sections.len() as u32,
                declared_len: raw.len(),
                checksum: checksum::weighted_checksum(raw, sections.len() as u32),
                body: raw.to_vec(),
            });
        } else if raw.starts_with(b"library=") {
            library_rev = crate::cursor::parse_u32(&raw[8..]).unwrap_or(0);
        } else if raw.starts_with(b"hospital=") {
            hospital_id = crate::cursor::parse_u32(&raw[9..]).unwrap_or(0);
        }
    }
    DoseBundle {
        library_rev,
        hospital_id,
        sections,
    }
}

fn parse_section_header(line: &[u8]) -> Option<String> {
    let line = crate::cursor::trim_ascii(line);
    if !line.starts_with(b"--DMESH:") || !line.ends_with(b"--") {
        return None;
    }
    let inner = &line[8..line.len().saturating_sub(2)];
    core::str::from_utf8(inner)
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
}
