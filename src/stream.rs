use crate::analyzer::RiskReport;
use crate::error::Result;
use crate::session::SessionState;

pub fn decode_stream(data: &[u8]) -> Result<SessionState> {
    crate::session::decode_stream(data)
}

pub fn decode_and_analyze(data: &[u8]) -> Result<RiskReport> {
    let mut session = decode_stream(data)?;
    Ok(session.finalize())
}
