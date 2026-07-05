//! DoseMesh decodes offline infusion-pump bundles, frames, scripts, and audit journals.
//!
//! The crate deliberately avoids external dependencies. The fuzz harnesses exercise the
//! public entry points below and then drive the decoded state through cross-module
//! reconciliation paths.

pub mod analyzer;
pub mod arena;
pub mod bundle;
pub mod catalog;
pub mod checksum;
pub mod codec;
pub mod cursor;
pub mod dictionary;
pub mod error;
pub mod fragment;
pub mod frame;
pub mod journal;
pub mod manifest;
pub mod model;
pub mod order;
pub mod pump;
pub mod script;
pub mod session;
pub mod stream;

pub use analyzer::{analyze_session, RiskReport};
pub use bundle::{decode_bundle, BundleDecoder};
pub use error::{DecodeError, ErrorKind, Result};
pub use frame::{parse_frame, parse_frames};
pub use journal::replay_journal;
pub use script::run_script;
pub use session::{decode_stream, SessionState};

pub fn parse(data: &[u8]) -> Result<SessionState> {
    decode_stream(data)
}

pub fn parse_one(data: &[u8]) -> Result<model::Frame> {
    parse_frame(data)
}
