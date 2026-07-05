#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = dosemesh::parse_frame(data) {
        let mut session = dosemesh::SessionState::new();
        session.apply_frame(frame);
        let _ = session.finalize();
    }
});
