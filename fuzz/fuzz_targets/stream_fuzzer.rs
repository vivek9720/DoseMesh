#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(mut session) = dosemesh::decode_stream(data) {
        let _ = session.finalize();
    }
});
