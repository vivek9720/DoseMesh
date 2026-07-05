#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = dosemesh::replay_journal(data);
});
