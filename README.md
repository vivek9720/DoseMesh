# DoseMesh

DoseMesh is an offline Rust decoder for hospital infusion-pump traffic: drug library bundles, dose orders, pump telemetry, fragment reassembly, bedside scripts, and audit journals.

The crate is intentionally dependency-free so it can be built in hermetic fuzzing environments. Fuzz harnesses live under `fuzz/`, and `.clusterfuzzlite/build.sh` builds every target into `$OUT` without fetching anything from the network.

The input formats are structured but forgiving:

- `DMF|kind|seq|flags|payload` text frames
- `DMB1` binary frames with length and checksum fields
- multi-section bundles separated by `--DMESH:<section>--`
- compact bedside scripts with arithmetic, table lookup, and history-window operations

The code models real workflow pressure points in infusion networks: pump libraries are updated out-of-band, fragments can arrive late, clinical order revisions are replayed from journals, and bedside pumps keep short-lived caches for speed.
