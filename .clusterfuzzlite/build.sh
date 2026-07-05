#!/usr/bin/env bash
set -euo pipefail

ROOT="${SRC:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$ROOT"

: "${OUT:=$ROOT/out}"
mkdir -p "$OUT"

if [[ -n "${LIB_FUZZING_ENGINE:-}" && -f "${LIB_FUZZING_ENGINE}" ]]; then
  FUZZ_ENGINE="${LIB_FUZZING_ENGINE}"
elif [[ -f /usr/lib/libFuzzingEngine.a ]]; then
  FUZZ_ENGINE="/usr/lib/libFuzzingEngine.a"
else
  echo "missing libFuzzer engine archive" >&2
  exit 1
fi

export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$ROOT/fuzz/target"
if command -v "${CXX:-clang++}" >/dev/null 2>&1; then
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="${CXX:-clang++}"
fi
if [[ "${SANITIZER:-address}" == "address" ]] && rustc -Z help >/dev/null 2>&1 && [[ "${RUSTFLAGS:-}" != *"sanitizer=address"* ]]; then
  export RUSTFLAGS="${RUSTFLAGS:-} -Zsanitizer=address -Cpanic=abort"
fi

targets=(stream_fuzzer frame_fuzzer bundle_fuzzer script_fuzzer journal_fuzzer)
for target in "${targets[@]}"; do
  cargo rustc --manifest-path "$ROOT/fuzz/Cargo.toml" --locked --offline --release --bin "$target" -- -C "link-arg=${FUZZ_ENGINE}"
  built="$CARGO_TARGET_DIR/release/$target"
  [[ -f "$built" ]] || { echo "missing built target $target" >&2; exit 1; }
  cp "$built" "$OUT/$target"
done

for target in "${targets[@]}"; do
  corpus="$ROOT/fuzz/corpus/$target"
  if [[ -d "$corpus" ]] && command -v zip >/dev/null 2>&1; then
    (cd "$corpus" && zip -q -r "$OUT/${target}_seed_corpus.zip" .)
  fi
  [[ -f "$ROOT/fuzz/dictionary.txt" ]] && cp "$ROOT/fuzz/dictionary.txt" "$OUT/${target}.dict"
done
