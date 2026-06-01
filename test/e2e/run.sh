#!/usr/bin/env bash
# Compile the C sources to IR and check that the plugin flags the expected
# patterns. opt comes from $LLVM_BIN/llvm-config/PATH; the compiler from $CLANG
# or PATH (it needs the system headers, so the freshly built in-tree clang is
# usually not the right choice unless a sysroot is available).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

bindir="${LLVM_BIN:-$(llvm-config --bindir 2>/dev/null || true)}"
opt="${OPT:-${bindir:+$bindir/}opt}"
command -v "$opt" >/dev/null 2>&1 || opt=opt
clang="${CLANG:-clang}"

isys=()
if sdk="$(xcrun --show-sdk-path 2>/dev/null)"; then
  isys=(-isysroot "$sdk")
fi

plugin="$(ls "$root"/build/libVulnDetect.* 2>/dev/null | head -n1 || true)"
if [ -z "$plugin" ]; then
  echo "plugin not built; build it in ./build first" >&2
  exit 1
fi

run() {
  "$clang" -g -O0 -S -emit-llvm "${isys[@]}" "$1" -o - |
    "$opt" -load-pass-plugin="$plugin" -passes=vuln-detect -disable-output 2>&1
}

fail=0
expect() {
  local file="$1" pattern="$2" out
  out="$(run "$here/$file")"
  if printf '%s\n' "$out" | grep -q "$pattern"; then
    echo "ok    $file: $pattern"
  else
    echo "FAIL  $file: expected $pattern"
    fail=1
  fi
}

expect uaf.c "CWE-416"
expect null.c "CWE-476"

exit $fail
