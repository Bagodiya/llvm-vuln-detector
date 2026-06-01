#!/usr/bin/env bash
# Compile a C/C++ source to IR and run the detector on it.
#   tools/run-on.sh path/to/file.c [extra clang flags...]
# opt is taken from $LLVM_BIN/llvm-config/PATH; the compiler from $CLANG or PATH.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"

if [ $# -lt 1 ]; then
  echo "usage: $0 source.c [clang flags...]" >&2
  exit 2
fi
src="$1"; shift

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
  echo "plugin not built; configure and build in ./build first" >&2
  exit 1
fi

"$clang" -g -O0 -S -emit-llvm "${isys[@]}" "$src" "$@" -o - |
  "$opt" -load-pass-plugin="$plugin" -passes=vuln-detect -disable-output
