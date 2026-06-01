# llvm-vuln-detector

An out-of-tree LLVM analysis pass that statically scans LLVM IR for two classes
of memory-safety bug:

- **Use-after-free** (CWE-416), including **double-free** (CWE-415)
- **Null-pointer dereference** (CWE-476)

It runs a forward, flow-sensitive, intraprocedural dataflow analysis over each
function's control-flow graph and reports the offending instruction with a CWE
id, a severity, and a source location when debug info is present. The pass never
modifies the IR — it returns `PreservedAnalyses::all()`.

This is a bug finder, not a verifier: it favours precision on the patterns below
but can miss bugs (false negatives) and, on code it can't reason about
precisely, over-report (false positives, reported at lower severity). It
complements runtime sanitizers like ASan/MSan, which find bugs on executed paths
at runtime; this finds candidate bugs statically on all paths.

## Supported patterns

| Pattern | CWE | Severity | Example |
|---|---|---|---|
| Use-after-free | 416 | error | `free(p); *p = 0;` |
| Double-free | 415 | error | `free(p); free(p);` |
| Null deref of a known-null value | 476 | error | `store i32 1, ptr null` |
| Deref on the null branch of a guard | 476 | error | `if (p == NULL) { *p = 0; }` |
| Deref of an unchecked allocation result | 476 | warning | `p = malloc(n); *p = 0;` |
| Use-after-free joined from one path | 416 | warning | freed on one predecessor only |

`error` findings are reported on a path where the bad state is certain. `warning`
findings hold on at least one incoming path (the join of states) or come from an
allocation that may return null without an intervening guard. Filter the warnings
with `-vuln-min-severity=high`.

## How it works

Two analyses share one generic worklist engine (`include/VulnDetect/Dataflow.h`),
each with its own lattice:

- **Free state** — `Unknown / Allocated / Freed / MaybeFreed`
- **Null state** — `Unknown / NonNull / Null / MaybeNull`

The `meet` at CFG joins is danger-sticky: `meet(Freed, Allocated) = MaybeFreed`
and `meet(Null, NonNull) = MaybeNull`, so a bug on one predecessor is never
silently lost. The null analysis also refines state along guard edges: after
`%c = icmp eq ptr %p, null ; br i1 %c, %t, %e`, `%p` is `Null` on the `%t` edge
and `NonNull` on the `%e` edge. That edge refinement is what keeps correctly
guarded allocations from being flagged.

State is keyed by an abstract location (`getUnderlyingObject`, with a load from
an alloca slot folded back to the slot) so that GEPs, no-op casts, and the
store/load round-trip emitted at `-O0` all resolve to the same object. Only
`load`, `store`, atomics, and the `llvm.mem*` intrinsics count as dereferences;
address arithmetic does not.

## Building

The plugin must be built against the same LLVM you run it with, using the same
`-fno-rtti` and C++ standard settings, or it will fail to load. Start by checking
your LLVM:

```sh
llvm-config --version
```

Then configure and build:

```sh
cmake -G Ninja -B build -DLLVM_DIR="$(llvm-config --cmakedir)"
cmake --build build
```

This produces `build/libVulnDetect.so` (`.dylib` on some setups). The plugin API
used here is stable across LLVM 18–23.

## Running

On IR with `opt`:

```sh
opt -load-pass-plugin=./build/libVulnDetect.so \
    -passes=vuln-detect -disable-output input.ll
```

During compilation with `clang` (the plugin must be built against this clang's
LLVM):

```sh
clang -g -O0 -fpass-plugin=./build/libVulnDetect.so -c input.c
```

Generate IR to inspect:

```sh
clang -g -O0 -S -emit-llvm input.c -o input.ll
```

`tools/run-on.sh file.c` does the compile-then-analyze step for you.

> Compile demos at `-O0`. At `-O1` and above the optimizer can prove a small
> heap allocation has no observable effect and delete the `malloc`/`free` pair
> entirely, so the pattern is gone before the analysis sees it. The pass itself
> handles optimized SSA fine — the hand-written `.ll` fixtures are in SSA form —
> it is the C-to-IR demos where optimization erases the bug.

### Flags

- `-vuln-min-severity={high,medium}` — lowest severity to report (default `medium`)
- `-vuln-paranoid` — treat unrecognized calls as possible frees of their pointer args
- `-vuln-no-uaf` — disable the use-after-free checker
- `-vuln-no-null` — disable the null-dereference checker

### Diagnostic format

```
warning: [CWE-476] possible null dereference of value returned by 'malloc'
  at input.c:5:10   (function 'unchecked_malloc')
```

Without `-g` the source location is replaced by the IR instruction text.

## Testing

The `.ll` fixtures under `test/` carry their own `RUN`/`CHECK` lines and run
under lit + FileCheck. Positive fixtures assert a finding; negative fixtures use
`CHECK-NOT` to assert the absence of one (the guarded-allocation and safe-branch
cases are the proof that edge refinement works).

```sh
cmake --build build --target check     # if llvm-lit was found at configure time
# or directly:
llvm-lit build/test
```

End-to-end tests compile small C files and grep for the expected CWE:

```sh
test/e2e/run.sh
```

The e2e script takes `opt` from `$LLVM_BIN`, `llvm-config`, or `PATH`, and the
compiler from `$CLANG` or `PATH`.

## Limitations

- Intraprocedural only — no cross-function reasoning. A free or null that happens
  inside a callee is not tracked across the call boundary.
- Canonicalization is based on `getUnderlyingObject`; it does not consult full
  alias analysis, so distinct pointers that must-alias through memory are not
  unified.
- Unrecognized calls are assumed not to free their arguments unless
  `-vuln-paranoid` is set.
- This is a bug finder, not a sound checker. Treat findings as candidates.

## Troubleshooting

- **`unknown pass name 'vuln-detect'`** — the plugin didn't load, or the pipeline
  name doesn't match. The name is exactly `vuln-detect`.
- **Segfault or symbol errors on load** — the plugin was built against a
  different LLVM, or with different RTTI/EH/C++-standard settings than the host
  `opt`/`clang`. Rebuild against the LLVM you are loading it into.
- **No source locations** — the input wasn't compiled with `-g`.
- **Nothing is flagged on a C file at `-O1`** — the optimizer removed the
  pattern; rebuild the demo at `-O0`.

## Layout

```
include/VulnDetect/   lattices, generic dataflow engine, diagnostics, helpers
src/                  plugin registration, the pass, the two checkers
test/                 lit/FileCheck fixtures and end-to-end C cases
tools/run-on.sh       compile a source and run the detector on it
```
