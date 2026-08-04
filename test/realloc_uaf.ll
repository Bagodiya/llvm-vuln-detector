; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s
; realloc releases the block it is handed, so the old pointer is stale after the
; call. It is only *possibly* freed: realloc returns null on failure and leaves
; the old block valid.
; CHECK: [CWE-416] possible use-after-free of 'p'

define void @realloc_uaf() {
  %p = call ptr @malloc(i64 8)
  %q = call ptr @realloc(ptr %p, i64 16)
  store i8 0, ptr %p
  ret void
}

declare ptr @malloc(i64)
declare ptr @realloc(ptr, i64)
