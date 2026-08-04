; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s --allow-empty
; The standard recovery path frees the old block when realloc fails. Because
; the analysis cannot tell the failure path from the success path, it downgrades
; the post-realloc state to MaybeFreed: this is reported as a possibility at
; most, never as a certain double-free.
; CHECK-NOT: error:

define ptr @realloc_recovery(ptr %p, i64 %n) {
entry:
  %q = call ptr @realloc(ptr %p, i64 %n)
  %c = icmp eq ptr %q, null
  br i1 %c, label %fail, label %ok

fail:
  call void @free(ptr %p)
  ret ptr null

ok:
  ret ptr %q
}

declare ptr @realloc(ptr, i64)
declare void @free(ptr)
