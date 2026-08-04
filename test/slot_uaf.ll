; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s
; The companion to slot_read_after_free.ll: dereferencing the value loaded out
; of the slot must still be caught.
; CHECK: [CWE-416] use-after-free of 'l2'

define void @slot_uaf() {
entry:
  %slot = alloca ptr
  %p = call ptr @malloc(i64 8)
  store ptr %p, ptr %slot
  %l1 = load ptr, ptr %slot
  call void @free(ptr %l1)
  %l2 = load ptr, ptr %slot
  store i8 0, ptr %l2
  ret void
}

declare ptr @malloc(i64)
declare void @free(ptr)
