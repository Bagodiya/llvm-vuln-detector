; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s --allow-empty
; CHECK-NOT: use-after-free
; CHECK-NOT: CWE-415

define void @ra() {
  %p = call ptr @malloc(i64 8)
  call void @free(ptr %p)
  %p2 = call ptr @malloc(i64 8)
  call void @free(ptr %p2)
  ret void
}

declare ptr @malloc(i64)
declare void @free(ptr)
