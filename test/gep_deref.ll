; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s
; CHECK: [CWE-416] use-after-free of 'q'

define void @gep() {
  %p = call ptr @malloc(i64 32)
  call void @free(ptr %p)
  %q = getelementptr i8, ptr %p, i64 4
  store i8 0, ptr %q
  ret void
}

declare ptr @malloc(i64)
declare void @free(ptr)
