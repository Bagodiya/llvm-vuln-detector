; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s
; CHECK: [CWE-416] use-after-free of 'p'

define void @uaf() {
  %p = call ptr @malloc(i64 8)
  call void @free(ptr %p)
  store i8 0, ptr %p
  ret void
}

declare ptr @malloc(i64)
declare void @free(ptr)
