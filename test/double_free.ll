; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s
; CHECK: [CWE-415] double-free of 'p'

define void @df() {
  %p = call ptr @malloc(i64 8)
  call void @free(ptr %p)
  call void @free(ptr %p)
  ret void
}

declare ptr @malloc(i64)
declare void @free(ptr)
