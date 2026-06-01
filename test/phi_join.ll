; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s
; CHECK: [CWE-416] possible use-after-free of 'p'

define void @pj(i1 %cond) {
entry:
  %p = call ptr @malloc(i64 8)
  br i1 %cond, label %a, label %b

a:
  call void @free(ptr %p)
  br label %join

b:
  br label %join

join:
  store i8 0, ptr %p
  ret void
}

declare ptr @malloc(i64)
declare void @free(ptr)
