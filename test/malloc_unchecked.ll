; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s
; CHECK: [CWE-476] possible null dereference of value returned by 'malloc'

define i32 @mu() {
  %p = call ptr @malloc(i64 64)
  %v = load i32, ptr %p
  ret i32 %v
}

declare ptr @malloc(i64)
