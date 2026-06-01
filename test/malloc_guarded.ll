; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s --allow-empty
; CHECK-NOT: CWE-476

define i32 @mg() {
entry:
  %p = call ptr @malloc(i64 64)
  %c = icmp eq ptr %p, null
  br i1 %c, label %bail, label %ok

bail:
  ret i32 -1

ok:
  %v = load i32, ptr %p
  ret i32 %v
}

declare ptr @malloc(i64)
