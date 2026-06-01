; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s --allow-empty
; CHECK-NOT: CWE-476

define void @sb(ptr %p) {
entry:
  %c = icmp eq ptr %p, null
  br i1 %c, label %then, label %else

then:
  ret void

else:
  store i32 0, ptr %p
  ret void
}
