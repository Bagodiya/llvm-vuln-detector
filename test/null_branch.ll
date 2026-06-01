; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s
; CHECK: [CWE-476] null dereference of 'p'

define void @nb(ptr %p) {
entry:
  %c = icmp eq ptr %p, null
  br i1 %c, label %then, label %else

then:
  store i32 0, ptr %p
  ret void

else:
  ret void
}
