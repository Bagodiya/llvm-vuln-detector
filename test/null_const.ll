; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s
; CHECK: [CWE-476] null dereference

define void @nc() {
  store i32 1, ptr null
  ret void
}
