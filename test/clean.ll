; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s --allow-empty
; CHECK-NOT: CWE-

define i32 @clean(ptr nonnull %p) {
  %v = load i32, ptr %p
  %w = add i32 %v, 1
  ret i32 %w
}
