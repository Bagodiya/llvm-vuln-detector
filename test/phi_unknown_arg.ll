; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s --allow-empty
; Merging a stack address (NonNull) with an unconstrained argument (Unknown)
; must not manufacture a MaybeNull. Dereferencing %a on its own is not reported,
; so routing it through a phi should not be either.
; CHECK-NOT: CWE-476

define void @phi_unknown_arg(ptr %a, i1 %c) {
entry:
  %s = alloca i32
  br i1 %c, label %t, label %f

t:
  br label %j

f:
  br label %j

j:
  %p = phi ptr [ %s, %t ], [ %a, %f ]
  store i32 0, ptr %p
  ret void
}
