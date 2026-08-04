; RUN: %opt %loadvd -passes=vuln-detect -disable-output %s 2>&1 | %FileCheck %s --allow-empty
; Reading the pointer variable back out of its stack slot after a free is not a
; dereference of the freed block. This is the shape clang emits at -O0 for
;   int *p = malloc(4); free(p); return p == NULL;
; CHECK-NOT: CWE-416

define i32 @read_after_free() {
entry:
  %slot = alloca ptr
  %p = call ptr @malloc(i64 8)
  store ptr %p, ptr %slot
  %l1 = load ptr, ptr %slot
  call void @free(ptr %l1)
  %l2 = load ptr, ptr %slot
  %c = icmp eq ptr %l2, null
  %r = zext i1 %c to i32
  ret i32 %r
}

declare ptr @malloc(i64)
declare void @free(ptr)
