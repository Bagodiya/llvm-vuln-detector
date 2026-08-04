#include "VulnDetect/MemoryFns.h"

#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"

using namespace llvm;

namespace vuln {

static StringRef calleeName(const CallBase *CB) {
  const Function *F = CB->getCalledFunction();
  return F ? F->getName() : StringRef();
}

static bool isFreeName(StringRef N) {
  if (N == "free" || N == "cfree")
    return true;
  // operator delete / operator delete[] and their sized/aligned overloads.
  return N.starts_with("_Zdl") || N.starts_with("_Zda");
}

static bool isNonNullAllocName(StringRef N) {
  // operator new / operator new[] report failure by throwing, not by null.
  return N.starts_with("_Znw") || N.starts_with("_Zna");
}

static bool isReallocName(StringRef N) {
  return N == "realloc" || N == "reallocf" || N == "reallocarray";
}

static bool isNullableAllocName(StringRef N) {
  return N == "malloc" || N == "calloc" || N == "aligned_alloc" ||
         N == "valloc" || N == "memalign" || N == "strdup" ||
         N == "strndup" || isReallocName(N);
}

AllocInfo classifyAlloc(const CallBase *CB, const TargetLibraryInfo &TLI) {
  AllocInfo Info;
  StringRef Name = calleeName(CB);

  bool Known = isNullableAllocName(Name) || isNonNullAllocName(Name);
  if (!Known && !isAllocationFn(CB, &TLI))
    return Info;
  if (isFreeName(Name))
    return Info;

  Info.IsAlloc = true;
  Info.Name = Name;
  Info.MayReturnNull = !isNonNullAllocName(Name) &&
                       !CB->hasRetAttr(Attribute::NonNull);
  return Info;
}

Value *freedPointer(const CallBase *CB, const TargetLibraryInfo &TLI) {
  if (Value *P = getFreedOperand(CB, &TLI))
    return P;
  if (isFreeName(calleeName(CB)) && CB->arg_size() >= 1)
    return CB->getArgOperand(0);
  return nullptr;
}

Value *reallocatedPointer(const CallBase *CB) {
  // The attribute-based helper only fires on allockind("realloc") declarations,
  // which hand-written IR and older headers do not carry; fall back to the name.
  if (Value *P = getReallocatedOperand(CB))
    return P;
  if (isReallocName(calleeName(CB)) && CB->arg_size() >= 1)
    return CB->getArgOperand(0);
  return nullptr;
}

} // namespace vuln
