#include "VulnDetect/Checkers.h"
#include "VulnDetect/Dataflow.h"
#include "VulnDetect/Diagnostics.h"
#include "VulnDetect/MemoryFns.h"
#include "VulnDetect/PointerLoc.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

using vuln::AllocInfo;
using vuln::canonicalLoc;
using vuln::classifyAlloc;
using vuln::collectDerefs;
using vuln::DiagEngine;
using vuln::NullState;
using vuln::Options;
using vuln::Severity;
using State = vuln::StateMap<NullState>;

std::string label(const Value *V) {
  if (V->hasName())
    return ("'" + V->getName() + "'").str();
  std::string S;
  raw_string_ostream OS(S);
  V->printAsOperand(OS, false);
  return OS.str();
}

class NullChecker {
public:
  NullChecker(Function &F, const TargetLibraryInfo &TLI, DiagEngine &Diag)
      : F(F), TLI(TLI), Diag(Diag) {}

  void run() {
    for (Instruction &I : instructions(F))
      if (auto *CB = dyn_cast<CallBase>(&I))
        if (classifyAlloc(CB, TLI).IsAlloc)
          if (const Function *C = CB->getCalledFunction())
            AllocName[canonicalLoc(CB)] = C->getName();

    auto Transfer = [this](BasicBlock &BB, const State &In) {
      return step(BB, In, /*report=*/false);
    };
    auto Refine = [this](BasicBlock *From, BasicBlock *To, const State &S) {
      return refine(From, To, S);
    };

    vuln::ForwardSolver<NullState> Solver(Transfer, Refine);
    auto InStates = Solver.solve(F, State());

    for (BasicBlock &BB : F)
      step(BB, InStates[&BB], /*report=*/true);
  }

private:
  NullState stateOf(const State &S, const Value *V) {
    if (isa<ConstantPointerNull>(V->stripPointerCasts()))
      return NullState::Null;
    // An address rooted directly in a stack slot or global is never null. This
    // must use the plain underlying object: a heap pointer *loaded out of* a
    // slot is canonicalized to that slot for tracking, but is not the slot's
    // address.
    const Value *Obj = getUnderlyingObject(V);
    if (isa<AllocaInst>(Obj) || isa<GlobalValue>(Obj))
      return NullState::NonNull;
    if (const auto *A = dyn_cast<Argument>(Obj))
      if (A->hasNonNullAttr())
        return NullState::NonNull;
    return S.get(canonicalLoc(V));
  }

  State step(BasicBlock &BB, const State &In, bool Report) {
    State S = In;
    for (Instruction &I : BB) {
      if (auto *PN = dyn_cast<PHINode>(&I)) {
        if (PN->getType()->isPointerTy())
          S.set(canonicalLoc(PN), joinIncoming(PN, S));
        continue;
      }
      if (auto *CB = dyn_cast<CallBase>(&I)) {
        AllocInfo A = classifyAlloc(CB, TLI);
        if (A.IsAlloc) {
          S.set(canonicalLoc(CB), A.MayReturnNull ? NullState::MaybeNull
                                                  : NullState::NonNull);
          continue;
        }
      }

      SmallVector<const Value *, 2> Derefs;
      collectDerefs(&I, Derefs);
      for (const Value *Q : Derefs) {
        checkUse(Q, &I, S, Report);
        // A surviving deref proves the pointer is non-null below this point.
        // Skip slot/global addresses: that key tracks the value stored in the
        // slot, not the slot's own (always non-null) address.
        const Value *Obj = getUnderlyingObject(Q);
        if (!isa<AllocaInst>(Obj) && !isa<GlobalValue>(Obj))
          S.set(canonicalLoc(Q), NullState::NonNull);
      }

      if (const Value *Slot = vuln::storeSlot(&I)) {
        auto *SI = cast<StoreInst>(&I);
        S.set(Slot, stateOf(S, SI->getValueOperand()));
      }
    }
    return S;
  }

  void checkUse(const Value *Q, Instruction *I, const State &S, bool Report) {
    if (!Report)
      return;
    NullState St = stateOf(S, Q);
    if (St == NullState::Null) {
      Diag.report(Severity::High, "CWE-476", "null dereference of " + label(Q),
                  I);
    } else if (St == NullState::MaybeNull) {
      auto It = AllocName.find(canonicalLoc(Q));
      std::string What = It != AllocName.end()
                             ? ("value returned by '" + It->second + "'").str()
                             : label(Q);
      Diag.report(Severity::Medium, "CWE-476",
                  "possible null dereference of " + What, I);
    }
  }

  NullState joinIncoming(PHINode *PN, const State &S) {
    NullState St = NullState::Unknown;
    bool First = true;
    for (Value *Inc : PN->incoming_values()) {
      NullState Cur = stateOf(S, Inc);
      St = First ? Cur : vuln::meet(St, Cur);
      First = false;
    }
    return St;
  }

  State refine(BasicBlock *From, BasicBlock *To, const State &In) {
    State S = In;
    auto *BI = dyn_cast<BranchInst>(From->getTerminator());
    if (!BI || !BI->isConditional())
      return S;
    auto *IC = dyn_cast<ICmpInst>(BI->getCondition());
    if (!IC)
      return S;

    CmpInst::Predicate P = IC->getPredicate();
    if (P != CmpInst::ICMP_EQ && P != CmpInst::ICMP_NE)
      return S;

    Value *Op0 = IC->getOperand(0), *Op1 = IC->getOperand(1);
    Value *Ptr = nullptr;
    if (isa<ConstantPointerNull>(Op0->stripPointerCasts()))
      Ptr = Op1;
    else if (isa<ConstantPointerNull>(Op1->stripPointerCasts()))
      Ptr = Op0;
    if (!Ptr || !Ptr->getType()->isPointerTy())
      return S;

    bool IsEq = P == CmpInst::ICMP_EQ;
    NullState OnTrue = IsEq ? NullState::Null : NullState::NonNull;
    NullState OnFalse = IsEq ? NullState::NonNull : NullState::Null;

    if (To == BI->getSuccessor(0))
      S.set(canonicalLoc(Ptr), OnTrue);
    else if (To == BI->getSuccessor(1))
      S.set(canonicalLoc(Ptr), OnFalse);
    return S;
  }

  Function &F;
  const TargetLibraryInfo &TLI;
  DiagEngine &Diag;
  DenseMap<const Value *, StringRef> AllocName;
};

} // namespace

namespace vuln {

void runNullChecker(Function &F, const TargetLibraryInfo &TLI, DiagEngine &Diag,
                    const Options &) {
  NullChecker(F, TLI, Diag).run();
}

} // namespace vuln
