#include "VulnDetect/Checkers.h"
#include "VulnDetect/Dataflow.h"
#include "VulnDetect/Diagnostics.h"
#include "VulnDetect/MemoryFns.h"
#include "VulnDetect/PointerLoc.h"

#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

using vuln::canonicalLoc;
using vuln::classifyAlloc;
using vuln::collectDerefs;
using vuln::DiagEngine;
using vuln::freedPointer;
using vuln::FreeState;
using vuln::Options;
using vuln::Severity;
using State = vuln::StateMap<FreeState>;

std::string label(const Value *V) {
  if (V->hasName())
    return ("'" + V->getName() + "'").str();
  std::string S;
  raw_string_ostream OS(S);
  V->printAsOperand(OS, false);
  return OS.str();
}

class FreeChecker {
public:
  FreeChecker(Function &F, const TargetLibraryInfo &TLI, DiagEngine &Diag,
              const Options &Opts)
      : F(F), TLI(TLI), Diag(Diag), Opts(Opts) {}

  void run() {
    auto Transfer = [this](BasicBlock &BB, const State &In) {
      return step(BB, In, /*report=*/false);
    };
    auto Refine = [](BasicBlock *, BasicBlock *, const State &S) { return S; };

    vuln::ForwardSolver<FreeState> Solver(Transfer, Refine);
    auto InStates = Solver.solve(F, State());

    for (BasicBlock &BB : F)
      step(BB, InStates[&BB], /*report=*/true);
  }

private:
  State step(BasicBlock &BB, const State &In, bool Report) {
    State S = In;
    for (Instruction &I : BB) {
      if (auto *PN = dyn_cast<PHINode>(&I)) {
        if (PN->getType()->isPointerTy())
          S.set(canonicalLoc(PN), joinIncoming(PN, S));
        continue;
      }
      if (auto *CB = dyn_cast<CallBase>(&I)) {
        if (Value *Freed = freedPointer(CB, TLI)) {
          handleFree(Freed, &I, S, Report);
          continue;
        }
        if (Value *Old = vuln::reallocatedPointer(CB)) {
          handleRealloc(Old, CB, S, Report);
          continue;
        }
        if (classifyAlloc(CB, TLI).IsAlloc) {
          S.set(canonicalLoc(CB), FreeState::Allocated);
          continue;
        }
        if (Opts.Paranoid)
          for (Value *Arg : CB->args())
            if (Arg->getType()->isPointerTy())
              taint(canonicalLoc(Arg), S);
      }

      SmallVector<const Value *, 2> Derefs;
      collectDerefs(&I, Derefs);
      for (const Value *Q : Derefs) {
        // Skip slot and global addresses. canonicalLoc folds a load-from-slot
        // onto the slot, so that key tracks the heap object stored in the slot
        // — not the slot's own address, which is stack memory and is never the
        // thing being freed. Reading the pointer variable back out of the slot
        // after a free is not itself a use-after-free.
        const Value *Obj = getUnderlyingObject(Q);
        if (isa<AllocaInst>(Obj) || isa<GlobalValue>(Obj))
          continue;
        checkUse(Q, &I, S, Report);
      }

      if (const Value *Slot = vuln::storeSlot(&I)) {
        auto *SI = cast<StoreInst>(&I);
        S.set(Slot, S.get(canonicalLoc(SI->getValueOperand())));
      }
    }
    return S;
  }

  void handleFree(Value *Freed, Instruction *I, State &S, bool Report) {
    const Value *L = canonicalLoc(Freed);
    FreeState St = S.get(L);
    if (Report) {
      if (St == FreeState::Freed)
        Diag.report(Severity::High, "CWE-415", "double-free of " + label(Freed),
                    I);
      else if (St == FreeState::MaybeFreed)
        Diag.report(Severity::Medium, "CWE-415",
                    "possible double-free of " + label(Freed), I);
    }
    S.set(L, FreeState::Freed);
  }

  // realloc both releases its argument and returns a new block, so it is
  // neither a plain free nor a plain allocation.
  void handleRealloc(Value *Old, CallBase *CB, State &S, bool Report) {
    const Value *L = canonicalLoc(Old);
    FreeState St = S.get(L);
    if (Report) {
      if (St == FreeState::Freed)
        Diag.report(Severity::High, "CWE-416",
                    "realloc of already-freed " + label(Old), CB);
      else if (St == FreeState::MaybeFreed)
        Diag.report(Severity::Medium, "CWE-416",
                    "possible realloc of already-freed " + label(Old), CB);
    }
    // On failure realloc returns null and leaves the old block valid, so the
    // old pointer is only possibly freed afterwards. Recording it as certainly
    // freed would report the standard recovery path — q = realloc(p, n); if
    // (!q) { free(p); ... } — as a double-free.
    S.set(L, FreeState::MaybeFreed);
    S.set(canonicalLoc(CB), FreeState::Allocated);
  }

  void checkUse(const Value *Q, Instruction *I, State &S, bool Report) {
    FreeState St = S.get(canonicalLoc(Q));
    if (!Report)
      return;
    if (St == FreeState::Freed)
      Diag.report(Severity::High, "CWE-416", "use-after-free of " + label(Q),
                  I);
    else if (St == FreeState::MaybeFreed)
      Diag.report(Severity::Medium, "CWE-416",
                  "possible use-after-free of " + label(Q), I);
  }

  FreeState joinIncoming(PHINode *PN, const State &S) {
    FreeState St = FreeState::Unknown;
    bool First = true;
    for (Value *Inc : PN->incoming_values()) {
      FreeState Cur = S.get(canonicalLoc(Inc));
      St = First ? Cur : vuln::meet(St, Cur);
      First = false;
    }
    return St;
  }

  void taint(const Value *L, State &S) {
    FreeState St = S.get(L);
    if (St == FreeState::Allocated || St == FreeState::Unknown)
      S.set(L, FreeState::MaybeFreed);
  }

  Function &F;
  const TargetLibraryInfo &TLI;
  DiagEngine &Diag;
  const Options &Opts;
};

} // namespace

namespace vuln {

void runFreeChecker(Function &F, const TargetLibraryInfo &TLI, DiagEngine &Diag,
                    const Options &Opts) {
  FreeChecker(F, TLI, Diag, Opts).run();
}

} // namespace vuln
