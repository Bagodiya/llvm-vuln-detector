#ifndef VULNDETECT_DATAFLOW_H
#define VULNDETECT_DATAFLOW_H

#include "VulnDetect/Lattices.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Value.h"

#include <functional>
#include <vector>

namespace vuln {

// A map from abstract locations to lattice elements. Absent keys read back as
// Unknown, so a location the analysis has never touched joins the same way
// whether it is missing from one side of the meet or explicitly Unknown on
// both.
template <class Elem> class StateMap {
  llvm::DenseMap<const llvm::Value *, Elem> M;

public:
  Elem get(const llvm::Value *V) const {
    auto It = M.find(V);
    return It == M.end() ? Elem::Unknown : It->second;
  }

  void set(const llvm::Value *V, Elem E) {
    if (E == Elem::Unknown)
      M.erase(V);
    else
      M[V] = E;
  }

  bool operator==(const StateMap &O) const {
    if (M.size() != O.M.size())
      return false;
    for (const auto &KV : M) {
      auto It = O.M.find(KV.first);
      if (It == O.M.end() || It->second != KV.second)
        return false;
    }
    return true;
  }
  bool operator!=(const StateMap &O) const { return !(*this == O); }

  static StateMap join(const StateMap &A, const StateMap &B) {
    StateMap R;
    for (const auto &KV : A.M)
      R.set(KV.first, vuln::meet(KV.second, B.get(KV.first)));
    for (const auto &KV : B.M)
      if (A.M.find(KV.first) == A.M.end())
        R.set(KV.first, vuln::meet(KV.second, A.get(KV.first)));
    return R;
  }
};

// Generic forward, flow-sensitive worklist solver. Instantiated once per
// analysis with its own lattice element type. The transfer function never
// reports during solving; callers do a separate stabilized walk for that.
template <class Elem> class ForwardSolver {
public:
  using State = StateMap<Elem>;
  using TransferFn = std::function<State(llvm::BasicBlock &, const State &)>;
  using RefineFn =
      std::function<State(llvm::BasicBlock *, llvm::BasicBlock *, const State &)>;

  ForwardSolver(TransferFn Transfer, RefineFn Refine)
      : Transfer(std::move(Transfer)), Refine(std::move(Refine)) {}

  llvm::DenseMap<llvm::BasicBlock *, State> solve(llvm::Function &F,
                                                  const State &Entry) {
    llvm::DenseMap<llvm::BasicBlock *, State> In, Out;
    llvm::DenseMap<llvm::BasicBlock *, bool> Computed;
    std::vector<llvm::BasicBlock *> Work;

    llvm::BasicBlock &EntryBB = F.getEntryBlock();
    In[&EntryBB] = Entry;
    Work.push_back(&EntryBB);

    const unsigned Cap = (F.size() + 1) * (F.size() + 1) + 64;
    unsigned Steps = 0;

    while (!Work.empty() && Steps++ < Cap) {
      llvm::BasicBlock *BB = Work.back();
      Work.pop_back();

      State InState;
      if (BB == &EntryBB) {
        InState = Entry;
      } else {
        bool First = true;
        for (llvm::BasicBlock *Pred : llvm::predecessors(BB)) {
          if (!Computed.lookup(Pred))
            continue;
          State Edge = Refine(Pred, BB, Out[Pred]);
          InState = First ? Edge : State::join(InState, Edge);
          First = false;
        }
      }
      In[BB] = InState;

      State OutState = Transfer(*BB, InState);
      bool Changed = !Computed.lookup(BB) || OutState != Out[BB];
      Out[BB] = OutState;
      Computed[BB] = true;

      if (Changed)
        for (llvm::BasicBlock *Succ : llvm::successors(BB))
          Work.push_back(Succ);
    }
    return In;
  }

private:
  TransferFn Transfer;
  RefineFn Refine;
};

} // namespace vuln

#endif
