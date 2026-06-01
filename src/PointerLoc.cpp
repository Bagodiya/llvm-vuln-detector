#include "VulnDetect/PointerLoc.h"

#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"

using namespace llvm;

namespace vuln {

const Value *canonicalLoc(const Value *V) {
  const Value *Base = getUnderlyingObject(V);
  if (const auto *LI = dyn_cast<LoadInst>(Base)) {
    const Value *Slot = getUnderlyingObject(LI->getPointerOperand());
    if (isa<AllocaInst>(Slot))
      return Slot;
  }
  return Base;
}

void collectDerefs(const Instruction *I,
                   SmallVectorImpl<const Value *> &Out) {
  if (const auto *LI = dyn_cast<LoadInst>(I)) {
    Out.push_back(LI->getPointerOperand());
    return;
  }
  if (const auto *SI = dyn_cast<StoreInst>(I)) {
    Out.push_back(SI->getPointerOperand());
    return;
  }
  if (const auto *RMW = dyn_cast<AtomicRMWInst>(I)) {
    Out.push_back(RMW->getPointerOperand());
    return;
  }
  if (const auto *CX = dyn_cast<AtomicCmpXchgInst>(I)) {
    Out.push_back(CX->getPointerOperand());
    return;
  }
  if (const auto *MT = dyn_cast<MemTransferInst>(I)) {
    Out.push_back(MT->getRawDest());
    Out.push_back(MT->getRawSource());
    return;
  }
  if (const auto *MS = dyn_cast<MemSetInst>(I)) {
    Out.push_back(MS->getRawDest());
    return;
  }
}

const Value *storeSlot(const Instruction *I) {
  const auto *SI = dyn_cast<StoreInst>(I);
  if (!SI || !SI->getValueOperand()->getType()->isPointerTy())
    return nullptr;
  const Value *Slot = getUnderlyingObject(SI->getPointerOperand());
  return isa<AllocaInst>(Slot) ? Slot : nullptr;
}

} // namespace vuln
