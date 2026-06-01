#ifndef VULNDETECT_POINTERLOC_H
#define VULNDETECT_POINTERLOC_H

#include "llvm/ADT/SmallVector.h"

namespace llvm {
class Value;
class Instruction;
} // namespace llvm

namespace vuln {

// Canonical abstract location for a pointer value. Looks through GEPs and no-op
// casts via getUnderlyingObject, and folds a load from an alloca slot back to
// the slot so state survives the store/load round-trip emitted at -O0.
const llvm::Value *canonicalLoc(const llvm::Value *V);

// The pointer operands that an instruction actually dereferences: loads,
// stores, atomics and the mem* intrinsics. Address arithmetic (GEP/casts)
// returns nothing here.
void collectDerefs(const llvm::Instruction *I,
                   llvm::SmallVectorImpl<const llvm::Value *> &Out);

// The alloca slot written by a store, or null when the destination is not a
// stack slot. Used to propagate a stored pointer's state onto the slot.
const llvm::Value *storeSlot(const llvm::Instruction *I);

} // namespace vuln

#endif
