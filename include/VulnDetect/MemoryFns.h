#ifndef VULNDETECT_MEMORYFNS_H
#define VULNDETECT_MEMORYFNS_H

#include "llvm/ADT/StringRef.h"

namespace llvm {
class CallBase;
class Value;
class TargetLibraryInfo;
} // namespace llvm

namespace vuln {

struct AllocInfo {
  bool IsAlloc = false;
  bool MayReturnNull = false;
  llvm::StringRef Name;
};

// Recognizes the heap allocators (malloc/calloc/realloc/operator new and
// friends). Works on both attributed Clang output and bare declarations by
// falling back to the library-function name, which the attribute-only helpers
// in MemoryBuiltins no longer cover for plain C free/malloc.
AllocInfo classifyAlloc(const llvm::CallBase *CB,
                        const llvm::TargetLibraryInfo &TLI);

// The pointer released by a free/delete call, or null if the call frees
// nothing.
llvm::Value *freedPointer(const llvm::CallBase *CB,
                          const llvm::TargetLibraryInfo &TLI);

} // namespace vuln

#endif
