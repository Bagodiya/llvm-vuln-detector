#ifndef VULNDETECT_CHECKERS_H
#define VULNDETECT_CHECKERS_H

namespace llvm {
class Function;
class TargetLibraryInfo;
} // namespace llvm

namespace vuln {

class DiagEngine;

struct Options {
  bool Paranoid = false;
};

// Use-after-free and double-free detection over the free-state lattice.
void runFreeChecker(llvm::Function &F, const llvm::TargetLibraryInfo &TLI,
                    DiagEngine &Diag, const Options &Opts);

// Null-dereference detection over the null-state lattice, including unchecked
// allocation results and guard-edge sensitivity.
void runNullChecker(llvm::Function &F, const llvm::TargetLibraryInfo &TLI,
                    DiagEngine &Diag, const Options &Opts);

} // namespace vuln

#endif
