#ifndef VULNDETECT_PASS_H
#define VULNDETECT_PASS_H

#include "llvm/IR/PassManager.h"

namespace vuln {

class VulnDetectPass : public llvm::PassInfoMixin<VulnDetectPass> {
public:
  llvm::PreservedAnalyses run(llvm::Function &F,
                              llvm::FunctionAnalysisManager &FAM);

  static bool isRequired() { return true; }
};

} // namespace vuln

#endif
