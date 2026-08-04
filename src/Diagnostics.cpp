#include "VulnDetect/Diagnostics.h"

#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace vuln {

void DiagEngine::report(Severity Sev, StringRef CWE, StringRef Message,
                        const Instruction *I) {
  if (Min == Severity::High && Sev == Severity::Medium)
    return;

  const char *Label = Sev == Severity::High ? "error" : "warning";
  errs() << Label << ": [" << CWE << "] " << Message << '\n';

  const Function *F = I->getFunction();
  StringRef FnName = F ? F->getName() : "";

  if (const DILocation *Loc = I->getDebugLoc()) {
    errs() << "  at " << Loc->getFilename() << ':' << Loc->getLine() << ':'
           << Loc->getColumn() << "   (function '" << FnName << "')\n";
  } else {
    std::string IRText;
    raw_string_ostream OS(IRText);
    I->print(OS);
    errs() << "  at" << OS.str() << "   (function '" << FnName << "')\n";
  }
}

} // namespace vuln
