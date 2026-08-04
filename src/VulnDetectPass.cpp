#include "VulnDetect/Pass.h"

#include "VulnDetect/Checkers.h"
#include "VulnDetect/Diagnostics.h"

#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;

namespace {

cl::opt<vuln::Severity> MinSeverity(
    "vuln-min-severity", cl::desc("Lowest severity to report"),
    cl::values(clEnumValN(vuln::Severity::High, "high", "errors only"),
               clEnumValN(vuln::Severity::Medium, "medium",
                          "errors and warnings")),
    cl::init(vuln::Severity::Medium));

cl::opt<bool> Paranoid("vuln-paranoid",
                       cl::desc("Treat unrecognized calls as possible frees"),
                       cl::init(false));

cl::opt<bool> NoUAF("vuln-no-uaf",
                    cl::desc("Disable the use-after-free checker"),
                    cl::init(false));

cl::opt<bool> NoNull("vuln-no-null",
                     cl::desc("Disable the null-dereference checker"),
                     cl::init(false));

} // namespace

namespace vuln {

PreservedAnalyses VulnDetectPass::run(Function &F,
                                      FunctionAnalysisManager &FAM) {
  if (F.isDeclaration())
    return PreservedAnalyses::all();

  const TargetLibraryInfo &TLI = FAM.getResult<TargetLibraryAnalysis>(F);

  DiagEngine Diag(MinSeverity);

  Options Opts;
  Opts.Paranoid = Paranoid;

  if (!NoNull)
    runNullChecker(F, TLI, Diag, Opts);
  if (!NoUAF)
    runFreeChecker(F, TLI, Diag, Opts);

  return PreservedAnalyses::all();
}

} // namespace vuln
