#include "VulnDetect/Pass.h"

#include "llvm/Passes/PassBuilder.h"
#if __has_include("llvm/Passes/PassPlugin.h")
#include "llvm/Passes/PassPlugin.h"
#else
#include "llvm/Plugins/PassPlugin.h"
#endif

using namespace llvm;

static void registerCallbacks(PassBuilder &PB) {
  // Explicit invocation: opt -passes=vuln-detect ...
  PB.registerPipelineParsingCallback(
      [](StringRef Name, FunctionPassManager &FPM,
         ArrayRef<PassBuilder::PipelineElement>) {
        if (Name == "vuln-detect") {
          FPM.addPass(vuln::VulnDetectPass());
          return true;
        }
        return false;
      });

  // Automatic invocation under clang -fpass-plugin. Running at pipeline start
  // means we see the IR before optimizations fold the patterns away.
  PB.registerPipelineStartEPCallback(
      [](ModulePassManager &MPM, OptimizationLevel) {
        MPM.addPass(createModuleToFunctionPassAdaptor(vuln::VulnDetectPass()));
      });
}

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "VulnDetect", LLVM_VERSION_STRING,
          registerCallbacks};
}
