#ifndef VULNDETECT_DIAGNOSTICS_H
#define VULNDETECT_DIAGNOSTICS_H

#include "llvm/ADT/StringRef.h"

#include <string>

namespace llvm {
class Instruction;
}

namespace vuln {

enum class Severity { High, Medium };

// Emits findings to stderr in a fixed, grep-friendly format and applies the
// -vuln-min-severity filter. One instance per function analysis run.
class DiagEngine {
public:
  explicit DiagEngine(Severity Min) : Min(Min) {}

  void report(Severity Sev, llvm::StringRef CWE, llvm::StringRef Message,
              const llvm::Instruction *I);

  unsigned count() const { return Count; }

private:
  Severity Min;
  unsigned Count = 0;
};

} // namespace vuln

#endif
