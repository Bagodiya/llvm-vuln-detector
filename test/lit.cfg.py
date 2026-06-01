import os
import lit.formats

config.name = "VulnDetect"
config.test_format = lit.formats.ShTest(execute_external=True)
config.suffixes = [".ll"]

tools = config.llvm_tools_dir
config.substitutions.append(("%opt", os.path.join(tools, "opt")))
config.substitutions.append(("%FileCheck", os.path.join(tools, "FileCheck")))
config.substitutions.append(
    ("%loadvd", "-load-pass-plugin=" + config.vuln_plugin)
)

config.environment["PATH"] = os.pathsep.join(
    [tools, config.environment.get("PATH", "")]
)
