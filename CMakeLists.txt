cmake_minimum_required(VERSION 3.20)
project(VulnDetect LANGUAGES C CXX)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Using LLVM ${LLVM_PACKAGE_VERSION} from ${LLVM_DIR}")

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)
include(HandleLLVMOptions)

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
add_definitions(${LLVM_DEFINITIONS})

add_library(VulnDetect MODULE
  src/Plugin.cpp
  src/VulnDetectPass.cpp
  src/FreeChecker.cpp
  src/NullChecker.cpp
  src/PointerLoc.cpp
  src/MemoryFns.cpp
  src/Diagnostics.cpp)

target_compile_features(VulnDetect PRIVATE cxx_std_17)

if(NOT LLVM_ENABLE_RTTI)
  target_compile_options(VulnDetect PRIVATE -fno-rtti)
endif()

if(APPLE)
  target_link_options(VulnDetect PRIVATE -Wl,-undefined,dynamic_lookup)
endif()

enable_testing()

find_program(LIT_COMMAND NAMES llvm-lit lit
  HINTS ${LLVM_TOOLS_BINARY_DIR})

file(GENERATE
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/test/lit.site.cfg.py
  CONTENT "config.vuln_plugin = '$<TARGET_FILE:VulnDetect>'\n\
config.llvm_tools_dir = '${LLVM_TOOLS_BINARY_DIR}'\n\
config.test_source_root = '${CMAKE_CURRENT_SOURCE_DIR}/test'\n\
lit_config.load_config(config, '${CMAKE_CURRENT_SOURCE_DIR}/test/lit.cfg.py')\n")

if(LIT_COMMAND)
  add_custom_target(check
    COMMAND ${LIT_COMMAND} -v ${CMAKE_CURRENT_BINARY_DIR}/test
    DEPENDS VulnDetect
    USES_TERMINAL)
endif()
