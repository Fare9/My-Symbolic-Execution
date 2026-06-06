cmake_minimum_required(VERSION 3.20)
project(vm_lifter CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION} at ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

llvm_map_components_to_libnames(LLVM_LIBS
    core
    support
    passes
    analysis
    transformutils
    scalaropts
    ipo
    irreader
    bitwriter
)

add_executable(vm_lifter
    src/main.cpp
    src/disassembler.cpp
    src/lifter.cpp
    src/optimizer.cpp
)

target_include_directories(vm_lifter PRIVATE include)
target_link_libraries(vm_lifter PRIVATE ${LLVM_LIBS})
target_compile_options(vm_lifter PRIVATE -Wall -Wextra)
