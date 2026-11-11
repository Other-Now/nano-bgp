cmake_minimum_required(VERSION 3.20)
project(nano_bgp CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()
add_compile_options(-Wall -Wextra -Wno-missing-field-initializers)

option(NBGP_SANITIZE "Build with ASan + UBSan" OFF)
option(NBGP_FUZZ "Build the libFuzzer target (needs clang)" OFF)
if(NBGP_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

add_library(nbgp_core STATIC src/wire.cpp src/rib.cpp)
target_include_directories(nbgp_core PUBLIC src)

add_executable(nbgpd src/main.cpp src/speaker.cpp src/fib.cpp)
target_link_libraries(nbgpd nbgp_core)

add_executable(unit_tests tests/unit_tests.cpp)
target_link_libraries(unit_tests nbgp_core)

if(NBGP_FUZZ)
  add_executable(fuzz_update fuzz/fuzz_update.cpp src/wire.cpp)
  target_include_directories(fuzz_update PRIVATE src)
  target_compile_options(fuzz_update PRIVATE -fsanitize=fuzzer,address,undefined)
  target_link_options(fuzz_update PRIVATE -fsanitize=fuzzer,address,undefined)
endif()
