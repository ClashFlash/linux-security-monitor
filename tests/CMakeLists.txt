cmake_minimum_required(VERSION 3.16)

# ── Fetch Google Test ─────────────────────────────────────────────────────────
include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.14.0
  GIT_SHALLOW    TRUE
)
# Prevent gtest from overriding our compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

# ── Test targets ─────────────────────────────────────────────────────────────
function(add_lsm_test name source)
  add_executable(${name} ${source})
  target_link_libraries(${name} PRIVATE lsm_lib GTest::gtest_main)
  target_include_directories(${name} PRIVATE ${CMAKE_SOURCE_DIR}/include)
  gtest_discover_tests(${name})
endfunction()

add_lsm_test(test_cpu             test_cpu.cpp)
add_lsm_test(test_ssh_parser      test_ssh_parser.cpp)
add_lsm_test(test_file_integrity  test_file_integrity.cpp)
add_lsm_test(test_security_rules  test_security_rules.cpp)
add_lsm_test(test_network_parser  test_network_parser.cpp)
add_lsm_test(test_process         test_process.cpp)
add_lsm_test(test_config          test_config.cpp)
