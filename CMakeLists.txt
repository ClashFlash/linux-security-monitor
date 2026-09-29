cmake_minimum_required(VERSION 3.16)
project(LinuxSecurityMonitor VERSION 1.0.0 LANGUAGES CXX)

# ── C++ standard ──────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Build type defaults ───────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type (Debug|Release)" FORCE)
endif()

# ── Compiler flags ────────────────────────────────────────────────────────────
set(COMMON_FLAGS "-Wall -Wextra -Wpedantic -Wno-unused-parameter")
set(CMAKE_CXX_FLAGS_DEBUG   "${COMMON_FLAGS} -g -O0 -DDEBUG -fsanitize=address,undefined")
set(CMAKE_CXX_FLAGS_RELEASE "${COMMON_FLAGS} -O2 -DNDEBUG")

# ── Linker flags for sanitizers in debug ─────────────────────────────────────
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address,undefined")
endif()

# ── Threads ───────────────────────────────────────────────────────────────────
find_package(Threads REQUIRED)

# ── Source files ─────────────────────────────────────────────────────────────
set(MONITOR_SOURCES
  src/cpu.cpp
  src/memory.cpp
  src/process.cpp
  src/network.cpp
  src/ssh_monitor.cpp
  src/file_integrity.cpp
  src/security_rules.cpp
  src/event_system.cpp
  src/ui.cpp
  src/alert.cpp
  src/config.cpp
)

# ── Library (used by both the binary and the tests) ───────────────────────────
add_library(lsm_lib STATIC ${MONITOR_SOURCES})
target_include_directories(lsm_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(lsm_lib PUBLIC Threads::Threads)

# ── Main binary ───────────────────────────────────────────────────────────────
add_executable(monitor src/main.cpp)
target_link_libraries(monitor PRIVATE lsm_lib)

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS monitor DESTINATION bin)
install(DIRECTORY config/ DESTINATION share/linux-security-monitor/config)

# ── Tests ─────────────────────────────────────────────────────────────────────
enable_testing()
add_subdirectory(tests)

# ── Summary ───────────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "── Linux Security Monitor ───────────────────")
message(STATUS "   Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "   C++ flags  : ${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE}}")
message(STATUS "────────────────────────────────────────────")
