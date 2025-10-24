cmake_minimum_required(VERSION 3.22)

project(
  NetGuard
  VERSION 0.0.1
  DESCRIPTION "Network Intrusion Detection System"
  LANGUAGES CXX C)

set(PROJECT_NAME netguard)

# Only set the cxx_standard if it is not set by someone else
if (NOT DEFINED CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 23)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

# strongly encouraged to enable this globally to avoid conflicts between
# -Wpedantic being enabled and -std=c++20 and -std=gnu++20 for example
# when compiling with PCH enabled
set(CMAKE_CXX_EXTENSIONS OFF)

include(cmake/PreventInSourceBuilds.cmake)
include(ProjectOptions.cmake)

set(PROJECT_IS_TOP_LEVEL ON)

netguard_setup_options()
netguard_global_options()

# include(Dependencies.cmake)
# netguard_setup_dependencies()

netguard_local_options()

# don't know if this should be set globally from here or not...
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

target_compile_features(netguard_options INTERFACE cxx_std_${CMAKE_CXX_STANDARD})

add_library(netguard::netguard_options ALIAS netguard_options)
add_library(netguard::netguard_warnings ALIAS netguard_warnings)


# Adding the src:
add_subdirectory(src)

# Don't even look at tests if we're not top level
if(NOT PROJECT_IS_TOP_LEVEL)
  return()
endif()


if(BUILD_TESTING)
  add_subdirectory(test)
endif()


if(NETGUARD_BUILD_FUZZ_TESTS)
  message(AUTHOR_WARNING "Building Fuzz Tests, using fuzzing sanitizer https://www.llvm.org/docs/LibFuzzer.html")
  if (NOT NETGUARD_ENABLE_SANITIZER_ADDRESS AND NOT NETGUARD_ENABLE_SANITIZER_THREAD)
    message(WARNING "You need asan or tsan enabled for meaningful fuzz testing")
  endif()
  add_subdirectory(fuzz_test)
endif()