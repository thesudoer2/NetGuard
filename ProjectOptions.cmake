include(cmake/SystemLink.cmake)
include(cmake/LibFuzzer.cmake)
include(CMakeDependentOption)
include(CheckCXXCompilerFlag)


include(CheckCXXSourceCompiles)


macro(netguard_supports_sanitizers)
  if((CMAKE_CXX_COMPILER_ID MATCHES ".*Clang.*" OR CMAKE_CXX_COMPILER_ID MATCHES ".*GNU.*") AND NOT WIN32)

    message(STATUS "Sanity checking UndefinedBehaviorSanitizer, it should be supported on this platform")
    set(TEST_PROGRAM "int main() { return 0; }")

    # Check if UndefinedBehaviorSanitizer works at link time
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=undefined")
    set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=undefined")
    check_cxx_source_compiles("${TEST_PROGRAM}" HAS_UBSAN_LINK_SUPPORT)

    if(HAS_UBSAN_LINK_SUPPORT)
      message(STATUS "UndefinedBehaviorSanitizer is supported at both compile and link time.")
      set(SUPPORTS_UBSAN ON)
    else()
      message(WARNING "UndefinedBehaviorSanitizer is NOT supported at link time.")
      set(SUPPORTS_UBSAN OFF)
    endif()
  else()
    set(SUPPORTS_UBSAN OFF)
  endif()

  if((CMAKE_CXX_COMPILER_ID MATCHES ".*Clang.*" OR CMAKE_CXX_COMPILER_ID MATCHES ".*GNU.*") AND WIN32)
    set(SUPPORTS_ASAN OFF)
  else()
    if (NOT WIN32)
      message(STATUS "Sanity checking AddressSanitizer, it should be supported on this platform")
      set(TEST_PROGRAM "int main() { return 0; }")

      # Check if AddressSanitizer works at link time
      set(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
      set(CMAKE_REQUIRED_LINK_OPTIONS "-fsanitize=address")
      check_cxx_source_compiles("${TEST_PROGRAM}" HAS_ASAN_LINK_SUPPORT)

      if(HAS_ASAN_LINK_SUPPORT)
        message(STATUS "AddressSanitizer is supported at both compile and link time.")
        set(SUPPORTS_ASAN ON)
      else()
        message(WARNING "AddressSanitizer is NOT supported at link time.")
        set(SUPPORTS_ASAN OFF)
      endif()
    else()
      set(SUPPORTS_ASAN ON)
    endif()
  endif()
endmacro()

macro(netguard_setup_options)
  option(NETGUARD_ENABLE_HARDENING "Enable hardening" ON)
  option(NETGUARD_ENABLE_COVERAGE "Enable coverage reporting" OFF)
  cmake_dependent_option(
    NETGUARD_ENABLE_GLOBAL_HARDENING
    "Attempt to push hardening options to built dependencies"
    ON
    NETGUARD_ENABLE_HARDENING
    OFF)

  netguard_supports_sanitizers()

  if(NOT PROJECT_IS_TOP_LEVEL OR NETGUARD_PACKAGING_MAINTAINER_MODE)
    option(NETGUARD_ENABLE_IPO "Enable IPO/LTO" OFF)
    option(NETGUARD_WARNINGS_AS_ERRORS "Treat Warnings As Errors" OFF)
    option(NETGUARD_ENABLE_USER_LINKER "Enable user-selected linker" OFF)
    option(NETGUARD_ENABLE_SANITIZER_ADDRESS "Enable address sanitizer" OFF)
    option(NETGUARD_ENABLE_SANITIZER_LEAK "Enable leak sanitizer" OFF)
    option(NETGUARD_ENABLE_SANITIZER_UNDEFINED "Enable undefined sanitizer" OFF)
    option(NETGUARD_ENABLE_SANITIZER_THREAD "Enable thread sanitizer" OFF)
    option(NETGUARD_ENABLE_SANITIZER_MEMORY "Enable memory sanitizer" OFF)
    option(NETGUARD_ENABLE_UNITY_BUILD "Enable unity builds" OFF)
    option(NETGUARD_ENABLE_CLANG_TIDY "Enable clang-tidy" OFF)
    option(NETGUARD_ENABLE_CPPCHECK "Enable cpp-check analysis" OFF)
    option(NETGUARD_ENABLE_PCH "Enable precompiled headers" OFF)
    option(NETGUARD_ENABLE_CACHE "Enable ccache" OFF)
  else()
    option(NETGUARD_ENABLE_IPO "Enable IPO/LTO" ON)
    option(NETGUARD_WARNINGS_AS_ERRORS "Treat Warnings As Errors" ON)
    option(NETGUARD_ENABLE_USER_LINKER "Enable user-selected linker" OFF)
    option(NETGUARD_ENABLE_SANITIZER_ADDRESS "Enable address sanitizer" ${SUPPORTS_ASAN})
    option(NETGUARD_ENABLE_SANITIZER_LEAK "Enable leak sanitizer" OFF)
    option(NETGUARD_ENABLE_SANITIZER_UNDEFINED "Enable undefined sanitizer" ${SUPPORTS_UBSAN})
    option(NETGUARD_ENABLE_SANITIZER_THREAD "Enable thread sanitizer" OFF)
    option(NETGUARD_ENABLE_SANITIZER_MEMORY "Enable memory sanitizer" OFF)
    option(NETGUARD_ENABLE_UNITY_BUILD "Enable unity builds" OFF)
    option(NETGUARD_ENABLE_CLANG_TIDY "Enable clang-tidy" ON)
    option(NETGUARD_ENABLE_CPPCHECK "Enable cpp-check analysis" ON)
    option(NETGUARD_ENABLE_PCH "Enable precompiled headers" OFF)
    option(NETGUARD_ENABLE_CACHE "Enable ccache" ON)
  endif()

  message(STATUS "Setup Options Status:")
  message(STATUS "  NETGUARD_ENABLE_IPO: ${NETGUARD_ENABLE_IPO}")
  message(STATUS "  NETGUARD_WARNINGS_AS_ERRORS: ${NETGUARD_WARNINGS_AS_ERRORS}")
  message(STATUS "  NETGUARD_ENABLE_USER_LINKER: ${NETGUARD_ENABLE_USER_LINKER}")
  message(STATUS "  NETGUARD_ENABLE_SANITIZER_ADDRESS: ${NETGUARD_ENABLE_SANITIZER_ADDRESS}")
  message(STATUS "  NETGUARD_ENABLE_SANITIZER_LEAK: ${NETGUARD_ENABLE_SANITIZER_LEAK}")
  message(STATUS "  NETGUARD_ENABLE_SANITIZER_UNDEFINED: ${NETGUARD_ENABLE_SANITIZER_UNDEFINED}")
  message(STATUS "  NETGUARD_ENABLE_SANITIZER_THREAD: ${NETGUARD_ENABLE_SANITIZER_THREAD}")
  message(STATUS "  NETGUARD_ENABLE_SANITIZER_MEMORY: ${NETGUARD_ENABLE_SANITIZER_MEMORY}")
  message(STATUS "  NETGUARD_ENABLE_UNITY_BUILD: ${NETGUARD_ENABLE_UNITY_BUILD}")
  message(STATUS "  NETGUARD_ENABLE_CLANG_TIDY: ${NETGUARD_ENABLE_CLANG_TIDY}")
  message(STATUS "  NETGUARD_ENABLE_CPPCHECK: ${NETGUARD_ENABLE_CPPCHECK}")
  message(STATUS "  NETGUARD_ENABLE_COVERAGE: ${NETGUARD_ENABLE_COVERAGE}")
  message(STATUS "  NETGUARD_ENABLE_PCH: ${NETGUARD_ENABLE_PCH}")
  message(STATUS "  NETGUARD_ENABLE_CACHE: ${NETGUARD_ENABLE_CACHE}")

  if(NOT PROJECT_IS_TOP_LEVEL)
    mark_as_advanced(
      NETGUARD_ENABLE_IPO
      NETGUARD_WARNINGS_AS_ERRORS
      NETGUARD_ENABLE_USER_LINKER
      NETGUARD_ENABLE_SANITIZER_ADDRESS
      NETGUARD_ENABLE_SANITIZER_LEAK
      NETGUARD_ENABLE_SANITIZER_UNDEFINED
      NETGUARD_ENABLE_SANITIZER_THREAD
      NETGUARD_ENABLE_SANITIZER_MEMORY
      NETGUARD_ENABLE_UNITY_BUILD
      NETGUARD_ENABLE_CLANG_TIDY
      NETGUARD_ENABLE_CPPCHECK
      NETGUARD_ENABLE_COVERAGE
      NETGUARD_ENABLE_PCH
      NETGUARD_ENABLE_CACHE)
  endif()

  netguard_check_libfuzzer_support(LIBFUZZER_SUPPORTED)
  if(LIBFUZZER_SUPPORTED AND (NETGUARD_ENABLE_SANITIZER_ADDRESS OR NETGUARD_ENABLE_SANITIZER_THREAD OR NETGUARD_ENABLE_SANITIZER_UNDEFINED))
    set(DEFAULT_FUZZER ON)
  else()
    set(DEFAULT_FUZZER OFF)
  endif()

  option(NETGUARD_BUILD_FUZZ_TESTS "Enable fuzz testing executable" ${DEFAULT_FUZZER})

endmacro()

macro(netguard_global_options)
  if(NETGUARD_ENABLE_IPO)
    include(cmake/InterproceduralOptimization.cmake)
    netguard_enable_ipo()
  endif()

  netguard_supports_sanitizers()

  if(NETGUARD_ENABLE_HARDENING AND NETGUARD_ENABLE_GLOBAL_HARDENING)
    include(cmake/Hardening.cmake)
    if(NOT SUPPORTS_UBSAN
       OR NETGUARD_ENABLE_SANITIZER_UNDEFINED
       OR NETGUARD_ENABLE_SANITIZER_ADDRESS
       OR NETGUARD_ENABLE_SANITIZER_THREAD
       OR NETGUARD_ENABLE_SANITIZER_LEAK)
      set(ENABLE_UBSAN_MINIMAL_RUNTIME FALSE)
    else()
      set(ENABLE_UBSAN_MINIMAL_RUNTIME TRUE)
    endif()
    message("${NETGUARD_ENABLE_HARDENING} ${ENABLE_UBSAN_MINIMAL_RUNTIME} ${NETGUARD_ENABLE_SANITIZER_UNDEFINED}")
    netguard_enable_hardening(netguard_options ON ${ENABLE_UBSAN_MINIMAL_RUNTIME})
  endif()
endmacro()

macro(netguard_local_options)
  if(PROJECT_IS_TOP_LEVEL)
    include(cmake/StandardProjectSettings.cmake)
  endif()

  add_library(netguard_warnings INTERFACE)
  add_library(netguard_options INTERFACE)

  include(cmake/CompilerWarnings.cmake)
  netguard_set_project_warnings(
    netguard_warnings
    ${NETGUARD_WARNINGS_AS_ERRORS}
    ""
    "")

  if(NETGUARD_ENABLE_USER_LINKER)
    include(cmake/Linker.cmake)
    netguard_configure_linker(netguard_options)
  endif()

  include(cmake/Sanitizers.cmake)
  netguard_enable_sanitizers(
    netguard_options
    ${NETGUARD_ENABLE_SANITIZER_ADDRESS}
    ${NETGUARD_ENABLE_SANITIZER_LEAK}
    ${NETGUARD_ENABLE_SANITIZER_UNDEFINED}
    ${NETGUARD_ENABLE_SANITIZER_THREAD}
    ${NETGUARD_ENABLE_SANITIZER_MEMORY})

  set_target_properties(netguard_options PROPERTIES UNITY_BUILD ${NETGUARD_ENABLE_UNITY_BUILD})

  if(NETGUARD_ENABLE_PCH)
    target_precompile_headers(
      netguard_options
      INTERFACE
      <vector>
      <string>
      <utility>)
  endif()

  if(NETGUARD_ENABLE_CACHE)
    include(cmake/Cache.cmake)
    netguard_enable_cache()
  endif()

  include(cmake/StaticAnalyzers.cmake)
  if(NETGUARD_ENABLE_CLANG_TIDY)
    netguard_enable_clang_tidy(netguard_options ${NETGUARD_WARNINGS_AS_ERRORS})
  endif()

  if(NETGUARD_ENABLE_CPPCHECK)
    netguard_enable_cppcheck(${NETGUARD_WARNINGS_AS_ERRORS} "" # override cppcheck options
    )
  endif()

  if(NETGUARD_ENABLE_COVERAGE)
    include(cmake/Tests.cmake)
    netguard_enable_coverage(netguard_options)
  endif()

  if(NETGUARD_WARNINGS_AS_ERRORS)
    check_cxx_compiler_flag("-Wl,--fatal-warnings" LINKER_FATAL_WARNINGS)
    if(LINKER_FATAL_WARNINGS)
      # This is not working consistently, so disabling for now
      # target_link_options(netguard_options INTERFACE -Wl,--fatal-warnings)
    endif()
  endif()

  if(NETGUARD_ENABLE_HARDENING AND NOT NETGUARD_ENABLE_GLOBAL_HARDENING)
    include(cmake/Hardening.cmake)
    if(NOT SUPPORTS_UBSAN
       OR NETGUARD_ENABLE_SANITIZER_UNDEFINED
       OR NETGUARD_ENABLE_SANITIZER_ADDRESS
       OR NETGUARD_ENABLE_SANITIZER_THREAD
       OR NETGUARD_ENABLE_SANITIZER_LEAK)
      set(ENABLE_UBSAN_MINIMAL_RUNTIME FALSE)
    else()
      set(ENABLE_UBSAN_MINIMAL_RUNTIME TRUE)
    endif()
    netguard_enable_hardening(netguard_options OFF ${ENABLE_UBSAN_MINIMAL_RUNTIME})
  endif()

endmacro()
