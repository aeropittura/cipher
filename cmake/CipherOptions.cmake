#
# Build options for Cipher.
#
# Every user-facing switch carries the CIPHER_ prefix so it cannot clash with options of a parent
# project when Cipher is added with add_subdirectory().
#

if(EMSCRIPTEN)
    # Emscripten has no shared libraries, no OpenMP and no test/benchmark harness support.
    set(CIPHER_BUILD_SHARED OFF)
    set(CIPHER_WITH_OPENMP OFF)
    message(STATUS "Emscripten: shared libraries and OpenMP are not supported")
    set(_cipher_default_shared OFF)
    set(_cipher_default_static ON)
    set(_cipher_default_programs OFF)
else()
    set(_cipher_default_shared ON)
    set(_cipher_default_static OFF)
    set(_cipher_default_programs ON)
endif()

option(CIPHER_BUILD_SHARED       "Build the shared libraries"                                ${_cipher_default_shared})
option(CIPHER_BUILD_STATIC       "Build the static libraries"                                ${_cipher_default_static})
option(CIPHER_BUILD_TESTS        "Build the unit tests"                                      ${_cipher_default_programs})
option(CIPHER_BUILD_EXAMPLES     "Build the example programs"                                ${_cipher_default_programs})
option(CIPHER_BUILD_BENCHMARKS   "Build the benchmarks"                                      ${_cipher_default_programs})
option(CIPHER_BUILD_EXTRAS       "Build the extra (experimental) programs"                   OFF)
option(CIPHER_WITH_OPENMP        "Parallelize with OpenMP"                                   ON)
option(CIPHER_GIT_SUBMODULES     "Initialize/update git submodules at configure time"       ON)
option(CIPHER_WITH_BE2           "Compile math backend 2 (fixed-width big integers)"        OFF)
option(CIPHER_WITH_BE4           "Compile math backend 4 (dynamic big integers)"            OFF)
option(CIPHER_WITH_NTL           "Compile math backend 6 (NTL); requires NTL and GMP"        OFF)
option(CIPHER_WITH_TCM           "Link tcmalloc from the bundled gperftools"                 OFF)
option(CIPHER_WITH_MALLOC_TUNING "Tune glibc malloc to retain freed memory for reuse"        ON)
option(CIPHER_WITH_NATIVEOPT     "Optimize for the build machine (-march/-mcpu=native)"      OFF)
option(CIPHER_WITH_COVERAGE      "Instrument for coverage reports (g++ only)"                OFF)
option(CIPHER_WITH_NOISE_DEBUG   "Lattice-estimator mode; never use in production"           OFF)
option(CIPHER_WITH_REDUCED_NOISE "Reduced noise in HKS and BFV HPSPOVERQ modes"              OFF)
option(CIPHER_WITH_NUMA_INTERLEAVE "Interleave memory across NUMA nodes at library load"     ON)
option(CIPHER_WITH_DEFAULT_DIAGNOSTIC_SINK "Build the built-in diagnostic output sink"       ON)
option(CIPHER_USE_MACPORTS       "Look for libomp in MacPorts instead of Homebrew"           OFF)

# Numeric settings
set(CIPHER_NATIVE_SIZE       64 CACHE STRING "Bit width of the native integer: 32, 64 or 128")
set(CIPHER_MATH_BACKEND       4 CACHE STRING "Default math backend: 2, 4 or 6")
set(CIPHER_CKKS_M_FACTOR      1 CACHE STRING "CKKS ring-dimension multiplier")
# Radix of the rotation-fold accumulations (EvalPartialSumInPlace, EvalSum); a power of two >= 2.
# Higher radices need fewer digit decompositions (log2(size)/log2(radix) per fold) but more
# rotation keys ((radix-1)/log2(radix)*log2(size)).
set(CIPHER_PARTIAL_SUM_RADIX  4 CACHE STRING "Radix of the rotation-fold accumulations")
set_property(CACHE CIPHER_NATIVE_SIZE PROPERTY STRINGS 32 64 128)
set_property(CACHE CIPHER_MATH_BACKEND PROPERTY STRINGS 2 4 6)

if(NOT (CIPHER_BUILD_SHARED OR CIPHER_BUILD_STATIC))
    message(SEND_ERROR "Enable at least one of CIPHER_BUILD_SHARED and CIPHER_BUILD_STATIC.")
endif()

if(CIPHER_WITH_COVERAGE AND NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(WARNING "CIPHER_WITH_COVERAGE needs g++; coverage is disabled.")
    set(CIPHER_WITH_COVERAGE OFF)
endif()

# Build type
set(_cipher_build_types Debug Release RelWithDebInfo MinSizeRel)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type: ${_cipher_build_types}" FORCE)
elseif(NOT CMAKE_BUILD_TYPE IN_LIST _cipher_build_types)
    message(FATAL_ERROR "CMAKE_BUILD_TYPE must be one of: ${_cipher_build_types}")
endif()
message(STATUS "Building in ${CMAKE_BUILD_TYPE} mode")

function(cipher_print_options)
    foreach(opt IN ITEMS
            CIPHER_BUILD_TESTS CIPHER_BUILD_EXAMPLES CIPHER_BUILD_BENCHMARKS CIPHER_BUILD_EXTRAS
            CIPHER_BUILD_STATIC CIPHER_BUILD_SHARED CIPHER_GIT_SUBMODULES CIPHER_WITH_BE2
            CIPHER_WITH_BE4 CIPHER_WITH_NTL CIPHER_WITH_TCM CIPHER_WITH_MALLOC_TUNING
            CIPHER_WITH_OPENMP CIPHER_NATIVE_SIZE CIPHER_CKKS_M_FACTOR CIPHER_PARTIAL_SUM_RADIX
            CIPHER_WITH_NATIVEOPT CIPHER_WITH_COVERAGE CIPHER_WITH_NOISE_DEBUG
            CIPHER_WITH_REDUCED_NOISE CIPHER_WITH_DEFAULT_DIAGNOSTIC_SINK CIPHER_USE_MACPORTS)
        string(LENGTH "${opt}" _len)
        math(EXPR _pad "38 - ${_len}")
        string(REPEAT " " ${_pad} _spaces)
        message(STATUS "${opt}:${_spaces}${${opt}}")
    endforeach()
endfunction()
