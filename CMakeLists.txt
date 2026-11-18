#
# Cipher - lattice-based homomorphic encryption library (BFV, BGV, CKKS and FHEW/TFHE-style
# boolean FHE). Derived from OpenFHE; see NOTICE.md.
#
# Typical use:
#     cmake -S . -B build -G Ninja
#     cmake --build build
#     ctest --test-dir build        # or: cmake --build build --target check
#
# All options are listed in cmake/CipherOptions.cmake.
#
cmake_minimum_required(VERSION 3.16.3)

project(Cipher VERSION 1.6.1 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

include(CipherOptions)
include(CipherPlatform)
include(CipherCompiler)
include(CipherInstallDirs)
include(CipherDependencies)
include(CipherHelpers)
cipher_print_options()

#--------------------------------------------------------------------
# Generated configuration header and sample data
#--------------------------------------------------------------------
set(CIPHER_HAVE_INT128 ${HAVE_INT128})
set(CIPHER_HAVE_INT64 ${HAVE_INT64})
configure_file(cmake/config.h.in ${PROJECT_BINARY_DIR}/include/cipher/config.h)

set(CIPHER_BUILD_INCLUDE_DIRS
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_BINARY_DIR}/include
    ${CIPHER_CEREAL_INCLUDE_DIR})

# Programs that (de)serialize use <build>/data as their scratch directory.
add_custom_target(cipher_data ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/data
    COMMENT "Preparing the sample data directory")
set_property(DIRECTORY APPEND PROPERTY ADDITIONAL_CLEAN_FILES ${PROJECT_BINARY_DIR}/data)

#--------------------------------------------------------------------
# Libraries, tests, examples, benchmarks
#--------------------------------------------------------------------
add_subdirectory(source)

if(CIPHER_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(CIPHER_BUILD_EXAMPLES OR CIPHER_BUILD_EXTRAS)
    add_subdirectory(examples)
endif()

if(CIPHER_BUILD_BENCHMARKS)
    add_subdirectory(bench)
endif()

include(CipherCoverage)
include(CipherPackaging)
