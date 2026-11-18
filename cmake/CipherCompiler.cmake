#
# Compiler checks and flags.
#
# Flags that every translation unit of this build needs (warnings, optimization level, OpenMP)
# are applied through CMAKE_<LANG>_FLAGS. Definitions that consumers of the installed package
# must also see (the math backend) are attached to the library targets instead.
#

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
        message(WARNING "GCC 9.0 or newer is required.")
    endif()
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 10)
        message(WARNING "Clang 10.0 or newer is required.")
    endif()
else()
    message(WARNING "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION} is not a supported compiler.")
endif()

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

# RPATH: use the build-tree RPATH while building, the install RPATH once installed.
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

set(_cipher_common_flags "-Wall -Werror -DCIPHER_VERSION=${PROJECT_VERSION}")
set(_cipher_c_flags "${_cipher_common_flags}")
set(_cipher_cxx_flags "${_cipher_common_flags}")

# -march=native is the x86 spelling and some aarch64 toolchains reject it; probe each language
# separately because the C and C++ front ends may accept different options.
if(CIPHER_WITH_NATIVEOPT)
    include(CheckCCompilerFlag)
    include(CheckCXXCompilerFlag)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64|armv8)")
        set(_candidates "-mcpu=native" "-march=native")
    else()
        set(_candidates "-march=native" "-mcpu=native")
    endif()
    set(_native_c "")
    set(_native_cxx "")
    foreach(flag IN LISTS _candidates)
        string(MAKE_C_IDENTIFIER "C_COMPILER_SUPPORTS${flag}" _var)
        check_c_compiler_flag("${flag}" ${_var})
        if(${_var} AND NOT _native_c)
            set(_native_c "${flag}")
        endif()
        string(MAKE_C_IDENTIFIER "CXX_COMPILER_SUPPORTS${flag}" _var)
        check_cxx_compiler_flag("${flag}" ${_var})
        if(${_var} AND NOT _native_cxx)
            set(_native_cxx "${flag}")
        endif()
    endforeach()
    if(_native_cxx)
        message(STATUS "Native optimization C++ flag: ${_native_cxx}")
        string(APPEND _cipher_cxx_flags " ${_native_cxx}")
        if(_native_c)
            message(STATUS "Native optimization C flag:   ${_native_c}")
            string(APPEND _cipher_c_flags " ${_native_c}")
        else()
            message(STATUS "${CMAKE_C_COMPILER_ID} accepts no native-optimization flag; C sources build without it.")
        endif()
    else()
        message(WARNING "CIPHER_WITH_NATIVEOPT is ON, but ${CMAKE_CXX_COMPILER_ID} on ${CMAKE_SYSTEM_PROCESSOR} "
                        "accepts neither -march=native nor -mcpu=native. Building without it.")
        set(CIPHER_WITH_NATIVEOPT OFF)
    endif()
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    string(APPEND _cipher_cxx_flags " -Wno-parentheses")
    # GCC provides __builtin_LINE(), __builtin_FUNCTION() and __builtin_FILE() for diagnostics.
    add_definitions(-DCIPHER_HAVE_BUILTIN_INFO)
    message(STATUS "CIPHER_HAVE_BUILTIN_INFO is defined")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    string(APPEND _cipher_cxx_flags " -Wno-unused-private-field -Wno-shift-op-parentheses")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS_RELEASE "-O0 -DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "-O0 -DNDEBUG")
    string(APPEND _cipher_c_flags " -O0 -g")
    string(APPEND _cipher_cxx_flags " -O0 -g")
else()
    string(APPEND _cipher_c_flags " -O3")
    string(APPEND _cipher_cxx_flags " -O3")
endif()

if(EMSCRIPTEN)
    set(_ems_ignore "-Wno-unused-but-set-variable -Wno-unknown-warning-option")
    string(APPEND _cipher_c_flags " ${_ems_ignore}")
    string(APPEND _cipher_cxx_flags " ${_ems_ignore}")
    add_compile_options(-fexceptions)
    add_link_options(
        -Wno-limited-postlink-optimizations
        -sINITIAL_MEMORY=2047MB -sMAXIMUM_MEMORY=4GB -sALLOW_MEMORY_GROWTH=1
        -sMALLOC=emmalloc -sDISABLE_EXCEPTION_CATCHING=0)
endif()

string(APPEND CMAKE_C_FLAGS " ${_cipher_c_flags}")
string(APPEND CMAKE_CXX_FLAGS " ${_cipher_cxx_flags}")

# The math backend selection must be identical for the library and everything compiled
# against it, so it travels with the targets (see source/CMakeLists.txt) and, for
# compatibility with flag-based consumers, with Cipher_CXX_FLAGS in the package config.
set(CIPHER_BACKEND_FLAGS "-DCIPHER_MATH_BACKEND=${CIPHER_MATH_BACKEND}")
string(APPEND CMAKE_CXX_FLAGS " ${CIPHER_BACKEND_FLAGS}")
string(APPEND CMAKE_C_FLAGS " ${CIPHER_BACKEND_FLAGS}")

if(CIPHER_WITH_COVERAGE)
    string(APPEND CMAKE_C_FLAGS " --coverage")
    string(APPEND CMAKE_CXX_FLAGS " --coverage")
    string(APPEND CMAKE_EXE_LINKER_FLAGS " --coverage")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " --coverage")
endif()

# Loading a user-provided PRNG shared object at run time needs libdl with g++ on Linux.
set(CIPHER_EXTRA_LIBS "")
if(UNIX AND NOT APPLE AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CIPHER_EXTRA_LIBS "-ldl")
endif()
