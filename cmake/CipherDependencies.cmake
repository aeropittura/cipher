#
# Third-party dependencies: git submodules, OpenMP/threads, tcmalloc, NTL/GMP and cereal.
#

set(CIPHER_EXTERN_DIR "${PROJECT_SOURCE_DIR}/extern")
set(CIPHER_THIRDPARTY_LIBS "")
set(CIPHER_THIRDPARTY_STATIC_LIBS "")

#--------------------------------------------------------------------
# Git submodules
#--------------------------------------------------------------------
if(CIPHER_GIT_SUBMODULES AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
    find_package(Git REQUIRED)
    message(STATUS "Updating git submodules")
    if(NOT CIPHER_GIT_SUBMODULES_SYNCED)
        # Sync only once per build tree (i.e. while there is no CMakeCache.txt yet).
        execute_process(COMMAND ${GIT_EXECUTABLE} submodule sync --recursive
                        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                        RESULT_VARIABLE _git_result)
        if(NOT _git_result EQUAL 0)
            message(FATAL_ERROR "'git submodule sync --recursive' failed (${_git_result}); check out the submodules manually")
        endif()
    endif()
    execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
                    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                    RESULT_VARIABLE _git_result)
    if(NOT _git_result EQUAL 0)
        if(NOT CIPHER_GIT_SUBMODULES_SYNCED)
            message(FATAL_ERROR "'git submodule update --init' failed (${_git_result}); check out the submodules manually")
        else()
            message(SEND_ERROR "'git submodule update --init' failed (${_git_result}); check out the submodules "
                               "manually or configure with -DCIPHER_GIT_SUBMODULES=OFF")
        endif()
    endif()
    set(CIPHER_GIT_SUBMODULES_SYNCED ON CACHE BOOL "" FORCE)
    mark_as_advanced(CIPHER_GIT_SUBMODULES_SYNCED)
endif()

#--------------------------------------------------------------------
# OpenMP or plain threads
#--------------------------------------------------------------------
if(CIPHER_WITH_OPENMP)
    add_definitions(-DCIPHER_PARALLEL)
    if(APPLE)
        # Apple clang ships without OpenMP; point it at libomp from Homebrew or MacPorts.
        if(CIPHER_USE_MACPORTS)
            message(STATUS "Using the MacPorts libomp")
            set(CIPHER_OPENMP_LIBRARIES "/opt/local/lib/libomp")
            set(CIPHER_OPENMP_INCLUDES "/opt/local/include/libomp")
            set(_omp_lib_name "omp")
        elseif(CIPHER_ARCHITECTURE MATCHES "arm64")
            message(STATUS "Apple silicon detected; using the Homebrew libomp")
            set(CIPHER_OPENMP_LIBRARIES "/opt/homebrew/opt/libomp/lib")
            set(CIPHER_OPENMP_INCLUDES "/opt/homebrew/opt/libomp/include")
            set(_omp_lib_name "libomp")
        else()
            message(STATUS "Apple Intel detected; using the Homebrew libomp")
            set(CIPHER_OPENMP_LIBRARIES "/usr/local/opt/libomp/lib")
            set(CIPHER_OPENMP_INCLUDES "/usr/local/opt/libomp/include")
            set(_omp_lib_name "libomp")
        endif()
        set(_omp_flags "-Xpreprocessor -fopenmp -lomp -Wno-unused-command-line-argument")
        if(CMAKE_C_COMPILER_ID MATCHES "Clang")
            set(OpenMP_C_FLAGS "${_omp_flags}")
            set(OpenMP_C_LIB_NAMES "${_omp_lib_name}")
        endif()
        if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
            set(OpenMP_CXX_FLAGS "${_omp_flags}")
            set(OpenMP_CXX_LIB_NAMES "${_omp_lib_name}")
        endif()
        set(OpenMP_${_omp_lib_name}_LIBRARY "${_omp_lib_name}")
        include_directories("${CIPHER_OPENMP_INCLUDES}")
        link_directories("${CIPHER_OPENMP_LIBRARIES}")
        # The flags above pass -lomp, so every link step (including the try_compile checks of
        # third-party projects such as google-benchmark) must also know where libomp lives.
        foreach(_kind EXE SHARED MODULE)
            string(APPEND CMAKE_${_kind}_LINKER_FLAGS " -L${CIPHER_OPENMP_LIBRARIES}")
        endforeach()
        string(APPEND CMAKE_CXX_FLAGS " ${OpenMP_CXX_FLAGS}")
        string(APPEND CMAKE_C_FLAGS " ${OpenMP_C_FLAGS}")
        message(STATUS "OpenMP libraries: ${CIPHER_OPENMP_LIBRARIES}")
        message(STATUS "OpenMP includes:  ${CIPHER_OPENMP_INCLUDES}")
    endif()

    find_package(OpenMP)
    if(OpenMP_CXX_FOUND OR OpenMP_FOUND)
        string(APPEND CMAKE_CXX_FLAGS " ${OpenMP_CXX_FLAGS}")
        string(APPEND CMAKE_EXE_LINKER_FLAGS " ${OpenMP_EXE_LINKER_FLAGS}")
    else()
        message(SEND_ERROR "OpenMP was not found. Install libomp or configure with -DCIPHER_WITH_OPENMP=OFF.")
    endif()
    if(OpenMP_C_FOUND OR OpenMP_FOUND)
        string(APPEND CMAKE_C_FLAGS " ${OpenMP_C_FLAGS}")
    endif()
else()
    if(NOT EMSCRIPTEN)
        find_package(Threads REQUIRED)
    endif()
    # Without OpenMP the "#pragma omp" lines are dead text; silence the warning about them.
    string(APPEND CMAKE_C_FLAGS " -Wno-unknown-pragmas")
    string(APPEND CMAKE_CXX_FLAGS " -Wno-unknown-pragmas")
endif()

# Pthreads settings that google-benchmark relies on for some Linux and macOS systems.
set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_WIN32_THREADS_INIT 0)
set(CMAKE_USE_PTHREADS_INIT 1)
set(THREADS_PREFER_PTHREAD_FLAG ON)

#--------------------------------------------------------------------
# Autotools are needed to build tcmalloc (and by users of NTL/GMP)
#--------------------------------------------------------------------
if(CIPHER_WITH_TCM OR CIPHER_WITH_NTL)
    if(MINGW)
        execute_process(COMMAND sh autoconf --version OUTPUT_VARIABLE _autoconf_version)
    else()
        execute_process(COMMAND autoconf --version OUTPUT_VARIABLE _autoconf_version)
    endif()
    if(NOT _autoconf_version)
        message(SEND_ERROR "autoconf is not installed.")
    endif()
endif()

#--------------------------------------------------------------------
# cereal (header only) and the shared third-party include directory
#--------------------------------------------------------------------
set(CIPHER_CEREAL_INCLUDE_DIR "${CIPHER_EXTERN_DIR}/cereal/include")
include_directories(${CIPHER_EXTERN_DIR}/include)

#--------------------------------------------------------------------
# tcmalloc from the bundled gperftools
#--------------------------------------------------------------------
add_custom_target(tcm
    COMMAND ./autogen.sh
    COMMAND ./configure --prefix=${PROJECT_BINARY_DIR}/extern --enable-minimal
    COMMAND make
    COMMAND make install
    WORKING_DIRECTORY ${CIPHER_EXTERN_DIR}/gperftools)
add_custom_target(tcm_clean
    COMMAND rm -rf include/gperftools include/google lib/libtcmalloc_minimal* lib/pkgconfig/libtcmalloc*
            lib/pkgconfig/libprofiler.pc share/doc/gperftools
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/extern)

if(CIPHER_BUILD_STATIC)
    add_library(tcmalloc_static STATIC IMPORTED GLOBAL)
    set_target_properties(tcmalloc_static PROPERTIES IMPORTED_LOCATION
        ${PROJECT_BINARY_DIR}/extern/lib/libtcmalloc_minimal${CMAKE_STATIC_LIBRARY_SUFFIX})
endif()
if(CIPHER_BUILD_SHARED)
    add_library(tcmalloc SHARED IMPORTED GLOBAL)
    set_target_properties(tcmalloc PROPERTIES IMPORTED_LOCATION
        ${PROJECT_BINARY_DIR}/extern/lib/libtcmalloc_minimal${CMAKE_SHARED_LIBRARY_SUFFIX})
endif()
if(CIPHER_WITH_TCM)
    message(STATUS "tcmalloc is enabled")
    if(MINGW)
        message(SEND_ERROR "tcmalloc is not supported on MinGW")
    endif()
    # The trailing slash installs the contents of extern/lib, so the destination follows
    # CMAKE_INSTALL_LIBDIR. Consumers look for these next to the Cipher libraries.
    install(DIRECTORY ${PROJECT_BINARY_DIR}/extern/lib/ DESTINATION ${Cipher_INSTALL_LIBDIR}
            FILES_MATCHING PATTERN "libtcmalloc_minimal.*")
    install(DIRECTORY ${PROJECT_BINARY_DIR}/extern/include DESTINATION ${Cipher_INSTALL_INCLUDEDIR}/cipher/extern/)
    list(APPEND CIPHER_THIRDPARTY_LIBS tcmalloc)
    list(APPEND CIPHER_THIRDPARTY_STATIC_LIBS tcmalloc_static)
endif()

#--------------------------------------------------------------------
# NTL and GMP (math backend 6); both must be installed by the user
#--------------------------------------------------------------------
if(CIPHER_WITH_NTL)
    # NTL_LIBRARIES / GMP_LIBRARIES may name either the library file or the directory holding it;
    # the include directories may be given the same way. Libraries are linked by full path so a
    # reconfigure cannot turn a cached file path into a bogus search directory.
    set(_search_roots "/usr" "/usr/local" "/opt" "/opt/local" "/opt/homebrew")
    set(_header_suffixes "include" "include/NTL" "include/${CMAKE_LIBRARY_ARCHITECTURE}")
    set(_lib_suffixes "lib" "lib/${CMAKE_LIBRARY_ARCHITECTURE}")
    include(FindPackageHandleStandardArgs)
    foreach(_pkg NTL GMP)
        if(_pkg STREQUAL "NTL")
            set(_header RR.h)
            set(_names ntl libntl)
            set(_lower ntl)
        else()
            set(_header gmp.h)
            set(_names gmp libgmp)
            set(_lower gmp)
        endif()
        find_path(${_pkg}_INCLUDE_DIR NAMES ${_header} PATHS ${_search_roots} PATH_SUFFIXES ${_header_suffixes})
        set(_hint "")
        if(${_pkg}_LIBRARIES AND IS_DIRECTORY "${${_pkg}_LIBRARIES}")
            set(_hint "${${_pkg}_LIBRARIES}")
        endif()
        if(_hint OR NOT ${_pkg}_LIBRARIES)
            find_library(${_pkg}_LIBRARY NAMES ${_names} HINTS ${_hint}
                         PATHS ${_search_roots} PATH_SUFFIXES ${_lib_suffixes})
        else()
            set(${_pkg}_LIBRARY "${${_pkg}_LIBRARIES}" CACHE FILEPATH "Path to lib${_lower}" FORCE)
        endif()
        find_package_handle_standard_args(${_pkg} DEFAULT_MSG ${_pkg}_INCLUDE_DIR ${_pkg}_LIBRARY)
        if(NOT ${_pkg}_FOUND)
            message(FATAL_ERROR "lib${_lower} was not found. Install it, or pass -D${_pkg}_INCLUDE_DIR=<dir> and "
                                "-D${_pkg}_LIBRARIES=<file or dir>, to use math backend 6.")
        endif()
        mark_as_advanced(${_pkg}_INCLUDE_DIR ${_pkg}_LIBRARY ${_pkg}_LIBRARIES)
    endforeach()
    include_directories(${NTL_INCLUDE_DIR} ${GMP_INCLUDE_DIR})
    list(APPEND CIPHER_THIRDPARTY_LIBS ${NTL_LIBRARY} ${GMP_LIBRARY})
    list(APPEND CIPHER_THIRDPARTY_STATIC_LIBS ${NTL_LIBRARY} ${GMP_LIBRARY})
endif()
