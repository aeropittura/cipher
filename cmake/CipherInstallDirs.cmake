#
# Install locations.
#
# Seed the historical 'lib' default before GNUInstallDirs runs: it derives lib64 or
# lib/<arch-triplet> only when CMAKE_INSTALL_LIBDIR is unset, so an explicit
# -DCMAKE_INSTALL_LIBDIR from a packager is still honored.
#
if(NOT DEFINED CMAKE_INSTALL_LIBDIR)
    set(CMAKE_INSTALL_LIBDIR lib CACHE PATH "Object code libraries")
endif()
include(GNUInstallDirs)

# Directory for the CMake package files. It sits next to the libraries it describes, so a
# lib64 or lib/<arch-triplet> layout does not grow a second tree just for these files. It may
# be overridden with -DCipher_INSTALL_CMAKEDIR=<dir> (relative to the prefix, or absolute).
if(WIN32 AND NOT CYGWIN)
    set(_cipher_default_cmakedir "CMake")
else()
    set(_cipher_default_cmakedir "${CMAKE_INSTALL_LIBDIR}/Cipher")
endif()
if(NOT DEFINED Cipher_INSTALL_CMAKEDIR)
    set(Cipher_INSTALL_CMAKEDIR "${_cipher_default_cmakedir}")
endif()

# Relative destinations for install(); the FULL_ forms are used by the build-tree package config.
set(Cipher_INSTALL_LIBDIR          "${CMAKE_INSTALL_LIBDIR}")
set(Cipher_INSTALL_BINDIR          "${CMAKE_INSTALL_BINDIR}")
set(Cipher_INSTALL_INCLUDEDIR      "${CMAKE_INSTALL_INCLUDEDIR}")
set(Cipher_FULL_INSTALL_LIBDIR     "${CMAKE_INSTALL_FULL_LIBDIR}")
set(Cipher_FULL_INSTALL_BINDIR     "${CMAKE_INSTALL_FULL_BINDIR}")
set(Cipher_FULL_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_FULL_INCLUDEDIR}")

# The shared libraries are installed side by side; resolve their dependencies relative to the
# loading library so a relocated installation does not keep pointing at the old prefix.
if(APPLE)
    set(Cipher_INSTALL_RPATH "@loader_path")
elseif(UNIX)
    set(Cipher_INSTALL_RPATH "$ORIGIN")
endif()

message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX} (change with -DCMAKE_INSTALL_PREFIX=<path>)")
set(CMAKE_INSTALL_MESSAGE LAZY)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

# uninstall: removes everything listed in install_manifest.txt
add_custom_target(uninstall
    COMMAND ${PROJECT_SOURCE_DIR}/tools/uninstall.sh
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    COMMENT "Uninstalling the files listed in install_manifest.txt"
    USES_TERMINAL)
