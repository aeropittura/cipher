#
# Installation of headers and the CMake package (CipherConfig.cmake, CipherTargets.cmake).
#

install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/cipher DESTINATION ${Cipher_INSTALL_INCLUDEDIR})
install(FILES ${PROJECT_BINARY_DIR}/include/cipher/config.h DESTINATION ${Cipher_INSTALL_INCLUDEDIR}/cipher)
install(DIRECTORY ${CIPHER_CEREAL_INCLUDE_DIR}/ DESTINATION ${Cipher_INSTALL_INCLUDEDIR}/cipher/extern)
# The test support headers are installed for downstream projects that reuse them.
install(DIRECTORY ${PROJECT_SOURCE_DIR}/tests/fhe/support/
        DESTINATION ${Cipher_INSTALL_INCLUDEDIR}/cipher/testing/fhe/support FILES_MATCHING PATTERN "*.h")

get_property(_cipher_libs GLOBAL PROPERTY CIPHER_LIBRARY_TARGETS)
set(Cipher_SHARED_LIBS "")
set(Cipher_STATIC_LIBS "")
foreach(lib IN LISTS _cipher_libs)
    if(lib MATCHES "_static$")
        list(APPEND Cipher_STATIC_LIBS ${lib})
    else()
        list(APPEND Cipher_SHARED_LIBS ${lib})
    endif()
endforeach()
set(Cipher_PACKAGE_LIBS ${Cipher_STATIC_LIBS} ${Cipher_SHARED_LIBS})

export(EXPORT CipherTargets NAMESPACE Cipher:: FILE "${PROJECT_BINARY_DIR}/CipherTargets.cmake")

# Build-tree package config: absolute paths into the install locations, as before.
set(PACKAGE_INIT "")
set(PACKAGE_Cipher_INSTALL_INCLUDEDIR "${Cipher_FULL_INSTALL_INCLUDEDIR}")
set(PACKAGE_Cipher_INSTALL_LIBDIR "${Cipher_FULL_INSTALL_LIBDIR}")
set(PACKAGE_Cipher_INSTALL_BINDIR "${Cipher_FULL_INSTALL_BINDIR}")
configure_file(${PROJECT_SOURCE_DIR}/cmake/CipherConfig.cmake.in "${PROJECT_BINARY_DIR}/CipherConfig.cmake" @ONLY)

# Install-tree package config: paths relative to the package file, so the install is relocatable.
include(CMakePackageConfigHelpers)
configure_package_config_file(${PROJECT_SOURCE_DIR}/cmake/CipherConfig.cmake.in
    "${PROJECT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CipherConfig.cmake"
    INSTALL_DESTINATION "${Cipher_INSTALL_CMAKEDIR}"
    PATH_VARS Cipher_INSTALL_INCLUDEDIR Cipher_INSTALL_LIBDIR Cipher_INSTALL_BINDIR
    NO_SET_AND_CHECK_MACRO
    NO_CHECK_REQUIRED_COMPONENTS_MACRO)
write_basic_package_version_file("${PROJECT_BINARY_DIR}/CipherConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion)

install(FILES
    "${PROJECT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CipherConfig.cmake"
    "${PROJECT_BINARY_DIR}/CipherConfigVersion.cmake"
    DESTINATION "${Cipher_INSTALL_CMAKEDIR}" COMPONENT dev)
install(EXPORT CipherTargets NAMESPACE Cipher:: DESTINATION "${Cipher_INSTALL_CMAKEDIR}" COMPONENT dev)
