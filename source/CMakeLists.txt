#
# The three library modules:
#   core    - integer arithmetic, number theory, polynomial rings, sampling and utilities
#   boolean - FHEW/TFHE-style boolean and small-integer FHE (depends on core)
#   fhe     - the BFV, BGV and CKKS RNS schemes (depends on core and boolean)
#

file(GLOB_RECURSE CIPHER_CORE_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/math/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ring/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/util/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/util/*.c)
file(GLOB CIPHER_BOOLEAN_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/boolean/*.cpp)
file(GLOB_RECURSE CIPHER_FHE_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/fhe/*.cpp)

cipher_add_module(core    SOURCES ${CIPHER_CORE_SOURCES})
cipher_add_module(boolean SOURCES ${CIPHER_BOOLEAN_SOURCES} DEPENDS core)
cipher_add_module(fhe     SOURCES ${CIPHER_FHE_SOURCES}     DEPENDS core boolean)

# When the built-in diagnostic sink is kept out of the library, in-tree programs link this
# interface library instead so that both configurations build and run.
if(NOT CIPHER_WITH_DEFAULT_DIAGNOSTIC_SINK)
    add_library(cipher_diagnostic_sink INTERFACE)
    target_sources(cipher_diagnostic_sink INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/util/diagnostic_output.cpp)
    target_compile_definitions(cipher_diagnostic_sink INTERFACE WITH_DEFAULT_DIAGNOSTIC_SINK)
endif()

get_property(_cipher_libs GLOBAL PROPERTY CIPHER_LIBRARY_TARGETS)
add_custom_target(all_libraries DEPENDS ${_cipher_libs})
