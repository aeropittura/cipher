#
# Example programs (CIPHER_BUILD_EXAMPLES) and extra/experimental programs (CIPHER_BUILD_EXTRAS).
# Each source file becomes one executable named after the file, under <build>/bin/examples/...
#

if(CIPHER_BUILD_EXAMPLES)
    file(GLOB core_examples CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/core/*.cpp)
    set(skip "")
    if(NOT CIPHER_WITH_OPENMP)
        message(STATUS "Skipping the 'parallel' example because CIPHER_WITH_OPENMP=OFF")
        set(skip parallel)
    endif()
    cipher_add_programs(core_examples MODULE core OUTPUT examples/core SOURCES ${core_examples} SKIP ${skip})

    # scheme_switching_serial shares its data (de)serializer with the unit tests.
    set(CIPHER_PROGRAM_EXTRA_SOURCES_scheme_switching_serial
        ${PROJECT_SOURCE_DIR}/tests/fhe/support/scheme_switching_data.cpp)
    file(GLOB fhe_examples CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/fhe/*.cpp)
    cipher_add_programs(fhe_examples MODULE fhe OUTPUT examples/fhe SOURCES ${fhe_examples}
                        INCLUDES ${PROJECT_SOURCE_DIR}/tests)

    file(GLOB boolean_examples CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/boolean/*.cpp)
    cipher_add_programs(boolean_examples MODULE boolean OUTPUT examples/boolean SOURCES ${boolean_examples})
    file(GLOB boolean_pke_examples CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/boolean/pke/*.cpp)
    cipher_add_programs(boolean_examples MODULE boolean OUTPUT examples/boolean/pke SOURCES ${boolean_pke_examples})

    add_custom_target(all_examples DEPENDS core_examples fhe_examples boolean_examples)
endif()

if(CIPHER_BUILD_EXTRAS)
    file(GLOB core_extras CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/extras/core/*.cpp)
    cipher_add_programs(core_extras MODULE core OUTPUT extras/core SOURCES ${core_extras})
    file(GLOB fhe_extras CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/extras/fhe/*.cpp)
    cipher_add_programs(fhe_extras MODULE fhe OUTPUT extras/fhe SOURCES ${fhe_extras})
    add_custom_target(all_extras DEPENDS core_extras fhe_extras)
endif()
