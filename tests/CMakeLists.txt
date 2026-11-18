#
# Unit tests: one GoogleTest executable per library module, all sharing tests/main.cpp.
# The executables land in <build>/tests so that test helpers resolving data relative to the
# executable find <build>/data.
#

add_subdirectory(${CIPHER_EXTERN_DIR}/google-test ${PROJECT_BINARY_DIR}/extern/google-test EXCLUDE_FROM_ALL)
# Older googletest trips -Werror on "maybe uninitialized"; keep the warning, drop the error.
foreach(gt IN ITEMS gtest gtest_main)
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${gt} PRIVATE -Wno-error=maybe-uninitialized)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(${gt} PRIVATE -Wno-uninitialized)
    endif()
endforeach()

set(CIPHER_GTEST_INCLUDE_DIRS
    ${CIPHER_EXTERN_DIR}/google-test/googletest
    ${CIPHER_EXTERN_DIR}/google-test/googletest/include
    CACHE INTERNAL "")

enable_testing()

function(cipher_add_test_suite module)
    cmake_parse_arguments(ARG "RECURSE" "" "DIRS" ${ARGN})
    set(sources "")
    foreach(dir IN LISTS ARG_DIRS)
        if(ARG_RECURSE)
            file(GLOB_RECURSE found CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${dir}/*.cpp)
        else()
            file(GLOB found CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${dir}/*.cpp)
        endif()
        list(APPEND sources ${found})
    endforeach()
    set(exe ${module}_tests)
    add_executable(${exe} ${sources} ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)
    set_target_properties(${exe} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/tests)
    target_include_directories(${exe} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CIPHER_GTEST_INCLUDE_DIRS})
    cipher_program_libs(libs ${module})
    target_link_libraries(${exe} PRIVATE gtest gtest_main ${libs})
    add_test(NAME ${module} COMMAND ${exe} WORKING_DIRECTORY ${PROJECT_BINARY_DIR})
    add_custom_target(test_${module}
        COMMAND $<TARGET_FILE:${exe}>
        DEPENDS ${exe}
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
        USES_TERMINAL)
endfunction()

if(CIPHER_NATIVE_SIZE EQUAL 32)
    message(STATUS "core and fhe tests are not built for CIPHER_NATIVE_SIZE=32")
    add_executable(core_tests ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)
    add_executable(fhe_tests ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)
    foreach(t IN ITEMS core fhe)
        set_target_properties(${t}_tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/tests)
        target_include_directories(${t}_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CIPHER_GTEST_INCLUDE_DIRS})
        cipher_program_libs(libs ${t})
        target_link_libraries(${t}_tests PRIVATE gtest gtest_main ${libs})
    endforeach()
else()
    cipher_add_test_suite(core DIRS core)
    cipher_add_test_suite(fhe RECURSE DIRS fhe)
endif()
cipher_add_test_suite(boolean DIRS boolean)

add_custom_target(all_tests DEPENDS core_tests fhe_tests boolean_tests)

# check: build and run every suite, continuing past failures in core and fhe (as before).
add_custom_target(check
    DEPENDS core_tests fhe_tests boolean_tests
    COMMAND echo core: && $<TARGET_FILE:core_tests> -t || true
    COMMAND echo fhe: && $<TARGET_FILE:fhe_tests> -t || true
    COMMAND echo boolean: && $<TARGET_FILE:boolean_tests> -t
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    USES_TERMINAL)
