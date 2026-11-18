#
# Benchmarks built on google-benchmark; one executable per source file in <build>/bin/bench.
#

set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(${CIPHER_EXTERN_DIR}/google-benchmark ${PROJECT_BINARY_DIR}/extern/google-benchmark EXCLUDE_FROM_ALL)

set(bench_flags -DHAVE_STD_REGEX -DHAVE_STEADY_CLOCK -DNDEBUG -falign-functions=64 -falign-loops=32)
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    list(APPEND bench_flags -Wno-unused-but-set-variable)
endif()

file(GLOB bench_sources CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
cipher_add_programs(all_benchmarks MODULE fhe OUTPUT bench SOURCES ${bench_sources}
                    INCLUDES ${CIPHER_EXTERN_DIR}/google-benchmark/include
                             ${CIPHER_EXTERN_DIR}/google-test/googletest/include
                    LIBS benchmark)
foreach(src IN LISTS bench_sources)
    get_filename_component(exe ${src} NAME_WE)
    target_compile_options(${exe} PRIVATE ${bench_flags})
endforeach()
