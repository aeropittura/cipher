#
# Template for a project that uses an installed Cipher.
#
#   cmake -S . -B build [-DCMAKE_PREFIX_PATH=<Cipher install prefix>] [-DUSE_STATIC=ON]
#   cmake --build build
#
cmake_minimum_required(VERSION 3.16.3)
project(demo CXX)
set(CMAKE_CXX_STANDARD 17)
option(USE_STATIC "Link the static Cipher libraries" OFF)

find_package(Cipher CONFIG REQUIRED)
message(STATUS "Cipher ${Cipher_VERSION_STRING}: headers in ${Cipher_INCLUDE}, libraries in ${Cipher_LIBDIR}")
message(STATUS "Cipher native integer size: ${Cipher_NATIVE_SIZE}, math backend: ${Cipher_MATH_BACKEND}")

# Cipher was compiled with these flags (OpenMP, math backend, ...); reuse them for consistency.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${Cipher_CXX_FLAGS}")
if(Cipher_OPENMP_INCLUDES)
    include_directories(${Cipher_OPENMP_INCLUDES})
    link_directories(${Cipher_OPENMP_LIBRARIES})
endif()
if(UNIX AND NOT APPLE)
    add_link_options(-Wl,--no-as-needed)
endif()

if(USE_STATIC)
    set(CIPHER_LIB Cipher::fhe_static)
else()
    set(CIPHER_LIB Cipher::fhe)
endif()

### Add your executables here, for example:
### add_executable(demo demo.cpp)
### target_link_libraries(demo PRIVATE ${CIPHER_LIB})
