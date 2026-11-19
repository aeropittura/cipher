//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  common unit test definitions
 */

// Should we move file location?

#ifndef CIPHER_TESTS_CORE_TEST_DEFS_H_
#define CIPHER_TESTS_CORE_TEST_DEFS_H_

#include "cipher/config.h"

// COMMON TESTING DEFINITIONS
extern bool test_b2;
extern bool test_b4;
extern bool test_b6;
extern bool test_native;

// macros for unit testing

#define RUN_NATIVE_BACKENDS_INT(FUNCTION, MESSAGE) \
    if (test_native)                               \
        FUNCTION<NativeInteger>("NativeInteger " MESSAGE);
#define RUN_NATIVE_BACKENDS(FUNCTION, MESSAGE) \
    if (test_native)                           \
        FUNCTION<NativeVector>("NativeVector " MESSAGE);
#define RUN_NATIVE_POLYS(FUNCTION, MESSAGE) \
    if (test_native)                        \
        FUNCTION<NativePoly>("NativePoly " MESSAGE);

#ifdef CIPHER_WITH_BE2
    #define RUN_BIG_BACKENDS_INT2(FUNCTION, MESSAGE) \
        if (test_b2)                                 \
            FUNCTION<M2Integer>("BE2Integer " MESSAGE);
    #define RUN_BIG_BACKENDS2(FUNCTION, MESSAGE) \
        if (test_b2)                             \
            FUNCTION<M2Vector>("BE2Vector " MESSAGE);
    #define RUN_BIG_POLYS2(FUNCTION, MESSAGE) \
        if (test_b2)                          \
            FUNCTION<M2Poly>("BE2Poly " MESSAGE);
    #define RUN_BIG_RNS_POLYS2(FUNCTION, MESSAGE) \
        if (test_b2)                              \
            FUNCTION<M2RnsPoly>("BE2RnsPoly " MESSAGE);
#else
    #define RUN_BIG_BACKENDS_INT2(FUNCTION, MESSAGE)
    #define RUN_BIG_BACKENDS2(FUNCTION, MESSAGE)
    #define RUN_BIG_POLYS2(FUNCTION, MESSAGE)
    #define RUN_BIG_RNS_POLYS2(FUNCTION, MESSAGE)
#endif

#ifdef CIPHER_WITH_BE4
    #define RUN_BIG_BACKENDS_INT4(FUNCTION, MESSAGE) \
        if (test_b4)                                 \
            FUNCTION<M4Integer>("BE4Integer " MESSAGE);
    #define RUN_BIG_BACKENDS4(FUNCTION, MESSAGE) \
        if (test_b4)                             \
            FUNCTION<M4Vector>("BE4Vector " MESSAGE);
    #define RUN_BIG_POLYS4(FUNCTION, MESSAGE) \
        if (test_b4)                          \
            FUNCTION<M4Poly>("BE4Poly " MESSAGE);
    #define RUN_BIG_RNS_POLYS4(FUNCTION, MESSAGE) \
        if (test_b4)                              \
            FUNCTION<M4RnsPoly>("BE4RnsPoly " MESSAGE);
#else
    #define RUN_BIG_BACKENDS_INT4(FUNCTION, MESSAGE)
    #define RUN_BIG_BACKENDS4(FUNCTION, MESSAGE)
    #define RUN_BIG_POLYS4(FUNCTION, MESSAGE)
    #define RUN_BIG_RNS_POLYS4(FUNCTION, MESSAGE)
#endif

#ifdef CIPHER_WITH_NTL
    #define RUN_BIG_BACKENDS_INT6(FUNCTION, MESSAGE) \
        if (test_b6)                                 \
            FUNCTION<M6Integer>("BE6Integer " MESSAGE);
    #define RUN_BIG_BACKENDS6(FUNCTION, MESSAGE) \
        if (test_b6)                             \
            FUNCTION<M6Vector>("BE6Vector " MESSAGE);
    #define RUN_BIG_POLYS6(FUNCTION, MESSAGE) \
        if (test_b6)                          \
            FUNCTION<M6Poly>("BE6Poly " MESSAGE);
    #define RUN_BIG_RNS_POLYS6(FUNCTION, MESSAGE) \
        if (test_b6)                              \
            FUNCTION<M6RnsPoly>("BE6RnsPoly " MESSAGE);
#else
    #define RUN_BIG_BACKENDS_INT6(FUNCTION, MESSAGE)
    #define RUN_BIG_BACKENDS6(FUNCTION, MESSAGE)
    #define RUN_BIG_POLYS6(FUNCTION, MESSAGE)
    #define RUN_BIG_RNS_POLYS6(FUNCTION, MESSAGE)
#endif

#define RUN_BIG_BACKENDS_INT(FUNCTION, MESSAGE)                                        \
    {RUN_BIG_BACKENDS_INT2(FUNCTION, MESSAGE) RUN_BIG_BACKENDS_INT4(FUNCTION, MESSAGE) \
             RUN_BIG_BACKENDS_INT6(FUNCTION, MESSAGE)}
#define RUN_BIG_BACKENDS(FUNCTION, MESSAGE) \
    {RUN_BIG_BACKENDS2(FUNCTION, MESSAGE) RUN_BIG_BACKENDS4(FUNCTION, MESSAGE) RUN_BIG_BACKENDS6(FUNCTION, MESSAGE)}
#define RUN_BIG_POLYS(FUNCTION, MESSAGE) \
    {RUN_BIG_POLYS2(FUNCTION, MESSAGE) RUN_BIG_POLYS4(FUNCTION, MESSAGE) RUN_BIG_POLYS6(FUNCTION, MESSAGE)}
#define RUN_BIG_RNS_POLYS(FUNCTION, MESSAGE) \
    {RUN_BIG_RNS_POLYS2(FUNCTION, MESSAGE) RUN_BIG_RNS_POLYS4(FUNCTION, MESSAGE) RUN_BIG_RNS_POLYS6(FUNCTION, MESSAGE)}

#define RUN_ALL_BACKENDS_INT(FUNCTION, MESSAGE) \
    {RUN_BIG_BACKENDS_INT(FUNCTION, MESSAGE) RUN_NATIVE_BACKENDS_INT(FUNCTION, MESSAGE)}

#define RUN_ALL_BACKENDS(FUNCTION, MESSAGE) {RUN_BIG_BACKENDS(FUNCTION, MESSAGE) RUN_NATIVE_BACKENDS(FUNCTION, MESSAGE)}

#define RUN_ALL_POLYS(FUNCTION, MESSAGE) {RUN_BIG_POLYS(FUNCTION, MESSAGE) RUN_NATIVE_POLYS(FUNCTION, MESSAGE)}

#endif  // CIPHER_TESTS_CORE_TEST_DEFS_H_
