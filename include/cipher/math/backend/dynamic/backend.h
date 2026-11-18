//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
  This file contains the definitions for CIPHER_MATH_BACKEND 4 also known as the dynamic multi-precision backend.
  This backend supports arbitrary bitwidths; no memory pool is used; can grow up to RAM limitation.
  Configurable type of underlying integer (either 32 or 64 bit)
 */

#ifndef CIPHER_MATH_BACKEND_DYNAMIC_BACKEND_H_
#define CIPHER_MATH_BACKEND_DYNAMIC_BACKEND_H_

#include "cipher/config.h"
#ifdef CIPHER_WITH_BE4

    #include "cipher/math/backend/dynamic/mod_vector.h"  // rings of ubints
    #include "cipher/math/backend/dynamic/transform.h"  // transforms for dynamic
    #include "cipher/math/backend/dynamic/integer.h"      // dynamically sized unsigned big integers or ubints

// Global alias for CIPHER_MATH_BACKEND 4 Integer
using M4Integer = dynamic_int::BigInteger;

// Global alias for CIPHER_MATH_BACKEND 4 Vector
using M4Vector = dynamic_int::BigVector;
#else
using M4Integer = void;
#endif

#endif  // CIPHER_MATH_BACKEND_DYNAMIC_BACKEND_H_
