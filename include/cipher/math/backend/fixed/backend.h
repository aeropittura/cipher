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
  This file contains the definitions for CIPHER_MATH_BACKEND 2 also known as the fixed multi-precision backend.
  This backend supports fixed bitwidths; Uses bigintfxd:: definition as default;
  Implemented as a vector of integers.
  Configurable maximum bit length and type of underlying integer
 */

#ifndef CIPHER_MATH_BACKEND_FIXED_BACKEND_H_
#define CIPHER_MATH_BACKEND_FIXED_BACKEND_H_

#include "cipher/config.h"
#ifdef CIPHER_WITH_BE2

    #include "cipher/math/backend/fixed/mod_vector.h"
    #include "cipher/math/backend/fixed/transform.h"
    #include "cipher/math/backend/fixed/integer.h"

static_assert(fixed_int::DataTypeChecker<integral_dtype>::value, "Data type provided is not supported in BigInteger");

// Global alias for CIPHER_MATH_BACKEND 2 Integer
using M2Integer = fixed_int::BigInteger;

// Global alias for CIPHER_MATH_BACKEND 2 Vector
using M2Vector = fixed_int::BigVector;
#else
using M2Integer = void;
#endif

#endif  // CIPHER_MATH_BACKEND_FIXED_BACKEND_H_
