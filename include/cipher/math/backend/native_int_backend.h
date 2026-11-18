//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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

#ifndef CIPHER_MATH_BACKEND_NATIVE_INT_BACKEND_H_
#define CIPHER_MATH_BACKEND_NATIVE_INT_BACKEND_H_

#include "cipher/math/backend/basic_int.h"
#include "cipher/math/backend/native/mod_vector.h"
#include "cipher/math/backend/native/transform.h"
#include "cipher/math/backend/native/integer.h"

template <typename VecType>
using NatChineseRemainderTransformFtt = native_int::ChineseRemainderTransformFttNat<VecType>;
template <typename VecType>
using NatChineseRemainderTransformArb = native_int::ChineseRemainderTransformArbNat<VecType>;

namespace cipher {

using NativeInteger = native_int::NativeInteger;
using NativeVector = native_int::NativeVector;

using NativeInteger32 = native_int::NativeInteger32;
using NativeVector32 = native_int::NativeVector32;

}  // namespace cipher

using NativeInteger = cipher::NativeInteger;
using NativeVector = cipher::NativeVector;

using NativeInteger32 = cipher::NativeInteger32;
using NativeVector32 = cipher::NativeVector32;

#endif  // CIPHER_MATH_BACKEND_NATIVE_INT_BACKEND_H_
