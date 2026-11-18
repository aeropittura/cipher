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

#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>

#include "include/gtest/gtest.h"
#include "cipher/ring/backend.h"
#include "cipher/math/distributions.h"
#include "cipher/math/backend.h"
#include "cipher/math/number_theory.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/utilities.h"

using namespace cipher;

/************************************************
 *	TESTING Modular operations for 128-bit backend
 ************************************************/
#if CIPHER_NATIVE_INT == 128
TEST(UT128, modular_operations) {
    native_int::NativeInteger modulus = ((native_int::NativeInteger(1) << 120) + native_int::NativeInteger(123456789));
    native_int::NativeInteger mu = modulus.compute_mu();

    native_int::NativeInteger a = (native_int::NativeInteger(1) << 110) + native_int::NativeInteger(1234);
    native_int::NativeInteger b = (native_int::NativeInteger(1) << 115) + native_int::NativeInteger(6789);

    native_int::NativeInteger c = (native_int::NativeInteger(1) << 120) + native_int::NativeInteger(6);

    native_int::NativeInteger result = a;

    result.mod_mul_eq(b, modulus, mu);

    EXPECT_EQ(BigInteger("784483038650039308657432244878529921"), BigInteger(result)) << "Failure in ModMulEq";

    result = a.mod_mul(b, modulus, mu);

    EXPECT_EQ(BigInteger("784483038650039308657432244878529921"), BigInteger(result)) << "Failure in ModMul";

    result = a.mod_mul_fast(b, modulus, mu);

    EXPECT_EQ(BigInteger("784483038650039308657432244878529921"), BigInteger(result)) << "Failure in ModMulFast";

    result = a;

    result.mod_mul_fast_eq(b, modulus, mu);

    EXPECT_EQ(BigInteger("784483038650039308657432244878529921"), BigInteger(result)) << "Failure in ModMulFastEq";

    native_int::NativeInteger precon = b.prep_mod_mul_const(modulus);

    result = a.mod_mul_fast_const(b, modulus, precon);

    EXPECT_EQ(BigInteger("784483038650039308657432244878529921"), BigInteger(result)) << "Failure in ModMulFastConst";

    result = a;

    result.mod_mul_fast_const_eq(b, modulus, precon);

    EXPECT_EQ(BigInteger("784483038650039308657432244878529921"), BigInteger(result)) << "Failure in ModMulFastConstEq";

    result = a.mod_exp(b, modulus);

    EXPECT_EQ(BigInteger("420836984722658338771647831749821018"), BigInteger(result)) << "Failure in ModExp";

    result = a;

    result.mod_exp_eq(b, modulus);

    EXPECT_EQ(BigInteger("420836984722658338771647831749821018"), BigInteger(result)) << "Failure in ModExpEq";

    result = a.mod_add_fast(c, modulus);

    EXPECT_EQ(BigInteger("1298074214633706907132623958849475"), BigInteger(result)) << "Failure in ModAddFast";

    result = a.mod_sub_fast(c, modulus);

    EXPECT_EQ(BigInteger("1298074214633706907132624205763041"), BigInteger(result)) << "Failure in ModSubFast";

    result = a.mod_inverse(modulus);

    EXPECT_EQ(BigInteger("859455677183853192994953853474516202"), BigInteger(result)) << "Failure in ModInverse";
}

TEST(UT128, NTT_operations) {
    uint32_t m1 = 16;
    uint32_t bits = 100;

    auto x1p = std::make_shared<NativePolyParams>(m1, bits);
    auto x2p = std::make_shared<NativePolyParams>(m1 / 2, bits);

    NativePoly x1(x1p, Format::COEFFICIENT);
    x1 = {431, 3414, 1234, 7845, 2145, 7415, 5471, 8452};

    NativePoly x2(x2p, Format::COEFFICIENT);
    x2 = {4127, 9647, 1987, 5410};

    NativePoly x1_clone(x1);
    NativePoly x2_clone(x2);

    x1.switch_format();
    x2.switch_format();
    x1.switch_format();
    x2.switch_format();

    EXPECT_EQ(x1, x1_clone) << "Failure in NTT test #1";
    EXPECT_EQ(x2, x2_clone) << "Failure in NTT test #2";
}

#endif
