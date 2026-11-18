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

#include <cmath>
#include <cstdint>
#include <string>

#include "cipher/boolean/context.h"
#include "gtest/gtest.h"

using namespace cipher;

// ---------------  TESTING METHODS OF FHEW ---------------

// Checks the arbitrary function evaluation
#if CIPHER_NATIVE_INT != 32
TEST(UnitTestFHEWGINX, EvalArbFunc) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, true, 12);
    auto sk = cc.key_gen();
    cc.bt_key_gen(sk);
    uint32_t p = cc.get_max_plaintext_space().convert_to_int();
    auto fp = [](NativeInteger m, NativeInteger p1) -> NativeInteger {
        if (m < p1)
            return (m * m * m) % p1;
        else
            return ((m - p1 / 2) * (m - p1 / 2) * (m - p1 / 2)) % p1;
    };
    auto lut = cc.generate_lut_via_function(fp, p);

    for (uint32_t i = 0; i < p; ++i) {
        auto ct1 = cc.encrypt(sk, i, LARGE_DIM, p);

        auto ct_cube = cc.eval_func(ct1, lut);

        LwePlaintext result;

        cc.decrypt(sk, ct_cube, &result, p);
        // std::cerr << ", i: " << i << ", f=" << fp(i, p).convert_to_int() << ", r=" << result << std::endl;
        std::string failed = "Arbitrary Function Evaluation failed";
        EXPECT_EQ(LwePlaintext(fp(i, p).convert_to_int()), result) << failed;
    }
}

// Checks the rounding down evaluation
TEST(UnitTestFHEWGINX, EvalFloorFunc) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, false, 12);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk);

    int p = cc.get_max_plaintext_space().convert_to_int();  // Obtain the maximum plaintext space

    for (int i = p / 2 - 3; i < p / 2 + 5; ++i) {
        auto ct1 = cc.encrypt(sk, i, LARGE_DIM, p);

        // round by one bit.
        auto ct_rounded = cc.eval_floor(ct1, 1);

        LwePlaintext result;

        cc.decrypt(sk, ct_rounded, &result, p / 2);
        //  std::cerr << "i: " << i << ", f=" << (i / 2) << ", r=" << result << std::endl;
        std::string failed = "Floor Function Evalution failed";
        EXPECT_EQ(LwePlaintext(i / 2), result) << failed;
    }
}

// Checks the sign evaluation
TEST(UnitTestFHEWGINX, EvalSignFuncTime) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, false, 29, 0, GINX, true);

    uint32_t Q = 1 << 29;
    int q = 4096;
    int factor = 1 << int(29 - std::log2(q));
    int p = cc.get_max_plaintext_space().convert_to_int();
    auto sk = cc.key_gen();
    cc.bt_key_gen(sk);

    std::string failed = "Large Precision Sign Evalution failed";

    for (int i = 0; i < 8; ++i) {
        auto ct1 = cc.encrypt(sk, p * factor / 2 + i - 3, LARGE_DIM, p * factor, Q);
        ct1 = cc.eval_sign(ct1);
        LwePlaintext result;
        cc.decrypt(sk, ct1, &result, 2);
        // std::cerr << "i: " << i << ", f=" << (i >= 3) << ", r=" << result << std::endl;
        EXPECT_EQ(LwePlaintext(i >= 3), result) << failed;
    }
}

// Checks the sign evaluation
TEST(UnitTestFHEWGINX, EvalSignFuncSpace) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, false, 29, 0, GINX, false);

    uint32_t Q = 1 << 29;
    int q = 4096;
    int factor = 1 << int(29 - std::log2(q));
    int p = cc.get_max_plaintext_space().convert_to_int();
    auto sk = cc.key_gen();
    cc.bt_key_gen(sk);

    std::string failed = "Large Precision Sign Evalution failed";

    for (int i = 0; i < 8; ++i) {
        auto ct1 = cc.encrypt(sk, p * factor / 2 + i - 3, LARGE_DIM, p * factor, Q);
        ct1 = cc.eval_sign(ct1);
        LwePlaintext result;
        cc.decrypt(sk, ct1, &result, 2);
        EXPECT_EQ(LwePlaintext(i >= 3), result) << failed;
    }
}

// Checks the digit decomposition evaluation
TEST(UnitTestFHEWGINX, EvalDigitDecompTime) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, false, 29, 0, GINX, true);
    uint32_t Q = 1 << 29;

    int basic = 4096;                                        // q
    int factor = 1 << int(std::log2(Q) - std::log2(basic));  // Q/q
    uint64_t p_basic = cc.get_max_plaintext_space().convert_to_int();
    uint64_t P = p_basic * factor;
    auto st = P / 2 - 3;
    // Generate the secret key
    auto sk = cc.key_gen();
    cc.bt_key_gen(sk);
    std::string failed = "Large Precision Ciphertext Decomposition failed";

    // digit decomposes values starting with st upto st + 7 and checks every digit of each decomposition
    for (uint64_t i = st; i < st + 8; ++i) {
        auto ct1 = cc.encrypt(sk, i, LARGE_DIM, p_basic * factor, Q);

        auto decomp = cc.eval_decomp(ct1);
        EXPECT_EQ(size_t(std::ceil(std::log(factor) / std::log(p_basic)) + 1), decomp.size()) << failed;

        auto p_basicdecrypt = p_basic;
        LwePlaintext result;
        for (size_t j = 0; j < decomp.size(); ++j) {
            ct1 = decomp[j];

            if (j == decomp.size() - 1) {
                // after every evalfloor, the least significant digit is dropped so the last modulus is computed as log p = (log P) mod (log get_max_plaintext_space)
                auto logp = get_msb(P - 1) % get_msb(p_basic - 1);
                p_basicdecrypt = 1 << logp;
            }
            cc.decrypt(sk, ct1, &result, p_basicdecrypt);

            if (i < st + 3) {
                if (j == 0) {
                    EXPECT_EQ(LwePlaintext(13 + i - st), result) << failed;
                } else if (j == decomp.size() - 1) {
                    EXPECT_EQ(LwePlaintext(0), result) << failed;
                } else {
                    EXPECT_EQ(LwePlaintext(15), result) << failed;
                }
            } else {
                if (j == 0) {
                    EXPECT_EQ(LwePlaintext(0 + i - (st + 3)), result) << failed;
                } else if (j == decomp.size() - 1) {
                    EXPECT_EQ(LwePlaintext(1), result) << failed;
                } else {
                    EXPECT_EQ(LwePlaintext(0), result) << failed;
                }
            }
        }
    }
}

// Checks the sign evaluation
TEST(UnitTestFHEWGINX, EvalDigitDecompSpace) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, false, 29, 0, GINX, false);
    uint32_t Q = 1 << 29;

    int basic = 4096;                                        // q
    int factor = 1 << int(std::log2(Q) - std::log2(basic));  // Q/q
    uint64_t p_basic = cc.get_max_plaintext_space().convert_to_int();
    uint64_t P = p_basic * factor;
    auto st = P / 2 - 3;
    // Generate the secret key
    auto sk = cc.key_gen();
    cc.bt_key_gen(sk);
    std::string failed = "Large Precision Ciphertext Decomposition failed";

    for (uint64_t i = st; i < st + 8; ++i) {
        auto ct1 = cc.encrypt(sk, i, LARGE_DIM, p_basic * factor, Q);

        auto decomp = cc.eval_decomp(ct1);
        EXPECT_EQ(size_t(std::ceil(std::log(factor) / std::log(p_basic)) + 1), decomp.size()) << failed;

        auto p_basicdecrypt = p_basic;
        LwePlaintext result;
        for (size_t j = 0; j < decomp.size(); ++j) {
            ct1 = decomp[j];

            if (j == decomp.size() - 1) {
                // after every evalfloor, the least significant digit is dropped so the last modulus is computed as log p = (log P) mod (log get_max_plaintext_space)
                auto logp = get_msb(P - 1) % get_msb(p_basic - 1);
                p_basicdecrypt = 1 << logp;
            }
            cc.decrypt(sk, ct1, &result, p_basicdecrypt);

            if (i < st + 3) {
                if (j == 0) {
                    EXPECT_EQ(LwePlaintext(13 + i - st), result) << failed;
                } else if (j == decomp.size() - 1) {
                    EXPECT_EQ(LwePlaintext(0), result) << failed;
                } else {
                    EXPECT_EQ(LwePlaintext(15), result) << failed;
                }
            } else {
                if (j == 0) {
                    EXPECT_EQ(LwePlaintext(0 + i - (st + 3)), result) << failed;
                } else if (j == decomp.size() - 1) {
                    EXPECT_EQ(LwePlaintext(1), result) << failed;
                } else {
                    EXPECT_EQ(LwePlaintext(0), result) << failed;
                }
            }
        }
    }
}
#endif
