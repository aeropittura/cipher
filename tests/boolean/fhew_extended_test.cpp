//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2024, NJIT, Duality Technologies Inc. and other contributors
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
#include <sstream>
#include <utility>
#include <vector>

#include "cipher/boolean/context.h"
#include "gtest/gtest.h"

using namespace cipher;

TEST(UNITTestFHEWExtended, EvalBinGate2) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, GINX);

    auto sk = cc.key_gen();
    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto pk = cc.get_public_key();
    auto Q = cc.get_params()->get_lwe_params()->get_Q();

    auto ct_small = cc.encrypt(pk, 1, SMALL_DIM, 4);
    EXPECT_NE(Q, ct_small->get_modulus());

    auto ct_large = cc.encrypt(pk, 1, LARGE_DIM, 4);
    EXPECT_EQ(Q, ct_large->get_modulus());

    auto ct11 = cc.eval_bin_gate(OR, ct_small, ct_large, true);
    EXPECT_EQ(Q, ct11->get_modulus());

    auto ct12 = cc.eval_bin_gate(AND, ct_large, ct_small, true);
    EXPECT_EQ(Q, ct12->get_modulus());

    auto ct2 = cc.eval_bin_gate(NAND, ct11, ct12, false);
    EXPECT_NE(Q, ct2->get_modulus());
    EXPECT_EQ(4, ct2->get_pt_modulus());

    LwePlaintext result;
    cc.decrypt(sk, ct2, &result);
    EXPECT_EQ(0, result);
}

TEST(UNITTestFHEWExtended, EvalBinGate3) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, GINX);

    auto sk = cc.key_gen();
    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto pk = cc.get_public_key();
    auto Q = cc.get_params()->get_lwe_params()->get_Q();

    auto ct_small = cc.encrypt(pk, 1, SMALL_DIM, 6);
    EXPECT_NE(Q, ct_small->get_modulus());

    auto ct_large = cc.encrypt(pk, 1, LARGE_DIM, 6);
    EXPECT_EQ(Q, ct_large->get_modulus());

    std::vector<LweCiphertext> v{ct_small, ct_large, cc.encrypt(pk, 0, SMALL_DIM, 6)};

    auto ct11 = cc.eval_bin_gate(OR3, v, true);
    EXPECT_EQ(Q, ct11->get_modulus());
    EXPECT_EQ(6, ct11->get_pt_modulus());

    auto ct12 = cc.eval_bin_gate(AND3, v, true);
    EXPECT_EQ(Q, ct12->get_modulus());
    EXPECT_EQ(6, ct12->get_pt_modulus());

    auto ct2 = cc.eval_bin_gate(NAND, ct11, ct12, false);
    EXPECT_NE(Q, ct2->get_modulus());
    EXPECT_EQ(4, ct2->get_pt_modulus());

    LwePlaintext result;
    cc.decrypt(sk, ct2, &result);
    EXPECT_EQ(1, result);
}

TEST(UNITTestFHEWExtended, EvalBinGate4) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, GINX);

    auto sk = cc.key_gen();
    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto pk = cc.get_public_key();
    auto Q = cc.get_params()->get_lwe_params()->get_Q();

    auto ct_small = cc.encrypt(pk, 1, SMALL_DIM, 8);
    EXPECT_NE(Q, ct_small->get_modulus());

    auto ct_large = cc.encrypt(pk, 1, LARGE_DIM, 8);
    EXPECT_EQ(Q, ct_large->get_modulus());

    std::vector<LweCiphertext> v{ct_small, ct_large, cc.encrypt(pk, 0, SMALL_DIM, 8), cc.encrypt(pk, 1, LARGE_DIM, 8)};

    auto ct11 = cc.eval_bin_gate(OR4, v, true);
    EXPECT_EQ(Q, ct11->get_modulus());
    EXPECT_EQ(8, ct11->get_pt_modulus());

    auto ct12 = cc.eval_bin_gate(AND4, v, true);
    EXPECT_EQ(Q, ct12->get_modulus());
    EXPECT_EQ(8, ct12->get_pt_modulus());

    auto ct2 = cc.eval_bin_gate(NAND, ct11, ct12, false);
    EXPECT_NE(Q, ct2->get_modulus());
    EXPECT_EQ(4, ct2->get_pt_modulus());

    LwePlaintext result;
    cc.decrypt(sk, ct2, &result);
    EXPECT_EQ(1, result);
}

TEST(UNITTestFHEWExtended, BootStrap) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, GINX);

    auto sk = cc.key_gen();
    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto pk = cc.get_public_key();
    auto Q = cc.get_params()->get_lwe_params()->get_Q();

    auto ct1 = cc.bootstrap(cc.encrypt(pk, 1, SMALL_DIM, 4), true);
    EXPECT_EQ(Q, ct1->get_modulus());

    auto ct0 = cc.bootstrap(cc.encrypt(pk, 0, LARGE_DIM, 4), true);
    EXPECT_EQ(Q, ct0->get_modulus());
}

// bt_key_gen caches the bootstrapping key per gadget base, but its validity also depends on the
// secret key. A second bt_key_gen with a different key must regenerate, not return the first key.
TEST(UNITTestFHEWExtended, BTKeyGenRegeneratesForNewSecretKey) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(STD128, GINX);

    for (uint32_t round = 0; round < 2; ++round) {
        auto sk = cc.key_gen();
        cc.bt_key_gen(sk);
        for (uint32_t i = 0; i < 4; ++i) {
            uint32_t b0 = i & 0x1, b1 = (i >> 1) & 0x1;
            auto ct = cc.eval_bin_gate(NAND, cc.encrypt(sk, b0), cc.encrypt(sk, b1));
            LwePlaintext result;
            cc.decrypt(sk, ct, &result);
            EXPECT_EQ(static_cast<LwePlaintext>(1 - (b0 & b1)), result)
                    << "NAND(" << b0 << "," << b1 << ") wrong for secret key " << (round + 1);
        }
    }
}

// The same, with the time-optimization path, which keeps one key per gadget base.
// Excluded at NATIVE_SIZE=32 as in UnitTestFunc.cpp: the large-precision constructor sets
// q_ks = 1 << 35, which truncates to zero in a 32-bit NativeInteger.
#if CIPHER_NATIVE_INT != 32
TEST(UNITTestFHEWExtended, BTKeyGenRegeneratesForNewSecretKeyTimeOptimization) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, false, 11, 0, GINX, true);

    for (uint32_t round = 0; round < 2; ++round) {
        auto sk = cc.key_gen();
        cc.bt_key_gen(sk);
        for (uint32_t i = 0; i < 4; ++i) {
            uint32_t b0 = i & 0x1, b1 = (i >> 1) & 0x1;
            auto ct = cc.eval_bin_gate(NAND, cc.encrypt(sk, b0), cc.encrypt(sk, b1));
            LwePlaintext result;
            cc.decrypt(sk, ct, &result);
            EXPECT_EQ(static_cast<LwePlaintext>(1 - (b0 & b1)), result)
                    << "NAND(" << b0 << "," << b1 << ") wrong for secret key " << (round + 1);
        }
    }
}
#endif

TEST(UNITTestFHEWExtended, ParamSetNamesRoundTrip) {
    for (int i = 0; i <= static_cast<int>(TOY_MULTI_BASE); ++i) {
        auto set = static_cast<BINFHE_PARAMSET>(i);
        std::ostringstream os;
        os << set;
        EXPECT_NE("UNKNOWN", os.str()) << i;
        EXPECT_EQ(set, convert_to_binfhe_paramset(os.str())) << os.str();
    }
    EXPECT_THROW(convert_to_binfhe_paramset("STD128_NONE"), CipherException);
}

// suffixed sets are bound to their method; unsuffixed sets are tuned for GINX but accept every method
TEST(UNITTestFHEWExtended, MethodParamSetCompatibility) {
    for (auto m : {GINX, AP, LMKCDEY}) {
        for (auto s : {TOY, TOY_MULTI_BASE, MEDIUM, STD128, STD256Q_4, LPF_STD192_3, SIGNED_MOD_TEST})
            EXPECT_NO_THROW(is_method_compatible(m, s)) << m << " " << s;
        if (m != LMKCDEY) {
            EXPECT_THROW(is_method_compatible(m, STD128_LMKCDEY), CipherException) << m;
        }
        if (m != AP) {
            EXPECT_THROW(is_method_compatible(m, STD128_AP), CipherException) << m;
        }
    }
    EXPECT_NO_THROW(is_method_compatible(LMKCDEY, STD128_LMKCDEY));
    EXPECT_NO_THROW(is_method_compatible(AP, STD128_AP));
    EXPECT_THROW(is_method_compatible(INVALID_METHOD, TOY), CipherException);
}

// DM's refresh key holds, at the top digit position of the base-R decomposition of q, only the
// values a coefficient below q can reach; the slots above that extent stay empty
TEST(UNITTestFHEWExtended, RefreshKeyTopPositionCompact) {
    BooleanContextParams params{27, 1024, 64, 1024, 0, 25, 512, 128, 9, UNIFORM_TERNARY, 3.19, {}};
    auto cc = BooleanContext();
    cc.generate_boolean_context(params, AP);
    auto&& rgsw = cc.get_params()->get_ring_gsw_params();
    ASSERT_EQ(2u, rgsw->get_digits_r().size());
    EXPECT_EQ(128u, rgsw->get_digit_extent_r(0));
    EXPECT_EQ(8u, rgsw->get_digit_extent_r(1)) << "q = 1024 in base 128 reaches 8 values at the top position";

    auto sk = cc.key_gen();
    cc.bt_key_gen(sk, SYM_ENCRYPT, /*internal32=*/false);
    const auto& key = cc.get_refresh_key()->get_elements();
    ASSERT_EQ(params.lattice_param, key.size());
    ASSERT_EQ(128u, key[0].size());
    ASSERT_EQ(2u, key[0][1].size());
    EXPECT_EQ(nullptr, key[0][0][0]);
    EXPECT_NE(nullptr, key[0][127][0]);
    EXPECT_NE(nullptr, key[0][7][1]);
    EXPECT_EQ(nullptr, key[0][8][1]) << "rows above the top extent must not be generated";

    for (uint32_t i = 0; i < 4; ++i) {
        uint32_t b0 = i & 0x1, b1 = (i >> 1) & 0x1;
        LwePlaintext result;
        cc.decrypt(sk, cc.eval_bin_gate(NAND, cc.encrypt(sk, b0), cc.encrypt(sk, b1)), &result);
        EXPECT_EQ(static_cast<LwePlaintext>(1 - (b0 & b1)), result) << "NAND(" << b0 << "," << b1 << ")";
    }
}

// TOY, with key_dist left free
static BooleanContextParams toy_params(SecretKeyDist key_dist) {
    return BooleanContextParams{27, 1024, 64, 512, 0, 25, 512, 23, 9, key_dist, 3.19, {}};
}

TEST(UNITTestFHEWExtended, GinxRejectsGaussianSecretKeyDist) {
    auto params = toy_params(GAUSSIAN);
    auto cc = BooleanContext();
    EXPECT_THROW(cc.generate_boolean_context(params, GINX), CipherException);
    EXPECT_NO_THROW(cc.generate_boolean_context(params, AP));
    EXPECT_NO_THROW(cc.generate_boolean_context(params, LMKCDEY));
}

TEST(UNITTestFHEWExtended, ManualContextPropagatesSecretKeyDist) {
    auto Q = last_prime<NativeInteger>(27, 1024);
    auto cc = BooleanContext();
    cc.generate_boolean_context(64, 512, 512, Q, 3.19, 25, 512, 23, GAUSSIAN, LMKCDEY, 9);
    EXPECT_EQ(GAUSSIAN, cc.get_params()->get_lwe_params()->get_key_dist());
    EXPECT_EQ(GAUSSIAN, cc.get_params()->get_ring_gsw_params()->get_key_dist());

    auto cc_ginx = BooleanContext();
    EXPECT_THROW(cc_ginx.generate_boolean_context(64, 512, 512, Q, 3.19, 25, 512, 23, GAUSSIAN, GINX, 9),
                 CipherException);
}

// Excluded at NATIVE_SIZE=32 for the reason given above: the large-precision constructor
// sets q_ks = 1 << 35, which truncates to zero in a 32-bit NativeInteger.
#if CIPHER_NATIVE_INT != 32
TEST(UNITTestFHEWExtended, ArbitraryFunctionContextUnaffected) {
    auto cc = BooleanContext();
    EXPECT_NO_THROW(cc.generate_boolean_context(TOY, false, 11, 0, GINX, false));
    EXPECT_EQ(UNIFORM_TERNARY, cc.get_params()->get_lwe_params()->get_key_dist());
    EXPECT_EQ(UNIFORM_TERNARY, cc.get_params()->get_ring_gsw_params()->get_key_dist());
}
#endif

TEST(UNITTestFHEWExtended, MethodKeyDistCrossProduct) {
    const std::vector<std::pair<BINFHE_METHOD, SecretKeyDist>> supported{{GINX, UNIFORM_TERNARY},
                                                                         {AP, UNIFORM_TERNARY},
                                                                         {LMKCDEY, UNIFORM_TERNARY},
                                                                         {AP, GAUSSIAN},
                                                                         {LMKCDEY, GAUSSIAN}};

    for (const auto& [method, key_dist] : supported) {
        auto cc = BooleanContext();
        cc.generate_boolean_context(toy_params(key_dist), method);
        auto sk = cc.key_gen();
        cc.bt_key_gen(sk);
        for (uint32_t i = 0; i < 4; ++i) {
            uint32_t b0 = i & 0x1, b1 = (i >> 1) & 0x1;
            auto ct = cc.eval_bin_gate(NAND, cc.encrypt(sk, b0), cc.encrypt(sk, b1));
            LwePlaintext result;
            cc.decrypt(sk, ct, &result);
            EXPECT_EQ(static_cast<LwePlaintext>(1 - (b0 & b1)), result)
                    << "NAND(" << b0 << "," << b1 << ") wrong for " << method << " / " << key_dist;
        }
    }
}

TEST(UNITTestFHEWExtended, GinxKeyGenRejectsNonTernarySecret) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(toy_params(UNIFORM_TERNARY), GINX);
    auto&& lwe_params = cc.get_params()->get_lwe_params();
    auto sk = cc.get_lwe_scheme()->key_gen_gaussian(lwe_params->get_n(), lwe_params->get_q_ks());
    EXPECT_THROW(cc.bt_key_gen(sk), CipherException);
}

// Encrypt/Decrypt accumulate the inner product over the whole dimension; holding a ciphertext
// at the ring modulus Q makes dim*Q exceed a 32-bit word, which corrupts the phase while still
// decrypting correctly. Only NATIVE_SIZE=32 is close enough to the bound to trip today.
TEST(UNITTestFHEWExtended, LargeModulusCiphertextPhaseIsClean) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(STD128, GINX);
    auto&& lwe_params = cc.get_params()->get_lwe_params();
    auto Q = lwe_params->get_Q();
    auto sk_n = cc.key_gen_n();

    NativeInteger mu = Q.compute_mu();
    for (uint32_t m = 0; m < 2; ++m) {
        auto ct = cc.encrypt(sk_n, m, LARGE_DIM, 4, Q);
        const auto& a = ct->get_A();
        const auto& s = sk_n->get_element();
        NativeInteger inner(0);
        for (uint32_t i = 0; i < a.get_length(); ++i)
            inner.mod_add_fast_eq(a[i].mod_mul_fast(s[i], Q, mu), Q);
        auto phase = ct->get_B().mod_sub(inner, Q);
        phase.mod_sub_fast_eq(NativeInteger(m) * (Q / NativeInteger(4)), Q);

        auto qi = static_cast<int64_t>(Q.convert_to_int());
        auto err_value = static_cast<int64_t>(phase.convert_to_int());
        if (err_value > qi / 2)
            err_value -= qi;
        EXPECT_LT(err_value < 0 ? -err_value : err_value, 1000) << "phase error " << err_value << " for m=" << m;
    }
}

// binfhe generates a Gaussian secret or a uniform ternary one and nothing else, so any other
// distribution would be silently substituted rather than honoured.
TEST(UNITTestFHEWExtended, RejectsUnsupportedKeyDist) {
    for (auto dist : {SPARSE_TERNARY, SPARSE_ENCAPSULATED}) {
        for (auto method : {GINX, AP, LMKCDEY}) {
            auto cc = BooleanContext();
            EXPECT_THROW(cc.generate_boolean_context(toy_params(dist), method), CipherException)
                    << "keyDist " << dist << ", method " << method;
        }
    }
}

// LMKCDEY sizes its automorphism-key vector by n and indexes it by num_auto_keys, so num_auto_keys
// == n writes one past the end -- a segfault before this was rejected.
TEST(UNITTestFHEWExtended, RejectsNumAutoKeysAtOrAboveLweDimension) {
    auto params = toy_params(UNIFORM_TERNARY);
    ASSERT_EQ(64u, params.lattice_param);

    params.num_auto_keys = params.lattice_param - 1;
    {
        auto cc = BooleanContext();
        EXPECT_NO_THROW(cc.generate_boolean_context(params, LMKCDEY));
    }
    params.num_auto_keys = params.lattice_param;
    {
        auto cc = BooleanContext();
        EXPECT_THROW(cc.generate_boolean_context(params, LMKCDEY), CipherException);
    }
    // the bound is LMKCDEY-only: GINX allocates no automorphism keys
    {
        auto cc = BooleanContext();
        EXPECT_NO_THROW(cc.generate_boolean_context(params, GINX));
    }
}

TEST(UNITTestFHEWExtended, RejectsLweModulusNotDividing2N) {
    auto params = toy_params(UNIFORM_TERNARY);
    ASSERT_EQ(1024u, params.cycl_order);
    params.mod_value = 768;
    for (auto method : {GINX, AP, LMKCDEY}) {
        auto cc = BooleanContext();
        EXPECT_THROW(cc.generate_boolean_context(params, method), CipherException) << "method " << method;
    }
    params.mod_value = 256;
    for (auto method : {GINX, AP, LMKCDEY}) {
        auto cc = BooleanContext();
        EXPECT_NO_THROW(cc.generate_boolean_context(params, method)) << "method " << method;
    }
}

// A ciphertext whose modulus is neither q nor Q passes eval_bin_gate's switch untouched. The
// bootstrap needs it to divide 2N, and the DM and LMKCDEY refresh keys are tied to q itself.
TEST(UNITTestFHEWExtended, BootstrapRejectsForeignCiphertextModulus) {
    for (auto method : {GINX, AP, LMKCDEY}) {
        auto cc = BooleanContext();
        cc.generate_boolean_context(TOY, method);
        auto sk = cc.key_gen();
        cc.bt_key_gen(sk);
        const auto q = cc.get_params()->get_lwe_params()->get_q();
        const auto N = cc.get_params()->get_lwe_params()->get_N();
        ASSERT_EQ(NativeInteger(N), q) << "TOY has q == N";

        auto ct1 = cc.encrypt(sk, 1, SMALL_DIM, 4, 4 * N);
        auto ct2 = cc.encrypt(sk, 1, SMALL_DIM, 4, 4 * N);
        EXPECT_THROW(cc.eval_bin_gate(AND, ct1, ct2), CipherException) << "method " << method << ": modulus above 2N";

        if (method == GINX)
            continue;
        auto ct3 = cc.encrypt(sk, 1, SMALL_DIM, 4, q >> 1);
        auto ct4 = cc.encrypt(sk, 1, SMALL_DIM, 4, q >> 1);
        EXPECT_THROW(cc.eval_bin_gate(AND, ct3, ct4), CipherException) << "method " << method << ": modulus below q";
    }
}

TEST(UNITTestFHEWExtended, KeySwitchRejectsCiphertextAboveKeySwitchingModulus) {
    BooleanContextParams params{27, 1024, 64, 512, 16384, 32, 512, 23, 9, UNIFORM_TERNARY, 3.19, {}};
    auto cc = BooleanContext();
    cc.generate_boolean_context(params, GINX);
    auto&& lwe = cc.get_params()->get_lwe_params();
    ASSERT_LT(lwe->get_digit_extent_ks(lwe->get_digit_count_ks() - 1), lwe->get_base_ks())
            << "top position must be truncated";

    auto sk = cc.key_gen();
    auto sk_n = cc.key_gen_n();
    auto ksk = cc.key_switch_gen(sk, sk_n);
    auto ct_q = cc.encrypt(sk_n, 1, LARGE_DIM, 4, lwe->get_Q());
    EXPECT_THROW(cc.get_lwe_scheme()->key_switch(lwe, ksk, ct_q), CipherException);

    LwePlaintext result;
    cc.decrypt(sk, cc.switch_c_ttoqn(ksk, ct_q), &result);
    EXPECT_EQ(1, static_cast<int>(result));
}

TEST(UNITTestFHEWExtended, LweParamsEqualityCoversKeySwitchingFields) {
    auto Q = last_prime<NativeInteger>(27, 1024);
    LweCryptoParams a(64, 512, 512, Q, 4096, 3.19, 32);
    LweCryptoParams b(64, 512, 512, Q, 4096, 3.19, 32);
    EXPECT_TRUE(a == b);
    LweCryptoParams c(64, 512, 512, Q, 8192, 3.19, 32);
    EXPECT_TRUE(a != c) << "qKS must take part in the comparison";
    LweCryptoParams d(64, 512, 512, Q, 4096, 3.19, 32, GAUSSIAN);
    EXPECT_TRUE(a != d) << "keyDist must take part in the comparison";
}

TEST(UNITTestFHEWExtended, RingGSWParamsEqualityCoversSemanticFields) {
    constexpr uint32_t N = 64;
    constexpr uint32_t base_g = 1 << 9;
    constexpr uint32_t base_r = 32;
    constexpr uint32_t num_auto_keys = 10;
    constexpr double std_dev_value = 3.19;
    const NativeInteger Q = last_prime<NativeInteger>(27, 2 * N);
    const NativeInteger q = 128;

    const RingGswCryptoParams reference(N, Q, q, base_g, base_r, AP, std_dev_value, UNIFORM_TERNARY, false,
                                        num_auto_keys);
    const RingGswCryptoParams same(N, Q, q, base_g, base_r, AP, std_dev_value, UNIFORM_TERNARY, false, num_auto_keys);
    EXPECT_EQ(reference, same);

    EXPECT_NE(reference, RingGswCryptoParams(N, Q, q / 2, base_g, base_r, AP, std_dev_value, UNIFORM_TERNARY, false,
                                             num_auto_keys));
    EXPECT_NE(reference, RingGswCryptoParams(N, Q, q, base_g, base_r, LMKCDEY, std_dev_value, UNIFORM_TERNARY, false,
                                             num_auto_keys));
    EXPECT_NE(reference,
              RingGswCryptoParams(N, Q, q, base_g, base_r, AP, std_dev_value, GAUSSIAN, false, num_auto_keys));
    EXPECT_NE(reference, RingGswCryptoParams(N, Q, q, base_g, base_r, AP, std_dev_value + 0.01, UNIFORM_TERNARY, false,
                                             num_auto_keys));
    EXPECT_NE(reference, RingGswCryptoParams(N, Q, q, base_g, base_r, AP, std_dev_value, UNIFORM_TERNARY, false,
                                             num_auto_keys - 1));
}
