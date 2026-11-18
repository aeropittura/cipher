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

#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "cipher/boolean/context_ser.h"
#include "gtest/gtest.h"

using namespace cipher;

// BinFHE at the build's true native word size.
//
// The rest of the suite exercises whatever the defaults do, and since keys whose moduli fit
// 32 bits are now held and evaluated in a narrowed form by default, that is the 32-bit path
// for every parameter set those tests use. Nothing there runs at the native word size any
// more. These tests ask for it explicitly, and they check that the narrowed representation
// agrees with it rather than merely working on its own.
//
// A NATIVE_SIZE=32 build has no narrowed form to select, so the native size is what the rest
// of the suite already covers and this file is empty there.
//
// For anyone extending these: bt_key_gen defaults to internal32 = true, so a test that wants a
// native-width key must say so.

#if CIPHER_NATIVE_INT != 32

namespace {

struct Gate {
    BINGATE gate;
    const char* name;
    int truth[4];  // indexed by (2 * a + b)
};

const std::vector<Gate> gates{{AND, "AND", {0, 0, 0, 1}}, {OR, "OR", {0, 1, 1, 1}},   {NAND, "NAND", {1, 1, 1, 0}},
                              {NOR, "NOR", {1, 0, 0, 0}}, {XOR, "XOR", {0, 1, 1, 0}}, {XNOR, "XNOR", {1, 0, 0, 1}}};

// every gate against every input pair, decrypted and compared with its truth table
void expect_truth_tables(BooleanContext& cc, ConstLwePrivateKey& sk, const std::string& msg) {
    for (const auto& g : gates) {
        for (int a = 0; a < 2; ++a) {
            for (int b = 0; b < 2; ++b) {
                auto ct = cc.eval_bin_gate(g.gate, cc.encrypt(sk, a), cc.encrypt(sk, b));
                LwePlaintext result;
                cc.decrypt(sk, ct, &result);
                EXPECT_EQ(g.truth[2 * a + b], static_cast<int>(result))
                        << msg << " " << g.name << "(" << a << "," << b << ")";
            }
        }
    }
}

}  // namespace

// Narrowing an existing key must not change a single ciphertext bit: same key, same inputs,
// evaluated before and after the conversion.
void unit_test_internal32_bit_identical(BINFHE_PARAMSET set, BINFHE_METHOD method, const std::string& msg) {
    BooleanContext cc;
    cc.generate_boolean_context(set, method);
    auto sk = cc.key_gen();
    cc.bt_key_gen(sk, SYM_ENCRYPT, /*internal32=*/false);
    ASSERT_FALSE(cc.has_internal32_refresh_key()) << msg << " expected a native-width refresh key to start from";

    // fixed inputs, so the two evaluations differ only in the key representation
    std::vector<LweCiphertext> in0, in1, before;
    for (const auto& g : gates) {
        in0.push_back(cc.encrypt(sk, 1));
        in1.push_back(cc.encrypt(sk, 0));
        before.push_back(cc.eval_bin_gate(g.gate, in0.back(), in1.back()));
    }

    // narrow through the public route an application would use
    cc.bt_key_load(cc.get_bt_key(), /*internal32=*/true);
    ASSERT_TRUE(cc.has_internal32_refresh_key()) << msg << " refresh key did not convert";
    ASSERT_TRUE(cc.has_internal32_switch_key()) << msg << " switching key did not convert";

    for (size_t i = 0; i < gates.size(); ++i) {
        auto after = cc.eval_bin_gate(gates[i].gate, in0[i], in1[i]);
        EXPECT_EQ(*before[i], *after) << msg << " " << gates[i].name << " differs after narrowing";
    }
}

// Keys generated directly in the 32-bit form are not bit-comparable with narrowed ones, because
// they are sampled natively, so the truth tables are the oracle.
void unit_test_internal32_key_gen(BINFHE_PARAMSET set, BINFHE_METHOD method, const std::string& msg) {
    BooleanContext cc;
    cc.generate_boolean_context(set, method);
    auto sk = cc.key_gen();
    cc.bt_key_gen(sk, SYM_ENCRYPT, /*internal32=*/true);
    EXPECT_TRUE(cc.has_internal32_refresh_key()) << msg << " refresh key was not generated in 32-bit form";
    EXPECT_TRUE(cc.has_internal32_switch_key()) << msg << " switching key was not generated in 32-bit form";
    expect_truth_tables(cc, sk, msg);
}

// The native word size, whatever the build selected. Asking for it explicitly matters twice
// over: no other test reaches it any more, and a parameter set that merely fails to qualify
// would give a mixed context rather than a native one.
void unit_test_native_size_path(BINFHE_PARAMSET set, BINFHE_METHOD method, const std::string& msg) {
    BooleanContext cc;
    cc.generate_boolean_context(set, method);
    auto sk = cc.key_gen();
    cc.bt_key_gen(sk, SYM_ENCRYPT, /*internal32=*/false);
    ASSERT_FALSE(cc.has_internal32_refresh_key()) << msg << " refresh key should have stayed native width";
    ASSERT_FALSE(cc.has_internal32_switch_key()) << msg << " switching key should have stayed native width";
    expect_truth_tables(cc, sk, msg);
}

TEST(UnitTestFHEWNativeSize, NativeSizePathGINX) {
    unit_test_native_size_path(TOY, GINX, "UnitTestFHEWNativeSize.NativeSizePathGINX:");
}
TEST(UnitTestFHEWNativeSize, NativeSizePathAP) {
    unit_test_native_size_path(TOY, AP, "UnitTestFHEWNativeSize.NativeSizePathAP:");
}
TEST(UnitTestFHEWNativeSize, NativeSizePathLMKCDEY) {
    unit_test_native_size_path(TOY, LMKCDEY, "UnitTestFHEWNativeSize.NativeSizePathLMKCDEY:");
}

TEST(UnitTestFHEWNativeSize, BitIdenticalGINX) {
    unit_test_internal32_bit_identical(TOY, GINX, "UnitTestFHEWNativeSize.BitIdenticalGINX:");
}
TEST(UnitTestFHEWNativeSize, BitIdenticalAP) {
    unit_test_internal32_bit_identical(TOY, AP, "UnitTestFHEWNativeSize.BitIdenticalAP:");
}
TEST(UnitTestFHEWNativeSize, BitIdenticalLMKCDEY) {
    unit_test_internal32_bit_identical(TOY, LMKCDEY, "UnitTestFHEWNativeSize.BitIdenticalLMKCDEY:");
}

TEST(UnitTestFHEWNativeSize, Internal32KeyGenGINX) {
    unit_test_internal32_key_gen(TOY, GINX, "UnitTestFHEWNativeSize.Internal32KeyGenGINX:");
}
TEST(UnitTestFHEWNativeSize, Internal32KeyGenLMKCDEY) {
    unit_test_internal32_key_gen(TOY, LMKCDEY, "UnitTestFHEWNativeSize.Internal32KeyGenLMKCDEY:");
}

// Qualification is per key. Every predefined set now fits both keys, so the mixed case is
// built explicitly: a 37-bit modulus is too wide for a 32-bit refresh key while its
// key-switching modulus still fits, so the context ends up mixed and must still evaluate.
TEST(UnitTestFHEWNativeSize, PartialQualification) {
    const std::string msg("UnitTestFHEWNativeSize.PartialQualification:");
    BooleanContext cc;
    cc.generate_boolean_context(
            BooleanContextParams{37, 4096, 821, 2048, 32768, 32, 8192, 64, 10, UNIFORM_TERNARY, 3.19, {}}, GINX);
    auto sk = cc.key_gen();
    cc.bt_key_gen(sk, SYM_ENCRYPT, /*internal32=*/true);
    EXPECT_FALSE(cc.has_internal32_refresh_key()) << msg << " a 37-bit modulus must not yield a 32-bit refresh key";
    EXPECT_TRUE(cc.has_internal32_switch_key()) << msg << " the key-switching modulus fits and should convert";

    LwePlaintext result;
    cc.decrypt(sk, cc.eval_bin_gate(AND, cc.encrypt(sk, 1), cc.encrypt(sk, 1)), &result);
    EXPECT_EQ(1, static_cast<int>(result)) << msg << " AND(1,1) on the mixed path";
}

// Loading a 64-bit key with internal32 requested must narrow it and keep evaluating correctly.
TEST(UnitTestFHEWNativeSize, KeyLoadNarrows) {
    const std::string msg("UnitTestFHEWNativeSize.KeyLoadNarrows:");
    BooleanContext src;
    src.generate_boolean_context(TOY, GINX);
    auto sk = src.key_gen();
    src.bt_key_gen(sk, SYM_ENCRYPT, /*internal32=*/false);

    BooleanContext dst;
    dst.generate_boolean_context(TOY, GINX);
    dst.bt_key_load(src.get_bt_key(), /*internal32=*/true);
    EXPECT_TRUE(dst.has_internal32_refresh_key()) << msg << " loaded refresh key did not narrow";
    EXPECT_TRUE(dst.has_internal32_switch_key()) << msg << " loaded switching key did not narrow";
    expect_truth_tables(dst, sk, msg);
}

// A 32-bit key serializes at its own width, and the archive records which width that was, so it
// reloads narrow by default and widens only when the caller asks for the native form.
TEST(UnitTestFHEWNativeSize, NarrowKeysSerializeNarrow) {
    const std::string msg("UnitTestFHEWNativeSize.NarrowKeysSerializeNarrow:");
    BooleanContext cc;
    cc.generate_boolean_context(TOY, GINX);
    auto sk = cc.key_gen();
    cc.bt_key_gen(sk, SYM_ENCRYPT, /*internal32=*/true);
    ASSERT_TRUE(cc.has_internal32_refresh_key()) << msg << " expected a 32-bit refresh key to start from";
    ASSERT_EQ(nullptr, cc.get_refresh_key()) << msg << " the 64-bit handle must be empty while the 32-bit one is held";

    std::stringstream s;
    serialization::to_stream(cc.get_bt_key(), s, SerType::BINARY);
    EXPECT_TRUE(cc.has_internal32_refresh_key()) << msg << " the context lost its 32-bit refresh key";
    EXPECT_TRUE(cc.has_internal32_switch_key()) << msg << " the context lost its 32-bit switching key";

    RingGswBtKey key;
    serialization::from_stream(key, s, SerType::BINARY);
    ASSERT_NE(nullptr, key.b_skey32) << msg << " the archive should carry the 32-bit refresh key";
    ASSERT_NE(nullptr, key.ks_key32) << msg << " the archive should carry the 32-bit switching key";
    EXPECT_EQ(nullptr, key.b_skey) << msg << " no 64-bit refresh key should have been written";
    EXPECT_EQ(*key.b_skey32, *cc.get_bt_key().b_skey32) << msg << " refresh key differs after the round trip";
    EXPECT_EQ(*key.ks_key32, *cc.get_bt_key().ks_key32) << msg << " switching key differs after the round trip";

    BooleanContext narrow;
    narrow.generate_boolean_context(TOY, GINX);
    narrow.bt_key_load(key, /*internal32=*/true);
    EXPECT_TRUE(narrow.has_internal32_refresh_key()) << msg << " the narrow archive should load narrow";
    expect_truth_tables(narrow, sk, msg);

    BooleanContext wide;
    wide.generate_boolean_context(TOY, GINX);
    wide.bt_key_load(key, /*internal32=*/false);
    EXPECT_FALSE(wide.has_internal32_refresh_key()) << msg << " asking for the native width should widen";
    expect_truth_tables(wide, sk, msg);
}

// The switching key holds rows for digit values 1..base_ks-1 only, and its top digit position only
// for the values a coefficient below q_ks can reach, in both key widths; the key switch still decrypts.
TEST(UnitTestFHEWNativeSize, SwitchingKeyTopPositionCompact) {
    const std::string msg("UnitTestFHEWNativeSize.SwitchingKeyTopPositionCompact:");
    BooleanContext cc;
    cc.generate_boolean_context(STD128, GINX);
    auto&& lwe = cc.get_params()->get_lwe_params();
    const uint32_t d = lwe->get_digit_count_ks();
    const uint32_t base_ks = lwe->get_base_ks();
    const uint32_t top = lwe->get_digit_extent_ks(d - 1);
    ASSERT_EQ(2u, d) << msg;
    EXPECT_EQ(base_ks, lwe->get_digit_extent_ks(0)) << msg;
    EXPECT_EQ(128u, top) << msg << " qKS = 2^15 in base 256 reaches 128 values at the top position";

    auto sk = cc.key_gen();
    auto sk_n = cc.key_gen_n();
    auto ksk = cc.key_switch_gen(sk, sk_n);
    const auto& A = ksk->get_elements_a();
    ASSERT_EQ(lwe->get_N(), A.size()) << msg;
    ASSERT_EQ(base_ks - 1, A[0].size()) << msg << " no row for digit value 0";
    EXPECT_EQ(d, A[0][top - 2].size()) << msg;
    EXPECT_EQ(d - 1, A[0][top - 1].size()) << msg << " rows above the top extent must not be stored";

    auto ct = cc.encrypt(sk_n, 1, LARGE_DIM, 4, lwe->get_Q());
    LwePlaintext result;
    cc.decrypt(sk, cc.switch_c_ttoqn(ksk, ct), &result);
    EXPECT_EQ(1, static_cast<int>(result)) << msg;

    LweSwitchingKey32Impl narrow(*lwe, *ksk);
    const uint64_t rows = static_cast<uint64_t>(lwe->get_N()) * ((d - 1) * (base_ks - 1) + (top - 1));
    EXPECT_EQ(rows * (lwe->get_n() + 1) * sizeof(uint32_t), narrow.key_bytes()) << msg;
    EXPECT_EQ(*ksk, *narrow.widen(*lwe)) << msg << " narrowing and widening must round-trip the compact key";
}

TEST(UnitTestFHEWNativeSize, SwitchingKey32FitsCapsModulus) {
    auto Q = last_prime<NativeInteger>(27, 1024);
    auto fits_fn = [&](uint64_t q_ks) {
        return LweSwitchingKey32Impl::fits(LweCryptoParams(64, 512, 512, Q, q_ks, 3.19, 32));
    };
    EXPECT_TRUE(fits_fn((1ull << 28) - 57));
    EXPECT_FALSE(fits_fn(1ull << 28));
    EXPECT_FALSE(fits_fn((1ull << 31) + 11));
    EXPECT_FALSE(fits_fn((1ull << 32) - 5));
}

TEST(UnitTestFHEWNativeSize, SwitchingKey32RejectsCiphertextAboveKeySwitchingModulus) {
    const std::string msg("UnitTestFHEWNativeSize.SwitchingKey32RejectsCiphertextAboveKeySwitchingModulus:");
    BooleanContext cc;
    cc.generate_boolean_context(BooleanContextParams{27, 1024, 64, 512, 16384, 32, 512, 23, 9, UNIFORM_TERNARY, 3.19, {}},
                             GINX);
    auto&& lwe = cc.get_params()->get_lwe_params();
    auto sk = cc.key_gen();
    auto sk_n = cc.key_gen_n();
    auto ksk = std::make_shared<LweSwitchingKey32Impl>(*lwe, *cc.key_switch_gen(sk, sk_n));
    auto ct_q = cc.encrypt(sk_n, 1, LARGE_DIM, 4, lwe->get_Q());
    EXPECT_THROW(cc.get_lwe_scheme()->key_switch(lwe, ksk, ct_q), CipherException) << msg;

    LwePlaintext result;
    cc.decrypt(sk, cc.get_lwe_scheme()->switch_c_ttoqn(lwe, ksk, ct_q), &result);
    EXPECT_EQ(1, static_cast<int>(result)) << msg;
}

#endif  // CIPHER_NATIVE_INT != 32
