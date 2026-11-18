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

#include <sstream>
#include <string>
#include <vector>

#include "cipher/boolean/context_ser.h"
#include "gtest/gtest.h"
#include "cipher/boolean/lwe_switch_key.h"

using namespace cipher;

template <typename ST, typename PS>
void unit_test_fhew_serial(const ST& sertype, const PS& sec_level, BINFHE_METHOD variant, BINFHE_OUTPUT ct_type,
                           const std::string& err_msg) {
    const LwePlaintext val(1);
    auto cc1 = BooleanContext();
    cc1.generate_boolean_context(sec_level, variant);

    auto sk1 = cc1.key_gen();
    cc1.bt_key_gen(sk1);

    // Encryption for a ciphertext that will be serialized
    auto ct1 = cc1.encrypt(sk1, val, ct_type);

    BooleanContext cc2;
    {
        std::stringstream s;
        serialization::to_stream(cc1, s, sertype);
        serialization::from_stream(cc2, s, sertype);

        EXPECT_EQ(*cc2.get_params(), *cc1.get_params()) << err_msg << " Context mismatch";
    }

    RingGswBtKey bt_key;
    {
        std::stringstream s;
        serialization::to_stream(cc1.get_bt_key(), s, sertype);
        serialization::from_stream(bt_key, s, sertype);
    }

    // Loading deserialized bootstrapping keys
    cc2.bt_key_load(bt_key);

    // Check the keys after adding them to cc2, at whichever width each context holds them
    EXPECT_EQ(cc1.has_internal32_refresh_key(), cc2.has_internal32_refresh_key()) << err_msg << " refresh key width";
    EXPECT_EQ(cc1.has_internal32_switch_key(), cc2.has_internal32_switch_key()) << err_msg << " switching key width";
#if CIPHER_NATIVE_INT != 32
    if (cc1.has_internal32_refresh_key())
        EXPECT_EQ(*(cc2.get_bt_key().b_skey32), *(cc1.get_bt_key().b_skey32)) << err_msg << " refresh key";
    else
#endif
        EXPECT_EQ(*(cc2.get_refresh_key()), *(cc1.get_refresh_key())) << err_msg << " refresh key";
#if CIPHER_NATIVE_INT != 32
    if (cc1.has_internal32_switch_key())
        EXPECT_EQ(*(cc2.get_bt_key().ks_key32), *(cc1.get_bt_key().ks_key32)) << err_msg << " switching key";
    else
#endif
        EXPECT_EQ(*(cc2.get_switch_key()), *(cc1.get_switch_key())) << err_msg << " switching key";

    LwePrivateKey sk2;
    {
        std::stringstream s;
        serialization::to_stream(sk1, s, sertype);
        serialization::from_stream(sk2, s, sertype);

        EXPECT_EQ(*sk1, *sk2) << err_msg << " Secret key mismatch";
    }

    LweCiphertext ct2;
    {
        std::stringstream s;
        serialization::to_stream(ct1, s, sertype);
        serialization::from_stream(ct2, s, sertype);

        EXPECT_EQ(*ct1, *ct2) << err_msg << " Ciphertext mismatch";
    }

    auto ct_new = cc2.encrypt(sk2, val, ct_type);
    auto ct_result = cc2.eval_bin_gate(AND, ct2, ct_new);
    LwePlaintext result;
    cc2.decrypt(sk2, ct_result, &result);

    EXPECT_EQ(val, result) << err_msg << "result = " << result << ", it is expected to be equal 1";
}

// ---------------  TESTING SERIALIZATION METHODS OF FHEW ---------------
// JSON tests were turned off as they take a very long time and require a lot of memory.
// They are left in this file for debugging purposes only.
// TEST(UnitTestFHEWSerialAP, JSON) {
//     std::string msg = "UnitTestFHEWSerialAP.JSON serialization test failed: ";
//     unit_test_fhew_serial(SerType::JSON, TOY, AP, SMALL_DIM, msg);
// }

TEST(UnitTestFHEWSerialAP, BINARY) {
    std::string msg = "UnitTestFHEWSerialAP.BINARY serialization test failed: ";
    unit_test_fhew_serial(SerType::BINARY, TOY, AP, SMALL_DIM, msg);
}

// TEST(UnitTestFHEWSerialGINX, JSON) {
//     std::string msg = "UnitTestFHEWSerialGINX.JSON serialization test failed: ";
//     unit_test_fhew_serial(SerType::JSON, TOY, GINX, SMALL_DIM, msg);
// }

TEST(UnitTestFHEWSerialGINX, BINARY) {
    std::string msg = "UnitTestFHEWSerialGINX.BINARY serialization test failed: ";
    unit_test_fhew_serial(SerType::BINARY, TOY, GINX, SMALL_DIM, msg);
}

TEST(UnitTestFHEWSerialLMKCDEY, BINARY) {
    std::string msg = "UnitTestFHEWSerialGINX.BINARY serialization test failed: ";
    unit_test_fhew_serial(SerType::BINARY, TOY, LMKCDEY, SMALL_DIM, msg);
}

// The secret key distribution is the one context field key generation dispatches on, and every
// predefined Gaussian set is too large to serialize in a unit test, so this builds a small one.
TEST(UnitTestFHEWSerialGaussian, BINARY) {
    std::string msg = "UnitTestFHEWSerialGaussian.BINARY serialization test failed: ";
    BooleanContextParams p{27, 1024, 64, 512, 0, 25, 512, 23, 9, GAUSSIAN, 3.19, {}};
    unit_test_fhew_serial(SerType::BINARY, p, LMKCDEY, SMALL_DIM, msg);
}

TEST(unit_test_fhew_serial, SwitchingKeyHasCorrectSerializedName) {
    LweSwitchingKeyImpl key;
    EXPECT_EQ("LWESwitchingKey", key.serialized_object_name());
}

// A ciphertext has to come back from an archive with the plaintext modulus it was encrypted with, not
// the default of 4, and a multi-input gate has to give the same result on it as on the original.
template <typename ST>
void unit_test_fhew_serial_multi_input(const ST& sertype, const std::string& err_msg) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, GINX);
    auto sk = cc.key_gen();
    cc.bt_key_gen(sk);

    struct Case {
        BINGATE gate;
        std::vector<LwePlaintext> in;
        LwePlaintextModulus p;
        LwePlaintext expected;
    };
    const std::vector<Case> cases = {
            {AND3, {1, 1, 0}, 6, 0},
            {OR3, {1, 1, 0}, 6, 1},
            {AND4, {1, 1, 1, 1}, 8, 1},
            {OR4, {1, 0, 0, 0}, 8, 1},
    };
    for (const auto& c : cases) {
        std::vector<LweCiphertext> in, in_ser, in_copy;
        for (auto m : c.in) {
            in.push_back(cc.encrypt(sk, m, SMALL_DIM, c.p));
            std::stringstream s;
            serialization::to_stream(in.back(), s, sertype);
            LweCiphertext ct;
            serialization::from_stream(ct, s, sertype);
            EXPECT_EQ(NativeInteger(c.p), ct->get_pt_modulus()) << err_msg << " plaintext modulus lost";
            EXPECT_EQ(*in.back(), *ct) << err_msg << " ciphertext mismatch";
            in_ser.push_back(ct);
            // a copy resets the plaintext modulus to 4, which the gate must not depend on either
            in_copy.push_back(std::make_shared<LweCiphertextImpl>(*in.back()));
        }
        auto out = cc.eval_bin_gate(c.gate, in);
        auto out_ser = cc.eval_bin_gate(c.gate, in_ser);
        EXPECT_EQ(*out, *out_ser) << err_msg << " gate " << c.gate << " differs on deserialized inputs";
        EXPECT_EQ(*out, *cc.eval_bin_gate(c.gate, in_copy)) << err_msg << " gate " << c.gate << " differs on copies";
        EXPECT_EQ(NativeInteger(c.p), out->get_pt_modulus()) << err_msg << " gate " << c.gate << " output modulus";
        LwePlaintext result;
        cc.decrypt(sk, out_ser, &result, c.p);
        EXPECT_EQ(c.expected, result) << err_msg << " gate " << c.gate;
    }
}

TEST(unit_test_fhew_serial_multi_input, BINARY) {
    unit_test_fhew_serial_multi_input(SerType::BINARY, "UnitTestFHEWSerialMultiInput.BINARY failed:");
}

TEST(unit_test_fhew_serial_multi_input, JSON) {
    unit_test_fhew_serial_multi_input(SerType::JSON, "UnitTestFHEWSerialMultiInput.JSON failed:");
}
