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
#include <cstring>
#include <iostream>
#include <new>
#include <sstream>
#include <string>
#include <vector>

#include "fhe/support/cc_params.h"
#include "fhe/support/crypto_context.h"
#include "fhe/support/test_utils.h"
#include "include/gtest/gtest.h"
#include "cipher/fhe/base/decrypt_result.h"
#include "cipher/util/exception.h"

using namespace cipher;

//===========================================================================================================
enum TEST_CASE_TYPE : int {
    STRING_TEST = 0,
    COEF_PACKED_TEST,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case STRING_TEST:
            typeName = "STRING_TEST";
            break;
        case COEF_PACKED_TEST:
            typeName = "COEF_PACKED_TEST";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTGENERAL_ENCRYPT_DECRYPT {
    TEST_CASE_TYPE test_case_type;
    // test case description - MUST BE UNIQUE
    std::string description;

    TestContextParams params;

    // additional test case data

    std::string build_test_name() const {
        std::stringstream ss;
        ss << test_case_type << "_" << description;
        return ss.str();
    }
    std::string to_string_impl() const {
        std::stringstream ss;
        ss << "testCaseType [" << test_case_type << "], " << params.to_string_impl();
        return ss.str();
    }
};

// this lambda provides a name to be printed for every test run by INSTANTIATE_TEST_SUITE_P.
// the name MUST be constructed from digits, letters and '_' only
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTGENERAL_ENCRYPT_DECRYPT>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTGENERAL_ENCRYPT_DECRYPT& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
constexpr uint32_t BATCH = 16;
constexpr uint32_t BV_DSIZE = 4;
// clang-format off
static std::vector<TEST_CASE_UTGENERAL_ENCRYPT_DECRYPT> test_cases = {
    // TestType,  Descr, Scheme,         RDim, MultDepth, SModSize, DSize,    BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech,         EncTech,  pre_mode
    { STRING_TEST, "01", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { STRING_TEST, "02", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    256,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { STRING_TEST, "03", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    256,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { STRING_TEST, "04", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    256,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { STRING_TEST, "05", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { STRING_TEST, "06", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    256,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { STRING_TEST, "07", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    256,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { STRING_TEST, "08", {BGVRNS_SCHEME, 256,  2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    256,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { STRING_TEST, "09", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      DFLT, HPS,              STANDARD, DFLT} },
    { STRING_TEST, "10", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      DFLT, BEHZ,             STANDARD, DFLT} },
    { STRING_TEST, "11", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD, DFLT} },
    { STRING_TEST, "12", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD, DFLT} },
    { STRING_TEST, "13", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      DFLT, HPS,              EXTENDED, DFLT} },
    { STRING_TEST, "14", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED, DFLT} },
    { STRING_TEST, "15", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED, DFLT} },
    { STRING_TEST, "16", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    256,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED, DFLT} },
    // ==========================================
    // TestType,       Descr, Scheme,         RDim, MultDepth, SModSize, DSize,    BatchSz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl,       KSTech, ScalTech,        LDigits, PtMod, std_dev, EvalAddCt, KSCt, MultTech,         EncTech,  pre_mode
    { COEF_PACKED_TEST, "01", {BGVRNS_SCHEME, 64,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { COEF_PACKED_TEST, "02", {BGVRNS_SCHEME, 64,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    512,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { COEF_PACKED_TEST, "03", {BGVRNS_SCHEME, 64,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    512,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { COEF_PACKED_TEST, "04", {BGVRNS_SCHEME, 64,   2,         DFLT,     BV_DSIZE, BATCH,   GAUSSIAN,        1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    512,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { COEF_PACKED_TEST, "05", {BGVRNS_SCHEME, 64,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             60,       HEStd_NotSet, BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { COEF_PACKED_TEST, "06", {BGVRNS_SCHEME, 64,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FIXEDAUTO,       DFLT,    512,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { COEF_PACKED_TEST, "07", {BGVRNS_SCHEME, 64,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTO,    DFLT,    512,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { COEF_PACKED_TEST, "08", {BGVRNS_SCHEME, 64,   2,         DFLT,     BV_DSIZE, BATCH,   UNIFORM_TERNARY, 1,             DFLT,     HEStd_NotSet, BV,     FLEXIBLEAUTOEXT, DFLT,    512,   DFLT,   DFLT,      DFLT, DFLT,             STANDARD, DFLT} },
    { COEF_PACKED_TEST, "09", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      DFLT, HPS,              STANDARD, DFLT} },
    { COEF_PACKED_TEST, "10", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      DFLT, BEHZ,             STANDARD, DFLT} },
    { COEF_PACKED_TEST, "11", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        STANDARD, DFLT} },
    { COEF_PACKED_TEST, "12", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD, DFLT} },
    { COEF_PACKED_TEST, "13", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      DFLT, HPS,              EXTENDED, DFLT} },
    { COEF_PACKED_TEST, "14", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      DFLT, BEHZ,             EXTENDED, DFLT} },
    { COEF_PACKED_TEST, "15", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      DFLT, HPSPOVERQ,        EXTENDED, DFLT} },
    { COEF_PACKED_TEST, "16", {BFVRNS_SCHEME, DFLT, DFLT,      DFLT,     20,       BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,         BV,     FIXEDMANUAL,     DFLT,    512,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED, DFLT} },
};
// clang-format on
//===========================================================================================================
class UTGENERAL_ENCRYPT_DECRYPT : public ::testing::TestWithParam<TEST_CASE_UTGENERAL_ENCRYPT_DECRYPT> {
    using Element = RnsPoly;

  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    void TearDown() {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    void encryption_string(const TEST_CASE_UTGENERAL_ENCRYPT_DECRYPT& test_data,
                           const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            std::string value = "You keep using that word. I do not think it means what you think it means";
            Plaintext plaintext = cc->make_string_plaintext(value);

            KeyPair<Element> kp = cc->key_gen();
            EXPECT_EQ(kp.good(), true) << failmsg << " key generation for string encrypt/decrypt failed";

            Ciphertext<Element> ciphertext = cc->encrypt(kp.public_key, plaintext);
            Plaintext plaintext_new;
            cc->decrypt(kp.secret_key, ciphertext, &plaintext_new);
            EXPECT_EQ(*plaintext, *plaintext_new) << failmsg << " string encrypt/decrypt failed";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void encryption_coef_packed(const TEST_CASE_UTGENERAL_ENCRYPT_DECRYPT& test_data,
                                const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            size_t int_size = cc->get_ring_dimension();
            auto ptm = cc->get_crypto_parameters()->get_plaintext_modulus();
            int half = ptm / 2;

            std::vector<int64_t> intvec;
            for (size_t ii = 0; ii < int_size; ii++)
                intvec.push_back(rand() % half);  // NOLINT
            Plaintext plaintext_int = cc->make_coef_packed_plaintext(intvec);

            std::vector<int64_t> sintvec;
            for (size_t ii = 0; ii < int_size; ii++) {
                int rnum = rand() % half;  // NOLINT
                if (rand() % 2)            // NOLINT
                    rnum *= -1;
                sintvec.push_back(rnum);
            }
            Plaintext plaintext_s_int = cc->make_coef_packed_plaintext(sintvec);

            KeyPair<Element> kp = cc->key_gen();
            EXPECT_EQ(kp.good(), true) << failmsg << " key generation for coef packed encrypt/decrypt failed";

            Ciphertext<Element> ciphertext4 = cc->encrypt(kp.public_key, plaintext_int);
            Plaintext plaintext_int_new;
            cc->decrypt(kp.secret_key, ciphertext4, &plaintext_int_new);
            EXPECT_EQ(*plaintext_int_new, *plaintext_int)
                    << failmsg << "coef packed encrypt/decrypt failed for integer plaintext";

            Ciphertext<Element> ciphertext5 = cc->encrypt(kp.public_key, plaintext_s_int);
            Plaintext plaintext_s_int_new;
            cc->decrypt(kp.secret_key, ciphertext5, &plaintext_s_int_new);
            EXPECT_EQ(*plaintext_s_int_new, *plaintext_s_int)
                    << failmsg << "coef packed encrypt/decrypt failed for signed integer plaintext";
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
};
//===========================================================================================================
TEST_P(UTGENERAL_ENCRYPT_DECRYPT, ENCRYPT) {
    setup_signals();
    auto test = GetParam();
    if (test.test_case_type == STRING_TEST)
        encryption_string(test, test.build_test_name());
    else if (test.test_case_type == COEF_PACKED_TEST)
        encryption_coef_packed(test, test.build_test_name());
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTGENERAL_ENCRYPT_DECRYPT, ::testing::ValuesIn(test_cases), testName);

// Default-initializes T in storage pre-filled with 0xFF bytes, so a member without an initializer
// keeps a non-zero garbage value instead of passing the check by chance.
template <typename T, typename Check>
static void check_default_init_on_dirty_storage(Check check) {
    alignas(T) unsigned char storage[sizeof(T)];
    std::memset(storage, 0xFF, sizeof(storage));
    T* obj = ::new (static_cast<void*>(storage)) T;  // no parentheses: default-, not value-initialization
    check(*obj);
    obj->~T();
}

TEST(UnitTestENCRYPT, ResultDefaultsAreInvalidAndEmpty) {
    check_default_init_on_dirty_storage<EncryptResult>([](const EncryptResult& r) {
        EXPECT_FALSE(r.is_valid);
        EXPECT_EQ(0u, r.num_bytes_encrypted);
    });

    check_default_init_on_dirty_storage<DecryptResult>([](const DecryptResult& r) {
        EXPECT_FALSE(r.is_valid);
        EXPECT_EQ(0u, r.message_length);
        EXPECT_EQ(NativeInteger(1), r.scaling_factor_int);
    });
}
