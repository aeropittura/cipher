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
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "fhe/support/cc_params.h"
#include "fhe/support/crypto_context.h"
#include "fhe/support/test_utils.h"
#include "gtest/gtest.h"
#include "cipher/util/exception.h"

using namespace cipher;

//===========================================================================================================
enum TEST_CASE_TYPE : int {
    RE_ENCRYPT = 0,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string type_name_of;
    switch (type) {
        case RE_ENCRYPT:
            type_name_of = "RE_ENCRYPT";
            break;
        default:
            type_name_of = "UNKNOWN";
            break;
    }
    return os << type_name_of;
}
//===========================================================================================================
struct TEST_CASE_UTGENERAL_REENCRYPT {
    TEST_CASE_TYPE test_case_type;
    // test case description - MUST BE UNIQUE
    std::string description;

    TestContextParams params;

    // additional test case data
    // ........

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
static auto make_test_name = [](const testing::TestParamInfo<TEST_CASE_UTGENERAL_REENCRYPT>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTGENERAL_REENCRYPT& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
const uint32_t PTMOD = 256;
const uint32_t BATCH = 16;
const uint32_t SCALE = 60;
const uint32_t DSIZ = 20;
// clang-format off
static std::vector<TEST_CASE_UTGENERAL_REENCRYPT> test_cases = {
    // TestType,  Descr, Scheme,        RDim, MultDepth, SModSize, DSize,batch_sz, SecKeyDist,      MaxRelinSkDeg, FModSize, SecLvl, KSTech, scal_tech, LDigits, PtMod, std_dev,  EvalAddCt, KSCt, mult_tech,         enc_tech,  pre_mode
    { RE_ENCRYPT, "01", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, HPS,              STANDARD, DFLT}, },
    { RE_ENCRYPT, "02", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, HPS,              STANDARD, DFLT}, },
    { RE_ENCRYPT, "03", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, BEHZ,             STANDARD, DFLT}, },
    { RE_ENCRYPT, "04", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, BEHZ,             STANDARD, DFLT}, },
    { RE_ENCRYPT, "05", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, HPSPOVERQ,        STANDARD, DFLT}, },
    { RE_ENCRYPT, "06", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, HPSPOVERQ,        STANDARD, DFLT}, },
    { RE_ENCRYPT, "07", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD, DFLT}, },
    { RE_ENCRYPT, "08", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, HPSPOVERQLEVELED, STANDARD, DFLT}, },
    { RE_ENCRYPT, "09", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, HPS,              EXTENDED, DFLT}, },
    { RE_ENCRYPT, "10", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, HPS,              EXTENDED, DFLT}, },
    { RE_ENCRYPT, "11", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, BEHZ,             EXTENDED, DFLT}, },
    { RE_ENCRYPT, "12", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, BEHZ,             EXTENDED, DFLT}, },
    { RE_ENCRYPT, "13", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, HPSPOVERQ,        EXTENDED, DFLT}, },
    { RE_ENCRYPT, "14", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, HPSPOVERQ,        EXTENDED, DFLT}, },
    { RE_ENCRYPT, "15", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   UNIFORM_TERNARY, DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED, DFLT}, },
    { RE_ENCRYPT, "16", {BFVRNS_SCHEME, DFLT, DFLT,      SCALE,    DSIZ, BATCH,   GAUSSIAN,        DFLT,          DFLT,     DFLT,   DFLT,   DFLT,     DFLT,    PTMOD, DFLT,    DFLT,      DFLT, HPSPOVERQLEVELED, EXTENDED, DFLT}, },
    // ==========================================
};
// clang-format on

class UTGENERAL_REENCRYPT : public ::testing::TestWithParam<TEST_CASE_UTGENERAL_REENCRYPT> {
    using Element = RnsPoly;

  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    void TearDown() {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    void re_encryption(const TEST_CASE_UTGENERAL_REENCRYPT& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            size_t vec_size = cc->get_ring_dimension();

            auto randchar = []() -> char {
                const char charset[] =
                        "0123456789"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                        "abcdefghijklmnopqrstuvwxyz";
                const size_t max_index = (sizeof(charset) - 1);
                return charset[rand() % max_index];
            };

            std::string short_str(vec_size / 2, 0);
            std::generate_n(short_str.begin(), vec_size / 2, randchar);
            Plaintext plaintext_short = cc->make_string_plaintext(short_str);

            std::string full_str(vec_size, 0);
            std::generate_n(full_str.begin(), vec_size, randchar);
            Plaintext plaintext_full = cc->make_string_plaintext(full_str);

            auto ptm = cc->get_crypto_parameters()->get_plaintext_modulus();

            std::vector<int64_t> intvec;
            for (size_t ii = 0; ii < vec_size; ii++)
                intvec.push_back((rand() % (ptm / 2)) * (rand() % 2 ? 1 : -1));  // NOLINT
            Plaintext plaintext_int = cc->make_coef_packed_plaintext(intvec);

            KeyPair<Element> kp = cc->key_gen();
            EXPECT_EQ(kp.good(), true) << failmsg << " key generation for scalar encrypt/decrypt failed";

            KeyPair<Element> new_kp = cc->key_gen();
            EXPECT_EQ(new_kp.good(), true) << failmsg << " second key generation for scalar encrypt/decrypt failed";

            // This generates the keys which are used to perform the key switching.
            EvalKey<Element> eval_key;
            eval_key = cc->re_key_gen(kp.secret_key, new_kp.public_key);

            Ciphertext<Element> ciphertext = cc->encrypt(kp.public_key, plaintext_short);
            Plaintext plaintext_short_new;
            Ciphertext<Element> re_ciphertext = cc->re_encrypt(ciphertext, eval_key);
            DecryptResult result = cc->decrypt(new_kp.secret_key, re_ciphertext, &plaintext_short_new);
            EXPECT_EQ(plaintext_short_new->get_string_value(), plaintext_short->get_string_value())
                    << failmsg << " ReEncrypt short string plaintext with padding";

            Ciphertext<Element> ciphertext2 = cc->encrypt(kp.public_key, plaintext_full);
            Plaintext plaintext_full_new;
            Ciphertext<Element> re_ciphertext2 = cc->re_encrypt(ciphertext2, eval_key);
            result = cc->decrypt(new_kp.secret_key, re_ciphertext2, &plaintext_full_new);
            EXPECT_EQ(plaintext_full_new->get_string_value(), plaintext_full->get_string_value())
                    << failmsg << " ReEncrypt full string plaintext";

            Ciphertext<Element> ciphertext4 = cc->encrypt(kp.public_key, plaintext_int);
            Plaintext plaintext_int_new;
            Ciphertext<Element> re_ciphertext4 = cc->re_encrypt(ciphertext4, eval_key);
            result = cc->decrypt(new_kp.secret_key, re_ciphertext4, &plaintext_int_new);
            EXPECT_EQ(plaintext_int_new->get_coef_packed_value(), plaintext_int->get_coef_packed_value())
                    << failmsg << " ReEncrypt integer plaintext";

            Ciphertext<Element> ciphertext5 = cc->encrypt(kp.public_key, plaintext_short);
            Plaintext plaintext_short_new2;
            Ciphertext<Element> re_ciphertext5 = cc->re_encrypt(ciphertext5, eval_key, kp.public_key);
            result = cc->decrypt(new_kp.secret_key, re_ciphertext5, &plaintext_short_new2);
            EXPECT_EQ(plaintext_short_new2->get_string_value(), plaintext_short->get_string_value())
                    << failmsg << " HRA-secure ReEncrypt short string plaintext with padding";

            Ciphertext<Element> ciphertext6 = cc->encrypt(kp.public_key, plaintext_full);
            Plaintext plaintext_full_new2;
            Ciphertext<Element> re_ciphertext6 = cc->re_encrypt(ciphertext6, eval_key, kp.public_key);
            result = cc->decrypt(new_kp.secret_key, re_ciphertext6, &plaintext_full_new2);
            EXPECT_EQ(plaintext_full_new2->get_string_value(), plaintext_full->get_string_value())
                    << failmsg << " HRA-secure ReEncrypt full string plaintext";

            Ciphertext<Element> ciphertext7 = cc->encrypt(kp.public_key, plaintext_int);
            Plaintext plaintext_int_new2;
            Ciphertext<Element> re_ciphertext7 = cc->re_encrypt(ciphertext7, eval_key, kp.public_key);
            result = cc->decrypt(new_kp.secret_key, re_ciphertext7, &plaintext_int_new2);
            EXPECT_EQ(plaintext_int_new2->get_coef_packed_value(), plaintext_int->get_coef_packed_value())
                    << failmsg << " HRA-secure ReEncrypt integer plaintext";
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
TEST_P(UTGENERAL_REENCRYPT, PRE) {
    setup_signals();
    auto test = GetParam();
    if (test.test_case_type == RE_ENCRYPT)
        re_encryption(test, test.build_test_name());
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTGENERAL_REENCRYPT, ::testing::ValuesIn(test_cases), make_test_name);
