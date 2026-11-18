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

#if !defined(_MSC_VER)

    #include <cstdint>
    #include <iostream>
    #include <sstream>
    #include <string>
    #include <vector>

    #include "fhe/support/cc_params.h"
    #include "fhe/support/crypto_context.h"
    #include "fhe/support/test_utils.h"
    #include "gtest/gtest.h"

using namespace cipher;

//===========================================================================================================
enum TEST_CASE_TYPE : int {
    EVAL_MULT_SINGLE = 0,
    EVAL_ADD_SINGLE,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string typeName;
    switch (type) {
        case EVAL_MULT_SINGLE:
            typeName = "EVAL_MULT_SINGLE";
            break;
        case EVAL_ADD_SINGLE:
            typeName = "EVAL_ADD_SINGLE";
            break;
        default:
            typeName = "UNKNOWN";
            break;
    }
    return os << typeName;
}
//===========================================================================================================
struct TEST_CASE_UTBGVRNS_SHEADVANCED {
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
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTBGVRNS_SHEADVANCED>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTBGVRNS_SHEADVANCED& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
constexpr uint32_t RING_DIM = 8192;
constexpr uint32_t PTM = 20;
constexpr uint32_t DSIZE = 4;
constexpr double STD_DEV = 3.19;

// clang-format off
static std::vector<TEST_CASE_UTBGVRNS_SHEADVANCED> test_cases_utbgvrns_sheadvanced = {
    // TestType,       Descr,  Scheme,        RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl, KSTech, ScalTech,        LDigits, PtMod, std_dev,  EvalAddCt, KSCt, MultTech, EncTech, pre_mode
    { EVAL_MULT_SINGLE, "01", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_MULT_SINGLE, "02", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDMANUAL,     DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_MULT_SINGLE, "03", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FIXEDAUTO,       DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_MULT_SINGLE, "04", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    // ==========================================
    // TestType,      Descr,  Scheme,        RDim,     MultDepth, SModSize, DSize, BatchSz, SecKeyDist, MaxRelinSkDeg,  FModSize, SecLvl, KSTech, ScalTech,        LDigits, PtMod, std_dev,  EvalAddCt, KSCt, MultTech, EncTech, pre_mode
    { EVAL_ADD_SINGLE, "01", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,           DFLT,     DFLT,   DFLT,   FLEXIBLEAUTO,    DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_ADD_SINGLE, "02", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,           DFLT,     DFLT,   DFLT,   FIXEDMANUAL,     DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_ADD_SINGLE, "03", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,           DFLT,     DFLT,   DFLT,   FIXEDAUTO,       DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
    { EVAL_ADD_SINGLE, "04", {BGVRNS_SCHEME, RING_DIM, DFLT,      DFLT,     DSIZE, DFLT,    DFLT,       DFLT,           DFLT,     DFLT,   DFLT,   FLEXIBLEAUTOEXT, DFLT,    PTM,   STD_DEV, DFLT,      DFLT, DFLT,     DFLT,    DFLT}, },
};
// clang-format on
//===========================================================================================================
class UTBGVRNS_SHEADVANCED : public ::testing::TestWithParam<TEST_CASE_UTBGVRNS_SHEADVANCED> {
    using Element = RnsPoly;

  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    void TearDown() {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    void unit_test_eval_mult_single(const TEST_CASE_UTBGVRNS_SHEADVANCED& test_data,
                                    const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->key_gen();
            cc->eval_mult_key_gen(kp.secret_key);

            std::vector<int64_t> vector_of_ints1 = {2};
            Plaintext int_array1 = cc->make_coef_packed_plaintext(vector_of_ints1);
            std::vector<int64_t> vector_of_ints2 = {3};
            Plaintext int_array2 = cc->make_coef_packed_plaintext(vector_of_ints2);
            std::vector<int64_t> vector_of_expected_values = {6};  // = vector_of_ints1 * vector_of_ints2
            Plaintext expected_values = cc->make_coef_packed_plaintext(vector_of_expected_values);

            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, int_array1);
            Ciphertext<Element> ciphertext2 = cc->encrypt(kp.public_key, int_array2);
            Ciphertext<Element> c_result = cc->eval_mult(ciphertext1, ciphertext2);

            KeyPair<Element> new_kp = cc->key_gen();
            EvalKey<Element> key_switch_hint2 = cc->key_switch_gen(kp.secret_key, new_kp.secret_key);
            cc->key_switch_in_place(c_result, key_switch_hint2);

            Plaintext results;
            cc->decrypt(new_kp.secret_key, c_result, &results);
            results->set_length(expected_values->get_length());

            EXPECT_TRUE(check_equality(results->get_coef_packed_value(), expected_values->get_coef_packed_value()));
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_eval_add_single(const TEST_CASE_UTBGVRNS_SHEADVANCED& test_data,
                                   const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->key_gen();

            std::vector<int64_t> vector_of_ints1 = {2, 3, 1, 4};
            Plaintext int_array1 = cc->make_coef_packed_plaintext(vector_of_ints1);
            std::vector<int64_t> vector_of_ints2 = {3, 6, 3, 1};
            Plaintext int_array2 = cc->make_coef_packed_plaintext(vector_of_ints2);
            std::vector<int64_t> vector_of_expected_values = {5, 9, 4, 5};  // = vector_of_ints1 + vector_of_ints2
            Plaintext expected_values = cc->make_coef_packed_plaintext(vector_of_expected_values);

            Ciphertext<Element> ciphertext1 = cc->encrypt(kp.public_key, int_array1);
            Ciphertext<Element> ciphertext2 = cc->encrypt(kp.public_key, int_array2);
            Ciphertext<Element> c_result = cc->eval_add(ciphertext1, ciphertext2);

            Plaintext results;
            cc->decrypt(kp.secret_key, c_result, &results);
            results->set_length(expected_values->get_length());

            EXPECT_TRUE(check_equality(results->get_coef_packed_value(), expected_values->get_coef_packed_value()));
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
TEST_P(UTBGVRNS_SHEADVANCED, SHEADVANCED) {
    setup_signals();
    auto test = GetParam();

    switch (test.test_case_type) {
        case EVAL_MULT_SINGLE:
            unit_test_eval_mult_single(test, test.build_test_name());
            break;
        case EVAL_ADD_SINGLE:
            unit_test_eval_add_single(test, test.build_test_name());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTBGVRNS_SHEADVANCED, ::testing::ValuesIn(test_cases_utbgvrns_sheadvanced),
                         testName);

#endif
