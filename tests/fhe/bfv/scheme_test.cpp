//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
#include <iterator>
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
    EVAL_FAST_ROTATION = 0,
    COMPRESSED_BFV = 1,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string type_name_of;
    switch (type) {
        case EVAL_FAST_ROTATION:
            type_name_of = "EVAL_FAST_ROTATION";
            break;
        case COMPRESSED_BFV:
            type_name_of = "COMPRESSED_BFV";
            break;
        default:
            type_name_of = "UNKNOWN";
            break;
    }
    return os << type_name_of;
}
//===========================================================================================================
struct TEST_CASE_UTBFVRNS {
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
static auto make_test_name = [](const testing::TestParamInfo<TEST_CASE_UTBFVRNS>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTBFVRNS& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
constexpr uint32_t MULDEPTH = 7;
constexpr uint32_t PTM = 65537;
// clang-format off
static std::vector<TEST_CASE_UTBFVRNS> test_cases = {
    // TestType,         Descr,  Scheme,        RDim, MultDepth, SModSize, DSize, batch_sz, SecKeyDist, MaxRelinSkDeg, FModSize, SecLvl, KSTech, scal_tech, LDigits, PtMod, std_dev, EvalAddCt, KSCt, mult_tech,         enc_tech, pre_mode
    { EVAL_FAST_ROTATION, "01", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   BV,     DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, DFLT,    DFLT}},
    { EVAL_FAST_ROTATION, "02", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   HYBRID, DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, DFLT,    DFLT}},
    { EVAL_FAST_ROTATION, "03", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   BV,     DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ, DFLT,    DFLT}},
    { EVAL_FAST_ROTATION, "04", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   HYBRID, DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ, DFLT,    DFLT}},
    { EVAL_FAST_ROTATION, "05", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   BV,     DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS, DFLT,    DFLT}},
    { EVAL_FAST_ROTATION, "06", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   HYBRID, DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPS, DFLT,    DFLT}},
    { EVAL_FAST_ROTATION, "07", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   BV,     DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ, DFLT,    DFLT}},
    { EVAL_FAST_ROTATION, "08", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   HYBRID, DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, BEHZ, DFLT,    DFLT}},
    { COMPRESSED_BFV,     "01", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   BV,     DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, DFLT,    DFLT}},
    { COMPRESSED_BFV,     "02", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   HYBRID, DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQLEVELED, DFLT,    DFLT}},
    { COMPRESSED_BFV,     "03", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   BV,     DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ, DFLT,    DFLT}},
    { COMPRESSED_BFV,     "04", {BFVRNS_SCHEME, DFLT, MULDEPTH,  DFLT,     DFLT,  DFLT,    DFLT,       DFLT,          DFLT,     DFLT,   HYBRID, DFLT,     DFLT,    PTM,   DFLT,   DFLT,      DFLT, HPSPOVERQ, DFLT,    DFLT}},
    // ==========================================
};
// clang-format on
//===========================================================================================================
class UTBFVRNS : public ::testing::TestWithParam<TEST_CASE_UTBFVRNS> {
    using Element = RnsPoly;

    // The precision after which we consider two values equal.
    // This is necessary because BFV works for approximate numbers.
    const double eps = EPSILON;

  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    void TearDown() {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    void unit_test_eval_fast_rotation(const TEST_CASE_UTBFVRNS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            KeyPair<RnsPoly> key_pair = cc->key_gen();

            // Generate the relinearization key
            cc->eval_mult_key_gen(key_pair.secret_key);

            // Generate the rotation evaluation keys
            cc->eval_rotate_key_gen(key_pair.secret_key, {1, 2, -1, -2});

            std::vector<int64_t> vector_of_ints1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
            Plaintext plaintext1 = cc->make_packed_plaintext(vector_of_ints1);
            auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);

            std::vector<int64_t> vector_of_ints2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
            Plaintext plaintext2 = cc->make_packed_plaintext(vector_of_ints2);
            auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

            std::vector<int64_t> vector_of_ints3 = {1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12};
            Plaintext plaintext3 = cc->make_packed_plaintext(vector_of_ints3);
            auto ciphertext3 = cc->encrypt(key_pair.public_key, plaintext3);

            // Homomorphic multiplications (do enough to drop some levels)
            auto ciphertext_mul12 = cc->eval_mult(ciphertext1, ciphertext2);
            auto ciphertext_mult_result = cc->eval_mult(ciphertext_mul12, ciphertext3);
            ciphertext_mult_result = cc->eval_square(ciphertext_mult_result);
            ciphertext_mult_result = cc->eval_square(ciphertext_mult_result);

            auto digits = cc->eval_fast_rotation_precompute(ciphertext_mul12);
            auto digits2 = cc->eval_fast_rotation_precompute(ciphertext_mult_result);
            const uint32_t M = cc->get_cyclotomic_order();

            auto ciphertext_rot1 = cc->eval_fast_rotation(ciphertext_mul12, 1, M, digits);
            auto ciphertext_rot2 = cc->eval_fast_rotation(ciphertext_mul12, -1, M, digits);
            auto ciphertext_rot3 = cc->eval_fast_rotation(ciphertext_mult_result, 2, M, digits2);
            auto ciphertext_rot4 = cc->eval_fast_rotation(ciphertext_mult_result, -2, M, digits2);

            // EvalFastRotate +1 (left rotation)
            std::vector<int64_t> expected_results1 = {4, 3, 16, 25, 36, 49, 64, 81, 100, 121, 144, 0};
            Plaintext plaintext_rot1;
            cc->decrypt(key_pair.secret_key, ciphertext_rot1, &plaintext_rot1);
            plaintext_rot1->set_length(vector_of_ints1.size());
            auto results1 = plaintext_rot1->get_packed_value();
            check_equality(results1, expected_results1, eps, failmsg + " eval_fast_rotation(+1) failed");

            // EvalFastRotate -1 (right rotation)
            std::vector<int64_t> expected_results2 = {0, 3, 4, 3, 16, 25, 36, 49, 64, 81, 100, 121};
            Plaintext plaintext_rot2;
            cc->decrypt(key_pair.secret_key, ciphertext_rot2, &plaintext_rot2);
            plaintext_rot2->set_length(vector_of_ints1.size());
            auto results2 = plaintext_rot2->get_packed_value();
            check_equality(results2, expected_results2, eps, failmsg + " eval_fast_rotation(-1) failed");

            // EvalFastRotate +2 (left rotation)
            std::vector<int64_t> expected_results3 = {-14912, -16,   15300, -29119, 3875, 16,
                                                      -2298,  15428, -8061, 5916,   0,    0};
            Plaintext plaintext_rot3;
            cc->decrypt(key_pair.secret_key, ciphertext_rot3, &plaintext_rot3);
            plaintext_rot3->set_length(vector_of_ints1.size());
            auto results3 = plaintext_rot3->get_packed_value();
            check_equality(results3, expected_results3, eps, failmsg + " eval_fast_rotation(+2) failed");

            // EvalFastRotate -2 (right rotation)
            std::vector<int64_t> expected_results4 = {0,     0,      81,   4096, -14912, -16,
                                                      15300, -29119, 3875, 16,   -2298,  15428};
            Plaintext plaintext_rot4;
            cc->decrypt(key_pair.secret_key, ciphertext_rot4, &plaintext_rot4);
            plaintext_rot4->set_length(vector_of_ints1.size());
            auto results4 = plaintext_rot4->get_packed_value();
            check_equality(results4, expected_results4, eps, failmsg + " eval_fast_rotation(-2) failed");
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }

    void unit_test_compressed_bfv(const TEST_CASE_UTBFVRNS& test_data, const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data.params));

            KeyPair<RnsPoly> key_pair = cc->key_gen();

            // Generate the relinearization key
            cc->eval_mult_key_gen(key_pair.secret_key);

            // Generate the rotation evaluation keys
            cc->eval_rotate_key_gen(key_pair.secret_key, {1});

            std::vector<int64_t> vector_of_ints1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 11, 12};
            Plaintext plaintext1 = cc->make_packed_plaintext(vector_of_ints1, 1, 1);
            auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);

            std::vector<int64_t> vector_of_ints2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
            Plaintext plaintext2 = cc->make_packed_plaintext(vector_of_ints2, 1, 1);
            auto ciphertext2 = cc->encrypt(key_pair.public_key, plaintext2);

            std::vector<int64_t> vector_of_ints3 = {1, 2, 5, 2, 5, 6, 7, 8, 9, 9, 11, 12};
            Plaintext plaintext3 = cc->make_packed_plaintext(vector_of_ints3, 1, 1);
            auto ciphertext3 = cc->encrypt(key_pair.public_key, plaintext3);

            // Homomorphic multiplications (do enough to drop some levels)
            auto ciphertext_mul12 = cc->eval_mult(ciphertext1, ciphertext2);
            auto ciphertext_mult_result = cc->eval_mult(ciphertext_mul12, ciphertext3);
            auto ciphertext_mult_compressed1 = cc->compress(ciphertext_mult_result, 1);
            auto ciphertext_mult_compressed2 = cc->compress(ciphertext_mult_result, 2);
            auto ciphertext_square_result = cc->eval_square(ciphertext1);

            auto digits = cc->eval_fast_rotation_precompute(ciphertext_mul12);
            const uint32_t M = cc->get_cyclotomic_order();

            auto ciphertext_rot1 = cc->eval_fast_rotation(ciphertext_mul12, 1, M, digits);
            auto ciphertext_rot2 = cc->eval_rotate(ciphertext_mul12, 1);

            auto ciphertext_ptxt_mult = cc->eval_mult(ciphertext1, plaintext2);

            auto ciphertext_ptxt_add = cc->eval_add(ciphertext1, plaintext2);

            // Multiplication
            std::vector<int64_t> expected_results1 = {3, 8, 15, 32, 125, 216, 343, 512, 729, 990, 1331, 1728};
            Plaintext plaintext_mult;
            cc->decrypt(key_pair.secret_key, ciphertext_mult_result, &plaintext_mult);
            plaintext_mult->set_length(vector_of_ints1.size());
            auto results1 = plaintext_mult->get_packed_value();
            check_equality(results1, expected_results1, eps, failmsg + " EvalMult failed");

            // Squaring
            expected_results1 = {1, 4, 9, 16, 25, 36, 49, 64, 81, 121, 121, 144};
            Plaintext plaintext_square;
            cc->decrypt(key_pair.secret_key, ciphertext_square_result, &plaintext_square);
            plaintext_square->set_length(vector_of_ints1.size());
            results1 = plaintext_square->get_packed_value();
            check_equality(results1, expected_results1, eps, failmsg + " eval_square failed");

            // Fast Rotation
            expected_results1 = {4, 3, 16, 25, 36, 49, 64, 81, 110, 121, 144, 0};
            Plaintext plaintext_rot1;
            cc->decrypt(key_pair.secret_key, ciphertext_rot1, &plaintext_rot1);
            plaintext_rot1->set_length(vector_of_ints1.size());
            results1 = plaintext_rot1->get_packed_value();
            check_equality(results1, expected_results1, eps, failmsg + " EvalFastRotation failed");

            // Rotation
            expected_results1 = {4, 3, 16, 25, 36, 49, 64, 81, 110, 121, 144, 0};
            Plaintext plaintext_rot2;
            cc->decrypt(key_pair.secret_key, ciphertext_rot2, &plaintext_rot2);
            plaintext_rot2->set_length(vector_of_ints1.size());
            results1 = plaintext_rot2->get_packed_value();
            check_equality(results1, expected_results1, eps, failmsg + " eval_rotate failed");

            // Multiplication by plaintext
            expected_results1 = {3, 4, 3, 16, 25, 36, 49, 64, 81, 110, 121, 144};
            Plaintext plaintext_ptxt_mult;
            cc->decrypt(key_pair.secret_key, ciphertext_ptxt_mult, &plaintext_ptxt_mult);
            plaintext_ptxt_mult->set_length(vector_of_ints1.size());
            results1 = plaintext_ptxt_mult->get_packed_value();
            check_equality(results1, expected_results1, eps, failmsg + " EvalMult with plaintext failed");

            // Addition of a plaintext
            expected_results1 = {4, 4, 4, 8, 10, 12, 14, 16, 18, 21, 22, 24};
            Plaintext plaintext_ptxt_add;
            cc->decrypt(key_pair.secret_key, ciphertext_ptxt_add, &plaintext_ptxt_add);
            plaintext_ptxt_add->set_length(vector_of_ints1.size());
            results1 = plaintext_ptxt_add->get_packed_value();
            check_equality(results1, expected_results1, eps, failmsg + " eval_add with plaintext failed");

            // Multiplication - compressed to 1
            expected_results1 = {3, 8, 15, 32, 125, 216, 343, 512, 729, 990, 1331, 1728};
            Plaintext plaintext_mult_comp1;
            cc->decrypt(key_pair.secret_key, ciphertext_mult_compressed1, &plaintext_mult_comp1);
            plaintext_mult_comp1->set_length(vector_of_ints1.size());
            results1 = plaintext_mult_comp1->get_packed_value();
            check_equality(results1, expected_results1, eps, failmsg + " EvalMult compressed to 1 RNS limb failed");

            // Multiplication - compressed to 2
            expected_results1 = {3, 8, 15, 32, 125, 216, 343, 512, 729, 990, 1331, 1728};
            Plaintext plaintext_mult_comp2;
            cc->decrypt(key_pair.secret_key, ciphertext_mult_compressed2, &plaintext_mult_comp2);
            plaintext_mult_comp2->set_length(vector_of_ints1.size());
            results1 = plaintext_mult_comp2->get_packed_value();
            check_equality(results1, expected_results1, eps, failmsg + " EvalMult compressed to 2 RNS limbs failed");
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
TEST_P(UTBFVRNS, BFVRNS) {
    setup_signals();
    auto test = GetParam();

    switch (test.test_case_type) {
        case EVAL_FAST_ROTATION:
            unit_test_eval_fast_rotation(test, test.build_test_name());
            break;
        case COMPRESSED_BFV:
            unit_test_compressed_bfv(test, test.build_test_name());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTBFVRNS, ::testing::ValuesIn(test_cases), make_test_name);
