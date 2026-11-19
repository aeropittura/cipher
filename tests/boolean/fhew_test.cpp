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
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "cipher/boolean/context.h"
#include "gtest/gtest.h"
#include "cipher/util/demangle.h"

using namespace cipher;

#if defined(__EMSCRIPTEN__)
    #define UNIT_TEST_EXCEPTION_TYPE_NAME_BINFHE "EMSCRIPTEN_UNKNOWN"
#else
    #define UNIT_TEST_EXCEPTION_TYPE_NAME_BINFHE demangle(__cxxabiv1::__cxa_current_exception_type()->name())
#endif
// UNIT_TEST_HANDLE_ALL_EXCEPTIONS must always fail
#define UNIT_TEST_HANDLE_ALL_EXCEPTIONS_BINFHE                                                                 \
    std::string name(UNIT_TEST_EXCEPTION_TYPE_NAME_BINFHE);                                                    \
    std::cerr << "Unknown exception of type \"" << name << "\" thrown from " << __func__ << "()" << std::endl; \
    EXPECT_TRUE(0 == 1) << failmsg;

//===========================================================================================================
enum TEST_CASE_TYPE {
    FHEW_AND = 0,
    FHEW_OR,
    FHEW_NAND,
    FHEW_NOR,
    FHEW_XOR,
    FHEW_XNOR,
    FHEW_SIGNED_MODE,
    FHEW_KEY_SWITCH,
    FHEW_MOD_SWITCH,
    FHEW_NOT,
    FHEW_AND3,
    FHEW_OR3,
    FHEW_AND4,
    FHEW_OR4,
    FHEW_MAJORITY,
    FHEW_CMUX,
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    std::string type_name_of;
    switch (type) {
        case FHEW_AND:
            type_name_of = "FHEW_AND";
            break;
        case FHEW_OR:
            type_name_of = "FHEW_OR";
            break;
        case FHEW_NAND:
            type_name_of = "FHEW_NAND";
            break;
        case FHEW_NOR:
            type_name_of = "FHEW_NOR";
            break;
        case FHEW_XOR:
            type_name_of = "FHEW_XOR";
            break;
        case FHEW_XNOR:
            type_name_of = "FHEW_XNOR";
            break;
        case FHEW_SIGNED_MODE:
            type_name_of = "FHEW_SIGNED_MODE";
            break;
        case FHEW_KEY_SWITCH:
            type_name_of = "FHEW_KEY_SWITCH";
            break;
        case FHEW_MOD_SWITCH:
            type_name_of = "FHEW_MOD_SWITCH";
            break;
        case FHEW_NOT:
            type_name_of = "FHEW_NOT";
            break;
        case FHEW_AND3:
            type_name_of = "FHEW_AND3";
            break;
        case FHEW_OR3:
            type_name_of = "FHEW_OR3";
            break;
        case FHEW_AND4:
            type_name_of = "FHEW_AND4";
            break;
        case FHEW_OR4:
            type_name_of = "FHEW_OR4";
            break;
        case FHEW_MAJORITY:
            type_name_of = "FHEW_MAJORITY";
            break;
        case FHEW_CMUX:
            type_name_of = "FHEW_CMUX";
            break;
        default:
            type_name_of = "UNKNOWN_TESTTYPE";
            break;
    }
    return os << type_name_of;
}
//===========================================================================================================
struct TEST_CASE_UTGENERAL_FHEW {
    TEST_CASE_TYPE test_case_type;
    // test case description - MUST BE UNIQUE
    std::string description;

    BINFHE_PARAMSET security_level;
    BINFHE_METHOD method;
    uint32_t num_of_inputs;
    LwePlaintextModulus ptmodulus;

    BINGATE gate;

    std::vector<LwePlaintext> results;

    // additional test case data
    // ........

    std::string build_test_name() const {
        std::stringstream ss;
        ss << test_case_type << "_" << description;
        return ss.str();
    }
    std::string to_string_impl() const {
        std::stringstream ss;
        ss << "testCaseType [" << test_case_type << "], BINFHE_PARAMSET: " << security_level
           << ", BINFHE_METHOD: " << method << ", number of inputs: " << num_of_inputs << ", BINGATE: " << gate;
        return ss.str();
    }
};

// this lambda provides a name to be printed for every test run by INSTANTIATE_TEST_SUITE_P.
// the name MUST be constructed from digits, letters and '_' only
static auto make_test_name = [](const testing::TestParamInfo<TEST_CASE_UTGENERAL_FHEW>& test) {
    return test.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTGENERAL_FHEW& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
// clang-format off
static std::vector<TEST_CASE_UTGENERAL_FHEW> test_cases_utgeneral_fhew = {
    // TestType,          Descr, ParamSet,         Method,  num_of_inputs, ptmodulus, Gate,     Results
    { FHEW_AND,           "01",  TOY,              GINX,    2,             4,         AND,      {1, 0, 0, 0} },
    { FHEW_AND,           "02",  TOY,              AP,      2,             4,         AND,      {1, 0, 0, 0} },
    { FHEW_AND,           "03",  TOY,              LMKCDEY, 2,             4,         AND,      {1, 0, 0, 0} },
    { FHEW_AND,           "04",  TOY_MULTI_BASE,   GINX,    2,             4,         AND,      {1, 0, 0, 0} },
    { FHEW_AND,           "05",  TOY_MULTI_BASE,   AP,      2,             4,         AND,      {1, 0, 0, 0} },
    { FHEW_AND,           "06",  TOY_MULTI_BASE,   LMKCDEY, 2,             4,         AND,      {1, 0, 0, 0} },
    // ==========================================
    { FHEW_NAND,          "01",  TOY,              GINX,    2,             4,         NAND,     {0, 1, 1, 1} },
    { FHEW_NAND,          "02",  TOY,              AP,      2,             4,         NAND,     {0, 1, 1, 1} },
    { FHEW_NAND,          "03",  TOY,              LMKCDEY, 2,             4,         NAND,     {0, 1, 1, 1} },
    { FHEW_NAND,          "04",  TOY_MULTI_BASE,   GINX,    2,             4,         NAND,     {0, 1, 1, 1} },
    { FHEW_NAND,          "05",  TOY_MULTI_BASE,   AP,      2,             4,         NAND,     {0, 1, 1, 1} },
    { FHEW_NAND,          "06",  TOY_MULTI_BASE,   LMKCDEY, 2,             4,         NAND,     {0, 1, 1, 1} },
    // ==========================================
    { FHEW_OR,            "01",  TOY,              GINX,    2,             4,         OR,       {1, 1, 1, 0} },
    { FHEW_OR,            "02",  TOY,              AP,      2,             4,         OR,       {1, 1, 1, 0} },
    { FHEW_OR,            "03",  TOY,              LMKCDEY, 2,             4,         OR,       {1, 1, 1, 0} },
    { FHEW_OR,            "04",  TOY_MULTI_BASE,   GINX,    2,             4,         OR,       {1, 1, 1, 0} },
    { FHEW_OR,            "05",  TOY_MULTI_BASE,   AP,      2,             4,         OR,       {1, 1, 1, 0} },
    { FHEW_OR,            "06",  TOY_MULTI_BASE,   LMKCDEY, 2,             4,         OR,       {1, 1, 1, 0} },
    // ==========================================
    { FHEW_NOR,           "01",  TOY,              GINX,    2,             4,         NOR,      {0, 0, 0, 1} },
    { FHEW_NOR,           "02",  TOY,              AP,      2,             4,         NOR,      {0, 0, 0, 1} },
    { FHEW_NOR,           "03",  TOY,              LMKCDEY, 2,             4,         NOR,      {0, 0, 0, 1} },
    { FHEW_NOR,           "04",  TOY_MULTI_BASE,   GINX,    2,             4,         NOR,      {0, 0, 0, 1} },
    { FHEW_NOR,           "05",  TOY_MULTI_BASE,   AP,      2,             4,         NOR,      {0, 0, 0, 1} },
    { FHEW_NOR,           "06",  TOY_MULTI_BASE,   LMKCDEY, 2,             4,         NOR,      {0, 0, 0, 1} },
    // ==========================================
    { FHEW_XOR,           "01",  TOY,              GINX,    2,             4,         XOR,      {0, 1, 1, 0} },
    { FHEW_XOR,           "02",  TOY,              AP,      2,             4,         XOR,      {0, 1, 1, 0} },
    { FHEW_XOR,           "03",  TOY,              LMKCDEY, 2,             4,         XOR,      {0, 1, 1, 0} },
    { FHEW_XOR,           "04",  TOY_MULTI_BASE,   GINX,    2,             4,         XOR,      {0, 1, 1, 0} },
    { FHEW_XOR,           "05",  TOY_MULTI_BASE,   AP,      2,             4,         XOR,      {0, 1, 1, 0} },
    { FHEW_XOR,           "06",  TOY_MULTI_BASE,   LMKCDEY, 2,             4,         XOR,      {0, 1, 1, 0} },
    // ==========================================
    { FHEW_XNOR,          "01",  TOY,              GINX,    2,             4,         XNOR,     {1, 0, 0, 1} },
    { FHEW_XNOR,          "02",  TOY,              AP,      2,             4,         XNOR,     {1, 0, 0, 1} },
    { FHEW_XNOR,          "03",  TOY,              LMKCDEY, 2,             4,         XNOR,     {1, 0, 0, 1} },
    { FHEW_XNOR,          "04",  TOY_MULTI_BASE,   GINX,    2,             4,         XNOR,     {1, 0, 0, 1} },
    { FHEW_XNOR,          "05",  TOY_MULTI_BASE,   AP,      2,             4,         XNOR,     {1, 0, 0, 1} },
    { FHEW_XNOR,          "06",  TOY_MULTI_BASE,   LMKCDEY, 2,             4,         XNOR,     {1, 0, 0, 1} },
    // ==========================================
    { FHEW_AND3,          "01",  TOY,              GINX,    3,             6,         AND3,     {0} },
    { FHEW_AND3,          "02",  TOY,              AP,      3,             6,         AND3,     {0} },
    { FHEW_AND3,          "03",  TOY,              LMKCDEY, 3,             6,         AND3,     {0} },
    { FHEW_AND3,          "04",  TOY_MULTI_BASE,   GINX,    3,             6,         AND3,     {0} },
    { FHEW_AND3,          "05",  TOY_MULTI_BASE,   AP,      3,             6,         AND3,     {0} },
    { FHEW_AND3,          "06",  TOY_MULTI_BASE,   LMKCDEY, 3,             6,         AND3,     {0} },
    // ==========================================
    { FHEW_OR3,           "01",  TOY,              GINX,    3,             6,         OR3,      {1} },
    { FHEW_OR3,           "02",  TOY,              AP,      3,             6,         OR3,      {1} },
    { FHEW_OR3,           "03",  TOY,              LMKCDEY, 3,             6,         OR3,      {1} },
    { FHEW_OR3,           "04",  TOY_MULTI_BASE,   GINX,    3,             6,         OR3,      {1} },
    { FHEW_OR3,           "05",  TOY_MULTI_BASE,   AP,      3,             6,         OR3,      {1} },
    { FHEW_OR3,           "06",  TOY_MULTI_BASE,   LMKCDEY, 3,             6,         OR3,      {1} },
    // ==========================================
    { FHEW_AND4,          "01",  TOY,              GINX,    4,             8,         AND4,     {0} },
    { FHEW_AND4,          "02",  TOY,              AP,      4,             8,         AND4,     {0} },
    { FHEW_AND4,          "03",  TOY,              LMKCDEY, 4,             8,         AND4,     {0} },
    { FHEW_AND4,          "04",  TOY_MULTI_BASE,   GINX,    4,             8,         AND4,     {0} },
    { FHEW_AND4,          "05",  TOY_MULTI_BASE,   AP,      4,             8,         AND4,     {0} },
    { FHEW_AND4,          "06",  TOY_MULTI_BASE,   LMKCDEY, 4,             8,         AND4,     {0} },
    // ==========================================
    { FHEW_OR4,           "01",  TOY,              GINX,    4,             8,         OR4,      {1} },
    { FHEW_OR4,           "02",  TOY,              AP,      4,             8,         OR4,      {1} },
    { FHEW_OR4,           "03",  TOY,              LMKCDEY, 4,             8,         OR4,      {1} },
    { FHEW_OR4,           "04",  TOY_MULTI_BASE,   GINX,    4,             8,         OR4,      {1} },
    { FHEW_OR4,           "05",  TOY_MULTI_BASE,   AP,      4,             8,         OR4,      {1} },
    { FHEW_OR4,           "06",  TOY_MULTI_BASE,   LMKCDEY, 4,             8,         OR4,      {1} },
    // ==========================================
    { FHEW_MAJORITY,      "01",  TOY,              GINX,    3,             4,         MAJORITY, {1} },
    { FHEW_MAJORITY,      "02",  TOY,              AP,      3,             4,         MAJORITY, {1} },
    { FHEW_MAJORITY,      "03",  TOY,              LMKCDEY, 3,             4,         MAJORITY, {1} },
    { FHEW_MAJORITY,      "04",  TOY_MULTI_BASE,   GINX,    3,             4,         MAJORITY, {1} },
    { FHEW_MAJORITY,      "05",  TOY_MULTI_BASE,   AP,      3,             4,         MAJORITY, {1} },
    { FHEW_MAJORITY,      "06",  TOY_MULTI_BASE,   LMKCDEY, 3,             4,         MAJORITY, {1} },
    // ==========================================
    { FHEW_CMUX,          "01",  TOY,              GINX,    3,             4,         CMUX,     {1, 0} },
    { FHEW_CMUX,          "02",  TOY,              AP,      3,             4,         CMUX,     {1, 0} },
    { FHEW_CMUX,          "03",  TOY,              LMKCDEY, 3,             4,         CMUX,     {1, 0} },
    { FHEW_CMUX,          "04",  TOY_MULTI_BASE,   GINX,    3,             4,         CMUX,     {1, 0} },
    { FHEW_CMUX,          "05",  TOY_MULTI_BASE,   AP,      3,             4,         CMUX,     {1, 0} },
    { FHEW_CMUX,          "06",  TOY_MULTI_BASE,   LMKCDEY, 3,             4,         CMUX,     {1, 0} },
    // ==========================================
    { FHEW_SIGNED_MODE,   "01",  SIGNED_MOD_TEST,  GINX,    2,             4,         AND,      {1, 0, 0, 0} },
    // ==========================================
    { FHEW_KEY_SWITCH,    "01",  TOY,              GINX,    2,             4,         OR,       {1, 0} },  // OR is not needed; added as a random value
    { FHEW_KEY_SWITCH,    "02",  TOY,              AP,      2,             4,         OR,       {1, 0} },  // OR is not needed; added as a random value
    { FHEW_KEY_SWITCH,    "03",  TOY,              LMKCDEY, 2,             4,         OR,       {1, 0} },  // OR is not needed; added as a random value
    // ==========================================
    { FHEW_MOD_SWITCH,    "01",  TOY,              GINX,    2,             4,         OR,       {1, 0} },  // OR is not needed; added as a random value
    { FHEW_MOD_SWITCH,    "02",  TOY,              AP,      2,             4,         OR,       {1, 0} },  // OR is not needed; added as a random value
    { FHEW_MOD_SWITCH,    "03",  TOY,              LMKCDEY, 2,             4,         OR,       {1, 0} },  // OR is not needed; added as a random value
    // ==========================================
    { FHEW_NOT,           "01",  TOY,              GINX,    2,             4,         OR,       {0, 1} },  // OR is not needed; added as a random value
    { FHEW_NOT,           "02",  TOY,              AP,      2,             4,         OR,       {0, 1} },  // OR is not needed; added as a random value
    { FHEW_NOT,           "03",  TOY,              LMKCDEY, 2,             4,         OR,       {0, 1} },  // OR is not needed; added as a random value
};
// clang-format on
//===========================================================================================================
class UTGENERAL_FHEW : public ::testing::TestWithParam<TEST_CASE_UTGENERAL_FHEW> {
  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }
    void TearDown() {
        cipher_parallel_controls.unit_test_stop();
    }

    // ---------------  TESTING METHODS OF FANDHEW ---------------
    void unit_test_fhew_key_switch(const TEST_CASE_UTGENERAL_FHEW& test_data,
                                   const std::string& failmsg = std::string()) {
        try {
            auto cc = BooleanContext();
            cc.generate_boolean_context(test_data.security_level, test_data.method);

            NativeInteger Q = cc.get_params()->get_lwe_params()->get_Q();

            auto sk = cc.key_gen();
            auto sk_n = cc.key_gen_n();

            auto ct_qn1 = cc.encrypt(sk_n, 1, SMALL_DIM, 4, Q);
            auto ct_qn0 = cc.encrypt(sk_n, 0, SMALL_DIM, 4, Q);

            NativeVector new_sk = sk->get_element();
            new_sk.switch_modulus(Q);
            auto sk_q = std::make_shared<LwePrivateKeyImpl>(new_sk);

            auto key_switch_hint = cc.key_switch_gen(sk, sk_n);

            LweCiphertext e_q1 =
                    cc.get_lwe_scheme()->key_switch(cc.get_params()->get_lwe_params(), key_switch_hint, ct_qn1);
            LweCiphertext e_q0 =
                    cc.get_lwe_scheme()->key_switch(cc.get_params()->get_lwe_params(), key_switch_hint, ct_qn0);

            LwePlaintext result_after_key_switch1;
            cc.decrypt(sk_q, e_q1, &result_after_key_switch1);

            LwePlaintext result_after_key_switch0;
            cc.decrypt(sk_q, e_q0, &result_after_key_switch0);

            std::string failed = test_data.to_string_impl() + " failed";

            EXPECT_EQ(test_data.results[0], result_after_key_switch1) << failed;
            EXPECT_EQ(test_data.results[1], result_after_key_switch0) << failed;
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS_BINFHE;
        }
    }

    void unit_test_fhew_mod_switch(const TEST_CASE_UTGENERAL_FHEW& test_data,
                                   const std::string& failmsg = std::string()) {
        try {
            auto cc = BooleanContext();
            cc.generate_boolean_context(test_data.security_level, test_data.method);

            NativeInteger Q = cc.get_params()->get_lwe_params()->get_Q();

            auto sk = cc.key_gen();

            // switch secret key to Q
            NativeVector new_sk = sk->get_element();
            new_sk.switch_modulus(Q);
            auto sk_q = std::make_shared<LwePrivateKeyImpl>(new_sk);

            auto ct_q1 = cc.encrypt(sk_q, 1, SMALL_DIM, 4, Q);
            auto ct_q0 = cc.encrypt(sk_q, 0, SMALL_DIM, 4, Q);

            // switches the modulus from Q to q
            auto ct1 = cc.get_lwe_scheme()->mod_switch(cc.get_params()->get_lwe_params()->get_q(), ct_q1);
            auto ct0 = cc.get_lwe_scheme()->mod_switch(cc.get_params()->get_lwe_params()->get_q(), ct_q0);

            LwePlaintext result_after_mod_switch1;
            cc.decrypt(sk, ct1, &result_after_mod_switch1);

            LwePlaintext result_after_mod_switch0;
            cc.decrypt(sk, ct0, &result_after_mod_switch0);

            std::string failed = test_data.to_string_impl() + " failed";

            EXPECT_EQ(1, result_after_mod_switch1) << failed;
            EXPECT_EQ(0, result_after_mod_switch0) << failed;
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS_BINFHE;
        }
    }

    void unit_test_fhew_not(const TEST_CASE_UTGENERAL_FHEW& test_data, const std::string& failmsg = std::string()) {
        try {
            auto cc = BooleanContext();
            cc.generate_boolean_context(test_data.security_level, test_data.method);

            auto sk = cc.key_gen();

            auto ct1 = cc.encrypt(sk, 1);
            auto ct0 = cc.encrypt(sk, 0);

            auto ct1_not = cc.eval_not(ct1);
            auto ct0_not = cc.eval_not(ct0);

            LwePlaintext result1;
            cc.decrypt(sk, ct1_not, &result1);

            LwePlaintext result0;
            cc.decrypt(sk, ct0_not, &result0);

            std::string failed = test_data.to_string_impl() + " failed";

            EXPECT_EQ(test_data.results[0], result1) << failed;
            EXPECT_EQ(test_data.results[1], result0) << failed;
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS_BINFHE;
        }
    }

    void unit_test_fhew(const TEST_CASE_UTGENERAL_FHEW& test_data, const std::string& failmsg = std::string()) {
        try {
            auto cc = BooleanContext();
            cc.generate_boolean_context(test_data.security_level, test_data.method);

            auto sk = cc.key_gen();

            cc.bt_key_gen(sk);

            auto ct1 = cc.encrypt(sk, 1);
            auto ct0 = cc.encrypt(sk, 0);
            auto ct1_alt = cc.encrypt(sk, 1);
            auto ct0_alt = cc.encrypt(sk, 0);

            auto ct11 = cc.eval_bin_gate(test_data.gate, ct1, ct1_alt);
            auto ct01 = cc.eval_bin_gate(test_data.gate, ct0, ct1);
            auto ct10 = cc.eval_bin_gate(test_data.gate, ct1, ct0);
            auto ct00 = cc.eval_bin_gate(test_data.gate, ct0, ct0_alt);

            LwePlaintext result11;
            cc.decrypt(sk, ct11, &result11);
            LwePlaintext result01;
            cc.decrypt(sk, ct01, &result01);
            LwePlaintext result10;
            cc.decrypt(sk, ct10, &result10);
            LwePlaintext result00;
            cc.decrypt(sk, ct00, &result00);

            std::string failed = test_data.to_string_impl() + " failed";

            EXPECT_EQ(test_data.results[0], result11) << failed;
            EXPECT_EQ(test_data.results[1], result01) << failed;
            EXPECT_EQ(test_data.results[2], result10) << failed;
            EXPECT_EQ(test_data.results[3], result00) << failed;
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS_BINFHE;
        }
    }

    void unit_test_fhew_multiinput(const TEST_CASE_UTGENERAL_FHEW& test_data,
                                   const std::string& failmsg = std::string()) {
        try {
            auto cc = BooleanContext();
            cc.generate_boolean_context(test_data.security_level, test_data.method);

            auto sk = cc.key_gen();

            cc.bt_key_gen(sk);

            std::vector<LweCiphertext> ctvec;
            if (test_data.num_of_inputs == 3) {
                auto ct1 = cc.encrypt(sk, 1, SMALL_DIM, test_data.ptmodulus);
                auto ct2 = cc.encrypt(sk, 1, SMALL_DIM, test_data.ptmodulus);
                auto ct3 = cc.encrypt(sk, 0, SMALL_DIM, test_data.ptmodulus);
                ctvec.push_back(ct1);
                ctvec.push_back(ct2);
                ctvec.push_back(ct3);
            } else if (test_data.num_of_inputs == 4) {
                auto ct1 = cc.encrypt(sk, 1, SMALL_DIM, test_data.ptmodulus);
                auto ct2 = cc.encrypt(sk, 0, SMALL_DIM, test_data.ptmodulus);
                auto ct3 = cc.encrypt(sk, 0, SMALL_DIM, test_data.ptmodulus);
                auto ct4 = cc.encrypt(sk, 0, SMALL_DIM, test_data.ptmodulus);
                ctvec.push_back(ct1);
                ctvec.push_back(ct2);
                ctvec.push_back(ct3);
                ctvec.push_back(ct4);
            }

            auto ct11 = cc.eval_bin_gate(test_data.gate, ctvec);
            LwePlaintext result11;
            cc.decrypt(sk, ct11, &result11, test_data.ptmodulus);

            std::string failed = test_data.to_string_impl() + " failed";

            EXPECT_EQ(test_data.results[0], result11) << failed;
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS_BINFHE;
        }
    }

    void unit_test_fhew_cmux(const TEST_CASE_UTGENERAL_FHEW& test_data, const std::string& failmsg = std::string()) {
        try {
            auto cc = BooleanContext();
            cc.generate_boolean_context(test_data.security_level, test_data.method);

            auto sk = cc.key_gen();
            cc.bt_key_gen(sk);

            auto ct1 = cc.encrypt(sk, 1, SMALL_DIM, test_data.ptmodulus);
            auto ct2 = cc.encrypt(sk, 1, SMALL_DIM, test_data.ptmodulus);
            auto ct3 = cc.encrypt(sk, 0, SMALL_DIM, test_data.ptmodulus);
            auto ct4 = cc.encrypt(sk, 0, SMALL_DIM, test_data.ptmodulus);

            // 1, 0, 0
            std::vector<LweCiphertext> ct134;
            ct134.push_back(ct1);
            ct134.push_back(ct3);
            ct134.push_back(ct4);

            // 1, 0, 1
            std::vector<LweCiphertext> ct132;
            ct132.push_back(ct1);
            ct132.push_back(ct3);
            ct132.push_back(ct2);

            // 1, 0, 1
            auto ct_cmux0 = cc.eval_bin_gate(test_data.gate, ct132);

            // 1, 0, 0
            auto ct_cmux1 = cc.eval_bin_gate(test_data.gate, ct134);

            LwePlaintext result1;
            cc.decrypt(sk, ct_cmux1, &result1, test_data.ptmodulus);

            LwePlaintext result0;
            cc.decrypt(sk, ct_cmux0, &result0, test_data.ptmodulus);

            std::string failed = test_data.to_string_impl() + " failed";

            EXPECT_EQ(test_data.results[0], result1) << failed;
            EXPECT_EQ(test_data.results[1], result0) << failed;
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
            // make it fail
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS_BINFHE;
        }
    }
};
//===========================================================================================================
TEST_P(UTGENERAL_FHEW, BINFHE) {
    // setup_signals();
    auto test = GetParam();

    switch (test.test_case_type) {
        case FHEW_AND:
        case FHEW_NAND:
        case FHEW_OR:
        case FHEW_NOR:
        case FHEW_XOR:
        case FHEW_XNOR:
        case FHEW_SIGNED_MODE:
            unit_test_fhew(test, test.build_test_name());
            break;
        case FHEW_AND3:
        case FHEW_OR3:
        case FHEW_AND4:
        case FHEW_OR4:
        case FHEW_MAJORITY:
            unit_test_fhew_multiinput(test, test.build_test_name());
            break;
        case FHEW_CMUX:
            unit_test_fhew_cmux(test, test.build_test_name());
            break;
        case FHEW_KEY_SWITCH:
            unit_test_fhew_key_switch(test, test.build_test_name());
            break;
        case FHEW_MOD_SWITCH:
            unit_test_fhew_mod_switch(test, test.build_test_name());
            break;
        case FHEW_NOT:
            unit_test_fhew_not(test, test.build_test_name());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTGENERAL_FHEW, ::testing::ValuesIn(test_cases_utgeneral_fhew), make_test_name);
