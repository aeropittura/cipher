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
#include <map>
#include <numeric>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "fhe/support/base_test_case.h"
#include "fhe/support/cc_params.h"
#include "fhe/support/crypto_context.h"
#include "fhe/support/csv_data.h"
#include "fhe/support/test_utils.h"
#include "gtest/gtest.h"

using namespace cipher;
class Params;

//===========================================================================================================
enum TEST_CASE_TYPE : int {
    BGVRNS_AUTOMORPHISM = 0,
    EVAL_AT_INDX_PACKED_ARRAY,
    EVAL_SUM_PACKED_ARRAY,
};
TEST_CASE_TYPE convert_string_to_case_type(const std::string& str) {
    const std::unordered_map<std::string, TEST_CASE_TYPE> string_to_case_type = {
            {"BGVRNS_AUTOMORPHISM", BGVRNS_AUTOMORPHISM},
            {"EVAL_AT_INDX_PACKED_ARRAY", EVAL_AT_INDX_PACKED_ARRAY},
            {"EVAL_SUM_PACKED_ARRAY", EVAL_SUM_PACKED_ARRAY}};
    auto search = string_to_case_type.find(str);
    if (string_to_case_type.end() != search) {
        return search->second;
    }
    CIPHER_THROW(std::string("Can not convert ") + str + "to test case");
}
static std::ostream& operator<<(std::ostream& os, const TEST_CASE_TYPE& type) {
    const std::unordered_map<TEST_CASE_TYPE, std::string> case_type_to_string = {
            {BGVRNS_AUTOMORPHISM, "BGVRNS_AUTOMORPHISM"},
            {EVAL_AT_INDX_PACKED_ARRAY, "EVAL_AT_INDX_PACKED_ARRAY"},
            {EVAL_SUM_PACKED_ARRAY, "EVAL_SUM_PACKED_ARRAY"}};
    auto search = case_type_to_string.find(type);
    if (case_type_to_string.end() != search) {
        return os << search->second;
    }
    CIPHER_THROW("Unknown test case");
}
//===========================================================================================================
enum TEST_CASE_ERROR {
    SUCCESS = 0,
    CORNER_CASES,
    INVALID_INPUT_DATA,
    INVALID_PRIVATE_KEY,
    INVALID_PUBLIC_KEY,
    INVALID_EVAL_KEY,
    INVALID_INDEX,
    INVALID_BATCH_SIZE,
    NO_KEY_GEN_CALL
};
TEST_CASE_ERROR convert_string_to_case_error(const std::string& str) {
    std::unordered_map<std::string, TEST_CASE_ERROR> string_to_error = {
            {"SUCCESS", SUCCESS},
            {"CORNER_CASES", CORNER_CASES},
            {"INVALID_INPUT_DATA", INVALID_INPUT_DATA},
            {"INVALID_PRIVATE_KEY", INVALID_PRIVATE_KEY},
            {"INVALID_PUBLIC_KEY", INVALID_PUBLIC_KEY},
            {"INVALID_EVAL_KEY", INVALID_EVAL_KEY},
            {"INVALID_INDEX", INVALID_INDEX},
            {"INVALID_BATCH_SIZE", INVALID_BATCH_SIZE},
            {"NO_KEY_GEN_CALL", NO_KEY_GEN_CALL},
    };
    auto search = string_to_error.find(str);
    if (string_to_error.end() != search) {
        return search->second;
    }
    CIPHER_THROW(std::string("Can not convert ") + str + "to test case error");
}
//===========================================================================================================
struct TEST_CASE_UTBGVRNS_AUTOMORPHISM : public BaseTestCase {
    TEST_CASE_TYPE test_case_type;
    // test case description - MUST BE UNIQUE
    std::string description;

    // additional test case data
    TEST_CASE_ERROR error;
    std::vector<uint32_t> index_list;

    std::string build_test_name() const {
        std::stringstream ss;
        ss << test_case_type << "_" << description;
        return ss.str();
    }
    std::string to_string_impl() const {
        std::stringstream ss;
        ss << "[testCase: " << test_case_type << "], [description: " << description
           << "], [params: " << get_crypto_context_param_overrides() << "], [error: " << error
           << "], [indexList: " << index_list << "] ";
        return ss.str();
    }
};

// this lambda provides a name to be printed for every test run by INSTANTIATE_TEST_SUITE_P.
// the name MUST be constructed from digits, letters and '_' only
static auto testName = [](const testing::TestParamInfo<TEST_CASE_UTBGVRNS_AUTOMORPHISM>& test_param_info) {
    return test_param_info.param.build_test_name();
};

static std::ostream& operator<<(std::ostream& os, const TEST_CASE_UTBGVRNS_AUTOMORPHISM& test) {
    return os << test.to_string_impl();
}
//===========================================================================================================
std::vector<TEST_CASE_UTBGVRNS_AUTOMORPHISM> get_test_data(std::string file_name) {
    // TODO: add a new test data file for CIPHER_NATIVE_INT == 128
    std::string test_data_file_name(create_data_file_name(file_name));
    std::vector<std::vector<std::string>> file_rows(read_data_file(test_data_file_name));
    size_t num_rows = file_rows.size();

    std::vector<TEST_CASE_UTBGVRNS_AUTOMORPHISM> all_data;
    all_data.reserve(num_rows);

    for (const std::vector<std::string>& vec : file_rows) {
        TEST_CASE_UTBGVRNS_AUTOMORPHISM test_case_value;

        auto it = vec.begin();
        test_case_value.test_case_type = convert_string_to_case_type(*it);
        test_case_value.description = *(++it);

        // size_t num_overrides = test_case_value.populateCryptoContextParams(++it);
        size_t num_overrides = test_case_value.set_crypto_context_params_overrides(++it);

        it += num_overrides;
        if (it != vec.end()) {
            // process TEST_CASE_ERROR
            test_case_value.error = convert_string_to_case_error(*it);
            if (++it != vec.end()) {
                // process list of indices
                std::string index_list_str(*it);
                if (!isEmpty(index_list_str)) {
                    std::vector<std::string> indices = tokenize(index_list_str, '|');
                    for (std::string& i : indices) {
                        test_case_value.index_list.push_back(static_cast<uint32_t>(std::stoul(i)));
                    }
                }
            }
        }

        all_data.push_back(std::move(test_case_value));
    }
    return all_data;
}
//===========================================================================================================
static std::vector<TEST_CASE_UTBGVRNS_AUTOMORPHISM> test_cases_utbgvrns_automorphism = get_test_data(__FILE__);
//===========================================================================================================

class UTBGVRNS_AUTOMORPHISM : public ::testing::TestWithParam<TEST_CASE_UTBGVRNS_AUTOMORPHISM> {
    using Element = RnsPoly;
    const double eps = EPSILON;

    const std::vector<int64_t> vector8{1, 2, 3, 4, 5, 6, 7, 8};
    const std::vector<int64_t> vector_failure{1, 2, 3, 4};
    const uint32_t invalid_index_automorphism = 4;
    const int64_t vector8_sum = std::accumulate(vector8.begin(), vector8.end(), int64_t(0));  // 36

  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    void TearDown() {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

    void unit_test_automorphism_packed_array(const TEST_CASE_UTBGVRNS_AUTOMORPHISM& test_data,
                                          const std::string& failmsg = std::string()) {
        for (auto index : test_data.index_list) {
            try {
                CryptoContext<Element> cc(unit_test_generate_context(test_data));

                // Initialize the public key containers.
                KeyPair<Element> kp = cc->key_gen();

                index = (INVALID_INDEX == test_data.error) ? invalid_index_automorphism : index;
                std::vector<int64_t> input_vec = (INVALID_INPUT_DATA == test_data.error) ? vector_failure : vector8;
                Plaintext int_array = cc->make_packed_plaintext(input_vec);

                Ciphertext<Element> ciphertext =
                        (INVALID_PUBLIC_KEY == test_data.error) ?
                                cc->encrypt(static_cast<const PublicKey<Element>>(nullptr), int_array) :
                                cc->encrypt(kp.public_key, int_array);

                std::vector<uint32_t> index_list(test_data.index_list);

                auto eval_keys =
                        (INVALID_PRIVATE_KEY == test_data.error) ?
                                cc->eval_automorphism_key_gen(static_cast<const PrivateKey<Element>>(nullptr), index_list) :
                                cc->eval_automorphism_key_gen(kp.secret_key, index_list);

                std::map<uint32_t, EvalKey<Element>> empty_eval_keys;
                Ciphertext<Element> p1 = (INVALID_EVAL_KEY == test_data.error) ?
                                                 cc->eval_automorphism(ciphertext, index, empty_eval_keys) :
                                                 cc->eval_automorphism(ciphertext, index, *eval_keys);

                Plaintext int_array_new;
                cc->decrypt(kp.secret_key, p1, &int_array_new);

                std::string err_msg(" for index[" + std::to_string(index) + "]");
                switch (test_data.error) {
                    case SUCCESS:
                        // should not fail
                        EXPECT_TRUE(check_automorphism(int_array_new->get_packed_value(), vector8)) << err_msg;
                        break;
                    case INVALID_INPUT_DATA:
                        // should fail
                        EXPECT_FALSE(check_automorphism(int_array_new->get_packed_value(), vector8)) << err_msg;
                        break;
                    default:
                        // make it fail
                        std::cerr << __func__ << " failed " << err_msg << std::endl;
                        EXPECT_EQ(0, 1);
                        break;
                }
            } catch (std::exception& e) {
                switch (test_data.error) {
                    case SUCCESS:
                    case INVALID_INPUT_DATA:
                        std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
                        // make it fail
                        EXPECT_EQ(0, 1);
                        break;
                    default:
                        EXPECT_EQ(1, 1);
                        break;
                }
            } catch (...) {
                UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
            }
        }
    }

    void unit_test_eval_at_index_packed_array(const TEST_CASE_UTBGVRNS_AUTOMORPHISM& test_data,
                                         const std::string& failmsg = std::string()) {
        for (auto index : test_data.index_list) {
            try {
                CryptoContext<Element> cc(unit_test_generate_context(test_data));

                // Initialize the public key containers.
                KeyPair<Element> kp = cc->key_gen();

                std::vector<int64_t> input_vec = (INVALID_INPUT_DATA == test_data.error) ? vector_failure : vector8;
                Plaintext int_array = cc->make_packed_plaintext(input_vec);

                if (NO_KEY_GEN_CALL != test_data.error) {
                    std::vector<int32_t> indices{(int32_t)index, (int32_t)-index};
                    if (INVALID_PRIVATE_KEY == test_data.error)
                        cc->eval_at_index_key_gen(static_cast<const PrivateKey<Element>>(nullptr), indices);
                    else
                        cc->eval_at_index_key_gen(kp.secret_key, indices);
                }

                Ciphertext<Element> ciphertext =
                        (INVALID_PUBLIC_KEY == test_data.error) ?
                                cc->encrypt(static_cast<const PublicKey<Element>>(nullptr), int_array) :
                                cc->encrypt(kp.public_key, int_array);

                if (INVALID_INDEX == test_data.error)
                    index = invalid_index_automorphism;
                Ciphertext<Element> p1 = cc->eval_at_index(ciphertext, index);
                Ciphertext<Element> p2 = cc->eval_at_index(p1, -index);

                Plaintext int_array_new;
                cc->decrypt(kp.secret_key, p2, &int_array_new);
                int_array_new->set_length(input_vec.size());

                std::string err_msg(" for index[" + std::to_string(index) + "]");
                switch (test_data.error) {
                    case SUCCESS:
                    case CORNER_CASES:
                        // should not fail
                        check_equality(int_array_new->get_packed_value(), vector8, eps, err_msg);
                        break;
                    case INVALID_INPUT_DATA:
                        // should fail
                        EXPECT_FALSE(check_equality(int_array_new->get_packed_value(), vector8)) << err_msg;
                        break;
                    default:
                        // make it fail
                        std::cerr << __func__ << " failed " << err_msg << std::endl;
                        EXPECT_EQ(0, 1);
                        break;
                }
            } catch (std::exception& e) {
                switch (test_data.error) {
                    case SUCCESS:
                    case CORNER_CASES:
                    case INVALID_INPUT_DATA:
                        std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
                        // make it fail
                        EXPECT_EQ(0, 1);
                        break;
                    default:
                        EXPECT_EQ(1, 1);
                        break;
                }
            } catch (...) {
                UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
            }
        }
    }

    void unit_test_eval_sum_packed_array(const TEST_CASE_UTBGVRNS_AUTOMORPHISM& test_data,
                                     const std::string& failmsg = std::string()) {
        try {
            CryptoContext<Element> cc(unit_test_generate_context(test_data));

            // Initialize the public key containers.
            KeyPair<Element> kp = cc->key_gen();

            std::vector<int64_t> input_vec = vector8;
            Plaintext int_array = cc->make_packed_plaintext(input_vec);

            if (NO_KEY_GEN_CALL != test_data.error) {
                if (INVALID_PRIVATE_KEY == test_data.error)
                    cc->eval_sum_key_gen(static_cast<const PrivateKey<Element>>(nullptr));
                else
                    cc->eval_sum_key_gen(kp.secret_key);
            }

            Ciphertext<Element> ciphertext =
                    (INVALID_PUBLIC_KEY == test_data.error) ?
                            cc->encrypt(static_cast<const PublicKey<Element>>(nullptr), int_array) :
                            cc->encrypt(kp.public_key, int_array);

            uint32_t batch_size = 8;
            uint32_t batch_sz = (INVALID_BATCH_SIZE == test_data.error) ? (batch_size * 1000) : batch_size;
            Ciphertext<Element> p1 = cc->eval_sum(ciphertext, batch_sz);

            Plaintext int_array_new;
            cc->decrypt(kp.secret_key, p1, &int_array_new);

            switch (test_data.error) {
                case SUCCESS:
                    // should not fail
                    EXPECT_TRUE(check_equality(int_array_new->get_packed_value()[0], vector8_sum));
                    break;
                default:
                    // make it fail
                    std::cerr << __func__ << " failed" << std::endl;
                    EXPECT_EQ(0, 1);
                    break;
            }
        } catch (std::exception& e) {
            if (SUCCESS == test_data.error) {
                std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
                // make it fail
                EXPECT_EQ(0, 1);
            } else
                EXPECT_EQ(1, 1);
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
};

//===========================================================================================================
TEST_P(UTBGVRNS_AUTOMORPHISM, Automorphism) {
    setup_signals();
    auto test = GetParam();

    switch (test.test_case_type) {
        case BGVRNS_AUTOMORPHISM:
            unit_test_automorphism_packed_array(test, test.build_test_name());
            break;
        case EVAL_AT_INDX_PACKED_ARRAY:
            unit_test_eval_at_index_packed_array(test, test.build_test_name());
            break;
        case EVAL_SUM_PACKED_ARRAY:
            unit_test_eval_sum_packed_array(test, test.build_test_name());
            break;
        default:
            break;
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTBGVRNS_AUTOMORPHISM, ::testing::ValuesIn(test_cases_utbgvrns_automorphism),
                         testName);
