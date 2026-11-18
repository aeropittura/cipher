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

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <map>
#include <numeric>
#include <vector>

#include "fhe/support/test_utils.h"
#include "cipher/fhe/context.h"
#include "cipher/fhe/encoding/encodings.h"
#include "cipher/fhe/context_gen.h"
#include "gtest/gtest.h"
#include "cipher/fhe/bfv/context_gen.h"
#include "cipher/util/debug.h"

using namespace cipher;

namespace {
class UTBFVRNS_AUTOMORPHISM : public ::testing::Test {
  protected:
    void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    void TearDown() {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }

  public:
};

const std::vector<int64_t> vector8{1, 2, 3, 4, 5, 6, 7, 8};
const std::vector<int64_t> vector10{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
const std::vector<int64_t> vector_failure{1, 2, 3, 4};
const std::vector<uint32_t> init_index_list{3, 5, 7, 9, 11, 13, 15};
const uint32_t invalid_index_automorphism = 4;
const int64_t vector8_sum = std::accumulate(vector8.begin(), vector8.end(), int64_t(0));  // 36

enum TEST_ESTIMATED_RESULT {
    SUCCESS,
    INVALID_INPUT_DATA,
    INVALID_PRIVATE_KEY,
    INVALID_PUBLIC_KEY,
    INVALID_EVAL_KEY,
    INVALID_INDEX,
    INVALID_BATCH_SIZE,
    NO_KEY_GEN_CALL
};

}  // anonymous namespace

//================================================================================================

// declaration for Automorphism Test on BFVrns scheme with polynomial operation
// in power of 2 cyclotomics.
std::vector<int64_t> bfv_rns_automorphism_packed_array(uint32_t i, TEST_ESTIMATED_RESULT test_result = SUCCESS) {
    using Element = RnsPoly;
    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(65537);
    parameters.set_standard_deviation(4);
    parameters.set_scaling_mod_size(60);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);

    // Initialize the public key containers.
    KeyPair<Element> kp = cc->key_gen();

    i = (INVALID_INDEX == test_result) ? invalid_index_automorphism : i;
    std::vector<int64_t> input_vec = (INVALID_INPUT_DATA == test_result) ? vector_failure : vector8;
    Plaintext int_array = cc->make_packed_plaintext(input_vec);

    Ciphertext<Element> ciphertext = (INVALID_PUBLIC_KEY == test_result) ?
                                             cc->encrypt(PublicKey<Element>(nullptr), int_array) :
                                             cc->encrypt(kp.public_key, int_array);

    std::vector<uint32_t> index_list(init_index_list);

    auto eval_keys = (INVALID_PRIVATE_KEY == test_result) ?
                            cc->eval_automorphism_key_gen(PrivateKey<Element>(nullptr), index_list) :
                            cc->eval_automorphism_key_gen(kp.secret_key, index_list);

    std::map<uint32_t, EvalKey<Element>> empty_eval_keys;
    Ciphertext<Element> p1 = (INVALID_EVAL_KEY == test_result) ? cc->eval_automorphism(ciphertext, i, empty_eval_keys) :
                                                                cc->eval_automorphism(ciphertext, i, *eval_keys);

    Plaintext int_array_new;
    cc->decrypt(kp.secret_key, p1, &int_array_new);

    return int_array_new->get_packed_value();
}

TEST_F(UTBFVRNS_AUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2) {
    PackedEncoding::destroy();

    for (auto index : init_index_list) {
        auto morphed_vector = bfv_rns_automorphism_packed_array(index);
        EXPECT_TRUE(check_automorphism(morphed_vector, vector8));
    }
}

TEST_F(UTBFVRNS_AUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2_INVALID_INPUT_DATA) {
    PackedEncoding::destroy();

    for (auto index : init_index_list) {
        auto morphed_vector = bfv_rns_automorphism_packed_array(index, INVALID_INPUT_DATA);
        EXPECT_FALSE(check_automorphism(morphed_vector, vector8));
    }
}

TEST_F(UTBFVRNS_AUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2_INVALID_PRIVATE_KEY) {
    PackedEncoding::destroy();

    try {
        for (auto index : init_index_list) {
            auto morphed_vector = bfv_rns_automorphism_packed_array(index, INVALID_PRIVATE_KEY);
            EXPECT_EQ(0, 1);
        }
    } catch (const std::exception& e) {
        // std::cout << "Test_BFVrns_Automorphism_PowerOf2_INVALID_PRIVATE_KEY exception: " << e.what() << std::endl;
        EXPECT_EQ(1, 1);
    }
}

TEST_F(UTBFVRNS_AUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2_INVALID_PUBLIC_KEY) {
    PackedEncoding::destroy();

    try {
        for (auto index : init_index_list) {
            auto morphed_vector = bfv_rns_automorphism_packed_array(index, INVALID_PUBLIC_KEY);
            EXPECT_EQ(0, 1);
        }
    } catch (const std::exception& e) {
        // std::cout << "Test_BFVrns_Automorphism_PowerOf2_INVALID_PUBLIC_KEY exception: " << e.what() << std::endl;
        EXPECT_EQ(1, 1);
    }
}

TEST_F(UTBFVRNS_AUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2_INVALID_EVAL_KEY) {
    PackedEncoding::destroy();

    try {
        for (auto index : init_index_list) {
            auto morphed_vector = bfv_rns_automorphism_packed_array(index, INVALID_EVAL_KEY);
            EXPECT_EQ(0, 1);
        }
    } catch (const std::exception& e) {
        // std::cout << "Test_BFVrns_Automorphism_PowerOf2_INVALID_EVAL_KEY exception: " << e.what() << std::endl;
        EXPECT_EQ(1, 1);
    }
}

TEST_F(UTBFVRNS_AUTOMORPHISM, Test_BFVrns_Automorphism_PowerOf2_INVALID_INDEX) {
    PackedEncoding::destroy();

    try {
        for (auto index : init_index_list) {
            auto morphed_vector = bfv_rns_automorphism_packed_array(index, INVALID_INDEX);
            EXPECT_EQ(0, 1);
        }
    } catch (const std::exception& e) {
        // std::cout << "Test_BFVrns_Automorphism_PowerOf2_INVALID_INDEX exception: " << e.what() << std::endl;
        EXPECT_EQ(1, 1);
    }
}
