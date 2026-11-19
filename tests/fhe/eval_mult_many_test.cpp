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
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/fhe/encoding/encodings.h"
#include "cipher/fhe/context_gen.h"
#include "gtest/gtest.h"
#include "cipher/fhe/bfv/context_gen.h"
#include "cipher/util/debug.h"

using namespace cipher;

class UTGENERAL_EVAL_MULT_MANY : public ::testing::Test {
  protected:
    virtual void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    virtual void TearDown() {
        cipher_parallel_controls.unit_test_stop();
    }

  public:
};

static CryptoContext<RnsPoly> make_bfv_rns_rns_poly_cc() {
    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(256);
    parameters.set_standard_deviation(4);
    parameters.set_multiplicative_depth(3);
    parameters.set_max_relin_sk_deg(4);
    parameters.set_scaling_mod_size(60);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);
    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);
    crypto_context->enable(ADVANCEDSHE);

    return crypto_context;
}

template <typename Element>
static void run_eval_mult_many_test(CryptoContext<Element> cc, std::string msg);

// Tests eval_mult w/o keyswitching and eval_mult_many for BFVrns in the
// UNIFORM_TERNARY mode
TEST(UTGENERAL_EVAL_MULT_MANY, Poly_BFVrns_Eval_Mult_Many_Operations) {
    run_eval_mult_many_test(make_bfv_rns_rns_poly_cc(), "BFVrns");
}

template <typename Element>
static void run_eval_mult_many_test(CryptoContext<Element> crypto_context, std::string msg) {
    CIPHER_DEBUG_FLAG(false);
    ////////////////////////////////////////////////////////////
    // Perform the key generation operation.
    ////////////////////////////////////////////////////////////
    CIPHER_DEBUG("In run_eval_mult_many_test " << msg);
    auto key_pair = crypto_context->key_gen();
    CIPHER_DEBUG("keygen");
    ASSERT_TRUE(key_pair.good()) << "Key generation failed!";
    CIPHER_DEBUG("eval_mult_keys_gen");
    // Create evaluation key vector to be used in keyswitching

    crypto_context->eval_mult_keys_gen(key_pair.secret_key);

    ////////////////////////////////////////////////////////////
    // Plaintext
    ////////////////////////////////////////////////////////////

    std::vector<int64_t> vector_of_ints1 = {5, 4, 3, 2, 1, 0, 5, 4, 3, 2, 1, 0};
    std::vector<int64_t> vector_of_ints2 = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    std::vector<int64_t> vector_of_ints3 = {3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    std::vector<int64_t> vector_of_ints4 = {4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    std::vector<int64_t> vector_of_ints5 = {10, 8, 6, 4, 2, 0, 10, 8, 6, 4, 2, 0};
    std::vector<int64_t> vector_of_ints6 = {30, 24, 18, 12, 6, 0, 30, 24, 18, 12, 6, 0};
    std::vector<int64_t> vector_of_ints7 = {120, 96, 72, 48, 24, 0, 120, 96, 72, 48, 24, 0};

    CIPHER_DEBUG("make_coef_packed_plaintext");
    Plaintext plaintext1 = crypto_context->make_coef_packed_plaintext(vector_of_ints1);
    Plaintext plaintext2 = crypto_context->make_coef_packed_plaintext(vector_of_ints2);
    Plaintext plaintext3 = crypto_context->make_coef_packed_plaintext(vector_of_ints3);
    Plaintext plaintext4 = crypto_context->make_coef_packed_plaintext(vector_of_ints4);

    Plaintext plaintext_result1 = crypto_context->make_coef_packed_plaintext(vector_of_ints5);
    Plaintext plaintext_result2 = crypto_context->make_coef_packed_plaintext(vector_of_ints6);
    Plaintext plaintext_result3 = crypto_context->make_coef_packed_plaintext(vector_of_ints7);

    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////
    CIPHER_DEBUG("Encryption");
    auto ciphertext1 = crypto_context->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = crypto_context->encrypt(key_pair.public_key, plaintext2);
    auto ciphertext3 = crypto_context->encrypt(key_pair.public_key, plaintext3);
    auto ciphertext4 = crypto_context->encrypt(key_pair.public_key, plaintext4);

    ////////////////////////////////////////////////////////////
    // eval_mult Operation
    ////////////////////////////////////////////////////////////
    CIPHER_DEBUG("EvalMults");
    // Perform consecutive multiplications and do a keyswtiching at the end.
    auto ciphertext_mul12 = crypto_context->eval_mult_no_relin(ciphertext1, ciphertext2);
    auto ciphertext_mul123 = crypto_context->eval_mult_no_relin(ciphertext_mul12, ciphertext3);
    auto ciphertext_mul1234 = crypto_context->eval_mult_and_relinearize(ciphertext_mul123, ciphertext4);

    ////////////////////////////////////////////////////////////
    // Decryption of multiplicative results with and without keyswtiching (depends
    // on the level)
    ////////////////////////////////////////////////////////////

    Plaintext plaintext_mul1;
    Plaintext plaintext_mul2;
    Plaintext plaintext_mul3;
    CIPHER_DEBUG("DECRYPTIO");
    crypto_context->decrypt(key_pair.secret_key, ciphertext_mul12, &plaintext_mul1);
    crypto_context->decrypt(key_pair.secret_key, ciphertext_mul123, &plaintext_mul2);
    crypto_context->decrypt(key_pair.secret_key, ciphertext_mul1234, &plaintext_mul3);

    ////////////////////////////////////////////////////////////
    // Prepare eval_mult_many
    ////////////////////////////////////////////////////////////

    std::vector<Ciphertext<Element>> cipher_text_list;

    cipher_text_list.push_back(ciphertext1);
    cipher_text_list.push_back(ciphertext2);
    cipher_text_list.push_back(ciphertext3);
    cipher_text_list.push_back(ciphertext4);

    ////////////////////////////////////////////////////////////
    // Compute eval_mult_many
    ////////////////////////////////////////////////////////////

    auto ciphertext_mul12345 = crypto_context->eval_mult_many(cipher_text_list);

    ////////////////////////////////////////////////////////////
    // Decrypt eval_mult_many
    ////////////////////////////////////////////////////////////

    Plaintext plaintext_mul_many;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_mul12345, &plaintext_mul_many);

    plaintext_result1->set_length(plaintext_mul1->get_length());
    plaintext_result2->set_length(plaintext_mul2->get_length());
    plaintext_result3->set_length(plaintext_mul3->get_length());

    EXPECT_EQ(*plaintext_mul1, *plaintext_result1) << msg << ".EvalMult gives incorrect results.\n";
    EXPECT_EQ(*plaintext_mul2, *plaintext_result2) << msg << ".EvalMult gives incorrect results.\n";
    EXPECT_EQ(*plaintext_mul3, *plaintext_result3) << msg << ".eval_mult_and_relinearize gives incorrect results.\n";
    EXPECT_EQ(*plaintext_mul_many, *plaintext_result3) << msg << ".eval_mult_many gives incorrect results.\n";
}
