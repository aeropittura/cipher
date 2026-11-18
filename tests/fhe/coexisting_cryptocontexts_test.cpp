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
/***
 * Very qiuck unittest to verify that ring_dim for the first cryptocontext is not overriden by
 * creation of another cryptocontext. This test's code should be as close to a regular user project
 * as possible
 */

#include <vector>

#include "fhe/support/test_utils.h"
#include "include/gtest/gtest.h"
#include "cipher/cipher.h"

using namespace cipher;

class UTGENERAL_CRYPTOCONTEXTS : public ::testing::Test {
  protected:
    virtual void SetUp() {
        cipher_parallel_controls.unit_test_start();
    }

    virtual void TearDown() {
        ContextFactory<RnsPoly>::release_all_contexts();
        cipher_parallel_controls.unit_test_stop();
    }
};

TEST_F(UTGENERAL_CRYPTOCONTEXTS, coexisting_ckks_cryptocontexts) {
    // Setup crypto context 1
    ContextParams<CkksRnsContext> parameters1;
    parameters1.set_multiplicative_depth(2);
    parameters1.set_scaling_mod_size(40);
    parameters1.set_ring_dim(4096 * 4);
    parameters1.set_batch_size(32);

    CryptoContext<cipher::RnsPoly> cc1 = make_crypto_context(parameters1);
    cc1->enable(PKE);
    cc1->enable(KEYSWITCH);
    cc1->enable(LEVELEDSHE);
    cipher::KeyPair<cipher::RnsPoly> key1 = cc1->key_gen();

    // Setup crypto context 2 for testing (not used)
    ContextParams<CkksRnsContext> parameters2;
    parameters2.set_multiplicative_depth(1);
    parameters2.set_scaling_mod_size(30);
    parameters2.set_ring_dim(16);
    parameters2.set_batch_size(4);
    parameters2.set_security_level(HEStd_NotSet);

    CryptoContext<cipher::RnsPoly> cc2 = make_crypto_context(parameters2);
    cc2->enable(PKE);
    cc2->enable(KEYSWITCH);
    cc2->enable(LEVELEDSHE);
    cipher::KeyPair<cipher::RnsPoly> key2 = cc2->key_gen();

    // Setup crypto context 3 for testing (not used)
    ContextParams<CkksRnsContext> parameters3;
    parameters3.set_multiplicative_depth(2);
    parameters3.set_scaling_mod_size(50);
    parameters3.set_ring_dim(2048);
    parameters3.set_digit_size(3);
    parameters3.set_batch_size(16);
    parameters3.set_security_level(HEStd_NotSet);
    parameters3.set_key_switch_technique(BV);
    parameters3.set_scaling_technique(FIXEDMANUAL);

    CryptoContext<cipher::RnsPoly> cc3 = make_crypto_context(parameters3);
    cc3->enable(PKE);
    cc3->enable(KEYSWITCH);
    cc3->enable(LEVELEDSHE);
    cipher::KeyPair<cipher::RnsPoly> key3 = cc3->key_gen();

    // Encrypt
    std::vector<double> values = {1.0, 1.1, 1.2};
    // const size_t dataSize = values.size();
    Plaintext ptxt = cc1->make_ckks_packed_plaintext(values);
    auto ciphertext = cc1->encrypt(ptxt, key1.public_key);

    // Decrypt
    Plaintext results;
    cc1->decrypt(ciphertext, key1.secret_key, &results);
    results->set_length(ptxt->get_length());

    constexpr double epsilon = 0.0000001;
    EXPECT_TRUE(check_equality(values, results->get_real_packed_value(), epsilon))
            << "static data for the first cryptocontext may be overriden";
}
