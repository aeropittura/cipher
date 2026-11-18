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

/*
  unit tests for Proxy Re-Encryption. Demo software for multiparty proxy reencryption operations for various schemes
 */

#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

#include "cipher/fhe/context.h"
#include "cipher/fhe/context_gen.h"
#include "include/gtest/gtest.h"
#include "cipher/fhe/bgv/context_gen.h"

using namespace cipher;

class UTGENERAL_MULTIHOP_PRE : public ::testing::TestWithParam<uint32_t> {
  protected:
    int run_demo_pre(uint32_t security_model, uint32_t num_of_hops) {
        // Generate parameters.
        PlaintextModulus plaintext_modulus{2};
        uint32_t ring_dimension_value;
        uint32_t digit_size;
        ContextParams<BgvRnsContext> parameters;

        if (security_model == 0) {
            ring_dimension_value = 1024;
            digit_size = 9;
            parameters.set_pre_mode(INDCPA);
            parameters.set_key_switch_technique(BV);
            parameters.set_first_mod_size(27);
        } else if (security_model == 1) {
            ring_dimension_value = 2048;
            digit_size = 16;
            parameters.set_pre_mode(FIXED_NOISE_HRA);
            parameters.set_key_switch_technique(BV);
            parameters.set_first_mod_size(54);
        } else if (security_model == 2) {
            ring_dimension_value = 8192;
            digit_size = 10;
            parameters.set_pre_mode(NOISE_FLOODING_HRA);
            parameters.set_key_switch_technique(BV);
            parameters.set_pre_num_hops(num_of_hops);
            parameters.set_statistical_security(40);
            parameters.set_num_adversarial_queries(1048576);
        } else if (security_model == 3) {
            ring_dimension_value = 8192;
            digit_size = 0;
            parameters.set_pre_mode(NOISE_FLOODING_HRA);
            parameters.set_key_switch_technique(HYBRID);
            parameters.set_pre_num_hops(num_of_hops);
            parameters.set_statistical_security(40);
            parameters.set_num_adversarial_queries(1048576);
        } else {
            CIPHER_THROW("invalid security model");
        }

        parameters.set_multiplicative_depth(0);
        parameters.set_plaintext_modulus(plaintext_modulus);
        parameters.set_ring_dim(ring_dimension_value);
        parameters.set_digit_size(digit_size);
        parameters.set_scaling_technique(FIXEDMANUAL);
        parameters.set_security_level(HEStd_NotSet);

        auto cc = make_crypto_context(parameters);
        cc->enable(PKE);
        cc->enable(KEYSWITCH);
        cc->enable(LEVELEDSHE);
        cc->enable(PRE);

        ////////////////////////////////////////////////////////////
        // Perform Key Generation Operation
        ////////////////////////////////////////////////////////////

        auto key_pair1 = cc->key_gen();
        if (!key_pair1.good())
            CIPHER_THROW("key generation failed!");

        ////////////////////////////////////////////////////////////
        // Encode source data
        ////////////////////////////////////////////////////////////

        std::vector<int64_t> vector_of_ints(ring_dimension_value);
        for (auto& v : vector_of_ints)
            v = (std::rand() % plaintext_modulus);
        auto plaintext = cc->make_coef_packed_plaintext(vector_of_ints);

        ////////////////////////////////////////////////////////////
        // Encryption
        ////////////////////////////////////////////////////////////

        auto ciphertext1 = cc->encrypt(key_pair1.public_key, plaintext);

        ////////////////////////////////////////////////////////////
        // Decryption of Ciphertext
        ////////////////////////////////////////////////////////////

        Plaintext plaintext_dec1;

        cc->decrypt(key_pair1.secret_key, ciphertext1, &plaintext_dec1);

        plaintext_dec1->set_length(plaintext->get_length());

        Ciphertext<RnsPoly> re_encrypted_ct;
        Plaintext plaintext_dec;

        // multiple hop
        std::vector<KeyPair<RnsPoly>> key_pairs{key_pair1};
        std::vector<Ciphertext<RnsPoly>> re_encrypted_c_ts{ciphertext1};

        for (uint32_t i = 0; i < num_of_hops; ++i) {
            key_pairs.push_back(cc->key_gen());

            auto reencryption_key = cc->re_key_gen(key_pairs[i].secret_key, key_pairs[i + 1].public_key);

            switch (security_model) {
                case 0:
                    // CPA secure PRE
                    re_encrypted_ct = cc->re_encrypt(re_encrypted_c_ts[i], reencryption_key);  // IND-CPA secure
                    break;
                case 1:
                    // Fixed noise (20 bits) practically secure PRE
                    re_encrypted_ct = cc->re_encrypt(re_encrypted_c_ts[i], reencryption_key, key_pairs[i].public_key);
                    break;
                case 2:
                    // Provable HRA secure PRE with noise flooding with BV switching
                    re_encrypted_ct = cc->re_encrypt(re_encrypted_c_ts[i], reencryption_key, key_pairs[i].public_key);
                    if (i < num_of_hops - 1)
                        re_encrypted_ct = cc->mod_reduce(re_encrypted_ct);  // mod reduction for noise flooding
                    break;
                case 3:
                    // Provable HRA secure PRE with noise flooding with Hybrid switching
                    re_encrypted_ct = cc->re_encrypt(re_encrypted_c_ts[i], reencryption_key, key_pairs[i].public_key);
                    if (i < num_of_hops - 1)
                        re_encrypted_ct = cc->mod_reduce(re_encrypted_ct);  // mod reduction for noise flooding
                    break;
                default:
                    CIPHER_THROW("Not a valid security mode");
            }
            re_encrypted_c_ts.push_back(re_encrypted_ct);
        }

        cc->decrypt(key_pairs.back().secret_key, re_encrypted_c_ts.back(), &plaintext_dec);

        // verification
        auto& unpacked_pt = plaintext_dec1->get_coef_packed_value();
        auto& unpacked_dec_pt = plaintext_dec->get_coef_packed_value();
        EXPECT_EQ(unpacked_pt.size(), unpacked_dec_pt.size());
        for (size_t j = 0; j < unpacked_pt.size(); ++j) {
            EXPECT_EQ(unpacked_pt[j], unpacked_dec_pt[j]) << "index " << j;
        }

        return 0;
    }
};

TEST_P(UTGENERAL_MULTIHOP_PRE, MULTIHOP_PRE_TEST) {
    auto test = GetParam();
    run_demo_pre(test, 1);
    run_demo_pre(test, 3);
    run_demo_pre(test, 4);
    run_demo_pre(test, 5);
}

uint32_t security_model_options[4] = {0, 1, 2, 3};

INSTANTIATE_TEST_SUITE_P(MULTIHOP_PRE_TEST, UTGENERAL_MULTIHOP_PRE, ::testing::ValuesIn(security_model_options));
