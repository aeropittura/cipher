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
  Examples of threshold FHE for BGVrns, BFVrns and CKKS
 */

#include <cmath>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

void run_bfv_rns();
void eval_noise_bfv(PrivateKey<RnsPoly> private_key, ConstCiphertext<RnsPoly> ciphertext, Plaintext ptxt, uint32_t ptm,
                    double& noise, double& log_q, EncryptionTechnique enc_method);

int main(int argc, char* argv[]) {
    std::cout << "\n=================RUNNING FOR BFVrns=====================" << std::endl;

    run_bfv_rns();

    return 0;
}

void run_bfv_rns() {
    int plaintext_modulus = 65537;
    double sigma = 3.2;
    cipher::SecurityLevel security_level = cipher::SecurityLevel::HEStd_128_classic;

    uint32_t batch_size = 16;
    uint32_t mult_depth_value = 4;
    uint32_t digit_size = 30;
    uint32_t dcrt_bits = 60;

    cipher::ContextParams<cipher::BfvRnsContext> parameters;

    parameters.set_plaintext_modulus(plaintext_modulus);
    parameters.set_security_level(security_level);
    parameters.set_standard_deviation(sigma);
    parameters.set_secret_key_dist(UNIFORM_TERNARY);
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_batch_size(batch_size);
    parameters.set_digit_size(digit_size);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_multiplication_technique(HPSPOVERQLEVELED);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    // enable features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(MULTIPARTY);

    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    // Output the generated parameters
    std::cout << "p = " << cc->get_crypto_parameters()->get_plaintext_modulus() << std::endl;
    std::cout << "n = " << cc->get_crypto_parameters()->get_element_params()->get_cyclotomic_order() / 2 << std::endl;
    std::cout << "log2 q = "
              << std::log2(cc->get_crypto_parameters()->get_element_params()->get_modulus().convert_to_double())
              << std::endl;

    // Initialize Public Key Containers for two parties A and B
    KeyPair<RnsPoly> kp1;
    KeyPair<RnsPoly> kp2;

    KeyPair<RnsPoly> kp_multiparty;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "Running key generation (used for source data)..." << std::endl;

    // Round 1 (party A)

    std::cout << "Round 1 (party A) started." << std::endl;

    kp1 = cc->key_gen();
    kp2 = cc->multiparty_key_gen(kp1.public_key);
    auto kp3 = cc->multiparty_key_gen(kp2.public_key);
    auto kp4 = cc->multiparty_key_gen(kp3.public_key);
    auto kp5 = cc->multiparty_key_gen(kp4.public_key);

    // Generate evalmult key part for A
    auto eval_mult_key = cc->key_switch_gen(kp1.secret_key, kp1.secret_key);

    auto eval_mult_key2 = cc->multi_key_switch_gen(kp2.secret_key, kp2.secret_key, eval_mult_key);

    auto eval_mult_key3 = cc->multi_key_switch_gen(kp3.secret_key, kp3.secret_key, eval_mult_key);

    auto eval_mult_key4 = cc->multi_key_switch_gen(kp4.secret_key, kp4.secret_key, eval_mult_key);

    auto eval_mult_key5 = cc->multi_key_switch_gen(kp5.secret_key, kp5.secret_key, eval_mult_key);

    auto eval_mult_ab = cc->multi_add_eval_keys(eval_mult_key, eval_mult_key2, kp2.public_key->get_key_tag());

    auto eval_mult_abc = cc->multi_add_eval_keys(eval_mult_ab, eval_mult_key3, kp3.public_key->get_key_tag());

    auto eval_mult_abcd = cc->multi_add_eval_keys(eval_mult_abc, eval_mult_key4, kp4.public_key->get_key_tag());

    auto eval_mult_abcde = cc->multi_add_eval_keys(eval_mult_abcd, eval_mult_key5, kp5.public_key->get_key_tag());

    auto eval_mult_eabcde = cc->multi_mult_eval_key(kp5.secret_key, eval_mult_abcde, kp5.public_key->get_key_tag());

    auto eval_mult_dabcde = cc->multi_mult_eval_key(kp4.secret_key, eval_mult_abcde, kp5.public_key->get_key_tag());

    auto eval_mult_cabcde = cc->multi_mult_eval_key(kp3.secret_key, eval_mult_abcde, kp5.public_key->get_key_tag());

    auto eval_mult_babcde = cc->multi_mult_eval_key(kp2.secret_key, eval_mult_abcde, kp5.public_key->get_key_tag());

    auto eval_mult_aabcde = cc->multi_mult_eval_key(kp1.secret_key, eval_mult_abcde, kp5.public_key->get_key_tag());

    auto eval_mult_deabcde =
            cc->multi_add_eval_mult_keys(eval_mult_eabcde, eval_mult_dabcde, eval_mult_eabcde->get_key_tag());

    auto eval_mult_cdeabcde =
            cc->multi_add_eval_mult_keys(eval_mult_cabcde, eval_mult_deabcde, eval_mult_cabcde->get_key_tag());

    auto eval_mult_bcdeabcde =
            cc->multi_add_eval_mult_keys(eval_mult_babcde, eval_mult_cdeabcde, eval_mult_babcde->get_key_tag());

    auto eval_mult_final =
            cc->multi_add_eval_mult_keys(eval_mult_aabcde, eval_mult_bcdeabcde, kp5.public_key->get_key_tag());
    cc->insert_eval_mult_key({eval_mult_final});

    //---------------------------------------------------
    std::cout << "Running evalsum key generation (used for source data)..." << std::endl;
    // Generate evalsum key part for A
    cc->eval_sum_key_gen(kp1.secret_key);
    auto eval_sum_keys = std::make_shared<std::map<uint32_t, EvalKey<RnsPoly>>>(
            cc->get_eval_sum_key_map(kp1.secret_key->get_key_tag()));

    auto eval_sum_keys_b = cc->multi_eval_sum_key_gen(kp2.secret_key, eval_sum_keys, kp2.public_key->get_key_tag());

    auto eval_sum_keys_c = cc->multi_eval_sum_key_gen(kp3.secret_key, eval_sum_keys, kp3.public_key->get_key_tag());

    auto eval_sum_keys_d = cc->multi_eval_sum_key_gen(kp4.secret_key, eval_sum_keys, kp4.public_key->get_key_tag());

    auto eval_sum_keys_e = cc->multi_eval_sum_key_gen(kp5.secret_key, eval_sum_keys, kp5.public_key->get_key_tag());

    auto eval_sum_keys_ab = cc->multi_add_eval_sum_keys(eval_sum_keys, eval_sum_keys_b, kp2.public_key->get_key_tag());

    auto eval_sum_keys_abc =
            cc->multi_add_eval_sum_keys(eval_sum_keys_c, eval_sum_keys_ab, kp3.public_key->get_key_tag());

    auto eval_sum_keys_abcd =
            cc->multi_add_eval_sum_keys(eval_sum_keys_abc, eval_sum_keys_d, kp4.public_key->get_key_tag());

    auto eval_sum_keys_join =
            cc->multi_add_eval_sum_keys(eval_sum_keys_e, eval_sum_keys_abcd, kp5.public_key->get_key_tag());

    cc->insert_eval_sum_key(eval_sum_keys_join);

    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////
    std::vector<int64_t> vector_of_ints1 = {1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1, 0};
    std::vector<int64_t> vector_of_ints2 = {1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0};
    std::vector<int64_t> vector_of_ints3 = {2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0};

    Plaintext plaintext1 = cc->make_packed_plaintext(vector_of_ints1);
    Plaintext plaintext2 = cc->make_packed_plaintext(vector_of_ints2);
    Plaintext plaintext3 = cc->make_packed_plaintext(vector_of_ints3);

    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    Ciphertext<RnsPoly> ciphertext1;
    Ciphertext<RnsPoly> ciphertext2;
    Ciphertext<RnsPoly> ciphertext3;

    ciphertext1 = cc->encrypt(kp5.public_key, plaintext1);
    ciphertext2 = cc->encrypt(kp5.public_key, plaintext2);
    ciphertext3 = cc->encrypt(kp5.public_key, plaintext3);

    ////////////////////////////////////////////////////////////
    // Homomorphic Operations
    ////////////////////////////////////////////////////////////

    Ciphertext<RnsPoly> ciphertext_add12;
    Ciphertext<RnsPoly> ciphertext_add123;

    ciphertext_add12 = cc->eval_add(ciphertext1, ciphertext2);
    ciphertext_add123 = cc->eval_add(ciphertext_add12, ciphertext3);

    auto ciphertext_mult1 = cc->eval_mult(ciphertext1, ciphertext1);
    auto ciphertext_mult2 = cc->eval_mult(ciphertext_mult1, ciphertext1);
    auto ciphertext_mult3 = cc->eval_mult(ciphertext_mult2, ciphertext1);
    auto ciphertext_mult = cc->eval_mult(ciphertext_mult3, ciphertext1);

    auto ciphertext_eval_sum = cc->eval_sum(ciphertext3, batch_size);

    ////////////////////////////////////////////////////////////
    // Decryption after Accumulation Operation on Encrypted Data with Multiparty
    ////////////////////////////////////////////////////////////

    Plaintext plaintext_add_new1;
    Plaintext plaintext_add_new2;
    Plaintext plaintext_add_new3;

    RnsPoly partial_plaintext1;
    RnsPoly partial_plaintext2;
    RnsPoly partial_plaintext3;

    Plaintext plaintext_multiparty_new;

    const std::shared_ptr<BaseCryptoParams<RnsPoly>> crypto_params = kp1.secret_key->get_crypto_parameters();
    const std::shared_ptr<typename RnsPoly::Params> element_params = crypto_params->get_element_params();

    // Distributed decryption
    // partial decryption by party A
    auto ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_add123}, kp1.secret_key);

    // partial decryption by party B
    auto ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_add123}, kp2.secret_key);

    // partial decryption by party C
    auto ciphertext_partial3 = cc->multiparty_decrypt_main({ciphertext_add123}, kp3.secret_key);

    // partial decryption by party D
    auto ciphertext_partial4 = cc->multiparty_decrypt_main({ciphertext_add123}, kp4.secret_key);

    // partial decryption by party E
    auto ciphertext_partial5 = cc->multiparty_decrypt_main({ciphertext_add123}, kp5.secret_key);

    std::vector<Ciphertext<RnsPoly>> partial_ciphertext_vec;
    partial_ciphertext_vec.push_back(ciphertext_partial1[0]);
    partial_ciphertext_vec.push_back(ciphertext_partial2[0]);
    partial_ciphertext_vec.push_back(ciphertext_partial3[0]);
    partial_ciphertext_vec.push_back(ciphertext_partial4[0]);
    partial_ciphertext_vec.push_back(ciphertext_partial5[0]);

    // Two partial decryptions are combined
    cc->multiparty_decrypt_fusion(partial_ciphertext_vec, &plaintext_multiparty_new);

    std::cout << "\n Original Plaintext: \n" << std::endl;
    std::cout << plaintext1 << std::endl;
    std::cout << plaintext2 << std::endl;
    std::cout << plaintext3 << std::endl;

    plaintext_multiparty_new->set_length(plaintext1->get_length());

    std::cout << "\n Resulting Fused Plaintext: \n" << std::endl;
    std::cout << plaintext_multiparty_new << std::endl;

    std::cout << "\n";

    Plaintext plaintext_multiparty_mult;

    ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_mult}, kp1.secret_key);

    ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_mult}, kp2.secret_key);

    // partial decryption by party C
    ciphertext_partial3 = cc->multiparty_decrypt_main({ciphertext_mult}, kp3.secret_key);

    // partial decryption by party D
    ciphertext_partial4 = cc->multiparty_decrypt_main({ciphertext_mult}, kp4.secret_key);

    // partial decryption by party E
    ciphertext_partial5 = cc->multiparty_decrypt_main({ciphertext_mult}, kp5.secret_key);

    std::vector<Ciphertext<RnsPoly>> partial_ciphertext_vec_mult;
    partial_ciphertext_vec_mult.push_back(ciphertext_partial1[0]);
    partial_ciphertext_vec_mult.push_back(ciphertext_partial2[0]);
    partial_ciphertext_vec_mult.push_back(ciphertext_partial3[0]);
    partial_ciphertext_vec_mult.push_back(ciphertext_partial4[0]);
    partial_ciphertext_vec_mult.push_back(ciphertext_partial5[0]);

    cc->multiparty_decrypt_fusion(partial_ciphertext_vec_mult, &plaintext_multiparty_mult);

    plaintext_multiparty_mult->set_length(plaintext1->get_length());

    std::cout << "\n Resulting Fused Plaintext after Multiplication of plaintexts 1 "
                 "and 3: \n"
              << std::endl;
    std::cout << plaintext_multiparty_mult << std::endl;

    std::cout << "\n";

    Plaintext plaintext_multiparty_eval_sum;

    ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_eval_sum}, kp1.secret_key);

    ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_eval_sum}, kp2.secret_key);

    ciphertext_partial3 = cc->multiparty_decrypt_main({ciphertext_eval_sum}, kp3.secret_key);

    ciphertext_partial4 = cc->multiparty_decrypt_main({ciphertext_eval_sum}, kp4.secret_key);

    ciphertext_partial5 = cc->multiparty_decrypt_main({ciphertext_eval_sum}, kp5.secret_key);

    std::vector<Ciphertext<RnsPoly>> partial_ciphertext_vec_eval_sum;
    partial_ciphertext_vec_eval_sum.push_back(ciphertext_partial1[0]);
    partial_ciphertext_vec_eval_sum.push_back(ciphertext_partial2[0]);
    partial_ciphertext_vec_eval_sum.push_back(ciphertext_partial3[0]);
    partial_ciphertext_vec_eval_sum.push_back(ciphertext_partial4[0]);
    partial_ciphertext_vec_eval_sum.push_back(ciphertext_partial5[0]);

    cc->multiparty_decrypt_fusion(partial_ciphertext_vec_eval_sum, &plaintext_multiparty_eval_sum);

    plaintext_multiparty_eval_sum->set_length(plaintext1->get_length());

    std::cout << "\n Fused result after summation of ciphertext 3: \n" << std::endl;
    std::cout << plaintext_multiparty_eval_sum << std::endl;
}
