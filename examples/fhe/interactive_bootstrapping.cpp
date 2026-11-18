//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2025, Duality Technologies Inc. and other contributors
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
 Examples for 2-party Interactive Bootstrapping
*/

#include <complex>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

void threshold_fhe(enum ScalingTechnique rescale_tech);
void chebyshev(enum ScalingTechnique rescale_tech);

int main(int argc, char* argv[]) {
    // the scaling technigue can be changed to FIXEDMANUAL, FIXEDAUTO, or FLEXIBLEAUTOEXT
    threshold_fhe(FLEXIBLEAUTO);
    chebyshev(FLEXIBLEAUTO);
    return 0;
}

void threshold_fhe(enum ScalingTechnique rescale_tech) {
    std::cout << "\nThreshold FHE example " << rescale_tech << std::endl;

    ContextParams<CkksRnsContext> parameters;

    // 1 extra level needs to be added for FIXED* modes (2 extra levels for FLEXIBLE* modes) to the multiplicative depth
    // to support 2-party interactive bootstrapping
    uint32_t depth = 7;
    parameters.set_multiplicative_depth(depth);
    parameters.set_scaling_mod_size(50);
    parameters.set_batch_size(16);
    parameters.set_scaling_technique(rescale_tech);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    // enable features that you wish to use
    cc->enable(PKE);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(MULTIPARTY);

    // Initialize Public Key Containers
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

    // Generate evalmult key part for A
    auto eval_mult_key = cc->key_switch_gen(kp1.secret_key, kp1.secret_key);

    std::cout << "Round 1 of key generation completed." << std::endl;

    // Round 2 (party B)

    std::cout << "Round 2 (party B) started." << std::endl;

    std::cout << "Joint public key for (s_a + s_b) is generated..." << std::endl;
    kp2 = cc->multiparty_key_gen(kp1.public_key);

    std::vector<std::complex<double>> input({-0.9, -0.8, -0.6, -0.4, -0.2, 0., 0.2, 0.4, 0.6, 0.8, 0.9});

    // This plaintext only has 3 RNS limbs, the minimum needed to perform 2-party interactive bootstrapping
    // for FLEXIBLEAUTO
    Plaintext plaintext1 = cc->make_ckks_packed_plaintext(input, 1, depth - 2);

    auto ciphertext1 = cc->encrypt(kp2.public_key, plaintext1);

    // INTERACTIVE BOOTSTRAPPING STARTS

    // under the hood it reduces to two towers
    ciphertext1 = cc->int_boot_adjust_scale(ciphertext1);
    std::cout << "IntBootAdjustScale Succeeded" << std::endl;

    // masked decryption on the server: c0 = b + a*s0
    auto ciphertext_output1 = cc->int_boot_decrypt(kp1.secret_key, ciphertext1);
    std::cout << "IntBootDecrypt on Server Succeeded" << std::endl;

    auto ciphertext2 = ciphertext1->clone();
    ciphertext2->set_elements({ciphertext2->get_elements()[1]});

    // masked decryption on the client: c1 = a*s1
    auto ciphertext_output2 = cc->int_boot_decrypt(kp2.secret_key, ciphertext2);
    std::cout << "IntBootDecrypt on Client Succeeded" << std::endl;

    // Encryption of masked decryption c1 = a*s1
    ciphertext_output2 = cc->int_boot_encrypt(kp2.public_key, ciphertext_output2);
    std::cout << "IntBootEncrypt on Client Succeeded" << std::endl;

    // Compute Enc(c1) + c0
    auto ciphertext_output = cc->int_boot_add(ciphertext_output2, ciphertext_output1);
    std::cout << "IntBootAdd on Server Succeeded" << std::endl;

    // INTERACTIVE BOOTSTRAPPING ENDS

    // distributed decryption

    auto ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_output}, kp1.secret_key);

    auto ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_output}, kp2.secret_key);

    std::vector<Ciphertext<RnsPoly>> partial_ciphertext_vec;
    partial_ciphertext_vec.push_back(ciphertext_partial1[0]);
    partial_ciphertext_vec.push_back(ciphertext_partial2[0]);

    Plaintext plaintext_multiparty;

    cc->multiparty_decrypt_fusion(partial_ciphertext_vec, &plaintext_multiparty);

    plaintext_multiparty->set_length(input.size());

    std::cout << "Original plaintext \n\t" << plaintext1->get_ckks_packed_value() << std::endl;
    std::cout << "Result after bootstrapping \n\t" << plaintext_multiparty->get_ckks_packed_value() << std::endl;
}

void chebyshev(enum ScalingTechnique rescale_tech) {
    std::cout << "\nThreshold FHE example " << rescale_tech << std::endl;

    ContextParams<CkksRnsContext> parameters;

    // 1 extra level needs to be added for FIXED* modes (2 extra levels for FLEXIBLE* modes) to the multiplicative depth
    // to support 2-party interactive bootstrapping
    parameters.set_multiplicative_depth(8);
    parameters.set_scaling_mod_size(50);
    parameters.set_batch_size(16);
    parameters.set_scaling_technique(rescale_tech);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    // enable features that you wish to use
    cc->enable(PKE);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(MULTIPARTY);

    // Initialize Public Key Containers
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

    // Generate evalmult key part for A
    auto eval_mult_key = cc->key_switch_gen(kp1.secret_key, kp1.secret_key);

    // Generate evalsum key part for A
    cc->eval_sum_key_gen(kp1.secret_key);
    auto eval_sum_keys = std::make_shared<std::map<uint32_t, EvalKey<RnsPoly>>>(
            cc->get_eval_sum_key_map(kp1.secret_key->get_key_tag()));

    std::cout << "Round 1 of key generation completed." << std::endl;

    // Round 2 (party B)

    std::cout << "Round 2 (party B) started." << std::endl;

    std::cout << "Joint public key for (s_a + s_b) is generated..." << std::endl;
    kp2 = cc->multiparty_key_gen(kp1.public_key);

    auto eval_mult_key2 = cc->multi_key_switch_gen(kp2.secret_key, kp2.secret_key, eval_mult_key);

    std::cout << "Joint evaluation multiplication key for (s_a + s_b) is generated..." << std::endl;
    auto eval_mult_ab = cc->multi_add_eval_keys(eval_mult_key, eval_mult_key2, kp2.public_key->get_key_tag());

    std::cout << "Joint evaluation multiplication key (s_a + s_b) is transformed "
                 "into s_b*(s_a + s_b)..."
              << std::endl;
    auto eval_mult_bab = cc->multi_mult_eval_key(kp2.secret_key, eval_mult_ab, kp2.public_key->get_key_tag());

    auto eval_sum_keys_b = cc->multi_eval_sum_key_gen(kp2.secret_key, eval_sum_keys, kp2.public_key->get_key_tag());

    std::cout << "Joint evaluation summation key for (s_a + s_b) is generated..." << std::endl;
    auto eval_sum_keys_join =
            cc->multi_add_eval_sum_keys(eval_sum_keys, eval_sum_keys_b, kp2.public_key->get_key_tag());

    cc->insert_eval_sum_key(eval_sum_keys_join);

    std::cout << "Round 2 of key generation completed." << std::endl;

    std::cout << "Round 3 (party A) started." << std::endl;

    std::cout << "Joint key (s_a + s_b) is transformed into s_a*(s_a + s_b)..." << std::endl;
    auto eval_mult_aab = cc->multi_mult_eval_key(kp1.secret_key, eval_mult_ab, kp2.public_key->get_key_tag());

    std::cout << "Computing the final evaluation multiplication key for (s_a + "
                 "s_b)*(s_a + s_b)..."
              << std::endl;
    auto eval_mult_final = cc->multi_add_eval_mult_keys(eval_mult_aab, eval_mult_bab, eval_mult_ab->get_key_tag());

    cc->insert_eval_mult_key({eval_mult_final});

    std::cout << "Round 3 of key generation completed." << std::endl;

    std::vector<std::complex<double>> input({-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0});

    std::vector<double> coefficients({1.0, 0.558971, 0.0, -0.0943712, 0.0, 0.0215023, 0.0, -0.00505348, 0.0, 0.00119324,
                                      0.0, -0.000281928, 0.0, 0.0000664347, 0.0, -0.0000148709});

    double a = -4;
    double b = 4;

    Plaintext plaintext1 = cc->make_ckks_packed_plaintext(input);

    auto ciphertext1 = cc->encrypt(kp2.public_key, plaintext1);

    // The Chebyshev series interpolation requires 6 levels
    ciphertext1 = cc->eval_chebyshev_series(ciphertext1, coefficients, a, b);
    std::cout << "Ran Chebyshev interpolation" << std::endl;

    // INTERACTIVE BOOTSTRAPPING STARTS

    ciphertext1 = cc->int_boot_adjust_scale(ciphertext1);
    std::cout << "IntBootAdjustScale Succeeded" << std::endl;

    // masked decryption on the server: c0 = b + a*s0
    auto ciphertext_output1 = cc->int_boot_decrypt(kp1.secret_key, ciphertext1);
    std::cout << "IntBootDecrypt on Server Succeeded" << std::endl;

    auto ciphertext2 = ciphertext1->clone();
    ciphertext2->set_elements({ciphertext2->get_elements()[1]});

    // masked decryption on the client: c1 = a*s1
    auto ciphertext_output2 = cc->int_boot_decrypt(kp2.secret_key, ciphertext2);
    std::cout << "IntBootDecrypt on Client Succeeded" << std::endl;

    // Encryption of masked decryption c1 = a*s1
    ciphertext_output2 = cc->int_boot_encrypt(kp2.public_key, ciphertext_output2);
    std::cout << "IntBootEncrypt on Client Succeeded" << std::endl;

    // Compute Enc(c1) + c0
    auto ciphertext_output = cc->int_boot_add(ciphertext_output2, ciphertext_output1);
    std::cout << "IntBootAdd on Server Succeeded" << std::endl;

    // INTERACTIVE BOOTSTRAPPING ENDS

    // distributed decryption

    auto ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_output}, kp1.secret_key);

    auto ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_output}, kp2.secret_key);

    std::vector<Ciphertext<RnsPoly>> partial_ciphertext_vec;
    partial_ciphertext_vec.push_back(ciphertext_partial1[0]);
    partial_ciphertext_vec.push_back(ciphertext_partial2[0]);

    Plaintext plaintext_multiparty;

    cc->multiparty_decrypt_fusion(partial_ciphertext_vec, &plaintext_multiparty);

    plaintext_multiparty->set_length(input.size());

    std::cout << "\n Original Plaintext #1: \n";
    std::cout << plaintext1 << std::endl;

    std::cout << "\n Results of evaluating the polynomial with coefficients " << coefficients << " \n";
    std::cout << "\n Ciphertext result:" << plaintext_multiparty << std::endl;

    std::cout
            << "\n Plaintext result: ( 0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011 ) \n";

    std::cout
            << "\n Exact result: ( 0.0179862, 0.0474259, 0.119203, 0.268941, 0.5, 0.731059, 0.880797, 0.952574, 0.982014 ) \n";

    std::cout << "\n Another round of Chebyshev interpolation after interactive bootstrapping: \n";

    ciphertext_output = cc->eval_chebyshev_series(ciphertext_output, coefficients, a, b);
    std::cout << "Ran Chebyshev interpolation" << std::endl;

    // distributed decryption

    ciphertext_partial1 = cc->multiparty_decrypt_lead({ciphertext_output}, kp1.secret_key);

    ciphertext_partial2 = cc->multiparty_decrypt_main({ciphertext_output}, kp2.secret_key);

    partial_ciphertext_vec.resize(0);
    partial_ciphertext_vec.push_back(ciphertext_partial1[0]);
    partial_ciphertext_vec.push_back(ciphertext_partial2[0]);

    cc->multiparty_decrypt_fusion(partial_ciphertext_vec, &plaintext_multiparty);

    plaintext_multiparty->set_length(input.size());

    std::cout << "\n Ciphertext result:" << plaintext_multiparty << std::endl;

    std::cout
            << "\n Plaintext result: ( 0.504497, 0.511855, 0.529766, 0.566832, 0.622459, 0.675039, 0.706987, 0.721632, 0.727508 ) \n";
}
