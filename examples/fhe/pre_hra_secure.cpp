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
  Example of HRA-secure Proxy Re-Encryption with 13 hops.
 */

#define PROFILE  // for TIC TOC
#include <cmath>
#include <cstdint>
#include <iostream>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

using CT = Ciphertext<RnsPoly>;  // ciphertext
using PT = Plaintext;             // plaintext

using VecInt = std::vector<int64_t>;  // vector of ints
using VecChar = std::vector<char>;    // vector of characters

bool run_demo_pre(void);

int main(int argc, char* argv[]) {
    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    bool passed = run_demo_pre();

    if (!passed) {  // there could be an error
        exit(1);
    }
    exit(0);  // successful return
}

bool run_demo_pre(void) {
    // Generate parameters.
    TimeVar t;  // timer for tic toc
    std::cout << "setting up the HRA-secure BGV PRE cryptosystem" << std::endl;
    TIC(t);

    double t1;

    uint32_t plaintext_modulus = 2;  // can encode shorts

    uint32_t num_hops = 13;

    ContextParams<BgvRnsContext> parameters;
    parameters.set_plaintext_modulus(plaintext_modulus);
    parameters.set_scaling_technique(FIXEDMANUAL);
    parameters.set_pre_num_hops(num_hops);
    parameters.set_statistical_security(40);
    parameters.set_num_adversarial_queries(1048576);
    parameters.set_ring_dim(32768);
    parameters.set_pre_mode(NOISE_FLOODING_HRA);
    parameters.set_key_switch_technique(HYBRID);
    parameters.set_multiplicative_depth(0);
    // parameters.set_num_large_digits(3);
    // parameters.set_key_switch_technique(BV);
    // parameters.set_digit_size(15);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    std::cout << "\nParam generation time: "
              << "\t" << TOC_US(t) << " ms" << std::endl;
    // Turn on features
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(PRE);

    std::cout << "p = " << cc->get_crypto_parameters()->get_plaintext_modulus() << std::endl;
    std::cout << "n = " << cc->get_crypto_parameters()->get_element_params()->get_cyclotomic_order() / 2 << std::endl;
    std::cout << "log2 q = " << std::log2(cc->get_crypto_parameters()->get_element_params()->get_modulus().convert_to_double())
              << std::endl;
    // std::cout << "crypto parameters = " << *cc->get_crypto_parameters() << std::endl;
    const auto crypto_params_bgv = std::dynamic_pointer_cast<BgvRnsCryptoParams>(cc->get_crypto_parameters());
    std::cout << "log QP = " << crypto_params_bgv->get_params_qp()->get_modulus().get_msb() << std::endl;
    // std::cout << "RNS parameters = " << *crypto_params_bgv->get_params_qp() << std::endl;

    auto ringsize = cc->get_ring_dimension();
    std::cout << "Alice can encrypt " << ringsize / 8 << " bytes of data" << std::endl;
    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    // Initialize Key Pair Containers
    KeyPair<RnsPoly> key_pair1;

    std::cout << "\nRunning Alice key generation (used for source data)..." << std::endl;

    TIC(t);
    key_pair1 = cc->key_gen();
    t1 = TOC_US(t);
    std::cout << "Key generation time: "
              << "\t" << t1 / 1000.0 << " ms" << std::endl;

    if (!key_pair1.good()) {
        std::cout << "Alice Key generation failed!" << std::endl;
        return (false);
    }

    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////

    unsigned int nshort = ringsize;

    VecInt v_shorts;

    for (size_t i = 0; i < nshort; i++)
        v_shorts.push_back(std::rand() % plaintext_modulus);

    PT pt = cc->make_coef_packed_plaintext(v_shorts);

    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    TIC(t);
    auto ct1 = cc->encrypt(key_pair1.public_key, pt);
    t1 = TOC_US(t);
    std::cout << "Encryption time: "
              << "\t" << t1 / 1000.0 << " ms" << std::endl;

    ////////////////////////////////////////////////////////////
    // Decryption of Ciphertext
    ////////////////////////////////////////////////////////////

    PT pt_dec1;

    TIC(t);
    cc->decrypt(key_pair1.secret_key, ct1, &pt_dec1);
    t1 = TOC_US(t);
    std::cout << "Decryption time: "
              << "\t" << t1 / 1000.0 << " ms" << std::endl;

    pt_dec1->set_length(pt->get_length());

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    // Initialize Key Pair Containers
    std::vector<KeyPair<RnsPoly>> key_pair_vector(num_hops);
    std::vector<EvalKey<RnsPoly>> reencryption_key_vector(num_hops);

    std::cout << "Generating keys for " << num_hops << " parties" << std::endl;

    for (unsigned int i = 0; i < num_hops; i++) {
        TIC(t);
        key_pair_vector[i] = cc->key_gen();
        t1 = TOC_US(t);
        if (i == 1)
            std::cout << "Key generation time: "
                      << "\t" << t1 / 1000.0 << " ms" << std::endl;

        if (!key_pair_vector[i].good()) {
            std::cout << "Bob Key generation failed!" << std::endl;
            return (false);
        }

        ////////////////////////////////////////////////////////////
        // Perform the proxy re-encryption key generation operation.
        // This generates the keys which are used to perform the key switching.
        ////////////////////////////////////////////////////////////
        if (i == 0) {
            reencryption_key_vector[i] = cc->re_key_gen(key_pair1.secret_key, key_pair_vector[i].public_key);
        } else {
            TIC(t);
            reencryption_key_vector[i] = cc->re_key_gen(key_pair_vector[i - 1].secret_key, key_pair_vector[i].public_key);
            t1 = TOC_US(t);
            if (i == 1)
                std::cout << "Re-encryption key generation time: "
                          << "\t" << t1 / 1000.0 << " ms" << std::endl;
        }
    }

    ////////////////////////////////////////////////////////////
    // Re-Encryption
    ////////////////////////////////////////////////////////////
    bool good = true;
    for (unsigned int i = 0; i < num_hops; i++) {
        TIC(t);
        ct1 = cc->re_encrypt(ct1, reencryption_key_vector[i]);
        t1 = TOC_US(t);
        std::cout << "Re-Encryption time at hop " << i + 1 << "\t" << t1 / 1000.0 << " ms" << std::endl;

        if (i < num_hops - 1)
            cc->mod_reduce_in_place(ct1);

        ////////////////////////////////////////////////////////////
        // Decryption of Ciphertext
        ////////////////////////////////////////////////////////////

        PT pt_dec2;

        TIC(t);
        cc->decrypt(key_pair_vector[i].secret_key, ct1, &pt_dec2);
        t1 = TOC_US(t);
        std::cout << "Decryption time: "
                  << "\t" << t1 / 1000.0 << " ms" << std::endl;

        pt_dec2->set_length(pt->get_length());

        auto unpacked0 = pt->get_coef_packed_value();
        auto unpacked1 = pt_dec1->get_coef_packed_value();
        auto unpacked2 = pt_dec2->get_coef_packed_value();

        // note that Cipher assumes that plaintext is in the range of -p/2..p/2
        // to recover 0...q simply add q if the unpacked value is negative
        for (unsigned int j = 0; j < pt->get_length(); j++) {
            if (unpacked1[j] < 0)
                unpacked1[j] += plaintext_modulus;
            if (unpacked2[j] < 0)
                unpacked2[j] += plaintext_modulus;
        }

        // compare all the results for correctness
        for (unsigned int j = 0; j < pt->get_length(); j++) {
            if ((unpacked0[j] != unpacked1[j]) || (unpacked0[j] != unpacked2[j])) {
                // std::cout << j << ", " << unpacked0[j] << ", " << unpacked1[j] << ", " << unpacked2[j] << std::endl;
                good = false;
            }
        }
        if (good) {
            std::cout << "PRE passes" << std::endl;
        } else {
            std::cout << "PRE fails" << std::endl;
        }
    }

    ////////////////////////////////////////////////////////////
    // Done
    ////////////////////////////////////////////////////////////

    std::cout << "Execution Completed." << std::endl;

    return good;
}
