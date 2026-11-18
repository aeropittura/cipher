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
  Example of Proxy Re-Encryption on a packed vector.
  Example software for multiparty proxy-reencryption of an integer buffer using BFV rns scheme.
 */

#define PROFILE  // for TIC TOC
#include <cmath>
#include <cstdint>
#include <iostream>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

using CT = Ciphertext<RnsPoly>;  // ciphertext
using PT = Plaintext;            // plaintext

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
    std::cout << "setting up BFV RNS crypto system" << std::endl;
    TIC(t);
    // int plaintext_modulus = 786433; //plaintext prime modulus
    int plaintext_modulus = 65537;  // can encode shorts

    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(plaintext_modulus);
    parameters.set_scaling_mod_size(60);
    parameters.set_pre_mode(INDCPA);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);
    std::cout << "\nParam generation time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    // Turn on features
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(PRE);

    std::cout << "p = " << cc->get_crypto_parameters()->get_plaintext_modulus() << std::endl;
    std::cout << "n = " << cc->get_crypto_parameters()->get_element_params()->get_cyclotomic_order() / 2 << std::endl;
    std::cout << "log2 q = "
              << std::log2(cc->get_crypto_parameters()->get_element_params()->get_modulus().convert_to_double())
              << std::endl;
    std::cout << "r = " << cc->get_crypto_parameters()->get_digit_size() << std::endl;

    auto ringsize = cc->get_ring_dimension();
    std::cout << "Alice can encrypt " << ringsize * 2 << " bytes of data" << std::endl;
    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    // Initialize Key Pair Containers
    KeyPair<RnsPoly> key_pair1;

    std::cout << "\nRunning Alice key generation (used for source data)..." << std::endl;

    TIC(t);
    key_pair1 = cc->key_gen();
    std::cout << "Key generation time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

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
        v_shorts.push_back(std::rand() % 65536);

    PT pt = cc->make_packed_plaintext(v_shorts);

    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    TIC(t);
    auto ct1 = cc->encrypt(key_pair1.public_key, pt);
    std::cout << "Encryption time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    ////////////////////////////////////////////////////////////
    // Decryption of Ciphertext
    ////////////////////////////////////////////////////////////

    PT pt_dec1;

    TIC(t);
    cc->decrypt(key_pair1.secret_key, ct1, &pt_dec1);
    std::cout << "Decryption time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    pt_dec1->set_length(pt->get_length());

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    // Initialize Key Pair Containers
    KeyPair<RnsPoly> key_pair2;

    std::cout << "Bob Running key generation ..." << std::endl;

    TIC(t);
    key_pair2 = cc->key_gen();
    std::cout << "Key generation time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    if (!key_pair2.good()) {
        std::cout << "Bob Key generation failed!" << std::endl;
        return (false);
    }

    ////////////////////////////////////////////////////////////
    // Perform the proxy re-encryption key generation operation.
    // This generates the keys which are used to perform the key switching.
    ////////////////////////////////////////////////////////////

    std::cout << "\n"
              << "Generating proxy re-encryption key..." << std::endl;

    EvalKey<RnsPoly> reencryption_key12;

    TIC(t);
    reencryption_key12 = cc->re_key_gen(key_pair1.secret_key, key_pair2.public_key);
    std::cout << "Key generation time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    ////////////////////////////////////////////////////////////
    // Re-Encryption
    ////////////////////////////////////////////////////////////

    TIC(t);
    auto ct2 = cc->re_encrypt(ct1, reencryption_key12);
    std::cout << "Re-Encryption time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    ////////////////////////////////////////////////////////////
    // Decryption of Ciphertext
    ////////////////////////////////////////////////////////////

    PT pt_dec2;

    TIC(t);
    cc->decrypt(key_pair2.secret_key, ct2, &pt_dec2);
    std::cout << "Decryption time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    pt_dec2->set_length(pt->get_length());

    auto unpacked0 = pt->get_packed_value();
    auto unpacked1 = pt_dec1->get_packed_value();
    auto unpacked2 = pt_dec2->get_packed_value();
    bool good = true;

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
            std::cout << j << ", " << unpacked0[j] << ", " << unpacked1[j] << ", " << unpacked2[j] << std::endl;
            good = false;
        }
    }
    if (good) {
        std::cout << "PRE passes" << std::endl;
    } else {
        std::cout << "PRE fails" << std::endl;
    }

    ////////////////////////////////////////////////////////////
    // Done
    ////////////////////////////////////////////////////////////

    std::cout << "Execution Completed." << std::endl;

    return good;
}
