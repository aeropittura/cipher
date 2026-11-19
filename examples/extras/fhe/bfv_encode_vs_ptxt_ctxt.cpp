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
  Compares the performance of BFV plaintext encode vs plaintext-ciphertext multiplication,
  both are heavly used operations
 */

#define PROFILE

#include <chrono>
#include <cstdint>
#include <iostream>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

int main() {
    // Sample Program: Step 1: Set CryptoContext
    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(65537);
    parameters.set_multiplicative_depth(5);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_multiplication_technique(HPSPOVERQLEVELED);
    parameters.set_key_switch_technique(BV);
    parameters.set_ring_dim((1 << 14));

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    std::cout << "Element parameters: \n" << *crypto_context->get_element_params() << "\n";

    uint32_t ring_dim = crypto_context->get_ring_dimension();
    std::cout << "BFVrns scheme is using ring dimension " << ring_dim << std::endl << std::endl;

    // Enable features that you wish to use
    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);

    // Sample Program: Step 2: Key Generation

    // Initialize Public Key Containers
    KeyPair<RnsPoly> key_pair;

    // Generate a public/private key pair
    key_pair = crypto_context->key_gen();

    // Sample Program: Step 3: Encryption
    std::vector<int64_t> payload = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    // Second plaintext vector is encoded
    std::vector<int64_t> payload2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext ptxt2 = crypto_context->make_packed_plaintext(payload2, 1, 3);

    // Number of iterations for benchmarking
    int num_iterations = 1000;

    // Variables to store total times
    TimeVar t;
    double total_encode_time = 0.0;
    double total_mult_time = 0.0;

    auto ctxt_gt = crypto_context->encrypt(key_pair.public_key, ptxt2);

    // Benchmark loop
    for (int i = 0; i < num_iterations; ++i) {
        TIC(t);
        Plaintext ptxt1 = crypto_context->make_packed_plaintext(payload, 1, 3);
        total_encode_time += TOC_NS(t);

        auto ctxt2 = crypto_context->encrypt(key_pair.public_key, ptxt2);

        TIC(t);
        auto ctxt_res = crypto_context->eval_mult(ctxt2, ptxt1);
        total_mult_time += TOC_NS(t);
        ctxt_gt = ctxt_res;
    }

    // Calculate and report average times
    double avg_encode_time = total_encode_time / num_iterations / 1e6;
    double avg_mult_time = total_mult_time / num_iterations / 1e6;

    // Average time to encode
    std::cout << "encode took: " << avg_encode_time << " ms" << std::endl;
    // Average time to compute evalmult(ctxt, ptxt)
    std::cout << "ptxt-ctxt took: " << avg_mult_time << " ms" << std::endl;

    Plaintext plaintext_mult;
    crypto_context->decrypt(key_pair.secret_key, ctxt_gt, &plaintext_mult);

    plaintext_mult->set_length(payload.size());

    // Output results
    std::cout << "\nResults of homomorphic computations" << std::endl;
    std::cout << "plaintext_mult: " << plaintext_mult << std::endl;

    return 0;
}
