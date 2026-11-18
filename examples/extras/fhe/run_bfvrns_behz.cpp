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
  BFV RNS testing programs
 */

#define PROFILE

#include <cstdint>
#include <iostream>
#include <limits>
#include <vector>

#include "cipher/cipher.h"
#include "cipher/util/parallel.h"

typedef std::numeric_limits<double> dbl;

using namespace cipher;

// Poly tests
void she_run();

int main() {
    she_run();

    // cin.get();
    return 0;
}

void she_run() {
    std::cerr << "Running with " << ParallelControls::get_num_procs() << " processors and "
              << ParallelControls().get_num_threads() << " threads. " << std::endl;

    std::cout << "\n===========BENCHMARKING FOR BFVRNS-B===============: " << std::endl;

    std::cout << "\nThis code demonstrates the use of the BFV-RNS scheme for "
                 "basic homomorphic encryption operations. "
              << std::endl;
    std::cout << "This code shows how to auto-generate parameters during run-time "
                 "based on desired plaintext moduli and security levels. "
              << std::endl;
    std::cout << "In this demonstration we use three input plaintext and show "
                 "how to both add them together and multiply them together. "
              << std::endl;

    size_t count = 100;

    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(2);
    parameters.set_multiplicative_depth(5);
    parameters.set_max_relin_sk_deg(3);
    parameters.set_scaling_mod_size(55);
    parameters.set_multiplication_technique(BEHZ);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);
    // enable features that you wish to use
    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);

    std::cout << "p = " << crypto_context->get_crypto_parameters()->get_plaintext_modulus() << std::endl;
    std::cout << "n = " << crypto_context->get_crypto_parameters()->get_element_params()->get_cyclotomic_order() / 2
              << std::endl;
    std::cout << "log2 q = " << crypto_context->get_crypto_parameters()->get_element_params()->get_modulus().get_msb()
              << std::endl;

    // Initialize Public Key Containers
    KeyPair<RnsPoly> key_pair;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "Running key generation (used for source data)..." << std::endl;

    double start = current_date_time();

    key_pair = crypto_context->key_gen();

    double finish = current_date_time();
    double diff = finish - start;
    std::cout << "Key generation time: "
              << "\t" << diff << " ms" << std::endl;

    if (!key_pair.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }

    crypto_context->eval_mult_key_gen(key_pair.secret_key);

    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////

    std::vector<int64_t> vector_of_ints1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext1 = crypto_context->make_coef_packed_plaintext(vector_of_ints1);

    std::vector<int64_t> vector_of_ints2 = {1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0};
    Plaintext plaintext2 = crypto_context->make_coef_packed_plaintext(vector_of_ints2);

    double time_decrypt(0.0);
    double time_mult(0.0);
    double time_relin(0.0);

    for (size_t k = 0; k < count; k++) {
        TimeVar t_decrypt;
        TimeVar t_mult;
        TimeVar t_relin;

        auto ciphertext1 = crypto_context->encrypt(key_pair.public_key, plaintext1);

        auto ciphertext2 = crypto_context->encrypt(key_pair.public_key, plaintext2);

        Plaintext plaintext_dec1;
        crypto_context->decrypt(key_pair.secret_key, ciphertext1, &plaintext_dec1);

        Plaintext plaintext_dec2;
        TIC(t_decrypt);
        crypto_context->decrypt(key_pair.secret_key, ciphertext2, &plaintext_dec2);
        time_decrypt += TOC_US(t_decrypt);

        TIC(t_mult);
        auto ciphertext_mul = crypto_context->eval_mult_no_relin(ciphertext1, ciphertext2);
        time_mult += TOC_US(t_mult);

        TIC(t_relin);
        auto ciphertext_mul_relin = crypto_context->eval_mult(ciphertext1, ciphertext2);
        time_relin += TOC_US(t_relin);
    }

    std::cout << "Average decryption time:\t" << time_decrypt / (1000 * count) << " ms" << std::endl;
    std::cout << "Average multiplication time:\t" << time_mult / (1000 * count) << " ms" << std::endl;
    std::cout << "Average relinearization time:\t" << (time_relin - time_mult) / (1000 * count) << " ms" << std::endl;
    std::cout << "Average multiplication + relinearization time:\t" << time_relin / (1000 * count) << " ms"
              << std::endl;
}
