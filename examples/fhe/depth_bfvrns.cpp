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
  Example of a computation circuit of depth 3.
  BFVrns demo for a homomorphic multiplication of depth 6 and three different approaches for depth-3 multiplications
 */

#define PROFILE

#include <cmath>
#include <cstdint>
#include <iostream>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

int main(int argc, char* argv[]) {
    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    std::cout << "\nThis code demonstrates the use of the BFVrns scheme for "
                 "homomorphic multiplication. "
              << std::endl;
    std::cout << "This code shows how to auto-generate parameters during run-time "
                 "based on desired plaintext moduli and security levels. "
              << std::endl;
    std::cout << "In this demonstration we use three input plaintext and show "
                 "how to both add them together and multiply them together. "
              << std::endl;

    // benchmarking variables
    TimeVar t;
    double processing_time(0.0);

    ContextParams<BfvRnsContext> parameters;
    parameters.set_plaintext_modulus(536903681);
    parameters.set_multiplicative_depth(3);
    parameters.set_max_relin_sk_deg(3);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);
    // enable features that you wish to use
    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);
    crypto_context->enable(ADVANCEDSHE);

    std::cout << "\np = " << crypto_context->get_crypto_parameters()->get_plaintext_modulus() << std::endl;
    std::cout << "n = " << crypto_context->get_crypto_parameters()->get_element_params()->get_cyclotomic_order() / 2
              << std::endl;
    std::cout
            << "log2 q = "
            << std::log2(
                       crypto_context->get_crypto_parameters()->get_element_params()->get_modulus().convert_to_double())
            << std::endl;

    // Initialize Public Key Containers
    KeyPair<RnsPoly> key_pair;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning key generation (used for source data)..." << std::endl;

    TIC(t);

    key_pair = crypto_context->key_gen();

    processing_time = TOC(t);
    std::cout << "Key generation time: " << processing_time << "ms" << std::endl;

    if (!key_pair.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }

    std::cout << "Running key generation for homomorphic multiplication "
                 "evaluation keys..."
              << std::endl;

    TIC(t);

    crypto_context->eval_mult_keys_gen(key_pair.secret_key);

    processing_time = TOC(t);
    std::cout << "Key generation time for homomorphic multiplication evaluation keys: " << processing_time << "ms"
              << std::endl;

    // crypto_context->eval_mult_key_gen(key_pair.secret_key);

    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////

    std::vector<int64_t> vector_of_ints1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext1 = crypto_context->make_packed_plaintext(vector_of_ints1);

    std::vector<int64_t> vector_of_ints2 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext2 = crypto_context->make_packed_plaintext(vector_of_ints2);

    std::vector<int64_t> vector_of_ints3 = {2, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext3 = crypto_context->make_packed_plaintext(vector_of_ints3);

    std::vector<int64_t> vector_of_ints4 = {2, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext4 = crypto_context->make_packed_plaintext(vector_of_ints4);

    std::vector<int64_t> vector_of_ints5 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext5 = crypto_context->make_packed_plaintext(vector_of_ints5);

    std::vector<int64_t> vector_of_ints6 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext6 = crypto_context->make_packed_plaintext(vector_of_ints6);

    std::vector<int64_t> vector_of_ints7 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext7 = crypto_context->make_packed_plaintext(vector_of_ints7);

    std::cout << "\nOriginal Plaintext #1: \n";
    std::cout << plaintext1 << std::endl;

    std::cout << "\nOriginal Plaintext #2: \n";
    std::cout << plaintext2 << std::endl;

    std::cout << "\nOriginal Plaintext #3: \n";
    std::cout << plaintext3 << std::endl;

    std::cout << "\nOriginal Plaintext #4: \n";
    std::cout << plaintext4 << std::endl;

    std::cout << "\nOriginal Plaintext #5: \n";
    std::cout << plaintext5 << std::endl;

    std::cout << "\nOriginal Plaintext #6: \n";
    std::cout << plaintext6 << std::endl;

    std::cout << "\nOriginal Plaintext #7: \n";
    std::cout << plaintext7 << std::endl;

    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning encryption of all plaintexts... ";

    std::vector<Ciphertext<RnsPoly>> ciphertexts;

    TIC(t);

    ciphertexts.push_back(crypto_context->encrypt(key_pair.public_key, plaintext1));
    ciphertexts.push_back(crypto_context->encrypt(key_pair.public_key, plaintext2));
    ciphertexts.push_back(crypto_context->encrypt(key_pair.public_key, plaintext3));
    ciphertexts.push_back(crypto_context->encrypt(key_pair.public_key, plaintext4));
    ciphertexts.push_back(crypto_context->encrypt(key_pair.public_key, plaintext5));
    ciphertexts.push_back(crypto_context->encrypt(key_pair.public_key, plaintext6));
    ciphertexts.push_back(crypto_context->encrypt(key_pair.public_key, plaintext7));

    processing_time = TOC(t);

    std::cout << "Completed\n";

    std::cout << "\nAverage encryption time: " << processing_time / 7 << "ms" << std::endl;

    ////////////////////////////////////////////////////////////
    // Homomorphic multiplication of 2 ciphertexts
    ////////////////////////////////////////////////////////////

    TIC(t);

    auto ciphertext_mult = crypto_context->eval_mult(ciphertexts[0], ciphertexts[1]);

    processing_time = TOC(t);
    std::cout << "\nTotal time of multiplying 2 ciphertexts using EvalMult w/ "
                 "relinearization: "
              << processing_time << "ms" << std::endl;

    Plaintext plaintext_dec_mult;

    TIC(t);

    crypto_context->decrypt(key_pair.secret_key, ciphertext_mult, &plaintext_dec_mult);

    processing_time = TOC(t);
    std::cout << "\nDecryption time: " << processing_time << "ms" << std::endl;

    plaintext_dec_mult->set_length(plaintext1->get_length());

    std::cout << "\nResult of homomorphic multiplication of ciphertexts #1 and #2: \n";
    std::cout << plaintext_dec_mult << std::endl;

    ////////////////////////////////////////////////////////////
    // Homomorphic multiplication of 7 ciphertexts
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning a binary-tree multiplication of 7 ciphertexts...";

    TIC(t);

    auto ciphertext_mult7 = crypto_context->eval_mult_many(ciphertexts);

    processing_time = TOC(t);

    std::cout << "Completed\n";

    std::cout << "\nTotal time of multiplying 7 ciphertexts using eval_mult_many: " << processing_time << "ms"
              << std::endl;

    Plaintext plaintext_dec_mult7;

    crypto_context->decrypt(key_pair.secret_key, ciphertext_mult7, &plaintext_dec_mult7);

    plaintext_dec_mult7->set_length(plaintext1->get_length());

    std::cout << "\nResult of 6 homomorphic multiplications: \n";
    std::cout << plaintext_dec_mult7 << std::endl;

    ////////////////////////////////////////////////////////////
    // Homomorphic multiplication of 3 ciphertexts where relinearization is done
    // at the end
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning a depth-3 multiplication w/o relinearization until the "
                 "very end...";

    TIC(t);

    auto ciphertext_mult12 = crypto_context->eval_mult_no_relin(ciphertexts[0], ciphertexts[1]);

    processing_time = TOC(t);

    std::cout << "Completed\n";

    std::cout << "Time of multiplying 2 ciphertexts w/o relinearization: " << processing_time << "ms" << std::endl;

    auto ciphertext_mult123 = crypto_context->eval_mult_and_relinearize(ciphertext_mult12, ciphertexts[2]);

    Plaintext plaintext_dec_mult123;

    crypto_context->decrypt(key_pair.secret_key, ciphertext_mult123, &plaintext_dec_mult123);

    plaintext_dec_mult123->set_length(plaintext1->get_length());

    std::cout << "\nResult of 3 homomorphic multiplications: \n";
    std::cout << plaintext_dec_mult123 << std::endl;

    ////////////////////////////////////////////////////////////
    // Homomorphic multiplication of 3 ciphertexts w/o any relinearization
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning a depth-3 multiplication w/o relinearization...";

    ciphertext_mult12 = crypto_context->eval_mult_no_relin(ciphertexts[0], ciphertexts[1]);
    ciphertext_mult123 = crypto_context->eval_mult_no_relin(ciphertext_mult12, ciphertexts[2]);

    std::cout << "Completed\n";

    crypto_context->decrypt(key_pair.secret_key, ciphertext_mult123, &plaintext_dec_mult123);

    plaintext_dec_mult123->set_length(plaintext1->get_length());

    std::cout << "\nResult of 3 homomorphic multiplications: \n";
    std::cout << plaintext_dec_mult123 << std::endl;

    ////////////////////////////////////////////////////////////
    // Homomorphic multiplication of 3 ciphertexts w/ relinearization after each
    // multiplication
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning a depth-3 multiplication w/ relinearization after each "
                 "multiplication...";

    TIC(t);

    ciphertext_mult12 = crypto_context->eval_mult(ciphertexts[0], ciphertexts[1]);

    processing_time = TOC(t);
    std::cout << "Completed\n";
    std::cout << "Time of multiplying 2 ciphertexts w/ relinearization: " << processing_time << "ms" << std::endl;

    ciphertext_mult123 = crypto_context->eval_mult(ciphertext_mult12, ciphertexts[2]);

    crypto_context->decrypt(key_pair.secret_key, ciphertext_mult123, &plaintext_dec_mult123);

    plaintext_dec_mult123->set_length(plaintext1->get_length());

    std::cout << "\nResult of 3 homomorphic multiplications: \n";
    std::cout << plaintext_dec_mult123 << std::endl;

    return 0;
}
