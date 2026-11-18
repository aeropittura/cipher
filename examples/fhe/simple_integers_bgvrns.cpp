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
  Simple example for BGVrns (integer arithmetic)
 */

#include <cstdint>
#include <iostream>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

int main() {
    // Sample Program: Step 1 - Set CryptoContext
    ContextParams<BgvRnsContext> parameters;
    parameters.set_multiplicative_depth(2);
    parameters.set_plaintext_modulus(65537);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);
    // Enable features that you wish to use
    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);

    // Sample Program: Step 2 - Key Generation

    // Initialize Public Key Containers
    KeyPair<RnsPoly> key_pair;

    // Generate a public/private key pair
    key_pair = crypto_context->key_gen();

    // Generate the relinearization key
    crypto_context->eval_mult_key_gen(key_pair.secret_key);

    // Generate the rotation evaluation keys
    crypto_context->eval_rotate_key_gen(key_pair.secret_key, {1, 2, -1, -2});

    // Sample Program: Step 3 - Encryption

    // First plaintext vector is encoded
    std::vector<int64_t> vector_of_ints1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext1 = crypto_context->make_packed_plaintext(vector_of_ints1);
    // Second plaintext vector is encoded
    std::vector<int64_t> vector_of_ints2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext2 = crypto_context->make_packed_plaintext(vector_of_ints2);
    // Third plaintext vector is encoded
    std::vector<int64_t> vector_of_ints3 = {1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext3 = crypto_context->make_packed_plaintext(vector_of_ints3);

    // The encoded vectors are encrypted
    auto ciphertext1 = crypto_context->encrypt(key_pair.public_key, plaintext1);
    auto ciphertext2 = crypto_context->encrypt(key_pair.public_key, plaintext2);
    auto ciphertext3 = crypto_context->encrypt(key_pair.public_key, plaintext3);

    // Sample Program: Step 4 - Evaluation

    // Homomorphic additions
    auto ciphertext_add12 = crypto_context->eval_add(ciphertext1, ciphertext2);
    auto ciphertext_add_result = crypto_context->eval_add(ciphertext_add12, ciphertext3);

    // Homomorphic multiplications
    // modulus switching is done automatically because by default the modulus
    // switching method is set to AUTO (rather than MANUAL)
    auto ciphertext_mul12 = crypto_context->eval_mult(ciphertext1, ciphertext2);
    auto ciphertext_mult_result = crypto_context->eval_mult(ciphertext_mul12, ciphertext3);
    // Homomorphic rotations
    auto ciphertext_rot1 = crypto_context->eval_rotate(ciphertext1, 1);
    auto ciphertext_rot2 = crypto_context->eval_rotate(ciphertext1, 2);
    auto ciphertext_rot3 = crypto_context->eval_rotate(ciphertext1, -1);
    auto ciphertext_rot4 = crypto_context->eval_rotate(ciphertext1, -2);

    // Sample Program: Step 5 - Decryption

    // Decrypt the result of additions
    Plaintext plaintext_add_result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_add_result, &plaintext_add_result);

    // Decrypt the result of multiplications
    Plaintext plaintext_mult_result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_mult_result, &plaintext_mult_result);

    // Decrypt the result of rotations
    Plaintext plaintext_rot1;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_rot1, &plaintext_rot1);
    Plaintext plaintext_rot2;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_rot2, &plaintext_rot2);
    Plaintext plaintext_rot3;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_rot3, &plaintext_rot3);
    Plaintext plaintext_rot4;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_rot4, &plaintext_rot4);

    plaintext_rot1->set_length(vector_of_ints1.size());
    plaintext_rot2->set_length(vector_of_ints1.size());
    plaintext_rot3->set_length(vector_of_ints1.size());
    plaintext_rot4->set_length(vector_of_ints1.size());

    std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    std::cout << "Plaintext #2: " << plaintext2 << std::endl;
    std::cout << "Plaintext #3: " << plaintext3 << std::endl;

    // Output results
    std::cout << "\nResults of homomorphic computations" << std::endl;
    std::cout << "#1 + #2 + #3: " << plaintext_add_result << std::endl;
    std::cout << "#1 * #2 * #3: " << plaintext_mult_result << std::endl;
    std::cout << "Left rotation of #1 by 1: " << plaintext_rot1 << std::endl;
    std::cout << "Left rotation of #1 by 2: " << plaintext_rot2 << std::endl;
    std::cout << "Right rotation of #1 by 1: " << plaintext_rot3 << std::endl;
    std::cout << "Right rotation of #1 by 2: " << plaintext_rot4 << std::endl;

    return 0;
}
