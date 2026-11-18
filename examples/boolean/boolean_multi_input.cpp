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
  Example for the FHEW scheme using the default bootstrapping method (GINX)
 */

#include <iostream>
#include <vector>

#include "cipher/boolean/context.h"

using namespace cipher;

int main() {
    // Sample Program: Step 1: Set CryptoContext

    auto cc = BooleanContext();

    cc.generate_boolean_context(STD128_4, GINX);

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk = cc.key_gen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.bt_key_gen(sk);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Encryption

    // Encrypt several ciphertexts representing Boolean True (1) or False (0).
    // plaintext modulus is set higher than 4 to 2 * num_of_inputs
    auto p = 6;
    auto ct1_3input = cc.encrypt(sk, 1, SMALL_DIM, p);
    auto ct2_3input = cc.encrypt(sk, 1, SMALL_DIM, p);
    auto ct3_3input = cc.encrypt(sk, 0, SMALL_DIM, p);

    // 1, 1, 0
    std::vector<LweCiphertext> ct123;
    ct123.push_back(ct1_3input);
    ct123.push_back(ct2_3input);
    ct123.push_back(ct3_3input);

    // 1, 1, 0
    auto ct_and3 = cc.eval_bin_gate(AND3, ct123);

    // 1, 1, 0
    auto ct_or3 = cc.eval_bin_gate(OR3, ct123);
    // Sample Program: Step 5: Decryption

    LwePlaintext result;
    cc.decrypt(sk, ct_and3, &result, p);
    if (result != 0)
        CIPHER_THROW("Decryption failure");

    std::cout << "Result of encrypted computation of AND(1, 1, 0) = " << result << std::endl;

    cc.decrypt(sk, ct_or3, &result, p);
    if (result != 1)
        CIPHER_THROW("Decryption failure");

    std::cout << "Result of encrypted computation of OR(1, 1, 0) = " << result << std::endl;

    // majority gate and cmux for 3 input does not need higher plaintext modulus
    p = 4;
    auto ct1_3input_p4 = cc.encrypt(sk, 1, SMALL_DIM, p);
    auto ct2_3input_p4 = cc.encrypt(sk, 1, SMALL_DIM, p);
    auto ct3_3input_p4 = cc.encrypt(sk, 0, SMALL_DIM, p);
    auto ct4_3input_p4 = cc.encrypt(sk, 0, SMALL_DIM, p);

    // 1, 1, 0
    std::vector<LweCiphertext> ct123_p4;
    ct123_p4.push_back(ct1_3input_p4);
    ct123_p4.push_back(ct2_3input_p4);
    ct123_p4.push_back(ct3_3input_p4);

    // 1, 0, 0
    std::vector<LweCiphertext> ct134_p4;
    ct134_p4.push_back(ct1_3input_p4);
    ct134_p4.push_back(ct3_3input_p4);
    ct134_p4.push_back(ct4_3input_p4);

    // 1, 0, 1
    std::vector<LweCiphertext> ct132_p4;
    ct132_p4.push_back(ct1_3input_p4);
    ct132_p4.push_back(ct3_3input_p4);
    ct132_p4.push_back(ct2_3input_p4);

    // 1, 1, 0
    auto ct_majority = cc.eval_bin_gate(MAJORITY, ct123_p4);

    // 1, 0, 1
    auto ct_cmux0 = cc.eval_bin_gate(CMUX, ct132_p4);

    // 1, 0, 0
    auto ct_cmux1 = cc.eval_bin_gate(CMUX, ct134_p4);

    cc.decrypt(sk, ct_majority, &result);
    if (result != 1)
        CIPHER_THROW("Decryption failure");

    std::cout << "Result of encrypted computation of Majority(1, 1, 0) = " << result << std::endl;

    cc.decrypt(sk, ct_cmux1, &result);
    if (result != 1)
        CIPHER_THROW("Decryption failure");
    std::cout << "Result of encrypted computation of CMUX(1, 0, 0) = " << result << std::endl;

    cc.decrypt(sk, ct_cmux0, &result);
    if (result != 0)
        CIPHER_THROW("Decryption failure");

    std::cout << "Result of encrypted computation of CMUX(1, 0, 1) = " << result << std::endl;

    // for 4 input gates
    p = 8;
    auto ct1_4input = cc.encrypt(sk, 1, SMALL_DIM, p);
    auto ct2_4input = cc.encrypt(sk, 0, SMALL_DIM, p);
    auto ct3_4input = cc.encrypt(sk, 0, SMALL_DIM, p);
    auto ct4_4input = cc.encrypt(sk, 0, SMALL_DIM, p);

    // 1, 0, 0, 0
    std::vector<LweCiphertext> ct1234;
    ct1234.push_back(ct1_4input);
    ct1234.push_back(ct2_4input);
    ct1234.push_back(ct3_4input);
    ct1234.push_back(ct4_4input);

    // Sample Program: Step 4: Evaluation

    // 1, 0, 0, 0
    auto ct_and4 = cc.eval_bin_gate(AND4, ct1234);

    // 1, 0, 0, 0
    auto ct_or4 = cc.eval_bin_gate(OR4, ct1234);

    // Sample Program: Step 5: Decryption
    cc.decrypt(sk, ct_and4, &result, p);
    if (result != 0)
        CIPHER_THROW("Decryption failure");

    std::cout << "Result of encrypted computation of AND(1, 0, 0, 0) = " << result << std::endl;

    cc.decrypt(sk, ct_or4, &result, p);
    if (result != 1)
        CIPHER_THROW("Decryption failure");

    std::cout << "Result of encrypted computation of OR(1, 0, 0, 0) = " << result << std::endl;

    return 0;
}
