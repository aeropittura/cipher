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

#include "cipher/boolean/context.h"

using namespace cipher;

int main() {
    // Sample Program: Step 1: Set CryptoContext

    auto cc = BooleanContext();

    // STD128 is the security level of 128 bits of security based on LWE Estimator
    // and HE standard. Other common options are TOY, MEDIUM, STD192, and STD256.
    // MEDIUM corresponds to the level of more than 100 bits for both quantum and
    // classical computer attacks.
    cc.generate_boolean_context(STD128);

    // verifying public key encrypt and decrypt without bootstrap
    // Generate the secret, public key pair
    auto kp = cc.key_gen_pair();

    // LARGE_DIM specifies the dimension of the output ciphertext
    auto ctp = cc.encrypt(kp->public_key, 1, LARGE_DIM);

    LwePlaintext result;

    // decryption check before computation
    cc.decrypt(kp->secret_key, ctp, &result);

    std::cout << "Result of encrypted ciphertext of 1 = " << result << std::endl;

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk = cc.key_gen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh, switching and public keys)
    cc.bt_key_gen(sk, PUB_ENCRYPT);

    std::cout << "Completed the key generation." << std::endl;

    // Sample Program: Step 3: Encryption

    // Encrypt two ciphertexts representing Boolean True (1).
    // By default, freshly encrypted ciphertexts are bootstrapped.
    // If you wish to get a fresh encryption without bootstrapping, write
    // auto   ct1 = cc.encrypt(sk, 1, LARGE_DIM);
    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct2 = cc.encrypt(cc.get_public_key(), 1);

    // decryption check before computation
    cc.decrypt(sk, ct1, &result);

    std::cout << "Result of encrypted ciphertext of 1 = " << result << std::endl;

    // Sample Program: Step 4: Evaluation

    // Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR
    LwePlaintext result1;
    auto ct_and1 = cc.eval_bin_gate(AND, ct1, ct2);

    cc.decrypt(sk, ct_and1, &result1);

    std::cout << "Result of encrypted computation of (1 AND 1) = " << result1 << std::endl;

    // Compute (NOT 1) = 0
    auto ct2_not = cc.eval_not(ct2);

    cc.decrypt(sk, ct2_not, &result);

    std::cout << "Result of encrypted computation of (NOT 1) = " << result << std::endl;

    // Compute (1 AND (NOT 1)) = 0
    auto ct_and2 = cc.eval_bin_gate(AND, ct2_not, ct1);

    cc.decrypt(sk, ct_and2, &result);

    std::cout << "Result of encrypted computation of (1 AND (NOT 1)) = " << result << std::endl;

    // Computes OR of the results in ct_and1 and ct_and2 = 1
    auto ct_result = cc.eval_bin_gate(OR, ct_and1, ct_and2);

    // Sample Program: Step 5: Decryption
    cc.decrypt(sk, ct_result, &result);

    std::cout << "Result of encrypted computation of (1 AND 1) OR (1 AND (NOT 1)) = " << result << std::endl;

    return 0;
}
