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
  Example for the FHEW scheme; it prints out the truth tables for all supported binary gates
 */

#include <iostream>

#include "cipher/boolean/context.h"

using namespace cipher;

int main() {
    // Sample Program: Step 1: Set CryptoContext
    auto cc = BooleanContext();

    std::cerr << "Generate cryptocontext" << std::endl;

    // STD128 is the security level of 128 bits of security based on LWE Estimator
    // and HE standard. Other options are TOY, MEDIUM, STD192, and STD256. MEDIUM
    // corresponds to the level of more than 100 bits for both quantum and
    // classical computer attacks.
    cc.generate_boolean_context(STD128);

    std::cerr << "Finished generating cryptocontext" << std::endl;

    // Sample Program: Step 2: Key Generation

    // Generate the secret key
    auto sk = cc.key_gen();

    std::cout << "Generating the bootstrapping keys..." << std::endl;

    // Generate the bootstrapping keys (refresh and switching keys)
    cc.bt_key_gen(sk);

    std::cout << "Completed the key generation."
              << "\n"
              << std::endl;

    // Sample Program: Step 3: Encryption

    // Encrypt two ciphertexts representing Boolean True (1)
    auto ct10 = cc.encrypt(sk, 1);
    auto ct11 = cc.encrypt(sk, 1);
    // Encrypt two ciphertexts representing Boolean False (0)
    auto ct00 = cc.encrypt(sk, 0);
    auto ct01 = cc.encrypt(sk, 0);

    // Sample Program: Step 4: Evaluation of NAND gates

    auto ct_nand1 = cc.eval_bin_gate(NAND, ct10, ct11);
    auto ct_nand2 = cc.eval_bin_gate(NAND, ct10, ct01);
    auto ct_nand3 = cc.eval_bin_gate(NAND, ct00, ct01);
    auto ct_nand4 = cc.eval_bin_gate(NAND, ct00, ct11);

    LwePlaintext result;

    cc.decrypt(sk, ct_nand1, &result);
    std::cout << "1 NAND 1 = " << result << std::endl;

    cc.decrypt(sk, ct_nand2, &result);
    std::cout << "1 NAND 0 = " << result << std::endl;

    cc.decrypt(sk, ct_nand3, &result);
    std::cout << "0 NAND 0 = " << result << std::endl;

    cc.decrypt(sk, ct_nand4, &result);
    std::cout << "0 NAND 1 = " << result << "\n" << std::endl;

    // Sample Program: Step 5: Evaluation of AND gates

    auto ct_and1 = cc.eval_bin_gate(AND, ct10, ct11);
    auto ct_and2 = cc.eval_bin_gate(AND, ct10, ct01);
    auto ct_and3 = cc.eval_bin_gate(AND, ct00, ct01);
    auto ct_and4 = cc.eval_bin_gate(AND, ct00, ct11);

    cc.decrypt(sk, ct_and1, &result);
    std::cout << "1 AND 1 = " << result << std::endl;

    cc.decrypt(sk, ct_and2, &result);
    std::cout << "1 AND 0 = " << result << std::endl;

    cc.decrypt(sk, ct_and3, &result);
    std::cout << "0 AND 0 = " << result << std::endl;

    cc.decrypt(sk, ct_and4, &result);
    std::cout << "0 AND 1 = " << result << "\n" << std::endl;

    // Sample Program: Step 6: Evaluation of OR gates

    auto ct_or1 = cc.eval_bin_gate(OR, ct10, ct11);
    auto ct_or2 = cc.eval_bin_gate(OR, ct10, ct01);
    auto ct_or3 = cc.eval_bin_gate(OR, ct00, ct01);
    auto ct_or4 = cc.eval_bin_gate(OR, ct00, ct11);

    cc.decrypt(sk, ct_or1, &result);
    std::cout << "1 OR 1 = " << result << std::endl;

    cc.decrypt(sk, ct_or2, &result);
    std::cout << "1 OR 0 = " << result << std::endl;

    cc.decrypt(sk, ct_or3, &result);
    std::cout << "0 OR 0 = " << result << std::endl;

    cc.decrypt(sk, ct_or4, &result);
    std::cout << "0 OR 1 = " << result << "\n" << std::endl;

    // Sample Program: Step 7: Evaluation of NOR gates

    auto ct_nor1 = cc.eval_bin_gate(NOR, ct10, ct11);
    auto ct_nor2 = cc.eval_bin_gate(NOR, ct10, ct01);
    auto ct_nor3 = cc.eval_bin_gate(NOR, ct00, ct01);
    auto ct_nor4 = cc.eval_bin_gate(NOR, ct00, ct11);

    cc.decrypt(sk, ct_nor1, &result);
    std::cout << "1 NOR 1 = " << result << std::endl;

    cc.decrypt(sk, ct_nor2, &result);
    std::cout << "1 NOR 0 = " << result << std::endl;

    cc.decrypt(sk, ct_nor3, &result);
    std::cout << "0 NOR 0 = " << result << std::endl;

    cc.decrypt(sk, ct_nor4, &result);
    std::cout << "0 NOR 1 = " << result << "\n" << std::endl;

    // Sample Program: Step 8: Evaluation of XOR gates

    auto ct_xor1 = cc.eval_bin_gate(XOR, ct10, ct11);
    auto ct_xor2 = cc.eval_bin_gate(XOR, ct10, ct01);
    auto ct_xor3 = cc.eval_bin_gate(XOR, ct00, ct01);
    auto ct_xor4 = cc.eval_bin_gate(XOR, ct00, ct11);

    cc.decrypt(sk, ct_xor1, &result);
    std::cout << "1 XOR 1 = " << result << std::endl;

    cc.decrypt(sk, ct_xor2, &result);
    std::cout << "1 XOR 0 = " << result << std::endl;

    cc.decrypt(sk, ct_xor3, &result);
    std::cout << "0 XOR 0 = " << result << std::endl;

    cc.decrypt(sk, ct_xor4, &result);
    std::cout << "0 XOR 1 = " << result << "\n" << std::endl;

    // Sample Program: Step 9: Evaluation of XNOR gates

    auto ct_xnor1 = cc.eval_bin_gate(XNOR, ct10, ct11);
    auto ct_xnor2 = cc.eval_bin_gate(XNOR, ct10, ct01);
    auto ct_xnor3 = cc.eval_bin_gate(XNOR, ct00, ct01);
    auto ct_xnor4 = cc.eval_bin_gate(XNOR, ct00, ct11);

    cc.decrypt(sk, ct_xnor1, &result);
    std::cout << "1 XNOR 1 = " << result << std::endl;

    cc.decrypt(sk, ct_xnor2, &result);
    std::cout << "1 XNOR 0 = " << result << std::endl;

    cc.decrypt(sk, ct_xnor3, &result);
    std::cout << "0 XNOR 0 = " << result << std::endl;

    cc.decrypt(sk, ct_xnor4, &result);
    std::cout << "0 XNOR 1 = " << result << "\n" << std::endl;

    return 0;
}
