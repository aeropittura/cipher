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

#include <string>

#include "cipher/boolean/context.h"
#include "gtest/gtest.h"

using namespace cipher;

// ---------------  TESTING METHODS OF FHEW ---------------

// Checks the truth table for NOT
TEST(UNITTestFHEWPKEAP, NOT) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, AP);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);

    auto ct1_not = cc.eval_not(ct1);
    auto ct0_not = cc.eval_not(ct0);

    LwePlaintext result1;
    cc.decrypt(sk, ct1_not, &result1);

    LwePlaintext result0;
    cc.decrypt(sk, ct0_not, &result0);

    EXPECT_EQ(0, result1) << "NOT failed";

    EXPECT_EQ(1, result0) << "NOT failed";
}

// Checks the truth table for NOT
TEST(UNITTestFHEWPKEGINX, NOT) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, GINX);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);
    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);

    auto ct1_not = cc.eval_not(ct1);
    auto ct0_not = cc.eval_not(ct0);

    LwePlaintext result1;
    cc.decrypt(sk, ct1_not, &result1);

    LwePlaintext result0;
    cc.decrypt(sk, ct0_not, &result0);

    EXPECT_EQ(0, result1) << "NOT failed";

    EXPECT_EQ(1, result0) << "NOT failed";
}

// Checks the truth table for AND
TEST(UNITTestFHEWPKEAP, Bootstrap) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, AP);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);

    auto ct11 = cc.bootstrap(ct1);
    auto ct01 = cc.bootstrap(ct0);

    LwePlaintext result11;
    cc.decrypt(sk, ct11, &result11);
    LwePlaintext result01;
    cc.decrypt(sk, ct01, &result01);

    std::string failed = "Bootstrapping failed";

    EXPECT_EQ(1, result11) << failed;
    EXPECT_EQ(0, result01) << failed;
}

// Checks the truth table for AND
TEST(UNITTestFHEWPKEGINX, Bootstrap) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, GINX);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);

    auto ct11 = cc.bootstrap(ct1);
    auto ct01 = cc.bootstrap(ct0);

    LwePlaintext result11;
    cc.decrypt(sk, ct11, &result11);
    LwePlaintext result01;
    cc.decrypt(sk, ct01, &result01);

    std::string failed = "Bootstrapping failed";

    EXPECT_EQ(1, result11) << failed;
    EXPECT_EQ(0, result01) << failed;
}

// Checks the truth table for AND
TEST(UNITTestFHEWPKEAP, AND) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, AP);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);
    auto ct1_alt = cc.encrypt(cc.get_public_key(), 1);
    auto ct0_alt = cc.encrypt(cc.get_public_key(), 0);

    auto ct11 = cc.eval_bin_gate(AND, ct1, ct1_alt);
    auto ct01 = cc.eval_bin_gate(AND, ct0, ct1);
    auto ct10 = cc.eval_bin_gate(AND, ct1, ct0);
    auto ct00 = cc.eval_bin_gate(AND, ct0, ct0_alt);

    LwePlaintext result11;
    cc.decrypt(sk, ct11, &result11);
    LwePlaintext result01;
    cc.decrypt(sk, ct01, &result01);
    LwePlaintext result10;
    cc.decrypt(sk, ct10, &result10);
    LwePlaintext result00;
    cc.decrypt(sk, ct00, &result00);

    std::string failed = "AND failed";

    EXPECT_EQ(1, result11) << failed;
    EXPECT_EQ(0, result01) << failed;
    EXPECT_EQ(0, result10) << failed;
    EXPECT_EQ(0, result00) << failed;
}

// Checks the truth table for AND
TEST(UNITTestFHEWPKEGINX, AND) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, GINX);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);
    auto ct1_alt = cc.encrypt(cc.get_public_key(), 1);
    auto ct0_alt = cc.encrypt(cc.get_public_key(), 0);

    auto ct11 = cc.eval_bin_gate(AND, ct1, ct1_alt);
    auto ct01 = cc.eval_bin_gate(AND, ct0, ct1);
    auto ct10 = cc.eval_bin_gate(AND, ct1, ct0);
    auto ct00 = cc.eval_bin_gate(AND, ct0, ct0_alt);

    LwePlaintext result11;
    cc.decrypt(sk, ct11, &result11);
    LwePlaintext result01;
    cc.decrypt(sk, ct01, &result01);
    LwePlaintext result10;
    cc.decrypt(sk, ct10, &result10);
    LwePlaintext result00;
    cc.decrypt(sk, ct00, &result00);

    std::string failed = "AND failed";

    EXPECT_EQ(1, result11) << failed;
    EXPECT_EQ(0, result01) << failed;
    EXPECT_EQ(0, result10) << failed;
    EXPECT_EQ(0, result00) << failed;
}

// Checks GINX for the parameter set
// that exercises the signed modular reduction
// implementation in signed_digit_decompose
TEST(UNITTestFHEWPKEGINX, SIGNED_MOD) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(SIGNED_MOD_TEST, GINX);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);
    auto ct1_alt = cc.encrypt(cc.get_public_key(), 1);
    auto ct0_alt = cc.encrypt(cc.get_public_key(), 0);

    auto ct11 = cc.eval_bin_gate(AND, ct1, ct1_alt);
    auto ct01 = cc.eval_bin_gate(AND, ct0, ct1);
    auto ct10 = cc.eval_bin_gate(AND, ct1, ct0);
    auto ct00 = cc.eval_bin_gate(AND, ct0, ct0_alt);

    LwePlaintext result11;
    cc.decrypt(sk, ct11, &result11);
    LwePlaintext result01;
    cc.decrypt(sk, ct01, &result01);
    LwePlaintext result10;
    cc.decrypt(sk, ct10, &result10);
    LwePlaintext result00;
    cc.decrypt(sk, ct00, &result00);

    std::string failed = "AND failed for SIGNED_MOD_TEST";

    EXPECT_EQ(1, result11) << failed;
    EXPECT_EQ(0, result01) << failed;
    EXPECT_EQ(0, result10) << failed;
    EXPECT_EQ(0, result00) << failed;
}

// Checks the truth table for OR
TEST(UNITTestFHEWPKEAP, OR) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, AP);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);
    auto ct1_alt = cc.encrypt(cc.get_public_key(), 1);
    auto ct0_alt = cc.encrypt(cc.get_public_key(), 0);

    auto ct11 = cc.eval_bin_gate(OR, ct1, ct1_alt);
    auto ct01 = cc.eval_bin_gate(OR, ct0, ct1);
    auto ct10 = cc.eval_bin_gate(OR, ct1, ct0);
    auto ct00 = cc.eval_bin_gate(OR, ct0, ct0_alt);

    LwePlaintext result11;
    cc.decrypt(sk, ct11, &result11);
    LwePlaintext result01;
    cc.decrypt(sk, ct01, &result01);
    LwePlaintext result10;
    cc.decrypt(sk, ct10, &result10);
    LwePlaintext result00;
    cc.decrypt(sk, ct00, &result00);

    std::string failed = "OR failed";

    EXPECT_EQ(1, result11) << failed;
    EXPECT_EQ(1, result01) << failed;
    EXPECT_EQ(1, result10) << failed;
    EXPECT_EQ(0, result00) << failed;
}

// Checks the truth table for OR
TEST(UNITTestFHEWPKEGINX, OR) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, GINX);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);
    auto ct1_alt = cc.encrypt(cc.get_public_key(), 1);
    auto ct0_alt = cc.encrypt(cc.get_public_key(), 0);

    auto ct11 = cc.eval_bin_gate(OR, ct1, ct1_alt);
    auto ct01 = cc.eval_bin_gate(OR, ct0, ct1);
    auto ct10 = cc.eval_bin_gate(OR, ct1, ct0);
    auto ct00 = cc.eval_bin_gate(OR, ct0, ct0_alt);

    LwePlaintext result11;
    cc.decrypt(sk, ct11, &result11);
    LwePlaintext result01;
    cc.decrypt(sk, ct01, &result01);
    LwePlaintext result10;
    cc.decrypt(sk, ct10, &result10);
    LwePlaintext result00;
    cc.decrypt(sk, ct00, &result00);

    std::string failed = "OR failed";

    EXPECT_EQ(1, result11) << failed;
    EXPECT_EQ(1, result01) << failed;
    EXPECT_EQ(1, result10) << failed;
    EXPECT_EQ(0, result00) << failed;
}

// Checks the truth table for AND
TEST(UNITTestFHEWPKEAP, NAND) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, AP);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);
    auto ct1_alt = cc.encrypt(cc.get_public_key(), 1);
    auto ct0_alt = cc.encrypt(cc.get_public_key(), 0);

    auto ct11 = cc.eval_bin_gate(NAND, ct1, ct1_alt);
    auto ct01 = cc.eval_bin_gate(NAND, ct0, ct1);
    auto ct10 = cc.eval_bin_gate(NAND, ct1, ct0);
    auto ct00 = cc.eval_bin_gate(NAND, ct0, ct0_alt);

    LwePlaintext result11;
    cc.decrypt(sk, ct11, &result11);
    LwePlaintext result01;
    cc.decrypt(sk, ct01, &result01);
    LwePlaintext result10;
    cc.decrypt(sk, ct10, &result10);
    LwePlaintext result00;
    cc.decrypt(sk, ct00, &result00);

    std::string failed = "NAND failed";

    EXPECT_EQ(0, result11) << failed;
    EXPECT_EQ(1, result01) << failed;
    EXPECT_EQ(1, result10) << failed;
    EXPECT_EQ(1, result00) << failed;
}

// Checks the truth table for AND
TEST(UNITTestFHEWPKEGINX, NAND) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, GINX);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);
    auto ct1_alt = cc.encrypt(cc.get_public_key(), 1);
    auto ct0_alt = cc.encrypt(cc.get_public_key(), 0);

    auto ct11 = cc.eval_bin_gate(NAND, ct1, ct1_alt);
    auto ct01 = cc.eval_bin_gate(NAND, ct0, ct1);
    auto ct10 = cc.eval_bin_gate(NAND, ct1, ct0);
    auto ct00 = cc.eval_bin_gate(NAND, ct0, ct0_alt);

    LwePlaintext result11;
    cc.decrypt(sk, ct11, &result11);
    LwePlaintext result01;
    cc.decrypt(sk, ct01, &result01);
    LwePlaintext result10;
    cc.decrypt(sk, ct10, &result10);
    LwePlaintext result00;
    cc.decrypt(sk, ct00, &result00);

    std::string failed = "NAND failed";

    EXPECT_EQ(0, result11) << failed;
    EXPECT_EQ(1, result01) << failed;
    EXPECT_EQ(1, result10) << failed;
    EXPECT_EQ(1, result00) << failed;
}

// Checks the truth table for AND
TEST(UNITTestFHEWPKEAP, NOR) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, AP);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);
    auto ct1_alt = cc.encrypt(cc.get_public_key(), 1);
    auto ct0_alt = cc.encrypt(cc.get_public_key(), 0);

    auto ct11 = cc.eval_bin_gate(NOR, ct1, ct1_alt);
    auto ct01 = cc.eval_bin_gate(NOR, ct0, ct1);
    auto ct10 = cc.eval_bin_gate(NOR, ct1, ct0);
    auto ct00 = cc.eval_bin_gate(NOR, ct0, ct0_alt);

    LwePlaintext result11;
    cc.decrypt(sk, ct11, &result11);
    LwePlaintext result01;
    cc.decrypt(sk, ct01, &result01);
    LwePlaintext result10;
    cc.decrypt(sk, ct10, &result10);
    LwePlaintext result00;
    cc.decrypt(sk, ct00, &result00);

    std::string failed = "NOR failed";

    EXPECT_EQ(0, result11) << failed;
    EXPECT_EQ(0, result01) << failed;
    EXPECT_EQ(0, result10) << failed;
    EXPECT_EQ(1, result00) << failed;
}

// Checks the truth table for AND
TEST(UNITTestFHEWPKEGINX, NOR) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, GINX);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);
    auto ct1_alt = cc.encrypt(cc.get_public_key(), 1);
    auto ct0_alt = cc.encrypt(cc.get_public_key(), 0);

    auto ct11 = cc.eval_bin_gate(NOR, ct1, ct1_alt);
    auto ct01 = cc.eval_bin_gate(NOR, ct0, ct1);
    auto ct10 = cc.eval_bin_gate(NOR, ct1, ct0);
    auto ct00 = cc.eval_bin_gate(NOR, ct0, ct0_alt);

    LwePlaintext result11;
    cc.decrypt(sk, ct11, &result11);
    LwePlaintext result01;
    cc.decrypt(sk, ct01, &result01);
    LwePlaintext result10;
    cc.decrypt(sk, ct10, &result10);
    LwePlaintext result00;
    cc.decrypt(sk, ct00, &result00);

    std::string failed = "NOR failed";

    EXPECT_EQ(0, result11) << failed;
    EXPECT_EQ(0, result01) << failed;
    EXPECT_EQ(0, result10) << failed;
    EXPECT_EQ(1, result00) << failed;
}

// Checks the truth table for XOR
TEST(UNITTestFHEWPKEAP, XOR) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, AP);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);
    auto ct1_alt = cc.encrypt(cc.get_public_key(), 1);
    auto ct0_alt = cc.encrypt(cc.get_public_key(), 0);

    auto ct11 = cc.eval_bin_gate(XOR, ct1, ct1_alt);
    auto ct01 = cc.eval_bin_gate(XOR, ct0, ct1);
    auto ct10 = cc.eval_bin_gate(XOR, ct1, ct0);
    auto ct00 = cc.eval_bin_gate(XOR, ct0, ct0_alt);

    LwePlaintext result11;
    cc.decrypt(sk, ct11, &result11);
    LwePlaintext result01;
    cc.decrypt(sk, ct01, &result01);
    LwePlaintext result10;
    cc.decrypt(sk, ct10, &result10);
    LwePlaintext result00;
    cc.decrypt(sk, ct00, &result00);

    std::string failed = "XOR failed";

    EXPECT_EQ(0, result11) << failed;
    EXPECT_EQ(1, result01) << failed;
    EXPECT_EQ(1, result10) << failed;
    EXPECT_EQ(0, result00) << failed;
}

// Checks the truth table for XOR
TEST(UNITTestFHEWPKEGINX, XOR) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, GINX);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);
    auto ct1_alt = cc.encrypt(cc.get_public_key(), 1);
    auto ct0_alt = cc.encrypt(cc.get_public_key(), 0);

    auto ct11 = cc.eval_bin_gate(XOR, ct1, ct1_alt);
    auto ct01 = cc.eval_bin_gate(XOR, ct0, ct1);
    auto ct10 = cc.eval_bin_gate(XOR, ct1, ct0);
    auto ct00 = cc.eval_bin_gate(XOR, ct0, ct0_alt);

    LwePlaintext result11;
    cc.decrypt(sk, ct11, &result11);
    LwePlaintext result01;
    cc.decrypt(sk, ct01, &result01);
    LwePlaintext result10;
    cc.decrypt(sk, ct10, &result10);
    LwePlaintext result00;
    cc.decrypt(sk, ct00, &result00);

    std::string failed = "XOR failed";

    EXPECT_EQ(0, result11) << failed;
    EXPECT_EQ(1, result01) << failed;
    EXPECT_EQ(1, result10) << failed;
    EXPECT_EQ(0, result00) << failed;
}

// Checks the truth table for XOR
TEST(UNITTestFHEWPKEAP, XNOR) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, AP);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);
    auto ct1_alt = cc.encrypt(cc.get_public_key(), 1);
    auto ct0_alt = cc.encrypt(cc.get_public_key(), 0);

    auto ct11 = cc.eval_bin_gate(XNOR, ct1, ct1_alt);
    auto ct01 = cc.eval_bin_gate(XNOR, ct0, ct1);
    auto ct10 = cc.eval_bin_gate(XNOR, ct1, ct0);
    auto ct00 = cc.eval_bin_gate(XNOR, ct0, ct0_alt);

    LwePlaintext result11;
    cc.decrypt(sk, ct11, &result11);
    LwePlaintext result01;
    cc.decrypt(sk, ct01, &result01);
    LwePlaintext result10;
    cc.decrypt(sk, ct10, &result10);
    LwePlaintext result00;
    cc.decrypt(sk, ct00, &result00);

    std::string failed = "XNOR failed";

    EXPECT_EQ(1, result11) << failed;
    EXPECT_EQ(0, result01) << failed;
    EXPECT_EQ(0, result10) << failed;
    EXPECT_EQ(1, result00) << failed;
}

// Checks the truth table for XOR
TEST(UNITTestFHEWPKEGINX, XNOR) {
    auto cc = BooleanContext();
    cc.generate_boolean_context(TOY, GINX);

    auto sk = cc.key_gen();

    cc.bt_key_gen(sk, PUB_ENCRYPT);

    auto ct1 = cc.encrypt(cc.get_public_key(), 1);
    auto ct0 = cc.encrypt(cc.get_public_key(), 0);
    auto ct1_alt = cc.encrypt(cc.get_public_key(), 1);
    auto ct0_alt = cc.encrypt(cc.get_public_key(), 0);

    auto ct11 = cc.eval_bin_gate(XNOR, ct1, ct1_alt);
    auto ct01 = cc.eval_bin_gate(XNOR, ct0, ct1);
    auto ct10 = cc.eval_bin_gate(XNOR, ct1, ct0);
    auto ct00 = cc.eval_bin_gate(XNOR, ct0, ct0_alt);

    LwePlaintext result11;
    cc.decrypt(sk, ct11, &result11);
    LwePlaintext result01;
    cc.decrypt(sk, ct01, &result01);
    LwePlaintext result10;
    cc.decrypt(sk, ct10, &result10);
    LwePlaintext result00;
    cc.decrypt(sk, ct00, &result00);

    std::string failed = "XNOR failed";

    EXPECT_EQ(1, result11) << failed;
    EXPECT_EQ(0, result01) << failed;
    EXPECT_EQ(0, result10) << failed;
    EXPECT_EQ(1, result00) << failed;
}
