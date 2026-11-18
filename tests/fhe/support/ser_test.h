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
  helper function to test serialization
 */

#ifndef CIPHER_TESTS_FHE_SUPPORT_SER_TEST_H_
#define CIPHER_TESTS_FHE_SUPPORT_SER_TEST_H_

#include <iostream>
#include <sstream>
#include <string>

#include "fhe/support/test_exception.h"
#include "cipher/fhe/context_ser.h"
#include "cipher/fhe/globals.h"
#include "gtest/gtest.h"

using namespace cipher;

template <typename Element, typename ST>
void unit_test_context_with_sertype(CryptoContext<Element> cc, const ST& sertype,
                                    const std::string& failmsg = std::string()) {
    try {
        KeyPair<Element> kp = cc->key_gen();
        cc->eval_mult_key_gen(kp.secret_key);
        cc->eval_sum_key_gen(kp.secret_key);

        std::stringstream s;
        serialization::to_stream(cc, s, sertype);

        // std::cerr << " Output " << s.str() << std::endl;

        disable_precompute_crt_tables_after_deserializaton();
        CryptoContext<Element> newcc;
        serialization::from_stream(newcc, s, sertype);

        ASSERT_TRUE(newcc) << failmsg << " Deserialize failed";

        EXPECT_EQ(*cc, *newcc) << failmsg << " Mismatched context";

        EXPECT_EQ(*cc->get_scheme(), *newcc->get_scheme()) << failmsg << " Scheme mismatch after ser/deser";
        EXPECT_EQ(*cc->get_crypto_parameters(), *newcc->get_crypto_parameters())
                << failmsg << " Crypto parms mismatch after ser/deser";
        EXPECT_EQ(*cc->get_encoding_params(), *newcc->get_encoding_params())
                << failmsg << " Encoding parms mismatch after ser/deser";
        EXPECT_EQ(cc->get_scheme()->get_enabled(), newcc->get_scheme()->get_enabled())
                << failmsg << " Enabled features mismatch after ser/deser";

        s.str("");
        s.clear();
        serialization::to_stream(kp.public_key, s, sertype);

        PublicKey<Element> new_pub;
        serialization::from_stream(new_pub, s, sertype);
        ASSERT_TRUE(new_pub) << failmsg << " Key deserialize failed";

        EXPECT_EQ(*kp.public_key, *new_pub) << failmsg << " Key mismatch";

        CryptoContext<Element> newcc_fromkey = new_pub->get_crypto_context();
        EXPECT_EQ(*cc, *newcc_fromkey) << failmsg << " Key deser has wrong context";
        enable_precompute_crt_tables_after_deserializaton();
    } catch (std::exception& e) {
        enable_precompute_crt_tables_after_deserializaton();

        std::cerr << "Exception thrown from " << __func__ << "(): " << e.what() << std::endl;
        // make it fail
        EXPECT_TRUE(0 == 1) << failmsg;
    } catch (...) {
        enable_precompute_crt_tables_after_deserializaton();

        UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
    }
}

#endif  // CIPHER_TESTS_FHE_SUPPORT_SER_TEST_H_
