//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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
  SchemeletRlweMp::encrypt_coeff converts each signed plaintext coefficient into its residue modulo
  the ciphertext modulus. That conversion used to negate the operand as a signed value, which is
  undefined for the signed minimum, and skipped the reduction. The existing functional
  bootstrapping tests only feed non-negative coefficients, so the negative branch went untested.
*/

#include <cstdint>
#include <limits>
#include <vector>

#include "gtest/gtest.h"
#include "cipher/cipher.h"
#include "cipher/fhe/schemelet/rlwe_mp.h"

using namespace cipher;

namespace {
// Plaintext modulus; decrypt_coeff centres its output, so coefficients must stay inside
// (-PLAINTEXT_MODULUS / 2, PLAINTEXT_MODULUS / 2) to round-trip.
constexpr int64_t PLAINTEXT_MODULUS = 256;

class UTRLWEMP : public ::testing::Test {
  protected:
    void TearDown() override {
        ContextFactory<RnsPoly>::release_all_contexts();
    }
};

// Negative coefficients must survive the round-trip unchanged. In-range values were already
// handled correctly, so this guards the branch rather than reproducing the defect; the reduction
// itself is covered below.
TEST_F(UTRLWEMP, NegativeCoefficientsRoundTrip) {
    ContextParams<CkksRnsContext> parameters;
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(1024);
    parameters.set_multiplicative_depth(1);
    parameters.set_scaling_mod_size(59);
    parameters.set_first_mod_size(60);
    parameters.set_batch_size(8);
    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);

    auto keys = cc->key_gen();
    auto element_params = SchemeletRlweMp::get_element_params(keys.secret_key, 0);
    const BigInteger Q = BigInteger(1) << 33;
    const BigInteger p = BigInteger(static_cast<uint64_t>(PLAINTEXT_MODULUS));
    const int64_t half_down = PLAINTEXT_MODULUS / 2 - 1;

    const std::vector<int64_t> input{-1, -half_down, -100, 0, 1, 100, half_down, -42};
    auto ciphertext = SchemeletRlweMp::encrypt_coeff(input, Q, p, keys.secret_key, element_params);
    auto output = SchemeletRlweMp::decrypt_coeff(ciphertext, Q, p, keys.secret_key, element_params, input.size());

    ASSERT_EQ(output.size(), input.size());
    for (size_t i = 0; i < input.size(); ++i)
        EXPECT_EQ(output[i], input[i]) << "coefficient " << i;
}

// A coefficient outside [0, Q) must be reduced modulo Q before it is encoded. Forming the negative
// residue as Q - |v| without reducing first underflows once |v| > Q, and the signed minimum was
// additionally negated as a signed value, which is undefined.
TEST_F(UTRLWEMP, OutOfRangeCoefficientsAreReduced) {
    ContextParams<CkksRnsContext> parameters;
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(1024);
    parameters.set_multiplicative_depth(1);
    parameters.set_scaling_mod_size(59);
    parameters.set_first_mod_size(60);
    parameters.set_batch_size(8);
    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);

    auto keys = cc->key_gen();
    auto element_params = SchemeletRlweMp::get_element_params(keys.secret_key, 0);
    const BigInteger p = BigInteger(static_cast<uint64_t>(PLAINTEXT_MODULUS));

    // Q divides 2^63, so the signed minimum reduces to zero; the other coefficients sit one step
    // past a multiple of Q and must come back as that step.
    const int64_t q = int64_t(1) << 33;
    const BigInteger Q = BigInteger(1) << 33;

    const std::vector<int64_t> input{
            std::numeric_limits<int64_t>::min(), -(q + 5), -(3 * q + 7), q + 5, 3 * q + 7, -q, q, 0};
    const std::vector<int64_t> expected{0, -5, -7, 5, 7, 0, 0, 0};

    std::vector<int64_t> output;
    ASSERT_NO_THROW(output = SchemeletRlweMp::decrypt_coeff(
                            SchemeletRlweMp::encrypt_coeff(input, Q, p, keys.secret_key, element_params), Q, p,
                            keys.secret_key, element_params, input.size()));
    ASSERT_EQ(output.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i)
        EXPECT_EQ(output[i], expected[i]) << "coefficient " << i << " (input " << input[i] << ")";
}
}  // namespace
