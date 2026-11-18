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
  Regression test for constants added to degree-2 ciphertexts with the FIXED* scaling techniques.

  The rescale divides by the actual prime q_l of the dropped tower, not by the scaling factor Delta, so a
  constant encoded as c * Delta^2 comes out as c * Delta / q_l. The residual (about 2^-33 for 50-bit
  primes) is a constant shift of T_2 = 2x^2 - 1 that the squaring chain of the Paterson-Stockmeyer giant
  steps amplifies by roughly the square of the degree. FIXEDAUTO adds every constant of the Chebyshev
  recursion before the automatic rescale and lost about 4 bits of a degree-119 evaluation compared with
  FIXEDMANUAL (2^-24 instead of 2^-28 at ring dimension 2^12 with 50-bit primes).
*/
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "fhe/support/test_utils.h"
#include "cipher/config.h"
#include "cipher/fhe/context.h"
#include "cipher/fhe/context_gen.h"
#include "gtest/gtest.h"
#include "cipher/math/chebyshev.h"
#include "cipher/fhe/ckks/context_gen.h"

using namespace cipher;

#if CIPHER_NATIVE_INT != 128
namespace {
// f(x) = c_0 / 2 + sum_{k >= 1} c_k T_k(x), the convention of eval_chebyshev_coefficients
long double eval_chebyshev_series_exact(const std::vector<double>& coefficients, long double x) {
    long double b1 = 0;
    long double b2 = 0;
    for (size_t k = coefficients.size() - 1; k >= 1; --k) {
        long double b0 = 2 * x * b1 - b2 + coefficients[k];
        b2 = b1;
        b1 = b0;
    }
    return x * b1 - b2 + coefficients[0] / 2;
}
}  // namespace
#endif

TEST(UTCKKSRNS_FIXED_SCALING, DegreeTwoConstantsChebyshev119) {
#if CIPHER_NATIVE_INT == 128
    GTEST_SKIP() << "precision thresholds are calibrated for the 64-bit build";
#else
    const uint32_t ring_dim = 1 << 12;
    const uint32_t slots = ring_dim / 2;
    const uint32_t degree = 119;
    const double K = 512;

    // the interpolant of the uniform-secret bootstrapping table before the double-angle iterations
    std::vector<double> coefficients = eval_chebyshev_coefficients(
            [K](double x) { return std::pow(2 * M_PI, -1.0 / 64) * std::cos(2 * M_PI * K * x / 64 - M_PI / 128); }, -1,
            1, degree);

    std::mt19937_64 gen(12345);
    std::uniform_real_distribution<double> uniform(-1.0, 1.0);
    std::vector<double> input(slots);
    for (auto& x : input)
        x = uniform(gen);

    for (auto scal_tech : {FIXEDMANUAL, FIXEDAUTO}) {
        ContextParams<CkksRnsContext> parameters;
        parameters.set_security_level(HEStd_NotSet);
        parameters.set_ring_dim(ring_dim);
        parameters.set_scaling_mod_size(50);
        parameters.set_first_mod_size(60);
        parameters.set_scaling_technique(scal_tech);
        parameters.set_multiplicative_depth(8);
        parameters.set_secret_key_dist(UNIFORM_TERNARY);

        auto cc = make_crypto_context(parameters);
        cc->enable(PKE);
        cc->enable(KEYSWITCH);
        cc->enable(LEVELEDSHE);
        cc->enable(ADVANCEDSHE);
        auto key_pair = cc->key_gen();
        cc->eval_mult_key_gen(key_pair.secret_key);

        auto ciphertext = cc->encrypt(key_pair.public_key, cc->make_ckks_packed_plaintext(input));
        auto result = cc->eval_chebyshev_series(ciphertext, coefficients, -1, 1);

        Plaintext decrypted;
        cc->decrypt(key_pair.secret_key, result, &decrypted);
        decrypted->set_length(slots);
        const auto& values = decrypted->get_real_packed_value();

        double max_error = 0;
        for (uint32_t i = 0; i < slots; ++i)
            max_error = std::max(
                    max_error,
                    static_cast<double>(std::fabs(values[i] - eval_chebyshev_series_exact(coefficients, input[i]))));
        const double precision_bits_value = -std::log2(max_error);

        // both techniques reach about 28 bits; FIXEDAUTO gave about 24 bits before the constants were fixed
        EXPECT_GE(precision_bits_value, 26.0) << "degree-" << degree << " Chebyshev series with scaling technique "
                                              << scal_tech << " lost precision: 2^-" << precision_bits_value;
    }
#endif
}
