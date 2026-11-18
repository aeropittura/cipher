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
  Regression tests for the 128-bit CKKS scalar operations
  (https://github.com/openfheorg/openfhe-development/issues/1258 and
  https://openfhe.discourse.group/t/2362): eval_add/eval_sub/eval_mult with a double operand
  convert the operand to a 128-bit integer by shifting the 52-bit mantissa by a count derived
  from the operand's exponent. That count was applied unchecked, so tiny operands shifted by
  more than the width of the intermediate type and large operands overflowed it silently.
*/

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "cipher/cipher.h"

using namespace cipher;

#if CIPHER_NATIVE_INT == 128
namespace {
// The scalar conversion splits an operand into mantissa * 2^n1, keeps MANTISSA_BITS bits of the
// mantissa and shifts them by (SCALING_MOD_SIZE - MANTISSA_BITS + n1). Deriving the test
// magnitudes from these two constants keeps the exercised shift counts fixed if the context
// parameters are ever retuned.
constexpr uint32_t SCALING_MOD_SIZE = 90;
constexpr uint32_t MANTISSA_BITS = 52;

// Exponent offsets below the scaling factor. An operand of 2^-(SCALING_MOD_SIZE + offset) is
// shifted right by (MANTISSA_BITS - 1 + offset), so these cover shifts of 51, 52, 63, 64, 65,
// 127, 128 and 129 - either side of both the 64-bit and the 128-bit word boundary.
constexpr int32_t TINY_OFFSETS[] = {0, 1, 12, 13, 14, 76, 77, 78};

CryptoContext<RnsPoly> make_context(uint32_t multiplicative_depth, uint32_t first_mod_size_value) {
    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(multiplicative_depth);
    parameters.set_scaling_mod_size(SCALING_MOD_SIZE);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_technique(FIXEDMANUAL);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(1024);
    parameters.set_batch_size(8);
    parameters.set_ckks_data_type(COMPLEX);
    auto cc = make_crypto_context(parameters);
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    return cc;
}

// Exact polynomial comparison, reporting only the first mismatching coefficient. Comparing the
// elements with EXPECT_EQ would print every coefficient of every tower of both operands
// (hundreds of kilobytes) whenever a case fails.
::testing::AssertionResult elements_equal(const Ciphertext<RnsPoly>& actual, const Ciphertext<RnsPoly>& expected) {
    const auto& actual_elements = actual->get_elements();
    const auto& expected_elements = expected->get_elements();
    if (actual_elements.size() != expected_elements.size())
        return ::testing::AssertionFailure()
            << "element count " << actual_elements.size() << " != " << expected_elements.size();
    for (size_t i = 0; i < actual_elements.size(); ++i) {
        const auto& actual_towers = actual_elements[i].get_all_elements();
        const auto& expected_towers = expected_elements[i].get_all_elements();
        if (actual_towers.size() != expected_towers.size())
            return ::testing::AssertionFailure()
                << "element " << i << ": tower count " << actual_towers.size() << " != " << expected_towers.size();
        for (size_t j = 0; j < actual_towers.size(); ++j) {
            for (size_t k = 0; k < actual_towers[j].get_length(); ++k) {
                if (actual_towers[j][k] != expected_towers[j][k])
                    return ::testing::AssertionFailure()
                        << "element " << i << ", tower " << j << ", coefficient " << k << ": "
                        << actual_towers[j][k].to_string() << " != " << expected_towers[j][k].to_string();
            }
        }
    }
    return ::testing::AssertionSuccess();
}

std::complex<double> first_slot(const CryptoContext<RnsPoly>& cc, const PrivateKey<RnsPoly>& secret_key,
                                const Ciphertext<RnsPoly>& ciphertext) {
    Plaintext decoded;
    cc->decrypt(secret_key, ciphertext, &decoded);
    return decoded->get_ckks_packed_value()[0];
}

// Checks both components of a slot against an expected complex value, scaling the tolerance by
// the expected magnitude so that a large real part cannot mask a wrong imaginary part.
void expect_slot_near(const std::complex<double>& actual, const std::complex<double>& expected) {
    EXPECT_NEAR(actual.real(), expected.real(), 1e-6 * std::max(1.0, std::abs(expected.real())));
    EXPECT_NEAR(actual.imag(), expected.imag(), 1e-6 * std::max(1.0, std::abs(expected.imag())));
}

class UTCKKSRNS_SCALAR : public ::testing::Test {
  protected:
    void TearDown() override {
        ContextFactory<RnsPoly>::release_all_contexts();
    }
};

// Operands below the integer precision of the scaling factor must underflow to zero. Before the
// fix they shifted by an out-of-range count, and a negative operand additionally rounded to -1
// (an arithmetic shift floors), which showed up as a result near -2^-SCALING_MOD_SIZE instead of
// zero.
TEST_F(UTCKKSRNS_SCALAR, TinyOperands) {
    auto cc = make_context(2, SCALING_MOD_SIZE + 10);
    auto keys = cc->key_gen();
    auto plaintext = cc->make_ckks_packed_plaintext(std::vector<double>(8, 1.0));
    auto ciphertext = cc->encrypt(keys.public_key, plaintext);
    auto zero_product = cc->eval_mult(ciphertext, 0.0);

    // A ciphertext whose scale has already been raised by a multiplication. eval_add/eval_sub only
    // run the crt_mult loop over crt_pow_p when get_noise_scale_deg() > 1, so without this the modular
    // reduction of crt_pow_p would go untested.
    auto scaled = cc->eval_mult(ciphertext, 1.0);
    ASSERT_GT(scaled->get_noise_scale_deg(), 1u);

    const int32_t smallest_exponent = -static_cast<int32_t>(SCALING_MOD_SIZE);
    std::vector<double> magnitudes;
    for (int32_t offset : TINY_OFFSETS)
        magnitudes.push_back(std::ldexp(1.0, smallest_exponent - offset));
    magnitudes.push_back(std::numeric_limits<double>::denorm_min());

    for (double magnitude : magnitudes) {
        // Mirrors the conversion in get_element_for_eval_add_or_sub/get_element_for_eval_mult: the mantissa
        // is shifted right by (MANTISSA_BITS - SCALING_MOD_SIZE - exponent) bits. Reporting the
        // count makes it obvious which word boundary a failing case sits on.
        int32_t exponent = 0;
        std::frexp(magnitude, &exponent);
        const int32_t shift = static_cast<int32_t>(MANTISSA_BITS) - static_cast<int32_t>(SCALING_MOD_SIZE) - exponent;
        SCOPED_TRACE("right shift of " + std::to_string(shift) + " bits");

        for (double sign : {1.0, -1.0}) {
            double operand = sign * magnitude;
            SCOPED_TRACE(operand);
            auto product = cc->eval_mult(ciphertext, operand);
            std::complex<double> complex_operand(operand, -operand);
            if (magnitude < std::ldexp(1.0, smallest_exponent)) {
                // Exact polynomial comparisons detect errors far below CKKS's usual decryption
                // tolerance, including negative values rounding to -1.
                EXPECT_TRUE(elements_equal(product, zero_product));
                EXPECT_TRUE(elements_equal(cc->eval_add(ciphertext, operand), ciphertext));
                EXPECT_TRUE(elements_equal(cc->eval_sub(ciphertext, operand), ciphertext));
                EXPECT_TRUE(elements_equal(cc->eval_mult(ciphertext, complex_operand), zero_product));
                EXPECT_TRUE(elements_equal(cc->eval_add(ciphertext, complex_operand), ciphertext));
                EXPECT_TRUE(elements_equal(cc->eval_sub(ciphertext, complex_operand), ciphertext));

                // Same underflow, but through the crt_pow_p path taken at a raised scale.
                EXPECT_TRUE(elements_equal(cc->eval_add(scaled, operand), scaled));
                EXPECT_TRUE(elements_equal(cc->eval_sub(scaled, operand), scaled));
                EXPECT_TRUE(elements_equal(cc->eval_add(scaled, complex_operand), scaled));
                EXPECT_TRUE(elements_equal(cc->eval_sub(scaled, complex_operand), scaled));
            } else {
                // The smallest representable power of two must survive conversion.
                EXPECT_FALSE(elements_equal(product, zero_product));
                EXPECT_NEAR(first_slot(cc, keys.secret_key, product).real() / operand, 1.0, 1e-6);
            }
        }
    }
}

// Operands large enough that mantissa * 2^shift no longer fits into 128 bits used to wrap
// silently: at SCALING_MOD_SIZE 90 the product overflows from 2^37 upwards, so eval_mult by 1e12
// returned about -9.95e10. Each operand here is well within the ciphertext modulus, so the
// results must be exact to CKKS precision.
TEST_F(UTCKKSRNS_SCALAR, LargeOperands) {
    auto cc = make_context(3, SCALING_MOD_SIZE + 10);
    auto keys = cc->key_gen();
    auto plaintext = cc->make_ckks_packed_plaintext(std::vector<double>(8, 1.0));
    auto ciphertext = cc->encrypt(keys.public_key, plaintext);

    // A ciphertext at a raised scale, so that eval_add/eval_sub also run the crt_mult loop over
    // crt_pow_p that is only reached when get_noise_scale_deg() > 1.
    auto scaled = cc->eval_mult(ciphertext, 2.0);
    ASSERT_GT(scaled->get_noise_scale_deg(), 1u);

    // 2^37 is the first magnitude that overflowed; the rest bracket it on both sides.
    for (double magnitude : {std::ldexp(1.0, 20), std::ldexp(1.0, 36), std::ldexp(1.0, 37), std::ldexp(1.0, 38),
                             std::ldexp(1.0, 50), 1.0e12, 1.0e15}) {
        for (double sign : {1.0, -1.0}) {
            double operand = sign * magnitude;
            SCOPED_TRACE(operand);

            auto product = cc->eval_mult(ciphertext, operand);
            cc->rescale_in_place(product);
            expect_slot_near(first_slot(cc, keys.secret_key, product), {operand, 0.0});

            expect_slot_near(first_slot(cc, keys.secret_key, cc->eval_add(ciphertext, operand)), {1.0 + operand, 0.0});
            expect_slot_near(first_slot(cc, keys.secret_key, cc->eval_sub(ciphertext, operand)), {1.0 - operand, 0.0});

            // The ciphertext holds 2.0 at twice the scale; the constant has to be raised to the
            // same scale before it is added.
            expect_slot_near(first_slot(cc, keys.secret_key, cc->eval_add(scaled, operand)), {2.0 + operand, 0.0});
            expect_slot_near(first_slot(cc, keys.secret_key, cc->eval_sub(scaled, operand)), {2.0 - operand, 0.0});

            // Complex operands whose real and imaginary parts are both large and distinct, so a
            // component that is dropped, swapped or wrongly signed is visible in the result.
            const std::complex<double> complex_operand(operand, -0.5 * operand);

            auto complex_product = cc->eval_mult(ciphertext, complex_operand);
            cc->rescale_in_place(complex_product);
            expect_slot_near(first_slot(cc, keys.secret_key, complex_product), complex_operand);

            expect_slot_near(first_slot(cc, keys.secret_key, cc->eval_add(ciphertext, complex_operand)),
                             1.0 + complex_operand);
            expect_slot_near(first_slot(cc, keys.secret_key, cc->eval_sub(ciphertext, complex_operand)),
                             1.0 - complex_operand);
            expect_slot_near(first_slot(cc, keys.secret_key, cc->eval_add(scaled, complex_operand)),
                             2.0 + complex_operand);
            expect_slot_near(first_slot(cc, keys.secret_key, cc->eval_sub(scaled, complex_operand)),
                             2.0 - complex_operand);
        }
    }
}

// Operands outside the representable range at either end produce meaningless plaintexts, but
// they must not shift by an out-of-range count on the way there - the reported failure was a
// shift of 1035 bits for a 128-bit type, reached both by denorm_min and by 1e300. The assertion
// here is only that the operations complete; a build with -fsanitize=shift (or UBSan) is what
// turns this into a check of the shift counts themselves.
TEST_F(UTCKKSRNS_SCALAR, UnrepresentableOperandsDoNotShiftOutOfRange) {
    auto cc = make_context(1, SCALING_MOD_SIZE);
    auto keys = cc->key_gen();
    auto plaintext = cc->make_ckks_packed_plaintext(std::vector<double>(8, 1.0));
    auto ciphertext = cc->encrypt(keys.public_key, plaintext);

    for (double magnitude : {1.0e300, std::numeric_limits<double>::max(), std::numeric_limits<double>::denorm_min()}) {
        for (double sign : {1.0, -1.0}) {
            double operand = sign * magnitude;
            SCOPED_TRACE(operand);
            EXPECT_NO_THROW(cc->eval_mult(ciphertext, operand));
            EXPECT_NO_THROW(cc->eval_add(ciphertext, operand));
            EXPECT_NO_THROW(cc->eval_sub(ciphertext, operand));
        }
    }
}
}  // namespace
#endif
