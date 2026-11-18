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

#include <cmath>
#include <complex>
#include <memory>
#include <vector>

#include "gtest/gtest.h"
#include "cipher/ring/field2n.h"
#include "cipher/math/dft.h"
#include "cipher/math/number_theory.h"
#include "cipher/util/debug.h"

using namespace cipher;

// ---------------  TESTING METHODS OF FIELD2N ---------------

// TEST FOR GETTER FOR FORMAT
TEST(UTField2n, get_format) {
    CIPHER_DEBUG_FLAG(false);

    CIPHER_DEBUG("Step 1");
    Field2n test(2, Format::COEFFICIENT, true);
    CIPHER_DEBUG("Step 2");
    EXPECT_EQ(Format::COEFFICIENT, test.get_format()) << "Failed getter" << std::endl;
}

// TEST FOR INVERSE OF FIELD ELEMENT
TEST(UTField2n, inverse) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n test(2, Format::EVALUATION, true);
    test.at(0) = std::complex<double>(2, 1);
    test.at(1) = std::complex<double>(-4, -2);
    CIPHER_DEBUG("Step 2");
    Field2n inverse_value(2, Format::EVALUATION, true);
    inverse_value.at(0) = std::complex<double>(0.4, -0.2);
    inverse_value.at(1) = std::complex<double>(-0.2, 0.1);
    CIPHER_DEBUG("Step 3");
    EXPECT_EQ(inverse_value, test.inverse());
}

// TEST FOR ADDITION OPERATION
TEST(UTField2n, plus) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n a(2, Format::EVALUATION, true);
    a.at(0) = std::complex<double>(2, 1);
    a.at(1) = std::complex<double>(-4, 2);
    CIPHER_DEBUG("Step 2");
    Field2n b(2, Format::EVALUATION, true);
    b.at(0) = std::complex<double>(3, -0.1);
    b.at(1) = std::complex<double>(-4, 3.2);
    CIPHER_DEBUG("Step 3");
    Field2n c(2, Format::EVALUATION, true);
    c.at(0) = std::complex<double>(5, 0.9);
    c.at(1) = std::complex<double>(-8, 5.2);
    EXPECT_EQ(c, a.plus_impl(b));
}

// TEST FOR SCALAR ADDITION
TEST(UTField2n, scalar_plus) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n a(2, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(2, 0);
    a.at(1) = std::complex<double>(-4, 0);
    CIPHER_DEBUG("Step 2");
    double b = 3.2;
    CIPHER_DEBUG("Step 3");
    Field2n c(2, Format::COEFFICIENT, true);
    c.at(0) = std::complex<double>(5.2, 0);
    c.at(1) = std::complex<double>(-4, 0);
    EXPECT_EQ(c, a.plus_impl(b));
}

// TEST FOR SUBSTRACTION OPERATION
TEST(UTField2n, minus) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n a(2, Format::EVALUATION, true);
    a.at(0) = std::complex<double>(2, 1);
    a.at(1) = std::complex<double>(-4, 2);
    CIPHER_DEBUG("Step 2");
    Field2n b(2, Format::EVALUATION, true);
    b.at(0) = std::complex<double>(3, -0.1);
    b.at(1) = std::complex<double>(-4, 3.2);
    CIPHER_DEBUG("Step 3");
    Field2n c(2, Format::EVALUATION, true);
    c.at(0) = std::complex<double>(-1, 1.1);
    c.at(1) = std::complex<double>(0, -1.2);

    Field2n d = a.minus_impl(b);
    for (int i = 0; i < 2; i++) {
        EXPECT_LE(std::fabs(d.at(i).real() - c.at(i).real()), std::fabs(c.at(i).real()) * 0.00001);
        EXPECT_LE(std::fabs(d.at(i).imag() - c.at(i).imag()), std::fabs(c.at(i).imag()) * 0.00001);
    }
}

// TEST FOR MULTIPLICATION OPERATION
TEST(UTField2n, times) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n a(2, Format::EVALUATION, true);
    a.at(0) = std::complex<double>(4, 3);
    a.at(1) = std::complex<double>(6, -3);
    CIPHER_DEBUG("Step 2");
    Field2n b(2, Format::EVALUATION, true);
    b.at(0) = std::complex<double>(4, -3);
    b.at(1) = std::complex<double>(4, -2.8);
    CIPHER_DEBUG("Step 3");
    Field2n c(2, Format::EVALUATION, true);
    c.at(0) = std::complex<double>(25, 0);
    c.at(1) = std::complex<double>(15.6, -28.8);
    CIPHER_DEBUG("Step 4");
    Field2n d = a.Times(b);
    for (int i = 0; i < 2; i++) {
        EXPECT_LE(std::fabs(d.at(i).real() - c.at(i).real()), std::fabs(c.at(i).real()) * 0.00001);
        EXPECT_LE(std::fabs(d.at(i).imag() - c.at(i).imag()), std::fabs(c.at(i).imag()) * 0.00001);
    }
}

// TEST FOR MULTIPLICATION OPERATION WITH SWITCH FORMAT
TEST(UTField2n, times_with_switch) {
    DiscreteFourierTransform::pre_compute_table(8);
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(1, 0);
    a.at(1) = std::complex<double>(1, 0);
    a.at(2) = std::complex<double>(1, 0);
    a.at(3) = std::complex<double>(1, 0);
    CIPHER_DEBUG("Step 2");
    Field2n b(4, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(1, 0);
    b.at(1) = std::complex<double>(0, 0);
    b.at(2) = std::complex<double>(1, 0);
    b.at(3) = std::complex<double>(0, 0);
    CIPHER_DEBUG("Step 3");
    Field2n c(4, Format::COEFFICIENT, true);
    c.at(0) = std::complex<double>(0, 0);
    c.at(1) = std::complex<double>(0, 0);
    c.at(2) = std::complex<double>(2, 0);
    c.at(3) = std::complex<double>(2, 0);
    CIPHER_DEBUG("Step 4");
    a.switch_format();
    b.switch_format();
    Field2n d = a.Times(b);
    d.switch_format();
    for (int i = 0; i < 4; i++) {
        EXPECT_LE(std::fabs(d.at(i).real() - c.at(i).real()), std::pow(10, -12));
    }
    DiscreteFourierTransform::reset();
}

// TEST FOR SHIFT RIGHT OPERATION
TEST(UTField2n, shift_right) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(4, 0);
    a.at(1) = std::complex<double>(3, 0);
    a.at(2) = std::complex<double>(2, 0);
    a.at(3) = std::complex<double>(1, 0);
    CIPHER_DEBUG("Step 2");
    Field2n b(4, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(-1, 0);
    b.at(1) = std::complex<double>(4, 0);
    b.at(2) = std::complex<double>(3, 0);
    b.at(3) = std::complex<double>(2, 0);
    CIPHER_DEBUG("Step 3");
    EXPECT_EQ(b, a.shift_right());
}

// TEST FOR TRANSPOSE OPERATION
TEST(UTField2n, transpose) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(4, 0);
    a.at(1) = std::complex<double>(3, 0);
    a.at(2) = std::complex<double>(2, 0);
    a.at(3) = std::complex<double>(1, 0);
    CIPHER_DEBUG("Step 2");
    Field2n b(4, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(4, 0);
    b.at(1) = std::complex<double>(-1, 0);
    b.at(2) = std::complex<double>(-2, 0);
    b.at(3) = std::complex<double>(-3, 0);
    CIPHER_DEBUG("Step 3");
    EXPECT_EQ(b, a.transposed());
}

// TEST FOR TRANSPOSE OPERATION
TEST(UTField2n, transpose_eval) {
    DiscreteFourierTransform::pre_compute_table(8);
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(4, 0);
    a.at(1) = std::complex<double>(3, 0);
    a.at(2) = std::complex<double>(2, 0);
    a.at(3) = std::complex<double>(1, 0);
    // Convert to Format::EVALUATION format
    a.switch_format();
    a = a.transposed();
    // back to Format::COEFFICIENT representation
    a.switch_format();
    CIPHER_DEBUG("Step 2");
    Field2n b(4, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(4, 0);
    b.at(1) = std::complex<double>(-1, 0);
    b.at(2) = std::complex<double>(-2, 0);
    b.at(3) = std::complex<double>(-3, 0);
    CIPHER_DEBUG("Step 3");
    for (int i = 0; i < 4; i++) {
        EXPECT_LE(std::fabs(b.at(i).real() - a.at(i).real()), std::fabs(b.at(i).real()) * 0.0001);
    }
    DiscreteFourierTransform::reset();
}

// TEST FOR AUTOMORPHISM OPERATION
TEST(UTField2n, automorphism) {
    DiscreteFourierTransform::pre_compute_table(8);
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(1, 0);
    a.at(1) = std::complex<double>(2, 0);
    a.at(2) = std::complex<double>(3, 0);
    a.at(3) = std::complex<double>(4, 0);
    a.switch_format();
    a = a.automorphism_transform(3);
    a.switch_format();
    CIPHER_DEBUG("Step 2");
    Field2n b(4, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(1, 0);
    b.at(1) = std::complex<double>(4, 0);
    b.at(2) = std::complex<double>(-3, 0);
    b.at(3) = std::complex<double>(2, 0);
    CIPHER_DEBUG("Step 3");
    for (int i = 0; i < 4; i++) {
        EXPECT_LE(std::fabs(b.at(i).real() - a.at(i).real()), std::fabs(b.at(i).real()) * 0.0001);
    }
    DiscreteFourierTransform::reset();
}

// TEST FOR EXTRACT ODD OPERATION
TEST(UTField2n, extract_odd) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(4, 0);
    a.at(1) = std::complex<double>(3, 0);
    a.at(2) = std::complex<double>(2, 0);
    a.at(3) = std::complex<double>(1, 0);
    CIPHER_DEBUG("Step 2");
    Field2n b(2, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(3, 0);
    b.at(1) = std::complex<double>(1, 0);
    CIPHER_DEBUG("Step 3");
    EXPECT_EQ(b, a.extract_odd());
}

// TEST FOR EXTRACT EVEN OPERATION
TEST(UTField2n, extract_even) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(4, 0);
    a.at(1) = std::complex<double>(3, 0);
    a.at(2) = std::complex<double>(2, 0);
    a.at(3) = std::complex<double>(1, 0);
    CIPHER_DEBUG("Step 2");
    Field2n b(2, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(4, 0);
    b.at(1) = std::complex<double>(2, 0);
    CIPHER_DEBUG("Step 3");
    EXPECT_EQ(b, a.extract_even());
}

// TEST FOR PERMUTE OPERATION
TEST(UTField2n, permute) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(1, 0);
    a.at(1) = std::complex<double>(2, 0);
    a.at(2) = std::complex<double>(3, 0);
    a.at(3) = std::complex<double>(4, 0);
    CIPHER_DEBUG("Step 2");
    Field2n b(4, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(1, 0);
    b.at(1) = std::complex<double>(3, 0);
    b.at(2) = std::complex<double>(2, 0);
    b.at(3) = std::complex<double>(4, 0);
    CIPHER_DEBUG("Step 3");
    EXPECT_EQ(b, a.permute());
}

// TEST FOR INVERSE PERMUTE OPERATION
TEST(UTField2n, inverse_permute) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n a(4, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(1, 0);
    a.at(1) = std::complex<double>(3, 0);
    a.at(2) = std::complex<double>(2, 0);
    a.at(3) = std::complex<double>(4, 0);
    CIPHER_DEBUG("Step 2");
    Field2n b(4, Format::COEFFICIENT, true);
    b.at(0) = std::complex<double>(1, 0);
    b.at(1) = std::complex<double>(2, 0);
    b.at(2) = std::complex<double>(3, 0);
    b.at(3) = std::complex<double>(4, 0);
    CIPHER_DEBUG("Step 3");
    EXPECT_EQ(b, a.inverse_permute());
}

// TEST FOR SCALAR MULT OPERATION
TEST(UTField2n, scalar_mult) {
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n a(4, Format::EVALUATION, true);
    a.at(0) = std::complex<double>(1, -1);
    a.at(1) = std::complex<double>(3, -2);
    a.at(2) = std::complex<double>(2, -3);
    a.at(3) = std::complex<double>(4, -4);
    CIPHER_DEBUG("Step 2");
    Field2n b(4, Format::EVALUATION, true);
    b.at(0) = std::complex<double>(3, -3);
    b.at(1) = std::complex<double>(9, -6);
    b.at(2) = std::complex<double>(6, -9);
    b.at(3) = std::complex<double>(12, -12);
    CIPHER_DEBUG("Step 3");
    EXPECT_EQ(b, a.scalar_mult(3));
}

// TEST FOR Format::COEFFICIENT TO Format::EVALUATION FORMAT CHANGE
TEST(UTField2n, COEFFICIENT_EVALUATION) {
    DiscreteFourierTransform::pre_compute_table(16);
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n a(8, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(4, 0);
    a.at(1) = std::complex<double>(5, 0);
    a.at(2) = std::complex<double>(5, 0);
    a.at(3) = std::complex<double>(4.2, 0);
    a.at(4) = std::complex<double>(5, 0);
    a.at(5) = std::complex<double>(7.1, 0);
    a.at(6) = std::complex<double>(6, 0);
    a.at(7) = std::complex<double>(3, 0);
    CIPHER_DEBUG("Step 2");
    Field2n b(8, Format::EVALUATION, true);
    b.at(0) = std::complex<double>(4.03087, 26.2795);
    b.at(1) = std::complex<double>(8.15172, 5.84489);
    b.at(2) = std::complex<double>(1.26249, 0.288539);
    b.at(3) = std::complex<double>(2.55492, 0.723132);
    b.at(4) = std::complex<double>(2.55492, -0.723132);
    b.at(5) = std::complex<double>(1.26249, -0.288539);
    b.at(6) = std::complex<double>(8.15172, -5.84489);
    b.at(7) = std::complex<double>(4.03087, -26.2795);
    CIPHER_DEBUG("Step 3");
    a.switch_format();
    for (int i = 0; i < 8; i++) {
        EXPECT_LE(std::fabs(a.at(i).real() - b.at(i).real()), std::fabs(b.at(i).real()) * 0.0001);
        EXPECT_LE(std::fabs(a.at(i).imag() - b.at(i).imag()), std::fabs(b.at(i).imag()) * 0.0001);
    }
    DiscreteFourierTransform::reset();
}

// TEST FOR Format::EVALUATION TO Format::COEFFICIENT FORMAT CHANGE
TEST(UTField2n, EVALUATION_COEFFICIENT) {
    DiscreteFourierTransform::pre_compute_table(16);
    CIPHER_DEBUG_FLAG(false);
    CIPHER_DEBUG("Step 1");
    Field2n b(8, Format::EVALUATION, true);
    b.at(0) = std::complex<double>(4.03087, 26.2795);
    b.at(1) = std::complex<double>(8.15172, 5.84489);
    b.at(2) = std::complex<double>(1.26249, 0.288539);
    b.at(3) = std::complex<double>(2.55492, 0.723132);
    b.at(4) = std::complex<double>(2.55492, -0.723132);
    b.at(5) = std::complex<double>(1.26249, -0.288539);
    b.at(6) = std::complex<double>(8.15172, -5.84489);
    b.at(7) = std::complex<double>(4.03087, -26.2795);
    CIPHER_DEBUG("Step 2");
    Field2n a(8, Format::COEFFICIENT, true);
    a.at(0) = std::complex<double>(4, 0);
    a.at(1) = std::complex<double>(5, 0);
    a.at(2) = std::complex<double>(5, 0);
    a.at(3) = std::complex<double>(4.2, 0);
    a.at(4) = std::complex<double>(5, 0);
    a.at(5) = std::complex<double>(7.1, 0);
    a.at(6) = std::complex<double>(6, 0);
    a.at(7) = std::complex<double>(3, 0);

    CIPHER_DEBUG("Step 3");
    b.switch_format();
    for (int i = 0; i < 8; i++) {
        EXPECT_LE(std::fabs(a.at(i).real() - b.at(i).real()), std::fabs(a.at(i).real()) * 0.0001);
    }
    DiscreteFourierTransform::reset();
}

TEST(UTField2n, poly_large_centered_coefficients) {
    // Issue #1253: +2^63 is below q/2 and must not be narrowed to int64_t.
    const BigInteger q("18446744073709551697");
    auto params = std::make_shared<PolyParams>(8, q, BigInteger("15713903524825792581"));
    Poly poly(params, Format::COEFFICIENT, true);
    const BigInteger magnitude("9223372036854775808");  // 2^63, one above INT64_MAX
    poly[0] = magnitude;
    poly[1] = q - magnitude;
    // q / 2 is the largest positive centered representative; one more is the most negative one.
    poly[2] = q / BigInteger(2);
    poly[3] = poly[2] + BigInteger(1);
    Field2n field(poly);
    EXPECT_EQ(field.get_format(), Format::COEFFICIENT);
    ASSERT_EQ(field.size(), 4u);

    const double exact = std::ldexp(1.0, 63);
    EXPECT_DOUBLE_EQ(field[0].real(), exact);
    EXPECT_DOUBLE_EQ(field[1].real(), -exact);
    // q / 2 is 2^63 + 40, and the ulp at this magnitude is 2048, so the nearest double is 2^63
    // itself: only the sign of these two distinguishes the fixed code from the broken one.
    EXPECT_DOUBLE_EQ(field[2].real(), exact);
    EXPECT_DOUBLE_EQ(field[3].real(), -exact);
    for (size_t i = 0; i < field.size(); ++i)
        EXPECT_DOUBLE_EQ(field[i].imag(), 0.0);
}

TEST(UTField2n, poly_magnitudes_beyond_uint64) {
    const BigInteger q = first_prime<BigInteger>(100, 8);
    auto params = std::make_shared<PolyParams>(8, q, root_of_unity<BigInteger>(8, q));
    Poly poly(params, Format::COEFFICIENT, true);
    const BigInteger magnitude = BigInteger(1) << 80;
    poly[0] = magnitude;
    poly[1] = q - magnitude;
    poly[2] = BigInteger(1);
    poly[3] = q - BigInteger(1);
    Field2n field(poly);
    EXPECT_DOUBLE_EQ(field[0].real(), std::ldexp(1.0, 80));
    EXPECT_DOUBLE_EQ(field[1].real(), -std::ldexp(1.0, 80));
    EXPECT_DOUBLE_EQ(field[2].real(), 1.0);
    EXPECT_DOUBLE_EQ(field[3].real(), -1.0);
}

TEST(UTField2n, native_and_dcrt_centered_coefficients) {
    // Also cover large native magnitudes when native integers are 128 bits wide.
#if CIPHER_NATIVE_INT == 128
    const NativeInteger q = first_prime<NativeInteger>(100, 8);
    const NativeInteger magnitude = NativeInteger(1) << 80;
    const double expected = std::ldexp(1.0, 80);
#else
    const NativeInteger q(97);
    const NativeInteger magnitude(48);
    const double expected = 48.0;
#endif
    const NativeInteger root = root_of_unity<NativeInteger>(8, q);
    auto params = std::make_shared<NativePolyParams>(8, q, root);
    NativePoly poly(params, Format::COEFFICIENT, true);
    poly[0] = magnitude;
    poly[1] = q - magnitude;
    poly[2] = NativeInteger(0);
    poly[3] = q - NativeInteger(1);
    Field2n native_field(poly);
    EXPECT_EQ(native_field.get_format(), Format::COEFFICIENT);
    ASSERT_EQ(native_field.size(), 4u);
    EXPECT_DOUBLE_EQ(native_field[0].real(), expected);
    EXPECT_DOUBLE_EQ(native_field[1].real(), -expected);
    EXPECT_DOUBLE_EQ(native_field[2].real(), 0.0);
    EXPECT_DOUBLE_EQ(native_field[3].real(), -1.0);

    auto crt_params =
            std::make_shared<RnsParams<BigInteger>>(8, std::vector<NativeInteger>{q}, std::vector<NativeInteger>{root});
    RnsPoly crt(crt_params, Format::COEFFICIENT, true);
    crt.set_element_at_index(0, poly);
    Field2n crt_field(crt);
    // Field2n has no operator== of its own, so this compares the std::vector base; check the
    // format separately rather than assume it came along.
    EXPECT_EQ(crt_field.get_format(), Format::COEFFICIENT);
    EXPECT_EQ(crt_field, native_field);
}

TEST(UTField2n, dcrt_coefficients_exceeding_first_tower) {
    // A coefficient larger than the first tower cannot be recovered from that tower alone, so the
    // constructor must fall back to CRT interpolation instead of reporting the tower-0 residue.
    auto crt_params = std::make_shared<RnsParams<BigInteger>>(8, 2, 50);
    const BigInteger Q = crt_params->get_modulus();
    const NativeInteger q0 = crt_params->get_params()[0]->get_modulus();
    ASSERT_GT(Q, BigInteger(q0));

    // Well above q0 yet well below Q / 2, so the centered representative is this value itself.
    const BigInteger magnitude = BigInteger(q0) * BigInteger(3) + BigInteger(7);
    ASSERT_LT(magnitude, Q / BigInteger(2));

    // Root of unity is set to ONE, as crt_interpolate() itself does: this polynomial is never
    // transformed, so computing a real root would be expensive and pointless.
    auto params = std::make_shared<PolyParams>(8, Q, BigInteger(1));
    Poly big(params, Format::COEFFICIENT, true);
    big[0] = magnitude;
    big[1] = Q - magnitude;
    big[2] = BigInteger(5);
    big[3] = Q - BigInteger(5);

    RnsPoly crt(big, crt_params);
    crt.set_format(Format::COEFFICIENT);
    Field2n field(crt);

    // The same polynomial through the (already correct) Poly path is the reference.
    Field2n reference(big);
    EXPECT_EQ(field.get_format(), Format::COEFFICIENT);
    ASSERT_EQ(field.size(), reference.size());
    for (size_t i = 0; i < field.size(); ++i)
        EXPECT_DOUBLE_EQ(field[i].real(), reference[i].real()) << "coefficient " << i;
    EXPECT_GT(field[0].real(), q0.convert_to_double());
    EXPECT_LT(field[1].real(), -q0.convert_to_double());
}

TEST(UTField2n, poly_uint64_boundary_magnitudes) {
    // Magnitudes straddling the 64-bit boundary, where the narrowing conversion of issue #1253
    // used to lose the sign or the value.
    const BigInteger q = first_prime<BigInteger>(100, 8);
    auto params = std::make_shared<PolyParams>(8, q, root_of_unity<BigInteger>(8, q));
    Poly poly(params, Format::COEFFICIENT, true);
    poly[0] = BigInteger(1) << 63;                    // one above INT64_MAX
    poly[1] = (BigInteger(1) << 64) - BigInteger(1);  // largest value a uint64_t holds
    poly[2] = BigInteger(1) << 64;                    // one above that
    poly[3] = q - (BigInteger(1) << 64);
    Field2n field(poly);
    EXPECT_DOUBLE_EQ(field[0].real(), std::ldexp(1.0, 63));
    EXPECT_DOUBLE_EQ(field[1].real(), std::ldexp(1.0, 64));  // 2^64 - 1 rounds to 2^64
    EXPECT_DOUBLE_EQ(field[2].real(), std::ldexp(1.0, 64));
    EXPECT_DOUBLE_EQ(field[3].real(), -std::ldexp(1.0, 64));
}

TEST(UTField2n, dcrt_without_towers_throws) {
    // get_element_at_index(0) is unchecked, so an empty RnsPoly must be rejected, not indexed.
    RnsPoly empty;
    empty.set_format(Format::COEFFICIENT);
    ASSERT_EQ(empty.get_num_of_elements(), 0u);
    EXPECT_THROW(Field2n{empty}, CipherException);
}
