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
#include <cstdint>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <string>

#include "gtest/gtest.h"
#include "cipher/ring/backend.h"
#include "cipher/math/distributions.h"
#include "cipher/math/matrix.h"
#include "cipher/math/matrix_strassen_impl.h"
#include "cipher/math/number_theory.h"
#include "core/test_defs.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/utilities.h"

using namespace cipher;

template <typename Element>
static std::function<Element()> secure_il2n_alloc() {
    uint32_t m = 2048;
    typename Element::Integer secure_modulus("8590983169");
    typename Element::Integer secure_root_of_unity("4810681236");
    return Element::allocator(std::make_shared<typename Element::Params>(m, secure_modulus, secure_root_of_unity),
                              Format::EVALUATION);
}

template <typename Element>
static std::function<Element()> fast_il2n_alloc() {
    uint32_t m = 16;
    typename Element::Integer modulus("67108913");
    typename Element::Integer root_of_unity_value("61564");
    return Element::allocator(std::make_shared<typename Element::Params>(m, modulus, root_of_unity_value),
                              Format::EVALUATION);
}

template <typename Element>
static std::function<Element()> fast_uniform_il2n_alloc() {
    uint32_t m = 16;
    typename Element::Integer modulus("67108913");
    typename Element::Integer root_of_unity_value("61564");
    return Element::make_discrete_uniform_allocator(
            std::make_shared<typename Element::Params>(m, modulus, root_of_unity_value), Format::EVALUATION);
}

TEST(UTMatrix, serializer) {
    Matrix<int32_t> m([]() { return 0; }, 3, 5);
}

TEST(UTMatrix, convert_to_int32_checks_centered_range) {
    constexpr uint64_t int32_max_value = static_cast<uint64_t>(std::numeric_limits<int32_t>::max());
    constexpr uint64_t int32_min_magnitude = int32_max_value + 1;
    const BigInteger modulus(2 * (int32_min_magnitude + 1) + 1);
    Matrix<BigInteger> input([]() { return BigInteger(0); }, 1, 1);

    input(0, 0) = BigInteger(int32_max_value);
    EXPECT_EQ(std::numeric_limits<int32_t>::max(), convert_to_int32(input, modulus)(0, 0));

    input(0, 0) = BigInteger(int32_min_magnitude);
    EXPECT_THROW(convert_to_int32(input, modulus), CipherException);

    input(0, 0) = modulus - BigInteger(int32_min_magnitude);
    EXPECT_EQ(std::numeric_limits<int32_t>::min(), convert_to_int32(input, modulus)(0, 0));

    input(0, 0) = modulus - BigInteger(int32_min_magnitude + 1);
    EXPECT_THROW(convert_to_int32(input, modulus), CipherException);
}

TEST(UTMatrix, convert_to_int32_checks_all_matrix_overloads) {
    constexpr uint64_t int32_min_magnitude = static_cast<uint64_t>(std::numeric_limits<int32_t>::max()) + 1;
    const BigInteger modulus(2 * (int32_min_magnitude + 1) + 1);
    const BigInteger unrepresentable(int32_min_magnitude);
    auto vector_allocator = [&modulus]() {
        return BigVector(1, modulus);
    };

    Matrix<BigVector> vector_input(vector_allocator, 1, 1);
    vector_input(0, 0).at(0) = unrepresentable;
    EXPECT_THROW(convert_to_int32(vector_input, modulus), CipherException);

    MatrixStrassen<BigInteger> strassen_input([]() { return BigInteger(0); }, 1, 1);
    strassen_input(0, 0) = unrepresentable;
    EXPECT_THROW(convert_to_int32(strassen_input, modulus), CipherException);

    MatrixStrassen<BigVector> strassen_vector_input(vector_allocator, 1, 1);
    strassen_vector_input(0, 0).at(0) = unrepresentable;
    EXPECT_THROW(convert_to_int32(strassen_vector_input, modulus), CipherException);
}

// additional coverage: values that must still convert, on every overload, plus the
// modulus from the bug report (q = 2^32 + 15, value = 2^31)
TEST(UTMatrix, convert_to_int32_representable_values) {
    constexpr int32_t int32_max = std::numeric_limits<int32_t>::max();
    constexpr int32_t int32_min = std::numeric_limits<int32_t>::min();
    const BigInteger modulus(static_cast<uint64_t>(4294967311ULL));
    const BigInteger minus_one(modulus - BigInteger(1));
    const BigInteger lowest(modulus - BigInteger(static_cast<uint64_t>(int32_max) + 1));

    Matrix<BigInteger> input([]() { return BigInteger(0); }, 2, 2);
    input(0, 0) = BigInteger(0);
    input(0, 1) = BigInteger(static_cast<uint64_t>(int32_max));
    input(1, 0) = minus_one;
    input(1, 1) = lowest;
    Matrix<int32_t> out = convert_to_int32(input, modulus);
    EXPECT_EQ(0, out(0, 0));
    EXPECT_EQ(int32_max, out(0, 1));
    EXPECT_EQ(-1, out(1, 0));
    EXPECT_EQ(int32_min, out(1, 1));

    // the value from the bug report is not representable and must throw, not wrap to INT32_MIN
    input(0, 0) = BigInteger(static_cast<uint64_t>(int32_max) + 1);
    EXPECT_THROW(convert_to_int32(input, modulus), CipherException);

    // the largest positive representative of this modulus, 2^31 + 7, used to wrap to -2147483641
    input(0, 0) = modulus / BigInteger(2);
    EXPECT_THROW(convert_to_int32(input, modulus), CipherException);

    auto vector_allocator = [&modulus]() {
        return BigVector(1, modulus);
    };
    Matrix<BigVector> vector_input(vector_allocator, 1, 2);
    vector_input(0, 0).at(0) = BigInteger(static_cast<uint64_t>(int32_max));
    vector_input(0, 1).at(0) = lowest;
    Matrix<int32_t> vector_out = convert_to_int32(vector_input, modulus);
    EXPECT_EQ(int32_max, vector_out(0, 0));
    EXPECT_EQ(int32_min, vector_out(0, 1));

    MatrixStrassen<BigInteger> strassen_input([]() { return BigInteger(0); }, 1, 2);
    strassen_input(0, 0) = BigInteger(static_cast<uint64_t>(int32_max));
    strassen_input(0, 1) = lowest;
    MatrixStrassen<int32_t> strassen_out = convert_to_int32(strassen_input, modulus);
    EXPECT_EQ(int32_max, strassen_out(0, 0));
    EXPECT_EQ(int32_min, strassen_out(0, 1));

    MatrixStrassen<BigVector> strassen_vector_input(vector_allocator, 1, 2);
    strassen_vector_input(0, 0).at(0) = BigInteger(static_cast<uint64_t>(int32_max));
    strassen_vector_input(0, 1).at(0) = lowest;
    MatrixStrassen<int32_t> strassen_vector_out = convert_to_int32(strassen_vector_input, modulus);
    EXPECT_EQ(int32_max, strassen_vector_out(0, 0));
    EXPECT_EQ(int32_min, strassen_vector_out(0, 1));
}

// a small modulus leaves every residue representable: no throw is possible
TEST(UTMatrix, convert_to_int32_small_modulus) {
    const BigInteger modulus(static_cast<uint64_t>(1024));
    Matrix<BigInteger> input([]() { return BigInteger(0); }, 1, 3);
    input(0, 0) = BigInteger(512);
    input(0, 1) = BigInteger(513);
    input(0, 2) = BigInteger(1023);
    Matrix<int32_t> out = convert_to_int32(input, modulus);
    EXPECT_EQ(512, out(0, 0));
    EXPECT_EQ(-511, out(0, 1));
    EXPECT_EQ(-1, out(0, 2));
}

// q = 2^32 - 1 is the largest modulus for which every centered representative is
// representable: both extremes must convert rather than throw
TEST(UTMatrix, convert_to_int32_widest_representable_modulus) {
    constexpr int32_t int32_max = std::numeric_limits<int32_t>::max();
    const BigInteger modulus(static_cast<uint64_t>(4294967295ULL));
    const BigInteger half(modulus / BigInteger(2));

    Matrix<BigInteger> input([]() { return BigInteger(0); }, 1, 3);
    input(0, 0) = half;                     // largest positive representative, +INT32_MAX
    input(0, 1) = half + BigInteger(1);     // largest negative magnitude, -INT32_MAX
    input(0, 2) = modulus - BigInteger(1);  // -1

    Matrix<int32_t> out([]() { return 0; }, 1, 1);
    EXPECT_NO_THROW(out = convert_to_int32(input, modulus));
    EXPECT_EQ(int32_max, out(0, 0));
    EXPECT_EQ(-int32_max, out(0, 1));
    EXPECT_EQ(-1, out(0, 2));
}

// for an even modulus the class q/2 has the two representatives -q/2 and q/2, of equal
// magnitude; q = 2^32 is the only modulus for which exactly one of them is an int32_t
TEST(UTMatrix, convert_to_int32_even_modulus_endpoint) {
    const BigInteger modulus(static_cast<uint64_t>(4294967296ULL));  // 2^32
    Matrix<BigInteger> input([]() { return BigInteger(0); }, 1, 1);

    input(0, 0) = modulus / BigInteger(2);  // 2^31, representable only as INT32_MIN
    EXPECT_EQ(std::numeric_limits<int32_t>::min(), convert_to_int32(input, modulus)(0, 0));

    input(0, 0) = modulus / BigInteger(2) - BigInteger(1);
    EXPECT_EQ(std::numeric_limits<int32_t>::max(), convert_to_int32(input, modulus)(0, 0));

    //  q = 2^33: the class q/2 has magnitude 2^32 either way, so neither fits
    const BigInteger wider(static_cast<uint64_t>(8589934592ULL));
    input(0, 0) = wider / BigInteger(2);
    EXPECT_THROW(convert_to_int32(input, wider), CipherException);
}

// large modulus: only values near 0 and near q are representable
TEST(UTMatrix, convert_to_int32_large_modulus) {
    constexpr int32_t int32_max = std::numeric_limits<int32_t>::max();
    const BigInteger modulus("1237940039285380274899124357");
    Matrix<BigInteger> input([]() { return BigInteger(0); }, 1, 1);

    input(0, 0) = BigInteger(12345);
    EXPECT_EQ(12345, convert_to_int32(input, modulus)(0, 0));

    input(0, 0) = modulus - BigInteger(12345);
    EXPECT_EQ(-12345, convert_to_int32(input, modulus)(0, 0));

    input(0, 0) = modulus - BigInteger(static_cast<uint64_t>(int32_max) + 1);
    EXPECT_EQ(std::numeric_limits<int32_t>::min(), convert_to_int32(input, modulus)(0, 0));

    input(0, 0) = BigInteger(static_cast<uint64_t>(int32_max) + 1);
    EXPECT_THROW(convert_to_int32(input, modulus), CipherException);

    input(0, 0) = modulus - BigInteger(static_cast<uint64_t>(int32_max) + 2);
    EXPECT_THROW(convert_to_int32(input, modulus), CipherException);
}

// a value outside Z_q has no centered representative: it must throw rather than
// convert to whatever the modular subtraction happens to produce
TEST(UTMatrix, convert_to_int32_value_outside_ring) {
    Matrix<BigInteger> input([]() { return BigInteger(0); }, 1, 1);

    const BigInteger small_modulus_value(static_cast<uint64_t>(67108913));
    input(0, 0) = small_modulus_value + BigInteger(5);
    EXPECT_THROW(convert_to_int32(input, small_modulus_value), CipherException);

    const BigInteger large_modulus_value("1237940039285380274899124357");
    input(0, 0) = large_modulus_value + BigInteger(5);
    EXPECT_THROW(convert_to_int32(input, large_modulus_value), CipherException);
}

template <typename Element>
void basic_il2n_math(const std::string& msg) {
    Matrix<Element> z(secure_il2n_alloc<Element>(), 2, 2);
    Matrix<Element> n = Matrix<Element>(secure_il2n_alloc<Element>(), 2, 2).ones();
    Matrix<Element> I = Matrix<Element>(secure_il2n_alloc<Element>(), 2, 2).identity();
    I.set_format(Format::COEFFICIENT);
    I.set_format(Format::EVALUATION);
    EXPECT_EQ(n, I * n) << msg;

    n = n - n;
    EXPECT_EQ(n, z) << msg;
}

TEST(UTMatrix, basic_il2n_math) {
    RUN_ALL_POLYS(basic_il2n_math, "basic_il2n_math")
}

template <typename T>
void basic_int_math(const std::string& msg) {
    Matrix<T> z(T::allocator, 2, 2);
    Matrix<T> n = Matrix<T>(T::allocator, 2, 2).ones();
    Matrix<T> I = Matrix<T>(T::allocator, 2, 2).identity();
    EXPECT_EQ(n, I * n) << msg;
    n = n - n;
    EXPECT_EQ(n, z) << msg;
}

TEST(UTMatrix, basic_int_math) {
    RUN_ALL_BACKENDS_INT(basic_int_math, "basic_int_math")
}

template <typename V>
void basic_intvec_math(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);

    typename V::Integer modulus("67108913");
    CIPHER_DEBUG("1");
    auto single_alloc = [=]() {
        return V(1, modulus);
    };
    CIPHER_DEBUG("2");
    Matrix<V> z(single_alloc, 2, 2);
    CIPHER_DEBUG("3");
    Matrix<V> n = Matrix<V>(single_alloc, 2, 2).ones();
    CIPHER_DEBUG("4");
    Matrix<V> I = Matrix<V>(single_alloc, 2, 2).identity();
    CIPHER_DEBUG("5");
    CIPHER_DEBUG("z mod 00 " << z(0, 0).get_modulus().to_string());
    CIPHER_DEBUG("z mod 01 " << z(0, 1).get_modulus().to_string());
    CIPHER_DEBUG("z mod 10 " << z(1, 0).get_modulus().to_string());
    CIPHER_DEBUG("z mod 1 1 " << z(1, 1).get_modulus().to_string());
    CIPHER_DEBUG("n mod " << n(0, 0).get_modulus().to_string());
    CIPHER_DEBUG("I mod " << I(0, 0).get_modulus().to_string());
    EXPECT_EQ(n, I * n) << msg;
    CIPHER_DEBUG("6");
    n = n - n;
    CIPHER_DEBUG("7");
    EXPECT_EQ(n, z) << msg;
    CIPHER_DEBUG("8");
}

TEST(UTMatrix, basic_intvec_math) {
    RUN_ALL_BACKENDS(basic_intvec_math, "basic_intvec_math")
}

template <typename Element>
void transpose(const std::string& msg) {
    Matrix<Element> n = Matrix<Element>(secure_il2n_alloc<Element>(), 4, 2).ones();
    Matrix<Element> n_t = Matrix<Element>(n).transposed();
    Matrix<Element> I = Matrix<Element>(secure_il2n_alloc<Element>(), 2, 2).identity();
    EXPECT_EQ(n_t, I * n_t) << msg;
}

TEST(UTMatrix, transpose) {
    RUN_ALL_POLYS(transpose, "transpose")
}

template <typename Element>
void scalar_mult_impl(const std::string& msg) {
    Matrix<Element> n = Matrix<Element>(secure_il2n_alloc<Element>(), 4, 2).ones();
    auto one = secure_il2n_alloc<Element>()();
    one = 1;
    EXPECT_EQ(n, one * n) << msg;
    EXPECT_EQ(n, n * one) << msg;
}

TEST(UTMatrix, scalar_mult) {
    RUN_ALL_POLYS(scalar_mult_impl, "scalar_mult")
}

template <typename Element>
void poly_mult_square_matrix(const std::string& msg) {
    int32_t dimension = 8;

    Matrix<Element> A =
            Matrix<Element>(fast_il2n_alloc<Element>(), dimension, dimension, fast_uniform_il2n_alloc<Element>());
    Matrix<Element> B =
            Matrix<Element>(fast_il2n_alloc<Element>(), dimension, dimension, fast_uniform_il2n_alloc<Element>());
    Matrix<Element> C =
            Matrix<Element>(fast_il2n_alloc<Element>(), dimension, dimension, fast_uniform_il2n_alloc<Element>());
    Matrix<Element> I = Matrix<Element>(fast_il2n_alloc<Element>(), dimension, dimension).identity();

    EXPECT_EQ(A, A * I) << msg << " Matrix multiplication of two Poly2Ns: A = AI - failed.\n";
    EXPECT_EQ(A, I * A) << msg << " Matrix multiplication of two Poly2Ns: A = IA - failed.\n";

    EXPECT_EQ((A * B).transposed(), B.transposed() * A.transposed())
            << "Matrix multiplication of two Poly2Ns: (A*B)^T = B^T*A^T - failed.\n";

    EXPECT_EQ(A * B * C, A * (B * C)) << msg << " Matrix multiplication of two Poly2Ns: A*B*C = A*(B*C) - failed.\n";
    EXPECT_EQ(A * B * C, (A * B) * C) << msg << " Matrix multiplication of two Poly2Ns: A*B*C = (A*B)*C - failed.\n";
}

TEST(UTMatrix, Poly_mult_square_matrix) {
    RUN_ALL_POLYS(poly_mult_square_matrix, "Poly_mult_square_matrix")
}

template <typename Element>
void poly_mult_square_matrix_caps(const std::string& msg) {
    int32_t dimension = 16;

    MatrixStrassen<Element> A = MatrixStrassen<Element>(fast_il2n_alloc<Element>(), dimension, dimension,
                                                        fast_uniform_il2n_alloc<Element>());
    MatrixStrassen<Element> B = MatrixStrassen<Element>(fast_il2n_alloc<Element>(), dimension, dimension,
                                                        fast_uniform_il2n_alloc<Element>());
    MatrixStrassen<Element> C = MatrixStrassen<Element>(fast_il2n_alloc<Element>(), dimension, dimension,
                                                        fast_uniform_il2n_alloc<Element>());
    MatrixStrassen<Element> I = MatrixStrassen<Element>(fast_il2n_alloc<Element>(), dimension, dimension).identity();

    // EXPECT_EQ((A.mult(B))(0, 0), (A.multiply_caps(B, 2))(0, 0)) << "CAPS matrix
    // multiplication of two Poly2Ns doesn't agree with Mult: A.mult(B),
    // A.multiply_caps(B,2) - failed.\n";
    EXPECT_EQ(A, A.mult(I, 2)) << msg << " CAPS matrix multiplication of two Poly2Ns: A = AI - failed.\n";
    EXPECT_EQ(A, I.mult(A, 2)) << msg << " Matrix multiplication of two Poly2Ns: A = IA - failed.\n";

    EXPECT_EQ((A.mult(B, 2)).transposed(), B.transposed().mult(A.transposed(), 2))
            << msg
            << " Matrix multiplication of two Poly2Ns: "
               "(A.multiply_caps(B,2)).transpose(), "
               "B.transpose().multiply_caps(A.transpose(),2) - failed.\n";

    EXPECT_EQ(A.mult(B, 2).mult(C, 2), A.mult((B.mult(C, 2)), 2))
            << msg
            << " Matrix multiplication of two Poly2Ns: "
               "A.multiply_caps(B,2).multiply_caps(C,2), "
               "A.multiply_caps((B.multiply_caps(C,2)),2) - failed.\n";
    EXPECT_EQ(A.mult(B, 2).mult(C, 2), (A.mult(B, 2)).mult(C, 2))
            << msg
            << " Matrix multiplication of two Poly2Ns: "
               "A.multiply_caps(B,2).multiply_caps(C,2), "
               "(A.multiply_caps(B,2)).multiply_caps(C,2) - failed.\n";
}

TEST(UTMatrix, Poly_mult_square_matrix_caps) {
    RUN_ALL_POLYS(poly_mult_square_matrix_caps, "Poly_mult_square_matrix_caps")
}

inline void expect_close(double a, double b) {
    EXPECT_LE(std::fabs(a - b), 10e-8);
}

TEST(UTMatrix, cholesky) {
    CIPHER_DEBUG_FLAG(false);
    Matrix<int32_t> m([]() { return 0; }, 2, 2);
    m(0, 0) = 20;
    m(0, 1) = 4;
    m(1, 0) = 4;
    m(1, 1) = 10;

    auto c = cholesky(m);
    CIPHER_DEBUGEXP(c);
    EXPECT_LE(std::fabs(4.47213595 - c(0, 0)), 1e-8);
    EXPECT_LE(std::fabs(0 - c(0, 1)), 1e-8);
    EXPECT_LE(std::fabs(.89442719 - c(1, 0)), 1e-8);
    EXPECT_LE(std::fabs(3.03315018 - c(1, 1)), 1e-8);
    auto cc = c * c.transposed();
    EXPECT_LE(std::fabs(m(0, 0) - cc(0, 0)), 1e-8);
    EXPECT_LE(std::fabs(m(0, 1) - cc(0, 1)), 1e-8);
    EXPECT_LE(std::fabs(m(1, 0) - cc(1, 0)), 1e-8);
    EXPECT_LE(std::fabs(m(1, 1) - cc(1, 1)), 1e-8);
    CIPHER_DEBUGEXP(cc);
}

// Beyond 1x1 the pivots come from the updated trailing block, not the input, which a 3x3 case
// exercises for every overload
TEST(UTMatrix, cholesky3x3) {
    const int32_t a[3][3] = {{4, 2, 2}, {2, 5, 3}, {2, 3, 6}};
    const double lower[3][3] = {{2, 0, 0}, {1, 2, 0}, {1, 1, 2}};

    Matrix<int32_t> m([]() { return 0; }, 3, 3);
    MatrixStrassen<int32_t> ms([]() { return 0; }, 3, 3);
    for (size_t i = 0; i < 3; ++i) {
        for (size_t j = 0; j < 3; ++j) {
            m(i, j) = a[i][j];
            ms(i, j) = a[i][j];
        }
    }

    auto c = cholesky(m);
    Matrix<double> c2([]() { return 0; }, 3, 3);
    cholesky(m, c2);
    auto cs = cholesky(ms);
    for (size_t i = 0; i < 3; ++i) {
        for (size_t j = 0; j < 3; ++j) {
            EXPECT_LE(std::fabs(lower[i][j] - c(i, j)), 1e-12) << "cholesky(input) at " << i << "," << j;
            EXPECT_LE(std::fabs(lower[i][j] - c2(i, j)), 1e-12) << "cholesky(input, result) at " << i << "," << j;
            EXPECT_LE(std::fabs(lower[i][j] - cs(i, j)), 1e-12) << "cholesky(MatrixStrassen) at " << i << "," << j;
        }
    }

    Matrix<double> wrong_size([]() { return 0; }, 2, 2);
    EXPECT_THROW(cholesky(m, wrong_size), CipherException);
}

template <typename Element>
void gadget_vector_impl(const std::string& msg) {
    Matrix<Element> n = Matrix<Element>(secure_il2n_alloc<Element>(), 1, 4).gadget_vector();
    auto v = secure_il2n_alloc<Element>()();
    v = 1;
    EXPECT_EQ(v, n(0, 0)) << msg;
    v = 2;
    EXPECT_EQ(v, n(0, 1)) << msg;
    v = 4;
    EXPECT_EQ(v, n(0, 2)) << msg;
    v = 8;
    EXPECT_EQ(v, n(0, 3)) << msg;
}

TEST(UTMatrix, gadget_vector) {
    RUN_ALL_POLYS(gadget_vector_impl, "gadget_vector")
}

template <typename Element>
void rotate_vec_result_impl(const std::string& msg) {
    Matrix<Element> n = Matrix<Element>(fast_il2n_alloc<Element>(), 1, 2).ones();
    const typename Element::Integer& modulus = n(0, 0).get_modulus();
    n.set_format(Format::COEFFICIENT);
    n(0, 0).at(2) = 1;
    Matrix<typename Element::Vector> R = rotate_vec_result(n);
    EXPECT_EQ(8U, R.get_rows()) << msg;
    EXPECT_EQ(16U, R.get_cols()) << msg;
    EXPECT_EQ(Element::Vector::single(1, modulus), R(0, 0)) << msg;

    typename Element::Integer neg_one = n(0, 0).get_modulus() - typename Element::Integer(1);
    typename Element::Vector neg_one_vec = Element::Vector::single(neg_one, modulus);
    EXPECT_EQ(neg_one_vec, R(0, 6)) << msg;
    EXPECT_EQ(neg_one_vec, R(1, 7)) << msg;

    auto single_alloc = [=]() {
        return typename Element::Vector(1, modulus);
    };
    EXPECT_EQ(single_alloc(), R(0, 6 + 8)) << msg;
    EXPECT_EQ(single_alloc(), R(1, 7 + 8)) << msg;
}

TEST(UTMatrix, rotate_vec_result) {
    RUN_ALL_POLYS(rotate_vec_result_impl, "rotate_vec_result")
}

template <typename Element>
void rotate(const std::string& msg) {
    Matrix<Element> n = Matrix<Element>(fast_il2n_alloc<Element>(), 1, 2).ones();

    n.set_format(Format::COEFFICIENT);
    n(0, 0).at(2) = 1;
    Matrix<typename Element::Integer> R = rotate_matrix(n);
    EXPECT_EQ(8U, R.get_rows()) << msg;
    EXPECT_EQ(16U, R.get_cols()) << msg;
    EXPECT_EQ(typename Element::Integer(1), R(0, 0)) << msg;

    typename Element::Integer neg_one = n(0, 0).get_modulus() - typename Element::Integer(1);
    EXPECT_EQ(neg_one, R(0, 6)) << msg;
    EXPECT_EQ(neg_one, R(1, 7)) << msg;

    EXPECT_EQ(typename Element::Integer(0), R(0, 6 + 8)) << msg;
    EXPECT_EQ(typename Element::Integer(0), R(1, 7 + 8)) << msg;
}

TEST(UTMatrix, rotate) {
    RUN_ALL_POLYS(rotate, "rotate")
}

template <typename Element>
void vstack(const std::string& msg) {
    Matrix<Element> n = Matrix<Element>(secure_il2n_alloc<Element>(), 4, 2).ones();
    Matrix<Element> m = Matrix<Element>(secure_il2n_alloc<Element>(), 8, 2).ones();
    EXPECT_EQ(m, n.v_stack(n)) << msg;
}

TEST(UTMatrix, vstack) {
    RUN_ALL_POLYS(vstack, "vstack")
}

template <typename Element>
void hstack(const std::string& msg) {
    Matrix<Element> n = Matrix<Element>(secure_il2n_alloc<Element>(), 2, 2).ones();
    Matrix<Element> m = Matrix<Element>(secure_il2n_alloc<Element>(), 2, 4).ones();
    EXPECT_EQ(m, n.h_stack(n)) << msg;
}

TEST(UTMatrix, hstack) {
    RUN_ALL_POLYS(hstack, "hstack")
}

template <typename Element>
void norm_impl(const std::string& msg) {
    Matrix<Element> n = Matrix<Element>(secure_il2n_alloc<Element>(), 2, 2).ones();
    EXPECT_EQ(1.0, n.norm());
    Matrix<Element> m = Matrix<Element>(secure_il2n_alloc<Element>(), 2, 2).identity();
    EXPECT_EQ(1.0, m.norm()) << msg;
}

// NOLINTNEXTLINE
TEST(UTMatrix, norm){RUN_ALL_POLYS(norm_impl, "norm")}

// Checks the implementantation of determinant based on a 3x3 matrix
TEST(UTMatrix, determinant) {
    Matrix<int32_t> m([]() { return 0; }, 3, 3);
    m(0, 0) = 1;
    m(0, 1) = 2;
    m(0, 2) = 1;
    m(1, 0) = -1;
    m(1, 1) = 1;
    m(1, 2) = 1;
    m(2, 0) = 1;
    m(2, 1) = 2;
    m(2, 2) = 3;

    // int32_t determinant = m.determinant();
    int32_t determinant_value = 0;
    m.determinant(&determinant_value);
    EXPECT_EQ(6, determinant_value);
}

// Checks the implementantation of cofactor matrix based on a 3x3 matrix
TEST(UTMatrix, cofactor_matrix) {
    Matrix<int32_t> m([]() { return 0; }, 3, 3);
    m(0, 0) = 1;
    m(0, 1) = 2;
    m(0, 2) = 0;
    m(1, 0) = -1;
    m(1, 1) = 1;
    m(1, 2) = 1;
    m(2, 0) = 1;
    m(2, 1) = 2;
    m(2, 2) = 3;

    Matrix<int32_t> r([]() { return 0; }, 3, 3);
    r(0, 0) = 1;
    r(0, 1) = 4;
    r(0, 2) = -3;
    r(1, 0) = -6;
    r(1, 1) = 3;
    r(1, 2) = 0;
    r(2, 0) = 2;
    r(2, 1) = -1;
    r(2, 2) = 3;

    EXPECT_EQ(r, m.cofactor_matrix());
}
