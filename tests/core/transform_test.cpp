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

#include <cstdint>
#include <iostream>
#include <random>
#include <string>

#include "gtest/gtest.h"
#include "cipher/ring/backend.h"
#include "cipher/math/distributions.h"
#include "cipher/math/backend.h"
#include "cipher/math/number_theory.h"
#include "core/test_defs.h"
#include "cipher/util/debug.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/utilities.h"

using namespace cipher;

// ---------------  TESTING METHODS OF TRANSFORM ---------------

// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION USING CHINESE REMAINDER THEOREM

template <typename V>
void crt_polynomial_mult(const std::string& msg) {
    typename V::Integer prime_modulus("113");  // 65537
    uint32_t cyclo_order = 8;
    uint32_t n = cyclo_order / 2;

    typename V::Integer primitive_root_of_unity = cipher::root_of_unity(cyclo_order, prime_modulus);

    ChineseRemainderTransformFtt<V>().pre_compute(primitive_root_of_unity, cyclo_order, prime_modulus);

    V a(n, prime_modulus);
    a.at(0) = typename V::Integer("1");
    a.at(1) = typename V::Integer("2");
    a.at(2) = typename V::Integer("4");
    a.at(3) = typename V::Integer("1");
    V b(a);

    V A(cyclo_order / 2);
    ChineseRemainderTransformFtt<V>().forward_transform_to_bit_reverse(a, primitive_root_of_unity, cyclo_order, &A);
    V B(cyclo_order / 2);
    ChineseRemainderTransformFtt<V>().forward_transform_to_bit_reverse(b, primitive_root_of_unity, cyclo_order, &B);

    V AB = A * B;

    V inverse_fftab(cyclo_order / 2);
    ChineseRemainderTransformFtt<V>().inverse_transform_from_bit_reverse(AB, primitive_root_of_unity, cyclo_order,
                                                                         &inverse_fftab);

    V expected_result(n, prime_modulus);
    expected_result.at(0) = typename V::Integer("94");
    expected_result.at(1) = typename V::Integer("109");
    expected_result.at(2) = typename V::Integer("11");
    expected_result.at(3) = typename V::Integer("18");

    EXPECT_EQ(expected_result, inverse_fftab) << msg << "inverse transform";
}

TEST(UTTransform, CRT_polynomial_mult) {
    RUN_ALL_BACKENDS(crt_polynomial_mult, "CRT_polynomial_mult")
}

// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION IN ARBITRARY CYCLOTOMIC FILED
// USING CHINESE REMAINDER THEOREM

template <typename V>
void crt_polynomial_mult_small(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);

    uint32_t m = 22;
    typename V::Integer square_root_of_root(3750);
    typename V::Integer modulus(4621);
    typename V::Integer big_modulus("32043581647489");
    typename V::Integer big_root("31971887649898");
    uint32_t n = get_totient(m);

    CIPHER_DEBUG("m is " << m << " and n is " << n);
    auto cyclo_poly = get_cyclotomic_polynomial<V>(m, modulus);
    CIPHER_DEBUG("2 " << cyclo_poly);

    // ChineseRemainderTransformArb<V>::pre_compute(m, modulus);
    ChineseRemainderTransformArb<V>().set_cylotomic_polynomial(cyclo_poly, modulus);
    CIPHER_DEBUG("3");

    V a(n, modulus);
    a = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    auto A = ChineseRemainderTransformArb<V>().forward_transform(a, square_root_of_root, big_modulus, big_root, m);
    CIPHER_DEBUG("4 " << A);

    V b(n, modulus);
    b = {5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
    auto B = ChineseRemainderTransformArb<V>().forward_transform(b, square_root_of_root, big_modulus, big_root, m);
    CIPHER_DEBUG("5 " << B);
    auto C = A * B;
    CIPHER_DEBUG("6 " << C);

    auto c = ChineseRemainderTransformArb<V>().inverse_transform(C, square_root_of_root, big_modulus, big_root, m);

    CIPHER_DEBUG("7 " << c);
    auto c_check = polynomial_multiplication(a, b);

    CIPHER_DEBUG("8");
    c_check = poly_mod(c_check, cyclo_poly, modulus);

    for (uint32_t i = 0; i < n; i++) {
        EXPECT_EQ(c_check.at(i), c.at(i)) << msg;
    }
}

TEST(UTTransform, CRT_polynomial_mult_small) {
    RUN_ALL_BACKENDS(crt_polynomial_mult_small, "CRT_polynomial_mult_small")
}

// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION IN ARBITRARY CYCLOTOMIC FILED
// USING CHINESE REMAINDER THEOREM

template <typename V>
void crt_polynomial_mult_big_ring(const std::string& msg) {
    uint32_t m = 1800;

    typename V::Integer modulus(14401);
    typename V::Integer big_modulus("1045889179649");
    typename V::Integer big_root("864331722621");
    typename V::Integer square_root_of_root("972");
    uint32_t n = get_totient(m);
    auto cyclo_poly = get_cyclotomic_polynomial<V>(m, modulus);

    ChineseRemainderTransformArb<V>().pre_compute(m, modulus);
    ChineseRemainderTransformArb<V>().set_cylotomic_polynomial(cyclo_poly, modulus);

    V a(n, modulus);
    a = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    auto A = ChineseRemainderTransformArb<V>().forward_transform(a, square_root_of_root, big_modulus, big_root, m);

    V b(n, modulus);
    b = {5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
    auto B = ChineseRemainderTransformArb<V>().forward_transform(b, square_root_of_root, big_modulus, big_root, m);

    auto C = A * B;

    auto c = ChineseRemainderTransformArb<V>().inverse_transform(C, square_root_of_root, big_modulus, big_root, m);

    auto c_check = polynomial_multiplication(a, b);

    c_check = poly_mod(c_check, cyclo_poly, modulus);
    for (uint32_t i = 0; i < n; i++) {
        EXPECT_EQ(c_check.at(i), c.at(i)) << msg;
    }
}

TEST(UTTransform, CRT_polynomial_mult_big_ring) {
    RUN_ALL_BACKENDS(crt_polynomial_mult_big_ring, "CRT_polynomial_mult_big_ring")
}

template <typename V>
void crt_polynomial_mult_big_ring_prime_cyclotomics(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);

    uint32_t m = 1733;

    typename V::Integer modulus("1152921504606909071");
    typename V::Integer big_modulus("10889035741470030830827987437816582848513");
    typename V::Integer big_root("5879632101734955395039618227388702592012");
    typename V::Integer square_root_of_root("44343872016735288");
    uint32_t n = get_totient(m);
    auto cyclo_poly = get_cyclotomic_polynomial<V>(m, modulus);

    ChineseRemainderTransformArb<V>().pre_compute(m, modulus);
    ChineseRemainderTransformArb<V>().set_cylotomic_polynomial(cyclo_poly, modulus);

    V a(n, modulus);
    a = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    auto A = ChineseRemainderTransformArb<V>().forward_transform(a, square_root_of_root, big_modulus, big_root, m);

    V b(n, modulus);
    b = {5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
    auto B = ChineseRemainderTransformArb<V>().forward_transform(b, square_root_of_root, big_modulus, big_root, m);

    auto C = A * B;

    auto c = ChineseRemainderTransformArb<V>().inverse_transform(C, square_root_of_root, big_modulus, big_root, m);

    auto c_check = polynomial_multiplication(a, b);

    c_check = poly_mod(c_check, cyclo_poly, modulus);
    CIPHER_DEBUG("c " << c);
    CIPHER_DEBUG("cCheck " << c_check);
    EXPECT_EQ(c_check, c) << msg;
}

TEST(UTTransform, CRT_polynomial_mult_big_ring_prime_cyclotomics) {
    RUN_BIG_BACKENDS(crt_polynomial_mult_big_ring_prime_cyclotomics, "CRT_polynomial_mult_big_ring_prime_cyclotomics")
}

// TEST CASE TO TEST FORWARD AND INVERSE TRANSFORM IN ARBITRARY CYCLOTOMIC
// FILED.
// CHECKING IF INVERSET-TRANSFORM(FORWARD-TRANSFORM(A)) = A.

template <typename V>
void crt_check_small_ring(const std::string& msg) {
    uint32_t m = 22;
    typename V::Integer square_root_of_root(3750);
    typename V::Integer modulus(4621);
    typename V::Integer big_modulus("32043581647489");
    typename V::Integer big_root("31971887649898");
    uint32_t n = get_totient(m);

    auto cyclo_poly = get_cyclotomic_polynomial<V>(m, modulus);

    // ChineseRemainderTransformArb<V>::pre_compute(m, modulus);
    ChineseRemainderTransformArb<V>().set_cylotomic_polynomial(cyclo_poly, modulus);

    V input(n, modulus);
    input = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    auto INPUT =
            ChineseRemainderTransformArb<V>().forward_transform(input, square_root_of_root, big_modulus, big_root, m);

    auto input_check =
            ChineseRemainderTransformArb<V>().inverse_transform(INPUT, square_root_of_root, big_modulus, big_root, m);

    for (uint32_t i = 0; i < n; i++) {
        EXPECT_EQ(input.at(i), input_check.at(i)) << msg;
    }
}

TEST(UTTransform, CRT_CHECK_small_ring) {
    RUN_ALL_BACKENDS(crt_check_small_ring, "CRT_CHECK_small_ring")
}

// TEST CASE TO TEST FORWARD AND INVERSE TRANSFORM IN ARBITRARY CYCLOTOMIC
// FILED.
// CHECKING IF INVERSET-TRANSFORM(FORWARD-TRANSFORM(A)) = A.

template <typename V>
void crt_check_big_ring(const std::string& msg) {
    uint32_t m = 1800;

    typename V::Integer modulus(14401);
    typename V::Integer square_root_of_root("972");
    typename V::Integer big_modulus("1045889179649");
    typename V::Integer big_root("864331722621");
    uint32_t n = get_totient(m);
    auto cyclo_poly = get_cyclotomic_polynomial<V>(m, modulus);

    // ChineseRemainderTransformArb<V>::pre_compute(m, modulus);
    ChineseRemainderTransformArb<V>().set_cylotomic_polynomial(cyclo_poly, modulus);

    V input(n, modulus);
    std::uniform_int_distribution<> dis(0, 100);  // generates a number in [0,100]
    for (uint32_t i = 0; i < n; i++) {
        input.at(i) = typename V::Integer(dis(PseudoRandomNumberGenerator::get_prng()));
    }

    auto output =
            ChineseRemainderTransformArb<V>().forward_transform(input, square_root_of_root, big_modulus, big_root, m);

    auto rec_out =
            ChineseRemainderTransformArb<V>().inverse_transform(output, square_root_of_root, big_modulus, big_root, m);

    for (uint32_t i = 0; i < n; i++) {
        EXPECT_EQ(input.at(i), rec_out.at(i)) << msg;
    }
}

TEST(UTTransform, CRT_CHECK_big_ring) {
    RUN_ALL_BACKENDS(crt_check_big_ring, "CRT_CHECK_big_ring")
}

template <typename V>
void crt_check_small_ring_precomputed(const std::string& msg) {
    uint32_t m = 22;
    typename V::Integer square_root_of_root(3750);
    typename V::Integer modulus(4621);
    uint32_t n = get_totient(m);

    auto cyclo_poly = get_cyclotomic_polynomial<V>(m, modulus);
    typename V::Integer nttmodulus("32043581647489");
    typename V::Integer nttroot("31971887649898");

    // ChineseRemainderTransformArb<V>::pre_compute(m, modulus);
    // ChineseRemainderTransformArb<V>::set_pre_computed_ntt_modulus(m, modulus,
    // nttmodulus, nttroot);
    ChineseRemainderTransformArb<V>().set_cylotomic_polynomial(cyclo_poly, modulus);

    V input(n, modulus);
    input = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    auto INPUT =
            ChineseRemainderTransformArb<V>().forward_transform(input, square_root_of_root, nttmodulus, nttroot, m);

    auto input_check =
            ChineseRemainderTransformArb<V>().inverse_transform(INPUT, square_root_of_root, nttmodulus, nttroot, m);

    for (uint32_t i = 0; i < n; i++) {
        EXPECT_EQ(input.at(i), input_check.at(i)) << msg;
    }
}

TEST(UTTransform, CRT_CHECK_small_ring_precomputed) {
    RUN_ALL_BACKENDS(crt_check_small_ring_precomputed, "CRT_CHECK_small_ring_precomputed")
}

template <typename V>
void crt_check_very_big_ring_precomputed(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);
    uint32_t m = 8422;
    CIPHER_DEBUG("1");
    // find a modulus that has 2*8422 root of unity and is 120 bit long
    typename V::Integer modulus("619578785044668429129510602549015713");
    typename V::Integer square_root_of_root("204851043665385327685783246012876507");
    uint32_t n = get_totient(m);
    CIPHER_DEBUG("UT GetTotient(" << m << ")= " << n);

    auto cyclo_poly = get_cyclotomic_polynomial<V>(m, modulus);
    typename V::Integer nttmodulus(
            "185267342779705912677713576013900652565231975465024902463132134412661007"
            "6631041");
    typename V::Integer nttroot(
            "101185740842230903903955690719590885956153523464987081415401983436274640"
            "8101010");

    // ChineseRemainderTransformArb<V>::pre_compute(m, modulus);
    // ChineseRemainderTransformArb<V>::set_pre_computed_ntt_modulus(m, modulus,
    // nttmodulus, nttroot);

    CIPHER_DEBUG("2");
    ChineseRemainderTransformArb<V>().set_cylotomic_polynomial(cyclo_poly, modulus);
    CIPHER_DEBUG("3");
    V input(n, modulus);
    input = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    CIPHER_DEBUG("4");
    auto INPUT =
            ChineseRemainderTransformArb<V>().forward_transform(input, square_root_of_root, nttmodulus, nttroot, m);
    CIPHER_DEBUG("5");
    auto input_check =
            ChineseRemainderTransformArb<V>().inverse_transform(INPUT, square_root_of_root, nttmodulus, nttroot, m);
    CIPHER_DEBUG("6");
    for (uint32_t i = 0; i < n; i++) {
        EXPECT_EQ(input.at(i), input_check.at(i)) << msg;
    }
}

TEST(UTTransform, CRT_CHECK_very_big_ring_precomputed) {
    RUN_BIG_BACKENDS(crt_check_very_big_ring_precomputed, "CRT_CHECK_very_big_ring_precomputed")
}
