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
#include <set>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "cipher/ring/backend.h"
#include "cipher/math/distributions.h"
#include "cipher/math/backend.h"
#include "cipher/math/number_theory.h"
#include "core/test_defs.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/utilities.h"

using namespace cipher;

// ---------------  TESTING METHODS OF NBTHEORY ---------------

template <typename T>
void method_greatest_common_divisor(const std::string& msg) {
    {
        // TEST CASE TO FIND GREATEST COMMON DIVISOR OF TWO SMALL NUMBERS
        T a("10403"), b("103");
        T c = greatest_common_divisor(a, b);

        uint64_t expected_result = 103;

        EXPECT_EQ(expected_result, c.convert_to_int()) << msg << " Failure equals_small_numbers";
    }
    {
        // TEST CASE TO FIND GREATEST COMMON DIVISOR OF TWO POWERS OF 2 NUMBERS

        T a("1048576"), b("4096");
        T c(greatest_common_divisor(a, b));

        T expected_result(b);

        EXPECT_EQ(expected_result, c) << msg << " Failure equals_powers_of_two_numbers";
    }
    {
        // test that failed in Issue #409
        T a("883035439563027"), b("3042269397984931");
        T c(greatest_common_divisor(a, b));
        T expected_result("1");
        EXPECT_EQ(expected_result, c) << msg << " Failure Issue 409";
    }
}

TEST(UTNbTheory, method_greatest_common_divisor) {
    RUN_ALL_BACKENDS_INT(method_greatest_common_divisor, "method_greatest_common_divisor")
}

template <typename T>
void method_miller_rabin_primality(const std::string& msg) {
    {
        // TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR SMALL PRIME
        T prime("24469");
        EXPECT_TRUE(miller_rabin_primality_test(prime)) << msg << " Failure is_prime_small_prime";
    }
    {
        // TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR BIG PRIME

        T prime("952229140957");

        EXPECT_TRUE(miller_rabin_primality_test(prime)) << msg << " Failure is_prime_big_prime";
    }
    {
        // TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR SMALL COMPOSITE NUMBER

        T is_not_prime("10403");

        EXPECT_FALSE(miller_rabin_primality_test(is_not_prime))
                << msg << " Failure is_not_prime_small_composite_number";
    }
    {
        // TEST CASE FOR MILLER RABIN PRIMALITY TEST FOR BIG COMPOSITE NUMBER

        T is_not_prime("952229140959");

        EXPECT_FALSE(miller_rabin_primality_test(is_not_prime)) << msg << " Failure is_not_prime_big_composite_number";
    }
}

TEST(UTNbTheory, method_miller_rabin_primality) {
    RUN_ALL_BACKENDS_INT(method_miller_rabin_primality, "method_miller_rabin_primality")
}

// TEST CASE FOR FACTORIZATION

template <typename Element>
::testing::AssertionResult is_member_of(Element val, const std::vector<Element>& values) {
    if (std::find(values.begin(), values.end(), val) != values.end())
        return ::testing::AssertionSuccess();
    return ::testing::AssertionFailure();
}

template <typename T>
void method_factorize_returns_factors(const std::string& msg) {
    T comp("53093040");
    std::set<T> factors;
    std::vector<T> answers({2, 3, 5, 7, 11, 13, 15, 17});

    prime_factorize(comp, factors);

    for (auto it = factors.begin(); it != factors.end(); ++it) {
        EXPECT_TRUE(is_member_of(*it, answers)) << msg;
    }
}

// NOLINTNEXTLINE
TEST(UTNbTheory, method_factorize_returns_factors){
        RUN_ALL_BACKENDS_INT(method_factorize_returns_factors, "method_factorize_returns_factors")}

TEST(UTNbTheory, first_prime_overflow) {
    // Failure case check
    uint32_t m = 512;
    uint32_t n_bits = CIPHER_NATIVE_INT;

    EXPECT_THROW(first_prime<NativeInteger>(n_bits, m), CipherException)
            << "did not detect overflow and throw exception for Native";
    EXPECT_THROW(last_prime<NativeInteger>(n_bits, m), CipherException)
            << "did not detect overflow and throw exception for Native";

#ifdef CIPHER_WITH_BE2
    n_bits = BigIntegerBitLength + 10;

    EXPECT_THROW(first_prime<M2Integer>(n_bits, m), CipherException)
            << "did not detect overflow and throw exception for BE2";
#endif
}

template <typename T>
void method_prime_modulus(const std::string& msg) {
    uint32_t m, n_bits;
    {
        // TEST CASE TO FIND PRIME MODULUS
        m = 2048;
        n_bits = 30;

        T expected_result("1073707009");

        EXPECT_EQ(expected_result, last_prime<T>(n_bits, m)) << msg << " Failure foundPrimeModulus";
    }
    {
        // TEST CASE TO FIND PRIME MODULUS FOR A HIGHER BIT LENGTH
        m = 4096;
        n_bits = 49;

        T expected_result("562949953392641");
        EXPECT_EQ(expected_result, last_prime<T>(n_bits, m)) << msg << " Failure returns_higher_bit_length";
    }
}

TEST(UTNbTheory, method_prime_modulus) {
    RUN_ALL_BACKENDS_INT(method_prime_modulus, "method_prime_modulus")
}

template <typename T>
void method_primitive_root_of_unity_very_long(const std::string& msg) {
    {
        // TEST CASE TO ENSURE THE ROOT OF UNITY THAT IS FOUND IS A PRIMITIVE ROOT
        // OF UNTIY
        uint32_t m = 4096;
        uint32_t n_bits = 33;

        T prime_modulus = last_prime<T>(n_bits, m);
        T primitive_root_of_unity = root_of_unity<T>(m, prime_modulus);

        T M(std::to_string(m)), mby_two(M.divided_by(2));

        T wpowerm = primitive_root_of_unity.mod_exp(M, prime_modulus);
        EXPECT_EQ(wpowerm, T(1)) << msg << " Failure single equal_m";

        T wpowermbytwo = primitive_root_of_unity.mod_exp(mby_two, prime_modulus);
        EXPECT_NE(wpowermbytwo, T(1)) << msg << " Failure single not_equal_mbytwo";
    }
    {
        // TEST CASE TO ENSURE THE ROOTS OF UNITY THAT ARE FOUND ARE
        // CONSISTENTLY THE PRIMITIVE ROOTS OF UNTIY
        const uint32_t n = 256;
        const uint32_t m = 2 * n;
        const uint32_t n_bits = 43;
        const int ITERATIONS = m * 2;

        T M(std::to_string(m)), mby_two(M.divided_by(2)), mby_four(mby_two.divided_by(2));

        T prime_modulus = last_prime<T>(n_bits, m);

        for (int i = 0; i < ITERATIONS; i++) {
            T primitive_root_of_unity = root_of_unity<T>(m, prime_modulus);
            T wpowerm = primitive_root_of_unity.mod_exp(M, prime_modulus);
            EXPECT_EQ(wpowerm, T(1)) << msg << " Failure single input iteration " << i << " equal_m";
            T wpowermbytwo = primitive_root_of_unity.mod_exp(mby_two, prime_modulus);
            EXPECT_NE(wpowermbytwo, T(1)) << msg << " Failure single input  iteration " << i << " not_equal_mbytwo";
            T wpowermbyfour = primitive_root_of_unity.mod_exp(mby_four, prime_modulus);
            EXPECT_NE(wpowermbyfour, T(1)) << msg << " Failure single input iteration " << i << "not_equal_mbyfour";
        }
    }
    {
        // TEST CASE TO ENSURE THE ROOTS OF UNITY FOUND FOR MULTIPLE
        // CYCLOTOMIC NUMBERS ARE ALL PRIMITIVE ROOTS OF UNTIY

        // ofstream fout;
        // fout.open ("primitiveRootsBug.log");
        uint32_t nq_bits_array[] = {
                1,
                1,
                2,
                4,
                8,
                20,
                1024,
                30,
                2048,
                31,
                2048,
                33,
                2048,
                40,
                2048,
                41
                // const uint32_t BIT_LENGTH = 200 and const uint32_t FRAGMENTATION_FACTOR =
                // 27 ,2048, 51
                ,
                4096,
                32,
                4096,
                43
                // ,4096, 53
                ,
                8192,
                33,
                8192,
                44
                // ,8192, 55
                ,
                16384,
                34,
                16384,
                46
                // ,16384, 57
                ,
                32768,
                35,
                32768,
                47
                // ,32768, 59
        };
        int length = sizeof(nq_bits_array) / sizeof(nq_bits_array[0]);
        // double diff, start, finish;
        uint32_t n, q_bits, m;
        // T M(std::to_string(m)), mby_two(M.divided_by(2)),
        // mby_four(mby_two.divided_by(2));

        for (int i = 2; i < length; i += 2) {
            // fout <<
            // "----------------------------------------------------------------------------------------------------------------------------------"
            // << endl; fout << "i = " << i << endl;
            n = nq_bits_array[i];
            q_bits = nq_bits_array[i + 1];
            m = 2 * n;

            T M(std::to_string(m)), mby_two(M.divided_by(2)), mby_four(mby_two.divided_by(2));

            // start = current_date_time();
            // fout << "m=" << m << ", q_bits=" << q_bits << ", M=" << M << ", mby_two="
            // << mby_two << endl;
            T prime_modulus = last_prime<T>(q_bits, m);
            // fout << "Prime modulus for n = " << n << " and qbits = " << q_bits << "
            // is " << prime_modulus << endl;

            T primitive_root_of_unity(root_of_unity<T>(m, prime_modulus));

            // fout << "The primitive_root_of_unity is " << primitive_root_of_unity << endl;

            // std::set<T> roots_of_unity_value = testRootsOfUnity(m, prime_modulus);

            // fout << "Roots of unity for prime modulus " << prime_modulus << " are: "
            // << endl; for(auto it = roots_of_unity_value.begin(); it != roots_of_unity_value.end();
            // ++it) {   fout << (*it) << ", ";
            // }
            // fout << endl;
            // finish = current_date_time();
            // diff = finish - start;
            // fout << "Computation time: " << "\t" << diff << " ms" << endl;
            // fout <<
            // "----------------------------------------------------------------------------------------------------------------------------------"
            // << endl;

            T wpowerm = primitive_root_of_unity.mod_exp(M, prime_modulus);
            // fout << "w^m = " << wpowerm << endl;
            EXPECT_EQ(wpowerm, T(1)) << msg << " Failure multi input iteration " << i << " equal_m";

            T wpowermbytwo = primitive_root_of_unity.mod_exp(mby_two, prime_modulus);
            // fout << "w^(m/2) = " << wpowermbytwo << endl;
            EXPECT_NE(wpowermbytwo, T(1)) << msg << " Failure multi input  iteration " << i << " not_equal_mbytwo";

            T wpowermbyfour = primitive_root_of_unity.mod_exp(mby_four, prime_modulus);
            // fout << "w^(m/4) = " << wpowermbyfour << endl;
            EXPECT_NE(wpowermbyfour, T(1)) << msg << " Failure multi input  iteration " << i << " not_equal_mbyfour";
            // fout <<
            // "----------------------------------------------------------------------------------------------------------------------------------"
            // << endl; fout << endl;
        }
        // fout << "End of Computation" << endl;
        // fout.close();
    }

    // Exception handling
    {
        CIPHER_DEBUG_FLAG(false);
        int m = 32;
        T modulus1("67108913"), modulus2("17729"), modulus3("2097169"), modulus4("8353"), modulus5("8369");

        // note this example shows two ways of testing for an exception throw
        T primitive_root_of_unity1;

        // the first way is to catch the error and expect the result.
        int caught_error = 0;
        try {
            primitive_root_of_unity1 = root_of_unity<T>(m, modulus1);
        } catch (...) {
            caught_error = 1;
        }
        EXPECT_EQ(caught_error, 1) << msg << " RootOfUnity did not throw an error and should have";

        // the second way is to directly expect the throw.
        EXPECT_ANY_THROW(  // this call should throw
                primitive_root_of_unity1 = root_of_unity<T>(m, modulus1);)
                << msg << " RootOfUnity did not throw an error and should have";

        T primitive_root_of_unity2;
        EXPECT_NO_THROW(  // this call should NOT throw
                primitive_root_of_unity2 = root_of_unity<T>(m, modulus2);)
                << msg << " RootOfUnity threw an error and should not have";

        CIPHER_DEBUG("RootOfUnity for " << modulus1 << " is " << primitive_root_of_unity1);
        CIPHER_DEBUG("RootOfUnity for " << modulus2 << " is " << primitive_root_of_unity2);
    }
}

TEST(UTNbTheory, method_primitive_root_of_unity_VERY_LONG) {
    RUN_ALL_BACKENDS_INT(method_primitive_root_of_unity_very_long, "method_primitive_root_of_unity_VERY_LONG")
}

template <typename T>
void test_next_q(const std::string& msg) {
    uint32_t m = 2048;
    uint32_t bits = 22;

    std::vector<T> moduli_bbv = {T("4208641"), T("4263937"), T("4270081"), T("4274177"), T("4294657"),
                                 T("4300801"), T("4304897"), T("4319233"), T("4323329"), T("4360193")};

    auto q = first_prime<T>(bits, m);
    for (uint32_t i = 0; i < 10; i++) {
        q = next_prime(q, m);
        EXPECT_EQ(q, moduli_bbv[i]) << msg;
    }
}

TEST(UTNbTheory, test_nextQ) {
    RUN_ALL_BACKENDS_INT(test_next_q, "test_nextQ")
}
