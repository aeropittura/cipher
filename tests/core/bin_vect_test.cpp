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
#include <string>

#include "gtest/gtest.h"
#include "cipher/ring/backend.h"
#include "core/test_defs.h"
#include "cipher/util/debug.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/utilities.h"

using namespace cipher;

// --------------- TESTING INTEGER OPERATIONS ON VECTOR  ---------------
/*
   at() operates on Big Vector, retrieves the value at the given index of a
   vector The functions returns BigInteger, which is passed to convert_to_int() to
   convert to integer One dimensional integer array expected_result is created
   Indivdual expected result for each index of the vector is store in array
   EXPECT_EQ is given the above integer from at, and the value of the
   expected_result at the corresponding index
*/

// --------------- TESTING METHOD MODULUS FOR ALL CONDITIONS ---------------
/*   The method "Mod" operates on Big Vector m, BigInteger q
     Returns:  m mod q, and the result is stored in Big Vector
   calculated_result.
*/
template <typename V>
void at_and_set_modulus_test(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);
    uint32_t len = 10;
    V m(len);

    // note at() does not set modulus
    m.at(0) = typename V::Integer("987968");
    m.at(1) = typename V::Integer("587679");
    m.at(2) = typename V::Integer("456454");
    m.at(3) = typename V::Integer("234343");
    m.at(4) = typename V::Integer("769789");
    m.at(5) = typename V::Integer("465654");
    m.at(6) = typename V::Integer("79");
    m.at(7) = typename V::Integer("346346");
    m.at(8) = typename V::Integer("325328");
    m.at(9) = typename V::Integer("7698798");

    typename V::Integer q("233");

    m.set_modulus(q);

    CIPHER_DEBUG("m" << m);
    V calculated_result = m.mod(q);
    CIPHER_DEBUG("calculated result" << m);
    uint64_t expected_result[] = {48, 53, 7, 178, 190, 120, 79, 108, 60, 12};
    for (uint32_t i = 0; i < len; i++) {
        EXPECT_EQ(expected_result[i], calculated_result[i].convert_to_int()) << msg << " Mod failed";
    }

    V n(len, q);

    n.at(0) = typename V::Integer("987968");  // note at() does not take modulus
    n.at(1) = typename V::Integer("587679");
    n.at(2) = typename V::Integer("456454");
    n.at(3) = typename V::Integer("234343");
    n.at(4) = typename V::Integer("769789");
    n.at(5) = typename V::Integer("465654");
    n.at(6) = typename V::Integer("79");
    n.at(7) = typename V::Integer("346346");
    n.at(8) = typename V::Integer("325328");
    n.at(9) = typename V::Integer("7698798");

    CIPHER_DEBUG("n" << n);
    for (uint32_t i = 0; i < len; i++) {
        if (i != 6) {  // value at 6 is < q
            EXPECT_NE(expected_result[i], n[i].convert_to_int()) << msg << " at no mod failed";
        } else {
            EXPECT_EQ(expected_result[i], n[i].convert_to_int()) << msg << " at no mod failed";
        }
    }

    V l(len, q);
    // note list assignment does take modulus
    l = {"987968", "587679", "456454", "234343", "769789", "465654", "79", "346346", "325328", "7698798"};
    CIPHER_DEBUG("l" << l);
    for (uint32_t i = 0; i < len; i++) {
        EXPECT_EQ(expected_result[i], l[i].convert_to_int()) << msg << " Mod on list assignment failed";
    }
}

TEST(UTBinVect, AtAndSetModulusTest) {
    RUN_BIG_BACKENDS(at_and_set_modulus_test, "AtAndSetModulusTest")
}

template <typename V>
void ctor_test(const std::string& msg) {
    typename V::Integer q("233");
    uint32_t expected_result[10] = {48, 53, 7, 178, 190, 120, 79, 108, 60, 12};
    const uint32_t len = sizeof(expected_result) / sizeof(expected_result[0]);

    {
        V m(len, q, {"987968", "587679", "456454", "234343", "769789", "465654", "79", "346346", "325328", "7698798"});

        V calculated_result = m.mod(q);

        for (uint32_t i = 0; i < len; i++) {
            EXPECT_EQ(expected_result[i], (calculated_result.at(i)).convert_to_int()) << msg;
        }
    }

    {
        V m(len, q, {48, 53, 7, 178, 190, 120, 79, 108, 60, 12});

        for (uint32_t i = 0; i < len; i++) {
            EXPECT_EQ(expected_result[i], m.at(i).convert_to_int()) << msg;
        }
    }
}

TEST(UTBinVect, CTOR_Test) {
    RUN_BIG_BACKENDS(ctor_test, "CTOR_Test")
}

// --------------- TESTING METHOD MODADD FOR ALLCONDITIONS ---------------

/*   The method "Mod Add" operates on Big Vector m, BigIntegers n,q
        Returns:  (m+n)mod q, and the result is stored in Big Vector
   calculated_result.
*/

// TEST CASE WHEN NUMBERS AFTER ADDITION ARE SMALLER THAN MODULUS

template <typename V>
void mod_add_big_modulus(const std::string& msg) {
    typename V::Integer q("3435435");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    typename V::Integer n("3");

    // at() is ok since q is bigger than values
    m.at(0) = typename V::Integer("9868");
    m.at(1) = typename V::Integer("5879");
    m.at(2) = typename V::Integer("4554");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("9789");

    V calculated_result = m.mod_add(n);

    uint64_t expected_result[5] = {9871, 5882, 4557, 2346, 9792};

    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_EQ(expected_result[i], (calculated_result.at(i)).convert_to_int()) << msg;
    }
}

TEST(UTBinVect, ModAddBigModulus) {
    RUN_BIG_BACKENDS(mod_add_big_modulus, "ModAddBigModulus")
}

// TEST CASE WHEN NUMBERS AFTER ADDITION ARE GREATER THAN MODULUS

template <typename V>
void mod_add_smaller_modulus(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);

    typename V::Integer q("3534");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    typename V::Integer n("34365");

    CIPHER_DEBUG("m " << m);
    CIPHER_DEBUG("m's modulus " << m.get_modulus());

    m.at(0) = typename V::Integer("9868");
    m.at(1) = typename V::Integer("5879");
    m.at(2) = typename V::Integer("4554");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("9789");

    // at() does not apply mod so m is currently ill-formed for input to mod_add
    // n is okay
    m.mod_eq(q);

    V calculated_result = m.mod_add(n);

    CIPHER_DEBUG("m " << m);
    CIPHER_DEBUG("calculated result  " << calculated_result);
    uint64_t expected_result[5] = {1825, 1370, 45, 1368, 1746};

    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_EQ(expected_result[i], (calculated_result.at(i)).convert_to_int()) << msg;
    }
}

TEST(UTBinVect, ModAddSmallerModulus) {
    RUN_BIG_BACKENDS(mod_add_smaller_modulus, "ModAddSmallerModulus")
}

// --------------- TESTING METHOD MODUSUB FOR ALL CONDITIONS ---------------
/*   The method "Mod Sub" operates on Big Vector m, BigIntegers n,q
        Returns:
                when m>n, (m-n)mod q
                when m=n, 0
                when m<n, {(m mod q)+q-(n mod q)} mod q
        and the result is stored in Big Vector calculated_result.
*/

// TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER

template <typename V>
void modsub_first_less_than_second(const std::string& msg) {
    typename V::Integer q("3534");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    typename V::Integer n("34365");

    m.at(0) = typename V::Integer("9868");
    m.at(1) = typename V::Integer("5879");
    m.at(2) = typename V::Integer("4554");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("9789");

    // at() does not apply mod so m is currently ill-formed for input to mod_sub
    // n is okay
    m.mod_eq(q);

    V calculated_result = m.mod_sub(n);

    uint64_t expected_result[5] = {241, 3320, 1995, 3318, 162};

    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_EQ(expected_result[i], (calculated_result.at(i)).convert_to_int()) << msg;
    }
}

TEST(UTBinVect, modsub_first_less_than_second) {
    RUN_BIG_BACKENDS(modsub_first_less_than_second, "modsub_first_less_than_second")
}

// TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER

template <typename V>
void modsub_first_greater_than_second(const std::string& msg) {
    typename V::Integer q("35");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    typename V::Integer n("765");

    m.at(0) = typename V::Integer("9868");
    m.at(1) = typename V::Integer("5879");
    m.at(2) = typename V::Integer("4554");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("9789");

    // at() does not apply mod so m is currently ill-formed for input to mod_sub
    // n is okay
    m.mod_eq(q);

    V calculated_result = m.mod_sub(n);

    uint64_t expected_result[5] = {3, 4, 9, 3, 29};

    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_EQ(expected_result[i], (calculated_result.at(i)).convert_to_int()) << msg;
    }
}

TEST(UTBinVect, modsub_first_greater_than_second) {
    RUN_BIG_BACKENDS(modsub_first_greater_than_second, "modsub_first_greater_than_second")
}

// --------------- TESTING METHOD MODUMUL FOR ALL CONDITIONS ---------------

/*   The method "Mod Mul" operates on Big Vector m, BigIntegers n,q
        Returns:  (m*n)mod q
        and the result is stored in Big Vector calculated_result.
*/
template <typename V>
void mod_mul_test(const std::string& msg) {
    typename V::Integer q("3534");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    typename V::Integer n("46");

    m.at(0) = typename V::Integer("9868");
    m.at(1) = typename V::Integer("5879");
    m.at(2) = typename V::Integer("4554");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("9789");

    V calculated_result = m.mod_mul(n);

    uint64_t expected_result[5] = {1576, 1850, 978, 1758, 1476};

    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_EQ(expected_result[i], (calculated_result.at(i)).convert_to_int()) << msg;
    }
}

TEST(UTBinVect, ModMulTest) {
    RUN_BIG_BACKENDS(mod_mul_test, "ModMulTest")
}

// --------------- TESTING METHOD MODEXP FOR ALL CONDITIONS  ---------------
/*   The method "Mod Exp" operates on Big Vector m, BigIntegers n,q
        Returns:  (m^n)mod q
        and the result is stored in Big Vector calculated_result.
*/
template <typename V>
void mod_exp_test(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);
    typename V::Integer q("3534");  // constructor calling to set mod value

    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    typename V::Integer n("3");

    m[0] = typename V::Integer("968");
    m[1] = typename V::Integer("579");
    m[2] = typename V::Integer("4");
    m[3] = typename V::Integer("2343");
    m[4] = typename V::Integer("97");
    CIPHER_DEBUG("m's modulus " << m.get_modulus());

    V calculated_result = m.mod_exp(n);

    uint64_t expected_result[5] = {2792, 3123, 64, 159, 901};

    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_EQ(expected_result[i], calculated_result[i].convert_to_int()) << msg;
    }
}

TEST(UTBinVect, ModExpTest) {
    RUN_ALL_BACKENDS(mod_exp_test, "ModExpTest")
}

template <typename V>
void mod_exp_large_exponent_test(const std::string& msg) {
    typename V::Integer q("7919");  // prime modulus
    typename V::Integer n = q + typename V::Integer(1);

    V m(5, q);
    m[0] = typename V::Integer("2");
    m[1] = typename V::Integer("3");
    m[2] = typename V::Integer("968");
    m[3] = typename V::Integer("0");
    m[4] = typename V::Integer("7918");

    V calculated_result = m.mod_exp(n);

    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_EQ(m[i].mod_exp(n, q), calculated_result[i]) << msg << " vector ModExp disagrees with scalar ModExp";
    }
    EXPECT_EQ(typename V::Integer(4), calculated_result[0]) << msg << " 2^(q+1) mod q";
    EXPECT_EQ(typename V::Integer(9), calculated_result[1]) << msg << " 3^(q+1) mod q";
    EXPECT_EQ(typename V::Integer(0), calculated_result[3]) << msg << " 0^(q+1) mod q";
    EXPECT_EQ(typename V::Integer(1), calculated_result[4]) << msg << " (q-1)^(q+1) mod q";

    V in_place_result(m);
    in_place_result.mod_exp_eq(n);
    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_EQ(calculated_result[i], in_place_result[i]) << msg << " ModExpEq disagrees with ModExp";
    }

    // an exponent aliasing a vector element must be read at its pre-call value
    V aliased_result(m);
    V expected_aliased = m.mod_exp(m[2]);
    aliased_result.mod_exp_eq(aliased_result[2]);
    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_EQ(expected_aliased[i], aliased_result[i]) << msg << " ModExpEq with aliased exponent";
    }
}

TEST(UTBinVect, ModExpLargeExponentTest) {
    RUN_ALL_BACKENDS(mod_exp_large_exponent_test, "ModExpLargeExponentTest")
}

// --------------- TESTING METHOD MODINVERSE FOR ALL CONDITIONS ---------------

/*   The method "Mod mod_inverse" operates on Big Vector m, BigInteger q
        Returns:  (m^(-1))mod q
                when m and q are co-prime (i,e GCD of m and q is 1)
                and is calculated using extended Eucleadian Algorithm
        and the result is stored in Big Vector calculated_result.
*/
template <typename V>
void test_modinv(const std::string& msg) {
    typename V::Integer q("35");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);

    m.at(0) = typename V::Integer("968");
    m.at(1) = typename V::Integer("579");
    m.at(2) = typename V::Integer("4");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("97");

    V calculated_result = m.mod_inverse();

    uint64_t expected_result[5] = {32, 24, 9, 17, 13};

    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_EQ(expected_result[i], (calculated_result.at(i)).convert_to_int()) << msg;
    }
}

TEST(UTBinVect, test_modinv) {
    RUN_BIG_BACKENDS(test_modinv, "test_modinv")
}

// --------------- TESTING METHOD MODADD FOR ALL CONDITIONS ---------------

/*   The method "Mod Add" operates on Big Vectors m,n BigInteger q
        Returns:  (m+n)mod q, and the result is stored in Big Vector
   calculated_result.
*/

// TEST CASE WHEN NUMBERS AFTER ADDITION ARE SMALLER THAN MODULUS

template <typename V>
void modadd_vector_result_smaller_modulus(const std::string& msg) {
    typename V::Integer q("878870");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    V n(5, q);

    m.at(0) = typename V::Integer("9868");
    m.at(1) = typename V::Integer("5879");
    m.at(2) = typename V::Integer("4554");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("9789");

    n.at(0) = typename V::Integer("4533");
    n.at(1) = typename V::Integer("4549");
    n.at(2) = typename V::Integer("6756");
    n.at(3) = typename V::Integer("1233");
    n.at(4) = typename V::Integer("7897");

    V calculated_result = m.mod_add(n);

    uint64_t expected_result[5] = {14401, 10428, 11310, 3576, 17686};

    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_EQ(expected_result[i], (calculated_result.at(i)).convert_to_int()) << msg;
    }
}

TEST(UTBinVect, modadd_vector_result_smaller_modulus) {
    RUN_BIG_BACKENDS(modadd_vector_result_smaller_modulus, "modadd_vector_result_smaller_modulus")
}

// TEST CASE WHEN NUMBERS AFTER ADDITION ARE GREATER THAN MODULUS

template <typename V>
void modadd_vector_result_greater_modulus(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);
    typename V::Integer q("657");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    V n(5, q);

    m = {"9868", "5879", "4554", "2343", "9789"};

    n = {"4533", "4549", "6756", "1233", "7897"};

    CIPHER_DEBUG("m " << m);
    CIPHER_DEBUG("m mod" << m.get_modulus());
    CIPHER_DEBUG("n " << n);
    CIPHER_DEBUG("n mod " << n.get_modulus());

    V calculated_result = m.mod_add(n);

    CIPHER_DEBUG("result mod " << calculated_result.get_modulus());
    uint64_t expected_result[5] = {604, 573, 141, 291, 604};

    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_EQ(expected_result[i], (calculated_result.at(i)).convert_to_int()) << msg;
    }
}

TEST(UTBinVect, modadd_vector_result_greater_modulus) {
    RUN_BIG_BACKENDS(modadd_vector_result_greater_modulus, "modadd_vector_result_greater_modulus")
}

// --------------- TESTING METHOD ADD EQUALS FOR ALL CONDITIONS ---------------
/*   The operator "Add Equals" operates on Big Vectors m,n BigInteger q
        Returns:  (m+n)mod q, and the result is stored in Big Vector a.
*/
template <typename V>
void method_add_equals_vector_operation(const std::string& msg) {
    CIPHER_DEBUG_FLAG(false);
    typename V::Integer q("657");
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    V n(5, q);

    m = {"9868", "5879", "4554", "2343", "9789"};

    // note at does not allow uses of modulus.
    n.at(0) = typename V::Integer("4");
    n.at(1) = typename V::Integer("9");
    n.at(2) = typename V::Integer("66");
    n.at(3) = typename V::Integer("33");
    n.at(4) = typename V::Integer("7");

    CIPHER_DEBUG("m " << m);
    CIPHER_DEBUG("n " << n);

    m += n;
    CIPHER_DEBUG("m" << m);
    uint64_t expected_result[5] = {17, 632, 21, 405, 598};

    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_EQ(expected_result[i], (m.at(i)).convert_to_int()) << msg;
    }
}

TEST(UTBinVect, method_add_equals_vector_operation) {
    RUN_BIG_BACKENDS(method_add_equals_vector_operation, "method_add_equals_vector_operation")
}

// --------------- TESTING METHOD MODMUL FOR ALL CONDITIONS ---------------

/*   The operator "Mod Mul" operates on Big Vectors m,n BigInteger q
        Returns:  (m*n)mod q, and the result is stored in Big Vector a.
*/

template <typename V>
void modmul_vector(const std::string& msg) {
    typename V::Integer q("657");  // constructor calling to set mod value
    // calling constructor to create a vector of length 5 and passing value of q
    V m(5, q);
    V n(5, q);

    m.at(0) = typename V::Integer("9868");
    m.at(1) = typename V::Integer("5879");
    m.at(2) = typename V::Integer("4554");
    m.at(3) = typename V::Integer("2343");
    m.at(4) = typename V::Integer("9789");

    n.at(0) = typename V::Integer("4");
    n.at(1) = typename V::Integer("9");
    n.at(2) = typename V::Integer("66");
    n.at(3) = typename V::Integer("33");
    n.at(4) = typename V::Integer("7");

    V calculated_result = m.mod_mul(n);

    uint64_t expected_result[5] = {52, 351, 315, 450, 195};

    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_EQ(expected_result[i], (calculated_result.at(i)).convert_to_int()) << msg;
    }
}

TEST(UTBinVect, modmul_vector) {
    RUN_BIG_BACKENDS(modmul_vector, "modmul_vector")
}
