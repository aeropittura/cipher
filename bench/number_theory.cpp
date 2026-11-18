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
 * This code benchmarks number theory operations.
 */

#define _USE_MATH_DEFINES
#include <cstdint>
#include <iostream>
#include <set>
#include <sstream>
#include <string>

#include "benchmark/benchmark.h"
#include "cipher/ring/backend.h"

using namespace cipher;

//==================================
// GCD benchmarks

// this benchmark returns a reference to a BBI which can be used for output
static BigInteger gcd_equals_small_numbers(void) {  // function
    BigInteger a("10403"), b("103");
    BigInteger c(cipher::greatest_common_divisor(a, b));
    return (c);
}

// this benchmark sets the output label with a result from the function
static void BM_GCD1(benchmark::State& state) {  // benchmark
    int out = 0;
    while (state.KeepRunning()) {
        benchmark::DoNotOptimize(gcd_equals_small_numbers());
    }
    // Prevent compiler optimizations (note I haven't seen the complier optimize
    // code out if we leave this out... )
    std::stringstream ss;
    ss << out;
    state.SetLabel(ss.str().c_str());  // label attached to output
}

BENCHMARK(BM_GCD1);  // register benchmark

// this benchmark returns an int. In some cases the return BBI value
// cannot be converted to an int (too big) so you need to return a
// reference to the BBI instead. this time we can use an int.
static int gcd_equals_powers_of_two_numbers(void) {
    BigInteger a("1048576"), b("4096");
    BigInteger c(cipher::greatest_common_divisor(a, b));
    return (c.convert_to_int());
}

static void BM_GCD2(benchmark::State& state) {  // benchmark
    int out = 0;
    while (state.KeepRunning()) {
        out = gcd_equals_powers_of_two_numbers();
    }
    // Prevent compiler optimizations
    std::stringstream ss;
    ss << out;
    state.SetLabel(ss.str().c_str());
}

BENCHMARK(BM_GCD2);  // register benchmark

//===================================================
// the following benchmark miller_rabin_primality_test for various inputs
//
// returns boolean
static bool mrp_is_prime_small_prime(void) {  // function
    BigInteger prime("24469");
    return (cipher::miller_rabin_primality_test(prime));
}

static void BM_MRP1(benchmark::State& state) {  // benchmark
    int out = 0;
    while (state.KeepRunning()) {
        out = mrp_is_prime_small_prime();
    }
    // Prevent compiler optimizations
    std::stringstream ss;
    ss << out;
    state.SetLabel(ss.str().c_str());
}

BENCHMARK(BM_MRP1);  // register benchmark

//
static bool mrp_is_prime_big_prime(void) {  // function
    BigInteger prime("952229140957");
    return (cipher::miller_rabin_primality_test(prime));
}

static void BM_MRP2(benchmark::State& state) {  // benchmark
    bool out = 0;
    while (state.KeepRunning()) {
        out = mrp_is_prime_big_prime();
    }
    // Prevent compiler optimizations
    std::stringstream ss;
    ss << out;
    state.SetLabel(ss.str().c_str());
}

BENCHMARK(BM_MRP2);  // register benchmark

//
static bool mrp_is_not_prime_small_composite_number(void) {  // function
    BigInteger is_not_prime("10403");
    return (cipher::miller_rabin_primality_test(is_not_prime));
}

static void BM_MRP3(benchmark::State& state) {  // benchmark
    bool out = 0;
    while (state.KeepRunning()) {
        out = mrp_is_not_prime_small_composite_number();
    }
    // Prevent compiler optimizations
    std::stringstream ss;
    ss << out;
    state.SetLabel(ss.str().c_str());
}

BENCHMARK(BM_MRP3);  // register benchmark

//
static bool mrp_is_not_prime_big_composite_number(void) {  // function
    BigInteger is_not_prime("952229140959");
    return (cipher::miller_rabin_primality_test(is_not_prime));
}

static void BM_MRP4(benchmark::State& state) {  // benchmark
    bool out = 0;
    while (state.KeepRunning()) {
        out = mrp_is_not_prime_big_composite_number();
    }
    // Prevent compiler optimizations
    std::stringstream ss;
    ss << out;
    state.SetLabel(ss.str().c_str());
}

BENCHMARK(BM_MRP4);  // register benchmark

//========================================

// the following does not return anything..
static void factorize_returns_factors(void) {
    BigInteger comp("53093040");
    std::set<BigInteger> factors;
    cipher::prime_factorize(comp, factors);
}

static void BM_FACT1(benchmark::State& state) {
    while (state.KeepRunning()) {
        // note you cannot use benchmark::DoNotOptimize() here because
        // factorize_returns_factors() is a void, it must return a value
        factorize_returns_factors();
    }
}

BENCHMARK(BM_FACT1);  // register benchmark

//======================================
// Prime Modulus tests
//
static BigInteger pm_found_prime_modulus(void) {
    const uint32_t m = 2048;
    const uint32_t n_bits = 30;

    return cipher::first_prime<BigInteger>(n_bits, m);
}

static void BM_PM1(benchmark::State& state) {  // benchmark
    BigInteger out;
    while (state.KeepRunning()) {
        out = pm_found_prime_modulus();
    }
    // Prevent compiler optimizations
    std::stringstream ss;
    ss << out.to_string();
    state.SetLabel(ss.str().c_str());
}

BENCHMARK(BM_PM1);  // register benchmark

#if 0  // this benchmark has not been tested


// note this returns a refrence to BBI
static BigInteger& PM_returns_higher_bit_length(void) {
  uint32_t m = 4096;
  uint32_t n_bits = 49;

  BigInteger prime_modulus = cipher::first_prime<BigInteger>(n_bits, m);
  return prime_modulus;
}

// saving the reference to BBI for output adds some copy overhead
static void BM_PM2(benchmark::State& state) {
  BigInteger out;
  while (state.KeepRunning()) {
    out = PM_returns_higher_bit_length();
  }
  // Prevent compiler optimizations
  std::stringstream ss;
  ss << out.to_string();
  state.SetLabel(ss.str().c_str());
}

BENCHMARK(BM_PM2);  // register benchmark
#endif

// Note this benchmark returns two BBIs so we return a string and suffer
// some overhead
static std::string prou_equals_m_not_equals_mbytwo(void) {
    uint32_t m = 4096;
    uint32_t n_bits = 33;

    BigInteger prime_modulus = cipher::first_prime<BigInteger>(n_bits, m);
    BigInteger primitive_root_of_unity = cipher::root_of_unity<BigInteger>(m, prime_modulus);

    BigInteger M(std::to_string(m)), mby_two(M.divided_by(2));

    BigInteger wpowerm = primitive_root_of_unity.mod_exp(M, prime_modulus);
    BigInteger wpowermbytwo = primitive_root_of_unity.mod_exp(mby_two, prime_modulus);
    return (wpowerm.to_string() + " " + wpowermbytwo.to_string());
}

static void BM_PROU1(benchmark::State& state) {
    std::string out;
    while (state.KeepRunning()) {
        out = prou_equals_m_not_equals_mbytwo();
    }
    // Prevent compiler optimizations
    std::stringstream ss;
    ss << out;
    state.SetLabel(ss.str().c_str());
}
BENCHMARK(BM_PROU1);  // register benchmark

#if 0  // this takes a long time to run so comment out for quick check
// similarly this outputs 3 values with a string
static std::string PROU_equals_m_not_equals_mbytwo_mbyfour_single_input(void) {
  const uint32_t n = 2048;
  const uint32_t m = 2*n;
  const uint32_t n_bits = 43;
  const int ITERATIONS = m*2;

  BigInteger M(std::to_string(m)),
    mby_two(M.divided_by(BigInteger::TWO)),
    mby_four(mby_two.divided_by(BigInteger::TWO));

  BigInteger prime_modulus = cipher::first_prime<BigInteger>(n_bits, m);

  BigInteger wpowerm("0");
  BigInteger wpowermbytwo("0");
  BigInteger wpowermbyfour("0");

  for (int i = 0; i < ITERATIONS; i++) {
    BigInteger primitive_root_of_unity = cipher::root_of_unity<BigInteger>(m, prime_modulus);

    wpowerm = primitive_root_of_unity.mod_exp(M, prime_modulus);
    wpowermbytwo = primitive_root_of_unity.mod_exp(mby_two, prime_modulus);
    wpowermbyfour = primitive_root_of_unity.mod_exp(mby_four, prime_modulus);
  }
  return(wpowerm.to_string() +  " " +
      wpowermbytwo.to_string() +  " " +
      wpowermbyfour.to_string());
}


static void BM_PROU2(benchmark::State& state) {
  std::string out;
  while (state.KeepRunning()) {
    out = PROU_equals_m_not_equals_mbytwo_mbyfour_single_input();
  }
  // Prevent compiler optimizations
  std::stringstream ss;
  ss << out;
  state.SetLabel(ss.str().c_str());
}

BENCHMARK(BM_PROU2);
#endif

// similarly this outputs 3 values with a string
static std::string prou_equals_m_not_equals_mbytwo_mbyfour_multiple_inputs(void) {
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
            // const uint32_t BIT_LENGTH = 200 and const uint32_t FRAGMENTATION_FACTOR = 27
            // ,2048, 51
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

    uint32_t n, q_bits, m;
    BigInteger wpowerm("0");
    BigInteger wpowermbytwo("0");
    BigInteger wpowermbyfour("0");

    for (int i = 2; i < length; i += 2) {
        n = nq_bits_array[i];
        q_bits = nq_bits_array[i + 1];
        m = 2 * n;

        BigInteger M(std::to_string(m)), mby_two(M.divided_by(2)), mby_four(mby_two.divided_by(2));

        BigInteger prime_modulus = cipher::first_prime<BigInteger>(q_bits, m);
        BigInteger primitive_root_of_unity(cipher::root_of_unity<BigInteger>(m, prime_modulus));
        wpowerm = primitive_root_of_unity.mod_exp(M, prime_modulus);
        wpowermbytwo = primitive_root_of_unity.mod_exp(mby_two, prime_modulus);
        wpowermbyfour = primitive_root_of_unity.mod_exp(mby_four, prime_modulus);
    }
    return (wpowerm.to_string() + " " + wpowermbytwo.to_string() + " " + wpowermbyfour.to_string());
}

static void BM_PROU3(benchmark::State& state) {  // benchmark
    std::string out;
    while (state.KeepRunning()) {
        out = prou_equals_m_not_equals_mbytwo_mbyfour_multiple_inputs();
    }
    // Prevent compiler optimizations
    std::stringstream ss;
    ss << out;
    state.SetLabel(ss.str().c_str());
}

BENCHMARK(BM_PROU3);  // register benchmark

// execute the benchmarks
BENCHMARK_MAIN();
