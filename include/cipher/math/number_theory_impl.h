//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
  This code provides number theory utilities
 */

#ifndef CIPHER_MATH_NUMBER_THEORY_IMPL_H_
#define CIPHER_MATH_NUMBER_THEORY_IMPL_H_

#define _USE_MATH_DEFINES

#include <cmath>
#include <cstdint>
#include <limits>
#include <random>
#include <set>
#include <string>
#include <type_traits>
#include <vector>

#include "cipher/math/distribution_gen.h"
#include "cipher/math/number_theory.h"
#include "cipher/util/debug.h"
#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"

namespace cipher {

/**
 * Generates a uniformly random integer in [0, modulus) by drawing 32-bit chunks from the
 * global PRNG and rejecting draws that are not below the modulus.
 *
 * @param modulus the exclusive upper bound
 * @return a uniformly random integer below modulus
 */
template <typename IntType>
static IntType RNG(const IntType& modulus) {
    constexpr uint32_t chunk_min{0};
    constexpr uint32_t chunk_max{std::numeric_limits<uint32_t>::max()};
    constexpr uint32_t chunk_width{std::numeric_limits<uint32_t>::digits};
    static std::uniform_int_distribution<uint32_t> distribution(chunk_min, chunk_max);

    uint32_t chunks_per_value{(modulus.get_msb() - 1) / chunk_width};
    uint32_t shift_chunk{chunks_per_value * chunk_width};
    std::uniform_int_distribution<uint32_t>::param_type bound(chunk_min, (modulus >> shift_chunk).convert_to_int());

    while (true) {
        IntType result{};
        for (uint32_t i{0}, shift{0}; i < chunks_per_value; ++i, shift += chunk_width)
            result += IntType{distribution(PseudoRandomNumberGenerator::get_prng())} << shift;
        result += IntType{distribution(PseudoRandomNumberGenerator::get_prng(), bound)} << shift_chunk;
        if (result < modulus)
            return result;
    }
}
/**
 * A witness function used for the Miller-Rabin primality test.
 *
 * @param a a randomly generated witness between 2 and p-1
 * @param d the odd factor with p-1 = 2^s * d
 * @param s the power of two with p-1 = 2^s * d
 * @param p the number to be tested for primality
 * @return true if p is composite, false if p is likely prime
 */
template <typename IntType>
static bool witness_function(const IntType& a, const IntType& d, uint32_t s, const IntType& p) {
    IntType mod_value = a.mod_exp(d, p);
    bool prev_mod = false;
    for (uint32_t i = 0; i < s; ++i) {
        prev_mod = (mod_value != IntType(1) && mod_value != p - IntType(1));
        mod_value.mod_mul_fast_eq(mod_value, p);
        if (mod_value == IntType(1) && prev_mod)
            return true;
    }
    return (mod_value != IntType(1));
}

/**
 * A helper function to root_of_unity function. This finds a generator of the multiplicative
 * group of a given prime q by random trials against the prime factors of q-1.
 *
 * @param q a prime
 * @return a generator of Z_q^*
 */
template <typename IntType>
static IntType find_generator(const IntType& q) {
    IntType qm1(q - IntType(1));
    IntType qm2(q - IntType(2));
    std::set<IntType> prime_factors;
    prime_factorize<IntType>(qm1, prime_factors);
    uint32_t cnt;
    IntType gen;
    do {
        cnt = 0;
        gen = RNG(qm2) + IntType(1);
        for (auto it = prime_factors.begin(); it != prime_factors.end(); ++it, ++cnt) {
            if (gen.mod_exp(qm1 / (*it), q) == IntType(1))
                break;
        }
    } while (cnt != prime_factors.size());
    return gen;
}

/*
 A helper function for arbitrary cyclotomics. This finds a generator for any
 composite q (cyclic group). Input: BigInteger q (cyclic group). Output: A
 generator of q
 */
template <typename IntType>
IntType find_generator_cyclic(const IntType& q) {
    IntType phi_q(get_totient(q.convert_to_int()));
    IntType phi_q_m1(get_totient(q.convert_to_int()));
    std::set<IntType> prime_factors;
    prime_factorize<IntType>(phi_q, prime_factors);
    uint32_t cnt;
    IntType gen;
    do {
        cnt = 0;
        gen = RNG(phi_q_m1) + IntType(1);  // gen is random in [1, phi(q)]

        // Generator must lie in the group!
        if (greatest_common_divisor<IntType>(gen, q) != IntType(1))
            continue;

        // Order of a generator cannot divide any co-factor
        for (auto it = prime_factors.begin(); it != prime_factors.end(); ++it, ++cnt) {
            if (gen.mod_exp(phi_q / (*it), q) == IntType(1))
                break;
        }
    } while (cnt != prime_factors.size());
    return gen;
}

/*
 A helper function for arbitrary cyclotomics. Checks if g is a generator of q
 (supports any cyclic group, not just prime-modulus groups) Input: Candidate
 generator g and modulus q Output: returns true if g is a generator for q
 */
template <typename IntType>
bool is_generator(const IntType& g, const IntType& q) {
    IntType qm1(get_totient(q.convert_to_int()));
    std::set<IntType> prime_factors;
    prime_factorize<IntType>(qm1, prime_factors);
    uint32_t cnt = 0;
    for (auto it = prime_factors.begin(); it != prime_factors.end(); ++it, ++cnt) {
        if (g.mod_exp(qm1 / (*it), q) == IntType(1))
            break;
    }
    return cnt == prime_factors.size();
}

/*
 finds roots of unity for given input.  Assumes the the input is a power of two.
 Mostly likely does not give correct results otherwise. input:  m as number
 which is cyclotomic(in format of int), modulo which is used to find generator
 (in format of BigInteger)

 output:  root of unity (in format of BigInteger)
 */
template <typename IntType>
IntType root_of_unity(uint32_t m, const IntType& modulo) {
    IntType M(m);
    if ((modulo - IntType(1)).mod(M) != IntType(0)) {
        std::string err_msg =
                "Please provide a primeModulus(q) and a cyclotomic number(m) "
                "satisfying the condition: (q-1)/m is an integer. The values of "
                "primeModulus = " +
                modulo.to_string() + " and m = " + std::to_string(m) + " do not satisfy this condition";
        CIPHER_THROW(err_msg);
    }

    IntType gen = find_generator(modulo);
    IntType result = gen.mod_exp((modulo - IntType(1)).divided_by(M), modulo);
    if (result == IntType(1))
        result = root_of_unity(m, modulo);

    /*
     * At this point, result contains a primitive root of unity. However,
     * we want to return the minimum root of unity, to avoid different
     * crypto contexts having different roots of unity for the same
     * cyclotomic order and moduli. Therefore, we are going to cycle over
     * all primitive roots of unity and select the smallest one (min_ru).
     *
     * To cycle over all primitive roots of unity, we raise the root of
     * unity in result to all the powers that are co-prime to the
     * cyclotomic order. In power-of-two cyclotomics, this will be the
     * set of all odd powers, but here we use a more general routine
     * to support arbitrary cyclotomics.
     *
     */

    IntType mu(modulo.compute_mu());
    IntType x(1);
    x.mod_mul_eq(result, modulo, mu);

    std::vector<IntType> coprimes = get_totient_list<IntType>(m);
    IntType min_ru(x);
    IntType cur_pow_idx(1);
    for (size_t i = 0; i < coprimes.size(); ++i) {
        auto next_pow_idx = coprimes[i];
        IntType diff_pow(next_pow_idx - cur_pow_idx);
        for (IntType j(0); j < diff_pow; j += IntType(1))
            x.mod_mul_eq(result, modulo, mu);
        if (x < min_ru && x != IntType(1))
            min_ru = x;
        cur_pow_idx = next_pow_idx;
    }
    return min_ru;
}

template <typename IntType>
std::vector<IntType> roots_of_unity(uint32_t m, const std::vector<IntType>& moduli) {
    std::vector<IntType> roots_of_unity_value(moduli.size());
    for (size_t i = 0; i < moduli.size(); ++i)
        roots_of_unity_value[i] = root_of_unity(m, moduli[i]);
    return roots_of_unity_value;
}

template <typename IntType>
IntType greatest_common_divisor(const IntType& a, const IntType& b) {
    static const IntType ZERO(0);
    auto a_(a);
    auto b_(b);
    while (b_ != ZERO) {
        auto tmp(b_);
        b_ = a_ % b_;
        a_ = tmp;
    }
    return a_;
}

/*
 The Miller-Rabin Primality Test
 Input: p the number to be tested for primality.
 Output: true if p is prime,
 false if p is not prime
 */
template <typename IntType>
bool miller_rabin_primality_test(const IntType& p, const uint32_t niter) {
    static const IntType ZERO(0);
    static const IntType TWO(2);
    static const IntType THREE(3);
    static const IntType FIVE(5);

    if (p == TWO || p == THREE || p == FIVE)
        return true;
    if (p < TWO || (p.mod(TWO) == ZERO))
        return false;

    IntType d(p - IntType(1));
    uint32_t s(0);
    while (d.mod(TWO) == ZERO) {
        // d.divided_by_eq(TWO);
        d.r_shift_eq(1);
        ++s;
    }
    for (uint32_t i = 0; i < niter; ++i) {
        if (witness_function(RNG(p - THREE).mod_add(TWO, p), d, s, p))
            return false;
    }
    return true;
}

/*
 The Pollard Rho factorization of a number n.
 Input: n the number to be factorized.
 Output: a factor of n.
 */
template <typename IntType>
const IntType pollard_rho_factorization(const IntType& n) {
    if (n.mod(IntType(2)) == IntType(0))
        return IntType(2);
    IntType divisor(1);
    IntType c(RNG(n));
    IntType x(RNG(n));
    IntType xx(x);
    IntType mu(n.compute_mu());
    do {
        x = x.mod_mul(x, n, mu).mod_add(c, n, mu);
        xx = xx.mod_mul(xx, n, mu).mod_add(c, n, mu);
        xx = xx.mod_mul(xx, n, mu).mod_add(c, n, mu);
        divisor = greatest_common_divisor((x > xx) ? x - xx : xx - x, n);
    } while (divisor == IntType(1));
    return divisor;
}

/*
 Recursively factorizes and find the distinct primefactors of a number
 Input: n is the number to be prime factorized,
 prime_factors is a set of prime factors of n.
 */
template <typename IntType>
void prime_factorize(IntType n, std::set<IntType>& prime_factors) {
    if (n == IntType(0) || n == IntType(1))
        return;
    if (miller_rabin_primality_test(n)) {
        prime_factors.insert(n);
        return;
    }

    IntType divisor(pollard_rho_factorization(n));
    prime_factorize(divisor, prime_factors);
    prime_factorize(n / divisor, prime_factors);
}

template <typename IntType>
IntType first_prime(uint32_t n_bits, uint64_t m) {
    if constexpr (std::is_same_v<IntType, NativeInteger>) {
        if (n_bits > MAX_MODULUS_SIZE)
            CIPHER_THROW("Requested bit length " + std::to_string(n_bits) + " exceeds maximum allowed length " +
                          std::to_string(MAX_MODULUS_SIZE));
    }

    IntType M(m);
    IntType q(IntType(1) << n_bits);
    IntType r(q.mod(M));
    IntType q_new(q + IntType(1) - r);
    if (r > IntType(0))
        q_new += M;
    while (!miller_rabin_primality_test(q_new)) {
        if ((q_new += M) < q)
            CIPHER_THROW("Overflow growing candidate");
    }
    return q_new;
}

template <typename IntType>
IntType last_prime(uint32_t n_bits, uint64_t m) {
    if constexpr (std::is_same_v<IntType, NativeInteger>) {
        if (n_bits > MAX_MODULUS_SIZE)
            CIPHER_THROW("Requested bit length " + std::to_string(n_bits) + " exceeds maximum allowed length " +
                          std::to_string(MAX_MODULUS_SIZE));
    }

    IntType M(m);
    IntType q(IntType(1) << n_bits);
    IntType r(q.mod(M));
    IntType q_new(q + IntType(1) - r);
    if (r < IntType(2))
        q_new -= M;
    while (!miller_rabin_primality_test(q_new)) {
        if ((q_new -= M) > q)
            CIPHER_THROW("overflow shrinking candidate");
    }

    if (q_new.get_msb() != n_bits)
        CIPHER_THROW("Requested " + std::to_string(n_bits) + " bits, but returned " + std::to_string(q_new.get_msb()) +
                      ". Please adjust parameters.");

    return q_new;
}

template <typename IntType>
IntType next_prime(const IntType& q, uint64_t m) {
    IntType M(m), q_new(q + M);
    while (!miller_rabin_primality_test(q_new)) {
        if ((q_new += M) < q)
            CIPHER_THROW("Overflow growing candidate");
    }
    return q_new;
}

template <typename IntType>
IntType previous_prime(const IntType& q, uint64_t m) {
    IntType M(m);
    if (q <= M)
        CIPHER_THROW("Overflow shrinking candidate");
    IntType q_new(q - M);
    while (!miller_rabin_primality_test(q_new)) {
        if ((q_new -= M) > q)
            CIPHER_THROW("Overflow shrinking candidate");
    }
    return q_new;
}

template <typename IntType>
IntType next_power_of_two(IntType n) {
    uint32_t result = get_msb(n - 1);
    return result;
}

/*Naive Loop to find coprimes to n*/
template <typename IntType>
std::vector<IntType> get_totient_list(const IntType& n) {
    std::vector<IntType> result;
    static const IntType one(1);
    for (IntType i = one; i < n; i = i + one) {
        if (greatest_common_divisor(i, n) == one)
            result.push_back(i);
    }
    return result;
}

/* Calculate the remainder from polynomial division */
template <typename IntVector>
IntVector poly_mod(const IntVector& dividend, const IntVector& divisor, const typename IntVector::Integer& modulus) {
    auto mu(modulus.compute_mu());
    uint32_t divisor_length(divisor.get_length());
    uint32_t dividend_length(dividend.get_length());
    uint32_t runs(dividend_length - divisor_length + 1);
    IntVector running_dividend_value(dividend);
    for (uint32_t i = 0; i < runs; ++i) {
        // get the highest degree coeff
        auto div_const(running_dividend_value[dividend_length - 1]);
        uint32_t divisor_ptr(divisor_length - 1);
        for (uint32_t j = 0; j < dividend_length - i - 1; j++) {
            auto& rdtmp1 = running_dividend_value[dividend_length - 1 - j];
            rdtmp1 = running_dividend_value[dividend_length - 2 - j];
            if (divisor_ptr > j)
                rdtmp1.mod_sub_eq(divisor[divisor_ptr - 1 - j] * div_const, modulus, mu);
        }
    }

    IntVector result(divisor_length - 1, modulus);
    for (uint32_t i = 0, j = runs; i < divisor_length - 1; ++i, ++j)
        result[i] = running_dividend_value[j];
    return result;
}

template <typename IntVector>
IntVector polynomial_multiplication(const IntVector& a, const IntVector& b) {
    uint32_t degree_a(a.get_length());
    uint32_t degree_b(b.get_length());
    uint32_t degree_resultant(degree_a + degree_b - 1);
    const auto& modulus = a.get_modulus();
    IntVector result(degree_resultant, modulus);
    for (uint32_t i = 0; i < degree_a; i++) {
        for (uint32_t j = 0; j < degree_b; j++) {
            result[i + j].mod_add_eq(a[i] * b[j], modulus);
        }
    }
    return result;
}

template <typename IntVector>
IntVector get_cyclotomic_polynomial(uint32_t m, const typename IntVector::Integer& modulus) {
    auto int_cp = get_cyclotomic_polynomial_recursive(m);
    IntVector result(int_cp.size(), modulus);
    for (uint32_t i = 0; i < int_cp.size(); i++) {
        auto val = int_cp[i];
        if (val > -1) {
            result[i] = typename IntVector::Integer(val);
        } else {
            result[i] = modulus - typename IntVector::Integer(-val);
        }
    }
    return result;
}

template <typename IntVector>
typename IntVector::Integer synthetic_remainder(const IntVector& dividend, const typename IntVector::Integer& a,
                                               const typename IntVector::Integer& modulus) {
    auto mu = modulus.compute_mu();
    auto val = dividend[dividend.get_length() - 1];
    for (int i = dividend.get_length() - 2; i >= 0; --i)
        val = (dividend[i] + a * val).mod(modulus, mu);
    return val;
}

template <typename IntVector>
IntVector synthetic_poly_remainder(const IntVector& dividend, const IntVector& a_list,
                                 const typename IntVector::Integer& modulus) {
    IntVector result(a_list.get_length(), modulus);
    for (uint32_t i = 0; i < a_list.get_length(); ++i)
        result[i] = synthetic_remainder(dividend, a_list[i], modulus);
    return result;
}

template <typename IntVector>
IntVector polynomial_power(const IntVector& input, uint32_t power) {
    uint32_t final_degree = (input.get_length() - 1) * power;
    IntVector final_poly(final_degree + 1, input.get_modulus());
    for (uint32_t i = 0; i < input.get_length(); ++i)
        final_poly[i * power] = input[i];
    return final_poly;
}

template <typename IntVector>
IntVector synthetic_polynomial_division(const IntVector& dividend, const typename IntVector::Integer& a,
                                      const typename IntVector::Integer& modulus) {
    auto mu(modulus.compute_mu());
    uint32_t n(dividend.get_length() - 1);
    IntVector result(n, modulus);
    result[n - 1] = dividend[n];
    auto val(dividend[n]);
    for (int i = n - 1; i > 0; i--) {
        val = (val * a + dividend[i]).mod(modulus, mu);
        result[i - 1] = val;
    }
    return result;
}

}  // namespace cipher

#endif  // CIPHER_MATH_NUMBER_THEORY_IMPL_H_
