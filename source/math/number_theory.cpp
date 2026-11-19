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
  This code provides number theory utilities that are not templated by Integer or Vector
 */

#define _USE_MATH_DEFINES

#include <cmath>
#include <cstdint>
#include <set>
#include <vector>

#include "cipher/config.h"
#include "cipher/math/distribution_gen.h"
#include "cipher/math/backend.h"
#include "cipher/math/number_theory.h"
#include "cipher/util/debug.h"
#include "cipher/util/utilities.h"

namespace cipher {

#ifdef CIPHER_WITH_NTL
// native NTL version
NTL::NtlInteger RNG(const NTL::NtlInteger& modulus) {
    return RandomBnd(modulus);
}

// define an NTL native implementation
NTL::NtlInteger greatest_common_divisor(const NTL::NtlInteger& a, const NTL::NtlInteger& b) {
    return GCD(a, b);
}

// NTL native version
bool miller_rabin_primality_test(const NTL::NtlInteger& p, const uint32_t niter) {
    if (p < NTL::NtlInteger(2) || ((p != NTL::NtlInteger(2)) && (p.mod(NTL::NtlInteger(2)) == NTL::NtlInteger(0))))
        return false;
    if (p == NTL::NtlInteger(2) || p == NTL::NtlInteger(3) || p == NTL::NtlInteger(5))
        return true;
    return static_cast<bool>(ProbPrime(p, niter));  // TODO: check to see if niter >maxint
}
#endif

/*
        Finds multiplicative inverse using the Extended Euclid Algorithms
*/
uint32_t mod_inverse(uint32_t a, uint32_t b) {
    // uint32_t b0 = b;
    uint32_t t, q;
    uint32_t x0 = 0, x1 = 1;
    if (b == 1)
        return 1;
    while (a > 1) {
        q = a / b;
        t = b, b = a % b, a = t;
        t = x0, x0 = x1 - q * x0, x1 = t;
    }
    // if (x1 < 0) x1 += b0;
    // TODO: x1 is never < 0

    return x1;
}

uint64_t get_totient(const uint64_t n) {
    std::set<NativeInteger> factors;
    NativeInteger enn(n);
    prime_factorize(enn, factors);

    NativeInteger prime_prod(1);
    NativeInteger numerator(1);
    for (auto& r : factors) {
        numerator = numerator * (r - 1);
        prime_prod = prime_prod * r;
    }

    prime_prod = (enn / prime_prod) * numerator;
    return prime_prod.convert_to_int();
}

std::vector<int> get_cyclotomic_polynomial_recursive(uint32_t m) {
    auto is_prime = [](uint32_t val) {
        if (val % 2 == 0)
            return false;
        for (uint32_t i = 3; i < val; i += 2) {
            if (val % i == 0)
                return false;
        }
        return true;
    };

    auto get_divisible_numbers = [](uint32_t val) {
        std::vector<uint32_t> div;
        div.reserve(val / 2);
        for (uint32_t i = 1; i < val; i++) {
            if (val % i == 0)
                div.push_back(i);
        }
        return div;
    };

    auto poly_mult = [](const std::vector<int>& a, const std::vector<int>& b) {
        uint32_t degree_a(a.size());
        uint32_t degree_b(b.size());
        uint32_t degree_resultant(degree_a + degree_b - 1);
        std::vector<int> product(degree_resultant, 0);
        for (uint32_t i = 0; i < degree_a; ++i) {
            for (uint32_t j = 0; j < degree_b; ++j)
                product[i + j] += a[i] * b[j];
        }
        return product;
    };

    auto poly_quotient = [](const std::vector<int>& dividend, const std::vector<int>& divisor) {
        uint32_t divisor_length(divisor.size());
        uint32_t dividend_length(dividend.size());
        uint32_t runs(dividend_length - divisor_length + 1);
        std::vector<int> quotient(runs + 1);
        std::vector<int> running_dividend_value(dividend);
        for (uint32_t i = 0; i < runs; ++i) {
            // get the highest degree coeff
            int div_const = running_dividend_value[dividend_length - 1];
            uint32_t divisor_ptr = divisor_length - 1;
            for (uint32_t j = 0; j < dividend_length - i - 1; ++j) {
                auto& rdtmp1 = running_dividend_value[dividend_length - 1 - j];
                rdtmp1 = running_dividend_value[dividend_length - 2 - j];
                if (divisor_ptr > j)
                    rdtmp1 -= (divisor[divisor_ptr - 1 - j] * div_const);
            }
            quotient[i + 1] = running_dividend_value[dividend_length - 1];
        }
        // under the assumption that both dividend and divisor are monic
        quotient[0] = 1;
        quotient.pop_back();
        return quotient;
    };

    if (m == 1)
        return std::vector<int>{-1, 1};
    if (m == 2)
        return std::vector<int>{1, 1};
    if (is_prime(m))
        return std::vector<int>(m, 1);

    auto divisible_numbers = get_divisible_numbers(m);

    std::vector<int> product{1};

    for (uint32_t i = 0; i < divisible_numbers.size(); i++) {
        auto P = get_cyclotomic_polynomial_recursive(divisible_numbers[i]);
        product = poly_mult(product, P);
    }

    // make big poly = x^m - 1
    std::vector<int> big_poly(m + 1, 0);
    big_poly[0] = -1;
    big_poly[m] = 1;
    return poly_quotient(big_poly, product);
}

uint32_t find_automorphism_index2n(int32_t i, uint32_t m) {
    if (i == 0) {
        return 1;
    }

    uint32_t n = get_totient(m);
    uint32_t f1, f2;
    if (i < 0) {
        f1 = NativeInteger(5).mod_inverse(m).convert_to_int();
        f2 = NativeInteger(m - 1).mod_inverse(m).convert_to_int();
    } else {
        f1 = 5;
        f2 = m - 1;
    }

    uint32_t i_unsigned = (uint32_t)std::abs(i);

    uint32_t g0 = f1;
    uint32_t g;

    if (i_unsigned < n / 2) {
        g = f1;
        for (size_t j = 1; j < i_unsigned; j++) {
            g = (g * g0) % m;
        }
    } else {
        g = f2;
        for (size_t j = n / 2; j < i_unsigned; j++) {
            g = (g * g0) % m;
        }
    }
    return g;
}

uint32_t find_automorphism_index_cyclic(int32_t i, uint32_t m, uint32_t g) {
    if (i == 0) {
        return 1;
    }

    int32_t n = get_totient(m);
    int32_t i_signed = i % n;
    if (i_signed <= 0) {
        i_signed += n;
    }

    uint32_t i_unsigned = (uint32_t)i_signed;
    uint32_t k = g;
    for (size_t ii = 2; ii < i_unsigned; ii++) {
        k = (k * g) % m;
    }
    return k;
}

uint32_t find_automorphism_index2n_complex(int32_t i, uint32_t m) {
    if (i == 0) {
        return 1;
    } else if (i == (static_cast<int32_t>(m) - 1)) {  // could be true if (i > 0)
        return static_cast<uint32_t>(i);
    }
    if (!is_power_of_two(m))
        CIPHER_THROW("m should be a power of two.");

    // conjugation automorphism
    // generator. the usage of uint64_t prevents occasional integer overflow if the result of (g*g0) is too high
    const uint64_t g0 = (i < 0) ? NativeInteger(5).mod_inverse(m).convert_to_int() : 5;
    uint64_t g = g0;
    uint32_t i_unsigned = static_cast<uint32_t>(std::abs(i));
    for (size_t j = 1; j < i_unsigned; j++) {
        g = (g * g0) & (m - 1);  // Modulus operation [ (g*g0)%m ] using bitwise AND
    }
    return static_cast<uint32_t>(g);
}

void precompute_auto_map(uint32_t n, uint32_t k, std::vector<uint32_t>* precomp) {
    uint32_t m = n << 1;  // cycl_order
    uint32_t logm = std::round(std::log2(m));
    uint32_t logn = std::round(std::log2(n));
    for (uint32_t j = 0; j < n; j++) {
        uint32_t j_tmp = ((j << 1) + 1);
        uint32_t idx = ((j_tmp * k) - (((j_tmp * k) >> logm) << logm)) >> 1;
        uint32_t jrev = reverse_bits(j, logn);
        uint32_t idxrev = reverse_bits(idx, logn);
        (*precomp)[jrev] = idxrev;
    }
}

}  // namespace cipher
