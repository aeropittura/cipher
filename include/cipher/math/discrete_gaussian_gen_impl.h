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
  This code provides generation of gaussian distributions of discrete values. Discrete uniform generator relies on
  the built-in C++ generator for 32-bit unsigned integers defined in <random>
 */

#ifndef CIPHER_MATH_DISCRETE_GAUSSIAN_GEN_IMPL_H_
#define CIPHER_MATH_DISCRETE_GAUSSIAN_GEN_IMPL_H_

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "cipher/math/discrete_gaussian_gen.h"
#include "cipher/util/exception.h"

namespace cipher {

template <typename VecType>
DiscreteGaussianGeneratorImpl<VecType>::DiscreteGaussianGeneratorImpl(double std) {
    set_std(std);
}

template <typename VecType>
bool DiscreteGaussianGeneratorImpl<VecType>::is_initialized() const {
    return std_ > 1.000000001;
}

template <typename VecType>
void DiscreteGaussianGeneratorImpl<VecType>::set_std(double std) {
    if (std::log2((std_ = std)) > 59)
        CIPHER_THROW("Standard deviation cannot exceed 59 bits");
    if ((peikert_ = (std_ < KARNEY_THRESHOLD)))
        this->Initialize();
}

template <typename VecType>
double DiscreteGaussianGeneratorImpl<VecType>::get_std() const {
    return std_;
}

template <typename VecType>
void DiscreteGaussianGeneratorImpl<VecType>::Initialize() {
    // usually the bound of std_ * M is used, where M = 12 .. 40
    // we use M = std::sqrt(-2. * std::log(5e-32)) = 12.0061 here,
    // which corresponds to the probability of roughly 2^(-100)
    double M{12.00610553538285};
    int64_t fin{static_cast<int64_t>(std::ceil(std_ * M))};
    vals_.resize(fin);
    double variance{2 * std_ * std_};
    double cusum{0.0};
    for (int64_t x = 1; x <= fin; ++x)
        vals_[x - 1] = (cusum += std::exp(-(static_cast<double>(x * x) / variance)));
    a_ = 1.0 / (2 * cusum + 1.0);
    for (int64_t x = 0; x < fin; ++x)
        vals_[x] *= a_;
}

template <typename VecType>
int64_t DiscreteGaussianGeneratorImpl<VecType>::find_in_vector(const std::vector<double>& S, double search) {
    // STL binary search implementation
    auto lower = std::lower_bound(S.begin(), S.end(), search);
    if (lower != S.end())
        return lower - S.begin() + 1;
    CIPHER_THROW("DGG Inversion Sampling. FindInVector value not found: " + std::to_string(search));
}

template <typename VecType>
int64_t DiscreteGaussianGeneratorImpl<VecType>::generate_int() const {
    return generate_int(PseudoRandomNumberGenerator::get_prng());
}

template <typename VecType>
int64_t DiscreteGaussianGeneratorImpl<VecType>::generate_int(PRNG& g) const {
    // we need to use the binary uniform generator rather than regular continuous
    // distribution; see DG14 for details
    double seed = std::uniform_real_distribution<double>(0.0, 1.0)(g) - 0.5;
    double tmp = std::abs(seed) - a_ / 2;
    return (tmp <= 0.0) ? 0 : find_in_vector(vals_, tmp) * (seed > 0.0 ? 1 : -1);
}

template <typename VecType>
std::vector<int64_t> DiscreteGaussianGeneratorImpl<VecType>::generate_int_vector(uint32_t size) const {
    std::vector<int64_t> ans(size);
    auto& g = PseudoRandomNumberGenerator::get_prng();
    for (uint32_t i = 0; i < size; ++i)
        ans[i] = peikert_ ? generate_int(g) : generate_integer_karney(0, std_, g);
    return ans;
}

template <typename VecType>
typename VecType::Integer DiscreteGaussianGeneratorImpl<VecType>::generate_integer(
        const typename VecType::Integer& modulus) const {
    auto val = peikert_ ? generate_int() : generate_integer_karney(0, std_);
    return (val < 0) ? modulus - typename VecType::Integer(-val) : typename VecType::Integer(val);
}

template <typename VecType>
VecType DiscreteGaussianGeneratorImpl<VecType>::generate_vector(uint32_t size,
                                                                const typename VecType::Integer& modulus) const {
    VecType ans(size, modulus);
    auto& g = PseudoRandomNumberGenerator::get_prng();
    for (uint32_t i = 0; i < size; ++i) {
        auto val = peikert_ ? generate_int(g) : generate_integer_karney(0, std_, g);
        ans[i] = (val < 0) ? modulus - typename VecType::Integer(-val) : typename VecType::Integer(val);
    }
    return ans;
}

template <typename VecType>
typename VecType::Integer DiscreteGaussianGeneratorImpl<VecType>::generate_integer(
        double mean, double stddev, size_t n, const typename VecType::Integer& modulus) const {
    double t = std::log2(n) * stddev;

    std::uniform_int_distribution<int32_t> uniform_int(std::floor(mean - t), std::ceil(mean + t));
    std::uniform_real_distribution<double> uniform_real(0.0, 1.0);

    int32_t x;
    do {
        x = uniform_int(PseudoRandomNumberGenerator::get_prng());
    } while (uniform_real(PseudoRandomNumberGenerator::get_prng()) > unnormalized_gaussian_pdf(mean, stddev, x));

    if (x < 0)
        return modulus - typename VecType::Integer(-x);
    return typename VecType::Integer(x);
}

template <typename VecType>
int32_t DiscreteGaussianGeneratorImpl<VecType>::generate_integer(double mean, double stddev, size_t n) const {
    if (std::isinf(mean))
        CIPHER_THROW("DiscreteGaussianGeneratorImpl called with mean == +-inf");
    if (std::isinf(stddev))
        CIPHER_THROW("DiscreteGaussianGeneratorImpl called with stddev == +-inf");

    // this representation of log_2 is used for Visual Studio
    double t = std::log2(n) * stddev;
    std::uniform_int_distribution<int32_t> uniform_int(std::floor(mean - t), std::ceil(mean + t));
    std::uniform_real_distribution<double> uniform_real(0.0, 1.0);

    double sigma_factor = 1 / (-2. * stddev * stddev);
    uint32_t count = 0;
    const uint32_t limit = 10000;

    int32_t x;
    bool flag_success = false;
    while (!flag_success) {
        //  pick random int
        x = uniform_int(PseudoRandomNumberGenerator::get_prng());
        //  roll the uniform dice
        auto dice = uniform_real(PseudoRandomNumberGenerator::get_prng());
        //  check if dice land below pdf
        flag_success = (dice <= unnormalized_gaussian_pdf_optimized(mean, sigma_factor, x));
        if (++count > limit)
            CIPHER_THROW("GenerateInteger could not find success after repeated attempts");
    }
    return x;
}

template <typename VecType>
int64_t DiscreteGaussianGeneratorImpl<VecType>::generate_integer_karney(double mean, double stddev) {
    return generate_integer_karney(mean, stddev, PseudoRandomNumberGenerator::get_prng());
}

template <typename VecType>
int64_t DiscreteGaussianGeneratorImpl<VecType>::generate_integer_karney(double mean, double stddev, PRNG& g) {
    std::uniform_int_distribution<int64_t> uniform_sign(0, 1);
    std::uniform_int_distribution<int64_t> uniform_j(0, std::ceil(stddev) - 1);

    while (true) {
        // STEP D1
        int32_t k = algorithm_g(g);

        // STEP D2
        if (!algorithm_p(g, k * (k - 1)))
            continue;

        // STEP D3
        int64_t s = uniform_sign(g);
        if (s == 0)
            s = -1;

        // STEP D4
        double di0 = stddev * k + s * mean;
        int64_t i0 = std::ceil(di0);
        double x0 = (i0 - di0) / stddev;
        int64_t j = uniform_j(g);

        double x = x0 + j / stddev;

        // STEPS D5 and D6
        if (!(x < 1) || (x == 0 && s < 0 && k == 0))
            continue;

        // STEP D7
        int32_t h = k + 1;
        while (h-- && algorithm_b(g, k, x)) {
        }
        if (!(h < 0))
            continue;

        // STEP D8
        return (s * (i0 + j));
    }
}

template <typename VecType>
bool DiscreteGaussianGeneratorImpl<VecType>::algorithm_p(PRNG& g, int n) {
    while (n-- && algorithm_h(g)) {
    }
    return n < 0;
}

template <typename VecType>
int32_t DiscreteGaussianGeneratorImpl<VecType>::algorithm_g(PRNG& g) {
    int n = 0;
    while (algorithm_h(g))
        ++n;
    return n;
}

// Use single floating-point precision in most cases; if a situation w/ not
// enough precision is encountered, call the double-precision algorithm
template <typename VecType>
bool DiscreteGaussianGeneratorImpl<VecType>::algorithm_h(PRNG& g) {
    std::uniform_real_distribution<float> dist(0, 1);
    float h_a, h_b;
    h_a = dist(g);

    // less than the half
    if (h_a > 0.5)
        return true;
    if (h_a < 0.5) {
        for (;;) {
            h_b = dist(g);
            if (h_b > h_a)
                return false;
            else if (h_b < h_a)
                h_a = dist(g);
            else  // numbers are equal - need higher precision
                return algorithm_h_double(g);
            if (h_a > h_b)
                return true;
            else if (h_a == h_b)  // numbers are equal - need higher precision
                return algorithm_h_double(g);
        }
    } else {  // numbers are equal - need higher precision
        return algorithm_h_double(g);
    }
}

template <typename VecType>
bool DiscreteGaussianGeneratorImpl<VecType>::algorithm_h_double(PRNG& g) {
    std::uniform_real_distribution<double> dist(0, 1);
    double h_a, h_b;
    h_a = dist(g);
    // less than the half
    if (!(h_a < 0.5))
        return true;
    for (;;) {
        h_b = dist(g);
        if (!(h_b < h_a))
            return false;
        else
            h_a = dist(g);
        if (!(h_a < h_b))
            return true;
    }
}

template <typename VecType>
bool DiscreteGaussianGeneratorImpl<VecType>::algorithm_b(PRNG& g, int32_t k, double x) {
    std::uniform_real_distribution<float> dist(0.0, 1.0);

    float y = x;
    int32_t n = 0, m = 2 * k + 2;
    float z, r;
    float r_temp;

    for (;; ++n) {
        z = dist(g);
        if (z > y) {
            break;
        } else if (z < y) {
            r = dist(g);
            r_temp = (2 * k + x) / m;
            if (r > r_temp)
                break;
            else if (r < r_temp)
                y = z;
            else  // r == Temp - need double precision
                return algorithm_b_double(g, k, x);
        } else {  // z == x - need double precision
            return algorithm_b_double(g, k, x);
        }
    }

    return (n % 2) == 0;
}

template <typename VecType>
bool DiscreteGaussianGeneratorImpl<VecType>::algorithm_b_double(PRNG& g, int32_t k, double x) {
    std::uniform_real_distribution<double> dist(0.0, 1.0);

    double y = x;
    int32_t n = 0, m = 2 * k + 2;
    double z, r;

    for (;; ++n) {
        z = dist(g);
        if (!(z < y))
            break;
        r = dist(g);
        if (!(r < (2 * k + x) / m))
            break;
        y = z;
    }

    return (n % 2) == 0;
}

}  // namespace cipher

#endif  // CIPHER_MATH_DISCRETE_GAUSSIAN_GEN_IMPL_H_
