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

/**
 * WARNING FOR PARAMETER SELECTION IN GENERIC SAMPLER
 *
 * MAKE SURE THAT PRECISION - BERNOULLI FLIPS IS ALWAYS DIVISIBLE BY LOG_BASE
 * WHEN CHOOSING A STANDARD DEVIATION SIGMA_B FOR BASE SAMPLER, MAKE SURE THAT
 * SIGMA_B>=4*SQRT(2)*N WHERE N IS THE SMOOTHING PARAMETER
 * */

#include "cipher/math/discrete_gaussian_gen_generic.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <memory>
#include <random>
#include <vector>

#include "cipher/util/exception.h"
#include "cipher/util/inttypes.h"

namespace cipher {

// const double DG_ERROR = 8.27181e-25;
// const int32_t N_MAX = 16384;
// const double SIGMA = std::sqrt(std::log(2 * N_MAX / DG_ERROR) / M_PI);
// const int32_t PRECISION = 128;
// const double TAIL_CUT = std::sqrt(log(2)*2*(double)(PRECISION));
// const int32_t DDG_DEPTH = 13;
const int32_t MAX_TREE_DEPTH = 64;

const int32_t PRECISION = 53;
const int32_t BERNOULLI_FLIPS = 23;

BaseSampler::BaseSampler(double mean, double std, BitGenerator* generator, BaseSamplerType type)
    : b_mean(mean), b_std(std), bg(generator), b_type(type) {
    double acc = 1e-17;
    fin = static_cast<int>(std::ceil(b_std * std::sqrt(-2 * std::log(acc))));
    if (mean >= 0)
        b_mean = std::floor(mean);
    else
        b_mean = std::ceil(mean);

    mean = mean - b_mean * 1.0;
    if (b_type == PEIKERT)
        initialize(mean);
    else
        generate_prob_matrix(b_std, mean);
}
int64_t BaseSampler::generate_integer() {
    if (b_type == PEIKERT)
        return generate_integer_peikert();
    else
        return generate_integer_knuth_yao();
}
/**
 *Generates the probability matrix of given distribution, which is used in
 *Knuth-Yao method
 */
void BaseSampler::generate_prob_matrix(double stddev, double mean) {
    /*if (DDGColumn != nullptr) {
          delete[] DDGColumn;
  }*/
    std::vector<uint64_t> prob_matrix;
    b_matrix_size = 2 * fin + 1;
    hamming_weights.resize(64, 0);
    prob_matrix.resize(b_matrix_size);
    std::vector<double> probs(b_matrix_size);
    double S = 0.0;
    b_std = stddev;
    double error = 1.0;
    for (int i = -1 * fin; i <= fin; i++) {
        double prob = std::pow(M_E, -std::pow((i - mean), 2) / (2. * stddev * stddev));
        S += prob;
        probs[i + fin] = prob;
    }
    prob_matrix[b_matrix_size - 1] = error * std::pow(2, 64);
    for (int i = 0; i < b_matrix_size; i++) {
        error -= probs[i] * (1.0 / S);
        prob_matrix[i] = probs[i] * (1.0 / S) * /*(1<<64)*/ std::pow(2, 64);
        for (int j = 0; j < 64; j++) {
            hamming_weights[j] += ((prob_matrix[i] >> (63 - j)) & 1);
        }
    }
    generate_ddg_tree(prob_matrix);
}

void BaseSampler::generate_ddg_tree(const std::vector<uint64_t>& prob_matrix) {
    for (unsigned int i = 0; i < prob_matrix.size(); i++) {
    }
    first_non_zero = -1;
    for (int i = 0; i < 64 && first_non_zero == -1; i++)
        if (hamming_weights[i] != 0)
            first_non_zero = i;
    end_index = first_non_zero;
    int32_t i_node_count = 1;
    for (int i = 0; i < first_non_zero; i++) {
        i_node_count *= 2;
    }
    bool end = false;
    unsigned int max_node_count = i_node_count;
    for (int i = first_non_zero; i < MAX_TREE_DEPTH && !end; i++) {
        i_node_count *= 2;
        end_index++;
        if ((uint32_t)i_node_count >= max_node_count)
            max_node_count = i_node_count;
        i_node_count -= hamming_weights[i];
        if (i_node_count <= 0) {
            end = true;
            if (i_node_count < 0) {
                end_index--;
            }
        }
    }

    uint64_t size = max_node_count; /*1 << (depth + 1)*/
    ddg_tree.resize(size);

    for (unsigned int i = 0; i < size; i++) {
        ddg_tree[i].resize(end_index - first_non_zero, -2);
    }
    i_node_count = 1;
    for (int i = 0; i < first_non_zero; i++) {
        i_node_count *= 2;
    }

    for (int i = first_non_zero; i < end_index; i++) {
        i_node_count *= 2;
        i_node_count -= hamming_weights[i];
        for (unsigned int j = 0; j < (uint32_t)i_node_count; j++) {
            ddg_tree[j][i - first_non_zero] = -1;
        }
        uint32_t e_node_count = 0;
        for (int j = 0; j < b_matrix_size && e_node_count != hamming_weights[i]; j++) {
            if ((prob_matrix[j] >> (63 - i)) & 1) {
                ddg_tree[i_node_count + e_node_count][i - first_non_zero] = j;
                e_node_count++;
            }
        }
    }
}

int64_t BaseSampler::generate_integer_knuth_yao() {
    int64_t ans = -1;
    bool hit = false;

    while (!hit) {
        uint32_t node_index = 0;
        // int64_t nodeCount = 1;
        bool error = false;
        for (int i = 0; i < MAX_TREE_DEPTH && !hit && !error; i++) {
            short bit = bg->generate();  // NOLINT
            node_index *= 2;
            // nodeCount *= 2;
            if (bit) {
                node_index += 1;
            }
            if (first_non_zero <= i) {
                if (i <= end_index) {
                    ans = ddg_tree[node_index][i - first_non_zero];
                }
                if (ans >= 0) {
                    if (ans != b_matrix_size - 1)
                        hit = true;
                    else
                        error = true;
                } else {
                    if (ans == -2) {
                        error = true;
                    }
                }
            }
        }
    }

    return (ans - fin + b_mean);
}

void BaseSampler::initialize(double mean) {
    vals_.clear();
    double variance = b_std * b_std;

    // this value of fin (M) corresponds to the limit for double precision
    // usually the bound of std_ * M is used, whe re M = 20 .. 40 - see DG14 for
    // details M = 20 corresponds to 1e-87
    // double mr = 20; // see DG14 for details
    // int fin = (int)ceil(std_ * mr);
    double cusum = 0.0;
    for (int x = -1 * fin; x <= fin; x++) {
        cusum = cusum + std::exp(-(x - mean) * (x - mean) / (variance * 2));
    }

    b_a = 1 / cusum;

    double temp;

    vals_.reserve(2 * fin + 2);
    for (int i = -1 * fin; i <= fin; i++) {
        temp = b_a * std::exp(-(static_cast<double>((i - mean) * (i - mean) / (2 * variance))));
        vals_.push_back(temp);
    }

    // take cumulative summation
    for (uint32_t i = 1; i < vals_.size(); i++) {
        vals_[i] += vals_[i - 1];
    }
}

int64_t BaseSampler::generate_integer_peikert() const {
    std::uniform_real_distribution<double> distribution(0.0, 1.0);

    int64_t val = 0;
    double seed;
    int32_t ans = 0;
    // TODO (dsuponit): this function should be reviewed as you may not hide caught exceptions
    try {
        // we need to use the binary uniform generator rathen than regular
        // continuous distribution; see DG14 for details
        seed = distribution(PseudoRandomNumberGenerator::get_prng());
        val = find_in_vector(vals_, seed);
        ans = val;
    } catch (std::exception& e) {
    }
    return ans - fin + b_mean;
}

uint32_t BaseSampler::find_in_vector(const std::vector<double>& S, double search) const {
    // STL binary search implementation
    auto lower = std::lower_bound(S.begin(), S.end(), search);
    if (lower != S.end())
        return lower - S.begin();

    CIPHER_THROW("DGG Inversion Sampling. find_in_vector value not found: " + std::to_string(search));
}

DiscreteGaussianGeneratorGeneric::DiscreteGaussianGeneratorGeneric(BaseSampler** samplers, const double std,
                                                                   const int b, double N) {
    // Precomputations for sigma bar
    int x1, x2;
    base_samplers = samplers;
    log_base = b;
    double base_variance = std * std;
    // SampleI Non-base case
    wide_sampler = samplers[0];
    wide_variance = base_variance;
    for (int i = 1; i < MAX_LEVELS; ++i) {
        x1 = static_cast<int>(std::floor(std::sqrt(wide_variance / (2 * N * N))));
        x2 = std::max(x1 - 1, 1);
        combiners[i - 1] = std::make_unique<SamplerCombiner>(wide_sampler, wide_sampler, x1, x2);
        wide_sampler = combiners[i - 1].get();
        wide_variance = (x1 * x1 + x2 * x2) * wide_variance;
    }

    k = static_cast<int>(std::ceil(static_cast<double>(PRECISION - BERNOULLI_FLIPS) / log_base));
    mask = (1UL << log_base) - 1;

    // compute rr_sigma2
    sampler_variance = 1;
    long double t = 1.0 / (1UL << (2 * log_base));
    long double s = 1;
    for (int i = 1; i < k; ++i) {
        s *= t;
        sampler_variance += s;
    }
    sampler_variance *= base_variance;
}

DiscreteGaussianGeneratorGeneric::~DiscreteGaussianGeneratorGeneric() = default;

// SampleZ
int64_t DiscreteGaussianGeneratorGeneric::generate_integer(double center, double std) {
    double variance = std * std;
    // SampleI Base Case
    x = wide_sampler->generate_integer();

    // Center perturbation
    c = center + x * (std::sqrt((variance - sampler_variance) / wide_variance));

    ci = std::floor(c);
    c -= ci;

    return (int64_t)ci + flip_and_round(c);
}
// Part of sample_c
int64_t DiscreteGaussianGeneratorGeneric::flip_and_round(double center) {
    int64_t c = (int64_t)(center * (1ULL << PRECISION));
    int64_t base_c = (c >> BERNOULLI_FLIPS);
    short random_bit_value;  // NOLINT

    // Rounding the center based on the coin flip
    for (int i = BERNOULLI_FLIPS - 1; i >= 0; --i) {
        random_bit_value = base_samplers[0]->random_bit();
        if (random_bit_value > extract_bit(c, i))
            return sample_c((int64_t)base_c);
        if (random_bit_value < extract_bit(c, i))
            return sample_c((int64_t)(base_c + 1));
    }
    return sample_c((int64_t)base_c + 1);
}

// sample_c defined in the UCSD paper
int64_t DiscreteGaussianGeneratorGeneric::sample_c(int64_t center) {
    int64_t c;
    c = center;
    int64_t sample;
    for (int i = 0; i < k; ++i) {
        sample = base_samplers[mask & c]->generate_integer();
        if ((mask & c) > 0 && c < 0)
            sample -= 1;
        for (int j = 0; j < log_base; ++j) {
            c /= 2;
        }
        c += sample;
    }
    return c;
}

}  // namespace cipher
