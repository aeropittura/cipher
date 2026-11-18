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

Use this script to find the correction factor, which gives the best precision for CKKS bootstrapping.
Specifically, we used this to choose the default correction factor for 64-bit FLEXIBLEAUTO and FLEXIBLEAUTOEXT.

*/

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <iostream>
#include <ostream>
#include <random>
#include <vector>

#include "cipher/cipher.h"

#define DOUBLEITTR
#define STCBOOT

using namespace cipher;

constexpr ScalingTechnique rescale_tech = FLEXIBLEAUTOEXT;
// constexpr ScalingTechnique rescale_tech = FIXEDMANUAL;

constexpr uint32_t ringdm = 1 << 12;

double measure_bootstrap_precision(uint32_t num_slots, uint32_t correction_factor);
double measure_st_c_first_bootstrap_precision(uint32_t num_slots, uint32_t correction_factor);
std::vector<double> measure_bootstrap_double_iter_precision(uint32_t num_slots, uint32_t correction_factor);
std::vector<double> measure_st_c_first_bootstrap_double_iter_precision(uint32_t num_slots, uint32_t correction_factor);

// calculate_approximation_error() calculates the precision number (or approximation error).
// The higher the precision, the less the error.
// As recomended in footnote 23 of Security Guidelines for Implementing Homomorphic Encryption
// (https://cic.iacr.org/p/1/4/26/pdf), precision bits are evaluated as the negative
// base 2 logarithm of the average L1 norm between results from standard (cleartext) calculation
// and those computed homomorphically.
double calculate_approximation_error(const std::vector<std::complex<double>>& result,
                                     const std::vector<std::complex<double>>& expected_result) {
    if (result.size() != expected_result.size())
        CIPHER_THROW("Cannot compare vectors with different numbers of elements");

    // using the average
    double acc_error = 0;
    for (size_t i = 0; i < result.size(); ++i)
        acc_error += std::abs(result[i] - expected_result[i]);
    return std::abs(std::log2(acc_error / result.size()));
}

int main(int argc, char* argv[]) {
#if CIPHER_NATIVE_INT == 64
    uint32_t num_iterations = 10;
    uint32_t min_correction_factor = 5;
    uint32_t max_correction_factor = 15;
    std::vector<uint32_t> slots_vec = {1 << 3, 1 << 7, 1 << 9, 1 << 11};
    for (uint32_t num_slots : slots_vec) {
        for (uint32_t correction_factor = min_correction_factor; correction_factor <= max_correction_factor;
             ++correction_factor) {
            std::cout << "`=======================================================================" << std::endl;
            std::cout << "Number of slots: " << num_slots << "\n";
            std::cout << "Correction Factor: " << correction_factor << "\n";

            double precision = 0.0;
    #ifdef DOUBLEITTR
            double precision2 = 0.0;
    #endif
            for (uint32_t i = 0; i < num_iterations; ++i) {
    #ifdef DOUBLEITTR
        #ifdef STCBOOT
                auto precision_vec = measure_st_c_first_bootstrap_double_iter_precision(num_slots, correction_factor);
        #else
                auto precision_vec = measure_bootstrap_double_iter_precision(num_slots, correction_factor);
        #endif
                precision += precision_vec[0];
                precision2 += precision_vec[1];
    #else
        #ifdef STCBOOT
                precision += measure_st_c_first_bootstrap_precision(num_slots, correction_factor);
        #else
                precision += measure_bootstrap_precision(num_slots, correction_factor);
        #endif
    #endif
            }
            precision /= num_iterations;
            std::cout << "Average initial precision over " << num_iterations << " iterations: " << precision << "\n";
    #ifdef DOUBLEITTR
            precision2 /= num_iterations;
            std::cout << "Average META-BTS precision over " << num_iterations << " iterations: " << precision2 << "\n";
    #endif
            std::cout << "`=======================================================================" << std::endl;
        }
    }
#endif
}

double measure_bootstrap_precision(uint32_t num_slots, uint32_t correction_factor) {
    ContextParams<CkksRnsContext> parameters;

    SecretKeyDist secret_key_dist = UNIFORM_TERNARY;
    parameters.set_secret_key_dist(secret_key_dist);

    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(ringdm);

    uint32_t dcrt_bits = 59;
    uint32_t first_mod = 60;
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(rescale_tech);
    parameters.set_first_mod_size(first_mod);

    std::vector<uint32_t> level_budget = {3, 3};
    uint32_t approx_bootstrap_depth = 9;
    std::vector<uint32_t> bsgs_dim = {0, 0};
    uint32_t levels_available_after_bootstrap = 10;
    uint32_t depth = levels_available_after_bootstrap +
                     CkksRnsFhe::get_bootstrap_depth(approx_bootstrap_depth, level_budget, secret_key_dist);
    parameters.set_multiplicative_depth(depth);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);
    crypto_context->enable(ADVANCEDSHE);
    crypto_context->enable(FHE);

    crypto_context->eval_bootstrap_setup(level_budget, bsgs_dim, num_slots, correction_factor);

    auto key_pair = crypto_context->key_gen();
    crypto_context->eval_mult_key_gen(key_pair.secret_key);
    crypto_context->eval_bootstrap_key_gen(key_pair.secret_key, num_slots);

    // Generate random input
    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    for (size_t i = 0; i < num_slots; i++) {
        x.push_back(dis(gen));
    }

    Plaintext ptxt = crypto_context->make_ckks_packed_plaintext(x, 1, depth - 1, nullptr, num_slots);
    ptxt->set_length(num_slots);

    Ciphertext<RnsPoly> ciph = crypto_context->encrypt(key_pair.public_key, ptxt);

    auto ciphertext_after = crypto_context->eval_bootstrap(ciph);

    Plaintext result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_after, &result);
    result->set_length(num_slots);

    double precision = calculate_approximation_error(ptxt->get_ckks_packed_value(), result->get_ckks_packed_value());

    crypto_context->clear_static_maps_and_vectors();

    return precision;
}

double measure_st_c_first_bootstrap_precision(uint32_t num_slots, uint32_t correction_factor) {
    ContextParams<CkksRnsContext> parameters;

    SecretKeyDist secret_key_dist = UNIFORM_TERNARY;
    parameters.set_secret_key_dist(secret_key_dist);

    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(ringdm);

    uint32_t dcrt_bits = 59;
    uint32_t first_mod = 60;
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(rescale_tech);
    parameters.set_first_mod_size(first_mod);

    std::vector<uint32_t> level_budget = {3, 3};
    std::vector<uint32_t> bsgs_dim = {0, 0};
    uint32_t levels_available_after_bootstrap = 10 + level_budget[1];
    uint32_t depth =
            levels_available_after_bootstrap + CkksRnsFhe::get_bootstrap_depth({level_budget[0], 0}, secret_key_dist);
    parameters.set_multiplicative_depth(depth);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);
    crypto_context->enable(ADVANCEDSHE);
    crypto_context->enable(FHE);

    crypto_context->eval_bootstrap_setup(level_budget, bsgs_dim, num_slots, correction_factor, true, true);

    auto key_pair = crypto_context->key_gen();
    crypto_context->eval_mult_key_gen(key_pair.secret_key);
    crypto_context->eval_bootstrap_key_gen(key_pair.secret_key, num_slots);

    // Generate random input
    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    for (size_t i = 0; i < num_slots; i++) {
        x.push_back(dis(gen));
    }

    Plaintext ptxt = crypto_context->make_ckks_packed_plaintext(x, 1, depth - 1 - level_budget[1], nullptr, num_slots);
    ptxt->set_length(num_slots);

    Ciphertext<RnsPoly> ciph = crypto_context->encrypt(key_pair.public_key, ptxt);

    auto ciphertext_after = crypto_context->eval_bootstrap(ciph);

    Plaintext result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_after, &result);
    result->set_length(num_slots);

    double precision = calculate_approximation_error(ptxt->get_ckks_packed_value(), result->get_ckks_packed_value());

    crypto_context->clear_static_maps_and_vectors();

    return precision;
}

std::vector<double> measure_bootstrap_double_iter_precision(uint32_t num_slots, uint32_t correction_factor) {
    ContextParams<CkksRnsContext> parameters;

    SecretKeyDist secret_key_dist = UNIFORM_TERNARY;
    parameters.set_secret_key_dist(secret_key_dist);

    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(ringdm);

    uint32_t dcrt_bits = 59;
    uint32_t first_mod = 60;
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(rescale_tech);
    parameters.set_first_mod_size(first_mod);

    std::vector<uint32_t> level_budget = {3, 3};
    uint32_t approx_bootstrap_depth = 9;
    std::vector<uint32_t> bsgs_dim = {0, 0};
    uint32_t levels_available_after_bootstrap = 10;
    uint32_t depth = levels_available_after_bootstrap +
                     CkksRnsFhe::get_bootstrap_depth(approx_bootstrap_depth, level_budget, secret_key_dist);
    parameters.set_multiplicative_depth(depth);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);
    crypto_context->enable(ADVANCEDSHE);
    crypto_context->enable(FHE);

    crypto_context->eval_bootstrap_setup(level_budget, bsgs_dim, num_slots, correction_factor);

    auto key_pair = crypto_context->key_gen();
    crypto_context->eval_mult_key_gen(key_pair.secret_key);
    crypto_context->eval_bootstrap_key_gen(key_pair.secret_key, num_slots);

    // Generate random input
    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 2.0);
    for (size_t i = 0; i < num_slots; i++) {
        x.push_back(dis(gen));
    }

    Plaintext ptxt = crypto_context->make_ckks_packed_plaintext(x, 1, depth - 1, nullptr, num_slots);
    ptxt->set_length(num_slots);

    Ciphertext<RnsPoly> ciph = crypto_context->encrypt(key_pair.public_key, ptxt);

    auto ciphertext_after = crypto_context->eval_bootstrap(ciph);

    Plaintext result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_after, &result);
    result->set_length(num_slots);

    double precision = calculate_approximation_error(ptxt->get_ckks_packed_value(), result->get_ckks_packed_value());

    // Give buffer for precision to be lower than one measured result.
    const double precision_buffer = 5;
    double precision_used = std::floor(std::max(0.0, precision - precision_buffer));

    // Add num_iterations as a parameter.
    uint32_t num_iterations = 2;
    auto ciphertext_two_iterations = crypto_context->eval_bootstrap(ciph, num_iterations, precision_used);

    Plaintext result_two_iterations;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_two_iterations, &result_two_iterations);
    result_two_iterations->set_length(num_slots);

    double precision_multiple_iterations = calculate_approximation_error(result_two_iterations->get_ckks_packed_value(),
                                                                         ptxt->get_ckks_packed_value());

    crypto_context->clear_static_maps_and_vectors();

    return {precision, precision_multiple_iterations};
}

std::vector<double> measure_st_c_first_bootstrap_double_iter_precision(uint32_t num_slots, uint32_t correction_factor) {
    ContextParams<CkksRnsContext> parameters;

    SecretKeyDist secret_key_dist = UNIFORM_TERNARY;
    parameters.set_secret_key_dist(secret_key_dist);

    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(ringdm);

    uint32_t dcrt_bits = 59;
    uint32_t first_mod = 60;
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(rescale_tech);
    parameters.set_first_mod_size(first_mod);

    std::vector<uint32_t> level_budget = {3, 3};
    uint32_t approx_bootstrap_depth = 9;
    std::vector<uint32_t> bsgs_dim = {0, 0};
    uint32_t levels_available_after_bootstrap = 10;
    uint32_t depth = levels_available_after_bootstrap +
                     CkksRnsFhe::get_bootstrap_depth(approx_bootstrap_depth, level_budget, secret_key_dist);
    parameters.set_multiplicative_depth(depth);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);
    crypto_context->enable(ADVANCEDSHE);
    crypto_context->enable(FHE);

    crypto_context->eval_bootstrap_setup(level_budget, bsgs_dim, num_slots, correction_factor, true, true);

    auto key_pair = crypto_context->key_gen();
    crypto_context->eval_mult_key_gen(key_pair.secret_key);
    crypto_context->eval_bootstrap_key_gen(key_pair.secret_key, num_slots);

    // Generate random input
    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 2.0);
    for (size_t i = 0; i < num_slots; i++) {
        x.push_back(dis(gen));
    }

    Plaintext ptxt = crypto_context->make_ckks_packed_plaintext(x, 1, depth - 1 - level_budget[1], nullptr, num_slots);
    ptxt->set_length(num_slots);

    Ciphertext<RnsPoly> ciph = crypto_context->encrypt(key_pair.public_key, ptxt);

    auto ciphertext_after = crypto_context->eval_bootstrap(ciph);

    Plaintext result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_after, &result);
    result->set_length(num_slots);

    double precision = calculate_approximation_error(ptxt->get_ckks_packed_value(), result->get_ckks_packed_value());

    // Give buffer for precision to be lower than one measured result.
    const double precision_buffer = 5;
    double precision_used = std::floor(std::max(0.0, precision - precision_buffer));

    // Add num_iterations as a parameter.
    uint32_t num_iterations = 2;
    auto ciphertext_two_iterations = crypto_context->eval_bootstrap(ciph, num_iterations, precision_used);

    Plaintext result_two_iterations;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_two_iterations, &result_two_iterations);
    result_two_iterations->set_length(num_slots);

    double precision_multiple_iterations = calculate_approximation_error(result_two_iterations->get_ckks_packed_value(),
                                                                         ptxt->get_ckks_packed_value());

    crypto_context->clear_static_maps_and_vectors();

    return {precision, precision_multiple_iterations};
}
