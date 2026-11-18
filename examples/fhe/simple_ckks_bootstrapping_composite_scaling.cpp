//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2025, Duality Technologies Inc. and other contributors
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

Example for CKKS bootstrapping with full packing

*/

#include <cmath>
#include <complex>
#include <cstdint>
#include <iostream>
#include <ostream>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

void simple_bootstrap_example();
void simple_bootstrap_st_c_first_example();

int main(int argc, char* argv[]) {
    simple_bootstrap_example();
    simple_bootstrap_st_c_first_example();
}

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

void simple_bootstrap_example() {
    ContextParams<CkksRnsContext> parameters;
    // A. Specify main parameters
    /*  A1) Secret key distribution
     * SPARSE_ENCAPSULATED is recommended for CKKS bootstrapping (probability of failure below 2^-128).
     * UNIFORM_TERNARY, used here, is the distribution of the homomorphic encryption security guidelines;
     * its probability of failure is 2^-67 for N = 2^16 and 2^-27 for N = 2^17 with full packing.
     * SPARSE_TERNARY (original CKKS paper) is discouraged: about 2^-23 for N = 2^16.
     */
    SecretKeyDist secret_key_dist = UNIFORM_TERNARY;
    parameters.set_secret_key_dist(secret_key_dist);

    /*  A2) Desired security level based on FHE standards.
     * In this example, we use the "NotSet" option, so the example can run more quickly with
     * a smaller ring dimension. Note that this should be used only in
     * non-production environments, or by experts who understand the security
     * implications of their choices. In production-like environments, we recommend using
     * HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic for 128-bit, 192-bit,
     * or 256-bit security, respectively. If you choose one of these as your security level,
     * you do not need to set the ring dimension.
     */
    // parameters.set_security_level(HEStd_NotSet);
    // parameters.set_ring_dim(1 << 15);

    /*  A3) Scaling parameters.
     * By default, we set the modulus sizes and rescaling technique to the following values
     * to obtain a good precision and performance tradeoff. We recommend keeping the parameters
     * below unless you are an FHE expert.
     */
    ScalingTechnique rescale_tech = COMPOSITESCALINGAUTO;
    uint32_t dcrt_bits = 98;
    uint32_t first_mod = 100;

    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(rescale_tech);
    parameters.set_first_mod_size(first_mod);

    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(1 << 12);

    uint32_t register_word_size = 64;
    parameters.set_register_word_size(register_word_size);

    /*  A4) Multiplicative depth.
     * The goal of bootstrapping is to increase the number of available levels we have, or in other words,
     * to dynamically increase the multiplicative depth. However, the bootstrapping procedure itself
     * needs to consume a few levels to run. We compute the number of bootstrapping levels required
     * using get_bootstrap_depth, and add it to levels_available_after_bootstrap to set our initial multiplicative
     * depth. We recommend using the input parameters below to get started.
     */
    std::vector<uint32_t> level_budget = {4, 4};

    // Note that the actual number of levels avalailable after bootstrapping before next bootstrapping
    // will be levels_available_after_bootstrap - 1 because an additional level
    // is used for scaling the ciphertext before next bootstrapping (in 64-bit CKKS bootstrapping)
    uint32_t levels_available_after_bootstrap = 10;
    uint32_t depth = levels_available_after_bootstrap + CkksRnsFhe::get_bootstrap_depth(level_budget, secret_key_dist);
    parameters.set_multiplicative_depth(depth);

    // std::cout << "approx_bootstrap_depth = " << approx_bootstrap_depth << std::endl;
    std::cout << "levelBudget[0] = " << level_budget[0] << std::endl;
    std::cout << "levelBudget[1] = " << level_budget[1] << std::endl;
    std::cout << "secretKeyDist = " << secret_key_dist << std::endl;
    std::cout << "depth = " << depth << std::endl;

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);
    crypto_context->enable(ADVANCEDSHE);
    crypto_context->enable(FHE);

    uint32_t ring_dim = crypto_context->get_ring_dimension();
    // This is the maximum number of slots that can be used for full packing.
    uint32_t num_slots = ring_dim / 2;
    std::cout << "CKKS scheme is using ring dimension " << ring_dim << std::endl << std::endl;

    crypto_context->eval_bootstrap_setup(level_budget);

    auto key_pair = crypto_context->key_gen();
    crypto_context->eval_mult_key_gen(key_pair.secret_key);
    crypto_context->eval_bootstrap_key_gen(key_pair.secret_key, num_slots);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
    size_t encoded_length = x.size();

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(crypto_context->get_crypto_parameters());
    uint32_t composite_degree = crypto_params->get_composite_degree();
    // We start with a depleted ciphertext that has used up all of its levels.
    // Plaintext ptxt = crypto_context->make_ckks_packed_plaintext(x, 1, depth - 1);
    Plaintext ptxt = crypto_context->make_ckks_packed_plaintext(x, 1, composite_degree * (depth - 1));

    std::cout << "Composite degree: " << composite_degree
              << " Bit length: " << static_cast<float>(dcrt_bits) / composite_degree
              << " Register size: " << register_word_size << std::endl;

    ptxt->set_length(encoded_length);
    std::cout << "Input: " << ptxt << std::endl;

    Ciphertext<RnsPoly> ciph = crypto_context->encrypt(key_pair.public_key, ptxt);

    std::cout << "Initial number of levels remaining: " << depth - ciph->get_level() / composite_degree << std::endl;

    // Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    // for HE computation.
    auto ciphertext_after = crypto_context->eval_bootstrap(ciph, 1);

    std::cout << "Number of levels remaining after bootstrapping: "
              << depth - ciphertext_after->get_level() / composite_degree -
                         (ciphertext_after->get_noise_scale_deg() - 1)
              << std::endl
              << std::endl;

    std::cout << "Scaling factor after bootstrapping: " << ciphertext_after->get_scaling_factor() << std::endl;

    std::cout << "Composite degree: " << crypto_params->get_composite_degree() << std::endl;
    std::cout << "Modulus bit length: " << static_cast<float>(dcrt_bits) / crypto_params->get_composite_degree()
              << std::endl;
    std::cout << "Word register size: " << register_word_size << std::endl;

    Plaintext result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_after, &result);
    result->set_length(encoded_length);
    std::cout << "Output after bootstrapping \n\t" << result << std::endl;

    auto actual_result = result->get_ckks_packed_value();
    double precision = calculate_approximation_error(actual_result, ptxt->get_ckks_packed_value());
    std::cout << "Estimated precision: " << precision << std::endl;
}

void simple_bootstrap_st_c_first_example() {
    ContextParams<CkksRnsContext> parameters;
    // A. Specify main parameters
    /*  A1) Secret key distribution
     * SPARSE_ENCAPSULATED is recommended for CKKS bootstrapping (probability of failure below 2^-128).
     * UNIFORM_TERNARY, used here, is the distribution of the homomorphic encryption security guidelines;
     * its probability of failure is 2^-67 for N = 2^16 and 2^-27 for N = 2^17 with full packing.
     * SPARSE_TERNARY (original CKKS paper) is discouraged: about 2^-23 for N = 2^16.
     */
    SecretKeyDist secret_key_dist = UNIFORM_TERNARY;
    parameters.set_secret_key_dist(secret_key_dist);

    /*  A2) Desired security level based on FHE standards.
     * In this example, we use the "NotSet" option, so the example can run more quickly with
     * a smaller ring dimension. Note that this should be used only in
     * non-production environments, or by experts who understand the security
     * implications of their choices. In production-like environments, we recommend using
     * HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic for 128-bit, 192-bit,
     * or 256-bit security, respectively. If you choose one of these as your security level,
     * you do not need to set the ring dimension.
     */
    // parameters.set_security_level(HEStd_NotSet);
    // parameters.set_ring_dim(1 << 15);

    /*  A3) Scaling parameters.
     * By default, we set the modulus sizes and rescaling technique to the following values
     * to obtain a good precision and performance tradeoff. We recommend keeping the parameters
     * below unless you are an FHE expert.
     */
    ScalingTechnique rescale_tech = COMPOSITESCALINGAUTO;
    uint32_t dcrt_bits = 98;
    uint32_t first_mod = 100;

    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(rescale_tech);
    parameters.set_first_mod_size(first_mod);

    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(1 << 12);

    uint32_t register_word_size = 64;
    parameters.set_register_word_size(register_word_size);

    /*  A4) Multiplicative depth.
     * The goal of bootstrapping is to increase the number of available levels we have, or in other words,
     * to dynamically increase the multiplicative depth. However, the bootstrapping procedure itself
     * needs to consume a few levels to run. We compute the number of bootstrapping levels required
     * using get_bootstrap_depth, and add it to levels_available_after_bootstrap to set our initial multiplicative
     * depth. We recommend using the input parameters below to get started.
     */
    std::vector<uint32_t> level_budget = {4, 4};

    // Note that the actual number of levels avalailable after bootstrapping before next bootstrapping
    // will be levels_available_after_bootstrap - 1 because an additional level
    // is used for scaling the ciphertext before next bootstrapping (in 64-bit CKKS bootstrapping)
    uint32_t levels_available_after_bootstrap = 10 + level_budget[1];
    uint32_t depth =
            levels_available_after_bootstrap + CkksRnsFhe::get_bootstrap_depth({level_budget[0], 0}, secret_key_dist);
    parameters.set_multiplicative_depth(depth);

    // std::cout << "approx_bootstrap_depth = " << approx_bootstrap_depth << std::endl;
    std::cout << "levelBudget[0] = " << level_budget[0] << std::endl;
    std::cout << "levelBudget[1] = " << level_budget[1] << std::endl;
    std::cout << "secretKeyDist = " << secret_key_dist << std::endl;
    std::cout << "depth = " << depth << std::endl;

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);
    crypto_context->enable(ADVANCEDSHE);
    crypto_context->enable(FHE);

    uint32_t ring_dim = crypto_context->get_ring_dimension();
    // This is the maximum number of slots that can be used for full packing.
    uint32_t num_slots = ring_dim / 2;
    std::cout << "CKKS scheme is using ring dimension " << ring_dim << std::endl << std::endl;

    crypto_context->eval_bootstrap_setup(level_budget, {0, 0}, num_slots, 0, true, true);

    auto key_pair = crypto_context->key_gen();
    crypto_context->eval_mult_key_gen(key_pair.secret_key);
    crypto_context->eval_bootstrap_key_gen(key_pair.secret_key, num_slots);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
    size_t encoded_length = x.size();

    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(crypto_context->get_crypto_parameters());
    uint32_t composite_degree = crypto_params->get_composite_degree();
    // We start with a depleted ciphertext that has used up all of its levels.
    Plaintext ptxt = crypto_context->make_ckks_packed_plaintext(x, 1, composite_degree * (depth - 1 - level_budget[1]));

    std::cout << "Composite degree: " << composite_degree
              << " Bit length: " << static_cast<float>(dcrt_bits) / composite_degree
              << " Register size: " << register_word_size << std::endl;

    ptxt->set_length(encoded_length);
    std::cout << "Input: " << ptxt << std::endl;

    Ciphertext<RnsPoly> ciph = crypto_context->encrypt(key_pair.public_key, ptxt);

    std::cout << "Initial number of levels remaining: " << depth - ciph->get_level() / composite_degree << std::endl;

    // Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    // for HE computation.
    auto ciphertext_after = crypto_context->eval_bootstrap(ciph);

    std::cout << "Number of levels remaining after bootstrapping: "
              << depth - ciphertext_after->get_level() / composite_degree -
                         (ciphertext_after->get_noise_scale_deg() - 1)
              << std::endl
              << std::endl;

    std::cout << "Scaling factor after bootstrapping: " << ciphertext_after->get_scaling_factor() << std::endl;

    std::cout << "Composite degree: " << crypto_params->get_composite_degree() << std::endl;
    std::cout << "Modulus bit length: " << static_cast<float>(dcrt_bits) / crypto_params->get_composite_degree()
              << std::endl;
    std::cout << "Word register size: " << register_word_size << std::endl;

    Plaintext result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_after, &result);
    result->set_length(encoded_length);
    std::cout << "Output after bootstrapping \n\t" << result << std::endl;

    auto actual_result = result->get_ckks_packed_value();
    double precision = calculate_approximation_error(actual_result, ptxt->get_ckks_packed_value());
    std::cout << "Estimated precision: " << precision << std::endl;
}
