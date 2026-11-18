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

Example for multiple iterations of CKKS bootstrapping to improve precision. Note that you need to run a
single iteration of bootstrapping first, to measure the precision. Then, you can input the measured
precision as a parameter to eval_bootstrap with multiple iterations. With 2 iterations, you can achieve
double the precision of a single bootstrapping.

* Source: Bae Y., Cheon J., Cho W., Kim J., and Kim T. META-BTS: Bootstrapping Precision
* Beyond the Limit. Cryptology ePrint Archive, Report
* 2022/1167. (https://eprint.iacr.org/2022/1167.pdf)

*/

#include <cmath>
#include <complex>
#include <cstdint>
#include <iostream>
#include <ostream>
#include <random>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

void iterative_bootstrap_example();
void iterative_bootstrap_stc_example();

int main(int argc, char* argv[]) {
    // We run the example with 8 slots and ring dimension 4096.
    iterative_bootstrap_example();
    iterative_bootstrap_stc_example();
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

void iterative_bootstrap_example() {
    std::cout << "***CKKS Bootstrapping Variant with ModRaise-first step***\n\n";
    // Step 1: Set CryptoContext
    ContextParams<CkksRnsContext> parameters;
    SecretKeyDist secret_key_dist = UNIFORM_TERNARY;
    parameters.set_secret_key_dist(secret_key_dist);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(1 << 12);

#if CIPHER_NATIVE_INT == 128
    // Currently, only FIXEDMANUAL and FIXEDAUTO modes are supported for 128-bit CKKS bootstrapping.
    ScalingTechnique rescale_tech = FIXEDAUTO;
    uint32_t dcrt_bits = 78;
    uint32_t first_mod = 89;
#else
    // All modes are supported for 64-bit CKKS bootstrapping.
    ScalingTechnique rescale_tech = FLEXIBLEAUTO;
    uint32_t dcrt_bits = 59;
    uint32_t first_mod = 60;
#endif

    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(rescale_tech);
    parameters.set_first_mod_size(first_mod);

    // Here, we specify the number of iterations to run bootstrapping. Note that we currently only support 1 or 2 iterations.
    // Two iterations should give us approximately double the precision of one iteration.
    uint32_t num_iterations = 2;

    std::vector<uint32_t> level_budget = {3, 3};
    std::vector<uint32_t> bsgs_dim = {0, 0};

    uint32_t levels_available_after_bootstrap = 10;
    uint32_t depth = levels_available_after_bootstrap + CkksRnsFhe::get_bootstrap_depth(level_budget, secret_key_dist) +
                     (num_iterations - 1);
    parameters.set_multiplicative_depth(depth);

    // Generate crypto context.
    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    // Enable features that you wish to use. Note, we must enable FHE to use bootstrapping.
    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);
    crypto_context->enable(ADVANCEDSHE);
    crypto_context->enable(FHE);

    uint32_t ring_dim = crypto_context->get_ring_dimension();
    std::cout << "CKKS scheme is using ring dimension " << ring_dim << "\n\n";

    // Step 2: Precomputations for bootstrapping
    // We use a sparse packing.
    uint32_t num_slots = 8;
    crypto_context->eval_bootstrap_setup(level_budget, bsgs_dim, num_slots);

    // Step 3: Key Generation
    auto key_pair = crypto_context->key_gen();
    crypto_context->eval_mult_key_gen(key_pair.secret_key);
    // Generate bootstrapping keys.
    crypto_context->eval_bootstrap_key_gen(key_pair.secret_key, num_slots);

    // Step 4: Encoding and encryption of inputs
    // Generate random input
    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 2.0);
    for (uint32_t i = 0; i < num_slots; ++i) {
        x.push_back(dis(gen));
    }

    // Encoding as plaintexts
    // We specify the number of slots as num_slots to achieve a performance improvement.
    // We use the other default values of depth 1, levels 0, and no params.
    // Alternatively, you can also set batch size as a parameter in the CryptoContext as follows:
    // parameters.set_batch_size(num_slots);
    // Here, we assume all ciphertexts in the crypto_context will have num_slots slots.
    // We start with a depleted ciphertext that has used up all of its levels.
    Plaintext ptxt = crypto_context->make_ckks_packed_plaintext(x, 1, depth - 1, nullptr, num_slots);
    ptxt->set_length(num_slots);
    std::cout << "Input: " << ptxt;

    // Encrypt the encoded vectors
    Ciphertext<RnsPoly> ciph = crypto_context->encrypt(key_pair.public_key, ptxt);

    // Step 5: Measure the precision of a single bootstrapping operation.
    auto ciphertext_after = crypto_context->eval_bootstrap(ciph);

    Plaintext result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_after, &result);
    result->set_length(num_slots);
    uint32_t precision =
            std::floor(calculate_approximation_error(result->get_ckks_packed_value(), ptxt->get_ckks_packed_value()));
    std::cout << "Bootstrapping precision after 1 iteration: " << precision << "\n\n";
    // Set precision equal to empirically measured value after many test runs. One could add a buffer to reduce this value as below.
    precision -= 5;
    std::cout << "Precision input to 2 iteration: " << precision << "\n";

    // Step 6: Run bootstrapping with multiple iterations.
    auto ciphertext_two_iterations = crypto_context->eval_bootstrap(ciph, num_iterations, precision);

    Plaintext result_two_iterations;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_two_iterations, &result_two_iterations);
    result_two_iterations->set_length(num_slots);
    auto actual_result = result_two_iterations->get_ckks_packed_value();

    std::cout << "Output after two iterations of bootstrapping: " << actual_result << "\n";
    double precision_multiple_iterations = calculate_approximation_error(actual_result, ptxt->get_ckks_packed_value());

    // Output the precision of bootstrapping after two iterations. It should be approximately double the original precision.
    std::cout << "Bootstrapping precision after 2 iterations: " << precision_multiple_iterations << "\n";
    std::cout << "Number of levels remaining after 2 bootstrappings: "
              << depth - ciphertext_two_iterations->get_level() - (ciphertext_two_iterations->get_noise_scale_deg() - 1)
              << "\n\n";
}

void iterative_bootstrap_stc_example() {
    std::cout << "***CKKS Bootstrapping Variant with SlotsToCoefficients-first step***\n\n";
    // Step 1: Set CryptoContext
    ContextParams<CkksRnsContext> parameters;
    SecretKeyDist secret_key_dist = UNIFORM_TERNARY;
    parameters.set_secret_key_dist(secret_key_dist);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(1 << 12);

#if CIPHER_NATIVE_INT == 128
    // Currently, only FIXEDMANUAL and FIXEDAUTO modes are supported for 128-bit CKKS bootstrapping.
    ScalingTechnique rescale_tech = FIXEDAUTO;
    uint32_t dcrt_bits = 78;
    uint32_t first_mod = 89;
#else
    // All modes are supported for 64-bit CKKS bootstrapping.
    ScalingTechnique rescale_tech = FLEXIBLEAUTO;
    uint32_t dcrt_bits = 59;
    uint32_t first_mod = 60;
#endif

    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(rescale_tech);
    parameters.set_first_mod_size(first_mod);

    // Here, we specify the number of iterations to run bootstrapping. Note that we currently only support 1 or 2 iterations.
    // Two iterations should give us approximately double the precision of one iteration.
    uint32_t num_iterations = 2;

    std::vector<uint32_t> level_budget = {3, 3};
    std::vector<uint32_t> bsgs_dim = {0, 0};

    uint32_t levels_available_after_bootstrap = 10 + level_budget[1];
    uint32_t depth =
            levels_available_after_bootstrap + CkksRnsFhe::get_bootstrap_depth(9, level_budget, secret_key_dist);
    parameters.set_multiplicative_depth(depth);

    // Generate crypto context.
    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    // Enable features that you wish to use. Note, we must enable FHE to use bootstrapping.
    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);
    crypto_context->enable(ADVANCEDSHE);
    crypto_context->enable(FHE);

    uint32_t ring_dim = crypto_context->get_ring_dimension();
    std::cout << "CKKS scheme is using ring dimension " << ring_dim << "\n\n";

    // Step 2: Precomputations for bootstrapping
    // We use a sparse packing and default correection factor for single iteration
    uint32_t num_slots = 8;
    crypto_context->eval_bootstrap_setup(level_budget, bsgs_dim, num_slots, 0, true, true);

    // Step 3: Key Generation
    auto key_pair = crypto_context->key_gen();
    crypto_context->eval_mult_key_gen(key_pair.secret_key);
    // Generate bootstrapping keys.
    crypto_context->eval_bootstrap_key_gen(key_pair.secret_key, num_slots);

    // Step 4: Encoding and encryption of inputs
    // Generate random input
    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 2.0);
    for (uint32_t i = 0; i < num_slots; ++i) {
        x.push_back(dis(gen));
    }

    // Encoding as plaintexts
    // We specify the number of slots as num_slots to achieve a performance improvement.
    // We use the other default values of depth 1, levels 0, and no params.
    // Alternatively, you can also set batch size as a parameter in the CryptoContext as follows:
    // parameters.set_batch_size(num_slots);
    // Here, we assume all ciphertexts in the crypto_context will have num_slots slots.
    // We start with a depleted ciphertext that has used up all of its levels.
    Plaintext ptxt = crypto_context->make_ckks_packed_plaintext(x, 1, depth - 1 - level_budget[1], nullptr, num_slots);
    ptxt->set_length(num_slots);
    std::cout << "Input: " << ptxt;

    std::cout << "Correction factor used: " << crypto_context->get_ckks_boot_correction_factor() << "\n";

    // Encrypt the encoded vectors
    Ciphertext<RnsPoly> ciph = crypto_context->encrypt(key_pair.public_key, ptxt);

    // Step 5: Measure the precision of a single bootstrapping operation.
    auto ciphertext_after = crypto_context->eval_bootstrap(ciph);

    Plaintext result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_after, &result);
    result->set_length(num_slots);
    uint32_t precision =
            std::floor(calculate_approximation_error(result->get_ckks_packed_value(), ptxt->get_ckks_packed_value()));
    std::cout << "Bootstrapping precision after 1 iteration: " << precision << "\n\n";

    // Set precision equal to empirically measured value after many test runs. One could add a buffer to reduce this value as below.
    precision -= 5;
    std::cout << "Precision input to 2nd iteration: " << precision << "\n";

    // Step 6: Run bootstrapping with multiple iterations.
    auto ciphertext_two_iterations = crypto_context->eval_bootstrap(ciph, num_iterations, precision);

    Plaintext result_two_iterations;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_two_iterations, &result_two_iterations);
    result_two_iterations->set_length(num_slots);
    auto actual_result = result_two_iterations->get_ckks_packed_value();

    std::cout << "Output after two iterations of bootstrapping: " << actual_result << "\n";
    double precision_multiple_iterations = calculate_approximation_error(actual_result, ptxt->get_ckks_packed_value());

    // Output the precision of bootstrapping after two iterations. It should be approximately double the original precision.
    std::cout << "Bootstrapping precision after 2 iterations: " << precision_multiple_iterations << "\n";
    std::cout << "Number of levels remaining after 2 bootstrappings: "
              << depth - ciphertext_two_iterations->get_level() - (ciphertext_two_iterations->get_noise_scale_deg() - 1)
              << "\n\n";

    //---------------------------------------------------------------------------------------------------------------------
    // When using eval_bootstrap for 2 iterations with STC first, it may be beneficial to scale down the default correction
    // factor to achieve a higher final precision. This behavior is specifically pronounced for sparse packing. As the
    // number of slots increases, the difference between the default correction factor and the best empirical correction
    // factor decreases. For full packing at full security for CKKS bootstrapping, this variant of CKKS bootstrapping
    // has better precision than the ModRaise-first variant without any change to the default correction factor.

    crypto_context->set_ckks_boot_correction_factor(crypto_context->get_ckks_boot_correction_factor() - 5);
    std::cout << "Correction factor used: " << crypto_context->get_ckks_boot_correction_factor() << "\n";

    ciphertext_after = crypto_context->eval_bootstrap(ciph);
    crypto_context->decrypt(key_pair.secret_key, ciphertext_after, &result);
    result->set_length(num_slots);
    precision =
            std::floor(calculate_approximation_error(result->get_ckks_packed_value(), ptxt->get_ckks_packed_value()));
    std::cout << "Bootstrapping precision after 1 iteration: " << precision << "\n\n";

    // Set precision equal to empirically measured value after many test runs. One could add a buffer to reduce this value as below.
    precision -= 5;
    std::cout << "Precision input to 2nd iteration: " << precision << "\n";

    ciphertext_two_iterations = crypto_context->eval_bootstrap(ciph, num_iterations, precision);
    crypto_context->decrypt(key_pair.secret_key, ciphertext_two_iterations, &result_two_iterations);
    actual_result = result_two_iterations->get_ckks_packed_value();

    std::cout << "Output after two iterations of bootstrapping: " << actual_result << "\n";
    precision_multiple_iterations = calculate_approximation_error(actual_result, ptxt->get_ckks_packed_value());

    // Output the precision of bootstrapping after two iterations. It should be approximately double the original precision.
    std::cout << "Bootstrapping precision after 2 iterations: " << precision_multiple_iterations << "\n";
    std::cout << "Number of levels remaining after 2 bootstrappings: "
              << depth - ciphertext_two_iterations->get_level() - (ciphertext_two_iterations->get_noise_scale_deg() - 1)
              << "\n\n";
}
