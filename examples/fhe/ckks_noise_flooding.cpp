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
  Please see CKKS_NOISE_FLOODING.md for technical details on CKKS noise flooding for the INDCPA^D scenario.

  Example for using CKKS with the experimental NOISE_FLOODING_DECRYPT mode. We do not recommend
  this mode for production yet. This experimental mode gives us equivalent security levels to
  BGV and BFV, but it requires the user to run all encrypted operations twice. The first iteration
  is a preliminary run to measure noise, and the second iteration is the actual run, which
  will input the noise as a parameter. We use the noise to enhance security within decryption.

  Note that a user can choose to run the first computation with NATIVE_SIZE = 64 to estimate noise,
  and the second computation with NATIVE_SIZE = 128, if they wish. This would require a
  different set of binaries: first, with NATIVE_SIZE = 64 and the second one with NATIVE_SIZE = 128.
  It can be considered as an optimization for the case when we need NATIVE_SIZE = 128.

  For NATIVE_SIZE=128, we automatically choose the scaling mod size and first mod size in the second iteration
  based on the input noise estimate. This means that we currently do not support bootstrapping in the
  NOISE_FLOODING_DECRYPT mode, since the scaling mod size and first mod size affect the noise estimate for
  bootstrapping. We plan to add support for bootstrapping in NOISE_FLOODING_DECRYPT mode in a future release.
 */

#include <complex>
#include <cstdint>
#include <iostream>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

// Demo function for NOISE_FLOODING_DECRYPT mode in CKKS
void ckks_noise_flooding_demo();

/**
 * We recommend putting part of the CryptoContext inside a function because
 * you must make sure all parameters are the same, except EXECUTION_MODE and NOISE_ESTIMATE.
 *
 * @param crypto_params Crypto parameters that already have their execution mode set (and noise estimate, if in EXEC_EVALUATION mode).
 * @return the crypto_context.
 */
CryptoContext<RnsPoly> get_crypto_context(ContextParams<CkksRnsContext>& crypto_params);

/**
 * We recommend putting the encrypted computation you wish to perform inside a function because
 * you have to perform it twice. In this example, we perform two multiplications and an addition.
 *
 * @param crypto_context Crypto context.
 * @param public_key Public key for encryption.
 * @return the ciphertext result. The first iteration will return a ciphertext that contains a noise measurement.
 * The second iteration will return the actual encrypted computation.
 */
Ciphertext<RnsPoly> encrypted_computation(CryptoContext<RnsPoly>& crypto_context, PublicKey<RnsPoly> public_key);

int main(int argc, char* argv[]) {
    ckks_noise_flooding_demo();
    return 0;
}

void ckks_noise_flooding_demo() {
    // ----------------------- Setup first CryptoContext -----------------------------
    // Phase 1 will be for noise estimation.
    // -------------------------------------------------------------------------------
    std::cout << "---------------------------------- PHASE 1: NOISE ESTIMATION ----------------------------------"
              << std::endl;
    ContextParams<CkksRnsContext> parameters_noise_estimation;
    // EXEC_NOISE_ESTIMATION indicates that the resulting plaintext will estimate the amount of noise in the computation.
    parameters_noise_estimation.set_execution_mode(EXEC_NOISE_ESTIMATION);

    auto crypto_context_noise_estimation = get_crypto_context(parameters_noise_estimation);

    uint32_t ring_dim = crypto_context_noise_estimation->get_ring_dimension();
    std::cout << "CKKS scheme is using ring dimension " << ring_dim << std::endl << std::endl;

    // Key Generation
    auto key_pair_noise_estimation = crypto_context_noise_estimation->key_gen();
    crypto_context_noise_estimation->eval_mult_key_gen(key_pair_noise_estimation.secret_key);

    // We run the encrypted computation the first time.
    auto noise_ciphertext = encrypted_computation(crypto_context_noise_estimation, key_pair_noise_estimation.public_key);

    // Decrypt  noise
    Plaintext noise_plaintext;
    crypto_context_noise_estimation->decrypt(key_pair_noise_estimation.secret_key, noise_ciphertext, &noise_plaintext);
    double noise = noise_plaintext->get_log_error();
    std::cout << "Noise \n\t" << noise << std::endl;

    // ----------------------- Setup second CryptoContext -----------------------------
    // Phase 2 will be for the actual evaluation.
    // IMPORTANT: We must use a different public/private key pair here to achieve the
    // security guarantees for noise flooding.
    // -------------------------------------------------------------------------------
    std::cout << "---------------------------------- PHASE 2: EVALUATION ----------------------------------"
              << std::endl;
    ContextParams<CkksRnsContext> parameters_evaluation;
    // EXEC_EVALUATION indicates that we are in phase 2 of computation, and wil5 obtain the actual result.
    parameters_evaluation.set_execution_mode(EXEC_EVALUATION);
    // Here, we set the noise of our previous computation
    parameters_evaluation.set_noise_estimate(noise);

    // We can set our desired precision for 128-bit CKKS only. For NATIVE_SIZE=64, we ignore this parameter.
    parameters_evaluation.set_desired_precision(25);

    // We can set the statistical security and number of adversarial queries, but we can also
    // leave these lines out, as we are setting them to the default values here.
    parameters_evaluation.set_statistical_security(30);
    parameters_evaluation.set_num_adversarial_queries(1);

    // The remaining parameters must be the same as the first CryptoContext. Note that we can choose to run the
    // first computation with CIPHER_NATIVE_INT = 64 to estimate noise, and the second computation with CIPHER_NATIVE_INT = 128,
    // or vice versa, if we wish.
    auto crypto_context_evaluation = get_crypto_context(parameters_evaluation);

    // IMPORTANT: Generate new keys
    auto key_pair_evaluation = crypto_context_evaluation->key_gen();
    crypto_context_evaluation->eval_mult_key_gen(key_pair_evaluation.secret_key);

    // We run the encrypted computation the second time.
    auto ciphertext_result = encrypted_computation(crypto_context_evaluation, key_pair_evaluation.public_key);

    // Decrypt final result
    Plaintext result;
    crypto_context_evaluation->decrypt(key_pair_evaluation.secret_key, ciphertext_result, &result);
    size_t vec_size = 8;
    result->set_length(vec_size);
    std::cout << "Final output \n\t" << result->get_ckks_packed_value() << std::endl;

    std::vector<std::complex<double>> expected_result = {1.01, 1.04, 0, 0, 1.25, 0, 0, 1.64};
    std::cout << "Expected result\n\t " << expected_result << std::endl;
}

CryptoContext<RnsPoly> get_crypto_context(ContextParams<CkksRnsContext>& parameters) {
    // This demo is to illustrate how to use the security mode NOISE_FLOODING_DECRYPT to achieve enhanced security.
    parameters.set_decryption_noise_mode(NOISE_FLOODING_DECRYPT);

    // Specify main parameters
    parameters.set_secret_key_dist(UNIFORM_TERNARY);

    /* Desired security level based on FHE standards. Note that this is different than NoiseDecryptionMode,
     * which also gives us enhanced security in CKKS when using NOISE_FLOODING_DECRYPT.
     * We must always use the same ring dimension in both iterations, so we set the security level to HEStd_NotSet,
     * and manually set the ring dimension.
     */
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(1 << 16);

    ScalingTechnique rescale_tech = FIXEDAUTO;
    uint32_t dcrt_bits = 59;
    uint32_t first_mod = 60;

    parameters.set_scaling_technique(rescale_tech);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_first_mod_size(first_mod);

    // In this example, we perform two multiplications and an addition.
    parameters.set_multiplicative_depth(2);

    // Generate crypto context.
    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    // Enable features that you wish to use.
    crypto_context->enable(PKE);
    crypto_context->enable(LEVELEDSHE);

    return crypto_context;
}

Ciphertext<RnsPoly> encrypted_computation(CryptoContext<RnsPoly>& crypto_context, PublicKey<RnsPoly> public_key) {
    // Encoding and encryption of inputs
    // Generate random input
    std::vector<double> vec1 = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};
    std::vector<double> vec2 = {1, 1, 0, 0, 1, 0, 0, 1};

    // Encoding as plaintexts and encrypt
    Plaintext ptxt1 = crypto_context->make_ckks_packed_plaintext(vec1);
    Plaintext ptxt2 = crypto_context->make_ckks_packed_plaintext(vec2);
    Ciphertext<RnsPoly> ciph1 = crypto_context->encrypt(public_key, ptxt1);
    Ciphertext<RnsPoly> ciph2 = crypto_context->encrypt(public_key, ptxt2);

    Ciphertext<RnsPoly> ciph_mult = crypto_context->eval_mult(ciph1, ciph2);
    Ciphertext<RnsPoly> ciph_mult2 = crypto_context->eval_mult(ciph_mult, ciph1);
    Ciphertext<RnsPoly> ciph_result = crypto_context->eval_add(ciph_mult2, ciph2);

    return ciph_result;
}
