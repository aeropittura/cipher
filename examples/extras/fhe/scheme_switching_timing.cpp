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
  Benchmarks for scheme switching between CKKS and FHEW and back, with intermediate computations
 */

#define PROFILE
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>

#include "cipher/boolean/context.h"
#include "cipher/cipher.h"

using namespace cipher;

void switch_ckks_to_fhew(uint32_t depth, uint32_t slots, uint32_t num_values);
void switch_fhew_to_ckks(uint32_t depth, uint32_t slots, uint32_t num_values);
void comparison_via_scheme_switching(uint32_t depth, uint32_t slots, uint32_t num_values);
void argmin_via_scheme_switching(uint32_t depth, uint32_t slots, uint32_t num_values);
void argmin_via_scheme_switching_alt(uint32_t depth, uint32_t slots, uint32_t num_values);
void argmin(uint32_t depth, uint32_t slots, uint32_t num_values, uint32_t ring_dim);
void argmin_alt(uint32_t depth, uint32_t slots, uint32_t num_values, uint32_t ring_dim);
void Comparison(uint32_t depth, uint32_t slots, uint32_t num_values, uint32_t ring_dim);

int main() {
    // // all examples set 128-bit security
    switch_ckks_to_fhew(24, 1024, 1024);
    switch_fhew_to_ckks(24, 1024, 1024);
    comparison_via_scheme_switching(24, 1024, 1024);

    // // depth >= 13 + log2(num_values);
    argmin_via_scheme_switching(24, 1024, 1024);
    argmin_via_scheme_switching_alt(24, 1024, 1024);

    argmin(39, 256, 256, 1 << 17);
    argmin_alt(39, 256, 256, 1 << 17);
    Comparison(39, 256, 256, 1 << 17);

    return 0;
}

void switch_ckks_to_fhew(uint32_t depth, uint32_t slots, uint32_t num_values) {
    /*
  Example of switching a packed ciphertext from CKKS to multiple FHEW ciphertexts.
 */
    std::cout << "\n-----SwitchCKKSToFHEW-----\n" << std::endl;

    TimeVar t, t_total_value;
    double time_key_gen(0.0), time_setup(0.0), time_precomp(0.0), time_eval(0.0);

    TIC(t_total_value);

    // Step 1: Setup CryptoContext for CKKS

    // Specify main parameters
    uint32_t first_mod_size_value = 60;
    uint32_t scale_mod_size = 50;
    uint32_t log_q_cc_lwe = 26;
    uint32_t batch_size = slots;

    ContextParams<CkksRnsContext> parameters;

    parameters.set_multiplicative_depth(depth);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_scaling_technique(FIXEDMANUAL);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << depth << std::endl
              << std::endl;

    // Generate encryption keys
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    TIC(t);
    auto private_key_fhew = cc->eval_ckks_to_fhew_setup(params);
    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();
    time_setup = TOC(t);
    std::cout << "Time to compute the CKKS to FHEW switching setup: " << time_setup / 1000 << " s" << std::endl;

    TIC(t);
    cc->eval_ckks_to_fhew_key_gen(keys, private_key_fhew);
    // Generate bootstrapping key for timing
    cc_lwe->bt_key_gen(private_key_fhew);
    time_key_gen = TOC(t);
    std::cout << "Time to compute the CKKS to FHEW switching key generation (+BTKey): " << time_key_gen / 60000
              << " min" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    std::cout << num_values << " slots are being switched." << std::endl << std::endl;

    // Perform the precomputation for switching
    TIC(t);
    // Compute the scaling factor to decrypt correctly in FHEW; the LWE mod switch is performed on the ciphertext at the last level
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());
    RnsParams<RnsPoly::Integer> element_params = *(crypto_params->get_element_params());
    auto params_q = element_params.get_params();
    auto modulus_ckks_from = params_q[0]->get_modulus();

    auto p_lwe = 1 << (log_q_cc_lwe - 12);  // Large precision

    double sc_factor = crypto_params->get_scaling_factor_real(0);
    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT)
        sc_factor = crypto_params->get_scaling_factor_real(1);
    double scale = modulus_ckks_from.convert_to_int() / (sc_factor * p_lwe);

    cc->eval_ckks_to_fhew_precompute(scale);
    time_precomp = TOC(t);
    std::cout << "Time to do the precomputations for the CKKS to FHEW switching: " << time_precomp / 1000 << " s"
              << std::endl;

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0};
    if (x.size() < slots) {
        std::vector<int> zeros(slots - x.size(), 0);
        x.insert(x.end(), zeros.begin(), zeros.end());
    }

    // Encoding as plaintexts
    Plaintext ptxt = cc->make_ckks_packed_plaintext(x, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto ct = cc->encrypt(keys.public_key, ptxt);

    // Step 4: Scheme switching from CKKS to FHEW

    // Transform the ciphertext from CKKS to FHEW
    TIC(t);
    auto c_temp = cc->eval_ckks_to_fhew(ct, num_values);
    time_eval = TOC(t);
    std::cout << "Time to evaluate the scheme switching from CKKS to FHEW: " << time_eval / 1000 << " s" << std::endl;

    std::vector<int32_t> x_int(slots);
    std::transform(x.begin(), x.end(), x_int.begin(), [&](const double& elem) {
        return static_cast<int32_t>(static_cast<int32_t>(std::round(elem)) % p_lwe);
    });
    ptxt->set_length(slots);
    if (slots < 64) {
        std::cout << "Input: " << ptxt->get_real_packed_value() << "; which rounds to: " << x_int << std::endl;
        std::cout << "FHEW decryption: ";
        LwePlaintext result;
        for (uint32_t i = 0; i < c_temp.size(); ++i) {
            cc_lwe->decrypt(private_key_fhew, c_temp[i], &result, p_lwe);
            std::cout << result << " ";
        }
        std::cout << "\n" << std::endl;
    } else {  // Suppress output
        LwePlaintext result;
        for (uint32_t i = 0; i < c_temp.size(); ++i) {
            cc_lwe->decrypt(private_key_fhew, c_temp[i], &result, p_lwe);
        }
    }

    double total_time = TOC(t_total_value);
    std::cout << "\nTotal time: " << total_time / 60000 << " min" << std::endl;

    cc->clear_static_maps_and_vectors();
}

void switch_fhew_to_ckks(uint32_t depth, uint32_t slots, uint32_t num_values) {
    /*
  Example of switching multiple FHEW ciphertexts to a packed CKKS ciphertext.
 */
    std::cout << "\n-----SwitchFHEWtoCKKS-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back.\n" << std::endl;

    TimeVar t, t_total_value;
    double time_key_gen(0.0), time_setup(0.0), time_eval(0.0);

    TIC(t_total_value);

    // Step 1: Setup CryptoContext for CKKS to be switched into

    // A. Specify main parameters
    ScalingTechnique sc_tech = FIXEDAUTO;
    if (sc_tech == FLEXIBLEAUTOEXT)
        depth += 1;
    uint32_t scale_mod_size = 50;
    uint32_t log_q_cc_lwe = 26;
    uint32_t batch_size = slots;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(depth);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_scaling_technique(sc_tech);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << depth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    auto cc_lwe = std::make_shared<BooleanContext>();
    cc_lwe->BooleanContext::generate_boolean_context(STD128, false, log_q_cc_lwe, 0, GINX, false);

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    std::cout << num_values << " slots are being switched." << std::endl << std::endl;

    // Step 3. Precompute the necessary keys and information for switching from FHEW to CKKS
    TIC(t);
    cc->eval_fhew_to_ckks_setup(cc_lwe, slots, log_q_cc_lwe);
    time_setup = TOC(t);
    std::cout << "Time to compute the FHEW to CKKS switching setup: " << time_setup / 1000 << " s" << std::endl;

    TIC(t);
    // LWE private key
    LwePrivateKey lwesk;
    lwesk = cc_lwe->key_gen();
    cc->eval_fhew_to_ckks_key_gen(keys, lwesk, slots);
    // Generate bootstrapping key for timing
    cc_lwe->bt_key_gen(lwesk);
    time_key_gen = TOC(t);
    std::cout << "Time to compute the FHEW to CKKS switching key generation (+ BT key): " << time_key_gen / 60000
              << " min" << std::endl;

    // Step 4: Encoding and encryption of inputs
    // For correct CKKS decryption, the messages have to be much smaller than the FHEW plaintext modulus!
    auto modulus_lwe = 1 << log_q_cc_lwe;
    auto p_lwe = 1 << (log_q_cc_lwe - 12);  // Large precision

    // Inputs
    std::vector<int> x = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    if (x.size() < slots) {
        std::vector<int> zeros(slots - x.size(), 0);
        x.insert(x.end(), zeros.begin(), zeros.end());
    }

    // Encrypt
    std::vector<LweCiphertext> ctxts_lwe(slots);
    for (uint32_t i = 0; i < slots; i++) {
        // encrypted under large plaintext modulus and large ciphertext modulus
        ctxts_lwe[i] = cc_lwe->encrypt(lwesk, x[i], LARGE_DIM, p_lwe, modulus_lwe);
    }

    // Step 5. Perform the scheme switching
    std::setprecision(log_q_cc_lwe + 10);
    TIC(t);
    auto c_temp = cc->eval_fhew_to_ckks(ctxts_lwe, num_values, slots, p_lwe, 0, p_lwe);
    time_eval = TOC(t);
    std::cout << "Time to evaluate the scheme switching from FHEW to CKKS: " << time_eval / 60000 << " min"
              << std::endl;

    // Step 6. Decrypt
    Plaintext plaintext_dec;
    cc->decrypt(keys.secret_key, c_temp, &plaintext_dec);
    plaintext_dec->set_length(num_values);

    if (num_values <= 64) {  // Otherwise, supress output
        std::cout << "\nInput: " << x << " encrypted under p = " << NativeInteger(p_lwe)
                  << " and Q = " << ctxts_lwe[0]->get_modulus() << std::endl;
        std::cout << "Switched CKKS decryption: " << plaintext_dec << std::endl;
    }

    double total_time = TOC(t_total_value);
    std::cout << "\nTotal time: " << total_time / 60000 << " min" << std::endl;

    cc->clear_static_maps_and_vectors();
}

void comparison_via_scheme_switching(uint32_t depth, uint32_t slots, uint32_t num_values) {
    /*
  Example of comparing two CKKS ciphertexts via scheme switching.
 */
    std::cout << "\n-----ComparisonViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back.\n" << std::endl;

    TimeVar t, t_total_value;
    double time_key_gen(0.0), time_setup(0.0), time_precomp(0.0), time_eval(0.0);

    TIC(t_total_value);

    // Step 1: Setup CryptoContext for CKKS
    ScalingTechnique sc_tech = FIXEDAUTO;
    if (sc_tech == FLEXIBLEAUTOEXT)
        depth += 1;

    uint32_t scale_mod_size = 50;
    uint32_t first_mod_size_value = 60;
    uint32_t log_q_cc_lwe = 26;
    uint32_t batch_size = slots;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(depth);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_technique(sc_tech);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << depth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    params.set_num_values(slots);
    TIC(t);
    auto private_key_fhew = cc->eval_scheme_switching_setup(params);
    time_setup = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << time_setup / 1000 << " s" << std::endl;

    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

    TIC(t);
    cc->eval_scheme_switching_key_gen(keys, private_key_fhew);
    time_key_gen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << time_key_gen / 60000 << " min" << std::endl
              << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    std::cout << num_values << " slots are being switched." << std::endl;

    TIC(t);
    // Pre-computations
    auto modulus_lwe = 1 << log_q_cc_lwe;
    auto beta = cc_lwe->get_beta().convert_to_int();
    auto p_lwe = modulus_lwe / (2 * beta);
    double scale_sign_fhew = 8.0;
    cc->eval_compare_switch_precompute(p_lwe, scale_sign_fhew);
    time_precomp = TOC(t);
    std::cout << "Time to perform precomputations: " << time_precomp / 1000 << " s" << std::endl;

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x1 = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0};
    std::vector<double> x2(slots, 5.25);
    if (x1.size() < slots) {
        std::vector<int> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }
    if (x2.size() < slots) {
        std::vector<int> zeros(slots - x2.size(), 0);
        x2.insert(x2.end(), zeros.begin(), zeros.end());
    }

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x1, 1, 0, nullptr);
    Plaintext ptxt2 = cc->make_ckks_packed_plaintext(x2, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->encrypt(keys.public_key, ptxt1);
    auto c2 = cc->encrypt(keys.public_key, ptxt2);

    // Compute the difference to compare to zero
    auto c_diff = cc->eval_sub(c1, c2);

    Plaintext p_diff;
    cc->decrypt(keys.secret_key, c_diff, &p_diff);
    p_diff->set_length(slots);
    if (slots <= 64) {  // Otherwise, supress output
        std::cout << "Difference of inputs: ";
        auto p_diff_rpv = p_diff->get_real_packed_value();
        for (uint32_t i = 0; i < slots; ++i) {
            std::cout << p_diff_rpv[i] << " ";
        }
    }

    if (num_values <= 64) {  // Otherwise, supress output
        const double eps = 0.0001;
        std::cout << "\nExpected sign result from CKKS: ";
        auto p_diff_rpv = p_diff->get_real_packed_value();
        for (uint32_t i = 0; i < num_values; ++i) {
            std::cout << int(std::round(p_diff_rpv[i] / eps) * eps < 0) << " ";
        }
        std::cout << "\n";
    }

    // Step 4: Comparison via CKKS->FHEW->CKKS
    TIC(t);
    auto c_result = cc->eval_compare_scheme_switching(c1, c2, num_values, slots);
    time_eval = TOC(t);
    std::cout << "Time to perform comparison via scheme switching: " << time_eval / 60000 << " min" << std::endl;

    Plaintext plaintext_dec3;
    cc->decrypt(keys.secret_key, c_result, &plaintext_dec3);
    plaintext_dec3->set_length(num_values);

    if (num_values <= 64) {  // Otherwise, supress output
        std::cout << "Decrypted switched result: " << plaintext_dec3 << std::endl;
    }

    double total_time = TOC(t_total_value);
    std::cout << "\nTotal time: " << total_time / 60000 << " min" << std::endl;

    cc->clear_static_maps_and_vectors();
}

void argmin_via_scheme_switching(uint32_t depth, uint32_t slots, uint32_t num_values) {
    /*
  Example of computing the min and argmin of the vector packed in a CKKS ciphertext.
 */
    std::cout << "\n-----ArgminViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    TimeVar t, t_total_value;
    double time_key_gen(0.0), time_setup(0.0), time_precomp(0.0), time_eval_min(0.0);  // timeEvalMax(0.0);

    TIC(t_total_value);

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scale_mod_size = 50;
    uint32_t first_mod_size_value = 60;
    uint32_t log_q_cc_lwe = 26;
    bool one_hot = true;  // Change to false if the output should not be one-hot encoded

    uint32_t batch_size = slots;
    ScalingTechnique sc_tech = FLEXIBLEAUTO;
    if (sc_tech == FLEXIBLEAUTOEXT)
        depth += 1;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(depth);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_technique(sc_tech);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << depth << std::endl << std::endl;

    // Generate encryption keys
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    params.set_num_values(num_values);
    params.set_compute_argmin(true);
    params.set_one_hot_encoding(one_hot);
    TIC(t);
    auto private_key_fhew = cc->eval_scheme_switching_setup(params);
    time_setup = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << time_setup / 1000 << " s" << std::endl;

    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

    TIC(t);
    cc->eval_scheme_switching_key_gen(keys, private_key_fhew);
    time_key_gen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << time_key_gen / 60000 << " min" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    std::cout << num_values << " slots are being switched." << std::endl << std::endl;

    TIC(t);
    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scale_sign = 512.0;
    auto p_lwe = 1 << (log_q_cc_lwe - 12);  // Large precision
    cc->eval_compare_switch_precompute(p_lwe, scale_sign);
    time_precomp = TOC(t);
    std::cout << "Time to do the precomputations: " << time_precomp / 1000 << " s" << std::endl;

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                             9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x.size() < slots) {
        std::vector<int> zeros(slots - x.size(), 0);
        x.insert(x.end(), zeros.begin(), zeros.end());
    }

    std::cout << "Expected minimum value " << *(std::min_element(x.begin(), x.begin() + num_values)) << " at location "
              << std::min_element(x.begin(), x.begin() + num_values) - x.begin() << std::endl;
    std::cout << "Expected maximum value " << *(std::max_element(x.begin(), x.begin() + num_values)) << " at location "
              << std::max_element(x.begin(), x.begin() + num_values) - x.begin() << std::endl;
    std::cout << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x);

    // Encrypt the encoded vectors
    auto c1 = cc->encrypt(keys.public_key, ptxt1);

    // Step 4: Argmin evaluation
    TIC(t);
    auto result = cc->eval_min_scheme_switching(c1, keys.public_key, num_values, slots);
    time_eval_min = TOC(t);

    Plaintext ptxt_min;
    cc->decrypt(keys.secret_key, result[0], &ptxt_min);
    ptxt_min->set_length(1);
    std::cout << "Minimum value: " << ptxt_min << std::endl;
    cc->decrypt(keys.secret_key, result[1], &ptxt_min);

    if (num_values <= 64) {  // Otherwise, supress output
        if (one_hot) {
            ptxt_min->set_length(num_values);
            std::cout << "Argmin indicator vector: " << ptxt_min << std::endl;
        } else {
            ptxt_min->set_length(1);
            std::cout << "Argmin: " << ptxt_min << std::endl;
        }
    }
    std::cout << "Time to compute min and argmin via scheme switching: " << time_eval_min / 60000 << " min"
              << std::endl;

    // TIC(t);
    // result      = cc->eval_max_scheme_switching(c1, keys.public_key, num_values, slots);
    // timeEvalMax = TOC(t);

    // Plaintext ptxt_max;
    // cc->decrypt(keys.secret_key, result[0], &ptxt_max);
    // ptxt_max->set_length(1);
    // std::cout << "Maximum value: " << ptxt_max << std::endl;
    // cc->decrypt(keys.secret_key, result[1], &ptxt_max);

    // if (num_values <= 64) {  // Otherwise, supress output
    //     if (one_hot) {
    //         ptxt_max->set_length(num_values);
    //         std::cout << "Argmax indicator vector: " << ptxt_max << std::endl;
    //     }
    //     else {
    //         ptxt_max->set_length(1);
    //         std::cout << "Argmax: " << ptxt_max << std::endl;
    //     }
    // }
    // std::cout << "Time to compute max and argmax via scheme switching: " << timeEvalMax/ 60000 << " min" << std::endl;

    double total_time = TOC(t_total_value);
    std::cout << "\nTotal time: " << total_time / 60000 << " min" << std::endl;

    cc->clear_static_maps_and_vectors();
}

void argmin_via_scheme_switching_alt(uint32_t depth, uint32_t slots, uint32_t num_values) {
    /*
  Example of computing the min and argmin of the vector packed in a CKKS ciphertext.
 */
    std::cout << "\n-----ArgminViaSchemeSwitchingAlt-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    TimeVar t, t_total_value;
    double time_key_gen(0.0), time_setup(0.0), time_precomp(0.0), time_eval_min(0.0);  // timeEvalMax(0.0);

    TIC(t_total_value);

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scale_mod_size = 50;
    uint32_t first_mod_size_value = 60;
    uint32_t log_q_cc_lwe = 26;
    bool one_hot = true;  // Change to false if the output should not be one-hot encoded

    uint32_t batch_size = slots;
    ScalingTechnique sc_tech = FLEXIBLEAUTO;
    if (sc_tech == FLEXIBLEAUTOEXT)
        depth += 1;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(depth);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_technique(sc_tech);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << depth << std::endl << std::endl;

    // Generate encryption keys
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    params.set_num_values(num_values);
    params.set_compute_argmin(true);
    params.set_one_hot_encoding(one_hot);
    params.set_use_alt_argmin(true);
    TIC(t);
    auto private_key_fhew = cc->eval_scheme_switching_setup(params);
    time_setup = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << time_setup / 1000 << " s" << std::endl;

    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

    TIC(t);
    cc->eval_scheme_switching_key_gen(keys, private_key_fhew);
    time_key_gen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << time_key_gen / 60000 << " min" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    std::cout << num_values << " slots are being switched." << std::endl << std::endl;

    TIC(t);
    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scale_sign = 512.0;
    auto p_lwe = 1 << (log_q_cc_lwe - 12);  // Large precision
    cc->eval_compare_switch_precompute(p_lwe, scale_sign);
    time_precomp = TOC(t);
    std::cout << "Time to do the precomputations: " << time_precomp / 1000 << " s" << std::endl;

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                             9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x.size() < slots) {
        std::vector<int> zeros(slots - x.size(), 0);
        x.insert(x.end(), zeros.begin(), zeros.end());
    }

    std::cout << "Expected minimum value " << *(std::min_element(x.begin(), x.begin() + num_values)) << " at location "
              << std::min_element(x.begin(), x.begin() + num_values) - x.begin() << std::endl;
    // std::cout << "Expected maximum value " << *(std::max_element(x.begin(), x.begin() + num_values)) << " at location "
    //   << std::max_element(x.begin(), x.begin() + num_values) - x.begin() << std::endl;
    std::cout << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x);

    // Encrypt the encoded vectors
    auto c1 = cc->encrypt(keys.public_key, ptxt1);

    // Step 4: Argmin evaluation
    TIC(t);
    auto result = cc->eval_min_scheme_switching_alt(c1, keys.public_key, num_values, slots);
    time_eval_min = TOC(t);

    Plaintext ptxt_min;
    cc->decrypt(keys.secret_key, result[0], &ptxt_min);
    ptxt_min->set_length(1);
    std::cout << "Minimum value: " << ptxt_min << std::endl;
    cc->decrypt(keys.secret_key, result[1], &ptxt_min);

    if (num_values <= 64) {  // Otherwise, supress output
        if (one_hot) {
            ptxt_min->set_length(num_values);
            std::cout << "Argmin indicator vector: " << ptxt_min << std::endl;
        } else {
            ptxt_min->set_length(1);
            std::cout << "Argmin: " << ptxt_min << std::endl;
        }
    }
    std::cout << "Time to compute min and argmin via scheme switching: " << time_eval_min / 60000 << " min"
              << std::endl;

    // TIC(t);
    // result      = cc->eval_max_scheme_switching_alt(c1, keys.public_key, num_values, slots);
    // timeEvalMax = TOC(t);

    // Plaintext ptxt_max;
    // cc->decrypt(keys.secret_key, result[0], &ptxt_max);
    // ptxt_max->set_length(1);
    // std::cout << "Maximum value: " << ptxt_max << std::endl;
    // cc->decrypt(keys.secret_key, result[1], &ptxt_max);

    // if (num_values <= 64) {  // Otherwise, supress output
    //     if (one_hot) {
    //         ptxt_max->set_length(num_values);
    //         std::cout << "Argmax indicator vector: " << ptxt_max << std::endl;
    //     }
    //     else {
    //         ptxt_max->set_length(1);
    //         std::cout << "Argmax: " << ptxt_max << std::endl;
    //     }
    // }
    // std::cout << "Time to compute max and argmax via scheme switching: " << timeEvalMax/ 60000 << " min" << std::endl;

    double total_time = TOC(t_total_value);
    std::cout << "\nTotal time: " << total_time / 60000 << " min" << std::endl;

    cc->clear_static_maps_and_vectors();
}

void argmin(uint32_t depth, uint32_t slots, uint32_t num_values, uint32_t ring_dim) {
    /*
  Example of computing the min and argmin of the vector packed in a CKKS ciphertext.
 */
    std::cout << "\n-----ArgminViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    TimeVar t, t_total_value;
    double time_key_gen(0.0), time_setup(0.0), time_precomp(0.0), time_eval_min(0.0);  // timeEvalMax(0.0);

    TIC(t_total_value);

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scale_mod_size = 52;
    uint32_t first_mod_size_value = 60;
    uint32_t log_q_cc_lwe = 26;
    bool one_hot = true;  // Change to false if the output should not be one-hot encoded

    uint32_t batch_size = slots;
    ScalingTechnique sc_tech = FLEXIBLEAUTO;
    if (sc_tech == FLEXIBLEAUTOEXT)
        depth += 1;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(depth);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_technique(sc_tech);
    parameters.set_batch_size(batch_size);
    parameters.set_ring_dim(ring_dim);
    parameters.set_security_level(HEStd_NotSet);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << depth << std::endl << std::endl;

    // Generate encryption keys
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    params.set_num_values(num_values);
    params.set_compute_argmin(true);
    params.set_one_hot_encoding(one_hot);
    TIC(t);
    auto private_key_fhew = cc->eval_scheme_switching_setup(params);
    time_setup = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << time_setup / 1000 << " s" << std::endl;

    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

    TIC(t);
    cc->eval_scheme_switching_key_gen(keys, private_key_fhew);
    time_key_gen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << time_key_gen / 60000 << " min" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    std::cout << num_values << " slots are being switched." << std::endl << std::endl;

    TIC(t);
    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scale_sign = 512.0;
    auto p_lwe = 1 << (log_q_cc_lwe - 12);  // Large precision
    cc->eval_compare_switch_precompute(p_lwe, scale_sign);
    time_precomp = TOC(t);
    std::cout << "Time to do the precomputations: " << time_precomp / 1000 << " s" << std::endl;

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                             9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x.size() < slots) {
        std::vector<int> zeros(slots - x.size(), 0);
        x.insert(x.end(), zeros.begin(), zeros.end());
    }

    std::cout << "Expected minimum value " << *(std::min_element(x.begin(), x.begin() + num_values)) << " at location "
              << std::min_element(x.begin(), x.begin() + num_values) - x.begin() << std::endl;
    std::cout << "Expected maximum value " << *(std::max_element(x.begin(), x.begin() + num_values)) << " at location "
              << std::max_element(x.begin(), x.begin() + num_values) - x.begin() << std::endl;
    std::cout << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x);

    // Encrypt the encoded vectors
    auto c1 = cc->encrypt(keys.public_key, ptxt1);

    // Step 4: Argmin evaluation
    TIC(t);
    auto result = cc->eval_min_scheme_switching(c1, keys.public_key, num_values, slots);
    time_eval_min = TOC(t);

    Plaintext ptxt_min;
    cc->decrypt(keys.secret_key, result[0], &ptxt_min);
    ptxt_min->set_length(1);
    std::cout << "Minimum value: " << ptxt_min << std::endl;
    cc->decrypt(keys.secret_key, result[1], &ptxt_min);

    if (num_values <= 64) {  // Otherwise, supress output
        if (one_hot) {
            ptxt_min->set_length(num_values);
            std::cout << "Argmin indicator vector: " << ptxt_min << std::endl;
        } else {
            ptxt_min->set_length(1);
            std::cout << "Argmin: " << ptxt_min << std::endl;
        }
    }
    std::cout << "Time to compute min and argmin via scheme switching: " << time_eval_min / 60000 << " min"
              << std::endl;

    // TIC(t);
    // result      = cc->eval_max_scheme_switching(c1, keys.public_key, num_values, slots);
    // timeEvalMax = TOC(t);

    // Plaintext ptxt_max;
    // cc->decrypt(keys.secret_key, result[0], &ptxt_max);
    // ptxt_max->set_length(1);
    // std::cout << "Maximum value: " << ptxt_max << std::endl;
    // cc->decrypt(keys.secret_key, result[1], &ptxt_max);

    // if (num_values <= 64) {  // Otherwise, supress output
    //     if (one_hot) {
    //         ptxt_max->set_length(num_values);
    //         std::cout << "Argmax indicator vector: " << ptxt_max << std::endl;
    //     }
    //     else {
    //         ptxt_max->set_length(1);
    //         std::cout << "Argmax: " << ptxt_max << std::endl;
    //     }
    // }
    // std::cout << "Time to compute max and argmax via scheme switching: " << timeEvalMax/ 60000 << " min" << std::endl;

    double total_time = TOC(t_total_value);
    std::cout << "\nTotal time: " << total_time / 60000 << " min" << std::endl;

    cc->clear_static_maps_and_vectors();
}

void argmin_alt(uint32_t depth, uint32_t slots, uint32_t num_values, uint32_t ring_dim) {
    /*
  Example of computing the min and argmin of the vector packed in a CKKS ciphertext.
 */
    std::cout << "\n-----ArgminViaSchemeSwitchingAlt-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    TimeVar t, t_total_value;
    double time_key_gen(0.0), time_setup(0.0), time_precomp(0.0), time_eval_min(0.0);  // timeEvalMax(0.0);

    TIC(t_total_value);

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scale_mod_size = 52;
    uint32_t first_mod_size_value = 60;
    uint32_t log_q_cc_lwe = 26;
    bool one_hot = true;  // Change to false if the output should not be one-hot encoded

    uint32_t batch_size = slots;
    ScalingTechnique sc_tech = FLEXIBLEAUTO;
    if (sc_tech == FLEXIBLEAUTOEXT)
        depth += 1;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(depth);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_technique(sc_tech);
    parameters.set_batch_size(batch_size);
    parameters.set_ring_dim(ring_dim);
    parameters.set_security_level(HEStd_NotSet);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << depth << std::endl << std::endl;

    // Generate encryption keys
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    params.set_num_values(num_values);
    params.set_compute_argmin(true);
    params.set_one_hot_encoding(one_hot);
    params.set_use_alt_argmin(true);
    TIC(t);
    auto private_key_fhew = cc->eval_scheme_switching_setup(params);
    time_setup = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << time_setup / 1000 << " s" << std::endl;

    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

    TIC(t);
    cc->eval_scheme_switching_key_gen(keys, private_key_fhew);
    time_key_gen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << time_key_gen / 60000 << " min" << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    std::cout << num_values << " slots are being switched." << std::endl << std::endl;

    TIC(t);
    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scale_sign = 512.0;
    auto p_lwe = 1 << (log_q_cc_lwe - 12);  // Large precision

    uint32_t init_level = 0;
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());
    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT)
        init_level = 1;
    cc->eval_compare_switch_precompute(p_lwe, init_level, scale_sign);
    time_precomp = TOC(t);
    std::cout << "Time to do the precomputations: " << time_precomp / 1000 << " s" << std::endl;

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                             9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x.size() < slots) {
        std::vector<int> zeros(slots - x.size(), 0);
        x.insert(x.end(), zeros.begin(), zeros.end());
    }

    std::cout << "Expected minimum value " << *(std::min_element(x.begin(), x.begin() + num_values)) << " at location "
              << std::min_element(x.begin(), x.begin() + num_values) - x.begin() << std::endl;
    std::cout << "Expected maximum value " << *(std::max_element(x.begin(), x.begin() + num_values)) << " at location "
              << std::max_element(x.begin(), x.begin() + num_values) - x.begin() << std::endl;
    std::cout << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x);

    // Encrypt the encoded vectors
    auto c1 = cc->encrypt(keys.public_key, ptxt1);

    // Step 4: Argmin evaluation
    TIC(t);
    auto result = cc->eval_min_scheme_switching_alt(c1, keys.public_key, num_values, slots);
    time_eval_min = TOC(t);

    Plaintext ptxt_min;
    cc->decrypt(keys.secret_key, result[0], &ptxt_min);
    ptxt_min->set_length(1);
    std::cout << "Minimum value: " << ptxt_min << std::endl;
    cc->decrypt(keys.secret_key, result[1], &ptxt_min);

    if (num_values <= 64) {  // Otherwise, supress output
        if (one_hot) {
            ptxt_min->set_length(num_values);
            std::cout << "Argmin indicator vector: " << ptxt_min << std::endl;
        } else {
            ptxt_min->set_length(1);
            std::cout << "Argmin: " << ptxt_min << std::endl;
        }
    }
    std::cout << "Time to compute min and argmin via scheme switching: " << time_eval_min / 60000 << " min"
              << std::endl;

    // TIC(t);
    // result      = cc->eval_max_scheme_switching_alt(c1, keys.public_key, num_values, slots);
    // timeEvalMax = TOC(t);

    // Plaintext ptxt_max;
    // cc->decrypt(keys.secret_key, result[0], &ptxt_max);
    // ptxt_max->set_length(1);
    // std::cout << "Maximum value: " << ptxt_max << std::endl;
    // cc->decrypt(keys.secret_key, result[1], &ptxt_max);

    // if (num_values <= 64) {  // Otherwise, supress output
    //     if (one_hot) {
    //         ptxt_max->set_length(num_values);
    //         std::cout << "Argmax indicator vector: " << ptxt_max << std::endl;
    //     }
    //     else {
    //         ptxt_max->set_length(1);
    //         std::cout << "Argmax: " << ptxt_max << std::endl;
    //     }
    // }
    // std::cout << "Time to compute max and argmax via scheme switching: " << timeEvalMax/ 60000 << " min" << std::endl;

    double total_time = TOC(t_total_value);
    std::cout << "\nTotal time: " << total_time / 60000 << " min" << std::endl;

    cc->clear_static_maps_and_vectors();
}

void Comparison(uint32_t depth, uint32_t slots, uint32_t num_values, uint32_t ring_dim) {
    /*
  Example of comparing two CKKS ciphertexts via scheme switching.
 */
    std::cout << "\n-----ComparisonViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back.\n" << std::endl;

    TimeVar t, t_total_value;
    double time_key_gen(0.0), time_setup(0.0), time_precomp(0.0), time_eval(0.0);

    TIC(t_total_value);

    // Step 1: Setup CryptoContext for CKKS
    ScalingTechnique sc_tech = FIXEDAUTO;
    if (sc_tech == FLEXIBLEAUTOEXT)
        depth += 1;

    uint32_t scale_mod_size = 52;
    uint32_t first_mod_size_value = 60;
    uint32_t log_q_cc_lwe = 26;
    uint32_t batch_size = slots;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(depth);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_technique(sc_tech);
    parameters.set_batch_size(batch_size);
    parameters.set_ring_dim(ring_dim);
    parameters.set_security_level(HEStd_NotSet);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << depth << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    params.set_num_values(slots);
    TIC(t);
    auto private_key_fhew = cc->eval_scheme_switching_setup(params);
    time_setup = TOC(t);
    std::cout << "Time to compute the scheme switching setup: " << time_setup / 1000 << " s" << std::endl;

    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

    TIC(t);
    cc->eval_scheme_switching_key_gen(keys, private_key_fhew);
    time_key_gen = TOC(t);
    std::cout << "Time to compute the scheme switching key generation: " << time_key_gen / 60000 << " min" << std::endl
              << std::endl;

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    std::cout << num_values << " slots are being switched." << std::endl;

    TIC(t);
    // Pre-computations
    auto modulus_lwe = 1 << log_q_cc_lwe;
    auto beta = cc_lwe->get_beta().convert_to_int();
    auto p_lwe = modulus_lwe / (2 * beta);

    double scale_sign_fhew = 8.0;
    const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());
    uint32_t init_level = 0;
    if (crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT)
        init_level = 1;
    cc->eval_compare_switch_precompute(p_lwe, init_level, scale_sign_fhew);
    time_precomp = TOC(t);
    std::cout << "Time to perform precomputations: " << time_precomp / 1000 << " s" << std::endl;

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x1 = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0};
    std::vector<double> x2(slots, 5.25);
    if (x1.size() < slots) {
        std::vector<int> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }
    if (x2.size() < slots) {
        std::vector<int> zeros(slots - x2.size(), 0);
        x2.insert(x2.end(), zeros.begin(), zeros.end());
    }

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x1, 1, 0, nullptr);
    Plaintext ptxt2 = cc->make_ckks_packed_plaintext(x2, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->encrypt(keys.public_key, ptxt1);
    auto c2 = cc->encrypt(keys.public_key, ptxt2);

    // Compute the difference to compare to zero
    auto c_diff = cc->eval_sub(c1, c2);

    Plaintext p_diff;
    cc->decrypt(keys.secret_key, c_diff, &p_diff);
    p_diff->set_length(slots);
    if (slots <= 64) {  // Otherwise, supress output
        std::cout << "Difference of inputs: ";
        auto p_diff_rpv = p_diff->get_real_packed_value();
        for (uint32_t i = 0; i < slots; ++i) {
            std::cout << p_diff_rpv[i] << " ";
        }
    }

    if (num_values <= 64) {  // Otherwise, supress output
        const double eps = 0.0001;
        std::cout << "\nExpected sign result from CKKS: ";
        auto p_diff_rpv = p_diff->get_real_packed_value();
        for (uint32_t i = 0; i < num_values; ++i) {
            std::cout << int(std::round(p_diff_rpv[i] / eps) * eps < 0) << " ";
        }
        std::cout << "\n";
    }

    // Step 4: Comparison via CKKS->FHEW->CKKS
    TIC(t);
    auto c_result = cc->eval_compare_scheme_switching(c1, c2, num_values, slots);
    time_eval = TOC(t);
    std::cout << "Time to perform comparison via scheme switching: " << time_eval / 60000 << " min" << std::endl;

    Plaintext plaintext_dec3;
    cc->decrypt(keys.secret_key, c_result, &plaintext_dec3);
    plaintext_dec3->set_length(num_values);

    if (num_values <= 64) {  // Otherwise, supress output
        std::cout << "Decrypted switched result: " << plaintext_dec3 << std::endl;
    }

    double total_time = TOC(t_total_value);
    std::cout << "\nTotal time: " << total_time / 60000 << " min" << std::endl;
}
