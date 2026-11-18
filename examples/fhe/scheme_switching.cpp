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
  Examples for scheme switching between CKKS and FHEW and back, with intermediate computations
 */

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>

#include "cipher/boolean/context.h"
#include "cipher/cipher.h"

using namespace cipher;

void switch_ckks_to_fhew();
void switch_fhew_to_ckks();
void floor_via_scheme_switching();
void comparison_via_scheme_switching();
void func_via_scheme_switching();
void poly_via_scheme_switching();
void argmin_via_scheme_switching();
void argmin_via_scheme_switching_alt();
void argmin_via_scheme_switching_unit();
void argmin_via_scheme_switching_alt_unit();
std::vector<int32_t> rotate_int(const std::vector<int32_t>&, int32_t);

int main() {
    switch_ckks_to_fhew();
    switch_fhew_to_ckks();
    floor_via_scheme_switching();
    func_via_scheme_switching();
    poly_via_scheme_switching();
    comparison_via_scheme_switching();
    argmin_via_scheme_switching();
    argmin_via_scheme_switching_alt();
    argmin_via_scheme_switching_unit();
    argmin_via_scheme_switching_alt_unit();

    return 0;
}

void switch_ckks_to_fhew() {
    /*
  Example of switching a packed ciphertext from CKKS to multiple FHEW ciphertexts.
 */

    std::cout << "\n-----SwitchCKKSToFHEW-----\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS

    // Specify main parameters
    uint32_t mult_depth_value = 3;
    uint32_t first_mod_size_value = 60;
    uint32_t scale_mod_size = 50;
    uint32_t ring_dim = 4096;
    SecurityLevel sl = HEStd_NotSet;
    BINFHE_PARAMSET sl_bin = TOY;
    uint32_t log_q_cc_lwe = 25;
    // uint32_t slots        = ring_dim / 2;  // Uncomment for fully-packed
    uint32_t slots = 16;  // sparsely-packed
    uint32_t batch_size = slots;

    ContextParams<CkksRnsContext> parameters;

    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_scaling_technique(FLEXIBLEAUTOEXT);
    parameters.set_security_level(sl);
    parameters.set_ring_dim(ring_dim);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << mult_depth_value
              << std::endl
              << std::endl;

    // Generate encryption keys
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_security_level_ckks(sl);
    params.set_security_level_fhew(sl_bin);
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    auto private_key_fhew = cc->eval_ckks_to_fhew_setup(params);
    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();
    cc->eval_ckks_to_fhew_key_gen(keys, private_key_fhew);

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    // Compute the scaling factor to decrypt correctly in FHEW; under the hood, the LWE mod switch will performed on the ciphertext at the last level
    auto p_lwe1 = cc_lwe->get_max_plaintext_space().convert_to_int();  // Small precision
    auto modulus_lwe = 1 << log_q_cc_lwe;
    auto beta = cc_lwe->get_beta().convert_to_int();
    auto p_lwe2 = modulus_lwe / (2 * beta);  // Large precision

    double scale1 = 1.0 / p_lwe1;
    double scale2 = 1.0 / p_lwe2;

    // Perform the precomputation for switching
    cc->eval_ckks_to_fhew_precompute(scale1);

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0};
    std::vector<double> x2 = {0.0, 271.0, 30000.0, static_cast<double>(p_lwe2) - 2};
    uint32_t encoded_length1 = x1.size();
    uint32_t encoded_length2 = x2.size();

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x1, 1, 0, nullptr);
    Plaintext ptxt2 = cc->make_ckks_packed_plaintext(x2, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->encrypt(keys.public_key, ptxt1);
    auto c2 = cc->encrypt(keys.public_key, ptxt2);

    // Step 4: Scheme switching from CKKS to FHEW

    // A: First scheme switching case

    // Transform the ciphertext from CKKS to FHEW
    auto c_temp = cc->eval_ckks_to_fhew(c1, encoded_length1);

    std::cout << "\n---Decrypting switched ciphertext with small precision (plaintext modulus " << NativeInteger(p_lwe1)
              << ")---\n"
              << std::endl;

    std::vector<int32_t> x1_int(encoded_length1);
    std::transform(x1.begin(), x1.end(), x1_int.begin(), [&](const double& elem) {
        return static_cast<int32_t>(static_cast<int32_t>(std::round(elem)) % p_lwe1);
    });
    ptxt1->set_length(encoded_length1);
    std::cout << "Input x1: " << ptxt1->get_real_packed_value() << "; which rounds to: " << x1_int << std::endl;
    std::cout << "FHEW decryption: ";
    LwePlaintext result;
    for (uint32_t i = 0; i < c_temp.size(); ++i) {
        cc_lwe->decrypt(private_key_fhew, c_temp[i], &result, p_lwe1);
        std::cout << result << " ";
    }
    std::cout << "\n" << std::endl;

    // B: Second scheme switching case

    // Perform the precomputation for switching
    cc->eval_ckks_to_fhew_precompute(scale2);

    // Transform the ciphertext from CKKS to FHEW (only for the number of inputs given)
    auto c_temp2 = cc->eval_ckks_to_fhew(c2, encoded_length2);

    std::cout << "\n---Decrypting switched ciphertext with large precision (plaintext modulus " << NativeInteger(p_lwe2)
              << ")---\n"
              << std::endl;

    ptxt2->set_length(encoded_length2);
    std::cout << "Input x2: " << ptxt2->get_real_packed_value() << std::endl;
    std::cout << "FHEW decryption: ";
    for (uint32_t i = 0; i < c_temp2.size(); ++i) {
        cc_lwe->decrypt(private_key_fhew, c_temp2[i], &result, p_lwe2);
        std::cout << result << " ";
    }
    std::cout << "\n" << std::endl;

    // C: Decompose the FHEW ciphertexts in smaller digits
    std::cout << "Decomposed values for digit size of " << NativeInteger(p_lwe1) << ": " << std::endl;
    // Generate the bootstrapping keys (refresh and switching keys)
    cc_lwe->bt_key_gen(private_key_fhew);

    for (uint32_t j = 0; j < c_temp2.size(); j++) {
        // Decompose the large ciphertext into small ciphertexts that fit in q
        auto decomp = cc_lwe->eval_decomp(c_temp2[j]);

        // Decryption
        auto p = cc_lwe->get_max_plaintext_space().convert_to_int();
        LweCiphertext ct;
        for (size_t i = 0; i < decomp.size(); i++) {
            ct = decomp[i];
            LwePlaintext result_decomp;
            // The last digit should be up to P / p^floor(log_p(P))
            if (i == decomp.size() - 1) {
                p = p_lwe2 / std::pow(static_cast<double>(p_lwe1), std::floor(std::log(p_lwe2) / std::log(p_lwe1)));
            }
            cc_lwe->decrypt(private_key_fhew, ct, &result_decomp, p);
            std::cout << "(" << result_decomp << " * " << NativeInteger(p_lwe1) << "^" << i << ")";
            if (i != decomp.size() - 1) {
                std::cout << " + ";
            }
        }
        std::cout << std::endl;
    }

    cc->clear_static_maps_and_vectors();
}

void switch_fhew_to_ckks() {
    std::cout << "\n-----SwitchFHEWtoCKKS-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back.\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS to be switched into

    // A. Specify main parameters
    ScalingTechnique sc_tech = FIXEDAUTO;
    // for r = 3 in FHEWtoCKKS, Chebyshev max depth allowed is 9, 1 more level for postscaling
    uint32_t mult_depth_value = 3 + 9 + 1;
    if (sc_tech == FLEXIBLEAUTOEXT)
        mult_depth_value += 1;
    uint32_t scale_mod_size = 50;
    uint32_t ring_dim = 8192;
    SecurityLevel sl = HEStd_NotSet;  // If this is not HEStd_NotSet, ensure ring_dim is compatible
    uint32_t log_q_cc_lwe = 28;

    // uint32_t slots = ring_dim/2; // Uncomment for fully-packed
    uint32_t slots = 16;  // sparsely-packed
    uint32_t batch_size = slots;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_scaling_technique(sc_tech);
    parameters.set_security_level(sl);
    parameters.set_ring_dim(ring_dim);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << mult_depth_value
              << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    auto cc_lwe = std::make_shared<BooleanContext>();
    cc_lwe->BooleanContext::generate_boolean_context(STD128, false, log_q_cc_lwe, 0, GINX, false);

    // LWE private key
    LwePrivateKey lwesk;
    lwesk = cc_lwe->key_gen();

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    // Step 3. Precompute the necessary keys and information for switching from FHEW to CKKS
    cc->eval_fhew_to_ckks_setup(cc_lwe, slots, log_q_cc_lwe);
    cc->set_bin_cc_for_scheme_switch(cc_lwe);

    cc->eval_fhew_to_ckks_key_gen(keys, lwesk);

    // Step 4: Encoding and encryption of inputs

    std::vector<int> x1 = {1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0};
    std::vector<int> x2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    if (x1.size() < slots) {
        std::vector<int> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
        x2.insert(x2.end(), zeros.begin(), zeros.end());
    }

    uint32_t modulus_lwe = 1 << log_q_cc_lwe;

    uint32_t p_lwe1 = cc_lwe->get_max_plaintext_space().convert_to_int();  // Small precision
    uint32_t p_lwe2 = 256;                                                 // Medium precision

    // Messages encoded as [0000000MMMMM0000000EEEEE]
    // High level idea is to have enough 0's both before and after message for CKKS-bootstrapped result to achieve reasonable accuracy.
    // Number of leading zeros determined by ratio of ciphertext modulus to plaintext modulus; Need 10 - 12 bits for better accuracy with sin(x) ~ x approximation of mod x.
    // Number of zeros between message and error determined by the ratio of plaintext modulus to magnitude of max value in message; Need gap between message and error
    //   large enough for correctly rounded message even after leveled computations in the linear transformation before evaluating sin(x).

    uint32_t gap_bits = (log_q_cc_lwe - std::log2(2 * (*std::max_element(x2.begin(), x2.end())))) / 2;
    uint32_t p_lwe3 = 1 << (log_q_cc_lwe - gap_bits);  // Large precision

    // Encrypt
    std::vector<LweCiphertext> ctxts_lwe1(slots);
    for (uint32_t i = 0; i < slots; i++) {
        // encrypted under small plantext modulus p = 4 and ciphertext modulus
        ctxts_lwe1[i] = cc_lwe->encrypt(lwesk, x1[i]);
    }

    std::vector<LweCiphertext> ctxts_lwe2(slots);
    for (uint32_t i = 0; i < slots; i++) {
        // encrypted under larger plaintext modulus p = 16 but small ciphertext modulus
        ctxts_lwe2[i] = cc_lwe->encrypt(lwesk, x1[i], LARGE_DIM, p_lwe1);
    }

    std::vector<LweCiphertext> ctxts_lwe3(slots);
    for (uint32_t i = 0; i < slots; i++) {
        // here, ratio between plaintext modulus and message magnitude is small, resulting in higher error
        ctxts_lwe3[i] = cc_lwe->encrypt(lwesk, x2[i], LARGE_DIM, p_lwe2, modulus_lwe);
    }

    std::vector<LweCiphertext> ctxts_lwe4(slots);
    for (uint32_t i = 0; i < slots; i++) {
        // here, ratio between plaintext modulus and message magnitude is high, resulting in better accuracy
        ctxts_lwe4[i] = cc_lwe->encrypt(lwesk, x2[i], LARGE_DIM, p_lwe3, modulus_lwe);
    }

    // Step 5. Perform the scheme switching
    auto c_temp = cc->eval_fhew_to_ckks(ctxts_lwe1, slots, slots);

    std::cout << "\n---Input x1: " << x1 << " encrypted under p = " << 4 << " and Q = " << ctxts_lwe1[0]->get_modulus()
              << "---" << std::endl;

    // Step 6. Decrypt
    Plaintext plaintext_dec;
    cc->decrypt(keys.secret_key, c_temp, &plaintext_dec);
    plaintext_dec->set_length(slots);
    std::cout << "Switched CKKS decryption 1: " << plaintext_dec << std::endl;

    // Step 5'. Perform the scheme switching
    c_temp = cc->eval_fhew_to_ckks(ctxts_lwe2, slots, slots, p_lwe1, 0, p_lwe1);

    std::cout << "\n---Input x1: " << x1 << " encrypted under p = " << NativeInteger(p_lwe1)
              << " and Q = " << ctxts_lwe2[0]->get_modulus() << "---" << std::endl;

    // Step 6'. Decrypt
    cc->decrypt(keys.secret_key, c_temp, &plaintext_dec);
    plaintext_dec->set_length(slots);
    std::cout << "Switched CKKS decryption 2: " << plaintext_dec << std::endl;

    // Step 5''. Perform the scheme switching
    c_temp = cc->eval_fhew_to_ckks(ctxts_lwe3, slots, slots, p_lwe2, 0, p_lwe2);

    std::cout << "\n---Input x2: " << x2 << " encrypted under p = " << p_lwe2
              << " and Q = " << ctxts_lwe3[0]->get_modulus() << "---" << std::endl;

    // Step 6''. Decrypt
    cc->decrypt(keys.secret_key, c_temp, &plaintext_dec);
    plaintext_dec->set_length(slots);
    std::cout << "Switched CKKS decryption 3: " << plaintext_dec << std::endl;

    // Step 5'''. Perform the scheme switching
    std::setprecision(log_q_cc_lwe + 10);
    auto c_temp2 = cc->eval_fhew_to_ckks(ctxts_lwe4, slots, slots, p_lwe3, 0, p_lwe3);

    std::cout << "\n---Input x2: " << x2 << " encrypted under p = " << NativeInteger(p_lwe3)
              << " and Q = " << ctxts_lwe4[0]->get_modulus() << "---" << std::endl;

    // Step 6'''. Decrypt
    Plaintext plaintext_dec2;
    cc->decrypt(keys.secret_key, c_temp2, &plaintext_dec2);
    plaintext_dec2->set_length(slots);
    std::cout << "Switched CKKS decryption 4: " << plaintext_dec2 << std::endl;

    cc->clear_static_maps_and_vectors();
}

void floor_via_scheme_switching() {
    std::cout << "\n-----FloorViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back.\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS
    ScalingTechnique sc_tech = FLEXIBLEAUTO;

    // for r = 3 in FHEWtoCKKS, Chebyshev max depth allowed is 9, 1 more level for postscaling
    uint32_t mult_depth_value = 3 + 9 + 1;
    if (sc_tech == FLEXIBLEAUTOEXT)
        mult_depth_value += 1;
    uint32_t scale_mod_size = 50;
    uint32_t ring_dim = 8192;
    SecurityLevel sl = HEStd_NotSet;
    BINFHE_PARAMSET sl_bin = TOY;
    uint32_t log_q_cc_lwe = 23;
    uint32_t slots = 16;  // sparsely-packed
    uint32_t batch_size = slots;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_scaling_technique(sc_tech);
    parameters.set_security_level(sl);
    parameters.set_ring_dim(ring_dim);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << mult_depth_value
              << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_security_level_ckks(sl);
    params.set_security_level_fhew(sl_bin);
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    params.set_num_values(slots);
    auto private_key_fhew = cc->eval_scheme_switching_setup(params);
    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

    cc->eval_scheme_switching_key_gen(keys, private_key_fhew);

    // Generate bootstrapping key for eval_floor
    cc_lwe->bt_key_gen(private_key_fhew);

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    // Set the scaling factor to be able to decrypt; under the hood, the LWE mod switch will be performed on the ciphertext at the last level
    auto modulus_lwe = 1 << log_q_cc_lwe;
    auto beta = cc_lwe->get_beta().convert_to_int();
    auto p_lwe = modulus_lwe / (2 * beta);  // Large precision
    double scale_cf = 1.0 / p_lwe;

    cc->eval_ckks_to_fhew_precompute(scale_cf);

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x1 = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0};

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x1, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->encrypt(keys.public_key, ptxt1);

    // Step 4: Scheme switching from CKKS to FHEW
    auto c_temp = cc->eval_ckks_to_fhew(c1);

    // Step 5: Evaluate the floor function
    uint32_t bits = 2;

    std::vector<LweCiphertext> c_floor(c_temp.size());
    for (uint32_t i = 0; i < c_temp.size(); i++) {
        c_floor[i] = cc_lwe->eval_floor(c_temp[i], bits);
    }

    auto ptxt1_rpv = ptxt1->get_real_packed_value();
    std::cout << "Input x1: " << ptxt1_rpv << std::endl;
    std::cout << "Expected result for EvalFloor with " << bits << " bits: ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << (static_cast<int>(ptxt1_rpv[i]) >> bits) << " ";
    }
    LwePlaintext p_floor;
    std::cout << "\nFHEW decryption p = " << NativeInteger(p_lwe)
              << "/(1 << bits) = " << NativeInteger(p_lwe) / (1 << bits) << ": ";
    for (uint32_t i = 0; i < c_floor.size(); ++i) {
        cc_lwe->decrypt(private_key_fhew, c_floor[i], &p_floor, p_lwe / (1 << bits));
        std::cout << p_floor << " ";
    }
    std::cout << "\n" << std::endl;

    // Step 6: Scheme switching from FHEW to CKKS
    auto c_temp2 = cc->eval_fhew_to_ckks(c_floor, slots, slots, p_lwe / (1 << bits), 0, p_lwe / (1 << bits));

    Plaintext plaintext_dec2;
    cc->decrypt(keys.secret_key, c_temp2, &plaintext_dec2);
    plaintext_dec2->set_length(slots);
    std::cout << "Switched floor decryption modulus_LWE mod " << NativeInteger(p_lwe) / (1 << bits) << ": "
              << plaintext_dec2 << std::endl;

    cc->clear_static_maps_and_vectors();
}

void func_via_scheme_switching() {
    std::cout << "\n-----FuncViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back.\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS
    // 1 for CKKS to FHEW, 14 for FHEW to CKKS
    uint32_t mult_depth_value = 9 + 3 + 2;
    uint32_t scale_mod_size = 50;
    uint32_t ring_dim = 2048;
    SecurityLevel sl = HEStd_NotSet;
    BINFHE_PARAMSET sl_bin = TOY;
    uint32_t log_q_cc_lwe = 25;
    uint32_t slots = 8;  // sparsely-packed
    uint32_t batch_size = slots;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_scaling_technique(FIXEDAUTO);
    parameters.set_security_level(sl);
    parameters.set_ring_dim(ring_dim);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", and number of slots " << slots << std::endl << std::endl;

    // Generate encryption keys.
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_security_level_ckks(sl);
    params.set_security_level_fhew(sl_bin);
    params.set_arbitrary_function_evaluation(true);
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    params.set_num_values(slots);
    auto private_key_fhew = cc->eval_scheme_switching_setup(params);
    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

    cc->eval_scheme_switching_key_gen(keys, private_key_fhew);

    // Generate the bootstrapping keys for eval_func in FHEW
    cc_lwe->bt_key_gen(private_key_fhew);

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    // Set the scaling factor to be able to decrypt; under the hood, the LWE mod switch will be performed on the ciphertext at the last level
    auto p_lwe = cc_lwe->get_max_plaintext_space()
                         .convert_to_int();  // Small precision because generate_lut_via_function needs p < q
    double scale_cf = 1.0 / p_lwe;

    cc->eval_ckks_to_fhew_precompute(scale_cf);

    // Step 3: Initialize the function

    // Initialize Function f(x) = x^3 + 2x + 1 % p
    auto fp = [](NativeInteger m, NativeInteger p1) -> NativeInteger {
        if (m < p1)
            return (m * m * m + 2 * m * m + 1) % p1;
        else
            return ((m - p1 / 2) * (m - p1 / 2) * (m - p1 / 2) + 2 * (m - p1 / 2) * (m - p1 / 2) + 1) % p1;
    };

    // Generate LUT from function f(x)
    auto lut = cc_lwe->generate_lut_via_function(fp, p_lwe);

    // Step 4: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x1 = {0.0, 0.3, 2.0, 4.0, 5.0, 6.0, 7.0, 8.0};

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x1, 1, 0, nullptr);

    // Encrypt the encoded vectors
    auto c1 = cc->encrypt(keys.public_key, ptxt1);

    // Step 5: Scheme switching from CKKS to FHEW
    auto c_temp = cc->eval_ckks_to_fhew(c1);

    std::cout << "Input x1: " << ptxt1->get_real_packed_value() << std::endl;
    std::cout << "FHEW decryption: ";
    LwePlaintext result;
    for (uint32_t i = 0; i < c_temp.size(); ++i) {
        cc_lwe->decrypt(private_key_fhew, c_temp[i], &result, p_lwe);
        std::cout << result << " ";
    }

    // Step 6: Evaluate the function
    std::vector<LweCiphertext> c_func(c_temp.size());
    for (uint32_t i = 0; i < c_temp.size(); i++) {
        c_func[i] = cc_lwe->eval_func(c_temp[i], lut);
    }

    std::cout << "\nExpected result x^3 + 2*x + 1 mod p: ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << fp(static_cast<int>(x1[i]) % p_lwe, p_lwe) << " ";
    }
    LwePlaintext p_func;
    std::cout << "\nFHEW decryption mod " << NativeInteger(p_lwe) << ": ";
    for (uint32_t i = 0; i < c_func.size(); ++i) {
        cc_lwe->decrypt(private_key_fhew, c_func[i], &p_func, p_lwe);
        std::cout << p_func << " ";
    }
    std::cout << "\n" << std::endl;

    // Step 7: Scheme switching from FHEW to CKKS
    auto c_temp2 = cc->eval_fhew_to_ckks(c_func, slots, slots, p_lwe, 0, p_lwe);

    Plaintext plaintext_dec2;
    cc->decrypt(keys.secret_key, c_temp2, &plaintext_dec2);
    plaintext_dec2->set_length(slots);
    std::cout << "\nSwitched decryption modulus_LWE mod " << NativeInteger(p_lwe)
              << " works only for messages << p: " << plaintext_dec2 << std::endl;

    // Transform through arcsine
    c_temp2 = cc->eval_fhew_to_ckks(c_func, slots, slots, 4, 0, 2);

    cc->decrypt(keys.secret_key, c_temp2, &plaintext_dec2);
    plaintext_dec2->set_length(slots);
    std::cout << "Arcsin(switched result) * p/2pi gives the correct result if messages are < p/4: ";
    auto plaintext_dec2_rpv = plaintext_dec2->get_real_packed_value();
    for (uint32_t i = 0; i < slots; i++) {
        double x = std::max(std::min(plaintext_dec2_rpv[i], 1.0), -1.0);
        std::cout << std::asin(x) * p_lwe / (2 * M_PI) << " ";
    }
    std::cout << "\n";

    cc->clear_static_maps_and_vectors();
}

void comparison_via_scheme_switching() {
    std::cout << "\n-----ComparisonViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back.\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS
    ScalingTechnique sc_tech = FLEXIBLEAUTO;
    uint32_t mult_depth_value = 17;
    if (sc_tech == FLEXIBLEAUTOEXT)
        mult_depth_value += 1;

    uint32_t scale_mod_size = 50;
    uint32_t first_mod_size_value = 60;
    uint32_t ring_dim = 8192;
    SecurityLevel sl = HEStd_NotSet;
    BINFHE_PARAMSET sl_bin = TOY;
    uint32_t log_q_cc_lwe = 25;
    uint32_t slots = 16;  // sparsely-packed
    uint32_t batch_size = slots;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_technique(sc_tech);
    parameters.set_security_level(sl);
    parameters.set_ring_dim(ring_dim);
    parameters.set_batch_size(batch_size);
    parameters.set_secret_key_dist(UNIFORM_TERNARY);
    parameters.set_key_switch_technique(HYBRID);
    parameters.set_num_large_digits(3);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << mult_depth_value
              << std::endl
              << std::endl;

    // Generate encryption keys
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_security_level_ckks(sl);
    params.set_security_level_fhew(sl_bin);
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    params.set_num_values(slots);
    auto private_key_fhew = cc->eval_scheme_switching_setup(params);
    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

    cc_lwe->bt_key_gen(private_key_fhew);
    cc->eval_scheme_switching_key_gen(keys, private_key_fhew);

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    // Set the scaling factor to be able to decrypt; the LWE mod switch is performed on the ciphertext at the last level
    auto p_lwe1 = cc_lwe->get_max_plaintext_space().convert_to_int();  // Small precision
    auto modulus_lwe = 1 << log_q_cc_lwe;
    auto beta = cc_lwe->get_beta().convert_to_int();
    auto p_lwe2 = modulus_lwe / (2 * beta);  // Large precision
    double scale_sign_fhew = 1.0;
    cc->eval_compare_switch_precompute(p_lwe2, scale_sign_fhew);

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x1 = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0};
    std::vector<double> x2(slots, 5.25);

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x1, 1, 0, nullptr, slots);
    Plaintext ptxt2 = cc->make_ckks_packed_plaintext(x2, 1, 0, nullptr, slots);

    // Encrypt the encoded vectors
    auto c1 = cc->encrypt(keys.public_key, ptxt1);
    auto c2 = cc->encrypt(keys.public_key, ptxt2);

    // Compute the difference to compare to zero
    auto c_diff = cc->eval_sub(c1, c2);

    // Step 4: CKKS to FHEW switching and sign evaluation to test correctness
    Plaintext p_diff;
    cc->decrypt(keys.secret_key, c_diff, &p_diff);
    p_diff->set_length(slots);
    std::cout << "Difference of inputs: ";
    auto p_diff_rpv = p_diff->get_real_packed_value();
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << p_diff_rpv[i] << " ";
    }

    const double eps = 0.0001;
    std::cout << "\nExpected sign result from CKKS: ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << int(std::round(p_diff_rpv[i] / eps) * eps < 0) << " ";
    }
    std::cout << "\n";

    auto lwe_ciphertexts = cc->eval_ckks_to_fhew(c_diff, slots);

    LwePlaintext plain_lwe;
    std::cout << "\nFHEW decryption with plaintext modulus " << NativeInteger(p_lwe2) << ": ";
    for (uint32_t i = 0; i < lwe_ciphertexts.size(); ++i) {
        cc_lwe->decrypt(private_key_fhew, lwe_ciphertexts[i], &plain_lwe, p_lwe2);
        std::cout << plain_lwe << " ";
    }

    std::cout << "\nExpected sign result in FHEW with plaintext modulus " << NativeInteger(p_lwe2) << " and scale "
              << scale_sign_fhew << ": ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << (static_cast<int>(std::round(p_diff_rpv[i] * scale_sign_fhew)) % p_lwe2 - p_lwe2 / 2.0 >= 0)
                  << " ";
    }
    std::cout << "\n";

    std::cout << "Obtained sign result in FHEW with plaintext modulus " << NativeInteger(p_lwe2) << " and scale "
              << scale_sign_fhew << ": ";
    std::vector<LweCiphertext> lwe_sign(lwe_ciphertexts.size());
    for (uint32_t i = 0; i < lwe_ciphertexts.size(); ++i) {
        lwe_sign[i] = cc_lwe->eval_sign(lwe_ciphertexts[i]);
        cc_lwe->decrypt(private_key_fhew, lwe_sign[i], &plain_lwe, 2);
        std::cout << plain_lwe << " ";
    }
    std::cout << "\n";

    // Step 5: Direct comparison via CKKS->FHEW->CKKS
    auto c_result = cc->eval_compare_scheme_switching(c1, c2, slots, slots);

    Plaintext plaintext_dec3;
    cc->decrypt(keys.secret_key, c_result, &plaintext_dec3);
    plaintext_dec3->set_length(slots);
    std::cout << "Decrypted switched result: " << plaintext_dec3 << std::endl;

    // Step 2': Recompute the scaled matrix using a larger scaling
    scale_sign_fhew = 8.0;
    cc->eval_compare_switch_precompute(p_lwe2, scale_sign_fhew);

    // Step 4': CKKS to FHEW switching and sign evaluation to test correctness
    lwe_ciphertexts = cc->eval_ckks_to_fhew(c_diff, slots);

    std::cout << "\nFHEW decryption with plaintext modulus " << NativeInteger(p_lwe2) << " and scale "
              << scale_sign_fhew << ": ";
    for (uint32_t i = 0; i < lwe_ciphertexts.size(); ++i) {
        cc_lwe->decrypt(private_key_fhew, lwe_ciphertexts[i], &plain_lwe, p_lwe2);
        std::cout << plain_lwe << " ";
    }
    std::cout << "\nExpected sign result in FHEW with plaintext modulus " << NativeInteger(p_lwe2) << " and scale "
              << scale_sign_fhew << ": ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << (static_cast<int>(std::round(p_diff_rpv[i] * scale_sign_fhew)) % p_lwe2 - p_lwe2 / 2.0 >= 0)
                  << " ";
    }
    std::cout << "\n";
    std::cout << "Obtained sign result in FHEW with plaintext modulus " << NativeInteger(p_lwe2) << " and scale "
              << scale_sign_fhew << ": ";
    for (uint32_t i = 0; i < lwe_ciphertexts.size(); ++i) {
        lwe_sign[i] = cc_lwe->eval_sign(lwe_ciphertexts[i]);
        cc_lwe->decrypt(private_key_fhew, lwe_sign[i], &plain_lwe, 2);
        std::cout << plain_lwe << " ";
    }
    std::cout << "\n";

    // Step 5': Direct comparison via CKKS->FHEW->CKKS
    c_result = cc->eval_compare_scheme_switching(c1, c2, slots, slots);

    cc->decrypt(keys.secret_key, c_result, &plaintext_dec3);
    plaintext_dec3->set_length(slots);
    std::cout << "Decrypted switched result: " << plaintext_dec3 << std::endl;

    // Step 2'': Recompute the scaled matrix using other parameters
    std::cout
            << "\nFor very small LWE plaintext modulus and initial fractional inputs, the sign does not always behave properly close to the boundaries at 0 and p/2."
            << std::endl;
    scale_sign_fhew = 1.0;
    cc->eval_compare_switch_precompute(p_lwe1, scale_sign_fhew);

    // Step 4'': CKKS to FHEW switching and sign evaluation to test correctness
    lwe_ciphertexts = cc->eval_ckks_to_fhew(c_diff, slots);

    std::cout << "\nFHEW decryption with plaintext modulus " << NativeInteger(p_lwe1) << ": ";
    for (uint32_t i = 0; i < lwe_ciphertexts.size(); ++i) {
        cc_lwe->decrypt(private_key_fhew, lwe_ciphertexts[i], &plain_lwe, p_lwe1);
        std::cout << plain_lwe << " ";
    }
    std::cout << "\nExpected sign result in FHEW with plaintext modulus " << NativeInteger(p_lwe1) << " and scale "
              << scale_sign_fhew << ": ";
    for (uint32_t i = 0; i < slots; ++i) {
        std::cout << (static_cast<int>(std::round(p_diff_rpv[i] * scale_sign_fhew)) % p_lwe1 - p_lwe1 / 2.0 >= 0)
                  << " ";
    }
    std::cout << "\n";
    std::cout << "Obtained sign result in FHEW with plaintext modulus " << NativeInteger(p_lwe1) << " and scale "
              << scale_sign_fhew << ": ";
    for (uint32_t i = 0; i < lwe_ciphertexts.size(); ++i) {
        lwe_sign[i] = cc_lwe->eval_sign(lwe_ciphertexts[i]);
        cc_lwe->decrypt(private_key_fhew, lwe_sign[i], &plain_lwe, 2);
        std::cout << plain_lwe << " ";
    }
    std::cout << "\n";

    // Step 5'': Direct comparison via CKKS->FHEW->CKKS
    c_result = cc->eval_compare_scheme_switching(c1, c2, slots, slots, 0, scale_sign_fhew);

    cc->decrypt(keys.secret_key, c_result, &plaintext_dec3);
    plaintext_dec3->set_length(slots);
    std::cout << "Decrypted switched result: " << plaintext_dec3 << std::endl;

    cc->clear_static_maps_and_vectors();
}

void argmin_via_scheme_switching() {
    std::cout << "\n-----ArgminViaSchemeSwitching-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scale_mod_size = 50;
    uint32_t first_mod_size_value = 60;
    uint32_t ring_dim = 8192;
    SecurityLevel sl = HEStd_NotSet;
    BINFHE_PARAMSET sl_bin = TOY;
    uint32_t log_q_cc_lwe = 25;
    bool one_hot = true;  // Change to false if the output should not be one-hot encoded

    uint32_t slots = 16;  // sparsely-packed
    uint32_t batch_size = slots;
    uint32_t num_values = 16;
    ScalingTechnique sc_tech = FLEXIBLEAUTOEXT;
    // 13 for FHEW to CKKS, log2(num_values) for argmin
    uint32_t mult_depth_value = 9 + 3 + 1 + static_cast<int>(std::log2(num_values));
    if (sc_tech == FLEXIBLEAUTOEXT)
        mult_depth_value += 1;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_technique(sc_tech);
    parameters.set_security_level(sl);
    parameters.set_ring_dim(ring_dim);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << mult_depth_value << std::endl
              << std::endl;

    // Generate encryption keys
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_security_level_ckks(sl);
    params.set_security_level_fhew(sl_bin);
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    params.set_num_values(num_values);
    params.set_compute_argmin(true);
    auto private_key_fhew = cc->eval_scheme_switching_setup(params);
    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

    cc->eval_scheme_switching_key_gen(keys, private_key_fhew);

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scale_sign = 512.0;
    auto modulus_lwe = 1 << log_q_cc_lwe;
    auto beta = cc_lwe->get_beta().convert_to_int();
    auto p_lwe = modulus_lwe / (2 * beta);  // Large precision
    // This formulation is for clarity
    cc->eval_compare_switch_precompute(p_lwe, scale_sign);
    // But we can also include the scale_sign in p_lwe (here we use the fact both p_lwe and scale_sign are powers of two)
    // cc->eval_compare_switch_precompute(p_lwe / scale_sign, 1);

    // Step 3: Encoding and encryption of inputs
    // Inputs
    std::vector<double> x1 = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                              9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x1.size() < num_values) {
        std::vector<int> zeros(num_values - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }

    std::cout << "Expected minimum value " << *(std::min_element(x1.begin(), x1.begin() + num_values))
              << " at location " << std::min_element(x1.begin(), x1.begin() + num_values) - x1.begin() << std::endl;
    std::cout << "Expected maximum value " << *(std::max_element(x1.begin(), x1.begin() + num_values))
              << " at location " << std::max_element(x1.begin(), x1.begin() + num_values) - x1.begin() << std::endl
              << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x1);  // Only if we we set batchsize
    // Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x1, 1, 0, nullptr, slots); // If batchsize is not set

    // Encrypt the encoded vectors
    auto c1 = cc->encrypt(keys.public_key, ptxt1);

    // Step 4: Argmin evaluation
    auto result = cc->eval_min_scheme_switching(c1, keys.public_key, num_values, slots);

    Plaintext ptxt_min;
    cc->decrypt(keys.secret_key, result[0], &ptxt_min);
    ptxt_min->set_length(1);
    std::cout << "Minimum value: " << ptxt_min << std::endl;
    cc->decrypt(keys.secret_key, result[1], &ptxt_min);
    if (one_hot) {
        ptxt_min->set_length(num_values);
        std::cout << "Argmin indicator vector: " << ptxt_min << std::endl;
    } else {
        ptxt_min->set_length(1);
        std::cout << "Argmin: " << ptxt_min << std::endl;
    }

    result = cc->eval_max_scheme_switching(c1, keys.public_key, num_values, slots);

    Plaintext ptxt_max;
    cc->decrypt(keys.secret_key, result[0], &ptxt_max);
    ptxt_max->set_length(1);
    std::cout << "Maximum value: " << ptxt_max << std::endl;
    cc->decrypt(keys.secret_key, result[1], &ptxt_max);
    if (one_hot) {
        ptxt_max->set_length(num_values);
        std::cout << "Argmax indicator vector: " << ptxt_max << std::endl;
    } else {
        ptxt_max->set_length(1);
        std::cout << "Argmax: " << ptxt_max << std::endl;
    }

    cc->clear_static_maps_and_vectors();
}

void argmin_via_scheme_switching_alt() {
    std::cout << "\n-----ArgminViaSchemeSwitchingAlt-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scale_mod_size = 50;
    uint32_t first_mod_size_value = 60;
    uint32_t ring_dim = 8192;
    SecurityLevel sl = HEStd_NotSet;
    BINFHE_PARAMSET sl_bin = TOY;
    uint32_t log_q_cc_lwe = 25;
    bool one_hot = true;  // Change to false if the output should not be one-hot encoded

    uint32_t slots = 16;  // sparsely-packed
    uint32_t batch_size = slots;
    uint32_t num_values = 16;
    ScalingTechnique sc_tech = FLEXIBLEAUTOEXT;
    // 13 for FHEW to CKKS, log2(num_values) for argmin
    uint32_t mult_depth_value = 9 + 3 + 1 + static_cast<int>(std::log2(num_values));
    if (sc_tech == FLEXIBLEAUTOEXT)
        mult_depth_value += 1;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_technique(sc_tech);
    parameters.set_security_level(sl);
    parameters.set_ring_dim(ring_dim);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << mult_depth_value << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_security_level_ckks(sl);
    params.set_security_level_fhew(sl_bin);
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    params.set_num_values(num_values);
    params.set_compute_argmin(true);
    params.set_use_alt_argmin(true);
    auto private_key_fhew = cc->eval_scheme_switching_setup(params);
    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

    cc->eval_scheme_switching_key_gen(keys, private_key_fhew);

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    // Scale the inputs to ensure their difference is correctly represented after switching to FHEW
    double scale_sign = 512.0;
    auto modulus_lwe = 1 << log_q_cc_lwe;
    auto beta = cc_lwe->get_beta().convert_to_int();
    auto p_lwe = modulus_lwe / (2 * beta);  // Large precision
    // This formulation is for clarity
    cc->eval_compare_switch_precompute(p_lwe, scale_sign);
    // But we can also include the scale_sign in p_lwe (here we use the fact both p_lwe and scale_sign are powers of two)
    // cc->eval_compare_switch_precompute(p_lwe / scale_sign, 1);

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                              9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x1.size() < num_values) {
        std::vector<int> zeros(num_values - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }

    std::cout << "Expected minimum value " << *(std::min_element(x1.begin(), x1.begin() + num_values))
              << " at location " << std::min_element(x1.begin(), x1.begin() + num_values) - x1.begin() << std::endl;
    std::cout << "Expected maximum value " << *(std::max_element(x1.begin(), x1.begin() + num_values))
              << " at location " << std::max_element(x1.begin(), x1.begin() + num_values) - x1.begin() << std::endl
              << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x1);  // Only if we we set batchsize
    // Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x1, 1, 0, nullptr, slots); // If batchsize is not set

    // Encrypt the encoded vectors
    auto c1 = cc->encrypt(keys.public_key, ptxt1);

    // Step 4: Argmin evaluation
    auto result = cc->eval_min_scheme_switching_alt(c1, keys.public_key, num_values, slots);

    Plaintext ptxt_min;
    cc->decrypt(keys.secret_key, result[0], &ptxt_min);
    ptxt_min->set_length(1);
    std::cout << "Minimum value: " << ptxt_min << std::endl;
    cc->decrypt(keys.secret_key, result[1], &ptxt_min);
    if (one_hot) {
        ptxt_min->set_length(num_values);
        std::cout << "Argmin indicator vector: " << ptxt_min << std::endl;
    } else {
        ptxt_min->set_length(1);
        std::cout << "Argmin: " << ptxt_min << std::endl;
    }

    result = cc->eval_max_scheme_switching_alt(c1, keys.public_key, num_values, slots);

    Plaintext ptxt_max;
    cc->decrypt(keys.secret_key, result[0], &ptxt_max);
    ptxt_max->set_length(1);
    std::cout << "Maximum value: " << ptxt_max << std::endl;
    cc->decrypt(keys.secret_key, result[1], &ptxt_max);
    if (one_hot) {
        ptxt_max->set_length(num_values);
        std::cout << "Argmax indicator vector: " << ptxt_max << std::endl;
    } else {
        ptxt_max->set_length(1);
        std::cout << "Argmax: " << ptxt_max << std::endl;
    }

    cc->clear_static_maps_and_vectors();
}

void argmin_via_scheme_switching_unit() {
    std::cout << "\n-----ArgminViaSchemeSwitchingUnit-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scale_mod_size = 50;
    uint32_t first_mod_size_value = 60;
    uint32_t ring_dim = 8192;
    SecurityLevel sl = HEStd_NotSet;
    BINFHE_PARAMSET sl_bin = TOY;
    uint32_t log_q_cc_lwe = 25;
    bool one_hot = true;

    uint32_t slots = 32;  // sparsely-packed
    uint32_t batch_size = slots;
    uint32_t num_values = 32;
    ScalingTechnique sc_tech = FLEXIBLEAUTO;
    // 1 for CKKS to FHEW, 13 for FHEW to CKKS, log2(num_values) for argmin
    uint32_t mult_depth_value = 9 + 3 + 1 + static_cast<int>(std::log2(num_values));
    if (sc_tech == FLEXIBLEAUTOEXT)
        mult_depth_value += 1;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_technique(sc_tech);
    parameters.set_security_level(sl);
    parameters.set_ring_dim(ring_dim);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);
    cc->enable(FHE);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << mult_depth_value << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_security_level_ckks(sl);
    params.set_security_level_fhew(sl_bin);
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    params.set_num_values(num_values);
    params.set_compute_argmin(true);
    auto private_key_fhew = cc->eval_scheme_switching_setup(params);
    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

    cc->eval_scheme_switching_key_gen(keys, private_key_fhew);

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    // Here we assume the message does not need scaling, as they are in the unit circle.
    cc->eval_compare_switch_precompute(1, 1);

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                              9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x1.size() < slots) {
        std::vector<int> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }
    std::cout << "Input: " << x1 << std::endl;

    /* Here we to assume each element of x1 is between (-0.5, 0.5]. The user will use heuristics on the size of the plaintext to achieve this.
     * This will mean that even the difference of the messages will be between (-1,1].
     * However, if a good enough approximation of the maximum is not available and the scaled inputs are too small, the precision of the result
     * might not be good enough.
     */
    double p = 1 << (first_mod_size_value - scale_mod_size - 1);
    std::transform(x1.begin(), x1.end(), x1.begin(), [&](const double& elem) { return elem / (2 * p); });

    std::cout << "Input scaled: " << x1 << std::endl;
    std::cout << "Expected minimum value " << *(std::min_element(x1.begin(), x1.begin() + num_values))
              << " at location " << std::min_element(x1.begin(), x1.begin() + num_values) - x1.begin() << std::endl;
    std::cout << "Expected maximum value " << *(std::max_element(x1.begin(), x1.begin() + num_values))
              << " at location " << std::max_element(x1.begin(), x1.begin() + num_values) - x1.begin() << std::endl
              << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x1);

    // Encrypt the encoded vectors
    auto c1 = cc->encrypt(keys.public_key, ptxt1);

    // Step 4: Argmin evaluation
    auto result = cc->eval_min_scheme_switching(c1, keys.public_key, num_values, slots);

    Plaintext ptxt_min;
    cc->decrypt(keys.secret_key, result[0], &ptxt_min);
    ptxt_min->set_length(1);
    std::cout << "Minimum value: " << ptxt_min << std::endl;
    cc->decrypt(keys.secret_key, result[1], &ptxt_min);
    if (one_hot) {
        ptxt_min->set_length(num_values);
        std::cout << "Argmin indicator vector: " << ptxt_min << std::endl;
    } else {
        ptxt_min->set_length(1);
        std::cout << "Argmin: " << ptxt_min << std::endl;
    }

    result = cc->eval_max_scheme_switching(c1, keys.public_key, num_values, slots);

    Plaintext ptxt_max;
    cc->decrypt(keys.secret_key, result[0], &ptxt_max);
    ptxt_max->set_length(1);
    std::cout << "Maximum value: " << ptxt_max << std::endl;
    cc->decrypt(keys.secret_key, result[1], &ptxt_max);
    if (one_hot) {
        ptxt_max->set_length(num_values);
        std::cout << "Argmax indicator vector: " << ptxt_max << std::endl;
    } else {
        ptxt_max->set_length(1);
        std::cout << "Argmax: " << ptxt_max << std::endl;
    }

    cc->clear_static_maps_and_vectors();
}

void argmin_via_scheme_switching_alt_unit() {
    std::cout << "\n-----ArgminViaSchemeSwitchingAltUnit-----\n" << std::endl;
    std::cout << "Output precision is only wrt the operations in CKKS after switching back\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS
    uint32_t scale_mod_size = 50;
    uint32_t first_mod_size_value = 60;
    uint32_t ring_dim = 8192;
    SecurityLevel sl = HEStd_NotSet;
    BINFHE_PARAMSET sl_bin = TOY;
    uint32_t log_q_cc_lwe = 25;
    bool one_hot = true;

    uint32_t slots = 32;  // sparsely-packed
    uint32_t batch_size = slots;
    uint32_t num_values = 32;
    ScalingTechnique sc_tech = FLEXIBLEAUTO;
    // 1 for CKKS to FHEW, 13 for FHEW to CKKS, log2(num_values) for argmin
    uint32_t mult_depth_value = 9 + 3 + 1 + static_cast<int>(std::log2(num_values));
    if (sc_tech == FLEXIBLEAUTOEXT)
        mult_depth_value += 1;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_first_mod_size(first_mod_size_value);
    parameters.set_scaling_technique(sc_tech);
    parameters.set_security_level(sl);
    parameters.set_ring_dim(ring_dim);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);
    cc->enable(FHE);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", and number of slots " << slots << ", and supports a depth of " << mult_depth_value << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_security_level_ckks(sl);
    params.set_security_level_fhew(sl_bin);
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    params.set_num_values(num_values);
    params.set_compute_argmin(true);
    params.set_use_alt_argmin(true);
    auto private_key_fhew = cc->eval_scheme_switching_setup(params);
    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

    cc->eval_scheme_switching_key_gen(keys, private_key_fhew);

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    // Here we assume the message does not need scaling, as they are in the unit circle.
    cc->eval_compare_switch_precompute(1, 1);

    // Step 3: Encoding and encryption of inputs

    // Inputs
    std::vector<double> x1 = {-1.125, -1.12, 5.0,  6.0,  -1.0, 2.0,  8.0,   -1.0,
                              9.0,    10.0,  11.0, 12.0, 13.0, 14.0, 15.25, 15.30};
    if (x1.size() < slots) {
        std::vector<int> zeros(slots - x1.size(), 0);
        x1.insert(x1.end(), zeros.begin(), zeros.end());
    }
    std::cout << "Input: " << x1 << std::endl;

    /* Here we to assume each element of x1 is between (-0.5, 0.5]. The user will use heuristics on the size of the plaintext to achieve this.
     * This will mean that even the difference of the messages will be between (-1,1].
     * However, if a good enough approximation of the maximum is not available and the scaled inputs are too small, the precision of the result
     * might not be good enough.
     */
    double p = 1 << (first_mod_size_value - scale_mod_size - 1);
    std::transform(x1.begin(), x1.end(), x1.begin(), [&](const double& elem) { return elem / (2 * p); });

    std::cout << "Input scaled: " << x1 << std::endl;
    std::cout << "Expected minimum value " << *(std::min_element(x1.begin(), x1.begin() + num_values))
              << " at location " << std::min_element(x1.begin(), x1.begin() + num_values) - x1.begin() << std::endl;
    std::cout << "Expected maximum value " << *(std::max_element(x1.begin(), x1.begin() + num_values))
              << " at location " << std::max_element(x1.begin(), x1.begin() + num_values) - x1.begin() << std::endl
              << std::endl;

    // Encoding as plaintexts
    Plaintext ptxt1 = cc->make_ckks_packed_plaintext(x1);

    // Encrypt the encoded vectors
    auto c1 = cc->encrypt(keys.public_key, ptxt1);

    // Step 4: Argmin evaluation
    auto result = cc->eval_min_scheme_switching_alt(c1, keys.public_key, num_values, slots);

    Plaintext ptxt_min;
    cc->decrypt(keys.secret_key, result[0], &ptxt_min);
    ptxt_min->set_length(1);
    std::cout << "Minimum value: " << ptxt_min << std::endl;
    cc->decrypt(keys.secret_key, result[1], &ptxt_min);
    if (one_hot) {
        ptxt_min->set_length(num_values);
        std::cout << "Argmin indicator vector: " << ptxt_min << std::endl;
    } else {
        ptxt_min->set_length(1);
        std::cout << "Argmin: " << ptxt_min << std::endl;
    }

    result = cc->eval_max_scheme_switching_alt(c1, keys.public_key, num_values, slots);

    Plaintext ptxt_max;
    cc->decrypt(keys.secret_key, result[0], &ptxt_max);
    ptxt_max->set_length(1);
    std::cout << "Maximum value: " << ptxt_max << std::endl;
    cc->decrypt(keys.secret_key, result[1], &ptxt_max);
    if (one_hot) {
        ptxt_max->set_length(num_values);
        std::cout << "Argmax indicator vector: " << ptxt_max << std::endl;
    } else {
        ptxt_max->set_length(1);
        std::cout << "Argmax: " << ptxt_max << std::endl;
    }

    cc->clear_static_maps_and_vectors();
}

void poly_via_scheme_switching() {
    std::cout << "\n-----PolyViaSchemeSwitching-----\n" << std::endl;

    // Step 1: Setup CryptoContext for CKKS to be switched into

    // A. Specify main parameters
    ScalingTechnique sc_tech = FIXEDMANUAL;
    // for r = 3 in FHEWtoCKKS, Chebyshev max depth allowed is 9, 1 more level for postscaling, 3 levels for functionality
    uint32_t mult_depth_value = 3 + 9 + 1 + 2;
    if (sc_tech == FLEXIBLEAUTOEXT)
        mult_depth_value += 1;
    uint32_t scale_mod_size = 50;
    uint32_t ring_dim = 2048;
    SecurityLevel sl = HEStd_NotSet;
    BINFHE_PARAMSET sl_bin = TOY;
    uint32_t log_q_cc_lwe = 25;

    uint32_t slots = 16;  // sparsely-packed
    uint32_t batch_size = slots;

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(mult_depth_value);
    parameters.set_scaling_mod_size(scale_mod_size);
    parameters.set_scaling_technique(sc_tech);
    parameters.set_security_level(sl);
    parameters.set_ring_dim(ring_dim);
    parameters.set_batch_size(batch_size);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

    // Enable the features that you wish to use
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(SCHEMESWITCH);

    std::cout << "CKKS scheme is using ring dimension " << cc->get_ring_dimension();
    std::cout << ", number of slots " << slots << ", and supports a multiplicative depth of " << mult_depth_value
              << std::endl
              << std::endl;

    // Generate encryption keys.
    auto keys = cc->key_gen();

    // Step 2: Prepare the FHEW cryptocontext and keys for FHEW and scheme switching
    SchSwchParams params;
    params.set_security_level_ckks(sl);
    params.set_security_level_fhew(sl_bin);
    params.set_ctxt_mod_size_fhew_large_prec(log_q_cc_lwe);
    params.set_num_slots_ckks(slots);
    params.set_num_values(slots);
    auto private_key_fhew = cc->eval_scheme_switching_setup(params);
    auto cc_lwe = cc->get_bin_cc_for_scheme_switch();

    // Step 3. Precompute the necessary keys and information for switching from FHEW to CKKS and back
    cc->eval_scheme_switching_key_gen(keys, private_key_fhew);

    std::cout << "FHEW scheme is using lattice parameter " << cc_lwe->get_params()->get_lwe_params()->get_n();
    std::cout << ", logQ " << log_q_cc_lwe;
    std::cout << ", and modulus q " << cc_lwe->get_params()->get_lwe_params()->get_q() << std::endl << std::endl;

    auto p_lwe1 = cc_lwe->get_max_plaintext_space().convert_to_int();  // Small precision
    auto modulus_lwe = 1 << log_q_cc_lwe;
    auto beta = cc_lwe->get_beta().convert_to_int();
    auto p_lwe2 = modulus_lwe / (2 * beta);  // Large precision

    double scale1 = 1.0 / p_lwe1;
    double scale2 = 1.0 / p_lwe2;

    // Generate keys for the CKKS intermediate computation
    cc->eval_mult_key_gen(keys.secret_key);
    cc->eval_rotate_key_gen(keys.secret_key, {1, 2});

    // Step 4: Encoding and encryption of inputs
    // For correct CKKS decryption, the messages have to be much smaller than the FHEW plaintext modulus!
    // Inputs
    std::vector<int32_t> x1 = {1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0};
    std::vector<int32_t> x2 = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

    std::vector<int32_t> x1_rot(rotate_int(x1, 1));
    std::transform(x1_rot.begin(), x1_rot.end(), x1.begin(), x1_rot.begin(), std::plus<int>());
    std::vector<int32_t> x1_int(slots);
    std::transform(x1_rot.begin(), x1_rot.end(), x1_int.begin(), [&](int32_t elem) {
        return static_cast<int32_t>(static_cast<int32_t>(std::round(0.25 * elem * elem)) % p_lwe1);
    });

    std::vector<int32_t> x2_rot(rotate_int(x2, 2));
    std::transform(x2_rot.begin(), x2_rot.end(), x2.begin(), x2_rot.begin(), std::plus<int>());
    std::vector<int32_t> x2_int(slots);
    std::transform(x2_rot.begin(), x2_rot.end(), x2_int.begin(), [&](int32_t elem) {
        return static_cast<int32_t>(static_cast<int32_t>(std::round(0.25 * elem * elem)) % p_lwe2);
    });

    // Encrypt
    std::vector<LweCiphertext> ctxts_lwe1(slots);
    for (uint32_t i = 0; i < slots; i++) {
        // encrypted under small plantext modulus p = 4 and ciphertext modulus
        ctxts_lwe1[i] = cc_lwe->encrypt(private_key_fhew, x1[i]);
    }

    std::vector<LweCiphertext> ctxts_lwe2(slots);
    for (uint32_t i = 0; i < slots; i++) {
        // encrypted under large plaintext modulus and large ciphertext modulus
        ctxts_lwe2[i] = cc_lwe->encrypt(private_key_fhew, x2[i], LARGE_DIM, p_lwe2, modulus_lwe);
    }

    // Step 5. Perform the scheme switching
    auto c_temp = cc->eval_fhew_to_ckks(ctxts_lwe1, slots, slots);

    std::cout << "\nInput x1: " << x1 << " encrypted under p = " << 4 << " and Q = " << ctxts_lwe1[0]->get_modulus()
              << std::endl;
    std::cout << "round( 0.5 * (x1 + rot(x1,1) )^2 ): " << x1_int << std::endl;

    // Step 6. Perform the desired computation in CKKS
    auto c_poly = cc->eval_add(c_temp, cc->eval_rotate(c_temp, 1));
    c_poly = cc->eval_mult(cc->eval_mult(c_poly, c_poly), 0.25);

    // Perform the precomputation for switching back to CKKS
    cc->eval_ckks_to_fhew_precompute(scale1);

    // Transform the ciphertext from CKKS to FHEW
    auto c_temp1 = cc->eval_ckks_to_fhew(c_poly, slots);

    LwePlaintext result;
    std::cout << "FHEW decryption with plaintext modulus " << NativeInteger(p_lwe1) << ": ";
    for (uint32_t i = 0; i < c_temp1.size(); ++i) {
        cc_lwe->decrypt(private_key_fhew, c_temp1[i], &result, p_lwe1);
        std::cout << result << " ";
    }
    std::cout << "\n" << std::endl;

    // Step 5'. Perform the scheme switching
    c_temp = cc->eval_fhew_to_ckks(ctxts_lwe2, slots, slots, p_lwe2, 0, p_lwe2);

    std::cout << "\nInput x2: " << x2 << " encrypted under p = " << NativeInteger(p_lwe2)
              << " and Q = " << ctxts_lwe2[0]->get_modulus() << std::endl;
    std::cout << "round( 0.5 * (x1 + rot(x2,2) )^2 ): " << x2_int << std::endl;

    // Step 6'. Perform the desired computation in CKKS
    c_poly = cc->eval_add(c_temp, cc->eval_rotate(c_temp, 2));
    c_poly = cc->eval_mult(cc->eval_mult(c_poly, c_poly), 0.25);

    // Perform the precomputation for switching back to CKKS
    cc->eval_ckks_to_fhew_precompute(scale2);

    // Transform the ciphertext from CKKS to FHEW
    auto c_temp2 = cc->eval_ckks_to_fhew(c_poly, slots);

    std::cout << "FHEW decryption with plaintext modulus " << NativeInteger(p_lwe2) << ": ";
    for (uint32_t i = 0; i < c_temp2.size(); ++i) {
        cc_lwe->decrypt(private_key_fhew, c_temp2[i], &result, p_lwe2);
        std::cout << result << " ";
    }
    std::cout << "\n" << std::endl;
}

std::vector<int32_t> rotate_int(const std::vector<int32_t>& a, int32_t index) {
    int32_t slots = a.size();

    std::vector<int32_t> result(slots);

    if (index < 0 || index > slots) {
        index = reduce_rotation(index, slots);
    }

    if (index == 0) {
        result = a;
    }

    else {
        // two cases: i+index <= slots and i+index > slots
        for (int32_t i = 0; i < slots - index; i++) {
            result[i] = a[i + index];
        }
        for (int32_t i = slots - index; i < slots; i++) {
            result[i] = a[i + index - slots];
        }
    }

    return result;
}
