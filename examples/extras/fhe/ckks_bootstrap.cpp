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

Example for CKKS bootstrapping

 */

#define PROFILE

#include <cmath>
#include <complex>
#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

#include "cipher/cipher.h"

using namespace std;
using namespace cipher;

void bootstrap_example(SecretKeyDist secret_key_dist, uint32_t n, uint32_t slots, uint32_t levels_remaining);
// same example with verbose console output removed
void bootstrap_example_clean(SecretKeyDist secret_key_dist, uint32_t n, uint32_t slots, uint32_t levels_remaining);

int main(int argc, char* argv[]) {
    // MODE - secret key distribution
    // SPARSE - sparse ternary secrets (with h = 64)
    // OPTIMIZED - uniform ternary secrets

    // low-security examples
    // bootstrap_example(SPARSE_TERNARY, 1<<12, 1<<11, 10);
    // bootstrap_example(SPARSE_TERNARY, 1<<12, 1<<10, 10);
    bootstrap_example(UNIFORM_TERNARY, 1 << 12, 1 << 11, 10);
    // bootstrap_example(UNIFORM_TERNARY, 1<<12, 1<<10, 10);

    // bootstrap_example(SPARSE_TERNARY, 1<<17, 1<<16, 10);
    // bootstrap_example(SPARSE_TERNARY, 1<<17, 1<<15, 10);
    // bootstrap_example(UNIFORM_TERNARY, 1<<17, 1<<16, 10);
    // bootstrap_example(UNIFORM_TERNARY, 1<<17, 1<<15, 10);

    return 0;
}

void bootstrap_example(SecretKeyDist secret_key_dist, uint32_t n, uint32_t slots, uint32_t levels_remaining) {
    TimeVar t;
    double time_key_gen(0.0);
    double time_precomp(0.0);
    double time_bootstrap(0.0);

    // giant step for baby-step-giant-step algorithm in linear transforms for encoding and decoding, respectively
    // Choose this a power of 2 preferably, otherwise an exact divisor of the number of elements in the sum
    std::vector<uint32_t> dim1 = {0, 0};

    // budget in levels for FFT for encoding and decoding, respectively
    // Choose a number smaller than ceil(log2(slots))

    std::vector<uint32_t> level_budget1 = {4, 4};
    std::vector<uint32_t> level_budget2 = {2, 4};
    std::vector<uint32_t> level_budget3 = {3, 2};
    std::vector<uint32_t> level_budget4 = {1, 1};
    std::vector<uint32_t> level_budget5 = {1, 2};
    std::vector<uint32_t> level_budget6 = {3, 1};

#if CIPHER_NATIVE_INT == 128
    ScalingTechnique rescale_tech = FIXEDMANUAL;
    uint32_t dcrt_bits = 78;
    uint32_t first_mod = 89; /*first_mod*/
#else
    ScalingTechnique rescale_tech = FLEXIBLEAUTO;
    uint32_t dcrt_bits = 59;
    uint32_t first_mod = 60; /*first_mod*/
#endif

    // computes how many levels are needed for
    uint32_t depth = levels_remaining + CkksRnsFhe::get_bootstrap_depth(9, level_budget1, secret_key_dist);

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(depth);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(rescale_tech);
    parameters.set_ring_dim(n);
    parameters.set_secret_key_dist(secret_key_dist);
    parameters.set_num_large_digits(3);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_key_switch_technique(HYBRID);
    parameters.set_first_mod_size(first_mod);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

#if 0
    CryptoContext<RnsPoly> cc =
        ContextFactory<RnsPoly>::genCryptoContextCKKS(
               depth,
               dcrt_bits,
               slots,
               HEStd_NotSet,
               n, /*ring_dimension_value*/
               rescale_tech,
               HYBRID,
               3, /*num_large_digits*/
               2, /*max_relin_sk_deg*/
    #if CIPHER_NATIVE_INT == 128
               89, /*first_mod*/
    #else
               60, /*first_mod*/
    #endif
               0,
               mode);
#endif

    // Turn on features
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(FHE);

    const shared_ptr<CkksRnsCryptoParams> crypto_params =
            std::dynamic_pointer_cast<CkksRnsCryptoParams>(cc->get_crypto_parameters());

    std::cerr << "SecretKeyDist: " << secret_key_dist << std::endl;

    std::cout << "p = " << crypto_params->get_plaintext_modulus() << std::endl;
    std::cout << "n = " << crypto_params->get_element_params()->get_cyclotomic_order() / 2 << std::endl;
    std::cout << "# slots = " << slots << std::endl;
    std::cout << "log2 q = " << crypto_params->get_element_params()->get_modulus().get_msb() << std::endl;
    std::cout << "log2 q*p = " << crypto_params->get_params_qp()->get_modulus().get_msb() << std::endl;

    std::cout << "dim1 = " << dim1 << std::endl;
    std::cout << "level budget = " << level_budget1 << std::endl;

    TIC(t);

    vector<uint32_t> slotsvec(6);
    for (size_t i = 0; i < 6; ++i) {
        slotsvec[i] = slots / (1 << i);
    }

    // precomputations for bootstrapping

    cc->eval_bootstrap_setup(level_budget1, dim1, slotsvec[0]);
    cc->eval_bootstrap_setup(level_budget2, dim1, slotsvec[1]);
    cc->eval_bootstrap_setup(level_budget3, dim1, slotsvec[2]);
    cc->eval_bootstrap_setup(level_budget4, dim1, slotsvec[3]);
    cc->eval_bootstrap_setup(level_budget5, dim1, slotsvec[4]);
    cc->eval_bootstrap_setup(level_budget6, dim1, slotsvec[5]);

    // std::cout << "gEnc = " << cc->GetGiantStepEnc() << std::endl;
    // std::cout << "# rot Enc = " << cc->GetNumRotationsEnc() << std::endl;
    // std::cout << "gEncRem = " << cc->GetGiantStepRemEnc() << std::endl;
    // std::cout << "W rot EncRem = " << cc->GetNumRotationsRemEnc() << std::endl;
    // std::cout << "gDec = " << cc->GetGiantStepDec() << std::endl;
    // std::cout << "# rot Dec = " << cc->GetNumRotationsDec() << std::endl;
    // std::cout << "gDecRem = " << cc->GetGiantStepRemDec() << std::endl;
    // std::cout << "W rot DecRem = " << cc->GetNumRotationsRemDec() << std::endl;

    time_precomp = TOC(t);

    std::cout << "\nLinear transform precomputation time: " << time_precomp / 1000.0 << " s" << std::endl;

    auto key_pair = cc->key_gen();
    cc->eval_mult_key_gen(key_pair.secret_key);

    // generation of all keys needed for bootstrapping

    for (size_t i = 0; i < 6; ++i) {
        TIC(t);
        cc->eval_bootstrap_key_gen(key_pair.secret_key, slotsvec[i]);
        time_key_gen = TOC(t);
        std::cout << "\nAutomorphism key generation time: " << time_key_gen / 1000.0 << " s" << std::endl;
        std::vector<std::complex<double>> a(
                {0.111111, 0.222222, 0.333333, 0.444444, 0.555555, 0.666666, 0.777777, 0.888888});

        size_t encoded_length = a.size();

        auto input(Fill(a, slotsvec[i]));
        Plaintext plaintext = cc->make_ckks_packed_plaintext(input, 1, depth - 1, nullptr, slotsvec[i]);
        auto ciphertext = cc->encrypt(key_pair.public_key, plaintext);

        std::cerr << "ciphertext number of slots: " << ciphertext->get_slots() << std::endl;

        std::cerr << "\nNumber of levels before bootstrapping: " << ciphertext->get_elements()[0].get_num_of_elements() - 1
                  << std::endl;

        TIC(t);
        auto ciphertext_after = cc->eval_bootstrap(ciphertext);
        time_bootstrap = TOC(t);
        std::cout << "\nBootstrapping time: " << time_bootstrap / 1000.0 << " s" << std::endl;
        std::cerr << "\nNumber of levels consumed: "
                  << depth - ciphertext_after->get_elements()[0].get_num_of_elements() + ciphertext_after->get_noise_scale_deg()
                  << std::endl;
        std::cerr << "\nNumber of levels remaining: "
                  << ciphertext_after->get_elements()[0].get_num_of_elements() - ciphertext_after->get_noise_scale_deg()
                  << std::endl;

        Plaintext result;
        std::cerr << "ciphertextAfter level        : " << ciphertext_after->get_level() << std::endl;
        std::cerr << "ciphertextAfter noiseScaleDeg: " << ciphertext_after->get_noise_scale_deg() << std::endl;
        std::cerr << "ciphertextAfter    sf        : " << ciphertext_after->get_scaling_factor() << std::endl;
        cc->decrypt(key_pair.secret_key, ciphertext_after, &result);
        std::cerr << "encodedLength: " << encoded_length << std::endl;

        result->set_length(encoded_length);
        plaintext->set_length(encoded_length);

        std::cout << "\nEncrypted text before bootstrapping \n\t" << plaintext << std::endl;

        std::cout << "\nEncrypted text after bootstrapping \n\t" << result << std::endl;

        double error = 0;
        for (size_t i = 0; i < encoded_length; i++) {
            error = error +
                    std::fabs((result->get_ckks_packed_value()[i].real() - plaintext->get_ckks_packed_value()[i].real()) /
                              plaintext->get_ckks_packed_value()[i].real());
        }

        std::cout << "\nAverage error: " << error / static_cast<double>(encoded_length) << std::endl;
        std::cout << "\nAverage error - in bits: " << std::log2(error / static_cast<double>(encoded_length))
                  << std::endl;
    }
}

void bootstrap_example_clean(SecretKeyDist secret_key_dist, uint32_t n, uint32_t slots, uint32_t levels_remaining) {
    // giant step for baby-step-giant-step algorithm in linear transforms for encoding and decoding, respectively
    // Choose this a power of 2 preferably, otherwise an exact divisor of the number of elements in the sum
    std::vector<uint32_t> dim1 = {0, 0};

    // budget in levels for FFT for encoding and decoding, respectively
    // Choose a number smaller than ceil(log2(slots))
    std::vector<uint32_t> level_budget = {4, 4};

#if CIPHER_NATIVE_INT == 128
    ScalingTechnique rescale_tech = FIXEDMANUAL;
    uint32_t dcrt_bits = 78;
    uint32_t first_mod = 89; /*first_mod*/
#else
    ScalingTechnique rescale_tech = FLEXIBLEAUTO;
    uint32_t dcrt_bits = 59;
    uint32_t first_mod = 60; /*first_mod*/
#endif

    // computes how many levels are needed for
    uint32_t depth = levels_remaining + CkksRnsFhe::get_bootstrap_depth(9, level_budget, secret_key_dist);

    ContextParams<CkksRnsContext> parameters;
    parameters.set_multiplicative_depth(depth);
    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(rescale_tech);
    parameters.set_ring_dim(n);
    parameters.set_secret_key_dist(secret_key_dist);
    parameters.set_num_large_digits(3);
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_key_switch_technique(HYBRID);
    parameters.set_first_mod_size(first_mod);

    CryptoContext<RnsPoly> cc = make_crypto_context(parameters);

#if 0
    CryptoContext<RnsPoly> cc =
        ContextFactory<RnsPoly>::genCryptoContextCKKS(
               depth,
               dcrt_bits,
               slots,
               HEStd_NotSet,
               n, /*ring_dimension_value*/
               rescale_tech,
               HYBRID,
               3, /*num_large_digits*/
               2, /*max_relin_sk_deg*/
    #if CIPHER_NATIVE_INT == 128
               89, /*first_mod*/
    #else
               60, /*first_mod*/
    #endif
               0,
               mode);
#endif

    // Turn on features
    cc->enable(PKE);
    cc->enable(KEYSWITCH);
    cc->enable(LEVELEDSHE);
    cc->enable(ADVANCEDSHE);
    cc->enable(FHE);

    // precomputations for bootstrapping
    cc->eval_bootstrap_setup(level_budget, dim1, slots);

    // keypair is generated
    auto key_pair = cc->key_gen();

    // generation of evaluation keys
    cc->eval_bootstrap_key_gen(key_pair.secret_key, slots);

    cc->eval_mult_key_gen(key_pair.secret_key);

    std::vector<std::complex<double>> a(
            {0.111111, 0.222222, 0.333333, 0.444444, 0.555555, 0.666666, 0.777777, 0.888888});

    size_t encoded_length = a.size();

    auto input(Fill(a, slots));

    Plaintext plaintext1 = cc->make_ckks_packed_plaintext(input, 1, depth - 1, nullptr, slots);

    auto ciphertext1 = cc->encrypt(key_pair.public_key, plaintext1);

    // bootstrapping operation
    auto ciphertext_after = cc->eval_bootstrap(ciphertext1);

    Plaintext result;

    cc->decrypt(key_pair.secret_key, ciphertext_after, &result);

    result->set_length(encoded_length);
    plaintext1->set_length(encoded_length);

    std::cout << "\nEncrypted text before bootstrapping \n\t" << plaintext1 << std::endl;

    std::cout << "\nEncrypted text after bootstrapping \n\t" << result << std::endl;
}
