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

Example for CKKS bootstrapping with sparse packing

*/

#define PROFILE

#include <cstdint>
#include <iostream>
#include <random>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

void bootstrap_example(uint32_t num_slots);

int main(int argc, char* argv[]) {
    // We run the example with 8 slots and ring dimension 4096 to illustrate how to run bootstrapping with a sparse plaintext.
    // Using a sparse plaintext and specifying the smaller number of slots gives a performance improvement (typically up to 3x).
    bootstrap_example(8);
}

void bootstrap_example(uint32_t num_slots) {
    // Step 1: Set CryptoContext
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
    parameters.set_security_level(HEStd_NotSet);
    parameters.set_ring_dim(1 << 12);

    /*  A3) Key switching parameters.
     * By default, we use HYBRID key switching with a digit size of 3.
     * Choosing a larger digit size can reduce complexity, but the size of keys will increase.
     * Note that you can leave these lines of code out completely, since these are the default values.
     */
    parameters.set_num_large_digits(3);
    parameters.set_key_switch_technique(HYBRID);

    /*  A4) Scaling parameters.
     * By default, we set the modulus sizes and rescaling technique to the following values
     * to obtain a good precision and performance tradeoff. We recommend keeping the parameters
     * below unless you are an FHE expert.
     */
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

    /*  A4) Bootstrapping parameters.
     * We set a budget for the number of levels we can consume in bootstrapping for encoding and decoding, respectively.
     * Using larger numbers of levels reduces the complexity and number of rotation keys,
     * but increases the depth required for bootstrapping.
     * We must choose values smaller than ceil(log2(slots)). A level budget of {4, 4} is good for higher ring
     * dimensions (65536 and higher).
     */
    std::vector<uint32_t> level_budget = {3, 3};

    /* We give the user the option of configuring values for an optimization algorithm in bootstrapping.
     * Here, we specify the giant step for the baby-step-giant-step algorithm in linear transforms
     * for encoding and decoding, respectively. Either choose this to be a power of 2
     * or an exact divisor of the number of slots. Setting it to have the default value of {0, 0} allows Cipher to choose
     * the values automatically.
     */
    std::vector<uint32_t> bsgs_dim = {0, 0};

    /*  A5) Multiplicative depth.
     * The goal of bootstrapping is to increase the number of available levels we have, or in other words,
     * to dynamically increase the multiplicative depth. However, the bootstrapping procedure itself
     * needs to consume a few levels to run. We compute the number of bootstrapping levels required
     * using get_bootstrap_depth, and add it to levels_available_after_bootstrap to set our initial multiplicative
     * depth.
     */
    uint32_t levels_available_after_bootstrap = 10;
    uint32_t depth = levels_available_after_bootstrap + CkksRnsFhe::get_bootstrap_depth(level_budget, secret_key_dist);
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
    std::cout << "CKKS scheme is using ring dimension " << ring_dim << std::endl << std::endl;

    // Step 2: Precomputations for bootstrapping
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
    std::uniform_real_distribution<> dis(0.0, 1.0);
    for (size_t i = 0; i < num_slots; i++) {
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
    std::cout << "Input: " << ptxt << std::endl;

    // Encrypt the encoded vectors
    Ciphertext<RnsPoly> ciph = crypto_context->encrypt(key_pair.public_key, ptxt);

    std::cout << "Initial number of levels remaining: " << depth - ciph->get_level() << std::endl;

    // Step 5: Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    // for HE computation.
    auto ciphertext_after = crypto_context->eval_bootstrap(ciph);

    std::cout << "Number of levels remaining after bootstrapping: " << depth - ciphertext_after->get_level()
              << std::endl
              << std::endl;

    // Step 7: Decryption and output
    Plaintext result;
    crypto_context->decrypt(key_pair.secret_key, ciphertext_after, &result);
    result->set_length(num_slots);
    std::cout << "Output after bootstrapping \n\t" << result << std::endl;
}
