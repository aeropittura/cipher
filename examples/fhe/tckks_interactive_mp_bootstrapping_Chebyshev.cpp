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

Demo for Multi-Party Interactive Collective Bootstrapping in Threshold-CKKS (TCKKS).
3 parties want to evaluate a Chebyshev series on their secret input
This protocol is secure against (n-1) collusion among the participating parties, where n is
the number of participating parties.

*/

#define PROFILE

#include <complex>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "cipher/cipher.h"

using namespace std;
using namespace cipher;

static void check_approximate_equality(const std::vector<std::complex<double>>& a,
                                       const std::vector<std::complex<double>>& b, int vector_size, double epsilon) {
    std::vector<std::complex<double>> all_true(vector_size);
    std::vector<std::complex<double>> tmp(vector_size);
    for (int i = 0; i < vector_size; i++) {
        all_true[i] = 1;
        tmp[i] = std::abs(a[i] - b[i]) <= epsilon;
    }
    if (tmp != all_true) {
        cerr << __func__ << " - " << __FILE__ << ":" << __LINE__ << " IntMPBoot - Ctxt Chebyshev Failed: " << endl;
        cerr << __func__ << " - " << __FILE__ << ":" << __LINE__ << " - is diff <= eps?: " << tmp << endl;
    } else {
        std::cout << "SUCESSFUL Bootstrapping!\n";
    }
}

void tckks_collective_boot(enum ScalingTechnique scale_tech);

int main(int argc, char* argv[]) {
    std::cout << "Interactive (3P) Bootstrapping Ciphertext [Chebyshev] (TCKKS) started ...\n";

    // Same test with different rescaling techniques in CKKS
    tckks_collective_boot(ScalingTechnique::FIXEDMANUAL);
    tckks_collective_boot(ScalingTechnique::FIXEDAUTO);
    tckks_collective_boot(ScalingTechnique::FLEXIBLEAUTO);
    tckks_collective_boot(ScalingTechnique::FLEXIBLEAUTOEXT);

    std::cout << "Interactive (3P) Bootstrapping Ciphertext [Chebyshev] (TCKKS) terminated gracefully!\n";

    return 0;
}

// Demonstrate interactive multi-party bootstrapping for 3 parties
// We follow Protocol 5 in https://eprint.iacr.org/2020/304, "Multiparty
// Homomorphic Encryption from Ring-Learning-With-Errors"

void tckks_collective_boot(enum ScalingTechnique scale_tech) {
    if (scale_tech != ScalingTechnique::FIXEDMANUAL && scale_tech != ScalingTechnique::FIXEDAUTO &&
        scale_tech != ScalingTechnique::FLEXIBLEAUTO && scale_tech != ScalingTechnique::FLEXIBLEAUTOEXT) {
        std::string err_msg = "ERROR: Scaling technique is not supported!";
        CIPHER_THROW(err_msg);
    }

    ContextParams<CkksRnsContext> parameters;
    // A. Specify main parameters
    /*  A1) Secret key distribution
     * The secret key distribution for CKKS should either be SPARSE_TERNARY or UNIFORM_TERNARY.
     * The SPARSE_TERNARY distribution was used in the original CKKS paper,
     * but in this example, we use UNIFORM_TERNARY because this is included in the homomorphic
     * encryption standard.
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
    parameters.set_security_level(HEStd_128_classic);

    /*  A3) Scaling parameters.
     * By default, we set the modulus sizes and rescaling technique to the following values
     * to obtain a good precision and performance tradeoff. We recommend keeping the parameters
     * below unless you are an FHE expert.
     */
    uint32_t dcrt_bits = 50;
    uint32_t first_mod = 60;

    parameters.set_scaling_mod_size(dcrt_bits);
    parameters.set_scaling_technique(scale_tech);
    parameters.set_first_mod_size(first_mod);

    /*  A4) Multiplicative depth.
     * The multiplicative depth detemins the computational capability of the instantiated scheme. It should be set
     * according the following formula:
     * mult_depth_value >= desired_depth + interactive_bootstrapping_depth
     * where,
     *   The desired_depth is the depth of the computation, as chosen by the user.
     *   The interactive_bootstrapping_depth is either 3 or 4, depending on the ciphertext compression mode: COMPACT vs SLACK (see below)
     * Example 1, if you want to perform a computation of depth 24, you can set mult_depth_value to 10, use 6 levels
     * for computation and 4 for interactive bootstrapping. You will need to bootstrap 3 times.
     */
    parameters.set_multiplicative_depth(10);
    parameters.set_key_switch_technique(KeySwitchTechnique::HYBRID);

    uint32_t batch_size = 16;
    parameters.set_batch_size(batch_size);

    /*  Protocol-specific parameters (SLACK or COMPACT)
     * SLACK (default) uses larger masks, which makes it more secure theoretically. However, it is also slightly less efficient.
     * COMPACT uses smaller masks, which makes it more efficient. However, it is relatively less secure theoretically.
     * Both options can be used for practical security.
     * The following table summarizes the differences between SLACK and COMPACT:
     * Parameter	        SLACK	                                        COMPACT
     * Mask size	        Larger	                                        Smaller
     * Security	        More secure	                                    Less secure
     * Efficiency	    Less efficient	                                More efficient
     * Recommended use	For applications where security is paramount	For applications where efficiency is paramount
     */
    auto compression_level = CompressionLevel::COMPACT;
    parameters.set_interactive_boot_compression_level(compression_level);

    CryptoContext<RnsPoly> crypto_context = make_crypto_context(parameters);

    crypto_context->enable(PKE);
    crypto_context->enable(KEYSWITCH);
    crypto_context->enable(LEVELEDSHE);
    crypto_context->enable(ADVANCEDSHE);
    crypto_context->enable(MULTIPARTY);

    uint32_t ring_dim = crypto_context->get_ring_dimension();
    // This is the maximum number of slots that can be used for full packing.
    uint32_t max_num_slots = ring_dim / 2;
    std::cout << "TCKKS scheme is using ring dimension " << ring_dim << std::endl;
    std::cout << "TCKKS scheme number of slots         " << batch_size << std::endl;
    std::cout << "TCKKS scheme max number of slots     " << max_num_slots << std::endl;
    std::cout << "TCKKS example with Scaling Technique " << scale_tech << std::endl;

    const uint32_t num_parties = 3;

    std::cout << "\n===========================IntMPBoot protocol parameters===========================\n";
    std::cout << "num of parties: " << num_parties << "\n";
    std::cout << "===============================================================\n";

    double eps = 0.0001;

    // Initialize Public Key Containers
    KeyPair<RnsPoly> kp1;  // Party 1
    KeyPair<RnsPoly> kp2;  // Party 2
    KeyPair<RnsPoly> kp3;  // Lead party - who finalizes interactive bootstrapping

    KeyPair<RnsPoly> kp_multiparty;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    // Round 1 (party A)
    kp1 = crypto_context->key_gen();

    // Generate evalmult key part for A
    auto eval_mult_key = crypto_context->key_switch_gen(kp1.secret_key, kp1.secret_key);

    // Generate evalsum key part for A
    crypto_context->eval_sum_key_gen(kp1.secret_key);
    auto eval_sum_keys = std::make_shared<std::map<uint32_t, EvalKey<RnsPoly>>>(
            crypto_context->get_eval_sum_key_map(kp1.secret_key->get_key_tag()));

    // Round 2 (party B)
    kp2 = crypto_context->multiparty_key_gen(kp1.public_key);
    auto eval_mult_key2 = crypto_context->multi_key_switch_gen(kp2.secret_key, kp2.secret_key, eval_mult_key);
    auto eval_mult_ab =
            crypto_context->multi_add_eval_keys(eval_mult_key, eval_mult_key2, kp2.public_key->get_key_tag());
    auto eval_mult_bab =
            crypto_context->multi_mult_eval_key(kp2.secret_key, eval_mult_ab, kp2.public_key->get_key_tag());
    auto eval_sum_keys_b =
            crypto_context->multi_eval_sum_key_gen(kp2.secret_key, eval_sum_keys, kp2.public_key->get_key_tag());
    auto eval_sum_keys_join =
            crypto_context->multi_add_eval_sum_keys(eval_sum_keys, eval_sum_keys_b, kp2.public_key->get_key_tag());
    crypto_context->insert_eval_sum_key(eval_sum_keys_join);
    auto eval_mult_aab =
            crypto_context->multi_mult_eval_key(kp1.secret_key, eval_mult_ab, kp2.public_key->get_key_tag());
    auto eval_mult_final =
            crypto_context->multi_add_eval_mult_keys(eval_mult_aab, eval_mult_bab, eval_mult_ab->get_key_tag());
    crypto_context->insert_eval_mult_key({eval_mult_final});

    /////////////////////
    // Round 3 (party C) - Lead Party (who encrypts and finalizes the bootstrapping protocol)
    kp3 = crypto_context->multiparty_key_gen(kp2.public_key);
    auto eval_mult_key3 = crypto_context->multi_key_switch_gen(kp3.secret_key, kp3.secret_key, eval_mult_key);
    auto eval_mult_abc =
            crypto_context->multi_add_eval_keys(eval_mult_ab, eval_mult_key3, kp3.public_key->get_key_tag());
    auto eval_mult_babc =
            crypto_context->multi_mult_eval_key(kp2.secret_key, eval_mult_abc, kp3.public_key->get_key_tag());
    auto eval_mult_aabc =
            crypto_context->multi_mult_eval_key(kp1.secret_key, eval_mult_abc, kp3.public_key->get_key_tag());
    auto eval_mult_cabc =
            crypto_context->multi_mult_eval_key(kp3.secret_key, eval_mult_abc, kp3.public_key->get_key_tag());
    auto eval_mult_ababc =
            crypto_context->multi_add_eval_mult_keys(eval_mult_babc, eval_mult_aabc, eval_mult_babc->get_key_tag());
    auto eval_mult_final2 =
            crypto_context->multi_add_eval_mult_keys(eval_mult_ababc, eval_mult_cabc, eval_mult_cabc->get_key_tag());
    crypto_context->insert_eval_mult_key({eval_mult_final2});

    auto eval_sum_keys_c =
            crypto_context->multi_eval_sum_key_gen(kp3.secret_key, eval_sum_keys, kp3.public_key->get_key_tag());
    auto eval_sum_keys_join2 =
            crypto_context->multi_add_eval_sum_keys(eval_sum_keys_join, eval_sum_keys_c, kp3.public_key->get_key_tag());
    crypto_context->insert_eval_sum_key(eval_sum_keys_join2);

    if (!kp1.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }
    if (!kp2.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }
    if (!kp3.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }

    // END of Key Generation

    std::vector<std::complex<double>> input({-4.0, -3.0, -2.0, -1.0, 0.0, 1.0, 2.0, 3.0, 4.0});

    // Chebyshev coefficients
    std::vector<double> coefficients({1.0, 0.558971, 0.0, -0.0943712, 0.0, 0.0215023, 0.0, -0.00505348, 0.0, 0.00119324,
                                      0.0, -0.000281928, 0.0, 0.0000664347, 0.0, -0.0000148709});
    // Input range
    double a = -4;
    double b = 4;

    Plaintext pt1 = crypto_context->make_ckks_packed_plaintext(input);
    uint32_t encoded_length = input.size();

    auto ct1 = crypto_context->encrypt(kp3.public_key, pt1);

    ct1 = crypto_context->eval_chebyshev_series(ct1, coefficients, a, b);

    // INTERACTIVE BOOTSTRAPPING STARTS

    ct1 = crypto_context->int_mp_boot_adjust_scale(ct1);

    // Leading party (party B) generates a Common Random Poly (crp) at max coefficient modulus (QNumPrime).
    // a is sampled at random uniformly from R_{Q}
    auto crp = crypto_context->int_mp_boot_random_element_gen(kp3.public_key);
    // Each party generates its own shares: masked_decryption_share and re_encryption_share
    // (h_{0,i}, h_{1,i}) = (masked decryption share, re-encryption share)
    // we use a vector inseat of std::pair for Python API compatibility
    vector<Ciphertext<RnsPoly>> shares_pair0;  // for Party A
    vector<Ciphertext<RnsPoly>> shares_pair1;  // for Party B
    vector<Ciphertext<RnsPoly>> shares_pair2;  // for Party C

    // extract c1 - element-wise
    auto c1 = ct1->clone();
    c1->get_elements().erase(c1->get_elements().begin());
    // masked decryption on the client: c1 = a*s1
    shares_pair0 = crypto_context->int_mp_boot_decrypt(kp1.secret_key, c1, crp);
    shares_pair1 = crypto_context->int_mp_boot_decrypt(kp2.secret_key, c1, crp);
    shares_pair2 = crypto_context->int_mp_boot_decrypt(kp3.secret_key, c1, crp);

    vector<vector<Ciphertext<RnsPoly>>> shares_pair_vec;
    shares_pair_vec.push_back(shares_pair0);
    shares_pair_vec.push_back(shares_pair1);
    shares_pair_vec.push_back(shares_pair2);

    // Party B finalizes the protocol by aggregating the shares and reEncrypting the results
    auto aggregated_shares_pair = crypto_context->int_mp_boot_add(shares_pair_vec);
    auto ciphertext_output = crypto_context->int_mp_boot_encrypt(kp3.public_key, aggregated_shares_pair, crp, ct1);

    // INTERACTIVE BOOTSTRAPPING ENDS

    // distributed decryption

    auto ciphertext_partial1 = crypto_context->multiparty_decrypt_main({ciphertext_output}, kp1.secret_key);
    auto ciphertext_partial2 = crypto_context->multiparty_decrypt_main({ciphertext_output}, kp2.secret_key);
    auto ciphertext_partial3 = crypto_context->multiparty_decrypt_lead({ciphertext_output}, kp3.secret_key);
    vector<Ciphertext<RnsPoly>> partial_ciphertext_vec;
    partial_ciphertext_vec.push_back(ciphertext_partial1[0]);
    partial_ciphertext_vec.push_back(ciphertext_partial2[0]);
    partial_ciphertext_vec.push_back(ciphertext_partial3[0]);

    Plaintext plaintext_multiparty;
    crypto_context->multiparty_decrypt_fusion(partial_ciphertext_vec, &plaintext_multiparty);
    plaintext_multiparty->set_length(encoded_length);

    // Ground truth result
    std::vector<std::complex<double>> result(
            {0.0179885, 0.0474289, 0.119205, 0.268936, 0.5, 0.731064, 0.880795, 0.952571, 0.982011});
    Plaintext plaintext_result = crypto_context->make_ckks_packed_plaintext(result);

    std::cout << "Ground Truth: \n\t" << plaintext_result->get_ckks_packed_value() << std::endl;
    std::cout << "Computed Res: \n\t" << plaintext_multiparty->get_ckks_packed_value() << std::endl;

    check_approximate_equality(plaintext_result->get_ckks_packed_value(), plaintext_multiparty->get_ckks_packed_value(),
                               encoded_length, eps);

    std::cout << "\n============================ INTERACTIVE DECRYPTION ENDED ============================\n";

    std::cout << "\nTCKKSCollectiveBoot FHE example with rescaling technique: " << scale_tech << " Completed!"
              << std::endl;
}
