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
 Demo for Multi-Party Interactive Collective Bootstrapping with Threshold-CKKS (TCKKS) for
 a single ciphertext.
 It is a trivial example showing how to encrypt, bootstrap, and decrypt for 3 parties. No
 computation is done here.

 This protocol is secure against (n-1) collusion among the participating parties, where n is
 the number of participating parties.
 */

#define PROFILE

#include <complex>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "cipher/cipher.h"

using namespace cipher;

/*
 * A utility class defining a party that is involved in the collective bootstrapping protocol
 */
struct Party {
  public:
    uint32_t id;  // unique party identifier starting from 0

    std::vector<Ciphertext<RnsPoly>> shares_pair;  // (h_{0,i}, h_{1,i}) = (masked decryption
                                                   // share, re-encryption share)
                                                   // we use a vector inseat of std::pair for Python API compatibility

    KeyPair<RnsPoly> kp_shard;  // key-pair shard (pk, sk_i)
};

void tckks_collective_boot(enum ScalingTechnique rescale_tech);

int main(int argc, char* argv[]) {
    std::cout << "Interactive Multi-Party Bootstrapping Ciphertext (TCKKS) started ...\n";

    // Same test with different rescaling techniques in CKKS
    tckks_collective_boot(ScalingTechnique::FIXEDMANUAL);
    tckks_collective_boot(ScalingTechnique::FIXEDAUTO);
    tckks_collective_boot(ScalingTechnique::FLEXIBLEAUTO);
    tckks_collective_boot(ScalingTechnique::FLEXIBLEAUTOEXT);

    std::cout << "Interactive Multi-Party Bootstrapping Ciphertext (TCKKS) terminated gracefully!\n";

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
    uint32_t multiplicative_depth = 7;
    parameters.set_multiplicative_depth(multiplicative_depth);
    parameters.set_key_switch_technique(KeySwitchTechnique::HYBRID);

    uint32_t batch_size = 4;
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
    auto compression_level = CompressionLevel::SLACK;
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

    const uint32_t num_parties = 3;  // n: number of parties involved in the interactive protocol

    std::cout << "\n===========================IntMPBoot protocol parameters===========================\n";
    std::cout << "number of parties: " << num_parties << "\n";
    std::cout << "===============================================================\n";

    std::vector<Party> parties(num_parties);

    // Joint public key
    KeyPair<RnsPoly> kp_multiparty;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    std::cout << "Running key generation (used for source data)..." << std::endl;

    // Initialization - Assuming num_parties (n) of parties
    // P0 is the leading party
    for (uint32_t i = 0; i < num_parties; i++) {
        parties[i].id = i;
        std::cout << "Party " << parties[i].id << " started.\n";
        if (0 == i)
            parties[i].kp_shard = crypto_context->key_gen();
        else
            parties[i].kp_shard = crypto_context->multiparty_key_gen(parties[0].kp_shard.public_key);
        std::cout << "Party " << i << " key generation completed.\n";
    }
    std::cout << "Joint public key for (s_0 + s_1 + ... + s_n) is generated..." << std::endl;

    // Assert everything is good
    for (uint32_t i = 0; i < num_parties; i++) {
        if (!parties[i].kp_shard.good()) {
            std::cout << "Key generation failed for party " << i << "!" << std::endl;
            exit(1);
        }
    }

    // Generate the collective public key
    std::vector<PrivateKey<RnsPoly>> secret_keys;
    for (uint32_t i = 0; i < num_parties; i++) {
        secret_keys.push_back(parties[i].kp_shard.secret_key);
    }
    kp_multiparty = crypto_context->multiparty_key_gen(secret_keys);  // This is the same core key generation operation.

    // Prepare input vector
    std::vector<std::complex<double>> msg1({-0.9, -0.8, 0.2, 0.4});
    Plaintext ptxt1 = crypto_context->make_ckks_packed_plaintext(msg1);

    // Encryption
    Ciphertext<RnsPoly> in_ctxt = crypto_context->encrypt(kp_multiparty.public_key, ptxt1);
    RnsPoly ptxtpoly = ptxt1->get_element<RnsPoly>();

    std::cout << "Compressing ctxt to the smallest possible number of towers!\n";
    in_ctxt = crypto_context->int_mp_boot_adjust_scale(in_ctxt);

    // INTERACTIVE BOOTSTRAPPING STARTS

    std::cout << "\n============================ INTERACTIVE BOOTSTRAPPING STARTS ============================\n";

    // Leading party (P0) generates a Common Random Poly (a) at max coefficient modulus (QNumPrime).
    // a is sampled at random uniformly from R_{Q}
    Ciphertext<RnsPoly> a = crypto_context->int_mp_boot_random_element_gen(parties[0].kp_shard.public_key);
    std::cout << "Common Random Poly (a) has been generated with coefficient modulus Q\n";

    // Each party generates its own shares: masked_decryption_share and re_encryption_share
    std::vector<std::vector<Ciphertext<RnsPoly>>> shares_pair_vec;

    // Make a copy of input ciphertext and remove the first element (c0), we only
    // c1 for int_mp_boot_decrypt
    auto c1 = in_ctxt->clone();
    c1->get_elements().erase(c1->get_elements().begin());
    for (uint32_t i = 0; i < num_parties; i++) {
        std::cout << "Party " << i << " started its part in the Collective Bootstrapping Protocol\n";
        parties[i].shares_pair = crypto_context->int_mp_boot_decrypt(parties[i].kp_shard.secret_key, c1, a);
        shares_pair_vec.push_back(parties[i].shares_pair);
    }

    // P0 finalizes the protocol by aggregating the shares and reEncrypting the results
    auto aggregated_shares_pair = crypto_context->int_mp_boot_add(shares_pair_vec);
    // Make sure you provide the non-striped ciphertext (in_ctxt) in int_mp_boot_encrypt
    auto out_ctxt =
            crypto_context->int_mp_boot_encrypt(parties[0].kp_shard.public_key, aggregated_shares_pair, a, in_ctxt);

    // INTERACTIVE BOOTSTRAPPING ENDS
    std::cout << "\n============================ INTERACTIVE BOOTSTRAPPING ENDED ============================\n";

    // Distributed decryption

    std::cout << "\n============================ INTERACTIVE DECRYPTION STARTED ============================ \n";

    std::vector<Ciphertext<RnsPoly>> partial_ciphertext_vec;

    std::cout << "Party 0 started its part in the collective decryption protocol\n";
    partial_ciphertext_vec.push_back(
            crypto_context->multiparty_decrypt_lead({out_ctxt}, parties[0].kp_shard.secret_key)[0]);

    for (uint32_t i = 1; i < num_parties; i++) {
        std::cout << "Party " << i << " started its part in the collective decryption protocol\n";
        partial_ciphertext_vec.push_back(
                crypto_context->multiparty_decrypt_main({out_ctxt}, parties[i].kp_shard.secret_key)[0]);
    }

    // Checking the results
    std::cout << "MultipartyDecryptFusion ...\n";
    Plaintext plaintext_multiparty;
    crypto_context->multiparty_decrypt_fusion(partial_ciphertext_vec, &plaintext_multiparty);
    plaintext_multiparty->set_length(msg1.size());

    std::cout << "Original plaintext \n\t" << ptxt1->get_ckks_packed_value() << std::endl;
    std::cout << "Result after bootstrapping \n\t" << plaintext_multiparty->get_ckks_packed_value() << std::endl;

    std::cout << "\n============================ INTERACTIVE DECRYPTION ENDED ============================\n";
}
