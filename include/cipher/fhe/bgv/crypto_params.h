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

#ifndef CIPHER_FHE_BGV_CRYPTO_PARAMS_H_
#define CIPHER_FHE_BGV_CRYPTO_PARAMS_H_

#include <cstdint>
#include <memory>
#include <string>

#include "cipher/fhe/globals.h"
#include "cipher/fhe/rns/crypto_params.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief Crypto parameters for the BGV scheme in the RNS (double-CRT) representation. Adds to
 * RnsCryptoParams the precomputation of the BGV modulus switching tables and of the FLEXIBLEAUTO /
 * FLEXIBLEAUTOEXT scaling factors modulo the plaintext modulus.
 */
class BgvRnsCryptoParams : public RnsCryptoParams {
    using ParmType = typename RnsPoly::Params;
#define DISABLED_FOR_BGVRNS_PARAMS CIPHER_THROW("This parameter is not available for BGVRNS.");

  public:
    BgvRnsCryptoParams() : RnsCryptoParams() {}

    BgvRnsCryptoParams(const BgvRnsCryptoParams& rhs) : RnsCryptoParams(rhs) {}

    /**
     * Constructor that initializes the BGV crypto parameters from a plaintext modulus.
     *
     * @param params element parameters (the DCRT modulus chain).
     * @param plaintext_modulus plaintext modulus t.
     * @param distribution_parameter standard deviation of the error distribution.
     * @param assurance_measure assurance measure (the number of standard deviations used for noise bounds).
     * @param security_level security level from the homomorphic encryption standard.
     * @param digit_size the size of the digit (relinearization window) for BV key switching.
     * @param secret_key_dist secret key distribution: GAUSSIAN, UNIFORM_TERNARY or SPARSE_TERNARY.
     * @param max_relin_sk_deg the maximum power of the secret key for which a relinearization key is generated.
     * @param ks_tech key switching technique (BV or HYBRID).
     * @param scal_tech scaling (modulus switching) technique.
     * @param enc_tech encryption technique (BFV-only; kept for a uniform interface).
     * @param mult_tech multiplication technique (BFV-only; kept for a uniform interface).
     * @param multiparty_mode security mode for multiparty (threshold) decryption.
     */
    BgvRnsCryptoParams(std::shared_ptr<ParmType> params, const PlaintextModulus& plaintext_modulus,
                           float distribution_parameter, float assurance_measure, SecurityLevel security_level,
                           uint32_t digit_size, SecretKeyDist secret_key_dist, int max_relin_sk_deg = 2,
                           KeySwitchTechnique ks_tech = BV, ScalingTechnique scal_tech = FIXEDMANUAL,
                           EncryptionTechnique enc_tech = STANDARD, MultiplicationTechnique mult_tech = HPS,
                           MultipartyMode multiparty_mode = FIXED_NOISE_MULTIPARTY)
        : RnsCryptoParams(params, plaintext_modulus, distribution_parameter, assurance_measure, security_level,
                              digit_size, secret_key_dist, max_relin_sk_deg, ks_tech, scal_tech, enc_tech, mult_tech,
                              multiparty_mode) {}

    /**
     * Constructor that initializes the BGV crypto parameters from explicit encoding parameters.
     *
     * @param params element parameters (the DCRT modulus chain).
     * @param encoding_params encoding parameters (plaintext modulus, batch size).
     * @param distribution_parameter standard deviation of the error distribution.
     * @param assurance_measure assurance measure (the number of standard deviations used for noise bounds).
     * @param security_level security level from the homomorphic encryption standard.
     * @param digit_size the size of the digit (relinearization window) for BV key switching.
     * @param secret_key_dist secret key distribution: GAUSSIAN, UNIFORM_TERNARY or SPARSE_TERNARY.
     * @param max_relin_sk_deg the maximum power of the secret key for which a relinearization key is generated.
     * @param ks_tech key switching technique (BV or HYBRID).
     * @param scal_tech scaling (modulus switching) technique.
     * @param enc_tech encryption technique (BFV-only; kept for a uniform interface).
     * @param mult_tech multiplication technique (BFV-only; kept for a uniform interface).
     * @param pre_mode security mode for proxy re-encryption.
     * @param multiparty_mode security mode for multiparty (threshold) decryption.
     * @param execution_mode execution mode (CKKS-only; kept for a uniform interface).
     * @param decryption_noise_mode decryption noise mode (CKKS-only; kept for a uniform interface).
     * @param noise_scale_value multiplier applied to the fresh encryption noise (the plaintext modulus t for BGV).
     * @param statistical_security statistical security parameter in bits (CKKS-only).
     * @param num_adversarial_queries number of adversarial decryption queries assumed (CKKS-only).
     * @param threshold_num_of_parties number of parties in a threshold-FHE application (bounds the joint secret key).
     */
    BgvRnsCryptoParams(std::shared_ptr<ParmType> params, EncodingParams encoding_params, float distribution_parameter,
                           float assurance_measure, SecurityLevel security_level, uint32_t digit_size,
                           SecretKeyDist secret_key_dist, int max_relin_sk_deg = 2, KeySwitchTechnique ks_tech = BV,
                           ScalingTechnique scal_tech = FIXEDMANUAL, EncryptionTechnique enc_tech = STANDARD,
                           MultiplicationTechnique mult_tech = HPS, ProxyReEncryptionMode pre_mode = NOT_SET,
                           MultipartyMode multiparty_mode = FIXED_NOISE_MULTIPARTY,
                           ExecutionMode execution_mode = EXEC_EVALUATION,
                           DecryptionNoiseMode decryption_noise_mode = FIXED_NOISE_DECRYPT,
                           PlaintextModulus noise_scale_value = 1, uint32_t statistical_security = 30,
                           uint32_t num_adversarial_queries = 1, uint32_t threshold_num_of_parties = 1)
        : RnsCryptoParams(params, encoding_params, distribution_parameter, assurance_measure, security_level, digit_size,
                              secret_key_dist, max_relin_sk_deg, ks_tech, scal_tech, enc_tech, mult_tech, pre_mode,
                              multiparty_mode, execution_mode, decryption_noise_mode, noise_scale_value, statistical_security,
                              num_adversarial_queries, threshold_num_of_parties) {}

    virtual ~BgvRnsCryptoParams() {}

    /**
     * Computes the RNS tables shared by all schemes (via RnsCryptoParams::precompute_crt_tables) and the
     * BGV-specific tables: [t]_{q_i}, [-t^{-1}]_{q_i} and [q_l^{-1}]_{q_i} for modulus switching, t^{-1} modulo
     * the q_i and p_j for HYBRID key switching, the Barrett constants for the q_i, and, for FLEXIBLEAUTO and
     * FLEXIBLEAUTOEXT, the per-level scaling factors and [q_i]_t.
     *
     * @param ks_tech the technique to use for key switching (BV or HYBRID).
     * @param scal_tech the technique to use for scaling (e.g., FLEXIBLEAUTOEXT or FIXEDMANUAL).
     * @param enc_tech the technique to use for encryption (unused by BGV).
     * @param mult_tech the technique to use for homomorphic multiplication (unused by BGV).
     * @param num_part_q the number of digits (partitions of Q) for HYBRID key switching.
     * @param aux_bits the number of bits in the auxiliary (special) prime moduli.
     * @param extra_bits the number of extra bits reserved for the auxiliary modulus in HYBRID key switching.
     */
    void precompute_crt_tables(KeySwitchTechnique ks_tech, ScalingTechnique scal_tech, EncryptionTechnique enc_tech,
                             MultiplicationTechnique mult_tech, uint32_t num_part_q, uint32_t aux_bits,
                             uint32_t extra_bits) override;

    /**
     * Returns the step for the auxiliary prime search of HYBRID key switching; for BGV the auxiliary primes
     * must be 1 modulo both the cyclotomic order 2n and the plaintext modulus t, so the step is their least
     * common multiple.
     *
     * @return lcm(2n, t).
     */
    uint64_t find_aux_prime_step() const override;

    /**
     * CKKS noise estimate for noise flooding; not available for BGV (always throws).
     *
     * @return never returns.
     */
    double get_noise_estimate() const override {
        DISABLED_FOR_BGVRNS_PARAMS;
    }

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::base_class<RnsCryptoParams>(this));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            std::string err_msg("serialized object version " + std::to_string(version) +
                               " is from a later version of the library");
            CIPHER_THROW(err_msg);
        }
        ar(cereal::base_class<RnsCryptoParams>(this));

        if (precompute_crt_tables_after_deserializaton()) {
            precompute_crt_tables(ks_technique_, scal_technique_, enc_technique_, mult_technique_, num_part_q_, aux_bits_,
                                extra_bits_);
        }
    }

    std::string serialized_object_name() const override {
        return "CryptoParametersBGVRNS";
    }
    static uint32_t serialized_version() {
        return 1;
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_BGV_CRYPTO_PARAMS_H_
