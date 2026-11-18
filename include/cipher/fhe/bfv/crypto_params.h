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

#ifndef CIPHER_FHE_BFV_CRYPTO_PARAMS_H_
#define CIPHER_FHE_BFV_CRYPTO_PARAMS_H_

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
 * @brief Crypto parameters for the BFV scheme in the RNS (double-CRT) representation. Adds to
 * RnsCryptoParams the precomputation of all BFV-specific tables (encryption, decryption and the
 * HPS/BEHZ/HPSPOVERQ/HPSPOVERQLEVELED homomorphic multiplication variants).
 */
class BfvRnsCryptoParams : public RnsCryptoParams {
    using ParmType = typename RnsPoly::Params;
#define DISABLED_FOR_BFVRNS_PARAMS CIPHER_THROW("This parameter is not available for BFVRNS.");

  public:
    BfvRnsCryptoParams() : RnsCryptoParams() {}

    BfvRnsCryptoParams(const BfvRnsCryptoParams& rhs) : RnsCryptoParams(rhs) {}

    /**
     * Constructor that initializes the BFV crypto parameters from a plaintext modulus.
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
     * @param scal_tech scaling technique (BFV always uses FIXEDMANUAL).
     * @param enc_tech encryption technique (STANDARD or EXTENDED).
     * @param mult_tech homomorphic multiplication technique (HPS, BEHZ, HPSPOVERQ or HPSPOVERQLEVELED).
     * @param multiparty_mode security mode for multiparty (threshold) decryption.
     */
    BfvRnsCryptoParams(std::shared_ptr<ParmType> params, const PlaintextModulus& plaintext_modulus,
                           float distribution_parameter, float assurance_measure, SecurityLevel security_level,
                           uint32_t digit_size, SecretKeyDist secret_key_dist, int max_relin_sk_deg = 2,
                           KeySwitchTechnique ks_tech = BV, ScalingTechnique scal_tech = FIXEDMANUAL,
                           EncryptionTechnique enc_tech = STANDARD, MultiplicationTechnique mult_tech = HPS,
                           MultipartyMode multiparty_mode = FIXED_NOISE_MULTIPARTY)
        : RnsCryptoParams(params, plaintext_modulus, distribution_parameter, assurance_measure, security_level,
                              digit_size, secret_key_dist, max_relin_sk_deg, ks_tech, scal_tech, enc_tech, mult_tech,
                              multiparty_mode) {}

    /**
     * Constructor that initializes the BFV crypto parameters from explicit encoding parameters.
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
     * @param scal_tech scaling technique (BFV always uses FIXEDMANUAL).
     * @param enc_tech encryption technique (STANDARD or EXTENDED).
     * @param mult_tech homomorphic multiplication technique (HPS, BEHZ, HPSPOVERQ or HPSPOVERQLEVELED).
     * @param pre_mode security mode for proxy re-encryption (only INDCPA and NOT_SET are supported by BFV).
     * @param multiparty_mode security mode for multiparty (threshold) decryption.
     * @param execution_mode execution mode (CKKS-only; kept for a uniform interface).
     * @param decryption_noise_mode decryption noise mode (CKKS-only; kept for a uniform interface).
     * @param noise_scale_value multiplier applied to the fresh encryption noise (always 1 for BFV).
     * @param statistical_security statistical security parameter in bits (CKKS-only).
     * @param num_adversarial_queries number of adversarial decryption queries assumed (CKKS-only).
     * @param threshold_num_of_parties number of parties in a threshold-FHE application (bounds the joint secret key).
     */
    BfvRnsCryptoParams(std::shared_ptr<ParmType> params, EncodingParams encoding_params, float distribution_parameter,
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

    virtual ~BfvRnsCryptoParams() {}

    /**
     * Computes the RNS tables shared by all schemes (via RnsCryptoParams::precompute_crt_tables) and the
     * BFV-specific tables: [-Q_l]_t and t^{-1} mod q_i for encryption, the basis Qr for EXTENDED encryption,
     * the auxiliary bases R_l / Q_l*R_l and the basis-extension and scale-and-round tables for the HPS family
     * of multiplication techniques (leveled versions for every Q_l when HPSPOVERQ or HPSPOVERQLEVELED is
     * used), the Bsk = B U {msk} tables for BEHZ, and the decryption scale-and-round tables.
     *
     * @param ks_tech the technique to use for key switching (BV or HYBRID).
     * @param scal_tech the technique to use for scaling (FIXEDMANUAL for BFV).
     * @param enc_tech the technique to use for encryption (STANDARD or EXTENDED).
     * @param mult_tech the technique to use for homomorphic multiplication (HPS, BEHZ, HPSPOVERQ or
     * HPSPOVERQLEVELED).
     * @param num_part_q the number of digits (partitions of Q) for HYBRID key switching.
     * @param aux_bits the number of bits in the auxiliary (special) prime moduli.
     * @param extra_bits the number of extra bits reserved for the auxiliary modulus in HYBRID key switching.
     */
    void precompute_crt_tables(KeySwitchTechnique ks_tech, ScalingTechnique scal_tech, EncryptionTechnique enc_tech,
                             MultiplicationTechnique mult_tech, uint32_t num_part_q, uint32_t aux_bits,
                             uint32_t extra_bits) override;

    /**
     * Returns the step for the auxiliary prime search of HYBRID key switching; for BFV the auxiliary primes
     * are chosen to be 1 modulo the cyclotomic order 2n.
     *
     * @return the cyclotomic order 2n.
     */
    uint64_t find_aux_prime_step() const override;

    /**
     * Number of hops for HRA-secure proxy re-encryption; not available for BFV (always throws).
     *
     * @return never returns.
     */
    uint32_t get_pre_num_hops() const override {
        DISABLED_FOR_BFVRNS_PARAMS;
    }

    /**
     * CKKS noise estimate for noise flooding; not available for BFV (always throws).
     *
     * @return never returns.
     */
    double get_noise_estimate() const override {
        DISABLED_FOR_BFVRNS_PARAMS;
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
        return "CryptoParametersBFVRNS";
    }
    static uint32_t serialized_version() {
        return 1;
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_BFV_CRYPTO_PARAMS_H_
