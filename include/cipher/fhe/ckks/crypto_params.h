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

#ifndef CIPHER_FHE_CKKS_CRYPTO_PARAMS_H_
#define CIPHER_FHE_CKKS_CRYPTO_PARAMS_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "cipher/fhe/globals.h"
#include "cipher/fhe/rns/crypto_params.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief Crypto parameters of the CKKS scheme in RNS form.
 *
 * Extends RnsCryptoParams with the CKKS-specific parts of the CRT table precomputation: the composite degree
 * of the COMPOSITESCALING* techniques, the tables of the exact CRT basis extension used by the bootstrapping
 * modulus raise with composite scaling, and the auxiliary modulus and tables of sparse secret encapsulation
 * (SPARSE_ENCAPSULATED). The BGV/BFV-only parameters (plaintext modulus counts, PRE hops) are disabled.
 */
class CkksRnsCryptoParams : public RnsCryptoParams {
    using ParmType = typename RnsPoly::Params;
#define DISABLED_FOR_CKKSRNS_PARAMS CIPHER_THROW("This parameter is not available for CKKSRNS.");

  public:
    CkksRnsCryptoParams() = default;
    CkksRnsCryptoParams(const CkksRnsCryptoParams& rhs) = default;
    CkksRnsCryptoParams(CkksRnsCryptoParams&& rhs) noexcept = default;

    /**
     * Constructor that initializes the CKKS parameters from a plaintext modulus (the scaling modulus size in bits);
     * forwards all arguments to RnsCryptoParams.
     *
     * @param params element parameters (the DCRT modulus chain).
     * @param plaintext_modulus plaintext modulus (for CKKS, the scaling modulus size in bits).
     * @param distribution_parameter standard deviation of the error distribution.
     * @param assurance_measure assurance measure (the number of standard deviations used for noise bounds).
     * @param security_level security level from the homomorphic encryption standard.
     * @param digit_size the size of the digit (relinearization window) for BV key switching.
     * @param secret_key_dist secret key distribution.
     * @param max_relin_sk_deg the maximum power of the secret key for which a relinearization key is generated.
     * @param ks_tech key switching technique (BV or HYBRID).
     * @param scal_tech scaling (rescaling) technique.
     * @param enc_tech encryption technique (STANDARD; EXTENDED is BFV-specific).
     * @param mult_tech multiplication technique (BFV-specific; unused by CKKS).
     * @param multiparty_mode security mode for multiparty (threshold) decryption.
     * @param execution_mode execution mode for CKKS noise flooding (EXEC_EVALUATION or EXEC_NOISE_ESTIMATION).
     * @param decryption_noise_mode decryption noise mode for CKKS noise flooding.
     * @param m_p_int_boot_ciphertext_compression_level compression level of the ciphertexts used in multi-party
     * interactive bootstrapping (SLACK or COMPACT).
     */
    CkksRnsCryptoParams(std::shared_ptr<ParmType> params, const PlaintextModulus& plaintext_modulus,
                        float distribution_parameter, float assurance_measure, SecurityLevel security_level,
                        uint32_t digit_size, SecretKeyDist secret_key_dist, int max_relin_sk_deg = 2,
                        KeySwitchTechnique ks_tech = BV, ScalingTechnique scal_tech = FIXEDMANUAL,
                        EncryptionTechnique enc_tech = STANDARD, MultiplicationTechnique mult_tech = HPS,
                        MultipartyMode multiparty_mode = FIXED_NOISE_MULTIPARTY,
                        ExecutionMode execution_mode = EXEC_EVALUATION,
                        DecryptionNoiseMode decryption_noise_mode = FIXED_NOISE_DECRYPT,
                        CompressionLevel m_p_int_boot_ciphertext_compression_level = CompressionLevel::SLACK)
        : RnsCryptoParams(params, plaintext_modulus, distribution_parameter, assurance_measure, security_level,
                          digit_size, secret_key_dist, max_relin_sk_deg, ks_tech, scal_tech, enc_tech, mult_tech,
                          multiparty_mode, execution_mode, decryption_noise_mode,
                          m_p_int_boot_ciphertext_compression_level) {}

    /**
     * Constructor that initializes the CKKS parameters from explicit encoding parameters, including the
     * threshold-FHE, noise-flooding and composite scaling settings; forwards all arguments to RnsCryptoParams.
     *
     * @param params element parameters (the DCRT modulus chain).
     * @param encoding_params encoding parameters (scaling modulus size as the plaintext modulus, batch size).
     * @param distribution_parameter standard deviation of the error distribution.
     * @param assurance_measure assurance measure (the number of standard deviations used for noise bounds).
     * @param security_level security level from the homomorphic encryption standard.
     * @param digit_size the size of the digit (relinearization window) for BV key switching.
     * @param secret_key_dist secret key distribution.
     * @param max_relin_sk_deg the maximum power of the secret key for which a relinearization key is generated.
     * @param ks_tech key switching technique (BV or HYBRID).
     * @param scal_tech scaling (rescaling) technique.
     * @param enc_tech encryption technique (STANDARD; EXTENDED is BFV-specific).
     * @param mult_tech multiplication technique (BFV-specific; unused by CKKS).
     * @param pre_mode security mode for proxy re-encryption.
     * @param multiparty_mode security mode for multiparty (threshold) decryption.
     * @param execution_mode execution mode for CKKS noise flooding (EXEC_EVALUATION or EXEC_NOISE_ESTIMATION).
     * @param decryption_noise_mode decryption noise mode for CKKS noise flooding.
     * @param noise_scale_value multiplier applied to the fresh encryption noise (always 1 for CKKS).
     * @param statistical_security statistical security parameter (in bits) for CKKS noise flooding.
     * @param num_adversarial_queries number of adversarial decryption queries assumed for CKKS noise flooding.
     * @param threshold_num_of_parties number of parties in a threshold-FHE application (bounds the joint secret key).
     * @param m_p_int_boot_ciphertext_compression_level compression level of the ciphertexts used in multi-party
     * interactive bootstrapping (SLACK or COMPACT).
     * @param composite_degree composite scaling degree d for the COMPOSITESCALING techniques (1 otherwise).
     * @param register_word_size register word size in bits (32, 48 or 64) used to size the primes in composite
     * scaling mode.
     * @param ckks_data_type CKKS data type (REAL or COMPLEX).
     */
    CkksRnsCryptoParams(std::shared_ptr<ParmType> params, EncodingParams encoding_params, float distribution_parameter,
                        float assurance_measure, SecurityLevel security_level, uint32_t digit_size,
                        SecretKeyDist secret_key_dist, int max_relin_sk_deg = 2, KeySwitchTechnique ks_tech = BV,
                        ScalingTechnique scal_tech = FIXEDMANUAL, EncryptionTechnique enc_tech = STANDARD,
                        MultiplicationTechnique mult_tech = HPS, ProxyReEncryptionMode pre_mode = NOT_SET,
                        MultipartyMode multiparty_mode = FIXED_NOISE_MULTIPARTY,
                        ExecutionMode execution_mode = EXEC_EVALUATION,
                        DecryptionNoiseMode decryption_noise_mode = FIXED_NOISE_DECRYPT,
                        PlaintextModulus noise_scale_value = 1, uint32_t statistical_security = 30,
                        uint32_t num_adversarial_queries = 1, uint32_t threshold_num_of_parties = 1,
                        CompressionLevel m_p_int_boot_ciphertext_compression_level = CompressionLevel::SLACK,
                        uint32_t composite_degree = BASE_NUM_LEVELS_TO_DROP,
                        uint32_t register_word_size = CIPHER_NATIVE_INT, CkksDataType ckks_data_type = REAL)
        : RnsCryptoParams(params, encoding_params, distribution_parameter, assurance_measure, security_level,
                          digit_size, secret_key_dist, max_relin_sk_deg, ks_tech, scal_tech, enc_tech, mult_tech,
                          pre_mode, multiparty_mode, execution_mode, decryption_noise_mode, noise_scale_value,
                          statistical_security, num_adversarial_queries, threshold_num_of_parties,
                          m_p_int_boot_ciphertext_compression_level, composite_degree, register_word_size,
                          ckks_data_type) {}

    virtual ~CkksRnsCryptoParams() = default;

    /**
     * Precomputes the CRT tables of the RNS operations for the given techniques (key switching, scaling,
     * encryption and multiplication), and additionally the CKKS-specific tables of the bootstrapping modulus
     * raise with composite scaling and of sparse secret encapsulation.
     *
     * @param ks_tech key switching technique
     * @param scal_tech scaling (rescaling) technique
     * @param enc_tech encryption technique
     * @param mult_tech multiplication technique
     * @param num_part_q number of digits (partitions of Q) for HYBRID key switching
     * @param aux_bits size in bits of the auxiliary moduli of HYBRID key switching
     * @param extra_bits size in bits of the extra modulus of FLEXIBLEAUTOEXT
     */
    void precompute_crt_tables(KeySwitchTechnique ks_tech, ScalingTechnique scal_tech, EncryptionTechnique enc_tech,
                               MultiplicationTechnique mult_tech, uint32_t num_part_q, uint32_t aux_bits,
                               uint32_t extra_bits) override;

    /**
     * Gets the step between candidate auxiliary primes of HYBRID key switching: 2n for CKKS, so that the primes
     * are congruent to 1 modulo the cyclotomic order.
     *
     * @return the step
     */
    uint64_t find_aux_prime_step() const override;

    /**
     * Sets the composite degree for COMPOSITESCALINGAUTO: the smallest number of primes of at most the register
     * word size whose product reaches the scaling modulus size (1 if the scaling modulus fits in the register word).
     * Each prime must have at least 19 bits; register word sizes above 64 bits are not supported. Has no effect for
     * the other scaling techniques.
     *
     * @param scaling_mod_size size of the scaling modulus in bits
     */
    void configure_composite_degree(uint32_t scaling_mod_size);

    // PlaintextModulus get_plaintext_modulus() const override {
    //     DISABLED_FOR_CKKSRNS_PARAMS;
    // }

    /**
     * Not available for CKKS (the number of additions is not tracked); always throws.
     *
     * @return never returns
     */
    uint32_t get_eval_add_count() const override {
        DISABLED_FOR_CKKSRNS_PARAMS;
    }

    /**
     * Not available for CKKS (the number of key switchings is not tracked); always throws.
     *
     * @return never returns
     */
    uint32_t get_key_switch_count() const override {
        DISABLED_FOR_CKKSRNS_PARAMS;
    }

    /**
     * Not available for CKKS (the number of PRE hops is not tracked); always throws.
     *
     * @return never returns
     */
    uint32_t get_pre_num_hops() const override {
        DISABLED_FOR_CKKSRNS_PARAMS;
    }

    /////////////////////////////////////
    // Composite scaling : bootstrapping modulus raise (extend_ciphertext)
    // Tables for the exact CRT basis extension (RnsPoly::expand_crt_basis) from the small
    // bottom basis Ql = {q_0, ..., q_{d-1}}, d = composite_degree (the towers remaining in
    // the depleted ciphertext), to the full basis Q. ComplQl = {q_d, ..., q_{L-1}} denotes
    // the complement of Ql in Q (the extension moduli).
    // Only populated when composite_degree > 1; see precompute_crt_tables.
    /////////////////////////////////////

    /**
     * Gets the element parameters of the extension basis ComplQl = {q_d, ..., q_{L-1}}
     *
     * @return the precomputed parameters
     */
    const std::shared_ptr<ParmType>& get_params_mod_raise_compl_ql() const {
        return params_mod_raise_compl_ql_;
    }

    /**
     * Gets the precomputed table of [(Ql/q_i)^{-1}]_{q_i}, q_i in Ql
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_mod_raise_ql_hat_inv_modq() const {
        return mod_raise_ql_hat_inv_modq_;
    }

    /**
     * Gets the modular multiplication precomputations for [(Ql/q_i)^{-1}]_{q_i}, q_i in Ql
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_mod_raise_ql_hat_inv_modq_precon() const {
        return mod_raise_ql_hat_inv_modq_precon_;
    }

    /**
     * Gets the precomputed table of [Ql/q_i]_{q_j}, q_i in Ql, q_j in ComplQl
     *
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_mod_raise_ql_hat_mod_complq() const {
        return mod_raise_ql_hat_mod_complq_;
    }

    /**
     * Gets the precomputed table of [a*Ql]_{q_j}, 0 <= a <= d, q_j in ComplQl (the overflow
     * correction used in the exact CRT reconstruction)
     *
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_mod_raise_alpha_ql_mod_complq() const {
        return mod_raise_alpha_ql_mod_complq_;
    }

    /**
     * Gets the Barrett modulo reduction precomputations for q_j in ComplQl
     *
     * @return the precomputed table
     */
    const std::vector<DoubleNativeInt>& get_mod_raise_mod_complq_barrett_mu() const {
        return mod_raise_mod_complq_barrett_mu_;
    }

    /**
     * Gets the precomputed table of 1./q_i for q_i in Ql
     *
     * @return the precomputed table
     */
    const std::vector<double>& get_mod_raiseq_inv() const {
        return mod_raiseq_inv_;
    }

    /////////////////////////////////////
    // Sparse secret encapsulation (SPARSE_ENCAPSULATED): switching between the dense and
    // sparse secrets at the bootstrapping modulus raise (CkksRnsFhe::key_switch_gen_sparse /
    // key_switch_sparse). The GHS-style switching key is generated over Ql*P', where
    // Ql = {q_0, ..., q_{d-1}} (d = composite_degree) is the basis of the bottom level and
    // P' = p'_0*...*p'_{k-1} is an auxiliary modulus generated here, during parameter generation:
    // two 33-bit primes without composite scaling; with it, ~66 bits when the bottom modulus has at
    // most 60 bits and ~127 bits for a larger one (at most 121 bits), split into primes that fit the
    // register word size. Making P' exceed the bottom modulus by ~6 bits makes
    // the key switching noise floor(Ql*e/P') comparable to the modulus switching noise.
    /////////////////////////////////////

    /**
     * Gets the element parameters of the sparse encapsulation auxiliary basis P' = {p'_0, ..., p'_{k-1}}
     *
     * @return the precomputed parameters
     */
    const std::shared_ptr<ParmType>& get_sparse_ks_params_p() const {
        return sparse_ks_params_p_;
    }

    /**
     * Gets the element parameters of the extended basis {q_0, ..., q_{d-1}, p'_0, ..., p'_{k-1}}
     *
     * @return the precomputed parameters
     */
    const std::shared_ptr<ParmType>& get_sparse_ks_params_qp() const {
        return sparse_ks_params_qp_;
    }

    /**
     * Gets the element parameters of the bottom basis Ql = {q_0, ..., q_{d-1}}
     *
     * @return the precomputed parameters
     */
    const std::shared_ptr<ParmType>& get_sparse_ks_params_q() const {
        return sparse_ks_params_q_;
    }

    /**
     * Gets [P']_{q_i} for q_i in Ql
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_sparse_ksp_modq() const {
        return sparse_ksp_modq_;
    }

    /**
     * Gets [P'^{-1}]_{q_i} for q_i in Ql
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_sparse_ksp_inv_modq() const {
        return sparse_ksp_inv_modq_;
    }

    /**
     * Gets [(P'/p'_j)^{-1}]_{p'_j}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_sparse_ksp_hat_inv_modp() const {
        return sparse_ksp_hat_inv_modp_;
    }

    /**
     * Gets the modular multiplication precomputations for [(P'/p'_j)^{-1}]_{p'_j}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_sparse_ksp_hat_inv_modp_precon() const {
        return sparse_ksp_hat_inv_modp_precon_;
    }

    /**
     * Gets [P'/p'_j]_{q_i}, indexed as [q_i][p'_j]
     *
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_sparse_ksp_hat_modq() const {
        return sparse_ksp_hat_modq_;
    }

    /**
     * Gets the overflow correction [a*P']_{q_i}, 0 <= a <= k, indexed as [a][q_i]
     *
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_sparse_ks_alpha_p_modq() const {
        return sparse_ks_alpha_p_modq_;
    }

    /**
     * Gets the Barrett modulo reduction precomputations for q_i in Ql
     *
     * @return the precomputed table
     */
    const std::vector<DoubleNativeInt>& get_sparse_ks_modq_barrett_mu() const {
        return sparse_ks_modq_barrett_mu_;
    }

    /**
     * Gets 1./p'_j
     *
     * @return the precomputed table
     */
    const std::vector<double>& get_sparse_ks_p_inv() const {
        return sparse_ks_p_inv_;
    }

    /**
     * Gets [Ql/q_i]_{p'_j}, indexed as [p'_j][q_i]
     *
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_sparse_ks_ql_hat_modp() const {
        return sparse_ks_ql_hat_modp_;
    }

    /**
     * Gets the overflow correction [a*Ql]_{p'_j}, 0 <= a <= d, indexed as [a][p'_j]
     *
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_sparse_ks_alpha_ql_modp() const {
        return sparse_ks_alpha_ql_modp_;
    }

    /**
     * Gets the Barrett modulo reduction precomputations for p'_j
     *
     * @return the precomputed table
     */
    const std::vector<DoubleNativeInt>& get_sparse_ks_modp_barrett_mu() const {
        return sparse_ks_modp_barrett_mu_;
    }

    /**
     * Gets the Hamming weight of the sparse secret used for sparse encapsulation: 32 for a first (bottom) modulus
     * of at most 60 bits, and 64 for larger first moduli; see sparse_ks_hamming_weight
     *
     * @return the Hamming weight
     */
    uint32_t get_sparse_ks_hamming_weight() const {
        return sparse_ks_hamming_weight_;
    }

    /**
     * Hamming weight of the sparse secret used for sparse encapsulation, fully determined by the size of the first
     * (bottom) modulus in bits: 32 for a first modulus of at most 60 bits, and 64 for larger first moduli (in the
     * 64-bit build these require composite scaling). The denser secret selects the K = 28 approximations of
     * SPARSE_TERNARY in bootstrapping (K = 16 otherwise). Static so that the bootstrapping depth estimates can
     * apply the same rule before a cryptocontext exists.
     *
     * @param first_mod_size_value size of the first modulus in bits
     * @return the Hamming weight (32 or 64)
     */
    static uint32_t sparse_ks_hamming_weight(uint32_t first_mod_size_value) {
        return (first_mod_size_value > 60) ? 64 : 32;
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
            precompute_crt_tables(ks_technique_, scal_technique_, enc_technique_, mult_technique_, num_part_q_,
                                  aux_bits_, extra_bits_);
        }
    }

    std::string serialized_object_name() const override {
        return "CryptoParametersCKKSRNS";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    // Params for the extension basis ComplQl
    std::shared_ptr<ParmType> params_mod_raise_compl_ql_;
    // [(Ql/q_i)^{-1}]_{q_i}, q_i in Ql
    std::vector<NativeInteger> mod_raise_ql_hat_inv_modq_;
    // modular multiplication precomputations for [(Ql/q_i)^{-1}]_{q_i}
    std::vector<NativeInteger> mod_raise_ql_hat_inv_modq_precon_;
    // [Ql/q_i]_{q_j}, q_i in Ql, q_j in ComplQl
    std::vector<std::vector<NativeInteger>> mod_raise_ql_hat_mod_complq_;
    // [a*Ql]_{q_j}, 0 <= a <= d, q_j in ComplQl
    std::vector<std::vector<NativeInteger>> mod_raise_alpha_ql_mod_complq_;
    // Barrett modulo reduction precomputations for q_j in ComplQl
    std::vector<DoubleNativeInt> mod_raise_mod_complq_barrett_mu_;
    // 1./q_i for q_i in Ql
    std::vector<double> mod_raiseq_inv_;

    // Sparse secret encapsulation (SPARSE_ENCAPSULATED) precomputations for the key
    // switching to/from the sparse secret at the bootstrapping modulus raise: auxiliary
    // basis P' = {p'_0, ..., p'_{k-1}} and the tables for the exact (HPS-style) CRT basis
    // switches between the bottom basis Ql = {q_0, ..., q_{d-1}} and P'.
    // Not serialized; regenerated by precompute_crt_tables (including after deserialization).

    // Params for the auxiliary basis P'
    std::shared_ptr<ParmType> sparse_ks_params_p_;
    // Params for the extended basis {q_0, ..., q_{d-1}, p'_0, ..., p'_{k-1}}
    std::shared_ptr<ParmType> sparse_ks_params_qp_;
    // Params for the bottom basis Ql = {q_0, ..., q_{d-1}}
    std::shared_ptr<ParmType> sparse_ks_params_q_;
    // [P']_{q_i}
    std::vector<NativeInteger> sparse_ksp_modq_;
    // [P'^{-1}]_{q_i}
    std::vector<NativeInteger> sparse_ksp_inv_modq_;
    // [(P'/p'_j)^{-1}]_{p'_j}
    std::vector<NativeInteger> sparse_ksp_hat_inv_modp_;
    // modular multiplication precomputations for [(P'/p'_j)^{-1}]_{p'_j}
    std::vector<NativeInteger> sparse_ksp_hat_inv_modp_precon_;
    // [P'/p'_j]_{q_i}, indexed as [q_i][p'_j]
    std::vector<std::vector<NativeInteger>> sparse_ksp_hat_modq_;
    // [a*P']_{q_i}, 0 <= a <= k, indexed as [a][q_i]
    std::vector<std::vector<NativeInteger>> sparse_ks_alpha_p_modq_;
    // Barrett modulo reduction precomputations for q_i in Ql
    std::vector<DoubleNativeInt> sparse_ks_modq_barrett_mu_;
    // 1./p'_j
    std::vector<double> sparse_ks_p_inv_;
    // [Ql/q_i]_{p'_j}, indexed as [p'_j][q_i]
    std::vector<std::vector<NativeInteger>> sparse_ks_ql_hat_modp_;
    // [a*Ql]_{p'_j}, 0 <= a <= d, indexed as [a][p'_j]
    std::vector<std::vector<NativeInteger>> sparse_ks_alpha_ql_modp_;
    // Barrett modulo reduction precomputations for p'_j
    std::vector<DoubleNativeInt> sparse_ks_modp_barrett_mu_;
    // Hamming weight of the sparse secret (32, or 64 for first moduli larger than 60 bits)
    uint32_t sparse_ks_hamming_weight_ = 32;
};

}  // namespace cipher

#endif  // CIPHER_FHE_CKKS_CRYPTO_PARAMS_H_
