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

#ifndef CIPHER_FHE_RNS_CRYPTO_PARAMS_H_
#define CIPHER_FHE_RNS_CRYPTO_PARAMS_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/ring/backend.h"
#include "cipher/fhe/base/rlwe_params.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief main implementation class to capture essential cryptoparameters of
 * any LBC system.
 * As RnsCryptoParams is not an abstract class and we don't want to
 * instantiate, then we make all its constructors and the destructor protected
 */
class RnsCryptoParams : public RlweCryptoParams<RnsPoly> {
    using ParmType = typename RnsPoly::Params;

  protected:
    RnsCryptoParams()
        : RlweCryptoParams<RnsPoly>(),
          ks_technique_(BV),
          scal_technique_(FIXEDMANUAL),
          enc_technique_(STANDARD),
          mult_technique_(HPS),
          mp_int_boot_ciphertext_compression_level_(SLACK) {}

    RnsCryptoParams(const RnsCryptoParams& rhs)
        : RlweCryptoParams<RnsPoly>(rhs),
          ks_technique_(rhs.ks_technique_),
          scal_technique_(rhs.scal_technique_),
          enc_technique_(rhs.enc_technique_),
          mult_technique_(rhs.mult_technique_),
          mp_int_boot_ciphertext_compression_level_(rhs.mp_int_boot_ciphertext_compression_level_) {}

    /**
     * Constructor that initializes values.  Note that it is possible to set
     * parameters in a way that is overall infeasible for actual use. There are
     * fewer degrees of freedom than parameters provided.  Typically one chooses
     * the basic noise, assurance and security parameters as the typical
     * community-accepted values, then chooses the plaintext modulus and depth
     * as needed.  The element parameters should then be choosen to provide
     * correctness and security.  In some cases we would need to operate over
     * already encrypted/provided ciphertext and the depth needs to be
     * pre-computed for initial settings.
     *
     * @param params element parameters.
     * @param plaintext_modulus plaintext modulus.
     * @param distribution_parameter noise distribution parameter.
     * @param assurance_measure assurance level.
     * @param security_level security level.
     * @param digit_size the size of the relinearization window.
     * @param secret_key_dist sets the secret_key_dist of operation: GAUSSIAN or UNIFORM_TERNARY
     * @param max_relin_sk_deg the maximum power of secret key for which the
     * relinearization key is generated
     * @param ks_tech key switching method
     * @param scal_tech scaling method
     * @param enc_tech encryption method
     * @param mult_tech multiplication method
     * @param multiparty_mode security mode for multiparty decryption
     * @param execution_mode execution mode for CKKS noise flooding
     * @param decryption_noise_mode decryption noise mode for CKKS noise flooding
     * @param m_p_int_boot_ciphertext_compression_level compression level of the ciphertexts used in
     * multi-party interactive bootstrapping
     */
    RnsCryptoParams(std::shared_ptr<ParmType> params, const PlaintextModulus& plaintext_modulus,
                        float distribution_parameter, float assurance_measure, SecurityLevel security_level,
                        uint32_t digit_size, SecretKeyDist secret_key_dist, int max_relin_sk_deg = 2,
                        KeySwitchTechnique ks_tech = BV, ScalingTechnique scal_tech = FIXEDMANUAL,
                        EncryptionTechnique enc_tech = STANDARD, MultiplicationTechnique mult_tech = HPS,
                        MultipartyMode multiparty_mode = FIXED_NOISE_MULTIPARTY,
                        ExecutionMode execution_mode = EXEC_EVALUATION,
                        DecryptionNoiseMode decryption_noise_mode = FIXED_NOISE_DECRYPT,
                        CompressionLevel m_p_int_boot_ciphertext_compression_level = CompressionLevel::SLACK)
        : RlweCryptoParams<RnsPoly>(
                  std::move(params), EncodingParams(std::make_shared<EncodingParamsImpl>(plaintext_modulus)),
                  distribution_parameter, assurance_measure, security_level, digit_size, max_relin_sk_deg, secret_key_dist,
                  INDCPA, multiparty_mode, execution_mode, decryption_noise_mode) {
        ks_technique_ = ks_tech;
        scal_technique_ = scal_tech;
        enc_technique_ = enc_tech;
        mult_technique_ = mult_tech;
        mp_int_boot_ciphertext_compression_level_ = m_p_int_boot_ciphertext_compression_level;
    }

    /**
     * Constructor that initializes all RNS crypto parameters from explicit encoding parameters. In addition to the
     * RLWE parameters it stores the RNS-specific techniques (key switching, scaling, encryption, multiplication),
     * the threshold-FHE and noise-flooding settings, and the CKKS composite scaling settings.
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
     * @param scal_tech scaling (rescaling/modulus switching) technique.
     * @param enc_tech encryption technique (STANDARD or EXTENDED; EXTENDED is BFV-specific).
     * @param mult_tech BFV homomorphic multiplication technique (HPS, BEHZ, HPSPOVERQ or HPSPOVERQLEVELED).
     * @param pre_mode security mode for proxy re-encryption.
     * @param multiparty_mode security mode for multiparty (threshold) decryption.
     * @param execution_mode execution mode for CKKS noise flooding (EXEC_EVALUATION or EXEC_NOISE_ESTIMATION).
     * @param decryption_noise_mode decryption noise mode for CKKS noise flooding.
     * @param noise_scale_value multiplier applied to the fresh encryption noise (1 for BFV/CKKS, the plaintext modulus
     * for BGV).
     * @param statistical_security statistical security parameter (in bits) for CKKS noise flooding.
     * @param num_adversarial_queries number of adversarial decryption queries assumed for CKKS noise flooding.
     * @param threshold_num_of_parties number of parties in a threshold-FHE application (bounds the joint secret key).
     * @param m_p_int_boot_ciphertext_compression_level compression level of the ciphertexts used in multi-party
     * interactive bootstrapping (SLACK or COMPACT).
     * @param composite_degree composite scaling degree d for the CKKS COMPOSITESCALING techniques (1 otherwise).
     * @param register_word_size register word size in bits (32, 48 or 64) used to size the primes in CKKS composite
     * scaling mode.
     * @param ckks_data_type CKKS data type (REAL or COMPLEX).
     */
    RnsCryptoParams(std::shared_ptr<ParmType> params, EncodingParams encoding_params, float distribution_parameter,
                        float assurance_measure, SecurityLevel security_level, uint32_t digit_size,
                        SecretKeyDist secret_key_dist, int max_relin_sk_deg = 2, KeySwitchTechnique ks_tech = BV,
                        ScalingTechnique scal_tech = FIXEDMANUAL, EncryptionTechnique enc_tech = STANDARD,
                        MultiplicationTechnique mult_tech = HPS, ProxyReEncryptionMode pre_mode = INDCPA,
                        MultipartyMode multiparty_mode = FIXED_NOISE_MULTIPARTY,
                        ExecutionMode execution_mode = EXEC_EVALUATION,
                        DecryptionNoiseMode decryption_noise_mode = FIXED_NOISE_DECRYPT, PlaintextModulus noise_scale_value = 1,
                        uint32_t statistical_security = 30, uint32_t num_adversarial_queries = 1,
                        uint32_t threshold_num_of_parties = 1,
                        CompressionLevel m_p_int_boot_ciphertext_compression_level = CompressionLevel::SLACK,
                        uint32_t composite_degree = BASE_NUM_LEVELS_TO_DROP, uint32_t register_word_size = CIPHER_NATIVE_INT,
                        CkksDataType ckks_data_type = REAL)
        : RlweCryptoParams<RnsPoly>(std::move(params), std::move(encoding_params), distribution_parameter,
                                         assurance_measure, security_level, digit_size, max_relin_sk_deg, secret_key_dist,
                                         pre_mode, multiparty_mode, execution_mode, decryption_noise_mode, noise_scale_value,
                                         statistical_security, num_adversarial_queries, threshold_num_of_parties) {
        ks_technique_ = ks_tech;
        scal_technique_ = scal_tech;
        enc_technique_ = enc_tech;
        mult_technique_ = mult_tech;
        mp_int_boot_ciphertext_compression_level_ = m_p_int_boot_ciphertext_compression_level;
        composite_degree_ = composite_degree;
        register_word_size_ = register_word_size;
        ckks_data_type_ = ckks_data_type;
    }

    ~RnsCryptoParams() override = default;

    /**
     * @brief compare_to() is a method to compare two RnsCryptoParams objects.
     *        It is called by BaseCryptoParams::operator==()
     * @param rhs - the other RnsCryptoParams object to compare to.
     * @return whether the two RnsCryptoParams objects are equivalent.
     */
    bool compare_to(const BaseCryptoParams<RnsPoly>& rhs) const override {
        auto el = dynamic_cast<const RnsCryptoParams*>(&rhs);
        if (!el)
            return false;

        return RlweCryptoParams<RnsPoly>::compare_to(rhs) && scal_technique_ == el->scal_technique_ &&
               ks_technique_ == el->ks_technique_ && mult_technique_ == el->mult_technique_ &&
               enc_technique_ == el->enc_technique_ && num_part_q_ == el->num_part_q_ && aux_bits_ == el->aux_bits_ &&
               extra_bits_ == el->extra_bits_ && pre_mode_ == el->pre_mode_ &&
               multiparty_mode_ == el->multiparty_mode_ && execution_mode_ == el->execution_mode_ &&
               composite_degree_ == el->composite_degree_ && register_word_size_ == el->register_word_size_ &&
               ckks_data_type_ == el->ckks_data_type_;
    }

    /**
     * Prints the RLWE parameters to the given output stream.
     *
     * @param os the output stream.
     */
    void print_parameters(std::ostream& os) const override {
        RlweCryptoParams<RnsPoly>::print_parameters(os);
    }

  public:
    /**
     * Computes all tables needed for decryption, homomorphic multiplication and key switching.
     * Even though this is a pure virtual function and must be overriden in all derived classes,
     * precompute_crt_tables() has its own implementation in the source file. It should be called from
     * derived classes' precompute_crt_tables() only and must not be called from RnsCryptoParams::load().
     * @param ks_tech the technique to use for key switching (e.g., BV or GHS).
     * @param scal_tech the technique to use for scaling (e.g., FLEXIBLEAUTO or FIXEDMANUAL).
     * @param enc_tech the technique to use for encryption (STANDARD or EXTENDED).
     * @param mult_tech the technique to use for homomorphic multiplication (e.g., HPS or BEHZ).
     * @param num_part_q the number of digits (partitions of Q) for HYBRID key switching.
     * @param aux_bits the number of bits in the auxiliary (special) prime moduli.
     * @param extra_bits the number of extra bits reserved for the auxiliary modulus in HYBRID key switching.
     */
    virtual void precompute_crt_tables(KeySwitchTechnique ks_tech, ScalingTechnique scal_tech, EncryptionTechnique enc_tech,
                                     MultiplicationTechnique mult_tech, uint32_t num_part_q, uint32_t aux_bits,
                                     uint32_t extra_bits) = 0;

    /**
     * Returns the step used when searching for the auxiliary (special) primes of HYBRID key switching: every
     * auxiliary prime p is chosen such that p = 1 (mod step) so that the required roots of unity exist. The base
     * implementation returns the ring dimension; the schemes override it (2n for BFV, lcm(2n, t) for BGV).
     *
     * @return the modulus step for the auxiliary prime search.
     */
    virtual uint64_t find_aux_prime_step() const;

    /**
     * Estimates the extra modulus bitsize needed for hybrid key switching (used for finding the minimum secure
     * ring dimension).
     *
     * @param num_part_q number of digits in hybrid key switching
     * @param first_modulus_size bit size of first modulus
     * @param dcrt_bits bit size for other moduli
     * @param extra_modulus_size bit size for extra modulus in FLEXIBLEAUTOEXT (CKKS and BGV only)
     * @param num_primes_value number of moduli witout extra_modulus
     * @param aux_bits size of auxiliar moduli used for hybrid key switching
     * @param scal_tech scaling technique
     * @param add_one should an extra bit be added (for CKKS and BGV)
     * @param is_noise_flooding_multiparty whether threshold FHE uses noise flooding multiparty mode (BGV and BFV)
     * @param composite_degree composite degree (for CKKS only)
     *
     * @return log2 of the modulus and number of RNS limbs.
     */
    static std::pair<double, uint32_t> estimate_log_p(uint32_t num_part_q, double first_modulus_size, double dcrt_bits,
                                                    double extra_modulus_size, uint32_t num_primes_value, uint32_t aux_bits,
                                                    ScalingTechnique scal_tech, bool add_one = false,
                                                    bool is_noise_flooding_multiparty = false,
                                                    uint32_t composite_degree = 1);

    /**
     * Estimates the extra modulus bitsize needed for threshold FHE noise flooding (only for BGV and BFV)
     *
     * @return number of extra bits needed for noise flooding
     */
    static constexpr double estimate_multiparty_flooding_log_q() {
        return static_cast<double>(NoiseFlooding::MULTIPARTY_MOD_SIZE * NoiseFlooding::NUM_MODULI_MULTIPARTY);
    }

    /////////////////////////////////////
    // precompute_crt_tables
    /////////////////////////////////////

    /**
     * Method to retrieve the technique to be used for key switching.
     *
     * @return the key switching technique.
     */
    KeySwitchTechnique get_key_switch_technique() const {
        return ks_technique_;
    }

    /**
     * Method to retrieve the technique to be used for scaling.
     *
     * @return the scaling technique.
     */
    ScalingTechnique get_scaling_technique() const {
        return scal_technique_;
    }

    /**
     * Method to retrieve the technique to be used for encryption.
     *
     * @return the encryption technique.
     */
    EncryptionTechnique get_encryption_technique() const {
        return enc_technique_;
    }

    /**
     * Method to retrieve the technique to be used for homomorphic multiplication.
     *
     * @return the multiplication technique.
     */
    MultiplicationTechnique get_multiplication_technique() const {
        return mult_technique_;
    }

    /**
     * Returns the bit size of the auxiliary (special) primes P used in HYBRID key switching.
     *
     * @return the number of bits in each auxiliary prime.
     */
    uint32_t get_aux_bits() const {
        return aux_bits_;
    }

    /**
     * Returns the number of extra bits reserved in the auxiliary modulus of HYBRID key switching (used by the
     * FLEXIBLEAUTOEXT technique to lower the key switching noise).
     *
     * @return the number of extra bits.
     */
    uint32_t get_extra_bits() const {
        return extra_bits_;
    }

    /**
     * Returns the element parameters used for public/secret key generation. These are the extended basis QP when
     * HYBRID key switching is used with proxy re-encryption enabled, the basis Qr when BFV EXTENDED encryption is
     * used, and the ciphertext basis Q otherwise.
     *
     * @return the CRT parameters of the key basis.
     */
    const std::shared_ptr<RnsParams<BigInteger>> get_params_pk() const override {
        if ((ks_technique_ == HYBRID) && (pre_mode_ != NOT_SET))
            return params_qp_;
        if ((enc_technique_ == EXTENDED) && (params_qr_ != nullptr))
            return params_qr_;
        return params_;
    }

    /////////////////////////////////////
    // BGVrns : mod_reduce
    /////////////////////////////////////

    /**
     * Method that returns the NTL precomputions for [t]_{q_i}
     *
     * @return the pre-computed values.
     */
    const std::vector<NativeInteger>& get_t_modq_precon() const {
        return t_modq_precon_;
    }

    /**
     * Get the precomputed value [-t^{-1}]_{q_l}
     *
     * @param l index of the tower q_l.
     * @return the pre-computed value.
     */
    NativeInteger get_negt_inv_modq(uint32_t l) const {
        return negt_inv_modq_[l];
    }

    /**
     * Method that returns the NTL precomputions for [-t^{-1}]_{q_l}
     *
     * @param l index of the tower q_l.
     * @return the pre-computed value.
     */
    NativeInteger get_negt_inv_modq_precon(uint32_t l) const {
        return negt_inv_modq_precon_[l];
    }

    /////////////////////////////////////
    // CKKSrns : drop_last_element_and_scale
    /////////////////////////////////////

    /**
     * Gets the precomputed table of [q_i^{-1}]_{q_j}
     *
     * @param i index of the tower q_i being dropped.
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_ql_inv_modq(size_t i) const {
        return ql_inv_modq_[i];
    }

    /**
     * Gets the NTL precomputions for [q_i^{-1}]_{q_j}
     *
     * @param i index of the tower q_i being dropped.
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_ql_inv_modq_precon(size_t i) const {
        return ql_inv_modq_precon_[i];
    }

    /////////////////////////////////////
    // KeySwitchHybrid : key_gen
    /////////////////////////////////////

    /**
     * Gets Q*P CRT basis
     * Q*P = {q_1,...,q_l,p_1,...,p_k}
     * Used in Hybrid key switch generation
     *
     * @return the precomputed CRT params
     */
    const std::shared_ptr<RnsParams<BigInteger>> get_params_qp() const {
        return params_qp_;
    }

    /**
     * Method that returns the number of digits.
     * Used in Hybrid key switch generation
     * @return the number of digits.
     */
    uint32_t get_num_part_q() const {
        return num_part_q_;
    }

    /**
     * Gets the precomputed table of [P]_{q_i}
     * Used in Hybrid key switch generation.
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_p_modq() const {
        return p_modq_;
    }

    /////////////////////////////////////
    // KeySwitchHybrid : key_switch
    /////////////////////////////////////

    /**
     * Gets the Auxiliary CRT basis {P} = {p_1,...,p_k}
     * Used in Hybrid key switching
     *
     * @return the parameters CRT params
     */
    const std::shared_ptr<RnsParams<BigInteger>> get_params_p() const {
        return params_p_;
    }

    /**
     * Gets params for the first size_ql towers of Q, used in HYBRID key_switch_down and returns a cached entry.
     * @param size_ql number of Q towers to include (1 to get_element_params()->get_params().size()).
     * @return shared_ptr to RnsParams for the first size_ql Q moduli.
     */
    const std::shared_ptr<RnsParams<BigInteger>> get_params_ql_hybrid(uint32_t size_ql) const {
        return params_ql_hybrid_.at(size_ql - 1);
    }

    /**
     * Method that returns the number of towers within every digit.
     * This is the alpha parameter from the paper (see documentation
     * for KeySwitchHHybrid).
     * Used in Hybrid key switching
     *
     * @return the number of towers per digit.
     */
    uint32_t get_num_per_part_q() const {
        return num_per_part_q_;
    }

    /**
     * Method that returns the number of partitions.
     * Used in Hybrid key switching
     *
     * @return the number of partitions.
     */
    uint32_t get_number_of_q_partitions() const {
        return params_part_q_.size();
    }

    /**
     * Method that returns the element parameters corresponding to
     * partitions {Q_j} of Q.
     * Used in Hybrid key switching
     *
     * @param part index of the partition (digit).
     * @return the pre-computed values.
     */
    const std::shared_ptr<RnsParams<BigInteger>>& get_params_part_q(uint32_t part) const {
        return params_part_q_[part];
    }

    /**
     * Method that returns the element parameters corresponding to the
     * complementary basis of a single digit j, i.e., the basis consisting of
     * all other digits plus the special primes.
     *
     * @param num_towers number of towers in the ciphertext minus 1 (the table is
     * indexed by size_ql - 1).
     * @param digit is the index of the digit we want to get the complementary
     * partition from.
     * @return the partitions.
     */
    const std::shared_ptr<RnsParams<BigInteger>>& get_params_compl_part_q(uint32_t num_towers, uint32_t digit) const {
        return params_compl_part_q_[num_towers][digit];
    }

    /**
     * Method that returns the precomputed values for q_hat^-1 mod qj within a
     * partition of towers, used in HYBRID.
     *
     * @param part index of the partition (digit).
     * @param sublvl number of towers in the partition minus 1.
     * @return the pre-computed values.
     */
    const std::vector<NativeInteger>& get_part_ql_hat_inv_modq(uint32_t part, uint32_t sublvl) const {
        if (part < part_ql_hat_inv_modq_.size() && sublvl < part_ql_hat_inv_modq_[part].size())
            return part_ql_hat_inv_modq_[part][sublvl];

        CIPHER_THROW("Index out of bounds.");
    }

    /**
     * NTL precomputations getter for q_hat^-1 mod qj within a partition of towers, used in HYBRID.
     *
     * @param part index of the partition (digit).
     * @param sublvl number of towers in the partition minus 1.
     * @return the pre-computed values.
     */
    const std::vector<NativeInteger>& get_part_ql_hat_inv_modq_precon(uint32_t part, uint32_t sublvl) const {
        if (part < part_ql_hat_inv_modq_precon_.size() && sublvl < part_ql_hat_inv_modq_precon_[part].size())
            return part_ql_hat_inv_modq_precon_[part][sublvl];

        CIPHER_THROW("Index out of bounds.");
    }

    /**
     * Getter for the table containing [part_q_hat_value]_{p_j}, used in HYBRID.
     *
     * @param lvl number of towers in the ciphertext minus 1.
     * @param part index of the partition (digit).
     * @return the pre-computed values.
     */
    const std::vector<std::vector<NativeInteger>>& get_part_ql_hat_modp(uint32_t lvl, uint32_t part) const {
        if (lvl < part_ql_hat_modp_.size() && part < part_ql_hat_modp_[lvl].size())
            return part_ql_hat_modp_[lvl][part];

        CIPHER_THROW("Index out of bounds.");
    }

    /**
     * Barrett multiplication precomputations getter for the complementary partition basis, used in HYBRID.
     *
     * @param lvl number of towers in the ciphertext minus 1.
     * @param part index of the partition (digit).
     * @return the pre-computed values.
     */
    const std::vector<DoubleNativeInt>& get_mod_compl_partq_barrett_mu(uint32_t lvl, uint32_t part) const {
        if (lvl < mod_compl_partq_barrett_mu_.size() && part < mod_compl_partq_barrett_mu_[lvl].size())
            return mod_compl_partq_barrett_mu_[lvl][part];

        CIPHER_THROW("Index out of bounds.");
    }

    /**
     * Gets the precomputed table of [P^{-1}]_{q_i}
     * Used in GHS key switching
     *
     * See more in "A full RNS variant of approximate homomorphic
     * encryption" by Cheon, et. al. Section 4.
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_p_inv_modq() const {
        return p_inv_modq_;
    }

    /**
     * Gets the NTL precomputions for [P^{-1}]_{q_i}
     * Used for speeding up GHS key switching.
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_p_inv_modq_precon() const {
        return p_inv_modq_precon_;
    }

    /**
     * Get the precomputed table of [(P/p_j)^{-1}]_{p_j}
     * Used in GHS key switching.
     *
     * See more in "A full RNS variant of approximate homomorphic
     * encryption" by Cheon, et. al. Section 4.
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_p_hat_inv_modp() const {
        return p_hat_inv_modp_;
    }

    /**
     * Get the NTL precomputions for [(P/p_j)^{-1}]_{p_j}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_p_hat_inv_modp_precon() const {
        return p_hat_inv_modp_precon_;
    }

    /**
     * Gets the precomputed table of [P/p_j]_{q_i}
     * Used in GHS key switching.
     *
     * See more in "A full RNS variant of approximate homomorphic
     * encryption" by Cheon, et. al. Section 4.
     *
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_p_hat_modq() const {
        return p_hat_modq_;
    }

    /**
     * Gets the Barrett modulo reduction precomputation for q_i
     *
     * @return the precomputed table
     */
    const std::vector<DoubleNativeInt>& get_modq_barrett_mu() const {
        return modq_barrett_mu_;
    }

    /**
     * Method that returns the precomputed values for [t^(-1)]_{q_i}
     * Used in ModulusSwitching.
     *
     * @return the pre-computed values.
     */
    const std::vector<NativeInteger>& get_t_inv_modq() const {
        return t_inv_modq_;
    }

    /**
     * Method that returns the NTL precomputions for [t^{-1}]_{q_i}
     *
     * @return the pre-computed values.
     */
    const std::vector<NativeInteger>& get_t_inv_modq_precon() const {
        return t_inv_modq_precon_;
    }

    /**
     * Method that returns the precomputed values for [t^(-1)]_{p_j}
     * Used in KeySwitching.
     *
     * @return the pre-computed values.
     */
    const std::vector<NativeInteger>& get_t_inv_modp() const {
        return t_inv_modp_;
    }

    /**
     * Method that returns the NTL precomputions for [t^{-1}]_{p_j}
     *
     * @return the pre-computed values.
     */
    const std::vector<NativeInteger>& get_t_inv_modp_precon() const {
        return t_inv_modp_precon_;
    }

    /////////////////////////////////////
    // CKKSrns Scaling Factor
    /////////////////////////////////////

    /**
     * Method to retrieve the scaling factor of level l.
     * For FIXEDMANUAL scaling technique method always returns 2^p, where p corresponds to plaintext modulus
     * @param l For FLEXIBLEAUTO and COMPOSITESCALING scaling techniques the level whose scaling factor we want to learn.
     * Levels start from 0 (no scaling done - all towers) and go up to K-1, where K is the number of towers supported.
     * @return the scaling factor.
     */
    double get_scaling_factor_real(uint32_t l = 0) const {
        if (scal_technique_ == FLEXIBLEAUTO || scal_technique_ == FLEXIBLEAUTOEXT ||
            scal_technique_ == COMPOSITESCALINGAUTO || scal_technique_ == COMPOSITESCALINGMANUAL) {
            if (l >= scaling_factors_real_.size()) {
                // TODO: Return an error here.
                return approx_sf_;
            }

            return scaling_factors_real_[l];
        }

        return approx_sf_;
    }

    /**
     * Method to retrieve the scaling factor of a ciphertext of noise scale degree 2 at level l, i.e., the product
     * of the scaling factors of the two multiplied operands (used for CKKS FLEXIBLEAUTO, FLEXIBLEAUTOEXT and
     * COMPOSITESCALING). For the other scaling techniques it returns the square of the fixed scaling factor 2^p.
     *
     * @param l the level (levels start from 0 with all towers present); if l is beyond the precomputed table,
     * the fixed scaling factor is returned.
     * @return the scaling factor of a degree-2 ciphertext.
     */
    double get_scaling_factor_real_big(uint32_t l = 0) const {
        if (scal_technique_ == FLEXIBLEAUTO || scal_technique_ == FLEXIBLEAUTOEXT ||
            scal_technique_ == COMPOSITESCALINGAUTO || scal_technique_ == COMPOSITESCALINGMANUAL) {
            if (l >= scaling_factors_real_big_.size()) {
                // TODO: Return an error here.
                return approx_sf_;
            }

            return scaling_factors_real_big_[l];
        }

        return approx_sf_ * approx_sf_;
    }

    /**
     * Method to retrieve the modulus to be dropped of level l.
     * For FIXEDMANUAL rescaling technique method always returns 2^p, where p corresponds to plaintext modulus
     * @param l index of modulus to be dropped for FLEXIBLEAUTO and COMPOSITESCALING scaling techniques
     * @return the precomputed table
     */
    double get_mod_reduce_factor(uint32_t l = 0) const {
        if (scal_technique_ == FLEXIBLEAUTO || scal_technique_ == FLEXIBLEAUTOEXT ||
            scal_technique_ == COMPOSITESCALINGAUTO || scal_technique_ == COMPOSITESCALINGMANUAL) {
            return dmoduli_q_[l];
        }

        return approx_sf_;
    }

    /////////////////////////////////////
    // CKKS RNS Composite Scaling Params
    /////////////////////////////////////

    /**
     * Returns the composite scaling degree d. Its values is determined at runtime based on
     * input scaling factor and architecture register size (e.g., 32 bits, 48 bits, 64 bits).
     * This parameter is only relevant when using the CKKS scheme with the COMPOSITESCALING scaling techniques.
     *
     * @return the composite degree value for COMPOSITESCALING scaling technique
     **/
    uint32_t get_composite_degree() const {
        // If not CKKS scheme, same value as BASE_NUM_LEVELS_TO_DROP
        return composite_degree_;
    }
    /**
     * Returns the architecture register word size (e.g., 32 bits, 48 bits, 64 bits).
     * Used to determine the size of prime moduli in the CKKS scheme on
     * composite scaling mode (COMPOSITESCALINGAUTO).
     *
     * @return the register word size for COMPOSITESCALING scaling technique
     **/
    uint32_t get_register_word_size() const {
        return register_word_size_;
    }

    /////////////////////////////////////
    // BFVrns : Encrypt : POverQ
    /////////////////////////////////////

    /**
     * Gets the precomputed value [-Q_l]_t, where Q_l is the ciphertext modulus with the last i towers dropped.
     * Used in BFV encryption and plaintext addition to scale the plaintext by Q_l/t.
     *
     * @param i number of RNS limbs dropped from the full modulus Q (0 for a fresh full-modulus ciphertext).
     * @return the precomputed value.
     */
    NativeInteger get_neg_q_modt(uint32_t i = 0) const {
        return neg_q_modt_[i];
    }

    /**
     * Gets the NTL precomputation for [-Q_l]_t.
     *
     * @param i number of RNS limbs dropped from the full modulus Q (0 for a fresh full-modulus ciphertext).
     * @return the precomputed value.
     */
    NativeInteger get_neg_q_modt_precon(uint32_t i = 0) const {
        return neg_q_modt_precon_[i];
    }

    /**
     * Gets the precomputed value [-Q*r]_t used in BFV encryption in EXTENDED mode, where r is the extra prime.
     *
     * @return the precomputed value.
     */
    NativeInteger get_neg_qr_modt() const {
        return neg_qr_modt_;
    }

    /**
     * Gets the NTL precomputation for [-Q*r]_t used in BFV encryption in EXTENDED mode.
     *
     * @return the precomputed value.
     */
    NativeInteger get_neg_qr_modt_precon() const {
        return neg_qr_modt_precon_;
    }

    /**
     * Method that returns the precomputed values for [t^(-1)]_{a} where a is from {q_i} U r
     * Used in ModulusSwitching.
     *
     * @return the pre-computed values.
     */
    const std::vector<NativeInteger>& get_t_inv_modqr() const {
        return t_inv_modqr_;
    }

    /////////////////////////////////////
    // BFVrns : Mult : expand_crt_basis
    /////////////////////////////////////

    /**
     * Gets the CRT basis {Q_l} = {q_0,...,q_l} used in BFV homomorphic multiplication. For HPS only index 0
     * (the full basis Q) is available.
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1; used in HPSPOVERQLEVELED).
     * @return the precomputed CRT params.
     */
    const std::shared_ptr<RnsParams<BigInteger>> get_params_ql(uint32_t l = 0) const {
        return params_ql_[l];
    }

    /**
     * Gets the precomputed fractional parts {[Q_l*(Q/q_j)^{-1}]_{q_j}/q_j} for the moduli q_j of Q that are not
     * in Q_l. Used to scale a polynomial from basis Q down to Q_l in HPSPOVERQLEVELED.
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1).
     * @return the precomputed table.
     */
    const std::vector<double>& get_ql_q_hat_inv_modq_divq_frac(uint32_t l) const {
        return ql_q_hat_inv_modq_divq_frac_[l];
    }

    /**
     * Gets the precomputed table of [floor(Q_l*(Q/q_j)^{-1}/q_j)]_{q_i} for q_i in Q_l and q_j in Q (the last
     * entry of each row corresponds to q_j = q_i). Used to scale a polynomial from basis Q down to Q_l in
     * HPSPOVERQLEVELED.
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1).
     * @return the precomputed table.
     */
    const std::vector<std::vector<NativeInteger>>& get_ql_q_hat_inv_modq_divq_modq(uint32_t l) const {
        return ql_q_hat_inv_modq_divq_modq_[l];
    }

    /**
     * Gets the Auxiliary CRT basis {R} = {r_1,...,r_k}
     * used in homomorphic multiplication
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1; used in HPSPOVERQLEVELED).
     * @return the precomputed CRT params
     */
    const std::shared_ptr<RnsParams<BigInteger>> get_params_rl(uint32_t l = 0) const {
        return params_rl_[l];
    }

    /**
     * Gets the Auxiliary expanded CRT basis {S} = {Q*R} =
     * {{q_i},{r_k}} used in homomorphic multiplication
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1; used in HPSPOVERQLEVELED).
     * @return the precomputed CRT params
     */
    const std::shared_ptr<RnsParams<BigInteger>> get_params_ql_rl(uint32_t l = 0) const {
        return params_ql_rl_[l];
    }

    /**
     * Gets the precomputed table of [(Q_l/q_i)^{-1}]_{q_i}
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1; used in HPSPOVERQLEVELED).
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_ql_hat_inv_modq(uint32_t l = 0) const {
        return ql_hat_inv_modq_[l];
    }

    /**
     * Gets the NTL precomputations for [(Q_l/q_i)^{-1}]_{q_i}
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1; used in HPSPOVERQLEVELED).
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_ql_hat_inv_modq_precon(uint32_t l = 0) const {
        return ql_hat_inv_modq_precon_[l];
    }

    /**
     * Gets the precomputed table of [Q_l/q_i]_{r_k}
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1; used in HPSPOVERQLEVELED).
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_ql_hat_modr(uint32_t l = 0) const {
        return ql_hat_modr_[l];
    }

    /**
     * Gets the precomputed table of [alpha*Q_l]_{r_k}
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1; used in HPSPOVERQLEVELED).
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_alpha_ql_modr(uint32_t l = 0) const {
        return alpha_ql_modr_[l];
    }

    /**
     * Gets the precomputed table of [-R_l*(Q/q_i)^{-1}]_{q_i} used for the fast basis extension from Q to R_l
     * (HPSPOVERQ and HPSPOVERQLEVELED).
     *
     * @param l index of the leveled parameter set (number of towers in R_l minus 1).
     * @return the precomputed table.
     */
    const std::vector<NativeInteger>& get_m_neg_rl_q_hat_inv_modq(uint32_t l = 0) const {
        return neg_rl_q_hat_inv_modq_[l];
    }

    /**
     * Gets the NTL precomputations for [-R_l*(Q/q_i)^{-1}]_{q_i}.
     *
     * @param l index of the leveled parameter set (number of towers in R_l minus 1).
     * @return the precomputed table.
     */
    const std::vector<NativeInteger>& get_m_neg_rl_q_hat_inv_modq_precon(uint32_t l = 0) const {
        return neg_rl_q_hat_inv_modq_precon_[l];
    }

    /**
     * Gets the precomputed table of [-R_l*(Q_l/q_i)^{-1}]_{q_i} used for the fast basis extension from Q_l to R_l
     * when the ciphertext has already been compressed to Q_l (HPSPOVERQ and HPSPOVERQLEVELED).
     *
     * @param l index of the leveled parameter set (number of towers in Q_l and R_l minus 1).
     * @return the precomputed table.
     */
    const std::vector<NativeInteger>& get_m_neg_rl_ql_hat_inv_modq(uint32_t l = 0) const {
        return neg_rl_ql_hat_inv_modq_[l];
    }

    /**
     * Gets the NTL precomputations for [-R_l*(Q_l/q_i)^{-1}]_{q_i}.
     *
     * @param l index of the leveled parameter set (number of towers in Q_l and R_l minus 1).
     * @return the precomputed table.
     */
    const std::vector<NativeInteger>& get_m_neg_rl_ql_hat_inv_modq_precon(uint32_t l = 0) const {
        return neg_rl_ql_hat_inv_modq_precon_[l];
    }

    /**
     * Gets the precomputed table of [q_i^{-1}]_{r_j} (indexed as [i][j]) used for the fast basis extension
     * from Q to R in BFV homomorphic multiplication.
     *
     * @return the precomputed table.
     */
    const std::vector<std::vector<NativeInteger>>& get_q_inv_modr() const {
        return q_inv_modr_;
    }

    /**
     * Gets the Barrett modulo reduction precomputations for r_k
     *
     * @return the precomputed table
     */
    const std::vector<DoubleNativeInt>& get_modr_barrett_mu() const {
        return modr_barrett_mu_;
    }

    /**
     * Gets the precomputed table of 1./q_i
     *
     * @return the precomputed table
     */
    const std::vector<double>& get_q_inv() const {
        return q_inv_;
    }

    /////////////////////////////////////
    // BFVrns : Mult : scale_and_round
    /////////////////////////////////////

    /**
     * For S = QR
     * Gets the precomputed table of frac{[t*R*(S/s_m)^{-1}]_{s_m}/s_m}
     *
     * @return the precomputed table
     */
    const std::vector<double>& get_t_rs_hat_inv_mods_divs_frac() const {
        return t_rs_hat_inv_mods_divs_frac_;
    }

    /**
     * For S = QR
     * Gets the precomputed table of [floor{t*R*(S/s_m)^{-1}/s_m}]_{r_k}
     *
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_t_rs_hat_inv_mods_divs_modr() const {
        return t_rs_hat_inv_mods_divs_modr_;
    }

    /////////////////////////////////////
    // BFVrns : Mult : switch_crt_basis
    /////////////////////////////////////

    /**
     * Gets the precomputed table of [(R_l/r_k)^{-1}]_{r_k}
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1; used in HPSPOVERQLEVELED).
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_rl_hat_inv_modr(uint32_t l = 0) const {
        return rl_hat_inv_modr_[l];
    }

    /**
     * Gets the NTL precomputation for [(R_l/r_k)^{-1}]_{r_k}
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1; used in HPSPOVERQLEVELED).
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_rl_hat_inv_modr_precon(uint32_t l = 0) const {
        return rl_hat_inv_modr_precon_[l];
    }

    /**
     * Gets the precomputed table of [R_l/r_k]_{q_i}
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1; used in HPSPOVERQLEVELED).
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_rl_hat_modq(uint32_t l = 0) const {
        return rl_hat_modq_[l];
    }

    /**
     * Gets the precomputed table of [alpha*R_l]_{q_i}
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1; used in HPSPOVERQLEVELED).
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_alpha_rl_modq(uint32_t l = 0) const {
        return alpha_rl_modq_[l];
    }

    /**
     * For S_l = Q_l*R_l, gets the precomputed fractional parts {[t*Q_l*(S_l/r_j)^{-1}]_{r_j}/r_j} used to scale
     * the product by t/R_l and round it back to basis Q_l (HPS, HPSPOVERQ and HPSPOVERQLEVELED).
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1; only 0 for HPS).
     * @return the precomputed table.
     */
    const std::vector<double>& get_t_ql_sl_hat_inv_mods_divs_frac(uint32_t l) const {
        return t_ql_sl_hat_inv_mods_divs_frac_[l];
    }

    /**
     * For S_l = Q_l*R_l, gets the precomputed table of [floor(t*Q_l*(S_l/s_m)^{-1}/s_m)]_{q_i} (the last entry
     * of each row corresponds to s_m = q_i) used to scale the product by t/R_l and round it back to basis Q_l.
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1; only 0 for HPS).
     * @return the precomputed table.
     */
    const std::vector<std::vector<NativeInteger>>& get_t_ql_sl_hat_inv_mods_divs_modq(uint32_t l) const {
        return t_ql_sl_hat_inv_mods_divs_modq_[l];
    }

    /**
     * Gets the precomputed table of [Q/Q_l]_{q_i} for q_i in Q_l, used to expand a polynomial from basis Q_l
     * back to the full basis Q in HPSPOVERQLEVELED.
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1).
     * @return the precomputed table.
     */
    const std::vector<NativeInteger>& get_ql_hat_modq(uint32_t l) const {
        return ql_hat_modq_[l];
    }

    /**
     * Gets the NTL precomputations for [Q/Q_l]_{q_i}.
     *
     * @param l index of the leveled parameter set (number of towers in Q_l minus 1).
     * @return the precomputed table.
     */
    const std::vector<NativeInteger>& get_ql_hat_modq_precon(uint32_t l) const {
        return ql_hat_modq_precon_[l];
    }

    /**
     * Gets the precomputed table of 1./r_k
     *
     * @return the precomputed table
     */
    const std::vector<double>& get_r_inv() const {
        return r_inv_;
    }

    /////////////////////////////////////
    // BFVrns : Decrypt : scale_and_round
    /////////////////////////////////////

    /**
     * Gets the precomputed table of frac{t*{Q/q_i}^{-1}/q_i}
     *
     * @return the precomputed table
     */
    const std::vector<double>& get_t_q_hat_inv_modq_divq_frac() const {
        return t_q_hat_inv_modq_divq_frac_;
    }

    /**
     * When log2(q_i) >= 45 bits, B = floor[2^{ceil{log2(q_i)/2}}
     * Gets the precomputed table of frac{t*{Q/q_i}^{-1}*B/q_i}
     *
     * @return the precomputed table
     */
    const std::vector<double>& get_t_q_hat_inv_modq_b_divq_frac() const {
        return t_q_hat_inv_modq_b_divq_frac_;
    }

    /**
     * Gets the precomputed table of [floor{t*{Q/q_i}^{-1}/q_i}]_t
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_t_q_hat_inv_modq_divq_modt() const {
        return t_q_hat_inv_modq_divq_modt_;
    }

    /**
     * Gets the NTL precomputations for [floor{t*{Q/q_i}^{-1}/q_i}]_t
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_t_q_hat_inv_modq_divq_modt_precon() const {
        return t_q_hat_inv_modq_divq_modt_precon_;
    }

    /**
     * When log2(q_i) >= 45 bits, B = floor[2^{ceil{log2(q_i)/2}}
     * Gets the precomputed table of [floor{t*{Q/q_i}^{-1}*B/q_i}]_t
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_t_q_hat_inv_modq_b_divq_modt() const {
        return t_q_hat_inv_modq_b_divq_modt_;
    }

    /**
     * When log2(q_i) >= 45 bits, B = floor[2^{ceil{log2(q_i)/2}}
     * Gets the NTL precomputations for [floor{t*{Q/q_i}^{-1}*B/q_i}]_t
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_t_q_hat_inv_modq_b_divq_modt_precon() const {
        return t_q_hat_inv_modq_b_divq_modt_precon_;
    }

    /**
     * Method to retrieve the BGV scaling factor (modulo the plaintext modulus t) of a ciphertext of noise scale
     * degree 1 at level l. For FLEXIBLEAUTO and FLEXIBLEAUTOEXT the value is read from the precomputed table;
     * for the other scaling techniques the fixed value 1 is returned.
     *
     * @param l the level (levels start from 0 with all towers present); if l is beyond the precomputed table,
     * the fixed scaling factor is returned.
     * @return the scaling factor modulo t.
     */
    NativeInteger get_scaling_factor_int(uint32_t l) const {
        if (scal_technique_ == FLEXIBLEAUTO || scal_technique_ == FLEXIBLEAUTOEXT ||
            scal_technique_ == COMPOSITESCALINGAUTO || scal_technique_ == COMPOSITESCALINGMANUAL) {
            if (l >= scaling_factors_int_.size()) {
                // TODO: Return an error here.
                return fixed_sf_;
            }
            return scaling_factors_int_[l];
        }
        return fixed_sf_;
    }

    /**
     * Method to retrieve the BGV scaling factor (modulo t) of a ciphertext of noise scale degree 2 at level l,
     * i.e., the product of the scaling factors of the two multiplied operands (FLEXIBLEAUTO and FLEXIBLEAUTOEXT).
     * For the other scaling techniques the fixed value 1 is returned.
     *
     * @param l the level (levels start from 0 with all towers present); if l is beyond the precomputed table,
     * the fixed scaling factor is returned.
     * @return the scaling factor modulo t.
     */
    NativeInteger get_scaling_factor_int_big(uint32_t l) const {
        if (scal_technique_ == FLEXIBLEAUTO || scal_technique_ == FLEXIBLEAUTOEXT ||
            scal_technique_ == COMPOSITESCALINGAUTO || scal_technique_ == COMPOSITESCALINGMANUAL) {
            if (l >= scaling_factors_int_big_.size()) {
                // TODO: Return an error here.
                return fixed_sf_;
            }
            return scaling_factors_int_big_[l];
        }
        return fixed_sf_;
    }

    /**
     * Method to retrieve [q_l]_t, the factor by which the BGV scaling factor is divided when tower q_l is dropped
     * by modulus switching (FLEXIBLEAUTO and FLEXIBLEAUTOEXT). For the other scaling techniques the fixed value 1
     * is returned.
     *
     * @param l index of the tower q_l being dropped.
     * @return the modulus reduction factor modulo t.
     */
    NativeInteger get_mod_reduce_factor_int(uint32_t l = 0) const {
        if (scal_technique_ == FLEXIBLEAUTO || scal_technique_ == FLEXIBLEAUTOEXT ||
            scal_technique_ == COMPOSITESCALINGAUTO || scal_technique_ == COMPOSITESCALINGMANUAL) {
            return q_modt_[l];
        }
        return fixed_sf_;
    }

    /////////////////////////////////////
    // BFVrns : Encrypt
    /////////////////////////////////////

    /**
     * Gets the precomputed table of [r^{-1}]_{q_i}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_r_inv_modq() const {
        return r_inv_modq_;
    }

    /**
     * Gets the Auxiliary CRT basis {Qr} = {Q U r}
     * used in BFV encryption in mode EXTENDED
     *
     * @return the precomputed CRT params
     */
    const std::shared_ptr<RnsParams<BigInteger>> get_params_qr() const {
        return params_qr_;
    }

    /////////////////////////////////////
    // BFVrnsB
    /////////////////////////////////////

    /**
     * Gets the Auxiliary CRT basis {Bsk} = {B U msk}
     * used in homomorphic multiplication
     *
     * @return the precomputed CRT params
     */
    const std::shared_ptr<RnsParams<BigInteger>> get_params_q_bsk() const {
        return params_q_bsk_;
    }

    /**
     * Gets the precomputed table of q_i
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_moduli_q() const {
        return moduli_q_;
    }

    /**
     * Gets the precomputed table of bsk_j
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_moduli_bsk() const {
        return moduli_bsk_;
    }

    /**
     * Gets the Barrett modulo reduction precomputation for bsk_j
     *
     * @return the precomputed table
     */
    const std::vector<DoubleNativeInt>& get_modbsk_barrett_mu() const {
        return modbsk_barrett_mu_;
    }

    /**
     * Gets the precomputed table of [mtilde*(Q/q_i)^{-1}]_{q_i}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger> get_mtilde_q_hat_inv_modq() const {
        return mtilde_q_hat_inv_modq_;
    }

    /**
     * Gets the NTL precomputations for [mtilde*(Q/q_i)^{-1}]_{q_i}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_mtilde_q_hat_inv_modq_precon() const {
        return mtilde_q_hat_inv_modq_precon_;
    }

    /**
     * Gets the precomputed table of [Q/q_i]_{bsk_j}
     *
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_q_hat_modbsk() const {
        return q_hat_modbsk_;
    }

    /**
     * Gets the precomputed table of [(q_i)^{-1}]_{bsk_j}
     *
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_q_inv_modbsk() const {
        return q_inv_modbsk_;
    }

    /**
     * Gets the precomputed table of [Q/q_i]_{mtilde}
     *
     * @return the precomputed table
     */
    const std::vector<uint64_t>& get_q_hat_modmtilde() const {
        return q_hat_modmtilde_;
    }

    /**
     * Gets the precomputed table of [Q]_{bsk_j}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_q_modbsk() const {
        return q_modbsk_;
    }

    /**
     * Gets the NTL precomputations for [Q]_{bsk_j}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_q_modbsk_precon() const {
        return q_modbsk_precon_;
    }

    /**
     * Gets the precomputed [-Q^{-1}]_{mtilde}
     *
     * @return the precomputed value
     */
    uint64_t get_neg_q_inv_modmtilde() const {
        return neg_q_inv_modmtilde_;
    }

    /**
     * Gets the precomputed table of [mtilde^{-1}]_{bsk_j}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_mtilde_inv_modbsk() const {
        return mtilde_inv_modbsk_;
    }

    /**
     * Gets the NTL precomputations for [mtilde^{-1}]_{bsk_j}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_mtilde_inv_modbsk_precon() const {
        return mtilde_inv_modbsk_precon_;
    }

    /**
     * Gets the precomputed table of [t*(Q/q_i)^{-1}]_{q_i}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_t_q_hat_inv_modq() const {
        return t_q_hat_inv_modq_;
    }

    /**
     * Gets the NTL precomputations for [t*(Q/q_i)^{-1}]_{q_i}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_t_q_hat_inv_modq_precon() const {
        return t_q_hat_inv_modq_precon_;
    }

    /**
     * Gets the precomputed table of [t*gamma*(Q/q_i)^(-1)]_{q_i}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_tgamma_q_hat_inv_modq() const {
        return tgamma_q_hat_inv_modq_;
    }

    /**
     * Gets the NTL precomputations for [t*gamma*(Q/q_i)^(-1)]_{q_i}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_tgamma_q_hat_inv_modq_precon() const {
        return tgamma_q_hat_inv_modq_precon_;
    }

    /**
     * Gets the precomputed table of [t/Q]_{bsk_j}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_t_q_inv_modbsk() const {
        return t_q_inv_modbsk_;
    }

    /**
     * Gets the NTL precomputations for [t/Q]_{bsk_j}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_t_q_inv_modbsk_precon() const {
        return t_q_inv_modbsk_precon_;
    }

    /**
     * Gets the precomputed table of [(B/b_j)^{-1}]_{b_j}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_b_hat_inv_modb() const {
        return b_hat_inv_modb_;
    }

    /**
     * Gets the NTL precomputations for [(B/b_j)^{-1}]_{b_j}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_b_hat_inv_modb_precon() const {
        return b_hat_inv_modb_precon_;
    }

    /**
     * Gets the precomputed table of [B/b_j]_{msk}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_b_hat_modmsk() const {
        return b_hat_modmsk_;
    }

    /**
     * Gets the precomputed [B^{-1}]_msk
     *
     * @return the precomputed value
     */
    NativeInteger get_b_inv_modmsk() const {
        return b_inv_modmsk_;
    }

    /**
     * Gets the NTL precomputions for [B^{-1}]_msk
     *
     * @return the precomputed value
     */
    NativeInteger get_b_inv_modmsk_precon() const {
        return b_inv_modmsk_precon_;
    }

    /**
     * Gets the precomputed table of [B/b_j]_{q_i}
     *
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_b_hat_modq() const {
        return b_hat_modq_;
    }

    /**
     * Gets the precomputed table of [B]_{q_i}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_b_modq() const {
        return b_modq_;
    }

    /**
     * Gets the NTL precomputions for [B]_{q_i}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_b_modq_precon() const {
        return b_modq_precon_;
    }

    /**
     * Gets auxiliary modulus gamma
     *
     * @return gamma
     */
    uint32_t get_gamma() const {
        return gamma_;
    }

    // TODO: use 64 bit words in case NativeInteger uses smaller word size
    /**
     * Gets t*gamma where t - plaintext modulus, gamma - auxiliary modulus
     *
     * @return t*gamma
     */
    NativeInteger get_tgamma() const {
        return tgamma_;
    }

    /**
     * Gets the precomputed table of [-(q_i)^{-1}]_{t*gamma}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_neg_invq_modtgamma() const {
        return neg_invq_modtgamma_;
    }

    /**
     * Gets the NTL precomputations for [-(q_i)^{-1}]_{t*gamma}
     *
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_neg_invq_modtgamma_precon() const {
        return neg_invq_modtgamma_precon_;
    }

    /**
     * Gets the precomputed table of [*(Q/q_i/q_0)^{-1}]_{q_i}
     *
     * @param l index of the leveled parameter set (number of towers in the ciphertext minus 2).
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_multiparty_q_hat_inv_modq_at_index(uint32_t l) const {
        return multiparty_q_hat_inv_modq_[l];
    }

    /**
     * Gets the NTL precomputations for [*(Q/q_i/q_0)^{-1}]_{q_i}
     *
     * @param l index of the leveled parameter set (number of towers in the ciphertext minus 2).
     * @return the precomputed table
     */
    const std::vector<NativeInteger>& get_multiparty_q_hat_inv_modq_precon_at_index(uint32_t l) const {
        return multiparty_q_hat_inv_modq_precon_[l];
    }

    /**
     * Gets the precomputed table of [Q/q_i/q_0]_{q_0}
     *
     * @param l index of the leveled parameter set (number of towers in the ciphertext minus 2).
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_multiparty_q_hat_modq0_at_index(uint32_t l) const {
        return multiparty_q_hat_modq0_[l];
    }

    /**
     * Gets the precomputed table of [alpha*Q/q_0]_{q_0} for 0 <= alpha <= 1
     *
     * @param l index of the leveled parameter set (number of towers in the ciphertext minus 2).
     * @return the precomputed table
     */
    const std::vector<std::vector<NativeInteger>>& get_multiparty_alpha_q_modq0_at_index(uint32_t l) const {
        return multiparty_alpha_q_modq0_[l];
    }

    /**
     * Gets the Barrett modulo reduction precomputation for q_0
     *
     * @return the precomputed table
     */
    const std::vector<DoubleNativeInt>& get_multiparty_modq0_barrett_mu() const {
        return multiparty_modq0_barrett_mu_;
    }

    /**
     * Gets the precomputed table of frac{1/q_i}
     *
     * @return the precomputed table
     */
    const std::vector<double>& get_multiparty_q_inv() const {
        return multiparty_q_inv_;
    }

    /////////////////////////////////////
    // CKKS RNS MultiParty Bootstrapping Parameter
    /////////////////////////////////////
    /**
     * Gets the Multi-Party Interactive Bootstrapping Ciphertext Compression Level
     * @return mp_int_boot_ciphertext_compression_level_
     */
    CompressionLevel get_mp_int_boot_ciphertext_compression_level() const {
        return mp_int_boot_ciphertext_compression_level_;
    }

    /**
     * Method to retrieve the CKKS data type.
     *
     * @return the CKKS data type.
     */
    CkksDataType get_ckks_data_type() const {
        return ckks_data_type_;
    }

  protected:
    /////////////////////////////////////
    // precompute_crt_tables
    /////////////////////////////////////

    // Stores the technique to use for key switching
    KeySwitchTechnique ks_technique_;

    ScalingTechnique scal_technique_;

    EncryptionTechnique enc_technique_;

    MultiplicationTechnique mult_technique_;

    uint32_t aux_bits_ = 0;

    uint32_t extra_bits_ = 0;

    /////////////////////////////////////
    // BGVrns mod_reduce
    /////////////////////////////////////

    // Stores NTL precomputations for [t]_{q_i}
    std::vector<NativeInteger> t_modq_precon_;

    // Stores [-t^{-1}]_{q_i}
    std::vector<NativeInteger> negt_inv_modq_;

    // Stores NTL precomputations for [-t^{-1}]_{q_i}
    std::vector<NativeInteger> negt_inv_modq_precon_;

    /////////////////////////////////////
    // CKKSrns/BFVrns drop_last_element_and_scale
    /////////////////////////////////////

    // Stores [q_l^{-1}]_{q_i}
    std::vector<std::vector<NativeInteger>> ql_inv_modq_;

    // Stores NTL precomputations for [q_l^{-1}]_{q_i}
    std::vector<std::vector<NativeInteger>> ql_inv_modq_precon_;

    /////////////////////////////////////
    // KeySwitchHybrid key_gen
    /////////////////////////////////////

    // Params for Extended CRT basis {QP} = {q_1...q_l,p_1,...,p_k}
    // used in GHS key switching
    std::shared_ptr<RnsParams<BigInteger>> params_qp_;

    // Cached params for Q_l (first size_ql towers of Q) used in key_switch_down.
    // params_ql_hybrid_[l] = params for first (l+1) Q towers; index by size_ql-1 when looking up.
    std::vector<std::shared_ptr<RnsParams<BigInteger>>> params_ql_hybrid_;

    // Stores the partition size {PartQ} = {Q_1,...,Q_l}
    // where each Q_i is the product of q_j
    uint32_t num_part_q_ = 0;

    // Stores [P]_{q_i}, used in GHS key switching
    std::vector<NativeInteger> p_modq_;

    /////////////////////////////////////
    // KeySwitchHybrid key_switch
    /////////////////////////////////////

    // Params for Auxiliary CRT basis {P} = {p_1,...,p_k}
    // used in GHS key switching
    std::shared_ptr<RnsParams<BigInteger>> params_p_;

    // Stores the number of towers per Q_i
    uint32_t num_per_part_q_ = 0;

    // Stores the parameters for moduli Q_i
    std::vector<std::shared_ptr<RnsParams<BigInteger>>> params_part_q_;

    // Stores the parameters for complementary {\bar{Q_i},P}
    std::vector<std::vector<std::shared_ptr<RnsParams<BigInteger>>>> params_compl_part_q_;

    // Stores [{(Q_k)^(l)/q_i}^{-1}]_{q_i} for HYBRID
    std::vector<std::vector<std::vector<NativeInteger>>> part_ql_hat_inv_modq_;

    // Stores NTL precomputations for
    // [{(Q_k)^(l)/q_i}^{-1}]_{q_i} for HYBRID
    std::vector<std::vector<std::vector<NativeInteger>>> part_ql_hat_inv_modq_precon_;

    // Stores [QHat_i]_{p_j}
    std::vector<std::vector<std::vector<std::vector<NativeInteger>>>> part_ql_hat_modp_;

    // Stores the Barrett mu for CompQBar_i
    std::vector<std::vector<std::vector<DoubleNativeInt>>> mod_compl_partq_barrett_mu_;

    // Stores [P^{-1}]_{q_i}, required for GHS key switching
    std::vector<NativeInteger> p_inv_modq_;

    // Stores NTL precomputations for [P^{-1}]_{q_i}
    std::vector<NativeInteger> p_inv_modq_precon_;

    // Stores [(P/p_j)^{-1}]_{p_j}, required for GHS key switching
    std::vector<NativeInteger> p_hat_inv_modp_;

    // Stores NTL precomputations for [(P/p_j)^{-1}]_{p_j}
    std::vector<NativeInteger> p_hat_inv_modp_precon_;

    // Stores [P/p_j]_{q_i}, required for GHS key switching
    std::vector<std::vector<NativeInteger>> p_hat_modq_;

    // Stores the barrett_uint128_mod_uint64 precomputations for q_j
    std::vector<DoubleNativeInt> modq_barrett_mu_;

    // Stores [t^{-1}]_{p_j}
    std::vector<NativeInteger> t_inv_modp_;

    // Stores NTL precomputations for [t^{-1}]_{p_j}
    std::vector<NativeInteger> t_inv_modp_precon_;

    /////////////////////////////////////
    // CKKS Scaling Factor
    /////////////////////////////////////

    // A vector holding the doubles that correspond to the exact
    // scaling factor of each level, when FLEXIBLEAUTO is used.
    std::vector<double> scaling_factors_real_;

    std::vector<double> scaling_factors_real_big_;

    // Stores q_i as doubles
    std::vector<double> dmoduli_q_;

    // Stores 2^ptm where ptm - plaintext modulus
    double approx_sf_ = 0;

    /////////////////////////////////////
    // CKKS RNS Composite Scaling Params
    /////////////////////////////////////

    // Stores composite degree for composite modulus chain
    uint32_t composite_degree_ = BASE_NUM_LEVELS_TO_DROP;
    // Stores the architecture register word size
    uint32_t register_word_size_ = CIPHER_NATIVE_INT;

    /////////////////////////////////////
    // BFVrns : Encrypt
    /////////////////////////////////////

    std::vector<NativeInteger> scaling_factors_int_;

    std::vector<NativeInteger> scaling_factors_int_big_;

    std::vector<NativeInteger> q_modt_;

    NativeInteger fixed_sf_ = NativeInteger(1);

    /////////////////////////////////////
    // BFVrns : Encrypt
    /////////////////////////////////////

    std::vector<NativeInteger> neg_q_modt_;
    std::vector<NativeInteger> neg_q_modt_precon_;
    std::vector<NativeInteger> t_inv_modq_;
    std::vector<NativeInteger> t_inv_modq_precon_;
    std::vector<NativeInteger> t_inv_modqr_;

    /////////////////////////////////////
    // BFVrns : Encrypt
    /////////////////////////////////////

    std::shared_ptr<RnsParams<BigInteger>> params_qr_;
    NativeInteger neg_qr_modt_;
    NativeInteger neg_qr_modt_precon_;
    std::vector<NativeInteger> r_inv_modq_;

    /////////////////////////////////////
    // BFVrns : Decrypt : scale_and_round
    /////////////////////////////////////

    // Stores \frac{t*{Q/q_i}^{-1}/q_i}
    std::vector<double> t_q_hat_inv_modq_divq_frac_;

    // when log2(q_i) >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
    // Stores \frac{t*{Q/q_i}^{-1}*B/q_i}
    std::vector<double> t_q_hat_inv_modq_b_divq_frac_;

    // Stores [\floor{t*{Q/q_i}^{-1}/q_i}]_t
    std::vector<NativeInteger> t_q_hat_inv_modq_divq_modt_;

    // Stores NTL precomputations for [\floor{t*{Q/q_i}^{-1}/q_i}]_t
    std::vector<NativeInteger> t_q_hat_inv_modq_divq_modt_precon_;

    // when log2(q_i) >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
    // Stores [\floor{t*{Q/q_i}^{-1}*B/q_i}]_t
    std::vector<NativeInteger> t_q_hat_inv_modq_b_divq_modt_;

    // when log2 q_i >= 45 bits, B = \floor[2^{\ceil{log2(q_i)/2}}
    // Stores NTL precomputations for [\floor{t*{Q/q_i}^{-1}*B/q_i}]_t
    std::vector<NativeInteger> t_q_hat_inv_modq_b_divq_modt_precon_;

    /////////////////////////////////////
    // BFVrns : Mult : expand_crt_basis
    /////////////////////////////////////

    // Auxiliary CRT basis {Ql} = {q_i}
    // used in homomorphic multiplication
    std::vector<std::shared_ptr<RnsParams<BigInteger>>> params_ql_;

    std::vector<std::vector<double>> ql_q_hat_inv_modq_divq_frac_;
    std::vector<std::vector<std::vector<NativeInteger>>> ql_q_hat_inv_modq_divq_modq_;

    // Auxiliary CRT basis {Rl} = {r_k}
    // used in homomorphic multiplication
    std::vector<std::shared_ptr<RnsParams<BigInteger>>> params_rl_;

    // Auxiliary expanded CRT basis Ql*Rl = {s_m}
    // used in homomorphic multiplication
    std::vector<std::shared_ptr<RnsParams<BigInteger>>> params_ql_rl_;

    // Stores [(Ql/q_i)^{-1}]_{q_i}
    std::vector<std::vector<NativeInteger>> ql_hat_inv_modq_;

    // Stores NTL precomputations for [(Ql/q_i)^{-1}]_{q_i}
    std::vector<std::vector<NativeInteger>> ql_hat_inv_modq_precon_;

    // Stores [Q/q_i]_{r_k}
    std::vector<std::vector<std::vector<NativeInteger>>> ql_hat_modr_;

    // Stores [\alpha*Ql]_{r_k} for 0 <= alpha <= size_ql
    std::vector<std::vector<std::vector<NativeInteger>>> alpha_ql_modr_;

    // Barrett modulo reduction precomputation for r_k
    std::vector<DoubleNativeInt> modr_barrett_mu_;

    // Stores \frac{1/q_i}
    std::vector<double> q_inv_;

    /////////////////////////////////////
    // BFVrns : Mult : scale_and_round
    /////////////////////////////////////

    // S = QR
    // Stores \frac{[t*R*(S/s_m)^{-1}]_{s_m}/s_m}
    std::vector<double> t_rs_hat_inv_mods_divs_frac_;

    // S = QR
    // Stores [\floor{t*R*(S/s_m)^{-1}/s_m}]_{r_k}
    std::vector<std::vector<NativeInteger>> t_rs_hat_inv_mods_divs_modr_;

    /////////////////////////////////////
    // BFVrns : Mult : switch_crt_basis
    /////////////////////////////////////

    // Stores [(Rl/r_k)^{-1}]_{r_k}
    std::vector<std::vector<NativeInteger>> rl_hat_inv_modr_;

    // Stores NTL precomputations for [(Rl/r_k)^{-1}]_{r_k}
    std::vector<std::vector<NativeInteger>> rl_hat_inv_modr_precon_;

    // Stores [Rl/r_k]_{q_i}
    std::vector<std::vector<std::vector<NativeInteger>>> rl_hat_modq_;

    // Stores [\alpha*Rl]_{q_i} for 0 <= alpha <= size_r
    std::vector<std::vector<std::vector<NativeInteger>>> alpha_rl_modq_;

    // Stores \frac{1/r_k}
    std::vector<double> r_inv_;

    /////////////////////////////////////
    // BFVrns : Mult : fast_expand_crt_basis_plover_q
    /////////////////////////////////////

    std::vector<std::vector<NativeInteger>> neg_rl_q_hat_inv_modq_;

    std::vector<std::vector<NativeInteger>> neg_rl_q_hat_inv_modq_precon_;

    std::vector<std::vector<NativeInteger>> neg_rl_ql_hat_inv_modq_;

    std::vector<std::vector<NativeInteger>> neg_rl_ql_hat_inv_modq_precon_;

    std::vector<std::vector<NativeInteger>> q_inv_modr_;

    /////////////////////////////////////
    // BFVrns : Mult : expand_crt_basis_ql_hat
    /////////////////////////////////////

    std::vector<std::vector<NativeInteger>> ql_hat_modq_;

    std::vector<std::vector<NativeInteger>> ql_hat_modq_precon_;

    /////////////////////////////////////
    // BFVrns : Mult : ScaleAndRoundP
    /////////////////////////////////////

    std::vector<std::vector<double>> t_ql_sl_hat_inv_mods_divs_frac_;

    std::vector<std::vector<std::vector<NativeInteger>>> t_ql_sl_hat_inv_mods_divs_modq_;

    /////////////////////////////////////
    // BFVrnsB
    /////////////////////////////////////

    // Auxiliary CRT basis {Bsk} = {B U msk} = {{b_j} U msk}
    std::shared_ptr<RnsParams<BigInteger>> params_q_bsk_;

    // number of moduli in the base {Q}
    uint32_t numq_ = 0;

    // number of moduli in the auxilliary base {B}
    uint32_t numb_ = 0;

    // mtilde = 2^16
    NativeInteger mtilde_ = NativeInteger(BasicInteger(1) << 16);

    // Auxiliary modulus msk
    NativeInteger msk_;

    // Stores q_i
    std::vector<NativeInteger> moduli_q_;

    // Stores auxilliary base moduli b_j
    std::vector<NativeInteger> moduli_b_;

    // Stores the roots of unity modulo bsk_j
    std::vector<NativeInteger> roots_bsk_;

    // Stores moduli {bsk_i} = {{b_j} U msk}
    std::vector<NativeInteger> moduli_bsk_;

    // Barrett modulo reduction precomputation for bsk_j
    std::vector<DoubleNativeInt> modbsk_barrett_mu_;

    // Stores [mtilde*(Q/q_i)^{-1}]_{q_i}
    std::vector<NativeInteger> mtilde_q_hat_inv_modq_;

    // Stores NTL precomputations for [mtilde*(Q/q_i)^{-1}]_{q_i}
    std::vector<NativeInteger> mtilde_q_hat_inv_modq_precon_;

    // Stores [Q/q_i]_{bsk_j}
    std::vector<std::vector<NativeInteger>> q_hat_modbsk_;

    // Stores [(q_i)^{-1}]_{bsk_j}
    std::vector<std::vector<NativeInteger>> q_inv_modbsk_;

    // Stores [Q/q_i]_{mtilde}
    std::vector<uint64_t> q_hat_modmtilde_;

    // Stores [Q]_{bsk_j}
    std::vector<NativeInteger> q_modbsk_;
    // Stores NTL precomputations for [Q]_{bsk_j}
    std::vector<NativeInteger> q_modbsk_precon_;

    // Stores [-Q^{-1}]_{mtilde}
    uint64_t neg_q_inv_modmtilde_ = 0;

    // Stores [mtilde^{-1}]_{bsk_j}
    std::vector<NativeInteger> mtilde_inv_modbsk_;
    // Stores NTL precomputations for [mtilde^{-1}]_{bsk_j}
    std::vector<NativeInteger> mtilde_inv_modbsk_precon_;

    // Stores [t*(Q/q_i)^{-1}]_{q_i}
    std::vector<NativeInteger> t_q_hat_inv_modq_;

    // Stores NTL precomputations for [t*(Q/q_i)^{-1}]_{q_i}
    std::vector<NativeInteger> t_q_hat_inv_modq_precon_;

    // Stores [t*gamma*(Q/q_i)^(-1)]_{q_i}
    std::vector<NativeInteger> tgamma_q_hat_inv_modq_;
    // Stores NTL precomputations for [t*gamma*(Q/q_i)^(-1)]_{q_i}
    std::vector<NativeInteger> tgamma_q_hat_inv_modq_precon_;

    // Stores [t/Q]_{bsk_j}
    std::vector<NativeInteger> t_q_inv_modbsk_;
    // Stores NTL precomputations for [t/Q]_{bsk_j}
    std::vector<NativeInteger> t_q_inv_modbsk_precon_;

    // Stores [(B/b_j)^{-1}]_{b_j}
    std::vector<NativeInteger> b_hat_inv_modb_;

    // Stores NTL precomputations for [(B/b_j)^{-1}]_{b_j}
    std::vector<NativeInteger> b_hat_inv_modb_precon_;

    // stores [B/b_j]_{msk}
    std::vector<NativeInteger> b_hat_modmsk_;

    // Stores [B^{-1}]_msk
    NativeInteger b_inv_modmsk_;
    // Stores NTL precomputations for [B^{-1}]_msk
    NativeInteger b_inv_modmsk_precon_;

    // Stores [B/b_j]_{q_i}
    std::vector<std::vector<NativeInteger>> b_hat_modq_;

    // Stores [B]_{q_i}
    std::vector<NativeInteger> b_modq_;
    // Stores NTL precomputations for [B]_{q_i}
    std::vector<NativeInteger> b_modq_precon_;

    // Stores gamma = 2^26;
    uint32_t gamma_ = 1 << 26;

    // TODO: use 64 bit words in case NativeInteger uses smaller word size
    // Stores t*gamma on a uint64_t word
    NativeInteger tgamma_;

    // Stores [-(q_i)^{-1}]_{t*gamma}
    std::vector<NativeInteger> neg_invq_modtgamma_;
    // Stores NTL precomputations for [-(q_i)^{-1}]_{t*gamma}
    std::vector<NativeInteger> neg_invq_modtgamma_precon_;

    /////////////////////////////////////
    // BFVrns and BGVrns : Multiparty Decryption : expand_crt_basis
    /////////////////////////////////////

    // Stores [*(Q/q_i/q_0)^{-1}]_{q_i}
    std::vector<std::vector<NativeInteger>> multiparty_q_hat_inv_modq_;

    // Stores NTL precomputations for [*(Q/q_i/q_0)^{-1}]_{q_i}
    std::vector<std::vector<NativeInteger>> multiparty_q_hat_inv_modq_precon_;

    // Stores [Q/q_i/q_0]_{q_0}
    std::vector<std::vector<std::vector<NativeInteger>>> multiparty_q_hat_modq0_;

    // Stores [\alpha*Q/q_0]_{q_0} for 0 <= alpha <= 1
    std::vector<std::vector<std::vector<NativeInteger>>> multiparty_alpha_q_modq0_;

    // Barrett modulo reduction precomputation for q_0
    std::vector<DoubleNativeInt> multiparty_modq0_barrett_mu_;

    // Stores \frac{1/q_i}
    std::vector<double> multiparty_q_inv_;

    /////////////////////////////////////
    // CKKS RNS MultiParty Bootstrapping Parameter
    /////////////////////////////////////
    CompressionLevel mp_int_boot_ciphertext_compression_level_;

    // CKKS Data Type
    CkksDataType ckks_data_type_;

  public:
    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::base_class<RlweCryptoParams<RnsPoly>>(this));
        ar(cereal::make_nvp("ks", ks_technique_));
        ar(cereal::make_nvp("rs", scal_technique_));
        ar(cereal::make_nvp("encs", enc_technique_));
        ar(cereal::make_nvp("muls", mult_technique_));
        ar(cereal::make_nvp("dnum", num_part_q_));
        ar(cereal::make_nvp("ab", aux_bits_));
        ar(cereal::make_nvp("eb", extra_bits_));
        ar(cereal::make_nvp("ccl", mp_int_boot_ciphertext_compression_level_));
        ar(cereal::make_nvp("cd", composite_degree_));
        ar(cereal::make_nvp("rws", register_word_size_));
        ar(cereal::make_nvp("cdt", ckks_data_type_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            std::string err_msg("serialized object version " + std::to_string(version) +
                               " is from a later version of the library");
            CIPHER_THROW(err_msg);
        }
        ar(cereal::base_class<RlweCryptoParams<RnsPoly>>(this));
        ar(cereal::make_nvp("ks", ks_technique_));
        ar(cereal::make_nvp("rs", scal_technique_));
        ar(cereal::make_nvp("encs", enc_technique_));
        ar(cereal::make_nvp("muls", mult_technique_));
        ar(cereal::make_nvp("dnum", num_part_q_));
        ar(cereal::make_nvp("ab", aux_bits_));
        ar(cereal::make_nvp("eb", extra_bits_));
        // try-catch is used for backwards compatibility down to 1.0.x
        // mp_int_boot_ciphertext_compression_level_ was added in v1.1.0
        try {
            ar(cereal::make_nvp("ccl", mp_int_boot_ciphertext_compression_level_));
        } catch (cereal::Exception&) {
            mp_int_boot_ciphertext_compression_level_ = CompressionLevel::SLACK;
        }
        ar(cereal::make_nvp("cd", composite_degree_));
        ar(cereal::make_nvp("rws", register_word_size_));
        ar(cereal::make_nvp("cdt", ckks_data_type_));
    }

    std::string serialized_object_name() const override {
        return "SchemeParametersRNS";
    }

    static uint32_t serialized_version() {
        return 1;
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_RNS_CRYPTO_PARAMS_H_
