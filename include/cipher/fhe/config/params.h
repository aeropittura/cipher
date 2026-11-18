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
  Scheme parameter default class
 */

#ifndef CIPHER_FHE_CONFIG_PARAMS_H_
#define CIPHER_FHE_CONFIG_PARAMS_H_

#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

#include "cipher/fhe/constants.h"
#include "cipher/ring/ring_constants.h"
#include "cipher/ring/standard_params.h"
#include "cipher/fhe/config/scheme_id.h"
#include "cipher/util/inttypes.h"

namespace cipher {

//====================================================================================================================
/**
 * @brief Scheme-independent set of parameters used to generate a crypto context. All data members are
 * initialized to the defaults of the selected scheme; the scheme-specific ContextParams specializations disable
 * the setters that do not apply to their scheme. The setters do not validate their arguments; the whole
 * parameter set is validated when the crypto context is generated.
 */
class Params {
    // NOTE: if any data member (below) is added/removed then update
    // cryptocontextparams-case.cpp and cryptocontextparams-defaults.h

    // Scheme ID
    SCHEME scheme;

    // PlaintextModulus pt_modulus is used in BGV/BFV type schemes and impacts noise growth
    PlaintextModulus pt_modulus;

    // digit_size is used in BV Key Switching only (KeySwitchTechnique = BV) and impacts noise growth
    uint32_t digit_size;

    // standard_deviation is used for Gaussian error generation
    float standard_deviation;

    // Secret key distribution: GAUSSIAN, UNIFORM_TERNARY, etc.
    SecretKeyDist secret_key_dist;

    // Max relinearization degree of secret key polynomial (used for lazy relinearization)
    uint32_t max_relin_sk_deg;

    // key switching technique: BV or HYBRID currently
    // For BV we do not have extra modulus, so the security depends on ciphertext modulus Q.
    // For HYBRID we do have extra modulus P, so the security depends on modulus P*Q
    // For BV we need digit_size - digit size in digit decomposition
    // For HYBRID we need num_large_digits - number of digits in digit decomposition
    // it is good to have alternative to num_large_digits (possibly numPrimesInDigit?)
    KeySwitchTechnique ks_tech;

    // rescaling/modulus switching technique used in CKKS/BGV: FLEXIBLEAUTOEXT, FIXEDMANUL, FLEXIBLEAUTO, etc.
    // see https://eprint.iacr.org/2022/915 for details
    ScalingTechnique scal_tech;

    // max batch size of messages to be packed in encoding (number of slots)
    uint32_t batch_size;

    // PRE security mode
    ProxyReEncryptionMode pre_mode;

    // Multiparty security mode in BFV/BGV
    // NOISE_FLOODING_MULTIPARTY is more secure than FIXED_NOISE_MULTIPARTY.
    MultipartyMode multiparty_mode;

    // Execution mode in CKKS
    // In EXEC_NOISE_ESTIMATION mode, we estimate the noise we need to add to the actual computation to guarantee
    // good security.
    // In EXEC_EVALUATION mode, we input our noise estimate and perform the desired secure encrypted computation.
    ExecutionMode execution_mode;

    // Decryption noise mode in CKKS
    // NOISE_FLOODING_DECRYPT is more secure than FIXED_NOISE_DECRYPT, but it requires executing all computations twice.
    DecryptionNoiseMode decryption_noise_mode;

    // Noise estimate in CKKS for NOISE_FLOODING_DECRYPT mode.
    // This estimate is obtained from running the computation in EXEC_NOISE_ESTIMATION mode.
    double noise_estimate;

    // Desired precision for 128-bit CKKS. We use this value in NOISE_FLOODING_DECRYPT mode to determine the scaling
    // factor.
    double desired_precision;

    // Statistical security of CKKS in NOISE_FLOODING_DECRYPT mode. This is the bound on the probability of success
    // that any adversary can have. Specifically, they a probability of success of at most 2^(-statistical_security).
    uint32_t statistical_security;

    // This is the number of adversarial queries a user is expecting for their application, which we use to ensure
    // security of CKKS in NOISE_FLOODING_DECRYPT mode.
    uint32_t num_adversarial_queries;

    // This is the number of parties in a threshold application, which is used for bound on the joint secret key
    uint32_t threshold_num_of_parties;
    // first_mod_size_value and scaling_mod_size are used to calculate ciphertext modulus. The ciphertext modulus should be
    // seen as:
    // Q = q_0 * q_1 * ... * q_n * q'
    // where q_0 is first prime, and it's number of bits is first_mod_size_value
    // other q_i have same number of bits and is equal to scaling_mod_size
    // the prime q' is not explicitly given,
    // but it is used internally in CKKS and BGV schemes (in *EXT scaling methods)
    uint32_t first_mod_size_value;
    uint32_t scaling_mod_size;

    // see KeySwitchTechnique - number of digits in HYBRID key switching
    uint32_t num_large_digits;

    // multiplicative depth
    uint32_t multiplicative_depth;

    // security level:
    // We use the values from the security standard  at
    // http://homomorphicencryption.org/wp-content/uploads/2018/11/HomomorphicEncryptionStandardv1.1.pdf
    // For given ring dimension and security level we have
    // upper bound of possible highest modulus (Q for BV or P*Q for HYBRID)
    SecurityLevel security_level;

    // ring dimension N of the scheme : the ring is Z_Q[x] / (X^N+1)
    uint32_t ring_dim;

    // number of additions (used for setting noise in BGV and BFV)
    uint32_t eval_add_count;

    // number of key switching operations (used for setting noise in BGV and BFV)
    uint32_t key_switch_count;

    // size of moduli used for PRE in the provable HRA setting
    uint32_t pre_num_hops;

    // STANDARD or EXTENDED mode for BFV encryption
    // EXTENDED slightly reduces the size of Q (by few bits) but makes encryption somewhat slower
    // see https://eprint.iacr.org/2022/915 for details
    EncryptionTechnique encryption_technique;

    // multiplication method in BFV: BEHZ, HPS, etc.
    // see https://eprint.iacr.org/2022/915 for details
    MultiplicationTechnique multiplication_technique;

    // Interactive multi-party bootstrapping parameter
    // Set the compression level in ciphertext (SLACK or COMPACT)
    // SLACK has weaker security assumption, thus less efficient
    // COMPACT has stronger security assumption, thus more efficient
    CompressionLevel interactive_boot_compression_level;

    // CKKS composite scaling parameters to support high-precision CKKS RNS with small word sizes
    // Please refer to https://eprint.iacr.org/2023/1462.pdf for details
    uint32_t composite_degree;
    uint32_t register_word_size;

    // CKKS data type: real or complex. Noise flooding is only enabled for real values.
    CkksDataType ckks_data_type;

    void set_to_defaults(SCHEME scheme);

  protected:
    // How to disable a particular setter for a particular scheme and get an exception thrown if a user tries to
    // call it:
    // 1. The set function should be declared virtual in this file
    // 2. The same function should be re-defined in the scheme-specific derived file using macros
    //    DISABLED_FOR_xxxxRNS defined below.
    //
    // Example:
    // the original setter defined in gen-cryptocontext-params.h:
    //
    // virtual void set_plaintext_modulus(PlaintextModulus pt_modulus0) {
    //     pt_modulus = pt_modulus0;
    // }
    //
    // the setter re-defined and disabled in gen-cryptocontext-ckksrns-params.h:
    //
    // void set_plaintext_modulus(PlaintextModulus pt_modulus0) override {
    //     DISABLED_FOR_CKKS;
    // }

#define DISABLED_FOR_CKKSRNS CIPHER_THROW("This function is not available for CKKSRNS.");
#define DISABLED_FOR_BGVRNS  CIPHER_THROW("This function is not available for BGVRNS.");
#define DISABLED_FOR_BFVRNS  CIPHER_THROW("This function is not available for BFVRNS.");

  public:
    /**
     * Constructor that sets all parameters to the defaults of the given scheme.
     *
     * @param scheme0 the scheme (CKKSRNS_SCHEME, BFVRNS_SCHEME or BGVRNS_SCHEME); any other value throws.
     */
    explicit Params(SCHEME scheme0 = INVALID_SCHEME) {
        set_to_defaults(scheme0);
    }

    /**
     * This Params' constructor "explicit Params(const std::vector<std::string>& vals)" is to be used by unittests only.
     *
     * @param vals - vector with override values. sequence of vals' elements must be the same as we get it from
     * get_all_params_data_members()
     */
    explicit Params(const std::vector<std::string>& vals);

    Params(const Params& obj) = default;
    Params& operator=(const Params& obj) = default;

    Params(Params&& obj) noexcept = default;
    Params& operator=(Params&& obj) noexcept = default;

    virtual ~Params() = default;

    /**
     * get_all_params_data_members() returns names of all data members of Params and the scheme enum ALWAYS goes first.
     * This function is meant for unittests only and holds the correct sequence of the parameters/column names.
     *
     * @return a vector with names of all data members of Params
     */
    static const std::vector<std::string> get_all_params_data_members() {
        return {"scheme",
                "ptModulus",
                "digitSize",
                "standardDeviation",
                "secretKeyDist",
                "maxRelinSkDeg",
                "ksTech",
                "scalTech",
                "firstModSize",
                "batchSize",
                "numLargeDigits",
                "multiplicativeDepth",
                "scalingModSize",
                "securityLevel",
                "ringDim",
                "evalAddCount",
                "keySwitchCount",
                "encryptionTechnique",
                "multiplicationTechnique",
                "PRENumHops",
                "PREMode",
                "multipartyMode",
                "executionMode",
                "decryptionNoiseMode",
                "noiseEstimate",
                "desiredPrecision",
                "statisticalSecurity",
                "numAdversarialQueries",
                "thresholdNumOfParties",
                "interactiveBootCompressionLevel",
                "compositeDegree",
                "registerWordSize",
                "ckksDataType"};
    }

    // getters
    SCHEME get_scheme() const {
        return scheme;
    }
    PlaintextModulus get_plaintext_modulus() const {
        return pt_modulus;
    }
    uint32_t get_digit_size() const {
        return digit_size;
    }
    float get_standard_deviation() const {
        return standard_deviation;
    }
    SecretKeyDist get_secret_key_dist() const {
        return secret_key_dist;
    }
    uint32_t get_max_relin_sk_deg() const {
        return max_relin_sk_deg;
    }
    ProxyReEncryptionMode get_pre_mode() const {
        return pre_mode;
    }
    MultipartyMode get_multiparty_mode() const {
        return multiparty_mode;
    }
    ExecutionMode get_execution_mode() const {
        return execution_mode;
    }
    DecryptionNoiseMode get_decryption_noise_mode() const {
        return decryption_noise_mode;
    }
    double get_noise_estimate() const {
        return noise_estimate;
    }
    double get_desired_precision() const {
        return desired_precision;
    }
    double get_statistical_security() const {
        return statistical_security;
    }
    double get_num_adversarial_queries() const {
        return num_adversarial_queries;
    }
    uint32_t get_threshold_num_of_parties() const {
        return threshold_num_of_parties;
    }
    KeySwitchTechnique get_key_switch_technique() const {
        return ks_tech;
    }
    ScalingTechnique get_scaling_technique() const {
        return scal_tech;
    }
    uint32_t get_batch_size() const {
        return batch_size;
    }
    uint32_t get_first_mod_size() const {
        return first_mod_size_value;
    }
    uint32_t get_num_large_digits() const {
        return num_large_digits;
    }
    uint32_t get_multiplicative_depth() const {
        return multiplicative_depth;
    }
    uint32_t get_scaling_mod_size() const {
        return scaling_mod_size;
    }
    SecurityLevel get_security_level() const {
        return security_level;
    }
    uint32_t get_ring_dim() const {
        return ring_dim;
    }
    uint32_t get_eval_add_count() const {
        return eval_add_count;
    }
    uint32_t get_key_switch_count() const {
        return key_switch_count;
    }
    EncryptionTechnique get_encryption_technique() const {
        return encryption_technique;
    }
    MultiplicationTechnique get_multiplication_technique() const {
        return multiplication_technique;
    }
    uint32_t get_pre_num_hops() const {
        return pre_num_hops;
    }
    CompressionLevel get_interactive_boot_compression_level() const {
        return interactive_boot_compression_level;
    }
    uint32_t get_composite_degree() const {
        return composite_degree;
    }
    uint32_t get_register_word_size() const {
        return register_word_size;
    }
    CkksDataType get_ckks_data_type() const {
        return ckks_data_type;
    }

    // setters
    // They all must be virtual, so any of them can be disabled in the derived class
    virtual void set_plaintext_modulus(PlaintextModulus pt_modulus0) {
        pt_modulus = pt_modulus0;
    }
    virtual void set_digit_size(uint32_t digit_size0) {
        digit_size = digit_size0;
    }
    virtual void set_standard_deviation(float standard_deviation0) {
        standard_deviation = standard_deviation0;
    }
    virtual void set_secret_key_dist(SecretKeyDist secret_key_dist0) {
        secret_key_dist = secret_key_dist0;
    }
    virtual void set_max_relin_sk_deg(uint32_t max_relin_sk_deg0) {
        max_relin_sk_deg = max_relin_sk_deg0;
    }
    virtual void set_pre_mode(ProxyReEncryptionMode pre_mode0) {
        pre_mode = pre_mode0;
    }
    virtual void set_multiparty_mode(MultipartyMode multiparty_mode0) {
        multiparty_mode = multiparty_mode0;
    }
    virtual void set_execution_mode(ExecutionMode execution_mode0) {
        execution_mode = execution_mode0;
    }
    virtual void set_decryption_noise_mode(DecryptionNoiseMode decryption_noise_mode0) {
        decryption_noise_mode = decryption_noise_mode0;
    }
    virtual void set_noise_estimate(double noise_estimate0) {
        noise_estimate = noise_estimate0;
    }
    virtual void set_desired_precision(double desired_precision0) {
        desired_precision = desired_precision0;
    }
    virtual void set_statistical_security(uint32_t statistical_security0) {
        statistical_security = statistical_security0;
    }
    virtual void set_num_adversarial_queries(uint32_t num_adversarial_queries0) {
        num_adversarial_queries = num_adversarial_queries0;
    }
    virtual void set_threshold_num_of_parties(uint32_t threshold_num_of_parties0) {
        threshold_num_of_parties = threshold_num_of_parties0;
    }
    virtual void set_key_switch_technique(KeySwitchTechnique ks_tech0) {
        ks_tech = ks_tech0;
    }
    virtual void set_scaling_technique(ScalingTechnique scal_tech0) {
        scal_tech = scal_tech0;
    }
    virtual void set_batch_size(uint32_t batch_size0) {
        batch_size = batch_size0;
    }
    virtual void set_first_mod_size(uint32_t first_mod_size0) {
        first_mod_size_value = first_mod_size0;
    }
    virtual void set_num_large_digits(uint32_t num_large_digits0) {
        num_large_digits = num_large_digits0;
    }
    virtual void set_multiplicative_depth(uint32_t multiplicative_depth0) {
        multiplicative_depth = multiplicative_depth0;
    }
    virtual void set_scaling_mod_size(uint32_t scaling_mod_size0) {
        scaling_mod_size = scaling_mod_size0;
    }
    virtual void set_security_level(SecurityLevel security_level0) {
        security_level = security_level0;
    }
    virtual void set_ring_dim(uint32_t ring_dim0) {
        ring_dim = ring_dim0;
    }
    virtual void set_eval_add_count(uint32_t eval_add_count0) {
        eval_add_count = eval_add_count0;
    }
    virtual void set_key_switch_count(uint32_t key_switch_count0) {
        key_switch_count = key_switch_count0;
    }
    virtual void set_encryption_technique(EncryptionTechnique encryption_technique0) {
        encryption_technique = encryption_technique0;
    }
    virtual void set_multiplication_technique(MultiplicationTechnique multiplication_technique0) {
        multiplication_technique = multiplication_technique0;
    }
    virtual void set_pre_num_hops(uint32_t pre_num_hops0) {
        pre_num_hops = pre_num_hops0;
    }
    virtual void set_interactive_boot_compression_level(CompressionLevel interactive_boot_compression_level0) {
        interactive_boot_compression_level = interactive_boot_compression_level0;
    }
    virtual void set_composite_degree(uint32_t composite_degree0) {
        composite_degree = composite_degree0;
    }
    virtual void set_register_word_size(uint32_t register_word_size0) {
        register_word_size = register_word_size0;
    }
    virtual void set_ckks_data_type(CkksDataType ckks_data_type0) {
        ckks_data_type = ckks_data_type0;
    }

    /**
     * Prints all parameters as "name: value" pairs separated by semicolons.
     *
     * @param os the output stream.
     * @param obj the parameters to print.
     * @return the output stream.
     */
    friend std::ostream& operator<<(std::ostream& os, const Params& obj);
};
// ====================================================================================================================

}  // namespace cipher

#endif  // CIPHER_FHE_CONFIG_PARAMS_H_
