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
  ring-learn-with-errors functionality
 */

#ifndef CIPHER_FHE_BASE_RLWE_PARAMS_H_
#define CIPHER_FHE_BASE_RLWE_PARAMS_H_

#include <cstdint>
#include <memory>
#include <string>

#include "cipher/fhe/constants.h"
#include "cipher/ring/ring_constants.h"
#include "cipher/ring/backend.h"
#include "cipher/fhe/base/crypto_params.h"

// TODO - temp include for the SecurityLevel
#include "cipher/ring/standard_params.h"

namespace cipher {

/**
 * @brief Template for crypto parameters.
 * @tparam Element a ring element.
 */
template <class Element>
class RlweCryptoParams : public BaseCryptoParams<Element> {
  public:
    /**
     * Default Constructor
     */
    RlweCryptoParams() = default;

    /**
     * Copy constructor.
     * @param rhs the parameters to copy from
     */
    RlweCryptoParams(const RlweCryptoParams& rhs)
        : BaseCryptoParams<Element>(rhs.get_element_params(), rhs.get_plaintext_modulus()) {
        distribution_parameter_ = rhs.distribution_parameter_;
        assurance_measure_ = rhs.assurance_measure_;
        noise_scale_ = rhs.noise_scale_;
        digit_size_ = rhs.digit_size_;
        noise_estimate_ = rhs.noise_estimate_;
        multiplicative_depth_ = rhs.multiplicative_depth_;
        eval_add_count_ = rhs.eval_add_count_;
        key_switch_count_ = rhs.key_switch_count_;
        pre_num_hops_ = rhs.pre_num_hops_;
        max_relin_sk_deg_ = rhs.max_relin_sk_deg_;
        secret_key_dist_ = rhs.secret_key_dist_;
        std_level_ = rhs.std_level_;
        flooding_distribution_parameter_ = rhs.flooding_distribution_parameter_;
        dgg_.set_std(distribution_parameter_);
        dgg_flooding_.set_std(flooding_distribution_parameter_);
        pre_mode_ = rhs.pre_mode_;
        multiparty_mode_ = rhs.multiparty_mode_;
        execution_mode_ = rhs.execution_mode_;
        decryption_noise_mode_ = rhs.decryption_noise_mode_;
        statistical_security_ = rhs.statistical_security_;
        num_adversarial_queries_ = rhs.num_adversarial_queries_;
        threshold_num_of_parties_ = rhs.threshold_num_of_parties_;
    }

    /**
     * Constructor that initializes values - uses HomomorphicEncryption.org
     * standard security levels
     *
     * @param params element parameters.
     * @param encoding_params encoding-specific parameters
     * @param distribution_parameter noise distribution parameter.
     * @param assurance_measure assurance level.
     * @param std_level security level.
     * @param digit_size the size of the digit size.
     * @param max_relin_sk_deg the maximum power of secret key for which the
     * relinearization key is generated
     * @param secret_key_dist mode for secret polynomial, defaults to GAUSSIAN.
     * @param pre_mode security mode for proxy re-encryption
     * @param multiparty_mode security mode for multiparty decryption
     * @param execution_mode execution mode for CKKS noise flooding
     * @param decryption_noise_mode decryption noise mode for CKKS noise flooding
     * @param noise_scale_value used in HRA-secure PRE
     * @param statistical_security statistical security parameter for CKKS noise flooding and PRE
     * @param num_adversarial_queries number of adversarial queries for CKKS noise flooding and PRE
     * @param threshold_num_of_parties number of parties in threshold FHE
     */
    RlweCryptoParams(std::shared_ptr<typename Element::Params> params, EncodingParams encoding_params,
                         float distribution_parameter, float assurance_measure, SecurityLevel std_level,
                         uint32_t digit_size, int max_relin_sk_deg = 2, SecretKeyDist secret_key_dist = GAUSSIAN,
                         ProxyReEncryptionMode pre_mode = INDCPA, MultipartyMode multiparty_mode = FIXED_NOISE_MULTIPARTY,
                         ExecutionMode execution_mode = EXEC_EVALUATION,
                         DecryptionNoiseMode decryption_noise_mode = FIXED_NOISE_DECRYPT, PlaintextModulus noise_scale_value = 1,
                         uint32_t statistical_security = 30, uint32_t num_adversarial_queries = 1,
                         uint32_t threshold_num_of_parties = 1)
        : BaseCryptoParams<Element>(params, encoding_params) {
        distribution_parameter_ = distribution_parameter;
        assurance_measure_ = assurance_measure;
        noise_scale_ = noise_scale_value;
        digit_size_ = digit_size;
        dgg_.set_std(distribution_parameter_);
        max_relin_sk_deg_ = max_relin_sk_deg;
        secret_key_dist_ = secret_key_dist;
        std_level_ = std_level;
        pre_mode_ = pre_mode;
        multiparty_mode_ = multiparty_mode;
        execution_mode_ = execution_mode;
        decryption_noise_mode_ = decryption_noise_mode;
        statistical_security_ = statistical_security;
        num_adversarial_queries_ = num_adversarial_queries;
        threshold_num_of_parties_ = threshold_num_of_parties;
    }

    /**
     * Virtual Destructor
     */
    ~RlweCryptoParams() override = default;

    /**
     * Returns the value of standard deviation r for discrete Gaussian
     * distribution
     *
     * @return the standard deviation r.
     */
    float get_distribution_parameter() const {
        return distribution_parameter_;
    }

    /**
     * Returns the value of standard deviation r for discrete Gaussian
     * distribution with flooding
     *
     * @return the flooding standard deviation r.
     */
    double get_flooding_distribution_parameter() const {
        return flooding_distribution_parameter_;
    }

    /**
     * Returns the values of assurance measure alpha
     *
     * @return the assurance measure.
     */
    float get_assurance_measure() const {
        return assurance_measure_;
    }

    /**
     * Returns the value of noise scale.
     *
     * @return the noise scale.
     */
    PlaintextModulus get_noise_scale() const {
        return noise_scale_;
    }

    /**
     * Returns the value of digit size.
     *
     * @return the digit size.
     */
    uint32_t get_digit_size() const override {
        return digit_size_;
    }

    virtual double get_noise_estimate() const {
        return noise_estimate_;
    }
    virtual uint32_t get_multiplicative_depth() const {
        return multiplicative_depth_;
    }
    virtual uint32_t get_eval_add_count() const {
        return eval_add_count_;
    }
    virtual uint32_t get_key_switch_count() const {
        return key_switch_count_;
    }
    virtual uint32_t get_pre_num_hops() const {
        return pre_num_hops_;
    }

    /**
     * Returns the value of the maximum power of secret key for which the
     * relinearization key is generated
     *
     * @return maximum power of secret key
     */
    uint32_t get_max_relin_sk_deg() const override {
        return max_relin_sk_deg_;
    }

    /**
     * Gets the secret_key_dist setting: GAUSSIAN or UNIFORM_TERNARY
     *
     * @return the secret_key_dist setting.
     */
    SecretKeyDist get_secret_key_dist() const {
        return secret_key_dist_;
    }

    /**
     * Gets the pre security mode setting:
     * INDCPA, FIXED_NOISE_HRA, NOISE_FLOODING_HRA or MODULUS_SWITCHING_HRA.
     *
     * @return the pre security mode setting.
     */
    ProxyReEncryptionMode get_pre_mode() const {
        return pre_mode_;
    }

    /**
     * Gets the multiparty security mode setting.
     *
     * @return the multiparty security mode setting.
     */
    MultipartyMode get_multiparty_mode() const {
        return multiparty_mode_;
    }

    /**
     * Gets the execution mode setting.
     *
     * @return the execution mode setting.
     */
    ExecutionMode get_execution_mode() const {
        return execution_mode_;
    }

    /**
     * Gets the decryption noise mode setting.
     *
     * @return the decryption noise mode setting.
     */
    DecryptionNoiseMode get_decryption_noise_mode() {
        return decryption_noise_mode_;
    }

    /**
     * Gets the standard security level
     *
     * @return the security level.
     */
    SecurityLevel get_std_level() const {
        return std_level_;
    }

    /**
     * Returns reference to Discrete Gaussian Generator
     *
     * @return reference to Discrete Gaussian Generator.
     */
    const typename Element::DggType& get_discrete_gaussian_generator() const {
        return dgg_;
    }

    /**
     * Returns reference to Discrete Gaussian Generator with flooding for PRE
     *
     * @return reference to Discrete Gaussian Generator with flooding for PRE.
     * The Std dev for this generator changes based on the PRE mode, so it is not const
     */
    typename Element::DggType& get_flooding_discrete_gaussian_generator() {
        return dgg_flooding_;
    }

    /**
     * Gets the statistical security level
     *
     * @return the statistical security level.
     */
    double get_statistical_security() const {
        return statistical_security_;
    }

    /**
     * Gets the number of adversarial queries
     *
     * @return the number of adversarial queries.
     */
    double get_num_adversarial_queries() const {
        return num_adversarial_queries_;
    }

    /**
     * Gets the threshold number of parties
     *
     * @return the threshold number of parties.
     */
    uint32_t get_threshold_num_of_parties() const {
        return threshold_num_of_parties_;
    }

    // @Set Properties

    /**
     * Sets the value of standard deviation r for discrete Gaussian distribution
     * @param distribution_parameter the standard deviation r
     */
    void set_distribution_parameter(float distribution_parameter) {
        distribution_parameter_ = distribution_parameter;
        dgg_.set_std(distribution_parameter_);
    }

    /**
     * Sets the value of flooding standard deviation r for discrete Gaussian distribution with flooding
     * @param distribution_parameter the flooding standard deviation r
     */
    void set_flooding_distribution_parameter(double distribution_parameter) {
        flooding_distribution_parameter_ = distribution_parameter;
        dgg_flooding_.set_std(flooding_distribution_parameter_);
    }

    /**
     * Sets the values of assurance measure alpha
     * @param assurance_measure the assurance measure
     */
    void set_assurance_measure(float assurance_measure) {
        assurance_measure_ = assurance_measure;
    }

    /**
     * Sets the standard security level
     * @param security_level the standard security level
     */
    void set_std_level(SecurityLevel security_level) {
        std_level_ = security_level;
    }

    /**
     * Sets the value of noise scale
     * @param noise_scale_value the noise scale used in HRA-secure PRE
     */
    void set_noise_scale(PlaintextModulus noise_scale_value) {
        noise_scale_ = noise_scale_value;
    }

    /**
     * Sets the value of digit size
     * @param digit_size the digit size
     */
    void set_digit_size(uint32_t digit_size) {
        digit_size_ = digit_size;
    }

    void set_noise_estimate(double noise_estimate) {
        noise_estimate_ = noise_estimate;
    }
    void set_multiplicative_depth(uint32_t multiplicative_depth) {
        multiplicative_depth_ = multiplicative_depth;
    }
    void set_eval_add_count(uint32_t eval_add_count) {
        eval_add_count_ = eval_add_count;
    }
    void set_key_switch_count(uint32_t key_switch_count) {
        key_switch_count_ = key_switch_count;
    }
    void set_pre_num_hops(uint32_t pre_num_hops) {
        pre_num_hops_ = pre_num_hops;
    }

    /**
     * Sets the value of the maximum power of secret key for which the
     * relinearization key is generated
     * @param max_relin_sk_deg the maximum power of secret key
     */
    void set_max_relin_sk_deg(uint32_t max_relin_sk_deg) {
        max_relin_sk_deg_ = max_relin_sk_deg;
    }

    /**
     * Configures the secret_key_dist for generating the secret key polynomial
     * @param secret_key_dist is GAUSSIAN or UNIFORM_TERNARY
     */
    void set_secret_key_dist(SecretKeyDist secret_key_dist) {
        secret_key_dist_ = secret_key_dist;
    }

    /**
     * Configures the security mode for pre
     * @param pre_mode is INDCPA, FIXED_NOISE_HRA, NOISE_FLOODING_HRA or MODULUS_SWITCHING_HRA.
     */
    void set_pre_mode(ProxyReEncryptionMode pre_mode) {
        pre_mode_ = pre_mode;
    }

    /**
     * Configures the security mode for multiparty
     * @param multiparty_mode Security mode for multiparty decryption.
     */
    void set_multiparty_mode(MultipartyMode multiparty_mode) {
        multiparty_mode_ = multiparty_mode;
    }

    /**
     * Configures the execution for CKKS noise flooding
     * @param execution_mode Execution mode.
     */
    void set_execution_mode(ExecutionMode execution_mode) {
        execution_mode_ = execution_mode;
    }

    /**
     * Configures the decryption noise mode for CKKS noise flooding
     * @param decryption_noise_mode Decryption noise mode.
     */
    void set_decryption_noise_mode(DecryptionNoiseMode decryption_noise_mode) {
        decryption_noise_mode_ = decryption_noise_mode;
    }

    /**
     * Configures the statistical security parameter for CKKS noise flooding and PRE
     * @param statistical_security the statistical security parameter
     */
    void set_statistical_security(uint32_t statistical_security) {
        statistical_security_ = statistical_security;
    }

    /**
     * Configures the number of adversarial queries for CKKS noise flooding and PRE
     * @param num_adversarial_queries the number of adversarial queries
     */
    void set_num_adversarial_queries(uint32_t num_adversarial_queries) {
        num_adversarial_queries_ = num_adversarial_queries;
    }

    /**
     * Configures the number of parties in threshold FHE
     * @param threshold_num_of_parties the number of parties
     */
    void set_threshold_num_of_parties(uint32_t threshold_num_of_parties) {
        threshold_num_of_parties_ = threshold_num_of_parties;
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::base_class<BaseCryptoParams<Element>>(this));
        ar(::cereal::make_nvp("dp", distribution_parameter_));
        ar(::cereal::make_nvp("am", assurance_measure_));
        ar(::cereal::make_nvp("ns", noise_scale_));
        ar(::cereal::make_nvp("rw", digit_size_));
        ar(::cereal::make_nvp("nest", noise_estimate_));
        ar(::cereal::make_nvp("muld", multiplicative_depth_));
        ar(::cereal::make_nvp("addc", eval_add_count_));
        ar(::cereal::make_nvp("kswc", key_switch_count_));
        ar(::cereal::make_nvp("phops", pre_num_hops_));
        ar(::cereal::make_nvp("md", max_relin_sk_deg_));
        ar(::cereal::make_nvp("mo", secret_key_dist_));
        ar(::cereal::make_nvp("pmo", pre_mode_));
        ar(::cereal::make_nvp("mmo", multiparty_mode_));
        ar(::cereal::make_nvp("exm", execution_mode_));
        ar(::cereal::make_nvp("dnm", decryption_noise_mode_));
        ar(::cereal::make_nvp("slv", std_level_));
        ar(::cereal::make_nvp("fdp", flooding_distribution_parameter_));
        ar(::cereal::make_nvp("ss", statistical_security_));
        ar(::cereal::make_nvp("aq", num_adversarial_queries_));
        ar(::cereal::make_nvp("tp", threshold_num_of_parties_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        ar(::cereal::base_class<BaseCryptoParams<Element>>(this));
        ar(::cereal::make_nvp("dp", distribution_parameter_));
        ar(::cereal::make_nvp("am", assurance_measure_));
        ar(::cereal::make_nvp("ns", noise_scale_));
        ar(::cereal::make_nvp("rw", digit_size_));
        ar(::cereal::make_nvp("nest", noise_estimate_));
        ar(::cereal::make_nvp("muld", multiplicative_depth_));
        ar(::cereal::make_nvp("addc", eval_add_count_));
        ar(::cereal::make_nvp("kswc", key_switch_count_));
        ar(::cereal::make_nvp("phops", pre_num_hops_));
        ar(::cereal::make_nvp("md", max_relin_sk_deg_));
        ar(::cereal::make_nvp("mo", secret_key_dist_));
        ar(::cereal::make_nvp("pmo", pre_mode_));
        ar(::cereal::make_nvp("mmo", multiparty_mode_));
        ar(::cereal::make_nvp("exm", execution_mode_));
        ar(::cereal::make_nvp("dnm", decryption_noise_mode_));
        ar(::cereal::make_nvp("slv", std_level_));
        ar(::cereal::make_nvp("fdp", flooding_distribution_parameter_));
        ar(::cereal::make_nvp("ss", statistical_security_));
        ar(::cereal::make_nvp("aq", num_adversarial_queries_));
        ar(::cereal::make_nvp("tp", threshold_num_of_parties_));

        dgg_.set_std(distribution_parameter_);
        dgg_flooding_.set_std(flooding_distribution_parameter_);
    }

    std::string serialized_object_name() const override {
        return "CryptoParametersRLWE";
    }

  protected:
    /// standard deviation in Discrete Gaussian Distribution
    float distribution_parameter_ = 0;
    /// standard deviation in Discrete Gaussian Distribution with Flooding
    double flooding_distribution_parameter_ = 0;
    /// assurance measure alpha
    float assurance_measure_ = 0;
    /// noise scale
    PlaintextModulus noise_scale_ = 1;
    /// digit size
    uint32_t digit_size_ = 1;

    /// log2 of the noise estimate used to set the flooding noise in the NOISE_FLOODING_DECRYPT mode of CKKS
    double noise_estimate_{0};
    /// multiplicative depth the parameters were generated for
    uint32_t multiplicative_depth_{1};
    /// number of additions assumed in parameter generation
    uint32_t eval_add_count_{0};
    /// number of key switching operations assumed in parameter generation
    uint32_t key_switch_count_{0};
    /// number of re-encryption hops supported in the HRA-secure mode of PRE
    uint32_t pre_num_hops_{0};

    /// the highest power of secret key for which relinearization key is generated
    uint32_t max_relin_sk_deg_ = 2;
    /// specifies whether the secret polynomials are generated from discrete
    /// Gaussian distribution or ternary distribution with the norm of unity
    SecretKeyDist secret_key_dist_ = GAUSSIAN;
    /// Security level according in the HomomorphicEncryption.org standard
    SecurityLevel std_level_ = HEStd_NotSet;

    /// dgg_ gets the same default value as distribution_parameter_ does
    typename Element::DggType dgg_ = typename Element::DggType(0);
    /// dgg_flooding_ gets the same default value as flooding_distribution_parameter_ does
    typename Element::DggType dgg_flooding_ = typename Element::DggType(0);

    /// specifies the security mode used for PRE
    ProxyReEncryptionMode pre_mode_ = NOT_SET;

    /// specifies the security mode used for multiparty decryption
    MultipartyMode multiparty_mode_ = FIXED_NOISE_MULTIPARTY;

    /// specifies the execution mode used for NOISE_FLOODING_DECRYPT mode in CKKS
    ExecutionMode execution_mode_ = EXEC_EVALUATION;

    /// specifies the noise mode used for decryption in CKKS
    DecryptionNoiseMode decryption_noise_mode_ = FIXED_NOISE_DECRYPT;

    /// Statistical security of CKKS in NOISE_FLOODING_DECRYPT mode. This is the bound on the probability of success
    /// that any adversary can have. Specifically, they a probability of success of at most 2^(-statistical_security).
    double statistical_security_ = 30;

    /// This is the number of adversarial queries a user is expecting for their application, which we use to ensure
    /// security of CKKS in NOISE_FLOODING_DECRYPT mode.
    double num_adversarial_queries_ = 1;

    /// number of parties in threshold FHE
    uint32_t threshold_num_of_parties_ = 1;

    /**
     * @brief compare_to() is a method to compare two RlweCryptoParams objects.
     *        It is called by BaseCryptoParams::operator==()
     * @param rhs - the other RlweCryptoParams object to compare to.
     * @return whether the two RlweCryptoParams objects are equivalent.
     */
    bool compare_to(const BaseCryptoParams<Element>& rhs) const override {
        auto el = dynamic_cast<const RlweCryptoParams*>(&rhs);
        if (!el)
            return false;

        return BaseCryptoParams<Element>::compare_to(rhs) &&
               distribution_parameter_ == el->distribution_parameter_ && assurance_measure_ == el->assurance_measure_ &&
               noise_scale_ == el->noise_scale_ && digit_size_ == el->digit_size_ &&
               noise_estimate_ == el->noise_estimate_ && multiplicative_depth_ == el->multiplicative_depth_ &&
               eval_add_count_ == el->eval_add_count_ && key_switch_count_ == el->key_switch_count_ &&
               pre_num_hops_ == el->pre_num_hops_ && secret_key_dist_ == el->secret_key_dist_ &&
               std_level_ == el->std_level_ && max_relin_sk_deg_ == el->max_relin_sk_deg_ && pre_mode_ == el->pre_mode_ &&
               multiparty_mode_ == el->multiparty_mode_ && execution_mode_ == el->execution_mode_ &&
               flooding_distribution_parameter_ == el->flooding_distribution_parameter_ &&
               statistical_security_ == el->statistical_security_ &&
               num_adversarial_queries_ == el->num_adversarial_queries_ &&
               threshold_num_of_parties_ == el->threshold_num_of_parties_;
    }

    /**
     * Prints the base-class parameters followed by the RLWE parameters (distribution parameter,
     * assurance measure, noise scale, digit size, secret key distribution and security level).
     *
     * @param os the stream to print to.
     */
    void print_parameters(std::ostream& os) const override {
        BaseCryptoParams<Element>::print_parameters(os);

        os << "Distrib parm " << distribution_parameter_ << ", Assurance measure " << assurance_measure_
           << ", Noise scale " << noise_scale_ << ", Digit Size " << digit_size_ << ", SecretKeyDist "
           << secret_key_dist_ << ", Standard security level " << std_level_ << std::endl;
    }
};

}  // namespace cipher

#endif  // CIPHER_FHE_BASE_RLWE_PARAMS_H_
