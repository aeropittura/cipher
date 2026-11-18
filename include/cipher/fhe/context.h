//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2025, NJIT, Duality Technologies Inc. and other contributors
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
  Control for encryption operations
 */

#ifndef CIPHER_FHE_CONTEXT_H_
#define CIPHER_FHE_CONTEXT_H_

#include <algorithm>
#include <complex>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include "cipher/boolean/context.h"
#include "cipher/fhe/ciphertext.h"
#include "cipher/fhe/context_fwd.h"
#include "cipher/fhe/context_factory.h"
#include "cipher/fhe/encoding/plaintext_factory.h"
#include "cipher/fhe/key/eval_key.h"
#include "cipher/fhe/key/key_pair.h"
#include "cipher/fhe/config/switching_params.h"
#include "cipher/fhe/base/pke.h"
#include "cipher/fhe/base/scheme.h"
#include "cipher/fhe/rns/crypto_params.h"
#include "cipher/util/caller_info.h"
#include "cipher/util/diagnostic_output.h"
#include "cipher/util/type_name.h"

#ifdef DEBUG_KEY
    #include <iostream>
#endif

namespace cipher {

/**
 * @class CryptoContextImpl
 * @brief A class to simplify access to Cipher's PKE functionality.
 *
 * Functionality is accessed by creating an instance of CryptoContextImpl.
 * Various objects are "created" in the instance, but they can only be used with the context in which they were created.
 *
 * Cipher methods are accessed through CryptoContextImpl methods. Guards are implemented to make certain that
 * only valid objects that have been created in the context are used
 *
 * Contexts are created using make_crypto_context(), and can be serialized and recovered from serialization
 */
template <typename Element>
class CryptoContextImpl : public Serializable {
    using IntType = typename Element::Integer;
    using ParmType = typename Element::Params;

    /**
     * @brief Checks if the cryptocontext scheme is CKKS and throws an exception if it is not.
     *
     * @param function_name the calling function name. __func__ can be used instead
     */
    inline void verify_ckks_scheme(const std::string& function_name) const {
        if (!is_ckks(scheme_id_)) {
            std::string err_msg = std::string(function_name) +
                                 "() is available for the CKKS scheme only."
                                 " The current scheme is " +
                                 convert_to_string_impl(scheme_id_);
            CIPHER_THROW(err_msg);
        }
    }

    /**
     * @brief verify_ckks_real_data_type Checks if the CKKS data type is real and throws an exception if it is not.
     *
     * @param function_name the calling function name. __func__ can be used instead
     */
    inline void verify_ckks_real_data_type(const std::string& function_name) const {
        if (get_ckks_data_type() != REAL) {
            std::string err_msg =
                    "Function " + std::string(function_name) + " is available for the real CKKS data types only.";
            CIPHER_THROW(err_msg);
        }
    }

    void set_ks_technique_in_scheme();

    const CryptoContext<Element> get_context_for_pointer(const CryptoContextImpl<Element>* cc) const {
        const auto& contexts = ContextFactory<Element>::get_all_contexts();
        for (const auto& ctx : contexts) {
            if (cc == ctx.get())
                return ctx;
        }
        CIPHER_THROW("Cannot find context for the given pointer to CryptoContextImpl");
    }

    /**
     * @brief Constructs CoefPackedEncoding or PackedEncoding in this context
     *
     * @param encoding encoding type
     * @param value the value to encode
     * @param depth the multiplicative depth to encode the plaintext at
     * @param level the level to encode the plaintext at
     * @return new plaintext
     */
    Plaintext make_plaintext(const PlaintextEncodings encoding, const std::vector<int64_t>& value, size_t depth,
                            uint32_t level) const {
        const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(params_);
        if (!crypto_params)
            CIPHER_THROW("Invalid crypto parameters: expected CryptoParametersRNS");

        if (level > 0) {
            size_t num_moduli = crypto_params->get_element_params()->get_params().size();
            if (!is_bfvrns(scheme_id_)) {
                // we throw an exception if level >= num_moduli. However, we use multiplicative_depth in the error message,
                // so the user can understand the error more easily.
                if (level >= num_moduli) {
                    uint32_t multiplicative_depth = (crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT) ?
                                                           (num_moduli - 2) :
                                                           (num_moduli - 1);
                    std::string error_msg{"The level value should be less than or equal to "};
                    error_msg +=
                            ((crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT) ? "(multiplicativeDepth + 1)." :
                                                                                        "multiplicativeDepth.");
                    error_msg += " Currently: level is [" + std::to_string(level) + "] and multiplicativeDepth is [" +
                                std::to_string(multiplicative_depth) + "]";
                    CIPHER_THROW(error_msg);
                }
            } else {
                if ((crypto_params->get_multiplication_technique() == BEHZ) ||
                    (crypto_params->get_multiplication_technique() == HPS)) {
                    CIPHER_THROW(
                            "BFV: Encoding at level > 0 is not currently supported for BEHZ or HPS. Use one of the HPSPOVERQ* methods instead.");
                }

                if ((crypto_params->get_encryption_technique() == EXTENDED)) {
                    CIPHER_THROW(
                            "BFV: Encoding at level > 0 is not currently supported for the EXTENDED encryption method. Use the STANDARD encryption method instead.");
                }
                if (level >= num_moduli) {
                    std::string error_msg =
                            "The level value should be less the current number of RNS limbs in the cryptocontext.";
                    error_msg += " Currently: level is [" + std::to_string(level) + "] and number of RNS limbs is [" +
                                std::to_string(num_moduli) + "]";
                    CIPHER_THROW(error_msg);
                }
            }
        }

        // uses a parameter set with a reduced number of RNS limbs corresponding to the level
        std::shared_ptr<RnsParams<RnsPoly::Integer>> elem_params_ptr;
        if (level != 0) {
            RnsParams<RnsPoly::Integer> elem_params = *(crypto_params->get_element_params());
            for (uint32_t i = 0; i < level; i++) {
                elem_params.pop_last_param();
            }
            elem_params_ptr = std::make_shared<RnsParams<RnsPoly::Integer>>(elem_params);
        } else {
            elem_params_ptr = crypto_params->get_element_params();
        }

        NativeInteger scf{1};
        bool set_noise_scale_deg_value = false;
        auto scale_tech = crypto_params->get_scaling_technique();
        if (is_bgvrns(scheme_id_) && (scale_tech == FLEXIBLEAUTO || scale_tech == FLEXIBLEAUTOEXT)) {
            if (scale_tech == FLEXIBLEAUTOEXT && level == 0) {
                scf = crypto_params->get_scaling_factor_int_big(level);
                depth = 1;
                set_noise_scale_deg_value = true;
            } else
                scf = crypto_params->get_scaling_factor_int(level);
        }

        Plaintext p = PlaintextFactory::make_plaintext(value, encoding, elem_params_ptr, this->get_encoding_params(),
                                                      get_scheme_id_impl(), depth, level, scf);
        if (set_noise_scale_deg_value)
            p->set_noise_scale_deg(2);

        return p;
    }

    /**
     * @brief Constructs CoefPackedEncoding, PackedEncoding in this context
     *
     * @param encoding encoding type
     * @param cc the context to create a plaintext with
     * @param value the value to encode
     * @return new plaintext
     */
    template <typename Value1>
    static Plaintext make_plaintext(PlaintextEncodings encoding, CryptoContext<Element> cc, const Value1& value) {
        return PlaintextFactory::make_plaintext(value, encoding, cc->get_element_params(), cc->get_encoding_params());
    }

    template <typename Value1, typename Value2>
    static Plaintext make_plaintext(PlaintextEncodings encoding, CryptoContext<Element> cc, const Value1& value,
                                   const Value2& value2) {
        return PlaintextFactory::make_plaintext(encoding, cc->get_element_params(), cc->get_encoding_params(), value,
                                               value2);
    }

    /**
     * @brief Gets automorphism keys for a specific secret key tag and an array of specific indices
     *
     * @param key_tag secret key tag
     * @param index_list array of specific indices to retrieve key for
     * @return shared_ptr to std::map where the map key/data pair is index/automorphism key
     */
    static std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> get_partial_eval_automorphism_key_map_ptr(
            const std::string& key_tag, const std::vector<uint32_t>& index_list);

    // cached evalmult keys, by secret key UID
    static std::map<std::string, std::vector<EvalKey<Element>>> eval_mult_key_map_;
    // cached evalautomorphism keys, by secret key UID
    static std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>> eval_automorphism_key_map_;

  protected:
    /// crypto parameters
    std::shared_ptr<BaseCryptoParams<Element>> params_{nullptr};
    /// algorithm used; accesses all crypto methods
    std::shared_ptr<SchemeBase<Element>> scheme_{nullptr};

    SCHEME scheme_id_{SCHEME::INVALID_SCHEME};  ///< identifier of the scheme this crypto context implements

    uint32_t key_gen_level_{0};  ///< level at which evaluation keys should be generated (for future use)

    /**
     * @brief type_check makes sure that an operation between two ciphertexts is permitted
     *
     * @param a ciphertext1
     * @param b ciphertext2
     */
    void type_check(ConstCiphertext<Element>& a, ConstCiphertext<Element>& b, CALLER_INFO_ARGS_HDR) const {
        if (a == nullptr || b == nullptr) {
            std::string error_msg(std::string("Null Ciphertext") + CALLER_INFO);
            CIPHER_THROW(error_msg);
        }
        if (a->get_crypto_context().get() != this) {
            std::string error_msg(std::string("Ciphertext was not created in this CryptoContext") + CALLER_INFO);
            CIPHER_THROW(error_msg);
        }
        if (a->get_crypto_context() != b->get_crypto_context()) {
            std::string error_msg(std::string("Ciphertexts were not created in the same CryptoContext") + CALLER_INFO);
            CIPHER_THROW(error_msg);
        }
        if (a->get_key_tag() != b->get_key_tag()) {
            std::string error_msg(std::string("Ciphertexts were not encrypted with same keys") + CALLER_INFO);
            CIPHER_THROW(error_msg);
        }
        if (a->get_encoding_type() != b->get_encoding_type()) {
            std::stringstream ss;
            ss << "Ciphertext encoding types " << a->get_encoding_type();
            ss << " and " << b->get_encoding_type();
            ss << " do not match";
            ss << CALLER_INFO;
            CIPHER_THROW(ss.str());
        }
    }

    /**
     * @brief type_check makes sure that an operation between a ciphertext and a plaintext is permitted
     *
     * @param a ciphertext
     * @param b plaintext
     */
    void type_check(ConstCiphertext<Element>& a, ConstPlaintext& b, CALLER_INFO_ARGS_HDR) const {
        if (a == nullptr) {
            std::string error_msg(std::string("Null Ciphertext") + CALLER_INFO);
            CIPHER_THROW(error_msg);
        }
        if (b == nullptr) {
            std::string error_msg(std::string("Null Plaintext") + CALLER_INFO);
            CIPHER_THROW(error_msg);
        }
        if (a->get_crypto_context().get() != this) {
            std::string error_msg(std::string("Ciphertext was not created in this CryptoContext") + CALLER_INFO);
            CIPHER_THROW(error_msg);
        }
        if (a->get_encoding_type() != b->get_encoding_type()) {
            std::stringstream ss;
            ss << "Ciphertext encoding type " << a->get_encoding_type();
            ss << " and Plaintext encoding type " << b->get_encoding_type();
            ss << " do not match";
            ss << CALLER_INFO;
            CIPHER_THROW(ss.str());
        }
    }

    /**
     * @brief Checks whether a crypto context is a different object than this one.
     *
     * @param a the crypto context to compare with
     * @return true if a is not this crypto context
     */
    bool mismatched(const CryptoContext<Element> a) const {
        return a.get() != this;
    }

    /**
     * @brief Throws if a key is null or was not generated with this crypto context.
     *
     * @param key the key to validate (any key type with get_crypto_context())
     */
    template <typename T>
    void validate_key(const T& key, CALLER_INFO_ARGS_HDR) const {
        if (key == nullptr) {
            std::string error_msg(std::string("Key is nullptr") + CALLER_INFO);
            CIPHER_THROW(error_msg);
        }
        if (mismatched(key->get_crypto_context())) {
            std::string error_msg(std::string("Key was not generated with the same crypto context") + CALLER_INFO);
            CIPHER_THROW(error_msg);
        }
    }

    /**
     * @brief Throws if a ciphertext is null or was not generated with this crypto context.
     *
     * @param ciphertext the ciphertext to validate
     */
    void validate_ciphertext(ConstCiphertext<Element>& ciphertext, CALLER_INFO_ARGS_HDR) const {
        if (ciphertext == nullptr) {
            std::string error_msg(std::string("Ciphertext is nullptr") + CALLER_INFO);
            CIPHER_THROW(error_msg);
        }
        if (mismatched(ciphertext->get_crypto_context())) {
            std::string error_msg(std::string("Ciphertext was not generated with the same crypto context") +
                                 CALLER_INFO);
            CIPHER_THROW(error_msg);
        }
    }

    /**
     * @brief Throws if proxy re-encryption is disabled for this crypto context, i.e., HYBRID key switching is
     * used and the PRE mode is NOT_SET.
     */
    void validate_pre_mode(CALLER_INFO_ARGS_HDR) const {
        const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(params_);
        if (crypto_params == nullptr)
            CIPHER_THROW("Invalid crypto parameters: expected CryptoParametersRNS");
        if (crypto_params->get_key_switch_technique() == HYBRID && crypto_params->get_pre_mode() == NOT_SET)
            CIPHER_THROW(
                    "PRE is disabled (default = NOT_SET). Enable with SetPREMode() before generating cryptocontext.");
    }

    /**
     * @brief Throws if a precomputed set of powers is null, empty, or was not generated with this crypto context.
     *
     * @param powers the powers to validate
     */
    void validate_series_powers(std::shared_ptr<SeriesPowers<Element>> powers, CALLER_INFO_ARGS_HDR) const {
        if (powers == nullptr) {
            std::string error_msg(std::string("The object for powers is nullptr") + CALLER_INFO);
            CIPHER_THROW(error_msg);
        }
        if (powers->powers_re.size() == 0) {
            std::string error_msg(std::string("The powersRe member is empty") + CALLER_INFO);
            CIPHER_THROW(error_msg);
        }
        if (mismatched(powers->powers_re[0]->get_crypto_context())) {
            std::string error_msg(std::string("Power ciphertext was not generated with the same crypto context") +
                                 CALLER_INFO);
            CIPHER_THROW(error_msg);
        }
    }

    /**
     * @brief Creates and encodes a CKKS plaintext from complex values at a given level and noise scale degree,
     * validating the level against the modulus chain and choosing the element parameters (the towers remaining at
     * that level) and the scaling factor of the level when params is null.
     *
     * @param value the complex values to encode
     * @param noise_scale_deg noise scale degree of the plaintext
     * @param level level of the plaintext (must be below the number of RNS moduli)
     * @param params element parameters to encode with (null = derived from the level)
     * @param slots number of slots (0 = default)
     * @return the encoded plaintext
     */
    virtual Plaintext make_ckks_packed_plaintext_internal(const std::vector<std::complex<double>>& value,
                                                      size_t noise_scale_deg, uint32_t level,
                                                      const std::shared_ptr<ParmType> params, uint32_t slots) const {
        verify_ckks_scheme(__func__);
        const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(params_);
        if (!crypto_params)
            CIPHER_THROW("Invalid crypto parameters: expected CryptoParametersRNS");
        if (level > 0) {
            // validation of level: We need to compare it to multiplicative_depth, but multiplicative_depth is not
            // readily available. so, what we get is num_moduli and use it for calculations
            size_t num_moduli = crypto_params->get_element_params()->get_params().size();
            uint32_t multiplicative_depth =
                    (crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT) ? (num_moduli - 2) : (num_moduli - 1);
            // we throw an exception if level >= num_moduli. however, we use multiplicative_depth in the error message,
            // so the user can understand the error more easily.
            if (level >= num_moduli) {
                std::string error_msg;
                if (crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT)
                    error_msg = "The level value should be less than or equal to (multiplicativeDepth + 1).";
                else
                    error_msg = "The level value should be less than or equal to multiplicativeDepth.";

                error_msg += " Currently: level is [" + std::to_string(level) + "] and multiplicativeDepth is [" +
                            std::to_string(multiplicative_depth) + "]";
                CIPHER_THROW(error_msg);
            }
        }

        double sc_fact = 0;
        if (crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT && level == 0) {
            sc_fact = crypto_params->get_scaling_factor_real_big(level);
            // In FLEXIBLEAUTOEXT mode at level 0, we don't use the noise_scale_deg in our encoding function,
            // so we set it to 1 to make sure it has no effect on the encoding.
            noise_scale_deg = 1;
        } else {
            sc_fact = crypto_params->get_scaling_factor_real(level);
        }

        Plaintext p;
        if (params == nullptr) {
            std::shared_ptr<RnsParams<RnsPoly::Integer>> elem_params_ptr;
            if (level != 0) {
                RnsParams<RnsPoly::Integer> elem_params = *(crypto_params->get_element_params());
                for (uint32_t i = 0; i < level; i++) {
                    elem_params.pop_last_param();
                }
                elem_params_ptr = std::make_shared<RnsParams<RnsPoly::Integer>>(elem_params);
            } else {
                elem_params_ptr = crypto_params->get_element_params();
            }
            // Check if plaintext has got enough slots for data (value)
            uint32_t ring_dim = elem_params_ptr->get_ring_dimension();
            size_t value_size = value.size();
            if (value_size > ring_dim / 2) {
                CIPHER_THROW("The size [" + std::to_string(value_size) +
                              "] of the vector with values should not be greater than ringDim/2 [" +
                              std::to_string(ring_dim / 2) + "] if the scheme is CKKS");
            }
            // TODO (dsuponit): we should call a version of make_plaintext instead of calling Plaintext() directly here
            p = Plaintext(std::make_shared<CKKSPackedEncoding>(elem_params_ptr, this->get_encoding_params(), value,
                                                               noise_scale_deg, level, sc_fact, slots,
                                                               this->get_ckks_data_type()));
        } else {
            // Check if plaintext has got enough slots for data (value)
            uint32_t ring_dim = params->get_ring_dimension();
            size_t value_size = value.size();
            if (value_size > ring_dim / 2) {
                CIPHER_THROW("The size [" + std::to_string(value_size) +
                              "] of the vector with values should not be greater than ringDim/2 [" +
                              std::to_string(ring_dim / 2) + "] if the scheme is CKKS");
            }
            // TODO (dsuponit): we should call a version of make_plaintext instead of calling Plaintext() directly here
            p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, this->get_encoding_params(), value, noise_scale_deg,
                                                               level, sc_fact, slots, this->get_ckks_data_type()));
        }
        p->encode();

        // In FLEXIBLEAUTOEXT mode, a fresh plaintext at level 0 always has noise_scale_deg 2.
        if (crypto_params->get_scaling_technique() == FLEXIBLEAUTOEXT && level == 0) {
            p->set_noise_scale_deg(2);
        }
        return p;
    }

    /**
     * @brief Getter for composite degree of the current scheme crypto context.
     * @return integer value corresponding to composite degree
     */
    uint32_t get_composite_degree_from_ctxt() const {
        const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(params_);
        if (!crypto_params)
            CIPHER_THROW("Invalid crypto parameters: expected CryptoParametersRNS");

        return crypto_params->get_composite_degree();
    }

#ifdef DEBUG_KEY
    PrivateKey<Element> m_privateKey;
#endif

  public:
#ifdef DEBUG_KEY
    /**
     * SetPrivateKey() stores the private key in the crypto context.
     * GetPrivateKey() gets the private key from the crypto context.
     *
     * Thees functions are only intended for debugging and should not be used in production systems.
     * Please define DEBUG_KEY in openfhe.h to enable them.
     *
     * If used, one can create a key pair and store the secret key in the crypto context like this:
     *
     * auto keys = cc->key_gen();
     * cc->SetPrivateKey(keys.secret_key);
     *
     * After that, anyone in the code can access the secret key by getting the crypto context and doing the following:
     *
     * auto sk = cc->GetPrivateKey();
     *
     * The key can be used for decrypting any intermediate ciphertexts for debugging purposes.
     */
    void SetPrivateKey(const PrivateKey<Element> private_key) {
        CIPHER_DIAGNOSTIC_ERR << "Warning - SetPrivateKey is only intended to be used for debugging "
                                  "purposes - not for production systems."
                               << std::endl;
        m_privateKey = private_key;
    }

    const PrivateKey<Element>& GetPrivateKey() const {
        return m_privateKey;
    }
#endif

    /**
     * @brief Sets the identifier of the scheme this crypto context implements.
     *
     * @param scheme_tag the scheme identifier
     */
    void set_scheme_id(SCHEME scheme_tag) {
        scheme_id_ = scheme_tag;
    }

    /**
     * @brief Gets the identifier of the scheme this crypto context implements.
     *
     * @return the scheme identifier
     */
    SCHEME get_scheme_id_impl() const {
        return scheme_id_;
    }

    /**
     * @brief Constructor from raw pointers to parameters and scheme
     *
     * @param params pointer to CryptoParameters
     * @param scheme pointer to Crypto Scheme object
     * @param scheme_id_value scheme identifier
     */
    // TODO (dsuponit): investigate if we really need 2 constructors for CryptoContextImpl as one of them take regular pointer
    // and the other one takes shared_ptr
    CryptoContextImpl(BaseCryptoParams<Element>* params = nullptr, SchemeBase<Element>* scheme = nullptr,
                      SCHEME scheme_id_value = SCHEME::INVALID_SCHEME) {
        params_.reset(params);
        scheme_.reset(scheme);
        key_gen_level_ = 0;
        scheme_id_ = scheme_id_value;
    }

    /**
     * @brief Constructor from shared pointers to parameters and scheme
     *
     * @param params shared pointer to CryptoParameters
     * @param scheme sharedpointer to Crypto Scheme object
     * @param scheme_id_value scheme identifier
     */
    CryptoContextImpl(std::shared_ptr<BaseCryptoParams<Element>> params,
                      std::shared_ptr<SchemeBase<Element>> scheme, SCHEME scheme_id_value = SCHEME::INVALID_SCHEME) {
        params_ = params;
        scheme_ = scheme;
        key_gen_level_ = 0;
        scheme_id_ = scheme_id_value;
    }

    /**
     * @brief Copy constructor
     * @param other cryptocontext to copy from
     */
    CryptoContextImpl(const CryptoContextImpl<Element>& other) {
        params_ = other.params_;
        scheme_ = other.scheme_;
        key_gen_level_ = 0;
        scheme_id_ = other.scheme_id_;
    }

    /**
     * @brief Assignment operator
     * @param rhs cryptocontext to assign values from
     * @return this
     */
    CryptoContextImpl<Element>& operator=(const CryptoContextImpl<Element>& rhs) {
        params_ = rhs.params_;
        scheme_ = rhs.scheme_;
        key_gen_level_ = rhs.key_gen_level_;
        scheme_id_ = rhs.scheme_id_;
        return *this;
    }

    /**
     * @brief Checks the CryptoContextImpl object health.
     * @return true if params and scheme exists in the object
     */
    operator bool() const {
        return params_ && scheme_;
    }

    /**
     * @brief Equality comparison operator
     *
     * @param a cryptocontext object1
     * @param b cryptocontext object2
     * @return true if the implementations have identical params and scheme
     * @attention this is for internal use only
     */
    friend bool operator==(const CryptoContextImpl<Element>& a, const CryptoContextImpl<Element>& b) {
        // Identical if the parameters and the schemes are identical... the exact
        // same object, OR the same type and the same values
        if (a.params_.get() == b.params_.get()) {
            return true;
        } else {
            if (typeid(*a.params_.get()) != typeid(*b.params_.get())) {
                return false;
            }
            if (*a.params_.get() != *b.params_.get())
                return false;
        }

        if (a.scheme_.get() == b.scheme_.get()) {
            return true;
        } else {
            if (typeid(*a.scheme_.get()) != typeid(*b.scheme_.get())) {
                return false;
            }
            if (*a.scheme_.get() != *b.scheme_.get())
                return false;
        }

        return true;
    }

    /**
     * @brief Inequality comparison operator
     *
     * @param a cryptocontext object1
     * @param b cryptocontext object2
     * @return true if the implementations do not have identical params and scheme
     * @attention this is for internal use only
     */
    friend bool operator!=(const CryptoContextImpl<Element>& a, const CryptoContextImpl<Element>& b) {
        return !(a == b);
    }

    /**
     * @brief Clears various caches within the library
     */
    static void clear_static_maps_and_vectors();

    /**
     * @brief Clear CKKS bootstrap precomputations cached by this context's scheme.
     */
    void clear_bootstrap_precom() {
        verify_ckks_scheme(__func__);
        scheme_->clear_bootstrap_precom();
    }

    /**
     * @brief Clear CKKS/FHEW scheme-switch precomputations cached by this context's scheme.
     */
    void clear_scheme_switch_precom() {
        verify_ckks_scheme(__func__);
        scheme_->clear_scheme_switch_precom();
    }

    /**
     * @brief Release all scheme-level caches (bootstrap + scheme-switch). Unlike the two calls
     *        above this is a teardown helper used to sweep contexts of any scheme, so it is a
     *        noexcept no-op when the caches cannot exist rather than an error.
     */
    void clear_all_ckks_caches() noexcept {
        if (scheme_ && is_ckks(scheme_id_)) {
            scheme_->clear_bootstrap_precom();
            scheme_->clear_scheme_switch_precom();
        }
    }

    /**
     * @brief Serializes either all eval_mult keys (if key_tag is empty) or the eval_mult keys for key_tag
     *
     * @param ser stream to serialize to
     * @param sertype type of serialization
     * @param key_tag secret key tag
     * @return true on success
     */
    template <typename ST>
    static bool serialize_eval_mult_key(std::ostream& ser, const ST& sertype, const std::string& key_tag = "") {
        const auto& eval_mult_keys = CryptoContextImpl<Element>::get_all_eval_mult_keys();
        if (key_tag.length() == 0) {
            serialization::to_stream(eval_mult_keys, ser, sertype);
        } else {
            const auto it = eval_mult_keys.find(key_tag);
            if (it == eval_mult_keys.end())
                return false;  // no such key_tag

            std::map<std::string, std::vector<EvalKey<Element>>> omap{{it->first, it->second}};

            serialization::to_stream(omap, ser, sertype);
        }
        return true;
    }

    /**
     * @brief Serializes all eval_mult keys associated with the given CryptoContext
     *
     * @param ser stream to serialize to
     * @param sertype type of serialization
     * @param cc the CryptoContext whose keys should be serialized
     * @return true on success
     */
    template <typename ST>
    static bool serialize_eval_mult_key(std::ostream& ser, const ST& sertype, const CryptoContext<Element> cc) {
        std::map<std::string, std::vector<EvalKey<Element>>> omap;
        for (const auto& [key, vec] : CryptoContextImpl<Element>::get_all_eval_mult_keys()) {
            if (vec[0]->get_crypto_context() == cc) {
                omap[key] = vec;
            }
        }

        if (omap.empty())
            return false;

        serialization::to_stream(omap, ser, sertype);
        return true;
    }

    /**
     * @brief Deserializes eval_mult keys
     *
     * @param ser stream to deserialize from
     * @param sertype type of serialization
     * @return true on success
     * @attention Silently replaces any existing matching keys and creates a new CryptoContextImpl if necessary
     */
    template <typename ST>
    static bool deserialize_eval_mult_key(std::istream& ser, const ST& sertype) {
        std::map<std::string, std::vector<EvalKey<Element>>> omap;

        serialization::from_stream(omap, ser, sertype);

        // The deserialize call creates all contexts that need to be created...
        // so, all we need to do is to insert the keys into the maps for their context(s)
        for (auto& [tag, vec] : omap) {
            CryptoContextImpl<Element>::insert_eval_mult_key(vec, tag);
        }
        return true;
    }

    /**
     * @brief Clears the entire EvalMultKey cache
     */
    static void clear_eval_mult_keys();

    /**
     * @brief Clears the EvalMultKey cache for the given key_tag or the entire EvalMultKey cache if key_tag is empty
     * @param key_tag secret key tag
     */
    static void clear_eval_mult_keys(const std::string& key_tag);

    /**
     * @brief Clears EvalMultKey cache for the given context
     * @param cc the context to clear all EvalMultKey for
     */
    static void clear_eval_mult_keys(const CryptoContext<Element>& cc);

    /**
     * @brief Adds the given vector of keys for the given key_tag to the map of all eval_mult keys
     *
     * @param eval_key_vec vector of keys
     * @param key_tag secret key tag
     * @attention Silently replaces any existing matching keys and if key_tag is empty, then the key tag is retrieved from eval_key_vec
     */
    static void insert_eval_mult_key(const std::vector<EvalKey<Element>>& eval_key_vec, const std::string& key_tag = "");

    /**
     * @brief Serializes either all eval_sum keys (if key_tag is empty) or the eval_sum keys for key_tag
     *
     * @param ser stream to serialize to
     * @param sertype type of serialization
     * @param key_tag secret key tag
     * @return true on success
     */
    template <typename ST>
    static bool serialize_eval_sum_key(std::ostream& ser, const ST& sertype, const std::string& key_tag = "") {
        return CryptoContextImpl<Element>::serialize_eval_automorphism_key(ser, sertype, key_tag);
    }

    /**
     * @brief Serializes all eval_sum keys associated with the given CryptoContext
     *
     * @param ser stream to serialize to
     * @param sertype type of serialization
     * @param cc the CryptoContext whose keys should be serialized
     * @return true on success
     */
    template <typename ST>
    static bool serialize_eval_sum_key(std::ostream& ser, const ST& sertype, const CryptoContext<Element> cc) {
        return CryptoContextImpl<Element>::serialize_eval_automorphism_key(ser, sertype, cc);
    }

    /**
     * @brief Deserializes eval_sum keys
     *
     * @param ser stream to deserialize from
     * @param sertype type of serialization
     * @return true on success
     * @attention Silently replaces any existing matching keys and creates a new CryptoContextImpl if necessary
     */
    template <typename ST>
    static bool deserialize_eval_sum_key(std::istream& ser, const ST& sertype) {
        return CryptoContextImpl<Element>::deserialize_eval_automorphism_key(ser, sertype);
    }

    /**
     * @brief Clears the entire EvalSumKey cache
     */
    static void clear_eval_sum_keys();

    /**
     * @brief Clears the EvalSumKey cache for the given key_tag or the entire EvalSumKey cache if key_tag is empty
     * @param key_tag secret key tag
     */
    static void clear_eval_sum_keys(const std::string& key_tag);

    /**
     * @brief Clears EvalSumKey cache for the given context
     * @param cc the context to clear all EvalSumKey for
     */
    static void clear_eval_sum_keys(const CryptoContext<Element> cc);

    /**
     * @brief Adds the given map of keys for the given key_tag to the map of all eval_sum keys
     *
     * @param map_to_insert map of keys
     * @param key_tag secret key tag
     * @attention Silently replaces any existing matching keys and if key_tag is empty, then the key tag is retrieved from map_to_insert
     */
    static void insert_eval_sum_key(const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> map_to_insert,
                                 std::string key_tag = "") {
        CryptoContextImpl<Element>::insert_eval_automorphism_key(map_to_insert, key_tag);
    }

    /**
     * @brief Serializes either all eval_automorphism keys (if key_tag is empty) or the eval_automorphism keys for key_tag
     *
     * @param ser stream to serialize to
     * @param sertype type of serialization
     * @param key_tag secret key tag
     * @return true on success
     */
    template <typename ST>
    static bool serialize_eval_automorphism_key(std::ostream& ser, const ST& sertype, const std::string& key_tag = "") {
        // TODO (dsuponit): do we need Serailize/Deserialized to return bool?
        std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>>* smap;
        std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>> omap;
        if (key_tag.length() == 0) {
            smap = &CryptoContextImpl<Element>::get_all_eval_automorphism_keys();
        } else {
            const auto keys = CryptoContextImpl<Element>::get_eval_automorphism_key_map_ptr(key_tag);
            omap[key_tag] = keys;
            smap = &omap;
        }
        serialization::to_stream(*smap, ser, sertype);
        return true;
    }

    /**
     * @brief Serializes all eval_automorphism keys associated with the given CryptoContext
     *
     * @param ser stream to serialize to
     * @param sertype type of serialization
     * @param cc the CryptoContext whose keys should be serialized
     * @return true on success
     */
    template <typename ST>
    static bool serialize_eval_automorphism_key(std::ostream& ser, const ST& sertype, const CryptoContext<Element> cc) {
        std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>> omap;
        for (const auto& k : CryptoContextImpl<Element>::get_all_eval_automorphism_keys()) {
            if (k.second->begin()->second->get_crypto_context() == cc) {
                omap[k.first] = k.second;
            }
        }

        if (omap.empty())
            return false;

        serialization::to_stream(omap, ser, sertype);
        return true;
    }

    /**
     * @brief Serializes eval_automorphism keys for an array of specific indices associated with the given key_tag
     *
     * @param ser stream to serialize to
     * @param sertype type of serialization
     * @param key_tag secret key tag
     * @param index_list array of specific indices to serialize keys for
     * @return true on success
     */
    template <typename ST>
    static bool serialize_eval_automorphism_key(std::ostream& ser, const ST& sertype, const std::string& key_tag,
                                             const std::vector<uint32_t>& index_list) {
        std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>> key_map = {
                {key_tag, CryptoContextImpl<Element>::get_partial_eval_automorphism_key_map_ptr(key_tag, index_list)}};

        serialization::to_stream(key_map, ser, sertype);
        return true;
    }

    /**
     * @brief Deserializes eval_automorphism keys for an array of specific indices associated with the given key_tag
     *
     * @param ser stream to deserialize from
     * @param sertype type of serialization
     * @param key_tag secret key tag
     * @param index_list array of specific indices to deserialize keys for
     * @return true on success
     */
    template <typename ST>
    static bool deserialize_eval_automorphism_key(std::istream& ser, const ST& sertype, const std::string& key_tag,
                                               const std::vector<uint32_t>& index_list) {
        if (index_list.empty())
            CIPHER_THROW("indexList may not be empty");
        if (key_tag.empty())
            CIPHER_THROW("keyTag may not be empty");

        std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>> all_deser_keys;
        serialization::from_stream(all_deser_keys, ser, sertype);

        const auto& key_map_it = all_deser_keys.find(key_tag);
        if (key_map_it == all_deser_keys.end()) {
            CIPHER_THROW("Deserialized automorphism keys are not generated for ID [" + key_tag + "].");
        }

        // create a new map with evalkeys for the specified indices
        std::map<uint32_t, EvalKey<Element>> new_map;
        for (const uint32_t indx : index_list) {
            const auto& key = key_map_it->second->find(indx);
            if (key == key_map_it->second->end()) {
                CIPHER_THROW("No automorphism key generated for index [" + std::to_string(indx) + "] within keyTag [" +
                              key_tag + "].");
            }
            new_map[indx] = key->second;
        }

        CryptoContextImpl<Element>::insert_eval_automorphism_key(
                std::make_shared<std::map<uint32_t, EvalKey<Element>>>(new_map), key_tag);

        return true;
    }

    /**
     * @brief Serializes bootstrap eval_automorphism keys associated with the given key tag
     *
     * @param ser stream to serialize to
     * @param sertype type of serialization
     * @param cc crypto context
     * @param key_tag secret key tag
     * @param slots number of slots for which the bootstrapping is performed
     * @return true on success
     */
    template <typename ST>
    static bool serialize_eval_bootstrap_key(std::ostream& ser, const ST& sertype, const CryptoContext<Element>& cc,
                                          const std::string& key_tag, uint32_t slots) {
        const auto index_list = cc->get_scheme()->eval_bootstrap_key_map_indices(cc, slots);
        std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>> key_map = {
                {key_tag, CryptoContextImpl<Element>::get_partial_eval_automorphism_key_map_ptr(key_tag, index_list)}};

        serialization::to_stream(key_map, ser, sertype);

        return true;
    }
    /**
     * @brief Deserializes bootstrap eval_automorphism keys for an array of specific indices associated with the given key_tag
     *
     * @param ser stream to deserialize from
     * @param sertype type of serialization
     * @param key_tag secret key tag
     * @param index_list array of specific indices to deserialize keys for
     * @return true on success
     */
    template <typename ST>
    static bool deserialize_eval_bootstrap_key(std::istream& ser, const ST& sertype, const std::string& key_tag,
                                            const std::vector<uint32_t>& index_list) {
        return CryptoContextImpl<Element>::deserialize_eval_automorphism_key(ser, sertype, key_tag, index_list);
    }

    /**
     * @brief Deserializes bootstrap eval_automorphism keys derived from the given crypto context, key tag, and slots count
     *
     * @param ser stream to deserialize from
     * @param sertype type of serialization
     * @param cc crypto context
     * @param key_tag secret key tag
     * @param slots number of slots for which the bootstrapping was performed
     * @return true on success
     */
    template <typename ST>
    static bool deserialize_eval_bootstrap_key(std::istream& ser, const ST& sertype, const CryptoContext<Element>& cc,
                                            const std::string& key_tag, uint32_t slots) {
        const auto index_list = cc->get_scheme()->eval_bootstrap_key_map_indices(cc, slots);
        return CryptoContextImpl<Element>::deserialize_eval_automorphism_key(ser, sertype, key_tag, index_list);
    }

    /**
     * @brief Deserializes eval_automorphism keys
     *
     * @param ser stream to deserialize from
     * @param sertype type of serialization
     * @return true on success
     * @attention Silently replaces any existing matching keys and creates a new CryptoContextImpl if necessary
     */
    template <typename ST>
    static bool deserialize_eval_automorphism_key(std::istream& ser, const ST& sertype) {
        std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>> key_map;

        serialization::from_stream(key_map, ser, sertype);

        // The deserialize call created any contexts that needed to be created....
        // so all we need to do is put the keys into the maps for their context
        for (auto& k : key_map) {
            CryptoContextImpl<Element>::insert_eval_automorphism_key(k.second, k.first);
        }
        return true;
    }

    /**
     * @brief Clears the entire EvalAutomorphismKey cache
     */
    static void clear_eval_automorphism_keys();

    /**
     * @brief Clears the EvalAutomorphismKey cache for the given key_tag or the entire EvalAutomorphismKey cache if key_tag is empty
     * @param key_tag secret key tag
     */
    static void clear_eval_automorphism_keys(const std::string& key_tag);

    /**
     * @brief Clears EvalAutomorphismKey cache for the given context
     * @param cc the context to clear all EvalAutomorphismKeys for
     */
    static void clear_eval_automorphism_keys(const CryptoContext<Element> cc);

    /**
     * @brief Adds the given map of keys for the given key_tag to the map of all eval_automorphism keys
     *
     * @param map_to_insert map of keys
     * @param key_tag secret key tag
     * @attention Silently replaces any existing matching keys and if key_tag is empty, then the key tag is retrieved from map_to_insert
     */
    // TODO (dsuponit): move insert_eval_automorphism_key() to the private section of the class
    static void insert_eval_automorphism_key(const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> map_to_insert,
                                          const std::string& key_tag = "");
    //------------------------------------------------------------------------------
    // TURN FEATURES ON
    //------------------------------------------------------------------------------

    /**
     * @brief Enable a particular feature for use with this CryptoContextImpl
     * @param feature the feature that should be enabled
     */
    void enable(PkeSchemeFeature feature) {
        scheme_->enable(feature);
    }

    /**
     * @brief Enable several features at once
     * @param feature_mask bitwise value of several PKESchemeFeatures
     */
    void enable(uint32_t feature_mask) {
        scheme_->enable(feature_mask);
    }

    // GETTERS
    /**
     * @brief Getter for Scheme
     * @return Scheme object
     */
    const std::shared_ptr<SchemeBase<Element>> get_scheme() const {
        return scheme_;
    }

    /**
     * @brief Getter for CryptoParams
     * @return CryptoParams
     */
    const std::shared_ptr<BaseCryptoParams<Element>> get_crypto_parameters() const {
        return params_;
    }

    /**
     * @brief Getter for the level at which evaluation keys should be generated
     * @return level
     * @attention For future use
     */
    size_t get_key_gen_level() const {
        return key_gen_level_;
    }

    /**
     * @brief Setter for the level at which evaluation keys should be generated
     * @param level the level at which evaluation keys should be generated
     * @attention For future use
     */
    void set_key_gen_level(size_t level) {
        key_gen_level_ = level;
    }

    /**
     * @brief Getter for element params
     * @return ElementParams
     */
    const std::shared_ptr<ParmType> get_element_params() const {
        return params_->get_element_params();
    }

    /**
     * @brief Getter for encoding params
     * @return EncodingParams
     */
    const EncodingParams get_encoding_params() const {
        return params_->get_encoding_params();
    }

    /**
     * @brief Getter for cyclotomic order
     * @return CyclotomicOrder
     */
    uint32_t get_cyclotomic_order() const {
        return params_->get_element_params()->get_cyclotomic_order();
    }

    /**
     * @brief Getter for ring dimension
     * @return RingDimension
     */
    uint32_t get_ring_dimension() const {
        return params_->get_element_params()->get_ring_dimension();
    }

    /**
     * @brief Getter for ciphertext modulus
     * @return modulus
     */
    const IntType& get_modulus() const {
        return params_->get_element_params()->get_modulus();
    }

    /**
     * @brief Getter for root of unity
     * @return root_of_unity
     */
    const IntType& get_root_of_unity() const {
        return params_->get_element_params()->get_root_of_unity();
    }

    /**
     * @brief Getter for the CKKS data type
     * @return data type of the CKKS data
     */
    CkksDataType get_ckks_data_type() const {
        const auto crypto_params = std::dynamic_pointer_cast<RnsCryptoParams>(params_);
        if (!crypto_params)
            CIPHER_THROW("Invalid crypto parameters: expected CryptoParametersRNS");

        return crypto_params->get_ckks_data_type();
    }

    //------------------------------------------------------------------------------
    // KEYS GETTERS
    //------------------------------------------------------------------------------

    /**
     * @brief Gets a map of all relinearization/evaluation multiplication keys
     * @return std::map where the map key/data pair is "key_tag"/"EvalMultKeys vector"
     */
    static std::map<std::string, std::vector<EvalKey<Element>>>& get_all_eval_mult_keys();

    /**
     * @brief Gets a vector of relinearization/evaluation multiplication keys for the given key_tag
     * @param key_tag secret key tag
     * @return vector of EvalMultKeys
     */
    static const std::vector<EvalKey<Element>>& get_eval_mult_key_vector(const std::string& key_tag);

    /**
     * @brief Gets a map of all eval_automorphism keys
     * @return std::map where the map key/data pair is "key_tag"/"shared_ptr to EvalMultKey map"
     */
    static std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>>& get_all_eval_automorphism_keys();

    /**
     * @brief Gets a map of eval_automorphism keys for the given key_tag
     * @param key_tag secret key tag
     * @return shared_ptr to EvalAutomorphismKey map
     */
    static std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> get_eval_automorphism_key_map_ptr(
            const std::string& key_tag);

    /**
     * @brief Gets a map of eval_automorphism keys for the given key_tag
     * @param key_tag secret key tag
     * @return EvalAutomorphismKey map
     */
    static std::map<uint32_t, EvalKey<Element>>& get_eval_automorphism_key_map(const std::string& key_tag) {
        return *(CryptoContextImpl<Element>::get_eval_automorphism_key_map_ptr(key_tag));
    }

    /**
     * @brief Gets a map of all summation keys
     * @return std::map where the map key/data pair is "key_tag"/"shared_ptr to EvalSumKey map"
     */
    static std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>>& get_all_eval_sum_keys();

    /**
     * @brief Gets a map of eval_sum keys for the given key_tag
     * @param key_tag secret key tag
     * @return EvalSumKey map
     */
    static const std::map<uint32_t, EvalKey<Element>>& get_eval_sum_key_map(const std::string& key_tag);

    //------------------------------------------------------------------------------
    // PLAINTEXT FACTORY METHODS
    //------------------------------------------------------------------------------

    // TODO to be deprecated in 2.0
    /**
     * @brief Creates a plaintext from a string using string encoding.
     *
     * @param str Input string to encode.
     * @return Encoded plaintext.
     */
    Plaintext make_string_plaintext(const std::string& str) const {
        return PlaintextFactory::make_plaintext(str, STRING_ENCODING, this->get_element_params(),
                                               this->get_encoding_params());
    }

    /**
     * @brief Encodes a vector of integers into a coefficient-packed plaintext.
     *
     * @param value           Input vector to encode.
     * @param noise_scale_deg   Degree of the scaling factor to encode the plaintext at.
     * @param level           Encryption level for the input vector.
     * @return Encoded plaintext.
     */
    Plaintext make_coef_packed_plaintext(const std::vector<int64_t>& value, size_t noise_scale_deg = 1,
                                      uint32_t level = 0) const {
        if (value.empty())
            CIPHER_THROW("Cannot encode an empty value vector");

        return make_plaintext(COEF_PACKED_ENCODING, value, noise_scale_deg, level);
    }

    /**
     * @brief Encodes a vector of integers into a packed plaintext.
     *
     * @param value           Input vector to encode.
     * @param noise_scale_deg   Degree of the scaling factor to encode the plaintext at.
     * @param level           Encryption level for the input vector.
     * @return Encoded plaintext.
     */
    Plaintext make_packed_plaintext(const std::vector<int64_t>& value, size_t noise_scale_deg = 1,
                                  uint32_t level = 0) const {
        if (value.empty())
            CIPHER_THROW("Cannot encode an empty value vector");

        return make_plaintext(PACKED_ENCODING, value, noise_scale_deg, level);
    }

    /**
     * @brief Encodes a vector of complex numbers into a CKKS packed plaintext.
     *
     * @param value           Input vector to encode.
     * @param noise_scale_deg   Degree of the scaling factor to encode the plaintext at.
     * @param level           Encryption level for the input vector.
     * @param params          Encoding parameters.
     * @param slots           Number of slots to use.
     * @return Encoded CKKS plaintext.
     */
    Plaintext make_ckks_packed_plaintext(const std::vector<std::complex<double>>& value, size_t noise_scale_deg = 1,
                                      uint32_t level = 0, const std::shared_ptr<ParmType> params = nullptr,
                                      uint32_t slots = 0) const {
        verify_ckks_scheme(__func__);
        if (value.empty())
            CIPHER_THROW("Cannot encode an empty value vector");

        return make_ckks_packed_plaintext_internal(value, noise_scale_deg, level, params, slots);
    }

    /**
     * @brief Encodes a vector of real numbers into a CKKS packed plaintext.
     *
     * @param value           Input vector to encode.
     * @param noise_scale_deg   Degree of the scaling factor to encode the plaintext at.
     * @param level           Encryption level for the input vector.
     * @param params          Encoding parameters.
     * @param slots           Number of slots to use.
     * @return Encoded CKKS plaintext.
     */
    Plaintext make_ckks_packed_plaintext(const std::vector<double>& value, size_t noise_scale_deg = 1, uint32_t level = 0,
                                      const std::shared_ptr<ParmType> params = nullptr, uint32_t slots = 0) const {
        verify_ckks_scheme(__func__);
        if (value.empty())
            CIPHER_THROW("Cannot encode an empty value vector");

        std::vector<std::complex<double>> complex_value(value.size());
        std::transform(value.begin(), value.end(), complex_value.begin(),
                       [](double da) { return std::complex<double>(da); });

        return make_ckks_packed_plaintext_internal(complex_value, noise_scale_deg, level, params, slots);
    }

    /**
     * @brief Returns a plaintext object for decryption based on encoding type and parameters.
     *
     * @param pte   Plaintext encoding type.
     * @param evp   Element parameters.
     * @param ep    Encoding parameters.
     * @param cdt   CKKS data type.
     * @return Plaintext for decryption.
     */
    static Plaintext get_plaintext_for_decrypt(PlaintextEncodings pte, std::shared_ptr<ParmType> evp, EncodingParams ep,
                                            CkksDataType cdt = REAL);

    //------------------------------------------------------------------------------
    // PKE Wrapper
    //------------------------------------------------------------------------------

    /**
     * @brief Generates a standard public/secret key pair.
     *
     * @return Generated key pair.
     */
    KeyPair<Element> key_gen() const {
        return scheme_->key_gen(get_context_for_pointer(this), false);
    }

    /**
     * @brief Generates a sparse key pair (with special structure and without full entropy) for special use cases like ring reduction.
     *
     * @return Generated key pair.
     * @attention Not supported by any crypto scheme currently.
     */
    KeyPair<Element> sparse_key_gen() const {
        return scheme_->key_gen(get_context_for_pointer(this), true);
    }

    /**
     * @brief Encrypts a plaintext using the given public key.
     *
     * @param plaintext  Plaintext to encrypt.
     * @param public_key  Public key to use for encryption.
     * @return Encrypted ciphertext (or null on failure).
     */
    Ciphertext<Element> encrypt(ConstPlaintext& plaintext, const PublicKey<Element>& public_key) const {
        if (plaintext == nullptr)
            CIPHER_THROW("Input plaintext is nullptr");
        validate_key(public_key);

        Ciphertext<Element> ciphertext = scheme_->encrypt(plaintext->get_element<Element>(), public_key);

        if (ciphertext) {
            ciphertext->set_slots(plaintext->get_slots());
            ciphertext->set_level(plaintext->get_level());
            ciphertext->set_noise_scale_deg(plaintext->get_noise_scale_deg());
            ciphertext->set_scaling_factor(plaintext->get_scaling_factor());
            ciphertext->set_scaling_factor_int(plaintext->get_scaling_factor_int());
            ciphertext->set_encoding_type(plaintext->get_encoding_type());
        }

        return ciphertext;
    }

    /**
     * @brief Encrypts a plaintext using the given public key.
     *
     * @param public_key  Public key to use for encryption.
     * @param plaintext  Plaintext to encrypt.
     * @return Encrypted ciphertext (or null on failure).
     */
    Ciphertext<Element> encrypt(const PublicKey<Element>& public_key, ConstPlaintext& plaintext) const {
        return encrypt(plaintext, public_key);
    }

    /**
     * @brief Encrypts a plaintext using the given private key.
     *
     * @param plaintext   Plaintext to encrypt.
     * @param private_key  Private key to use for encryption.
     * @return Encrypted ciphertext (or null on failure).
     */
    Ciphertext<Element> encrypt(ConstPlaintext& plaintext, const PrivateKey<Element>& private_key) const {
        //    if (plaintext == nullptr)
        //      CIPHER_THROW( "Input plaintext is nullptr");
        validate_key(private_key);

        Ciphertext<Element> ciphertext = scheme_->encrypt(plaintext->get_element<Element>(), private_key);

        if (ciphertext) {
            ciphertext->set_slots(plaintext->get_slots());
            ciphertext->set_level(plaintext->get_level());
            ciphertext->set_noise_scale_deg(plaintext->get_noise_scale_deg());
            ciphertext->set_scaling_factor(plaintext->get_scaling_factor());
            ciphertext->set_scaling_factor_int(plaintext->get_scaling_factor_int());
            ciphertext->set_encoding_type(plaintext->get_encoding_type());
        }

        return ciphertext;
    }

    /**
     * @brief Encrypts a plaintext using the given private key.
     *
     * @param private_key  Private key to use for encryption.
     * @param plaintext   Plaintext to encrypt.
     * @return Encrypted ciphertext (or null on failure).
     */
    Ciphertext<Element> encrypt(const PrivateKey<Element>& private_key, ConstPlaintext& plaintext) const {
        return encrypt(plaintext, private_key);
    }

    /**
     * @brief Decrypts a ciphertext using the given private key.
     *
     * @param ciphertext  Ciphertext to decrypt.
     * @param private_key  Private key for decryption.
     * @param plaintext   Output pointer for the resulting plaintext.
     * @return Decryption result status.
     */
    DecryptResult decrypt(ConstCiphertext<Element>& ciphertext, const PrivateKey<Element>& private_key,
                          Plaintext* plaintext);

    /**
     * @brief Decrypts a ciphertext using the given private key.
     *
     * @param private_key  Private key for decryption.
     * @param ciphertext  Ciphertext to decrypt.
     * @param plaintext   Output pointer for the resulting plaintext.
     * @return Decryption result status.
     */
    inline DecryptResult decrypt(const PrivateKey<Element>& private_key, ConstCiphertext<Element>& ciphertext,
                                 Plaintext* plaintext) {
        return decrypt(ciphertext, private_key, plaintext);
    }

    //------------------------------------------------------------------------------
    // key_switch Wrapper
    //------------------------------------------------------------------------------

    /**
     * @brief Generates a key switching key from one secret key to another.
     *
     * @param old_private_key  Original secret key.
     * @param new_private_key  Target secret key.
     * @return New evaluation key for key switching.
     */
    EvalKey<Element> key_switch_gen(const PrivateKey<Element>& old_private_key,
                                  const PrivateKey<Element>& new_private_key) const {
        validate_key(old_private_key);
        validate_key(new_private_key);
        return scheme_->key_switch_gen(old_private_key, new_private_key);
    }

    /**
     * @brief Applies key switching to a ciphertext using the given evaluation key.
     *
     * @param ciphertext  Input ciphertext.
     * @param eval_key     Evaluation key for key switching.
     * @return Ciphertext after key switching.
     */
    Ciphertext<Element> key_switch(ConstCiphertext<Element>& ciphertext, const EvalKey<Element>& eval_key) const {
        validate_ciphertext(ciphertext);
        validate_key(eval_key);
        return scheme_->key_switch(ciphertext, eval_key);
    }

    /**
     * @brief Applies key switching in place on the given ciphertext.
     *
     * @param ciphertext  Ciphertext to modify.
     * @param eval_key     Evaluation key for key switching.
     */
    void key_switch_in_place(Ciphertext<Element>& ciphertext, const EvalKey<Element>& eval_key) const {
        validate_ciphertext(ciphertext);
        validate_key(eval_key);
        scheme_->key_switch_in_place(ciphertext, eval_key);
    }

    //------------------------------------------------------------------------------
    // SHE NEGATION Wrapper
    //------------------------------------------------------------------------------

    /**
     * @brief Negates a ciphertext.
     *
     * @param ciphertext  Input ciphertext.
     * @return Negated ciphertext.
     */
    Ciphertext<Element> eval_negate(ConstCiphertext<Element>& ciphertext) const {
        validate_ciphertext(ciphertext);
        return scheme_->eval_negate(ciphertext);
    }

    /**
     * @brief Performs in-place negation of a ciphertext.
     *
     * @param ciphertext  Ciphertext to negate.
     */
    void eval_negate_in_place(Ciphertext<Element>& ciphertext) const {
        validate_ciphertext(ciphertext);
        scheme_->eval_negate_in_place(ciphertext);
    }

    //------------------------------------------------------------------------------
    // SHE ADDITION Wrapper
    //------------------------------------------------------------------------------

    /**
     * @brief Homomorphic addition of two ciphertexts.
     *
     * @param ciphertext1  First addend.
     * @param ciphertext2  Second addend.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_add(ConstCiphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const {
        type_check(ciphertext1, ciphertext2);
        return scheme_->eval_add(ciphertext1, ciphertext2);
    }

    /**
     * @brief In-place homomorphic addition of two ciphertexts.
     *
     * @param ciphertext1  First addend (modified in place).
     * @param ciphertext2  Second addend.
     */
    void eval_add_in_place(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const {
        type_check(ciphertext1, ciphertext2);
        scheme_->eval_add_in_place(ciphertext1, ciphertext2);
    }

    /**
     * @brief In-place element-wise addition of two ciphertexts without any type, level or scaling factor checks;
     * the ciphertexts must already have the same number of elements, level and noise scale degree.
     *
     * @param ctxt1  First addend (modified in place).
     * @param ctxt2  Second addend.
     */
    void eval_add_in_place_no_check(Ciphertext<Element>& ctxt1, ConstCiphertext<Element>& ctxt2) const {
        auto& cv1 = ctxt1->get_elements();
        auto& cv2 = ctxt2->get_elements();
        uint32_t n = cv1.size();
        for (uint32_t i = 0; i < n; ++i)
            cv1[i] += cv2[i];
    }

    /**
     * @brief Homomorphic addition of two mutable ciphertexts.
     *
     * @param ciphertext1  First addend (may be modified).
     * @param ciphertext2  Second addend (may be modified).
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_add_mutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        type_check(ciphertext1, ciphertext2);
        return scheme_->eval_add_mutable(ciphertext1, ciphertext2);
    }

    /**
     * @brief In-place homomorphic addition of two mutable ciphertexts.
     *
     * @param ciphertext1  First addend (modified in place).
     * @param ciphertext2  Second addend (may be modified).
     */
    void eval_add_mutable_in_place(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        type_check(ciphertext1, ciphertext2);
        scheme_->eval_add_mutable_in_place(ciphertext1, ciphertext2);
    }

    /**
     * @brief Homomorphic addition of a ciphertext and a plaintext.
     *
     * @param ciphertext  Input ciphertext.
     * @param plaintext   Input plaintext.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_add(ConstCiphertext<Element>& ciphertext, Plaintext& plaintext) const {
        type_check(ciphertext, plaintext);
        plaintext->set_format(EVALUATION);
        return scheme_->eval_add(ciphertext, plaintext);
    }

    /**
     * @brief Homomorphic addition of a plaintext and a ciphertext.
     *
     * @param plaintext   Input plaintext.
     * @param ciphertext  Input ciphertext.
     * @return Resulting ciphertext.
     */
    inline Ciphertext<Element> eval_add(Plaintext& plaintext, ConstCiphertext<Element>& ciphertext) const {
        return eval_add(ciphertext, plaintext);
    }

    /**
     * @brief In-place addition of a ciphertext and a plaintext.
     *
     * @param ciphertext  Ciphertext to modify.
     * @param plaintext   Plaintext to add.
     */
    void eval_add_in_place(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        type_check(ciphertext, plaintext);
        plaintext->set_format(EVALUATION);
        scheme_->eval_add_in_place(ciphertext, plaintext);
    }

    /**
     * @brief In-place addition of a plaintext and a ciphertext.
     *
     * @param plaintext   Plaintext to add.
     * @param ciphertext  Ciphertext to modify.
     */
    void eval_add_in_place(Plaintext& plaintext, Ciphertext<Element>& ciphertext) const {
        eval_add_in_place(ciphertext, plaintext);
    }

    /**
     * @brief Homomorphic addition of a mutable ciphertext and a plaintext.
     *
     * @param ciphertext  Input ciphertext (may be modified).
     * @param plaintext   Input plaintext.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_add_mutable(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        type_check(ciphertext, plaintext);
        plaintext->set_format(EVALUATION);
        return scheme_->eval_add_mutable(ciphertext, plaintext);
    }

    /**
     * @brief Homomorphic addition of a plaintext and a mutable ciphertext.
     *
     * @param plaintext   Input plaintext.
     * @param ciphertext  Input ciphertext (may be modified).
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_add_mutable(Plaintext& plaintext, Ciphertext<Element>& ciphertext) const {
        return eval_add_mutable(ciphertext, plaintext);
    }

    /**
     * @brief Homomorphic addition of a ciphertext and a real number (CKKS only).
     *
     * @param ciphertext  Input ciphertext.
     * @param scalar      Real number to add.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_add(ConstCiphertext<Element>& ciphertext, double scalar) const {
        return scalar >= 0. ? scheme_->eval_add(ciphertext, scalar) : scheme_->eval_sub(ciphertext, -scalar);
    }

    /**
     * @brief Homomorphic addition of a real number and a ciphertext (CKKS only).
     *
     * @param scalar      Real number to add.
     * @param ciphertext  Input ciphertext.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_add(double scalar, ConstCiphertext<Element>& ciphertext) const {
        return eval_add(ciphertext, scalar);
    }

    /**
     * @brief In-place addition of a ciphertext and a real number (CKKS only).
     *
     * @param ciphertext  Ciphertext to modify.
     * @param scalar      Real number to add.
     */
    void eval_add_in_place(Ciphertext<Element>& ciphertext, double scalar) const {
        if (scalar == 0.)
            return;
        if (scalar > 0.)
            scheme_->eval_add_in_place(ciphertext, scalar);
        else
            scheme_->eval_sub_in_place(ciphertext, -scalar);
    }

    /**
     * @brief In-place addition of a real number and a ciphertext (CKKS only).
     *
     * @param scalar      Real number to add.
     * @param ciphertext  Ciphertext to modify.
     */
    void eval_add_in_place(double scalar, Ciphertext<Element>& ciphertext) const {
        eval_add_in_place(ciphertext, scalar);
    }

    /**
     * @brief Homomorphic addition of a ciphertext and a complex number (CKKS only).
     *
     * @param ciphertext  Input ciphertext.
     * @param scalar      Complex number to add.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_add(ConstCiphertext<Element>& ciphertext, std::complex<double> scalar) const {
        return scheme_->eval_add(ciphertext, scalar);
    }

    /**
     * @brief Homomorphic addition of a complex number and a ciphertext (CKKS only).
     *
     * @param scalar      Complex number to add.
     * @param ciphertext  Input ciphertext.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_add(std::complex<double> scalar, ConstCiphertext<Element>& ciphertext) const {
        return eval_add(ciphertext, scalar);
    }

    /**
     * @brief In-place addition of a ciphertext and a complex number (CKKS only).
     *
     * @param ciphertext  Ciphertext to modify.
     * @param scalar      Complex number to add.
     */
    void eval_add_in_place(Ciphertext<Element>& ciphertext, std::complex<double> scalar) const {
        if (scalar == std::complex<double>(0.0, 0.0))
            return;
        scheme_->eval_add_in_place(ciphertext, scalar);
    }

    /**
     * @brief In-place addition of a complex number and a ciphertext (CKKS only).
     *
     * @param scalar      Complex number to add.
     * @param ciphertext  Ciphertext to modify.
     */
    void eval_add_in_place(std::complex<double> scalar, Ciphertext<Element>& ciphertext) const {
        eval_add_in_place(ciphertext, scalar);
    }

    //------------------------------------------------------------------------------
    // SHE SUBTRACTION Wrapper
    //------------------------------------------------------------------------------

    /**
     * @brief Homomorphic subtraction of two ciphertexts.
     *
     * @param ciphertext1  Minuend.
     * @param ciphertext2  Subtrahend.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_sub(ConstCiphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const {
        type_check(ciphertext1, ciphertext2);
        return scheme_->eval_sub(ciphertext1, ciphertext2);
    }

    /**
     * @brief In-place homomorphic subtraction of two ciphertexts.
     *
     * @param ciphertext1  Minuend (modified in place).
     * @param ciphertext2  Subtrahend.
     */
    void eval_sub_in_place(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const {
        type_check(ciphertext1, ciphertext2);
        scheme_->eval_sub_in_place(ciphertext1, ciphertext2);
    }

    /**
     * @brief Homomorphic subtraction of two mutable ciphertexts.
     *
     * @param ciphertext1  Minuend (may be modified).
     * @param ciphertext2  Subtrahend (may be modified).
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_sub_mutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        type_check(ciphertext1, ciphertext2);
        return scheme_->eval_sub_mutable(ciphertext1, ciphertext2);
    }

    /**
     * @brief In-place homomorphic subtraction of two mutable ciphertexts.
     *
     * @param ciphertext1  Minuend (modified in place).
     * @param ciphertext2  Subtrahend (may be modified).
     */
    void eval_sub_mutable_in_place(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        type_check(ciphertext1, ciphertext2);
        scheme_->eval_sub_mutable_in_place(ciphertext1, ciphertext2);
    }

    /**
     * @brief Homomorphic subtraction of a ciphertext and a plaintext.
     *
     * @param ciphertext  Minuend.
     * @param plaintext   Subtrahend.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_sub(ConstCiphertext<Element>& ciphertext, Plaintext& plaintext) const {
        type_check(ciphertext, plaintext);
        return scheme_->eval_sub(ciphertext, plaintext);
    }

    /**
     * @brief Homomorphic subtraction of a ciphertext from a plaintext.
     *
     * @param plaintext   Minuend.
     * @param ciphertext  Subtrahend.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_sub(Plaintext& plaintext, ConstCiphertext<Element>& ciphertext) const {
        return eval_add(eval_negate(ciphertext), plaintext);
    }

    /**
     * @brief Homomorphic subtraction of a plaintext from a mutable ciphertext.
     *
     * @param ciphertext  Minuend (may be modified).
     * @param plaintext   Subtrahend.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_sub_mutable(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        type_check(ciphertext, plaintext);
        return scheme_->eval_sub_mutable(ciphertext, plaintext);
    }

    /**
     * @brief Homomorphic subtraction of a mutable ciphertext from a plaintext.
     *
     * @param plaintext   Minuend.
     * @param ciphertext  Subtrahend (may be modified).
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_sub_mutable(Plaintext& plaintext, Ciphertext<Element>& ciphertext) const {
        Ciphertext<Element> negated = eval_negate(ciphertext);
        Ciphertext<Element> result = eval_add_mutable(negated, plaintext);
        ciphertext = eval_negate(negated);
        return result;
    }

    /**
     * @brief In-place subtraction of a plaintext from a ciphertext.
     *
     * @param ciphertext  Minuend (modified in place).
     * @param plaintext  Subtrahend.
     */
    void eval_sub_in_place(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const {
        type_check(ciphertext, plaintext);
        scheme_->eval_sub_in_place(ciphertext, plaintext);
    }

    /**
     * @brief In-place subtraction of a ciphertext from a plaintext.
     *
     * @param plaintext   Minuend (may be modified).
     * @param ciphertext  Subtrahend (modified in place to hold the result).
     */
    void eval_sub_in_place(Plaintext& plaintext, Ciphertext<Element>& ciphertext) const {
        eval_negate_in_place(ciphertext);
        eval_add_in_place(ciphertext, plaintext);
    }

    /**
     * @brief Homomorphic subtraction of a real number from a ciphertext (CKKS only).
     *
     * @param ciphertext  Input ciphertext.
     * @param scalar      Real number to subtract.
     * @return Resulting ciphertext (ciphertext - scalar).
     */
    Ciphertext<Element> eval_sub(ConstCiphertext<Element>& ciphertext, double scalar) const {
        return scalar >= 0 ? scheme_->eval_sub(ciphertext, scalar) : scheme_->eval_add(ciphertext, -scalar);
    }

    /**
     * @brief Homomorphic subtraction of a ciphertext from a real number (CKKS only).
     *
     * @param scalar      Real number.
     * @param ciphertext  Ciphertext to subtract.
     * @return Resulting ciphertext (scalar - ciphertext).
     */
    Ciphertext<Element> eval_sub(double scalar, ConstCiphertext<Element>& ciphertext) const {
        return eval_add(eval_negate(ciphertext), scalar);
    }

    /**
     * @brief In-place subtraction of a real number from a ciphertext (CKKS only).
     *
     * @param ciphertext  Ciphertext to modify.
     * @param scalar      Real number to subtract.
     */
    void eval_sub_in_place(Ciphertext<Element>& ciphertext, double scalar) const {
        if (scalar == 0.)
            return;
        if (scalar > 0.)
            scheme_->eval_sub_in_place(ciphertext, scalar);
        else
            scheme_->eval_add_in_place(ciphertext, -scalar);
    }

    /**
     * @brief In-place subtraction of a ciphertext from a real number (CKKS only).
     *
     * @param scalar      Real number.
     * @param ciphertext  Ciphertext to modify.
     */
    void eval_sub_in_place(double scalar, Ciphertext<Element>& ciphertext) const {
        eval_negate_in_place(ciphertext);
        eval_add_in_place(ciphertext, scalar);
    }

    /**
     * @brief Homomorphic subtraction of a complex number from a ciphertext (CKKS only).
     *
     * @param ciphertext  Input ciphertext.
     * @param scalar      Complex number to subtract.
     * @return Resulting ciphertext (ciphertext - scalar).
     */
    Ciphertext<Element> eval_sub(ConstCiphertext<Element>& ciphertext, std::complex<double> scalar) const {
        return scheme_->eval_add(ciphertext, -scalar);
    }

    /**
     * @brief Homomorphic subtraction of a ciphertext from a complex number (CKKS only).
     *
     * @param scalar      Complex number.
     * @param ciphertext  Ciphertext to subtract.
     * @return Resulting ciphertext (scalar - ciphertext).
     */
    Ciphertext<Element> eval_sub(std::complex<double> scalar, ConstCiphertext<Element>& ciphertext) const {
        return eval_add(eval_negate(ciphertext), scalar);
    }

    /**
     * @brief In-place subtraction of a complex number from a ciphertext (CKKS only).
     *
     * @param ciphertext  Ciphertext to modify.
     * @param scalar      Complex number to subtract.
     */
    void eval_sub_in_place(Ciphertext<Element>& ciphertext, std::complex<double> scalar) const {
        if (scalar == std::complex<double>(0.0, 0.0))
            return;
        scheme_->eval_add_in_place(ciphertext, -scalar);
    }

    /**
     * @brief In-place subtraction of a ciphertext from a complex number (CKKS only).
     *
     * @param scalar      Complex number.
     * @param ciphertext  Ciphertext to modify.
     */
    void eval_sub_in_place(std::complex<double> scalar, Ciphertext<Element>& ciphertext) const {
        eval_negate_in_place(ciphertext);
        eval_add_in_place(ciphertext, scalar);
    }

    //------------------------------------------------------------------------------
    // SHE MULTIPLICATION Wrapper
    //------------------------------------------------------------------------------

    /**
     * @brief Creates a relinearization key (for s^2) that can be used with the Cipher eval_mult operator
     *
     * @param key secret key
     * @note the new evaluation key is stored in cryptocontext
     */
    void eval_mult_key_gen(const PrivateKey<Element>& key);

    /**
     * @brief Creates a vector evalmult keys that can be used with the Cipher eval_mult operator
     * @param key secret key
     *
     * @note 1st key (for s^2) is used for multiplication of ciphertexts of depth 1,
     * 2nd key (for s^3) is used for multiplication of ciphertexts of depth 2, etc.
     * A vector of new evaluation keys is stored in cryptocontext
     */
    void eval_mult_keys_gen(const PrivateKey<Element>& key);

    /**
     * @brief Homomorphic multiplication of two ciphertexts using a relinearization key.
     *
     * @param ciphertext1  Multiplier.
     * @param ciphertext2  Multiplicand.
     * @return Resulting ciphertext (ciphertext1 * ciphertext2).
     */
    Ciphertext<Element> eval_mult(ConstCiphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const {
        type_check(ciphertext1, ciphertext2);

        const auto& eval_key_vec = CryptoContextImpl<Element>::get_eval_mult_key_vector(ciphertext1->get_key_tag());
        if (eval_key_vec.empty())
            CIPHER_THROW("Evaluation key has not been generated for EvalMult");

        return scheme_->eval_mult(ciphertext1, ciphertext2, eval_key_vec[0]);
    }

    /**
     * @brief Homomorphic multiplication of two mutable ciphertexts using a relinearization key.
     *
     * @param ciphertext1  Multiplier (may be modified).
     * @param ciphertext2  Multiplicand (may be modified).
     * @return Resulting ciphertext (ciphertext1 * ciphertext2).
     */
    Ciphertext<Element> eval_mult_mutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        type_check(ciphertext1, ciphertext2);

        const auto& eval_key_vec = CryptoContextImpl<Element>::get_eval_mult_key_vector(ciphertext1->get_key_tag());
        if (eval_key_vec.empty())
            CIPHER_THROW("Evaluation key has not been generated for EvalMultMutable");

        return scheme_->eval_mult_mutable(ciphertext1, ciphertext2, eval_key_vec[0]);
    }

    /**
     * @brief In-place homomorphic multiplication of two mutable ciphertexts using a relinearization key.
     *
     * @param ciphertext1  Multiplier (modified in place).
     * @param ciphertext2  Multiplicand (may be modified).
     */
    void eval_mult_mutable_in_place(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        type_check(ciphertext1, ciphertext2);

        const auto& eval_key_vec = CryptoContextImpl<Element>::get_eval_mult_key_vector(ciphertext1->get_key_tag());
        if (eval_key_vec.empty())
            CIPHER_THROW("Evaluation key has not been generated for EvalMultMutableInPlace");

        scheme_->eval_mult_mutable_in_place(ciphertext1, ciphertext2, eval_key_vec[0]);
    }

    /**
     * @brief Homomorphic squaring of a ciphertext using a relinearization key.
     *
     * @param ciphertext  Input ciphertext.
     * @return Squared ciphertext.
     */
    Ciphertext<Element> eval_square(ConstCiphertext<Element>& ciphertext) const {
        validate_ciphertext(ciphertext);

        const auto& eval_key_vec = CryptoContextImpl<Element>::get_eval_mult_key_vector(ciphertext->get_key_tag());
        if (eval_key_vec.empty())
            CIPHER_THROW("Evaluation key has not been generated for EvalSquare");

        return scheme_->eval_square(ciphertext, eval_key_vec[0]);
    }

    /**
     * @brief Homomorphic squaring of a mutable ciphertext using a relinearization key.
     *
     * @param ciphertext  Input ciphertext (may be modified).
     * @return Squared ciphertext.
     */
    Ciphertext<Element> eval_square_mutable(Ciphertext<Element>& ciphertext) const {
        validate_ciphertext(ciphertext);

        const auto& eval_key_vec = CryptoContextImpl<Element>::get_eval_mult_key_vector(ciphertext->get_key_tag());
        if (eval_key_vec.empty())
            CIPHER_THROW("Evaluation key has not been generated for EvalSquareMutable");

        return scheme_->eval_square_mutable(ciphertext, eval_key_vec[0]);
    }

    /**
     * @brief In-place homomorphic squaring of a ciphertext using a relinearization key.
     *
     * @param ciphertext  Ciphertext to square (modified in place).
     */
    void eval_square_in_place(Ciphertext<Element>& ciphertext) const {
        validate_ciphertext(ciphertext);

        const auto& eval_key_vec = CryptoContextImpl<Element>::get_eval_mult_key_vector(ciphertext->get_key_tag());
        if (eval_key_vec.empty())
            CIPHER_THROW("Evaluation key has not been generated for EvalSquareInPlace");

        scheme_->eval_square_in_place(ciphertext, eval_key_vec[0]);
    }

    /**
     * @brief Homomorphic multiplication of two ciphertexts without relinearization.
     *
     * @param ciphertext1  Multiplier.
     * @param ciphertext2  Multiplicand.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_mult_no_relin(ConstCiphertext<Element>& ciphertext1,
                                        ConstCiphertext<Element>& ciphertext2) const {
        type_check(ciphertext1, ciphertext2);
        return scheme_->eval_mult(ciphertext1, ciphertext2);
    }

    /**
     * @brief Homomorphic multiplication of two ciphertexts without relinearization and without any type, level
     * or scaling factor checks: the tensor product of the ciphertext elements is computed directly, so the
     * ciphertexts must already have the same level and scaling factor. The result carries the summed noise scale
     * degree and the product of the scaling factors.
     *
     * @param ctxt1  Multiplier.
     * @param ctxt2  Multiplicand.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_mult_no_relin_no_check(ConstCiphertext<Element>& ctxt1, ConstCiphertext<Element>& ctxt2) const {
        auto& cv1 = ctxt1->get_elements();
        auto& cv2 = ctxt2->get_elements();

        uint32_t n1 = cv1.size();
        uint32_t n2 = cv2.size();
        uint32_t nr = n1 + n2 - 1;

        std::vector<RnsPoly> cvr;
        cvr.reserve(nr);

        if (n1 == 2 && n2 == 2) {
            cvr.emplace_back(cv1[0] * cv2[0]);
            cvr.emplace_back((cv1[0] * cv2[1]) += (cv1[1] * cv2[0]));
            cvr.emplace_back(cv1[1] * cv2[1]);
        } else {
            uint32_t m = 0;
            for (uint32_t i = 0; i < n1; ++i) {
                auto& cv1i = cv1[i];
                for (uint32_t j = 0, k = i; j < n2; ++j, ++k) {
                    if (k == m) {
                        cvr.emplace_back(cv1i * cv2[j]);
                        ++m;
                    } else {
                        cvr[k] += (cv1i * cv2[j]);
                    }
                }
            }
        }

        auto result = ctxt1->clone_empty();
        result->set_elements(std::move(cvr));
        result->set_noise_scale_deg(ctxt1->get_noise_scale_deg() + ctxt2->get_noise_scale_deg());
        result->set_scaling_factor(ctxt1->get_scaling_factor() * ctxt2->get_scaling_factor());
        result->set_scaling_factor_int(ctxt1->get_scaling_factor_int().mod_mul(
                ctxt2->get_scaling_factor_int(), ctxt1->get_crypto_parameters()->get_plaintext_modulus()));
        return result;
    }

    /**
     * @brief Relinearizes a ciphertext to reduce it to two components (2 polynomials per ciphertext).
     *
     * @param ciphertext  Input ciphertext.
     * @return Relinearized ciphertext.
     */
    Ciphertext<Element> relinearize(ConstCiphertext<Element>& ciphertext) const {
        // input parameter check
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");

        const auto& eval_key_vec = CryptoContextImpl<Element>::get_eval_mult_key_vector(ciphertext->get_key_tag());

        if (eval_key_vec.size() < (ciphertext->number_ciphertext_elements() - 2))
            CIPHER_THROW("Insufficient value was used for maxRelinSkDeg to generate keys for Relinearize");

        return scheme_->relinearize(ciphertext, eval_key_vec);
    }

    /**
     * @brief In-place relinearization of a ciphertext to reduce it to two components (2 polynomials per ciphertext).
     *
     * @param ciphertext  Ciphertext to relinearize (modified in place).
     */
    void relinearize_in_place(Ciphertext<Element>& ciphertext) const {
        // input parameter check
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");

        const auto& eval_key_vec = CryptoContextImpl<Element>::get_eval_mult_key_vector(ciphertext->get_key_tag());
        if (eval_key_vec.size() < (ciphertext->number_ciphertext_elements() - 2))
            CIPHER_THROW("Insufficient value was used for maxRelinSkDeg to generate keys for RelinearizeInPlace");

        scheme_->relinearize_in_place(ciphertext, eval_key_vec);
    }

    /**
     * @brief Homomorphic multiplication of two ciphertexts followed by relinearization to the lowest level.
     *
     * @param ciphertext1  First input ciphertext.
     * @param ciphertext2  Second input ciphertext.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_mult_and_relinearize(ConstCiphertext<Element>& ciphertext1,
                                               ConstCiphertext<Element>& ciphertext2) const {
        if (!ciphertext1 || !ciphertext2)
            CIPHER_THROW("Input ciphertext is nullptr");

        const auto& eval_key_vec = CryptoContextImpl<Element>::get_eval_mult_key_vector(ciphertext1->get_key_tag());

        if (eval_key_vec.size() <
            (ciphertext1->number_ciphertext_elements() + ciphertext2->number_ciphertext_elements() - 3)) {
            CIPHER_THROW("Insufficient value was used for maxRelinSkDeg to generate keys for EvalMultAndRelinearize");
        }

        return scheme_->eval_mult_and_relinearize(ciphertext1, ciphertext2, eval_key_vec);
    }

    /**
     * @brief Multiplies all ciphertext elements by an unscaled integer without any checks; the level, noise scale
     * degree and scaling factor of the ciphertext are unchanged.
     *
     * @param ctxt  Input ciphertext.
     * @param k     Integer to multiply by.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_mult_no_check(ConstCiphertext<Element>& ctxt, NativeInteger k) const {
        auto result = ctxt->clone();
        auto& cv = result->get_elements();
        uint32_t n = cv.size();
        for (uint32_t i = 0; i < n; ++i)
            cv[i] *= k;
        return result;
    }

    /**
     * @brief Homomorphic multiplication of a ciphertext by a plaintext.
     *
     * @param ciphertext  Multiplier.
     * @param plaintext   Multiplicand.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_mult(ConstCiphertext<Element>& ciphertext, ConstPlaintext& plaintext) const {
        type_check(ciphertext, plaintext);
        return scheme_->eval_mult(ciphertext, plaintext);
    }

    /**
     * @brief Homomorphic multiplication of a plaintext by a ciphertext.
     *
     * @param plaintext   Multiplier.
     * @param ciphertext  Multiplicand.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_mult(ConstPlaintext& plaintext, ConstCiphertext<Element>& ciphertext) const {
        return eval_mult(ciphertext, plaintext);
    }

    /**
     * @brief Homomorphic multiplication of a mutable ciphertext and a plaintext.
     *
     * @param ciphertext  Multiplier (may be modified).
     * @param plaintext   Multiplicand.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_mult_mutable(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        type_check(ciphertext, plaintext);
        return scheme_->eval_mult_mutable(ciphertext, plaintext);
    }

    /**
     * @brief Homomorphic multiplication of a plaintext and a mutable ciphertext.
     *
     * @param plaintext   Multiplier.
     * @param ciphertext  Multiplicand (may be modified).
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_mult_mutable(Plaintext& plaintext, Ciphertext<Element>& ciphertext) const {
        return eval_mult_mutable(ciphertext, plaintext);
    }

    /**
     * @brief Homomorphic multiplication of a ciphertext by a real number (CKKS only).
     *
     * @param ciphertext  Multiplier.
     * @param scalar      Real number multiplicand.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_mult(ConstCiphertext<Element>& ciphertext, double scalar) const {
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");
        return scheme_->eval_mult(ciphertext, scalar);
    }

    /**
     * @brief Homomorphic multiplication of a ciphertext by a real number (CKKS only).
     *
     * @param scalar      Real number multiplier.
     * @param ciphertext  Multiplicand.
     * @return Resulting ciphertext.
     */
    inline Ciphertext<Element> eval_mult(double scalar, ConstCiphertext<Element>& ciphertext) const {
        return eval_mult(ciphertext, scalar);
    }

    /**
     * @brief In-place multiplication of a ciphertext by a real number (CKKS only).
     *
     * @param ciphertext  Ciphertext to modify.
     * @param scalar      Real number multiplicand.
     */
    void eval_mult_in_place(Ciphertext<Element>& ciphertext, double scalar) const {
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");
        scheme_->eval_mult_in_place(ciphertext, scalar);
    }

    /**
     * @brief In-place multiplication of a ciphertext by a real number (CKKS only).
     *
     * @param scalar      Real number multiplier.
     * @param ciphertext  Ciphertext to modify (multiplicand).
     */
    inline void eval_mult_in_place(double scalar, Ciphertext<Element>& ciphertext) const {
        eval_mult_in_place(ciphertext, scalar);
    }

    /**
     * @brief Homomorphic multiplication of a ciphertext by a complex number (CKKS only).
     *
     * @param ciphertext  Multiplier.
     * @param scalar      Complex number multiplicand.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_mult(ConstCiphertext<Element>& ciphertext, std::complex<double> scalar) const {
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");
        return scheme_->eval_mult(ciphertext, scalar);
    }

    /**
     * @brief Homomorphic multiplication of a ciphertext by a complex number (CKKS only).
     *
     * @param scalar      Complex number multiplier.
     * @param ciphertext  Multiplicand.
     * @return Resulting ciphertext.
     */
    inline Ciphertext<Element> eval_mult(std::complex<double> scalar, ConstCiphertext<Element>& ciphertext) const {
        return eval_mult(ciphertext, scalar);
    }

    /**
     * @brief In-place multiplication of a ciphertext by a complex number (CKKS only).
     *
     * @param ciphertext  Ciphertext to modify.
     * @param scalar      Complex number multiplicand.
     */
    void eval_mult_in_place(Ciphertext<Element>& ciphertext, std::complex<double> scalar) const {
        if (!ciphertext)
            CIPHER_THROW("Input ciphertext is nullptr");
        scheme_->eval_mult_in_place(ciphertext, scalar);
    }

    /**
     * @brief In-place multiplication of a ciphertext by a complex number (CKKS only).
     *
     * @param scalar      Complex number multiplier.
     * @param ciphertext  Ciphertext to modify (multiplicand).
     */
    inline void eval_mult_in_place(std::complex<double> scalar, Ciphertext<Element>& ciphertext) const {
        eval_mult_in_place(ciphertext, scalar);
    }

    //------------------------------------------------------------------------------
    // SHE AUTOMORPHISM Wrapper
    //------------------------------------------------------------------------------

    /**
     * @brief Generates automorphism evaluation keys for the given private key.
     *
     * @param private_key   Private key to use for key generation.
     * @param index_list    List of automorphism indices to be computed.
     * @return Map of generated evaluation keys.
     */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_automorphism_key_gen(
            const PrivateKey<Element> private_key, const std::vector<uint32_t>& index_list) const {
        validate_key(private_key);
        if (index_list.empty())
            CIPHER_THROW("Input index vector is empty");
        auto eval_keys = scheme_->eval_automorphism_key_gen(private_key, index_list);
        CryptoContextImpl<Element>::insert_eval_automorphism_key(eval_keys, private_key->get_key_tag());
        return eval_keys;
    }

    /**
     * @brief Applies an automorphism to a ciphertext using the given evaluation keys.
     *
     * @param ciphertext   Input ciphertext.
     * @param i            Automorphism index.
     * @param eval_key_map   Map of evaluation keys generated by eval_automorphism_key_gen.
     * @return Transformed ciphertext.
     */
    Ciphertext<Element> eval_automorphism(ConstCiphertext<Element>& ciphertext, uint32_t i,
                                         const std::map<uint32_t, EvalKey<Element>>& eval_key_map,
                                         CALLER_INFO_ARGS_HDR) const {
        validate_ciphertext(ciphertext);

        if (eval_key_map.empty())
            CIPHER_THROW(std::string("Empty input key map") + CALLER_INFO);

        auto key = eval_key_map.find(i);
        if (key == eval_key_map.end())
            CIPHER_THROW(std::string("Could not find an EvalKey for index ") + std::to_string(i) + CALLER_INFO);

        auto eval_key = key->second;
        validate_key(eval_key);

        return scheme_->eval_automorphism(ciphertext, i, eval_key_map);
    }

    /**
     * @brief Computes the automorphism index for a given vector index.
     *
     * @param idx  Vector index.
     * @return Corresponding automorphism index.
     */
    uint32_t find_automorphism_index(const uint32_t idx) const {
        const auto crypto_params = params_;
        const auto element_params = crypto_params->get_element_params();
        uint32_t m = element_params->get_cyclotomic_order();
        return scheme_->find_automorphism_index(idx, m);
    }

    /**
     * @brief Computes automorphism indices for a list of vector indices.
     *
     * @param idx_list  List of vector indices.
     * @return Vector of corresponding automorphism indices.
     */
    std::vector<uint32_t> find_automorphism_indices(const std::vector<uint32_t>& idx_list) const {
        std::vector<uint32_t> new_indices;
        new_indices.reserve(idx_list.size());
        for (const auto idx : idx_list) {
            new_indices.emplace_back(find_automorphism_index(idx));
        }
        return new_indices;
    }

    /**
     * @brief Rotates a ciphertext by the given index using a stored rotation key.
     *
     * @param ciphertext  Input ciphertext.
     * @param index       Rotation index (positive for left, negative for right).
     * @return Rotated ciphertext.
     */
    Ciphertext<Element> eval_rotate(ConstCiphertext<Element>& ciphertext, int32_t index) const {
        validate_ciphertext(ciphertext);

        auto eval_key_map = CryptoContextImpl<Element>::get_eval_automorphism_key_map(ciphertext->get_key_tag());
        return scheme_->eval_at_index(ciphertext, index, eval_key_map);
    }

    /**
     * @brief implements the precomputation step of hoisted automorphisms.
     *
     * Please refer to Section 5 of Halevi and Shoup, "Faster Homomorphic linear transformations in HELib."
     * for more details, link: https://eprint.iacr.org/2018/244.
     *
     * Generally, automorphisms are performed with three steps:
     * (1) the automorphism is applied on the ciphertext
     * (2) the automorphed values are decomposed into digits
     * (3) key switching is applied to make it possible to further compute on the ciphertext.
     *
     * Hoisted automorphisms is a technique that performs the digit decomposition for the original ciphertext first,
     * and then performs the automorphism and the key switching on the decomposed digits. The benefit of this is that the
     * digit decomposition is independent of the automorphism rotation index, so  it can be reused for
     * multiple different indices. This can greatly improve performance when we have to compute many automorphisms
     * on the same ciphertext. This routinely happens when we do permutations (EvalPermute).
     *
     * it implements the digit decomposition step of hoisted automorphisms.
     *
     * @param ciphertext Input ciphertext on which to do the precomputation (digit decomposition).
     * @return Pointer to precomputed rotation data.
     */
    std::shared_ptr<std::vector<Element>> eval_fast_rotation_precompute(ConstCiphertext<Element>& ciphertext) const {
        return scheme_->eval_fast_rotation_precompute(ciphertext);
    }

    /**
     * @brief Implements the automorphism and key switching step of hoisted automorphisms.
     *
     * Please refer to Section 5 of Halevi and Shoup, "Faster Homomorphic linear transformations in HELib."
     * for more details, link: https://eprint.iacr.org/2018/244.
     *
     * Generally, automorphisms are performed with three steps:
     * (1) the automorphism is applied on the ciphertext
     * (2) the automorphed values are decomposed into digits
     * (3) key switching is applied to make it possible to further compute on the ciphertext.
     *
     * Hoisted automorphisms is a technique that performs the digit decomposition for the original ciphertext first,
     * and then performs the automorphism and the key switching on the decomposed digits. The benefit of this is that the
     * digit decomposition is independent of the automorphism rotation index, so  it can be reused for
     * multiple different indices. This can greatly improve performance when we have to compute many automorphisms
     * on the same ciphertext. This routinely happens when we do permutations (EvalPermute).
     *
     * This method assumes that all required rotation keys exist. This may not be true if we are
     * using baby-step/giant-step key switching. Please refer to Section 5.1 of the above reference and
     * EvalPermuteBGStepHoisted to see how to deal with this issue.
     *
     * @param ciphertext  Input ciphertext.
     * @param index       Rotation index (positive for left, negative for right).
     * @param m           Cyclotomic order.
     * @param digits      Precomputed rotation data (the digit decomposition created by eval_fast_rotation_precompute).
     * @return Rotated ciphertext.
     */
    Ciphertext<Element> eval_fast_rotation(ConstCiphertext<Element>& ciphertext, const uint32_t index, const uint32_t m,
                                         const std::shared_ptr<std::vector<Element>> digits) const {
        return scheme_->eval_fast_rotation(ciphertext, index, m, digits);
    }

    /**
     * @brief Implements the automorphism and key switching step of hoisted automorphisms.
     *
     * Please refer to Section 5 of Halevi and Shoup, "Faster Homomorphic linear transformations in HELib."
     * for more details, link: https://eprint.iacr.org/2018/244.
     *
     * Generally, automorphisms are performed with three steps:
     * (1) the automorphism is applied on the ciphertext
     * (2) the automorphed values are decomposed into digits
     * (3) key switching is applied to make it possible to further compute on the ciphertext.
     *
     * Hoisted automorphisms is a technique that performs the digit decomposition for the original ciphertext first,
     * and then performs the automorphism and the key switching on the decomposed digits. The benefit of this is that the
     * digit decomposition is independent of the automorphism rotation index, so  it can be reused for
     * multiple different indices. This can greatly improve performance when we have to compute many automorphisms
     * on the same ciphertext. This routinely happens when we do permutations (EvalPermute).
     *
     * This method assumes that all required rotation keys exist. This may not be true if we are
     * using baby-step/giant-step key switching. Please refer to Section 5.1 of the above reference and
     * EvalPermuteBGStepHoisted to see how to deal with this issue.
     *
     * The cyclotomic order is computed from the CryptoContext.
     *
     * @param ciphertext  Input ciphertext.
     * @param index       Rotation index (positive for left, negative for right).
     * @param digits      Precomputed rotation data (the digit decomposition created by eval_fast_rotation_precompute).
     * @return Rotated ciphertext.
     */
    Ciphertext<Element> eval_fast_rotation(ConstCiphertext<Element>& ciphertext, const uint32_t index,
                                         const std::shared_ptr<std::vector<Element>> digits) const {
        return eval_fast_rotation(ciphertext, index, get_ring_dimension() * 2, digits);
    }

    /**
     * @brief Performs fast (hoisted) rotation in the extended CRT basis P*Q. Only supported with hybrid key switching.
     *
     * @param ciphertext  Input ciphertext.
     * @param index       Rotation index (positive for left, negative for right).
     * @param digits      Precomputed digits for the ciphertext.
     * @param add_first    If true, the first element c0 is also computed.
     * @return Rotated ciphertext in extended basis.
     */
    Ciphertext<Element> eval_fast_rotation_ext(ConstCiphertext<Element>& ciphertext, uint32_t index,
                                            const std::shared_ptr<std::vector<Element>> digits, bool add_first) const {
        auto eval_key_map = CryptoContextImpl<Element>::get_eval_automorphism_key_map(ciphertext->get_key_tag());
        return scheme_->eval_fast_rotation_ext(ciphertext, index, digits, add_first, eval_key_map);
    }

    /**
     * @brief Scales a ciphertext down from the extended CRT basis P*Q to Q. Only supported with hybrid key switching.
     *
     * @param ciphertext  Input ciphertext in extended basis.
     * @return Scaled ciphertext in basis Q.
     */
    Ciphertext<Element> key_switch_down(ConstCiphertext<Element>& ciphertext) const {
        validate_ciphertext(ciphertext);
        return scheme_->key_switch_down(ciphertext);
    }

    /**
     * @brief Scales down the first polynomial c0 from extended CRT basis P*Q to Q. Only supported with hybrid key switching.
     *
     * @param ciphertext  Input ciphertext in extended basis.
     * @return Scaled polynomial c0 in basis Q.
     */
    Element key_switch_down_first_element(ConstCiphertext<Element>& ciphertext) const {
        validate_ciphertext(ciphertext);
        return scheme_->key_switch_down_first_element(ciphertext);
    }

    /**
     * @brief Extends a ciphertext from basis Q to the extended CRT basis P*Q. Only supported with hybrid key switching.
     *
     * @param ciphertext  Input ciphertext in basis Q.
     * @param add_first    If true, includes the first component c0 in the output.
     * @return Extended ciphertext in basis P*Q.
     */
    Ciphertext<Element> key_switch_ext(ConstCiphertext<Element>& ciphertext, bool add_first) const {
        validate_ciphertext(ciphertext);
        return scheme_->key_switch_ext(ciphertext, add_first);
    }

    /**
     * @brief Generates evaluation keys for a list of rotation indices.
     *
     * @param private_key  Private key used for key generation.
     * @param index_list   List of rotation indices.
     */
    void eval_at_index_key_gen(const PrivateKey<Element> private_key, const std::vector<int32_t>& index_list);

    /**
     * @brief Generates rotation evaluation keys for a list of indices. Internally calls eval_at_index_key_gen.
     *
     * @param private_key  Private key used for key generation.
     * @param index_list   List of rotation indices.
     */
    void eval_rotate_key_gen(const PrivateKey<Element> private_key, const std::vector<int32_t>& index_list) {
        eval_at_index_key_gen(private_key, index_list);
    };

    /**
     * @brief Rotates a ciphertext by the given index using stored rotation keys.
     *        Positive index = left shift; negative index = right shift.
     *
     * @param ciphertext  Input ciphertext.
     * @param index       Rotation index.
     * @return Rotated ciphertext.
     */
    Ciphertext<Element> eval_at_index(ConstCiphertext<Element>& ciphertext, int32_t index) const;

    //------------------------------------------------------------------------------
    // SHE Leveled Methods Wrapper
    //------------------------------------------------------------------------------

    /**
     * @brief Performs multiplication, relinearization, and rescaling in one step.
     *        Uses a relinearization key from the crypto context.
     *
     * @param ciphertext1  First ciphertext.
     * @param ciphertext2  Second ciphertext.
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> composed_eval_mult(ConstCiphertext<Element>& ciphertext1,
                                         ConstCiphertext<Element>& ciphertext2) const {
        validate_ciphertext(ciphertext1);
        validate_ciphertext(ciphertext2);

        auto eval_key_vec = CryptoContextImpl<Element>::get_eval_mult_key_vector(ciphertext1->get_key_tag());
        if (eval_key_vec.empty())
            CIPHER_THROW("Evaluation key has not been generated for EvalMult");

        return scheme_->composed_eval_mult(ciphertext1, ciphertext2, eval_key_vec[0]);
    }

    /**
     * @brief Rescales a ciphertext by reducing its modulus (alias for mod_reduce in CKKS).
     *
     * @param ciphertext  Input ciphertext.
     * @return Rescaled ciphertext.
     */
    Ciphertext<Element> rescale(ConstCiphertext<Element>& ciphertext) const {
        validate_ciphertext(ciphertext);
        return scheme_->mod_reduce(ciphertext, get_composite_degree_from_ctxt());
    }

    /**
     * @brief In-place rescaling of a ciphertext (alias for mod_reduce_in_place in CKKS).
     *
     * @param ciphertext  Ciphertext to rescale.
     */
    void rescale_in_place(Ciphertext<Element>& ciphertext) const {
        validate_ciphertext(ciphertext);
        scheme_->mod_reduce_in_place(ciphertext, get_composite_degree_from_ctxt());
    }

    /**
     * @brief Performs modulus reduction on a ciphertext (used in BGV/CKKS).
     *
     * @param ciphertext  Input ciphertext.
     * @return Modulus-reduced ciphertext.
     */
    Ciphertext<Element> mod_reduce(ConstCiphertext<Element>& ciphertext) const {
        validate_ciphertext(ciphertext);
        return scheme_->mod_reduce(ciphertext, get_composite_degree_from_ctxt());
    }

    /**
     * @brief In-place modulus reduction of a ciphertext (used in BGV/CKKS).
     *
     * @param ciphertext  Ciphertext to reduce.
     */
    void mod_reduce_in_place(Ciphertext<Element>& ciphertext) const {
        validate_ciphertext(ciphertext);
        scheme_->mod_reduce_in_place(ciphertext, get_composite_degree_from_ctxt());
    }

    /**
     * @brief Reduces the number of RNS limbs (levels) in a ciphertext.
     *
     * @param ciphertext  Input ciphertext.
     * @param eval_key     Evaluation key (currently unused; kept for API compatibility).
     * @param levels      Number of levels to drop.
     * @return Ciphertext with reduced levels.
     *
     * @note Supported in BGV and CKKS. In CKKS with COMPOSITESCALING*, levels are scaled by the composite degree.
     */
    Ciphertext<Element> level_reduce(ConstCiphertext<Element>& ciphertext, const EvalKey<Element> eval_key,
                                    size_t levels = 1) const {
        validate_ciphertext(ciphertext);
        return scheme_->level_reduce(ciphertext, eval_key, levels * get_composite_degree_from_ctxt());
    }

    /**
     * @brief In-place reduction of RNS limbs (levels) in a ciphertext.
     *
     * @param ciphertext  Ciphertext to modify.
     * @param eval_key     Evaluation key (currently unused; kept for API compatibility).
     * @param levels      Number of levels to drop.
     *
     * @note Supported in BGV and CKKS. In CKKS with COMPOSITESCALING*, levels are scaled by the composite degree.
     */
    void level_reduce_in_place(Ciphertext<Element>& ciphertext, const EvalKey<Element> eval_key, size_t levels = 1) const {
        validate_ciphertext(ciphertext);
        if (levels > 0)
            scheme_->level_reduce_in_place(ciphertext, eval_key, levels * get_composite_degree_from_ctxt());
    }

    /**
     * @brief Compresses a ciphertext by reducing its modulus to lower communication cost.
     *
     * @param ciphertext     Input ciphertext.
     * @param towers_left     Number of RNS limbs to retain.
     * @param noise_scale_deg  Noise scale degree the ciphertext is reduced to before dropping limbs (must not exceed towers_left).
     * @return Compressed ciphertext.
     */
    Ciphertext<Element> compress(ConstCiphertext<Element>& ciphertext, uint32_t towers_left = 1,
                                 size_t noise_scale_deg = 1) const {
        if (ciphertext == nullptr)
            CIPHER_THROW("input ciphertext is invalid (has no data)");
        if (towers_left < noise_scale_deg) {
            std::string error_msg{"Input towersLeft["};
            error_msg += std::to_string(towers_left) + "] may not be less than noiseScaleDeg[";
            error_msg += std::to_string(noise_scale_deg) + "]";
            CIPHER_THROW(error_msg);
        }
        return scheme_->compress(ciphertext, towers_left, noise_scale_deg);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE Wrapper
    //------------------------------------------------------------------------------

    /**
     * @brief Homomorphic addition of multiple ciphertexts (null entries are skipped).
     *
     * @param ciphertext_vec  Vector of ciphertexts.
     * @return Resulting ciphertext; never aliases an input, so it is always safe to mutate.
     */
    Ciphertext<Element> eval_add_many(const std::vector<Ciphertext<Element>>& ciphertext_vec) const {
        if (ciphertext_vec.empty())
            CIPHER_THROW("Empty input ciphertext vector");
        return scheme_->eval_add_many(ciphertext_vec);
    }

    /**
     * @brief In-place homomorphic addition of multiple ciphertexts (null entries are skipped; the result is also left in slot 0 of the vector).
     *
     * @param ciphertext_vec  Vector of ciphertexts (modified in place to store intermediate results).
     * @return Resulting ciphertext.
     */
    Ciphertext<Element> eval_add_many_in_place(std::vector<Ciphertext<Element>>& ciphertext_vec) const {
        if (ciphertext_vec.empty())
            CIPHER_THROW("Empty input ciphertext vector");
        return scheme_->eval_add_many_in_place(ciphertext_vec);
    }

    /**
     * @brief Homomorphic multiplication of multiple ciphertexts using a binary tree approach,
     *        followed by relinearization to reduce ciphertext size to two elements after each multiplication.
     *
     * @param ciphertext_vec  Vector of ciphertexts to multiply.
     * @return Resulting ciphertext.
     *
     * @note Assumes each multiplication produces a ciphertext within the supported ring size
     *       (for the secret key degree used by eval_mult_keys_gen).
     *       Otherwise, it throws an error
     */
    Ciphertext<Element> eval_mult_many(const std::vector<Ciphertext<Element>>& ciphertext_vec) const {
        if (ciphertext_vec.empty())
            CIPHER_THROW("Empty input ciphertext vector");
        if (ciphertext_vec.size() == 1)
            return ciphertext_vec[0]->clone();
        const auto eval_key_vec = CryptoContextImpl<Element>::get_eval_mult_key_vector(ciphertext_vec[0]->get_key_tag());
        if (eval_key_vec.size() < (ciphertext_vec[0]->number_ciphertext_elements() - 2))
            CIPHER_THROW("Insufficient value was used for maxRelinSkDeg to generate keys");
        return scheme_->eval_mult_many(ciphertext_vec, eval_key_vec);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE LINEAR WEIGHTED SUM
    //------------------------------------------------------------------------------

    /**
     * @brief Computes a linear weighted sum of ciphertexts (CKKS only).
     *
     * @param ciphertext_vec  List of ciphertexts.
     * @param constant_vec    Corresponding weights.
     * @return Weighted sum as a ciphertext.
     */
    template <typename VectorDataType = double>
    Ciphertext<Element> eval_linear_w_sum(std::vector<ReadOnlyCiphertext<Element>>& ciphertext_vec,
                                       const std::vector<VectorDataType>& constant_vec) const {
        return scheme_->eval_linear_w_sum(ciphertext_vec, constant_vec);
    }

    /**
     * @brief Computes a linear weighted sum of ciphertexts (CKKS only).
     *
     * @param constants_vec   Corresponding weights.
     * @param ciphertext_vec  List of ciphertexts.
     * @return Weighted sum as a ciphertext.
     */
    template <typename VectorDataType = double>
    Ciphertext<Element> eval_linear_w_sum(const std::vector<VectorDataType>& constants_vec,
                                       std::vector<ReadOnlyCiphertext<Element>>& ciphertext_vec) const {
        return eval_linear_w_sum(ciphertext_vec, constants_vec);
    }

    /**
     * @brief Computes a linear weighted sum using mutable ciphertexts (CKKS only).
     *
     * @param ciphertext_vec  List of mutable ciphertexts.
     * @param constants_vec   Corresponding weights.
     * @return Weighted sum as a ciphertext.
     */
    template <typename VectorDataType = double>
    Ciphertext<Element> eval_linear_w_sum_mutable(std::vector<Ciphertext<Element>>& ciphertext_vec,
                                              const std::vector<VectorDataType>& constants_vec) const {
        return scheme_->eval_linear_w_sum_mutable(ciphertext_vec, constants_vec);
    }

    /**
     * @brief Computes a linear weighted sum using mutable ciphertexts (CKKS only).
     *
     * @param constants_vec   Corresponding weights.
     * @param ciphertext_vec  List of mutable ciphertexts.
     * @return Weighted sum as a ciphertext.
     */
    template <typename VectorDataType = double>
    Ciphertext<Element> eval_linear_w_sum_mutable(const std::vector<VectorDataType>& constants_vec,
                                              std::vector<Ciphertext<Element>>& ciphertext_vec) const {
        return eval_linear_w_sum_mutable(ciphertext_vec, constants_vec);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL POLYNOMIAL
    //------------------------------------------------------------------------------

    /**
     * @brief Computes the powers of a ciphertext to be used when evaluating a polynomial (CKKS only).
     *        Uses EvalPowersLinear() for low polynomial degrees (degree < 5), or EvalPowersPS() for higher degrees.
     *
     * @param ciphertext    Input ciphertext.
     * @param coefficients  Polynomial coefficients (vector's size = (degree + 1)).
     * @return Resulting structure of powers.
     */

    template <typename VectorDataType = double>
    std::shared_ptr<SeriesPowers<Element>> eval_powers(ConstCiphertext<Element>& ciphertext,
                                                      const std::vector<VectorDataType>& coefficients) const {
        validate_ciphertext(ciphertext);
        return scheme_->eval_powers(ciphertext, coefficients);
    }

    /**
     * @brief Evaluates a polynomial (given as a power series) on a ciphertext (CKKS only).
     *        Use eval_poly_linear() for low polynomial degrees (degree < 5), or eval_poly_ps() for higher degrees.
     *
     * @param ciphertext    Input ciphertext.
     * @param coefficients  Polynomial coefficients (vector's size = (degree + 1)).
     * @return Resulting ciphertext.
     */

    template <typename VectorDataType = double>
    Ciphertext<Element> eval_poly(ConstCiphertext<Element>& ciphertext,
                                 const std::vector<VectorDataType>& coefficients) const {
        validate_ciphertext(ciphertext);
        return scheme_->eval_poly(ciphertext, coefficients);
    }

    /**
     * @brief Evaluates a polynomial (given as a power series) from the powers of a ciphertext precomputed
     *        by eval_powers (CKKS only). The powers are left unmodified, so the same precomputation can be
     *        reused for further polynomials of the same degree as the one it was computed for (below degree 5,
     *        eval_powers builds only the powers its coefficients need, so the nonzero terms must match as well).
     *
     * @param powers        Powers of the input ciphertext, as returned by eval_powers.
     * @param coefficients  Polynomial coefficients (vector's size = (degree + 1)).
     * @return Resulting ciphertext.
     */
    template <typename VectorDataType = double>
    Ciphertext<Element> eval_poly_with_precomp(std::shared_ptr<SeriesPowers<Element>> powers,
                                            const std::vector<VectorDataType>& coefficients) const {
        validate_series_powers(powers);
        return scheme_->eval_poly_with_precomp(powers, coefficients);
    }

    /**
     * @brief Naive polynomial evaluation using a binary tree approach (efficient for low-degree polynomials, <10).
     *        Polynomials are given as a power series. Supported only in CKKS.
     *
     * @param ciphertext    Input ciphertext.
     * @param coefficients  Polynomial coefficients (vector's size = (degree + 1)).
     * @return Resulting ciphertext.
     */
    template <typename VectorDataType = double>
    Ciphertext<Element> eval_poly_linear(ConstCiphertext<Element>& ciphertext,
                                       const std::vector<VectorDataType>& coefficients) const {
        validate_ciphertext(ciphertext);
        return scheme_->eval_poly_linear(ciphertext, coefficients);
    }

    /**
     * @brief Evaluates a polynomial (given as a power series) using the Paterson-Stockmeyer method (efficient for high-degree polynomials).
     *        Supported only in CKKS.
     *
     * @param ciphertext    Input ciphertext.
     * @param coefficients  Polynomial coefficients (vector's size = (degree + 1)).
     * @return Resulting ciphertext.
     */
    template <typename VectorDataType = double>
    Ciphertext<Element> eval_poly_ps(ConstCiphertext<Element>& ciphertext,
                                   const std::vector<VectorDataType>& coefficients) const {
        validate_ciphertext(ciphertext);
        return scheme_->eval_poly_ps(ciphertext, coefficients);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL CHEBYSHEV SERIES
    //------------------------------------------------------------------------------

    /**
     * @brief Computes the Chebyshev polynomials for a ciphertext to be used when evaluating a Chebyshev series (CKKS only).
     *        Maps [a, b] to [-1, 1] using the linear transformation 1 + 2(x-a)/(b-a), then computes the polynomials
     *        needed by eval_chebyshev_series_linear (degree < 5) or eval_chebyshev_series_ps (higher degrees) depending on degree.
     *
     * @param ciphertext    Input ciphertext.
     * @param coefficients  Polynomial coefficients (vector's size = (degree + 1)).
     * @param a             Lower bound of argument for which the coefficients were found.
     * @param b             Upper bound of argument for which the coefficients were found.
     * @return Resulting structure of Chebyshev polynomials.
     */

    template <typename VectorDataType = double>
    std::shared_ptr<SeriesPowers<Element>> eval_cheby_polys(ConstCiphertext<Element>& ciphertext,
                                                          const std::vector<VectorDataType>& coefficients, double a,
                                                          double b) const {
        validate_ciphertext(ciphertext);
        return scheme_->eval_cheby_polys(ciphertext, coefficients, a, b);
    }

    /**
     * @brief Evaluates a Chebyshev interpolated polynomial on a ciphertext.
     *        Uses a linear transformation to map [a, b] to [-1, 1] using linear transformation 1 + 2(x-a)/(b-a),
     *        then applies either eval_chebyshev_series_linear (degree < 5) or eval_chebyshev_series_ps depending on degree.
     *        Supported only in CKKS.
     *
     * @param ciphertext    Input ciphertext.
     * @param coefficients  Chebyshev series coefficients.
     * @param a             Lower bound of argument for which the coefficients were found.
     * @param b             Upper bound of argument for which the coefficients were found.
     * @return Resulting ciphertext.
     */
    template <typename VectorDataType = double>
    Ciphertext<Element> eval_chebyshev_series(ConstCiphertext<Element>& ciphertext,
                                            const std::vector<VectorDataType>& coefficients, double a, double b) const {
        validate_ciphertext(ciphertext);
        return scheme_->eval_chebyshev_series(ciphertext, coefficients, a, b);
    }

    /**
     * @brief Evaluates a Chebyshev series from the Chebyshev polynomials of a ciphertext precomputed by
     *        eval_cheby_polys (CKKS only). The polynomials are left unmodified, so the same precomputation
     *        can be reused for further series of the same degree as the one it was computed for.
     *
     * @param polys         Chebyshev polynomials of the input ciphertext, as returned by eval_cheby_polys.
     * @param coefficients  Chebyshev series coefficients.
     * @return Resulting ciphertext.
     */
    template <typename VectorDataType = double>
    Ciphertext<Element> eval_chebyshev_series_with_precomp(std::shared_ptr<SeriesPowers<Element>> polys,
                                                       const std::vector<VectorDataType>& coefficients) const {
        validate_series_powers(polys);
        return scheme_->eval_chebyshev_series_with_precomp(polys, coefficients);
    }

    /**
     * @brief Evaluates a Chebyshev interpolated polynomial using a naive linear method.
     *        Maps [a, b] to [-1, 1] using linear transformation 1 + 2(x-a)/(b-a). Supported only in CKKS.
     *
     * @param ciphertext    Input ciphertext.
     * @param coefficients  Chebyshev series coefficients.
     * @param a             Lower bound of argument for which the coefficients were found.
     * @param b             Upper bound of argument for which the coefficients were found.
     * @return Resulting ciphertext.
     */
    template <typename VectorDataType = double>
    Ciphertext<Element> eval_chebyshev_series_linear(ConstCiphertext<Element>& ciphertext,
                                                  const std::vector<VectorDataType>& coefficients, double a,
                                                  double b) const {
        validate_ciphertext(ciphertext);
        return scheme_->eval_chebyshev_series_linear(ciphertext, coefficients, a, b);
    }

    /**
     * @brief Evaluates a Chebyshev interpolated polynomial using the Paterson-Stockmeyer method.
     *        Maps [a, b] to [-1, 1] using linear transformation 1 + 2(x-a)/(b-a). Supported only in CKKS.
     *
     * @param ciphertext    Input ciphertext.
     * @param coefficients  Chebyshev series coefficients.
     * @param a             Lower bound of argument for which the coefficients were found.
     * @param b             Upper bound of argument for which the coefficients were found.
     * @return Resulting ciphertext.
     */
    template <typename VectorDataType = double>
    Ciphertext<Element> eval_chebyshev_series_ps(ConstCiphertext<Element>& ciphertext,
                                              const std::vector<VectorDataType>& coefficients, double a,
                                              double b) const {
        validate_ciphertext(ciphertext);
        return scheme_->eval_chebyshev_series_ps(ciphertext, coefficients, a, b);
    }

    /**
     * @brief Evaluates a smooth function on a ciphertext using Chebyshev polynomial approximation over [a, b].
     *        Supported only in CKKS.
     *
     * @param func        Function to approximate.
     * @param ciphertext  Input ciphertext.
     * @param a           Lower bound of argument for which the coefficients were found.
     * @param b           Upper bound of argument for which the coefficients were found.
     * @param degree      Degree of the Chebyshev approximation.
     * @return Ciphertext after function evaluation.
     */
    Ciphertext<Element> eval_chebyshev_function(std::function<double(double)> func, ConstCiphertext<Element>& ciphertext,
                                              double a, double b, uint32_t degree) const;

    /**
     * @brief Evaluates an approximate sine function on a ciphertext using Chebyshev approximation.
     *        Supported only in CKKS.
     *
     * @param ciphertext  Input ciphertext.
     * @param a           Lower bound of argument for which the coefficients were found.
     * @param b           Upper bound of argument for which the coefficients were found.
     * @param degree      Degree of the Chebyshev approximation.
     * @return Ciphertext after sine approximation.
     */
    Ciphertext<Element> eval_sin(ConstCiphertext<Element>& ciphertext, double a, double b, uint32_t degree) const;

    /**
     * @brief Evaluates an approximate cosine function on a ciphertext using Chebyshev approximation.
     *        Supported only in CKKS.
     *
     * @param ciphertext  Input ciphertext.
     * @param a           Lower bound of argument for which the coefficients were found.
     * @param b           Upper bound of argument for which the coefficients were found.
     * @param degree      Degree of the Chebyshev approximation.
     * @return Ciphertext after cosine approximation.
     */
    Ciphertext<Element> eval_cos(ConstCiphertext<Element>& ciphertext, double a, double b, uint32_t degree) const;

    /**
     * @brief Evaluates an approximate logistic function 1 / (1 + exp(-x)) on a ciphertext using Chebyshev approximation.
     *        Supported only in CKKS.
     *
     * @param ciphertext  Input ciphertext.
     * @param a           Lower bound of argument for which the coefficients were found.
     * @param b           Upper bound of argument for which the coefficients were found.
     * @param degree      Degree of the Chebyshev approximation.
     * @return Ciphertext after logistic approximation.
     */
    Ciphertext<Element> eval_logistic(ConstCiphertext<Element>& ciphertext, double a, double b, uint32_t degree) const;

    /**
     * @brief Evaluates an approximate reciprocal function 1 / x (for x ≥ 1) on a ciphertext using Chebyshev approximation.
     *        Supported only in CKKS.
     *
     * @param ciphertext  Input ciphertext.
     * @param a           Lower bound of argument for which the coefficients were found.
     * @param b           Upper bound of argument for which the coefficients were found.
     * @param degree      Degree of the Chebyshev approximation.
     * @return Ciphertext after reciprocal approximation.
     */
    Ciphertext<Element> eval_divide(ConstCiphertext<Element>& ciphertext, double a, double b, uint32_t degree) const;

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL SUM
    //------------------------------------------------------------------------------

    /**
     * @brief Generates evaluation keys required for homomorphic summation (eval_sum).
     *
     * @param private_key  Private key used for key generation.
     */
    void eval_sum_key_gen(const PrivateKey<Element> private_key);

    /**
     * @brief Generates automorphism keys for eval_sum_rows (only for packed encoding).
     *
     * @param private_key    Private key used for key generation.
     * @param row_size       Number of slots per row in the packed matrix.
     * @param subring_dim    Subring dimension (use cyclotomic order if 0).
     * @return Map of generated evaluation keys.
     */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_rows_key_gen(const PrivateKey<Element> private_key,
                                                                            uint32_t row_size = 0,
                                                                            uint32_t subring_dim = 0);

    /**
     * @brief Generates automorphism keys for eval_sum_rows (only for packed encoding). Kept for backwards
     * compatibility; the public key is unused.
     *
     * @param private_key    Private key used for key generation.
     * @param public_key     Unused.
     * @param row_size       Number of slots per row in the packed matrix.
     * @param subring_dim    Subring dimension (use cyclotomic order if 0).
     * @return Map of generated evaluation keys.
     */
    // TODO: this is here for backwards compatibility; should remove in v2.0
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_rows_key_gen(const PrivateKey<Element> private_key,
                                                                            const PublicKey<Element> public_key,
                                                                            uint32_t row_size = 0,
                                                                            uint32_t subring_dim = 0);

    /**
     * @brief Generates automorphism keys for eval_sum_cols (only for packed encoding).
     *
     * @param private_key  Private key used for key generation.
     * @return Map of generated evaluation keys.
     */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_sum_cols_key_gen(const PrivateKey<Element> private_key);

    /**
     * @brief Computes the sum of all components in a packed ciphertext vector.
     *
     * @param ciphertext  Input ciphertext.
     * @param batch_size   Number of slots to sum over.
     * @return Resulting ciphertext containing the sum.
     */
    Ciphertext<Element> eval_sum(ConstCiphertext<Element>& ciphertext, uint32_t batch_size) const;

    /**
     * @brief Sums all elements across each row in a packed-encoded matrix ciphertext.
     *
     * @param ciphertext      Input ciphertext.
     * @param num_rows         Number of rows in the matrix.
     * @param eval_sum_key_map   Map of evaluation keys generated for row summation.
     * @param subring_dim      Subring dimension (use full cyclotomic order if 0).
     * @return Ciphertext containing row-wise sums.
     */
    Ciphertext<Element> eval_sum_rows(ConstCiphertext<Element>& ciphertext, uint32_t num_rows,
                                    const std::map<uint32_t, EvalKey<Element>>& eval_sum_key_map,
                                    uint32_t subring_dim = 0) const;

    /**
     * @brief Sums all elements across each column in a packed-encoded matrix ciphertext.
     *
     * @param ciphertext      Input ciphertext.
     * @param num_cols         Number of columns in the matrix.
     * @param eval_sum_key_map   Map of evaluation keys generated for column summation.
     * @return Ciphertext containing column-wise sums.
     */
    Ciphertext<Element> eval_sum_cols(ConstCiphertext<Element>& ciphertext, uint32_t num_cols,
                                    const std::map<uint32_t, EvalKey<Element>>& eval_sum_key_map) const;

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL INNER PRODUCT
    //------------------------------------------------------------------------------

    /**
     * @brief Computes the inner product of two ciphertext vectors using packed encoding and eval_sum.
     *
     * @param ciphertext1  First input ciphertext vector.
     * @param ciphertext2  Second input ciphertext vector.
     * @param batch_size    Number of slots to sum over.
     * @return Ciphertext containing the inner product.
     */
    Ciphertext<Element> eval_inner_product(ConstCiphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2,
                                         uint32_t batch_size) const;

    /**
     * @brief Computes the inner product of a ciphertext and a plaintext using packed encoding and eval_sum.
     *
     * @param ciphertext  Encrypted input vector.
     * @param plaintext   Plaintext input vector.
     * @param batch_size   Number of slots to sum over.
     * @return Ciphertext containing the inner product.
     */
    Ciphertext<Element> eval_inner_product(ConstCiphertext<Element>& ciphertext, ConstPlaintext& plaintext,
                                         uint32_t batch_size) const;

    /**
     * @brief Merges multiple ciphertexts with values in slot 0 into a single packed ciphertext.
     *
     * @param ciphertext_vec  Vector of ciphertexts to merge.
     * @return Merged ciphertext with values placed into slots in order.
     *
     * @note Requires rotation keys for the necessary indices.
     */
    Ciphertext<Element> eval_merge(const std::vector<Ciphertext<Element>>& ciphertext_vec) const;

    //------------------------------------------------------------------------------
    // PRE Wrapper
    //------------------------------------------------------------------------------

    /**
     * @brief Generates a re-encryption key for Proxy Re-Encryption (PRE).
     *
     * @param old_private_key  Original private key.
     * @param new_public_key   Public key of the target recipient.
     * @return Re-encryption evaluation key.
     */
    EvalKey<Element> re_key_gen(const PrivateKey<Element> old_private_key, const PublicKey<Element> new_public_key) const {
        validate_key(old_private_key);
        validate_key(new_public_key);
        validate_pre_mode();
        return scheme_->re_key_gen(old_private_key, new_public_key);
    }

    /**
     * @brief Produces an Eval Key that Cipher can use for Proxy Re-Encryption
     *
     * @param original_private_key original secret key
     * @param new_private_key new secret key
     * @return new evaluation key
     * @attention This functionality has been completely removed from Cipher
     */
    EvalKey<Element> re_key_gen(const PrivateKey<Element> original_private_key,
                              const PrivateKey<Element> new_private_key) const
            __attribute__((deprecated("functionality removed from Cipher")));

    /**
     * @brief Re-encrypts a ciphertext using a re-encryption key for Proxy Re-Encryption.
     *
     * @param ciphertext  Input ciphertext.
     * @param eval_key     Re-encryption key.
     * @param public_key   Optional public key of the recipient.
     * @return Re-encrypted ciphertext.
     */
    Ciphertext<Element> re_encrypt(ConstCiphertext<Element>& ciphertext, EvalKey<Element> eval_key,
                                  const PublicKey<Element> public_key = nullptr) const {
        validate_ciphertext(ciphertext);
        validate_key(eval_key);
        validate_pre_mode();
        return scheme_->re_encrypt(ciphertext, eval_key, public_key);
    }

    //------------------------------------------------------------------------------
    // Multiparty Wrapper
    //------------------------------------------------------------------------------

    /**
     * @brief Generates a joined public key from a set of secret key shares (Threshold FHE).
     *
     * @param private_key_vec  Vector of secret key shares.
     * @return Key pair containing this party's private key and the joined public key.
     *
     * @attention Only for debugging purposes. Not for production use.
     */
    KeyPair<Element> multiparty_key_gen(const std::vector<PrivateKey<Element>>& private_key_vec) {
        if (private_key_vec.empty())
            CIPHER_THROW("Input private key vector is empty");
        return scheme_->multiparty_key_gen(get_context_for_pointer(this), private_key_vec, false);
    }

    /**
     * @brief Generates a joined public key using a prior public key and the current party's secret share (Threshold FHE).
     *
     * @param public_key   joined public key from prior parties.
     * @param make_sparse_value  Use ring reduction (no longer supported).
     * @param fresh       Indicates if proxy re-encryption is used in the multi-party protocol or star topology is used.
     * @return Key pair containing this party's private key and the updated joined public key.
     */
    KeyPair<Element> multiparty_key_gen(const PublicKey<Element> public_key, bool make_sparse_value = false, bool fresh = false) {
        if (!public_key)
            CIPHER_THROW("Input public key is empty");
        return scheme_->multiparty_key_gen(get_context_for_pointer(this), public_key, make_sparse_value, fresh);
    }

    /**
     * @brief Performs partial decryption as the lead decryption party (Threshold FHE).
     *
     * @param ciphertext_vec  Vector of ciphertexts to decrypt.
     * @param private_key     Secret key share of the lead party.
     * @return Vector of partially decrypted ciphertexts.
     */
    std::vector<Ciphertext<Element>> multiparty_decrypt_lead(const std::vector<Ciphertext<Element>>& ciphertext_vec,
                                                           const PrivateKey<Element> private_key) const {
        validate_key(private_key);
        std::vector<Ciphertext<Element>> new_ciphertext_vec;
        new_ciphertext_vec.reserve(ciphertext_vec.size());
        for (const auto& ciphertext : ciphertext_vec) {
            validate_ciphertext(ciphertext);
            new_ciphertext_vec.push_back(scheme_->multiparty_decrypt_lead(ciphertext, private_key));
        }
        return new_ciphertext_vec;
    }

    /**
     * @brief Performs partial decryption by non-lead parties in a Threshold FHE setting.
     *
     * @param ciphertext_vec  Vector of ciphertexts to decrypt.
     * @param private_key     Secret key share of a non-lead party.
     * @return Vector of partially decrypted ciphertexts.
     */
    std::vector<Ciphertext<Element>> multiparty_decrypt_main(const std::vector<Ciphertext<Element>>& ciphertext_vec,
                                                           const PrivateKey<Element> private_key) const {
        validate_key(private_key);
        std::vector<Ciphertext<Element>> new_ciphertext_vec;
        new_ciphertext_vec.reserve(ciphertext_vec.size());
        for (const auto& ciphertext : ciphertext_vec) {
            validate_ciphertext(ciphertext);
            new_ciphertext_vec.push_back(scheme_->multiparty_decrypt_main(ciphertext, private_key));
        }
        return new_ciphertext_vec;
    }

    /**
     * @brief Combines partially decrypted ciphertexts into the final plaintext result (Threshold FHE).
     *
     * @param partial_ciphertext_vec  Vector of partial decryptions.
     * @param plaintext             Output plaintext.
     * @return Decoding result.
     */
    DecryptResult multiparty_decrypt_fusion(const std::vector<Ciphertext<Element>>& partial_ciphertext_vec,
                                          Plaintext* plaintext) const {
        std::string datatype = demangle(typeid(Element).name());
        CIPHER_THROW("Not implemented for " + datatype);
    }

    /**
     * @brief Generates a new joined evaluation key from a prior key and secret key shares (Threshold FHE).
     *
     * @param original_private_key  Original private key.
     * @param new_private_key       New private key.
     * @param eval_key             Prior joined evaluation key.
     * @return New joined evaluation key.
     */
    EvalKey<Element> multi_key_switch_gen(const PrivateKey<Element> original_private_key,
                                       const PrivateKey<Element> new_private_key, const EvalKey<Element> eval_key) const {
        if (!original_private_key)
            CIPHER_THROW("Input first private key is nullptr");
        if (!new_private_key)
            CIPHER_THROW("Input second private key is nullptr");
        if (!eval_key)
            CIPHER_THROW("Input evaluation key is nullptr");
        return scheme_->multi_key_switch_gen(original_private_key, new_private_key, eval_key);
    }

    /**
     * @brief Generates joined automorphism keys from the current secret share and prior keys (Threshold FHE).
     *
     * @param private_key   Secret key share.
     * @param eval_key_map   Prior joined automorphism keys.
     * @param index_list    List of automorphism indices.
     * @param key_tag       Secret key tag (optional).
     * @return Map of updated joined automorphism keys.
     */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> multi_eval_automorphism_key_gen(
            const PrivateKey<Element> private_key,
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map,
            const std::vector<uint32_t>& index_list, const std::string& key_tag = "") {
        if (!private_key)
            CIPHER_THROW("Input private key is nullptr");
        if (!eval_key_map)
            CIPHER_THROW("Input evaluation key map is nullptr");
        if (index_list.empty())
            CIPHER_THROW("Input index vector is empty");
        return scheme_->multi_eval_automorphism_key_gen(private_key, eval_key_map, index_list, key_tag);
    }

    /**
     * @brief Generates joined rotation keys from the current secret share and prior keys (Threshold FHE).
     *
     * @param private_key   Secret key share.
     * @param eval_key_map   Prior joined rotation keys.
     * @param index_list    List of rotation indices.
     * @param key_tag       Secret key tag (optional).
     * @return Map of updated joined rotation keys.
     */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> multi_eval_at_index_key_gen(
            const PrivateKey<Element> private_key,
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map,
            const std::vector<int32_t>& index_list, const std::string& key_tag = "") {
        if (!private_key)
            CIPHER_THROW("Input private key is nullptr");
        if (!eval_key_map)
            CIPHER_THROW("Input evaluation key map is nullptr");
        if (index_list.empty())
            CIPHER_THROW("Input index vector is empty");
        return scheme_->multi_eval_at_index_key_gen(private_key, eval_key_map, index_list, key_tag);
    }

    /**
     * @brief Generates joined summation evaluation keys from the current secret share and prior keys (Threshold FHE).
     *
     * @param private_key   Secret key share.
     * @param eval_key_map   Prior summation evaluation keys.
     * @param key_tag       Secret key tag (optional).
     * @return Map of updated summation evaluation keys.
     */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> multi_eval_sum_key_gen(
            const PrivateKey<Element> private_key,
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map, const std::string& key_tag = "") {
        if (!private_key)
            CIPHER_THROW("Input private key is nullptr");
        if (!eval_key_map)
            CIPHER_THROW("Input evaluation key map is nullptr");
        return scheme_->multi_eval_sum_key_gen(private_key, eval_key_map, key_tag);
    }

    /**
     * @brief Adds two evaluation keys to produce a new joined evaluation key (Threshold FHE).
     *
     * @param eval_key1  First evaluation key.
     * @param eval_key2  Second evaluation key.
     * @param key_tag    Secret key tag (optional).
     * @return Joined evaluation key.
     */
    EvalKey<Element> multi_add_eval_keys(EvalKey<Element> eval_key1, EvalKey<Element> eval_key2,
                                      const std::string& key_tag = "") {
        if (!eval_key1)
            CIPHER_THROW("Input first evaluation key is nullptr");
        if (!eval_key2)
            CIPHER_THROW("Input second evaluation key is nullptr");
        return scheme_->multi_add_eval_keys(eval_key1, eval_key2, key_tag);
    }

    /**
     * @brief Generates a joined partial evaluation key for homomorphic multiplication from a partial key and current secret share (Threshold FHE).
     *
     * @param private_key  Current secret share.
     * @param eval_key     Prior partial evaluation key.
     * @param key_tag      Secret key tag (optional).
     * @return Joined evaluation key.
     */
    EvalKey<Element> multi_mult_eval_key(PrivateKey<Element> private_key, EvalKey<Element> eval_key,
                                      const std::string& key_tag = "") {
        if (!private_key)
            CIPHER_THROW("Input private key is nullptr");
        if (!eval_key)
            CIPHER_THROW("Input evaluation key is nullptr");
        return scheme_->multi_mult_eval_key(private_key, eval_key, key_tag);
    }

    /**
     * @brief Adds two summation evaluation key sets (Threshold FHE).
     *
     * @param eval_key_map1  First summation key set.
     * @param eval_key_map2  Second summation key set.
     * @param key_tag       Secret key tag (optional).
     * @return Combined summation evaluation key set.
     */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> multi_add_eval_sum_keys(
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map1,
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map2, const std::string& key_tag = "") {
        if (!eval_key_map1)
            CIPHER_THROW("Input first evaluation key map is nullptr");
        if (!eval_key_map2)
            CIPHER_THROW("Input second evaluation key map is nullptr");
        return scheme_->multi_add_eval_sum_keys(eval_key_map1, eval_key_map2, key_tag);
    }

    /**
     * @brief Adds two automorphism evaluation key sets (Threshold FHE).
     *
     * @param eval_key_map1  First automorphism key set.
     * @param eval_key_map2  Second automorphism key set.
     * @param key_tag       Secret key tag (optional).
     * @return Combined automorphism evaluation key set.
     */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> multi_add_eval_automorphism_keys(
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map1,
            const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> eval_key_map2, const std::string& key_tag = "") {
        if (!eval_key_map1)
            CIPHER_THROW("Input first evaluation key map is nullptr");
        if (!eval_key_map2)
            CIPHER_THROW("Input second evaluation key map is nullptr");
        return scheme_->multi_add_eval_automorphism_keys(eval_key_map1, eval_key_map2, key_tag);
    }

    /**
     * @brief Adds two public keys to produce a combined public key (Threshold FHE).
     *
     * @param public_key1  First public key.
     * @param public_key2  Second public key.
     * @param key_tag      Secret key tag (optional).
     * @return Combined public key.
     */
    PublicKey<Element> multi_add_pub_keys(PublicKey<Element> public_key1, PublicKey<Element> public_key2,
                                       const std::string& key_tag = "") {
        if (!public_key1)
            CIPHER_THROW("Input first public key is nullptr");
        if (!public_key2)
            CIPHER_THROW("Input second public key is nullptr");
        return scheme_->multi_add_pub_keys(public_key1, public_key2, key_tag);
    }

    /**
     * @brief Adds two partial evaluation keys for multiplication (Threshold FHE).
     *
     * @param eval_key1  First evaluation key.
     * @param eval_key2  Second evaluation key.
     * @param key_tag    Secret key tag (optional).
     * @return Combined evaluation key.
     */
    EvalKey<Element> multi_add_eval_mult_keys(EvalKey<Element> eval_key1, EvalKey<Element> eval_key2,
                                          const std::string& key_tag = "") {
        if (!eval_key1)
            CIPHER_THROW("Input first evaluation key is nullptr");
        if (!eval_key2)
            CIPHER_THROW("Input second evaluation key is nullptr");
        return scheme_->multi_add_eval_mult_keys(eval_key1, eval_key2, key_tag);
    }

    /**
     * @brief Performs masked decryption for interactive bootstrapping (2-party protocol).
     *
     * @param private_key   Secret key share.
     * @param ciphertext   Input ciphertext.
     * @return Masked decrypted ciphertext.
     *
     * @note For Server, expects ciphertext with both polynomials a and b.
     *       For Client, expects only the linear term a.
     *       Includes rounding as part of decryption.
     */
    Ciphertext<Element> int_boot_decrypt(const PrivateKey<Element> private_key,
                                       ConstCiphertext<Element>& ciphertext) const {
        validate_ciphertext(ciphertext);
        validate_key(private_key);
        return scheme_->int_boot_decrypt(private_key, ciphertext);
    }

    /**
     * @brief Encrypts Client's masked decryption for interactive bootstrapping.
     *        Increases ciphertext modulus to allow further computation. Done by Client.
     *
     * @param public_key   Joined public key (Threshold FHE).
     * @param ciphertext  Input ciphertext.
     * @return Encrypted ciphertext.
     */
    Ciphertext<Element> int_boot_encrypt(const PublicKey<Element> public_key, ConstCiphertext<Element>& ciphertext) const {
        validate_ciphertext(ciphertext);
        validate_key(public_key);
        return scheme_->int_boot_encrypt(public_key, ciphertext);
    }

    /**
     * @brief Combines encrypted and unencrypted masked decryptions in 2-party interactive bootstrapping.
     *        It is the last step in the bootstrapping.
     *
     * @param ciphertext1  Encrypted masked decryption.
     * @param ciphertext2  Unencrypted masked decryption.
     * @return Refreshed ciphertext.
     */
    Ciphertext<Element> int_boot_add(ConstCiphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const {
        validate_ciphertext(ciphertext1);
        validate_ciphertext(ciphertext2);
        return scheme_->int_boot_add(ciphertext1, ciphertext2);
    }

    /**
     * @brief Prepares a ciphertext for interactive bootstrapping.
     *
     * @param ciphertext  Input ciphertext.
     * @return Adjusted ciphertext.
     *
     * @note CKKS FIXEDMANUAL/FIXEDAUTO: requires ≥ 2 towers; reduces to 2 towers and sets scale to Delta (not a power of Delta).
     *       CKKS FLEXIBLEAUTO: requires ≥ 3 towers; adjusts scale to level 0.
     */
    Ciphertext<Element> int_boot_adjust_scale(ConstCiphertext<Element>& ciphertext) const {
        validate_ciphertext(ciphertext);
        return scheme_->int_boot_adjust_scale(ciphertext);
    }

    /**
     * @brief Prepares a ciphertext for multi-party interactive bootstrapping (Threshold FHE).
     *
     * @param ciphertext  Input ciphertext.
     * @return Adjusted ciphertext.
     */
    Ciphertext<Element> int_mp_boot_adjust_scale(ConstCiphertext<Element>& ciphertext) const;

    /**
     * @brief Generates a common random polynomial for Multi-Party Interactive Bootstrapping (Threshold FHE).
     *
     * @param public_key  Scheme public key or lead party's public key.
     * @return Random ring element as ciphertext.
     */
    Ciphertext<Element> int_mp_boot_random_element_gen(const PublicKey<Element> public_key) const;
    /**
     * @brief Generates a common random polynomial for Multi-Party Interactive Bootstrapping (Threshold FHE)
     *        using an existing ciphertext, eliminating the need to supply a public key explicitly
     *
     * @param ciphertext Reference ciphertext used to derive the cryptocontext and parameters.
     * @return Random ring element as ciphertext.
     */
    Ciphertext<Element> int_mp_boot_random_element_gen(ConstCiphertext<Element>& ciphertext) const;

    /**
     * @brief Performs masked decryption as part of Multi-Party Interactive Bootstrapping (Threshold FHE).
     *        Each party calls this function as part of the protocol
     *
     * @param private_key  Secret key share for the party.
     * @param ciphertext  Input ciphertext.
     * @param a           Common random polynomial.
     * @return Vector of masked decryption shares.
     */
    std::vector<Ciphertext<Element>> int_mp_boot_decrypt(const PrivateKey<Element> private_key,
                                                      ConstCiphertext<Element>& ciphertext,
                                                      ConstCiphertext<Element>& a) const;

    /**
     * @brief Aggregates masked decryption and re-encryption shares (Threshold FHE).
     *        It is the second step of the interactive multiparty bootstrapping procedure.
     *
     * @param shares_pair_vec  Vector of (h_0i, h_1i) shares from each party.
     * @return Aggregated pair of shares (h_0, h_1).
     */
    std::vector<Ciphertext<Element>> int_mp_boot_add(std::vector<std::vector<Ciphertext<Element>>>& shares_pair_vec) const;

    /**
     * @brief Encrypts the lead party's masked decryption result as the final step of Multi-Party Interactive Bootstrapping (Threshold FHE).
     *        It increases the ciphertext modulus and enables future computations. This operation is done by the lead party as the final step
     *        of interactive multi-party bootstrapping.
     *
     * @param public_key   Lead party's public key.
     * @param shares_pair  Aggregated masked decryption and re-encryption shares.
     * @param a           Common random polynomial.
     * @param ciphertext  Input ciphertext.
     * @return Encrypted refreshed ciphertext.
     */
    Ciphertext<Element> int_mp_boot_encrypt(const PublicKey<Element> public_key,
                                         const std::vector<Ciphertext<Element>>& shares_pair,
                                         ConstCiphertext<Element>& a, ConstCiphertext<Element>& ciphertext) const;

    /**
     * @brief Performs secret sharing of a secret key for Threshold FHE with aborts.
     *
     * @param sk         Secret key to be shared.
     * @param N          Total number of parties.
     * @param threshold  Threshold number of parties required to reconstruct the key.
     * @param index      Index of the current party.
     * @param share_type  Type of secret sharing ("additive" or "shamir").
     * @return Map of secret key shares indexed by party ID.
     */
    std::unordered_map<uint32_t, Element> share_keys(const PrivateKey<Element>& sk, uint32_t N, uint32_t threshold,
                                                    uint32_t index, const std::string& share_type) const {
        std::string datatype = demangle(typeid(Element).name());
        CIPHER_THROW("Not implemented for " + datatype);
    }

    /**
     * @brief Recovers a secret key share from existing shares for Threshold FHE with aborts.
     *
     * @param sk         Output: recovered secret key.
     * @param sk_shares  Map of secret key shares indexed by party ID.
     * @param N          Total number of parties.
     * @param threshold  Threshold number of parties required to reconstruct the key.
     * @param share_type  Type of secret sharing ("additive" or "shamir").
     */
    void recover_shared_key(PrivateKey<Element>& sk, std::unordered_map<uint32_t, Element>& sk_shares, uint32_t N,
                          uint32_t threshold, const std::string& share_type) const;

    //------------------------------------------------------------------------------
    // FHE Bootstrap Methods
    //------------------------------------------------------------------------------

    /**
     * Bootstrap functionality:
     * There are four methods that have to be called in this specific order:
     * 1. eval_bootstrap_setup: computes and encodes the coefficients for encoding and
     * decoding and stores the necessary parameters
     * 2. eval_bootstrap_key_gen: computes and stores the keys for rotations and conjugation
     * 3. eval_bootstrap_precompute: computes and stores the plaintexts for encoding and decoding if not already done in eval_bootstrap_setup
     * 4. eval_bootstrap: refreshes the given ciphertext
     */

    /**
     * @brief Sets all bootstrapping parameters for both linear and FFT-like methods. Supported only in CKKS.
     *
     * @param level_budget      Vector of level budgets for encoding and decoding.
     * @param dim1             Inner dimensions for baby-step giant-step routine.
     * @param slots            Number of slots to be bootstrapped.
     * @param correction_factor Internal rescaling factor to improve precision (only for NATIVE_SIZE=64; 0 = default).
     * @param precompute       Whether to precompute plaintexts for encoding/decoding.
     * @param bt_slots_encoding  Whether the approximate modular reduction happens over the message being in slots or coefficients
     */
    void eval_bootstrap_setup(std::vector<uint32_t> level_budget = {5, 4}, std::vector<uint32_t> dim1 = {0, 0},
                            uint32_t slots = 0, uint32_t correction_factor = 0, bool precompute = true,
                            bool bt_slots_encoding = false) {
        scheme_->eval_bootstrap_setup(*this, level_budget, dim1, slots, correction_factor, precompute, bt_slots_encoding);
    }

    /**
     * @brief Generates automorphism keys for eval_bootstrap. Uses baby-step/giant-step strategy. Supported only in CKKS.
     *
     * @param private_key  Secret key.
     * @param slots       Number of slots to support permutations on.
     */
    void eval_bootstrap_key_gen(const PrivateKey<Element> private_key, uint32_t slots) {
        validate_key(private_key);
        auto eval_keys = scheme_->eval_bootstrap_key_gen(private_key, slots);
        CryptoContextImpl<Element>::insert_eval_automorphism_key(eval_keys, private_key->get_key_tag());
    }

    /**
     * @brief Precomputes plaintexts for encoding and decoding used in bootstrapping. Supported only in CKKS.
     *
     * @param slots  Number of slots to be bootstrapped.
     */
    void eval_bootstrap_precompute(uint32_t slots = 0) {
        scheme_->eval_bootstrap_precompute(*this, slots);
    }

    /**
     * @brief Evaluates bootstrapping on a ciphertext using FFT-like or linear method. Supported only in CKKS.
     *
     * @param ciphertext     Input ciphertext.
     * @param num_iterations  Number of Meta-BTS iterations to improve precision.
     * @param precision      Initial bootstrapping precision (set to 0 for default; tune experimentally).
     * @return Refreshed ciphertext.
     */
    Ciphertext<Element> eval_bootstrap(ConstCiphertext<Element>& ciphertext, uint32_t num_iterations = 1,
                                      uint32_t precision = 0) const {
        return scheme_->eval_bootstrap(ciphertext, num_iterations, precision);
    }

    /**
     * @brief Evaluates the slots-encoding variant of CKKS bootstrapping (SlotsToCoeffs first, then modulus raise,
     *        CoeffsToSlots and the approximate modular reduction over the message values). eval_bootstrap dispatches
     *        here automatically when eval_bootstrap_setup was called with bt_slots_encoding = true. Supported only in
     *        CKKS.
     *
     * @param ciphertext     Input ciphertext.
     * @param num_iterations  Number of Meta-BTS iterations to improve precision (1 or 2).
     * @param precision      Initial bootstrapping precision (set to 0 for default; tune experimentally).
     * @return Refreshed ciphertext.
     */
    Ciphertext<Element> eval_bootstrap_st_c_first(ConstCiphertext<Element>& ciphertext, uint32_t num_iterations = 1,
                                              uint32_t precision = 0) const {
        return scheme_->eval_bootstrap_st_c_first(ciphertext, num_iterations, precision);
    }

    /**
     * @brief Precomputes the encoding/decoding plaintexts for FE functional bootstrapping. Supported only in
     *        CKKS, with HYBRID key switching and first_mod_size == ScalingModSize + 1.
     *
     * Shares the bootstrapping precomputation slot for @p slots with eval_bootstrap_setup and eval_fbt_setup, so
     * a context can hold the precomputation for only one of them per slot count.
     *
     * @param level_budget  Levels spent on CoeffsToSlots and SlotsToCoeffs.
     * @param dim1         Baby-step dimensions for the two linear transforms (0 = choose automatically).
     * @param slots        Number of slots to be bootstrapped (0 = full packing).
     */
    void eval_fe_func_bootstrap_setup(const std::vector<uint32_t>& level_budget = {5, 4},
                                  const std::vector<uint32_t>& dim1 = {0, 0}, uint32_t slots = 0) {
        get_scheme()->eval_fe_func_bootstrap_setup(*this, level_budget, dim1, slots);
    }

    /**
     * @brief Refreshes a ciphertext and evaluates a function on it in one pass, by evaluating the function's
     *        Fourier extension over the bootstrapped message. Supported only in CKKS.
     *
     * The message is embedded into half of the series period (t = m/2), so the input must lie in [-1/2, 1/2)
     * and @p coefficients must be the Fourier extension of the target function over that domain. The result
     * is 2*Re(c_0 + sum_{j>=1} c_j exp(2*Pi*i*j*t)) and is therefore always real-valued: with CkksDataType
     * COMPLEX the imaginary part of each input slot is discarded and the output slots have zero imaginary
     * part. Use CkksDataType REAL unless complex intermediates are needed elsewhere in the computation.
     *
     * @param ciphertext    Input ciphertext, with slot values in [-1/2, 1/2).
     * @param coefficients  Fourier coefficients c_j of the target function, c_0 first.
     * @return Refreshed ciphertext holding the function values.
     */
    Ciphertext<Element> eval_fe_func_bootstrap(ConstCiphertext<Element>& ciphertext,
                                            const std::vector<std::complex<double>>& coefficients) const {
        validate_ciphertext(ciphertext);
        return get_scheme()->eval_fe_func_bootstrap(ciphertext, coefficients);
    }

    /**
     * @brief Runs the function-independent part of FE functional bootstrapping and returns the powers of the
     *        complex exponential, so that several functions can be evaluated on one bootstrapped ciphertext.
     *        Supported only in CKKS.
     *
     * The refresh itself - SlotsToCoeffs, modulus raise, CoeffsToSlots and the complex exponential - happens
     * here and dominates the cost; each subsequent eval_fe_func_bootstrap_with_precomp only evaluates a series.
     * The Paterson-Stockmeyer shape is fixed by @p coefficients, which must have degree at least 5, so pass
     * the longest series of the family: every series later evaluated against these powers may have at most
     * the degree of @p coefficients rounded up to the shape's capacity (eval_fe_func_bootstrap_with_precomp
     * reports the exact bound if it is exceeded). A series below degree 5 is evaluated straight from the
     * power basis and is accepted as long as its degree does not exceed the number of powers the shape holds.
     *
     * @param ciphertext    Input ciphertext, with slot values in [-1/2, 1/2).
     * @param coefficients  Fourier coefficients of the longest series to be evaluated, c_0 first.
     * @return Powers of the complex exponential, to be passed to eval_fe_func_bootstrap_with_precomp.
     */
    std::shared_ptr<SeriesPowers<Element>> eval_fe_func_bootstrap_precompute(
            ConstCiphertext<Element>& ciphertext, const std::vector<std::complex<double>>& coefficients) const {
        validate_ciphertext(ciphertext);
        return get_scheme()->eval_fe_func_bootstrap_precompute(ciphertext, coefficients);
    }

    /**
     * @brief Evaluates one function's Fourier series against powers from eval_fe_func_bootstrap_precompute.
     *        Supported only in CKKS.
     *
     * @param powers        Powers returned by eval_fe_func_bootstrap_precompute.
     * @param coefficients  Fourier coefficients c_j of this function, c_0 first.
     * @return Refreshed ciphertext holding the function values.
     */
    Ciphertext<Element> eval_fe_func_bootstrap_with_precomp(const std::shared_ptr<SeriesPowers<Element>>& powers,
                                                       const std::vector<std::complex<double>>& coefficients) const {
        validate_series_powers(powers);
        return get_scheme()->eval_fe_func_bootstrap_with_precomp(powers, coefficients);
    }

    /**
     * @brief Sets up CKKS functional bootstrapping of a look-up table (see CKKS_FUNCTIONAL_BOOTSTRAPING.md):
     *        computes its depth and precomputes the homomorphic encoding and decoding matrices with the required
     *        scalings folded in. Supported only in CKKS with HYBRID key switching (64-bit build). Shares the
     *        precomputation entry for @p num_slots with eval_bootstrap_setup and eval_fe_func_bootstrap_setup.
     *
     * @param coeffs                   Trigonometric Hermite interpolation coefficients of the look-up table
     *                                 (complex, or integer for a Boolean function of order 1); only their number
     *                                 is used here.
     * @param num_slots                 Number of slots to be bootstrapped (0 = full packing).
     * @param p_in                      Plaintext modulus of the RLWE input.
     * @param P_out                     Plaintext modulus of the RLWE output.
     * @param Bigq                     Ciphertext modulus of the RLWE scheme the input is converted from.
     * @param pub_key                   Public key (its element parameters define the modulus chain).
     * @param dim1                     Baby-step dimensions for CoeffsToSlots and SlotsToCoeffs (0 = automatic).
     * @param level_budget              Levels spent on CoeffsToSlots and SlotsToCoeffs (each in [1, log2(slots)]).
     * @param lvls_after_boot            Number of levels remaining after functional bootstrapping.
     * @param depth_leveled_computation  Depth reserved for a leveled computation between eval_fbt_no_decoding and
     *                                 eval_hom_decoding.
     * @param order                    Order of the trigonometric Hermite interpolation (1, 2 or 3).
     */
    template <typename VectorDataType>
    void eval_fbt_setup(const std::vector<VectorDataType>& coeffs, uint32_t num_slots, const BigInteger& p_in,
                      const BigInteger& P_out, const BigInteger& bigq, const PublicKey<RnsPoly>& pub_key,
                      const std::vector<uint32_t>& dim1, const std::vector<uint32_t>& level_budget,
                      uint32_t lvls_after_boot = 0, uint32_t depth_leveled_computation = 0, size_t order = 1) {
        scheme_->eval_fbt_setup(*this, coeffs, num_slots, p_in, P_out, bigq, pub_key, dim1, level_budget, lvls_after_boot,
                               depth_leveled_computation, order);
    }

    /**
     * @brief Functional bootstrapping of a look-up table on a CKKS ciphertext imported from RLWE
     *        (SchemeletRlweMp::convert_rlwe_to_ckks): modulus raise, CoeffsToSlots, complex exponential (or cosine
     *        for a Boolean function of order 1), trigonometric Hermite series, SlotsToCoeffs and scalings.
     *        Supported only in CKKS.
     *
     * @param ciphertext      Input ciphertext holding the RLWE input in its coefficients.
     * @param coeffs          Trigonometric Hermite interpolation coefficients of the look-up table (complex, or
     *                        integer for a Boolean function of order 1), scaled to magnitude at most one.
     * @param digit_bit_size    Bit size of the look-up table input (log2 of the input plaintext modulus).
     * @param initial_scaling  Scale of the imported message (the RLWE ciphertext modulus of the input).
     * @param post_scaling     Integer the result is multiplied by after SlotsToCoeffs (typically the scale the
     *                        coefficients were divided by; values of at most 1 are ignored).
     * @param level_to_reduce   Number of levels to drop before SlotsToCoeffs.
     * @param order           Order of the trigonometric Hermite interpolation (1, 2 or 3).
     * @return Ciphertext holding the look-up table outputs in its coefficients, ready for
     *         SchemeletRlweMp::convert_ckks_to_rlwe.
     */
    template <typename VectorDataType>
    Ciphertext<Element> eval_fbt(ConstCiphertext<Element>& ciphertext, const std::vector<VectorDataType>& coeffs,
                                uint32_t digit_bit_size, const BigInteger& initial_scaling, uint64_t post_scaling,
                                uint32_t level_to_reduce = 0, size_t order = 1) {
        return scheme_->eval_fbt(ciphertext, coeffs, digit_bit_size, initial_scaling, post_scaling, level_to_reduce, order);
    }

    /**
     * @brief Functional bootstrapping of a look-up table without the final homomorphic decoding: the outputs stay
     *        in the slots so that a leveled computation can be applied before eval_hom_decoding. Supported only in
     *        CKKS.
     *
     * @param ciphertext      Input ciphertext holding the RLWE input in its coefficients.
     * @param coeffs          Trigonometric Hermite interpolation coefficients of the look-up table.
     * @param digit_bit_size    Bit size of the look-up table input (log2 of the input plaintext modulus).
     * @param initial_scaling  Scale of the imported message (the RLWE ciphertext modulus of the input).
     * @param order           Order of the trigonometric Hermite interpolation (1, 2 or 3).
     * @return Ciphertext holding the look-up table outputs in its slots.
     */
    template <typename VectorDataType>
    Ciphertext<Element> eval_fbt_no_decoding(ConstCiphertext<Element>& ciphertext,
                                          const std::vector<VectorDataType>& coeffs, uint32_t digit_bit_size,
                                          const BigInteger& initial_scaling, size_t order = 1) {
        return scheme_->eval_fbt_no_decoding(ciphertext, coeffs, digit_bit_size, initial_scaling, order);
    }

    /**
     * @brief Homomorphic decoding step of functional bootstrapping: drops levels if requested, applies
     *        SlotsToCoeffs, multiplies by post_scaling and rescales to noise scale degree 1. Supported only in CKKS.
     *
     * @param ciphertext     Ciphertext with the look-up table outputs in its slots.
     * @param post_scaling    Integer the result is multiplied by after SlotsToCoeffs (values of at most 1 are
     *                       ignored).
     * @param level_to_reduce  Number of levels to drop before SlotsToCoeffs.
     * @return Ciphertext holding the outputs in its coefficients, at noise scale degree 1.
     */
    Ciphertext<Element> eval_hom_decoding(ConstCiphertext<Element>& ciphertext, uint64_t post_scaling,
                                        uint32_t level_to_reduce = 0) {
        return scheme_->eval_hom_decoding(ciphertext, post_scaling, level_to_reduce);
    }

    /**
     * @brief Precomputes the complex-exponential powers for multi-value bootstrapping (modulus raise,
     *        CoeffsToSlots, complex exponential and its powers). Every look-up table later evaluated on the
     *        result (eval_mvb, eval_mvb_no_decoding) must be interpolated with the same shape (same plaintext modulus
     *        and order) as @p coeffs, since those determine which powers are computed. Supported only in CKKS.
     *
     * @param ciphertext      Input ciphertext holding the RLWE input in its coefficients.
     * @param coeffs          Trigonometric Hermite interpolation coefficients of one of the look-up tables.
     * @param digit_bit_size    Bit size of the look-up table input (log2 of the input plaintext modulus).
     * @param initial_scaling  Scale of the imported message (the RLWE ciphertext modulus of the input).
     * @param order           Order of the trigonometric Hermite interpolation (1, 2 or 3).
     * @return Powers of the complex exponential.
     */
    template <typename VectorDataType>
    std::shared_ptr<SeriesPowers<Element>> eval_mvb_precompute(ConstCiphertext<Element>& ciphertext,
                                                             const std::vector<VectorDataType>& coeffs,
                                                             uint32_t digit_bit_size, const BigInteger& initial_scaling,
                                                             size_t order = 1) {
        return scheme_->eval_mvb_precompute(ciphertext, coeffs, digit_bit_size, initial_scaling, order);
    }

    /**
     * @brief Multi-value bootstrapping: evaluates the trigonometric Hermite series of a look-up table on the
     *        powers from eval_mvb_precompute and applies the homomorphic decoding. Supported only in CKKS.
     *
     * @param ciphertexts    Powers of the complex exponential from eval_mvb_precompute.
     * @param coeffs         Trigonometric Hermite interpolation coefficients of the look-up table (same shape as
     *                       in eval_mvb_precompute).
     * @param digit_bit_size   Bit size of the look-up table input (log2 of the input plaintext modulus).
     * @param post_scaling    Integer the result is multiplied by after SlotsToCoeffs (values of at most 1 are
     *                       ignored).
     * @param level_to_reduce  Number of levels to drop before SlotsToCoeffs.
     * @param order          Order of the trigonometric Hermite interpolation (1, 2 or 3).
     * @return Ciphertext holding the look-up table outputs in its coefficients, at noise scale degree 1.
     */
    template <typename VectorDataType>
    Ciphertext<Element> eval_mvb(const std::shared_ptr<SeriesPowers<Element>> ciphertexts,
                                const std::vector<VectorDataType>& coeffs, uint32_t digit_bit_size,
                                const uint64_t post_scaling, uint32_t level_to_reduce = 0, size_t order = 1) {
        return scheme_->eval_mvb(ciphertexts, coeffs, digit_bit_size, post_scaling, level_to_reduce, order);
    }

    /**
     * @brief Multi-value bootstrapping without the final homomorphic decoding: the look-up table outputs stay in
     *        the slots so that a leveled computation can be applied before eval_hom_decoding. Supported only in
     *        CKKS.
     *
     * @param ciphertexts   Powers of the complex exponential from eval_mvb_precompute.
     * @param coeffs        Trigonometric Hermite interpolation coefficients of the look-up table (same shape as in
     *                      eval_mvb_precompute).
     * @param digit_bit_size  Bit size of the look-up table input (log2 of the input plaintext modulus).
     * @param order         Order of the trigonometric Hermite interpolation (1, 2 or 3).
     * @return Ciphertext holding the look-up table outputs in its slots.
     */
    template <typename VectorDataType>
    Ciphertext<Element> eval_mvb_no_decoding(const std::shared_ptr<SeriesPowers<Element>> ciphertexts,
                                          const std::vector<VectorDataType>& coeffs, uint32_t digit_bit_size,
                                          size_t order = 1) {
        return scheme_->eval_mvb_no_decoding(ciphertexts, coeffs, digit_bit_size, order);
    }

    /**
     * @brief Evaluates a trigonometric Hermite series: approximates exp(i*Pi/2*x) with the given Chebyshev series
     *        over [a, b], squares it twice to get exp(2*Pi*i*x), evaluates the Hermite series in the power basis of
     *        the exponential and returns its real part. The exponential can be cached in the bootstrapping
     *        precomputation for the ciphertext's slot count and reused. Supported only in CKKS.
     *
     * @param ciphertext        Input ciphertext.
     * @param coefficients_cheb  Chebyshev coefficients of exp(i*Pi/2*x) over [a, b].
     * @param a                 Lower bound of the Chebyshev interpolation interval.
     * @param b                 Upper bound of the Chebyshev interpolation interval.
     * @param coefficients_herm  Hermite series coefficients in the power basis of the exponential, divided by 2.
     * @param precomp           0 or 1: compute the exponential and cache it in the first or second slot; 2: reuse
     *                          the first cached exponential; any other value: reuse the second one.
     * @return The real part of the evaluated series.
     */
    template <typename VectorDataType>
    Ciphertext<Element> eval_hermite_trig_series(ConstCiphertext<Element>& ciphertext,
                                              const std::vector<std::complex<double>>& coefficients_cheb, double a,
                                              double b, const std::vector<VectorDataType>& coefficients_herm,
                                              size_t precomp = 0) {
        return scheme_->eval_hermite_trig_series(ciphertext, coefficients_cheb, a, b, coefficients_herm, precomp);
    }

    /**
     * @brief Gets the correction factor of CKKS bootstrapping (the number of bits the message is scaled down by in
     *        total before the approximate modular reduction to improve precision), as set by eval_bootstrap_setup.
     *        Supported only in CKKS.
     *
     * @return The correction factor.
     */
    uint32_t get_ckks_boot_correction_factor() {
        return scheme_->get_ckks_boot_correction_factor();
    }

    /**
     * @brief Sets the correction factor of CKKS bootstrapping. Supported only in CKKS.
     *
     * @param cf  The correction factor.
     */
    void set_ckks_boot_correction_factor(uint32_t cf) {
        return scheme_->set_ckks_boot_correction_factor(cf);
    }

    //------------------------------------------------------------------------------
    // Scheme switching Methods
    //------------------------------------------------------------------------------

    /**
     * Scheme switching between CKKS and FHEW functionality
     * There are three methods that have to be called in this specific order:
     * 1. eval_ckks_to_fhew_setup: generates a FHEW cryptocontext and returns the key, computes and encodes
     * the coefficients for encoding and decoding and stores the necessary parameters
     * 2. eval_ckks_to_fhew_key_gen: computes and stores the keys for rotations and conjugation
     * 3. eval_ckks_to_fhew: returns the FHEW/CGGI ciphertext
     * 1'. eval_fhew_to_ckks_setup: takes in the CKKS cryptocontext and sets the parameters
     * 2'. eval_fhew_to_ckks_key_gen: computes and stores the switching key and the keys for rotations and conjugation
     * 3'. eval_fhew_to_ckks: returns the CKKS ciphertext
     * 1''. eval_scheme_switching_setup: generates a FHEW cryptocontext and returns the key, computes and encodes
     * the coefficients for encoding and decoding and stores the necessary parameters
     * 2''. eval_scheme_switching_key_gen: computes and stores the switching key and the keys for rotations and conjugation
     * 3''. eval_compare_scheme_switching/EvalFuncSchemeSwitching: returns the CKKS ciphertext of the function specified
     */

    /**
     * @brief Sets all parameters for switching from CKKS to FHEW.
     *
     * @param params  Parameters for CKKS-to-FHEW scheme switching.
     * @return FHEW secret key.
     *
     * @note TODO: Add overload for pre-generated BooleanContext.
     */
    LwePrivateKey eval_ckks_to_fhew_setup(SchSwchParams params) {
        verify_ckks_scheme(__func__);
        verify_ckks_real_data_type(__func__);
        set_params_from_ckks_cryptocontext(params);
        return scheme_->eval_ckks_to_fhew_setup(params);
    }

    /**
     * @brief Generates keys for CKKS-to-FHEW scheme switching: rotation keys, conjugation keys, and switching key.
     *
     * @param key_pair  CKKS key pair.
     * @param lwesk    FHEW secret key.
     */
    void eval_ckks_to_fhew_key_gen(const KeyPair<Element>& key_pair, ConstLwePrivateKey& lwesk) {
        verify_ckks_scheme(__func__);
        verify_ckks_real_data_type(__func__);
        validate_key(key_pair.secret_key);
        if (!lwesk)
            CIPHER_THROW("FHEW private key passed to EvalCKKStoFHEWKeyGen is null");

        auto eval_keys = scheme_->eval_ckks_to_fhew_key_gen(key_pair, lwesk);
        CryptoContextImpl<Element>::insert_eval_automorphism_key(eval_keys, key_pair.secret_key->get_key_tag());
    }

    /**
     * @brief Performs precomputations for CKKS homomorphic decoding. Allows setting a custom scale factor. Given as
     *        a separate method than eval_ckks_to_fhew_setup to allow the user to specify a scale that depends on
     *        the CKKS and FHEW cryptocontexts
     *
     * @param scale  Scaling factor for the linear transform matrix.
     */
    void eval_ckks_to_fhew_precompute(double scale = 1.0) {
        verify_ckks_scheme(__func__);
        verify_ckks_real_data_type(__func__);
        scheme_->eval_ckks_to_fhew_precompute(*this, scale);
    }

    /**
     * @brief Switches a CKKS ciphertext to a vector of FHEW ciphertexts.
     *
     * @param ciphertext  Input CKKS ciphertext.
     * @param num_ctxts    Number of coefficients to extract (defaults to number of slots if 0).
     * @return Vector of LWE ciphertexts.
     */
    std::vector<std::shared_ptr<LweCiphertextImpl>> eval_ckks_to_fhew(ConstCiphertext<Element>& ciphertext,
                                                                   uint32_t num_ctxts = 0) {
        verify_ckks_scheme(__func__);
        verify_ckks_real_data_type(__func__);
        if (ciphertext == nullptr)
            CIPHER_THROW("ciphertext passed to EvalCKKStoFHEW is empty");

        return scheme_->eval_ckks_to_fhew(ciphertext, num_ctxts);
    }

    /**
     * @brief Sets parameters for switching from FHEW to CKKS. Requires existing CKKS context.
     *
     * @param cc_lwe         Source FHEW crypto context.
     * @param num_slots_ckks  Number of slots in resulting CKKS ciphertext.
     * @param log_q          Ciphertext modulus size in FHEW (for high precision).
     */
    void eval_fhew_to_ckks_setup(const std::shared_ptr<BooleanContext>& cc_lwe, uint32_t num_slots_ckks = 0,
                             uint32_t log_q = 25) {
        verify_ckks_scheme(__func__);
        verify_ckks_real_data_type(__func__);
        scheme_->eval_fhew_to_ckks_setup(*this, cc_lwe, num_slots_ckks, log_q);
    }

    /**
     * @brief Generates keys for switching from FHEW to CKKS.
     *
     * @param key_pair   CKKS key pair.
     * @param lwesk     FHEW secret key.
     * @param num_slots  Number of slots for CKKS encryption.
     * @param num_ctxts  Number of LWE ciphertext values to encrypt.
     * @param dim1      Baby-step parameter for linear transform.
     * @param L         Target level for homomorphic decoding matrix.
     */
    void eval_fhew_to_ckks_key_gen(const KeyPair<Element>& key_pair, ConstLwePrivateKey& lwesk, uint32_t num_slots = 0,
                              uint32_t num_ctxts = 0, uint32_t dim1 = 0, uint32_t L = 0) {
        verify_ckks_scheme(__func__);
        verify_ckks_real_data_type(__func__);
        validate_key(key_pair.secret_key);

        auto eval_keys = scheme_->eval_fhew_to_ckks_key_gen(key_pair, lwesk, num_slots, num_ctxts, dim1, L);
        CryptoContextImpl<Element>::insert_eval_automorphism_key(eval_keys, key_pair.secret_key->get_key_tag());
    }

    /**
     * @brief Switches a vector of FHEW ciphertexts to a single CKKS ciphertext.
     *
     * @param lwe_ciphertexts  Input vector of FHEW ciphertexts.
     * @param num_ctxts        Number of values to encode.
     * @param num_slots        Number of CKKS slots to use.
     * @param p               Plaintext modulus (default = 4).
     * @param pmin            Minimum expected plaintext value (default = 0.0).
     * @param pmax            Maximum expected plaintext value (default = 2.0).
     * @param dim1            Baby-step parameter (used in argmin).
     * @return CKKS ciphertext encoding the input LWE messages.
     */
    Ciphertext<Element> eval_fhew_to_ckks(std::vector<std::shared_ptr<LweCiphertextImpl>>& lwe_ciphertexts,
                                       uint32_t num_ctxts = 0, uint32_t num_slots = 0, uint32_t p = 4, double pmin = 0.0,
                                       double pmax = 2.0, uint32_t dim1 = 0) const {
        verify_ckks_scheme(__func__);
        verify_ckks_real_data_type(__func__);
        return scheme_->eval_fhew_to_ckks(lwe_ciphertexts, num_ctxts, num_slots, p, pmin, pmax, dim1);
    }

    /**
     * @brief Sets scheme switching parameters using the current CKKS crypto context.
     *
     * @param params  Scheme switching parameter object to populate.
     */
    void set_params_from_ckks_cryptocontext(SchSwchParams& params) {
        const auto crypto_params = std::dynamic_pointer_cast<CkksRnsCryptoParams>(params_);
        if (!crypto_params)
            CIPHER_THROW("Invalid crypto parameters: expected CryptoParametersCKKSRNS");
        params.set_initial_ckks_modulus(crypto_params->get_element_params()->get_params()[0]->get_modulus());
        params.set_ring_dimension(get_ring_dimension());
        // TODO (dsuponit): is this correct - PlaintextModulus used as scaling_mod_size?
        params.set_scaling_mod_size(get_encoding_params()->get_plaintext_modulus());
        params.set_batch_size(get_encoding_params()->get_batch_size());
        params.set_params_from_ckks_cryptocontext_called();
    }

    /**
     * @brief Sets parameters for switching between CKKS and FHEW.
     *
     * @param params  Scheme switching parameter object.
     * @return FHEW secret key.
     *
     * @note TODO: Add overload for pre-generated BooleanContext.
     */
    LwePrivateKey eval_scheme_switching_setup(SchSwchParams& params) {
        verify_ckks_scheme(__func__);
        verify_ckks_real_data_type(__func__);
        set_params_from_ckks_cryptocontext(params);
        return scheme_->eval_scheme_switching_setup(params);
    }

    /**
     * @brief Generates keys for switching between CKKS and FHEW.
     *
     * @param key_pair  CKKS key pair.
     * @param lwesk    FHEW secret key.
     */
    void eval_scheme_switching_key_gen(const KeyPair<Element>& key_pair, ConstLwePrivateKey& lwesk) {
        verify_ckks_scheme(__func__);
        verify_ckks_real_data_type(__func__);
        validate_key(key_pair.secret_key);

        auto eval_keys = scheme_->eval_scheme_switching_key_gen(key_pair, lwesk);
        CryptoContextImpl<Element>::insert_eval_automorphism_key(eval_keys, key_pair.secret_key->get_key_tag());
    }

    /**
     * @brief Performs precomputations for scheme switching in CKKS-to-FHEW comparison.
     *        Given as a separate method than eval_scheme_switching_setup to allow the user to specify a scale.
     *
     * @param p_lwe       Target plaintext modulus for FHEW ciphertexts.
     * @param scale_sign  Scaling factor for CKKS ciphertexts before switching.
     * @param unit       Indicates if input messages are normalized to unit circle.
     */
    void eval_compare_switch_precompute(uint32_t p_lwe = 0, double scale_sign = 1.0, bool unit = false) {
        verify_ckks_scheme(__func__);
        verify_ckks_real_data_type(__func__);
        scheme_->eval_compare_switch_precompute(*this, p_lwe, scale_sign, unit);
    }

    /**
     * @brief Compares two CKKS ciphertexts using FHEW-based scheme switching and returns CKKS result.
     *
     * @param ciphertext1  First input CKKS ciphertext.
     * @param ciphertext2  Second input CKKS ciphertext.
     * @param num_ctxts     Number of coefficients to extract.
     * @param num_slots     Number of slots to encode in the result.
     * @param p_lwe         Target plaintext modulus for FHEW ciphertexts.
     * @param scale_sign    Scaling factor for CKKS ciphertexts before switching.
     * @param unit         Indicates if input messages are normalized to unit circle.
     * @return CKKS ciphertext encoding sign comparison result.
     */
    Ciphertext<Element> eval_compare_scheme_switching(ConstCiphertext<Element>& ciphertext1,
                                                   ConstCiphertext<Element>& ciphertext2, uint32_t num_ctxts = 0,
                                                   uint32_t num_slots = 0, uint32_t p_lwe = 0, double scale_sign = 1.0,
                                                   bool unit = false) {
        verify_ckks_scheme(__func__);
        verify_ckks_real_data_type(__func__);
        validate_ciphertext(ciphertext1);
        validate_ciphertext(ciphertext2);
        return scheme_->eval_compare_scheme_switching(ciphertext1, ciphertext2, num_ctxts, num_slots, p_lwe, scale_sign,
                                                    unit);
    }

    /**
     * @brief Computes minimum and index of the first packed values using scheme switching.
     *
     * @param ciphertext  Input CKKS ciphertext.
     * @param public_key   CKKS public key.
     * @param num_values   Number of values to compare (we assume that num_values is a power of two).
     * @param num_slots    Number of output slots.
     * @param p_lwe        Target plaintext modulus for FHEW.
     * @param scale_sign   Scaling factor before switching to FHEW. The resulting FHEW ciphertexts will encrypt values modulo p_lwe,
     *                    so scale_sign should account for this p_lwe and is given here only if the homomorphic decoding matrix is
     *                    not scaled with the desired values
     * @return A vector of two CKKS ciphertexts: [min, argmin]. The ciphertexts have junk after the first slot in the first ciphertext
     *         and after num_values in the second ciphertext if one_hot=true and after the first slot if one_hot=false.
     */
    std::vector<Ciphertext<Element>> eval_min_scheme_switching(ConstCiphertext<Element>& ciphertext,
                                                            PublicKey<Element>& public_key, uint32_t num_values = 0,
                                                            uint32_t num_slots = 0, uint32_t p_lwe = 0,
                                                            double scale_sign = 1.0) {
        verify_ckks_scheme(__func__);
        verify_ckks_real_data_type(__func__);
        validate_ciphertext(ciphertext);
        return scheme_->eval_min_scheme_switching(ciphertext, public_key, num_values, num_slots, p_lwe, scale_sign);
    }

    /**
     * @brief Computes minimum and index using more FHEW operations than CKKS with higher precision, but slower than eval_min_scheme_switching.
     *
     * @param ciphertext  Input CKKS ciphertext.
     * @param public_key   CKKS public key.
     * @param num_values   Number of packed values to compare.
     * @param num_slots    Number of slots in the output ciphertexts.
     * @param p_lwe        Target plaintext modulus for FHEW ciphertexts.
     * @param scale_sign   Scaling factor before switching to FHEW.
     * @return A vector with two CKKS ciphertexts: [min, argmin].
     */
    std::vector<Ciphertext<Element>> eval_min_scheme_switching_alt(ConstCiphertext<Element>& ciphertext,
                                                               PublicKey<Element>& public_key, uint32_t num_values = 0,
                                                               uint32_t num_slots = 0, uint32_t p_lwe = 0,
                                                               double scale_sign = 1.0) {
        verify_ckks_scheme(__func__);
        verify_ckks_real_data_type(__func__);
        validate_ciphertext(ciphertext);
        return scheme_->eval_min_scheme_switching_alt(ciphertext, public_key, num_values, num_slots, p_lwe, scale_sign);
    }

    /**
     * @brief Computes maximum and index from the first packed values using scheme switching.
     *
     * @param ciphertext  Input CKKS ciphertext.
     * @param public_key   CKKS public key.
     * @param num_values   Number of values to compare (we assume that num_values is a power of two).
     * @param num_slots    Number of output slots.
     * @param p_lwe        Target plaintext modulus for FHEW.
     * @param scale_sign   Scaling factor before switching to FHEW.
     * @return A vector of two CKKS ciphertexts: [max, argmax]. The ciphertexts have junk after the first slot in the first ciphertext
     *         and after num_values in the second ciphertext if one_hot=true and after the first slot if one_hot=false.
     */
    std::vector<Ciphertext<Element>> eval_max_scheme_switching(ConstCiphertext<Element>& ciphertext,
                                                            PublicKey<Element>& public_key, uint32_t num_values = 0,
                                                            uint32_t num_slots = 0, uint32_t p_lwe = 0,
                                                            double scale_sign = 1.0) {
        verify_ckks_scheme(__func__);
        verify_ckks_real_data_type(__func__);
        validate_ciphertext(ciphertext);
        return scheme_->eval_max_scheme_switching(ciphertext, public_key, num_values, num_slots, p_lwe, scale_sign);
    }

    /**
     * @brief Computes max and index via scheme switching, with more FHEW operations for better precision than eval_max_scheme_switching.
     *
     * @param ciphertext  Input CKKS ciphertext.
     * @param public_key   CKKS public key.
     * @param num_values   Number of values to compare.
     * @param num_slots    Number of output slots.
     * @param p_lwe        Target plaintext modulus for FHEW.
     * @param scale_sign   Scaling factor before switching to FHEW.
     * @return A vector of two CKKS ciphertexts: [max, argmax].
     */
    std::vector<Ciphertext<Element>> eval_max_scheme_switching_alt(ConstCiphertext<Element>& ciphertext,
                                                               PublicKey<Element>& public_key, uint32_t num_values = 0,
                                                               uint32_t num_slots = 0, uint32_t p_lwe = 0,
                                                               double scale_sign = 1.0) {
        verify_ckks_scheme(__func__);
        verify_ckks_real_data_type(__func__);
        validate_ciphertext(ciphertext);
        return scheme_->eval_max_scheme_switching_alt(ciphertext, public_key, num_values, num_slots, p_lwe, scale_sign);
    }

    /**
     * @brief Returns the BinFHE context used for scheme switching.
     * @return BinFHE context.
     */
    std::shared_ptr<cipher::BooleanContext> get_bin_cc_for_scheme_switch() const {
        return scheme_->get_bin_cc_for_scheme_switch();
    }

    /**
     * @brief Sets the BinFHE context to be used for scheme switching.
     * @param cc_lwe BinFHE context.
     */
    void set_bin_cc_for_scheme_switch(std::shared_ptr<cipher::BooleanContext> cc_lwe) {
        scheme_->set_bin_cc_for_scheme_switch(cc_lwe);
    }

    /**
     * @brief Gets the FHEW-to-CKKS scheme switching key ciphertext.
     * @return Switching key ciphertext.
     */
    Ciphertext<Element> get_swk_fc() const {
        return scheme_->get_swk_fc();
    }

    /**
     * @brief Sets the FHEW-to-CKKS scheme switching key ciphertext.
     * @param fhew_to_ckks_swk Switching key ciphertext.
     */
    void set_swk_fc(Ciphertext<Element> fhew_to_ckks_swk) {
        scheme_->set_swk_fc(fhew_to_ckks_swk);
    }

    /**
     * @brief Gets indices that do not have automorphism keys for the given secret key tag in the key map
     *
     * @param key_tag secret key tag
     * @param indices set of specific indices to check the key map against
     * @return indices that do not have automorphism keys associated with
     */
    static std::set<uint32_t> get_eval_automorphism_no_key_indices(const std::string& key_tag,
                                                              const std::set<uint32_t>& indices) {
        std::set<uint32_t> existing_indices{CryptoContextImpl<Element>::get_existing_eval_automorphism_key_indices(key_tag)};
        // if no index found for the given key_tag, then the entire set "indices" is returned
        return (existing_indices.empty()) ? indices :
                                           CryptoContextImpl<Element>::get_unique_values(existing_indices, indices);
    }

    /**
     * @brief Returns automorphism indices for all existing evaluation keys.
     * @param key_tag      Secret key tag.
     * @return Set of indices found for the given key tag. Empty if none exist.
     */
    static std::set<uint32_t> get_existing_eval_automorphism_key_indices(const std::string& key_tag);

    /**
     * @brief Compares two sets and returns unique values from the second set.
     * @param old_values   First set to compare against.
     * @param new_values   Second set to extract unique values from.
     * @return Set of values present in new_values but not in old_values.
     */
    static std::set<uint32_t> get_unique_values(const std::set<uint32_t>& old_values, const std::set<uint32_t>& new_values);

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::make_nvp("cc", params_));
        ar(cereal::make_nvp("kt", scheme_));
        ar(cereal::make_nvp("si", scheme_id_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > CryptoContextImpl<Element>::serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(cereal::make_nvp("cc", params_));
        ar(cereal::make_nvp("kt", scheme_));
        ar(cereal::make_nvp("si", scheme_id_));
        set_ks_technique_in_scheme();

        // NOTE: a pointer to this object will be wrapped in a shared_ptr, and is a
        // "CryptoContext". Cipher relies on the notion that identical
        // CryptoContextImpls are not duplicated in memory Once we deserialize this
        // object, we must check to see if there is a matching object for this
        // object that's already existing in memory if it DOES exist, use it. If it
        // does NOT exist, add this to the cache of all contexts
    }

    std::string serialized_object_name() const override {
        return "CryptoContext";
    }

    static uint32_t serialized_version() {
        return 1;
    }
};

// Member function specializations. Their implementations are in cryptocontext.cpp
/// @cond INTERNAL
template <>
DecryptResult CryptoContextImpl<RnsPoly>::multiparty_decrypt_fusion(
        const std::vector<Ciphertext<RnsPoly>>& partial_ciphertext_vec, Plaintext* plaintext) const;
template <>
std::unordered_map<uint32_t, RnsPoly> CryptoContextImpl<RnsPoly>::share_keys(const PrivateKey<RnsPoly>& sk,
                                                                              uint32_t N, uint32_t threshold,
                                                                              uint32_t index,
                                                                              const std::string& share_type) const;
/// @endcond
}  // namespace cipher

#endif  // CIPHER_FHE_CONTEXT_H_
