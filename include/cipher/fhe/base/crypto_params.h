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
#ifndef CIPHER_FHE_BASE_CRYPTO_PARAMS_H_
#define CIPHER_FHE_BASE_CRYPTO_PARAMS_H_

#include <cstdint>
#include <memory>
#include <string>

#include "cipher/fhe/encoding/encodings.h"
#include "cipher/fhe/encoding/plaintext.h"
#include "cipher/util/serializable.h"

/**
 * @namespace cipher
 * The namespace of cipher
 */
namespace cipher {

/**
 * @brief main implementation class to capture essential cryptoparameters of
 * any LBC system
 * @tparam Element a ring element.
 */
template <typename Element>
class BaseCryptoParams : public Serializable {
    using ParmType = typename Element::Params;
    using IntType = typename Element::Integer;
    using DugType = typename Element::DugType;
    using DggType = typename Element::DggType;
    using TugType = typename Element::TugType;

  public:
    BaseCryptoParams() = default;

    virtual ~BaseCryptoParams() = default;

    // NOTE: some getters and setters are declared "virtual" as they should be overriden and disabled in
    // some scheme-specific parameter classes derived from BaseCryptoParams
    /**
     * Returns the value of plaintext modulus p
     *
     * @return the plaintext modulus.
     */
    virtual PlaintextModulus get_plaintext_modulus() const {
        return encoding_params_->get_plaintext_modulus();
    }

    uint32_t get_batch_size() const {
        return encoding_params_->get_batch_size();
    }

    /**
     * Returns the reference to IL params
     *
     * @return the ring element parameters.
     */
    const std::shared_ptr<typename Element::Params> get_element_params() const {
        return params_;
    }

    uint32_t get_ring_dimension() const {
        return params_->get_ring_dimension();
    }

    /**
     * Returns the element parameters used for public key generation and public-key encryption; a scheme
     * may extend the ciphertext parameters here (e.g., with the auxiliary or extra moduli needed by
     * HRA-secure PRE or by the EXTENDED encryption technique).
     *
     * @return the element parameters for the public key.
     */
    virtual const std::shared_ptr<typename Element::Params> get_params_pk() const = 0;

    /**
     * Returns the reference to encoding params
     *
     * @return the encoding parameters.
     */
    const EncodingParams get_encoding_params() const {
        return encoding_params_;
    }

    /**
     * Sets the value of plaintext modulus p
     * @param plaintext_modulus the plaintext modulus
     */
    void set_plaintext_modulus(PlaintextModulus plaintext_modulus) {
        encoding_params_->set_plaintext_modulus(plaintext_modulus);
    }

    void set_batch_size(uint32_t batch_size) {
        encoding_params_->set_batch_size(batch_size);
    }

    bool operator==(const BaseCryptoParams<Element>& rhs) const {
        return compare_to(rhs);
    }

    bool operator!=(const BaseCryptoParams<Element>& rhs) const {
        return !(*this == rhs);
    }

    /**
     * Overload to allow printing of parameters to an iostream
     * NOTE that the implementation relies on calling the virtual
     * print_parameters method
     * @param out - the stream to print to
     * @param item - reference to the item to print
     * @return the stream
     */
    friend std::ostream& operator<<(std::ostream& out, const BaseCryptoParams& item) {
        item.print_parameters(out);
        return out;
    }

    virtual uint32_t get_digit_size() const {
        return 0;
    }

    /**
     * Returns the value of the maximum power of secret key for which the
     * relinearization key is generated
     *
     * @return maximum power of secret key
     */
    virtual uint32_t get_max_relin_sk_deg() const {
        return 0;
    }

    /**
     * Sets the reference to element params
     * @param params the ring element parameters
     */
    virtual void set_element_params(std::shared_ptr<typename Element::Params> params) {
        params_ = params;
    }

    /**
     * Sets the reference to encoding params
     * @param encoding_params the encoding parameters
     */
    virtual void set_encoding_params(EncodingParams encoding_params) {
        encoding_params_ = encoding_params;
    }

    /////////////////////////////////////
    // SERIALIZATION
    /////////////////////////////////////

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("elp", params_));
        ar(::cereal::make_nvp("enp", encoding_params_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        ar(::cereal::make_nvp("elp", params_));
        ar(::cereal::make_nvp("enp", encoding_params_));
    }

    std::string serialized_object_name() const override {
        return "CryptoParametersBase";
    }
    static uint32_t serialized_version() {
        return 1;
    }

  protected:
    /**
     * Constructor that creates default encoding parameters for the given plaintext modulus; the element
     * parameters are left unset.
     *
     * @param plaintext_modulus the plaintext modulus.
     */
    explicit BaseCryptoParams(const PlaintextModulus& plaintext_modulus) {
        encoding_params_ = std::make_shared<EncodingParamsImpl>(plaintext_modulus);
    }

    /**
     * Constructor that sets the element parameters and creates default encoding parameters for the
     * given plaintext modulus.
     *
     * @param params the ring element parameters.
     * @param plaintext_modulus the plaintext modulus.
     */
    BaseCryptoParams(std::shared_ptr<typename Element::Params> params, const PlaintextModulus& plaintext_modulus) {
        params_ = params;
        encoding_params_ = std::make_shared<EncodingParamsImpl>(plaintext_modulus);
    }

    /**
     * Constructor that sets the element parameters and the encoding parameters.
     *
     * @param params the ring element parameters.
     * @param encoding_params the encoding parameters.
     */
    BaseCryptoParams(std::shared_ptr<typename Element::Params> params, EncodingParams encoding_params) {
        params_ = params;
        encoding_params_ = encoding_params;
    }

    /**
     * Constructor that copies the parameters of another object and replaces its element parameters.
     *
     * @param from the parameters to copy.
     * @param new_elem_parms the ring element parameters of the new object.
     */
    BaseCryptoParams(BaseCryptoParams<Element>* from, std::shared_ptr<typename Element::Params> new_elem_parms) {
        *this = *from;
        params_ = new_elem_parms;
    }

    /**
     * @brief compare_to() is a method to compare two BaseCryptoParams objects. It is called by operator==()
     *
     * @param rhs - the other BaseCryptoParams object to compare to.
     * @return whether the two BaseCryptoParams objects are equivalent.
     */
    virtual bool compare_to(const BaseCryptoParams<Element>& rhs) const {
        return (*encoding_params_ == *(rhs.encoding_params_) && *params_ == *(rhs.params_));
    }

    /**
     * Prints the element parameters and the encoding parameters to the stream; called by operator<<
     * and extended by derived classes.
     *
     * @param out the stream to print to.
     */
    virtual void print_parameters(std::ostream& out) const {
        out << "Element Parameters: " << *params_ << std::endl;
        out << "Encoding Parameters: " << *encoding_params_ << std::endl;
    }

    /// element-specific parameters
    std::shared_ptr<typename Element::Params> params_;

    /// encoding-specific parameters
    EncodingParams encoding_params_;
};

}  // namespace cipher

#endif  // CIPHER_FHE_BASE_CRYPTO_PARAMS_H_
