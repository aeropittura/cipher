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
  Represents and defines parameters for plaintext encoding
 */

#ifndef CIPHER_FHE_ENCODING_ENCODING_PARAMS_H_
#define CIPHER_FHE_ENCODING_ENCODING_PARAMS_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "cipher/ring/backend.h"
#include "cipher/util/inttypes.h"
#include "cipher/util/serializable.h"

namespace cipher {
class EncodingParamsImpl;

/// shared pointer to the encoding parameters
typedef std::shared_ptr<EncodingParamsImpl> EncodingParams;

/**
 * @class EncodingParamsImpl
 * @brief All parameters for plaintext encodings into ciphertext space.
 */
class EncodingParamsImpl : public cipher::Serializable {
  public:
    /**
     * Main constructor. Supports (1) default constructor, (2) regular encoding
     * with plaintext modulus set, (3) packed encoding with at least first two
     * parameters set. All of the private members not explicitly included as
     * arguments will be initialized to zero.
     *
     * @param plaintext_modulus plaintext modulus (used by all encodings)
     * @param batch_size sets the maximum batch size (as a power of 2) needed for
     * eval_sum
     * @param plaintext_generator (used by packed encoding for plaintext slot
     * rotation)
     * @param plaintext_root_of_unity root of unity for the plaintext modulus (used by packed encoding)
     * @param plaintext_big_modulus big plaintext modulus used for arbitrary cyclotomics (used by packed encoding)
     * @param plaintext_big_root_of_unity root of unity for the big plaintext modulus (used by packed encoding)
     */
    EncodingParamsImpl(PlaintextModulus plaintext_modulus = 0, uint32_t batch_size = 0, uint32_t plaintext_generator = 0,
                       NativeInteger plaintext_root_of_unity = 0, NativeInteger plaintext_big_modulus = 0,
                       NativeInteger plaintext_big_root_of_unity = 0)
        : plaintext_modulus_(plaintext_modulus),
          plaintext_root_of_unity_(plaintext_root_of_unity),
          plaintext_big_modulus_(plaintext_big_modulus),
          plaintext_big_root_of_unity_(plaintext_big_root_of_unity),
          plaintext_generator_(plaintext_generator),
          batch_size_(batch_size) {}

    /**
     * Copy constructor.
     *
     * @param rhs the input set of parameters which is copied.
     */
    EncodingParamsImpl(const EncodingParamsImpl& rhs) {
        plaintext_modulus_ = rhs.plaintext_modulus_;
        plaintext_root_of_unity_ = rhs.plaintext_root_of_unity_;
        plaintext_big_modulus_ = rhs.plaintext_big_modulus_;
        plaintext_big_root_of_unity_ = rhs.plaintext_big_root_of_unity_;
        plaintext_generator_ = rhs.plaintext_generator_;
        batch_size_ = rhs.batch_size_;
    }

    /**
     * Move constructor.
     *
     * @param rhs the input set of parameters which is moved.
     */
    EncodingParamsImpl(EncodingParamsImpl&& rhs) noexcept {
        plaintext_modulus_ = std::move(rhs.plaintext_modulus_);
        plaintext_root_of_unity_ = std::move(rhs.plaintext_root_of_unity_);
        plaintext_big_modulus_ = std::move(rhs.plaintext_big_modulus_);
        plaintext_big_root_of_unity_ = std::move(rhs.plaintext_big_root_of_unity_);
        plaintext_generator_ = std::move(rhs.plaintext_generator_);
        batch_size_ = rhs.batch_size_;
    }

    /**
     * Assignment Operator.
     *
     * @param rhs the EncodingParamsImpl to be copied.
     * @return the resulting EncodingParamsImpl.
     */
    const EncodingParamsImpl& operator=(const EncodingParamsImpl& rhs) {
        plaintext_modulus_ = rhs.plaintext_modulus_;
        plaintext_root_of_unity_ = rhs.plaintext_root_of_unity_;
        plaintext_big_modulus_ = rhs.plaintext_big_modulus_;
        plaintext_big_root_of_unity_ = rhs.plaintext_big_root_of_unity_;
        plaintext_generator_ = rhs.plaintext_generator_;
        batch_size_ = rhs.batch_size_;
        return *this;
    }

    /**
     * Destructor.
     */
    virtual ~EncodingParamsImpl() = default;

    // ACCESSORS

    // Get accessors

    /**
     * @brief Getter for the plaintext modulus.
     * @return The plaintext modulus.
     */
    PlaintextModulus get_plaintext_modulus() const {
        return plaintext_modulus_;
    }

    /**
     * @brief Setter for the plaintext modulus.
     * @param plaintext_modulus the plaintext modulus.
     */
    void set_plaintext_modulus(PlaintextModulus plaintext_modulus) {
        plaintext_modulus_ = plaintext_modulus;
    }

    /**
     * @brief Getter for the plaintext modulus root of unity.
     * @return The plaintext modulus root of unity.
     */
    NativeInteger get_plaintext_root_of_unity() const {
        return plaintext_root_of_unity_;
    }

    /**
     * @brief Setter for the plaintext modulus root of unity.
     * @param plaintext_root_of_unity the plaintext modulus root of unity.
     */
    void set_plaintext_root_of_unity(NativeInteger plaintext_root_of_unity) {
        plaintext_root_of_unity_ = plaintext_root_of_unity;
    }

    /**
     * @brief Getter for the big plaintext modulus.
     * @return The big plaintext modulus.
     */
    NativeInteger get_plaintext_big_modulus() const {
        return plaintext_big_modulus_;
    }

    /**
     * @brief Setter for the big plaintext modulus.
     * @param plaintext_big_modulus the big plaintext modulus.
     */
    void set_plaintext_big_modulus(NativeInteger plaintext_big_modulus) {
        plaintext_big_modulus_ = plaintext_big_modulus;
    }

    /**
     * @brief Getter for the big plaintext modulus root of unity.
     * @return The big plaintext modulus root of unity.
     */
    NativeInteger get_plaintext_big_root_of_unity() const {
        return plaintext_big_root_of_unity_;
    }

    /**
     * @brief Setter for the big plaintext modulus root of unity.
     * @param plaintext_big_root_of_unity the big plaintext modulus root of unity.
     */
    void set_plaintext_big_root_of_unity(NativeInteger plaintext_big_root_of_unity) {
        plaintext_big_root_of_unity_ = plaintext_big_root_of_unity;
    }

    /**
     * @brief Getter for the plaintext generator.
     * @return The plaintext generator.
     */
    uint32_t get_plaintext_generator() const {
        return plaintext_generator_;
    }

    /**
     * @brief Setter for the plaintext generator.
     * @param plaintext_generator the plaintext generator.
     */
    void set_plaintext_generator(uint32_t plaintext_generator) {
        plaintext_generator_ = plaintext_generator;
    }

    /**
     * @brief Getter for the plaintext batch size.
     * @return The plaintext batch size.
     */
    uint32_t get_batch_size() const {
        return batch_size_;
    }

    /**
     * @brief Setter for the batch size
     * @param batch_size the batch size.
     */
    void set_batch_size(uint32_t batch_size) {
        batch_size_ = batch_size;
    }

    // Operators
    /**
     * @brief output stream operator.
     * @param out the output stream to output.
     * @param item the following object to output.
     * @return the string output.
     */
    friend std::ostream& operator<<(std::ostream& out, const EncodingParamsImpl& item) {
        return item.doprint(out);
    }
    /**
     * @brief Equality operator for the parameters.  Tests that all the parameters
     * are equal.
     * @param other the other parameter set to compare to.
     * @return true if values of all data are equal.
     */
    bool operator==(const EncodingParamsImpl& other) const {
        return plaintext_modulus_ == other.plaintext_modulus_ &&
               plaintext_root_of_unity_ == other.plaintext_root_of_unity_ &&
               plaintext_big_modulus_ == other.plaintext_big_modulus_ &&
               plaintext_big_root_of_unity_ == other.plaintext_big_root_of_unity_ &&
               plaintext_generator_ == other.plaintext_generator_ && batch_size_ == other.batch_size_;
    }
    /**
     * @brief Inequality operator for the parameters.  Tests that all the
     * parameters are not equal.
     * @param other the other parameter set to compare to.
     * @return true if values of any data is not equal.
     */
    bool operator!=(const EncodingParamsImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("m", plaintext_modulus_));
        ar(::cereal::make_nvp("ru", plaintext_root_of_unity_));
        ar(::cereal::make_nvp("bm", plaintext_big_modulus_));
        ar(::cereal::make_nvp("bru", plaintext_big_root_of_unity_));
        ar(::cereal::make_nvp("g", plaintext_generator_));
        ar(::cereal::make_nvp("bs", batch_size_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("m", plaintext_modulus_));
        ar(::cereal::make_nvp("ru", plaintext_root_of_unity_));
        ar(::cereal::make_nvp("bm", plaintext_big_modulus_));
        ar(::cereal::make_nvp("bru", plaintext_big_root_of_unity_));
        ar(::cereal::make_nvp("g", plaintext_generator_));
        ar(::cereal::make_nvp("bs", batch_size_));
    }

    std::string serialized_object_name() const {
        return "EncodingParms";
    }
    static uint32_t serialized_version() {
        return 1;
    }

  protected:
    /**
     * @brief Prints all parameters to a stream; called by operator<<.
     * @param out the output stream
     * @return the output stream
     */
    std::ostream& doprint(std::ostream& out) const {
        out << "[p=" << plaintext_modulus_ << " rootP =" << plaintext_root_of_unity_ << " bigP =" << plaintext_big_modulus_
            << " rootBigP =" << plaintext_big_root_of_unity_ << " g=" << plaintext_generator_ << " L=" << batch_size_
            << "]";
        return out;
    }

  private:
    // plaintext modulus that is used by all schemes
    PlaintextModulus plaintext_modulus_;
    // root of unity for plaintext modulus
    NativeInteger plaintext_root_of_unity_;
    // big plaintext modulus that is used for arbitrary cyclotomics
    NativeInteger plaintext_big_modulus_;
    // root of unity for big plaintext modulus
    NativeInteger plaintext_big_root_of_unity_;
    // plaintext generator is used for packed encoding (to find the correct
    // automorphism index)
    uint32_t plaintext_generator_;
    // maximum batch size used by eval_sum_key_gen for packed encoding
    uint32_t batch_size_;
};

/**
 * @brief Output stream operator for a shared pointer to encoding parameters; prints nothing for a null pointer.
 * @param out the output stream
 * @param o the encoding parameters
 * @return the output stream
 */
inline std::ostream& operator<<(std::ostream& out, const std::shared_ptr<EncodingParamsImpl>& o) {
    if (o)
        out << *o;
    return out;
}
/**
 * @brief Equality operator for shared pointers to encoding parameters: two null pointers are equal, a null and a
 * non-null pointer are not, and two non-null pointers compare the parameters they point to.
 * @param o1 the first encoding parameters
 * @param o2 the second encoding parameters
 * @return true if both are null or both point to equal parameters
 */
inline bool operator==(const std::shared_ptr<EncodingParamsImpl>& o1, const std::shared_ptr<EncodingParamsImpl>& o2) {
    if (o1 && o2)
        return *o1 == *o2;
    if (!o1 && !o2)
        return true;
    return false;
}

}  // namespace cipher

#endif  // CIPHER_FHE_ENCODING_ENCODING_PARAMS_H_
