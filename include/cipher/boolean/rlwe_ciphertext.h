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

#ifndef CIPHER_BOOLEAN_RLWE_CIPHERTEXT_H_
#define CIPHER_BOOLEAN_RLWE_CIPHERTEXT_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/ring/backend.h"
#include "cipher/boolean/lwe_ciphertext.h"
#include "cipher/boolean/lwe_params.h"
#include "cipher/boolean/lwe_switch_key.h"
#include "cipher/boolean/lwe_private_key.h"
#include "cipher/math/discrete_gaussian_gen.h"
#include "cipher/math/number_theory.h"
#include "cipher/util/serializable.h"
#include "cipher/util/utilities.h"

namespace cipher {

class RlweCiphertextImpl;
using RlweCiphertext = std::shared_ptr<RlweCiphertextImpl>;
using ConstRlweCiphertext = const std::shared_ptr<const RlweCiphertextImpl>;

/**
 * @brief Class that stores an RLWE ciphertext; a vector of ring elements
 */
class RlweCiphertextImpl : public Serializable {
  public:
    RlweCiphertextImpl() = default;

    /**
     * Constructs an RLWE ciphertext from its ring elements
     *
     * @param elements the RLWE pair (a, b) as a vector of two ring elements, elements[0] = a and elements[1] = b,
     * where b = a * s + e + encoded message for the RLWE secret key s
     */
    explicit RlweCiphertextImpl(const std::vector<NativePoly>& elements) : elements_(elements) {}

    /**
     * Constructs an RLWE ciphertext from its ring elements, moving them
     *
     * @param elements the RLWE pair (a, b) as a vector of two ring elements, elements[0] = a and elements[1] = b,
     * where b = a * s + e + encoded message for the RLWE secret key s
     */
    explicit RlweCiphertextImpl(std::vector<NativePoly>&& elements) noexcept : elements_(std::move(elements)) {}

    RlweCiphertextImpl(const RlweCiphertextImpl& rhs) : elements_(rhs.elements_) {}

    RlweCiphertextImpl(RlweCiphertextImpl&& rhs) noexcept : elements_(std::move(rhs.elements_)) {}

    RlweCiphertextImpl& operator=(const RlweCiphertextImpl& rhs) {
        elements_ = rhs.elements_;
        return *this;
    }

    RlweCiphertextImpl& operator=(RlweCiphertextImpl&& rhs) noexcept {
        elements_ = std::move(rhs.elements_);
        return *this;
    }

    const std::vector<NativePoly>& get_elements() const {
        return elements_;
    }

    std::vector<NativePoly>& get_elements() {
        return elements_;
    }

    /**
     * Switches all ring elements between COEFFICIENT and EVALUATION representation using NTT
     *
     * @param format the representation to switch the ring elements to
     */
    void set_format(const Format format) {
        for (size_t i = 0; i < elements_.size(); ++i)
            elements_[i].set_format(format);
    }

    /**
     * @param other the RLWE ciphertext to compare with
     * @return true if both ciphertexts have equal ring elements
     */
    bool operator==(const RlweCiphertextImpl& other) const {
        return elements_ == other.elements_;
    }

    /**
     * @param other the RLWE ciphertext to compare with
     * @return true if the ring elements differ
     */
    bool operator!=(const RlweCiphertextImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("elements", elements_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        ar(::cereal::make_nvp("elements", elements_));
    }

    std::string serialized_object_name() const override {
        return "RLWECiphertext";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    std::vector<NativePoly> elements_;  ///< the ring elements (a, b) of the ciphertext
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_RLWE_CIPHERTEXT_H_
