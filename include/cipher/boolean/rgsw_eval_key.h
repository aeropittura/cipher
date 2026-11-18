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

#ifndef CIPHER_BOOLEAN_RGSW_EVAL_KEY_H_
#define CIPHER_BOOLEAN_RGSW_EVAL_KEY_H_

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

class RingGswEvalKeyImpl;
using RingGswEvalKey = std::shared_ptr<RingGswEvalKeyImpl>;
using ConstRingGswEvalKey = const std::shared_ptr<const RingGswEvalKeyImpl>;

/**
 * @brief Class that stores a RingGSW ciphertext; a two-dimensional vector of
 * ring elements
 */
class RingGswEvalKeyImpl : public Serializable {
  public:
    RingGswEvalKeyImpl() = default;

    /**
     * Allocates a row_size x col_size matrix of default-constructed ring elements
     *
     * Every row of a RingGSW ciphertext is an RLWE pair (a, b) stored as columns 0 and 1, so col_size is 2.
     * An RGSW encryption of a monomial has 2 * (digits_g - 1) rows: row 2t adds the gadget power base_g^(t + 1)
     * times the monomial to "a" and row 2t + 1 adds it to "b" (the first gadget digit is dropped by the
     * approximate gadget decomposition). An LMKCDEY automorphism key has digits_g - 1 rows.
     *
     * @param row_size the number of rows (RLWE pairs)
     * @param col_size the number of ring elements per row
     */
    RingGswEvalKeyImpl(uint32_t row_size, uint32_t col_size) noexcept
        : elements_(row_size, std::vector<NativePoly>(col_size)) {}

    /**
     * Constructs a RingGSW ciphertext from its matrix of ring elements
     *
     * @param elements the ring elements indexed [row][column]; each row is an RLWE pair (a, b) in columns 0 and 1
     */
    explicit RingGswEvalKeyImpl(const std::vector<std::vector<NativePoly>>& elements) : elements_(elements) {}

    /**
     * Constructs a RingGSW ciphertext from its matrix of ring elements, moving it
     *
     * @param elements the ring elements indexed [row][column]; each row is an RLWE pair (a, b) in columns 0 and 1
     */
    explicit RingGswEvalKeyImpl(std::vector<std::vector<NativePoly>>&& elements) noexcept
        : elements_(std::move(elements)) {}

    RingGswEvalKeyImpl(const RingGswEvalKeyImpl& rhs) : elements_(rhs.elements_) {}

    RingGswEvalKeyImpl(RingGswEvalKeyImpl&& rhs) noexcept : elements_(std::move(rhs.elements_)) {}

    RingGswEvalKeyImpl& operator=(const RingGswEvalKeyImpl& rhs) {
        RingGswEvalKeyImpl::elements_ = rhs.elements_;
        return *this;
    }

    RingGswEvalKeyImpl& operator=(RingGswEvalKeyImpl&& rhs) noexcept {
        RingGswEvalKeyImpl::elements_ = std::move(rhs.elements_);
        return *this;
    }

    const std::vector<std::vector<NativePoly>>& get_elements() const {
        return elements_;
    }

    void set_elements(const std::vector<std::vector<NativePoly>>& elements) {
        elements_ = elements;
    }

    void set_elements(std::vector<std::vector<NativePoly>>&& elements) noexcept {
        elements_ = std::move(elements);
    }

    /**
     * Switches between COEFFICIENT and Format::EVALUATION polynomial
     * representations using NTT
     *
     * @param format the representation to switch all ring elements to
     */
    void set_format(const Format format) {
        for (size_t i = 0; i < elements_.size(); ++i) {
            auto& l1 = elements_[i];
            for (size_t j = 0; j < l1.size(); ++j)
                l1[j].set_format(format);
        }
    }

    /**
     * @param i the row index
     * @return the row i (an RLWE pair)
     */
    std::vector<NativePoly>& operator[](uint32_t i) {
        return elements_[i];
    }

    /**
     * @param i the row index
     * @return the row i (an RLWE pair)
     */
    const std::vector<NativePoly>& operator[](uint32_t i) const {
        return elements_[i];
    }

    /**
     * Compares the two matrices element by element
     *
     * @param other the RingGSW ciphertext to compare with
     * @return true if both have the same dimensions and equal ring elements
     */
    bool operator==(const RingGswEvalKeyImpl& other) const {
        if (elements_.size() != other.elements_.size())
            return false;
        for (size_t i = 0; i < elements_.size(); ++i) {
            const auto& l1 = elements_[i];
            const auto& o1 = other.elements_[i];
            if (l1.size() != o1.size())
                return false;
            for (size_t j = 0; j < l1.size(); ++j) {
                if (l1[j] != o1[j])
                    return false;
            }
        }
        return true;
    }

    /**
     * @param other the RingGSW ciphertext to compare with
     * @return true if the dimensions or any ring element differ
     */
    bool operator!=(const RingGswEvalKeyImpl& other) const {
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
        return "RingGSWEvalKey";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    std::vector<std::vector<NativePoly>> elements_;  ///< ring elements indexed [row][column]; columns are (a, b)
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_RGSW_EVAL_KEY_H_
