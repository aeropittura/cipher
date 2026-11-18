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

#ifndef CIPHER_BOOLEAN_RGSW_ACC_KEY_H_
#define CIPHER_BOOLEAN_RGSW_ACC_KEY_H_

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
#include "cipher/boolean/rgsw_eval_key.h"
#include "cipher/util/serializable.h"
#include "cipher/util/utilities.h"

namespace cipher {

class RingGswAccKeyImpl;
using RingGswAccKey = std::shared_ptr<RingGswAccKeyImpl>;
using ConstRingGswAccKey = const std::shared_ptr<const RingGswAccKeyImpl>;

/**
 * @brief Class that stores the refresh key (used in bootstrapping)
 * A three-dimensional vector of RingGSW ciphertexts
 */
class RingGswAccKeyImpl : public Serializable {
  public:
    RingGswAccKeyImpl() = default;

    /**
     * Allocates a dim1 x dim2 x dim3 array of (null) RingGSW evaluation keys
     *
     * The meaning of the three dimensions depends on the bootstrapping method; see the key_gen_acc methods of the
     * RingGswAccumulator classes. With s the LWE secret key of dimension n:
     * - DM (AP): [n][base_r][digits_r], indexed [i][j][k] with i the position in s, j in [1, base_r) the value of a
     *   base-base_r digit and k the digit position; the entry is RGSW(X^(s_i * j * base_r^k)). The entries with
     *   j = 0, and with j at or above the extent of the top digit position, stay null.
     * - CGGI (GINX): [1][2][n]; [0][0][i] encrypts 1 if s_i = 1 and 0 otherwise, [0][1][i] encrypts 1 if s_i = -1
     *   and 0 otherwise.
     * - LMKCDEY: [1][2][n]; [0][0][i] = RGSW(X^(s_i)), [0][1][0] is the automorphism key for the exponent 2N - 5
     *   and [0][1][t] for t = 1..num_auto_keys is the automorphism key for 5^t mod 2N; the remaining [0][1] entries
     *   stay null.
     *
     * @param dim1 the size of the first dimension
     * @param dim2 the size of the second dimension
     * @param dim3 the size of the third dimension
     */
    RingGswAccKeyImpl(uint32_t dim1, uint32_t dim2, uint32_t dim3) : key_(dim1, dim2_t(dim2, dim3_t(dim3))) {}

    /**
     * Constructs a refresh key from a three-dimensional array of RingGSW evaluation keys
     *
     * @param key the RingGSW evaluation keys, laid out per bootstrapping method as described for the constructor
     * taking the three dimensions
     */
    explicit RingGswAccKeyImpl(const std::vector<std::vector<std::vector<RingGswEvalKey>>>& key) : key_(key) {}

    /**
     * Constructs a refresh key from a three-dimensional array of RingGSW evaluation keys, moving it
     *
     * @param key the RingGSW evaluation keys, laid out per bootstrapping method as described for the constructor
     * taking the three dimensions
     */
    explicit RingGswAccKeyImpl(std::vector<std::vector<std::vector<RingGswEvalKey>>>&& key) noexcept
        : key_(std::move(key)) {}

    RingGswAccKeyImpl(const RingGswAccKeyImpl& rhs) : key_(rhs.key_) {}

    RingGswAccKeyImpl(RingGswAccKeyImpl&& rhs) noexcept : key_(std::move(rhs.key_)) {}

    RingGswAccKeyImpl& operator=(const RingGswAccKeyImpl& rhs) {
        key_ = rhs.key_;
        return *this;
    }

    RingGswAccKeyImpl& operator=(RingGswAccKeyImpl&& rhs) noexcept {
        key_ = std::move(rhs.key_);
        return *this;
    }

    const std::vector<std::vector<std::vector<RingGswEvalKey>>>& get_elements() const {
        return key_;
    }

    void set_elements(const std::vector<std::vector<std::vector<RingGswEvalKey>>>& key) {
        key_ = key;
    }

    void set_elements(std::vector<std::vector<std::vector<RingGswEvalKey>>>&& key) noexcept {
        key_ = std::move(key);
    }

    /**
     * @param i the index in the first dimension
     * @return the two-dimensional slice of RingGSW evaluation keys at index i
     */
    std::vector<std::vector<RingGswEvalKey>>& operator[](uint32_t i) {
        return key_[i];
    }

    /**
     * @param i the index in the first dimension
     * @return the two-dimensional slice of RingGSW evaluation keys at index i
     */
    const std::vector<std::vector<RingGswEvalKey>>& operator[](uint32_t i) const {
        return key_[i];
    }

    /**
     * Compares the two keys entry by entry through the shared pointers; two null entries compare equal
     *
     * @param other the refresh key to compare with
     * @return true if both keys have the same dimensions and equal RingGSW evaluation keys in every position
     */
    bool operator==(const RingGswAccKeyImpl& other) const {
        // as RingGswEvalKey is shared_ptr<RingGswEvalKeyImpl>, we have to loop through all elements to compare them
        if (key_.size() != other.key_.size())
            return false;
        for (size_t i = 0; i < key_.size(); ++i) {
            const auto& l1 = key_[i];
            const auto& o1 = other.key_[i];
            if (l1.size() != o1.size())
                return false;
            for (size_t j = 0; j < l1.size(); ++j) {
                const auto& l2 = l1[j];
                const auto& o2 = o1[j];
                if (l2.size() != o2.size())
                    return false;
                for (size_t k = 0; k < l2.size(); ++k) {
                    const auto& l3 = l2[k];
                    const auto& o3 = o2[k];
                    if (l3.get() == nullptr || o3.get() == nullptr) {
                        if (l3.get() != o3.get())
                            return false;
                    } else {
                        if (*l3 != *o3)
                            return false;
                    }
                }
            }
        }
        return true;
    }

    /**
     * @param other the refresh key to compare with
     * @return true if the dimensions or any RingGSW evaluation key differ
     */
    bool operator!=(const RingGswAccKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("k", key_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("k", key_));
    }

    std::string serialized_object_name() const override {
        return "RingGSWACCKey";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    using dim3_t = std::vector<RingGswEvalKey>;
    using dim2_t = std::vector<dim3_t>;
    using dim1_t = std::vector<dim2_t>;

    std::vector<std::vector<std::vector<RingGswEvalKey>>> key_;  ///< RingGSW evaluation keys, laid out per method
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_RGSW_ACC_KEY_H_
