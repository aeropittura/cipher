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

#ifndef CIPHER_BOOLEAN_LWE_SWITCH_KEY_H_
#define CIPHER_BOOLEAN_LWE_SWITCH_KEY_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "cipher/boolean/lwe_switch_key_fwd.h"
#include "cipher/math/backend.h"
#include "cipher/util/serializable.h"

namespace cipher {

/**
 * @brief Class that stores the LWE scheme switching key
 */
class LweSwitchingKeyImpl : public Serializable {
  public:
    LweSwitchingKeyImpl() = default;

    /**
     * Constructs a key-switching key from its components
     *
     * Both components are indexed [i][j - 1][k], where i is the position in the source (dimension-N) secret
     * key sk_n, j in [1, base_ks) is the value of a base-base_ks digit and k is the digit position. The pair
     * (key_a[i][j - 1][k], key_b[i][j - 1][k]) is an LWE encryption of sk_n[i] * j * base_ks^k under the target
     * (dimension-n) secret key s modulo q_ks, i.e. key_b = <key_a, s> + e + sk_n[i] * j * base_ks^k. For digit
     * values j at or above the extent of the top digit position the innermost vectors have one entry fewer,
     * since that position is never read during key switching.
     *
     * @param key_a the vectors "a" of the key-switching LWE encryptions
     * @param key_b the integers "b" of the key-switching LWE encryptions
     */
    LweSwitchingKeyImpl(const std::vector<std::vector<std::vector<NativeVector>>>& key_a,
                        const std::vector<std::vector<std::vector<NativeInteger>>>& key_b)
        : key_a_(key_a), key_b_(key_b) {}

    /**
     * Constructs a key-switching key from its components, moving them
     *
     * Both components are indexed [i][j - 1][k], where i is the position in the source (dimension-N) secret
     * key sk_n, j in [1, base_ks) is the value of a base-base_ks digit and k is the digit position. The pair
     * (key_a[i][j - 1][k], key_b[i][j - 1][k]) is an LWE encryption of sk_n[i] * j * base_ks^k under the target
     * (dimension-n) secret key s modulo q_ks, i.e. key_b = <key_a, s> + e + sk_n[i] * j * base_ks^k. For digit
     * values j at or above the extent of the top digit position the innermost vectors have one entry fewer,
     * since that position is never read during key switching.
     *
     * @param key_a the vectors "a" of the key-switching LWE encryptions
     * @param key_b the integers "b" of the key-switching LWE encryptions
     */
    LweSwitchingKeyImpl(std::vector<std::vector<std::vector<NativeVector>>>&& key_a,
                        std::vector<std::vector<std::vector<NativeInteger>>>&& key_b) noexcept
        : key_a_(std::move(key_a)), key_b_(std::move(key_b)) {}

    LweSwitchingKeyImpl(const LweSwitchingKeyImpl& rhs) : key_a_(rhs.key_a_), key_b_(rhs.key_b_) {}

    LweSwitchingKeyImpl(LweSwitchingKeyImpl&& rhs) noexcept
        : key_a_(std::move(rhs.key_a_)), key_b_(std::move(rhs.key_b_)) {}

    LweSwitchingKeyImpl& operator=(const LweSwitchingKeyImpl& rhs) {
        key_a_ = rhs.key_a_;
        key_b_ = rhs.key_b_;
        return *this;
    }

    LweSwitchingKeyImpl& operator=(LweSwitchingKeyImpl&& rhs) noexcept {
        key_a_ = std::move(rhs.key_a_);
        key_b_ = std::move(rhs.key_b_);
        return *this;
    }

    const std::vector<std::vector<std::vector<NativeVector>>>& get_elements_a() const {
        return key_a_;
    }

    const std::vector<std::vector<std::vector<NativeInteger>>>& get_elements_b() const {
        return key_b_;
    }

    void set_elements_a(const std::vector<std::vector<std::vector<NativeVector>>>& key_a) {
        key_a_ = key_a;
    }

    void set_elements_b(const std::vector<std::vector<std::vector<NativeInteger>>>& key_b) {
        key_b_ = key_b;
    }

    void set_elements_a(std::vector<std::vector<std::vector<NativeVector>>>&& key_a) noexcept {
        key_a_ = std::move(key_a);
    }

    void set_elements_b(std::vector<std::vector<std::vector<NativeInteger>>>&& key_b) noexcept {
        key_b_ = std::move(key_b);
    }

    /**
     * @param other the key-switching key to compare with
     * @return true if both keys have the same "a" vectors and "b" integers
     */
    bool operator==(const LweSwitchingKeyImpl& other) const {
        return (key_a_ == other.key_a_ && key_b_ == other.key_b_);
    }

    /**
     * @param other the key-switching key to compare with
     * @return true if the keys differ
     */
    bool operator!=(const LweSwitchingKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("a", key_a_));
        ar(::cereal::make_nvp("b", key_b_));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > serialized_version()) {
            CIPHER_THROW("serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
        }
        ar(::cereal::make_nvp("a", key_a_));
        ar(::cereal::make_nvp("b", key_b_));
    }

    std::string serialized_object_name() const override {
        return "LWESwitchingKey";
    }

    static uint32_t serialized_version() {
        return 1;
    }

  private:
    std::vector<std::vector<std::vector<NativeVector>>> key_a_;   ///< vectors "a", indexed [i][j - 1][k]
    std::vector<std::vector<std::vector<NativeInteger>>> key_b_;  ///< integers "b", indexed [i][j - 1][k]
};

}  // namespace cipher

#endif  // CIPHER_BOOLEAN_LWE_SWITCH_KEY_H_
